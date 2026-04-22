"""
Sentinel - MODBUS TCP Honey Server
====================================
A deception-layer MODBUS TCP server that simulates ICS/SCADA devices.
Any interaction is treated as a confirmed reconnaissance or attack
indicator against industrial control systems.

Supported function codes:
    - FC 0x03: Read Holding Registers
    - FC 0x06: Write Single Register

All other function codes return a MODBUS exception (illegal function).

Usage:
    from sentinel.honey_ics import HoneyModbusServer

    def on_trigger(event):
        print(f"MODBUS trigger from {event['source_ip']}")

    server = HoneyModbusServer(port=5020, trigger_callback=on_trigger)
    server.start()      # runs in background daemon thread
    # ...
    server.stop()
"""

import datetime
import logging
import socketserver
import struct
import threading
from collections import deque
from typing import Any, Callable, Dict, List, Optional

log = logging.getLogger("sentinel.honey_ics")


# ---------------------------------------------------------------------------
# MODBUS TCP Constants
# ---------------------------------------------------------------------------

# MBAP header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1)
MBAP_HEADER_SIZE = 7

# Function codes we handle
FC_READ_HOLDING_REGISTERS = 0x03
FC_WRITE_SINGLE_REGISTER = 0x06

# Exception codes
EXCEPTION_ILLEGAL_FUNCTION = 0x01
EXCEPTION_ILLEGAL_DATA_ADDRESS = 0x02
EXCEPTION_ILLEGAL_DATA_VALUE = 0x03

# Exception response flag (FC + 0x80)
EXCEPTION_FLAG = 0x80


# ---------------------------------------------------------------------------
# Simulated register bank
# ---------------------------------------------------------------------------

def _build_default_registers() -> Dict[int, int]:
    """Initialize holding registers with plausible ICS sensor values.

    Register layout (mimics a water treatment plant):
        0-9:   Temperature sensors (raw ADC scaled to 0.1 degC units)
        10-19: Pressure gauges (0.01 PSI units)
        20-29: Flow meters (0.1 GPM units)
        30-39: Level sensors (0.1% units)
        40-49: Valve positions (0-10000 = 0-100.00%)
        50-59: Pump speeds (RPM)
        60-69: Status words (bitfields)
        100+:  Setpoints
    """
    regs: Dict[int, int] = {}

    # Temperature sensors (e.g., 72.4 degC = 724 in 0.1 degC units)
    temps = [724, 681, 753, 698, 712, 695, 730, 710, 688, 741]
    for i, v in enumerate(temps):
        regs[i] = v

    # Pressure gauges (e.g., 14.70 PSI = 1470 in 0.01 PSI units)
    pressures = [1470, 1523, 1389, 1455, 1501, 1478, 1445, 1512, 1498, 1467]
    for i, v in enumerate(pressures):
        regs[10 + i] = v

    # Flow meters (e.g., 450.2 GPM = 4502 in 0.1 GPM units)
    flows = [4502, 3801, 4215, 3950, 4100, 3875, 4320, 4055, 3990, 4180]
    for i, v in enumerate(flows):
        regs[20 + i] = v

    # Level sensors (e.g., 68.1% = 681 in 0.1% units)
    levels = [681, 723, 654, 698, 710, 665, 702, 688, 671, 715]
    for i, v in enumerate(levels):
        regs[30 + i] = v

    # Valve positions (0-10000 = 0-100.00%)
    valves = [7500, 5000, 8200, 6100, 9000, 4500, 7800, 5500, 6800, 8500]
    for i, v in enumerate(valves):
        regs[40 + i] = v

    # Pump speeds (RPM)
    pumps = [1750, 1480, 3550, 1750, 0, 1480, 3550, 0, 1750, 1480]
    for i, v in enumerate(pumps):
        regs[50 + i] = v

    # Status words (bit 0 = running, bit 1 = alarm, bit 2 = manual)
    status = [0x0001, 0x0001, 0x0003, 0x0001, 0x0000, 0x0001, 0x0005, 0x0000, 0x0001, 0x0001]
    for i, v in enumerate(status):
        regs[60 + i] = v

    # Setpoints
    setpoints = [750, 1500, 4000, 700, 7500, 1750]
    for i, v in enumerate(setpoints):
        regs[100 + i] = v

    return regs


# ---------------------------------------------------------------------------
# MODBUS TCP Handler
# ---------------------------------------------------------------------------

class _ModbusHandler(socketserver.BaseRequestHandler):
    """Handles a single MODBUS TCP connection.

    Shared state is stored in ``_handler_ctx`` (a dict) on the class
    to avoid Python's descriptor protocol turning callables into
    unbound methods.
    """

    # Populated by HoneyModbusServer.start() on a dynamically-created subclass.
    _handler_ctx: Dict[str, Any] = {}

    # Convenience accessors for the context dict
    @property
    def _registers(self) -> Dict[int, int]:
        return self._handler_ctx["registers"]

    @property
    def _reg_lock(self) -> threading.RLock:
        return self._handler_ctx["register_lock"]

    @property
    def _trigger_cb(self) -> Optional[Callable]:
        return self._handler_ctx.get("trigger_callback")

    @property
    def _ilog(self) -> Optional[deque]:
        return self._handler_ctx.get("interaction_log")

    @property
    def _ilog_lock(self) -> Optional[threading.RLock]:
        return self._handler_ctx.get("log_lock")

    def handle(self):
        source_ip = self.client_address[0]
        source_port = self.client_address[1]

        log.info("[HONEY-MODBUS] Connection from %s:%d", source_ip, source_port)

        # Fire trigger on any connection (reconnaissance indicator)
        self._fire_trigger(source_ip, source_port, "connection", 0, 0, 0)

        while True:
            try:
                # Read MBAP header (7 bytes)
                header_data = self._recv_exact(MBAP_HEADER_SIZE)
                if header_data is None:
                    break

                transaction_id, protocol_id, length, unit_id = struct.unpack(
                    ">HHHB", header_data
                )

                # Protocol ID must be 0 for MODBUS TCP
                if protocol_id != 0:
                    log.debug("Non-MODBUS protocol ID: %d, closing", protocol_id)
                    break

                # Read the PDU (length includes unit_id byte, already read)
                pdu_length = length - 1
                if pdu_length < 1 or pdu_length > 253:
                    break

                pdu_data = self._recv_exact(pdu_length)
                if pdu_data is None:
                    break

                function_code = pdu_data[0]

                # Process and respond
                response_pdu = self._process_pdu(
                    function_code, pdu_data, source_ip, source_port, unit_id
                )

                # Build MBAP response header
                resp_length = len(response_pdu) + 1  # +1 for unit_id
                resp_header = struct.pack(
                    ">HHHB", transaction_id, 0, resp_length, unit_id
                )

                self.request.sendall(resp_header + response_pdu)

            except (ConnectionResetError, BrokenPipeError, OSError):
                break
            except Exception as exc:
                log.debug("MODBUS handler error: %s", exc)
                break

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes, or return None on disconnect."""
        data = b""
        while len(data) < n:
            try:
                chunk = self.request.recv(n - len(data))
            except (ConnectionResetError, OSError):
                return None
            if not chunk:
                return None
            data += chunk
        return data

    def _process_pdu(self, fc: int, pdu: bytes,
                     source_ip: str, source_port: int,
                     unit_id: int) -> bytes:
        """Dispatch to the correct function code handler."""
        if fc == FC_READ_HOLDING_REGISTERS:
            return self._handle_read_holding_registers(
                pdu, source_ip, source_port, unit_id
            )
        elif fc == FC_WRITE_SINGLE_REGISTER:
            return self._handle_write_single_register(
                pdu, source_ip, source_port, unit_id
            )
        else:
            # Unsupported function code -- return exception
            log.warning(
                "[HONEY-MODBUS] Unsupported FC 0x%02X from %s:%d",
                fc, source_ip, source_port,
            )
            self._fire_trigger(
                source_ip, source_port, "unsupported_fc",
                fc, 0, 0,
            )
            return struct.pack("BB", fc | EXCEPTION_FLAG, EXCEPTION_ILLEGAL_FUNCTION)

    def _handle_read_holding_registers(self, pdu: bytes,
                                        source_ip: str, source_port: int,
                                        unit_id: int) -> bytes:
        """FC 0x03: Read Holding Registers."""
        if len(pdu) < 5:
            return struct.pack("BB", FC_READ_HOLDING_REGISTERS | EXCEPTION_FLAG,
                               EXCEPTION_ILLEGAL_DATA_VALUE)

        start_addr, quantity = struct.unpack(">HH", pdu[1:5])

        log.info(
            "[HONEY-MODBUS] FC03 Read %d registers @ %d from %s:%d",
            quantity, start_addr, source_ip, source_port,
        )

        self._fire_trigger(
            source_ip, source_port, "read_holding_registers",
            FC_READ_HOLDING_REGISTERS, start_addr, quantity,
        )

        # Validate range
        if quantity < 1 or quantity > 125:
            return struct.pack("BB", FC_READ_HOLDING_REGISTERS | EXCEPTION_FLAG,
                               EXCEPTION_ILLEGAL_DATA_VALUE)

        # Build response with register values
        byte_count = quantity * 2
        response = struct.pack("BB", FC_READ_HOLDING_REGISTERS, byte_count)

        with self._reg_lock:
            for addr in range(start_addr, start_addr + quantity):
                value = self._registers.get(addr, 0)
                response += struct.pack(">H", value & 0xFFFF)

        return response

    def _handle_write_single_register(self, pdu: bytes,
                                       source_ip: str, source_port: int,
                                       unit_id: int) -> bytes:
        """FC 0x06: Write Single Register."""
        if len(pdu) < 5:
            return struct.pack("BB", FC_WRITE_SINGLE_REGISTER | EXCEPTION_FLAG,
                               EXCEPTION_ILLEGAL_DATA_VALUE)

        register_addr, register_value = struct.unpack(">HH", pdu[1:5])

        log.warning(
            "[HONEY-MODBUS] FC06 WRITE register %d = %d from %s:%d (ATTACK INDICATOR)",
            register_addr, register_value, source_ip, source_port,
        )

        self._fire_trigger(
            source_ip, source_port, "write_single_register",
            FC_WRITE_SINGLE_REGISTER, register_addr, register_value,
        )

        # Accept the write (deception: appear to comply)
        with self._reg_lock:
            self._registers[register_addr] = register_value & 0xFFFF

        # Echo back (standard MODBUS write response)
        return struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER,
                           register_addr, register_value & 0xFFFF)

    def _fire_trigger(self, source_ip: str, source_port: int,
                      action: str, function_code: int,
                      register_addr: int, value: int) -> None:
        """Record interaction and fire the trigger callback."""
        event = {
            "service": "modbus-tcp",
            "protocol": "modbus",
            "source_ip": source_ip,
            "source_port": source_port,
            "action": action,
            "function_code": function_code,
            "register_address": register_addr,
            "value": value,
            "timestamp": datetime.datetime.now().isoformat(),
        }

        ilog = self._ilog
        ilog_lock = self._ilog_lock
        if ilog is not None and ilog_lock is not None:
            with ilog_lock:
                ilog.append(event)

        cb = self._trigger_cb
        if cb is not None:
            try:
                cb(event)
            except Exception as exc:
                log.debug("Trigger callback error: %s", exc)


# ---------------------------------------------------------------------------
# Public Server Class
# ---------------------------------------------------------------------------

class HoneyModbusServer:
    """MODBUS TCP honey server simulating ICS/SCADA devices.

    Listens for MODBUS TCP connections, parses frames, returns realistic
    register values, and fires a callback on every interaction.

    Args:
        port: TCP port to listen on (default 502, use >1024 for unprivileged).
        trigger_callback: Callable invoked on every MODBUS interaction.
        max_log_entries: Maximum interaction log entries to retain.
    """

    _MAX_LOG = 50000

    def __init__(self, port: int = 502,
                 trigger_callback: Optional[Callable] = None,
                 max_log_entries: int = _MAX_LOG):
        self.port = port
        self.trigger_callback = trigger_callback
        self._registers = _build_default_registers()
        self._register_lock = threading.RLock()
        self._interaction_log: deque = deque(maxlen=max_log_entries)
        self._log_lock = threading.RLock()
        self._server: Optional[socketserver.TCPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the MODBUS honey server in a background daemon thread."""
        if self._server is not None:
            return

        ctx = {
            "registers": self._registers,
            "register_lock": self._register_lock,
            "trigger_callback": self.trigger_callback,
            "interaction_log": self._interaction_log,
            "log_lock": self._log_lock,
        }

        class Handler(_ModbusHandler):
            _handler_ctx = ctx

        socketserver.TCPServer.allow_reuse_address = True
        self._server = socketserver.TCPServer(("0.0.0.0", self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"honey-modbus-{self.port}",
            daemon=True,
        )
        self._thread.start()
        log.info("Honey MODBUS server listening on port %d", self.port)

    def stop(self) -> None:
        """Stop the MODBUS honey server."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self._thread = None
            log.info("Honey MODBUS server stopped (port %d)", self.port)

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._thread is not None and self._thread.is_alive()

    def get_register(self, address: int) -> int:
        """Read a holding register value."""
        with self._register_lock:
            return self._registers.get(address, 0)

    def set_register(self, address: int, value: int) -> None:
        """Set a holding register value (for simulation tuning)."""
        with self._register_lock:
            self._registers[address] = value & 0xFFFF

    def get_interactions(self, limit: int = 100) -> List[dict]:
        """Return recent MODBUS interaction events."""
        with self._log_lock:
            items = list(self._interaction_log)
            return items[-limit:] if limit < len(items) else items

    @property
    def interaction_count(self) -> int:
        with self._log_lock:
            return len(self._interaction_log)
