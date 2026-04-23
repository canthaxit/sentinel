#!/usr/bin/env python3
"""
Tests for sentinel.honey_ics - MODBUS TCP honey server.
"""

import socket
import struct
import threading
import time

import pytest

from sentinel.honey_ics import (
    EXCEPTION_FLAG,
    EXCEPTION_ILLEGAL_FUNCTION,
    FC_READ_HOLDING_REGISTERS,
    FC_WRITE_SINGLE_REGISTER,
    HoneyModbusServer,
    MBAP_HEADER_SIZE,
    _build_default_registers,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_mbap_request(transaction_id, unit_id, pdu):
    """Build a MODBUS TCP frame: MBAP header + PDU."""
    length = len(pdu) + 1  # +1 for unit_id
    header = struct.pack(">HHHB", transaction_id, 0, length, unit_id)
    return header + pdu


def _send_modbus(port, pdu, transaction_id=1, unit_id=1):
    """Send a MODBUS TCP request and return the response PDU."""
    frame = _build_mbap_request(transaction_id, unit_id, pdu)
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock.sendall(frame)
        # Read MBAP header
        resp_header = b""
        while len(resp_header) < MBAP_HEADER_SIZE:
            chunk = sock.recv(MBAP_HEADER_SIZE - len(resp_header))
            if not chunk:
                break
            resp_header += chunk
        if len(resp_header) < MBAP_HEADER_SIZE:
            return None, None
        txn, proto, resp_len, uid = struct.unpack(">HHHB", resp_header)
        # Read PDU
        pdu_len = resp_len - 1
        resp_pdu = b""
        while len(resp_pdu) < pdu_len:
            chunk = sock.recv(pdu_len - len(resp_pdu))
            if not chunk:
                break
            resp_pdu += chunk
        return resp_header, resp_pdu
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDefaultRegisters:
    def test_registers_populated(self):
        regs = _build_default_registers()
        assert len(regs) > 50
        # Temperature register 0 should be around 724 (72.4 degC)
        assert regs[0] == 724
        # Pressure register 10
        assert regs[10] == 1470
        # Flow register 20
        assert regs[20] == 4502
        # Level register 30
        assert regs[30] == 681

    def test_all_values_16bit(self):
        regs = _build_default_registers()
        for addr, val in regs.items():
            assert 0 <= val <= 0xFFFF, f"Register {addr} out of 16-bit range: {val}"


class TestHoneyModbusServer:
    """Tests that start/stop the server and send actual MODBUS frames."""

    PORT = 15020  # Non-privileged test port

    @pytest.fixture(autouse=True)
    def _server(self):
        """Start a MODBUS honey server for each test."""
        self.triggers = []
        self.server = HoneyModbusServer(
            port=self.PORT,
            trigger_callback=lambda e: self.triggers.append(e),
        )
        self.server.start()
        time.sleep(0.3)
        yield
        self.server.stop()
        time.sleep(0.1)

    def test_start_stop(self):
        assert self.server.is_running

    def test_connection_fires_trigger(self):
        # Send a minimal MODBUS read to ensure the handler fully executes
        pdu = struct.pack(">BHH", FC_READ_HOLDING_REGISTERS, 0, 1)
        _send_modbus(self.PORT, pdu)
        time.sleep(0.3)
        # Connection trigger fires at the start of every handler invocation
        conn_triggers = [t for t in self.triggers if t["action"] == "connection"]
        assert len(conn_triggers) >= 1

    def test_read_holding_registers(self):
        # FC 0x03: Read 5 registers starting at address 0
        pdu = struct.pack(">BHH", FC_READ_HOLDING_REGISTERS, 0, 5)
        _, resp_pdu = _send_modbus(self.PORT, pdu)

        assert resp_pdu is not None
        assert resp_pdu[0] == FC_READ_HOLDING_REGISTERS
        byte_count = resp_pdu[1]
        assert byte_count == 10  # 5 registers * 2 bytes each

        # Parse register values
        values = []
        for i in range(5):
            val = struct.unpack(">H", resp_pdu[2 + i * 2: 4 + i * 2])[0]
            values.append(val)

        # First register should be temperature 724
        assert values[0] == 724

    def test_read_pressure_registers(self):
        # Read 3 pressure registers starting at address 10
        pdu = struct.pack(">BHH", FC_READ_HOLDING_REGISTERS, 10, 3)
        _, resp_pdu = _send_modbus(self.PORT, pdu)

        assert resp_pdu[0] == FC_READ_HOLDING_REGISTERS
        values = []
        for i in range(3):
            val = struct.unpack(">H", resp_pdu[2 + i * 2: 4 + i * 2])[0]
            values.append(val)

        assert values[0] == 1470  # 14.70 PSI
        assert values[1] == 1523

    def test_write_single_register(self):
        # FC 0x06: Write value 9999 to register 200
        pdu = struct.pack(">BHH", FC_WRITE_SINGLE_REGISTER, 200, 9999)
        _, resp_pdu = _send_modbus(self.PORT, pdu)

        assert resp_pdu is not None
        assert resp_pdu[0] == FC_WRITE_SINGLE_REGISTER
        addr, val = struct.unpack(">HH", resp_pdu[1:5])
        assert addr == 200
        assert val == 9999

        # MED F-06 fix (2026-04-22 audit): FC06 writes no longer mutate the
        # register bank -- that behaviour let attackers calibrate the honey
        # by writing and reading back a distinctive value. Register retains
        # its original value while the ACK is still returned.
        assert self.server.get_register(200) != 9999

        # Should have triggered a write alert
        write_triggers = [t for t in self.triggers if t["action"] == "write_single_register"]
        assert len(write_triggers) >= 1
        assert write_triggers[0]["register_address"] == 200
        assert write_triggers[0]["value"] == 9999

    def test_unsupported_function_code(self):
        # FC 0x10 (Write Multiple Registers) is not supported
        pdu = struct.pack(">BHHB", 0x10, 0, 1, 2) + struct.pack(">H", 100)
        _, resp_pdu = _send_modbus(self.PORT, pdu)

        assert resp_pdu is not None
        # Response should be exception: FC | 0x80
        assert resp_pdu[0] == (0x10 | EXCEPTION_FLAG)
        assert resp_pdu[1] == EXCEPTION_ILLEGAL_FUNCTION

    def test_invalid_quantity_returns_exception(self):
        # Read 0 registers (invalid quantity)
        pdu = struct.pack(">BHH", FC_READ_HOLDING_REGISTERS, 0, 0)
        _, resp_pdu = _send_modbus(self.PORT, pdu)

        assert resp_pdu[0] == (FC_READ_HOLDING_REGISTERS | EXCEPTION_FLAG)

    def test_interaction_logging(self):
        pdu = struct.pack(">BHH", FC_READ_HOLDING_REGISTERS, 0, 1)
        _send_modbus(self.PORT, pdu)
        time.sleep(0.2)

        interactions = self.server.get_interactions()
        # Should have at least connection + read
        assert len(interactions) >= 2

    def test_get_set_register(self):
        self.server.set_register(999, 12345)
        assert self.server.get_register(999) == 12345
        # Unset register defaults to 0
        assert self.server.get_register(65535) == 0

    def test_transaction_id_preserved(self):
        pdu = struct.pack(">BHH", FC_READ_HOLDING_REGISTERS, 0, 1)
        resp_header, _ = _send_modbus(self.PORT, pdu, transaction_id=42)

        txn_id = struct.unpack(">H", resp_header[0:2])[0]
        assert txn_id == 42
