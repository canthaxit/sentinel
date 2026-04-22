"""
Sentinel - Agent Policy Validation
============================================
Runtime tool allowlists, action budgets, and delegation depth limits
for agentic AI architectures.

Validates that agent actions conform to a defined policy before execution.

Usage:
    from sentinel.agent_policy import AgentPolicy, PolicyValidator

    policy = AgentPolicy(
        allowed_tools={"search", "calculator"},
        max_delegation_depth=3,
        max_tool_calls_per_turn=10,
    )
    validator = PolicyValidator(policy)
    allowed, reason = validator.validate_tool_call("search", depth=1, call_count=5)
"""

import dataclasses


class PolicyViolation(Exception):
    """Raised when an agent action violates the configured policy."""

    def __init__(self, action: str, reason: str):
        self.action = action
        self.reason = reason
        super().__init__(f"Policy violation ({action}): {reason}")


@dataclasses.dataclass(frozen=True)
class AgentPolicy:
    """Immutable specification of what an agent is allowed to do.

    Attributes:
        allowed_tools: Set of tool names the agent may invoke. If empty,
            all tools are allowed unless explicitly denied.
        denied_tools: Set of tool names the agent must never invoke.
            Takes precedence over allowed_tools.
        max_delegation_depth: Maximum nesting depth for sub-agent calls.
        max_tool_calls_per_turn: Maximum tool invocations in a single turn.
        forbidden_actions: Set of high-level action labels that are always
            blocked (e.g., "delete_production_db", "send_email").
    """
    allowed_tools: frozenset[str] = dataclasses.field(default_factory=frozenset)
    denied_tools: frozenset[str] = dataclasses.field(default_factory=frozenset)
    max_delegation_depth: int = 5
    max_tool_calls_per_turn: int = 50
    forbidden_actions: frozenset[str] = dataclasses.field(default_factory=frozenset)

    def __post_init__(self):
        # Coerce mutable sets to frozensets for immutability
        if not isinstance(self.allowed_tools, frozenset):
            object.__setattr__(self, "allowed_tools", frozenset(self.allowed_tools))
        if not isinstance(self.denied_tools, frozenset):
            object.__setattr__(self, "denied_tools", frozenset(self.denied_tools))
        if not isinstance(self.forbidden_actions, frozenset):
            object.__setattr__(self, "forbidden_actions", frozenset(self.forbidden_actions))


class PolicyValidator:
    """Validates agent actions against an AgentPolicy."""

    def __init__(self, policy: AgentPolicy):
        self.policy = policy

    def validate_tool_call(
        self, tool_name: str, depth: int = 0, call_count: int = 0
    ) -> tuple[bool, str | None]:
        """Check whether a tool call is permitted.

        Args:
            tool_name: Name of the tool to invoke.
            depth: Current delegation nesting depth.
            call_count: Number of tool calls already made this turn.

        Returns:
            (True, None) if allowed, or (False, reason_string) if denied.
        """
        # Denied list takes precedence
        if tool_name in self.policy.denied_tools:
            return False, f"Tool '{tool_name}' is in the denied list"

        # Allowed list check (empty = everything allowed)
        if self.policy.allowed_tools and tool_name not in self.policy.allowed_tools:
            return False, f"Tool '{tool_name}' is not in the allowed list"

        # Delegation depth check
        if depth > self.policy.max_delegation_depth:
            return False, (
                f"Delegation depth {depth} exceeds max "
                f"{self.policy.max_delegation_depth}"
            )

        # Tool call budget check
        if call_count >= self.policy.max_tool_calls_per_turn:
            return False, (
                f"Tool call count {call_count} reaches per-turn limit "
                f"{self.policy.max_tool_calls_per_turn}"
            )

        return True, None

    def validate_action(self, action_name: str) -> tuple[bool, str | None]:
        """Check whether a high-level action is permitted.

        Args:
            action_name: Logical action label (e.g., "send_email").

        Returns:
            (True, None) if allowed, or (False, reason_string) if denied.
        """
        if action_name in self.policy.forbidden_actions:
            return False, f"Action '{action_name}' is forbidden by policy"
        return True, None

    def enforce_tool_call(
        self, tool_name: str, depth: int = 0, call_count: int = 0
    ) -> None:
        """Like validate_tool_call but raises PolicyViolation on denial."""
        allowed, reason = self.validate_tool_call(tool_name, depth, call_count)
        if not allowed:
            raise PolicyViolation(tool_name, reason)

    def enforce_action(self, action_name: str) -> None:
        """Like validate_action but raises PolicyViolation on denial."""
        allowed, reason = self.validate_action(action_name)
        if not allowed:
            raise PolicyViolation(action_name, reason)
