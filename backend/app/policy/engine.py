import os
import yaml
from typing import Tuple

class PolicyEngine:
    def __init__(self, policy_path=None):
        if policy_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.policy_path = os.path.join(base_dir, "rules.yaml")
        else:
            self.policy_path = policy_path
        
        self.rules = self._load_rules()
        self.version = self.rules.get("version", "1.0.0")

    def _load_rules(self) -> dict:
        if not os.path.exists(self.policy_path):
            return {"roles": {}}
        try:
            with open(self.policy_path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading rules from {self.policy_path}: {e}")
            return {"roles": {}}

    def evaluate(self, role: str, action: str, ml_risk: str) -> Tuple[str, str]:
        """
        Evaluate access permission based on RBAC/ABAC policy and ML Risk score.
        Returns:
            final_decision: "allow" | "block" | "require_human_approval"
            override_note: Optional explanation if policy overrides ML recommendation
        """
        role_rules = self.rules.get("roles", {}).get(role)
        if not role_rules:
            return "block", f"Policy Override: Unknown agent role '{role}'. Defaulting to block for safety."

        allowed_actions = role_rules.get("allowed_actions", [])
        blocked_actions = role_rules.get("explicit_blocked_actions", [])
        max_risk = role_rules.get("max_risk_allowed", "low")

        # 1. Check explicit block list
        if action in blocked_actions:
            return "block", f"Policy Override: Action '{action}' is explicitly banned for role '{role}'."

        # 2. Check if action is not in allowed list
        if action not in allowed_actions:
            return "block", f"Policy Override: Action '{action}' is not in the allowed action set for role '{role}'."

        # 3. Check if ML risk exceeds role limits
        risk_levels = {"low": 0, "medium": 1, "high": 2}
        ml_risk_val = risk_levels.get(ml_risk.lower(), 0)
        max_risk_val = risk_levels.get(max_risk.lower(), 0)

        if ml_risk_val > max_risk_val:
            return "block", f"Policy Override: ML Risk '{ml_risk.upper()}' exceeds max allowed risk '{max_risk.upper()}' for role '{role}'."

        # 4. Map standard decisions if within policy bounds
        if ml_risk == "high":
            # Defer high risk actions within limits (OperationsAgent) to human approval
            return "require_human_approval", f"Policy Deferral: Allowed for role '{role}' but requires human verification due to HIGH risk classification."
        elif ml_risk == "medium":
            return "require_human_approval", ""
        else:
            return "allow", ""
