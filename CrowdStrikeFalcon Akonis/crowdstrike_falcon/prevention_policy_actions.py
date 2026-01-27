from typing import Any

from crowdstrike_falcon.action import CrowdstrikeAction


class CrowdstrikeActionPerformPreventionPolicyAction(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        action_name: str = arguments.get("action_name", "")
        ids: list[str] = arguments.get("ids", [])
        if not ids:
            self.error("List of IDs should not be empty.")
            return
        if not action_name:
            self.error("Action name should not be empty.")
            return

        self.log("Performing action {0} on {1} prevention policies".format(action_name, len(ids)))
        results = list(self.client.perform_prevention_policy_action(action_name, ids))
        return {"resources": results}


class CrowdstrikeActionGetPreventionPolicies(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        ids: list[str] = arguments.get("ids", [])
        if not ids:
            self.error("List of IDs should not be empty.")
            return

        self.log("Retrieving {0} prevention policies".format(len(ids)))
        results = list(self.client.get_prevention_policies(ids))
        return {"policies": results}


class CrowdstrikeActionCreatePreventionPolicies(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        resources: list[dict] = arguments.get("resources", [])
        if not resources:
            self.error("List of resources should not be empty.")
            return

        self.log("Creating {0} prevention policies".format(len(resources)))
        results = list(self.client.create_prevention_policies(resources))
        return {"policies": results}


class CrowdstrikeActionDeletePreventionPolicies(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        ids: list[str] = arguments.get("ids", [])
        if not ids:
            self.error("List of IDs should not be empty.")
            return

        self.log("Deleting {0} prevention policies".format(len(ids)))
        list(self.client.delete_prevention_policies(ids))
        self.log("Prevention policies deleted.")


class CrowdstrikeActionUpdatePreventionPolicies(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        resources: list[dict] = arguments.get("resources", [])
        if not resources:
            self.error("List of resources should not be empty.")
            return

        self.log("Updating {0} prevention policies".format(len(resources)))
        results = list(self.client.update_prevention_policies(resources))
        return {"policies": results}
