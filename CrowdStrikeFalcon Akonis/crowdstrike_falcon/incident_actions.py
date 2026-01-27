from typing import Any

from crowdstrike_falcon.action import CrowdstrikeAction


class CrowdstrikeActionGetBehaviors(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        ids: list[str] = arguments.get("ids", [])
        if not ids:
            self.error("List of IDs should not be empty.")
            return

        self.log("Retrieving details for {0} behaviors".format(len(ids)))
        results = list(self.client.get_behaviors(ids))
        return {"behaviors": results}


class CrowdstrikeActionGetIncidents(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        ids: list[str] = arguments.get("ids", [])
        if not ids:
            self.error("List of IDs should not be empty.")
            return

        self.log("Retrieving details for {0} incidents".format(len(ids)))
        results = list(self.client.get_incidents(ids))
        return {"incidents": results}
