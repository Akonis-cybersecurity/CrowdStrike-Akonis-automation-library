from typing import Any

from crowdstrike_falcon.action import CrowdstrikeAction
from crowdstrike_falcon.client.schemas import HostAction


class CrowdstrikeHostAction(CrowdstrikeAction):
    ACTION: HostAction

    def run(self, arguments: dict[str, Any]) -> None:
        ids: list[str] = arguments.get("ids", [])
        if not ids:
            self.error(f"List of ID`s should not be empty.")
            return

        self.log("Applying action {0} to {1} hosts".format(self.ACTION, ",".join(ids)))

        # In case of any error it will raise an exception inside client, so no need to handle pure response here.
        result = [_ for _ in self.client.host_action(ids, self.ACTION)]

        self.log("Action applied to hosts.")


class CrowdstrikeActionIsolateHosts(CrowdstrikeHostAction):
    ACTION = HostAction.contain


class CrowdstrikeActionDeIsolateHosts(CrowdstrikeHostAction):
    ACTION = HostAction.lift_containment


class CrowdstrikeActionGetDeviceDetails(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        ids: list[str] = arguments.get("ids", [])
        if not ids:
            self.error("List of IDs should not be empty.")
            return

        self.log("Retrieving details for {0} devices".format(len(ids)))
        results = list(self.client.get_devices_infos(ids))
        return {"devices": results}


class CrowdstrikeActionPerformHostAction(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        ids: list[str] = arguments.get("ids", [])
        action_name: str = arguments.get("action_name", "")
        if not ids:
            self.error("List of IDs should not be empty.")
            return
        if not action_name:
            self.error("Action name should not be empty.")
            return

        try:
            action = HostAction(action_name)
        except ValueError:
            self.error(f"Invalid action name: {action_name}. Valid actions: {', '.join(a.value for a in HostAction)}")
            return

        self.log("Applying action {0} to {1} hosts".format(action_name, len(ids)))
        result = list(self.client.host_action(ids, action))
        return {"resources": result}


class CrowdstrikeActionQueryDevicesByFilter(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        fql_filter = arguments.get("filter")
        sort = arguments.get("sort")
        limit = arguments.get("limit")
        offset = arguments.get("offset")

        self.log("Querying devices by filter")
        results = list(self.client.query_devices_by_filter(filter=fql_filter, sort=sort, limit=limit, offset=offset))
        return {"device_ids": results}


class CrowdstrikeActionQueryDeviceLoginHistory(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        ids: list[str] = arguments.get("ids", [])
        if not ids:
            self.error("List of IDs should not be empty.")
            return

        self.log("Retrieving login history for {0} devices".format(len(ids)))
        results = list(self.client.query_device_login_history(ids))
        return {"history": results}


class CrowdstrikeActionGetOnlineState(CrowdstrikeAction):
    def run(self, arguments: dict[str, Any]) -> None:
        ids: list[str] = arguments.get("ids", [])
        if not ids:
            self.error("List of IDs should not be empty.")
            return

        self.log("Retrieving online state for {0} devices".format(len(ids)))
        results = list(self.client.get_online_state(ids))
        return {"states": results}
