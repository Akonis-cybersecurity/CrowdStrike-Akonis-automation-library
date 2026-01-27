from crowdstrike_falcon.account_validator import CrowdstrikeFalconAccountValidator
from crowdstrike_falcon import CrowdStrikeFalconModule
from crowdstrike_falcon.alert_actions import (
    CrowdstrikeActionCommentAlert,
    CrowdstrikeActionGetAlertsV2,
    CrowdstrikeActionUpdateAlertStatus,
)
from crowdstrike_falcon.custom_iocs import (
    CrowdstrikeActionBlockIOC,
    CrowdstrikeActionCreateIndicators,
    CrowdstrikeActionDeleteIndicators,
    CrowdstrikeActionGetIndicators,
    CrowdstrikeActionGetIndicatorsReport,
    CrowdstrikeActionGetIOCActions,
    CrowdstrikeActionMonitorIOC,
    CrowdstrikeActionPushIOCsBlock,
    CrowdstrikeActionPushIOCsDetect,
    CrowdstrikeActionSearchIndicators,
    CrowdstrikeActionUpdateIndicators,
)
from crowdstrike_falcon.event_stream_trigger import EventStreamTrigger
from crowdstrike_falcon.host_actions import (
    CrowdstrikeActionDeIsolateHosts,
    CrowdstrikeActionGetDeviceDetails,
    CrowdstrikeActionGetOnlineState,
    CrowdstrikeActionIsolateHosts,
    CrowdstrikeActionPerformHostAction,
    CrowdstrikeActionQueryDeviceLoginHistory,
    CrowdstrikeActionQueryDevicesByFilter,
)
from crowdstrike_falcon.incident_actions import (
    CrowdstrikeActionGetBehaviors,
    CrowdstrikeActionGetIncidents,
)
from crowdstrike_falcon.prevention_policy_actions import (
    CrowdstrikeActionCreatePreventionPolicies,
    CrowdstrikeActionDeletePreventionPolicies,
    CrowdstrikeActionGetPreventionPolicies,
    CrowdstrikeActionPerformPreventionPolicyAction,
    CrowdstrikeActionUpdatePreventionPolicies,
)

# from crowdstrike_falcon.asset_connectors.user_assets import CrowdstrikeUserAssetConnector
from crowdstrike_falcon.asset_connectors.device_assets import CrowdstrikeDeviceAssetConnector

if __name__ == "__main__":
    module = CrowdStrikeFalconModule()
    module.register_account_validator(CrowdstrikeFalconAccountValidator)
    # module.register(CrowdstrikeUserAssetConnector, "crowdstrike_falcon_user_asset_connector")
    module.register(CrowdstrikeDeviceAssetConnector, "crowdstrike_falcon_device_asset_connector")
    module.register(EventStreamTrigger, "event_stream_trigger")

    # IOC actions (existing)
    module.register(CrowdstrikeActionPushIOCsBlock, "push_iocs_block")
    module.register(CrowdstrikeActionPushIOCsDetect, "push_iocs_detect")
    module.register(CrowdstrikeActionBlockIOC, "block_ioc")
    module.register(CrowdstrikeActionMonitorIOC, "monitor_ioc")

    # Host actions (existing)
    module.register(CrowdstrikeActionIsolateHosts, "isolate_hosts")
    module.register(CrowdstrikeActionDeIsolateHosts, "deisolate_hosts")

    # Alert actions (existing)
    module.register(CrowdstrikeActionUpdateAlertStatus, "alert_update_status")
    module.register(CrowdstrikeActionCommentAlert, "alert_add_comment")

    # Alert actions (new)
    module.register(CrowdstrikeActionGetAlertsV2, "get_alerts_v2")

    # IOC actions (new)
    module.register(CrowdstrikeActionGetIOCActions, "ioc_get_actions")
    module.register(CrowdstrikeActionGetIndicatorsReport, "ioc_get_indicators_report")
    module.register(CrowdstrikeActionGetIndicators, "ioc_get_indicators")
    module.register(CrowdstrikeActionCreateIndicators, "ioc_create_indicators")
    module.register(CrowdstrikeActionDeleteIndicators, "ioc_delete_indicators")
    module.register(CrowdstrikeActionUpdateIndicators, "ioc_update_indicators")
    module.register(CrowdstrikeActionSearchIndicators, "ioc_search_indicators")

    # Incident actions (new)
    module.register(CrowdstrikeActionGetBehaviors, "get_behaviors")
    module.register(CrowdstrikeActionGetIncidents, "get_incidents")

    # Host actions (new)
    module.register(CrowdstrikeActionGetDeviceDetails, "get_device_details")
    module.register(CrowdstrikeActionPerformHostAction, "perform_host_action")
    module.register(CrowdstrikeActionQueryDevicesByFilter, "query_devices_by_filter")
    module.register(CrowdstrikeActionQueryDeviceLoginHistory, "query_device_login_history")
    module.register(CrowdstrikeActionGetOnlineState, "get_online_state")

    # Prevention Policy actions (new)
    module.register(CrowdstrikeActionPerformPreventionPolicyAction, "perform_prevention_policy_action")
    module.register(CrowdstrikeActionGetPreventionPolicies, "get_prevention_policies")
    module.register(CrowdstrikeActionCreatePreventionPolicies, "create_prevention_policies")
    module.register(CrowdstrikeActionDeletePreventionPolicies, "delete_prevention_policies")
    module.register(CrowdstrikeActionUpdatePreventionPolicies, "update_prevention_policies")

    module.run()
