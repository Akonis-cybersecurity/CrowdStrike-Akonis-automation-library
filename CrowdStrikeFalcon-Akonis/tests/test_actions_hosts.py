import requests_mock

from crowdstrike_falcon import CrowdStrikeFalconModule
from crowdstrike_falcon.action import CrowdstrikeAction
from crowdstrike_falcon.host_actions import (
    CrowdstrikeActionDeIsolateHosts,
    CrowdstrikeActionGetDeviceDetails,
    CrowdstrikeActionGetOnlineState,
    CrowdstrikeActionIsolateHosts,
    CrowdstrikeActionPerformHostAction,
    CrowdstrikeActionQueryDeviceLoginHistory,
    CrowdstrikeActionQueryDevicesByFilter,
)


def configured_action(action: CrowdstrikeAction):
    module = CrowdStrikeFalconModule()
    a = action(module)

    a.module.configuration = {
        "base_url": "https://my.fake.sekoia",
        "client_id": "my-client-id",
        "client_secret": "my-client-secret",
    }

    return a


def test_isolate_hosts_action():
    action = configured_action(CrowdstrikeActionIsolateHosts)
    ids = ["host1", "host2"]
    with requests_mock.Mocker() as mock:
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/oauth2/token",
            json={
                "access_token": "foo-token",
                "token_type": "bearer",
                "expires_in": 1799,
            },
        )
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/devices/entities/devices-actions/v2?action_name=contain",
            complete_qs=True,
            json={"ids": ids},
        )

        action.run({"ids": ids})

        history = mock.request_history
        assert mock.call_count == 2  # One call to OAUTH2 token, one call to isolate hosts
        assert "action_name=contain" in history[1].url


def test_deisolate_hosts_action():
    action = configured_action(CrowdstrikeActionDeIsolateHosts)
    ids = ["host1", "host2"]
    with requests_mock.Mocker() as mock:
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/oauth2/token",
            json={
                "access_token": "foo-token",
                "token_type": "bearer",
                "expires_in": 1799,
            },
        )
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/devices/entities/devices-actions/v2?action_name=lift_containment",
            complete_qs=True,
            json={"ids": ids},
        )

        action.run({"ids": ids})

        history = mock.request_history
        assert mock.call_count == 2  # One call to OAUTH2 token, one call to isolate hosts
        assert "action_name=lift_containment" in history[1].url


OAUTH2_TOKEN_MOCK = {
    "access_token": "foo-token",
    "token_type": "bearer",
    "expires_in": 1799,
}


def test_get_device_details():
    action = configured_action(CrowdstrikeActionGetDeviceDetails)
    ids = ["aid1", "aid2"]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/devices/entities/devices/v2",
            json={
                "resources": [
                    {"device_id": "aid1", "hostname": "host1"},
                    {"device_id": "aid2", "hostname": "host2"},
                ]
            },
        )

        action.run({"ids": ids})

        assert mock.call_count == 2


def test_get_device_details_empty_ids():
    action = configured_action(CrowdstrikeActionGetDeviceDetails)
    action.run({"ids": []})
    assert action._error is not None


def test_perform_host_action():
    action = configured_action(CrowdstrikeActionPerformHostAction)
    ids = ["host1", "host2"]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/devices/entities/devices-actions/v2?action_name=contain",
            complete_qs=True,
            json={"resources": [{"id": "host1"}, {"id": "host2"}]},
        )

        action.run({"ids": ids, "action_name": "contain"})

        assert mock.call_count == 2
        history = mock.request_history
        assert "action_name=contain" in history[1].url


def test_perform_host_action_invalid():
    action = configured_action(CrowdstrikeActionPerformHostAction)
    action.run({"ids": ["host1"], "action_name": "invalid_action"})
    assert action._error is not None


def test_perform_host_action_empty_ids():
    action = configured_action(CrowdstrikeActionPerformHostAction)
    action.run({"ids": [], "action_name": "contain"})
    assert action._error is not None


def test_query_devices_by_filter():
    action = configured_action(CrowdstrikeActionQueryDevicesByFilter)
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "GET",
            "https://my.fake.sekoia/devices/queries/devices-scroll/v1",
            json={"resources": ["aid1", "aid2", "aid3"]},
        )

        action.run({"filter": "platform_name:'Windows'", "limit": 10})

        assert mock.call_count == 2
        history = mock.request_history
        assert "filter=" in history[1].url
        assert "limit=10" in history[1].url


def test_query_device_login_history():
    action = configured_action(CrowdstrikeActionQueryDeviceLoginHistory)
    ids = ["aid1"]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/devices/entities/devices/login-history/v2",
            json={
                "resources": [
                    {"device_id": "aid1", "recent_logins": [{"user_name": "admin", "login_time": "2024-01-01"}]}
                ]
            },
        )

        action.run({"ids": ids})

        assert mock.call_count == 2


def test_query_device_login_history_empty_ids():
    action = configured_action(CrowdstrikeActionQueryDeviceLoginHistory)
    action.run({"ids": []})
    assert action._error is not None


def test_get_online_state():
    action = configured_action(CrowdstrikeActionGetOnlineState)
    ids = ["aid1", "aid2"]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "GET",
            "https://my.fake.sekoia/devices/entities/online-state/v1",
            json={
                "resources": [
                    {"id": "aid1", "state": "online"},
                    {"id": "aid2", "state": "offline"},
                ]
            },
        )

        action.run({"ids": ids})

        assert mock.call_count == 2


def test_get_online_state_empty_ids():
    action = configured_action(CrowdstrikeActionGetOnlineState)
    action.run({"ids": []})
    assert action._error is not None
