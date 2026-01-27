import requests_mock

from crowdstrike_falcon import CrowdStrikeFalconModule
from crowdstrike_falcon.action import CrowdstrikeAction
from crowdstrike_falcon.prevention_policy_actions import (
    CrowdstrikeActionCreatePreventionPolicies,
    CrowdstrikeActionDeletePreventionPolicies,
    CrowdstrikeActionGetPreventionPolicies,
    CrowdstrikeActionPerformPreventionPolicyAction,
    CrowdstrikeActionUpdatePreventionPolicies,
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


OAUTH2_TOKEN_MOCK = {
    "access_token": "foo-token",
    "token_type": "bearer",
    "expires_in": 1799,
}


def test_perform_prevention_policy_action():
    action = configured_action(CrowdstrikeActionPerformPreventionPolicyAction)
    ids = ["policy1", "policy2"]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/policy/entities/prevention-actions/v1?action_name=enable",
            complete_qs=True,
            json={"resources": [{"id": "policy1", "enabled": True}, {"id": "policy2", "enabled": True}]},
        )

        action.run({"action_name": "enable", "ids": ids})

        assert mock.call_count == 2
        history = mock.request_history
        assert "action_name=enable" in history[1].url


def test_perform_prevention_policy_action_empty_ids():
    action = configured_action(CrowdstrikeActionPerformPreventionPolicyAction)
    action.run({"action_name": "enable", "ids": []})
    assert action._error is not None


def test_perform_prevention_policy_action_empty_action():
    action = configured_action(CrowdstrikeActionPerformPreventionPolicyAction)
    action.run({"action_name": "", "ids": ["policy1"]})
    assert action._error is not None


def test_get_prevention_policies():
    action = configured_action(CrowdstrikeActionGetPreventionPolicies)
    ids = ["policy1", "policy2"]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "GET",
            "https://my.fake.sekoia/policy/entities/prevention/v1",
            json={
                "resources": [
                    {"id": "policy1", "name": "Default Prevention", "enabled": True},
                    {"id": "policy2", "name": "Custom Prevention", "enabled": False},
                ]
            },
        )

        action.run({"ids": ids})

        assert mock.call_count == 2


def test_get_prevention_policies_empty_ids():
    action = configured_action(CrowdstrikeActionGetPreventionPolicies)
    action.run({"ids": []})
    assert action._error is not None


def test_create_prevention_policies():
    action = configured_action(CrowdstrikeActionCreatePreventionPolicies)
    resources = [{"name": "New Policy", "description": "Test policy", "platform_name": "Windows"}]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/policy/entities/prevention/v1",
            json={"resources": [{"id": "new-policy-1", "name": "New Policy", "enabled": False}]},
        )

        action.run({"resources": resources})

        assert mock.call_count == 2


def test_create_prevention_policies_empty():
    action = configured_action(CrowdstrikeActionCreatePreventionPolicies)
    action.run({"resources": []})
    assert action._error is not None


def test_delete_prevention_policies():
    action = configured_action(CrowdstrikeActionDeletePreventionPolicies)
    ids = ["policy1", "policy2"]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "DELETE",
            "https://my.fake.sekoia/policy/entities/prevention/v1",
            json={"resources": ids},
        )

        action.run({"ids": ids})

        assert mock.call_count == 2


def test_delete_prevention_policies_empty_ids():
    action = configured_action(CrowdstrikeActionDeletePreventionPolicies)
    action.run({"ids": []})
    assert action._error is not None


def test_update_prevention_policies():
    action = configured_action(CrowdstrikeActionUpdatePreventionPolicies)
    resources = [{"id": "policy1", "name": "Updated Policy", "description": "Updated description"}]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "PATCH",
            "https://my.fake.sekoia/policy/entities/prevention/v1",
            json={"resources": [{"id": "policy1", "name": "Updated Policy"}]},
        )

        action.run({"resources": resources})

        assert mock.call_count == 2


def test_update_prevention_policies_empty():
    action = configured_action(CrowdstrikeActionUpdatePreventionPolicies)
    action.run({"resources": []})
    assert action._error is not None
