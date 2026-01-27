import requests_mock

from crowdstrike_falcon import CrowdStrikeFalconModule
from crowdstrike_falcon.action import CrowdstrikeAction
from crowdstrike_falcon.incident_actions import CrowdstrikeActionGetBehaviors, CrowdstrikeActionGetIncidents


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


def test_get_behaviors():
    action = configured_action(CrowdstrikeActionGetBehaviors)
    ids = ["behavior1", "behavior2"]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/incidents/entities/behaviors/GET/v1",
            json={
                "resources": [
                    {"behavior_id": "behavior1", "tactic": "Persistence"},
                    {"behavior_id": "behavior2", "tactic": "Execution"},
                ]
            },
        )

        action.run({"ids": ids})

        assert mock.call_count == 2


def test_get_behaviors_empty_ids():
    action = configured_action(CrowdstrikeActionGetBehaviors)
    action.run({"ids": []})
    assert action._error is not None


def test_get_incidents():
    action = configured_action(CrowdstrikeActionGetIncidents)
    ids = ["inc:abc123:1234567890", "inc:def456:9876543210"]
    with requests_mock.Mocker() as mock:
        mock.register_uri("POST", "https://my.fake.sekoia/oauth2/token", json=OAUTH2_TOKEN_MOCK)
        mock.register_uri(
            "POST",
            "https://my.fake.sekoia/incidents/entities/incidents/GET/v1",
            json={
                "resources": [
                    {"incident_id": "inc:abc123:1234567890", "status": 20},
                    {"incident_id": "inc:def456:9876543210", "status": 25},
                ]
            },
        )

        action.run({"ids": ids})

        assert mock.call_count == 2


def test_get_incidents_empty_ids():
    action = configured_action(CrowdstrikeActionGetIncidents)
    action.run({"ids": []})
    assert action._error is not None
