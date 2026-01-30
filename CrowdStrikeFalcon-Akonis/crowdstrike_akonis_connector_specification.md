# CrowdStrike Falcon Akonis - Integration Specification

## Table of Contents

- [Architecture](#architecture)
- [Specification](#specification)
- [Github](#github)
- [Repositories](#repositories)
- [Context](#context)
- [Connector](#connector)
- [Format](#format)
- [Documentation](#documentation)
- [Deliverable](#deliverable)
- [Implementation Notes](#implementation-notes)
- [Blockers & Dependencies](#blockers--dependencies)

---

# Architecture

## Commercial URL of the product

- https://api.eu-1.crowdstrike.com (default `base_url` in `manifest.json`)

## Type of technology

- Cloud (SaaS)

### Reason for choosing technology type

- The module description states CrowdStrike Falcon is a cloud-native cybersecurity platform.

## Product version (on-prem)

- N/A (Cloud only - SaaS platform)

### Prerequisites to use integration (module, plan, role, permission, etc.)

- **CrowdStrike Falcon API credentials**: `client_id` and `client_secret`
- **Base URL**: `base_url` (default `https://api.eu-1.crowdstrike.com`)
- **Event Stream access**: required to read datafeed streams
- **Alert API access**: required to enrich detections via `/alerts/entities/alerts/v2`
- **ThreatGraph API access**: required only if `ACTIVATE_VERTICLES_COLLECTION=true`

## Detection use-case

- **Pass-through**: events are forwarded as received from the CrowdStrike Event Stream.

## Available event types

- **Event Stream detections** (streamed events from CrowdStrike datafeed)
- **ThreatGraph vertices** (optional enrichment when enabled)

## Chosen event types

| Event type | Description |
| --- | --- |
| Event Stream | Raw detection events read from the datafeed stream |
| Vertex | ThreatGraph vertices linked to detections/alerts (optional) |

## Chosen event fields

### Vertex wrapper fields (added by the connector)

| Field name | Description | Type | Mandatory |
| --- | --- | --- | --- |
| metadata.detectionIdString | Detection or alert identifier | string | Yes |
| metadata.eventType | Fixed value `Vertex` | string | Yes |
| metadata.edge.sourceVertexId | Source vertex identifier | string | Yes |
| metadata.edge.type | Edge type | string | Yes |
| metadata.severity.name | Severity name from detection event | string | No |
| metadata.severity.code | Severity code from detection event | integer | No |
| event | Vertex payload from ThreatGraph | object | Yes |

---

# Specification

## Github

*Github link*: https://github.com/SEKOIA-IO/automation-library

## Repositories

Location of the module: https://github.com/SEKOIA-IO/automation-library

---

# Context

### Product version

- Module version: `0.0.2` (from `manifest.json`)
- API version: not specified in the module

### Vendor description

CrowdStrike Falcon is a cloud-native cybersecurity platform known for its advanced threat detection, endpoint protection, and real-time response capabilities.

### Integration

*This integration collects CrowdStrike Falcon Event Stream detections and optionally enriches them with ThreatGraph vertices.*

*This development consists of:*

- *A connector to read the Event Stream datafeed and forward events to Sekoia intake*
- *Two asset connectors to collect device/user inventory into OCSF models*
- *A set of actions to interact with alerts, hosts, incidents, IOCs, and prevention policies*

---

# Connector

## Description

The module contains three runtime components:

1. **Event Stream Trigger** (`event_stream_trigger`)
   - Reads datafeed streams returned by `/sensors/entities/datafeed/v2`.
   - Refreshes streams using `refreshActiveSessionURL`.
   - Forwards events to Sekoia intake in batches.
   - Stores per-stream offsets in `cache.json`.
   - Optional ThreatGraph vertex enrichment controlled by `ACTIVATE_VERTICLES_COLLECTION`.

2. **Device Asset Connector** (`crowdstrike_falcon_device_asset_connector`)
   - Collects device inventory and maps to OCSF `Device Inventory Info`.
   - Uses checkpoint `most_recent_device_id` in `context.json`.

3. **User Asset Connector** (`crowdstrike_falcon_user_asset_connector`)
   - Collects user inventory and maps to OCSF `User Inventory Info`.
   - Uses checkpoint `most_recent_user_id` in `context.json`.
   - Present in code but not registered in `main.py`.

## Access

### Type of authentication

- [X] OAuth 2.0 (Client ID / Client Secret)

### Authentication credentials required

**Module-level configuration:**
- `client_id`
- `client_secret`
- `base_url`

**Connector-level configuration (Event Stream):**
- `intake_key`

**Connector-level configuration (Assets):**
- `sekoia_api_key` (required)
- `sekoia_base_url` (optional)
- `frequency` (optional)
- `batch_size` (optional)

## Credentials

Example configuration (based on module and connector schemas):

```yaml
# Module configuration
client_id: "..."
client_secret: "..."
base_url: "https://api.eu-1.crowdstrike.com"

# Event Stream connector
intake_key: "..."

# Asset connector (device/user)
sekoia_api_key: "..."
sekoia_base_url: "https://api.sekoia.io"  # optional
frequency: 60                              # optional
batch_size: 100                            # optional
```

## Authentication

### OAuth2 token retrieval

The module authenticates against:

```
POST {base_url}/oauth2/token
```

The connector stores and refreshes credentials automatically, renewing when less than 5 minutes remain before expiration.

### Event Stream authentication

The datafeed stream uses a session token returned by the datafeed API:

```
Authorization: Token <sessionToken.token>
```

## Get events

### Event Stream datafeed

**List streams:**
```
GET /sensors/entities/datafeed/v2?appId=<app_id>
```

**Read stream:**
```
GET <dataFeedURL>
Authorization: Token <sessionToken.token>
```

**Refresh stream:**
```
POST <refreshActiveSessionURL>
{
  "action_name": "refresh_active_stream_session",
  "appId": "<app_id>"
}
```

### Enrichment APIs (optional)

- **Alert details:** `POST /alerts/entities/alerts/v2`
- **Detection summaries (fallback):** `POST /detects/entities/summaries/GET/v1`
- **ThreatGraph edge types:** `GET /threatgraph/queries/edge-types/v1`
- **ThreatGraph edges:** `GET /threatgraph/combined/edges/v1`
- **ThreatGraph vertices:** `GET /threatgraph/entities/{verticle_type}/v1`

## Actions

### Actions available

The following actions are defined in `action_*.json` files:

| Action | Slug | Docker parameters | Description |
| --- | --- | --- | --- |
| Add new comment to alert | `add_new_comment_to_alert` | `alert_add_comment` | Appends a new comment to any existing comments for the specified alerts. |
| Update alert status | `update_alert_status` | `alert_update_status` | Update the status for the specified alerts. |
| Block IOC | `block_ioc` | `block_ioc` | Block the provided IOC. |
| Create Prevention Policies | `create_prevention_policies` | `create_prevention_policies` | Create Prevention Policies by specifying details about the policy to create. |
| Deisolate hosts | `deisolate_endpoints` | `deisolate_hosts` | Lifts containment on the host and returns its network communications to normal. |
| Delete Prevention Policies | `delete_prevention_policies` | `delete_prevention_policies` | Delete a set of Prevention Policies by specifying their IDs. |
| Get Alerts V2 | `get_alerts_v2` | `get_alerts_v2` | Retrieve all alerts given their composite IDs. |
| Get Behaviors | `get_behaviors` | `get_behaviors` | Get details on behaviors by providing behavior IDs. |
| Get Device Details | `get_device_details` | `get_device_details` | Get details on one or more hosts by providing agent IDs (AID). |
| Get Incidents | `get_incidents` | `get_incidents` | Get details on incidents by providing incident IDs. |
| Get Online State | `get_online_state` | `get_online_state` | Get the online status for one or more hosts by specifying each host's unique ID. |
| Get Prevention Policies | `get_prevention_policies` | `get_prevention_policies` | Retrieve a set of Prevention Policies by specifying their IDs. |
| Create Indicators | `create_indicators` | `ioc_create_indicators` | Create Indicators. |
| Delete Indicators | `delete_indicators` | `ioc_delete_indicators` | Delete Indicators by IDs. |
| Get IOC Actions | `get_ioc_actions` | `ioc_get_actions` | Get Actions by IDs. |
| Get Indicators | `get_indicators` | `ioc_get_indicators` | Get Indicators by IDs. |
| Get Indicators Report | `get_indicators_report` | `ioc_get_indicators_report` | Launch an indicators report creation job. |
| Search Indicators | `search_indicators` | `ioc_search_indicators` | Search for Indicators. |
| Update Indicators | `update_indicators` | `ioc_update_indicators` | Update Indicators. |
| Isolate hosts | `isolate_endpoints` | `isolate_hosts` | Contains the host and stops any network communications to locations other than the CrowdStrike cloud and IPs specified in your containment policy. |
| Monitor IOC | `monitor_ioc` | `monitor_ioc` | Enable detection for the provided IOC. |
| Perform Host Action | `perform_host_action` | `perform_host_action` | Take various actions on the hosts in your environment. Contain or lift containment on a host. Delete or restore a host. |
| Perform Prevention Policy Action | `perform_prevention_policy_action` | `perform_prevention_policy_action` | Perform the specified action on the Prevention Policies specified in the request. |
| Push IOCs for prevention | `push_iocs_for_prevention` | `push_iocs_block` | Block the provided IOCs: md5 / sha256 file hashes. |
| Push IOCs for detection | `push_iocs_for_detection` | `push_iocs_detect` | Enable detections on the provided IOCs: md5 / sha256 file hashes, IPv4/v6 address, domains. |
| Query Device Login History | `query_device_login_history` | `query_device_login_history` | Retrieve details about recent login sessions for a set of devices. |
| Query Devices By Filter | `query_devices_by_filter` | `query_devices_by_filter` | Search for hosts in your environment by platform, hostname, IP, and other criteria. |
| Update Prevention Policies | `update_prevention_policies` | `update_prevention_policies` | Update Prevention Policies by specifying the ID of the policy and details to update. |

### Action arguments

Each action below lists its input arguments (from the JSON schema in the module).

#### Add new comment to alert (`action_alert_add_comment.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of alert IDs to apply action to. |
| comment | string | Yes | New comment to add to the alert. |

#### Update alert status (`action_alert_update_status.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of alert IDs to apply action to. |
| new_status | string | Yes | The new status to apply to the alerts. |

#### Block IOC (`action_block_ioc.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| value | string | Yes | The value of the IOC to block. |
| type | string | Yes | Type of the IOC to block: md5, sha256. |

#### Create Prevention Policies (`action_create_prevention_policies.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| resources | array | Yes | List of prevention policy objects to create. Each object should contain name, description, platform_name, etc. |

#### Deisolate hosts (`action_deisolate_hosts.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of host agent IDs to apply action to. |

#### Delete Prevention Policies (`action_delete_prevention_policies.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of prevention policy IDs to delete. |

#### Get Alerts V2 (`action_get_alerts_v2.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of composite alert IDs to retrieve. |

#### Get Behaviors (`action_get_behaviors.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of behavior IDs to retrieve. |

#### Get Device Details (`action_get_device_details.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of host agent IDs (AIDs) to retrieve details for. Maximum: 5000. |

#### Get Incidents (`action_get_incidents.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of incident IDs to retrieve. |

#### Get Online State (`action_get_online_state.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of host agent IDs to get online state for. |

#### Get Prevention Policies (`action_get_prevention_policies.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of prevention policy IDs to retrieve. |

#### Create Indicators (`action_ioc_create_indicators.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| indicators | array | Yes | List of indicator objects to create. Each object should contain type, value, action, platforms, severity, etc. |

#### Delete Indicators (`action_ioc_delete_indicators.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of indicator IDs to delete. |

#### Get IOC Actions (`action_ioc_get_actions.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of action IDs to retrieve. |

#### Get Indicators (`action_ioc_get_indicators.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of indicator IDs to retrieve. |

#### Get Indicators Report (`action_ioc_get_indicators_report.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| report_format | string | No | Report format. Default: csv. |
| search | object | No | Search criteria for the report (FQL filter, query, sort, etc.). |

#### Search Indicators (`action_ioc_search_indicators.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| filter | string | No | FQL filter expression to search indicators. |
| sort | string | No | Sort expression (e.g. `modified_on|desc`). |
| limit | integer | No | Maximum number of results to return. |
| offset | string | No | Pagination offset. |

#### Update Indicators (`action_ioc_update_indicators.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| indicators | array | Yes | List of indicator objects to update. Each object should contain id and the fields to update. |

#### Isolate hosts (`action_isolate_hosts.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of host agent IDs to apply action to. |

#### Monitor IOC (`action_monitor_ioc.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| value | string | Yes | The value of the IOC to monitor. |
| type | string | Yes | Type of the IOC to monitor: md5, sha256, domain, ipv4, ipv6. |

#### Perform Host Action (`action_perform_host_action.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of host agent IDs to apply action to. |
| action_name | string | Yes | Action to perform on the hosts. |

#### Perform Prevention Policy Action (`action_perform_prevention_policy_action.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| action_name | string | Yes | Action to perform on the prevention policies. |
| ids | array | Yes | List of prevention policy IDs to apply action to. |

#### Push IOCs for prevention (`action_push_iocs_block.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| stix_objects_path | string | Yes | Filepath of the STIX objects fetched from the collection. |
| sekoia_base_url | string | No | Optional Sekoia base URL used to generate links to IOCs. |

#### Push IOCs for detection (`action_push_iocs_detect.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| stix_objects_path | string | Yes | Filepath of the STIX objects fetched from the collection. |
| sekoia_base_url | string | No | Optional Sekoia base URL used to generate links to IOCs. |
| valid_for | integer | No | If set, remove IOCs older than `valid_for` days (based on last modified date). |

#### Query Device Login History (`action_query_device_login_history.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| ids | array | Yes | List of device IDs to retrieve login history for. |

#### Query Devices By Filter (`action_query_devices_by_filter.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| filter | string | No | FQL filter expression to search devices (e.g. `platform_name:'Windows'`). |
| sort | string | No | Sort expression (e.g. `hostname|asc`). |
| limit | integer | No | Maximum number of results to return. |
| offset | string | No | Pagination offset. |

#### Update Prevention Policies (`action_update_prevention_policies.json`)

| Field | Type | Mandatory | Description |
| --- | --- | --- | --- |
| resources | array | Yes | List of prevention policy objects to update. Each object should contain id and the fields to update. |

## Pagination

The API client supports pagination based on the response `meta.pagination`:

- **Cursor-based**: `after` parameter if present
- **Offset-based**: `offset`, `limit`, `total`

If no pagination data is returned, the client stops after the first response.

## Rate-limit

Client-side limits and retries defined in the module:

- **Auth API rate limit**: 10 requests/second (LimiterAdapter in `auth.py`)
- **API client rate limit**: 100 requests/second (LimiterAdapter in `client/__init__.py`)
- **Retry policy**: total 5 retries, backoff factor 1
- **Retry-After handling**: supports `Retry-After` and `X-RateLimit-RetryAfter`
- **Event stream 429 handling**: sleep 60 seconds before retry (in `EventStreamTrigger`)

## Timestepper

- Stream refresh interval is derived from `refreshActiveSessionInterval` returned by the API.
- Event stream reader runs continuously; offsets are stored per stream.

## Checkpoint

### Event Stream

Checkpoint data stored in `cache.json` (per stream root URL):

```json
{
  "<stream_root_url>": "<last_offset>"
}
```

### Asset Connectors

Checkpoint data stored in `context.json`:

```json
{
  "most_recent_device_id": "<device_uuid>",
  "most_recent_user_id": "<user_uuid>"
}
```

## Cache

- Event stream offsets are cached in `cache.json`.
- Asset connector checkpoints are stored in `context.json`.

---

# Format

No parser or intake format files are included in this module.

---

# Documentation

No documentation files are included in this module.

---

# Deliverable

## automation-library

Directory structure in `CrowdStrikeFalcon Akonis/`:

```
CrowdStrikeFalcon Akonis/
├── main.py
├── manifest.json
├── connector_event_stream.json
├── trigger_event_stream.json
├── connector_crowdstrike_device_assets.json
├── _connector_crowdstrike_user_assets.json
├── action_*.json (29 action definitions)
├── crowdstrike_falcon/
│   ├── __init__.py
│   ├── account_validator.py
│   ├── action.py
│   ├── alert_actions.py
│   ├── asset_connectors/
│   │   ├── device_assets.py
│   │   └── user_assets.py
│   ├── client/
│   │   ├── __init__.py
│   │   ├── auth.py
│   │   ├── retry.py
│   │   └── schemas.py
│   ├── custom_iocs.py
│   ├── event_stream_trigger.py
│   ├── exceptions.py
│   ├── helpers.py
│   ├── host_actions.py
│   ├── incident_actions.py
│   ├── logging.py
│   ├── metrics.py
│   ├── models.py
│   └── prevention_policy_actions.py
└── tests/
```

---

# Implementation Notes

## Event Stream behavior

- Uses `EventStreamTrigger` with multiple reader threads (one per stream URL).
- Forwarding is batched up to 1000 events per batch.
- Offsets are persisted per stream to resume after restart.
- Alert API is attempted first; on 403 it falls back to detection API.
- ThreatGraph vertex collection is enabled only when `ACTIVATE_VERTICLES_COLLECTION=true`.

## Asset connectors

- Device connector maps to OCSF `Device Inventory Info` (class UID 5001).
- User connector maps to OCSF `User Inventory Info` (class UID 5003).
- Both connectors track the most recent ID to avoid reprocessing.

---

# Blockers & Dependencies

## Required inputs

- `client_id` and `client_secret` for CrowdStrike Falcon API
- Access to Event Stream datafeed
- `intake_key` to forward events to Sekoia intake

## Optional dependencies

- Alert API permissions for enrichment
- ThreatGraph API permissions for vertex collection

---

**End of Specification**
