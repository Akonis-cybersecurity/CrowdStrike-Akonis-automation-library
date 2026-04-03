# CrowdStrike Falcon Akonis - Connector Specification

## Table of Contents

- [Overview](#overview)
- [Module Configuration](#module-configuration)
- [Connectors & Triggers](#connectors--triggers)
- [Actions](#actions)
  - [Alert Actions](#alert-actions)
  - [Host Actions](#host-actions)
  - [Incident Actions](#incident-actions)
  - [IOC Actions](#ioc-actions)
  - [Prevention Policy Actions](#prevention-policy-actions)
- [Architecture](#architecture)
- [Rate Limits & Retry Policy](#rate-limits--retry-policy)

---

## Overview

**Module name:** CrowdStrike Falcon
**Slug:** `crowdstrike-falcon`
**Version:** 0.0.3
**Category:** Endpoint

CrowdStrike Falcon is a cloud-native cybersecurity platform known for its advanced threat detection, endpoint protection, and real-time response capabilities. It leverages AI and machine learning to protect against malware and sophisticated cyberattacks.

This Sekoia integration module provides:

- An **Event Stream trigger** to collect CrowdStrike Falcon detection events
- A **Device Asset connector** to synchronize device inventory
- **27 playbook actions** to interact with alerts, hosts, incidents, IOCs, and prevention policies

---

## Module Configuration

Authentication uses OAuth 2.0 (Client ID / Client Secret). The module authenticates against `POST {base_url}/oauth2/token` and automatically renews tokens when less than 5 minutes remain before expiration.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `client_id` | string | Yes | - | CrowdStrike API Client Identifier |
| `client_secret` | string | Yes | - | CrowdStrike API Client Secret (stored as a secret) |
| `base_url` | string (URI) | Yes | `https://api.eu-1.crowdstrike.com` | Base URL of the CrowdStrike API |

---

## Connectors & Triggers

### Event Stream Trigger

| Property | Value |
|---|---|
| **Name** | Fetch CrowdStrike Falcon Events |
| **Docker parameter** | `event_stream_trigger` |
| **Description** | Reads datafeed streams from `/sensors/entities/datafeed/v2`, refreshes sessions, and forwards events to Sekoia intake in batches of up to 1000 events. Stores per-stream offsets in `cache.json`. Optional ThreatGraph vertex enrichment via `ACTIVATE_VERTICLES_COLLECTION` env var. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `intake_key` | string | Yes | Intake key to use when sending events to Sekoia |

---

### Device Asset Connector

| Property | Value |
|---|---|
| **Name** | Crowdstrike Falcon devices |
| **Docker parameter** | `crowdstrike_falcon_device_asset_connector` |
| **Type** | Asset (device capability) |
| **Description** | Fetches CrowdStrike Falcon device assets and maps them to OCSF Device Inventory Info (class UID 5001). Uses `most_recent_device_id` checkpoint in `context.json`. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `sekoia_api_key` | string | Yes | API key from sekoia.io (stored as a secret) |
| `sekoia_base_url` | string | No | Sekoia base URL |
| `frequency` | integer | No | Batch frequency in seconds |
| `batch_size` | integer | No | Batch size for each request |

---

### User Asset Connector (not registered)

| Property | Value |
|---|---|
| **Name** | Crowdstrike Falcon users |
| **Docker parameter** | `crowdstrike_falcon_user_asset_connector` |
| **Type** | Asset (user capability) |
| **Description** | Fetches CrowdStrike Falcon user assets and maps them to OCSF User Inventory Info (class UID 5003). Present in code but **not registered** in `main.py`. |

**Arguments:** Same as Device Asset Connector.

---

## Actions

### Alert Actions

#### Add New Comment to Alert

| Property | Value |
|---|---|
| **Name** | Add new comment to alert |
| **Slug** | `add_new_comment_to_alert` |
| **Docker parameter** | `alert_add_comment` |
| **UUID** | `b85ef7ca-7be9-4345-97df-fbb0c3f63353` |
| **API endpoint** | `PATCH /alerts/entities/alerts/v3` |
| **Description** | Appends a new comment to any existing comments for the specified alerts. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of alert IDs to apply the action to |
| `comment` | string | Yes | New comment to add to the alert |

**Results:** None (void action).

---

#### Update Alert Status

| Property | Value |
|---|---|
| **Name** | Update alert status |
| **Slug** | `update_alert_status` |
| **Docker parameter** | `alert_update_status` |
| **UUID** | `3d8c3167-d059-4d12-958e-6071572c0b41` |
| **API endpoint** | `PATCH /alerts/entities/alerts/v3` |
| **Description** | Updates the status for the specified alerts. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of alert IDs to apply the action to |
| `new_status` | string (enum) | Yes | The new status to apply. Allowed values: `new`, `in_progress`, `closed`, `reopened` |

**Results:** None (void action).

---

#### Get Alerts V2

| Property | Value |
|---|---|
| **Name** | Get Alerts V2 |
| **Slug** | `get_alerts_v2` |
| **Docker parameter** | `get_alerts_v2` |
| **UUID** | `6a8cc908-c563-400b-9d60-c78cf30f6abf` |
| **API endpoint** | `POST /alerts/entities/alerts/v2` |
| **Description** | Retrieves all alerts given their composite IDs. Returns parsed alert fields for SOC triage including MITRE ATT&CK mappings, process details, device information, and parent/grandparent process context. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of composite alert IDs to retrieve |

**Results:**

| Field | Type | Description |
|---|---|---|
| `success` | boolean | Whether the operation succeeded |
| `parsed.alerts` | array of objects | Parsed alert fields (see below) |
| `results` | array of objects | Raw API results |

<details>
<summary>Parsed alert fields</summary>

Each alert object may contain the following fields:

| Field | Type | Description |
|---|---|---|
| `id` | string | Alert ID |
| `composite_id` | string | Composite alert ID |
| `aggregate_id` | string | Aggregate ID |
| `indicator_id` | string | Indicator ID |
| `cid` | string | Customer ID |
| `agent_id` | string | Agent ID |
| `device_id` | string | Device ID |
| `status` | string | Alert status |
| `severity` | number | Severity score |
| `severity_name` | string | Severity label |
| `confidence` | number | Confidence score |
| `priority_value` | number | Priority value |
| `tactic` | string | MITRE tactic name |
| `tactic_id` | string | MITRE tactic ID |
| `technique` | string | MITRE technique name |
| `technique_id` | string | MITRE technique ID |
| `mitre_attack` | array | List of MITRE ATT&CK tactic/technique pairs |
| `timestamp` | string | Event timestamp |
| `created_timestamp` | string | Alert creation timestamp |
| `updated_timestamp` | string | Last update timestamp |
| `cmdline` | string | Command line of the triggering process |
| `filename` | string | Filename of the triggering process |
| `filepath` | string | File path of the triggering process |
| `md5` | string | MD5 hash of the file |
| `sha1` | string | SHA1 hash of the file |
| `sha256` | string | SHA256 hash of the file |
| `process_id` | string | Process ID |
| `parent_process_id` | string | Parent process ID |
| `user_name` | string | User name |
| `device` | object | Device info (hostname, platform, IPs, agent version) |
| `parent_details` | object | Parent process details (filename, cmdline, user) |
| `grandparent_details` | object | Grandparent process details |
| `description` | string | Alert description |
| `display_name` | string | Display name |
| `scenario` | string | Detection scenario |
| `falcon_host_link` | string | Direct link to Falcon console |
| `comments` | array | List of comments on the alert |

</details>

---

### Host Actions

#### Isolate Hosts

| Property | Value |
|---|---|
| **Name** | Isolate hosts |
| **Slug** | `isolate_endpoints` |
| **Docker parameter** | `isolate_hosts` |
| **UUID** | `2ab45e20-efa0-4483-a6d3-5cbfa4bd5621` |
| **API endpoint** | `POST /devices/entities/devices-actions/v2?action_name=contain` |
| **Description** | Contains the host and stops any network communications to locations other than the CrowdStrike cloud and IPs specified in your containment policy. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of host agent IDs to isolate |

**Results:** None (void action).

---

#### Deisolate Hosts

| Property | Value |
|---|---|
| **Name** | Deisolate hosts |
| **Slug** | `deisolate_endpoints` |
| **Docker parameter** | `deisolate_hosts` |
| **UUID** | `ee32894a-f2bc-4f4f-aba4-0d518adf2521` |
| **API endpoint** | `POST /devices/entities/devices-actions/v2?action_name=lift_containment` |
| **Description** | Lifts containment on the host and returns its network communications to normal. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of host agent IDs to deisolate |

**Results:** None (void action).

---

#### Perform Host Action

| Property | Value |
|---|---|
| **Name** | Perform Host Action |
| **Slug** | `perform_host_action` |
| **Docker parameter** | `perform_host_action` |
| **UUID** | `54b1456c-b891-4f5a-a0a4-59fe3c940f4e` |
| **API endpoint** | `POST /devices/entities/devices-actions/v2?action_name={action}` |
| **Description** | Takes various actions on the hosts in your environment. Contain or lift containment on a host. Delete or restore a host. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of host agent IDs to apply the action to |
| `action_name` | string (enum) | Yes | Action to perform. Allowed values: `contain`, `lift_containment`, `hide_host`, `unhide_host` |

**Results:**

| Field | Type | Description |
|---|---|---|
| `resources` | array of objects | Action result resources |

---

#### Get Device Details

| Property | Value |
|---|---|
| **Name** | Get Device Details |
| **Slug** | `get_device_details` |
| **Docker parameter** | `get_device_details` |
| **UUID** | `9c649c35-d636-471c-8fb2-5985ce4c32a2` |
| **API endpoint** | `POST /devices/entities/devices/v2` |
| **Description** | Gets details on one or more hosts by providing agent IDs (AID). Maximum 5000 IDs per request. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of host agent IDs (AIDs) to retrieve details for. Maximum: 5000. |

**Results:**

| Field | Type | Description |
|---|---|---|
| `success` | boolean | Whether the operation succeeded |
| `parsed.devices` | array of objects | Parsed device fields (see below) |
| `results` | array of objects | Raw API results |

<details>
<summary>Parsed device fields</summary>

Each device object may contain the following fields:

| Field | Type | Description |
|---|---|---|
| `device_id` | string | Device identifier |
| `cid` | string | Customer ID |
| `hostname` | string | Device hostname |
| `status` | string | Device status |
| `tags` | array | Device tags |
| `groups` | array | Host groups |
| `local_ip` | string | Local IP address |
| `external_ip` | string | External IP address |
| `connection_ip` | string | Connection IP |
| `mac_address` | string | MAC address |
| `platform_name` | string | Platform name (Windows, Mac, Linux) |
| `os_version` | string | OS version |
| `os_build` | string | OS build number |
| `kernel_version` | string | Kernel version |
| `last_seen` | string | Last seen timestamp |
| `first_seen` | string | First seen timestamp |
| `last_reboot` | string | Last reboot timestamp |
| `agent_version` | string | Falcon agent version |
| `rtr_state` | string | Real-time response state |
| `provision_status` | string | Provisioning status |
| `filesystem_containment_status` | string | Containment status |
| `reduced_functionality_mode` | string | Reduced functionality mode |
| `last_login_user` | string | Last logged-in user |
| `last_login_timestamp` | string | Last login timestamp |
| `machine_domain` | string | Machine domain |
| `product_type_desc` | string | Product type (Server, Workstation) |
| `chassis_type_desc` | string | Chassis type |
| `bios_version` | string | BIOS version |
| `system_manufacturer` | string | System manufacturer |
| `serial_number` | string | Serial number |
| `policies` | array | Applied policies with IDs, types, and dates |
| `device_policies` | array | Device-specific policies |

</details>

---

#### Get Online State

| Property | Value |
|---|---|
| **Name** | Get Online State |
| **Slug** | `get_online_state` |
| **Docker parameter** | `get_online_state` |
| **UUID** | `5f1c83b9-5fd9-4471-9ebb-7eff65ec7db2` |
| **API endpoint** | `GET /devices/entities/online-state/v1` |
| **Description** | Gets the online status for one or more hosts by specifying each host's unique ID. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of host agent IDs to get online state for |

**Results:**

| Field | Type | Description |
|---|---|---|
| `success` | boolean | Whether the operation succeeded |
| `parsed.states` | array of objects | List of `{id, state}` objects |
| `results` | array of objects | Raw API results |

---

#### Query Devices By Filter

| Property | Value |
|---|---|
| **Name** | Query Devices By Filter |
| **Slug** | `query_devices_by_filter` |
| **Docker parameter** | `query_devices_by_filter` |
| **UUID** | `fd407e07-efde-4ac7-b3e7-481075718de3` |
| **API endpoint** | `GET /devices/queries/devices-scroll/v1` |
| **Description** | Searches for hosts in your environment by platform, hostname, IP, and other criteria using FQL filters. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `filter` | string | No | FQL filter expression (e.g. `platform_name:'Windows'`) |
| `sort` | string | No | Sort expression (e.g. `hostname\|asc`) |
| `limit` | integer | No | Maximum number of results to return |
| `offset` | string | No | Pagination offset |

**Results:**

| Field | Type | Description |
|---|---|---|
| `device_ids` | array of strings | List of matching device IDs |

---

#### Query Device Login History

| Property | Value |
|---|---|
| **Name** | Query Device Login History |
| **Slug** | `query_device_login_history` |
| **Docker parameter** | `query_device_login_history` |
| **UUID** | `157aa15e-fe78-4bd7-9b79-372d587532fe` |
| **API endpoint** | `POST /devices/entities/devices/login-history/v2` |
| **Description** | Retrieves details about recent login sessions for a set of devices. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of device IDs to retrieve login history for |

**Results:**

| Field | Type | Description |
|---|---|---|
| `history` | array of objects | List of login history records |

---

### Incident Actions

#### Get Behaviors

| Property | Value |
|---|---|
| **Name** | Get Behaviors |
| **Slug** | `get_behaviors` |
| **Docker parameter** | `get_behaviors` |
| **UUID** | `bfa4f389-834f-4357-acd8-5f593d9bd42b` |
| **API endpoint** | `POST /incidents/entities/behaviors/GET/v1` |
| **Description** | Gets details on behaviors by providing behavior IDs. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of behavior IDs to retrieve |

**Results:**

| Field | Type | Description |
|---|---|---|
| `behaviors` | array of objects | List of behavior details |

---

#### Get Incidents

| Property | Value |
|---|---|
| **Name** | Get Incidents |
| **Slug** | `get_incidents` |
| **Docker parameter** | `get_incidents` |
| **UUID** | `18f0e733-b279-41a0-919e-3fe805c2d434` |
| **API endpoint** | `POST /incidents/entities/incidents/GET/v1` |
| **Description** | Gets details on incidents by providing incident IDs. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of incident IDs to retrieve |

**Results:**

| Field | Type | Description |
|---|---|---|
| `incidents` | array of objects | List of incident details |

---

### IOC Actions

#### Block IOC

| Property | Value |
|---|---|
| **Name** | Block IOC |
| **Slug** | `block_ioc` |
| **Docker parameter** | `block_ioc` |
| **UUID** | `6e7ea4f7-2015-461f-97cd-d352eee29316` |
| **API endpoint** | `POST /iocs/entities/indicators/v1` |
| **Description** | Blocks the provided IOC by creating an indicator with `prevent` action. Supported types: `md5`, `sha256`. The indicator is applied globally with `high` severity on all platforms (mac, windows, linux). |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `value` | string | Yes | The value of the IOC to block (hash value) |
| `type` | string | Yes | Type of the IOC to block: `md5`, `sha256` |

**Results:** None (void action).

---

#### Monitor IOC

| Property | Value |
|---|---|
| **Name** | Monitor IOC |
| **Slug** | `monitor_ioc` |
| **Docker parameter** | `monitor_ioc` |
| **UUID** | `afe96fcb-6286-4488-8639-5a7e17d7ccd9` |
| **API endpoint** | `POST /iocs/entities/indicators/v1` |
| **Description** | Enables detection for the provided IOC by creating an indicator with `detect` action. Supported types: `md5`, `sha256`, `domain`, `ipv4`, `ipv6`. The indicator is applied globally with `high` severity on all platforms. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `value` | string | Yes | The value of the IOC to monitor |
| `type` | string | Yes | Type of the IOC: `md5`, `sha256`, `domain`, `ipv4`, `ipv6` |

**Results:** None (void action).

---

#### Push IOCs for Prevention

| Property | Value |
|---|---|
| **Name** | Push IOCs for prevention |
| **Slug** | `push_iocs_for_prevention` |
| **Docker parameter** | `push_iocs_block` |
| **UUID** | `daaf7465-3469-4cfb-84b5-26ee7e96c316` |
| **API endpoint** | `POST /iocs/entities/indicators/v1` (create) + `DELETE /iocs/entities/indicators/v1` (cleanup) |
| **Description** | Blocks the provided IOCs from a STIX bundle. Supports MD5 and SHA256 file hashes only. Before creating new indicators, expired and revoked indicators are automatically cleaned up. The action parses STIX patterns and maps them to CrowdStrike indicator format with `prevent` action. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `stix_objects_path` | string | Yes | File path of the STIX objects fetched from the collection |
| `sekoia_base_url` | string | No | Sekoia base URL used to generate direct links to IOCs (default: `https://app.sekoia.io`) |

**Results:** None (void action).

**Supported STIX-to-IOC mapping:**

| STIX Type | STIX Key | CrowdStrike Type |
|---|---|---|
| `file` | `hashes.MD5` | `md5` |
| `file` | `hashes.SHA-256` | `sha256` |

---

#### Push IOCs for Detection

| Property | Value |
|---|---|
| **Name** | Push IOCs for detection |
| **Slug** | `push_iocs_for_detection` |
| **Docker parameter** | `push_iocs_detect` |
| **UUID** | `08a8be72-6833-4aa8-8d81-c0a00c0eda97` |
| **API endpoint** | `POST /iocs/entities/indicators/v1` (create) + `DELETE /iocs/entities/indicators/v1` (cleanup) |
| **Description** | Enables detections on the provided IOCs from a STIX bundle. Supports MD5/SHA256 file hashes, IPv4/IPv6 addresses, and domains. Before creating new indicators, expired indicators and optionally old indicators (based on `valid_for`) are cleaned up. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `stix_objects_path` | string | Yes | File path of the STIX objects fetched from the collection |
| `sekoia_base_url` | string | No | Sekoia base URL used to generate direct links to IOCs (default: `https://app.sekoia.io`) |
| `valid_for` | integer | No | If set, removes IOCs older than `valid_for` days based on the last modified date in CrowdStrike. Minimum: 1 |

**Results:** None (void action).

**Supported STIX-to-IOC mapping:**

| STIX Type | STIX Key | CrowdStrike Type |
|---|---|---|
| `file` | `hashes.MD5` | `md5` |
| `file` | `hashes.SHA-256` | `sha256` |
| `ipv4-addr` | `value` | `ipv4` |
| `ipv6-addr` | `value` | `ipv6` |
| `domain-name` | `value` | `domain` |

---

#### Create Indicators

| Property | Value |
|---|---|
| **Name** | Create Indicators |
| **Slug** | `create_indicators` |
| **Docker parameter** | `ioc_create_indicators` |
| **UUID** | `c94f259b-5632-41e0-a189-15801c546fa6` |
| **API endpoint** | `POST /iocs/entities/indicators/v1` |
| **Description** | Creates custom IOC indicators in CrowdStrike Falcon. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `indicators` | array of objects | Yes | List of indicator objects to create. Each should contain `type`, `value`, `action`, `platforms`, `severity`, etc. |

**Results:**

| Field | Type | Description |
|---|---|---|
| `indicators` | array of objects | List of created indicators |

---

#### Get Indicators

| Property | Value |
|---|---|
| **Name** | Get Indicators |
| **Slug** | `get_indicators` |
| **Docker parameter** | `ioc_get_indicators` |
| **UUID** | `8cfb7bd8-8c59-42d8-9976-9f212892c5d8` |
| **API endpoint** | `GET /iocs/entities/indicators/v1` |
| **Description** | Retrieves indicators by their IDs. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of indicator IDs to retrieve |

**Results:**

| Field | Type | Description |
|---|---|---|
| `indicators` | array of objects | List of indicator details |

---

#### Update Indicators

| Property | Value |
|---|---|
| **Name** | Update Indicators |
| **Slug** | `update_indicators` |
| **Docker parameter** | `ioc_update_indicators` |
| **UUID** | `602bcddc-f951-4cf2-ab0c-a148caae261d` |
| **API endpoint** | `PATCH /iocs/entities/indicators/v1` |
| **Description** | Updates existing indicators by providing indicator objects with the fields to modify. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `indicators` | array of objects | Yes | List of indicator objects to update. Each should contain `id` and the fields to update. |

**Results:**

| Field | Type | Description |
|---|---|---|
| `indicators` | array of objects | List of updated indicators |

---

#### Delete Indicators

| Property | Value |
|---|---|
| **Name** | Delete Indicators |
| **Slug** | `delete_indicators` |
| **Docker parameter** | `ioc_delete_indicators` |
| **UUID** | `ed581520-1d3f-4260-a3d1-8ee74dbc0b4d` |
| **API endpoint** | `DELETE /iocs/entities/indicators/v1` |
| **Description** | Deletes indicators by their IDs. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of indicator IDs to delete |

**Results:** None (void action).

---

#### Search Indicators

| Property | Value |
|---|---|
| **Name** | Search Indicators |
| **Slug** | `search_indicators` |
| **Docker parameter** | `ioc_search_indicators` |
| **UUID** | `37870872-e1a4-4993-92ab-caba661e6750` |
| **API endpoint** | `GET /iocs/queries/indicators/v1` |
| **Description** | Searches for indicators using FQL filter expressions. Supports pagination and sorting. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `filter` | string | No | FQL filter expression to search indicators |
| `sort` | string | No | Sort expression (e.g. `modified_on\|desc`) |
| `limit` | integer | No | Maximum number of results to return |
| `offset` | string | No | Pagination offset |

**Results:**

| Field | Type | Description |
|---|---|---|
| `indicator_ids` | array of strings | List of matching indicator IDs |

---

#### Get IOC Actions

| Property | Value |
|---|---|
| **Name** | Get IOC Actions |
| **Slug** | `get_ioc_actions` |
| **Docker parameter** | `ioc_get_actions` |
| **UUID** | `dfdcd29e-dfd7-4f4e-9e65-f6f08d2fc108` |
| **API endpoint** | `GET /iocs/entities/actions/v1` |
| **Description** | Retrieves IOC action details by their IDs. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of action IDs to retrieve |

**Results:**

| Field | Type | Description |
|---|---|---|
| `actions` | array of objects | List of action details |

---

#### Get Indicators Report

| Property | Value |
|---|---|
| **Name** | Get Indicators Report |
| **Slug** | `get_indicators_report` |
| **Docker parameter** | `ioc_get_indicators_report` |
| **UUID** | `866b38ce-c6d2-4cce-85e3-00f641166102` |
| **API endpoint** | `POST /iocs/entities/indicators-report/v1` |
| **Description** | Launches an indicators report creation job. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `report_format` | string | No | Report format (default: `csv`) |
| `search` | object | No | Search criteria for the report (FQL filter, query, sort, etc.) |

**Results:**

| Field | Type | Description |
|---|---|---|
| `report` | array of objects | Report creation job result |

---

### Prevention Policy Actions

#### Get Prevention Policies

| Property | Value |
|---|---|
| **Name** | Get Prevention Policies |
| **Slug** | `get_prevention_policies` |
| **Docker parameter** | `get_prevention_policies` |
| **UUID** | `70e62ad3-1739-4e70-bf6f-83ad569d5684` |
| **API endpoint** | `GET /policy/entities/prevention/v1` |
| **Description** | Retrieves a set of Prevention Policies by specifying their IDs. Returns parsed policy fields including settings, groups, and IOA rule groups. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of prevention policy IDs to retrieve |

**Results:**

| Field | Type | Description |
|---|---|---|
| `success` | boolean | Whether the operation succeeded |
| `parsed.policies` | array of objects | Parsed policy fields (see below) |
| `results` | array of objects | Raw API results |

<details>
<summary>Parsed policy fields</summary>

Each policy object may contain the following fields:

| Field | Type | Description |
|---|---|---|
| `id` | string | Policy ID |
| `cid` | string | Customer ID |
| `name` | string | Policy name |
| `description` | string | Policy description |
| `enabled` | boolean | Whether the policy is enabled |
| `platform_name` | string | Target platform |
| `created_by` | string | Creator |
| `modified_by` | string | Last modifier |
| `created_timestamp` | string | Creation timestamp |
| `modified_timestamp` | string | Last modification timestamp |
| `groups` | array | Assigned host groups |
| `groups_count` | number | Number of assigned groups |
| `ioa_rule_groups` | array | IOA rule groups |
| `settings` | array | Flattened list of prevention settings per category (id, name, type, enabled, configured, detection, prevention) |

</details>

---

#### Create Prevention Policies

| Property | Value |
|---|---|
| **Name** | Create Prevention Policies |
| **Slug** | `create_prevention_policies` |
| **Docker parameter** | `create_prevention_policies` |
| **UUID** | `b040ed2d-2c0c-4f9e-882f-97cdd7a04fdd` |
| **API endpoint** | `POST /policy/entities/prevention/v1` |
| **Description** | Creates Prevention Policies by specifying details about the policy to create. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `resources` | array of objects | Yes | List of prevention policy objects to create. Each should contain `name`, `description`, `platform_name`, etc. |

**Results:**

| Field | Type | Description |
|---|---|---|
| `policies` | array of objects | List of created prevention policies |

---

#### Update Prevention Policies

| Property | Value |
|---|---|
| **Name** | Update Prevention Policies |
| **Slug** | `update_prevention_policies` |
| **Docker parameter** | `update_prevention_policies` |
| **UUID** | `fedff2b3-41cd-4e4f-a611-f61e425dd101` |
| **API endpoint** | `PATCH /policy/entities/prevention/v1` |
| **Description** | Updates Prevention Policies by specifying the ID of the policy and the details to update. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `resources` | array of objects | Yes | List of prevention policy objects to update. Each should contain `id` and the fields to update. |

**Results:**

| Field | Type | Description |
|---|---|---|
| `policies` | array of objects | List of updated prevention policies |

---

#### Delete Prevention Policies

| Property | Value |
|---|---|
| **Name** | Delete Prevention Policies |
| **Slug** | `delete_prevention_policies` |
| **Docker parameter** | `delete_prevention_policies` |
| **UUID** | `31f10154-9992-41af-86d7-5f1121c8e1ae` |
| **API endpoint** | `DELETE /policy/entities/prevention/v1` |
| **Description** | Deletes a set of Prevention Policies by specifying their IDs. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `ids` | array of strings | Yes | List of prevention policy IDs to delete |

**Results:** None (void action).

---

#### Perform Prevention Policy Action

| Property | Value |
|---|---|
| **Name** | Perform Prevention Policy Action |
| **Slug** | `perform_prevention_policy_action` |
| **Docker parameter** | `perform_prevention_policy_action` |
| **UUID** | `82a975c7-b8ad-4386-aa05-1b69ea52c3f5` |
| **API endpoint** | `POST /policy/entities/prevention-actions/v1?action_name={action}` |
| **Description** | Performs the specified action on the Prevention Policies. |

**Arguments:**

| Field | Type | Required | Description |
|---|---|---|---|
| `action_name` | string (enum) | Yes | Action to perform. Allowed values: `enable`, `disable` |
| `ids` | array of strings | Yes | List of prevention policy IDs to apply the action to |

**Results:**

| Field | Type | Description |
|---|---|---|
| `resources` | array of objects | Action result resources |

---

## Architecture

### Authentication Flow

1. The module authenticates via `POST {base_url}/oauth2/token` using `client_id` and `client_secret`
2. Tokens are cached and automatically renewed when less than 5 minutes remain before expiration
3. Auth API is rate-limited to 10 requests/second

### Pagination

The API client supports automatic pagination based on the response `meta.pagination`:

- **Cursor-based**: Uses `after` parameter when present
- **Offset-based**: Uses `offset`, `limit`, and `total` when cursor is not available
- Pagination stops when all results have been fetched or when no pagination metadata is returned

### Event Stream Flow

1. List streams via `GET /sensors/entities/datafeed/v2`
2. Read events from each stream URL using the session token
3. Refresh sessions using `refreshActiveSessionURL` at intervals from the API
4. Forward events to Sekoia intake in batches of up to 1000
5. Store per-stream offsets in `cache.json`
6. Optional alert enrichment via `POST /alerts/entities/alerts/v2` (falls back to detection API on 403)
7. Optional ThreatGraph vertex collection when `ACTIVATE_VERTICLES_COLLECTION=true`

---

## Rate Limits & Retry Policy

| Component | Limit | Details |
|---|---|---|
| Auth API | 10 req/s | LimiterAdapter on token endpoint |
| API client | 100 req/s | LimiterAdapter on all API calls |
| Retry policy | 5 retries | Backoff factor: 1 |
| Retry-After | Supported | Handles `Retry-After` and `X-RateLimit-RetryAfter` headers |
| Event stream 429 | 60s sleep | Waits 60 seconds before retrying on rate limit |

---

**End of Specification**