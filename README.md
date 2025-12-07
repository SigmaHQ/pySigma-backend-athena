![Tests](https://github.com/nsmithuk/pySigma-backend-athena/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/nsmithuk/b932f78b1023d303a0ebf37e6a27f405/raw/pySigma-backend-athena.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma Athena Backend

An AWS Athena backend for pySigma that converts Sigma detection rules into Athena-compatible SQL queries.

While designed for AWS Athena, it likely works with any Trino-based SQL engine.

---

## Features

Most standard Sigma rule features are supported, including logical and comparison operators,
wildcards, regular expressions, CIDR matching, field reference matching, existence checks and case-sensitive matching. 
A handful of operations—like full-text value-only expressions and distinct-count window 
functions—aren't implemented; see the Limitations section below.


## Limitations

- Full-text searches (value-only expressions) are not supported.
- At present, only the `event_count` correlation rule type is supported.

---

[//]: # (## Installation)

[//]: # ()
[//]: # (Install via pip:)

[//]: # ()
[//]: # (```bash)

[//]: # (pip install pySigma-backend-athena)

[//]: # (```)

[//]: # ()
[//]: # (Or with Poetry:)

[//]: # ()
[//]: # (```bash)

[//]: # (poetry add pySigma-backend-athena)

[//]: # (```)

[//]: # ()
[//]: # (---)

## Usage

From the CLI:
```shell
sigma convert -t athena rules/cloud/aws/cloudtrail/
```

From Python:
```python
from sigma.backends.athena import athenaBackend
from sigma.collection import SigmaCollection

# Initialize the backend, optionally specifying table, fields, and time field
backend = athenaBackend()

# Load your Sigma rule collection
collection = SigmaCollection.from_yaml("...")

# Convert to Athena SQL
queries = backend.convert(collection)
for q in queries:
    print(q)
```

### Set Table Name

There are a few ways of setting the table name that will appear in the SQL.

If all of your rules use the same table name, regardless of the `logsource` set, you can pass a backend-option of `table`.

For example:
```python
athena_backend = athenaBackend(table="events")
```

Will result in:
```sql
SELECT * FROM events WHERE ...
```

If you need to set your table name based on the `logsource` seen, you can use a pipeline. The backend will look for a 
processing state value of `table_name` and, if set, will use this table name.

For example:
```yaml
name: AWS Security Lake Table Mapping
priority: 100

vars:
  region: eu_west_2

transformations:
  - id: cloudtrail_mgmt_table
    type: set_state
    key: table_name
    val: "amazon_security_lake_table_{region}_cloud_trail_mgmt_2_0"
    rule_conditions:
      - type: logsource
        product: aws
        service: cloudtrail
```

### Set Table Name with AWS Security Lake

If you are using this backend with AWS Security Lake, a helper plugin is also provided for setting the correct table name.

For example, the following will map an AWS CloudTrail source to `amazon_security_lake_table_eu_west_2_cloud_trail_mgmt_2_0`.

```python
from sigma.pipelines.athena import athena_pipeline_security_lake_table_name
from sigma.backends.athena import athenaBackend
from sigma.collection import SigmaCollection

pipeline = athena_pipeline_security_lake_table_name()
backend = athenaBackend(
  aws_table_region="eu-west-2",  # Replace with your AWS region  
  processing_pipeline=pipeline,    
)

rules = SigmaCollection.load_ruleset("path/to/rules/")
queries = backend.convert(rules)
```

This supports the following log sources:
* product: `aws`, service: `cloudtrail`
* product: `aws`, service: `cloudtrail_s3`
* product: `aws`, service: `cloudtrail_lambda`
* product: `aws`, service: `route53`
* product: `aws`, service: `security_hub`
* product: `aws`, service: `vpc_flow_logs`
* product: `aws`, service: `waf`
* product: `aws`, service: `eks_audit`

You can also use this pipeline from the CLI:
```shell
sigma convert -t athena -O aws_table_region=eu-west-2 -p athena_security_lake_table_name rules/cloud/aws/cloudtrail/
```

### Select Column Names

The backend supports the [fields](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html#fields) attribute in Sigma rules. 
If a Sigma rule specifies a list of fields, the generated Athena SQL query will SELECT only those specified fields instead of using `SELECT *`.

This is useful for optimising queries by retrieving only necessary data.

For example, if your Sigma rule includes:
```yaml
fields:
  - uid
  - time_dt
  - process.command_line as command_line
```

The generated query will start with:
```sql
SELECT uid, time_dt, process.command_line as command_line FROM ...
```

If no `fields` are specified in the rule, the query defaults to `SELECT *`.

This feature is automatically applied when converting rules with the backend.

---

## Supported Correlation Rules

The Athena backend currently supports **event\_count** correlation rules. Other types (`value_count`, `temporal`, `temporal_ordered`) are not implemented and will raise `NotImplementedError`.

### event\_count

- **Type**: `event_count`
- **Parameters**:
  - `rules`: List of Sigma rules to correlate
  - `group-by`: Fields to partition by
  - `timespan`: Window duration (e.g. `15m`, `1h`)
  - `condition`: Comparison operator and threshold (e.g. `gte: 10`)

Generates a sliding time window-function query that counts matching events within the specified timeframe.

#### Example

```yaml
title: Windows Failed Logon
id: dc9f1a2e-7d3b-4f1c-b8f4-1e23eadf4567
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
---
title: Possible Brute-Force Attack via Repeated Logon Failures
id: e8b2c3d4-5f6a-7b8c-9d0e-f1a2b3c4d5e6
status: stable
description: Detects more than 5 failed Windows logon attempts from the same source IP within 10 minutes.
correlation:
  type: event_count
  rules:
    - dc9f1a2e-7d3b-4f1c-b8f4-1e23eadf4567
  group-by:
    - SourceIp
  timespan: 10m
  condition:
    gte: 5
```
Gives:
```sql
WITH combined_events AS (
    SELECT *
    FROM <TABLE>
    WHERE EventID = 4625
),
event_counts AS (
    SELECT *,
           COUNT(*) OVER (
               PARTITION BY SourceIp
               ORDER BY time
               RANGE BETWEEN INTERVAL '600' SECOND PRECEDING AND CURRENT ROW
           ) AS correlation_event_count
    FROM combined_events
)
SELECT *
FROM event_counts
WHERE correlation_event_count >= 5;
```

### Specifying the DateTime column to use for the time window

By default, the `time` column is used for the rule's sliding time window. This can be changed by setting the
`time_field` backend-option.

For example:
```python
athena_backend = athenaBackend(time_field="time_dt")
```

---

## Testing

Run the test suite:

```bash
pytest
```

---

## Maintainers

- [Neil Smith](https://github.com/nsmithuk/)

---

## License

Licensed under the [MIT License](LICENSE).
