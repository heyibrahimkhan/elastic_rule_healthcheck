# Elastic Rule Healthcheck

## What

It is a tool to detect if a native Elastic rule is failing due to some error.
It also has the ability to be able to notify on Slack in case of a failing rule detection.

## Why

Because setting up detection rules and then not being able to detect the attack because for some reason the rule started failing and no one investigated and tuned the rule properly would be a PITA.

## Tech Stack

This project uses:

* Elasticsearch
* Slack
* Python

# Setup

## Install all required packages

This is a one-time command
```
pipenv install
```

# Usage

## Required params:

* `-e`: Elasticsearch URL that will be queried for status of Elastic rules.
* `-u`: Elastic user name that has relevant permissions to query to *detections* API on Elasticsearch.
* `-p`: Elastic user password that has relevant permissions to query to *detections* API on Elasticsearch.
* `-m`: Set by default. Max time threshold of the rule, in minutes, which a successful rule execution time must not exceed to be considered as a working rule. Eg: 5, 10, 15, 20.

## Optional params:

* `-s`: Slack webhook where all the failure results will be sent.
* `-v`: Verbosity level.

## Example:

### View script help menu
```
python.exe elastic_rule_healthcheck.py -h
```

### Simply execute the script
```
python.exe elastic_rule_healthcheck.py -e https://my_es_cloud.eu-central-1.aws.cloud.es.io -u username -p 'password'
```

### Execute the script with custom Max Time Threshold
```
python.exe elastic_rule_healthcheck.py -e https://my_es_cloud.eu-central-1.aws.cloud.es.io -u username -p 'password' -m 20
```

### Execute the script and forward failure results to Slack
```
python.exe elastic_rule_healthcheck.py -e https://my_es_cloud.eu-central-1.aws.cloud.es.io -u username -p 'password' -s https://hooks.slack.com/randomvalue
```