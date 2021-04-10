import os
import sys
import logging
import argparse
import requests
import colorlog
from pprint import pprint
from datetime import datetime, timedelta
from slack_sdk.webhook import WebhookClient


def setup_logger(log_fmt="%(log_color)s%(asctime)s:%(levelname)s:%(message)s", log_file_name=".output-{}.log".format(os.path.basename(__file__)), level='DEBUG'):
    formatter = colorlog.ColoredFormatter(
        log_fmt,
        datefmt='%DT%H:%M:%SZ'
    )

    with open(log_file_name, 'w') as o: pass

    logger = logging.getLogger()

    handler2 = logging.FileHandler(log_file_name)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.addHandler(handler2)
    logger.setLevel(level)

    return logger


# global variables
logger = setup_logger()
args = ''
exit_status_value = 0
# 


def setup_args():
    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument('-e', '--elastic_host', metavar='<elastic_host>', type=str, help='Link to Elastic host. Eg: https://asd.es.io:8443')
    parser.add_argument('-u', '--user', metavar='<user>', type=str, help='Elastic user name. Eg: elastic_user')
    parser.add_argument('-p', '--password', metavar='<password>', type=str, help='Elastic user password. Eg: p@SSw0Rd!@#')
    parser.add_argument('-m', '--max_time_threshold', metavar='<max_time_threshold>', type=str, default='60', help='Max time threshold of the rule, in minutes, which a successful rule execution time must not exceed to be considered as a working rule. Eg: 5, 10, 15, 20')
    parser.add_argument('-s', '--slack_token', metavar='<slack_token>', type=str, default='', help='Slack token...')
    parser.add_argument('-v', '--verbosity', metavar='<verbosity_level>', type=str, default='DEBUG', help='Execution verbosity level. Eg: SUCCESS|warning|INFO|DEBUG.')
    logger.info('Arguments parsed successfully...')
    return parser.parse_args()


def convert_to_slack_block(rule):
    text = "*======================*\n`{0}` ({1})\n`Last Success Time (UTC):` {2}\n`Last Failure Time (UTC):` {3}\n*Failure Message:*\n```{4}```".format(rule.get('Name'), rule.get('Rule ID'), rule.get('Last Success Time (UTC)'), rule.get('Last Failure Time (UTC)'), rule.get('Failure Message'))
    ret = {
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": text
			}
		}
    return ret


def send_to_slack(failing_rules, slack_token):
    webhook = WebhookClient(slack_token)
    blocks = []
    for rule in failing_rules:
        # pprint(convert_to_slack_block(rule))
        blocks.append({"type": "divider"})
        blocks.append(convert_to_slack_block(rule))
    logger.info("Printing blocks:")
    pprint(blocks)
    try:
        if len(failing_rules) > 0:    
            response = webhook.send(text='Failing Rules...', blocks=blocks)
            logger.info(response.status_code)
            logger.info('Message successfully posted in Slack...')
        else: logger.info('No blocks created since no failing rules were found. Skipping Slack message sending...')
    except Exception as e:
        logger.error('Exception {} occurred in {}...'.format(e, send_to_slack))
        logger.error(response.status_code)


def main():
    global args
    args = setup_args()
    failing_rules = get_failing_rules(args.elastic_host, args.user, args.password, args.max_time_threshold)
    if args.slack_token != '':
        send_to_slack(failing_rules, args.slack_token)
    set_exit_status(failing_rules)
    sys.exit(exit_status_value)
    

def get_failing_rules(host, user, password, max_time_threshold):
    detection_engine = host + '/api/detection_engine/rules/_find?per_page=600&filter=alert.attributes.enabled:true'
    response = requests.get(detection_engine, auth=(user, password)).json()
    # logger.info('Printing Response:...')
    # pprint(response)
    rule_list = []
    num = 0
    for item in response['data']:
        if time_diff_threshold_breached(item.get('last_success_at'), max_time_threshold):
            rule_dict = {'Name': item.get('name'), 'Rule ID': item.get('rule_id'), 'Last Success Time (UTC)': item.get('last_success_at'), 'Last Failure Time (UTC)': item.get('last_failure_at'), 'Failure Message': item.get('last_failure_message')}
            logger.warning('rule {} ({}) breached threshold.'.format(item.get('name'), item.get('rule_id')))
            rule_list.append(rule_dict)
    logger.info('Printing failing rules list:')
    pprint(rule_list)
    return rule_list


def time_diff_threshold_breached(last_success_time, max_time_threshold):
    ret = False
    time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
    try:
        # if rule last execution time is farther back in time than now-MaxThresholdTime
        if datetime.strptime(last_success_time, time_format) < datetime.utcnow() -  timedelta(minutes=int(max_time_threshold)):
            ret = True
        else: ret =  False
    except Exception as e:
        logger.error('Exception {} occurred in time_diff_threshold_breached for {}'.format(e, last_success_time))
        ret = True
    return ret


def set_exit_status(failing_rules):
    global exit_status_value
    if len(failing_rules) > 0: 
        logger.warning('Exitting with non-zero status code because some rules are failing...')
        exit_status_value = 1 


if __name__ == '__main__':
    main()