#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""disable-inactive-iam-users.py
Monitors user accounts in IAM and expires any credentials that have not been
used in the last X days

"""

import datetime
import logging
from acgaws import IamHelper

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

CREDENTIAL_TIMEOUT = 90
GRACE_PERIOD = 30
TODAY = datetime.date.today()
DELETE_DATE = TODAY + datetime.timedelta(days=GRACE_PERIOD)


def lambda_handler(event, context):
    iam = IamHelper()
    all_users = iam.get_all_users()

    for user in all_users:
        user_tags = iam.get_user_tags(user)
        access_key_list = iam.get_api_access_keys(user)
        if "DeleteDate" in user_tags:
            if user_tags['DeleteDate'] <= str(TODAY):
                logging.info(f'Delete User: {user}')
                iam.remove_user_from_group(user)
                iam.detach_user_policies(user)
                iam.delete_api_access_keys(user)
                iam.deactivate_mfa(user)
                iam.delete_user(user)
        elif "DoNotDelete" in user_tags:
            logging.info(f'Do Not Delete User: {user}')
        else:
            last_console_access = iam.get_last_console_access(user)
            last_api_access = iam.get_last_api_access(access_key_list)
            if last_console_access >= CREDENTIAL_TIMEOUT or last_console_access == -1:
                if last_api_access >= CREDENTIAL_TIMEOUT or last_api_access == -1:
                    iam.tag_deletion_date(user, str(DELETE_DATE))

                    logging.info(f'Locking User: {user}')
                    try:
                        iam.disable_console_access(user)
                    except:
                        pass
                    for key in access_key_list:
                        iam.disable_api_access(user, key)


if __name__ == "__main__":
    lambda_handler("e", "c")
