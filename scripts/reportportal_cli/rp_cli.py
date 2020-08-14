import argparse
import json
import logging
import os
import shutil
import sys
import time
import traceback
import re
from mimetypes import guess_type

import requests
import xmltodict
import yaml
from packaging import version as pkg_version
from reportportal_client import ReportPortalServiceAsync, ReportPortalService
from reportportal_client.service import uri_join

# default log file name
LOG_FILE_NAME = 'rp_cli.log'
# log levels mapping
LOG_LEVELS = {
    'debug': logging.DEBUG,
    'info':  logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
    }

DEFAULT_LOG_LEVEL = "info"
STRATEGIES = ["Rhv", "Raut", "Cfme"]
DEFAULT_OUT_FILE = "rp_cli.json"

logger = logging.getLogger("rp_cli.py")

# Waiting parameters for end of tasks
WAIT = {"TRIES": 180, "TIMEOUT": 10, "START": 1, "STEP": 1}
MAX_PAGE_SIZE = "10000"
IN_PROGRESS = "IN_PROGRESS"
IS_FIRST_RUN_STR = "is_first_run"


def timestamp():
    return str(int(time.time() * 1000))


def init_logger(level, filename=LOG_FILE_NAME):
    handler = logging.FileHandler(filename)
    formatter = logging.Formatter(
        "%(asctime)s:%(name)s:%(levelname)s:%(threadName)s:%(message)s"
    )
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(LOG_LEVELS.get(level, logging.NOTSET))


class Strategy():
    """
    The class holds the interface of handling the xunit file.
    """

    def __init__(self):
        pass

    def my_error_handler(self, exc_info):
        """
        This callback function will be called by async service client when error occurs.

        Args:
            exc_info: result of sys.exc_info() -> (type, value, traceback)

        """
        logger.error("Error occurred: {}".format(exc_info[1]))
        traceback.print_exception(*exc_info)

    def extract_failure_msg_from_xunit(self, case):
        pass

    def get_tags(self, case, test_owners={}):
        pass

    def get_testcase_name(self, case):
        pass

    def get_testcase_description(self, case):
        pass

    def get_logs_per_test_path(self,  case):
        pass

    def should_create_folders_in_launch(self):
        return False

    def create_folder(self, case):
        pass

    def is_first_folder(self):
        pass


class Rhv(Strategy):

    def __init__(self):
        self.current_team = None
        self.first_folder = True

    def extract_failure_msg_from_xunit(self, case):
        text = ""
        data = case.get('failure', case.get('error'))
        if isinstance(data, list):
            for err in data:
                text += '{txt}\n'.format(txt=err.get('#text').encode('ascii', 'ignore'))
            return text
        return data.get('#text')

    def get_logs_per_test_path(self, case):
        name = case.get('@classname') + '.' + case.get('@name')
        return '/'.join(name.split('.')[1:])

    def get_testcase_name(self, case):
        return"{class_name}.{tc_name}".format(class_name=case.get('@classname'), tc_name=case.get('@name'))

    def get_testcase_description(self, case):
        return "{tc_name} time: {case_time}".format(tc_name=case.get('@name'), case_time=case.get('@time'))

    def _get_properties(self, case):
        tags = list()

        if 'properties' in case.keys():
            properties = case.get('properties').get('property')

            if not isinstance(properties, list):
                properties = [properties]

            for p in properties:
                tags.append(
                    '{key}:{value}'.format(
                        key=p.get('@name'),
                        value=p.get('@value'),
                    )
                )

        return tags

    def _get_test_owner(self, case, test_owners={}):

        for owner in test_owners.keys():
            for test in test_owners.get(owner):
                if test in case.get('@classname'):
                    return owner
        return

    def get_tags(self, case, test_owners={}):
        tags = list()
        # extract team name
        tags.append(self.get_team_dir_name(case))
        # extract properties like polarion id and bz
        tags.extend(self._get_properties(case))
        # add test owner name to test case according to test_owner.yaml file
        tc_owner = self._get_test_owner(case, test_owners)
        if tc_owner:
            tags.append(tc_owner)

        return tags

    def create_folder(self, case):
        if self.current_team != self.get_team_dir_name(case):
            self.current_team = self.get_team_dir_name(case)
            return True, self.current_team

        return False, self.current_team

    def get_team_dir_name(self, case):
        """
        Return the team directory name
        "rhevmtests.<team dir name>.<test package>.<test module>.<test class>"

        Args:
            case (dict): One test as published by pytest xunit output file
        """
        return case.get('@classname').split('.')[1]

    def should_create_folders_in_launch(self):
        return True

    def is_first_folder(self):
        if self.first_folder:
            self.first_folder = False
            return True
        else:
            return False

    def get_version(self, tags):
        """
        Extract the RHV version from the given tags

        Args:
            tags (list): List of strings that send through the CLI "--launch_tags"

        Returns:
            str: RHV version ("rhv-x.y.z-n") if version was found, empty string otherwise
        """
        for tag in tags:
            if re.findall(r"rhv-\d.\d+\.\d+\-\d+", tag):
                return tag
        return ""

    def get_version_number(self, version_tag=None):
        """
        Convert version format from "rhv-1.2.3-10" to "1.2.3.10"
        So it can be compared

        Args:
            version_tag (str): Product version include letters and numbers e.g.: rhv-1.2.3-4
                if given then it will be translated to number, else read from the init tag

        Returns:
            str: Version formatted as: 1.2.3.4
        """
        if not version_tag:
            version_tag = self.get_version(tags=self.launch_tags)
        return ".".join(version_tag.split("-")[1:]) if version_tag else ""

    def parse_launch_name(self, launch_name_cli, teams):
        """
        Split the given launch_name (pass through CLI) to launch name and team name

        launch_name by CLI examples: "RHV-4.3-tier2-network", "RHV-4.3-tier2-sla-virt"

        Args:
            launch_name_cli (str): Launch name as given through CLI
            teams (list): Teams names

        Returns:
            tuple: (launch name, team name) if team is a valid team name, ("", "") if not
        """
        result = re.findall(r"(RHV-\d.\d-tier\d)\-?([a-z\-]+)?", launch_name_cli)
        if result and len(result) == 1:
            return result[0][0], result[0][1]
        return "", ""

    def get_latest_filter_name(self, tags):
        """
        Returns the expected latest filter name at the Report Portal
        """
        version = self.get_version(tags=tags)  # e.g.: "rhv-4.4.1-5"
        major, minor, _ = tuple(version.split("-")[1].split("."))  # ['4', '4', '1']
        return "RHV {major}.{minor} latest".format(major=major, minor=minor)

# END: Class Rhv


class Raut(Rhv):

    def get_logs_per_test_path(self, case):
        name = self.get_testcase_name(case)
        return name.split('.')[-1]

    def get_tags(self, case, test_owners={}):
        tags = list()
        # extract properties like polarion id and bz
        tags.extend(self._get_properties(case))
        # add test owner name to test case according to test_owner.yaml file
        tc_owner = self._get_test_owner(case, test_owners)
        if tc_owner:
            tags.append(tc_owner)

        return tags

    def should_create_folders_in_launch(self):
        return False
# END: Class Raut


class Cfme(Rhv):

    # These properties will be attached as a simple (not key:value pair) tag to each test case
    properties_to_parse = ['rhv_tier']

    @staticmethod
    def get_testcase_name(case):
        """Example: cfme/tests/test_rest.py::test_product_info[rhv_cfme_integration]"""
        file, classname, name = case.get("@file"), case.get("@classname").split(".")[-1], case.get("@name")
        # If a test case is encapsulated in pytest class, include the class in test case signature
        if classname.startswith('Test'):
            return "{}::{}::{}".format(file, classname, name)
        else:
            return "{}::{}".format(file, name)

    @staticmethod
    def get_testcase_description(case):
        """Include info on skip reason and time it took to execute."""
        skip_msg = '\n' + case.get('skipped').get('@message') if case.get('skipped') else ''
        return "Time: {}{}".format(case.get('@time'), skip_msg)

    def get_tags(self, case, test_owners={}):
        """Only get values of properties we are explicitly interested in."""
        if test_owners:
            raise NotImplementedError('Test owners not implemented for CFME.')

        tags = []

        if 'properties' in case.keys():
            properties = case.get('properties').get('property')
            if not isinstance(properties, list):
                properties = [properties]
            for p in properties:
                if p.get("@name") in self.properties_to_parse:
                    tags.append(p.get("@value"))

        return tags

    def should_create_folders_in_launch(self):
        return False


class RpManager:
    def __init__(self, config, strategy):
        self.url = config.get('rp_endpoint')
        self.uuid = config.get('rp_uuid')
        self.project = config.get('rp_project')
        self.launch_description = config.get('launch_description')
        self.launch_tags = config.get('launch_tags').split()
        self.upload_xunit = config.get('upload_xunit')
        self.update_headers = {
            'Authorization': 'bearer %s' % self.uuid,
            'Accept': 'application/json',
            'Cache-Control': 'no-cache',
            'content-type': 'application/json',
        }
        self.import_headers = {
            'Authorization': 'bearer %s' % self.uuid,
            'Accept': 'application/json',
            'Cache-Control': 'no-cache',
        }
        self.launch_url = "{url}/api/v1/{project_name}/launch/%s".format(
            url=self.url, project_name=self.project
        )
        self.launch_public_url = "{url}/ui/#{project_name}/launches/all/%s".format(
            url=self.url, project_name=self.project
        )
        self.launch_id = ''
        self.xunit_feed = config.get('xunit_feed')
        self.launch_name_cli = config.get('launch_name', 'rp_cli-launch')
        self.all_teams = config.get('teams', {})
        self.strategy = strategy
        self.service = ReportPortalServiceAsyncRH(
            endpoint=self.url, project=self.project, token=self.uuid, error_handler=self.strategy.my_error_handler
        )
        self.test_logs = config.get('test_logs')
        self.zipped = config.get('zipped')
        self.test_owners = config.get('test_owners', {})
        self.strategy = strategy

        self.launch_name, self.launch_teams = self.strategy.parse_launch_name(
            launch_name_cli=self.launch_name_cli, teams=self.all_teams.keys()
        )
        if self.launch_teams:
            self.launch_teams = [team for team in self.launch_teams.split("-") if self._is_valid_team(team=team)]
        if not self.launch_teams:
            self.launch_name = self.launch_name_cli

    @staticmethod
    def _check_return_code(req):
        if req.status_code != 200:
            logger.error('Something went wrong status code is %s; MSG: %s', req.status_code, req.json()['message'])
            sys.exit(1)

    def _import_results(self):
        with open(self.upload_xunit, 'rb') as xunit_file:
            files = {'file': xunit_file}
            req = requests.post(self.launch_url % "import", headers=self.import_headers, files=files)

        response = req.json()
        self._check_return_code(req)
        logger.info("Import is done successfully")
        response_msg = response['msg'].encode('ascii', 'ignore')
        logger.info('Status code: %s; %s', req.status_code, response_msg)

        # returning the launch_id
        return response_msg.split()[4]

    def _verify_upload_succeeded(self, launch_id):
        launch_id_url = self.launch_url % launch_id
        req = requests.get(launch_id_url, headers=self.update_headers)
        self._check_return_code(req)
        logger.info('Launch has been created successfully')
        return True

    def _update_launch_description_and_tags(self, launch_id):
        update_url = self.launch_url % launch_id + "/update"

        data = {
            "description": self.launch_description,
            "tags": self.launch_tags
        }

        req = requests.put(url=update_url, headers=self.update_headers, data=json.dumps(data), verify=False)
        self._check_return_code(req)
        logger.info(
            'Launch description %s and tags %s where updated for launch id %s',
            self.launch_description, self.launch_tags, launch_id
        )

    def import_results(self):
        self.launch_id = self._import_results()
        self._verify_upload_succeeded(self.launch_id)
        self._update_launch_description_and_tags(self.launch_id)

    def _start_launch(self):
        """
        Start new launch

        Returns:
            str: Launch ID if Start success, empty string otherwise
        """
        self.service.start_launch(
            name=self.launch_name,
            start_time=timestamp(),
            description=self.launch_description,
            tags=self.launch_tags
        )
        self._wait_tasks_to_finish()
        parent_launch = self.service.find_launch_version(
            launch_name=self.launch_name,
            version=self.strategy.get_version(tags=self.launch_tags)
        )
        if parent_launch:
            return parent_launch.get("id", "")
        return ""

    def _process_launch(self, launch=None):
        """
        Continue an existing launch

        Args:
            launch (str): Launch name

        Returns:
            str: Launch ID if success, empty string otherwise
        """
        version = self.strategy.get_version(tags=self.launch_tags)
        if launch is None:
            launch = self.service.find_launch_version(launch_name=self.launch_name, version=version)

        if launch["status"].strip() != IN_PROGRESS:
            logger.error(
                "An existing launch ('{name} #{number}') that match the launching version '{ver}' was found, "
                "but its state is not 'in-progress'".format(
                    ver=version, name=launch["name"], number=launch["number"]
                )
            )
            return ""
        self.launch_tags += launch.get("tags")
        self.launch_description = "\n".join([self.launch_description, launch.get("description")])
        self._update_launch_description_and_tags(launch_id=launch.get("id"))
        return launch.get("id")

    def _init_launch(self):
        """
        Init current launch if exists or create new launch if it does not exits
        """
        self.launch_id = ""
        version = self.strategy.get_version(tags=self.launch_tags)
        launch = self.service.find_launch_version(launch_name=self.launch_name, version=version)
        if launch:
            self.launch_id = self._process_launch(launch=launch)

        if not self.launch_id:
            self.launch_id = self._start_launch()

        assert self.launch_id, "Fail to create launch '{name}'".format(name=self.launch_name)
        self.service.rp_client.launch_id = self.launch_id

    def is_last_run(self):
        """
        Is this the last test run for current launch

        It is the last run if:
        1. Team name was not given, or
        2. Team name was given and tags field include one entry for each team listed at the 'rp_conf.yaml'

        Returns:
            bool: True if this is the last run for current launch, False otherwise
        """
        if not self.launch_teams:
            logger.info("is_last_run = true")
            return True

        for team in self.all_teams.keys():
            if team not in self.launch_tags:
                logger.info("is_last_run = False")
                return False
        logger.info("is_last_run = True")
        return True

    def is_first_run(self):
        """
        Is this the first test run for current launch

        It is the first run if:
        1. Team name was not given, or
        2. Team name was given and tags field does not include any entry for team

        Returns:
            bool: True if this is the first run for current launch, False otherwise
        """
        if not self.launch_teams:
            logger.info("No teams was entered, %s = True", IS_FIRST_RUN_STR)
            return True

        for team in self.all_teams.keys():
            if team not in self.launch_teams and team in self.launch_tags:
                logger.info("Found a team that already ran ('%s'), %s = False", team, IS_FIRST_RUN_STR)
                return False
        logger.info("%s = True", IS_FIRST_RUN_STR)
        return True

    def _wait_tasks_to_finish(self):
        logger.info("Waiting for tasks to complete...")
        max_tries = WAIT.get("START")
        while self.service.queue.qsize() > 0 and max_tries < WAIT.get("TRIES"):
            time.sleep(WAIT.get("TIMEOUT"))
            max_tries += WAIT.get("STEP")
        time.sleep(WAIT.get("TIMEOUT"))
        logger.info("End waiting for tasks to complete")

    def _end_launch(self):
        self.service.finish_launch(end_time=timestamp())
        self.service.terminate()
        self.launch_id = self.service.rp_client.launch_id
        logger.info("Ending launch '%s'", self.launch_id)

    def _upload_attachment(self, file, name):
        logger.info("Uploading attachment file name: '%s' log file: '%s'", file, name)
        with open(file, "rb") as fh:
            attachment = {
                "name": name,
                "data": fh.read(),
                "mime": guess_type(file)[0]
            }
            self.service.log(timestamp(), name, "INFO", attachment)

    def upload_test_case_attachments(self, path):
        for root, dirs, files in os.walk(path):
            for log_file in files:
                file_name = os.path.join(root, log_file)
                self._upload_attachment(file_name, log_file)

    def upload_zipped_test_case_attachments(self, zip_file_name, path):
        whole_path = os.path.join(self.test_logs, path)
        try:
            ld = os.listdir(whole_path)
        except OSError:
            logger.warning("Path (%s) with log files does not exist!" % (whole_path,))
            return
        # check if there is something to zip
        if len(ld) > 0:
            zip_file_name = shutil.make_archive(zip_file_name, 'zip', whole_path)
            self._upload_attachment(zip_file_name, os.path.basename(zip_file_name))
            os.remove(zip_file_name)

        else:
            logger.warning("There are no logs on the path (%s)!" % (whole_path, ))

    def _log_message_to_rp_console(self, msg, level="INFO"):
        self.service.log(
            time=timestamp(),
            message=msg,
            level=level
        )

    def _process_failed_case(self, case):
        logger.info("Process failed case")
        msg = self.strategy.extract_failure_msg_from_xunit(case)
        self._log_message_to_rp_console(msg, "ERROR")

    def store_launch_info(self, dest):
        logger.info("Store launch info to: '%s'", dest)
        launch_url = self.launch_public_url % self.launch_id
        json_data = {
            "rp_launch_url":  launch_url,
            "rp_launch_name": self.launch_name_cli,
            "rp_launch_tags": self.launch_tags,
            "rp_launch_desc": self.launch_description,
            "rp_launch_id":   self.launch_id
        }
        with open(dest, "w") as file:
            json.dump(json_data, file)

    def attach_logs_to_failed_case(self, case):
        logger.info("Attach logs to failed case")
        path_to_logs_per_test = self.strategy.get_logs_per_test_path(case)

        if self.zipped:
            # zip logs per test and upload zip file
            self.upload_zipped_test_case_attachments("{0}".format(case.get('@name')), path_to_logs_per_test)
        else:
            # upload logs per tests one by one and do not zip them
            self.upload_test_case_attachments("{0}/{1}".format(self.test_logs, path_to_logs_per_test))

    def _open_new_folder(self, folder_name):
        logger.info("Open new folder: '%s'", folder_name)
        self.service.start_test_item(
            name=folder_name,
            start_time=timestamp(),
            item_type="SUITE",
        )

    def _close_folder(self):
        logger.info("Closing folder")
        self.service.finish_test_item(end_time=timestamp(), status=None)

    def _is_valid_team(self, team):
        """
        Is given team team is listed at the config file

        Args:
             team (str): Team name

        Returns:
            bool: True if given team name is listed at the config file, False otherwise
        """
        if team in self.all_teams.keys():
            logger.info("Team '%s' is valid", team)
            return True

        logger.error("Team '%s' is not valid", team)
        return False

    def is_team_test(self, case):
        """
        If given test case belongs to the current launching team

        Args:
            case (dict): One test as published by pytest xunit output file

        Returns:
            bool: True if given case belong to current launched team, False otherwise
        """
        # Eliminate if the team name was not given, e.g.: tier1
        if not self.launch_teams:
            return True

        for team_name in self.launch_teams:
            for dir_ in self.all_teams.get(team_name, []):
                if dir_ in self.strategy.get_team_dir_name(case=case):
                    return True
            return False

    def update_latest_filter(self):
        """
        Update an existing filter name

        Returns:
            bool: True if update success, False otherwise
        """
        if not self.is_old_filter_version():
            logger.info("Latest filter version is newer, will not be updated!")
            return False

        filter_name = self.strategy.get_latest_filter_name(tags=self.launch_tags)
        if filter_name:
            ver = self.strategy.get_version(tags=self.launch_tags)
            filter_data = {
                "type": "launch",
                "entities": [
                    {
                        "filtering_field": "tags",
                        "condition": "in",
                        "value": "{ver}".format(ver=ver)
                      }
                ]
            }
            response = self.service.update_shared_filter_by_name(filter_name=filter_name, filter_data=filter_data)
            if response and response.status_code == 200:
                logger.info(
                    "Filter '{filter_name}' was successfully updated with latest version '{ver}'".format(
                        filter_name=filter_name, ver=ver)
                )
            else:
                logger.error("Fail to update filter '{filter_name}'".format(filter_name=filter_name))
                return False
        else:
            logger.error("Can't update filter: '%s', filter does not exist!", filter_name)
            return False
        return True

    def is_old_filter_version(self):
        """
        Returns True if filter version need to be updated, False otherwise
        """
        filter_name = self.strategy.get_latest_filter_name(tags=self.launch_tags)
        if filter_name:
            flt = self.service.get_filter_by_name(filter_name=filter_name)
            if flt:
                entities = flt.get('entities')
                if entities and len(entities) == 1:
                    filter_ver = entities[0].get('value')
                    filter_ver = self.strategy.get_version_number(version_tag=filter_ver)
                    product_ver = self.strategy.get_version_number(
                        version_tag=self.strategy.get_version(tags=self.launch_tags)
                    )
                    logger.info("Product version is: '%s' latest filter version is: '%s'", filter_ver, product_ver)
                    return pkg_version.parse(product_ver) > pkg_version.parse(filter_ver)
        return False

    def feed_results(self):
        self._init_launch()

        with open(self.xunit_feed) as fd:
            data = xmltodict.parse(fd.read())

        xml = data.get("testsuite").get("testcase")

        # if there is only 1 test case, convert 'xml' from dict to list
        # otherwise, 'xml' is always list
        if not isinstance(xml, list):
            xml = [xml]

        xml = sorted(xml, key=lambda k: k['@classname'])

        for case in xml:
            # Handle pytest issue that collects tests not belonging to the delivered marked team-name
            if not self.is_team_test(case=case):
                continue

            issue = None
            name = self.strategy.get_testcase_name(case)
            logger.info("=== Starting case name: '%s' ===", name)

            description = self.strategy.get_testcase_description(case)
            logger.info("Case description: '%s'", description)

            tags = self.strategy.get_tags(case, test_owners=self.test_owners)
            logger.info("Case tags: '%s'", tags)

            if self.strategy.should_create_folders_in_launch():
                open_new_folder, folder_name = self.strategy.create_folder(case)
                if self.strategy.is_first_folder():
                    if open_new_folder:
                        self._open_new_folder(folder_name)
                elif open_new_folder:  # in case a new folder should be open, need to close last one and open new one
                    self._close_folder()
                    self._open_new_folder(folder_name)

            logger.info("--- Start test item: '%s' ---", name[:255])
            self.service.start_test_item(
                name=name[:255],
                description=description,
                tags=tags,
                start_time=timestamp(),
                item_type="STEP",
            )

            # Create text log message with INFO level.
            if case.get('system_out'):
                self._log_message_to_rp_console(case.get('system_out'), "INFO")

            if case.get('skipped'):
                issue = {"issue_type": "NOT_ISSUE"}  # this will cause skipped test to not be "To Investigate"
                status = 'SKIPPED'
                self._log_message_to_rp_console(case.get('skipped').get('@message'), "DEBUG")
            elif case.get('failure') or case.get('error'):  # Error or failed cases
                status = 'FAILED'
                self._process_failed_case(case)

                if self.test_logs:
                    self.attach_logs_to_failed_case(case)
            else:
                status = 'PASSED'

            logger.info("Finish test item status: '%s', issue: '%s'", status, issue)
            self.service.finish_test_item(end_time=timestamp(), status=status, issue=issue)

        if self.strategy.should_create_folders_in_launch():
            self._close_folder()

        # Finish launch.
        self._wait_tasks_to_finish()

        if self.is_first_run():
            self.update_latest_filter()

        if self.is_last_run():
            self._end_launch()
# End class RpManager


def parse_configuration_file(config):
    """
    Parses the configuration file.

    Returns: dictionary containing the configuration file data
    """

    try:
        with open(config, 'r') as stream:
            conf_data = yaml.load(stream)
    except (OSError, IOError) as error:
        logger.error("Failed when opening config file. Error: %s", error)
        sys.exit(1)

    # Check configuration file:
    if not all(key in conf_data for key in ['rp_endpoint', 'rp_uuid', 'rp_project']):
        logger.error('Configuration file missing one of: rp_endpoint, rp_uuid or rp_project')
        sys.exit(1)

    return conf_data


def parser():
    """
    Parses module arguments.

    Returns: A dictionary containing parsed arguments
    """

    rp_parser = argparse.ArgumentParser()

    rp_parser.add_argument(
        "--config", type=str, required=True,
        help="Configuration file path",
    )
    rp_parser.add_argument(
        "--upload_xunit", type=str, required=False,
        help="launch_name.zip: zip file contains the xunit.xml",
    )
    rp_parser.add_argument(
        "--launch_name", type=str, required=False,
        help="Description of the launch",
    )
    rp_parser.add_argument(
        "--launch_description", type=str, required=False,
        help="Description of the launch",
    )
    rp_parser.add_argument(
        "--launch_tags", type=str, required=False,
        help="Tags for that launch",
    )
    rp_parser.add_argument(
        "--xunit_feed", type=str, required=False,
        help="Parse xunit and feed data to report portal",
    )
    rp_parser.add_argument(
        "--test_logs", type=str, required=False,
        help="Path to folder where all logs per tests are located.",
    )
    rp_parser.add_argument(
        "--zipped", action='store_true',
        help="True to upload the logs zipped to save time and traffic",
    )
    rp_parser.add_argument(
        "--log_file", type=str, required=False, default=LOG_FILE_NAME,
        help="Log filename for rp_cli (default %s)" % (LOG_FILE_NAME, ),
    )
    rp_parser.add_argument(
        "--log_level", required=False, default=DEFAULT_LOG_LEVEL,
        choices=LOG_LEVELS.keys(),
        help="Log level (default %s)" % (DEFAULT_LOG_LEVEL, ),
    )
    rp_parser.add_argument(
        "--strategy", type=str, required=False, choices=STRATEGIES,
        help="Strategies to handle the xunit file: {0}".format(STRATEGIES),
    )
    rp_parser.add_argument(
        "--store_out_file", nargs="?", const=DEFAULT_OUT_FILE, default=False,
        help="""Produce output file.
                When no name specified
                default name (%s) is used.""" % (DEFAULT_OUT_FILE, ),
    )
    return rp_parser


class ReportPortalServiceRH(ReportPortalService):
    """
    Service class with report portal event callbacks.

    Args:
        endpoint: endpoint of report portal service.
        project: project name to use for launch names.
        token: authorization token.
        api_base: defaults to api/v1, can be changed to other version.
    """
    def __init__(self, endpoint, project, token, api_base="api/v1"):
        super(ReportPortalServiceRH, self).__init__(
            endpoint=endpoint, project=project, token=token, api_base=api_base
        )
        self.session.verify = False

    def get_launches(self, launch_name):
        """
        Get lunches information

        Args:
            launch_name (str): Launch name, e.g.:  e.g.: 'RHV-4.3-tier1', 'RHV-4.2-tier2', 'RHV-4.3-tier3'

        Returns:
             list: of dictionaries include details of latest lunches
        """
        url = uri_join(
            self.base_url, "launch?filter.eq.name={launch_name}&page.size={max_page_size}".format(
                launch_name=launch_name, max_page_size=MAX_PAGE_SIZE
            )
        )
        return self.session.get(url=url)

    def get_shared_filters(self):
        """
        Returns list of shared filters

        Returns:
            requests.Response: Response structure send from server
                Response.content includes list of shared filters
        """
        url = uri_join(self.base_url, "filter/shared")
        return self.session.get(url=url)

    def update_shared_filter(self, filter_id, filter_data):
        """
        Update an existing filter

        Args:
            filter_id (str): The filter ID to update
            filter_data (dict): Dictionary to send to server, see example

        Returns:
            requests.Response: Response structure send from server

        Example:
            filter_data: {
                "name": "string",
                "description": "string",
                "type": "string"
                "is_link": true,
                "share": true,

                "entities": [
                    {
                        "condition": "string",
                        "filtering_field": "string",
                        "value": "string"
                    }
                  ],

                "selection_parameters": {
                    "orders": [
                        {
                            "is_asc": true,
                            "sorting_column": "string"
                        }
                    ],
                    "page_number": 0
                },
             }
        """
        url = uri_join(self.base_url, "filter/{filter_id}".format(filter_id=filter_id))
        return self.session.put(url=url, json=filter_data)


class ReportPortalServiceAsyncRH(ReportPortalServiceAsync):
    """
    Wrapper around service class to transparently provide async operations to agents.

    Args:
        endpoint: endpoint of report portal service.
        project: project name to use for launch names.
        token: authorization token.
        api_base: defaults to api/v1, can be changed to other version.
    """
    def __init__(self, endpoint, project, token, api_base="api/v1", **kwargs):
        super(ReportPortalServiceAsyncRH, self).__init__(
            endpoint=endpoint, project=project, token=token, api_base=api_base, **kwargs
        )
        self.rp_client = ReportPortalServiceRH(endpoint, project, token, api_base)

        # new wrapper methods should be added to this list
        self.supported_methods += ["get_launches", "get_shared_filters", "update_shared_filter"]

    def get_launches(self, launch_name):
        """
        Wrapper method for ReportPortalServiceRH.get_launches()

        Returns:
             list: of dictionaries include details of latest lunches
        """
        args_ = {
            "launch_name": launch_name
        }
        logger.debug("Start get_launches")
        return self.rp_client.get_launches(**args_)

    def get_launches_info(self, launch_name, keys=[]):
        """
        Return all launches information for the given launch_name

        Args:
            launch_name (str): Launch name e.g.: 'RHV-4.3-tier1', 'RHV-4.2-tier2', 'RHV-4.3-tier3'
            keys (list): The dict keys name to return, if empty return all keys

        Returns:
             list: List of dictionaries, each dict include launch information
        """
        launches = self.get_launches(launch_name=launch_name)

        if not launches and launches.status_code != 200:
            logger.error(
                "Fail to get information for launch: '{name}', status code is: '{code}'".format(
                    name=launch_name, code=launches.status_code
                )
            )
            return list()

        if launches.json()["page"]["totalPages"] > 1:
            logger.error(
                "Retrieve results include more then one page: '{pages}'".format(
                    pages=launches.json()["page"]["totalPages"]
                )
            )
            return list()

        if keys:
            ret = list()
            for dic in launches.json()["content"]:
                ret.append([{k: v} for k, v in dic.items() if k in keys][0])
        else:
            ret = launches.json()["content"]
        return ret

    def find_launch_version(self, launch_name, version):
        """
        Find the launch that include the given version

        Args:
            launch_name (str): Launch name e.g.: 'RHV-4.3-tier1', 'RHV-4.2-tier2', 'RHV-4.3-tier3'
            version (str): Product version e.g.: 'rhv-4.3.5-10'

        Return:
            dict: Launch details if launch exists, empty dict otherwise
        """
        launches = self.get_launches_info(launch_name=launch_name)
        launches = [launch for launch in launches if version in launch["tags"]]
        if len(launches) > 1:
            logger.error("Found multiple launches for '{launch}' while only one is expected\n".format(
                launch=launch_name)
            )
            logger.error("Launches for '{launch}' are: {launches}".format(launch=launch_name, launches=launches))
            launches = [launch for launch in launches if launch["status"].strip() == IN_PROGRESS]
        return launches[-1] if launches else dict()

    def get_shared_filters(self):
        """
        Wrapper method for ReportPortalServiceRH.get_shared_filters()

        Returns:
            requests.Response: Response structure send from server
                Response.content includes list of shared filters when each dict is a shared filter
        """
        logger.debug("Start get_shared_filters()")
        return self.rp_client.get_shared_filters()

    def update_shared_filter(self, filter_id, filter_data):
        """
        Wrapper method for ReportPortalServiceRH.update_shared_filters()

        Returns:
             requests.Response: Response structure send from server
        """
        logger.debug(
            "Start update_shared_filters() filter_ID: {id}, json: {data}".format(id=filter_id, data=filter_data)
        )
        return self.rp_client.update_shared_filter(filter_id=filter_id, filter_data=filter_data)

    def update_shared_filter_by_name(self, filter_name, filter_data):
        """
        Update the given shared filter name

        Args:
            filter_name (str): Filter name
            filter_data (dict): New filter data to post

        Returns:
            requests.Response: Response structure send from server if update succeeded,
                or None if filter does not exists
        """
        flt = self.get_filter_by_name(filter_name=filter_name)
        if flt:
            return self.update_shared_filter(filter_id=flt.get("id"), filter_data=filter_data)

        logger.error("Can't update filter '{filter_name}', filter not found!".format(filter_name=filter_name))
        return None

    def get_filter_by_name(self, filter_name):
        """
        Find shared filter by its name

        Args:
            filter_name (str): Shared filter name

        Returns:
             dict: Shared filter details if found, else None
        """
        filters = self.get_shared_filters()
        if filters:
            filters = yaml.full_load(filters.content)
            if filters:
                for flt in filters:
                    if flt.get("name").lower().strip() == filter_name.lower().strip():
                        return flt
        logger.error("No filters found")
        return None


if __name__ == "__main__":
    rp = None
    rp_parser = parser()
    args = rp_parser.parse_args()
    init_logger(args.log_level, args.log_file)
    logger.info("Start")

    config_data = parse_configuration_file(args.config)
    config_data.update(args.__dict__)

    if args.upload_xunit:
        rp = RpManager(config_data, strategy=Strategy())
        rp.import_results()
    elif args.xunit_feed:
        if not args.strategy:
            rp_parser.error('You must specify --strategy if you use --xunit-feed.')
        if args.strategy == 'Rhv':
            rp = RpManager(config_data, strategy=Rhv())
        elif args.strategy == 'Raut':
            rp = RpManager(config_data, strategy=Raut())
        elif args.strategy == 'Cfme':
            rp = RpManager(config_data, strategy=Cfme())
        rp.feed_results()
    else:
        logger.error("Bad command - see the usage!")
        rp_parser.print_help()
        sys.exit(1)
    if rp is not None and args.store_out_file:
        rp.store_launch_info(args.store_out_file)
        logger.info("Output file generated in {}.".format(args.store_out_file))
    logger.info("Finish")
