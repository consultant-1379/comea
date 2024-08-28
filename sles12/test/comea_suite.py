#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import re
import snmp_unittest
import util_unittest
import authentication_unittest
import spi_revision_unittest
import ssh_unittest
import vsftp_unittest

from xml.etree import ElementTree as ET
import pydoc
from datetime import datetime
import time

# Subclass TestSuite for test case data collection
class TesterSuite(unittest.TestSuite):

    def __init__(self):
        self.tc_list = []
        unittest.TestSuite.__init__(self)

    def addTest(self, test):
        tc_name_type = re.split('( )', str(test))
        pattern = re.compile('(.*)unittest.(.*)\)')
        tc_type = re.search(pattern, str(tc_name_type[2]))
        tc = (str(tc_name_type[0]), str(tc_type.group(2)))
        self.tc_list.append(tc)
        unittest.TestSuite.addTest(self, test)

def suite():
    suite = TesterSuite()

    # tests from util_unittest
    suite.addTest(util_unittest.util('test_without_cmd'))
    suite.addTest(util_unittest.util('test_unknown_cmd'))
    suite.addTest(util_unittest.util('test_obsolete_option_authorization'))
    suite.addTest(util_unittest.util('test_version'))
    #suite.addTest(util_unittest.util('test_terminate'))

    # tests from snmp_unittest
    suite.addTest(snmp_unittest.snmp('test_without_cmd'))
    suite.addTest(snmp_unittest.snmp('test_unknown_cmd'))
    #suite.addTest(snmp_unittest.snmp('test_availability'))
    suite.addTest(snmp_unittest.snmp('test_config_address'))
    suite.addTest(snmp_unittest.snmp('test_config_without_arg'))
    suite.addTest(snmp_unittest.snmp('test_config_unknown_arg'))
    #suite.addTest(snmp_unittest.snmp('test_new_pwd'))
    suite.addTest(snmp_unittest.snmp('test_config_community'))
    suite.addTest(snmp_unittest.snmp('test_config_community_ipv6'))
    suite.addTest(snmp_unittest.snmp('test_config_community_withIpAddr'))
    suite.addTest(snmp_unittest.snmp('test_config_community_withoutIpAddr'))
    suite.addTest(snmp_unittest.snmp('test_config_trapsess'))
    suite.addTest(snmp_unittest.snmp('test_exactengineid_support_version'))
    #suite.addTest(snmp_unittest.snmp('test_availability_ipv6'))
    suite.addTest(snmp_unittest.snmp('test_comea_run'))

    # tests from spi_revision_unittest
    suite.addTest(spi_revision_unittest.spi_revision('test_spi_revision'))
    suite.addTest(spi_revision_unittest.spi_revision('test_spi_revision_with_invalid_arg'))

    # old tests from authentication_unittest
    suite.addTest(authentication_unittest.authentication('old_test_default'))
    suite.addTest(authentication_unittest.authentication('old_test_commit_no_nodetype'))
    suite.addTest(authentication_unittest.authentication('old_test_commit_one_nodetype'))
    suite.addTest(authentication_unittest.authentication('old_test_commit_several_nodetypes'))
    suite.addTest(authentication_unittest.authentication('old_test_prepare'))
    suite.addTest(authentication_unittest.authentication('old_test_prepare_no_other_args'))
    suite.addTest(authentication_unittest.authentication('test_oldLOTC_versionfile_and_No_LOTCscript'))

    # tests from authentication_unittest
    suite.addTest(authentication_unittest.authentication('test_default'))
    suite.addTest(authentication_unittest.authentication('test_default_without_tlsd'))
    suite.addTest(authentication_unittest.authentication('test_no_tls_or_nodetype'))
    suite.addTest(authentication_unittest.authentication('test_no_tls_prepare'))
    suite.addTest(authentication_unittest.authentication('test_no_tls_use_old_lotc_script'))
    suite.addTest(authentication_unittest.authentication('test_no_tls_with_binddn'))
    suite.addTest(authentication_unittest.authentication('test_no_tls_with_binddn_and_bindpw'))
    suite.addTest(authentication_unittest.authentication('test_obsolete_option_bind_password'))
    suite.addTest(authentication_unittest.authentication('test_no_tls_without_binddn_and_bindpw'))

    suite.addTest(authentication_unittest.authentication('test_prepare_no_other_args'))
    suite.addTest(authentication_unittest.authentication('test_prepare_wildcard_nodetype'))

    suite.addTest(authentication_unittest.authentication('test_syncd_default_twice'))

    suite.addTest(authentication_unittest.authentication('test_tls_all_options_set'))
    suite.addTest(authentication_unittest.authentication('test_tls_no_tls_mode_option'))
    suite.addTest(authentication_unittest.authentication('test_tls_tls_mode_ldaps'))
    suite.addTest(authentication_unittest.authentication('test_tls_commit_no_nodetype'))
    suite.addTest(authentication_unittest.authentication('test_tls_commit_one_nodetype'))
    suite.addTest(authentication_unittest.authentication('test_tls_commit_wildcard_nodetype'))
    suite.addTest(authentication_unittest.authentication('test_tls_commit_several_nodetypes'))
    suite.addTest(authentication_unittest.authentication('test_tls_prepare'))
    suite.addTest(authentication_unittest.authentication('test_tls_syncd_no_nodetype_twice'))
    suite.addTest(authentication_unittest.authentication('test_tls_use_old_lotc_script'))
    suite.addTest(authentication_unittest.authentication('test_override_ldap_gid'))
    suite.addTest(authentication_unittest.authentication('test_override_ldap_home_dir'))
    suite.addTest(authentication_unittest.authentication('test_tls_ca_cert_dir_set'))
    suite.addTest(authentication_unittest.authentication('test_tls_prepare_with_tls_ca_cert_directory'))
    suite.addTest(authentication_unittest.authentication('test_empty_baseDn'))
    suite.addTest(authentication_unittest.authentication('test_tls_with_referrals_on_off'))

    # tests from com sshd manager
    suite.addTest(ssh_unittest.ssh('test_without_cmd'))
    suite.addTest(ssh_unittest.ssh('test_unknown_cmd'))
    suite.addTest(ssh_unittest.ssh('test_configuration_without_arg'))
    suite.addTest(ssh_unittest.ssh('test_configuration_unlock'))
    suite.addTest(ssh_unittest.ssh('test_enable_publickeyauthentication'))
    suite.addTest(ssh_unittest.ssh('test_disable_publickeyauthentication'))
    suite.addTest(ssh_unittest.ssh('test_remove_publickeyauthentication'))
    suite.addTest(ssh_unittest.ssh('test_no_banner_in_sshd_config_file_and_both_api_present'))
    suite.addTest(ssh_unittest.ssh('test_no_banner_in_sshd_config_file_and_no_api_present'))
    suite.addTest(ssh_unittest.ssh('test_no_banner_in_sshd_config_file_and_legal_notice_api_present'))
    suite.addTest(ssh_unittest.ssh('test_no_banner_in_sshd_config_file_and_legal_privacynotice_api_present'))
    suite.addTest(ssh_unittest.ssh('test_legal_notice_banner_in_sshd_config_file_and_no_api_present'))
    suite.addTest(ssh_unittest.ssh('test_legal_privcaynotice_banner_in_sshd_config_file_and_no_api_present'))
    suite.addTest(ssh_unittest.ssh('test_legal_notice_banner_in_sshd_config_file_and_both_api_present'))
    suite.addTest(ssh_unittest.ssh('test_legal_notice_banner_in_sshd_config_file_and_legal_privacynotice_api_present'))
    suite.addTest(ssh_unittest.ssh('test_legal_privacynotice_banner_in_sshd_config_file_and_legal_notice_api_present'))
    suite.addTest(ssh_unittest.ssh('test_configuration_lock'))
    suite.addTest(ssh_unittest.ssh('test_ssh_ciphers'))
    suite.addTest(ssh_unittest.ssh('test_ssh_kex'))
    suite.addTest(ssh_unittest.ssh('test_ssh_macs'))
    suite.addTest(ssh_unittest.ssh('test_ssh_ciphers_kex'))
    suite.addTest(ssh_unittest.ssh('test_ssh_ciphers_macs'))
    suite.addTest(ssh_unittest.ssh('test_ssh_kex_macs'))
    suite.addTest(ssh_unittest.ssh('test_ssh_ciphers_kex_macs'))
    suite.addTest(ssh_unittest.ssh('test_ssh_ipqos'))
    suite.addTest(ssh_unittest.ssh('test_ssh_renegotiationTime'))
    suite.addTest(ssh_unittest.ssh('test_ssh_clientAliveInterval'))
    suite.addTest(ssh_unittest.ssh('test_ssh_clientAliveCountMax'))

    #tests from vsftpd_unittest
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_without_cmd'))
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_unknown_cmd'))
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_without_optionvalue_1'))
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_without_optionvalue_2'))
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_without_optionvalue_3'))
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_get_config_file_path'))
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_remove_config_file'))
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_with_one_optionvalue'))
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_with_multiple_optionvalues'))
    suite.addTest(vsftp_unittest.Vsftp('vsftpd_test_with_all_optionvalues'))
    return suite


def create_report():

    date_now = str(datetime.now())
    date_string = ""
    stripped_time = re.findall(r'\d+', date_now)
    for digits in stripped_time:
        date_string += digits

    _cmake_bin = os.getenv("CMAKE_BINARY_DIR")

    if not os.path.isdir("%s/gen/comea/test-report" % _cmake_bin):
        os.mkdir("%s/gen/comea/test-report" % _cmake_bin)

    if not os.path.isdir("%s/gen/comea/test-report/%s" % (_cmake_bin, date_string[:-6])):
        os.mkdir("%s/gen/comea/test-report/%s" % (_cmake_bin, date_string[:-6]))

    path = "%s/gen/comea/test-report/%s/test_report.txt" % (_cmake_bin, date_string[:-6])
    pathToXmlStr = "%s/gen/comea/test-report/%s/test_report.xml" % (_cmake_bin, date_string[:-6])

    # creating root element
    testsuites = ET.Element('testsuites')
    testsuite = ET.SubElement(testsuites, 'testsuite')

    # result table formatting data
    word_len = 0

    for name_type_tuple in test_suite.tc_list:
        if len(name_type_tuple[0]) > word_len:
            word_len = len(name_type_tuple[0])

    # write to file
    report_file = file(path, "w")
    report_file.write("COM EA Test Report\n\n")
    report_file.write("Execution Date: %s\n\n" % date_now[:-7])

    # extract tc type and name from errors and failures
    pattern = re.compile('\.([^\.]*) testMethod=([^>]*)')
    failures = re.findall(pattern, str(results.failures))
    errors = re.findall(pattern, str(results.errors))

    tc_type = ""

    for name_type_tuple in test_suite.tc_list:
        fail = False
        error = False

        if tc_type == "" or tc_type != name_type_tuple[1]:
            tc_type = name_type_tuple[1]
            report_file.write("\n%s\n\n" % tc_type)

        testcase=ET.SubElement(testsuite, "testcase",name = name_type_tuple[0],classname = tc_type)

        report_file.write("%s" % name_type_tuple[0].ljust(word_len+4, '.'))

        for fail_tc in failures:
            if name_type_tuple[0] == fail_tc[1] and fail_tc[0] == tc_type:
                report_file.write("FAIL!\n")
                fail = True
                ET.SubElement(testcase, "failure",type = name_type_tuple[0])

        for error_tc in errors:
            if name_type_tuple[0] == error_tc[1] and error_tc[0] == tc_type:
                report_file.write("ERROR!\n")
                error = True
                ET.SubElement(testcase, "error",type = name_type_tuple[0])

        if not (fail or error):
            report_file.write("PASS\n")

    # storing the test results in xml format
    testsuite.set('tests',str(results.testsRun))
    testsuite.set('failures', str(len(failures)))
    testsuite.set('errors', str(len(errors)))
    testsuite.set('time',str(time_diff))
    testsuite.set('name','comeaunittest')
    tree = ET.ElementTree(testsuites)
    pattern = re.compile('(.*)Result (.*)>')
    res = re.search(pattern, str(results))

    report_file.write("\n\nTotal: %s" % res.group(2))

    outFile = open(pathToXmlStr, 'w')
    tree.write(outFile)


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    test_suite = suite()
    # calculation the start time of the test_suite execution
    start_time = time.time()
    results = runner.run(test_suite)
    # here calculating the total test_suite execution time and using round method setting into 2 decimal values
    time_diff = round((time.time() - start_time),2)
    create_report()

