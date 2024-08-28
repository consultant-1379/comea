#!/usr/bin/env python
# -*- coding: utf-8 -*-
##
## Copyright (c) 2011Ericsson AB, 2009 - 2010.
##
## All Rights Reserved. Reproduction in whole or in part is prohibited
## without the written consent of the copyright owner.
##
## ERICSSON MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE
## SUITABILITY OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING
## BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT. ERICSSON
## SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A
## RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
## DERIVATIVES.
##
##

## Testsuite: comea author: Johan Croneby
##

import sys
import datetime
import os
import unittest
import shutil
import re
import time
import subprocess
import pydoc
import base64

class snmp(unittest.TestCase):
    """Snmp availability and configuration tests.
    Tests generally execute commands using pipes and asserts on outputs in
    stderr and stdout, and on exit value. These all are non-blocking commands.
    """

    _cmake_bin = os.getenv("CMAKE_BINARY_DIR")
    _comea_src = os.getenv("COMEA_SOURCE_DIR")
    _comea_root = os.getenv("COMEA_ROOT_DIR")

    _check_process = "ps aux |grep ${USER} |awk '/\\/usr\\/sbin\\/snmpd/ && !/awk/ {print $2}'"

    def setUp(self):
        # set-up test folders and copy comea source

        # create root
        if not os.path.isdir("%s/gen/comea/" % self._cmake_bin):
            os.mkdir("%s/gen/comea/" % self._cmake_bin)

        # create bin
        if not os.path.isdir("%s/gen/comea/bin" % self._cmake_bin):
            os.mkdir("%s/gen/comea/bin" % self._cmake_bin)
        os.system("cp -f %s/src/bin/comea %s/gen/comea/bin" %
            (self._comea_src , self._cmake_bin))

        # create scripts
        if not os.path.isdir("%s/gen/comea/scripts" % self._cmake_bin):
            os.mkdir("%s/gen/comea/scripts" % self._cmake_bin)
        os.system("cp -f %s/src/scripts/comea-* %s/gen/comea/scripts/" %
            (self._comea_src, self._cmake_bin))

        # create etc
        if not os.path.isdir("%s/gen/comea/etc" % self._cmake_bin):
            os.mkdir("%s/gen/comea/etc" % self._cmake_bin)
        os.system("cp -f %s/src/etc/*.conf %s/gen/comea/etc/" %
            (self._comea_src, self._cmake_bin))

        # create log
        if not os.path.isdir("%s/gen/comea/log" % self._cmake_bin):
            os.mkdir("%s/gen/comea/log" % self._cmake_bin)

        # create run
        if not os.path.isdir("%s/gen/comea/run" % self._cmake_bin):
            os.mkdir("%s/gen/comea/run" % self._cmake_bin)

        if os.popen(self._check_process).read():
            os.system("killall snmpd")

    def test_without_cmd(self):
        """Test snmp command without any sub-commands (negative).
        Error case, expect non-zero return code, error printout in stderr and
        help printout with available sub-commands in stdout.
        """
        # execute snmp command without sub-command
        pipe = subprocess.Popen("%s/bin/comea snmp" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-snmp error: sub-command must be specified\n")
        self.assertTrue(pipe.stdout.read()) # the help text

    def test_unknown_cmd(self):
        """Test snmp command with unknown command (negative).
        Error case, expect non-zero return code and error printout in stderr.
        """
        # execute snmp command with unknown sub-command
        pipe = subprocess.Popen("%s/bin/comea snmp san-jose" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-snmp error: unknown command\n")
        self.assertFalse(pipe.stdout.read())

    def test_availability(self):
        """Test snmp start, stop and restart sub-commands.
        The sub-commands are verified sequentially:
            - Start the daemon and expect clean outputs, and zero return code.
              Check the pid file and process if it's actually running.
            - Restart the daemon and expect clean outputs, and zero return
              code. Check the pid, process identification should be updated.
            - Stop the daemon and expect clean outputs, and zero return code.
              Check that process is killed and pid file is removed.
        """
        # start snmpd
        pipe = subprocess.Popen("%s/bin/comea snmp start" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())
        # sleep a bit
        time.sleep(1)
        # check if new snmpd process is created
        process = os.popen(self._check_process).read()
        self.assertTrue(len(process))
        # check if process id is written correctly
        pid = os.popen("cat %s/run/snmpd.pid" % self._comea_root).read()
        self.assertEqual(process, pid)

        # restart snmpd
        pipe = subprocess.Popen("%s/bin/comea snmp restart" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())
        # sleep a bit
        time.sleep(1)
        # check new process
        new_process = os.popen(self._check_process).read()
        self.assertTrue(len(new_process))
        # check if new process has different id
        self.assertNotEqual(process, new_process)
        # check if pid file is updated
        self.assertEqual(new_process, os.popen("cat %s/run/snmpd.pid" %
                         self._comea_root).read())


        # stop snmpd and sleep a bit
        pipe = subprocess.Popen("%s/bin/comea snmp stop" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())
        # sleep a bit
        time.sleep(1)
        # check if the process is killed
        self.assertFalse(len(os.popen(self._check_process).read()))

    def test_config_address(self):
        """Test snmp configure sub-command (agentaddress).
        Set agentaddress and assert it to be updated in the configuration
        file, expect clean outputs and zero return code.
        """
        #pattern = re.compile('agentaddress(.*):(.*):')
        pattern = re.compile('agentaddress[\s](.*)')
        address = "udp:1.1.1.1:123,sdp:[::]:321,udp:0.0.0.0:111"
        # configure snmp address
        pipe = subprocess.Popen("%s/bin/comea snmp configure agentAddress %s"
            % (self._comea_root, address), shell=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())
        # check configuration file
        f = open("%s/etc/snmpd.conf" % self._comea_root, "r")
        for line in f:
            m = re.search(pattern, line)
            if (m):
                break
        self.assertEqual(address, m.group(1))

    def test_config_without_arg(self):
        """Test snmp configure without argument (negative).
        Error case, expect non-zero return code and error printout in stderr.
        """
        # execute snmp configure without argument
        pipe = subprocess.Popen("%s/bin/comea snmp configure" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-snmp error: argument must be specified\n")
        self.assertEqual(pipe.stdout.read(), "usage: comea snmp configure "
            "agentAddress <address> community <communities>\n")

    def test_config_unknown_arg(self):
        """Test snmp configure with unknown argument (negative).
        Error case, expect non-zero return code and error printout in stderr.
        """
        # execute snmp configure with unknown argument
        pipe = subprocess.Popen("%s/bin/comea snmp configure california=%s"
            % (self._comea_root, "san-jose"), shell=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-snmp error: unknown argument\n")
        self.assertFalse(pipe.stderr.read())

    def test_new_pwd(self):
        """Test new password generation.
        Check existing password in conf file., call start in order for a new password
        to be generated and written to the conf file. Check that new password differs
        from the old one, expect clean outputs and zero return code.
        """
        # create humbug pwd file
        path = "%s/run/snmpPwdFile" % self._comea_root
        pwd_file = file(path, "w")
        pwd_file.write("1234567")
        pwd_file.close()

        # check existing password
        old_pwd = ""
        f = open("%s/run/snmpPwdFile" % self._comea_root, "r")
        for line in f:
            m = re.search('(.*)', line)
            if (m):
                old_pwd = m.group(0)
                break

        # start and stop snmpd to generate new password
        # start snmpd
        pipe = subprocess.Popen("%s/bin/comea snmp start" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())
        # sleep a bit
        time.sleep(1)
        # check if new snmpd process is created
        process = os.popen(self._check_process).read()
        self.assertTrue(len(process))
        # check if process id is written correctly
        pid = os.popen("cat %s/run/snmpd.pid" % self._comea_root).read()
        self.assertEqual(process, pid)

        # check new password
        f = open("%s/run/snmpPwdFile" % self._comea_root, "r")
        for line in f:
            m = re.search('(.*)', line)
            if (m):
                break
        new_pwd = m.group(0)
        self.assertNotEqual(old_pwd, new_pwd)

        # stop snmpd and sleep a bit
        pipe = subprocess.Popen("%s/bin/comea snmp stop" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())
        # sleep a bit
        time.sleep(1)
        # check if the process is killed
        self.assertFalse(len(os.popen(self._check_process).read()))

    def test_config_community(self):
        """Test snmp configure sub-command (community).
        Set new community values and assert them to be updated in the configuration
        file, expect clean outputs and zero return code.
        """
                        
        community_values = str(base64.b64encode("public"))+","+str(base64.b64encode("private"))+","+str(base64.b64encode("pistage"))+","+str(base64.b64encode("pelikan"))
        test_values = "public,private,pistage,pelikan"

        # configure community values
        pipe = subprocess.Popen("%s/bin/comea snmp configure community %s"
            % (self._comea_root, community_values), shell=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())

        # check configuration file
        read_com2sec = ""
        pattern = re.compile('^com2sec[\s]+[\'](.*)[\'][\s]+default[\s]+[\'](.*)[\']')
        f = open("%s/etc/snmpd.conf" % self._comea_root, "r")
        for line in f:
            m = re.search(pattern, line)
            if (m):
                read_com2sec += "%s," % (m.group(2) )

        # Quick ditry fix solution to match string
        read_com2sec = read_com2sec.rstrip(',')               

        self.assertEqual(test_values, read_com2sec)

    def test_config_community_ipv6(self):
        """Test snmp configure sub-command (community).
        Set new community values after an ipv6 address is listed under agentxaddress tag,
        then the com2sec rows should be doubled also listing ipv6 values.
        """

        # Tmp test
        address = "udp:1.1.1.1:123,udp6:[::]:321,udp:0.0.0.0:111"
        # Configure com2sec values

        assert_values = "public,private,pistage,pelikan"
        community_values = str(base64.b64encode("public"))+","+str(base64.b64encode("private"))+","+str(base64.b64encode("pistage"))+","+str(base64.b64encode("pelikan"))

        # configure community values
        pipe = subprocess.Popen("%s/bin/comea snmp configure agentAddress %s community %s"
            % (self._comea_root, address, community_values), shell=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())
        # read values from conf

        read_com2sec=""

        pattern = re.compile('^com2sec6[\s]+[\'](.*)[\'][\s]+default[\s]+[\'](.*)[\']')
        f = open("%s/etc/snmpd.conf" % self._comea_root, "r")
        for line in f:
            m = re.search(pattern, line)
            if (m):
                read_com2sec += "%s," % (m.group(2) )

        # Quick ditry fix solution to match string
        read_com2sec = read_com2sec.rstrip(',')
        self.assertEqual(assert_values, read_com2sec)

    def test_config_community_withIpAddr(self):
        """Test snmp configure with IPaddr sub-command (community ipAddress).
        Set new community values and Ip address and assert them to be updated in the configuration
        file, expect clean outputs and zero return code.
        """
        community_values = str(base64.b64encode("public"))+","+str(base64.b64encode("private"))+","+str(base64.b64encode("pistage"))+","+ \
                           str(base64.b64encode("pelikan"))
        ipaddress_values = str("10.10.10.1")+","+str("10.10.10.2")+","+str("10.10.10.3")+","+str("10.10.10.4")
        test_values = "10.10.10.1,10.10.10.2,10.10.10.3,10.10.10.4"

        # configure community values
        pipe = subprocess.Popen("%s/bin/comea snmp configure community %s ipAddress %s"
            % (self._comea_root, community_values, ipaddress_values), shell=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())

        # check configuration file
        read_com2sec = ""
        pattern = re.compile('^com2sec[\s]+[\'](.*)[\'][\s]+(((?:[0-9]{1,3}\.){3}[0-9]{1,3})|default)[\s]+[\'](.*)[\']')
        f = open("%s/etc/snmpd.conf" % self._comea_root, "r")
        for line in f:
            m = re.search(pattern, line)
            if (m):
                read_com2sec += "%s," % (m.group(2) )

        # Quick ditry fix solution to match string
        read_com2sec = read_com2sec.rstrip(',')

        self.assertEqual(test_values, read_com2sec)

    def test_config_community_withoutIpAddr(self):
        """Test snmp configure without ipAddress sub-command (community).
        Set new community values, default values and assert them to be updated in the configuration
        file, expect clean outputs and zero return code.
        """
        community_values = str(base64.b64encode("public"))+","+str(base64.b64encode("private"))+","+str(base64.b64encode("pistage"))+","+ \
                           str(base64.b64encode("pelikan"))
        test_values = "default,default,default,default"

       # configure community values
        pipe = subprocess.Popen("%s/bin/comea snmp configure community %s"
            % (self._comea_root, community_values), shell=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())

        # check configuration file
        read_com2sec = ""
        pattern = re.compile('^com2sec[\s]+[\'](.*)[\'][\s]+(((?:[0-9]{1,3}\.){3}[0-9]{1,3})|default)[\s]+[\'](.*)[\']')
        f = open("%s/etc/snmpd.conf" % self._comea_root, "r")
        for line in f:
            m = re.search(pattern, line)
            if (m):
                read_com2sec += "%s," % (m.group(2) )

        # Quick ditry fix solution to match string
        read_com2sec = read_com2sec.rstrip(',')

        self.assertEqual(test_values, read_com2sec)

    def test_config_trapsess(self):
        """Test trapsess configuration written to the conf file.
        Expect clean outputs and zero return code."""
        # create temporary file
        path = "%s/temp_inform" %self._comea_root
        trapsess_config = "trapsess -Ci -v 3 -u user -r 1 -t 3 -l authPriv -a MD5 -A keykeykey -x DES -X keykeykey 1.2.3.4:162\n"
        pwd_file = open(path, "w+")
        pwd_file.write("%s" % trapsess_config)
        pwd_file.close()

        # configure trapsess values
        pipe = subprocess.Popen("%s/bin/comea snmp configure trapsess %s"
            % (self._comea_root, path), shell=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())

        # sleep a bit
        time.sleep(1)

         #check if trapsess is configured
        pipe = subprocess.Popen("grep \"%s\" %s/etc/snmpd.conf" % (trapsess_config, self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stderr.read())
        self.assertIn(trapsess_config,pipe.stdout.read())

    def test_exactengineid_support_version(self):
        """Test exactEngineID supported net-snmp version is installed or not."""
        supported_version = "5.5.0"
        expected_result = "no"
        # Check the installed net-snmp version
        pipe = subprocess.Popen("/usr/sbin/snmpd --version | awk '/NET-SNMP\ version/ {print $3}'"
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        installed_version = pipe.stdout.read()
        if installed_version >= supported_version:
            expected_result = "yes"

        # Check isExactEngineIdSupported for the installed net-snmp version
        pipe = subprocess.Popen("%s/bin/comea snmp isExactEngineIdSupported"
            % (self._comea_root), shell=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)

        # check return code and expected result
        self.assertEqual(pipe.wait(), 0)
        self.assertIn(expected_result,pipe.stdout.read())

    def test_availability_ipv6(self):
        """Test snmp start and stop using ipv6 address.
        Set agent address to ipv6 localhost and try to start and stop Net-SNMP daemon.
        """

        address = "udp6:[::1]:54321"
        # configure snmp address
        pipe = subprocess.Popen("%s/bin/comea snmp configure agentAddress %s"
            % (self._comea_root, address), shell=True, stderr=subprocess.PIPE,
            stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())

        # start snmpd
        pipe = subprocess.Popen("%s/bin/comea snmp start" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())
        # sleep a bit
        time.sleep(1)
        # check if new snmpd process is created
        process = os.popen(self._check_process).read()
        self.assertTrue(len(process))
        # check if process id is written correctly
        pid = os.popen("cat %s/run/snmpd.pid" % self._comea_root).read()
        self.assertEqual(process, pid)

        # stop snmpd and sleep a bit
        pipe = subprocess.Popen("%s/bin/comea snmp stop" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        self.assertFalse(pipe.stderr.read())
        # sleep a bit
        time.sleep(1)
        # check if the process is killed
        self.assertFalse(len(os.popen(self._check_process).read()))

    def test_comea_run(self):
        """Test snmp start and stop after changing the runtime location of comea.
        The sub-commands are verified sequentially:
            - Create any temporary directory and set it to the env variable COMEA_SNMP_RUN_DIR
	    - Start the daemon with new env variable as input and expect clean outputs, and zero return code.
            - Compare the pid in the pid file and pid of the process which is currently running.
        """
        # create comea_run dir
        if not os.path.isdir("%s/gen/comea/comea_run_dir" % self._cmake_bin):
            os.mkdir("%s/gen/comea/comea_run_dir" % self._cmake_bin)
        #Set the COMEA_SNMP_RUN_DIR variable
        new_env = os.environ.copy()
        new_env['COMEA_SNMP_RUN_DIR'] = self._cmake_bin + "/gen/comea/comea_run_dir"
        # start snmpd and send the new variable as input to the subprocess
        pipe = subprocess.Popen("%s/bin/comea snmp start" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=new_env)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        output = pipe.stdout.read()
        self.assertFalse("error" in output)
        # sleep a bit
        time.sleep(1)
        # check if new snmpd process is created
        process = os.popen(self._check_process).read()
        self.assertTrue(len(process))
        # check if process id is written in the new directory correctly
        pid = os.popen("cat %s/comea_run_dir/snmpd.pid" % self._comea_root).read()
        self.assertEqual(process, pid)

	# stop snmpd and sleep a bit
        pipe = subprocess.Popen("%s/bin/comea snmp stop" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=new_env)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        output = pipe.stdout.read()
        self.assertFalse("error" in output)
        # sleep a bit
        time.sleep(1)
        # check if the process is killed
        self.assertFalse(len(os.popen(self._check_process).read()))

    # check if the process is killed
    def tearDown(self):
        # kill if some snmpd exists
        if os.popen(self._check_process).read():
            os.system("killall snmpd")

