#!/usr/bin/env python
# -*- coding: utf-8 -*-
##
## Copyright (c) 2018 Ericsson AB.
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

import sys
import datetime
import os
import unittest
import shutil
import re
import time
import subprocess
import pydoc

class Vsftp(unittest.TestCase):
    """vsftp availability and configuration tests.
    Tests generally execute commands using pipes and asserts on outputs in
    stderr and stdout, and on exit value. These all are non-blocking commands.
    """
    _cmake_bin  = os.getenv("CMAKE_BINARY_DIR")
    _comea_src  = os.getenv("COMEA_SOURCE_DIR")
    _comea_root = os.getenv("COMEA_ROOT_DIR")

    conf_file_dir = "%s/gen/comea/bin" %_cmake_bin
    conf_file_content = "#Please don't modify this file manually \n\
#This is the reference copy to generate config file based on values provided \n\
#through NBI.This reference copy is updated(only if there are any changes in\n\
#the configuration file)when the vsftpd version used by COM is updated.\n\
\n\
#Configurable options via COM NBI\n \
#match:begin\n \
listen_port=21 \n \
pasv_min_port=0 \n \
pasv_max_port=0 \n \
idle_session_timeout=0 \n \
ssl_ciphers=HIGH \n \
ca_certs_file= \n \
rsa_cert_file= \n \
rsa_private_key_file= \n \
#match:end \n \
\n \
#Options with fixed value \n \
pam_service_name=com-vsftpd \n \
listen=NO \n \
listen_ipv6=YES \n \
local_enable=YES \n \
anonymous_enable=NO \n \
syslog_enable=YES \n \
xferlog_enable=YES \n \
session_support=YES \n \
seccomp_sandbox=NO \n \
pasv_enable=YES \n \
ssl_enable=YES \n \
implicit_ssl=NO \n \
force_local_logins_ssl=YES \n \
force_local_data_ssl=YES \n \
ssl_tlsv1=YES \n \
ssl_sslv2=NO \n \
ssl_sslv3=NO \n \
require_cert=YES \n \
validate_cert=YES \n \
ssl_user_auth_cert=YES \n \
ssl_crosscheck_username=YES \n \
allow_writeable_chroot=YES \n \
chroot_local_user=YES \n \
local_root= %s\n" %conf_file_dir

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
        os.system("cp -f %s/tmp/comea/comea-vsftpd %s/gen/comea/scripts/" %
            (self._cmake_bin, self._cmake_bin))

        # create etc
        if not os.path.isdir("%s/gen/comea/etc" % self._cmake_bin):
            os.mkdir("%s/gen/comea/etc" % self._cmake_bin)
        os.system("cp -f %s/src/etc/*.conf %s/gen/comea/etc/" %
            (self._comea_src, self._cmake_bin))

        # create run
        if not os.path.isdir("%s/gen/comea/run" % self._cmake_bin):
            os.mkdir("%s/gen/comea/run" % self._cmake_bin)

        # create vsftp.conf file and copy it to the necessary path in the
        # build directory
        try:
         os.chdir("%s/gen/comea/etc"%(self._cmake_bin))
         f = open("com-vsftpd.conf",'w')
         f.write("%s"%self.conf_file_content)
         f.close()
        except IOError:
         sys.stderr.write('problem writing:' + 'com-vsftpd.conf')
        """
        The tests require the path of cmake variable "@COM_VSFTPD_INSTALL_PREFIX@"
        COM_VSFTPD_ROOT_DIR="@COM_VSFTPD_INSTALL_PREFIX@"
        Since, this variable will be present only when we build cba-repo,
        For unittests purpose, we will add path from the build directory as
        COM_VSFTPD_ROOT_DIR
        """
        match_string="COM_VSFTPD_ROOT_DIR="
        os.system("sed -i 's>%s>%s\"%s\" #>g' %s/scripts/comea-vsftpd" % (match_string,match_string,self._comea_root,self._comea_root))

    def vsftpd_test_without_cmd(self):
        """Test vsftp script without any sub-commands (negative).
        Error case, expect non-zero return code, error printout in stderr and
        help printout with available sub-commands in stdout.
        """
        #update vsftp configuration file
        pipe = subprocess.Popen("%s/bin/comea vsftpd" % self._comea_root,
               shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertIn("ERROR option must be specified\n",pipe.stderr.read())
        self.assertTrue(pipe.stdout.read()) #help text

    def vsftpd_test_unknown_cmd(self):
        """Test vsftp script with unknown command (negative).
        Error case, expect non-zero return code and error printout in stderr.
        """
        #update vsftp configuration file
        pipe = subprocess.Popen("%s/bin/comea vsftpd titan" % self._comea_root,
               shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertIn("ERROR unknown option\n",pipe.stderr.read())
        self.assertTrue(pipe.stdout.read())

    def vsftpd_test_without_optionvalue_1(self):
        """Test vsftp update script with configure command but
        without optionValue(negative).Assert on successful
        value and return code.
        """
        #update vsftp configuration file without optionValue
        pipe = subprocess.Popen("%s/bin/comea vsftpd configure" % self._comea_root,
               shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertIn("ERROR sub-option must be specified\n",pipe.stderr.read())
        self.assertTrue(pipe.stdout.read())

    def vsftpd_test_without_optionvalue_2(self):
        """Test vsftp update script with configure command but
        without optionValue(negative).Assert on successful
        value and return code.
        """
        pipe = subprocess.Popen("%s/bin/comea vsftpd configure --port" % self._comea_root,
               shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertIn("ERROR Value must be specified\n",pipe.stderr.read())
        self.assertTrue(pipe.stdout.read())

    def vsftpd_test_without_optionvalue_3(self):
        """Test vsftp update script with configure command but
        without optionValue(negative).Assert on successful
        value and return code.
        """
        #update vsftp configuration file without optionValue
        pipe = subprocess.Popen("%s/bin/comea vsftpd configure --port 4 --maxport" % self._comea_root,
               shell=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertIn("ERROR Value must be specified\n",pipe.stderr.read())
        self.assertTrue(pipe.stdout.read())

    def vsftpd_test_get_config_file_path(self):
        """Test vsftp update script with get-config-file option.
        Assert on successful value and return code.
        """
        #get vsftpd configuration file
        pipe = subprocess.Popen("%s/bin/comea vsftpd get-config-file-path" % self._comea_root,
               shell=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"%s/run/com-vsftpd.conf\n" %self._comea_root)

    def vsftpd_test_remove_config_file(self):
        """Test vsftp update script with configure --clear option.
        Assert on successful value and return code.
        """
        #remove vsftpd configuration file
        pipe = subprocess.Popen("%s/bin/comea vsftpd configure --clear" % self._comea_root,
               shell=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(pipe.stdout.read())

        # check configuration file existence
        self.assertFalse(os.path.exists("%s/run/com-vsftpd.conf" % self._comea_root))

    def vsftpd_test_with_one_optionvalue(self):
        """Test vsftp update script with one optionValue(--port).
        Assert on successful value and return code.
        """
        pattern = re.compile('listen_port[\=](.*)')
        port_value = "40"

        #update vsftp configuration file with one optionValue
        pipe = subprocess.Popen("%s/bin/comea vsftpd configure --port %s" % (self._comea_root,port_value),
               shell=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(pipe.stdout.read())

        # check configuration file
        f = open("%s/run/com-vsftpd.conf" % self._comea_root, "r")
        for line in f:
            m = re.search(pattern, line)
            if m:
               break
        self.assertEqual(port_value, m.group(1))

    def vsftpd_test_with_multiple_optionvalues(self):
        """Test vsftp update script with multiple optionValues(positive).
        Assert on successful value and return code.
        """
        minport_pattern = re.compile('pasv_min_port[\=](.*)')
        minport_value = "1"
        maxport_pattern = re.compile('pasv_max_port[\=](.*)')
        maxport_value = "1024"
        timeout_pattern = re.compile('idle_session_timeout[\=](.*)')
        timeout_value = "60"

        #update vsftp configuration file with multiple optionValue
        pipe = subprocess.Popen("%s/bin/comea vsftpd configure --minport %s --maxport %s --timeout %s" % (self._comea_root,
               minport_value,maxport_value,timeout_value),shell=True,stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(pipe.stdout.read())

        # check configuration file
        f = open("%s/run/com-vsftpd.conf" % self._comea_root, "r")
        for line in f:
            m = re.search(minport_pattern, line)
            if m:
               break
        self.assertEqual(minport_value, m.group(1))

        for line in f:
            m = re.search(maxport_pattern, line)
            if m:
               break
        self.assertEqual(maxport_value, m.group(1))

        for line in f:
            m = re.search(timeout_pattern, line)
            if m:
               break
        self.assertEqual(timeout_value, m.group(1))

    def vsftpd_test_with_all_optionvalues(self):
        """Test vsftp update script with all optionValues(positive).
        Assert on successful value and return code.
        """
        port_pattern = re.compile('listen_port[\=](.*)')
        port_value = "40"
        minport_pattern = re.compile('pasv_min_port[\=](.*)')
        minport_value = "1"
        maxport_pattern = re.compile('pasv_max_port[\=](.*)')
        maxport_value = "1024"
        timeout_pattern = re.compile('idle_session_timeout[\=](.*)')
        timeout_value = "60"
        ciphers_pattern = re.compile('ssl_ciphers[\=](.*)')
        ciphers_value = "kEECDH:kEDH:kRSA:!kPSK:!aPSK:!aDSS:!aNULL:!NULL:!SEED:!3DES:!DES:!MD5:!RC4:!CAMELLIA:@STRENGTH"
        cacert_pattern = re.compile('ca_certs_file[\=](.*)')
        cacert_value = "/storage/clear/com-apr9010443/vsftpd/trustedCertsFile.pem"
        rsacert_pattern = re.compile('rsa_cert_file[\=](.*)')
        rsacert_value = "/tmp/cba_sec_credu_11574_0x7f3830100320/node_creds/node_cert_id_1.pem"
        rsakey_pattern = re.compile('rsa_private_key_file[\=](.*)')
        rsakey_value = "/tmp/cba_sec_credu_11574_0x7f3830100320/node_creds/node_key_id_1.pem"

        #update vsftp configuration file with all optionValue
        pipe = subprocess.Popen("%s/bin/comea vsftpd configure --port %s --minport %s --maxport %s --timeout %s --ciphers %s --cacert %s --rsacert %s --rsakey %s"
               %(self._comea_root,port_value,minport_value,maxport_value,timeout_value,ciphers_value,cacert_value,rsacert_value,rsakey_value),
               shell=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE)

        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(pipe.stdout.read())

        # check configuration file
        f = open("%s/run/com-vsftpd.conf" % self._comea_root, "r")

        #checking for port
        for line in f:
            m = re.search(port_pattern, line)
            if m:
               break
        self.assertEqual(port_value, m.group(1))

        #checking for minport
        for line in f:
            m = re.search(minport_pattern, line)
            if m:
               break
        self.assertEqual(minport_value, m.group(1))

        #checking for maxport
        for line in f:
            m = re.search(maxport_pattern, line)
            if m:
               break
        self.assertEqual(maxport_value, m.group(1))

        #checking for timeout
        for line in f:
            m = re.search(timeout_pattern, line)
            if m:
               break
        self.assertEqual(timeout_value, m.group(1))

        #checking for ciphers
        for line in f:
            m = re.search(ciphers_pattern, line)
            if m:
               break
        self.assertEqual(ciphers_value, m.group(1))

        #checking for cacert
        for line in f:
            m = re.search(cacert_pattern, line)
            if m:
               break
        self.assertEqual(cacert_value, m.group(1))

        #checking for rsacert
        for line in f:
            m = re.search(rsacert_pattern, line)
            if m:
               break
        self.assertEqual(rsacert_value, m.group(1))

        #checking for rsakey
        for line in f:
            m = re.search(rsakey_pattern, line)
            if m:
               break
        self.assertEqual(rsakey_value, m.group(1))
