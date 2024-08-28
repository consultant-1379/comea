#!/usr/bin/env python
# -*- coding: utf-8 -*-
##
## Copyright (c) 2015 Ericsson AB.
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
import commands
import random
import filecmp

class ssh(unittest.TestCase):
    """Ssh configuration tests.
    Tests generally execute commands using pipes and asserts on outputs in
    stderr and stdout, and on exit value. These all are non-blocking commands.
    """

    _cmake_bin = os.getenv("CMAKE_BINARY_DIR")
    _comea_src = os.getenv("COMEA_SOURCE_DIR")
    _comea_root = os.getenv("COMEA_ROOT_DIR")
    _sss_ssh_authorizedkeys = os.getenv("SSH_SSH_AUTHORIZEDKEYSFILE")
    _sec_legal_notice_api = os.getenv("SSH_LEGALNOTICEFILE")
    _sec_legal_privacynotice_api = os.getenv("SSH_LEGAL_PRIVACYNOTICEFILE")
    _sec_legal_privacynotice_symlink = os.getenv("SSH_LEGAL_PRIVACYNOTICE_SYMLINK")

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
        os.system("cp -f %s/src/etc/ssh* %s/gen/comea/etc/" %
            (self._comea_src, self._cmake_bin))

        # create log
        if not os.path.isdir("%s/gen/comea/log" % self._cmake_bin):
            os.mkdir("%s/gen/comea/log" % self._cmake_bin)

        # create run
        if not os.path.isdir("%s/gen/comea/run" % self._cmake_bin):
            os.mkdir("%s/gen/comea/run" % self._cmake_bin)

        if os.path.exists(self._sec_legal_privacynotice_api):
            os.system("rm %s" % self._sec_legal_privacynotice_api)

        os.system("touch %s" % self._sss_ssh_authorizedkeys)

        os.system("touch %s" % self._sec_legal_notice_api)

        os.system("touch %s" % self._sec_legal_privacynotice_symlink)

        os.symlink(self._sec_legal_privacynotice_symlink, self._sec_legal_privacynotice_api)

    def test_without_cmd(self):
        """Test netconfssh/clissh/ssh commands without any sub-commands (negative).
        Error case, expect non-zero return code, error printout in stderr and
        help printout with available sub-commands in stdout.
        """
        # execute netconfssh command without sub-command
        pipe = subprocess.Popen("%s/bin/comea netconfssh" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: sub-command must be specified\n")
        self.assertTrue(pipe.stdout.read()) # the help text

        # execute clissh command without sub-command
        pipe = subprocess.Popen("%s/bin/comea clissh" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: sub-command must be specified\n")
        self.assertTrue(pipe.stdout.read()) # the help text

        # execute ssh command without sub-command
        pipe = subprocess.Popen("%s/bin/comea ssh" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: sub-command must be specified\n")
        self.assertTrue(pipe.stdout.read()) # the help text

    def test_unknown_cmd(self):
        """Test netconfssh/clissh/ssh commands with unknown command (negative).
        Error case, expect non-zero return code and error printout in stderr.
        """
        # execute netconfssh command with unknown sub-command
        pipe = subprocess.Popen("%s/bin/comea netconfssh san-jose" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: unknown command\n")
        self.assertFalse(pipe.stdout.read())

        # execute clissh command with unknown sub-command
        pipe = subprocess.Popen("%s/bin/comea clissh san-jose" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: unknown command\n")
        self.assertFalse(pipe.stdout.read())

        # execute ssh command with unknown sub-command
        pipe = subprocess.Popen("%s/bin/comea ssh san-jose" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: unknown command\n")
        self.assertFalse(pipe.stdout.read())

    def test_configuration_without_arg(self):
        """Test ssh configure without argument (negative).
        Error case, expect non-zero return code and error printout in stderr.
        """
        # configure netconfssh without any argument
        pipe = subprocess.Popen("%s/bin/comea netconfssh unlock" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: argument must be specified\n")
        self.assertEqual(pipe.stdout.read(), "usage: comea netconfssh/clissh unlock port <portNumber>\n")

        # configure netconfssh without port number
        pipe = subprocess.Popen("%s/bin/comea netconfssh unlock port" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: Port Number not specified\n")
        self.assertFalse(pipe.stdout.read())

        # configure clissh without any argument
        pipe = subprocess.Popen("%s/bin/comea clissh unlock" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: argument must be specified\n")
        self.assertEqual(pipe.stdout.read(), "usage: comea netconfssh/clissh unlock port <portNumber>\n")

        # configure clissh without port number
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh error: Port Number not specified\n")
        self.assertFalse(pipe.stdout.read())

       # configure ciphers without value
        pipe = subprocess.Popen("%s/bin/comea ssh --ciphers" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh: option '--ciphers' requires an argument\nER Error: getopt failed, rc=1\n")
        self.assertFalse(pipe.stdout.read())

        # configure kex without value
        pipe = subprocess.Popen("%s/bin/comea ssh --kexAlgorithms" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh: option '--kexAlgorithms' requires an argument\nER Error: getopt failed, rc=1\n")
        self.assertFalse(pipe.stdout.read())

        # configure macs without value
        pipe = subprocess.Popen("%s/bin/comea ssh --macs" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh: option '--macs' requires an argument\nER Error: getopt failed, rc=1\n")
        self.assertFalse(pipe.stdout.read())

        # configure ciphers with value but kex without value
        pipe = subprocess.Popen("%s/bin/comea ssh --ciphers aes256-ctr --kexAlgorithms" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh: option '--kexAlgorithms' requires an argument\nER Error: getopt failed, rc=1\n")
        self.assertFalse(pipe.stdout.read())

        # configure ciphers and kex with value but macs without value
        pipe = subprocess.Popen("%s/bin/comea ssh --ciphers aes256-ctr --kexAlgorithms diffie-hellman-group1-sha1 --macs" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea-ssh: option '--macs' requires an argument\nER Error: getopt failed, rc=1\n")
        self.assertFalse(pipe.stdout.read())

    def test_configuration_unlock(self):
        """Test ssh unlock sub-commands
        unlock command will write/configure the ports in oam sshd configuration file"""

        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # check if cli port is configured in oam sshd configuration file
        status,cliPort = commands.getstatusoutput("sed -e '/#cli:port:begin/,/#cli:port:end/!d' %s/etc/sshd_config_oam | grep ^Port | cut -d' ' -f2"  % self._comea_root)
        self.assertEqual(str(cli_port), cliPort)

        #configure netconfssh port with any random number between 22 and 830
        netconf_port = random.randint(22,830)
        pipe = subprocess.Popen("%s/bin/comea netconfssh unlock port %d" % (self._comea_root, netconf_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # check if netconf port is configured in oam sshd configuration file
        status,netconfPort = commands.getstatusoutput("sed -e '/#netconf:port:begin/,/#netconf:port:end/!d' %s/etc/sshd_config_oam | grep ^Port | cut -d' ' -f2"  % self._comea_root)
        self.assertEqual(str(netconf_port), netconfPort)

    def test_enable_publickeyauthentication(self):
        """Test public key authentication support.
        Positive case, expect PubkeyAuthentication in the sshd_config_oam file
        """
        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        #check if pubkeyauthentication is configured
        pipe = subprocess.Popen("grep PubkeyAuthentication %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stderr.read())
        self.assertIn("PubkeyAuthentication",pipe.stdout.read())

    def test_disable_publickeyauthentication(self):
        """Test public key authentication support.
        Negative case, expect PubkeyAuthentication not in the sshd_config_oam file
        """
        # Remove sss_ssh_authorizedkeys file to disable publickey authentication
        os.system("rm %s" % self._sss_ssh_authorizedkeys)
        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        #check if pubkeyauthentication is not configured
        pipe = subprocess.Popen("grep PubkeyAuthentication %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(), 1)
        self.assertFalse(pipe.stderr.read())
        self.assertNotIn("PubkeyAuthentication",pipe.stdout.read())

        #Restore back the file for next testcases
        os.system("touch %s" % self._sss_ssh_authorizedkeys)

    def test_remove_publickeyauthentication(self):
        """Test public key authentication support.
        remove case, expect PubkeyAuthentication not in the sshd_config_oam file
        """
        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        #check if pubkeyauthentication is configured
        pipe = subprocess.Popen("grep PubkeyAuthentication %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stderr.read())
        self.assertIn("PubkeyAuthentication",pipe.stdout.read())

        # Remove sss_ssh_authorizedkeys file to disable publickey authentication
        os.system("rm %s" % self._sss_ssh_authorizedkeys)

        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        #check if pubkeyauthentication is not configured
        pipe = subprocess.Popen("grep PubkeyAuthentication %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(), 1)
        self.assertFalse(pipe.stderr.read())
        self.assertNotIn("PubkeyAuthentication",pipe.stdout.read())

        #Restore back the file for next testcases
        os.system("touch %s" % self._sss_ssh_authorizedkeys)

    def test_no_banner_in_sshd_config_file_and_both_api_present(self):
        """Test banner message configured with both api's available.
        Positive case,expect legal-privacy notice banner message in
        the sshd_config_oam file
        """
        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        # Banner tag configured with legal-privacy notice api oam sshd configuration file
        banner_msg = "Banner %s\n" % self._sec_legal_privacynotice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        # sleep a bit
        time.sleep(1)
        #check if legal-privacy notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(),0)
        self.assertEqual(banner_msg,pipe.stdout.read())

    def test_no_banner_in_sshd_config_file_and_no_api_present(self):
        """Test banner message is empty.
        negative case,expect no banner message in the sshd_config_oam file
        """
        #Remove banner message api's
        os.system("rm %s" % self._sec_legal_privacynotice_api)
        os.system("rm %s" % self._sec_legal_privacynotice_symlink)
        os.system("rm %s" % self._sec_legal_notice_api)

        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)
        banner_msg = "0"

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        #check return code and outputs
        self.assertEqual(pipe.wait(),0)
        #sleep a bit
        time.sleep(1)
        #check if banner message is empty
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(),1)
        self.assertFalse(pipe.stdout.read())
        self.assertNotIn(banner_msg,pipe.stdout.read())

    def test_no_banner_in_sshd_config_file_and_legal_notice_api_present(self):
        """Test banner message configured with legal notice api available.
        Positive case,expect legal notice banner message in the sshd_config_oam file
        """
        #Remove legal-privacy notice api so that legal notice will be configured
        os.system("rm %s" % self._sec_legal_privacynotice_api)
        os.system("rm %s" % self._sec_legal_privacynotice_symlink)

        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        # Banner tag configured with legal notice api in oam sshd config file
        banner_msg = "Banner %s\n" % self._sec_legal_notice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        # sleep a bit
        time.sleep(1)
        #check if legal notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(),0)
        self.assertEqual(banner_msg,pipe.stdout.read())

    def test_no_banner_in_sshd_config_file_and_legal_privacynotice_api_present(self):
        """Test banner message configured with legal-privacy notice api available.
        Positive case,expect legal-privacy notice banner message in the sshd_config_oam file
        """
        #Remove legal notice api
        os.system("rm %s" % self._sec_legal_notice_api)

        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        # Banner tag configured with legal notice api in oam sshd config file
        banner_msg = "Banner %s\n" % self._sec_legal_privacynotice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        # sleep a bit
        time.sleep(1)
        #check if legal-privacy notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(),0)
        self.assertEqual(banner_msg,pipe.stdout.read())

    def test_legal_notice_banner_in_sshd_config_file_and_no_api_present(self):
        """Test banner message is empty.
        Negative case,expect empty banner message when legal notice api
        is configured earlier in the sshd_config_oam file and no api available.
        """
        #Remove legal-privacy notice api so that legal notice will be configured first
        os.system("rm %s" % self._sec_legal_privacynotice_api)
        os.system("rm %s" % self._sec_legal_privacynotice_symlink)

        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        # Banner tag configured with legal notice api in oam sshd configuration file
        banner_msg = "Banner %s\n" % self._sec_legal_notice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        # sleep a bit
        time.sleep(1)
        #check if legal notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(),0)
        self.assertEqual(banner_msg,pipe.stdout.read())

        #Remove both api's
        os.system("rm %s" % self._sec_legal_notice_api)

        # Empty banner message
        banner_msg = "0"

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        #check if banner message is empty
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(),1)
        self.assertFalse(pipe.stdout.read())
        self.assertNotIn(banner_msg,pipe.stdout.read())

    def test_legal_privcaynotice_banner_in_sshd_config_file_and_no_api_present(self):
        """Test banner message is empty.
        Negative case,expect empty banner message when legal-privcay notice api
        is configured earlier in the sshd_config_oam file and no api available.
        """
        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        # Banner tag configured with legal-privacy notice api in oam sshd configuration file
        banner_msg = "Banner %s\n" % self._sec_legal_privacynotice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        # sleep a bit
        time.sleep(1)
        #check if legal-privacy notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(),0)
        self.assertEqual(banner_msg,pipe.stdout.read())

        #Remove both api's
        os.system("rm %s" % self._sec_legal_privacynotice_api)
        os.system("rm %s" % self._sec_legal_privacynotice_symlink)
        os.system("rm %s" % self._sec_legal_notice_api)

        # Empty banner message
        banner_msg = "0"

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # check if banner message is empty
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(),1)
        self.assertFalse(pipe.stdout.read())
        self.assertNotIn(banner_msg,pipe.stdout.read())

    def test_legal_notice_banner_in_sshd_config_file_and_both_api_present(self):
        """Test banner message configured with both api's available.
        Positive case,expect banner message of legal-privacy notice is updated
        when legal notice api is configured earlier in the sshd_config_oam file
        """
        #Remove legal-privacy notice api so that legal notice will be configured first
        os.system("rm %s" % self._sec_legal_privacynotice_api)
        os.system("rm %s" % self._sec_legal_privacynotice_symlink)

        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        # Banner tag configured with legal notice api in oam sshd configuration file
        banner_msg = "Banner %s\n" % self._sec_legal_notice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        # sleep a bit
        time.sleep(1)
        #check if legal notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(),0)
        self.assertEqual(banner_msg,pipe.stdout.read())

        #Restore legal-privacy notice api
        os.system("touch %s" % self._sec_legal_privacynotice_symlink)
        os.symlink(self._sec_legal_privacynotice_symlink, self._sec_legal_privacynotice_api)

        # Banner tag updated with legal-privacy notice api in oam sshd configuration file
        banner_msg = "Banner %s\n" % self._sec_legal_privacynotice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        #check if legal-privacy notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertEqual(banner_msg,pipe.stdout.read())

    def test_legal_notice_banner_in_sshd_config_file_and_legal_privacynotice_api_present(self):
        """Test banner message configured.
        Positive case,expect banner message of legal-privacy notice is updated
        when legal notice api is configured earlier in the sshd_config_oam file
        """
        #Remove legal-privacy notice api so that legal notice will be configured first
        os.system("rm %s" % self._sec_legal_privacynotice_api)
        os.system("rm %s" % self._sec_legal_privacynotice_symlink)

        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        # Banner tag configured with legal notice api in oam sshd configuration file
        banner_msg = "Banner %s\n" % self._sec_legal_notice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        # sleep a bit
        time.sleep(1)
        #check if legal notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(),0)
        self.assertEqual(banner_msg,pipe.stdout.read())

        #Remove legal notice api
        os.system("rm %s" % self._sec_legal_notice_api)

        #Restore legal-privacy notice api
        os.system("touch %s" % self._sec_legal_privacynotice_symlink)
        os.symlink(self._sec_legal_privacynotice_symlink, self._sec_legal_privacynotice_api)

        # Banner tag updated with legal-privacy notice api in oam sshd configuration file
        banner_msg = "Banner %s\n" % self._sec_legal_privacynotice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        #check if legal-privacy notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertEqual(banner_msg,pipe.stdout.read())

    def test_legal_privacynotice_banner_in_sshd_config_file_and_legal_notice_api_present(self):
        """Test banner message configured.
        Positive case,expect banner message of legal notice is updated when
        legal-privacy notice api is configured earlier in the sshd_config_oam file
        """
        #configure clissh port with any random number between 22 and 830
        cli_port = random.randint(22,830)

        # Banner tag configured with legal-privacy notice api in oam sshd configuration file
        banner_msg = "Banner %s\n" % self._sec_legal_privacynotice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(),0)
        # sleep a bit
        time.sleep(1)
        #check if legal-privacy notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(),0)
        self.assertEqual(banner_msg,pipe.stdout.read())

        #Remove legal-privacy notice api
        os.system("rm %s" % self._sec_legal_privacynotice_api)
        os.system("rm %s" % self._sec_legal_privacynotice_symlink)

        # Banner tag updated with legal notice api in oam sshd configuration file
        banner_msg = "Banner %s\n" % self._sec_legal_notice_api

        #configureBanner executed as part of unlock()
        pipe = subprocess.Popen("%s/bin/comea clissh unlock port %d" % (self._comea_root, cli_port)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        #check if legal notice api is configured
        pipe = subprocess.Popen("grep Banner %s/etc/sshd_config_oam" % (self._comea_root)
             , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertEqual(banner_msg,pipe.stdout.read())

    def test_configuration_lock(self):
        """Test ssh lock sub-commands
        lock command will remove the ports in oam sshd configuration file"""

        #lock command should remove the clissh port in sshd_config_oam
        pipe = subprocess.Popen("%s/bin/comea clissh lock" % (self._comea_root)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # check if cli port is removed in oam sshd configuration file
        status,cliPort = commands.getstatusoutput("sed -e '/^#cli:port:begin/,/#cli:port:end$/!d'  %s/etc/sshd_config_oam | sed 's/[^0-9]*//g' " % self._comea_root)
        cliPort = cliPort.strip()
        self.assertEqual("", cliPort)

        #lock command should remove the netconfssh port in sshd_config_oam
        pipe = subprocess.Popen("%s/bin/comea netconfssh lock" % (self._comea_root)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # check if netconf port is removed in oam sshd configuration file
        status,netconfPort = commands.getstatusoutput("sed -e '/^#netconf:port:begin/,/#netconf:port:end$/!d'  %s/etc/sshd_config_oam | sed 's/[^0-9]*//g' " % self._comea_root)
        netconfPort = netconfPort.strip()
        self.assertEqual("", netconfPort)

    def test_ssh_ciphers(self):
        """Test ssh ciphers sub-command
        ciphers command will add a new cipher value in sshd_config_oam """
        cipher_value = "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256"
        # This command should write the cipher value in oam sshd configuration file
        pipe = subprocess.Popen("%s/bin/comea ssh --ciphers %s" % (self._comea_root, cipher_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if Ciphers value is configured in oam sshd configuration file
        status,cipherValue = commands.getstatusoutput("grep -m 1 '^Ciphers' %s/etc/sshd_config_oam" % self._comea_root)
        cipher_value = "Ciphers " + cipher_value
        self.assertEqual(str(cipher_value), cipherValue)

    def test_ssh_kex(self):
        """Test ssh kexAlgorithms sub-command
        kexAlgorithm command will add a new KexAlgorithms value in sshd_config_oam """
        kex_value = "diffie-hellman-group-exchange-sha256"
        # This command should write the KexAlgorithms value in oam sshd configuration file
        pipe = subprocess.Popen("%s/bin/comea ssh --kexAlgorithms %s" % (self._comea_root, kex_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if KexAlgorithms value is configured in oam sshd configuration file
        status,kexValue = commands.getstatusoutput("grep -m 1 '^KexAlgorithms' %s/etc/sshd_config_oam" % self._comea_root)
        kex_value = "KexAlgorithms " + kex_value
        self.assertEqual(str(kex_value), kexValue)

    def test_ssh_macs(self):
        """Test ssh macs sub-command
        macs command will add a new MACs value in sshd_config_oam """
        macs_value = "hmac-md5,hmac-sha1"
        # This command should write the MACs value in oam sshd configuration file
        pipe = subprocess.Popen("%s/bin/comea ssh --macs %s" % (self._comea_root,macs_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if KexAlgorithms value is configured in oam sshd configuration file
        status,macsValue = commands.getstatusoutput("grep -m 1 '^MACs' %s/etc/sshd_config_oam" % self._comea_root)
        macs_value = "MACs " + macs_value
        self.assertEqual(str(macs_value), macsValue)

    def test_ssh_ciphers_kex(self):
        """Test ssh sub-commands
        This command will add a new cipher value and kex value in sshd_config_oam """

        # This command should write the cipher value and kex value in oam sshd configuration file
        cipher_value = "aes128-ctr"
        kex_value = "diffie-hellman-group1-sha1"
        pipe = subprocess.Popen("%s/bin/comea ssh --ciphers %s --kexAlgorithms %s" % (self._comea_root, cipher_value, kex_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

        # Check if Ciphers value is configured in oam sshd configuration file
        status,cipherValue = commands.getstatusoutput("grep -m 1 '^Ciphers' %s/etc/sshd_config_oam" % self._comea_root)
        cipher_value = "Ciphers " + cipher_value
        self.assertEqual(str(cipher_value), cipherValue)
        status,kexValue = commands.getstatusoutput("grep -m 1 '^KexAlgorithms' %s/etc/sshd_config_oam" % self._comea_root)
        kex_value = "KexAlgorithms " + kex_value
        self.assertEqual(str(kex_value), kexValue)

    def test_ssh_ciphers_macs(self):
        """Test ssh sub-commands
        This command will add a new cipher value and macs value in sshd_config_oam """

        # This command should write the cipher value and macs value in oam sshd configuration file
        cipher_value = "aes128-ctr"
        macs_value = "hmac-sha1"
        pipe = subprocess.Popen("%s/bin/comea ssh --ciphers %s --macs %s" % (self._comea_root, cipher_value, macs_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

        # Check if Ciphers value is configured in oam sshd configuration file
        status,cipherValue = commands.getstatusoutput("grep -m 1 '^Ciphers' %s/etc/sshd_config_oam" % self._comea_root)
        cipher_value = "Ciphers " + cipher_value
        self.assertEqual(str(cipher_value), cipherValue)
        status,macsValue = commands.getstatusoutput("grep -m 1 '^MACs' %s/etc/sshd_config_oam" % self._comea_root)
        macs_value = "MACs " + macs_value
        self.assertEqual(str(macs_value), macsValue)

    def test_ssh_kex_macs(self):
        """Test ssh sub-commands
        This command will add a new kex value and macs value in sshd_config_oam """

        # This command should write the kex value and macs value in oam sshd configuration file
        kex_value = "diffie-hellman-group1-sha1"
        macs_value = "hmac-sha1"
        pipe = subprocess.Popen("%s/bin/comea ssh --kexAlgorithms %s --macs %s" % (self._comea_root, kex_value, macs_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

        # Check if Ciphers value is configured in oam sshd configuration file
        status,kexValue = commands.getstatusoutput("grep -m 1 '^KexAlgorithms' %s/etc/sshd_config_oam" % self._comea_root)
        kex_value = "KexAlgorithms " + kex_value
        self.assertEqual(str(kex_value), kexValue)
        status,macsValue = commands.getstatusoutput("grep -m 1 '^MACs' %s/etc/sshd_config_oam" % self._comea_root)
        macs_value = "MACs " + macs_value
        self.assertEqual(str(macs_value), macsValue)

    def test_ssh_ciphers_kex_macs(self):
        """Test ssh sub-commands
        This command will add a new cipher value, kex value and macs value in sshd_config_oam """

        # This command should write the cipher value, kex value and macs value in oam sshd configuration file
        cipher_value = "aes128-ctr"
        kex_value = "diffie-hellman-group1-sha1"
        macs_value = "hmac-sha1"
        pipe = subprocess.Popen("%s/bin/comea ssh --ciphers %s --kexAlgorithms %s --macs %s" % (self._comea_root, cipher_value, kex_value, macs_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

        # Check if Ciphers value is configured in oam sshd configuration file
        status,cipherValue = commands.getstatusoutput("grep -m 1 '^Ciphers' %s/etc/sshd_config_oam" % self._comea_root)
        cipher_value = "Ciphers " + cipher_value
        self.assertEqual(str(cipher_value), cipherValue)
        status,kexValue = commands.getstatusoutput("grep -m 1 '^KexAlgorithms' %s/etc/sshd_config_oam" % self._comea_root)
        kex_value = "KexAlgorithms " + kex_value
        self.assertEqual(str(kex_value), kexValue)
        status,macsValue = commands.getstatusoutput("grep -m 1 '^MACs' %s/etc/sshd_config_oam" % self._comea_root)
        macs_value = "MACs " + macs_value
        self.assertEqual(str(macs_value), macsValue)

    def test_ssh_ipqos(self):
        """Test ssh subcommand ipqos
        This command will add IpQos configuration in sshd_config_oam """

        # This command should write the IPQoS configuration in oam sshd configuration file
        ipqos_value = "16"
        pipe = subprocess.Popen("%s/bin/comea ssh --ipQos %s" % (self._comea_root, ipqos_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

        # Check if ipqos value is configured in oam sshd configuration file
        status,ipqos_str = commands.getstatusoutput("grep -m 1 '^IPQoS' %s/etc/sshd_config_oam" % self._comea_root)
        ipqos_line = "IPQoS " + ipqos_value
        self.assertEqual(str(ipqos_line), ipqos_str)

	#Now modify the value
        ipqos_newval = "20"
        pipe = subprocess.Popen("%s/bin/comea ssh --ipQos %s" % (self._comea_root, ipqos_newval)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

        # Check if ipqos value is configured in oam sshd configuration file
        status,ipqos_str = commands.getstatusoutput("grep -m 1 '^IPQoS' %s/etc/sshd_config_oam" % self._comea_root)
        ipqos_line = "IPQoS " + ipqos_newval
        self.assertEqual(str(ipqos_line), ipqos_str)


	#Now remove the ipqos value
	pipe = subprocess.Popen("%s/bin/comea ssh --removeIpQoS" % (self._comea_root)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
	#assert that ipqos is removed from oam sshd configuration file
	status,ipqos_str = commands.getstatusoutput("grep -m 1 '^IPQoS' %s/etc/sshd_config_oam" % self._comea_root)
	self.assertEqual(str(""), ipqos_str)

    def test_ssh_renegotiationTime(self):
        """Test ssh renegotiationTime sub-command
        renegotiation command will modify the time value in RekeyLimit in sshd_config_oam """

        renegotiationTime = "none"
        # RekeyLimit value should be removed from oam sshd configuration file when renegotiationTime is none
        pipe = subprocess.Popen("%s/bin/comea ssh --renegotiationTime %s" % (self._comea_root, renegotiationTime)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if RekeyLimit value and Banner are removed in oam sshd configuration file
        status,RekeyLimitBanner = commands.getstatusoutput("grep -m 1 '^#Time interval for renegotiation' %s/etc/sshd_config_oam" % self._comea_root)
        RekeyLimit_banner = ""
        self.assertEqual(str(RekeyLimit_banner), RekeyLimitBanner)

        status,RekeyLimitValue = commands.getstatusoutput("grep -m 1 '^RekeyLimit' %s/etc/sshd_config_oam" % self._comea_root)
        RekeyLimit_value = ""
        self.assertEqual(RekeyLimit_value, RekeyLimitValue)

        renegotiationTime = "12"
        # This command should write the renegotiationTime value in oam sshd configuration file
        pipe = subprocess.Popen("%s/bin/comea ssh --renegotiationTime %s" % (self._comea_root, renegotiationTime)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if RekeyLimit value is configured in oam sshd configuration file
        status,RekeyLimitBanner = commands.getstatusoutput("grep -m 1 '^#Time interval for renegotiation' %s/etc/sshd_config_oam" % self._comea_root)
        RekeyLimit_banner = "#Time interval for renegotiation of NBI connections over SSH"
        self.assertEqual(str(RekeyLimit_banner), RekeyLimitBanner)

        status,RekeyLimitValue = commands.getstatusoutput("grep -m 1 '^RekeyLimit' %s/etc/sshd_config_oam" % self._comea_root)
        RekeyLimit_value = "RekeyLimit default " + renegotiationTime +"s"
        self.assertEqual(str(RekeyLimit_value), RekeyLimitValue)

        renegotiationTime = "none"
        # RekeyLimit value should be removed from oam sshd configuration file when renegotiationTime is none
        pipe = subprocess.Popen("%s/bin/comea ssh --renegotiationTime %s" % (self._comea_root, renegotiationTime)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if RekeyLimit value and Banner are removed in oam sshd configuration file
        status,RekeyLimitBanner = commands.getstatusoutput("grep -m 1 '^#Time interval for renegotiation' %s/etc/sshd_config_oam" % self._comea_root)
        RekeyLimit_banner = ""
        self.assertEqual(str(RekeyLimit_banner), RekeyLimitBanner)

        status,RekeyLimitValue = commands.getstatusoutput("grep -m 1 '^RekeyLimit' %s/etc/sshd_config_oam" % self._comea_root)
        RekeyLimit_value = ""
        self.assertEqual(RekeyLimit_value, RekeyLimitValue)

    def test_ssh_AllowTcpForwarding(self):
        """Test ssh subcommand AllowTcpForwarding
        This command will update AllowTcpForwarding configuration in sshd_config_oam """

        # This command should write the AllowTcpForwarding configuration in oam sshd configuration file
        allowTcpForwarding_value = "ENABLED"
        pipe = subprocess.Popen("%s/bin/comea ssh --allowTcpForwarding %s" % (self._comea_root, allowTcpForwarding_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

        # Check if allowTcpForwarding value is configured in oam sshd configuration file
        status,allowTcpForwarding_str = commands.getstatusoutput("grep -m 1 '^#AllowTcpForwarding' %s/etc/sshd_config_oam" % self._comea_root)
        allowTcpForwarding_line = "#AllowTcpForwarding no"
        self.assertEqual(str(allowTcpForwarding_line), allowTcpForwarding_str)

        #Now modify the value
        allowTcpForwarding_newval = "DISABLED"
        pipe = subprocess.Popen("%s/bin/comea ssh --allowTcpForwarding %s" % (self._comea_root, allowTcpForwarding_newval)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

        # Check if allowTcpForwarding value is configured in oam sshd configuration file
        status,allowTcpForwarding_str = commands.getstatusoutput("grep -m 1 '^AllowTcpForwarding' %s/etc/sshd_config_oam" % self._comea_root)
        allowTcpForwarding_line = "AllowTcpForwarding no"
        self.assertEqual(str(allowTcpForwarding_line), allowTcpForwarding_str)

        #Now modify the value
        allowTcpForwarding_newval = "abcxyz"
        pipe = subprocess.Popen("%s/bin/comea ssh --allowTcpForwarding %s" % (self._comea_root, allowTcpForwarding_newval)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

        # Check if allowTcpForwarding value is configured in oam sshd configuration file
        status,allowTcpForwarding_str = commands.getstatusoutput("grep -m 1 '^AllowTcpForwarding' %s/etc/sshd_config_oam" % self._comea_root)
        allowTcpForwarding_line = "AllowTcpForwarding no"
        self.assertEqual(str(allowTcpForwarding_line), allowTcpForwarding_str)

    def test_ssh_maxStartUps(self):
        """Test ssh subcommand maxStartUps
        This command will update maxStartUps configuration in sshd_config_oam """

       # This command should write the maxStartUps configuration in oam sshd configuration file
        maxStartUps_value = "ENABLED"
        pipe = subprocess.Popen("%s/bin/comea ssh --maxStartUps %s" % (self._comea_root, maxStartUps_value)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

       # Check if maxStartUps value is configured in oam sshd configuration file
        status,maxStartUps_str = commands.getstatusoutput("grep -m 1 '^#MaxStartUps' %s/etc/sshd_config_oam" % self._comea_root)
        maxStartUps_line = "#MaxStartUps no"
        self.assertEqual(str(maxStartUps_line), maxStartUps_str)

       #Now modify the value
        maxStartUps_newval = "DISABLED"
        pipe = subprocess.Popen("%s/bin/comea ssh --maxStartUps %s" % (self._comea_root, maxStartUps_newval)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

       # Check if maxStartUps value is configured in oam sshd configuration file
        status,maxStartUps_str = commands.getstatusoutput("grep -m 1 '^MaxStartUps' %s/etc/sshd_config_oam" % self._comea_root)
        maxStartUps_line = "MaxStartUps no"
        self.assertEqual(str(maxStartUps_line), maxStartUps_str)

        #Now modify the value with unknown
        maxStartUps_newval = "abcdxyz"
        pipe = subprocess.Popen("%s/bin/comea ssh --maxStartUps %s" % (self._comea_root, maxStartUps_newval)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)

       # Check if maxStartUps value is configured in oam sshd configuration file
        status,maxStartUps_str = commands.getstatusoutput("grep -m 1 '^MaxStartUps' %s/etc/sshd_config_oam" % self._comea_root)
        maxStartUps_line = "MaxStartUps no"
        self.assertEqual(str(maxStartUps_line), maxStartUps_str)

    def test_ssh_clientAliveInterval(self):
        """Test ssh clientAliveInterval sub-command
        clientAliveInterval command will modify the value in ClientAliveInterval in sshd_config_oam """

        clientAliveInterval = "none"
        # ClientAliveInterval value should be removed from oam sshd configuration file when clientAliveInterval is none
        pipe = subprocess.Popen("%s/bin/comea ssh --clientAliveInterval %s" % (self._comea_root, clientAliveInterval)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if ClientAliveInterval value is removed in oam sshd configuration file
        status,ClientAliveIntervalValue = commands.getstatusoutput("grep -m 1 '^#ClientAliveInterval' %s/etc/sshd_config_oam" % self._comea_root)
        ClientAliveInterval_value = "#ClientAliveInterval 0"
        self.assertEqual(ClientAliveInterval_value, ClientAliveIntervalValue)

        clientAliveInterval = "300"
        # This command should write the clientAliveInterval value in oam sshd configuration file
        pipe = subprocess.Popen("%s/bin/comea ssh --clientAliveInterval %s" % (self._comea_root, clientAliveInterval)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if ClientAliveInterval value is configured in oam sshd configuration file
        status,ClientAliveIntervalValue = commands.getstatusoutput("grep -m 1 '^ClientAliveInterval' %s/etc/sshd_config_oam" % self._comea_root)
        ClientAliveInterval_value = "ClientAliveInterval " + clientAliveInterval
        self.assertEqual(str(ClientAliveInterval_value), ClientAliveIntervalValue)

        clientAliveInterval = "none"
        # ClientAliveInterval value should be removed from oam sshd configuration file when clientAliveInterval is none
        pipe = subprocess.Popen("%s/bin/comea ssh --clientAliveInterval %s" % (self._comea_root, clientAliveInterval)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if ClientAliveInterval value is removed in oam sshd configuration file
        status,ClientAliveIntervalValue = commands.getstatusoutput("grep -m 1 '^#ClientAliveInterval' %s/etc/sshd_config_oam" % self._comea_root)
        ClientAliveInterval_value = "#ClientAliveInterval 0"
        self.assertEqual(ClientAliveInterval_value, ClientAliveIntervalValue)

    def test_ssh_clientAliveCountMax(self):
        """Test ssh clientAliveCountMax sub-command
        clientAliveCountMax command will modify the value in ClientAliveCountMax in sshd_config_oam """

        clientAliveCountMax = "none"
        # ClientAliveCountMax value should be removed from oam sshd configuration file when clientAliveCountMax is none
        pipe = subprocess.Popen("%s/bin/comea ssh --clientAliveCountMax %s" % (self._comea_root, clientAliveCountMax)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if ClientAliveCountMax value is removed in oam sshd configuration file
        status,ClientAliveCountMaxValue = commands.getstatusoutput("grep -m 1 '^#ClientAliveCountMax' %s/etc/sshd_config_oam" % self._comea_root)
        ClientAliveCountMax_value = "#ClientAliveCountMax 3"
        self.assertEqual(ClientAliveCountMax_value, ClientAliveCountMaxValue)

        clientAliveCountMax = "3"
        # This command should write the clientAliveCountMax value in oam sshd configuration file
        pipe = subprocess.Popen("%s/bin/comea ssh --clientAliveCountMax %s" % (self._comea_root, clientAliveCountMax)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if ClientAliveCountMax value is configured in oam sshd configuration file
        status,ClientAliveCountMaxValue = commands.getstatusoutput("grep -m 1 '^ClientAliveCountMax' %s/etc/sshd_config_oam" % self._comea_root)
        ClientAliveCountMax_value = "ClientAliveCountMax " + clientAliveCountMax
        self.assertEqual(str(ClientAliveCountMax_value), ClientAliveCountMaxValue)

        clientAliveCountMax = "none"
        # ClientAliveCountMax value should be removed from oam sshd configuration file when clientAliveCountMax is none
        pipe = subprocess.Popen("%s/bin/comea ssh --clientAliveCountMax %s" % (self._comea_root, clientAliveCountMax)
            , shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        # sleep a bit
        time.sleep(1)
        # Check if ClientAliveCountMax value is removed in oam sshd configuration file
        status,ClientAliveCountMaxValue = commands.getstatusoutput("grep -m 1 '^#ClientAliveCountMax' %s/etc/sshd_config_oam" % self._comea_root)
        ClientAliveCountMax_value = "#ClientAliveCountMax 3"
        self.assertEqual(ClientAliveCountMax_value, ClientAliveCountMaxValue)
