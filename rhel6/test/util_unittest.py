#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import time
import subprocess


class util(unittest.TestCase):
    """Utility tests.
    Tests generally execute commands using pipes and asserts on outputs in
    stderr and stdout, and on exit value. These all are non-blocking commands.
    """

    _cmake_bin = os.getenv("CMAKE_BINARY_DIR")
    _comea_src = os.getenv("COMEA_SOURCE_DIR")
    _comea_root = os.getenv("COMEA_ROOT_DIR")

    _check_process = "ps aux |grep ${USER} |awk '/snmpd/ && !/awk/ {print $2}'"

    def setUp(self):
        # set-up test folders and copy comea source

        # create root
        if not os.path.isdir("%s/gen/comea/" % self._cmake_bin):
            os.makedirs("%s/gen/comea/" % self._cmake_bin)

        # create bin
        if not os.path.isdir("%s/gen/comea/bin" % self._cmake_bin):
            os.makedirs("%s/gen/comea/bin" % self._cmake_bin)
        os.system("cp -f %s/src/bin/comea %s/gen/comea/bin" %
            (self._comea_src , self._cmake_bin))

        # create scripts
        if not os.path.isdir("%s/gen/comea/scripts" % self._cmake_bin):
            os.makedirs("%s/gen/comea/scripts" % self._cmake_bin)
        os.system("cp -f %s/src/scripts/comea-* %s/gen/comea/scripts/" %
            (self._comea_src, self._cmake_bin))

        # create etc
        if not os.path.isdir("%s/gen/comea/etc" % self._cmake_bin):
            os.makedirs("%s/gen/comea/etc" % self._cmake_bin)
        os.system("cp -f %s/src/etc/*.conf %s/gen/comea/etc/" %
            (self._comea_src, self._cmake_bin))

        # create log
        if not os.path.isdir("%s/gen/comea/log" % self._cmake_bin):
            os.makedirs("%s/gen/comea/log" % self._cmake_bin)

        # create run
        if not os.path.isdir("%s/gen/comea/run" % self._cmake_bin):
            os.makedirs("%s/gen/comea/run" % self._cmake_bin)

        if os.popen(self._check_process).read():
            os.system("killall snmpd")


    def test_without_cmd(self):
        """Test main script without any commands (negative).
        Error case, expect non-zero return code, error printout in stderr and
        additionally help text printout in stdout.
        """
        pipe = subprocess.Popen("%s/bin/comea" % self._comea_root, shell=True,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 1)
        self.assertEqual(pipe.stderr.read(), "comea error: Command must be specified.\n")
        self.assertTrue(pipe.stdout.read()) # the help text


    def test_unknown_cmd(self):
        """Test main script with unknown command (negative).
        Error case, expect non-zero return code and error printout in stderr.
        """
        pipe = subprocess.Popen("%s/bin/comea san-jose" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.stderr.read(), "comea error: Unknown command.\n")
        self.assertFalse(pipe.stdout.read())


    def test_obsolete_option_authorization(self):
	"""Test that it is not possible to use obsolete option authorization (negative).
        Error case, expect non-zero return code and error printout in stderr.
        """
        pipe = subprocess.Popen("%s/bin/comea authorization default" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1) 
        self.assertEqual(pipe.stderr.read(), "comea error: Option authorization is obsolete.\n")
        self.assertFalse(pipe.stdout.read())


    def test_version(self):
        """Test version command.
        Assert on successful value and return code.
        """
        pipe = subprocess.Popen("%s/bin/comea version" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertEqual(pipe.stdout.read(), "1.2\n")
        self.assertFalse(pipe.stderr.read())

    def test_terminate(self):
        """Test terminate command.
        The command terminate releases all the allocated resources. Currently
        only Net-SNMP daemon needs to be killed.
        """
        os.system("%s/bin/comea snmp start" % self._comea_root)
        time.sleep(2)
        pipe = subprocess.Popen("%s/bin/comea terminate" % self._comea_root,
            shell=True, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stdout.read())
        #self.assertFalse(pipe.stderr.read())
        # check snmp process
        self.assertFalse(os.popen(self._check_process).read())

    def tearDown(self):
        # kill if some snmpd exists
        if os.popen(self._check_process).read():
            os.system("killall snmpd")

