#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import subprocess


class spi_revision(unittest.TestCase):
    """Spi Revision tests.
    Tests generally execute commands using pipes and asserts on outputs in
    stderr and stdout, and on exit value. These all are non-blocking commands.
    """

    _com_src = os.getenv("COM_SOURCE_DIR")
    _comea_src = os.getenv("COMEA_SOURCE_DIR")
    _comea_root = os.getenv("COMEA_ROOT_DIR")


    def setUp(self):
        # set-up test folders and copy comea source

        # create root
        if not os.path.isdir("%s/gen/comea/" % self._com_src):
            os.makedirs("%s/gen/comea/" % self._com_src)

        # create bin
        if not os.path.isdir("%s/gen/comea/bin" % self._com_src):
            os.makedirs("%s/gen/comea/bin" % self._com_src)
        os.system("cp -f %s/src/bin/comea %s/gen/comea/bin" %
            (self._comea_src , self._com_src))

        # create scripts
        if not os.path.isdir("%s/gen/comea/scripts" % self._com_src):
            os.makedirs("%s/gen/comea/scripts" % self._com_src)
        os.system("cp -f %s/src/scripts/comea-* %s/gen/comea/scripts/" %
            (self._comea_src, self._com_src))

    def test_spi_revision(self):
        """Test spi-revision command.
        Assert on successful value and return code.
        """
	pipe = subprocess.Popen("%s/bin/comea spi-revision" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertEqual(pipe.stdout.read(), "1.11.0\n")
        self.assertFalse(pipe.stderr.read())

    def test_spi_revision_with_invalid_arg(self):
        """Test spi-revision command with invalid arguemnt(negative).
        Error case, expect non-zero return core and error printout in stderr.
        """
        pipe = subprocess.Popen("%s/bin/comea spi-revision version" % self._comea_root,
            shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.stderr.read(), "comea-spi-revision error: unknown command\n")
        self.assertFalse(pipe.stdout.read())

#    def tearDown(self):
#	print "tearDown\n"
