#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import time
import subprocess
import re
from shutil import rmtree, copyfile, copytree, copy
import glob
from difflib import Differ

class authentication(unittest.TestCase):
    """Utility tests. 
    Tests generally execute commands using pipes and asserts on outputs in
    stderr and stdout, and on exit value. These all are non-blocking commands.
    """

    _comea_src = os.getenv("COMEA_SOURCE_DIR")
    _comea_root = os.getenv("COMEA_ROOT_DIR")

    # The name of the password file that will be sent to COMEA in the password-file parameter
    password_file = _comea_root + "/test_files/.ldap.secret.tmp"

    print("COMEA source directory=" + "%s" % _comea_src)
    print("COMEA root directory=" + "%s" % _comea_root)

    """Setup 
	Copy test files to the test directory
    """
    def setUp(self):
        # set-up test folders and copy comea source
        os.system("rm -rf %s" % self._comea_root)
        os.system("mkdir -p %s" % self._comea_root)

        copytree("%s/src/bin" % self._comea_src, "%s/bin" % self._comea_root)
        copy("%s/test/test_stub/comea/bin/ldapsearch" % self._comea_src, "%s/bin/ldapsearch" % self._comea_root)

        copytree("%s/src/scripts" % self._comea_src, "%s/scripts" % self._comea_root)

        copytree("%s/src/etc" % self._comea_src, "%s/etc" % self._comea_root) 
        os.mkdir("%s/etc/comea" % self._comea_root)

        # pam.d/*
        copytree("%s/test/testfilesldap/etc/pam.d" % self._comea_src,    "%s/etc/pam.d" % self._comea_root)

        # ldap.conf
        copy("%s/test/testfilesldap/etc/ldap.conf" % self._comea_src,    "%s/etc/ldap.conf" % self._comea_root)
	for file in glob.glob("%s/test/testfilesldap/etc/ldap.conf.testdata*" % self._comea_src):
	        copy(file,"%s/etc/" % self._comea_root)

        # nsswitch.conf
        copy("%s/test/testfilesldap/etc/nsswitch.conf" % self._comea_src,"%s/etc/nsswitch.conf" % self._comea_root)
        copy("%s/test/testfilesldap/etc/nsswitch.conf.testdata1" % self._comea_src,"%s/etc/nsswitch.conf.testdata1" % self._comea_root)
	copy("%s/test/testfilesldap/etc/nsswitch.conf.testdata2" % self._comea_src,"%s/etc/nsswitch.conf.testdata2" % self._comea_root)
        copy("%s/test/testfilesldap/etc/nsswitch.conf.testdata3" % self._comea_src,"%s/etc/nsswitch.conf.testdata3" % self._comea_root)

        # group
        copy("%s/test/testfilesldap/etc/group" % self._comea_src,"%s/etc/group" % self._comea_root)
        copy("%s/test/testfilesldap/etc/group.testdata1" % self._comea_src,"%s/etc/group.testdata1" % self._comea_root)

        # syncd.conf
        copy("%s/test/testfilesldap/etc/syncd.conf" % self._comea_src, "%s/etc/syncd.conf" % self._comea_root)
        copy("%s/test/testfilesldap/etc/syncd.conf.testdata2" % self._comea_src,"%s/etc/syncd.conf.testdata2" % self._comea_root)
        
        os.mkdir("%s/test_log" % self._comea_root) 
        os.mkdir("%s/test_files" % self._comea_root) 

        # Create old fake empty LOTC script
        os.mkdir("%s/usr" % self._comea_root) 
        os.mkdir("%s/usr/lib" % self._comea_root) 
        os.mkdir("%s/usr/bin" % self._comea_root)
        os.mkdir("%s/usr/lib/cmwea" % self._comea_root)
        os.system("echo \"echo \"UNITTEST: Old LOTC script run\"\" > %s/usr/bin/cmwea.tmp" % self._comea_root)
        os.system("chmod 755 %s/usr/bin/cmwea.tmp" % self._comea_root)
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root , "%s/usr/bin/cmwea" % self._comea_root)
        os.system("echo \"echo \"UNITTEST: Old LOTC script run\"\" > %s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)
        os.system("chmod 755 %s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)
       
        # Set variables ETC_DIR, CLUSTER_ETC_DIR and HOME to approriate values for unit testing.
        comea_root_sed_proof=self._comea_root.replace("/", "\\/");
        os.system("sed -i \'s/ETC_DIR=\".*\"/ETC_DIR=\"%s\/etc\"" % comea_root_sed_proof + "/g\'" + " %s/scripts/comea-authentication-method-set" % self._comea_root)
        os.system("sed -i \'s/CLUSTER_ETC_DIR=\".*\"/CLUSTER_ETC_DIR=\"%s\/etc\"" % comea_root_sed_proof + "/g\'" + " %s/scripts/comea-authentication-method-set" % self._comea_root)
        os.system("sed -i \'s/HOME_DIR=\".*\"/HOME_DIR=\"%s\/etc\"" % comea_root_sed_proof + "/g\'" + " %s/scripts/comea-authentication-method-set" % self._comea_root)

        # Substitute stop_syncd, start_syncd and restart_nscd function calls with stdout printing.
        # This is needed since these functions must be run as root.
        os.system("sed -e 's/[ \t]*start_syncd$/echo \"UNITTEST: service syncd start\"/'" + " -i" + " %s/scripts/comea-authentication-method-set" % self._comea_root );
        os.system("sed -e 's/[ \t]*stop_syncd$/echo \"UNITTEST: service syncd stop\"/'" + " -i" + " %s/scripts/comea-authentication-method-set" % self._comea_root );
        os.system("sed -e 's/[ \t]*restart_nscd$/echo \"UNITTEST: service nscd restart\"/'" + " -i" + " %s/scripts/comea-authentication-method-set" % self._comea_root );

        os.system("sed -e 's/[ \t]*chgrp.*/echo \"UNITTEST: ldap conf group changed\"/'" + " -i" + " %s/scripts/comea-authentication-method-set" % self._comea_root );

         # Enable syslog
        os.system("sed -i \'s/DO_SYSLOG=0/DO_SYSLOG=1/g\'" + " %s/scripts/comea-authentication-method-set" % self._comea_root)
        
        copy("%s/test/test_stub/comea/usr/lib/cmwea/authentication-method-set" % self._comea_src, "%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)

        #################################################################
        # Substitute placeholders in syncd.conf with actual values.
        comea_sed_root=self._comea_root.replace("/", "\/")

        ldap_conf=comea_sed_root + "\/etc\/ldap.conf"
        nsswitch_conf=comea_sed_root + "\/etc\/nsswitch.conf"
        sshd_conf=comea_sed_root + "\/etc\/pam.d\/sshd"
        systemd_user_conf=comea_sed_root + "\/etc\/pam.d\/systemd-user"
        ldap_secret_conf=comea_sed_root + "\/etc\/ldap.secret"
        
        os.system("sed -e \'s/" + "LDAP_LOCAL_PATH" + "/" + ldap_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);
        os.system("sed -e \'s/" + "LDAP_REMOTE_PATH" + "/" + ldap_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);
        os.system("sed -e \'s/" + "NSSWITCH_LOCAL_PATH" + "/" + nsswitch_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);
        os.system("sed -e \'s/" + "NSSWITCH_REMOTE_PATH" + "/" + nsswitch_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);
        os.system("sed -e \'s/" + "SSHD_LOCAL_PATH" + "/" + sshd_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);
        os.system("sed -e \'s/" + "SSHD_REMOTE_PATH" + "/" + sshd_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);
        os.system("sed -e \'s/" + "SYSTEMD_USER_LOCAL_PATH" + "/" + systemd_user_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);
        os.system("sed -e \'s/" + "SYSTEMD_USER_REMOTE_PATH" + "/" + systemd_user_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);
        os.system("sed -e \'s/" + "LDAP_SECRET_LOCAL_PATH" + "/" + ldap_secret_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);
        os.system("sed -e \'s/" + "LDAP_SECRET_REMOTE_PATH" + "/" + ldap_secret_conf + "/g\' -i " + "%s/etc/syncd.conf.testdata2" % comea_sed_root);

#
# LEGACY TESTS. TESTS THAT DEPENDS ON LOTC SCRIPT BEING AVAILABLE.
# All legacy tests will check if stubbed LOTC script is being called.
#
    def old_test_default(self):
        """
        Test the default configuration is set and authentication-method-set is called.
        """
        os.rename("%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set" % self._comea_root)
        os.system("echo \"echo \"authentication-method-set   authenticate using LOTC script\"\" > %s/usr/bin/cmwea" % self._comea_root)

        cmd = "comea authentication default"
        expect = "default\n"
        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"Old LOTC-script found. Using it.\n") 
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_commit.log" % self._comea_root))
        
        f = open("%s/test_log/authentication-method-set_commit.log" % self._comea_root, "r")
        self.assertEqual(f.read(), expect) 
        f.close()
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root, "%s/usr/bin/cmwea" % self._comea_root)
        os.rename("%s/usr/lib/cmwea/authentication-method-set" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)


    def test_oldLOTC_versionfile_and_No_LOTCscript(self):
	"""
	Test when OLD old LOTC is installed and OLD LOTC Script is not present.
        """
        os.system("echo \"echo \"authentication-method-set   authenticate using LOTC script\"\" > %s/usr/bin/cmwea" % self._comea_root)
        cmd = "comea authentication default"
        expect = "Failed to find old LOTC script. Exiting. Used args : default \n"
        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 1) 
        self.assertFalse(pipe.stderr.read())
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_fail.log" % self._comea_root))
        
        f = open("%s/test_log/authentication-method-set_fail.log" % self._comea_root, "r")
        self.assertEqual(f.read(), expect) 
        f.close()
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root, "%s/usr/bin/cmwea" % self._comea_root)


    def old_test_commit_no_nodetype(self):
        """
        Test configuration variables are being forwarded to LOTC script and produced correctly, with no node type
        """
        os.rename("%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set" % self._comea_root)
        os.system("echo \"echo \"authentication-method-set   authenticate using LOTC script\"\" > %s/usr/bin/cmwea" % self._comea_root)

        self.create_password_file("pass")

        cmd = "comea authentication ldap \
        --bind-dn=dc=example,dc=com \
        --password-file=%s \
        --uri=ldaps://10.64.72.170 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem" % self.password_file

        expect = "ldap --bind-dn=dc=example,dc=com --password-file=%s --uri=ldaps://10.64.72.170 --base-dn=dc=example,dc=com --login-attribute=uid --tls-ca-certificate=/etc/ssl/certs/cacert.pem --tls-client-certificate=/home/ldap-user/certs/client.cert.pem --tls-client-key=/home/ldap-user/certs/keys/client.key.pem\n" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"Old LOTC-script found. Using it.\n")
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_commit.log" % self._comea_root))
        
        f = open("%s/test_log/authentication-method-set_commit.log" % self._comea_root, "r")
        self.assertEqual(f.read(), expect) 
        f.close()
        os.rename("%s/usr/lib/cmwea/authentication-method-set" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root, "%s/usr/bin/cmwea" % self._comea_root)


    def old_test_commit_one_nodetype(self):
        """
        Test configuration variables are being forwarded to LOTC script and produced correctly, with one node type
        """
        os.rename("%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set" % self._comea_root)
        os.system("echo \"echo \"authentication-method-set   authenticate using LOTC script\"\" > %s/usr/bin/cmwea" % self._comea_root)

        cmd = "comea authentication ldap \
        --uri=ldaps://10.64.72.170 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista"

        expect = "ldap --uri=ldaps://10.64.72.170 --base-dn=dc=example,dc=com --login-attribute=uid --tls-ca-certificate=/etc/ssl/certs/cacert.pem --tls-client-certificate=/home/ldap-user/certs/client.cert.pem --tls-client-key=/home/ldap-user/certs/keys/client.key.pem --pam-filter=&(objectClass=posixAccount)(ericssonUserAuthenticationScope=bsc.kista)\n"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"Old LOTC-script found. Using it.\n") 
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_commit.log" % self._comea_root))
        
        f = open("%s/test_log/authentication-method-set_commit.log" % self._comea_root, "r")

        self.assertEqual(f.read(), expect) 
        f.close()
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root, "%s/usr/bin/cmwea" % self._comea_root)
        os.rename("%s/usr/lib/cmwea/authentication-method-set" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)

        
    def old_test_commit_several_nodetypes(self):
        """
        Test configuration variables are being forwarded to LOTC script and produced correctly, with several node types
        """
        os.rename("%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set" % self._comea_root)
        os.system("echo \"echo \"authentication-method-set   authenticate using LOTC script\"\" > %s/usr/bin/cmwea" % self._comea_root)
        
	cmd = "comea authentication ldap \
        --uri=ldaps://10.64.72.170 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista:bsc.alvsjo"

        expect = "ldap --uri=ldaps://10.64.72.170 --base-dn=dc=example,dc=com --login-attribute=uid --tls-ca-certificate=/etc/ssl/certs/cacert.pem --tls-client-certificate=/home/ldap-user/certs/client.cert.pem --tls-client-key=/home/ldap-user/certs/keys/client.key.pem --pam-filter=&(objectClass=posixAccount)(|(ericssonUserAuthenticationScope=bsc.kista)(ericssonUserAuthenticationScope=bsc.alvsjo))\n"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"Old LOTC-script found. Using it.\n") 
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_commit.log" % self._comea_root))
        
        f = open("%s/test_log/authentication-method-set_commit.log" % self._comea_root, "r")
        self.assertEqual(f.read(), expect) 
        f.close()
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root, "%s/usr/bin/cmwea" % self._comea_root)
        os.rename("%s/usr/lib/cmwea/authentication-method-set" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)


    def old_test_prepare(self):
        """
        Test prepare option with extra arguments. Verify authentication-method-set is not executed.
        """
        os.rename("%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set" % self._comea_root)
        os.system("echo \"echo \"authentication-method-set   authenticate using LOTC script\"\" > %s/usr/bin/cmwea" % self._comea_root)
        
        cmd = "comea authentication ldap \
        --prepare \
        --uri=ldaps://10.64.72.170 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"Old LOTC-script found. Using it.\n")
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_commit.log" % self._comea_root))
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root, "%s/usr/bin/cmwea" % self._comea_root)
        os.rename("%s/usr/lib/cmwea/authentication-method-set" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)
        
        
    def old_test_prepare_no_other_args(self):
        """
        Test prepare option with no extra arguments. Verify authentication-method-set is not executed.
        """        
        os.rename("%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set" % self._comea_root)
        os.system("echo \"echo \"authentication-method-set   authenticate using LOTC script\"\" > %s/usr/bin/cmwea" % self._comea_root)

        cmd = "comea authentication ldap --prepare"
        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"Old LOTC-script found. Using it.\n") 
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_commit.log" % self._comea_root))
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root, "%s/usr/bin/cmwea" % self._comea_root)
        os.rename("%s/usr/lib/cmwea/authentication-method-set" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)
        


    #def old_test_prepare_no_other_args_fail(self):
        """
        Test that the command authentication-method-set is not executed if it does not exist and that comea-authentication-set exit 1.
        Not a use case that is valid in new script... it is allowed to not have the old script.
        """

#
# END OF LEGACY TESTS. TESTS THAT DEPENDS ON LOTC SCRIPT BEING AVAILABLE.
#

#
# NEW TESTS THAT TESTS THE COMBINED TEST SCRIPT 
#
    def test_default(self):
        """
        Test the default configuration is set in the config file.
        """        
        cmd = "comea authentication default"
        expect = "AUTH_TYPE=default\n"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service nscd restart\n") 

        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))

        self.check_equal("%s/etc/syncd.conf" % self._comea_root, "%s/test/testfilesldap/etc/syncd.conf" % self._comea_src)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/test/testfilesldap/etc/ldap.conf" % self._comea_src)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/test/testfilesldap/etc/nsswitch.conf" % self._comea_src)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/test/testfilesldap/etc/pam.d/sshd" % self._comea_src)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/test/testfilesldap/etc/pam.d/com-tlsd" % self._comea_src)


    def test_default_without_tlsd(self):
        """
        Test the default configuration is set in the config file.
        """
        cmd = "comea authentication default"
        expect = "AUTH_TYPE=default\n"

	os.system("rm -rf %s/etc/pam.d/com-tlsd*" % self._comea_root)

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service nscd restart\n")

        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))

        self.check_equal("%s/etc/syncd.conf" % self._comea_root, "%s/test/testfilesldap/etc/syncd.conf" % self._comea_src)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/test/testfilesldap/etc/ldap.conf" % self._comea_src)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/test/testfilesldap/etc/nsswitch.conf" % self._comea_src)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/test/testfilesldap/etc/pam.d/sshd" % self._comea_src)
        self.assertFalse(os.path.isfile("%s/etc/pam.d/com-tlsd" % self._comea_root))


    def test_no_tls_or_nodetype(self):
        """
        Test all valid options are going through to result config file
        """

        cmd = "comea authentication ldap \
        --uri=ldap://10.0.0.3 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")

        print pipe.stderr.read()
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_not_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata15" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata5" % self._comea_root)
        self.check_not_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata3" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_not_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata2" % self._comea_root)
        self.check_not_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata2" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)


    def test_no_tls_prepare(self):
        """
        Test prepare option with extra arguments, using no TLS. Verify result config file is not generated.
        """
        cmd = "comea authentication ldap \
        --prepare \
        --uri=ldap://10.0.0.3 \
        --uri=ldap://10.0.0.4 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid"
        
        expect = "ldap --prepare --uri=ldap://10.0.0.3 --uri=ldap://10.0.0.4 --base-dn=dc=example,dc=com --login-attribute=uid\n"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(pipe.stdout.read()) 
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        f = open("%s/test_log/authentication-method-set_prepare.log" % self._comea_root, "r")
        self.assertEqual(f.read(), expect) 
        self.assertEqual(pipe.wait(), 0) 
        f.close()


    def test_no_tls_use_old_lotc_script(self):
        """
        Test that the old LOTC script is called if it is there. This is for legacy reasons. If LOTC is not there it should use the new combined script, using TLS.
        """
        cmd = "comea authentication ldap \
        --uri=ldap://10.0.0.3 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid"

        expect = "Old LOTC-script found. Using it.\n"

        os.rename("%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set" % self._comea_root)
        os.system("echo \"echo \"authentication-method-set   authenticate using LOTC script\"\" > %s/usr/bin/cmwea" % self._comea_root)
        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(), expect) 
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root, "%s/usr/bin/cmwea" % self._comea_root)
        os.rename("%s/usr/lib/cmwea/authentication-method-set" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)


    def test_no_tls_with_binddn(self):
        """
        Test all valid options are going through to result config file
        """

        cmd = "comea authentication ldap \
        --uri=ldap://10.0.0.3 \
        --uri=ldap://10.0.0.4 \
        --base-dn=dc=example,dc=com \
        --bind-dn=cn=admin,dc=example,dc=com \
        --login-attribute=uid \
        --nodeType=bsc.kista:bsc.alvsjo"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata7" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)


    def test_no_tls_with_binddn_and_bindpw(self):
        """
        Test all valid options are going through to result config file
        """
        self.create_password_file("secret")

        cmd = "comea authentication ldap \
        --uri=ldap://10.0.0.3 \
        --base-dn=dc=example,dc=com \
        --bind-dn=cn=admin,dc=example,dc=com \
        --password-file=%s \
        --login-attribute=uid \
        --nodeType=bsc.kista:bsc.alvsjo" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata8" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)


    def test_obsolete_option_bind_password(self):
	"""
	Test that it is not possible to use obsolete option --bind-password.
        """
        cmd = "comea authentication ldap \
        --uri=ldap://10.0.0.3 \
        --base-dn=dc=example,dc=com \
        --bind-dn=cn=admin,dc=example,dc=com \
        --bind-password=\"secret\" \
        --login-attribute=uid \
        --nodeType=bsc.kista:bsc.alvsjo"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # check return code and outputs
        self.assertEqual(pipe.wait(), 1) 
        self.assertEqual(pipe.stderr.read(), "ER Option --bind-password is obsolete.\n")
        self.assertFalse(pipe.stdout.read())


    def test_no_tls_without_binddn_and_bindpw(self):
        """
        Test all valid options are going through to result config file
        """
        cmd = "comea authentication ldap \
        --uri=ldap://10.0.0.3 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --nodeType=bsc.kista:bsc.alvsjo"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata6" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

        
    def test_prepare_no_other_args(self):
        """
        Test prepare option with extra arguments. Verify result config file is not generated.
        """
        cmd = "comea authentication ldap --prepare"
        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(pipe.stdout.read()) 
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))       

    def test_prepare_wildcard_nodetype(self):
        """
        Test prepare option with wildcard in nodeType-argument. Verify result config file is not generated.
        """
        cmd = "comea authentication ldap --nodeType=\\\* --prepare"
        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(pipe.stdout.read()) 
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))  
	f = open("%s/test_log/authentication-method-set_prepare.log" % self._comea_root, "r")
        self.assertEqual(f.read(), "ldap --nodeType=\* --prepare\n") 
	f.close()

    def test_syncd_default_twice(self):
        """
        Verify the syncd.conf default configuration being identical if 'default' is executed twice.
        """        
        cmd = "comea authentication default"
        expect = "AUTH_TYPE=default\n"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service nscd restart\n")
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal("%s/etc/syncd.conf" % self._comea_root, "%s/test/testfilesldap/etc/syncd.conf" % self._comea_src)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/test/testfilesldap/etc/ldap.conf" % self._comea_src)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/test/testfilesldap/etc/nsswitch.conf" % self._comea_src)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/test/testfilesldap/etc/pam.d/sshd" % self._comea_src)

        # Execute same command again.
        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service nscd restart\n")        
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal("%s/etc/syncd.conf" % self._comea_root, "%s/test/testfilesldap/etc/syncd.conf" % self._comea_src)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/test/testfilesldap/etc/ldap.conf" % self._comea_src)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/test/testfilesldap/etc/nsswitch.conf" % self._comea_src)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/test/testfilesldap/etc/pam.d/sshd" % self._comea_src) 


    def test_tls_all_options_set(self):
        """
        Test all valid options are going through to result config file, using TLS.
        """
        self.create_password_file("secret")

        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --tls-mode=STARTTLS \
        --base-dn=dc=example,dc=com \
        --bind-dn=cn=admin,dc=example,dc=com \
        --password-file=%s \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista:bsc.alvsjo \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

    def test_tls_no_tls_mode_option(self):
        """
        Test that start_tls (default) is generated if tls-mode is omitted.
        """
        self.create_password_file("secret")

        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --base-dn=dc=example,dc=com \
        --bind-dn=cn=admin,dc=example,dc=com \
        --password-file=%s \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista:bsc.alvsjo \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

    def test_tls_tls_mode_ldaps(self):
        """
        Test that tls-mode LDAPS is generated.
        """
        self.create_password_file("secret")

        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --tls-mode=LDAPS \
        --base-dn=dc=example,dc=com \
        --bind-dn=cn=admin,dc=example,dc=com \
        --password-file=%s \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista:bsc.alvsjo \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata12" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

    def test_tls_no_usetls_tls_mode_ldaps(self):
        """
        Test that useTls is required if tls-mode is included.
        """

	cmd = "comea authentication ldap  \
	--uri=ldap://127.0.0.1:26003 \
	--tls-mode=LDAPS \
	--base-dn=dc=example,dc=com \
	--login-attribute=uid \
       --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 1) 
	self.assertFalse(pipe.stdout.read())
	self.assertEqual(pipe.stderr.read(),"ER authentication-method-set failed, inconsistent argument list, --tls-mode but not --useTls\n")

    def test_tls_commit_no_nodetype(self):
        """
        Test configuration variables are being set in the result config file, using TLS. The config file will later be handled by LOTC syncd.
        """
        self.create_password_file("pass")

        cmd = "comea authentication ldap \
        --bind-dn=dc=example,dc=com \
        --password-file=%s \
        --uri=ldap://10.64.72.170 \
        --uri=ldap://10.64.72.171 \
        --useTls \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.assertEqual(pipe.wait(), 0) 
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata3" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)	
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)


    def test_tls_commit_one_nodetype(self):
        """
        Test configuration variables, with one node type, are being set in the result config file, using TLS.
        """
        
        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root)) 
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata4" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

    def test_tls_commit_wildcard_nodetype(self):
        """
        Test configuration variables, with wildcard node type, are being set in the result config file, using TLS.
        """
        
        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=\\\* \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
	self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
 
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root)) 
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata14" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

    def test_tls_commit_several_nodetypes(self):
        """
        Test configuration variables, with several node types, are being set in the result config file, using TLS.
        """       
        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista:bsc.alvsjo \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read()) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)


    def test_tls_prepare(self):
        """
        Test prepare option with extra arguments, using TLS. Verify result config file is not generated.
        """
        cmd = "comea authentication ldap \
        --prepare \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem"
        
        expect = "ldap --prepare --uri=ldap://10.64.72.170 --useTls --base-dn=dc=example,dc=com --login-attribute=uid --tls-ca-certificate=/etc/ssl/certs/cacert.pem --tls-client-certificate=/home/ldap-user/certs/client.cert.pem --tls-client-key=/home/ldap-user/certs/keys/client.key.pem\n"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(pipe.stdout.read()) 
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        f = open("%s/test_log/authentication-method-set_prepare.log" % self._comea_root, "r")
        self.assertEqual(f.read(), expect) 
        f.close()


    def test_tls_syncd_no_nodetype_twice(self):
        """
        Verify syncd.conf being identical the first time as well as the second time the same command is executed, using TLS.
        """
        self.create_password_file("pass")

        cmd = "comea authentication ldap \
        --bind-dn=dc=example,dc=com \
        --password-file=%s \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.assertEqual(pipe.wait(), 0) 
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata9" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)	
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

        # Test same command once again.
        self.create_password_file("pass")

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
	self.assertEqual(pipe.wait(), 0) 
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata9" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)
        

    def test_tls_use_old_lotc_script(self):
        """
        Test that the old LOTC script is called if it is there. This is for legacy reasons. If LOTC is not there it should use the new combined script, using TLS.
        """
        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem"
        expect = "Old LOTC-script found. Using it.\n"

        os.rename("%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set" % self._comea_root)
        os.system("echo \"echo \"authentication-method-set   authenticate using LOTC script\"\" > %s/usr/bin/cmwea" % self._comea_root)
        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertFalse(pipe.stderr.read())
        self.assertEqual(pipe.stdout.read(), expect) 
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        
        copy("%s/usr/bin/cmwea.tmp" % self._comea_root, "%s/usr/bin/cmwea" % self._comea_root)
        os.rename("%s/usr/lib/cmwea/authentication-method-set" % self._comea_root, "%s/usr/lib/cmwea/authentication-method-set.tmp" % self._comea_root)



    def test_override_ldap_gid(self):
        """
        Test that the nss_override_attribute_value directive is added to ldap.conf, if the group 'com-ldap' is defined.
        """
        os.rename("%s/etc/group" % self._comea_root, "%s/etc/group.tmp" % self._comea_root)
        os.rename("%s/etc/group.testdata1" % self._comea_root, "%s/etc/group" % self._comea_root)

        cmd = "comea authentication ldap \
        --uri=ldap://10.0.0.3 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid" 

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
 
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/test/testfilesldap/etc/ldap.conf.testdata10" % self._comea_src)
	self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata2" % self._comea_root)

        os.rename("%s/etc/group.tmp" % self._comea_root, "%s/etc/group" % self._comea_root)

    def test_override_ldap_home_dir(self):
        """
        Test that the nss_override_attribute_value directive is added to ldap.conf, if /home/nohome is created.
        """
	os.system("mkdir -p %s/home/nohome" % self._comea_root)

        cmd = "comea authentication ldap \
        --uri=ldap://10.0.0.3 \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid" 

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0) 
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
 
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/test/testfilesldap/etc/ldap.conf.testdata11" % self._comea_src)

	os.system("rmdir %s/home/nohome" % self._comea_root)

    def test_tls_ca_cert_dir_set(self):
        """
        Test set tls-ca-cer-directory along with all valid options are going through to result config file, using TLS.
        """
        self.create_password_file("secret")

        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --tls-mode=STARTTLS \
        --base-dn=dc=example,dc=com \
        --bind-dn=cn=admin,dc=example,dc=com \
        --password-file=%s \
        --login-attribute=uid \
        --tls-ca-cert-directory=/etc/ssl/certs \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista:bsc.alvsjo \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
	self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata13" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

    def test_tls_prepare_with_tls_ca_cert_directory(self):
        """
        Test prepare option with tls-ca-cert-directory with extra arguments, using TLS. Verify result config file is not generated.
        """
        cmd = "comea authentication ldap \
        --prepare \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --base-dn=dc=example,dc=com \
        --login-attribute=uid \
        --tls-ca-cert-directory=/etc/ssl/certs \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem"

        expect = "ldap --prepare --uri=ldap://10.64.72.170 --useTls --base-dn=dc=example,dc=com --login-attribute=uid --tls-ca-cert-directory=/etc/ssl/certs --tls-client-certificate=/home/ldap-user/certs/client.cert.pem --tls-client-key=/home/ldap-user/certs/keys/client.key.pem\n"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(pipe.stdout.read())
        self.assertTrue(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        f = open("%s/test_log/authentication-method-set_prepare.log" % self._comea_root, "r")
        self.assertEqual(f.read(), expect)
        f.close()

    def test_empty_baseDn(self):
        """
        Test that the baseDn attribute is given as empty string.
        """
        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --base-dn=\"\" \
        --login-attribute=uid"

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),
                                shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))

    def test_tls_with_referrals_on_off(self):
        """
        Slogan:
        MR36308 - Test the --useReferrals options on/off.

        Tests:
        Run1     : --useReferrals is not passed to comea
        Expected : ldap.conf has referral no
        Run2     : --useReferrals is passed to comea
        Expected : ldap.conf has referral yes
        """

        #Run 1
        self.create_password_file("secret")
        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --tls-mode=STARTTLS \
        --base-dn=dc=example,dc=com \
        --bind-dn=cn=admin,dc=example,dc=com \
        --password-file=%s \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista:bsc.alvsjo \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd), shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        self.check_equal("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

        #Run 2
        self.create_password_file("secret")
        cmd = "comea authentication ldap \
        --uri=ldap://10.64.72.170 \
        --useTls \
        --tls-mode=STARTTLS \
        --base-dn=dc=example,dc=com \
        --bind-dn=cn=admin,dc=example,dc=com \
        --password-file=%s \
        --login-attribute=uid \
        --tls-ca-certificate=/etc/ssl/certs/cacert.pem \
        --tls-client-certificate=/home/ldap-user/certs/client.cert.pem \
        --tls-client-key=/home/ldap-user/certs/keys/client.key.pem \
        --nodeType=bsc.kista:bsc.alvsjo \
        --useReferrals \
        --cipherFilter=ALL:!aNULL:!eNULL:!DES:@STRENGTH" % self.password_file

        pipe = subprocess.Popen("%s/bin/%s" % (self._comea_root, cmd),shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.assertEqual(pipe.wait(), 0)
        self.assertEqual(pipe.stdout.read(),"UNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: service syncd stop\nUNITTEST: service syncd start\nUNITTEST: ldap conf group changed\nUNITTEST: service nscd restart\n")
        self.assertFalse(pipe.stderr.read())
        self.assertFalse(os.path.isfile("%s/test_log/authentication-method-set_prepare.log" % self._comea_root))
        self.check_equal_extra_cr("%s/etc/syncd.conf" % self._comea_root, "%s/etc/syncd.conf.testdata2" % self._comea_root)
        exception_list = ['- # Enable automatic referrals','+ # Disable automatic referrals','- referrals yes','+ referrals no']
        self.check_equal_except("%s/etc/ldap.conf" % self._comea_root, "%s/etc/ldap.conf.testdata1" % self._comea_root, exception_list)
        self.check_equal("%s/etc/nsswitch.conf" % self._comea_root, "%s/etc/nsswitch.conf.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/sshd" % self._comea_root, "%s/etc/pam.d/sshd.testdata1" % self._comea_root)
        self.check_equal("%s/etc/pam.d/com-tlsd" % self._comea_root, "%s/etc/pam.d/com-tlsd.testdata1" % self._comea_root)

#######################################################################
## Functions below are used for file verification and are not testcases

    def check_equal(self, file1, file2):
        #filepath = file2.split('/')[-2]
        #filename = file2.split('/')[-1]
        #copy(file1, "/tmp/%s/comea%s%s" % (os.environ['USER'], filepath ,  filename))
        f1 = open(file1, "r")
        f2 = open(file2, "r")
        self.assertEqual(f1.read(), f2.read())
        f1.close()
        f2.close()

    def check_not_equal(self, file1, file2):
        f1 = open(file1, "r")
        f2 = open(file2, "r")
        self.assertNotEqual(f1.read(), f2.read())
	f1.close()
        f2.close()

    def check_equal_extra_cr(self, file1, file2):
        f1 = open(file1, "r")
        f2 = open(file2, "r")
        self.assertEqual(f1.read() + "\n", f2.read())
        f1.close()
        f2.close()

    # Create the .ldap.secret.tmp file (normally created by COM)   
    def create_password_file(self, password):
        os.system("echo \"%s\" > %s" % (password, self.password_file))
        os.system("chmod 600 %s" % self.password_file)

    def check_equal_except(self, file1, file2, exceptions):
        """
        Method which checks if two file contents are equal with the exceptions list.
        param1 : self object
        param2 : path to file1
        param3 : path to file2
        param4 : list of exception strings
        """
        delta = Differ().compare(open(file1).readlines(),open(file2).readlines())
        l = list(line.rstrip() for line in delta if line.startswith('+') or line.startswith('-'))
        self.assertEqual(0,cmp(l,exceptions))

#    def tearDown(self):
#        print "tearDown\n"
