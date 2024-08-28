
find_package(PythonInterp)

add_custom_target(comea_lotc_unittest
        export CMAKE_BINARY_DIR=${CMAKE_BINARY_DIR} &&
        export COMEA_SOURCE_DIR=${COM_SOURCE_DIR}/comea/sles12 &&
        export SNMPD_CONF=${CMAKE_BINARY_DIR}/gen/comea/etc/snmpd.conf &&
        export SSHD_CONFIG=${CMAKE_BINARY_DIR}/gen/comea/etc/sshd_config_oam &&
        export COMEA_ROOT_DIR=${CMAKE_BINARY_DIR}/gen/comea &&
        export SSH_SSH_AUTHORIZEDKEYSFILE=${CMAKE_BINARY_DIR}/tmp/sss_ssh_authorizedkeys &&
        export SSH_LEGALNOTICEFILE=${CMAKE_BINARY_DIR}/tmp/legal-notice &&
        export SSH_LEGAL_PRIVACYNOTICEFILE=${CMAKE_BINARY_DIR}/tmp/legal-privacy-notice &&
        export SSH_LEGAL_PRIVACYNOTICE_SYMLINK=${CMAKE_BINARY_DIR}/tmp/legal-privacy-notice-symlink &&
        export COMEA_MSG_OUT="false" &&
        ${COMEA_SLES12_DIR}/test/comea_suite.py
	)

if (UT)

    # Variable definition
    set(COMEA_TEST_TMP_INSTALLDIR ${COM_INSTALL_PREFIX})

    install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        DESTINATION ${COMEA_TEST_TMP_INSTALLDIR}/comea
        USE_SOURCE_PERMISSIONS
        COMPONENT comea_test
        )

endif()
