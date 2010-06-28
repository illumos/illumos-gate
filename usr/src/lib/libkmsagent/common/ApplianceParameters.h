/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*-----------------------------------------------------------------------------
* File: ApplianceParameters.h
-----------------------------------------------------------------------------*/

#ifndef ApplianceParameters_h
#define ApplianceParameters_h

// Server Config

#define DEFAULT_SERVER_LOG_FILENAME                                 "KeyMgrLog.log"
#define DEFAULT_SERVER_CONFIG_FILENAME                              "ServerConfig.cfg"
#define DEFAULT_CONNECTION_QUEUE_SIZE                               100
#define DEFAULT_THREAD_POOL_SIZE                                    8
#define DEFAULT_THREAD_POOL_MIN_IDLE_THREADS                        8
#define DEFAULT_THREAD_POOL_MAX_IDLE_THREADS                        8
#define DEFAULT_THREAD_POOL_MAINTENANCE_FREQUENCY_IN_SECONDS        0
#define DEFAULT_THREAD_POOL_SHRINK_BY                               0
#define DEFAULT_THREAD_POOL_SPAWN_BY                                0
#define DEFAULT_THREAD_POOL_ORIGINAL_SIZE                           8
#define DEFAULT_SOCKET_TIMEOUT_IN_SECONDS                           60
// former default for SSL_Accept timeout was 10s - increased to 20s to support HP LTO-4
#define DEFAULT_SSL_ACCEPT_TIMEOUT_IN_SECONDS                       20
#define DEFAULT_SOCKET_CONNECTION_BACKLOG                           100
#define DEFAULT_MANAGEMENT_SERVICE_MAX_CONNECTIONS                  10
#define DEFAULT_CA_SERVICE_PORT_NUMBER                              3331
#define DEFAULT_CERTIFICATE_SERVICE_PORT_NUMBER                     3332
#define DEFAULT_MANAGEMENT_SERVICE_PORT_NUMBER                      3333
#define DEFAULT_AGENT_SERVICE_PORT_NUMBER                           3334
#define DEFAULT_DISCOVERY_SERVICE_PORT_NUMBER                       3335
#define DEFAULT_REPLICATION_SERVICE_PORT_NUMBER                     3336
#define EXTENDED_SSL_SESSION_CACHE_TIMEOUT                          86400
#define DEFAULT_DATABASE_MAINTENANCE_FREQUENCY_IN_SECONDS           86400
#define DEFAULT_TRIGGER_DATABASE_MAINTENANCE_TIMEOUT_IN_SECONDS     30
#define DEFAULT_AUDIT_LOG_MAINTENANCE_FREQUENCY_IN_SECONDS          3600
// see CR 6689920
#define DEFAULT_KEY_POOL_MAINTENANCE_FREQUENCY_IN_SECONDS           15
#define KEY_POOL_MINIMUM_SIZE                                       1000
#define KEY_POOL_MAXIMUM_SIZE                                       200000
#define DEFAULT_KEY_GENERATION_BATCH_SIZE                           10
#define DEFAULT_REPLICATION_ANTI_ENTROPY_FREQUENCY_IN_SECONDS       60
#define DEFAULT_MAXIMUM_REPLICATION_MESSAGE_SIZE_IN_BYTES           8192
#define DEFAULT_MAXIMUM_JOIN_CLUSTER_MESSAGE_SIZE_IN_BYTES          262144
#define DEFAULT_MAXIMUM_JOIN_CLUSTER_KMA_ENTRIES                    20
#define DEFAULT_REPLICATION_THROTTLE_TIME_IN_MILLISECONDS           1000
#define DEFAULT_REPLICATION_SPREAD_TIME_IN_MILLISECONDS             3000
#define DEFAULT_REPLICATION_TIMEOUT_IN_SECONDS                      15
#define DEFAULT_RETRIEVE_ROOT_CA_CERTIFICATE_TIMEOUT_IN_SECONDS     15
#define DEFAULT_RETRIEVE_APPLIANCE_CERTIFICATE_TIMEOUT_IN_SECONDS   15
#define DEFAULT_JOIN_CLUSTER_TIMEOUT_IN_SECONDS                     15
#define DEFAULT_JOIN_CLUSTER_REPLICATED_IN_SECONDS                  10
#define DEFAULT_REQUEST_ANTI_ENTROPY_PUSH_TIMEOUT_IN_SECONDS        60
#define DEFAULT_PUSH_UPDATES_TIMEOUT_IN_SECONDS                     60
#define DEFAULT_CLUSTER_PEER_STATUS_TIMEOUT_IN_SECONDS              10
#define DEFAULT_TABLE_LOCK_TIMEOUT_IN_SECONDS                       2
#define DEFAULT_REPLICATION_TABLE_LOCK_TIMEOUT_IN_SECONDS           8
#define DEFAULT_TRANSACTION_RETRY_TIMEOUT_IN_SECONDS                4
#define DEFAULT_KEY_STORE_GROW_SIZE_IN_SLOTS                        10000
// Since write-caching is disabled on the hard disk, this is not necessary to force overwrites to disk
#define DEFAULT_KEY_STORE_OVERWRITE_BUFFER_EXTRA_SIZE               0
#define DEFAULT_KEY_STORE_OVERWRITE_PASS_COUNT                      7
#define DEFAULT_CLOCK_ADJUSTMENT_LIMIT_IN_SECONDS                   300
#define DEFAULT_DATABASE_START_TIMEOUT_IN_SECONDS                   30
#define DEFAULT_DATABASE_TRANSACTION_RETRY_COUNT                    10
#define DEFAULT_DATABASE_TRANSACTION_RETRY_SLEEP_IN_MILLISECONDS    1000
#define DEFAULT_MAX_SNMP_TRAP_QUEUE_SIZE                            10000
#define DEFAULT_SNMP_TIMEOUT_IN_SECONDS                             10
#define DEFAULT_SNMP_RETRY_LIMIT                                    1
#define DEFAULT_FILE_TRANSFER_MAXIMUM_CHUNK_SIZE_IN_KILOBYTES       1024
#define DEFAULT_CERTIFICATE_START_TIME_SHIFT_IN_SECONDS             (60*60*24)
#define DEFAULT_DISCOVERY_FREQUENCY_IN_SECONDS                      (60*10)
#define DEFAULT_AUDIT_LOG_FAIL_BACK_FREQUENCY_IN_SECONDS            (60*10)
#define DEFAULT_NTP_PEER_UPDATE_FREQUENCY_IN_SECONDS                23 
#define DEFAULT_NTP_PEER_UPDATE_QUERY_INTERVAL                      156
#define DEFAULT_SYSTEM_DUMP_LOG_LINE_COUNT                          5000
#define DEFAULT_MASTER_KEY_PROVIDER_MAINTENANCE_FREQUENCY_IN_SECONDS 3600
#define DEFAULT_SEND_PUSH_UPDATES_TO_JOIN_PEER_KMA_IN_SECONDS       3600
#define DEFAULT_PENDING_QUORUM_OPERATION_EXPIRATION_FREQUENCY_IN_SECONDS 600
#define DEFAULT_SUPPORT_ACCOUNT_MAX_PASSWORD_AGE_IN_DAYS            7
#define DEFAULT_REPLICATION_ACCELERATION_TIMEOUT_IN_SECONDS         300

#define DEFAULT_DATABASE_ADMINISTRATOR_USERNAME                     "dbadmin"
#define DEFAULT_DATABASE_ADMINISTRATOR_PASSWORD                     "npwd4kms2"
#define DEFAULT_DATABASE_NAME                                       "keymgr"
#define DEFAULT_DATABASE_PARAMS                                     ""
#define DEFAULT_DATABASE_USERNAME                                   "keymgr"
#define DEFAULT_DATABASE_PASSWORD                                   "npwd4kms2"
#define DEFAULT_KEY_STORE_FILE_NAME                                 "KeyStore.dat"
#define DEFAULT_OPENSSL_ROOT_CA_CERTIFICATE_FILE_NAME               "RootCACertificate.crt"
#define DEFAULT_OPENSSL_APPLIANCE_KEY_PAIR_FILE_NAME                "KMAKeyPair.pem"
#ifndef WIN32
#define DEFAULT_OPENSSL_AGENT_PRIVATE_KEY_DIR                       "/var/opt/SUNWkms2/data/"
#endif

#ifndef DEFAULT_SERVER_VERSION
#define DEFAULT_SERVER_VERSION                                      "2.1.04"
#endif
#define DEFAULT_SNMP_TRAP_GENERIC_TRAP_OID                          "1.3.6.1.4.1.42.2"
#define DEFAULT_SNMP_TRAP_DATE_TIME_OID                             "1.3.6.1.4.1.42.2.1"
#define DEFAULT_SNMP_TRAP_AUDIT_CLASS_OID                           "1.3.6.1.4.1.42.2.2"
#define DEFAULT_SNMP_TRAP_AUDIT_OPERATION_OID                       "1.3.6.1.4.1.42.2.3"
#define DEFAULT_SNMP_TRAP_AUDIT_CONDITION_OID                       "1.3.6.1.4.1.42.2.4"
#define DEFAULT_SNMP_TRAP_AUDIT_SEVERITY_OID                        "1.3.6.1.4.1.42.2.5"
#define DEFAULT_SNMP_TRAP_ENTITY_ID_OID                             "1.3.6.1.4.1.42.2.6"
#define DEFAULT_SNMP_TRAP_NETWORK_ADDRESS_OID                       "1.3.6.1.4.1.42.2.7"
#define DEFAULT_SNMP_TRAP_MESSAGE_OID                               "1.3.6.1.4.1.42.2.8"
#define DEFAULT_SNMP_TRAP_AUDIT_SOLUTION_OID                        "1.3.6.1.4.1.42.2.9"
#define DEFAULT_BACKUP_FILE_NAME                                    "BackupFile"
#define DEFAULT_RESTORE_FILE_NAME                                   "RestoreFile"
#define DEFAULT_CACHED_BACKUP_FILE_NAME                             "/var/opt/SUNWkms2/CachedBackupFile"
#define DEFAULT_CACHED_CORE_SECURITY_XML_FILE_NAME                  "/var/opt/SUNWkms2/CachedCoreSecurityXMLFile"
#define DEFAULT_CACHED_BACKUP_KEY_XML_FILE_NAME                     "/var/opt/SUNWkms2/CachedBackupKeyXMLFile"
#define DEFAULT_SOFTWARE_UPGRADE_FILE_NAME                          "/SUNWkms2/boxcar/SoftwareUpgradeFile"
#define DEFAULT_IMPORT_10KEYS_FILE_NAME                             "Import10KeysFile"
#define DEFAULT_KEY_SHARING_EXPORT_FILE_NAME                        "KeySharingExport.dat"
#define DEFAULT_KEY_SHARING_IMPORT_FILE_NAME                        "KeySharingImport.dat"
#define DEFAULT_JOIN_PEER_KMA_FILE_NAME                             "/var/opt/SUNWkms2/data/JoinPeerKMAFile"

#define DEFAULT_PRIMARY_NETWORK_IF                                  "bge0"
#define DEFAULT_SECONDARY_NETWORK_IF                                "aggr1"
#define DEFAULT_AGGREGATE_NETWORK                                   "nge1 nge0"
#define DEFAULT_PRIMARY_ALIAS                                       "KMA-Mgmt"
#define DEFAULT_SECONDARY_ALIAS                                     "KMA-Service"
#define DEFAULT_DATABASE_FILE_SYSTEM_PATH                           "/var/lib/pgsql"
#define DEFAULT_BUNDLE_SOFTWARE_COMMAND                             "/opt/SUNWkms2/bin/BundleSoftwareUpgrade"
#define DEFAULT_FLAR_FILE_PATH                                      "/SUNWkms2/boxcar/SoftwareUpgrade.flar"

// System Calls (Config)

#define DEFAULT_SERVER_RESTART_COMMAND                              "/usr/sbin/svcadm restart kms2 > /dev/null 2>&1"
#define DEFAULT_SET_IP_CONFIGURATION_COMMAND                        "/opt/SUNWkms2/bin/SetIPAddresses"
#define DEFAULT_RESET_TO_FACTORY_DEFAULT_COMMAND                    "/opt/SUNWkms2/bin/ResetAndZeroizeLauncher > /dev/null 2>&1"
#define DEFAULT_RESET_TO_FACTORY_AND_ZEROIZE_DEFAULT_COMMAND        "/opt/SUNWkms2/bin/ResetAndZeroizeLauncher -zeroize > /dev/null 2>&1"
#define DEFAULT_SHUTDOWN_COMMAND                                    "/usr/sbin/shutdown -y -g 5 -i 5 'KMS is shutting down the system' > /dev/null 2>&1"
#define DEFAULT_ENABLE_SUPPORT_COMMAND                              "/bin/passwd -u support > /dev/null 2>&1"
#define DEFAULT_DISABLE_SUPPORT_COMMAND                             "/bin/passwd -l support > /dev/null 2>&1"
#define DEFAULT_REGENERATE_SSH_KEYS_COMMAND                         "/opt/SUNWkms2/bin/RegenerateSSHKeys > /dev/null 2>&1"
#define DEFAULT_DISPLAY_SSH_KEYS_COMMAND                            "/opt/SUNWkms2/bin/GetSSHKeys"
#define DEFAULT_ENABLE_SSH_COMMAND                                  "/usr/sbin/svcadm enable ssh > /dev/null 2>&1"
#define DEFAULT_DISABLE_SSH_COMMAND                                 "/opt/SUNWkms2/bin/DisableSSH > /dev/null 2>&1"
#define DEFAULT_GET_SUPPORT_STATUS_COMMAND                          "/opt/SUNWkms2/bin/StateOfSupport"
#define DEFAULT_GET_SSH_STATUS_COMMAND                              "/opt/SUNWkms2/bin/StateOfSSHD"
#define DEFAULT_ENABLE_SERVER_STARTUP_COMMAND                       "/bin/true"
#define DEFAULT_SERVER_STARTUP_COMMAND                              "/usr/sbin/svcadm enable kms2 > /dev/null 2>&1"
#define DEFAULT_SOFTWARE_UPGRADE_COMMAND                            "/opt/SUNWkms2/bin/InstallSoftwareVersion"
#define DEFAULT_LIST_SOFTWARE_VERSIONS_COMMAND                      "/opt/SUNWkms2/bin/ListSoftwareVersions"
#define DEFAULT_STOP_SOFTWARE_AND_RUN_COMMAND                       "echo Stop and run not implemented" // "/usr/local/bin/StopSoftwareAndRun"
#define DEFAULT_VERIFY_SOFTWARE_COMMAND                             "/opt/SUNWkms2/bin/VerifySoftwareFile"
#define DEFAULT_VERIFY_ACTIVATE_COMMAND                             "/opt/SUNWkms2/bin/VerifyActivateSoftware"
#define DEFAULT_CHANGE_SOFTWARE_COMMAND                             "/opt/SUNWkms2/bin/ChangeSoftwareVersion"
#define DEFAULT_REBOOT_SYSTEM_COMMAND                               "/usr/sbin/shutdown -y -g 5 -i 6 'KMS is rebooting the system' > /dev/null 2>&1"
#define DEFAULT_STOP_SERVER_COMMAND                                 "/usr/sbin/svcadm disable kms2"
#define DEFAULT_INTERFACE_CONFIG_COMMAND                            "/usr/sbin/ifconfig"
#define DEFAULT_SYSTEM_DUMP_COMMAND                                 "/opt/SUNWkms2/bin/SystemDump"
#define DEFAULT_CONFIGURE_NTP_COMMAND                               "/opt/SUNWkms2/bin/ConfigureNTP"
#define DEFAULT_SET_TIMEZONE_COMMAND                                "/opt/SUNWkms2/bin/SetTimezone"
#define DEFAULT_GET_KEYBOARD_LAYOUT_COMMAND                         "/opt/SUNWkms2/bin/GetKeyboardLayout"
#define DEFAULT_SET_KEYBOARD_LAYOUT_COMMAND                         "/opt/SUNWkms2/bin/SetKeyboardLayout"
#define DEFAULT_CONFIGURE_PRIMARY_ADMIN_COMMAND                     "/opt/SUNWkms2/bin/ConfigurePrimaryAdmin"
#define DEFAULT_GET_IPV6_ADDRESS_COMMAND                            "/opt/SUNWkms2/bin/GetIPv6Address"
#define DEFAULT_INITIALIZE_SCA6000_COMMAND                          "/opt/SUNWkms2/bin/InitializeSCA6000"
#define DEFAULT_QUERY_SYSTEM_MESSAGES_COMMAND                       "/opt/SUNWkms2/bin/QuerySystemMessages"

// @see StringUtilities.cpp
#define DEFAULT_PENDING_QUORUM_OPERATION_TIMEOUT                    "P2D" // Default to 2 days (defined by ISO 8601)
#define PENDING_OPERATIONS_VERSION_STRING                           "2.2"

// PKI

#define KEY_SIZE                                                    2048
#define CRL_DAYS                                                    365
#define CRL_HOURS                                                   0
#define PKI_FORMAT                                                  FILE_FORMAT_PEM
#define DER_FORMAT                                                  FILE_FORMAT_DER
#define PKCS12_FORMAT                                               FILE_FORMAT_PKCS12
#define PKI_UNPROTECTED_PASSWORD                                    "password"
#define DN_O_ROOT_CA                                                "Oracle"
#define DN_OU_ROOT_CA                                               "KMS"
#define DN_CN_ROOT_CA                                               "RootCA"
    // NOTE: Do not directly use the following values.
    // Use the configurable Security Parameter values instead
#define DEFAULT_ROOT_CA_CERTIFICATE_LIFETIME                        "P49Y"
#define DEFAULT_CERTIFICATE_LIFETIME                                "P49Y"
#define AUTHENTICATION_SECRET_LENGTH                                20
#define AUTHENTICATION_CHALLENGE_LENGTH                             20
#define AUTHENTICATION_RESPONSE_LENGTH                              20
#define AUTHENTICATION_ITERATION_TIME_IN_MILLISECONDS               100
// reduce the time for agents since we support agents on embedded processors
#define AGENT_AUTHENTICATION_ITERATION_TIME_IN_MILLISECONDS         10
#define MIN_AUTHENTICATION_ITERATION_COUNT                          40000   // a bit less than 1/10 second on standard Appliance hardware
#define MAX_AUTHENTICATION_ITERATION_COUNT                          400000  // a bit less that 1 second on standard Appliance hardware

// Core Security

#define MAX_CORE_SECURITY_KEY_SPLIT_COUNT                           10
#define CORE_SECURITY_HMAC_LENGTH                                   64
#define MAX_CORE_SECURITY_PAD_LENGTH                                16

//------------- to be removed: Transfer Partner code is obsolete -----------
#define MAX_KEY_DISTRIBUTION_PUBLIC_KEY_COUNT                       4
#define MAX_CORE_SECURITY_PUBLIC_KEY_LENGTH                         256
//--------------------------------------------------------------------------

// SOAP Services

// TODO: make functions instead of macros?

#define SOAP_SERVER_ERROR( pstSoap )                                (soap_receiver_fault( pstSoap, "Server Error", NULL ))
// This has been replaced with SoapClientError:
//#define SOAP_CLIENT_ERROR( pstSoap, sMessage )                      (soap_sender_fault( pstSoap, sMessage, NULL ))
#define SOAP_IS_CLIENT_ERROR( pstSoap )                             (strcmp( *soap_faultcode( pstSoap ), pstSoap->version == 2 ? "SOAP-ENV:Sender" : "SOAP-ENV:Client" ) == 0)
#define GET_SOAP_FAULTCODE( pstSoap )                               ((soap_set_fault( pstSoap ),*soap_faultcode( pstSoap )) ? (*soap_faultcode( pstSoap )) : "Unknown")
#define GET_SOAP_FAULTSTRING( pstSoap )                             ((soap_set_fault( pstSoap ),*soap_faultstring( pstSoap )) ? (*soap_faultstring( pstSoap )) : "Unknown")
#define GET_SOAP_FAULTDETAIL( pstSoap )                             ((soap_set_fault( pstSoap ),*soap_faultdetail( pstSoap )) ? (*soap_faultdetail( pstSoap )) : "Unknown")
#define SOAP_AUDIT_LOG_MESSAGE( pStringTable, pstSoap )             ( CAuditMessage( CAuditLogger::AUDIT_VALUE_SOAP_FAULTCODE, GET_SOAP_FAULTCODE( pstSoap ) ) + CAuditMessage( CAuditLogger::AUDIT_VALUE_SOAP_FAULTSTRING, GET_SOAP_FAULTSTRING( pstSoap ) ) + CAuditMessage( CAuditLogger::AUDIT_VALUE_SOAP_FAULTDETAIL, GET_SOAP_FAULTDETAIL( pstSoap ) ) )
#define SOAP_HTTP_PROTOCOL                                          "http://"
#define SOAP_HTTPS_PROTOCOL                                         "https://"

// Data Entry

#define MINIMUM_WIDE_STRING_VALUE_LENGTH                            1
#define MAXIMUM_WIDE_STRING_VALUE_LENGTH                            64
#define MAXIMUM_UTF8_STRING_VALUE_LENGTH                            ( MAXIMUM_WIDE_STRING_VALUE_LENGTH * 6 )
#define MINIMUM_WIDE_TEXT_VALUE_LENGTH                              1
#define MAXIMUM_WIDE_TEXT_VALUE_LENGTH                              8192
#define MAXIMUM_UTF8_TEXT_VALUE_LENGTH                              ( MAXIMUM_WIDE_TEXT_VALUE_LENGTH * 6 )

// Business Logic

#define AUDIT_ID_BUFFER_LENGTH                                      16
#define CERTIFICATE_SERIAL_NUMBER_BUFFER_LENGTH                     16
#define BACKUP_ID_BUFFER_LENGTH                                     16
#define DATA_UNIT_ID_HEX_STRING_LENGTH                              32
#define DATA_UNIT_KEY_ID_BUFFER_LENGTH                              30
#define DATA_UNIT_KEY_ID_HEX_STRING_LENGTH                          (DATA_UNIT_KEY_ID_BUFFER_LENGTH*2)
#define MAXIMUM_QUERY_NEXT_PAGE_SIZE                                1000
#define MAXIMUM_QUERY_FILTER_PARAMS_COUNT                           100
#define MAXIMUM_LIST_DATA_UNIT_STATUS_PARAMS_COUNT                  ( MAXIMUM_QUERY_FILTER_PARAMS_COUNT )
#define MAXIMUM_LIST_AUDIT_LOGS_FOR_AGENTS_PARAMS_COUNT             ( MAXIMUM_QUERY_FILTER_PARAMS_COUNT )
#define MAXIMUM_LIST_AUDIT_LOGS_FOR_DATA_UNITS_PARAMS_COUNT         ( MAXIMUM_QUERY_FILTER_PARAMS_COUNT )
#define MAXIMUM_LIST_AUDIT_LOGS_FOR_KEYS_PARAMS_COUNT               ( MAXIMUM_QUERY_FILTER_PARAMS_COUNT )
// 0 allows unlimited # of DUs to be exported, positive int constricts the size
#define DEFAULT_KEYSHARING_MAXIMUM_EXPORT_DATA_UNITS_RESULT_SIZE    0
#define TRANSFER_PARTNER_KEY_ID_LENGTH                              32
#define TRANSFER_PARTNER_KEY_VALUE_LENGTH                           259
#define TRANSFER_PARTNER_KEY_VALUE_HEX_STRING_LENGTH                (TRANSFER_PARTNER_KEY_VALUE_LENGTH*2)
    // NOTE: Do not directly use the following value.
    // Use the configurable Security Parameter value instead
#define DEFAULT_MAX_FAILED_RETRIEVE_CERTIFICATE_ATTEMPTS            5
    // The obvious logic for determining if a key's bits are on a backup is as follows:
    // The key must have been created before the backup was created:
    //    Backup.CreatedDate >= DataUnitKey.CreatedDate
    // And the key must not have been destroyed before the backup was created:
    //    (DataUnitKey.DestroyedDate IS NULL) OR (Backup.CreatedDate <= DataUnitKey.DestroyedDate)
    // This logic would be fine in a single-appliance cluster, or if we had (or when we have) 
    // time synchronization. But right now the appliances in a cluster may have different 
    // times from each other, and that makes it dangerous to use a simple date comparison.
    // (Note that when determining if a key is on a backup, we *really* don't want false
    // negatives, but we don't mind false positives so much, within reason.)
    // To address this, the best solution we came up with is to use a "backup date window".
    // Instead of simply using the CreatedDate of a backup in our logic, we'll use:
    //    (Backup.CreatedDate + BACKUP_DATE_WINDOW_INTERVAL) >= DataUnitKey.CreatedDate
    // and
    //    (DataUnitKey.DestroyedDate IS NULL) OR ((Backup.CreatedDate - BACKUP_DATE_WINDOW_INTERVAL) <= DataUnitKey.DestroyedDate)
    // Note that the adding and subtracting of BACKUP_DATE_WINDOW_INTERVAL effectively increases
    // the chance that the calculation will show that a key's bits are on a backup. 
    // It's still possible to get false negatives, and there will be more false positives,
    // but if BACKUP_DATE_WINDOW_INTERVAL is set to the largest reasonable value that
    // appliances' clocks could differ by, then we can eliminate false negatives to a 
    // fairly high degree of probability. (We can raise the probability to any arbitrary 
    // amount by increasing the window, but the trade-off is that we'll have more and more
    // false positives.)
#define DEFAULT_BACKUP_DATE_WINDOW_IN_SECONDS                       300

// Security Parameter Constraints

#define MINIMUM_LONG_TERM_RETENTION_AUDIT_LOG_SIZE_LIMIT            1000
#define MAXIMUM_LONG_TERM_RETENTION_AUDIT_LOG_SIZE_LIMIT            1000000
#define MINIMUM_LONG_TERM_RETENTION_AUDIT_LOG_LIFETIME              "P7D"
#define MINIMUM_MEDIUM_TERM_RETENTION_AUDIT_LOG_SIZE_LIMIT          1000
#define MAXIMUM_MEDIUM_TERM_RETENTION_AUDIT_LOG_SIZE_LIMIT          1000000
#define MINIMUM_MEDIUM_TERM_RETENTION_AUDIT_LOG_LIFETIME            "P7D"
#define MINIMUM_SHORT_TERM_RETENTION_AUDIT_LOG_SIZE_LIMIT           1000
#define MAXIMUM_SHORT_TERM_RETENTION_AUDIT_LOG_SIZE_LIMIT           1000000
#define MINIMUM_SHORT_TERM_RETENTION_AUDIT_LOG_LIFETIME             "P7D"
#define MINIMUM_AUDIT_LOG_MAINTENANCE_FREQUENCY                     "PT1M"
#define MINIMUM_ROOT_CA_CERTIFICATE_LIFETIME                        "P1M"
#define MINIMUM_CERTIFICATE_LIFETIME                                "P1M"
#define MINIMUM_RETRIEVE_CERTIFICATE_ATTEMPT_LIMIT                  1
#define MAXIMUM_RETRIEVE_CERTIFICATE_ATTEMPT_LIMIT                  1000
#define MINIMUM_PASSPHRASE_MINIMUM_LENGTH                           8
#define MAXIMUM_PASSPHRASE_MINIMUM_LENGTH                           ( MAXIMUM_WIDE_STRING_VALUE_LENGTH )
#define MINIMUM_MANAGEMENT_SESSION_TIMEOUT_IN_MINUTES               0
#define MAXIMUM_MANAGEMENT_SESSION_TIMEOUT_IN_MINUTES               60

// The SYSTEM_FIPS_MODE_ONLY_ values must match those in
// enum KMS_Management__FIPSModeOnly in KMS_Management_SOAP.h and
// enum KMSManagement_FIPSModeOnly in KMSManagement.h
#define SYSTEM_FIPS_MODE_ONLY_UNCHANGED                             (-1)
#define SYSTEM_FIPS_MODE_ONLY_FALSE                                 0
#define SYSTEM_FIPS_MODE_ONLY_TRUE                                  1
#define MINIMUM_FIPS_MODE_ONLY                                      ( SYSTEM_FIPS_MODE_ONLY_FALSE )
#define MAXIMUM_FIPS_MODE_ONLY                                      ( SYSTEM_FIPS_MODE_ONLY_TRUE )

#define DEFAULT_MINIMUM_PASSPHRASE_LENGTH                           8
#define DEFAULT_MANAGEMENT_SESSION_TIMEOUT_IN_MINUTES               15
#define DEFAULT_FIPS_MODE_ONLY                                      ( SYSTEM_FIPS_MODE_ONLY_FALSE )

// To limit maximum query size, we limit # created
// this is probably (hopefully) temporary
#define MAXIMUM_CREATION_COUNT                                      999

// Audit Log

#define AUDIT_LOG_DEFAULT_SIZE_LONG_TERM_RETENTION                  1000000
#define AUDIT_LOG_DEFAULT_SIZE_MEDIUM_TERM_RETENTION                100000
#define AUDIT_LOG_DEFAULT_SIZE_SHORT_TERM_RETENTION                 10000
#define AUDIT_LOG_DEFAULT_LIFETIME_DAYS_LONG_TERM_RETENTION         "P2Y"
#define AUDIT_LOG_DEFAULT_LIFETIME_DAYS_MEDIUM_TERM_RETENTION       "P3M"
#define AUDIT_LOG_DEFAULT_LIFETIME_DAYS_SHORT_TERM_RETENTION        "P7D"

// Replication

// schema version 7: change to soap Discovery Service for supporting DNS
// schema version 8: change to soap Agent Service for RetrieveDataUnitKeys
// schema version 9: ensure that Ready keys appear in current backup
// schema version 10: IPv6 support and AES key wrap
// schema version 11: ICSF integration, distributed quorum, SNMP v2
// schema version 12: replication acceleration
#define REPLICATION_SCHEMA_VERSION_MIN                              8
#define REPLICATION_SCHEMA_VERSION_MAX                             12
#define REPLICATION_SCHEMA_VERSION_KEYS_IN_BACKUP                   9
#define REPLICATION_SCHEMA_VERSION_IPV6_ADDRESSES                  10 
#define REPLICATION_SCHEMA_VERSION_AES_KEY_WRAP                    10 
#define REPLICATION_SCHEMA_VERSION_MASTER_KEY_MODE                 11
#define REPLICATION_SCHEMA_VERSION_DISTRIBUTED_QUORUM              11
#define REPLICATION_SCHEMA_VERSION_SNMP_PROTOCOL_VERSION_TWO       11
#define REPLICATION_SCHEMA_VERSION_REPLICATION_ACCELERATION        12 
// value to return on inactive software versions
#define REPLICATION_SCHEMA_VERSION_INVALID                          0

// Key Sharing Transfer Formats

#define TRANSFER_FORMAT_INVALID                                       (-100)
#define TRANSFER_FORMAT_DEFAULT                                       (-1)
#define TRANSFER_FORMAT_LEGACY                                        0
#define TRANSFER_FORMAT_LEGACY_VERSION_STRING                         "2.0.1"
#define TRANSFER_FORMAT_FIPS                                          1
#define TRANSFER_FORMAT_FIPS_VERSION_STRING                           "2.1"

// Master Key Modes
#define _MASTER_KEY_MODE_OFF                                         0
#define _MASTER_KEY_MODE_ALL_KEYS                                    1
#define _MASTER_KEY_MODE_RECOVER_KEYS_ONLY                           2

// Derived/Master Key stuff
#define KEY_VERSION_PREFIX_LENGTH                                   2
#define KEY_VERSION_PREFIX_HEX_LENGTH                               (KEY_VERSION_PREFIX_LENGTH*2)
#define NON_DERIVED_KEY_VERSION                                     0x0000
#define NON_DERIVED_KEY_VERSION_HEX                                 (L"0000")
#define DERIVED_KEY_VERSION                                         0x0001
#define DERIVED_KEY_VERSION_HEX                                     (L"0001")
#define MASTER_KEY_ID_PREFIX_HEX                                    (L"0000")
#define MASTER_KEY_ID_PREFIX_LENGTH                                 2
#define MASTER_KEY_ID_PREFIX_HEX_LENGTH                             (MASTER_KEY_ID_PREFIX_LENGTH*2) 
#define MASTER_KEY_ID_KMAID_LENGTH                                  8
#define MASTER_KEY_ID_KMAID_HEX_LENGTH                              (MASTER_KEY_ID_KMAID_LENGTH*2)
#define MASTER_KEY_ID_RANDOM_LENGTH                                 8
#define MASTER_KEY_ID_LENGTH                                        (MASTER_KEY_ID_PREFIX_LENGTH + MASTER_KEY_ID_KMAID_LENGTH + MASTER_KEY_ID_RANDOM_LENGTH)
#define MASTER_KEY_ID_HEX_LENGTH                                    (MASTER_KEY_ID_LENGTH*2)	// ICSF can only handle 32-byte string IDs for keys
#define MASTER_KEY_ID_BASE64_LENGTH                                 32
#define DATA_UNIT_KEY_ID_HEX_LENGTH                                 (DATA_UNIT_KEY_ID_BUFFER_LENGTH*2)

// SNMP Manager protocol version stuff
#define SYSTEM_SNMP_PROTOCOL_VERSION_THREE                          0
#define SYSTEM_SNMP_PROTOCOL_VERSION_TWO                            1

#endif //ApplianceParameters_h
