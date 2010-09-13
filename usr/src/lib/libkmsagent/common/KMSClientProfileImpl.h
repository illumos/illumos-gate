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

/**
 * \file KMSClientProfileImpl.h
 */

#ifndef CLIENT_PROFILE_IMPL_H
#define CLIENT_PROFILE_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#define AGENT_LOG_FILE              "KMSAgentLog.log"
    
/**
 *  Build383 corresponds to 2.0.2 which does not support AES Key Wrap and
 *  enforcment of FIPS mode.
 */
#define FIPS_COMPATIBLE_KMA_VERSION "Build384"


extern bool g_bUseFileLog;

/*---------------------------------------------------------------------------
 * Function: KMSClient_InitializeLibrary
 *
 * Description: This function initializes the KMS Agent or Management API library. 
 *              It should be called before any other functions are invoked.
 *              Internally, it setups SSL library and Logging module.
 *                    
 *
 * Input
 * -----
 * i_wsWorkingDirectory -- Working directory of the program which uses the library
 * i_bIsManager -- TRUE: Initialize Management Library; FALSE: initialize Agent Library.
 * i_bUseFileLog:   True if logs should go to a log file in the working directory.  
 *                  False otherwise.
 *
 * Output
 * ------
 * return value                 TRUE or FALSE
 *
 *--------------------------------------------------------------------------*/
bool KMSClient_InitializeLibrary(
                        const utf8cstr i_wsWorkingDirectory,
                        int i_bUseFileLog );

/*---------------------------------------------------------------------------
 * Function: KMSClient_FinalizeLibrary
 *
 * Description: This function finalizes the KMS Agent(Or Management) API library. 
 *              It should be called when the library is not needed by the program. 
 *              Internally it cleans up SSL library and Logging module.
 * 
 *
 * Input
 * -----
 * i_bIsManager -- TRUE: Finalize Management Library; FALSE: Finalize Agent Library.
 *
 * Output
 * ------
 * return value                 TRUE or FALSE
 *
 *--------------------------------------------------------------------------*/
bool KMSClient_FinalizeLibrary();

utf8cstr KMSClient_GetLastErrorMessage(KMSClientProfile *i_pProfile);

bool KMSClient_LoadProfile(
                KMSClientProfile *io_pProfile,
                utf8cstr  i_wsProfileName,
                utf8cstr  i_wsEntityID,
                utf8cstr  i_wsPassphrase,
                utf8cstr  i_wsApplianceAddress,
                int       i_iTransactionTimeout,
                int       i_iFailOverLimit,
                int       i_iClusterDiscoveryFrequency,
                int       i_eKMSmode);

/*---------------------------------------------------------------------------
 * Function: KMSClient_GetClusterInformation
 *
 * Description: Get the cluster information by calling cluster discovery
 *              service. 
 *
 * Input
 * -----
 *            i_pProfile -- a pointer to an initialized KMSClientProfile structure
 *            i_iEntitySiteIDSize -- the buffer size of the entity site ID
 *                                           (KMS_MAX_ENTITIY_SITE_ID)
 *            i_iClusterEntryArraySize -- the array size for cluster entries
 *                                             (KMS_MAX_CLUSTER_NUM)
 * Output
 * ------
  *            o_wsEntitySiteID -- the entity's Site ID
 *            o_pApplianceNum -- the returned number of the appliances in the cluster                         
 *        o_pClusterEntryArray -- the array of cluster entries
 *
 * return value     TRUE/FALSE 
 *                         Use KMSAgent_GetLastErrorMessage() to get the error message
 *
 *
 *--------------------------------------------------------------------------*/
bool KMSClient_GetClusterInformation(KMSClientProfile *i_pProfile, 
                                     utf8cstr  o_wsEntitySiteID,
                                     int i_iEntitySiteIDSize,
                                     int *o_pApplianceNum,
                                     KMSClusterEntry *o_pClusterEntryArray,
                                     int i_iClusterEntryArraySize);

/**
 *  @return true if any KMAs are not FIPS compatible, i.e. perform AES key
 *  wrap.
 */
bool KMSClient_NoFIPSCompatibleKMAs(const KMSClientProfile * const i_pProfile);

/*---------------------------------------------------------------------------
 * Function: KMSClient_SelectAppliance
 *
 * Description: Select the current appliance. The current appliance is used for
 *              retrieving cluster information.
 *
 * Input
 * -----
 *            i_pProfile -- a pointer to an initialized KMSClientProfile structure
 *            i_wsApplianceAddress -- the IP address of the appliance
 * Output
 * ------
 *          (none)
 * return value     TRUE/FALSE 
 *                         Use KMSAgent_GetLastErrorMessage() to get the error message
 *
 *
 *--------------------------------------------------------------------------*/
bool KMSClient_SelectAppliance(KMSClientProfile *i_pProfile,
                               utf8cstr i_wsApplianceAddress);

/**
 *  check if the profile was loaded successfully
 *
 *  @param  i_pProfile  a pointer that may, or may not be to a loaded profile
 *
 *  @return true if the profile was loaded
 */
bool KMSClient_ProfileLoaded( KMSClientProfile *i_pProfile );

/*---------------------------------------------------------------------------
 * Function: KMSClient_DeleteProfile
 *
 * Description: Delete the profile information from the local disk
 * 
 *
 * Input
 * -----
 *               i_wsProfileName -- the profile name

 * Output
 * ------
 * return value     TRUE/FALSE 
 *                         Use KMSAgent_GetLastErrorMessage() to get the error message
 *
 *--------------------------------------------------------------------------*/   
bool KMSClient_DeleteProfile(utf8cstr i_wsProfileName);

/*---------------------------------------------------------------------------
 * Function: KMSClient_UnloadProfile
 *
 * Description: Destroy the profile information in memory including agent's private
 *              key.
 * 
 *
 * Input
 * -----
 *            i_pProfile -- a pointer to an initialized KMSClientProfile structure

 * Output
 * ------
 * return value     TRUE/FALSE 
 *                         Use KMSAgent_GetLastErrorMessage() to get the error message
 *
 *--------------------------------------------------------------------------*/   
bool KMSClient_UnloadProfile(KMSClientProfile *i_pProfile);

/**
 *   @return true if the soap fault string indicates that the SSL handshake
 *   did not succeed due to an invalid certificate.
 */
bool SSL_InvalidCertificate(const char * const i_sErrorString );

/**
 *   compares the error string with various soap fault substrings to determine if the
 *   error was a server-side error or not, also checks the supplied errno codes against
 *   various POSIX errno macros that would imply server connection issues
 */
bool ServerError (const char * i_sErrorString, int i_iErrno );

#ifdef __cplusplus
}

// helper macro to turn value into a string
#define LogError(a,b,c,d,e)        LogError_function(a,b,#b,c,d,e)

/**
 *  Log an error after saving the message in the profile.  This supports <code>KMSAgent_GetLastErrorMessage</code>
 *  @param i_pProfile an initialized profile
 *
 *  @param i_iErrno, the error expressed as a number
 *  @param i_sOperation, the operation number as a string
 *  @param i_sEntityID optional, the agent ID
 *  @param i_sNetworkAddress optional, the address of the KMA involved in the error
 *  @param i_sMessage optional, an informative error message
 */
void LogError_function(KMSClientProfile *i_pProfile,
              int i_iErrno,
              const char* i_sOperation,
              const char* i_sEntityID,
              const char* i_sNetworkAddress,
              const char* i_sMessage );

#endif

/**
 *  @return true if the KMA version string corresponds to a FIPS compatible
 *  KMA
 */
bool FIPScompatibleKMA (
                        const char * const i_sKMAVersion);

#define AUDIT_CLIENT_LOG_ERROR_BASE 0x300

#define AUDIT_CLIENT_AGENT_CREATE_AUDIT_LOG_SOAP_ERROR	                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x00)
#define AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_RESPONSE_INVALID_DESCRIPTION_LENGTH	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x01)
#define AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_RESPONSE_INVALID_DU_ID_LENGTH	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x02)
#define AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_RESPONSE_INVALID_EXTERNAL_TAG_LENGTH	(AUDIT_CLIENT_LOG_ERROR_BASE + 0x03)
#define AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_SOAP_ERROR	                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x04)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEYID_RESPONSE	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x05)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEY_GROUP_ID_LENGTH_RESPONSE	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x06)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEY_LENGTH_RESPONSE	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x07)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEY_STATE_RESPONSE	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x08)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEY_TYPE_RESPONSE	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x09)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_KEY_CALLOUT_ERROR	                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x0a)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_SOAP_ERROR	                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x0b)
#define AUDIT_CLIENT_AGENT_DISASSOCIATE_DATA_UNIT_KEYS_SOAP_ERROR	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x0c)
#define AUDIT_CLIENT_AGENT_LIST_KEY_GROUPS_SOAP_ERROR	                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x0d)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_RESPONSE_INVALID_DESCRIPTION_LENGTH	    (AUDIT_CLIENT_LOG_ERROR_BASE + 0x0e)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_RESPONSE_INVALID_EXTERNAL_TAG_LENGTH    (AUDIT_CLIENT_LOG_ERROR_BASE + 0x0f)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_SOAP_ERROR	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x10)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEYS_REMAINING_RESPONSE	(AUDIT_CLIENT_LOG_ERROR_BASE + 0x11)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEYS_SIZE_RESPONSE	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x12)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_ARRAY_SIZE_RESPONSE	(AUDIT_CLIENT_LOG_ERROR_BASE + 0x13)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_LENGTH_RESPONSE	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x14)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_RESPONSE	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x15)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_STATE_RESPONSE	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x16)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_TYPE_RESPONSE	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x17)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_KEY_CALLOUT_ERROR	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x18)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_SOAP_ERROR	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x19)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_RESPONSE_INVALID_DESCRIPTION_LENGTH	(AUDIT_CLIENT_LOG_ERROR_BASE + 0x1a)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_RESPONSE_INVALID_EXTERNAL_TAG_LENGTH	(AUDIT_CLIENT_LOG_ERROR_BASE + 0x1b)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_SOAP_ERROR	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x1c)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEYID_RESPONSE	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x1d)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEY_GROUP_ID_LENGTH_RESPONSE	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x1e)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEY_LENGTH_RESPONSE	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x1f)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEY_STATE_RESPONSE	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x20)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEY_TYPE_RESPONSE	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x21)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_KEY_CALLOUT_ERROR	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x22)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_SOAP_ERROR	                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x23)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEYID_RESPONSE	(AUDIT_CLIENT_LOG_ERROR_BASE + 0x24)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEY_GROUP_ID_LENGTH_RESPONSE (AUDIT_CLIENT_LOG_ERROR_BASE + 0x25)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEY_LENGTH_RESPONSE	         (AUDIT_CLIENT_LOG_ERROR_BASE + 0x26)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEY_STATE_RESPONSE	         (AUDIT_CLIENT_LOG_ERROR_BASE + 0x27)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEY_TYPE_RESPONSE	         (AUDIT_CLIENT_LOG_ERROR_BASE + 0x28)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_KEY_CALLOUT_ERROR	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x29)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_SOAP_ERROR	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x2a)
#define AUDIT_CLIENT_COMPUTE_CHALLENGE_RESPONSE_FAILED	                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x2b)
#define AUDIT_CLIENT_COMPUTE_FIXED_FAILED	                                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x2c)
#define AUDIT_CLIENT_GET_CERTIFICATE_INVALID_CERTIFICATE_FORMAT	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x2d)
#define AUDIT_CLIENT_GET_CERTIFICATE_INVALID_CHALLENGE_RESPONSE	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x2e)
#define AUDIT_CLIENT_GET_CERTIFICATE_INVALID_KEY_FORMAT	                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x2f)
#define AUDIT_CLIENT_GET_CERTIFICATE_INVALID_RESPONSE_FORMAT	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x30)
#define AUDIT_CLIENT_GET_CERTIFICATE_SAVE_CA_CERTIFICATE_FAILED	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x31)
#define AUDIT_CLIENT_GET_CERTIFICATE_SOAP_ERROR	                                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x32)
#define AUDIT_CLIENT_GET_CLUSTER_INFORMATION	                                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x33)
#define AUDIT_CLIENT_GET_CLUSTER_INFORMATION_SOAP_ERROR	                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x34)
#define AUDIT_CLIENT_GET_ROOT_CA_CERTIFICATE_INVALID_CA_CERTIFICATE_FORMAT	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x35)
#define AUDIT_CLIENT_GET_ROOT_CA_CERTIFICATE_INVALID_RESPONSE_FORMAT	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x36)
#define AUDIT_CLIENT_LOAD_CLUSTER_INFORMATION_INVALID_CLUSTER_FILE_FORMAT	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x37)
#define AUDIT_CLIENT_LOAD_CLUSTER_INFORMATION_OPEN_CLUSTER_FILE_FAILED	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x38)
#define AUDIT_CLIENT_LOAD_PROFILE_EXPORT_CERTIFICATE_AND_KEY_FAILED	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x39)
#define AUDIT_CLIENT_LOAD_PROFILE_FAILED	                                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x3a)
#define AUDIT_CLIENT_LOAD_PROFILE_SAVE_CA_CERTIFICATE_FAILED	                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x3b)
#define AUDIT_CLIENT_LOAD_PROFILE_SOAP_ERROR	                                        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x3c)
#define AUDIT_CLIENT_SAVE_CLUSTER_INFORMATION_OPEN_CLUSTER_FILE_FAILED	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x3d)
#define AUDIT_CLIENT_SAVE_ROOTCA_FAILED	                                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x3e)
#define AUDIT_CLIENT_SELECT_APPLIANCE	                                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x3f)
#define AUDIT_PROFILE_READ_CONFIG_FILE_INVALID_CONFIGURATION_FILE_FORMAT	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x40)
#define AUDIT_PROFILE_READ_CONFIG_FILE_OPEN_CONFIGURATION_FILE_FAILED	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x41)
#define AUDIT_PROFILE_WRITE_CONFIG_FILE_OPEN_CONFIGURATION_FILE_FAILED	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x42)
#define LoadProfile_AUDIT_CLIENT_GET_ROOT_CA_CERTIFICATE_SOAP_ERROR	                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x43)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_AESKEYUNWRAP_ERROR                            (AUDIT_CLIENT_LOG_ERROR_BASE + 0x44)
#define AUDIT_CLIENT_AGENT_REGISTER_KWK_ERROR                                       (AUDIT_CLIENT_LOG_ERROR_BASE + 0x45)
#define AUDIT_CLIENT_AGENT_REGISTER_KWK_INVALID_KEYID_RESPONSE                      (AUDIT_CLIENT_LOG_ERROR_BASE + 0x46)
#define AUDIT_CLIENT_AGENT_CREATE_KWK_RNG_ERROR                                     (AUDIT_CLIENT_LOG_ERROR_BASE + 0x47)
#define AUDIT_CLIENT_GET_KWK_WRAPPING_KEY_SOAP_ERROR                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x48)
#define AUDIT_CLIENT_GET_KWK_WRAPPING_KEY_INVALID_KEY_RESPONSE                      (AUDIT_CLIENT_LOG_ERROR_BASE + 0x49)
#define AUDIT_CLIENT_GET_KWK_WRAPPING_KEY_INVALID_RSA_PUB_KEY                       (AUDIT_CLIENT_LOG_ERROR_BASE + 0x50)
#define AUDIT_CLIENT_AGENT_CREATE_KWK_PUBLIC_ENCRYPT_ERROR                          (AUDIT_CLIENT_LOG_ERROR_BASE + 0x51)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_AESKEYUNWRAP_ERROR                          (AUDIT_CLIENT_LOG_ERROR_BASE + 0x52)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_AESKEYUNWRAP_ERROR      (AUDIT_CLIENT_LOG_ERROR_BASE + 0x53)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_AESKEYUNWRAP_ERROR               (AUDIT_CLIENT_LOG_ERROR_BASE + 0x54)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_WRAPPED_KEY_LENGTH_RESPONSE	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x55)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_WRAPPED_KEY_LENGTH_RESPONSE	        (AUDIT_CLIENT_LOG_ERROR_BASE + 0x56)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_WRAPPED_KEY_LENGTH_RESPONSE (AUDIT_CLIENT_LOG_ERROR_BASE + 0x57)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_WRAPPED_KEY_LENGTH_RESPONSE (AUDIT_CLIENT_LOG_ERROR_BASE + 0x58)
#define AUDIT_CLIENT_AGENT_CREATE_KEY_KWKID_MISMATCH                                (AUDIT_CLIENT_LOG_ERROR_BASE + 0x59)
#define AUDIT_CLIENT_AGENT_RETRIEVE_KEY_KWKID_MISMATCH                              (AUDIT_CLIENT_LOG_ERROR_BASE + 0x60)
#define AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_KWKID_MISMATCH                   (AUDIT_CLIENT_LOG_ERROR_BASE + 0x61)
#define AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_KWKID_MISMATCH          (AUDIT_CLIENT_LOG_ERROR_BASE + 0x62)
#define AUDIT_CLIENT_AGENT_LOAD_PROFILE_NO_FIPS_COMPATIBLE_KMAS_AVAILABLE           (AUDIT_CLIENT_LOG_ERROR_BASE + 0x63)

#endif
