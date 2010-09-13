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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/** @file             KMSAgent.h 
 *  @defgroup         EncryptionAgent Encryption Agent API
 *
 * The Agent API is used to communicate with the KMS Appliance for the
 * purpose of registering storage devices, obtaining device keys, and
 * receiving notifications of storage device events such as destruction.
 *
 */
#ifndef KMS_AGENT_H
#define KMS_AGENT_H

#include "KMSClientProfile.h"

/*---------------------------------------------------------------------------
 * The following ifdef block is the standard way of creating macros which
 * make exporting from a DLL simpler. All files within this DLL are compiled
 * with the KMS_AGENT_EXPORT symbol defined on the command line. this symbol
 * should not be defined on any project that uses this DLL. This way any
 * other project whose source files include this file see KMS Agent API functions
 * as being imported from a DLL, wheras this DLL sees symbols defined with
 * this macro as being exported.
 *--------------------------------------------------------------------------*/
#ifdef KMS_AGENT_EXPORT
#define KMS_AGENT_API __declspec(dllexport)
#else
#define KMS_AGENT_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------
 * Return Codes
 *--------------------------------------------------------------------------*/

/**
 * The status type returned on API calls
 */
typedef int KMS_AGENT_STATUS;

/**
 *  successful status
 */
#define KMS_AGENT_STATUS_OK                                                 0

/* error status values */
/**
 *   generic error is a catch all for a wide variety of errors, see the specific
 *   entry in the audit log for the details.  In general, the client API will return
 *   one of the specific status codes.  
 */
#define KMS_AGENT_STATUS_GENERIC_ERROR                                      100

/**
 * insufficient memory for the agent library to complete the request
 */
#define KMS_AGENT_STATUS_NO_MEMORY                                          102

/**
 * parameter error, invalid input 
 */
#define KMS_AGENT_STATUS_INVALID_PARAMETER                                  103

/**
 *  an API call was made before the profile was loaded
 */
#define KMS_AGENT_STATUS_PROFILE_NOT_LOADED                                 104

/**
 *  upon receipt of a key the callout function returned an error
 */
#define KMS_AGENT_STATUS_KEY_CALLOUT_FAILURE                                105

/**
 *  the specified profile failover attempts have been exceeded or no KMAs are available within the cluster
 */
#define KMS_AGENT_STATUS_KMS_UNAVAILABLE                                    106

/**
 *  the KMS does not have any keys in the READY state, this is a KMS issue that requires attention 
 *  from a KMS administrator.
 */
#define KMS_AGENT_STATUS_KMS_NO_READY_KEYS                                  107

/**
 *   the FIPS 140-2 known answer test (KAK) failed for AES Key wrap.
 */
#define KMS_AGENT_STATUS_FIPS_KAT_AES_KEYWRAP_ERROR                         108

/**
 *   #FIPS_MODE was specified on #KMSAgent_LoadProfile
 *   but no FIPS compatible KMAs are currently
 *   available.  Also, it may be that no FIPS compatible KMAs have been 
 *   configured within the KMS.
 */
#define KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE                             109

/**
 *  the profile was already successfully loaded and should be unloaded
 *  before attempting to load it again
 */
#define KMS_AGENT_STATUS_PROFILE_ALREADY_LOADED                             110

/**
 *   the FIPS 140-2 known answer test (KAK) failed for AES ECB.
 */
#define KMS_AGENT_STATUS_FIPS_KAT_AES_ECB_ERROR                             111

/**
 *   the FIPS 140-2 known answer test (KAK) failed for HMAC-SHA1.
 */
#define KMS_AGENT_STATUS_FIPS_KAT_HMAC_SHA1_ERROR                             112

/*
 *  SOAP Sender Errors - client errors associated with a KMS SOAP service
 */
 
/**
 * the following conditions can result in access denied being returned by the KMSAgent Soap service:
 * <ul>
 * <li>Agent is not enabled on the KMS
 * <li>Invalid DataUnitID or DataUnit does not exist
 * <li>Invalid ExternalUniqueID or DataUnit does not exist with specified ID
 * <li>Invalid ExternalTag
 * <li>Invalid KeyID
 * <li>Invalid KeyGroup or KeyGroup does not exist
 * <li>The Agent ID is not recognized as an agent by the KMS, i.e. the agent may not exist or the
 * ID represents another kind of entity.
 * <li>No KeyGroup specified and the Agent is not configured to have a default KeyGroup
 * <li>Agent does not have access to the specified KeyGroup
 * </ul>
 * to prevent leakage of information the specific details for access being denied are not
 * disclosed.  Audit log entries at the KMS can be used to determine specific reasons for 
 * access being denied.
 */
#define KMS_AGENT_STATUS_ACCESS_DENIED                                      200

/**
 *  This error status is only returned when received from the KMS and the transaction
 *  timeout has been exceeded.
 */
#define KMS_AGENT_STATUS_SERVER_BUSY                                        201

/**
 *   a data unit already exists with the specified external unique identifier
 */
#define KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS                          202

/**
 *  The external unique ID specified was found to exist but the corresponding
 *  DataUnitID did not exist.
 */
#define KMS_AGENT_STATUS_DATA_UNIT_ID_NOT_FOUND_EXTERNAL_ID_EXISTS          203


/**
 * The specified key has been destroyed or is unknown to the KMS
 */
#define KMS_AGENT_STATUS_KEY_DOES_NOT_EXIST                                 204

/**
 * The requested key has been destroyed.
 */
#define KMS_AGENT_STATUS_KEY_DESTROYED                                      205

/**
 *  The key received from a KMA encountered an error during AES Key Unwrapping
 */
#define KMS_AGENT_AES_KEY_UNWRAP_ERROR                                      206

/**
 *  An error occurred during establishment of an AES Key-Encryption Key
 */
#define KMS_AGENT_AES_KEY_WRAP_SETUP_ERROR                                  207

/*
 * Failed to decrypt the client private key data file due to incorrect PIN
 */
#define	KMS_AGENT_LOCAL_AUTH_FAILURE					    208

/**
 *   supported key types
 */
enum KMS_KEY_TYPE
{
    /**
     *  AES 256 key type
     */
    KMS_KEY_TYPE_AES_256                                                 
};

/**
 *  This enumerator type defines the various Key States.
 */
enum KMS_AGENT_KEY_STATE 
{
    KMS_KEY_STATE_GENERATED = 0,
    KMS_KEY_STATE_READY,

    /**
     * A key in this state can be used for both encryption and decryption. 
     * A key is placed into this state when it is assigned. The assignment is done when an encryption agent requests a new key be created.
     */
    KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS,

    /**
     * A key in this state can be used for decryption but not encryption. When an agent determines that none of the keys available to 
     * it (e.g., for a specific data unit that is being read or written) are in the protect-and-process state, it should create a new key. 
     * Keys transition from protect-and-process to process only when the encryption period for the key expires.
     */
    KMS_KEY_STATE_ACTIVE_PROCESS_ONLY,

    /**
     * The key has passed its cryptoperiod but may still be needed to process (decrypt) information. Auditable events are generated
     * when keys in this state are provided to the agent.
     */
    KMS_KEY_STATE_DEACTIVATED,

    /**
     * Keys are compromised when they are released to or discovered by an unauthorized entity. 
     * Compromised keys should not be used to protect information, but may be used to process information.
     * Auditable events are generated
     * when keys in this state are provided to the agent.
     */
    KMS_KEY_STATE_COMPROMISED,

    KMS_KEY_STATE_DESTROYED_INCOMPLETE,
    KMS_KEY_STATE_DESTROYED_COMPLETE,
    KMS_KEY_STATE_DESTROYED_COMPROMISED_INCOMPLETE,
    KMS_KEY_STATE_DESTROYED_COMPROMISED_COMPLETE

};

/*---------------------------------------------------------------------------
 * Data Unit State
 *--------------------------------------------------------------------------*/

/**
 *  this enumeration defines the DataUnit states
 */
enum KMS_AGENT_DATA_UNIT_STATE 
{
    /**
     * When a data unit has been created, but has not yet had any keys created it will be in "no key" state. 
     * This should be a short, transient condition that will be exited as soon as a key has been created.
     */
    KMS_DATA_UNIT_STATE_NO_KEY = 0,

    /**
     * Normal is a substate of readable. In this state, a data unit has at least one protect-and-process state key that can be used to encrypt data. 
     * The data unit is therefore writable.
     */
    KMS_DATA_UNIT_STATE_READABLE_NORMAL,                          

    /**
     * Needs rekey is a substate of readable. In this state, the data unit has no protect-and-process keys. 
     * Data should not be encrypted and written to the data unit unless the data unit is rekeyed and a new, active key is assigned. 
     * Its the responsibility of the agent to avoid using a key that is not in protect-and-process state for encryption. 
     * The data unit may have keys that are in process only, deactivated, or compromised state. Any of these keys can be used for decryption.
     */
    KMS_DATA_UNIT_STATE_READABLE_NEEDS_REKEY,                     		

    /**
     * When all of the keys for a data unit are destroyed, the data unit is shredded. The data unit cannot be read or written. 
     * However, a new key can be created for the data unit. This will return the data unit to normal state, allowing it to be read and written.
     */
    KMS_DATA_UNIT_STATE_SHREDDED                                 
};

/**
 *  This enumeration type defines Audit Log Retention values
 */
enum KMS_AUDIT_LOG_RETENTION
{
    /**
     * specifies that an audit log entry should have long term retention
     */
    KMS_AUDIT_LOG_LONG_TERM_RETENTION = 0,                                   
    /**
     * specifies that an audit log entry should have medium term retention
     */
    KMS_AUDIT_LOG_MEDIUM_TERM_RETENTION,                                
    /**
     * specifies that an audit log entry should have short term retention
     */
    KMS_AUDIT_LOG_SHORT_TERM_RETENTION                                  
};

/**
 *  This enumeration type defines Audit Log Condition values
 */
enum KMS_AUDIT_LOG_CONDITION
{
    /**
     * specifies that an audit log entry should should indicate a success condition
     */
    KMS_AUDIT_LOG_SUCCESS_CONDITION = 0,                                    

    /**
     * specifies that an audit log entry should should indicate an error condition
     */
    KMS_AUDIT_LOG_ERROR_CONDITION,                                       

    /**
     * specifies that an audit log entry should should indicate a warning condition
     */
    KMS_AUDIT_LOG_WARNING_CONDITION                                     
};

/**
 *   supported security modes
 */
enum KMS_SECURITY_MODE
{
    /**
     *  agent will work with any level of KMA
     */
    DEFAULT_MODE = 0,
    
    /**
     *  agent will only communicate with KMAs supporting FIPS 140-2 so that
     *  keys are encrypted at the KMA using AES Key Wrap.
     */
    FIPS_MODE
};

/*---------------------------------------------------------------------------
 * API Input/Output Data Structures
 *--------------------------------------------------------------------------*/
/**
 *  typedef for descriptions used in various places within the API
 */
typedef utf8char DESCRIPTION [KMS_MAX_DESCRIPTION+1];

/**
 *  typedef for key group ID
 */
typedef utf8char KEY_GROUP_ID[KMS_MAX_ID+1];

/**
 *  typedef for the Key Group struct
 */
typedef struct KMSAgent_KeyGroup KMSAgent_KeyGroup;

/** \struct KMSAgent_KeyGroup
 *  a Key Group with its ID and description
 */
struct KMSAgent_KeyGroup
{
    /**
     *  the unique ID of the KeyGroup
     */
    KEY_GROUP_ID m_acKeyGroupID;
    
    /**
     * the description of the KeyGroup
     */
    DESCRIPTION m_acDescription;
};

/**
 * An array of Key Groups
 */
typedef struct KMSAgent_ArrayOfKeyGroups KMSAgent_ArrayOfKeyGroups;

/** \struct KMSAgent_ArrayOfKeyGroups
 *  An array of Key Groups
 */
struct KMSAgent_ArrayOfKeyGroups
{
    /**
     *  pointer to an array of Key Groups
     */
    KMSAgent_KeyGroup* m_pKeyGroups;
    
    /**
     *  the number of Key Groups in the array
     */
    int m_iSize;
};


/**
 * typedef for a Key struct
 */
typedef struct KMSAgent_Key KMSAgent_Key;

/** \struct KMSAgent_Key
 *  key and its associated properites: KeyID, state, type, lenth, KeyGroup and the Key value
 */
struct KMSAgent_Key
{
    /**
     *  the unique ID of the key
     */
    KEY_ID m_acKeyID; 
    
    /**
     *  the state of the Key
     */
    enum KMS_AGENT_KEY_STATE m_iKeyState;
    
    /**
     *  the type of the key, e.g. AES_256
     */
    enum KMS_KEY_TYPE m_iKeyType;
    
    /**
     *  the unique ID of the KeyGroup
     */
    KEY_GROUP_ID m_acKeyGroupID;
    
    /**
     *  the key in plaintext.
     */
    KEY m_acKey;
    
    /**
     *  length of #m_acKey
     */
    int m_iKeyLength;
};

/**
 *  typedef for the External Unique ID
 */
typedef unsigned char EXTERNAL_UNIQUE_ID [KMS_MAX_EXTERNAL_UNIQUE_ID_SIZE];

/**
 *  typedef for the Data Unit ID
 */
typedef unsigned char DATA_UNIT_ID [KMS_DATA_UNIT_ID_SIZE];

/**
 *  typedef for the External Tag 
 */
typedef utf8char EXTERNAL_TAG [KMS_MAX_EXTERNAL_TAG+1];

/**
 * typedef for aData Unit structure. 
 */
typedef struct KMSAgent_DataUnit KMSAgent_DataUnit;

/** \struct KMSAgent_DataUnit
 *  struct for a DataUnit and its associated properties: DataUnitID, external unique ID,
 *  external tag, description and state. Data units are associated with zero or more keys.
 */
struct KMSAgent_DataUnit
{
    /**
     *  the unique DataUnit ID provided by the KMS
     */
    DATA_UNIT_ID m_acDataUnitID;
    
    /**
     *  a unique external ID for the data unit that is provided by the agent, may be NULL if one is not provided.
     *  The KMS will enforce the uniqueness of this identifier and not allow multiple data units having the same 
     *  #m_acExternalUniqueID value.
     */
    EXTERNAL_UNIQUE_ID m_acExternalUniqueID;
    /**
     *  the length in bytes of the #m_acExternalUniqueID field that represents the
     *  ID. The length
     *  must be less than or equal to #KMS_MAX_EXTERNAL_UNIQUE_ID_SIZE
     */
    int m_iExternalUniqueIDLength;

    /**
     *  an external tag representing information pertinent to the data unit, for example a volume serial number
     */
    EXTERNAL_TAG m_acExternalTag;
    
    /**
     *  a description of the data unit
     */
    DESCRIPTION m_acDescription;
    
    /**
     *  the state of the DataUnit
     */
    enum KMS_AGENT_DATA_UNIT_STATE m_iDataUnitState;
    
};

/**
 *   typedef for a list of keys
 */
typedef struct KMSAgent_ArrayOfKeys KMSAgent_ArrayOfKeys;

/** \struct KMSAgent_ArrayOfKeys
 *  struct for an array of keys
 */
struct KMSAgent_ArrayOfKeys
{
    /**
     *  keys are in chronological order based upon key creation date. However,
     *  when page offset argument to #KMSAgent_RetrieveDataUnitKeys
     *  is 0 the first key in the array will be the key in the 
     *  #KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS.
     */
    KMSAgent_Key* m_pKeys;
    
    /**
     *  the number of keys in the list
     */
    int m_iSize;
};

/**
 *  @return the version string for the KMS Agent Library
 */
const char * KMSAgent_GetVersion();

/** 
 *
 * This function initializes the KMS Agent API library. It
 * should be called before any other functions are invoked. Internally, 
 * sets up the SSL library and Logging module.
 *                
 * @param i_pWorkingDirectory       Working directory of the program which uses the
 *                                  library.  Default is "." if NULL is passed.
 * @param i_bUseFileLog:            True(1) if errors should go to a log file in the working directory.  
 *                                  If false(0) then errors will not be logged to a file.
 *
 * @return #KMS_AGENT_STATUS_OK
 * @return #KMS_AGENT_STATUS_GENERIC_ERROR if library initialization fails
 */
KMS_AGENT_STATUS KMSAgent_InitializeLibrary(
                        const utf8cstr     i_pWorkingDirectory,
                        int                i_bUseFileLog );

/**
 * This function exercises FIPS 140-2 Known Answer Tests for certified algorithms
 * used in the agent toolkit.  This function should only be called once and may
 * be called prior to #KMSAgent_InitializeLibrary.
 *
 * @return #KMS_AGENT_STATUS_OK
 * @return #KMS_AGENT_STATUS_FIPS_KAT_AES_KEYWRAP_ERROR
 * @return #KMS_AGENT_STATUS_FIPS_KAT_AES_ECB_ERROR
 * @return #KMS_AGENT_STATUS_FIPS_KAT_HMAC_SHA1_ERROR
 */
KMS_AGENT_STATUS KMSAgent_KnownAnswerTests();

/**
 * This function finalizes the KMS Agent API library. It should
 * be called when the library is not needed by the program. Internally it
 * cleans up the SSL library and Logging module.
 * 
 * @return #KMS_AGENT_STATUS_OK
 * @return #KMS_AGENT_STATUS_GENERIC_ERROR if library finalization fails
 *
 */
KMS_AGENT_STATUS KMSAgent_FinalizeLibrary();

/**
 * This function can be used to get the last error message when
 * an API function encounters an error.  These error messages also
 * are written to the log, if file logging was enabled during library
 * initialization.
 *
 * @param     i_pProfile        an initialized #KMSClientProfile; the failed
 *                              function must have used this profile.
 * @return    the pointer to the last error message or NULL
 *
 */
utf8cstr KMSAgent_GetLastErrorMessage(
                        KMSClientProfile* i_pProfile );


    /**
     * Get the cluster information by calling the KMS_Discovery service using the KMA specified in the
     * profile, no load balancing will occur.  If discovery to this KMA fails then discovery will be
     * attempted using previously retrieved cluster information.
     *
     * If #KMSAgent_LoadProfile was called with an IPv6 address for
     * the <code>i_pInitialApplianceAddress</code> argument then the <code>o_pClusterEntryArray</code> will contain
     * IPv6 addresses instead of IPv4 addresses for each KMA that has an IPv6 address.
     * @see #KMSAgent_LoadProfile and #KMSAgent_SelectAppliance.
     *
     * If the size of the cluster returned by the KMS_Discovery servic exceeds <code>i_iClusterEntryArraySize</code>
     * then the KMA list is filtered to contain the
     * first <code>i_iClusterEntryArraySize</code> KMAs that meet the profile's FIPS setting, agent site and are reported as responding by the
     * KMS discover cluster response.
     *
     * @param    i_pProfile               a pointer to an initialized #KMSClientProfile structure
     * @param    i_iEntitySiteIDSize      the buffer size of the entity site ID including null terminator
     *                                    (should be greater than #KMS_MAX_ENTITY_SITE_ID )
     * @param    i_iClusterEntryArraySize the array size for cluster entries (must be less than or equal to #KMS_MAX_CLUSTER_NUM )
     * @param    o_pEntitySiteID          a buffer allocated by the caller to store the agent's (aka entity) Site ID
     * @param    o_pApplianceNum          the returned number of appliances in the cluster
     * @param    o_pClusterEntryArray     a buffer allocated by the caller to store the array of cluster entries
     *
     * @return #KMS_AGENT_STATUS_OK
     * @return #KMS_AGENT_STATUS_INVALID_PARAMETER
     * @return #KMS_AGENT_STATUS_GENERIC_ERROR
     * @return #KMS_AGENT_STATUS_ACCESS_DENIED
     * @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
     * @return #KMS_AGENT_STATUS_SERVER_BUSY
     * @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
     * @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
     */
    KMS_AGENT_STATUS KMSAgent_GetClusterInformation(
            KMSClientProfile * const i_pProfile,
            int i_iEntitySiteIDSize,
            int i_iClusterEntryArraySize,
            utf8cstr const o_pEntitySiteID,
            int * const o_pApplianceNum,
            KMSClusterEntry * const o_pClusterEntryArray);

/**
 * Specifies the Key Management Appliance to be used
 * for retrieving cluster information.
 *
 * @param i_pProfile               a pointer to an initialized #KMSClientProfile
 *                                 structure
 * @param i_pApplianceAddress      the IP address of the appliance.  IPv6 addresses
 *                                 must be enclosed in brackets, [], see #KMSAgent_LoadProfile.
 *
 * @return #KMS_AGENT_STATUS_OK
 * @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 * @return #KMS_AGENT_STATUS_GENERIC_ERROR
 * @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *
 */
KMS_AGENT_STATUS KMSAgent_SelectAppliance(
                        KMSClientProfile* const i_pProfile,
                        utf8cstr const          i_pApplianceAddress );

/**
 * Load profile handles both agent enrollment with the KMS and post enrollment setup.
 * <p>
 * <b>Enrollment Behavior</b>
 * <br>
 * When a passphrase is supplied enrollment, or reenrollment, with a KMS cluster is attempted in order
 * to establish a mutual trust relationship.  Enrollment occurs with the KMA in the cluster specified
 * by <code>i_pApplianceAddress</code>.  
 * <p>
 * The KMS CA web service is used for CA certificate retrieval prior to
 * invoking the KMS Certificate web service. Certficate retrieval via these services
 * uses the <code>i_pApplianceAddress</code> for enrollment. Cluster discovery is then performed to
 * identify the set of KMAs within the cluster.
 * Successful enrollment results in
 * persistent storage of the CA X.509 certificate, agent X.509 certificate and private key.  
 * </p>
 * Once enrolled successfully the KMS
 * will then disable usage of the agent's passphrase for enrollment as a security precaution.
 * Subsequent enrollment will require a new passphrase.
 * <p>
 * <b>Post Enrollment Behavior</b>
 * <br>
 * When a passphrase is not provided a profile is assumed to exist and the library profile structure
 * is initialized from persistent storage with the configuration settings(agent ID, 
 * KMA service port numbers, KMA Address, transaction timeout, discovery frequency, transaction timeout
 * and failover limit), cluster information(agent's site ID and KMA cluster information and KMA status) and 
 * enrollment items: the CA certificate, Agent Certificate and agent private key.  
 * <p>
 * Finally, cluster discovery is performed(unless disabled), and a load balancer is initialized 
 * for balancing transactions across KMAs within the
 * cluster and for handling transaction failover scenarios.  
 * Subsequent API calls using the profile will invoke cluster discovery at the frequency specified
 * by <code>iClusterDiscoveryFrequency</code>.  Updated discovery information is persisted with the
 * profile. The load balancer maintains affinity to KMAs within the same site as the agent for
 * agent transactions unless an error requires failover
 * to another KMA in the cluster. An agent's site ID may also be updated by a discovery
 * operation.
 * 
 * @param io_pProfile               a pointer to a #KMSClientProfile buffer allocated by the caller
 * @param i_pProfileName            the profile name
 * @param i_pAgentID                Optional.  For a new profile the encryption agent's ID is required.
 * @param i_pPassphrase             Optional.  For a new profile the encryption agent's passphrase is required.  This passphrase
 *                                  may only be used once for a successful retrieval of the Certificate and agent private key.
 * @param i_pInitialApplianceAddress the initial IP Address of an Appliance in the KMS Cluster that is reachable by this agent. If
 *                                  enrollment has previously occurred specification of an initial IP address that is not
 *                                  a member of the profile's cluster information will force the cluster information 
 *                                  to be deleted and discovery to be performed with the new IP address.
 *                                  An IPv6 address may be supplied but must be enclosed with brackets, [], in accordance
 *                                  with RFC 2396, "Format for Literal IPv6 Addresses in URL's".  Supplying an IPv6 address will cause
 *                                  the agent library to utilize KMA IPv6 addresses over IPv4 addresses when they are available,
 *                                  otherwise IPv4 KMA addresses will be used.  
 * @param i_iTransactionTimeout     the timeout setting for a transaction in seconds, must be a positive value.
 * @param i_iFailOverLimit          Failed KMA transactions will be retried up to this limit. Once this limit
 *                                  has been reached API calls will return #KMS_AGENT_STATUS_KMS_UNAVAILABLE.
 *                                  Specify -1 for unlimited failover attempts, 0 for no failover.  The worst case completion time for
 *                                  an API call is approximately equal to <code>i_iFailOverLimit</code> * <code>i_iTransactionTimeout</code>.
 *                                  
 * @param i_iClusterDiscoveryFrequency
 *                                  frequency of calling cluster discovery service
 *                                  in seconds (use 0 to disable load balancing and periodic cluster discovery)
 * @param i_eKMSmode                specifies the KMS operational mode that the 
 *                                  agent should enforce.  Setting this to #FIPS_MODE
 *                                  causes the agent to only communicate with KMAs in the
 *                                  cluster that support AES key wrapping for key requests.
 *                                  This is not a persisted setting and is only applicable
 *                                  to the current session.
 *                                  
 * @return #KMS_AGENT_STATUS_OK
 * @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 * @return #KMS_AGENT_STATUS_GENERIC_ERROR
 * @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 * @return #KMS_AGENT_STATUS_PROFILE_ALREADY_LOADED
 * @return #KMS_AGENT_STATUS_ACCESS_DENIED
 * @return #KMS_AGENT_STATUS_SERVER_BUSY
 * @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 * @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 */
KMS_AGENT_STATUS KMSAgent_LoadProfile(
                        KMSClientProfile* const io_pProfile,
                        utf8cstr const          i_pProfileName,
                        utf8cstr const          i_pAgentID,
                        utf8cstr const          i_pPassphrase,
                        utf8cstr const          i_pInitialApplianceAddress,
                        int                     i_iTransactionTimeout,
                        int                     i_iFailOverLimit,
                        int                     i_iClusterDiscoveryFrequency,
                        int                     i_eKMSmode );

    
/**
 * Destroy the profile information in memory, the agent's profile configuration,
 * cluster information, certificate and 
 * private key are retained in persistant storage.
 * 
 * @param i_pProfile        a pointer to an initialized KMSClientProfile
 *                          structure.
 *
 * @return #KMS_AGENT_STATUS_OK
 * @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *
 */
KMS_AGENT_STATUS KMSAgent_UnloadProfile(
                        KMSClientProfile* const i_pProfile );

/**
 * Delete the profile information from persistent storage.  The agent's profile configuration,
 * cluster information, certificate and
 * private key are discared, see #KMSAgent_LoadProfile for how to initialize
 * the profile again.  The profile should be unloaded prior to making this call.
 * 
 * @param i_pProfileName          the profile name
 *
 * @return #KMS_AGENT_STATUS_OK
 * @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 * @return #KMS_AGENT_STATUS_GENERIC_ERROR
 */
KMS_AGENT_STATUS KMSAgent_DeleteProfile(
                        utf8cstr i_pProfileName );

/**
 * Fetch the key groups this agent is allowed to access.  The caller should invoke #KMSAgent_FreeArrayOfKeyGroups
 * to release the allocated memory resources for the array. Up to #KMS_MAX_LIST_KEY_GROUPS key groups will be
 * returned.
 * 
 * @param i_pProfile       an initialized #KMSClientProfile
 * @param o_ppKeyGroups    a buffer allocated by this routine for the array of Key Groups and individual key groups
 *                         that this agent is allowed to access
 *
 * @return #KMS_AGENT_STATUS_OK
 * @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 * @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 * @return #KMS_AGENT_STATUS_NO_MEMORY
 * @return #KMS_AGENT_STATUS_GENERIC_ERROR
 * @return #KMS_AGENT_STATUS_ACCESS_DENIED
 * @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 * @return #KMS_AGENT_STATUS_SERVER_BUSY
 * @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 * @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 */
KMS_AGENT_STATUS KMSAgent_ListKeyGroups(
                         KMSClientProfile* const 	       i_pProfile,
                         KMSAgent_ArrayOfKeyGroups** const o_ppKeyGroups );

/**
 * Helper function which frees memory allocated for the output
 * to #KMSAgent_ListKeyGroups.
 *
 * @param i_pArrayOfKeyGroups   a pointer to #KMSAgent_ArrayOfKeyGroups                   
 * 
 * @return void
 *
 */
void KMSAgent_FreeArrayOfKeyGroups(
                         KMSAgent_ArrayOfKeyGroups* i_pArrayOfKeyGroups );

/**
 *  Creates a Key for the specified data unit. If a data unit is provided then the key will be associated with
 *  the data unit.  The type of key created is dictated by the KMS key policy for the key group.  This policy is set up by KMS
 *  administrators to be compatible with agents associated with the key group.
 *  If KeyGroup is provided then the new key is associated with the specified KeyGroup, otherwise the agent's 
 *  default KeyGroup is associated with the key.
 *  @param i_pProfile               an initialized #KMSClientProfile
 *  @param i_pDataUnit              Optional. a pointer to a data unit to be associated with the key, if known.  
 *  @param i_pKeyGroupID            Optional, the KeyGroup ID to be assigned to the new Key, if known.  Pass NULL
 *                                  if unknown and the new key will be associated with the agent's default key group
 *  @param o_pKey                   A pointer to a buffer for returning the new key and key associated data.
 *
 *  @return #KMS_AGENT_STATUS_OK
 *  @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *  @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *  @return #KMS_AGENT_STATUS_NO_MEMORY
 *  @return #KMS_AGENT_STATUS_KEY_CALLOUT_FAILURE
 *  @return #KMS_AGENT_STATUS_GENERIC_ERROR
 *  @return #KMS_AGENT_STATUS_ACCESS_DENIED
 *  @return #KMS_AGENT_STATUS_SERVER_BUSY
 *  @return #KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS
 *  @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  @return #KMS_AGENT_STATUS_KMS_NO_READY_KEYS
 *  @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 *  @return #KMS_AGENT_AES_KEY_UNWRAP_ERROR
 *  @return #KMS_AGENT_AES_KEY_WRAP_SETUP_ERROR
 */
KMS_AGENT_STATUS KMSAgent_CreateKey(
                        KMSClientProfile* const        i_pProfile,
                        const KMSAgent_DataUnit* const i_pDataUnit,
                        KEY_GROUP_ID const             i_pKeyGroupID,
                        KMSAgent_Key* const            o_pKey);

/**
 *  Creates a DataUnit with the specified external unique id and external tag. 
 *
 *  @param i_pProfile                   an initialized #KMSClientProfile
 *  @param i_pExternalUniqueID          Optional. A unique data unit identifier to be associated with 
 *                                      the data unit. Uniqueness is enforced by the KMS. See also #KMSAgent_RetrieveDataUnit.
 *  @param i_iExternalUniqueIDIDLen     Length in bytes of the external unique identifier.  If                                    
 *                                      <code>i_pExternalUniqueID</code> is NULL then this field is ignored, otherwise a positive length must be provided.
 *  @param i_pExternalTag               Optional, but recommended. Pointer to an External Tag for the data unit, e.g. a volume serial number.
 *  @param i_pDescription               Optional, a textual description of the data unit.
 *  @param o_pDataUnit                  a pointer to a DataUnit buffer where
 *                                      data unit information is returned
 *
 *  @return #KMS_AGENT_STATUS_OK
 *  @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *  @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *  @return #KMS_AGENT_STATUS_NO_MEMORY
 *  @return #KMS_AGENT_STATUS_GENERIC_ERROR
 *  @return #KMS_AGENT_STATUS_ACCESS_DENIED
 *  @return #KMS_AGENT_STATUS_SERVER_BUSY
 *  @return #KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS
 *  @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
*/
KMS_AGENT_STATUS KMSAgent_CreateDataUnit(
                        KMSClientProfile* const    i_pProfile,
                        const unsigned char *      i_pExternalUniqueID,
                        int                        i_iExternalUniqueIDIDLen,
                        utf8cstr const             i_pExternalTag,
                        utf8cstr const             i_pDescription,
                        KMSAgent_DataUnit* const   o_pDataUnit);

/**
 *  The agent may use this function to inform the KMS that the DataUnit has, or will be, overwritten.  
 *  The KMS will remove the association from the specified DataUnit to all its keys, excluding its key
 *  in the #KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS state. By utilizing this API, agent's can help keep the
 *  number of keys returned by #KMSAgent_RetrieveDataUnitKeys to just the keys being used on the Data Unit.
 *
 *  @param i_pProfile       an initialized #KMSClientProfile
 *  @param i_pDataUnit      A pointer to the data unit
 *
 *  @return #KMS_AGENT_STATUS_OK
 *  @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *  @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *  @return #KMS_AGENT_STATUS_NO_MEMORY
 *  @return #KMS_AGENT_STATUS_GENERIC_ERROR
 *  @return #KMS_AGENT_STATUS_ACCESS_DENIED
 *  @return #KMS_AGENT_STATUS_SERVER_BUSY
 *  @return #KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS
 *  @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 */
KMS_AGENT_STATUS KMSAgent_DisassociateDataUnitKeys(
                    KMSClientProfile* const            i_pProfile,
                    const KMSAgent_DataUnit* const     i_pDataUnit);

                        
/**
 *  retrieve a key by the Key's ID, optionally specifying the Data Unit and KeyGroup to be
 *  associated with the key.  Supplying the Data Unit information allows the KMS to add an
 *  association between the Key and the Data Unit. The assumption being made is that the key being
 *  retrieved has been used on the specified Data Unit and needs to be associated with it.  This 
 *  side affect allows the KMS to build up its knowledge of key usage as it relies upon agents
 *  for discovering and reporting how keys are being used on Data Units.  For example, when keys 
 *  are imported into a KMS the information associating keys with DataUnits may not be provided, 
 *  consequently the KMS is unaware of what DataUnits were encrypted with a particular key.
 *
 *  @param i_pProfile       an initialized KMSClientProfile
 *  @param i_pKeyID         The ID of the Key being requested
 *  @param i_pDataUnit      Optional. If non-NULL, the  KMS will verify that an association exists between the key and the Data Unit and create
 *                          the association if it is missing.  
 *  @param i_pKeyGroupID    Optional. If non-NULL, and the key is not already associated with a KeyGroup, then the KMS will associate the key with the specified KeyGroup.
 *  @param o_pKey           A pointer to a buffer allcoated by the caller for returning the new key and key associated data.
 *
 *  @return #KMS_AGENT_STATUS_OK
 *  @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *  @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *  @return #KMS_AGENT_STATUS_NO_MEMORY
 *  @return #KMS_AGENT_STATUS_KEY_CALLOUT_FAILURE
 *  @return #KMS_AGENT_STATUS_GENERIC_ERROR
 *  @return #KMS_AGENT_STATUS_ACCESS_DENIED
 *  @return #KMS_AGENT_STATUS_SERVER_BUSY
 *  @return #KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS
 *  @return #KMS_AGENT_STATUS_KEY_DOES_NOT_EXIST
 *  @return #KMS_AGENT_STATUS_KEY_DESTROYED
 *  @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 *  @return #KMS_AGENT_AES_KEY_UNWRAP_ERROR
 *  @return #KMS_AGENT_AES_KEY_WRAP_SETUP_ERROR
 */
KMS_AGENT_STATUS KMSAgent_RetrieveKey(
                        KMSClientProfile* const              i_pProfile,
                        const unsigned char * const          i_pKeyID,
                        const KMSAgent_DataUnit* const       i_pDataUnit,
                        utf8cstr const                       i_pKeyGroupID,
                        KMSAgent_Key* const                  o_pKey);

/**
 *  Retrieve a Data Unit by its data unit identifier.
 *
 *  @param i_pProfile                   an initialized #KMSClientProfile
 *  @param i_pDataUnitID                the data unit ID by which retrieval will be performed
 *  @param i_pExternalUniqueID          Optional, a unique data unit identifier to be associated with 
 *                                      the data unit. Uniqueness is enforced by the KMS. 
 *  @param i_iExternalUniqueIDLen       Length in bytes of the external unique identifier, must be positive.  If                                    
 *                                      <code>i_pExternalUniqueID</code> is NULL then this field is ignored.                                     
 *  @param i_pExternalTag               Optional, but recommended. Pointer to a data unit external tag, e.g. volser
 *  @param i_pDescription               Optional, a textual description of the data unit.
 *  @param o_pDataUnit                  a pointer to a DataUnit buffer allocated by the caller where
 *                                      data unit information is returned
 *
 *  @return #KMS_AGENT_STATUS_OK
 *  @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *  @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *  @return #KMS_AGENT_STATUS_NO_MEMORY
 *  @return #KMS_AGENT_STATUS_GENERIC_ERROR
 *  @return #KMS_AGENT_STATUS_ACCESS_DENIED
 *  @return #KMS_AGENT_STATUS_SERVER_BUSY
 *  @return #KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS
 *  @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 */
KMS_AGENT_STATUS KMSAgent_RetrieveDataUnit(
                        KMSClientProfile* const         i_pProfile,
                        const unsigned char * const     i_pDataUnitID,
                        const unsigned char * const     i_pExternalUniqueID,
                        int                             i_iExternalUniqueIDLen,
                        utf8cstr const                  i_pExternalTag,
                        utf8cstr const                  i_pDescription,
                        KMSAgent_DataUnit* const        o_pDataUnit);

/**
 *  Retrieve a Data Unit by its external unique identifier.
 *  If the KMS does not contain a data unit with the specified unique identifier then a data unit will
 *  be created.  The new data unit will contain the external unique identifier and the external tag, if 
 *  provided.
 *
 *  @param i_pProfile                   an initialized #KMSClientProfile
 *  @param i_pExternalUniqueID          A unique data unit identifier to be associated with 
 *                                      the data unit. Uniqueness is enforced by the KMS. 
 *  @param i_iExternalUniqueIDLen       Length in bytes of the external unique identifier, must be positive.                      
 *  @param i_pExternalTag               Optional, but recommended. Pointer to a data unit external tag, e.g. volser
 *  @param i_pDescription               Optional, a textual description of the data unit.
 *  @param o_pDataUnit                  a pointer to a DataUnit buffer allocated by the caller where
 *                                      data unit information is returned
 *
 *  @return #KMS_AGENT_STATUS_OK
 *  @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *  @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *  @return #KMS_AGENT_STATUS_NO_MEMORY
 *  @return #KMS_AGENT_STATUS_GENERIC_ERROR
 *  @return #KMS_AGENT_STATUS_ACCESS_DENIED
 *  @return #KMS_AGENT_STATUS_SERVER_BUSY
 *  @return #KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS
 *  @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 */
KMS_AGENT_STATUS KMSAgent_RetrieveDataUnitByExternalUniqueID(
                        KMSClientProfile* const         i_pProfile,
                        const unsigned char* const      i_pExternalUniqueID,
                        int                             i_iExternalUniqueIDLen,
                        utf8cstr const                  i_pExternalTag,
                        utf8cstr const                  i_pDescription,
                        KMSAgent_DataUnit* const        o_pDataUnit);

/**
 *  retrieve keys assigned to a Data Unit. 
 *  Agents should consult the state of each key that is returned and only
 *  use the key in the #KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS state for encryption. The agent service
 *  attempts to return the most recently created key in the #KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS state
 *  as the first key in the list when a <code>i_pKeyID</code> is not specified.  This cannot be guaranteed as
 *  there may not be a key in the #KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS state for the specified 
 *  data unit.  The rest of the keys returned are sorted in ascending order by the time in which
 *  they were created on the server.
 *  #KMSAgent_DisassociateDataUnitKeys may be used to manage the
 *  size of the key list associated with a data unit.  
 *  The <code>i_iPageSize</code>, <code>i_iPageOffset</code> and <code>o_piKeysRemaining</code> parameters may be used for retrieving
 *  subsets of the list. For the <code>i_pKeyID</code> argument see the parameter's description.  
 *  Callers should invoke#KMSAgent_FreeArrayOfKeys when finished with the buffer of keys.
 * 
 *  @param i_pProfile        an initialized #KMSClientProfile
 *  @param i_pDataUnit       The Data Unit for which all keys will be retrieved. 
 *  @param i_iPageSize       the number of keys to be retrieved, up to #KMS_MAX_PAGE_SIZE.
 *  @param i_iPageOffset     the offset from the start of the data unit's key list. Set this to zero for
 *                           retrieval from the start of the list or if <code>i_pKeyID</code> is non-null.  
 *                           When set to zero the first key returned in the list
 *                           will be the most recently created key in the #KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS state.
 *  @param o_piKeysRemaining a pointer to an integer where the number of keys remaining in the list will be returned
 *  @param i_pKeyID          Optional. If non-null, the caller provides a pointer to a KeyID that is used for 
 *                           the retrieval and the list returned begins with the specified data unit's KeyID and up to 
 *                           <code>i_iPageSize</code> keys associated with the data unit having an activation date greater than the key 
 *                           corresponding to <code>i_pKeyID</code>.  The first key in the list is not guaranteed
 *                           to be in the #KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS state.  If the specified <code>i_pKeyID</code>
 *                           is not associated with the Data Unit then the behavior is like #KMSAgent_RetrieveKey and
 *                           a single key is returned.
 *                           When non-null the <code>i_iPageOffset</code>
 *                           argument must be 0, these arguments are mutually exclusive.
 *  @param o_ppKeys          a pointer to pointer to a #KMSAgent_ArrayOfKeys struct allocated by this routine for returning the specified number of
 *                           Data Unit's keys and key associated data.  Up to <code>i_iPageSize</code>
 *                           keys will be returned. Callers should invoke #KMSAgent_FreeArrayOfKeys
 *                           when finished with the buffer of keys.
 *  @return #KMS_AGENT_STATUS_OK
 *  @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *  @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *  @return #KMS_AGENT_STATUS_NO_MEMORY
 *  @return #KMS_AGENT_STATUS_GENERIC_ERROR
 *  @return #KMS_AGENT_STATUS_ACCESS_DENIED
 *  @return #KMS_AGENT_STATUS_KEY_CALLOUT_FAILURE
 *  @return #KMS_AGENT_STATUS_SERVER_BUSY
 *  @return #KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS
 *  @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  @return #KMS_AGENT_STATUS_KEY_DOES_NOT_EXIST  if <code>i_pKeyID</code> does not exist in the KMS.
 *  @return #KMS_AGENT_STATUS_KEY_DESTROYED if <code>i_pKeyID</code> has been destroyed.
 *  @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 *  @return #KMS_AGENT_AES_KEY_UNWRAP_ERROR
 *  @return #KMS_AGENT_AES_KEY_WRAP_SETUP_ERROR
 */
KMS_AGENT_STATUS KMSAgent_RetrieveDataUnitKeys(
                        KMSClientProfile* const              i_pProfile,
                        const KMSAgent_DataUnit* const       i_pDataUnit,
                        int                                  i_iPageSize,
                        int                                  i_iPageOffset,
                        int* const                           o_piKeysRemaining,
                        const unsigned char * const          i_pKeyID,
                        KMSAgent_ArrayOfKeys** const         o_ppKeys);

/**
 *  returns a key in the #KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS for the specified data unit.  A new
 *  key will be created if the data unit does not have a key in the protect and process state or if the
 *  agent is not authorized to access the key in the protect and process state.
 *  @param i_pProfile                an initialized #KMSClientProfile
 *  @param i_pDataUnit               The Data Unit for which a key in the protect and process state will be returned. 
 *  @param i_pKeyGroupID             Optional. If non-NULL and a new key is to be created, the KMS will associate the key with the specified KeyGroup
 *  @param o_pKey                    A pointer to a buffer for returning the protect and process key.  If the data unit
 *                                   is associated with multiple keys in the protect and process state then the
 *                                   most recently created protect and process key is returned.
 *                                   
 *  @return #KMS_AGENT_STATUS_OK
 *  @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *  @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *  @return #KMS_AGENT_STATUS_NO_MEMORY
 *  @return #KMS_AGENT_STATUS_GENERIC_ERROR
 *  @return #KMS_AGENT_STATUS_ACCESS_DENIED
 *  @return #KMS_AGENT_STATUS_KEY_CALLOUT_FAILURE
 *  @return #KMS_AGENT_STATUS_SERVER_BUSY
 *  @return #KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS
 *  @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  @return #KMS_AGENT_STATUS_KMS_NO_READY_KEYS
 *  @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 *  @return #KMS_AGENT_AES_KEY_UNWRAP_ERROR
 *  @return #KMS_AGENT_AES_KEY_WRAP_SETUP_ERROR
 */
KMS_AGENT_STATUS KMSAgent_RetrieveProtectAndProcessKey(
                        KMSClientProfile* const              i_pProfile,
                        const KMSAgent_DataUnit* const       i_pDataUnit,
                        utf8cstr const                       i_pKeyGroupID,
                        KMSAgent_Key* const                  o_pKey);

/**
 *  Helper function which frees memory allocated for the output to #KMSAgent_RetrieveDataUnitKeys. 
 *  @param i_pArrayOfKeys  The array of keys to be freed 
 */
void KMSAgent_FreeArrayOfKeys(
                        KMSAgent_ArrayOfKeys*   i_pArrayOfKeys);

/**
 *  create an entry in the KMS audit log
 *
 *  @param i_pProfile        an initialized #KMSClientProfile
 *  @param i_iRetention      the retention of audit log, can be one of:
 *                           #KMS_AUDIT_LOG_LONG_TERM_RETENTION
 *                           #KMS_AUDIT_LOG_MEDIUM_TERM_RETENTION
 *                           #KMS_AUDIT_LOG_SHORT_TERM_RETENTION
 *  @param i_iCondition      the condition of audit log, can be one of:
 *                           #KMS_AUDIT_LOG_SUCCESS_CONDITION
 *                           #KMS_AUDIT_LOG_ERROR_CONDITION
 *                           #KMS_AUDIT_LOG_WARNING_CONDITION
 *  @param i_bIssueAlert     issue alert (SNMP INFORM) for this audit
 *  @param i_pMessage        the message text to be logged
 *
 *  @return #KMS_AGENT_STATUS_OK
 *  @return #KMS_AGENT_STATUS_INVALID_PARAMETER
 *  @return #KMS_AGENT_STATUS_PROFILE_NOT_LOADED
 *  @return #KMS_AGENT_STATUS_GENERIC_ERROR
 *  @return #KMS_AGENT_STATUS_ACCESS_DENIED
 *  @return #KMS_AGENT_STATUS_SERVER_BUSY
 *  @return #KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  @return #KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE
 */
KMS_AGENT_STATUS KMSAgent_CreateAuditLog(
                        KMSClientProfile*            i_pProfile,
                        enum KMS_AUDIT_LOG_RETENTION i_iRetention,
                        enum KMS_AUDIT_LOG_CONDITION i_iCondition,
                        int                          i_bIssueAlert,
                        utf8cstr                     i_pMessage );


#ifdef KMSUSERPKCS12
#include <sys/types.h>
KMS_AGENT_STATUS KMSAgent_ChangeLocalPWD(
	KMSClientProfile* i_pProfile,
	utf8cstr const i_pOldPassphrase,
	utf8cstr const i_pNewPassphrase);

#define	KMSAGENT_PROFILE_FLAGS	uint32_t

KMS_AGENT_STATUS
KMSAgent_GetProfileStatus(
	char *i_pProfileName,
	KMSAGENT_PROFILE_FLAGS *flags);


#define	KMSAGENT_PROFILE_EXISTS_FLAG	0x01
#define	KMSAGENT_CLIENTKEY_EXISTS_FLAG	0x02
#endif /* KMSUSERPKCS12 */

#ifdef __cplusplus
}
#endif

#endif
