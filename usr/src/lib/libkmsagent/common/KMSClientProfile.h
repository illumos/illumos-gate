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

/*-------------------------------------------------------------------------*/
/**
 * \file      KMSClientProfile.h
 *
 * The KMS Client profile management API, including profile setup, CA
 * certificate download, and Certificate retrieval
 *
 */
/*-------------------------------------------------------------------------*/

#ifndef KMSCLIENT_PROFILE_H
#define KMSCLIENT_PROFILE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef KMS_LONG_LONG
#define KMS_LONG_LONG

#ifdef WIN32
  typedef __int64 Long64;
#else
  typedef long long Long64;
#endif

   
#endif
   
#ifdef KMSUSERPKCS12
#define	CLIENT_PK12_FILE	"clientkey.p12"
#endif

/**
 *  \note UTF-8 encoding is used for the underlying SOAP RPC transactions by
 *  this API. In order to support environments lacking wchar.h
 *  traditional C strings are used instead.
 */ 
typedef char * utf8cstr;

/**
 *  @see commments for utf8cstr.
 */
typedef char utf8char;

/**
 *  KMS Agent Toolkit Version identifier
 */
#define KMS_AGENT_VERSION 0x210

/*---------------------------------------------------------------------------
 * Limits and sizes
 *--------------------------------------------------------------------------*/
/**
 *   The maximum length of an agent name.
 */
#define KMS_MAX_AGENT_NAME                                                  64

/**
 *  The size of a data unit ID in bytes.
 */
#define KMS_DATA_UNIT_ID_SIZE                                               16

/**
 *  The maximum lenght of a description for key group or data unit.
 */
#define KMS_MAX_DESCRIPTION                                                 64

/**
 *  The maximum maximum length of an external unique id.
 */
#define KMS_MAX_EXTERNAL_UNIQUE_ID_SIZE                                     32

/**
 *  The maximum external tag length.
 */
#define KMS_MAX_EXTERNAL_TAG                                                64

/**
 *  The size of a key ID in bytes.
 */
#define KMS_KEY_ID_SIZE                                                     30

/**
 *  The size of an AES Key Wrapping Key ID.
 */
#define KMS_KWK_KEY_ID_SIZE                                                 8

/**
 *  The maximum size of a key in bytes.
 */
#define KMS_MAX_KEY_SIZE                                                    32

/**
 *  The maximum size of an wrapped key(RFC3394 AES Key Wrap) in bytes.
 */
#define KMS_MAX_WRAPPED_KEY_SIZE                                   KMS_MAX_KEY_SIZE+8 

/**
 *  The maximum length of a key group ID.
 */
#define KMS_MAX_KEY_GROUP_ID_SIZE                                           64

/**
 *  The maximum size of a key group list to be returned.  This should
 *  be sufficient for agents as this is an atypical call.
 */
#define KMS_MAX_LIST_KEY_GROUPS                                             100

/**
 * The maximum number of keys returned in a key list.
 */
#define KMS_MAX_PAGE_SIZE                                                   32

/**
 *  The maximum passphrase length.
 */
#define KMS_MAX_PASSPHRASE                                                  64

/**
 *  The maximum length of agent's name, aka ID.
 */
#define KMS_MAX_ENTITY_ID                           64

/**
 *  The maximum length of an agent's sited ID.
 */
#define KMS_MAX_ENTITY_SITE_ID                      64

/**
 *  The maximum length of a URL.
 */
#define KMS_MAX_URL                                 512

/** 
 *  The maximum length of a filter parameter field name.
 */
#define KMS_MAX_FIELD_NAME                          64

/**
 *  The maximum length of a query parameter sort field value.
 */
#define KMS_MAX_FIELD_VALUE                         64

/**
 *  The maximum ID length used in various types of IDs.
 */
#define KMS_MAX_ID                                  64

/**
 *  The maximum length of a KMA network address, either IPv4 or IPv6.
 *  Also maximum hostname length if/when hostnames are supported
 */
#define KMS_MAX_NETWORK_ADDRESS                     256

/**
 *  The maximum length of a file name.
 */
#define KMS_MAX_FILE_NAME                           256

/**
 *  The maximum length of error strings.
 */
#define KMS_MAX_ERROR_STRING                        1024

/**
 *  the number of nodes in a KMS is variable.  This constant
 * dictates how many of the KMAs in a KMS will be saved to the
 * profile, persisted to storage and used for load balancing and failover.  See
 * <code>KMSAgent_GetClusterInformation</code>
 * Range: 1 .. max int, users should con
 */
#ifndef KMS_MAX_CLUSTER_NUM
#define KMS_MAX_CLUSTER_NUM                         20
#endif

/**
 *  The maximum length for SHA1 hashes used in authentication.
 */
#define KMS_MAX_HASH_SIZE                           20

/**
 *  The maximum length of a KMS verstion string.
 */
#define KMS_MAX_VERSION_LENGTH                      100

/**
 *  The maximum length of working directory.
 */
#define KMS_MAX_PATH_LENGTH                         1024

/**
 *  typedef for Key ID
 */
typedef unsigned char KEY_ID [KMS_KEY_ID_SIZE];

/**
 *  typedef for an unwrapped Key
 */
typedef unsigned char KEY [KMS_MAX_KEY_SIZE];

/**
 *  typedef for an AES wrapped key
 */
typedef unsigned char WRAPPED_KEY [KMS_MAX_WRAPPED_KEY_SIZE];

/**
 *  typedef for KMSClusterEntry struct
 */
typedef struct KMSClusterEntry KMSClusterEntry;

/** \struct KMSClusterEntry
 *  A struct representing each Key Management Appliance discovered in the KMS cluster 
 */
struct KMSClusterEntry
{
    /**
     *   The KMA's identifier.
     */
    Long64      m_lApplianceID;
    
    /**
     *   The KMA's name.
     */
    utf8char    m_wsApplianceAlias[KMS_MAX_ENTITY_ID + 1];
    
    /**
     *  The Sited ID for the KMA.
     */
    utf8char    m_wsApplianceSiteID[KMS_MAX_ENTITY_SITE_ID + 1];
    
    /**
     *  A network address for the KMA that corresponds to the agent's network.
     *  KMAs are multi-homed so only an address useful to the agent is provided.
     */
    utf8char    m_wsApplianceNetworkAddress[KMS_MAX_NETWORK_ADDRESS + 1];
    
    /**
     *  Enabled status for the KMA, 1 for enabled, 0 if disabled.
     */
    int         m_iEnabled;
    
    /**
     *   Unused at present but may be used for reporting a KMAs load to be used
     *   as a load balancing heuristic.
     */
    Long64      m_lLoad;
    
    /**
     *  A boolean indicating the current response status of a KMA on the network.
     *  A non-responding KMA may be either down or unreachable due to the network.
     */
    int         m_iResponding;
    
    /**
     *  The KMA's version level.
     */
    utf8char    m_sKMAVersion[KMS_MAX_VERSION_LENGTH+1];
    
    /**
     *  KMA lock status as provided by KMS Discover Cluster service. Defaults
     *  to false for KMAs earlier than KMS 2.3 where it was first introduced.
     */
    int m_iKMALocked;
};


/**
 * the profile for an agent.  The profile contains sections that are persisted
 * and fields that are volatile.  See KMSAgentStorage.h for interfaces to load/store
 * the persistent sections.
 * <p><b>Note</b> that members of this struct should
 * not be accessed directly by users of this library.
 */

/** \struct KMSClientProfile
 *   the properties comprising the profile, some of which must be persisted. 
 */
typedef struct KMSClientProfile_s
{
    /**
     *  the version of the KMS Agent Library
     */ 
    int m_iVersion;

    /**
    * Profile Name
    */
    utf8char m_wsProfileName[KMS_MAX_ENTITY_ID + 1];

    /**
     *  Subject Name
     */
    utf8char m_wsEntityID[KMS_MAX_ENTITY_ID + 1];

    /**
     * Appliance Address used for enrollment and discovery
     */
    utf8char m_wsApplianceAddress[KMS_MAX_NETWORK_ADDRESS + 1]; 

    /**
     *  KMS CA service port
     */
    int m_iPortForCAService;
    /**
     *  KMS Certificate service port
     */
    int m_iPortForCertificateService;
    
    /**
     *  KMS Agent service port
     */
    int m_iPortForAgentService;
    
    /**
     *  KMS Discovery service port
     */
    int m_iPortForDiscoveryService;

    /**
     *  timeout in seconds before failover to alternate KMS in cluster
     */
    int m_iTransactionTimeout; 

    /**
     *  the number of times failover will be attempted
     */
    int m_iFailoverLimit;

    /**
     *  the number of times the current transaction has failed over
     */
    int m_iFailoverAttempts;

    /**
     *  TRUE when agent has enrolled and stored its certificates.
     */
    int m_iEnrolled;

    /**
     *  The agent's passphrase after "key stretching", i.e. hashing the number of
     *  times specified by the KMA during enrollment, and converted to hexadecimal.
     */
    char m_sHexHashedPassphrase[2*KMS_MAX_HASH_SIZE+1];
    
    /**
     *  gSOAP runtime context.
     */
    void *m_pvSoap; 

    /**
     * gSOAP runtime context for discovery.
     */
    void *m_pvDiscoverySoap; 

    /**
     *  A lock used internally by the agent library.
     */
    void *m_pLock;

    /**  
     *  The minimum interval between automatic cluster discovery requests in seconds.
     *  A value of zero seconds disables load balancing and periodic cluster
     *  discovery calls.  
     */
    int m_iClusterDiscoveryFrequency;
    
    /**
     *  The time in seconds when the cluster discovery service was last called for the
     *  current session.
     */
    int m_iLastClusterDiscoveryTime;

    /**
     *  The Site ID assigned to the agent by the KMS administrators.
     */
    utf8char m_wsEntitySiteID[KMS_MAX_ENTITY_SITE_ID + 1];

    /** 
     *  The total number of KMA in the KMS cluster as reported by the last
     *  cluster discovery.
     */
    int m_iClusterNum;

    /**
     *  An array of the KMAs withhin the cluster.
     */
    KMSClusterEntry m_aCluster[KMS_MAX_CLUSTER_NUM];

    /**
     *  A boolean flag for the first cluster discovery call.
     */
    int m_bIsClusterDiscoveryCalled;

    /**
     *  A handle to the DataUnitCache used for selection of a KMA.
     */
    void *m_pDataUnitCache;

    /**
     *  A handle to the load balancer.
     */
    void *m_pAgentLoadBalancer;

    /**
     *  error string
     */
    utf8char m_wsErrorString[KMS_MAX_ERROR_STRING + 1];

    /**
     *  URL to KMA service within cluster
     */
    char m_sURL[KMS_MAX_URL + 1];
    
    /** 
     *  The security mode specified to <code>KMSAgent_LoadProfile</code>
     */
    int m_eKMSmode;

#ifdef KMSUSERPKCS12
    int m_iLastErrorCode;
#endif
} KMSClientProfile;

#ifdef __cplusplus
}
#endif


#endif 

