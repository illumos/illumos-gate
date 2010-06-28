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
 * \file KMSAgentLoadBalancer.cpp
 */

#ifdef WIN32
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <process.h>
#endif

#include <stdlib.h>

#include "KMS_AgentH.h"
#include "KMSClientProfile.h"
#include "KMSAgentSoapUtilities.h"
#include "KMSAgentStringUtilities.h"
#include "KMSClientProfileImpl.h"
#include "KMSAgent.h"
#include "KMSAuditLogger.h"
#include "ApplianceParameters.h"
#include "KMSAgentCryptoUtilities.h"

#ifdef METAWARE
#include "debug.h"
#include "sizet.h"
typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long	uint64_t;
#endif
#include "KMSAgentAESKeyWrap.h"

#ifdef METAWARE
#include "stdsoap2.h" /* makes fewer platform assumptions 
                          than the standard stdsoap2.h */

int time (char *);
#include "literals.h"
#else
#include "stdsoap2.h"
#endif

#include "AutoMutex.h"

// real declaration of soap *
#include "KMSAgentDataUnitCache.h"

#include "ClientSoapFaultCodes.h"
#include "KMSAgentPKICommon.h"
#include "KMSAgentLoadBalancer.h" // needs to be after stdsoap2.h to use the

CAgentLoadBalancer::CAgentLoadBalancer (KMSClientProfile * const i_pProfile)
: m_pProfile (i_pProfile),
m_iTransactionStartTimeInMilliseconds (0),
m_bFIPS (false),
m_iKWKEntryNum (0),
m_iLastAttemptedWhenNoneResponding (0)
{
    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) m_pProfile->m_pLock);

    // initialize the aCluster, let it contain the default appliance
    m_iClusterNum = 1;
    memset(&(m_aCluster[0]), 0, sizeof (KMSClusterEntry));
    strncpy(m_aCluster[0].m_wsApplianceNetworkAddress,
            i_pProfile->m_wsApplianceAddress,
            sizeof(m_aCluster[0].m_wsApplianceNetworkAddress));
    m_aCluster[0].m_wsApplianceNetworkAddress[sizeof(m_aCluster[0].m_wsApplianceNetworkAddress)-1] = '\0';

    // This may not be known because the initial 
    // appliance's Alias is not yet entered.
    strcpy(m_aCluster[0].m_wsApplianceAlias, "");
    strcpy(m_sURL, "");
    memset(m_aKWKEntries, 0, KMS_MAX_CLUSTER_NUM * sizeof(struct KWKEntry *));
}

CAgentLoadBalancer::~CAgentLoadBalancer ()
{
    // free up KWK entries
    for( int i=0; i < m_iKWKEntryNum && i < KMS_MAX_CLUSTER_NUM; i++)
    {
        if (m_aKWKEntries[i] != NULL)
        {
            delete m_aKWKEntries[i];
        }
    }
    return;
}

char *CAgentLoadBalancer::GetHTTPSURL (int i_iIndex, int i_iPort)
{
    if (i_iIndex < 0 || i_iIndex >= m_iClusterNum)
    {
        strcpy(m_sURL, "");
    }
    else
    {
        K_snprintf(m_sURL, KMS_MAX_URL, "https://%s:%d",
                m_aCluster[i_iIndex].m_wsApplianceNetworkAddress,
                i_iPort);
    }

    return m_sURL;
}

char *CAgentLoadBalancer::GetHTTPURL (int i_iIndex, int i_iPort)
{
    if (i_iIndex < 0 || i_iIndex >= m_iClusterNum)
    {
        strcpy(m_sURL, "");
    }
    else
    {
        K_snprintf(m_sURL, KMS_MAX_URL, "http://%s:%d",
                m_aCluster[i_iIndex].m_wsApplianceNetworkAddress,
                i_iPort);
    }

    return m_sURL;
}

int CAgentLoadBalancer::Balance ()
{
    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) m_pProfile->m_pLock);

    int i;
    unsigned int iSelected = 0;
    unsigned int iSelected2 = 0;

    // clear the failover attempts
    m_pProfile->m_iFailoverAttempts = 0;

    // This assumes Balance()/BalanceBy...() are called at the top of
    // each Agent Library transaction
    // m_iTransactionStartTimeInMilliseconds is used to determine if
    // enough time remains
    // (vs. KMSClientProfile::m_iTransactionTimeout) to retry a
    // request if there was a Server Busy error.

    m_iTransactionStartTimeInMilliseconds = K_GetTickCount();

    // if not enabling load balancing, return the default appliance & if
    // its FIPS compatible when running in FIPS_MODE

    if (m_pProfile->m_iClusterDiscoveryFrequency == 0)
    {
        if (m_bFIPS && !FIPScompatibleKMA(m_aCluster[0].m_sKMAVersion))
        {
            return NO_FIPS_KMA_AVAILABLE;
        }
        return 0;
    }

    int iCurrentTime = K_GetTickCount() / 1000;

    // if it is the first time or time to get cluster information
    if ((!m_pProfile->m_bIsClusterDiscoveryCalled) ||
        ((iCurrentTime - m_pProfile->m_iLastClusterDiscoveryTime) >
        m_pProfile->m_iClusterDiscoveryFrequency))
    {
        if (!KMSClient_GetClusterInformation(m_pProfile,
            m_pProfile->m_wsEntitySiteID,
            sizeof (m_pProfile->m_wsEntitySiteID),
            &(m_pProfile->m_iClusterNum),
            m_pProfile->m_aCluster,
            KMS_MAX_CLUSTER_NUM))
        {
            // if failed due to some error, return default one
            // KMSClient_GetClusterInformation logs

            return 0;
        }

        m_pProfile->m_bIsClusterDiscoveryCalled = true;

        // Reset the transaction start time to not include the time spent
        // calling KMSClient_GetClusterInformation.

        m_iTransactionStartTimeInMilliseconds = K_GetTickCount();

        // reset this index since cluster size may have changed
        m_iLastAttemptedWhenNoneResponding = 0;

        // TODO: Adjust timeouts to guarentee a response to the Agent
        // Library called in m_iTransactionTimeout seconds?  This means
        // not adjusting m_iTransactionStartTimeInMilliseconds, but also
        // reducing socket timeouts for subsequent calls.
    }

    // sort the cluster array by Load

    KMSClient_SortClusterArray(m_pProfile);

    // copy all Appliances to this object

    for (i = 0; i < m_pProfile->m_iClusterNum; i++)
    {
        m_aCluster[i] = m_pProfile->m_aCluster[i];
    }

    m_iClusterNum = m_pProfile->m_iClusterNum;

    int iCandidateAppliances = 0;

    // the initial set of candidates for load balancing are all enabled,
    // responding and unlocked KMAs (assumes they are at the top of the sort
    // order) & FIPS compatible if we're in that mode

    for (i = 0; i < m_iClusterNum; i++)
    {
        if ((m_aCluster[i].m_iResponding == TRUE) &&
            (m_aCluster[i].m_iEnabled == TRUE ) &&
			(m_aCluster[i].m_iKMALocked == FALSE))
        {
            iCandidateAppliances++;
        }
    }

    // check if there are any enabled and responding Appliances in the
    // same site as this Agent, and if so make those the candidates
    // (assumes they are at the top of the sort order)

    int iCandidateAppliancesInSameSite = 0;

    if (strlen(m_pProfile->m_wsEntitySiteID) > 0)
    {
        for (i = 0; i < iCandidateAppliances; i++)
        {
            if (strncmp(m_aCluster[i].m_wsApplianceSiteID,
                m_pProfile->m_wsEntitySiteID,
                sizeof(m_aCluster[i].m_wsApplianceSiteID)) == 0)
            {
                iCandidateAppliancesInSameSite++;
            }
        }
    }

    // reduce the candidate set to just KMAs within the site
    if (iCandidateAppliancesInSameSite > 0)
    {
        iCandidateAppliances = iCandidateAppliancesInSameSite;
    }

    // constrain the candidate set to just FIPS compatible KMAs
    if (m_bFIPS)
    {
        int iCandidateFIPSKMAs = 0;
        
        for (i = 0; i < iCandidateAppliances; i++)
        {
            if ( FIPScompatibleKMA(m_aCluster[i].m_sKMAVersion ))
            {
                iCandidateFIPSKMAs++;
            }
        }
        
        // select only from FIPS capable KMAs
        iCandidateAppliances = iCandidateFIPSKMAs;
    }
    
    // if there are no candidate Appliances, use the default Appliance unless
    // we're in FIPS mode

    if (!m_bFIPS && iCandidateAppliances <= 1)
    {
        return 0;
    }
    
    // FIPS mode
    else if (iCandidateAppliances <= 0)
    {
        return NO_FIPS_KMA_AVAILABLE;
    }
    else if (iCandidateAppliances == 1)
    {
        return 0;
    }

    // randomly select two candidate Appliances and select the one
    // with the smaller load

    // choose one random number between 0 -- iCandidateAppliances - 1
    iSelected = rand() % iCandidateAppliances;
    iSelected2 = (iSelected + 1) % iCandidateAppliances;

    // select the one with the smaller load

    if (m_aCluster[iSelected2].m_lLoad < m_aCluster[iSelected].m_lLoad)
    {
        iSelected = iSelected2;
    }

    return iSelected;
}

int CAgentLoadBalancer::BalanceByDataUnitID (
                                             const unsigned char * const i_pDataUnitID,
                                             int i_iDataUnitIDMaxLen)
{
    FATAL_ASSERT(i_pDataUnitID);

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) m_pProfile->m_pLock);

    // clear the failover attempts
    m_pProfile->m_iFailoverAttempts = 0;

    // This assumes Balance(), or BalanceBy...(),
    // is called at the top of each Agent Library transaction 
    // m_iTransactionStartTimeInMilliseconds is used to determine if enough time remains
    // (vs. KMSClientProfile::m_iTransactionTimeout) to retry a request if there was
    // a Server Busy error.

    m_iTransactionStartTimeInMilliseconds = K_GetTickCount();

    // look in cache

    CDataUnitCache *pDataUnitCache = (CDataUnitCache *) m_pProfile->m_pDataUnitCache;

    // if not enabling load balancing, return the default appliance & if
    // its FIPS compatible when running in FIPS_MODE

    if (m_pProfile->m_iClusterDiscoveryFrequency == 0)
    {
        if (m_bFIPS && !FIPScompatibleKMA(m_aCluster[0].m_sKMAVersion))
        {
            return NO_FIPS_KMA_AVAILABLE;
        }
        return 0;
    }

    // if the Data Unit ID is in the server affinity cache, use that Appliance

    utf8char wsApplianceNetworkAddress[KMS_MAX_NETWORK_ADDRESS];
    int iIndex = CLIENT_SIDE_ERROR;

    if (pDataUnitCache->GetApplianceByDataUnitID(
        i_pDataUnitID,
        i_iDataUnitIDMaxLen,
        wsApplianceNetworkAddress,
        sizeof(wsApplianceNetworkAddress)))
    {
        iIndex = FindIndexByNetworkAddress(wsApplianceNetworkAddress);
    }

    if (iIndex != CLIENT_SIDE_ERROR)
    {
        if (m_bFIPS && !FIPScompatibleKMA(m_aCluster[iIndex].m_sKMAVersion))
        {
            // in spite of caching we need to attempt an alternate KMA due
            // to the FIPS mode setting
            return Balance();
        }
        return iIndex;
    }

    // normal balancing
    return Balance();
}

int CAgentLoadBalancer::BalanceByDataUnitKeyID (
                                                const unsigned char * const i_pDataUnitKeyID,
                                                int i_iDataUnitKeyIDMaxLen)
{
    FATAL_ASSERT(i_pDataUnitKeyID);

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) m_pProfile->m_pLock);

    // clear the failover attempts
    m_pProfile->m_iFailoverAttempts = 0;

    // This assumes Balance()/BalanceBy...()
    // are called at the top of each Agent Library transaction 
    // m_iTransactionStartTimeInMilliseconds is used to determine if enough time remains
    // (vs. KMSClientProfile::m_iTransactionTimeout) to retry a request if there was
    // a Server Busy error.

    m_iTransactionStartTimeInMilliseconds = K_GetTickCount();

    // look in cache

    CDataUnitCache *pDataUnitCache = (CDataUnitCache *) m_pProfile->m_pDataUnitCache;

    // if not enabling load balancing, return the default appliance & if
    // its FIPS compatible when running in FIPS_MODE

    if (m_pProfile->m_iClusterDiscoveryFrequency == 0)
    {
        if (m_bFIPS && !FIPScompatibleKMA(m_aCluster[0].m_sKMAVersion))
        {
            return NO_FIPS_KMA_AVAILABLE;
        }
        return 0;
    }

    // if the Data Unit Key ID is in the server affinity cache, use that Appliance

    utf8char sApplianceNetworkAddress[KMS_MAX_NETWORK_ADDRESS];
    int iIndex = CLIENT_SIDE_ERROR;

    if (pDataUnitCache->GetApplianceByDataUnitKeyID(
        i_pDataUnitKeyID,
        i_iDataUnitKeyIDMaxLen,
        sApplianceNetworkAddress,
        sizeof(sApplianceNetworkAddress)))
    {
        iIndex = FindIndexByNetworkAddress(sApplianceNetworkAddress);
    }

    if (iIndex != CLIENT_SIDE_ERROR)
    {
        if (m_bFIPS && !FIPScompatibleKMA(m_aCluster[iIndex].m_sKMAVersion))
        {
            // in spite of caching we need to attempt an alternate KMA due
            // to the FIPS mode setting
            return Balance();
        }
        return iIndex;
    }

    // normal balancing
    return Balance();
}

int CAgentLoadBalancer::FindIndexByNetworkAddress
(char * i_wsApplianceNetworkAddress)
{
    FATAL_ASSERT(i_wsApplianceNetworkAddress);

    for (int i = 0; i < m_iClusterNum; i++)
    {

        if ((strncmp(m_aCluster[i].m_wsApplianceNetworkAddress,
            i_wsApplianceNetworkAddress,
            sizeof(m_aCluster[i].m_wsApplianceNetworkAddress)) == 0) &&
            m_aCluster[i].m_iEnabled == TRUE &&
            m_aCluster[i].m_iResponding == TRUE)
        {
            return i;
        }

    }

    return CLIENT_SIDE_ERROR;
}

char* CAgentLoadBalancer::GetApplianceNetworkAddress (int i_iIndex)
{
    if (i_iIndex < 0 || i_iIndex >= m_iClusterNum)
    {
        return (char *)"";
    }

    return m_aCluster[i_iIndex].m_wsApplianceNetworkAddress;
}

bool CAgentLoadBalancer::FailOverLimit (void)
{
    if (m_pProfile->m_iFailoverLimit >= 0 &&
        m_pProfile->m_iFailoverAttempts > m_pProfile->m_iFailoverLimit)
        return true;
    else
        return false;
}

int CAgentLoadBalancer::FailOver (int i_iFailedApplianceIndex,
                                  struct soap *i_pstSoap)
{
    FATAL_ASSERT(i_pstSoap);

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) m_pProfile->m_pLock);

    const char *strError = GET_SOAP_FAULTSTRING(i_pstSoap);
    int iSoapErrno = i_pstSoap->errnum;
    int iErrorCode = GET_FAULT_CODE(strError);
    int i;

    if ( m_bFIPS &&
        KMSClient_NoFIPSCompatibleKMAs(m_pProfile))
    {
        return NO_FIPS_KMA_AVAILABLE;
    }

    m_pProfile->m_iFailoverAttempts++;

    /*
     *  if KWK is not registered, or mismatched, most likely KMA lost its key due to a service
     *  restart.  Call RegisterKWK to re-register the KWK.
     *  If RegisterKWK  fails proceed from here with new failover info
     */
    if ( iErrorCode == CLIENT_ERROR_AGENT_KWK_NOT_REGISTERED ||
         iErrorCode == CLIENT_ERROR_AGENT_KWK_ID_MISMATCH )
    {
        LogError(m_pProfile,
                AGENT_LOADBALANCER_FAILOVER,
                NULL,
                m_aCluster[i_iFailedApplianceIndex].m_wsApplianceNetworkAddress,
                "KWK not registered or ID mismatch - registering");
        // delete the KWK entry since the KMA no longer has it
        DeleteKWKEntry( GetKMAID(i_iFailedApplianceIndex));
        
        return i_iFailedApplianceIndex;
    }

    bool bServerError = false;

    // if the request failed due to a Server Busy error, and if
    //  - transaction timeout has not been exceeded OR
    //  - failover attempts remain
    // then failover

    if (iErrorCode == CLIENT_ERROR_SERVER_BUSY &&
        (K_GetTickCount() < m_iTransactionStartTimeInMilliseconds + (m_pProfile->m_iTransactionTimeout * 1000) ||
        !CAgentLoadBalancer::FailOverLimit()))
    {
        LogError(m_pProfile,
                AGENT_LOADBALANCER_FAILOVER,
                NULL,
                m_aCluster[i_iFailedApplianceIndex].m_wsApplianceNetworkAddress,
                "Server Busy - failing over");
        bServerError = true;
    }
    else if (ServerError(strError,iSoapErrno))
    {
        bServerError = true;
    }
    else
    {
        if (i_iFailedApplianceIndex == AES_KEY_WRAP_SETUP_ERROR)
        {
            return AES_KEY_WRAP_SETUP_ERROR;
        }
        else
        {
            return CLIENT_SIDE_ERROR; // it is a client side problem, don't fail over
        }
    }

    // disable the failed Appliance in the profile, and
    // re-sort the cluster array, so transactions in other threads
    // will not send requests to the same failed Appliance
#if defined(METAWARE)
    log_cond_printf(ECPT_LOG_AGENT, "CAgentLoadBalancer::Failover(): FailoverAttempts=%d\n",
            m_pProfile->m_iFailoverAttempts);
#endif
    for (i = 0; i < m_pProfile->m_iClusterNum; i++)
    {
        if (m_pProfile->m_aCluster[i].m_lApplianceID ==
            m_aCluster[i_iFailedApplianceIndex].m_lApplianceID)
        {
            m_pProfile->m_aCluster[i].m_iResponding = FALSE;
            break;
        }
    }

    KMSClient_SortClusterArray(m_pProfile);

    // mark the failed Appliance as not responding (unlike the case
    // above which is conditional on bServerError, this marking is
    // only local to this transaction; it must be done to ensure that
    // this transaction does not cycle in its fail-over loop.)

    m_aCluster[i_iFailedApplianceIndex].m_iResponding = FALSE;

    if (!CAgentLoadBalancer::FailOverLimit())
    {
        // now try to fail over to all other Appliances that are
        // apparently enabled and responding 

        for (i = 0; i < m_iClusterNum; i++)
        {
            if (m_aCluster[i].m_iEnabled == TRUE &&
                m_aCluster[i].m_iResponding == TRUE &&
				m_aCluster[i].m_iKMALocked == FALSE)
            {
                Log(AGENT_LOADBALANCER_FAILOVER,
                        NULL,
                        m_aCluster[i].m_wsApplianceNetworkAddress,
                        "Failing over to this addr");

                return i;
            }
        }

        // now retry KMAs previously reported as not responding

        m_iLastAttemptedWhenNoneResponding++;

        if (m_iLastAttemptedWhenNoneResponding >= m_iClusterNum)
        {
            m_iLastAttemptedWhenNoneResponding = m_iLastAttemptedWhenNoneResponding % m_iClusterNum;
        }

        Log(AGENT_LOADBALANCER_FAILOVER,
                NULL,
                m_aCluster[m_iLastAttemptedWhenNoneResponding].m_wsApplianceNetworkAddress,
                "Failing over to retry this addr");

        return m_iLastAttemptedWhenNoneResponding;
    }
    else
    {
         Log(AGENT_LOADBALANCER_FAILOVER,
                NULL,
                NULL,
                "Failover limit reached");       
    }

    return m_bFIPS ? NO_FIPS_KMA_AVAILABLE : NO_KMA_AVAILABLE;
}

void CAgentLoadBalancer::UpdateResponseStatus(int i_iIndex)
{
    bool bStatusChanged = false;
    
    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) m_pProfile->m_pLock);

    // enable the responding Appliance in the profile, and
    // re-sort the cluster array, so transactions in other threads
    // will not send requests to the same failed Appliance

    for (int i = 0; i < m_pProfile->m_iClusterNum; i++)
    {
        if (m_pProfile->m_aCluster[i].m_lApplianceID ==
            m_aCluster[i_iIndex].m_lApplianceID)
        {
            if (m_pProfile->m_aCluster[i].m_iResponding == FALSE)
            {
                bStatusChanged = true;
            }
            m_pProfile->m_aCluster[i].m_iResponding = TRUE;
            break;
        }
    }

    // only resort if the responding status actually changed
    if (bStatusChanged)
    {
        KMSClient_SortClusterArray(m_pProfile);
    }

    // mark the Appliance as now responding
    m_aCluster[i_iIndex].m_iResponding = TRUE;

    return;
}

Long64 CAgentLoadBalancer::GetKMAID (
                                     int i_iIndex)
{
    if (i_iIndex < 0 || i_iIndex >= m_iClusterNum)
    {
        return -1;
    }

    return m_aCluster[i_iIndex].m_lApplianceID;
}

CAgentLoadBalancer::KWKEntry *CAgentLoadBalancer::GetKWK (
                                                          Long64 i_lKMAID)
{
    if (i_lKMAID == -1)
    {
        return NULL;
    }
    
    for (int i = 0; i < m_iKWKEntryNum && i < KMS_MAX_CLUSTER_NUM; i++)
    {
        if (m_aKWKEntries[i] != NULL &&
            m_aKWKEntries[i]->m_lKMAID == i_lKMAID )
        {
            return m_aKWKEntries[i];
        }
    }

    return NULL;
}

CAgentLoadBalancer::KWKEntry *CAgentLoadBalancer::CreateKWK (
                                         Long64 i_lKMAID,
                                         struct soap * const i_pstSoap,
                                         const char * const i_sURL,
                                         bool * const o_pbClientAESKeyWrapSetupError)
{
    FATAL_ASSERT(i_pstSoap);
    FATAL_ASSERT(i_sURL);

    int bSuccess = FALSE;
    KWKEntry *oKWKEntry = new KWKEntry;

    oKWKEntry->m_lKMAID = i_lKMAID;
    *o_pbClientAESKeyWrapSetupError = false;
    
    bSuccess = GetPseudorandomBytes(sizeof (oKWKEntry->m_acKWK),
            oKWKEntry->m_acKWK);
    if (!bSuccess)
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_KWK_RNG_ERROR,
                NULL,
                NULL,
                "Error from RNG");
        *o_pbClientAESKeyWrapSetupError = true;
        delete(oKWKEntry);
        return NULL;
    }

#if defined(DEBUG)
    char sHexKWK[2*KMS_MAX_KEY_SIZE+1];
    ConvertBinaryToUTF8HexString( sHexKWK, oKWKEntry->m_acKWK, sizeof (oKWKEntry->m_acKWK));
#if defined(METAWARE)
    log_printf("CAgentLoadBalancer::CreateKWK(): KWK hex=%s\n",
            sHexKWK);
#else
//    printf("CAgentLoadBalancer::CreateKWK(): KWK hex=%s\n",
//            sHexKWK);
#endif    
#endif
    
    CPublicKey oPublicKEK;

    bSuccess = GetKWKWrappingKey(i_pstSoap, i_sURL, &oPublicKEK);

    if (!bSuccess)
    {
        // GetKWKWrappingKey logs errors   
        
        if (!ServerError(GET_SOAP_FAULTSTRING(i_pstSoap),i_pstSoap->errnum))
        {
            *o_pbClientAESKeyWrapSetupError = true;
        }
        delete(oKWKEntry);
        return NULL;
    }

    unsigned char acWrappedKWK[MAX_RSA_PUB_KEY_LENGTH];
    int iWrappedKWKLength;
    bSuccess = oPublicKEK.Encrypt(sizeof (oKWKEntry->m_acKWK),
            oKWKEntry->m_acKWK, (unsigned char *) acWrappedKWK, &iWrappedKWKLength);

    if (!bSuccess)
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_KWK_PUBLIC_ENCRYPT_ERROR,
                NULL,
                NULL,
                "Error encrypting KWK with KMA public key");
        *o_pbClientAESKeyWrapSetupError = true;
        delete(oKWKEntry);
        return NULL;
    }
//#if defined(DEBUG) && !defined(METAWARE)
//    char sHexWrappedKWK[2*MAX_RSA_PUB_KEY_LENGTH+1];
//    ConvertBinaryToUTF8HexString( sHexWrappedKWK, acWrappedKWK, iWrappedKWKLength);
//    printf("CAgentLoadBalancer::CreateKWK(): wrapped KWK hex=%s\n",
//            sHexWrappedKWK);
//#endif

    // register the new KWK
    bSuccess = RegisterKWK(iWrappedKWKLength, acWrappedKWK, i_pstSoap,
            i_sURL, oKWKEntry->m_acKWKID);

    if (!bSuccess)
    {
        // RegisterKWK logs errors       
        if (!ServerError(GET_SOAP_FAULTSTRING(i_pstSoap), i_pstSoap->error))
        {
            *o_pbClientAESKeyWrapSetupError = true;
        }
        delete(oKWKEntry);
        return NULL;
    }

    // save the new KWK entry in an empty slot in the array
    for (int i=0; i < m_iKWKEntryNum && i < KMS_MAX_CLUSTER_NUM; i++)
    {
        if (m_aKWKEntries[i] == NULL)
        {
            m_aKWKEntries[i] = oKWKEntry; 
            return oKWKEntry;
        }
    }
    
    // no empty slots so add it to the end
    m_aKWKEntries[m_iKWKEntryNum++] = oKWKEntry;

    return oKWKEntry;
}

void CAgentLoadBalancer::DeleteKWKEntry(Long64 i_lKMAID)
{
    for (int i=0; i < m_iKWKEntryNum && i < KMS_MAX_CLUSTER_NUM; i++)
    {
        if (m_aKWKEntries[i] && m_aKWKEntries[i]->m_lKMAID == i_lKMAID)
        {
            delete(m_aKWKEntries[i]);
            m_aKWKEntries[i] = NULL;
            return;
        }
    }
    // should not occur
    FATAL_ASSERT(0);
    return;
}

bool CAgentLoadBalancer::AESKeyWrapSupported (int i_iIndex)
{
    if (i_iIndex < 0 || i_iIndex >= m_iClusterNum)
    {
        return false;
    }
    return (strcmp(m_aCluster[i_iIndex].m_sKMAVersion,
                    FIPS_COMPATIBLE_KMA_VERSION) >= 0);
}

int CAgentLoadBalancer::GetKWKID (
                                  int    i_Index,
                                  Long64 i_lKMAID,
                                  struct soap * const i_pstSoap,
                                  UTF8_KEYID o_pKWKID,
                                  bool * const o_pbClientAESKeyWrapSetupError)
{
    FATAL_ASSERT(i_Index >= 0 && i_Index <= m_iClusterNum);
    FATAL_ASSERT(i_lKMAID != 0);
    FATAL_ASSERT(i_pstSoap);
    FATAL_ASSERT(o_pKWKID);
    FATAL_ASSERT(o_pbClientAESKeyWrapSetupError);

    *o_pbClientAESKeyWrapSetupError = false;
    
    // check if the KMA for this cluster index is at a version supporting
    // AES key wrap
    if (!AESKeyWrapSupported(i_Index))
    {
        strcpy(o_pKWKID, "");
        return TRUE;
    }

    // AES Key Wrap Mode

    struct KWKEntry* pKWKentry = GetKWK(i_lKMAID);

    if (pKWKentry == NULL)
    {
        const char* sURL = GetHTTPSURL(
                i_Index,
                m_pProfile->m_iPortForAgentService);

        pKWKentry = CreateKWK(i_lKMAID, i_pstSoap, sURL, o_pbClientAESKeyWrapSetupError);

        if (pKWKentry == NULL)
        {
            return FALSE;
        }
    }

#if defined(DEBUG) && defined(METAWARE)
    log_printf("CAgentLoadBalancer::GetKWKID(): KWK IDhex=%s\n",
            pKWKentry->m_acKWKID,
            sizeof (UTF8_KEYID));
#endif
    
    strncpy(o_pKWKID, pKWKentry->m_acKWKID, sizeof(UTF8_KEYID));
    o_pKWKID[sizeof(UTF8_KEYID)-1] = '\0';

    return TRUE;
};

int CAgentLoadBalancer::GetKWKWrappingKey (
                                           struct soap * const i_pstSoap,
                                           const char * const i_sURL,
                                           CPublicKey * const  o_opPublicKEK)
{
    FATAL_ASSERT(i_pstSoap);
    FATAL_ASSERT(i_sURL);
    FATAL_ASSERT(o_opPublicKEK);

    int bSuccess = TRUE;
    struct KMS_Agent::KMS_Agent__GetAgentKWKPublicKeyResponse oResponse;
    char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];
    char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];

    bSuccess = KMS_Agent::soap_call_KMS_Agent__GetAgentKWKPublicKey(
            const_cast<struct soap *> (i_pstSoap),
            i_sURL,
            NULL,
            oResponse) == SOAP_OK;

    if (!bSuccess)
    {
        GetSoapFault(sSoapFaultMsg, const_cast<struct soap *> (i_pstSoap));
        GetPeerNetworkAddress(sKmaAddress, const_cast<struct soap *> (i_pstSoap));

        LogError(m_pProfile,
                AUDIT_CLIENT_GET_KWK_WRAPPING_KEY_SOAP_ERROR,
                NULL,
                sKmaAddress,
                sSoapFaultMsg);

        return FALSE;
    }

    // Validate the response structure
    if (bSuccess)
    {
        if (oResponse.KWKPublicKey.__ptr == NULL
            || oResponse.KWKPublicKey.__size < 1)
        {
            bSuccess = FALSE;

            GetPeerNetworkAddress(sKmaAddress, const_cast<struct soap *> (i_pstSoap));

            LogError(m_pProfile,
                    AUDIT_CLIENT_GET_KWK_WRAPPING_KEY_INVALID_KEY_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
        }
        else
        {
            bSuccess = o_opPublicKEK->Load(oResponse.KWKPublicKey.__ptr,
                    oResponse.KWKPublicKey.__size, PKI_FORMAT);
            if (!bSuccess)
            {
                GetPeerNetworkAddress(sKmaAddress, const_cast<struct soap *> (i_pstSoap));

                LogError(m_pProfile,
                        AUDIT_CLIENT_GET_KWK_WRAPPING_KEY_INVALID_RSA_PUB_KEY,
                        NULL,
                        sKmaAddress,
                        NULL);
            }
        }
    }

    // Note: no SOAP cleanup as caller's environment will get destroyed

    return bSuccess;
};

int CAgentLoadBalancer::RegisterKWK (
                                     int i_iWrappedKWKSize,
                                     const unsigned char * const i_acWrappedKWK,
                                     struct soap * const i_pstSoap,
                                     const char * const i_sURL,
                                     UTF8_KEYID o_acUTF8KeyID)
{
    FATAL_ASSERT(i_iWrappedKWKSize > 0);
    FATAL_ASSERT(i_acWrappedKWK);
    FATAL_ASSERT(i_pstSoap);
    FATAL_ASSERT(i_sURL);
    FATAL_ASSERT(o_acUTF8KeyID);

    int bSuccess;

    struct KMS_Agent::xsd__hexBinary oKWK;

#if defined(DEBUG) && defined(METAWARE)
    char sHexWrappedKWK[512];
    ConvertBinaryToUTF8HexString( sHexWrappedKWK, i_acWrappedKWK, i_iWrappedKWKSize);
    log_printf("CAgentLoadBalancer::RegisterKWK(): Wrapped KWK hex=%s, len=%d\n",
            sHexWrappedKWK, i_iWrappedKWKSize);
#endif
    
    if (!PutBinaryIntoSoapBinary(i_pstSoap,
        i_acWrappedKWK,
        i_iWrappedKWKSize,
        oKWK.__ptr,
        oKWK.__size))
    {
        return FALSE;
    }

    char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];
    char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
    struct KMS_Agent::KMS_Agent__RegisterAgentKWKResponse oResponse;

    bSuccess = KMS_Agent::soap_call_KMS_Agent__RegisterAgentKWK(
            const_cast<struct soap *> (i_pstSoap),
            i_sURL, NULL, oKWK, oResponse) == SOAP_OK;

    if (bSuccess)
    {
        // verify response
        if (oResponse.AgentKWKID &&
            strlen(oResponse.AgentKWKID) == 2 * KMS_KWK_KEY_ID_SIZE)
        {
#if defined(DEBUG) && defined(METAWARE)
            log_printf("CAgentLoadBalancer::RegisterKWK(): KWK ID hex=%s\n",
                    oResponse.AgentKWKID,
                    sizeof (UTF8_KEYID));
#endif
            strncpy(o_acUTF8KeyID, oResponse.AgentKWKID, sizeof(UTF8_KEYID));
            o_acUTF8KeyID[sizeof(UTF8_KEYID)-1] = '\0';
        }
        else
        {
            GetPeerNetworkAddress(sKmaAddress, const_cast<struct soap *> (i_pstSoap));
            GetSoapFault(sSoapFaultMsg, const_cast<struct soap *> (i_pstSoap));

            Log(AUDIT_CLIENT_AGENT_REGISTER_KWK_INVALID_KEYID_RESPONSE,
                    NULL,
                    sKmaAddress,
                    sSoapFaultMsg);
            bSuccess = FALSE;
        }
    }
    else
    {
        GetPeerNetworkAddress(sKmaAddress, const_cast<struct soap *> (i_pstSoap));
        GetSoapFault(sSoapFaultMsg, const_cast<struct soap *> (i_pstSoap));

        Log(AUDIT_CLIENT_AGENT_REGISTER_KWK_ERROR,
                NULL,
                sKmaAddress,
                sSoapFaultMsg);
        bSuccess = FALSE;
    }

    // Note: Clean up SOAP must happen in caller, not here

    return bSuccess;

};

bool CAgentLoadBalancer::AESKeyUnwrap (
                                       int * const io_pIndex,
                                       const WRAPPED_KEY i_pAESWrappedKey,
                                       KEY o_pPlainTextKey)
{
    FATAL_ASSERT(io_pIndex);
    FATAL_ASSERT(*io_pIndex >= 0);
    FATAL_ASSERT(o_pPlainTextKey);
    FATAL_ASSERT(i_pAESWrappedKey);

    struct KWKEntry * pKWKEntry = GetKWK(GetKMAID(*io_pIndex));

    if (pKWKEntry == NULL)
    {
        Log(AGENT_LOADBALANCER_AESKEYUNWRAP_GETKWK_RETURNED_NULL,
                NULL,
                m_aCluster[*io_pIndex].m_wsApplianceNetworkAddress,
                NULL);
        *io_pIndex = CAgentLoadBalancer::AES_KEY_UNWRAP_ERROR;
        
        return false;
    }

#if defined(DEBUG) && defined(METAWARE)
    char sHexKWK[2*KMS_MAX_KEY_SIZE+1];
    ConvertBinaryToUTF8HexString( sHexKWK, pKWKEntry->m_acKWK, sizeof (pKWKEntry->m_acKWK));
    log_printf("CAgentLoadBalancer::AESKeyUnwrap(): KWK hex=%s\n",
            sHexKWK);
#endif
    
    if (aes_key_unwrap(pKWKEntry->m_acKWK,
        sizeof (pKWKEntry->m_acKWK),
        i_pAESWrappedKey,
        o_pPlainTextKey, 4) != 0)
    {
        Log(AGENT_LOADBALANCER_AESKEYUNWRAP_KEY_UNWRAP_FAILED,
                NULL,
                m_aCluster[*io_pIndex].m_wsApplianceNetworkAddress,
                NULL);
        *io_pIndex = CAgentLoadBalancer::AES_KEY_UNWRAP_ERROR;
        return false;
    }

    return true;
}

/*---------------------------------------------------------------------------
 * Function: KMSClient_SortClusterArray
 *
 *--------------------------------------------------------------------------*/
void CAgentLoadBalancer::KMSClient_SortClusterArray (KMSClientProfile * const i_pProfile)
{
    FATAL_ASSERT(i_pProfile);

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    int i;


    // adjust loads according to availability, site and FIPS compatibility
    for (i = 0; i < i_pProfile->m_iClusterNum; i++)
    {
        if ((i_pProfile->m_aCluster[i].m_iEnabled == FALSE
            || i_pProfile->m_aCluster[i].m_iResponding == FALSE
			|| i_pProfile->m_aCluster[i].m_iKMALocked))
        {
            ((unsigned char*) &(i_pProfile->m_aCluster[i].m_lLoad))[sizeof (int)+1] = 1;
        }
        else
        {
            ((unsigned char*) &(i_pProfile->m_aCluster[i].m_lLoad))[sizeof (int)+1] = 0;
        }

        if (strcmp(i_pProfile->m_aCluster[i].m_wsApplianceSiteID,
            i_pProfile->m_wsEntitySiteID) != 0)
        {
            ((unsigned char*) &(i_pProfile->m_aCluster[i].m_lLoad))[sizeof (int)] = 1;
        }
        else
        {
            ((unsigned char*) &(i_pProfile->m_aCluster[i].m_lLoad))[sizeof (int)] = 0;
        }
        
        if ( m_bFIPS && 
                !FIPScompatibleKMA(i_pProfile->m_aCluster[i].m_sKMAVersion))
        {
            ((unsigned char*) &(i_pProfile->m_aCluster[i].m_lLoad))[sizeof (int)+2] = 1;
        }
        else
        {
            ((unsigned char*) &(i_pProfile->m_aCluster[i].m_lLoad))[sizeof (int)+2] = 0;
        }
    }

    // sort ascending by load

    // gnome sort: the simplest sort algoritm
    // http://www.cs.vu.nl/~dick/gnomesort.html

    //void gnomesort(int n, int ar[]) {
    //    int i = 0;
    //
    //    while (i < n) {
    //        if (i == 0 || ar[i-1] <= ar[i]) i++;
    //        else {int tmp = ar[i]; ar[i] = ar[i-1]; ar[--i] = tmp;}
    //    }
    //}    

    i = 0;
    while (i < i_pProfile->m_iClusterNum)
    {
        if (i == 0 || i_pProfile->m_aCluster[i - 1].m_lLoad <= i_pProfile->m_aCluster[i].m_lLoad)
        {
            i++;
        }
        else
        {
            KMSClusterEntry tmp = i_pProfile->m_aCluster[i];
            i_pProfile->m_aCluster[i] = i_pProfile->m_aCluster[i - 1];
            i_pProfile->m_aCluster[--i] = tmp;
        }
    }
}
