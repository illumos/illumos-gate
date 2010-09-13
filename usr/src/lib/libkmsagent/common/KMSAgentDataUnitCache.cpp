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
 * \file KMSAgentDataUnitCache.cpp
 */

#include <stdio.h>
#include "SYSCommon.h"
#include "KMSClientProfile.h"
#include "KMSAgentDataUnitCache.h"

CDataUnitCache::CDataUnitCache(int i_iMaxSize)
{
    m_iSize = 0;
    m_iIndex = 0;
    m_iMaxSize = i_iMaxSize;
    m_pCache = 0;

    K_CreateMutex(&m_Lock);
}

CDataUnitCache::~CDataUnitCache()
{
    delete[] m_pCache;
    K_DestroyMutex(m_Lock);
}

bool CDataUnitCache::Insert(
                const unsigned char* const i_pDataUnitID,
                int i_iDataUnitIDMaxLen, 
                const unsigned char* const i_pDataUnitKeyID ,
                int i_iDataUnitKeyIDMaxLen,
                const utf8char* const i_wsApplianceNetworkAddress )
{
    FATAL_ASSERT( (i_pDataUnitID && i_iDataUnitIDMaxLen == KMS_DATA_UNIT_ID_SIZE) ||
                  (i_pDataUnitKeyID && i_iDataUnitKeyIDMaxLen == KMS_KEY_ID_SIZE));
    FATAL_ASSERT( i_wsApplianceNetworkAddress && 
                  strlen( i_wsApplianceNetworkAddress ) < KMS_MAX_NETWORK_ADDRESS );

    Lock();

    if ( m_pCache == 0 )
    {
        m_pCache = new DataUnitCacheEntry[m_iMaxSize];

        if ( !m_pCache )
        {
            // no error logged on out of memory
            Unlock();
#if defined(DEBUG) && defined(METAWARE)
            log_printf("CDataUnitCache::Insert new DataUnitCacheEntry alloc failure\n");
#endif
            return false;
        }
    }

    if( m_iSize >= m_iMaxSize )
    {
        // the cache is full, so reuse an old slot

        m_iIndex  = (m_iIndex + 1) % m_iMaxSize;
    }
    else
    {
        m_iIndex = m_iSize;

        m_iSize++;
    }

    strncpy( m_pCache[m_iIndex].m_wsApplianceNetworkAddress, 
             i_wsApplianceNetworkAddress, 
             sizeof(m_pCache[m_iIndex].m_wsApplianceNetworkAddress) );
    m_pCache[m_iIndex].m_wsApplianceNetworkAddress[sizeof(m_pCache[m_iIndex].m_wsApplianceNetworkAddress)-1] = '\0';

    if ( i_pDataUnitID )
    {
        memcpy( m_pCache[m_iIndex].m_aDataUnitID, 
                i_pDataUnitID, 
                i_iDataUnitIDMaxLen );
    }
    else
    {
        memset( m_pCache[m_iIndex].m_aDataUnitID,0,KMS_DATA_UNIT_ID_SIZE);
    }

    if ( i_pDataUnitKeyID )
    {
        memcpy( m_pCache[m_iIndex].m_aDataUnitKeyID, 
            i_pDataUnitKeyID, 
            i_iDataUnitKeyIDMaxLen );
    }
    else
    {
        memset(m_pCache[m_iIndex].m_aDataUnitKeyID,0,KMS_KEY_ID_SIZE);
    }

    Unlock();

    return true;
}

bool CDataUnitCache::GetApplianceByDataUnitID(
                const unsigned char* const i_pDataUnitID,
                int i_iDataUnitIDMaxLen,
                utf8char* const o_wsApplianceNetworkAddress,
                int i_iMaxApplianceNetworkAddressLen )
{
    FATAL_ASSERT( i_pDataUnitID );
    FATAL_ASSERT( i_iDataUnitIDMaxLen == KMS_DATA_UNIT_ID_SIZE );
    FATAL_ASSERT( i_iMaxApplianceNetworkAddressLen <= KMS_MAX_NETWORK_ADDRESS );

    // assumes o_wsApplianceNetworkAddress points to at least KMS_MAX_NETWORK_ADDRESS

    Lock();

    int i;
    for( i = 0; i < m_iSize; i++ )
    {
        if( memcmp(m_pCache[i].m_aDataUnitID, i_pDataUnitID, KMS_DATA_UNIT_ID_SIZE) == 0 )
        {
            strncpy( o_wsApplianceNetworkAddress, 
                m_pCache[i].m_wsApplianceNetworkAddress, 
                i_iMaxApplianceNetworkAddressLen );
            o_wsApplianceNetworkAddress[i_iMaxApplianceNetworkAddressLen-1] = '\0';
            Unlock();
            return true;
        }
    }

    Unlock();

    return false;
}

bool CDataUnitCache::GetApplianceByDataUnitKeyID(
                const unsigned char* const i_pDataUnitKeyID,
                int i_iDataUnitKeyIDMaxLen,
                utf8char* const o_wsApplianceNetworkAddress,
                int i_iMaxApplianceNetworkAddressLen )
{
    FATAL_ASSERT( i_pDataUnitKeyID );
    FATAL_ASSERT( i_iDataUnitKeyIDMaxLen == KMS_KEY_ID_SIZE );
    FATAL_ASSERT( i_iMaxApplianceNetworkAddressLen <= KMS_MAX_NETWORK_ADDRESS );

    // assumes o_wsApplianceNetworkAddress points to at least KMS_MAX_NETWORK_ADDRESS

    Lock();

    int i;
    for( i = 0; i < m_iSize; i++ )
    {
        if( memcmp(m_pCache[i].m_aDataUnitKeyID,
                i_pDataUnitKeyID, KMS_KEY_ID_SIZE) == 0 )
        {
            strncpy( o_wsApplianceNetworkAddress, 
                m_pCache[i].m_wsApplianceNetworkAddress, 
                i_iMaxApplianceNetworkAddressLen );
            o_wsApplianceNetworkAddress[i_iMaxApplianceNetworkAddressLen-1] = '\0';

            Unlock();

            return true;
        }
    }

    Unlock();

    return false;
}

void CDataUnitCache::Lock()
{
    K_LockMutex(m_Lock);
}

void CDataUnitCache::Unlock()
{
    K_UnlockMutex(m_Lock);
}
