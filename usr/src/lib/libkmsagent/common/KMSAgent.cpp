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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/**
 * \file KMSAgent.cpp
 */

#ifdef WIN32
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <process.h>
#endif

#include <stdlib.h>

#include "KMSClientProfile.h"

#include "KMS_AgentStub.h"
#include "KMS_DiscoveryStub.h"

#include "KMSClientProfileImpl.h"
#include "KMSAgent.h"
#include "KMSAuditLogger.h"
#include "KMSAgentSoapUtilities.h"
#include "KMSAgentStringUtilities.h"
#include "KMSAgentPKICommon.h"
#include "KMSAgentLoadBalancer.h"

#include "KMSAgentWebServiceNamespaces.h"
#include "k_setupssl.h"

#include "ApplianceParameters.h"

#include "AutoMutex.h"
#include "KMSAgentKeyCallout.h"

#include "KMSAgentLoadBalancer.h"
#include "KMSAgentDataUnitCache.h"

#ifdef K_SOLARIS_PLATFORM
#include "KMSAgentStorage.h"
#endif

#include "ClientSoapFaultCodes.h"

#ifdef METAWARE
#include "debug.h"
#include "sizet.h"
typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long	uint64_t;
#endif

#include "KMSAgentAESKeyWrap.h"
#include "KMSAgentKnownAnswerTests.h"

#if defined(METAWARE) && defined(DEBUG_RETURNS)
extern "C" void ecpt_trace_msg (ECPT_TRACE_ENTRY*, char*, ...);

#define RETURN(a) { ecpt_trace_msg( trace,"(returned=%x)",(a));  return(a);  }

#else
#define RETURN(a) return(a)
#endif

/* KMS_AGENT_VERSION_STRING  gets passed in via compilation flags */
extern "C" const char KMSAgent_Version[KMS_MAX_VERSION_LENGTH + 1] = KMS_AGENT_VERSION_STRING;


/* The following enum and structs are used for QueryParameters in
 * ListKeyGroup. Since they are only used in implementation code,
 * so they are not in the header file in order to hide these details
 */


/*---------------------------Start Query Parameters Declartion -------- */

#define KMS_MAX_AGENT_FILTER_PARAMETERS     10

enum KMSAgent_SortOrder
{
    SORT_ORDER_ASCENDING = 0,
    SORT_ORDER_DESCENDING
};

enum KMSAgent_FilterOperator
{
    FILTER_OPERATOR_EQUAL = 0,
    FILTER_OPERATOR_NOT_EQUAL,
    FILTER_OPERATOR_GREATER_THAN,
    FILTER_OPERATOR_LESS_THAN,
    FILTER_OPERATOR_GREATER_THAN_OR_EQUAL,
    FILTER_OPERATOR_LESS_THAN_OR_EQUAL,
    FILTER_OPERATOR_STARTS_WITH
};

struct KMSAgent_FilterParameters
{
    utf8char m_wsFieldName[KMS_MAX_FIELD_NAME + 1];
    enum KMSAgent_FilterOperator m_eFilterOperator;
    utf8char m_wsFieldValue[KMS_MAX_FIELD_VALUE + 1];
};

struct KMSAgent_QueryParameters
{
    utf8char m_wsSortFieldName[KMS_MAX_FIELD_NAME + 1];
    enum KMSAgent_SortOrder m_eSortOrder;

    struct KMSAgent_FilterParameters m_aFilterParameters[KMS_MAX_AGENT_FILTER_PARAMETERS];
    int m_iSizeFilterParameters;

    utf8char m_wsPreviousPageLastIDValue[KMS_MAX_ID + 1];
    utf8char m_wsPreviousPageLastSortFieldValue[KMS_MAX_FIELD_VALUE + 1];
};

/*---------------------------End Of Query Parameters Declaration -------- */

#ifdef METAWARE
int CAgentLoadBalancer::FailOver (int i_iFailedApplianceIndex,
                                  struct soap *i_pstSoap);
#endif

extern const char * KMSAgent_GetVersion ()
{
    return (KMSAgent_Version);
}

static bool CopyQueryParametersFromRequest
(
 struct soap *i_pstSoap,
 int i_iPageSize,
 struct KMS_Agent::KMS_Agent__QueryParameters *i_pQueryParameters,
 struct KMSAgent_QueryParameters *i_pSourceQueryParameters
 )
{

    // set page size
    i_pQueryParameters->NextPageSize = i_iPageSize;

    // copy sort field name
    i_pQueryParameters->SortFieldName = (char *)
            soap_malloc(i_pstSoap,
            sizeof (i_pSourceQueryParameters->m_wsSortFieldName));
    if (i_pQueryParameters->SortFieldName == NULL)
    {
        return (false);
    }
    strncpy(i_pQueryParameters->SortFieldName,
            i_pSourceQueryParameters->m_wsSortFieldName,
            sizeof (i_pSourceQueryParameters->m_wsSortFieldName));
    i_pQueryParameters->SortFieldName[sizeof (i_pSourceQueryParameters->m_wsSortFieldName)-1] = 0;

    // sort order
    i_pQueryParameters->SortOrder =
            (enum KMS_Agent::KMS_Agent__SortOrder)i_pSourceQueryParameters->m_eSortOrder;

    // copy filter parameters
    i_pQueryParameters->FilterParameters.__size =
            i_pSourceQueryParameters->m_iSizeFilterParameters;

    if (i_pQueryParameters->FilterParameters.__size > 0)
    {
        i_pQueryParameters->
                FilterParameters.__ptr =
                (struct KMS_Agent::KMS_Agent__FilterParameters *)soap_malloc
                (i_pstSoap,
                sizeof (KMS_Agent::KMS_Agent__FilterParameters) *
                i_pQueryParameters->FilterParameters.__size);

        if (i_pQueryParameters->FilterParameters.__ptr == NULL)
        {
            return (false);
        }
    }
    else
    {
        i_pQueryParameters->FilterParameters.__ptr = NULL;
    }

    for (int i = 0; i < i_pSourceQueryParameters->m_iSizeFilterParameters; i++)
    {
        struct KMS_Agent::KMS_Agent__FilterParameters *pParameters;

        pParameters = &(i_pQueryParameters->FilterParameters.__ptr[i]);

        // copy field name
        pParameters->FieldName = (
                utf8cstr) soap_malloc(i_pstSoap,
                sizeof (i_pSourceQueryParameters->
                m_aFilterParameters[i].m_wsFieldName));
        if (pParameters->FieldName == NULL)
        {
            return (false);
        }

        strncpy(pParameters->FieldName,
                i_pSourceQueryParameters->m_aFilterParameters[i].m_wsFieldName,
                sizeof (i_pSourceQueryParameters->
                    m_aFilterParameters[i].m_wsFieldName));
        pParameters->FieldName[sizeof (i_pSourceQueryParameters->
                    m_aFilterParameters[i].m_wsFieldName)-1] = '\0';

        // copy field value
        pParameters->FieldValue =
                (utf8cstr) soap_malloc
                (i_pstSoap,
                sizeof (i_pSourceQueryParameters->m_aFilterParameters[i].m_wsFieldValue));
        if (pParameters->FieldValue == NULL)
        {
            return (false);
        }

        strncpy(pParameters->FieldValue,
                i_pSourceQueryParameters->m_aFilterParameters[i].m_wsFieldValue,
                sizeof (i_pSourceQueryParameters->m_aFilterParameters[i].m_wsFieldValue));
        pParameters->FieldValue[sizeof (i_pSourceQueryParameters->m_aFilterParameters[i].m_wsFieldValue)-1] = '\0';

        // copy FilterOperator
        pParameters->FilterOperator =
                (KMS_Agent::KMS_Agent__FilterOperator)
                i_pSourceQueryParameters->m_aFilterParameters[i].m_eFilterOperator;
    }

    // copy PreviousPageLastIDValue
    i_pQueryParameters->PreviousPageLastIDValue =
            (utf8cstr) soap_malloc(i_pstSoap,
            sizeof (i_pSourceQueryParameters->m_wsPreviousPageLastIDValue));
    if (i_pQueryParameters->PreviousPageLastIDValue == NULL)
    {
        return (false);
    }
    strncpy(i_pQueryParameters->PreviousPageLastIDValue,
            i_pSourceQueryParameters->m_wsPreviousPageLastIDValue,
            sizeof (i_pSourceQueryParameters->m_wsPreviousPageLastIDValue));
    i_pQueryParameters->PreviousPageLastIDValue[sizeof (i_pSourceQueryParameters->m_wsPreviousPageLastIDValue)-1] = '\0';

    // copy PreviousPageLastIDValue
    i_pQueryParameters->PreviousPageLastSortFieldValue =
            (utf8cstr) soap_malloc(i_pstSoap,
            sizeof (i_pSourceQueryParameters->
            m_wsPreviousPageLastSortFieldValue));
    if (i_pQueryParameters->PreviousPageLastSortFieldValue == NULL)
    {
        return (false);
    }
    strncpy(i_pQueryParameters->PreviousPageLastSortFieldValue,
            i_pSourceQueryParameters->m_wsPreviousPageLastSortFieldValue,
            sizeof (i_pSourceQueryParameters->
            m_wsPreviousPageLastSortFieldValue));
    i_pQueryParameters->PreviousPageLastSortFieldValue[sizeof (i_pSourceQueryParameters->
            m_wsPreviousPageLastSortFieldValue)-1] = 0;

    return (true);
}

static void CopyQueryParametersFromResponse (
                                             struct KMSAgent_QueryParameters *i_pQueryParameters,
                                             struct KMS_Agent::KMS_Agent__QueryParameters *i_pSourceQueryParameters)
{

    // copy sort field name
    if (i_pSourceQueryParameters->SortFieldName)
    {
        strncpy(i_pQueryParameters->m_wsSortFieldName,
                i_pSourceQueryParameters->SortFieldName,
                sizeof(i_pQueryParameters->m_wsSortFieldName));
        i_pQueryParameters->m_wsSortFieldName[sizeof(i_pQueryParameters->m_wsSortFieldName)-1] = '\0';
    }

    // copy order
    i_pQueryParameters->m_eSortOrder =
            (KMSAgent_SortOrder) i_pSourceQueryParameters->SortOrder;

    // copy filter parameters
    i_pQueryParameters->m_iSizeFilterParameters =
            i_pSourceQueryParameters->FilterParameters.__size;

    // we only accept this amount of parameters
    if (i_pQueryParameters->m_iSizeFilterParameters >= KMS_MAX_AGENT_FILTER_PARAMETERS)
    {
        // this should not happen, but just for defending the code
        i_pQueryParameters->m_iSizeFilterParameters = KMS_MAX_AGENT_FILTER_PARAMETERS;
    }

    for (int i = 0; i < i_pQueryParameters->m_iSizeFilterParameters; i++)
    {
        struct KMS_Agent::KMS_Agent__FilterParameters *pParameters;

        pParameters = i_pSourceQueryParameters->FilterParameters.__ptr + i;

        i_pQueryParameters->m_aFilterParameters[i].m_eFilterOperator
                = (KMSAgent_FilterOperator) pParameters->FilterOperator;

        if (pParameters->FieldName)
        {
            strncpy(i_pQueryParameters->m_aFilterParameters[i].m_wsFieldName,
                    pParameters->FieldName,
                    sizeof (i_pQueryParameters->m_aFilterParameters[i].m_wsFieldName));
            i_pQueryParameters->
                    m_aFilterParameters[i].m_wsFieldName[sizeof (i_pQueryParameters->m_aFilterParameters[i].m_wsFieldName) - 1] = '\0';
        }

        if (pParameters->FieldValue)
        {
            strncpy(i_pQueryParameters->m_aFilterParameters[i].m_wsFieldValue,
                    pParameters->FieldValue,
                    sizeof(i_pQueryParameters->m_aFilterParameters[i].m_wsFieldValue));
            i_pQueryParameters->
                    m_aFilterParameters[i].m_wsFieldValue[sizeof(i_pQueryParameters->m_aFilterParameters[i].m_wsFieldValue)-1] = '\0';
        }
    }
    // copy PreviousPageLastIDValue
    if (i_pSourceQueryParameters->PreviousPageLastIDValue)
    {
        strncpy(i_pQueryParameters->m_wsPreviousPageLastIDValue,
                i_pSourceQueryParameters->PreviousPageLastIDValue,
                sizeof(i_pQueryParameters->m_wsPreviousPageLastIDValue));
        i_pQueryParameters->m_wsPreviousPageLastIDValue[sizeof(i_pQueryParameters->m_wsPreviousPageLastIDValue)-1] = '\0';
    }

    // copy PreviousPageLastSortFieldValue
    if (i_pSourceQueryParameters->PreviousPageLastSortFieldValue)
    {
        strncpy(i_pQueryParameters->m_wsPreviousPageLastSortFieldValue,
                i_pSourceQueryParameters->PreviousPageLastSortFieldValue,
                sizeof(i_pQueryParameters->m_wsPreviousPageLastSortFieldValue));
        i_pQueryParameters->m_wsPreviousPageLastSortFieldValue[sizeof(i_pQueryParameters->m_wsPreviousPageLastSortFieldValue)-1] = '\0';
    }

}

/**
 *  copies data unit to the soap data unit structure, placing the xsd_string types on the
 *  gsoap heap.
 *  @return(false if soap_malloc fails
 */
static bool CopyDataUnitFromRequest (struct soap *i_pstSoap,
                                     struct KMS_Agent::KMS_Agent__DataUnit *i_pDataUnit,
                                     const KMSAgent_DataUnit * const i_pSourceDataUnit)
{

    if (i_pSourceDataUnit)
    {
        // copy field name
        i_pDataUnit->DataUnitID =
                (utf8cstr) soap_malloc(i_pstSoap,
                2 * sizeof (i_pSourceDataUnit->m_acDataUnitID) + 1);
        if (i_pDataUnit->DataUnitID == NULL)
        {
            return (false);
        }

        ConvertBinaryToUTF8HexString(i_pDataUnit->DataUnitID,
                i_pSourceDataUnit->m_acDataUnitID,
                KMS_DATA_UNIT_ID_SIZE);
    }
    else
    {
        strcpy(i_pDataUnit->DataUnitID, "");
    }

    i_pDataUnit->ExternalUniqueID = (utf8cstr) soap_malloc(i_pstSoap,
            2 * sizeof (i_pSourceDataUnit->m_acExternalUniqueID) + 1);
    if (i_pDataUnit->ExternalUniqueID == NULL)
    {
        return (false);
    }

    if (i_pSourceDataUnit->m_iExternalUniqueIDLength > 0 &&
        i_pSourceDataUnit->m_iExternalUniqueIDLength <= KMS_MAX_EXTERNAL_UNIQUE_ID_SIZE)
    {
        ConvertBinaryToUTF8HexString(i_pDataUnit->ExternalUniqueID,
                i_pSourceDataUnit->m_acExternalUniqueID,
                i_pSourceDataUnit->m_iExternalUniqueIDLength);
    }
    else
    {
        strcpy(i_pDataUnit->ExternalUniqueID, "");
    }

    i_pDataUnit->ExternalTag = (utf8cstr) soap_malloc(i_pstSoap, sizeof (i_pSourceDataUnit->m_acExternalTag));
    if (i_pDataUnit->ExternalTag == NULL)
    {
        return (false);
    }

    if (strlen(i_pSourceDataUnit->m_acExternalTag) <= sizeof (i_pSourceDataUnit->m_acExternalTag))
    {
        strncpy(i_pDataUnit->ExternalTag,
                i_pSourceDataUnit->m_acExternalTag,
                sizeof (i_pSourceDataUnit->m_acExternalTag));
        i_pDataUnit->ExternalTag[sizeof (i_pSourceDataUnit->m_acExternalTag)-1] = '\0';
    }
    else
    {
        strcpy(i_pDataUnit->ExternalTag, "");
    }

    i_pDataUnit->Description = (utf8cstr) soap_malloc(i_pstSoap, sizeof (i_pSourceDataUnit->m_acDescription));
    if (i_pDataUnit->Description == NULL)
    {
        return (false);
    }
    if (strlen(i_pSourceDataUnit->m_acDescription) <= sizeof (i_pSourceDataUnit->m_acDescription))
    {
        strncpy(i_pDataUnit->Description,
                i_pSourceDataUnit->m_acDescription,
                sizeof (i_pSourceDataUnit->m_acDescription));
        i_pDataUnit->Description[sizeof (i_pSourceDataUnit->m_acDescription)-1] = '\0';
    }
    else
    {
        strcpy(i_pDataUnit->Description, "");
    }

    i_pDataUnit->DataUnitState = (KMS_Agent::KMS_Agent__DataUnitState) i_pSourceDataUnit->m_iDataUnitState;

    return (true);
}

/**
 *  Converts an ExternalUniqueID value to UTF8Hexstring value from gSoap managed heap storage
 *  @param  i_pstSoap pointer to gSoap runtime
 *  @param  i_pExternalUniqueID non-NULL pointer to an external unique id to be converted
 *  @return(NULL if memory cannot be allocated
 */
static char * ConvertBinaryDataFromRequest (struct soap *i_pstSoap,
                                            const unsigned char * i_pBinaryData,
                                            int i_iBinaryDataLen)
{
    char * pBinaryData = (char *) soap_malloc(i_pstSoap, 2 * i_iBinaryDataLen + 1);
    if (pBinaryData != NULL)
    {
        ConvertBinaryToUTF8HexString(pBinaryData,
                i_pBinaryData,
                i_iBinaryDataLen);
    }
    return (pBinaryData);
}

/**
 *  Converts a UTF8 char string value to a fixed length array from
 *  gSoap managed heap storage
 *  @param  pointer to gSoap runtime
 *  @param  i_pUTF8string non-NULL pointer to a null terminated UTF8 string
 *  @param  i_iLen size of arrray to be allocated
 *  @return(NULL if gSoap allocated storage could not be obtained
 */
static char * ConvertUTF8StringFromRequest (struct soap *i_pstSoap,
                                            const char * const i_pUTF8string,
                                            size_t i_iLen)
{
    char * pUTF8string = NULL;
    pUTF8string = (char *) soap_malloc(i_pstSoap, i_iLen);
    if (pUTF8string != NULL)
    {
        strncpy(pUTF8string, i_pUTF8string, i_iLen);
        pUTF8string[i_iLen-1] = '\0';
    }
    return (pUTF8string);
}

static KMSAgent_ArrayOfKeyGroups * CopyKeyGroupsResponse
(
 struct KMS_Agent::KMS_Agent__ArrayOfKeyGroups *i_pKeyGroupsResponse
 )
{
    // alloc memory for result
    KMSAgent_ArrayOfKeyGroups *pResult =
            (KMSAgent_ArrayOfKeyGroups *) calloc(1, sizeof (KMSAgent_ArrayOfKeyGroups));

    // no memory, return
    if (pResult == NULL)
    {
        return (NULL);
    }

    // copy size
    pResult->m_iSize = i_pKeyGroupsResponse->__size;

    // if the size is 0, return(an empty result
    if (pResult->m_iSize == 0)
    {
        return (pResult);
    }

    // alloc memory for all key groups
    pResult->m_pKeyGroups = (KMSAgent_KeyGroup*)
            calloc(1, sizeof (KMSAgent_KeyGroup) * pResult->m_iSize);

    if (pResult->m_pKeyGroups == NULL)
    {
        free(pResult);
        return (NULL);
    }

    for (int i = 0; i < pResult->m_iSize; i++)
    {
        KMSAgent_KeyGroup *pKeyGroup;

        pKeyGroup = &(pResult->m_pKeyGroups[i]);

        strncpy(pKeyGroup->m_acKeyGroupID,
                i_pKeyGroupsResponse->__ptr[i].KeyGroupID,
                sizeof(pKeyGroup->m_acKeyGroupID));
        pKeyGroup->m_acKeyGroupID[sizeof(pKeyGroup->m_acKeyGroupID)-1] = '\0';

        strncpy(pKeyGroup->m_acDescription,
                i_pKeyGroupsResponse->__ptr[i].Description,
                sizeof(pKeyGroup->m_acDescription));
        pKeyGroup->m_acDescription[sizeof(pKeyGroup->m_acDescription)-1] = '\0';
    }

    return (pResult);
}
/**
 *  allocate storage for the KMSAgent_ArrayOfKeys struct and the array of keys returned in the
 *  soap response.
 *  @param  i_pProfile pointer to profile
 *  @param  io_pClusterIndex pointer to the cluster index value which is used
 *      by AES Key Unwrap to access the KWK for the KMA corresponding to the
 *      cluster index.
 *  @param  i_pKeysResponse pointer to the soap response' array of keys struct
 *  @return(pointer to allocated KMSAgent_ArrayOfKeys and the corresponding keys, returns NULL
 *  on any error and frees any allocated storage before returning.  For response data validation errors a
 *  message will be logged.
 */
static KMSAgent_ArrayOfKeys * CopyDataUnitKeysResponse (
                    KMSClientProfile *i_pProfile,
                    int * const io_pClusterIndex,
                    struct KMS_Agent::KMS_Agent__ArrayOfKeys *i_pKeysResponse)
{
    KMSAgent_ArrayOfKeys * pResult =
            (KMSAgent_ArrayOfKeys *) calloc(1, sizeof (KMSAgent_ArrayOfKeys));

    if (pResult == NULL)
    {
        return (NULL);
    }

    // if the size is 0, return(an empty result
    if (i_pKeysResponse->__size == 0)
    {
        return (pResult);
    }

    if (i_pKeysResponse->__size > KMS_MAX_PAGE_SIZE)
    {
        free(pResult);
        LogError(i_pProfile,
                AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_ARRAY_SIZE_RESPONSE,
                NULL,
                NULL,
                NULL);
        return (NULL);
    }

    pResult->m_iSize = i_pKeysResponse->__size;

    // alloc memory for all keys returned
    pResult->m_pKeys = (KMSAgent_Key*)
            calloc(1, sizeof (KMSAgent_Key) * i_pKeysResponse->__size);

    if (pResult->m_pKeys == NULL)
    {
        free(pResult);
        return (NULL);
        // no memory, don't log
    }

    // copy keys from response
    for (int i = 0; i < i_pKeysResponse->__size; i++)
    {
        if (KMS_KEY_ID_SIZE != ConvertUTF8HexStringToBinary(
            i_pKeysResponse->__ptr[i].KeyID, NULL))
        {
            free(pResult->m_pKeys);
            free(pResult);

            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_RESPONSE,
                    NULL,
                    NULL,
                    NULL);
            return (NULL);
        }

        ConvertUTF8HexStringToBinary(
                i_pKeysResponse->__ptr[i].KeyID, pResult->m_pKeys[i].m_acKeyID);

        if ((KMS_AGENT_KEY_STATE) i_pKeysResponse->__ptr[i].KeyState < KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS ||
            (KMS_AGENT_KEY_STATE) i_pKeysResponse->__ptr[i].KeyState > KMS_KEY_STATE_COMPROMISED)
        {
            free(pResult->m_pKeys);
            free(pResult);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_STATE_RESPONSE,
                    NULL,
                    NULL,
                    NULL);
            return (NULL);
        }
        pResult->m_pKeys[i].m_iKeyState = (KMS_AGENT_KEY_STATE) i_pKeysResponse->__ptr[i].KeyState;

        if ((KMS_KEY_TYPE) i_pKeysResponse->__ptr[i].KeyType != (KMS_KEY_TYPE)KMS_KEY_TYPE_AES_256)
        {
            free(pResult->m_pKeys);
            free(pResult);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_TYPE_RESPONSE,
                    NULL,
                    NULL,
                    NULL);
            return (NULL);
        }
        pResult->m_pKeys[i].m_iKeyType = (KMS_KEY_TYPE) i_pKeysResponse->__ptr[i].KeyType;

        strncpy(pResult->m_pKeys[i].m_acKeyGroupID,
                i_pKeysResponse->__ptr[i].KeyGroupID,
                sizeof(pResult->m_pKeys[i].m_acKeyGroupID));
        pResult->m_pKeys[i].m_acKeyGroupID[sizeof(pResult->m_pKeys[i].m_acKeyGroupID)-1] = '\0';

        CAgentLoadBalancer *pAgentLoadBalancer = reinterpret_cast
                <CAgentLoadBalancer *> (i_pProfile->m_pAgentLoadBalancer);

        if (pAgentLoadBalancer->AESKeyWrapSupported(*io_pClusterIndex))
        {
            if (i_pKeysResponse->__ptr[i].Key.__size != KMS_MAX_WRAPPED_KEY_SIZE)
            {
                free(pResult->m_pKeys);
                free(pResult);
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_WRAPPED_KEY_LENGTH_RESPONSE,
                        NULL,
                        NULL,
                        NULL);
                return (NULL);
            }
            else
            {
                if (pAgentLoadBalancer->AESKeyUnwrap(io_pClusterIndex,
                    i_pKeysResponse->__ptr[i].Key.__ptr,
                    pResult->m_pKeys[i].m_acKey) == false)
                {
                    free(pResult->m_pKeys);
                    free(pResult);
                    LogError(i_pProfile,
                            AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_AESKEYUNWRAP_ERROR,
                            NULL,
                            NULL,
                            NULL);

                    return (NULL);
                }
            }
        }
        else  // non-AES Key Wrap
        {
            if (i_pKeysResponse->__ptr[i].Key.__size != KMS_MAX_KEY_SIZE)
            {
                free(pResult->m_pKeys);
                free(pResult);
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEY_LENGTH_RESPONSE,
                        NULL,
                        NULL,
                        NULL);
                return (NULL);
            }

            memcpy(pResult->m_pKeys[i].m_acKey,
                    i_pKeysResponse->__ptr[i].Key.__ptr,
                    KMS_MAX_KEY_SIZE);
        }

        pResult->m_pKeys[i].m_iKeyLength = KMS_MAX_KEY_SIZE;

        if (KMSAgentKeyCallout(pResult->m_pKeys[i].m_acKey) != 0)
        {
            free(pResult->m_pKeys);
            free(pResult);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_KEY_CALLOUT_ERROR,
                    NULL,
                    NULL,
                    NULL);
            return (NULL);
        }
    }

    return (pResult);
}

/**
 *  This function returns the API status code based upon the error string in the profile and
 *  availability of KMAs. KMA availability determination is based upon the i_iKMAFailoverReturnCode
 *  parameter and the size of the cluster.  A cluster size of 0 is an indicator that there are
 *  no KMAs available, unless cluster discovery is disabled by the profile's cluster discovery
 *  frequency.
 *
 *  @param i_pProfile  pointer to the profile
 *  @param i_iKMAFailoverReturnCode the return(code from CAgentLoadBalancer::Failover() or 0
 *  if it was not called.  This is used to for determining if KMS_AGENT_STATUS_KMS_UNAVAILABLE
 *  needs to be returned.
 *  @returns KMS_AGENT_STATUS_GENERIC_ERROR
 *  unless the profile's last error message field contains a message substring matching one of the
 *  KMSAgent service soap fault strings.
 *
 */
static KMS_AGENT_STATUS KMSAgent_GetLastStatusCode (KMSClientProfile *i_pProfile,
                                                    int i_iKMAFailoverReturnCode)
{
    bool bServerError = false;

    FATAL_ASSERT(i_pProfile);

    // see KMSAgentLoadBalancer.h for return codes from Failover

    if (i_iKMAFailoverReturnCode == CAgentLoadBalancer::NO_FIPS_KMA_AVAILABLE)
    {
        return (KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE);
    }

    // parse for server errors -
    // when KMAs have no ready keys we want to inform the client, vs reporting that the KMS is unavailable
    bServerError = ServerError(i_pProfile->m_wsErrorString, 0);

    // parse for Soap errors
    const char* sFaultstringStart = strstr(i_pProfile->m_wsErrorString, "SoapFaultString=");

    int iErrorCode = INVALID_CLIENT_ERROR; // initially


    // if there is a Soap error
    if (sFaultstringStart)
    {
        if (SSL_InvalidCertificate(sFaultstringStart))
        {
            // this can be caused by the KMS invalidating the agent's cert
            return (KMS_AGENT_STATUS_ACCESS_DENIED);
        }
        iErrorCode = GET_FAULT_CODE(sFaultstringStart + strlen("SoapFaultString="));
    }


#ifdef METAWARE
    // log the failure code/cause to the event log
    LogToFile(i_iKMAFailoverReturnCode, i_pProfile->m_wsErrorString);
    LogToFile(iErrorCode, "error code");
#endif


    // parse return code passed in from last call to FailOver, Balance or BalanceByDataUnitKeyID
    // if failover reported no kma and there is a valid server error and client couldn't get keys
    if (i_iKMAFailoverReturnCode == CAgentLoadBalancer::NO_KMA_AVAILABLE &&
        bServerError &&
        iErrorCode == CLIENT_ERROR_AGENT_NO_READY_KEYS)
    {
        return (KMS_AGENT_STATUS_KMS_UNAVAILABLE);
    }

    // if there is a server error and we are doing discovery
    if (bServerError &&
        ((i_pProfile->m_iClusterDiscoveryFrequency > 0 &&
        i_pProfile->m_iClusterNum == 0)
        || iErrorCode == CLIENT_ERROR_AGENT_APPLIANCE_LOCKED))
    {
        return (KMS_AGENT_STATUS_KMS_UNAVAILABLE);
    }

    if (bServerError && i_iKMAFailoverReturnCode == CAgentLoadBalancer::NO_KMA_AVAILABLE)
    {
        return (KMS_AGENT_STATUS_KMS_UNAVAILABLE);
    }

    if ( i_iKMAFailoverReturnCode == CAgentLoadBalancer::AES_KEY_UNWRAP_ERROR )
        return (KMS_AGENT_AES_KEY_UNWRAP_ERROR);
    if ( i_iKMAFailoverReturnCode == CAgentLoadBalancer::AES_KEY_WRAP_SETUP_ERROR )
        return (KMS_AGENT_AES_KEY_WRAP_SETUP_ERROR);

    if (iErrorCode == CLIENT_ERROR_ACCESS_DENIED)
        return (KMS_AGENT_STATUS_ACCESS_DENIED);
    if (iErrorCode == CLIENT_ERROR_SERVER_BUSY)
        return (KMS_AGENT_STATUS_SERVER_BUSY);
    if (iErrorCode == CLIENT_ERROR_AGENT_INVALID_PARAMETERS)
        return (KMS_AGENT_STATUS_INVALID_PARAMETER);
    if (iErrorCode == CLIENT_ERROR_AGENT_KEY_DOES_NOT_EXIST)
        return (KMS_AGENT_STATUS_KEY_DOES_NOT_EXIST);
    if (iErrorCode == CLIENT_ERROR_AGENT_KEY_DESTROYED)
        return (KMS_AGENT_STATUS_KEY_DESTROYED);
    if (iErrorCode == CLIENT_ERROR_AGENT_DATA_UNIT_ID_NOT_FOUND_EXTERNAL_ID_EXISTS)
        return (KMS_AGENT_STATUS_DATA_UNIT_ID_NOT_FOUND_EXTERNAL_ID_EXISTS);
    if (iErrorCode == CLIENT_ERROR_AGENT_DUPLICATE_EXTERNAL_ID)
        return (KMS_AGENT_STATUS_EXTERNAL_UNIQUE_ID_EXISTS);
    if (iErrorCode == CLIENT_ERROR_AGENT_NO_READY_KEYS)
        return (KMS_AGENT_STATUS_KMS_NO_READY_KEYS);

    // this check is made last to allow other specific errors that may have occurred to take precedence,
    // e.g. return access denied before reporting No FIPS KMAs
    if (i_pProfile->m_eKMSmode == FIPS_MODE &&
        KMSClient_NoFIPSCompatibleKMAs(i_pProfile))
    {
        return (KMS_AGENT_STATUS_NO_FIPS_KMAS_AVAILABLE);
    }

    return (KMS_AGENT_STATUS_GENERIC_ERROR);
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_InitializeLibrary
 *--------------------------------------------------------------------------*/
#include "KMSAuditLogger.h"

extern "C"
KMS_AGENT_STATUS KMSAgent_InitializeLibrary (utf8cstr const i_pWorkingDirectory,
                                             int i_bUseFileLog)

{
    bool bSuccess;

#if defined(METAWARE)
#warn "debug timing is on"
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_InitializeLibrary);
#endif

#if defined(DEBUG) && defined(METAWARE)
    log_printf("KMSAgent_InitializeLibrary : Entered");
#endif

    bSuccess = KMSClient_InitializeLibrary(
            i_pWorkingDirectory,
            i_bUseFileLog);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMS_AGENT_STATUS_GENERIC_ERROR);
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_KnownAnswerTests
 *
 *--------------------------------------------------------------------------*/
KMS_AGENT_STATUS KMSAgent_KnownAnswerTests()
{
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_KnownAnswerTests);
#endif

   // Known Answer Test on AES Key Wrap code
   if ( KnownAnswerTestAESKeyWrap() != 0 )
   {
       RETURN(KMS_AGENT_STATUS_FIPS_KAT_AES_KEYWRAP_ERROR);
   }

   if ( KnownAnswerTestAESECB() != 0 )
   {
       RETURN(KMS_AGENT_STATUS_FIPS_KAT_AES_ECB_ERROR);
   }

   if ( KnownAnswerTestHMACSHA1() != 0 )
   {
       RETURN(KMS_AGENT_STATUS_FIPS_KAT_HMAC_SHA1_ERROR);
   }

   RETURN(KMS_AGENT_STATUS_OK);

}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_FinalizeLibrary
 *
 *--------------------------------------------------------------------------*/

extern "C"
KMS_AGENT_STATUS KMSAgent_FinalizeLibrary ()
{
    bool bSuccess;

#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_FinalizeLibrary);
#endif

    bSuccess = KMSClient_FinalizeLibrary();

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMS_AGENT_STATUS_GENERIC_ERROR);
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_GetLastErrorMessage
 *
 *--------------------------------------------------------------------------*/

extern "C"
utf8cstr KMSAgent_GetLastErrorMessage (KMSClientProfile* i_pProfile)
{
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_GetLastErrorMessage);
#endif

    if (i_pProfile == NULL)
    {
        RETURN(NULL);
    }

    RETURN(KMSClient_GetLastErrorMessage(i_pProfile));
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_GetClusterInformation
 *
 *--------------------------------------------------------------------------*/
extern "C"
KMS_AGENT_STATUS KMSAgent_GetClusterInformation (
                                                 KMSClientProfile * const i_pProfile,
                                                 int i_iEntitySiteIDSize,
                                                 int i_iClusterEntryArraySize,
                                                 utf8cstr const o_pEntitySiteID,
                                                 int * const o_pApplianceNum,
                                                 KMSClusterEntry * const o_pClusterEntryArray)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_GetClusterInformation);
#endif

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_GET_CLUSTER_INFORMATION_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!o_pEntitySiteID || (i_iEntitySiteIDSize <= (KMS_MAX_ENTITY_SITE_ID)))
    {
        Log(AUDIT_CLIENT_AGENT_GET_CLUSTER_INFORMATION_INVALID_PARAMETERS,
                NULL,
                NULL,
                "EntitySiteIDSize arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_iClusterEntryArraySize > KMS_MAX_CLUSTER_NUM)
    {
        Log(AUDIT_CLIENT_AGENT_GET_CLUSTER_INFORMATION_INVALID_PARAMETERS,
                NULL,
                NULL,
                "i_iClusterEntryArraySize exceeds KMS_MAX_CLUSTER_NUM");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    
    if (!o_pApplianceNum)
    {
        Log(AUDIT_CLIENT_AGENT_GET_CLUSTER_INFORMATION_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ApplianceNum arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!o_pClusterEntryArray ||
        (i_iClusterEntryArraySize <= 0))
    {
        Log(AUDIT_CLIENT_AGENT_GET_CLUSTER_INFORMATION_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ClusterEntry or Size arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    bSuccess = KMSClient_GetClusterInformation(
            i_pProfile,
            o_pEntitySiteID,
            i_iEntitySiteIDSize,
            o_pApplianceNum,
            o_pClusterEntryArray,
            i_iClusterEntryArraySize);

    // KMSClient_GetClusterInformation logs if there was an error

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile, 0));
}

extern "C"
KMS_AGENT_STATUS KMSAgent_SelectAppliance (
                                           KMSClientProfile * const i_pProfile,
                                           utf8cstr const i_pApplianceAddress)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_SelectAppliance);
#endif

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_SELECT_APPLIANCE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!i_pApplianceAddress)
    {
        Log(AUDIT_CLIENT_AGENT_GET_CLUSTER_INFORMATION_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ApplianceAddress arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    // All modes are supported by this function.

    bSuccess = KMSClient_SelectAppliance(i_pProfile, i_pApplianceAddress);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile, 0));
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_LoadProfile
 *
 *--------------------------------------------------------------------------*/
extern "C"
KMS_AGENT_STATUS KMSAgent_LoadProfile (
                                       KMSClientProfile * const io_pProfile,
                                       utf8cstr const i_pProfileName,
                                       utf8cstr const i_pAgentID,
                                       utf8cstr const i_pPassphrase,
                                       utf8cstr const i_pInitialApplianceAddress,
                                       int i_iTransactionTimeout,
                                       int i_iFailOverLimit,
                                       int i_iClusterDiscoveryFrequency,
                                       int i_eKMSmode)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_LoadProfile);
#endif

#if defined(DEBUG) && defined(METAWARE)
    log_printf("KMSAgent_LoadProfile : Entered");
#endif
    if (!io_pProfile ||
        !i_pProfileName || (strlen(i_pProfileName) <= 0))
    {
        Log(AUDIT_CLIENT_AGENT_LOAD_PROFILE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile or Name arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!i_pInitialApplianceAddress || (strlen(i_pInitialApplianceAddress) <= 0))
    {
        Log(AUDIT_CLIENT_AGENT_LOAD_PROFILE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "InitialApplianceAddress arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_iTransactionTimeout <= 0)
    {
        Log(AUDIT_CLIENT_AGENT_LOAD_PROFILE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "TransactionTimeout arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (i_iClusterDiscoveryFrequency < 0)
    {
        Log(AUDIT_CLIENT_AGENT_LOAD_PROFILE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ClusterDiscoveryFrequency arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    // for enrollment both arguments are required
    if ((i_pAgentID && !i_pPassphrase) || (i_pPassphrase && !i_pAgentID))
    {
        Log(AUDIT_CLIENT_AGENT_LOAD_PROFILE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Enrollment requires AgentID & Passphrase");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_pAgentID && (strlen(i_pAgentID) <= 0))
    {
        Log(AUDIT_CLIENT_AGENT_LOAD_PROFILE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "AgentID arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_pPassphrase && (strlen(i_pPassphrase) <= 0))
    {
        Log(AUDIT_CLIENT_AGENT_LOAD_PROFILE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Passphrase arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if ( i_eKMSmode != DEFAULT_MODE && i_eKMSmode != FIPS_MODE )
    {
        Log(AUDIT_CLIENT_AGENT_LOAD_PROFILE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "KMS security mode arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (KMSClient_ProfileLoaded(io_pProfile))
    {
        Log(AUDIT_CLIENT_AGENT_LOAD_PROFILE_PROFILE_ALREADY_LOADED,
                NULL,
                NULL,
                "profile is already loaded and should be unloaded first");
        RETURN(KMS_AGENT_STATUS_PROFILE_ALREADY_LOADED);
    }

    memset(io_pProfile, 0, sizeof (KMSClientProfile));
    char sInitialApplianceAddress[KMS_MAX_NETWORK_ADDRESS+1];
    strncpy(sInitialApplianceAddress, i_pInitialApplianceAddress, sizeof(sInitialApplianceAddress));
    sInitialApplianceAddress[sizeof(sInitialApplianceAddress)-1] = '\0';
    
    // Convert to lower case

    for ( size_t i = 0; i < strlen( sInitialApplianceAddress ); i++ )
    {
        if ( isupper( sInitialApplianceAddress[i] ) )
        {
            sInitialApplianceAddress[i] = tolower( sInitialApplianceAddress[i] );
        }
    }

    bSuccess = KMSClient_LoadProfile(
                            io_pProfile,
                            i_pProfileName,
                            i_pAgentID,
                            i_pPassphrase,
                            sInitialApplianceAddress,
                            i_iTransactionTimeout,
                            i_iFailOverLimit,
                            i_iClusterDiscoveryFrequency,
                            i_eKMSmode);

    if (bSuccess)
    {
#if defined(DEBUG) && defined(METAWARE)
        log_printf("KMSAgent_LoadProfile : Returned ok");
#endif
        RETURN(KMS_AGENT_STATUS_OK);
    }

    // when not enrolling & cluster discovery is disabled there are no
    // soap transactions so failover would not have occurred
    bool bEnrolling = i_pAgentID && i_pPassphrase;

    if (!bEnrolling &&
        i_iClusterDiscoveryFrequency == 0)
    {
        RETURN(KMSAgent_GetLastStatusCode(io_pProfile, 0));
    }
    else
    {
//        if (i_eKMSmode == FIPS_MODE &&
//            KMSClient_NoFIPSCompatibleKMAs(io_pProfile))
//        {
//            RETURN(KMSAgent_GetLastStatusCode(io_pProfile,
//                CAgentLoadBalancer::NO_FIPS_KMA_AVAILABLE));
//        }

        RETURN(KMSAgent_GetLastStatusCode(io_pProfile,
            CAgentLoadBalancer::NO_KMA_AVAILABLE));
    }
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_UnloadProfile
 *
 *--------------------------------------------------------------------------*/
extern "C"
KMS_AGENT_STATUS KMSAgent_UnloadProfile (KMSClientProfile * const i_pProfile)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_UnloadProfile);
#endif

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_UNLOAD_PROFILE_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    bSuccess = KMSClient_UnloadProfile(i_pProfile);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile, 0));
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_DeleteProfile
 *
 *--------------------------------------------------------------------------*/
extern "C"
KMS_AGENT_STATUS KMSAgent_DeleteProfile (utf8cstr i_pProfileName)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_DeleteProfile);
#endif

    if (!i_pProfileName || (strlen(i_pProfileName) <= 0))
    {
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    bSuccess = KMSClient_DeleteProfile(i_pProfileName);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMS_AGENT_STATUS_GENERIC_ERROR);
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_ListKeyGroups
 *
 *--------------------------------------------------------------------------*/

extern "C"
KMS_AGENT_STATUS KMSAgent_ListKeyGroups (
                                         KMSClientProfile * const i_pProfile,
                                         KMSAgent_ArrayOfKeyGroups* * const o_ppKeyGroups)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_ListKeyGroups);
#endif

    int bIsLastPage;
    struct KMSAgent_QueryParameters stQueryParameters;

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_LIST_KEY_GROUPS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!o_ppKeyGroups)
    {
        Log(AUDIT_CLIENT_AGENT_LIST_KEY_GROUPS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "KeyGroups arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    struct soap *pstSoap = (struct soap *) i_pProfile->m_pvSoap;

    // Get Key Groups
    memset(&stQueryParameters, 0, sizeof (stQueryParameters));

    struct KMS_Agent::KMS_Agent__QueryParameters oQueryParameters;
    struct KMS_Agent::KMS_Agent__ListKeyGroupsResponse oResponse;

    memset(&oQueryParameters, 0, sizeof (oQueryParameters));

    bSuccess = CopyQueryParametersFromRequest(pstSoap,
            KMS_MAX_LIST_KEY_GROUPS,
            &oQueryParameters,
            &stQueryParameters);
    if (!bSuccess)
    {
        soap_destroy(pstSoap);
        soap_end(pstSoap);
        // no memory, don't log
        RETURN(KMS_AGENT_STATUS_NO_MEMORY);
    }

    CAgentLoadBalancer *pLoadBalancer =
            (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;

    int iIndex = pLoadBalancer->Balance();

    if ( iIndex >= 0 )
    {
        do
        {
            const char* sURL =
                    pLoadBalancer->GetHTTPSURL(iIndex, i_pProfile->m_iPortForAgentService);
            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));
            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = '\0';

            bSuccess = KMS_Agent::soap_call_KMS_Agent__ListKeyGroups(
                    pstSoap,
                    sURL,
                    NULL,
                    oQueryParameters,
                    oResponse) == SOAP_OK;

            if (!bSuccess)
            {
                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
                char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];

                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                GetSoapFault(sSoapFaultMsg, pstSoap);

                LogError(i_pProfile, AUDIT_CLIENT_AGENT_LIST_KEY_GROUPS_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            else
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }
        }
        while (iIndex >= 0 && (!bSuccess));
    }
    else
    {
        bSuccess = false;
    }

    if (bSuccess)
    {
        bIsLastPage = oResponse.LastPage;

        *o_ppKeyGroups = CopyKeyGroupsResponse(&oResponse.KeyGroups);
        if (*o_ppKeyGroups == NULL)
        {
            bSuccess = false;
            // no memory, don't log
        }

        CopyQueryParametersFromResponse(&stQueryParameters,
                &oResponse.NextPageQueryParameters);
    }

    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
        RETURN(KMS_AGENT_STATUS_OK);

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile, iIndex));
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_FreeArrayOfKeyGroups
 *
 *--------------------------------------------------------------------------*/

extern "C"
void KMSAgent_FreeArrayOfKeyGroups (
                                    struct KMSAgent_ArrayOfKeyGroups *i_pArrayOfKeyGroups)
{
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_FreeArrayOfKeyGroups);
#endif
    if (!i_pArrayOfKeyGroups)
    {
        return;
    }

    // free memory for all information groups
    if (i_pArrayOfKeyGroups->m_pKeyGroups)
    {
        free(i_pArrayOfKeyGroups->m_pKeyGroups);
    }

    free(i_pArrayOfKeyGroups);
}

extern "C"
KMS_AGENT_STATUS KMSAgent_CreateKey (
                                     KMSClientProfile * const i_pProfile,
                                     const KMSAgent_DataUnit * const i_pDataUnit,
                                     KEY_GROUP_ID const i_pKeyGroupID,
                                     KMSAgent_Key * const o_pKey)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_CreateKey);
#endif

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!o_pKey)
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Key arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    if (i_pKeyGroupID &&
        strlen(i_pKeyGroupID) > KMS_MAX_KEY_GROUP_ID_SIZE)
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "GroupID arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    struct KMS_Agent::KMS_Agent__DataUnit
                        stDataUnit = {(char *)"", (char *)"", (char *)"",
                                      (char *)"",
				      (KMS_Agent::KMS_Agent__DataUnitState) 0};

    struct soap *pstSoap = (struct soap *) i_pProfile->m_pvSoap;
    struct KMS_Agent::KMS_Agent__CreateKeyResponse oResponse;

    if (i_pDataUnit != NULL)
    {
        if (!CopyDataUnitFromRequest(pstSoap,
            &stDataUnit,
            i_pDataUnit))
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    char * pKeyGroupID = NULL;
    if (i_pKeyGroupID)
    {
        pKeyGroupID = ConvertUTF8StringFromRequest(pstSoap,
                i_pKeyGroupID,
                KMS_MAX_KEY_GROUP_ID_SIZE + 1);
        if (pKeyGroupID == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    CAgentLoadBalancer *pLoadBalancer =
            (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;

    char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
    char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];

    int iIndex;
    UTF8_KEYID acKWKID;
    bool bClientAESKeyWrapSetupError = false;

    if (i_pDataUnit)
    {
        // attempt to maintain affinity with KMA for specified DU ID
        iIndex = pLoadBalancer->BalanceByDataUnitID(
                i_pDataUnit->m_acDataUnitID,
                KMS_DATA_UNIT_ID_SIZE);
    }
    else
    {
        iIndex = pLoadBalancer->Balance();
    }
    
    if (iIndex >= 0)
    {
        do
        {
            bSuccess = true;
            const char* sURL = pLoadBalancer->GetHTTPSURL(
                    iIndex,
                    i_pProfile->m_iPortForAgentService);

            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));

            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = '\0';

            Long64 lKMAID = pLoadBalancer->GetKMAID(iIndex);

            if (bSuccess && pLoadBalancer->AESKeyWrapSupported(iIndex))
            {
                // if this fails we want to utilize normal failover logic, GetKWKID
                // logs error
                bSuccess = pLoadBalancer->GetKWKID(iIndex, lKMAID, pstSoap,
					acKWKID, &bClientAESKeyWrapSetupError) ? true : false;
                if (bSuccess)
                {
                    bSuccess = KMS_Agent::soap_call_KMS_Agent__CreateKey2(
                            pstSoap,
                            sURL,
                            NULL,
                            stDataUnit,
                            i_pKeyGroupID ? pKeyGroupID : (char *) "",
                            acKWKID,
                            //NOTE: this is ugly but the soap response struct's are the same for both flavors of CreateKey
                            *(reinterpret_cast<struct KMS_Agent::KMS_Agent__CreateKey2Response *>(&oResponse))) == SOAP_OK;
                }
            }
            else  if (bSuccess) // NO AES Key Wrap
            {
                bSuccess = KMS_Agent::soap_call_KMS_Agent__CreateKey(
                        pstSoap,
                        sURL,
                        NULL,
                        stDataUnit,
                        i_pKeyGroupID ? pKeyGroupID : (char *) "",
                        oResponse) == SOAP_OK;
            }

            // don'f failover for Client side AES Key Wrap setup problems
            if (!bSuccess && !bClientAESKeyWrapSetupError)
            {
                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                GetSoapFault(sSoapFaultMsg, pstSoap);

                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_CREATE_KEY_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            if (bSuccess)
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }
        }
        while (iIndex >= 0 && (!bSuccess) && (!bClientAESKeyWrapSetupError));
    }
    else
    {
        bSuccess = false;
    }


#if defined(DEBUG) && defined(METAWARE)
    log_printf("CreateKey gets keyID %s (size %x) \n",
            oResponse.Key.KeyID,
            sizeof (oResponse.Key.KeyID));
#endif


    if (bSuccess)
    {
        if (KMS_KEY_ID_SIZE != ConvertUTF8HexStringToBinary(
            oResponse.Key.KeyID, NULL))
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEYID_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }

        ConvertUTF8HexStringToBinary(
                oResponse.Key.KeyID, // in
                o_pKey->m_acKeyID); // out

#if defined(DEBUG) && defined(METAWARE)
        log_printf("CreateKey gets keyState %x (size %x) \n",
                oResponse.Key.KeyState,
                sizeof (oResponse.Key.KeyState));
#endif

        if ((KMS_AGENT_KEY_STATE) oResponse.Key.KeyState < KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS ||
            (KMS_AGENT_KEY_STATE) oResponse.Key.KeyState > KMS_KEY_STATE_COMPROMISED)
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEY_STATE_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }

        o_pKey->m_iKeyState = (KMS_AGENT_KEY_STATE) oResponse.Key.KeyState;

#if defined(DEBUG) && defined(METAWARE)
        log_printf("CreateKey o_pKey->m_iKeyState %x (size %x) = "
                "(KMS_AGENT_KEY_STATE) oResponse.Key.KeyState %x (size %x)\n",
                o_pKey->m_iKeyState,
                sizeof (o_pKey->m_iKeyState),
                oResponse.Key.KeyState,
                sizeof (oResponse.Key.KeyState));
#endif


        if ((KMS_KEY_TYPE) oResponse.Key.KeyType != KMS_KEY_TYPE_AES_256)
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEY_TYPE_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }
        o_pKey->m_iKeyType = (KMS_KEY_TYPE) oResponse.Key.KeyType;

        if (strlen(oResponse.Key.KeyGroupID) > KMS_MAX_KEY_GROUP_ID_SIZE)
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEY_GROUP_ID_LENGTH_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }
        else
        {
            strncpy(o_pKey->m_acKeyGroupID,
                    oResponse.Key.KeyGroupID,
                    sizeof(o_pKey->m_acKeyGroupID));
            o_pKey->m_acKeyGroupID[sizeof(o_pKey->m_acKeyGroupID)-1] = '\0';
        }

        if ( bSuccess && pLoadBalancer->AESKeyWrapSupported(iIndex))
        {
            // verify KWK ID matches what was registered
            if (oResponse.Key.Key.__size != KMS_MAX_WRAPPED_KEY_SIZE)
            {
                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_WRAPPED_KEY_LENGTH_RESPONSE,
                        NULL,
                        sKmaAddress,
                        NULL);
                bSuccess = false;
            }
            else
            {
                if (pLoadBalancer->AESKeyUnwrap(&iIndex, oResponse.Key.Key.__ptr,
                    o_pKey->m_acKey) == false)
                {
                    GetPeerNetworkAddress(sKmaAddress, pstSoap);
                    LogError(i_pProfile,
                            AUDIT_CLIENT_AGENT_CREATE_KEY_AESKEYUNWRAP_ERROR,
                            NULL,
                            sKmaAddress,
                            NULL);

                    bSuccess = false;
                }
            }
        }
        else if (bSuccess) // non-AES key wrap
        {
            if (oResponse.Key.Key.__size != KMS_MAX_KEY_SIZE)
            {
                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_CREATE_KEY_INVALID_KEY_LENGTH_RESPONSE,
                        NULL,
                        sKmaAddress,
                        NULL);
                bSuccess = false;
            }
            else
            {
                memcpy(o_pKey->m_acKey,
                        oResponse.Key.Key.__ptr,
                        KMS_MAX_KEY_SIZE);
            }
        }

        if (bSuccess)
        {
            o_pKey->m_iKeyLength = KMS_MAX_KEY_SIZE;

            if (KMSAgentKeyCallout(o_pKey->m_acKey) != 0)
            {
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_CREATE_KEY_KEY_CALLOUT_ERROR,
                        NULL,
                        NULL,
                        NULL);
                bSuccess = false;
            }
        }
    }

    if (bSuccess)
    {
        // add Key ID and the creating KMA IP address to the DU cache
        CDataUnitCache* pDataUnitCache = (CDataUnitCache*) i_pProfile->m_pDataUnitCache;

        if (i_pProfile->m_iClusterDiscoveryFrequency != 0) // load balancing enabled
        {
            bSuccess = pDataUnitCache->Insert(
                    NULL,
                    0,
                    o_pKey->m_acKeyID,
                    KMS_KEY_ID_SIZE,
                    pLoadBalancer->GetApplianceNetworkAddress(iIndex));
        }
    }
    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile,
            bClientAESKeyWrapSetupError ?
                CAgentLoadBalancer::AES_KEY_WRAP_SETUP_ERROR : iIndex));
}

extern "C"
KMS_AGENT_STATUS KMSAgent_CreateDataUnit (
                                          KMSClientProfile * const i_pProfile,
                                          const unsigned char * i_pExternalUniqueID,
                                          int i_iExternalUniqueIDIDLen,
                                          utf8cstr const i_pExternalTag,
                                          utf8cstr const i_pDescription,
                                          KMSAgent_DataUnit * const o_pDataUnit)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_CreateDataUnit);
#endif

#if defined(DEBUG) && defined(METAWARE)
#warn "debug Create Data Unit is on"
    log_printf("KMSAgent_CreateDataUnit entered\n");
    log_printf("KMSAgent_CreateDataUnit profile=%x\n", i_pProfile);
#endif

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!o_pDataUnit)
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_INVALID_PARAMETERS,
                NULL,
                NULL,
                "DataUnit arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    // validate input parms

    if (i_pExternalUniqueID &&
        (i_iExternalUniqueIDIDLen <= 0 ||
        i_iExternalUniqueIDIDLen > KMS_MAX_EXTERNAL_UNIQUE_ID_SIZE))
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ExternalUniqueID arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_pExternalTag && strlen(i_pExternalTag) > KMS_MAX_EXTERNAL_TAG)
    {
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_pDescription && strlen(i_pDescription) > KMS_MAX_DESCRIPTION)
    {
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    struct soap *pstSoap = (struct soap *) i_pProfile->m_pvSoap;
    struct KMS_Agent::KMS_Agent__CreateDataUnitResponse oResponse;

    char * pExternalUniqueID = NULL;
    if (i_pExternalUniqueID)
    {
        pExternalUniqueID = ConvertBinaryDataFromRequest(pstSoap,
                i_pExternalUniqueID,
                i_iExternalUniqueIDIDLen);
        if (pExternalUniqueID == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    char * pExternalTag = NULL;
    if (i_pExternalTag)
    {
        pExternalTag = ConvertUTF8StringFromRequest(pstSoap,
                i_pExternalTag,
                strlen(i_pExternalTag) + 1);
        if (pExternalTag == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    char * pDescription = NULL;
    if (i_pDescription)
    {
        pDescription = ConvertUTF8StringFromRequest(pstSoap,
                i_pDescription,
                strlen(i_pDescription) + 1);
        if (pDescription == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    CAgentLoadBalancer *pLoadBalancer =
            (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;
    int iIndex = pLoadBalancer->Balance();

    if (iIndex >= 0)
    {
        do
        {
            const char* sURL = pLoadBalancer->GetHTTPSURL(
                    iIndex,
                    i_pProfile->m_iPortForAgentService);

            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));

            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = '\0';

            bSuccess = KMS_Agent::soap_call_KMS_Agent__CreateDataUnit(
                    pstSoap,
                    sURL,
                    NULL,
                    i_pExternalUniqueID ? pExternalUniqueID : (char *) "",
                    i_pExternalTag ? pExternalTag : (char *) "",
                    i_pDescription ? pDescription : (char *) "",
                    oResponse) == SOAP_OK;

            if (!bSuccess)
            {
                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
                char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];

                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                GetSoapFault(sSoapFaultMsg, pstSoap);

                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            else
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }

        }
        while (iIndex >= 0 && (!bSuccess));
    }
    else
    {
        bSuccess = false;
    }

    if (bSuccess)
    {
        int iDataUnitIDLength;
        iDataUnitIDLength = ConvertUTF8HexStringToBinary(
                oResponse.DataUnit.DataUnitID, o_pDataUnit->m_acDataUnitID);

        if (iDataUnitIDLength != KMS_DATA_UNIT_ID_SIZE)
        {
#if defined(DEBUG) && defined(METAWARE)
            log_printf("iDataUnitIDLength (%x) != KMS_DATA_UNIT_ID_SIZE (%x)",
                    iDataUnitIDLength,
                    KMS_DATA_UNIT_ID_SIZE);
#endif
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_RESPONSE_INVALID_DU_ID_LENGTH,
                    NULL,
                    NULL,
                    NULL);
            bSuccess = false;
        }
        o_pDataUnit->m_iExternalUniqueIDLength = ConvertUTF8HexStringToBinary(
                oResponse.DataUnit.ExternalUniqueID, o_pDataUnit->m_acExternalUniqueID);

        if (strlen(oResponse.DataUnit.ExternalTag) > KMS_MAX_EXTERNAL_TAG)
        {
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_RESPONSE_INVALID_EXTERNAL_TAG_LENGTH,
                    NULL,
                    NULL,
                    NULL);
            bSuccess = false;
        }
        else
        {
            strncpy(o_pDataUnit->m_acExternalTag,
                    oResponse.DataUnit.ExternalTag,
                    sizeof(o_pDataUnit->m_acExternalTag));
            o_pDataUnit->m_acExternalTag[sizeof(o_pDataUnit->m_acExternalTag)-1] = '\0';
        }

        if (strlen(oResponse.DataUnit.Description) > KMS_MAX_DESCRIPTION)
        {
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_CREATE_DATA_UNIT_RESPONSE_INVALID_DESCRIPTION_LENGTH,
                    NULL,
                    NULL,
                    NULL);
            bSuccess = false;
        }
        else
        {
            strcpy(o_pDataUnit->m_acDescription,
                    oResponse.DataUnit.Description);
        }

        o_pDataUnit->m_iDataUnitState =
                (KMS_AGENT_DATA_UNIT_STATE) oResponse.DataUnit.DataUnitState;
    }

    if (bSuccess)
    {
        // add data unit ID and the creating KMA IP address to the DU cache
        CDataUnitCache* pDataUnitCache = (CDataUnitCache*) i_pProfile->m_pDataUnitCache;

        if (i_pProfile->m_iClusterDiscoveryFrequency != 0) // load balancing enabled
        {
            bSuccess = pDataUnitCache->Insert(
                    o_pDataUnit->m_acDataUnitID,
                    KMS_DATA_UNIT_ID_SIZE,
                    NULL, 0,
                    pLoadBalancer->GetApplianceNetworkAddress(iIndex));
        }
    }

    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile, iIndex));
}

extern "C"
KMS_AGENT_STATUS KMSAgent_DisassociateDataUnitKeys (
                                                    KMSClientProfile * const i_pProfile,
                                                    const KMSAgent_DataUnit * const i_pDataUnit)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_DisassociateDataUnitKeys);
#endif

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_DISASSOCIATE_DATA_UNIT_KEYS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!i_pDataUnit)
    {
        Log(AUDIT_CLIENT_AGENT_DISASSOCIATE_DATA_UNIT_KEYS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "DataUnit arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    struct KMS_Agent::KMS_Agent__DataUnit stDataUnit = {(char *)"",
        (char *)"", (char *)"", (char *)"",
        (KMS_Agent::KMS_Agent__DataUnitState) 0};

    struct soap *pstSoap = (struct soap *) i_pProfile->m_pvSoap;
    struct KMS_Agent::KMS_Agent__DisassociateDataUnitKeysResponse oResponse;

    if (!CopyDataUnitFromRequest(pstSoap,
        &stDataUnit,
        i_pDataUnit))
    {
        soap_destroy(pstSoap);
        soap_end(pstSoap);
        // no memory dont' log
        RETURN(KMS_AGENT_STATUS_NO_MEMORY);
    }

    CAgentLoadBalancer *pLoadBalancer =
            (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;
    int iIndex = pLoadBalancer->BalanceByDataUnitID(
            i_pDataUnit->m_acDataUnitID,
            KMS_DATA_UNIT_ID_SIZE);

    if (iIndex >= 0)
    {
        do
        {
            const char* sURL = pLoadBalancer->GetHTTPSURL(
                    iIndex,
                    i_pProfile->m_iPortForAgentService);

            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));

            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = '\0';

            bSuccess = KMS_Agent::soap_call_KMS_Agent__DisassociateDataUnitKeys(
                    pstSoap,
                    sURL,
                    NULL,
                    stDataUnit,
                    oResponse) == SOAP_OK;

            if (!bSuccess)
            {
                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
                char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];

                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                GetSoapFault(sSoapFaultMsg, pstSoap);

                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_DISASSOCIATE_DATA_UNIT_KEYS_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            else
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }
        }
        while (iIndex >= 0 && (!bSuccess));
    }
    else
    {
        bSuccess = false;
    }

    // no response data for this transaction

    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile, iIndex));
}

extern "C"
KMS_AGENT_STATUS KMSAgent_RetrieveKey (
                                       KMSClientProfile * const i_pProfile,
                                       const unsigned char * const i_pKeyID,
                                       const KMSAgent_DataUnit * const i_pDataUnit,
                                       utf8cstr const i_pKeyGroupID,
                                       KMSAgent_Key * const o_pKey)
{
    bool bSuccess;

#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_RetrieveKey);
#endif

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!i_pKeyID)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "KeyID arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!o_pKey)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Key arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    if (i_pKeyGroupID &&
        strlen(i_pKeyGroupID) > KMS_MAX_KEY_GROUP_ID_SIZE)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "GroupID arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    struct KMS_Agent::KMS_Agent__DataUnit stDataUnit = {
        (char *)"", (char *)"", (char *)"", (char *)"",
        (KMS_Agent::KMS_Agent__DataUnitState) 0};

    struct soap *pstSoap = (struct soap *) i_pProfile->m_pvSoap;
    struct KMS_Agent::KMS_Agent__RetrieveKeyResponse oResponse;

    char * pKeyID = NULL;
    pKeyID = ConvertBinaryDataFromRequest(pstSoap,
            i_pKeyID,
            KMS_KEY_ID_SIZE);
    if (pKeyID == NULL)
    {
        soap_destroy(pstSoap);
        soap_end(pstSoap);
        // no memory dont' log
        RETURN(KMS_AGENT_STATUS_NO_MEMORY);
    }

    if (i_pDataUnit != NULL)
    {
        if (!CopyDataUnitFromRequest(pstSoap,
            &stDataUnit,
            i_pDataUnit))
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    char * pKeyGroupID = NULL;
    if (i_pKeyGroupID)
    {
        pKeyGroupID = ConvertUTF8StringFromRequest(pstSoap,
                i_pKeyGroupID,
                KMS_MAX_KEY_GROUP_ID_SIZE + 1);
        if (pKeyGroupID == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    UTF8_KEYID acKWKID;

    char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
    char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];
    bool bClientAESKeyWrapSetupError = false;

    CAgentLoadBalancer *pLoadBalancer =
            (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;
    int iIndex = pLoadBalancer->BalanceByDataUnitKeyID(i_pKeyID, KMS_KEY_ID_SIZE);

    if (iIndex >= 0)
    {
        do
        {
            bSuccess = true;
            const char* sURL = pLoadBalancer->GetHTTPSURL(
                    iIndex,
                    i_pProfile->m_iPortForAgentService);

            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));

            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = '\0';

            Long64 lKMAID = pLoadBalancer->GetKMAID(iIndex);

            if (bSuccess && pLoadBalancer->AESKeyWrapSupported(iIndex))
            {
                // if this fails we want to utilize normal failover logic, GetKWKID
                // logs error
                bSuccess = pLoadBalancer->GetKWKID(iIndex, lKMAID, pstSoap,
					acKWKID, &bClientAESKeyWrapSetupError) ? true : false;
                if (bSuccess)
                {
                    bSuccess = KMS_Agent::soap_call_KMS_Agent__RetrieveKey2(
                            pstSoap,
                            sURL,
                            NULL,
                            pKeyID,
                            stDataUnit,
                            i_pKeyGroupID ? i_pKeyGroupID : (char *) "",
                            acKWKID,
                            //NOTE: this is ugly but the soap response struct's are the same for both flavors of CreateKey
                            *(reinterpret_cast<struct KMS_Agent::KMS_Agent__RetrieveKey2Response *>(&oResponse))) == SOAP_OK;
                }
            }
            else if (bSuccess)  // NO AES Key Wrap
            {
                    bSuccess = KMS_Agent::soap_call_KMS_Agent__RetrieveKey(
                            pstSoap,
                            sURL,
                            NULL,
                            pKeyID,
                            stDataUnit,
                            i_pKeyGroupID ? i_pKeyGroupID : (char *) "",
                            oResponse) == SOAP_OK;
            }

            // don'f failover for Client side AES Key Wrap setup problems
            if (!bSuccess && !bClientAESKeyWrapSetupError)
            {
                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                GetSoapFault(sSoapFaultMsg, pstSoap);

                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_KEY_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            if (bSuccess)
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }
        }
        while (iIndex >= 0 && (!bSuccess) && (!bClientAESKeyWrapSetupError));
    }
    else
    {
        bSuccess = false;
    }

    if (bSuccess)
    {
        if (KMS_KEY_ID_SIZE != ConvertUTF8HexStringToBinary(
            oResponse.Key.KeyID, NULL))
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEYID_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }
    }

    if (bSuccess)
    {
        ConvertUTF8HexStringToBinary(
                oResponse.Key.KeyID, o_pKey->m_acKeyID);

        //if ( oResponse.Key.KeyState < (KMS_Agent__KeyState)KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS ||
        //    oResponse.Key.KeyState > (KMS_Agent__KeyState)KMS_KEY_STATE_COMPROMISED )
        if ((KMS_AGENT_KEY_STATE) oResponse.Key.KeyState < KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS ||
            (KMS_AGENT_KEY_STATE) oResponse.Key.KeyState > KMS_KEY_STATE_COMPROMISED)
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEY_STATE_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }

        o_pKey->m_iKeyState = (KMS_AGENT_KEY_STATE) oResponse.Key.KeyState;

        if ((KMS_KEY_TYPE) oResponse.Key.KeyType != KMS_KEY_TYPE_AES_256)
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEY_TYPE_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }

        o_pKey->m_iKeyType = (KMS_KEY_TYPE) oResponse.Key.KeyType;

        if (strlen(oResponse.Key.KeyGroupID) > KMS_MAX_KEY_GROUP_ID_SIZE)
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEY_GROUP_ID_LENGTH_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }
        else
        {
            strncpy(o_pKey->m_acKeyGroupID,
                    oResponse.Key.KeyGroupID,
                    sizeof(o_pKey->m_acKeyGroupID));
            o_pKey->m_acKeyGroupID[sizeof(o_pKey->m_acKeyGroupID)-1] = '\0';
        }

        if ( bSuccess && pLoadBalancer->AESKeyWrapSupported(iIndex))
        {
            // verify KWK ID matches what was registered
            if (oResponse.Key.Key.__size != KMS_MAX_WRAPPED_KEY_SIZE)
            {
                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_WRAPPED_KEY_LENGTH_RESPONSE,
                        NULL,
                        sKmaAddress,
                        NULL);
                bSuccess = false;
            }
            else
            {
                if (pLoadBalancer->AESKeyUnwrap(&iIndex, oResponse.Key.Key.__ptr,
                    o_pKey->m_acKey) == false)
                {
                    GetPeerNetworkAddress(sKmaAddress, pstSoap);
                    LogError(i_pProfile,
                            AUDIT_CLIENT_AGENT_RETRIEVE_KEY_AESKEYUNWRAP_ERROR,
                            NULL,
                            sKmaAddress,
                            NULL);

                    bSuccess = false;
                }
            }
        }
        else if (bSuccess) // non-AES key wrap
        {
            if (oResponse.Key.Key.__size != KMS_MAX_KEY_SIZE)
            {
                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_KEY_INVALID_KEY_LENGTH_RESPONSE,
                        NULL,
                        sKmaAddress,
                        NULL);
                bSuccess = false;
            }
            else
            {
                memcpy(o_pKey->m_acKey,
                        oResponse.Key.Key.__ptr,
                        KMS_MAX_KEY_SIZE);
            }
        }

        if (bSuccess)
        {
            o_pKey->m_iKeyLength = KMS_MAX_KEY_SIZE;

            if (KMSAgentKeyCallout(o_pKey->m_acKey) != 0)
            {
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_KEY_KEY_CALLOUT_ERROR,
                        NULL,
                        NULL,
                        NULL);
                bSuccess = false;
            }
        }
    }

    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile,
            bClientAESKeyWrapSetupError ?
                CAgentLoadBalancer::AES_KEY_WRAP_SETUP_ERROR : iIndex));
}

extern "C"
KMS_AGENT_STATUS KMSAgent_RetrieveDataUnit (
                                            KMSClientProfile * const i_pProfile,
                                            const unsigned char * const i_pDataUnitID,
                                            const unsigned char * const i_pExternalUniqueID,
                                            int i_iExternalUniqueIDLen,
                                            utf8cstr const i_pExternalTag,
                                            utf8cstr const i_pDescription,
                                            KMSAgent_DataUnit * const o_pDataUnit)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_RetrieveDataUnit);
#endif

#if defined(DEBUG) && defined(METAWARE)
    log_printf("KMSAgent_RetrieveDataUnit entered\n");
#endif

    // required parms
    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!i_pDataUnitID)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_INVALID_PARAMETERS,
                NULL,
                NULL,
                "DataUnitID arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!o_pDataUnit)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_INVALID_PARAMETERS,
                NULL,
                NULL,
                "DataUnit arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }



    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
#if defined(DEBUG) && defined(METAWARE)
        log_printf("KMSAgent_RetrieveDataUnit profile not loaded\n");
#endif
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    // validate input parms

    if (i_pExternalUniqueID &&
        (i_iExternalUniqueIDLen <= 0 ||
        i_iExternalUniqueIDLen > KMS_MAX_EXTERNAL_UNIQUE_ID_SIZE))
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ExternalUniqueID arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_pExternalTag && strlen(i_pExternalTag) > KMS_MAX_EXTERNAL_TAG)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ExternalTag arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_pDescription &&
        strlen(i_pDescription) > KMS_MAX_DESCRIPTION)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Description arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    // prepare args to soap transaction

    struct soap *pstSoap = (struct soap *) i_pProfile->m_pvSoap;
    struct KMS_Agent::KMS_Agent__RetrieveDataUnitResponse oResponse;

    char * pDataUnitID = NULL;
    pDataUnitID = ConvertBinaryDataFromRequest(pstSoap,
            i_pDataUnitID,
            KMS_DATA_UNIT_ID_SIZE);
    //sizeof(DATA_UNIT_ID) );
    if (pDataUnitID == NULL)
    {
        soap_destroy(pstSoap);
        soap_end(pstSoap);
        // no memory dont' log
        RETURN(KMS_AGENT_STATUS_NO_MEMORY);
    }

    char * pExternalUniqueID = NULL;
    if (i_pExternalUniqueID)
    {
        pExternalUniqueID = ConvertBinaryDataFromRequest(pstSoap,
                i_pExternalUniqueID,
                i_iExternalUniqueIDLen);
        if (pExternalUniqueID == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    char * pExternalTag = NULL;
    if (i_pExternalTag)
    {
        pExternalTag = ConvertUTF8StringFromRequest(pstSoap,
                i_pExternalTag,
                KMS_MAX_EXTERNAL_TAG + 1);
        if (pExternalTag == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    char * pDescription = NULL;
    if (i_pDescription)
    {
        pDescription = ConvertUTF8StringFromRequest(pstSoap,
                i_pDescription,
                KMS_MAX_DESCRIPTION + 1);
        if (pDescription == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    CAgentLoadBalancer *pLoadBalancer =
            (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;
    int iIndex = pLoadBalancer->BalanceByDataUnitID(i_pDataUnitID,
            KMS_DATA_UNIT_ID_SIZE);

    if ( iIndex >= 0 )
    {
        do
        {
            const char* sURL = pLoadBalancer->GetHTTPSURL(
                    iIndex,
                    i_pProfile->m_iPortForAgentService);

            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));

            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = '\0';

            bSuccess = KMS_Agent::soap_call_KMS_Agent__RetrieveDataUnit(
                    pstSoap,
                    sURL,
                    NULL,
                    pDataUnitID,
                    i_pExternalUniqueID ? pExternalUniqueID : (char *) "",
                    i_pExternalTag ? pExternalTag : (char *) "",
                    i_pDescription ? pDescription : (char *) "",
                    oResponse) == SOAP_OK;

            if (!bSuccess)
            {
                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
                char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];

                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                GetSoapFault(sSoapFaultMsg, pstSoap);

                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            else
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }
        }
        while (iIndex >= 0 && (!bSuccess));
    }
    else
    {
        bSuccess = false;
    }

    if (bSuccess)
    {
        ConvertUTF8HexStringToBinary(
                oResponse.DataUnit.DataUnitID, o_pDataUnit->m_acDataUnitID);

        o_pDataUnit->m_iExternalUniqueIDLength = ConvertUTF8HexStringToBinary(
                oResponse.DataUnit.ExternalUniqueID, o_pDataUnit->m_acExternalUniqueID);

        if (strlen(oResponse.DataUnit.ExternalTag) > KMS_MAX_EXTERNAL_TAG)
        {
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_RESPONSE_INVALID_EXTERNAL_TAG_LENGTH,
                    NULL,
                    NULL,
                    NULL);
            bSuccess = false;
        }
        else
        {
            strncpy(o_pDataUnit->m_acExternalTag,
                    oResponse.DataUnit.ExternalTag,
                    sizeof(o_pDataUnit->m_acExternalTag));
            o_pDataUnit->m_acExternalTag[sizeof(o_pDataUnit->m_acExternalTag)-1] = '\0';
        }

        if (strlen(oResponse.DataUnit.Description) > KMS_MAX_DESCRIPTION)
        {
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_RESPONSE_INVALID_DESCRIPTION_LENGTH,
                    NULL,
                    NULL,
                    NULL);
            bSuccess = false;
        }
        else
        {
            strcpy(o_pDataUnit->m_acDescription,
                    oResponse.DataUnit.Description);
        }

        o_pDataUnit->m_iDataUnitState =
                (KMS_AGENT_DATA_UNIT_STATE) oResponse.DataUnit.DataUnitState;
    }

    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile, iIndex));
}

extern "C"
KMS_AGENT_STATUS KMSAgent_RetrieveDataUnitByExternalUniqueID (
                                                              KMSClientProfile * const i_pProfile,
                                                              const unsigned char* const i_pExternalUniqueID,
                                                              int i_iExternalUniqueIDLen,
                                                              utf8cstr const i_pExternalTag,
                                                              utf8cstr const i_pDescription,
                                                              KMSAgent_DataUnit * const o_pDataUnit)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_RetrieveDataUnitByExternalUniqueID);
#endif

    // required parms
    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!i_pExternalUniqueID)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ExternalUniqueID arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!o_pDataUnit)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_INVALID_PARAMETERS,
                NULL,
                NULL,
                "DataUnit arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    // validate input parms

    if (i_iExternalUniqueIDLen <= 0 ||
        i_iExternalUniqueIDLen > KMS_MAX_EXTERNAL_UNIQUE_ID_SIZE)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ExternalUniqueIDLen arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_pExternalTag && strlen(i_pExternalTag) > KMS_MAX_EXTERNAL_TAG)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_INVALID_PARAMETERS,
                NULL,
                NULL,
                "ExternalTag arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_pDescription &&
        strlen(i_pDescription) > KMS_MAX_DESCRIPTION)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Description arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    // prepare args to soap transaction

    struct soap *pstSoap = (struct soap *) i_pProfile->m_pvSoap;
    struct KMS_Agent::KMS_Agent__RetrieveDataUnitByExternalUniqueIDResponse oResponse;

    char * pExternalUniqueID = NULL;
    pExternalUniqueID = ConvertBinaryDataFromRequest(pstSoap,
            i_pExternalUniqueID,
            i_iExternalUniqueIDLen);
    if (pExternalUniqueID == NULL)
    {
        soap_destroy(pstSoap);
        soap_end(pstSoap);
        // no memory dont' log
        RETURN(KMS_AGENT_STATUS_NO_MEMORY);
    }

    char * pExternalTag = NULL;
    if (i_pExternalTag)
    {
        pExternalTag = ConvertUTF8StringFromRequest(pstSoap,
                i_pExternalTag,
                KMS_MAX_EXTERNAL_TAG + 1);
        if (pExternalTag == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    char * pDescription = NULL;
    if (i_pDescription)
    {
        pDescription = ConvertUTF8StringFromRequest(pstSoap,
                i_pDescription,
                KMS_MAX_DESCRIPTION + 1);
        if (pDescription == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    CAgentLoadBalancer *pLoadBalancer =
            (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;
    int iIndex = pLoadBalancer->Balance();

    if ( iIndex >= 0 )
    {
        do
        {
            const char* sURL = pLoadBalancer->GetHTTPSURL(
                    iIndex,
                    i_pProfile->m_iPortForAgentService);

            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));

            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = '\0';

            bSuccess = KMS_Agent::
                    soap_call_KMS_Agent__RetrieveDataUnitByExternalUniqueID(
                    pstSoap,
                    sURL,
                    NULL,
                    pExternalUniqueID,
                    i_pExternalTag ? pExternalTag : (char *) "",
                    i_pDescription ? pDescription : (char *) "",
                    oResponse) == SOAP_OK;

            if (!bSuccess)
            {
                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
                char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];

                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                GetSoapFault(sSoapFaultMsg, pstSoap);

                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            else
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }
        }
        while (iIndex >= 0 && (!bSuccess));
    }
    else
    {
        bSuccess = false;
    }

    if (bSuccess)
    {
        ConvertUTF8HexStringToBinary(
                oResponse.DataUnit.DataUnitID, o_pDataUnit->m_acDataUnitID);

        o_pDataUnit->m_iExternalUniqueIDLength = ConvertUTF8HexStringToBinary(
                oResponse.DataUnit.ExternalUniqueID,
                o_pDataUnit->m_acExternalUniqueID);

        if (strlen(oResponse.DataUnit.ExternalTag) > KMS_MAX_EXTERNAL_TAG)
        {
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_RESPONSE_INVALID_EXTERNAL_TAG_LENGTH,
                    NULL,
                    NULL,
                    NULL);
            bSuccess = false;
        }
        else
        {
            strncpy(o_pDataUnit->m_acExternalTag,
                    oResponse.DataUnit.ExternalTag,
                    sizeof(o_pDataUnit->m_acExternalTag));
            o_pDataUnit->m_acExternalTag[sizeof(o_pDataUnit->m_acExternalTag)-1] = '\0';
        }

        if (strlen(oResponse.DataUnit.Description) > KMS_MAX_DESCRIPTION)
        {
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_BY_EXTERNAL_UNIQUE_ID_RESPONSE_INVALID_DESCRIPTION_LENGTH,
                    NULL,
                    NULL,
                    NULL);
            bSuccess = false;
        }
        else
        {
            strcpy(o_pDataUnit->m_acDescription,
                    oResponse.DataUnit.Description);
        }

        o_pDataUnit->m_iDataUnitState =
                (KMS_AGENT_DATA_UNIT_STATE) oResponse.DataUnit.DataUnitState;

        if (bSuccess)
        {
            // RetrieveDataUnitByExternalUniqueID may create a DU so add data unit ID
            // and the KMA IP address to the DU cache
            CDataUnitCache* pDataUnitCache = (CDataUnitCache*) i_pProfile->m_pDataUnitCache;

            if (i_pProfile->m_iClusterDiscoveryFrequency != 0) // load balancing enabled
            {
                bSuccess = pDataUnitCache->Insert(
                        o_pDataUnit->m_acDataUnitID,
                        KMS_DATA_UNIT_ID_SIZE,
                        NULL, 0,
                        pLoadBalancer->GetApplianceNetworkAddress(iIndex));
            }
        }
    }

    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile, iIndex));
}

extern "C"
KMS_AGENT_STATUS KMSAgent_RetrieveDataUnitKeys (
                                                KMSClientProfile * const i_pProfile,
                                                const KMSAgent_DataUnit * const i_pDataUnit,
                                                int i_iPageSize,
                                                int i_iPageOffset,
                                                int* const o_piKeysRemaining,
                                                const unsigned char * const i_pKeyID,
                                                KMSAgent_ArrayOfKeys* * const o_ppKeys)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_RetrieveDataUnitKeys);
#endif

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!i_pDataUnit)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "DataUnit arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!o_piKeysRemaining)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "KeysRemaining arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!o_ppKeys)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Keys arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (i_pKeyID && i_iPageOffset != 0)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "KeyID and PageOffset are mutually exclusive");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    // validate input parms

    if (i_iPageSize <= 0 || i_iPageSize > KMS_MAX_PAGE_SIZE)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "PageSize arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_iPageOffset < 0)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_PARAMETERS,
                NULL,
                NULL,
                "PageOffset arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    // prepare args to soap transaction

    struct KMS_Agent::KMS_Agent__DataUnit stDataUnit = {
        (char *)"", (char *)"", (char *)"", (char *)"",
        (KMS_Agent::KMS_Agent__DataUnitState) 0};

    struct soap *pstSoap = (struct soap *) i_pProfile->m_pvSoap;
    struct KMS_Agent::KMS_Agent__RetrieveDataUnitKeysResponse oResponse;

    if (!CopyDataUnitFromRequest(pstSoap,
        &stDataUnit,
        i_pDataUnit))
    {
        soap_destroy(pstSoap);
        soap_end(pstSoap);
        // no memory dont' log
        RETURN(KMS_AGENT_STATUS_NO_MEMORY);
    }

    char * pKeyID = NULL;
    if (i_pKeyID)
    {
        pKeyID = ConvertBinaryDataFromRequest(pstSoap,
                i_pKeyID,
                KMS_KEY_ID_SIZE);
        if (pKeyID == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    UTF8_KEYID acKWKID;
    char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
    char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];
    bool bClientAESKeyWrapSetupError = false;

    CAgentLoadBalancer *pLoadBalancer =
            (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;

    int iIndex = pLoadBalancer->BalanceByDataUnitID(i_pDataUnit->m_acDataUnitID,
            KMS_DATA_UNIT_ID_SIZE);

    if (iIndex >= 0)
    {
        do
        {
            bSuccess = true;

            const char* sURL = pLoadBalancer->GetHTTPSURL(
                    iIndex,
                    i_pProfile->m_iPortForAgentService);

            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));

            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = 0;

            Long64 lKMAID = pLoadBalancer->GetKMAID(iIndex);

            if (bSuccess && pLoadBalancer->AESKeyWrapSupported(iIndex))
            {
                // if this fails we want to utilize normal failover logic, GetKWKID
                // logs error
                bSuccess = pLoadBalancer->GetKWKID(iIndex, lKMAID, pstSoap,
					acKWKID, &bClientAESKeyWrapSetupError) ? true : false;
                if (bSuccess)
                {
                    bSuccess = KMS_Agent::soap_call_KMS_Agent__RetrieveDataUnitKeys2(
                            pstSoap,
                            sURL,
                            NULL,
                            stDataUnit,
                            i_iPageSize,
                            i_iPageOffset,
                            pKeyID,
                            acKWKID,
                            *(reinterpret_cast<struct KMS_Agent::KMS_Agent__RetrieveDataUnitKeys2Response *>(&oResponse))) == SOAP_OK;
                }
            }
            else if (bSuccess)  // No AES Key Wrap
            {
                    bSuccess = KMS_Agent::soap_call_KMS_Agent__RetrieveDataUnitKeys(
                            pstSoap,
                            sURL,
                            NULL,
                            stDataUnit,
                            i_iPageSize,
                            i_iPageOffset,
                            pKeyID,
                            oResponse) == SOAP_OK;
            }

            // don'f failover for Client side AES Key Wrap setup problems
            if (!bSuccess && !bClientAESKeyWrapSetupError)
            {
                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                GetSoapFault(sSoapFaultMsg, pstSoap);

                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            if (bSuccess)
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }
        }
        while (iIndex >= 0 && (!bSuccess) && (!bClientAESKeyWrapSetupError));
    }
    else
    {
        bSuccess = false;
    }

    // validate response

    if (bSuccess && oResponse.KeysRemaining < 0)
    {
        LogError(i_pProfile,
                AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEYS_REMAINING_RESPONSE,
                NULL,
                NULL,
                NULL);
        bSuccess = false;
    }

    if (bSuccess &&
        (oResponse.Keys.__size < 0 ||
        oResponse.Keys.__size > i_iPageSize))
    {
        LogError(i_pProfile,
                AUDIT_CLIENT_AGENT_RETRIEVE_DATA_UNIT_KEYS_INVALID_KEYS_SIZE_RESPONSE,
                NULL,
                NULL,
                NULL);
        bSuccess = false;
    }

    if ( bSuccess && pLoadBalancer->AESKeyWrapSupported(iIndex))
    {
        // verify KWK ID matches what was registered
    }

    if (bSuccess)
    {
        *o_ppKeys = CopyDataUnitKeysResponse(i_pProfile, &iIndex, &oResponse.Keys);

        if (*o_ppKeys == NULL)
        {
            // CopyDataUnitKeysResponse logs errors
            bSuccess = false;
        }
        *o_piKeysRemaining = (int) oResponse.KeysRemaining;
    }

    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile,
            bClientAESKeyWrapSetupError ?
                CAgentLoadBalancer::AES_KEY_WRAP_SETUP_ERROR : iIndex));
}

extern "C"
KMS_AGENT_STATUS KMSAgent_RetrieveProtectAndProcessKey (
                                                        KMSClientProfile * const i_pProfile,
                                                        const KMSAgent_DataUnit * const i_pDataUnit,
                                                        utf8cstr const i_pKeyGroupID,
                                                        KMSAgent_Key * const o_pKey)
{
    bool bSuccess;
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_RetrieveProtectAndProcessKey);
#endif

    if (!i_pProfile || !i_pDataUnit || !o_pKey)
    {
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!i_pDataUnit)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "DataUnit arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!o_pKey)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Key arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_pKeyGroupID &&
        strlen(i_pKeyGroupID) > KMS_MAX_KEY_GROUP_ID_SIZE)
    {
        Log(AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_PARAMETERS,
                NULL,
                NULL,
                "GroupID arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    struct KMS_Agent::KMS_Agent__DataUnit stDataUnit = {
        (char *)"", (char *)"", (char *)"", (char *)"",
        (KMS_Agent::KMS_Agent__DataUnitState) 0};

    struct soap *pstSoap = (struct soap *) i_pProfile->m_pvSoap;
    struct KMS_Agent::KMS_Agent__RetrieveProtectAndProcessKeyResponse oResponse;

    if (i_pDataUnit != NULL)
    {
        if (!CopyDataUnitFromRequest(pstSoap,
            &stDataUnit,
            i_pDataUnit))
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    char * pKeyGroupID = NULL;
    if (i_pKeyGroupID)
    {
        pKeyGroupID = ConvertUTF8StringFromRequest(pstSoap,
                i_pKeyGroupID,
                KMS_MAX_KEY_GROUP_ID_SIZE + 1);
        if (pKeyGroupID == NULL)
        {
            soap_destroy(pstSoap);
            soap_end(pstSoap);
            // no memory dont' log
            RETURN(KMS_AGENT_STATUS_NO_MEMORY);
        }
    }

    char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
    char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];
    bool bClientAESKeyWrapSetupError = false;
    UTF8_KEYID acKWKID;

    CAgentLoadBalancer *pLoadBalancer = (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;
    int iIndex = pLoadBalancer->BalanceByDataUnitID(i_pDataUnit->m_acDataUnitID,
                                                    KMS_DATA_UNIT_ID_SIZE);

    if (iIndex >= 0)
    {
        do
        {
            bSuccess = true;
            const char* sURL = pLoadBalancer->GetHTTPSURL(
                    iIndex,
                    i_pProfile->m_iPortForAgentService);

            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));

            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = '\0';

            Long64 lKMAID = pLoadBalancer->GetKMAID(iIndex);

            if (bSuccess && pLoadBalancer->AESKeyWrapSupported(iIndex))
            {
                // if this fails we want to utilize normal failover logic, GetKWKID
                // logs error
                bSuccess = pLoadBalancer->GetKWKID(iIndex, lKMAID, pstSoap,
                                            acKWKID, &bClientAESKeyWrapSetupError)
											? true : false;
                if (bSuccess)
                {
                    bSuccess = KMS_Agent::soap_call_KMS_Agent__RetrieveProtectAndProcessKey2(
                            pstSoap,
                            sURL,
                            NULL,
                            stDataUnit,
                            i_pKeyGroupID ? i_pKeyGroupID : (char *) "",
                            acKWKID,
                            *(reinterpret_cast<struct KMS_Agent::KMS_Agent__RetrieveProtectAndProcessKey2Response *>(&oResponse))) == SOAP_OK;
                }
            }
            else if (bSuccess)  // No AES Key Wrap
            {
                    bSuccess = KMS_Agent::soap_call_KMS_Agent__RetrieveProtectAndProcessKey(
                            pstSoap,
                            sURL,
                            NULL,
                            stDataUnit,
                            i_pKeyGroupID ? i_pKeyGroupID : (char *) "",
                            oResponse) == SOAP_OK;
            }

            // don'f failover for Client side AES Key Wrap setup problems
            if (!bSuccess && !bClientAESKeyWrapSetupError)
            {
                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                GetSoapFault(sSoapFaultMsg, pstSoap);

                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            else
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }
        }
        while (iIndex >= 0 && (!bSuccess) && (!bClientAESKeyWrapSetupError));
    }
    else
    {
        bSuccess = false;
    }

    if (bSuccess)
    {
        if (KMS_KEY_ID_SIZE != ConvertUTF8HexStringToBinary(
            oResponse.Key.KeyID, NULL))
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEYID_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }
    }

    if (bSuccess)
    {
        ConvertUTF8HexStringToBinary(
                oResponse.Key.KeyID, o_pKey->m_acKeyID);

        if ((KMS_AGENT_KEY_STATE) oResponse.Key.KeyState < KMS_KEY_STATE_ACTIVE_PROTECT_AND_PROCESS ||
            (KMS_AGENT_KEY_STATE) oResponse.Key.KeyState > KMS_KEY_STATE_COMPROMISED)
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEY_STATE_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }

        o_pKey->m_iKeyState = (KMS_AGENT_KEY_STATE) oResponse.Key.KeyState;

        if ((KMS_KEY_TYPE) oResponse.Key.KeyType != KMS_KEY_TYPE_AES_256)
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEY_TYPE_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }

        o_pKey->m_iKeyType = (KMS_KEY_TYPE) oResponse.Key.KeyType;

        if (strlen(oResponse.Key.KeyGroupID) > KMS_MAX_KEY_GROUP_ID_SIZE)
        {
            GetPeerNetworkAddress(sKmaAddress, pstSoap);
            LogError(i_pProfile,
                    AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEY_GROUP_ID_LENGTH_RESPONSE,
                    NULL,
                    sKmaAddress,
                    NULL);
            bSuccess = false;
        }
        else
        {
            strncpy(o_pKey->m_acKeyGroupID,
                    oResponse.Key.KeyGroupID,
                    sizeof(o_pKey->m_acKeyGroupID));
            o_pKey->m_acKeyGroupID[sizeof(o_pKey->m_acKeyGroupID)-1] = '\0';
        }

        if ( bSuccess && pLoadBalancer->AESKeyWrapSupported(iIndex))
        {
            // verify KWK ID matches what was registered
            if (oResponse.Key.Key.__size != KMS_MAX_WRAPPED_KEY_SIZE)
            {
                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_WRAPPED_KEY_LENGTH_RESPONSE,
                        NULL,
                        sKmaAddress,
                        NULL);
                bSuccess = false;
            }
            else
            {
                if (pLoadBalancer->AESKeyUnwrap(&iIndex, oResponse.Key.Key.__ptr,
                    o_pKey->m_acKey) == false)
                {
                    GetPeerNetworkAddress(sKmaAddress, pstSoap);
                    LogError(i_pProfile,
                            AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_AESKEYUNWRAP_ERROR,
                            NULL,
                            sKmaAddress,
                            NULL);

                    bSuccess = false;
                }
            }
        }
        else if (bSuccess) // non-AES key wrap
        {
            if (oResponse.Key.Key.__size != KMS_MAX_KEY_SIZE)
            {
                GetPeerNetworkAddress(sKmaAddress, pstSoap);
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_INVALID_KEY_LENGTH_RESPONSE,
                        NULL,
                        sKmaAddress,
                        NULL);
                bSuccess = false;
            }
            else
            {
                memcpy(o_pKey->m_acKey,
                        oResponse.Key.Key.__ptr,
                        KMS_MAX_KEY_SIZE);
            }
        }

        if (bSuccess)
        {
            o_pKey->m_iKeyLength = KMS_MAX_KEY_SIZE;

            if (KMSAgentKeyCallout(o_pKey->m_acKey) != 0)
            {
                LogError(i_pProfile,
                        AUDIT_CLIENT_AGENT_RETRIEVE_PROTECT_AND_PROCESS_KEY_KEY_CALLOUT_ERROR,
                        NULL,
                        NULL,
                        NULL);
                bSuccess = false;
            }
        }
    }

    if (bSuccess)
    {
        // add Key ID and the creating KMA IP address to the DU cache
        CDataUnitCache* pDataUnitCache = (CDataUnitCache*) i_pProfile->m_pDataUnitCache;

        if (i_pProfile->m_iClusterDiscoveryFrequency != 0) // load balancing enabled
        {
            bSuccess = pDataUnitCache->Insert(
                    NULL,
                    0,
                    o_pKey->m_acKeyID,
                    KMS_KEY_ID_SIZE,
                    pLoadBalancer->GetApplianceNetworkAddress(iIndex));
        }
    }
    
    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
    {
        RETURN(KMS_AGENT_STATUS_OK);
    }

    RETURN(KMSAgent_GetLastStatusCode(i_pProfile,
            bClientAESKeyWrapSetupError ?
                CAgentLoadBalancer::AES_KEY_WRAP_SETUP_ERROR : iIndex));
}

extern "C"
void KMSAgent_FreeArrayOfKeys (
                               KMSAgent_ArrayOfKeys* i_pArrayOfKeys)
{
#if defined(METAWARE)
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_FreeArrayOfKeys);
#endif
    if (!i_pArrayOfKeys)
    {
        return;
    }

    // free memory for all information groups
    if (i_pArrayOfKeys->m_pKeys)
    {
        free(i_pArrayOfKeys->m_pKeys);
    }

    free(i_pArrayOfKeys);
}

/*---------------------------------------------------------------------------
 * Function: KMSAgent_CreateAuditLog
 *
 *--------------------------------------------------------------------------*/
extern "C"
KMS_AGENT_STATUS KMSAgent_CreateAuditLog (
                                          KMSClientProfile* i_pProfile,
                                          enum KMS_AUDIT_LOG_RETENTION i_iRetention,
                                          enum KMS_AUDIT_LOG_CONDITION i_iCondition,
                                          int i_bIssueAlert,
                                          utf8cstr i_pMessage)
{
    bool bSuccess = true;
#ifdef DEBUG_TIMING
    ECPT_TRACE_ENTRY *trace = NULL;
    ECPT_TRACE(trace, KMSAgent_CreateAuditLog);
#endif

    //   START_STACK_CHECK;

    if (!i_pProfile)
    {
        Log(AUDIT_CLIENT_AGENT_CREATED_AUDIT_LOG_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Profile arg");

        //        END_STACK_CHECK;

        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    // check arguments
    if (i_iRetention > KMS_AUDIT_LOG_SHORT_TERM_RETENTION)
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_AUDIT_LOG_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Retention arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (i_iCondition > KMS_AUDIT_LOG_WARNING_CONDITION)
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_AUDIT_LOG_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Condition arg");
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }

    if (!i_pMessage || (strlen(i_pMessage) <= 0))
    {
        Log(AUDIT_CLIENT_AGENT_CREATE_AUDIT_LOG_INVALID_PARAMETERS,
                NULL,
                NULL,
                "Message arg");
        //       END_STACK_CHECK;
        RETURN(KMS_AGENT_STATUS_INVALID_PARAMETER);
    }
    if (!KMSClient_ProfileLoaded(i_pProfile))
    {
        //        END_STACK_CHECK;
        RETURN(KMS_AGENT_STATUS_PROFILE_NOT_LOADED);
    }

    CAutoMutex oAutoMutex((K_MUTEX_HANDLE) i_pProfile->m_pLock);

    struct soap* pstSoap = (struct soap*) i_pProfile->m_pvSoap;

    // Create Audit Log

    KMS_Agent::KMS_Agent__CreateAuditLogResponse oResponse;

    CAgentLoadBalancer *pLoadBalancer =
            (CAgentLoadBalancer *) i_pProfile->m_pAgentLoadBalancer;

    int iIndex = pLoadBalancer->Balance();
    if (iIndex >= 0)
    {
        do
        {
            const char* sURL = pLoadBalancer->
                    GetHTTPSURL(iIndex, i_pProfile->m_iPortForAgentService);
            strncpy(i_pProfile->m_sURL, sURL, sizeof(i_pProfile->m_sURL));
            i_pProfile->m_sURL[sizeof(i_pProfile->m_sURL)-1] = '\0';

            bSuccess = KMS_Agent::soap_call_KMS_Agent__CreateAuditLog(
                    pstSoap,
                    sURL,
                    NULL,
                    (enum KMS_Agent::KMS_Agent__AuditLogRetention)i_iRetention,
                    (enum KMS_Agent::KMS_Agent__AuditLogCondition)i_iCondition,
                    i_bIssueAlert ? true : false,
                    i_pMessage,
                    oResponse) == SOAP_OK;


            if (!bSuccess)
            {
                char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];
                char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];

                GetSoapFault(sSoapFaultMsg, pstSoap);
                GetPeerNetworkAddress(sKmaAddress, pstSoap);

                iIndex = pLoadBalancer->FailOver(iIndex, pstSoap);

                LogError(i_pProfile, AUDIT_CLIENT_AGENT_CREATE_AUDIT_LOG_SOAP_ERROR,
                        NULL,
                        sKmaAddress,
                        sSoapFaultMsg);
            }
            else
            {
                pLoadBalancer->UpdateResponseStatus(iIndex);
            }
        }
        while (iIndex >= 0 && (!bSuccess));
    }
    else
    {
        bSuccess = false;
    }

    // free allocated memory for output if error condition
    // Clean up SOAP

    soap_destroy(pstSoap);
    soap_end(pstSoap);

    if (bSuccess)
    {
        //      END_STACK_CHECK;
        RETURN(KMS_AGENT_STATUS_OK);
    }

    //   END_STACK_CHECK;
    RETURN(KMSAgent_GetLastStatusCode(i_pProfile, iIndex));
}

#ifdef KMSUSERPKCS12
/*
 * This function allows the user to change the PIN on the PKCS12
 * file that holds the clients private key and cert.
 */
extern "C"
KMS_AGENT_STATUS KMSAgent_ChangeLocalPWD(
	KMSClientProfile* i_pProfile,
	utf8cstr const i_pOldPassphrase,
	utf8cstr const i_pNewPassphrase)
{
	CCertificate *pCert;
	CPrivateKey *pKey;
	bool bSuccess;

	pCert = new CCertificate;
	pKey = new CPrivateKey;

	bSuccess = GetPKCS12CertAndKey(i_pProfile, i_pOldPassphrase,
		pCert, pKey);
	if (!bSuccess)
    		return(KMSAgent_GetLastStatusCode(i_pProfile, 0));

	bSuccess = StoreAgentPKI(i_pProfile, pCert, pKey, i_pNewPassphrase);
	if (!bSuccess)
    		return(KMSAgent_GetLastStatusCode(i_pProfile, 0));

	return (KMS_AGENT_STATUS_OK);
}
#endif /* KMSUSERPKCS12 */
