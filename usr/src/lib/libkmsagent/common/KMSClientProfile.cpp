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

#include <stdio.h>
#include <errno.h>

#if !defined(UNIX) && !defined(METAWARE)
#include "KMSAgent_direct.h"
#endif

#include <string.h>

#include "KMSClientProfile.h"

#include "KMSAgent.h"
#include "KMS_CAStub.h"
#include "KMS_CertificateStub.h"
#include "KMS_DiscoveryStub.h"
#include "KMSClientProfileImpl.h"
#include "KMSAuditLogger.h"
#include "KMSAgentSoapUtilities.h"
#include "KMSAgentStringUtilities.h"


#include "KMSAgentPKICommon.h" // must be before agentstorage

#include "stdsoap2.h"          
#include "KMSAgentStorage.h"   // uses KMSClientProfile


#include "KMSAgentWebServiceNamespaces.h"
#include "k_setupssl.h"
#include "KMSAgentChallenge.h"
#include "KMSAgentCryptoUtilities.h"
#include "ApplianceParameters.h"
#include "AutoMutex.h"

#include "KMSAgentLoadBalancer.h"
#include "KMSAgentDataUnitCache.h"

#include "ClientSoapFaultCodes.h"
#ifdef METAWARE
#include "debug.h"
#include "sizet.h"
typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long	uint64_t;
#include "literals.h"
#endif
#include "KMSAgentAESKeyWrap.h"

#if defined(METAWARE) && defined(DEBUG)
#include "debug.h"
#endif
#include "KMSAuditLogger.h"
#include "KMSClientProfileImpl.h"

#ifdef METAWARE
extern "C" void
tnMsg( const char   *format,
       ... );
#endif

bool g_bUseFileLog = false;
char g_wsWorkingDirectory[KMS_MAX_PATH_LENGTH+1] = "./";


static bool InitializeLogging( 
   const utf8cstr  i_wsWorkingDirectory,
   int i_bUseFileLog )
{
   FATAL_ASSERT( !i_bUseFileLog || i_wsWorkingDirectory );
   
   bool bFileLogSuccess = true;
   
   g_bUseFileLog = ( i_bUseFileLog != 0 );
   
   // InitializeFileLogging must always be called, 
   // because the file is always used by FATALs.
   
   bFileLogSuccess = InitializeFileLogging( i_wsWorkingDirectory ) ? true:false;
   
   return bFileLogSuccess;
}

static void FinalizeLogging()
{
   // FinalizeFileLogging must always be called, 
   // because the file is always used by FATALs.
   FinalizeFileLogging();
   
   return;
}




/*---------------------------------------------------------------------------
 * Function: KMSClient_InitializeLibrary
 *
 *--------------------------------------------------------------------------*/

bool KMSClient_InitializeLibrary(
   const utf8cstr  i_wsWorkingDirectory,
   int i_bUseFileLog)
{
   bool bSuccess;
   
#if defined(DEBUG) && defined(METAWARE)
   log_printf("KMSClient_InitializeLibrary : ENTERING");
#endif

   // setup SSL
   bSuccess = K_SetupSSL() == 1;
   if(!bSuccess)
   {
      return false;
   }

#if defined(DEBUG) && defined(METAWARE)
   log_printf("KMSClient_InitializeLibrary : set current directory");
#endif

   // if i_wsWorkingDirectory is null, caller means current directory
   if ( i_wsWorkingDirectory != NULL )
   {
#if defined(DEBUG) && defined(METAWARE)
      log_printf("KMSClient_InitializeLibrary : check working directory");
#endif

      // string is there but is empty or junk
      if (strlen(i_wsWorkingDirectory) <= 0)
      {
         strcpy(i_wsWorkingDirectory, ".");
      }

      if ( strlen(i_wsWorkingDirectory) >= KMS_MAX_PATH_LENGTH )
      {
         return false;
      }

#if defined(DEBUG) && defined(METAWARE)
      log_printf("KMSClient_InitializeLibrary : set global working directory");
#endif
      
      // set global working directory to input
      strncpy(g_wsWorkingDirectory, 
              i_wsWorkingDirectory,
              KMS_MAX_PATH_LENGTH); 
      g_wsWorkingDirectory[KMS_MAX_PATH_LENGTH] = 0;
   }
   else   
   {
      strcpy(g_wsWorkingDirectory, ".");
   }

#if defined(DEBUG) && defined(METAWARE)
   log_printf("KMSClient_InitializeLibrary : Initialize logging");
#endif

   // initialize file logging
   bSuccess = InitializeLogging( g_wsWorkingDirectory,
                                 i_bUseFileLog);
    
   return bSuccess;
}


/*---------------------------------------------------------------------------
 * Function: KMSClient_FinalizeLibrary 
 *--------------------------------------------------------------------------*/
bool KMSClient_FinalizeLibrary()
{
#if defined(DEBUG) && defined(METAWARE)
   log_printf("KMSClient_FinalizeLibrary : ENTERING");
#endif
   
   K_CleanupSSL();
   
   FinalizeLogging();
   
   return true; /* always */
}


int LogError_lastErrno;


/** 
 * Construct a message for the KMSAuditLogger and store the message
 *  in the profile as the last error message.  
 */
void LogError_function(KMSClientProfile *i_pProfile,
                       int i_iErrno,
                       const char* i_sOperation,
                       const char* i_sEntityID,
                       const char* i_sNetworkAddress,
                       const char* i_sMessage )
{
   FATAL_ASSERT( i_pProfile && i_sOperation );

   // save for caller's use - this shouldn't be a global, but I don't
   // want this as an item in the profile as I don't want it persisted
   LogError_lastErrno = i_iErrno;

   // log the message to a data file (and internal logs)
#ifndef METAWARE
   if ( g_bUseFileLog )
#endif
   {
      Log_function(i_iErrno, 
                   i_sOperation, 
                   i_sEntityID, 
                   i_sNetworkAddress, 
                   i_sMessage);
   }

#ifdef METAWARE
   /* print this to the T10000/9840 VOP */
   /* NOTE the \n is important to VOP - leave it in */
   tnMsg("`msg`KMS2.0:msg#=%i,op=%s\r\n",
         i_iErrno,
         i_sOperation);
   
   tnMsg("`msg`msg=%s,eid=%s,addr=%s\r\n", 
         i_sMessage,
         i_sEntityID, 
         i_sNetworkAddress);
   
#endif

   // copy the error message into the profile (for later reference)
   strncpy(i_pProfile->m_wsErrorString, 
           i_sOperation,
           KMS_MAX_ERROR_STRING);

   // make sure to NUL out the end
   i_pProfile->m_wsErrorString[KMS_MAX_ERROR_STRING] = 0;

   if ( i_sEntityID )
   {
      strncat(i_pProfile->m_wsErrorString, 
              i_sEntityID,
              KMS_MAX_ERROR_STRING);
   }

   if ( i_sNetworkAddress )
   {
      strncat(i_pProfile->m_wsErrorString, 
              ",Address=",
              KMS_MAX_ERROR_STRING);
      strncat(i_pProfile->m_wsErrorString, 
              i_sNetworkAddress,
              KMS_MAX_ERROR_STRING);
   }

   if ( i_sMessage )
   {
      strncat(i_pProfile->m_wsErrorString, 
              ",Msg=",
              KMS_MAX_ERROR_STRING);
      strncat(i_pProfile->m_wsErrorString, 
              i_sMessage,
              KMS_MAX_ERROR_STRING);
   }

   // make sure to NUL out the end
   i_pProfile->m_wsErrorString[KMS_MAX_ERROR_STRING] = 0;
   
}

// see KMSClientProfileImpl.h
bool SSL_InvalidCertificate (const char * const i_sErrorString)
{
    if (
        // OpenSSL generates this msg
        strstr(i_sErrorString, "sslv3 alert certificate unknown"))
    {
        return true;
    }
    return false;

}

// see KMSClientProfileImpl.h
bool ServerError (const char * i_sErrorString, int i_iErrno )
{
    // The Client Soap Fault Code returned by the KMA
    // may be at the start of i_sErrorString or immediately
    // follwing "SoapFaultString=" depending on the caller's
    // string

    int iErrorCode;
    
    const char* sFaultstringStart  = strstr(i_sErrorString, "SoapFaultString=" );
    if ( sFaultstringStart )
    {
        iErrorCode = GET_FAULT_CODE( sFaultstringStart + strlen("SoapFaultString=") );
    }
    else
    {
        // This may be zero if there is no error code at the start of the string.
        iErrorCode = GET_FAULT_CODE( i_sErrorString );
    }

    // the following is commented out so the former check can be observed.  This check is no longer
    // made since invalid certificate failures may be due to a KMA that is behind on
    // replication updates hence failover would succeed.
//    if (
//            // OpenSSL generates this msg
//            SSL_InvalidCertificate(i_sErrorString))
//    {
//        return false;
//    }
            
    if (
       // when the KMA is locked
       iErrorCode == CLIENT_ERROR_AGENT_APPLIANCE_LOCKED

       // KMS 2.2 change when the KMA is locked
       || iErrorCode == CLIENT_ERROR_MANAGER_APPLIANCE_LOCKED

       // KMS 2.2 change for core security internal error
       || iErrorCode == CLIENT_ERROR_MANAGER_INTERNAL

       // if the KMA's pre-gen'd key pool is depleted
       || iErrorCode == CLIENT_ERROR_AGENT_NO_READY_KEYS

       // if the KMA's HSM is broke and the KMA is in FIPS mode
       || iErrorCode == CLIENT_ERROR_SERVER_HSM_REQUIRED_BUT_MISSING
        
       // when the server is too slow
       || NULL != strstr( i_sErrorString, "Timeout" )
       || NULL != strstr( i_sErrorString, "Operation interrupted or timed out" )
       
       // The Appliance is powered down, or is not reachable
       || NULL != strstr( i_sErrorString, "Connection refused" )

       || NULL != strstr( i_sErrorString, "Unknown error" )

       // SOAP EOF
       || NULL != strstr( i_sErrorString, "End of file or no input:" )

       // Appliance server software is not running (while Appliance machine is OK)
       || NULL != strstr( i_sErrorString, "connect failed in tcp_connect()" )

       // If the server has an internal error but still responds
       || NULL != strstr( i_sErrorString, "Server Error" )

       // OpenSSL protocol errors (Note: the SSL_ERROR_SSL may be due
       // to invalid client-side values, but for now it's used as a
       // catch-all; a side-effect is that any actual invalid client-side
       // value will cause one audit log entry to be created on each
       // Appliance in the cluster).
       || NULL != strstr( i_sErrorString, 
                       "Error observed by underlying BIO: No error" )
       || NULL != strstr( i_sErrorString, 
                          "EOF was observed that violates the protocol" )
       || NULL != strstr( i_sErrorString, 
                          "SSL_ERROR_SSL" ) )
    {
        return true;
    }

#ifndef WIN32
	// check for errno values that imply connection problems to the server
    switch (i_iErrno)
    {
        case ECONNABORTED : return true; // Connection aborted.
        case ECONNREFUSED : return true; // Connection refused.
        case ECONNRESET :   return true; // Connection reset.
        case EHOSTUNREACH : return true; // Host is unreachable.
        case ENETDOWN :     return true; // Network is down.
        case ENETRESET :    return true; // Connection aborted by network.
        case ENETUNREACH :  return true; // Network unreachable.
        case ENOPROTOOPT :  return true; // Protocol not available.
#ifndef METAWARE
        case ETIME :        return true; // Stream ioctl() timeout.
#endif
        case ETIMEDOUT :    return true; // Connection timed out.
    }
#endif    
    // at this point we conclude its a client side issue
    return false;
}

/*---------------------------------------------------------------------------
 * Function: KMSClient_GetLastErrorMessage
 *
 *--------------------------------------------------------------------------*/

// extern "C"
utf8char * KMSClient_GetLastErrorMessage(KMSClientProfile *i_pProfile)
{
   FATAL_ASSERT(i_pProfile);
   
   CAutoMutex oAutoMutex( 0 );
   if ( i_pProfile->m_pLock )
   {
      oAutoMutex.Lock( (K_MUTEX_HANDLE)i_pProfile->m_pLock );
   }
   
   return i_pProfile->m_wsErrorString;
}


/*---------------------------------------------------------------------------
 * Function: KMSClient_RetrieveEntityCertificate
 * Get the Root CA Certificate and store it into the profile
 *--------------------------------------------------------------------------*/
static bool KMSClient_RetrieveEntityCertificate(
   KMSClientProfile* i_pProfile,
   utf8cstr  i_wsEntityID,
   utf8cstr  i_wsPassphrase,
   char* const o_sHexHashedPassphrase )
{
   FATAL_ASSERT( i_pProfile && i_wsEntityID && i_wsPassphrase );

#if defined(DEBUG) && defined(METAWARE)
    log_printf("KMSClient_RetrieveEntityCertificate : entered");
#endif
   
   CAutoMutex oAutoMutex( (K_MUTEX_HANDLE)i_pProfile->m_pLock );
   char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];
   char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];
   
   strcpy(o_sHexHashedPassphrase, "");
   
   bool bSuccess = true;
   bool bTryFailOver = false;
   
   struct soap *pstCASoap;
   pstCASoap = (struct soap *) malloc( sizeof(struct soap) );
   if(pstCASoap == NULL)
   {
#if defined(DEBUG) && defined(METAWARE)
      log_printf("Malloc %x pstCASoap returned null\n", sizeof(struct soap));
#endif
      LogError(i_pProfile,
               LoadProfile_AUDIT_CLIENT_GET_ROOT_CA_CERTIFICATE_SOAP_ERROR,
               NULL,
               NULL,
               "malloc failure for pstCASoap" );
      return false;
   }

   // initialize the SOAP connection that will get the RootCA 
   soap_init2( pstCASoap, (SOAP_XML_STRICT | SOAP_C_UTFSTRING), (SOAP_XML_STRICT | SOAP_C_UTFSTRING) );

#ifdef METAWARE
   K_SetupCallbacks ( pstCASoap );
#endif

   CCertificate* pRootCACertificate = 0;
   CCertificate* pEntityCertificate = 0;
   CPrivateKey*  pEntityPrivateKey = 0;

   soap_set_namespaces( pstCASoap, KMS_CA_namespaces );
   
   pstCASoap->connect_timeout = i_pProfile->m_iTransactionTimeout;
   pstCASoap->send_timeout    = i_pProfile->m_iTransactionTimeout;
   pstCASoap->recv_timeout    = i_pProfile->m_iTransactionTimeout;
   
   struct soap *pstCertificateSoap;

   pstCertificateSoap = (struct soap *) malloc( sizeof(struct soap) );

   if(pstCertificateSoap == NULL)
   {
#if defined(METAWARE)
      log_printf("Malloc %x pstCertificateSoap returned null\n", 
                 sizeof(struct soap));
#endif
      soap_free( pstCASoap );
      free(pstCASoap);
      return false;
   }

   // initialize the SOAP connection that will get the Certificate
   soap_init2( pstCertificateSoap, (SOAP_XML_STRICT | SOAP_C_UTFSTRING), (SOAP_XML_STRICT | SOAP_C_UTFSTRING) );
    
#ifdef METAWARE
   K_SetupCallbacks ( pstCertificateSoap );
#endif

   soap_set_namespaces( pstCertificateSoap, KMS_Certificate_namespaces );
   
   pstCertificateSoap->connect_timeout = i_pProfile->m_iTransactionTimeout;
   pstCertificateSoap->send_timeout = i_pProfile->m_iTransactionTimeout;
   pstCertificateSoap->recv_timeout = i_pProfile->m_iTransactionTimeout;
   
   CAgentLoadBalancer oLoadBalancer(i_pProfile);
   int iIndex = oLoadBalancer.Balance();

#if defined(DEBUG) && defined(METAWARE)
   log_printf("KMSClient_RetrieveEntityCertificate : call KMS_CA__RetrieveRootCACertificate");
#endif

   // get the server's URL that will provide SOAP services
   do
   {
      bSuccess = true;
      bTryFailOver = false;
      bool bFailedOnRetrieveRootCA = false;
      const char* sURL = 0;
      
      if ( bSuccess )
      {
         sURL = oLoadBalancer.GetHTTPURL(iIndex, 
                                         i_pProfile->m_iPortForCAService);
         
         if ( !sURL )
         {
            bSuccess = false;
         }
      }
      
      if ( bSuccess )
      {
         strncpy(i_pProfile->m_sURL, sURL, KMS_MAX_URL);
         i_pProfile->m_sURL[KMS_MAX_URL] = 0;
      }      
      

      // SOAP CALL -  retrieve Root CA Certificate from the Server
      struct KMS_CA::
         KMS_CA__RetrieveRootCACertificateResponse stRootCACertificateResponse;
      
      if ( bSuccess )
      {
#if defined(DEBUG) && defined(METAWARE)
         log_printf("KMSClient_RetrieveCertificate : call KMS_CA__RetrieveRootCACertificate again");
#endif
         bSuccess = 
            KMS_CA::soap_call_KMS_CA__RetrieveRootCACertificate(
               pstCASoap, 
               i_pProfile->m_sURL,
               NULL,
               i_wsEntityID,
               stRootCACertificateResponse ) == SOAP_OK;

         if ( !bSuccess )
         {            
            GetSoapFault(sSoapFaultMsg, (struct soap*)pstCASoap);      
            GetPeerNetworkAddress(sKmaAddress, pstCASoap);
            LogError(i_pProfile,
                     LoadProfile_AUDIT_CLIENT_GET_ROOT_CA_CERTIFICATE_SOAP_ERROR,
                     NULL,
                     sKmaAddress,
                     sSoapFaultMsg );

            bTryFailOver = ServerError(GET_SOAP_FAULTSTRING(pstCASoap), pstCASoap->errnum);
            bFailedOnRetrieveRootCA = true;
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 1\n");
      }
#endif


      // Validate the SOAP response
      if ( bSuccess )
      {
         if ( stRootCACertificateResponse.RootCACertificate.__size < 1 ||
              stRootCACertificateResponse.RootCACertificate.__ptr == NULL ||
              stRootCACertificateResponse.AuthenticationHashIterationCount < 
              MIN_AUTHENTICATION_ITERATION_COUNT ||
              stRootCACertificateResponse.AuthenticationHashIterationCount > 
                  MAX_AUTHENTICATION_ITERATION_COUNT ||
              stRootCACertificateResponse.ClientAuthenticationChallenge.__size != 
                  AUTHENTICATION_CHALLENGE_LENGTH ||
              stRootCACertificateResponse.ClientAuthenticationChallenge.__ptr == NULL )
         {
            bSuccess = false;

            GetPeerNetworkAddress(sKmaAddress, pstCASoap);
            LogError(i_pProfile,
                     AUDIT_CLIENT_GET_ROOT_CA_CERTIFICATE_INVALID_RESPONSE_FORMAT,
                     NULL,
                     sKmaAddress,
                     NULL);
         }
         else
         {
            GetPeerNetworkAddress(sKmaAddress, pstCASoap);
            Log(AUDIT_CLIENT_GET_ROOT_CA_CERTIFICATE_SUCCESS,
                 NULL,
                 sKmaAddress,
                 NULL);
         }

      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 2\n");
      }
#endif

      // build our RootCACertificate object
      if ( bSuccess )
      {
         pRootCACertificate = new CCertificate;

         // make sure the new was successful
         bSuccess = ( pRootCACertificate != 0 );
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 3\n");
      }
#endif

      if ( bSuccess )
      {
         // OVERLOADED Load method - 3 parameters means 
         // recall from BUFFER
         bSuccess =
            pRootCACertificate->Load(
               stRootCACertificateResponse.RootCACertificate.__ptr,  // to here
               stRootCACertificateResponse.RootCACertificate.__size, // size
               PKI_FORMAT );                                         // ignored

         if( !bSuccess )
         {          
            GetPeerNetworkAddress(sKmaAddress, pstCASoap);
            LogError(i_pProfile,
                     AUDIT_CLIENT_GET_ROOT_CA_CERTIFICATE_INVALID_CA_CERTIFICATE_FORMAT,
                     NULL,
                     sKmaAddress,
                     NULL);
         }

      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 4\n");
      }
#endif

      
      if ( bSuccess )
      {
         // save the built CACertificate object to a FILE (i_pProfile gets the
         // persistent handle to that file) 
         bSuccess = StoreCACertificate( i_pProfile, pRootCACertificate );
         
         if ( !bSuccess )
         {
            LogError(i_pProfile,AUDIT_CLIENT_GET_CERTIFICATE_SAVE_CA_CERTIFICATE_FAILED,
                     NULL,
                     NULL,
                     NULL);
         }           
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 5\n");
      }
#endif
	
      //-------------------------------
      // Initialize SSL - use SERVER AUTH
      //-------------------------------
      if ( bSuccess )
      {
         // SERVER_AUTHENTICATION needs just the pstCertificateSoap
         bSuccess =
            K_soap_ssl_client_context( 
               i_pProfile,                            // in ->m_wsProfileName,->m_sHexHashedPassphrase
               pstCertificateSoap,                    // in - soap structure
               SOAP_SSL_REQUIRE_SERVER_AUTHENTICATION // in - flags
               ) == SOAP_OK;
         
         if ( !bSuccess )
         {
            GetSoapFault(sSoapFaultMsg, (struct soap*)pstCertificateSoap);
            GetPeerNetworkAddress(sKmaAddress, pstCertificateSoap);
            LogError(i_pProfile,AUDIT_CLIENT_GET_CERTIFICATE_SOAP_ERROR,
                     NULL,
                     sKmaAddress,
                     sSoapFaultMsg );
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 6\n");
      }
#endif

      // hash the passphrase passed in
      char sHexAuthenticationSecret[2*HASH_LENGTH+1];

      if ( bSuccess )
      {
         bSuccess = ComputeFixedEntityHashedPassphraseAndAuthenticationSecret(
            i_wsPassphrase,
            o_sHexHashedPassphrase,
            stRootCACertificateResponse.AuthenticationHashIterationCount,
            sHexAuthenticationSecret );

         if ( !bSuccess )
         {
            LogError(i_pProfile,AUDIT_CLIENT_COMPUTE_FIXED_FAILED,
                     NULL,
                     NULL,
                     NULL);
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 7\n");
      }
#endif
      
      // copy received Root CA into buffer for input 
      // into challenge-response computation
      unsigned char aRootCACertificate[MAX_CERT_SIZE];
      int iRootCACertificateLength;

      if ( bSuccess )
      {
         // OVERLOADED save method - save iRootCACertificateLength to aRootCACertificate
         // buffer 
         bSuccess = pRootCACertificate->Save( 
            aRootCACertificate,    
            MAX_CERT_SIZE, 
            &iRootCACertificateLength,   
            PKI_FORMAT );

         if ( !bSuccess )
         {
            LogError(i_pProfile,AUDIT_CLIENT_SAVE_ROOTCA_FAILED,
                     NULL,
                     NULL,
                     NULL);
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 8\n");
      }
#endif

      // respond to server's challenge
      unsigned char aAuthenticationSecret[AUTHENTICATION_SECRET_LENGTH];
      unsigned char 
         aClientAuthenticationChallengeResponse[AUTHENTICATION_RESPONSE_LENGTH];
      
      if ( bSuccess )
      {
         FATAL_ASSERT( AUTHENTICATION_SECRET_LENGTH == 
                       ConvertUTF8HexStringToBinary( 
                          sHexAuthenticationSecret, NULL ) );

         ConvertUTF8HexStringToBinary( 
            sHexAuthenticationSecret, aAuthenticationSecret );

         // client authentication response
         bSuccess = ComputeChallengeResponse(
            aAuthenticationSecret,
            AUTHENTICATION_SECRET_LENGTH,
            aRootCACertificate,
            iRootCACertificateLength,
            stRootCACertificateResponse.ClientAuthenticationChallenge.__ptr,
            AUTHENTICATION_CHALLENGE_LENGTH,
            aClientAuthenticationChallengeResponse,
            AUTHENTICATION_RESPONSE_LENGTH );
         
         if ( !bSuccess )
         {
            LogError(i_pProfile,AUDIT_CLIENT_COMPUTE_CHALLENGE_RESPONSE_FAILED,
                     NULL,
                     NULL,
                     NULL);
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 9\n");
      }
#endif

      struct KMS_Certificate::xsd__hexBinary stClientAuthenticationResponse;

      if ( bSuccess )
      {
         stClientAuthenticationResponse.__size = 
            AUTHENTICATION_RESPONSE_LENGTH;
         stClientAuthenticationResponse.__ptr = 
            (unsigned char*)soap_malloc( 
               pstCertificateSoap, AUTHENTICATION_RESPONSE_LENGTH );

         if ( stClientAuthenticationResponse.__ptr != NULL )
         {
            memcpy( stClientAuthenticationResponse.__ptr, 
                    aClientAuthenticationChallengeResponse, 
                    AUTHENTICATION_RESPONSE_LENGTH );
         }
         else
         {
            bSuccess = false;
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 10\n");
      }
#endif

      // generate challenge nonce
      struct KMS_Certificate::xsd__hexBinary stServerAuthenticationChallenge;

      if ( bSuccess )
      {
         stServerAuthenticationChallenge.__size = 
            AUTHENTICATION_CHALLENGE_LENGTH;
         stServerAuthenticationChallenge.__ptr = 
            (unsigned char*)soap_malloc( pstCertificateSoap, 
                                         AUTHENTICATION_CHALLENGE_LENGTH );
            
         bSuccess = ( stServerAuthenticationChallenge.__ptr != NULL );
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 11\n");
      }
#endif      

      if ( bSuccess )
      {
         bSuccess = GetPseudorandomBytes( 
            AUTHENTICATION_CHALLENGE_LENGTH, 
            stServerAuthenticationChallenge.__ptr );
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 12\n");
      }
#endif      

      if ( bSuccess )
      {
         sURL = oLoadBalancer.GetHTTPSURL(iIndex, 
                                          i_pProfile->
                                          m_iPortForCertificateService);

         if ( !sURL )
         {
            bSuccess = false;
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 13\n");
      }
#endif      

      // Verify that the same URL is used for Root CA Certificate
      // retrieval as for Entity Certificate retrieval
        
      if ( bSuccess )
      {            
         char sTempCAURL[KMS_MAX_URL + 1];
         strncpy( sTempCAURL, i_pProfile->m_sURL, KMS_MAX_URL );
         sTempCAURL[KMS_MAX_URL] = 0;

         char * sRetrieveRootCACertificateURL = strtok( sTempCAURL, ":" );
        
         sRetrieveRootCACertificateURL = strtok(NULL, ":");

         char sTempAgentURL[KMS_MAX_URL + 1];
         strncpy( sTempAgentURL, sURL, KMS_MAX_URL );
         sTempAgentURL[KMS_MAX_URL] = 0;
         char * sRetrieveAgentCertificateURL = strtok( sTempAgentURL, ":" );
         sRetrieveAgentCertificateURL = strtok(NULL, ":");

         FATAL_ASSERT( strcmp( sRetrieveRootCACertificateURL, 
                               sRetrieveAgentCertificateURL ) == 0 );

         strncpy(i_pProfile->m_sURL, sURL, KMS_MAX_URL);
         i_pProfile->m_sURL[KMS_MAX_URL] = 0;
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 14\n");
      }
#endif

      KMS_Certificate::KMS_Certificate__RetrieveEntityCertificateResponse 
         stRetrieveEntityCertificateResponse;

      // SOAP - retrieve ENTITY Certificate, passing the challenge response,
      // a challenge to the server and get back the server's response
      if ( bSuccess )
      {
         bSuccess =
            KMS_Certificate::soap_call_KMS_Certificate__RetrieveEntityCertificate(
               pstCertificateSoap,
               sURL,
               NULL,
               (utf8cstr )i_wsEntityID,
               stClientAuthenticationResponse,
               stServerAuthenticationChallenge,
               stRetrieveEntityCertificateResponse ) == SOAP_OK;

         if( !bSuccess )
         {                
            GetSoapFault(sSoapFaultMsg, (struct soap*)pstCertificateSoap);
            GetPeerNetworkAddress(sKmaAddress, pstCertificateSoap);
            LogError(i_pProfile,AUDIT_CLIENT_GET_CERTIFICATE_SOAP_ERROR,
                     NULL,
                     sKmaAddress,
                     sSoapFaultMsg );
 
            bTryFailOver = ServerError(GET_SOAP_FAULTSTRING(pstCertificateSoap),
                                        pstCertificateSoap->errnum);
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 15\n");
      }
#endif      

      // Validate the response structure
      if ( bSuccess )
      {
         if ( stRetrieveEntityCertificateResponse.
              ServerAuthenticationResponse.__ptr == NULL 

              || stRetrieveEntityCertificateResponse.
              ServerAuthenticationResponse.__size != 
              AUTHENTICATION_RESPONSE_LENGTH

              || stRetrieveEntityCertificateResponse.Certificate.__size < 1

              || stRetrieveEntityCertificateResponse.Certificate.__ptr == 0

              || stRetrieveEntityCertificateResponse.
              WrappedPrivateKeyMaterial.__size < 1

              || stRetrieveEntityCertificateResponse.
              WrappedPrivateKeyMaterial.__ptr == 0 )
         {
            bSuccess = false;

            GetPeerNetworkAddress(sKmaAddress, pstCertificateSoap);
            LogError(i_pProfile,AUDIT_CLIENT_GET_CERTIFICATE_INVALID_RESPONSE_FORMAT,
                     NULL,
                     sKmaAddress,
                     NULL );
         }
         else
         {
            GetPeerNetworkAddress(sKmaAddress, pstCertificateSoap);
            Log(AUDIT_CLIENT_GET_CERTIFICATE_SUCCESS,
                 NULL,
                 sKmaAddress,
                 NULL );
         }
     }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 16\n");
      }
#endif      

      // if valid, calculate the correct challenge-response
      unsigned char 
         aServerAuthenticationChallengeResponse[AUTHENTICATION_RESPONSE_LENGTH];

      if ( bSuccess )
      {
         bSuccess = ComputeChallengeResponse(
            aAuthenticationSecret,
            AUTHENTICATION_SECRET_LENGTH,
            aRootCACertificate,
            iRootCACertificateLength,
            stServerAuthenticationChallenge.__ptr,
            AUTHENTICATION_CHALLENGE_LENGTH,
            aServerAuthenticationChallengeResponse,
            AUTHENTICATION_RESPONSE_LENGTH );
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 17\n");
      }
#endif      

      // if successful, check if the server provided the correct challenge-response
      if ( bSuccess )
      {
         if ( 0 != memcmp(
            aServerAuthenticationChallengeResponse,
            stRetrieveEntityCertificateResponse.ServerAuthenticationResponse.__ptr,
            AUTHENTICATION_RESPONSE_LENGTH )  )
         {
            bSuccess = false;

            GetPeerNetworkAddress(sKmaAddress, pstCertificateSoap);
            LogError(i_pProfile,AUDIT_CLIENT_GET_CERTIFICATE_INVALID_CHALLENGE_RESPONSE,
                     NULL,
                     sKmaAddress,
                     NULL );
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 18\n");
      }
#endif      


      if ( bSuccess )
      {
         pEntityCertificate = new CCertificate;
         // if certificate was obtained
         bSuccess = ( pEntityCertificate != 0 );
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 19\n");
      }
#endif      

      if ( bSuccess )
      {
         // Load(recall) the signed certificate using OVERLOADED load method
         // 3 parameters means load from a buffer
         bSuccess = pEntityCertificate->Load(
            stRetrieveEntityCertificateResponse.Certificate.__ptr,  // load into
            stRetrieveEntityCertificateResponse.Certificate.__size, 
            PKI_FORMAT );

         if ( !bSuccess )
         {
            GetPeerNetworkAddress(sKmaAddress, pstCertificateSoap);
            LogError(i_pProfile,AUDIT_CLIENT_GET_CERTIFICATE_INVALID_CERTIFICATE_FORMAT,
                     NULL,
                     sKmaAddress,
                     NULL );
         }
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 20\n");
      }
#endif      

      if ( bSuccess )
      {
         pEntityPrivateKey = new CPrivateKey;
         bSuccess = ( pEntityPrivateKey != 0 );
      }
#if defined(DEBUG) && defined(METAWARE)
      else
      {
         log_printf("!bSuccess 21\n");
      }
#endif      


      if ( bSuccess )
      {
         // Load the Private Key using OVERLOADED Load method - 3 parameters
         // means load from a buffer

         // TODO: change this when certificate service supports requesting unwrapped private keys
         bSuccess = pEntityPrivateKey->Load(
            stRetrieveEntityCertificateResponse.WrappedPrivateKeyMaterial.__ptr, // load into
            stRetrieveEntityCertificateResponse.WrappedPrivateKeyMaterial.__size, 
            NULL, 
            PKI_FORMAT );

         if (!bSuccess )
         {

            GetPeerNetworkAddress(sKmaAddress, pstCertificateSoap);
            LogError(i_pProfile,AUDIT_CLIENT_GET_CERTIFICATE_INVALID_KEY_FORMAT,
                     NULL,
                     sKmaAddress,
                     NULL );
         }
      }

      if ( bSuccess )
      {
            strncpy(i_pProfile->m_wsEntityID,
                i_wsEntityID,
                KMS_MAX_ENTITY_ID );
            i_pProfile->m_wsEntityID[KMS_MAX_ENTITY_ID] = 0;

            // store PKI certificates and unwrapped private key  
            bSuccess = StorePKIcerts( i_pProfile, 
                            pRootCACertificate, 
                            pEntityCertificate, 
                            pEntityPrivateKey,
#ifdef KMSUSERPKCS12
			    i_wsPassphrase
#else
                            NULL
#endif
			    );
#ifdef KMSUSERPKCS12
		if (bSuccess) {
			/*
			 * Write out the cert and key individually so GetPKIcerts
			 * can use them.
			 */
			bSuccess = StoreTempAgentPKI(i_pProfile,
			    pEntityCertificate, pEntityPrivateKey);
		}

#endif
	}

      if ( !bSuccess )
      {
         if (pRootCACertificate)
         {
             delete pRootCACertificate;
         }
         if (pEntityCertificate)
         {
             delete pEntityCertificate;
         }
         if (pEntityPrivateKey)
         {
             delete pEntityPrivateKey;
         }

         i_pProfile->m_iEnrolled = FALSE;

         if ( bTryFailOver )
         {
            iIndex = oLoadBalancer.FailOver(iIndex, bFailedOnRetrieveRootCA ? pstCASoap : pstCertificateSoap);
         }
      }
   } 
   while ( bTryFailOver && (iIndex >= 0) && !bSuccess );

   // certs are now persisted so free up space
   if ( bSuccess )
   {
        delete pRootCACertificate;
        delete pEntityCertificate;
        delete pEntityPrivateKey;
   }

   // Clean up SOAP resources for pstCASoap
   soap_destroy( pstCASoap );
   soap_end( pstCASoap );
   soap_done( pstCASoap );

   // Clean up SOAP resources for pstCertificateSoap
   soap_destroy( pstCertificateSoap );
   soap_end( pstCertificateSoap );
   soap_done( pstCertificateSoap );

   free(pstCASoap);
   free(pstCertificateSoap);

   return bSuccess;
}

/*--------------------------------------------------------------------------
 * LoadClusterInformation
 *  calls GetCluster - that's it.
 *    If there is no cluster file, this function will return true, 
 *    but o_bClusterInformationFound will be false.
 *-------------------------------------------------------------------------*/
static bool LoadClusterInformation( KMSClientProfile* i_pProfile, 
                                    int& o_bClusterInformationFound )
{
    FATAL_ASSERT( i_pProfile );

    o_bClusterInformationFound = false;

    CAutoMutex oAutoMutex( (K_MUTEX_HANDLE)i_pProfile->m_pLock );    

    return GetCluster( i_pProfile, o_bClusterInformationFound ) ;
    
}


/*--------------------------------------------------------------------------
 * EnrollAgent
 *  calls functions to perform enrollment and save PKI info to persistent storage 
 *  stores configuration in persistent storage
 *-------------------------------------------------------------------------*/

static bool EnrollAgent( KMSClientProfile * io_pProfile,
                         utf8cstr           i_wsEntityID,
                         utf8cstr           i_wsPassphrase )
{
    FATAL_ASSERT( io_pProfile && i_wsEntityID && i_wsPassphrase );

    bool bSuccess = true;

    // see KMSAgentCryptoUtilities for HASH_LENGTH, aka KMS_MAX_HASH_SIZE
    char sHexHashedPassphrase[2*KMS_MAX_HASH_SIZE+1];

    if ( bSuccess )
    {
        // performs enrollment and saves PKI info to persistent storage 
        bSuccess = KMSClient_RetrieveEntityCertificate(
                                    io_pProfile,
                                    i_wsEntityID,
                                    i_wsPassphrase,
                                    sHexHashedPassphrase );

        // KMSClient_RetrieveCertificate logs errors
    }

    if (bSuccess)
    {
        strncpy(io_pProfile->m_sHexHashedPassphrase, 
            sHexHashedPassphrase,
            2*KMS_MAX_HASH_SIZE );
        io_pProfile->m_sHexHashedPassphrase[2*KMS_MAX_HASH_SIZE] = 0;
        
        // persist the profile now updated with the hashed passphrase
        bSuccess = StoreConfig( io_pProfile ); 

        if (!bSuccess)
        {
              Log(AUDIT_CLIENT_LOAD_PROFILE,
                  i_wsEntityID,
                  NULL,
                  "store config failed following enrollment" );
        }
    }

    return bSuccess;
}

/*---------------------------------------------------------------------------
 * Function: KMSClient_LoadProfile
 *
 *--------------------------------------------------------------------------*/
bool KMSClient_LoadProfile(
                KMSClientProfile *io_pProfile,
                utf8char *i_wsProfileName,
                utf8char *i_wsEntityID,
                utf8char *i_wsPassphrase,
                utf8char *i_wsApplianceAddress,
                int      i_iTransactionTimeout,
                int      i_iFailOverLimit,
                int      i_iClusterDiscoveryFrequency,
                int       i_eKMSmode)
{
    FATAL_ASSERT(io_pProfile);
    FATAL_ASSERT(i_wsProfileName);

    bool bSuccess = true;

    char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];
    char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];

#if defined(DEBUG) && defined(METAWARE)
    log_printf("KMSClient_LoadProfile : entered");
#endif
    
    memset( io_pProfile, 0, sizeof(KMSClientProfile) );

    // create lock

    if (bSuccess)
    {
        bSuccess = 
           ( K_CreateMutex((K_MUTEX_HANDLE *)&io_pProfile->m_pLock) == 
             K_SYS_OK );
    }

    // initialize profile with parameters

    strncpy(io_pProfile->m_wsProfileName,
            i_wsProfileName,
            KMS_MAX_ENTITY_ID); 
    io_pProfile->m_wsProfileName[KMS_MAX_ENTITY_ID] = 0;

    io_pProfile->m_iPortForCAService = 
       DEFAULT_CA_SERVICE_PORT_NUMBER;
    io_pProfile->m_iPortForCertificateService = 
       DEFAULT_CERTIFICATE_SERVICE_PORT_NUMBER;
    io_pProfile->m_iPortForDiscoveryService = 
       DEFAULT_DISCOVERY_SERVICE_PORT_NUMBER;
    io_pProfile->m_iPortForAgentService = 
       DEFAULT_AGENT_SERVICE_PORT_NUMBER;
    strncpy(io_pProfile->m_wsApplianceAddress,
            i_wsApplianceAddress,
            KMS_MAX_NETWORK_ADDRESS); 
    io_pProfile->m_wsApplianceAddress[KMS_MAX_NETWORK_ADDRESS] = 0;
    io_pProfile->m_iClusterDiscoveryFrequency = i_iClusterDiscoveryFrequency;
    io_pProfile->m_iTransactionTimeout = i_iTransactionTimeout;
    io_pProfile->m_iFailoverLimit = i_iFailOverLimit;
    io_pProfile->m_eKMSmode = i_eKMSmode;

    // if the file isn't found, create a new one
    bool bProfileExists = ProfileExists( g_wsWorkingDirectory,  /* pass in default */
                                         io_pProfile->m_wsProfileName );

#ifdef KMSUSERPKCS12
	/*
	 * Fix logic for determining if this request is for enrollment.
	 * Look to see if the server cert and clientkey.p12 file exist.
	 * We always expect a password for Solaris which is used to
	 * validate that the user has access to the clientkey data by
	 * attempting to use it to open the PKCS12 file.
	 */
	 bool bEnrolling = !ClientKeyP12Exists(io_pProfile->m_wsProfileName);
#else
    bool bEnrolling = i_wsEntityID && i_wsPassphrase;
#endif

    if ( bSuccess && !bEnrolling && !bProfileExists )
    {
       // when not enrolling a profile must exist
       bSuccess = false;
       Log(AUDIT_CLIENT_LOAD_PROFILE,
           i_wsProfileName,
           NULL,
           "Enrollment attempted but profile could not be found" );
    }

    // if the file isn't found, create a new one
    if ( bSuccess && !bProfileExists )
    {
       strncpy(io_pProfile->m_wsEntityID,
               i_wsEntityID,
               KMS_MAX_ENTITY_ID );
       io_pProfile->m_wsEntityID[KMS_MAX_ENTITY_ID] = 0;
       bSuccess = CreateProfile( io_pProfile, 
                                 g_wsWorkingDirectory, 
                                 io_pProfile->m_wsProfileName );
    }
    
    // load profile.cfg file
    if ( bSuccess )
    {
        bSuccess = GetConfig( io_pProfile );

    }

    // if profile settings changed then update the profile storage
    if ( bSuccess && 
         ( strncmp(io_pProfile->m_wsApplianceAddress, 
                   i_wsApplianceAddress, KMS_MAX_NETWORK_ADDRESS ) != 0 ||
           io_pProfile->m_iClusterDiscoveryFrequency != i_iClusterDiscoveryFrequency ||
           io_pProfile->m_iTransactionTimeout != i_iTransactionTimeout ||
           io_pProfile->m_iFailoverLimit != i_iFailOverLimit
         ))
    {
        strncpy(io_pProfile->m_wsApplianceAddress,
                i_wsApplianceAddress,
                KMS_MAX_NETWORK_ADDRESS); 
        io_pProfile->m_wsApplianceAddress[KMS_MAX_NETWORK_ADDRESS] = 0;
        io_pProfile->m_iClusterDiscoveryFrequency = i_iClusterDiscoveryFrequency;
        io_pProfile->m_iTransactionTimeout = i_iTransactionTimeout;
        io_pProfile->m_iFailoverLimit = i_iFailOverLimit;

        bSuccess = StoreConfig( io_pProfile );
    }

    // get PKI info from prior enrollment
    if ( bSuccess && !bEnrolling )
    {
#ifdef KMSUSERPKCS12
	/*
	 * Decrypt the PKCS12 file with the client cert and key using
	 * the given password.  If it fails, then return an auth failure
	 * status.  If success, write the client cert and key to the client file
	 * so it can be used later by the SOAP SSL functions.
	 */
	CCertificate* pEntityCertificate = new CCertificate;;
	CPrivateKey*  pEntityPrivateKey = new CPrivateKey;
	bSuccess = GetPKCS12CertAndKey(io_pProfile,
	    i_wsPassphrase,
	    pEntityCertificate,
	    pEntityPrivateKey);
	if (!bSuccess) {
		Log(AUDIT_CLIENT_LOAD_PROFILE,
			i_wsProfileName,
			NULL,
			"Enrollment Certificate and Private Key "\
			"were not loaded from PKCS12" );
	} else {
		/*
		 * Write out the cert and key individually so GetPKIcerts
		 * can use them.
		 */
		 bSuccess = StoreTempAgentPKI(io_pProfile,
		    pEntityCertificate, pEntityPrivateKey);
		 if (!bSuccess) {
			Log(AUDIT_CLIENT_LOAD_PROFILE,
				i_wsProfileName,
				NULL,
				"Enrollment Certificate and Private Key "\
				"were not stored to file." );
		 }
	}
	delete pEntityCertificate;
	delete pEntityPrivateKey;

#endif
	if (bSuccess)
        	bSuccess = GetPKIcerts( io_pProfile );
    }

    // if not enrolling then previously enrolled PKI info should now be initialized
    if ( bSuccess && !bEnrolling && 
        (!io_pProfile->m_sHexHashedPassphrase || 
        !io_pProfile->m_iEnrolled  ))
    {
        bSuccess = false;
        Log(AUDIT_CLIENT_LOAD_PROFILE,
          i_wsProfileName,
          NULL,
          "Enrollment Certificates and Private Key were not loaded from profile" );
    }

    io_pProfile->m_bIsClusterDiscoveryCalled = false;

    // allocate main soap struct
    struct soap* pstSoap = 0;

    if ( bSuccess )
    {
        pstSoap = (struct soap*)malloc( sizeof(struct soap) );

        io_pProfile->m_pvSoap = pstSoap;

        bSuccess = ( pstSoap != NULL );

        if ( bSuccess )
        {
            soap_init2( pstSoap, 
                    (SOAP_XML_STRICT | SOAP_C_UTFSTRING ),
                    (SOAP_XML_STRICT | SOAP_C_UTFSTRING) );
            
#ifdef METAWARE
            K_SetupCallbacks ( pstSoap );
#endif

            soap_set_namespaces( pstSoap, KMS_Agent_namespaces );

            pstSoap->connect_timeout = io_pProfile->m_iTransactionTimeout;
            pstSoap->send_timeout = io_pProfile->m_iTransactionTimeout;
            pstSoap->recv_timeout = io_pProfile->m_iTransactionTimeout;
        }
        else
        {
#if defined(DEBUG) && defined(METAWARE)
           log_printf("Malloc %x pstSoap returned null\n", 
                      sizeof(struct soap));
#endif
           
        }      
    }

    // delete the existing cluster config if the input IP address 
    // does not match one already known to the cluster config

    // Note that KMSClientProfile may be too large to fit on the stack, so we're
    // going to put it on the heap.

    KMSClientProfile* pstTempProfile = 0;
    bool bFound = false;
    int i;

    if ( bSuccess )
    {
        pstTempProfile = (KMSClientProfile*)malloc( sizeof(KMSClientProfile) );
        bSuccess = (pstTempProfile != 0);
#if defined(METAWARE)
        if (!bSuccess) 
           log_printf("Malloc %x pstTempProfile returned null\n", 
                      sizeof(KMSClientProfile));
#endif

    }

    int bClusterInformationFound = false;

    if ( bSuccess )
    {
        memcpy( pstTempProfile, io_pProfile, sizeof(KMSClientProfile) );

        bSuccess = LoadClusterInformation( pstTempProfile, bClusterInformationFound );
    }

    // got cluster info from persistent storage
    if ( bSuccess && bClusterInformationFound )
    {
       // see if address is a member of the remembered cluster or is a 
       // new kma, meaning this KMA joins the cluster as the 
       // discovery KMA.
        for ( i = 0; i < pstTempProfile->m_iClusterNum; i++ )
        {
            bFound = (strncmp( pstTempProfile->m_aCluster[i].m_wsApplianceNetworkAddress, 
                              io_pProfile->m_wsApplianceAddress,
                              KMS_MAX_NETWORK_ADDRESS) == 0);

            if ( bFound )
            {
                break;
            }
#if defined(DEBUG) && defined(METAWARE)
            else
               log_printf ("KMSClient_LoadProfile : Appliance Address doesn't match");
#endif
        }
        
        if ( !bFound ) 
        {
#if defined(DEBUG) && defined(METAWARE)
           log_printf ("KMSClient_LoadProfile : delete cluster");
#endif
           DeleteCluster( pstTempProfile );
           char msg[256];
           K_snprintf(msg, 256,
               "KMSClientProfile.LoadProfile(): deleting previous cluster config, %s not found\n",
                io_pProfile->m_wsApplianceAddress);
           Log(AUDIT_CLIENT_LOAD_PROFILE,
              i_wsProfileName,
              NULL,
              msg );
           DeleteCluster( pstTempProfile );
        }
        else
        {
            // since address is a member of the persisted cluster copy the persisted cluster info to the profile 
            io_pProfile->m_iClusterNum = pstTempProfile->m_iClusterNum;
            memcpy(io_pProfile->m_aCluster,
                   pstTempProfile->m_aCluster,
                    sizeof(KMSClusterEntry)*io_pProfile->m_iClusterNum);
        }
    }
#if defined(DEBUG) && defined(METAWARE)
    else
       log_printf ("KMSClient_LoadProfile : no persisted cluster information");
#endif

    if ( pstTempProfile )
    {
#if defined(DEBUG) && defined(METAWARE)
       log_printf ("KMSClient_LoadProfile : free the temporary profile");
#endif
        free( pstTempProfile );
        pstTempProfile = 0;
    }

    if ( bSuccess && !io_pProfile->m_iEnrolled )
    {
#if defined(DEBUG) && defined(METAWARE)
       log_printf ("KMSClient_LoadProfile : call EnrollAgent");
#endif
        // enroll the agent
        bSuccess = EnrollAgent( io_pProfile,
                                i_wsEntityID,
                                i_wsPassphrase );
    }
#if defined(DEBUG) && defined(METAWARE)
    else if (io_pProfile->m_iEnrolled)
       log_printf ("KMSClient_LoadProfile : Already Enrolled");
#endif


 
    if (bSuccess)
    {
       // Initialize SSL - use CLIENT AUTH
       // CLIENT_AUTHENTICATION needs the pstSoap, and expects 
       // the profile io_pProfile to be full (have the other certificates 
       // and keypair)

        if ( bSuccess )
        {
            bSuccess = 
                K_soap_ssl_client_context( 
                   io_pProfile,                            // in/out
                   pstSoap,                                // out
                   SOAP_SSL_REQUIRE_CLIENT_AUTHENTICATION  // in - flags
                    ) == SOAP_OK;

            if ( !bSuccess )
            {
#if defined(DEBUG) && defined(METAWARE)
                if (!bSuccess)
                  log_printf ("KMSClient_LoadProfile : K_soap_ssl_client_context failed");
#endif
                GetSoapFault(sSoapFaultMsg, (struct soap*)pstSoap);      
                GetPeerNetworkAddress(sKmaAddress, pstSoap);

                LogError(io_pProfile,
                    AUDIT_CLIENT_LOAD_PROFILE_SOAP_ERROR,
                    NULL,
                    sKmaAddress,
                    sSoapFaultMsg );
            }
        }
        
        // discover the cluster

        if ( bSuccess && 
            io_pProfile->m_iClusterDiscoveryFrequency > 0 )
         {
              bSuccess = ( KMSClient_GetClusterInformation(
                                            io_pProfile,
                                            io_pProfile->m_wsEntitySiteID, 
                                            sizeof(io_pProfile->m_wsEntitySiteID),
                                            &(io_pProfile->m_iClusterNum),
                                            io_pProfile->m_aCluster,
                                            KMS_MAX_CLUSTER_NUM) != 0 );
              // KMSClient_GetClusterInformation logs errors
              
              if (bSuccess && i_eKMSmode == FIPS_MODE)
              {
                    bSuccess = !KMSClient_NoFIPSCompatibleKMAs(io_pProfile);
                    if (!bSuccess)
                    {
                        LogError(io_pProfile,
                            AUDIT_CLIENT_AGENT_LOAD_PROFILE_NO_FIPS_COMPATIBLE_KMAS_AVAILABLE,
                            NULL,
                            NULL,
                            NULL );                        
                    }
              }
         }
#if defined(DEBUG) && defined(METAWARE)
        if (!bSuccess)
           log_printf ("KMSClient_LoadProfile : getClusterInformation failed");
#endif

#ifdef KMSUSERPKCS12
	/*
	 * Once the SSL context is established, delete the
	 * private key file.
	 */
	 (void) CleanupPrivateKeyFile(io_pProfile);
#endif
    }
#if defined(DEBUG) && defined(METAWARE)
    else if (!bSuccess)
       log_printf ("KMSClient_LoadProfile : EnrollAgent failed");
#endif

    CAgentLoadBalancer *pAgentLoadBalancer = new CAgentLoadBalancer(io_pProfile);
    if(pAgentLoadBalancer == NULL)
    {
        bSuccess = false;
    }

#if defined(DEBUG) && defined(METAWARE)
    if (!bSuccess)
       log_printf ("KMSClient_LoadProfile : new CAgentLoadBalancer failed");
#endif

    io_pProfile->m_pAgentLoadBalancer = pAgentLoadBalancer;

    // create a data unit server affinity cache for Agents

    if ( bSuccess )
    {
        io_pProfile->m_pDataUnitCache = new CDataUnitCache();

        bSuccess = ( io_pProfile->m_pDataUnitCache != NULL );
    }

    if ( bSuccess )
    {
#if defined(DEBUG) && defined(METAWARE)
       log_printf ("KMSClient_LoadProfile : set version to KMS_AGENT_VERSION = %x", 
                   KMS_AGENT_VERSION);
       log_printf ("KMSClient_LoadProfile : profile is: %x\n", io_pProfile);
#endif
       // this is checked later by ProfileLoaded and is taken 
       // to indicate that the profile was correctly loaded
	   io_pProfile->m_iVersion = KMS_AGENT_VERSION;
    }

    if( !bSuccess )
    {
        K_DestroyMutex((K_MUTEX_HANDLE)io_pProfile->m_pLock);
        io_pProfile->m_pLock = 0;

        if ( io_pProfile->m_pvSoap )
        {
            soap_destroy( (struct soap*)io_pProfile->m_pvSoap );
            soap_end( (struct soap*)io_pProfile->m_pvSoap );
            soap_done( (struct soap*)io_pProfile->m_pvSoap );

            free( (struct soap*)io_pProfile->m_pvSoap );
            io_pProfile->m_pvSoap = 0;

            if( io_pProfile->m_pAgentLoadBalancer != NULL)
            {
                delete(reinterpret_cast <CAgentLoadBalancer *>(io_pProfile->m_pAgentLoadBalancer));
            }

            if( io_pProfile->m_pDataUnitCache != NULL)
            {
                delete(reinterpret_cast <CDataUnitCache *>(io_pProfile->m_pDataUnitCache));
            }

        }
#if defined(DEBUG) && defined(METAWARE)
        log_printf ("KMSClient_LoadProfile : failed - returning");
#endif
    }

    return bSuccess;
}

/**
 *  compare cluster entries having equivalent KMA names (aka Appliance alias) and 
 *  return true if equal.  Note:  KMANetworkAddress comparison is handled separately
 *  due to IPv4/IPv6
 */
static bool EqualClusterEntry( 
                       struct KMS_Discovery::KMS_Discovery_ClusterMember const *i_pLeft, 
                       KMSClusterEntry                                   const *i_pRight)
{
    bool bEnabled = i_pRight->m_iEnabled ? true : false;
    if ( i_pLeft->Enabled != bEnabled )
    {
        return false;
    }
    if ( i_pLeft->KMAID != i_pRight->m_lApplianceID )
    {
        return false;
    }
    if ( strncmp(i_pLeft->KMASiteID, 
            i_pRight->m_wsApplianceSiteID,
            KMS_MAX_ENTITY_SITE_ID) != 0 )
    {
        return false;
    }
    //    Note: we now minimize persistence of cluster changes by not saving 
    //      whenever m_iResponding changes

    return true;
}
/**
 *  @return true if the current address matches the provided IPv6Address
 *  when the i_bUseIPv6 arg is true, otherwise compare the current address
 *  with the IPv4Address.  If i_bUseIPv6 then i_pCurrentAddress must be
 *  enclosed in brackets, i.e. as in RFC 2396.
 */
static bool EqualKMANetworkAddress (
                                    bool i_bUseIPv6,
                                    const char * const i_pIPv6Address,
                                    const char * const i_pIPv4Address,
                                    const char * const i_pCurrentAddress
                                    )
{
    bool bEqualAddress = true;
    
    if ( i_pCurrentAddress == NULL )
    {
        return false;
    }
    
    if (i_bUseIPv6)
    {
        if ( i_pIPv6Address == NULL )
        {
            return false;
        }
        char sIPv6Address[KMS_MAX_NETWORK_ADDRESS] = "[";
        
        strcat(sIPv6Address, i_pIPv6Address);
        
        char * pLoc = strchr(sIPv6Address, '/');
                
        if ( pLoc != NULL )
        {
            // remove prefix from address
            *pLoc = '\0';
        }
        strcat(sIPv6Address, "]");
        bEqualAddress = strncmp(sIPv6Address, i_pCurrentAddress, KMS_MAX_NETWORK_ADDRESS) == 0;
    }
    else
    {
        if ( i_pIPv4Address == NULL )
        {
            return false;
        }
        bEqualAddress = strncmp(i_pIPv4Address, i_pCurrentAddress, KMS_MAX_NETWORK_ADDRESS) == 0;
    }
    
    return bEqualAddress;
}

/**
 *  compares the profile's current cluster state with the filtered discover
 *  cluster response and returns true if the repsonse
 *  differs from i_pProfile->m_aCluster.  A cluster has changed if the state of any
 *  cluster node has changed or if the set of cluster nodes has changed.
 *  The order of nodes is immaterial.
 */
static bool ClusterConfigChanged (
                                  KMSClientProfile const *i_pProfile,
                                  char * const i_sResponseEntitySiteID,
                                  struct KMS_Discovery::KMS_Discovery__ArrayOfClusterMembers const *i_pFilteredCluster)
{
    int i, j;

    FATAL_ASSERT(i_pProfile);
    FATAL_ASSERT(i_pFilteredCluster);

    // cardinality check
    if (i_pProfile->m_iClusterNum !=
        i_pFilteredCluster->__size)
    {
        return true;
    }

    // check if the agent's site ID changed
    if (strncmp(i_pProfile->m_wsEntitySiteID,
        i_sResponseEntitySiteID, KMS_MAX_ENTITY_SITE_ID) != 0)
    {
        return true;
    }

    // for all KMAs in filtered response check if they exist unchanged in the profile
    for (i = 0; i < i_pFilteredCluster->__size; i++)
    {
        bool bFound = false;
        for (j = 0; j < i_pProfile->m_iClusterNum; j++)
        {
            if (strncmp(i_pFilteredCluster->__ptr[i].KMAName,
                    i_pProfile->m_aCluster[j].m_wsApplianceAlias,
                    KMS_MAX_ENTITY_ID) == 0)
            {
                bFound = true;
                if (
                !EqualKMANetworkAddress(
                    strchr(i_pProfile->m_wsApplianceAddress, ':') ? true : false,
                    i_pFilteredCluster->__ptr[i].KMANetworkAddressIPv6,
                    i_pFilteredCluster->__ptr[i].KMANetworkAddress,
                    i_pProfile->m_aCluster[j].m_wsApplianceNetworkAddress) ||
                !EqualClusterEntry((i_pFilteredCluster->__ptr + i),
                    &i_pProfile->m_aCluster[j]))
                
                {
                    return true;
                }
            }
        }
        if ( !bFound )
        {
            return true;
        }
    }
    return false;
}

/**
 *  returns true if the string is a valid IPv6 address syntactically
 */
static bool ValidIPv6KMAaddress( const char * const i_pIPAddress )
{
    FATAL_ASSERT( i_pIPAddress );
    
    if ( strlen(i_pIPAddress) <= 0 )
    {
        return false;
    }
    
    // simple check
    if ( strchr( i_pIPAddress, ':'))
    {
        return true;
    }
    
    return false;
}
/**
 *
 */
static void FreeFilteredCluster (
                                  struct KMS_Discovery::KMS_Discovery__ArrayOfClusterMembers * const io_stFilteredCluster,
                                  int iLimit )
{
    int j = 0;
    for (; j < iLimit; j++ )
    {
        free( io_stFilteredCluster->__ptr[j].KMAName );
        free( io_stFilteredCluster->__ptr[j].KMASiteID );
        free( io_stFilteredCluster->__ptr[j].KMAHostName );
        free( io_stFilteredCluster->__ptr[j].KMANetworkAddress );
        free( io_stFilteredCluster->__ptr[j].KMAVersion );
        free( io_stFilteredCluster->__ptr[j].KMAHostNameIPv6 );
        free( io_stFilteredCluster->__ptr[j].KMANetworkAddressIPv6 );
    }

    free( io_stFilteredCluster->__ptr );
}

/**
 *  filters the discover cluster response to be less than or equal to KMS_MAX_CLUSTER_NUM KMAs.  The heuristic used to filter
 *  the response is the same as used by CAgentLoadBalancer::KMSClient_SortClusterArray(), FIPS compatibility, then within site,
 *  then responding and enabled KMAs.
 *  @param i_stResponse pointer to gsoap discover cluster service response
 *  @param io_stFilteredCluster pointer to gsoap discover cluster array to be populated with the filtered list of KMAs
 *  @return true on success and io_stFilteredCluster->__size less than or equal to KMS_MAX_CLUSTER_NUM,
 *  otherwise io_stFilteredCluster is undefined. io_stFilteredCluster->__ptr is populated with the array of elements
 *  malloc'd.
 */
static bool FilterCluster (struct KMS_Discovery::KMS_Discovery__DiscoverClusterResponse * const i_stResponse,
                           bool i_bFIPS,
                           struct KMS_Discovery::KMS_Discovery__ArrayOfClusterMembers * const io_stFilteredCluster)
{
    /*
     *  do something like KMSAgentLoadBalancer:SortClusterArray() to the stResponse array
     *  return 1st KMS_MAX_CLUSTER_NUM entries and free the rest.
    */

    FATAL_ASSERT(i_stResponse);
    FATAL_ASSERT(io_stFilteredCluster);

    io_stFilteredCluster->__size = i_stResponse->ArrayOfClusterMembers.__size;
    io_stFilteredCluster->__ptr = reinterpret_cast < struct KMS_Discovery::KMS_Discovery_ClusterMember * >
            ( calloc( io_stFilteredCluster->__size,
                      sizeof (struct KMS_Discovery::KMS_Discovery_ClusterMember ) ) );

    if (io_stFilteredCluster->__ptr == NULL)
    {
        Log(AUDIT_CLIENT_FILTER_CLUSTER_FAILED,
                NULL,
                NULL,
                "calloc failed");
        return false;
    }

    if (io_stFilteredCluster->__size <= 0)
    {
        Log(AUDIT_CLIENT_FILTER_CLUSTER_FAILED,
                NULL,
                NULL,
                "returned cluster size is not positive");
        return false;
    }

    // copy response cluster members
    for (int i = 0; i < io_stFilteredCluster->__size; i++)
    {
        bool bSuccess = true;

        size_t iKMANameSize = 0, iKMASiteIDSize = 0, iKMAHostNameSize = 0,
                iKMANetworkAddressSize = 0, iKMAVersionSize = 0, iKMAHostNameIPv6Size = 0,
                iKMANetworkAddressIPv6Size = 0;
        
        // allocate storage for the various struct member's arrays
        iKMANameSize = strlen(i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAName)+1;
        io_stFilteredCluster->__ptr[i].KMAName = reinterpret_cast <char *> (malloc(iKMANameSize));

        iKMASiteIDSize = strlen(i_stResponse->ArrayOfClusterMembers.__ptr[i].KMASiteID)+1;
        io_stFilteredCluster->__ptr[i].KMASiteID = reinterpret_cast <char *> (malloc(iKMASiteIDSize));

        iKMAHostNameSize = strlen(i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAHostName)+1;
        io_stFilteredCluster->__ptr[i].KMAHostName = reinterpret_cast <char *> (malloc(iKMAHostNameSize));

        iKMANetworkAddressSize = strlen(i_stResponse->ArrayOfClusterMembers.__ptr[i].KMANetworkAddress)+1;
        io_stFilteredCluster->__ptr[i].KMANetworkAddress = reinterpret_cast <char *> (malloc(iKMANetworkAddressSize));

        // KMAVersion is an optional field derived from an xml attribute in the soap interface that will not be present in 2.0 KMAs
        if (i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAVersion)
        {
            iKMAVersionSize = strlen(i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAVersion)+1;
            io_stFilteredCluster->__ptr[i].KMAVersion = reinterpret_cast <char *> (malloc(iKMAVersionSize));
            if (io_stFilteredCluster->__ptr[i].KMAVersion == NULL)
            {
                bSuccess = false;
            }
        }
        else
        {
            io_stFilteredCluster->__ptr[i].KMAVersion = NULL;
        }

        // KMAHostNameIPv6 is an optional field derived from an xml attribute in the soap interface that will not be present in 2.0 KMAs
        if (i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAHostNameIPv6)
        {
            iKMAHostNameIPv6Size = strlen(i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAHostNameIPv6)+1;
            io_stFilteredCluster->__ptr[i].KMAHostNameIPv6 = reinterpret_cast <char *> (malloc(iKMAHostNameIPv6Size));
            if ( io_stFilteredCluster->__ptr[i].KMAHostNameIPv6 == NULL )
            {
                bSuccess = false;
            }
        }
        else
        {
            io_stFilteredCluster->__ptr[i].KMAHostNameIPv6 = NULL;
        }

        // KMANetworkAddressIPv6 is an optional field derived from an xml attribute in the soap interface that will not be present in 2.0 KMAs
        if (i_stResponse->ArrayOfClusterMembers.__ptr[i].KMANetworkAddressIPv6)
        {
            iKMANetworkAddressIPv6Size = strlen(i_stResponse->ArrayOfClusterMembers.__ptr[i].KMANetworkAddressIPv6)+1;
            io_stFilteredCluster->__ptr[i].KMANetworkAddressIPv6 = reinterpret_cast <char *> (malloc(iKMANetworkAddressIPv6Size));
            if ( io_stFilteredCluster->__ptr[i].KMANetworkAddressIPv6 == NULL )
            {
                bSuccess = false;
            }
            }
        else
        {
            io_stFilteredCluster->__ptr[i].KMANetworkAddressIPv6 = NULL;
        }

        if ( io_stFilteredCluster->__ptr[i].KMAName == NULL ||
             io_stFilteredCluster->__ptr[i].KMASiteID == NULL ||
             io_stFilteredCluster->__ptr[i].KMAHostName == NULL ||
             io_stFilteredCluster->__ptr[i].KMANetworkAddress == NULL ||
             !bSuccess )
        {
            // cleanup and return
            FreeFilteredCluster( io_stFilteredCluster, i+1 );
            Log( AUDIT_CLIENT_FILTER_CLUSTER_FAILED,
                    NULL,
                    NULL,
                    "malloc failed" );
            return false;
        }

        strncpy(io_stFilteredCluster->__ptr[i].KMAName,
                i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAName,
                iKMANameSize);
        io_stFilteredCluster->__ptr[i].KMAName[iKMANameSize-1] = '\0';

        strncpy(io_stFilteredCluster->__ptr[i].KMASiteID,
                i_stResponse->ArrayOfClusterMembers.__ptr[i].KMASiteID,
                iKMASiteIDSize);
        io_stFilteredCluster->__ptr[i].KMASiteID[iKMASiteIDSize-1] = '\0';

        strncpy(io_stFilteredCluster->__ptr[i].KMAHostName,
                i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAHostName,
                iKMAHostNameSize);
        io_stFilteredCluster->__ptr[i].KMAHostName[iKMAHostNameSize-1] = '\0';

        strncpy(io_stFilteredCluster->__ptr[i].KMANetworkAddress,
                i_stResponse->ArrayOfClusterMembers.__ptr[i].KMANetworkAddress,
                iKMANetworkAddressSize);
        io_stFilteredCluster->__ptr[i].KMANetworkAddress[iKMANetworkAddressSize-1] = '\0';

        if ( io_stFilteredCluster->__ptr[i].KMAVersion )
        {
            strncpy( io_stFilteredCluster->__ptr[i].KMAVersion,
                    i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAVersion,
                    iKMAVersionSize );
            io_stFilteredCluster->__ptr[i].KMAVersion[iKMAVersionSize-1] = '\0';
        }

        if (io_stFilteredCluster->__ptr[i].KMAHostNameIPv6)
        {
            strncpy(io_stFilteredCluster->__ptr[i].KMAHostNameIPv6,
                    i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAHostNameIPv6,
                    iKMAHostNameIPv6Size);
            io_stFilteredCluster->__ptr[i].KMAHostNameIPv6[iKMAHostNameIPv6Size-1] = '\0';
        }

        if ( io_stFilteredCluster->__ptr[i].KMANetworkAddressIPv6 )
        {
            strncpy( io_stFilteredCluster->__ptr[i].KMANetworkAddressIPv6,
                    i_stResponse->ArrayOfClusterMembers.__ptr[i].KMANetworkAddressIPv6,
                    iKMANetworkAddressIPv6Size );
            io_stFilteredCluster->__ptr[i].KMANetworkAddressIPv6[iKMANetworkAddressIPv6Size-1] = '\0';
        }

        io_stFilteredCluster->__ptr[i].KMAID = i_stResponse->ArrayOfClusterMembers.__ptr[i].KMAID;
        io_stFilteredCluster->__ptr[i].Enabled = i_stResponse->ArrayOfClusterMembers.__ptr[i].Enabled;
        io_stFilteredCluster->__ptr[i].KMS_Discovery__Locked = i_stResponse->ArrayOfClusterMembers.__ptr[i].KMS_Discovery__Locked;
        
        // set load to zero, KMA with version <= Build600 don't initialize
        // the load field from the service network
        if ( ( io_stFilteredCluster->__ptr[i].KMAVersion &&
             strcmp( io_stFilteredCluster->__ptr[i].KMAVersion, "Build600" ) <= 0 ) ||
             io_stFilteredCluster->__ptr[i].KMAVersion == NULL )
        {
            io_stFilteredCluster->__ptr[i].Load = 0;
        }
        else
        {
            io_stFilteredCluster->__ptr[i].Load = i_stResponse->ArrayOfClusterMembers.__ptr[i].Load;
        }

        io_stFilteredCluster->__ptr[i].Responding = i_stResponse->ArrayOfClusterMembers.__ptr[i].Responding;

        if (!bSuccess)
        {
            FreeFilteredCluster( io_stFilteredCluster, i );
            Log(AUDIT_CLIENT_FILTER_CLUSTER_FAILED,
                    NULL,
                    NULL,
                    "cluster member copy failed");
            return false;
        }
    }

    // is filtering necessary?
    if (io_stFilteredCluster->__size <= KMS_MAX_CLUSTER_NUM)
    {
        // no filtering required
        return true;
    }
    else
    {
        char sMesg[100];
        K_snprintf(sMesg, sizeof (sMesg), "DiscoverCluster returned %d KMAs, filtering to %d ...", io_stFilteredCluster->__size, KMS_MAX_CLUSTER_NUM);
        Log(AUDIT_CLIENT_FILTER_CLUSTER,
                    NULL,
                    NULL,
                    sMesg);

    }

    // adjust loads according to availability, site and FIPS compatibility
    {
        int i = 0;
        for (; i < io_stFilteredCluster->__size; i++)
        {
            if (io_stFilteredCluster->__ptr[i].Enabled == false
                || io_stFilteredCluster->__ptr[i].Responding == false
                || io_stFilteredCluster->__ptr[i].KMS_Discovery__Locked == true)
            {
                io_stFilteredCluster->__ptr[i].Load += 0x40;
            }

            if (strcmp(io_stFilteredCluster->__ptr[i].KMASiteID,
                i_stResponse->EntitySiteID) != 0)
            {
                io_stFilteredCluster->__ptr[i].Load += 0x20;

            }

            if ( i_bFIPS &&
                    !FIPScompatibleKMA(io_stFilteredCluster->__ptr[i].KMAVersion))
            {
                io_stFilteredCluster->__ptr[i].Load += 0x80;
            }
        }
    }

    // sort ascending by load

    // gnome sort: the simplest sort algoritm
    {
        int i = 0;
        while (i < io_stFilteredCluster->__size)
        {
            if (i == 0 || io_stFilteredCluster->__ptr[i - 1].Load <= io_stFilteredCluster->__ptr[i].Load)
            {
                i++;
            }
            else
            {
                struct KMS_Discovery::KMS_Discovery_ClusterMember tmp = io_stFilteredCluster->__ptr[i];
                io_stFilteredCluster->__ptr[i] = io_stFilteredCluster->__ptr[i - 1];
                io_stFilteredCluster->__ptr[--i] = tmp;
            }
        }
    }

    // now filter the list, freeing memory allocated for copied elements that are not being retained
    {
        int i=KMS_MAX_CLUSTER_NUM;
        for (; i < io_stFilteredCluster->__size; i++)
        {
            free(io_stFilteredCluster->__ptr[i].KMAName);
            free(io_stFilteredCluster->__ptr[i].KMASiteID);
            free(io_stFilteredCluster->__ptr[i].KMAHostName);
            free(io_stFilteredCluster->__ptr[i].KMANetworkAddress);
            free(io_stFilteredCluster->__ptr[i].KMAVersion);
            free(io_stFilteredCluster->__ptr[i].KMAHostNameIPv6);
            free(io_stFilteredCluster->__ptr[i].KMANetworkAddressIPv6);
        }
    }

    io_stFilteredCluster->__size = KMS_MAX_CLUSTER_NUM;
    
    Log(AUDIT_CLIENT_FILTER_CLUSTER,
                NULL,
                NULL,
                "success");
    
    return true;
};

/*---------------------------------------------------------------------------
 * Function: KMSClient_GetClusterInformation
 *
 *--------------------------------------------------------------------------*/
bool KMSClient_GetClusterInformation(
        KMSClientProfile *i_pProfile, 
        utf8char *o_wsEntitySiteID,
        int i_iEntitySiteIDSize,
        int *o_pApplianceNum,
        KMSClusterEntry *o_pClusterEntryArray,
        int i_iClusterEntryArraySize)
{
   FATAL_ASSERT(i_pProfile);
   FATAL_ASSERT( o_wsEntitySiteID );
   FATAL_ASSERT( o_pApplianceNum );
   FATAL_ASSERT( o_pClusterEntryArray );
   FATAL_ASSERT( i_iEntitySiteIDSize <= KMS_MAX_ENTITY_ID+1 );

   CAutoMutex oAutoMutex( (K_MUTEX_HANDLE)i_pProfile->m_pLock );

   bool bSuccess = true;
   char sSoapFaultMsg[g_iMAX_SOAP_FAULT_MESSAGE_LENGTH];
   char sKmaAddress[g_iMAX_PEER_NETWORK_ADDRESS_LENGTH];

   char sURL[KMS_MAX_URL+1];

   // set URL from the initial appliance address
   utf8cstr sApplianceAddress = i_pProfile->m_wsApplianceAddress;

#if defined(DEBUG) && defined(METAWARE)
    log_printf("KMSClient_GetClusterInformation : entered");
#endif

   K_snprintf(sURL,
           KMS_MAX_URL,
           "https://%s:%d",
           sApplianceAddress,
           i_pProfile->m_iPortForDiscoveryService);
   strncpy(i_pProfile->m_sURL, sURL, KMS_MAX_URL);
   i_pProfile->m_sURL[KMS_MAX_URL] = 0;
           
   // allocate and initialize a new soap env for the cluster discovery call
   struct soap *pstSoap = (struct soap*)i_pProfile->m_pvDiscoverySoap;

   if ( !i_pProfile->m_iEnrolled )
   {
        bSuccess = false;
   }
   
   if ( bSuccess )
   {
	   // allocate discovery soap runtime
	   if (pstSoap == NULL )
	   {
   	   	   pstSoap = soap_new();
		   i_pProfile->m_pvDiscoverySoap = pstSoap;
           /* soap_copy results in a segfault in sk_free() within libcrytpo.so
           pstSoap = soap_copy( (soap*)i_pProfile->m_pvSoap );
           */
           if (pstSoap == NULL)
           {
               bSuccess = false;
           }
           else
           {
               pstSoap->connect_timeout = i_pProfile->m_iTransactionTimeout;
               pstSoap->send_timeout = i_pProfile->m_iTransactionTimeout;
               pstSoap->recv_timeout = i_pProfile->m_iTransactionTimeout;

               soap_set_imode( pstSoap, (SOAP_XML_STRICT | SOAP_C_UTFSTRING) );      
               soap_set_omode( pstSoap, (SOAP_XML_STRICT | SOAP_C_UTFSTRING) );      

               soap_set_namespaces( pstSoap, KMS_Discovery_namespaces );
               bSuccess = K_soap_ssl_client_context( 
                               i_pProfile,
                               pstSoap,                   
                               SOAP_SSL_REQUIRE_CLIENT_AUTHENTICATION 
                                ) == SOAP_OK;
               if ( !bSuccess )
               {
                    Log(AUDIT_CLIENT_GetClusterInformation, 
                       NULL, 
                       NULL, 
                       "K_soap_ssl_client_context failed");
                    soap_destroy(pstSoap);
                    soap_end(pstSoap);
                    soap_done(pstSoap);
               }
           }
	   }
   }

   // Discovery
   struct KMS_Discovery::KMS_Discovery__DiscoverClusterResponse stResponse;

#if defined(DEBUG) && defined(METAWARE)
    log_printf("KMSClient_GetClusterInformation : call KMS_Discovery_DiscoverCluster");
#endif
    
    // SOAP - discover cluster
   if ( bSuccess )
   {
#ifdef DEBUG
      int iStartTickCount = K_GetTickCount();
      int iEndTickCount;
      char sDiscoverTimeMsg[100];
#endif
      bSuccess = 
         KMS_Discovery::soap_call_KMS_Discovery__DiscoverCluster(
            pstSoap, 
            sURL,
            NULL,
            NULL,
            stResponse ) == SOAP_OK;
#ifdef DEBUG
      iEndTickCount = K_GetTickCount();
      sprintf(sDiscoverTimeMsg, "DiscoverCluster soapcall elapsed time=%u ms",
              iEndTickCount-iStartTickCount);
      Log(AUDIT_CLIENT_GetClusterInformation, 
           NULL, 
           sApplianceAddress, 
           sDiscoverTimeMsg);
#endif

      if ( !bSuccess )
      {
         GetSoapFault(sSoapFaultMsg, (struct soap*)pstSoap);      
         GetPeerNetworkAddress(sKmaAddress, pstSoap);
         LogError(i_pProfile,AUDIT_CLIENT_GET_CLUSTER_INFORMATION_SOAP_ERROR,
                  NULL,
                  sKmaAddress,
                  sSoapFaultMsg );

         if ( !ServerError( sSoapFaultMsg, pstSoap->errnum ) )
         {
                // do not failover if error is client related
                soap_destroy( pstSoap );
                soap_end( pstSoap );
                soap_free( pstSoap );
                return false;
         }
      }

      // If we did not succeed to Discover from the initial appliance, 
      // try to discover from other appliances that we know about that are enabled.
      // Disabled Appliances are not attempted because they may have a stale view
      // of the cluster. In particular, they themselves are not aware that they
      // are disabled.

      if ( !bSuccess && i_pProfile->m_iClusterNum > 0 )
      {
         // Copy the profile's cluster array so that we don't have to lock the 
         // profile around a SOAP call

         int j = 0;
         int iClusterNum = 0;
         KMSClusterEntry* aCluster =
            (KMSClusterEntry*)malloc(sizeof(KMSClusterEntry) * KMS_MAX_CLUSTER_NUM);

         bSuccess = ( aCluster != 0 );
#if defined(DEBUG) && defined(METAWARE)
        if (!bSuccess) 
           log_printf("Malloc %x aCluster returned null\n", 
                      sizeof(KMSClusterEntry) * KMS_MAX_CLUSTER_NUM);
#endif

         if ( bSuccess )
         {
            iClusterNum = i_pProfile->m_iClusterNum;
            memcpy( aCluster, i_pProfile->m_aCluster, 
                    sizeof(KMSClusterEntry) * iClusterNum );

            // initialize to false since all KMAs could be disabled
            bSuccess = false;
            for ( j = 0; j < iClusterNum; j++ )
            {
               if ( aCluster[j].m_iEnabled == FALSE )
               {
                  continue;
               }

               sApplianceAddress = aCluster[j].m_wsApplianceNetworkAddress;
               K_snprintf(sURL,
                       KMS_MAX_URL,
                       "https://%s:%d", 
                       sApplianceAddress,
                       i_pProfile->m_iPortForDiscoveryService);

               Log(AUDIT_CLIENT_GetClusterInformation, 
                   NULL, 
                   sApplianceAddress, 
                   "Failing over and trying this appliance");

               // SOAP - discover cluster
               bSuccess = 
                  KMS_Discovery::soap_call_KMS_Discovery__DiscoverCluster(
                     pstSoap, 
                     sURL,
                     NULL,
                     NULL,
                     stResponse ) == SOAP_OK;

               if ( !bSuccess )
               {                        
                  GetSoapFault(sSoapFaultMsg, (struct soap*)pstSoap);
                  GetPeerNetworkAddress(sKmaAddress, pstSoap);
                  LogError(i_pProfile,AUDIT_CLIENT_GET_CLUSTER_INFORMATION_SOAP_ERROR,
                           NULL,
                           sKmaAddress,
                           sSoapFaultMsg );
               }
               else
               {
                  // The discover succeeded
                  break;
               }
            }
         }

         if ( aCluster != 0 )
         {
            free(aCluster);
         }

         if ( bSuccess )
         {
            // Set the Profile's initial appliance to the Appliance
            // that we just succeeded to Discover from. KMSClient_SelectAppliance()
            // persists the updated config
            KMSClient_SelectAppliance( i_pProfile, 
                                       i_pProfile->m_aCluster[j].m_wsApplianceNetworkAddress );
         }
      }
   }

   if ( bSuccess )
   {
      if (((int)strlen(stResponse.EntitySiteID) > i_iEntitySiteIDSize - 1)) 
      {
         bSuccess = false;
         LogError(i_pProfile,AUDIT_CLIENT_GET_CLUSTER_INFORMATION,
                  NULL,
                  NULL,
                  "returned site id size too large" );
      }
   }

   // copy returned cluster information into i_pProfile->m_aCluster after
   // filtering the cluster members to a list with size <= KMS_MAX_CLUSTER_NUM
   if ( bSuccess )
   {
      KMS_Discovery::KMS_Discovery__ArrayOfClusterMembers aFilteredCluster;
      
      bSuccess = FilterCluster(&stResponse, i_pProfile->m_eKMSmode == FIPS_MODE, &aFilteredCluster);
      if (!bSuccess )
      {
          LogError(i_pProfile, AUDIT_CLIENT_GET_CLUSTER_INFORMATION,
                  NULL,
                  NULL,
                  "cluster response filtering failed" );
      }

      if(bSuccess)
      {
         int i;
         bool bPersistClusterConfig = ClusterConfigChanged(i_pProfile,
                    stResponse.EntitySiteID,
                    &aFilteredCluster);
                      
         strncpy(o_wsEntitySiteID,stResponse.EntitySiteID, i_iEntitySiteIDSize-1 );
         o_wsEntitySiteID[i_iEntitySiteIDSize-1] = '\0';

         strncpy(i_pProfile->m_wsEntitySiteID, stResponse.EntitySiteID, i_iEntitySiteIDSize-1 );
         i_pProfile->m_wsEntitySiteID[i_iEntitySiteIDSize-1] = '\0';

         // fill the aCluster array in the i_pProfile
         i_pProfile->m_iClusterNum = aFilteredCluster.__size;
         for (i = 0;  i < i_pProfile->m_iClusterNum; i++)
         {
            i_pProfile->m_aCluster[i].m_lApplianceID = 
               (aFilteredCluster.__ptr+i)->KMAID;
            i_pProfile->m_aCluster[i].m_iEnabled = 
               (aFilteredCluster.__ptr+i)->Enabled;
            i_pProfile->m_aCluster[i].m_iResponding = 
               (aFilteredCluster.__ptr+i)->Responding;

            i_pProfile->m_aCluster[i].m_lLoad = (aFilteredCluster.__ptr+i)->Load;
            strncpy(i_pProfile->m_aCluster[i].m_wsApplianceAlias, 
                   (aFilteredCluster.__ptr+i)->KMAName,
                   KMS_MAX_ENTITY_ID);
            i_pProfile->m_aCluster[i].m_wsApplianceAlias[KMS_MAX_ENTITY_ID] = '\0';
            // if the m_wsApplianceAddress is IPv6 then we'll store
            // KMA IPv6 addresses if they have one
            if ( strchr( i_pProfile->m_wsApplianceAddress, ':') )
            {
                // KMAs prior to 2.1, or 2.1 KMAs at rep schema < 10
                // will not have IPv6 attributes in the soap response
                if ( (aFilteredCluster.__ptr+i)->KMANetworkAddressIPv6 &&
                      ValidIPv6KMAaddress((aFilteredCluster.__ptr+i)->KMANetworkAddressIPv6))
                {
                    strcpy(i_pProfile->m_aCluster[i].m_wsApplianceNetworkAddress, "[");
                    char * pLoc = strchr((aFilteredCluster.__ptr+i)->KMANetworkAddressIPv6,
                            '/');
                    if ( pLoc != NULL )
                    {
                        // remove prefix from address
                        *pLoc = '\0';
                        strcat(i_pProfile->m_aCluster[i].m_wsApplianceNetworkAddress,
                               (aFilteredCluster.__ptr+i)->KMANetworkAddressIPv6 );
                    }
                    else
                    {
                        strcat(i_pProfile->m_aCluster[i].m_wsApplianceNetworkAddress,
                                (aFilteredCluster.__ptr + i)->KMANetworkAddressIPv6);
                    }
                    strcat(i_pProfile->m_aCluster[i].m_wsApplianceNetworkAddress, "]");
                }
                else
                {
                    // use the IPv4 address
                    strncpy(i_pProfile->m_aCluster[i].m_wsApplianceNetworkAddress, 
                           (aFilteredCluster.__ptr+i)->KMANetworkAddress,
                           KMS_MAX_NETWORK_ADDRESS);                    
                }
            }
            else
            {
                strncpy(i_pProfile->m_aCluster[i].m_wsApplianceNetworkAddress, 
                       (aFilteredCluster.__ptr+i)->KMANetworkAddress,
                       KMS_MAX_NETWORK_ADDRESS);
            }
            i_pProfile->m_aCluster[i].m_wsApplianceNetworkAddress[KMS_MAX_NETWORK_ADDRESS] = '\0';
            strncpy(i_pProfile->m_aCluster[i].m_wsApplianceSiteID, 
                   (aFilteredCluster.__ptr+i)->KMASiteID,
                   KMS_MAX_ENTITY_SITE_ID);
            i_pProfile->m_aCluster[i].m_wsApplianceSiteID[KMS_MAX_ENTITY_SITE_ID] = '\0';

            if ((aFilteredCluster.__ptr + i)->KMAVersion)
            {
                strncpy(i_pProfile->m_aCluster[i].m_sKMAVersion,
                        (aFilteredCluster.__ptr + i)->KMAVersion,
                        KMS_MAX_VERSION_LENGTH);
                i_pProfile->m_aCluster[i].m_sKMAVersion[KMS_MAX_VERSION_LENGTH] = '\0';
            }
            else
            {
                i_pProfile->m_aCluster[i].m_sKMAVersion[0] = '\0';
            }

            if ((aFilteredCluster.__ptr + i)->KMS_Discovery__Locked)
            {
                i_pProfile->m_aCluster[i].m_iKMALocked = TRUE;
            }
            else
            {
                i_pProfile->m_aCluster[i].m_iKMALocked = FALSE;
            }
         }

         // now release malloc'd storage from filtering the cluster response
         FreeFilteredCluster( &aFilteredCluster, aFilteredCluster.__size );

         // fill the array specified by the caller
         *o_pApplianceNum = i_pProfile->m_iClusterNum;
         for (i = 0;  i < i_pProfile->m_iClusterNum; i++)
         {
            o_pClusterEntryArray[i].m_lApplianceID = i_pProfile->m_aCluster[i].m_lApplianceID;
            o_pClusterEntryArray[i].m_iEnabled = i_pProfile->m_aCluster[i].m_iEnabled;
            o_pClusterEntryArray[i].m_iResponding = i_pProfile->m_aCluster[i].m_iResponding;
            o_pClusterEntryArray[i].m_lLoad = i_pProfile->m_aCluster[i].m_lLoad;
            strncpy(o_pClusterEntryArray[i].m_wsApplianceAlias, 
                   i_pProfile->m_aCluster[i].m_wsApplianceAlias,
                   KMS_MAX_ENTITY_ID);
            o_pClusterEntryArray[i].m_wsApplianceAlias[KMS_MAX_ENTITY_ID] = '\0';
            strncpy(o_pClusterEntryArray[i].m_wsApplianceNetworkAddress, 
                   i_pProfile->m_aCluster[i].m_wsApplianceNetworkAddress,
                   KMS_MAX_NETWORK_ADDRESS);
            o_pClusterEntryArray[i].m_wsApplianceNetworkAddress[KMS_MAX_NETWORK_ADDRESS] = '\0';
            strncpy(o_pClusterEntryArray[i].m_wsApplianceSiteID, 
                   i_pProfile->m_aCluster[i].m_wsApplianceSiteID,
                   KMS_MAX_ENTITY_SITE_ID);
            o_pClusterEntryArray[i].m_wsApplianceSiteID[KMS_MAX_ENTITY_SITE_ID] = '\0';
            strncpy(o_pClusterEntryArray[i].m_sKMAVersion, i_pProfile->m_aCluster[i].m_sKMAVersion,
                    KMS_MAX_VERSION_LENGTH);
            o_pClusterEntryArray[i].m_sKMAVersion[KMS_MAX_VERSION_LENGTH] = '\0';
         }

         i_pProfile->m_iLastClusterDiscoveryTime = K_GetTickCount() / 1000;
         i_pProfile->m_bIsClusterDiscoveryCalled = true;

         if ( bPersistClusterConfig )
         {
             bSuccess = StoreCluster(i_pProfile);
             if (!bSuccess)
             {
                 Log(AUDIT_CLIENT_GetClusterInformation, 
                     NULL, 
                     NULL, 
                     "Could not store cluster");
             }
         }
      }
   }

   // cleanup 
   if (pstSoap)
   {
      soap_destroy(pstSoap);
      soap_end(pstSoap);
      if (!bSuccess)
      {
          soap_free(pstSoap);
      }
      else
      {
        // we want to persist discovery soap runtime to avoid ssl handshakes so soap_free() is not called
      }
   }
         
   // if we're enrolled but cannot get cluster information from an appliance, then we'll try to load
   // it from the profile
   if ( !bSuccess && i_pProfile->m_iEnrolled )
   {
      int bClusterInformationFound = false;

      bSuccess = LoadClusterInformation( i_pProfile, bClusterInformationFound );

      if ( bSuccess && bClusterInformationFound )
      {
         Log(AUDIT_CLIENT_GetClusterInformation, 
                 NULL, 
                 NULL, 
                 "Using persisted cluster information");

         strncpy(o_wsEntitySiteID, i_pProfile->m_wsEntitySiteID, i_iEntitySiteIDSize-1);
         o_wsEntitySiteID[i_iEntitySiteIDSize-1] = '\0';

         // fill the array specified by the caller
         *o_pApplianceNum = i_pProfile->m_iClusterNum;
         for (int i = 0;  i < i_pProfile->m_iClusterNum; i++)
         {
            o_pClusterEntryArray[i].m_lApplianceID = i_pProfile->m_aCluster[i].m_lApplianceID;
            o_pClusterEntryArray[i].m_iEnabled = i_pProfile->m_aCluster[i].m_iEnabled;
            o_pClusterEntryArray[i].m_iResponding = TRUE; // since cluster info comes from a file, set it to TRUE

            o_pClusterEntryArray[i].m_lLoad = i_pProfile->m_aCluster[i].m_lLoad;
            strncpy(o_pClusterEntryArray[i].m_wsApplianceAlias, 
                   i_pProfile->m_aCluster[i].m_wsApplianceAlias,
                   KMS_MAX_ENTITY_ID);
            o_pClusterEntryArray[i].m_wsApplianceAlias[KMS_MAX_ENTITY_ID] = '\0';
            strncpy(o_pClusterEntryArray[i].m_wsApplianceNetworkAddress, 
                   i_pProfile->m_aCluster[i].m_wsApplianceNetworkAddress,
                   KMS_MAX_NETWORK_ADDRESS);
            o_pClusterEntryArray[i].m_wsApplianceNetworkAddress[KMS_MAX_NETWORK_ADDRESS] = '\0';
            strncpy(o_pClusterEntryArray[i].m_wsApplianceSiteID, 
                   i_pProfile->m_aCluster[i].m_wsApplianceSiteID,
                   KMS_MAX_ENTITY_SITE_ID);
            o_pClusterEntryArray[i].m_wsApplianceSiteID[KMS_MAX_ENTITY_SITE_ID] = '\0';
            strncpy(o_pClusterEntryArray[i].m_sKMAVersion,
                    i_pProfile->m_aCluster[i].m_sKMAVersion, 
                    KMS_MAX_VERSION_LENGTH);
            o_pClusterEntryArray[i].m_sKMAVersion[KMS_MAX_VERSION_LENGTH] = '\0';
         }

         i_pProfile->m_iLastClusterDiscoveryTime = K_GetTickCount() / 1000;
      }
      else if ( bSuccess && !bClusterInformationFound )
      {
         // if we're here, then we need to return an error
         bSuccess = false;
      }
   }

   return bSuccess;
}

bool KMSClient_NoFIPSCompatibleKMAs(const KMSClientProfile * const i_pProfile)
{
    bool bNoFIPScompatibleKMA = true;
    for (int i=0; i < i_pProfile->m_iClusterNum; i++)
    {
        if ( FIPScompatibleKMA(i_pProfile->m_aCluster[i].m_sKMAVersion))
        {
            bNoFIPScompatibleKMA = false;
            break;
        }
    }
    return bNoFIPScompatibleKMA;
}

/*---------------------------------------------------------------------------
 * Function: KMSClient_SelectAppliance
 *
 *--------------------------------------------------------------------------*/
bool KMSClient_SelectAppliance(KMSClientProfile *i_pProfile,
                                utf8char *i_wsApplianceAddress)
{
    FATAL_ASSERT(i_pProfile);
    FATAL_ASSERT(i_wsApplianceAddress);

    CAutoMutex oAutoMutex( (K_MUTEX_HANDLE)i_pProfile->m_pLock );

    bool bSuccess = true;

    if(strlen(i_wsApplianceAddress) >= KMS_MAX_NETWORK_ADDRESS)
    {
        LogError(i_pProfile,AUDIT_CLIENT_SELECT_APPLIANCE,
            NULL,
            NULL,
            "Appliance Address too large" );
        bSuccess = false;        
    }

    if(bSuccess)
    {
        strncpy(i_pProfile->m_wsApplianceAddress, 
            i_wsApplianceAddress,
            KMS_MAX_NETWORK_ADDRESS);
        i_pProfile->m_wsApplianceAddress[KMS_MAX_NETWORK_ADDRESS] = 0;
    }

    bSuccess = StoreConfig( i_pProfile );

    return bSuccess;
}

bool KMSClient_ProfileLoaded( KMSClientProfile *i_pProfile )
{

#if defined(DEBUG) && defined(METAWARE)
   log_printf ("profile: %x", i_pProfile);
   log_printf ("profile: enrolled %x", i_pProfile->m_iEnrolled);
   log_printf ("profile: version  %x", i_pProfile->m_iVersion);
#endif   

    // more extensive tests could be performed but this should suffice
    if ( i_pProfile && 
        i_pProfile->m_iEnrolled &&
		i_pProfile->m_iVersion == KMS_AGENT_VERSION )
    {
        return true;
    }
    else
    {
        return false;
    }
}

/*---------------------------------------------------------------------------
 * Function: KMSClient_DeleteProfile
 *
 *--------------------------------------------------------------------------*/
bool KMSClient_DeleteProfile(utf8char *i_wsProfileName)
{
    FATAL_ASSERT( i_wsProfileName && (strlen(i_wsProfileName) > 0) );
    
    bool bSuccess = true;

    if (ProfileExists(g_wsWorkingDirectory, /* pass in default */
                      i_wsProfileName))
    {
        bSuccess = DeleteStorageProfile(i_wsProfileName);
    }

    return bSuccess;
}

/*---------------------------------------------------------------------------
 * Function: KMSClient_UnloadProfile
 *
 *--------------------------------------------------------------------------*/
bool KMSClient_UnloadProfile(KMSClientProfile *i_pProfile)
{
    if(i_pProfile != NULL && i_pProfile->m_pLock != NULL )
    {
#ifdef KMSUSERPKCS12
	/* Delete the private client key file if it's still around */
	CleanupPrivateKeyFile(i_pProfile);
#endif
        if (i_pProfile->m_pAgentLoadBalancer != NULL)
        {
            delete reinterpret_cast
                <CAgentLoadBalancer *> (i_pProfile->m_pAgentLoadBalancer);
        }
        if (i_pProfile->m_pDataUnitCache != NULL)
        {
            delete reinterpret_cast<CDataUnitCache *> (i_pProfile->m_pDataUnitCache);
        }
        K_DestroyMutex((K_MUTEX_HANDLE)i_pProfile->m_pLock);
        i_pProfile->m_pLock = 0;

        if ( i_pProfile->m_pvSoap )
        {
            soap_destroy( (struct soap*)i_pProfile->m_pvSoap );
            soap_end( (struct soap*)i_pProfile->m_pvSoap );
            soap_done( (struct soap*)i_pProfile->m_pvSoap );

            free( (struct soap*)i_pProfile->m_pvSoap );
            i_pProfile->m_pvSoap = 0;
        }
        
        if ( i_pProfile->m_pvDiscoverySoap)
        {
            soap_destroy( (struct soap*)i_pProfile->m_pvDiscoverySoap );
            soap_end( (struct soap*)i_pProfile->m_pvDiscoverySoap );
            soap_done( (struct soap*)i_pProfile->m_pvDiscoverySoap );

            free( (struct soap*)i_pProfile->m_pvDiscoverySoap );
            i_pProfile->m_pvDiscoverySoap = 0;           
        }
    }

    i_pProfile->m_iEnrolled = FALSE;

    return true; /* always return true, maybe there are cases which return false in the future */
}

bool FIPScompatibleKMA(
        const char * const i_sKMAVersion) {
    return (strcmp(i_sKMAVersion,
            FIPS_COMPATIBLE_KMA_VERSION) >= 0);
}

#ifdef KMSUSERPKCS12
extern "C"
KMS_AGENT_STATUS
KMSAgent_GetProfileStatus(
	char* i_pProfileName,
	KMSAGENT_PROFILE_FLAGS *flags)
{
	/*
	 * Determine how "initialized" the KMS token is by checking for
	 * the profile config file and also the entity key container (pkcs#12).
	 */
	if (ProfileExists(g_wsWorkingDirectory, i_pProfileName)) {
		*flags |= KMSAGENT_PROFILE_EXISTS_FLAG;
		if (ClientKeyP12Exists(i_pProfileName))
			*flags |= KMSAGENT_CLIENTKEY_EXISTS_FLAG;
	}
	return (KMS_AGENT_STATUS_OK);
}
#endif
