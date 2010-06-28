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
 * \file    KMSAgentStorage.h
 *
 *  This header provides an interface for the agent library to persist profile information, including
 *  <ul>
 *  <li>Profile Configuration properties
 *  <li>Profile KMS Cluster information
 *  <li>PKI Certificates and Agent Private Key
 *  </ul>
 *  With the storage management of PKI elements is an interface for initialization of the gSoap SSL 
 *  client context.
 *  <p>
 *  The reference implementation of this interface maps these storage elements into files.
 *  Other implmentations may need to persist these elements into other types of non-volatile
 *  storage.
 */

#ifndef KMSAGENT_STORAGE_H
#define KMSAGENT_STORAGE_H

/**
 *  checks if a profile exists in the working directory with the name specified in the io_pProfile struct
 */
extern "C" bool ProfileExists(
                const char* const i_pWorkingDirectory,
                const char* const i_pProfileName);

/**
 *   creates a Storage object in the working directory with the specified name.  
 *   The storage object's contents are empty.
 */
bool CreateProfile(
   KMSClientProfile* const io_pProfile,
   const char* const i_pWorkingDirectory,
   const char* const i_pProfileName);

/**
 *  saves the Config portion of the profile into persistent storage
 */
bool StoreConfig(
            KMSClientProfile* const i_pProfile );

/**
 *  saves the Cluster information from the profile into persistent storage
 */
bool StoreCluster(            
            KMSClientProfile* const i_pProfile );

/**
 *  retrieve the Config information from persistent storage into the profile
 */
bool GetConfig(
        KMSClientProfile* const io_pProfile );


/**
 *  populate cluster array with names from storage.  If the profile does
 *  does not contain cluster information then sets o_bClusterInformationFound
 *  to true.
 */
bool GetCluster(
   KMSClientProfile* const io_pProfile,
   int&                   o_bClusterInformationFound );

/**
 *   delete the cluster information from persistent storage
 */
bool DeleteCluster( KMSClientProfile* const io_pProfile );

/**
 *  saves the CA certificate into persistent storage
 */
bool StoreCACertificate(
   KMSClientProfile* const     i_pProfile,
   CCertificate* const         i_pCACertificate );


/**
 *  save the CA certificate, agent certificate and agent
 *  private key material to persistent storage
 *  @param i_sHexHashedPassphrase this is an optional passphrase
 *  that is required when the caller wishes the private key to be
 *  encrypted.  The private key will then be encrypted using this
 *  pass phrase.
 */
bool StorePKIcerts(
        KMSClientProfile* const     io_pProfile,
        CCertificate* const         i_pCACertificate,
        CCertificate* const         i_pAgentCertificate,
        CPrivateKey* const          i_pAgentPrivateKey,
        const char* const           i_sHexHashedPassphrase );

/**
 *  retrieve the CA certificate, agent certificate and agent
 *  private key material from persistent storage and reference
 *  from the profile
 */
bool GetPKIcerts(
        KMSClientProfile* const     io_pProfile );

#ifdef KMSUSERPKCS12
bool StoreAgentPKI(
	KMSClientProfile* const i_pProfile,
	CCertificate* const     i_pAgentCertificate,
	CPrivateKey* const      i_pAgentPrivateKey,
	const char* const       i_sHexHashedPassphrase);

bool GetPKCS12CertAndKey(
	KMSClientProfile* const io_pProfile,
	utf8char        *i_pPassphrase,
	CCertificate    *i_pEntityCert,
	CPrivateKey     *i_pEntityPrivateKey);

bool StoreTempAgentPKI(
	KMSClientProfile* const io_pProfile,
	CCertificate    *i_pEntityCert,
	CPrivateKey     *i_pEntityPrivateKey);

bool ClientKeyP12Exists(char *profileName);

void CleanupPrivateKeyFile(KMSClientProfile* const io_pProfile);
#endif

/**
 *  Provides a wrapper to gSoap's soap_ssl_client_context()
 *  that hides how Certificates and Private key material are presented to the underlying SSL
 *  layer.
 *  @param  i_pProfile The profile must contain a reference to the CA certificate and for 
 *                  SOAP_SSL_REQUIRE_CLIENT_AUTHENTICATION the Agent's certificate and private key material.
 *  @param  io_pSoap  gSoap runtime
 *  @param  i_iFlags  These are the gSoap authentication flags, either 
 *                  SOAP_SSL_REQUIRE_SERVER_AUTHENTICATION or SOAP_SSL_REQUIRE_CLIENT_AUTHENTICATION.  
 *                  The private key password argument is only applicable
 *                  for SOAP_SSL_REQUIRE_CLIENT_AUTHENTICATION.
 *
 *  @return value from gSoap's soap_ssl_client_context()
 */
int K_soap_ssl_client_context(
        KMSClientProfile* const   i_pProfile,
        struct soap *             io_pSoap, 
        unsigned short            i_iFlags ); 

/**
 *  deletes the persistent storage object specified by name and its contents
 */
bool DeleteStorageProfile( 
                const char* const i_pName);

#endif // KMSAGENT_STORAGE_H

