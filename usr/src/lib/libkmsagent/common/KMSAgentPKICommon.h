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
 * \file KMSAgentPKICommon.h
 *
 * X.509 Certificate and Private Key Support Interface
 *
 * This module provides simple interfaces to support SSL communication
 * for the KMS Agent enrollment protocol.  Basic classes supporting 
 * X.509 certificates, private key management are provided and hide
 * specific implementations from users of these classes.
 */
/*-------------------------------------------------------------------------*/

#ifndef K_KMSAgentPKICommon_h
#define K_KMSAgentPKICommon_h

#ifdef WIN32
#pragma warning(disable: 4786)
#endif

#define MAX_CERT_SIZE                                       4096
#define MAX_KEY_SIZE                                        4096

#define DEFAULT_KEY_SIZE                                    2048

#ifdef KMSUSERPKCS12
enum EnumPKIFileFormat { FILE_FORMAT_DER, FILE_FORMAT_PEM, FILE_FORMAT_PKCS12 };
#else
enum EnumPKIFileFormat { FILE_FORMAT_DER, FILE_FORMAT_PEM };
#endif

/**
 *   This class provides a simple interface for the management of
 *   public keys.  Simple load and store operations are provided for
 *   storage and retrieval from memory buffers.
 */
class CPublicKey
{

public:

	CPublicKey();

	/**
     * This method saves public key into a buffer,
     * it also returns the actual used buffer length.
     * @param i_pcBuffer Buffer to receive public key
     * @param i_iBufferLength length of the buffer provided
     * @param o_pActualLength actual length of the public key stored into the buffer
     * @param i_iFormat key format, @see EnumPKIFileFormat
     */
    bool Save(unsigned char * const i_pcBuffer, 
            int                     i_iBufferLength, 
            int * const             o_pActualLength,
			int                     i_iFormat);
   /**
     *  This method loads the public key from a buffer
     *  @param i_pcBuffer
     *  @param i_iLength
     *  @param i_iFormat   one of the enums from EnumPKIFileFormat,
     *                     only FILE_FORMAT_PEM is supported.
     *  @return true for success, false otherwise
     */
    bool Load (unsigned char * const i_pcBuffer,
               int i_iLength,
               int i_iFormat);
    
   /**
     *   use this object's public key to encrypt plaintext buffer
     */
    bool Encrypt (int i_iLength,
                  const unsigned char * const i_pcPlainText,
                  unsigned char * const o_pcCypherText,
                  int * const o_pActualLength);
    
    ~CPublicKey();

private:
   void *m_pPublicKeyImpl;
};

/**
 *   This class provides a simple interface for the management of
 *   private keys.  Simple load and store operations are provided for
 *   storage and retrieval from memory buffers.
 *
 */
class CPrivateKey
{

  public:

   CPrivateKey();
    
   /**
    *   Saves the private key to a memory buffer specified by
    *   i_pcBuffer. Currently just the PEM format is supported.
    *   Specification of a passphrase allows encryption of the private
    *   key subject to the choice of the implementation.
    *
    *   @param[in]   i_pcBuffer
    *   @param[in]   i_iBufferLength
    *   @param[out]  o_pActualLength
    *   @param[in]   i_pPassphrase optional, if non-null the private key is
    *   wrapped using this passphrase
    *   @param[in]   i_iFormat   one of the enums from EnumPKIFileFormat,
    *                      only FILE_FORMAT_PEM is supported.
    *   @return true for success, false otherwise
    */
   bool Save( unsigned char * const      i_pcBuffer, 
              int                        i_iBufferLength,
              int * const                o_pActualLength,
              const char * const         i_pPassphrase, 
              int                        i_iFormat );

   /**
    *  This method loads the private key from a buffer
    *  @param i_pcBuffer
    *  @param i_iLength
    *  @param i_pPassphrase optional, if non-null the private key is
    *   unwrapped using this passphrase
    *  @param i_iFormat   one of the enums from EnumPKIFileFormat,
    *                     only FILE_FORMAT_PEM is supported.
    *  @return true for success, false otherwise
    */
   bool Load(unsigned char * const i_pcBuffer,
             int                   i_iLength,
             const char * const    i_pPassphrase,
             int                   i_iFormat);

   ~CPrivateKey();

#ifdef KMSUSERPKCS12
	void *GetNative();
	void SetNative(void *);
#endif
  private:
   void *m_pPKeyImpl;

};

/**
 *   This class provides a simple interface for managing X.509
 *   certificates providing only simple load and save operations for
 *   storage and retrieval.
 *
 */
class CCertificate
{

public:
	CCertificate();

	~CCertificate();
    
    /**
     *   save the certificate to the specified file name. Currently,
     *   only FILE_FORMAT_PEM is supported.
     */
	bool Save(  const char * const  i_pcFileName, 
                int                 i_iFormat);

    /**
     *  save the certificate to the specified buffer. Currently, only
     *  FILE_FORMAT_PEM is supported.
     */      
	bool Save( unsigned char * const i_pcBuffer,
               int                   i_iBufferLength,
               int * const           o_pActualLength,
               int                   i_iFormat);

    /**
     *   load a certificate from the specified filename. Currently,
     *   only FILE_FORMAT_PEM is supported.
     */      
    bool Load( const char * const i_pcFileName, 
               int                i_iFormat );

    /**
     *   load a certificate from the specified buffer. Currently, only
     *   FILE_FORMAT_PEM is supported.
     */          
    bool Load( unsigned char * const i_pcBuffer,
               int                   i_iLength,
               int                   i_iFormat );

    /**
     *   prints the certificate to stdout
     */          
    bool Dump();
        
#ifdef KMSUSERPKCS12
	bool LoadPKCS12CertAndKey(char *filename,
		int i_iFormat,
		CPrivateKey *i_pPrivateKey,
		char *i_pPassphrase);

	bool SavePKCS12(
	    unsigned char *i_pcBuffer,
	    int i_iBufferLength,
	    int *o_pActualLength,
	    CPrivateKey* i_pPrivateKey,
	    char* i_sPassphrase );
#endif

private:
    /**
     *  an opague pointer to implementation specific resources to be
     *  freed by the Destructor.
     */
    void    *m_pCertImpl;
#ifdef KMSUSERPKCS12
    /**
     * saves certificate to PKCS#12 memory BIO
     * @param i_pPrivateKey
     * @param i_sPassphrase
     * @return pointer to the Memory BIO
     */
    void* SaveCertToPKCS12MemoryBIO(
            CPrivateKey* i_pPrivateKey,
            char *i_sPassphrase);
#endif

};


/**
 *  This class provides a method for storing an X.509 certificate and
 *  private key to a file.  The private key is appended to the
 *  certificate and optionally encrypted with the specified passphrase
 *  for encoding and storage in PEM format.
 */
class CPKI
{
  public:
   CPKI();
   ~CPKI();

  public:

      /**
       *   exports a certificate and associated private key to the
       *   specified file.
       *   @param i_pCertificate a pointer to an instance of a certificate
       *   @param i_pPrivateKey  a pointer to an instance of a private key 
       *   @param i_pcFileName  the name of the file to store the cert and private key
       *   @param i_sPassphrase optional but when provided supplies a
       *   pass phrase to use for encrypting the private key.  The cipher
       *   used for encryption is determined by the underlying implementation 
       *   which for the reference implementation uses triple DES by default.
       *   @param i_eFileFormat the encoding format to use for the certificate and private key
       */
      bool ExportCertAndKeyToFile(
            CCertificate* const         i_pCertificate,  
            CPrivateKey*  const         i_pPrivateKey,
            const char* const           i_pcFileName,
            const char* const           i_sPassphrase,
            EnumPKIFileFormat           i_eFileFormat );

  private:

   int m_iKeyLength;

   CCertificate *m_pCACertificate;
   CPrivateKey *m_pCAPrivateKey;
 };

#endif  //K_KMSAgentPKICommon_h
