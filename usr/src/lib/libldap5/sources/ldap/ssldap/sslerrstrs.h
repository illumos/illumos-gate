/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The contents of this file are subject to the Netscape Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/NPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is Mozilla Communicator client code, released
 * March 31, 1998.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation. Portions created by Netscape are
 * Copyright (C) 1998-1999 Netscape Communications Corporation. All
 * Rights Reserved.
 *
 * Contributor(s):
 */
/*
 * sslerrstrs.h - map SSL errors to strings (used by errormap.c)
 *
 */

/*
 ****************************************************************************
 * The code below this point was provided by Nelson Bolyard <nelsonb> of the
 *	Netscape Certificate Server team on 27-March-1998.
 *	Taken from the file ns/security/cmd/lib/SSLerrs.h on NSS_1_BRANCH.
 *	Last updated from there: 24-July-1998 by Mark Smith <mcs>
 *
 * All of the Directory Server specific changes are enclosed inside
 *	#ifdef NS_DIRECTORY.
 ****************************************************************************
 */

/* SSL-specific security error codes  */
/* caller must include "sslerr.h" */

ER3(SSL_ERROR_EXPORT_ONLY_SERVER,			SSL_ERROR_BASE + 0,
dgettext(TEXT_DOMAIN,
"Unable to communicate securely.  Peer does not support high-grade encryption."))

ER3(SSL_ERROR_US_ONLY_SERVER,				SSL_ERROR_BASE + 1,
dgettext(TEXT_DOMAIN,
"Unable to communicate securely.  Peer requires high-grade encryption which is not supported."))

ER3(SSL_ERROR_NO_CYPHER_OVERLAP,			SSL_ERROR_BASE + 2,
dgettext(TEXT_DOMAIN,
"Cannot communicate securely with peer: no common encryption algorithm(s)."))

ER3(SSL_ERROR_NO_CERTIFICATE,				SSL_ERROR_BASE + 3,
dgettext(TEXT_DOMAIN,
"Unable to find the certificate or key necessary for authentication."))

ER3(SSL_ERROR_BAD_CERTIFICATE,				SSL_ERROR_BASE + 4,
dgettext(TEXT_DOMAIN,
"Unable to communicate securely with peer: peers's certificate was rejected."))

/* unused						(SSL_ERROR_BASE + 5),*/

ER3(SSL_ERROR_BAD_CLIENT,				SSL_ERROR_BASE + 6,
dgettext(TEXT_DOMAIN,
"The server has encountered bad data from the client."))

ER3(SSL_ERROR_BAD_SERVER,				SSL_ERROR_BASE + 7,
dgettext(TEXT_DOMAIN,
"The client has encountered bad data from the server."))

ER3(SSL_ERROR_UNSUPPORTED_CERTIFICATE_TYPE,		SSL_ERROR_BASE + 8,
dgettext(TEXT_DOMAIN,
"Unsupported certificate type."))

ER3(SSL_ERROR_UNSUPPORTED_VERSION,			SSL_ERROR_BASE + 9,
dgettext(TEXT_DOMAIN,
"Peer using unsupported version of security protocol."))

/* unused						(SSL_ERROR_BASE + 10),*/

ER3(SSL_ERROR_WRONG_CERTIFICATE,			SSL_ERROR_BASE + 11,
dgettext(TEXT_DOMAIN,
"Client authentication failed: private key in key database does not match public key in certificate database."))

ER3(SSL_ERROR_BAD_CERT_DOMAIN,				SSL_ERROR_BASE + 12,
dgettext(TEXT_DOMAIN,
"Unable to communicate securely with peer: requested domain name does not match the server's certificate."))

/* SSL_ERROR_POST_WARNING				(SSL_ERROR_BASE + 13),
   defined in sslerr.h
*/

ER3(SSL_ERROR_SSL2_DISABLED,				(SSL_ERROR_BASE + 14),
dgettext(TEXT_DOMAIN,
"Peer only supports SSL version 2, which is locally disabled."))


ER3(SSL_ERROR_BAD_MAC_READ,				(SSL_ERROR_BASE + 15),
dgettext(TEXT_DOMAIN,
"SSL received a record with an incorrect Message Authentication Code."))

ER3(SSL_ERROR_BAD_MAC_ALERT,				(SSL_ERROR_BASE + 16),
dgettext(TEXT_DOMAIN,
"SSL peer reports incorrect Message Authentication Code."))

ER3(SSL_ERROR_BAD_CERT_ALERT,				(SSL_ERROR_BASE + 17),
dgettext(TEXT_DOMAIN,
"SSL peer cannot verify your certificate."))

ER3(SSL_ERROR_REVOKED_CERT_ALERT,			(SSL_ERROR_BASE + 18),
dgettext(TEXT_DOMAIN,
"SSL peer rejected your certificate as revoked."))

ER3(SSL_ERROR_EXPIRED_CERT_ALERT,			(SSL_ERROR_BASE + 19),
dgettext(TEXT_DOMAIN,
"SSL peer rejected your certificate as expired."))

ER3(SSL_ERROR_SSL_DISABLED,				(SSL_ERROR_BASE + 20),
dgettext(TEXT_DOMAIN,
"Cannot connect: SSL is disabled."))

ER3(SSL_ERROR_FORTEZZA_PQG,				(SSL_ERROR_BASE + 21),
dgettext(TEXT_DOMAIN,
"Cannot connect: SSL peer is in another FORTEZZA domain."))

ER3(SSL_ERROR_UNKNOWN_CIPHER_SUITE          , (SSL_ERROR_BASE + 22),
dgettext(TEXT_DOMAIN,
"An unknown SSL cipher suite has been requested."))

ER3(SSL_ERROR_NO_CIPHERS_SUPPORTED          , (SSL_ERROR_BASE + 23),
dgettext(TEXT_DOMAIN,
"No cipher suites are present and enabled in this program."))

ER3(SSL_ERROR_BAD_BLOCK_PADDING             , (SSL_ERROR_BASE + 24),
dgettext(TEXT_DOMAIN,
"SSL received a record with bad block padding."))

ER3(SSL_ERROR_RX_RECORD_TOO_LONG            , (SSL_ERROR_BASE + 25),
dgettext(TEXT_DOMAIN,
"SSL received a record that exceeded the maximum permissible length."))

ER3(SSL_ERROR_TX_RECORD_TOO_LONG            , (SSL_ERROR_BASE + 26),
dgettext(TEXT_DOMAIN,
"SSL attempted to send a record that exceeded the maximum permissible length."))

/*
 * Received a malformed (too long or short or invalid content) SSL handshake.
 */
ER3(SSL_ERROR_RX_MALFORMED_HELLO_REQUEST    , (SSL_ERROR_BASE + 27),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Hello Request handshake message."))

ER3(SSL_ERROR_RX_MALFORMED_CLIENT_HELLO     , (SSL_ERROR_BASE + 28),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Client Hello handshake message."))

ER3(SSL_ERROR_RX_MALFORMED_SERVER_HELLO     , (SSL_ERROR_BASE + 29),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Server Hello handshake message."))

ER3(SSL_ERROR_RX_MALFORMED_CERTIFICATE      , (SSL_ERROR_BASE + 30),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Certificate handshake message."))

ER3(SSL_ERROR_RX_MALFORMED_SERVER_KEY_EXCH  , (SSL_ERROR_BASE + 31),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Server Key Exchange handshake message."))

ER3(SSL_ERROR_RX_MALFORMED_CERT_REQUEST     , (SSL_ERROR_BASE + 32),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Certificate Request handshake message."))

ER3(SSL_ERROR_RX_MALFORMED_HELLO_DONE       , (SSL_ERROR_BASE + 33),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Server Hello Done handshake message."))

ER3(SSL_ERROR_RX_MALFORMED_CERT_VERIFY      , (SSL_ERROR_BASE + 34),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Certificate Verify handshake message."))

ER3(SSL_ERROR_RX_MALFORMED_CLIENT_KEY_EXCH  , (SSL_ERROR_BASE + 35),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Client Key Exchange handshake message."))

ER3(SSL_ERROR_RX_MALFORMED_FINISHED         , (SSL_ERROR_BASE + 36),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Finished handshake message."))

/*
 * Received a malformed (too long or short) SSL record.
 */
ER3(SSL_ERROR_RX_MALFORMED_CHANGE_CIPHER    , (SSL_ERROR_BASE + 37),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Change Cipher Spec record."))

ER3(SSL_ERROR_RX_MALFORMED_ALERT            , (SSL_ERROR_BASE + 38),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Alert record."))

ER3(SSL_ERROR_RX_MALFORMED_HANDSHAKE        , (SSL_ERROR_BASE + 39),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Handshake record."))

ER3(SSL_ERROR_RX_MALFORMED_APPLICATION_DATA , (SSL_ERROR_BASE + 40),
dgettext(TEXT_DOMAIN,
"SSL received a malformed Application Data record."))

/*
 * Received an SSL handshake that was inappropriate for the state we're in.
 * E.g. Server received message from server, or wrong state in state machine.
 */
ER3(SSL_ERROR_RX_UNEXPECTED_HELLO_REQUEST   , (SSL_ERROR_BASE + 41),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Hello Request handshake message."))

ER3(SSL_ERROR_RX_UNEXPECTED_CLIENT_HELLO    , (SSL_ERROR_BASE + 42),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Client Hello handshake message."))

ER3(SSL_ERROR_RX_UNEXPECTED_SERVER_HELLO    , (SSL_ERROR_BASE + 43),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Server Hello handshake message."))

ER3(SSL_ERROR_RX_UNEXPECTED_CERTIFICATE     , (SSL_ERROR_BASE + 44),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Certificate handshake message."))

ER3(SSL_ERROR_RX_UNEXPECTED_SERVER_KEY_EXCH , (SSL_ERROR_BASE + 45),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Server Key Exchange handshake message."))

ER3(SSL_ERROR_RX_UNEXPECTED_CERT_REQUEST    , (SSL_ERROR_BASE + 46),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Certificate Request handshake message."))

ER3(SSL_ERROR_RX_UNEXPECTED_HELLO_DONE      , (SSL_ERROR_BASE + 47),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Server Hello Done handshake message."))

ER3(SSL_ERROR_RX_UNEXPECTED_CERT_VERIFY     , (SSL_ERROR_BASE + 48),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Certificate Verify handshake message."))

ER3(SSL_ERROR_RX_UNEXPECTED_CLIENT_KEY_EXCH , (SSL_ERROR_BASE + 49),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Cllient Key Exchange handshake message."))

ER3(SSL_ERROR_RX_UNEXPECTED_FINISHED        , (SSL_ERROR_BASE + 50),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Finished handshake message."))

/*
 * Received an SSL record that was inappropriate for the state we're in.
 */
ER3(SSL_ERROR_RX_UNEXPECTED_CHANGE_CIPHER   , (SSL_ERROR_BASE + 51),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Change Cipher Spec record."))

ER3(SSL_ERROR_RX_UNEXPECTED_ALERT           , (SSL_ERROR_BASE + 52),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Alert record."))

ER3(SSL_ERROR_RX_UNEXPECTED_HANDSHAKE       , (SSL_ERROR_BASE + 53),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Handshake record."))

ER3(SSL_ERROR_RX_UNEXPECTED_APPLICATION_DATA, (SSL_ERROR_BASE + 54),
dgettext(TEXT_DOMAIN,
"SSL received an unexpected Application Data record."))

/*
 * Received record/message with unknown discriminant.
 */
ER3(SSL_ERROR_RX_UNKNOWN_RECORD_TYPE        , (SSL_ERROR_BASE + 55),
dgettext(TEXT_DOMAIN,
"SSL received a record with an unknown content type."))

ER3(SSL_ERROR_RX_UNKNOWN_HANDSHAKE          , (SSL_ERROR_BASE + 56),
dgettext(TEXT_DOMAIN,
"SSL received a handshake message with an unknown message type."))

ER3(SSL_ERROR_RX_UNKNOWN_ALERT              , (SSL_ERROR_BASE + 57),
dgettext(TEXT_DOMAIN,
"SSL received an alert record with an unknown alert description."))

/*
 * Received an alert reporting what we did wrong.  (more alerts above)
 */
ER3(SSL_ERROR_CLOSE_NOTIFY_ALERT            , (SSL_ERROR_BASE + 58),
dgettext(TEXT_DOMAIN,
"SSL peer has closed this connection."))

ER3(SSL_ERROR_HANDSHAKE_UNEXPECTED_ALERT    , (SSL_ERROR_BASE + 59),
dgettext(TEXT_DOMAIN,
"SSL peer was not expecting a handshake message it received."))

ER3(SSL_ERROR_DECOMPRESSION_FAILURE_ALERT   , (SSL_ERROR_BASE + 60),
dgettext(TEXT_DOMAIN,
"SSL peer was unable to succesfully decompress an SSL record it received."))

ER3(SSL_ERROR_HANDSHAKE_FAILURE_ALERT       , (SSL_ERROR_BASE + 61),
dgettext(TEXT_DOMAIN,
"SSL peer was unable to negotiate an acceptable set of security parameters."))

ER3(SSL_ERROR_ILLEGAL_PARAMETER_ALERT       , (SSL_ERROR_BASE + 62),
dgettext(TEXT_DOMAIN,
"SSL peer rejected a handshake message for unacceptable content."))

ER3(SSL_ERROR_UNSUPPORTED_CERT_ALERT        , (SSL_ERROR_BASE + 63),
dgettext(TEXT_DOMAIN,
"SSL peer does not support certificates of the type it received."))

ER3(SSL_ERROR_CERTIFICATE_UNKNOWN_ALERT     , (SSL_ERROR_BASE + 64),
dgettext(TEXT_DOMAIN,
"SSL peer had some unspecified issue with the certificate it received."))

ER3(SSL_ERROR_GENERATE_RANDOM_FAILURE       , (SSL_ERROR_BASE + 65),
dgettext(TEXT_DOMAIN,
"SSL experienced a failure of its random number generator."))

ER3(SSL_ERROR_SIGN_HASHES_FAILURE           , (SSL_ERROR_BASE + 66),
dgettext(TEXT_DOMAIN,
"Unable to digitally sign data required to verify your certificate."))

ER3(SSL_ERROR_EXTRACT_PUBLIC_KEY_FAILURE    , (SSL_ERROR_BASE + 67),
dgettext(TEXT_DOMAIN,
"SSL was unable to extract the public key from the peer's certificate."))

ER3(SSL_ERROR_SERVER_KEY_EXCHANGE_FAILURE   , (SSL_ERROR_BASE + 68),
dgettext(TEXT_DOMAIN,
"Unspecified failure while processing SSL Server Key Exchange handshake."))

ER3(SSL_ERROR_CLIENT_KEY_EXCHANGE_FAILURE   , (SSL_ERROR_BASE + 69),
dgettext(TEXT_DOMAIN,
"Unspecified failure while processing SSL Client Key Exchange handshake."))

ER3(SSL_ERROR_ENCRYPTION_FAILURE            , (SSL_ERROR_BASE + 70),
dgettext(TEXT_DOMAIN,
"Bulk data encryption algorithm failed in selected cipher suite."))

ER3(SSL_ERROR_DECRYPTION_FAILURE            , (SSL_ERROR_BASE + 71),
dgettext(TEXT_DOMAIN,
"Bulk data decryption algorithm failed in selected cipher suite."))

ER3(SSL_ERROR_SOCKET_WRITE_FAILURE          , (SSL_ERROR_BASE + 72),
dgettext(TEXT_DOMAIN,
"Attempt to write encrypted data to underlying socket failed."))

ER3(SSL_ERROR_MD5_DIGEST_FAILURE            , (SSL_ERROR_BASE + 73),
dgettext(TEXT_DOMAIN,
"MD5 digest function failed."))

ER3(SSL_ERROR_SHA_DIGEST_FAILURE            , (SSL_ERROR_BASE + 74),
dgettext(TEXT_DOMAIN,
"SHA-1 digest function failed."))

ER3(SSL_ERROR_MAC_COMPUTATION_FAILURE       , (SSL_ERROR_BASE + 75),
dgettext(TEXT_DOMAIN,
"MAC computation failed."))

ER3(SSL_ERROR_SYM_KEY_CONTEXT_FAILURE       , (SSL_ERROR_BASE + 76),
dgettext(TEXT_DOMAIN,
"Failure to create Symmetric Key context."))

ER3(SSL_ERROR_SYM_KEY_UNWRAP_FAILURE        , (SSL_ERROR_BASE + 77),
dgettext(TEXT_DOMAIN,
"Failure to unwrap the Symmetric key in Client Key Exchange message."))

ER3(SSL_ERROR_PUB_KEY_SIZE_LIMIT_EXCEEDED   , (SSL_ERROR_BASE + 78),
dgettext(TEXT_DOMAIN,
"SSL Server attempted to use domestic-grade public key with export cipher suite."))

ER3(SSL_ERROR_IV_PARAM_FAILURE              , (SSL_ERROR_BASE + 79),
dgettext(TEXT_DOMAIN,
"PKCS11 code failed to translate an IV into a param."))

ER3(SSL_ERROR_INIT_CIPHER_SUITE_FAILURE     , (SSL_ERROR_BASE + 80),
dgettext(TEXT_DOMAIN,
"Failed to initialize the selected cipher suite."))

ER3(SSL_ERROR_SESSION_KEY_GEN_FAILURE       , (SSL_ERROR_BASE + 81),
dgettext(TEXT_DOMAIN,
"Client failed to generate session keys for SSL session."))

ER3(SSL_ERROR_NO_SERVER_KEY_FOR_ALG         , (SSL_ERROR_BASE + 82),
dgettext(TEXT_DOMAIN,
"Server has no key for the attempted key exchange algorithm."))

ER3(SSL_ERROR_TOKEN_INSERTION_REMOVAL       , (SSL_ERROR_BASE + 83),
dgettext(TEXT_DOMAIN,
"PKCS#11 token was inserted or removed while operation was in progress."))

ER3(SSL_ERROR_TOKEN_SLOT_NOT_FOUND          , (SSL_ERROR_BASE + 84),
dgettext(TEXT_DOMAIN,
"No PKCS#11 token could be found to do a required operation."))

ER3(SSL_ERROR_NO_COMPRESSION_OVERLAP        , (SSL_ERROR_BASE + 85),
dgettext(TEXT_DOMAIN,
"Cannot communicate securely with peer: no common compression algorithm(s)."))

ER3(SSL_ERROR_HANDSHAKE_NOT_COMPLETED       , (SSL_ERROR_BASE + 86),
dgettext(TEXT_DOMAIN,
"Cannot initiate another SSL handshake until current handshake is complete."))

ER3(SSL_ERROR_BAD_HANDSHAKE_HASH_VALUE      , (SSL_ERROR_BASE + 87),
dgettext(TEXT_DOMAIN,
"Received incorrect handshakes hash values from peer."))

ER3(SSL_ERROR_CERT_KEA_MISMATCH             , (SSL_ERROR_BASE + 88),
dgettext(TEXT_DOMAIN,
"The certificate provided cannot be used with the selected key exchange algorithm."))
