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
 * secerrstrs.h - map security errors to strings (used by errormap.c)
 *
 */

/*
 ****************************************************************************
 * The code below this point was provided by Nelson Bolyard <nelsonb> of the
 *	Netscape Certificate Server team on 27-March-1998.
 *	Taken from the file ns/security/cmd/lib/SECerrs.h on NSS_1_BRANCH.
 *	Last updated from there: 24-July-1998 by Mark Smith <mcs>
 *
 * All of the Directory Server specific changes are enclosed inside
 *	#ifdef NS_DIRECTORY.
 ****************************************************************************
 */

/* General security error codes  */
/* Caller must #include "secerr.h" */


ER3(SEC_ERROR_IO,				SEC_ERROR_BASE + 0,
dgettext(TEXT_DOMAIN,
"An I/O error occurred during security authorization."))

ER3(SEC_ERROR_LIBRARY_FAILURE,			SEC_ERROR_BASE + 1,
dgettext(TEXT_DOMAIN,
"security library failure."))

ER3(SEC_ERROR_BAD_DATA,				SEC_ERROR_BASE + 2,
dgettext(TEXT_DOMAIN,
"security library: received bad data."))

ER3(SEC_ERROR_OUTPUT_LEN,			SEC_ERROR_BASE + 3,
dgettext(TEXT_DOMAIN,
"security library: output length error."))

ER3(SEC_ERROR_INPUT_LEN,			SEC_ERROR_BASE + 4,
dgettext(TEXT_DOMAIN,
"security library has experienced an input length error."))

ER3(SEC_ERROR_INVALID_ARGS,			SEC_ERROR_BASE + 5,
dgettext(TEXT_DOMAIN,
"security library: invalid arguments."))

ER3(SEC_ERROR_INVALID_ALGORITHM,		SEC_ERROR_BASE + 6,
dgettext(TEXT_DOMAIN,
"security library: invalid algorithm."))

ER3(SEC_ERROR_INVALID_AVA,			SEC_ERROR_BASE + 7,
dgettext(TEXT_DOMAIN,
"security library: invalid AVA."))

ER3(SEC_ERROR_INVALID_TIME,			SEC_ERROR_BASE + 8,
dgettext(TEXT_DOMAIN,
"security library: invalid time."))

ER3(SEC_ERROR_BAD_DER,				SEC_ERROR_BASE + 9,
dgettext(TEXT_DOMAIN,
"security library: improperly formatted DER-encoded message."))

ER3(SEC_ERROR_BAD_SIGNATURE,			SEC_ERROR_BASE + 10,
dgettext(TEXT_DOMAIN,
"Peer's certificate has an invalid signature."))

ER3(SEC_ERROR_EXPIRED_CERTIFICATE,		SEC_ERROR_BASE + 11,
dgettext(TEXT_DOMAIN,
"Peer's Certificate has expired."))

ER3(SEC_ERROR_REVOKED_CERTIFICATE,		SEC_ERROR_BASE + 12,
dgettext(TEXT_DOMAIN,
"Peer's Certificate has been revoked."))

ER3(SEC_ERROR_UNKNOWN_ISSUER,			SEC_ERROR_BASE + 13,
dgettext(TEXT_DOMAIN,
"Peer's Certificate issuer is not recognized."))

ER3(SEC_ERROR_BAD_KEY,				SEC_ERROR_BASE + 14,
dgettext(TEXT_DOMAIN,
"Peer's public key is invalid."))

ER3(SEC_ERROR_BAD_PASSWORD,			SEC_ERROR_BASE + 15,
dgettext(TEXT_DOMAIN,
"The security password entered is incorrect."))

ER3(SEC_ERROR_RETRY_PASSWORD,			SEC_ERROR_BASE + 16,
dgettext(TEXT_DOMAIN,
"New password entered incorrectly.  Please try again."))

ER3(SEC_ERROR_NO_NODELOCK,			SEC_ERROR_BASE + 17,
dgettext(TEXT_DOMAIN,
"security library: no nodelock."))

ER3(SEC_ERROR_BAD_DATABASE,			SEC_ERROR_BASE + 18,
dgettext(TEXT_DOMAIN,
"security library: bad database."))

ER3(SEC_ERROR_NO_MEMORY,			SEC_ERROR_BASE + 19,
dgettext(TEXT_DOMAIN,
"security library: memory allocation failure."))

ER3(SEC_ERROR_UNTRUSTED_ISSUER,			SEC_ERROR_BASE + 20,
dgettext(TEXT_DOMAIN,
"Peer's certificate issuer has been marked as not trusted by the user."))

ER3(SEC_ERROR_UNTRUSTED_CERT,			SEC_ERROR_BASE + 21,
dgettext(TEXT_DOMAIN,
"Peer's certificate has been marked as not trusted by the user."))

ER3(SEC_ERROR_DUPLICATE_CERT,			(SEC_ERROR_BASE + 22),
dgettext(TEXT_DOMAIN,
"Certificate already exists in your database."))

ER3(SEC_ERROR_DUPLICATE_CERT_NAME,		(SEC_ERROR_BASE + 23),
dgettext(TEXT_DOMAIN,
"Downloaded certificate's name duplicates one already in your database."))

ER3(SEC_ERROR_ADDING_CERT,			(SEC_ERROR_BASE + 24),
dgettext(TEXT_DOMAIN,
"Error adding certificate to database."))

ER3(SEC_ERROR_FILING_KEY,			(SEC_ERROR_BASE + 25),
dgettext(TEXT_DOMAIN,
"Error refiling the key for this certificate."))

ER3(SEC_ERROR_NO_KEY,				(SEC_ERROR_BASE + 26),
dgettext(TEXT_DOMAIN,
"The private key for this certificate cannot be found in key database"))

ER3(SEC_ERROR_CERT_VALID,			(SEC_ERROR_BASE + 27),
dgettext(TEXT_DOMAIN,
"This certificate is valid."))

ER3(SEC_ERROR_CERT_NOT_VALID,			(SEC_ERROR_BASE + 28),
dgettext(TEXT_DOMAIN,
"This certificate is not valid."))

ER3(SEC_ERROR_CERT_NO_RESPONSE,			(SEC_ERROR_BASE + 29),
dgettext(TEXT_DOMAIN,
"Cert Library: No Response"))

ER3(SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE,	(SEC_ERROR_BASE + 30),
dgettext(TEXT_DOMAIN,
"The certificate issuer's certificate has expired.  Check your system date and time."))

ER3(SEC_ERROR_CRL_EXPIRED,			(SEC_ERROR_BASE + 31),
dgettext(TEXT_DOMAIN,
"The CRL for the certificate's issuer has expired.  Update it or check your system data and time."))

ER3(SEC_ERROR_CRL_BAD_SIGNATURE,		(SEC_ERROR_BASE + 32),
dgettext(TEXT_DOMAIN,
"The CRL for the certificate's issuer has an invalid signature."))

ER3(SEC_ERROR_CRL_INVALID,			(SEC_ERROR_BASE + 33),
dgettext(TEXT_DOMAIN,
"New CRL has an invalid format."))

ER3(SEC_ERROR_EXTENSION_VALUE_INVALID,		(SEC_ERROR_BASE + 34),
dgettext(TEXT_DOMAIN,
"Certificate extension value is invalid."))

ER3(SEC_ERROR_EXTENSION_NOT_FOUND,		(SEC_ERROR_BASE + 35),
dgettext(TEXT_DOMAIN,
"Certificate extension not found."))

ER3(SEC_ERROR_CA_CERT_INVALID,			(SEC_ERROR_BASE + 36),
dgettext(TEXT_DOMAIN,
"Issuer certificate is invalid."))
   
ER3(SEC_ERROR_PATH_LEN_CONSTRAINT_INVALID,	(SEC_ERROR_BASE + 37),
dgettext(TEXT_DOMAIN,
"Certificate path length constraint is invalid."))

ER3(SEC_ERROR_CERT_USAGES_INVALID,		(SEC_ERROR_BASE + 38),
dgettext(TEXT_DOMAIN,
"Certificate usages field is invalid."))

ER3(SEC_INTERNAL_ONLY,				(SEC_ERROR_BASE + 39),
dgettext(TEXT_DOMAIN,
"**Internal ONLY module**"))

ER3(SEC_ERROR_INVALID_KEY,			(SEC_ERROR_BASE + 40),
dgettext(TEXT_DOMAIN,
"The key does not support the requested operation."))

ER3(SEC_ERROR_UNKNOWN_CRITICAL_EXTENSION,	(SEC_ERROR_BASE + 41),
dgettext(TEXT_DOMAIN,
"Certificate contains unknown critical extension."))

ER3(SEC_ERROR_OLD_CRL,				(SEC_ERROR_BASE + 42),
dgettext(TEXT_DOMAIN,
"New CRL is not later than the current one."))

ER3(SEC_ERROR_NO_EMAIL_CERT,			(SEC_ERROR_BASE + 43),
dgettext(TEXT_DOMAIN,
"Not encrypted or signed: you do not yet have an email certificate."))

ER3(SEC_ERROR_NO_RECIPIENT_CERTS_QUERY,		(SEC_ERROR_BASE + 44),
dgettext(TEXT_DOMAIN,
"Not encrypted: you do not have certificates for each of the recipients."))

ER3(SEC_ERROR_NOT_A_RECIPIENT,			(SEC_ERROR_BASE + 45),
dgettext(TEXT_DOMAIN,
"Cannot decrypt: you are not a recipient, or matching certificate and \
private key not found."))

ER3(SEC_ERROR_PKCS7_KEYALG_MISMATCH,		(SEC_ERROR_BASE + 46),
dgettext(TEXT_DOMAIN,
"Cannot decrypt: key encryption algorithm does not match your certificate."))

ER3(SEC_ERROR_PKCS7_BAD_SIGNATURE,		(SEC_ERROR_BASE + 47),
dgettext(TEXT_DOMAIN,
"Signature verification failed: no signer found, too many signers found, \
or improper or corrupted data."))

ER3(SEC_ERROR_UNSUPPORTED_KEYALG,		(SEC_ERROR_BASE + 48),
dgettext(TEXT_DOMAIN,
"Unsupported or unknown key algorithm."))

ER3(SEC_ERROR_DECRYPTION_DISALLOWED,		(SEC_ERROR_BASE + 49),
dgettext(TEXT_DOMAIN,
"Cannot decrypt: encrypted using a disallowed algorithm or key size."))


/* Fortezza Alerts */
ER3(XP_SEC_FORTEZZA_BAD_CARD,			(SEC_ERROR_BASE + 50),
dgettext(TEXT_DOMAIN,
"Fortezza card has not been properly initialized.  \
Please remove it and return it to your issuer."))

ER3(XP_SEC_FORTEZZA_NO_CARD,			(SEC_ERROR_BASE + 51),
dgettext(TEXT_DOMAIN,
"No Fortezza cards Found"))

ER3(XP_SEC_FORTEZZA_NONE_SELECTED,		(SEC_ERROR_BASE + 52),
dgettext(TEXT_DOMAIN,
"No Fortezza card selected"))

ER3(XP_SEC_FORTEZZA_MORE_INFO,			(SEC_ERROR_BASE + 53),
dgettext(TEXT_DOMAIN,
"Please select a personality to get more info on"))

ER3(XP_SEC_FORTEZZA_PERSON_NOT_FOUND,		(SEC_ERROR_BASE + 54),
dgettext(TEXT_DOMAIN,
"Personality not found"))

ER3(XP_SEC_FORTEZZA_NO_MORE_INFO,		(SEC_ERROR_BASE + 55),
dgettext(TEXT_DOMAIN,
"No more information on that Personality"))

ER3(XP_SEC_FORTEZZA_BAD_PIN,			(SEC_ERROR_BASE + 56),
dgettext(TEXT_DOMAIN,
"Invalid Pin"))

ER3(XP_SEC_FORTEZZA_PERSON_ERROR,		(SEC_ERROR_BASE + 57),
dgettext(TEXT_DOMAIN,
"Couldn't initialize Fortezza personalities."))
/* end fortezza alerts. */

ER3(SEC_ERROR_NO_KRL,				(SEC_ERROR_BASE + 58),
dgettext(TEXT_DOMAIN,
"No KRL for this site's certificate has been found."))

ER3(SEC_ERROR_KRL_EXPIRED,			(SEC_ERROR_BASE + 59),
dgettext(TEXT_DOMAIN,
"The KRL for this site's certificate has expired."))

ER3(SEC_ERROR_KRL_BAD_SIGNATURE,		(SEC_ERROR_BASE + 60),
dgettext(TEXT_DOMAIN,
"The KRL for this site's certificate has an invalid signature."))

ER3(SEC_ERROR_REVOKED_KEY,			(SEC_ERROR_BASE + 61),
dgettext(TEXT_DOMAIN,
"The key for this site's certificate has been revoked."))

ER3(SEC_ERROR_KRL_INVALID,			(SEC_ERROR_BASE + 62),
dgettext(TEXT_DOMAIN,
"New KRL has an invalid format."))

ER3(SEC_ERROR_NEED_RANDOM,			(SEC_ERROR_BASE + 63),
dgettext(TEXT_DOMAIN,
"security library: need random data."))

ER3(SEC_ERROR_NO_MODULE,			(SEC_ERROR_BASE + 64),
dgettext(TEXT_DOMAIN,
"security library: no security module can perform the requested operation."))

ER3(SEC_ERROR_NO_TOKEN,				(SEC_ERROR_BASE + 65),
dgettext(TEXT_DOMAIN,
"The security card or token does not exist, needs to be initialized, or has been removed."))

ER3(SEC_ERROR_READ_ONLY,			(SEC_ERROR_BASE + 66),
dgettext(TEXT_DOMAIN,
"security library: read-only database."))

ER3(SEC_ERROR_NO_SLOT_SELECTED,			(SEC_ERROR_BASE + 67),
dgettext(TEXT_DOMAIN,
"No slot or token was selected."))

ER3(SEC_ERROR_CERT_NICKNAME_COLLISION,		(SEC_ERROR_BASE + 68),
dgettext(TEXT_DOMAIN,
"A certificate with the same nickname already exists."))

ER3(SEC_ERROR_KEY_NICKNAME_COLLISION,		(SEC_ERROR_BASE + 69),
dgettext(TEXT_DOMAIN,
"A key with the same nickname already exists."))

ER3(SEC_ERROR_SAFE_NOT_CREATED,			(SEC_ERROR_BASE + 70),
dgettext(TEXT_DOMAIN,
"error while creating safe object"))

ER3(SEC_ERROR_BAGGAGE_NOT_CREATED,		(SEC_ERROR_BASE + 71),
dgettext(TEXT_DOMAIN,
"error while creating baggage object"))

ER3(XP_JAVA_REMOVE_PRINCIPAL_ERROR,		(SEC_ERROR_BASE + 72),
dgettext(TEXT_DOMAIN,
"Couldn't remove the principal"))

ER3(XP_JAVA_DELETE_PRIVILEGE_ERROR,		(SEC_ERROR_BASE + 73),
dgettext(TEXT_DOMAIN,
"Couldn't delete the privilege"))

ER3(XP_JAVA_CERT_NOT_EXISTS_ERROR,		(SEC_ERROR_BASE + 74),
dgettext(TEXT_DOMAIN,
"This principal doesn't have a certificate"))

ER3(SEC_ERROR_BAD_EXPORT_ALGORITHM,		(SEC_ERROR_BASE + 75),
dgettext(TEXT_DOMAIN,
"Required algorithm is not allowed."))

ER3(SEC_ERROR_EXPORTING_CERTIFICATES,		(SEC_ERROR_BASE + 76),
dgettext(TEXT_DOMAIN,
"Error attempting to export certificates."))

ER3(SEC_ERROR_IMPORTING_CERTIFICATES,		(SEC_ERROR_BASE + 77),
dgettext(TEXT_DOMAIN,
"Error attempting to import certificates."))

ER3(SEC_ERROR_PKCS12_DECODING_PFX,		(SEC_ERROR_BASE + 78),
dgettext(TEXT_DOMAIN,
"Unable to import.  Decoding error.  File not valid."))

ER3(SEC_ERROR_PKCS12_INVALID_MAC,		(SEC_ERROR_BASE + 79),
dgettext(TEXT_DOMAIN,
"Unable to import.  Invalid MAC.  Incorrect password or corrupt file."))

ER3(SEC_ERROR_PKCS12_UNSUPPORTED_MAC_ALGORITHM,	(SEC_ERROR_BASE + 80),
dgettext(TEXT_DOMAIN,
"Unable to import.  MAC algorithm not supported."))

ER3(SEC_ERROR_PKCS12_UNSUPPORTED_TRANSPORT_MODE,(SEC_ERROR_BASE + 81),
dgettext(TEXT_DOMAIN,
"Unable to import.  Only password integrity and privacy modes supported."))

ER3(SEC_ERROR_PKCS12_CORRUPT_PFX_STRUCTURE,	(SEC_ERROR_BASE + 82),
dgettext(TEXT_DOMAIN,
"Unable to import.  File structure is corrupt."))

ER3(SEC_ERROR_PKCS12_UNSUPPORTED_PBE_ALGORITHM, (SEC_ERROR_BASE + 83),
dgettext(TEXT_DOMAIN,
"Unable to import.  Encryption algorithm not supported."))

ER3(SEC_ERROR_PKCS12_UNSUPPORTED_VERSION,	(SEC_ERROR_BASE + 84),
dgettext(TEXT_DOMAIN,
"Unable to import.  File version not supported."))

ER3(SEC_ERROR_PKCS12_PRIVACY_PASSWORD_INCORRECT,(SEC_ERROR_BASE + 85),
dgettext(TEXT_DOMAIN,
"Unable to import.  Incorrect privacy password."))

ER3(SEC_ERROR_PKCS12_CERT_COLLISION,		(SEC_ERROR_BASE + 86),
dgettext(TEXT_DOMAIN,
"Unable to import.  Same nickname already exists in database."))

ER3(SEC_ERROR_USER_CANCELLED,			(SEC_ERROR_BASE + 87),
dgettext(TEXT_DOMAIN,
"The user pressed cancel."))

ER3(SEC_ERROR_PKCS12_DUPLICATE_DATA,		(SEC_ERROR_BASE + 88),
dgettext(TEXT_DOMAIN,
"Not imported, already in database."))

ER3(SEC_ERROR_MESSAGE_SEND_ABORTED,		(SEC_ERROR_BASE + 89),
dgettext(TEXT_DOMAIN,
"Message not sent."))

ER3(SEC_ERROR_INADEQUATE_KEY_USAGE,		(SEC_ERROR_BASE + 90),
dgettext(TEXT_DOMAIN,
"Certificate key usage inadequate for attempted operation."))

ER3(SEC_ERROR_INADEQUATE_CERT_TYPE,		(SEC_ERROR_BASE + 91),
dgettext(TEXT_DOMAIN,
"Certificate type not approved for application."))

ER3(SEC_ERROR_CERT_ADDR_MISMATCH,		(SEC_ERROR_BASE + 92),
dgettext(TEXT_DOMAIN,
"Address in signing certificate does not match address in message headers."))

ER3(SEC_ERROR_PKCS12_UNABLE_TO_IMPORT_KEY,	(SEC_ERROR_BASE + 93),
dgettext(TEXT_DOMAIN,
"Unable to import.  Error attempting to import private key."))

ER3(SEC_ERROR_PKCS12_IMPORTING_CERT_CHAIN,	(SEC_ERROR_BASE + 94),
dgettext(TEXT_DOMAIN,
"Unable to import.  Error attempting to import certificate chain."))

ER3(SEC_ERROR_PKCS12_UNABLE_TO_LOCATE_OBJECT_BY_NAME, (SEC_ERROR_BASE + 95),
dgettext(TEXT_DOMAIN,
"Unable to export.  Unable to locate certificate or key by nickname."))

ER3(SEC_ERROR_PKCS12_UNABLE_TO_EXPORT_KEY,	(SEC_ERROR_BASE + 96),
dgettext(TEXT_DOMAIN,
"Unable to export.  Private Key could not be located and exported."))

ER3(SEC_ERROR_PKCS12_UNABLE_TO_WRITE, 		(SEC_ERROR_BASE + 97),
dgettext(TEXT_DOMAIN,
"Unable to export.  Unable to write the export file."))

ER3(SEC_ERROR_PKCS12_UNABLE_TO_READ,		(SEC_ERROR_BASE + 98),
dgettext(TEXT_DOMAIN,
"Unable to import.  Unable to read the import file."))

ER3(SEC_ERROR_PKCS12_KEY_DATABASE_NOT_INITIALIZED, (SEC_ERROR_BASE + 99),
dgettext(TEXT_DOMAIN,
"Unable to export.  Key database corrupt or deleted."))

ER3(SEC_ERROR_KEYGEN_FAIL,			(SEC_ERROR_BASE + 100),
dgettext(TEXT_DOMAIN,
"Unable to generate public/private key pair."))

ER3(SEC_ERROR_INVALID_PASSWORD,			(SEC_ERROR_BASE + 101),
dgettext(TEXT_DOMAIN,
"Password entered is invalid.  Please pick a different one."))

ER3(SEC_ERROR_RETRY_OLD_PASSWORD,		(SEC_ERROR_BASE + 102),
dgettext(TEXT_DOMAIN,
"Old password entered incorrectly.  Please try again."))

ER3(SEC_ERROR_BAD_NICKNAME,			(SEC_ERROR_BASE + 103),
dgettext(TEXT_DOMAIN,
"Certificate nickname already in use."))

ER3(SEC_ERROR_NOT_FORTEZZA_ISSUER,       	(SEC_ERROR_BASE + 104),
dgettext(TEXT_DOMAIN,
"Peer FORTEZZA chain has a non-FORTEZZA Certificate."))

/* ER3(SEC_ERROR_UNKNOWN, 			(SEC_ERROR_BASE + 105), */

ER3(SEC_ERROR_JS_INVALID_MODULE_NAME, 		(SEC_ERROR_BASE + 106),
dgettext(TEXT_DOMAIN,
"Invalid module name."))

ER3(SEC_ERROR_JS_INVALID_DLL, 			(SEC_ERROR_BASE + 107),
dgettext(TEXT_DOMAIN,
"Invalid module path/filename"))

ER3(SEC_ERROR_JS_ADD_MOD_FAILURE, 		(SEC_ERROR_BASE + 108),
dgettext(TEXT_DOMAIN,
"Unable to add module"))

ER3(SEC_ERROR_JS_DEL_MOD_FAILURE, 		(SEC_ERROR_BASE + 109),
dgettext(TEXT_DOMAIN,
"Unable to delete module"))

ER3(SEC_ERROR_OLD_KRL,	     			(SEC_ERROR_BASE + 110),
dgettext(TEXT_DOMAIN,
"New KRL is not later than the current one."))
 
ER3(SEC_ERROR_CKL_CONFLICT,	     		(SEC_ERROR_BASE + 111),
dgettext(TEXT_DOMAIN,
"New CKL has different issuer than current CKL.  Delete current CKL."))

#if 0 /* This was defined AFTER HCL 1.5 was released. */
ER3(SEC_ERROR_CERT_NOT_IN_NAME_SPACE, 		(SEC_ERROR_BASE + 112),
"The Certifying Authority for this certifcate is not permitted to issue a \
certifcate with this name."))
#endif



