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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file implements the export operation for this tool.
 * The basic flow of the process is to find the soft token,
 * log into it, find the PKCS#11 objects in the soft token
 * to be exported matching keys with their certificates, export
 * them to the PKCS#12 file encrypting them with a file password
 * if desired, and log out.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <cryptoutil.h>
#include <security/cryptoki.h>
#include "common.h"
#include "biginteger.h"
#include "osslcommon.h"
#include "p12common.h"
#include <openssl/pkcs12.h>

/*
 * Writes OpenSSL objects to PKCS#12 file.  The PKCS#11 objects from
 * the soft token need to be converted to OpenSSL structures prior
 * to this call, since the PKCS#12 routines depend on that format.
 * This code is patterned from OpenSSL apps that write PKCS#12 files.
 *
 * Note:  it's not clear from the usage of all the functions here by
 * OpenSSL apps whether these functions have return values or error
 * conditions that can be checked.  This function may benefit from
 * a closer review at a later time.
 */
static int
write_objs_pkcs12(BIO *fbio, CK_UTF8CHAR *pin, CK_ULONG pinlen,
	CK_BYTE_PTR id, CK_ULONG id_len, EVP_PKEY *priv_key, X509 *cert,
	STACK_OF(X509) *ca_certs, int *successes, int *failures)
/* ARGSUSED */
{
	STACK_OF(PKCS12_SAFEBAG)	*bag_stack = NULL;
	PKCS12_SAFEBAG			*bag = NULL;
	X509				*ca = NULL;
	PKCS7				*cert_authsafe = NULL;
	PKCS8_PRIV_KEY_INFO		*p8 = NULL;
	PKCS7				*key_authsafe = NULL;
	STACK_OF(PKCS7)			*authsafe_stack = NULL;
	PKCS12				*p12_elem = NULL;
	unsigned char			*lab = NULL;
	int				lab_len = 0;
	int				i;
	int				n_writes = 0;

	cryptodebug("inside write_objs_pkcs12");

	/* Do not reset *successes or *failures -- keep running totals. */

	/* If there is nothing to write to the PKCS#12 file, leave. */
	if (cert == NULL && ca_certs == NULL && priv_key == NULL) {
		cryptodebug("nothing to write to export file");
		return (0);
	}

	/*
	 * Section 1:
	 *
	 * The first PKCS#12 container (safebag) will hold the certificates
	 * associated with this key.  The result of this section is a
	 * PIN-encrypted PKCS#7 container (authsafe).  If there are no
	 * certificates, there is no point in creating the "safebag" or the
	 * "authsafe" so we go to the next section.
	 */
	if (cert != NULL || ca_certs != NULL) {
		/* Start a PKCS#12 safebag container for the certificates. */
		cryptodebug("creating certificate PKCS#12 safebag");
		bag_stack = sk_PKCS12_SAFEBAG_new_null();
		if (bag_stack == NULL) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to create PKCS#12 certificate bag."));
			(*failures)++;
			return (-1);
		}

		/* Add the cert corresponding to private key to bag_stack. */
		if (cert) {
			/* Convert cert from X509 struct to PKCS#12 bag */
			cryptodebug("adding certificate to PKCS#12 safebag");
			bag = PKCS12_x5092certbag(cert);
			if (bag == NULL) {
				cryptoerror(LOG_STDERR, gettext(
				    "Unable to convert certificate to "
				    "PKCS#12 bag."));
				/* Cleanup the safebag. */
				sk_PKCS12_SAFEBAG_pop_free(bag_stack,
				    PKCS12_SAFEBAG_free);
				(*failures)++;
				return (-1);
			}

			/* Add the key id to the certificate bag. */
			cryptodebug("add key id to PKCS#12 safebag");
			if (!PKCS12_add_localkeyid(bag, id, id_len))
				cryptodebug("error not caught");

			/* Add the friendly name to the certificate bag. */
			if ((lab = X509_alias_get0(cert, &lab_len)) != NULL) {
				cryptodebug(
				    "label PKCS#12 safebag with friendly name");
				if (!PKCS12_add_friendlyname(bag, (char *)lab,
				    lab_len))
					cryptodebug("error not caught");
			}

			/* Pile it on the bag_stack. */
			if (!sk_PKCS12_SAFEBAG_push(bag_stack, bag))
				cryptodebug("error not caught");

			n_writes++;
		}

		/* Add all the CA chain certs to the bag_stack. */
		if (ca_certs) {
			cryptodebug("adding CA certificate chain to PKCS#12 "
			    "safebag");
			/*
			 * Go through the stack of CA certs, converting each
			 * one to a PKCS#12 bag and piling them onto the
			 * bag_stack.
			 */
			for (i = 0; i < sk_X509_num(ca_certs); i++) {
				/*
				 * sk_X509_value() is macro that embeds a
				 * cast to (X509 *).  Here it translates
				 * into ((X509 *)sk_value((ca_certs), (i))).
				 * Lint is complaining about the embedded
				 * casting, and to fix it, you need to fix
				 * openssl header files.
				 */
				/* LINTED E_BAD_PTR_CAST_ALIGN */
				ca = sk_X509_value(ca_certs, i);

				/* Convert CA cert to PKCS#12 bag. */
				cryptodebug("adding CA certificate #%d "
				    "to PKCS#12 safebag", i+1);
				bag = PKCS12_x5092certbag(ca);
				if (bag == NULL) {
					cryptoerror(LOG_STDERR, gettext(
					    "Unable to convert CA certificate "
					    "#%d to PKCS#12 bag."), i+1);
					/* Cleanup the safebag. */
					sk_PKCS12_SAFEBAG_pop_free(bag_stack,
					    PKCS12_SAFEBAG_free);
					(*failures)++;
					return (-1);
				}

				/* Note CA certs do not have friendly name. */

				/* Pile it onto the bag_stack. */
				if (!sk_PKCS12_SAFEBAG_push(bag_stack, bag))
					cryptodebug("error not caught");

				n_writes++;
			}
		}

		/* Turn bag_stack of certs into encrypted authsafe. */
		cryptodebug("encrypt certificate PKCS#12 bag into "
		    "PKCS#7 authsafe");
		cert_authsafe = PKCS12_pack_p7encdata(
		    NID_pbe_WithSHA1And40BitRC2_CBC, (char *)pin, -1, NULL,
		    0, PKCS12_DEFAULT_ITER, bag_stack);

		/* Clear away this bag_stack, we're done with it. */
		sk_PKCS12_SAFEBAG_pop_free(bag_stack, PKCS12_SAFEBAG_free);
		bag_stack = NULL;

		if (cert_authsafe == NULL) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to PKCS#7-encrypt certificate bag."));
			(*failures)++;
			return (-1);
		}
	}

	/*
	 * Section 2:
	 *
	 * The second PKCS#12 container (safebag) will hold the private key
	 * that goes with the certificates above.  The results of this section
	 * is an unencrypted PKCS#7 container (authsafe).  If there is no
	 * private key, there is no point in creating the "safebag" or the
	 * "authsafe" so we go to the next section.
	 */
	if (priv_key != NULL) {
		/* Make a PKCS#8 shrouded key bag. */
		cryptodebug("create PKCS#8 shrouded key out of private key");
		p8 = EVP_PKEY2PKCS8(priv_key);
		if (p8 == NULL) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to create PKCS#8 shrouded key for "
			    "private key."));
			(*failures)++;
			return (-1);
		}

		/* Put the shrouded key into a PKCS#12 bag. */
		cryptodebug("convert shrouded key to PKCS#12 bag");
		bag = PKCS12_MAKE_SHKEYBAG(
		    NID_pbe_WithSHA1And3_Key_TripleDES_CBC, (char *)pin,
		    -1, NULL, 0, PKCS12_DEFAULT_ITER, p8);

		/* Clean up the PKCS#8 shrouded key, don't need it now. */
		PKCS8_PRIV_KEY_INFO_free(p8);
		p8 = NULL;

		if (bag == NULL) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert private key to PKCS#12 bag."));
			(*failures)++;
			return (-1);
		}

		/* Add the key id to the certificate bag. */
		cryptodebug("add key id to PKCS#12 safebag");
		if (!PKCS12_add_localkeyid(bag, id, id_len))
			cryptodebug("error not caught");

		/* Add the cert friendly name to the private key bag. */
		if (lab != NULL) {
			cryptodebug("label PKCS#12 safebag with friendly name");
			if (!PKCS12_add_friendlyname(bag, (char *)lab, lab_len))
				cryptodebug("error not caught");
		}

		/* Start a PKCS#12 safebag container for the private key. */
		cryptodebug("creating private key PKCS#12 safebag");
		bag_stack = sk_PKCS12_SAFEBAG_new_null();
		if (bag_stack == NULL) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to create PKCS#12 private key bag."));
			(*failures)++;
			return (-1);
		}

		/* Pile on the private key on the bag_stack. */
		if (!sk_PKCS12_SAFEBAG_push(bag_stack, bag))
			cryptodebug("error not caught");

		/* Turn bag_stack with private key into unencrypted authsafe. */
		cryptodebug("put private PKCS#12 bag into PKCS#7 authsafe");
		key_authsafe = PKCS12_pack_p7data(bag_stack);

		/* Clear away this bag_stack, we're done with it. */
		sk_PKCS12_SAFEBAG_pop_free(bag_stack, PKCS12_SAFEBAG_free);
		bag_stack = NULL;

		if (key_authsafe == NULL) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to PKCS#7-convert private key bag."));
			(*failures)++;
			return (-1);
		}

		n_writes++;
	}

	/*
	 * Section 3:
	 *
	 * This is where the two PKCS#7 containers, one for the certificates
	 * and one for the private key, are put together into a PKCS#12
	 * element.  This final PKCS#12 element is written to the export file.
	 */
	/* Start a PKCS#7 stack. */
	cryptodebug("create PKCS#7 authsafe for private key and certificates");
	authsafe_stack = sk_PKCS7_new_null();
	if (authsafe_stack == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to create PKCS#7 container for private key "
		    "and certificates."));
		(*failures)++;
		return (-1);
	}

	/* Put certificates and private key into PKCS#7 stack. */
	if (key_authsafe != NULL) {
		cryptodebug("put private key authsafe into PKCS#7 container");
		if (!sk_PKCS7_push(authsafe_stack, key_authsafe))
			cryptodebug("error not caught");
	}
	if (cert_authsafe != NULL) {
		cryptodebug("put certificate authsafe into PKCS#7 container");
		if (!sk_PKCS7_push(authsafe_stack, cert_authsafe))
			cryptodebug("error not caught");
	}

	/* Create PKCS#12 element out of PKCS#7 stack. */
	cryptodebug("create PKCS#12 element for export file");
	p12_elem = PKCS12_init(NID_pkcs7_data);
	if (p12_elem == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to create PKCS#12 element for export file."));
		sk_PKCS7_pop_free(authsafe_stack, PKCS7_free);
		(*failures)++;
		return (-1);
	}

	/* Put the PKCS#7 stack into the PKCS#12 element. */
	if (!PKCS12_pack_authsafes(p12_elem, authsafe_stack))
		cryptodebug("error not caught");

	/* Clear away the PKCS#7 stack, we're done with it. */
	sk_PKCS7_pop_free(authsafe_stack, PKCS7_free);
	authsafe_stack = NULL;

	/* Set the integrity MAC on the PKCS#12 element. */
	cryptodebug("setting MAC for PKCS#12 element");
	if (!PKCS12_set_mac(p12_elem, (char *)pin, -1, NULL, 0,
	    PKCS12_DEFAULT_ITER, NULL))
		cryptodebug("error not caught");

	/* Write the PKCS#12 element to the export file. */
	cryptodebug("writing PKCS#12 element to export file");
	if (!i2d_PKCS12_bio(fbio, p12_elem))
		cryptodebug("error not caught");

	(*successes) += n_writes;

	/* Clear away the PKCS#12 element. */
	PKCS12_free(p12_elem);
	return (0);
}

/*
 * Get token objects: private key, its cert, and its cert chain.
 */
static CK_RV
get_token_objs(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj,
	CK_OBJECT_HANDLE *mate, CK_OBJECT_HANDLE_PTR *chain,
	CK_ULONG *chain_len, CK_BYTE_PTR *id, CK_ULONG *id_len)
{
	CK_RV			rv = CKR_OK;
	CK_ATTRIBUTE		keyid_attr[1] = {
		{ CKA_ID, NULL, 0 }
	    };
	static CK_OBJECT_CLASS	class = CKO_CERTIFICATE;
	static CK_CERTIFICATE_TYPE	certtype = CKC_X_509;
	CK_ATTRIBUTE		cert_attr[4] = {
		{ CKA_CLASS, &class, sizeof (CK_OBJECT_CLASS) },
		{ CKA_CERTIFICATE_TYPE, &certtype, sizeof (certtype) },
		{ CKA_TOKEN, &pk_true, sizeof (pk_true) },
		{ CKA_ID, NULL, 0 }
	    };
	CK_ULONG	num_attr = sizeof (cert_attr) / sizeof (CK_ATTRIBUTE);
	CK_OBJECT_HANDLE	cert = ~0UL;
	CK_ULONG		num = 0;

	cryptodebug("inside get_token_objs");

	/* Get the size of the object's CKA_ID field first. */
	cryptodebug("getting CKA_ID size for object 0x%x", obj);
	if ((rv = C_GetAttributeValue(sess, obj, keyid_attr, 1)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext("Unable to get size of object"
		    " key id (%s)."), pkcs11_strerror(rv));
		return (rv);
	}

	/* Allocate the space needed for the key id. */
	if ((keyid_attr[0].pValue = malloc(keyid_attr[0].ulValueLen)) == NULL) {
		cryptoerror(LOG_STDERR, "%s.", strerror(errno));
		return (CKR_HOST_MEMORY);
	}

	/* Get the CKA_ID field to match obj with its cert. */
	cryptodebug("getting CKA_ID attribute for object 0x%x", obj);
	if ((rv = C_GetAttributeValue(sess, obj, keyid_attr, 1)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext("Unable to get object "
		    "key id (%s)."), pkcs11_strerror(rv));
		free(keyid_attr[0].pValue);
		return (rv);
	}

	/* Now try to find any certs that have the same id. */
	cryptodebug("searching for certificates with same CKA_ID");
	cert_attr[3].pValue = keyid_attr[0].pValue;
	cert_attr[3].ulValueLen = keyid_attr[0].ulValueLen;
	if ((rv = C_FindObjectsInit(sess, cert_attr, num_attr)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext("Unable to initialize "
		    "certificate search (%s)."), pkcs11_strerror(rv));
		free(keyid_attr[0].pValue);
		return (rv);
	}

	/* Find the first cert that matches the key id. */
	if ((rv = C_FindObjects(sess, &cert, 1, &num)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext("Certificate search failed "
		    "(%s)."), pkcs11_strerror(rv));
		free(keyid_attr[0].pValue);
		return (rv);
	}

	(void) C_FindObjectsFinal(sess);

	*id = keyid_attr[0].pValue;
	*id_len = keyid_attr[0].ulValueLen;

	*mate = (num == 1) ? cert : ~0UL;

	/* We currently do not find all the certs in the chain. */
	*chain_len = 0;
	*chain = NULL;

	return (CKR_OK);
}

/*
 * Converts PKCS#11 biginteger_t format to OpenSSL BIGNUM.
 * "to" should be the address of a ptr init'ed to NULL to
 * receive the BIGNUM, e.g.,
 *	biginteger_t	from;
 * 	BIGNUM	*foo = NULL;
 *	cvt_bigint2bn(&from, &foo);
 */
static int
cvt_bigint2bn(biginteger_t *from, BIGNUM **to)
{
	BIGNUM	*temp = NULL;

	cryptodebug("inside cvt_bigint2bn");

	if (from == NULL || to == NULL)
		return (-1);

	cryptodebug("calling BN_bin2bn");
	if ((temp = BN_bin2bn(from->big_value, from->big_value_len, *to)) ==
	    NULL)
		return (-1);

	*to = temp;
	return (0);
}

/*
 * Convert PKCS#11 RSA private key to OpenSSL EVP_PKEY structure.
 */
static CK_RV
cvt_rsa2evp_pkey(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, EVP_PKEY **pk)
{
	CK_RV		rv = CKR_OK;
	EVP_PKEY	*key = NULL;		/* OpenSSL representation */
	RSA		*rsa = NULL;		/* OpenSSL representation */
	biginteger_t	mod = { NULL, 0 };	/* required */
	biginteger_t	pubexp = { NULL, 0 };	/* required */
	biginteger_t	priexp = { NULL, 0 };	/* optional */
	biginteger_t	prime1 = { NULL, 0 };	/* optional */
	biginteger_t	prime2 = { NULL, 0 };	/* optional */
	biginteger_t	exp1 = { NULL, 0 };	/* optional */
	biginteger_t	exp2 = { NULL, 0 };	/* optional */
	biginteger_t	coef = { NULL, 0 };	/* optional */
	CK_ATTRIBUTE	rsa_pri_attrs[8] = {
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 },
		{ CKA_PRIVATE_EXPONENT, NULL, 0 },	/* optional */
		{ CKA_PRIME_1, NULL, 0 },		/*  |  */
		{ CKA_PRIME_2, NULL, 0 },		/*  |  */
		{ CKA_EXPONENT_1, NULL, 0 },		/*  |  */
		{ CKA_EXPONENT_2, NULL, 0 },		/*  |  */
		{ CKA_COEFFICIENT, NULL, 0 }		/*  V  */
	    };
	CK_ULONG	count = sizeof (rsa_pri_attrs) / sizeof (CK_ATTRIBUTE);
	int		i;

	cryptodebug("inside cvt_rsa2evp_pkey");

	cryptodebug("calling RSA_new");
	if ((rsa = RSA_new()) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to allocate internal RSA structure."));
		return (CKR_HOST_MEMORY);
	}

	/* Get the sizes of the attributes we need. */
	cryptodebug("calling C_GetAttributeValue for size info");
	if ((rv = C_GetAttributeValue(sess, obj, rsa_pri_attrs, count)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get RSA private key attribute sizes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Allocate memory for each attribute. */
	for (i = 0; i < count; i++) {
		if (rsa_pri_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    rsa_pri_attrs[i].ulValueLen == 0) {
			cryptodebug("cvt_rsa2evp_pkey: *** should not happen");
			rsa_pri_attrs[i].ulValueLen = 0;
			continue;
		}
		if ((rsa_pri_attrs[i].pValue =
		    malloc(rsa_pri_attrs[i].ulValueLen)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			return (CKR_HOST_MEMORY);
		}
	}

	/* Now really get the attributes. */
	cryptodebug("calling C_GetAttributeValue for attribute info");
	if ((rv = C_GetAttributeValue(sess, obj, rsa_pri_attrs, count)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get RSA private key attributes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/*
	 * Fill in all the temp variables.  Modulus and public exponent
	 * are required.  The rest are optional.
	 */
	i = 0;
	copy_attr_to_bigint(&(rsa_pri_attrs[i++]), &mod);
	copy_attr_to_bigint(&(rsa_pri_attrs[i++]), &pubexp);

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		copy_attr_to_bigint(&(rsa_pri_attrs[i]), &priexp);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		copy_attr_to_bigint(&(rsa_pri_attrs[i]), &prime1);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		copy_attr_to_bigint(&(rsa_pri_attrs[i]), &prime2);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		copy_attr_to_bigint(&(rsa_pri_attrs[i]), &exp1);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		copy_attr_to_bigint(&(rsa_pri_attrs[i]), &exp2);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		copy_attr_to_bigint(&(rsa_pri_attrs[i]), &coef);
	i++;

	/* Start the conversion to internal OpenSSL RSA structure. */

	/* Modulus n */
	if (cvt_bigint2bn(&mod, &(rsa->n)) < 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert RSA private key modulus."));
		return (CKR_GENERAL_ERROR);
	}

	/* Public exponent e */
	if (cvt_bigint2bn(&pubexp, &(rsa->e)) < 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert RSA private key public exponent."));
		return (CKR_GENERAL_ERROR);
	}

	/* Private exponent e */
	if (priexp.big_value != NULL) {
		if (cvt_bigint2bn(&priexp, &(rsa->d)) < 0) {
			cryptoerror(LOG_STDERR, gettext("Unable to convert "
			    "RSA private key private exponent."));
			return (CKR_GENERAL_ERROR);
		}
	} else
		cryptodebug("no RSA private key private exponent");

	/* Prime p */
	if (prime1.big_value != NULL) {
		if (cvt_bigint2bn(&prime1, &(rsa->p)) < 0) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key prime 1."));
			return (CKR_GENERAL_ERROR);
		}
	} else
		cryptodebug("no RSA private key prime 1");

	/* Prime q */
	if (prime2.big_value != NULL) {
		if (cvt_bigint2bn(&prime2, &(rsa->q)) < 0) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key prime 2."));
			return (CKR_GENERAL_ERROR);
		}
	} else
		cryptodebug("no RSA private key prime 2");

	/* Private exponent d modulo p-1 */
	if (exp1.big_value != NULL) {
		if (cvt_bigint2bn(&exp1, &(rsa->dmp1)) < 0) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key exponent 1."));
			return (CKR_GENERAL_ERROR);
		}
	} else
		cryptodebug("no RSA private key exponent 1");

	/* Private exponent d modulo q-1 */
	if (exp2.big_value != NULL) {
		if (cvt_bigint2bn(&exp2, &(rsa->dmq1)) < 0) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key exponent 2."));
			return (CKR_GENERAL_ERROR);
		}
	} else
		cryptodebug("no RSA private key exponent 2");

	/* CRT coefficient q-inverse mod p */
	if (coef.big_value != NULL) {
		if (cvt_bigint2bn(&coef, &(rsa->iqmp)) < 0) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to convert RSA private key coefficient."));
			return (CKR_GENERAL_ERROR);
		}
	} else
		cryptodebug("no RSA private key coefficient");

	/* Create OpenSSL EVP_PKEY struct in which to stuff RSA struct. */
	cryptodebug("calling EVP_PKEY_new");
	if ((key = EVP_PKEY_new()) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to allocate internal EVP_PKEY structure."));
		return (CKR_HOST_MEMORY);
	}

	/* Put the RSA struct into the EVP_PKEY struct and return it. */
	cryptodebug("calling EVP_PKEY_set1_RSA");
	(void) EVP_PKEY_set1_RSA(key, rsa);

	*pk = key;
	return (CKR_OK);
}

/*
 * Convert PKCS#11 DSA private key to OpenSSL EVP_PKEY structure.
 */
static CK_RV
cvt_dsa2evp_pkey(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, EVP_PKEY **pk)
{
	CK_RV		rv = CKR_OK;
	EVP_PKEY	*key = NULL;		/* OpenSSL representation */
	DSA		*dsa = NULL;		/* OpenSSL representation */
	biginteger_t	prime = { NULL, 0 };	/* required */
	biginteger_t	subprime = { NULL, 0 };	/* required */
	biginteger_t	base = { NULL, 0 };	/* required */
	biginteger_t	value = { NULL, 0 };	/* required */
	CK_ATTRIBUTE	dsa_pri_attrs[4] = {
		{ CKA_PRIME, NULL, 0 },
		{ CKA_SUBPRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	    };
	CK_ULONG	count = sizeof (dsa_pri_attrs) / sizeof (CK_ATTRIBUTE);
	int		i;

	cryptodebug("inside cvt_dsa2evp_pkey");

	cryptodebug("calling DSA_new");
	if ((dsa = DSA_new()) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to allocate internal DSA structure."));
		return (CKR_HOST_MEMORY);
	}

	/* Get the sizes of the attributes we need. */
	cryptodebug("calling C_GetAttributeValue for size info");
	if ((rv = C_GetAttributeValue(sess, obj, dsa_pri_attrs, count)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get DSA private key object attributes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Allocate memory for each attribute. */
	for (i = 0; i < count; i++) {
		if (dsa_pri_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    dsa_pri_attrs[i].ulValueLen == 0) {
			cryptodebug("cvt_dsa2evp_pkey:  *** should not happen");
			dsa_pri_attrs[i].ulValueLen = 0;
			continue;
		}
		if ((dsa_pri_attrs[i].pValue =
		    malloc(dsa_pri_attrs[i].ulValueLen)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			return (CKR_HOST_MEMORY);
		}
	}

	/* Now really get the attributes. */
	cryptodebug("calling C_GetAttributeValue for attribute info");
	if ((rv = C_GetAttributeValue(sess, obj, dsa_pri_attrs, count)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get DSA private key attributes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Fill in all the temp variables.  They are all required. */
	i = 0;
	copy_attr_to_bigint(&(dsa_pri_attrs[i++]), &prime);
	copy_attr_to_bigint(&(dsa_pri_attrs[i++]), &subprime);
	copy_attr_to_bigint(&(dsa_pri_attrs[i++]), &base);
	copy_attr_to_bigint(&(dsa_pri_attrs[i++]), &value);

	/* Start the conversion to internal OpenSSL DSA structure. */

	/* Prime p */
	if (cvt_bigint2bn(&prime, &(dsa->p)) < 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DSA private key prime."));
		return (CKR_GENERAL_ERROR);
	}

	/* Subprime q */
	if (cvt_bigint2bn(&subprime, &(dsa->q)) < 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DSA private key subprime."));
		return (CKR_GENERAL_ERROR);
	}

	/* Base g */
	if (cvt_bigint2bn(&base, &(dsa->g)) < 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DSA private key base."));
		return (CKR_GENERAL_ERROR);
	}

	/* Private key x */
	if (cvt_bigint2bn(&value, &(dsa->priv_key)) < 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DSA private key value."));
		return (CKR_GENERAL_ERROR);
	}

	/* Create OpenSSL EVP PKEY struct in which to stuff DSA struct. */
	cryptodebug("calling EVP_PKEY_new");
	if ((key = EVP_PKEY_new()) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to allocate internal EVP_PKEY structure."));
		return (CKR_HOST_MEMORY);
	}

	/* Put the DSA struct into the EVP_PKEY struct and return it. */
	cryptodebug("calling EVP_PKEY_set1_DSA");
	(void) EVP_PKEY_set1_DSA(key, dsa);

	*pk = key;
	return (CKR_OK);
}

/*
 * Convert PKCS#11 DH private key to OpenSSL EVP_PKEY structure.
 */
static CK_RV
cvt_dh2evp_pkey(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, EVP_PKEY **pk)
{
	CK_RV		rv = CKR_OK;
	EVP_PKEY	*key = NULL;		/* OpenSSL representation */
	DH		*dh = NULL;		/* OpenSSL representation */
	biginteger_t	prime = { NULL, 0 };	/* required */
	biginteger_t	base = { NULL, 0 };	/* required */
	biginteger_t	value = { NULL, 0 };	/* required */
	CK_ATTRIBUTE	dh_pri_attrs[3] = {
		{ CKA_PRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	    };
	CK_ULONG	count = sizeof (dh_pri_attrs) / sizeof (CK_ATTRIBUTE);
	int		i;

	cryptodebug("inside cvt_dh2evp_pkey");

	cryptodebug("calling DH_new");
	if ((dh = DH_new()) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to allocate internal DH structure."));
		return (CKR_HOST_MEMORY);
	}

	/* Get the sizes of the attributes we need. */
	cryptodebug("calling C_GetAttributeValue for size info");
	if ((rv = C_GetAttributeValue(sess, obj, dh_pri_attrs, count)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get DH private key object attributes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Allocate memory for each attribute. */
	for (i = 0; i < count; i++) {
		if (dh_pri_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    dh_pri_attrs[i].ulValueLen == 0) {
			cryptodebug("cvt_dh2evp_pkey: ***should not happen");
			dh_pri_attrs[i].ulValueLen = 0;
			continue;
		}
		if ((dh_pri_attrs[i].pValue =
		    malloc(dh_pri_attrs[i].ulValueLen)) == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			return (CKR_HOST_MEMORY);
		}
	}

	/* Now really get the attributes. */
	cryptodebug("calling C_GetAttributeValue for attribute info");
	if ((rv = C_GetAttributeValue(sess, obj, dh_pri_attrs, count)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get DH private key attributes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Fill in all the temp variables.  They are all required. */
	i = 0;
	copy_attr_to_bigint(&(dh_pri_attrs[i++]), &prime);
	copy_attr_to_bigint(&(dh_pri_attrs[i++]), &base);
	copy_attr_to_bigint(&(dh_pri_attrs[i++]), &value);

	/* Start the conversion to internal OpenSSL DH structure. */

	/* Prime p */
	if (cvt_bigint2bn(&prime, &(dh->p)) < 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DH private key prime."));
		return (CKR_GENERAL_ERROR);
	}

	/* Base g */
	if (cvt_bigint2bn(&base, &(dh->g)) < 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DH private key base."));
		return (CKR_GENERAL_ERROR);
	}

	/* Private value x */
	if (cvt_bigint2bn(&value, &(dh->priv_key)) < 0) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert DH private key value."));
		return (CKR_GENERAL_ERROR);
	}

	/* Create OpenSSL EVP PKEY struct in which to stuff DH struct. */
	cryptodebug("calling EVP_PKEY_new");
	if ((key = EVP_PKEY_new()) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to allocate internal EVP_PKEY structure."));
		return (CKR_HOST_MEMORY);
	}

	/* Put the DH struct into the EVP_PKEY struct and return it. */
	cryptodebug("calling EVP_PKEY_set1_DH");
	(void) EVP_PKEY_set1_DH(key, dh);

	*pk = key;
	return (CKR_OK);
}

/*
 * Convert PKCS#11 private key object to OpenSSL EVP_PKEY structure.
 */
static CK_RV
cvt_obj2evp_pkey(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, EVP_PKEY **pk)
{
	CK_RV			rv = CKR_OK;
	static CK_KEY_TYPE	keytype = 0;
	CK_ATTRIBUTE		keytype_attr[1] = {
		{ CKA_KEY_TYPE, &keytype, sizeof (keytype) }
	    };

	cryptodebug("inside cvt_obj2evp_pkey");

	/* Find out the key type to do the right conversion. */
	cryptodebug("calling C_GetAttributeValue");
	if ((rv = C_GetAttributeValue(sess, obj, keytype_attr, 1)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get token object key type (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	switch (keytype) {
	case CKK_RSA:
		cryptodebug("converting RSA key");
		return (cvt_rsa2evp_pkey(sess, obj, pk));
	case CKK_DSA:
		cryptodebug("converting DSA key");
		return (cvt_dsa2evp_pkey(sess, obj, pk));
	case CKK_DH:
		cryptodebug("converting DH key");
		return (cvt_dh2evp_pkey(sess, obj, pk));
	default:
		cryptoerror(LOG_STDERR, gettext(
		    "Private key type 0x%02x conversion not supported."),
		    keytype);
		return (CKR_GENERAL_ERROR);
	}
}

/*
 * Convert PKCS#11 certificate object to OpenSSL X509 structure.
 */
static CK_RV
cvt_cert2x509(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj, X509 **c)
{
	CK_RV			rv = CKR_OK;
	X509			*cert = NULL;	/* OpenSSL representation */
	X509			*temp_cert = NULL;
	CK_BYTE			*subject = NULL;
	CK_ULONG		subject_len = 0;
	CK_BYTE			*value = NULL;
	CK_ULONG		value_len = 0;
	CK_BYTE			*label = NULL;
	CK_ULONG		label_len = 0;
	CK_BYTE			*id = NULL;
	CK_ULONG		id_len = 0;
	CK_BYTE			*issuer = NULL;
	CK_ULONG		issuer_len = 0;
	CK_BYTE			*serial = NULL;
	CK_ULONG		serial_len = 0;
	CK_ATTRIBUTE		cert_attrs[6] = {
		{ CKA_SUBJECT, NULL, 0 },		/* required */
		{ CKA_VALUE, NULL, 0 },			/* required */
		{ CKA_LABEL, NULL, 0 },			/* optional */
		{ CKA_ID, NULL, 0 },			/* optional */
		{ CKA_ISSUER, NULL, 0 },		/* optional */
		{ CKA_SERIAL_NUMBER, NULL, 0 }		/* optional */
	    };
	CK_ULONG	count = sizeof (cert_attrs) / sizeof (CK_ATTRIBUTE);
	int		i = 0;
	X509_NAME	*ssl_subject = NULL;
	X509_NAME	*ssl_issuer = NULL;
	ASN1_INTEGER	*ssl_serial = NULL;

	cryptodebug("inside cvt_cert2x509");

	cryptodebug("calling X509_new");
	if ((cert = X509_new()) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to allocate internal X509 structure."));
		return (CKR_HOST_MEMORY);
	}

	/* Get the sizes of the attributes we need. */
	cryptodebug("calling C_GetAttributeValue for size info");
	if ((rv = C_GetAttributeValue(sess, obj, cert_attrs, count)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get certificate attribute sizes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/* Allocate memory for each attribute. */
	for (i = 0; i < count; i++) {
		if (cert_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    cert_attrs[i].ulValueLen == 0) {
			cryptodebug("cvt_cert2x509:  *** should not happen");
			cert_attrs[i].ulValueLen = 0;
			continue;
		}
		if ((cert_attrs[i].pValue = malloc(cert_attrs[i].ulValueLen))
		    == NULL) {
			cryptoerror(LOG_STDERR, "%s.", strerror(errno));
			return (CKR_HOST_MEMORY);
		}
	}

	/* Now really get the attributes. */
	cryptodebug("calling C_GetAttributeValue for attribute info");
	if ((rv = C_GetAttributeValue(sess, obj, cert_attrs, count)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get certificate attributes (%s)."),
		    pkcs11_strerror(rv));
		return (rv);
	}

	/*
	 * Fill in all the temp variables.  Subject and value are required.
	 * The rest are optional.
	 */
	i = 0;
	copy_attr_to_string(&(cert_attrs[i++]), &subject, &subject_len);
	copy_attr_to_string(&(cert_attrs[i++]), &value, &value_len);

	if (cert_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    cert_attrs[i].ulValueLen != 0)
		copy_attr_to_string(&(cert_attrs[i]), &label, &label_len);
	i++;

	if (cert_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    cert_attrs[i].ulValueLen != 0)
		copy_attr_to_string(&(cert_attrs[i]), &id, &id_len);
	i++;

	if (cert_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    cert_attrs[i].ulValueLen != 0)
		copy_attr_to_string(&(cert_attrs[i]), &issuer, &issuer_len);
	i++;

	if (cert_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    cert_attrs[i].ulValueLen != 0)
		copy_attr_to_string(&(cert_attrs[i]), &serial, &serial_len);
	i++;

	/* Start the conversion to internal OpenSSL X509 structure. */

	/* Subject name (required) */
	cryptodebug("calling d2i_X509_NAME for subject name");
	if ((ssl_subject = d2i_X509_NAME(NULL,
	    (const unsigned char **) &subject, subject_len)) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert certificate subject name."));
		return (CKR_GENERAL_ERROR);
	}
	cryptodebug("calling X509_set_subject_name");
	if (!X509_set_subject_name(cert, ssl_subject)) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to pack certificate subject name entries."));
		return (CKR_GENERAL_ERROR);
	}

	/* Label (optional) */
	cryptodebug("calling X509_alias_set1");
	if (!X509_alias_set1(cert, label, label_len))
		cryptodebug("error not caught");

	/* Id (optional) */
	cryptodebug("calling X509_keyid_set1");
	if (!X509_keyid_set1(cert, id, id_len))
		cryptodebug("error not caught");

	/* Issuer name (optional) */
	cryptodebug("calling d2i_X509_NAME for issuer name");
	if ((ssl_issuer = d2i_X509_NAME(NULL, (const unsigned char **) &issuer,
	    issuer_len)) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert certificate issuer name."));
		return (CKR_GENERAL_ERROR);
	}
	cryptodebug("calling X509_set_issuer_name");
	if (!X509_set_issuer_name(cert, ssl_issuer)) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to pack certificate issuer name entries."));
		return (CKR_GENERAL_ERROR);
	}

	/* Serial number (optional) */
	cryptodebug("calling OPENSSL_malloc() for serial number");
	if ((ssl_serial = OPENSSL_malloc(sizeof (ASN1_INTEGER))) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert certificate serial number."));
		return (CKR_HOST_MEMORY);
	}
	ssl_serial->length = serial_len;
	ssl_serial->type = (serial[0] & 0x80) ? V_ASN1_NEG_INTEGER :
	    V_ASN1_INTEGER;
	ssl_serial->data = serial;
	ssl_serial->flags = 0;
	cryptodebug("calling X509_set_serialNumber");
	if (!X509_set_serialNumber(cert, ssl_serial))
		cryptodebug("error not caught");

	/*
	 * Value (required)
	 *
	 * The rest of this code takes the CKA_VALUE attribute, converts
	 * it into a temp OpenSSL X509 structure and picks out the rest
	 * of the fields we need to convert it back into the current X509
	 * structure that will get exported.  The reason we don't just
	 * start with CKA_VALUE is because while the object was in the
	 * softtoken, it is possible that some of its attributes changed.
	 * Those changes would not appear in CKA_VALUE and would be lost
	 * if we started with CKA_VALUE that was saved originally.
	 */
	cryptodebug("calling d2i_X509 for cert value");
	if ((temp_cert = d2i_X509(NULL, (const unsigned char **) &value,
	    value_len)) == NULL) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to convert main certificate values."));
		return (CKR_GENERAL_ERROR);
	}

	/* Transfer these values from temp_cert to cert. */
	cryptodebug("calling X509_set_version/X509_get_version");
	if (!X509_set_version(cert, X509_get_version(temp_cert)))
		cryptodebug("error not caught");

	cryptodebug("calling X509_set_notBefore/X509_get_notBefore");
	if (!X509_set_notBefore(cert, X509_get_notBefore(temp_cert)))
		cryptodebug("error not caught");

	cryptodebug("calling X509_set_notAfter/X509_get_notAfter");
	if (!X509_set_notAfter(cert, X509_get_notAfter(temp_cert)))
		cryptodebug("error not caught");

	cryptodebug("calling X509_set_pubkey/X509_get_pubkey");
	if (!X509_set_pubkey(cert, X509_get_pubkey(temp_cert)))
		cryptodebug("error not caught");

	/*
	 * These don't get transfered from temp_cert to cert.
	 * It -appears- that they may get regenerated as needed.
	 *
	 * cert->cert_info->signature = dup(temp_cert->cert_info->signature);
	 * cert->sig_alg = dup(temp_cert->sig_alg);
	 * cert->signature = dup(temp_cert->signature);
	 * cert->skid = dup(temp_cert->skid);
	 * cert->akid = dup(temp_cert->akid);
	 */

	*c = cert;
	return (CKR_OK);
}

static CK_RV
convert_token_objs(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE obj,
	CK_OBJECT_HANDLE mate, CK_OBJECT_HANDLE *chain, CK_ULONG chain_len,
	EVP_PKEY **priv_key, X509 **cert, STACK_OF(X509) **ca)
{
	CK_RV		rv = CKR_OK;
	EVP_PKEY	*pk = NULL;
	X509		*c = NULL;
	X509		*one_ca = NULL;
	STACK_OF(X509)	*ch = NULL;
	int		i;

	cryptodebug("inside convert_token_objs");

	if ((rv = cvt_obj2evp_pkey(sess, obj, &pk)) != CKR_OK)
		return (rv);

	if (mate != ~0UL) {
		cryptodebug("converting cert corresponding to private key");
		if ((rv = cvt_cert2x509(sess, mate, &c)) != CKR_OK)
			return (rv);
	}

	if (chain_len != 0) {
		cryptodebug("converting ca chain of %d certs corresponding "
		    "to private key", chain_len);
		ch = sk_X509_new_null();
		for (i = 0; i < chain_len; i++) {
			if ((rv = cvt_cert2x509(sess, chain[i], &one_ca)) !=
			    CKR_OK) {
				return (rv);
			}
			if (!sk_X509_push(ch, one_ca))
				cryptodebug("error not caught");
		}
	}

	*priv_key = pk;
	*cert = (mate != ~0UL) ? c : NULL;
	*ca = (chain_len != 0) ? ch : NULL;
	return (CKR_OK);
}

/*
 * Export objects from token to PKCS#12 file.
 */
int
pk_export(int argc, char *argv[])
{
	int		opt;
	extern int	optind_av;
	extern char	*optarg_av;
	char		*token_spec = NULL;
	char		*token_name = NULL;
	char		*manuf_id = NULL;
	char		*serial_no = NULL;
	char		full_name[FULL_NAME_LEN];
	char		*filename = NULL;
	CK_SLOT_ID	slot_id;
	CK_FLAGS	pin_state;
	CK_UTF8CHAR_PTR	pin = NULL;
	CK_ULONG	pinlen = 0;
	CK_UTF8CHAR_PTR	pk12pin = NULL;
	CK_ULONG	pk12pinlen = 0;
	CK_SESSION_HANDLE	sess;
	BIO		*fbio = NULL;
	EVP_PKEY	*priv_key = NULL;
	X509		*cert = NULL;
	STACK_OF(X509)	*ca = NULL;
	CK_RV		rv = CKR_OK;
	CK_OBJECT_HANDLE	*objs = NULL;
	CK_ULONG	num_objs = 0;
	CK_OBJECT_HANDLE	mate = ~0UL;
	CK_OBJECT_HANDLE	*chain = NULL;
	CK_ULONG	chain_len;
	CK_BYTE		*id = NULL;
	CK_ULONG	id_len = 0;
	int		i = 0;
	int		good_ones = 0, bad_ones = 0;	/* running totals */

	cryptodebug("inside pk_export");

	/* Parse command line options.  Do NOT i18n/l10n. */
	while ((opt = getopt_av(argc, argv, "T:(token)o:(outfile)")) != EOF) {
		switch (opt) {
		case 'T':	/* token specifier */
			if (token_spec)
				return (PK_ERR_USAGE);
			token_spec = optarg_av;
			break;
		case 'o':	/* output file name */
			if (filename)
				return (PK_ERR_USAGE);
			filename = optarg_av;
			break;
		default:
			return (PK_ERR_USAGE);
			break;
		}
	}

	/* If nothing is specified, default is to use softtoken. */
	if (token_spec == NULL) {
		token_name = SOFT_TOKEN_LABEL;
		manuf_id = SOFT_MANUFACTURER_ID;
		serial_no = SOFT_TOKEN_SERIAL;
	} else {
		/*
		 * Parse token specifier into token_name, manuf_id, serial_no.
		 * Token_name is required; manuf_id and serial_no are optional.
		 */
		if (parse_token_spec(token_spec, &token_name, &manuf_id,
		    &serial_no) < 0)
			return (PK_ERR_USAGE);
	}

	/* Filename arg is required. */
	if (filename == NULL)
		return (PK_ERR_USAGE);

	/* No additional args allowed. */
	argc -= optind_av;
	argv += optind_av;
	if (argc)
		return (PK_ERR_USAGE);
	/* Done parsing command line options. */

	/* Check if the file exists and might be overwritten. */
	if (access(filename, F_OK) == 0) {
		cryptoerror(LOG_STDERR, gettext("Warning: file \"%s\" exists, "
		    "will be overwritten."), filename);
		if (yesno(gettext("Continue with export? "),
		    gettext("Respond with yes or no.\n"), B_FALSE) == B_FALSE) {
			return (0);
		}
	}

	full_token_name(token_name, manuf_id, serial_no, full_name);

	/* Find the slot with token. */
	if ((rv = find_token_slot(token_name, manuf_id, serial_no, &slot_id,
	    &pin_state)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to find token %s (%s)."), full_name,
		    pkcs11_strerror(rv));
		return (PK_ERR_PK11);
	}

	/* Get the user's PIN. */
	if ((rv = get_pin(gettext("Enter token passphrase:"), NULL, &pin,
	    &pinlen)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to get token passphrase (%s)."),
		    pkcs11_strerror(rv));
		quick_finish(NULL);
		return (PK_ERR_PK11);
	}

	/* Assume user must be logged in R/W to export objects from token. */
	if ((rv = quick_start(slot_id, CKF_RW_SESSION, pin, pinlen, &sess)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to log into token (%s)."),
		    pkcs11_strerror(rv));
		quick_finish(sess);
		return (PK_ERR_PK11);
	}

	/* Collect all private keys first. */
	if ((rv = find_objs(sess, PK_PRIVATE_OBJ|PK_KEY_OBJ, NULL,
	    &objs, &num_objs)) != CKR_OK) {
		cryptoerror(LOG_STDERR, gettext(
		    "Unable to retrieve private key token objects (%s)."),
		    pkcs11_strerror(rv));
		quick_finish(sess);
		return (PK_ERR_PK11);
	}

	/* Nothing to do? */
	if (num_objs == 0) {
		cryptoerror(LOG_STDERR, gettext("No objects found."));
		quick_finish(sess);
		return (0);
	}

	/* Setup OpenSSL context. */
	PKTOOL_setup_openssl();

	/* Create PKCS#12 file. */
	if ((create_pkcs12(filename, &fbio)) < 0) {
		cryptoerror(LOG_STDERR, gettext("No export file created."));
		quick_finish(sess);
		return (PK_ERR_SYSTEM);
	}

	/* Get the PIN for the PKCS#12 export file. */
	if ((rv = get_pin(gettext("Create export file passphrase:"), gettext(
	    "Re-enter export file passphrase:"), &pk12pin, &pk12pinlen)) !=
	    CKR_OK) {
		cryptoerror(LOG_STDERR,
		    gettext("Unable to get export file passphrase (%s)."),
		    pkcs11_strerror(rv));
		close_pkcs12(fbio);
		quick_finish(sess);
		return (PK_ERR_PK11);
	}

	for (i = 0; i < num_objs; i++) {
		/* Get a private key and its certificate and CA chain. */
		if ((rv = get_token_objs(sess, objs[i], &mate, &chain,
		    &chain_len, &id, &id_len)) != CKR_OK) {
			/*
			 * Note this "rv" is either CKR_OK or !CKR_OK.  The
			 * real error codes/messages are handled inside
			 * read_token_objs().
			 */
			cryptoerror(LOG_STDERR,
			    gettext("Unable to get token objects."));
			free(id);
			close_pkcs12(fbio);
			quick_finish(sess);
			return (PK_ERR_PK11);
		}

		/* Convert to OpenSSL equivalents. */
		if ((rv = convert_token_objs(sess, objs[i], mate, chain,
		    chain_len, &priv_key, &cert, &ca)) != CKR_OK) {
			/*
			 * Note this "rv" is either CKR_OK or !CKR_OK.  The
			 * real error codes/messages are handled inside
			 * read_token_objs().
			 */
			cryptoerror(LOG_STDERR,
			    gettext("Unable to convert token objects."));
			free(id);
			close_pkcs12(fbio);
			quick_finish(sess);
			return (PK_ERR_PK11);
		}

		/*
		 * When exporting of cert chains is implemented, these
		 * messages should be updated accordingly.
		 */
		if (mate == ~0UL)
			(void) fprintf(stdout, gettext(
			    "Writing object #%d...\n"), i+1);
		else
			(void) fprintf(stdout, gettext("Writing object #%d "
			    "and its certificate...\n"), i+1);

		/* Write object and its certs to the PKCS#12 export file. */
		if (write_objs_pkcs12(fbio, pk12pin, pk12pinlen, id, id_len,
		    priv_key, cert, ca, &good_ones, &bad_ones) < 0) {
			cryptoerror(LOG_STDERR, gettext(
			    "Unable to write object #%d to export file."), i+1);
			sk_X509_pop_free(ca, X509_free);
			free(id);
			close_pkcs12(fbio);
			quick_finish(sess);
			return (PK_ERR_OPENSSL);
		}

		/* Destroy key id and CA cert chain, done with them. */
		free(id);
		id = NULL;
		sk_X509_pop_free(ca, X509_free);
		ca = NULL;
	}

	(void) fprintf(stdout, gettext(
	    "%d token objects exported, %d errors occurred.\n"),
	    good_ones, bad_ones);

	/* Close PKCS#12 file. */
	close_pkcs12(fbio);

	/* Clean up. */
	quick_finish(sess);
	return (0);
}
