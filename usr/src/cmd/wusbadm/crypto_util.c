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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include <pwd.h>
#include <nss_dbdefs.h>
#include <auth_attr.h>
#include "crypto_util.h"

/* init kmf handle and pkcs11 handle, for cc creation */
int
wusb_crypto_init(
		KMF_HANDLE_T *kmfhandle,
		CK_SESSION_HANDLE *pkhandle,
		const char *pktoken,
		const char *tokendir)
{
	KMF_KEYSTORE_TYPE kstype = KMF_KEYSTORE_PK11TOKEN;
	boolean_t bfalse = FALSE;
	KMF_ATTRIBUTE attrlist[20];
	int numattr;

	/* change default softtoken directory */
	if (setenv("SOFTTOKEN_DIR", tokendir, 1) != 0) {

		return (-1);
	}

	/* init kmf */
	if (kmf_initialize(kmfhandle, NULL, NULL) != KMF_OK) {

		return (-1);
	}

	numattr = 0;
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_KEYSTORE_TYPE_ATTR, &kstype, sizeof (kstype));
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_TOKEN_LABEL_ATTR, (void *)pktoken, strlen(pktoken) + 1);
	kmf_set_attr_at_index(attrlist, numattr++,
	    KMF_READONLY_ATTR, &bfalse, sizeof (bfalse));

	if (kmf_configure_keystore(*kmfhandle, numattr, attrlist) != KMF_OK) {

		return (-1);
	}

	/* get pkcs11 handle from kmf */
	*pkhandle = kmf_get_pk11_handle(*kmfhandle);
	if (*pkhandle == NULL) {

		return (-1);
	}

	return (0);
}

void
wusb_crypto_fini(KMF_HANDLE_T kmfhandle)
{
	(void) kmf_finalize(kmfhandle);
}

/* random generation, for cc creation */
int
wusb_random(
		CK_SESSION_HANDLE hSession,
		CK_BYTE *seed, size_t slen,
		CK_BYTE *rand, size_t rlen)
{
	hrtime_t hrt;

	if (seed == NULL) {
		hrt = gethrtime() + gethrvtime();
		if (C_SeedRandom(hSession, (CK_BYTE *)&hrt,
		    sizeof (hrt)) != CKR_OK) {

			return (-1);
		}
	} else {
		if (C_SeedRandom(hSession, seed, slen) != CKR_OK) {

			return (-1);
		}
	}

	if (C_GenerateRandom(hSession, rand, rlen) != CKR_OK) {

		return (-1);
	}

	return (0);
}


/* conver mac address to label string */
void
mac_to_label(uint8_t *mac, char *label)
{
	int i;

	bzero(label, WUSB_CC_LABEL_LENGTH);
	for (i = 0; i < WUSB_DEV_MAC_LENGTH; i++) {
		(void) snprintf(label, WUSB_CC_LABEL_LENGTH,
		    "%s%02x", label, mac[i]);
	}
}

/* ARGSUSED */
/* For debug only, print an array of byte */
void
print_array(const char *label, CK_BYTE *array, size_t len)
{
#ifdef DEBUG
	int i;

	fprintf(stdout, "%s :\n", label);
	for (i = 0; i < len; i++) {
		fprintf(stdout, "%02x ", array[i]);
		if ((i & 15) == 15) fprintf(stdout, "\n");
	}
#endif
}

/* Check if a uid has auths */
int
chk_auths(uid_t uid, const char *auths)
{
	struct	passwd pwd;
	char	buf[NSS_LINELEN_PASSWD];


	if (uid == (uid_t)-1) {
		return (-1);
	}

	/* get user name */
	if (getpwuid_r(uid, &pwd, buf, sizeof (buf)) == NULL) {
		return (-1);
	}

	/* check the auths */
	if (chkauthattr(auths, pwd.pw_name) != 1) {
		return (-1);
	}
	return (0);

}
