/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	This provides the interface to store a named key in stable local
 *	storage.  These keys are retrieved and used by OBP and WAN boot
 *	to do decryption and HMAC verification of network-downloaded data.
 */

#include <sys/promimpl.h>
#ifdef	PROM_32BIT_ADDRS
#include <sys/sunddi.h>
#endif	/* PROM_32BIT_ADDRS */

int
prom_set_security_key(char *keyname, caddr_t buf, int buflen, int *reslen,
    int *status)
{
	int	rv;
	cell_t	ci[7];
	int	result;
#ifdef	PROM_32BIT_ADDRS
	char	*okeyname = NULL;
	char	*obuf = NULL;
	size_t	keynamelen;

	if ((uintptr_t)keyname > (uint32_t)-1) {
		okeyname = keyname;
		keynamelen = prom_strlen(okeyname) + 1;	/* include '\0' */
		keyname = promplat_alloc(keynamelen);
		if (keyname == NULL)
			return (-1);
		(void) prom_strcpy(keyname, okeyname);
	}

	/*
	 *	A key length of zero is used to delete the named key.
	 *	No need to reallocate and copy buf[] in this case.
	 */
	if (buflen > 0 && ((uintptr_t)buf > (uint32_t)-1)) {
		obuf = buf;
		buf = promplat_alloc(buflen);
		if ((buf == NULL) && (okeyname != NULL)) {
			promplat_free(keyname, keynamelen);
			return (-1);
		}
		promplat_bcopy(obuf, buf, buflen);
	}
#endif	/* PROM_32BIT_ADDRS */

	/*
	 *	The arguments to the SUNW,set-security-key service
	 *	that stores a key are
	 *		ci[0]	the service name
	 *		ci[1]	the number of ``in'' arguments
	 *		ci[2]	the number of ``out'' arguments
	 *		ci[3]	the key's name, as a string
	 *		ci[4]	the key buffer itself
	 *		ci[5]	the length of the key buffer
	 *
	 *	When p1275_cif_handler() returns, the return value is
	 *		ci[6]	the length of the key stored, or (if
	 *			negative) an error code.
	 */
	ci[0] = p1275_ptr2cell("SUNW,set-security-key");
	ci[1] = 3;
	ci[2] = 1;
	ci[3] = p1275_ptr2cell(keyname);
	ci[4] = p1275_ptr2cell(buf);
	ci[5] = p1275_uint2cell(buflen);

	promif_preprom();
	rv = p1275_cif_handler(ci);
	promif_postprom();

#ifdef	PROM_32BIT_ADDRS
	if (okeyname != NULL)
		promplat_free(keyname, keynamelen);
	if (obuf != NULL)
		promplat_free(buf, buflen);
#endif	/* PROM_32BIT_ADDRS */

	if (rv != 0)
		return (-1);

	result = p1275_cell2int(ci[6]);
	if (result >= 0) {
		*reslen = result;
		*status = 0;
	} else {
		*reslen = 0;
		*status = result;
	}
	return (0);
}

int
prom_get_security_key(char *keyname, caddr_t buf, int buflen, int *keylen,
    int *status)
{
	int	rv;
	cell_t	ci[7];
	int	result;
#ifdef	PROM_32BIT_ADDRS
	char	*okeyname = NULL;
	char	*obuf = NULL;
	size_t	keynamelen;

	if ((uintptr_t)keyname > (uint32_t)-1) {
		okeyname = keyname;
		keynamelen = prom_strlen(okeyname) + 1; /* include '\0' */
		keyname = promplat_alloc(keynamelen);
		if (keyname == NULL)
			return (-1);
		(void) prom_strcpy(keyname, okeyname);
	}
	if ((uintptr_t)buf > (uint32_t)-1) {
		obuf = buf;
		buf = promplat_alloc(buflen);
		if ((buf == NULL) && (okeyname != NULL)) {
			promplat_free(keyname, keynamelen);
			return (-1);
		}
	}
#endif	/* PROM_32BIT_ADDRS */

	/*
	 *	The arguments to the SUNW,get-security-key service
	 *	that stores a key are
	 *		ci[0]	the service name
	 *		ci[1]	the number of ``in'' arguments
	 *		ci[2]	the number of ``out'' arguments
	 *		ci[3]	the key's name, as a string
	 *		ci[4]	the key buffer itself
	 *		ci[5]	the length of the key buffer
	 *
	 *	When p1275_cif_handler() returns, the return value is
	 *		ci[6]	the length of the key, or (if
	 *			negative) an error code.
	 */
	ci[0] = p1275_ptr2cell("SUNW,get-security-key");
	ci[1] = 3;
	ci[2] = 1;
	ci[3] = p1275_ptr2cell(keyname);
	ci[4] = p1275_ptr2cell(buf);
	ci[5] = p1275_uint2cell(buflen);

	promif_preprom();
	rv = p1275_cif_handler(ci);
	promif_postprom();

#ifdef	PROM_32BIT_ADDRS
	if (okeyname != NULL)
		promplat_free(keyname, keynamelen);
	if (obuf != NULL) {
		promplat_bcopy(buf, obuf, buflen);
		promplat_free(buf, buflen);
	}
#endif	/* PROM_32BIT_ADDRS */

	if (rv != 0)
		return (-1);

	result = p1275_cell2int(ci[6]);
	if (result > 0) {
		*keylen = result;
		*status = 0;
	} else {
		*keylen = 0;
		*status = result;
	}
	return (0);
}
