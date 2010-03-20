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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <strings.h>
#include <rpc/xdr.h>
#include <errno.h>
#include <syslog.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_door.h>


/*
 * Generic XDR encoder.
 *
 * Returns a malloc'd, encoded buffer upon success.
 * Otherwise, returns NULL.
 */
char *
smb_common_encode(void *data, xdrproc_t proc, size_t *rsize)
{
	XDR	xdrs;
	char	*buf;
	size_t	len;

	if (proc == NULL || data == NULL || rsize == NULL) {
		syslog(LOG_ERR, "smb_common_encode: invalid parameter");
		return (NULL);
	}

	len = xdr_sizeof(proc, data);

	if ((buf = malloc(len)) == NULL) {
		syslog(LOG_ERR, "smb_common_encode: %m");
		*rsize = 0;
		return (NULL);
	}

	xdrmem_create(&xdrs, buf, len, XDR_ENCODE);
	*rsize = len;

	if (!proc(&xdrs, data)) {
		syslog(LOG_DEBUG, "smb_common_encode: encode error");
		free(buf);
		buf = NULL;
		*rsize = 0;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

/*
 * Generic XDR decoder.  Ensure that data is non-null and bzero'd.
 */
int
smb_common_decode(char *buf, size_t len, xdrproc_t proc, void *data)
{
	XDR xdrs;
	int rc = 0;

	if (data == NULL)
		return (-1);

	xdrmem_create(&xdrs, buf, len, XDR_DECODE);
	if (!proc(&xdrs, data))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * smb_kshare_mkselfrel
 *
 * encode: structure -> flat buffer (buffer size)
 * Pre-condition: kshare is non-null.
 */
uint8_t *
smb_kshare_mkselfrel(smb_dr_kshare_t *kshare, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	if (!kshare)
		return (NULL);

	*len = xdr_sizeof(smb_dr_kshare_xdr, kshare);
	buf = (uint8_t *)malloc(*len);
	if (!buf)
		return (NULL);

	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);

	if (!smb_dr_kshare_xdr(&xdrs, kshare)) {
		*len = 0;
		free(buf);
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

char *
smb_string_encode(char *s, size_t *rsize)
{
	smb_string_t	obj;
	XDR		xdrs;
	char		*buf = NULL;
	size_t		len;

	if ((obj.buf = s) == NULL) {
		syslog(LOG_DEBUG, "smb_string_encode: invalid param");
		goto smb_string_encode_failed;
	}

	len = xdr_sizeof(smb_string_xdr, &obj);
	if ((buf = calloc(len, 1)) == NULL) {
		syslog(LOG_DEBUG, "smb_string_encode: %m");
		goto smb_string_encode_failed;
	}

	xdrmem_create(&xdrs, buf, len, XDR_ENCODE);

	if (!smb_string_xdr(&xdrs, &obj)) {
		syslog(LOG_DEBUG, "smb_string_encode: encode failed");
		xdr_destroy(&xdrs);
		free(buf);
		goto smb_string_encode_failed;
	}

	xdr_destroy(&xdrs);
	if (rsize)
		*rsize = len;
	return (buf);

smb_string_encode_failed:
	if (rsize)
		*rsize = 0;
	return (NULL);
}

int
smb_string_decode(smb_string_t *obj, char *buf, size_t buflen)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_DECODE);

	bzero(obj, sizeof (smb_string_t));
	if (!smb_string_xdr(&xdrs, obj))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * Encode an lsa_account_t into a buffer.
 */
int
lsa_account_encode(lsa_account_t *acct, uint8_t *buf, uint32_t buflen)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_ENCODE);

	if (!lsa_account_xdr(&xdrs, acct))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * Decode an XDR buffer into an lsa_account_t.
 */
int
lsa_account_decode(lsa_account_t *acct, uint8_t *buf, uint32_t buflen)
{
	XDR xdrs;
	int rc = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, buflen, XDR_DECODE);

	bzero(acct, sizeof (lsa_account_t));
	if (!lsa_account_xdr(&xdrs, acct))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

bool_t
lsa_account_xdr(XDR *xdrs, lsa_account_t *objp)
{
	if (!xdr_uint16_t(xdrs, &objp->a_sidtype))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->a_status))
		return (FALSE);
	if (!xdr_vector(xdrs, (char *)objp->a_domain, MAXNAMELEN,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);
	if (!xdr_vector(xdrs, (char *)objp->a_name, MAXNAMELEN,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);
	if (!xdr_vector(xdrs, (char *)objp->a_sid, SMB_SID_STRSZ,
	    sizeof (char), (xdrproc_t)xdr_char))
		return (FALSE);
	return (TRUE);
}
