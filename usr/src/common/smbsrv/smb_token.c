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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * NT Token library (kernel/user)
 */

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#else /* _KERNEL */
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#endif /* _KERNEL */

#include <smbsrv/string.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/smb_xdr.h>

/*
 * smb_token_query_privilege
 *
 * Find out if the specified privilege is enable in the given
 * access token.
 */
int
smb_token_query_privilege(smb_token_t *token, int priv_id)
{
	smb_privset_t *privset;
	int i;

	if ((token == NULL) || (token->tkn_privileges == NULL))
		return (0);

	privset = token->tkn_privileges;
	for (i = 0; privset->priv_cnt; i++) {
		if (privset->priv[i].luid.lo_part == priv_id) {
			if (privset->priv[i].attrs == SE_PRIVILEGE_ENABLED)
				return (1);
			else
				return (0);
		}
	}

	return (0);
}

#ifndef _KERNEL
/*
 * smb_token_mkselfrel
 *
 * encode: structure -> flat buffer (buffer size)
 * Pre-condition: obj is non-null.
 */
uint8_t *
smb_token_mkselfrel(smb_token_t *obj, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	if (!obj) {
		syslog(LOG_ERR, "smb_token_mkselfrel: invalid parameter");
		return (NULL);
	}

	*len = xdr_sizeof(xdr_smb_token_t, obj);
	buf = (uint8_t *)malloc(*len);
	if (!buf) {
		syslog(LOG_ERR, "smb_token_mkselfrel: resource shortage");
		return (NULL);
	}

	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);

	if (!xdr_smb_token_t(&xdrs, obj)) {
		syslog(LOG_ERR, "smb_token_mkselfrel: XDR encode error");
		*len = 0;
		free(buf);
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

/*
 * netr_client_mkabsolute
 *
 * decode: flat buffer -> structure
 */
netr_client_t *
netr_client_mkabsolute(uint8_t *buf, uint32_t len)
{
	netr_client_t *obj;
	XDR xdrs;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);
	obj = (netr_client_t *)malloc(sizeof (netr_client_t));
	if (!obj) {
		syslog(LOG_ERR, "netr_client_mkabsolute: resource shortage");
		xdr_destroy(&xdrs);
		return (NULL);
	}

	bzero(obj, sizeof (netr_client_t));
	if (!xdr_netr_client_t(&xdrs, obj)) {
		syslog(LOG_ERR, "netr_client_mkabsolute: XDR decode error");
		free(obj);
		obj = NULL;
	}

	xdr_destroy(&xdrs);
	return (obj);
}

void
netr_client_xfree(netr_client_t *clnt)
{
	xdr_free(xdr_netr_client_t, (char *)clnt);
	free(clnt);
}
#else /* _KERNEL */
/*
 * smb_token_mkabsolute
 *
 * decode: flat buffer -> structure
 */
smb_token_t *
smb_token_mkabsolute(uint8_t *buf, uint32_t len)
{
	smb_token_t *obj;
	XDR xdrs;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);
	obj = kmem_zalloc(sizeof (smb_token_t), KM_SLEEP);

	if (!xdr_smb_token_t(&xdrs, obj)) {
		cmn_err(CE_NOTE, "smb_token_mkabsolute: XDR decode error");
		kmem_free(obj, sizeof (smb_token_t));
		obj = NULL;
	}

	xdr_destroy(&xdrs);
	return (obj);
}

/*
 * netr_client_mkselfrel
 *
 * encode: structure -> flat buffer (buffer size)
 * Pre-condition: obj is non-null.
 */
uint8_t *
netr_client_mkselfrel(netr_client_t *obj, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	*len = xdr_sizeof(xdr_netr_client_t, obj);
	buf = kmem_alloc(*len, KM_SLEEP);

	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);

	if (!xdr_netr_client_t(&xdrs, obj)) {
		cmn_err(CE_NOTE, "netr_client_mkselfrel: XDR encode error");
		kmem_free(buf, *len);
		*len = 0;
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

void
smb_token_free(smb_token_t *token)
{
	if (!token)
		return;

	/*
	 * deallocate any pointer field of an access token object
	 * using xdr_free since they are created by the XDR decode
	 * operation.
	 */
	xdr_free(xdr_smb_token_t, (char *)token);
	kmem_free(token, sizeof (smb_token_t));
}
#endif /* _KERNEL */
