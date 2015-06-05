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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * NT Token library (kernel/user)
 */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#else /* _KERNEL */
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#endif /* _KERNEL */

#include <smbsrv/string.h>
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

/*
 * Basic sanity check on a token.
 */
boolean_t
smb_token_valid(smb_token_t *token)
{
	if (token == NULL)
		return (B_FALSE);

	if ((token->tkn_user.i_sid == NULL) ||
	    (token->tkn_owner.i_sid == NULL) ||
	    (token->tkn_primary_grp.i_sid == NULL) ||
	    (token->tkn_account_name == NULL) ||
	    (token->tkn_domain_name == NULL) ||
	    (token->tkn_posix_grps == NULL))
		return (B_FALSE);

	if ((token->tkn_win_grps.i_cnt != 0) &&
	    (token->tkn_win_grps.i_ids == NULL))
		return (B_FALSE);

	return (B_TRUE);
}

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
/*
 * Encode: structure -> flat buffer (buffer size)
 * Pre-condition: obj is non-null.
 */
uint8_t *
smb_token_encode(smb_token_t *obj, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	if (!obj) {
		syslog(LOG_ERR, "smb_token_encode: invalid parameter");
		return (NULL);
	}

	*len = xdr_sizeof(smb_token_xdr, obj);
	buf = (uint8_t *)malloc(*len);
	if (!buf) {
		syslog(LOG_ERR, "smb_token_encode: %m");
		return (NULL);
	}

	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);

	if (!smb_token_xdr(&xdrs, obj)) {
		syslog(LOG_ERR, "smb_token_encode: XDR encode error");
		*len = 0;
		free(buf);
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

/*
 * Decode: flat buffer -> structure
 */
smb_logon_t *
smb_logon_decode(uint8_t *buf, uint32_t len)
{
	smb_logon_t	*obj;
	XDR		xdrs;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);

	if ((obj = malloc(sizeof (smb_logon_t))) == NULL) {
		syslog(LOG_ERR, "smb_logon_decode: %m");
		xdr_destroy(&xdrs);
		return (NULL);
	}

	bzero(obj, sizeof (smb_logon_t));
	if (!smb_logon_xdr(&xdrs, obj)) {
		syslog(LOG_ERR, "smb_logon_decode: XDR decode error");
		free(obj);
		obj = NULL;
	}

	xdr_destroy(&xdrs);
	return (obj);
}

void
smb_logon_free(smb_logon_t *obj)
{
	xdr_free(smb_logon_xdr, (char *)obj);
	free(obj);
}
#else /* _KERNEL */
/*
 * Tokens are allocated in the kernel via XDR.
 * Call xdr_free before freeing the token structure.
 */
void
smb_token_free(smb_token_t *token)
{
	if (token != NULL) {
		xdr_free(smb_token_xdr, (char *)token);
		kmem_free(token, sizeof (smb_token_t));
	}
}
#endif /* _KERNEL */
