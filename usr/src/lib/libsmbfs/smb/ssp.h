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

#ifndef _SSP_H
#define	_SSP_H

/*
 * Security Support Package (SSP) interface,
 * somewhat modeled on Microsoft's SSPI.
 *
 * XXX: Yes, should use GSS-API.  See ssp.c
 */

typedef struct ssp_ctx {
	struct smb_ctx *smb_ctx;

	SPNEGO_TOKEN_HANDLE	sp_hint;
	SPNEGO_MECH_OID		sp_mech;

	/*
	 * Now the mechanism-specific stuff.
	 */
	int (*sp_nexttok)(struct ssp_ctx *,
	    struct mbdata *, struct mbdata *);
	void (*sp_destroy)(struct ssp_ctx *);
	void *sp_private;

} ssp_ctx_t;

int ntlmssp_init_client(ssp_ctx_t *);
int krb5ssp_init_client(ssp_ctx_t *);

#endif /* _SSP_H */
