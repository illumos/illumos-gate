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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _NTLM_H
#define	_NTLM_H

/*
 * NTLM support functions
 * See ntlm.c
 */

/*
 * Size of all LM/NTLM hashes, challenge
 * NTLM_HASH_SZ: 16 bytes (see smb_lib.h)
 * NTLM_CHAL_SZ:  8 bytes (see smb_lib.h)
 */
#define	NTLM_V1_RESP_SZ 	24	/* response size */

#define	NAMETYPE_EOL		0x0000	/* end of list of names */
#define	NAMETYPE_MACHINE_NB	0x0001	/* NetBIOS machine name */
#define	NAMETYPE_DOMAIN_NB	0x0002	/* NetBIOS domain name */
#define	NAMETYPE_MACHINE_DNS	0x0003	/* DNS machine name */
#define	NAMETYPE_DOMAIN_DNS	0x0004	/* DNS (AD) domain name */

int
ntlm_compute_lm_hash(uchar_t *hash, const char *pw);

int
ntlm_compute_nt_hash(uchar_t *hash, const char *pw);

int
ntlm_build_target_info(struct smb_ctx *, struct mbuf *, struct mbdata *);

int
ntlm_put_v1_responses(struct smb_ctx *ctx,
	struct mbdata *lm_mbp, struct mbdata *nt_mbp);

int
ntlm_put_v1x_responses(struct smb_ctx *ctx,
	struct mbdata *lm_mbp, struct mbdata *nt_mbp);

int
ntlm_put_v2_responses(struct smb_ctx *ctx, struct mbdata *ti_mbp,
	struct mbdata *lm_mbp, struct mbdata *nt_mbp);

int
ntlm_build_mac_key(struct smb_ctx *ctx, struct mbdata *ntresp_mbp);

void
ntlm2_kxkey(struct smb_ctx *ctx, struct mbdata *lm_mbp, uchar_t *kxkey);

#endif /* _NTLM_H */
