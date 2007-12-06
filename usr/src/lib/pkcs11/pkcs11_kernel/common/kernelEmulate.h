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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KERNEL_EMULATE_H
#define	_KERNEL_EMULATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <strings.h>
#include <sys/crypto/ioctl.h>
#include <security/cryptoki.h>
#include "kernelGlobal.h"
#include "kernelSession.h"
#include "kernelSoftCommon.h"

#define	SLOT_THRESHOLD(sp) (slot_table[sp->ses_slotid]->sl_threshold)
#define	SLOT_MAX_INDATA_LEN(sp)	(slot_table[sp->ses_slotid]->sl_max_inlen)
#define	SLOT_HAS_LIMITED_HASH(sp) (slot_table[sp->ses_slotid]->sl_flags & \
	CRYPTO_LIMITED_HASH_SUPPORT)
#define	get_sp(opp)	(((digest_buf_t *)((opp)->context))->soft_sp)
#define	get_spp(opp)	(&(((digest_buf_t *)((opp)->context))->soft_sp))

/* reinit buffer so that we can reuse it */
#define	REINIT_OPBUF(opp) {			 		\
	if ((opp)->flags & CRYPTO_EMULATE) {			\
		digest_buf_t *bufp = (opp)->context;		\
		if (bufp != NULL) {				\
			bzero(bufp->buf, bufp->indata_len);	\
			bufp->indata_len = 0;			\
		}						\
	}							\
}

boolean_t is_hmac(CK_MECHANISM_TYPE mechanism);
CK_RV emulate_buf_init(kernel_session_t *session_p, int buflen, int opflag);
CK_RV emulate_init(kernel_session_t *session_p, CK_MECHANISM_PTR pMechanism,
    crypto_key_t *keyp, int opflag);
CK_RV emulate_update(kernel_session_t *session_p, CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen, int opflag);

#ifdef __cplusplus
}
#endif

#endif /* _KERNEL_EMULATE_H */
