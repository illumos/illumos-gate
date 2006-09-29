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
 * Routines to handle bootparams* calls in nscd
 */

#include "cache.h"

#define	nam_db	ctx->nsc_db[0]
#define	NSC_NAME_BOOTPARAMS_BYNAME	"bootparams"

void
bootp_init_ctx(nsc_ctx_t *ctx) {
	ctx->dbname = NSS_DBNAM_BOOTPARAMS;
	ctx->file_name = "/etc/bootparams";
	ctx->db_count = 1;
	nam_db = make_cache(nsc_key_cis,
			NSS_DBOP_BOOTPARAMS_BYNAME,
			NSC_NAME_BOOTPARAMS_BYNAME,
			NULL, NULL, NULL, nsc_ht_default, -1);
}
