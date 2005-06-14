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
 *	dh_common.h
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 */

#ifndef _DH_COMMON_H_
#define	_DH_COMMON_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpcsvc/nis_dhext.h>

#ifdef __cplusplus
extern "C" {
#endif

gss_mechanism
__dh_generic_initialize(gss_mechanism dhmech,
			gss_OID_desc mech_type, dh_keyopts_t keyopts);

void
__generic_gen_dhkeys(int keylen, char *xmodulus, int proot,
		    char *public, char *secret, char *pass);
void
__generic_common_dhkeys(char *pkey, char *skey, int keylen,
			char *xmodulus, des_block keys[], int keynum);


extern void
des_setparity(char *);

#ifdef __cplusplus
}
#endif

#endif /* _DH_COMMON_H_ */
