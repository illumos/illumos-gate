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
 * Copyright (c) 1996, by Sun MicroSystem, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if 0

/*
 * Generic capabilities Routines
 */

#include <sys/dada/dada.h>

#define	A_TO_TRAN(ap) (ap->a_hba_tran)


int
dcd_ifgetcap(struct dcd_address *ap, char *cap, int whom)
{

	return (*A_TO_TRAN(ap)->tran_getcap)(ap, cap, whom);
}

int
dcd_ifsetcap(struct dcd_address *ap, char *cap, int value, int whom)
{

	return (*A_TO_TRAN(ap)->tran_setcap)(ap, cap, value, whom);
}
#endif
