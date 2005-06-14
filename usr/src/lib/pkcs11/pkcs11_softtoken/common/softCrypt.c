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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <security/cryptoki.h>
#include <bignum.h>


CK_RV
convert_rv(BIG_ERR_CODE err)
{
	switch (err) {

	case BIG_OK:
		return (CKR_OK);

	case BIG_NO_MEM:
		return (CKR_HOST_MEMORY);

	case BIG_NO_RANDOM:
		return (CKR_DEVICE_ERROR);

	case BIG_INVALID_ARGS:
		return (CKR_ARGUMENTS_BAD);

	case BIG_DIV_BY_0:
	default:
		return (CKR_GENERAL_ERROR);
	}
}

BIG_ERR_CODE
convert_brv(CK_RV err)
{
	switch (err) {

	case CKR_OK:
		return (BIG_OK);

	case CKR_HOST_MEMORY:
		return (BIG_NO_MEM);

	case CKR_DEVICE_ERROR:
		return (BIG_NO_RANDOM);

	case CKR_ARGUMENTS_BAD:
		return (BIG_INVALID_ARGS);

	default:
		return (BIG_GENERAL_ERR);
	}
}
