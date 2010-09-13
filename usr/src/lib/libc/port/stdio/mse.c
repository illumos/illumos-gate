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

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include "mtlib.h"
#include "mbstatet.h"
#include "file64.h"
#include <sys/types.h>
#include <stdio.h>
#include <wchar.h>
#include <thread.h>
#include <synch.h>
#include <stdlib.h>
#include <string.h>
#include "libc.h"
#include "stdiom.h"
#include "mse.h"

/*
 * DESCRIPTION:
 * This function/macro gets the orientation bound to the specified iop.
 *
 * RETURNS:
 * _WC_MODE	if iop has been bound to Wide orientation
 * _BYTE_MODE	if iop has been bound to Byte orientation
 * _NO_MODE	if iop has been bound to neither Wide nor Byte
 */
_IOP_orientation_t
_getorientation(FILE *iop)
{
	if (GET_BYTE_MODE(iop))
		return (_BYTE_MODE);
	else if (GET_WC_MODE(iop))
		return (_WC_MODE);

	return (_NO_MODE);
}

/*
 * DESCRIPTION:
 * This function/macro sets the orientation to the specified iop.
 *
 * INPUT:
 * flag may take one of the following:
 *	_WC_MODE	Wide orientation
 *	_BYTE_MODE	Byte orientation
 *	_NO_MODE	Unoriented
 */
void
_setorientation(FILE *iop, _IOP_orientation_t mode)
{
	switch (mode) {
	case _NO_MODE:
		CLEAR_BYTE_MODE(iop);
		CLEAR_WC_MODE(iop);
		break;
	case _BYTE_MODE:
		CLEAR_WC_MODE(iop);
		SET_BYTE_MODE(iop);
		break;
	case _WC_MODE:
		CLEAR_BYTE_MODE(iop);
		SET_WC_MODE(iop);
		break;
	}
}
