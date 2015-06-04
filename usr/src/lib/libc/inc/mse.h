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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MSE_H
#define	_MSE_H

#include "lint.h"
#include "file64.h"
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include "stdiom.h"

typedef enum {
	_NO_MODE,					/* not bound */
	_BYTE_MODE,					/* Byte orientation */
	_WC_MODE					/* Wide orientation */
} _IOP_orientation_t;

/*
 * DESCRIPTION:
 * This function gets the pointer to the mbstate_t structure associated
 * with the specified iop.
 *
 * RETURNS:
 * If the associated mbstate_t found, the pointer to the mbstate_t is
 * returned.  Otherwise, (mbstate_t *)NULL is returned.
 */
#ifdef _LP64
#define	_getmbstate(iop)	(&(iop)->_state)
#else
extern mbstate_t	*_getmbstate(FILE *);
#endif

/*
 * DESCRIPTION:
 * This function/macro gets the orientation bound to the specified iop.
 *
 * RETURNS:
 * _WC_MODE	if iop has been bound to Wide orientation
 * _BYTE_MODE	if iop has been bound to Byte orientation
 * _NO_MODE	if iop has been bound to neither Wide nor Byte
 */
extern _IOP_orientation_t	_getorientation(FILE *);

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
extern void	_setorientation(FILE *, _IOP_orientation_t);

/*
 * From page 32 of XSH5
 * Once a wide-character I/O function has been applied
 * to a stream without orientation, the stream becomes
 * wide-oriented.  Similarly, once a byte I/O function
 * has been applied to a stream without orientation,
 * the stream becomes byte-oriented.  Only a call to
 * the freopen() function or the fwide() function can
 * otherwise alter the orientation of a stream.
 */

#define	_SET_ORIENTATION_BYTE(iop) \
{ \
	if (GET_NO_MODE(iop)) \
		_setorientation(iop, _BYTE_MODE); \
}

#endif	/* _MSE_H */
