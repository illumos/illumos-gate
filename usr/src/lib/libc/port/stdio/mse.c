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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * This function sets the error indicator for the specified stream.
 * This is a private API for the L10N method functions, especially
 * for fgetwc().
 *
 * The stream needs to have been properly locked.  Usually, the wrapper
 * function of fgetwc() locks the stream.
 */
void
__fseterror_u(FILE *iop)
{
	iop->_flag |= _IOERR;
}

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

static mbstate_t	**__top_mbstates = NULL;
static mutex_t	__top_mbstates_lock = DEFAULTMUTEX;

void
_clear_internal_mbstate(void)
{
	int	i;

	lmutex_lock(&__top_mbstates_lock);
	if (__top_mbstates) {
		for (i = 0; i <= _MAX_MB_FUNC; i++) {
			if (*(__top_mbstates + i)) {
				lfree(*(__top_mbstates + i),
				    sizeof (mbstate_t));
			}
		}
		lfree(__top_mbstates,
		    (_MAX_MB_FUNC + 1) * sizeof (mbstate_t *));
		__top_mbstates = NULL;
	}
	lmutex_unlock(&__top_mbstates_lock);
}

mbstate_t *
_get_internal_mbstate(int item)
{
	if (item < 0 || item > _MAX_MB_FUNC)
		return (NULL);

	lmutex_lock(&__top_mbstates_lock);
	if (__top_mbstates == NULL) {
		__top_mbstates =
		    lmalloc((_MAX_MB_FUNC + 1) * sizeof (mbstate_t *));
		if (__top_mbstates == NULL) {
			lmutex_unlock(&__top_mbstates_lock);
			return (NULL);
		}
		*(__top_mbstates + item) = lmalloc(sizeof (mbstate_t));
		if (*(__top_mbstates + item) == NULL) {
			lmutex_unlock(&__top_mbstates_lock);
			return (NULL);
		}
		lmutex_unlock(&__top_mbstates_lock);
		return (*(__top_mbstates + item));
	}
	if (*(__top_mbstates + item) == NULL) {
		*(__top_mbstates + item) = lmalloc(sizeof (mbstate_t));
		if (*(__top_mbstates + item) == NULL) {
			lmutex_unlock(&__top_mbstates_lock);
			return (NULL);
		}
	}
	lmutex_unlock(&__top_mbstates_lock);
	return (*(__top_mbstates + item));
}

/*
 * From page 32 of XSH5
 * Once a wide-character I/O function has been applied
 * to a stream without orientation, the stream becomes
 * wide-orientated.  Similarly, once a byte I/O function
 * has been applied to a stream without orientation,
 * the stream becomes byte-orientated.  Only a call to
 * the freopen() function or the fwide() function can
 * otherwise alter the orientation of a stream.
 */

/*
 * void
 * _set_orientation_byte(FILE *iop)
 *
 * Note: this is now implemented as macro __SET_ORIENTATION_BYTE()
 *       (in libc/inc/mse.h) for performance improvement.
 */

/* Returns the value of 'ps->__nconsumed' */
char
__mbst_get_nconsumed(const mbstate_t *ps)
{
	return (ps->__nconsumed);
}

/* Sets 'n' to 'ps->__nconsumed' */
void
__mbst_set_nconsumed(mbstate_t *ps, char n)
{
	ps->__nconsumed = n;
}

/* Copies 'len' bytes from '&ps->__consumed[index]' to 'str' */
int
__mbst_get_consumed_array(const mbstate_t *ps, char *str,
	size_t index, size_t len)
{
	if ((index + len) > 8) {
		/* The max size of __consumed[] is 8 */
		return (-1);
	}
	(void) memcpy((void *)str, (const void *)&ps->__consumed[index], len);
	return (0);
}

/* Copies 'len' bytes from 'str' to '&ps->__consumed[index]' */
int
__mbst_set_consumed_array(mbstate_t *ps, const char *str,
	size_t index, size_t len)
{
	if ((index + len) > 8) {
		/* The max size of __consumed[] is 8 */
		return (-1);
	}
	(void) memcpy((void *)&ps->__consumed[index], (const void *)str, len);
	return (0);
}

/* Returns 'ps->__lc_locale' */
void *
__mbst_get_locale(const mbstate_t *ps)
{
	return (ps->__lc_locale);
}

/* Sets 'loc' to 'ps->__lc_locale' */
void
__mbst_set_locale(mbstate_t *ps, const void *loc)
{
	ps->__lc_locale = (void *)loc;
}
