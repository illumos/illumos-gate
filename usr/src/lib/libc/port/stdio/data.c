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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak __iob = _iob

#include "lint.h"
#include "mbstatet.h"
#include "mtlib.h"
#include "file64.h"
#include <stdio.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"
#include <wchar.h>

/*
 * Ptrs to start of preallocated buffers for stdin, stdout.
 * Some slop is allowed at the end of the buffers in case an upset in
 * the synchronization of _cnt and _ptr (caused by an interrupt or other
 * signal) is not immediately detected.
 */

Uchar _sibuf[BUFSIZ + _SMBFSZ], _sobuf[BUFSIZ + _SMBFSZ];
Uchar _smbuf[_NFILE + 1][_SMBFSZ] = {0};  /* shared library compatibility */


#define	DEFAULTMBSTATE \
	{ NULL, NULL, {0, 0, 0, 0, 0, 0, 0, 0}, 0, {0, 0}}

#ifdef	_LP64

#if _NFILE != 20
#error "_iob[] initialization impossible"
#endif

FILE _iob[_NFILE] = {
	{ NULL, NULL, NULL, 0, 0, _IOREAD, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 1, _IOWRT, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 2, _IOWRT|_IONBF, RECURSIVEMUTEX,
		DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE },
	{ NULL, NULL, NULL, 0, 0, 0, RECURSIVEMUTEX, DEFAULTMBSTATE }
};

#else

#if _NFILE != 20 && _NFILE != 60
#error "_iob[] initialization impossible"
#endif

/*
 * FILEs not in _iob will never reference this table, so we only need _NFILE
 * entries.
 */
struct xFILEdata _xftab[_NFILE] = {
	XFILEINITIALIZER, XFILEINITIALIZER,
	{ 0, _smbuf[2] + _SBFSIZ, RECURSIVEMUTEX, DEFAULTMBSTATE }, /* stderr */
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
#if _NFILE == 60
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
	XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER, XFILEINITIALIZER,
#endif
	XFILEINITIALIZER };

/*
 * Ptrs to end of read/write buffers for first _NFILE devices.
 * There is an extra bufend pointer which corresponds to the dummy
 * file number _NFILE, which is used by sscanf and sprintf.
 * Our implementation makes sure it never references _realbufend/_reallock/
 * etc for *sscanf() and *sprintf(); such use of a shared item would not be
 * thread safe.
 */
Uchar *_bufendtab[_NFILE+1] = { NULL, NULL, _smbuf[2] + _SBFSIZ, };

FILE _iob[_NFILE] = {
	{ 0, NULL, NULL, _IOREAD, 0 },
	{ 0, NULL, NULL, _IOWRT, 1 },
	{ 0, NULL, NULL, _IOWRT|_IONBF, 2 },
};

/*
 * Ptr to end of io control blocks
 */
FILE *_lastbuf = &_iob[_NFILE];

#endif	/*	_LP64	*/
