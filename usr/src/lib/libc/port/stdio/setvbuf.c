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
/*	  All Rights Reserved	*/

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"

int
setvbuf(FILE *iop, char *abuf, int type, size_t size)
{

	Uchar	*buf = (Uchar *)abuf;
	Uchar *temp;
	int	sflag = iop->_flag & _IOMYBUF;
	rmutex_t *lk;
	int fd = _get_fd(iop);

	FLOCKFILE(lk, iop);
	iop->_flag &= ~(_IOMYBUF | _IONBF | _IOLBF);
	switch (type) {
	/* note that the flags are the same as the possible values for type */
	case _IONBF:
		iop->_flag |= _IONBF;	 /* file is unbuffered */
		if (fd == 0 || fd == 1) {
			/* use special buffer for std{in,out} */
			buf = (fd == 0) ? _sibuf : _sobuf;
			size = BUFSIZ;
		} else if (fd >= 2 && fd < _NFILE) {
			buf = _smbuf[fd];
			size = _SMBFSZ - PUSHBACK;
		} else {
			if ((buf = malloc(_SMBFSZ * sizeof (Uchar))) != NULL) {
				iop->_flag |= _IOMYBUF;
				size = _SMBFSZ - PUSHBACK;
			} else {
				FUNLOCKFILE(lk);
				return (EOF);
			}
		}
		break;
	case _IOLBF:
	case _IOFBF:
		iop->_flag |= type;	/* buffer file */
		/*
		 * need at least an 8 character buffer for
		 * out_of_sync concerns.
		 */
		if (size <= _SMBFSZ) {
			size = BUFSIZ;
			buf = NULL;
		}
		if (buf == NULL) {
			if ((buf = malloc(sizeof (Uchar) *
			    (size + _SMBFSZ))) != NULL)
				iop->_flag |= _IOMYBUF;
			else {
				FUNLOCKFILE(lk);
				return (EOF);
			}
		}
		else
			size -= _SMBFSZ;
		break;
	default:
		FUNLOCKFILE(lk);
		return (EOF);
	}
	if (iop->_base != NULL && sflag)
		free((char *)iop->_base - PUSHBACK);
	temp = buf + PUSHBACK;
	iop->_base = temp;
	_setbufend(iop, temp + size);
	iop->_ptr = temp;
	iop->_cnt = 0;
	FUNLOCKFILE(lk);
	return (0);
}
