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

/*
 * The intent here is to provide a means to make the order of
 * bytes in an io-stream correspond to the order of the bytes
 * in the memory while doing the io a `word' at a time.
 */

#pragma weak _putw = putw

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include <stdio.h>
#include <thread.h>
#include <synch.h>
#include "stdiom.h"

int
putw(int w, FILE *stream)
{
	char *s = (char *)&w;
	int i = sizeof (int);
	int ret;
	rmutex_t *lk;

	FLOCKFILE(lk, stream);
	while (--i >= 0 && putc_unlocked(*s++, stream) != EOF)
		;
	ret = stream->_flag & _IOERR;
	FUNLOCKFILE(lk);
	return (ret);
}
