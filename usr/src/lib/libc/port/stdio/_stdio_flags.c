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

/* Copyright (c) 2013 OmniTI Computer Consulting, Inc. All rights reserved. */
/*
 * Copyright 2020 Robert Mustacchi
 */

/*
 * Commonized processing of the 'mode' string for stdio.
 */

#include "mtlib.h"
#include "file64.h"
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

int
_stdio_flags(const char *type, int *oflagsp, int *fflagsp)
{
	int oflag, fflag, plusflag, eflag, xflag;
	const char *echr;

	oflag = fflag = 0;
	switch (type[0]) {
	default:
		errno = EINVAL;
		return (-1);
	case 'r':
		oflag = O_RDONLY;
		fflag = _IOREAD;
		break;
	case 'w':
		oflag = O_WRONLY | O_TRUNC | O_CREAT;
		fflag = _IOWRT;
		break;
	case 'a':
		oflag = O_WRONLY | O_APPEND | O_CREAT;
		fflag = _IOWRT;
		break;
	}

	plusflag = 0;
	eflag = 0;
	xflag = 0;
	for (echr = type + 1; *echr != '\0'; echr++) {
		switch (*echr) {
		/* UNIX ignores 'b' and treats text and binary the same */
		default:
			break;
		case '+':
			plusflag = 1;
			break;
		case 'e':
			eflag = 1;
			break;
		case 'x':
			xflag = 1;
			break;
		}
	}

	if (eflag) {
		/* Subsequent to a mode flag, 'e' indicates O_CLOEXEC */
		oflag = oflag | O_CLOEXEC;
	}

	if (plusflag) {
		oflag = (oflag & ~(O_RDONLY | O_WRONLY)) | O_RDWR;
		fflag = _IORW;
	}

	if (xflag) {
		oflag |= O_EXCL;
	}

	*oflagsp = oflag;
	*fflagsp = fflag;

	return (0);
}
