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
 * Copyright 2015 Joyent, Inc.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include "lint.h"
#include "_libc_gettext.h"
#include <string.h>
#include <sys/types.h>
#include <errno.h>

extern const char _sys_errs[];
extern const int _sys_index[];
extern int _sys_num_err;

char *
strerror_l(int errnum, locale_t loc)
{
	if (errnum < _sys_num_err && errnum >= 0)
		return (_libc_gettext_l(&_sys_errs[_sys_index[errnum]],
		    loc));

	errno = EINVAL;
	return (_libc_gettext_l("Unknown error", loc));
}

char *
strerror(int errnum)
{
	return (strerror_l(errnum, uselocale(NULL)));
}

/*
 * Implemented strerror_r in Solaris 10 to comply with SUSv3 2001.
 */
int
strerror_r(int errnum, char *strerrbuf, size_t buflen)
{
	char *buf;
	int ret = 0;

	if (errnum < _sys_num_err && errnum >= 0) {
		buf = _libc_gettext((char *)&_sys_errs[_sys_index[errnum]]);
	} else {
		buf = _libc_gettext("Unknown error");
		ret = errno = EINVAL;
	}

	/*
	 * At compile time, there is no way to determine the max size of
	 * language-dependent error message.
	 */
	if (buflen < (strlen(buf) + 1)) {
		ret = errno = ERANGE;
	} else {
		(void) strcpy(strerrbuf, buf);
	}

	return (ret);
}
