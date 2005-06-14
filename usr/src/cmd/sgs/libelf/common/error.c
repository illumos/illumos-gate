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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 	/* SVr4.0 1.16	*/


#pragma weak	elf_errmsg = _elf_errmsg
#pragma weak	elf_errno = _elf_errno

#include	"syn.h"
#include	<thread.h>
#include	<stdlib.h>
#include	<string.h>
#include	<stdio.h>
#include	<libelf.h>
#include	"msg.h"
#include	"decl.h"

#define	ELFERRSHIFT	16
#define	SYSERRMASK	0xffff


/*
 * _elf_err has two values encoded in it, both the _elf_err # and
 * the system errno value (if relevant).  These values are encoded
 * in the upper & lower 16 bits of the 4 byte integer.
 */
static int		_elf_err = 0;

static mutex_t		keylock;
static mutex_t		buflock;
static thread_key_t	errkey;
static thread_key_t	bufkey;
static int		keyonce = 0;
static int		bufonce = 0;
NOTE(DATA_READABLE_WITHOUT_LOCK(keyonce))
NOTE(DATA_READABLE_WITHOUT_LOCK(bufonce))


extern char *_dgettext(const char *, const char *);


const char *
_libelf_msg(Msg mid)
{
	return (_dgettext(MSG_ORIG(MSG_SUNW_OST_SGS), MSG_ORIG(mid)));
}


void
_elf_seterr(Msg lib_err, int sys_err)
{
	/*LINTED*/
	intptr_t encerr = ((int)lib_err << ELFERRSHIFT) |
	    (sys_err & SYSERRMASK);

#ifndef	__lock_lint
	if (thr_main()) {
		_elf_err = (int)encerr;
		return;
	}
#endif
	if (keyonce == 0) {
		(void) mutex_lock(&keylock);
		if (keyonce == 0) {
			(void) thr_keycreate(&errkey, 0);
			keyonce++;
		}
		(void) mutex_unlock(&keylock);
	}

	(void) thr_setspecific(errkey, (void *)encerr);
}

int
_elf_geterr() {
	intptr_t	rc;

#ifndef	__lock_lint
	if (thr_main())
		return (_elf_err);
#endif
	if (keyonce == 0)
		return (0);

	(void) thr_getspecific(errkey, (void **)(&rc));
	return ((int)rc);
}

const char *
elf_errmsg(int err)
{
	char			*errno_str;
	char			*elferr_str;
	char			*buffer = 0;
	int			syserr;
	int			elferr;
	static char		intbuf[MAXELFERR];

	if (err == 0) {
		if ((err = _elf_geterr()) == 0)
			return (0);
	} else if (err == -1) {
		if ((err = _elf_geterr()) == 0)
			/*LINTED*/ /* MSG_INTL(EINF_NULLERROR) */
			err = (int)EINF_NULLERROR << ELFERRSHIFT;
	}

	if (thr_main())
		buffer = intbuf;
	else {
		/*
		 * If this is a threaded APP then we store the
		 * errmsg buffer in Thread Specific Storage.
		 *
		 * Each thread has its own private buffer.
		 */
		if (bufonce == 0) {
			(void) mutex_lock(&buflock);
			if (bufonce == 0) {
				if (thr_keycreate(&bufkey, free) != 0) {
					(void) mutex_unlock(&buflock);
					return (MSG_INTL(EBUG_THRDKEY));
				}
				bufonce++;
			}
			(void) mutex_unlock(&buflock);
		}

		(void) thr_getspecific(bufkey, (void **)&buffer);

		if (!buffer) {
			if ((buffer = malloc(MAXELFERR)) == 0)
				return (MSG_INTL(EMEM_ERRMSG));
			if (thr_setspecific(bufkey, buffer) != 0) {
				free(buffer);
				return (MSG_INTL(EBUG_THRDSET));
			}
		}
	}

	elferr = (int)((uint_t)err >> ELFERRSHIFT);
	syserr = err & SYSERRMASK;
	/*LINTED*/
	elferr_str = (char *)MSG_INTL(elferr);
	if (syserr && (errno_str = strerror(syserr)))
		(void) snprintf(buffer, MAXELFERR,
		    MSG_ORIG(MSG_FMT_ERR), elferr_str, errno_str);
	else {
		(void) strncpy(buffer, elferr_str, MAXELFERR - 1);
		buffer[MAXELFERR - 1] = '\0';
	}

	return (buffer);
}

int
elf_errno()
{
	int	rc = _elf_geterr();

	_elf_seterr(0, 0);
	return (rc);
}
