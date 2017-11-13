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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 RackTop Systems.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/log.h>

#include <fakekernel.h>

void	abort(void) __NORETURN;

char *volatile panicstr;
va_list  panicargs;
char panicbuf[512];

volatile int aok;

static const int
ce_flags[CE_IGNORE] = { SL_NOTE, SL_NOTE, SL_WARN, SL_FATAL };
static const char
ce_prefix[CE_IGNORE][10] = { "", "NOTICE: ", "WARNING: ", "" };
static const char
ce_suffix[CE_IGNORE][2] = { "", "\n", "\n", "" };


/*
 * This function is just a stub, exported NODIRECT so that
 * comsumers like fksmbd can provide their own.
 * (One that actually prints the messages.)
 *
 * It's used by fakekernel_cprintf() below.
 * The flags are SL_... from strlog.h
 */
/* ARGSUSED */
void
fakekernel_putlog(char *msg, size_t len, int flags)
{
}

/*
 * fakekernel_cprintf() corresponds to os/printf.c:cprintf()
 * This formats the message and calls fakekernel_putlog().
 * It's exported NODIRECT to allow replacment.
 * The flags are SL_... from strlog.h
 */
void
fakekernel_cprintf(const char *fmt, va_list adx, int flags,
    const char *prefix, const char *suffix)
{
	size_t bufsize = LOG_MSGSIZE;
	char buf[LOG_MSGSIZE];
	char *bufp = buf;
	char *msgp, *bufend;
	size_t len;

	if (strchr("^!?", fmt[0]) != NULL) {
		if (fmt[0] == '^')
			flags |= SL_CONSONLY;
		else if (fmt[0] == '!')
			flags |= SL_LOGONLY;
		fmt++;
	}

	bufend = bufp + bufsize;
	msgp = bufp;
	msgp += snprintf(msgp, bufend - msgp, "[fake_kernel] ");
	msgp += snprintf(msgp, bufend - msgp, prefix);
	msgp += vsnprintf(msgp, bufend - msgp, fmt, adx);
	msgp += snprintf(msgp, bufend - msgp, suffix);
	len = msgp - bufp;

	fakekernel_putlog(bufp, len, flags);
}

/*
 * "User-level crash dump", if you will.
 */
void
vpanic(const char *fmt, va_list adx)
{
	va_list tmpargs;

	panicstr = (char *)fmt;
	va_copy(panicargs, adx);

	va_copy(tmpargs, adx);
	fakekernel_cprintf(fmt, tmpargs, SL_FATAL, "fatal: ", "\n");

	/* Call libc`assfail() so that mdb ::status works */
	(void) vsnprintf(panicbuf, sizeof (panicbuf), fmt, adx);
	assfail(panicbuf, "(panic)", 0);

	abort();	/* avoid "noreturn" warnings */
}

void
panic(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vpanic(fmt, adx);
	va_end(adx);
}

void
fm_panic(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vpanic(fmt, adx);
	va_end(adx);
}

void
vcmn_err(int ce, const char *fmt, va_list adx)
{

	if (ce == CE_PANIC)
		vpanic(fmt, adx);
	if (ce >= CE_IGNORE)
		return;

	fakekernel_cprintf(fmt, adx, ce_flags[ce] | SL_CONSOLE,
	    ce_prefix[ce], ce_suffix[ce]);
}

/*PRINTFLIKE2*/
void
cmn_err(int ce, const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vcmn_err(ce, fmt, adx);
	va_end(adx);
}
