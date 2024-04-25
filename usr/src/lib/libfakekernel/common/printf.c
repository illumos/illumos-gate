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
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2022 RackTop Systems, Inc.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/log.h>
#include <upanic.h>

#include <fakekernel.h>

void	debug_enter(char *);

char *volatile panicstr;
va_list  panicargs;
char panicbuf[512];

int aok;

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

/* ARGSUSED */
void
vzprintf(zoneid_t zoneid, const char *fmt, va_list adx)
{
	fakekernel_cprintf(fmt, adx, SL_CONSOLE | SL_NOTE, "", "");
}

/*PRINTFLIKE2*/
void
zprintf(zoneid_t zoneid, const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vzprintf(zoneid, fmt, adx);
	va_end(adx);
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

	(void) vsnprintf(panicbuf, sizeof (panicbuf), fmt, adx);
	debug_enter(panicbuf);

	/* Call libc`upanic() so that mdb ::status works */
	upanic(panicbuf, sizeof (panicbuf));
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

/* ARGSUSED */
void
debug_enter(char *str)
{
	/* Just a place for a break point. */
}

void
assfail(const char *a, const char *f, int l)
{
	if (!aok)
		panic("assertion failed: %s, file: %s, line: %d", a, f, l);

	fprintf(stderr, "ASSERTION CAUGHT: %s, file: %s, line: %d\n", a, f, l);
}

void
assfail3(const char *a, uintmax_t lv, const char *op, uintmax_t rv,
    const char *f, int l)
{
	if (!aok) {
		panic("assertion failed: %s (0x%llx %s 0x%llx), file: %s, "
		    "line: %d", a, (u_longlong_t)lv, op, (u_longlong_t)rv,
		    f, l);
	}

	fprintf(stderr, "ASSERTION CAUGHT: %s (0x%llx %s 0x%llx), file: %s, "
	    "line: %d\n", a, (u_longlong_t)lv, op, (u_longlong_t)rv,
	    f, l);
}
