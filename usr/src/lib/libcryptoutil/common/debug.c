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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <cryptoutil.h>

#define	CRYPTO_DEBUG_ENV	"SUNW_CRYPTO_DEBUG"

static char *_cryptodebug_prefix = NULL;
static int _cryptodebug_enabled = -1; /* -1 unknown, 0 disabled, 1 enabled */
static int _cryptoerror_enabled = 1; /* 0 disabled, 1 enabled */
static boolean_t _cryptodebug_syslog = B_TRUE;

/*PRINTFLIKE1*/
void
cryptodebug(const char *fmt, ...)
{
	va_list args;
	char fmtbuf[BUFSIZ];
	char msgbuf[BUFSIZ];

	if (fmt == NULL || _cryptodebug_enabled != 1)
		return;

	va_start(args, fmt);
	if (_cryptodebug_prefix == NULL) {
		(void) vsnprintf(msgbuf, sizeof (msgbuf), fmt, args);
	} else {
		(void) snprintf(fmtbuf, sizeof (fmtbuf), "%s: %s",
		    _cryptodebug_prefix, fmt);
		(void) vsnprintf(msgbuf, sizeof (msgbuf), fmtbuf, args);
	}

	if (_cryptodebug_syslog) {
		syslog(LOG_DEBUG, msgbuf);
	} else {
		(void) fprintf(stderr, "%s\n", msgbuf);
	}
	va_end(args);
}

/*
 * cryptoerror
 *
 * This is intended to be used both by interactive commands like cryptoadm(8)
 * digest(1) etc, and by libraries libpkcs11, libelfsign etc.
 *
 * A library probably wants most (all?) of its errors going to syslog but
 * commands are usually happy for them to go to stderr.
 *
 * If a syslog priority is passed we log on that priority.  Otherwise we
 * use LOG_STDERR to mean use stderr instead. LOG_STDERR is defined in
 * cryptoutil.h
 */

/*PRINTFLIKE2*/
void
cryptoerror(int priority, const char *fmt, ...)
{
	char fmtbuf[BUFSIZ];
	char msgbuf[BUFSIZ];
	va_list args;

	if (fmt == NULL || _cryptoerror_enabled == 0)
		return;

	va_start(args, fmt);
	if (_cryptodebug_prefix == NULL) {
		(void) vsnprintf(msgbuf, sizeof (msgbuf), fmt, args);
	} else {
		(void) snprintf(fmtbuf, sizeof (fmtbuf), "%s: %s",
		    _cryptodebug_prefix, fmt);
		(void) vsnprintf(msgbuf, sizeof (msgbuf), fmtbuf, args);
	}

	if ((priority == LOG_STDERR) || (priority < 0))  {
		(void) fprintf(stderr, "%s\n", msgbuf);
	} else {
		syslog(priority, msgbuf);
	}
	va_end(args);
}

void
cryptoerror_off()
{
	_cryptoerror_enabled = 0;
}

void
cryptoerror_on()
{
	_cryptoerror_enabled = 1;
}

void
cryptodebug_init(const char *prefix)
{
	char *envval = NULL;

	if (prefix != NULL) {
		_cryptodebug_prefix = strdup(prefix);
	}

	if (_cryptodebug_enabled == -1) {
		envval = getenv(CRYPTO_DEBUG_ENV);
		/*
		 * If unset or it isn't one of syslog or stderr
		 * disable debug.
		 */
		if (envval == NULL || (strcmp(envval, "") == 0)) {
			_cryptodebug_enabled = 0;
			return;
		} else if (strcmp(envval, "stderr") == 0) {
			_cryptodebug_syslog = B_FALSE;
			_cryptodebug_enabled = 1;
		} else if (strcmp(envval, "syslog") == 0) {
			_cryptodebug_syslog = B_TRUE;
			_cryptodebug_enabled = 1;
		}
	}

	openlog(_cryptodebug_prefix, LOG_PID, LOG_USER);
}

#pragma fini(_cryptodebug_fini)

static void
_cryptodebug_fini(void)
{
	if (_cryptodebug_prefix != NULL)
		free(_cryptodebug_prefix);
}
