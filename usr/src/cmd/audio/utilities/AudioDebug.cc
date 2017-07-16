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
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

// XXX - all this either goes away or gets repackaged
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <AudioDebug.h>

// Global debugging level variable
int	Audio_debug;


// Get debug level
int
GetDebug()
{
	return (Audio_debug);
}

// Set debug level
void
SetDebug(
	int	val)			// new level
{
	Audio_debug = val;
}

// Default error printing routine
Boolean
AudioStderrMsg(
	const Audio*	cp,		// object pointer
	AudioError	code,		// error code
	AudioSeverity	sev,		// error severity
	const char	*str)		// additional message string
{
	int		id;
	char		*name;

	id = cp->getid();
	switch (sev) {
	default:
		name = cp->GetName();
		break;
	case InitMessage:		// virtual function table not ready
	case InitFatal:
		name = cp->Audio::GetName();
		break;
	}

	switch (sev) {
	case InitMessage:
	case Message:
		if (Audio_debug > 1)
			(void) fprintf(stderr, _MGET_("%d: %s (%s) %s\n"),
			    id, str, name, code.msg());
		return (TRUE);
	case Warning:
		(void) fprintf(stderr, _MGET_("Warning: %s: %s %s\n"),
		    name, code.msg(), str);
		if (Audio_debug > 2)
			abort();
		return (TRUE);
	case Error:
		(void) fprintf(stderr, _MGET_("Error: %s: %s %s\n"),
		    name, code.msg(), str);
		if (Audio_debug > 1)
			abort();
		return (FALSE);
	case Consistency:
		(void) fprintf(stderr,
		    _MGET_("Audio Consistency Error: %s: %s %s\n"),
		    name, str, code.msg());
		if (Audio_debug > 0)
			abort();
		return (FALSE);
	case InitFatal:
	case Fatal:
		(void) fprintf(stderr,
		    _MGET_("Audio Internal Error: %s: %s %s\n"),
		    name, str, code.msg());
		if (Audio_debug > 0)
			abort();
		return (FALSE);
	}
	return (TRUE);
}

#ifdef DEBUG
void
AudioDebugMsg(
	int	level,
	char	*fmt,
		...)
{
	va_list ap;

	if (Audio_debug >= level) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}
#endif
