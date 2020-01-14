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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MULTIMEDIA_AUDIOERROR_H
#define	_MULTIMEDIA_AUDIOERROR_H

#include <locale.h>
#include <errno.h>
#include <audio_errno.h>	/* to get enum for error codes */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif

#define	_MGET_(str)	(char *)dgettext(TEXT_DOMAIN, str)
#define	_GETTEXT_(str)	(char *)gettext(str)

// The AudioError class allows various interesting automatic conversions
class AudioError {
private:
	audioerror_t	code;			// error code

public:
	int		sys;			// system error code

	AudioError(const AudioError&) = default;
	inline AudioError(audioerror_t val = AUDIO_SUCCESS):	// Constructor
	    code(val), sys(0)
	    { if (code == AUDIO_UNIXERROR) sys = errno; }
	inline AudioError(int val):			// Constructor from int
	    code((audioerror_t)val), sys(0)
	    { if (code == AUDIO_UNIXERROR) sys = errno; }

	inline AudioError operator = (AudioError val)	// Assignment
	    { code = val.code; sys = val.sys; return (*this); }
	inline operator int()				// Cast to integer
	    { return (code); }
	inline int operator == (audioerror_t e)		// Compare
	    { return (code == e); }
	inline int operator != (audioerror_t e)		// Compare
	    { return (code != e); }
	inline int operator == (AudioError e)		// Compare
	    { return ((code == e.code) && (sys == e.sys)); }
	inline int operator != (AudioError e)		// Compare
	    { return ((code != e.code) || (sys != e.sys)); }

	char *msg();					// Return error string
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOERROR_H */
