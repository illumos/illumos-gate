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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <AudioError.h>


// class Audio methods

// Convert error code to string
char *AudioError::
msg()
{
	if (code == AUDIO_NOERROR)
		return (char *)("");
	if (code == AUDIO_UNIXERROR) {
		if (sys == 0) {
			sys = errno;
		}
		if (sys >= 0) {
			return (strerror(sys));
		} else {
			return (_MGET_("Unknown UNIX error"));
		}
	}

	// XXX - these must jive with what's in audio_errno.h
	switch (code) {
	case 0:				/* AUDIO_SUCCESS = 0 */
		return (_MGET_("Audio operation successful"));
	case 1:				/* AUDIO_ERR_BADHDR = 1 */
		return (_MGET_("Invalid audio header"));
	case 2:				/* AUDIO_ERR_BADFILEHDR = 2 */
		return (_MGET_("Invalid audio file header"));
	case 3:				/* AUDIO_ERR_BADARG = 3 */
		return (_MGET_("Invalid argument or value"));
	case 4:				/* AUDIO_ERR_NOEFFECT = 4 */
		return (_MGET_("Audio operation not performed"));
	case 5:				/* AUDIO_ERR_ENCODING = 5 */
		return (_MGET_("Unknown audio encoding format"));
	case 6:				/* AUDIO_ERR_INTERRUPTED = 6 */
		return (_MGET_("Audio operation interrupted"));
	case 7:				/* AUDIO_EOF = 7 */
		return (_MGET_("Audio end-of-file"));
	case 8:				/* AUDIO_ERR_HDRINVAL = 8 */
		return (_MGET_("Unsupported audio data format"));
	case 9:				/* AUDIO_ERR_PRECISION = 9 */
		return (_MGET_("Unsupported audio data precision"));
	case 10:			/* AUDIO_ERR_NOTDEVICE = 10 */
		return (_MGET_("Not an audio device"));
	case 11:			/* AUDIO_ERR_DEVICEBUSY = 11 */
		return (_MGET_("Audio device is busy"));
	case 12:			/* AUDIO_ERR_BADFRAME = 12 */
		return (_MGET_("Partial sample frame"));
	case 13:			/* AUDIO_ERR_FORMATLOCK = 13 */
		return (_MGET_("Audio format cannot be changed"));
	case 14:			/* AUDIO_ERR_DEVOVERFLOW = 14 */
		return (_MGET_("Audio device overrun"));
	default:
		return (_MGET_("Unknown audio error"));
	}
}
