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
 * Copyright 1992-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MULTIMEDIA_AUDIO_ERRNO_H
#define	_MULTIMEDIA_AUDIO_ERRNO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * libaudio error codes
 */

/* XXX - error returns and exception handling need to be worked out */
enum audioerror_t {
	AUDIO_SUCCESS = 0,		/* no error */
	AUDIO_NOERROR = -2,		/* no error, no message */
	AUDIO_UNIXERROR = -1,		/* check errno for error code */
	AUDIO_ERR_BADHDR = 1,		/* bad audio header structure */
	AUDIO_ERR_BADFILEHDR = 2,	/* bad file header format */
	AUDIO_ERR_BADARG = 3,		/* bad subroutine argument */
	AUDIO_ERR_NOEFFECT = 4,		/* device control ignored */
	AUDIO_ERR_ENCODING = 5,		/* unknown encoding format */
	AUDIO_ERR_INTERRUPTED = 6,	/* operation was interrupted */
	AUDIO_EOF = 7,			/* end-of-file */
	AUDIO_ERR_HDRINVAL = 8,		/* unsupported data format */
	AUDIO_ERR_PRECISION = 9,	/* unsupported data precision */
	AUDIO_ERR_NOTDEVICE = 10,	/* not an audio device */
	AUDIO_ERR_DEVICEBUSY = 11,	/* audio device is busy */
	AUDIO_ERR_BADFRAME = 12,	/* partial sample frame */
	AUDIO_ERR_FORMATLOCK = 13,	/* audio format cannot be changed */
	AUDIO_ERR_DEVOVERFLOW = 14,	/* device overflow error */
	AUDIO_ERR_BADFILETYPE = 15	/* bad audio header type */
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIO_ERRNO_H */
