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

#ifndef _AUDIOCONVERT_CONVERT_H
#define	_AUDIOCONVERT_CONVERT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <audio_i18n.h>
#include <Audio.h>
#include <AudioUnixfile.h>
#include <AudioBuffer.h>
#include <AudioTypeConvert.h>

#include <parse.h>

#ifdef __cplusplus
extern "C" {
#endif

// for localizing strings
#define	MGET(str)	(char *)gettext(str)

extern int		Statistics;		// report timing statistics
extern int		Debug;			// Debug flag

extern AudioBuffer*	create_buffer(Audio*);
extern void		get_realfile(char *&, struct stat *);
extern AudioUnixfile*	open_input_file(const char *, const AudioHdr,
			    int, int, off_t, format_type&);
extern AudioUnixfile*	create_output_file(const char *, const AudioHdr,
			    format_type, const char *infoString);
extern int		verify_conversion(AudioHdr, AudioHdr);
extern int		do_convert(AudioStream*, AudioStream*);
extern AudioError	write_output(AudioBuffer*, AudioStream*);
extern int		noop_conversion(AudioHdr, AudioHdr,
			    format_type, format_type, off_t, off_t);
extern void		Err(char *, ...);

#ifdef __cplusplus
}
#endif

#endif /* !_AUDIOCONVERT_CONVERT_H */
