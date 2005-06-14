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

#ifndef _MULTIMEDIA_LIBAUDIO_H
#define	_MULTIMEDIA_LIBAUDIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <audio_types.h>
#include <audio_hdr.h>
#include <audio_device.h>
#include <audio_errno.h>
#include <audio_encode.h>
#include <audio/au.h>
#include <aiff.h>
#include <wav.h>

#ifdef __cplusplus
extern "C" {
#endif

/* define various constants for general use */

/* Theoretical maximum length of hh:mm:ss.dd string */
#define	AUDIO_MAX_TIMEVAL	(32)

/* Theoretical maximum length of encoding information string */
#define	AUDIO_MAX_ENCODE_INFO	(80)


/* Why aren't these stupid values defined in a standard place?! */
#ifndef TRUE
#define	TRUE	(1)
#endif
#ifndef FALSE
#define	FALSE	(0)
#endif
#ifndef NULL
#define	NULL	0
#endif

/* Help for endian-ness */
#define	SWABI(I)							\
	I = (((I >> 24) & 0xff) | ((I & 0xff) << 24) |			\
	((I >> 8) & 0xff00) | ((I & 0xff00) << 8))

/* Defines for the audio file formats we support */
#define	FILE_ERROR	0
#define	FILE_AU		1
#define	FILE_WAV	2
#define	FILE_AIFF	3

/* Declare libaudio C routines */

/* File Header routines */
EXTERN_FUNCTION(int audio_write_filehdr, (int, Audio_hdr *, int, char *,
		    unsigned));
EXTERN_FUNCTION(int audio_rewrite_filesize, (int, int, unsigned,
		    unsigned, unsigned));
EXTERN_FUNCTION(int audio_read_filehdr, (int, Audio_hdr*, int *, char *,
		    unsigned));
EXTERN_FUNCTION(int audio_isaudiofile, (char *));
EXTERN_FUNCTION(int audio_decode_filehdr,
		    (int, unsigned char *, int *, Audio_hdr *, int *));

extern int audio_write_filehdr(int, Audio_hdr *, int, char *, unsigned);
extern int audio_rewrite_filesize(int, int, unsigned int, unsigned int,
	unsigned int);



/* Audio Header routines */
EXTERN_FUNCTION(double audio_bytes_to_secs, (Audio_hdr*, unsigned));
EXTERN_FUNCTION(unsigned audio_secs_to_bytes, (Audio_hdr*, double));
EXTERN_FUNCTION(double audio_str_to_secs, (char *));
EXTERN_FUNCTION(char *audio_secs_to_str, (double, char *, int));
EXTERN_FUNCTION(int audio_cmp_hdr, (Audio_hdr*, Audio_hdr *));
EXTERN_FUNCTION(int audio_enc_to_str, (Audio_hdr*, char *));


/* Device Control routines */
EXTERN_FUNCTION(int audio_getinfo, (int, Audio_info*));
EXTERN_FUNCTION(int audio_setinfo, (int, Audio_info*));
EXTERN_FUNCTION(int audio__setplayhdr, (int, Audio_hdr *, unsigned));
EXTERN_FUNCTION(int audio__setval, (int, unsigned *, unsigned));
EXTERN_FUNCTION(int audio__setgain, (int, double *, unsigned));
EXTERN_FUNCTION(int audio__setpause, (int, unsigned));
EXTERN_FUNCTION(int audio__flush, (int, unsigned int));
EXTERN_FUNCTION(int audio_drain, (int, int));
EXTERN_FUNCTION(int audio_play_eof, (int));

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_LIBAUDIO_H */
