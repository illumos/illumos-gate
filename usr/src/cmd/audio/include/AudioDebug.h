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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MULTIMEDIA_AUDIODEBUG_H
#define	_MULTIMEDIA_AUDIODEBUG_H

#include <audio_types.h>
#include <Audio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Declare default message printing routine
Boolean AudioStderrMsg(const Audio *, AudioError, AudioSeverity, const char *);


#ifdef DEBUG
EXTERN_FUNCTION(void AudioDebugMsg, (int, char *fmt, DOTDOTDOT));
#endif

EXTERN_FUNCTION(void SetDebug, (int));
EXTERN_FUNCTION(int GetDebug, ());

#ifdef DEBUG
#define	AUDIO_DEBUG(args)    AudioDebugMsg args
#else
#define	AUDIO_DEBUG(args)
#endif /* !DEBUG */

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIODEBUG_H */
