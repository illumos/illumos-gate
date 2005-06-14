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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_AUDIO_H
#define	_AUDIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Contains the audio files information for cdrw.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

typedef struct {
	char riff[4];
	uint32_t total_chunk_size;
	char wave[4];
	char fmt[4];
	uint32_t fmt_size;
	uint16_t fmt_tag;
	uint16_t n_channels;
	uint32_t sample_rate;
	uint32_t bytes_per_second;
	uint16_t align;
	uint16_t bits_per_sample;
	char data[4];
	uint32_t data_size;
} Wave_filehdr;


#define	PRE_DEF_WAV_HDR		{   'R', 'I', 'F', 'F', 0, 0, 0, 0, \
				    'W', 'A', 'V', 'E', 'f', 'm', 't', ' ', \
				    0x10, 0, 0, 0, 1, 0, 2, 0, \
				    0x44, 0xac, 0, 0, 0x10, 0xb1, 2, 0, \
				    4, 0, 0x10, 0, 'd', 'a', 't', 'a', \
				    0, 0, 0, 0 }
#define	PRE_DEF_WAV_HDR_LEN	44

#define	PRE_DEF_AU_HDR		{   '.', 's', 'n', 'd', 0, 0, 0, 0x28, \
				    0, 0, 0, 0, 0, 0, 0, 3, \
				    0, 0, 0xac, 0x44, 0, 0, 0, 2, \
				    0x43, 0x44, 0x20, 0x41, 0x75, 0x64, 0x69, \
				    0x6f, 0, 0, 0, 0, 0, 0, 0, 0 }
#define	PRE_DEF_AU_HDR_LEN	40

#ifdef	__cplusplus
}
#endif

#endif /* _AUDIO_H */
