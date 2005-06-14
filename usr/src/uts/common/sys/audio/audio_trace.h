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

/*
 * This header file defines the public interfaces for audio tracing.
 *
 * CAUTION: This header file has not gone through a formal review process.
 *	Thus its commitment level is very low and may change or be removed
 *	at any time.
 */

#ifndef	_SYS_AUDIO_TRACE_H
#define	_SYS_AUDIO_TRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Trace declarations and defines.
 */

struct audio_trace_buf {
	uint_t		atb_seq;	/* trace sequence number */
	char		*atb_comment;	/* trace comment string */
	uintptr_t	atb_data;	/* data to go with string */
};
typedef struct audio_trace_buf audio_trace_buf_t;

#define	AUDIO_TRACE_BUFFER_SIZE		1024

#ifdef DEBUG

#ifndef __lock_lint
extern audio_trace_buf_t audio_trace_buffer[AUDIO_TRACE_BUFFER_SIZE];
extern kmutex_t audio_tb_lock;	/* global trace buffer lock */
extern size_t audio_tb_siz;
extern int audio_tb_pos;
extern uint_t audio_tb_seq;

_NOTE(MUTEX_PROTECTS_DATA(audio_tb_lock, audio_tb_pos))
_NOTE(MUTEX_PROTECTS_DATA(audio_tb_lock, audio_tb_seq))
_NOTE(MUTEX_PROTECTS_DATA(audio_tb_lock, audio_trace_buffer))

#define	ATRACE(M, D) {							\
	mutex_enter(&audio_tb_lock);					\
	audio_trace_buffer[audio_tb_pos].atb_seq = audio_tb_seq++;	\
	audio_trace_buffer[audio_tb_pos].atb_comment = (M);		\
	audio_trace_buffer[audio_tb_pos++].atb_data = (uintptr_t)(D);	\
	if (audio_tb_pos >= audio_tb_siz)				\
		audio_tb_pos = 0;					\
	mutex_exit(&audio_tb_lock);					\
	}

#define	ATRACE_64(M, D)		ATRACE(M, D)

#define	ATRACE_32(M, D) {						\
	mutex_enter(&audio_tb_lock);					\
	audio_trace_buffer[audio_tb_pos].atb_seq = audio_tb_seq++;	\
	audio_trace_buffer[audio_tb_pos].atb_comment = (M);		\
	audio_trace_buffer[audio_tb_pos++].atb_data = 			\
	    (uintptr_t)(uint32_t)(D);					\
	if (audio_tb_pos >= audio_tb_siz)				\
		audio_tb_pos = 0;					\
	mutex_exit(&audio_tb_lock);					\
	}

#define	ATRACE_16(M, D) {						\
	mutex_enter(&audio_tb_lock);					\
	audio_trace_buffer[audio_tb_pos].atb_seq = audio_tb_seq++;	\
	audio_trace_buffer[audio_tb_pos].atb_comment = (M);		\
	audio_trace_buffer[audio_tb_pos++].atb_data =			\
	    (uintptr_t)(uint16_t)(D);					\
	if (audio_tb_pos >= audio_tb_siz)				\
		audio_tb_pos = 0;					\
	mutex_exit(&audio_tb_lock);					\
	}

#define	ATRACE_8(M, D) {						\
	mutex_enter(&audio_tb_lock);					\
	audio_trace_buffer[audio_tb_pos].atb_seq = audio_tb_seq++;	\
	audio_trace_buffer[audio_tb_pos].atb_comment = (M);		\
	audio_trace_buffer[audio_tb_pos++].atb_data =			\
	    (uintptr_t)(uint8_t)(D);					\
	if (audio_tb_pos >= audio_tb_siz)				\
		audio_tb_pos = 0;					\
	mutex_exit(&audio_tb_lock);					\
	}
#else

#define	ATRACE(M, D)
#define	ATRACE_32(M, D)
#define	ATRACE_16(M, D)
#define	ATRACE_8(M, D)

#endif

#else	/* DEBUG */

#define	ATRACE(M, D)
#define	ATRACE_32(M, D)
#define	ATRACE_16(M, D)
#define	ATRACE_8(M, D)

#endif	/* DEBUG */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_TRACE_H */
