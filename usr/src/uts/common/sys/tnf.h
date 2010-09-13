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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 *	All rights reserved.
 */

#ifndef _SYS_TNF_H
#define	_SYS_TNF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef NPROBE

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *
 */

typedef struct {
	ulong_t probenum;
	int enabled;
	int traced;
	int attrsize;
} tnf_probevals_t;

/*
 *
 */

typedef struct {
	enum {
		TIFIOCBUF_NONE,
		TIFIOCBUF_UNINIT,
		TIFIOCBUF_OK,
		TIFIOCBUF_BROKEN
		} buffer_state;
	int buffer_size;
	int trace_stopped;
	int pidfilter_mode;
	int pidfilter_size;
} tifiocstate_t;

typedef struct {
	char *dst_addr;
	int block_num;
} tifiocgblock_t;

typedef struct {
	long *dst_addr;
	int start;
	int slots;
} tifiocgfw_t;

/*
 * ioctl codes
 */

#define	TIFIOCGMAXPROBE		(('t' << 8) | 1) /* get max probe number */
#define	TIFIOCGPROBEVALS	(('t' << 8) | 2) /* get probe info */
#define	TIFIOCGPROBESTRING	(('t' << 8) | 3) /* get probe string */
#define	TIFIOCSPROBEVALS	(('t' << 8) | 4) /* set probe info */
#define	TIFIOCGSTATE		(('t' << 8) | 5) /* get tracing system state */
#define	TIFIOCALLOCBUF		(('t' << 8) | 6) /* allocate trace buffer */
#define	TIFIOCDEALLOCBUF	(('t' << 8) | 7) /* dealloc trace buffer */
#define	TIFIOCSTRACING		(('t' << 8) | 8) /* set ktrace mode */
#define	TIFIOCSPIDFILTER	(('t' << 8) | 9) /* set pidfilter mode */
#define	TIFIOCGPIDSTATE		(('t' << 8) | 10) /* check pid filter member */
#define	TIFIOCSPIDON		(('t' << 8) | 11) /* add pid to filter */
#define	TIFIOCSPIDOFF		(('t' << 8) | 12) /* drop pid from filter */
#define	TIFIOCPIDFILTERGET	(('t' << 8) | 13) /* return pid filter set */
#define	TIFIOCGHEADER		(('t' << 8) | 14) /* copy out tnf header blk */
#define	TIFIOCGBLOCK		(('t' << 8) | 15) /* copy out tnf block */
#define	TIFIOCGFWZONE		(('t' << 8) | 16) /* copy out forwarding ptrs */

#ifdef _KERNEL

extern volatile int tnf_tracing_active;

extern void tnf_thread_create(kthread_t *);
extern void tnf_thread_queue(kthread_t *, cpu_t *, pri_t);
extern void tnf_thread_switch(kthread_t *);
extern void tnf_thread_exit(void);
extern void tnf_thread_free(kthread_t *);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* NPROBE */

#endif /* _SYS_TNF_H */
