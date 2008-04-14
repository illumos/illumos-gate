/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FPSAPI_H
#define	_FPSAPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FPS structures and constants.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include  <sys/types.h>

#define	FPS_DOOR_FILE	"/var/run/fpsdiagd_door"

/* Message types and associated priorities */
#define	FPS_ERROR	0	/* Goes to syslog(LOG_ERR) */
#define	FPS_WARNING	1	/* Goes to syslog(LOG_WARNING) */
#define	FPS_INFO	2	/* Goes to syslog(LOG_INFO) */
#define	FPS_DEBUG	3	/* Goes to syslog(LOG_DEBUG) */

/* Max Limits */

/* FP-test return codes */

#define	FPU_UNSUPPORT	-1
#define	FPU_OK	0 /* All tests passed */
/* Failed a test, FPU will/should be offlined after ereport is sent */
#define	FPU_FOROFFLINE  1
#define	FPU_BIND_FAIL   2 /* Could not bind to CPU ID or bind was lost */
#define	FPU_INVALID_ARG 3 /* Invalid argument passed in */
#define	FPU_SIG_SEGV	4
#define	FPU_SIG_BUS		5
#define	FPU_SIG_FPE		6
#define	FPU_SIG_ILL		7
#define	FPU_SYSCALL_TRYAGAIN	8
#define	FPU_SYSCALL_FAIL	9
#define	FPU_EREPORT_INCOM	10
#define	FPU_EREPORT_FAIL	11
#define	FPU_TIMED_OUT		12

typedef struct fps_event {
	uint32_t	version;
	uint32_t	type;
	uint32_t	length;  /* remaining length of data */
	char	data[1]; /* Variable sized data */
}fps_event_t;

typedef struct fps_event_reply {
	int32_t	result;
} fps_event_reply_t;


#ifdef __cplusplus
}
#endif

#endif /* _FPSAPI_H */
