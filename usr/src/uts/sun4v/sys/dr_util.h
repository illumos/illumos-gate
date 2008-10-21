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

#ifndef _DR_UTIL_H
#define	_DR_UTIL_H

/*
 * sun4v Common DR Header
 */

#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/note.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Debugging support
 */
#ifdef DEBUG

extern uint_t	dr_debug;

#define	DR_DBG_FLAG_CTL		0x01
#define	DR_DBG_FLAG_CPU		0x02
#define	DR_DBG_FLAG_MEM		0x04
#define	DR_DBG_FLAG_IO		0x08
#define	DR_DBG_FLAG_TRANS	0x10
#define	DR_DBG_FLAG_KMEM	0x20

#define	DR_DBG_ALL	if (dr_debug)			  printf
#define	DR_DBG_CTL	if (dr_debug & DR_DBG_FLAG_CTL)	  printf
#define	DR_DBG_CPU	if (dr_debug & DR_DBG_FLAG_CPU)	  printf
#define	DR_DBG_MEM	if (dr_debug & DR_DBG_FLAG_MEM)	  printf
#define	DR_DBG_IO	if (dr_debug & DR_DBG_FLAG_IO)	  printf
#define	DR_DBG_TRANS	if (dr_debug & DR_DBG_FLAG_TRANS) printf
#define	DR_DBG_KMEM	if (dr_debug & DR_DBG_FLAG_KMEM)  printf

#define	DR_DBG_DUMP_MSG(buf, len)	dr_dbg_dump_msg(buf, len)

extern void dr_dbg_dump_msg(void *buf, size_t len);

#else /* DEBUG */

#define	DR_DBG_ALL	_NOTE(CONSTCOND) if (0)	printf
#define	DR_DBG_CTL	DR_DBG_ALL
#define	DR_DBG_CPU	DR_DBG_ALL
#define	DR_DBG_MEM	DR_DBG_ALL
#define	DR_DBG_IO	DR_DBG_ALL
#define	DR_DBG_TRANS	DR_DBG_ALL
#define	DR_DBG_KMEM	DR_DBG_ALL

#define	DR_DBG_DUMP_MSG(buf, len)

#endif /* DEBUG */

typedef enum {
	DR_TYPE_INVAL,
	DR_TYPE_CPU,
	DR_TYPE_MEM,
	DR_TYPE_VIO
} dr_type_t;

/*
 * Macro to convert a dr_type_t into a string. These strings are
 * used to generate DR events and should only be modified using
 * extreme caution.
 */
#define	DR_TYPE2STR(t)	((t) == DR_TYPE_INVAL ? "invalid" :	\
			    (t) == DR_TYPE_CPU ? OBP_CPU : 	\
			    (t) == DR_TYPE_MEM ? "memory" :	\
			    (t) == DR_TYPE_VIO ? "vio" :	\
			    "unknown")

extern boolean_t dr_is_disabled(dr_type_t type);
extern void dr_generate_event(dr_type_t type, int se_hint);

#ifdef __cplusplus
}
#endif

#endif /* _DR_UTIL_H */
