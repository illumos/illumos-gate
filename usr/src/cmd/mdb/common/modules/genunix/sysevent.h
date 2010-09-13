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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYSEVENT_H
#define	_SYSEVENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/sysmacros.h>
#else
#include <stddef.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysevent.h>
#include <sys/sysevent_impl.h>
#include <mdb/mdb_modapi.h>

#define	SYSEVENT_SENTQ		0x1
#define	SYSEVENT_VERBOSE	0x2
#define	CLASS_FIELD_MAX		9
#define	CHAN_FIELD_MAX		14
#define	CLASS_LIST_FIELD_MAX	24
#define	SUBCLASS_FIELD_MAX	10


extern int sysevent_buf(uintptr_t addr, uint_t flags, uint_t opt_flags);
extern int sysevent(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
extern int sysevent_channel(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
extern int sysevent_class_list(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);
extern int sysevent_subclass_list(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv);

extern int sysevent_pend_walk_init(mdb_walk_state_t *wsp);
extern int sysevent_walk_step(mdb_walk_state_t *wsp);
extern int sysevent_sent_walk_init(mdb_walk_state_t *wsp);
extern void sysevent_walk_fini(mdb_walk_state_t *wsp);
extern int sysevent_channel_walk_init(mdb_walk_state_t *wsp);
extern int sysevent_channel_walk_step(mdb_walk_state_t *wsp);
extern void sysevent_channel_walk_fini(mdb_walk_state_t *wsp);
extern int sysevent_class_list_walk_init(mdb_walk_state_t *wsp);
extern int sysevent_class_list_walk_step(mdb_walk_state_t *wsp);
extern void sysevent_class_list_walk_fini(mdb_walk_state_t *wsp);
extern int sysevent_subclass_list_walk_init(mdb_walk_state_t *wsp);
extern int sysevent_subclass_list_walk_step(mdb_walk_state_t *wsp);
extern void sysevent_subclass_list_walk_fini(mdb_walk_state_t *wsp);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYSEVENT_H */
