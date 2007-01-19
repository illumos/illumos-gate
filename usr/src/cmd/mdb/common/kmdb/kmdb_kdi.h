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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KMDB_KDI_H
#define	_KMDB_KDI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/kdi.h>
#include <sys/modctl.h>
#include <gelf.h>

#include <kmdb/kmdb_auxv.h>
#include <mdb/mdb_target.h>
#include <kmdb/kmdb_kdi_isadep.h>

/*
 * The following directive tells the mapfile generator that only those
 * prototypes and declarations ending with a "Driver OK" comment should be
 * included in the mapfile.
 *
 * MAPFILE: export "Driver OK"
 */

#ifdef __cplusplus
extern "C" {
#endif

struct module;

/*
 * KDI initialization
 */
extern void kmdb_kdi_init(kdi_t *, kmdb_auxv_t *);
extern void kmdb_kdi_init_isadep(kdi_t *, kmdb_auxv_t *);
extern void kmdb_kdi_end_init(void);

/*
 * Debugger -> Kernel functions for use when the kernel is stopped
 */
extern int kmdb_kdi_mods_changed(void);
extern int kmdb_kdi_mod_iter(int (*)(struct modctl *, void *), void *);
extern int kmdb_kdi_mod_isloaded(struct modctl *);
extern int kmdb_kdi_mod_haschanged(struct modctl *, struct module *,
    struct modctl *, struct module *);
extern ssize_t kmdb_kdi_pread(void *, size_t, physaddr_t);
extern ssize_t kmdb_kdi_pwrite(void *, size_t, physaddr_t);
extern void kmdb_kdi_stop_slaves(int, int);
extern void kmdb_kdi_start_slaves(void);
extern void kmdb_kdi_slave_wait(void);
extern void kmdb_kdi_kmdb_enter(void);	/* Driver OK */
extern void kmdb_kdi_system_claim(void);
extern void kmdb_kdi_system_release(void);
extern size_t kmdb_kdi_range_is_nontoxic(uintptr_t, size_t, int);
extern void kmdb_kdi_flush_caches(void);
extern struct cons_polledio *kmdb_kdi_get_polled_io(void);
extern int kmdb_kdi_vtop(uintptr_t, physaddr_t *);
extern kdi_dtrace_state_t kmdb_kdi_dtrace_get_state(void);
extern int kmdb_kdi_dtrace_set(int);

/*
 * Driver -> Debugger notifications
 */

extern int kmdb_kdi_get_unload_request(void);			/* Driver OK */
extern void kmdb_kdi_set_unload_request(void);			/* Driver OK */

#define	KMDB_KDI_FL_NOMODS		0x1
#define	KMDB_KDI_FL_NOCTF		0x2

extern int kmdb_kdi_get_flags(void);				/* Driver OK */

/*
 * Debugger -> Kernel functions for use only when the kernel is running
 */
extern uintptr_t kmdb_kdi_lookup_by_name(char *, char *);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_KDI_H */
