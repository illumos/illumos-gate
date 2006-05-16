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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KMDB_PROMIF_H
#define	_KMDB_PROMIF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/obpdefs.h>
#include <sys/termios.h>

#include <kmdb/kmdb_promif_isadep.h>
#include <kmdb/kmdb_auxv.h>
#include <mdb/mdb_target.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void kmdb_prom_init_begin(char *, kmdb_auxv_t *);
extern void kmdb_prom_init_finish(kmdb_auxv_t *);
#ifdef sun4v
extern void kmdb_prom_init_promif(char *, kmdb_auxv_t *);
#endif
extern ssize_t kmdb_prom_read(void *, size_t, struct termios *);
extern ssize_t kmdb_prom_write(const void *, size_t, struct termios *);
extern ihandle_t kmdb_prom_get_handle(char *);

extern void kmdb_prom_check_interrupt(void);
extern int kmdb_prom_vtop(uintptr_t, physaddr_t *);

extern char *kmdb_prom_term_type(void);
extern int kmdb_prom_term_ctl(int, void *);

extern void kmdb_prom_debugger_entry(void);
extern void kmdb_prom_debugger_exit(void);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_PROMIF_H */
