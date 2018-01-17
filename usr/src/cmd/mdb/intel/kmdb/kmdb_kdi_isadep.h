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
 *
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _KMDB_KDI_ISADEP_H
#define	_KMDB_KDI_ISADEP_H

#include <sys/types.h>
#include <sys/kdi_machimpl.h>

#include <mdb/mdb_target.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gate_desc;

extern void kmdb_kdi_activate(kdi_main_t, kdi_cpusave_t *, int);
extern void kmdb_kdi_deactivate(void);

extern void kmdb_kdi_idt_switch(kdi_cpusave_t *);

extern void kmdb_kdi_update_drreg(kdi_drreg_t *);

extern uintptr_t kmdb_kdi_get_userlimit(void);

extern int kmdb_kdi_get_cpuinfo(uint_t *, uint_t *, uint_t *);

extern void kmdb_kdi_memrange_add(caddr_t, size_t);

extern void kmdb_kdi_reboot(void);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_KDI_ISADEP_H */
