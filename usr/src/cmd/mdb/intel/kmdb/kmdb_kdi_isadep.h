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

#ifndef _KMDB_KDI_ISADEP_H
#define	_KMDB_KDI_ISADEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#include <mdb/mdb_target.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gate_desc;

extern void (**kdi_shutdownp)(int, int);

extern uintptr_t kmdb_kdi_get_userlimit(void);
extern int kmdb_kdi_xc_initialized(void);

extern void kmdb_kdi_idt_init_gate(struct gate_desc *, void (*)(void), uint_t,
    int);
extern void kmdb_kdi_idt_read(struct gate_desc *, struct gate_desc *, uint_t);
extern void kmdb_kdi_idt_write(struct gate_desc *, struct gate_desc *, uint_t);
extern struct gate_desc *kmdb_kdi_cpu2idt(struct cpu *);

extern int kmdb_kdi_get_cpuinfo(uint_t *, uint_t *, uint_t *);

/*
 * To be used only when the kernel is running
 */
extern void kmdb_kdi_cpu_iter(void (*)(struct cpu *, uint_t),
    uint_t);

#ifdef __cplusplus
}
#endif

#endif /* _KMDB_KDI_ISADEP_H */
