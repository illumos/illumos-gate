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

#ifndef _SYS_KDI_MACHIMPL_H
#define	_SYS_KDI_MACHIMPL_H

/*
 * The Kernel/Debugger interface.  The operations provided by the kdi_t,
 * defined below, comprise the Debugger -> Kernel portion of the interface,
 * and are to be used only when the system has been stopped.
 */

#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/kdi_regs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*kdi_main_t)(kdi_cpusave_t *);

typedef struct kdi_memrange {
	caddr_t mr_base;
	caddr_t mr_lim;
} kdi_memrange_t;

#define	KDI_MEMRANGES_MAX	2

typedef struct kdi_mach {
	void (*mkdi_activate)(kdi_main_t, kdi_cpusave_t *, uint_t);
	void (*mkdi_deactivate)(void);

	void (*mkdi_idt_switch)(kdi_cpusave_t *);

	void (*mkdi_update_drreg)(kdi_drreg_t *);

	uintptr_t (*mkdi_get_userlimit)(void);

	int (*mkdi_get_cpuinfo)(uint_t *, uint_t *, uint_t *);

	void (*mkdi_stop_slaves)(int, int);

	void (*mkdi_start_slaves)(void);

	void (*mkdi_slave_wait)(void);

	void (*mkdi_memrange_add)(caddr_t, size_t);

	void (*mkdi_reboot)(void);
} kdi_mach_t;

#define	mkdi_activate			kdi_mach.mkdi_activate
#define	mkdi_deactivate			kdi_mach.mkdi_deactivate
#define	mkdi_idt_switch			kdi_mach.mkdi_idt_switch
#define	mkdi_update_drreg		kdi_mach.mkdi_update_drreg
#define	mkdi_get_userlimit		kdi_mach.mkdi_get_userlimit
#define	mkdi_get_cpuinfo		kdi_mach.mkdi_get_cpuinfo
#define	mkdi_stop_slaves		kdi_mach.mkdi_stop_slaves
#define	mkdi_start_slaves		kdi_mach.mkdi_start_slaves
#define	mkdi_slave_wait			kdi_mach.mkdi_slave_wait
#define	mkdi_memrange_add		kdi_mach.mkdi_memrange_add
#define	mkdi_reboot			kdi_mach.mkdi_reboot

extern void hat_kdi_init(void);

extern ulong_t kdi_getdr0(void), kdi_getdr1(void), kdi_getdr2(void);
extern ulong_t kdi_getdr3(void), kdi_getdr6(void), kdi_getdr7(void);
extern void kdi_setdr0(ulong_t), kdi_setdr1(ulong_t), kdi_setdr2(ulong_t);
extern void kdi_setdr3(ulong_t), kdi_setdr6(ulong_t), kdi_setdr7(ulong_t);
extern ulong_t kdi_dreg_get(int);
extern void kdi_dreg_set(int, ulong_t);
extern void kdi_update_drreg(kdi_drreg_t *);
extern void kdi_cpu_debug_init(kdi_cpusave_t *);

extern void kdi_cpu_init(void);
extern void kdi_xc_others(int, void (*)(void));
extern void kdi_start_slaves(void);
extern void kdi_slave_wait(void);

extern void kdi_idtr_set(gate_desc_t *, size_t);
extern void kdi_idt_write(struct gate_desc *, uint_t);
extern void kdi_idt_sync(void);
extern void kdi_idt_switch(kdi_cpusave_t *);
#ifdef __xpv
extern void kdi_idtr_write(desctbr_t *);
#else
#define	kdi_idtr_write(idtr) wr_idtr(idtr)
#endif

extern void kdi_activate(kdi_main_t, kdi_cpusave_t *, uint_t);
extern void kdi_deactivate(void);
extern void kdi_stop_slaves(int, int);
extern void kdi_memrange_add(caddr_t, size_t);
extern void kdi_reboot(void);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KDI_MACHIMPL_H */
