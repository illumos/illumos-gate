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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */
/*
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _SYS_APIC_COMMON_H
#define	_SYS_APIC_COMMON_H

#include <sys/psm_types.h>
#include <sys/avintr.h>
#include <sys/privregs.h>
#include <sys/pci.h>
#include <sys/cyclic.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Functions & Variables common to pcplusmp & apix
 */

#include <sys/psm_common.h>

/* Methods for multiple IOAPIC */
enum apic_ioapic_method_type {
	APIC_MUL_IOAPIC_NONE,		/* use to disable pcplusmp fallback */
	APIC_MUL_IOAPIC_MASK,		/* Set RT Entry Mask bit before EOI */
	APIC_MUL_IOAPIC_DEOI,		/* Directed EOI */
	APIC_MUL_IOAPIC_IOXAPIC,	/* IOxAPIC */
	APIC_MUL_IOAPIC_IIR,		/* IOMMU interrup remapping */
	APIC_MUL_IOAPIC_PCPLUSMP	/* Fall back to old pcplusmp */
};

#define	APIX_IS_DIRECTED_EOI(type)	\
	((type) == APIC_MUL_IOAPIC_DEOI || (type) == APIC_MUL_IOAPIC_IIR)
#define	APIX_IS_MASK_RDT(type)	\
	((type) == APIC_MUL_IOAPIC_NONE || (type) == APIC_MUL_IOAPIC_MASK)

extern int	apix_enable;
extern int	apix_loaded(void);
extern enum apic_ioapic_method_type apix_mul_ioapic_method;

extern int	apic_oneshot;
/* to allow disabling one-shot capability */
extern int	apic_oneshot_enable;

/* Now the ones for Dynamic Interrupt distribution */
extern int	apic_enable_dynamic_migration;

extern int apic_have_32bit_cr8;

extern struct psm_ops *psmops;

/*
 * These variables are frequently accessed in apic_intr_enter(),
 * apic_intr_exit and apic_setspl, so group them together
 */
extern volatile uint32_t *apicadr;	/* virtual addr of local APIC	*/
extern uchar_t	apic_io_vectbase[MAX_IO_APIC];
extern uchar_t	apic_io_vectend[MAX_IO_APIC];
extern uchar_t	apic_io_ver[MAX_IO_APIC];
extern int	apic_io_max;
extern int 	apic_nvidia_io_max;
extern int apic_setspl_delay;		/* apic_setspl - delay enable	*/
extern int apic_clkvect;

/* vector at which error interrupts come in */
extern int apic_errvect;
extern int apic_enable_error_intr;
extern int apic_error_display_delay;

/* vector at which performance counter overflow interrupts come in */
extern int apic_cpcovf_vect;
extern int apic_enable_cpcovf_intr;

/* vector at which CMCI interrupts come in */
extern int apic_cmci_vect;
extern int cmi_enable_cmci;
extern void cmi_cmci_trap(void);

extern kmutex_t cmci_cpu_setup_lock;	/* protects cmci_cpu_setup_registered */
extern int cmci_cpu_setup_registered;

extern int	apic_forceload;

extern int	apic_coarse_hrtime;	/* 0 - use accurate slow gethrtime() */
					/* 1 - use gettime() for performance */
extern int	apic_flat_model;		/* 0 - clustered. 1 - flat */

extern int	apic_panic_on_nmi;
extern int	apic_panic_on_apic_error;

extern int	apic_verbose;

extern int	apic_pir_vect;

#ifdef DEBUG
extern int	apic_debug;
extern int	apic_restrict_vector;

extern int	apic_debug_msgbuf[APIC_DEBUG_MSGBUFSIZE];
extern int	apic_debug_msgbufindex;

#endif /* DEBUG */

extern uint_t	apic_nsec_per_intr;
extern uint_t	apic_nticks;
extern uint_t	apic_skipped_redistribute;

extern uint_t	last_count_read;
extern lock_t	apic_mode_switch_lock;
extern lock_t	apic_gethrtime_lock;
extern volatile int	apic_hrtime_stamp;
extern volatile hrtime_t apic_nsec_since_boot;
extern uint_t	apic_hertz_count;

extern uint64_t apic_ticks_per_SFnsecs;	/* # of ticks in SF nsecs */

extern int	apic_hrtime_error;
extern int	apic_remote_hrterr;
extern int	apic_num_nmis;
extern int	apic_apic_error;
extern int	apic_num_apic_errors;
extern int	apic_num_cksum_errors;

extern int	apic_error;

/* use to make sure only one cpu handles the nmi */
extern lock_t	apic_nmi_lock;
/* use to make sure only one cpu handles the error interrupt */
extern lock_t	apic_error_lock;

/* Patchable global variables. */
extern int	apic_kmdb_on_nmi;	/* 0 - no, 1 - yes enter kmdb */
extern uint32_t	apic_divide_reg_init;	/* 0 - divide by 2 */

extern apic_intrmap_ops_t *apic_vt_ops;

#ifdef	DEBUG
extern int	apic_break_on_cpu;
extern int	apic_stretch_interrupts;
extern int	apic_stretch_ISR;	/* IPL of 3 matches nothing now */
#endif

extern cyclic_id_t apic_cyclic_id;

extern void apic_nmi_intr(caddr_t arg, struct regs *rp);
extern int	apic_clkinit();
extern hrtime_t apic_gettime();
extern hrtime_t apic_gethrtime();
extern int	apic_cpu_start(processorid_t cpuid, caddr_t ctx);
extern int	apic_cpu_stop(processorid_t cpuid, caddr_t ctx);
extern int	apic_cpu_add(psm_cpu_request_t *reqp);
extern int	apic_cpu_remove(psm_cpu_request_t *reqp);
extern int	apic_cpu_ops(psm_cpu_request_t *reqp);
extern void	apic_switch_ipi_callback(boolean_t enter);
extern void	apic_send_ipi(int cpun, int ipl);
extern void	apic_set_idlecpu(processorid_t cpun);
extern void	apic_unset_idlecpu(processorid_t cpun);
extern void	apic_shutdown(int cmd, int fcn);
extern void	apic_preshutdown(int cmd, int fcn);
extern processorid_t	apic_get_next_processorid(processorid_t cpun);
extern uint64_t	apic_calibrate();
extern int	apic_get_pir_ipivect(void);
extern void	apic_send_pir_ipi(processorid_t);

extern int apic_error_intr();
extern void apic_cpcovf_mask_clear(void);
extern int cmci_cpu_setup(cpu_setup_t what, int cpuid, void *arg);
extern void apic_intrmap_init(int apic_mode);
extern processorid_t apic_find_cpu(int flag);
extern processorid_t apic_get_next_bind_cpu(void);

extern int	apic_support_msi;
extern int	apic_multi_msi_enable;
extern int	apic_msix_enable;

extern uint32_t apic_get_localapicid(uint32_t cpuid);
extern uchar_t apic_get_ioapicid(uchar_t ioapicindex);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_APIC_COMMON_H */
