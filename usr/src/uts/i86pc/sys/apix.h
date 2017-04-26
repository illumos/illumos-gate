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
 * Copyright 2017 Joyent, Inc.
 */

#ifndef __SYS_APIX_APIX_H
#define	__SYS_APIX_APIX_H

#include <sys/note.h>
#include <sys/avintr.h>
#include <sys/traptrace.h>
#include <sys/apic.h>
#include <sys/apic_common.h>
#include <sys/apic_timer.h>

#ifdef	__cplusplus
extern	"C" {
#endif

#ifdef	DEBUG
#ifndef	TRAPTRACE
#define	TRAPTRACE
#endif
#endif

#define	APIX_NAME		"apix"

#define	APIX_NVECTOR		256	/* max number of per-cpu vectors */
#define	APIX_NIRQ		256	/* maximum number of IRQs */
#define	APIX_INVALID_VECT	0	/* invalid vector */

/* vector type */
#define	APIX_TYPE_FIXED	DDI_INTR_TYPE_FIXED	/* 1 */
#define	APIX_TYPE_MSI		DDI_INTR_TYPE_MSI	/* 2 */
#define	APIX_TYPE_MSIX	DDI_INTR_TYPE_MSIX	/* 4 */
#define	APIX_TYPE_IPI		8

/* vector states */
enum {
	APIX_STATE_FREED = 0,
	APIX_STATE_OBSOLETED,	/* 1 */
	APIX_STATE_ALLOCED,	/* 2 */
	APIX_STATE_ENABLED,	/* 3 */
	APIX_STATE_DISABLED	/* 4 */
};
#define	IS_VECT_FREE(p)		\
	(((p) == NULL) || ((p)->v_state == APIX_STATE_FREED))
#define	IS_VECT_OBSOL(p)	\
	(((p) != NULL) && ((p)->v_state == APIX_STATE_OBSOLETED))
#define	IS_VECT_ENABLED(p)	\
	(((p) != NULL) && ((p)->v_state == APIX_STATE_ENABLED))

/* flags */
#define	APIX_VECT_USER_BOUND	0x1
#define	APIX_VECT_MASKABLE	0x2

/*
 * Number of interrupt vectors reserved by software on each LOCAL APIC:
 * 	1. Dtrace
 *	2. int80
 *	3. system-call
 *	4. fast-trap
 * 	5. apix-reserved
 */
#define	APIX_SW_RESERVED_VECTORS	5

/*
 * Macros to help deal with shared interrupts and to differentiate
 * between vector and irq number when passing arguments to interfaces
 * xxx_avintr()
 */
#define	APIX_VIRTVEC_VECMASK		0xff
#define	APIX_VIRTVEC_FLAG		0x80000000
#define	APIX_VIRTVECTOR(cpuid, v)	\
	(APIX_VIRTVEC_FLAG | ((cpuid) << 8) | (v))
#define	APIX_IS_VIRTVEC(vv)		\
	((vv) & APIX_VIRTVEC_FLAG)
#define	APIX_VIRTVEC_VECTOR(vv)	\
	(((uchar_t)(vv)) & APIX_VIRTVEC_VECMASK)
#define	APIX_VIRTVEC_CPU(vv)		\
	(((uint32_t)(vv) & ~APIX_VIRTVEC_FLAG) >> 8)

struct apix_dev_vector;
typedef struct apix_vector {
	ushort_t		v_state;
	ushort_t		v_type;	/* interrupt type */
	processorid_t		v_cpuid;	/* current target cpu */
	uchar_t			v_vector;	/* vector */
	uchar_t			v_share;	/* intrs at this vector */
	int			v_inum;	/* irq for fixed, inum for msi/x */
	uint_t			v_flags;
	processorid_t		v_bound_cpuid;	/* binding cpu */
	uint_t			v_busy;	/* How frequently did clock */
					/* find us in this */
	uint_t			v_pri;	/* maximum priority */
	struct autovec		*v_autovect;	/* ISR linked list */
	void			*v_intrmap_private; /* intr remap data */
	struct apix_dev_vector *v_devp;	/* pointer to device */
	struct apix_vector	*v_next; /* next on per-cpu obosoletes chain */
} apix_vector_t;

typedef struct apix_impl {
	processorid_t		x_cpuid;	/* cpu number */

	uint16_t		x_intr_pending;	/* pending intr by IPL */
	/* pointer to head of interrupt pending list */
	struct autovec		*x_intr_head[PIL_MAX + 1];
	/* pointer to tail of interrupt pending list */
	struct autovec		*x_intr_tail[PIL_MAX + 1];

	apix_vector_t		*x_obsoletes;	/* obosoleted vectors */
	apix_vector_t		*x_vectbl[APIX_NVECTOR]; /* vector table */

	lock_t			x_lock;
} apix_impl_t;

#define	HILEVEL_PENDING(cpu)	\
	(apixs[(cpu)->cpu_id]->x_intr_pending & CPU_INTR_ACTV_HIGH_LEVEL_MASK)
#define	LOWLEVEL_PENDING(cpu)	\
	(apixs[(cpu)->cpu_id]->x_intr_pending & ~CPU_INTR_ACTV_HIGH_LEVEL_MASK)
#define	IS_HILEVEL_RUNNING(cpu)	\
	(((ushort_t)((cpu)->intr_actv)) & CPU_INTR_ACTV_HIGH_LEVEL_MASK)
#define	IS_LOWLEVEL_RUNNING(cpu)	\
	(((ushort_t)((cpu)->intr_actv)) & ~CPU_INTR_ACTV_HIGH_LEVEL_MASK)

#define	INTR_PENDING(apixp, ipl)			\
	((ipl) <= LOCK_LEVEL ?				\
	((apixp)->x_intr_pending & (1 << (ipl))) :	\
	((apixp)->x_intr_pending >> (LOCK_LEVEL + 1)))

/*
 * We need a way to find allocated vector for a device. One option
 * is to maintain a mapping table in pcplusmp. Another option would
 * be to record vector or irq with interrupt handler hdlp->ih_vector or
 * hdlp->ih_irq.
 * Second option requires interface changes, such as, a new interface
 * for  noticing vector changes caused by interrupt re-targeting.
 * Currently we choose the first option cause it doesn't require
 * new interfaces.
 */
typedef struct apix_dev_vector {
	dev_info_t		*dv_dip;
	int			dv_inum;	/* interrupt number */
	int			dv_type;	/* interrupt type */
	apix_vector_t		*dv_vector;	/* vector */
	struct apix_dev_vector *dv_next;	/* per major chain */
} apix_dev_vector_t;

extern lock_t apix_lock;
extern apix_impl_t *apixs[];
extern int apix_nipis;
extern int apix_cpu_nvectors;
extern apix_dev_vector_t **apix_dev_vector;
extern processorid_t *apix_major_to_cpu;
extern kmutex_t apix_mutex;

#define	xv_vector(cpu, v)	apixs[(cpu)]->x_vectbl[(v)]
#define	xv_intrmap_private(cpu, v)	(xv_vector(cpu, v))->v_intrmap_private

#define	APIX_IPI_MAX		APIC_MAX_VECTOR
#define	APIX_IPI_MIN		(APIX_NVECTOR - apix_nipis)
#define	APIX_AVINTR_MIN	0x20
#define	APIX_NAVINTR		\
	(apix_cpu_nvectors - apix_nipis - APIX_AVINTR_MIN)
#define	APIX_AVINTR_MAX	\
	((APIX_NAVINTR <= 0) ? 0 : \
	(((APIX_AVINTR_MIN + APIX_NAVINTR) > APIX_IPI_MIN) ? \
	(APIX_IPI_MIN - 2) : \
	(APIX_AVINTR_MIN + APIX_NAVINTR - 2)))
#define	APIX_RESV_VECTOR	(APIX_AVINTR_MAX + 1)

#define	IS_VALID_AVINTR(v)		\
	((v) >= APIX_AVINTR_MIN && (v) <= APIX_AVINTR_MAX)

#define	APIX_ENTER_CPU_LOCK(cpuid)	lock_set(&apixs[(cpuid)]->x_lock)
#define	APIX_LEAVE_CPU_LOCK(cpuid)	lock_clear(&apixs[(cpuid)]->x_lock)
#define	APIX_CPU_LOCK_HELD(cpuid)	LOCK_HELD(&apixs[(cpuid)]->x_lock)

/* Get dip for msi/x */
#define	APIX_GET_DIP(v)		\
	((v)->v_devp->dv_dip)

/*
 * For irq
 */
extern apic_irq_t *apic_irq_table[APIC_MAX_VECTOR+1];
#define	IS_IRQ_FREE(p)		\
	((p) == NULL || ((p)->airq_mps_intr_index == FREE_INDEX))

#define	UNREFERENCED_1PARAMETER(_p)		_NOTE(ARGUNUSED(_p))
#define	UNREFERENCED_3PARAMETER(_p, _q, _r)	_NOTE(ARGUNUSED(_p, _q, _r))

/*
 * From mp_platform_common.c
 */
extern int apic_intr_policy;
extern iflag_t apic_sci_flags;
extern int apic_hpet_vect;
extern iflag_t apic_hpet_flags;
extern int	apic_redist_cpu_skip;
extern int	apic_num_imbalance;
extern int	apic_num_rebind;
extern struct apic_io_intr *apic_io_intrp;
extern int	apic_use_acpi_madt_only;
extern uint32_t	eisa_level_intr_mask;
extern int	apic_pci_bus_total;
extern uchar_t	apic_single_pci_busid;

extern ACPI_MADT_INTERRUPT_OVERRIDE *acpi_isop;
extern int acpi_iso_cnt;

extern int	apic_defconf;
extern int	apic_irq_translate;

extern int apic_max_reps_clear_pending;

extern int apic_probe_common(char *modname);
extern uchar_t acpi_find_ioapic(int irq);
extern int apic_find_bus_id(int bustype);
extern int apic_find_intin(uchar_t ioapic, uchar_t intin);
extern struct apic_io_intr *apic_find_io_intr_w_busid(int irqno, int busid);
extern int apic_acpi_translate_pci_irq(dev_info_t *dip, int busid, int devid,
    int ipin, int *pci_irqp, iflag_t *intr_flagp);
extern int apic_handle_pci_pci_bridge(dev_info_t *idip, int child_devno,
    int child_ipin, struct apic_io_intr **intrp);
extern void apic_record_rdt_entry(apic_irq_t *irqptr, int irq);

/*
 * From apic_regops.c
 */
extern int apic_have_32bit_cr8;

/*
 * apix_intr.c
 */
extern void apix_do_interrupt(struct regs *rp, trap_trace_rec_t *ttp);

/*
 * apix_utils.c
 */

typedef struct apix_rebind_info {
	int		i_go;	/* if rebinding op is in progress */
	uint_t		i_pri;
	processorid_t	i_old_cpuid;
	struct autovec	*i_old_av;
	processorid_t	i_new_cpuid;
	struct autovec	*i_new_av;
} apix_rebind_info_t;

extern struct apix_rebind_info apix_rebindinfo;

#define	APIX_SET_REBIND_INFO(_ovp, _nvp)\
	if (((_ovp)->v_flags & APIX_VECT_MASKABLE) == 0) {\
		apix_rebindinfo.i_pri = (_ovp)->v_pri;\
		apix_rebindinfo.i_old_cpuid = (_ovp)->v_cpuid;\
		apix_rebindinfo.i_old_av = (_ovp)->v_autovect;\
		apix_rebindinfo.i_new_cpuid = (_nvp)->v_cpuid;\
		apix_rebindinfo.i_new_av = (_nvp)->v_autovect;\
		apix_rebindinfo.i_go = 1;\
	}

#define	APIX_CLR_REBIND_INFO() \
	apix_rebindinfo.i_go = 0

#define	APIX_IS_FAKE_INTR(_vector)\
	(apix_rebindinfo.i_go && (_vector) == APIX_RESV_VECTOR)

#define	APIX_DO_FAKE_INTR(_cpu, _vector)\
	if (APIX_IS_FAKE_INTR(_vector)) {\
		struct autovec *tp = NULL;\
		if ((_cpu) == apix_rebindinfo.i_old_cpuid)\
			tp = apix_rebindinfo.i_old_av;\
		else if ((_cpu) == apix_rebindinfo.i_new_cpuid)\
			tp = apix_rebindinfo.i_new_av;\
		ASSERT(tp != NULL);\
		if (tp->av_vector != NULL &&\
		    (tp->av_flags & AV_PENTRY_PEND) == 0) {\
			tp->av_flags |= AV_PENTRY_PEND;\
			apix_insert_pending_av(apixs[(_cpu)], tp,\
			    tp->av_prilevel);\
			apixs[(_cpu)]->x_intr_pending |=\
			    (1 << tp->av_prilevel);\
		}\
	}

extern int apix_add_avintr(void *intr_id, int ipl, avfunc xxintr, char *name,
    int vector, caddr_t arg1, caddr_t arg2, uint64_t *ticksp, dev_info_t *dip);
extern void apix_rem_avintr(void *intr_id, int ipl, avfunc xxintr,
    int virt_vect);

extern uint32_t apix_bind_cpu_locked(dev_info_t *dip);
extern apix_vector_t *apix_rebind(apix_vector_t *vecp, processorid_t tocpu,
    int count);

extern uchar_t apix_alloc_ipi(int ipl);
extern apix_vector_t *apix_alloc_intx(dev_info_t *dip, int inum, int irqno);
extern int apix_alloc_msi(dev_info_t *dip, int inum, int count, int behavior);
extern int apix_alloc_msix(dev_info_t *dip, int inum, int count, int behavior);
extern void apix_free_vectors(dev_info_t *dip, int inum, int count, int type);
extern void apix_enable_vector(apix_vector_t *vecp);
extern void apix_disable_vector(apix_vector_t *vecp);
extern int apix_obsolete_vector(apix_vector_t *vecp);
extern int apix_find_cont_vector_oncpu(uint32_t cpuid, int count);

extern void apix_set_dev_map(apix_vector_t *vecp, dev_info_t *dip, int inum);
extern apix_vector_t *apix_get_dev_map(dev_info_t *dip, int inum, int type);
extern apix_vector_t *apix_setup_io_intr(apix_vector_t *vecp);
extern void ioapix_init_intr(int mask_apic);
extern int apix_get_min_dev_inum(dev_info_t *dip, int type);
extern int apix_get_max_dev_inum(dev_info_t *dip, int type);

/*
 * apix.c
 */
extern int apix_addspl(int virtvec, int ipl, int min_ipl, int max_ipl);
extern int apix_delspl(int virtvec, int ipl, int min_ipl, int max_ipl);
extern void apix_intx_set_vector(int irqno, uint32_t cpuid, uchar_t vector);
extern apix_vector_t *apix_intx_get_vector(int irqno);
extern void apix_intx_enable(int irqno);
extern void apix_intx_disable(int irqno);
extern void apix_intx_free(int irqno);
extern int apix_intx_rebind(int irqno, processorid_t cpuid, uchar_t vector);
extern apix_vector_t *apix_set_cpu(apix_vector_t *vecp, int new_cpu,
    int *result);
extern apix_vector_t *apix_grp_set_cpu(apix_vector_t *vecp, int new_cpu,
    int *result);
extern void apix_level_intr_pre_eoi(int irq);
extern void apix_level_intr_post_dispatch(int irq);

#ifdef	__cplusplus
}
#endif

#endif	/* __SYS_APIX_APIX_H */
