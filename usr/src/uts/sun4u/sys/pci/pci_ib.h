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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef	_SYS_PCI_IB_H
#define	_SYS_PCI_IB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddi_subrdefs.h>
#include <sys/pci_tools.h>

typedef uint8_t ib_ino_t;
typedef uint16_t ib_mondo_t;
typedef struct ib_ino_info ib_ino_info_t;
typedef struct ib_ino_pil ib_ino_pil_t;
typedef uint8_t device_num_t;
typedef uint8_t interrupt_t;

/*
 * interrupt block soft state structure:
 *
 * Each pci node may share an interrupt block structure with its peer
 * node or have its own private interrupt block structure.
 */
typedef struct ib ib_t;
struct ib {

	pci_t *ib_pci_p;	/* link back to pci soft state */
	pci_ign_t ib_ign;	/* interrupt group # */

	/*
	 * PCI slot and onboard I/O interrupt mapping register blocks addresses:
	 */
	uintptr_t ib_slot_intr_map_regs;
#define	ib_intr_map_regs	ib_slot_intr_map_regs
	uintptr_t ib_obio_intr_map_regs;

	/*
	 * PCI slot and onboard I/O clear interrupt register block addresses:
	 */
	uintptr_t ib_slot_clear_intr_regs;
	uintptr_t ib_obio_clear_intr_regs;

	/*
	 * UPA expansion slot interrupt mapping register addresses:
	 */
	volatile uint64_t *ib_upa_imr[2];
	uint64_t ib_upa_imr_state[2];

	/*
	 * Interrupt retry register address:
	 */
	volatile uint64_t *ib_intr_retry_timer_reg;

	/*
	 * PCI slot and onboard I/O interrupt state diag register addresses:
	 */
	volatile uint64_t *ib_slot_intr_state_diag_reg;
	volatile uint64_t *ib_obio_intr_state_diag_reg;

	uint_t ib_max_ino;			/* largest supported INO */
	ib_ino_info_t *ib_ino_lst;		/* ino link list */
	kmutex_t ib_ino_lst_mutex;		/* mutex for ino link list */
	kmutex_t ib_intr_lock;			/* lock for internal intr  */
	uint16_t ib_map_reg_counters[8];	/* counters for shared map */
						/* registers */
};

#define	PCI_PULSE_INO	0x80000000
#define	PSYCHO_MAX_INO	0x3f
#define	SCHIZO_MAX_INO	0x37
#define	PCI_INO_BITS	6			/* INO#s are 6 bits long */
#define	PCI_IGN_BITS	5			/* IGN#s are 5 bits long */

/*
 * ih structure: one per every consumer of each ino and pil pair with interrupt
 * registered.
 */
typedef struct ih {
	dev_info_t *ih_dip;		/* devinfo structure */
	uint32_t ih_inum;		/* interrupt number for this device */
	uint_t	ih_intr_state;		/* Only used for fixed interrupts */
	uint_t (*ih_handler)();		/* interrupt handler */
	caddr_t ih_handler_arg1;	/* interrupt handler argument #1 */
	caddr_t ih_handler_arg2;	/* interrupt handler argument #2 */
	ddi_acc_handle_t ih_config_handle; /* config space reg map handle */
	struct ih *ih_next;		/* next entry in list */
	uint64_t ih_ticks;		/* ticks spent in this handler */
	uint64_t ih_nsec;		/* nsec spent in this handler */
	kstat_t *ih_ksp;		/* pointer to kstat information */
	ib_ino_pil_t *ih_ipil_p;	/* only for use by kstat */
} ih_t;

/* Only used for fixed or legacy interrupts */
#define	PCI_INTR_STATE_DISABLE	0	/* disabled */
#define	PCI_INTR_STATE_ENABLE	1	/* enabled */

/*
 * ino_pil structure: one per each ino and pil pair with interrupt registered
 */
struct ib_ino_pil {
	ushort_t ipil_pil;		/* PIL for this ino */
	ushort_t ipil_ih_size;		/* size of ih_t list */
	ih_t *ipil_ih_head;		/* ih_t list head */
	ih_t *ipil_ih_tail;		/* ih_t list tail */
	ih_t *ipil_ih_start;		/* starting point in ih_t list  */
	ib_ino_info_t *ipil_ino_p;	/* pointer to ib_ino_info_t */
	ib_ino_pil_t *ipil_next_p;	/* pointer to next ib_ino_pil_t */
};

/*
 * ino structure: one per each ino with interrupt registered
 */
struct ib_ino_info {
	ib_ino_t ino_ino;		/* INO number - 8 bit */
	uint64_t ino_mondo;		/* store mondo number */
	uint8_t ino_slot_no;		/* PCI slot number 0-8 */
	ib_t *ino_ib_p;			/* link back to interrupt block state */
	volatile uint64_t *ino_clr_reg;	/* ino interrupt clear register */
	volatile uint64_t *ino_map_reg;	/* ino interrupt mapping register */
	uint64_t ino_map_reg_save;	/* = *ino_map_reg if saved */
	volatile uint_t ino_unclaimed_intrs; /* number of unclaimed intrs */
	clock_t ino_spurintr_begin;	/* begin time of spurious intr series */
	int ino_established;		/* ino has been associated with a cpu */
	uint32_t ino_cpuid;		/* cpu that ino is targeting */
	int32_t ino_intr_weight;	/* intr weight of devices sharing ino */
	ushort_t ino_ipil_size;		/* number of ib_ino_pil_t sharing ino */
	ushort_t ino_lopil;		/* lowest PIL sharing ino */
	ushort_t ino_claimed;		/* pil bit masks, who claimed intr */
	ib_ino_pil_t *ino_ipil_p;	/* pointer to first ib_ino_pil_t */
	ib_ino_info_t *ino_next_p;	/* pointer to next ib_ino_info_t */
};

#define	IB_INTR_WAIT	1		/* wait for interrupt completion */
#define	IB_INTR_NOWAIT	0		/* already handling intr, no wait */

#define	IB2CB(ib_p)	((ib_p)->ib_pci_p->pci_cb_p)

#define	IB_MONDO_TO_INO(mondo)		((ib_ino_t)((mondo) & 0x3f))
#define	IB_INO_INTR_ON(reg_p)		*(reg_p) |= COMMON_INTR_MAP_REG_VALID
#define	IB_INO_INTR_OFF(reg_p)		*(reg_p) &= ~COMMON_INTR_MAP_REG_VALID
#define	IB_INO_INTR_RESET(reg_p)	*(reg_p) = 0ull
#define	IB_INO_INTR_STATE_REG(ib_p, ino) ((ino) & 0x20 ? \
	ib_p->ib_obio_intr_state_diag_reg : ib_p->ib_slot_intr_state_diag_reg)
#define	IB_INO_INTR_PENDING(reg_p, ino) \
	(((*(reg_p) >> (((ino) & 0x1f) << 1)) & COMMON_CLEAR_INTR_REG_MASK) == \
	COMMON_CLEAR_INTR_REG_PENDING)
#define	IB_INO_INTR_CLEAR(reg_p)	*(reg_p) = COMMON_CLEAR_INTR_REG_IDLE
#define	IB_INO_INTR_TRIG(reg_p)	*(reg_p) = COMMON_CLEAR_INTR_REG_RECEIVED
#define	IB_INO_INTR_PEND(reg_p)		*(reg_p) = COMMON_CLEAR_INTR_REG_PENDING
#define	IB_INO_INTR_ISON(imr)		((imr) >> 31)
#define	IB_IMR2MONDO(imr) \
	((imr) & (COMMON_INTR_MAP_REG_IGN | COMMON_INTR_MAP_REG_INO))

#define	IB_IS_OBIO_INO(ino) (ino & 0x20)

#define	IB_IGN_TO_MONDO(ign, ino)	(((ign) << PCI_INO_BITS) | (ino))
#define	IB_INO_TO_MONDO(ib_p, ino)	IB_IGN_TO_MONDO((ib_p)->ib_ign, ino)

extern void ib_create(pci_t *pci_p);
extern void ib_destroy(pci_t *pci_p);
extern void ib_configure(ib_t *ib_p);
extern uint64_t ib_get_map_reg(ib_mondo_t mondo, uint32_t cpu_id);
extern void ib_intr_enable(pci_t *pci_p, ib_ino_t ino);
extern void ib_intr_disable(ib_t *ib_p, ib_ino_t ino, int wait);
extern void ib_nintr_clear(ib_t *ib_p, ib_ino_t ino);
extern void ib_suspend(ib_t *ib_p);
extern void ib_resume(ib_t *ib_p);

extern ib_ino_info_t *ib_locate_ino(ib_t *ib_p, ib_ino_t ino_num);
extern ib_ino_pil_t *ib_new_ino_pil(ib_t *ib_p, ib_ino_t ino_num, uint_t pil,
    ih_t *ih_p);
extern void ib_delete_ino_pil(ib_t *ib_p, ib_ino_pil_t *ipil_p);
extern void ib_free_ino_all(ib_t *ib_p);
extern ib_ino_pil_t *ib_ino_locate_ipil(ib_ino_info_t *ino_p, uint_t pil);
extern void ib_ino_add_intr(pci_t *pci_p, ib_ino_pil_t *ipil_p, ih_t *ih_p);
extern void ib_ino_rem_intr(pci_t *pci_p, ib_ino_pil_t *ipil_p, ih_t *ih_p);
extern ih_t *ib_intr_locate_ih(ib_ino_pil_t *ipil_p, dev_info_t *dip,
    uint32_t inum);
extern ih_t *ib_alloc_ih(dev_info_t *dip, uint32_t inum,
    uint_t (*int_handler)(caddr_t int_handler_arg1, caddr_t int_handler_arg2),
    caddr_t int_handler_arg1, caddr_t int_handler_arg2);
extern void ib_free_ih(ih_t *ih_p);
extern void ib_ino_map_reg_share(ib_t *ib_p, ib_ino_t ino,
    ib_ino_info_t *ino_p);
extern int ib_ino_map_reg_unshare(ib_t *ib_p, ib_ino_t ino,
    ib_ino_info_t *ino_p);
extern uint32_t ib_register_intr(ib_t *ib_p, ib_mondo_t mondo, uint_t pil,
    uint_t (*handler)(caddr_t arg), caddr_t arg);
extern void ib_unregister_intr(ib_mondo_t mondo);
extern void ib_intr_dist_nintr(ib_t *ib_p, ib_ino_t ino,
    volatile uint64_t *imr_p);
extern void ib_intr_dist_all(void *arg, int32_t max_weight, int32_t weight);
extern void ib_cpu_ticks_to_ih_nsec(ib_t *ib_p, ih_t *ih_p, uint32_t cpu_id);
extern int ib_update_intr_state(pci_t *pci_p, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, uint_t new_intr_state);
extern int ib_get_intr_target(pci_t *pci_p, ib_ino_t ino, int *cpu_id_p);
extern int ib_set_intr_target(pci_t *pci_p, ib_ino_t ino, int cpu_id);
extern uint8_t ib_get_ino_devs(ib_t *ib_p, uint32_t ino, uint8_t *devs_ret,
    pcitool_intr_dev_t *devs);
extern void ib_log_new_cpu(ib_t *ib_p, uint32_t old_cpu_id, uint32_t new_cpu_id,
    uint32_t ino);

extern int pci_pil[];

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_IB_H */
