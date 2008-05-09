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

#ifndef	_SYS_PCMU_IB_H
#define	_SYS_PCMU_IB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddi_subrdefs.h>

typedef uint8_t pcmu_ib_ino_t;
typedef uint16_t pcmu_ib_mondo_t;

/*
 * The following structure represents an interrupt entry for an INO.
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
} ih_t;

/*
 * ino structure : one per CMU-CH ino with interrupt registered
 */
typedef struct pcmu_ib_ino_info {
	struct pcmu_ib_ino_info *pino_next;
	pcmu_ib_ino_t pino_ino;		/* INO number - 8 bit */
	uint8_t pino_slot_no;		/* PCI slot number 0-8 */
	uint16_t pino_ih_size;		/* size of the pci intrspec list */
	ih_t *pino_ih_head;		/* intr spec (part of ppd) list head */
	ih_t *pino_ih_tail;		/* intr spec (part of ppd) list tail */
	ih_t *pino_ih_start;		/* starting point in intr spec list  */
	pcmu_ib_t *pino_ib_p;		/* link back to interrupt block state */
	volatile uint64_t *pino_clr_reg; /* ino interrupt clear register */
	volatile uint64_t *pino_map_reg; /* ino interrupt mapping register */
	uint64_t pino_map_reg_save;	/* = *pino_map_reg if saved */
	uint32_t pino_pil;		/* PIL for this ino */
	volatile uint_t pino_unclaimed;	/* number of unclaimed interrupts */
	clock_t pino_spurintr_begin;	/* begin time of spurious intr series */
	int pino_established;		/* ino has been associated with a cpu */
	uint32_t pino_cpuid;		/* cpu that ino is targeting */
	int32_t pino_intr_weight;	/* intr weight of devices sharing ino */
} pcmu_ib_ino_info_t;

/*
 * interrupt block soft state structure:
 */
struct pcmu_ib {
	pcmu_t *pib_pcmu_p;	/* link back to pci soft state */
	pcmu_ign_t pib_ign;	/* interrupt group # */
	uintptr_t pib_obio_intr_map_regs;	/* onboard intr map register */
	uintptr_t pib_obio_clear_intr_regs;	/* onboard intr clear reg */
	volatile uint64_t *pib_upa_imr[2]; /* UPA expansion intr map register */
	uint64_t pib_upa_imr_state[2];	   /* UPA intr map state */ /* RAGS */
	volatile uint64_t *pib_intr_retry_timer_reg; /* intr retry register */
	volatile uint64_t *pib_obio_intr_state_diag_reg; /* onboard intr st. */
	uint_t pib_max_ino;			/* largest supported INO */
	pcmu_ib_ino_info_t *pib_ino_lst;	/* ino link list */
	kmutex_t pib_ino_lst_mutex;		/* mutex for ino link list */
	kmutex_t pib_intr_lock;			/* lock for internal intr  */
};

#define	PCMU_MAX_INO		0x3f
#define	PCMU_INO_BITS		6		/* INO#s are 6 bits long */

/*
 * Only used for fixed or legacy interrupts
 */
#define	PCMU_INTR_STATE_DISABLE	0		/* disabled */
#define	PCMU_INTR_STATE_ENABLE	1		/* enabled */

#define	PCMU_IB_INTR_WAIT	1		/* wait for inter completion */
#define	PCMU_IB_INTR_NOWAIT	0		/* handling intr, no wait */

#define	PCMU_IB2CB(pib_p)	((pib_p)->pib_pcmu_p->pcmu_cb_p)

#define	PCMU_IB_MONDO_TO_INO(mondo)	((pcmu_ib_ino_t)((mondo) & 0x3f))
#define	PCMU_IB_INO_INTR_ON(reg_p)	*(reg_p) |= PCMU_INTR_MAP_REG_VALID
#define	PCMU_IB_INO_INTR_OFF(reg_p)	*(reg_p) &= ~PCMU_INTR_MAP_REG_VALID
#define	PCMU_IB_INO_INTR_STATE_REG(pib_p, ino)		\
	    (pib_p->pib_obio_intr_state_diag_reg)

#define	PCMU_IB_INO_INTR_PENDING(reg_p, ino)		\
	    (((*(reg_p) >> (((ino) & 0x1f) << 1)) &	\
	    PCMU_CLEAR_INTR_REG_MASK) == PCMU_CLEAR_INTR_REG_PENDING)

#define	PCMU_IB_INO_INTR_CLEAR(reg_p)	*(reg_p) = PCMU_CLEAR_INTR_REG_IDLE
#define	PCMU_IB_INO_INTR_PEND(reg_p)	*(reg_p) = PCMU_CLEAR_INTR_REG_PENDING
#define	PCMU_IB_INO_INTR_ISON(imr)	((imr) >> 31)

#define	PCMU_IB_IMR2MONDO(imr)	((imr) &		\
	    (PCMU_INTR_MAP_REG_IGN | PCMU_INTR_MAP_REG_INO))

#define	PCMU_IB_IS_OBIO_INO(ino) (ino & 0x20)

#define	PCMU_IB_IGN_TO_MONDO(ign, ino)	(((ign) << PCMU_INO_BITS) | (ino))
#define	PCMU_IB_INO_TO_MONDO(pib_p, ino)	\
    PCMU_IB_IGN_TO_MONDO((pib_p)->pib_ign, ino)


extern int pcmu_pil[];

/*
 * Prototypes
 */
extern void pcmu_ib_create(pcmu_t *pcmu_p);
extern void pcmu_ib_destroy(pcmu_t *pcmu_p);
extern void pcmu_ib_configure(pcmu_ib_t *pib_p);
extern uint64_t ib_get_map_reg(pcmu_ib_mondo_t mondo, uint32_t cpu_id);
extern void pcmu_ib_intr_enable(pcmu_t *pcmu_p, pcmu_ib_ino_t ino);
extern void pcmu_ib_intr_disable(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino, int wait);
extern void pcmu_ib_nintr_clear(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino);
extern void pcmu_ib_suspend(pcmu_ib_t *pib_p);
extern void pcmu_ib_resume(pcmu_ib_t *pib_p);
extern pcmu_ib_ino_info_t *pcmu_ib_locate_ino(pcmu_ib_t *pib_p,
    pcmu_ib_ino_t ino_num);
extern pcmu_ib_ino_info_t *pcmu_ib_new_ino(pcmu_ib_t *pib_p,
    pcmu_ib_ino_t ino_num, ih_t *ih_p);
extern void pcmu_ib_delete_ino(pcmu_ib_t *pib_p, pcmu_ib_ino_info_t *ino_p);
extern void pcmu_ib_free_ino_all(pcmu_ib_t *pib_p);
extern int pcmu_ib_update_intr_state(pcmu_t *pcmu_p, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, uint_t new_intr_state);
extern void pcmu_ib_ino_add_intr(pcmu_t *pcmu_p,
    pcmu_ib_ino_info_t *ino_p, ih_t *ih_p);
extern int pcmu_ib_ino_rem_intr(pcmu_t *pcmu_p,
    pcmu_ib_ino_info_t *ino_p, ih_t *ih_p);
extern ih_t *pcmu_ib_ino_locate_intr(pcmu_ib_ino_info_t *ino_p,
    dev_info_t *dip, uint32_t inum);
extern ih_t *pcmu_ib_alloc_ih(dev_info_t *dip, uint32_t inum,
    uint_t (*int_handler)(caddr_t int_handler_arg1, caddr_t int_handler_arg2),
    caddr_t int_handler_arg1, caddr_t int_handler_arg2);
extern void pcmu_ib_intr_dist_nintr(pcmu_ib_t *pib_p, pcmu_ib_ino_t ino,
    volatile uint64_t *imr_p);
extern void pcmu_ib_intr_dist_all(void *arg,
    int32_t max_weight, int32_t weight);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCMU_IB_H */
