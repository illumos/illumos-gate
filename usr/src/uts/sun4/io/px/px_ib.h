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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PX_IB_H
#define	_SYS_PX_IB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddi_subrdefs.h>
#include <sys/pci_tools.h>

typedef struct px_ib		px_ib_t;
typedef struct px_ino		px_ino_t;
typedef struct px_ino_pil	px_ino_pil_t;
typedef struct px_ih		px_ih_t;

/*
 * interrupt block soft state structure:
 *
 * Each px node may share an interrupt block structure with its peer
 * node or have its own private interrupt block structure.
 */
struct px_ib {
	px_t		*ib_px_p;	/* link back to px soft state */
	px_ino_t	*ib_ino_lst;	/* ino link list */
	kmutex_t	ib_ino_lst_mutex; /* mutex for ino link list */
	kmutex_t	ib_intr_lock;	/* lock for internal intr  */

	px_msiq_state_t	ib_msiq_state;	/* MSIQ soft state */
	px_msi_state_t	ib_msi_state;	/* MSI soft state */
};

/*
 * ih structure: one per every consumer of each ino and pil pair with interrupt
 * registered.
 */
struct px_ih {
	dev_info_t	*ih_dip;	/* devinfo structure */
	uint32_t	ih_inum;	/* interrupt number for this device */
	uint_t		(*ih_handler)(); /* interrupt handler */
	caddr_t		ih_handler_arg1; /* interrupt handler argument #1 */
	caddr_t		ih_handler_arg2; /* interrupt handler argument #2 */
	ddi_acc_handle_t ih_config_handle; /* config space reg map handle */
	uint_t		ih_intr_state;	/* only used for fixed interrupts */
	msiq_rec_type_t	ih_rec_type;	/* MSI or PCIe record type */
	msgcode_t	ih_msg_code;	/* MSI number or PCIe message code */
	uint8_t		ih_intr_flags;	/* interrupt handler status flags */
	px_ih_t		*ih_next;	/* Next entry in list */
	uint64_t	ih_ticks;	/* ticks spent in this handler */
	uint64_t	ih_nsec;	/* nsec spent in this handler */
	kstat_t		*ih_ksp;	/* pointer to kstat information */
	px_ino_pil_t	*ih_ipil_p;	/* only for use by kstat */
};

/* Only used for fixed or legacy interrupts */
#define	PX_INTR_STATE_DISABLE	0	/* disabled */
#define	PX_INTR_STATE_ENABLE	1	/* enabled */

/* Only used for MSI/X to track interrupt handler status */
#define	PX_INTR_IDLE		0x0	/* handler is idle */
#define	PX_INTR_RETARGET	0x1	/* retarget in progress */
#define	PX_INTR_PENDING		0x2	/* handler is pending */

/*
 * ino_pil structure: one per each ino and pil pair with interrupt registered
 */
struct px_ino_pil {
	ushort_t	ipil_pil;	/* pil for this ino */
	ushort_t	ipil_ih_size;	/* size of px_ih_t list */
	px_ih_t		*ipil_ih_head;	/* px_ih_t list head */
	px_ih_t		*ipil_ih_tail;	/* px_ih_t list tail */
	px_ih_t		*ipil_ih_start;	/* starting point in px_ih_t list  */
	px_ino_t	*ipil_ino_p;	/* pointer to px_ino_t structure */
	px_ino_pil_t	*ipil_next_p;	/* pointer to next px_ino_pil_t */
};

/*
 * ino structure: one per each ino with interrupt registered
 */
struct px_ino {
	devino_t	ino_ino;	/* INO number - 8 bit */
	sysino_t	ino_sysino;	/* Virtual inumber */
	px_ib_t		*ino_ib_p;	/* link back to interrupt block state */
	uint_t		ino_unclaimed_intrs; /* number of unclaimed intrs */
	clock_t		ino_spurintr_begin; /* begin time of spurious intr */
	cpuid_t		ino_cpuid;	/* current cpu for this ino */
	cpuid_t		ino_default_cpuid; /* default cpu for this ino */
	int32_t		ino_intr_weight; /* intr wt of devices sharing ino */
	ushort_t	ino_ipil_size;	/* no of px_ino_pil_t sharing ino */
	ushort_t	ino_lopil;	/* lowest pil sharing ino */
	ushort_t	ino_claimed;	/* pil bit masks, who claimed intr */
	px_msiq_t	*ino_msiq_p;	/* pointer to MSIQ used */
	px_ino_pil_t	*ino_ipil_p;	/* pointer to first px_ino_pil_t */
	px_ino_t	*ino_next_p;	/* pointer to next px_ino_t */
	ushort_t	ino_ipil_cntr;	/* counter for pil sharing ino */
};

#define	IB_INTR_WAIT	1		/* wait for interrupt completion */
#define	IB_INTR_NOWAIT	0		/* already handling intr, no wait */

#define	PX_INTR_ENABLE(dip, sysino, cpuid) \
	(void) px_lib_intr_settarget(dip, sysino, cpuid); \
	(void) px_lib_intr_setvalid(dip, sysino, INTR_VALID);

#define	PX_INTR_DISABLE(dip, sysino) \
	(void) px_lib_intr_setvalid(dip, sysino, INTR_NOTVALID);

extern int px_ib_attach(px_t *px_p);
extern void px_ib_detach(px_t *px_p);
extern void px_ib_intr_enable(px_t *px_p, cpuid_t cpuid, devino_t ino);
extern void px_ib_intr_disable(px_ib_t *ib_p, devino_t ino, int wait);
extern void px_ib_intr_dist_en(dev_info_t *dip, cpuid_t cpu_id, devino_t ino,
    boolean_t wait_flag);

extern px_ino_t *px_ib_locate_ino(px_ib_t *ib_p, devino_t ino_num);
extern void px_ib_free_ino_all(px_ib_t *ib_p);

extern px_ino_pil_t *px_ib_ino_locate_ipil(px_ino_t *ino_p, uint_t pil);
extern px_ino_t *px_ib_alloc_ino(px_ib_t *ib_p, devino_t ino_num);
extern px_ino_pil_t *px_ib_new_ino_pil(px_ib_t *ib_p, devino_t ino_num,
    uint_t pil, px_ih_t *ih_p);
extern void px_ib_delete_ino_pil(px_ib_t *ib_p, px_ino_pil_t *ipil_p);
extern int px_ib_ino_add_intr(px_t *px_p, px_ino_pil_t *ipil_p, px_ih_t *ih_p);
extern int px_ib_ino_rem_intr(px_t *px_p, px_ino_pil_t *ipil_p, px_ih_t *ih_p);

extern px_ih_t *px_ib_intr_locate_ih(px_ino_pil_t *ipil_p, dev_info_t *dip,
	uint32_t inum, msiq_rec_type_t rec_type, msgcode_t msg_code);
extern px_ih_t *px_ib_alloc_ih(dev_info_t *rdip, uint32_t inum,
	uint_t (*int_handler)(caddr_t int_handler_arg1,
	caddr_t int_handler_arg2), caddr_t int_handler_arg1,
	caddr_t int_handler_arg2, msiq_rec_type_t rec_type, msgcode_t msg_code);
extern void px_ib_free_ih(px_ih_t *ih_p);
extern int px_ib_update_intr_state(px_t *px_p, dev_info_t *rdip, uint_t inum,
	devino_t ino, uint_t pil, uint_t new_intr_state,
	msiq_rec_type_t rec_type, msgcode_t msg_code);
extern int px_ib_get_intr_target(px_t *px_p, devino_t ino, cpuid_t *cpu_id_p);
extern int px_ib_set_intr_target(px_t *px_p, devino_t ino, cpuid_t cpu_id);
extern int px_ib_set_msix_target(px_t *px_p, ddi_intr_handle_impl_t *hdlp,
	msinum_t msi_num, cpuid_t cpuid);
extern uint8_t pxtool_ib_get_ino_devs(px_t *px_p, uint32_t ino,
	uint32_t msi_num, uint8_t *devs_ret, pcitool_intr_dev_t *devs);
extern int pxtool_ib_get_msi_info(px_t *px_p, devino_t ino, msinum_t msi_num,
	ddi_intr_handle_impl_t *hdlp);
extern void px_ib_log_new_cpu(px_ib_t *ib_p, cpuid_t old_cpu_id,
	cpuid_t new_cpu_id, uint32_t ino);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_IB_H */
