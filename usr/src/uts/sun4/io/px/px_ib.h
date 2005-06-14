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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PX_IB_H
#define	_SYS_PX_IB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddi_subrdefs.h>

typedef struct px_ib_ino_info	px_ib_ino_info_t;

/*
 * interrupt block soft state structure:
 *
 * Each px node may share an interrupt block structure with its peer
 * node or have its own private interrupt block structure.
 */
typedef struct px_ib px_ib_t;
struct px_ib {
	px_t		*ib_px_p;	/* link back to px soft state */
	px_ib_ino_info_t	*ib_ino_lst;	/* ino link list */
	kmutex_t	ib_ino_lst_mutex; /* mutex for ino link list */
	kmutex_t	ib_intr_lock;	/* lock for internal intr  */

	px_msiq_state_t	ib_msiq_state;	/* MSIQ soft state */
	px_msi_state_t	ib_msi_state;	/* MSI soft state */
};

/*
 * The following structure represents an interrupt entry for an INO.
 */
typedef struct px_ih {
	dev_info_t	*ih_dip;	/* devinfo structure */
	uint32_t	ih_inum;	/* interrupt number for this device */
	uint_t		(*ih_handler)(); /* interrupt handler */
	caddr_t		ih_handler_arg1; /* interrupt handler argument #1 */
	caddr_t		ih_handler_arg2; /* interrupt handler argument #2 */
	ddi_acc_handle_t ih_config_handle; /* config space reg map handle */
	uint_t		ih_intr_state;	/* Only used for fixed interrupts */
	msiq_rec_type_t	ih_rec_type;	/* MSI or PCIe record type */
	msgcode_t	ih_msg_code;	/* MSI number or PCIe message code */
	struct px_ih	*ih_next;	/* next entry in list */
	uint64_t	ih_ticks;	/* ticks spent in this handler */
	uint64_t	ih_nsec;	/* nsec spent in this handler */
	kstat_t		*ih_ksp;
	struct px_ib_ino_info *ih_ino_p;	/* only for use by kstat */
} px_ih_t;

/* Only used for fixed or legacy interrupts */
#define	PX_INTR_STATE_DISABLE	0	/* disabled */
#define	PX_INTR_STATE_ENABLE	1	/* enabled */

/*
 * ino structure : one per each ino with interrupt registered
 */
struct px_ib_ino_info {
	devino_t	ino_ino;	/* INO number - 8 bit */
	sysino_t	ino_sysino;	/* Virtual inumber */
	uint16_t	ino_ih_size;	/* size of the px intrspec list */
	px_ih_t		*ino_ih_head;	/* intr spec (part of ppd) list head */
	px_ih_t		*ino_ih_tail;	/* intr spec (part of ppd) list tail */
	px_ih_t		*ino_ih_start;	/* starting point in intr spec list  */
	px_ib_t		*ino_ib_p;	/* link back to interrupt block state */
	uint32_t	ino_pil;	/* PIL for this ino */
	uint_t		ino_unclaimed;	/* number of unclaimed interrupts */
	clock_t		ino_spurintr_begin; /* begin time of spurious intr */
	cpuid_t		ino_cpuid;	/* cpu that ino is targeting */
	int32_t		ino_intr_weight; /* intr wt of devices sharing ino */
	px_msiq_t	*ino_msiq_p;	/* Pointer to MSIQ used */
	struct px_ib_ino_info *ino_next;
};

#define	IB_INTR_WAIT	1		/* wait for interrupt completion */
#define	IB_INTR_NOWAIT	0		/* already handling intr, no wait */

#define	PX_INTR_ENABLE(dip, sysino, cpuid) \
	px_lib_intr_settarget(dip, sysino, cpuid); \
	px_lib_intr_setstate(dip, sysino, INTR_IDLE_STATE); \
	px_lib_intr_setvalid(dip, sysino, INTR_VALID);

#define	PX_INTR_DISABLE(dip, sysino) \
	px_lib_intr_setvalid(dip, sysino, INTR_NOTVALID);

extern int px_ib_attach(px_t *px_p);
extern void px_ib_detach(px_t *px_p);
extern void px_ib_intr_enable(px_t *px_p, cpuid_t cpuid, devino_t ino);
extern void px_ib_intr_disable(px_ib_t *ib_p, devino_t ino, int wait);

extern px_ib_ino_info_t *px_ib_locate_ino(px_ib_t *ib_p, devino_t ino_num);
extern px_ib_ino_info_t *px_ib_new_ino(px_ib_t *ib_p, devino_t ino_num,
    px_ih_t *ih_p);
extern void px_ib_delete_ino(px_ib_t *ib_p, px_ib_ino_info_t *ino_p);
extern void px_ib_free_ino_all(px_ib_t *ib_p);
extern int px_ib_ino_add_intr(px_t *px_p, px_ib_ino_info_t *ino_p,
    px_ih_t *ih_p);
extern int px_ib_ino_rem_intr(px_t *px_p, px_ib_ino_info_t *ino_p,
    px_ih_t *ih_p);
extern px_ih_t *px_ib_ino_locate_intr(px_ib_ino_info_t *ino_p, dev_info_t *dip,
	uint32_t inum, msiq_rec_type_t rec_type, msgcode_t msg_code);
extern px_ih_t *px_ib_alloc_ih(dev_info_t *rdip, uint32_t inum,
	uint_t (*int_handler)(caddr_t int_handler_arg1,
	caddr_t int_handler_arg2), caddr_t int_handler_arg1,
	caddr_t int_handler_arg2, msiq_rec_type_t rec_type, msgcode_t msg_code);
extern void px_ib_free_ih(px_ih_t *ih_p);
extern int px_ib_update_intr_state(px_t *px_p, dev_info_t *rdip, uint_t inum,
	devino_t ino, uint_t new_intr_state);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_IB_H */
