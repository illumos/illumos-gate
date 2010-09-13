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
 */

#ifndef _SYS_PCICMU_H
#define	_SYS_PCICMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/pci.h>
#include <sys/pci_intr_lib.h>
#include <sys/pcicmu/pcmu_types.h>
#include <sys/pcicmu/pcmu_ib.h>
#include <sys/pcicmu/pcmu_cb.h>
#include <sys/pcicmu/pcmu_ecc.h>
#include <sys/pcicmu/pcmu_pbm.h>
#include <sys/pcicmu/pcmu_counters.h>
#include <sys/pcicmu/pcmu_util.h>
#include <sys/pcicmu/pcmu_err.h>


/*
 * The following typedef is used to represent a
 * 1275 "bus-range" property of a PCI Bus node.
 */
struct pcmu_bus_range {
	uint32_t lo;
	uint32_t hi;
};

/*
 * Structure to represent an entry in the
 * "ranges" property of a device node.
 */
struct pcmu_ranges {
	uint32_t child_high;
	uint32_t child_mid;
	uint32_t child_low;
	uint32_t parent_high;
	uint32_t parent_low;
	uint32_t size_high;
	uint32_t size_low;
};

typedef enum {
	PCMU_NEW,
	PCMU_ATTACHED,
	PCMU_DETACHED,
	PCMU_SUSPENDED
} pcmu_state_t;

typedef enum {
	PCMU_PBM_OBJ,
	PCMU_ECC_OBJ,
	PCMU_CB_OBJ
} pcmu_obj_t;

typedef enum {
	PCMU_OBJ_INTR_ADD,
	PCMU_OBJ_INTR_REMOVE
} pcmu_obj_op_t;

#define	PCI_OPLCMU	"pcicmu"

/*
 * pcicmu soft state structure.
 */
struct pcicmu {
	/*
	 * State flags and mutex:
	 */
	pcmu_state_t pcmu_state;
	uint_t pcmu_soft_state;
	uint_t pcmu_open_count;
	kmutex_t pcmu_mutex;

	/*
	 * Links to other state structures:
	 */
	dev_info_t *pcmu_dip;			/* devinfo structure */
	pcmu_ib_t *pcmu_ib_p;			/* interrupt block */
	pcmu_cb_t *pcmu_cb_p;			/* control block */
	pcmu_pbm_t *pcmu_pcbm_p;		/* PBM block */
	pcmu_ecc_t *pcmu_pecc_p;		/* ECC error block */

	/*
	 * other state info:
	 */
	uint_t pcmu_id;			/* Jupiter device id */
	uint32_t pcmu_rev;		/* Bus bridge chip identification */

	/*
	 * pci device node properties:
	 */
	pcmu_bus_range_t pcmu_bus_range;	/* "bus-range" */
	pcmu_ranges_t *pcmu_ranges;	/* "ranges" data & length */
	int pcmu_ranges_length;
	uint32_t *pcmu_inos;		/* inos from "interrupts" prop */
	int pcmu_inos_len;		/* "interrupts" length */
	int pcmu_numproxy;		/* upa interrupt proxies */

	/*
	 * register mapping:
	 */
	caddr_t pcmu_address[4];
	ddi_acc_handle_t pcmu_ac[4];

	/*
	 * Performance counters kstat.
	 */
	pcmu_cntr_pa_t	pcmu_uks_pa;
	kstat_t	*pcmu_uksp;		/* ptr to upstream kstat */
	kmutex_t pcmu_err_mutex;	/* per chip error handling mutex */

	/* Fault Management support */
	int pcmu_fm_cap;
	ddi_iblock_cookie_t pcmu_fm_ibc;
};

/*
 * pcmu_soft_state values.
 */
#define	PCMU_SOFT_STATE_OPEN		0x01
#define	PCMU_SOFT_STATE_OPEN_EXCL	0x02
#define	PCMU_SOFT_STATE_CLOSED		0x04

/*
 * CMU-CH and PBM soft state macros:
 */
#define	PCMU_AP_MINOR_NUM_TO_INSTANCE(x)	((x) >> 8)

#define	get_pcmu_soft_state(i)	\
	((pcmu_t *)ddi_get_soft_state(per_pcmu_state, (i)))

#define	alloc_pcmu_soft_state(i)	\
	ddi_soft_state_zalloc(per_pcmu_state, (i))

#define	free_pcmu_soft_state(i)	\
	ddi_soft_state_free(per_pcmu_state, (i))

#define	DEV_TO_SOFTSTATE(dev)	((pcmu_t *)ddi_get_soft_state(per_pcmu_state, \
	PCMU_AP_MINOR_NUM_TO_INSTANCE(getminor(dev))))

#define	PCMU_ATTACH_RETCODE(obj, op, err) \
	((err) ? (obj) << 8 | (op) << 4 | (err) & 0xf : DDI_SUCCESS)


/*
 * Performance counters information.
 */
#define	PCMU_SHIFT_PIC0	8
#define	PCMU_SHIFT_PIC1	0

/*
 * CMU-CH-specific register offsets & bit field positions.
 */

/*
 * Offsets of global registers:
 */
#define	PCMU_CB_DEVICE_ID_REG_OFFSET		0x00000000	/* RAGS */
#define	PCMU_CB_CONTROL_STATUS_REG_OFFSET	0x00000010

/*
 * CMU-CH performance counters offsets.
 */
#define	PCMU_PERF_PCR_OFFSET			0x00000100
#define	PCMU_PERF_PIC_OFFSET			0x00000108

/*
 * Offsets of registers in the interrupt block:
 */
#define	PCMU_IB_OBIO_INTR_MAP_REG_OFFSET	0x00001000
#define	PCMU_IB_OBIO_CLEAR_INTR_REG_OFFSET	0x00001800

/*
 * Offsets of registers in the PBM block:
 */
#define	PCMU_PCI_PBM_REG_BASE			0x00002000 /* RAGS */
#define	PCMU_PCI_CTRL_REG_OFFSET		0x00000000
#define	PCMU_PCI_ASYNC_FLT_STATUS_REG_OFFSET	0x00000010
#define	PCMU_PCI_ASYNC_FLT_ADDR_REG_OFFSET	0x00000018
#define	PCMU_PCI_DIAG_REG_OFFSET		0x00000020

/*
 * CMU-CH control register bit definitions:
 */
#define	PCMU_CB_CONTROL_STATUS_MODE		0x0000000000000001ull
#define	PCMU_CB_CONTROL_STATUS_IMPL		0xf000000000000000ull
#define	PCMU_CB_CONTROL_STATUS_IMPL_SHIFT	60
#define	PCMU_CB_CONTROL_STATUS_VER		0x0f00000000000000ull
#define	PCMU_CB_CONTROL_STATUS_VER_SHIFT	56

/*
 * CMU-CH ECC UE AFSR bit definitions:
 */
#define	PCMU_ECC_UE_AFSR_BYTEMASK		0x0000ffff00000000ull
#define	PCMU_ECC_UE_AFSR_BYTEMASK_SHIFT		32
#define	PCMU_ECC_UE_AFSR_DW_OFFSET		0x00000000e0000000ull
#define	PCMU_ECC_UE_AFSR_DW_OFFSET_SHIFT	29
#define	PCMU_ECC_UE_AFSR_ID			0x000000001f000000ull
#define	PCMU_ECC_UE_AFSR_ID_SHIFT		24
#define	PCMU_ECC_UE_AFSR_BLK			0x0000000000800000ull

/*
 * CMU-CH pci control register bits:
 */
#define	PCMU_PCI_CTRL_ARB_PARK			0x0000000000200000ull
#define	PCMU_PCI_CTRL_WAKEUP_EN			0x0000000000000200ull
#define	PCMU_PCI_CTRL_ERR_INT_EN		0x0000000000000100ull
#define	PCMU_PCI_CTRL_ARB_EN_MASK		0x000000000000000full

/*
 * CMU-CH PCI asynchronous fault status register bit definitions:
 */
#define	PCMU_PCI_AFSR_PE_SHIFT			60
#define	PCMU_PCI_AFSR_SE_SHIFT			56
#define	PCMU_PCI_AFSR_E_MA			0x0000000000000008ull
#define	PCMU_PCI_AFSR_E_TA			0x0000000000000004ull
#define	PCMU_PCI_AFSR_E_RTRY			0x0000000000000002ull
#define	PCMU_PCI_AFSR_E_PERR			0x0000000000000001ull
#define	PCMU_PCI_AFSR_E_MASK			0x000000000000000full
#define	PCMU_PCI_AFSR_BYTEMASK			0x0000ffff00000000ull
#define	PCMU_PCI_AFSR_BYTEMASK_SHIFT		32
#define	PCMU_PCI_AFSR_BLK			0x0000000080000000ull
#define	PCMU_PCI_AFSR_MID			0x000000003e000000ull
#define	PCMU_PCI_AFSR_MID_SHIFT			25

/*
 * CMU-CH PCI diagnostic register bit definitions:
 */
#define	PCMU_PCI_DIAG_DIS_DWSYNC		0x0000000000000010ull

#define	PBM_AFSR_TO_PRIERR(afsr)	\
	(afsr >> PCMU_PCI_AFSR_PE_SHIFT & PCMU_PCI_AFSR_E_MASK)
#define	PBM_AFSR_TO_SECERR(afsr)	\
	(afsr >> PCMU_PCI_AFSR_SE_SHIFT & PCMU_PCI_AFSR_E_MASK)

#define	PCMU_ID_TO_IGN(pcmu_id)		((pcmu_ign_t)UPAID_TO_IGN(pcmu_id))


/*
 * Number of dispatch target entries.
 */
#define	U2U_DATA_NUM  16

/*
 *  Offsets of registers in the Interrupt Dispatch Table:
 */
#define	U2U_MODE_STATUS_REGISTER_OFFSET		0x00000000
#define	U2U_PID_REGISTER_OFFSET			0x00000008
#define	U2U_DATA_REGISTER_OFFSET		0x00000010

/*
 * Mode Status register bit definitions:
 */
#define	U2U_MS_IEV    0x00000040	/* bit-6: Interrupt Extension enable */

/*
 * Index number of U2U registers in OBP's "regs-property" of CMU-CH
 */
#define	REGS_INDEX_OF_U2U	3

/*
 * The following two difinitions are used to control target id
 * for Interrupt dispatch data by software.
 */
typedef struct u2u_ittrans_id {
	uint_t u2u_tgt_cpu_id;			/* target CPU ID */
	uint_t u2u_rsv1;			/* reserved */
	volatile uint64_t *u2u_ino_map_reg;	/* u2u intr. map register */
} u2u_ittrans_id_t;

typedef struct u2u_ittrans_data {
	kmutex_t u2u_ittrans_lock;
	uintptr_t u2u_regs_base;	/* "reg" property */
	ddi_acc_handle_t u2u_acc;	/* pointer to acc */
	uint_t u2u_port_id;		/* "PID" register n U2U */
	uint_t u2u_board;		/* "board#" property */
	u2u_ittrans_id_t u2u_ittrans_id[U2U_DATA_NUM];
} u2u_ittrans_data_t;

/*
 * Driver binding name for OPL DC system
 */
#define	PCICMU_OPL_DC_BINDING_NAME		"pci10cf,1390"

/*
 * Offsets of registers in the interrupt block:
 */

#define	PCMU_IB_UPA0_INTR_MAP_REG_OFFSET	0x6000
#define	PCMU_IB_UPA1_INTR_MAP_REG_OFFSET	0x8000
#define	PCMU_IB_SLOT_CLEAR_INTR_REG_OFFSET	0x1400
#define	PCMU_IB_OBIO_INTR_STATE_DIAG_REG	0xA808
#define	PCMU_IB_INTR_RETRY_TIMER_OFFSET		0x1A00

/*
 * Offsets of registers in the ECC block:
 */
#define	PCMU_ECC_CSR_OFFSET			0x20
#define	PCMU_UE_AFSR_OFFSET			0x30
#define	PCMU_UE_AFAR_OFFSET			0x38

/*
 * CMU-CH control register bit definitions:
 */
#define	PCMU_CB_CONTROL_STATUS_IGN		0x0007c00000000000ull
#define	PCMU_CB_CONTROL_STATUS_IGN_SHIFT	46
#define	PCMU_CB_CONTROL_STATUS_APCKEN		0x0000000000000008ull
#define	PCMU_CB_CONTROL_STATUS_APERR		0x0000000000000004ull
#define	PCMU_CB_CONTROL_STATUS_IAP		0x0000000000000002ull

/*
 * CMU-CH interrupt mapping register bit definitions:
 */
#define	PCMU_INTR_MAP_REG_VALID			0x0000000080000000ull
#define	PCMU_INTR_MAP_REG_TID			0x000000007C000000ull
#define	PCMU_INTR_MAP_REG_IGN			0x00000000000007C0ull
#define	PCMU_INTR_MAP_REG_INO			0x000000000000003full
#define	PCMU_INTR_MAP_REG_TID_SHIFT		26
#define	PCMU_INTR_MAP_REG_IGN_SHIFT		6

/*
 * CMU-CH clear interrupt register bit definitions:
 */
#define	PCMU_CLEAR_INTR_REG_MASK		0x0000000000000003ull
#define	PCMU_CLEAR_INTR_REG_IDLE		0x0000000000000000ull
#define	PCMU_CLEAR_INTR_REG_RECEIVED		0x0000000000000001ull
#define	PCMU_CLEAR_INTR_REG_RSVD		0x0000000000000002ull
#define	PCMU_CLEAR_INTR_REG_PENDING		0x0000000000000003ull

/*
 * CMU-CH ECC control register bit definitions:
 */
#define	PCMU_ECC_CTRL_ECC_EN			0x8000000000000000ull
#define	PCMU_ECC_CTRL_UE_INTEN			0x4000000000000000ull

/*
 * CMU-CH ECC UE AFSR bit definitions:
 */
#define	PCMU_ECC_UE_AFSR_PE_SHIFT		61
#define	PCMU_ECC_UE_AFSR_SE_SHIFT		58
#define	PCMU_ECC_UE_AFSR_E_MASK			0x0000000000000007ull
#define	PCMU_ECC_UE_AFSR_E_PIO			0x0000000000000004ull

/*
 * CMU-CH PCI diagnostic register bit definitions:
 */
#define	PCMU_PCI_DIAG_DIS_RETRY			0x0000000000000040ull
#define	PCMU_PCI_DIAG_DIS_INTSYNC		0x0000000000000020ull


#define	NAMEINST(dip)	ddi_driver_name(dip), ddi_get_instance(dip)
#define	NAMEADDR(dip)	ddi_node_name(dip), ddi_get_name_addr(dip)


/*
 * CMU-CH Tunables
 */
extern uint32_t pcmu_spurintr_duration;		/* spurious interupt duration */
extern ushort_t pcmu_command_default;		/* default command */
extern uint_t ecc_error_intr_enable;		/* ECC error intr */
extern uint_t pcmu_ecc_afsr_retries;		/* num ECC afsr retries */
extern uint_t pcmu_intr_retry_intv;		/* intr retry interval */
extern uint_t pcmu_panic_on_fatal_errors;	/* PANIC on fatal errors */
extern uint_t pcmu_unclaimed_intr_max;		/* Max unclaimed interrupts */
extern hrtime_t pcmu_intrpend_timeout;		/* intr pending timeout */


extern void *per_pcmu_state;		/* per-pbm soft state pointer */
extern kmutex_t pcmu_global_mutex;	/* attach/detach common struct lock */
extern uint64_t pcmu_errtrig_pa;


/*
 * Prototypes.
 */
extern void pcmu_post_uninit_child(pcmu_t *);
extern void pcmu_kstat_init(void);
extern void pcmu_kstat_fini(void);
extern void pcmu_add_upstream_kstat(pcmu_t *);
extern void pcmu_fix_ranges(pcmu_ranges_t *, int);
extern uint_t pcmu_pbm_disable_errors(pcmu_pbm_t *);
extern uint32_t ib_map_reg_get_cpu(volatile uint64_t);
extern uint64_t *ib_intr_map_reg_addr(pcmu_ib_t *, pcmu_ib_ino_t);
extern uint64_t *ib_clear_intr_reg_addr(pcmu_ib_t *, pcmu_ib_ino_t);
extern void pcmu_cb_setup(pcmu_t *);
extern void pcmu_cb_teardown(pcmu_t *);
extern int cb_register_intr(pcmu_t *);
extern void cb_enable_intr(pcmu_t *);
extern uint64_t cb_ino_to_map_pa(pcmu_cb_t *, pcmu_ib_ino_t);
extern uint64_t cb_ino_to_clr_pa(pcmu_cb_t *, pcmu_ib_ino_t);
extern int cb_remove_xintr(pcmu_t *, dev_info_t *, dev_info_t *,
    pcmu_ib_ino_t, pcmu_ib_mondo_t);
extern uint32_t pcmu_intr_dist_cpuid(pcmu_ib_t *, pcmu_ib_ino_info_t *);
extern void pcmu_ecc_setup(pcmu_ecc_t *);
extern ushort_t pcmu_ecc_get_synd(uint64_t);
extern void pcmu_pbm_setup(pcmu_pbm_t *);
extern void pcmu_pbm_teardown(pcmu_pbm_t *);
extern uintptr_t pcmu_ib_setup(pcmu_ib_t *);
extern int pcmu_get_numproxy(dev_info_t *);
extern int pcmu_ecc_add_intr(pcmu_t *, int, pcmu_ecc_intr_info_t *);
extern void pcmu_ecc_rem_intr(pcmu_t *, int, pcmu_ecc_intr_info_t *);
extern int pcmu_pbm_err_handler(dev_info_t *, ddi_fm_error_t *,
    const void *, int);
extern void pcmu_ecc_classify(uint64_t, pcmu_ecc_errstate_t *);
extern int pcmu_pbm_classify(pcmu_pbm_errstate_t *);
extern int pcmu_check_error(pcmu_t *);
extern void set_intr_mapping_reg(int, uint64_t *, int);
extern uint32_t pcmu_class_to_pil(dev_info_t *rdip);
extern int pcmu_add_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);
extern int pcmu_remove_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp);
extern void pcmu_intr_teardown(pcmu_t *pcmu_p);

extern int u2u_translate_tgtid(pcmu_t *, uint_t, volatile uint64_t *);
extern void u2u_ittrans_cleanup(u2u_ittrans_data_t *, volatile uint64_t *);
void pcmu_err_create(pcmu_t *pcmu_p);
void pcmu_err_destroy(pcmu_t *pcmu_p);
void pcmu_pbm_ereport_post(dev_info_t *dip, uint64_t ena,
    pcmu_pbm_errstate_t *pbm_err);
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCICMU_H */
