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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_HOTPLUG_PCI_PCIEHPC_IMPL_H
#define	_SYS_HOTPLUG_PCI_PCIEHPC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/disp.h>
#include <sys/stat.h>
#include <sys/condvar.h>
#include <sys/pcie.h>
#include <sys/hotplug/hpcsvc.h>
#include <sys/hotplug/pci/pciehpc.h>

/*
 * PCI Express Hot Plug slot softstate structure
 *
 */
typedef struct pciehpc_slot
{
	hpc_slot_info_t	slot_info;		/* HPS framework slot info */
	hpc_slot_t	slot_handle;		/* HPS framework handle */
	hpc_slot_ops_t	slot_ops;		/* HPS framework callbacks */
	uint32_t	fault_led_state;	/* Fault LED state */
	uint32_t	power_led_state;	/* Power LED state */
	uint32_t	attn_led_state;		/* Attn LED state */
	uint32_t	active_led_state;	/* Active LED state */
	hpc_slot_state_t slot_state;		/* Slot State */
	uint32_t	slotNum;		/* slot number */
	/* synchronization variable(s) for hot plug events */
	kcondvar_t	cmd_comp_cv;		/* Command Completion intr. */
	boolean_t	command_pending;
	kcondvar_t	attn_btn_cv;		/* ATTN button pressed intr */
	boolean_t	attn_btn_pending;
	kthread_t	*attn_btn_threadp;	/* ATTN button event thread */
	boolean_t	attn_btn_thread_exit;
	kcondvar_t	dll_active_cv;		/* DLL State Changed intr */
} pciehpc_slot_t;

typedef enum {
	PCIEHPC_NATIVE_HP_MODE, PCIEHPC_ACPI_HP_MODE
} pciehpc_hp_mode_t;

typedef uint32_t pciehpc_soft_state_t;

/* init_flags */
#define	PCIEHPC_SOFT_STATE_UNINITIALIZED	0x01
#define	PCIEHPC_SOFT_STATE_INITIALIZED		0x02
#define	PCIEHPC_SOFT_STATE_INIT_HTABLE		0x04
#define	PCIEHPC_SOFT_STATE_INIT_ALLOC		0x08
#define	PCIEHPC_SOFT_STATE_INIT_HANDLER		0x10
#define	PCIEHPC_SOFT_STATE_INIT_ENABLE		0x20
#define	PCIEHPC_SOFT_STATE_INIT_BLOCK		0x40
#define	PCIEHPC_SOFT_STATE_INIT_FM		0x80
#define	PCIEHPC_SOFT_STATE_PCIE_DEV		0x10000

/*
 * PCI Express Hotplug controller soft state structure
 */
typedef struct pciehpc
{
	dev_info_t		*dip;		/* DIP for the Nexus */
	uint8_t			bus;		/* primary bus number */
	uint8_t			dev;		/* device number */
	uint8_t			func;		/* function number */
	kmutex_t		pciehpc_mutex;	/* Mutex for this ctrl */
	pciehpc_soft_state_t	soft_state;	/* soft state flags */
	pciehpc_hp_mode_t	hp_mode;	/* HP mode (Native, ACPI) */
	struct pciehpc		*nextp;		/* Linked list pointer */

	/* PCIE Hot Plug Controller register access */
	ddi_acc_handle_t	cfghdl;		/* PCI cfg access handle */
	caddr_t			regs_base;	/* config regs base */
	uint_t		pcie_caps_reg_offset;	/* offset to PCIE Cap regs */

	/* slot information */
	pciehpc_slot_t		slot;		/* Slot info */
	boolean_t		has_attn;	/* Do we have attn btn? */
	boolean_t		has_mrl;	/* Do we have MRL? */
	boolean_t		has_emi_lock;	/* Do we have EMI Lock? */

	/* link capablities */
	boolean_t	dll_active_rep;	/* Do we report DLL DL_Active state? */

	/* register read/write ops for non-standard HPC (e.g: OPL) */
	pciehpc_regops_t	regops;

	/* platform specific ops (Native HP, ACPI, etc.) */
	struct pciehpc_ops {
		/* initialize/setup hot plug controller hw */
		int	(*init_hpc_hw)(struct pciehpc *ctrl_p);
		/* initialize slot information structure */
		int	(*init_hpc_slotinfo)(struct pciehpc *ctrl_p);
		/* disable hot plug interrupts/events */
		int	(*disable_hpc_intr)(struct pciehpc *ctrl_p);
		/* enable hot plug interrupts/events */
		int	(*enable_hpc_intr)(struct pciehpc *ctrl_p);
		/* uninitialize hot plug controller hw */
		int	(*uninit_hpc_hw)(struct pciehpc *ctrl_p);
		/* uninitialize slot information structure */
		int	(*uninit_hpc_slotinfo)(struct pciehpc *ctrl_p);
		/* probe for HPC */
		int	(*probe_hpc)(struct pciehpc *ctrl_p);
	} ops;

	/* platform implementation specific data if any: ACPI, CK804,... */
	void			*misc_data;
} pciehpc_t;

typedef struct pciehpc_ops pciehpc_ops_t;

/*
 * PCI-E HPC Command Completion delay in microseconds and the max retry
 * count.
 */
#define	PCIEHPC_CMD_WAIT_TIME	10000
#define	PCIEHPC_CMD_WAIT_RETRY	100

/*
 * PCI-E HPC Dll State Change time out in seconds
 */
#define	PCIEHPC_DLL_STATE_CHANGE_TIMEOUT 1

#define	SLOTCTL_SUPPORTED_INTRS_MASK	\
	(PCIE_SLOTCTL_ATTN_BTN_EN \
	| PCIE_SLOTCTL_PWR_FAULT_EN \
	| PCIE_SLOTCTL_MRL_SENSOR_EN \
	| PCIE_SLOTCTL_PRESENCE_CHANGE_EN \
	| PCIE_SLOTCTL_CMD_INTR_EN \
	| PCIE_SLOTCTL_HP_INTR_EN \
	| PCIE_SLOTCTL_DLL_STATE_EN)

#define	SLOT_STATUS_EVENTS	\
	(PCIE_SLOTSTS_ATTN_BTN_PRESSED \
	| PCIE_SLOTSTS_PWR_FAULT_DETECTED \
	| PCIE_SLOTSTS_MRL_SENSOR_CHANGED \
	| PCIE_SLOTSTS_COMMAND_COMPLETED \
	| PCIE_SLOTSTS_PRESENCE_CHANGED \
	| PCIE_SLOTSTS_DLL_STATE_CHANGED)

/*
 * function prototype defintions for common native mode functions in
 * PCIEHPC module.
 */
int pciehpc_hpc_init(pciehpc_t *ctrl_p);
int pciehpc_hpc_uninit(pciehpc_t *ctrl_p);
int pciehpc_slotinfo_init(pciehpc_t *ctrl_p);
int pciehpc_enable_intr(pciehpc_t *ctrl_p);
int pciehpc_disable_intr(pciehpc_t *ctrl_p);
int pciehpc_slotinfo_uninit(pciehpc_t *ctrl_p);
int pciehpc_probe_hpc(pciehpc_t *ctrl_p);
hpc_led_state_t pciehpc_led_state_to_hpc(uint16_t state);
uint16_t pciehpc_led_state_to_pciehpc(hpc_led_state_t state);
hpc_led_state_t pciehpc_get_led_state(pciehpc_t *ctrl_p, hpc_led_t led);
void pciehpc_set_led_state(pciehpc_t *ctrl_p, hpc_led_t led,
	hpc_led_state_t state);
int pciehpc_slot_connect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags);
int pciehpc_slot_disconnect(caddr_t ops_arg, hpc_slot_t slot_hdl,
	void *data, uint_t flags);
int pciehpc_slot_control(caddr_t ops_arg, hpc_slot_t slot_hdl,
	int request, caddr_t arg);
void pciehpc_get_slot_state(pciehpc_t *ctrl_p);
void pciehpc_issue_hpc_command(pciehpc_t *ctrl_p, uint16_t control);
int pciehpc_regs_setup(dev_info_t *dip, uint_t rnum, offset_t off,
	caddr_t *addrp, ddi_acc_handle_t *handle);
void pciehpc_regs_teardown(ddi_acc_handle_t *handle);
int pciehpc_register_slot(pciehpc_t *ctrl_p);
int pciehpc_unregister_slot(pciehpc_t *ctrl_p);
uint8_t pciehpc_reg_get8(pciehpc_t *ctrl_p, uint_t off);
uint16_t pciehpc_reg_get16(pciehpc_t *ctrl_p, uint_t off);
uint32_t pciehpc_reg_get32(pciehpc_t *ctrl_p, uint_t off);
void pciehpc_reg_put8(pciehpc_t *ctrl_p, uint_t off, uint8_t val);
void pciehpc_reg_put16(pciehpc_t *ctrl_p, uint_t off, uint16_t val);
void pciehpc_reg_put32(pciehpc_t *ctrl_p, uint_t off, uint32_t val);
void pciehpc_set_slot_name(pciehpc_t *ctrl_p);

#if	defined(__i386) || defined(__amd64)
void pciehpc_update_ops(pciehpc_t *ctrl_p);
#endif	/* defined(__i386) || defined(__amd64) */

#ifdef DEBUG
extern int pciehpc_debug;
#define	PCIEHPC_DEBUG(args)	if (pciehpc_debug >= 1) cmn_err args
#define	PCIEHPC_DEBUG2(args)	if (pciehpc_debug >= 2) cmn_err args
#define	PCIEHPC_DEBUG3(args)	if (pciehpc_debug >= 3) cmn_err args
#else
#define	PCIEHPC_DEBUG(args)
#define	PCIEHPC_DEBUG2(args)
#define	PCIEHPC_DEBUG3(args)
#endif

/* default interrupt priority for Hot Plug interrupts */
#define	PCIEHPC_INTR_PRI	1

#if	defined(__sparc)
#define	PCIE_ENABLE_ERRORS(arg1, arg2)	\
	pcie_enable_errors(arg1, arg2);	\
	(void) pcie_enable_ce(arg1, arg2)
#define	PCIE_DISABLE_ERRORS(arg1, arg2)	pcie_disable_errors(arg1, arg2)
#else
#define	PCIE_ENABLE_ERRORS(arg1, arg2)	pcie_error_enable(arg1, arg2)
#define	PCIE_DISABLE_ERRORS(arg1, arg2)	pcie_error_disable(arg1, arg2)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HOTPLUG_PCI_PCIEHPC_IMPL_H */
