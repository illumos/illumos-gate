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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef	_SYS_PCIE_HP_H
#define	_SYS_PCIE_HP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/ddi_hp.h>
#include <sys/pcie_impl.h>
#endif /* _KERNEL */
#include "../../../../../common/pci/pci_strings.h"
#include <sys/hotplug/pci/pcihp.h>

#define	PCIEHPC_PROP_HELP		"help"
#define	PCIEHPC_PROP_ALL		"all"
#define	PCIEHPC_PROP_LED_FAULT		"fault_led"
#define	PCIEHPC_PROP_LED_POWER		"power_led"
#define	PCIEHPC_PROP_LED_ATTN		"attn_led"
#define	PCIEHPC_PROP_LED_ACTIVE		"active_led"
#define	PCIEHPC_PROP_CARD_TYPE		"card_type"
#define	PCIEHPC_PROP_BOARD_TYPE		"board_type"
#define	PCIEHPC_PROP_SLOT_CONDITION	"slot_condition"

#define	PCIEHPC_PROP_VALUE_UNKNOWN	"unknown"
#define	PCIEHPC_PROP_VALUE_ON		"on"
#define	PCIEHPC_PROP_VALUE_OFF		"off"
#define	PCIEHPC_PROP_VALUE_BLINK	"blink"
#define	PCIEHPC_PROP_VALUE_PCIHOTPLUG	"pci hotplug"
#define	PCIEHPC_PROP_VALUE_OK		"ok"
#define	PCIEHPC_PROP_VALUE_FAILING	"failing"
#define	PCIEHPC_PROP_VALUE_FAILED	"failed"
#define	PCIEHPC_PROP_VALUE_UNUSABLE	"unusable"
#define	PCIEHPC_PROP_VALUE_LED		"<on|off|blink>"
#define	PCIEHPC_PROP_VALUE_TYPE		"<type description>"
#define	PCIEHPC_PROP_VALUE_CONDITION	"<unknown|ok|failing|failed|unusable>"

/* condition */
#define	PCIEHPC_PROP_COND_OK		"ok"
#define	PCIEHPC_PROP_COND_FAILING	"failing"
#define	PCIEHPC_PROP_COND_FAILED	"failed"
#define	PCIEHPC_PROP_COND_UNUSABLE	"unusable"
#define	PCIEHPC_PROP_COND_UNKNOWN	"unknown"

#ifdef _KERNEL

#define	PCIE_HP_MAX_SLOTS		31	/* Max # of slots */
#define	PCIE_HP_CMD_WAIT_TIME		10000	/* Delay in microseconds */
#define	PCIE_HP_CMD_WAIT_RETRY		100	/* Max retry count */
#define	PCIE_HP_DLL_STATE_CHANGE_TIMEOUT 1	/* Timeout in seconds */
#define	PCIE_HP_POWER_GOOD_WAIT_TIME	220000	/* Wait time after issuing a */
						/* cmd to change slot state */

/* definations for PCIEHPC/PCISHPC */
#define	PCIE_NATIVE_HP_TYPE	"PCIe-Native"		/* PCIe Native type */
#define	PCIE_ACPI_HP_TYPE	"PCIe-ACPI"		/* PCIe ACPI type */
#define	PCIE_PROP_HP_TYPE	"PCIe-Proprietary"	/* PCIe Prop type */
#define	PCIE_PCI_HP_TYPE	"PCI-SHPC"		/* PCI (SHPC) type */

#define	PCIE_GET_HP_CTRL(dip)	\
	(pcie_hp_ctrl_t *)PCIE_DIP2BUS(dip)->bus_hp_ctrl

#define	PCIE_SET_HP_CTRL(dip, ctrl_p) \
	(PCIE_DIP2BUS(dip)->bus_hp_ctrl) = (pcie_hp_ctrl_t *)ctrl_p

#define	PCIE_IS_PCIE_HOTPLUG_CAPABLE(bus_p) \
	((bus_p->bus_hp_sup_modes & PCIE_ACPI_HP_MODE) || \
	(bus_p->bus_hp_sup_modes & PCIE_NATIVE_HP_MODE))

#define	PCIE_IS_PCI_HOTPLUG_CAPABLE(bus_p) \
	(bus_p->bus_hp_sup_modes & PCIE_PCI_HP_MODE)

#define	PCIE_IS_PCIE_HOTPLUG_ENABLED(bus_p) \
	((bus_p->bus_hp_curr_mode == PCIE_ACPI_HP_MODE) || \
	(bus_p->bus_hp_curr_mode == PCIE_NATIVE_HP_MODE))

#define	PCIE_IS_PCI_HOTPLUG_ENABLED(bus_p) \
	(bus_p->bus_hp_curr_mode & PCIE_PCI_HP_MODE)

typedef struct pcie_hp_ctrl pcie_hp_ctrl_t;
typedef struct pcie_hp_slot pcie_hp_slot_t;

/*
 * Maximum length of the string converted from the digital number of pci device
 * number and function number, including the string's end mark. For example,
 * device number 0 and function number 255 (ARI case), then the length is
 * (1 + 3 + 1).
 */
#define	PCIE_HP_DEV_FUNC_NUM_STRING_LEN 5

/*
 * Length of the characters in a PCI port name.
 * The format of the PCI port name is: pci.d,f where d is device number, f is
 * function number. The constant string and characters are "pci." and ",".
 */
#define	PCIE_HP_PORT_NAME_STRING_LEN	5

/* Platform specific ops (Native HP, ACPI, etc.) */
typedef struct pcie_hp_ops {
	/* initialize/setup hot plug controller hw */
	int	(*init_hpc_hw)(pcie_hp_ctrl_t *ctrl_p);

	/* uninitialize hot plug controller hw */
	int	(*uninit_hpc_hw)(pcie_hp_ctrl_t *ctrl_p);

	/* initialize slot information structure */
	int	(*init_hpc_slotinfo)(pcie_hp_ctrl_t *ctrl_p);

	/* uninitialize slot information structure */
	int	(*uninit_hpc_slotinfo)(pcie_hp_ctrl_t *ctrl_p);

	/* slot poweron */
	int	(*poweron_hpc_slot)(pcie_hp_slot_t *slot_p,
	    ddi_hp_cn_state_t *result);

	/* slot poweroff */
	/* uninitialize hot plug controller hw */
	int	(*poweroff_hpc_slot)(pcie_hp_slot_t *slot_p,
	    ddi_hp_cn_state_t *result);

	/* enable hot plug interrupts/events */
	int	(*enable_hpc_intr)(pcie_hp_ctrl_t *ctrl_p);

	/* disable hot plug interrupts/events */
	int	(*disable_hpc_intr)(pcie_hp_ctrl_t *ctrl_p);
} pcie_hp_ops_t;

/* Slot occupant information structure */
#define	PCIE_HP_MAX_OCCUPANTS	128
typedef struct pcie_hp_occupant_info {
	int	i;
	char	*id[PCIE_HP_MAX_OCCUPANTS];
} pcie_hp_occupant_info_t;

/*
 * pcie_hp_led_t
 *
 * Type definitions for LED type
 */
typedef	enum {
	PCIE_HP_FAULT_LED,
	PCIE_HP_POWER_LED,
	PCIE_HP_ATTN_LED,
	PCIE_HP_ACTIVE_LED
} pcie_hp_led_t;

/*
 * pcie_hp_led_state_t
 *
 * Type definitions for LED state
 */
typedef	enum {
	PCIE_HP_LED_OFF,
	PCIE_HP_LED_ON,
	PCIE_HP_LED_BLINK
} pcie_hp_led_state_t;

/*
 * PCI and PCI Express Hotplug slot structure
 */
struct pcie_hp_slot {
	uint32_t	hs_num;			/* Logical slot number */
	uint32_t	hs_phy_slot_num;	/* Physical slot number */
	uint32_t	hs_device_num;		/* PCI device num for slot */
	uint16_t	hs_minor;		/* Minor num for this slot */
	ddi_hp_cn_info_t hs_info;		/* Slot information */
	ddi_hp_cn_state_t hs_state;		/* Slot state */

	pcie_hp_led_state_t hs_power_led_state;		/* Power LED state */
	pcie_hp_led_state_t hs_attn_led_state;		/* Attn LED state */
	pcie_hp_led_state_t hs_active_led_state;	/* Active LED state */
	pcie_hp_led_state_t hs_fault_led_state;		/* Fault LED state */

	ap_condition_t	hs_condition;		/* Condition of the slot. */
						/* For cfgadm condition. */

	/* Synchronization variable(s) for hot plug events */
	kcondvar_t	hs_attn_btn_cv;		/* ATTN button pressed intr */
	boolean_t	hs_attn_btn_pending;
	kthread_t	*hs_attn_btn_threadp;	/* ATTN button event thread */
	boolean_t	hs_attn_btn_thread_exit;
	kcondvar_t	hs_dll_active_cv;	/* DLL State Changed intr */

	pcie_hp_ctrl_t	*hs_ctrl;		/* Hotplug ctrl for this slot */
};

/*
 * Register ops for read/write of non-standard HPC (e.g: OPL platform).
 */
typedef struct pcie_hp_regops {
	uint_t	(*get)(void *cookie, off_t offset);
	uint_t	(*put)(void *cookie, off_t offset, uint_t val);
	void	*cookie;
} pcie_hp_regops_t;

/*
 * PCI and PCI Express Hotplug controller structure
 */
struct pcie_hp_ctrl {
	dev_info_t	*hc_dip;		/* DIP for HP controller */
	kmutex_t	hc_mutex;		/* Mutex for this ctrl */
	uint_t		hc_flags;		/* Misc flags */

	/* Slot information */
	pcie_hp_slot_t	*hc_slots[PCIE_HP_MAX_SLOTS]; /* Slot pointers */
	boolean_t	hc_has_attn;		/* Do we have attn btn?	*/
	boolean_t	hc_has_mrl;		/* Do we have MRL? */
	boolean_t	hc_has_pwr;		/* Do we have a power ctl? */
	kcondvar_t	hc_cmd_comp_cv;		/* Command Completion intr */
	boolean_t	hc_cmd_pending;		/* Command completion pending */

	/* PCI Express Hotplug specific fields */
	boolean_t	hc_has_emi_lock;	/* Do we have EMI Lock? */
	boolean_t	hc_dll_active_rep;	/* Report DLL DL_Active state */
	taskqid_t	hc_startup_sync;	/* Startup synched? */
	pcie_hp_ops_t	hc_ops;			/* Platform specific ops */
						/* (Native, ACPI) */

	/* PCI Hotplug (SHPC) specific fields */
	uint32_t	hc_num_slots_impl;	/* # of HP Slots Implemented */
	uint32_t	hc_num_slots_connected;	/* # of HP Slots Connected */
	int		hc_curr_bus_speed;	/* Current Bus Speed */
	uint32_t	hc_device_start;	/* 1st PCI Device # */
	uint32_t	hc_phys_start;		/* 1st Phys Device # */
	uint32_t	hc_device_increases;	/* Device # Increases */
	boolean_t	hc_arbiter_timeout;	/* Got a Arb timeout IRQ */

	/* Register read/write ops for non-standard HPC (e.g: OPL) */
	pcie_hp_regops_t hc_regops;

	/* Platform implementation specific data if any: ACPI, CK804,... */
	void		*hc_misc_data;
};

/*
 * Control structure for tree walk during configure/unconfigure operation.
 */
typedef struct pcie_hp_cn_cfg_t {
	void *slotp;
	boolean_t		flag;		/* Flag to ignore errors */
	int			rv;		/* Return error code */
	dev_info_t		*dip;		/* dip at which the (first) */
						/* error occurred */
	void			*cn_private;	/* Connection specific data */
} pcie_hp_cn_cfg_t;

/*
 * arg for unregistering port of a pci bridge
 */
typedef struct pcie_hp_unreg_port {
	/* pci bridge dip to which the port is associated */
	dev_info_t	*nexus_dip;
	/*
	 * Connector number of the physical slot whose dependent ports will be
	 * unregistered. If NULL, then all the ports of the pci bridge dip will
	 * be unregistered.
	 */
	int		connector_num;
	int		rv;
} pcie_hp_unreg_port_t;

/*
 * arg for getting a port's state
 */
typedef struct pcie_hp_port_state {
	char			*cn_name;
	ddi_hp_cn_state_t	cn_state;
	int			rv;
} pcie_hp_port_state_t;

/* hc_flags */
#define	PCIE_HP_INITIALIZED_FLAG	(1 << 0) /* HPC initialized */
/*
 * These two flags are all related to initial synchronization. See
 * uts/common/io/pciex/hotplug/pciehpc.c for more information. The first is used
 * to track that this is required while the second indicates that it's actively
 * occurring.
 */
#define	PCIE_HP_SYNC_PENDING		(1 << 1)
#define	PCIE_HP_SYNC_RUNNING		(1 << 2)

/* PCIe hotplug friendly functions */
extern int pcie_hp_init(dev_info_t *dip, caddr_t arg);
extern int pcie_hp_uninit(dev_info_t *dip);
extern int pcie_hp_intr(dev_info_t *dip);
extern int pcie_hp_probe(pcie_hp_slot_t *slot_p);
extern int pcie_hp_unprobe(pcie_hp_slot_t *slot_p);
extern int pcie_hp_common_ops(dev_info_t *dip, char *cn_name, ddi_hp_op_t op,
    void *arg, void *result);
extern dev_info_t *pcie_hp_devi_find(dev_info_t *dip, uint_t device,
    uint_t function);
extern void pcie_hp_create_occupant_props(dev_info_t *self, dev_t dev,
    int pci_dev);
extern void pcie_hp_create_occupant_props(dev_info_t *self, dev_t dev,
    int pci_dev);
extern void pcie_hp_delete_occupant_props(dev_info_t *dip, dev_t dev);
extern int pcie_copyin_nvlist(char *packed_buf, size_t packed_sz,
    nvlist_t **nvlp);
extern int pcie_copyout_nvlist(nvlist_t *nvl, char *packed_buf,
    size_t *packed_sz);
extern char *pcie_led_state_text(pcie_hp_led_state_t state);
extern char *pcie_slot_condition_text(ap_condition_t condition);
extern int pcie_create_minor_node(pcie_hp_ctrl_t *, int);
extern void pcie_remove_minor_node(pcie_hp_ctrl_t *, int);
extern void pcie_hp_gen_sysevent_req(char *slot_name, int hint,
    dev_info_t *self, int kmflag);

extern const struct pci_class_strings_s class_pci[];
extern int class_pci_items;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIE_HP_H */
