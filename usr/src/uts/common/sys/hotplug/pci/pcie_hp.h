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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef	_SYS_PCIE_HP_H
#define	_SYS_PCIE_HP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/ddi_hp.h>
#include <sys/pcie_impl.h>
#include <sys/stdbool.h>
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
#define	PCIEHPC_PROP_VALUE_DEFAULT	"default"
#define	PCIEHPC_PROP_VALUE_PCIHOTPLUG	"pci hotplug"
#define	PCIEHPC_PROP_VALUE_OK		"ok"
#define	PCIEHPC_PROP_VALUE_FAILING	"failing"
#define	PCIEHPC_PROP_VALUE_FAILED	"failed"
#define	PCIEHPC_PROP_VALUE_UNUSABLE	"unusable"
#define	PCIEHPC_PROP_VALUE_LED		"<on|off|blink>"
#define	PCIEHPC_PROP_VALUE_LED_DEF	"<on|off|blink|default>"
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

/* Definitions for PCIEHPC/PCISHPC */
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
 * Type definitions for LED type. These are all the types of LEDs that the
 * subsystem knows about; however, both PCIe and SHPC only implement the Power
 * and Attention LEDs.
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
 * Type definitions for LED state. This structure represents the underlying
 * hardware state and not what we are using for tracking the meta state
 * ourselves.
 */
typedef	enum {
	PCIE_HP_LED_OFF = 0,
	PCIE_HP_LED_ON,
	PCIE_HP_LED_BLINK
} pcie_hp_led_state_t;

/*
 * The following enumerations and structures are used to track the way that we
 * manage LEDs for the native PCIe hotplug subsystem. See the 'LED Management'
 * section of the theory statement of uts/common/io/pciex/hotplug/pciehpc.c for
 * more information. While this is all specific to the native PCIe
 * implementation there and not used for the SHPC bits, because everything uses
 * a shared structure for slots, we must track that here.
 *
 * Roughly the pcie_hp_led_act_t is used to describe what we can do to an LED in
 * our table. The pciehpc_logical_led_t describes the different LED states that
 * we can be in. Finally, the pciehpc_led_plat_id_t is yet another LED
 * definition. This would be much simpler if the pcie_hp_led_t reflected
 * reality.
 */
typedef enum pcie_hp_led_act {
	PCIE_HLA_PASS,
	PCIE_HLA_OFF,
	PCIE_HLA_ON,
	PCIE_HLA_BLINK
} pcie_hp_led_act_t;

typedef enum pciehpc_logical_led {
	/*
	 * The base case here indicates what should happen when we have a slot
	 * without power and no device present.
	 */
	PCIE_LL_BASE			= 0,
	/*
	 * This is the state that the system should be in when a device is
	 * powered.
	 */
	PCIE_LL_POWERED,
	/*
	 * This indicates what should happen when an explicit power transition
	 * has been requested. The standard PCIe activity is to blink the power
	 * LED.
	 */
	PCIE_LL_POWER_TRANSITION,
	/*
	 * This is the activity to take when a device driver probe has failed.
	 * This lasts until another state transition or acknowledgement.
	 */
	PCIE_LL_PROBE_FAILED,
	/*
	 * This is the activity to take when a power fault occurs. This will
	 * remain until a device is removed or an active state transition
	 * occurs.
	 */
	PCIE_LL_POWER_FAULT,
	/*
	 * This is the activity to take when the attention button has been
	 * pushed during the 5 second window that is used to confirm behavior.
	 */
	PCIE_LL_ATTENTION_BUTTON
} pciehpc_logical_led_t;

#define	PCIEHPC_LED_NSTATES	6
CTASSERT(PCIEHPC_LED_NSTATES == PCIE_LL_ATTENTION_BUTTON + 1);

typedef enum {
	PCIEHPC_PLAT_ID_POWER,
	PCIEHPC_PLAT_ID_ATTN
} pciehpc_led_plat_id_t;

#define	PCIEHPC_LED_NLEDS	2
CTASSERT(PCIEHPC_LED_NLEDS == PCIEHPC_PLAT_ID_ATTN + 1);

typedef struct pciehpc_led_plat_state {
	pcie_hp_led_act_t plps_acts[PCIEHPC_LED_NLEDS];
} pciehpc_led_plat_state_t;

struct pciehpc_stat_data;

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

	/*
	 * LED states are split into three groups. The first group is the state
	 * that we believe we should have set into hardware. This state is the
	 * only state the SHPC form of the hotplug controller uses. While there
	 * are four LEDs here, only two are actually supported by the SHPC and
	 * PCIe controllers: the attention and power LEDs.
	 *
	 * The subsequent two groups are only used by the PCIe backend. In the
	 * future we should consider whether or not these structures really
	 * should be shared by all hotplug backends (especially when we add the
	 * ACPI/PCI hotplug scheme that virtual machines use).
	 */
	pcie_hp_led_state_t hs_power_led_state;		/* Power LED state */
	pcie_hp_led_state_t hs_attn_led_state;		/* Attn LED state */
	pcie_hp_led_state_t hs_active_led_state;	/* Active LED state */
	pcie_hp_led_state_t hs_fault_led_state;		/* Fault LED state */

	/*
	 * The second of three LED groups. This is used to track when a user
	 * overrides an LED. This is separate from the third group so we can
	 * always return to the expected LED behavior when the override is
	 * disabled again. Currently only used by the PCIe backend.
	 */
	pcie_hp_led_state_t hs_power_usr_ovr_state;
	pcie_hp_led_state_t hs_attn_usr_ovr_state;
	bool hs_power_usr_ovr;
	bool hs_attn_usr_ovr;

	/*
	 * The final group of LED state. This array tracks logical events that
	 * have occurred in the hotplug controller. Higher indexed events that
	 * are true take priority over lower indexed ones. The actual mapping of
	 * states to LEDs is in hs_led_plat_conf. For more information see the
	 * pciehpc.c theory statement.
	 */
	bool hs_led_plat_en[PCIEHPC_LED_NSTATES];
	const pciehpc_led_plat_state_t *hs_led_plat_conf;

	ap_condition_t	hs_condition;		/* Condition of the slot. */
						/* For cfgadm condition. */

	/* Synchronization variable(s) for hot plug events */
	kcondvar_t	hs_attn_btn_cv;		/* ATTN button pressed intr */
	boolean_t	hs_attn_btn_pending;
	kthread_t	*hs_attn_btn_threadp;	/* ATTN button event thread */
	boolean_t	hs_attn_btn_thread_exit;
	kcondvar_t	hs_dll_active_cv;	/* DLL State Changed intr */

	/* Event counters and timestamps */
	kstat_t		*hs_kstat;
	struct pciehpc_stat_data *hs_stat_data;

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

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIE_HP_H */
