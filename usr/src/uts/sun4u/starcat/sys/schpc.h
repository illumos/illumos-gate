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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SCHPC_H
#define	_SYS_SCHPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	STARCAT_MAX_SLOTS	(18 * 4)

/*
 * Slot LED Descriptor
 *
 * Each hot pluggable PCI/cPCI slot has three leds.  Each LED can
 * be on, off, or flashing.
 */
typedef struct slot_led {
	char		led_power;
	char		led_service;
	char		led_fault;
	char		reserved;
} slot_led_t;

#define	LED_OFF		0x00
#define	LED_ON		0x01
#define	LED_FLASH	0x02

/*
 * LED Commands
 */
#define	POWER_LED_ON		0x00000001
#define	POWER_LED_OFF		0x00000002
#define	POWER_LED_FLASH		0x00000004
#define	SERVICE_LED_ON		0x00000010
#define	SERVICE_LED_OFF		0x00000020
#define	SERVICE_LED_FLASH	0x00000040
#define	FAULT_LED_ON		0x00000100
#define	FAULT_LED_OFF		0x00000200
#define	FAULT_LED_FLASH		0x00000400


/*
 * Hot Plug Slot Descriptor.  Each hot pluggable slot will have
 * a schpc_slot_t structure allocated for it.
 */
typedef struct {
	dev_info_t	*devi;			/* Ptr to PCI dev_info */
	uint32_t	state;			/* Slot's Hot Plug State */
	uint16_t	pci_id;			/* PCI ID for slot */
	uint8_t		expander;		/* Centerplane Expander */
	uint8_t		board;			/* Number of IO Board 0/1 */
	uint8_t		schizo;			/* Number of Schizo 0/1 */
	uint8_t		leaf;			/* A or B (0 or 1) */
	uint8_t		slot;			/* Slot Number */
	slot_led_t	led;			/* Current LED state */
	hpc_slot_ops_t	*slot_ops;		/* Ptr HPC entry points */
	hpc_slot_info_t	slot_info;		/* Bus Specific SlotInfo */
	hpc_slot_t	slot_handle;		/* Handle used by HPS */
	char		nexus_path[MAXNAMELEN];	/* Pathname of Nexus */
	char		ap_id[MAXNAMELEN];	/* Attachment point name */
	caddr_t		saved_regs_va[3];	/* Reg set virtual addresses */
	ddi_acc_handle_t saved_handle[3];	/* Handle from map in */
	uint64_t	*saved_regs;		/* Ptr to saved off regs */
	int		saved_size;		/* Size of saved off regs */
} schpc_slot_t;

/*
 * PCI/cPCI Hot Plug states for an attachment point
 */
#define	SCHPC_SLOTSTATE_REC_GOOD	0x01	/* Receptacle is Good */
#define	SCHPC_SLOTSTATE_OCC_GOOD	0x02	/* Occupant is Good */
#define	SCHPC_SLOTSTATE_BAD_NEXUS	0x04	/* Invalid PCI Nexus */
#define	SCHPC_SLOTSTATE_PRESENT		0x10	/* Occupant Present */
#define	SCHPC_SLOTSTATE_CONNECTED	0x100	/* Receptacle Connected */
#define	SCHPC_SLOTSTATE_CONFIGURED	0x1000	/* Occupant Configured */
#define	SCHPC_SLOTSTATE_AUTOCFG_ENABLE	0x10000	/* Auto Configuration Enabled */
#define	SCHPC_SLOTSTATE_ENUM		0x100000 /* ENUM Handling in progress */
#define	SCHPC_SLOTSTATE_EXECUTING	0x200000 /* Executing a mailbox cmd */
#define	SCHPC_SLOTSTATE_HPCINITED	0x400000 /* Ready to accept commands */

/*
 * Soft state structure definition for each schpc instance.
 * There will be a single soft state stucture for each IO Board.
 */
typedef struct schpc {
	uint32_t	schpc_instance;		/* Instance # */
	dev_info_t	*schpc_devi;		/* Ptr to dev_info */
	kmutex_t	schpc_mutex;		/* Mutex to protect struct */
	kcondvar_t	schpc_cv;		/* Conditional Variable */
	char		*schpc_property;	/* Ptr to slot-table */
	uint32_t	schpc_property_size;	/* Size of slot-table */
	uint32_t	schpc_hotplugmodel;	/* Type of Hot Plug */
	uint16_t	schpc_transid;		/* Current transaction ID */
	uint16_t	schpc_number_of_slots;	/* Slot on IO Board */
	struct schpc	*schpc_next;		/* Ptr to next schpc */
	schpc_slot_t	*schpc_slot;		/* Slot Specific stuff */
} schpc_t;

/*
 * Types of Hot Plug/Hot Swap Models
 */
#define	SCHPC_HOTPLUGTYPE_NOTHOTPLUGGABLE	0
#define	SCHPC_HOTPLUGTYPE_CPCIHOTPLUG		1
#define	SCHPC_HOTPLUGTYPE_CPCIHOTSWAPBASIC	2
#define	SCHPC_HOTPLUGTYPE_CPCIHOTSWAPFULL	3
#define	SCHPC_HOTPLUGTYPE_PCIHOTPLUG		4

/*
 * schpc_t's slot table, schpc_slot[], is indexed by
 * a value in the range [0,STARCAT_MAX_SLOTS).
 *
 * That index is composed of these bit-fields:
 *
 *                   <-- slot num  -->
 *      |----------------------------|
 *      |  expander  | schizo | leaf |
 *      |------------|--------|------|
 *       7          2     1       0
 *
 */
/* Extract various bit-fields from a slot table index: */
#define	SCHPC_SLOT_EXPANDER(idx)	(((idx) & 0xfc) >> 2)
#define	SCHPC_SLOT_SCHIZO(idx)		(((idx) & 0x2) >> 1)
#define	SCHPC_SLOT_LEAF(idx)		((idx) & 0x1)
#define	SCHPC_SLOT_NUM(idx)		((idx) & (0x1 | 0x2))

/* Build a slot index from component bit-fields: */
#define	SCHPC_MAKE_SLOT_INDEX2(expander, slot_num)\
	(((expander) << 2) | (slot_num))
#define	SCHPC_MAKE_SLOT_INDEX3(expander, schizo, leaf)\
	(((expander) << 2) | ((schizo) << 1) | (leaf))

/*
 * Integer values for the clock-frequency property.
 */
#define	SCHPC_33MHZ	(33 * 1000 * 1000)
#define	SCHPC_66MHZ	(66 * 1000 * 1000)
#define	SCHPC_90MHZ	(90 * 1000 * 1000)
#define	SCHPC_133MHZ	(133 * 1000 * 1000)

/*
 * module-revision# for the XMITS versions
 */
#define	XMITS_10	1
#define	XMITS_20	2
#define	XMITS_21	3
#define	XMITS_30	4
#define	XMITS_31	5

extern int schpc_add_pci(dev_info_t *);
extern int schpc_remove_pci(dev_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SCHPC_H */
