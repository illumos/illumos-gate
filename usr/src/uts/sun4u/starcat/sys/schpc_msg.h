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

#ifndef _SYS_SCHPC_MSG_H
#define	_SYS_SCHPC_MSG_H

/*
 * This header file describes the messages that are sent between the
 * schpc Hot Plug Controller Driver running on the domain and the System
 * Controller.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Format of the Get Slot Status specific part of
 * PCI Hot Plug message.
 */
typedef struct {
	uint16_t	slot_power_on 		:1, /* Slot Power is on */
			slot_powergood		:1, /* Slot Power is good */
			slot_powerfault		:1, /* Slot Power has faulted */
			slot_empty		:1, /* No occupant in slot */
			slot_freq_cap		:2, /* Slot's Freq Capability */
			slot_freq_setting	:2, /* Slot Freq setting */
			slot_condition		:2, /* Condition of slot */
			slot_HEALTHY		:1, /* Value of HEALTHY# sig */
			slot_ENUM		:1, /* Value of ENUM# sig */
			slot_mode_cap		:1, /* Conven or PCI-X */
			slot_mode_setting	:1, /* Conven or PCI-X */
			reserved		:2;
	uint8_t		slot_replystatus;
} pci_getslot_t;

/*
 * Format of the Set Slot Status specific part of
 * PCI Hot Plug message.
 */
typedef struct {
	uint16_t	slot_power_on		:1, /* Connect Slot to bus */
			slot_power_off		:1, /* Disconnect from bus */
			slot_led_power		:2, /* Slot Power LED */
			slot_led_service	:2, /* OK To Remove LED */
			slot_led_fault		:2, /* Fault LED */
			slot_disable_ENUM	:1, /* Disable ENUM Event */
			slot_enable_ENUM	:1, /* Enable ENUM Event */
			slot_disable_HEALTHY	:1, /* Disable HEALTHY EVENT */
			slot_enable_HEALTHY	:1, /* Enable HEALTHY EVENT */
			reserved		:4;
	uint8_t		slot_replystatus;
} pci_setslot_t;

/*
 * Format of the Slot Event specific part of
 * the PCI Hot Plug message.
 */
typedef struct {
	uint16_t	slot_power		:1, /* Slot Power has changed */
			slot_presence		:1, /* occupant has been    */
						    /* inserted or removed  */
			slot_ENUM		:1, /* ENUM# has changed */
			slot_HEALTHY		:1, /* HEALTHY# has changed */
			slot_powergood		:1, /* Power is good */
			slot_powerfault		:1, /* Power has faulted */
			reserved		:10;
} pci_slotevent_t;

/*
 * PCI Hot Plug message
 */
typedef struct {
	uint8_t		pcimsg_node;
	uint8_t		pcimsg_board;
	uint8_t		pcimsg_slot;
	uint8_t		pcimsg_revision;
	uint8_t		pcimsg_command;
	union {
		pci_setslot_t	pcimsg_setslot;
		pci_getslot_t	pcimsg_getslot;
		pci_slotevent_t	pcimsg_slotevent;
	} pcimsg_type;
} pcimsg_t;

/*
 * Keys for the outgoing and incoming mailboxes
 */
#define	KEY_PCSC	0x50435343	/* Outgoing Mailbox 'PCSC' */
#define	KEY_SCPC	0x53435043	/* Incoming Mailbox 'SCPC' */

/*
 * default timeout in seconds for mboxsc_getmsg calls
 */
#define	PCSC_TIMEOUT	30

/* Commands */
#define	PCIMSG_GETSLOTSTATUS	0x1
#define	PCIMSG_SETSLOTSTATUS	0x2
#define	PCIMSG_SLOTEVENT	0x3

/* Message Revisions */
#define	PCIMSG_REVISION		0x10
#define	PCIMSG_REVISION_1_0	0x10

/*
 * Values for the slot_condition field of the get slot status command.
 */
#define	PCIMSG_SLOTCOND_UNKNOWN		0x0
#define	PCIMSG_SLOTCOND_GOOD		0x1
#define	PCIMSG_SLOTCOND_REC_FAIL	0x2
#define	PCIMSG_SLOTCOND_OCC_FAIL	0x3

/*
 * Values for the slot_freq_cap and slot_freq_setting fields of the get
 * slot status command.
 */
#define	PCIMSG_FREQ_33MHZ	0x0
#define	PCIMSG_FREQ_66MHZ	0x1
#define	PCIMSG_FREQ_90MHZ	0x2
#define	PCIMSG_FREQ_133MHZ	0x3

/*
 * Values for the slot_mode_cap and slot_mode_setting of the get
 * slot status command.
 */
#define	PCIMSG_MODE_CONVEN	0x0
#define	PCIMSG_MODE_PCIX	0x1

/*
 * Values for the PRSNT signals.
 */
#define	PCIMSG_PRSNT_NOADAPTER	0x0
#define	PCIMSG_PRSNT_25W	0x1
#define	PCIMSG_PRSNT_15W	0x2
#define	PCIMSG_PRSNT_7_5W	0x3

/*
 * Values to turn on and off slot characteristics.
 */
#define	PCIMSG_ON		0x1
#define	PCIMSG_OFF		0x0

/*
 * Values to set the power, service and fault LEDs
 */
#define	PCIMSG_LED_OFF		0x00
#define	PCIMSG_LED_ON		0x01
#define	PCIMSG_LED_FLASH	0x02

/*
 * Return values for the slot_replystatus field for the get/set slot status
 * commands.
 */
#define	PCIMSG_REPLY_GOOD	0x0
#define	PCIMSG_REPLY_FAIL	0x1

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SCHPC_MSG_H */
