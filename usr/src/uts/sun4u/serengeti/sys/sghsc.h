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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SGHSC_H
#define	_SYS_SGHSC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Serengeti CompactPCI Hot Swap Controller Driver header file. This file is
 * structured in a following way: common, sghsc data (defines and structures)
 * and mailbox related data (defines and structures).
 */

#include <sys/hotplug/hpctrl.h>
#include <sys/hotplug/hpcsvc.h>
#include <sys/sgsbbc_mailbox.h>

/*
 * sghsc node path with insert placeholders
 */
#define	SGHSC_PATH		"/ssm@%x,0/pci@%x,%x00000"

/*
 * Mutex short hands
 */
#define	SGHSC_MUTEX(sghsc) \
	(&sghsc->sghsc_mutex)
#define	SGHSC_MUTEX_OWNED(sghsc) \
	mutex_owned(SGHSC_MUTEX(sghsc))
#define	SGHSC_MUTEX_ENTER(sghsc) \
	mutex_enter(SGHSC_MUTEX(sghsc))
#define	SGHSC_MUTEX_EXIT(sghsc) \
	mutex_exit(SGHSC_MUTEX(sghsc))

#define	SGHSC_SLOT_MUTEX(sghsc, slot_num) \
	(&sghsc->sghsc_slot_table[slot_num]->slot_mutex)
#define	SGHSC_SLOT_MUTEX_OWNED(sghsc, slot_num) \
	mutex_owned(SGHSC_SLOT_MUTEX(sghsc, slot_num));
#define	SGHSC_SLOT_MUTEX_ENTER(sghsc, slot_num) \
	mutex_enter(SGHSC_SLOT_MUTEX(sghsc, slot_num));
#define	SGHSC_SLOT_MUTEX_EXIT(sghsc, slot_num) \
	mutex_exit(SGHSC_SLOT_MUTEX(sghsc, slot_num));

/*
 * Misc definitions
 */
#define	SGHSC_ALL_SLOTS_ENABLE	0x3F
#define	SGHSC_SLOT_ENABLE	0x01
#define	SGHSC_ALL_SLOTS_DISABLE	0x02
#define	SGHSC_SLOT_DISABLE	0x03
#define	SGHSC_ALL_LEDS_ENABLE	0x3F3F
#define	SGHSC_LED_ENABLE	0x04
#define	SGHSC_ALL_LEDS_DISABLE	0x05
#define	SGHSC_LED_DISABLE	0x06
#define	SGHSC_LED_BLINKING	0x07
#define	SGHSC_SLOT_ISOLATE	0x08
#define	SGHSC_SLOT_POWER	0x09
#define	SGHSC_LED_ENABLE_MASK	0x0000FFFF
#define	SGHSC_SAFARI_ID_EVEN	0x3fe


/* Individual events definitions */
#define	SGHSC_EVENT_CARD_INSERT		0x1
#define	SGHSC_EVENT_CARD_REMOVE		0x2
#define	SGHSC_EVENT_LEVER_ACTION	0x3
#define	SGHSC_EVENT_HEALTHY_LOST	0x4
#define	SGHSC_EVENT_POWER_ON		0x5
#define	SGHSC_EVENT_POWER_OFF		0x6

/* Slot flags */
#define	SGHSC_SLOT_AUTO_CFG_EN	0x1
#define	SGHSC_SLOT_HEALTHY_LOST	0x2

/* LED definitions */
#define	SGHSC_POWER_LED		0x10
#define	SGHSC_FAULT_LED		0x20
#define	SGHSC_ACTIVE_LED	0x40
#define	SGHSC_ATTN_LED		0x80

/* Ring buffer size, has to be power of 2 */
#define	SGHSC_RING_BUFFER_SZ	0x10

/*
 * Per Hot Swappable Slot info
 */
typedef struct sghsc_slot {

	/*
	 * Mutex for each slots for state change
	 */
	kmutex_t		slot_mutex;

	/*
	 * pathname of bus node
	 */
	char nexus_path[MAXPATHLEN];

	/*
	 * property, status, cap  for each slot
	 */
	hpc_slot_info_t		slot_info;
	hpc_slot_state_t	slot_status;
	uint32_t		slot_capb;

	/*
	 * PCI Bus number for each slot
	 */
	uint8_t			pci_device_num;

	/*
	 * dynamically allocated hpc_slot_ops_t
	 * and register slot handle
	 */
	hpc_slot_ops_t		*slot_ops;
	hpc_slot_t		handle;

	/*
	 * Leds for each slot are not cached
	 */

	/*
	 * slot state, flags, board type
	 */
	uint32_t		flags;
	uint32_t		state;
	uint32_t		board_type;

} sghsc_slot_t;

/*
 * Per Serenget CompactPCI HSC instance soft state structure
 */
typedef struct sghsc {
	dev_info_t	*sghsc_dip;
	kmutex_t	sghsc_mutex;
	uint32_t	sghsc_instance;
	uint32_t	sghsc_board;
	uint32_t	sghsc_node_id;
	uint32_t	sghsc_portid;
	uint32_t	sghsc_num_slots;
	uint32_t	sghsc_valid;
	sghsc_slot_t	*sghsc_slot_table;
} sghsc_t;

/*
 * Slot map descriptor (slot to bus segment mapping)
 */
typedef struct sdesc {
	uint32_t	agent_delta;
	uint32_t	off;
	uint32_t	pcidev;
	uint32_t	slot_type;
} sdesc_t;

/*
 * Mailbox related data and structures
 */
#define	CPCI_GET_SLOT_STATUS		0x5000
#define	CPCI_SET_SLOT_FAULT_LED		0x5001
#define	CPCI_SET_SLOT_STATUS		0x5002
#define	CPCI_SET_SLOT_POWER		0x5003
#define	CPCI_GET_NUM_SLOTS		0x5004
#define	CPCI_SET_ENUM_CLEARED		0x5005
#define	CPCI_BOARD_TYPE			0x5006

/*
 * Bit definition for Boat Type
 */
#define	NO_BOARD_TYPE			0
#define	PCI_BOARD			1
#define	CPCI_BOARD			2
#define	SP_CPCI_BOARD			3
#define	WCI_CPCI_BOARD			4
#define	WCI_SP_CPCI_BOARD		5

/*
 * Shifts definition for CPCI_GET_SLOT_STATUS
 */
#define	ONE_BIT				1
#define	TWO_BITS			3
#define	THREE_BITS			7
#define	CPCI_STAT_POWER_ON_SHIFT	0
#define	CPCI_STAT_LED_POWER_SHIFT	1
#define	CPCI_STAT_LED_FAULT_SHIFT	2
#define	CPCI_STAT_LED_HP_SHIFT		3
#define	CPCI_STAT_SLOT_EMPTY_SHIFT	4
#define	CPCI_STAT_HOT_SWAP_STATUS_SHIFT	5
#define	CPCI_STAT_HEALTHY_SHIFT		12	/* One bit */
#define	CPCI_STAT_RESET_SHIFT		13	/* One bit */

/*
 * Bit definition for CPCI_SET_SLOT_STATUS
 */
#define	CPCI_SET_STATUS_SLOT_RESET	0x00001
#define	CPCI_SET_STATUS_SLOT_READY	0x00000
/*
 * Bit definition for CPCI_SET_SLOT_STATUS_FAULT_LED
 */
#define	CPCI_SET_FAULT_LED_OFF		0x00000
#define	CPCI_SET_FAULT_LED_ON		0x00001
#define	CPCI_SET_FAULT_LED_KEEP		0x00002
#define	CPCI_SET_FAULT_LED_TOGGLE	0x00003

/*
 * Bit definition for CPCI_SET_SLOT_POWER
 */
#define	CPCI_POWER_OFF	0x0
#define	CPCI_POWER_ON	0x1

/*
 * Mailbox timeout
 */
#define	SGHSC_MBX_TIMEOUT		600

/*
 * cPCI command codes (internal)
 */
#define	_SGHSC_CODE			('N' << 16)

#define	SGHSC_GET_SLOT_STATUS		(_SGHSC_CODE | 0x14)
#define	SGHSC_SET_SLOT_STATUS_RESET	(_SGHSC_CODE | 0x15)
#define	SGHSC_SET_SLOT_STATUS_READY	(_SGHSC_CODE | 0x16)
#define	SGHSC_SET_SLOT_FAULT_LED_ON	(_SGHSC_CODE | 0x17)
#define	SGHSC_SET_SLOT_FAULT_LED_OFF	(_SGHSC_CODE | 0x18)
#define	SGHSC_SET_SLOT_FAULT_LED_KEEP	(_SGHSC_CODE | 0x19)
#define	SGHSC_SET_SLOT_FAULT_LED_TOGGLE	(_SGHSC_CODE | 0x1a)
#define	SGHSC_SET_SLOT_POWER_OFF	(_SGHSC_CODE | 0x1b)
#define	SGHSC_SET_SLOT_POWER_ON		(_SGHSC_CODE | 0x1c)
#define	SGHSC_GET_NUM_SLOTS		(_SGHSC_CODE | 0x1d)
#define	SGHSC_SET_ENUM_CLEARED		(_SGHSC_CODE | 0x1e)
#define	SGHSC_GET_CPCI_BOARD_TYPE	(_SGHSC_CODE | 0x1f)

typedef struct {
	uint32_t	cmd_id;
	uint32_t	node_id;
	uint32_t	board;
	uint32_t	slot;
	uint32_t	info;
} bitcmd_info_t;

typedef struct {
	uint32_t	cmd_id;
	uint32_t	result;
} bitcmd_resp_t;

typedef enum { SGHSC_RB_EMPTY, SGHSC_RB_FLOAT,
	SGHSC_RB_FULL } sghsc_rb_state_t;

typedef struct sghsc_event {
	int type;
	int node_id;
	int board;
	int slot;
	int info;
} sghsc_event_t;

typedef struct sghsc_rb_head {
	sghsc_event_t *buf;
	int put_idx;
	int get_idx;
	int size;
	sghsc_rb_state_t state;
} sghsc_rb_head_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGHSC_H */
