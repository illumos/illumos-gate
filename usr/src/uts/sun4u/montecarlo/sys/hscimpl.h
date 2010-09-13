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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MONTECARLO_SYS_HSCIMPL_H
#define	_MONTECARLO_SYS_HSCIMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/hotplug/hpctrl.h>

/*
 * Flag values
 */
#define	HSC_ENABLED		0x1	/* if not enabled, slot unmanaged */
#define	HSC_AUTOCFG		0x2	/* if set, ENUM# events will be sent */
#define	HSC_REGISTERED		HSC_ENABLED
#define	HSC_ALARM_CARD_PRES	0x4	/* Alarm Card on this slot */
#define	HSC_BOARD_TYPE_HS	0x8
#define	HSC_BOARD_TYPE_UNKNOWN	0x10
#define	HSC_SLOT_ENABLED	0x20
#define	HSC_SLOT_BAD_STATE	0x40	/* Surprise Removal on this slot */
#define	HSC_ENUM_FAILED		0x80	/* Could not Enumerate this slot */
#define	HSC_SCB_HOTSWAPPED	0x100	/* slot status change due to SCB swap */
#define	HSC_HOTSWAP_MODE_BASIC	0
#define	HSC_HOTSWAP_MODE_FULL	1


typedef struct hsc_slot_state {
	int		pslotnum;
	int		state;
} hsc_slot_state_t;

typedef struct hsc_slot_table {
	char	nexus[128];
	int	pci_devno;
	int	pslotnum;
	int	ga;
} hsc_slot_table_t;

typedef struct hsc_prom_slot_table {
	int	phandle;
	int	pci_devno;
	int	pslotnum;
	int	ga;
} hsc_prom_slot_table_t;

typedef struct hsc_state {
	int		instance;
	int		state;
	dev_info_t	*dip;
	void		*scsb_handle;
	struct hsc_slot	*hsp_last;	/* last board plugged in. */
	hsc_slot_table_t *slot_table_prop;
	int		slot_table_size;
	int		hsc_intr_counter;
	kmutex_t	hsc_mutex;
	ddi_iblock_cookie_t enum_iblock;
	boolean_t	regDone;
	int		n_registered_occupants;
	int	hotswap_mode;
} hsc_state_t;

/*
 * This struct describes a HS slot known to us. It maintains
 * all the state associated with the slot.
 * Slots are placed on a linked list.
 */
typedef struct hsc_slot {
	struct hsc_slot		*hs_next;

	void			*hs_hpchandle; /* HPC (scsb) handle */

	/*
	 * The hs_slot_number identifies the plysical slot.
	 * It should match with the documentation.
	 */
	int			hs_slot_number;

	hpc_slot_info_t		hs_info;

	hpc_board_type_t	hs_board_type;
	/*
	 * We only have 2 LEDs/slot on MonteCarlo, so we map them
	 * to the ACTIVE and FAULT ones.
	 * ACTIVE will be set when a board is in the slot, and has
	 * been configured.
	 */
	hpc_led_state_t		hs_active_led_state;
	hpc_led_state_t		hs_fault_led_state;

	/*
	 * hs_slot_handle is useful for supporting ENUM#
	 * (when we need to inform the nexus of the event).
	 */
	hpc_slot_t		hs_slot_handle;

	uint_t			hs_flags;

	boolean_t		hs_board_configured;
	boolean_t		hs_board_configuring;
	boolean_t		hs_board_unconfiguring;
	boolean_t		hs_board_healthy;

	/*
	 * The hs_slot_state is useful for HW-connection control
	 */
	hpc_slot_state_t	hs_slot_state;
	hsc_state_t		*hsc;	/* pointer to our controller device */
} hsc_slot_t;

/* state values in our control structure */
#define	HSC_ENUM_ENABLED	1
#define	HSC_ATTACHED		2
#define	HSC_SCB_CONNECTED	4

#ifdef	__cplusplus
}
#endif

#endif	/* _MONTECARLO_SYS_HSCIMPL_H */
