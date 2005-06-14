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
 * Copyright 2000-2001, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_HPC3130_DAK_H
#define	_SYS_HPC3130_DAK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

#include <sys/i2c/clients/i2c_client.h>

/* masks */

#define	HPC3130_PROTECT_ON 0x01 /* (R/W) protection enable mechanism */
#define	HPC3130_SYSM66STAT 0x02 /* (R) indicates bus runs at 66Mhz */
#define	HPC3130_SEQUENCING 0x0c /* (R/W) hotplug sequencing mode */
#define	HPC3130_MANUAL_SEQ 0x00 /* controle with idividual register calls */
#define	HPC3130_AUTO1_SEQ  0x04 /* enable CBT before disable RST# */
#define	HPC3130_AUTO2_SEQ  0x08 /* enable CBT after disable RST# */

#define	HPC3130_GCR		0x00
#define	HPC3130_STATUS		0x01
#define	HPC3130_CONTROL		0x02
#define	HPC3130_ATTEN		0x03
#define	HPC3130_EVENT_STATUS	0x06
#define	HPC3130_INTERRUPT	0x07
#define	HPC3130_NO_REGISTER	0xff

/*
 * masks
 */
#define	HPC3130_PRSNT1   0x01 /* (R) Logic level of PRSNT1# signal */
#define	HPC3130_PRSNT2   0x02 /* (R) Logic level of PRSNT2# signal */
#define	HPC3130_DETECT0  0x04 /* (R) Logic level of DETECT0# signal */
#define	HPC3130_DETECT1  0x08 /* (R) Logic level of DETECT1# signal */
#define	HPC3130_PWRFAULT 0x10 /* (R) Logic level of PWRFAULT# signal */
#define	HPC3130_PWRGOOD  0x20 /* (R) Logic level of PWRGOOD# signal */
#define	HPC3130_M66EN    0x40 /* (R) Logic level of M66EN terminal */
#define	HPC3130_BUSON    0x80 /* (R) Logic level of BUSON# signal */


/*
 * more masks
 */
/* (R/W) Logical level of SLOTRST# (used to reset a slot) */
#define	HPC3130_SLOTRST		0x01
/* (R/W) Logical level of CLKON# (used to control clock signal) */
#define	HPC3130_CLKON		0x02
/* (R/W) Logical level of REQ64ON# signal */
#define	HPC3130_REQ64		0x04
/* (R/W) Logical level of SLOTREQ64# signal */
#define	HPC3130_SLOTREQ64	0x08
/* (R/W) Bus control (for auto sequence level==1?disconnect:connect */
#define	HPC3130_BUS_CTL		0x10
/* (R/W) Logical level of power control on the slot */
#define	HPC3130_SLTPWRCTL	0x20


#define	HPC3130_ATTN0		0x00
#define	HPC3130_ATTN1		0x01

#define	HPC3130_LED_FAULT	HPC3130_ATTN1
#define	HPC3130_LED_OK2REM	HPC3130_ATTN0

#define	HPC3130_ATTN_MASK(led)	(3<<(HPC3130_ATTN_SHIFT(led)))	/* 3 or c */
#define	HPC3130_ATTN_SHIFT(led)	(led<<1)			/* 0 or 2 */

#define	HPC3130_ATTN_OFF	0x00
#define	HPC3130_ATTN_SLO	0x01 		/* not used by Daktari */
#define	HPC3130_ATTN_FST	0x02
#define	HPC3130_ATTN_ON		0x03

/*
 * These two macros map between the Hot Plug Services LED constants
 * (cf. uts/common/sys/hotplug/hpctrl.h) and the values used by the
 * HPC3130 hardware.
 */

static char hpc3130_to_hpc_led_map[] = {
	HPC_LED_OFF, HPC_LED_BLINK, HPC_LED_BLINK, HPC_LED_ON
};
static char hpc3130_from_hpc_led_map[] = {
	HPC3130_ATTN_OFF, HPC3130_ATTN_ON, HPC3130_ATTN_FST
};
#define	HPC3130_TO_HPC_LED(val)		(hpc3130_to_hpc_led_map[val])
#define	HPC3130_FROM_HPC_LED(val)	(hpc3130_from_hpc_led_map[val])

#define	HPC3130_MAX_SLOT	0x4

#define	HPC3130_TABLE_COLUMNS	3 /* number of colums in slot-table property */
#define	HPC3130_DEBOUNCE_COUNT	2 /* consecutive equal readings == debounced */
#define	HPC3130_DEBOUNCE_LIMIT	1000 /* hard upper limit on debouce code */
#define	HPC3130_POWER_TRIES	3 /* Try this may times to connect/disconnect */
#define	HPC3130_ADEQUATE_PAUSE	25000 /* usec delay for connect sequence */

/*
 * This structure defines an element of the controller's
 * slot table array
 */

typedef struct hpc3130_slot_table_entry hpc3130_slot_table_entry_t;
typedef struct hpc3130_callback_arg hpc3130_callback_arg_t;

struct hpc3130_callback_arg {
	caddr_t		handle;
	caddr_t		statep;
	uint8_t		offset;
};

struct hpc3130_slot_table_entry {
	hpc_slot_info_t		hpc3130_slot_info;
	hpc_slot_t		hpc3130_slot_handle;
	char			nexus[MAXNAMELEN];
	hpc3130_callback_arg_t	callback_info;
};

/*
 * The soft state structure
 */
struct hpc3130_unit {

	dev_info_t *dip;

	hpc_slot_ops_t *hpc3130_slot_ops;

	/*
	 * the following fields hold the value of the "slot-table"
	 * property for this controller
	 */
	caddr_t hpc3130_slot_table_data;
	int hpc3130_slot_table_size;

	/*
	 * the following fields represent the array of hot-plug
	 * slots derived from the "slot-table" property
	 */
	hpc3130_slot_table_entry_t *hpc3130_slot_table;
	int hpc3130_slot_table_length;

	/*
	 * Mutex associated with this structure
	 */
	kmutex_t hpc3130_mutex;

	/*
	 * Trap interrupt cookie
	 */
	ddi_iblock_cookie_t ic_trap_cookie;

	/*
	 * Open flag
	 */
	int hpc3130_oflag;

	/*
	 * An integer field describing the type
	 * of slots (PCI/SBD).
	 */
	hpc3130_slot_type_t slots_are;

	/*
	 * A place to put the name of this driver
	 * What gets put here is "hpc3130n" - where
	 * n is the instance number.
	 */
	char hpc3130_name[16];

	/*
	 * The handle within the I2C nexus that this instance
	 * represents.
	 */
	i2c_client_hdl_t hpc3130_hdl;

	/*
	 * condition variable used to throttle power OK signal
	 */
	kcondvar_t hpc3130_cond;

	/*
	 * Present vector - if B_TRUE there is a card in the corresponding
	 * slot.
	 */
	boolean_t present[HPC3130_MAX_SLOT];

	/*
	 * Power vector - if B_TRUE, then power is applied to the slot
	 */
	boolean_t power[HPC3130_MAX_SLOT];

	/*
	 * Enable vector - if B_TRUE the slot is enabled.
	 */
	boolean_t enabled[HPC3130_MAX_SLOT];

	/*
	 * LED state indicators.
	 */
	char fault_led[HPC3130_MAX_SLOT];
	char ok2rem_led[HPC3130_MAX_SLOT];

	/* For poll(9e)/ioctl(HPC3130_GET_SOFT_EVENT */
	uint_t events[HPC3130_MAX_SLOT];
	pollhead_t pollhead[HPC3130_MAX_SLOT];
};

typedef struct hpc3130_unit hpc3130_unit_t;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HPC3130_DAK_H */
