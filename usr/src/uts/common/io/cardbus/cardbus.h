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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c)  * Copyright (c) 2001 Tadpole Technology plc
 * All rights reserved.
 */

#ifndef	_SYS_CARDBUS_H
#define	_SYS_CARDBUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef  __cplusplus
extern "C" {
#endif

#define	CB_BCNF_BCNTRL_ISA_INT_ENAB	0x0080
#define	CB_BCNF_BCNTRL_MEM0_PREF	0x0100
#define	CB_BCNF_BCNTRL_MEM1_PREF	0x0200
#define	CB_BCNF_BCNTRL_WRITE_POST	0x0400

typedef struct cb_nexus_cb {
	void	(*enable_intr)(dev_info_t *);
	void	(*disable_intr)(dev_info_t *);
} cb_nexus_cb_t;

typedef enum { PCIHP_SOFT_STATE_CLOSED, PCIHP_SOFT_STATE_OPEN,
		PCIHP_SOFT_STATE_OPEN_EXCL } cbhp_soft_state_t;

/*
 * Main softstate per cardbus device
 */
typedef struct cardbus_dev {
	int	cb_instance;
	boolean_t fatal_problem;
	dev_info_t *cb_dip;
	kmutex_t cb_mutex;
	cb_nexus_cb_t *cb_nex_ops;
	struct dev_ops cb_dops;
	struct dev_ops *orig_dopsp;
	struct bus_ops *orig_bopsp;
	struct cb_deviceset_props *cb_dsp;
	ndi_event_hdl_t	cb_ndi_event_hdl;
	ndi_event_set_t	cb_ndi_events;
#ifdef HOTPLUG
	/* Nexus specific variables */
	ap_rstate_t	rstate;		/* state of Receptacle */
	ap_ostate_t	ostate;		/* state of the Occupant */
	ap_condition_t	condition;	/* condition of the occupant */
	cbhp_soft_state_t	soft_state;
	uint32_t	event_mask;	/* last event mask registerd */
	boolean_t	auto_config;
	boolean_t	disabled;
	char	*name;

	/* Slot specific variables */
	char	ap_id[32];		/* Attachment point name */
	char	*nexus_path;		/* Pathname of Nexus */
	hpc_slot_ops_t	*slot_ops;	/* Ptr HPC entry points */
	hpc_slot_info_t	slot_info;	/* Bus Specific SlotInfo */
	hpc_slot_t	slot_handle;	/* HPS slot handle */
	boolean_t card_present;
	hpc_led_state_t leds[4];
#endif
} cbus_t;

typedef struct cardbus_bus_range {
	uint32_t lo;
	uint32_t hi;
} cardbus_bus_range_t;

typedef struct cardbus_range {
	uint32_t child_hi;
	uint32_t child_mid;
	uint32_t child_lo;
	uint32_t parent_hi;
	uint32_t parent_mid;
	uint32_t parent_lo;
	uint32_t size_hi;
	uint32_t size_lo;

} cardbus_range_t;

#if defined(DEBUG)
#define	CARDBUS_DEBUG
#endif

#ifdef CARDBUS_DEBUG
extern void prom_printf(const char *, ...);
#endif

extern int cardbus_debug;

#ifdef _KERNEL
extern int cardbus_attach(dev_info_t *, cb_nexus_cb_t *);
extern boolean_t cardbus_load_cardbus(dev_info_t *, uint_t, uint32_t);
extern void cardbus_unload_cardbus(dev_info_t *);
extern void cardbus_err(dev_info_t *dip, int level, const char *fmt, ...);

/* The following only exists for hotplug support */
extern int cardbus_open(dev_t *, int, int, cred_t *);
extern int cardbus_close(dev_t, int, int, cred_t *);
extern int cardbus_ioctl(dev_t, int, intptr_t, int, cred_t *,
	    int *);
extern boolean_t cardbus_is_cb_minor(dev_t);
void cardbus_save_children(dev_info_t *dip);
void cardbus_restore_children(dev_info_t *dip);
#endif

#ifdef  __cplusplus
}
#endif

#endif	/* _SYS_CARDBUS_H */
