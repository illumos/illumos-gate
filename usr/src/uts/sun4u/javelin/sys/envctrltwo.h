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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_JAV_ENVCTRLTWO_H
#define	_JAV_ENVCTRLTWO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

struct envctrlunit {
	struct envctrl_pcd8584_regs *bus_ctl_regs;
	ddi_acc_handle_t ctlr_handle;
	kmutex_t umutex;			/* lock for this structure */
	int instance;
	dev_info_t *dip;			/* device information */
	struct envctrl_ps2 ps_kstats[ENVCTRL_MAX_DEVS];	/* kstats for ps */
	struct envctrl_fan fan_kstats; 		/* kstats for fans */
	struct envctrl_encl encl_kstats;		/* kstats for FSP */
	struct envctrl_temp temp_kstats[ENVCTRL_MAX_DEVS]; /* tempreratures */
	struct envctrl_disk disk_kstats[ENVCTRL_MAX_DEVS]; /* disks */
	int cpu_pr_location[ENVCTRL_MAX_CPUS]; /* slot true if cpu present */
	uint_t num_fans_present;
	uint_t num_ps_present;
	uint_t num_encl_present;
	uint_t num_cpus_present;
	uint_t num_temps_present;
	uint_t num_disks_present;
	kstat_t *psksp;
	kstat_t *fanksp;
	kstat_t *enclksp;
	kstat_t *tempksp;
	kstat_t *diskksp;
	ddi_iblock_cookie_t ic_trap_cookie;	/* interrupt cookie */
	/*  CPR support */
	boolean_t suspended;			/* TRUE if driver suspended */
	boolean_t oflag;			/*  already open */
	int current_mode;			/* NORMAL or DIAG_MODE */
	timeout_id_t timeout_id;				/* timeout id */
	timeout_id_t pshotplug_id;			/* ps poll id */
	int activity_led_blink;
	int present_led_state; 			/* is it on or off?? */
	timeout_id_t blink_timeout_id;
	int initting; /* 1 is TRUE , 0 is FALSE , used to mask intrs */
	boolean_t shutdown; /* TRUE = power off in error event */
	boolean_t fan_failed; /* TRUE = fan failure detected */
	boolean_t tempr_warning; /* TRUE = thermal warning detected */
};

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _JAV_ENVCTRLTWO_H */
