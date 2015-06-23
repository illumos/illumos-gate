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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SUNPM_H
#define	_SYS_SUNPM_H

/*
 * Sun Specific Power Management definitions
 */

#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/ddipropdefs.h>
#include <sys/devops.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/ddidevmap.h>
#include <sys/ddi_implfuncs.h>
#include <sys/ddi_isa.h>
#include <sys/model.h>
#include <sys/devctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * Power cycle transition check is supported for SCSI and SATA devices.
 */
#define	DC_SCSI_FORMAT		0x1		/* SCSI */
#define	DC_SMART_FORMAT		0x2		/* SMART */

#define	DC_SCSI_MFR_LEN		6		/* YYYYWW */

struct pm_scsi_cycles {
	int	lifemax;			/* lifetime max power cycles */
	int	ncycles;			/* number of cycles so far */
	char	svc_date[DC_SCSI_MFR_LEN];	/* service date YYYYWW */
	int	flag;				/* reserved for future */
};

struct pm_smart_count {
	int	allowed;	/* normalized max cycles allowed */
	int	consumed;	/* normalized consumed cycles */
	int	flag;		/* type of cycles */
};

struct pm_trans_data {
	int	format;				/* data format */
	union {
		struct pm_scsi_cycles scsi_cycles;
		struct pm_smart_count smart_count;
	} un;
};

/*
 * Power levels for devices supporting ACPI based D0, D1, D2, D3 states.
 *
 * Note that 0 is off in Solaris PM framework but D0 is full power
 * for these devices.
 */
#define	PM_LEVEL_D3		0	/* D3 state - off */
#define	PM_LEVEL_D2		1	/* D2 state */
#define	PM_LEVEL_D1		2	/* D1 state */
#define	PM_LEVEL_D0		3	/* D0 state - fully on */

/*
 * Useful strings for creating pm-components property for these devices.
 * If a device driver wishes to provide more specific description of power
 * levels (highly recommended), it should NOT use following generic defines.
 */
#define	PM_LEVEL_D3_STR		"0=Device D3 State"
#define	PM_LEVEL_D2_STR		"1=Device D2 State"
#define	PM_LEVEL_D1_STR		"2=Device D1 State"
#define	PM_LEVEL_D0_STR		"3=Device D0 State"

/*
 * Generic Sun PM definitions.
 */

/*
 * These are obsolete power management interfaces, they will be removed from
 * a subsequent release.
 */
int pm_create_components(dev_info_t *dip, int num_components);

void pm_destroy_components(dev_info_t *dip);

void pm_set_normal_power(dev_info_t *dip, int component_number, int level);

int pm_get_normal_power(dev_info_t *dip, int component_number);

/*
 * These are power management interfaces.
 */

int pm_busy_component(dev_info_t *dip, int component_number);

int pm_idle_component(dev_info_t *dip, int component_number);

int pm_get_current_power(dev_info_t *dip, int component, int *levelp);

int pm_power_has_changed(dev_info_t *, int, int);

int pm_trans_check(struct pm_trans_data *datap, time_t *intervalp);

int pm_lower_power(dev_info_t *dip, int comp, int level);

int pm_raise_power(dev_info_t *dip, int comp, int level);

int pm_update_maxpower(dev_info_t *dip, int comp, int level);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SUNPM_H */
