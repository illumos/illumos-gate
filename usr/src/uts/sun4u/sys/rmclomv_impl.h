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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_RMCLOMV_IMPL_H
#define	_SYS_RMCLOMV_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/envmon.h>

/*
 * local driver defines and structures
 */

#define	RMCLOMV_DEFAULT_MAX_MBOX_WAIT_TIME	10000
#define	RMCLOMV_MIN_LED_STATE			0
#define	RMCLOMV_MAX_LED_STATE			2
/*
 * These are PSU flag bits that map to voltage-indicators:
 * DP_PSU_OUTPUT_STATUS
 * DP_PSU_INPUT_STATUS
 * DP_PSU_SEC_INPUT_STATUS
 * DP_PSU_OUTPUT_VLO_STATUS
 * DP_PSU_OUTPUT_VHI_STATUS
 */
#define	RMCLOMV_MAX_VI_PER_PSU			5

/*
 * Current indicators:
 * DP_PSU_OUTPUT_AHI_STATUS
 * DP_PSU_NR_WARNING
 */
#define	RMCLOMV_MAX_CI_PER_PSU			2

/*
 * Fan indicators:
 * DP_PSU_FAN_FAULT
 * DP_PSU_PDCT_FAN
 */
#define	RMCLOMV_MAX_FI_PER_PSU			2

/*
 * Temperature indicators:
 * DP_PSU_OVERTEMP_FAULT
 */
#define	RMCLOMV_MAX_TI_PER_PSU			1

#define	RMCLOMV_NUM_SPECIAL_FRUS		1
#define	RMCLOMV_MIN_ALARM_STATE			0
#define	RMCLOMV_MAX_ALARM_STATE			1

/*
 * defines for various environmental detectors
 */
#define	RMCLOMV_ANY_ENV		0
#define	RMCLOMV_TEMP_SENS	1
#define	RMCLOMV_FAN_SENS	2
#define	RMCLOMV_PSU_IND		3
#define	RMCLOMV_LED_IND		4
#define	RMCLOMV_VOLT_SENS	5
#define	RMCLOMV_HPU_IND		6
#define	RMCLOMV_AMP_IND		7
#define	RMCLOMV_VOLT_IND	8
#define	RMCLOMV_TEMP_IND	9
#define	RMCLOMV_FAN_IND		10
#define	RMCLOMV_ALARM_IND	11

typedef struct {
	dp_handle_t	handle;
	uint16_t	ind_mask;
	envmon_handle_t	handle_name;
} rmclomv_cache_entry_t;

/*
 * section_len is used when freeing the structure.
 * It includes unused entries whereas num_entries does not.
 */
typedef struct rmclomv_cache_section {
	struct rmclomv_cache_section	*next_section;
	size_t				section_len;
	uint16_t			sensor_type;
	uint16_t			num_entries;
	rmclomv_cache_entry_t		entry[1];
} rmclomv_cache_section_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RMCLOMV_IMPL_H */
