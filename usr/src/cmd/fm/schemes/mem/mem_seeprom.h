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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MEM_SEEPROM_H
#define	_MEM_SEEPROM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Layout of SEEPROM data
 *
 * XXX need cite
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Care must be taken when accessing these structures, as the SEEPROM source
 * data does not have an alignment requirement.
 */

typedef struct seeprom_seg_sd {
	uint32_t seesd_header;
	uint32_t seesd_tstamp;
	char seesd_frudesc[80];
	char seesd_mfgloc[64];
	char seesd_sun_pno[7];
	char seesd_sun_sno[6];
	uint8_t seesd_vendorhi;
	uint8_t seesd_vendorlo;
	char seesd_hwdash[2];
	char seesd_hwrev[2];
	char seesd_fruname[16];
} seeprom_seg_sd_t;

typedef struct seeprom_seg {
	char sees_name[2];
	uint16_t sees_prothi;
	uint16_t sees_protlo;
	uint16_t sees_segoff;
	uint16_t sees_seglen;
} seeprom_seg_t;

typedef struct seeprom_container {
	uint8_t	seec_tag;
	uint8_t seec_verhi;
	uint8_t seec_verlo;
	uint8_t seec_contsz;
	uint8_t seec_crc8;
	uint8_t seec_nsegs;
} seeprom_container_t;

#ifdef __cplusplus
}
#endif

#endif /* _MEM_SEEPROM_H */
