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

#ifndef _REPORT_H
#define	_REPORT_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Prototypes */
uint64_t hrtime_delta(hrtime_t, hrtime_t);
uint32_t u32_delta(uint32_t, uint32_t);
uint64_t u64_delta(uint64_t, uint64_t);
void io_report(kstat_io_t *, kstat_io_t *, sdbcstat_t *);
int io_value_check(kstat_io_t *, kstat_io_t *);
void cd_report(sdbcstat_t *);
void header();

/* BEGIN CSTYLED */
/* END CSTYLED */

#define	VOL_HDR_FMT	"%-16s"
#define	VOL_HDR_SIZE	17
#define	SET_HDR_TXT	"name"

#define	STAT_HDR_FMT	"%3s"
#define	STAT_HDR_SIZE	3
#define	STAT_HDR_TXT	"s"
#define	TYPE_HDR_TXT	"t"

#define	ROLE_HDR_FMT	"%5s"
#define	ROLE_HDR_SIZE	5
#define	ROLE_INF_FMT	" %4s"
#define	ROLE_HDR_TXT	"role"

#define	PCT_HDR_FMT	"%7s"
#define	PCT_HDR_SIZE	7
#define	PCT_INF_FMT	" %6.2f"
#define	SN_HDR_TXT	"sn"
#define	PCT_HDR_TXT	"pct"

#define	KPS_HDR_FMT	"%7s"
#define	KPS_HDR_SIZE	7
#define	KPS_INF_FMT	" %6.0f"
#define	KPS_HDR_TXT	"kps"
#define	RKPS_HDR_TXT	"rkps"
#define	WKPS_HDR_TXT	"wkps"
#define	CKPS_HDR_TXT	"ckps"
#define	DKPS_HDR_TXT	"dkps"
#define	CRKPS_HDR_TXT	"crkps"
#define	CWKPS_HDR_TXT	"cwkps"
#define	DRKPS_HDR_TXT	"drkps"
#define	DWKPS_HDR_TXT	"dwkps"

#define	TPS_HDR_FMT	"%6s"
#define	TPS_HDR_SIZE	6
#define	TPS_INF_FMT	" %5u"
#define	TPS_HDR_TXT	"tps"
#define	RTPS_HDR_TXT	"rtps"
#define	WTPS_HDR_TXT	"wtps"

#define	SVT_HDR_FMT	"%5s"
#define	SVT_HDR_SIZE	5
#define	SVT_INF_FMT	" %4.0f"
#define	SVT_HDR_TXT	"svt"

#define	HIT_HDR_FMT	"%6s"
#define	HIT_HDR_SIZE	6
#define	HIT_INF_FMT	" %5.1f"
#define	HIT_PAD_FMT	" %5s"
#define	HIT_HDR_TXT	"hit"
#define	RHIT_HDR_TXT	"rhit"
#define	WHIT_HDR_TXT	"whit"

#define	QUEUE_HDR_TXT		"q"
#define	QUEUE_ITEMS_TXT		"qi"
#define	QUEUE_KBYTES_TXT	"qk"
#define	QUEUE_ITEMS_HW_TXT	"qhwi"
#define	QUEUE_KBYTES_HW_TXT	"qhwk"

#define	NO_INFO		"-"

#define	DATA_C16	"%-16s"
#define	DATA_C2		" %2s"
#define	DATA_C4		" %4s"
#define	DATA_C5		" %5s"
#define	DATA_C6		" %6s"
#define	DATA_I32	" %6u"
#define	DATA_I64	" %6llu"
#define	DATA_F62	" %6.2f"
#define	DATA_F60	" %6.0f"
#define	DATA_F50	" %5.0f"
#define	DATA_F40	" %4.0f"

#ifdef	__cplusplus
}
#endif

#endif /* _REPORT_H */
