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
 *
 * fme.h -- public definitions for fme module
 *
 * this module supports the management of a "fault management exercise".
 */

#ifndef	_EFT_FME_H
#define	_EFT_FME_H

#include <fm/fmd_api.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	UNDIAG_DEFECT_CHKPT	"defect.sunos.eft.undiag.checkpoint"
#define	UNDIAG_DEFECT_FME	"defect.sunos.eft.undiag.fme"
#define	UNDIAG_DEFECT_LIMIT	"defect.sunos.eft.undiag.limit"
#define	UNDIAG_DEFECT_UNKNOWN	"defect.sunos.eft.undiag.unknown"

#define	UNDIAG_REASON		"reason"

/* Undiagnosable reason values */
#define	UD_VAL_UNKNOWN		0
#define	UD_VAL_BADEVENTI	1
#define	UD_VAL_BADOBS		2
#define	UD_VAL_CFGMISMATCH	3
#define	UD_VAL_INSTFAIL		4
#define	UD_VAL_MAXFME		5
#define	UD_VAL_MISSINGINFO	6
#define	UD_VAL_MISSINGOBS	7
#define	UD_VAL_MISSINGPATH	8
#define	UD_VAL_MISSINGZERO	9
#define	UD_VAL_NOPATH		10
#define	UD_VAL_UNSOLVD		11

/* Undiagnosable reason strings */
#define	UD_STR_UNKNOWN		"undiagnosable reason unknown"
#define	UD_STR_MISSINGPATH	"bad or missing path in persisted observation"
#define	UD_STR_MISSINGINFO	"buffer persisting case info is AWOL"
#define	UD_STR_MISSINGZERO	"buffer persisting principal ereport is AWOL"
#define	UD_STR_CFGMISMATCH	"persisted config buffer size != actual size"
#define	UD_STR_MISSINGOBS	"buffer persisting an observation is AWOL"
#define	UD_STR_BADEVENTI	"ereport zero not found in instance tree"
#define	UD_STR_INSTFAIL	"creation of instance tree failed"
#define	UD_STR_UNSOLVD	"all hypotheses disproved"
#define	UD_STR_BADOBS	"persisted observation not found in instance tree"
#define	UD_STR_NOPATH	"no path to component found in ereport"
#define	UD_STR_MAXFME	"reached the maximum number of open FMEs (maxfme)"

#define	WOBUF_CFGLEN	"rawcfglen"
#define	WOBUF_POSTD	"posted"
#define	WOBUF_NOBS	"observations"
#define	WOBUF_PULL	"timewaited"
#define	WOBUF_CFG	"rawcfgdata"
#define	WOBUF_ID	"fmeid"
#define	WOBUF_ISTATS	"istats"
#define	WOBUF_SERDS	"serds"

struct lut *Istats;	/* instanced stats a la "count=" */
struct lut *SerdEngines;

struct fme;

void fme_receive_external_report(fmd_hdl_t *hdl, fmd_event_t *ffep,
    nvlist_t *nvl, const char *eventstring);
void fme_receive_topology_change(void);
void fme_receive_repair_list(fmd_hdl_t *hdl, fmd_event_t *ffep,
    nvlist_t *nvl, const char *eventstring);
void fme_restart(fmd_hdl_t *hdl, fmd_case_t *inprogress);
void fme_istat_load(fmd_hdl_t *hdl);
void fme_serd_load(fmd_hdl_t *hdl);
void fme_close_case(fmd_hdl_t *hdl, fmd_case_t *fmcase);
void fme_timer_fired(struct fme *, id_t);
void fme_status(int flags);
void fme_fini(void);
void istat_fini(void);

struct istat_entry {
	const char *ename;
	const struct ipath *ipath;
};
int istat_cmp(struct istat_entry *ent1, struct istat_entry *ent2);

void serd_fini(void);

struct serd_entry {
	const char *ename;
	const struct ipath *ipath;
	fmd_hdl_t *hdl;
};
int serd_cmp(struct serd_entry *ent1, struct serd_entry *ent2);

#ifdef	__cplusplus
}
#endif

#endif	/* _EFT_FME_H */
