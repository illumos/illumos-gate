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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CMD_DATAPATH_H
#define	_CMD_DATAPATH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <cmd_fmri.h>

/*
 * Member Name     Data Type          Comments
 * -----------     ---------          -----------
 * version         uint8              0
 * class           string             "asic"
 * ENA             uint64             ENA Format 1
 * detector        fmri               aggregated ID data for SC-DE
 *
 * Datapath ereport subclasses and data payloads:
 * There will be two types of ereports (error and fault) which will be
 * identified by the "type" member.
 *
 * ereport.asic.*.cds.cds-dp
 * ereport.asic.*.dx.dx-dp
 * ereport.asic.*.sdi.sdi-dp
 * ereport.asic.*.cp.cp-dp
 * ereport.asic.*.rp.rp-dp
 *
 * Member Name     Data Type          Comments
 * -----------     ---------          -----------
 * erptype         uint16            derived from message type: error or
 *                                   fault
 * t-value         uint32            SC's datapath SERD timeout threshold
 * dp-list-sz      uint8             number of dp-list array elements
 * dp-list         array of uint16   Safari IDs of affected cpus
 * sn-list         array of uint64   Serial numbers of affected cpus
 */

#define		DP_MAX_FRU	23	/* maximum char length of dp FRUs */
#define		DP_MAX_ASRUS	12	/* maximum number of dp ASRUs */
#define		DP_MAX_CLASS	32	/* max length of dp fault class */
#define		DP_MAX_BUF	16	/* max len for general purpose buffer */
#define		DP_MAX_NUM_CPUS	8	/* max number of CPUs in a DP ereport */
#define		DP_MAX_MCS	4	/* max # of MCs per memory page */

#define	CMD_DP_VERSION_0	0
#define	CMD_DP_VERSION		CMD_DP_VERSION_0

/* Portion of datapath structure to be persisted */
typedef struct cmd_dp_pers {
	cmd_header_t	dpp_header;	/* Nodetype must be CMD_NT_DP */
	uint_t		dpp_version;	/* struct version */
	uint16_t	dpp_erpt_type;	/* ereport type (fault or error) */
	uint8_t		dpp_err;	/* CDS, DX, EX, CP (xc), RP (sg) */
	uint32_t	dpp_t_value;	/* SERD timeout threshold (seconds) */
	uint32_t	dpp_ncpus;	/* number of associated CPUs */
	uint16_t	dpp_cpuid_list[DP_MAX_NUM_CPUS]; /* array of CPU ids */
	uint64_t	dpp_serid_list[DP_MAX_NUM_CPUS]; /* CPU serial #'s */
} cmd_dp_pers_t;

typedef struct cmd_dp {
	cmd_dp_pers_t	dp_pers;
	fmd_case_t	*dp_case;	/* fmd case pointer */
	id_t		dp_id;		/* timer id */
} cmd_dp_t;

#define	CMD_DP_MAXSIZE		sizeof (cmd_dp_pers_t)
#define	CMD_DP_MINSIZE		sizeof (cmd_dp_pers_t)

#define	dp_header		dp_pers.dpp_header
#define	dp_nodetype		dp_pers.dpp_header.hdr_nodetype
#define	dp_bufname		dp_pers.dpp_header.hdr_bufname
#define	dp_version		dp_pers.dpp_version
#define	dp_erpt_type		dp_pers.dpp_erpt_type
#define	dp_err			dp_pers.dpp_err
#define	dp_cpuid		dp_pers.dpp_cpuid
#define	dp_ncpus		dp_pers.dpp_ncpus
#define	dp_t_value		dp_pers.dpp_t_value
#define	dp_cpuid_list		dp_pers.dpp_cpuid_list
#define	dp_serid_list		dp_pers.dpp_serid_list

extern cmd_evdisp_t cmd_dp_cds(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

extern cmd_evdisp_t cmd_dp_dx(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

extern cmd_evdisp_t cmd_dp_ex(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

extern cmd_evdisp_t cmd_dp_cp(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

extern void cmd_dp_close(fmd_hdl_t *, void *);
extern void cmd_dp_timeout(fmd_hdl_t *, id_t);
extern cmd_dp_t *cmd_dp_lookup_fault(fmd_hdl_t *, uint32_t);
extern void *cmd_dp_restore(fmd_hdl_t *, fmd_case_t *, cmd_case_ptr_t *);
extern void cmd_dp_validate(fmd_hdl_t *);
extern void cmd_dp_destroy(fmd_hdl_t *, cmd_dp_t *);
extern nvlist_t *cmd_dp_setasru(fmd_hdl_t *, cmd_dp_t *);
extern cmd_dp_t *cmd_dp_lookup_error(cmd_dp_t *);
extern void dp_buf_write(fmd_hdl_t *, cmd_dp_t *);
extern int cmd_dp_error(fmd_hdl_t *);
extern int cmd_dp_fault(fmd_hdl_t *, uint64_t);
extern int cmd_dp_get_mcid(uint64_t, int *);
extern void cmd_dp_fini(fmd_hdl_t *);

#endif /* _CMD_DATAPATH_H */
