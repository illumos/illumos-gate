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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CMD_LxCACHE_H
#define	_CMD_LxCACHE_H

/*
 * Routines for the creation of Lxcache retirement faults and for the
 * management of Lxcache-related state.
 */

#include <cmd_state.h>
#include <cmd_cpu.h>
#include <cmd_fmri.h>

#include <fm/fmd_api.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	QTCLR		1
#define	CMD_ANON_WAY	-1
#define	MAX_WAYS	8
#define	HUNDRED_PERCENT	100
#define	SUSPECT_PERCENT	50

#define	CMD_LxCACHE_F_ACTIVE	0x0
#define	CMD_LxCACHE_F_FAULTING	0x1
#define	CMD_LxCACHE_F_RETIRED	0x2
#define	CMD_LxCACHE_F_UNRETIRED	0x4
#define	CMD_LxCACHE_F_RERETIRED	0x8

#define	LxCACHE_MKVERSION(version)	((version) << 4 | 1)

#define	CMD_LxCACHE_VERSION_1	LxCACHE_MKVERSION(1)	/* 17 */
#define	CMD_LxCACHE_VERSION	CMD_LxCACHE_VERSION_1

#define	CMD_LxCACHE_VERSIONED(Lxcache)	((Lxcache)->Lxcache_version & 1)

#define	MAX_FMRI_LEN	128

#define	IS_TAG(type)	((type == CMD_PTR_CPU_L2TAG) ||\
			    (type == CMD_PTR_CPU_L3TAG))

typedef struct cmd_Lxcache_pers {
	cmd_header_t Lxcachep_header;	/* Nodetype must be CMD_NT_LxCACHE */
	/*
	 * We need the cpu_hdr_bufname  in order to restore the Lxcache.
	 */
	char Lxcachep_cpu_hdr_bufname[CMD_BUFNMLEN];
	uint_t Lxcachep_version;
	cmd_fmri_t Lxcachep_asru;	/* ASRU for this LxCACHE */
	char	Lxcachep_retired_fmri[MAX_FMRI_LEN];
	cmd_ptrsubtype_t Lxcachep_type;	/* L2 or L3 */
	uint32_t Lxcachep_index;	/* cache index Lxcache represents */
	uint32_t Lxcachep_way;		/* cache way this Lxcache represents */
	uint16_t Lxcachep_bit;		/* bit in Lxcache that has fault */
	uint_t Lxcachep_flags;		/* CMD_MEM_F_* */
	uint_t	Lxreason;		/* Suspicion or convicted */
} cmd_Lxcache_pers_t;

#define	CMD_LXFUNCTIONING	0	/* Initial value */
#define	CMD_LXSUSPICIOUS	0x1
#define	CMD_LXSUSPECT_DATA	0x1
#define	CMD_LXCONVICTED		0x2
#define	CMD_LXSUSPECT_0_TAG	0x4
#define	CMD_LXSUSPECT_1_TAG	0x8
#define	CMD_LXSUSPICIOUS_BY_ASSOCIATION		0x10
#define	CMD_LXCONVICTED_BY_ASSOCIATION		0x20

typedef struct cmd_Lxcache {
	cmd_Lxcache_pers_t Lxcache_pers;
	int	Lxcache_retry_count;	/* retry count for recheck taga */
	id_t	Lxcache_timeout_id;
	cmd_errcl_t	Lxcache_clcode;
	char	*Lxcache_class;
	fmd_event_t	*Lxcache_ep;
	nvlist_t	*Lxcache_nvl;
	char	*Lxcache_serdnm;	/* SERD to hold the ep during */
					/* recheck of tags */
	cmd_case_t Lxcache_case;	/* Open CE case against this Lxcache */
	cmd_xr_t	*xr;		/* The associated XR struct */
} cmd_Lxcache_t;

#define	Lxcache_header		Lxcache_pers.Lxcachep_header
#define	Lxcache_nodetype	Lxcache_pers.Lxcachep_header.hdr_nodetype
#define	Lxcache_bufname		Lxcache_pers.Lxcachep_header.hdr_bufname
#define	Lxcache_cpu_bufname	Lxcache_pers.Lxcachep_cpu_hdr_bufname
#define	Lxcache_version		Lxcache_pers.Lxcachep_version
#define	Lxcache_asru		Lxcache_pers.Lxcachep_asru
#define	Lxcache_asru_nvl	Lxcache_pers.Lxcachep_asru.fmri_nvl
#define	Lxcache_flags		Lxcache_pers.Lxcachep_flags
#define	Lxcache_type		Lxcache_pers.Lxcachep_type
#define	Lxcache_index		Lxcache_pers.Lxcachep_index
#define	Lxcache_way		Lxcache_pers.Lxcachep_way
#define	Lxcache_bit		Lxcache_pers.Lxcachep_bit
#define	Lxcache_retired_fmri	Lxcache_pers.Lxcachep_retired_fmri
#define	Lxcache_reason		Lxcache_pers.Lxreason
#define	Lxcache_list		Lxcache_header.hdr_list

/*
 * Lxcache retirement
 *
 * When a Lxcache is to be retired, these routines are called to generate and
 * manage a fault.memory.Lxcache against the Lxcache.
 */
#ifdef sun4u
extern int cmd_cache_ce_panther(fmd_hdl_t *, fmd_event_t *, cmd_xr_t *);
extern int cmd_xr_pn_cache_fill(fmd_hdl_t *, nvlist_t *, cmd_xr_t *,
    cmd_cpu_t *, cmd_errcl_t);
#endif
extern cmd_evdisp_t cmd_us4plus_tag_err(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
	cmd_cpu_t *, cmd_ptrsubtype_t,
	const char *, const char *, const char *, cmd_errcl_t);
extern void cmd_Lxcache_close(fmd_hdl_t *, void *);
extern void cmd_Lxcache_write(fmd_hdl_t *, cmd_Lxcache_t *);

extern cmd_Lxcache_t *cmd_Lxcache_create(fmd_hdl_t *,  cmd_xr_t *xr,
    cmd_cpu_t *, nvlist_t *, cmd_ptrsubtype_t, int32_t, int8_t, int16_t);

extern cmd_Lxcache_t *cmd_Lxcache_lookup_by_type_index_way_bit(cmd_cpu_t *,
	cmd_ptrsubtype_t, int32_t, int8_t, int16_t);

extern cmd_Lxcache_t *
cmd_Lxcache_lookup_by_index_way(cmd_cpu_t *, cmd_ptrsubtype_t,
	int32_t, int8_t);
extern cmd_Lxcache_t *
cmd_Lxcache_lookup_by_type_index_way_reason(cmd_cpu_t *, cmd_ptrsubtype_t,
	int32_t, int8_t, int32_t);
extern cmd_Lxcache_t *
cmd_Lxcache_lookup_by_type_index_bit_reason(cmd_cpu_t *, cmd_ptrsubtype_t,
	int32_t, int16_t, int32_t);
extern int8_t cmd_Lxcache_get_next_retirable_way(cmd_cpu_t *, int32_t,
	cmd_ptrsubtype_t, int8_t);
extern int8_t cmd_Lxcache_get_lowest_retirable_way(cmd_cpu_t *,
	int32_t, cmd_ptrsubtype_t);
extern void cmd_Lxcache_destroy_anonymous_serd_engines(fmd_hdl_t *,
	cmd_cpu_t *, cmd_ptrsubtype_t, int32_t, int16_t);
extern const char *cmd_type_to_str(cmd_ptrsubtype_t);
extern const char *cmd_reason_to_str(int);
extern const char *cmd_flags_to_str(int);
extern boolean_t cmd_Lxcache_unretire(fmd_hdl_t *, cmd_cpu_t *,
	cmd_Lxcache_t *, const char *);
extern boolean_t cmd_Lxcache_retire(fmd_hdl_t *, cmd_cpu_t *,
	cmd_Lxcache_t *, const char *, uint_t);
extern int cmd_Lx_repair_rsrc(fmd_hdl_t *, nvlist_t *);
extern ssize_t cmd_fmri_nvl2str(fmd_hdl_t *hdl, nvlist_t *nvl, char *,
	size_t);
extern void cmd_Lxcache_dirty(fmd_hdl_t *, cmd_Lxcache_t *);
extern void *cmd_Lxcache_restore(fmd_hdl_t *, fmd_case_t *, cmd_case_ptr_t *);
extern void cmd_Lxcache_validate(fmd_hdl_t *, cmd_cpu_t *);
extern void cmd_Lxcache_destroy(fmd_hdl_t *, cmd_cpu_t *, cmd_Lxcache_t *);
extern void cmd_Lxcache_free(fmd_hdl_t *, cmd_cpu_t *, cmd_Lxcache_t *, int);
extern void cmd_Lxcache_fini(fmd_hdl_t *, cmd_cpu_t *);
extern char *cmd_Lxcache_serdnm_create(fmd_hdl_t *, uint32_t, cmd_ptrsubtype_t,
				int32_t, int8_t, int16_t);
extern char *cmd_Lxcache_anonymous_serdnm_create(fmd_hdl_t *, uint32_t,
		cmd_ptrsubtype_t, int32_t, int8_t, int16_t);
extern void cmd_Lxcache_gc(fmd_hdl_t *);
extern void cmd_Lxcache_fault(fmd_hdl_t *, cmd_cpu_t *, cmd_Lxcache_t *,
				const char *, nvlist_t *, uint_t);
extern cmd_evdisp_t get_tagdata(cmd_cpu_t *, cmd_ptrsubtype_t,
    int32_t, uint64_t *);

extern int get_cpu_retired_ways(cmd_cpu_t *, cmd_ptrsubtype_t);
extern int get_index_retired_ways(cmd_cpu_t *, cmd_ptrsubtype_t, int32_t);
extern int is_index_way_retired(cmd_cpu_t *, cmd_ptrsubtype_t, int32_t,
    int8_t);
extern void cmd_fault_the_cpu(fmd_hdl_t *, cmd_cpu_t *, cmd_ptrsubtype_t,
	    const char *);
extern uint32_t cmd_Lx_index_count_type1_ways(cmd_cpu_t *);
extern uint32_t cmd_Lx_index_count_type2_ways(cmd_cpu_t *);
extern void cmd_Lxcache_anonymous_tag_error_timeout(fmd_hdl_t *, id_t);
extern cmd_Lxcache_t *cmd_Lxcache_lookup_by_timeout_id(id_t);
extern boolean_t cmd_create_case_for_Lxcache(fmd_hdl_t *, cmd_cpu_t *,
	cmd_Lxcache_t *);
extern int test_mode;
#ifdef __cplusplus
}
#endif

#endif /* _CMD_LxCACHE_H */
