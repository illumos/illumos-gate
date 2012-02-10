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

#ifndef _CMD_CPU_H
#define	_CMD_CPU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Each CPU of interest has a cmd_cpu_t structure.  CPUs become of interest when
 * they are the focus of ereports, or when they detect UEs.  CPUs may be the
 * target of several different kinds of ereport, each of which is tracked
 * differently.  cpu_cases lists the types of cases that can be open against a
 * given CPU.  The life of a CPU is complicated by the fact that xxCs and xxUs
 * received by the DE may in fact be side-effects of earlier UEs, xxCs, or xxUs.
 * Causes of side-effects, and actions taken to resolve them, can be found below
 * and in cmd_memerr.h.
 *
 * Data structures:
 *      ________                                   CMD_PTR_CPU_ICACHE
 *     /        \       ,--------.                 CMD_PTR_CPU_DCACHE
 *     |CPU     | <---- |case_ptr| (one or more of CMD_PTR_CPU_PCACHE         )
 *     |        |       `--------'                 CMD_PTR_CPU_ITLB
 *     |,-------|       ,-------.                  CMD_PTR_CPU_DTLB
 *     ||asru   | ----> |fmri_t |                  CMD_PTR_CPU_L2DATA
 *     |:-------|       :-------:                  CMD_PTR_CPU_L2DATA_UERETRY
 *     ||fru    | ----> |fmri_t |                  CMD_PTR_CPU_L2TAG
 *     |`-------|       `-------'                  CMD_PTR_CPU_L3DATA
 *     |        |       ,---------.                CMD_PTR_CPU_L3DATA_UERETRY
 *     | uec    | ----> |UE cache |                CMD_PTR_CPU_L3TAG
 *     \________/       `---------'                CMD_PTR_CPU_FPU
 *						   CMD_PTR_CPU_IREG
 *						   CMD_PTR_CPU_FREG
 *						   CMD_PTR_CPU_MAU
 *						   CMD_PTR_CPU_L2CTL
 *
 *      ________
 *     /        \       ,--------.
 *     | xr     | <---- |case_ptr| (CMD_PTR_XR_WAITER)
 *     |        |       `--------'
 *     |,-------|       ,-------.
 *     ||rsrc   | ----> |fmri_t |
 *     |`-------|       `-------'
 *     | cpu    | ----> detecting CPU
 *     \________/
 *
 * Data structure	P?  Case- Notes
 *                          Rel?
 * ----------------	--- ----- --------------------------------------
 * cmd_cpu_t		Yes No    Name is derived from CPU ID ("cpu_%d")
 * cmd_case_ptr_t	Yes Yes   Name is case's UUID
 * cpu_asru (fmri_t)	Yes No    Name is derived from CPU ID ("cpu_asru_%d")
 * cpu_fru (fmri_t)	Yes No    Name is derived from CPU ID ("cpu_fru_%d")
 * cpu_uec		Yes No    Name is derived from CPU ID ("cpu_uec_%d")
 * cmd_xr_t		Yes Yes   Name is `redelivery'
 * xr_rsrc (fmri_t)     Yes No    Name is derived from case's UUID ("%s_rsrc")
 */

#include <cmd.h>
#include <cmd_state.h>
#include <cmd_fmri.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	CPU_FRU_FMRI		FM_FMRI_SCHEME_HC":///" \
    FM_FMRI_LEGACY_HC"="

#define	BK_LFUFAULT_CERT	50

typedef struct cmd_cpu cmd_cpu_t;

typedef enum cmd_cpu_type {
	CPU_ULTRASPARC_III = 1,
	CPU_ULTRASPARC_IIIplus,
	CPU_ULTRASPARC_IIIi,
	CPU_ULTRASPARC_IV,
	CPU_ULTRASPARC_IVplus,
	CPU_ULTRASPARC_IIIiplus,
	CPU_ULTRASPARC_T1,
	CPU_SPARC64_VI,
	CPU_SPARC64_VII,
	CPU_ULTRASPARC_T2,
	CPU_ULTRASPARC_T2plus
} cmd_cpu_type_t;

typedef struct cmd_cpu_cases {
	cmd_case_t cpuc_icache;		/* All I$ errors (IPE, IDSPE, etc) */
	cmd_case_t cpuc_dcache;		/* All D$ errors (DPE, DDSPE, etc) */
	cmd_case_t cpuc_pcache;		/* All P$ errors (PDSPE) */
	cmd_case_t cpuc_itlb;		/* ITLB errors (ITLBPE) */
	cmd_case_t cpuc_dtlb;		/* DTLB errors (DTLBPE) */
	cmd_case_t cpuc_l2data;		/* All correctable L2$ data errors */
	cmd_case_t cpuc_l2tag;		/* All correctable L2$ tag errors */
	cmd_case_t cpuc_l3data;		/* All correctable L3$ data errors */
	cmd_case_t cpuc_l3tag;		/* All correctable L3$ tag errors */
	cmd_case_t cpuc_fpu;		/* FPU errors */
	cmd_case_t cpuc_ireg;		/* Integer reg errors (IRC, IRU) */
	cmd_case_t cpuc_freg;		/* Floatpnt reg errors (frc, fru) */
	cmd_case_t cpuc_mau;		/* Modular arith errors (MAU) */
	cmd_case_t cpuc_l2ctl;		/* L2$ directory, VUAD parity */
	cmd_case_t cpuc_misc_regs;	/* Scratchpad array (SCA) */
					/* Tick compare (TC) */
					/* Store buffer (SBD) */
					/* Trap stack array errors (TSA) */
	cmd_case_t cpuc_lfu;		/* Coherency link error (LFU) */
#ifdef sun4u
	cmd_case_t cpuc_opl_invsfsr;	/* Olympus-C cpu inv-sfsr errors */
	cmd_case_t cpuc_oplue_detcpu;	/* Olympus-C cpu det. ue (eid=CPU) */
	cmd_case_t cpuc_oplue_detio;	/* Olympus-C io det. ue (eid=CPU) */
	cmd_case_t cpuc_opl_mtlb;	/* Olympus-C mtlb errors */
	cmd_case_t cpuc_opl_tlbp;	/* Olympus-C tlbp errors */
	cmd_case_t cpuc_opl_inv_urg;	/* Olympus-C inv-urg invalid urgent */
	cmd_case_t cpuc_opl_cre;	/* Olympus-C cre urgent errors */
	cmd_case_t cpuc_opl_tsb_ctx;	/* Olympus-C tsb_ctx urgent errors */
	cmd_case_t cpuc_opl_tsbp;	/* Olympus-C tsbp urgent errors */
	cmd_case_t cpuc_opl_pstate;	/* Olympus-C pstate urgent errors */
	cmd_case_t cpuc_opl_tstate;	/* Olympus-C tstate urgent errors */
	cmd_case_t cpuc_opl_iug_f;	/* Olympus-C iug_f urgent errors */
	cmd_case_t cpuc_opl_iug_r;	/* Olympus-C iug_r urgent errors */
	cmd_case_t cpuc_opl_sdc;	/* Olympus-C sdc urgent errors */
	cmd_case_t cpuc_opl_wdt;	/* Olympus-C wdt urgent errors */
	cmd_case_t cpuc_opl_dtlb;	/* Olympus-C dtlb urgent errors */
	cmd_case_t cpuc_opl_itlb;	/* Olympus-C itlb urgent errors */
	cmd_case_t cpuc_opl_core_err;	/* Olympus-C core-err urgent errors */
	cmd_case_t cpuc_opl_dae;	/* Olympus-C dae urgent errors */
	cmd_case_t cpuc_opl_iae;	/* Olympus-C iae urgent errors */
	cmd_case_t cpuc_opl_uge;	/* Olympus-C uge urgent errors */
#endif	/* sun4u */
} cmd_cpu_cases_t;

/*
 * The UE cache.  We actually have two UE caches - the current one and the old
 * one.  When it's time to flush the UE cache, we move the current UE cache to
 * the old position and flush the E$.  Then, we schedule the removal of the old
 * UE cache.  This allows a) xxUs triggered by the flush to match against the
 * old cache, while b) still allowing new UEs to be added to the current UE
 * cache.  UE matches will always search in both caches (if present), but
 * additions will only end up in the current cache.  We go to all of this
 * effort because the cost of a missed ereport (discarding due to a false match
 * in the cache) is much less than that of a missed match.  In the latter case,
 * the CPU will be erroneously offlined.
 *
 * A special case is triggered if we see a UE with a not valid AFAR.  Without
 * the AFAR, we aren't able to properly match subsequent xxU's.  As a result,
 * we need to throw the cache into all-match mode, wherein all subsequent match
 * attempts will succeed until the UE cache is flushed.
 */

#define	CPU_UEC_F_ALLMATCH	0x1	/* all-match mode active */

typedef struct cmd_cpu_uec {
	uint64_t *uec_cache;		/* The UE cache */
	uint_t uec_nent;		/* Number of allocated slots in cache */
	uint_t uec_flags;		/* CPU_UEC_F_* */
	char uec_bufname[CMD_BUFNMLEN];	/* Name of buffer used for cache */
} cmd_cpu_uec_t;

extern const char *cmd_cpu_type2name(fmd_hdl_t *, cmd_cpu_type_t);
extern void cmd_cpu_uec_add(fmd_hdl_t *, cmd_cpu_t *, uint64_t);
extern int cmd_cpu_uec_match(cmd_cpu_t *, uint64_t);
extern void cmd_cpu_uec_clear(fmd_hdl_t *, cmd_cpu_t *);
extern void cmd_cpu_uec_set_allmatch(fmd_hdl_t *, cmd_cpu_t *);

/*
 * Certain types of xxC and xxU can trigger other types as side-effects.  These
 * secondary ereports need to be discarded, as treating them as legitimate
 * ereports in their own right will cause erroneous diagnosis.  As an example
 * (see cmd_xxcu_trains for more), an L2$ UCC will usually trigger an L2$ WDC
 * resulting from the trap handler's flushing of the L2$.  If we treat both as
 * legitimate, we'll end up adding two ereports to the SERD engine,
 * significantly cutting the threshold for retiring the CPU.
 *
 * Our saving grace is the fact that the side-effect ereports will have the same
 * ENA as the primary.  As such, we can keep track of groups of ereports by ENA.
 * These groups, which we'll call trains, can then be matched against a list of
 * known trains.  The list (an array of cmd_xxcu_train_t structures) has both a
 * description of the composition of the train and an indication as to which of
 * the received ereports is the primary.
 *
 * The cmd_xxcu_trw_t is used to gather the members of the train.  When the
 * first member comes in, we allocate a trw, recording the ENA of the ereport,
 * as well as noting its class in trw_mask.  We then reschedule the delivery of
 * the ereport for some configurable time in the future, trusting that all
 * members of the train will have arrived by that time.  Subsequent ereports in
 * the same train match the recorded ENA, and add themselves to the mask.
 * When the first ereport is redelivered, trw_mask is used to determine whether
 * or not a train has been seen.  An exact match is required.  If a match is
 * made, the ereport indicated as the primary cause is used for diagnosis.
 */

#define	CMD_TRW_F_DELETING	0x1	/* reclaiming events */
#define	CMD_TRW_F_CAUSESEEN	0x2	/* cause of train already processed */
#define	CMD_TRW_F_GCSEEN	0x4	/* seen by GC, erased next time */

typedef struct cmd_xxcu_trw {
	uint64_t trw_ena;	/* the ENA for this group of ereports */
	uint64_t trw_afar;	/* the AFAR for this group of ereports */
	cmd_errcl_t trw_mask;	/* ereports seen thus far with this ENA */
	uint16_t trw_cpuid;	/* CPU to which this watcher belongs */
	uint8_t	 trw_ref;	/* number of ereports with this ENA */
	uint8_t	 trw_flags;	/* CMD_TRW_F_* */
	uint32_t trw_pad;
} cmd_xxcu_trw_t;

extern cmd_xxcu_trw_t *cmd_trw_lookup(uint64_t, uint8_t, uint64_t);
extern cmd_xxcu_trw_t *cmd_trw_alloc(uint64_t, uint64_t);
extern void cmd_trw_restore(fmd_hdl_t *);
extern void cmd_trw_write(fmd_hdl_t *);
extern void cmd_trw_ref(fmd_hdl_t *, cmd_xxcu_trw_t *, cmd_errcl_t);
extern void cmd_trw_deref(fmd_hdl_t *, cmd_xxcu_trw_t *);

extern cmd_errcl_t cmd_xxcu_train_match(cmd_errcl_t);

/*
 * We don't have access to ereport nvlists when they are redelivered via timer.
 * As such, we have to retrieve everything we might need for diagnosis when we
 * first receive the ereport.  The retrieved information is stored in the
 * cmd_xr_t, which is persisted.
 */

typedef struct cmd_xr cmd_xr_t;

/*
 * xr_hdlr can't be persisted, so we use these in xr_hdlrid to indicate the
 * handler to be used.  xr_hdlr is then updated so it can be used directly.
 */
#define	CMD_XR_HDLR_XXC		1
#define	CMD_XR_HDLR_XXU		2
#define	CMD_XR_HDLR_NOP		3

typedef void cmd_xr_hdlr_f(fmd_hdl_t *, cmd_xr_t *, fmd_event_t *);

/*
 * For sun4v, the size of xr_synd is expanded to 32 bits in order to
 * accomodate the Niagara L2 syndrome (4x7 bits).
 */

struct cmd_xr {
	cmd_list_t xr_list;
	id_t xr_id;		/* ID of timer used for redelivery */
	cmd_cpu_t *xr_cpu;	/* Detecting CPU, recalc'd from cpuid */
	uint32_t xr_cpuid;	/* ID of detecting CPU */
	uint64_t xr_ena;	/* ENA from ereport */
	uint64_t xr_afar;	/* AFAR from ereport nvlist */
#ifdef sun4u
	uint16_t xr_synd;	/* syndrome from ereport nvlist */
#else /* sun4u */
	uint32_t xr_synd;	/* for Niagara, enlarged to 32 bits */
#endif /* sun4u */
	uint8_t xr_afar_status;	/* AFAR status from ereport nvlist */
	uint8_t xr_synd_status;	/* syndrome status from ereport nvlist */
	cmd_fmri_t xr_rsrc;	/* resource from ereport nvlist */
	cmd_errcl_t xr_clcode;	/* CMD_ERRCL_* for this ereport */
	cmd_xr_hdlr_f *xr_hdlr;	/* handler, recalc'd from hdlrid on restart */
	uint_t xr_hdlrid;	/* CMD_XR_HDLR_*, used for recalc of hdlr */
	fmd_case_t *xr_case;	/* Throwaway case used to track redelivery */
	uint_t xr_ref;		/* Number of references to this struct */
#ifdef sun4u
	uint64_t xr_afsr;	/* AFSR from ereport nvlist */
	uint8_t  xr_num_ways;   /* Number of Cache ways reporting from nvlist */
	uint32_t xr_error_way;  /* The way from the ereport nvlist payload */
	uint64_t xr_error_tag;  /* The tag from the ereport nvlist payload */
	uint32_t xr_error_index; /* the index from the ereport payload */
	uint64_t *xr_cache_data; /* The cache data */
	nvlist_t *xr_detector_nvlist; /* The detecting resource */
#endif
};

#define	xr_rsrc_nvl		xr_rsrc.fmri_nvl

extern cmd_xr_t *cmd_xr_create(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    cmd_cpu_t *, cmd_errcl_t);
extern cmd_evdisp_t cmd_xr_reschedule(fmd_hdl_t *, cmd_xr_t *, uint_t);
extern void cmd_xr_deref(fmd_hdl_t *, cmd_xr_t *);
extern void cmd_xr_write(fmd_hdl_t *, cmd_xr_t *);

extern void cmd_xxc_resolve(fmd_hdl_t *, cmd_xr_t *, fmd_event_t *);
extern void cmd_xxu_resolve(fmd_hdl_t *, cmd_xr_t *, fmd_event_t *);
extern void cmd_nop_resolve(fmd_hdl_t *, cmd_xr_t *, fmd_event_t *);
extern cmd_evdisp_t cmd_xxcu_initial(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t,  uint_t);

/*
 * The master structure containing or referencing all of the state for a given
 * CPU.
 */

/*
 * We periodically flush the E$, thus allowing us to flush the UE cache (see
 * above for a description of the UE cache).  In particular, we flush it
 * whenever we see a UE with a non-valid AFAR.  To keep from overflushing the
 * CPU, we cap the number of flushes that we'll do in response to UEs with
 * non-valid AFARs.  The cap is the number of permitted flushes per GC/restart
 * cycle, and was determined arbitrarily.
 */
#define	CPU_UEC_FLUSH_MAX	3

/*
 * The CPU structure started life without a version number.  Making things more
 * complicated, the version number in the new struct occupies the space used for
 * cpu_cpuid in the non-versioned struct.  We therefore have to use somewhat
 * unorthodox version numbers to distinguish between the two types of struct
 * (pre- and post-versioning) -- version numbers that can't be mistaken for
 * CPUIDs.  Our version numbers, therefore, will be negative.
 *
 * For future expansion, the version member must always stay where it is.  At
 * some point in the future, when more structs get versions, the version member
 * should move into the cmd_header_t.
 */
#define	CPU_MKVERSION(version)	((uint_t)(0 - (version)))

#define	CMD_CPU_VERSION_1	CPU_MKVERSION(1)	/* -1 */
#define	CMD_CPU_VERSION_2	CPU_MKVERSION(2)	/* -2 */
#define	CMD_CPU_VERSION_3	CPU_MKVERSION(3)	/* -3 */
#define	CMD_CPU_VERSION		CMD_CPU_VERSION_3

#define	CMD_CPU_VERSIONED(cpu)	((int)(cpu)->cpu_version < 0)

#define	CMD_CPU_F_DELETING	0x1

typedef struct cmd_cpu_0 {
	cmd_header_t cpu0_header;	/* Nodetype must be CMD_NT_CPU */
	uint32_t cpu0_cpuid;		/* Logical ID for this CPU */
	cmd_cpu_type_t cpu0_type;	/* CPU model */
	fmd_case_t *cpu0_cases[4];	/* v0 had embedded case_t w/4 cases */
	uint8_t cpu0_faulting;		/* Set if fault has been issued */
	cmd_fmri_t cpu0_asru;		/* ASRU for this CPU */
	cmd_fmri_t cpu0_fru;		/* FRU for this CPU */
	cmd_cpu_uec_t cpu0_uec;		/* UE cache */
	cmd_cpu_uec_t cpu0_olduec;	/* To-be-flushed UE cache */
	id_t cpu0_uec_flush;		/* Timer ID for UE cache flush */
	uint_t cpu0_uec_nflushes;	/* # of flushes since last restart/GC */
	cmd_list_t cpu0_xxu_retries;	/* List of pending xxU retries */
} cmd_cpu_0_t;

typedef struct cmd_cpu_1 {
	cmd_header_t cpu1_header;	/* Nodetype must be CMD_NT_CPU */
	uint_t cpu1_version;		/* struct version - must follow hdr */
	uint32_t cpu1_cpuid;		/* Logical ID for this CPU */
	cmd_cpu_type_t cpu1_type;	/* CPU model */
	uintptr_t *cpu1_cases;		/* v1 had a pointer to a case array */
	uint8_t cpu1_faulting;		/* Set if fault has been issued */
	cmd_fmri_t cpu1_asru;		/* ASRU for this CPU */
	cmd_fmri_t cpu1_fru;		/* FRU for this CPU */
	cmd_cpu_uec_t cpu1_uec;		/* UE cache */
	cmd_cpu_uec_t cpu1_olduec;	/* To-be-flushed UE cache */
	id_t cpu1_uec_flush;		/* Timer ID for UE cache flush */
	uint_t cpu1_uec_nflushes;	/* # of flushes since last restart/GC */
	cmd_list_t cpu1_xxu_retries;	/* List of pending xxU retries */
} cmd_cpu_1_t;

typedef struct cmd_cpu_2 {
	cmd_header_t cpu2_header;	/* Nodetype must be CMD_NT_CPU */
	uint_t cpu2_version;		/* struct version - must follow hdr */
	uint32_t cpu2_cpuid;		/* Logical ID for this CPU */
	cmd_cpu_type_t cpu2_type;	/* CPU model */
	uint8_t cpu2_faulting;		/* Set if fault has been issued */
	cmd_fmri_t cpu2_asru;		/* ASRU for this CPU */
	cmd_fmri_t cpu2_fru;		/* FRU for this CPU */
	cmd_cpu_uec_t cpu2_uec;		/* UE cache */
	cmd_cpu_uec_t cpu2_olduec;	/* To-be-flushed UE cache */
} cmd_cpu_2_t;

/* Portion of the cpu structure which must be persisted */
typedef struct cmd_cpu_pers {
	cmd_header_t cpup_header;	/* Nodetype must be CMD_NT_CPU */
	uint_t cpup_version;		/* struct version - must follow hdr */
	uint32_t cpup_cpuid;		/* Logical ID for this CPU */
	cmd_cpu_type_t cpup_type;	/* CPU model */
	uint8_t cpup_faulting;		/* Set if fault has been issued */
	uint8_t cpup_level;		/* cpu group level - 0 == thread */
	cmd_fmri_t cpup_asru;		/* ASRU for this CPU */
	cmd_fmri_t cpup_fru;		/* FRU for this CPU */
	cmd_cpu_uec_t cpup_uec;		/* UE cache */
	cmd_cpu_uec_t cpup_olduec;	/* To-be-flushed UE cache */
} cmd_cpu_pers_t;

/* Persistent and dynamic CPU data */
struct cmd_cpu {
	cmd_cpu_pers_t cpu_pers;
	cmd_cpu_cases_t cpu_cases;
	id_t cpu_uec_flush;		/* Timer ID for UE cache flush */
	uint_t cpu_uec_nflushes;	/* # of flushes since last restart/GC */
	cmd_list_t cpu_xxu_retries;	/* List of pending xxU retries */
	uint_t cpu_flags;
	cmd_list_t cpu_Lxcaches;	/* List of Lxcache state structures */
	fmd_stat_t Lxcache_creat;	/* num of Lxcache states created */
};

#define	CMD_CPU_MAXSIZE \
	MAX(MAX(sizeof (cmd_cpu_0_t), sizeof (cmd_cpu_1_t)), \
	    MAX(sizeof (cmd_cpu_2_t), sizeof (cmd_cpu_pers_t)))
#define	CMD_CPU_MINSIZE \
	MIN(MIN(sizeof (cmd_cpu_0_t), sizeof (cmd_cpu_1_t)), \
	    MIN(sizeof (cmd_cpu_2_t), sizeof (cmd_cpu_pers_t)))

#define	cpu_header		cpu_pers.cpup_header
#define	cpu_nodetype		cpu_pers.cpup_header.hdr_nodetype
#define	cpu_bufname		cpu_pers.cpup_header.hdr_bufname
#define	cpu_version		cpu_pers.cpup_version
#define	cpu_cpuid		cpu_pers.cpup_cpuid
#define	cpu_type		cpu_pers.cpup_type
#define	cpu_faulting		cpu_pers.cpup_faulting
#define	cpu_level		cpu_pers.cpup_level
#define	cpu_asru		cpu_pers.cpup_asru
#define	cpu_fru			cpu_pers.cpup_fru
#define	cpu_uec			cpu_pers.cpup_uec
#define	cpu_olduec		cpu_pers.cpup_olduec
#define	cpu_icache		cpu_cases.cpuc_icache
#define	cpu_dcache		cpu_cases.cpuc_dcache
#define	cpu_pcache		cpu_cases.cpuc_pcache
#define	cpu_itlb		cpu_cases.cpuc_itlb
#define	cpu_dtlb		cpu_cases.cpuc_dtlb
#define	cpu_l2data		cpu_cases.cpuc_l2data
#define	cpu_l2tag		cpu_cases.cpuc_l2tag
#define	cpu_l3data		cpu_cases.cpuc_l3data
#define	cpu_l3tag		cpu_cases.cpuc_l3tag
#define	cpu_fpu			cpu_cases.cpuc_fpu
#define	cpu_ireg 		cpu_cases.cpuc_ireg
#define	cpu_freg		cpu_cases.cpuc_freg
#define	cpu_mau			cpu_cases.cpuc_mau
#define	cpu_l2ctl		cpu_cases.cpuc_l2ctl
#define	cpu_misc_regs		cpu_cases.cpuc_misc_regs
#define	cpu_lfu			cpu_cases.cpuc_lfu
#ifdef sun4u
#define	cpu_opl_invsfsr		cpu_cases.cpuc_opl_invsfsr
#define	cpu_oplue_detcpu	cpu_cases.cpuc_oplue_detcpu
#define	cpu_oplue_detio		cpu_cases.cpuc_oplue_detio
#define	cpu_opl_mtlb		cpu_cases.cpuc_opl_mtlb
#define	cpu_opl_tlbp		cpu_cases.cpuc_opl_tlbp
#define	cpu_opl_inv_urg		cpu_cases.cpuc_opl_inv_urg
#define	cpu_opl_cre		cpu_cases.cpuc_opl_cre
#define	cpu_opl_tsb_ctx		cpu_cases.cpuc_opl_tsb_ctx
#define	cpu_opl_tsbp		cpu_cases.cpuc_opl_tsbp
#define	cpu_opl_pstate		cpu_cases.cpuc_opl_pstate
#define	cpu_opl_tstate		cpu_cases.cpuc_opl_tstate
#define	cpu_opl_iug_f		cpu_cases.cpuc_opl_iug_f
#define	cpu_opl_iug_r		cpu_cases.cpuc_opl_iug_r
#define	cpu_opl_sdc		cpu_cases.cpuc_opl_sdc
#define	cpu_opl_wdt		cpu_cases.cpuc_opl_wdt
#define	cpu_opl_dtlb		cpu_cases.cpuc_opl_dtlb
#define	cpu_opl_itlb		cpu_cases.cpuc_opl_itlb
#define	cpu_opl_core_err	cpu_cases.cpuc_opl_core_err
#define	cpu_opl_dae		cpu_cases.cpuc_opl_dae
#define	cpu_opl_iae		cpu_cases.cpuc_opl_iae
#define	cpu_opl_uge		cpu_cases.cpuc_opl_uge
#endif	/* sun4u */

#define	cpu_asru_nvl		cpu_asru.fmri_nvl
#define	cpu_fru_nvl		cpu_fru.fmri_nvl

/*
 * L2$ and L3$ Data errors
 *
 *          SERD name
 *   Type   (if any)   Fault
 *  ------ ----------- -------------------------------
 *   xxC   l2cachedata fault.cpu.<cputype>.l2cachedata
 *   xxU        -      fault.cpu.<cputype>.l2cachedata
 *  L3_xxC l3cachedata fault.cpu.<cputype>.l3cachedata
 *  L3_xxU      -      fault.cpu.<cputype>.l3cachedata
 *
 * NOTE: For the purposes of the discussion below, xxC and xxU refer to both
 *       L2$ and L3$ data errors.
 *
 * These ereports will be dropped if (among other things) they are side-effects
 * of UEs (xxUs only) or other xxCs or xxUs.  Whenever UEs are detected, they
 * are added to a per-CPU cache.  xxUs are then compared to this cache.  If a
 * xxU's AFAR refers to an address which recently saw a UE, the xxU is dropped,
 * as it was most likely caused by the UE.  When multiple xxCs and xxUs are seen
 * with the same ENA, all save one are generally side-effects.  We track these
 * groups (referred to as trains), matching them against a premade list.  If one
 * of the trains matches, we drop all but the primary, which is indicated in the
 * list.
 *
 * The expected resolution of l2cachedata and l3cachedata faults is the
 * disabling of the indicated CPU.
 */
extern cmd_evdisp_t cmd_xxc(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_xxu(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * As of Niagara-2, we ignore writeback (ldwc, ldwu) errors.  Since these were
 * the only defined follow-on errors for sun4v trains, sun4v L2 cache data
 * errors no longer need to use the train mechanism.
 */

extern cmd_evdisp_t cmd_l2c(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_l2u(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * Common Errdata structure for SERD engines
 */
typedef struct errdata {
	cmd_serd_t *ed_serd;
	const char *ed_fltnm;
	const cmd_ptrsubtype_t ed_pst;
} errdata_t;

/*
 * L2$ and L3$ Tag errors
 *
 *           SERD name
 *   Type    (if any)   Fault
 *  ------- ----------- -------------------------------
 *   TxCE   l2cachetag  fault.cpu.<cputype>.l2cachetag
 *  L3_THCE l3cachetag  fault.cpu.<cputype>.l3cachetag
 *    LTC   l2cachetag	fault.cpu.<cputype>.l2cachetag
 *
 * We'll never see the uncorrectable Tag errors - they'll cause the machine to
 * reset, and we'll be ne'er the wiser.
 *
 * The expected resolution of l2cachetag and l3cachetag faults is the disabling
 * of the indicated CPU.
 */
extern cmd_evdisp_t cmd_txce(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

extern cmd_evdisp_t cmd_l3_thce(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * L1$ errors
 *
 *          SERD name
 *   Type   (if any)   Fault
 *  ------- --------- -------------------------------
 *   IPE     icache   fault.cpu.<cputype>.icache
 *   IxSPE   icache   fault.cpu.<cputype>.icache
 *   DPE     dcache   fault.cpu.<cputype>.dcache
 *   DxSPE   dcache   fault.cpu.<cputype>.dcache
 *   PDSPE   pcache   fault.cpu.<cputype>.pcache
 *
 * The I$, D$, and P$ are clean, and thus have no uncorrectable errors.
 *
 * The expected resolution of icache, dcache, and pcache faults is the disabling
 * of the indicated CPU.
 */
extern cmd_evdisp_t cmd_icache(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_dcache(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_pcache(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * TLB errors
 *
 *         SERD name
 *   Type  (if any)   Fault
 *  ------ --------- -------------------------------
 *  ITLBPE   itlb    fault.cpu.<cputype>.itlb
 *  DTLBPE   dtlb    fault.cpu.<cputype>.dtlb
 *
 * The expected resolution of itlb and dtlb faults is the disabling of the
 * indicated CPU.
 */
extern cmd_evdisp_t cmd_itlb(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_dtlb(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

extern void cmd_cpuerr_close(fmd_hdl_t *, void *);

/*
 * FPU errors
 *
 *         SERD name
 *   Type  (if any)   Fault
 *  ------ --------- -------------------------------
 *   FPU       -     fault.cpu.<cputype>.fpu
 *
 * The expected resolution of FPU faults is the disabling of the indicated CPU.
 */
extern cmd_evdisp_t cmd_fpu(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);


/*
 * ireg errors
 *
 *         SERD name
 *   Type  (if any)   Fault
 *  ------ --------- -------------------------------
 *   IRC     ireg    fault.cpu.<cputype>.ireg
 *   IRU      -				 "
 *
 * The expected resolution of ireg faults is the disabling of the indicated CPU.
 */
extern cmd_evdisp_t cmd_irc(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_iru(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * freg errors
 *
 *         SERD name
 *   Type  (if any)   Fault
 *  ------ --------- -------------------------------
 *   FRC     freg    fault.cpu.ultraSPARC-T1.frc
 *   FRU      -                           " .fru
 *
 * The expected resolution of freg faults is the repair of the indicated CPU.
 */
extern cmd_evdisp_t cmd_frc(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_fru(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * MAU errors
 *
 *         SERD name
 *   Type  (if any)   Fault
 *  ------ --------- -------------------------------
 *   MAU     mau    fault.cpu.<cputype>.mau
 *
 * The expected resolution of mau faults is the repair of the indicated CPU.
 */
extern cmd_evdisp_t cmd_mau(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * L2CTL errors
 *
 *         SERD name
 *   Type  (if any)   Fault
 *  ------ --------- -------------------------------
 *  L2CTL     -     fault.cpu.<cputype>.l2ctl
 *
 * The expected resolution of l2ctl faults is the repair of the indicated CPU.
 */
extern cmd_evdisp_t cmd_l2ctl(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * SBD (Storage Buffer Data) errors
 * SCA (Scratchpath Array) erros
 * TC (Tick compare) errors
 * TSA (Trap stack Array) errors
 *
 *         SERD name
 *   Type  (if any)   Fault
 *  ------ --------- -------------------------------
 *   SBDC     misc_regs    fault.cpu.<cputype>.misc_regs
 *   SBDU
 *   SCAC, SCAU
 *   TCC, TCU
 *   TSAC, TSAU
 *
 * The expected resolution of misc_regs faults is the repair of
 * the indicated CPU.
 */
extern cmd_evdisp_t cmd_miscregs_ce(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_miscregs_ue(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

extern cmd_evdisp_t cmd_miscregs_train(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * Type                                          Fault
 * ---------------------------------------------------------------------
 * LFU-RTF   uncorrectable link retrain fail error    fault.cpu.T2plus.lfu-u
 * LFU-TTO   uncorrectable training timeout error
 * LFU-CTO   uncorrectable config timeout error
 * LFU-MLF   uncorrectable multi lanes link fail error
 * LFU-SLF   correctable single lane failover	      fault.cpu.T2plus.lfu-f
 *
 * The expected resolution of lfu faults is the repair of the indicated CPU.
 */
extern cmd_evdisp_t cmd_lfu_ue(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_evdisp_t cmd_lfu_ce(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
/*
 * Type                                          Fault
 * ---------------------------------------------------------------------
 * Coherency link protocol errors
 * to        Transaction timed out  		fault.cpu.T2plus.lfu-p
 * frack     Invalid or redundant request ack
 * fsr       Invalid or redundant snoop response
 * fdr       Invalid or redundant data return
 * snptyp    Invalid snoop type received from
 *           coherency link
 *
 * The expected resolution of lfu faults is the repair of the indicated CPU.
 */
extern cmd_evdisp_t cmd_lfu_pe(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);

/*
 * CPUs are described by FMRIs.  This routine will retrieve the CPU state
 * structure (creating a new one if necessary) described by the detector
 * FMRI in the passed ereport.
 */
extern cmd_cpu_t *cmd_cpu_lookup_from_detector(fmd_hdl_t *, nvlist_t *,
    const char *, uint8_t);

extern char *cmd_cpu_getfrustr(fmd_hdl_t *, cmd_cpu_t *);
extern char *cmd_cpu_getpartstr(fmd_hdl_t *, cmd_cpu_t *);

extern char *cmd_cpu_getserialstr(fmd_hdl_t *, cmd_cpu_t *);
extern nvlist_t *cmd_cpu_mkfru(fmd_hdl_t *, char *, char *, char *);

extern cmd_cpu_t *cmd_cpu_lookup(fmd_hdl_t *, nvlist_t *, const char *,
    uint8_t);

extern void cmd_cpu_create_faultlist(fmd_hdl_t *, fmd_case_t *, cmd_cpu_t *,
    const char *, nvlist_t *, uint_t);

extern cmd_cpu_t *cmd_restore_cpu_only(fmd_hdl_t *, fmd_case_t *, char *);
extern void cmd_cpu_destroy(fmd_hdl_t *, cmd_cpu_t *);
extern void *cmd_cpu_restore(fmd_hdl_t *, fmd_case_t *, cmd_case_ptr_t *);
extern void cmd_cpu_validate(fmd_hdl_t *);
extern void cmd_cpu_timeout(fmd_hdl_t *, id_t, void *);
extern void cmd_cpu_gc(fmd_hdl_t *);
extern void cmd_cpu_fini(fmd_hdl_t *hdl);
extern char *cmd_cpu_serdnm_create(fmd_hdl_t *, cmd_cpu_t *, const char *);
extern nvlist_t *cmd_cpu_fmri_create(uint32_t, uint8_t);

extern uint32_t cmd_cpu2core(uint32_t, cmd_cpu_type_t, uint8_t);

#define	CMD_CPU_LEVEL_THREAD		0
#define	CMD_CPU_LEVEL_CORE		1
#define	CMD_CPU_LEVEL_CHIP		2
#define	CMD_CPU_STAT_BUMP(cpu, name)    cpu->name.fmds_value.ui64++

typedef enum {
    CMD_CPU_FAM_UNSUPPORTED,
    CMD_CPU_FAM_CHEETAH,
    CMD_CPU_FAM_NIAGARA,
    CMD_CPU_FAM_SPARC64
} cpu_family_t;

typedef struct faminfo {
	cpu_family_t fam_value;
	boolean_t ecache_flush_needed;
} faminfo_t;

extern cpu_family_t cmd_cpu_check_support(void);
extern boolean_t cmd_cpu_ecache_support(void);

extern int cmd_xr_fill(fmd_hdl_t *, nvlist_t *, cmd_xr_t *, cmd_errcl_t);
extern void cmd_fill_errdata(cmd_errcl_t, cmd_cpu_t *, cmd_case_t **,
    const errdata_t **);
extern cmd_xxcu_trw_t *cmd_trw_lookup(uint64_t, uint8_t, uint64_t);
extern cmd_evdisp_t cmd_nop_train(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
    const char *, cmd_errcl_t);
extern cmd_errcl_t cmd_train_match(cmd_errcl_t, cmd_errcl_t);
extern int cmd_afar_status_check(uint8_t, cmd_errcl_t);

#ifdef sun4u
extern int cmd_cpu_synd_check(uint16_t, cmd_errcl_t clcode);
#else /* sun4u */
extern int cmd_cpu_synd_check(uint32_t, cmd_errcl_t clcode);
#endif /* sun4u */

extern int cmd_afar_valid(fmd_hdl_t *hdl, nvlist_t *nvl, cmd_errcl_t,
    uint64_t *afar);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_CPU_H */
