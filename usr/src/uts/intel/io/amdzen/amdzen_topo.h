/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _AMDZEN_TOPO_H
#define	_AMDZEN_TOPO_H

#include "amdzen_client.h"

/*
 * This contains the ioctl definitions for allowing and exploring access to the
 * internal device topology of the Zen CPUs on the system. This ioctl interface
 * is private and subject to change.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	AMDZEN_TOPO_IOCTL	(('z' << 24) | ('z' << 16) | ('t' << 8))

/*
 * Get base information about the system's present sockets and the DF
 * configuration. Our current assumption is that even in a case where we have
 * heterogeneous DF instances (like some of the DFv3.5 devices), then we'll need
 * to revisit this structure and move the DF decomposition into the DF
 * structure.
 */
#define	AMDZEN_TOPO_IOCTL_BASE		(AMDZEN_TOPO_IOCTL | 0x00)
typedef struct amdzen_topo_base {
	uint32_t atb_ndf;
	uint32_t atb_maxdfent;
	df_rev_t atb_rev;
	df_fabric_decomp_t atb_df_decomp;
	amdzen_apic_decomp_t atb_apic_decomp;
} amdzen_topo_base_t;

/*
 * Get information about a basic instance of the data fabric. If we're in a Zen
 * 1 / DFv2 style environment, then this is a part of the underlying die. In a
 * DFv3 (aka Zen 2+) then this represents a relatively coherent set of
 * resources. Though there are some DFv3.5 parts that theoretically have two
 * different types of DFs.
 *
 * We include all of the entities in the DF here as well. Note, that the types
 * and subtypes are currently not normalized across DF generations and device
 * families.
 */
#define	AMDZEN_TOPO_IOCTL_DF		(AMDZEN_TOPO_IOCTL | 0x01)

/*
 * The current maximum number of peers is derived from the width of the bitfield
 * in the data fabric.
 */
#define	AMDZEN_TOPO_DF_MAX_PEERS	8

typedef struct amdzen_topo_ccm_data {
	uint32_t atcd_nccds;
	uint32_t atcd_ccd_en[DF_MAX_CCDS_PER_CCM];
	uint32_t atcd_ccd_ids[DF_MAX_CCDS_PER_CCM];
} amdzen_topo_ccm_data_t;

typedef union amdzen_topo_df_data {
	amdzen_topo_ccm_data_t atded_ccm;
} amdzen_topo_df_data_t;

typedef struct amdzen_topo_df_ent {
	df_type_t atde_type;
	uint8_t	atde_subtype;
	uint8_t	atde_fabric_id;
	uint8_t	atde_inst_id;
	uint8_t	atde_npeers;
	uint8_t	atde_peers[AMDZEN_TOPO_DF_MAX_PEERS];
	amdzen_topo_df_data_t atde_data;
} amdzen_topo_df_ent_t;

typedef struct amdzen_topo_df {
	/*
	 * Users specify the DF number which is in the range from 0 to the
	 * number of DFs specified in the amdzen_topo_base_t. The nodeid and its
	 * corresponding decomposed socket and die IDs will all be filled in.
	 */
	uint32_t atd_dfno;
	uint32_t atd_nodeid;
	uint32_t atd_sockid;
	uint32_t atd_dieid;
	df_rev_t atd_rev;
	uint32_t atd_major;
	uint32_t atd_minor;
	/*
	 * atd_ndf_buf_nents should be set to the size of the number of DF
	 * entries that are present in atd_df_ents. atd_ndf_buf_valid will
	 * determine the number of entries that are considered valid in the
	 * resulting array. atd_ndf_act_nents is the total number of entries
	 * that are present in the underlying DF. Setting atd_ndf_buf_nents to
	 * atb_maxdfent will ensure that we can obtain everything.
	 */
	uint32_t atd_df_buf_nents;
	uint32_t atd_df_buf_nvalid;
	uint32_t atd_df_act_nents;
	amdzen_topo_df_ent_t *atd_df_ents;
} amdzen_topo_df_t;

#ifdef	_KERNEL
typedef struct {
	uint32_t atd_dfno;
	uint32_t atd_nodeid;
	uint32_t atd_sockid;
	uint32_t atd_dieid;
	df_rev_t atd_rev;
	uint32_t atd_major;
	uint32_t atd_minor;
	uint32_t atd_df_buf_nents;
	uint32_t atd_df_buf_nvalid;
	uint32_t atd_df_act_nents;
	caddr32_t atd_df_ents;
} amdzen_topo_df32_t;
#endif	/* _KERNEL */

/*
 * This describes information about what is physically enabled for a given
 * compute based CCM. This is only known for Zen 3+. Input is the DF number and
 * the CCM's fabric ID. Information about the resulting CCXs, cores, and their
 * logical and physical numbers is then returned. All data is sized in terms of
 * uint32_t's to try and keep the data independent of the model (i.e. ILP32 vs.
 * LP64).
 *
 * Note, the maximum numbers defined below are subject to change and ABI
 * compatibility is not guaranteed.
 */
#define	AMDZEN_TOPO_IOCTL_CCD		(AMDZEN_TOPO_IOCTL | 0x02)

#define	AMDZEN_TOPO_CORE_MAX_THREADS	2
#define	AMDZEN_TOPO_CCX_MAX_CORES	16
#define	AMDZEN_TOPO_CCD_MAX_CCX		2

typedef struct amdzen_topo_core {
	uint32_t atcore_log_no;
	uint32_t atcore_phys_no;
	uint32_t atcore_nthreads;
	uint32_t atcore_thr_en[AMDZEN_TOPO_CORE_MAX_THREADS];
	uint32_t atcore_apicids[AMDZEN_TOPO_CORE_MAX_THREADS];
} amdzen_topo_core_t;

typedef struct amdzen_topo_ccx {
	uint32_t atccx_log_no;
	uint32_t atccx_phys_no;
	uint32_t atccx_nlog_cores;
	uint32_t atccx_nphys_cores;
	uint32_t atccx_core_en[AMDZEN_TOPO_CCX_MAX_CORES];
	amdzen_topo_core_t atccx_cores[AMDZEN_TOPO_CCX_MAX_CORES];
} amdzen_topo_ccx_t;

typedef enum amdzen_topo_ccd_err {
	AMDZEN_TOPO_CCD_E_OK		= 0,
	/*
	 * Indicates that the system was unable to determine the APIC
	 * decomposition and therefore we do not have mapping information
	 * available.
	 */
	AMDZEN_TOPO_CCD_E_NO_APIC_DECOMP,
	/*
	 * Indicates that this DF number did not map to something that exists.
	 */
	AMDZEN_TOPO_CCD_E_BAD_DFNO,
	/*
	 * Indicates that the current system is unsupported. Generally this is
	 * only the case for Zen 1 / DFv2.
	 */
	AMDZEN_TOPO_CCD_E_SOC_UNSUPPORTED,
	/*
	 * Indicates that the instance ID in question doesn't map to a DF entity
	 * and is invalid.
	 */
	AMDZEN_TOPO_CCD_E_BAD_INSTID,
	/*
	 * Indicates that the named DF element does not actually point to a CCD.
	 */
	AMDZEN_TOPO_CCD_E_NOT_A_CCD,
	/*
	 * Indicates that the specified CCD ID is not known within the given
	 * instance.
	 */
	AMDZEN_TOPO_CCD_E_BAD_CCDID,
	/*
	 * Indicates that the fabric ID does point to a CCD, but we don't
	 * believe it is actually present in the system. This often happens
	 * when a CCM is enabled but there is no CCD. This is the case in many
	 * DFv3 (Zen 2/3) systems.
	 */
	AMDZEN_TOPO_CCD_E_CCD_MISSING
} amdzen_topo_ccd_err_t;

/*
 * The following flags are set to cover our understanding of the output.
 */
typedef enum amdzen_topo_ccd_flags {
	/*
	 * Indicates that we don't actually know the mapping of physical to
	 * logical cores in the CCX and therefore we have assumed a 1:1
	 * relationship.
	 */
	AMDZEN_TOPO_CCD_F_CORE_PHYS_UNKNOWN	= 1 << 0
} amdzen_topo_ccd_flags_t;

typedef struct amdzen_topo_ccd {
	uint32_t atccd_dfno;
	uint32_t atccd_instid;
	uint32_t atccd_phys_no;
	amdzen_topo_ccd_err_t atccd_err;
	amdzen_topo_ccd_flags_t atccd_flags;
	uint32_t atccd_log_no;
	uint32_t atccd_nlog_ccx;
	uint32_t atccd_nphys_ccx;
	uint32_t atccd_ccx_en[AMDZEN_TOPO_CCD_MAX_CCX];
	amdzen_topo_ccx_t atccd_ccx[AMDZEN_TOPO_CCD_MAX_CCX];
} amdzen_topo_ccd_t;

#ifdef __cplusplus
}
#endif

#endif /* _AMDZEN_TOPO_H */
