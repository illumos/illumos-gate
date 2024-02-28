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

#ifndef _AMDZEN_H
#define	_AMDZEN_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/list.h>
#include <sys/pci.h>
#include <sys/taskq.h>
#include <sys/bitmap.h>
#include <sys/x86_archext.h>
#include <sys/amdzen/df.h>

#include "amdzen_client.h"

/*
 * This header describes properties of the data fabric and our internal state
 * for the Zen Nexus driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The data fabric devices are always defined to be on PCI bus zero starting at
 * device 0x18.
 */
#define	AMDZEN_DF_BUSNO		0x00
#define	AMDZEN_DF_FIRST_DEVICE	0x18

/*
 * The maximum amount of Data Fabric node's we can see. In Zen 1 there were up
 * to four per package.
 */
#define	AMDZEN_MAX_DFS		0x8

/*
 * The maximum number of PCI functions we expect to encounter on the data
 * fabric.
 */
#define	AMDZEN_MAX_DF_FUNCS	0x8

/*
 * Northbridge registers that are relevant for the nexus, mostly for SMN.
 */
#define	AMDZEN_NB_SMN_ADDR	0x60
#define	AMDZEN_NB_SMN_DATA	0x64

/*
 * AMD PCI ID for reference
 */
#define	AMDZEN_PCI_VID_AMD	0x1022

/*
 * Hygon PCI ID for reference
 */
#define	AMDZEN_PCI_VID_HYGON	0x1d94

typedef enum {
	AMDZEN_STUB_TYPE_DF,
	AMDZEN_STUB_TYPE_NB
} amdzen_stub_type_t;

typedef struct {
	list_node_t		azns_link;
	dev_info_t		*azns_dip;
	uint16_t		azns_vid;
	uint16_t		azns_did;
	uint16_t		azns_bus;
	uint16_t		azns_dev;
	uint16_t		azns_func;
	ddi_acc_handle_t	azns_cfgspace;
} amdzen_stub_t;

typedef enum {
	AMDZEN_DFE_F_MCA	= 1 << 0,
	AMDZEN_DFE_F_ENABLED	= 1 << 1,
	AMDZEN_DFE_F_DATA_VALID	= 1 << 2
} amdzen_df_ent_flags_t;

/*
 * Data specific to a CCM.
 */
typedef struct {
	uint32_t acd_nccds;
	uint8_t acd_ccd_en[DF_MAX_CCDS_PER_CCM];
	uint32_t acd_ccd_id[DF_MAX_CCDS_PER_CCM];
	void *acd_ccd_data[DF_MAX_CCDS_PER_CCM];
} amdzen_ccm_data_t;

typedef union {
	amdzen_ccm_data_t aded_ccm;
} amdzen_df_ent_data_t;

typedef struct {
	uint8_t adfe_drvid;
	amdzen_df_ent_flags_t adfe_flags;
	df_type_t adfe_type;
	uint8_t adfe_subtype;
	uint8_t adfe_fabric_id;
	uint8_t adfe_inst_id;
	uint32_t adfe_info0;
	uint32_t adfe_info1;
	uint32_t adfe_info2;
	uint32_t adfe_info3;
	amdzen_df_ent_data_t adfe_data;
} amdzen_df_ent_t;

typedef enum {
	AMDZEN_DF_F_VALID		= 1 << 0,
	AMDZEN_DF_F_FOUND_NB		= 1 << 1,
} amdzen_df_flags_t;

typedef struct {
	amdzen_df_flags_t	adf_flags;
	uint_t		adf_nb_busno;
	amdzen_stub_t	*adf_funcs[AMDZEN_MAX_DF_FUNCS];
	amdzen_stub_t	*adf_nb;
	uint8_t		adf_major;
	uint8_t		adf_minor;
	uint_t		adf_nents;
	df_rev_t	adf_rev;
	amdzen_df_ent_t	*adf_ents;
	uint32_t	adf_nodeid;
	uint32_t	adf_syscfg;
	uint32_t	adf_mask0;
	uint32_t	adf_mask1;
	uint32_t	adf_mask2;
	uint32_t	adf_nccm;
	df_fabric_decomp_t	adf_decomp;
} amdzen_df_t;

typedef enum {
	AMDZEN_F_UNSUPPORTED		= 1 << 0,
	AMDZEN_F_DEVICE_ERROR		= 1 << 1,
	AMDZEN_F_MAP_ERROR		= 1 << 2,
	AMDZEN_F_SCAN_DISPATCHED	= 1 << 3,
	AMDZEN_F_SCAN_COMPLETE		= 1 << 4,
	AMDZEN_F_ATTACH_DISPATCHED	= 1 << 5,
	AMDZEN_F_ATTACH_COMPLETE	= 1 << 6,
	AMDZEN_F_APIC_DECOMP_VALID	= 1 << 7
} amdzen_flags_t;

#define	AMDZEN_F_TASKQ_MASK	(AMDZEN_F_SCAN_DISPATCHED | \
    AMDZEN_F_SCAN_COMPLETE | AMDZEN_F_ATTACH_DISPATCHED | \
    AMDZEN_F_ATTACH_COMPLETE)

/*
 * These are the set of flags we want to consider when determining whether or
 * not we're OK for receiving topo ioctls.
 */
#define	AMDZEN_F_IOCTL_MASK	(AMDZEN_F_UNSUPPORTED | \
    AMDZEN_F_DEVICE_ERROR | AMDZEN_F_MAP_ERROR | AMDZEN_F_ATTACH_COMPLETE)

typedef struct amdzen {
	kmutex_t	azn_mutex;
	kcondvar_t	azn_cv;
	amdzen_flags_t	azn_flags;
	dev_info_t	*azn_dip;
	taskqid_t	azn_taskqid;
	uint_t		azn_nscanned;
	uint_t		azn_npresent;
	list_t		azn_df_stubs;
	list_t		azn_nb_stubs;
	uint_t		azn_ndfs;
	amdzen_df_t	azn_dfs[AMDZEN_MAX_DFS];
	x86_uarchrev_t	azn_uarchrev;
	x86_chiprev_t	azn_chiprev;
	uint32_t	azn_ncore_per_ccx;
	amdzen_apic_decomp_t azn_apic_decomp;
} amdzen_t;

typedef enum {
	AMDZEN_C_SMNTEMP = 1,
	AMDZEN_C_USMN,
	AMDZEN_C_ZEN_UDF,
	AMDZEN_C_ZEN_UMC
} amdzen_child_t;

/*
 * Functions for stubs.
 */
extern int amdzen_attach_stub(dev_info_t *, ddi_attach_cmd_t);
extern int amdzen_detach_stub(dev_info_t *, ddi_detach_cmd_t);

#ifdef __cplusplus
}
#endif

#endif /* _AMDZEN_H */
