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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _CHIP_H
#define	_CHIP_H

#include <kstat.h>
#include <libnvpair.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	CHIP_VERSION		TOPO_VERSION

/* Below should match the definitions in x86pi_impl.h */
#define	X86PI_FULL		1
#define	X86PI_NONE		2

/*
 * FM_AWARE_SMBIOS means SMBIOS meets FMA needs
 * X86PI_FULL is defined as 1 in x86pi.so
 * And passed from x86pi.so to chip.so as module
 * private data
 */
#define	FM_AWARE_SMBIOS(mod)	\
	(topo_mod_getspecific(mod) != NULL && \
	    (*(int *)topo_mod_getspecific(mod) == X86PI_FULL))
#define	IGNORE_ID	0xFFFF

/*
 * These definitions are for the Tree Nodes
 * in the FM Topology
 */
#define	CHIP_NODE_NAME		"chip"
#define	CORE_NODE_NAME		"core"
#define	STRAND_NODE_NAME	"strand"
#define	MCT_NODE_NAME		"memory-controller"
#define	CHAN_NODE_NAME		"dram-channel"
#define	CS_NODE_NAME		"chip-select"
#define	DIMM_NODE_NAME		"dimm"
#define	RANK_NODE_NAME		"rank"

#define	PGNAME(prefix)	(prefix##_NODE_NAME "-properties")

/*
 * chip-properties
 */
#define	CHIP_VENDOR_ID		"vendor_id"
#define	CHIP_FAMILY		"family"
#define	CHIP_MODEL		"model"
#define	CHIP_STEPPING		"stepping"
#define	CHIP_NCORE		"ncore_per_chip"

/*
 * memory-controller-properties
 * check usr/src/uts/i86pc/os/cpuid.c to understand more
 * on procnodeid values for AMD & Intel
 */
#define	MCT_PROCNODE_ID		"procnodeid"

/*
 * core-properties
 */
#define	CORE_CHIP_ID		"chip_id"
#define	CORE_PROCNODE_ID	"procnodeid"

/*
 * strand-properties
 */
#define	STRAND_CHIP_ID		"chip_id"
#define	STRAND_PROCNODE_ID	"procnodeid"
#define	STRAND_CORE_ID		"core_id"
#define	STRAND_PKG_CORE_ID	"pkg_core_id"
#define	STRAND_CPU_ID		"cpuid"

/*
 * label property methods
 */
#define	SIMPLE_DIMM_LBL		"simple_dimm_label"
#define	SIMPLE_DIMM_LBL_MP	"simple_dimm_label_mp"
#define	SEQ_DIMM_LBL		"seq_dimm_label"
#define	G4_DIMM_LBL		"g4_dimm_label"
#define	G12F_DIMM_LBL		"g12f_dimm_label"
#define	SIMPLE_CHIP_LBL		"simple_chip_label"
#define	G4_CHIP_LBL		"g4_chip_label"
#define	A4FPLUS_CHIP_LBL	"a4fplus_chip_label"
#define	SIMPLE_CS_LBL_MP	"simple_cs_label_mp"
#define	FSB2_CHIP_LBL		"fsb2_chip_label"

/*
 * DIMM serial number property methods
 */
#define	GET_DIMM_SERIAL		"get_dimm_serial"

extern int simple_dimm_label(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int simple_dimm_label_mp(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int seq_dimm_label(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int g4_dimm_label(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

extern int g12f_dimm_label(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

extern int simple_chip_label(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int g4_chip_label(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int a4fplus_chip_label(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int simple_cs_label_mp(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int get_dimm_serial(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
extern int fsb2_chip_label(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

/*
 * Support functions of chip_subr.c
 */
extern void whinge(topo_mod_t *, int *, const char *, ...);
extern int nvprop_add(topo_mod_t *, nvpair_t *, const char *, tnode_t *);
extern int add_nvlist_strprop(topo_mod_t *, tnode_t *, nvlist_t *,
    const char *, const char *, const char **);
extern int add_nvlist_longprop(topo_mod_t *, tnode_t *, nvlist_t *,
    const char *, const char *, int32_t *);
extern int add_nvlist_longprops(topo_mod_t *, tnode_t *, nvlist_t *,
    const char *, int32_t *, ...);
extern int mkrsrc(topo_mod_t *, tnode_t *, const char *, int,
    nvlist_t *, nvlist_t **);
extern nvlist_t *cpu_fmri_create(topo_mod_t *, uint32_t, char *, uint8_t);
extern boolean_t is_xpv();

/*
 * topo methods
 */
extern int mem_asru_compute(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int rank_fmri_present(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int rank_fmri_replaced(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int retire_strands(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int unretire_strands(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int service_state_strands(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int unusable_strands(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int ntv_page_retire(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int ntv_page_service_state(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int ntv_page_unretire(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int ntv_page_unusable(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
extern int chip_fmri_replaced(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

extern int mem_asru_create(topo_mod_t *, nvlist_t *, nvlist_t **);

/*
 * Prototypes for chip_amd.c
 */
extern void amd_mc_create(topo_mod_t *, uint16_t, tnode_t *, const char *,
    nvlist_t *, int32_t, int32_t, int, int, int *);

/*
 * Prototypes for chip_intel.c
 */
extern int mc_offchip_open(void);
extern int mc_offchip_create(topo_mod_t *, tnode_t *, const char *, nvlist_t *);
extern void onchip_mc_create(topo_mod_t *, uint16_t, tnode_t *,
    const char *, nvlist_t *);

extern char *get_fmtstr(topo_mod_t *, nvlist_t *);
extern int store_prop_val(topo_mod_t *, char *, char *, nvlist_t **out);

/*
 * Prototypes for chip_smbios.c
 */

extern int init_chip_smbios(topo_mod_t *);
extern int chip_status_smbios_get(topo_mod_t *, id_t);
extern int chip_fru_smbios_get(topo_mod_t *, id_t);
extern const char *chip_label_smbios_get(topo_mod_t *, tnode_t *, id_t, char *);
extern const char *chip_serial_smbios_get(topo_mod_t *, id_t);
extern const char *chip_part_smbios_get(topo_mod_t *, id_t);
extern const char *chip_rev_smbios_get(topo_mod_t *, id_t);
extern id_t memnode_to_smbiosid(topo_mod_t *, uint16_t, const char *,
    uint64_t, void *);


#ifdef __cplusplus
}
#endif

#endif /* _CHIP_H */
