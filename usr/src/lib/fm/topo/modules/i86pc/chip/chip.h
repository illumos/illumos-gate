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
 * core-properties
 */
#define	CORE_CHIP_ID		"chip_id"

/*
 * strand-properties
 */
#define	STRAND_CHIP_ID		"chip_id"
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

extern int mem_asru_create(topo_mod_t *, nvlist_t *, nvlist_t **);

/*
 * Prototypes for chip_amd.c
 */
extern void amd_mc_create(topo_mod_t *, tnode_t *, const char *, nvlist_t *,
    int, int, int, int *);

/*
 * Prototypes for chip_intel.c
 */
extern int mc_offchip_open(void);
extern int mc_offchip_create(topo_mod_t *, tnode_t *, const char *, nvlist_t *);
extern void onchip_mc_create(topo_mod_t *, tnode_t *, const char *, nvlist_t *);

extern char *get_fmtstr(topo_mod_t *, nvlist_t *);
extern int store_prop_val(topo_mod_t *, char *, char *, nvlist_t **out);

#ifdef __cplusplus
}
#endif

#endif /* _CHIP_H */
