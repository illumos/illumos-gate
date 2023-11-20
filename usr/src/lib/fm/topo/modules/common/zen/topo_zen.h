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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _TOPO_ZEN_H
#define	_TOPO_ZEN_H

/*
 * The ufm module provides the ability for callers to enumerate various portions
 * of information related to the AMD Zen family of systems. The following node
 * types are supported and require the following argument:
 *
 * CHIP - topo_zen_chip_t	Enumerates a full CPU socket identified
 *				tzc_sockid. It assumes the caller has already
 *				created the corresponding node range. The
 *				various CCDs, I/O dies, and more will all be
 *				populated under this.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	TOPO_MOD_ZEN	"zen"
#define	TOPO_MOD_ZEN_VERS	1

typedef struct {
	uint32_t tzc_sockid;
} topo_zen_chip_t;

/*
 * Property groups and their corresponding properties. The properties listed
 * here are currently specific to nodes that exist in the AMD tree.
 */
#define	TOPO_PGROUP_DF	"data-fabric"
#define	TOPO_PGROUP_DF_NODEID	"node-id"
#define	TOPO_PGROUP_DF_SOCKID	"socket-id"
#define	TOPO_PGROUP_DF_DIEID	"die-id"
#define	TOPO_PGROUP_DF_REV	"revision"
#define	TOPO_PGROUP_DF_INSTID	"instance-id"
#define	TOPO_PGROUP_DF_FABID	"fabric-id"
#define	TOPO_PGROUP_DF_TYPE	"type-id"
#define	TOPO_PGROUP_DF_SUBTYPE	"subtype-id"
#define	TOPO_PGROUP_DF_PEERS	"peers"

#define	TOPO_PGROUP_CCD	"ccd-properties"
#define	TOPO_PGROUP_CCD_LOGID	"logical-ccd"
#define	TOPO_PGROUP_CCD_PHYSID	"physical-ccd"

#define	TOPO_PGROUP_CCX	"ccx-properties"
#define	TOPO_PGROUP_CCX_LOGID	"logical-ccx"
#define	TOPO_PGROUP_CCX_PHYSID	"physical-ccx"

#define	TOPO_PGROUP_CORE	"core-properties"
#define	TOPO_PGROUP_CORE_LOGID	"logical-core"
#define	TOPO_PGROUP_CORE_PHYSID	"physical-core"

/*
 * The strand property group is also used by the i86pc chip module. We define a
 * different property (so we can change this type to an unsigned value). As part
 * of working through SERD cases we should unify these.
 */
#define	TOPO_PGROUP_STRAND	"strand-properties"
#define	TOPO_PGROUP_STRAND_CPUID	"cpu-id"
#define	TOPO_PGROUP_STRAND_APICID	"apic-id"

/*
 * These chip properties are loosely shared with the i86pc chip module. They're
 * not in <fm/topo_hc.h> as these are really x86-specific items and not generic.
 */
#define	TOPO_PGROUP_CHIP	"chip-properties"
#define	TOPO_PGROUP_CHIP_BRAND		"brand"
#define	TOPO_PGROUP_CHIP_FAMILY		"family"
#define	TOPO_PGROUP_CHIP_MODEL		"model"
#define	TOPO_PGROUP_CHIP_STEPPING	"stepping"
#define	TOPO_PGROUP_CHIP_SOCKET		"socket"
#define	TOPO_PGROUP_CHIP_REVISION	"revision"

#ifdef __cplusplus
}
#endif

#endif /* _TOPO_ZEN_H */
