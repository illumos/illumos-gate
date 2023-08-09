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

#ifndef _TOPO_DIMM_H
#define	_TOPO_DIMM_H

/*
 * This is an interface to the topo DIMM enumerator. The purpose of this module
 * is to have a common interface to create DIMMs that potentially consumes both
 * platform-specific information (e.g. zen_umc, imc, etc.) and general
 * information (e.g. various SPD revisions, SMBIOS, etc).
 *
 * Currently, the primary supported enumeration entry point is the DIMM entry
 * point. The parent should not create the range. That will be taken care of
 * automatically.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	TOPO_MOD_DIMM	"dimm"
#define	TOPO_MOD_DIMM_VERS	1

/*
 * Information to enumerate a given DIMM. This will expand as we have more
 * integration with other variants (and fold SMBIOS information, this'll expand.
 * This structure should be consider private and not a stable interface.
 */
typedef struct {
	uint32_t td_nspd;
	const uint8_t *td_spd;
} topo_dimm_t;

#ifdef __cplusplus
}
#endif

#endif /* _TOPO_DIMM_H */
