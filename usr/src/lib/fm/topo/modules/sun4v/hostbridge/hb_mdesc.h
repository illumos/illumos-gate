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

#ifndef	_HB_MDESC_H
#define	_HB_MDESC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/topo_mod.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Node/Field names in the PRI/MD
 */
#define	MD_STR_ID		"id"
#define	MD_STR_IODEVICE		"iodevice"
#define	MD_STR_DEVICE_TYPE	"device-type"
#define	MD_STR_PCIEX		"pciex"
#define	MD_STR_CFGHDL		"cfg-handle"

/* A root complex */
typedef struct md_rc {
	int16_t id;			/* physical id of the rc */
	uint64_t cfg_handle;		/* bus address */
} md_rc_t;

/* A hostbridge */
typedef struct md_hb {
	int16_t id;			/* physiscal id of the hostbridge */
	md_rc_t *rcs;			/* a list of pciex root complexes */
	int16_t srcs;			/* size of the rcs */
	int16_t nrcs;			/* count of rc entries in rcs */
} md_hb_t;

typedef struct md_info {
	md_hb_t *hbs;			/* a list of hostbridges */
	int16_t shbs;			/* size of the hbs */
	int16_t nhbs;			/* count of hb entries in hbs */
} md_info_t;


extern int hb_mdesc_init(topo_mod_t *mod, md_info_t *hbmdp);
extern void hb_mdesc_fini(topo_mod_t *mod, md_info_t *hbmdp);

extern md_hb_t *hb_find_hb(md_info_t *hbmd, int hbid);

#ifdef __cplusplus
}
#endif

#endif	/* _HB_MDESC_H */
