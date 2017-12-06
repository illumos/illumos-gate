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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017, Joyent, Inc.
 */

#ifndef _LIBDLADM_IMPL_H
#define	_LIBDLADM_IMPL_H

#include <sys/types.h>
#include <sys/mac.h>
#include <sys/mac_flow.h>
#include <libdladm.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAXLINELEN		1024
#define	BUFLEN(lim, ptr)	(((lim) > (ptr)) ? ((lim) - (ptr)) : 0)
#define	V4_PART_OF_V6(v6)	((v6)._S6_un._S6_u32[3])

/*
 * The handle contains file descriptors to DLD_CONTROL_DEV and
 * DLMGMT_DOOR.  Rather than opening the file descriptor each time
 * it is required, the handle is opened by consumers of libdladm
 * (e.g., dladm) and then passed to libdladm.
 */
struct dladm_handle {
	int dld_fd;	/* file descriptor to DLD_CONTROL_DEV */
	int door_fd;	/* file descriptor to DLMGMT_DOOR */
};

/* DLMGMT_DOOR can only be accessed by libdladm and dlmgmtd */
extern dladm_status_t	dladm_door_fd(dladm_handle_t, int *);

extern dladm_status_t	dladm_errno2status(int);
extern dladm_status_t   i_dladm_rw_db(dladm_handle_t, const char *, mode_t,
			    dladm_status_t (*)(dladm_handle_t, void *, FILE *,
			    FILE *), void *, boolean_t);
extern dladm_status_t	dladm_get_state(dladm_handle_t, datalink_id_t,
			    link_state_t *);
extern void		dladm_find_setbits32(uint32_t, uint32_t *, uint32_t *);
extern dladm_status_t	dladm_parse_args(char *, dladm_arg_list_t **,
			    boolean_t);
extern void		dladm_free_args(dladm_arg_list_t *);

/*
 * Link attributes persisted by dlmgmtd.
 */
/*
 * Set for VLANs only
 */
#define	FVLANID		"vid"		/* uint64_t */
#define	FLINKOVER	"linkover"	/* uint64_t */

/*
 * Set for AGGRs only
 */
#define	FKEY		"key"		/* uint64_t */
#define	FNPORTS		"nports"	/* uint64_t */
#define	FPORTS		"portnames"	/* string */
#define	FPOLICY		"policy"	/* uint64_t */
#define	FFIXMACADDR	"fix_macaddr"	/* boolean_t */
#define	FFORCE		"force"		/* boolean_t */
#define	FLACPMODE	"lacp_mode"	/* uint64_t */
#define	FLACPTIMER	"lacp_timer"	/* uint64_t */

/*
 * Set for VNICs only
 */
#define	FMADDRTYPE	"maddrtype"	/* uint64_t */
#define	FMADDRLEN	"maddrlen"	/* uint64_t */
#define	FMADDRSLOT	"maddrslot"	/* uint64_t */
#define	FMADDRPREFIXLEN	"maddrpreflen"	/* uint64_t */
#define	FVRID		"vrid"		/* uint64_t */
#define	FVRAF		"vraf"		/* uint64_t */

/*
 * Set for simlinks only
 */
#define	FSIMNETTYPE	"simnettype"	/* uint64_t */
#define	FSIMNETPEER	"simnetpeer"	/* uint64_t */

/*
 * Set for IB partitions only
 */
#define	FPORTPKEY	"pkey"		/* uint64_t */

/*
 * Common fields
 */
#define	FMACADDR	"macaddr"	/* string */

/*
 * List of all the above attributes.
 */
#define	DLADM_ATTR_NAMES	FVLANID, FLINKOVER, \
				FKEY, FNPORTS, FPORTS, FPOLICY, \
				FFIXMACADDR, FFORCE, FLACPMODE, FLACPTIMER, \
				FMADDRTYPE, FMADDRLEN, FMADDRSLOT, \
				FMADDRPREFIXLEN, FVRID, FVRAF,	\
				FMACADDR, FSIMNETTYPE, FSIMNETPEER

/*
 * Data structures used for implementing temporary properties
 */

typedef struct val_desc {
	char		*vd_name;
	uintptr_t	vd_val;
} val_desc_t;

#define	VALCNT(vals)	(sizeof ((vals)) / sizeof (val_desc_t))

extern dladm_status_t	dladm_link_proplist_extract(dladm_handle_t,
			    dladm_arg_list_t *, mac_resource_props_t *,
			    uint_t);

extern dladm_status_t	dladm_flow_proplist_extract(dladm_arg_list_t *,
			    mac_resource_props_t *);

/*
 * The prop extract() callback.
 *
 * rp_extract extracts the kernel structure from the val_desc_t created
 * by the pd_check function.
 */
typedef	dladm_status_t	rp_extractf_t(val_desc_t *, uint_t, void *);
extern rp_extractf_t	extract_priority, extract_cpus,
			extract_protection, extract_allowallcids, extract_pool,
			extract_allowedips, extract_allowedcids, extract_maxbw,
			extract_rxrings, extract_txrings;

typedef struct resource_prop_s {
	/*
	 * resource property name
	 */
	char		*rp_name;

	/*
	 * callback to extract kernel structure
	 */
	rp_extractf_t	*rp_extract;
} resource_prop_t;

/*
 * Set for bridged links only
 */
#define	FBRIDGE		"bridge"	/* string */

/*
 * For error lists
 */
extern dladm_status_t	dladm_errlist_append(dladm_errlist_t *,
    const char *, ...);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLADM_IMPL_H */
