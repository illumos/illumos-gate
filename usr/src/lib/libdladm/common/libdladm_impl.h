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

#ifndef _LIBDLADM_IMPL_H
#define	_LIBDLADM_IMPL_H

#include <libdladm.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAXLINELEN		1024
#define	BUFLEN(lim, ptr)	(((lim) > (ptr)) ? ((lim) - (ptr)) : 0)

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
extern dladm_status_t	i_dladm_get_state(dladm_handle_t, datalink_id_t,
			    link_state_t *);

extern const char	*dladm_pri2str(mac_priority_level_t, char *);
extern dladm_status_t	dladm_str2pri(char *, mac_priority_level_t *);
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
#define	FHWRINGS	"hwrings"	/* boolean_t */

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
				FMADDRPREFIXLEN, FHWRINGS, \
				FMACADDR

/*
 * Data structures used for implementing temporary properties
 */

typedef struct val_desc {
	char		*vd_name;
	uintptr_t	vd_val;
} val_desc_t;

#define	VALCNT(vals)	(sizeof ((vals)) / sizeof (val_desc_t))

extern dladm_status_t	dladm_link_proplist_extract(dladm_handle_t,
			    dladm_arg_list_t *, mac_resource_props_t *);

extern dladm_status_t	dladm_flow_proplist_extract(dladm_arg_list_t *,
			    mac_resource_props_t *);

/*
 * The prop extract() callback.
 *
 * rp_extract extracts the kernel structure from the val_desc_t created
 * by the pd_check function.
 */
typedef	dladm_status_t	rp_extractf_t(val_desc_t *propval, void *arg,
				uint_t cnt);
extern rp_extractf_t	do_extract_maxbw, do_extract_priority,
			do_extract_cpus;

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

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLADM_IMPL_H */
