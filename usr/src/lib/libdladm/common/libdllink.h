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

#ifndef _LIBDLLINK_H
#define	_LIBDLLINK_H

/*
 * This file includes structures, macros and routines used by general
 * link administration (i.e. not limited to one specific type of link).
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <libdladm.h>
#include <libdladm_impl.h>
#include <sys/mac_flow.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_attr {
	uint_t			da_max_sdu;
} dladm_attr_t;

typedef struct dladm_phys_attr {
	char		dp_dev[MAXLINKNAMELEN];
	/*
	 * Whether this physical link supports vanity naming (links with media
	 * types not supported by GLDv3 don't have vanity naming support).
	 */
	boolean_t	dp_novanity;
} dladm_phys_attr_t;

typedef enum {
	DLADM_PROP_VAL_CURRENT = 1,
	DLADM_PROP_VAL_DEFAULT,
	DLADM_PROP_VAL_PERM,
	DLADM_PROP_VAL_MODIFIABLE,
	DLADM_PROP_VAL_PERSISTENT
} dladm_prop_type_t;

/*
 * Maximum size of secobj value. Note that it should not be greater than
 * DLD_SECOBJ_VAL_MAX.
 */
#define	DLADM_SECOBJ_VAL_MAX	256

/*
 * Maximum size of secobj name. Note that it should not be greater than
 * DLD_SECOBJ_NAME_MAX.
 */
#define	DLADM_SECOBJ_NAME_MAX	32

#define	DLADM_MAX_PROP_VALCNT	32
/*
 * Size of prop_val buffer passed to pd_get function must be at
 * least DLADM_PROP_VAL_MAX
 */
#define	DLADM_PROP_VAL_MAX	128

#define		DLADM_SECOBJ_CLASS_WEP	0
#define		DLADM_SECOBJ_CLASS_WPA	1
typedef int	dladm_secobj_class_t;

typedef int (dladm_walkcb_t)(const char *, void *);

/* possible flags for ma_flags below */
#define	DLADM_MACADDR_USED	0x1

typedef enum {
	DLADM_HWGRP_TYPE_RX = 0x1,
	DLADM_HWGRP_TYPE_TX
} dladm_hwgrp_type_t;

typedef struct dladm_hwgrp_attr {
	char		hg_link_name[MAXLINKNAMELEN];
	uint_t		hg_grp_num;
	dladm_hwgrp_type_t	hg_grp_type;
	uint_t		hg_n_rings;
	uint_t		hg_n_clnts;
	char		hg_client_names[MAXCLIENTNAMELEN];
} dladm_hwgrp_attr_t;

typedef struct dladm_macaddr_attr {
	uint_t		ma_slot;
	uint_t		ma_flags;
	uchar_t		ma_addr[MAXMACADDRLEN];
	uint_t		ma_addrlen;
	char		ma_client_name[MAXNAMELEN];
	datalink_id_t	ma_client_linkid;
} dladm_macaddr_attr_t;

extern dladm_status_t	dladm_walk(dladm_walkcb_t *, dladm_handle_t, void *,
			    datalink_class_t, datalink_media_t, uint32_t);
extern dladm_status_t	dladm_mac_walk(dladm_walkcb_t *, void *);
extern dladm_status_t	dladm_info(dladm_handle_t, datalink_id_t,
			    dladm_attr_t *);
extern dladm_status_t	dladm_setzid(dladm_handle_t, const char *, char *);

extern dladm_status_t	dladm_rename_link(dladm_handle_t, const char *,
			    const char *);

extern dladm_status_t	dladm_set_linkprop(dladm_handle_t, datalink_id_t,
			    const char *, char **, uint_t, uint_t);
extern dladm_status_t	dladm_get_linkprop(dladm_handle_t, datalink_id_t,
			    dladm_prop_type_t, const char *, char **, uint_t *);
extern dladm_status_t	dladm_walk_linkprop(dladm_handle_t, datalink_id_t,
			    void *, int (*)(dladm_handle_t, datalink_id_t,
			    const char *, void *));
extern boolean_t	dladm_attr_is_linkprop(const char *name);

extern dladm_status_t	dladm_set_secobj(dladm_handle_t, const char *,
			    dladm_secobj_class_t, uint8_t *, uint_t, uint_t);
extern dladm_status_t	dladm_get_secobj(dladm_handle_t, const char *,
			    dladm_secobj_class_t *, uint8_t *, uint_t *,
			    uint_t);
extern dladm_status_t	dladm_unset_secobj(dladm_handle_t, const char *,
			    uint_t);
extern dladm_status_t	dladm_walk_secobj(dladm_handle_t, void *,
			    boolean_t (*)(dladm_handle_t, void *, const char *),
			    uint_t);

extern const char	*dladm_linkstate2str(link_state_t, char *);
extern const char	*dladm_linkduplex2str(link_duplex_t, char *);
extern const char	*dladm_secobjclass2str(dladm_secobj_class_t, char *);
extern dladm_status_t	dladm_str2secobjclass(const char *,
			    dladm_secobj_class_t *);

extern dladm_status_t	dladm_init_linkprop(dladm_handle_t, datalink_id_t,
			    boolean_t);
extern dladm_status_t	dladm_init_secobj(dladm_handle_t);
extern boolean_t	dladm_valid_secobj_name(const char *);

extern dladm_status_t	dladm_create_datalink_id(dladm_handle_t, const char *,
			    datalink_class_t, uint_t, uint32_t,
			    datalink_id_t *);
extern dladm_status_t	dladm_destroy_datalink_id(dladm_handle_t, datalink_id_t,
			    uint32_t);
extern dladm_status_t	dladm_remap_datalink_id(dladm_handle_t, datalink_id_t,
			    const char *);
extern dladm_status_t	dladm_up_datalink_id(dladm_handle_t, datalink_id_t);
extern dladm_status_t	dladm_name2info(dladm_handle_t, const char *,
			    datalink_id_t *, uint32_t *, datalink_class_t *,
			    uint32_t *);
extern dladm_status_t	dladm_datalink_id2info(dladm_handle_t, datalink_id_t,
			    uint32_t *, datalink_class_t *, uint32_t *, char *,
			    size_t);
extern dladm_status_t	dladm_walk_datalink_id(int (*)(dladm_handle_t,
			    datalink_id_t, void *), dladm_handle_t, void *,
			    datalink_class_t, datalink_media_t, uint32_t);
extern dladm_status_t	dladm_create_conf(dladm_handle_t, const char *,
			    datalink_id_t, datalink_class_t, uint32_t,
			    dladm_conf_t *);
extern dladm_status_t	dladm_read_conf(dladm_handle_t, datalink_id_t,
			    dladm_conf_t *);
extern dladm_status_t	dladm_write_conf(dladm_handle_t, dladm_conf_t);
extern dladm_status_t	dladm_remove_conf(dladm_handle_t, datalink_id_t);
extern void		dladm_destroy_conf(dladm_handle_t, dladm_conf_t);
extern dladm_status_t	dladm_get_conf_field(dladm_handle_t, dladm_conf_t,
			    const char *, void *, size_t);
extern dladm_status_t	dladm_getnext_conf_linkprop(dladm_handle_t,
			    dladm_conf_t, const char *, char *, void *,
			    size_t, size_t *);
extern dladm_status_t	dladm_set_conf_field(dladm_handle_t, dladm_conf_t,
			    const char *, dladm_datatype_t, const void *);
extern dladm_status_t	dladm_unset_conf_field(dladm_handle_t, dladm_conf_t,
			    const char *);

extern dladm_status_t	dladm_dev2linkid(dladm_handle_t, const char *,
			    datalink_id_t *);
extern dladm_status_t	dladm_linkid2legacyname(dladm_handle_t, datalink_id_t,
			    char *, size_t);
extern dladm_status_t	dladm_phys_delete(dladm_handle_t, datalink_id_t);

extern dladm_status_t	dladm_phys_info(dladm_handle_t, datalink_id_t,
			    dladm_phys_attr_t *, uint32_t);
extern dladm_status_t	dladm_parselink(const char *, char *, uint_t *);

extern int		dladm_walk_macaddr(dladm_handle_t, datalink_id_t,
			    void *,
			    boolean_t (*)(void *, dladm_macaddr_attr_t *));
extern int		dladm_walk_hwgrp(dladm_handle_t, datalink_id_t, void *,
			    boolean_t (*)(void *, dladm_hwgrp_attr_t *));

extern dladm_status_t	dladm_link_get_proplist(dladm_handle_t, datalink_id_t,
			    dladm_arg_list_t **);

extern dladm_status_t	i_dladm_set_link_proplist_db(char *,
			    dladm_arg_list_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLLINK_H */
