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

#include <sys/types.h>
#include <sys/param.h>
#include <libdladm.h>
#include <kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_attr {
	uint_t		da_max_sdu;
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

extern dladm_status_t	dladm_walk(dladm_walkcb_t *, void *, datalink_class_t,
			    datalink_media_t, uint32_t);
extern dladm_status_t	dladm_mac_walk(dladm_walkcb_t *, void *);
extern dladm_status_t	dladm_info(datalink_id_t, dladm_attr_t *);
extern dladm_status_t	dladm_setzid(const char *, char *);

extern dladm_status_t	dladm_rename_link(const char *, const char *);

extern dladm_status_t	dladm_set_linkprop(datalink_id_t, const char *,
			    char **, uint_t, uint_t);
extern dladm_status_t	dladm_get_linkprop(datalink_id_t, dladm_prop_type_t,
			    const char *, char **, uint_t *);
extern dladm_status_t	dladm_walk_linkprop(datalink_id_t, void *,
			    int (*)(datalink_id_t, const char *, void *));

extern dladm_status_t	dladm_set_secobj(const char *, dladm_secobj_class_t,
			    uint8_t *, uint_t, uint_t);
extern dladm_status_t	dladm_get_secobj(const char *, dladm_secobj_class_t *,
			    uint8_t *, uint_t *, uint_t);
extern dladm_status_t	dladm_unset_secobj(const char *, uint_t);
extern dladm_status_t	dladm_walk_secobj(void *,
			    boolean_t (*)(void *, const char *), uint_t);

extern const char	*dladm_linkstate2str(link_state_t, char *);
extern const char	*dladm_linkduplex2str(link_duplex_t, char *);
extern const char	*dladm_secobjclass2str(dladm_secobj_class_t, char *);
extern dladm_status_t	dladm_str2secobjclass(const char *,
			    dladm_secobj_class_t *);

extern dladm_status_t	dladm_init_linkprop(datalink_id_t, boolean_t);
extern dladm_status_t	dladm_init_secobj(void);

extern dladm_status_t	dladm_create_datalink_id(const char *, datalink_class_t,
			    uint_t, uint32_t, datalink_id_t *);
extern dladm_status_t	dladm_destroy_datalink_id(datalink_id_t, uint32_t);
extern dladm_status_t	dladm_remap_datalink_id(datalink_id_t, const char *);
extern dladm_status_t	dladm_up_datalink_id(datalink_id_t);
extern dladm_status_t	dladm_name2info(const char *, datalink_id_t *,
			    uint32_t *, datalink_class_t *, uint32_t *);
extern dladm_status_t	dladm_datalink_id2info(datalink_id_t, uint32_t *,
			    datalink_class_t *, uint32_t *, char *, size_t);
extern dladm_status_t	dladm_walk_datalink_id(int (*)(datalink_id_t, void *),
			    void *, datalink_class_t, datalink_media_t,
			    uint32_t);
extern dladm_status_t	dladm_create_conf(const char *, datalink_id_t,
			    datalink_class_t, uint32_t, dladm_conf_t *);
extern dladm_status_t	dladm_read_conf(datalink_id_t, dladm_conf_t *);
extern dladm_status_t	dladm_write_conf(dladm_conf_t);
extern dladm_status_t	dladm_remove_conf(datalink_id_t);
extern void		dladm_destroy_conf(dladm_conf_t);
extern dladm_status_t	dladm_get_conf_field(dladm_conf_t, const char *,
			    void *, size_t);
extern dladm_status_t	dladm_set_conf_field(dladm_conf_t, const char *,
			    dladm_datatype_t, const void *);
extern dladm_status_t	dladm_unset_conf_field(dladm_conf_t, const char *);

extern dladm_status_t	dladm_dev2linkid(const char *, datalink_id_t *);
extern dladm_status_t	dladm_linkid2legacyname(datalink_id_t, char *, size_t);
extern dladm_status_t	dladm_phys_delete(datalink_id_t);

extern dladm_status_t	dladm_phys_info(datalink_id_t, dladm_phys_attr_t *,
			    uint32_t);
extern dladm_status_t	dladm_get_single_mac_stat(datalink_id_t, const char *,
    uint8_t, void *);
extern int		dladm_kstat_value(kstat_t *, const char *, uint8_t,
    void *);
extern dladm_status_t	dladm_parselink(const char *, char *, uint_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLLINK_H */
