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

#ifndef _LIBDLFLOW_IMPL_H
#define	_LIBDLFLOW_IMPL_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mac.h>
#include <libdladm.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct fprop_desc;
struct fattr_desc;

typedef	dladm_status_t	fpd_getf_t(dladm_handle_t, const char *, char **,
			    uint_t *);
typedef	dladm_status_t	fpd_setf_t(dladm_handle_t, const char *, val_desc_t *,
			    uint_t);
typedef	dladm_status_t	fpd_checkf_t(struct fprop_desc *, char **, uint_t,
			    val_desc_t **);

typedef struct fprop_desc {
	char		*pd_name;
	val_desc_t	pd_defval;
	val_desc_t	*pd_modval;
	uint_t		pd_nmodval;
	boolean_t	pd_temponly;
	fpd_setf_t	*pd_set;
	fpd_getf_t	*pd_getmod;
	fpd_getf_t	*pd_get;
	fpd_checkf_t	*pd_check;
} fprop_desc_t;

typedef struct prop_table {
	fprop_desc_t	*pt_table;
	uint_t		pt_size;
} prop_table_t;

typedef enum {
	DLADM_PROP_VAL_CURRENT = 1,
	DLADM_PROP_VAL_DEFAULT,
	DLADM_PROP_VAL_MODIFIABLE,
	DLADM_PROP_VAL_PERSISTENT
} prop_type_t;

typedef	dladm_status_t	fad_checkf_t(char *, flow_desc_t *);

extern dladm_status_t	do_check_ip_addr(char *, boolean_t, flow_desc_t *);
extern dladm_status_t	do_check_dsfield(char *, flow_desc_t *);

typedef struct fattr_desc {
	const char	*ad_name;
	fad_checkf_t	*ad_check;
} fattr_desc_t;

extern dladm_status_t	i_dladm_get_prop_temp(dladm_handle_t, const char *,
			    prop_type_t, const char *, char **, uint_t *,
			    prop_table_t *);
extern dladm_status_t	i_dladm_set_prop_temp(dladm_handle_t, const char *,
			    const char *, char **, uint_t, uint_t, char **,
			    prop_table_t *);
extern boolean_t	i_dladm_is_prop_temponly(const char *prop_name,
			    char **, prop_table_t *);
/*
 * Data structures used for implementing persistent properties
 */
typedef struct prop_val {
	const char		*lv_name;
	struct prop_val		*lv_nextval;
} prop_val_t;

typedef struct prop_db_info {
	const char		*li_name;
	struct prop_db_info	*li_nextprop;
	struct prop_val		*li_val;
} prop_db_info_t;

typedef struct prop_db_state	prop_db_state_t;

typedef boolean_t (*prop_db_op_t)(dladm_handle_t, prop_db_state_t *,
    char *, prop_db_info_t *, dladm_status_t *);

typedef dladm_status_t (*prop_db_initop_t)(dladm_handle_t, const char *,
    const char *, char **, uint_t, uint_t, char **);

struct prop_db_state {
	prop_db_op_t		ls_op;
	const char		*ls_name;
	const char		*ls_propname;
	char			**ls_propval;
	uint_t			*ls_valcntp;
	prop_db_initop_t	ls_initop;
};

extern boolean_t	process_prop_set(dladm_handle_t, prop_db_state_t *lsp,
			    char *buf, prop_db_info_t *listp,
			    dladm_status_t *statusp);
extern boolean_t	process_prop_get(dladm_handle_t, prop_db_state_t *lsp,
			    char *buf, prop_db_info_t *listp,
			    dladm_status_t *statusp);
extern boolean_t	process_prop_init(dladm_handle_t, prop_db_state_t *lsp,
			    char *buf, prop_db_info_t *listp,
			    dladm_status_t *statusp);
extern dladm_status_t	process_prop_db(dladm_handle_t, void *arg, FILE *fp,
			    FILE *nfp);

extern dladm_status_t	i_dladm_init_flowprop_db(dladm_handle_t);
extern dladm_status_t	i_dladm_set_flow_proplist_db(dladm_handle_t, char *,
			    dladm_arg_list_t *);
extern dladm_status_t	i_dladm_flow_check_restriction(datalink_id_t,
			    flow_desc_t *, mac_resource_props_t *, boolean_t);

extern dladm_status_t	dladm_flow_attrlist_extract(dladm_arg_list_t *,
			    flow_desc_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLFLOW_IMPL_H */
