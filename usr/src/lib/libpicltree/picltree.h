/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PICLTREE_H
#define	_PICLTREE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PTree Interface
 */

#include <door.h>

/*
 * Plug-in directories
 */
#define	PICLD_COMMON_PLUGIN_DIR	"/usr/lib/picl/plugins"
#define	PICLD_PLAT_PLUGIN_DIRF	"/usr/platform/%s/lib/picl/plugins/"

typedef struct {
	picl_nodehdl_t	nodeh;
	picl_prophdl_t	proph;
	door_cred_t	cred;
} ptree_rarg_t;

typedef struct {
	picl_nodehdl_t	nodeh;
	picl_prophdl_t	proph;
	door_cred_t	cred;
} ptree_warg_t;
/*
 * Volatile type properties must specify their maximum size in 'size'
 * of propinfo_t at the time of creation. That guarantees clients
 * accessing those properties an upper limit on value size.
 * The two property types that have to specify a maximum are:
 *  PICL_PTYPE_BYTEARRAY, and PICL_PTYPE_CHARSTRING
 */
#define	PTREE_PROPINFO_VERSION_1	1
#define	PTREE_PROPINFO_VERSION	PTREE_PROPINFO_VERSION_1

typedef struct {
	int			version;
	picl_propinfo_t		piclinfo;	/* client info */
	int			(*read)(ptree_rarg_t *arg, void *buf);
	int			(*write)(ptree_warg_t *arg, const void *buf);
} ptree_propinfo_t;

/*
 * --------------------------------------------------
 * Function prototypes of PTree Interface primitives
 * --------------------------------------------------
 */
/*
 * create/destroy/add/delete a node/property instance
 */
extern	int	ptree_get_root(picl_nodehdl_t *nodeh);
extern	int	ptree_create_node(const char *name, const char *clname,
			picl_nodehdl_t *nodeh);
extern	int	ptree_destroy_node(picl_nodehdl_t nodeh);
extern	int	ptree_add_node(picl_nodehdl_t parh, picl_nodehdl_t chdh);
extern	int	ptree_delete_node(picl_nodehdl_t nodeh);

extern	int	ptree_create_prop(const ptree_propinfo_t *pi, const void *vbuf,
			picl_prophdl_t *proph);
extern	int	ptree_destroy_prop(picl_prophdl_t proph);
extern	int 	ptree_delete_prop(picl_prophdl_t proph);
extern	int	ptree_add_prop(picl_nodehdl_t nodeh, picl_prophdl_t proph);
extern	int	ptree_create_table(picl_prophdl_t *tbl_hdl);
extern	int	ptree_add_row_to_table(picl_prophdl_t tbl, int nprops,
			const picl_prophdl_t *props);
extern	int	ptree_update_propval_by_name(picl_nodehdl_t nodeh,
		const char *name, const void *vbuf, size_t sz);
extern	int	ptree_update_propval(picl_prophdl_t proph, const void *buf,
			size_t sz);
extern	int 	ptree_get_propval(picl_prophdl_t proph, void *buf,
			size_t sz);
extern	int 	ptree_get_propval_by_name(picl_nodehdl_t nodeh,
			const char *name, void *buf, size_t sz);
extern	int	ptree_get_propinfo(picl_prophdl_t proph, ptree_propinfo_t *pi);
extern	int	ptree_get_first_prop(picl_nodehdl_t nodeh,
			picl_prophdl_t *proph);
extern	int	ptree_get_next_prop(picl_prophdl_t thish,
			picl_prophdl_t *proph);
extern	int	ptree_get_prop_by_name(picl_nodehdl_t nodeh, const char *name,
			picl_prophdl_t *proph);
extern	int 	ptree_get_next_by_row(picl_prophdl_t proph,
			picl_prophdl_t *rowh);
extern	int	ptree_get_next_by_col(picl_prophdl_t proph,
			picl_prophdl_t *colh);
extern	int	ptree_init_propinfo(ptree_propinfo_t *infop, int version,
			int ptype, int pmode, size_t psize, char *pname,
			int (*readfn)(ptree_rarg_t *, void *),
			int (*writefn)(ptree_warg_t *, const void *));
extern	int	ptree_create_and_add_prop(picl_nodehdl_t nodeh,
			ptree_propinfo_t *infop, void *vbuf,
			picl_prophdl_t *proph);
extern	int	ptree_create_and_add_node(picl_nodehdl_t rooth,
			const char *name, const char *classname,
			picl_nodehdl_t *nodeh);
extern	int	ptree_get_node_by_path(const char *piclurl,
			picl_nodehdl_t *handle);
extern	int	ptree_walk_tree_by_class(picl_nodehdl_t rooth,
			const char *classname, void *c_args,
			int (*callback_fn)(picl_nodehdl_t hdl, void *args));
extern	int	ptree_find_node(picl_nodehdl_t rooth, char *pname,
			picl_prop_type_t ptype, void *pval, size_t valsize,
			picl_nodehdl_t *retnodeh);
extern	int	ptree_post_event(const char *ename, const void *earg,
			size_t size, void (*completion_handler)(char *ename,
			void *earg, size_t size));
extern	int	ptree_register_handler(const char *ename,
			void (*evt_handler)(const char *ename, const void *earg,
			size_t size, void *cookie), void *cookie);
extern	void	ptree_unregister_handler(const char *ename,
			void (*evt_handler)(const char *ename, const void *earg,
			size_t size, void *cookie), void *cookie);
extern	int	ptree_get_frutree_parent(picl_nodehdl_t nodeh,
			picl_nodehdl_t *retnodeh);

/*
 * PICL plug-in revision
 */
#define	PICLD_PLUGIN_VERSION_1	1
#define	PICLD_PLUGIN_VERSION_2	2

#define	PICLD_PLUGIN_VERSION	PICLD_PLUGIN_VERSION_1

#define	PICLD_PLUGIN_NON_CRITICAL	0
#define	PICLD_PLUGIN_CRITICAL		1

/*
 * PICL plug-in registration interface
 */
typedef struct {
	int	version;
	int	critical;
	char	*name;
	void	(*plugin_init)(void);
	void	(*plugin_fini)(void);
} picld_plugin_reg_t;

extern	int	picld_plugin_register(picld_plugin_reg_t *regp);

#ifdef	__cplusplus
}
#endif

#endif	/* _PICLTREE_H */
