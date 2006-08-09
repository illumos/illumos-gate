#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libpicltree/spec/picltree.spec

function	ptree_get_root
include		<picl.h> <picltree.h>
declaration	int ptree_get_root(picl_nodehdl_t *nodeh)
version		SUNW_1.1
end		

function	ptree_create_node
include		<picl.h> <picltree.h>
declaration	int ptree_create_node(const char *name, const char *clname, picl_nodehdl_t *nodeh)
version		SUNW_1.1
end		

function	ptree_destroy_node
include		<picl.h> <picltree.h>
declaration	int ptree_destroy_node(picl_nodehdl_t nodeh)
version		SUNW_1.1
end		

function	ptree_add_node
include		<picl.h> <picltree.h>
declaration	int ptree_add_node(picl_nodehdl_t parh, picl_nodehdl_t chdh)
version		SUNW_1.1
end		

function	ptree_delete_node
include		<picl.h> <picltree.h>
declaration	int ptree_delete_node(picl_nodehdl_t nodeh)
version		SUNW_1.1
end		

function	ptree_create_prop
include		<picl.h> <picltree.h>
declaration	int ptree_create_prop(const ptree_propinfo_t *pi, const void *vbuf, picl_prophdl_t *proph)
version		SUNW_1.1
end		

function	ptree_destroy_prop
include		<picl.h> <picltree.h>
declaration	int ptree_destroy_prop(picl_prophdl_t proph)
version		SUNW_1.1
end		

function	ptree_delete_prop
include		<picl.h> <picltree.h>
declaration	int ptree_delete_prop(picl_prophdl_t proph)
version		SUNW_1.1
end		

function	ptree_add_prop
include		<picl.h> <picltree.h>
declaration	int ptree_add_prop(picl_nodehdl_t nodeh, picl_prophdl_t proph)
version		SUNW_1.1
end		

function	ptree_create_table
include		<picl.h> <picltree.h>
declaration	int ptree_create_table(picl_prophdl_t *tbl_hdl)
version		SUNW_1.1
end		

function	ptree_add_row_to_table
include		<picl.h> <picltree.h>
declaration	int ptree_add_row_to_table(picl_prophdl_t tbl, int nprops, const picl_prophdl_t *props)
version		SUNW_1.1
end		

function	ptree_update_propval_by_name
include		<picl.h> <picltree.h>
declaration	int ptree_update_propval_by_name(picl_nodehdl_t nodeh, const char *name, const void *vbuf, size_t sz)
version		SUNW_1.1
end		

function	ptree_update_propval
include		<picl.h> <picltree.h>
declaration	int ptree_update_propval(picl_prophdl_t proph, const void *buf, size_t sz)
version		SUNW_1.1
end		

function	ptree_get_propval
include		<picl.h> <picltree.h>
declaration	int ptree_get_propval(picl_prophdl_t proph, void *buf, size_t sz)
version		SUNW_1.1
end		

function	ptree_get_propval_by_name
include		<picl.h> <picltree.h>
declaration	int ptree_get_propval_by_name(picl_nodehdl_t nodeh, const char *name, void *buf, size_t sz)
version		SUNW_1.1
end		

function	ptree_get_propinfo
include		<picl.h> <picltree.h>
declaration	int ptree_get_propinfo(picl_prophdl_t proph, ptree_propinfo_t *pi)
version		SUNW_1.1
end		

function	ptree_get_first_prop
include		<picl.h> <picltree.h>
declaration	int ptree_get_first_prop(picl_nodehdl_t nodeh, picl_prophdl_t *proph)
version		SUNW_1.1
end		

function	ptree_get_next_prop
include		<picl.h> <picltree.h>
declaration	int ptree_get_next_prop(picl_prophdl_t thish, picl_prophdl_t *proph)
version		SUNW_1.1
end		

function	ptree_get_prop_by_name
include		<picl.h> <picltree.h>
declaration	int ptree_get_prop_by_name(picl_nodehdl_t nodeh, const char *name, picl_prophdl_t *proph)
version		SUNW_1.1
end		

function	ptree_get_next_by_row
include		<picl.h> <picltree.h>
declaration	int ptree_get_next_by_row(picl_prophdl_t proph, picl_prophdl_t *rowh)
version		SUNW_1.1
end		

function	ptree_get_next_by_col
include		<picl.h> <picltree.h>
declaration	int ptree_get_next_by_col(picl_prophdl_t proph, picl_prophdl_t *colh)
version		SUNW_1.1
end		

function	picld_plugin_register
include		<picl.h> <picltree.h>
declaration	int picld_plugin_register(picld_plugin_reg_t *infop)
version		SUNW_1.1
end		

function	ptree_init_propinfo
include		<picl.h> <picltree.h>
declaration	int ptree_init_propinfo(ptree_propinfo_t *infop, int version, int ptype, int pmode, size_t psize, char *pname, int (*readfn)(ptree_rarg_t *, void *), int (*writefn)(ptree_warg_t *, const void *));
version		SUNW_1.2
end

function	ptree_create_and_add_prop
include		<picl.h> <picltree.h>
declaration	int ptree_create_and_add_prop(picl_nodehdl_t nodeh, ptree_propinfo_t *infop, void *vbuf, picl_prophdl_t *proph);
version		SUNW_1.2
end

function	ptree_create_and_add_node
include		<picl.h> <picltree.h>
declaration	int ptree_create_and_add_node(picl_nodehdl_t rooth, const char *name, const char *classname, picl_nodehdl_t *nodeh);
version		SUNW_1.2
end

function	ptree_walk_tree_by_class
include		<picl.h> <picltree.h>
declaration	int ptree_walk_tree_by_class(picl_nodehdl_t rooth, const char *classname, void *c_args, int (*callback_fn)(picl_nodehdl_t hdl, void *args))
version		SUNW_1.2
end

function	ptree_find_node
include		<picl.h> <picltree.h>
declaration	int ptree_find_node(picl_nodehdl_t rooth, char *pname, picl_prop_type_t ptype, void *pval, size_t valsize, picl_nodehdl_t *retnodeh)
version		SUNW_1.2
end

function	ptree_post_event
include		<picl.h> <picltree.h>
declaration	int	ptree_post_event(const char *ename, const void *earg, size_t size, void (*completion_handler)(char *ename, void *earg, size_t size))
version		SUNW_1.2
end

function	ptree_register_handler
include		<picl.h> <picltree.h>
declaration	int	ptree_register_handler(const char *ename, void (*evt_handler)(const char *ename, const void *earg, size_t size, void *cookie), void *cookie)
version		SUNW_1.2
end

function	ptree_unregister_handler
include		<picl.h> <picltree.h>
declaration	void	ptree_unregister_handler(const char *ename, void (*evt_handler)(const char *ename, const void *earg, size_t size, void *cookie), void *cookie);
version		SUNW_1.2
end

data		verbose_level
include		"ptree_impl.h"
declaration	int verbose_level;
version		SUNWprivate_1.2
end

function	dbg_print
include		"ptree_impl.h"
declaration	void	dbg_print(int level, const char *fmt, ...)
version		SUNWprivate_1.2
end

function	dbg_exec
include		"ptree_impl.h"
declaration	void	dbg_exec(int level, void (*fn)(void *arg), void *arg)
version		SUNWprivate_1.2
end
		
function	xptree_initialize
include		"ptree_impl.h"
declaration	int xptree_initialize(int)
version		SUNWprivate_1.1
end		

function	xptree_reinitialize
include		"ptree_impl.h"
declaration	int xptree_reinitialize(void)
version		SUNWprivate_1.1
end
		
function	xptree_destroy
include		"ptree_impl.h"
declaration	void xptree_destroy(void)
version		SUNWprivate_1.1
end
		
function	xptree_refresh_notify
include		"ptree_impl.h"
declaration	int xptree_refresh_notify(unsigned int)
version		SUNWprivate_1.1
end

function	cvt_picl2ptree
include		"ptree_impl.h"
declaration	int cvt_picl2ptree(picl_hdl_t piclh, picl_hdl_t *ptreeh)
version		SUNWprivate_1.1
end

function	cvt_ptree2picl
include		"ptree_impl.h"
declaration	void cvt_ptree2picl(picl_hdl_t *vbuf)
version		SUNWprivate_1.1
end

function	xptree_get_propval_with_cred
include		"ptree_impl.h"
declaration	int xptree_get_propval_with_cred(picl_prophdl_t proph, void *valbuf, size_t size, door_cred_t cred)
version		SUNWprivate_1.1
end		

function	xptree_get_propval_by_name_with_cred
include		"ptree_impl.h"
declaration	int xptree_get_propval_by_name_with_cred(picl_nodehdl_t nodeh, const char *propname, void *valbuf, size_t sz, door_cred_t cred)
version		SUNWprivate_1.1
end		

function	xptree_update_propval_with_cred
include		"ptree_impl.h"
declaration	int xptree_update_propval_with_cred(picl_prophdl_t proph, const void *valbuf, size_t sz, door_cred_t cred)
version		SUNWprivate_1.1
end		

function	xptree_update_propval_by_name_with_cred
include		"ptree_impl.h"
declaration	int xptree_update_propval_by_name_with_cred(picl_nodehdl_t nodeh, const char *propname, const void *valbuf, size_t sz, door_cred_t cred)
version		SUNWprivate_1.1
end

function	xptree_get_propinfo_by_name
include		"ptree_impl.h"
declaration	int xptree_get_propinfo_by_name(picl_nodehdl_t nodeh, const char *pname, ptree_propinfo_t *pinfo)
version		SUNWprivate_1.1
end		

function	ptree_get_node_by_path
include		<picl.h> <picltree.h>
declaration	int ptree_get_node_by_path(const char *piclurl, picl_nodehdl_t *handle)
version		SUNW_1.2
end

function	ptree_get_frutree_parent
include		<picl.h> <picltree.h>
declaration	int ptree_get_frutree_parent(picl_nodehdl_t rooth, picl_nodehdl_t *retnodeh)
version		SUNW_1.3
end
