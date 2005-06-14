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
# lib/libpicl/spec/picl.spec

function	picl_initialize
include		<picl.h>
declaration	int picl_initialize(void)
version		SUNW_1.1
end		

function	picl_shutdown
include		<picl.h>
declaration	int picl_shutdown(void)
version		SUNW_1.1
end		

function	picl_get_root
include		<picl.h>
declaration	int picl_get_root(picl_nodehdl_t *nodeh)
version		SUNW_1.1
end		

function	picl_get_propval
include		<picl.h>
declaration	int picl_get_propval(picl_prophdl_t proph, void *valbuf, size_t sz)
version		SUNW_1.1
end		

function	picl_get_propval_by_name
include		<picl.h>
declaration	int picl_get_propval_by_name(picl_nodehdl_t nodeh, const char *propname, void *valbuf, size_t sz)
version		SUNW_1.1
end		

function	picl_set_propval
include		<picl.h>
declaration	int picl_set_propval(picl_prophdl_t proph, void *valbuf, size_t sz)
version		SUNW_1.1
end		

function	picl_set_propval_by_name
include		<picl.h>
declaration	int picl_set_propval_by_name(picl_nodehdl_t nodeh, const char *propname, void *valbuf, size_t sz)
version		SUNW_1.1
end		

function	picl_get_propinfo
include		<picl.h>
declaration	int picl_get_propinfo(picl_prophdl_t proph, picl_propinfo_t *pi)
version		SUNW_1.1
end		

function	picl_get_first_prop
include		<picl.h>
declaration	int picl_get_first_prop(picl_nodehdl_t nodeh, picl_prophdl_t *proph)
version		SUNW_1.1
end		

function	picl_get_next_prop
include		<picl.h>
declaration	int picl_get_next_prop(picl_prophdl_t proph, picl_prophdl_t *nexth)
version		SUNW_1.1
end		

function	picl_get_prop_by_name
include		<picl.h>
declaration	int picl_get_prop_by_name(picl_nodehdl_t nodeh, const char *nm, picl_prophdl_t *ph)
version		SUNW_1.1
end		

function	picl_get_next_by_row
include		<picl.h>
declaration	int picl_get_next_by_row(picl_prophdl_t thish, picl_prophdl_t *proph)
version		SUNW_1.1
end		

function	picl_get_next_by_col
include		<picl.h>
declaration	int picl_get_next_by_col(picl_prophdl_t thish, picl_prophdl_t *proph)
version		SUNW_1.1
end		

function	picl_wait
include		<picl.h>
declaration	int picl_wait(unsigned int secs)
version		SUNW_1.1
end		

function	picl_strerror
include		<picl.h>
declaration	char *picl_strerror(int err)
version		SUNW_1.1
end		

function	picl_walk_tree_by_class
include		<picl.h>
declaration	int  picl_walk_tree_by_class(picl_nodehdl_t rooth, const char *classname, void *c_args, int (*callback_fn)(picl_nodehdl_t hdl, void *args))
version		SUNW_1.2
end		

function	picl_get_propinfo_by_name
include		<picl.h>
declaration	int  picl_get_propinfo_by_name(picl_nodehdl_t nodeh, const char *pname, picl_propinfo_t *pinfo, picl_prophdl_t *proph)
version		SUNW_1.2
end		

function	picl_find_node
include		<picl.h>
declaration	int  picl_find_node(picl_nodehdl_t rooth, char *pname, picl_prop_type_t ptype, void *pval, size_t valsize, picl_nodehdl_t *retnodeh)
version		SUNW_1.3
end

function	picl_get_node_by_path
include		<picl.h>
declaration 	int  picl_get_node_by_path(const char *piclpath, picl_nodehdl_t *nodeh)
version		SUNW_1.3
end

function	picl_get_frutree_parent
include		<picl.h>
declaration	int  picl_get_frutree_parent(picl_nodehdl_t devh, picl_nodehdl_t *fruh)
version		SUNW_1.3
end
