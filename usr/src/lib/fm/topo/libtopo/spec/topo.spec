#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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

function	topo_open
version		SUNWprivate
end

function        topo_close
version         SUNWprivate
end

function	topo_snap_hold
version		SUNWprivate
end

function	topo_snap_release
version		SUNWprivate
end

function	topo_node_name
version		SUNWprivate
end

function	topo_node_instance
version		SUNWprivate
end

function	topo_node_private
version		SUNWprivate
end

function	topo_hdl_errno
version		SUNWprivate
end

function	topo_strerror
version		SUNWprivate
end

function	topo_hdl_errmsg
version		SUNWprivate
end

function	topo_hdl_alloc
version		SUNWprivate
end

function	topo_hdl_zalloc
version		SUNWprivate
end

function	topo_hdl_free
version		SUNWprivate
end

function	topo_hdl_nvalloc
version		SUNWprivate
end

function	topo_hdl_nvdup
version		SUNWprivate
end

function	topo_hdl_strdup
version		SUNWprivate
end

function	topo_hdl_strfree
version		SUNWprivate
end

function	topo_walk_init
version		SUNWprivate
end

function	topo_walk_step
version		SUNWprivate
end

function	topo_walk_fini
version		SUNWprivate
end

function	topo_debug_set
version		SUNWprivate
end

function	topo_pgroup_create
version		SUNWprivate
end

function	topo_pgroup_destroy
version		SUNWprivate
end

function	topo_prop_get_int32
version		SUNWprivate
end

function	topo_prop_get_uint32
version		SUNWprivate
end

function	topo_prop_get_int64
version		SUNWprivate
end

function	topo_prop_get_uint64
version		SUNWprivate
end

function	topo_prop_get_string
version		SUNWprivate
end

function	topo_prop_get_fmri
version		SUNWprivate
end

function	topo_prop_get_all
version		SUNWprivate
end

function	topo_prop_set_int32
version		SUNWprivate
end

function	topo_prop_set_uint32
version		SUNWprivate
end

function	topo_prop_set_int64
version		SUNWprivate
end

function	topo_prop_set_uint64
version		SUNWprivate
end

function	topo_prop_set_string
version		SUNWprivate
end

function	topo_prop_set_fmri
version		SUNWprivate
end

function	topo_prop_inherit
version		SUNWprivate
end

function	topo_prop_stability
version		SUNWprivate
end

function	topo_node_resource
version		SUNWprivate
end

function	topo_node_asru
version		SUNWprivate
end

function	topo_node_fru
version		SUNWprivate
end

function	topo_node_label
version		SUNWprivate
end

function	topo_node_fru_set
version		SUNWprivate
end

function	topo_node_asru_set
version		SUNWprivate
end

function	topo_node_label_set
version		SUNWprivate
end

function	topo_node_range_create
version		SUNWprivate
end

function	topo_node_range_destroy
version		SUNWprivate
end

function	topo_node_bind
version		SUNWprivate
end

function	topo_node_unbind
version		SUNWprivate
end

function	topo_node_name
version		SUNWprivate
end

function	topo_node_private
version		SUNWprivate
end

function	topo_node_instance
version		SUNWprivate
end

function	topo_mod_alloc
version		SUNWprivate
end

function	topo_mod_zalloc
version		SUNWprivate
end

function	topo_mod_free
version		SUNWprivate
end

function	topo_mod_nvalloc
version		SUNWprivate
end

function	topo_mod_nvdup
version		SUNWprivate
end

function	topo_mod_strfree
version		SUNWprivate
end

function	topo_mod_strdup
version		SUNWprivate
end

function	topo_fmri_present
version		SUNWprivate
end

function	topo_fmri_contains
version		SUNWprivate
end

function	topo_fmri_create
version		SUNWprivate
end

function	topo_fmri_unusable
version		SUNWprivate
end

function	topo_fmri_nvl2str
version		SUNWprivate
end

function	topo_fmri_str2nvl
version		SUNWprivate
end

function	topo_fmri_expand
version		SUNWprivate
end

function	topo_fmri_asru
version		SUNWprivate
end

function	topo_fmri_fru
version		SUNWprivate
end

function	topo_fmri_compare
version		SUNWprivate
end

function	topo_fmri_invoke
version		SUNWprivate
end

function	topo_mod_clrdebug
version		SUNWprivate
end

function	topo_mod_setdebug
version		SUNWprivate
end

function	topo_mod_seterrno
version		SUNWprivate
end

function	topo_mod_dprintf
version		SUNWprivate
end

function	topo_mod_errmsg
version		SUNWprivate
end

function	topo_mod_errno
version		SUNWprivate
end

function	topo_mod_load
version		SUNWprivate
end

function	topo_mod_unload
version		SUNWprivate
end

function	topo_mod_register
version		SUNWprivate
end

function	topo_mod_unregister
version		SUNWprivate
end

function	topo_mod_enumerate
version		SUNWprivate
end

function	topo_method_invoke
version		SUNWprivate
end

function	topo_method_register
version		SUNWprivate
end

function	topo_method_unregister
version		SUNWprivate
end

function	topo_method_unregister_all
version		SUNWprivate
end

function	topo_mod_rootdir
version		SUNWprivate
end

function	topo_mod_private
version		SUNWprivate
end

function	topo_mod_handle
version		SUNWprivate
end

