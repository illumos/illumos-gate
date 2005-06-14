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
#ident	"%Z%%M%	%I%	%E% SMI"

data		_dtrace_debug
version		SUNWprivate_1.1
end

data		_dtrace_version
version		SUNWprivate_1.1
end

function	dtrace_aggregate_clear
version		SUNWprivate_1.1
end

function	dtrace_aggregate_print
version		SUNWprivate_1.1
end

function	dtrace_aggregate_snap
version		SUNWprivate_1.1
end

function	dtrace_aggregate_walk
version		SUNWprivate_1.1
end

function	dtrace_aggregate_walk_keysorted
version		SUNWprivate_1.1
end

function	dtrace_aggregate_walk_keyrevsorted
version		SUNWprivate_1.1
end

function	dtrace_aggregate_walk_keyvarrevsorted
version		SUNWprivate_1.1
end

function	dtrace_aggregate_walk_keyvarsorted
version		SUNWprivate_1.1
end

function	dtrace_aggregate_walk_valsorted
version		SUNWprivate_1.1
end

function	dtrace_aggregate_walk_valrevsorted
version		SUNWprivate_1.1
end

function	dtrace_aggregate_walk_valvarrevsorted
version		SUNWprivate_1.1
end

function	dtrace_aggregate_walk_valvarsorted
version		SUNWprivate_1.1
end

function	dtrace_attr2str
version		SUNWprivate_1.1
end

function	dtrace_class_name
version		SUNWprivate_1.1
end

function	dtrace_close
version		SUNWprivate_1.1
end

function	dtrace_consume
version		SUNWprivate_1.1
end

function	dtrace_ctlfd
version		SUNWprivate_1.1
end

function	dtrace_desc2str
version		SUNWprivate_1.1
end

function	dtrace_difo_create
version		SUNWprivate_1.1
end

function	dtrace_difo_hold
version		SUNWprivate_1.1
end

function	dtrace_difo_print
version		SUNWprivate_1.1
end

function	dtrace_difo_release
version		SUNWprivate_1.1
end

function	dtrace_dof_create
version		SUNWprivate_1.1
end

function	dtrace_dof_destroy
version		SUNWprivate_1.1
end

function	dtrace_ecbdesc_create
version		SUNWprivate_1.1
end

function	dtrace_ecbdesc_hold
version		SUNWprivate_1.1
end

function	dtrace_ecbdesc_release
version		SUNWprivate_1.1
end

function	dtrace_errmsg
version		SUNWprivate_1.1
end

function	dtrace_errno
version		SUNWprivate_1.1
end

function	dtrace_faultstr
version		SUNWprivate_1.1
end

function	dtrace_fprinta
version		SUNWprivate_1.1
end

function	dtrace_fprintf
version		SUNWprivate_1.1
end

function	dtrace_geterr_dof
version		SUNWprivate_1.1
end

function	dtrace_getopt
version		SUNWprivate_1.1
end

function	dtrace_getopt_dof
version		SUNWprivate_1.1
end

function	dtrace_go
version		SUNWprivate_1.1
end

function	dtrace_handle_buffered
version		SUNWprivate_1.1
end

function	dtrace_handle_drop
version		SUNWprivate_1.1
end

function	dtrace_handle_err
version		SUNWprivate_1.1
end

function	dtrace_handle_proc
version		SUNWprivate_1.1
end

function	dtrace_id2desc
version		SUNWprivate_1.1
end

function	dtrace_lookup_by_addr
version		SUNWprivate_1.1
end

function	dtrace_lookup_by_name
version		SUNWprivate_1.1
end

function	dtrace_lookup_by_type
version		SUNWprivate_1.1
end

function	dtrace_object_info
version		SUNWprivate_1.1
end

function	dtrace_object_iter
version		SUNWprivate_1.1
end

function	dtrace_open
version		SUNWprivate_1.1
end

function	dtrace_printa_create
version		SUNWprivate_1.1
end

function	dtrace_printf_create
version		SUNWprivate_1.1
end

function	dtrace_printf_format
version		SUNWprivate_1.1
end

function	dtrace_probe
version		SUNWprivate_1.1
end

function	dtrace_probe_info
version		SUNWprivate_1.1
end

function	dtrace_probe_iter
version		SUNWprivate_1.1
end

function	dtrace_proc_continue
version		SUNWprivate_1.1
end

function	dtrace_proc_create
version		SUNWprivate_1.1
end

function	dtrace_proc_grab
version		SUNWprivate_1.1
end

function	dtrace_proc_release
version		SUNWprivate_1.1
end

function	dtrace_program_create
version		SUNWprivate_1.1
end

function	dtrace_program_destroy
version		SUNWprivate_1.1
end

function	dtrace_program_exec
version		SUNWprivate_1.1
end

function	dtrace_program_info
version		SUNWprivate_1.1
end

function	dtrace_program_link
version		SUNWprivate_1.1
end

function	dtrace_program_fcompile
version		SUNWprivate_1.1
end

function	dtrace_program_strcompile
version		SUNWprivate_1.1
end

function	dtrace_provider_modules
version		SUNWprivate_1.1
end

function	dtrace_setopt
version		SUNWprivate_1.1
end

function	dtrace_sleep
version		SUNWprivate_1.1
end

function	dtrace_stability_name
version		SUNWprivate_1.1
end

function	dtrace_status
version		SUNWprivate_1.1
end

function	dtrace_stmt_create
version		SUNWprivate_1.1
end

function	dtrace_stmt_action
version		SUNWprivate_1.1
end

function	dtrace_stmt_add
version		SUNWprivate_1.1
end

function	dtrace_stmt_destroy
version		SUNWprivate_1.1
end

function	dtrace_stmt_iter
version		SUNWprivate_1.1
end

function	dtrace_str2desc
version		SUNWprivate_1.1
end

function	dtrace_stop
version		SUNWprivate_1.1
end

function	dtrace_str2attr
version		SUNWprivate_1.1
end

function	dtrace_symbol_type
version		SUNWprivate_1.1
end

function	dtrace_type_strcompile
version		SUNWprivate_1.1
end

function	dtrace_type_fcompile
version		SUNWprivate_1.1
end

function	dtrace_update
version		SUNWprivate_1.1
end

function	dtrace_vopen
version		SUNWprivate_1.1
end

function	dtrace_work
version		SUNWprivate_1.1
end

function	dtrace_xstr2desc
version		SUNWprivate_1.1
end
