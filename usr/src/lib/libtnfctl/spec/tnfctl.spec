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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libtnfctl/spec/tnfctl.spec

function	tnfctl_exec_open
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_exec_open(const char *pgm_name, \
			char * const *argv, char * const *envp, \
			const char *libnfprobe_path, \
			const char *ld_preload, \
			tnfctl_handle_t **ret_val)
version		SUNW_1.1
end

function	tnfctl_pid_open
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_pid_open(pid_t pid, \
			tnfctl_handle_t **ret_val)
version		SUNW_1.1
end

function	tnfctl_continue
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_continue(tnfctl_handle_t *hndl, \
			tnfctl_event_t *evt, \
			tnfctl_handle_t **child_hndl)
version		SUNW_1.1
end

function	tnfctl_internal_open
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_internal_open( \
			tnfctl_handle_t **ret_val)
version		SUNW_1.1
end

function	tnfctl_kernel_open
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_kernel_open( \
			tnfctl_handle_t ** ret_val)
version		SUNW_1.1
end

function	tnfctl_indirect_open
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_indirect_open(void *prochandle, \
			tnfctl_ind_config_t *config, \
			tnfctl_handle_t **ret_val)
version		SUNW_1.1
end

function	tnfctl_trace_attrs_get
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_trace_attrs_get( \
			tnfctl_handle_t *hndl, tnfctl_trace_attrs_t *attrs)
version		SUNW_1.1
end

function	tnfctl_buffer_alloc
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_buffer_alloc(tnfctl_handle_t *hndl, \
			const char *trace_file_name, uint_t trace_buffer_size)
version		SUNW_1.1
end

function	tnfctl_register_funcs
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_register_funcs( \
			tnfctl_handle_t *hndl, \
			void * (*create_func)(tnfctl_handle_t *, \
			tnfctl_probe_t *), \
			void (*destroy_func)(void *))
version		SUNW_1.1
end

function	tnfctl_probe_apply
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_probe_apply(tnfctl_handle_t *hndl, \
			tnfctl_probe_op_t probe_op, void *clientdata)
version		SUNW_1.1
end

function	tnfctl_probe_apply_ids
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_probe_apply_ids(tnfctl_handle_t *hndl,\
			ulong_t probe_count, ulong_t *probe_ids, \
			tnfctl_probe_op_t probe_op, void *clientdata)
version		SUNW_1.1
end

function	tnfctl_probe_state_get
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_probe_state_get(tnfctl_handle_t *hndl,\
			tnfctl_probe_t *probe_hndl, \
			tnfctl_probe_state_t *state)
version		SUNW_1.1
end

function	tnfctl_probe_enable
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_probe_enable(tnfctl_handle_t *hndl, \
			tnfctl_probe_t *probe_hndl, void *ignored)
version		SUNW_1.1
end

function	tnfctl_probe_disable
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_probe_disable(tnfctl_handle_t *hndl, \
			tnfctl_probe_t *probe_hndl, void *ignored)
version		SUNW_1.1
end

function	tnfctl_probe_trace
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_probe_trace(tnfctl_handle_t *hndl, \
			tnfctl_probe_t *probe_hndl, void *ignored)
version		SUNW_1.1
end

function	tnfctl_probe_untrace
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_probe_untrace(tnfctl_handle_t *hndl, \
			tnfctl_probe_t *probe_hndl, void *ignored)
version		SUNW_1.1
end

function	tnfctl_check_libs
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_check_libs(tnfctl_handle_t *hndl)
version		SUNW_1.1
end

function	tnfctl_close
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_close(tnfctl_handle_t *hndl, \
			tnfctl_targ_op_t action)
version		SUNW_1.1
end

function	tnfctl_strerror
include		<tnf/tnfctl.h>
declaration	const char * tnfctl_strerror(tnfctl_errcode_t errcode)
version		SUNW_1.1
end

function	tnfctl_probe_connect
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_probe_connect(tnfctl_handle_t *hndl, \
			tnfctl_probe_t *probe_hndl, \
			const char *lib_base_name, const char *func_name)
version		SUNW_1.1
end

function	tnfctl_probe_disconnect_all
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_probe_disconnect_all( \
			tnfctl_handle_t *hndl, tnfctl_probe_t *probe_hndl, \
			void *ignored)
version		SUNW_1.1
end

function	tnfctl_buffer_dealloc
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_buffer_dealloc(tnfctl_handle_t *hndl)
version		SUNW_1.1
end

function	tnfctl_trace_state_set
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_trace_state_set( \
			tnfctl_handle_t *hndl, boolean_t trace_state)
version		SUNW_1.1
end

function	tnfctl_filter_state_set
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_filter_state_set( \
			tnfctl_handle_t *hndl, boolean_t filter_state)
version		SUNW_1.1
end

function	tnfctl_filter_list_get
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_filter_list_get( \
			tnfctl_handle_t *hndl, \
			pid_t **pid_list, int *pid_count)
version		SUNW_1.1
end

function	tnfctl_filter_list_add
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_filter_list_add( \
			tnfctl_handle_t *hndl,  pid_t pid_to_add)
version		SUNW_1.1
end

function	tnfctl_filter_list_delete
include		<tnf/tnfctl.h>
declaration	tnfctl_errcode_t tnfctl_filter_list_delete( \
			tnfctl_handle_t *hndl, pid_t pid_to_delete)
version		SUNW_1.1
end

function	_tnfctl_externally_traced_pid
version		SUNWprivate_1.1
end

function	_tnfctl_internal_tracing_flag
version		SUNWprivate_1.1
end
