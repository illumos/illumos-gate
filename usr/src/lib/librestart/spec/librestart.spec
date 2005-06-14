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
# pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# The delegated restarter interface
#

function	_restarter_get_channel_name
include		<librestart_priv.h>
declaration	char *_restarter_get_channel_name(const char *, int)
version		SUNWprivate_1.1
end

function	_restarter_commit_states
include		<librestart_priv.h>
declaration	int _restarter_commit_states(scf_handle_t *, instance_data_t *, restarter_instance_state_t, restarter_instance_state_t, const char *)
version		SUNWprivate_1.1
end

function	restarter_bind_handle
include		<librestart.h>
declaration	int restarter_bind_handle(uint32_t, const char *, int (*event_handler)(restarter_event_t *), int, restarter_event_handle_t **)
version		SUNWprivate_1.1
end

function	restarter_unbind_handle
include		<librestart.h>
declaration	void restarter_unbind_handle(restarter_event_handle_t *)
version		SUNWprivate_1.1
end

function	restarter_event_get_type
include		<librestart.h>
declaration	restarter_event_type_t restarter_event_get_type(restarter_event_t *)
version		SUNWprivate_1.1
end

function	restarter_event_get_seq
include		<librestart.h>
declaration	uint64_t restarter_event_get_seq(restarter_event_t *)
version		SUNWprivate_1.1
end

function	restarter_event_get_time
include		<librestart.h>
declaration	void restarter_event_get_time(restarter_event_t *, hrtime_t *)
version		SUNWprivate_1.1
end

function	restarter_event_get_instance
include		<librestart.h>
declaration	ssize_t restarter_event_get_instance(restarter_event_t *, char *, size_t)
version		SUNWprivate_1.1
end

function	restarter_event_get_handle
include		<librestart.h>
declaration	restarter_event_handle_t *restarter_event_get_handle(restarter_event_t *)
version		SUNWprivate_1.1
end

function	restarter_event_get_enabled
include		<librestart.h>
declaration	int restarter_event_get_enabled(restarter_event_t *)
version		SUNWprivate_1.1
end

function	restarter_event_get_current_states
include		<librestart.h>
declaration	int restarter_event_get_current_states(restarter_event_t *, restarter_instance_state_t *, restarter_instance_state_t *)
version		SUNWprivate_1.1
end

function	restarter_set_states
include		<librestart.h>
declaration	int restarter_set_states(restarter_event_handle_t *, const char *, restarter_instance_state_t, restarter_instance_state_t, restarter_instance_state_t, restarter_instance_state_t, restarter_error_t, const char *)
version		SUNWprivate_1.1
end

function	restarter_store_contract
include		<librestart.h>
declaration	int restarter_store_contract(scf_instance_t *, ctid_t, restarter_contract_type_t)
version		SUNWprivate_1.1
end

function	restarter_remove_contract
include		<librestart.h>
declaration	int restarter_remove_contract(scf_instance_t *, ctid_t, restarter_contract_type_t)
version		SUNWprivate_1.1
end

function	restarter_state_to_string
include		<librestart.h>
declaration	ssize_t restarter_state_to_string(restarter_instance_state_t, char *, size_t)
version		SUNWprivate_1.1
end

function	restarter_string_to_state
include		<librestart.h>
declaration	restarter_instance_state_t restarter_string_to_state(char *)
version		SUNWprivate_1.1
end

function	restarter_rm_libs_loadable
include		<librestart.h>
declaration	int restarter_rm_libs_loadable(void)
version		SUNWprivate_1.1
end

function	restarter_get_method_context
include		<librestart.h>
declaration	const char *restarter_get_method_context(uint_t, scf_instance_t *, scf_snapshot_t *, const char *, const char *, struct method_context **)
version		SUNWprivate_1.1
end

function	restarter_set_method_context
include		<librestart.h>
declaration	int restarter_set_method_context(struct method_context *, const char **)
version		SUNWprivate_1.1
end

function	restarter_free_method_context
include		<librestart.h>
declaration	void restarter_free_method_context(struct method_context *)
version		SUNWprivate_1.1
end

function	restarter_is_null_method
include		<librestart.h>
declaration	int restarter_is_null_method(const char *)
version		SUNWprivate_1.1
end

function	restarter_is_kill_method
include		<librestart.h>
declaration	int restarter_is_kill_method(const char *)
version		SUNWprivate_1.1
end

function	restarter_is_kill_proc_method
include		<librestart.h>
declaration	int restarter_is_kill_proc_method(const char *)
version		SUNWprivate_1.1
end
