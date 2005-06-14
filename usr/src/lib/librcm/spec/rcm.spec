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
# lib/librcm/spec/rcm.spec

#
# Consolidation private PSARC 1998/460
#

function	rcm_alloc_handle
include		<librcm.h>
declaration	int rcm_alloc_handle(char *, uint_t, void *, rcm_handle_t **)
version		SUNWprivate_1.1
end

function	rcm_free_handle
include		<librcm.h>
declaration	int rcm_free_handle(rcm_handle_t *)
version		SUNWprivate_1.1
end

function	rcm_get_info
include		<librcm.h>
include		<librcm_impl.h>
declaration	int rcm_get_info(rcm_handle_t *, char *, uint_t, rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_get_info_list
include		<librcm.h>
include		<librcm_impl.h>
declaration	int rcm_get_info_list(rcm_handle_t *, char **, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_free_info
include		<librcm.h>
declaration	void rcm_free_info(rcm_info_t *)
version		SUNWprivate_1.1
end

function	rcm_append_info
include		<librcm.h>
declaration	int rcm_append_info(rcm_info_t **, rcm_info_t *)
version		SUNWprivate_1.1
end

function	rcm_info_next
include		<librcm.h>
declaration	rcm_info_tuple_t *rcm_info_next(rcm_info_t *, \
		rcm_info_tuple_t *)
version		SUNWprivate_1.1
end

function	rcm_info_rsrc
include		<librcm.h>
declaration	const char *rcm_info_rsrc(rcm_info_tuple_t *)
version		SUNWprivate_1.1
end

function	rcm_info_info
include		<librcm.h>
declaration	const char *rcm_info_info(rcm_info_tuple_t *)
version		SUNWprivate_1.1
end

function	rcm_info_error
include		<librcm.h>
declaration	const char *rcm_info_error(rcm_info_tuple_t *)
version		SUNWprivate_1.1
end

function	rcm_info_modname
include		<librcm.h>
declaration	const char *rcm_info_modname(rcm_info_tuple_t *)
version		SUNWprivate_1.1
end

function	rcm_info_pid
include		<librcm.h>
declaration	pid_t rcm_info_pid(rcm_info_tuple_t *)
version		SUNWprivate_1.1
end

function	rcm_info_state
include		<librcm.h>
declaration	int rcm_info_state(rcm_info_tuple_t *)
version		SUNWprivate_1.1
end

function	rcm_info_seqnum
include		<librcm.h>
declaration	int rcm_info_seqnum(rcm_info_tuple_t *)
version		SUNWprivate_1.1
end

function	rcm_info_properties
include		<librcm.h>
declaration	nvlist_t *rcm_info_properties(rcm_info_tuple_t *)
version		SUNWprivate_1.1
end

function	rcm_request_offline
include		<librcm.h>
declaration	int rcm_request_offline(rcm_handle_t *, char *, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_request_offline_list
include		<librcm.h>
declaration	int rcm_request_offline_list(rcm_handle_t *, char **, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_notify_online
include		<librcm.h>
declaration	int rcm_notify_online(rcm_handle_t *, char *, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_notify_online_list
include		<librcm.h>
declaration	int rcm_notify_online_list(rcm_handle_t *, char **, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_notify_remove
include		<librcm.h>
declaration	int rcm_notify_remove(rcm_handle_t *, char *, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_notify_remove_list
include		<librcm.h>
declaration	int rcm_notify_remove_list(rcm_handle_t *, char **, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_request_suspend
include		<librcm.h>
declaration	int rcm_request_suspend(rcm_handle_t *, char *, uint_t, \
		timespec_t *, rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_request_suspend_list
include		<librcm.h>
declaration	int rcm_request_suspend_list(rcm_handle_t *, char **, uint_t, \
		timespec_t *, rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_notify_resume
include		<librcm.h>
declaration	int rcm_notify_resume(rcm_handle_t *, char *, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_notify_resume_list
include		<librcm.h>
declaration	int rcm_notify_resume_list(rcm_handle_t *, char **, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_notify_capacity_change
include		<librcm.h>
declaration	int rcm_notify_capacity_change(rcm_handle_t *, char *, uint_t, \
		nvlist_t *, rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_request_capacity_change
include		<librcm.h>
declaration	int rcm_request_capacity_change(rcm_handle_t *, char *, \
		uint_t, nvlist_t *, rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_notify_event
include		<librcm.h>
declaration	int rcm_notify_event(rcm_handle_t *, char *, uint_t, \
		nvlist_t *, rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_register_interest
include		<librcm.h>
declaration	int rcm_register_interest(rcm_handle_t *, char *, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_unregister_interest
include		<librcm.h>
declaration	int rcm_unregister_interest(rcm_handle_t *, char *, uint_t)
version		SUNWprivate_1.1
end

function	rcm_register_event
include		<librcm.h>
declaration	int rcm_register_event(rcm_handle_t *, char *, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_unregister_event
include		<librcm.h>
declaration	int rcm_unregister_event(rcm_handle_t *, char *, uint_t)
version		SUNWprivate_1.1
end

function	rcm_register_capacity
include		<librcm.h>
declaration	int rcm_register_capacity(rcm_handle_t *, char *, uint_t, \
		rcm_info_t **)
version		SUNWprivate_1.1
end

function	rcm_unregister_capacity
include		<librcm.h>
declaration	int rcm_unregister_capacity(rcm_handle_t *, char *, uint_t)
version		SUNWprivate_1.1
end

#
# Project private interfaces
#
function	rcm_exec_cmd
include		<librcm.h>
declaration	int rcm_exec_cmd(char *)
version		SUNWprivate_1.1
end

function	rcm_module_dir
include		<librcm_impl.h>
declaration	char *rcm_module_dir(uint_t)
version		SUNWprivate_1.1
end

function	rcm_script_dir
include		<librcm_impl.h>
declaration	char *rcm_script_dir(uint_t)
version		SUNWprivate_1.1
end

function	rcm_dir
include		<librcm_impl.h>
declaration	char *rcm_dir(uint_t, int *)
version		SUNWprivate_1.1
end

function	rcm_get_script_dir
include		<librcm_impl.h>
declaration	char *rcm_get_script_dir(char *)
version		SUNWprivate_1.1
end

function	rcm_is_script
include		<librcm_impl.h>
declaration	int rcm_is_script(char *)
version		SUNWprivate_1.1
end

function	rcm_module_open
include		<librcm_impl.h>
declaration	void *rcm_module_open(char *)
version		SUNWprivate_1.1
end

function	rcm_module_close
include		<librcm_impl.h>
declaration	void rcm_module_close(void *)
version		SUNWprivate_1.1
end

function	rcm_log_message
include		<librcm_impl.h>
declaration	void rcm_log_message(int, char *, ...)
version		SUNWprivate_1.1
end

function	rcm_get_rsrcstate
include		<librcm_impl.h>
declaration	int rcm_get_rsrcstate(rcm_handle_t *, char *, int *)
version		SUNWprivate_1.1
end

function	rcm_get_client_name
include		<librcm.h>
declaration	const char *rcm_get_client_name(rcm_handle_t *)
version		SUNWprivate_1.1
end
