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
# lib/libsysevent/spec/sysevent.spec

function	sysevent_open_channel
include		<libsysevent.h>
declaration	sysevent_handle_t *sysevent_open_channel(const char *channel)
version		SUNWprivate_1.1
end

function	sysevent_open_channel_alt
include		<libsysevent.h>
declaration	sysevent_handle_t *sysevent_open_channel_alt(const char *channel_path)
version		SUNWprivate_1.1
end

function	sysevent_close_channel
include		<libsysevent.h>
declaration	void sysevent_close_channel(sysevent_handle_t *shp)
version		SUNWprivate_1.1
end

function	sysevent_bind_subscriber
include		<libsysevent.h>
declaration	int sysevent_bind_subscriber(sysevent_handle_t *shp, void (*event_handler)(sysevent_t *ev))
version		SUNWprivate_1.1
end

function	sysevent_bind_publisher
include		<libsysevent.h>
declaration	int sysevent_bind_publisher(sysevent_handle_t *shp)
version		SUNWprivate_1.1
end

function	sysevent_unbind_subscriber
include		<libsysevent.h>
declaration	void sysevent_unbind_subscriber(sysevent_handle_t *shp)
version		SUNWprivate_1.1
end

function	sysevent_unbind_publisher
include		<libsysevent.h>
declaration	void sysevent_unbind_publisher(sysevent_handle_t *shp)
version		SUNWprivate_1.1
end

function	sysevent_send_event
include		<libsysevent.h>
declaration	int sysevent_send_event(sysevent_handle_t *shp, sysevent_t *ev)
version		SUNWprivate_1.1
end

function	sysevent_register_event
include		<libsysevent.h>
declaration	int sysevent_register_event(sysevent_handle_t *shp, const char *event_class, const char **event_subclass_list, int subclass_num)
version		SUNWprivate_1.1
end


function	sysevent_unregister_event
include		<libsysevent.h>
declaration	void sysevent_unregister_event(sysevent_handle_t *shp, const char *event_class)
version		SUNWprivate_1.1
end

function	sysevent_cleanup_publishers
include		<libsysevent.h>
declaration	void sysevent_cleanup_publishers(sysevent_handle_t *shp)
version		SUNWprivate_1.1
end

function	sysevent_cleanup_subscribers
include		<libsysevent.h>
declaration	void sysevent_cleanup_subscribers(sysevent_handle_t *shp)
version		SUNWprivate_1.1
end

function	sysevent_bind_handle
include		<libsysevent.h>
declaration	sysevent_handle_t *sysevent_bind_handle(void (*event_handler)(sysevent_t *ev))
version		SUNW_1.1
end

function	sysevent_unbind_handle
include		<libsysevent.h>
declaration	void sysevent_unbind_handle(sysevent_handle_t *shp)
version		SUNW_1.1
end

function	sysevent_subscribe_event
include		<libsysevent.h>
declaration	int sysevent_subscribe_event(sysevent_handle_t *shp, const char *event_class, const char **event_subclass_list, int num_subclasses)
version		SUNW_1.1
end

function	sysevent_unsubscribe_event
include		<libsysevent.h>
declaration	void sysevent_unsubscribe_event(sysevent_handle_t *shp, const char *event_class)
version		SUNW_1.1
end

function	sysevent_alloc_event
include		<libsysevent.h>
declaration	sysevent_t *sysevent_alloc_event(char *event_class, char *event_subclass, char *vendor, char *pub_name, nvlist_t *attr_list)
version		SUNWprivate_1.1
end

function	sysevent_post_event
include		<libsysevent.h>
declaration	int sysevent_post_event(char *event_class, char *event_subclass, char *vendor, char *pub_name, nvlist_t *attr_list, sysevent_id_t *eid)
version		SUNW_1.1
end

function	sysevent_dup
include		<libsysevent.h>
declaration	sysevent_t *sysevent_dup(sysevent_t *ev)
version		SUNWprivate_1.1
end

function	sysevent_free
include		<libsysevent.h>
declaration	void sysevent_free(sysevent_t *ev)
version		SUNW_1.1
end

function	sysevent_get_attr_list
include		<libsysevent.h>
declaration	int sysevent_get_attr_list(sysevent_t *ev, nvlist_t **nvlist)	
version		SUNW_1.1
end

function	sysevent_lookup_attr
include		<libsysevent.h>
declaration	int sysevent_lookup_attr(sysevent_t *ev, char *name, int datatype, sysevent_value_t *se_value)
version		SUNWprivate_1.1
end

function	sysevent_attr_next
include		<libsysevent.h>
declaration	sysevent_attr_t *sysevent_attr_next(sysevent_t *ev, sysevent_attr_t *attr)
version		SUNWprivate_1.1
end

function	sysevent_attr_name
include		<libsysevent.h>
declaration	char *sysevent_attr_name(sysevent_attr_t *attr)
version		SUNWprivate_1.1
end

function	sysevent_attr_value
include		<libsysevent.h>
declaration	int sysevent_attr_value(sysevent_attr_t *attr, sysevent_value_t *se_value)
version		SUNWprivate_1.1
end

function	sysevent_get_class
include		<libsysevent.h>
declaration	int sysevent_get_class(sysevent_t *ev)
version		SUNWprivate_1.1
end

function	sysevent_get_class_name
include		<libsysevent.h>
declaration	char *sysevent_get_class_name(sysevent_t *ev)
version		SUNW_1.1
end

function	sysevent_get_subclass
include		<libsysevent.h>
declaration	int sysevent_get_subclass(sysevent_t *ev)
version		SUNWprivate_1.1
end

function	sysevent_get_subclass_name
include		<libsysevent.h>
declaration	char *sysevent_get_subclass_name(sysevent_t *ev)
version		SUNW_1.1
end

function	sysevent_get_pub
include		<libsysevent.h>
declaration	char *sysevent_get_pub(sysevent_t *ev)
version		SUNWprivate_1.1
end

function	sysevent_get_vendor_name
include		<libsysevent.h>
declaration	char *sysevent_get_vendor_name(sysevent_t *ev)
version		SUNW_1.1
end

function	sysevent_get_pub_name
include		<libsysevent.h>
declaration	char *sysevent_get_pub_name(sysevent_t *ev)
version		SUNW_1.1
end

function	sysevent_get_pid
include		<libsysevent.h>
declaration	void sysevent_get_pid(sysevent_t *ev, pid_t *pid)
version		SUNW_1.1
end

function	sysevent_get_seq
include		<libsysevent.h>
declaration	uint64_t sysevent_get_seq(sysevent_t *ev)
version		SUNW_1.1
end

function	sysevent_get_time
include		<libsysevent.h>
declaration	void sysevent_get_time(sysevent_t *ev, hrtime_t *etime)
version		SUNW_1.1
end

function	sysevent_get_size
include		<libsysevent.h>
declaration	size_t sysevent_get_size(sysevent_t *ev)
version		SUNW_1.1
end

function	se_print
include		<libsysevent.h>
declaration	void se_print(FILE *fp, sysevent_t *ev)
version		SUNWprivate_1.1
end

function	sysevent_evc_bind
include		<libsysevent.h>
declaration	int sysevent_evc_bind(const char *channel, evchan_t **scpp, uint32_t flags)
version		SUNWprivate_1.1
end

function	sysevent_evc_unbind	
include		<libsysevent.h>
declaration	void sysevent_evc_unbind(evchan_t *scp)
version		SUNWprivate_1.1
end

function	sysevent_evc_publish
include		<libsysevent.h>
declaration	int sysevent_evc_publish(evchan_t *scp, const char *event_class,const char *event_subclass, const char *vendor, const char *pub_name, nvlist_t *attr_list, uint32_t flags)
version		SUNWprivate_1.1
end

function	sysevent_evc_subscribe
include		<libsysevent.h>
declaration	int sysevent_evc_subscribe(evchan_t *scp, const char *sid, const char *event_class, int (*event_handler)(sysevent_t *ev, void *cookie), void *cookie, uint32_t flags)
version		SUNWprivate_1.1
end

function	sysevent_evc_unsubscribe
include		<libsysevent.h>
declaration	void sysevent_evc_unsubscribe(evchan_t *scp, const char *sid)
version		SUNWprivate_1.1
end

function	sysevent_evc_control
include		<libsysevent.h>
declaration	int sysevent_evc_control(evchan_t *scp, int cmd, ...)
version		SUNWprivate_1.1
end
