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
# lib/libdiskmgt/spec/diskmgt.spec

function        dm_free_descriptors
include         <libdiskmgt.h>
declaration     void dm_free_descriptors(dm_descriptor_t *desc_list)
version         SUNWprivate_1.1
end

function        dm_free_descriptor
include         <libdiskmgt.h>
declaration     void dm_free_descriptor(dm_descriptor_t desc)
version         SUNWprivate_1.1
end

function        dm_free_name
include         <libdiskmgt.h>
declaration     void dm_free_name(char *name)
version         SUNWprivate_1.1
end

function        dm_get_descriptors
include         <libdiskmgt.h>
declaration     dm_descriptor_t *dm_get_descriptors(dm_desc_type_t type, \
                int filter[], int *errp)
version         SUNWprivate_1.1
end

function        dm_get_associated_descriptors
include         <libdiskmgt.h>
declaration     dm_descriptor_t * \
                dm_get_associated_descriptors(dm_descriptor_t desc, \
                dm_desc_type_t type, int *errp)
version         SUNWprivate_1.1
end

function        dm_get_associated_types
include         <libdiskmgt.h>
declaration     dm_desc_type_t *dm_get_associated_types(dm_desc_type_t type)
version         SUNWprivate_1.1
end

function        dm_get_descriptor_by_name
include         <libdiskmgt.h>
declaration     dm_descriptor_t dm_get_descriptor_by_name(dm_desc_type_t \
                desc_type, char *name, int *errp)
version         SUNWprivate_1.1
end

function        dm_get_name
include         <libdiskmgt.h>
declaration     char *dm_get_name(dm_descriptor_t desc, int *errp)
version         SUNWprivate_1.1
end

function        dm_get_type
include         <libdiskmgt.h>
declaration     dm_desc_type_t dm_get_type(dm_descriptor_t desc)
version         SUNWprivate_1.1
end

function        dm_get_attributes
include         <libdiskmgt.h>
declaration     nvlist_t *dm_get_attributes(dm_descriptor_t desc, int *errp)
version         SUNWprivate_1.1
end

function        dm_get_stats
include         <libdiskmgt.h>
declaration     nvlist_t *dm_get_stats(dm_descriptor_t desc, int stat_type, \
                int *errp)
version         SUNWprivate_1.1
end

function        dm_init_event_queue
include         <libdiskmgt.h>
declaration     void dm_init_event_queue(void(*callback)(nvlist_t *, int), \
                int *errp)
version         SUNWprivate_1.1
end

function        dm_get_event
include         <libdiskmgt.h>
declaration     nvlist_t *dm_get_event(int *errp)
version         SUNWprivate_1.1
end

function	dm_get_slices
include		<libdiskmgt.h>
declaration	void dm_get_slices(char * drive, dm_descriptor_t **slices, \
		int *errp)
version		SUNWprivate_1.1
end

function	dm_get_slice_stats
include		<libdiskmgt.h>
declaration	void dm_get_slice_stats(char *slice, nvlist_t **dev_stats, \
		int *errp)
version		SUNWprivate_1.1
end

function	dm_inuse
include		<libdiskmgt.h>
declaration	void dm_inuse(char * dev_name, char **msg, dm_who_type_t who, 
		int *errp)
version		SUNWprivate_1.1
end

