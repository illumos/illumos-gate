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

function	ea_alloc
include		<exacct.h>
declaration	void *ea_alloc(size_t size)
version		SUNW_1.2
end

function	ea_free
include		<exacct.h>
declaration	void ea_free(void *ptr, size_t size)
version		SUNW_1.2
end

function	ea_strdup
include		<exacct.h>
declaration	char *ea_strdup(const char *ptr)
version		SUNW_1.2
end

function	ea_strfree
include		<exacct.h>
declaration	void ea_strfree(char *ptr)
version		SUNW_1.2
end

function	ea_error
include		<exacct.h>
declaration	int ea_error(void)
version		SUNW_1.1
end

function	ea_open
include		<exacct.h>
declaration	int ea_open(ea_file_t *ef, const char *name, const char *creator, int aflags, int oflags, mode_t mode)
version		SUNW_1.1
end

function	ea_fdopen
include		<exacct.h>
declaration	int ea_fdopen(ea_file_t *ef, int fd, const char *creator, int aflags, int oflags)
version		SUNW_1.3
end

function	ea_clear
include		<exacct.h>
declaration	void ea_clear(ea_file_t *ef)
version		SUNW_1.3
end

function	ea_close
include		<exacct.h>
declaration	int ea_close(ea_file_t *ef)
version		SUNW_1.1
end

function	ea_next_object
include		<exacct.h>
declaration	ea_object_type_t ea_next_object(ea_file_t *ef, ea_object_t *obj)
version		SUNW_1.1
end

function	ea_previous_object
include		<exacct.h>
declaration	ea_object_type_t ea_previous_object(ea_file_t *ef, ea_object_t *obj)
version		SUNW_1.1
end

function	ea_get_object
include		<exacct.h>
declaration	ea_object_type_t ea_get_object(ea_file_t *ef, ea_object_t *obj)
version		SUNW_1.1
end

function	ea_write_object
include		<exacct.h>
declaration	int ea_write_object(ea_file_t *ef, ea_object_t *obj)
version		SUNW_1.1
end

function	ea_unpack_object
include		<sys/exacct.h>
declaration	ea_object_type_t ea_unpack_object(ea_object_t **objp, int flag, void *buf, size_t bufsize)
version		SUNW_1.1
end

function	ea_pack_object
include		<sys/exacct.h>
declaration	size_t ea_pack_object(ea_object_t *obj, void *buf, size_t bufsize)
version		SUNW_1.1
end

function	ea_match_object_catalog
include		<sys/exacct.h>
declaration	int ea_match_object_catalog(ea_object_t *obj, ea_catalog_t mask)
version		SUNW_1.1
end

function	ea_set_item
include		<sys/exacct.h>
declaration	int ea_set_item(ea_object_t *obj, ea_catalog_t tag, const void *value, size_t valsize)
version		SUNW_1.1
end

function	ea_set_group
include		<sys/exacct.h>
declaration	int ea_set_group(ea_object_t *obj, ea_catalog_t tag)
version		SUNW_1.1
end

function	ea_attach_to_object
include		<sys/exacct.h>
declaration	int ea_attach_to_object(ea_object_t *root, ea_object_t *obj)
version		SUNW_1.2
end

function	ea_attach_to_group
include		<sys/exacct.h>
declaration	int ea_attach_to_group(ea_object_t *group, ea_object_t *obj)
version		SUNW_1.2
end

function	ea_free_item
include		<sys/exacct.h>
declaration	int ea_free_item(ea_object_t *obj, int flag)
version		SUNW_1.2
end

function	ea_free_object
include		<sys/exacct.h>
declaration	void ea_free_object(ea_object_t *obj, int flag)
version		SUNW_1.1
end

function	ea_get_creator
include		<sys/exacct.h>
declaration	const char *ea_get_creator(ea_file_t *ef)
version		SUNW_1.1
end

function	ea_get_hostname
include		<sys/exacct.h>
declaration	const char *ea_get_hostname(ea_file_t *ef)
version		SUNW_1.1
end

function	ea_copy_object
include		<sys/exacct.h>
declaration	ea_object_t *ea_copy_object(const ea_object_t *src)
version		SUNW_1.2
end

function	ea_copy_object_tree
include		<sys/exacct.h>
declaration	ea_object_t *ea_copy_object_tree(const ea_object_t *src)
version		SUNW_1.2
end

function	ea_get_object_tree
include		<sys/exacct.h>
declaration	ea_object_t *ea_get_object_tree(ea_file_t *file, uint32_t nobj)
version		SUNW_1.2
end

function	exacct_order16
version		SUNWprivate
end

function	exacct_order32
version		SUNWprivate
end

function	exacct_order64
version		SUNWprivate
end
