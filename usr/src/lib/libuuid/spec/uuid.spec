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
# lib/libuuid/spec/uuid.spec

# UUID generation
function	uuid_generate
include		<uuid/uuid.h>
declaration	void uuid_generate(uuid_t)
version		SUNW_1.1
end

function	uuid_generate_random
include		<uuid/uuid.h>
declaration	void uuid_generate_random(uuid_t)
version		SUNW_1.1
end

function	uuid_generate_time
include		<uuid/uuid.h>
declaration	void uuid_generate_time(uuid_t)
version		SUNW_1.1
end

function	uuid_copy
include		<uuid/uuid.h>
declaration	void uuid_copy(uuid_t, uuid_t)
version		SUNW_1.1
end

function	uuid_clear
include		<uuid/uuid.h>
declaration	void uuid_clear(uuid_t)
version		SUNW_1.1
end

function	uuid_unparse
include		<uuid/uuid.h>
declaration	void uuid_unparse(uuid_t, char *)
version		SUNW_1.1
end

function	uuid_compare
include		<uuid/uuid.h>
declaration	int uuid_compare(uuid_t, uuid_t)
version		SUNW_1.1
end

function	uuid_is_null
include		<uuid/uuid.h>
declaration	int uuid_is_null(uuid_t)
version		SUNW_1.1
end

function	uuid_parse
include		<uuid/uuid.h>
declaration	int uuid_parse(char *, uuid_t)
version		SUNW_1.1
end

function	uuid_time
include		<uuid/uuid.h>
declaration	time_t uuid_time(uuid_t, struct timeval *)
version		SUNW_1.1
end
