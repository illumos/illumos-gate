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
# lib/librcm/spec/rcm_event.spec

function	get_event_service
include		<librcm_event.h>
declaration	int get_event_service(char *door_name, void *data, size_t datalen, void **result, size_t *rlen)
version		SUNWprivate_1.1
end

function	create_event_service
include		<librcm_event.h>
declaration	int create_event_service(char *door_name, void (*func)(void **data, size_t *datalen))
version		SUNWprivate_1.1
end

function	revoke_event_service
include		<librcm_event.h>
declaration	int revoke_event_service(int fd)
version		SUNWprivate_1.1
end
