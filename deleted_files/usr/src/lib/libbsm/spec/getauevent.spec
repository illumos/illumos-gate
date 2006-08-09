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
# lib/libbsm/spec/getauevent.spec

function	getauevent
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_event_ent *getauevent(void)
version		SUNW_0.7
exception	($return == 0)
end

function	getauevnam
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_event_ent *getauevnam(char *name)
version		SUNW_0.7
exception	($return == 0)
end

function	getauevnum
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_event_ent *getauevnum(au_event_t event_number)
version		SUNW_0.7
exception	($return == 0)
end

function	getauevnonam
include		<sys/param.h>, <bsm/libbsm.h>
declaration	au_event_t getauevnonam(char *event_name)
version		SUNW_0.7
end

function	setauevent
include		<sys/param.h>, <bsm/libbsm.h>
declaration	void setauevent(void)
version		SUNW_0.7
end

function	endauevent
include		<sys/param.h>, <bsm/libbsm.h>
declaration	void endauevent(void)
version		SUNW_0.7
end

function	getauevent_r
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_event_ent *getauevent_r(au_event_ent_t *e)
version		SUNW_0.8
exception	($return == 0)
end

function	getauevnam_r
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_event_ent *getauevnam_r(au_event_ent_t *e, char *name)
version		SUNW_0.8
end

function	getauevnum_r
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_event_ent *getauevnum_r(au_event_ent_t *e, \
			au_event_t  event_number)
version		SUNW_0.8
exception	($return == 0)
end
