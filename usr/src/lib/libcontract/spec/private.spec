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
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	contract_latest
include		<libcontract_priv.h>
declaration	int contract_latest(ctid_t *)
version		SUNWprivate_1.1
end

function	contract_open
include		<libcontract_priv.h>
declaration	int contract_open(ctid_t, const char *, const char *, int)
version		SUNWprivate_1.1
end

function	contract_abandon_id
include		<libcontract_priv.h>
declaration	int contract_abandon_id(ctid_t)
version		SUNWprivate_1.1
end

function	getctid
include		<libcontract_priv.h>
declaration	ctid_t getctid(void)
version		SUNWprivate_1.1
end

function	contract_event_dump
include		<libcontract_priv.h>
declaration	void contract_event_dump(FILE *, ct_evthdl_t, int)
version		SUNWprivate_1.1
end
