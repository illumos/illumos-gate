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
# lib/cfgadm_plugins/scsi/spec/cfga_scsi.spec


function	cfga_change_state
include		<sys/param.h>, <config_admin.h>
declaration	cfga_err_t cfga_change_state(cfga_cmd_t, const char *, \
			const char *, struct cfga_confirm *, \
			struct cfga_msg *, char **, cfga_flags_t)
version		SUNWprivate_1.1
end

function	cfga_help
include		<sys/param.h>, <config_admin.h>
declaration	cfga_err_t cfga_help(struct cfga_msg *, const char *, \
			cfga_flags_t)
version		SUNWprivate_1.1
end

function	cfga_list_ext
include		<sys/param.h>, <config_admin.h>
declaration	cfga_err_t cfga_list_ext(const char *, \
			struct cfga_list_data **, int *, const char *, \
			const char *, char **, cfga_flags_t)
version		SUNWprivate_1.1
end

function	cfga_private_func
include		<sys/param.h>, <config_admin.h>
declaration	cfga_err_t cfga_private_func(const char *, const char *, \
			const char *, struct cfga_confirm *, \
			struct cfga_msg *, char **, cfga_flags_t)
version		SUNWprivate_1.1
end

function	cfga_test
include		<sys/param.h>, <config_admin.h>
declaration	cfga_err_t cfga_test(const char *, const char *, \
			struct cfga_msg *, char **, cfga_flags_t)
version		SUNWprivate_1.1
end

data		cfga_version
declaration	int cfga_version
version		SUNWprivate_1.1
end
