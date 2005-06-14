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
# lib/cfgadm_plugins/pci/pci.spec

function	cfga_change_state
include		<sys/types.h>
include		<sys/param.h>
include		<config_admin.h>
declaration	cfga_err_t cfga_change_state(cfga_cmd_t state_change_cmd, \
			const char *ap_id, char *options, \
			struct cfga_confirm *confp, struct cfga_msg *msgp, \
			char **errstring, cfga_flags_t flags)
version		SUNWprivate_1.1
end

function	cfga_private_func
include		<sys/types.h>
include		<sys/param.h>
include		<config_admin.h>
declaration	cfga_err_t cfga_private_func(const char *function, \
			const char *ap_id, const char *options, \
			struct cfga_confirm *confp, struct cfga_msg *msgp, \
			char **errstring, cfga_flags_t flags)
version		SUNWprivate_1.1
end

function	cfga_test
include		<sys/types.h>
include		<sys/param.h>
include		<config_admin.h>
declaration	cfga_err_t cfga_test(int num_ap_ids, char *const *ap_ids, \
			const char *options, struct cfga_msg *msgp, \
			char **errstring, cfga_flags_t flags)
version		SUNWprivate_1.1
end

function	cfga_list_ext
include			<sys/types.h>
include			<sys/param.h>
include			<config_admin.h>
declaration	cfga_err_t cfga_list_ext(const char *ap_id, \
			cfga_list_data_t **cs, int *nlist, \
			const char *options, const char *listopts, \
			char **errstring, cfga_flags_t flags)
version			SUNWprivate_1.1
end


function	cfga_help
include		<sys/types.h>
include		<sys/param.h>
include		<config_admin.h>
declaration	cfga_err_t cfga_help(struct cfga_msg *msgp, \
			const char *options, cfga_flags_t flags)
version		SUNWprivate_1.1
end

data		cfga_version
declaration	int cfga_version
version		SUNWprivate_1.1
end
