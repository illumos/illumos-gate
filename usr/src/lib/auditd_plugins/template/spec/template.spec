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

function	auditd_plugin_open
include		<security/auditd.h> <secdb.h>
declaration	auditd_rc_t auditd_plugin_open(const kva_t *kvlist,\
		char **ret_list, char **error)
end

function	auditd_plugin
include		<security/auditd.h> <secdb.h>
declaration	auditd_rc_t auditd_plugin(const char *input,\
		size_t in_len, uint32_t sequence, char **error)
end

function	auditd_plugin_close
include		<security/auditd.h> <secdb.h>
declaration	auditd_rc_t auditd_plugin_close(char **error)
end
