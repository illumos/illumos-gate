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
# lib/libkstat/spec/kstat.spec

function	kstat_chain_update
include		<kstat.h>
declaration	kid_t kstat_chain_update(kstat_ctl_t *kc)
version		SUNW_0.7
exception	((int)$return == -1)
end

function	kstat_lookup
include		<kstat.h>
declaration	kstat_t *kstat_lookup(kstat_ctl_t *kc, char *ks_module, \
			int ks_instance, char	*ks_name)
version		SUNW_0.7
errno		
exception	($return == 0)
end

function	kstat_data_lookup
include		<kstat.h>
declaration	void *kstat_data_lookup(kstat_t *ksp, char *name)
version		SUNW_0.7
exception	($return == 0)
end

function	kstat_open
include		<kstat.h>
declaration	kstat_ctl_t *kstat_open(void)
version		SUNW_0.7
exception	($return == 0)
end

function	kstat_close
include		<kstat.h>
declaration	int kstat_close(kstat_ctl_t *kc)
version		SUNW_0.7
exception	($return == -1)
end

function	kstat_read
include		<kstat.h>
declaration	kid_t kstat_read(kstat_ctl_t *kc, kstat_t *ksp, void *buf)
version		SUNW_0.7
exception	($return == -1)
end

function	kstat_write
include		<kstat.h>
declaration	kid_t kstat_write(kstat_ctl_t *kc, kstat_t *ksp, void *buf)
version		SUNW_0.7
exception	($return == -1)
end
