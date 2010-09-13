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

@ _START_

# Messages to satisfy chkmsg target.  Numerous messages within common code
# aren't required for each target, but chkmsg has no way of dealing with
# ifdefs, thus this file exists to satisfy common code messages.

@ _END_

@ MSG_PTH_CONFIG_64	"/var/ld/64/ld.config"
@ MSG_PTH_LDPROF_64	"/usr/lib/link_audit/64/ldprof.so.1"
@ MSG_PTH_LDPROFSE_64	"/usr/lib/secure/64/ldprof.so.1"
@ MSG_PTH_RTLD_64	"/usr/lib/64/ld.so.1"
@ MSG_PTH_LIB_64	"/lib/64
@ MSG_PTH_USRLIB_64	"/usr/lib/64
@ MSG_PTH_LIBSE_64	"/lib/secure/64"
@ MSG_PTH_USRLIBSE_64	"/usr/lib/secure/64"

@ MSG_SYM_LAV8PLTENTER		"la_sparcv8_pltenter"
@ MSG_SYM_LAV9PLTENTER		"la_sparcv9_pltenter"
@ MSG_SYM_LAX86PLTENTER		"la_i86_pltenter"
@ MSG_SYM_LAAMD64PLTENTER	"la_amd64_pltenter"

@ MSG_SYM_LAPLTEXIT	"la_pltexit"
@ MSG_SYM_LAPLTEXIT_64	"la_pltexit64"
@ MSG_SYM_LASYMBIND	"la_symbind"
@ MSG_SYM_LASYMBIND_64	"la_symbind64"
