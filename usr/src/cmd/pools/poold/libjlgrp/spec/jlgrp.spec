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
# cmd/pools/poold/libjlgrp/spec/jlgrp.spec

function	Java_com_sun_solaris_service_locality_LocalityDomain_jl_1fini
include		"../../jlgrp.h"
declaration	jint \
		Java_com_sun_solaris_service_locality_LocalityDomain_jl_1fini \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_locality_LocalityDomain_jl_1init
include		"../../jlgrp.h"
declaration	jlong \
		Java_com_sun_solaris_service_locality_LocalityDomain_jl_1init \
		(JNIEnv *env, jobject obj, jint view)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_locality_LocalityDomain_jl_1root
include		"../../jlgrp.h"
declaration	jobject \
		Java_com_sun_solaris_service_locality_LocalityDomain_jl_1root \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_locality_LocalityGroup_jl_1children
include		"../../jlgrp.h"
declaration	jlongArray \
		Java_com_sun_solaris_service_locality_LocalityGroup_jl_1children \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_locality_LocalityGroup_jl_1cpus
include		"../../jlgrp.h"
declaration	jintArray \
		Java_com_sun_solaris_service_locality_LocalityGroup_jl_1cpus \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_locality_LocalityGroup_jl_1latency
include		"../../jlgrp.h"
declaration	jint \
		Java_com_sun_solaris_service_locality_LocalityGroup_jl_1latency \
		(JNIEnv *env, jobject obj, jlong from, jlong to)
version		SUNWprivate_1.1
end

