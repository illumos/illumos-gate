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
# cmd/pools/poold/libjkstat/spec/jkstat.spec

function	Java_com_sun_solaris_service_kstat_KstatCtl_chainUpdate
include		"../../jkstat.h"
declaration	void \
		Java_com_sun_solaris_service_kstat_KstatCtl_chainUpdate \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_kstat_KstatCtl_close
include		"../../jkstat.h"
declaration	int \
		Java_com_sun_solaris_service_kstat_KstatCtl_close \
		(JNIEnv *env, jobject obj, jlong kctl)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_kstat_KstatCtl_init
include		"../../jkstat.h"
declaration	void \
		Java_com_sun_solaris_service_kstat_KstatCtl_init \
		(JNIEnv *env, jclass clazz)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_kstat_KstatCtl_lookup
include		"../../jkstat.h"
declaration	jobject \
		Java_com_sun_solaris_service_kstat_KstatCtl_lookup \
		(JNIEnv *env, jobject obj, jstring moduleObj, \
		jint instance, jstring nameObj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_kstat_KstatCtl_open
include		"../../jkstat.h"
declaration	jlong \
		Java_com_sun_solaris_service_kstat_KstatCtl_open \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_kstat_Kstat_getCreationTime
include		"../../jkstat.h"
declaration	jobject \
		Java_com_sun_solaris_service_kstat_Kstat_getCreationTime \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_kstat_Kstat_getSnapTime
include		"../../jkstat.h"
declaration	jobject \
		Java_com_sun_solaris_service_kstat_Kstat_getSnapTime \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_kstat_Kstat_getValue
include		"../../jkstat.h"
declaration	jobject \
		Java_com_sun_solaris_service_kstat_Kstat_getValue \
		(JNIEnv *env, jobject obj, jstring nameObj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_kstat_Kstat_read
include		"../../jkstat.h"
declaration	void \
		Java_com_sun_solaris_service_kstat_Kstat_read \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

