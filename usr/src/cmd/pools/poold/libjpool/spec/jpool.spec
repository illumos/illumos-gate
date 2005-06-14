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
# "../../jpool.h"

function	Java_com_sun_solaris_service_pools_Value_getUnsignedInt64Value
include		"../../jpool.h"
declaration	jobject \
		Java_com_sun_solaris_service_pools_Value_getUnsignedInt64Value \
		(JNIEnv *jenv, jclass class, jlong pointer)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1bool
include		"../../jpool.h"
declaration	void \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1bool \
		(JNIEnv *jenv, jclass jcls, jlong jvalue, jshort jb)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1get_1type
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1get_1type \
		(JNIEnv *jenv, jclass jcls, jlong jvalue)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1INVAL
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1INVAL \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1info
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1info \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jpool, \
		jint jflags)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1rm_1property
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1rm_1property \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jelem, \
		jstring jname)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POF_1DESTROY
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POF_1DESTROY \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1properties
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1properties \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jelem, \
		jlong jarg, jlong jcallback)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POF_1INVALID
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POF_1INVALID \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1NONE
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1NONE \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_Value_getDoubleValue
include		"../../jpool.h"
declaration	jdouble \
		Java_com_sun_solaris_service_pools_Value_getDoubleValue \
		(JNIEnv *jenv, jclass class, jlong pointer)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1to_1elem
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1to_1elem \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jpool)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1static_1location
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1static_1location \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1INT
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1INT \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1rollback
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1rollback \
		(JNIEnv *jenv, jclass jcls, jlong jconf)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1status
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1status \
		(JNIEnv *jenv, jclass jcls, jlong jconf)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_Value_getBoolValue
include		"../../jpool.h"
declaration	jboolean \
		Java_com_sun_solaris_service_pools_Value_getBoolValue \
		(JNIEnv *jenv, jclass class, jlong pointer)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1components
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1components \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jresource, \
		jlong jarg, jlong jcallback)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1version
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1version \
		(JNIEnv *jenv, jclass jcls, jlong jver)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1name
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1name \
		(JNIEnv *jenv, jclass jcls, jlong jvalue, jstring jname)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1free
include		"../../jpool.h"
declaration	void \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1free \
		(JNIEnv *jenv, jclass jcls, jlong jvalue)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1set_1status
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1set_1status \
		(JNIEnv *jenv, jclass jcls, jint jstate)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1xtransfer
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1xtransfer \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jsource, \
		jlong jtarget, jobject jcomponents)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1DOUBLE
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1DOUBLE \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POF_1VALID
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POF_1VALID \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1alloc
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1alloc \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1resources
include		"../../jpool.h"
declaration	jobject \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1resources \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jobject jprops)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_Value_getLongValue
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_Value_getLongValue \
		(JNIEnv *jenv, jclass class, jlong pointer)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1strerror_1sys
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1strerror_1sys \
		(JNIEnv * jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1destroy
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1destroy \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jpool)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1property
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1property \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jelem, \
		jstring jname, jlong jproperty)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1dynamic_1location
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1dynamic_1location \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1component_1to_1elem
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1component_1to_1elem \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jcomponent)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1status
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1status \
		(JNIEnv *jenv, jclass jcls, jlong jstatep)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1LOOSE
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1LOOSE \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_HRTime_timestamp
include		"../../jpool.h"
declaration	jobject \
		Java_com_sun_solaris_service_pools_HRTime_timestamp \
		(JNIEnv *env, jobject obj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1info
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1info \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jresource, \
		jint jflags)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1alloc
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1alloc \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1STRING
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1STRING \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1create
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1create \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jstring jname)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1owning_1resource
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1owning_1resource \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jcomponent)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_init
include		"../../jpool.h"
declaration	void \
		Java_com_sun_solaris_service_pools_PoolInternal_init \
		(JNIEnv *env, jclass clazz)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_Value_getStringValue
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_Value_getStringValue \
		(JNIEnv *jenv, jclass class, jlong pointer)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1resources
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1resources \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jpool, \
		jlong jarg, jlong jcallback)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1set_1binding
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1set_1binding \
		(JNIEnv *jenv, jclass jcls, jstring jpool, jint jidtype, \
		jint jpid)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1info
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1info \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jint jflags)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POX_1NATIVE
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POX_1NATIVE \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1validate
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1validate \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jint jlevel)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1resource
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1resource \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jstring jtype, \
		jstring jname)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1dissociate
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1dissociate \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jpool, \
		jlong jresource)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolsException_getErrno
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolsException_getErrno \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1to_1elem
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1to_1elem \
		(JNIEnv *jenv, jclass jcls, jlong jconf)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1pools
include		"../../jpool.h"
declaration	jobject \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1pools \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jobject jprops)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1resource_1components
include		"../../jpool.h"
declaration	jobject \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1resource_1components \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong resource, \
		jobject jprops)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POX_1TEXT
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POX_1TEXT \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1location
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1location \
		(JNIEnv *jenv, jclass jcls, jlong jconf)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1close
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1close \
		(JNIEnv *jenv, jclass jcls, jlong jconf)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1associate
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1associate \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jpool, \
		jlong jresource)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1put_1property
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1put_1property \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jelem, \
		jstring jname, jlong jvalue)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1resource_1binding
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1resource_1binding \
		(JNIEnv *jenv, jclass jcls, jstring jtype, jint jpid)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1int64
include		"../../jpool.h"
declaration	void \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1int64 \
		(JNIEnv *jenv, jclass jcls, jlong jvalue, jlong ji64)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1type_1list
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1type_1list \
		(JNIEnv *jenv, jclass jcls, jlong jreslist, jlong jnumres)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1destroy
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1destroy \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jresource)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1pool
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1pool \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jstring jname)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1commit
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1commit \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jint jactive)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1uint64
include		"../../jpool.h"
declaration	void \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1uint64 \
		(JNIEnv *jenv, jclass jcls, jlong jvalue, jlong jui64)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1double
include		"../../jpool.h"
declaration	void \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1double \
		(JNIEnv *jenv, jclass jcls, jlong jvalue, jdouble jd)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1get_1name
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1get_1name \
		(JNIEnv *jenv, jclass jcls, jlong jvalue)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1UINT
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1UINT \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1remove
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1remove \
		(JNIEnv *jenv, jclass jcls, jlong jconf)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1STRICT
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1STRICT \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_Element_walkProps
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_Element_walkProps \
		(JNIEnv *env, jobject obj, jlong conf, jlong elem, \
		jobject handler, jobject userobj)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1open
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1open \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jstring jlocation, \
		jint jflags)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1free
include		"../../jpool.h"
declaration	void \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1free \
		(JNIEnv *jenv, jclass jcls, jlong jconf)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1error
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1error \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1transfer
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1transfer \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jsource, \
		jlong jtarget, jlong jsize)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1to_1elem
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1to_1elem \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jresource)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1update
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1update \
		(JNIEnv *jenv, jclass jcls, jlong jconf)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1pools
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1walk_1pools \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jarg, \
		jlong jcallback)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1create
include		"../../jpool.h"
declaration	jlong \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1resource_1create \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jstring jtype, \
		jstring jname)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1RUNTIME
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POV_1RUNTIME \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1component_1info
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1component_1info \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jcomponent, \
		jint jflags)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1binding
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1get_1binding \
		(JNIEnv *jenv, jclass jcls, jint jpid)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1strerror
include		"../../jpool.h"
declaration	jstring \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1strerror \
		(JNIEnv *jenv, jclass jcls, jint jperr)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1BOOL
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_get_1POC_1BOOL \
		(JNIEnv *jenv, jclass jcls)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1string
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1value_1set_1string \
		(JNIEnv * jenv, jclass jcls, jlong jvalue, jstring jstr)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1pool_1resources
include		"../../jpool.h"
declaration	jobject \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1pool_1resources \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jlong jpool, jobject jprops)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1export
include		"../../jpool.h"
declaration	jint \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1conf_1export \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jstring jlocation, \
		jint jformat)
version		SUNWprivate_1.1
end

function	Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1components
include		"../../jpool.h"
declaration	jobject \
		Java_com_sun_solaris_service_pools_PoolInternal_pool_1query_1components \
		(JNIEnv *jenv, jclass jcls, jlong jconf, jobject jprops)
version		SUNWprivate_1.1
end
