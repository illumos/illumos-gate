/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.service.pools;

/**
 * A thin layer over the libpool(3LIB) interface so that Java can be
 * used to manipulate resource pools. For more information on this
 * facility refer to the manpage and the developer documentation.
 *
 * Most of the functionality in this class is not intended to be
 * exposed to users of the package. The other classes in the package
 * provide appropriate Java abstractions for using this functionality.
 *
 * Refer to the package documentation and the documentation of the
 * other publicly visible classes for more details.
 */
public class PoolInternal {
	static {
		System.loadLibrary("jpool");
		PoolInternal.init();
	}

	final static native void init();
	final static native long pool_version(long ver);
	final static native int get_POX_NATIVE();
	final static native int get_POX_TEXT();
	final static native int get_POC_INVAL();
	final static native int get_POC_UINT();
	final static native int get_POC_INT();
	final static native int get_POC_DOUBLE();
	final static native int get_POC_BOOL();
	final static native int get_POC_STRING();
	final static native int get_POV_NONE();
	final static native int get_POV_LOOSE();
	final static native int get_POV_STRICT();
	final static native int get_POV_RUNTIME();
	final static native int get_POF_INVALID();
	final static native int get_POF_VALID();
	final static native int get_POF_DESTROY();
	public final static native int pool_error();
	public final static native String pool_strerror(int error);
	public final static native String pool_strerror_sys();
	public final static native int pool_resource_type_list(long types,
	    long numtypes);
	public final static native int pool_get_status();
	public final static native int pool_set_status(int state);
	final static native long pool_conf_alloc();
	final static native void pool_conf_free(long conf);
	final static native int pool_conf_status(long conf);
	final static native int pool_conf_close(long conf);
	final static native int pool_conf_remove(long conf);
	final static native int pool_conf_open(long conf, String location,
	    int oflags);
	final static native int pool_conf_rollback(long conf);
	final static native int pool_conf_commit(long conf, int active);
	final static native int pool_conf_export(long conf, String location,
	    int fmt);
	final static native int pool_conf_validate(long conf, int level);
	final static native int pool_conf_update(long conf);
	final static native long pool_get_pool(long conf, String name);
	final static native java.util.List pool_query_pools(long conf,
	    java.util.List props);
	final static native long pool_get_resource(long conf, String type,
	    String name);
	final static native java.util.List pool_query_resources(long conf,
	    java.util.List props);
	final static native java.util.List pool_query_components(long conf,
	    java.util.List props);
	final static native String pool_conf_location(long conf);
	final static native String pool_conf_info(long conf, int deep);
	final static native long pool_resource_create(long conf,
	    String type, String name);
	final static native int pool_resource_destroy(long conf, long res);
	final static native int pool_resource_transfer(long conf,
	    long src, long tgt, long size);
	final static native int pool_resource_xtransfer(long conf,
	    long src, long tgt, java.util.List components);
	final static native java.util.List pool_query_resource_components(
	    long conf, long res, java.util.List props);
	final static native String pool_resource_info(long conf, long res,
	    int deep);
	final static native long pool_create(long conf, String name);
	final static native int pool_destroy(long conf, long pool);
	final static native int pool_associate(long conf, long pool,
	    long res);
	final static native int pool_dissociate(long conf, long pool,
	    long res);
	final static native String pool_info(long conf, long pool, int deep);
	final static native java.util.List pool_query_pool_resources(
	    long conf, long pool, java.util.List props);
	final static native long pool_get_owning_resource(long conf,
	    long comp);
	final static native String pool_component_info(long conf,
	    long comp, int deep);
	final static native int pool_get_property(long conf, long elem,
	    String name, long val);
	final static native int pool_put_property(long conf, long elem,
	    String name, long val);
	final static native int pool_rm_property(long conf, long elem,
	    String name);
	final static native int pool_walk_properties(long conf, long elem,
	    long user, long callback);
	final static native long pool_conf_to_elem(long conf);
	final static native long pool_to_elem(long conf, long pool);
	final static native long pool_resource_to_elem(long conf, long res);
	final static native long pool_component_to_elem(long conf, long comp);
	final static native int pool_value_get_uint64(long pv, long result);
	final static native int pool_value_get_int64(long pv, long result);
	final static native int pool_value_get_double(long pv, long result);
	final static native int pool_value_get_bool(long pv, long result);
	final static native int pool_value_get_string(long pv, long result);
	final static native int pool_value_get_type(long pv);
	final static native void pool_value_set_uint64(long pv, long val);
	final static native void pool_value_set_int64(long pv, long val);
	final static native void pool_value_set_double(long pv, double val);
	final static native void pool_value_set_bool(long pv, short val);
	final static native int pool_value_set_string(long pv, String val);
	final static native String pool_value_get_name(long pv);
	final static native int pool_value_set_name(long pv, String val);
	final static native long pool_value_alloc();
	final static native void pool_value_free(long pv);
	public final static native String pool_static_location();
	public final static native String pool_dynamic_location();
	public final static native int pool_set_binding(String name,
	    int idtype, int id);
	public final static native String pool_get_binding(int pid);
	public final static native String pool_get_resource_binding(
	    String type, int pid);
	final static native int pool_walk_pools(long conf, long user,
	    long callback);
	final static native int pool_walk_resources(long conf, long pool,
	    long user, long callback);
	final static native int pool_walk_components(long conf, long res,
	    long user, long callback);
	/*
	 * enums and constants
	 */
	public final static int POOL_VER_CURRENT = 1;
	public final static int POOL_VER_NONE = 0;
	public final static int PO_TRUE = 1;
	public final static int PO_FALSE = 0;
	public final static int PO_SUCCESS = 0;
	public final static int PO_FAIL = -1;
	public final static int POE_OK = 0;
	public final static int POE_BAD_PROP_TYPE = 1;
	public final static int POE_INVALID_CONF = 2;
	public final static int POE_NOTSUP = 3;
	public final static int POE_INVALID_SEARCH = 4;
	public final static int POE_BADPARAM = 5;
	public final static int POE_PUTPROP = 6;
	public final static int POE_DATASTORE = 7;
	public final static int POE_SYSTEM = 8;
	public final static int POE_ACCESS = 9;
	public final static int PO_RDONLY = 0x0;
	public final static int PO_RDWR = 0x1;
	public final static int PO_CREAT = 0x2;
	public final static int PO_DISCO = 0x4;
	public final static int PO_UPDATE = 0x8;
	public final static String POA_IMPORTANCE = "importance based";
	public final static String POA_SURPLUS_TO_DEFAULT =
	    "surplus to default";
	public final static int POU_SYSTEM = 0x1;
	public final static int POU_POOL = 0x2;
	public final static int POU_PSET = 0x4;
	public final static int POU_CPU = 0x8;
	public final static int POX_NATIVE = get_POX_NATIVE();
	public final static int POX_TEXT = get_POX_TEXT();
	public final static int POC_INVAL = get_POC_INVAL();
	public final static int POC_UINT = get_POC_UINT();
	public final static int POC_INT = get_POC_INT();
	public final static int POC_DOUBLE = get_POC_DOUBLE();
	public final static int POC_BOOL = get_POC_BOOL();
	public final static int POC_STRING = get_POC_STRING();
	public final static int POV_NONE = get_POV_NONE();
	public final static int POV_LOOSE = get_POV_LOOSE();
	public final static int POV_STRICT = get_POV_STRICT();
	public final static int POV_RUNTIME = get_POV_RUNTIME();
	public final static int POF_INVALID = get_POF_INVALID();
	public final static int POF_VALID = get_POF_VALID();
	public final static int POF_DESTROY = get_POF_DESTROY();
}
