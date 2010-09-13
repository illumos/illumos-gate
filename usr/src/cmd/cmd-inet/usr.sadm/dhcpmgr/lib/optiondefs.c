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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <arpa/inet.h>
#include <jni.h>
#include <com_sun_dhcpmgr_bridge_Bridge.h>

#include "exception.h"
#include "dd_opt.h"
#include "class_cache.h"

/*
 * Retrieve default value for an option with a string value.  Returns a
 * single String.
 */
/*ARGSUSED*/
JNIEXPORT jstring JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getStringOption(
    JNIEnv *env,
    jobject obj,
    jshort code,
    jstring jarg)
{
	jstring jstr;
	struct dhcp_option *opt;
	ushort_t scode = (ushort_t)code;
	const char *arg;

	/* Get the option whose default value we want to generate. */
	arg = (*env)->GetStringUTFChars(env, jarg, NULL);
	if (arg == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Get the option data */
	opt = dd_getopt(scode, arg, NULL);
	(*env)->ReleaseStringUTFChars(env, jarg, arg);

	if (opt == NULL) {
		throw_memory_exception(env);
		return (NULL);
	}

	if (opt->error_code != 0) {
		throw_bridge_exception(env, opt->u.msg);
		dd_freeopt(opt);
		return (NULL);
	}

	/* Set the return value */
	jstr = (*env)->NewStringUTF(env, opt->u.ret.data.strings[0]);
	dd_freeopt(opt);
	return (jstr);
}

/*
 * Get the default value for an option whose value is one or more IP
 * addresses.  Returns an array of IPAddress objects.
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getIPOption(
    JNIEnv *env,
    jobject obj,
    jshort code,
    jstring jarg)
{
	jclass ip_class;
	jmethodID ip_cons;
	jobjectArray jlist = NULL;
	jobject jaddr;
	jstring jstr;
	struct dhcp_option *opt;
	ushort_t scode = (ushort_t)code;
	int i;
	const char *arg;

	/* Get classes and methods we need */
	ip_class = find_class(env, IP_CLASS);
	if (ip_class == NULL) {
		/* exception thrown */
		return (NULL);
	}
	ip_cons = get_methodID(env, ip_class, IP_CONS);
	if (ip_cons == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Retrieve option to generate value for */
	arg = (*env)->GetStringUTFChars(env, jarg, NULL);
	if (arg == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Go get the default value */
	opt = dd_getopt(scode, arg, NULL);
	(*env)->ReleaseStringUTFChars(env, jarg, arg);

	if (opt == NULL) {
		throw_memory_exception(env);
		return (NULL);
	}

	if (opt->error_code != 0) {
		throw_bridge_exception(env, opt->u.msg);
		dd_freeopt(opt);
		return (NULL);
	}

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, opt->u.ret.count, ip_class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		dd_freeopt(opt);
		return (NULL);
	}

	/* For each address, create an object and add it to the array */
	for (i = 0; i < opt->u.ret.count; ++i) {
		jstr = (*env)->NewStringUTF(env,
		    inet_ntoa(*opt->u.ret.data.addrs[i]));
		if (jstr == NULL) {
			/* exception thrown */
			break;
		}
		jaddr = (*env)->NewObject(env, ip_class, ip_cons, jstr);
		if (jaddr == NULL) {
			/* exception thrown */
			break;
		}

		(*env)->SetObjectArrayElement(env, jlist, i, jaddr);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			break;
		}
	}

	dd_freeopt(opt);
	return (jlist);
}

/*
 * Generate the default value for an option whose value is a list of numbers.
 * Returns an array of longs.
 */
/*ARGSUSED*/
JNIEXPORT jlongArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getNumberOption(
    JNIEnv *env,
    jobject obj,
    jshort code,
    jstring jarg)
{
	jlongArray list;
	struct dhcp_option *opt;
	const char *arg;
	ushort_t scode = (ushort_t)code;
	jlong *listel;
	int i;

	/* Get option to retrieve */
	arg = (*env)->GetStringUTFChars(env, jarg, NULL);
	if (arg == NULL) {
		/* exception thrown */
		return (NULL);
	}

	opt = dd_getopt(scode, arg, NULL);
	(*env)->ReleaseStringUTFChars(env, jarg, arg);

	if (opt == NULL) {
		throw_memory_exception(env);
		return (NULL);
	}

	if (opt->error_code != 0) {
		throw_bridge_exception(env, opt->u.msg);
		dd_freeopt(opt);
		return (NULL);
	}

	/* Allocate return array */
	list = (*env)->NewLongArray(env, opt->u.ret.count);
	if (list == NULL) {
		/* exception thrown */
		dd_freeopt(opt);
		return (NULL);
	}

	/* Get access to elements of return array, then copy data in */
	listel = (*env)->GetLongArrayElements(env, list, NULL);
	if (listel == NULL) {
		/* exception thrown */
		dd_freeopt(opt);
		return (NULL);
	}

	for (i = 0; i < opt->u.ret.count; ++i) {
		listel[i] = opt->u.ret.data.numbers[i];
	}

	/* Tell VM we're done so it can finish putting data back */
	(*env)->ReleaseLongArrayElements(env, list, listel, 0);

	dd_freeopt(opt);
	return (list);
}
