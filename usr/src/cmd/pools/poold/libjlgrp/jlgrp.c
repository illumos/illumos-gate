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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdlib.h>
#include <sys/lgrp_user.h>

#include "jlgrp.h"

static lgrp_cookie_t getCookie(JNIEnv *, jclass, jobject);
static void throwException(JNIEnv *, const char *, const char *);

/*
 * Return the output of the getCookie() method executed on the
 * supplied instance.
 */
lgrp_cookie_t
getCookie(JNIEnv *env, jclass clazz, jobject obj)
{
	jfieldID fid;

	fid = (*env)->GetFieldID(env, clazz, "cookie", "J");
	return ((lgrp_cookie_t)(*env)->GetLongField(env, obj, fid));
}

/*
 * Throw an exception of the specified class with the specified message.
 */
void
throwException(JNIEnv *env, const char *class, const char *msg)
{
	jclass clazz;

	clazz = (*env)->FindClass(env, class);

	(*env)->ThrowNew(env, clazz, msg);
}

/*
 * Obtain an lgrp cookie for an lgrp snapshot which contains details
 * about available resources that the operating system knows about.
 *
 * If the call fails, then throw an exception which indicates that the
 * snapshot could not be obtained.
 */
/*ARGSUSED1*/
JNIEXPORT jlong JNICALL
Java_com_sun_solaris_service_locality_LocalityDomain_jl_1init(JNIEnv *env,
    jobject obj, jint view)
{
	lgrp_cookie_t cookie;

	if ((cookie = lgrp_init(view)) == LGRP_COOKIE_NONE) {
		throwException(env, "java/lang/Exception",
		    "Could not obtain latency group cookie");
	}

	return ((jlong)cookie);
}

/*
 * Release the snapshot in use by this instance. It is assumed that
 * the cookie is held in the "cookie" field of the invoking instance
 */
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_locality_LocalityDomain_jl_1fini(JNIEnv *env,
    jobject obj)
{
	jclass clazz;

	clazz = (*env)->GetObjectClass(env, obj);
	return ((jint)lgrp_fini(getCookie(env, clazz, obj)));
}

/*
 * Create a new LocalityGroup object which acts as a proxy for the
 * root LocalityGroup.
 */
JNIEXPORT jobject JNICALL
Java_com_sun_solaris_service_locality_LocalityDomain_jl_1root(JNIEnv *env,
    jobject obj)
{
	jclass clazz;
	jmethodID mid;
	jlong root;
	jobject lgrp;

	clazz = (*env)->GetObjectClass(env, obj);

	root = (jlong) lgrp_root(getCookie(env, clazz, obj));

	clazz = (*env)->FindClass(env, "com/sun/solaris/service/locality/"
	    "LocalityGroup");
	mid = (*env)->GetMethodID(env, clazz, "<init>", "(Lcom/sun/solaris/"
	    "service/locality/LocalityDomain;JLcom/sun/solaris/service/"
	    "locality/LocalityGroup;)V");
	lgrp = (*env)->NewObject(env, clazz, mid, obj, root, NULL);
	return (lgrp);
}

/*
 * Return a new array containing all of the child LocalityGroup ids
 * for the supplied instance.
 */
JNIEXPORT jlongArray JNICALL
Java_com_sun_solaris_service_locality_LocalityGroup_jl_1children(JNIEnv *env,
    jobject obj)
{
	jclass clazz;
	jfieldID fid;
	lgrp_cookie_t cookie;
	jlong id;
	jsize nchild0, nchild;
	jlongArray children;
	int i;
	lgrp_id_t *native_child;
	jlong *java_child;
	jobject domain;

	clazz = (*env)->GetObjectClass(env, obj);
	fid = (*env)->GetFieldID(env, clazz, "domain",
	    "Lcom/sun/solaris/service/locality/LocalityDomain;");
	domain = (*env)->GetObjectField(env, obj, fid);

	cookie = getCookie(env, (*env)->GetObjectClass(env, domain), domain);
	fid = (*env)->GetFieldID(env, clazz, "id", "J");
	id = (*env)->GetLongField(env, obj, fid);
retry:
	nchild0 = (jsize)lgrp_children(cookie, (lgrp_id_t)id, NULL, 0);
	children = (*env)->NewLongArray(env, nchild0);
	if ((native_child = calloc(nchild0, sizeof (lgrp_id_t))) == NULL) {
		throwException(env, "java/lang/Exception",
		    "Could not allocate memory for native_child array");
		return (NULL);
	}
	nchild = lgrp_children(cookie, (lgrp_id_t)id, native_child, nchild0);
	if (nchild != nchild0) {
		free(native_child);
		goto retry;
	}

	if ((java_child = calloc(nchild, sizeof (jlong))) == NULL) {
		throwException(env, "java/lang/Exception",
		    "Could not allocate memory for java_child array");
		free(native_child);
		return (NULL);
	}

	for (i = 0; i < nchild; i++)
		java_child[i] = (jlong) native_child[i];
	(*env)->SetLongArrayRegion(env, children, 0, nchild, java_child);
	free(native_child);
	free(java_child);
	return (children);
}

/*
 * Return a new array containing all of the cpus contained directly
 * within the LocalityGroup identified by the supplied instance.
 */
JNIEXPORT jintArray JNICALL
Java_com_sun_solaris_service_locality_LocalityGroup_jl_1cpus(JNIEnv *env,
    jobject obj)
{
	jclass clazz;
	jfieldID fid;
	lgrp_cookie_t cookie;
	jlong id;
	jsize ncpus0, ncpus;
	jintArray cpus;
	int i;
	processorid_t *native_cpus;
	jint *java_cpus;
	jobject domain;

	clazz = (*env)->GetObjectClass(env, obj);
	fid = (*env)->GetFieldID(env, clazz, "domain",
	    "Lcom/sun/solaris/service/locality/LocalityDomain;");
	domain = (*env)->GetObjectField(env, obj, fid);

	cookie = getCookie(env, (*env)->GetObjectClass(env, domain), domain);

	fid = (*env)->GetFieldID(env, clazz, "id", "J");
	id = (*env)->GetLongField(env, obj, fid);
retry:
	ncpus0 = (jsize)lgrp_cpus((lgrp_cookie_t)cookie, (lgrp_id_t)id,
	    NULL, 0, LGRP_CONTENT_DIRECT);
	cpus = (*env)->NewIntArray(env, ncpus0);
	if ((native_cpus = calloc(ncpus0, sizeof (processorid_t))) == NULL) {
		throwException(env, "java/lang/Exception",
		    "Could not allocate memory for native_cpus array");
		return (NULL);
	}
	ncpus = (jsize)lgrp_cpus((lgrp_cookie_t)cookie, (lgrp_id_t)id,
	    native_cpus, ncpus0, LGRP_CONTENT_DIRECT);
	if (ncpus != ncpus0) {
		free(native_cpus);
		goto retry;
	}

	if ((java_cpus = calloc(ncpus, sizeof (jint))) == NULL) {
		free(native_cpus);
		throwException(env, "java/lang/Exception",
		    "Could not allocate memory for java_cpus array");
		return (NULL);
	}

	for (i = 0; i < ncpus; i++)
		java_cpus[i] = (jint)native_cpus[i];
	(*env)->SetIntArrayRegion(env, cpus, 0, ncpus, java_cpus);
	free(native_cpus);
	free(java_cpus);
	return (cpus);
}

/*
 * Return the latency between two supplied latency group IDs.
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
Java_com_sun_solaris_service_locality_LocalityGroup_jl_1latency(JNIEnv *env,
    jobject obj, jlong from, jlong to)
{
	return ((jint) lgrp_latency((lgrp_id_t)from, (lgrp_id_t)to));
}
