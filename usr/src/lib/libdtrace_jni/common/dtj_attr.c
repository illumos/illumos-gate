/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dtrace_jni.h>

/*
 * This file creates instances of the Java class
 * org.opensolaris.os.dtrace.InterfaceAttributes.
 */

static const char *
dtj_stability_name(dtrace_stability_t stability)
{
	const char *name;
	switch (stability) {
	case DTRACE_STABILITY_INTERNAL:
		name = "INTERNAL";
		break;
	case DTRACE_STABILITY_PRIVATE:
		name = "PRIVATE";
		break;
	case DTRACE_STABILITY_OBSOLETE:
		name = "OBSOLETE";
		break;
	case DTRACE_STABILITY_EXTERNAL:
		name = "EXTERNAL";
		break;
	case DTRACE_STABILITY_UNSTABLE:
		name = "UNSTABLE";
		break;
	case DTRACE_STABILITY_EVOLVING:
		name = "EVOLVING";
		break;
	case DTRACE_STABILITY_STABLE:
		name = "STABLE";
		break;
	case DTRACE_STABILITY_STANDARD:
		name = "STANDARD";
		break;
	default:
		name = NULL;
	}

	return (name);
}

static const char *
dtj_dependency_class_name(dtrace_class_t class)
{
	const char *name;
	switch (class) {
	case DTRACE_CLASS_UNKNOWN:
		name = "UNKNOWN";
		break;
	case DTRACE_CLASS_CPU:
		name = "CPU";
		break;
	case DTRACE_CLASS_PLATFORM:
		name = "PLATFORM";
		break;
	case DTRACE_CLASS_GROUP:
		name = "GROUP";
		break;
	case DTRACE_CLASS_ISA:
		name = "ISA";
		break;
	case DTRACE_CLASS_COMMON:
		name = "COMMON";
		break;
	default:
		name = NULL;
	}

	return (name);
}

jobject
dtj_new_attribute(dtj_java_consumer_t *jc, const dtrace_attribute_t *attr)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	const char *name;

	jstring jname = NULL;
	jobject jattr = NULL; /* return value */

	jattr = (*jenv)->NewObject(jenv, g_attr_jc, g_attrinit_jm);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (NULL);
	}

	/* name stability */
	name = dtj_stability_name(attr->dtat_name);
	if (!name) {
		dtj_throw_illegal_argument(jenv,
		    "unexpected name stability value: %d",
		    attr->dtat_name);
		(*jenv)->DeleteLocalRef(jenv, jattr);
		return (NULL);
	}
	jname = (*jenv)->NewStringUTF(jenv, name);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, jattr);
		return (NULL);
	}
	(*jenv)->CallVoidMethod(jenv, jattr, g_attrset_name_jm, jname);
	(*jenv)->DeleteLocalRef(jenv, jname);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, jattr);
		return (NULL);
	}

	/* data stability */
	name = dtj_stability_name(attr->dtat_data);
	if (!name) {
		dtj_throw_illegal_argument(jenv,
		    "unexpected data stability value: %d",
		    attr->dtat_data);
		(*jenv)->DeleteLocalRef(jenv, jattr);
		return (NULL);
	}
	jname = (*jenv)->NewStringUTF(jenv, name);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, jattr);
		return (NULL);
	}
	(*jenv)->CallVoidMethod(jenv, jattr, g_attrset_data_jm, jname);
	(*jenv)->DeleteLocalRef(jenv, jname);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, jattr);
		return (NULL);
	}

	/* dependency class */
	name = dtj_dependency_class_name(attr->dtat_class);
	if (!name) {
		dtj_throw_illegal_argument(jenv,
		    "unexpected dependency class value: %d",
		    attr->dtat_class);
		(*jenv)->DeleteLocalRef(jenv, jattr);
		return (NULL);
	}
	jname = (*jenv)->NewStringUTF(jenv, name);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, jattr);
		return (NULL);
	}
	(*jenv)->CallVoidMethod(jenv, jattr, g_attrset_class_jm, jname);
	(*jenv)->DeleteLocalRef(jenv, jname);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, jattr);
		return (NULL);
	}

	return (jattr);
}
