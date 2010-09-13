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

#include <string.h>
#include <dtrace_jni.h>

/*
 * This file creates instances of the following Java classes:
 *	- org.opensolaris.os.dtrace.ProbeDescription
 *	- org.opensolaris.os.dtrace.ProbeInfo
 */

jobject
dtj_new_probedesc(dtj_java_consumer_t *jc, const dtrace_probedesc_t *probedesc)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	jstring jprov = NULL;
	jstring jmod = NULL;
	jstring jfunc = NULL;
	jstring jname = NULL;
	jobject jprobedesc = NULL;

	jprov = (*jenv)->NewStringUTF(jenv, probedesc->dtpd_provider);
	if ((*jenv)->ExceptionCheck(jenv)) {
		goto cleanup;
	}
	jmod = (*jenv)->NewStringUTF(jenv, probedesc->dtpd_mod);
	if ((*jenv)->ExceptionCheck(jenv)) {
		goto cleanup;
	}
	jfunc = (*jenv)->NewStringUTF(jenv, probedesc->dtpd_func);
	if ((*jenv)->ExceptionCheck(jenv)) {
		goto cleanup;
	}
	jname = (*jenv)->NewStringUTF(jenv, probedesc->dtpd_name);
	if ((*jenv)->ExceptionCheck(jenv)) {
		goto cleanup;
	}
	jprobedesc = (*jenv)->NewObject(jenv, g_probedesc_jc,
	    g_probedescinit_jm, jprov, jmod, jfunc, jname);
	if ((*jenv)->ExceptionCheck(jenv)) {
		goto cleanup;
	}
	/* Does not throw exceptions */
	(*jenv)->SetIntField(jenv, jprobedesc, g_probedesc_id_jf,
	    probedesc->dtpd_id);

cleanup:

	(*jenv)->DeleteLocalRef(jenv, jprov);
	(*jenv)->DeleteLocalRef(jenv, jmod);
	(*jenv)->DeleteLocalRef(jenv, jfunc);
	(*jenv)->DeleteLocalRef(jenv, jname);
	return (jprobedesc);
}

jobject
dtj_new_probeinfo(dtj_java_consumer_t *jc, const dtrace_probeinfo_t *probeinfo)
{
	JNIEnv *jenv = jc->dtjj_jenv;

	jobject jprobeattr = NULL;
	jobject jargattr = NULL;
	jobject jprobeinfo = NULL; /* return value */

	jprobeattr = dtj_new_attribute(jc, &probeinfo->dtp_attr);
	if ((*jenv)->ExceptionCheck(jenv)) {
		return (NULL);
	}
	jargattr = dtj_new_attribute(jc, &probeinfo->dtp_arga);
	if ((*jenv)->ExceptionCheck(jenv)) {
		(*jenv)->DeleteLocalRef(jenv, jprobeattr);
		return (NULL);
	}

	jprobeinfo = (*jenv)->NewObject(jenv, g_probeinfo_jc,
	    g_probeinfoinit_jm, jprobeattr, jargattr);

	(*jenv)->DeleteLocalRef(jenv, jprobeattr);
	(*jenv)->DeleteLocalRef(jenv, jargattr);
	return (jprobeinfo);
}
