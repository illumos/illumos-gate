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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <syslog.h>

#include "jsyslog.h"

#define	ILL_ARG_EX_CLASS_DESC	"java/lang/IllegalArgumentException"
#define	THROWABLE_CLASS_DESC	"java/lang/Throwable"

#define	CLASS_FIELD_DESC(class_desc)	"L" class_desc ";"

/*
 * syslog(3c) ident string
 */
static char jsyslog_ident[32];

/*
 * Log the given message with the given severity.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_logging_SyslogHandler_syslog(JNIEnv *env,
    jclass clazz, jint severity, jstring messageObj)
{
	const char *message;

	if (messageObj == NULL) {
		jclass exceptionClass;

		if (!(exceptionClass = (*env)->FindClass(env,
		    ILL_ARG_EX_CLASS_DESC)))
			return; /* exception thrown */
		(*env)->Throw(env, (*env)->NewObject(env, exceptionClass,
		    (*env)->GetStaticMethodID(env, exceptionClass, "<init>",
		    "()" CLASS_FIELD_DESC(THROWABLE_CLASS_DESC))));
		return;
	}

	if (!(message = (*env)->GetStringUTFChars(env, messageObj, NULL)))
		return; /* exception thrown */
	syslog(severity, "%s", message);
	(*env)->ReleaseStringUTFChars(env, messageObj, message);
}

/*
 * Invoke openlog(3c).
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_logging_SyslogHandler_openlog(JNIEnv *env,
    jclass clazz, jstring identObj, jint logopt, jint facility)
{
	const char *ident;

	if (identObj == NULL) {
		jclass exceptionClass;

		if (!(exceptionClass = (*env)->FindClass(env,
		    ILL_ARG_EX_CLASS_DESC)))
			return; /* exception thrown */
		(*env)->Throw(env, (*env)->NewObject(env, exceptionClass,
		    (*env)->GetStaticMethodID(env, exceptionClass, "<init>",
		    "()" CLASS_FIELD_DESC(THROWABLE_CLASS_DESC))));
		return;
	}

	if (!(ident = (*env)->GetStringUTFChars(env, identObj, NULL)))
		return; /* exception thrown */
	(void) strlcpy(jsyslog_ident, ident, sizeof (jsyslog_ident));
	openlog(jsyslog_ident, logopt, facility);

	(*env)->ReleaseStringUTFChars(env, identObj, ident);
}

/*
 * Invoke closelog(3c).
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_solaris_service_logging_SyslogHandler_closelog(JNIEnv *env,
    jclass clazz)
{
	closelog();
}
