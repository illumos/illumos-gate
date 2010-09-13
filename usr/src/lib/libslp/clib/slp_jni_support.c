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
 * Copyright 1998,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains native methods for the Java SLP implementation.
 * So far this is just the syslog function.
 *
 * The file also contains two support functions, one for throwing exceptions
 * given a class name, and one for correctly converting unicode Strings to C
 * byte arrays.
 */

#include <malloc.h>
#include <jni.h>
#include <syslog.h>

#define	CLASS_JAVA_LANG_OUTOFMEMORYERROR "java/lang/OutOfMemoryError"
#define	CLASS_JAVA_LANG_STRING "java/lang/String"

#define	METHOD_GETBYTES "getBytes"

#define	SIG_JAVA_LANG_STRING_GETBYTES "()[B"

/*
 * Given a class name of an exception and a message attempt to throw
 * a new instance of the exception.
 */
static void
JNU_ThrowByName(JNIEnv *env, const char *name, const char *msg)
{
	jclass class = (*env)->FindClass(env, name);

	/*
	 * If class is NULL FindClass() encountered a problem locating the
	 * desired class and has already called ThrowNew() with an
	 * exception.
	 */
	if (class == NULL) {
		return;
	}

	(*env)->ThrowNew(env, class, msg);
	(*env)->DeleteLocalRef(env, class);
}

/*
 * Convert a Java String into a native set of characters using the
 * method String.getBytes(). This will ensure that the appropriate
 * character set encoding will be used. This is necessary if the
 * Java String uses unicode characters that cannot be easily
 * encoded into native chars.
 *
 * The buffer returned must be released by using free() once it is
 * finished with.
 *
 * This function returns NULL if an exception has been thrown during its
 * execution.
 */
static char
*JNU_GetStringNativeChars(JNIEnv *env, jstring jstr)
{
	jclass class;
	jmethodID method;
	jint len;
	jbyteArray bytes = NULL;
	char *result = NULL;

	/*
	 * Need a local reference for (1) FindClass(), (2) the bytes and
	 * (3) the FindClass() in ThrowByName() if all goes wrong.
	 */
	if ((*env)->EnsureLocalCapacity(env, 3) < 0) {
		JNU_ThrowByName(
		    env,
		    CLASS_JAVA_LANG_OUTOFMEMORYERROR,
		    NULL);

		return (NULL);
	}

	class = (*env)->FindClass(env, CLASS_JAVA_LANG_STRING);

	/*
	 * If class is NULL FindClass() encountered a problem locating the
	 * desired class and has already called ThrowNew() with an
	 * exception.
	 */
	if (class == NULL) {
		return (NULL);
	}

	method = (*env)->GetMethodID(
	    env,
	    class,
	    METHOD_GETBYTES,
	    SIG_JAVA_LANG_STRING_GETBYTES);

	/*
	 * If method is NULL GetMethodID() encountered a problem
	 * locating the desired method and has already called
	 * ThrowNew() with an exception.
	 */
	if (method != NULL) {
		/*
		 * Call String.getBytes(), creating our temporary
		 * byte array
		 */
		bytes = (*env)->CallObjectMethod(env, jstr, method);

		/* See if CallObjectMethod() threw an exception */
		if ((*env)->ExceptionCheck(env) == JNI_FALSE) {

			len = (*env)->GetArrayLength(env, bytes);

			/*
			 * Allocate a buffer for the native characters,
			 * need an extra char for string terminator.
			 * Note: calloc will provide the terminating
			 * '\0' for us.
			 */
			result = (char *)calloc(len + 1, sizeof (char));

			/*
			 * If allocation failed assume we are out of
			 * memory
			 */
			if (result == NULL) {
				JNU_ThrowByName(
				    env,
				    CLASS_JAVA_LANG_OUTOFMEMORYERROR,
				    NULL);
			} else {
				/*
				 * Copy the encoded bytes into the
				 * native string buffer
				 */
				(*env)->GetByteArrayRegion(
				    env,
				    bytes,
				    0,
				    len,
				    (jbyte *)result);
			}
		}

		if (bytes != NULL) {
		    (*env)->DeleteLocalRef(env, bytes);
		}
	}

	/* Clean up by deleting the local references */
	(*env)->DeleteLocalRef(env, class);

	return (result);
}

/*
 * Class:     com_sun_slp_Syslog
 * Method:    syslog
 * Signature: (ILjava/lang/String;)V
 */
/* ARGSUSED */
JNIEXPORT
void JNICALL Java_com_sun_slp_Syslog_syslog(JNIEnv *env,
					    jobject obj,
					    jint priority,
					    jstring jmsg) {

	char *msg = JNU_GetStringNativeChars(env, jmsg);

	/*
	 * Check to see if the String conversion was successful,
	 * if it wasn't an exception will have already been thrown.
	 */
	if (msg != NULL) {
		openlog("slpd", LOG_PID, LOG_DAEMON);
		syslog(priority, "%s", msg);
		closelog();

		free(msg);
	}
}
