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
 * adt_jni.c
 *
 * JNI wrapper for adt interface within libbsm
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <bsm/adt.h>
#include "adt_jni.h"
#include <jni.h>
#include "../com/sun/audit/AuditSession.h"	/* javah output */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

/*
 * local_throw  -- throw an exception.
 * "why" string must be i18n'd before calling here.
 *
 */

void
local_throw(JNIEnv *env, const char *exception, const char *why) {
	jobject jexception;
	jclass exceptionclass;
	jmethodID jexceptionnew;

	jbyteArray jbarray;

	jstring jmsg;
	jclass strclass;
	jmethodID jstrnew;

	/* Get a String class and "new" method */
	strclass = (*env)->FindClass(env, "java/lang/String");
	jstrnew = (*env)->GetMethodID(env, strclass, "<init>", "([B)V");

	/* Create a Byte Array from message "why" */
	jbarray = (*env)->NewByteArray(env, (jsize)(strlen(why)));
	(*env)->SetByteArrayRegion(env, jbarray, (jsize)0,
	    (jsize)(strlen(why)), (jbyte*) why);

	/* Create string from byte array */
	jmsg = (*env)->NewObject(env, strclass, jstrnew, jbarray);
	exceptionclass = (*env)->FindClass(env, exception);
	jexceptionnew = (*env)->GetMethodID(env, exceptionclass,
	    "<init>", "(Ljava/lang/String;)V");

	jexception = (*env)->NewObject(env, exceptionclass, jexceptionnew,
	    jmsg);
	(*env)->Throw(env, jexception);
}

/*
 * i18n the strerror return.  Input is errno.
 *
 */

static char *
errno_to_i18n(int error_code) {
	char	*locale;
	char	*local_text;

	locale = I18N_SETUP;
	local_text = strerror(error_code);
	(void) setlocale(LC_MESSAGES, locale);
	return (local_text);
}

/*
 * j2c_pointer
 *
 * convert java byte array into a C pointer
 */
int
j2c_pointer(JNIEnv *env, jbyteArray jpointer, caddr_t *cpointer) {
	union {
		caddr_t		ptr;
		jbyte		buf[sizeof (uint64_t)];
	} u;
	size_t			jpointer_length;
	char	*locale;

	(void) memset(u.buf, 0, sizeof (uint64_t));

	assert(jpointer != NULL);

	jpointer_length = (*env)->GetArrayLength(env, jpointer);
	if (jpointer_length != sizeof (uint64_t)) {
		locale = I18N_SETUP;
		local_throw(env, "java/lang/Error",
		    gettext("Bad session handle"));
		(void) setlocale(LC_MESSAGES, locale);
		return (-1);
	}
	(*env)->GetByteArrayRegion(env, jpointer, 0, jpointer_length,
	    &(u.buf[0]));
	*cpointer = (caddr_t)u.ptr;

	return (0);
}

/*
 * c2j_pointer
 *
 * convert a C pointer into a java byte array
 */
void
c2j_pointer(JNIEnv *env, caddr_t cpointer, jbyteArray *jpointer) {
	union {
		caddr_t		ptr;
		jbyte		buf[sizeof (uint64_t)];
	} u;

	(void) memset(u.buf, 0, sizeof (uint64_t));
	u.ptr = cpointer;

	*jpointer = (*env)->NewByteArray(env, sizeof (uint64_t));

	(*env)->SetByteArrayRegion(env, *jpointer, 0, sizeof (uint64_t),
	    &(u.buf[0]));
}

/*
 * adt_start_session wrapper
 *
 */
/*ARGSUSED*/
JNIEXPORT jbyteArray JNICALL
Java_com_sun_audit_AuditSession_startSession(JNIEnv *env, jobject cls,
    jbyteArray jimport, jlong flags) {
	jbyteArray		jstate;
	adt_session_data_t	*state;
	jbyte			*import;
	size_t			import_size;
	int			rc;

	if (jimport == NULL) {
		import = NULL;
	} else {
		import_size = (*env)->GetArrayLength(env, jimport);
		import = (jbyte *)malloc(import_size * sizeof (jbyte));
		if (import == NULL) {
			local_throw(env, "java/lang/Error",
			    errno_to_i18n(errno));
			return (NULL);
		}
		(*env)->GetByteArrayRegion(env, jimport, 0, import_size,
		    import);
	}
	rc = adt_start_session(&state, (adt_export_data_t *)import, flags);

	if (import != NULL)
		free(import);

	if (rc) {
		local_throw(env, "java/lang/Error", errno_to_i18n(errno));
		return (NULL);
	}
	c2j_pointer(env, (caddr_t)state, &jstate);

	return (jstate);
}

/*
 * adt_end_session wrapper
 */

/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditSession_endSession(JNIEnv *env, jobject cls,
    jbyteArray jstate) {
	adt_session_data_t	*state;
	char	*locale;

	if (j2c_pointer(env, jstate, (caddr_t *)&state))
		return;

	if (state == NULL)
		return;  /* invalid session, nothing to free */

	/* presently, no errors defined, but what the heck? */
	if (adt_end_session(state)) {
		locale = I18N_SETUP;
		local_throw(env, "java/lang/Error",
		    gettext("Bad session handle"));
		(void) setlocale(LC_MESSAGES, locale);
	}
}

/*
 * adt_dup_session wrapper
 */

/* ARGSUSED */
JNIEXPORT jbyteArray JNICALL
Java_com_sun_audit_AuditSession_dupSession(JNIEnv *env, jobject cls,
    jbyteArray jsource) {
	jbyteArray		jdest;
	adt_session_data_t	*source, *dest;
	char	*locale;

	if (j2c_pointer(env, jsource, (caddr_t *)&source))
		return (NULL);

	if (adt_dup_session(source, &dest)) {
		locale = I18N_SETUP;
		local_throw(env, "java/lang/Error",
		    gettext("Out of memory"));
		(void) setlocale(LC_MESSAGES, locale);
	}

	c2j_pointer(env, (caddr_t)dest, &jdest);

	return (jdest);
}

/*
 * adt_get_session_id wrapper
 *
 */

/* ARGSUSED */
JNIEXPORT jstring JNICALL
Java_com_sun_audit_AuditSession_getSessionId(JNIEnv *env, jobject cls,
    jbyteArray jstate) {
	adt_session_data_t	*state;
	char			*session_id;
	jstring			return_val;

	if (j2c_pointer(env, jstate, (caddr_t *)&state))
		return (NULL);

	if (adt_get_session_id(state, &session_id)) {
		return_val = (*env)->NewStringUTF(env, session_id);
		free(session_id);
		return (return_val);
	} else
		return (NULL);
}

/*
 * adt_get_session_id wrapper
 */

/* ARGSUSED */
JNIEXPORT jbyteArray JNICALL
Java_com_sun_audit_AuditSession_exportSessionData
	(JNIEnv *env, jobject cls, jbyteArray jstate) {
	adt_session_data_t	*state;
	size_t			length;
	jbyte			*buffer;
	jbyteArray		jbuf;

	if (j2c_pointer(env, jstate, (caddr_t *)&state))
		return (NULL);

	length = adt_export_session_data(state, (adt_export_data_t **)&buffer);

	if ((jbuf = (*env)->NewByteArray(env, length)) == NULL) {
		free(buffer);
		return (NULL);
	}
	(*env)->SetByteArrayRegion(env, jbuf, 0, length, buffer);
	free(buffer);

	return (jbuf);
}

/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditSession_sessionAttr(JNIEnv *env, jobject cls,
    jbyteArray jstate,
    jint euid, jint egid, jint ruid, jint rgid,
    jstring jhostname, jint context) {
	adt_session_data_t	*state;
	const char		*hostname;
	adt_termid_t		*termid;

	if (j2c_pointer(env, jstate, (caddr_t *)&state))
		return;	/* j2c_pointer threw exception */

	if (state == NULL)
		return;	/* invalid session */

	hostname = (*env)->GetStringUTFChars(env, jhostname, NULL);

	if (adt_load_hostname(hostname, &termid)) {
		local_throw(env, "java/lang/Error", errno_to_i18n(errno));
	} else if (adt_set_user(state, euid, egid, ruid, rgid, termid,
	    context)) {
		free(termid);
		local_throw(env, "java/lang/Error", errno_to_i18n(errno));
	}
	(*env)->ReleaseStringUTFChars(env, jhostname, hostname);
	free(termid);
}

/* ARGSUSED */
JNIEXPORT jboolean JNICALL
Java_com_sun_audit_AuditSession_bsmAuditOn(JNIEnv *env, jobject cls) {
	int condition;

	if (auditon(A_GETCOND, (caddr_t)&condition, sizeof (condition)))
		return (0);

	return (1);
}
