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
 * adt_jni_event.c
 *
 * helper functions for the event-specific Java classes
 *
 * Automatically generated code; do not edit
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "../../libbsm/common/adt_xlate.h"
#include <jni.h>
#include "../com/sun/audit/AuditSession.h"	/* javah output */
#include "adt_jni.h"
#include <stdlib.h>
#include <string.h>

static char *except_class = "java/lang/Exception";

/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1admin_1authenticate_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jint	message)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_admin_authenticate);


	event->adt_admin_authenticate.message = message;

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);


	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1filesystem_1add_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	initial_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_filesystem_add);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_add.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_filesystem_add.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_add.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_filesystem_add.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_add.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_filesystem_add.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_add.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_filesystem_add.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* initial_values */
	if (initial_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, initial_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_add.initial_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, initial_values, string);
		if (event->adt_filesystem_add.initial_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_filesystem_add.object_name != NULL)
		free(event->adt_filesystem_add.object_name);

	if (event->adt_filesystem_add.domain != NULL)
		free(event->adt_filesystem_add.domain);

	if (event->adt_filesystem_add.name_service != NULL)
		free(event->adt_filesystem_add.name_service);

	if (event->adt_filesystem_add.auth_used != NULL)
		free(event->adt_filesystem_add.auth_used);

	if (event->adt_filesystem_add.initial_values != NULL)
		free(event->adt_filesystem_add.initial_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1filesystem_1delete_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	delete_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_filesystem_delete);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_delete.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_filesystem_delete.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_delete.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_filesystem_delete.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_delete.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_filesystem_delete.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_delete.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_filesystem_delete.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* delete_values */
	if (delete_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, delete_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_delete.delete_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, delete_values, string);
		if (event->adt_filesystem_delete.delete_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_filesystem_delete.object_name != NULL)
		free(event->adt_filesystem_delete.object_name);

	if (event->adt_filesystem_delete.domain != NULL)
		free(event->adt_filesystem_delete.domain);

	if (event->adt_filesystem_delete.name_service != NULL)
		free(event->adt_filesystem_delete.name_service);

	if (event->adt_filesystem_delete.auth_used != NULL)
		free(event->adt_filesystem_delete.auth_used);

	if (event->adt_filesystem_delete.delete_values != NULL)
		free(event->adt_filesystem_delete.delete_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1filesystem_1modify_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	changed_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_filesystem_modify);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_modify.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_filesystem_modify.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_modify.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_filesystem_modify.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_modify.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_filesystem_modify.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_modify.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_filesystem_modify.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* changed_values */
	if (changed_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, changed_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_filesystem_modify.changed_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, changed_values, string);
		if (event->adt_filesystem_modify.changed_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_filesystem_modify.object_name != NULL)
		free(event->adt_filesystem_modify.object_name);

	if (event->adt_filesystem_modify.domain != NULL)
		free(event->adt_filesystem_modify.domain);

	if (event->adt_filesystem_modify.name_service != NULL)
		free(event->adt_filesystem_modify.name_service);

	if (event->adt_filesystem_modify.auth_used != NULL)
		free(event->adt_filesystem_modify.auth_used);

	if (event->adt_filesystem_modify.changed_values != NULL)
		free(event->adt_filesystem_modify.changed_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1login_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jint	message)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_login);


	event->adt_login.message = message;

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);


	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1logout_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	user_name)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_logout);

	/* user_name */
	if (user_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, user_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_logout.user_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, user_name, string);
		if (event->adt_logout.user_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_logout.user_name != NULL)
		free(event->adt_logout.user_name);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1network_1add_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	initial_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_network_add);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_add.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_network_add.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_add.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_network_add.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_add.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_network_add.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_add.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_network_add.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* initial_values */
	if (initial_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, initial_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_add.initial_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, initial_values, string);
		if (event->adt_network_add.initial_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_network_add.object_name != NULL)
		free(event->adt_network_add.object_name);

	if (event->adt_network_add.domain != NULL)
		free(event->adt_network_add.domain);

	if (event->adt_network_add.name_service != NULL)
		free(event->adt_network_add.name_service);

	if (event->adt_network_add.auth_used != NULL)
		free(event->adt_network_add.auth_used);

	if (event->adt_network_add.initial_values != NULL)
		free(event->adt_network_add.initial_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1network_1delete_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	delete_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_network_delete);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_delete.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_network_delete.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_delete.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_network_delete.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_delete.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_network_delete.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_delete.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_network_delete.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* delete_values */
	if (delete_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, delete_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_delete.delete_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, delete_values, string);
		if (event->adt_network_delete.delete_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_network_delete.object_name != NULL)
		free(event->adt_network_delete.object_name);

	if (event->adt_network_delete.domain != NULL)
		free(event->adt_network_delete.domain);

	if (event->adt_network_delete.name_service != NULL)
		free(event->adt_network_delete.name_service);

	if (event->adt_network_delete.auth_used != NULL)
		free(event->adt_network_delete.auth_used);

	if (event->adt_network_delete.delete_values != NULL)
		free(event->adt_network_delete.delete_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1network_1modify_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	changed_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_network_modify);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_modify.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_network_modify.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_modify.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_network_modify.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_modify.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_network_modify.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_modify.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_network_modify.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* changed_values */
	if (changed_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, changed_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_network_modify.changed_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, changed_values, string);
		if (event->adt_network_modify.changed_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_network_modify.object_name != NULL)
		free(event->adt_network_modify.object_name);

	if (event->adt_network_modify.domain != NULL)
		free(event->adt_network_modify.domain);

	if (event->adt_network_modify.name_service != NULL)
		free(event->adt_network_modify.name_service);

	if (event->adt_network_modify.auth_used != NULL)
		free(event->adt_network_modify.auth_used);

	if (event->adt_network_modify.changed_values != NULL)
		free(event->adt_network_modify.changed_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1passwd_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	username)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_passwd);

	/* username */
	if (username != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, username, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_passwd.username = strdup(string);
		(*env)->ReleaseStringUTFChars(env, username, string);
		if (event->adt_passwd.username == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_passwd.username != NULL)
		free(event->adt_passwd.username);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1printer_1add_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	initial_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_printer_add);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_add.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_printer_add.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_add.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_printer_add.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_add.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_printer_add.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_add.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_printer_add.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* initial_values */
	if (initial_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, initial_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_add.initial_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, initial_values, string);
		if (event->adt_printer_add.initial_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_printer_add.object_name != NULL)
		free(event->adt_printer_add.object_name);

	if (event->adt_printer_add.domain != NULL)
		free(event->adt_printer_add.domain);

	if (event->adt_printer_add.name_service != NULL)
		free(event->adt_printer_add.name_service);

	if (event->adt_printer_add.auth_used != NULL)
		free(event->adt_printer_add.auth_used);

	if (event->adt_printer_add.initial_values != NULL)
		free(event->adt_printer_add.initial_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1printer_1delete_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	delete_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_printer_delete);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_delete.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_printer_delete.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_delete.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_printer_delete.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_delete.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_printer_delete.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_delete.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_printer_delete.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* delete_values */
	if (delete_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, delete_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_delete.delete_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, delete_values, string);
		if (event->adt_printer_delete.delete_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_printer_delete.object_name != NULL)
		free(event->adt_printer_delete.object_name);

	if (event->adt_printer_delete.domain != NULL)
		free(event->adt_printer_delete.domain);

	if (event->adt_printer_delete.name_service != NULL)
		free(event->adt_printer_delete.name_service);

	if (event->adt_printer_delete.auth_used != NULL)
		free(event->adt_printer_delete.auth_used);

	if (event->adt_printer_delete.delete_values != NULL)
		free(event->adt_printer_delete.delete_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1printer_1modify_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	changed_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_printer_modify);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_modify.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_printer_modify.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_modify.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_printer_modify.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_modify.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_printer_modify.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_modify.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_printer_modify.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* changed_values */
	if (changed_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, changed_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_printer_modify.changed_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, changed_values, string);
		if (event->adt_printer_modify.changed_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_printer_modify.object_name != NULL)
		free(event->adt_printer_modify.object_name);

	if (event->adt_printer_modify.domain != NULL)
		free(event->adt_printer_modify.domain);

	if (event->adt_printer_modify.name_service != NULL)
		free(event->adt_printer_modify.name_service);

	if (event->adt_printer_modify.auth_used != NULL)
		free(event->adt_printer_modify.auth_used);

	if (event->adt_printer_modify.changed_values != NULL)
		free(event->adt_printer_modify.changed_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1rlogin_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jint	message)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_rlogin);


	event->adt_rlogin.message = message;

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);


	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1role_1login_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jint	message)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_role_login);


	event->adt_role_login.message = message;

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);


	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1scheduledjob_1add_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	initial_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_scheduledjob_add);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_add.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_scheduledjob_add.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_add.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_scheduledjob_add.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_add.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_scheduledjob_add.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_add.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_scheduledjob_add.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* initial_values */
	if (initial_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, initial_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_add.initial_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, initial_values, string);
		if (event->adt_scheduledjob_add.initial_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_scheduledjob_add.object_name != NULL)
		free(event->adt_scheduledjob_add.object_name);

	if (event->adt_scheduledjob_add.domain != NULL)
		free(event->adt_scheduledjob_add.domain);

	if (event->adt_scheduledjob_add.name_service != NULL)
		free(event->adt_scheduledjob_add.name_service);

	if (event->adt_scheduledjob_add.auth_used != NULL)
		free(event->adt_scheduledjob_add.auth_used);

	if (event->adt_scheduledjob_add.initial_values != NULL)
		free(event->adt_scheduledjob_add.initial_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1scheduledjob_1delete_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	delete_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_scheduledjob_delete);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_delete.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_scheduledjob_delete.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_delete.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_scheduledjob_delete.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_delete.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_scheduledjob_delete.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_delete.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_scheduledjob_delete.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* delete_values */
	if (delete_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, delete_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_delete.delete_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, delete_values, string);
		if (event->adt_scheduledjob_delete.delete_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_scheduledjob_delete.object_name != NULL)
		free(event->adt_scheduledjob_delete.object_name);

	if (event->adt_scheduledjob_delete.domain != NULL)
		free(event->adt_scheduledjob_delete.domain);

	if (event->adt_scheduledjob_delete.name_service != NULL)
		free(event->adt_scheduledjob_delete.name_service);

	if (event->adt_scheduledjob_delete.auth_used != NULL)
		free(event->adt_scheduledjob_delete.auth_used);

	if (event->adt_scheduledjob_delete.delete_values != NULL)
		free(event->adt_scheduledjob_delete.delete_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1scheduledjob_1modify_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	changed_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_scheduledjob_modify);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_modify.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_scheduledjob_modify.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_modify.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_scheduledjob_modify.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_modify.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_scheduledjob_modify.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_modify.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_scheduledjob_modify.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* changed_values */
	if (changed_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, changed_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_scheduledjob_modify.changed_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, changed_values, string);
		if (event->adt_scheduledjob_modify.changed_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_scheduledjob_modify.object_name != NULL)
		free(event->adt_scheduledjob_modify.object_name);

	if (event->adt_scheduledjob_modify.domain != NULL)
		free(event->adt_scheduledjob_modify.domain);

	if (event->adt_scheduledjob_modify.name_service != NULL)
		free(event->adt_scheduledjob_modify.name_service);

	if (event->adt_scheduledjob_modify.auth_used != NULL)
		free(event->adt_scheduledjob_modify.auth_used);

	if (event->adt_scheduledjob_modify.changed_values != NULL)
		free(event->adt_scheduledjob_modify.changed_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1screenlock_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_screenlock);


	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);


	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1screenunlock_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_screenunlock);


	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);


	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1serialport_1add_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	initial_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_serialport_add);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_add.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_serialport_add.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_add.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_serialport_add.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_add.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_serialport_add.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_add.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_serialport_add.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* initial_values */
	if (initial_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, initial_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_add.initial_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, initial_values, string);
		if (event->adt_serialport_add.initial_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_serialport_add.object_name != NULL)
		free(event->adt_serialport_add.object_name);

	if (event->adt_serialport_add.domain != NULL)
		free(event->adt_serialport_add.domain);

	if (event->adt_serialport_add.name_service != NULL)
		free(event->adt_serialport_add.name_service);

	if (event->adt_serialport_add.auth_used != NULL)
		free(event->adt_serialport_add.auth_used);

	if (event->adt_serialport_add.initial_values != NULL)
		free(event->adt_serialport_add.initial_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1serialport_1delete_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	delete_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_serialport_delete);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_delete.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_serialport_delete.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_delete.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_serialport_delete.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_delete.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_serialport_delete.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_delete.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_serialport_delete.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* delete_values */
	if (delete_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, delete_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_delete.delete_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, delete_values, string);
		if (event->adt_serialport_delete.delete_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_serialport_delete.object_name != NULL)
		free(event->adt_serialport_delete.object_name);

	if (event->adt_serialport_delete.domain != NULL)
		free(event->adt_serialport_delete.domain);

	if (event->adt_serialport_delete.name_service != NULL)
		free(event->adt_serialport_delete.name_service);

	if (event->adt_serialport_delete.auth_used != NULL)
		free(event->adt_serialport_delete.auth_used);

	if (event->adt_serialport_delete.delete_values != NULL)
		free(event->adt_serialport_delete.delete_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1serialport_1modify_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	changed_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_serialport_modify);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_modify.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_serialport_modify.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_modify.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_serialport_modify.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_modify.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_serialport_modify.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_modify.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_serialport_modify.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* changed_values */
	if (changed_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, changed_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_serialport_modify.changed_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, changed_values, string);
		if (event->adt_serialport_modify.changed_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_serialport_modify.object_name != NULL)
		free(event->adt_serialport_modify.object_name);

	if (event->adt_serialport_modify.domain != NULL)
		free(event->adt_serialport_modify.domain);

	if (event->adt_serialport_modify.name_service != NULL)
		free(event->adt_serialport_modify.name_service);

	if (event->adt_serialport_modify.auth_used != NULL)
		free(event->adt_serialport_modify.auth_used);

	if (event->adt_serialport_modify.changed_values != NULL)
		free(event->adt_serialport_modify.changed_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1ssh_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jint	message)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_ssh);


	event->adt_ssh.message = message;

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);


	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1su_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	message)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_su);

	/* message */
	if (message != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, message, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_su.message = strdup(string);
		(*env)->ReleaseStringUTFChars(env, message, string);
		if (event->adt_su.message == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_su.message != NULL)
		free(event->adt_su.message);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1telnet_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jint	message)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_telnet);


	event->adt_telnet.message = message;

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);


	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1uauth_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	auth_used,
    jstring	objectname)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_uauth);

	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_uauth.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_uauth.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* objectname */
	if (objectname != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, objectname, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_uauth.objectname = strdup(string);
		(*env)->ReleaseStringUTFChars(env, objectname, string);
		if (event->adt_uauth.objectname == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_uauth.auth_used != NULL)
		free(event->adt_uauth.auth_used);

	if (event->adt_uauth.objectname != NULL)
		free(event->adt_uauth.objectname);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1usermgr_1add_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	initial_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_usermgr_add);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_add.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_usermgr_add.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_add.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_usermgr_add.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_add.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_usermgr_add.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_add.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_usermgr_add.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* initial_values */
	if (initial_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, initial_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_add.initial_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, initial_values, string);
		if (event->adt_usermgr_add.initial_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_usermgr_add.object_name != NULL)
		free(event->adt_usermgr_add.object_name);

	if (event->adt_usermgr_add.domain != NULL)
		free(event->adt_usermgr_add.domain);

	if (event->adt_usermgr_add.name_service != NULL)
		free(event->adt_usermgr_add.name_service);

	if (event->adt_usermgr_add.auth_used != NULL)
		free(event->adt_usermgr_add.auth_used);

	if (event->adt_usermgr_add.initial_values != NULL)
		free(event->adt_usermgr_add.initial_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1usermgr_1delete_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	delete_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_usermgr_delete);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_delete.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_usermgr_delete.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_delete.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_usermgr_delete.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_delete.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_usermgr_delete.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_delete.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_usermgr_delete.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* delete_values */
	if (delete_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, delete_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_delete.delete_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, delete_values, string);
		if (event->adt_usermgr_delete.delete_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_usermgr_delete.object_name != NULL)
		free(event->adt_usermgr_delete.object_name);

	if (event->adt_usermgr_delete.domain != NULL)
		free(event->adt_usermgr_delete.domain);

	if (event->adt_usermgr_delete.name_service != NULL)
		free(event->adt_usermgr_delete.name_service);

	if (event->adt_usermgr_delete.auth_used != NULL)
		free(event->adt_usermgr_delete.auth_used);

	if (event->adt_usermgr_delete.delete_values != NULL)
		free(event->adt_usermgr_delete.delete_values);

	adt_free_event((adt_event_data_t *)event);
}
/* ARGSUSED */
JNIEXPORT void JNICALL
Java_com_sun_audit_AuditEvent_1usermgr_1modify_putEvent(
    JNIEnv	*env,
    jobject	self,
    jbyteArray	jsession,
    jint	status,
    jint	ret_val,
    jstring	object_name,
    jstring	domain,
    jstring	name_service,
    jstring	auth_used,
    jstring	changed_values)
{
	adt_event_data_t	*event;
	adt_session_data_t	*session;
	char			*string;
	char			*locale;

	(void) j2c_pointer(env, jsession, (char **)&session);

	event = adt_alloc_event(session, ADT_usermgr_modify);

	/* object_name */
	if (object_name != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, object_name, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_modify.object_name = strdup(string);
		(*env)->ReleaseStringUTFChars(env, object_name, string);
		if (event->adt_usermgr_modify.object_name == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* domain */
	if (domain != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, domain, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_modify.domain = strdup(string);
		(*env)->ReleaseStringUTFChars(env, domain, string);
		if (event->adt_usermgr_modify.domain == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* name_service */
	if (name_service != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, name_service, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_modify.name_service = strdup(string);
		(*env)->ReleaseStringUTFChars(env, name_service, string);
		if (event->adt_usermgr_modify.name_service == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* auth_used */
	if (auth_used != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, auth_used, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_modify.auth_used = strdup(string);
		(*env)->ReleaseStringUTFChars(env, auth_used, string);
		if (event->adt_usermgr_modify.auth_used == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}
	/* changed_values */
	if (changed_values != NULL) {
		string = (char *)(*env)->GetStringUTFChars(
		    env, changed_values, NULL);
		if (string == NULL)
			goto cleanup; /* exception thrown */
		event->adt_usermgr_modify.changed_values = strdup(string);
		(*env)->ReleaseStringUTFChars(env, changed_values, string);
		if (event->adt_usermgr_modify.changed_values == NULL) {
			locale = I18N_SETUP;
			local_throw(env, except_class,
			    gettext("Out of memory"));
			(void) setlocale(LC_MESSAGES, locale);
			goto cleanup;
		}
	}

	(void) adt_put_event((adt_event_data_t *)event, status, ret_val);

	cleanup:

	if (event->adt_usermgr_modify.object_name != NULL)
		free(event->adt_usermgr_modify.object_name);

	if (event->adt_usermgr_modify.domain != NULL)
		free(event->adt_usermgr_modify.domain);

	if (event->adt_usermgr_modify.name_service != NULL)
		free(event->adt_usermgr_modify.name_service);

	if (event->adt_usermgr_modify.auth_used != NULL)
		free(event->adt_usermgr_modify.auth_used);

	if (event->adt_usermgr_modify.changed_values != NULL)
		free(event->adt_usermgr_modify.changed_values);

	adt_free_event((adt_event_data_t *)event);
}
