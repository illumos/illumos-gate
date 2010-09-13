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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdarg.h>
#include <dhcp_svc_private.h>
#include <dhcp_symbol.h>
#include <libintl.h>
#include <jni.h>

#include "dd_misc.h"
#include "exception.h"

/*
 * Note: These must match exactly with the message ids defined in the
 * bridge ResourceBundle.properties file.
 */
#define	DSVC_EXISTS_EX			"dsvc_exists_exception"
#define	DSVC_ACCESS_EX			"dsvc_access_exception"
#define	DSVC_CREDENTIAL_EX		"dsvc_credential_exception"
#define	DSVC_NO_ENT_EX			"dsvc_no_ent_exception"
#define	DSVC_BUSY_EX			"dsvc_busy_exception"
#define	DSVC_INVALID_ARGS_EX		"dsvc_invalid_args_exception"
#define	DSVC_INTERNAL_EX		"dsvc_internal_exception"
#define	DSVC_UNAVAILABLE_EX		"dsvc_unavailable_exception"
#define	DSVC_COLLISION_EX		"dsvc_collision_exception"
#define	DSVC_UNSUPPORTED_EX		"dsvc_unsupported_exception"
#define	DSVC_NO_MEMORY_EX		"dsvc_no_memory_exception"
#define	DSVC_NO_RESOURCES_EX		"dsvc_no_resources_exception"
#define	DSVC_BAD_RESOURCE_EX		"dsvc_bad_resource_exception"
#define	DSVC_BAD_PATH_EX		"dsvc_bad_path_exception"
#define	DSVC_MOD_VERSION_EX		"dsvc_mod_version_exception"
#define	DSVC_MOD_ERR_EX			"dsvc_mod_err_exception"
#define	DSVC_MOD_LOAD_ERR_EX		"dsvc_mod_load_err_exception"
#define	DSVC_MOD_UNLOAD_ERR_EX		"dsvc_mod_unload_err_exception"
#define	DSVC_MOD_CFG_ERR_EX		"dsvc_mod_cfg_err_exception"
#define	DSVC_SYNCH_ERR_EX		"dsvc_synch_err_exception"
#define	DSVC_NO_LOCKMGR_EX		"dsvc_no_lockmgr_exception"
#define	DSVC_NO_LOCATION_EX		"dsvc_no_location_exception"
#define	DSVC_NO_TABLE_EX		"dsvc_no_table_exception"
#define	DSVC_TABLE_EXISTS_EX		"dsvc_table_exists_exception"
#define	DSVC_BAD_CONVER_EX		"dsvc_bad_conver_exception"
#define	DSVC_INTERNAL_ERROR		"dsvc_internal_error"

#define	DSYM_CODE_OUT_OF_RANGE_EX	"dsym_code_out_of_range_exception"
#define	DSYM_EXCEEDS_CLASS_SIZE_EX	"dsym_exceeds_class_size_exception"
#define	DSYM_EXCEEDS_MAX_CLASS_SIZE_EX	"dsym_exceeds_max_class_size_exception"
#define	DSYM_INTERNAL_EX		"dsym_internal_exception"
#define	DSYM_INVALID_CAT_EX		"dsym_invalid_cat_exception"
#define	DSYM_INVALID_TYPE_EX		"dsym_invalid_type_exception"
#define	DSYM_NO_MEMORY_EX		"dsym_no_memory_exception"
#define	DSYM_TOO_FEW_FIELDS_EX		"dsym_too_few_fields_exception"
#define	DSYM_SYNTAX_EX			"dsym_syntax_exception"
#define	DSYM_TOO_MANY_FIELDS_EX		"dsym_too_many_fields_exception"
#define	DSYM_VALUE_OUT_OF_RANGE_EX	"dsym_value_out_of_range_exception"

static void
throw_exception(JNIEnv *env, const char *name, const char *msgid,
    int nargs, ...)
{
	va_list ap;

	jclass class;
	jmethodID mid;
	jstring jmsgid = NULL;
	jobjectArray jlist = NULL;
	jthrowable throwObj;

	va_start(ap, nargs);

	class = (*env)->FindClass(env, name);
	if (class == NULL) {
		/* exception thrown */
		va_end(ap);
		return;
	}

	mid = (*env)->GetMethodID(env, class, "<init>",
	    "(Ljava/lang/String;[Ljava/lang/Object;)V");
	if (mid == NULL) {
		/* exception thrown */
		va_end(ap);
		return;
	}

	if (msgid != NULL) {
		jmsgid = dd_native_to_jstring(env, msgid);
		if (jmsgid == NULL) {
			/* exception thrown */
			va_end(ap);
			return;
		}
	}

	/* The arguments (if any) are arguments to the message */
	if (nargs != 0) {

		jclass strclass;
		int i;
		strclass = (*env)->FindClass(env, "java/lang/String");
		if (strclass == NULL) {
			/* exception thrown */
			va_end(ap);
			return;
		}

		jlist = (*env)->NewObjectArray(env, nargs, strclass, NULL);
		if (jlist == NULL) {
			/* exception thrown */
			va_end(ap);
			return;
		}

		for (i = 0; i < nargs; i++) {
			jstring jarg;
			char *arg;

			if ((arg = va_arg(ap, char *)) == 0) {
				break;
			}

			jarg = dd_native_to_jstring(env, arg);
			if (jarg == NULL) {
				/* exception thrown */
				break;
			}

			(*env)->SetObjectArrayElement(env, jlist, i, jarg);
			if ((*env)->ExceptionOccurred(env) != NULL) {
				break;
			}
		}

	}

	if ((*env)->ExceptionOccurred(env) == NULL) {
		throwObj = (jthrowable)(*env)->NewObject(env, class, mid,
		    jmsgid, jlist);
		if (throwObj == NULL) {
			/* exception thrown */
			va_end(ap);
			return;
		}

		/* finally! */
		(*env)->Throw(env, throwObj);
	}

	va_end(ap);
}

/* Throw an exception indicating record or file exists */
static void
throw_exists_exception(JNIEnv *env, const char *obj)
{
	throw_exception(env,
	    "com/sun/dhcpmgr/bridge/ExistsException", NULL, 1, obj);
}

/* Throw an exception indicating a table already exists */
static void
throw_table_exists_exception(JNIEnv *env, const char *obj)
{
	throw_exception(env, "com/sun/dhcpmgr/bridge/TableExistsException",
	    NULL, 1, obj);
}

/* Throw an exception indicating a table does not exist */
static void
throw_notable_exception(JNIEnv *env, const char *obj)
{
	throw_exception(env,
	    "com/sun/dhcpmgr/bridge/NoTableException", NULL, 1, obj);
}

/* Throw a generic bridge exception with a specified message */
void
throw_bridge_exception(JNIEnv *env, const char *msgid)
{
	throw_exception(env,
	    "com/sun/dhcpmgr/bridge/BridgeException", msgid, 0);
}

/* Throw an exception as a result of an remove_dd() error */
void
throw_remove_dd_exception(JNIEnv *env, int rcode, const char *obj)
{
	switch (rcode) {
	case DSVC_NO_TABLE:
		throw_notable_exception(env, obj);
		break;
	default:
		throw_libdhcpsvc_exception(env, rcode);
	}
}

/* Throw an exception as a result of an open_dd() error */
void
throw_open_dd_exception(JNIEnv *env, int rcode, const char *obj)
{
	switch (rcode) {
	case DSVC_TABLE_EXISTS:
		throw_table_exists_exception(env, obj);
		break;
	case DSVC_NO_TABLE:
		throw_notable_exception(env, obj);
		break;
	default:
		throw_libdhcpsvc_exception(env, rcode);
	}
}

/* Throw an exception as a result of an add_dd_entry() error */
void
throw_add_dd_entry_exception(JNIEnv *env, int rcode, const char *obj)
{
	switch (rcode) {
	case DSVC_EXISTS:
		throw_exists_exception(env, obj);
		break;
	default:
		throw_libdhcpsvc_exception(env, rcode);
	}
}

/* Throw an exception as a result of an delete_dd_entry() error */
void
throw_delete_dd_entry_exception(JNIEnv *env, int rcode, const char *obj)
{
	switch (rcode) {
	case DSVC_NOENT:
		throw_noent_exception(env, obj);
		break;
	default:
		throw_libdhcpsvc_exception(env, rcode);
	}
}

/* Throw an exception as a result of an modify_dd_entry() error */
void
throw_modify_dd_entry_exception(JNIEnv *env, int rcode, const char *orig,
	const char *new)
{
	switch (rcode) {
	case DSVC_EXISTS:
		throw_exists_exception(env, new);
		break;
	case DSVC_NOENT:
		throw_noent_exception(env, orig);
		break;
	default:
		throw_libdhcpsvc_exception(env, rcode);
	}
}

/* Throw an out of memory exception */
void
throw_memory_exception(JNIEnv *env)
{
	throw_libdhcpsvc_exception(env, DSVC_NO_MEMORY);
}

/* Throw an exception indicating that there is no DHCP config file */
void
throw_no_defaults_exception(JNIEnv *env)
{
	throw_exception(env,
	    "com/sun/dhcpmgr/bridge/NoDefaultsException", NULL, 0);
}

/* Throw an exception indicating record or file does not exist */
void
throw_noent_exception(JNIEnv *env, const char *obj)
{
	throw_exception(env,
	    "com/sun/dhcpmgr/bridge/NoEntryException", NULL, 1, obj);
}

/* Throw an exception indicating an invalid resource */
void
throw_invalid_resource_exception(JNIEnv *env, const char *obj)
{
	throw_exception(env, "com/sun/dhcpmgr/bridge/InvalidRsrcException",
	    NULL, 1, obj);
}

/* Throw an exception indicating an invalid path */
void
throw_invalid_path_exception(JNIEnv *env, const char *obj)
{
	throw_exception(env, "com/sun/dhcpmgr/bridge/InvalidPathException",
	    NULL, 1, obj);
}

/* Throw an exception indicating that the service is not currently running */
void
throw_not_running_exception(JNIEnv *env)
{
	throw_exception(env,
	    "com/sun/dhcpmgr/bridge/NotRunningException", NULL, 0);
}

/* Throw exception for a libdhcpsvc error that requires no special treatment */
void
throw_libdhcpsvc_exception(JNIEnv *env, int rcode)
{
	const char *msgid;

	switch (rcode) {
	case DSVC_SUCCESS:
		break;
	case DSVC_EXISTS:
		msgid = DSVC_EXISTS_EX;
		break;
	case DSVC_ACCESS:
		msgid = DSVC_ACCESS_EX;
		break;
	case DSVC_NO_CRED:
		msgid = DSVC_CREDENTIAL_EX;
		break;
	case DSVC_NOENT:
		msgid = DSVC_NO_ENT_EX;
		break;
	case DSVC_BUSY:
		msgid = DSVC_BUSY_EX;
		break;
	case DSVC_INVAL:
		msgid = DSVC_INVALID_ARGS_EX;
		break;
	case DSVC_INTERNAL:
		msgid = DSVC_INTERNAL_EX;
		break;
	case DSVC_UNAVAILABLE:
		msgid = DSVC_UNAVAILABLE_EX;
		break;
	case DSVC_COLLISION:
		msgid = DSVC_COLLISION_EX;
		break;
	case DSVC_UNSUPPORTED:
		msgid = DSVC_UNSUPPORTED_EX;
		break;
	case DSVC_NO_MEMORY:
		msgid = DSVC_NO_MEMORY_EX;
		break;
	case DSVC_NO_RESOURCES:
		msgid = DSVC_NO_RESOURCES_EX;
		break;
	case DSVC_BAD_RESOURCE:
		msgid = DSVC_BAD_RESOURCE_EX;
		break;
	case DSVC_BAD_PATH:
		msgid = DSVC_BAD_PATH_EX;
		break;
	case DSVC_MODULE_VERSION:
		msgid = DSVC_MOD_VERSION_EX;
		break;
	case DSVC_MODULE_ERR:
		msgid = DSVC_MOD_ERR_EX;
		break;
	case DSVC_MODULE_LOAD_ERR:
		msgid = DSVC_MOD_LOAD_ERR_EX;
		break;
	case DSVC_MODULE_UNLOAD_ERR:
		msgid = DSVC_MOD_UNLOAD_ERR_EX;
		break;
	case DSVC_MODULE_CFG_ERR:
		msgid = DSVC_MOD_CFG_ERR_EX;
		break;
	case DSVC_SYNCH_ERR:
		msgid = DSVC_SYNCH_ERR_EX;
		break;
	case DSVC_NO_LOCKMGR:
		msgid = DSVC_NO_LOCKMGR_EX;
		break;
	case DSVC_NO_LOCATION:
		msgid = DSVC_NO_LOCATION_EX;
		break;
	case DSVC_BAD_CONVER:
		msgid = DSVC_BAD_CONVER_EX;
		break;
	default:
		msgid = DSVC_INTERNAL_ERROR;
	}

	throw_bridge_exception(env, msgid);
}

/* Determine whether an exception is a defaults file doesn't exist exception */
boolean_t
is_no_defaults_exception(JNIEnv *env, jthrowable e)
{
	jclass class;
	boolean_t result = B_FALSE;

	class = (*env)->FindClass(env,
	    "com/sun/dhcpmgr/bridge/NoDefaultsException");
	if (class != NULL) {
		if ((*env)->IsInstanceOf(env, e, class) == JNI_TRUE &&
		    e != NULL) {
			result = B_TRUE;
		}
	}

	return (result);
}

/* Throw a symbol parsing error */
/* ARGSUSED [one day we should use the `key' argument in messages] */
void
throw_dsym_parser_exception(JNIEnv *env, const char *key, char **fields,
    int field, dsym_errcode_t rcode)
{
	const char *dsym_exception  = "com/sun/dhcpmgr/bridge/DsymException";

	char ascii_long_1[ULONG_MAX_CHAR + 1];
	char ascii_long_2[ULONG_MAX_CHAR + 1];
	ushort_t min;
	ushort_t max;

	switch (rcode) {
	case DSYM_SUCCESS:
		break;
	case DSYM_SYNTAX_ERROR:
		throw_exception(env,
		    dsym_exception, DSYM_SYNTAX_EX, 1, fields[field]);
		break;
	case DSYM_CODE_OUT_OF_RANGE:
		(void) dsym_get_code_ranges(fields[DSYM_CAT_FIELD],
		    &min, &max, B_TRUE);
		(void) sprintf(ascii_long_1, "%d", min);
		(void) sprintf(ascii_long_2, "%d", max);
		throw_exception(env, dsym_exception, DSYM_CODE_OUT_OF_RANGE_EX,
		    3, fields[DSYM_CAT_FIELD], ascii_long_1, ascii_long_2);
		break;
	case DSYM_VALUE_OUT_OF_RANGE:
		throw_exception(env, dsym_exception,
		    DSYM_VALUE_OUT_OF_RANGE_EX, 1, fields[field]);
		break;
	case DSYM_INVALID_CAT:
		throw_exception(env, dsym_exception,
		    DSYM_INVALID_CAT_EX, 1, fields[DSYM_CAT_FIELD]);
		break;
	case DSYM_INVALID_TYPE:
		throw_exception(env, dsym_exception,
		    DSYM_INVALID_TYPE_EX, 1, fields[DSYM_TYPE_FIELD]);
		break;
	case DSYM_EXCEEDS_CLASS_SIZE:
		(void) sprintf(ascii_long_1, "%d", DSYM_CLASS_SIZE);
		throw_exception(env, dsym_exception,
		    DSYM_EXCEEDS_CLASS_SIZE_EX, 1, ascii_long_1);
		break;
	case DSYM_EXCEEDS_MAX_CLASS_SIZE:
		(void) sprintf(ascii_long_1, "%d", DSYM_MAX_CLASS_SIZE);
		throw_exception(env, dsym_exception,
		    DSYM_EXCEEDS_MAX_CLASS_SIZE_EX, 1, ascii_long_1);
		break;
	case DSYM_NO_MEMORY:
		throw_exception(env, dsym_exception, DSYM_NO_MEMORY_EX, 0);
		break;
	default:
		throw_exception(env, dsym_exception, DSYM_INTERNAL_EX, 0);
	}
}

/* Throw a symbol init parsing error */
void
throw_dsym_parser_init_exception(JNIEnv *env, const char *key,
    dsym_errcode_t rcode)
{
	const char *dsym_exception  = "com/sun/dhcpmgr/bridge/DsymException";

	switch (rcode) {
	case DSYM_SUCCESS:
		break;
	case DSYM_NULL_FIELD:
		throw_exception(env,
		    dsym_exception, DSYM_TOO_FEW_FIELDS_EX, 1, key);
		break;
	case DSYM_TOO_MANY_FIELDS:
		throw_exception(env,
		    dsym_exception, DSYM_TOO_MANY_FIELDS_EX, 1, key);
		break;
	case DSYM_NO_MEMORY:
		throw_exception(env, dsym_exception, DSYM_NO_MEMORY_EX, 0);
		break;
	default:
		throw_exception(env, dsym_exception, DSYM_INTERNAL_EX, 0);
	}
}

/* Throw an exception indicating an error in wordexp */
void
throw_wordexp_exception(JNIEnv *env, int code)
{
	char buf[UINT64_MAX_CHAR + 1];

	(void) snprintf(buf, sizeof (buf), "%d", code);
	throw_exception(env, "com/sun/dhcpmgr/bridge/WordexpException",
	    NULL, 1, buf);
}
