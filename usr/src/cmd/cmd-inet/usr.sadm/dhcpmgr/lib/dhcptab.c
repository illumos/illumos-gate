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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <jni.h>
#include <dhcp_svc_private.h>
#include <dhcp_svc_confkey.h>
#include <dhcp_symbol.h>
#include <com_sun_dhcpmgr_bridge_Bridge.h>

#include "exception.h"
#include "dd_misc.h"
#include "class_cache.h"

/*
 * Validate that a symbol definition in dhcptab(4) format is valid.
 */
static boolean_t
validate_OptionValue(JNIEnv *env,
    const char *key,
    const char *value) {

	dhcp_symbol_t sym;
	char **fields;
	int last = 0;
	dsym_errcode_t dsymret;

	dsymret = dsym_init_parser(key, value, &fields, &sym);
	if (dsymret != DSYM_SUCCESS) {
		throw_dsym_parser_init_exception(env, key, dsymret);
		return (B_FALSE);
	}

	dsymret = dsym_parser(fields, &sym, &last, B_FALSE);
	if (dsymret != DSYM_SUCCESS) {
		throw_dsym_parser_exception(env, key, fields, last,
			dsymret);
	}

	dsym_close_parser(fields, &sym);
	return (dsymret == DSYM_SUCCESS);
}

/*
 * Create a dt_rec from a DhcptabRecord.
 */
static dt_rec_t *
create_dtrec(
    JNIEnv *env,
    jobject dhcptabRecord,
    boolean_t validate)
{
	jclass dtr_class;
	dt_rec_t *dtrec;
	char *str;

	/* Locate the class we need */
	dtr_class = find_class(env, DTR_CLASS);
	if (dtr_class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	dtrec = malloc(sizeof (dt_rec_t));
	if (dtrec == NULL) {
		throw_memory_exception(env);
		return (NULL);
	}

	if (!dd_get_str_attr(env, dtr_class, DTR_GETKEY, dhcptabRecord,
		&str)) {
		/* exception thrown */
		free_dtrec(dtrec);
		return (NULL);
	}
	(void) strlcpy(dtrec->dt_key, str, sizeof (dtrec->dt_key));
	free(str);

	if (!dd_get_str_attr(env, dtr_class, DTR_GETFLAG, dhcptabRecord,
		&str)) {
		/* exception thrown */
		free_dtrec(dtrec);
		return (NULL);
	}
	dtrec->dt_type = str[0];
	free(str);

	if (!dd_get_str_attr(env, dtr_class, DTR_GETSIG, dhcptabRecord,
		&str)) {
		/* exception thrown */
		free_dtrec(dtrec);
		return (NULL);
	}
	dtrec->dt_sig = atoll(str);
	free(str);

	if (!dd_get_str_attr(env, dtr_class, DTR_GETVAL, dhcptabRecord,
		&dtrec->dt_value)) {
		/* exception thrown */
		free_dtrec(dtrec);
		return (NULL);
	}

	if (validate) {
		if (dtrec->dt_type == DT_SYMBOL) {
			if (!validate_OptionValue(env, dtrec->dt_key,
			    dtrec->dt_value)) {
				/* exception thrown */
				free_dtrec(dtrec);
				return (NULL);
			}
		}
	}
	return (dtrec);
}

/*
 * Create a Macro from a dt_rec.
 */
static jobject
create_Macro(
    JNIEnv *env,
    const dt_rec_t *dtrec)
{
	jobject dhcptabRecord;
	jclass class;
	jmethodID cons;

	char ascii_sig[UINT64_MAX_CHAR + 1];

	/* Find the class we need */
	class = find_class(env, MAC_CLASS);
	if (class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Locate the class constructor we need */
	cons = get_methodID(env, class, MAC_CONS);
	if (cons == NULL) {
		/* exception thrown */
		return (NULL);
	}

	(void) sprintf(ascii_sig, "%lld", dtrec->dt_sig);
	dhcptabRecord = (*env)->NewObject(env, class, cons,
		(*env)->NewStringUTF(env, dtrec->dt_key),
		(*env)->NewStringUTF(env, dtrec->dt_value),
		(*env)->NewStringUTF(env, ascii_sig));

	if ((*env)->ExceptionOccurred(env) != NULL) {
		dhcptabRecord = NULL;
	}

	return (dhcptabRecord);
}

/*
 * Create an Array of vendor classes.
 */
static jobjectArray
create_vendors(JNIEnv *env,
    dhcp_classes_t *classes) {

	jclass class;
	jobjectArray jlist = NULL;
	int i;

	class = (*env)->FindClass(env, "java/lang/String");
	if (class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, classes->dc_cnt, class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* For each vendor, create an object and add it to the array */
	for (i = 0; i < classes->dc_cnt; i++) {
		(*env)->SetObjectArrayElement(env, jlist, i,
			    (*env)->NewStringUTF(env, classes->dc_names[i]));
		if ((*env)->ExceptionOccurred(env) != NULL) {
			jlist = NULL;
			break;
		}
	}
	return (jlist);
}

/*
 * Create an Option from a dt_rec.
 */
static jobject
create_Option(
    JNIEnv *env,
    const char *key,
    const char *value,
    uint64_t sig,
    boolean_t force)
{
	jobject dhcptabRecord = NULL;
	jclass class;
	jmethodID cons;

	char ascii_sig[UINT64_MAX_CHAR + 1];

	dhcp_symbol_t sym;
	char **fields;
	int last = 0;
	dsym_errcode_t ret = DSYM_SUCCESS;

	/* Find the class we need */
	class = find_class(env, OPT_CLASS);
	if (class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Locate the class constructor we need */
	cons = get_methodID(env, class, OPT_CONS);
	if (cons == NULL) {
		/* exception thrown */
		return (NULL);
	}

	(void) sprintf(ascii_sig, "%lld", sig);

	ret = dsym_init_parser(key, value, &fields, &sym);
	if (ret != DSYM_SUCCESS) {
		/* throw exception */
		throw_dsym_parser_init_exception(env, key, ret);
		return (NULL);
	}

	ret = dsym_parser(fields, &sym, &last, force);
	if (ret == DSYM_SUCCESS || force) {
		jboolean isValid = (ret == DSYM_SUCCESS) ? JNI_TRUE : JNI_FALSE;
		dhcptabRecord = (*env)->NewObject(env, class, cons,
		    (*env)->NewStringUTF(env, sym.ds_name),
		    (jbyte)sym.ds_category,
		    create_vendors(env, &sym.ds_classes),
		    (jshort)sym.ds_code,
		    (jbyte)sym.ds_type,
		    (jint)sym.ds_gran,
		    (jint)sym.ds_max,
		    (*env)->NewStringUTF(env, ascii_sig), isValid);

		if ((*env)->ExceptionOccurred(env) != NULL) {
			dhcptabRecord = NULL;
		}
	} else {
		/* throw exception */
		throw_dsym_parser_exception(env, key, fields, last, ret);
	}

	dsym_close_parser(fields, &sym);
	return (dhcptabRecord);
}

/*
 * Retrieve an option from the dhcptab.  Returns
 * the record as a new instance of a Option
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getOption(
    JNIEnv *env,
    jobject obj,
    jstring jkey,
    jobject jdatastore)
{
	dsvc_datastore_t datastore;
	dsvc_handle_t handle;

	dt_rec_t record;
	dt_rec_list_t *recordList;
	uint32_t query;
	uint32_t count = 0;

	char *key;
	int rcode;

	jobject dhcptabRecord;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return (NULL);
	}

	/* Retrieve the key argument */
	if (!dd_jstring_to_UTF(env, jkey, &key)) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return (NULL);
	}

	/* Open the dhcptab */
	rcode = open_dd(&handle, &datastore, DSVC_DHCPTAB,
		DT_DHCPTAB, DSVC_READ);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
		free(key);
		return (NULL);
	}

	/* Get the records */
	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QTYPE | DT_QKEY);
	(void) strlcpy(record.dt_key, key, sizeof (record.dt_key));
	record.dt_type = DT_SYMBOL;

	rcode = lookup_dd(handle, B_FALSE, query, 1, &record,
			(void**)&recordList, &count);

	(void) close_dd(&handle);
	if (rcode == DSVC_SUCCESS) {
		if (count == 1) {
			dhcptabRecord = create_Option(env,
			    recordList->dtl_rec->dt_key,
			    recordList->dtl_rec->dt_value,
			    recordList->dtl_rec->dt_sig, B_TRUE);
			free_dtrec_list(recordList);
		} else {
			throw_noent_exception(env, key);
		}
	} else {
		throw_libdhcpsvc_exception(env, rcode);
	}

	free(key);

	return (dhcptabRecord);
}

/*
 * Use the current datastore to create a dhcptab table in a new datastore.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_cvtDhcptab(
    JNIEnv *env,
    jobject obj,
    jobject jdatastore)
{

	dt_rec_t record;
	dt_rec_list_t *recordList;
	dt_rec_list_t *originalList = NULL;
	uint32_t query;
	uint32_t count = 0;

	dsvc_handle_t curHandle;
	dsvc_handle_t newHandle;
	dsvc_datastore_t curDatastore;
	dsvc_datastore_t newDatastore;

	int rcode;
	int i;

	/* Get the current data store configuration */
	if (!dd_get_conf_datastore_t(env, &curDatastore)) {
		/* exception thrown */
		return;
	}

	/* Make a "new" dsvc_datastore_t */
	if (!dd_make_datastore_t(env, &newDatastore, jdatastore)) {
		/* exception thrown */
		dd_free_datastore_t(&curDatastore);
		return;
	}

	/* Open the current dhcptab */
	rcode = open_dd(&curHandle, &curDatastore, DSVC_DHCPTAB,
		DT_DHCPTAB, DSVC_READ);

	dd_free_datastore_t(&curDatastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
		dd_free_datastore_t(&newDatastore);
		return;
	}

	/* Open the new dhcptab */
	rcode = open_dd(&newHandle, &newDatastore, DSVC_DHCPTAB, DT_DHCPTAB,
		DSVC_CREATE | DSVC_READ | DSVC_WRITE);

	dd_free_datastore_t(&newDatastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
		(void) close_dd(&curHandle);
		return;
	}

	/* Get the records */
	DSVC_QINIT(query);
	rcode = lookup_dd(curHandle, B_FALSE, query, -1, &record,
			(void**)&recordList, &count);

	(void) close_dd(&curHandle);
	if (rcode != DSVC_SUCCESS) {
		throw_libdhcpsvc_exception(env, rcode);
		(void) close_dd(&newHandle);
		return;
	}

	if (count != 0) {
		originalList = recordList;
	}

	/* For each row, write client record to new table */
	for (i = 0; i < count; i++) {
		/* Now add the record */
		rcode = add_dd_entry(newHandle, recordList->dtl_rec);

		if (rcode != DSVC_SUCCESS) {
			throw_add_dd_entry_exception(env, rcode,
				recordList->dtl_rec->dt_key);
			break;
		}

		recordList = recordList->dtl_next;
	}

	(void) close_dd(&newHandle);

	if (originalList != NULL) {
		free_dtrec_list(originalList);
	}

}

/*
 * Return all options (aka symbols) currently defined in the dhcptab.
 * The options are returned as an array of Options.
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getOptions(
    JNIEnv *env,
    jobject obj,
    jobject jdatastore)
{
	dsvc_datastore_t datastore;
	dsvc_handle_t handle;

	dt_rec_t record;
	dt_rec_list_t *recordList;
	dt_rec_list_t *originalList = NULL;
	uint32_t query;
	uint32_t count = 0;
	int rcode;

	jclass opt_class;
	jobjectArray jlist = NULL;
	jobject dhcptabRecord;
	int i;

	/* Find the Option class and its constructor */
	opt_class = find_class(env, OPT_CLASS);
	if (opt_class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return (NULL);
	}

	/* Open the dhcptab */
	rcode = open_dd(&handle, &datastore, DSVC_DHCPTAB,
		DT_DHCPTAB, DSVC_READ);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
		return (NULL);
	}

	/* Get the records */
	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QTYPE);
	record.dt_type = DT_SYMBOL;

	rcode = lookup_dd(handle, B_FALSE, query, -1, &record,
			(void**)&recordList, &count);

	(void) close_dd(&handle);
	if (rcode != DSVC_SUCCESS) {
		throw_libdhcpsvc_exception(env, rcode);
		return (NULL);
	}

	if (count != 0) {
		originalList = recordList;
	}

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, count, opt_class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		if (originalList != NULL) {
			free_dtrec_list(originalList);
		}
		return (NULL);
	}

	/* For each option, create an object and add it to the array */
	for (i = 0; i < count; i++) {
		dhcptabRecord = create_Option(env,
		    recordList->dtl_rec->dt_key,
		    recordList->dtl_rec->dt_value,
		    recordList->dtl_rec->dt_sig, B_TRUE);
		if (dhcptabRecord == NULL) {
			/* exception thrown */
			break;
		}

		(*env)->SetObjectArrayElement(env, jlist, i, dhcptabRecord);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			break;
		}

		recordList = recordList->dtl_next;
	}

	if (originalList != NULL) {
		free_dtrec_list(originalList);
	}

	return (jlist);
}

/*
 * Retrieve a macro from the dhcptab.  Returns
 * the record as a new instance of a Macro
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getMacro(
    JNIEnv *env,
    jobject obj,
    jstring jkey,
    jobject jdatastore)
{
	dsvc_datastore_t datastore;
	dsvc_handle_t handle;

	dt_rec_t record;
	dt_rec_list_t *recordList;
	uint32_t query;
	uint32_t count = 0;

	char *key;
	int rcode;

	jobject dhcptabRecord;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return (NULL);
	}

	/* Retrieve the key argument */
	if (!dd_jstring_to_UTF(env, jkey, &key)) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return (NULL);
	}

	/* Open the dhcptab */
	rcode = open_dd(&handle, &datastore, DSVC_DHCPTAB,
		DT_DHCPTAB, DSVC_READ);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
		free(key);
		return (NULL);
	}

	/* Get the records */
	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QTYPE | DT_QKEY);
	(void) strlcpy(record.dt_key, key, sizeof (record.dt_key));
	record.dt_type = DT_MACRO;

	rcode = lookup_dd(handle, B_FALSE, query, 1, &record,
			(void**)&recordList, &count);

	(void) close_dd(&handle);
	if (rcode == DSVC_SUCCESS) {
		if (count == 1) {
			dhcptabRecord = create_Macro(env, recordList->dtl_rec);
			free_dtrec_list(recordList);
		} else {
			throw_noent_exception(env, key);
		}
	} else {
		throw_libdhcpsvc_exception(env, rcode);
	}

	free(key);

	return (dhcptabRecord);
}

/*
 * Return all macros defined in the dhcptab.  Returned as an array of
 * Macro objects.
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getMacros(
    JNIEnv *env,
    jobject obj,
    jobject jdatastore)
{
	dsvc_datastore_t datastore;
	dsvc_handle_t handle;

	dt_rec_t record;
	dt_rec_list_t *recordList;
	dt_rec_list_t *originalList = NULL;
	uint32_t query;
	uint32_t count = 0;
	int rcode;

	jclass mac_class;
	jobjectArray jlist = NULL;
	jobject dhcptabRecord;
	int i;

	/* Locate the Macro class and its constructor */
	mac_class = find_class(env, MAC_CLASS);
	if (mac_class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return (NULL);
	}

	/* Open the dhcptab */
	rcode = open_dd(&handle, &datastore, DSVC_DHCPTAB,
		DT_DHCPTAB, DSVC_READ);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
		return (NULL);
	}

	/* Get the records */
	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QTYPE);
	record.dt_type = DT_MACRO;

	rcode = lookup_dd(handle, B_FALSE, query, -1, &record,
			(void**)&recordList, &count);

	(void) close_dd(&handle);
	if (rcode != DSVC_SUCCESS) {
		throw_libdhcpsvc_exception(env, rcode);
		return (NULL);
	}

	if (count != 0) {
		originalList = recordList;
	}

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, count, mac_class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		if (originalList != NULL) {
			free_dtrec_list(originalList);
		}
		return (NULL);
	}

	/* For each macro, create an object and add it to the array */
	for (i = 0; i < count; i++) {
		dhcptabRecord = create_Macro(env, recordList->dtl_rec);
		if (dhcptabRecord == NULL) {
			/* exception thrown */
			break;
		}

		(*env)->SetObjectArrayElement(env, jlist, i, dhcptabRecord);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			break;
		}

		recordList = recordList->dtl_next;
	}

	if (originalList != NULL) {
		free_dtrec_list(originalList);
	}

	return (jlist);
}

/*
 * Function to create an Option object
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_createOption(
    JNIEnv *env,
    jobject obj,
    jstring jkey,
    jstring jvalue)
{

	jobject option;
	char *key;
	char *value;

	/* Retrieve the key argument */
	if (!dd_jstring_to_UTF(env, jkey, &key)) {
		/* exception thrown */
		return (NULL);
	}

	/* Retrieve the value argument */
	if (!dd_jstring_to_UTF(env, jvalue, &value)) {
		/* exception thrown */
		free(key);
		return (NULL);
	}

	option = create_Option(env, key, value, 0, B_FALSE);

	free(key);
	free(value);

	return (option);
}

/*
 * Function to create a new dhcptab record.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_createDhcptabRecord(
    JNIEnv *env,
    jobject obj,
    jobject jrec,
    jobject jdatastore)
{
	dsvc_handle_t handle;
	dsvc_datastore_t datastore;
	dt_rec_t *dtrec;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	dtrec = create_dtrec(env, jrec, B_TRUE);
	if (dtrec == NULL) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return;
	}

	/* Open the dhcptab */
	rcode = open_dd(&handle, &datastore, DSVC_DHCPTAB,
		DT_DHCPTAB, DSVC_WRITE);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
		free_dtrec(dtrec);
		return;
	}

	/* Now add the record */
	rcode = add_dd_entry(handle, dtrec);

	(void) close_dd(&handle);
	if (rcode != DSVC_SUCCESS) {
		throw_add_dd_entry_exception(env, rcode, dtrec->dt_key);
	}

	free_dtrec(dtrec);

}

/*
 * Modify a dhcptab record.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_modifyDhcptabRecord(
    JNIEnv *env,
    jobject obj,
    jobject joldrec,
    jobject jnewrec,
    jobject jdatastore)
{
	dsvc_handle_t handle;
	dsvc_datastore_t datastore;
	dt_rec_t *dtoldrec;
	dt_rec_t *dtnewrec;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	dtoldrec = create_dtrec(env, joldrec, B_FALSE);
	if (dtoldrec == NULL) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return;
	}

	dtnewrec = create_dtrec(env, jnewrec, B_TRUE);
	if (dtnewrec == NULL) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		free_dtrec(dtoldrec);
		return;
	}

	/* Open the dhcptab */
	rcode = open_dd(&handle, &datastore, DSVC_DHCPTAB,
		DT_DHCPTAB, DSVC_WRITE);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
		free_dtrec(dtoldrec);
		free_dtrec(dtnewrec);
		return;
	}

	/* Modify the record */
	rcode = modify_dd_entry(handle, dtoldrec, dtnewrec);

	(void) close_dd(&handle);
	if (rcode != DSVC_SUCCESS) {
		throw_modify_dd_entry_exception(env, rcode, dtoldrec->dt_key,
			dtnewrec->dt_key);
	}

	free_dtrec(dtnewrec);
	free_dtrec(dtoldrec);

}

/*
 * Delete a record from the dhcptab
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_deleteDhcptabRecord(
    JNIEnv *env,
    jobject obj,
    jobject jrec,
    jobject jdatastore)
{
	dsvc_handle_t handle;
	dsvc_datastore_t datastore;
	dt_rec_t *dtrec;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	dtrec = create_dtrec(env, jrec, B_FALSE);
	if (dtrec == NULL) {
		/* exception thrown */
		dd_free_datastore_t(&datastore);
		return;
	}

	/* Open the dhcptab */
	rcode = open_dd(&handle, &datastore, DSVC_DHCPTAB,
		DT_DHCPTAB, DSVC_WRITE);

	dd_free_datastore_t(&datastore);
	if (rcode != DSVC_SUCCESS) {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
		free_dtrec(dtrec);
		return;
	}

	/* Delete the record */
	rcode = delete_dd_entry(handle, dtrec);

	(void) close_dd(&handle);
	if (rcode != DSVC_SUCCESS) {
		throw_delete_dd_entry_exception(env, rcode, dtrec->dt_key);
	}

	free_dtrec(dtrec);
}

/*
 * Create the dhcptab.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_createDhcptab(
    JNIEnv *env,
    jobject obj,
    jobject jdatastore)
{
	dsvc_handle_t handle;
	dsvc_datastore_t datastore;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	/* Open the dhcptab and in the process create it */
	rcode = open_dd(&handle, &datastore, DSVC_DHCPTAB, DT_DHCPTAB,
		DSVC_CREATE | DSVC_READ | DSVC_WRITE);

	dd_free_datastore_t(&datastore);

	/*
	 * If open was successful, then close. Otherwise, if unsuccessful
	 * opening table, then map error to exception.
	 */
	if (rcode == DSVC_SUCCESS) {
		(void) close_dd(&handle);
	} else {
		throw_open_dd_exception(env, rcode, DT_DHCPTAB);
	}
}

/*
 * Delete the dhcptab.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_deleteDhcptab(
    JNIEnv *env,
    jobject obj,
    jobject jdatastore)
{
	dsvc_datastore_t datastore;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config settings */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	rcode = remove_dd(&datastore, DSVC_DHCPTAB, DT_DHCPTAB);

	if (rcode != DSVC_SUCCESS) {
		throw_remove_dd_exception(env, rcode, DT_DHCPTAB);
	}

	dd_free_datastore_t(&datastore);
}
