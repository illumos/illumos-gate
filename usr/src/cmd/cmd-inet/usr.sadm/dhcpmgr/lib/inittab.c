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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <jni.h>
#include <dhcp_inittab.h>
#include <dhcp_symbol.h>
#include <exception.h>
#include <com_sun_dhcpmgr_bridge_Bridge.h>
#include <dhcp_svc_private.h>

#include "class_cache.h"

/*
 * Retrieve a list of DHCP options from the dhcp inittab.
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getInittabOptions(
    JNIEnv *env,
    jobject obj,
    jbyte jcategory) {

	jclass opt_class;
	jmethodID opt_cons;
	jobjectArray jlist = NULL;
	jobject jobj;
	jstring jname;
	jshort jcode;
	jbyte jtype;
	jint jgran;
	jint jmax;

	uchar_t category;
	dhcp_symbol_t *entryptr;
	dhcp_symbol_t *list;
	dhcp_symbol_t internal;
	size_t num;
	int i;

	/* Make sure we have the classes & methods we need */
	opt_class = find_class(env, OPT_CLASS);
	if (opt_class == NULL) {
		/* exception thrown */
		return (NULL);
	}
	opt_cons = get_methodID(env, opt_class, OPT_CONS);
	if (opt_cons == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Translate the dhcpmgr category to the inittab category */
	if (jcategory == DSYM_STANDARD) {
		category = ITAB_CAT_STANDARD | ITAB_CAT_INTERNAL |
		    ITAB_CAT_FIELD;
	} else {
		category = jcategory;
	}

	/* Get the list of options */
	list = inittab_load(category, ITAB_CONS_MANAGER, &num);
	if (list == NULL) {
		return (NULL);
	}

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, num, opt_class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		free(list);
		return (NULL);
	}

	/* For each option, create an object and add it to the array */
	for (i = 0; i < num; ++i) {

		/* Verify the entry. Use the internal if necessary. */
		if (inittab_verify(&list[i], &internal) == ITAB_FAILURE) {
			entryptr = &internal;
		} else {
			entryptr = &list[i];
		}

		jtype = entryptr->ds_type;
		jname = (*env)->NewStringUTF(env, entryptr->ds_name);
		if (jname == NULL) {
			/* exception thrown */
			break;
		}

		/* HACK. Since the codes for fields can overlap the	*/
		/* codes for STANDARD options, we will just set the	*/
		/* code to zero and ignore the need for these codes to	*/
		/* be unique. We do the same for internal but not	*/
		/* for the same reason. For internal we have no need	*/
		/* for the actual code and since we expect them to	*/
		/* change in the future, we'll just go ahead and	*/
		/* set them to zero too.				*/
		if (entryptr->ds_category == DSYM_INTERNAL ||
		    entryptr->ds_category == DSYM_FIELD) {
			jcode = (jshort)0;
		} else {
			jcode = entryptr->ds_code;
		}

		jmax = entryptr->ds_max;
		jgran = entryptr->ds_gran;

		/* Create an 'Option' */
		jobj = (*env)->NewObject(env, opt_class, opt_cons, jname,
		    jcategory, NULL, jcode, jtype, jgran, jmax, NULL,
		    JNI_TRUE);
		if (jobj == NULL) {
			/* exception thrown */
			break;
		}

		(*env)->SetObjectArrayElement(env, jlist, i, jobj);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			break;
		}
	}

	free(list);

	return (jlist);
}
