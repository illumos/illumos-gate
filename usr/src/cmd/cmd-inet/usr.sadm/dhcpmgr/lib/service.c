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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <wordexp.h>
#include <string.h>
#include <malloc.h>
#include <sys/signal.h>
#include <libintl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dhcp_svc_private.h>
#include <dhcp_svc_confkey.h>
#include <jni.h>
#include <libscf.h>
#include <com_sun_dhcpmgr_bridge_Bridge.h>

#include "exception.h"
#include "dd_misc.h"
#include "class_cache.h"

#define	DHCP_SERVER_INST	"svc:/network/dhcp-server:default"

#define	DHCPD_FNAME	"in.dhcpd"
#define	CONFOPT_MODE	0644

/*
 * Gets called when the library is loaded.
 */
/*ARGSUSED*/
JNIEXPORT jint JNICALL
JNI_OnLoad(
    JavaVM *jvm,
    void *reserved)
{
	JNIEnv *env;

	if ((*jvm)->GetEnv(jvm, (void**)&env, JNI_VERSION_1_2)) {
		return (JNI_ERR);
	}

	init_class_cache();
	return (JNI_VERSION_1_2);
}

/*
 * Determine whether an upgrade of the datastore is necessary.
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_isVersionCurrent(
    JNIEnv *env,
    jobject obj)
{
	dsvc_datastore_t datastore;
	int cfgVersion;
	int curVersion;
	int rcode;
	jboolean result = JNI_FALSE;

	/* Get the data store configuration */
	if (dd_get_conf_datastore_t(env, &datastore)) {
		cfgVersion = datastore.d_conver;

		datastore.d_conver = DSVC_CUR_CONVER;
		free(datastore.d_location);
		datastore.d_location = NULL;
		rcode = status_dd(&datastore);
		if (rcode != DSVC_SUCCESS) {
			throw_libdhcpsvc_exception(env, rcode);
		} else {
			curVersion = datastore.d_conver;

			if (curVersion == cfgVersion) {
				result = JNI_TRUE;
			}
		}
		dd_free_datastore_t(&datastore);
	}

	return (result);
}

/*
 * Retrieve the data store object for the specified resource.
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getDataStore(
    JNIEnv *env,
    jobject obj,
    jstring jresource)
{
	jclass ds_class;
	jmethodID ds_cons;
	jobject dsObject;
	jboolean avail;
	jint version;
	dsvc_datastore_t datastore;
	char *resource;

	/* Make sure we have the classes & methods we need */
	ds_class = find_class(env, DS_CLASS);
	if (ds_class == NULL) {
		/* exception thrown */
		return (NULL);
	}
	ds_cons = get_methodID(env, ds_class, DS_CONS);
	if (ds_cons == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Retrieve the resource argument */
	if (!dd_jstring_to_UTF(env, jresource, &resource)) {
		/* exception thrown */
		return (NULL);
	}

	datastore.d_conver = DSVC_CUR_CONVER;
	datastore.d_resource = resource;
	datastore.d_location = NULL;
	avail = JNI_FALSE;
	if (status_dd(&datastore) == DSVC_SUCCESS) {
		avail = JNI_TRUE;
		version = datastore.d_conver;
	}

	dsObject = (*env)->NewObject(env, ds_class, ds_cons,
	    jresource, version, avail);

	free(resource);
	return (dsObject);
}

/*
 * Retrieve the list of data stores available for DHCP.  Returns an array of
 * DHCP datastore names.
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getDataStores(
    JNIEnv *env,
    jobject obj)
{
	jclass ds_class;
	jmethodID ds_cons;
	jobjectArray jlist = NULL;
	jobject jobj;
	jstring jstr;
	jboolean avail;
	jint version;
	char **list;
	dsvc_datastore_t datastore;
	int i, len;

	/* Make sure we have the classes & methods we need */
	ds_class = find_class(env, DS_CLASS);
	if (ds_class == NULL) {
		/* exception thrown */
		return (NULL);
	}
	ds_cons = get_methodID(env, ds_class, DS_CONS);
	if (ds_cons == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Get the list */
	list = dd_data_stores(env);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		return (NULL);
	}

	/* Compute the length of the array, store in len */
	ARRAY_LENGTH(list, len);

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, len, ds_class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		dd_free_data_stores(list);
		return (NULL);
	}

	/* For each store, create an object and add it to the array */
	for (i = 0; i < len; ++i) {

		jstr = (*env)->NewStringUTF(env, list[i]);
		if (jstr == NULL) {
			/* exception thrown */
			break;
		}

		datastore.d_conver = DSVC_CUR_CONVER;
		datastore.d_resource = list[i];
		datastore.d_location = NULL;
		avail = JNI_FALSE;
		if (status_dd(&datastore) == DSVC_SUCCESS) {
			avail = JNI_TRUE;
			version = datastore.d_conver;
		}

		jobj = (*env)->NewObject(env, ds_class, ds_cons,
		    jstr, version, avail);
		if (jobj == NULL) {
			/* exception thrown */
			break;
		}

		(*env)->SetObjectArrayElement(env, jlist, i, jobj);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			break;
		}
	}

	dd_free_data_stores(list);
	return (jlist);
}

/*
 * Read the config file for DHCP and return its contents as a DhcpdOptions
 * object.
 */
/*ARGSUSED*/
JNIEXPORT jobject JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_readDefaults(
    JNIEnv *env,
    jobject obj)
{
	jclass cfg_class;
	jmethodID cfg_cons;
	jmethodID cfg_set;
	jobject cfgobj = NULL;
	dhcp_confopt_t *cfgs, *tcfgs;

	/* Make sure we have the classes & methods we need */
	cfg_class = find_class(env, CFG_CLASS);
	if (cfg_class == NULL) {
		/* exception thrown */
		return (NULL);
	}
	cfg_cons = get_methodID(env, cfg_class, CFG_CONS);
	if (cfg_cons == NULL) {
		/* exception thrown */
		return (NULL);
	}
	cfg_set = get_methodID(env, cfg_class, CFG_SET);
	if (cfg_set == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Get the data */
	if (read_dsvc_conf(&cfgs) != 0) {
		throw_bridge_exception(env, strerror(errno));
	} else {
		/* Construct returned options object */
		cfgobj = (*env)->NewObject(env, cfg_class, cfg_cons);
		if (cfgobj == NULL) {
			/* exception thrown */
			free_dsvc_conf(cfgs);
			return (NULL);
		}

		/* Load the option settings into the options object */
		tcfgs = cfgs;
		for (;;) {
			if (cfgs->co_type == DHCP_COMMENT) {
				(*env)->CallVoidMethod(env, cfgobj, cfg_set,
				    (*env)->NewStringUTF(env, cfgs->co_key),
				    (*env)->NewStringUTF(env, ""), JNI_TRUE);
			} else {
				if (cfgs->co_key == NULL) {
					break;
				}
				(*env)->CallVoidMethod(env, cfgobj, cfg_set,
				    (*env)->NewStringUTF(env, cfgs->co_key),
				    (*env)->NewStringUTF(env, cfgs->co_value),
				    JNI_FALSE);
			}
			if ((*env)->ExceptionOccurred(env) != NULL) {
				free_dsvc_conf(tcfgs);
				return (NULL);
			}
			++cfgs;
		}
		free_dsvc_conf(tcfgs);
	}
	return (cfgobj);
}

/*
 * Write the DHCP config file.  Takes a DhcpdOptions object as input
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_writeDefaults(
    JNIEnv *env,
    jobject obj,
    jobject jcfgs)
{
	jclass cfg_class;
	jmethodID cfg_getall;
	jclass res_class;
	jmethodID res_getkey;
	jmethodID res_getval;
	jmethodID res_iscom;
	jobjectArray resArray;
	jsize reslen;
	jobject jobj, resobj;
	dhcp_confopt_t *cfgs;
	int i;
	jboolean comment;
	const char *tmpstr;

	/* Make sure we can get at the classes we need */
	cfg_class = find_class(env, CFG_CLASS);
	if (cfg_class == NULL) {
		/* exception thrown */
		return;
	}
	cfg_getall = get_methodID(env, cfg_class, CFG_GETALL);
	if (cfg_getall == NULL) {
		/* exception thrown */
		return;
	}
	res_class = find_class(env, RES_CLASS);
	if (res_class == NULL) {
		/* exception thrown */
		return;
	}
	res_getkey = get_methodID(env, res_class, RES_GETKEY);
	res_getval = get_methodID(env, res_class, RES_GETVAL);
	res_iscom = get_methodID(env, res_class, RES_ISCOM);
	if (res_getkey == NULL || res_getval == NULL || res_iscom == NULL) {
		/* exception thrown */
		return;
	}

	/* Get the resource array from the config object */
	resArray = (*env)->CallObjectMethod(env, jcfgs, cfg_getall);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		return;
	}
	reslen = (*env)->GetArrayLength(env, resArray);
	/* Allocate array to convert into; extra zero'd item to signal end */
	cfgs = calloc(reslen+1, sizeof (dhcp_confopt_t));
	if (cfgs == NULL) {
		throw_memory_exception(env);
		return;
	}

	/* Now copy data into local array */
	for (i = 0; i < reslen; ++i) {
		jobj = (*env)->GetObjectArrayElement(env, resArray, i);
		if (jobj == NULL) {
			/* exception thrown */
			free_dsvc_conf(cfgs);
			return;
		}
		/* Set record type */
		comment = (*env)->CallBooleanMethod(env, jobj, res_iscom);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			return;
		}
		if (comment == JNI_TRUE) {
			cfgs[i].co_type = DHCP_COMMENT;
		} else {
			cfgs[i].co_type = DHCP_KEY;
		}
		/*
		 * Get the key from the object, convert to a char *,
		 * and then duplicate into the cfgs array so that
		 * free_dsvc_conf can be used correctly.
		 * Do the same thing for the value.
		 */
		resobj = (*env)->CallObjectMethod(env, jobj, res_getkey);
		tmpstr = (*env)->GetStringUTFChars(env, resobj, NULL);
		if (tmpstr == NULL) {
			/* exception thrown */
			free_dsvc_conf(cfgs);
			throw_bridge_exception(env,
			    gettext("Error converting key"));
			return;
		}
		cfgs[i].co_key = strdup(tmpstr);
		(*env)->ReleaseStringUTFChars(env, resobj, tmpstr);
		if (cfgs[i].co_key == NULL) {
			/* Out of memory, fail */
			free_dsvc_conf(cfgs);
			throw_memory_exception(env);
			return;
		}
		resobj = (*env)->CallObjectMethod(env, jobj, res_getval);
		tmpstr = (*env)->GetStringUTFChars(env, resobj, NULL);
		if (tmpstr == NULL) {
			free_dsvc_conf(cfgs);
			throw_bridge_exception(env,
			    gettext("Error converting value"));
			return;
		}
		cfgs[i].co_value = strdup(tmpstr);
		(*env)->ReleaseStringUTFChars(env, resobj, tmpstr);
		if (cfgs[i].co_value == NULL) {
			/* Out of memory, fail */
			free_dsvc_conf(cfgs);
			throw_memory_exception(env);
			return;
		}
	}

	/* Now write the new data */
	if (write_dsvc_conf(cfgs, CONFOPT_MODE) != 0) {
		throw_bridge_exception(env, strerror(errno));
	}
	free_dsvc_conf(cfgs);
}

/*
 * Remove the DHCP config file
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_removeDefaults(
    JNIEnv *env,
    jobject obj)
{
	if (delete_dsvc_conf() != 0) {
		throw_bridge_exception(env, strerror(errno));
	}
}

/*
 * Start up the daemon.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_startup(
    JNIEnv *env,
    jobject obj)
{
	char *s;
	int ret;

	/*
	 * We first get the current state of the server according to
	 * svc.startd; if it's "disabled", we can just enable it.
	 * In any other case, we want to send a refresh so that
	 * dependencies are re-evaluated, which will be the case if the
	 * service was marked enabled by the profile, yet the
	 * config file didn't exist to allow it to run.
	 */
	if ((s = smf_get_state(DHCP_SERVER_INST)) != NULL) {
		if (strcmp(SCF_STATE_STRING_DISABLED, s) == 0)
			ret = smf_enable_instance(DHCP_SERVER_INST, 0);
		else
			ret = smf_refresh_instance(DHCP_SERVER_INST);
		free(s);
		if (ret == 0)
			return;
	}

	/* Something wasn't right, return exception with error from smf */
	throw_bridge_exception(env, scf_strerror(scf_error()));
}

/*
 * Shut down the daemon.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_shutdown(
    JNIEnv *env,
    jobject obj)
{
	if (smf_disable_instance(DHCP_SERVER_INST, 0) != 0) {
		throw_bridge_exception(env, scf_strerror(scf_error()));
	}
}

/*
 * Tell the daemon to re-read the dhcptab.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_reload(
    JNIEnv *env,
    jobject obj)
{
	int err;

	if ((err = dd_signal(DHCPD_FNAME, SIGHUP)) != 0) {
		if (err == -1) {
			/* dd_signal couldn't find in.dhcpd running */
			throw_not_running_exception(env);
		} else {
			throw_bridge_exception(env, strerror(err));
		}
	}
}

/*
 * Make the resource location.
 */
/*ARGSUSED*/
JNIEXPORT void JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_makeLocation(
    JNIEnv *env,
    jobject obj,
    jobject jdatastore)
{
	dsvc_datastore_t datastore;
	int rcode;

	/* Create a dsvc_datastore_t using args and DHCP config file */
	if (!dd_make_datastore_t(env, &datastore, jdatastore)) {
		/* exception thrown */
		return;
	}

	/* If the location does not already exist, go create it. */
	if (status_dd(&datastore) != DSVC_SUCCESS) {
		rcode = mklocation_dd(&datastore);
		if (rcode != DSVC_SUCCESS) {
			throw_libdhcpsvc_exception(env, rcode);
		}
	}

	dd_free_datastore_t(&datastore);
}

/*
 * Check if the server is running; returns true if so, false if not.
 */
/*ARGSUSED*/
JNIEXPORT jboolean JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_isServerRunning(
    JNIEnv *env,
    jobject obj)
{
	if (dd_getpid(DAEMON_FNAME) != (pid_t)-1) {
		return (JNI_TRUE);
	} else {
		return (JNI_FALSE);
	}
}

/*
 * Retrieve the list of interfaces on the system which are candidates for
 * use by the DHCP daemon.  Returns an array of IPInterface objects.
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getInterfaces(
    JNIEnv *env,
    jobject obj)
{
	jclass ipif_class;
	jmethodID ipif_cons;
	jobjectArray jlist = NULL;
	jobject jobj;
	jsize len;
	struct ip_interface **list;
	int i;

	/* Locate the class and constructor we need */
	ipif_class = find_class(env, IPIF_CLASS);
	if (ipif_class == NULL) {
		/* exception thrown */
		return (NULL);
	}
	ipif_cons = get_methodID(env, ipif_class, IPIF_CONS);
	if (ipif_cons == NULL) {
		return (NULL);
	}

	/* Retrieve interface list */
	list = dd_get_interfaces();
	if (list == NULL) {
		throw_bridge_exception(env,
		    gettext("Error in dd_get_interfaces"));
		return (NULL);
	}
	/* Compute length of list */
	ARRAY_LENGTH(list, len);

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, len, ipif_class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		for (i = 0; i < len; i++) {
			free(list[i]);
		}
		free(list);
		return (NULL);
	}

	/* For each interface, construct an object and add to the array */
	for (i = 0; i < len; ++i) {
		jobj = (*env)->NewObject(env, ipif_class, ipif_cons,
		    (*env)->NewStringUTF(env, list[i]->name),
		    (*env)->NewStringUTF(env, inet_ntoa(list[i]->addr)),
		    (*env)->NewStringUTF(env, inet_ntoa(list[i]->mask)));

		if (jobj == NULL) {
			/* exception thrown */
			break;
		}

		(*env)->SetObjectArrayElement(env, jlist, i, jobj);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			break;
		}
	}

	for (i = 0; i < len; i++) {
		free(list[i]);
	}
	free(list);

	return (jlist);
}

/*
 * Parse a line into arguments.
 */
/*ARGSUSED*/
JNIEXPORT jobjectArray JNICALL
Java_com_sun_dhcpmgr_bridge_Bridge_getArguments(
    JNIEnv *env,
    jobject obj,
    jstring jline)
{
	wordexp_t exp;
	int flags = WRDE_NOCMD;
	char *line;
	jclass str_class;
	jobjectArray jlist = NULL;
	jstring jarg;
	int i, ret;

	/* Go ahead and get the class for a String class */
	str_class = (*env)->GetObjectClass(env, jline);
	if (str_class == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Retrieve the line argument */
	if (jline != NULL &&
	    (line = dd_jstring_to_native(env, jline)) == NULL) {
		/* exception thrown */
		return (NULL);
	}

	/* Retrieve argument list */
	ret = wordexp(line, &exp, flags);
	free(line);
	if (ret != 0) {
		throw_wordexp_exception(env, ret);
		/* Free memory for the one error case where it's allocated */
		if (ret == WRDE_NOSPACE)
			wordfree(&exp);
		return (NULL);
	}

	/* Construct the array */
	jlist = (*env)->NewObjectArray(env, exp.we_wordc, str_class, NULL);
	if (jlist == NULL) {
		/* exception thrown */
		wordfree(&exp);
		return (NULL);
	}

	/* For each argument, create an object and add it to the array */
	for (i = 0; i < exp.we_wordc; i++) {
		jarg = dd_native_to_jstring(env, exp.we_wordv[i]);
		if (jarg == NULL) {
			/* exception thrown */
			break;
		}

		(*env)->SetObjectArrayElement(env, jlist, i, jarg);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			break;
		}
	}

	wordfree(&exp);
	return (jlist);
}
