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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <dhcp_svc_private.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <libintl.h>
#include <procfs.h>
#include <rpcsvc/nis.h>
#include <malloc.h>
#include <ctype.h>
#include <jni.h>

#include "exception.h"
#include "class_cache.h"
#include "dd_misc.h"

#define	PROCFS_DIR	"/proc"

/*
 * Frees the list of data store strings.
 */
static void
free_enumerated_dd(char **module, int count)
{
	while (count-- > 0) {
		free(module[count]);
	}
	free(module);
}

/*
 * Determines if a given data store name is valid.
 */
static boolean_t
dd_is_valid_data_store(JNIEnv *env, const char *name)
{
	char **module;
	int count;
	int ndx;
	int rcode;
	boolean_t isValid = B_FALSE;

	if (name != NULL) {
		rcode = enumerate_dd(&module, &count);
		if (rcode != DSVC_SUCCESS) {
			throw_libdhcpsvc_exception(env, rcode);
		} else {
			for (ndx = 0; !isValid && ndx < count; ndx++) {
				if (strcmp(module[ndx], name) == 0) {
					isValid = B_TRUE;
				}
			}
			free_enumerated_dd(module, count);
		}
	}
	return (isValid);
}

/*
 * Call a java object's int getter method.
 */
static boolean_t
dd_get_int_attr(
	JNIEnv *env,
	jclass class,
	int id,
	jobject obj,
	int *value) {

	jmethodID methodID;
	jint jval;
	boolean_t noException = B_TRUE;

	methodID = get_methodID(env, class, id);
	if (methodID == NULL) {
		noException = B_FALSE;
	} else {
		jval = (*env)->CallIntMethod(env, obj, methodID);
		if ((*env)->ExceptionOccurred(env) != NULL) {
			noException = B_FALSE;
		} else {
			*value = jval;
		}
	}
	return (noException);
}

/*
 * Convert a possibly multi-byte string to a jstring.
 */
jstring
dd_native_to_jstring(JNIEnv *env, const char *str)
{
	jstring result;
	jbyteArray bytes = 0;
	int len;

	jclass strclass;
	jmethodID mid;

	strclass = (*env)->FindClass(env, "java/lang/String");
	if (strclass == NULL) {
		/* exception thrown */
		return (NULL);
	}

	mid = (*env)->GetMethodID(env, strclass, "<init>", "([B)V");
	if (mid == NULL) {
		/* exception thrown */
		return (NULL);
	}

	len = strlen(str);
	bytes = (*env)->NewByteArray(env, len);
	if (bytes == NULL) {
		/* exception thrown */
		return (NULL);
	}

	(*env)->SetByteArrayRegion(env, bytes, 0, len, (jbyte *) str);
	result = (*env)->NewObject(env, strclass, mid, bytes);

	(*env)->DeleteLocalRef(env, bytes);
	return (result);
}

/*
 * Convert a jstring to a possibly multi-byte string.
 */
char *
dd_jstring_to_native(JNIEnv *env, jstring jstr) {

	jbyteArray bytes = 0;
	jint len;
	char *result;

	jclass strclass;
	jmethodID mid;

	strclass = (*env)->FindClass(env, "java/lang/String");
	if (strclass == NULL) {
		/* exception thrown */
		return (NULL);
	}

	mid = (*env)->GetMethodID(env, strclass, "getBytes", "()[B");
	if (mid == NULL) {
		/* exception thrown */
		return (NULL);
	}

	bytes = (*env)->CallObjectMethod(env, jstr, mid);
	if ((*env)->ExceptionOccurred(env)) {
		/* exception thrown */
		return (NULL);
	}

	len = (*env)->GetArrayLength(env, bytes);
	result = (char *)malloc(len + 1);
	if (result == NULL) {
		throw_memory_exception(env);
		(*env)->DeleteLocalRef(env, bytes);
		return (NULL);
	}

	(*env)->GetByteArrayRegion(env, bytes, 0, len, (jbyte *) result);
	result[len] = 0;

	(*env)->DeleteLocalRef(env, bytes);
	return (result);
}

/*
 * Convert a jstring to a UTF-8 string.
 */
boolean_t
dd_jstring_to_UTF(
	JNIEnv *env,
	jstring javaString,
	char **nativeString)
{
	boolean_t noException = B_TRUE;

	if (javaString != NULL) {
		const char *str;
		str = (*env)->GetStringUTFChars(env, javaString, NULL);
		if (str == NULL) {
			noException = B_FALSE;
		} else {
			*nativeString = strdup(str);
			(*env)->ReleaseStringUTFChars(env, javaString, str);
			if (*nativeString == NULL) {
				throw_memory_exception(env);
				noException = B_FALSE;
			}
		}
	} else {
		*nativeString = NULL;
	}

	return (noException);
}


/*
 * Call a java object's string getter method.
 */
boolean_t
dd_get_str_attr(
	JNIEnv *env,
	jclass class,
	int id,
	jobject obj,
	char **value) {

	jmethodID methodID;
	jstring jstr;

	*value = NULL;

	methodID = get_methodID(env, class, id);
	if (methodID == NULL) {
		return (B_FALSE);
	}

	jstr = (*env)->CallObjectMethod(env, obj, methodID);
	if ((*env)->ExceptionOccurred(env) != NULL) {
		return (B_FALSE);
	}

	if (jstr != NULL) {
		*value = dd_jstring_to_native(env, jstr);
		(*env)->DeleteLocalRef(env, jstr);
		if (*value == NULL) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * Reads the DHCP configuration file and creates a dsvc_datastore_t.
 */
boolean_t
dd_get_conf_datastore_t(JNIEnv *env, dsvc_datastore_t *dsp) {

	dhcp_confopt_t *confopts;
	int result;
	boolean_t noException = B_TRUE;

	dsp->d_resource = NULL;
	dsp->d_location = NULL;
	dsp->d_config = NULL;

	result = read_dsvc_conf(&confopts);
	if (result != 0) {
		throw_no_defaults_exception(env);
		noException = B_FALSE;
	} else {
		result = confopt_to_datastore(confopts, dsp);
		if (result != DSVC_SUCCESS) {
			throw_libdhcpsvc_exception(env, result);
			noException = B_FALSE;
		}
		free_dsvc_conf(confopts);
	}
	return (noException);
}

/*
 * Makes a dsvc_datastore_t using the DHCP configuration file and overriding
 * the settings with the arguments if they are non-NULL.
 */
boolean_t
dd_make_datastore_t(JNIEnv *env,
    dsvc_datastore_t *dsp,
    jobject jdatastore) {

	jclass ds_class;
	jthrowable e;

	char *resource = NULL;
	char *location = NULL;
	char *config = NULL;
	int version = DSVC_CUR_CONVER;

	dsp->d_resource = NULL;
	dsp->d_location = NULL;
	dsp->d_config = NULL;

	/* Locate the class we need */
	ds_class = find_class(env, DS_CLASS);
	if (ds_class == NULL) {
		/* exception thrown */
		return (B_FALSE);
	}

	/* Obtain the DHCP config file data store settings */
	if (!dd_get_conf_datastore_t(env, dsp)) {
		e = (*env)->ExceptionOccurred(env);
		(*env)->ExceptionClear(env);
		if (!is_no_defaults_exception(env, e)) {
			(*env)->Throw(env, e);
			return (B_FALSE);
		}
	}

	/* Get the resource */
	if (jdatastore != NULL && !dd_get_str_attr(env, ds_class, DS_GETRSRC,
	    jdatastore, &resource)) {
		/* exception thrown */
		dd_free_datastore_t(dsp);
		return (B_FALSE);
	}

	/* If resource was passed in, then override config setting */
	if (resource != NULL) {
		free(dsp->d_resource);
		dsp->d_resource = resource;
		dsp->d_conver = DSVC_CUR_CONVER;
	}

	/* Validate the resource */
	if (!dd_is_valid_data_store(env, dsp->d_resource)) {
		if ((*env)->ExceptionOccurred(env) == NULL) {
			throw_invalid_resource_exception(env, dsp->d_resource);
		}
		dd_free_datastore_t(dsp);
		return (B_FALSE);
	}

	/* Get the location */
	if (jdatastore != NULL && !dd_get_str_attr(env, ds_class, DS_GETLOC,
	    jdatastore, &location)) {
		/* exception thrown */
		dd_free_datastore_t(dsp);
		return (B_FALSE);
	}

	/* If location was passed in, then override config setting */
	if (location != NULL) {
		free(dsp->d_location);
		dsp->d_location = location;
	}

	/* Must be defined */
	if (dsp->d_location == NULL) {
		throw_invalid_path_exception(env, dsp->d_location);
		dd_free_datastore_t(dsp);
		return (B_FALSE);
	}

	/* Get the config string */
	if (jdatastore != NULL && !dd_get_str_attr(env, ds_class, DS_GETRSRCCFG,
	    jdatastore,	&config)) {
		/* exception thrown */
		dd_free_datastore_t(dsp);
		return (B_FALSE);
	}

	/* If config string was passed in, then override config setting */
	if (config != NULL) {
		free(dsp->d_config);
		dsp->d_config = config;
	}

	/* Get the version */
	if (jdatastore != NULL && !dd_get_int_attr(env, ds_class, DS_GETVER,
	    jdatastore,	&version)) {
		/* exception thrown */
		dd_free_datastore_t(dsp);
		return (B_FALSE);
	}

	/* If version was passed in, then override config setting */
	if (version != DSVC_CUR_CONVER) {
		dsp->d_conver = version;
	}

	return (B_TRUE);
}

/*
 * Frees the strings in a dsvc_datastore_t structure.
 */
void
dd_free_datastore_t(dsvc_datastore_t *dsp) {
	free(dsp->d_resource);
	free(dsp->d_location);
	free(dsp->d_config);
}

/*
 * Returns the list of possible data stores for DHCP data.
 * List returned is terminated with a NULL.
 */
char **
dd_data_stores(JNIEnv *env)
{
	char **dsl = NULL;
	char **module;
	int count;
	int ndx;
	int rcode;

	rcode = enumerate_dd(&module, &count);
	if (rcode != DSVC_SUCCESS) {
		throw_libdhcpsvc_exception(env, rcode);
		return (NULL);
	}

	if (count == 0) {
		return (NULL);
	}

	dsl = calloc((count + 1), sizeof (char *));
	if (dsl == NULL) {
		free_enumerated_dd(module, count);
		throw_memory_exception(env);
		return (NULL);
	}

	for (ndx = 0; ndx < count; ndx++) {
		dsl[ndx] = strdup(module[ndx]);
		if (dsl[ndx] == NULL) {
			break;
		}
	}

	free_enumerated_dd(module, count);

	if (ndx != count) {
		dd_free_data_stores(dsl);
		throw_memory_exception(env);
		dsl = NULL;
	}

	return (dsl);
}

/*
 * Free a data store list created by dd_data_stores().
 */
void
dd_free_data_stores(char **dsl)
{
	int i = 0;

	if (dsl != NULL) {
		for (i = 0; dsl[i] != NULL; ++i) {
			free(dsl[i]);
		}
		free(dsl);
	}
}

/*
 * Send a signal to a process whose command name is as specified
 */
int
dd_signal(char *fname, int sig)
{
	pid_t pid;

	pid = dd_getpid(fname);
	if (pid == (pid_t)-1) {
		return (-1);
	}

	if (kill(pid, sig) != 0) {
		return (errno);
	} else {
		return (0);
	}
}

/*
 * Return a process's pid
 */
pid_t
dd_getpid(char *fname)
{
	DIR *dirptr;
	dirent_t *direntptr;
	psinfo_t psinfo;
	int proc_fd;
	char buf[MAXPATHLEN];
	pid_t retval = (pid_t)-1;

	/*
	 * Read entries in /proc, each one is in turn a directory
	 * containing files relating to the process's state.  We read
	 * the psinfo file to get the command name.
	 */
	dirptr = opendir(PROCFS_DIR);
	if (dirptr == (DIR *) NULL) {
		return (retval);
	}
	while ((direntptr = readdir(dirptr)) != NULL) {
		(void) snprintf(buf, sizeof (buf), PROCFS_DIR"/%s/psinfo",
		    direntptr->d_name);
		if ((proc_fd = open(buf, O_RDONLY)) < 0) {
			continue;	/* skip this one */
		}
		if (read(proc_fd, &psinfo, sizeof (psinfo)) > 0) {
			if (strncmp(psinfo.pr_fname, fname, PRFNSZ) == 0) {
				retval = psinfo.pr_pid;
				(void) close(proc_fd);
				break;
			}
		}
		(void) close(proc_fd);
	}
	(void) closedir(dirptr);
	return (retval);
}


/*
 * Get list of physical, non-loopback interfaces for the system.  Those are
 * the ones in.dhcpd will support.
 */
struct ip_interface **
dd_get_interfaces()
{
	int s;
	struct ifconf ifc;
	int num_ifs;
	int i;
	struct ifreq *ifr;
	struct ip_interface **ret = NULL;
	struct ip_interface **tmpret;
	int retcnt = 0;
	struct sockaddr_in *sin;

	/*
	 * Open socket, needed for doing the ioctls.  Then get number of
	 * interfaces so we know how much memory to allocate, then get
	 * all the interface configurations.
	 */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (ioctl(s, SIOCGIFNUM, &num_ifs) < 0) {
		(void) close(s);
		return (NULL);
	}
	ifc.ifc_len = num_ifs * sizeof (struct ifreq);
	ifc.ifc_buf = malloc(ifc.ifc_len);
	if (ifc.ifc_buf == NULL) {
		(void) close(s);
		return (NULL);
	}
	if (ioctl(s, SIOCGIFCONF, &ifc) < 0) {
		free(ifc.ifc_buf);
		(void) close(s);
		return (NULL);
	}

	/*
	 * For each interface, stuff its name, address and netmask into the
	 * structure that we return.  Filter out loopback and virtual
	 * interfaces as they are of no interest for DHCP.
	 */
	for (i = 0, ifr = ifc.ifc_req; i < num_ifs; ++i, ++ifr) {
		if (strchr(ifr->ifr_name, ':') != NULL) {
			continue;	/* Ignore a virtual interface */
		}
		if (ioctl(s, SIOCGIFFLAGS, ifr) < 0) {
			continue;	/* Can't get flags? Ignore it. */
		}

		if ((ifr->ifr_flags & IFF_LOOPBACK) ||
		    !(ifr->ifr_flags & IFF_UP)) {
			continue;	/* Ignore if loopback or down */
		}
		/* Get more space to store this in */
		tmpret = realloc(ret,
		    (retcnt+1)*sizeof (struct ip_interface *));
		if (tmpret == NULL) {
			while (retcnt-- > 0)
				free(ret[retcnt]);
			free(ret);
			free(ifc.ifc_buf);
			(void) close(s);
			return (NULL);
		}
		ret = tmpret;
		ret[retcnt] = malloc(sizeof (struct ip_interface));
		if (ret[retcnt] == NULL) {
			while (retcnt-- > 0)
				free(ret[retcnt]);
			free(ret);
			free(ifc.ifc_buf);
			(void) close(s);
			return (NULL);
		}
		(void) strcpy(ret[retcnt]->name, ifr->ifr_name);
		if (ioctl(s, SIOCGIFADDR, ifr) < 0) {
			(void) close(s);
			while (retcnt-- > 0) {
				free(ret[retcnt]);
			}
			free(ret);
			free(ifc.ifc_buf);
			return (NULL);
		}
		/*LINTED - alignment*/
		sin = (struct sockaddr_in *)&ifr->ifr_addr;
		ret[retcnt]->addr = sin->sin_addr;

		if (ioctl(s, SIOCGIFNETMASK, ifr) < 0) {
			(void) close(s);
			while (retcnt-- > 0) {
				free(ret[retcnt]);
			}
			free(ret);
			free(ifc.ifc_buf);
			return (NULL);
		}
		/*LINTED - alignment*/
		sin = (struct sockaddr_in *)&ifr->ifr_addr;
		ret[retcnt]->mask = sin->sin_addr;
		++retcnt;
	}

	/* Null-terminate the list */
	if (retcnt > 0) {
		tmpret = realloc(ret,
		    (retcnt+1)*sizeof (struct ip_interface *));
		if (tmpret == NULL) {
			while (retcnt-- > 0)
				free(ret[retcnt]);
			free(ret);
			free(ifc.ifc_buf);
			(void) close(s);
			return (NULL);
		}
		ret = tmpret;
		ret[retcnt] = NULL;
	}
	(void) close(s);
	free(ifc.ifc_buf);
	return (ret);
}
