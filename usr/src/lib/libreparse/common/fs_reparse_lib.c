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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <limits.h>
#include <libnvpair.h>
#include <dlfcn.h>
#include <libintl.h>
#include <sys/systeminfo.h>
#include <sys/fs_reparse.h>
#include "rp_plugin.h"

#define	MAXISALEN	257	/* based on sysinfo(2) man page */

static rp_proto_handle_t rp_proto_handle;
static rp_proto_plugin_t *rp_proto_list;

int rp_plugin_init(void);
static void proto_plugin_fini(void);
static rp_plugin_ops_t *rp_find_protocol(const char *svctype);

extern int errno;
static int rp_plugin_inited = 0;

/*
 * reparse_create()
 *
 * Create a symlink at the specified 'path' as a reparse point.
 * This function will fail if path refers to an existing file system
 * object or an object named string already exists at the given path.
 *
 * return 0 if ok else return error code.
 */
int
reparse_create(const char *path, const char *data)
{
	int err;
	struct stat sbuf;

	if (path == NULL || data == NULL)
		return (EINVAL);

	if ((err = reparse_validate(data)) != 0)
		return (err);

	/* check if object exists */
	if (lstat(path, &sbuf) == 0)
		return (EEXIST);

	return (symlink(data, path) ? errno : 0);
}

/*
 * reparse_unparse()
 *
 * Convert an nvlist back to a string format suitable to write
 * to the reparse point symlink body.  The string returned is in
 * allocated memory and must be freed by the caller.
 *
 * return 0 if ok else return error code.
 */
int
reparse_unparse(nvlist_t *nvl, char **stringp)
{
	int err, buflen;
	char *buf, *stype, *val;
	nvpair_t *curr;

	if (nvl == NULL || stringp == NULL ||
	    ((curr = nvlist_next_nvpair(nvl, NULL)) == NULL))
		return (EINVAL);

	buflen = SYMLINK_MAX;
	if ((buf = malloc(buflen)) == NULL)
		return (ENOMEM);

	err = 0;
	(void) snprintf(buf, buflen, "%s", FS_REPARSE_TAG_STR);
	while (curr != NULL) {
		if (!(stype = nvpair_name(curr))) {
			err = EINVAL;
			break;
		}
		if ((strlcat(buf, FS_TOKEN_START_STR, buflen) >= buflen) ||
		    (strlcat(buf, stype, buflen) >= buflen) ||
		    (strlcat(buf, ":", buflen) >= buflen) ||
		    (nvpair_value_string(curr, &val) != 0) ||
		    (strlcat(buf, val, buflen) >= buflen) ||
		    (strlcat(buf, FS_TOKEN_END_STR, buflen) >= buflen)) {
			err = E2BIG;
			break;
		}
		curr = nvlist_next_nvpair(nvl, curr);
	}
	if (err != 0) {
		free(buf);
		return (err);
	}
	if (strlcat(buf, FS_REPARSE_TAG_END_STR, buflen) >= buflen) {
		free(buf);
		return (E2BIG);
	}

	*stringp = buf;
	return (0);
}

/*
 * reparse_deref()
 *
 * Accepts the service-specific item from the reparse point and returns
 * the service-specific data requested.  The caller specifies the size
 * of the buffer provided via *bufsz.
 *
 * if ok return 0 and *bufsz is updated to contain the actual length of
 * the returned results, else return error code. If the error code is
 * EOVERFLOW; results do not fit in the buffer, *bufsz will be updated
 * to contain the number of bytes needed to hold the results.
 */
int
reparse_deref(const char *svc_type, const char *svc_data, char *buf,
    size_t *bufsz)
{
	rp_plugin_ops_t *ops;

	if ((svc_type == NULL) || (svc_data == NULL) || (buf == NULL) ||
	    (bufsz == NULL))
		return (EINVAL);

	ops = rp_find_protocol(svc_type);
	if ((ops != NULL) && (ops->rpo_deref != NULL))
		return (ops->rpo_deref(svc_type, svc_data, buf, bufsz));

	/* no plugin, return error */
	return (ENOTSUP);
}

/*
 * reparse_delete()
 *
 * Delete a reparse point at a given pathname.  It will fail if
 * a reparse point does not exist at the given path or the pathname
 * is not a symlink.
 *
 * return 0 if ok else return error code.
 */
int
reparse_delete(const char *path)
{
	struct stat sbuf;

	if (path == NULL)
		return (EINVAL);

	/* check if object exists */
	if (lstat(path, &sbuf) != 0)
		return (errno);

	if ((sbuf.st_mode & S_IFLNK) != S_IFLNK)
		return (EINVAL);

	return (unlink(path) ? errno : 0);
}

/*
 * reparse_add()
 *
 * Add a service type entry to a nvlist with a copy of svc_data,
 * replacing one of the same type if already present.
 *
 * return 0 if ok else return error code.
 */
int
reparse_add(nvlist_t *nvl, const char *svc_type, const char *svc_data)
{
	int err;
	char *buf;
	size_t bufsz;
	rp_plugin_ops_t *ops;

	if ((nvl == NULL) || (svc_type == NULL) || (svc_data == NULL))
		return (EINVAL);

	bufsz = SYMLINK_MAX;		/* no need to mess around */
	if ((buf = malloc(bufsz)) == NULL)
		return (ENOMEM);

	ops = rp_find_protocol(svc_type);
	if ((ops != NULL) && (ops->rpo_form != NULL))
		err = ops->rpo_form(svc_type, svc_data, buf, &bufsz);
	else
		err = ENOTSUP;		/* no plugin */

	if (err != 0) {
		free(buf);
		return (err);
	}

	err =  nvlist_add_string(nvl, svc_type, buf);
	free(buf);
	return (err);
}

/*
 * reparse_remove()
 *
 * Remove a service type entry from the nvlist, if present.
 *
 * return 0 if ok else return error code.
 */
int
reparse_remove(nvlist_t *nvl, const char *svc_type)
{
	if ((nvl == NULL) || (svc_type == NULL))
		return (EINVAL);

	return (nvlist_remove_all(nvl, svc_type));
}

/*
 * Returns true if name is "." or "..", otherwise returns false.
 */
static boolean_t
rp_is_dot_or_dotdot(const char *name)
{
	if (*name != '.')
		return (B_FALSE);

	if (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))
		return (B_TRUE);

	return (B_FALSE);
}

static void
proto_plugin_fini()
{
	rp_proto_plugin_t *p;

	/*
	 * Protocols may call this framework during _fini
	 */
	for (p = rp_proto_list; p != NULL; p = p->plugin_next) {
		if (p->plugin_ops->rpo_fini)
			(void) p->plugin_ops->rpo_fini();
	}
	while ((p = rp_proto_list) != NULL) {
		rp_proto_list = p->plugin_next;
		if (p->plugin_handle != NULL)
			(void) dlclose(p->plugin_handle);
		free(p);
	}

	if (rp_proto_handle.rp_ops != NULL) {
		free(rp_proto_handle.rp_ops);
		rp_proto_handle.rp_ops = NULL;
	}
	rp_proto_handle.rp_num_proto = 0;
}

/*
 * rp_plugin_init()
 *
 * Initialize the service type specific plugin modules.
 * For each reparse service type, there should be a plugin library for it.
 * This function walks /usr/lib/reparse directory for plugin libraries.
 * For each plugin library found, initialize it and add it to the internal
 * list of service type plugin. These are used for service type specific
 * operations.
 */
int
rp_plugin_init()
{
	int err, ret = RP_OK;
	char isa[MAXISALEN], dirpath[MAXPATHLEN], path[MAXPATHLEN];
	int num_protos = 0;
	rp_proto_handle_t *rp_hdl;
	rp_proto_plugin_t *proto, *tmp;
	rp_plugin_ops_t *plugin_ops;
	struct stat st;
	void *dlhandle;
	DIR *dir;
	struct dirent *dent;

#if defined(_LP64)
	if (sysinfo(SI_ARCHITECTURE_64, isa, MAXISALEN) == -1)
		isa[0] = '\0';
#else
	isa[0] = '\0';
#endif

	(void) snprintf(dirpath, MAXPATHLEN,
	    "%s/%s", RP_LIB_DIR, isa);

	if ((dir = opendir(dirpath)) == NULL)
		return (RP_NO_PLUGIN_DIR);

	while ((dent = readdir(dir)) != NULL) {
		if (rp_is_dot_or_dotdot(dent->d_name))
			continue;

		(void) snprintf(path, MAXPATHLEN,
		    "%s/%s", dirpath, dent->d_name);

		/*
		 * If file doesn't exist, don't try to map it
		 */
		if (stat(path, &st) < 0)
			continue;
		if ((dlhandle = dlopen(path, RTLD_FIRST|RTLD_LAZY)) == NULL)
			continue;

		plugin_ops = (rp_plugin_ops_t *)
		    dlsym(dlhandle, "rp_plugin_ops");
		if (plugin_ops == NULL) {
			(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Error in plugin ops for service type %s\n%s\n"),
			    dent->d_name, dlerror());
			(void) dlclose(dlhandle);
			continue;
		}
		proto = (rp_proto_plugin_t *)
		    calloc(1, sizeof (rp_proto_plugin_t));
		if (proto == NULL) {
			(void) dlclose(dlhandle);
			(void) fprintf(stderr,
			    dgettext(TEXT_DOMAIN, "No memory for plugin %s\n"),
			    dent->d_name);
			ret = RP_NO_MEMORY;
			break;
		}

		proto->plugin_ops = plugin_ops;
		proto->plugin_handle = dlhandle;
		num_protos++;
		proto->plugin_next = rp_proto_list;
		rp_proto_list = proto;
	}

	(void) closedir(dir);

	if ((num_protos == 0) && (ret == 0))
		ret = RP_NO_PLUGIN;
	/*
	 * There was an error, so cleanup prior to return of failure.
	 */
	if (ret != RP_OK) {
		proto_plugin_fini();
		return (ret);
	}

	rp_proto_handle.rp_ops = (rp_plugin_ops_t **)calloc(num_protos,
	    sizeof (rp_plugin_ops_t *));
	if (!rp_proto_handle.rp_ops) {
		proto_plugin_fini();
		return (RP_NO_MEMORY);
	}

	rp_hdl = &rp_proto_handle;
	rp_hdl->rp_num_proto = 0;
	for (tmp = rp_proto_list; rp_hdl->rp_num_proto < num_protos &&
	    tmp != NULL; tmp = tmp->plugin_next) {

		err = RP_OK;
		if (tmp->plugin_ops->rpo_init != NULL)
			err = tmp->plugin_ops->rpo_init();
		if (err != RP_OK)
			continue;
		rp_hdl->rp_ops[rp_hdl->rp_num_proto++] = tmp->plugin_ops;
	}

	return (rp_hdl->rp_num_proto > 0 ? RP_OK : RP_NO_PLUGIN);
}


/*
 * find_protocol()
 *
 * Search the plugin list for the specified protocol and return the
 * ops vector.  return NULL if protocol is not defined.
 */
static rp_plugin_ops_t *
rp_find_protocol(const char *svc_type)
{
	int i;
	rp_plugin_ops_t *ops = NULL;

	if (svc_type == NULL)
		return (NULL);

	if (rp_plugin_inited == 0) {
		if (rp_plugin_init() == RP_OK)
			rp_plugin_inited = 1;
		else
			return (NULL);
	}

	for (i = 0; i < rp_proto_handle.rp_num_proto; i++) {
		ops = rp_proto_handle.rp_ops[i];
		if (ops->rpo_supports_svc(svc_type))
			return (ops);

	}
	return (NULL);
}
