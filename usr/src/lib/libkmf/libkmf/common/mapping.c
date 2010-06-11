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
 *
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * This file implements the KMF certificate to name mapping framework.
 */
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <libgen.h>
#include <kmftypes.h>
#include <kmfapiP.h>

/* Mappers go in the same dir as plugins. */
#define	DEFAULT_MAPPER_DIR KMF_PLUGIN_PATH

static void
cleanup_mapper(KMF_HANDLE_T handle)
{
	KMF_MAPPER_RECORD *mapper = &handle->policy->mapper;
	void (*finalize)(KMF_HANDLE_T);

	if (mapper->curpathname != NULL) {
		free(mapper->curpathname);
		mapper->curpathname = NULL;
	}
	if (mapper->curoptions != NULL) {
		free(mapper->curoptions);
		mapper->curoptions = NULL;
	}
	if (mapper->dldesc != NULL) {
		finalize = (void(*)())dlsym(mapper->dldesc,
		    MAPPER_FINISH_FUNCTION);
		/* Optional, not an error if it does not exist. */
		if (finalize != NULL)
			finalize(handle);

		(void) dlclose(mapper->dldesc);
		mapper->dldesc = NULL;
	}
}

/* The caller is expected to free the returned string. */
char *
get_mapper_pathname(char *name, char *dir)
{
	char *pathname = NULL;
	int len;

	if (name == NULL)
		return (NULL);

	if (dir == NULL)
		dir = DEFAULT_MAPPER_DIR;

	/*
	 * MAPPER_NAME_TEMPLATE has 2 extra characters (%s) which make up for
	 * the "/" and the terminating NULL when computing the total length.
	 */
	len = strlen(name) + strlen(MAPPER_NAME_TEMPLATE) + strlen(dir);

	pathname = malloc(len);
	if (pathname == NULL)
		return (NULL);
	(void) memset(pathname, 0, len);
	/* Avoid double forward slash if the dir's last character is "/". */
	(void) snprintf(pathname, len, "%s%s" MAPPER_NAME_TEMPLATE,
	    dir, dir[strlen(dir) - 1] == '/' ? "" : "/", name);

	return (pathname);
}

static KMF_RETURN
open_mapper_library(KMF_MAPPER_RECORD *map)
{
	KMF_RETURN ret = KMF_OK;

	map->dldesc = dlopen(map->curpathname, RTLD_LAZY | RTLD_PARENT);
	if (map->dldesc == NULL)
		return (KMF_ERR_MAPPER_OPEN);

	return (ret);
}

/*
 * The mapping framework uses either attributes or the policy file. Those two
 * sources are never mixed. We always need a mapper name or a mapper pathname
 * but these two are mutually exclusive. Directory can be set only if name is
 * set.
 */
KMF_RETURN
kmf_cert_to_name_mapping_initialize(KMF_HANDLE_T handle, int numattr,
	KMF_ATTRIBUTE *attrlist)
{
	KMF_RETURN ret = KMF_OK;
	KMF_RETURN (*initialize)(KMF_HANDLE_T, char *);
	KMF_MAPPER_RECORD *map = NULL;
	char *dir = NULL;
	char *name = NULL;
	char *opts = NULL;
	char *path = NULL;
	char *tmppath = NULL;
	char *old_curpathname = NULL;
	char *old_curoptions = NULL;

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	map = &handle->policy->mapper;
	old_curpathname = map->curpathname;
	old_curoptions = map->curoptions;

	name = kmf_get_attr_ptr(KMF_MAPPER_NAME_ATTR, attrlist, numattr);
	dir = kmf_get_attr_ptr(KMF_DIRPATH_ATTR, attrlist, numattr);
	path = kmf_get_attr_ptr(KMF_MAPPER_PATH_ATTR, attrlist, numattr);
	opts = kmf_get_attr_ptr(KMF_MAPPER_OPTIONS_ATTR, attrlist, numattr);

	if (path != NULL) {
		/* Mutually exclusive. */
		if (name != NULL || dir != NULL)
			return (KMF_ERR_BAD_PARAMETER);
		tmppath = strdup(path);
		if (tmppath == NULL)
			return (KMF_ERR_MEMORY);
	/* If we only have a name and possibly a dir, we can find the path. */
	} else if (name != NULL) {
		tmppath = get_mapper_pathname(name, dir);
		/*
		 * If we were given name but the returned path is still NULL,
		 * return an error.
		 */
		if (tmppath == NULL)
			return (KMF_ERR_MEMORY);
	/* Can not exist standalone. */
	} else if (dir != NULL || opts != NULL) {
			return (KMF_ERR_BAD_PARAMETER);
	/* No attributes define the mapper so let's use the policy database. */
	} else if (map->pathname != NULL) {
		tmppath = strdup(map->pathname);
		if (tmppath == NULL)
			return (KMF_ERR_MEMORY);
		opts = map->options;
	} else if (map->mapname != NULL) {
		tmppath = get_mapper_pathname(map->mapname, map->dir);
		/*
		 * If we were given name but the returned path is still NULL,
		 * return an error.
		 */
		if (tmppath == NULL)
			return (KMF_ERR_MEMORY);
		opts = map->options;
	} else {
		/*
		 * Either a name or a full pathname must be provided whether
		 * from attributes or the policy database.
		 */
		return (KMF_ERR_BAD_PARAMETER);
	}

	/*
	 * Dlopen the mapper specified by the policy. If anything goes wrong
	 * just return an error. We do not have to worry about resetting
	 * curpathname and curoptions to the previous values since there was no
	 * mapper initialized beforehand.
	 *
	 * No mapper was open so stored curoptions and curpathname are
	 * already NULL and need not to be freed.
	 */
	if (map->dldesc == NULL) {
		map->curpathname = tmppath;
		if (opts != NULL) {
			map->curoptions = strdup(opts);
			if (map->curoptions == NULL) {
				free(map->curpathname);
				map->curpathname = NULL;
				return (KMF_ERR_MEMORY);
			}
		} else
			map->curoptions = NULL;

		if ((ret = open_mapper_library(map)) != KMF_OK) {
			free(map->curpathname);
			map->curpathname = NULL;
			if (map->curoptions != NULL) {
				free(map->curoptions);
				map->curoptions = NULL;
			}
			return (ret);
		}

		goto end;
	}

	/*
	 * We already have an open mapper, let's see if this is a new mapper
	 * library.
	 */
	if (map->curpathname != NULL &&
	    /* No change in mapper pathname. */
	    strcmp(map->curpathname, tmppath) == 0) {
		/* New options are empty while we had some before. */
		if (map->curoptions != NULL && opts == NULL) {
			map->curoptions = NULL;
		/* We have some options now while we had none before. */
		} else if (map->curoptions == NULL && opts != NULL) {
			if ((map->curoptions = strdup(opts)) == NULL)
				goto err_mem;
		/* We got different options. */
		} else if (strcmp(map->curoptions, opts) != 0) {
			if ((map->curoptions = strdup(opts)) == NULL)
				goto err_mem;
		} else {
			/*
			 * Same options, no free() of current options is
			 * required.
			 */
			old_curoptions = NULL;
		}

		/* Free old options if applicable. */
		if (old_curoptions != NULL)
			free(old_curoptions);
	} else {
		/*
		 * This is a new mapper path, clean up the old data and open the
		 * new mapper.
		 */
		cleanup_mapper(handle);
		/* These two are no longer valid. */
		old_curoptions = NULL;
		old_curpathname = NULL;
		map->curpathname = tmppath;
		if (opts != NULL) {
			map->curoptions = strdup(opts);
			if (map->curoptions == NULL)
				goto err_mem;
		}
		if ((ret = open_mapper_library(map)) != KMF_OK) {
			/*
			 * This will cleanup curoptions and curpathname, and
			 * ignores the dldesc since it is NULL. Do not free
			 * tmppath, it will be freed through map->curpathname.
			 */
			cleanup_mapper(handle);
			return (ret);
		}
	}

end:
	initialize = (KMF_RETURN(*)())dlsym(map->dldesc,
	    MAPPER_INIT_FUNCTION);
	/* Optional, not an error if it does not exist. */
	ret = KMF_OK;
	if (initialize != NULL)
		ret = initialize(handle, map->curoptions);

	if (ret != KMF_OK)
		cleanup_mapper(handle);

	return (ret);

err_mem:
	/*
	 * Try to put the old curpathname and curoptions back there. In theory,
	 * the application might be able to continue to use the old mapping
	 * unless we already called cleanup_mapper(). However, it's neither
	 * recommended nor officially supported. The app should initialize the
	 * old mapping again.
	 */
	if (tmppath != NULL)
		free(tmppath);
	map->curoptions = old_curoptions;
	map->curpathname = old_curpathname;
	return (KMF_ERR_MEMORY);
}

KMF_RETURN
kmf_cert_to_name_mapping_finalize(KMF_HANDLE_T handle)
{
	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	cleanup_mapper(handle);

	return (KMF_OK);
}

KMF_RETURN
kmf_map_cert_to_name(KMF_HANDLE_T handle, KMF_DATA *cert, KMF_DATA *name)
{
	KMF_MAPPER_RECORD *map = NULL;
	KMF_RETURN (*cert2name)(KMF_HANDLE *, KMF_DATA *, KMF_DATA *);

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	map = &handle->policy->mapper;
	if (map->dldesc == NULL)
		return (KMF_ERR_MAPPER_NOT_FOUND);

	cert2name = (KMF_RETURN(*)())dlsym(map->dldesc,
	    MAP_CERT_TO_NAME_FUNCTION);
	if (cert2name == NULL)
		return (KMF_ERR_FUNCTION_NOT_FOUND);

	return (cert2name(handle, cert, name));
}

/*
 * If mapped_name is non-NULL the caller is later expected to free its Data
 * after use.
 */
KMF_RETURN
kmf_match_cert_to_name(KMF_HANDLE_T handle, KMF_DATA *cert,
    KMF_DATA *name_to_match, KMF_DATA *mapped_name)
{
	KMF_MAPPER_RECORD *map = NULL;
	KMF_RETURN (*cert2name)(KMF_HANDLE *, KMF_DATA *, KMF_DATA *,
	    KMF_DATA *);

	if (handle == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	map = &handle->policy->mapper;

	if (map->curpathname == NULL || map->dldesc == NULL)
		return (KMF_ERR_MAPPER_NOT_FOUND);

	cert2name = (KMF_RETURN(*)())dlsym(map->dldesc,
	    MATCH_CERT_TO_NAME_FUNCTION);
	if (cert2name == NULL)
		return (KMF_ERR_FUNCTION_NOT_FOUND);

	return (cert2name(handle, cert, name_to_match, mapped_name));
}

/*
 * The caller is responsible for freeing the error string (ie., *errstr) when
 * done with it.
 */
KMF_RETURN
kmf_get_mapper_error_str(KMF_HANDLE_T handle, char **errstr)
{
	KMF_HANDLE *h = NULL;
	KMF_MAPPER_RECORD *map = NULL;
	KMF_RETURN (*err2string)(KMF_HANDLE *, char **);

	if (handle == NULL || errstr == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	h = (KMF_HANDLE *)handle;
	map = &(h->policy->mapper);

	if (map->curpathname == NULL || map->dldesc == NULL)
		return (KMF_ERR_MAPPER_NOT_FOUND);

	err2string = (KMF_RETURN(*)())dlsym(map->dldesc,
	    MAPPER_ERROR_STRING_FUNCTION);
	if (err2string == NULL)
		return (KMF_ERR_FUNCTION_NOT_FOUND);

	return (err2string(h, errstr));
}

void
kmf_set_mapper_lasterror(KMF_HANDLE_T handle, uint32_t err)
{
	handle->mapstate->lastmappererr = err;
}

uint32_t
kmf_get_mapper_lasterror(KMF_HANDLE_T handle)
{
	return (handle->mapstate->lastmappererr);
}

void
kmf_set_mapper_options(KMF_HANDLE_T handle, void *opts)
{
	handle->mapstate->options = opts;
}

void *
kmf_get_mapper_options(KMF_HANDLE_T handle)
{
	return (handle->mapstate->options);
}
