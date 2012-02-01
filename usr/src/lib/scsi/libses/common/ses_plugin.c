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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

#include <scsi/libses.h>
#include "ses_impl.h"

static boolean_t ses_plugin_dlclose;

/*ARGSUSED*/
void *
ses_plugin_ctlpage_lookup(ses_plugin_t *sp, ses_snap_t *snap, int pagenum,
    size_t len, ses_node_t *np, boolean_t unique)
{
	ses_target_t *tp = snap->ss_target;
	ses_snap_page_t *pp;
	ses_pagedesc_t *dp;

	if ((pp = ses_snap_ctl_page(snap, pagenum, len, unique)) == NULL)
		return (NULL);

	if ((dp = ses_get_pagedesc(tp, pagenum, SES_PAGE_CTL)) == NULL)
		return (NULL);

	if (np != NULL && dp->spd_ctl_fill != NULL) {
		return (dp->spd_ctl_fill(sp, pp->ssp_page,
		    pp->ssp_len, np));
	} else {
		return (pp->ssp_page);
	}
}

int
ses_fill_node(ses_node_t *np)
{
	ses_target_t *tp = np->sn_snapshot->ss_target;
	ses_plugin_t *sp;

	for (sp = tp->st_plugin_first; sp != NULL; sp = sp->sp_next) {
		if (sp->sp_node_parse == NULL)
			continue;

		if (sp->sp_node_parse(sp, np) != 0)
			return (-1);
	}

	return (0);
}

int
ses_node_ctl(ses_node_t *np, const char *op, nvlist_t *arg)
{
	ses_target_t *tp = np->sn_snapshot->ss_target;
	ses_plugin_t *sp;
	nvlist_t *nvl;
	nvpair_t *nvp;
	int ret;

	if (nvlist_dup(arg, &nvl, 0) != 0)
		return (ses_set_errno(ESES_NOMEM));

	/*
	 * Technically we could get away with a per-snapshot lock while we fill
	 * the control page contents, but this doesn't take much time and we
	 * want actual control operations to be protected per-target, so we just
	 * take the target lock.
	 */
	(void) pthread_mutex_lock(&tp->st_lock);

	/*
	 * We walk the list of plugins backwards, so that a product-specific
	 * plugin can rewrite the nvlist to control operations in terms of the
	 * standard mechanisms, if desired.
	 */
	for (sp = tp->st_plugin_first; sp != NULL; sp = sp->sp_next) {
		if (sp->sp_node_ctl == NULL)
			continue;

		if (sp->sp_node_ctl(sp, np, op, nvl) != 0) {
			nvlist_free(nvl);
			(void) pthread_mutex_unlock(&tp->st_lock);
			return (-1);
		}
	}

	if ((nvp = nvlist_next_nvpair(nvl, NULL)) != NULL) {
		(void) ses_error(ESES_NOTSUP, "property '%s' invalid for "
		    "this node", nvpair_name(nvp));
		nvlist_free(nvl);
		(void) pthread_mutex_unlock(&tp->st_lock);
		return (-1);
	}

	nvlist_free(nvl);

	ret = ses_snap_do_ctl(np->sn_snapshot);
	(void) pthread_mutex_unlock(&tp->st_lock);

	return (ret);
}

/*ARGSUSED*/
void *
ses_plugin_page_lookup(ses_plugin_t *sp, ses_snap_t *snap, int pagenum,
    ses_node_t *np, size_t *lenp)
{
	ses_snap_page_t *pp;
	ses_target_t *tp = sp->sp_target;
	ses_pagedesc_t *dp;

	if ((dp = ses_get_pagedesc(tp, pagenum, SES_PAGE_DIAG)) == NULL)
		return (NULL);

	if ((pp = ses_snap_find_page(snap, pagenum, B_FALSE)) == NULL)
		return (NULL);

	if (np != NULL && dp->spd_index != NULL) {
		return (dp->spd_index(sp, np, pp->ssp_page, pp->ssp_len,
		    lenp));
	} else {
		*lenp = pp->ssp_len;
		return (pp->ssp_page);
	}
}

ses_pagedesc_t *
ses_get_pagedesc(ses_target_t *tp, int pagenum, ses_pagetype_t type)
{
	ses_plugin_t *sp;
	ses_pagedesc_t *dp;

	for (sp = tp->st_plugin_first; sp != NULL; sp = sp->sp_next) {
		if (sp->sp_pages == NULL)
			continue;

		for (dp = &sp->sp_pages[0]; dp->spd_pagenum != -1;
		    dp++) {
			if ((type == SES_PAGE_CTL && dp->spd_ctl_len == NULL) ||
			    (type == SES_PAGE_DIAG && dp->spd_ctl_len != NULL))
				continue;

			if (dp->spd_pagenum == pagenum)
				return (dp);
		}
	}

	(void) ses_error(ESES_BAD_PAGE, "failed to find page 0x%x", pagenum);
	return (NULL);
}

int
ses_plugin_register(ses_plugin_t *sp, int version, ses_plugin_config_t *scp)
{
	if (version != LIBSES_PLUGIN_VERSION)
		return (ses_set_errno(ESES_VERSION));

	sp->sp_pages = scp->spc_pages;
	sp->sp_node_parse = scp->spc_node_parse;
	sp->sp_node_ctl = scp->spc_node_ctl;

	return (0);
}

void
ses_plugin_setspecific(ses_plugin_t *sp, void *data)
{
	sp->sp_data = data;
}

void *
ses_plugin_getspecific(ses_plugin_t *sp)
{
	return (sp->sp_data);
}

static void
ses_plugin_cleanstr(char *s)
{
	while (*s != '\0') {
		if (*s == ' ' || *s == '/')
			*s = '-';
		s++;
	}
}

static void
ses_plugin_destroy(ses_plugin_t *sp)
{
	if (sp->sp_initialized && sp->sp_fini != NULL)
		sp->sp_fini(sp);

	if (ses_plugin_dlclose)
		(void) dlclose(sp->sp_object);

	ses_free(sp);
}

static int
ses_plugin_loadone(ses_target_t *tp, const char *path, uint32_t pass)
{
	ses_plugin_t *sp, **loc;
	void *obj;
	int (*ses_priority)(void);

	if ((obj = dlopen(path, RTLD_PARENT | RTLD_LOCAL | RTLD_LAZY)) == NULL)
		return (0);

	if ((sp = ses_zalloc(sizeof (ses_plugin_t))) == NULL) {
		(void) dlclose(obj);
		return (-1);
	}

	sp->sp_object = obj;
	sp->sp_init = (int (*)())dlsym(obj, "_ses_init");
	sp->sp_fini = (void (*)())dlsym(obj, "_ses_fini");
	sp->sp_target = tp;

	if (sp->sp_init == NULL) {
		ses_plugin_destroy(sp);
		return (0);
	}

	/*
	 * Framework modules can establish an explicit prioritying by declaring
	 * the '_ses_priority' symbol, which returns an integer used to create
	 * an explicit ordering between plugins.
	 */
	if ((ses_priority = (int (*)())dlsym(obj, "_ses_priority")) != NULL)
		sp->sp_priority = ses_priority();

	sp->sp_priority |= (uint64_t)pass << 32;

	for (loc = &tp->st_plugin_first; *loc != NULL; loc = &(*loc)->sp_next) {
		if ((*loc)->sp_priority > sp->sp_priority)
			break;
	}

	if (*loc != NULL)
		(*loc)->sp_prev = sp;
	else
		tp->st_plugin_last = sp;

	sp->sp_next = *loc;
	*loc = sp;

	if (sp->sp_init(sp) != 0)
		return (-1);
	sp->sp_initialized = B_TRUE;

	return (0);
}

static int
ses_plugin_load_dir(ses_target_t *tp, const char *pluginroot)
{
	char path[PATH_MAX];
	DIR *dirp;
	struct dirent64 *dp;
	char *vendor, *product, *revision;
	char isa[257];

	(void) snprintf(path, sizeof (path), "%s/%s",
	    pluginroot, LIBSES_PLUGIN_FRAMEWORK);

#if defined(_LP64)
	if (sysinfo(SI_ARCHITECTURE_64, isa, sizeof (isa)) < 0)
		isa[0] = '\0';
#else
	isa[0] = '\0';
#endif

	if ((dirp = opendir(path)) != NULL) {
		while ((dp = readdir64(dirp)) != NULL) {
			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0)
				continue;

			(void) snprintf(path, sizeof (path), "%s/%s/%s/%s",
			    pluginroot, LIBSES_PLUGIN_FRAMEWORK,
			    isa, dp->d_name);

			if (ses_plugin_loadone(tp, path, 0) != 0) {
				(void) closedir(dirp);
				return (-1);
			}
		}

		(void) closedir(dirp);
	}

	/*
	 * Create a local copy of the vendor/product/revision, strip out any
	 * questionable characters, and then attempt to load each plugin.
	 */
	vendor = strdupa(libscsi_vendor(tp->st_target));
	product = strdupa(libscsi_product(tp->st_target));
	revision = strdupa(libscsi_revision(tp->st_target));

	ses_plugin_cleanstr(vendor);
	ses_plugin_cleanstr(product);
	ses_plugin_cleanstr(revision);

	(void) snprintf(path, sizeof (path), "%s/%s/%s/%s%s", pluginroot,
	    LIBSES_PLUGIN_VENDOR, isa, vendor,
	    LIBSES_PLUGIN_EXT);
	if (ses_plugin_loadone(tp, path, 1) != 0)
		return (-1);

	(void) snprintf(path, sizeof (path), "%s/%s/%s/%s-%s%s", pluginroot,
	    LIBSES_PLUGIN_VENDOR, isa, vendor, product,
	    LIBSES_PLUGIN_EXT);
	if (ses_plugin_loadone(tp, path, 2) != 0)
		return (-1);

	(void) snprintf(path, sizeof (path), "%s/%s/%s/%s-%s-%s%s", pluginroot,
	    LIBSES_PLUGIN_VENDOR, isa, vendor, product,
	    revision, LIBSES_PLUGIN_EXT);
	if (ses_plugin_loadone(tp, path, 3) != 0)
		return (-1);

	return (0);
}

int
ses_plugin_load(ses_target_t *tp)
{
	char pluginroot[PATH_MAX];
	const char *pluginpath, *p, *q;

	if ((pluginpath = getenv("SES_PLUGINPATH")) == NULL)
		pluginpath = LIBSES_DEFAULT_PLUGINDIR;
	ses_plugin_dlclose = (getenv("SES_NODLCLOSE") == NULL);

	for (p = pluginpath; p != NULL; p = q) {
		if ((q = strchr(p, ':')) != NULL) {
			ptrdiff_t len = q - p;
			(void) strncpy(pluginroot, p, len);
			pluginroot[len] = '\0';
			while (*q == ':')
				++q;
			if (*q == '\0')
				q = NULL;
			if (len == 0)
				continue;
		} else {
			(void) strcpy(pluginroot, p);
		}

		if (pluginroot[0] != '/')
			continue;

		if (ses_plugin_load_dir(tp, pluginroot) != 0)
			return (-1);
	}

	if (tp->st_plugin_first == NULL)
		return (ses_error(ESES_PLUGIN, "no plugins found"));

	return (0);
}

void
ses_plugin_unload(ses_target_t *tp)
{
	ses_plugin_t *sp;

	while ((sp = tp->st_plugin_first) != NULL) {
		tp->st_plugin_first = sp->sp_next;
		ses_plugin_destroy(sp);
	}
}
