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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/systeminfo.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>

#include <scsi/libsmp.h>
#include <scsi/libsmp_plugin.h>

#include <alloca.h>
#include <dlfcn.h>
#include <link.h>
#include <dirent.h>
#include <string.h>
#include <strings.h>
#include <limits.h>

#include "smp_impl.h"

static boolean_t _libsmp_plugin_dlclose;

/*
 * As part of basic initialization, we always retrieve the REPORT GENERAL
 * data so that we will know whether this target supports the long response
 * format.
 */
static int
smp_report_general(smp_target_t *tp)
{
	smp_action_t *ap;
	smp_report_general_resp_t *rp;
	smp_result_t result;
	size_t len;

	if ((ap = smp_action_alloc(SMP_FUNC_REPORT_GENERAL, tp, 0)) == NULL)
		return (-1);

	if (smp_exec(ap, tp) != 0) {
		smp_action_free(ap);
		return (smp_set_errno(ESMP_REPGEN_FAILED));
	}

	smp_action_get_response(ap, &result, (void **)&rp, &len);

	if (result != SMP_RES_FUNCTION_ACCEPTED || len < 24) {
		smp_action_free(ap);
		return (smp_set_errno(ESMP_REPGEN_FAILED));
	}

	bcopy(rp, &tp->st_repgen, sizeof (tp->st_repgen));

	smp_action_free(ap);

	return (0);
}

static int
smp_report_manufacturer_information(smp_target_t *tp)
{
	smp_action_t *ap;
	smp_report_manufacturer_info_resp_t *rp;
	smp_result_t result;
	size_t len;

	ap = smp_action_alloc(SMP_FUNC_REPORT_MANUFACTURER_INFO, tp, 0);
	if (ap == NULL)
		return (-1);

	if (smp_exec(ap, tp) != 0) {
		smp_action_free(ap);
		return (smp_set_errno(ESMP_REPGEN_FAILED));
	}

	smp_action_get_response(ap, &result, (void **)&rp, &len);

	if (result != SMP_RES_FUNCTION_ACCEPTED ||
	    len != sizeof (smp_report_manufacturer_info_resp_t)) {
		smp_action_free(ap);
		return (0);	/* Not supported */
	}

	tp->st_vendor = smp_trim_strdup(rp->srmir_vendor_identification,
	    sizeof (rp->srmir_vendor_identification));
	tp->st_product = smp_trim_strdup(rp->srmir_product_identification,
	    sizeof (rp->srmir_product_identification));
	tp->st_revision = smp_trim_strdup(rp->srmir_product_revision_level,
	    sizeof (rp->srmir_product_revision_level));

	if (rp->srmir_sas_1_1_format) {
		tp->st_component_vendor =
		    smp_trim_strdup(rp->srmir_component_vendor_identification,
		    sizeof (rp->srmir_component_vendor_identification));

		tp->st_component_id = SCSI_READ16(&rp->srmir_component_id);
		tp->st_component_revision = rp->srmir_component_revision_level;
	}

	if (tp->st_vendor == NULL || tp->st_product == NULL ||
	    tp->st_revision == NULL ||
	    (rp->srmir_sas_1_1_format && tp->st_component_vendor == NULL)) {
		smp_action_free(ap);
		return (smp_set_errno(ESMP_NOMEM));
	}

	smp_action_free(ap);

	return (0);
}

static int
smp_target_fill(smp_target_t *tp)
{
	if (smp_report_general(tp) != 0 ||
	    smp_report_manufacturer_information(tp) != 0)
		return (-1);

	return (0);
}

const smp_function_def_t *
smp_get_funcdef(smp_target_t *tp, int fn)
{
	smp_plugin_t *pp;
	const smp_function_def_t *dp;

	for (pp = tp->st_plugin_first; pp != NULL; pp = pp->sp_next) {
		if (pp->sp_functions == NULL)
			continue;

		for (dp = &pp->sp_functions[0]; dp->sfd_rq_len != NULL; dp++) {
			if (dp->sfd_function == fn)
				return (dp);
		}
	}

	(void) smp_error(ESMP_BADFUNC, "failed to find function 0x%x", fn);
	return (NULL);
}

int
smp_plugin_register(smp_plugin_t *pp, int version,
    const smp_plugin_config_t *pcp)
{
	if (version != LIBSMP_PLUGIN_VERSION)
		return (smp_set_errno(ESMP_VERSION));

	pp->sp_functions = pcp->spc_functions;

	return (0);
}

void
smp_plugin_setspecific(smp_plugin_t *pp, void *data)
{
	pp->sp_data = data;
}

void *
smp_plugin_getspecific(smp_plugin_t *pp)
{
	return (pp->sp_data);
}

static void
smp_plugin_cleanstr(char *s)
{
	while (*s != '\0') {
		if (*s == ' ' || *s == '/')
			*s = '-';
		s++;
	}
}

static void
smp_plugin_destroy(smp_plugin_t *pp)
{
	if (pp->sp_initialized && pp->sp_fini != NULL)
		pp->sp_fini(pp);

	if (_libsmp_plugin_dlclose)
		(void) dlclose(pp->sp_object);

	smp_free(pp);
}

static int
smp_plugin_loadone(smp_target_t *tp, const char *path, uint32_t pass)
{
	smp_plugin_t *pp, **loc;
	void *obj;
	int (*smp_priority)(void);

	if ((obj = dlopen(path, RTLD_PARENT | RTLD_LOCAL | RTLD_LAZY)) == NULL)
		return (0);

	if ((pp = smp_zalloc(sizeof (smp_plugin_t))) == NULL) {
		(void) dlclose(obj);
		return (-1);
	}

	pp->sp_object = obj;
	pp->sp_init = (int (*)())dlsym(obj, "_smp_init");
	pp->sp_fini = (void (*)())dlsym(obj, "_smp_fini");
	pp->sp_target = tp;

	if (pp->sp_init == NULL) {
		smp_plugin_destroy(pp);
		return (0);
	}

	/*
	 * Framework modules can establish an explicit prioritying by declaring
	 * the '_smp_priority' symbol, which returns an integer used to create
	 * an explicit ordering between plugins.
	 */
	if ((smp_priority = (int (*)())dlsym(obj, "_smp_priority")) != NULL)
		pp->sp_priority = smp_priority();

	pp->sp_priority |= (uint64_t)pass << 32;

	for (loc = &tp->st_plugin_first; *loc != NULL; loc = &(*loc)->sp_next) {
		if ((*loc)->sp_priority > pp->sp_priority)
			break;
	}

	if (*loc != NULL)
		(*loc)->sp_prev = pp;
	else
		tp->st_plugin_last = pp;

	pp->sp_next = *loc;
	*loc = pp;

	if (pp->sp_init(pp) != 0)
		return (-1);
	pp->sp_initialized = B_TRUE;

	return (0);
}

static int
smp_plugin_load_dir(smp_target_t *tp, const char *pluginroot)
{
	char path[PATH_MAX];
	DIR *dirp;
	struct dirent64 *dp;
	char *c_vendor, *vendor, *product, *revision;
	char isa[257];

	(void) snprintf(path, sizeof (path), "%s/%s",
	    pluginroot, LIBSMP_PLUGIN_FRAMEWORK);

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
			    pluginroot, LIBSMP_PLUGIN_FRAMEWORK,
			    isa, dp->d_name);

			if (smp_plugin_loadone(tp, path, 0) != 0) {
				(void) closedir(dirp);
				return (-1);
			}
		}

		(void) closedir(dirp);
	}

	/*
	 * Now attempt to load platform-specific plugins.  The framework
	 * plugins had better give us the ability to perform basic SMP
	 * functions like REPORT GENERAL and REPORT MANUFACTURER INFORMATION;
	 * if not, we're toast anyway.  If the latter is not supported, we
	 * will not be able to use any vendor-specific plugins.  Note that
	 * there are actually two possible specifications for vendor plugins:
	 * those matching the vendor/product/revision fields, and those
	 * matching the component vendor/id/revision fields.  The component is
	 * less specific, so we try to load those first.
	 */

	if (smp_target_fill(tp) != 0)
		return (-1);

	if (tp->st_vendor == NULL)
		return (0);

	if (tp->st_component_vendor != NULL) {
		c_vendor = alloca(strlen(tp->st_component_vendor) + 1);
		(void) strcpy(c_vendor, tp->st_component_vendor);
		smp_plugin_cleanstr(c_vendor);
	}

	vendor = alloca(strlen(tp->st_vendor) + 1);
	product = alloca(strlen(tp->st_product) + 1);
	revision = alloca(strlen(tp->st_revision) + 1);

	(void) strcpy(vendor, tp->st_vendor);
	(void) strcpy(product, tp->st_product);
	(void) strcpy(revision, tp->st_revision);

	smp_plugin_cleanstr(vendor);
	smp_plugin_cleanstr(product);
	smp_plugin_cleanstr(revision);

	if (tp->st_component_vendor != NULL) {
		(void) snprintf(path, sizeof (path), "%s/%s/%s/component_%s%s",
		    pluginroot, LIBSMP_PLUGIN_VENDOR, isa, c_vendor,
		    LIBSMP_PLUGIN_EXT);
		if (smp_plugin_loadone(tp, path, 1) != 0)
			return (-1);

		(void) snprintf(path, sizeof (path),
		    "%s/%s/%s/component_%s-%04x%s",
		    pluginroot, LIBSMP_PLUGIN_VENDOR, isa, c_vendor,
		    tp->st_component_id, LIBSMP_PLUGIN_EXT);
		if (smp_plugin_loadone(tp, path, 2) != 0)
			return (-1);

		(void) snprintf(path, sizeof (path),
		    "%s/%s/%s/component_%s-%04x-%02x%s",
		    pluginroot, LIBSMP_PLUGIN_VENDOR, isa, c_vendor,
		    tp->st_component_id, tp->st_component_revision,
		    LIBSMP_PLUGIN_EXT);
		if (smp_plugin_loadone(tp, path, 3) != 0)
			return (-1);
	}

	(void) snprintf(path, sizeof (path), "%s/%s/%s/%s%s", pluginroot,
	    LIBSMP_PLUGIN_VENDOR, isa, vendor, LIBSMP_PLUGIN_EXT);
	if (smp_plugin_loadone(tp, path, 4) != 0)
		return (-1);

	(void) snprintf(path, sizeof (path), "%s/%s/%s/%s-%s%s", pluginroot,
	    LIBSMP_PLUGIN_VENDOR, isa, vendor, product, LIBSMP_PLUGIN_EXT);
	if (smp_plugin_loadone(tp, path, 5) != 0)
		return (-1);

	(void) snprintf(path, sizeof (path), "%s/%s/%s/%s-%s-%s%s", pluginroot,
	    LIBSMP_PLUGIN_VENDOR, isa, vendor, product,
	    revision, LIBSMP_PLUGIN_EXT);
	if (smp_plugin_loadone(tp, path, 6) != 0)
		return (-1);

	return (0);
}

int
smp_plugin_load(smp_target_t *tp)
{
	char pluginroot[PATH_MAX];
	const char *pluginpath, *p, *q;

	if ((pluginpath = getenv("SMP_PLUGINPATH")) == NULL)
		pluginpath = LIBSMP_DEFAULT_PLUGINDIR;
	_libsmp_plugin_dlclose = (getenv("SMP_NODLCLOSE") == NULL);

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

		if (smp_plugin_load_dir(tp, pluginroot) != 0)
			return (-1);
	}

	if (tp->st_plugin_first == NULL)
		return (smp_error(ESMP_PLUGIN, "no plugins found"));

	return (0);
}

void
smp_plugin_unload(smp_target_t *tp)
{
	smp_plugin_t *pp;

	while ((pp = tp->st_plugin_first) != NULL) {
		tp->st_plugin_first = pp->sp_next;
		smp_plugin_destroy(pp);
	}
}
