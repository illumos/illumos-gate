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

#include <libnvpair.h>
#include <fm/topo_mod.h>

#include <sys/fm/protocol.h>
#include <sys/types.h>

#include <topo_method.h>
#include <topo_subr.h>
#include <sw.h>

static int sw_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sw_fmri_create(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_method_t sw_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, sw_fmri_nvl2str },
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, sw_fmri_create },
	{ NULL }
};

static int sw_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void sw_release(topo_mod_t *, tnode_t *);

static const topo_modops_t sw_ops =
	{ sw_enum, sw_release };

static const topo_modinfo_t sw_info =
	{ "sw", FM_FMRI_SCHEME_SW, SW_VERSION, &sw_ops };

int
sw_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOSWDEBUG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing sw builtin\n");

	if (version != SW_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &sw_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register sw_info: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1);
	}

	return (0);
}

void
sw_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static int
sw_get_optl_string(nvlist_t *nvl, char *name, char **dest)
{
	if (nvlist_lookup_string(nvl, name, dest) == 0) {
		return (0);
	} else {
		*dest = NULL;
		return (errno == ENOENT ? 0 : 1);
	}
}

static int
sw_get_optl_int64(nvlist_t *nvl, char *name, int64_t *dest)
{
	if (nvlist_lookup_int64(nvl, name, dest) == 0) {
		return (0);
	} else {
		*dest = -1;
		return (errno == ENOENT ? 0 : 1);
	}
}

static int
sw_get_optl_nvlist(nvlist_t *nvl, char *name, nvlist_t **dest)
{
	if (nvlist_lookup_nvlist(nvl, name, dest) == 0) {
		return (0);
	} else {
		*dest = NULL;
		return (errno == ENOENT ? 0 : 1);
	}
}

static int
sw_add_optl_string(nvlist_t *nvl, char *name, char *val)
{
	if (val)
		return (nvlist_add_string(nvl, name, val) != 0);
	else
		return (0);
}

/*ARGSUSED*/
static int
sw_fmri_create(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *args, *fmri = NULL, *obj = NULL, *site = NULL, *ctxt = NULL;
	topo_mod_errno_t moderr;
	int err = 0;

	char *obj_path, *obj_root;
	nvlist_t *obj_pkg;

	char *site_token, *site_module, *site_file, *site_func;
	int64_t site_line;

	char *ctxt_origin, *ctxt_execname, *ctxt_zone;
	int64_t ctxt_pid, ctxt_ctid;
	char **ctxt_stack;
	uint_t ctxt_stackdepth;


	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_NVL, &args) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	if (nvlist_lookup_string(args, "obj_path", &obj_path) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	err |= sw_get_optl_string(args, "obj_root", &obj_root);
	err |= sw_get_optl_nvlist(args, "obj-pkg", &obj_pkg);

	err |= sw_get_optl_string(args, "site_token", &site_token);
	err |= sw_get_optl_string(args, "site_module", &site_module);
	err |= sw_get_optl_string(args, "site_file", &site_file);
	err |= sw_get_optl_string(args, "site_func", &site_func);
	err |= sw_get_optl_int64(args, "site_line", &site_line);

	err |= sw_get_optl_string(args, "ctxt_origin", &ctxt_origin);
	err |= sw_get_optl_string(args, "ctxt_execname", &ctxt_execname);
	err |= sw_get_optl_string(args, "ctxt_zone", &ctxt_zone);
	err |= sw_get_optl_int64(args, "ctxt_pid", &ctxt_pid);
	err |= sw_get_optl_int64(args, "ctxt_ctid", &ctxt_ctid);

	if (nvlist_lookup_string_array(args, "stack", &ctxt_stack,
	    &ctxt_stackdepth) != 0) {
		if (errno == ENOENT)
			ctxt_stack = NULL;
		else
			err++;
	}

	if (err)
		(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0 ||
	    topo_mod_nvalloc(mod, &obj, NV_UNIQUE_NAME) != 0) {
		moderr = EMOD_NOMEM;
		goto out;
	}

	/*
	 * Add standard FMRI members 'version' and 'scheme'.
	 */
	err |= nvlist_add_uint8(fmri, FM_VERSION, FM_SW_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_SW);

	/*
	 * Build up the 'object' nvlist.
	 */
	err |= nvlist_add_string(obj, FM_FMRI_SW_OBJ_PATH, obj_path);
	err |= sw_add_optl_string(obj, FM_FMRI_SW_OBJ_ROOT, obj_root);
	if (obj_pkg)
		err |= nvlist_add_nvlist(obj, FM_FMRI_SW_OBJ_PKG, obj_pkg);

	/*
	 * Add 'object' to the fmri.
	 */
	if (err == 0)
		err |= nvlist_add_nvlist(fmri, FM_FMRI_SW_OBJ, obj);

	if (err) {
		moderr = EMOD_NOMEM;
		goto out;
	}

	/*
	 * Do we have anything for a 'site' nvlist?
	 */
	if (site_token == NULL && site_module == NULL && site_file == NULL &&
	    site_func == NULL && site_line == -1)
		goto context;

	/*
	 * Allocate and build 'site' nvlist.
	 */
	if (topo_mod_nvalloc(mod, &site, NV_UNIQUE_NAME) != 0) {
		moderr = EMOD_NOMEM;
		goto out;
	}

	err |= sw_add_optl_string(site, FM_FMRI_SW_SITE_TOKEN, site_token);
	err |= sw_add_optl_string(site, FM_FMRI_SW_SITE_MODULE, site_module);
	err |= sw_add_optl_string(site, FM_FMRI_SW_SITE_FILE, site_file);
	err |= sw_add_optl_string(site, FM_FMRI_SW_SITE_FUNC, site_func);
	if ((site_token || site_module || site_file || site_func) &&
	    site_line != -1)
		err |= nvlist_add_int64(site, FM_FMRI_SW_SITE_LINE, site_line);

	/*
	 * Add 'site' to the fmri.
	 */
	if (err == 0)
		err |= nvlist_add_nvlist(fmri, FM_FMRI_SW_SITE, site);

	if (err) {
		moderr = EMOD_NOMEM;
		goto out;
	}

context:
	/*
	 * Do we have anything for a 'context' nvlist?
	 */
	if (ctxt_origin || ctxt_execname || ctxt_zone ||
	    ctxt_pid != -1 || ctxt_ctid != -1 || ctxt_stack != NULL)
		goto out;

	/*
	 * Allocate and build 'context' nvlist.
	 */
	if (topo_mod_nvalloc(mod, &ctxt, NV_UNIQUE_NAME) != 0) {
		moderr = EMOD_NOMEM;
		goto out;
	}

	err |= sw_add_optl_string(ctxt, FM_FMRI_SW_CTXT_ORIGIN, ctxt_origin);
	err |= sw_add_optl_string(ctxt, FM_FMRI_SW_CTXT_EXECNAME,
	    ctxt_execname);
	err |= sw_add_optl_string(ctxt, FM_FMRI_SW_CTXT_ZONE, ctxt_zone);
	if (ctxt_pid != -1)
		err |= nvlist_add_int64(ctxt, FM_FMRI_SW_CTXT_PID, ctxt_pid);
	if (ctxt_ctid != -1)
		err |= nvlist_add_int64(ctxt, FM_FMRI_SW_CTXT_CTID, ctxt_ctid);
	if (ctxt_stack != NULL)
		err |= nvlist_add_string_array(ctxt, FM_FMRI_SW_CTXT_STACK,
		    ctxt_stack, ctxt_stackdepth);

	/*
	 * Add 'context' to the fmri.
	 */
	if (err == 0)
		err |= nvlist_add_nvlist(fmri, FM_FMRI_SW_CTXT, ctxt);

	moderr = err ? EMOD_NOMEM : 0;
out:
	if (moderr == 0)
		*out = fmri;
	else
		nvlist_free(fmri);

	nvlist_free(obj);
	nvlist_free(site);
	nvlist_free(ctxt);

	return (moderr == 0 ? 0 : topo_mod_seterrno(mod, moderr));
}


/*ARGSUSED*/
static int
sw_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	(void) topo_method_register(mod, pnode, sw_methods);
	return (0);
}

static void
sw_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

/*
 * Lookup a string in an nvlist.  Possible return values:
 *	if 'required' is B_TRUE:
 *		1 = found
 *		0 = not found
 *	if 'required' is B_FALSE:
 *		1 = found
 *		0 = not found, but some error other than ENOENT encountered
 *		-1 = not found, with ENOENT
 *
 *	So 0 is an error condition in both cases.
 *
 *	In all "not found" cases, *valp is NULLed.
 */
static int
lookup_string(nvlist_t *nvl, char *name, char **valp, boolean_t required)
{
	int err;

	err = nvlist_lookup_string(nvl, name, valp);

	/*
	 * A return value of 1 always means "found"
	 */
	if (err == 0)
		return (1);

	/*
	 * Failure to lookup for whatever reason NULLs valp
	 */
	*valp = NULL;

	/*
	 * Return 0 if not found but required, or optional but some error
	 * other than ENOENT was returned.
	 */
	if (required == B_TRUE || err != ENOENT)
		return (0);

	/*
	 * Return -1 if not found but was optional (and got ENOENT).
	 */
	return (-1);
}

/*ARGSUSED*/
static int
sw_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	nvlist_t *object, *site = NULL, *anvl = NULL;
	char *file, *func, *token;
	uint8_t scheme_version;
	char *path, *root;
	nvlist_t *fmristr;
	size_t buflen = 0;
	int linevalid = 0;
	char *buf = NULL;
	ssize_t size = 0;
	char linebuf[32];
	int64_t line;
	int pass;
	int err;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &scheme_version) != 0 ||
	    scheme_version > FM_SW_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	/* Get authority, if present */
	err = nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &anvl);
	if (err != 0 && err != ENOENT)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	/*
	 * The 'object' nvlist is required. It must include the path,
	 * but the root is optional.
	 */
	if (nvlist_lookup_nvlist(nvl, FM_FMRI_SW_OBJ, &object) != 0 ||
	    !lookup_string(object, FM_FMRI_SW_OBJ_PATH, &path, B_TRUE) ||
	    !lookup_string(object, FM_FMRI_SW_OBJ_ROOT, &root, B_FALSE))
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	/* The 'site' nvlist is optional */
	file = func = token = NULL;
	linevalid = 0;
	if ((err = nvlist_lookup_nvlist(nvl, FM_FMRI_SW_SITE, &site)) == 0) {
		/*
		 * Prefer 'token' to file/func/line
		 */
		if (lookup_string(site, FM_FMRI_SW_SITE_TOKEN, &token,
		    B_FALSE) <= 0) {
			/*
			 * If no token then try file, func, line - but
			 * func and line are meaningless without file.
			 */
			if (lookup_string(site, FM_FMRI_SW_SITE_FILE,
			    &file, B_FALSE) == 1) {
				(void) lookup_string(site, FM_FMRI_SW_SITE_FUNC,
				    &func, B_FALSE);
				if (nvlist_lookup_int64(site,
				    FM_FMRI_SW_SITE_LINE, &line) == 0)
					linevalid = 1;
			}
		}
	} else if (err != ENOENT) {
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	/* On the first pass buf is NULL and size and buflen are 0 */
	pass = 1;
again:
	/*
	 * sw://[<authority>]/
	 *	[:root=<object.root]
	 *	:path=<object.path>
	 *	[#<fragment-identifier>]
	 *
	 *	<fragment-identifier> is one of
	 *
	 *		:token=<site.token>
	 *	or
	 *		:file=<site.file>[:func=<site.func>][:line=<site.line>]
	 */

	/* sw:// */
	topo_fmristr_build(&size, buf, buflen, FM_FMRI_SCHEME_SW,
	    NULL, "://");

	/* authority, if any */
	if (anvl != NULL) {
		nvpair_t *apair;
		char *aname, *aval;

		for (apair = nvlist_next_nvpair(anvl, NULL);
		    apair != NULL; apair = nvlist_next_nvpair(anvl, apair)) {
			if (nvpair_type(apair) != DATA_TYPE_STRING ||
			    nvpair_value_string(apair, &aval) != 0)
				continue;
			aname = nvpair_name(apair);
			topo_fmristr_build(&size, buf, buflen, ":", NULL, NULL);
			topo_fmristr_build(&size, buf, buflen, "=",
			    aname, aval);
		}
	}

	/* separating slash */
	topo_fmristr_build(&size, buf, buflen, "/", NULL, NULL);

	/* :root=... */
	if (root) {
		topo_fmristr_build(&size, buf, buflen, root,
		    ":" FM_FMRI_SW_OBJ_ROOT "=", NULL);
	}

	/* :path=... */
	topo_fmristr_build(&size, buf, buflen, path,
	    ":" FM_FMRI_SW_OBJ_PATH "=", NULL);

	if (token) {
		/* #:token=... */
		topo_fmristr_build(&size, buf, buflen, token,
		    "#:" FM_FMRI_SW_SITE_TOKEN "=", NULL);
	} else if (file) {
		/* #:file=... */
		topo_fmristr_build(&size, buf, buflen, file,
		    "#:" FM_FMRI_SW_SITE_FILE "=", NULL);

		/* :func=... */
		if (func) {
			topo_fmristr_build(&size, buf, buflen, func,
			    ":" FM_FMRI_SW_SITE_FUNC "=", NULL);
		}

		/* :line=... */
		if (linevalid) {
			if (pass == 1)
				(void) snprintf(linebuf, sizeof (linebuf),
				    "%lld", line);

			topo_fmristr_build(&size, buf, buflen, linebuf,
			    ":" FM_FMRI_SW_SITE_LINE "=", NULL);
		}
	}

	if (buf == NULL) {
		if ((buf = topo_mod_alloc(mod, size + 1)) == NULL)
			return (topo_mod_seterrno(mod, EMOD_NOMEM));

		buflen = size + 1;
		size = 0;
		pass = 2;
		goto again;
	}

	/*
	 * Construct the nvlist to return as the result.
	 */
	if (topo_mod_nvalloc(mod, &fmristr, NV_UNIQUE_NAME) != 0) {
		topo_mod_strfree(mod, buf);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	if (nvlist_add_string(fmristr, "fmri-string", buf) != 0) {
		topo_mod_strfree(mod, buf);
		nvlist_free(fmristr);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	topo_mod_strfree(mod, buf);
	*out = fmristr;

	return (0);
}
