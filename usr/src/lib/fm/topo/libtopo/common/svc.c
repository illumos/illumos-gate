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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This provides the basic mechanisms (str2nvl and nvl2str) for dealing with
 * the service schema.  The official version of a svc FMRI has the form:
 *
 *	svc://[scope@][system-fqn]/service[:instance][@contract-id]
 *
 * Where 'service' is a slash-delimited list of names.  Of these fields, the
 * scope, constract-id, and system-fqn are rarely used, leaving the much more
 * common form such as:
 *
 *	svc:///network/ssh:default
 *
 * Note that the SMF software typically uses a shorthard form, where the
 * authority is elided (svc:/network/ssh:default).  As this module deals with
 * FMA FMRIs, we only support fully specified FMRIs.
 *
 * This module does not support enumeration, but implements methods for FMRI
 * state (present, unusable, service state, and replaced).
 */

#include <fm/topo_mod.h>
#include <fm/fmd_fmri.h>
#include <sys/fm/protocol.h>
#include <topo_method.h>
#include <topo_subr.h>
#include <topo_prop.h>
#include <alloca.h>
#include <assert.h>
#include <svc.h>
#include <strings.h>
#include <libscf.h>

static int svc_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int svc_fmri_str2nvl(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int svc_fmri_present(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int svc_fmri_replaced(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int svc_fmri_service_state(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int svc_fmri_unusable(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int svc_fmri_prop_get(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_method_t svc_methods[] = {
	{ TOPO_METH_PROP_GET, TOPO_METH_PROP_GET_DESC,
	    TOPO_METH_PROP_GET_VERSION, TOPO_STABILITY_INTERNAL,
	    svc_fmri_prop_get },
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, svc_fmri_nvl2str },
	{ TOPO_METH_STR2NVL, TOPO_METH_STR2NVL_DESC, TOPO_METH_STR2NVL_VERSION,
	    TOPO_STABILITY_INTERNAL, svc_fmri_str2nvl },
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC, TOPO_METH_PRESENT_VERSION,
	    TOPO_STABILITY_INTERNAL, svc_fmri_present },
	{ TOPO_METH_REPLACED, TOPO_METH_REPLACED_DESC,
	    TOPO_METH_REPLACED_VERSION, TOPO_STABILITY_INTERNAL,
	    svc_fmri_replaced },
	{ TOPO_METH_SERVICE_STATE, TOPO_METH_SERVICE_STATE_DESC,
	    TOPO_METH_SERVICE_STATE_VERSION, TOPO_STABILITY_INTERNAL,
	    svc_fmri_service_state },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL,
	    svc_fmri_unusable },
	{ NULL }
};

static int svc_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void svc_release(topo_mod_t *, tnode_t *);

static const topo_modops_t svc_ops =
	{ svc_enum, svc_release };
static const topo_modinfo_t svc_info =
	{ "svc", FM_FMRI_SCHEME_SVC, SVC_VERSION, &svc_ops };

static int
svc_error(topo_mod_t *mod)
{
	switch (scf_error()) {
	case SCF_ERROR_NO_MEMORY:
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	default:
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
}

static scf_handle_t *
svc_get_handle(topo_mod_t *mod)
{
	scf_handle_t *hdl = topo_mod_getspecific(mod);

	if (hdl != NULL)
		return (hdl);

	if ((hdl = scf_handle_create(SCF_VERSION)) == NULL) {
		(void) svc_error(mod);
		return (NULL);
	}

	if (scf_handle_bind(hdl) != 0) {
		scf_handle_destroy(hdl);
		(void) svc_error(mod);
		return (NULL);
	}

	topo_mod_setspecific(mod, hdl);

	return (hdl);
}

int
svc_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOSVCDEBUG"))
		topo_mod_setdebug(mod);

	if (version != SVC_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &svc_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register svc_info: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1);
	}

	return (0);
}

void
svc_fini(topo_mod_t *mod)
{
	scf_handle_t *hdl = topo_mod_getspecific(mod);

	if (hdl != NULL)
		scf_handle_destroy(hdl);

	topo_mod_unregister(mod);
}

static tnode_t *
svc_create_node(topo_mod_t *mod, tnode_t *pnode, char *fmristr)
{
	nvlist_t *fmri;
	tnode_t *tn;
	char *fixed;
	ssize_t len;
	int i, j, err;

	/*
	 * the scf_{x}_to_fmri interfaces return short-hand svc-scheme FMRI's
	 * that look like:
	 *
	 * svc:/service[:instance]
	 *
	 * But all our other code assumes a proper svc-scheme FMRI, so we
	 * correct the fmri string before we try to convert it to an nvlist.
	 *
	 * The short-hand version is kept as the label and can be used when
	 * dealing with the SMF libraries and CLI's.
	 */
	len = strlen(fmristr) + 1;
	if ((fixed = topo_mod_zalloc(mod, len + 1)) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		topo_mod_dprintf(mod, "topo_mod_zalloc() failed: %s",
		    topo_mod_errmsg(mod));
		return (NULL);
	}
	for (i = 0, j = 0; i < len; i++)
		if (i == 5)
			fixed[i] = '/';
		else
			fixed[i] = fmristr[j++];
	fixed[i] = '\0';

	if (topo_mod_str2nvl(mod, fixed, &fmri) < 0) {
		topo_mod_dprintf(mod, "topo_mod_str2nvl() failed: %s",
		    topo_mod_errmsg(mod));
		topo_mod_free(mod, fixed, len + 1);
		return (NULL);
	}
	topo_mod_free(mod, fixed, len + 1);

	if (topo_node_range_create(mod, pnode, fmristr, 0, 0) < 0) {
		topo_mod_dprintf(mod, "topo_node_range_create() failed: %s",
		    topo_mod_errmsg(mod));
		nvlist_free(fmri);
		return (NULL);
	}
	if ((tn = topo_node_bind(mod, pnode, fmristr, 0, fmri)) == NULL) {
		topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
		    topo_mod_errmsg(mod));
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);

	if (topo_node_label_set(tn, fmristr, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set label: %s\n",
		    topo_strerror(err));
		return (NULL);
	}
	(void) topo_method_register(mod, tn, svc_methods);

	return (tn);
}

/*ARGSUSED*/
static int
svc_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	scf_handle_t *hdl;
	scf_scope_t *sc = NULL;
	scf_iter_t *svc_iter = NULL;
	scf_iter_t *inst_iter = NULL;
	scf_service_t *svc = NULL;
	scf_instance_t *inst = NULL;
	int ret = -1;
	char *sfmri, *ifmri;
	ssize_t slen, ilen;
	tnode_t *svc_node;

	(void) topo_method_register(mod, pnode, svc_methods);

	if ((hdl = svc_get_handle(mod)) == NULL)
		goto out;

	if ((sc = scf_scope_create(hdl)) == NULL ||
	    (svc = scf_service_create(hdl)) == NULL ||
	    (inst = scf_instance_create(hdl)) == NULL ||
	    (svc_iter = scf_iter_create(hdl)) == NULL ||
	    (inst_iter = scf_iter_create(hdl)) == NULL)
		goto out;

	if (scf_handle_get_scope(hdl, SCF_SCOPE_LOCAL, sc) != 0)
		goto out;

	if (scf_iter_scope_services(svc_iter, sc) != 0)
		goto out;

	while (scf_iter_next_service(svc_iter, svc) == 1) {
		if (scf_iter_service_instances(inst_iter, svc) != 0)
			continue;

		if ((slen = scf_service_to_fmri(svc, NULL, 0)) < 0)
			continue;

		if ((sfmri = topo_mod_zalloc(mod, slen + 1)) == NULL) {
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			goto out;
		}
		if (scf_service_to_fmri(svc, sfmri, slen + 1) == -1)
			goto out;

		if ((svc_node = svc_create_node(mod, pnode, sfmri)) == NULL) {
			topo_mod_free(mod, sfmri, slen + 1);
			/* topo mod errno set */
			goto out;
		}

		while (scf_iter_next_instance(inst_iter, inst) == 1) {
			if ((ilen = scf_instance_to_fmri(inst, NULL, 0)) < 0)
				continue;

			if ((ifmri = topo_mod_zalloc(mod, ilen + 1))
			    == NULL) {
				(void) topo_mod_seterrno(mod, EMOD_NOMEM);
				topo_mod_free(mod, sfmri, slen + 1);
				goto out;
			}
			if (scf_instance_to_fmri(inst, ifmri, ilen + 1) == -1)
				goto out;

			if ((svc_node = svc_create_node(mod, svc_node, ifmri))
			    == NULL) {
				topo_mod_free(mod, sfmri, slen + 1);
				topo_mod_free(mod, ifmri, ilen + 1);
				/* topo mod errno set */
				goto out;
			}
			topo_mod_free(mod, ifmri, ilen + 1);
		}
		topo_mod_free(mod, sfmri, slen + 1);
	}
	ret = 0;
out:
	scf_scope_destroy(sc);
	scf_service_destroy(svc);
	scf_instance_destroy(inst);
	scf_iter_destroy(svc_iter);
	scf_iter_destroy(inst_iter);

	return (ret);
}

static void
svc_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

static boolean_t
svc_component_valid(const char *str)
{
	if (str == NULL)
		return (B_TRUE);

	if (*str == '\0')
		return (B_FALSE);

	if (strpbrk(str, "@/:") != NULL)
		return (B_FALSE);

	return (B_TRUE);
}

static int
svc_fmri_prop_get(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	char *svc_name, *svc_inst = NULL;
	nvlist_t *rsrc, *args;
	char *pgroup, *pname;
	tnode_t *svc_node;
	char *search;
	size_t len;
	int err;

	if (version > TOPO_METH_PROP_GET_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	err = nvlist_lookup_string(in, TOPO_PROP_GROUP, &pgroup);
	err |= nvlist_lookup_string(in, TOPO_PROP_VAL_NAME, &pname);
	err |= nvlist_lookup_nvlist(in, TOPO_PROP_RESOURCE, &rsrc);
	if (err != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	/*
	 * Private args to prop method are optional
	 */
	if ((err = nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &args)) != 0) {
		if (err != ENOENT)
			return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
		else
			args = NULL;
	}

	/*
	 * Lookup a topo node named svc:/svc_name[:svc_inst]
	 */
	if (nvlist_lookup_string(rsrc, FM_FMRI_SVC_NAME, &svc_name) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	(void) nvlist_lookup_string(rsrc, FM_FMRI_SVC_INSTANCE, &svc_inst);

	len = 5 + strlen(svc_name) +
	    (svc_inst != NULL ? 1 + strlen(svc_inst) : 0) + 1;

	if ((search = topo_mod_alloc(mod, len)) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	(void) snprintf(search, len, "svc:/%s", svc_name);
	svc_node = topo_node_lookup(node, (const char *)search, 0);

	if (svc_node == NULL) {
		topo_mod_free(mod, search, len);
		return (topo_mod_seterrno(mod, EMOD_NODE_NOENT));
	}

	if (svc_inst != NULL) {
		(void) snprintf(search, len, "svc:/%s:%s", svc_name, svc_inst);
		svc_node = topo_node_lookup(svc_node, (const char *)search, 0);
		if (svc_node == NULL) {
			topo_mod_free(mod, search, len);
			return (topo_mod_seterrno(mod, EMOD_NODE_NOENT));
		}
	}

	topo_mod_free(mod, search, len);

	err = 0;
	(void) topo_prop_getprop(svc_node, pgroup, pname, args, out, &err);

	return (err);
}

/*ARGSUSED*/
static int
svc_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	uint8_t scheme_version;
	char *scope = NULL;
	char *fqn = NULL;
	char *contract = NULL;
	char *instance = NULL;
	char *service;
	int err;
	char *buf = NULL;
	size_t buflen = 0;
	ssize_t size = 0;
	nvlist_t *fmristr;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &scheme_version) != 0 ||
	    scheme_version > FM_SVC_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	/*
	 * Check for optional members.
	 */
	err = nvlist_lookup_string(nvl, FM_FMRI_SVC_INSTANCE, &instance);
	if ((err != 0 && err != ENOENT) || !svc_component_valid(instance))
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	err = nvlist_lookup_string(nvl, FM_FMRI_SVC_AUTH_SCOPE, &scope);
	if ((err != 0 && err != ENOENT) || !svc_component_valid(scope))
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	err = nvlist_lookup_string(nvl, FM_FMRI_SVC_AUTH_SYSTEM_FQN, &fqn);
	if ((err != 0 && err != ENOENT) || !svc_component_valid(scope))
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	err = nvlist_lookup_string(nvl, FM_FMRI_SVC_CONTRACT_ID, &contract);
	if ((err != 0 && err != ENOENT) || !svc_component_valid(contract))
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	/*
	 * Get the service name.
	 */
	if (nvlist_lookup_string(nvl, FM_FMRI_SVC_NAME, &service) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	/*
	 * We make two passes through this code.  The first time through we
	 * calculate the size of buffer that we'll need, and the second time
	 * through we fill it in.
	 */
again:
	/*
	 * svc://[scope@][system-fqn]
	 */
	topo_fmristr_build(&size, buf, buflen, FM_FMRI_SCHEME_SVC,
	    NULL, "://");
	topo_fmristr_build(&size, buf, buflen, scope, NULL, "@");
	topo_fmristr_build(&size, buf, buflen, fqn, NULL, NULL);

	/* svc path */
	if (*service == '\0')
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	topo_fmristr_build(&size, buf, buflen, service, "/", NULL);

	/* [:instance][@contract-id] */
	topo_fmristr_build(&size, buf, buflen, instance, ":", NULL);
	topo_fmristr_build(&size, buf, buflen, contract, "@", NULL);

	if (buf == NULL) {
		if ((buf = topo_mod_alloc(mod, size + 1)) == NULL)
			return (topo_mod_seterrno(mod, EMOD_NOMEM));

		buflen = size + 1;
		size = 0;
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

/*ARGSUSED*/
static int
svc_fmri_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *fmri;
	char *str, *loc, val;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, "fmri-string", &str) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (strncmp(str, "svc://", 6) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	str += 6;
	if ((loc = strpbrk(str, "@/")) == NULL)
		goto malformed;

	if (*loc == '@') {
		/* scope */
		*loc = '\0';
		if (!svc_component_valid(str)) {
			*loc = '@';
			goto malformed;
		}

		if (nvlist_add_string(fmri, FM_FMRI_SVC_AUTH_SCOPE, str) != 0) {
			*loc = '@';
			goto nomem;
		}

		*loc = '@';
		str = loc + 1;
		if ((loc = strchr(str, '/')) == NULL)
			goto malformed;
	}

	if (loc != str) {
		/* system-fqn */
		*loc = '\0';
		if (!svc_component_valid(str)) {
			*loc = '/';
			goto malformed;
		}

		if (nvlist_add_string(fmri, FM_FMRI_SVC_AUTH_SYSTEM_FQN,
		    str) != 0) {
			*loc = '/';
			goto nomem;
		}

		*loc = '/';
	}

	str = loc + 1;
	loc = strpbrk(str, ":@");

	if (str[0] == '\0' || loc == str)
		goto malformed;

	if (loc != NULL) {
		val = *loc;
		*loc = '\0';
	}

	/* service name */
	if (nvlist_add_string(fmri, FM_FMRI_SVC_NAME, str) != 0) {
		if (loc != NULL)
			*loc = val;
		goto nomem;
	}

	if (loc != NULL)
		*loc = val;

	if (loc != NULL && *loc == ':') {
		/* instance */
		str = loc + 1;
		if (str[0] == '\0' || str[0] == '@')
			goto malformed;

		loc = strchr(str, '@');
		if (loc != NULL)
			*loc = '\0';

		if (nvlist_add_string(fmri, FM_FMRI_SVC_INSTANCE,
		    str) != 0) {
			if (loc != NULL)
				*loc = '@';
			goto nomem;
		}

		if (loc != NULL)
			*loc = '@';
	}

	if (loc != NULL) {
		/* contract-id */
		assert(*loc == '@');
		str = loc + 1;
		if (str[0] == '\0')
			goto malformed;

		if (nvlist_add_string(fmri, FM_FMRI_SVC_CONTRACT_ID,
		    str) != 0) {
			goto nomem;
		}
	}

	if (nvlist_add_uint8(fmri, FM_VERSION, FM_SVC_SCHEME_VERSION) != 0 ||
	    nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_SVC) != 0)
		goto nomem;

	*out = fmri;
	return (0);

malformed:
	nvlist_free(fmri);
	return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

nomem:
	nvlist_free(fmri);
	return (topo_mod_seterrno(mod, EMOD_NOMEM));
}

/*
 * This common function is shared by all consumers (present, replaced,
 * service state and unusable).
 *
 *				svc_get_state succeeds
 * Case				with FMD_SERVICE_STATE_*
 * ----------------------------	------------------------
 * svc name deleted		UNKNOWN
 * svc name not found		UNKNOWN
 * no fmri instance		OK
 * instance deleted		UNKNOWN
 * instance not found		UNKNOWN
 *
 * If none of the above apply and this is a call from the "present"
 * or "replaced" method (presence_only == B_TRUE) then
 * svc_get_state returns FMD_SERVICE_STATE_OK.
 *
 * The "present" method maps a svc_get_state return of UNKNOWN to
 * "not present" and a svc_get_state return of OK to "present".
 *
 * The "replaced" methods maps a return of UNKNOWN to FMD_OBJ_STATE_NOT_PRESENT
 * and OK to FMD_OBJ_STATE_UNKNOWN.
 *
 * For the "service state" and "unusable" methods svc_get_state goes on
 * to return the instance state as below, and the two methods map that
 * result as in the last two columns of the following table:
 *
 *			svc_get_state succeeds		Service
 * Instance state	with FMD_SERVICE_STATE_*	State		Unusable
 * --------------	-------------------------------	---------------	--------
 * none			OK				OK
 * uninitialized	OK				OK
 * maintenance		UNUSABLE			UNUSABLE	Yes
 * offline		OK				OK
 * disabled		OK				OK
 * online		OK				OK
 * degraded		DEGRADED			DEGRADED
 * legacy_run		OK (XXX can we see this?)	OK
 *
 * Note that *only* "maintenance" state should map to an unusable service state
 * or unusable status.  That's because a service entering maintenance state
 * is modelled as a defect fault diagnosis in FMA, but there is no
 * corresponding isolation action from a response agent since the the service
 * is already isolated by virtue of being in maintenance state.  Any transition
 * from maintenance state, even to offline, is considered a repair.  If on
 * repair fmd does not see the service usable again then the case hangs
 * around in the "resolved but not all resources back online" state and
 * further maintenance events for this service will not show up in fmd state
 * because case duplicate checking code will find the old case.
 */

static int
svc_get_state(topo_mod_t *mod, nvlist_t *fmri, boolean_t presence_only,
    int *ret)
{
	scf_handle_t *hdl;
	uint8_t fmversion;
	char *instance, *name;
	scf_service_t *svc = NULL;
	scf_scope_t *scope = NULL;
	scf_instance_t *inst = NULL;
	scf_property_t *prop = NULL;
	scf_iter_t *iter = NULL;
	scf_value_t *val = NULL;
	scf_propertygroup_t *pg = NULL;
	int err, retval = 0;
	ssize_t len;
	char *state;

	if ((hdl = svc_get_handle(mod)) == NULL)
		return (-1);

	if (nvlist_lookup_uint8(fmri, FM_VERSION, &fmversion) != 0 ||
	    fmversion > FM_SVC_SCHEME_VERSION ||
	    nvlist_lookup_string(fmri, FM_FMRI_SVC_NAME, &name) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	if ((svc = scf_service_create(hdl)) == NULL ||
	    (inst = scf_instance_create(hdl)) == NULL ||
	    (scope = scf_scope_create(hdl)) == NULL ||
	    (prop = scf_property_create(hdl)) == NULL ||
	    (iter = scf_iter_create(hdl)) == NULL ||
	    (pg = scf_pg_create(hdl)) == NULL ||
	    (val = scf_value_create(hdl)) == NULL)
		goto error;

	if (scf_handle_get_scope(hdl, SCF_SCOPE_LOCAL, scope) != 0)
		goto error;

	/*
	 * If we fail to get the service due to _DELETED or _NOT_FOUND, then we
	 * treat this as not present.
	 */
	if (scf_scope_get_service(scope, name, svc) != 0) {
		err = scf_error();
		if (err == SCF_ERROR_NOT_FOUND || err == SCF_ERROR_DELETED) {
			*ret = FMD_SERVICE_STATE_UNKNOWN;
			goto out;
		} else {
			goto error;
		}
	}

	if (nvlist_lookup_string(fmri, FM_FMRI_SVC_INSTANCE, &instance) != 0) {
		*ret = FMD_SERVICE_STATE_OK;
		goto out;
	}

	/*
	 * Again, check for _DELETED or _NOT_FOUND.
	 */
	if (scf_service_get_instance(svc, instance, inst) != 0) {
		err = scf_error();
		if (err == SCF_ERROR_NOT_FOUND || err == SCF_ERROR_DELETED) {
			*ret = FMD_SERVICE_STATE_UNKNOWN;
			goto out;
		} else {
			goto error;
		}
	}

	/*
	 * For presence, we are done.  Otherwise, we need to get the current
	 * state of the instance.
	 */
	if (presence_only) {
		*ret = FMD_SERVICE_STATE_OK;
		goto out;
	}

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != 0 ||
	    scf_pg_get_property(pg, SCF_PROPERTY_STATE, prop) != 0 ||
	    scf_iter_property_values(iter, prop) != 0 ||
	    scf_iter_next_value(iter, val) != 1)
		goto error;

	if ((len = scf_value_get_astring(val, NULL, 0)) < 0)
		goto error;

	state = alloca(len + 1);
	if (scf_value_get_astring(val, state, len + 1) < 0)
		goto error;

	if (strcmp(state, SCF_STATE_STRING_MAINT) == 0) {
		*ret = FMD_SERVICE_STATE_UNUSABLE;
	} else if (strcmp(state, SCF_STATE_STRING_DEGRADED) == 0) {
		*ret = FMD_SERVICE_STATE_DEGRADED;
	} else {
		*ret = FMD_SERVICE_STATE_OK;
	}
	goto out;

error:
	retval = -1;
out:
	scf_value_destroy(val);
	scf_pg_destroy(pg);
	scf_iter_destroy(iter);
	scf_property_destroy(prop);
	scf_instance_destroy(inst);
	scf_scope_destroy(scope);
	scf_service_destroy(svc);
	return (retval);
}

/*ARGSUSED*/
static int
svc_fmri_present(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int state;

	if (version > TOPO_METH_PRESENT_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (svc_get_state(mod, in, B_TRUE, &state) != 0)
		return (-1);

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_PRESENT_RET,
	    state != FMD_SERVICE_STATE_UNKNOWN) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}

/*ARGSUSED*/
static int
svc_fmri_replaced(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int state;

	if (version > TOPO_METH_REPLACED_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (svc_get_state(mod, in, B_TRUE, &state) != 0)
		return (-1);

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_REPLACED_RET,
	    state == FMD_SERVICE_STATE_UNKNOWN ?
	    FMD_OBJ_STATE_NOT_PRESENT : FMD_OBJ_STATE_UNKNOWN) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}

/*ARGSUSED*/
static int
svc_fmri_service_state(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int state;

	if (version > TOPO_METH_SERVICE_STATE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (svc_get_state(mod, in, B_FALSE, &state) != 0)
		return (-1);

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_SERVICE_STATE_RET,
	    state) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}

/*ARGSUSED*/
static int
svc_fmri_unusable(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int state;

	if (version > TOPO_METH_UNUSABLE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (svc_get_state(mod, in, B_FALSE, &state) != 0)
		return (-1);

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_UNUSABLE_RET,
	    (state == FMD_SERVICE_STATE_UNKNOWN ||
	    state == FMD_SERVICE_STATE_UNUSABLE)) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}
