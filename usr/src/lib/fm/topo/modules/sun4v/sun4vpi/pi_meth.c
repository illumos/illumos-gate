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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <strings.h>
#include <string.h>
#include <libnvpair.h>
#include <sys/fm/ldom.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>
#include <fm/fmd_fmri.h>
#include <fm/fmd_agent.h>
#include <sys/fm/ldom.h>

struct cpu_walk_data {
	tnode_t		*parent;	/* walk start node */
	ldom_hdl_t	*lhp;		/* ldom handle */
	int		(*func)(ldom_hdl_t *, nvlist_t *); /* callback func */
	int		err;		/* walk errors count */
	int		online;		/* online cpus count */
	int		offline;	/* offline cpus count */
	int		fail;		/* callback fails */
};

static topo_method_f
	cpu_retire, cpu_unretire, cpu_service_state,
	cpu_unusable, mem_asru_compute, dimm_page_unusable,
	dimm_page_service_state, dimm_page_retire, dimm_page_unretire;

const topo_method_t pi_cpu_methods[] = {
	{ TOPO_METH_RETIRE, TOPO_METH_RETIRE_DESC,
	    TOPO_METH_RETIRE_VERSION, TOPO_STABILITY_INTERNAL,
	    cpu_retire },
	{ TOPO_METH_UNRETIRE, TOPO_METH_UNRETIRE_DESC,
	    TOPO_METH_UNRETIRE_VERSION, TOPO_STABILITY_INTERNAL,
	    cpu_unretire },
	{ TOPO_METH_SERVICE_STATE, TOPO_METH_SERVICE_STATE_DESC,
	    TOPO_METH_SERVICE_STATE_VERSION, TOPO_STABILITY_INTERNAL,
	    cpu_service_state },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL,
	    cpu_unusable },
	{ NULL }
};

const topo_method_t pi_mem_methods[] = {
	{ TOPO_METH_ASRU_COMPUTE, TOPO_METH_ASRU_COMPUTE_DESC,
	    TOPO_METH_ASRU_COMPUTE_VERSION, TOPO_STABILITY_INTERNAL,
	    mem_asru_compute },
	{ TOPO_METH_SERVICE_STATE, TOPO_METH_SERVICE_STATE_DESC,
	    TOPO_METH_SERVICE_STATE_VERSION, TOPO_STABILITY_INTERNAL,
	    dimm_page_service_state },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL,
	    dimm_page_unusable },
	{ TOPO_METH_RETIRE, TOPO_METH_RETIRE_DESC,
	    TOPO_METH_RETIRE_VERSION, TOPO_STABILITY_INTERNAL,
	    dimm_page_retire },
	{ TOPO_METH_UNRETIRE, TOPO_METH_UNRETIRE_DESC,
	    TOPO_METH_UNRETIRE_VERSION, TOPO_STABILITY_INTERNAL,
	    dimm_page_unretire },
	{ NULL }
};

static ldom_hdl_t *pi_lhp = NULL;

#pragma init(pi_ldom_init)
static void
pi_ldom_init(void)
{
	pi_lhp = ldom_init(NULL, NULL);
}

#pragma fini(pi_ldom_fini)
static void
pi_ldom_fini(void)
{
	if (pi_lhp != NULL)
		ldom_fini(pi_lhp);
}

static int
set_retnvl(topo_mod_t *mod, nvlist_t **out, const char *retname, uint32_t ret)
{
	nvlist_t *nvl;

	topo_mod_dprintf(mod, "topo method set \"%s\" = %u\n", retname, ret);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) < 0)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	if (nvlist_add_uint32(nvl, retname, ret) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	*out = nvl;
	return (0);
}

/*
 * For each visited cpu node, call the callback function with its ASRU.
 */
static int
cpu_walker(topo_mod_t *mod, tnode_t *node, void *pdata)
{
	struct cpu_walk_data *swdp = pdata;
	nvlist_t *asru;
	int err, rc;

	/*
	 * Terminate the walk if we reach start-node's sibling
	 */
	if (node != swdp->parent &&
	    topo_node_parent(node) == topo_node_parent(swdp->parent))
		return (TOPO_WALK_TERMINATE);

	if (strcmp(topo_node_name(node), CPU) != 0 &&
	    strcmp(topo_node_name(node), STRAND) != 0)
		return (TOPO_WALK_NEXT);

	if (topo_node_asru(node, &asru, NULL, &err) != 0) {
		swdp->fail++;
		return (TOPO_WALK_NEXT);
	}

	rc = swdp->func(swdp->lhp, asru);

	/*
	 * The "offline" and "online" counter are only useful for the "status"
	 * callback.
	 */
	if (rc == P_OFFLINE || rc == P_FAULTED) {
		swdp->offline++;
		err = 0;
	} else if (rc == P_ONLINE) {
		swdp->online++;
		err = 0;
	} else {
		swdp->fail++;
		err = errno;
	}

	/* dump out status info if debug is turned on. */
	if (getenv("TOPOCHIPDBG") != NULL ||
	    getenv("TOPOSUN4VPIDBG") != NULL) {
		const char *op;
		char *fmristr = NULL;

		if (swdp->func == ldom_fmri_retire)
			op = "retire";
		else if (swdp->func == ldom_fmri_unretire)
			op = "unretire";
		else if (swdp->func == ldom_fmri_status)
			op = "check status";
		else
			op = "unknown op";

		(void) topo_mod_nvl2str(mod, asru, &fmristr);
		topo_mod_dprintf(mod, "%s cpu (%s): rc = %d, err = %s\n",
		    op, fmristr == NULL ? "unknown fmri" : fmristr,
		    rc, strerror(err));
		if (fmristr != NULL)
			topo_mod_strfree(mod, fmristr);
	}

	nvlist_free(asru);
	return (TOPO_WALK_NEXT);
}

static int
walk_cpus(topo_mod_t *mod, struct cpu_walk_data *swdp, tnode_t *parent,
    int (*func)(ldom_hdl_t *, nvlist_t *))
{
	topo_walk_t *twp;
	int err;

	swdp->lhp = pi_lhp;
	swdp->parent = parent;
	swdp->func = func;
	swdp->err = swdp->offline = swdp->online = swdp->fail = 0;

	/*
	 * Return failure if ldom service is not initialized.
	 */
	if (pi_lhp == NULL) {
		swdp->fail++;
		return (0);
	}

	twp = topo_mod_walk_init(mod, parent, cpu_walker, swdp, &err);
	if (twp == NULL)
		return (-1);

	err = topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);

	if (err == TOPO_WALK_ERR || swdp->err > 0)
		return (-1);

	return (0);
}

/* ARGSUSED */
int
cpu_retire(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	struct cpu_walk_data swd;
	uint32_t rc;

	if (version > TOPO_METH_RETIRE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (walk_cpus(mod, &swd, node, ldom_fmri_retire) == -1)
		return (-1);

	rc = swd.fail > 0 ? FMD_AGENT_RETIRE_FAIL : FMD_AGENT_RETIRE_DONE;

	return (set_retnvl(mod, out, TOPO_METH_RETIRE_RET, rc));
}

/* ARGSUSED */
int
cpu_unretire(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	struct cpu_walk_data swd;
	uint32_t rc;

	if (version > TOPO_METH_UNRETIRE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (walk_cpus(mod, &swd, node, ldom_fmri_unretire) == -1)
		return (-1);

	rc = swd.fail > 0 ? FMD_AGENT_RETIRE_FAIL : FMD_AGENT_RETIRE_DONE;

	return (set_retnvl(mod, out, TOPO_METH_UNRETIRE_RET, rc));
}

/* ARGSUSED */
int
cpu_service_state(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	struct cpu_walk_data swd;
	uint32_t rc;

	if (version > TOPO_METH_SERVICE_STATE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (walk_cpus(mod, &swd, node, ldom_fmri_status) == -1)
		return (-1);

	if (swd.fail > 0)
		rc = FMD_SERVICE_STATE_UNKNOWN;
	else if (swd.offline > 0)
		rc = swd.online > 0 ? FMD_SERVICE_STATE_DEGRADED :
		    FMD_SERVICE_STATE_UNUSABLE;
	else
		rc = FMD_SERVICE_STATE_OK;

	return (set_retnvl(mod, out, TOPO_METH_SERVICE_STATE_RET, rc));
}

/* ARGSUSED */
int
cpu_unusable(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	struct cpu_walk_data swd;
	uint32_t rc;

	if (version > TOPO_METH_UNUSABLE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (walk_cpus(mod, &swd, node, ldom_fmri_status) == -1)
		return (-1);

	rc = (swd.offline > 0 && swd.fail + swd.online == 0) ? 1 : 0;

	return (set_retnvl(mod, out, TOPO_METH_UNUSABLE_RET, rc));
}

static nvlist_t *
mem_fmri_create(topo_mod_t *mod, char *serial, char *label)
{
	int err;
	nvlist_t *fmri;

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0)
		return (NULL);
	err = nvlist_add_uint8(fmri, FM_VERSION, FM_MEM_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_MEM);
	if (serial != NULL)
		err |= nvlist_add_string_array(fmri, FM_FMRI_MEM_SERIAL_ID,
		    &serial, 1);
	if (label != NULL)
		err |= nvlist_add_string(fmri, FM_FMRI_MEM_UNUM, label);
	if (err != 0) {
		nvlist_free(fmri);
		(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);
		return (NULL);
	}

	return (fmri);
}

/* Topo Methods */
static int
mem_asru_compute(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *asru, *pargs, *args, *hcsp;
	int err;
	char *serial = NULL, *label = NULL;
	uint64_t pa, offset;

	if (version > TOPO_METH_ASRU_COMPUTE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (strcmp(topo_node_name(node), DIMM) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	pargs = NULL;

	if (nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0)
		(void) nvlist_lookup_string(pargs, FM_FMRI_HC_SERIAL_ID,
		    &serial);
	if (serial == NULL &&
	    nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) == 0)
		(void) nvlist_lookup_string(args, FM_FMRI_HC_SERIAL_ID,
		    &serial);

	(void) topo_node_label(node, &label, &err);

	asru = mem_fmri_create(mod, serial, label);

	if (label != NULL)
		topo_mod_strfree(mod, label);

	if (asru == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	err = 0;

	/*
	 * For a memory page, 'in' includes an hc-specific member which
	 * specifies physaddr and/or offset. Set them in asru as well.
	 */
	if (pargs && nvlist_lookup_nvlist(pargs,
	    FM_FMRI_HC_SPECIFIC, &hcsp) == 0) {
		if (nvlist_lookup_uint64(hcsp,
		    FM_FMRI_HC_SPECIFIC_PHYSADDR, &pa) == 0)
			err += nvlist_add_uint64(asru, FM_FMRI_MEM_PHYSADDR,
			    pa);
		if (nvlist_lookup_uint64(hcsp,
		    FM_FMRI_HC_SPECIFIC_OFFSET, &offset) == 0)
			err += nvlist_add_uint64(asru, FM_FMRI_MEM_OFFSET,
			    offset);
	}


	if (err != 0 || topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) < 0) {
		nvlist_free(asru);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	err = nvlist_add_string(*out, TOPO_PROP_VAL_NAME, TOPO_PROP_ASRU);
	err |= nvlist_add_uint32(*out, TOPO_PROP_VAL_TYPE, TOPO_TYPE_FMRI);
	err |= nvlist_add_nvlist(*out, TOPO_PROP_VAL_VAL, asru);
	nvlist_free(asru);

	if (err != 0) {
		nvlist_free(*out);
		*out = NULL;
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}

static boolean_t
is_page_fmri(nvlist_t *nvl)
{
	nvlist_t *hcsp;
	uint64_t val;

	if (nvlist_lookup_nvlist(nvl, FM_FMRI_HC_SPECIFIC, &hcsp) == 0 &&
	    (nvlist_lookup_uint64(hcsp, FM_FMRI_HC_SPECIFIC_OFFSET,
	    &val) == 0 ||
	    nvlist_lookup_uint64(hcsp, "asru-" FM_FMRI_HC_SPECIFIC_OFFSET,
	    &val) == 0 ||
	    nvlist_lookup_uint64(hcsp, FM_FMRI_HC_SPECIFIC_PHYSADDR,
	    &val) == 0 ||
	    nvlist_lookup_uint64(hcsp, "asru-" FM_FMRI_HC_SPECIFIC_PHYSADDR,
	    &val) == 0))
		return (B_TRUE);

	return (B_FALSE);
}

static int
dimm_page_service_state(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint32_t rc = FMD_SERVICE_STATE_OK;
	nvlist_t *asru;
	int err;

	if (version > TOPO_METH_SERVICE_STATE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (pi_lhp != NULL && is_page_fmri(in) &&
	    topo_node_asru(node, &asru, in, &err) == 0) {
		err = ldom_fmri_status(pi_lhp, asru);

		if (err == 0 || err == EINVAL)
			rc = FMD_SERVICE_STATE_UNUSABLE;
		else if (err == EAGAIN)
			rc = FMD_SERVICE_STATE_ISOLATE_PENDING;
		nvlist_free(asru);
	}

	return (set_retnvl(mod, out, TOPO_METH_SERVICE_STATE_RET, rc));
}

static int
dimm_page_unusable(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint32_t rc = 0;
	nvlist_t *asru;
	int err;

	if (version > TOPO_METH_UNUSABLE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (pi_lhp != NULL && is_page_fmri(in) &&
	    topo_node_asru(node, &asru, in, &err) == 0) {
		err = ldom_fmri_status(pi_lhp, asru);

		if (err == 0 || err == EINVAL)
			rc = 1;
		nvlist_free(asru);
	}

	return (set_retnvl(mod, out, TOPO_METH_UNUSABLE_RET, rc));
}

static int
dimm_page_retire(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint32_t rc = FMD_AGENT_RETIRE_FAIL;
	nvlist_t *asru;
	int err;

	if (version > TOPO_METH_RETIRE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (pi_lhp != NULL && is_page_fmri(in) &&
	    topo_node_asru(node, &asru, in, &err) == 0) {
		err = ldom_fmri_retire(pi_lhp, asru);

		if (err == 0 || err == EIO || err == EINVAL)
			rc = FMD_AGENT_RETIRE_DONE;
		else if (err == EAGAIN)
			rc = FMD_AGENT_RETIRE_ASYNC;
		nvlist_free(asru);
	}

	return (set_retnvl(mod, out, TOPO_METH_RETIRE_RET, rc));
}

static int
dimm_page_unretire(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint32_t rc = FMD_AGENT_RETIRE_FAIL;
	nvlist_t *asru;
	int err;

	if (version > TOPO_METH_UNRETIRE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (pi_lhp != NULL && is_page_fmri(in) &&
	    topo_node_asru(node, &asru, in, &err) == 0) {
		err = ldom_fmri_unretire(pi_lhp, asru);

		if (err == 0 || err == EIO)
			rc = FMD_AGENT_RETIRE_DONE;
		nvlist_free(asru);
	}

	return (set_retnvl(mod, out, TOPO_METH_UNRETIRE_RET, rc));
}
