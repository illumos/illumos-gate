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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * Support function for the i86pc chip enumerator
 */

#include <sys/types.h>
#include <stdarg.h>
#include <strings.h>
#include <fm/fmd_fmri.h>
#include <sys/systeminfo.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/fmd_agent.h>

#include "chip.h"

static void fmri_dprint(topo_mod_t *, const char *, uint32_t, nvlist_t *);
static boolean_t is_page_fmri(nvlist_t *);

/*
 * Whinge a debug message via topo_mod_dprintf and increment the
 * given error counter.
 */
void
whinge(topo_mod_t *mod, int *nerr, const char *fmt, ...)
{
	va_list ap;
	char buf[160];

	if (nerr != NULL)
		++*nerr;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	topo_mod_dprintf(mod, "%s", buf);
}

/*
 * Given an nvpair of a limited number of data types, extract the property
 * name and value and add that combination to the given node in the
 * specified property group using the corresponding topo_prop_set_* function
 * for the data type.  Return 1 on success, otherwise 0.
 */
int
nvprop_add(topo_mod_t *mod, nvpair_t *nvp, const char *pgname, tnode_t *node)
{
	int success = 0;
	int err;
	char *pname = nvpair_name(nvp);

	switch (nvpair_type(nvp)) {
	case DATA_TYPE_BOOLEAN_VALUE: {
		boolean_t val;

		if (nvpair_value_boolean_value(nvp, &val) == 0 &&
		    topo_prop_set_string(node, pgname, pname,
		    TOPO_PROP_IMMUTABLE, val ? "true" : "false", &err) == 0)
			success = 1;
		break;
	}

	case DATA_TYPE_UINT32: {
		uint32_t val;

		if (nvpair_value_uint32(nvp, &val) == 0 &&
		    topo_prop_set_uint32(node, pgname, pname,
		    TOPO_PROP_IMMUTABLE, val, &err) == 0)
			success = 1;
		break;
	}

	case DATA_TYPE_UINT64: {
		uint64_t val;

		if (nvpair_value_uint64(nvp, &val) == 0 &&
		    topo_prop_set_uint64(node, pgname, pname,
		    TOPO_PROP_IMMUTABLE, val, &err) == 0)
			success = 1;
		break;
	}

	case DATA_TYPE_UINT32_ARRAY: {
		uint32_t *arrp;
		uint_t nelem;

		if (nvpair_value_uint32_array(nvp, &arrp, &nelem) == 0 &&
		    nelem > 0 && topo_prop_set_uint32_array(node, pgname, pname,
		    TOPO_PROP_IMMUTABLE, arrp, nelem, &err) == 0)
			success = 1;
		break;
	}

	case DATA_TYPE_STRING: {
		char *str;

		if (nvpair_value_string(nvp, &str) == 0 &&
		    topo_prop_set_string(node, pgname, pname,
		    TOPO_PROP_IMMUTABLE, str, &err) == 0)
			success = 1;
		break;
	}

	default:
		whinge(mod, &err, "nvprop_add: Can't handle type %d for "
		    "'%s' in property group %s of %s node\n",
		    nvpair_type(nvp), pname, pgname, topo_node_name(node));
		break;
	}

	return (success ? 0 : 1);
}

/*
 * Lookup string data named pname in the given nvlist and add that
 * as property named pname in the given property group pgname on the indicated
 * topo node.  Fill pvalp with a pointer to the string value, valid until
 * nvlist_free is called.
 */
int
add_nvlist_strprop(topo_mod_t *mod, tnode_t *node, nvlist_t *nvl,
    const char *pgname, const char *pname, const char **pvalp)
{
	char *pval;
	int err = 0;

	if (nvlist_lookup_string(nvl, pname, &pval) != 0)
		return (-1);

	if (topo_prop_set_string(node, pgname, pname,
	    TOPO_PROP_IMMUTABLE, pval, &err) == 0) {
		if (pvalp)
			*pvalp = pval;
		return (0);
	} else {
		whinge(mod, &err, "add_nvlist_strprop: failed to add '%s'\n",
		    pname);
		return (-1);
	}
}

/*
 * Lookup an int32 item named pname in the given nvlist and add that
 * as property named pname in the given property group pgname on the indicated
 * topo node.  Fill pvalp with the property value.
 */
int
add_nvlist_longprop(topo_mod_t *mod, tnode_t *node, nvlist_t *nvl,
    const char *pgname, const char *pname, int32_t *pvalp)
{
	int32_t pval;
	int err;

	if ((nvlist_lookup_int32(nvl, pname, &pval)) != 0)
		return (-1);

	if (topo_prop_set_int32(node, pgname, pname,
	    TOPO_PROP_IMMUTABLE, pval, &err) == 0) {
		if (pvalp)
			*pvalp = pval;
		return (0);
	} else {
		whinge(mod, &err, "add_nvlist_longprop: failed to add '%s'\n",
		    pname);
		return (-1);
	}
}

/*
 * In a given nvlist lookup a variable number of int32 properties named in
 * const char * varargs and each each in the given property group on the
 * node.  Fill an array of the retrieved values.
 */
int
add_nvlist_longprops(topo_mod_t *mod, tnode_t *node, nvlist_t *nvl,
    const char *pgname, int32_t *pvalap, ...)
{
	const char *pname;
	va_list ap;
	int nerr = 0;

	va_start(ap, pvalap);
	while ((pname = va_arg(ap, const char *)) != NULL) {
		if (add_nvlist_longprop(mod, node, nvl, pgname, pname,
		    pvalap) != 0)
			nerr++;		/* have whinged elsewhere */

		if (pvalap != NULL)
			++pvalap;
	}
	va_end(ap);

	return (nerr == 0 ? 0 : -1);
}

/*
 * Construct an hc scheme resource FMRI for a node named name with
 * instance number inst, parented by the given parent node pnode.
 */
int
mkrsrc(topo_mod_t *mod, tnode_t *pnode, const char *name, int inst,
    nvlist_t *auth, nvlist_t **nvl)
{
	*nvl = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION, name,
	    inst, NULL, auth, NULL, NULL, NULL);
	return (*nvl != NULL ? 0 : -1);	/* caller must free nvlist */
}

/*
 * Construct a cpu scheme FMRI with the given data; the caller must free
 * the allocated nvlist with nvlist_free().
 */
nvlist_t *
cpu_fmri_create(topo_mod_t *mod, uint32_t cpuid, char *s, uint8_t cpumask)
{
	int err;
	nvlist_t *asru;

	if (topo_mod_nvalloc(mod, &asru, NV_UNIQUE_NAME) != 0)
		return (NULL);

	err = nvlist_add_uint8(asru, FM_VERSION, FM_CPU_SCHEME_VERSION);
	err |= nvlist_add_string(asru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_CPU);
	err |= nvlist_add_uint32(asru, FM_FMRI_CPU_ID, cpuid);
	err |= nvlist_add_uint8(asru, FM_FMRI_CPU_MASK, cpumask);
	if (s != NULL)
		err |= nvlist_add_string(asru, FM_FMRI_CPU_SERIAL_ID, s);
	if (err != 0) {
		nvlist_free(asru);
		(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);
		return (NULL);
	}

	return (asru);
}

/*ARGSUSED*/
int
mem_asru_compute(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *asru, *args, *pargs, *hcsp;
	int err;
	uint64_t pa, offset;

	if (strcmp(topo_node_name(node), RANK_NODE_NAME) != 0 &&
	    strcmp(topo_node_name(node), DIMM_NODE_NAME) != 0 &&
	    strcmp(topo_node_name(node), CS_NODE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	if ((err = nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs)) != 0) {
		if (err == ENOENT) {
			pargs = args;
		} else {
			return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
		}
	}

	if (topo_mod_nvdup(mod, pargs, &asru) != 0)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	err = 0;

	/*
	 * if 'in' includes an hc-specific member which specifies asru-physaddr
	 * or asru-offset then rename them to asru and physaddr respectively.
	 */
	if (nvlist_lookup_nvlist(asru, FM_FMRI_HC_SPECIFIC, &hcsp) == 0) {
		if (nvlist_lookup_uint64(hcsp,
		    "asru-"FM_FMRI_HC_SPECIFIC_PHYSADDR, &pa) == 0) {
			err += nvlist_remove(hcsp,
			    "asru-"FM_FMRI_HC_SPECIFIC_PHYSADDR,
			    DATA_TYPE_UINT64);
			err += nvlist_add_uint64(hcsp,
			    FM_FMRI_HC_SPECIFIC_PHYSADDR,
			    pa);
		}

		if (nvlist_lookup_uint64(hcsp,
		    "asru-"FM_FMRI_HC_SPECIFIC_OFFSET, &offset) == 0) {
			err += nvlist_remove(hcsp,
			    "asru-"FM_FMRI_HC_SPECIFIC_OFFSET,
			    DATA_TYPE_UINT64);
			err += nvlist_add_uint64(hcsp,
			    FM_FMRI_HC_SPECIFIC_OFFSET,
			    offset);
		}
	}

	if (err != 0 || topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) < 0) {
		nvlist_free(asru);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	err = nvlist_add_string(*out, TOPO_PROP_VAL_NAME, TOPO_PROP_ASRU);
	err |= nvlist_add_uint32(*out, TOPO_PROP_VAL_TYPE, TOPO_TYPE_FMRI);
	err |= nvlist_add_nvlist(*out, TOPO_PROP_VAL_VAL, asru);
	if (err != 0) {
		nvlist_free(asru);
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	nvlist_free(asru);

	return (0);
}

static int
set_retnvl(topo_mod_t *mod, nvlist_t **out, const char *retname, uint32_t ret)
{
	nvlist_t *nvl;

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
 * If we're getting called then the question of whether this dimm is plugged
 * in has already been answered.  What we don't know for sure is whether it's
 * the same dimm or a different one plugged in the same slot.  To check, we
 * try and compare the serial numbers on the dimm in the current topology with
 * the serial num from the unum fmri that got passed into this function as the
 * argument.
 *
 */
static int
fmri_replaced(topo_mod_t *mod, tnode_t *node, nvlist_t *unum, int *errp)
{
	tnode_t *dimmnode;
	nvlist_t *resource;
	int rc, err;
	char *old_serial, *curr_serial;
	fmd_agent_hdl_t *hdl;

	/*
	 * If input is a page, return "replaced" if the offset is invalid.
	 */
	if (is_page_fmri(unum) &&
	    (hdl = fmd_agent_open(FMD_AGENT_VERSION)) != NULL) {
		rc = fmd_agent_page_isretired(hdl, unum);
		err = fmd_agent_errno(hdl);
		fmd_agent_close(hdl);

		if (rc == FMD_AGENT_RETIRE_DONE &&
		    err == EINVAL)
			return (FMD_OBJ_STATE_NOT_PRESENT);
	}

	/*
	 * If a serial number for the dimm was available at the time of the
	 * fault, it will have been added as a string to the unum nvlist
	 */
	if (nvlist_lookup_string(unum, FM_FMRI_HC_SERIAL_ID, &old_serial))
		return (FMD_OBJ_STATE_UNKNOWN);

	/*
	 * If the current serial number is available for the DIMM that this rank
	 * belongs to, it will be accessible as a property on the parent (dimm)
	 * node. If there is a serial id in the resource fmri, then use that.
	 * Otherwise fall back to looking for a serial id property in the
	 * protocol group.
	 */
	dimmnode = topo_node_parent(node);
	if (topo_node_resource(dimmnode, &resource, &err) != -1) {
		if (nvlist_lookup_string(resource, FM_FMRI_HC_SERIAL_ID,
		    &curr_serial) == 0) {
			if (strcmp(old_serial, curr_serial) != 0) {
				nvlist_free(resource);
				return (FMD_OBJ_STATE_REPLACED);
			} else {
				nvlist_free(resource);
				return (FMD_OBJ_STATE_STILL_PRESENT);
			}
		}
		nvlist_free(resource);
	}
	if (topo_prop_get_string(dimmnode, TOPO_PGROUP_PROTOCOL,
	    FM_FMRI_HC_SERIAL_ID, &curr_serial, &err) != 0) {
		if (err == ETOPO_PROP_NOENT) {
			return (FMD_OBJ_STATE_UNKNOWN);
		} else {
			*errp = EMOD_NVL_INVAL;
			whinge(mod, NULL, "rank_fmri_present: Unexpected "
			    "error retrieving serial from node");
			return (-1);
		}
	}

	if (strcmp(old_serial, curr_serial) != 0) {
		topo_mod_strfree(mod, curr_serial);
		return (FMD_OBJ_STATE_REPLACED);
	}

	topo_mod_strfree(mod, curr_serial);

	return (FMD_OBJ_STATE_STILL_PRESENT);
}

/*
 * In the event we encounter problems comparing serials or if a comparison isn't
 * possible, we err on the side of caution and set is_present to TRUE.
 */
int
rank_fmri_present(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int is_present, err;

	if (version > TOPO_METH_PRESENT_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	switch (fmri_replaced(mod, node, in, &err)) {
	case FMD_OBJ_STATE_REPLACED:
	case FMD_OBJ_STATE_NOT_PRESENT:
		is_present = 0;
		break;

	case FMD_OBJ_STATE_UNKNOWN:
	case FMD_OBJ_STATE_STILL_PRESENT:
		is_present = 1;
		break;

	default:
		return (topo_mod_seterrno(mod,  err));
	}

	fmri_dprint(mod, "rank_fmri_present", is_present, in);

	return (set_retnvl(mod, out, TOPO_METH_PRESENT_RET, is_present));
}

int
rank_fmri_replaced(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int is_replaced, err;

	if (version > TOPO_METH_REPLACED_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	is_replaced = fmri_replaced(mod, node, in, &err);
	if (is_replaced == -1)
		return (topo_mod_seterrno(mod,  err));

	fmri_dprint(mod, "rank_fmri_replaced", is_replaced, in);

	return (set_retnvl(mod, out, TOPO_METH_REPLACED_RET, is_replaced));
}

static void
fmri_dprint(topo_mod_t *mod, const char *op, uint32_t rc, nvlist_t *fmri)
{
	char *fmristr;
	const char *status;

	if (getenv("TOPOCHIPDBG") == NULL)
		return;

	switch (rc) {
	case FMD_AGENT_RETIRE_DONE:
		status = "sync success";
		break;
	case FMD_AGENT_RETIRE_ASYNC:
		status = "async retiring";
		break;
	case FMD_AGENT_RETIRE_FAIL:
		status = "not retired";
		break;
	default:
		status = "unknown status";
	}
	if (fmri != NULL && topo_mod_nvl2str(mod, fmri, &fmristr) == 0) {
		topo_mod_dprintf(mod, "[%s]: %s => %d (\"%s\")\n", fmristr,
		    op, rc, status);
		topo_mod_strfree(mod, fmristr);
	}
}

struct strand_walk_data {
	tnode_t		*parent;
	fmd_agent_hdl_t	*hdl;
	int		(*func)(fmd_agent_hdl_t *, int, int, int);
	int		err;
	int		done;
	int		fail;
	int		async;
};

static int
strand_walker(topo_mod_t *mod, tnode_t *node, void *pdata)
{
	struct strand_walk_data *swdp = pdata;
	int32_t chipid, coreid, strandid;
	int err, rc;

	/*
	 * Terminate the walk if we reach start-node's sibling
	 */
	if (node != swdp->parent &&
	    topo_node_parent(node) == topo_node_parent(swdp->parent))
		return (TOPO_WALK_TERMINATE);

	if (strcmp(topo_node_name(node), STRAND) != 0)
		return (TOPO_WALK_NEXT);

	if (topo_prop_get_int32(node, PGNAME(STRAND), STRAND_CHIP_ID,
	    &chipid, &err) < 0 ||
	    topo_prop_get_int32(node, PGNAME(STRAND), STRAND_CORE_ID,
	    &coreid, &err) < 0) {
		swdp->err++;
		return (TOPO_WALK_NEXT);
	}
	strandid = topo_node_instance(node);
	rc = swdp->func(swdp->hdl, chipid, coreid, strandid);

	if (rc == FMD_AGENT_RETIRE_DONE)
		swdp->done++;
	else if (rc == FMD_AGENT_RETIRE_FAIL)
		swdp->fail++;
	else if (rc == FMD_AGENT_RETIRE_ASYNC)
		swdp->async++;
	else
		swdp->err++;

	if (getenv("TOPOCHIPDBG") != NULL) {
		const char *op;

		if (swdp->func == fmd_agent_cpu_retire)
			op = "retire";
		else if (swdp->func == fmd_agent_cpu_unretire)
			op = "unretire";
		else if (swdp->func == fmd_agent_cpu_isretired)
			op = "check status";
		else
			op = "unknown op";

		topo_mod_dprintf(mod, "%s cpu (%d:%d:%d): rc = %d, err = %s\n",
		    op, (int)chipid, (int)coreid, (int)strandid, rc,
		    fmd_agent_errmsg(swdp->hdl));
	}

	return (TOPO_WALK_NEXT);
}

static int
walk_strands(topo_mod_t *mod, struct strand_walk_data *swdp, tnode_t *parent,
    int (*func)(fmd_agent_hdl_t *, int, int, int))
{
	topo_walk_t *twp;
	int err;

	swdp->parent = parent;
	swdp->func = func;
	swdp->err = swdp->done = swdp->fail = swdp->async = 0;
	if ((swdp->hdl = fmd_agent_open(FMD_AGENT_VERSION)) == NULL) {
		swdp->fail++;
		return (0);
	}

	twp = topo_mod_walk_init(mod, parent, strand_walker, swdp, &err);
	if (twp == NULL) {
		fmd_agent_close(swdp->hdl);
		return (-1);
	}

	err = topo_walk_step(twp, TOPO_WALK_CHILD);
	topo_walk_fini(twp);
	fmd_agent_close(swdp->hdl);

	if (err == TOPO_WALK_ERR || swdp->err > 0)
		return (-1);

	return (0);
}

/* ARGSUSED */
int
retire_strands(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	struct strand_walk_data swd;
	uint32_t rc;

	if (version > TOPO_METH_RETIRE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (walk_strands(mod, &swd, node, fmd_agent_cpu_retire) == -1)
		return (-1);

	if (swd.fail > 0)
		rc = FMD_AGENT_RETIRE_FAIL;
	else if (swd.async > 0)
		rc = FMD_AGENT_RETIRE_ASYNC;
	else
		rc = FMD_AGENT_RETIRE_DONE;

	return (set_retnvl(mod, out, TOPO_METH_RETIRE_RET, rc));
}

/* ARGSUSED */
int
unretire_strands(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	struct strand_walk_data swd;
	uint32_t rc;

	if (version > TOPO_METH_UNRETIRE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (walk_strands(mod, &swd, node, fmd_agent_cpu_unretire) == -1)
		return (-1);

	if (swd.fail > 0)
		rc = FMD_AGENT_RETIRE_FAIL;
	else if (swd.async > 0)
		rc = FMD_AGENT_RETIRE_ASYNC;
	else
		rc = FMD_AGENT_RETIRE_DONE;

	return (set_retnvl(mod, out, TOPO_METH_UNRETIRE_RET, rc));
}

/* ARGSUSED */
int
service_state_strands(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	struct strand_walk_data swd;
	uint32_t rc;

	if (version > TOPO_METH_SERVICE_STATE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (walk_strands(mod, &swd, node, fmd_agent_cpu_isretired) == -1)
		return (-1);

	if (swd.done > 0)
		rc = (swd.fail + swd.async > 0) ? FMD_SERVICE_STATE_DEGRADED :
		    FMD_SERVICE_STATE_UNUSABLE;
	else if (swd.async > 0)
		rc = FMD_SERVICE_STATE_ISOLATE_PENDING;
	else if (swd.fail > 0)
		rc = FMD_SERVICE_STATE_OK;
	else
		rc = FMD_SERVICE_STATE_UNKNOWN;

	return (set_retnvl(mod, out, TOPO_METH_SERVICE_STATE_RET, rc));
}

/* ARGSUSED */
int
unusable_strands(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	struct strand_walk_data swd;
	uint32_t rc;

	if (version > TOPO_METH_UNUSABLE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (walk_strands(mod, &swd, node, fmd_agent_cpu_isretired) == -1)
		return (-1);

	rc = (swd.fail + swd.async > 0 || swd.done == 0) ? 0 : 1;

	return (set_retnvl(mod, out, TOPO_METH_UNUSABLE_RET, rc));
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

/* ARGSUSED */
int
ntv_page_retire(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	fmd_agent_hdl_t *hdl;
	uint32_t rc = FMD_AGENT_RETIRE_FAIL;

	if (version > TOPO_METH_RETIRE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));
	if (is_page_fmri(in)) {
		if ((hdl = fmd_agent_open(FMD_AGENT_VERSION)) != NULL) {
			rc = fmd_agent_page_retire(hdl, in);
			fmd_agent_close(hdl);
		}
	}
	fmri_dprint(mod, "ntv_page_retire", rc, in);
	return (set_retnvl(mod, out, TOPO_METH_RETIRE_RET, rc));
}

/* ARGSUSED */
int
ntv_page_unretire(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	fmd_agent_hdl_t *hdl;
	uint32_t rc = FMD_AGENT_RETIRE_FAIL;

	if (version > TOPO_METH_UNRETIRE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));
	if (is_page_fmri(in)) {
		if ((hdl = fmd_agent_open(FMD_AGENT_VERSION)) != NULL) {
			rc = fmd_agent_page_unretire(hdl, in);
			fmd_agent_close(hdl);
		}
	}
	fmri_dprint(mod, "ntv_page_unretire", rc, in);
	return (set_retnvl(mod, out, TOPO_METH_UNRETIRE_RET, rc));
}

/* ARGSUSED */
int
ntv_page_service_state(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	fmd_agent_hdl_t *hdl;
	uint32_t rc = FMD_SERVICE_STATE_UNKNOWN;

	if (version > TOPO_METH_SERVICE_STATE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));
	if (is_page_fmri(in)) {
		if ((hdl = fmd_agent_open(FMD_AGENT_VERSION)) != NULL) {
			rc = fmd_agent_page_isretired(hdl, in);
			fmd_agent_close(hdl);
			if (rc == FMD_AGENT_RETIRE_DONE)
				rc = FMD_SERVICE_STATE_UNUSABLE;
			else if (rc == FMD_AGENT_RETIRE_FAIL)
				rc = FMD_SERVICE_STATE_OK;
			else if (rc == FMD_AGENT_RETIRE_ASYNC)
				rc = FMD_SERVICE_STATE_ISOLATE_PENDING;
		}
	}

	topo_mod_dprintf(mod, "ntv_page_service_state: rc = %u\n", rc);
	return (set_retnvl(mod, out, TOPO_METH_SERVICE_STATE_RET, rc));
}

/* ARGSUSED */
int
ntv_page_unusable(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	fmd_agent_hdl_t *hdl;
	uint32_t rc = FMD_AGENT_RETIRE_FAIL;

	if (version > TOPO_METH_UNUSABLE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));
	if (is_page_fmri(in)) {
		if ((hdl = fmd_agent_open(FMD_AGENT_VERSION)) != NULL) {
			rc = fmd_agent_page_isretired(hdl, in);
			fmd_agent_close(hdl);
		}
	}
	topo_mod_dprintf(mod, "ntv_page_unusable: rc = %u\n", rc);
	return (set_retnvl(mod, out, TOPO_METH_UNUSABLE_RET,
	    rc == FMD_AGENT_RETIRE_DONE ? 1 : 0));
}

/*
 * Determine whether or not we believe a chip has been replaced. While it's
 * tempting to just do a straight up comparison of the FMRI and its serial
 * number, things are not that straightforward.
 *
 * The presence of a serial number on the CPU is not always guaranteed. It is
 * possible that systems firmware can hide the information required to generate
 * a synthesized serial number or that it is strictly not present. As such, we
 * will only declare something replaced when both the old and current resource
 * have a serial number present. If it is missing for whatever reason, then we
 * cannot assume anything about a replacement having occurred.
 *
 * This logic applies regardless of whether or not we have an FM-aware SMBIOS.
 */
int
chip_fmri_replaced(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *rsrc = NULL;
	int err, ret;
	char *old_serial, *new_serial;

	if (version > TOPO_METH_REPLACED_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_node_resource(node, &rsrc, &err) == -1) {
		return (topo_mod_seterrno(mod, err));
	}

	if (nvlist_lookup_string(rsrc, FM_FMRI_HC_SERIAL_ID,
	    &new_serial) != 0) {
		ret = FMD_OBJ_STATE_UNKNOWN;
		goto out;
	}

	if (nvlist_lookup_string(in, FM_FMRI_HC_SERIAL_ID, &old_serial) != 0) {
		ret = FMD_OBJ_STATE_UNKNOWN;
		goto out;
	}

	if (strcmp(old_serial, new_serial) == 0) {
		ret = FMD_OBJ_STATE_STILL_PRESENT;
	} else {
		ret = FMD_OBJ_STATE_REPLACED;
	}

out:
	nvlist_free(rsrc);
	return (set_retnvl(mod, out, TOPO_METH_REPLACED_RET, ret));
}

const char *
get_chip_brand(topo_mod_t *mod, kstat_ctl_t *kc, int32_t chipid)
{
	kstat_t *ksp;
	kstat_named_t *ks;

	if ((ksp = kstat_lookup(kc, "cpu_info", chipid, NULL)) == NULL ||
	    kstat_read(kc, ksp, NULL) == -1 ||
	    (ks = kstat_data_lookup(ksp, "brand")) == NULL) {
		topo_mod_dprintf(mod, "failed to read stat cpu_info:%d:brand",
		    chipid);
		return (NULL);
	}
	return (topo_mod_strdup(mod, ks->value.str.addr.ptr));
}
