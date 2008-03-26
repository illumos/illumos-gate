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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support function for the i86pc chip enumerator
 */

#include <sys/types.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/fm/protocol.h>

#include "chip.h"

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
 * Lookup string data named pname in the given kstat_t and add that
 * as property named pname in the given property group pgname on the indicated
 * topo node.  Fill pvalp with a pointer to the string value, valid until
 * kstat_close is called (or the given kstat_t is otherwise invalidated).
 */
int
add_kstat_strprop(topo_mod_t *mod, tnode_t *node, kstat_t *ksp,
    const char *pgname, const char *pname, const char **pvalp)
{
	const char *pval;
	kstat_named_t *k;
	int err = 0;

	if ((k = kstat_data_lookup(ksp, (char *)pname)) == NULL)
		return (-1);
	pval = k->value.str.addr.ptr;

	if (topo_prop_set_string(node, pgname, pname,
	    TOPO_PROP_IMMUTABLE, pval, &err) == 0) {
		if (pvalp)
			*pvalp = pval;
		return (0);
	} else {
		whinge(mod, &err, "chip_strprop: failed to add '%s'\n",
		    pname);
		return (-1);
	}
}

/*
 * Lookup an int32 item named pname in the given kstat_t and add that
 * as property named pname in the given property group pgname on the indicated
 * topo node.  Fill pvalp with the property value.
 */
int
add_kstat_longprop(topo_mod_t *mod, tnode_t *node, kstat_t *ksp,
    const char *pgname, const char *pname, int32_t *pvalp)
{
	kstat_named_t *k;
	int32_t pval;
	int err;

	if ((k = kstat_data_lookup(ksp, (char *)pname)) == NULL)
		return (-1);
	pval = k->value.l;

	if (topo_prop_set_int32(node, pgname, pname,
	    TOPO_PROP_IMMUTABLE, pval, &err) == 0) {
		if (pvalp)
			*pvalp = pval;
		return (0);
	} else {
		whinge(mod, &err, "chip_longprop: failed to add '%s'\n",
		    pname);
		return (-1);
	}
}

/*
 * In a given kstat_t lookup a variable number of int32 properties named in
 * const char * varargs and each each in the given property group on the
 * node.  Fill an array of the retrieved values.
 */
int
add_kstat_longprops(topo_mod_t *mod, tnode_t *node, kstat_t *ksp,
    const char *pgname, int32_t *pvalap, ...)
{
	const char *pname;
	va_list ap;
	int nerr = 0;

	va_start(ap, pvalap);
	while ((pname = va_arg(ap, const char *)) != NULL) {
		if (add_kstat_longprop(mod, node, ksp, pgname, pname,
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
	return (nvl != NULL ? 0 : -1);	/* caller must free nvlist */
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

/*
 * Construct a mem scheme FMRI for the given unum string; the caller must
 * free the allocated nvlist with nvlist_free().
 */
nvlist_t *
mem_fmri_create(topo_mod_t *mod, const char *unum)
{
	nvlist_t *asru;

	if (topo_mod_nvalloc(mod, &asru, NV_UNIQUE_NAME) != 0)
		return (NULL);

	if (nvlist_add_string(asru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_MEM) != 0 ||
	    nvlist_add_uint8(asru, FM_VERSION, FM_MEM_SCHEME_VERSION) != 0 ||
	    nvlist_add_string(asru, FM_FMRI_MEM_UNUM, unum) != 0) {
		nvlist_free(asru);
		return (NULL);
	}

	return (asru);
}

/*
 * Registered method for asru computation for rank nodes.  The 'node'
 * argument identifies the node for which we seek an asru.  The 'in'
 * argument is used to select which asru we will return, as follows:
 *
 * - the node name must be "dimm" or "rank"
 * - if 'in' is NULL then return any statically defined asru for this node
 * - if 'in' is an "hc" scheme fmri then we construct a "mem" scheme asru
 *   with unum being the hc path to the dimm or rank (this method is called
 *   as part of dynamic asru computation for rank nodes only, but
 *   it is also called directly to construct a "mem" scheme asru for a dimm
 *   node)
 * - if 'in' in addition includes an hc-specific member which specifies
 *   asru-physaddr or asru-offset then these are includes in the "mem" scheme
 *   asru as additional members physaddr and offset
 */
int
mem_asru_create(topo_mod_t *mod, nvlist_t *fmri, nvlist_t **asru)
{
	int incl_pa = 0, incl_offset = 0;
	nvlist_t *hcsp, *ap;
	char *unum, *scheme;
	uint64_t pa, offset;
	int err = 0;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0 ||
	    strcmp(scheme, FM_FMRI_SCHEME_HC) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	if (nvlist_lookup_nvlist(fmri, FM_FMRI_HC_SPECIFIC, &hcsp) == 0) {
		if (nvlist_lookup_uint64(hcsp, "asru-"FM_FMRI_MEM_PHYSADDR,
		    &pa) == 0)
			incl_pa = 1;

		if (nvlist_lookup_uint64(hcsp, "asru-"FM_FMRI_MEM_OFFSET,
		    &offset) == 0)
			incl_offset = 1;
	}

	/* use 'fmri' to obtain resource path;  could use node resource */
	if (topo_mod_nvl2str(mod, fmri, &unum) < 0)
		return (-1);  /* mod errno set */

	ap = mem_fmri_create(mod, unum);
	topo_mod_strfree(mod, unum);
	if (ap == NULL)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (incl_pa)
		err += nvlist_add_uint64(ap, FM_FMRI_MEM_PHYSADDR, pa) != 0;
	if (incl_offset)
		err += nvlist_add_uint64(ap, FM_FMRI_MEM_OFFSET, offset) != 0;

	if (err != 0) {
		nvlist_free(ap);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*asru = ap;

	return (0);
}

/*ARGSUSED*/
int
mem_asru_compute(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *asru;
	nvlist_t *args, *pargs;
	int err;

	if (strcmp(topo_node_name(node), RANK_NODE_NAME) != 0 &&
	    strcmp(topo_node_name(node), DIMM_NODE_NAME) != 0 &&
	    strcmp(topo_node_name(node), CS_NODE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	if ((err = nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs)) != 0) {
		if (err == ENOENT) {
			if (topo_mod_nvdup(mod, args, &asru) < 0)
				return (topo_mod_seterrno(mod, EMOD_NOMEM));
		} else {
			return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
		}
	} else if (mem_asru_create(mod, pargs, &asru) != 0) {
		return (-1); /* mod errno already set */
	}

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) < 0) {
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

/*
 * If we're getting called then the question of whether this dimm is plugged
 * in has already been answered.  What we don't know for sure is whether it's
 * the same dimm or a different one plugged in the same slot.  To check, we
 * try and compare the serial numbers on the dimm in the current topology with
 * the serial num from the unum fmri that got passed into this function as the
 * argument.
 *
 * In the event we encounter problems comparing serials or if a comparison isn't
 * possible, we err on the side of caution and set is_present to TRUE.
 */
/* ARGSUSED */
int
rank_fmri_present(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	tnode_t *dimmnode;
	int err, is_present = 1;
	nvlist_t *unum;
	char *curr_serial, *old_serial = NULL;

	/*
	 * If a serial number for the dimm was available at the time of the
	 * fault, it will have been added as a string to the unum nvlist
	 */
	unum = in;
	if (nvlist_lookup_string(unum, FM_FMRI_HC_SERIAL_ID, &old_serial) != 0)
		goto done;

	/*
	 * If the current serial number is available for the DIMM that this rank
	 * belongs to, it will be accessible as a property on the parent (dimm)
	 * node.
	 */
	dimmnode = topo_node_parent(node);
	if (topo_prop_get_string(dimmnode, TOPO_PGROUP_PROTOCOL,
	    FM_FMRI_HC_SERIAL_ID, &curr_serial, &err) != 0) {
		if (err != ETOPO_PROP_NOENT) {
			whinge(mod, &err, "rank_fmri_present: Unexpected error "
			    "retrieving serial from node");
			return (topo_mod_seterrno(mod,  EMOD_NVL_INVAL));
		} else
			goto done;
	}

	if (strcmp(old_serial, curr_serial) != 0)
		is_present = 0;

	topo_mod_strfree(mod, curr_serial);
done:
	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) < 0) {
		whinge(mod, &err,
		    "rank_fmri_present: failed to allocate nvlist!");
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	if (nvlist_add_uint32(*out, TOPO_METH_PRESENT_RET, is_present) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}
