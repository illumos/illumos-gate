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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <alloca.h>
#include <kstat.h>
#include <fcntl.h>
#include <errno.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/processor.h>
#include <sys/param.h>
#include <sys/fm/protocol.h>
#include <sys/systeminfo.h>
#include <sys/mc.h>
#include <sys/mc_amd.h>
#include <fm/topo_mod.h>

#include "chip.h"

#ifndef MAX
#define	MAX(a, b)	((a) > (b) ? (a) : (b))
#endif

#define	MAX_DIMMNUM	7
#define	MAX_CSNUM	7

/*
 * Enumerates the processing chips, or sockets, (as distinct from cores) in a
 * system.  For each chip found, the necessary nodes (one or more cores, and
 * possibly a memory controller) are constructed underneath.
 */

static int chip_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);

static int mem_asru_compute(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_modops_t chip_ops =
	{ chip_enum, NULL};
static const topo_modinfo_t chip_info =
	{ CHIP_NODE_NAME, FM_FMRI_SCHEME_HC, CHIP_VERSION, &chip_ops };

static const topo_pgroup_info_t cs_pgroup =
	{ PGNAME(CS), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t dimm_pgroup =
	{ PGNAME(DIMM), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t mc_pgroup =
	{ PGNAME(MCT), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t chip_pgroup =
	{ PGNAME(CHIP), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t cpu_pgroup =
	{ PGNAME(CPU), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t rank_pgroup =
	{ PGNAME(RANK), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t chan_pgroup =
	{ PGNAME(CHAN), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

const topo_method_t rank_methods[] = {
	{ TOPO_METH_ASRU_COMPUTE, TOPO_METH_ASRU_COMPUTE_DESC,
	    TOPO_METH_ASRU_COMPUTE_VERSION, TOPO_STABILITY_INTERNAL,
	    mem_asru_compute },
	{ NULL }
};

const topo_method_t dimm_methods[] = {
	{ SIMPLE_DIMM_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, simple_dimm_label},
	{ SIMPLE_DIMM_LBL_MP, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, simple_dimm_label_mp},
	{ SEQ_DIMM_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, seq_dimm_label},
	{ NULL }
};

const topo_method_t chip_methods[] = {
	{ SIMPLE_CHIP_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, simple_chip_label},
	{ G4_CHIP_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, g4_chip_label},
	{ NULL }
};

static nvlist_t *cs_fmri[MC_CHIP_NCS];

static void
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

int
_topo_init(topo_mod_t *mod)
{
	chip_t *chip;

	if (getenv("TOPOCHIPDBG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing chip enumerator\n");

	if ((chip = topo_mod_zalloc(mod, sizeof (chip_t))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	if ((chip->chip_kc = kstat_open()) == NULL) {
		whinge(mod, NULL, "kstat_open failed: %s\n",
		    strerror(errno));
		topo_mod_free(mod, chip, sizeof (chip_t));
		return (topo_mod_seterrno(mod, errno));
	}

	chip->chip_ncpustats = sysconf(_SC_CPUID_MAX);
	if ((chip->chip_cpustats = topo_mod_zalloc(mod, (
	    chip->chip_ncpustats + 1) * sizeof (kstat_t *))) == NULL) {
		(void) kstat_close(chip->chip_kc);
		topo_mod_free(mod, chip, sizeof (chip_t));
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	if (topo_mod_register(mod, &chip_info, TOPO_VERSION) != 0) {
		whinge(mod, NULL, "failed to register hc: "
		    "%s\n", topo_mod_errmsg(mod));
		topo_mod_free(mod, chip->chip_cpustats,
		    (chip->chip_ncpustats + 1) * sizeof (kstat_t *));
		(void) kstat_close(chip->chip_kc);
		topo_mod_free(mod, chip, sizeof (chip_t));
		return (-1); /* mod errno set */
	}
	topo_mod_setspecific(mod, (void *)chip);

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	chip_t *chip = topo_mod_getspecific(mod);

	if (chip->chip_cpustats != NULL)
		topo_mod_free(mod, chip->chip_cpustats,
		    (chip->chip_ncpustats + 1) * sizeof (kstat_t *));

	(void) kstat_close(chip->chip_kc);
	topo_mod_free(mod, chip, sizeof (chip_t));

	topo_mod_unregister(mod);
}

static int
add_kstat_strprop(topo_mod_t *mod, tnode_t *node, kstat_t *ksp,
    const char *pgname, const char *pname)
{
	int err = 0;
	kstat_named_t *k;

	if ((k = kstat_data_lookup(ksp, (char *)pname)) == NULL)
		return (-1);

	if (topo_prop_set_string(node, pgname, pname,
	    TOPO_PROP_IMMUTABLE, k->value.str.addr.ptr, &err) == 0) {
		return (0);
	} else {
		whinge(mod, &err, "chip_strprop: failed to add '%s'\n",
		    pname);
		return (-1);
	}
}

static int
add_kstat_longprop(topo_mod_t *mod, tnode_t *node, kstat_t *ksp,
    const char *pgname, const char *pname)
{
	int err;
	kstat_named_t *k;

	if ((k = kstat_data_lookup(ksp, (char *)pname)) == NULL)
		return (-1);

	if (topo_prop_set_int32(node, pgname, pname,
	    TOPO_PROP_IMMUTABLE, k->value.l, &err) == 0) {
		return (0);
	} else {
		whinge(mod, &err, "chip_longprop: failed to add '%s'\n",
		    pname);
		return (-1);
	}
}

static int
add_kstat_longprops(topo_mod_t *mod, tnode_t *node, kstat_t *ksp,
    const char *pgname, ...)
{
	const char *pname;
	va_list ap;
	int nerr = 0;

	va_start(ap, pgname);
	while ((pname = va_arg(ap, const char *)) != NULL) {
		if (add_kstat_longprop(mod, node, ksp, pgname, pname) != 0)
			nerr++;		/* have whinged elsewhere */
	}
	va_end(ap);

	return (nerr == 0 ? 0 : -1);
}

static int
mkrsrc(topo_mod_t *mod, tnode_t *pnode, const char *name, int inst,
    nvlist_t *auth, nvlist_t **nvl)
{
	*nvl = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION, name,
	    inst, NULL, auth, NULL, NULL, NULL);
	return (nvl != NULL ? 0 : -1);	/* caller must free nvlist */
}

static nvlist_t *
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

static nvlist_t *
mem_fmri_create(topo_mod_t *mod)
{
	nvlist_t *asru;

	if (topo_mod_nvalloc(mod, &asru, NV_UNIQUE_NAME) != 0)
		return (NULL);

	if (nvlist_add_string(asru, FM_FMRI_SCHEME, FM_FMRI_SCHEME_MEM) != 0 ||
	    nvlist_add_uint8(asru, FM_VERSION, FM_MEM_SCHEME_VERSION) != 0) {
		nvlist_free(asru);
		return (NULL);
	}

	return (asru);
}

static int
cpu_create(topo_mod_t *mod, tnode_t *pnode, const char *name, int chipid,
    chip_t *chip, nvlist_t *auth)
{
	kstat_named_t *k;
	nvlist_t *fmri, *asru;
	tnode_t *cnode;
	int err, nerr = 0;
	int clogid, cpuid;

	if (topo_node_range_create(mod, pnode, name, 0,
	    chip->chip_ncpustats) < 0)
		return (-1);

	for (cpuid = 0; cpuid <= chip->chip_ncpustats; cpuid++) {
		if (chip->chip_cpustats[cpuid] == NULL)
			continue;

		/*
		 * The chip_id in the cpu_info kstat numbers the individual
		 * chips from 0 to #chips - 1.
		 */
		if ((k = kstat_data_lookup(chip->chip_cpustats[cpuid],
		    "chip_id")) == NULL) {
			whinge(mod, &nerr, "cpu_create: chip_id lookup via "
			    "kstats failed\n");
			continue;
		}

		if (k->value.l != chipid)
			continue;	/* not an error */

		/*
		 * The clog_id in the cpu_info kstat numbers the virtual
		 * processors of a single chip;  these may be separate
		 * processor cores, or they may be hardware threads/strands
		 * of individual cores.
		 *
		 * The core_id in the cpu_info kstat tells us which cpus
		 * share the same core - i.e., are hardware strands of the
		 * same core.  This enumerator does not distinguish stranded
		 * cores so core_id is unused.
		 */
		if ((k = kstat_data_lookup(chip->chip_cpustats[cpuid],
		    "clog_id")) == NULL) {
			whinge(mod, &nerr, "cpu_create: clog_id lookup via "
			    "kstats failed\n");
			continue;
		}
		clogid = k->value.l;

		if (mkrsrc(mod, pnode, name, clogid, auth, &fmri) != 0) {
			whinge(mod, &nerr, "cpu_create: mkrsrc failed\n");
			continue;
		}

		if ((cnode = topo_node_bind(mod, pnode, name, clogid, fmri))
		    == NULL) {
			whinge(mod, &nerr, "cpu_create: node bind failed\n");
			nvlist_free(fmri);
			continue;
		}
		nvlist_free(fmri);

		if ((asru = cpu_fmri_create(mod, cpuid, NULL, 0)) != NULL) {
			(void) topo_node_asru_set(cnode, asru, 0, &err);
			nvlist_free(asru);
		} else {
			whinge(mod, &nerr, "cpu_create: cpu_fmri_create "
			    "failed\n");
		}
		(void) topo_node_fru_set(cnode, NULL, 0, &err);

		(void) topo_pgroup_create(cnode, &cpu_pgroup, &err);

		(void) topo_prop_set_uint32(cnode, PGNAME(CPU), "cpuid",
		    TOPO_PROP_IMMUTABLE, cpuid, &err);

		if (add_kstat_longprops(mod, cnode, chip->chip_cpustats[cpuid],
		    PGNAME(CPU), CPU_CHIP_ID, CPU_CORE_ID, CPU_CLOG_ID,
		    NULL) != 0)
			nerr++;		/* have whinged elsewhere */
	}

	return (nerr == 0 ? 0 : -1);
}

static int
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

static int
chip_htconfig(topo_mod_t *mod, tnode_t *cnode, nvlist_t *htnvl)
{
	nvpair_t *nvp;
	int nerr = 0;

	if (strcmp(topo_node_name(cnode), CHIP_NODE_NAME) != 0) {
		whinge(mod, &nerr, "chip_htconfig: must pass a chip node!");
		return (-1);
	}

	for (nvp = nvlist_next_nvpair(htnvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(htnvl, nvp)) {
		if (nvprop_add(mod, nvp, PGNAME(CHIP), cnode) != 0)
			nerr++;
	}

	return (nerr == 0 ? 0 : -1);
}

static int
dramchan_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    nvlist_t *auth)
{
	tnode_t *chnode;
	nvlist_t *fmri;
	char *socket;
	int i, nchan;
	int err, nerr = 0;

	/*
	 * We will enumerate the number of channels present even if only
	 * channel A is in use (i.e., running in 64-bit mode).  Only
	 * the socket 754 package has a single channel.
	 */
	if (topo_prop_get_string(pnode, PGNAME(MCT), "socket",
	    &socket, &err) != 0)
		return (-1);

	if (strcmp(socket, "Socket 754") == 0)
		nchan = 1;
	else
		nchan = 2;

	topo_mod_strfree(mod, socket);

	if (topo_node_range_create(mod, pnode, name, 0, nchan - 1) < 0)
		return (-1);

	for (i = 0; i < nchan; i++) {
		if (mkrsrc(mod, pnode, name, i, auth, &fmri) != 0) {
			whinge(mod, &nerr, "dramchan_create: mkrsrc "
			    "failed\n");
			continue;
		}

		if ((chnode = topo_node_bind(mod, pnode, name, i, fmri))
		    == NULL) {
			nvlist_free(fmri);
			whinge(mod, &nerr, "dramchan_create: node bind "
			    "failed\n");
			continue;
		}

		nvlist_free(fmri);

		(void) topo_pgroup_create(chnode, &chan_pgroup, &err);

		(void) topo_prop_set_string(chnode, PGNAME(CHAN), "channel",
		    TOPO_PROP_IMMUTABLE, i == 0 ? "A" : "B", &err);
	}

	return (nerr == 0 ? 0 : -1);
}

static int
cs_create(topo_mod_t *mod, tnode_t *pnode, const char *name, nvlist_t *mc,
    nvlist_t *auth)
{
	int i, err, nerr = 0;
	nvpair_t *nvp;
	tnode_t *csnode;
	nvlist_t *fmri, **csarr = NULL;
	uint64_t csnum;
	uint_t ncs;

	if (nvlist_lookup_nvlist_array(mc, "cslist", &csarr, &ncs) != 0)
		return (-1);

	if (ncs == 0)
		return (0);	/* no chip-selects configured on this node */

	if (topo_node_range_create(mod, pnode, name, 0, MAX_CSNUM) < 0)
		return (-1);

	for (i = 0; i < ncs; i++) {
		if (nvlist_lookup_uint64(csarr[i], "num", &csnum) != 0) {
			whinge(mod, &nerr, "cs_create: cs num property "
			    "missing\n");
			continue;
		}

		if (mkrsrc(mod, pnode, name, csnum, auth, &fmri) != 0) {
			whinge(mod, &nerr, "cs_create: mkrsrc failed\n");
			continue;
		}

		if ((csnode = topo_node_bind(mod, pnode, name, csnum, fmri))
		    == NULL) {
			nvlist_free(fmri);
			whinge(mod, &nerr, "cs_create: node bind failed\n");
			continue;
		}

		cs_fmri[csnum] = fmri;	/* nvlist will be freed in mc_create */

		(void) topo_node_asru_set(csnode, fmri, 0, &err);

		(void) topo_pgroup_create(csnode, &cs_pgroup, &err);

		for (nvp = nvlist_next_nvpair(csarr[i], NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(csarr[i], nvp)) {
			nerr += nvprop_add(mod, nvp, PGNAME(CS), csnode);
		}
	}

	return (nerr == 0 ? 0 : -1);
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
 *   as part of dynamic asru computation for rank nodes only, but dimm_create
 *   also calls it directly to construct a "mem" scheme asru for a dimm node)
 * - if 'in' in addition includes an hc-specific member which specifies
 *   asru-physaddr or asru-offset then these are includes in the "mem" scheme
 *   asru as additional members physaddr and offset
 */
static int
mem_asru_create(topo_mod_t *mod, nvlist_t *fmri, nvlist_t **asru)
{
	int incl_pa = 0, incl_offset = 0;
	nvlist_t *hcsp, *ap;
	char *unum, *scheme;
	uint64_t pa, offset;
	int err;

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

	if ((ap = mem_fmri_create(mod)) == NULL) {
		topo_mod_strfree(mod, unum);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	err = nvlist_add_string(ap, FM_FMRI_MEM_UNUM, unum);
	if (incl_pa)
		err |= nvlist_add_uint64(ap, FM_FMRI_MEM_PHYSADDR, pa);
	if (incl_offset)
		err |= nvlist_add_uint64(ap, FM_FMRI_MEM_OFFSET, offset);

	topo_mod_strfree(mod, unum);
	if (err != 0) {
		nvlist_free(ap);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*asru = ap;

	return (0);
}

/*ARGSUSED*/
static int
mem_asru_compute(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *asru;
	nvlist_t *args, *pargs;
	int err;

	if (strcmp(topo_node_name(node), RANK_NODE_NAME) != 0 &&
	    strcmp(topo_node_name(node), DIMM_NODE_NAME) != 0)
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

static int
rank_create(topo_mod_t *mod, tnode_t *pnode, nvlist_t *dimmnvl, nvlist_t *auth)
{
	uint64_t *csnumarr;
	char **csnamearr;
	uint_t ncs, ncsname;
	tnode_t *ranknode;
	nvlist_t *fmri, *pfmri = NULL;
	uint64_t dsz, rsz;
	int nerr = 0;
	int err;
	int i;

	if (nvlist_lookup_uint64_array(dimmnvl, "csnums", &csnumarr,
	    &ncs) != 0 || nvlist_lookup_string_array(dimmnvl, "csnames",
	    &csnamearr, &ncsname) != 0 || ncs != ncsname) {
		whinge(mod, &nerr, "rank_create: "
		    "csnums/csnames extraction failed\n");
		return (nerr);
	}

	if (topo_node_resource(pnode, &pfmri, &err) < 0) {
		whinge(mod, &nerr, "rank_create: parent fmri lookup "
		    "failed\n");
		return (nerr);
	}

	if (topo_node_range_create(mod, pnode, RANK_NODE_NAME, 0, ncs) < 0) {
		whinge(mod, &nerr, "rank_create: range create failed\n");
		nvlist_free(pfmri);
		return (nerr);
	}

	if (topo_prop_get_uint64(pnode, PGNAME(DIMM), "size", &dsz,
	    &err) == 0) {
		rsz = dsz / ncs;
	} else {
		whinge(mod, &nerr, "rank_create: parent dimm has no size\n");
		return (nerr);
	}

	for (i = 0; i < ncs; i++) {
		if (mkrsrc(mod, pnode, RANK_NODE_NAME, i, auth, &fmri) < 0) {
			whinge(mod, &nerr, "rank_create: mkrsrc failed\n");
			continue;
		}

		if ((ranknode = topo_node_bind(mod, pnode, RANK_NODE_NAME, i,
		    fmri)) == NULL) {
			nvlist_free(fmri);
			whinge(mod, &nerr, "rank_create: node bind "
			    "failed\n");
			continue;
		}

		nvlist_free(fmri);

		(void) topo_node_fru_set(ranknode, pfmri, 0, &err);

		/*
		 * If a rank is faulted the asru is the associated
		 * chip-select, but if a page within a rank is faulted
		 * the asru is just that page.  Hence the dual preconstructed
		 * and computed ASRU.
		 */
		if (topo_method_register(mod, ranknode, rank_methods) < 0)
			whinge(mod, &nerr, "rank_create: "
			    "topo_method_register failed");

		(void) topo_node_asru_set(ranknode, cs_fmri[csnumarr[i]],
		    TOPO_ASRU_COMPUTE, &err);

		(void) topo_pgroup_create(ranknode, &rank_pgroup, &err);

		(void) topo_prop_set_uint64(ranknode, PGNAME(RANK), "size",
		    TOPO_PROP_IMMUTABLE, rsz, &err);

		(void) topo_prop_set_string(ranknode, PGNAME(RANK), "csname",
		    TOPO_PROP_IMMUTABLE, csnamearr[i], &err);

		(void) topo_prop_set_uint64(ranknode, PGNAME(RANK), "csnum",
		    TOPO_PROP_IMMUTABLE, csnumarr[i], &err);
	}

	nvlist_free(pfmri);

	return (nerr);
}

static int
dimm_create(topo_mod_t *mod, tnode_t *pnode, const char *name, nvlist_t *mc,
    nvlist_t *auth)
{
	int i, err, nerr = 0;
	nvpair_t *nvp;
	tnode_t *dimmnode;
	nvlist_t *fmri, *asru, **dimmarr = NULL;
	uint64_t num;
	uint_t ndimm;

	if (nvlist_lookup_nvlist_array(mc, "dimmlist", &dimmarr, &ndimm) != 0) {
		whinge(mod, NULL, "dimm_create: dimmlist lookup failed\n");
		return (-1);
	}

	if (ndimm == 0)
		return (0);	/* no dimms present on this node */

	if (topo_node_range_create(mod, pnode, name, 0, MAX_DIMMNUM) < 0) {
		whinge(mod, NULL, "dimm_create: range create failed\n");
		return (-1);
	}

	for (i = 0; i < ndimm; i++) {
		if (nvlist_lookup_uint64(dimmarr[i], "num", &num) != 0) {
			whinge(mod, &nerr, "dimm_create: dimm num property "
			    "missing\n");
			continue;
		}

		if (mkrsrc(mod, pnode, name, num, auth, &fmri) < 0) {
			whinge(mod, &nerr, "dimm_create: mkrsrc failed\n");
			continue;
		}

		if ((dimmnode = topo_node_bind(mod, pnode, name, num, fmri))
		    == NULL) {
			nvlist_free(fmri);
			whinge(mod, &nerr, "dimm_create: node bind "
			    "failed\n");
			continue;
		}

		if (topo_method_register(mod, dimmnode, dimm_methods) < 0)
			whinge(mod, &nerr, "dimm_create: "
			    "topo_method_register failed");

		/*
		 * Use the mem computation method directly to publish the asru
		 * in the "mem" scheme.
		 */
		if (mem_asru_create(mod, fmri, &asru) == 0) {
			(void) topo_node_asru_set(dimmnode, asru, 0, &err);
			nvlist_free(asru);
		} else {

			nvlist_free(fmri);
			whinge(mod, &nerr, "dimm_create: mem_asru_compute "
			    "failed\n");
			continue;
		}

		(void) topo_node_fru_set(dimmnode, fmri, 0, &err);

		nvlist_free(fmri);

		(void) topo_pgroup_create(dimmnode, &dimm_pgroup, &err);

		for (nvp = nvlist_next_nvpair(dimmarr[i], NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(dimmarr[i], nvp)) {
			if (nvpair_type(nvp) == DATA_TYPE_UINT64_ARRAY &&
			    strcmp(nvpair_name(nvp), "csnums") == 0 ||
			    nvpair_type(nvp) == DATA_TYPE_STRING_ARRAY &&
			    strcmp(nvpair_name(nvp), "csnames") == 0)
				continue;	/* used in rank_create() */

			nerr += nvprop_add(mod, nvp, PGNAME(DIMM), dimmnode);
		}

		nerr += rank_create(mod, dimmnode, dimmarr[i], auth);
	}

	return (nerr == 0 ? 0 : -1);
}

static nvlist_t *
mc_lookup_by_mcid(topo_mod_t *mod, topo_instance_t id)
{
	mc_snapshot_info_t mcs;
	void *buf = NULL;
	uint8_t ver;

	nvlist_t *nvl = NULL;
	char path[64];
	int fd, err;

	(void) snprintf(path, sizeof (path), "/dev/mc/mc%d", id);
	fd = open(path, O_RDONLY);

	if (fd == -1) {
		/*
		 * Some v20z and v40z systems may have had the 3rd-party
		 * NWSnps packagae installed which installs a /dev/mc
		 * link.  So try again via /devices.
		 */
		(void) snprintf(path, sizeof (path),
		    "/devices/pci@0,0/pci1022,1102@%x,2:mc-amd",
		    MC_AMD_DEV_OFFSET + id);
		fd = open(path, O_RDONLY);
	}

	if (fd == -1) {
		whinge(mod, NULL, "mc failed to open %s: %s\n",
		    path, strerror(errno));
		return (NULL);
	}

	if (ioctl(fd, MC_IOC_SNAPSHOT_INFO, &mcs) == -1 ||
	    (buf = topo_mod_alloc(mod, mcs.mcs_size)) == NULL ||
	    ioctl(fd, MC_IOC_SNAPSHOT, buf) == -1) {

		whinge(mod, NULL, "mc failed to snapshot %s: %s\n",
		    path, strerror(errno));

		free(buf);
		(void) close(fd);
		return (NULL);
	}

	(void) close(fd);
	err = nvlist_unpack(buf, mcs.mcs_size, &nvl, 0);
	topo_mod_free(mod, buf, mcs.mcs_size);


	if (nvlist_lookup_uint8(nvl, MC_NVLIST_VERSTR, &ver) != 0) {
		whinge(mod, NULL, "mc nvlist is not versioned\n");
		nvlist_free(nvl);
		return (NULL);
	} else if (ver != MC_NVLIST_VERS1) {
		whinge(mod, NULL, "mc nvlist version mismatch\n");
		nvlist_free(nvl);
		return (NULL);
	}

	return (err ? NULL : nvl);
}

static int
mc_create(topo_mod_t *mod, tnode_t *pnode, const char *name, nvlist_t *auth)
{
	int err, rc = 0;
	tnode_t *mcnode;
	nvlist_t *fmri;
	nvpair_t *nvp;
	nvlist_t *mc = NULL;
	int i;

	if (mkrsrc(mod, pnode, name, 0, auth, &fmri) != 0) {
		whinge(mod, NULL, "mc_create: mkrsrc failed\n");
		return (-1);
	}

	if (topo_node_range_create(mod, pnode, name, 0, 0) < 0) {
		nvlist_free(fmri);
		whinge(mod, NULL, "mc_create: node range create failed\n");
		return (-1);
	}

	/*
	 * Gather and create memory controller topology
	 */
	if ((mc = mc_lookup_by_mcid(mod, topo_node_instance(pnode))) == NULL ||
	    (mcnode = topo_node_bind(mod, pnode,
	    name, 0, fmri)) == NULL) {
		if (mc != NULL)
			nvlist_free(mc);
		topo_node_range_destroy(pnode, name);
		nvlist_free(fmri);
		whinge(mod, NULL, "mc_create: mc lookup or bind failed\n");
		return (-1);
	}

	(void) topo_node_fru_set(mcnode, NULL, 0, &err);
	nvlist_free(fmri);

	/*
	 * Add memory controller properties
	 */
	(void) topo_pgroup_create(mcnode, &mc_pgroup, &err);

	for (nvp = nvlist_next_nvpair(mc, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(mc, nvp)) {
		char *name = nvpair_name(nvp);
		data_type_t type = nvpair_type(nvp);

		if (type == DATA_TYPE_NVLIST_ARRAY &&
		    (strcmp(name, "cslist") == 0 ||
		    strcmp(name, "dimmlist") == 0)) {
			continue;
		} else if (type == DATA_TYPE_UINT8 &&
		    strcmp(name, MC_NVLIST_VERSTR) == 0) {
			continue;
		} else if (type == DATA_TYPE_NVLIST &&
		    strcmp(name, "htconfig") == 0) {
			nvlist_t *htnvl;

			(void) nvpair_value_nvlist(nvp, &htnvl);
			if (chip_htconfig(mod, pnode, htnvl) != 0)
				rc = -1;
		} else {
			if (nvprop_add(mod, nvp, PGNAME(MCT), mcnode) != 0)
				rc = -1;
		}
	}

	if (dramchan_create(mod, mcnode, CHAN_NODE_NAME, auth) != 0 ||
	    cs_create(mod, mcnode, CS_NODE_NAME, mc, auth) != 0 ||
	    dimm_create(mod, mcnode, DIMM_NODE_NAME, mc, auth) != 0)
		rc = -1;

	/*
	 * Free the fmris for the chip-selects allocated in cs_create
	 */
	for (i = 0; i < MC_CHIP_NCS; i++) {
		if (cs_fmri[i] != NULL) {
			nvlist_free(cs_fmri[i]);
			cs_fmri[i] = NULL;
		}
	}

	nvlist_free(mc);
	return (rc);
}

static int
chip_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, chip_t *chip, nvlist_t *auth)
{
	int i, nerr = 0;
	kstat_t *ksp;
	ulong_t *chipmap;
	tnode_t *cnode;
	nvlist_t *fmri;

	if ((chipmap = topo_mod_zalloc(mod, BT_BITOUL(max) *
	    sizeof (ulong_t))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	/*
	 * Read in all cpu_info kstats, for all chip ids.  The ks_instance
	 * argument to kstat_lookup is the logical cpu_id - we will use this
	 * in cpu_create.
	 */
	for (i = 0; i <= chip->chip_ncpustats; i++) {
		if ((ksp = kstat_lookup(chip->chip_kc, "cpu_info", i, NULL)) ==
		    NULL || kstat_read(chip->chip_kc, ksp, NULL) < 0)
			continue;

		chip->chip_cpustats[i] = ksp;
	}

	for (i = 0; i <= chip->chip_ncpustats; i++) {
		kstat_named_t *k;
		int err, chipid;

		if ((ksp = chip->chip_cpustats[i]) == NULL)
			continue;

		if ((k = kstat_data_lookup(ksp, "chip_id")) == NULL) {
			whinge(mod, &nerr, "chip_create: chip_id lookup "
			    "via kstats failed\n");
			continue;
		}

		chipid = k->value.l;
		if (BT_TEST(chipmap, chipid))
			continue;

		if (chipid < min || chipid > max)
			continue;

		if (mkrsrc(mod, pnode, name, chipid, auth, &fmri) != 0) {
			whinge(mod, &nerr, "chip_create: mkrsrc failed\n");
			continue;
		}

		if ((cnode = topo_node_bind(mod, pnode, name, chipid, fmri))
		    == NULL) {
			nvlist_free(fmri);
			whinge(mod, &nerr, "chip_create: node bind "
			    "failed for chipid %d\n", chipid);
			continue;
		}
		BT_SET(chipmap, chipid);

		if (topo_method_register(mod, cnode, chip_methods) < 0)
			whinge(mod, &nerr, "chip_create: "
			    "topo_method_register failed");

		(void) topo_node_fru_set(cnode, fmri, 0, &err);

		nvlist_free(fmri);

		(void) topo_pgroup_create(cnode, &chip_pgroup, &err);
		if (add_kstat_strprop(mod, cnode, ksp, PGNAME(CHIP),
		    CHIP_VENDOR_ID) != 0)
			nerr++;		/* have whinged elsewhere */

		if (add_kstat_longprops(mod, cnode, ksp, PGNAME(CHIP),
		    CHIP_FAMILY, CHIP_MODEL, CHIP_STEPPING, NULL) != 0)
			nerr++;		/* have whinged elsewhere */

		if (cpu_create(mod, cnode, CPU_NODE_NAME, chipid, chip, auth)
		    != 0 || mc_create(mod, cnode, MCT_NODE_NAME, auth) != 0)
			nerr++;		/* have whinged elsewhere */
	}

	topo_mod_free(mod, chipmap, BT_BITOUL(max) * sizeof (ulong_t));

	if (nerr == 0) {
		return (0);
	} else {
		(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
		return (-1);
	}
}

/*ARGSUSED*/
static int
chip_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	int rv = 0;
	chip_t *chip = (chip_t *)arg;
	nvlist_t *auth = NULL;

	auth = topo_mod_auth(mod, pnode);

	if (strcmp(name, CHIP_NODE_NAME) == 0)
		rv = chip_create(mod, pnode, name, min, max, chip, auth);

	nvlist_free(auth);

	return (rv);
}
