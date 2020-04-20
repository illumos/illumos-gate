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

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/fm/protocol.h>

#include <unistd.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <umem.h>

#include <cpu_mdesc.h>


/*
 * Enumerates the processing chips, or sockets, (as distinct from cores) in a
 * system.  For each chip found, the necessary nodes (one or more cores, and
 * possibly a memory controller) are constructed underneath.
 */

#define	CHIP_VERSION	TOPO_VERSION
#define	CPU_NODE_NAME	"cpu"
#define	CHIP_NODE_NAME	"chip"

extern topo_method_t pi_cpu_methods[];

/* Forward declaration */
static int chip_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void chip_release(topo_mod_t *, tnode_t *);

static const topo_modops_t chip_ops =
	{ chip_enum, chip_release };
static const topo_modinfo_t chip_info =
	{ "chip", FM_FMRI_SCHEME_HC, CHIP_VERSION, &chip_ops };


static const topo_pgroup_info_t chip_auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

int
_topo_init(topo_mod_t *mod)
{
	md_info_t *chip;

	if (getenv("TOPOCHIPDBG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing chip enumerator\n");

	if ((chip = topo_mod_zalloc(mod, sizeof (md_info_t))) == NULL)
		return (-1);

	if (cpu_mdesc_init(mod, chip) != 0) {
		topo_mod_dprintf(mod, "failed to get cpus from the PRI/MD\n");
		topo_mod_free(mod, chip, sizeof (md_info_t));
		return (-1);
	}

	topo_mod_setspecific(mod, (void *)chip);

	if (topo_mod_register(mod, &chip_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register hc: "
		    "%s\n", topo_mod_errmsg(mod));
		cpu_mdesc_fini(mod, chip);
		topo_mod_free(mod, chip, sizeof (md_info_t));
		return (-1);
	}

	topo_mod_dprintf(mod, "chip enumerator inited\n");

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	md_info_t *chip;

	chip = (md_info_t *)topo_mod_getspecific(mod);

	cpu_mdesc_fini(mod, chip);

	topo_mod_free(mod, chip, sizeof (md_info_t));

	topo_mod_unregister(mod);
}

static tnode_t *
chip_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, char *serial,
    nvlist_t *fru, char *label, void *priv)
{
	int err;
	nvlist_t *fmri;
	tnode_t *ntn;
	char *prod = NULL, *psn = NULL, *csn = NULL, *server = NULL;
	nvlist_t *auth = NULL;

	if (topo_mod_nvalloc(mod, &auth, NV_UNIQUE_NAME) == 0) {
		if (topo_prop_get_string(parent, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &prod, &err) == 0) {
			(void) nvlist_add_string(auth, FM_FMRI_AUTH_PRODUCT,
			    prod);
			topo_mod_strfree(mod, prod);
		}
		if (topo_prop_get_string(parent, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT_SN, &psn, &err) == 0) {
			(void) nvlist_add_string(auth, FM_FMRI_AUTH_PRODUCT_SN,
			    psn);
			topo_mod_strfree(mod, psn);
		}
		if (topo_prop_get_string(parent, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, &server, &err) == 0) {
			(void) nvlist_add_string(auth, FM_FMRI_AUTH_SERVER,
			    server);
			topo_mod_strfree(mod, server);
		}
		if (topo_prop_get_string(parent, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &csn, &err) == 0) {
			(void) nvlist_add_string(auth, FM_FMRI_AUTH_CHASSIS,
			    csn);
			topo_mod_strfree(mod, csn);
		}
	}


	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, name, i,
	    NULL, auth, NULL, NULL, serial);
	nvlist_free(auth);
	if (fmri == NULL) {
		topo_mod_dprintf(mod,
		    "Unable to make nvlist for %s bind: %s.\n",
		    name, topo_mod_errmsg(mod));
		return (NULL);
	}

	ntn = topo_node_bind(mod, parent, name, i, fmri);
	if (ntn == NULL) {
		topo_mod_dprintf(mod,
		    "topo_node_bind (%s%d/%s%d) failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i,
		    topo_strerror(topo_mod_errno(mod)));
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);
	topo_node_setspecific(ntn, priv);

	if (topo_pgroup_create(ntn, &chip_auth_pgroup, &err) == 0) {
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT_SN, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, &err);
	}

	/* Inherit the Label FRU fields from the parent */
	(void) topo_node_label_set(ntn, label, &err);
	(void) topo_node_fru_set(ntn, fru, 0, &err);

	/* Register retire methods */
	if (topo_method_register(mod, ntn, pi_cpu_methods) < 0)
		topo_mod_dprintf(mod, "Unsable to register retire methods "
		    "for %s%d/%s%d: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i, topo_mod_errmsg(mod));

	return (ntn);
}

static nvlist_t *
cpu_fmri_create(topo_mod_t *mod, uint32_t cpuid, char *serial, uint8_t cpumask)
{
	int err;
	nvlist_t *fmri;

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0)
		return (NULL);
	err = nvlist_add_uint8(fmri, FM_VERSION, FM_CPU_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_CPU);
	err |= nvlist_add_uint32(fmri, FM_FMRI_CPU_ID, cpuid);
	err |= nvlist_add_uint8(fmri, FM_FMRI_CPU_MASK, cpumask);
	if (serial != NULL)
		err |= nvlist_add_string(fmri, FM_FMRI_CPU_SERIAL_ID, serial);
	if (err != 0) {
		nvlist_free(fmri);
		(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);
		return (NULL);
	}

	return (fmri);
}

/*ARGSUSED*/
static int
cpu_create(topo_mod_t *mod, tnode_t *rnode, const char *name, md_info_t *chip,
    uint64_t serial)
{
	int i;
	int min = -1;
	int max = -1;
	int err;
	int nerr = 0;
	int pid;
	char sbuf[32];
	tnode_t *cnode;
	nvlist_t *asru;
	md_cpumap_t *mcmp;

	topo_mod_dprintf(mod, "enumerating cpus\n");

	/*
	 * find the min/max id of cpus per this cmp and create a cpu range
	 */
	for (i = 0, mcmp = chip->cpus; i < chip->ncpus; i++, mcmp++) {
		if (mcmp->cpumap_serialno != serial)
			continue;
		if ((min < 0) || (mcmp->cpumap_pid < min))
			min = mcmp->cpumap_pid;
		if ((max < 0) || (mcmp->cpumap_pid > max))
			max = mcmp->cpumap_pid;
	}
	if (min < 0 || max < 0) {
		topo_mod_dprintf(mod, "Invalid cpu range(%d,%d)\n", min, max);
		return (-1);
	}
	if (topo_node_range_create(mod, rnode, name, 0, max+1) < 0) {
		topo_mod_dprintf(mod, "failed to create cpu range[0,%d]: %s\n",
		    max, topo_mod_errmsg(mod));
		return (-1);
	}

	(void) snprintf(sbuf, sizeof (sbuf), "%llx", serial);

	/*
	 * Create the cpu[i] nodes of a given cmp i
	 */
	for (i = 0, mcmp = chip->cpus; i < chip->ncpus; i++, mcmp++) {

		if (mcmp->cpumap_serialno == 0 ||
		    mcmp->cpumap_serialno != serial) {
			continue;
		}

		/* physical cpuid */
		pid = mcmp->cpumap_pid;
		cnode = chip_tnode_create(mod, rnode, name,
		    (topo_instance_t)pid, sbuf, NULL, NULL, NULL);
		if (cnode == NULL) {
			topo_mod_dprintf(mod,
			    "failed to create a cpu=%d node: %s\n",
			    pid, topo_mod_errmsg(mod));
			nerr++;
			continue;
		}

		if ((asru = cpu_fmri_create(mod, pid, sbuf, 0)) != NULL) {
			(void) topo_node_asru_set(cnode, asru, 0, &err);
			nvlist_free(asru);
		} else {
			nerr++;
		}
	}

	if (nerr != 0)
		(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);

	return (0);
}

static int
dimm_instantiate(tnode_t *parent, const char *name, topo_mod_t *mod)
{
	if (strcmp(name, CHIP) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    CHIP);
		return (0);
	}
	topo_mod_dprintf(mod,
	    "Calling dimm_enum\n");
	if (topo_mod_enumerate(mod,
	    parent, DIMM, DIMM, 0, 0, NULL) != 0) {
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}
	return (0);
}

static topo_mod_t *
dimm_enum_load(topo_mod_t *mp)
{
	topo_mod_t *rp = NULL;

	topo_mod_dprintf(mp, "dimm_enum_load: %s\n", CHIP);
	if ((rp = topo_mod_load(mp, DIMM, TOPO_VERSION)) == NULL) {
		topo_mod_dprintf(mp,
		    "%s enumerator could not load %s enum. (%d: %s)\n",
		    CHIP, DIMM, errno, strerror(errno));
	}
	topo_mod_dprintf(mp, "dimm_enum_load(EXIT): %s, rp=%p\n", CHIP, rp);
	return (rp);
}

/*ARGSUSED*/
static int
chip_create(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, md_info_t *chip)
{
	int nerr = 0;
	int err;
	int i;
	char sbuf[32];
	tnode_t *cnode;
	nvlist_t *fru = NULL;
	char *label = NULL;
	md_proc_t *procp;

	topo_mod_dprintf(mod, "enumerating cmp chip\n");
	if (min > max) {
		topo_mod_dprintf(mod, "Invalid chip range(%d,%d)\n", min, max);
		return (-1);
	}

	if (dimm_enum_load(mod) == NULL)
		return (-1);

	/*
	 * Create the chip[i] nodes, one for each CMP chip uniquely identified
	 * by the serial number.
	 */
	for (i = min; i <= max; i++) {

		/* Skip the processors with no serial number */
		if ((procp = cpu_find_proc(chip, i)) == NULL) {
			continue;
		}
		if (procp->serialno == 0) {
			continue;
		}

		(void) snprintf(sbuf, sizeof (sbuf), "%llx", procp->serialno);
		topo_mod_dprintf(mod, "node chip[%d], sn=%s\n", i, sbuf);

		cnode = chip_tnode_create(mod, rnode, name, (topo_instance_t)i,
		    sbuf, fru, label, NULL);
		if (cnode == NULL) {
			topo_mod_dprintf(mod, "failed to create a chip node: "
			    "%s\n", topo_mod_errmsg(mod));
			nerr++;
			continue;
		}

		/* Enumerate all cpu strands of this CMP chip */
		err = cpu_create(mod, cnode, CPU_NODE_NAME, chip,
		    procp->serialno);
		if (err != 0) {
			nerr++;
		}

		/* Enumerate all DIMMs belonging to this chip */
		if (dimm_instantiate(cnode, CHIP, mod) < 0) {
			topo_mod_dprintf(mod, "Enumeration of dimm "
			    "failed %s\n", topo_mod_errmsg(mod));
			return (-1);
		}
	}

	if (nerr != 0)
		(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);

	return (0);
}

/*ARGSUSED*/
static int
chip_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	md_info_t *chip = (md_info_t *)arg;

	if (strcmp(name, CHIP_NODE_NAME) == 0)
		return (chip_create(mod, rnode, name, min, max, chip));

	return (0);
}

/*ARGSUSED*/
static void
chip_release(topo_mod_t *mp, tnode_t *node)
{
}
