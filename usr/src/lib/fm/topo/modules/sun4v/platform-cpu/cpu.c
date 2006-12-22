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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <strings.h>
#include <umem.h>
#include <sys/types.h>
#include <sys/mdesc.h>
#include <sys/fm/ldom.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>

/*
 * Enumerates the cpu strands in a system. For each strand found, the
 * necessary cpu-schemed nodes are constructed underneath.
 */

#define	PLATFORM_CPU_NAME	"platform-cpu"
#define	PLATFORM_CPU_VERSION	TOPO_VERSION
#define	CPU_NODE_NAME		"cpu"

typedef struct md_cpumap {
	uint32_t cpumap_id;		/* virtual cpuid */
	uint32_t cpumap_pid;		/* physical cpuid */
	uint64_t cpumap_serialno;	/* cpu serial number */
} md_cpumap_t;

typedef struct chip {
	uint64_t *chip_serials;		/* list of cpu serial numbers */
	md_cpumap_t *chip_cpus;		/* List of cpu maps */
	uint32_t chip_ncpus;		/* size */
} chip_t;


/* Forward declaration */
static int cpu_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void cpu_release(topo_mod_t *, tnode_t *);
static int cpu_mdesc_init(topo_mod_t *mod, chip_t *chip);


static const topo_modops_t cpu_ops =
	{ cpu_enum, cpu_release };
static const topo_modinfo_t cpu_info =
	{ PLATFORM_CPU_NAME, FM_FMRI_SCHEME_CPU, PLATFORM_CPU_VERSION,
		&cpu_ops };


static void *
cpu_alloc(size_t size)
{
	return (umem_alloc(size, UMEM_DEFAULT));
}

static void
cpu_free(void *data, size_t size)
{
	umem_free(data, size);
}

int
_topo_init(topo_mod_t *mod)
{
	chip_t *chip;

	if (getenv("TOPOPLATFORMCPUDBG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing %s enumerator\n",
			PLATFORM_CPU_NAME);

	if ((chip = topo_mod_zalloc(mod, sizeof (chip_t))) == NULL)
		return (-1);

	if (cpu_mdesc_init(mod, chip) != 0) {
		topo_mod_dprintf(mod, "failed to get cpus from the PRI/MD\n");
		topo_mod_free(mod, chip, sizeof (chip_t));
		return (-1);
	}

	if (topo_mod_register(mod, &cpu_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register hc: "
		    "%s\n", topo_mod_errmsg(mod));
		topo_mod_free(mod, chip, sizeof (chip_t));
		return (-1);
	}
	topo_mod_setspecific(mod, (void *)chip);

	topo_mod_dprintf(mod, "%s enumerator inited\n", PLATFORM_CPU_NAME);

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	chip_t *chip;

	chip = (chip_t *)topo_mod_getspecific(mod);

	if (chip->chip_serials != NULL)
		topo_mod_free(mod, chip->chip_serials,
			chip->chip_ncpus * sizeof (uint64_t));

	if (chip->chip_cpus != NULL)
		topo_mod_free(mod, chip->chip_cpus,
			chip->chip_ncpus * sizeof (md_cpumap_t));

	topo_mod_free(mod, chip, sizeof (chip_t));

	topo_mod_unregister(mod);

}

static int
cpu_mdesc_init(topo_mod_t *mod, chip_t *chip)
{
	md_t *mdp;
	mde_cookie_t *listp;
	md_cpumap_t *mcmp;
	int i, num_nodes, idx;
	ssize_t bufsiz = 0;
	uint64_t *bufp;
	ldom_hdl_t *lhp;

	lhp = ldom_init(cpu_alloc, cpu_free);
	if ((lhp == NULL) || (bufsiz = ldom_get_core_md(lhp, &bufp)) <= 0) {
		return (-1);
	}

	if ((mdp = md_init_intern(bufp, cpu_alloc, cpu_free)) == NULL ||
	    (num_nodes = md_node_count(mdp)) <= 0) {
		cpu_free(bufp, (size_t)bufsiz);
		return (-1);
	}

	listp = topo_mod_zalloc(mod, sizeof (mde_cookie_t) * num_nodes);

	chip->chip_ncpus = md_scan_dag(mdp,
					MDE_INVAL_ELEM_COOKIE,
					md_find_name(mdp, "cpu"),
					md_find_name(mdp, "fwd"),
					listp);
	topo_mod_dprintf(mod, "Found %d cpus\n", chip->chip_ncpus);

	chip->chip_cpus = topo_mod_zalloc(mod, chip->chip_ncpus *
	    sizeof (md_cpumap_t));
	chip->chip_serials = topo_mod_zalloc(mod, chip->chip_ncpus *
	    sizeof (uint64_t));

	for (idx = 0, mcmp = chip->chip_cpus;
	    idx < chip->chip_ncpus;
	    idx++, mcmp++) {
		uint64_t tl;

		if (md_get_prop_val(mdp, listp[idx], "id", &tl) < 0)
			tl = (uint64_t)-1; /* invalid value */
		mcmp->cpumap_id = tl;

		if (md_get_prop_val(mdp, listp[idx], "pid", &tl) < 0)
			tl = mcmp->cpumap_id;
		mcmp->cpumap_pid = tl;

		if (md_get_prop_val(mdp, listp[idx], "serial#",
		    &mcmp->cpumap_serialno) < 0)
			mcmp->cpumap_serialno = 0;

		/* unique serial number */
		for (i = 0; i < chip->chip_ncpus &&
		    chip->chip_serials[i] != 0; i++) {
			if (mcmp->cpumap_serialno == chip->chip_serials[i]) {
				break;
			}
		}
		if (i < chip->chip_ncpus && chip->chip_serials[i] == 0) {
			chip->chip_serials[i] = mcmp->cpumap_serialno;
			topo_mod_dprintf(mod, "chip[%d] serial is %llx\n", i,
				chip->chip_serials[i]);
		}
	}

	topo_mod_free(mod, listp, sizeof (mde_cookie_t) * num_nodes);
	topo_mod_free(mod, *mdp, bufsiz);
	(void) md_fini(mdp);

	return (0);
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

static tnode_t *
cpu_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, char *serial, void *priv)
{
	int cpu_mask = 0;
	nvlist_t *fmri;
	tnode_t *ntn;

	fmri = cpu_fmri_create(mod, i, serial, cpu_mask);
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

	return (ntn);
}

/*ARGSUSED*/
static int
cpu_create(topo_mod_t *mod, tnode_t *rnode, const char *name, chip_t *chip)
{
	int i;
	int min = -1;
	int max = -1;
	int nerr = 0;
	int pid;
	char sbuf[32];
	tnode_t *cnode;

	topo_mod_dprintf(mod, "enumerating cpus\n");

	/*
	 * find the min/max id of cpus per this cmp and create a cpu range
	 */
	for (i = 0; i < chip->chip_ncpus; i++) {
		if ((min < 0) || (chip->chip_cpus[i].cpumap_pid < min))
			min = chip->chip_cpus[i].cpumap_pid;
		if ((max < 0) || (chip->chip_cpus[i].cpumap_pid > max))
			max = chip->chip_cpus[i].cpumap_pid;
	}
	if (min < 0 || max < 0)
		return (-1);
	topo_node_range_destroy(rnode, name);
	if (topo_node_range_create(mod, rnode, name, 0, max+1) < 0) {
		topo_mod_dprintf(mod, "failed to create cpu range[0,%d]: %s\n",
					max+1, topo_mod_errmsg(mod));
		return (-1);
	}

	/*
	 * Create the cpu nodes
	 */
	for (i = 0; i < chip->chip_ncpus; i++) {

		(void) snprintf(sbuf, sizeof (sbuf), "%llx",
			chip->chip_cpus[i].cpumap_serialno);

		/* physical cpuid */
		pid = chip->chip_cpus[i].cpumap_pid;
		cnode = cpu_tnode_create(mod, rnode, name,
					(topo_instance_t)pid, sbuf, NULL);
		if (cnode == NULL) {
			topo_mod_dprintf(mod,
					"failed to create a cpu=%d node: %s\n",
					pid, topo_mod_errmsg(mod));
			nerr++;
			continue;
		}

	}

	if (nerr != 0)
		(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);

	return (0);
}

/*ARGSUSED*/
static int
cpu_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	topo_mod_dprintf(mod, "%s enumerating %s\n", PLATFORM_CPU_NAME, name);
	if (strcmp(name, CPU_NODE_NAME) == 0)
		return (cpu_create(mod, rnode, name, (chip_t *)arg));

	return (0);
}

/*ARGSUSED*/
static void
cpu_release(topo_mod_t *mp, tnode_t *node)
{
}
