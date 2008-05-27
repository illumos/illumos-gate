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

#include <strings.h>
#include <umem.h>
#include <fm/topo_mod.h>
#include <sys/fm/ldom.h>
#include <sys/fm/protocol.h>

#include <cpu_mdesc.h>

/*
 * This enumerator creates cpu-schemed nodes for each strand found in the
 * sun4v Physical Rource Inventory (PRI).
 * Each node export three methods present(), expand() and unusable().
 *
 */

#define	PLATFORM_CPU_NAME	"platform-cpu"
#define	PLATFORM_CPU_VERSION	TOPO_VERSION
#define	CPU_NODE_NAME		"cpu"


/* Forward declaration */
static int cpu_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void cpu_release(topo_mod_t *, tnode_t *);
static int cpu_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int cpu_expand(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int cpu_unusable(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

static const topo_modops_t cpu_ops =
	{ cpu_enum, cpu_release };
static const topo_modinfo_t cpu_info =
	{ PLATFORM_CPU_NAME, FM_FMRI_SCHEME_CPU, PLATFORM_CPU_VERSION,
		&cpu_ops };

static const topo_method_t cpu_methods[] = {
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC,
	    TOPO_METH_PRESENT_VERSION, TOPO_STABILITY_INTERNAL, cpu_present },
	{ TOPO_METH_EXPAND, TOPO_METH_EXPAND_DESC,
	    TOPO_METH_EXPAND_VERSION, TOPO_STABILITY_INTERNAL, cpu_expand },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL, cpu_unusable },
	{ NULL }
};

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
	md_info_t *chip;

	if (getenv("TOPOPLATFORMCPUDBG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing %s enumerator\n",
	    PLATFORM_CPU_NAME);

	if ((chip = topo_mod_zalloc(mod, sizeof (md_info_t))) == NULL)
		return (-1);

	if (cpu_mdesc_init(mod, chip) != 0) {
		topo_mod_dprintf(mod, "failed to get cpus from the PRI/MD\n");
		topo_mod_free(mod, chip, sizeof (md_info_t));
		return (-1);
	}

	topo_mod_setspecific(mod, (void *)chip);

	if (topo_mod_register(mod, &cpu_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register %s: %s\n",
		    PLATFORM_CPU_NAME, topo_mod_errmsg(mod));
		cpu_mdesc_fini(mod, chip);
		topo_mod_free(mod, chip, sizeof (md_info_t));
		return (-1);
	}

	topo_mod_dprintf(mod, "%s enumerator inited\n", PLATFORM_CPU_NAME);

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

/*ARGSUSED*/
static int
cpu_present(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	uint8_t version;
	uint32_t cpuid;
	uint64_t nvlserid;
	uint32_t present = 0;
	md_cpumap_t *mcmp;
	md_info_t *chip = (md_info_t *)topo_mod_getspecific(mod);

	/*
	 * Get the physical cpuid
	 */
	if (nvlist_lookup_uint8(in, FM_VERSION, &version) != 0 ||
	    version > FM_CPU_SCHEME_VERSION ||
	    nvlist_lookup_uint32(in, FM_FMRI_CPU_ID, &cpuid) != 0) {
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/*
	 * Find the cpuid entry
	 * If the input nvl contains a serial number, the cpu is identified
	 * by a tuple <cpuid, cpuserial>
	 * Otherwise, the cpu is identified by the <cpuid>.
	 */
	if ((mcmp = cpu_find_cpumap(chip, cpuid)) != NULL) {
		if (nvlist_lookup_uint64(in, FM_FMRI_CPU_SERIAL_ID, &nvlserid)
		    == 0)
			present = nvlserid == mcmp->cpumap_serialno;
		else
			present = 1;
	}

	/* return the present status */
	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_PRESENT_RET, present) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}

/*ARGSUSED*/
static int
cpu_expand(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	int rc;
	uint8_t version;
	uint32_t cpuid;
	uint64_t nvlserid;
	md_cpumap_t *mcmp = NULL;
	md_info_t *chip = (md_info_t *)topo_mod_getspecific(mod);

	if (nvlist_lookup_uint8(in, FM_VERSION, &version) != 0 ||
	    version > FM_CPU_SCHEME_VERSION ||
	    nvlist_lookup_uint32(in, FM_FMRI_CPU_ID, &cpuid) != 0) {
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/* Find the cpuid entry */
	if ((mcmp = cpu_find_cpumap(chip, cpuid)) == NULL)
		return (-1);

	if ((rc = nvlist_lookup_uint64(in, FM_FMRI_CPU_SERIAL_ID,
	    &nvlserid)) == 0) {
		if (nvlserid != mcmp->cpumap_serialno)
			return (-1);
	} else if (rc != ENOENT)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	else {
		if ((rc = nvlist_add_uint64(in, FM_FMRI_CPU_SERIAL_ID,
		    mcmp->cpumap_serialno)) != 0) {
			return (topo_mod_seterrno(mod, rc));
		}
	}

	topo_mod_dprintf(mod, "nvlserid=%llX\n", nvlserid);

	if (mcmp != NULL &&
	    mcmp->cpumap_chipidx >= 0 &&
	    mcmp->cpumap_chipidx < chip->nprocs &&
	    chip->procs &&
	    chip->procs[mcmp->cpumap_chipidx].fru) {
		int len;
		char *str;
		md_fru_t *frup = chip->procs[mcmp->cpumap_chipidx].fru;

		/* part number + dash number */
		len = (frup->part ? strlen(frup->part) : 0) +
		    (frup->dash ? strlen(frup->dash) : 0) + 1;
		str = cpu_alloc(len);
		(void) snprintf(str, len, "%s%s",
		    frup->part ? frup->part : MD_STR_BLANK,
		    frup->dash ? frup->dash : MD_STR_BLANK);
		(void) nvlist_add_string(in, FM_FMRI_HC_PART, str);
		cpu_free(str, len);

		/* fru name */
		(void) nvlist_add_string(in, FM_FMRI_CPU_CPUFRU,
		    frup->nac ? frup->nac : MD_STR_BLANK);

		/* fru serial */
		in->nvl_nvflag = NV_UNIQUE_NAME_TYPE;
		(void) nvlist_add_string(in, FM_FMRI_HC_SERIAL_ID,
		    frup->serial ? frup->serial : MD_STR_BLANK);
	}

	return (0);
}

/*ARGSUSED*/
static int
cpu_unusable(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	int rc = -1;
	uint8_t version;
	int status;
	uint32_t cpuid;
	ldom_hdl_t *lhp;
	uint64_t nvlserid;
	uint32_t present = 0;
	md_cpumap_t *mcmp;
	md_info_t *chip = (md_info_t *)topo_mod_getspecific(mod);

	if (nvlist_lookup_uint8(in, FM_VERSION, &version) != 0 ||
	    version > FM_CPU_SCHEME_VERSION ||
	    nvlist_lookup_uint32(in, FM_FMRI_CPU_ID, &cpuid) != 0) {
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/*
	 * Check the cpu presence
	 */
	if ((mcmp = cpu_find_cpumap(chip, cpuid)) != NULL) {
		if (nvlist_lookup_uint64(in, FM_FMRI_CPU_SERIAL_ID, &nvlserid)
		    == 0)
			present = nvlserid == mcmp->cpumap_serialno;
		else
			present = 1;
	}
	if (present == 0) {
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	lhp = ldom_init(cpu_alloc, cpu_free);
	if (lhp == NULL) {
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	status = ldom_fmri_status(lhp, in);
	rc = (status == P_FAULTED ||
	    (status == P_OFFLINE && ldom_major_version(lhp) == 1));
	ldom_fini(lhp);

	/* return the unusable status */
	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_UNUSABLE_RET, rc) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

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
cpu_create(topo_mod_t *mod, tnode_t *rnode, const char *name, md_info_t *chip)
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
	for (i = 0; i < chip->ncpus; i++) {
		if ((min < 0) || (chip->cpus[i].cpumap_pid < min))
			min = chip->cpus[i].cpumap_pid;
		if ((max < 0) || (chip->cpus[i].cpumap_pid > max))
			max = chip->cpus[i].cpumap_pid;
	}
	if (min < 0 || max < 0)
		return (-1);
	topo_node_range_destroy(rnode, name);
	if (topo_node_range_create(mod, rnode, name, 0, max+1) < 0) {
		topo_mod_dprintf(mod, "failed to create cpu range[0,%d]: %s\n",
		    max, topo_mod_errmsg(mod));
		return (-1);
	}

	/*
	 * Create the cpu nodes
	 */
	for (i = 0; i < chip->ncpus; i++) {

		(void) snprintf(sbuf, sizeof (sbuf), "%llx",
		    chip->cpus[i].cpumap_serialno);

		/* physical cpuid */
		pid = chip->cpus[i].cpumap_pid;
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

	if (topo_method_register(mod, rnode, cpu_methods) < 0) {
		topo_mod_dprintf(mod, "topo_method_register failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	if (strcmp(name, CPU_NODE_NAME) == 0)
		return (cpu_create(mod, rnode, name, (md_info_t *)arg));

	return (0);
}

/*ARGSUSED*/
static void
cpu_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}
