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
#include <sys/mc_intel.h>
#include <fm/topo_mod.h>

#include "chip.h"

#define	MAX_DIMMNUM	7
#define	MAX_CSNUM	7

/*
 * Enumerates the processing chips, or sockets, (as distinct from cores) in a
 * system.  For each chip found, the necessary nodes (one or more cores, and
 * possibly a memory controller) are constructed underneath.
 */

static int chip_enum(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t, void *, void *);

static const topo_modops_t chip_ops =
	{ chip_enum, NULL};
static const topo_modinfo_t chip_info =
	{ CHIP_NODE_NAME, FM_FMRI_SCHEME_HC, CHIP_VERSION, &chip_ops };

static const topo_pgroup_info_t chip_pgroup =
	{ PGNAME(CHIP), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t cpu_pgroup =
	{ PGNAME(CPU), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_method_t chip_methods[] = {
	{ SIMPLE_CHIP_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, simple_chip_label},
	{ G4_CHIP_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, g4_chip_label},
	{ NULL }
};

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
		 * same core.  The core ids do not reset to zero for each
		 * distinct chip - they number across all cores of all chips.
		 * This enumerator does not distinguish stranded
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
		    PGNAME(CPU), NULL, CPU_CHIP_ID, CPU_CORE_ID, CPU_CLOG_ID,
		    NULL) != 0)
			nerr++;		/* have whinged elsewhere */
	}

	return (nerr == 0 ? 0 : -1);
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
		const char *vendor;
		int32_t fms[3];
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
		    CHIP_VENDOR_ID, &vendor) != 0)
			nerr++;		/* have whinged elsewhere */

		if (add_kstat_longprops(mod, cnode, ksp, PGNAME(CHIP),
		    fms, CHIP_FAMILY, CHIP_MODEL, CHIP_STEPPING, NULL) != 0)
			nerr++;		/* have whinged elsewhere */

		if (cpu_create(mod, cnode, CPU_NODE_NAME, chipid, chip, auth)
		    != 0)
			nerr++;		/* have whinged elsewhere */

		/*
		 * Create memory-controller node under a chip for architectures
		 * that may have on-chip memory-controller(s).
		 */
		if (strcmp(vendor, "AuthenticAMD") == 0)
			amd_mc_create(mod, cnode, MCT_NODE_NAME, auth,
			    fms[0], fms[1], fms[2], &nerr);
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
	int intel_mc;

	auth = topo_mod_auth(mod, pnode);

	intel_mc = mc_offchip_open();
	if (strcmp(name, CHIP_NODE_NAME) == 0)
		rv = chip_create(mod, pnode, name, min, max, chip, auth);

	if (intel_mc)
		(void) mc_offchip_create(mod, pnode, "memory-controller", auth);

	nvlist_free(auth);

	return (rv);
}
