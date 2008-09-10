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

#include <unistd.h>
#include <fcntl.h>
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
#include <sys/devfm.h>
#include <fm/fmd_agent.h>
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

static const topo_pgroup_info_t core_pgroup =
	{ PGNAME(CORE), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_pgroup_info_t strand_pgroup =
	{ PGNAME(STRAND), TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_method_t chip_methods[] = {
	{ SIMPLE_CHIP_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, simple_chip_label},
	{ G4_CHIP_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, g4_chip_label},
	{ A4FPLUS_CHIP_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, a4fplus_chip_label},
	{ NULL }
};

static const topo_method_t strands_retire_methods[] = {
	{ TOPO_METH_RETIRE, TOPO_METH_RETIRE_DESC,
	    TOPO_METH_RETIRE_VERSION, TOPO_STABILITY_INTERNAL,
	    retire_strands },
	{ TOPO_METH_UNRETIRE, TOPO_METH_UNRETIRE_DESC,
	    TOPO_METH_UNRETIRE_VERSION, TOPO_STABILITY_INTERNAL,
	    unretire_strands },
	{ TOPO_METH_SERVICE_STATE, TOPO_METH_SERVICE_STATE_DESC,
	    TOPO_METH_SERVICE_STATE_VERSION, TOPO_STABILITY_INTERNAL,
	    service_state_strands },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL,
	    unusable_strands },
	{ NULL }
};

int
_topo_init(topo_mod_t *mod)
{
	if (getenv("TOPOCHIPDBG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing chip enumerator\n");

	if (topo_mod_register(mod, &chip_info, TOPO_VERSION) != 0) {
		whinge(mod, NULL, "failed to register hc: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1); /* mod errno set */
	}

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

boolean_t
is_xpv(void)
{
	static int r = -1;
	char platform[MAXNAMELEN];

	if (r != -1)
		return (r == 0);

	(void) sysinfo(SI_PLATFORM, platform, sizeof (platform));
	r = strcmp(platform, "i86xpv");
	return (r == 0);
}

static tnode_t *
create_node(topo_mod_t *mod, tnode_t *pnode, nvlist_t *auth, char *name,
    topo_instance_t inst)
{
	nvlist_t *fmri;
	tnode_t *cnode;

	if (mkrsrc(mod, pnode, name, inst, auth, &fmri) != 0) {
		whinge(mod, NULL, "create_node: mkrsrc failed\n");
		return (NULL);
	}
	cnode = topo_node_bind(mod, pnode, name, inst, fmri);
	nvlist_free(fmri);
	if (cnode == NULL)
		whinge(mod, NULL, "create_node: node bind failed for %s %d\n",
		    name, (int)inst);

	return (cnode);
}

static int
create_strand(topo_mod_t *mod, tnode_t *pnode, nvlist_t *cpu, nvlist_t *auth)
{
	tnode_t *strand;
	int32_t strandid, cpuid;
	int err, nerr = 0;
	nvlist_t *fmri;

	if ((err = nvlist_lookup_int32(cpu, FM_PHYSCPU_INFO_STRAND_ID,
	    &strandid)) != 0) {
		whinge(mod, NULL, "create_strand: lookup strand_id failed: "
		    "%s\n", strerror(err));
		return (-1);
	}

	if ((strand = topo_node_lookup(pnode, STRAND_NODE_NAME, strandid))
	    != NULL) {
		whinge(mod, NULL, "create_strand: duplicate tuple found\n");
		return (-1);
	}

	if ((strand = create_node(mod, pnode, auth, STRAND_NODE_NAME,
	    strandid)) == NULL)
		return (-1);

	/*
	 * Inherit FRU from core node, in native use cpu scheme ASRU,
	 * in xpv, use hc scheme ASRU.
	 */
	(void) topo_node_fru_set(strand, NULL, 0, &err);
	if (is_xpv()) {
		if (topo_node_resource(strand, &fmri, &err) == -1) {
			whinge(mod, &nerr, "create_strand: "
			    "topo_node_resource failed\n");
		} else {
			(void) topo_node_asru_set(strand, fmri, 0, &err);
			nvlist_free(fmri);
		}
	} else {
		if (nvlist_lookup_int32(cpu, STRAND_CPU_ID, &cpuid) != 0) {
			whinge(mod, &nerr, "create_strand: lookup cpuid "
			    "failed\n");
		} else {
			if ((fmri = cpu_fmri_create(mod, cpuid, NULL, 0))
			    != NULL) {
				(void) topo_node_asru_set(strand, fmri,
				    0, &err);
				nvlist_free(fmri);
			} else {
				whinge(mod, &nerr, "create_strand: "
				    "cpu_fmri_create() failed\n");
			}
		}
	}

	if (topo_method_register(mod, strand, strands_retire_methods) < 0)
		whinge(mod, &nerr, "create_strand: "
		    "topo_method_register failed\n");

	(void) topo_pgroup_create(strand, &strand_pgroup, &err);
	nerr -= add_nvlist_longprops(mod, strand, cpu, PGNAME(STRAND), NULL,
	    STRAND_CHIP_ID, STRAND_CORE_ID, STRAND_CPU_ID, NULL);

	return (err == 0 && nerr == 0 ? 0 : -1);
}

static int
create_core(topo_mod_t *mod, tnode_t *pnode, nvlist_t *cpu, nvlist_t *auth)
{
	tnode_t *core;
	int32_t coreid, cpuid;
	int err, nerr = 0;
	nvlist_t *fmri;

	if ((err = nvlist_lookup_int32(cpu, FM_PHYSCPU_INFO_CORE_ID, &coreid))
	    != 0) {
		whinge(mod, NULL, "create_core: lookup core_id failed: %s\n",
		    strerror(err));
		return (-1);
	}
	if ((core = topo_node_lookup(pnode, CORE_NODE_NAME, coreid)) == NULL) {
		if ((core = create_node(mod, pnode, auth, CORE_NODE_NAME,
		    coreid)) == NULL)
			return (-1);

		/*
		 * Inherit FRU from the chip node, for native, we use hc
		 * scheme ASRU for the core node.
		 */
		(void) topo_node_fru_set(core, NULL, 0, &err);
		if (is_xpv()) {
			if (topo_node_resource(core, &fmri, &err) == -1) {
				whinge(mod, &nerr, "create_core: "
				    "topo_node_resource failed\n");
			} else {
				(void) topo_node_asru_set(core, fmri, 0, &err);
				nvlist_free(fmri);
			}
		}
		if (topo_method_register(mod, core, strands_retire_methods) < 0)
			whinge(mod, &nerr, "create_core: "
			    "topo_method_register failed\n");

		(void) topo_pgroup_create(core, &core_pgroup, &err);
		nerr -= add_nvlist_longprop(mod, core, cpu, PGNAME(CORE),
		    CORE_CHIP_ID, NULL);

		if (topo_node_range_create(mod, core, STRAND_NODE_NAME,
		    0, 255) != 0)
			return (-1);
	}

	if (! is_xpv()) {
		/*
		 * In native mode, we're in favor of cpu scheme ASRU for
		 * printing reason.  More work needs to be done to support
		 * multi-strand cpu: the ASRU will be a list of cpuid then.
		 */
		if (nvlist_lookup_int32(cpu, STRAND_CPU_ID, &cpuid) != 0) {
			whinge(mod, &nerr, "create_core: lookup cpuid "
			    "failed\n");
		} else {
			if ((fmri = cpu_fmri_create(mod, cpuid, NULL, 0))
			    != NULL) {
				(void) topo_node_asru_set(core, fmri, 0, &err);
				nvlist_free(fmri);
			} else {
				whinge(mod, &nerr, "create_core: "
				    "cpu_fmri_create() failed\n");
			}
		}
	}

	err = create_strand(mod, core, cpu, auth);

	return (err == 0 && nerr == 0 ? 0 : -1);
}

static int
create_chip(topo_mod_t *mod, tnode_t *pnode, topo_instance_t min,
    topo_instance_t max, nvlist_t *cpu, nvlist_t *auth,
    int mc_offchip)
{
	tnode_t *chip;
	int32_t chipid;
	nvlist_t *fmri = NULL;
	int err, nerr = 0;
	int32_t fms[3];
	const char *vendor = NULL;

	if ((err = nvlist_lookup_int32(cpu, FM_PHYSCPU_INFO_CHIP_ID, &chipid))
	    != 0) {
		whinge(mod, NULL, "create_chip: lookup chip_id failed: %s\n",
		    strerror(err));
		return (-1);
	}

	if (chipid < min || chipid > max)
		return (-1);

	if ((chip = topo_node_lookup(pnode, CHIP_NODE_NAME, chipid)) == NULL) {
		if ((chip = create_node(mod, pnode, auth, CHIP_NODE_NAME,
		    chipid)) == NULL)
			return (-1);

		if (topo_method_register(mod, chip, chip_methods) < 0)
			whinge(mod, &nerr, "create_chip: "
			    "topo_method_register failed\n");

		if (topo_node_resource(chip, &fmri, &err) == -1) {
			whinge(mod, &nerr, "create_chip: "
			    "topo_node_resource failed\n");
		} else {
			(void) topo_node_fru_set(chip, fmri, 0, &err);
			nvlist_free(fmri);
		}

		(void) topo_pgroup_create(chip, &chip_pgroup, &err);
		nerr -= add_nvlist_strprop(mod, chip, cpu, PGNAME(CHIP),
		    CHIP_VENDOR_ID, &vendor);
		nerr -= add_nvlist_longprops(mod, chip, cpu, PGNAME(CHIP),
		    fms, CHIP_FAMILY, CHIP_MODEL, CHIP_STEPPING, NULL);

		if (topo_method_register(mod, chip, strands_retire_methods) < 0)
			whinge(mod, &nerr, "create_chip: "
			    "topo_method_register failed\n");

		if (topo_node_range_create(mod, chip, CORE_NODE_NAME,
		    0, 255) != 0)
			return (-1);
	}

	err = create_core(mod, chip, cpu, auth);

	/*
	 * Create memory-controller node under a chip for architectures
	 * that may have on-chip memory-controller(s).
	 */
	if (vendor != NULL && strcmp(vendor, "AuthenticAMD") == 0)
		amd_mc_create(mod, chip, MCT_NODE_NAME, auth,
		    fms[0], fms[1], fms[2], &nerr);
	else if (!mc_offchip)
		onchip_mc_create(mod, chip, MCT_NODE_NAME, auth);

	return (err == 0 && nerr == 0 ? 0 : -1);
}

/*ARGSUSED*/
static int
create_chips(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, nvlist_t *auth,
    int mc_offchip)
{
	fmd_agent_hdl_t *hdl;
	nvlist_t **cpus;
	int nerr = 0;
	uint_t i, ncpu;

	if (strcmp(name, CHIP_NODE_NAME) != 0)
		return (0);

	if ((hdl = fmd_agent_open(FMD_AGENT_VERSION)) == NULL)
		return (-1);
	if (fmd_agent_physcpu_info(hdl, &cpus, &ncpu) != 0) {
		whinge(mod, NULL, "create_chip: fmd_agent_physcpu_info "
		    "failed: %s\n", fmd_agent_errmsg(hdl));
		fmd_agent_close(hdl);
		return (-1);
	}
	fmd_agent_close(hdl);

	for (i = 0; i < ncpu; i++) {
		nerr -= create_chip(mod, pnode, min, max, cpus[i], auth,
		    mc_offchip);
		nvlist_free(cpus[i]);
	}
	umem_free(cpus, sizeof (nvlist_t *) * ncpu);

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
	nvlist_t *auth = NULL;
	int offchip_mc;
	char buf[BUFSIZ];
	const char *dom0 = "control_d";

	/*
	 * Create nothing if we're running in domU.
	 */
	if (sysinfo(SI_PLATFORM, buf, sizeof (buf)) == -1)
		return (-1);

	if (strncmp(buf, "i86pc", sizeof (buf)) != 0 &&
	    strncmp(buf, "i86xpv", sizeof (buf)) != 0)
		return (0);

	if (strncmp(buf, "i86xpv", sizeof (buf)) == 0) {
		int fd = open("/dev/xen/domcaps", O_RDONLY);

		if (fd != -1) {
			if (read(fd, buf, sizeof (buf)) <= 0 ||
			    strncmp(buf, dom0, strlen(dom0)) != 0) {
				(void) close(fd);
				return (0);
			}
			(void) close(fd);
		}
	}

	auth = topo_mod_auth(mod, pnode);

	offchip_mc = mc_offchip_open();
	if (strcmp(name, CHIP_NODE_NAME) == 0)
		rv = create_chips(mod, pnode, name, min, max, NULL, auth,
		    offchip_mc);

	if (offchip_mc)
		(void) mc_offchip_create(mod, pnode, "memory-controller", auth);

	nvlist_free(auth);

	return (rv);
}
