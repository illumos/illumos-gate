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
	{ FSB2_CHIP_LBL, "Property method", 0,
	    TOPO_STABILITY_INTERNAL, fsb2_chip_label},
	{ TOPO_METH_REPLACED, TOPO_METH_REPLACED_DESC,
	    TOPO_METH_REPLACED_VERSION, TOPO_STABILITY_INTERNAL,
	    chip_fmri_replaced },
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
    topo_instance_t inst, nvlist_t *cpu, uint16_t smbios_id)
{
	nvlist_t *fmri;
	tnode_t *cnode;

	if (mkrsrc(mod, pnode, name, inst, auth, &fmri) != 0) {
		whinge(mod, NULL, "create_node: mkrsrc failed\n");
		return (NULL);
	}

	if (FM_AWARE_SMBIOS(mod)) {
		id_t phys_cpu_smbid;
		int perr = 0;
		const char *serial = NULL;
		const char *part = NULL;
		const char *rev = NULL;

		phys_cpu_smbid = smbios_id;
		serial = chip_serial_smbios_get(mod, phys_cpu_smbid);
		part = chip_part_smbios_get(mod, phys_cpu_smbid);
		rev = chip_rev_smbios_get(mod, phys_cpu_smbid);

		perr += nvlist_add_string(fmri, FM_FMRI_HC_SERIAL_ID,
		    serial);
		perr += nvlist_add_string(fmri, FM_FMRI_HC_PART,
		    part);
		perr += nvlist_add_string(fmri, FM_FMRI_HC_REVISION,
		    rev);

		if (perr != 0)
			whinge(mod, NULL,
			    "create_node: nvlist_add_string failed\n");

		topo_mod_strfree(mod, (char *)serial);
		topo_mod_strfree(mod, (char *)part);
		topo_mod_strfree(mod, (char *)rev);
	} else {
		char *serial = NULL;

		if (nvlist_lookup_string(cpu, FM_PHYSCPU_INFO_CHIP_IDENTSTR,
		    &serial) == 0) {
			if (nvlist_add_string(fmri, FM_FMRI_HC_SERIAL_ID,
			    serial) != 0) {
				whinge(mod, NULL,
				    "create_node: nvlist_add_string failed\n");
			}
		}
	}

	cnode = topo_node_bind(mod, pnode, name, inst, fmri);

	nvlist_free(fmri);
	if (cnode == NULL) {
		whinge(mod, NULL, "create_node: node bind failed"
		    " for %s %d\n", name, (int)inst);
	}

	return (cnode);
}

static int
create_strand(topo_mod_t *mod, tnode_t *pnode, nvlist_t *cpu,
    nvlist_t *auth, uint16_t chip_smbiosid)
{
	tnode_t *strand;
	int32_t strandid, cpuid;
	int err, perr, nerr = 0;
	nvlist_t *fmri;
	char *serial = NULL;
	char *part = NULL;
	char *rev = NULL;

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
	    strandid, cpu, chip_smbiosid)) == NULL)
		return (-1);

	/*
	 * Inherit FRU from core node, in native use cpu scheme ASRU,
	 * in xpv, use hc scheme ASRU.
	 */
	(void) topo_node_fru_set(strand, NULL, 0, &perr);
	/*
	 * From the inherited FRU, extract the Serial
	 * number(if SMBIOS donates) and set it in the ASRU
	 */
	if (FM_AWARE_SMBIOS(mod)) {
		char *val = NULL;

		if (topo_prop_get_fmri(strand, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_RESOURCE, &fmri, &err) != 0)
			whinge(mod, NULL,
			    "create_strand: topo_prop_get_fmri failed\n");
		if (nvlist_lookup_string(fmri, FM_FMRI_HC_SERIAL_ID, &val) != 0)
			whinge(mod, NULL,
			    "create_strand: nvlist_lookup_string failed: \n");
		else
			serial = topo_mod_strdup(mod, val);
		nvlist_free(fmri);
	}
	if (is_xpv()) {
		if (topo_node_resource(strand, &fmri, &err) == -1) {
			whinge(mod, &nerr, "create_strand: "
			    "topo_node_resource failed\n");
		} else {
			if (FM_AWARE_SMBIOS(mod))
				(void) nvlist_add_string(fmri,
				    FM_FMRI_HC_SERIAL_ID, serial);
			(void) topo_node_asru_set(strand, fmri, 0, &err);
			nvlist_free(fmri);
		}
	} else {
		if (nvlist_lookup_int32(cpu, STRAND_CPU_ID, &cpuid) != 0) {
			whinge(mod, &nerr, "create_strand: lookup cpuid "
			    "failed\n");
		} else {
			if ((fmri = cpu_fmri_create(mod, cpuid, serial, 0))
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
	    STRAND_CHIP_ID, STRAND_PROCNODE_ID, STRAND_CORE_ID, STRAND_CPU_ID,
	    NULL);

	if (FM_AWARE_SMBIOS(mod)) {
		(void) topo_node_label_set(strand, NULL, &perr);

		if (topo_node_resource(strand, &fmri, &perr) != 0) {
			whinge(mod, &nerr, "create_strand: "
			    "topo_node_resource failed\n");
			perr = 0;
		}

		perr += nvlist_lookup_string(fmri,
		    FM_FMRI_HC_PART, &part);
		perr += nvlist_lookup_string(fmri,
		    FM_FMRI_HC_REVISION, &rev);

		if (perr != 0) {
			whinge(mod, NULL,
			    "create_strand: nvlist_lookup_string failed\n");
			perr = 0;
		}

		perr += topo_prop_set_string(strand, PGNAME(STRAND),
		    FM_FMRI_HC_SERIAL_ID, TOPO_PROP_IMMUTABLE, serial, &perr);
		perr += topo_prop_set_string(strand, PGNAME(STRAND),
		    FM_FMRI_HC_PART, TOPO_PROP_IMMUTABLE, part, &perr);
		perr += topo_prop_set_string(strand, PGNAME(STRAND),
		    FM_FMRI_HC_REVISION, TOPO_PROP_IMMUTABLE, rev, &perr);

		if (perr != 0)
			whinge(mod, NULL, "create_strand: topo_prop_set_string"
			    "failed\n");

		nvlist_free(fmri);
		topo_mod_strfree(mod, serial);
	}

	return (err == 0 && nerr == 0 ? 0 : -1);
}

static int
create_core(topo_mod_t *mod, tnode_t *pnode, nvlist_t *cpu,
    nvlist_t *auth, uint16_t chip_smbiosid)
{
	tnode_t *core;
	int32_t coreid, cpuid;
	int err, perr, nerr = 0;
	nvlist_t *fmri;
	char *serial = NULL;
	char *part = NULL;
	char *rev = NULL;

	if ((err = nvlist_lookup_int32(cpu, FM_PHYSCPU_INFO_CORE_ID, &coreid))
	    != 0) {
		whinge(mod, NULL, "create_core: lookup core_id failed: %s\n",
		    strerror(err));
		return (-1);
	}
	if ((core = topo_node_lookup(pnode, CORE_NODE_NAME, coreid)) == NULL) {
		if ((core = create_node(mod, pnode, auth, CORE_NODE_NAME,
		    coreid, cpu, chip_smbiosid)) == NULL)
			return (-1);

		/*
		 * Inherit FRU from the chip node, for native, we use hc
		 * scheme ASRU for the core node.
		 */
		(void) topo_node_fru_set(core, NULL, 0, &perr);
		/*
		 * From the inherited FRU, extract the Serial
		 * number if SMBIOS donates and set it in the ASRU
		 */
		if (FM_AWARE_SMBIOS(mod)) {
			char *val = NULL;

			if (topo_node_resource(core, &fmri, &err) != 0)
				whinge(mod, NULL,
				    "create_core: topo_prop_get_fmri failed\n");
			if (nvlist_lookup_string(fmri, FM_FMRI_HC_SERIAL_ID,
			    &val) != 0)
				whinge(mod, NULL, "create_core:"
				    "nvlist_lookup_string failed\n");
			else
				serial = topo_mod_strdup(mod, val);
			nvlist_free(fmri);
		}
		if (is_xpv()) {
			if (topo_node_resource(core, &fmri, &err) == -1) {
				whinge(mod, &nerr, "create_core: "
				    "topo_node_resource failed\n");
			} else {
				if (FM_AWARE_SMBIOS(mod))
					(void) nvlist_add_string(fmri,
					    FM_FMRI_HC_SERIAL_ID, serial);
				(void) topo_node_asru_set(core, fmri, 0, &err);
				nvlist_free(fmri);
			}
		}
		if (topo_method_register(mod, core, strands_retire_methods) < 0)
			whinge(mod, &nerr, "create_core: "
			    "topo_method_register failed\n");

		(void) topo_pgroup_create(core, &core_pgroup, &err);
		nerr -= add_nvlist_longprops(mod, core, cpu, PGNAME(CORE), NULL,
		    CORE_CHIP_ID, CORE_PROCNODE_ID, NULL);

		if (topo_node_range_create(mod, core, STRAND_NODE_NAME,
		    0, 255) != 0)
			return (-1);

		/*
		 * Creating a temperature sensor may fail because the sensor
		 * doesn't exist or due to internal reasons. At the moment, we
		 * swallow any such errors that occur.
		 */
		(void) chip_create_core_temp_sensor(mod, core);
	}

	if (!is_xpv()) {
		/*
		 * In native mode, we're in favor of cpu scheme ASRU for
		 * printing reason.  More work needs to be done to support
		 * multi-strand cpu: the ASRU will be a list of cpuid then.
		 */
		if (nvlist_lookup_int32(cpu, STRAND_CPU_ID, &cpuid) != 0) {
			whinge(mod, &nerr, "create_core: lookup cpuid "
			    "failed\n");
		} else {
			if ((fmri = cpu_fmri_create(mod, cpuid, serial, 0))
			    != NULL) {
				(void) topo_node_asru_set(core, fmri, 0, &err);
				nvlist_free(fmri);
			} else {
				whinge(mod, &nerr, "create_core: "
				    "cpu_fmri_create() failed\n");
			}
		}
	}

	if (FM_AWARE_SMBIOS(mod)) {
		(void) topo_node_label_set(core, NULL, &perr);

		if (topo_node_resource(core, &fmri, &perr) != 0) {
			whinge(mod, &nerr, "create_core: "
			    "topo_node_resource failed\n");
			perr = 0;
		}

		perr += nvlist_lookup_string(fmri,
		    FM_FMRI_HC_PART, &part);
		perr += nvlist_lookup_string(fmri,
		    FM_FMRI_HC_REVISION, &rev);

		if (perr != 0) {
			whinge(mod, NULL,
			    "create_core: nvlist_lookup_string failed\n");
			perr = 0;
		}

		perr += topo_prop_set_string(core, PGNAME(CORE),
		    FM_FMRI_HC_SERIAL_ID, TOPO_PROP_IMMUTABLE, serial, &perr);
		perr += topo_prop_set_string(core, PGNAME(CORE),
		    FM_FMRI_HC_PART, TOPO_PROP_IMMUTABLE, part, &perr);
		perr += topo_prop_set_string(core, PGNAME(CORE),
		    FM_FMRI_HC_REVISION, TOPO_PROP_IMMUTABLE, rev, &perr);

		if (perr != 0)
			whinge(mod, NULL, "create_core: topo_prop_set_string"
			    "failed\n");

		nvlist_free(fmri);
		topo_mod_strfree(mod, serial);
	}

	err = create_strand(mod, core, cpu, auth, chip_smbiosid);

	return (err == 0 && nerr == 0 ? 0 : -1);
}

static int
create_chip(topo_mod_t *mod, tnode_t *pnode, topo_instance_t min,
    topo_instance_t max, nvlist_t *cpu, nvlist_t *auth,
    int mc_offchip, kstat_ctl_t *kc)
{
	tnode_t *chip;
	nvlist_t *fmri = NULL;
	int err, perr, nerr = 0;
	int32_t chipid, procnodeid, procnodes_per_pkg;
	const char *vendor, *brand;
	int32_t family, model;
	boolean_t create_mc = B_FALSE;
	uint16_t smbios_id;

	/*
	 * /dev/fm will export the chipid based on SMBIOS' ordering
	 * of Type-4 structures, if SMBIOS meets FMA needs
	 */
	err = nvlist_lookup_pairs(cpu, 0,
	    FM_PHYSCPU_INFO_CHIP_ID, DATA_TYPE_INT32, &chipid,
	    FM_PHYSCPU_INFO_NPROCNODES, DATA_TYPE_INT32, &procnodes_per_pkg,
	    FM_PHYSCPU_INFO_PROCNODE_ID, DATA_TYPE_INT32, &procnodeid,
	    FM_PHYSCPU_INFO_VENDOR_ID, DATA_TYPE_STRING, &vendor,
	    FM_PHYSCPU_INFO_FAMILY, DATA_TYPE_INT32, &family,
	    FM_PHYSCPU_INFO_MODEL, DATA_TYPE_INT32, &model,
	    NULL);

	if (err) {
		whinge(mod, NULL, "create_chip: lookup failed: %s\n",
		    strerror(err));
		return (-1);
	}

	if (chipid < min || chipid > max)
		return (-1);

	if (FM_AWARE_SMBIOS(mod)) {
		if ((err = nvlist_lookup_uint16(cpu,
		    FM_PHYSCPU_INFO_SMBIOS_ID, &smbios_id)) != 0) {
			whinge(mod, NULL,
			    "create_chip: lookup smbios_id failed"
			    ": enumerating x86pi & chip topology, but"
			    " no Chip properties from SMBIOS"
			    " - err msg : %s\n", strerror(err));
			/*
			 * Lets reset the module specific
			 * data to NULL, overriding any
			 * SMBIOS capability encoded earlier.
			 * This will fail all subsequent
			 * FM_AWARE_SMBIOS checks.
			 */
			topo_mod_setspecific(mod, NULL);
		}
	}

	if ((chip = topo_node_lookup(pnode, CHIP_NODE_NAME, chipid)) == NULL) {
		if ((chip = create_node(mod, pnode, auth, CHIP_NODE_NAME,
		    chipid, cpu, smbios_id)) == NULL)
			return (-1);
		/*
		 * Do not register XML map methods if SMBIOS can provide
		 * serial, part, revision & label
		 */
		if (!FM_AWARE_SMBIOS(mod)) {
			if (topo_method_register(mod, chip, chip_methods) < 0)
				whinge(mod, &nerr, "create_chip: "
				    "topo_method_register failed\n");
		}

		(void) topo_pgroup_create(chip, &chip_pgroup, &err);
		nerr -= add_nvlist_strprop(mod, chip, cpu, PGNAME(CHIP),
		    CHIP_VENDOR_ID, NULL);
		nerr -= add_nvlist_longprops(mod, chip, cpu, PGNAME(CHIP),
		    NULL, CHIP_FAMILY, CHIP_MODEL, CHIP_STEPPING, NULL);

		/*
		 * Attempt to lookup the processor brand string in kstats.
		 * and add it as a prop, if found.
		 */
		brand = get_chip_brand(mod, kc, chipid);
		if (brand != NULL && topo_prop_set_string(chip, PGNAME(CHIP),
		    CHIP_BRAND, TOPO_PROP_IMMUTABLE, brand, &perr) != 0) {
			whinge(mod, &nerr, "failed to set prop %s/%s",
			    PGNAME(CHIP), CHIP_BRAND);
		}
		topo_mod_strfree(mod, (char *)brand);

		if (FM_AWARE_SMBIOS(mod)) {
			int fru = 0;
			char *serial = NULL;
			char *part = NULL;
			char *rev = NULL;
			char *label;

			fru = chip_fru_smbios_get(mod, smbios_id);
			/*
			 * Chip is not a FRU, set the FRU fmri of parent node
			 */
			if (topo_node_resource(chip, &fmri, &perr) != 0)
				whinge(mod, &nerr, "create_chip: "
				    "topo_node_resource failed\n");
			if (!fru) {
				(void) topo_node_fru_set(chip, NULL, 0, &perr);
				label = NULL;
			} else {
				label = (char *)chip_label_smbios_get(mod,
				    pnode, smbios_id, NULL);

				if (topo_node_fru_set(chip, fmri, 0, &perr)
				    != 0) {
					whinge(mod, NULL, "create_chip: "
					    "topo_node_fru_set failed\n");
					perr = 0;
				}
			}

			perr += nvlist_lookup_string(fmri,
			    FM_FMRI_HC_SERIAL_ID, &serial);
			perr += nvlist_lookup_string(fmri,
			    FM_FMRI_HC_PART, &part);
			perr += nvlist_lookup_string(fmri,
			    FM_FMRI_HC_REVISION, &rev);

			if (perr != 0) {
				whinge(mod, NULL,
				    "create_chip: nvlist_lookup_string"
				    "failed\n");
				perr = 0;
			}

			perr += topo_prop_set_string(chip, PGNAME(CHIP),
			    FM_FMRI_HC_SERIAL_ID, TOPO_PROP_IMMUTABLE,
			    serial, &perr);
			perr += topo_prop_set_string(chip, PGNAME(CHIP),
			    FM_FMRI_HC_PART, TOPO_PROP_IMMUTABLE,
			    part, &perr);
			perr += topo_prop_set_string(chip, PGNAME(CHIP),
			    FM_FMRI_HC_REVISION, TOPO_PROP_IMMUTABLE,
			    rev, &perr);

			if (perr != 0)
				whinge(mod, NULL,
				    "create_chip: topo_prop_set_string"
				    "failed\n");

			nvlist_free(fmri);

			if (topo_node_label_set(chip, label, &perr)
			    == -1) {
				whinge(mod, NULL, "create_chip: "
				    "topo_node_label_set failed\n");
			}
			topo_mod_strfree(mod, label);

		} else {
			if (topo_node_resource(chip, &fmri, &err) == -1) {
				whinge(mod, &nerr, "create_chip: "
				    "topo_node_resource failed\n");
			} else {
				(void) topo_node_fru_set(chip, fmri, 0, &perr);
				nvlist_free(fmri);
			}
		}

		if (topo_method_register(mod, chip, strands_retire_methods) < 0)
			whinge(mod, &nerr, "create_chip: "
			    "topo_method_register failed\n");

		if (topo_node_range_create(mod, chip, CORE_NODE_NAME, 0, 255))
			return (-1);

		if (strcmp(vendor, "AuthenticAMD") == 0) {
			if (topo_node_range_create(mod, chip, MCT_NODE_NAME,
			    0, 255))
				return (-1);
		}

		create_mc = B_TRUE;

		/*
		 * Creating a temperature sensor may fail because the sensor
		 * doesn't exist or due to internal reasons. At the moment, we
		 * swallow any such errors that occur.
		 */
		(void) chip_create_chip_temp_sensor(mod, chip);
	}

	if (FM_AWARE_SMBIOS(mod)) {
		int status = 0;
		/*
		 * STATUS
		 * CPU Socket Populated
		 * CPU Socket Unpopulated
		 * Populated : Enabled
		 * Populated : Disabled by BIOS (Setup)
		 * Populated : Disabled by BIOS (Error)
		 * Populated : Idle
		 *
		 * Enumerate core & strand only for Populated : Enabled
		 * Enumerate Off-Chip Memory Controller only for
		 * Populated : Enabled
		 */

		status = chip_status_smbios_get(mod, (id_t)smbios_id);
		if (!status) {
			whinge(mod, NULL, "create_chip: "
			    "CPU Socket is not populated or is disabled\n");
			return (0);
		}
	}

	err = create_core(mod, chip, cpu, auth, smbios_id);

	/*
	 * Create memory-controller node under a chip for architectures
	 * that may have on-chip memory-controller(s).
	 * If SMBIOS meets FMA needs, when Multi-Chip-Module is
	 * addressed, mc instances should be derived from SMBIOS
	 */
	if (strcmp(vendor, "AuthenticAMD") == 0) {
		amd_mc_create(mod, smbios_id, chip, MCT_NODE_NAME, auth,
		    procnodeid, procnodes_per_pkg, family, model, &nerr);
	} else if (create_mc && !mc_offchip)
		onchip_mc_create(mod, smbios_id, chip, MCT_NODE_NAME, auth);

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
	kstat_ctl_t *kc;

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

	if ((kc = kstat_open()) == NULL) {
		whinge(mod, NULL, "kstat_open() failed");
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}

	for (i = 0; i < ncpu; i++) {
		nerr -= create_chip(mod, pnode, min, max, cpus[i], auth,
		    mc_offchip, kc);
		nvlist_free(cpus[i]);
	}
	(void) kstat_close(kc);
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
    topo_instance_t min, topo_instance_t max, void *arg, void *smbios_enabled)
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

	/*
	 * Set Chip Enumerator Module's private data with the value passed by
	 * x86pi Enumerator, defining SMBIOS capabilities
	 */
	topo_mod_setspecific(mod, smbios_enabled);

	if (FM_AWARE_SMBIOS(mod))
		if (init_chip_smbios(mod) != 0) {
			whinge(mod, NULL,
			    "init_chip_smbios() failed, "
			    " enumerating x86pi & chip topology, but no"
			    " CPU & Memory properties will be"
			    " derived from SMBIOS\n");
			/*
			 * Lets reset the module specific
			 * data to NULL, overriding any
			 * SMBIOS capability encoded earlier.
			 * This will fail all subsequent
			 * FM_AWARE_SMBIOS checks.
			 */
			topo_mod_setspecific(mod, NULL);
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
