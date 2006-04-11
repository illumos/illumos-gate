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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
    topo_instance_t, void *);

const topo_modinfo_t chip_info =
	{ "chip", CHIP_VERSION, chip_enum, NULL};

int
_topo_init(topo_mod_t *mod)
{
	chip_t *chip;

	topo_mod_setdebug(mod, TOPO_DBG_ALL);
	topo_mod_dprintf(mod, "initializing chip enumerator\n");

	if ((chip = topo_mod_zalloc(mod, sizeof (chip_t))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	if ((chip->chip_kc = kstat_open()) == NULL) {
		topo_mod_dprintf(mod, "kstat_open failed: %s\n",
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

	if (topo_mod_register(mod, &chip_info, (void *)chip) != 0) {
		topo_mod_dprintf(mod, "failed to register hc: "
		    "%s\n", topo_mod_errmsg(mod));
		topo_mod_free(mod, chip->chip_cpustats,
		    (chip->chip_ncpustats + 1) * sizeof (kstat_t *));
		(void) kstat_close(chip->chip_kc);
		topo_mod_free(mod, chip, sizeof (chip_t));
		return (-1); /* mod errno set */
	}

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	chip_t *chip = topo_mod_private(mod);

	if (chip->chip_cpustats != NULL)
		topo_mod_free(mod, chip->chip_cpustats,
		    (chip->chip_ncpustats + 1) * sizeof (kstat_t *));

	(void) kstat_close(chip->chip_kc);
	topo_mod_free(mod, chip, sizeof (chip_t));

	topo_mod_unregister(mod);
}

static int
chip_strprop(tnode_t *cnode, kstat_t *ksp, const char *name)
{
	int err;
	kstat_named_t *k;

	if ((k = kstat_data_lookup(ksp, (char *)name)) == NULL)
		return (0);

	(void) topo_prop_set_string(cnode, CHIP_PGROUP, name,
	    TOPO_PROP_SET_ONCE, k->value.str.addr.ptr, &err);

	return (-1);
}

static int
chip_longprop(tnode_t *cnode, kstat_t *ksp, const char *name)
{
	int err;
	kstat_named_t *k;

	if ((k = kstat_data_lookup(ksp, (char *)name)) == NULL)
		return (0);

	(void) topo_prop_set_int32(cnode, CHIP_PGROUP, name, TOPO_PROP_SET_ONCE,
	    k->value.l, &err);

	return (-1);
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

static int
cpu_create(topo_mod_t *mod, tnode_t *pnode, const char *name, int chipid,
    chip_t *chip)
{
	kstat_named_t *k;
	topo_hdl_t *thp;
	nvlist_t *fmri, *pfmri, *asru, *args;
	tnode_t *cnode;
	int i, err, nerr = 0;

	if (topo_node_range_create(mod, pnode, name, 0,
	    chip->chip_ncpustats) < 0)
		return (-1);

	thp = topo_mod_handle(mod);

	for (i = 0; i <= chip->chip_ncpustats; i++) {

		if (chip->chip_cpustats[i] == NULL)
			continue;

		if ((k = kstat_data_lookup(chip->chip_cpustats[i], "chip_id"))
		    == NULL || k->value.l != chipid) {
			++nerr;
			continue;
		}

		if ((k = kstat_data_lookup(chip->chip_cpustats[i], "clog_id"))
		    == NULL) {
			++nerr;
			continue;
		}

		args = pfmri = NULL;
		if (topo_node_resource(pnode, &pfmri, &err) < 0 ||
		    topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0 ||
		    nvlist_add_nvlist(args,
			TOPO_METH_FMRI_ARG_PARENT, pfmri) != 0) {
				nvlist_free(pfmri);
				nvlist_free(args);
				++nerr;
				continue;
			}

		fmri = topo_fmri_create(thp, FM_FMRI_SCHEME_HC, name,
		    (topo_instance_t)k->value.l, args, &err);
		nvlist_free(pfmri);
		nvlist_free(args);
		if (fmri == NULL) {
			++nerr;
			continue;
		}

		if ((cnode = topo_node_bind(mod, pnode, name, i, fmri,
		    NULL)) == NULL) {
			++nerr;
			nvlist_free(fmri);
			continue;
		}
		nvlist_free(fmri);

		if ((asru = cpu_fmri_create(mod, i, NULL, 0)) != NULL) {
			(void) topo_node_asru_set(cnode, asru, 0, &err);
			nvlist_free(asru);
		} else {
			++nerr;
		}
		(void) topo_node_fru_set(cnode, NULL, 0, &err);
	}

	if (nerr != 0)
		return (-1);
	else
		return (0);
}

static int
nvprop_add(nvpair_t *nvp, const char *pgname, tnode_t *node)
{
	int err;
	char *pname = nvpair_name(nvp);

	switch (nvpair_type(nvp)) {
	case DATA_TYPE_BOOLEAN_VALUE: {
		boolean_t val;

		if (nvpair_value_boolean_value(nvp, &val) == 0) {
			(void) topo_prop_set_string(node, pgname, pname,
			    TOPO_PROP_SET_ONCE, (val ? "true" : "false"), &err);
		}
		return (0);
	}

	case DATA_TYPE_UINT64: {
		uint64_t val;

		if (nvpair_value_uint64(nvp, &val) == 0) {
			(void) topo_prop_set_uint64(node, pgname, pname,
			    TOPO_PROP_SET_ONCE, val, &err);
		}
		return (0);
	}

	case DATA_TYPE_STRING: {
		char *str;

		if (nvpair_value_string(nvp, &str) == 0)
			(void) topo_prop_set_string(node, pgname, pname,
			    TOPO_PROP_SET_ONCE, str, &err);
		return (0);
	}

	default:
		return (-1);
	}
}

nvlist_t *
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
cs_create(topo_mod_t *mod, tnode_t *pnode, const char *name, nvlist_t *mc)
{
	int i, err, nerr = 0;
	nvpair_t *nvp;
	tnode_t *csnode;
	topo_hdl_t *thp;
	nvlist_t *fmri, **csarr = NULL;
	nvlist_t *pfmri, *args;
	uint64_t csnum;
	uint_t ncs;

	if (nvlist_lookup_nvlist_array(mc, "cslist", &csarr, &ncs) != 0 ||
	    ncs == 0)
		return (-1);

	if (topo_node_range_create(mod, pnode, name, 0, MAX_CSNUM) < 0)
		return (-1);

	thp = topo_mod_handle(mod);
	for (i = 0; i < ncs; i++) {
		if (nvlist_lookup_uint64(csarr[i], "num", &csnum) != 0) {
			++nerr;
			continue;
		}

		args = pfmri = NULL;
		if (topo_node_resource(pnode, &pfmri, &err) < 0 ||
		    topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0 ||
		    nvlist_add_nvlist(args,
			TOPO_METH_FMRI_ARG_PARENT, pfmri) != 0) {
				nvlist_free(pfmri);
				nvlist_free(args);
				++nerr;
				continue;
			}
		fmri = topo_fmri_create(thp, FM_FMRI_SCHEME_HC, name,
		    csnum, args, &err);
		nvlist_free(pfmri);
		nvlist_free(args);
		if (fmri == NULL) {
			++nerr;
			continue;
		}

		if ((csnode = topo_node_bind(mod, pnode, name, csnum, fmri,
		    NULL)) == NULL) {
			nvlist_free(fmri);
			++nerr;
			continue;
		}

		nvlist_free(fmri);

		(void) topo_pgroup_create(csnode, CS_PGROUP,
		    TOPO_STABILITY_PRIVATE, &err);

		for (nvp = nvlist_next_nvpair(csarr[i], NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(csarr[i], nvp)) {
			(void) nvprop_add(nvp, CS_PGROUP, csnode);
		}
	}

	if (nerr != 0)
		return (-1);
	else
		return (0);
}

static int
dimm_create(topo_mod_t *mod, tnode_t *pnode, const char *name, nvlist_t *mc)
{
	int i, err, nerr = 0;
	nvpair_t *nvp;
	tnode_t *dimmnode;
	nvlist_t *fmri, *asru, **dimmarr = NULL;
	nvlist_t *pfmri, *args;
	uint64_t ldimmnum;
	uint_t ndimm;
	topo_hdl_t *thp;

	thp = topo_mod_handle(mod);

	if (nvlist_lookup_nvlist_array(mc, "dimmlist", &dimmarr, &ndimm) != 0 ||
	    ndimm == 0)
		return (-1);

	if (topo_node_range_create(mod, pnode, name, 0, MAX_DIMMNUM) < 0)
		return (-1);

	for (i = 0; i < ndimm; i++) {
		if (nvlist_lookup_uint64(dimmarr[i], "num", &ldimmnum) != 0) {
			++nerr;
			continue;
		}

		args = pfmri = NULL;
		if (topo_node_resource(pnode, &pfmri, &err) < 0 ||
		    topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0 ||
		    nvlist_add_nvlist(args,
		    TOPO_METH_FMRI_ARG_PARENT, pfmri) != 0) {
				nvlist_free(pfmri);
				nvlist_free(args);
				++nerr;
				continue;
			}
		fmri = topo_fmri_create(thp,
		    FM_FMRI_SCHEME_HC, name, ldimmnum, args, &err);
		nvlist_free(pfmri);
		nvlist_free(args);
		if (fmri == NULL) {
			++nerr;
			continue;
		}

		if ((dimmnode = topo_node_bind(mod, pnode, name, ldimmnum, fmri,
		    NULL)) == NULL) {
			nvlist_free(fmri);
			++nerr;
			continue;
		}

		(void) topo_node_fru_set(dimmnode, fmri, 0, &err);
		if ((asru = mem_fmri_create(mod)) != NULL) {
			(void) topo_node_asru_set(dimmnode, asru,
			    TOPO_ASRU_COMPUTE, &err);
			nvlist_free(asru);
		}

		nvlist_free(fmri);

		(void) topo_pgroup_create(dimmnode, DIMM_PGROUP,
		    TOPO_STABILITY_PRIVATE, &err);

		for (nvp = nvlist_next_nvpair(dimmarr[i], NULL); nvp != NULL;
		    nvp = nvlist_next_nvpair(dimmarr[i], nvp)) {
			if (nvprop_add(nvp, DIMM_PGROUP, dimmnode) == 0) {
				continue;
			} else if (nvpair_type(nvp) == DATA_TYPE_UINT64_ARRAY) {
				uint64_t *csnumarr;
				uint_t ncs;
				int i;

				if (strcmp(nvpair_name(nvp), "csnums") != 0 ||
				    nvpair_value_uint64_array(nvp, &csnumarr,
				    &ncs) != 0)
					continue;

				for (i = 0; i < ncs; i++) {
					char name[7];
					(void) snprintf(name, sizeof (name),
					    "csnum%d", i);
					(void) topo_prop_set_uint64(dimmnode,
					    DIMM_PGROUP, name,
					    TOPO_PROP_SET_ONCE,
					    csnumarr[i], &err);
				}
			}
		}
	}

	if (nerr != 0)
		return (-1);
	else
		return (0);
}

static nvlist_t *
mc_lookup_by_mcid(topo_mod_t *mod, topo_instance_t id)
{
	mc_snapshot_info_t mcs;
	void *buf = NULL;

	nvlist_t *nvl;
	char path[64];
	int fd, err;

	(void) snprintf(path, sizeof (path), "/dev/mc/mc%d", id);
	fd = open(path, O_RDONLY);

	if (fd == -1) {
		topo_mod_dprintf(mod, "mc failed to open %s: %s\n",
		    path, strerror(errno));
		return (NULL);
	}

	if (ioctl(fd, MC_IOC_SNAPSHOT_INFO, &mcs) == -1 ||
	    (buf = topo_mod_alloc(mod, mcs.mcs_size)) == NULL ||
	    ioctl(fd, MC_IOC_SNAPSHOT, buf) == -1) {

		topo_mod_dprintf(mod, "mc failed to snapshot %s: %s\n",
		    path, strerror(errno));

		free(buf);
		(void) close(fd);
		return (NULL);
	}

	(void) close(fd);
	err = nvlist_unpack(buf, mcs.mcs_size, &nvl, 0);
	topo_mod_free(mod, buf, mcs.mcs_size);
	return (err ? NULL : nvl);
}

static int
mc_create(topo_mod_t *mod, tnode_t *pnode, const char *name)
{
	int err, rc = 0;
	tnode_t *mcnode;
	nvlist_t *fmri;
	nvpair_t *nvp;
	nvlist_t *mc = NULL;
	nvlist_t *pfmri, *args;
	topo_hdl_t *thp;

	thp = topo_mod_handle(mod);
	args = pfmri = NULL;
	if (topo_node_resource(pnode, &pfmri, &err) < 0 ||
	    topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_nvlist(args, TOPO_METH_FMRI_ARG_PARENT, pfmri) != 0) {
		nvlist_free(pfmri);
		nvlist_free(args);
		return (-1);
	}
	fmri = topo_fmri_create(thp, FM_FMRI_SCHEME_HC, name, 0, args, &err);
	nvlist_free(pfmri);
	nvlist_free(args);
	if (fmri == NULL)
		return (-1);

	if (topo_node_range_create(mod, pnode, name, 0, 0) < 0) {
		nvlist_free(fmri);
		return (-1);
	}

	/*
	 * Gather and create memory controller topology
	 */
	if ((mc = mc_lookup_by_mcid(mod, topo_node_instance(pnode))) == NULL ||
	    (mcnode = topo_node_bind(mod, pnode,
	    name, 0, fmri, NULL)) == NULL) {
		if (mc != NULL)
			nvlist_free(mc);
		topo_node_range_destroy(pnode, name);
		nvlist_free(fmri);
		return (-1);
	}

	(void) topo_node_fru_set(mcnode, NULL, 0, &err);
	nvlist_free(fmri);

	/*
	 * Add memory controller properties
	 */
	(void) topo_pgroup_create(mcnode, MC_PGROUP,
	    TOPO_STABILITY_PRIVATE, &err);

	for (nvp = nvlist_next_nvpair(mc, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(mc, nvp)) {
		if (nvprop_add(nvp, MC_PGROUP, mcnode) == 0)
			continue;
		else if (nvpair_type(nvp) == DATA_TYPE_NVLIST_ARRAY)
			break;
	}

	if (dimm_create(mod, mcnode, DIMM_NODE_NAME, mc) != 0 ||
	    cs_create(mod, mcnode, CS_NODE_NAME, mc) != 0)
		rc = -1;

	nvlist_free(mc);
	return (rc);
}

static int
chip_create(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, chip_t *chip)
{
	int i, nerr = 0;
	kstat_t *ksp;
	ulong_t *chipmap;
	tnode_t *cnode;
	nvlist_t *pfmri, *fmri, *args;
	topo_hdl_t *thp;

	thp = topo_mod_handle(mod);

	if ((chipmap = topo_mod_zalloc(mod, BT_BITOUL(chip->chip_ncpustats) *
	    sizeof (ulong_t))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	for (i = min; i <= MAX(max, chip->chip_ncpustats); i++) {

		if (i < min || i > max)
			break;

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
			++nerr;
			continue;
		}

		chipid = k->value.l;
		if (BT_TEST(chipmap, chipid))
			continue;

		if (chipid < min || chipid > max)
			continue;

		args = pfmri = NULL;
		if (topo_node_resource(pnode, &pfmri, &err) < 0 ||
		    topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0 ||
		    nvlist_add_nvlist(args,
		    TOPO_METH_FMRI_ARG_PARENT, pfmri) != 0) {
			nvlist_free(pfmri);
			nvlist_free(args);
			++nerr;
			continue;
		}
		fmri = topo_fmri_create(thp,
		    FM_FMRI_SCHEME_HC, name, chipid, args, &err);
		nvlist_free(pfmri);
		nvlist_free(args);
		if (fmri == NULL) {
			++nerr;
			continue;
		}

		if ((cnode = topo_node_bind(mod, pnode, name, chipid, fmri,
		    NULL)) == NULL) {
			++nerr;
			nvlist_free(fmri);
			continue;
		}

		(void) topo_node_fru_set(cnode, fmri, 0, &err);

		nvlist_free(fmri);

		(void) topo_pgroup_create(cnode, CHIP_PGROUP,
		    TOPO_STABILITY_PRIVATE, &err);
		(void) chip_strprop(cnode, ksp, CHIP_VENDOR_ID);
		(void) chip_longprop(cnode, ksp, CHIP_FAMILY);
		(void) chip_longprop(cnode, ksp, CHIP_MODEL);
		(void) chip_longprop(cnode, ksp, CHIP_STEPPING);

		if (mc_create(mod, cnode, MC_NODE_NAME) != 0 ||
		    cpu_create(mod, cnode, CPU_NODE_NAME, chipid, chip) != 0)
			++nerr;
	}

	topo_mod_free(mod, chipmap, BT_BITOUL(chip->chip_ncpustats) *
	    sizeof (ulong_t));

	if (nerr != 0)
		(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);

	return (0);
}

static int
chip_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg)
{
	chip_t *chip = (chip_t *)arg;

	if (strcmp(name, "chip") == 0)
		return (chip_create(mod, pnode, name, min, max, chip));

	return (0);
}
