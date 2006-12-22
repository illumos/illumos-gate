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
#include <errno.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/processor.h>
#include <sys/param.h>
#include <sys/fm/protocol.h>
#include <sys/systeminfo.h>
#include <fm/topo_mod.h>

/*
 * Enumerates the processing chips, or sockets, (as distinct from cores) in a
 * system.  For each chip found, the necessary nodes (one or more cores, and
 * possibly a memory controller) are constructed underneath.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	CHIP_VERSION	TOPO_VERSION
#define	CPU_NODE_NAME	"cpu"
#define	CHIP_NODE_NAME	"chip"

typedef struct chip {
	kstat_ctl_t *chip_kc;
	kstat_t **chip_cpustats;
	uint_t chip_ncpustats;
} chip_t;

static int chip_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);

static const topo_modops_t chip_ops =
	{ chip_enum, NULL};
static const topo_modinfo_t chip_info =
	{ "chip", FM_FMRI_SCHEME_HC, CHIP_VERSION, &chip_ops };

int
_topo_init(topo_mod_t *mod)
{
	chip_t *chip;

	if (getenv("TOPOCHIPDBG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing chip enumerator\n");

	if ((chip = topo_mod_zalloc(mod, sizeof (chip_t))) == NULL)
		return (-1);

	if ((chip->chip_kc = kstat_open()) == NULL) {
		topo_mod_dprintf(mod, "kstat_open failed: %s\n",
		    strerror(errno));
		topo_mod_free(mod, chip, sizeof (chip_t));
		return (-1);
	}

	chip->chip_ncpustats = sysconf(_SC_CPUID_MAX);
	if ((chip->chip_cpustats = topo_mod_zalloc(mod, (
	    chip->chip_ncpustats + 1) * sizeof (kstat_t *))) == NULL) {
		(void) kstat_close(chip->chip_kc);
		topo_mod_free(mod, chip, sizeof (chip_t));
		return (-1);
	}

	if (topo_mod_register(mod, &chip_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register hc: "
		    "%s\n", topo_mod_errmsg(mod));
		topo_mod_free(mod, chip->chip_cpustats,
		    (chip->chip_ncpustats + 1) * sizeof (kstat_t *));
		(void) kstat_close(chip->chip_kc);
		topo_mod_free(mod, chip, sizeof (chip_t));
		return (-1);
	}
	topo_mod_setspecific(mod, (void *)chip);

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	chip_t *chip;

	chip = topo_mod_getspecific(mod);

	if (chip->chip_cpustats != NULL)
		topo_mod_free(mod, chip->chip_cpustats,
		    (chip->chip_ncpustats + 1) * sizeof (kstat_t *));

	(void) kstat_close(chip->chip_kc);
	topo_mod_free(mod, chip, sizeof (chip_t));

	topo_mod_unregister(mod);
}

static int
cpu_kstat_init(chip_t *chip, int i)
{
	kstat_t *ksp;

	if (chip->chip_cpustats[i] == NULL) {
		if ((ksp = kstat_lookup(chip->chip_kc, "cpu_info", i, NULL)) ==
		    NULL || kstat_read(chip->chip_kc, ksp, NULL) < 0)
			return (-1);

		chip->chip_cpustats[i] = ksp;
	} else {
		ksp = chip->chip_cpustats[i];
	}

	return (ksp->ks_instance);
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

/*ARGSUSED*/
static int
cpu_create(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, chip_t *chip)
{
	int i, err, chip_id, nerr = 0;
	char *s, sbuf[21];
	tnode_t *cnode;
	kstat_named_t *ks, *kf;
	nvlist_t *fmri, *asru;
	nvlist_t *auth = topo_mod_auth(mod, rnode);

	/*
	 * Override what was created for us
	 */
	topo_node_range_destroy(rnode, name);
	if (topo_node_range_create(mod, rnode, name, 0, chip->chip_ncpustats)
	    < 0)
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));

	for (i = 0; i <= chip->chip_ncpustats; i++) {

		if ((chip_id = cpu_kstat_init(chip, i)) < 0)
			continue;

		if ((ks = kstat_data_lookup(chip->chip_cpustats[i],
		    "device_ID")) != NULL) {
			(void) snprintf(sbuf, 21, "%llX", ks->value.ui64);
			s = sbuf;
		} else {
			s = NULL;
		}

		fmri = topo_mod_hcfmri(mod, rnode, FM_HC_SCHEME_VERSION, name,
		    (topo_instance_t)chip_id, NULL, auth, NULL, NULL, s);
		if (fmri == NULL || (cnode = topo_node_bind(mod,
		    rnode, name, i, fmri)) == NULL) {
			++nerr;
			nvlist_free(fmri);
			continue;
		}
		nvlist_free(fmri);

		if ((asru = cpu_fmri_create(mod, i, s, 0)) != NULL) {
			(void) topo_node_asru_set(cnode, asru, 0, &err);
			nvlist_free(asru);
		} else {
			++nerr;
		}

		/*
		 * We look for a cpu_fru kstat.  If one is available and
		 * it contains something useful, use it as the label and
		 * and the FRU.
		 *
		 * This is a problem for platforms that do not properly
		 * support the cpu_fru kstat like Ontario or if
		 * we start exporting a different type of FRU label
		 */
		if ((kf = kstat_data_lookup(chip->chip_cpustats[i], "cpu_fru"))
		    != NULL && strcmp(KSTAT_NAMED_STR_PTR(kf),
		    "hc:///component=") != 0) {
			nvlist_t *fru;
			char *lp;

			if (topo_mod_str2nvl(mod, KSTAT_NAMED_STR_PTR(kf),
			    &fru) == 0) {
				(void) topo_node_fru_set(cnode, fru, 0, &err);
				nvlist_free(fru);
			}

			if ((lp = strchr(KSTAT_NAMED_STR_PTR(kf), '='))
			    == NULL) {
				(void) topo_node_label_set(cnode, NULL, &err);
			} else {
				++lp;
				(void) topo_node_label_set(cnode, lp, &err);
			}
		} else {
			(void) topo_node_label_set(cnode, NULL, &err);
		}
	}

	nvlist_free(auth);

	if (nerr != 0)
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	else
		return (0);
}

/*ARGSUSED*/
static int
chip_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	chip_t *chip = (chip_t *)arg;

	if (strcmp(name, CPU_NODE_NAME) == 0)
		return (cpu_create(mod, rnode, name, min, max, chip));

	return (0);
}
