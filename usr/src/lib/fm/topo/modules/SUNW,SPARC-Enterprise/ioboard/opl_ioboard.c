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
 * SUNW,OPL-Enterprise platform ioboard topology enumerator
 */
#include <string.h>
#include <strings.h>
#include <libdevinfo.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/fm/protocol.h>
#include "opl_topo.h"

#define	IOB_ENUMR_VERS	1
#define	FRUNAME		"iou"
#define	LABEL		FRUNAME "#%d"
#define	IOBDFRU		"hc:///component=" LABEL

#define	IKKAKU_FRUNAME	"MBU_A"
#define	IKKAKU_LABEL	IKKAKU_FRUNAME
#define	IKKAKU_IOBDFRU	"hc:///component=" IKKAKU_LABEL

static int opl_iob_enum(topo_mod_t *hdl, tnode_t *parent, const char *name,
    topo_instance_t imin, topo_instance_t imax, void *notused1, void *notused2);

static const topo_modops_t Iobops =
	{ opl_iob_enum, NULL };

static const topo_modinfo_t IobInfo = {
	IOBOARD,
	FM_FMRI_SCHEME_HC,
	IOB_ENUMR_VERS,
	&Iobops};

/* OPL model type */
typedef enum {
	MODEL_FF,
	MODEL_DC,
	MODEL_IKKAKU
} opl_model_t;

void
_topo_init(topo_mod_t *modhdl)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOIOBDBG") != NULL)
		topo_mod_setdebug(modhdl);
	topo_mod_dprintf(modhdl, "initializing ioboard enumerator\n");

	topo_mod_register(modhdl, &IobInfo, TOPO_VERSION);
}

void
_topo_fini(topo_mod_t *modhdl)
{
	topo_mod_unregister(modhdl);
}

/*
 * Checks to see if there's a physical board number property on this
 * device node.
 */
static int
opl_get_physical_board(topo_mod_t *mod, di_node_t n)
{
	di_prom_handle_t ptp = DI_PROM_HANDLE_NIL;
	di_prom_prop_t pp = DI_PROM_PROP_NIL;
	uchar_t *buf;
	int val;

	if ((ptp = topo_mod_prominfo(mod)) == DI_PROM_HANDLE_NIL)
		return (-1);

	for (pp = di_prom_prop_next(ptp, n, pp);
	    pp != DI_PROM_PROP_NIL;
	    pp = di_prom_prop_next(ptp, n, pp)) {
		if (strcmp(di_prom_prop_name(pp), OPL_PHYSICAL_BD) == 0) {
			if (di_prom_prop_data(pp, &buf) < sizeof (val))
				continue;
			bcopy(buf, &val, sizeof (val));
			return (val);
		}
	}
	return (-1);
}

/*
 * Creates a map of logical boards to physical location.
 */
static void
opl_map_boards(topo_mod_t *mod, di_node_t opl_devtree,
    int lsb_to_psb[OPL_IOB_MAX])
{
	di_node_t n;
	int i;

	/* Initialize all entries to no mapping */
	for (i = 0; i < OPL_IOB_MAX; i++) {
		lsb_to_psb[i] = i;
	}
	/*
	 * Get LSB-to-PSB (logical-to-physical board) mapping by finding the
	 * memory controller driver per LSB. The MC driver will have a
	 * physical-board# property.
	 */
	for (n = di_drv_first_node(OPL_MC_DRV, opl_devtree);
	    n != DI_NODE_NIL;
	    n = di_drv_next_node(n)) {
		int a, lsb, psb;
		char *ba = di_bus_addr(n);
		if (ba == NULL) {
			/*
			 * di_bus_addr returned NULL. This can happen during
			 * DR attach/detach of the mc driver. Just skip this
			 * node for now.
			 */
			continue;
		}
		a = OPL_MC_STR2BA(ba);
		lsb = OPL_MC_LSB(a);

		psb = opl_get_physical_board(mod, n);
		if (psb < 0 || psb >= OPL_IOB_MAX) {
			/* psb mapping is out of range, skip */
			continue;
		}
		lsb_to_psb[lsb] = psb;
	}
}

/*
 * Create the ioboard node. Add fru and label properties, and create room
 * for child hostbridge nodes.
 *
 * Only IKKAKU model has different IO topology.
 */
static tnode_t *
opl_iob_node_create(topo_mod_t *mp, tnode_t *parent, int inst,
    opl_model_t opl_model)
{
	int err;
	tnode_t *ion;
	nvlist_t *fmri;
	char label[8];
	char fmri_str[32];
	nvlist_t *auth = topo_mod_auth(mp, parent);

	if (parent == NULL || inst < 0) {
		return (NULL);
	}

	/* Create ioboard FMRI */
	if ((fmri = topo_mod_hcfmri(mp, parent, FM_HC_SCHEME_VERSION, IOBOARD,
	    inst, NULL, auth, NULL, NULL, NULL)) == NULL) {
		nvlist_free(auth);
		topo_mod_dprintf(mp, "create of tnode for ioboard failed: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		return (NULL);
	}
	nvlist_free(auth);
	/* Create node for this ioboard */
	ion = topo_node_bind(mp, parent, IOBOARD, inst, fmri);
	if (ion == NULL) {
		nvlist_free(fmri);
		topo_mod_dprintf(mp, "unable to bind ioboard: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		return (NULL); /* mod_errno already set */
	}
	nvlist_free(fmri);
	/* Create and add FRU fmri for this ioboard */
	if (opl_model == MODEL_IKKAKU)
		(void) snprintf(fmri_str, sizeof (fmri_str), IKKAKU_IOBDFRU);
	else
		(void) snprintf(fmri_str, sizeof (fmri_str), IOBDFRU, inst);
	if (topo_mod_str2nvl(mp, fmri_str, &fmri) == 0) {
		(void) topo_node_fru_set(ion, fmri, 0, &err);
		nvlist_free(fmri);
	}
	/* Add label for this ioboard */
	if (opl_model == MODEL_IKKAKU)
		(void) snprintf(label, sizeof (label), IKKAKU_LABEL);
	else
		(void) snprintf(label, sizeof (label), LABEL, inst);
	(void) topo_node_label_set(ion, label, &err);

	/* Create range of hostbridges on this ioboard */
	if (topo_node_range_create(mp, ion, HOSTBRIDGE, 0, OPL_HB_MAX) != 0) {
		topo_mod_dprintf(mp, "topo_node_range_create failed: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		return (NULL);
	}

	return (ion);
}

/*
 * get the OPL model name from rootnode property "model"
 */
static int
opl_get_model(topo_mod_t *mp, di_node_t opl_devtree, char *model)
{
	char *bufp;
	di_prom_handle_t promh = DI_PROM_HANDLE_NIL;

	if (opl_devtree == DI_NODE_NIL ||
	    (promh = topo_mod_prominfo(mp)) == DI_PROM_HANDLE_NIL)
		return (-1);

	if (di_prom_prop_lookup_bytes(promh, opl_devtree, "model",
	    (unsigned char **)&bufp) != -1) {
		(void) strlcpy(model, bufp, MAXNAMELEN);
		return (0);
	} else {
		return (-1);
	}

}

/*ARGSUSED*/
static int
opl_iob_enum(topo_mod_t *mp, tnode_t *parent, const char *name,
    topo_instance_t imin, topo_instance_t imax, void *notused1, void *notused2)
{
	di_node_t opl_devtree;
	di_node_t pnode;
	tnode_t *ion;
	topo_instance_t inst;
	int lsb_to_psb[OPL_IOB_MAX];
	ioboard_contents_t ioboard_list[OPL_IOB_MAX];
	int retval = 0;
	char model[MAXNAMELEN];
	opl_model_t opl_model = MODEL_FF;

	/* Validate the name is correct */
	if (strcmp(name, "ioboard") != 0) {
		return (-1);
	}
	/* Make sure we don't exceed OPL_IOB_MAX */
	if (imax >= OPL_IOB_MAX) {
		imax = OPL_IOB_MAX;
	}

	bzero(ioboard_list, sizeof (ioboard_list));

	opl_devtree = topo_mod_devinfo(mp);
	if (opl_devtree == DI_NODE_NIL) {
		(void) topo_mod_seterrno(mp, errno);
		topo_mod_dprintf(mp, "devinfo init failed.\n");
		return (-1);
	}

	if (opl_get_model(mp, opl_devtree, model) == -1) {
		topo_mod_dprintf(mp, "opl_get_model failed.\n");
	} else {
		if (strncmp(model, "FF", 2) == 0)
			opl_model = MODEL_FF;
		else if (strncmp(model, "DC", 2) == 0)
			opl_model = MODEL_DC;
		else if (strcmp(model, "IKKAKU") == 0)
			opl_model = MODEL_IKKAKU;

		topo_mod_dprintf(mp, "opl_get_model %s found.\n", model);
	}

	/*
	 * Create a mapping from logical board numbers (which are part of
	 * the device node bus address) to physical board numbers, so we
	 * can create meaningful fru labels.
	 */
	opl_map_boards(mp, opl_devtree, lsb_to_psb);

	/*
	 * Figure out which boards are installed by finding hostbridges
	 * with matching bus addresses.
	 */
	for (pnode = di_drv_first_node(OPL_PX_DRV, opl_devtree);
	    pnode != DI_NODE_NIL;
	    pnode = di_drv_next_node(pnode)) {
		int psb = -1;
		int a, lsb, hb, rc;

		/* Get the bus address */
		char *ba = di_bus_addr(pnode);
		if (ba == NULL || (*ba == '\0')) {
			return (-1); /* Return if it's not assigned */
		}

		a = OPL_PX_STR2BA(ba);
		lsb = OPL_PX_LSB(a);
		hb = OPL_PX_HB(a);
		rc = OPL_PX_RC(a);
		/* Map logical system board to physical system board */
		if (lsb >= 0 && lsb <= OPL_IOB_MAX) {
			psb = lsb_to_psb[lsb];
		}
		/* If valid psb, note that this board exists */
		if (psb >= 0 && psb < OPL_IOB_MAX) {
			ioboard_list[psb].count++;
			ioboard_list[psb].rcs[hb][rc] = pnode;
		}
	}

	/*
	 * Now enumerate each existing board  Exit loop if retval is
	 * ever set to non-zero.
	 */
	for (inst = imin; inst <= imax && retval == 0; inst++) {
		/* If this board doesn't contain any hostbridges, skip it */
		if (ioboard_list[inst].count == 0) {
			continue;
		}
		/* Create node for this ioboard */
		ion = opl_iob_node_create(mp, parent, inst, opl_model);
		if (ion == NULL) {
			topo_mod_dprintf(mp,
			    "enumeration of ioboard failed: %s\n",
			    topo_strerror(topo_mod_errno(mp)));
			retval = -1;
			break;
		}
		/* Enumerate hostbridges on this ioboard, sets errno */
		retval = opl_hb_enum(mp, &ioboard_list[inst], ion, inst);
	}
	return (retval);
}
