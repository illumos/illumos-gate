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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

#include <alloca.h>
#include <assert.h>
#include <fm/topo_mod.h>
#include <libnvpair.h>
#include <string.h>
#include <sys/fm/protocol.h>

#include <did.h>
#include <pcibus.h>
#include <pcibus_labels.h>

extern slotnm_rewrite_t *Slot_Rewrites;
extern physlot_names_t *Physlot_Names;
extern missing_names_t *Missing_Names;

/*
 * Do a platform specific label lookup based on physical slot number.
 */
static const char *
pci_label_physlot_lookup(topo_mod_t *mod, char *platform, did_t *dp)
{
	const char *rlabel = NULL;
	int n, p, i;

	topo_mod_dprintf(mod, "%s: doing a lookup for platform=%s\n",
	    __func__, platform);

	if ((n = did_physlot(dp)) < 0 || Physlot_Names == NULL ||
	    platform == NULL)
		return (NULL);

	topo_mod_dprintf(mod, "%s: doing a lookup for physlot=%d\n",
	    __func__, n);

	for (p = 0; p < Physlot_Names->psn_nplats; p++) {
		topo_mod_dprintf(mod, "%s: comparing against platform=%s\n",
		    __func__, Physlot_Names->psn_names[p].pnm_platform);
		if (strcasecmp(Physlot_Names->psn_names[p].pnm_platform,
		    platform) != 0)
			continue;
		topo_mod_dprintf(mod, "%s: found lookup table for this "
		    "platform\n", __func__);
		for (i = 0; i < Physlot_Names->psn_names[p].pnm_nnames; i++) {
			physnm_t ps;
			ps = Physlot_Names->psn_names[p].pnm_names[i];
			if (ps.ps_num == n) {
				topo_mod_dprintf(mod, "%s: matched entry=%d, "
				    "label=%s\n", __func__, i, ps.ps_label);
				rlabel = ps.ps_label;
				break;
			}
		}
		break;
	}
	if (rlabel != NULL) {
		topo_mod_dprintf(mod, "%s: returning label=%s\n",
		    __func__, rlabel);
	}
	return (rlabel);
}

/*
 * Do a platform specific label lookup based on slot name.
 */
static const char *
pci_label_slotname_lookup(topo_mod_t *mod, char *platform,
    const char *label, did_t *dp)
{
	const char *rlabel = label;
	int s, i, ret;

	if (Slot_Rewrites == NULL || platform == NULL)
		return (rlabel);

	topo_mod_dprintf(mod, "%s: doing a lookup for platform=%s\n",
	    __func__, platform);

	for (s = 0; s < Slot_Rewrites->srw_nplats; s++) {
		topo_mod_dprintf(mod, "%s: comparing against platform=%s\n",
		    __func__, Slot_Rewrites->srw_platrewrites[s].prw_platform);
		if (strcasecmp(Slot_Rewrites->srw_platrewrites[s].prw_platform,
		    platform) != 0)
			continue;
		topo_mod_dprintf(mod, "%s: found lookup table for this "
		    "platform\n", __func__);
		for (i = 0;
		    i < Slot_Rewrites->srw_platrewrites[s].prw_nrewrites;
		    i++) {
			slot_rwd_t rw;
			rw = Slot_Rewrites->srw_platrewrites[s].prw_rewrites[i];
			if (strcmp(rw.srw_obp, label) == 0) {
				topo_mod_dprintf(mod, "%s: matched entry=%d, "
				    "old_label=%s, new_label=%s\n",
				    __func__, i, rw.srw_obp,
				    rw.srw_new ? rw.srw_new : NULL);
				/*
				 * If a test function is specified then call
				 * it to do an additional check.
				 */
				if (rw.srw_test != NULL) {
					topo_mod_dprintf(mod,
					    "%s: calling test function=%p\n",
					    __func__, rw.srw_test);
					if (ret = rw.srw_test(mod, dp))
						rlabel = rw.srw_new;
					topo_mod_dprintf(mod,
					    "%s: test function return=%d\n",
					    __func__, ret);
				} else {
					rlabel = rw.srw_new;
				}
				break;
			}
		}
		break;
	}
	topo_mod_dprintf(mod, "%s: returning label=%s\n", __func__,
	    rlabel ? rlabel : "NULL");
	return (rlabel);
}

/*
 * Do a platform specific label lookup based on bus, dev, etc.
 */
static const char *
pci_label_missing_lookup(topo_mod_t *mod, char *platform, did_t *dp)
{
	const char *rlabel = NULL;
	int board, bridge, rc, bus, dev;
	int p, i, ret;

	if (Missing_Names == NULL || platform == NULL)
		return (NULL);

	bridge = did_bridge(dp);
	board = did_board(dp);
	rc = did_rc(dp);
	did_BDF(dp, &bus, &dev, NULL);

	topo_mod_dprintf(mod, "%s: doing a lookup for platform=%s, "
	    "board=%d, bridge=%d, rc=%d, bus=%d, dev=%d\n",
	    __func__, platform, board, bridge, rc, bus, dev);

	for (p = 0; p < Missing_Names->mn_nplats; p++) {
		topo_mod_dprintf(mod, "%s: comparing against platform=%s\n",
		    __func__, Missing_Names->mn_names[p].pdl_platform);
		if (strcasecmp(Missing_Names->mn_names[p].pdl_platform,
		    platform) != 0)
			continue;
		topo_mod_dprintf(mod, "%s: found lookup table for this "
		    "platform\n", __func__);
		for (i = 0; i < Missing_Names->mn_names[p].pdl_nnames; i++) {
			devlab_t m;
			m = Missing_Names->mn_names[p].pdl_names[i];
			if (m.dl_board == board && m.dl_bridge == bridge &&
			    m.dl_rc == rc &&
			    (m.dl_bus == -1 || m.dl_bus == bus) &&
			    (m.dl_dev == -1 || m.dl_dev == dev)) {
				topo_mod_dprintf(mod, "%s: matched entry=%d, "
				    "label=%s\n", __func__, i, m.dl_label);
				/*
				 * If a test function is specified then call
				 * it to do an additional test.
				 */
				if (m.dl_test != NULL) {
					topo_mod_dprintf(mod,
					    "%s: calling test function=%p\n",
					    __func__, m.dl_test);
					if (ret = m.dl_test(mod, dp))
						rlabel = m.dl_label;
					topo_mod_dprintf(mod,
					    "%s: test function return=%d\n",
					    __func__, ret);
					if (ret)
						break;
				} else {
					rlabel = m.dl_label;
					break;
				}
			}
		}
		break;
	}
	if (rlabel != NULL) {
		topo_mod_dprintf(mod, "%s: match found, label=%s\n",
		    __func__, rlabel);
	}
	return (rlabel);
}

/*
 * Do an overall slot label lookup for the device node.
 */
char *
pci_slot_label_lookup(topo_mod_t *mod, tnode_t *node, did_t *dp, did_t *pdp)
{
	tnode_t *anode, *apnode;
	did_t *adp, *apdp;
	char *plat, *pp, *l, *ancestor_l = NULL, *new_l = NULL;
	int err, b, d, f, done = 0;
	size_t len;

	did_BDF(dp, &b, &d, &f);

	topo_mod_dprintf(mod, "%s: entry: node=%p, node_name=%s, "
	    "node_inst=%d, dp=%p, dp_bdf=%d/%d/%d, pdp=%p\n",
	    __func__, node, topo_node_name(node), topo_node_instance(node),
	    dp, b, d, f, pdp);

	/*
	 * If this device has a physical slot number then check if
	 * an ancestor also has a slot label.
	 *
	 * If an ancestor has a slot label, then this node's label
	 * is generated by concatenating a default label onto the
	 * ancestor's label.
	 *
	 * We grab pairs of ancestors (parent and child) as we go up
	 * the tree because the parent is checked for the presence
	 * of a slot while the child contains the label.
	 *
	 * Note that this algorithm only applies to nodes which have
	 * a physical slot number. (i.e. PCIE devices or PCI/PCIX
	 * devices off of a PCIE to PCIX switch)
	 */
	if (did_physlot(pdp) >= 0) {

		topo_mod_dprintf(mod, "%s: node=%p: node has a physical "
		    "slot=%d, checking ancestors for slots\n",
		    __func__, node, did_physlot(pdp));

		/*
		 * Get this device's physical slot name.
		 */
		l = (char *)did_physlot_name(pdp, d);
		anode = topo_node_parent(node);

		/*
		 * Check ancestors for a slot label until we
		 * either find one or hit a non-pci device.
		 */
		while (!done) {

			/*
			 * Get next ancestor node and data pointers.
			 */
			anode = topo_node_parent(anode);
			if (anode != NULL) {
				adp = did_find(mod,
				    topo_node_getspecific(anode));
				apnode = topo_node_parent(anode);
				if (apnode != NULL)
					apdp = did_find(mod,
					    topo_node_getspecific(apnode));
				else
					apdp = NULL;
			} else {
				apnode = NULL;
				apdp = adp = NULL;
			}

			topo_mod_dprintf(mod, "%s: node=%p: checking next "
			    "two ancestors: anode=%p, adp=%p "
			    "apnode=%p, apdp=%p\n",
			    __func__, node, anode, adp, apnode, apdp);
			if ((anode != NULL) && (adp != NULL)) {
				did_BDF(adp, &b, &d, &f);
				topo_mod_dprintf(mod, "%s: node=%p: "
				    "anode_name=%s[%d], anode_bdf=%d/%d/%d\n",
				    __func__, node, topo_node_name(anode),
				    topo_node_instance(anode), b, d, f);
			}
			if ((apnode != NULL) && (apdp != NULL)) {
				did_BDF(apdp, &b, &d, &f);
				topo_mod_dprintf(mod, "%s: node=%p: "
				    "apnode_name=%s[%d], "
				    "apnode_bdf=%d/%d/%d\n",
				    __func__, node, topo_node_name(apnode),
				    topo_node_instance(apnode), b, d, f);
			}

			/*
			 * If the ancestors do not exist or are not pci
			 * devices then we're done searching.
			 *
			 * Otherwise, if the ancestor has a physical slot,
			 * and it is a different slot than the one we
			 * started with then lookup the ancestor label,
			 * and we're done.
			 */
			if ((anode == NULL) || (adp == NULL) ||
			    (apnode == NULL) || (apdp == NULL)) {
				done++;
			} else if (did_physlot_exists(apdp) &&
			    (apdp != pdp)) {
				if (topo_node_label(anode, &ancestor_l,
				    &err) != 0) {
					topo_mod_dprintf(mod,
					    "%s: node=%p: topo_node_label() "
					    "FAILED!", __func__, node);
					(void) topo_mod_seterrno(mod, err);
					return (NULL);
				}
				done++;
				topo_mod_dprintf(mod, "%s: node=%p: found "
				    "ancestor with a slot, label=%s ",
				    __func__, node, ancestor_l);
			}
		}
		if (ancestor_l == NULL) {
			topo_mod_dprintf(mod, "%s: node=%p: no ancestor "
			    "slot found\n", __func__, node);
		}
	}

	/*
	 * If we found an ancestor with a slot label, and this node has
	 * a physical slot number label then concatenate the two to form
	 * this node's label. Otherwise, do a full slot label lookup.
	 */
	if (ancestor_l && l) {
		topo_mod_dprintf(mod, "%s: node=%p: concatenating "
		    "ancestor_l=%s and l=%s\n",
		    __func__, node, ancestor_l, l);
		len = strlen(ancestor_l) + strlen(l) + 2;
		new_l = alloca(len);
		(void) snprintf(new_l, len, "%s/%s", ancestor_l, l);
		l = new_l;
	} else {
		/*
		 * Get platform name used for lookups.
		 */
		if (topo_prop_get_string(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &plat, &err) < 0) {
			(void) topo_mod_seterrno(mod, err);
			return (NULL);
		}
		/*
		 * Trim SUNW, from the platform name
		 */
		pp = strchr(plat, ',');
		if (pp == NULL)
			pp = plat;
		else
			++pp;
		/*
		 * Get device number used for lookup.
		 */
		did_BDF(dp, NULL, &d, NULL);

		/*
		 * The slot label is determined in the following order:
		 * - Platform specific lookup based on physical slot #.
		 * - Platform specific lookup based on default label string.
		 * - Platform specific lookup based on device number.
		 * - Default label.
		 *   The default label is based on the slot names property
		 *   if it exists, else it is a generic name derived from
		 *   the slot #.
		 */
		if ((l = (char *)pci_label_physlot_lookup(mod, pp, pdp))
		    == NULL) {
			if ((l = (char *)did_physlot_name(dp, d)) != NULL) {
				l = (char *)
				    pci_label_slotname_lookup(mod, pp, l, dp);
			}
			if (l == NULL) {
				l = (char *)
				    pci_label_missing_lookup(mod, pp, dp);
			}
		}
		topo_mod_strfree(mod, plat);
	}

	/*
	 * If we calculated a slot label,  then save it in the
	 * node's data structure so we can free it later.
	 */
	if (l) {
		if (did_slot_label_get(dp) != NULL)
			topo_mod_strfree(mod, did_slot_label_get(dp));
		l = topo_mod_strdup(mod, l);
		did_slot_label_set(dp, l);
	}

	topo_mod_dprintf(mod, "%s: exit: node=%p: label=%s\n",
	    __func__, node, (l ? l : "NULL"));

	return (l);
}

int
pci_label_cmn(topo_mod_t *mod, tnode_t *node, nvlist_t *in, nvlist_t **out)
{
	uint64_t ptr;
	char *l;
	did_t *dp, *pdp;
	tnode_t *pnode;
	char *nm;
	int err;

	/*
	 * If it's not a device or a PCI-express bus (which could potentially
	 * represent a slot, and therefore we might need to capture its slot
	 * name information), just inherit any label from our parent
	 */
	*out = NULL;
	nm = topo_node_name(node);
	if (strcmp(nm, PCI_DEVICE) != 0 && strcmp(nm, PCIEX_DEVICE) != 0 &&
	    strcmp(nm, PCIEX_BUS) != 0) {
		if (topo_node_label_set(node, NULL, &err) < 0)
			if (err != ETOPO_PROP_NOENT)
				return (topo_mod_seterrno(mod, err));
		return (0);
	}

	if (nvlist_lookup_uint64(in, TOPO_METH_LABEL_ARG_NVL, &ptr) != 0) {
		topo_mod_dprintf(mod,
		    "%s: label method argument not found.\n", __func__);
		return (-1);
	}
	dp = (did_t *)(uintptr_t)ptr;
	pnode = did_gettnode(dp);
	pdp = did_find(mod, topo_node_getspecific(pnode));

	/*
	 * Is there a slot label associated with the device?
	 */
	if ((l = pci_slot_label_lookup(mod, node, dp, pdp)) != NULL) {
		nvlist_t *rnvl;

		if (topo_mod_nvalloc(mod, &rnvl, NV_UNIQUE_NAME) != 0 ||
		    nvlist_add_string(rnvl, TOPO_METH_LABEL_RET_STR, l) != 0)
			return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
		*out = rnvl;
		return (0);
	} else {
		if (topo_node_label_set(node, NULL, &err) < 0)
			if (err != ETOPO_PROP_NOENT)
				return (topo_mod_seterrno(mod, err));
		return (0);
	}
}

int
pci_fru_cmn(topo_mod_t *mod, tnode_t *node, nvlist_t *in, nvlist_t **out)
{
	int err = 0;
	uint64_t ptr;
	did_t *dp, *pdp;
	tnode_t *pnode;
	char *nm;

	*out = NULL;
	nm = topo_node_name(node);
	if (strcmp(nm, PCI_DEVICE) != 0 && strcmp(nm, PCIEX_DEVICE) != 0 &&
	    strcmp(nm, PCIEX_BUS) != 0)
		return (0);

	if (nvlist_lookup_uint64(in, "nv1", &ptr) != 0) {
		topo_mod_dprintf(mod,
		    "%s: label method argument not found.\n", __func__);
		return (-1);
	}
	dp = (did_t *)(uintptr_t)ptr;
	pnode = did_gettnode(dp);
	pdp = did_find(mod, topo_node_getspecific(pnode));

	/*
	 * Is there a slot label associated with the device?
	 */
	if (pci_slot_label_lookup(mod, pnode, dp, pdp) != NULL) {
		nvlist_t *rnvl;

		if (topo_node_resource(node, &rnvl, &err) < 0 || rnvl == NULL) {
			topo_mod_dprintf(mod, "%s: error: %s\n",
			    __func__, topo_strerror(topo_mod_errno(mod)));
			return (topo_mod_seterrno(mod, err));
		}
		*out = rnvl;
	}
	return (0);
}
