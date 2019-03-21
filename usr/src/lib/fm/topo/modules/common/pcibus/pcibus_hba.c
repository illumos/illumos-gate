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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include <sys/fm/protocol.h>
#include <strings.h>
#include <fm/topo_mod.h>
#include <fm/topo_method.h>
#include <sys/scsi/impl/inquiry.h>
#include <sys/scsi/impl/scsi_sas.h>
#include <sys/scsi/scsi_address.h>
#include <did_props.h>

static const topo_pgroup_info_t storage_pgroup =
	{ TOPO_PGROUP_STORAGE, TOPO_STABILITY_PRIVATE,
	    TOPO_STABILITY_PRIVATE, 1 };

static const topo_method_t recep_methods[] = {
	{ TOPO_METH_OCCUPIED, TOPO_METH_OCCUPIED_DESC,
	    TOPO_METH_OCCUPIED_VERSION, TOPO_STABILITY_INTERNAL,
	    topo_mod_hc_occupied },
	{ NULL }
};

void
pci_di_prop_set(tnode_t *tn, di_node_t din, char *dpnm, char *tpnm)
{
	int err;
	char *tmpbuf;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, din, dpnm, &tmpbuf) == 1)
		(void) topo_prop_set_string(tn, TOPO_PGROUP_STORAGE, tpnm,
		    TOPO_PROP_IMMUTABLE, tmpbuf, &err);
}

void
pci_pi_prop_set(tnode_t *tn, di_path_t din, char *dpnm, char *tpnm)
{
	int err;
	char *tmpbuf;

	if (di_path_prop_lookup_strings(din, dpnm, &tmpbuf) == 1)
		(void) topo_prop_set_string(tn, TOPO_PGROUP_STORAGE, tpnm,
		    TOPO_PROP_IMMUTABLE, tmpbuf, &err);
}

static void
pci_scsi_device_create(topo_mod_t *mod, nvlist_t *auth, tnode_t *parent,
    di_node_t cn, int instance, di_path_t pi)
{
	tnode_t *child;
	nvlist_t *fmri;
	int e, *val;
	int64_t *val64;

	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, SCSI_DEVICE,
	    instance, NULL, auth, NULL, NULL, NULL);
	if (fmri == NULL)
		return;
	child = topo_node_bind(mod, parent, SCSI_DEVICE, instance, fmri);
	nvlist_free(fmri);
	if (child == NULL)
		return;
	if (topo_pgroup_create(child, &storage_pgroup, &e) < 0)
		return;
	if (pi != NULL) {
		pci_pi_prop_set(child, pi, SCSI_ADDR_PROP_TARGET_PORT,
		    TOPO_STORAGE_TARGET_PORT);
		pci_pi_prop_set(child, pi, SCSI_ADDR_PROP_ATTACHED_PORT,
		    TOPO_STORAGE_ATTACHED_PORT);
		pci_pi_prop_set(child, pi, SCSI_ADDR_PROP_TARGET_PORT_PM,
		    TOPO_STORAGE_TARGET_PORT_PM);
		pci_pi_prop_set(child, pi, SCSI_ADDR_PROP_ATTACHED_PORT_PM,
		    TOPO_STORAGE_ATTACHED_PORT_PM);
		if (di_path_prop_lookup_int64s(pi,
		    SCSI_ADDR_PROP_LUN64, &val64) == 1)
			(void) topo_prop_set_int64(child, TOPO_PGROUP_STORAGE,
			    TOPO_STORAGE_LUN64, TOPO_PROP_IMMUTABLE, *val64,
			    &e);
	} else {
		pci_di_prop_set(child, cn, SCSI_ADDR_PROP_TARGET_PORT,
		    TOPO_STORAGE_TARGET_PORT);
		pci_di_prop_set(child, cn, SCSI_ADDR_PROP_ATTACHED_PORT,
		    TOPO_STORAGE_ATTACHED_PORT);
		pci_di_prop_set(child, cn, SCSI_ADDR_PROP_TARGET_PORT_PM,
		    TOPO_STORAGE_TARGET_PORT_PM);
		pci_di_prop_set(child, cn, SCSI_ADDR_PROP_ATTACHED_PORT_PM,
		    TOPO_STORAGE_ATTACHED_PORT_PM);
		if (di_prop_lookup_int64(DDI_DEV_T_ANY, cn,
		    SCSI_ADDR_PROP_LUN64, &val64) == 1)
			(void) topo_prop_set_int64(child, TOPO_PGROUP_STORAGE,
			    TOPO_STORAGE_LUN64, TOPO_PROP_IMMUTABLE, *val64,
			    &e);
	}
	pci_di_prop_set(child, cn, DEVID_PROP_NAME, TOPO_STORAGE_DEVID);
	pci_di_prop_set(child, cn, INQUIRY_VENDOR_ID,
	    TOPO_STORAGE_MANUFACTURER);
	pci_di_prop_set(child, cn, INQUIRY_PRODUCT_ID, TOPO_STORAGE_MODEL);
	pci_di_prop_set(child, cn, INQUIRY_REVISION_ID,
	    TOPO_STORAGE_FIRMWARE_REV);
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, cn,
	    INQUIRY_DEVICE_TYPE, &val) == 1)
		(void) topo_prop_set_int32(child, TOPO_PGROUP_STORAGE,
		    TOPO_STORAGE_DEVICE_TYPE, TOPO_PROP_IMMUTABLE, *val, &e);
}

static void
pci_smp_device_create(topo_mod_t *mod, nvlist_t *auth, tnode_t *parent,
    di_node_t cn, int instance)
{
	tnode_t *child;
	nvlist_t *fmri;
	int e;

	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, SMP_DEVICE,
	    instance, NULL, auth, NULL, NULL, NULL);
	if (fmri == NULL)
		return;
	child = topo_node_bind(mod, parent, SMP_DEVICE, instance, fmri);
	nvlist_free(fmri);
	if (child == NULL)
		return;
	if (topo_pgroup_create(child, &storage_pgroup, &e) < 0)
		return;
	pci_di_prop_set(child, cn, SCSI_ADDR_PROP_TARGET_PORT,
	    TOPO_STORAGE_TARGET_PORT);
	pci_di_prop_set(child, cn, SCSI_ADDR_PROP_ATTACHED_PORT,
	    TOPO_STORAGE_ATTACHED_PORT);
	pci_di_prop_set(child, cn, SCSI_ADDR_PROP_TARGET_PORT_PM,
	    TOPO_STORAGE_TARGET_PORT_PM);
	pci_di_prop_set(child, cn, SCSI_ADDR_PROP_ATTACHED_PORT_PM,
	    TOPO_STORAGE_ATTACHED_PORT_PM);
	pci_di_prop_set(child, cn, DEVID_PROP_NAME, TOPO_STORAGE_DEVID);
	pci_di_prop_set(child, cn, INQUIRY_VENDOR_ID,
	    TOPO_STORAGE_MANUFACTURER);
	pci_di_prop_set(child, cn, INQUIRY_PRODUCT_ID, TOPO_STORAGE_MODEL);
	pci_di_prop_set(child, cn, INQUIRY_REVISION_ID,
	    TOPO_STORAGE_FIRMWARE_REV);
}

static tnode_t *
pci_iport_device_create(topo_mod_t *mod, nvlist_t *auth, tnode_t *parent,
    di_node_t cn, int instance)
{
	tnode_t *child;
	nvlist_t *fmri;
	int e;

	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, IPORT,
	    instance, NULL, auth, NULL, NULL, NULL);
	if (fmri == NULL)
		return (NULL);
	child = topo_node_bind(mod, parent, IPORT, instance, fmri);
	nvlist_free(fmri);
	if (child == NULL)
		return (NULL);
	if (topo_pgroup_create(child, &storage_pgroup, &e) < 0)
		return (child);
	pci_di_prop_set(child, cn, SCSI_ADDR_PROP_INITIATOR_PORT,
	    TOPO_STORAGE_INITIATOR_PORT);
	(void) topo_prop_set_string(child, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_INITIATOR_PORT_PM, TOPO_PROP_IMMUTABLE,
	    di_bus_addr(cn), &e);
	return (child);
}

void
pci_iports_instantiate(topo_mod_t *mod, tnode_t *parent, di_node_t pn,
    int niports)
{
	di_node_t cn, smp, sd;
	di_path_t pi;
	tnode_t *iport;
	int i, j;
	nvlist_t *auth;

	if (topo_node_range_create(mod, parent, IPORT, 0, niports) < 0)
		return;
	auth = topo_mod_auth(mod, parent);
	for (i = 0, cn = di_child_node(pn); cn != DI_NODE_NIL;
	    cn = di_sibling_node(cn)) {
		/*
		 * First create any iport nodes.
		 */
		if (strcmp(di_node_name(cn), "iport") != 0)
			continue;
		iport = pci_iport_device_create(mod, auth, parent, cn, i++);
		if (iport == NULL)
			continue;

		/*
		 * Now create any scsi-device nodes.
		 */
		for (j = 0, sd = di_child_node(cn); sd != DI_NODE_NIL;
		    sd = di_sibling_node(sd))
			if (strcmp(di_node_name(sd), "smp") != 0)
				j++;
		for (pi = di_path_phci_next_path(cn, DI_PATH_NIL);
		    pi != DI_PATH_NIL; pi = di_path_phci_next_path(cn, pi))
			if (di_path_client_node(pi) != NULL &&
			    strcmp(di_node_name(di_path_client_node(pi)),
			    "smp") != 0)
				j++;
		if (topo_node_range_create(mod, iport, SCSI_DEVICE, 0, j) < 0)
			continue;
		for (j = 0, sd = di_child_node(cn); sd != DI_NODE_NIL;
		    sd = di_sibling_node(sd))
			if (strcmp(di_node_name(sd), "smp") != 0)
				pci_scsi_device_create(mod, auth, iport, sd,
				    j++, NULL);
		for (pi = di_path_phci_next_path(cn, DI_PATH_NIL);
		    pi != DI_PATH_NIL; pi = di_path_phci_next_path(cn, pi))
			if (di_path_client_node(pi) != NULL &&
			    strcmp(di_node_name(di_path_client_node(pi)),
			    "smp") != 0)
				pci_scsi_device_create(mod, auth, iport,
				    di_path_client_node(pi),  j++, pi);

		/*
		 * Now create any smp-device nodes.
		 */
		for (j = 0, smp = di_child_node(cn); smp != DI_NODE_NIL;
		    smp = di_sibling_node(smp))
			if (strcmp(di_node_name(smp), "smp") == 0)
				j++;
		if (topo_node_range_create(mod, iport, SMP_DEVICE, 0, j) < 0)
			continue;
		for (j = 0, smp = di_child_node(cn); smp != DI_NODE_NIL;
		    smp = di_sibling_node(smp))
			if (strcmp(di_node_name(smp), "smp") == 0)
				pci_smp_device_create(mod, auth, iport, smp,
				    j++);
	}
	nvlist_free(auth);
}

void
pci_receptacle_instantiate(topo_mod_t *mod, tnode_t *parent, di_node_t pnode)
{
	int err, i, rcnt, lcnt;
	char *propstrpm, *propstrlabel, *pm, *label;
	nvlist_t *fmri, *auth;
	tnode_t	*recep;

	rcnt = di_prop_lookup_strings(DDI_DEV_T_ANY, pnode,
	    DI_RECEPTACLE_PHYMASK, &propstrpm);
	if ((lcnt = di_prop_lookup_strings(DDI_DEV_T_ANY, pnode,
	    DI_RECEPTACLE_LABEL, &propstrlabel)) <= 0) {
		topo_mod_dprintf(mod,
		    "pci_receptacle_instanciate: rececptacle label not "
		    "found for the pci function node.\n");
		return;
	}

	if (rcnt != lcnt) {
		topo_mod_dprintf(mod,
		    "pci_receptacle_instantiate: rececptacle label count %d "
		    "doesn match with phy mask count %d\n", lcnt, rcnt);
	}

	label = propstrlabel;
	pm = propstrpm;
	auth = topo_mod_auth(mod, parent);
	for (i = 0; i < rcnt; i++) {
		fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION,
		    RECEPTACLE, i, NULL, auth, NULL, NULL, NULL);
		if (fmri == NULL) {
			topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
			    topo_mod_errmsg(mod));
			continue;
		}
		recep = topo_node_bind(mod, parent, RECEPTACLE, i, fmri);
		nvlist_free(fmri);
		if (recep == NULL) {
			topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
			    topo_mod_errmsg(mod));
			continue;
		}

		if (label) {
			if (topo_node_label_set(recep, label, &err) < 0) {
				topo_mod_dprintf(mod,
				    "topo_receptacle_instantiate: "
				    "topo_node_label_set error(%s)\n",
				    topo_strerror(err));
			}
			if (i < lcnt) {
				label = label + strlen(label) + 1;
			} else {
				label = NULL;
			}
		}

		if (topo_pgroup_create(recep, &storage_pgroup, &err) < 0) {
			topo_mod_dprintf(mod, "ses_set_expander_props: "
			    "create storage error %s\n", topo_strerror(err));
			continue;
		}
		(void) topo_prop_set_string(recep, TOPO_PGROUP_STORAGE,
		    TOPO_STORAGE_SAS_PHY_MASK,
		    TOPO_PROP_IMMUTABLE, pm, &err);

		if (topo_method_register(mod, recep, recep_methods) != 0) {
			topo_mod_dprintf(mod, "topo_method_register() failed "
			    "on %s=%d: %s", RECEPTACLE, i,
			    topo_mod_errmsg(mod));
			/* errno set */
			continue;
		}

		pm = pm + strlen(pm) + 1;
	}

	nvlist_free(auth);
}
