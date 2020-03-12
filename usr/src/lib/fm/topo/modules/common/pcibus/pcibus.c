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
 * Copyright 2020 Joyent, Inc.
 */

#include <sys/fm/protocol.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <libdevinfo.h>
#include <libnvpair.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/ddi_ufm.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <hostbridge.h>
#include <pcibus.h>
#include <did.h>
#include <did_props.h>
#include <util.h>
#include <topo_nic.h>
#include <topo_usb.h>

extern txprop_t Bus_common_props[];
extern txprop_t Dev_common_props[];
extern txprop_t Fn_common_props[];
extern int Bus_propcnt;
extern int Dev_propcnt;
extern int Fn_propcnt;

extern int platform_pci_label(topo_mod_t *mod, tnode_t *, nvlist_t *,
    nvlist_t **);
extern int platform_pci_fru(topo_mod_t *mod, tnode_t *, nvlist_t *,
    nvlist_t **);
static void pci_release(topo_mod_t *, tnode_t *);
static int pci_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static int pci_label(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int pci_fru(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

static const topo_modops_t Pci_ops =
	{ pci_enum, pci_release };
static const topo_modinfo_t Pci_info =
	{ PCI_BUS, FM_FMRI_SCHEME_HC, PCI_ENUMR_VERS, &Pci_ops };

static const topo_method_t Pci_methods[] = {
	{ TOPO_METH_LABEL, TOPO_METH_LABEL_DESC,
	    TOPO_METH_LABEL_VERSION, TOPO_STABILITY_INTERNAL, pci_label },
	{ TOPO_METH_FRU_COMPUTE, TOPO_METH_FRU_COMPUTE_DESC,
	    TOPO_METH_FRU_COMPUTE_VERSION, TOPO_STABILITY_INTERNAL, pci_fru },
	{ NULL }
};

int
_topo_init(topo_mod_t *modhdl, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOPCIDBG") != NULL)
		topo_mod_setdebug(modhdl);
	topo_mod_dprintf(modhdl, "initializing pcibus builtin\n");

	if (version != PCI_ENUMR_VERS)
		return (topo_mod_seterrno(modhdl, EMOD_VER_NEW));

	if (topo_mod_register(modhdl, &Pci_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(modhdl, "failed to register module");
		return (-1);
	}
	topo_mod_dprintf(modhdl, "PCI Enumr initd\n");

	return (0);
}

void
_topo_fini(topo_mod_t *modhdl)
{
	topo_mod_unregister(modhdl);
}

static int
pci_label(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_LABEL_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));
	return (platform_pci_label(mp, node, in, out));
}
static int
pci_fru(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_FRU_COMPUTE_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));
	return (platform_pci_fru(mp, node, in, out));
}
static tnode_t *
pci_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, void *priv)
{
	tnode_t *ntn;

	if ((ntn = tnode_create(mod, parent, name, i, priv)) == NULL)
		return (NULL);
	if (topo_method_register(mod, ntn, Pci_methods) < 0) {
		topo_mod_dprintf(mod, "topo_method_register failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

/*ARGSUSED*/
static int
hostbridge_asdevice(topo_mod_t *mod, tnode_t *bus)
{
	di_node_t di;
	tnode_t *dev32;

	di = topo_node_getspecific(bus);
	assert(di != DI_NODE_NIL);

	if ((dev32 = pcidev_declare(mod, bus, di, 32)) == NULL)
		return (-1);
	if (pcifn_declare(mod, dev32, di, 0) == NULL) {
		topo_node_unbind(dev32);
		return (-1);
	}
	return (0);
}

static int
pciexfn_add_ufm(topo_mod_t *mod, tnode_t *node)
{
	char *devpath = NULL;
	ufm_ioc_getcaps_t ugc = { 0 };
	ufm_ioc_bufsz_t ufbz = { 0 };
	ufm_ioc_report_t ufmr = { 0 };
	nvlist_t *ufminfo = NULL, **images;
	uint_t nimages;
	int err, fd, ret = -1;

	if (topo_prop_get_string(node, TOPO_PGROUP_IO, TOPO_IO_DEV, &devpath,
	    &err) != 0) {
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
	if (strlen(devpath) >= MAXPATHLEN) {
		topo_mod_dprintf(mod, "devpath is too long: %s", devpath);
		topo_mod_strfree(mod, devpath);
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	if ((fd = open(DDI_UFM_DEV, O_RDONLY)) < 0) {
		topo_mod_dprintf(mod, "%s: failed to open %s", __func__,
		    DDI_UFM_DEV);
		topo_mod_strfree(mod, devpath);
		return (0);
	}
	/*
	 * Make an ioctl to probe if the driver for this function is
	 * UFM-capable.  If the ioctl fails or if it doesn't advertise the
	 * DDI_UFM_CAP_REPORT capability, we bail out.
	 */
	ugc.ufmg_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ugc.ufmg_devpath, devpath, MAXPATHLEN);
	if (ioctl(fd, UFM_IOC_GETCAPS, &ugc) < 0) {
		topo_mod_dprintf(mod, "UFM_IOC_GETCAPS failed: %s",
		    strerror(errno));
		(void) close(fd);
		topo_mod_strfree(mod, devpath);
		return (0);
	}
	if ((ugc.ufmg_caps & DDI_UFM_CAP_REPORT) == 0) {
		topo_mod_dprintf(mod, "driver doesn't advertise "
		    "DDI_UFM_CAP_REPORT");
		(void) close(fd);
		topo_mod_strfree(mod, devpath);
		return (0);
	}

	/*
	 * If we made it this far, then the driver is indeed UFM-capable and
	 * is capable of reporting its firmware information.  First step is to
	 * make an ioctl to query the size of the report data so that we can
	 * allocate a buffer large enough to hold it.
	 */
	ufbz.ufbz_version = DDI_UFM_CURRENT_VERSION;
	(void) strlcpy(ufbz.ufbz_devpath, devpath, MAXPATHLEN);
	if (ioctl(fd, UFM_IOC_REPORTSZ, &ufbz) < 0) {
		topo_mod_dprintf(mod, "UFM_IOC_REPORTSZ failed: %s\n",
		    strerror(errno));
		(void) close(fd);
		topo_mod_strfree(mod, devpath);
		return (0);
	}

	ufmr.ufmr_version = DDI_UFM_CURRENT_VERSION;
	if ((ufmr.ufmr_buf = topo_mod_alloc(mod, ufbz.ufbz_size)) == NULL) {
		topo_mod_dprintf(mod, "failed to alloc %u bytes\n",
		    ufbz.ufbz_size);
		(void) close(fd);
		topo_mod_strfree(mod, devpath);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	ufmr.ufmr_bufsz = ufbz.ufbz_size;
	(void) strlcpy(ufmr.ufmr_devpath, devpath, MAXPATHLEN);
	topo_mod_strfree(mod, devpath);

	/*
	 * Now, make the ioctl to retrieve the actual report data.  The data
	 * is stored as a packed nvlist.
	 */
	if (ioctl(fd, UFM_IOC_REPORT, &ufmr) < 0) {
		topo_mod_dprintf(mod, "UFM_IOC_REPORT failed: %s\n",
		    strerror(errno));
		topo_mod_free(mod, ufmr.ufmr_buf, ufmr.ufmr_bufsz);
		(void) close(fd);
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
	(void) close(fd);

	if (nvlist_unpack(ufmr.ufmr_buf, ufmr.ufmr_bufsz, &ufminfo,
	    NV_ENCODE_NATIVE) != 0) {
		topo_mod_dprintf(mod, "failed to unpack nvlist\n");
		topo_mod_free(mod, ufmr.ufmr_buf, ufmr.ufmr_bufsz);
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}
	topo_mod_free(mod, ufmr.ufmr_buf, ufmr.ufmr_bufsz);

	if (nvlist_lookup_nvlist_array(ufminfo, DDI_UFM_NV_IMAGES, &images,
	    &nimages) != 0) {
		topo_mod_dprintf(mod, "failed to lookup %s nvpair",
		    DDI_UFM_NV_IMAGES);
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto err;
	}
	if (topo_node_range_create(mod, node, UFM, 0, (nimages - 1)) != 0) {
		topo_mod_dprintf(mod, "failed to create %s range", UFM);
		/* errno set */
		goto err;
	}
	for (uint_t i = 0; i < nimages; i++) {
		tnode_t *ufmnode = NULL;
		char *descr;
		uint_t nslots;
		nvlist_t **slots;

		if (nvlist_lookup_string(images[i], DDI_UFM_NV_IMAGE_DESC,
		    &descr) != 0 ||
		    nvlist_lookup_nvlist_array(images[i],
		    DDI_UFM_NV_IMAGE_SLOTS, &slots, &nslots) != 0) {
			(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
			goto err;
		}
		if ((ufmnode = topo_mod_create_ufm(mod, node, descr, NULL)) ==
		    NULL) {
			topo_mod_dprintf(mod, "failed to create ufm nodes for "
			    "%s", descr);
			/* errno set */
			goto err;
		}
		for (uint_t s = 0; s < nslots; s++) {
			topo_ufm_slot_info_t slotinfo = { 0 };
			uint32_t slotattrs;

			if (nvlist_lookup_string(slots[s],
			    DDI_UFM_NV_SLOT_VERSION,
			    (char **)&slotinfo.usi_version) != 0 ||
			    nvlist_lookup_uint32(slots[s],
			    DDI_UFM_NV_SLOT_ATTR, &slotattrs) != 0) {
				topo_node_unbind(ufmnode);
				topo_mod_dprintf(mod, "malformed slot nvlist");
				(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
				goto err;
			}
			(void) nvlist_lookup_nvlist(slots[s],
			    DDI_UFM_NV_SLOT_MISC, &slotinfo.usi_extra);

			if (slotattrs & DDI_UFM_ATTR_READABLE &&
			    slotattrs & DDI_UFM_ATTR_WRITEABLE)
				slotinfo.usi_mode = TOPO_UFM_SLOT_MODE_RW;
			else if (slotattrs & DDI_UFM_ATTR_READABLE)
				slotinfo.usi_mode = TOPO_UFM_SLOT_MODE_RO;
			else if (slotattrs & DDI_UFM_ATTR_WRITEABLE)
				slotinfo.usi_mode = TOPO_UFM_SLOT_MODE_WO;
			else
				slotinfo.usi_mode = TOPO_UFM_SLOT_MODE_NONE;

			if (slotattrs & DDI_UFM_ATTR_ACTIVE)
				slotinfo.usi_active = B_TRUE;

			if (topo_node_range_create(mod, ufmnode, SLOT, 0,
			    (nslots - 1)) < 0) {
				topo_mod_dprintf(mod, "failed to create %s "
				    "range", SLOT);
				/* errno set */
				goto err;
			}
			if (topo_mod_create_ufm_slot(mod, ufmnode,
			    &slotinfo) == NULL) {
				topo_node_unbind(ufmnode);
				topo_mod_dprintf(mod, "failed to create ufm "
				    "slot %d for %s", s, descr);
				/* errno set */
				goto err;
			}
		}
	}
	ret = 0;
err:
	nvlist_free(ufminfo);
	return (ret);
}

tnode_t *
pciexfn_declare(topo_mod_t *mod, tnode_t *parent, di_node_t dn,
    topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn, *ptn;
	di_node_t pdn;
	uint_t class, subclass;
	char *devtyp, *pdevtyp;
	int pcie_devtyp, pexcap;
	boolean_t dev_is_pcie, pdev_is_pcie;

	/* We need the parent's dev info node for some of the info */
	ptn = find_predecessor(parent, PCIEX_FUNCTION);
	/* If this is the first child under root, get root's ptn */
	if (ptn == NULL)
		ptn = find_predecessor(parent, PCIEX_ROOT);
	if (ptn == NULL)
		return (NULL);
	pdn = topo_node_getspecific(ptn);

	/* Get the required info to populate the excap */
	(void) pci_classcode_get(mod, dn, &class, &subclass);
	devtyp = pci_devtype_get(mod, dn);
	pdevtyp = pci_devtype_get(mod, pdn);
	pexcap = pciex_cap_get(mod, pdn);

	dev_is_pcie = devtyp && (strcmp(devtyp, "pciex") == 0);
	pdev_is_pcie = pdevtyp && (strcmp(pdevtyp, "pciex") == 0);

	/*
	 * Populate the excap with correct PCIe device type.
	 *
	 * Device	Parent		Device		Parent	Device
	 * excap	device-type	device-type	excap	Class Code
	 * -------------------------------------------------------------------
	 * PCI(default)	pci		N/A		N/A	!= bridge
	 * PCIe		pciex		N/A		N/A	!= bridge
	 * Root Port	Defined in hostbridge
	 * Switch Up	pciex		pciex		!= up	= bridge
	 * Switch Down	pciex		pciex		= up	= bridge
	 * PCIe-PCI	pciex		pci		N/A	= bridge
	 * PCI-PCIe	pci		pciex		N/A	= bridge
	 */
	pcie_devtyp = PCIE_PCIECAP_DEV_TYPE_PCI_DEV;
	if (class == PCI_CLASS_BRIDGE && subclass == PCI_BRIDGE_PCI) {
		if (pdev_is_pcie) {
			if (dev_is_pcie) {
				if (pexcap != PCIE_PCIECAP_DEV_TYPE_UP)
					pcie_devtyp = PCIE_PCIECAP_DEV_TYPE_UP;
				else
					pcie_devtyp =
					    PCIE_PCIECAP_DEV_TYPE_DOWN;
			} else {
				pcie_devtyp = PCIE_PCIECAP_DEV_TYPE_PCIE2PCI;
			}
		} else {
			if (dev_is_pcie)
				pcie_devtyp = PCIE_PCIECAP_DEV_TYPE_PCI2PCIE;
		}
	} else {
		if (pdev_is_pcie)
			pcie_devtyp = PCIE_PCIECAP_DEV_TYPE_PCIE_DEV;
	}

	if ((pd = did_find(mod, dn)) == NULL)
		return (NULL);
	did_excap_set(pd, pcie_devtyp);

	if ((ntn = pci_tnode_create(mod, parent, PCIEX_FUNCTION, i, dn))
	    == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, Fn_common_props, Fn_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}

	/*
	 * Check if the driver associated with this function exports firmware
	 * information via the DDI UFM subsystem and, if so, create the
	 * corresponding ufm topo nodes.
	 */
	if (pciexfn_add_ufm(mod, ntn) != 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}

	/*
	 * We may find pci-express buses or plain-pci buses beneath a function
	 */
	if (child_range_add(mod, ntn, PCIEX_BUS, 0, MAX_HB_BUSES) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	if (child_range_add(mod, ntn, PCI_BUS, 0, MAX_HB_BUSES) < 0) {
		topo_node_range_destroy(ntn, PCIEX_BUS);
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pciexdev_declare(topo_mod_t *mod, tnode_t *parent, di_node_t dn,
    topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(mod, dn)) == NULL)
		return (NULL);
	did_settnode(pd, parent);

	if ((ntn = pci_tnode_create(mod, parent, PCIEX_DEVICE, i, dn)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, Dev_common_props, Dev_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}

	/*
	 * We can expect to find pci-express functions beneath the device
	 */
	if (child_range_add(mod,
	    ntn, PCIEX_FUNCTION, 0, MAX_PCIDEV_FNS) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pciexbus_declare(topo_mod_t *mod, tnode_t *parent, di_node_t dn,
    topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(mod, dn)) == NULL)
		return (NULL);
	did_settnode(pd, parent);
	if ((ntn = pci_tnode_create(mod, parent, PCIEX_BUS, i, dn)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, Bus_common_props, Bus_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We can expect to find pci-express devices beneath the bus
	 */
	if (child_range_add(mod,
	    ntn, PCIEX_DEVICE, 0, MAX_PCIBUS_DEVS) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pcifn_declare(topo_mod_t *mod, tnode_t *parent, di_node_t dn,
    topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(mod, dn)) == NULL)
		return (NULL);
	did_excap_set(pd, PCIE_PCIECAP_DEV_TYPE_PCI_DEV);

	if ((ntn = pci_tnode_create(mod, parent, PCI_FUNCTION, i, dn)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, Fn_common_props, Fn_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We may find pci buses beneath a function
	 */
	if (child_range_add(mod, ntn, PCI_BUS, 0, MAX_HB_BUSES) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pcidev_declare(topo_mod_t *mod, tnode_t *parent, di_node_t dn,
    topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(mod, dn)) == NULL)
		return (NULL);
	/* remember parent tnode */
	did_settnode(pd, parent);

	if ((ntn = pci_tnode_create(mod, parent, PCI_DEVICE, i, dn)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, Dev_common_props, Dev_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}

	/*
	 * We can expect to find pci functions beneath the device
	 */
	if (child_range_add(mod, ntn, PCI_FUNCTION, 0, MAX_PCIDEV_FNS) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pcibus_declare(topo_mod_t *mod, tnode_t *parent, di_node_t dn,
    topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;
	int hbchild = 0;

	if ((pd = did_find(mod, dn)) == NULL)
		return (NULL);
	did_settnode(pd, parent);
	if ((ntn = pci_tnode_create(mod, parent, PCI_BUS, i, dn)) == NULL)
		return (NULL);
	/*
	 * If our devinfo node is lacking certain information of its
	 * own, and our parent topology node is a hostbridge, we may
	 * need/want to inherit information available in the
	 * hostbridge node's private data.
	 */
	if (strcmp(topo_node_name(parent), HOSTBRIDGE) == 0)
		hbchild = 1;
	if (did_props_set(ntn, pd, Bus_common_props, Bus_propcnt) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We can expect to find pci devices beneath the bus
	 */
	if (child_range_add(mod, ntn, PCI_DEVICE, 0, MAX_PCIBUS_DEVS) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * On each bus child of the hostbridge, we represent the
	 * hostbridge as a device outside the range of legal device
	 * numbers.
	 */
	if (hbchild == 1) {
		if (hostbridge_asdevice(mod, ntn) < 0) {
			topo_node_range_destroy(ntn, PCI_DEVICE);
			topo_node_unbind(ntn);
			return (NULL);
		}
	}
	return (ntn);
}

static int
pci_bridge_declare(topo_mod_t *mod, tnode_t *fn, di_node_t din, int board,
    int bridge, int rc, int depth)
{
	int err;
	char *devtyp;

	devtyp = pci_devtype_get(mod, din);
	/* Check if the children are PCI or PCIe */
	if (devtyp && (strcmp(devtyp, "pciex") == 0))
		err = pci_children_instantiate(mod, fn, din, board, bridge,
		    rc, TRUST_BDF, depth + 1);
	else
		err = pci_children_instantiate(mod, fn, din, board, bridge,
		    rc - TO_PCI, TRUST_BDF, depth + 1);
	return (err);
}

static void
declare_dev_and_fn(topo_mod_t *mod, tnode_t *bus, tnode_t **dev, di_node_t din,
    int board, int bridge, int rc, int devno, int fnno, int depth)
{
	int dcnt = 0, rcnt, err;
	char *propstr, *label = NULL, *pdev = NULL;
	tnode_t *fn;
	uint_t class, subclass;
	uint_t vid, did;
	uint_t pdev_sz;
	did_t *dp = NULL;

	if (*dev == NULL) {
		if (rc >= 0)
			*dev = pciexdev_declare(mod, bus, din, devno);
		else
			*dev = pcidev_declare(mod, bus, din, devno);
		if (*dev == NULL)
			return;
		++dcnt;
	}
	if (rc >= 0)
		fn = pciexfn_declare(mod, *dev, din, fnno);
	else
		fn = pcifn_declare(mod, *dev, din, fnno);

	if (fn == NULL) {
		if (dcnt) {
			topo_node_unbind(*dev);
			*dev = NULL;
		}
		return;
	}

	if (pci_classcode_get(mod, din, &class, &subclass) < 0) {
		topo_node_unbind(fn);
		if (dcnt)
			topo_node_unbind(*dev);
		return;
	}

	/*
	 * This function may be a bridge.  If not, check for a possible
	 * topology map file and kick off its enumeration of lower-level
	 * devices.
	 */
	if (class == PCI_CLASS_BRIDGE && subclass == PCI_BRIDGE_PCI) {
		(void) pci_bridge_declare(mod, fn, din, board, bridge, rc,
		    depth);
	}

	/*
	 * Check for a Neptune-based NIC. This could either be a Neptune
	 * adapter card or an Neptune ASIC on a board (e.g. motherboard)
	 *
	 * For Netpune adapter cards, use xfp-hc-topology.xml to expand
	 * topology to include the XFP optical module, which is a FRU on
	 * the Neptune based 10giga fiber NICs.
	 *
	 * For Neptune ASICs, use the XAUI enumerator to expand topology.
	 * The 10giga ports are externalized by a XAUI cards, which
	 * are FRUs. The XAUI enumerator in turn instantiates the XFP
	 * optical module FRUs.
	 */
	else if (class == PCI_CLASS_NET &&
	    di_uintprop_get(mod, din, DI_VENDIDPROP, &vid) >= 0 &&
	    di_uintprop_get(mod, din, DI_DEVIDPROP, &did) >= 0 &&
	    vid == SUN_VENDOR_ID && did == NEPTUNE_DEVICE_ID) {
		/*
		 * Is this an adapter card? Check the bus's physlot
		 */
		dp = did_find(mod, topo_node_getspecific(bus));
		if (did_physlot(dp) >= 0) {
			topo_mod_dprintf(mod, "Found Neptune slot\n");
			(void) topo_mod_enummap(mod, fn,
			    "xfp", FM_FMRI_SCHEME_HC);
		} else {
			topo_mod_dprintf(mod, "Found Neptune ASIC\n");
			if (topo_mod_load(mod, XAUI, TOPO_VERSION) == NULL) {
				topo_mod_dprintf(mod, "pcibus enum "
				    "could not load xaui enum\n");
				(void) topo_mod_seterrno(mod,
				    EMOD_PARTIAL_ENUM);
				return;
			} else {
				if (topo_node_range_create(mod, fn,
				    XAUI, 0, 1) < 0) {
					topo_mod_dprintf(mod,
					    "child_range_add for "
					    "XAUI failed: %s\n",
					    topo_strerror(
					    topo_mod_errno(mod)));
					return;
				}
				(void) topo_mod_enumerate(mod, fn,
				    XAUI, XAUI, fnno, fnno, fn);
			}
		}
	} else if (class == PCI_CLASS_NET) {
		/*
		 * Ask the nic module if there are any nodes that need to be
		 * enumerated under this device. This might include things like
		 * transceivers or some day, LEDs.
		 */
		if (topo_mod_load(mod, NIC, NIC_VERSION) == NULL) {
			topo_mod_dprintf(mod, "pcibus enum could not load "
			    "nic enum\n");
			(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
			return;
		}

		(void) topo_mod_enumerate(mod, fn, NIC, NIC, 0, 0, din);
	} else if (class == PCI_CLASS_SERIALBUS && subclass == PCI_SERIAL_USB) {
		/*
		 * If we encounter a USB controller, make sure to enumerate all
		 * of its USB ports.
		 */
		if (topo_mod_load(mod, USB, USB_VERSION) == NULL) {
			topo_mod_dprintf(mod, "pcibus enum could not load "
			    "usb enum\n");
			(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
			return;
		}

		(void) topo_mod_enumerate(mod, fn, USB, USB_PCI, 0, 0, din);
	} else if (class == PCI_CLASS_MASS) {
		di_node_t cn;
		int niports = 0;
		extern void pci_iports_instantiate(topo_mod_t *, tnode_t *,
		    di_node_t, int);
		extern void pci_receptacle_instantiate(topo_mod_t *, tnode_t *,
		    di_node_t);

		for (cn = di_child_node(din); cn != DI_NODE_NIL;
		    cn = di_sibling_node(cn)) {
			if (strcmp(di_node_name(cn), IPORT) == 0)
				niports++;
		}
		if (niports > 0)
			pci_iports_instantiate(mod, fn, din, niports);

		if ((rcnt = di_prop_lookup_strings(DDI_DEV_T_ANY, din,
		    DI_RECEPTACLE_PHYMASK, &propstr)) > 0) {
			if (topo_node_range_create(mod, fn, RECEPTACLE, 0,
			    rcnt) >= 0)
				pci_receptacle_instantiate(mod, fn, din);
		}
	}

	/*
	 * If this is an NVMe device and if the FRU label indicates it's not an
	 * onboard device then invoke the disk enumerator to enumerate the NVMe
	 * controller and associated namespaces.
	 *
	 * We skip NVMe devices that appear to be onboard as those are likely
	 * M.2 or U.2 devices and so should be enumerated via a
	 * platform-specific XML map so that they can be associated with the
	 * correct physical bay/slot.  This code is intended to pick up NVMe
	 * devices that are part of PCIe add-in cards.
	 */
	if (topo_node_label(fn, &label, &err) != 0) {
		topo_mod_dprintf(mod, "%s: failed to lookup FRU label on %s=%d",
		    __func__, topo_node_name(fn), topo_node_instance(fn));
		goto out;
	}

	if (class == PCI_CLASS_MASS && subclass == PCI_MASS_NVME &&
	    strcmp(label, "MB") != 0) {
		char *driver = di_driver_name(din);
		char *slash;
		topo_pgroup_info_t pgi;

		if (topo_prop_get_string(fn, TOPO_PGROUP_IO, TOPO_IO_DEV,
		    &pdev, &err) != 0) {
			topo_mod_dprintf(mod, "%s: failed to lookup %s on "
			    "%s=%d", __func__, TOPO_IO_DEV, topo_node_name(fn),
			    topo_node_instance(fn));
			goto out;
		}

		/*
		 * Add the binding properties that are required by the disk
		 * enumerator to discover the accociated NVMe controller.
		 */
		pdev_sz = strlen(pdev) + 1;
		if ((slash = strrchr(pdev, '/')) == NULL) {
			topo_mod_dprintf(mod, "%s: malformed dev path\n",
			    __func__);
			(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
			goto out;
		}
		*slash = '\0';

		pgi.tpi_name = TOPO_PGROUP_BINDING;
		pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
		pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
		pgi.tpi_version = TOPO_VERSION;
		if (topo_pgroup_create(fn, &pgi, &err) != 0 ||
		    topo_prop_set_string(fn, TOPO_PGROUP_BINDING,
		    TOPO_BINDING_DRIVER, TOPO_PROP_IMMUTABLE, driver,
		    &err) != 0 ||
		    topo_prop_set_string(fn, TOPO_PGROUP_BINDING,
		    TOPO_BINDING_PARENT_DEV, TOPO_PROP_IMMUTABLE, pdev,
		    &err) != 0) {
			topo_mod_dprintf(mod, "%s: failed to set binding "
			    "props", __func__);
			(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
			goto out;
		}

		/*
		 * Load and invoke the disk enumerator module.
		 */
		if (topo_mod_load(mod, DISK, TOPO_VERSION) == NULL) {
			topo_mod_dprintf(mod, "pcibus enum could not load "
			    "disk enum\n");
			(void) topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM);
			goto out;
		}
		(void) topo_mod_enumerate(mod, fn, DISK, NVME, 0, 0, NULL);
	}
out:
	if (pdev != NULL) {
		topo_mod_free(mod, pdev, pdev_sz);
	}
	topo_mod_strfree(mod, label);
}

int
pci_children_instantiate(topo_mod_t *mod, tnode_t *parent, di_node_t pn,
    int board, int bridge, int rc, int bover, int depth)
{
	did_t *pps[MAX_PCIBUS_DEVS][MAX_PCIDEV_FNS];
	did_t *bp = NULL;
	did_t *np;
	di_node_t sib;
	di_node_t din;
	tnode_t *bn = NULL;
	tnode_t *dn = NULL;
	int pb = -1;
	int b, d, f;

	for (d = 0; d < MAX_PCIBUS_DEVS; d++)
		for (f = 0; f < MAX_PCIDEV_FNS; f++)
			pps[d][f] = NULL;

	/* start at the parent's first sibling */
	sib = di_child_node(pn);
	while (sib != DI_NODE_NIL) {
		np = did_create(mod, sib, board, bridge, rc, bover);
		if (np == NULL)
			return (-1);
		did_BDF(np, &b, &d, &f);
		pps[d][f] = np;
		if (bp == NULL)
			bp = np;
		if (pb < 0)
			pb = ((bover == TRUST_BDF) ? b : bover);
		sib = di_sibling_node(sib);
	}
	if (pb < 0 && bover < 0)
		return (0);
	if (rc >= 0)
		bn = pciexbus_declare(mod, parent, pn, ((pb < 0) ? bover : pb));
	else
		bn = pcibus_declare(mod, parent, pn, ((pb < 0) ? bover : pb));
	if (bn == NULL)
		return (-1);
	if (pb < 0)
		return (0);

	for (d = 0; d < MAX_PCIBUS_DEVS; d++) {
		for (f = 0; f < MAX_PCIDEV_FNS; f++) {
			if (pps[d][f] == NULL)
				continue;
			din = did_dinode(pps[d][f]);

			/*
			 * Try to enumerate as many devices and functions as
			 * possible.  If we fail to declare a device, break
			 * out of the function loop.
			 */
			declare_dev_and_fn(mod, bn,
			    &dn, din, board, bridge, rc, d, f, depth);
			did_rele(pps[d][f]);

			if (dn == NULL)
				break;
		}
		dn = NULL;
	}
	return (0);
}

static int
pciexbus_enum(topo_mod_t *mp, tnode_t *ptn, char *pnm, topo_instance_t min,
    topo_instance_t max)
{
	di_node_t pdn;
	int rc, hb;
	tnode_t *hbtn;
	int retval;

	/*
	 * PCI-Express; parent node's private data is a simple di_node_t
	 * and we have to construct our own did hash and did_t.
	 */
	rc = topo_node_instance(ptn);
	if ((hbtn = topo_node_parent(ptn)) != NULL)
		hb = topo_node_instance(hbtn);
	else
		hb = rc;

	if ((pdn = topo_node_getspecific(ptn)) == DI_NODE_NIL) {
		topo_mod_dprintf(mp,
		    "Parent %s node missing private data.\n"
		    "Unable to proceed with %s enumeration.\n", pnm, PCIEX_BUS);
		return (0);
	}
	if (did_hash_init(mp) != 0)
		return (-1);
	if ((did_create(mp, pdn, 0, hb, rc, TRUST_BDF)) == NULL)
		return (-1);	/* errno already set */

	retval = pci_children_instantiate(mp, ptn, pdn, 0, hb, rc,
	    (min == max) ? min : TRUST_BDF, 0);
	did_hash_fini(mp);

	return (retval);
}

static int
pcibus_enum(topo_mod_t *mp, tnode_t *ptn, char *pnm, topo_instance_t min,
    topo_instance_t max, void *data)
{
	did_t *didp, *hbdid = (did_t *)data;
	int retval;

	/*
	 * XXTOPO: we should not be sharing private node data with another
	 * module. PCI Bus; Parent node's private data is a did_t.  We'll
	 * use the did hash established by the parent.
	 */
	did_setspecific(mp, data);

	/*
	 * If we're looking for a specific bus-instance, find the right
	 * did_t in the chain, otherwise, there should be only one did_t.
	 */
	if (min == max) {
		int b;
		didp = hbdid;
		while (didp != NULL) {
			did_BDF(didp, &b, NULL, NULL);
			if (b == min)
				break;
			didp = did_link_get(didp);
		}
		if (didp == NULL) {
			topo_mod_dprintf(mp,
			    "Parent %s node missing private data related\n"
			    "to %s instance %d.\n", pnm, PCI_BUS, min);
			topo_mod_setspecific(mp, NULL);
			return (0);
		}
	} else {
		assert(did_link_get(hbdid) == NULL);
		didp = hbdid;
	}
	retval = pci_children_instantiate(mp, ptn, did_dinode(didp),
	    did_board(didp), did_bridge(didp), did_rc(didp),
	    (min == max) ? min : TRUST_BDF, 0);

	topo_mod_setspecific(mp, NULL);

	return (retval);
}

/*ARGSUSED*/
static int
pci_enum(topo_mod_t *mod, tnode_t *ptn, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused, void *data)
{
	int retval;
	char *pname;

	topo_mod_dprintf(mod, "Enumerating pci!\n");

	if (strcmp(name, PCI_BUS) != 0 && strcmp(name, PCIEX_BUS) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s or %s.\n",
		    PCI_BUS, PCIEX_BUS);
		return (0);
	}
	pname = topo_node_name(ptn);
	if (strcmp(pname, HOSTBRIDGE) != 0 && strcmp(pname, PCIEX_ROOT) != 0) {
		topo_mod_dprintf(mod,
		    "Currently can only enumerate a %s or %s directly\n",
		    PCI_BUS, PCIEX_BUS);
		topo_mod_dprintf(mod,
		    "descended from a %s or %s node.\n",
		    HOSTBRIDGE, PCIEX_ROOT);
		return (0);
	}

	if (strcmp(name, PCI_BUS) == 0) {
		retval = pcibus_enum(mod, ptn, pname, min, max, data);
	} else if (strcmp(name, PCIEX_BUS) == 0) {
		retval = pciexbus_enum(mod, ptn, pname, min, max);
	} else {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s or %s not %s.\n",
		    PCI_BUS, PCIEX_BUS, name);
		return (0);
	}

	return (retval);
}

/*ARGSUSED*/
static void
pci_release(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);

	/*
	 * node private data (did_t) for this node is destroyed in
	 * did_hash_destroy()
	 */

	topo_node_unbind(node);
}
