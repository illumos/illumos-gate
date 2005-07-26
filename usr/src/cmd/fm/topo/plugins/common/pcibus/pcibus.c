/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/libtopo_enum.h>
#include <sys/fm/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <alloca.h>
#include <sys/param.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include "enumpci.h"

static struct tenumr pci_enumr = {
	NULL,
	topo_pci_init,
	topo_pci_fini,
	topo_pci_enum
};

static di_prom_handle_t Promtree = DI_PROM_HANDLE_NIL;
static di_node_t Devtree = DI_NODE_NIL;

void instantiate_children(tnode_t *, di_node_t, di_prom_handle_t);
di_node_t pciex_di_match(const char *);
di_node_t pci_di_match(const char *);

struct tenumr *
_enum_init(void)
{
	return (&pci_enumr);
}

int
topo_pci_init(void)
{
/*	Devtree = di_init("/", DINFOCACHE); */
	Devtree = di_init("/", DINFOCPYALL);

	if (Devtree == DI_NODE_NIL) {
		topo_out(TOPO_ERR, "PCI enumerator: di_init failed.\n");
		return (TE_INITFAIL);
	}

	Promtree = di_prom_init();
	if (Promtree == DI_PROM_HANDLE_NIL) {
		di_fini(Devtree);
		topo_out(TOPO_ERR,
		    "PCI enumerator: di_prom_handle_init failed.\n");
		return (TE_INITFAIL);
	}
	topo_out(TOPO_DEBUG, "PCI Enumr initd\n");
	return (TE_INITOK);
}

void
topo_pci_fini(void)
{
	di_prom_fini(Promtree);
	di_fini(Devtree);
}

/*
 * If this devinfo node came originally from OBP data, we'll have prom
 * properties associated with the node where we can find properties of
 * interest.  We ignore anything after the the first four bytes of the
 * property, and interpet those first four bytes as our unsigned
 * integer.  If we don't find the property or it's not large enough,
 * 'val' will remained unchanged and we'll return -1.  Otherwise 'val'
 * gets updated with the property value and we return 0.
 */
static int
promprop2uint(di_node_t n, di_prom_handle_t ph, const char *propnm,
    uint_t *val)
{
	di_prom_prop_t pp = DI_PROM_PROP_NIL;
	uchar_t *buf;

	while ((pp = di_prom_prop_next(ph, n, pp)) != DI_PROM_PROP_NIL) {
		if (strcmp(di_prom_prop_name(pp), propnm) == 0) {
			if (di_prom_prop_data(pp, &buf) < sizeof (uint_t))
				continue;
			bcopy(buf, val, sizeof (uint_t));
			return (0);
		}
	}
	return (-1);
}

/*
 * If this devinfo node was added by the PCI hotplug framework it
 * doesn't have the PROM properties, but hopefully has the properties
 * we're looking for attached directly to the devinfo node.  We only
 * care about the first four bytes of the property, which we read as
 * our unsigned integer.  The remaining bytes are ignored.  If we
 * don't find the property we're looking for, or can't get its value,
 * 'val' remains unchanged and we return -1.  Otherwise 'val' gets the
 * property value and we return 0.
 */
static int
hwprop2uint(di_node_t n, const char *propnm, uint_t *val)
{
	di_prop_t hp = DI_PROP_NIL;
	uchar_t *buf;

	while ((hp = di_prop_next(n, hp)) != DI_PROP_NIL) {
		if (strcmp(di_prop_name(hp), propnm) == 0) {
			if (di_prop_bytes(hp, &buf) < sizeof (uint_t))
				continue;
			bcopy(buf, val, sizeof (uint_t));
			return (0);
		}
	}
	return (-1);
}

/*
 * copy_ancestor_prop
 *	Look for a prop of name 'prop' on an ancestor node in the
 *	topo tree and duplicate that property and its value on node.
 */
static void
copy_ancestor_prop(tnode_t *node, const char *prop)
{
	const char *value;
	tnode_t *p = node;

	if (p == NULL || prop == NULL)
		return;

	while ((p = topo_parent(p)) != NULL)
		if ((value = topo_get_prop(p, prop)) != NULL) {
			(void) topo_set_prop(node, prop, value);
			break;
		}
}

/*
 * copy_prop
 *	Look for a prop of name 'prop' on the 'from' node in the
 *	topo tree and duplicate that property and its value on node.
 */
static void
copy_prop(const char *prop, tnode_t *node, tnode_t *from)
{
	const char *value;

	if (node == NULL || prop == NULL || from == NULL)
		return;

	if ((value = topo_get_prop(from, prop)) != NULL)
		(void) topo_set_prop(node, prop, value);
}

static void
set_fru_info(tnode_t *node)
{
	if (topo_get_prop(node, PLATFRU) == NULL)
		copy_ancestor_prop(node, PLATFRU);
}

static void
set_devtype_prop(tnode_t *node, di_node_t dinode, di_prom_handle_t ph)
{
	di_prom_prop_t pp = DI_PROM_PROP_NIL;
	di_prop_t hp = DI_PROP_NIL;
	uchar_t *typbuf;
	char *tmpbuf;
	int sz = -1;

	tmpbuf = alloca(MAXPATHLEN);

	while ((hp = di_prop_next(dinode, hp)) != DI_PROP_NIL) {
		if (strcmp(di_prop_name(hp), DEVTYPEPROP) == 0) {
			if ((sz = di_prop_bytes(hp, &typbuf)) < 0)
				continue;
			break;
		}
	}

	if (sz < 0) {
		while ((pp = di_prom_prop_next(ph, dinode, pp)) !=
		    DI_PROM_PROP_NIL) {
			if (strcmp(di_prom_prop_name(pp), DEVTYPEPROP) == 0) {
				sz = di_prom_prop_data(pp, &typbuf);
				if (sz < 0)
					continue;
				break;
			}
		}
	}

	if (sz > 0 && sz < MAXPATHLEN - 1) {
		bcopy(typbuf, tmpbuf, sz);
		tmpbuf[sz] = 0;
		(void) topo_set_prop(node, DEVTYPE, tmpbuf);
	}
}

/*
 * Look for a hardware property containing the contents of this node's
 * pci express capability register.  For now, only look at hardware
 * properties and not prom properties.  Take the prom handle, though, in
 * case we decide we need to check prom properties at a later date.
 */
/*ARGSUSED*/
static int
get_excap(di_node_t dinode, di_prom_handle_t ph)
{
	int excap;

	if (hwprop2uint(dinode, SAVED_PCIEX_CAP_REG, (uint_t *)&excap) != 0)
		return (-1);
	return (excap);
}

/*
 * Set an EXCAP prop for pci-express capabilities.
 */
static void
set_excap_prop(tnode_t *node, int excap)
{
	if (excap < 0)
		return;

	switch (excap & PCIE_PCIECAP_DEV_TYPE_MASK) {
	case PCIE_PCIECAP_DEV_TYPE_ROOT:
		(void) topo_set_prop(node, EXCAPTPROP, PCIEX_ROOT);
		break;
	case PCIE_PCIECAP_DEV_TYPE_UP:
		(void) topo_set_prop(node, EXCAPTPROP, PCIEX_SWUP);
		break;
	case PCIE_PCIECAP_DEV_TYPE_DOWN:
		(void) topo_set_prop(node, EXCAPTPROP, PCIEX_SWDWN);
		break;
	case PCIE_PCIECAP_DEV_TYPE_PCI2PCIE:
		(void) topo_set_prop(node, EXCAPTPROP, PCIEX_BUS);
		break;
	case PCIE_PCIECAP_DEV_TYPE_PCIE2PCI:
		(void) topo_set_prop(node, EXCAPTPROP, PCI_BUS);
		break;
	case PCIE_PCIECAP_DEV_TYPE_PCIE_DEV:
		(void) topo_set_prop(node, EXCAPTPROP, PCIEX_DEVICE);
		break;
	}
}

/*
 * Get any physical slot name property on this node.  The node has to
 * declare itself as representing a physical slot number by having a
 * .PHYSLOTNUM property.  We then look for a .PHYSLOTNAME<slot-#>
 * property on the node or an ancestor of the node.  If the property
 * is found on an ancestor, this routine has the side-effect of
 * copying the property to this node.
 */
const char *
slotname_from_tprops(tnode_t *node)
{
	const char *str;
	char *tmpbuf;
	char *left;
	int physlot;

	if ((str = topo_get_prop(node, ".PHYSLOTNUM")) == NULL)
		return (NULL);

	physlot = (int)strtol(str, &left, 0);
	if (str == left || physlot < 0 || physlot > 0x1fff)
		return (NULL);

	tmpbuf = alloca(20);
	(void) snprintf(tmpbuf, 20, ".PHYSLOTNAME%d", physlot);
	if ((str = topo_get_prop(node, tmpbuf)) != NULL)
		return (str);
	copy_ancestor_prop(node, tmpbuf);
	return (topo_get_prop(node, tmpbuf));
}

static void
set_std_properties(tnode_t *node, di_node_t dinode, di_prom_handle_t ph)
{
	const char *labelval;
	const char *platval;
	tnode_t *pop;
	char *tmpbuf;
	char *dnpath;
	char *dnm;
	int devno;

	/*
	 * If it's a root complex, set the pciex capabilities property
	 */
	if (strcmp(PCIEX_ROOT, topo_name(node)) == 0)
		(void) topo_set_prop(node, EXCAPTPROP, PCIEX_ROOT);

	/*
	 * If it's a device node, we pretty much don't add any props
	 */
	if (strcmp(PCI_DEVICE, topo_name(node)) == 0 ||
	    strcmp(PCIEX_DEVICE, topo_name(node)) == 0) {
		set_fru_info(node);
		return;
	}

	tmpbuf = alloca(MAXPATHLEN);

	/*
	 * Create a DEVTYPE property as necessary
	 */
	set_devtype_prop(node, dinode, ph);

	/*
	 * Cheat for now and always say the thing is ON
	 */
	(void) topo_set_prop(node, ON, TPROP_TRUE);

	if ((dnpath = di_devfs_path(dinode)) != NULL) {
		(void) topo_set_prop(node, DEV, dnpath);
		di_devfs_path_free(dnpath);
	}

	if ((dnm = di_driver_name(dinode)) != NULL)
		(void) topo_set_prop(node, DRIVER, dnm);

	/*
	 * For functions, set LABEL based on a .SLOTNM<devno> property
	 * in our parent's parent or a .PHYSLOTNAME<slot-#> property
	 * in an ancestor, or the parent's parent's LABEL, but only if
	 * LABEL is not already set.  Also set PLATFRU and PLATASRU
	 * based on any .PLATFRU<devno> and .PLATASRU<devno>
	 * properties from parent's parent.
	 */
	if (strcmp(PCI_FUNCTION, topo_name(node)) != 0 &&
	    strcmp(PCIEX_FUNCTION, topo_name(node)) != 0)
		return;

	pop = topo_parent(topo_parent(node));
	devno = topo_get_instance_num(topo_parent(node));

	if ((labelval = topo_get_prop(node, LABEL)) == NULL) {
		(void) snprintf(tmpbuf, MAXPATHLEN, ".SLOTNM%d", devno);
		if ((labelval = topo_get_prop(pop, tmpbuf)) != NULL ||
		    (labelval = slotname_from_tprops(pop)) != NULL) {
			(void) topo_set_prop(node, LABEL, labelval);
		} else {
			copy_ancestor_prop(node, LABEL);
		}
	}

	if (topo_get_prop(node, PLATASRU) == NULL) {
		(void) snprintf(tmpbuf, MAXPATHLEN, ".%s%d", PLATASRU, devno);
		if ((platval = topo_get_prop(pop, tmpbuf)) != NULL)
			(void) topo_set_prop(node, PLATASRU, platval);
	}

	/*
	 * Pecking order for determining the value of PLAT-FRU:
	 *
	 * PLAT-FRU already defined by the .topo file, done.
	 * .PLATFRU<devno> defined, copy that as the value, done.
	 * LABEL defined (and not inherited), copy that as the value,
	 * done.
	 * Copy value from an ancestor.
	 */
	if (topo_get_prop(node, PLATFRU) == NULL) {
		(void) snprintf(tmpbuf, MAXPATHLEN, ".%s%d", PLATFRU, devno);
		if ((platval = topo_get_prop(pop, tmpbuf)) != NULL) {
			(void) topo_set_prop(node, PLATFRU, platval);
		} else {
			if (labelval != NULL)
				(void) topo_set_prop(node, PLATFRU, labelval);
			else
				copy_ancestor_prop(node, PLATFRU);
		}
	}
}

/*
 * fix_dev_prop -- sometimes di_devfs_path() doesn't tell the whole
 * story, leaving off the device and function number.  Chances are if
 * devfs doesn't put these on then we'll never see this device as an
 * error detector called out in an ereport.  Unfortunately, there are
 * races and we sometimes do get ereports from devices that devfs
 * decides aren't there.  For example, the error injector card seems
 * to bounce in and out of existence according to devfs.  We tack on
 * the missing dev and fn here so that the DEV property used to look
 * up the topology node is correct.
 */
static void
fix_dev_prop(tnode_t *node, int devno, int fnno)
{
	const char *curdev;
	char *lastslash;
	char *newpath;
	int need;

	/* Check if there is a DEV prop to fix. */
	if ((curdev = topo_get_prop(node, DEV)) == NULL)
		return;

	/*
	 * We only care about the last component of the dev path. If
	 * we don't find a slash, something is probably weird and we'll
	 * just bail.
	 */
	if ((lastslash = strrchr(curdev, '/')) == NULL)
		return;

	/*
	 * If an @ sign is present in the last component, the
	 * di_devfs_path() result had the device,fn unit-address.
	 * In that case there's nothing we need do.
	 */
	if (strchr(lastslash, '@') != NULL)
		return;

	if (fnno == 0)
		need = snprintf(NULL, 0, "%s@%x", curdev, devno);
	else
		need = snprintf(NULL, 0, "%s@%x,%x", curdev, devno, fnno);
	need++;

	newpath = alloca(need);

	if (fnno == 0)
		(void) snprintf(newpath, need, "%s@%x", curdev, devno);
	else
		(void) snprintf(newpath, need, "%s@%x,%x", curdev, devno, fnno);
	(void) topo_set_prop(node, DEV, newpath);
}

static int
slot_info_from_props(di_node_t n, di_prom_handle_t ph,
    int *physlot, uint_t *slotmap, uchar_t **slotbuf)
{
	di_prom_prop_t pp = DI_PROM_PROP_NIL;
	di_prop_t hp = DI_PROP_NIL;
	uint_t slotcap = 0;
	uint_t excap = 0;
	char *prnm;
	int slotsz = -1;

	while ((hp = di_prop_next(n, hp)) != DI_PROP_NIL) {
		prnm = di_prop_name(hp);
		if (strcmp(prnm, SLOTPROP) == 0) {
			slotsz = di_prop_bytes(hp, slotbuf);
			if (slotsz < sizeof (uint_t))
				continue;
			bcopy(*slotbuf, slotmap, sizeof (uint_t));
			break;
		} else if (strcmp(prnm, PHYSPROP) == 0) {
			slotsz = di_prop_bytes(hp, slotbuf);
			if (slotsz != sizeof (int))
				continue;
			bcopy(*slotbuf, physlot, sizeof (int));
			break;
		}
	}

	if (slotsz < 0) {
		while ((pp = di_prom_prop_next(ph, n, pp)) !=
		    DI_PROM_PROP_NIL) {
			prnm = di_prom_prop_name(pp);
			if (strcmp(prnm, SLOTPROP) == 0) {
				slotsz = di_prom_prop_data(pp, slotbuf);
				if (slotsz < sizeof (uint_t))
					continue;
				bcopy(*slotbuf, slotmap, sizeof (uint_t));
				break;
			} else if (strcmp(prnm, PHYSPROP) == 0) {
				slotsz = di_prom_prop_data(pp, slotbuf);
				if (slotsz != sizeof (int))
					continue;
				bcopy(*slotbuf, physlot, sizeof (int));
				break;
			}
		}
	}

	if (slotsz < 0) {
		if (hwprop2uint(n, SAVED_PCIEX_CAP_REG, &excap) != 0 ||
		    (excap & PCIE_PCIECAP_SLOT_IMPL) == 0 ||
		    hwprop2uint(n, SAVED_PCIEX_SLOTCAP_REG, &slotcap) != 0)
			return (slotsz);
		*physlot = slotcap >> PCIE_SLOTCAP_PHY_SLOT_NUM_SHIFT;
		slotsz = 0;
	}

	return (slotsz);
}

static void
set_slot_info(tnode_t *tn, di_node_t n, di_prom_handle_t ph)
{
	const char *slotnumstr;
	uchar_t *slotbuf;
	uint_t slotmap = 0;
	char *slotname;
	char *tmphcbuf;
	char *fmribuf;
	char *tmpbuf;
	char *left;
	int physlot = -1;
	int andbit;

	/*
	 * An absolute physical slot number defined in the .topo overrides
	 * anything we might find in devinfo properties.
	 */
	if ((slotnumstr = topo_get_prop(tn, ".PHYSLOTNUM")) != NULL) {
		physlot = (int)strtol(slotnumstr, &left, 0);
		/*
		 * Check for failure to interpret the property
		 * as a valid slot number, or for a bogus slot
		 * number.
		 */
		if (slotnumstr == left || physlot < 0 || physlot > 0x1fff)
			physlot = -1;
	}

	/*
	 * No .topo override, so look for "slot-names" or
	 * "physical-slot#" properties.
	 */
	if (physlot < 0 &&
	    slot_info_from_props(n, ph, &physlot, &slotmap, &slotbuf) < 0)
		return;

	/*
	 * physical-slot# of zero indicates everything is on-board, ...
	 */
	if (physlot == 0)
		return;

	/*
	 * ... else it's the pciexpress indicator for what slot the child is
	 * in and so we'll set a property for later use in describing the
	 * FRU.
	 */
	if (physlot > 0 && physlot <= 0x1fff) {
		/*
		 * If no .PHYSLOTNUM property is set, we should set one
		 * so folks coming along later can use that number to find
		 * the .PHYSLOTNAME<.PHYSLOTNUM> property.
		 */
		tmpbuf = alloca(20);
		if (topo_get_prop(tn, ".PHYSLOTNUM") == NULL) {
			(void) snprintf(tmpbuf, 20, "%d", physlot);
			(void) topo_set_prop(tn, ".PHYSLOTNUM", tmpbuf);
		}
		/*
		 * A .PHYSLOTNAME defined in the .topo overrides any
		 * value we would set.  The name is allowed to be on
		 * any of our ancestors, so we copy it here first.
		 */
		(void) snprintf(tmpbuf, 20, ".PHYSLOTNAME%d", physlot);
		if (topo_get_prop(tn, tmpbuf) == NULL)
			copy_ancestor_prop(tn, tmpbuf);
		if (topo_get_prop(tn, tmpbuf) == NULL) {
			/*
			 * No .PHYSLOTNAME<slot-#> is set, so we
			 * create one, making it the somewhat boring
			 * "hc:///component=SLOT <slot-#>".
			 */
			fmribuf = alloca(32);
			(void) snprintf(fmribuf, 32,
			    "hc:///component=SLOT %d", physlot);
			(void) topo_set_prop(tn, tmpbuf, fmribuf);
		}
		return;
	}

	if (slotmap == 0)
		return;

	tmpbuf = alloca(10);
	tmphcbuf = alloca(MAXPATHLEN);

	slotname = (char *)&slotbuf[4];
	for (andbit = 0; andbit < 32; andbit++) {
		if (slotmap & (1<<andbit)) {
			char *s = slotname;
			(void) snprintf(tmpbuf, 10, ".SLOTNM%d", andbit);
			slotname += strlen(s) + 1;
			/*
			 * Let a slot name defined in the .topo override
			 * the value from the slot-names property.  This
			 * allows us to fix up mistakes in the OBP (can
			 * you say chalupa) or elsewise fudge the label
			 * creatively from the .topo file.
			 */
			if (topo_get_prop(tn, tmpbuf) == NULL) {
				(void) snprintf(tmphcbuf,
				    MAXPATHLEN, "hc:///component=%s", s);
				(void) topo_set_prop(tn, tmpbuf, tmphcbuf);
			}
		}
	}
}

static int
minorwalkcb(di_node_t din, di_minor_t dim, void *arg)
{
	tnode_t *tn = (tnode_t *)arg;
	char *pnm;
	char *devname;
	char *apath;

	apath = alloca(MAXPATHLEN);
	pnm = alloca(MAXPATHLEN);

	/*
	 * Use any attachment point info to indirectly set PLATASRU
	 * and PLATFRU properties on children of the bus node.  We set
	 * .ASRU# and .FRU# values to be inherited by the appropriate
	 * children.  We allow these to be overridden in the .topo file
	 * by not setting a property value here if one already exists.
	 */
	if ((devname = di_devfs_path(din)) == NULL)
		return (DI_WALK_CONTINUE);

	(void) snprintf(pnm,
	    MAXPATHLEN, ".%s%d", PLATASRU, dim->dev_minor % 256);
	if (topo_get_prop(tn, pnm) == NULL) {
		(void) snprintf(apath,
		    MAXPATHLEN, "hc:///component=%s", di_minor_name(dim));
		(void) topo_set_prop(tn, pnm, apath);
	}
	(void) snprintf(pnm,
	    MAXPATHLEN, ".%s%d", PLATFRU, dim->dev_minor % 256);
	if (topo_get_prop(tn, pnm) == NULL) {
		(void) snprintf(apath,
		    MAXPATHLEN,
		    "hc:///component=%s:%s",
		    devname,
		    di_minor_name(dim));
		(void) topo_set_prop(tn, pnm, apath);
	}
	di_devfs_path_free(devname);
	return (DI_WALK_CONTINUE);
}

static void
set_attachpt_info(tnode_t *tn, di_node_t n)
{
	(void) di_walk_minor(n, "ddi_ctl:attachment_point:pci", 0,
	    (void *)tn, minorwalkcb);
}

#define	IDBUFLEN 13

static const char *
set_pci_properties(tnode_t *tn, di_node_t n, di_prom_handle_t ph)
{
	static char idstring[IDBUFLEN];	/* pciVVVV,DDDD */
	uint_t vendor = 0x10000;  /* out of legal range for a vendor-id */
	uint_t device = 0x10000;  /* out of legal range for a device-id */
	char *tmpbuf;

	tmpbuf = alloca(MAXPATHLEN);

	(void) hwprop2uint(n, DEVIDPROP, &device);
	if (device == 0x10000)
		(void) promprop2uint(n, ph, DEVIDPROP, &device);
	if (device != 0x10000) {
		(void) snprintf(tmpbuf, MAXPATHLEN, "%x", device);
		(void) topo_set_prop(tn, DEVIDTPROP, tmpbuf);
	}

	(void) hwprop2uint(n, VENDIDPROP, &vendor);
	if (vendor == 0x10000)
		(void) promprop2uint(n, ph, VENDIDPROP, &vendor);
	if (vendor != 0x10000) {
		(void) snprintf(tmpbuf, MAXPATHLEN, "%x", vendor);
		(void) topo_set_prop(tn, VENDIDTPROP, tmpbuf);
	}

	if (device != 0x10000 && vendor != 0x10000) {
		(void) snprintf(idstring, IDBUFLEN, "pci%x,%x", vendor, device);
		return (idstring);
	}
	return (NULL);
}

static int
get_class_code_and_reg(uint_t *cc, uint_t *reg, di_node_t n,
    di_prom_handle_t ph)
{
	if (hwprop2uint(n, REGPROP, reg) < 0 &&
	    promprop2uint(n, ph, REGPROP, reg) < 0)
		return (-1);

	if (hwprop2uint(n, CLASSPROP, cc) < 0 &&
	    promprop2uint(n, ph, CLASSPROP, cc) < 0)
		return (-1);

	return (0);
}

static tnode_t *
expected_child(tnode_t *parent, const char *expect_type, int intent)
{
	tnode_t *cn = NULL;
	int min, max;

	/*
	 * We prefer to instance a child node that's uninstanced, so
	 * it inherits all the right properties.
	 */
	while ((cn = topo_next_child(parent, cn)) != NULL) {
		if (strcmp(topo_name(cn), expect_type) != 0)
			continue;
		if (topo_get_instance_num(cn) < 0) {
			topo_get_instance_range(cn, &min, &max);
			if (intent < 0 || (intent >= min && intent <= max))
				break;
		}
	}

	if (cn == NULL) {
		topo_out(TOPO_DEBUG,
		    "Expected to set instance %d of a %s topo node.  "
		    "But found no match.", intent, expect_type);
	}
	return (cn);
}

static void
examine_prom_props(tnode_t *pn, di_node_t n, di_prom_handle_t ph)
{
	tnode_t *ppn;
	tnode_t *cn = NULL;
	uint_t reg, cc;
	const char *topof;
	const char *parentcap;
	uint_t childclass, childsubclass;
	int childcap, childetyp;
	int busno, devno, fnno;

	if (get_class_code_and_reg(&cc, &reg, n, ph) < 0)
		return;

	busno = PCI_REG_BUS_G(reg);
	devno = PCI_REG_DEV_G(reg);
	fnno = PCI_REG_FUNC_G(reg);

	/*
	 * Get the child's pci express capabilities (if any).  We'll later
	 * convert this to a property on the appropriate topo node.
	 */
	childcap = get_excap(n, ph);
	if (childcap > 0)
		childetyp = childcap & PCIE_PCIECAP_DEV_TYPE_MASK;
	childclass = GETCLASS(cc);
	childsubclass = GETSUBCLASS(cc);

	/*
	 * If the child is a root complex, enumerate it as such rather
	 * than as just another dev/fn of the parent pcibus.
	 */
	if (childcap > 0 && childetyp == PCIE_PCIECAP_DEV_TYPE_ROOT) {
		if ((ppn = topo_parent(pn)) == NULL ||
		    (pn = expected_child(ppn, PCIEX_ROOT, devno)) == NULL) {
			topo_out(TOPO_DEBUG, "found pci-express root"
			    "complex, but grand-parent topo node "
			    "lacks a " PCIEX_ROOT " child node.\n");
			return;
		}
		pn = topo_set_instance_num(pn, devno);
		set_excap_prop(pn, childcap);
		set_slot_info(pn, n, ph);
		/*
		 * Beneath a root complex we expect to find a switch,
		 * bridge or direct link.  Whichever it is, it will be
		 * enumerated as a pci-express bus/dev/fn trio.
		 */
		if ((cn = expected_child(pn, PCIEX_BUS, -1)) == NULL) {
			topo_out(TOPO_DEBUG,
			    "found pci-express root complex "
			    "that lacks a " PCIEX_BUS
			    "child node to instance.\n");
			return;
		}
		instantiate_children(cn, n, ph);
		return;
	}

	/*
	 * Sanity check here: The child of an upstream switch should
	 * be a downstream switch.
	 */
	if ((parentcap = topo_get_prop(pn, EXCAPTPROP)) != NULL) {
		if (strcmp(parentcap, PCIEX_SWUP) == 0) {
			if (childclass != PCI_CLASS_BRIDGE ||
			    childetyp != PCIE_PCIECAP_DEV_TYPE_DOWN) {
				topo_out(TOPO_DEBUG,
				    "Devinfo child of UP switch is not a "
				    "down switch.\n");
				return;
			}
		}
	}

	/*
	 * If the parent is an unenumerated bus, do it a favor and set
	 * an instance number based on the bus defined for this
	 * device.
	 */
	if ((strcmp(PCI_BUS, topo_name(pn)) == 0 ||
	    strcmp(PCIEX_BUS, topo_name(pn)) == 0) &&
	    topo_get_instance_num(pn) < 0) {
		pn = topo_set_instance_num(pn, busno);
		topo_out(TOPO_DEBUG, "Set parent's bus instance #%d,"
		    " np=%p.\n", busno, (void *)pn);
		set_slot_info(pn, di_parent_node(n), ph);
		set_attachpt_info(pn, di_parent_node(n));
		set_fru_info(pn);
	}

	if (strcmp(PCI_BUS, topo_name(pn)) == 0 &&
	    (cn = expected_child(pn, PCI_DEVICE, devno)) == NULL)
		return;
	if (strcmp(PCIEX_BUS, topo_name(pn)) == 0 &&
	    (cn = expected_child(pn, PCIEX_DEVICE, devno)) ==
	    NULL)
		return;
	if (cn == NULL) {
		topo_out(TOPO_DEBUG, "Topo node is neither " PCI_BUS
		    " nor " PCIEX_BUS " so, we don't know what the heck "
		    "the child node would be.\n");
		return;
	}

	pn = topo_set_instance_num(cn, devno);
	topo_out(TOPO_DEBUG, "Set device instance #%d.\n", devno);
	set_std_properties(pn, n, ph);

	if (strcmp(PCI_DEVICE, topo_name(pn)) == 0 &&
	    (cn = expected_child(pn, PCI_FUNCTION, fnno)) == NULL)
		return;
	if (strcmp(PCIEX_DEVICE, topo_name(pn)) == 0 &&
	    (cn = expected_child(pn, PCIEX_FUNCTION, fnno)) == NULL)
		return;
	pn = topo_set_instance_num(cn, fnno);
	topo_out(TOPO_DEBUG, "Set function instance #%d.\n", fnno);
	set_excap_prop(pn, childcap);
	set_std_properties(pn, n, ph);
	fix_dev_prop(pn, devno, fnno);

	if ((topof = set_pci_properties(pn, n, ph)) != NULL) {
		/*
		 * Look for topology information specific to this
		 * vendor-id & device-id, if any.
		 */
		(void) topo_load(topof, pn);
	}

	if (childclass == PCI_CLASS_BRIDGE) {
		topo_out(TOPO_DEBUG, "device/fn is a bridge, ");

		if (childsubclass != PCI_BRIDGE_PCI) {
			topo_out(TOPO_DEBUG, "but not to PCI.\n");
			return;
		}
		/*
		 * What sort of child is this? If there is no
		 * PCI-express capability or if the capability is a
		 * bridge to PCI, then children we will enumerate are
		 * PCI buses.
		 */
		if (childcap < 0 ||
		    childetyp == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
			topo_out(TOPO_DEBUG,
			    "no PCI-express capabilities, or a "
			    "bridge to PCI.\n");
			if ((cn = expected_child(pn, PCI_BUS, -1)) == NULL) {
				topo_out(TOPO_DEBUG,
				    "BUT the topo nodes lacks a "
				    PCI_BUS
				    "child node.\n");
				return;
			}
		} else {
			topo_out(TOPO_DEBUG,
			    "and has PCI-express capability.\n");
			cn = expected_child(pn, PCIEX_BUS, -1);
			if (cn == NULL) {
				topo_out(TOPO_DEBUG,
				    "but the topo nodes lacks a "
				    PCIEX_BUS
				    "child node.\n");
				return;
			}
		}
		/*
		 * We don't know the instance number of this bus,
		 * so we'll have to rely on it getting filled in
		 * later by one of its children.
		 */
		instantiate_children(cn, n, Promtree);
		return;
	}
}

void
instantiate_children(tnode_t *tn, di_node_t n, di_prom_handle_t ph)
{
	di_node_t pn;

	pn = di_child_node(n);
	while (pn != DI_NODE_NIL) {
		examine_prom_props(tn, pn, ph);
		pn = di_sibling_node(pn);
	}
}

static di_node_t
drivers_match(const char *drvr_type, const char *devprop)
{
	di_node_t pnode;
	char *dnpath;

	topo_out(TOPO_DEBUG, "search for drivers of type %s.\n", drvr_type);

	pnode = di_drv_first_node(drvr_type, Devtree);
	while (pnode != DI_NODE_NIL) {
		if ((dnpath = di_devfs_path(pnode)) == NULL)
			continue;
		topo_out(TOPO_DEBUG, "%s within %s ? ", dnpath, devprop);
		if (strcmp(devprop, dnpath) == 0) {
			topo_out(TOPO_DEBUG, "yesh!\n");
			di_devfs_path_free(dnpath);
			break;
		}
		topo_out(TOPO_DEBUG, "no.\n");
		di_devfs_path_free(dnpath);
		pnode = di_drv_next_node(pnode);
	}
	return (pnode);
}

static void
represent_hostbridge_pbm(tnode_t *node)
{
	tnode_t *parent;
	tnode_t *cn, *cn1;

	/*
	 * Only do this for PCI_BUS nodes
	 */
	if (strcmp(PCI_BUS, topo_name(node)) != 0)
		return;

	if ((cn = expected_child(node, PCI_DEVICE, 32)) == NULL)
		return;
	cn = topo_set_instance_num(cn, 32);
	set_fru_info(cn);
	if (strcmp(PCI_DEVICE, topo_name(cn)) == 0 &&
	    (cn1 = expected_child(cn, PCI_FUNCTION, 0)) == NULL)
		return;
	if (strcmp(PCIEX_DEVICE, topo_name(cn)) == 0 &&
	    (cn1 = expected_child(cn, PCIEX_FUNCTION, 0)) == NULL)
		return;
	cn = topo_set_instance_num(cn1, 0);
	copy_ancestor_prop(cn, DEV);
	copy_ancestor_prop(cn, ATTACHD);
	copy_ancestor_prop(cn, DRIVER);
	copy_ancestor_prop(cn, ON);
	set_fru_info(cn);

	(void) topo_set_prop(node, DEV, "none");

	/*
	 *  The topo node for the hostbridge should inherit the node's
	 *  DRIVER property.  The hostbridge is driven by the same
	 *  software as the bus.
	 */
	if ((parent = topo_parent(node)) != NULL &&
	    strcmp(topo_name(parent), "hostbridge") == 0)
		copy_prop(DRIVER, parent, node);
}

static void
instantiate_all(tnode_t *node, const char *drvr_type, di_prom_handle_t ph)
{
	di_node_t pnode;
	char *dnpath;

	pnode = di_drv_first_node(drvr_type, Devtree);
	while (pnode != DI_NODE_NIL) {
		const char *devprop;
		tnode_t *parent;

		if ((dnpath = di_devfs_path(pnode)) == NULL)
			continue;
		if ((parent = topo_parent(node)) != NULL)
			devprop = topo_get_prop(parent, DEV);

		if (parent == NULL ||
		    devprop == NULL ||
		    strcmp(devprop, dnpath) == 0) {
			set_std_properties(node, pnode, ph);
			set_slot_info(node, pnode, ph);
			set_attachpt_info(node, pnode);
			set_fru_info(node);
			represent_hostbridge_pbm(node);
			instantiate_children(node, pnode, ph);
		}
		di_devfs_path_free(dnpath);
		pnode = di_drv_next_node(pnode);
	}
}

di_node_t
pci_di_match(const char *devproppath)
{
	di_node_t pnode;

	/*
	 * Search for devinfo nodes for psycho, schizo, or generic
	 * pci bus and find one that matches the DEV property path
	 * passed to us.
	 */
	pnode = drivers_match(PSYCHO, devproppath);
	if (pnode != DI_NODE_NIL)
		return (pnode);

	pnode = drivers_match(SCHIZO, devproppath);
	if (pnode != DI_NODE_NIL)
		return (pnode);

	pnode = drivers_match(NPE, devproppath);
	if (pnode != DI_NODE_NIL)
		return (pnode);

	pnode = drivers_match(PX, devproppath);
	if (pnode != DI_NODE_NIL)
		return (pnode);

	pnode = drivers_match(PCI, devproppath);
	return (pnode);
}

di_node_t
pciex_di_match(const char *devproppath)
{
	di_node_t pnode;

	pnode = drivers_match(NPE, devproppath);
	if (pnode != DI_NODE_NIL)
		return (pnode);

	pnode = drivers_match(PX, devproppath);
	return (pnode);
}

/*
 *  The enum_pci_bus() routine gets called by topo to set instance
 *  numbers for all the PCI bus nodes.  The enumerator takes care of
 *  all devices, functions, bridges, and sub-buses beneath the bus
 *  node as well.
 */
void
enum_pci_bus(tnode_t *node)
{
	const char *dev, *scan;
	di_node_t selfdn;
	tnode_t *parent;
	tnode_t *self;
	int express;
	int min, max;

	/*
	 * First thing, decide if we're looking for pci-express or
	 * good old pci.  Then orient ourselves within the devinfo
	 * tree.  The static topo info hopefully will have left us an
	 * orienting clue by providing a DEV property.
	 *
	 * Alternatively if there is no DEV, but there's a SCAN
	 * property, we'll scan for pci buses.
	 */
	if (strcmp(PCIEX_ROOT, topo_name(node)) == 0)
		express = 1;
	else if (strcmp(PCI_BUS, topo_name(node)) == 0)
		express = 0;
	else
		return;

	if ((dev = topo_get_prop(node, DEV)) == NULL) {
		scan = topo_get_prop(node, SCAN);
		if (scan == NULL) {
			topo_out(TOPO_DEBUG,
			    "Bus tnode has no DEV or SCAN prop\n");
			return;
		}
		if (express == 0) {
			instantiate_all(node, PCI, Promtree);
			instantiate_all(node, NPE, Promtree);
			instantiate_all(node, PX, Promtree);
		} else {
			instantiate_all(node, NPE, Promtree);
			instantiate_all(node, PX, Promtree);
		}
		return;
	} else {
		if (express == 0 &&
		    (selfdn = pci_di_match(dev)) == DI_NODE_NIL) {
			topo_out(TOPO_DEBUG,
			    "No match found for %s in devinfo.\n", dev);
			return;
		}
		if (express == 1 &&
		    (selfdn = pciex_di_match(dev)) == DI_NODE_NIL) {
			topo_out(TOPO_DEBUG,
			    "No match found for %s in devinfo.\n", dev);
			return;
		}
	}

	/*
	 * We've found ourselves in the devtree.  A correctly written
	 * .topo file will have left the instance number unambiguous
	 * (a range of exactly one number) and so we'll know and can
	 * officially establish the instance number of the bus or root
	 * complex.  This creates a new topo node returned to us, with
	 * children for which we must set instance numbers...
	 */
	topo_get_instance_range(node, &min, &max);
	if (min < 0 || max < 0 || min != max) {
		topo_out(TOPO_DEBUG,
		    "Unexpected bus instance min %d != max %d.\n",
		    min, max);
		return;
	}
	self = topo_set_instance_num(node, min);
	set_std_properties(self, selfdn, Promtree);
	set_slot_info(self, selfdn, Promtree);
	set_attachpt_info(self, selfdn);
	set_fru_info(self);

	if (express == 0) {
		/*
		 * We represent the hostbridge's PCI bus module as a "device"
		 * on the bus outside of the range of normal devices.
		 */
		represent_hostbridge_pbm(self);
	} else {
		/*
		 * Beneath a root complex we expect to find a switch,
		 * bridge or direct link.  Whichever it is, it will be
		 * enumerated as a pci-express bus/dev/fn trio.
		 */
		if ((self = expected_child(self, PCIEX_BUS, -1)) == NULL) {
			topo_out(TOPO_DEBUG,
			    "Found pci-express root complex "
			    "that lacks a " PCIEX_BUS
			    " child node to instance.\n");
			return;
		}
	}
	instantiate_children(self, selfdn, Promtree);

	/*
	 * Check to see if we're the descendant of a topo node that's
	 * not enumerated, but whose instance number is unambiguous.
	 * If we are, we can enumerate that puppy because we now know that
	 * the ancestor is for real.
	 */
	parent = topo_parent(self);
	while (parent != NULL) {
		if (topo_get_instance_num(parent) < 0) {
			topo_get_instance_range(parent, &min, &max);
			if (min == max && min >= 0)
				(void) topo_set_instance_num(parent, min);
		}
		parent = topo_parent(parent);
	}
}

void
topo_pci_enum(tnode_t *node)
{
	/*
	 * Any enumerations other than buses should have already
	 * happened at the time the bus was enumerated, so we can just
	 * return.
	 */
	if (strcmp(PCI_BUS, topo_name(node)) != 0 &&
	    strcmp(PCIEX_ROOT, topo_name(node)) != 0)
		return;
	enum_pci_bus(node);
}
