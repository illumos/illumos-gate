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
 */
/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <assert.h>
#include <alloca.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <libdevinfo.h>
#include <hostbridge.h>
#include <pcibus.h>
#include <did.h>
#include <did_props.h>
#include <fm/libtopo.h>
#include <pcidb.h>

static int ASRU_set(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int FRU_set(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int DEVprop_set(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int DRIVERprop_set(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int MODULEprop_set(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int EXCAP_set(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int BDF_set(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int label_set(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int maybe_di_chars_copy(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int maybe_di_uint_to_str(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int maybe_di_uint_to_dec_str(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int AADDR_set(tnode_t *, did_t *,
    const char *, const char *, const char *);
static int maybe_pcidb_set(tnode_t *, did_t *,
    const char *, const char *, const char *);

/*
 * Arrays of "property translation routines" to set the properties a
 * given type of topology node should have.
 *
 * Note that the label_set translation *MUST COME BEFORE* the FRU
 * translation.  For the near term we're setting the FRU fmri to
 * be a legacy-hc style FMRI based on the label, so the label needs
 * to have been set before we do the FRU translation.
 *
 */

static const topo_pgroup_info_t io_pgroup =
	{ TOPO_PGROUP_IO, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t pci_pgroup =
	{ TOPO_PGROUP_PCI, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_pgroup_info_t protocol_pgroup = {
	TOPO_PGROUP_PROTOCOL,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
}; /* Request to create protocol will be ignored by libtopo */

txprop_t Fn_common_props[] = {
	{ NULL, &io_pgroup, TOPO_IO_DEV, DEVprop_set },
	{ DI_DEVTYPPROP, &io_pgroup, TOPO_IO_DEVTYPE, maybe_di_chars_copy },
	{ DI_DEVIDPROP, &pci_pgroup, TOPO_PCI_DEVID, maybe_di_uint_to_str },
	{ NULL, &io_pgroup, TOPO_IO_DRIVER, DRIVERprop_set },
	{ NULL, &io_pgroup, TOPO_IO_MODULE, MODULEprop_set },
	{ "serd_io_device_nonfatal_n", &io_pgroup, "serd_io_device_nonfatal_n",
	    maybe_di_uint_to_dec_str },
	{ "serd_io_device_nonfatal_t", &io_pgroup, "serd_io_device_nonfatal_t",
	    maybe_di_chars_copy },
	{ "serd_io_device_nonfatal_btlp_n", &io_pgroup,
	    "serd_io_device_nonfatal_btlp_n", maybe_di_uint_to_dec_str },
	{ "serd_io_device_nonfatal_btlp_t", &io_pgroup,
	    "serd_io_device_nonfatal_btlp_t", maybe_di_chars_copy },
	{ "serd_io_device_nonfatal_bdllp_n", &io_pgroup,
	    "serd_io_device_nonfatal_bdllp_n", maybe_di_uint_to_dec_str },
	{ "serd_io_device_nonfatal_bdllp_t", &io_pgroup,
	    "serd_io_device_nonfatal_bdllp_t", maybe_di_chars_copy },
	{ "serd_io_device_nonfatal_re_n", &io_pgroup,
	    "serd_io_device_nonfatal_re_n", maybe_di_uint_to_dec_str },
	{ "serd_io_device_nonfatal_re_t", &io_pgroup,
	    "serd_io_device_nonfatal_re_t", maybe_di_chars_copy },
	{ "serd_io_device_nonfatal_rto_n", &io_pgroup,
	    "serd_io_device_nonfatal_rto_n", maybe_di_uint_to_dec_str },
	{ "serd_io_device_nonfatal_rto_t", &io_pgroup,
	    "serd_io_device_nonfatal_rto_t", maybe_di_chars_copy },
	{ "serd_io_device_nonfatal_rnr_n", &io_pgroup,
	    "serd_io_device_nonfatal_rnr_n", maybe_di_uint_to_dec_str },
	{ "serd_io_device_nonfatal_rnr_t", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_rnr_t", maybe_di_chars_copy },
	{ "serd_io_pciex_corrlink-bus_btlp_n", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_btlp_n", maybe_di_uint_to_dec_str },
	{ "serd_io_pciex_corrlink-bus_btlp_t", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_btlp_t", maybe_di_chars_copy },
	{ "serd_io_pciex_corrlink-bus_bdllp_n", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_bdllp_n", maybe_di_uint_to_dec_str },
	{ "serd_io_pciex_corrlink-bus_bdllp_t", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_bdllp_t", maybe_di_chars_copy },
	{ "serd_io_pciex_corrlink-bus_re_n", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_re_n", maybe_di_uint_to_dec_str },
	{ "serd_io_pciex_corrlink-bus_re_t", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_re_t", maybe_di_chars_copy },
	{ "serd_io_pciex_corrlink-bus_rto_n", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_rto_n", maybe_di_uint_to_dec_str },
	{ "serd_io_pciex_corrlink-bus_rto_t", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_rto_t", maybe_di_chars_copy },
	{ "serd_io_pciex_corrlink-bus_rnr_n", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_rnr_n", maybe_di_uint_to_dec_str },
	{ "serd_io_pciex_corrlink-bus_rnr_t", &io_pgroup,
	    "serd_io_pciex_corrlink-bus_rnr_t", maybe_di_chars_copy },
	{ NULL, &pci_pgroup, TOPO_PCI_EXCAP, EXCAP_set },
	{ DI_CLASSPROP, &pci_pgroup, TOPO_PCI_CLASS, maybe_di_uint_to_str },
	{ DI_VENDIDPROP, &pci_pgroup, TOPO_PCI_VENDID, maybe_di_uint_to_str },
	{ DI_AADDRPROP, &pci_pgroup, TOPO_PCI_AADDR, AADDR_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_LABEL, label_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_FRU, FRU_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_ASRU, ASRU_set },
	/*
	 * This entry will attempt to set the following three properties via
	 * lookups in the PCI database:
	 * - vendor-name
	 * - device-name
	 * - subsystem-name
	 */
	{ NULL, &pci_pgroup, NULL, maybe_pcidb_set }
};

txprop_t Dev_common_props[] = {
	{ NULL, &protocol_pgroup, TOPO_PROP_LABEL, label_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_FRU, FRU_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_ASRU, ASRU_set }
};

txprop_t Bus_common_props[] = {
	{ DI_DEVTYPPROP, &io_pgroup, TOPO_IO_DEVTYPE, maybe_di_chars_copy },
	{ NULL, &io_pgroup, TOPO_IO_DRIVER, DRIVERprop_set },
	{ NULL, &io_pgroup, TOPO_IO_MODULE, MODULEprop_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_LABEL, label_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_FRU, FRU_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_ASRU, ASRU_set }
};

txprop_t RC_common_props[] = {
	{ NULL, &io_pgroup, TOPO_IO_DEV, DEVprop_set },
	{ DI_DEVTYPPROP, &io_pgroup, TOPO_IO_DEVTYPE, maybe_di_chars_copy },
	{ NULL, &io_pgroup, TOPO_IO_DRIVER, DRIVERprop_set },
	{ NULL, &io_pgroup, TOPO_IO_MODULE, MODULEprop_set },
	{ NULL, &pci_pgroup, TOPO_PCI_EXCAP, EXCAP_set },
	{ NULL, &pci_pgroup, TOPO_PCI_BDF, BDF_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_ASRU, ASRU_set },
	/*
	 * These props need to be put at the end of table.  x86pi has its
	 * own way to set them.
	 */
	{ NULL, &protocol_pgroup, TOPO_PROP_LABEL, label_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_FRU, FRU_set }
};

txprop_t ExHB_common_props[] = {
	{ NULL, &protocol_pgroup, TOPO_PROP_ASRU, ASRU_set },
	/*
	 * These props need to be put at the end of table.  x86pi has its
	 * own way to set them.
	 */
	{ NULL, &protocol_pgroup, TOPO_PROP_LABEL, label_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_FRU, FRU_set }
};

txprop_t IOB_common_props[] = {
	{ NULL, &protocol_pgroup, TOPO_PROP_LABEL, label_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_FRU, FRU_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_ASRU, ASRU_set }
};

txprop_t HB_common_props[] = {
	{ NULL, &io_pgroup, TOPO_IO_DEV, DEVprop_set },
	{ NULL, &io_pgroup, TOPO_IO_DRIVER, DRIVERprop_set },
	{ NULL, &io_pgroup, TOPO_IO_MODULE, MODULEprop_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_ASRU, ASRU_set },
	/*
	 * These props need to be put at the end of table.  x86pi has its
	 * own way to set them.
	 */
	{ NULL, &protocol_pgroup, TOPO_PROP_LABEL, label_set },
	{ NULL, &protocol_pgroup, TOPO_PROP_FRU, FRU_set }
};

int Bus_propcnt = sizeof (Bus_common_props) / sizeof (txprop_t);
int Dev_propcnt = sizeof (Dev_common_props) / sizeof (txprop_t);
int ExHB_propcnt = sizeof (ExHB_common_props) / sizeof (txprop_t);
int HB_propcnt = sizeof (HB_common_props) / sizeof (txprop_t);
int IOB_propcnt = sizeof (IOB_common_props) / sizeof (txprop_t);
int RC_propcnt = sizeof (RC_common_props) / sizeof (txprop_t);
int Fn_propcnt = sizeof (Fn_common_props) / sizeof (txprop_t);

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
promprop2uint(topo_mod_t *mod, di_node_t n, const char *propnm, uint_t *val)
{
	di_prom_handle_t ptp = DI_PROM_HANDLE_NIL;
	di_prom_prop_t pp = DI_PROM_PROP_NIL;
	uchar_t *buf;

	if ((ptp = topo_mod_prominfo(mod)) == DI_PROM_HANDLE_NIL)
		return (-1);

	while ((pp = di_prom_prop_next(ptp, n, pp)) != DI_PROM_PROP_NIL) {
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

int
di_uintprop_get(topo_mod_t *mod, di_node_t n, const char *pnm, uint_t *pv)
{
	if (hwprop2uint(n, pnm, pv) < 0)
		if (promprop2uint(mod, n, pnm, pv) < 0)
			return (-1);
	return (0);
}

int
di_bytes_get(topo_mod_t *mod, di_node_t n, const char *pnm, int *sz,
    uchar_t **db)
{
	di_prom_handle_t ptp = DI_PROM_HANDLE_NIL;
	di_prom_prop_t pp = DI_PROM_PROP_NIL;
	di_prop_t hp = DI_PROP_NIL;

	if ((ptp = topo_mod_prominfo(mod)) == DI_PROM_HANDLE_NIL)
		return (-1);

	*sz = -1;
	while ((hp = di_prop_next(n, hp)) != DI_PROP_NIL) {
		if (strcmp(di_prop_name(hp), pnm) == 0) {
			if ((*sz = di_prop_bytes(hp, db)) < 0)
				continue;
			break;
		}
	}
	if (*sz < 0) {
		while ((pp = di_prom_prop_next(ptp, n, pp)) !=
		    DI_PROM_PROP_NIL) {
			if (strcmp(di_prom_prop_name(pp), pnm) == 0) {
				*sz = di_prom_prop_data(pp, db);
				if (*sz < 0)
					continue;
				break;
			}
		}
	}

	if (*sz < 0)
		return (-1);
	return (0);
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
static char *
dev_path_fix(topo_mod_t *mp, char *path, int devno, int fnno)
{
	char *lastslash;
	char *newpath;
	int need;

	/*
	 * We only care about the last component of the dev path. If
	 * we don't find a slash, something is weird.
	 */
	lastslash = strrchr(path, '/');
	assert(lastslash != NULL);

	/*
	 * If an @ sign is present in the last component, the
	 * di_devfs_path() result had the device,fn unit-address.
	 * In that case there's nothing we need do.
	 */
	if (strchr(lastslash, '@') != NULL)
		return (path);

	if (fnno == 0)
		need = snprintf(NULL, 0, "%s@%x", path, devno);
	else
		need = snprintf(NULL, 0, "%s@%x,%x", path, devno, fnno);
	need++;

	if ((newpath = topo_mod_alloc(mp, need)) == NULL) {
		topo_mod_strfree(mp, path);
		return (NULL);
	}

	if (fnno == 0)
		(void) snprintf(newpath, need, "%s@%x", path, devno);
	else
		(void) snprintf(newpath, need, "%s@%x,%x", path, devno, fnno);

	topo_mod_strfree(mp, path);
	return (newpath);
}

/*
 * dev_for_hostbridge() -- For hostbridges we truncate the devfs path
 * after the first element in the bus address.
 */
static char *
dev_for_hostbridge(topo_mod_t *mp, char *path)
{
	char *lastslash;
	char *newpath;
	char *comma;
	int plen;

	plen = strlen(path) + 1;

	/*
	 * We only care about the last component of the dev path. If
	 * we don't find a slash, something is weird.
	 */
	lastslash = strrchr(path, '/');
	assert(lastslash != NULL);

	/*
	 * Find the comma in the last component component@x,y, and
	 * truncate the comma and any following number.
	 */
	comma = strchr(lastslash, ',');
	assert(comma != NULL);

	*comma = '\0';
	if ((newpath = topo_mod_strdup(mp, path)) == NULL) {
		topo_mod_free(mp, path, plen);
		return (NULL);
	}

	*comma = ',';
	topo_mod_free(mp, path, plen);
	return (newpath);
}

/*ARGSUSED*/
static int
ASRU_set(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	topo_mod_t *mp;
	nvlist_t *fmri;
	char *dnpath, *path, *fpath, *nm;
	int d, e, f;

	/*
	 * If this topology node represents a function of device,
	 * set the ASRU to a dev scheme FMRI based on the value of
	 * di_devfs_path().  If that path is NULL, set the ASRU to
	 * be the resource describing this topology node.  If this
	 * isn't a function, inherit any ASRU from the parent.
	 */
	mp = did_mod(pd);
	nm = topo_node_name(tn);
	if ((strcmp(nm, PCI_BUS) == 0 && did_gettnode(pd) &&
	    strcmp(topo_node_name(did_gettnode(pd)), HOSTBRIDGE) == 0) ||
	    strcmp(nm, PCI_FUNCTION) == 0 || strcmp(nm, PCIEX_FUNCTION) == 0 ||
	    strcmp(nm, PCIEX_ROOT) == 0) {
		if ((dnpath = di_devfs_path(did_dinode(pd))) != NULL) {
			/*
			 * Dup the path, dev_path_fix() may replace it and
			 * dev_path_fix() wouldn't know to use
			 * di_devfs_path_free()
			 */
			if ((path = topo_mod_strdup(mp, dnpath)) == NULL) {
				di_devfs_path_free(dnpath);
				return (topo_mod_seterrno(mp, EMOD_NOMEM));
			}
			di_devfs_path_free(dnpath);
			did_BDF(pd, NULL, &d, &f);
			if ((fpath = dev_path_fix(mp, path, d, f)) == NULL)
				return (topo_mod_seterrno(mp, EMOD_NOMEM));

			fmri = topo_mod_devfmri(mp, FM_DEV_SCHEME_VERSION,
			    fpath, NULL);
			if (fmri == NULL) {
				topo_mod_dprintf(mp,
				    "dev:///%s fmri creation failed.\n", fpath);
				topo_mod_strfree(mp, fpath);
				return (-1);
			}
			topo_mod_strfree(mp, fpath);
		} else {
			topo_mod_dprintf(mp, "NULL di_devfs_path.\n");
			if (topo_prop_get_fmri(tn, TOPO_PGROUP_PROTOCOL,
			    TOPO_PROP_RESOURCE, &fmri, &e) < 0)
				return (topo_mod_seterrno(mp, e));
		}
		if (topo_node_asru_set(tn, fmri, 0, &e) < 0) {
			nvlist_free(fmri);
			return (topo_mod_seterrno(mp, e));
		}
		nvlist_free(fmri);
		return (0);
	}
	(void) topo_node_asru_set(tn, NULL, 0, &e);

	return (0);
}

/*
 * Set the FRU property to the hc fmri of this tnode
 */
int
FRU_fmri_set(topo_mod_t *mp, tnode_t *tn)
{
	nvlist_t *fmri;
	int err, e;

	if (topo_node_resource(tn, &fmri, &err) < 0 ||
	    fmri == NULL) {
		topo_mod_dprintf(mp, "FRU_fmri_set error: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		return (topo_mod_seterrno(mp, err));
	}
	e = topo_node_fru_set(tn, fmri, 0, &err);
	nvlist_free(fmri);
	if (e < 0)
		return (topo_mod_seterrno(mp, err));
	return (0);
}

tnode_t *
find_predecessor(tnode_t *tn, char *mod_name)
{
	tnode_t *pnode = topo_node_parent(tn);

	while (pnode && (strcmp(topo_node_name(pnode), mod_name) != 0)) {
		pnode = topo_node_parent(pnode);
	}
	return (pnode);
}

static int
use_predecessor_fru(tnode_t *tn, char *mod_name)
{
	tnode_t *pnode = NULL;
	nvlist_t *fru = NULL;
	int err = 0;

	if ((pnode = find_predecessor(tn, mod_name)) == NULL)
		return (-1);
	if ((pnode = topo_node_parent(pnode)) == NULL)
		return (-1);
	if (topo_node_fru(pnode, &fru, NULL, &err) != 0)
		return (-1);

	(void) topo_node_fru_set(tn, fru, 0, &err);
	nvlist_free(fru);

	return (0);
}

static int
use_predecessor_label(topo_mod_t *mod, tnode_t *tn, char *mod_name)
{
	tnode_t *pnode = NULL;
	int err = 0;
	char *plabel = NULL;

	if ((pnode = find_predecessor(tn, mod_name)) == NULL)
		return (-1);
	if ((pnode = topo_node_parent(pnode)) == NULL)
		return (-1);
	if (topo_node_label(pnode, &plabel, &err) != 0 || plabel == NULL)
		return (-1);

	(void) topo_node_label_set(tn, plabel, &err);

	topo_mod_strfree(mod, plabel);

	return (0);
}


/*ARGSUSED*/
static int
FRU_set(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	topo_mod_t *mp;
	char *nm;
	int e = 0, err = 0;

	nm = topo_node_name(tn);
	mp = did_mod(pd);

	/*
	 * If this is a PCIEX_BUS and its parent is a PCIEX_ROOT,
	 * check for a CPUBOARD predecessor.  If found, inherit its
	 * parent's FRU.  Otherwise, continue with FRU set.
	 */
	if ((strcmp(nm, PCIEX_BUS) == 0) &&
	    (strcmp(topo_node_name(topo_node_parent(tn)), PCIEX_ROOT) == 0)) {

		if (use_predecessor_fru(tn, CPUBOARD) == 0)
			return (0);
	}
	/*
	 * If this topology node represents something other than an
	 * ioboard or a device that implements a slot, inherit the
	 * parent's FRU value.  If there is no label, inherit our
	 * parent's FRU value.  Otherwise, munge up an fmri based on
	 * the label.
	 */
	if (strcmp(nm, IOBOARD) != 0 && strcmp(nm, PCI_DEVICE) != 0 &&
	    strcmp(nm, PCIEX_DEVICE) != 0 && strcmp(nm, PCIEX_BUS) != 0) {
		(void) topo_node_fru_set(tn, NULL, 0, &e);
		return (0);
	}

	/*
	 * If ioboard, set fru fmri to hc fmri
	 */
	if (strcmp(nm, IOBOARD) == 0) {
		e = FRU_fmri_set(mp, tn);
		return (e);
	} else if (strcmp(nm, PCI_DEVICE) == 0 ||
	    strcmp(nm, PCIEX_DEVICE) == 0 || strcmp(nm, PCIEX_BUS) == 0) {
		nvlist_t *in, *out;

		mp = did_mod(pd);
		if (topo_mod_nvalloc(mp, &in, NV_UNIQUE_NAME) != 0)
			return (topo_mod_seterrno(mp, EMOD_FMRI_NVL));
		if (nvlist_add_uint64(in, "nv1", (uintptr_t)pd) != 0) {
			nvlist_free(in);
			return (topo_mod_seterrno(mp, EMOD_NOMEM));
		}
		if (topo_method_invoke(tn,
		    TOPO_METH_FRU_COMPUTE, TOPO_METH_FRU_COMPUTE_VERSION,
		    in, &out, &err) != 0) {
			nvlist_free(in);
			return (topo_mod_seterrno(mp, err));
		}
		nvlist_free(in);
		(void) topo_node_fru_set(tn, out, 0, &err);
		nvlist_free(out);
	} else
		(void) topo_node_fru_set(tn, NULL, 0, &err);

	return (0);
}

/*ARGSUSED*/
static int
label_set(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	topo_mod_t *mp;
	nvlist_t *in, *out;
	char *label;
	int err;

	mp = did_mod(pd);
	/*
	 * If this is a PCIEX_BUS and its parent is a PCIEX_ROOT,
	 * check for a CPUBOARD predecessor.  If found, inherit its
	 * parent's Label.  Otherwise, continue with label set.
	 */
	if ((strcmp(topo_node_name(tn), PCIEX_BUS) == 0) &&
	    (strcmp(topo_node_name(topo_node_parent(tn)), PCIEX_ROOT) == 0)) {

		if (use_predecessor_label(mp, tn, CPUBOARD) == 0)
			return (0);
	}
	if (topo_mod_nvalloc(mp, &in, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mp, EMOD_FMRI_NVL));
	if (nvlist_add_uint64(in, TOPO_METH_LABEL_ARG_NVL, (uintptr_t)pd) !=
	    0) {
		nvlist_free(in);
		return (topo_mod_seterrno(mp, EMOD_NOMEM));
	}
	if (topo_method_invoke(tn,
	    TOPO_METH_LABEL, TOPO_METH_LABEL_VERSION, in, &out, &err) != 0) {
		nvlist_free(in);
		return (topo_mod_seterrno(mp, err));
	}
	nvlist_free(in);
	if (out != NULL &&
	    nvlist_lookup_string(out, TOPO_METH_LABEL_RET_STR, &label) == 0) {
		if (topo_prop_set_string(tn, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_LABEL, TOPO_PROP_IMMUTABLE, label, &err) != 0) {
			nvlist_free(out);
			return (topo_mod_seterrno(mp, err));
		}
		nvlist_free(out);
	}
	return (0);
}

/*ARGSUSED*/
static int
EXCAP_set(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	int excap = did_excap(pd);
	int err;
	int e = 0;

	switch (excap & PCIE_PCIECAP_DEV_TYPE_MASK) {
	case PCIE_PCIECAP_DEV_TYPE_ROOT:
		e = topo_prop_set_string(tn, TOPO_PGROUP_PCI,
		    TOPO_PCI_EXCAP, TOPO_PROP_IMMUTABLE, PCIEX_ROOT, &err);
		break;
	case PCIE_PCIECAP_DEV_TYPE_UP:
		e = topo_prop_set_string(tn, TOPO_PGROUP_PCI,
		    TOPO_PCI_EXCAP, TOPO_PROP_IMMUTABLE, PCIEX_SWUP, &err);
		break;
	case PCIE_PCIECAP_DEV_TYPE_DOWN:
		e = topo_prop_set_string(tn, TOPO_PGROUP_PCI,
		    TOPO_PCI_EXCAP, TOPO_PROP_IMMUTABLE, PCIEX_SWDWN, &err);
		break;
	case PCIE_PCIECAP_DEV_TYPE_PCI2PCIE:
		e = topo_prop_set_string(tn, TOPO_PGROUP_PCI,
		    TOPO_PCI_EXCAP, TOPO_PROP_IMMUTABLE, PCIEX_BUS, &err);
		break;
	case PCIE_PCIECAP_DEV_TYPE_PCIE2PCI:
		e = topo_prop_set_string(tn, TOPO_PGROUP_PCI,
		    TOPO_PCI_EXCAP, TOPO_PROP_IMMUTABLE, PCI_BUS, &err);
		break;
	case PCIE_PCIECAP_DEV_TYPE_PCIE_DEV:
		e = topo_prop_set_string(tn, TOPO_PGROUP_PCI,
		    TOPO_PCI_EXCAP, TOPO_PROP_IMMUTABLE, PCIEX_DEVICE, &err);
		break;
	}
	if (e != 0)
		return (topo_mod_seterrno(did_mod(pd), err));
	return (0);
}

/*ARGSUSED*/
static int
DEVprop_set(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	topo_mod_t *mp;
	char *dnpath;
	char *path, *fpath;
	int d, f;
	int err, e;

	mp = did_mod(pd);
	if ((dnpath = di_devfs_path(did_dinode(pd))) == NULL) {
		topo_mod_dprintf(mp, "NULL di_devfs_path.\n");
		return (topo_mod_seterrno(mp, ETOPO_PROP_NOENT));
	}
	if ((path = topo_mod_strdup(mp, dnpath)) == NULL) {
		di_devfs_path_free(dnpath);
		return (-1);
	}
	di_devfs_path_free(dnpath);

	/* The DEV path is modified for hostbridges */
	if (strcmp(topo_node_name(tn), HOSTBRIDGE) == 0) {
		fpath = dev_for_hostbridge(did_mod(pd), path);
	} else {
		did_BDF(pd, NULL, &d, &f);
		fpath = dev_path_fix(mp, path, d, f);
	}
	if (fpath == NULL)
		return (-1);
	e = topo_prop_set_string(tn,
	    tpgrp, tpnm, TOPO_PROP_IMMUTABLE, fpath, &err);
	topo_mod_strfree(mp, fpath);
	if (e != 0)
		return (topo_mod_seterrno(mp, err));
	return (0);
}

/*ARGSUSED*/
static int
DRIVERprop_set(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	char *dnm;
	int err;

	if ((dnm = di_driver_name(did_dinode(pd))) == NULL)
		return (0);
	if (topo_prop_set_string(tn,
	    tpgrp, tpnm, TOPO_PROP_IMMUTABLE, dnm, &err) < 0)
		return (topo_mod_seterrno(did_mod(pd), err));

	return (0);
}

/*ARGSUSED*/
static int
MODULEprop_set(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	nvlist_t *mod;
	topo_mod_t *mp;
	char *dnm;
	int err;

	if ((dnm = di_driver_name(did_dinode(pd))) == NULL)
		return (0);

	mp = did_mod(pd);
	if ((mod = topo_mod_modfmri(mp, FM_MOD_SCHEME_VERSION, dnm)) == NULL)
		return (0); /* driver maybe detached, return success */

	if (topo_prop_set_fmri(tn, tpgrp, tpnm, TOPO_PROP_IMMUTABLE, mod,
	    &err) < 0) {
		nvlist_free(mod);
		return (topo_mod_seterrno(mp, err));
	}
	nvlist_free(mod);

	return (0);
}

/*ARGSUSED*/
static int
maybe_di_chars_copy(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	topo_mod_t *mp;
	uchar_t *typbuf;
	char *tmpbuf;
	int sz = -1;
	int err, e;

	if (di_bytes_get(did_mod(pd), did_dinode(pd), dpnm, &sz, &typbuf) < 0)
		return (0);
	mp = did_mod(pd);

	if ((tmpbuf = topo_mod_alloc(mp, sz + 1)) == NULL)
		return (topo_mod_seterrno(mp, EMOD_NOMEM));

	bcopy(typbuf, tmpbuf, sz);
	tmpbuf[sz] = 0;
	e = topo_prop_set_string(tn,
	    tpgrp, tpnm, TOPO_PROP_IMMUTABLE, tmpbuf, &err);
	topo_mod_free(mp, tmpbuf, sz + 1);
	if (e != 0)
		return (topo_mod_seterrno(mp, err));
	return (0);
}

static int
uint_to_strprop(topo_mod_t *mp, uint_t v, tnode_t *tn,
    const char *tpgrp, const char *tpnm)
{
	char str[21]; /* sizeof (UINT64_MAX) + '\0' */
	int e;

	(void) snprintf(str, 21, "%x", v);
	if (topo_prop_set_string(tn,
	    tpgrp, tpnm, TOPO_PROP_IMMUTABLE, str, &e) < 0)
		return (topo_mod_seterrno(mp, e));
	return (0);
}

static int
maybe_di_uint_to_str(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	uint_t v;

	if (di_uintprop_get(did_mod(pd), did_dinode(pd), dpnm, &v) < 0)
		return (0);

	return (uint_to_strprop(did_mod(pd), v, tn, tpgrp, tpnm));
}

static int
uint_to_dec_strprop(topo_mod_t *mp, uint_t v, tnode_t *tn,
    const char *tpgrp, const char *tpnm)
{
	char str[21]; /* sizeof (UINT64_MAX) + '\0' */
	int e;

	(void) snprintf(str, 21, "%d", v);
	if (topo_prop_set_string(tn,
	    tpgrp, tpnm, TOPO_PROP_IMMUTABLE, str, &e) < 0)
		return (topo_mod_seterrno(mp, e));
	return (0);
}

static int
maybe_di_uint_to_dec_str(tnode_t *tn, did_t *pd,
    const char *dpnm, const char *tpgrp, const char *tpnm)
{
	uint_t v;

	if (di_uintprop_get(did_mod(pd), did_dinode(pd), dpnm, &v) < 0)
		return (0);

	return (uint_to_dec_strprop(did_mod(pd), v, tn, tpgrp, tpnm));
}

static int
AADDR_set(tnode_t *tn, did_t *pd, const char *dpnm, const char *tpgrp,
    const char *tpnm)
{
	topo_mod_t *mp;
	uchar_t *typbuf;
	int sz = -1;
	int err, e;

	if (di_bytes_get(did_mod(pd), did_dinode(pd), dpnm, &sz, &typbuf) < 0)
		return (0);

	mp = did_mod(pd);

	e = topo_prop_set_uint32_array(tn, tpgrp, tpnm, TOPO_PROP_IMMUTABLE,
	    /*LINTED*/
	    (uint32_t *)typbuf, sz/4, &err);

	if (e != 0)
		return (topo_mod_seterrno(mp, err));
	return (0);
}

/*ARGSUSED*/
static int
BDF_set(tnode_t *tn, did_t *pd, const char *dpnm, const char *tpgrp,
    const char *tpnm)
{
	int bdf;
	char str[23]; /* '0x' + sizeof (UINT64_MAX) + '\0' */
	int e;

	if ((bdf = did_bdf(pd)) <= 0)
		return (0);

	(void) snprintf(str, 23, "0x%x", bdf);
	if (topo_prop_set_string(tn,
	    tpgrp, tpnm, TOPO_PROP_IMMUTABLE, str, &e) < 0)
		return (topo_mod_seterrno(did_mod(pd), e));
	return (0);
}

/*ARGSUSED*/
static int
maybe_pcidb_set(tnode_t *tn, did_t *pd, const char *dpnm, const char *tpgrp,
    const char *tpnm)
{
	const char *vname, *dname = NULL, *ssname = NULL;
	uint_t vid, pid, svid, ssid;
	pcidb_vendor_t *pciv;
	pcidb_device_t *pcid;
	pcidb_subvd_t *pcis = NULL;
	pcidb_hdl_t *pcih;
	topo_mod_t *mod = did_mod(pd);
	int err;

	/*
	 * At a minimum, we need the vid/devid of the device to be able to
	 * lookup anything in the PCI database.  So if we fail to look either
	 * of those up, bail out.
	 */
	if (di_uintprop_get(did_mod(pd), did_dinode(pd), DI_VENDIDPROP, &vid) <
	    0 || di_uintprop_get(did_mod(pd), did_dinode(pd), DI_DEVIDPROP,
	    &pid) < 0) {
		return (0);
	}
	/*
	 * If we fail to lookup the vendor, by the vid that's also a
	 * deal-breaker.
	 */
	if ((pcih = topo_mod_pcidb(mod)) == NULL ||
	    (pciv = pcidb_lookup_vendor(pcih, vid)) == NULL) {
		return (0);
	}

	/* lookup vendor-name and set the topo property, if found */
	vname = pcidb_vendor_name(pciv);
	if (vname != NULL &&
	    topo_prop_set_string(tn, tpgrp, TOPO_PCI_VENDNM,
	    TOPO_PROP_IMMUTABLE, vname, &err) != 0) {
		return (topo_mod_seterrno(mod, err));
	}

	/* lookup device-name and set the topo property, if found */
	if ((pcid = pcidb_lookup_device_by_vendor(pciv, pid)) != NULL) {
		dname = pcidb_device_name(pcid);
	}
	if (dname != NULL &&
	    topo_prop_set_string(tn, tpgrp, TOPO_PCI_DEVNM,
	    TOPO_PROP_IMMUTABLE, dname, &err) != 0) {
		return (topo_mod_seterrno(mod, err));
	}

	/*
	 * Not all devices will have a subsystem-name that we can lookup,
	 * but if both subsystem-vendorid and subsystem-id exist in devinfo and
	 * if we were previously able to find the device by devid then we can
	 * at least attempt a lookup.  If found, set the topo property.
	 */
	if (pcid != NULL &&
	    di_uintprop_get(did_mod(pd), did_dinode(pd), DI_SUBVENDIDPROP,
	    &svid) == 0 &&
	    di_uintprop_get(did_mod(pd), did_dinode(pd), DI_SUBSYSTEMID,
	    &ssid) == 0) {
		pcis = pcidb_lookup_subvd_by_device(pcid, svid, ssid);
	}
	if (pcis != NULL) {
		ssname = pcidb_subvd_name(pcis);
	}
	if (ssname != NULL && strlen(ssname) > 0 &&
	    topo_prop_set_string(tn, tpgrp, TOPO_PCI_SUBSYSNM,
	    TOPO_PROP_IMMUTABLE, ssname, &err) != 0) {
		return (topo_mod_seterrno(mod, err));
	}
	return (0);
}

int
did_props_set(tnode_t *tn, did_t *pd, txprop_t txarray[], int txnum)
{
	topo_mod_t *mp;
	int i, r, e;

	mp = did_mod(pd);
	for (i = 0; i < txnum; i++) {
		/*
		 * Ensure the property group has been created.
		 */
		if (txarray[i].tx_tpgroup != NULL) {
			if (topo_pgroup_create(tn, txarray[i].tx_tpgroup, &e)
			    < 0) {
				if (e != ETOPO_PROP_DEFD)
					return (topo_mod_seterrno(mp, e));
			}
		}

		topo_mod_dprintf(mp,
		    "Setting property %s in group %s.\n",
		    txarray[i].tx_tprop, txarray[i].tx_tpgroup->tpi_name);
		r = txarray[i].tx_xlate(tn, pd,
		    txarray[i].tx_diprop, txarray[i].tx_tpgroup->tpi_name,
		    txarray[i].tx_tprop);
		if (r != 0) {
			topo_mod_dprintf(mp, "failed.\n");
			topo_mod_dprintf(mp, "Error was %s.\n",
			    topo_strerror(topo_mod_errno(mp)));
			return (-1);
		}
		topo_mod_dprintf(mp, "succeeded.\n");
	}
	return (0);
}
