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
 * Portions Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2008, Intel Corporation.
 * All rights reserved.
 */


#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/list.h>
#include <sys/pci.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_impl.h>
#include <sys/sunndi.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/bootconf.h>
#include <sys/int_fmtio.h>
#include <sys/dmar_acpi.h>
#include <sys/smbios.h>
#include <sys/iommulib.h>

/*
 * the following pci manipulate function pinter
 * are defined in pci_cfgspace.h
 */
#define	pci_getb	(*pci_getb_func)

/*
 * define for debug
 */
int intel_dmar_acpi_debug = 0;
#define	dcmn_err	if (intel_dmar_acpi_debug) cmn_err

/*
 * define for printing blacklist ID
 */
int intel_iommu_blacklist_id;

/*
 * global varables
 */
boolean_t intel_iommu_support;
intel_dmar_info_t *dmar_info;

/*
 * global varables to save source id and drhd info for ioapic
 * to support interrupt remapping
 */
list_t	ioapic_drhd_infos;

/*
 * internal varables
 */
static void *dmart;

/*
 * helper functions to release the allocated resources
 * when failed
 */
static void
release_dev_scope(list_t *lp)
{
	pci_dev_scope_t *devs;

	if (list_is_empty(lp))
		return;

	while ((devs = list_head(lp)) != NULL) {
		list_remove(lp, devs);
		kmem_free(devs, sizeof (pci_dev_scope_t));
	}
}

static void
release_drhd_info(void)
{
	drhd_info_t *drhd;
	list_t *lp;
	int i;

	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {
		lp = &dmar_info->dmari_drhd[i];
		if (list_is_empty(lp))
			break;

		while ((drhd = list_head(lp)) != NULL) {
			list_remove(lp, drhd);

			/*
			 * release the device scope
			 */
			release_dev_scope(&drhd->di_dev_list);
			list_destroy(&drhd->di_dev_list);
			kmem_free(drhd, sizeof (drhd_info_t));
		}
	}
}

static void
release_rmrr_info(void)
{
	rmrr_info_t *rmrr;
	list_t *lp;
	int i;

	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {
		lp = &dmar_info->dmari_rmrr[i];
		if (list_is_empty(lp))
			break;

		while ((rmrr = list_head(lp)) != NULL) {
			list_remove(lp, rmrr);
			release_dev_scope(&rmrr->ri_dev_list);
			list_destroy(&rmrr->ri_dev_list);
			kmem_free(rmrr, sizeof (rmrr_info_t));
		}
	}
}

/*
 * intel_iommu_release_dmar_info()
 *   global function, which is called to release dmar_info
 *   when the dmar_intel_iommu_supportinfo is not
 *   needed any more.
 */
void
intel_iommu_release_dmar_info(void)
{
	int i;

	intel_iommu_support = B_FALSE;
	release_drhd_info();
	release_rmrr_info();

	/*
	 * destroy the drhd and rmrr list
	 */
	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {
		list_destroy(&dmar_info->dmari_drhd[i]);
		list_destroy(&dmar_info->dmari_rmrr[i]);
	}

	kmem_free(dmar_info, sizeof (intel_dmar_info_t));
}

/*
 * create_dmar_devi()
 *
 *   create the dev_info node in the device tree,
 *   the info node is a nuxus child of the root
 *   nexus
 */
static void
create_dmar_devi(void)
{
	dev_info_t *dip;
	drhd_info_t *drhd;
	struct regspec reg;
	struct ddi_parent_private_data *pdptr;
	char nodename[64];
	int i, j;

	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {

		/*
		 * ignore the empty list
		 */
		if (list_is_empty(&dmar_info->dmari_drhd[i]))
			break;

		/*
		 * alloc dev_info per drhd unit
		 */
		j = 0;
		for_each_in_list(&dmar_info->dmari_drhd[i], drhd) {
			(void) snprintf(nodename, sizeof (nodename),
			    "dmar%d,%d", drhd->di_segment, j++);
			ndi_devi_alloc_sleep(ddi_root_node(), nodename,
			    DEVI_SID_NODEID, &dip);
			drhd->di_dip = dip;
			reg.regspec_bustype = 0;
			reg.regspec_addr = drhd->di_reg_base;
			reg.regspec_size = IOMMU_REG_SIZE;

			/*
			 * update the reg properties
			 *
			 *   reg property will be used for register
			 *   set access
			 *
			 * refer to the bus_map of root nexus driver
			 * I/O or memory mapping:
			 *
			 * <bustype=0, addr=x, len=x>: memory
			 * <bustype=1, addr=x, len=x>: i/o
			 * <bustype>1, addr=0, len=x>: x86-compatibility i/o
			 */
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
			    dip, "reg", (int *)&reg,
			    sizeof (struct regspec) / sizeof (int));

			pdptr = (struct ddi_parent_private_data *)
			    kmem_zalloc(sizeof (struct ddi_parent_private_data)
			    + sizeof (struct regspec), KM_SLEEP);
			pdptr->par_nreg = 1;
			pdptr->par_reg = (struct regspec *)(pdptr + 1);
			pdptr->par_reg->regspec_bustype = 0;
			pdptr->par_reg->regspec_addr = drhd->di_reg_base;
			pdptr->par_reg->regspec_size = IOMMU_REG_SIZE;
			ddi_set_parent_data(dip, pdptr);
		}
	}
}

/*
 * parse_dmar_dev_scope()
 *   parse the device scope attached to drhd or rmrr
 */
static int
parse_dmar_dev_scope(dmar_acpi_dev_scope_t *scope, pci_dev_scope_t **devs)
{
	int depth;
	int bus, dev, func;
	pci_dev_scope_t *entry;

	struct path_to_dev {
		uint8_t device;
		uint8_t function;
	} *path;

	path = (struct path_to_dev *)(scope + 1);
	depth = (scope->ds_length - 6)/2;
	bus = scope->ds_sbusnum;
	dev = path->device;
	func = path->function;

	while (--depth) {
		path++;
		bus = pci_getb(bus, dev, func, PCI_BCNF_SECBUS);
		dev = path->device;
		func = path->function;
	}

	entry = (pci_dev_scope_t *)kmem_zalloc(
	    sizeof (pci_dev_scope_t), KM_SLEEP);
	entry->pds_bus = bus;
	entry->pds_dev = dev;
	entry->pds_func = func;
	entry->pds_type = scope->ds_type;

	*devs = entry;
	return (PARSE_DMAR_SUCCESS);
}

/*
 * parse_dmar_rmrr()
 *   parse the rmrr units in dmar table
 */
static int
parse_dmar_rmrr(dmar_acpi_unit_head_t *head)
{
	dmar_acpi_rmrr_t *rmrr;
	rmrr_info_t *rinfo;
	dmar_acpi_dev_scope_t *scope;
	pci_dev_scope_t *devs;

	rmrr = (dmar_acpi_rmrr_t *)head;
	ASSERT(head->uh_type == DMAR_UNIT_TYPE_RMRR);
	ASSERT(rmrr->rm_segment <= DMAR_MAX_SEGMENT);

	/*
	 * for each rmrr, limiaddr must > baseaddr
	 */
	if (rmrr->rm_baseaddr >= rmrr->rm_limiaddr) {
		cmn_err(CE_NOTE, "Invalid BIOS RMRR: Disabling Intel IOMMU");
		cmn_err(CE_WARN, "!invalid rmrr,"
		    " baseaddr = 0x%" PRIx64
		    ", limiaddr = 0x%" PRIx64 "",
		    rmrr->rm_baseaddr, rmrr->rm_limiaddr);
		return (PARSE_DMAR_FAIL);
	}

	/*
	 * allocate and setup the device info structure
	 */
	rinfo = (rmrr_info_t *)kmem_zalloc(sizeof (rmrr_info_t),
	    KM_SLEEP);
	rinfo->ri_segment = rmrr->rm_segment;
	rinfo->ri_baseaddr = rmrr->rm_baseaddr;
	rinfo->ri_limiaddr = rmrr->rm_limiaddr;
	list_create(&rinfo->ri_dev_list, sizeof (pci_dev_scope_t),
	    offsetof(pci_dev_scope_t, node));

	/*
	 * parse the device scope
	 */
	scope = (dmar_acpi_dev_scope_t *)(rmrr + 1);
	while ((unsigned long)scope < ((unsigned long)rmrr + head->uh_length)) {
		if (parse_dmar_dev_scope(scope, &devs)
		    != PARSE_DMAR_SUCCESS) {
			return (PARSE_DMAR_FAIL);
		}

		list_insert_tail(&rinfo->ri_dev_list, devs);
		scope = (dmar_acpi_dev_scope_t *)((unsigned long)scope
		    + scope->ds_length);
	}

	/*
	 * save this info structure
	 */
	list_insert_tail(&dmar_info->dmari_rmrr[rinfo->ri_segment], rinfo);
	return (PARSE_DMAR_SUCCESS);
}

/*
 * parse_dmar_drhd()
 *   parse the drhd uints in dmar table
 */
static int
parse_dmar_drhd(dmar_acpi_unit_head_t *head)
{
	dmar_acpi_drhd_t *drhd;
	drhd_info_t *dinfo;
	dmar_acpi_dev_scope_t *scope;
	list_t *lp;
	pci_dev_scope_t *devs;
	ioapic_drhd_info_t	*ioapic_dinfo;

	drhd = (dmar_acpi_drhd_t *)head;
	ASSERT(head->uh_type == DMAR_UNIT_TYPE_DRHD);

	/*
	 * assert the segment boundary
	 */
	ASSERT(drhd->dr_segment <= DMAR_MAX_SEGMENT);

	/*
	 * allocate and setup the info structure
	 */
	dinfo = (drhd_info_t *)kmem_zalloc(sizeof (drhd_info_t), KM_SLEEP);
	dinfo->di_segment = drhd->dr_segment;
	dinfo->di_reg_base = drhd->dr_baseaddr;
	dinfo->di_include_all = (drhd->dr_flags & INCLUDE_PCI_ALL) ?
	    B_TRUE : B_FALSE;
	list_create(&dinfo->di_dev_list, sizeof (pci_dev_scope_t),
	    offsetof(pci_dev_scope_t, node));

	/*
	 * parse the device scope
	 */
	scope = (dmar_acpi_dev_scope_t *)(drhd + 1);
	while ((unsigned long)scope < ((unsigned long)drhd +
	    head->uh_length)) {

		if (parse_dmar_dev_scope(scope, &devs)
		    != PARSE_DMAR_SUCCESS) {
			return (PARSE_DMAR_FAIL);
		}
		/* get ioapic source id for interrupt remapping */
		if (devs->pds_type == DEV_SCOPE_IOAPIC) {
			ioapic_dinfo = kmem_zalloc
			    (sizeof (ioapic_drhd_info_t), KM_SLEEP);

			ioapic_dinfo->ioapic_id = scope->ds_enumid;
			ioapic_dinfo->sid =
			    (devs->pds_bus << 8) |
			    (devs->pds_dev << 3) |
			    (devs->pds_func);
			ioapic_dinfo->drhd = dinfo;
			list_insert_tail(&ioapic_drhd_infos, ioapic_dinfo);
		}

		list_insert_tail(&dinfo->di_dev_list, devs);
		scope = (dmar_acpi_dev_scope_t *)((unsigned long)scope +
		    scope->ds_length);
	}

	lp = &dmar_info->dmari_drhd[dinfo->di_segment];
	list_insert_tail(lp, dinfo);
	return (PARSE_DMAR_SUCCESS);
}

#define	OEMID_OFF	10
#define	OEMID_LEN	6
#define	OEM_TBLID_OFF	16
#define	OEM_TBLID_LEN	8
#define	OEMREV_OFF	24
#define	OEMREV_LEN	4

static int
dmar_blacklisted(caddr_t dmart)
{
	char oemid[OEMID_LEN + 1] = {0};
	char oem_tblid[OEM_TBLID_LEN + 1] = {0};
	char oemrev[OEMREV_LEN + 1] = {0};
	const char *mfgr = "?";
	const char *product = "?";
	const char *version = "?";
	smbios_info_t smbios_info;
	smbios_system_t smbios_sys;
	id_t id;
	char **blacklist;
	int i;
	uint_t n;

	(void) strncpy(oemid, dmart + OEMID_OFF, OEMID_LEN);
	(void) strncpy(oem_tblid, dmart + OEM_TBLID_OFF, OEM_TBLID_LEN);
	(void) strncpy(oemrev, dmart + OEMREV_OFF, OEMREV_LEN);

	iommulib_smbios = smbios_open(NULL, SMB_VERSION, ksmbios_flags,
	    NULL);
	if (iommulib_smbios &&
	    (id = smbios_info_system(iommulib_smbios, &smbios_sys))
	    != SMB_ERR &&
	    smbios_info_common(iommulib_smbios, id, &smbios_info)
	    != SMB_ERR) {
		mfgr = smbios_info.smbi_manufacturer;
		product = smbios_info.smbi_product;
		version = smbios_info.smbi_version;
	}

	if (intel_iommu_blacklist_id) {
		cmn_err(CE_NOTE, "SMBIOS ID:");
		cmn_err(CE_NOTE, "Manufacturer = <%s>", mfgr);
		cmn_err(CE_NOTE, "Product = <%s>", product);
		cmn_err(CE_NOTE, "Version = <%s>", version);
		cmn_err(CE_NOTE, "DMAR ID:");
		cmn_err(CE_NOTE, "oemid = <%s>", oemid);
		cmn_err(CE_NOTE, "oemtblid = <%s>", oem_tblid);
		cmn_err(CE_NOTE, "oemrev = <%s>", oemrev);
	}

	/*
	 * Fake up a dev_t since searching global prop list needs it
	 */
	if (ddi_prop_lookup_string_array(
	    makedevice(ddi_name_to_major("rootnex"), 0), ddi_root_node(),
	    DDI_PROP_DONTPASS | DDI_PROP_ROOTNEX_GLOBAL,
	    "intel-iommu-blacklist", &blacklist, &n) != DDI_PROP_SUCCESS) {
		/* No blacklist */
		return (0);
	}

	if (n < 4 || n % 4 != 0) {
		cmn_err(CE_WARN,
		    "invalid Intel IOMMU blacklist: not a multiple of four");
		ddi_prop_free(blacklist);
		return (0);
	}

	for (i = 0; i < n; i += 4) {
		if (strcmp(blacklist[i], "SMBIOS") == 0 &&
		    strcmp(blacklist[i+1], mfgr) == 0 &&
		    (blacklist[i+2][0] == '\0' ||
		    strcmp(blacklist[i+2], product) == 0) &&
		    (blacklist[i+3][0] == '\0' ||
		    strcmp(blacklist[i+3], version) == 0)) {
			ddi_prop_free(blacklist);
			return (1);
		}
		if (strcmp(blacklist[i], "DMAR") == 0 &&
		    strcmp(blacklist[i+1], oemid) == 0 &&
		    (blacklist[i+2][0] == '\0' ||
		    strcmp(blacklist[i+2], oem_tblid) == 0) &&
		    (blacklist[i+3][0] == '\0' ||
		    strcmp(blacklist[i+3], oemrev) == 0)) {
			ddi_prop_free(blacklist);
			return (1);
		}
	}

	ddi_prop_free(blacklist);

	return (0);
}

/*
 * parse_dmar()
 *   parse the dmar table
 */
static int
parse_dmar(void)
{
	dmar_acpi_head_t *dmar_head;
	dmar_acpi_unit_head_t *unit_head;
	drhd_info_t *drhd;
	int i;

	dmar_head = (dmar_acpi_head_t *)dmart;

	/*
	 * do a sanity check
	 */
	if (!dmar_head || strncmp(dmar_head->dh_sig, "DMAR", 4)) {
		dcmn_err(CE_CONT, "wrong DMAR signature: %c%c%c%c",
		    dmar_head->dh_sig[0], dmar_head->dh_sig[1],
		    dmar_head->dh_sig[2], dmar_head->dh_sig[3]);
		return (PARSE_DMAR_FAIL);
	}

	if (dmar_blacklisted(dmart)) {
		cmn_err(CE_NOTE, "Intel IOMMU is blacklisted on this platform");
		return (PARSE_DMAR_FAIL);
	}

	dmar_info->dmari_haw = dmar_head->dh_haw + 1;
	dmar_info->dmari_intr_remap = dmar_head->dh_flags & 0x1 ?
	    B_TRUE : B_FALSE;

	/*
	 * parse each unit
	 *    only DRHD and RMRR are parsed, others are ignored
	 */
	unit_head = (dmar_acpi_unit_head_t *)(dmar_head + 1);
	while ((unsigned long)unit_head < (unsigned long)dmar_head +
	    dmar_head->dh_len) {
		switch (unit_head->uh_type) {
		case DMAR_UNIT_TYPE_DRHD:
			if (parse_dmar_drhd(unit_head) !=
			    PARSE_DMAR_SUCCESS) {

				/*
				 * iommu_detect_parse() will release
				 * all drhd info structure, just
				 * return false here
				 */
				return (PARSE_DMAR_FAIL);
			}
			break;
		case DMAR_UNIT_TYPE_RMRR:
			if (parse_dmar_rmrr(unit_head) !=
			    PARSE_DMAR_SUCCESS)
				return (PARSE_DMAR_FAIL);
			break;
		default:
			cmn_err(CE_WARN,
			    "unit type %d ignored\n", unit_head->uh_type);
		}
		unit_head = (dmar_acpi_unit_head_t *)
		    ((unsigned long)unit_head +
		    unit_head->uh_length);
	}

#ifdef	DEBUG
	/*
	 * make sure the include_all drhd is the
	 * last drhd in the list, this is only for
	 * debug
	 */
	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {
		if (list_is_empty(&dmar_info->dmari_drhd[i]))
			break;

		for_each_in_list(&dmar_info->dmari_drhd[i], drhd) {
			if (drhd->di_include_all &&
			    list_next(&dmar_info->dmari_drhd[i], drhd)
			    != NULL) {
				list_remove(&dmar_info->dmari_drhd[i], drhd);
				list_insert_tail(&dmar_info->dmari_drhd[i],
				    drhd);
				dcmn_err(CE_CONT,
				    "include_all drhd is adjusted\n");
			}
		}
	}
#endif

	return (PARSE_DMAR_SUCCESS);
}

/*
 * detect_dmar()
 *   detect the dmar acpi table
 */
static boolean_t
detect_dmar(void)
{
	int len;
	char *intel_iommu;
	char *enable;

	/*
	 * if "intel-iommu = no" boot property is set,
	 * ignore intel iommu
	 */
	if ((len = do_bsys_getproplen(NULL, "intel-iommu")) > 0) {
		intel_iommu = kmem_alloc(len, KM_SLEEP);
		(void) do_bsys_getprop(NULL, "intel-iommu", intel_iommu);
		if (strcmp(intel_iommu, "no") == 0) {
			dcmn_err(CE_CONT, "\"intel-iommu=no\" was set\n");
			kmem_free(intel_iommu, len);
			return (B_FALSE);
		}
		kmem_free(intel_iommu, len);
	}

	/*
	 * Check rootnex.conf for enable/disable IOMMU
	 * Fake up a dev_t since searching global prop list needs it
	 */
	if (ddi_prop_lookup_string(
	    makedevice(ddi_name_to_major("rootnex"), 0), ddi_root_node(),
	    DDI_PROP_DONTPASS | DDI_PROP_ROOTNEX_GLOBAL,
	    "intel-iommu", &enable) == DDI_PROP_SUCCESS) {
		if (strcmp(enable, "false") == 0 || strcmp(enable, "no") == 0) {
			dcmn_err(CE_CONT,
			    "\"intel-iommu=no\" set in rootnex.conf\n");
			ddi_prop_free(enable);
			return (B_FALSE);
		}
		ddi_prop_free(enable);
	}

	/*
	 * get dmar-table from system properties
	 */
	if ((len = do_bsys_getproplen(NULL, DMAR_TABLE_PROPNAME)) <= 0) {
		dcmn_err(CE_CONT, "dmar-table getprop failed\n");
		return (B_FALSE);
	}
	dcmn_err(CE_CONT, "dmar-table length = %d\n", len);
	dmart = kmem_alloc(len, KM_SLEEP);
	(void) do_bsys_getprop(NULL, DMAR_TABLE_PROPNAME, dmart);

	return (B_TRUE);
}

/*
 * print dmar_info for debug
 */
static void
print_dmar_info(void)
{
	drhd_info_t *drhd;
	rmrr_info_t *rmrr;
	pci_dev_scope_t *dev;
	int i;

	/* print the title */
	cmn_err(CE_CONT, "dmar_info->:\n");
	cmn_err(CE_CONT, "\thaw = %d\n", dmar_info->dmari_haw);
	cmn_err(CE_CONT, "\tintr_remap = %d\n",
	    dmar_info->dmari_intr_remap ? 1 : 0);

	/* print drhd info list */
	cmn_err(CE_CONT, "\ndrhd list:\n");
	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {
		if (list_is_empty(&dmar_info->dmari_drhd[i]))
			break;
		for (drhd = list_head(&dmar_info->dmari_drhd[i]);
		    drhd != NULL; drhd = list_next(&dmar_info->dmari_drhd[i],
		    drhd)) {
			cmn_err(CE_CONT, "\n\tsegment = %d\n",
			    drhd->di_segment);
			cmn_err(CE_CONT, "\treg_base = 0x%" PRIx64 "\n",
			    drhd->di_reg_base);
			cmn_err(CE_CONT, "\tinclude_all = %s\n",
			    drhd->di_include_all ? "yes" : "no");
			cmn_err(CE_CONT, "\tdip = 0x%p\n",
			    (void *)drhd->di_dip);
			cmn_err(CE_CONT, "\tdevice list:\n");
			for (dev = list_head(&drhd->di_dev_list);
			    dev != NULL; dev = list_next(&drhd->di_dev_list,
			    dev)) {
				cmn_err(CE_CONT, "\n\t\tbus = %d\n",
				    dev->pds_bus);
				cmn_err(CE_CONT, "\t\tdev = %d\n",
				    dev->pds_dev);
				cmn_err(CE_CONT, "\t\tfunc = %d\n",
				    dev->pds_func);
				cmn_err(CE_CONT, "\t\ttype = %d\n",
				    dev->pds_type);
			}
		}
	}

	/* print rmrr info list */
	cmn_err(CE_CONT, "\nrmrr list:\n");
	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {
		if (list_is_empty(&dmar_info->dmari_rmrr[i]))
			break;
		for (rmrr = list_head(&dmar_info->dmari_rmrr[i]);
		    rmrr != NULL; rmrr = list_next(&dmar_info->dmari_rmrr[i],
		    rmrr)) {
			cmn_err(CE_CONT, "\n\tsegment = %d\n",
			    rmrr->ri_segment);
			cmn_err(CE_CONT, "\tbaseaddr = 0x%" PRIx64 "\n",
			    rmrr->ri_baseaddr);
			cmn_err(CE_CONT, "\tlimiaddr = 0x%" PRIx64 "\n",
			    rmrr->ri_limiaddr);
			cmn_err(CE_CONT, "\tdevice list:\n");
			for (dev = list_head(&rmrr->ri_dev_list);
			    dev != NULL;
			    dev = list_next(&rmrr->ri_dev_list, dev)) {
				cmn_err(CE_CONT, "\n\t\tbus = %d\n",
				    dev->pds_bus);
				cmn_err(CE_CONT, "\t\tdev = %d\n",
				    dev->pds_dev);
				cmn_err(CE_CONT, "\t\tfunc = %d\n",
				    dev->pds_func);
				cmn_err(CE_CONT, "\t\ttype = %d\n",
				    dev->pds_type);
			}
		}
	}
}

/*
 * intel_iommu_probe_and_parse()
 *   called from rootnex driver
 */
void
intel_iommu_probe_and_parse(void)
{
	int i, len;
	char *opt;

	dmar_info = NULL;

	/*
	 * retrieve the print-dmar-acpi boot option
	 */
	if ((len = do_bsys_getproplen(NULL, "print-dmar-acpi")) > 0) {
		opt = kmem_alloc(len, KM_SLEEP);
		(void) do_bsys_getprop(NULL, "print-dmar-acpi", opt);
		if (strcmp(opt, "yes") == 0 ||
		    strcmp(opt, "true") == 0) {
			intel_dmar_acpi_debug = 1;
			cmn_err(CE_CONT, "\"print-dmar-acpi=true\" was set\n");
		} else if (strcmp(opt, "no") == 0 ||
		    strcmp(opt, "false") == 0) {
			intel_dmar_acpi_debug = 0;
			cmn_err(CE_CONT, "\"print-dmar-acpi=false\" was set\n");
		}
		kmem_free(opt, len);
	}

	/*
	 * retrieve the print-iommu-blacklist-id boot option
	 */
	if ((len = do_bsys_getproplen(NULL, "print-iommu-blacklist-id")) > 0) {
		opt = kmem_alloc(len, KM_SLEEP);
		(void) do_bsys_getprop(NULL, "print-iommu-blacklist-id", opt);
		if (strcmp(opt, "yes") == 0 ||
		    strcmp(opt, "true") == 0) {
			intel_iommu_blacklist_id = 1;
		} else if (strcmp(opt, "no") == 0 ||
		    strcmp(opt, "false") == 0) {
			intel_iommu_blacklist_id = 0;
		}
		kmem_free(opt, len);
	}


	dcmn_err(CE_CONT, "intel iommu detect start\n");

	if (detect_dmar() == B_FALSE) {
		dcmn_err(CE_CONT, "no intel iommu detected\n");
		return;
	}

	/*
	 * the platform has intel iommu, setup globals
	 */
	intel_iommu_support = B_TRUE;
	dmar_info = kmem_zalloc(sizeof (intel_dmar_info_t),
	    KM_SLEEP);
	for (i = 0; i < DMAR_MAX_SEGMENT; i++) {
		list_create(&(dmar_info->dmari_drhd[i]), sizeof (drhd_info_t),
		    offsetof(drhd_info_t, node));
		list_create(&(dmar_info->dmari_rmrr[i]), sizeof (rmrr_info_t),
		    offsetof(rmrr_info_t, node));
	}

	/* create ioapic - drhd map info for interrupt remapping */
	list_create(&ioapic_drhd_infos, sizeof (ioapic_drhd_info_t),
	    offsetof(ioapic_drhd_info_t, node));

	/*
	 * parse dmar acpi table
	 */
	if (parse_dmar() != PARSE_DMAR_SUCCESS) {
		intel_iommu_release_dmar_info();
		dcmn_err(CE_CONT, "DMAR parse failed\n");
		return;
	}

	/*
	 * create dev_info structure per hrhd
	 * and prepare it for binding driver
	 */
	create_dmar_devi();

	/*
	 * print the dmar info if the debug
	 * is set
	 */
	if (intel_dmar_acpi_debug)
		print_dmar_info();
}
