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
 * Portions Copyright (c) 2010, Oracle and/or its affiliates.
 * All rights reserved.
 */
/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

/*
 * Intel IOMMU implementation
 * This file contains Intel IOMMU code exported
 * to the rest of the system and code that deals
 * with the Intel IOMMU as a whole.
 */

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddifm.h>
#include <sys/sunndi.h>
#include <sys/debug.h>
#include <sys/fm/protocol.h>
#include <sys/note.h>
#include <sys/apic.h>
#include <vm/hat_i86.h>
#include <sys/smp_impldefs.h>
#include <sys/spl.h>
#include <sys/archsystm.h>
#include <sys/x86_archext.h>
#include <sys/avl.h>
#include <sys/bootconf.h>
#include <sys/bootinfo.h>
#include <sys/atomic.h>
#include <sys/immu.h>
/* ########################### Globals and tunables ######################## */
/*
 * Global switches (boolean) that can be toggled either via boot options
 * or via /etc/system or kmdb
 */

/* Various features */
boolean_t immu_enable = B_TRUE;
boolean_t immu_dvma_enable = B_TRUE;

/* accessed in other files so not static */
boolean_t immu_gfxdvma_enable = B_TRUE;
boolean_t immu_intrmap_enable = B_FALSE;
boolean_t immu_qinv_enable = B_TRUE;

/* various quirks that need working around */

/* XXX We always map page 0 read/write for now */
boolean_t immu_quirk_usbpage0 = B_TRUE;
boolean_t immu_quirk_usbrmrr = B_TRUE;
boolean_t immu_quirk_usbfullpa;
boolean_t immu_quirk_mobile4;

/* debug messages */
boolean_t immu_dmar_print;

/* Tunables */
int64_t immu_flush_gran = 5;

immu_flags_t immu_global_dvma_flags;

/* ############  END OPTIONS section ################ */

/*
 * Global used internally by Intel IOMMU code
 */
dev_info_t *root_devinfo;
kmutex_t immu_lock;
list_t immu_list;
boolean_t immu_setup;
boolean_t immu_running;
boolean_t immu_quiesced;

/* ######################## END Globals and tunables ###################### */
/* Globals used only in this file */
static char **black_array;
static uint_t nblacks;

static char **unity_driver_array;
static uint_t nunity;
static char **xlate_driver_array;
static uint_t nxlate;

static char **premap_driver_array;
static uint_t npremap;
static char **nopremap_driver_array;
static uint_t nnopremap;
/* ###################### Utility routines ############################# */

/*
 * Check if the device has mobile 4 chipset
 */
static int
check_mobile4(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg));
	int vendor, device;
	int *ip = (int *)arg;

	vendor = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", -1);
	device = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", -1);

	if (vendor == 0x8086 && device == 0x2a40) {
		*ip = B_TRUE;
		ddi_err(DER_NOTE, dip, "iommu: Mobile 4 chipset detected. "
		    "Force setting IOMMU write buffer");
		return (DDI_WALK_TERMINATE);
	} else {
		return (DDI_WALK_CONTINUE);
	}
}

static void
map_bios_rsvd_mem(dev_info_t *dip)
{
	struct memlist *mp;

	/*
	 * Make sure the domain for the device is set up before
	 * mapping anything.
	 */
	(void) immu_dvma_device_setup(dip, 0);

	memlist_read_lock();

	mp = bios_rsvd;
	while (mp != NULL) {
		memrng_t mrng = {0};

		ddi_err(DER_LOG, dip, "iommu: Mapping BIOS rsvd range "
		    "[0x%" PRIx64 " - 0x%"PRIx64 "]\n", mp->ml_address,
		    mp->ml_address + mp->ml_size);

		mrng.mrng_start = IMMU_ROUNDOWN(mp->ml_address);
		mrng.mrng_npages = IMMU_ROUNDUP(mp->ml_size) / IMMU_PAGESIZE;

		(void) immu_map_memrange(dip, &mrng);

		mp = mp->ml_next;
	}

	memlist_read_unlock();
}


/*
 * Check if the driver requests a specific type of mapping.
 */
/*ARGSUSED*/
static void
check_conf(dev_info_t *dip, void *arg)
{
	immu_devi_t *immu_devi;
	const char *dname;
	uint_t i;
	int hasmapprop = 0, haspreprop = 0;
	boolean_t old_premap;

	/*
	 * Only PCI devices can use an IOMMU. Legacy ISA devices
	 * are handled in check_lpc.
	 */
	if (!DEVI_IS_PCI(dip))
		return;

	dname = ddi_driver_name(dip);
	if (dname == NULL)
		return;
	immu_devi = immu_devi_get(dip);

	for (i = 0; i < nunity; i++) {
		if (strcmp(unity_driver_array[i], dname) == 0) {
			hasmapprop = 1;
			immu_devi->imd_dvma_flags |= IMMU_FLAGS_UNITY;
		}
	}

	for (i = 0; i < nxlate; i++) {
		if (strcmp(xlate_driver_array[i], dname) == 0) {
			hasmapprop = 1;
			immu_devi->imd_dvma_flags &= ~IMMU_FLAGS_UNITY;
		}
	}

	old_premap = immu_devi->imd_use_premap;

	for (i = 0; i < nnopremap; i++) {
		if (strcmp(nopremap_driver_array[i], dname) == 0) {
			haspreprop = 1;
			immu_devi->imd_use_premap = B_FALSE;
		}
	}

	for (i = 0; i < npremap; i++) {
		if (strcmp(premap_driver_array[i], dname) == 0) {
			haspreprop = 1;
			immu_devi->imd_use_premap = B_TRUE;
		}
	}

	/*
	 * Report if we changed the value from the default.
	 */
	if (hasmapprop && (immu_devi->imd_dvma_flags ^ immu_global_dvma_flags))
		ddi_err(DER_LOG, dip, "using %s DVMA mapping",
		    immu_devi->imd_dvma_flags & IMMU_FLAGS_UNITY ?
		    DDI_DVMA_MAPTYPE_UNITY : DDI_DVMA_MAPTYPE_XLATE);

	if (haspreprop && (immu_devi->imd_use_premap != old_premap))
		ddi_err(DER_LOG, dip, "%susing premapped DVMA space",
		    immu_devi->imd_use_premap ? "" : "not ");
}

/*
 * Check if the device is USB controller
 */
/*ARGSUSED*/
static void
check_usb(dev_info_t *dip, void *arg)
{
	const char *drv = ddi_driver_name(dip);
	immu_devi_t *immu_devi;


	/*
	 * It's not clear if xHCI really needs these quirks; however, to be on
	 * the safe side until we know for certain we add it to the list below.
	 */
	if (drv == NULL ||
	    (strcmp(drv, "uhci") != 0 && strcmp(drv, "ohci") != 0 &&
	    strcmp(drv, "ehci") != 0 && strcmp(drv, "xhci") != 0)) {
		return;
	}

	immu_devi = immu_devi_get(dip);

	/*
	 * If unit mappings are already specified, globally or
	 * locally, we're done here, since that covers both
	 * quirks below.
	 */
	if (immu_devi->imd_dvma_flags & IMMU_FLAGS_UNITY)
		return;

	/* This must come first since it does unity mapping */
	if (immu_quirk_usbfullpa == B_TRUE) {
		immu_devi->imd_dvma_flags |= IMMU_FLAGS_UNITY;
	} else if (immu_quirk_usbrmrr == B_TRUE) {
		ddi_err(DER_LOG, dip, "Applying USB RMRR quirk");
		map_bios_rsvd_mem(dip);
	}
}

/*
 * Check if the device is a LPC device
 */
/*ARGSUSED*/
static void
check_lpc(dev_info_t *dip, void *arg)
{
	immu_devi_t *immu_devi;

	immu_devi = immu_devi_get(dip);
	if (immu_devi->imd_lpc == B_TRUE) {
		ddi_err(DER_LOG, dip, "iommu: Found LPC device");
		/* This will put the immu_devi on the LPC "specials" list */
		(void) immu_dvma_device_setup(dip, IMMU_FLAGS_SLEEP);
	}
}

/*
 * Check if the device is a GFX device
 */
/*ARGSUSED*/
static void
check_gfx(dev_info_t *dip, void *arg)
{
	immu_devi_t *immu_devi;

	immu_devi = immu_devi_get(dip);
	if (immu_devi->imd_display == B_TRUE) {
		immu_devi->imd_dvma_flags |= IMMU_FLAGS_UNITY;
		ddi_err(DER_LOG, dip, "iommu: Found GFX device");
		/* This will put the immu_devi on the GFX "specials" list */
		(void) immu_dvma_get_immu(dip, IMMU_FLAGS_SLEEP);
	}
}

static void
walk_tree(int (*f)(dev_info_t *, void *), void *arg)
{
	int count;

	ndi_devi_enter(root_devinfo, &count);
	ddi_walk_devs(ddi_get_child(root_devinfo), f, arg);
	ndi_devi_exit(root_devinfo, count);
}

static int
check_pre_setup_quirks(dev_info_t *dip, void *arg)
{
	/* just 1 check right now */
	return (check_mobile4(dip, arg));
}

static int
check_pre_startup_quirks(dev_info_t *dip, void *arg)
{
	if (immu_devi_set(dip, IMMU_FLAGS_SLEEP) != DDI_SUCCESS) {
		ddi_err(DER_PANIC, dip, "Failed to get immu_devi");
	}

	check_gfx(dip, arg);

	check_lpc(dip, arg);

	check_conf(dip, arg);

	check_usb(dip, arg);

	return (DDI_WALK_CONTINUE);
}

static void
pre_setup_quirks(void)
{
	walk_tree(check_pre_setup_quirks, &immu_quirk_mobile4);
}

static void
pre_startup_quirks(void)
{
	walk_tree(check_pre_startup_quirks, NULL);

	immu_dmar_rmrr_map();
}

static int
get_conf_str(char *bopt, char **val)
{
	int ret;

	/*
	 * Check the rootnex.conf property
	 * Fake up a dev_t since searching the global
	 * property list needs it
	 */
	ret = ddi_prop_lookup_string(
	    makedevice(ddi_name_to_major("rootnex"), 0),
	    root_devinfo, DDI_PROP_DONTPASS | DDI_PROP_ROOTNEX_GLOBAL,
	    bopt, val);

	return (ret);
}

/*
 * get_conf_opt()
 * 	get a rootnex.conf setting  (always a boolean)
 */
static void
get_conf_opt(char *bopt, boolean_t *kvar)
{
	char *val = NULL;

	/*
	 * Check the rootnex.conf property
	 * Fake up a dev_t since searching the global
	 * property list needs it
	 */

	if (get_conf_str(bopt, &val) != DDI_PROP_SUCCESS)
		return;

	if (strcmp(val, "true") == 0) {
		*kvar = B_TRUE;
	} else if (strcmp(val, "false") == 0) {
		*kvar = B_FALSE;
	} else {
		ddi_err(DER_WARN, NULL, "rootnex.conf switch %s=\"%s\" ",
		    "is not set to true or false. Ignoring option.",
		    bopt, val);
	}
	ddi_prop_free(val);
}

/*
 * get_bootopt()
 * 	check a boot option  (always a boolean)
 */
static int
get_boot_str(char *bopt, char **val)
{
	int ret;

	ret = ddi_prop_lookup_string(DDI_DEV_T_ANY, root_devinfo,
	    DDI_PROP_DONTPASS, bopt, val);

	return (ret);
}

static void
get_bootopt(char *bopt, boolean_t *kvar)
{
	char *val = NULL;

	/*
	 * All boot options set at the GRUB menu become
	 * properties on the rootnex.
	 */
	if (get_boot_str(bopt, &val) != DDI_PROP_SUCCESS)
		return;

	if (strcmp(val, "true") == 0) {
		*kvar = B_TRUE;
	} else if (strcmp(val, "false") == 0) {
		*kvar = B_FALSE;
	} else {
		ddi_err(DER_WARN, NULL, "boot option %s=\"%s\" ",
		    "is not set to true or false. Ignoring option.",
		    bopt, val);
	}
	ddi_prop_free(val);
}

static void
get_boot_dvma_mode(void)
{
	char *val = NULL;

	if (get_boot_str(DDI_DVMA_MAPTYPE_ROOTNEX_PROP, &val)
	    != DDI_PROP_SUCCESS)
		return;

	if (strcmp(val, DDI_DVMA_MAPTYPE_UNITY) == 0) {
		immu_global_dvma_flags |= IMMU_FLAGS_UNITY;
	} else if (strcmp(val, DDI_DVMA_MAPTYPE_XLATE) == 0) {
		immu_global_dvma_flags &= ~IMMU_FLAGS_UNITY;
	} else {
		ddi_err(DER_WARN, NULL, "bad value \"%s\" for boot option %s",
		    val, DDI_DVMA_MAPTYPE_ROOTNEX_PROP);
	}
	ddi_prop_free(val);
}

static void
get_conf_dvma_mode(void)
{
	char *val = NULL;

	if (get_conf_str(DDI_DVMA_MAPTYPE_ROOTNEX_PROP, &val)
	    != DDI_PROP_SUCCESS)
		return;

	if (strcmp(val, DDI_DVMA_MAPTYPE_UNITY) == 0) {
		immu_global_dvma_flags |= IMMU_FLAGS_UNITY;
	} else if (strcmp(val, DDI_DVMA_MAPTYPE_XLATE) == 0) {
		immu_global_dvma_flags &= ~IMMU_FLAGS_UNITY;
	} else {
		ddi_err(DER_WARN, NULL, "bad value \"%s\" for rootnex "
		    "option %s", val, DDI_DVMA_MAPTYPE_ROOTNEX_PROP);
	}
	ddi_prop_free(val);
}


static void
get_conf_tunables(char *bopt, int64_t *ivar)
{
	int64_t	*iarray;
	uint_t n;

	/*
	 * Check the rootnex.conf property
	 * Fake up a dev_t since searching the global
	 * property list needs it
	 */
	if (ddi_prop_lookup_int64_array(
	    makedevice(ddi_name_to_major("rootnex"), 0), root_devinfo,
	    DDI_PROP_DONTPASS | DDI_PROP_ROOTNEX_GLOBAL, bopt,
	    &iarray, &n) != DDI_PROP_SUCCESS) {
		return;
	}

	if (n != 1) {
		ddi_err(DER_WARN, NULL, "More than one value specified for "
		    "%s property. Ignoring and using default",
		    "immu-flush-gran");
		ddi_prop_free(iarray);
		return;
	}

	if (iarray[0] < 0) {
		ddi_err(DER_WARN, NULL, "Negative value specified for "
		    "%s property. Inoring and Using default value",
		    "immu-flush-gran");
		ddi_prop_free(iarray);
		return;
	}

	*ivar = iarray[0];

	ddi_prop_free(iarray);
}

static void
read_conf_options(void)
{
	/* enable/disable options */
	get_conf_opt("immu-enable", &immu_enable);
	get_conf_opt("immu-dvma-enable", &immu_dvma_enable);
	get_conf_opt("immu-gfxdvma-enable", &immu_gfxdvma_enable);
	get_conf_opt("immu-intrmap-enable", &immu_intrmap_enable);
	get_conf_opt("immu-qinv-enable", &immu_qinv_enable);

	/* workaround switches */
	get_conf_opt("immu-quirk-usbpage0", &immu_quirk_usbpage0);
	get_conf_opt("immu-quirk-usbfullpa", &immu_quirk_usbfullpa);
	get_conf_opt("immu-quirk-usbrmrr", &immu_quirk_usbrmrr);

	/* debug printing */
	get_conf_opt("immu-dmar-print", &immu_dmar_print);

	/* get tunables */
	get_conf_tunables("immu-flush-gran", &immu_flush_gran);

	get_conf_dvma_mode();
}

static void
read_boot_options(void)
{
	/* enable/disable options */
	get_bootopt("immu-enable", &immu_enable);
	get_bootopt("immu-dvma-enable", &immu_dvma_enable);
	get_bootopt("immu-gfxdvma-enable", &immu_gfxdvma_enable);
	get_bootopt("immu-intrmap-enable", &immu_intrmap_enable);
	get_bootopt("immu-qinv-enable", &immu_qinv_enable);

	/* workaround switches */
	get_bootopt("immu-quirk-usbpage0", &immu_quirk_usbpage0);
	get_bootopt("immu-quirk-usbfullpa", &immu_quirk_usbfullpa);
	get_bootopt("immu-quirk-usbrmrr", &immu_quirk_usbrmrr);

	/* debug printing */
	get_bootopt("immu-dmar-print", &immu_dmar_print);

	get_boot_dvma_mode();
}

static void
mapping_list_setup(void)
{
	char **string_array;
	uint_t nstrings;

	if (ddi_prop_lookup_string_array(
	    makedevice(ddi_name_to_major("rootnex"), 0), root_devinfo,
	    DDI_PROP_DONTPASS | DDI_PROP_ROOTNEX_GLOBAL,
	    "immu-dvma-unity-drivers",
	    &string_array, &nstrings) == DDI_PROP_SUCCESS) {
		unity_driver_array = string_array;
		nunity = nstrings;
	}

	if (ddi_prop_lookup_string_array(
	    makedevice(ddi_name_to_major("rootnex"), 0), root_devinfo,
	    DDI_PROP_DONTPASS | DDI_PROP_ROOTNEX_GLOBAL,
	    "immu-dvma-xlate-drivers",
	    &string_array, &nstrings) == DDI_PROP_SUCCESS) {
		xlate_driver_array = string_array;
		nxlate = nstrings;
	}

	if (ddi_prop_lookup_string_array(
	    makedevice(ddi_name_to_major("rootnex"), 0), root_devinfo,
	    DDI_PROP_DONTPASS | DDI_PROP_ROOTNEX_GLOBAL,
	    "immu-dvma-premap-drivers",
	    &string_array, &nstrings) == DDI_PROP_SUCCESS) {
		premap_driver_array = string_array;
		npremap = nstrings;
	}

	if (ddi_prop_lookup_string_array(
	    makedevice(ddi_name_to_major("rootnex"), 0), root_devinfo,
	    DDI_PROP_DONTPASS | DDI_PROP_ROOTNEX_GLOBAL,
	    "immu-dvma-nopremap-drivers",
	    &string_array, &nstrings) == DDI_PROP_SUCCESS) {
		nopremap_driver_array = string_array;
		nnopremap = nstrings;
	}
}

/*
 * Note, this will not catch hardware not enumerated
 * in early boot
 */
static boolean_t
blacklisted_driver(void)
{
	char **strptr;
	int i;
	major_t maj;

	/* need at least 2 strings */
	if (nblacks < 2) {
		return (B_FALSE);
	}

	for (i = 0; nblacks - i > 1; i++) {
		strptr = &black_array[i];
		if (strcmp(*strptr++, "DRIVER") == 0) {
			if ((maj = ddi_name_to_major(*strptr++))
			    != DDI_MAJOR_T_NONE) {
				/* is there hardware bound to this drvr */
				if (devnamesp[maj].dn_head != NULL) {
					return (B_TRUE);
				}
			}
			i += 1;   /* for loop adds 1, so add only 1 here */
		}
	}

	return (B_FALSE);
}

static boolean_t
blacklisted_smbios(void)
{
	id_t smid;
	smbios_hdl_t *smhdl;
	smbios_info_t sminf;
	smbios_system_t smsys;
	char *mfg, *product, *version;
	char **strptr;
	int i;

	/* need at least 4 strings for this setting */
	if (nblacks < 4) {
		return (B_FALSE);
	}

	smhdl = smbios_open(NULL, SMB_VERSION, ksmbios_flags, NULL);
	if (smhdl == NULL ||
	    (smid = smbios_info_system(smhdl, &smsys)) == SMB_ERR ||
	    smbios_info_common(smhdl, smid, &sminf) == SMB_ERR) {
		return (B_FALSE);
	}

	mfg = (char *)sminf.smbi_manufacturer;
	product = (char *)sminf.smbi_product;
	version = (char *)sminf.smbi_version;

	ddi_err(DER_CONT, NULL, "?System SMBIOS information:\n");
	ddi_err(DER_CONT, NULL, "?Manufacturer = <%s>\n", mfg);
	ddi_err(DER_CONT, NULL, "?Product = <%s>\n", product);
	ddi_err(DER_CONT, NULL, "?Version = <%s>\n", version);

	for (i = 0; nblacks - i > 3; i++) {
		strptr = &black_array[i];
		if (strcmp(*strptr++, "SMBIOS") == 0) {
			if (strcmp(*strptr++, mfg) == 0 &&
			    (*strptr[0] == '\0' ||
			    strcmp(*strptr++, product) == 0) &&
			    (*strptr[0] == '\0' ||
			    strcmp(*strptr++, version) == 0)) {
				return (B_TRUE);
			}
			i += 3;
		}
	}

	return (B_FALSE);
}

static boolean_t
blacklisted_acpi(void)
{
	if (nblacks == 0) {
		return (B_FALSE);
	}

	return (immu_dmar_blacklisted(black_array, nblacks));
}

/*
 * Check if system is blacklisted by Intel IOMMU driver
 * i.e. should Intel IOMMU be disabled on this system
 * Currently a system can be blacklistd based on the
 * following bases:
 *
 * 1. DMAR ACPI table information.
 *    This information includes things like
 *    manufacturer and revision number. If rootnex.conf
 *    has matching info set in its blacklist property
 *    then Intel IOMMu will be disabled
 *
 * 2. SMBIOS information
 *
 * 3. Driver installed - useful if a particular
 *    driver or hardware is toxic if Intel IOMMU
 *    is turned on.
 */

static void
blacklist_setup(void)
{
	char **string_array;
	uint_t nstrings;

	/*
	 * Check the rootnex.conf blacklist property.
	 * Fake up a dev_t since searching the global
	 * property list needs it
	 */
	if (ddi_prop_lookup_string_array(
	    makedevice(ddi_name_to_major("rootnex"), 0), root_devinfo,
	    DDI_PROP_DONTPASS | DDI_PROP_ROOTNEX_GLOBAL, "immu-blacklist",
	    &string_array, &nstrings) != DDI_PROP_SUCCESS) {
		return;
	}

	/* smallest blacklist criteria works with multiples of 2 */
	if (nstrings % 2 != 0) {
		ddi_err(DER_WARN, NULL, "Invalid IOMMU blacklist "
		    "rootnex.conf: number of strings must be a "
		    "multiple of 2");
		ddi_prop_free(string_array);
		return;
	}

	black_array = string_array;
	nblacks = nstrings;
}

static void
blacklist_destroy(void)
{
	if (black_array) {
		ddi_prop_free(black_array);
		black_array = NULL;
		nblacks = 0;
	}
}

static char *
immu_alloc_name(const char *str, int instance)
{
	size_t slen;
	char *s;

	slen = strlen(str) + IMMU_ISTRLEN + 1;
	s = kmem_zalloc(slen, VM_SLEEP);
	if (s != NULL)
		(void) snprintf(s, slen, "%s%d", str, instance);

	return (s);
}


/*
 * Now set all the fields in the order they are defined
 * We do this only as a defensive-coding practice, it is
 * not a correctness issue.
 */
static void *
immu_state_alloc(int seg, void *dmar_unit)
{
	immu_t *immu;
	char *nodename, *hcachename, *pcachename;
	int instance;

	dmar_unit = immu_dmar_walk_units(seg, dmar_unit);
	if (dmar_unit == NULL) {
		/* No more IOMMUs in this segment */
		return (NULL);
	}

	immu = kmem_zalloc(sizeof (immu_t), KM_SLEEP);

	mutex_init(&(immu->immu_lock), NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&(immu->immu_lock));

	immu->immu_dmar_unit = dmar_unit;
	immu->immu_dip = immu_dmar_unit_dip(dmar_unit);

	nodename = ddi_node_name(immu->immu_dip);
	instance = ddi_get_instance(immu->immu_dip);

	immu->immu_name = immu_alloc_name(nodename, instance);
	if (immu->immu_name == NULL)
		return (NULL);

	/*
	 * the immu_intr_lock mutex is grabbed by the IOMMU
	 * unit's interrupt handler so we need to use an
	 * interrupt cookie for the mutex
	 */
	mutex_init(&(immu->immu_intr_lock), NULL, MUTEX_DRIVER,
	    (void *)ipltospl(IMMU_INTR_IPL));

	/* IOMMU regs related */
	mutex_init(&(immu->immu_regs_lock), NULL, MUTEX_DEFAULT, NULL);
	cv_init(&(immu->immu_regs_cv), NULL, CV_DEFAULT, NULL);
	immu->immu_regs_busy = B_FALSE;

	/* DVMA related */
	immu->immu_dvma_coherent = B_FALSE;

	/* DVMA context related */
	rw_init(&(immu->immu_ctx_rwlock), NULL, RW_DEFAULT, NULL);

	/* DVMA domain related */
	list_create(&(immu->immu_domain_list), sizeof (domain_t),
	    offsetof(domain_t, dom_immu_node));

	/* DVMA special device lists */
	immu->immu_dvma_gfx_only = B_FALSE;
	list_create(&(immu->immu_dvma_lpc_list), sizeof (immu_devi_t),
	    offsetof(immu_devi_t, imd_spc_node));
	list_create(&(immu->immu_dvma_gfx_list), sizeof (immu_devi_t),
	    offsetof(immu_devi_t, imd_spc_node));

	/* interrupt remapping related */
	mutex_init(&(immu->immu_intrmap_lock), NULL, MUTEX_DEFAULT, NULL);

	/* qinv related */
	mutex_init(&(immu->immu_qinv_lock), NULL, MUTEX_DEFAULT, NULL);

	/*
	 * insert this immu unit into the system-wide list
	 */
	list_insert_tail(&immu_list, immu);

	pcachename = immu_alloc_name("immu_pgtable_cache", instance);
	if (pcachename == NULL)
		return (NULL);

	hcachename = immu_alloc_name("immu_hdl_cache", instance);
	if (hcachename == NULL)
		return (NULL);

	immu->immu_pgtable_cache = kmem_cache_create(pcachename,
	    sizeof (pgtable_t), 0, pgtable_ctor, pgtable_dtor, NULL, immu,
	    NULL, 0);
	immu->immu_hdl_cache = kmem_cache_create(hcachename,
	    sizeof (immu_hdl_priv_t), 64, immu_hdl_priv_ctor,
	    NULL, NULL, immu, NULL, 0);

	mutex_exit(&(immu->immu_lock));

	ddi_err(DER_LOG, immu->immu_dip, "unit setup");

	immu_dmar_set_immu(dmar_unit, immu);

	return (dmar_unit);
}

static void
immu_subsystems_setup(void)
{
	int seg;
	void *unit_hdl;

	ddi_err(DER_VERB, NULL,
	    "Creating state structures for Intel IOMMU units");

	mutex_init(&immu_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&immu_list, sizeof (immu_t), offsetof(immu_t, immu_node));

	mutex_enter(&immu_lock);

	unit_hdl = NULL;
	for (seg = 0; seg < IMMU_MAXSEG; seg++) {
		while (unit_hdl = immu_state_alloc(seg, unit_hdl)) {
			;
		}
	}

	immu_regs_setup(&immu_list);	/* subsequent code needs this first */
	immu_dvma_setup(&immu_list);
	if (immu_qinv_setup(&immu_list) == DDI_SUCCESS)
		immu_intrmap_setup(&immu_list);
	else
		immu_intrmap_enable = B_FALSE;

	mutex_exit(&immu_lock);
}

/*
 * immu_subsystems_startup()
 * 	startup all units that were setup
 */
static void
immu_subsystems_startup(void)
{
	immu_t *immu;
	iommulib_ops_t *iommulib_ops;

	mutex_enter(&immu_lock);

	immu_dmar_startup();

	immu = list_head(&immu_list);
	for (; immu; immu = list_next(&immu_list, immu)) {

		mutex_enter(&(immu->immu_lock));

		immu_intr_register(immu);
		immu_dvma_startup(immu);
		immu_intrmap_startup(immu);
		immu_qinv_startup(immu);

		/*
		 * Set IOMMU unit's regs to do
		 * the actual startup. This will
		 * set immu->immu_running  field
		 * if the unit is successfully
		 * started
		 */
		immu_regs_startup(immu);

		mutex_exit(&(immu->immu_lock));

		iommulib_ops = kmem_alloc(sizeof (iommulib_ops_t), KM_SLEEP);
		*iommulib_ops = immulib_ops;
		iommulib_ops->ilops_data = (void *)immu;
		(void) iommulib_iommu_register(immu->immu_dip, iommulib_ops,
		    &immu->immu_iommulib_handle);
	}

	mutex_exit(&immu_lock);
}

/* ##################  Intel IOMMU internal interfaces ###################### */

/*
 * Internal interfaces for IOMMU code (i.e. not exported to rootnex
 * or rest of system)
 */

/*
 * ddip can be NULL, in which case we walk up until we find the root dip
 * NOTE: We never visit the root dip since its not a hardware node
 */
int
immu_walk_ancestor(
	dev_info_t *rdip,
	dev_info_t *ddip,
	int (*func)(dev_info_t *, void *arg),
	void *arg,
	int *lvlp,
	immu_flags_t immu_flags)
{
	dev_info_t *pdip;
	int level;
	int error = DDI_SUCCESS;

	/* ddip and immu can be NULL */

	/* Hold rdip so that branch is not detached */
	ndi_hold_devi(rdip);
	for (pdip = rdip, level = 1; pdip && pdip != root_devinfo;
	    pdip = ddi_get_parent(pdip), level++) {

		if (immu_devi_set(pdip, immu_flags) != DDI_SUCCESS) {
			error = DDI_FAILURE;
			break;
		}
		if (func(pdip, arg) == DDI_WALK_TERMINATE) {
			break;
		}
		if (immu_flags & IMMU_FLAGS_DONTPASS) {
			break;
		}
		if (pdip == ddip) {
			break;
		}
	}

	ndi_rele_devi(rdip);

	if (lvlp)
		*lvlp = level;

	return (error);
}

/* ########################  Intel IOMMU entry points ####################### */
/*
 * immu_init()
 *	called from rootnex_attach(). setup but don't startup the Intel IOMMU
 *      This is the first function called in Intel IOMMU code
 */
void
immu_init(void)
{
	char *phony_reg = "A thing of beauty is a joy forever";

	/* Set some global shorthands that are needed by all of IOMMU code */
	root_devinfo = ddi_root_node();

	/*
	 * Intel IOMMU only supported only if MMU(CPU) page size is ==
	 * IOMMU pages size.
	 */
	/*LINTED*/
	if (MMU_PAGESIZE != IMMU_PAGESIZE) {
		ddi_err(DER_WARN, NULL,
		    "MMU page size (%d) is not equal to\n"
		    "IOMMU page size (%d). "
		    "Disabling Intel IOMMU. ",
		    MMU_PAGESIZE, IMMU_PAGESIZE);
		immu_enable = B_FALSE;
		return;
	}

	/*
	 * Read rootnex.conf options. Do this before
	 * boot options so boot options can override .conf options.
	 */
	read_conf_options();

	/*
	 * retrieve the Intel IOMMU boot options.
	 * Do this before parsing immu ACPI table
	 * as a boot option could potentially affect
	 * ACPI parsing.
	 */
	ddi_err(DER_CONT, NULL, "?Reading Intel IOMMU boot options\n");
	read_boot_options();

	/*
	 * Check the IOMMU enable boot-option first.
	 * This is so that we can skip parsing the ACPI table
	 * if necessary because that may cause problems in
	 * systems with buggy BIOS or ACPI tables
	 */
	if (immu_enable == B_FALSE) {
		return;
	}

	if (immu_intrmap_enable == B_TRUE)
		immu_qinv_enable = B_TRUE;

	/*
	 * Next, check if the system even has an Intel IOMMU
	 * We use the presence or absence of the IOMMU ACPI
	 * table to detect Intel IOMMU.
	 */
	if (immu_dmar_setup() != DDI_SUCCESS) {
		immu_enable = B_FALSE;
		return;
	}

	mapping_list_setup();

	/*
	 * Check blacklists
	 */
	blacklist_setup();

	if (blacklisted_smbios() == B_TRUE) {
		blacklist_destroy();
		immu_enable = B_FALSE;
		return;
	}

	if (blacklisted_driver() == B_TRUE) {
		blacklist_destroy();
		immu_enable = B_FALSE;
		return;
	}

	/*
	 * Read the "raw" DMAR ACPI table to get information
	 * and convert into a form we can use.
	 */
	if (immu_dmar_parse() != DDI_SUCCESS) {
		blacklist_destroy();
		immu_enable = B_FALSE;
		return;
	}

	/*
	 * now that we have processed the ACPI table
	 * check if we need to blacklist this system
	 * based on ACPI info
	 */
	if (blacklisted_acpi() == B_TRUE) {
		immu_dmar_destroy();
		blacklist_destroy();
		immu_enable = B_FALSE;
		return;
	}

	blacklist_destroy();

	/*
	 * Check if system has HW quirks.
	 */
	pre_setup_quirks();

	/* Now do the rest of the setup */
	immu_subsystems_setup();

	/*
	 * Now that the IMMU is setup, create a phony
	 * reg prop so that suspend/resume works
	 */
	if (ddi_prop_update_byte_array(DDI_DEV_T_NONE, root_devinfo, "reg",
	    (uchar_t *)phony_reg, strlen(phony_reg) + 1) != DDI_PROP_SUCCESS) {
		ddi_err(DER_PANIC, NULL, "Failed to create reg prop for "
		    "rootnex node");
		/*NOTREACHED*/
	}

	immu_setup = B_TRUE;
}

/*
 * immu_startup()
 * 	called directly by boot code to startup
 *      all units of the IOMMU
 */
void
immu_startup(void)
{
	/*
	 * If IOMMU is disabled, do nothing
	 */
	if (immu_enable == B_FALSE) {
		return;
	}

	if (immu_setup == B_FALSE) {
		ddi_err(DER_WARN, NULL, "Intel IOMMU not setup, "
		    "skipping IOMMU startup");
		return;
	}

	pre_startup_quirks();

	ddi_err(DER_CONT, NULL,
	    "?Starting Intel IOMMU (dmar) units...\n");

	immu_subsystems_startup();

	immu_running = B_TRUE;
}

/*
 * Hook to notify IOMMU code of device tree changes
 */
void
immu_device_tree_changed(void)
{
	if (immu_setup == B_FALSE) {
		return;
	}

	ddi_err(DER_WARN, NULL, "Intel IOMMU currently "
	    "does not use device tree updates");
}

/*
 * Hook to notify IOMMU code of memory changes
 */
void
immu_physmem_update(uint64_t addr, uint64_t size)
{
	if (immu_setup == B_FALSE) {
		return;
	}
	immu_dvma_physmem_update(addr, size);
}

/*
 * immu_quiesce()
 * 	quiesce all units that are running
 */
int
immu_quiesce(void)
{
	immu_t *immu;
	int ret = DDI_SUCCESS;

	mutex_enter(&immu_lock);

	if (immu_running == B_FALSE) {
		mutex_exit(&immu_lock);
		return (DDI_SUCCESS);
	}

	immu = list_head(&immu_list);
	for (; immu; immu = list_next(&immu_list, immu)) {

		/* if immu is not running, we dont quiesce */
		if (immu->immu_regs_running == B_FALSE)
			continue;

		/* flush caches */
		rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
		immu_flush_context_gbl(immu, &immu->immu_ctx_inv_wait);
		immu_flush_iotlb_gbl(immu, &immu->immu_ctx_inv_wait);
		rw_exit(&(immu->immu_ctx_rwlock));
		immu_regs_wbf_flush(immu);

		mutex_enter(&(immu->immu_lock));

		/*
		 * Set IOMMU unit's regs to do
		 * the actual shutdown.
		 */
		immu_regs_shutdown(immu);
		immu_regs_suspend(immu);

		/* if immu is still running, we failed */
		if (immu->immu_regs_running == B_TRUE)
			ret = DDI_FAILURE;
		else
			immu->immu_regs_quiesced = B_TRUE;

		mutex_exit(&(immu->immu_lock));
	}

	if (ret == DDI_SUCCESS) {
		immu_running = B_FALSE;
		immu_quiesced = B_TRUE;
	}
	mutex_exit(&immu_lock);

	return (ret);
}

/*
 * immu_unquiesce()
 * 	unquiesce all units
 */
int
immu_unquiesce(void)
{
	immu_t *immu;
	int ret = DDI_SUCCESS;

	mutex_enter(&immu_lock);

	if (immu_quiesced == B_FALSE) {
		mutex_exit(&immu_lock);
		return (DDI_SUCCESS);
	}

	immu = list_head(&immu_list);
	for (; immu; immu = list_next(&immu_list, immu)) {

		mutex_enter(&(immu->immu_lock));

		/* if immu was not quiesced, i.e was not running before */
		if (immu->immu_regs_quiesced == B_FALSE) {
			mutex_exit(&(immu->immu_lock));
			continue;
		}

		if (immu_regs_resume(immu) != DDI_SUCCESS) {
			ret = DDI_FAILURE;
			mutex_exit(&(immu->immu_lock));
			continue;
		}

		/* flush caches before unquiesce */
		rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
		immu_flush_context_gbl(immu, &immu->immu_ctx_inv_wait);
		immu_flush_iotlb_gbl(immu, &immu->immu_ctx_inv_wait);
		rw_exit(&(immu->immu_ctx_rwlock));

		/*
		 * Set IOMMU unit's regs to do
		 * the actual startup. This will
		 * set immu->immu_regs_running  field
		 * if the unit is successfully
		 * started
		 */
		immu_regs_startup(immu);

		if (immu->immu_regs_running == B_FALSE) {
			ret = DDI_FAILURE;
		} else {
			immu_quiesced = B_TRUE;
			immu_running = B_TRUE;
			immu->immu_regs_quiesced = B_FALSE;
		}

		mutex_exit(&(immu->immu_lock));
	}

	mutex_exit(&immu_lock);

	return (ret);
}

void
immu_init_inv_wait(immu_inv_wait_t *iwp, const char *name, boolean_t sync)
{
	caddr_t vaddr;
	uint64_t paddr;

	iwp->iwp_sync = sync;

	vaddr = (caddr_t)&iwp->iwp_vstatus;
	paddr = pfn_to_pa(hat_getpfnum(kas.a_hat, vaddr));
	paddr += ((uintptr_t)vaddr) & MMU_PAGEOFFSET;

	iwp->iwp_pstatus = paddr;
	iwp->iwp_name = name;
}

/* ##############  END Intel IOMMU entry points ################## */
