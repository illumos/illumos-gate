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
 * Portions Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <sys/rootnex.h>
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
boolean_t immu_qinv_enable = B_FALSE;

/* various quirks that need working around */

/* XXX We always map page 0 read/write for now */
boolean_t immu_quirk_usbpage0 = B_TRUE;
boolean_t immu_quirk_usbrmrr = B_TRUE;
boolean_t immu_quirk_usbfullpa;
boolean_t immu_quirk_mobile4;

boolean_t immu_mmio_safe = B_TRUE;

/* debug messages */
boolean_t immu_dmar_print;

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

	ASSERT(arg);

	vendor = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", -1);
	device = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", -1);

	if (vendor == 0x8086 && device == 0x2a40) {
		*ip = B_TRUE;
		ddi_err(DER_NOTE, dip, "IMMU: Mobile 4 chipset detected. "
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
	int e;

	memlist_read_lock();

	mp = bios_rsvd;
	while (mp != NULL) {
		memrng_t *mrng = {0};

		ddi_err(DER_LOG, dip, "IMMU: Mapping BIOS rsvd range "
		    "[0x%" PRIx64 " - 0x%"PRIx64 "]\n", mp->ml_address,
		    mp->ml_address + mp->ml_size);

		mrng->mrng_start = IMMU_ROUNDOWN(mp->ml_address);
		mrng->mrng_npages = IMMU_ROUNDUP(mp->ml_size) / IMMU_PAGESIZE;

		e = immu_dvma_map(NULL, NULL, mrng, 0, dip, IMMU_FLAGS_MEMRNG);
		ASSERT(e == DDI_DMA_MAPPED || e == DDI_DMA_USE_PHYSICAL);

		mp = mp->ml_next;
	}

	memlist_read_unlock();
}

/*
 * Check if the device is USB controller
 */
/*ARGSUSED*/
static void
check_usb(dev_info_t *dip, void *arg)
{
	const char *drv = ddi_driver_name(dip);

	if (drv == NULL ||
	    (strcmp(drv, "uhci") != 0 && strcmp(drv, "ohci") != 0 &&
	    strcmp(drv, "ehci") != 0)) {
		return;
	}

	/* This must come first since it does unity mapping */
	if (immu_quirk_usbfullpa == B_TRUE) {
		int e;
		ddi_err(DER_NOTE, dip, "Applying USB FULL PA quirk");
		e = immu_dvma_map(NULL, NULL, NULL, 0, dip, IMMU_FLAGS_UNITY);
		/* for unity mode, map will return USE_PHYSICAL */
		ASSERT(e == DDI_DMA_USE_PHYSICAL);
	}

	if (immu_quirk_usbrmrr == B_TRUE) {
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
	ASSERT(immu_devi);
	if (immu_devi->imd_lpc == B_TRUE) {
		ddi_err(DER_LOG, dip, "IMMU: Found LPC device");
		/* This will put the immu_devi on the LPC "specials" list */
		(void) immu_dvma_get_immu(dip, IMMU_FLAGS_SLEEP);
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
	int e;

	immu_devi = immu_devi_get(dip);
	ASSERT(immu_devi);
	if (immu_devi->imd_display == B_TRUE) {
		ddi_err(DER_LOG, dip, "IMMU: Found GFX device");
		/* This will put the immu_devi on the GFX "specials" list */
		(void) immu_dvma_get_immu(dip, IMMU_FLAGS_SLEEP);
		e = immu_dvma_map(NULL, NULL, NULL, 0, dip, IMMU_FLAGS_UNITY);
		/* for unity mode, map will return USE_PHYSICAL */
		ASSERT(e == DDI_DMA_USE_PHYSICAL);
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

/*
 * get_bootopt()
 * 	check a boot option  (always a boolean)
 */
static void
get_bootopt(char *bopt, boolean_t *kvar)
{
	char *val = NULL;

	ASSERT(bopt);
	ASSERT(kvar);

	/*
	 * All boot options set at the GRUB menu become
	 * properties on the rootnex.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, root_devinfo,
	    DDI_PROP_DONTPASS, bopt, &val) == DDI_SUCCESS) {
		ASSERT(val);
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
	get_bootopt("immu-mmio-safe", &immu_mmio_safe);

	/* workaround switches */
	get_bootopt("immu-quirk-usbpage0", &immu_quirk_usbpage0);
	get_bootopt("immu-quirk-usbfullpa", &immu_quirk_usbfullpa);
	get_bootopt("immu-quirk-usbrmrr", &immu_quirk_usbrmrr);

	/* debug printing */
	get_bootopt("immu-dmar-print", &immu_dmar_print);
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

	ASSERT((black_array == NULL) ^ (nblacks != 0));

	/* need at least 2 strings */
	if (nblacks < 2) {
		return (B_FALSE);
	}

	strptr = black_array;
	for (i = 0; nblacks - i > 1; i++) {
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

	ASSERT((black_array == NULL) ^ (nblacks != 0));

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

	strptr = black_array;
	for (i = 0; nblacks - i > 3; i++) {
		if (strcmp(*strptr++, "SMBIOS") == 0) {
			if (strcmp(*strptr++, mfg) == 0 &&
			    ((char *)strptr == '\0' ||
			    strcmp(*strptr++, product) == 0) &&
			    ((char *)strptr == '\0' ||
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
	ASSERT((black_array == NULL) ^ (nblacks != 0));
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

	ASSERT(black_array == NULL);
	ASSERT(nblacks == 0);
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

	dmar_unit = immu_dmar_walk_units(seg, dmar_unit);
	if (dmar_unit == NULL) {
		/* No more IOMMUs in this segment */
		return (NULL);
	}

	immu = kmem_zalloc(sizeof (immu_t), KM_SLEEP);

	mutex_init(&(immu->immu_lock), NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&(immu->immu_lock));

	immu->immu_dmar_unit = dmar_unit;
	immu->immu_name = ddi_strdup(immu_dmar_unit_name(dmar_unit),
	    KM_SLEEP);
	immu->immu_dip = immu_dmar_unit_dip(dmar_unit);

	/*
	 * the immu_intr_lock mutex is grabbed by the IOMMU
	 * unit's interrupt handler so we need to use an
	 * interrupt cookie for the mutex
	 */
	mutex_init(&(immu->immu_intr_lock), NULL, MUTEX_DRIVER,
	    (void *)ipltospl(IMMU_INTR_IPL));

	/* IOMMU regs related */
	mutex_init(&(immu->immu_regs_lock), NULL, MUTEX_DEFAULT, NULL);

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

	mutex_exit(&(immu->immu_lock));

	ddi_err(DER_LOG, immu->immu_dip, "IMMU: unit setup");

	immu_dmar_set_immu(dmar_unit, immu);

	return (dmar_unit);
}

static void
immu_subsystems_setup(void)
{
	int seg;
	void *unit_hdl;

	ddi_err(DER_VERB, NULL,
	    "Creating state structures for Intel IOMMU units\n");

	ASSERT(immu_setup == B_FALSE);
	ASSERT(immu_running == B_FALSE);

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
	immu_intrmap_setup(&immu_list);
	immu_qinv_setup(&immu_list);

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

	mutex_enter(&immu_lock);

	ASSERT(immu_setup == B_TRUE);
	ASSERT(immu_running == B_FALSE);

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

	ASSERT(root_devinfo);
	ASSERT(rdip);
	ASSERT(rdip != root_devinfo);
	ASSERT(func);

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
	ASSERT(root_devinfo == NULL);
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

	/*
	 * Next, check if the system even has an Intel IOMMU
	 * We use the presence or absence of the IOMMU ACPI
	 * table to detect Intel IOMMU.
	 */
	if (immu_dmar_setup() != DDI_SUCCESS) {
		immu_enable = B_FALSE;
		return;
	}

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
		    "skipping IOMU startup");
		return;
	}

	pre_startup_quirks();

	ddi_err(DER_CONT, NULL,
	    "?Starting Intel IOMMU (dmar) units...\n");

	immu_subsystems_startup();

	immu_running = B_TRUE;
}

/*
 * immu_map_sgl()
 * 	called from rootnex_coredma_bindhdl() when Intel
 *	IOMMU is enabled to build DVMA cookies and map them.
 */
int
immu_map_sgl(ddi_dma_impl_t *hp, struct ddi_dma_req *dmareq,
    int prealloc_count, dev_info_t *rdip)
{
	if (immu_running == B_FALSE) {
		return (DDI_DMA_USE_PHYSICAL);
	}

	return (immu_dvma_map(hp, dmareq, NULL, prealloc_count, rdip,
	    IMMU_FLAGS_DMAHDL));
}

/*
 * immu_unmap_sgl()
 * 	called from rootnex_coredma_unbindhdl(), to unmap DVMA
 * 	cookies and free them
 */
int
immu_unmap_sgl(ddi_dma_impl_t *hp, dev_info_t *rdip)
{
	if (immu_running == B_FALSE) {
		return (DDI_DMA_USE_PHYSICAL);
	}

	return (immu_dvma_unmap(hp, rdip));
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

	if (immu_running == B_FALSE)
		return (DDI_SUCCESS);

	ASSERT(immu_setup == B_TRUE);

	immu = list_head(&immu_list);
	for (; immu; immu = list_next(&immu_list, immu)) {

		/* if immu is not running, we dont quiesce */
		if (immu->immu_regs_running == B_FALSE)
			continue;

		/* flush caches */
		rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
		immu_regs_context_flush(immu, 0, 0, 0, CONTEXT_GLOBAL);
		rw_exit(&(immu->immu_ctx_rwlock));
		immu_regs_iotlb_flush(immu, 0, 0, 0, 0, IOTLB_GLOBAL);
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
	mutex_exit(&immu_lock);

	if (ret == DDI_SUCCESS) {
		immu_running = B_FALSE;
		immu_quiesced = B_TRUE;
	}

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

	if (immu_quiesced == B_FALSE)
		return (DDI_SUCCESS);

	ASSERT(immu_setup == B_TRUE);
	ASSERT(immu_running == B_FALSE);

	immu = list_head(&immu_list);
	for (; immu; immu = list_next(&immu_list, immu)) {

		mutex_enter(&(immu->immu_lock));

		/* if immu was not quiesced, i.e was not running before */
		if (immu->immu_regs_quiesced == B_FALSE)
			continue;

		if (immu_regs_resume(immu) != DDI_SUCCESS) {
			ret = DDI_FAILURE;
			continue;
		}

		/* flush caches before unquiesce */
		rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
		immu_regs_context_flush(immu, 0, 0, 0, CONTEXT_GLOBAL);
		rw_exit(&(immu->immu_ctx_rwlock));
		immu_regs_iotlb_flush(immu, 0, 0, 0, 0, IOTLB_GLOBAL);

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

/* ##############  END Intel IOMMU entry points ################## */
