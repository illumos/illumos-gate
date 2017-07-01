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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "amd_iommu_acpi.h"
#include "amd_iommu_impl.h"

static int create_acpi_hash(amd_iommu_acpi_t *acpi);
static void amd_iommu_acpi_table_fini(amd_iommu_acpi_t **acpipp);

static void dump_acpi_aliases(void);


/*
 * Globals
 */
static amd_iommu_acpi_global_t *amd_iommu_acpi_global;
static amd_iommu_acpi_ivhd_t **amd_iommu_acpi_ivhd_hash;
static amd_iommu_acpi_ivmd_t **amd_iommu_acpi_ivmd_hash;

static int
type_byte_size(char *cp)
{
	uint8_t type8 = *((uint8_t *)cp);
	uint8_t len_bits;

	len_bits = AMD_IOMMU_REG_GET8(&type8, AMD_IOMMU_ACPI_DEVENTRY_LEN);

	switch (len_bits) {
	case 0:
			return (4);
	case 1:
			return (8);
	case 2:
			return (16);
	case 3:
			return (32);
	default:
			cmn_err(CE_WARN, "%s: Invalid deventry len: %d",
			    amd_iommu_modname, len_bits);
			return (len_bits);
	}
	/*NOTREACHED*/
}

static void
process_4byte_deventry(ivhd_container_t *c, char *cp)
{
	int entry_type = *((uint8_t *)cp);
	ivhd_deventry_t deventry = {0};
	ivhd_deventry_t *devp;
	uint8_t datsetting8;
	align_16_t al = {0};
	int i;

	/* 4 byte entry */
	deventry.idev_len = 4;
	deventry.idev_deviceid = -1;
	deventry.idev_src_deviceid = -1;

	for (i = 0; i < 2; i++) {
		al.ent8[i] = *((uint8_t *)&cp[i + 1]);
	}

	switch (entry_type) {
	case 1:
		deventry.idev_type = DEVENTRY_ALL;
		break;
	case 2:
		deventry.idev_type = DEVENTRY_SELECT;
		deventry.idev_deviceid = al.ent16;
		break;
	case 3:
		deventry.idev_type = DEVENTRY_RANGE;
		deventry.idev_deviceid = al.ent16;
		break;
	case 4:
		deventry.idev_type = DEVENTRY_RANGE_END;
		deventry.idev_deviceid = al.ent16;
		ASSERT(cp[3] == 0);
		break;
	case 0:
		ASSERT(al.ent16 == 0);
		ASSERT(cp[3] == 0);
	default:
		return;
	}


	devp = kmem_alloc(sizeof (ivhd_deventry_t), KM_SLEEP);
	*devp = deventry;

	if (c->ivhdc_first_deventry == NULL)
		c->ivhdc_first_deventry =  devp;
	else
		c->ivhdc_last_deventry->idev_next = devp;

	c->ivhdc_last_deventry = devp;

	if (entry_type == 4)
		return;

	datsetting8 = (*((uint8_t *)&cp[3]));

	devp->idev_Lint1Pass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_LINT1PASS);

	devp->idev_Lint0Pass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_LINT0PASS);

	devp->idev_SysMgt = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_SYSMGT);

	ASSERT(AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_DATRSV) == 0);

	devp->idev_NMIPass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_NMIPASS);

	devp->idev_ExtIntPass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_EXTINTPASS);

	devp->idev_INITPass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_INITPASS);
}

static void
process_8byte_deventry(ivhd_container_t *c, char *cp)
{
	uint8_t datsetting8;
	int entry_type = (uint8_t)*cp;
	ivhd_deventry_t deventry = {0};
	ivhd_deventry_t *devp;
	align_16_t al1 = {0};
	align_16_t al2 = {0};
	align_32_t al3 = {0};
	int i;

	/* Length is 8 bytes */
	deventry.idev_len = 8;
	deventry.idev_deviceid = -1;
	deventry.idev_src_deviceid = -1;

	for (i = 0; i < 2; i++) {
		al1.ent8[i] = *((uint8_t *)&cp[i+1]);
		al2.ent8[i] = *((uint8_t *)&cp[i+5]);
	}

	datsetting8 = *((uint8_t *)&cp[3]);

	switch (entry_type) {
	case 66:
		deventry.idev_type = DEVENTRY_ALIAS_SELECT;
		deventry.idev_deviceid = al1.ent16;
		deventry.idev_src_deviceid = al2.ent16;
		ASSERT(cp[4] == 0);
		ASSERT(cp[7] == 0);
		break;
	case 67:
		deventry.idev_type = DEVENTRY_ALIAS_RANGE;
		deventry.idev_deviceid = al1.ent16;
		deventry.idev_src_deviceid = al2.ent16;
		ASSERT(cp[4] == 0);
		ASSERT(cp[7] == 0);
		break;
	case 70:
		deventry.idev_type = DEVENTRY_EXTENDED_SELECT;
		deventry.idev_deviceid = al1.ent16;
		break;
	case 71:
		deventry.idev_type = DEVENTRY_EXTENDED_RANGE;
		deventry.idev_deviceid = al1.ent16;
		break;
	case 72:
		deventry.idev_type = DEVENTRY_SPECIAL_DEVICE;
		ASSERT(al1.ent16 == 0);
		deventry.idev_deviceid = -1;
		deventry.idev_handle = cp[4];
		deventry.idev_variety = cp[7];
		deventry.idev_src_deviceid = al2.ent16;
	default:
#ifdef BROKEN_ASSERT
		for (i = 0; i < 7; i++) {
			ASSERT(cp[i] == 0);
		}
#endif
		return;
	}


	devp = kmem_alloc(sizeof (ivhd_deventry_t), KM_SLEEP);
	*devp = deventry;

	if (c->ivhdc_first_deventry == NULL)
		c->ivhdc_first_deventry =  devp;
	else
		c->ivhdc_last_deventry->idev_next = devp;

	c->ivhdc_last_deventry = devp;

	devp->idev_Lint1Pass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_LINT1PASS);

	devp->idev_Lint0Pass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_LINT0PASS);

	devp->idev_SysMgt = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_SYSMGT);

	ASSERT(AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_DATRSV) == 0);

	devp->idev_NMIPass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_NMIPASS);

	devp->idev_ExtIntPass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_EXTINTPASS);

	devp->idev_INITPass = AMD_IOMMU_REG_GET8(&datsetting8,
	    AMD_IOMMU_ACPI_INITPASS);

	if (entry_type != 70 && entry_type != 71) {
		return;
	}

	/* Type 70 and 71 */
	for (i = 0; i < 4; i++) {
		al3.ent8[i] = *((uint8_t *)&cp[i+4]);
	}

	devp->idev_AtsDisabled = AMD_IOMMU_REG_GET8(&al3.ent32,
	    AMD_IOMMU_ACPI_ATSDISABLED);

	ASSERT(AMD_IOMMU_REG_GET8(&al3.ent32, AMD_IOMMU_ACPI_EXTDATRSV) == 0);
}

static void
process_ivhd(amd_iommu_acpi_t *acpi, ivhd_t *ivhdp)
{
	ivhd_container_t *c;
	caddr_t ivhd_end;
	caddr_t ivhd_tot_end;
	caddr_t cp;

	ASSERT(ivhdp->ivhd_type == 0x10);

	c = kmem_zalloc(sizeof (ivhd_container_t), KM_SLEEP);
	c->ivhdc_ivhd = kmem_alloc(sizeof (ivhd_t), KM_SLEEP);
	*(c->ivhdc_ivhd) = *ivhdp;

	if (acpi->acp_first_ivhdc == NULL)
		acpi->acp_first_ivhdc = c;
	else
		acpi->acp_last_ivhdc->ivhdc_next = c;

	acpi->acp_last_ivhdc = c;

	ivhd_end = (caddr_t)ivhdp + sizeof (ivhd_t);
	ivhd_tot_end = (caddr_t)ivhdp + ivhdp->ivhd_len;

	for (cp = ivhd_end; cp < ivhd_tot_end; cp += type_byte_size(cp)) {
		/* 16 byte and 32 byte size are currently reserved */
		switch (type_byte_size(cp)) {
		case 4:
			process_4byte_deventry(c, cp);
			break;
		case 8:
			process_8byte_deventry(c, cp);
			break;
		case 16:
		case 32:
			/* Reserved */
			break;
		default:
			cmn_err(CE_WARN, "%s: unsupported length for device "
			    "entry in ACPI IVRS table's IVHD entry",
			    amd_iommu_modname);
			break;
		}
	}
}

static void
process_ivmd(amd_iommu_acpi_t *acpi, ivmd_t *ivmdp)
{
	ivmd_container_t *c;

	ASSERT(ivmdp->ivmd_type != 0x10);

	c = kmem_zalloc(sizeof (ivmd_container_t), KM_SLEEP);
	c->ivmdc_ivmd = kmem_alloc(sizeof (ivmd_t), KM_SLEEP);
	*(c->ivmdc_ivmd) = *ivmdp;

	if (acpi->acp_first_ivmdc == NULL)
		acpi->acp_first_ivmdc = c;
	else
		acpi->acp_last_ivmdc->ivmdc_next = c;

	acpi->acp_last_ivmdc = c;
}

int
amd_iommu_acpi_init(void)
{
	ivrs_t *ivrsp;
	caddr_t ivrsp_end;
	caddr_t table_end;
	caddr_t cp;
	uint8_t type8;
	amd_iommu_acpi_t *acpi;
	align_ivhd_t al_vhd = {0};
	align_ivmd_t al_vmd = {0};

	if (AcpiGetTable(IVRS_SIG, 1, (ACPI_TABLE_HEADER **)&ivrsp) != AE_OK) {
		cmn_err(CE_NOTE, "!amd_iommu: No AMD IOMMU ACPI IVRS table");
		return (DDI_FAILURE);
	}

	/*
	 * Reserved field must be 0
	 */
	ASSERT(ivrsp->ivrs_resv == 0);

	ASSERT(AMD_IOMMU_REG_GET32(&ivrsp->ivrs_ivinfo,
	    AMD_IOMMU_ACPI_IVINFO_RSV1) == 0);
	ASSERT(AMD_IOMMU_REG_GET32(&ivrsp->ivrs_ivinfo,
	    AMD_IOMMU_ACPI_IVINFO_RSV2) == 0);

	ivrsp_end = (caddr_t)ivrsp + sizeof (struct ivrs);
	table_end = (caddr_t)ivrsp + ivrsp->ivrs_hdr.Length;

	acpi = kmem_zalloc(sizeof (amd_iommu_acpi_t), KM_SLEEP);
	acpi->acp_ivrs = kmem_alloc(sizeof (ivrs_t), KM_SLEEP);
	*(acpi->acp_ivrs) = *ivrsp;

	for (cp = ivrsp_end; cp < table_end; cp += (al_vhd.ivhdp)->ivhd_len) {
		al_vhd.cp = cp;
		if (al_vhd.ivhdp->ivhd_type == 0x10)
			process_ivhd(acpi, al_vhd.ivhdp);
	}

	for (cp = ivrsp_end; cp < table_end; cp += (al_vmd.ivmdp)->ivmd_len) {
		al_vmd.cp = cp;
		type8 = al_vmd.ivmdp->ivmd_type;
		if (type8 == 0x20 || type8 == 0x21 || type8 == 0x22)
			process_ivmd(acpi, al_vmd.ivmdp);
	}

	if (create_acpi_hash(acpi) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	amd_iommu_acpi_table_fini(&acpi);

	ASSERT(acpi == NULL);

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_ACPI) {
		dump_acpi_aliases();
		debug_enter("dump");
	}

	return (DDI_SUCCESS);
}

static ivhd_deventry_t *
free_ivhd_deventry(ivhd_deventry_t *devp)
{
	ivhd_deventry_t *next = devp->idev_next;

	kmem_free(devp, sizeof (ivhd_deventry_t));

	return (next);
}

static ivhd_container_t *
free_ivhd_container(ivhd_container_t *ivhdcp)
{
	ivhd_container_t *next = ivhdcp->ivhdc_next;
	ivhd_deventry_t *devp;

	for (devp = ivhdcp->ivhdc_first_deventry; devp; ) {
		devp = free_ivhd_deventry(devp);
	}

	kmem_free(ivhdcp->ivhdc_ivhd, sizeof (ivhd_t));
	kmem_free(ivhdcp, sizeof (ivhd_container_t));

	return (next);
}

static ivmd_container_t *
free_ivmd_container(ivmd_container_t *ivmdcp)
{
	ivmd_container_t *next = ivmdcp->ivmdc_next;

	kmem_free(ivmdcp->ivmdc_ivmd, sizeof (ivmd_t));
	kmem_free(ivmdcp, sizeof (ivmd_container_t));

	return (next);
}

void
amd_iommu_acpi_fini(void)
{
}

/*
 * TODO: Do we need to free the ACPI table for om GetFirmwareTable()
 */
static void
amd_iommu_acpi_table_fini(amd_iommu_acpi_t **acpipp)
{
	amd_iommu_acpi_t *acpi = *acpipp;
	ivhd_container_t *ivhdcp;
	ivmd_container_t *ivmdcp;

	ASSERT(acpi);

	for (ivhdcp = acpi->acp_first_ivhdc; ivhdcp; ) {
		ivhdcp = free_ivhd_container(ivhdcp);
	}
	for (ivmdcp = acpi->acp_first_ivmdc; ivmdcp; ) {
		ivmdcp = free_ivmd_container(ivmdcp);
	}

	kmem_free(acpi->acp_ivrs, sizeof (struct ivrs));
	kmem_free(acpi, sizeof (amd_iommu_acpi_t));

	*acpipp = NULL;
}

static uint16_t
deviceid_hashfn(uint16_t deviceid)
{
	return (deviceid % AMD_IOMMU_ACPI_INFO_HASH_SZ);
}

static void
add_deventry_info(ivhd_t *ivhdp, ivhd_deventry_t *deventry,
    amd_iommu_acpi_ivhd_t **hash)
{
	static amd_iommu_acpi_ivhd_t *last;
	amd_iommu_acpi_ivhd_t *acpi_ivhdp;
	uint8_t uint8_flags;
	uint16_t uint16_info;
	uint16_t idx;

	if (deventry->idev_type == DEVENTRY_RANGE_END) {
		ASSERT(last);
		acpi_ivhdp = last;
		last = NULL;
		ASSERT(acpi_ivhdp->ach_dev_type == DEVENTRY_RANGE ||
		    acpi_ivhdp->ach_dev_type == DEVENTRY_ALIAS_RANGE ||
		    acpi_ivhdp->ach_dev_type == DEVENTRY_EXTENDED_RANGE);
		ASSERT(acpi_ivhdp->ach_deviceid_end == -1);
		acpi_ivhdp->ach_deviceid_end = deventry->idev_deviceid;
		/* TODO ASSERT data is 0 */
		return;
	}

	ASSERT(last == NULL);
	acpi_ivhdp = kmem_zalloc(sizeof (*acpi_ivhdp), KM_SLEEP);

	uint8_flags = ivhdp->ivhd_flags;

#ifdef BROKEN_ASSERT
	ASSERT(AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVHD_FLAGS_RSV) == 0);
#endif

	acpi_ivhdp->ach_IotlbSup = AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVHD_FLAGS_IOTLBSUP);
	acpi_ivhdp->ach_Isoc = AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVHD_FLAGS_ISOC);
	acpi_ivhdp->ach_ResPassPW = AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVHD_FLAGS_RESPASSPW);
	acpi_ivhdp->ach_PassPW = AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVHD_FLAGS_PASSPW);
	acpi_ivhdp->ach_HtTunEn = AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVHD_FLAGS_HTTUNEN);

	/* IVHD fields */
	acpi_ivhdp->ach_IOMMU_deviceid = ivhdp->ivhd_deviceid;
	acpi_ivhdp->ach_IOMMU_cap_off = ivhdp->ivhd_cap_off;
	acpi_ivhdp->ach_IOMMU_reg_base = ivhdp->ivhd_reg_base;
	acpi_ivhdp->ach_IOMMU_pci_seg = ivhdp->ivhd_pci_seg;

	/* IVHD IOMMU info fields */
	uint16_info = ivhdp->ivhd_iommu_info;

#ifdef BROKEN_ASSERT
	ASSERT(AMD_IOMMU_REG_GET16(&uint16_info,
	    AMD_IOMMU_ACPI_IOMMU_INFO_RSV1) == 0);
#endif

	acpi_ivhdp->ach_IOMMU_UnitID = AMD_IOMMU_REG_GET16(&uint16_info,
	    AMD_IOMMU_ACPI_IOMMU_INFO_UNITID);
	ASSERT(AMD_IOMMU_REG_GET16(&uint16_info,
	    AMD_IOMMU_ACPI_IOMMU_INFO_RSV2) == 0);
	acpi_ivhdp->ach_IOMMU_MSInum = AMD_IOMMU_REG_GET16(&uint16_info,
	    AMD_IOMMU_ACPI_IOMMU_INFO_MSINUM);

	/* Initialize  deviceids to -1 */
	acpi_ivhdp->ach_deviceid_start = -1;
	acpi_ivhdp->ach_deviceid_end = -1;
	acpi_ivhdp->ach_src_deviceid = -1;

	/* All range type entries are put on hash entry 0 */
	switch (deventry->idev_type) {
	case DEVENTRY_ALL:
		acpi_ivhdp->ach_deviceid_start = 0;
		acpi_ivhdp->ach_deviceid_end = (uint16_t)-1;
		acpi_ivhdp->ach_dev_type = DEVENTRY_ALL;
		idx = AMD_IOMMU_ACPI_INFO_HASH_SZ;
		break;
	case DEVENTRY_SELECT:
		acpi_ivhdp->ach_deviceid_start = deventry->idev_deviceid;
		acpi_ivhdp->ach_deviceid_end = deventry->idev_deviceid;
		acpi_ivhdp->ach_dev_type = DEVENTRY_SELECT;
		idx = deviceid_hashfn(deventry->idev_deviceid);
		break;
	case DEVENTRY_RANGE:
		acpi_ivhdp->ach_deviceid_start = deventry->idev_deviceid;
		acpi_ivhdp->ach_deviceid_end = -1;
		acpi_ivhdp->ach_dev_type = DEVENTRY_RANGE;
		idx = AMD_IOMMU_ACPI_INFO_HASH_SZ;
		last = acpi_ivhdp;
		break;
	case DEVENTRY_RANGE_END:
		cmn_err(CE_PANIC, "%s: Unexpected Range End Deventry",
		    amd_iommu_modname);
		/*NOTREACHED*/
		break;
	case DEVENTRY_ALIAS_SELECT:
		acpi_ivhdp->ach_deviceid_start = deventry->idev_deviceid;
		acpi_ivhdp->ach_deviceid_end = deventry->idev_deviceid;
		acpi_ivhdp->ach_src_deviceid = deventry->idev_src_deviceid;
		acpi_ivhdp->ach_dev_type = DEVENTRY_ALIAS_SELECT;
		idx = deviceid_hashfn(deventry->idev_deviceid);
		break;
	case DEVENTRY_ALIAS_RANGE:
		acpi_ivhdp->ach_deviceid_start = deventry->idev_deviceid;
		acpi_ivhdp->ach_deviceid_end = -1;
		acpi_ivhdp->ach_src_deviceid = deventry->idev_src_deviceid;
		acpi_ivhdp->ach_dev_type = DEVENTRY_ALIAS_RANGE;
		idx = AMD_IOMMU_ACPI_INFO_HASH_SZ;
		last = acpi_ivhdp;
		break;
	case DEVENTRY_EXTENDED_SELECT:
		acpi_ivhdp->ach_deviceid_start = deventry->idev_deviceid;
		acpi_ivhdp->ach_deviceid_end = deventry->idev_deviceid;
		acpi_ivhdp->ach_dev_type = DEVENTRY_EXTENDED_SELECT;
		idx = deviceid_hashfn(deventry->idev_deviceid);
		break;
	case DEVENTRY_EXTENDED_RANGE:
		acpi_ivhdp->ach_deviceid_start = deventry->idev_deviceid;
		acpi_ivhdp->ach_deviceid_end = -1;
		acpi_ivhdp->ach_dev_type = DEVENTRY_EXTENDED_RANGE;
		idx = AMD_IOMMU_ACPI_INFO_HASH_SZ;
		last = acpi_ivhdp;
		break;
	case DEVENTRY_SPECIAL_DEVICE:
		acpi_ivhdp->ach_deviceid_start = -1;
		acpi_ivhdp->ach_deviceid_end = -1;
		acpi_ivhdp->ach_src_deviceid = deventry->idev_src_deviceid;
		acpi_ivhdp->ach_special_handle = deventry->idev_handle;
		acpi_ivhdp->ach_special_variety = deventry->idev_variety;
		idx = AMD_IOMMU_ACPI_INFO_HASH_SZ;
		break;
	default:
		cmn_err(CE_PANIC, "%s: Unsupported deventry type",
		    amd_iommu_modname);
		/*NOTREACHED*/
	}

	acpi_ivhdp->ach_Lint1Pass = deventry->idev_Lint1Pass;
	acpi_ivhdp->ach_Lint0Pass = deventry->idev_Lint0Pass;
	acpi_ivhdp->ach_SysMgt = deventry->idev_SysMgt;
	acpi_ivhdp->ach_NMIPass = deventry->idev_NMIPass;
	acpi_ivhdp->ach_ExtIntPass = deventry->idev_ExtIntPass;
	acpi_ivhdp->ach_INITPass = deventry->idev_INITPass;


	/* extended data */
	if (acpi_ivhdp->ach_dev_type == DEVENTRY_EXTENDED_SELECT ||
	    acpi_ivhdp->ach_dev_type == DEVENTRY_EXTENDED_RANGE) {
		acpi_ivhdp->ach_AtsDisabled = deventry->idev_AtsDisabled;
	}

	/*
	 * Now add it to the hash
	 */
	ASSERT(hash[idx] != acpi_ivhdp);
	acpi_ivhdp->ach_next = hash[idx];
	hash[idx] = acpi_ivhdp;
}

/*
 * A device entry may be declared implicitly as a source device ID
 * in an alias entry. This routine adds it to the hash
 */
static void
add_implicit_deventry(ivhd_container_t *ivhdcp, amd_iommu_acpi_ivhd_t **hash)
{
	ivhd_deventry_t *d;
	int deviceid;

	for (d = ivhdcp->ivhdc_first_deventry; d; d = d->idev_next) {

		if ((d->idev_type != DEVENTRY_ALIAS_SELECT) &&
		    (d->idev_type != DEVENTRY_ALIAS_RANGE))
			continue;

		deviceid = d->idev_src_deviceid;

		if (amd_iommu_lookup_ivhd(deviceid) == NULL) {
			ivhd_deventry_t deventry;

			/* Fake a SELECT entry */
			deventry.idev_type = DEVENTRY_SELECT;
			deventry.idev_len = 4;
			deventry.idev_deviceid = deviceid;
			deventry.idev_src_deviceid = -1;

			deventry.idev_Lint1Pass = d->idev_Lint1Pass;
			deventry.idev_Lint0Pass = d->idev_Lint0Pass;
			deventry.idev_SysMgt = d->idev_SysMgt;
			deventry.idev_NMIPass = d->idev_NMIPass;
			deventry.idev_ExtIntPass = d->idev_ExtIntPass;
			deventry.idev_INITPass = d->idev_INITPass;

			add_deventry_info(ivhdcp->ivhdc_ivhd, &deventry, hash);

			if (amd_iommu_debug & AMD_IOMMU_DEBUG_ACPI) {
				cmn_err(CE_NOTE, "Added implicit IVHD entry "
				    "for: deviceid = %u", deviceid);
			}
		}
	}
}

static void
add_ivhdc_info(ivhd_container_t *ivhdcp, amd_iommu_acpi_ivhd_t **hash)
{
	ivhd_deventry_t *deventry;
	ivhd_t *ivhdp = ivhdcp->ivhdc_ivhd;

	for (deventry = ivhdcp->ivhdc_first_deventry; deventry;
	    deventry = deventry->idev_next) {
		add_deventry_info(ivhdp, deventry, hash);
	}

	add_implicit_deventry(ivhdcp, hash);

}

static void
add_ivhd_info(amd_iommu_acpi_t *acpi, amd_iommu_acpi_ivhd_t **hash)
{
	ivhd_container_t *ivhdcp;

	for (ivhdcp = acpi->acp_first_ivhdc; ivhdcp;
	    ivhdcp = ivhdcp->ivhdc_next) {
		add_ivhdc_info(ivhdcp, hash);
	}
}

static void
set_ivmd_info(ivmd_t *ivmdp, amd_iommu_acpi_ivmd_t **hash)
{
	amd_iommu_acpi_ivmd_t *acpi_ivmdp;
	uint8_t uint8_flags;
	uint16_t idx;

	uint8_flags = ivmdp->ivmd_flags;

	acpi_ivmdp = kmem_zalloc(sizeof (*acpi_ivmdp), KM_SLEEP);

	switch (ivmdp->ivmd_type) {
	case 0x20:
		acpi_ivmdp->acm_deviceid_start = 0;
		acpi_ivmdp->acm_deviceid_end = (uint16_t)-1;
		acpi_ivmdp->acm_dev_type = IVMD_DEVICEID_ALL;
		idx = AMD_IOMMU_ACPI_INFO_HASH_SZ;
		break;
	case 0x21:
		acpi_ivmdp->acm_deviceid_start = ivmdp->ivmd_deviceid;
		acpi_ivmdp->acm_deviceid_end = ivmdp->ivmd_deviceid;
		acpi_ivmdp->acm_dev_type = IVMD_DEVICEID_SELECT;
		idx = deviceid_hashfn(ivmdp->ivmd_deviceid);
		break;
	case 0x22:
		acpi_ivmdp->acm_deviceid_start = ivmdp->ivmd_deviceid;
		acpi_ivmdp->acm_deviceid_end = ivmdp->ivmd_auxdata;
		acpi_ivmdp->acm_dev_type = IVMD_DEVICEID_RANGE;
		idx = AMD_IOMMU_ACPI_INFO_HASH_SZ;
		break;
	default:
		cmn_err(CE_PANIC, "Unknown AMD IOMMU ACPI IVMD deviceid type: "
		    "%x", ivmdp->ivmd_type);
		/*NOTREACHED*/
	}

	ASSERT(AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVMD_RSV) == 0);

	acpi_ivmdp->acm_ExclRange = AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVMD_EXCL_RANGE);
	acpi_ivmdp->acm_IW = AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVMD_IW);
	acpi_ivmdp->acm_IR = AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVMD_IR);
	acpi_ivmdp->acm_Unity = AMD_IOMMU_REG_GET8(&uint8_flags,
	    AMD_IOMMU_ACPI_IVMD_UNITY);

	acpi_ivmdp->acm_ivmd_phys_start = ivmdp->ivmd_phys_start;
	acpi_ivmdp->acm_ivmd_phys_len = ivmdp->ivmd_phys_len;

	acpi_ivmdp->acm_next = hash[idx];
	hash[idx] = acpi_ivmdp;
}

static void
add_ivmdc_info(ivmd_container_t *ivmdcp, amd_iommu_acpi_ivmd_t **hash)
{
	set_ivmd_info(ivmdcp->ivmdc_ivmd, hash);
}

static void
add_ivmd_info(amd_iommu_acpi_t *acpi, amd_iommu_acpi_ivmd_t **hash)
{
	ivmd_container_t *ivmdcp;

	for (ivmdcp = acpi->acp_first_ivmdc; ivmdcp;
	    ivmdcp = ivmdcp->ivmdc_next) {
		add_ivmdc_info(ivmdcp, hash);
	}
}

static void
add_global_info(amd_iommu_acpi_t *acpi, amd_iommu_acpi_global_t *global)
{
	uint32_t ivrs_ivinfo = acpi->acp_ivrs->ivrs_ivinfo;

	global->acg_HtAtsResv =
	    AMD_IOMMU_REG_GET32(&ivrs_ivinfo, AMD_IOMMU_ACPI_HT_ATSRSV);
	global->acg_VAsize =
	    AMD_IOMMU_REG_GET32(&ivrs_ivinfo, AMD_IOMMU_ACPI_VA_SIZE);
	global->acg_PAsize =
	    AMD_IOMMU_REG_GET32(&ivrs_ivinfo, AMD_IOMMU_ACPI_PA_SIZE);
}

static int
create_acpi_hash(amd_iommu_acpi_t *acpi)
{
	/* Last hash entry is for deviceid ranges including "all" */

	amd_iommu_acpi_global = kmem_zalloc(sizeof (amd_iommu_acpi_global_t),
	    KM_SLEEP);

	amd_iommu_acpi_ivhd_hash = kmem_zalloc(sizeof (amd_iommu_acpi_ivhd_t *)
	    * (AMD_IOMMU_ACPI_INFO_HASH_SZ + 1), KM_SLEEP);

	amd_iommu_acpi_ivmd_hash = kmem_zalloc(sizeof (amd_iommu_acpi_ivmd_t *)
	    * (AMD_IOMMU_ACPI_INFO_HASH_SZ + 1), KM_SLEEP);

	add_global_info(acpi, amd_iommu_acpi_global);

	add_ivhd_info(acpi, amd_iommu_acpi_ivhd_hash);

	add_ivmd_info(acpi, amd_iommu_acpi_ivmd_hash);

	return (DDI_SUCCESS);
}

static void
set_deventry(amd_iommu_t *iommu, int entry, amd_iommu_acpi_ivhd_t *hinfop)
{
	uint64_t *dentry;

	dentry = (uint64_t *)(intptr_t)
	    &iommu->aiomt_devtbl[entry * AMD_IOMMU_DEVTBL_ENTRY_SZ];

	AMD_IOMMU_REG_SET64(&(dentry[1]), AMD_IOMMU_DEVTBL_SYSMGT,
	    hinfop->ach_SysMgt);
}

/* Initialize device table according to IVHD */
int
amd_iommu_acpi_init_devtbl(amd_iommu_t *iommu)
{
	int i, j;
	amd_iommu_acpi_ivhd_t *hinfop;

	for (i = 0; i <= AMD_IOMMU_ACPI_INFO_HASH_SZ; i++) {
		for (hinfop = amd_iommu_acpi_ivhd_hash[i];
		    hinfop; hinfop = hinfop->ach_next) {

			if (hinfop->ach_IOMMU_deviceid != iommu->aiomt_bdf)
				continue;

			switch (hinfop->ach_dev_type) {
			case DEVENTRY_ALL:
				for (j = 0; j < AMD_IOMMU_MAX_DEVICEID; j++)
					set_deventry(iommu, j, hinfop);
				break;
			case DEVENTRY_SELECT:
			case DEVENTRY_EXTENDED_SELECT:
				set_deventry(iommu,
				    hinfop->ach_deviceid_start,
				    hinfop);
				break;
			case DEVENTRY_RANGE:
			case DEVENTRY_EXTENDED_RANGE:
				for (j = hinfop->ach_deviceid_start;
				    j <= hinfop->ach_deviceid_end;
				    j++)
					set_deventry(iommu, j, hinfop);
				break;
			case DEVENTRY_ALIAS_SELECT:
			case DEVENTRY_ALIAS_RANGE:
			case DEVENTRY_SPECIAL_DEVICE:
				set_deventry(iommu,
				    hinfop->ach_src_deviceid,
				    hinfop);
				break;
			default:
				cmn_err(CE_WARN,
				    "%s: Unknown deventry type",
				    amd_iommu_modname);
				return (DDI_FAILURE);
			}
		}
	}

	return (DDI_SUCCESS);
}

amd_iommu_acpi_global_t *
amd_iommu_lookup_acpi_global(void)
{
	ASSERT(amd_iommu_acpi_global);

	return (amd_iommu_acpi_global);
}

amd_iommu_acpi_ivhd_t *
amd_iommu_lookup_all_ivhd(void)
{
	amd_iommu_acpi_ivhd_t *hinfop;

	hinfop = amd_iommu_acpi_ivhd_hash[AMD_IOMMU_ACPI_INFO_HASH_SZ];
	for (; hinfop; hinfop = hinfop->ach_next) {
		if (hinfop->ach_deviceid_start == 0 &&
		    hinfop->ach_deviceid_end == (uint16_t)-1) {
			break;
		}
	}

	return (hinfop);
}

amd_iommu_acpi_ivmd_t *
amd_iommu_lookup_all_ivmd(void)
{
	amd_iommu_acpi_ivmd_t *minfop;

	minfop = amd_iommu_acpi_ivmd_hash[AMD_IOMMU_ACPI_INFO_HASH_SZ];
	for (; minfop; minfop = minfop->acm_next) {
		if (minfop->acm_deviceid_start == 0 &&
		    minfop->acm_deviceid_end == (uint16_t)-1) {
			break;
		}
	}

	return (minfop);
}

amd_iommu_acpi_ivhd_t *
amd_iommu_lookup_any_ivhd(amd_iommu_t *iommu)
{
	int i;
	amd_iommu_acpi_ivhd_t *hinfop;

	for (i = AMD_IOMMU_ACPI_INFO_HASH_SZ; i >= 0; i--) {
		hinfop = amd_iommu_acpi_ivhd_hash[i];
		if ((hinfop != NULL) &&
		    hinfop->ach_IOMMU_deviceid == iommu->aiomt_bdf)
			break;
	}

	return (hinfop);
}

amd_iommu_acpi_ivmd_t *
amd_iommu_lookup_any_ivmd(void)
{
	int i;
	amd_iommu_acpi_ivmd_t *minfop;

	for (i = AMD_IOMMU_ACPI_INFO_HASH_SZ; i >= 0; i--) {
		if ((minfop = amd_iommu_acpi_ivmd_hash[i]) != NULL)
			break;
	}

	return (minfop);
}

static void
dump_acpi_aliases(void)
{
	amd_iommu_acpi_ivhd_t *hinfop;
	uint16_t idx;

	for (idx = 0; idx <= AMD_IOMMU_ACPI_INFO_HASH_SZ; idx++) {
		hinfop = amd_iommu_acpi_ivhd_hash[idx];
		for (; hinfop; hinfop = hinfop->ach_next) {
			cmn_err(CE_NOTE, "start=%d, end=%d, src_bdf=%d",
			    hinfop->ach_deviceid_start,
			    hinfop->ach_deviceid_end,
			    hinfop->ach_src_deviceid);
		}
	}
}

amd_iommu_acpi_ivhd_t *
amd_iommu_lookup_ivhd(int32_t deviceid)
{
	amd_iommu_acpi_ivhd_t *hinfop;
	uint16_t idx;

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_ACPI) {
		cmn_err(CE_NOTE, "Attempting to get ACPI IVHD info "
		    "for deviceid: %d", deviceid);
	}

	ASSERT(amd_iommu_acpi_ivhd_hash);

	/* check if special device */
	if (deviceid == -1) {
		hinfop = amd_iommu_acpi_ivhd_hash[AMD_IOMMU_ACPI_INFO_HASH_SZ];
		for (; hinfop; hinfop = hinfop->ach_next) {
			if (hinfop->ach_deviceid_start  == -1 &&
			    hinfop->ach_deviceid_end == -1) {
				break;
			}
		}
		return (hinfop);
	}

	/* First search for an exact match */

	idx = deviceid_hashfn(deviceid);


range:
	hinfop = amd_iommu_acpi_ivhd_hash[idx];

	for (; hinfop; hinfop = hinfop->ach_next) {
		if (deviceid < hinfop->ach_deviceid_start ||
		    deviceid > hinfop->ach_deviceid_end)
			continue;

		if (amd_iommu_debug & AMD_IOMMU_DEBUG_ACPI) {
			cmn_err(CE_NOTE, "Found ACPI IVHD match: %p, "
			    "actual deviceid = %u, start = %u, end = %u",
			    (void *)hinfop, deviceid,
			    hinfop->ach_deviceid_start,
			    hinfop->ach_deviceid_end);
		}
		goto out;
	}

	if (idx !=  AMD_IOMMU_ACPI_INFO_HASH_SZ) {
		idx = AMD_IOMMU_ACPI_INFO_HASH_SZ;
		goto range;
	}

out:
	if (amd_iommu_debug & AMD_IOMMU_DEBUG_ACPI) {
		cmn_err(CE_NOTE, "%u: %s ACPI IVHD %p", deviceid,
		    hinfop ? "GOT" : "Did NOT get", (void *)hinfop);
	}

	return (hinfop);
}

amd_iommu_acpi_ivmd_t *
amd_iommu_lookup_ivmd(int32_t deviceid)
{
	amd_iommu_acpi_ivmd_t *minfop;
	uint16_t idx;

	if (amd_iommu_debug & AMD_IOMMU_DEBUG_ACPI) {
		cmn_err(CE_NOTE, "Attempting to get ACPI IVMD info "
		    "for deviceid: %u", deviceid);
	}

	ASSERT(amd_iommu_acpi_ivmd_hash);

	/* First search for an exact match */

	idx = deviceid_hashfn(deviceid);

range:
	minfop = amd_iommu_acpi_ivmd_hash[idx];

	for (; minfop; minfop = minfop->acm_next) {
		if (deviceid < minfop->acm_deviceid_start &&
		    deviceid > minfop->acm_deviceid_end)
			continue;

		if (amd_iommu_debug & AMD_IOMMU_DEBUG_ACPI) {
			cmn_err(CE_NOTE, "Found ACPI IVMD match: %p, "
			    "actual deviceid = %u, start = %u, end = %u",
			    (void *)minfop, deviceid,
			    minfop->acm_deviceid_start,
			    minfop->acm_deviceid_end);
		}

		goto out;
	}

	if (idx !=  AMD_IOMMU_ACPI_INFO_HASH_SZ) {
		idx = AMD_IOMMU_ACPI_INFO_HASH_SZ;
		goto range;
	}

out:
	if (amd_iommu_debug & AMD_IOMMU_DEBUG_ACPI) {
		cmn_err(CE_NOTE, "%u: %s ACPI IVMD info %p", deviceid,
		    minfop ? "GOT" : "Did NOT get", (void *)minfop);
	}

	return (minfop);
}
