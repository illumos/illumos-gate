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

#include "amd_iommu_acpi.h"
#include "amd_iommu_impl.h"

static int
type_byte_size(char *cp)
{
	uint8_t type8 = *((uint8_t *)cp);
	uint8_t len_bits;

	len_bits = AMD_IOMMU_REG_GET(type8, AMD_IOMMU_ACPI_DEVENTRY_LEN);

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
	int entry_type = (uint8_t)*cp;
	ivhd_deventry_t deventry = {4};
	ivhd_deventry_t *devp;
	uint8_t setting8;

	switch (entry_type) {
	case 1:
		deventry.idev_flags = DEVENTRY_ALL;
		break;
	case 2:
		deventry.idev_flags = DEVENTRY_SELECT;
		/*LINTED*/
		deventry.idev_bdf = *((uint16_t *)&cp[1]);
		break;
	case 3:
		deventry.idev_flags = DEVENTRY_RANGE;
		/*LINTED*/
		deventry.idev_bdf = *((uint16_t *)&cp[1]);
		break;
	case 4:
		deventry.idev_flags = DEVENTRY_RANGE_END;
		/*LINTED*/
		deventry.idev_bdf = *((uint16_t *)&cp[1]);
		break;
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

	setting8 = (uint8_t)cp[3];

	devp->idev_Lint1Pass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_LINT1PASS);

	devp->idev_Lint0Pass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_LINT0PASS);

	devp->idev_SysMgt = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_SYSMGT);

	devp->idev_NMIPass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_NMIPASS);

	devp->idev_ExtIntPass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_EXTINTPASS);

	devp->idev_INITPass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_INITPASS);
}

static void
process_8byte_deventry(ivhd_container_t *c, char *cp)
{
	uint8_t setting8;
	uint32_t ext_setting32;
	int entry_type = (uint8_t)*cp;
	ivhd_deventry_t deventry = {8};
	ivhd_deventry_t *devp;

	switch (entry_type) {
	case 66:
		deventry.idev_flags = DEVENTRY_ALIAS_SELECT;
		/*LINTED*/
		deventry.idev_bdf = *((uint16_t *)&cp[1]);
		/*LINTED*/
		deventry.idev_src_bdf = *((uint16_t *)&cp[5]);
		break;
	case 67:
		deventry.idev_flags = DEVENTRY_ALIAS_RANGE;
		/*LINTED*/
		deventry.idev_bdf = *((uint16_t *)&cp[1]);
		/*LINTED*/
		deventry.idev_src_bdf = *((uint16_t *)&cp[5]);

		break;
	case 70:
		deventry.idev_flags = DEVENTRY_EXTENDED_SELECT;
		/*LINTED*/
		deventry.idev_bdf = *((uint16_t *)&cp[1]);
		break;
	case 71:
		deventry.idev_flags = DEVENTRY_EXTENDED_RANGE;
		/*LINTED*/
		deventry.idev_bdf = *((uint16_t *)&cp[1]);
		break;
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

	setting8 = (uint8_t)cp[3];

	devp->idev_Lint1Pass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_LINT1PASS);

	devp->idev_Lint0Pass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_LINT0PASS);

	devp->idev_SysMgt = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_SYSMGT);

	devp->idev_NMIPass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_NMIPASS);

	devp->idev_ExtIntPass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_EXTINTPASS);

	devp->idev_INITPass = AMD_IOMMU_REG_GET(setting8,
	    AMD_IOMMU_ACPI_INITPASS);

	/*LINTED*/
	ext_setting32 = *(uint32_t *)(&cp[4]);

	if (entry_type == 70 || entry_type == 71) {
		devp->idev_AtsDisabled = AMD_IOMMU_REG_GET(ext_setting32,
		    AMD_IOMMU_ACPI_ATSDISABLED);
	}
}

static void
process_ivhd(amd_iommu_acpi_t *acpi, ivhd_t *ivhdp)
{
	ivhd_container_t *c;
	caddr_t ivhd_end;
	caddr_t ivhd_tot_end;
	caddr_t cp;

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
amd_iommu_acpi_init(amd_iommu_acpi_t **acpipp)
{
	ivrs_t *ivrsp;
	caddr_t ivrsp_end;
	caddr_t table_end;
	caddr_t cp;
	uint8_t type8;
	amd_iommu_acpi_t *acpi;

	if (AcpiGetTable(IVRS_SIG, 1, (ACPI_TABLE_HEADER **)&ivrsp) != AE_OK) {
		cmn_err(CE_NOTE, "!amd_iommu: No AMD IOMMU ACPI IVRS table");
		return (DDI_FAILURE);
	}

	amd_iommu_htatsresv =
	    AMD_IOMMU_REG_GET(ivrsp->ivrs_ivinfo, AMD_IOMMU_HT_ATSRSV);
	amd_iommu_vasize =
	    AMD_IOMMU_REG_GET(ivrsp->ivrs_ivinfo, AMD_IOMMU_VA_SIZE);
	amd_iommu_pasize =
	    AMD_IOMMU_REG_GET(ivrsp->ivrs_ivinfo, AMD_IOMMU_PA_SIZE);

	ivrsp_end = (caddr_t)ivrsp + sizeof (struct ivrs);
	table_end = (caddr_t)ivrsp + ivrsp->ivrs_hdr.Length;

	acpi = kmem_zalloc(sizeof (amd_iommu_acpi_t), KM_SLEEP);
	acpi->acp_ivrs = kmem_alloc(sizeof (ivrs_t), KM_SLEEP);
	*(acpi->acp_ivrs) = *ivrsp;

	/*LINTED*/
	for (cp = ivrsp_end; cp < table_end; cp += ((ivhd_t *)cp)->ivhd_len) {
		type8 = *((uint8_t *)cp);
		if (type8 == 0x10) {
			/*LINTED*/
			process_ivhd(acpi, (ivhd_t *)cp);
		}
	}

	/*LINTED*/
	for (cp = ivrsp_end; cp < table_end; cp += ((ivmd_t *)cp)->ivmd_len) {
		type8 = *((uint8_t *)cp);
		if (type8 == 0x20 || type8 == 0x21 || type8 == 0x22) {
			/*LINTED*/
			process_ivmd(acpi, (ivmd_t *)cp);
		}
	}

	*acpipp = acpi;

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
amd_iommu_acpi_fini(amd_iommu_acpi_t **acpipp)
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
alias_hashfn(uint16_t bdf)
{
	return (bdf % AMD_IOMMU_ALIAS_HASH_SZ);
}

static void
alias_create(uint16_t bdf, uint16_t src_bdf, amd_iommu_alias_t **alias)
{
	amd_iommu_alias_t *alias_ent;
	uint16_t idx;

	ASSERT(alias);

	alias_ent = kmem_zalloc(sizeof (amd_iommu_alias_t), KM_SLEEP);
	alias_ent->al_bdf = bdf;
	alias_ent->al_src_bdf = src_bdf;

	idx = alias_hashfn(bdf);
	alias_ent->al_next = alias[idx];
	alias[idx] = alias_ent;

	if (amd_iommu_debug == AMD_IOMMU_DEBUG_ACPI) {
		cmn_err(CE_NOTE, "Setting alias: 0x%x is aliased to 0x%x, "
		    "hash idx 0x%x", bdf, src_bdf, idx);
	}
}

static void
parse_alias_select(ivhd_deventry_t *deventry, amd_iommu_alias_t **alias)
{
	ASSERT(deventry->idev_flags == DEVENTRY_ALIAS_SELECT);
	ASSERT(deventry->idev_len == 8);

	alias_create(deventry->idev_bdf, deventry->idev_src_bdf, alias);
}

static ivhd_deventry_t *
parse_alias_range(ivhd_deventry_t *start_deventry, amd_iommu_alias_t **alias)
{
	uint16_t bdf;
	uint16_t start_bdf;
	uint16_t src_bdf;
	uint16_t end_bdf;
	ivhd_deventry_t *deventry = start_deventry;
	const char *f = "parse_alias_range";

	ASSERT(start_deventry->idev_flags == DEVENTRY_ALIAS_RANGE);
	ASSERT(start_deventry->idev_len == 8);

	start_bdf = start_deventry->idev_bdf;
	src_bdf = start_deventry->idev_src_bdf;

	for (deventry = start_deventry; deventry &&
	    deventry->idev_flags != DEVENTRY_RANGE_END;
	    deventry = deventry->idev_next)
		;

	if (deventry == NULL) {
		cmn_err(CE_WARN, "%s: %s: Failed to find ACPI device alias "
		    "range end. Skipping alias entry with BDF = %u, "
		    "source BDF = %u", amd_iommu_modname, f, start_bdf,
		    src_bdf);
		return (start_deventry->idev_next);
	}

	ASSERT(deventry->idev_flags == DEVENTRY_RANGE_END);
	ASSERT(deventry->idev_len == 4);
	end_bdf = deventry->idev_bdf;

	for (bdf = start_bdf; bdf <= end_bdf; bdf++) {
		alias_create(bdf, src_bdf, alias);
	}

	return (deventry->idev_next);
}

static ivhd_deventry_t *
parse_alias(ivhd_deventry_t *deventry, amd_iommu_alias_t **alias)
{
	ASSERT(deventry->idev_flags == DEVENTRY_ALIAS_SELECT ||
	    deventry->idev_flags == DEVENTRY_ALIAS_RANGE);
	ASSERT(deventry->idev_len == 8);

	switch (deventry->idev_flags) {
	case DEVENTRY_ALIAS_SELECT:
		parse_alias_select(deventry, alias);
		deventry = deventry->idev_next;
		break;
	case DEVENTRY_ALIAS_RANGE:
		deventry = parse_alias_range(deventry, alias);
		break;
	default:
		cmn_err(CE_PANIC, "%s: Invalid deviceid alaias type: %d",
		    amd_iommu_modname, deventry->idev_flags);
		/*NOTREACHED*/
	}
	return (deventry);
}

static void
parse_deventry_list(ivhd_container_t *ivhdcp, amd_iommu_alias_t **alias)
{
	ivhd_deventry_t *deventry;

	for (deventry = ivhdcp->ivhdc_first_deventry; deventry; ) {
		if (deventry->idev_flags == DEVENTRY_ALIAS_SELECT ||
		    deventry->idev_flags == DEVENTRY_ALIAS_RANGE) {
			deventry = parse_alias(deventry, alias);
		} else {
			deventry = deventry->idev_next;
		}
	}
}

static void
parse_amd_iommu_acpi(amd_iommu_acpi_t *acpip, amd_iommu_alias_t **alias)
{
	ivhd_container_t *ivhdcp;

	for (ivhdcp = acpip->acp_first_ivhdc; ivhdcp;
	    ivhdcp = ivhdcp->ivhdc_next) {
		parse_deventry_list(ivhdcp, alias);
	}
}

static void
amd_iommu_generate_alias_hash(void)
{
	ASSERT(MUTEX_HELD(&amd_iommu_global_lock));
	if (amd_iommu_alias != NULL) {
		return;
	}
	amd_iommu_alias = kmem_zalloc(AMD_IOMMU_ALIAS_HASH_SZ *
	    sizeof (amd_iommu_alias_t *), KM_SLEEP);

	parse_amd_iommu_acpi(amd_iommu_acpip, amd_iommu_alias);
}

int
amd_iommu_lookup_src_bdf(uint16_t bdf, uint16_t *src_bdfp)
{
	amd_iommu_alias_t *alias_ent;
	uint16_t idx;

	*src_bdfp = 0;

	if (amd_iommu_debug == AMD_IOMMU_DEBUG_ACPI) {
		cmn_err(CE_NOTE, "Attempting to get src bdf for bdf: %u", bdf);
	}

	mutex_enter(&amd_iommu_global_lock);
	if (amd_iommu_alias == NULL) {
		amd_iommu_generate_alias_hash();
		ASSERT(amd_iommu_alias != NULL);
	}

	idx = alias_hashfn(bdf);

	for (alias_ent = amd_iommu_alias[idx]; alias_ent;
	    alias_ent = alias_ent->al_next) {

		if (amd_iommu_debug == AMD_IOMMU_DEBUG_ACPI) {
			cmn_err(CE_NOTE, "Trying alias_ent: %p, has bdf = %u "
			    "expecting BDF %u", (void *)alias_ent,
			    alias_ent->al_bdf, bdf);
		}

		if (alias_ent->al_bdf == bdf) {
			*src_bdfp = alias_ent->al_src_bdf;
			break;
		}
	}

	mutex_exit(&amd_iommu_global_lock);

	if (alias_ent == NULL) {
		*src_bdfp = bdf;
	}

	if (amd_iommu_debug == AMD_IOMMU_DEBUG_ACPI) {
		cmn_err(CE_NOTE, "%s - using src bdf %u for bdf: %u",
		    alias_ent ? "GOT alias" : "Did NOT get alias",
		    *src_bdfp, bdf);
	}

	return (DDI_SUCCESS);
}
