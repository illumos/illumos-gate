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
 */

/*
 * Copyright (c) 2009, Intel Corporation.
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
#include <sys/smbios.h>
#include <sys/apic.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/immu.h>
#include <sys/smp_impldefs.h>

static void dmar_table_destroy(dmar_table_t *tbl);

/*
 * internal global variables
 */
static char	*dmar_raw;		/* raw DMAR ACPI table */
static dmar_table_t *dmar_table;	/* converted form of DMAR table */

/*
 * global variables exported outside this file
 */
boolean_t dmar_print = B_FALSE;
kmutex_t ioapic_drhd_lock;
list_t ioapic_drhd_list;

/* ######################################################################### */

/*
 * helper functions to read the "raw" DMAR table
 */

static uint8_t
get_uint8(char *cp)
{
	uint8_t val = *((uint8_t *)cp);
	return (val);
}

static uint16_t
get_uint16(char *cp)
{
	uint16_t val = *((uint16_t *)cp);
	return (val);
}

static uint32_t
get_uint32(char *cp)
{
	uint32_t val = *((uint32_t *)cp);
	return (val);
}

static uint64_t
get_uint64(char *cp)
{
	uint64_t val = *((uint64_t *)cp);
	return (val);
}

static char *
get_str(char *cp, uint_t len)
{
	char *str = kmem_alloc(len + 1, KM_SLEEP);

	(void) strlcpy(str, cp, len + 1);

	return (str);
}

static void
scope_list_free(list_t *scope_list)
{
	scope_t *scope;

	if (list_is_empty(scope_list)) {
		list_destroy(scope_list);
		return;
	}

	while ((scope = list_remove_head(scope_list)) != NULL) {
		kmem_free(scope, sizeof (scope_t));
	}

	ASSERT(list_is_empty(scope_list));
	list_destroy(scope_list);
}

static void
drhd_list_destroy(list_t *drhd_list)
{
	drhd_t *drhd;

	ASSERT(drhd_list);

	if (list_is_empty(drhd_list)) {
		list_destroy(drhd_list);
		return;
	}

	while ((drhd = list_remove_head(drhd_list)) != NULL) {
		scope_list_free(&(drhd->dr_scope_list));
		kmem_free(drhd, sizeof (drhd_t));
	}

	ASSERT(list_is_empty(drhd_list));
	list_destroy(drhd_list);
}

static void
rmrr_list_destroy(list_t *rmrr_list)
{
	rmrr_t *rmrr;

	ASSERT(rmrr_list);

	if (list_is_empty(rmrr_list)) {
		list_destroy(rmrr_list);
		return;
	}

	while ((rmrr = list_remove_head(rmrr_list)) != NULL) {
		scope_list_free(&(rmrr->rm_scope_list));
		kmem_free(rmrr, sizeof (rmrr_t));
	}

	ASSERT(list_is_empty(rmrr_list));
	list_destroy(rmrr_list);
}

/*
 * parse_scope()
 *      parse a scope structure in the "raw" table
 */
static scope_t *
parse_scope(char *shead)
{
	scope_t *scope;
	char *phead;
	int bus, dev, func;
	uint8_t startbus;
	uint8_t len;
	int depth;

	ASSERT(shead);

	scope = kmem_zalloc(sizeof (scope_t), KM_SLEEP);
	scope->scp_type = get_uint8(&shead[0]);
	scope->scp_enumid = get_uint8(&shead[4]);

	len = get_uint8(&shead[1]);
	startbus = get_uint8(&shead[5]);
	depth = (len - 6)/2;
	ASSERT(depth >= 1);

	phead = &shead[6];

	bus = startbus;
	dev = get_uint8(phead++);
	func = get_uint8(phead++);

	for (depth--; depth > 0; depth--) {
		bus = pci_getb_func(bus, dev, func, PCI_BCNF_SECBUS);
		dev = get_uint8(phead++);
		func = get_uint8(phead++);
	}

	ASSERT(bus >= 0 && bus < 256);
	ASSERT(dev >= 0 && dev < 32);
	ASSERT(func >= 0 && func < 8);

	/* ok we got the device BDF */
	scope->scp_bus = bus;
	scope->scp_dev = dev;
	scope->scp_func = func;

	return (scope);
}


/* setup the ioapic_drhd structure */
static void
ioapic_drhd_setup(void)
{
	mutex_init(&(ioapic_drhd_lock), NULL, MUTEX_DEFAULT, NULL);

	mutex_enter(&(ioapic_drhd_lock));
	list_create(&(ioapic_drhd_list), sizeof (ioapic_drhd_t),
	    offsetof(ioapic_drhd_t, ioapic_node));
	mutex_exit(&(ioapic_drhd_lock));
}

/* get ioapic source id for interrupt remapping */
static void
ioapic_drhd_insert(scope_t *scope, drhd_t *drhd)
{
	ioapic_drhd_t *idt;

	idt = kmem_zalloc(sizeof (ioapic_drhd_t), KM_SLEEP);
	idt->ioapic_ioapicid = scope->scp_enumid;
	idt->ioapic_sid = ((scope->scp_bus << 8) | (scope->scp_dev << 3) |
	    (scope->scp_func));
	idt->ioapic_drhd = drhd;

	mutex_enter(&ioapic_drhd_lock);
	list_insert_tail(&ioapic_drhd_list, idt);
	mutex_exit(&ioapic_drhd_lock);
}

static ioapic_drhd_t *
ioapic_drhd_lookup(int ioapicid)
{
	ioapic_drhd_t *idt;

	mutex_enter(&ioapic_drhd_lock);
	idt = list_head(&ioapic_drhd_list);
	for (; idt; idt = list_next(&ioapic_drhd_list, idt)) {
		if (idt->ioapic_ioapicid == ioapicid) {
			break;
		}
	}
	mutex_exit(&ioapic_drhd_lock);

	return (idt);
}

static void
ioapic_drhd_destroy(void)
{
	ioapic_drhd_t *idt;

	mutex_enter(&ioapic_drhd_lock);
	while (idt = list_remove_head(&ioapic_drhd_list)) {
		kmem_free(idt, sizeof (ioapic_drhd_t));
	}
	list_destroy(&ioapic_drhd_list);
	mutex_exit(&(ioapic_drhd_lock));

	mutex_destroy(&(ioapic_drhd_lock));
}

/*
 * parse_drhd()
 *   parse the drhd uints in dmar table
 */
static int
parse_drhd(char *uhead, dmar_table_t *tbl)
{
	drhd_t *drhd;
	int seg;
	int len;
	char *shead;
	scope_t *scope;

	ASSERT(uhead);
	ASSERT(tbl);
	ASSERT(get_uint16(&uhead[0]) == DMAR_DRHD);

	seg = get_uint16(&uhead[6]);
	if (seg < 0 || seg >= IMMU_MAXSEG) {
		ddi_err(DER_WARN, NULL, "invalid segment# <%d>"
		    "in DRHD unit in ACPI DMAR table", seg);
		return (DDI_FAILURE);
	}

	drhd = kmem_zalloc(sizeof (drhd_t), KM_SLEEP);
	mutex_init(&(drhd->dr_lock), NULL, MUTEX_DEFAULT, NULL);
	list_create(&(drhd->dr_scope_list), sizeof (scope_t),
	    offsetof(scope_t, scp_node));

	len = get_uint16(&uhead[2]);
	drhd->dr_include_all =
	    (get_uint8(&uhead[4]) & DMAR_INCLUDE_ALL) ? B_TRUE : B_FALSE;
	drhd->dr_seg = seg;
	drhd->dr_regs = get_uint64(&uhead[8]);

	/*
	 * parse each scope.
	 */
	shead = &uhead[16];
	while (shead < &uhead[len - 1]) {
		scope = parse_scope(shead);
		if (scope == NULL) {
			return (DDI_FAILURE);
		}

		if (scope->scp_type == DMAR_IOAPIC)  {
			ioapic_drhd_insert(scope, drhd);
		}

		list_insert_tail(&(drhd->dr_scope_list), scope);
		shead += get_uint8(&shead[1]);
	}

	list_insert_tail(&(tbl->tbl_drhd_list[drhd->dr_seg]), drhd);

	return (DDI_SUCCESS);
}

/*
 * parse_rmrr()
 *   parse the rmrr units in dmar table
 */
static int
parse_rmrr(char *uhead, dmar_table_t *tbl)
{
	rmrr_t *rmrr;
	int seg;
	int len;
	char *shead;
	scope_t *scope;

	ASSERT(uhead);
	ASSERT(tbl);
	ASSERT(get_uint16(&uhead[0]) == DMAR_RMRR);

	seg = get_uint16(&uhead[6]);
	if (seg < 0 || seg >= IMMU_MAXSEG) {
		ddi_err(DER_WARN, NULL, "invalid segment# <%d>"
		    "in RMRR unit in ACPI DMAR table", seg);
		return (DDI_FAILURE);
	}

	rmrr = kmem_zalloc(sizeof (rmrr_t), KM_SLEEP);
	mutex_init(&(rmrr->rm_lock), NULL, MUTEX_DEFAULT, NULL);
	list_create(&(rmrr->rm_scope_list), sizeof (scope_t),
	    offsetof(scope_t, scp_node));

	/* RMRR region is [base,limit] */
	len = get_uint16(&uhead[2]);
	rmrr->rm_seg = get_uint16(&uhead[6]);
	rmrr->rm_base = get_uint64(&uhead[8]);
	rmrr->rm_limit = get_uint64(&uhead[16]);

	if (rmrr->rm_base > rmrr->rm_limit) {
		ddi_err(DER_WARN, NULL, "IMMU: BIOS bug detected: "
		    "RMRR: base (%lx) > limit (%lx)",
		    rmrr->rm_base, rmrr->rm_limit);
		list_destroy(&(rmrr->rm_scope_list));
		mutex_destroy(&(rmrr->rm_lock));
		kmem_free(rmrr, sizeof (rmrr_t));
		return (DDI_SUCCESS);
	}

	/*
	 * parse each scope in RMRR
	 */
	shead = &uhead[24];
	while (shead < &uhead[len - 1]) {
		scope = parse_scope(shead);
		if (scope == NULL) {
			return (DDI_FAILURE);
		}
		list_insert_tail(&(rmrr->rm_scope_list), scope);
		shead += get_uint8(&shead[1]);
	}

	list_insert_tail(&(tbl->tbl_rmrr_list[rmrr->rm_seg]), rmrr);

	return (DDI_SUCCESS);
}

#define	TBL_OEM_ID_SZ		(6)
#define	TBL_OEM_TBLID_SZ	(8)

/*
 * parse the "raw" DMAR table and convert it
 * into a useful form.
 */
static int
dmar_parse(dmar_table_t **tblpp, char *raw)
{
	char *uhead;
	dmar_table_t *tbl;
	int i;
	char *unmstr;

	ASSERT(raw);
	ASSERT(tblpp);

	*tblpp = NULL;

	/*
	 * do a sanity check. make sure the raw table
	 * has the right signature
	 */
	if (raw[0] != 'D' || raw[1] != 'M' ||
	    raw[2] != 'A' || raw[3] != 'R') {
		ddi_err(DER_WARN, NULL, "IOMMU ACPI "
		    "signature != \"DMAR\"");
		return (DDI_FAILURE);
	}

	/*
	 * the platform has intel iommu, create processed ACPI struct
	 */
	tbl = kmem_zalloc(sizeof (dmar_table_t), KM_SLEEP);
	mutex_init(&(tbl->tbl_lock), NULL, MUTEX_DEFAULT, NULL);

	tbl->tbl_raw = raw;

	/*
	 * Note we explicitly show offsets for clarity
	 */
	tbl->tbl_rawlen = get_uint32(&raw[4]);

	/* XXX TO DO verify checksum of table */
	tbl->tbl_oem_id = get_str(&raw[10], TBL_OEM_ID_SZ);
	tbl->tbl_oem_tblid = get_str(&raw[16], TBL_OEM_TBLID_SZ);
	tbl->tbl_oem_rev = get_uint32(&raw[24]);
	tbl->tbl_haw = get_uint8(&raw[36]) + 1;
	tbl->tbl_intrmap = (get_uint8(&raw[37]) & DMAR_INTRMAP_SUPPORT)
	    ? B_TRUE : B_FALSE;

	/* create lists for DRHD and RMRR */
	for (i = 0; i < IMMU_MAXSEG; i++) {
		list_create(&(tbl->tbl_drhd_list[i]), sizeof (drhd_t),
		    offsetof(drhd_t, dr_node));
		list_create(&(tbl->tbl_rmrr_list[i]), sizeof (rmrr_t),
		    offsetof(rmrr_t, rm_node));
	}

	ioapic_drhd_setup();

	/*
	 * parse each unit. Currently only DRHD and RMRR types
	 * are parsed. We ignore all other types of units.
	 */
	uhead = &raw[48];
	while (uhead < &raw[tbl->tbl_rawlen - 1]) {
		unmstr = NULL;
		switch (get_uint16(uhead)) {
		case DMAR_DRHD:
			if (parse_drhd(uhead, tbl) != DDI_SUCCESS) {
				goto failed;
			}
			break;
		case DMAR_RMRR:
			if (parse_rmrr(uhead, tbl) != DDI_SUCCESS) {
				goto failed;
			}
			break;
		case DMAR_ATSR:
			unmstr = "ATSR";
			break;
		case DMAR_RHSA:
			unmstr = "RHSA";
			break;
		default:
			unmstr = "unknown unity type";
			break;
		}
		if (unmstr) {
			ddi_err(DER_NOTE, NULL, "DMAR ACPI table: "
			    "skipping unsupported unit type %s", unmstr);
		}
		uhead += get_uint16(&uhead[2]);
	}

	*tblpp = tbl;
	return (DDI_SUCCESS);

failed:
	dmar_table_destroy(tbl);
	return (DDI_FAILURE);
}

static char *
scope_type(int devtype)
{
	char *typestr;

	switch (devtype) {
	case DMAR_ENDPOINT:
		typestr = "endpoint-device";
		break;
	case DMAR_SUBTREE:
		typestr = "subtree-device";
		break;
	case DMAR_IOAPIC:
		typestr = "IOAPIC";
		break;
	case DMAR_HPET:
		typestr = "HPET";
		break;
	default:
		typestr = "Unknown device";
		break;
	}

	return (typestr);
}

static void
print_scope_list(list_t *scope_list)
{
	scope_t *scope;

	if (list_is_empty(scope_list))
		return;

	ddi_err(DER_CONT, NULL, "\tdevice list:\n");

	for (scope = list_head(scope_list); scope;
	    scope = list_next(scope_list, scope)) {
		ddi_err(DER_CONT, NULL, "\t\ttype = %s\n",
		    scope_type(scope->scp_type));
		ddi_err(DER_CONT, NULL, "\n\t\tbus = %d\n",
		    scope->scp_bus);
		ddi_err(DER_CONT, NULL, "\t\tdev = %d\n",
		    scope->scp_dev);
		ddi_err(DER_CONT, NULL, "\t\tfunc = %d\n",
		    scope->scp_func);
	}
}

static void
print_drhd_list(list_t *drhd_list)
{
	drhd_t *drhd;

	if (list_is_empty(drhd_list))
		return;

	ddi_err(DER_CONT, NULL, "\ndrhd list:\n");

	for (drhd = list_head(drhd_list); drhd;
	    drhd = list_next(drhd_list, drhd)) {

		ddi_err(DER_CONT, NULL, "\n\tsegment = %d\n",
		    drhd->dr_seg);
		ddi_err(DER_CONT, NULL, "\treg_base = 0x%" PRIx64 "\n",
		    drhd->dr_regs);
		ddi_err(DER_CONT, NULL, "\tinclude_all = %s\n",
		    drhd->dr_include_all == B_TRUE ? "TRUE" : "FALSE");
		ddi_err(DER_CONT, NULL, "\tdip = 0x%p\n",
		    (void *)drhd->dr_dip);

		print_scope_list(&(drhd->dr_scope_list));
	}
}


static void
print_rmrr_list(list_t *rmrr_list)
{
	rmrr_t *rmrr;

	if (list_is_empty(rmrr_list))
		return;

	ddi_err(DER_CONT, NULL, "\nrmrr list:\n");

	for (rmrr = list_head(rmrr_list); rmrr;
	    rmrr = list_next(rmrr_list, rmrr)) {

		ddi_err(DER_CONT, NULL, "\n\tsegment = %d\n",
		    rmrr->rm_seg);
		ddi_err(DER_CONT, NULL, "\tbase = 0x%lx\n",
		    rmrr->rm_base);
		ddi_err(DER_CONT, NULL, "\tlimit = 0x%lx\n",
		    rmrr->rm_limit);

		print_scope_list(&(rmrr->rm_scope_list));
	}
}

/*
 * print DMAR table
 */
static void
dmar_table_print(dmar_table_t *tbl)
{
	int i;

	if (dmar_print == B_FALSE) {
		return;
	}

	/* print the title */
	ddi_err(DER_CONT, NULL, "#### Start of dmar_table ####\n");
	ddi_err(DER_CONT, NULL, "\thaw = %d\n", tbl->tbl_haw);
	ddi_err(DER_CONT, NULL, "\tintr_remap = %s\n",
	    tbl->tbl_intrmap == B_TRUE ? "<true>" : "<false>");

	/* print drhd list */
	for (i = 0; i < IMMU_MAXSEG; i++) {
		print_drhd_list(&(tbl->tbl_drhd_list[i]));
	}


	/* print rmrr list */
	for (i = 0; i < IMMU_MAXSEG; i++) {
		print_rmrr_list(&(tbl->tbl_rmrr_list[i]));
	}

	ddi_err(DER_CONT, NULL, "#### END of dmar_table ####\n");
}

static void
drhd_devi_create(drhd_t *drhd, int unit)
{
	struct ddi_parent_private_data *pdptr;
	struct regspec reg;
	dev_info_t *dip;

	dip = ddi_add_child(root_devinfo, IMMU_UNIT_NAME,
	    DEVI_SID_NODEID, unit);

	drhd->dr_dip = dip;

	reg.regspec_bustype = 0;
	reg.regspec_addr = drhd->dr_regs;
	reg.regspec_size = IMMU_REGSZ;

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

	/*
	 * This is an artificially constructed dev_info, and we
	 * need to set a few more things to be able to use it
	 * for ddi_dma_alloc_handle/free_handle.
	 */
	ddi_set_driver(dip, ddi_get_driver(ddi_root_node()));
	DEVI(dip)->devi_bus_dma_allochdl =
	    DEVI(ddi_get_driver((ddi_root_node())));

	pdptr = kmem_zalloc(sizeof (struct ddi_parent_private_data)
	    + sizeof (struct regspec), KM_SLEEP);
	pdptr->par_nreg = 1;
	pdptr->par_reg = (struct regspec *)(pdptr + 1);
	pdptr->par_reg->regspec_bustype = 0;
	pdptr->par_reg->regspec_addr = drhd->dr_regs;
	pdptr->par_reg->regspec_size = IMMU_REGSZ;
	ddi_set_parent_data(dip, pdptr);
}

/*
 * dmar_devinfos_create()
 *
 *   create the dev_info node in the device tree,
 *   the info node is a nuxus child of the root
 *   nexus
 */
static void
dmar_devinfos_create(dmar_table_t *tbl)
{
	list_t *drhd_list;
	drhd_t *drhd;
	int i, unit;

	for (i = 0; i < IMMU_MAXSEG; i++) {

		drhd_list = &(tbl->tbl_drhd_list[i]);

		if (list_is_empty(drhd_list))
			continue;

		drhd = list_head(drhd_list);
		for (unit = 0; drhd;
		    drhd = list_next(drhd_list, drhd), unit++) {
			drhd_devi_create(drhd, unit);
		}
	}
}

static void
drhd_devi_destroy(drhd_t *drhd)
{
	dev_info_t *dip;
	int count;

	dip = drhd->dr_dip;
	ASSERT(dip);

	ndi_devi_enter(root_devinfo, &count);
	if (ndi_devi_offline(dip, NDI_DEVI_REMOVE) != DDI_SUCCESS) {
		ddi_err(DER_WARN, dip, "Failed to destroy");
	}
	ndi_devi_exit(root_devinfo, count);
	drhd->dr_dip = NULL;
}

/*
 * dmar_devi_destroy()
 *
 * destroy dev_info nodes for all drhd units
 */
static void
dmar_devi_destroy(dmar_table_t *tbl)
{
	drhd_t *drhd;
	list_t *drhd_list;
	int i;

	for (i = 0; i < IMMU_MAXSEG; i++) {
		drhd_list = &(tbl->tbl_drhd_list[i]);
		if (list_is_empty(drhd_list))
			continue;

		drhd = list_head(drhd_list);
		for (; drhd; drhd = list_next(drhd_list, drhd)) {
			drhd_devi_destroy(drhd);
		}
	}
}

static int
match_bdf(dev_info_t *ddip, void *arg)
{
	immu_arg_t *imarg = (immu_arg_t *)arg;
	immu_devi_t *immu_devi;

	ASSERT(ddip);
	ASSERT(imarg);
	ASSERT(imarg->ima_seg == 0);
	ASSERT(imarg->ima_bus >= 0);
	ASSERT(imarg->ima_devfunc >= 0);
	ASSERT(imarg->ima_ddip == NULL);

	/* rdip can be NULL */

	mutex_enter(&(DEVI(ddip)->devi_lock));

	immu_devi = IMMU_DEVI(ddip);
	ASSERT(immu_devi);

	if (immu_devi->imd_seg == imarg->ima_seg &&
	    immu_devi->imd_bus == imarg->ima_bus &&
	    immu_devi->imd_devfunc == imarg->ima_devfunc) {
		imarg->ima_ddip = ddip;
	}

	mutex_exit(&(DEVI(ddip)->devi_lock));

	return (imarg->ima_ddip ? DDI_WALK_TERMINATE : DDI_WALK_CONTINUE);
}
static void
dmar_table_destroy(dmar_table_t *tbl)
{
	int i;

	ASSERT(tbl);

	/* destroy lists for DRHD and RMRR */
	for (i = 0; i < IMMU_MAXSEG; i++) {
		rmrr_list_destroy(&(tbl->tbl_rmrr_list[i]));
		drhd_list_destroy(&(tbl->tbl_drhd_list[i]));
	}

	/* free strings */
	kmem_free(tbl->tbl_oem_tblid, TBL_OEM_TBLID_SZ + 1);
	kmem_free(tbl->tbl_oem_id, TBL_OEM_ID_SZ + 1);
	tbl->tbl_raw = NULL; /* raw ACPI table doesn't have to be freed */
	mutex_destroy(&(tbl->tbl_lock));
	kmem_free(tbl, sizeof (dmar_table_t));
}

/*
 * #########################################################################
 * Functions exported by dmar.c
 * This file deals with reading and processing the DMAR ACPI table
 * #########################################################################
 */

/*
 * immu_dmar_setup()
 *	Check if the system has a DMAR ACPI table. If yes, the system
 *	has Intel IOMMU hardware
 */
int
immu_dmar_setup(void)
{
	if (AcpiGetTable("DMAR", 1, (ACPI_TABLE_HEADER **)&dmar_raw) != AE_OK) {
		ddi_err(DER_LOG, NULL,
		    "No DMAR ACPI table. No Intel IOMMU present\n");
		dmar_raw = NULL;
		return (DDI_FAILURE);
	}
	ASSERT(dmar_raw);
	return (DDI_SUCCESS);
}

/*
 * immu_dmar_parse()
 *  Called by immu.c to parse and convert "raw" ACPI DMAR table
 */
int
immu_dmar_parse(void)
{
	dmar_table_t *tbl = NULL;

	/* we should already have found the "raw" table */
	ASSERT(dmar_raw);

	ddi_err(DER_CONT, NULL, "?Processing DMAR ACPI table\n");

	dmar_table = NULL;

	/*
	 * parse DMAR ACPI table
	 */
	if (dmar_parse(&tbl, dmar_raw) != DDI_SUCCESS) {
		ASSERT(tbl == NULL);
		return (DDI_FAILURE);
	}

	ASSERT(tbl);

	/*
	 * create one devinfo for every drhd unit
	 * in the DMAR table
	 */
	dmar_devinfos_create(tbl);

	/*
	 * print the dmar table if the debug option is set
	 */
	dmar_table_print(tbl);

	dmar_table = tbl;

	return (DDI_SUCCESS);
}

void
immu_dmar_startup(void)
{
	/* nothing to do */
}

void
immu_dmar_shutdown(void)
{
	/* nothing to do */
}

void
immu_dmar_destroy(void)
{
	dmar_devi_destroy(dmar_table);
	dmar_table_destroy(dmar_table);
	ioapic_drhd_destroy();
	dmar_table = NULL;
	dmar_raw = NULL;
}

boolean_t
immu_dmar_blacklisted(char **strptr, uint_t nstrs)
{
	dmar_table_t *tbl = dmar_table;
	int i;
	char oem_rev[IMMU_MAXNAMELEN];

	ASSERT(tbl);

	ASSERT((strptr == NULL) ^ (nstrs != 0));

	/*
	 * Must be a minimum of 4
	 */
	if (nstrs < 4) {
		return (B_FALSE);
	}

	ddi_err(DER_CONT, NULL, "?System DMAR ACPI table information:\n");
	ddi_err(DER_CONT, NULL, "?OEM-ID = <%s>\n", tbl->tbl_oem_id);
	ddi_err(DER_CONT, NULL, "?Table-ID = <%s>\n", tbl->tbl_oem_tblid);
	(void) snprintf(oem_rev, sizeof (oem_rev), "%d", tbl->tbl_oem_rev);
	ddi_err(DER_CONT, NULL, "?Revision = <%s>\n", oem_rev);

	for (i = 0; nstrs - i >= 4; i++) {
		if (strcmp(*strptr++, "DMAR") == 0) {
			if (strcmp(*strptr++, tbl->tbl_oem_id) == 0 &&
			    (*strptr[0] == '\0' ||
			    strcmp(*strptr++, tbl->tbl_oem_tblid) == 0) &&
			    (*strptr[0] == '\0' ||
			    strcmp(*strptr++, oem_rev) == 0)) {
				return (B_TRUE);
			}
			i += 3; /* for loops adds 1 as well, so only 3 here */
		}
	}
	return (B_FALSE);
}

void
immu_dmar_rmrr_map(void)
{
	int seg;
	int count;
	dev_info_t *rdip;
	scope_t *scope;
	rmrr_t *rmrr;
	dmar_table_t *tbl;

	ASSERT(dmar_table);

	tbl = dmar_table;

	/* called during boot, when kernel is single threaded. No lock */

	/*
	 * for each segment, walk the rmrr list looking for an exact match
	 */
	for (seg = 0; seg < IMMU_MAXSEG; seg++) {
		rmrr = list_head(&(tbl->tbl_rmrr_list)[seg]);
		for (; rmrr; rmrr = list_next(&(tbl->tbl_rmrr_list)[seg],
		    rmrr)) {

			/*
			 * try to match BDF *exactly* to a device scope.
			 */
			scope = list_head(&(rmrr->rm_scope_list));
			for (; scope;
			    scope = list_next(&(rmrr->rm_scope_list), scope)) {
				immu_arg_t imarg = {0};
				memrng_t mrng = {0};

				/* PCI endpoint devices only */
				if (scope->scp_type != DMAR_ENDPOINT)
					continue;

				imarg.ima_seg = seg;
				imarg.ima_bus = scope->scp_bus;
				imarg.ima_devfunc =
				    IMMU_PCI_DEVFUNC(scope->scp_dev,
				    scope->scp_func);
				imarg.ima_ddip = NULL;
				imarg.ima_rdip = NULL;

				ASSERT(root_devinfo);
				/* XXX should be optimized */
				ndi_devi_enter(root_devinfo, &count);
				ddi_walk_devs(ddi_get_child(root_devinfo),
				    match_bdf, &imarg);
				ndi_devi_exit(root_devinfo, count);

				if (imarg.ima_ddip == NULL) {
					ddi_err(DER_WARN, NULL,
					    "No dip found for "
					    "bus=0x%x, dev=0x%x, func= 0x%x",
					    scope->scp_bus, scope->scp_dev,
					    scope->scp_func);
					continue;
				}

				rdip = imarg.ima_ddip;
				/*
				 * This address must be in the BIOS reserved
				 * map
				 */
				if (!address_in_memlist(bios_rsvd,
				    (uint64_t)rmrr->rm_base, rmrr->rm_limit -
				    rmrr->rm_base + 1)) {
					ddi_err(DER_WARN, rdip, "RMRR range "
					    " [0x%" PRIx64 " - 0x%" PRIx64 "]"
					    " not in BIOS reserved map",
					    rmrr->rm_base, rmrr->rm_limit);
				}

				/* XXX could be more efficient */
				memlist_read_lock();
				if (address_in_memlist(phys_install,
				    (uint64_t)rmrr->rm_base, rmrr->rm_limit -
				    rmrr->rm_base + 1)) {
					ddi_err(DER_WARN, rdip, "RMRR range "
					    " [0x%" PRIx64 " - 0x%" PRIx64 "]"
					    " is in physinstall map",
					    rmrr->rm_base, rmrr->rm_limit);
				}
				memlist_read_unlock();

				(void) immu_dvma_device_setup(rdip, 0);

				ddi_err(DER_LOG, rdip,
				    "IMMU: Mapping RMRR range "
				    "[0x%" PRIx64 " - 0x%"PRIx64 "]",
				    rmrr->rm_base, rmrr->rm_limit);

				mrng.mrng_start =
				    IMMU_ROUNDOWN((uintptr_t)rmrr->rm_base);
				mrng.mrng_npages =
				    IMMU_ROUNDUP((uintptr_t)rmrr->rm_limit -
				    (uintptr_t)rmrr->rm_base + 1) /
				    IMMU_PAGESIZE;

				(void) immu_map_memrange(rdip, &mrng);
			}
		}
	}

}

immu_t *
immu_dmar_get_immu(dev_info_t *rdip)
{
	int seg;
	int tlevel;
	int level;
	drhd_t *drhd;
	drhd_t *tdrhd;
	scope_t *scope;
	dmar_table_t *tbl;

	ASSERT(dmar_table);

	tbl = dmar_table;

	mutex_enter(&(tbl->tbl_lock));

	/*
	 * for each segment, walk the drhd list looking for an exact match
	 */
	for (seg = 0; seg < IMMU_MAXSEG; seg++) {
		drhd = list_head(&(tbl->tbl_drhd_list)[seg]);
		for (; drhd; drhd = list_next(&(tbl->tbl_drhd_list)[seg],
		    drhd)) {

			/*
			 * we are currently searching for exact matches so
			 * skip "include all" (catchall) and subtree matches
			 */
			if (drhd->dr_include_all == B_TRUE)
				continue;

			/*
			 * try to match BDF *exactly* to a device scope.
			 */
			scope = list_head(&(drhd->dr_scope_list));
			for (; scope;
			    scope = list_next(&(drhd->dr_scope_list), scope)) {
				immu_arg_t imarg = {0};

				/* PCI endpoint devices only */
				if (scope->scp_type != DMAR_ENDPOINT)
					continue;

				imarg.ima_seg = seg;
				imarg.ima_bus = scope->scp_bus;
				imarg.ima_devfunc =
				    IMMU_PCI_DEVFUNC(scope->scp_dev,
				    scope->scp_func);
				imarg.ima_ddip = NULL;
				imarg.ima_rdip = rdip;
				level = 0;
				if (immu_walk_ancestor(rdip, NULL, match_bdf,
				    &imarg, &level, IMMU_FLAGS_DONTPASS)
				    != DDI_SUCCESS) {
					/* skip - nothing else we can do */
					continue;
				}

				/* Should have walked only 1 level i.e. rdip */
				ASSERT(level == 1);

				if (imarg.ima_ddip) {
					ASSERT(imarg.ima_ddip == rdip);
					goto found;
				}
			}
		}
	}

	/*
	 * walk the drhd list looking for subtree match
	 * i.e. is the device a descendant of a devscope BDF.
	 * We want the lowest subtree.
	 */
	tdrhd = NULL;
	tlevel = 0;
	for (seg = 0; seg < IMMU_MAXSEG; seg++) {
		drhd = list_head(&(tbl->tbl_drhd_list)[seg]);
		for (; drhd; drhd = list_next(&(tbl->tbl_drhd_list)[seg],
		    drhd)) {

			/* looking for subtree match */
			if (drhd->dr_include_all == B_TRUE)
				continue;

			/*
			 * try to match the device scope
			 */
			scope = list_head(&(drhd->dr_scope_list));
			for (; scope;
			    scope = list_next(&(drhd->dr_scope_list), scope)) {
				immu_arg_t imarg = {0};

				/* PCI subtree only */
				if (scope->scp_type != DMAR_SUBTREE)
					continue;

				imarg.ima_seg = seg;
				imarg.ima_bus = scope->scp_bus;
				imarg.ima_devfunc =
				    IMMU_PCI_DEVFUNC(scope->scp_dev,
				    scope->scp_func);

				imarg.ima_ddip = NULL;
				imarg.ima_rdip = rdip;
				level = 0;
				if (immu_walk_ancestor(rdip, NULL, match_bdf,
				    &imarg, &level, 0) != DDI_SUCCESS) {
					/* skip - nothing else we can do */
					continue;
				}

				/* should have walked 1 level i.e. rdip */
				ASSERT(level > 0);

				/* look for lowest ancestor matching drhd */
				if (imarg.ima_ddip && (tdrhd == NULL ||
				    level < tlevel)) {
					tdrhd = drhd;
					tlevel = level;
				}
			}
		}
	}

	if ((drhd = tdrhd) != NULL) {
		goto found;
	}

	for (seg = 0; seg < IMMU_MAXSEG; seg++) {
		drhd = list_head(&(tbl->tbl_drhd_list[seg]));
		for (; drhd; drhd = list_next(&(tbl->tbl_drhd_list)[seg],
		    drhd)) {
			/* Look for include all */
			if (drhd->dr_include_all == B_TRUE) {
				break;
			}
		}
	}

	/*FALLTHRU*/

found:
	mutex_exit(&(tbl->tbl_lock));

	/*
	 * No drhd (dmar unit) found for this device in the ACPI DMAR tables.
	 * This may happen with buggy versions of BIOSes. Just warn instead
	 * of panic as we don't want whole system to go down because of one
	 * device.
	 */
	if (drhd == NULL) {
		ddi_err(DER_WARN, rdip, "can't find Intel IOMMU unit for "
		    "device in ACPI DMAR table.");
		return (NULL);
	}

	return (drhd->dr_immu);
}

dev_info_t *
immu_dmar_unit_dip(void *dmar_unit)
{
	drhd_t *drhd = (drhd_t *)dmar_unit;
	return (drhd->dr_dip);
}

void *
immu_dmar_walk_units(int seg, void *dmar_unit)
{
	list_t *drhd_list;
	drhd_t *drhd = (drhd_t *)dmar_unit;

	drhd_list = &(dmar_table->tbl_drhd_list[seg]);

	if (drhd == NULL) {
		return ((void *)list_head(drhd_list));
	} else {
		return ((void *)list_next(drhd_list, drhd));
	}
}

void
immu_dmar_set_immu(void *dmar_unit, immu_t *immu)
{
	drhd_t *drhd = (drhd_t *)dmar_unit;

	ASSERT(drhd);
	ASSERT(immu);

	drhd->dr_immu = immu;
}

boolean_t
immu_dmar_intrmap_supported(void)
{
	ASSERT(dmar_table);
	return (dmar_table->tbl_intrmap);
}

/* for a given ioapicid, find the source id and immu */
uint16_t
immu_dmar_ioapic_sid(int ioapic_ix)
{
	ioapic_drhd_t *idt;

	idt = ioapic_drhd_lookup(psm_get_ioapicid(ioapic_ix));
	if (idt == NULL) {
		ddi_err(DER_PANIC, NULL, "cannot determine source-id for "
		    "IOAPIC (index = %d)", ioapic_ix);
		/*NOTREACHED*/
	}

	return (idt->ioapic_sid);
}

/* for a given ioapicid, find the source id and immu */
immu_t *
immu_dmar_ioapic_immu(int ioapic_ix)
{
	ioapic_drhd_t *idt;

	idt = ioapic_drhd_lookup(psm_get_ioapicid(ioapic_ix));
	if (idt) {
		return (idt->ioapic_drhd ? idt->ioapic_drhd->dr_immu : NULL);
	}
	return (NULL);
}
