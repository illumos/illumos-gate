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
 * sun4 specific DDI implementation
 */
#include <sys/cpuvar.h>
#include <sys/ddi_subrdefs.h>
#include <sys/machsystm.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>
#include <sys/ontrap.h>
#include <vm/seg_kmem.h>
#include <sys/membar.h>
#include <sys/dditypes.h>
#include <sys/ndifm.h>
#include <sys/fm/io/ddi.h>
#include <sys/ivintr.h>
#include <sys/bootconf.h>
#include <sys/conf.h>
#include <sys/ethernet.h>
#include <sys/idprom.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/systeminfo.h>
#include <sys/fpu/fpusystm.h>
#include <sys/vm.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/snode.h>
#include <sys/ddi_isa.h>
#include <sys/modhash.h>
#include <sys/modctl.h>
#include <sys/sunldi_impl.h>

dev_info_t *get_intr_parent(dev_info_t *, dev_info_t *,
    ddi_intr_handle_impl_t *);
#pragma weak get_intr_parent

int process_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
    ddi_intr_handle_impl_t *, void *);
#pragma weak process_intr_ops

void cells_1275_copy(prop_1275_cell_t *, prop_1275_cell_t *, int32_t);
    prop_1275_cell_t *cells_1275_cmp(prop_1275_cell_t *, prop_1275_cell_t *,
    int32_t len);
#pragma weak cells_1275_copy

/*
 * Wrapper for ddi_prop_lookup_int_array().
 * This is handy because it returns the prop length in
 * bytes which is what most of the callers require.
 */

static int
get_prop_int_array(dev_info_t *di, char *pname, int **pval, uint_t *plen)
{
	int ret;

	if ((ret = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, di,
	    DDI_PROP_DONTPASS, pname, pval, plen)) == DDI_PROP_SUCCESS) {
		*plen = (*plen) * (uint_t)sizeof (int);
	}
	return (ret);
}

/*
 * SECTION: DDI Node Configuration
 */

/*
 * init_regspec_64:
 *
 * If the parent #size-cells is 2, convert the upa-style or
 * safari-style reg property from 2-size cells to 1 size cell
 * format, ignoring the size_hi, which must be zero for devices.
 * (It won't be zero in the memory list properties in the memory
 * nodes, but that doesn't matter here.)
 */
struct ddi_parent_private_data *
init_regspec_64(dev_info_t *dip)
{
	struct ddi_parent_private_data *pd;
	dev_info_t *parent;
	int size_cells;

	/*
	 * If there are no "reg"s in the child node, return.
	 */
	pd = ddi_get_parent_data(dip);
	if ((pd == NULL) || (pd->par_nreg == 0)) {
		return (pd);
	}
	parent = ddi_get_parent(dip);

	size_cells = ddi_prop_get_int(DDI_DEV_T_ANY, parent,
	    DDI_PROP_DONTPASS, "#size-cells", 1);

	if (size_cells != 1)  {

		int n, j;
		struct regspec *irp;
		struct reg_64 {
			uint_t addr_hi, addr_lo, size_hi, size_lo;
		};
		struct reg_64 *r64_rp;
		struct regspec *rp;
		uint_t len = 0;
		int *reg_prop;

		ASSERT(size_cells == 2);

		/*
		 * We already looked the property up once before if
		 * pd is non-NULL.
		 */
		(void) ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, OBP_REG, &reg_prop, &len);
		ASSERT(len != 0);

		n = sizeof (struct reg_64) / sizeof (int);
		n = len / n;

		/*
		 * We're allocating a buffer the size of the PROM's property,
		 * but we're only using a smaller portion when we assign it
		 * to a regspec.  We do this so that in the
		 * impl_ddi_sunbus_removechild function, we will
		 * always free the right amount of memory.
		 */
		irp = rp = (struct regspec *)reg_prop;
		r64_rp = (struct reg_64 *)pd->par_reg;

		for (j = 0; j < n; ++j, ++rp, ++r64_rp) {
			ASSERT(r64_rp->size_hi == 0);
			rp->regspec_bustype = r64_rp->addr_hi;
			rp->regspec_addr = r64_rp->addr_lo;
			rp->regspec_size = r64_rp->size_lo;
		}

		ddi_prop_free((void *)pd->par_reg);
		pd->par_nreg = n;
		pd->par_reg = irp;
	}
	return (pd);
}

/*
 * Create a ddi_parent_private_data structure from the ddi properties of
 * the dev_info node.
 *
 * The "reg" is required if the driver wishes to create mappings on behalf
 * of the device. The "reg" property is assumed to be a list of at least
 * one triplet
 *
 *	<bustype, address, size>*1
 *
 * The "interrupt" property is no longer part of parent private data on
 * sun4u. The interrupt parent is may not be the device tree parent.
 *
 * The "ranges" property describes the mapping of child addresses to parent
 * addresses.
 *
 * N.B. struct rangespec is defined for the following default values:
 *			parent  child
 *	#address-cells	2	2
 *	#size-cells	1	1
 * This function doesn't deal with non-default cells and will not create
 * ranges in such cases.
 */
void
make_ddi_ppd(dev_info_t *child, struct ddi_parent_private_data **ppd)
{
	struct ddi_parent_private_data *pdptr;
	int *reg_prop, *rng_prop;
	uint_t reg_len = 0, rng_len = 0;
	dev_info_t *parent;
	int parent_addr_cells, parent_size_cells;
	int child_addr_cells, child_size_cells;

	*ppd = pdptr = kmem_zalloc(sizeof (*pdptr), KM_SLEEP);

	/*
	 * root node has no parent private data, so *ppd should
	 * be initialized for naming to work properly.
	 */
	if ((parent = ddi_get_parent(child)) == NULL)
		return;

	/*
	 * Set reg field of parent data from "reg" property
	 */
	if ((get_prop_int_array(child, OBP_REG, &reg_prop, &reg_len)
	    == DDI_PROP_SUCCESS) && (reg_len != 0)) {
		pdptr->par_nreg = (int)(reg_len / sizeof (struct regspec));
		pdptr->par_reg = (struct regspec *)reg_prop;
	}

	/*
	 * "ranges" property ...
	 *
	 * This function does not handle cases where #address-cells != 2
	 * and * min(parent, child) #size-cells != 1 (see bugid 4211124).
	 *
	 * Nexus drivers with such exceptions (e.g. pci ranges)
	 * should either create a separate function for handling
	 * ranges or not use parent private data to store ranges.
	 */

	/* root node has no ranges */
	if ((parent = ddi_get_parent(child)) == NULL)
		return;

	child_addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "#address-cells", 2);
	child_size_cells = ddi_prop_get_int(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "#size-cells", 1);
	parent_addr_cells = ddi_prop_get_int(DDI_DEV_T_ANY, parent,
	    DDI_PROP_DONTPASS, "#address-cells", 2);
	parent_size_cells = ddi_prop_get_int(DDI_DEV_T_ANY, parent,
	    DDI_PROP_DONTPASS, "#size-cells", 1);
	if (child_addr_cells != 2 || parent_addr_cells != 2 ||
	    (child_size_cells != 1 && parent_size_cells != 1)) {
		NDI_CONFIG_DEBUG((CE_NOTE, "!ranges not made in parent data; "
		    "#address-cells or #size-cells have non-default value"));
		return;
	}

	if (get_prop_int_array(child, OBP_RANGES, &rng_prop, &rng_len)
	    == DDI_PROP_SUCCESS) {
		pdptr->par_nrng = rng_len / (int)(sizeof (struct rangespec));
		pdptr->par_rng = (struct rangespec *)rng_prop;
	}
}

/*
 * Free ddi_parent_private_data structure
 */
void
impl_free_ddi_ppd(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr = ddi_get_parent_data(dip);

	if (pdptr == NULL)
		return;

	if (pdptr->par_nrng != 0)
		ddi_prop_free((void *)pdptr->par_rng);

	if (pdptr->par_nreg != 0)
		ddi_prop_free((void *)pdptr->par_reg);

	kmem_free(pdptr, sizeof (*pdptr));
	ddi_set_parent_data(dip, NULL);
}

/*
 * Name a child of sun busses based on the reg spec.
 * Handles the following properties:
 *
 *	Property	value
 *	Name		type
 *
 *	reg		register spec
 *	interrupts	new (bus-oriented) interrupt spec
 *	ranges		range spec
 *
 * This may be called multiple times, independent of
 * initchild calls.
 */
static int
impl_sunbus_name_child(dev_info_t *child, char *name, int namelen)
{
	struct ddi_parent_private_data *pdptr;
	struct regspec *rp;

	/*
	 * Fill in parent-private data and this function returns to us
	 * an indication if it used "registers" to fill in the data.
	 */
	if (ddi_get_parent_data(child) == NULL) {
		make_ddi_ppd(child, &pdptr);
		ddi_set_parent_data(child, pdptr);
	}

	/*
	 * No reg property, return null string as address
	 * (e.g. root node)
	 */
	name[0] = '\0';
	if (sparc_pd_getnreg(child) == 0) {
		return (DDI_SUCCESS);
	}

	rp = sparc_pd_getreg(child, 0);
	(void) snprintf(name, namelen, "%x,%x",
	    rp->regspec_bustype, rp->regspec_addr);
	return (DDI_SUCCESS);
}


/*
 * Called from the bus_ctl op of some drivers.
 * to implement the DDI_CTLOPS_INITCHILD operation.
 *
 * NEW drivers should NOT use this function, but should declare
 * there own initchild/uninitchild handlers. (This function assumes
 * the layout of the parent private data and the format of "reg",
 * "ranges", "interrupts" properties and that #address-cells and
 * #size-cells of the parent bus are defined to be default values.)
 */
int
impl_ddi_sunbus_initchild(dev_info_t *child)
{
	char name[MAXNAMELEN];

	(void) impl_sunbus_name_child(child, name, MAXNAMELEN);
	ddi_set_name_addr(child, name);

	/*
	 * Try to merge .conf node. If successful, return failure to
	 * remove this child.
	 */
	if ((ndi_dev_is_persistent_node(child) == 0) &&
	    (ndi_merge_node(child, impl_sunbus_name_child) == DDI_SUCCESS)) {
		impl_ddi_sunbus_removechild(child);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * A better name for this function would be impl_ddi_sunbus_uninitchild()
 * It does not remove the child, it uninitializes it, reclaiming the
 * resources taken by impl_ddi_sunbus_initchild.
 */
void
impl_ddi_sunbus_removechild(dev_info_t *dip)
{
	impl_free_ddi_ppd(dip);
	ddi_set_name_addr(dip, NULL);
	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	impl_rem_dev_props(dip);
}

/*
 * SECTION: DDI Interrupt
 */

void
cells_1275_copy(prop_1275_cell_t *from, prop_1275_cell_t *to, int32_t len)
{
	int i;
	for (i = 0; i < len; i++)
		*to = *from;
}

prop_1275_cell_t *
cells_1275_cmp(prop_1275_cell_t *cell1, prop_1275_cell_t *cell2, int32_t len)
{
	prop_1275_cell_t *match_cell = 0;
	int32_t i;

	for (i = 0; i < len; i++)
		if (cell1[i] != cell2[i]) {
			match_cell = &cell1[i];
			break;
		}

	return (match_cell);
}

/*
 * get_intr_parent() is a generic routine that process a 1275 interrupt
 * map (imap) property.  This function returns a dev_info_t structure
 * which claims ownership of the interrupt domain.
 * It also returns the new interrupt translation within this new domain.
 * If an interrupt-parent or interrupt-map property are not found,
 * then we fallback to using the device tree's parent.
 *
 * imap entry format:
 * <reg>,<interrupt>,<phandle>,<translated interrupt>
 * reg - The register specification in the interrupts domain
 * interrupt - The interrupt specification
 * phandle - PROM handle of the device that owns the xlated interrupt domain
 * translated interrupt - interrupt specifier in the parents domain
 * note: <reg>,<interrupt> - The reg and interrupt can be combined to create
 *	a unique entry called a unit interrupt specifier.
 *
 * Here's the processing steps:
 * step1 - If the interrupt-parent property exists, create the ispec and
 *	return the dip of the interrupt parent.
 * step2 - Extract the interrupt-map property and the interrupt-map-mask
 *	If these don't exist, just return the device tree parent.
 * step3 - build up the unit interrupt specifier to match against the
 *	interrupt map property
 * step4 - Scan the interrupt-map property until a match is found
 * step4a - Extract the interrupt parent
 * step4b - Compare the unit interrupt specifier
 */
dev_info_t *
get_intr_parent(dev_info_t *pdip, dev_info_t *dip, ddi_intr_handle_impl_t *hdlp)
{
	prop_1275_cell_t *imap, *imap_mask, *scan, *reg_p, *match_req;
	int32_t imap_sz, imap_cells, imap_scan_cells, imap_mask_sz,
	    addr_cells, intr_cells, reg_len, i, j;
	int32_t match_found = 0;
	dev_info_t *intr_parent_dip = NULL;
	uint32_t *intr = &hdlp->ih_vector;
	uint32_t nodeid;
#ifdef DEBUG
	static int debug = 0;
#endif

	/*
	 * step1
	 * If we have an interrupt-parent property, this property represents
	 * the nodeid of our interrupt parent.
	 */
	if ((nodeid = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
	    "interrupt-parent", -1)) != -1) {
		intr_parent_dip = e_ddi_nodeid_to_dip(nodeid);
		ASSERT(intr_parent_dip);

		/*
		 * Attach the interrupt parent.
		 *
		 * N.B. e_ddi_nodeid_to_dip() isn't safe under DR.
		 *	Also, interrupt parent isn't held. This needs
		 *	to be revisited if DR-capable platforms implement
		 *	interrupt redirection.
		 */
		if (i_ddi_attach_node_hierarchy(intr_parent_dip)
		    != DDI_SUCCESS) {
			ndi_rele_devi(intr_parent_dip);
			return (NULL);
		}

		return (intr_parent_dip);
	}

	/*
	 * step2
	 * Get interrupt map structure from PROM property
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS,
	    "interrupt-map", (caddr_t)&imap, &imap_sz)
	    != DDI_PROP_SUCCESS) {
		/*
		 * If we don't have an imap property, default to using the
		 * device tree.
		 */

		ndi_hold_devi(pdip);
		return (pdip);
	}

	/* Get the interrupt mask property */
	if (ddi_getlongprop(DDI_DEV_T_ANY, pdip, DDI_PROP_DONTPASS,
	    "interrupt-map-mask", (caddr_t)&imap_mask, &imap_mask_sz)
	    != DDI_PROP_SUCCESS) {
		/*
		 * If we don't find this property, we have to fail the request
		 * because the 1275 imap property wasn't defined correctly.
		 */
		ASSERT(intr_parent_dip == NULL);
		goto exit2;
	}

	/* Get the address cell size */
	addr_cells = ddi_getprop(DDI_DEV_T_ANY, pdip, 0,
	    "#address-cells", 2);

	/* Get the interrupts cell size */
	intr_cells = ddi_getprop(DDI_DEV_T_ANY, pdip, 0,
	    "#interrupt-cells", 1);

	/*
	 * step3
	 * Now lets build up the unit interrupt specifier e.g. reg,intr
	 * and apply the imap mask.  match_req will hold this when we're
	 * through.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&reg_p, &reg_len) != DDI_SUCCESS) {
		ASSERT(intr_parent_dip == NULL);
		goto exit3;
	}

	match_req = kmem_alloc(CELLS_1275_TO_BYTES(addr_cells) +
	    CELLS_1275_TO_BYTES(intr_cells), KM_SLEEP);

	for (i = 0; i < addr_cells; i++)
		match_req[i] = (reg_p[i] & imap_mask[i]);

	for (j = 0; j < intr_cells; i++, j++)
		match_req[i] = (intr[j] & imap_mask[i]);

	/* Calculate the imap size in cells */
	imap_cells = BYTES_TO_1275_CELLS(imap_sz);

#ifdef DEBUG
	if (debug)
		prom_printf("reg cell size 0x%x, intr cell size 0x%x, "
		    "match_request 0x%p, imap 0x%p\n", addr_cells, intr_cells,
		    (void *)match_req, (void *)imap);
#endif

	/*
	 * Scan the imap property looking for a match of the interrupt unit
	 * specifier.  This loop is rather complex since the data within the
	 * imap property may vary in size.
	 */
	for (scan = imap, imap_scan_cells = i = 0;
	    imap_scan_cells < imap_cells; scan += i, imap_scan_cells += i) {
		int new_intr_cells;

		/* Set the index to the nodeid field */
		i = addr_cells + intr_cells;

		/*
		 * step4a
		 * Translate the nodeid field to a dip
		 */
		ASSERT(intr_parent_dip == NULL);
		intr_parent_dip = e_ddi_nodeid_to_dip((uint_t)scan[i++]);

		ASSERT(intr_parent_dip != 0);
#ifdef DEBUG
		if (debug)
			prom_printf("scan 0x%p\n", (void *)scan);
#endif
		/*
		 * The tmp_dip describes the new domain, get it's interrupt
		 * cell size
		 */
		new_intr_cells = ddi_getprop(DDI_DEV_T_ANY, intr_parent_dip, 0,
		    "#interrupts-cells", 1);

		/*
		 * step4b
		 * See if we have a match on the interrupt unit specifier
		 */
		if (cells_1275_cmp(match_req, scan, addr_cells + intr_cells)
		    == 0) {
			uint32_t *intr;

			match_found = 1;

			/*
			 * If we have an imap parent whose not in our device
			 * tree path, we need to hold and install that driver.
			 */
			if (i_ddi_attach_node_hierarchy(intr_parent_dip)
			    != DDI_SUCCESS) {
				ndi_rele_devi(intr_parent_dip);
				intr_parent_dip = (dev_info_t *)NULL;
				goto exit4;
			}

			/*
			 * We need to handcraft an ispec along with a bus
			 * interrupt value, so we can dup it into our
			 * standard ispec structure.
			 */
			/* Extract the translated interrupt information */
			intr = kmem_alloc(
			    CELLS_1275_TO_BYTES(new_intr_cells), KM_SLEEP);

			for (j = 0; j < new_intr_cells; j++, i++)
				intr[j] = scan[i];

			cells_1275_copy(intr, &hdlp->ih_vector, new_intr_cells);

			kmem_free(intr, CELLS_1275_TO_BYTES(new_intr_cells));

#ifdef DEBUG
			if (debug)
				prom_printf("dip 0x%p\n",
				    (void *)intr_parent_dip);
#endif
			break;
		} else {
#ifdef DEBUG
			if (debug)
				prom_printf("dip 0x%p\n",
				    (void *)intr_parent_dip);
#endif
			ndi_rele_devi(intr_parent_dip);
			intr_parent_dip = NULL;
			i += new_intr_cells;
		}
	}

	/*
	 * If we haven't found our interrupt parent at this point, fallback
	 * to using the device tree.
	 */
	if (!match_found) {
		ndi_hold_devi(pdip);
		ASSERT(intr_parent_dip == NULL);
		intr_parent_dip = pdip;
	}

	ASSERT(intr_parent_dip != NULL);

exit4:
	kmem_free(reg_p, reg_len);
	kmem_free(match_req, CELLS_1275_TO_BYTES(addr_cells) +
	    CELLS_1275_TO_BYTES(intr_cells));

exit3:
	kmem_free(imap_mask, imap_mask_sz);

exit2:
	kmem_free(imap, imap_sz);

	return (intr_parent_dip);
}

/*
 * process_intr_ops:
 *
 * Process the interrupt op via the interrupt parent.
 */
int
process_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int		ret = DDI_FAILURE;

	if (NEXUS_HAS_INTR_OP(pdip)) {
		ret = (*(DEVI(pdip)->devi_ops->devo_bus_ops->
		    bus_intr_op)) (pdip, rdip, op, hdlp, result);
	} else {
		cmn_err(CE_WARN, "Failed to process interrupt "
		    "for %s%d due to down-rev nexus driver %s%d",
		    ddi_get_name(rdip), ddi_get_instance(rdip),
		    ddi_get_name(pdip), ddi_get_instance(pdip));
	}

	return (ret);
}

/*ARGSUSED*/
uint_t
softlevel1(caddr_t arg)
{
	softint();
	return (1);
}

/*
 * indirection table, to save us some large switch statements
 * NOTE: This must agree with "INTLEVEL_foo" constants in
 *	<sys/avintr.h>
 */
struct autovec *const vectorlist[] = { 0 };

/*
 * This value is exported here for the functions in avintr.c
 */
const uint_t maxautovec = (sizeof (vectorlist) / sizeof (vectorlist[0]));

/*
 * Check for machine specific interrupt levels which cannot be reassigned by
 * settrap(), sun4u version.
 *
 * sun4u does not support V8 SPARC "fast trap" handlers.
 */
/*ARGSUSED*/
int
exclude_settrap(int lvl)
{
	return (1);
}

/*
 * Check for machine specific interrupt levels which cannot have interrupt
 * handlers added. We allow levels 1 through 15; level 0 is nonsense.
 */
/*ARGSUSED*/
int
exclude_level(int lvl)
{
	return ((lvl < 1) || (lvl > 15));
}

/*
 * Wrapper functions used by New DDI interrupt framework.
 */

/*
 * i_ddi_intr_ops:
 */
int
i_ddi_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	dev_info_t	*pdip = ddi_get_parent(dip);
	int		ret = DDI_FAILURE;

	/*
	 * The following check is required to address
	 * one of the test case of ADDI test suite.
	 */
	if (pdip == NULL)
		return (DDI_FAILURE);

	if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
		return (process_intr_ops(pdip, rdip, op, hdlp, result));

	if (hdlp->ih_vector == 0)
		hdlp->ih_vector = i_ddi_get_inum(rdip, hdlp->ih_inum);

	if (hdlp->ih_pri == 0)
		hdlp->ih_pri = i_ddi_get_intr_pri(rdip, hdlp->ih_inum);

	switch (op) {
	case DDI_INTROP_ADDISR:
	case DDI_INTROP_REMISR:
	case DDI_INTROP_ENABLE:
	case DDI_INTROP_DISABLE:
	case DDI_INTROP_BLOCKENABLE:
	case DDI_INTROP_BLOCKDISABLE:
		/*
		 * Try and determine our parent and possibly an interrupt
		 * translation. intr parent dip returned held
		 */
		if ((pdip = get_intr_parent(pdip, dip, hdlp)) == NULL)
			goto done;
	}

	ret = process_intr_ops(pdip, rdip, op, hdlp, result);

done:
	switch (op) {
	case DDI_INTROP_ADDISR:
	case DDI_INTROP_REMISR:
	case DDI_INTROP_ENABLE:
	case DDI_INTROP_DISABLE:
	case DDI_INTROP_BLOCKENABLE:
	case DDI_INTROP_BLOCKDISABLE:
		/* Release hold acquired in get_intr_parent() */
		if (pdip)
			ndi_rele_devi(pdip);
	}

	hdlp->ih_vector = 0;

	return (ret);
}

/*
 * i_ddi_add_ivintr:
 */
/*ARGSUSED*/
int
i_ddi_add_ivintr(ddi_intr_handle_impl_t *hdlp)
{
	/*
	 * If the PIL was set and is valid use it, otherwise
	 * default it to 1
	 */
	if ((hdlp->ih_pri < 1) || (hdlp->ih_pri > PIL_MAX))
		hdlp->ih_pri = 1;

	VERIFY(add_ivintr(hdlp->ih_vector, hdlp->ih_pri,
	    (intrfunc)hdlp->ih_cb_func, hdlp->ih_cb_arg1,
	    hdlp->ih_cb_arg2, NULL) == 0);

	return (DDI_SUCCESS);
}

/*
 * i_ddi_rem_ivintr:
 */
/*ARGSUSED*/
void
i_ddi_rem_ivintr(ddi_intr_handle_impl_t *hdlp)
{
	VERIFY(rem_ivintr(hdlp->ih_vector, hdlp->ih_pri) == 0);
}

/*
 * i_ddi_get_inum - Get the interrupt number property from the
 * specified device. Note that this function is called only for
 * the FIXED interrupt type.
 */
uint32_t
i_ddi_get_inum(dev_info_t *dip, uint_t inumber)
{
	int32_t			intrlen, intr_cells, max_intrs;
	prop_1275_cell_t	*ip, intr_sz;
	uint32_t		intr = 0;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS |
	    DDI_PROP_CANSLEEP,
	    "interrupts", (caddr_t)&ip, &intrlen) == DDI_SUCCESS) {

		intr_cells = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
		    "#interrupt-cells", 1);

		/* adjust for number of bytes */
		intr_sz = CELLS_1275_TO_BYTES(intr_cells);

		/* Calculate the number of interrupts */
		max_intrs = intrlen / intr_sz;

		if (inumber < max_intrs) {
			prop_1275_cell_t *intrp = ip;

			/* Index into interrupt property */
			intrp += (inumber * intr_cells);

			cells_1275_copy(intrp, &intr, intr_cells);
		}

		kmem_free(ip, intrlen);
	}

	return (intr);
}

/*
 * i_ddi_get_intr_pri - Get the interrupt-priorities property from
 * the specified device. Note that this function is called only for
 * the FIXED interrupt type.
 */
uint32_t
i_ddi_get_intr_pri(dev_info_t *dip, uint_t inumber)
{
	uint32_t	*intr_prio_p;
	uint32_t	pri = 0;
	int32_t		i;

	/*
	 * Use the "interrupt-priorities" property to determine the
	 * the pil/ipl for the interrupt handler.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupt-priorities", (caddr_t)&intr_prio_p,
	    &i) == DDI_SUCCESS) {
		if (inumber < (i / sizeof (int32_t)))
			pri = intr_prio_p[inumber];
		kmem_free(intr_prio_p, i);
	}

	return (pri);
}

int
i_ddi_get_intx_nintrs(dev_info_t *dip)
{
	int32_t intrlen;
	prop_1275_cell_t intr_sz;
	prop_1275_cell_t *ip;
	int32_t ret = 0;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS |
	    DDI_PROP_CANSLEEP,
	    "interrupts", (caddr_t)&ip, &intrlen) == DDI_SUCCESS) {

		intr_sz = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
		    "#interrupt-cells", 1);
		/* adjust for number of bytes */
		intr_sz = CELLS_1275_TO_BYTES(intr_sz);

		ret = intrlen / intr_sz;

		kmem_free(ip, intrlen);
	}

	return (ret);
}

/*
 * i_ddi_add_softint - allocate and add a software interrupt.
 *
 * NOTE: All software interrupts that are registered through DDI
 *	 should be triggered only on a single target or CPU.
 */
int
i_ddi_add_softint(ddi_softint_hdl_impl_t *hdlp)
{
	if ((hdlp->ih_private = (void *)add_softintr(hdlp->ih_pri,
	    hdlp->ih_cb_func, hdlp->ih_cb_arg1, SOFTINT_ST)) == NULL)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/*
 * i_ddi_remove_softint - remove and free a software interrupt.
 */
void
i_ddi_remove_softint(ddi_softint_hdl_impl_t *hdlp)
{
	ASSERT(hdlp->ih_private != NULL);

	if (rem_softintr((uint64_t)hdlp->ih_private) == 0)
		hdlp->ih_private = NULL;
}

/*
 * i_ddi_trigger_softint - trigger a software interrupt.
 */
int
i_ddi_trigger_softint(ddi_softint_hdl_impl_t *hdlp, void *arg2)
{
	int	ret;

	ASSERT(hdlp->ih_private != NULL);

	/* Update the second argument for the software interrupt */
	if ((ret = update_softint_arg2((uint64_t)hdlp->ih_private, arg2)) == 0)
		setsoftint((uint64_t)hdlp->ih_private);

	return (ret ? DDI_EPENDING : DDI_SUCCESS);
}

/*
 * i_ddi_set_softint_pri - change software interrupt priority.
 */
/* ARGSUSED */
int
i_ddi_set_softint_pri(ddi_softint_hdl_impl_t *hdlp, uint_t old_pri)
{
	int	ret;

	ASSERT(hdlp->ih_private != NULL);

	/* Update the interrupt priority for the software interrupt */
	ret = update_softint_pri((uint64_t)hdlp->ih_private, hdlp->ih_pri);

	return (ret ? DDI_FAILURE : DDI_SUCCESS);
}

/*ARGSUSED*/
void
i_ddi_alloc_intr_phdl(ddi_intr_handle_impl_t *hdlp)
{
}

/*ARGSUSED*/
void
i_ddi_free_intr_phdl(ddi_intr_handle_impl_t *hdlp)
{
}

/*
 * SECTION: DDI Memory/DMA
 */

/* set HAT endianess attributes from ddi_device_acc_attr */
void
i_ddi_devacc_to_hatacc(ddi_device_acc_attr_t *devaccp, uint_t *hataccp)
{
	if (devaccp != NULL) {
		if (devaccp->devacc_attr_endian_flags == DDI_STRUCTURE_LE_ACC) {
			*hataccp &= ~HAT_ENDIAN_MASK;
			*hataccp |= HAT_STRUCTURE_LE;
		}
	}
}

/*
 * Check if the specified cache attribute is supported on the platform.
 * This function must be called before i_ddi_cacheattr_to_hatacc().
 */
boolean_t
i_ddi_check_cache_attr(uint_t flags)
{
	/*
	 * The cache attributes are mutually exclusive. Any combination of
	 * the attributes leads to a failure.
	 */
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);
	if ((cache_attr != 0) && ((cache_attr & (cache_attr - 1)) != 0))
		return (B_FALSE);

	/*
	 * On the sparc architecture, only IOMEM_DATA_CACHED is meaningful,
	 * but others lead to a failure.
	 */
	if (cache_attr & IOMEM_DATA_CACHED)
		return (B_TRUE);
	else
		return (B_FALSE);
}

/* set HAT cache attributes from the cache attributes */
void
i_ddi_cacheattr_to_hatacc(uint_t flags, uint_t *hataccp)
{
	uint_t cache_attr = IOMEM_CACHE_ATTR(flags);
	static char *fname = "i_ddi_cacheattr_to_hatacc";
#if defined(lint)
	*hataccp = *hataccp;
#endif
	/*
	 * set HAT attrs according to the cache attrs.
	 */
	switch (cache_attr) {
	/*
	 * The cache coherency is always maintained on SPARC, and
	 * nothing is required.
	 */
	case IOMEM_DATA_CACHED:
		break;
	/*
	 * Both IOMEM_DATA_UC_WRITE_COMBINED and IOMEM_DATA_UNCACHED are
	 * not supported on SPARC -- this case must not occur because the
	 * cache attribute is scrutinized before this function is called.
	 */
	case IOMEM_DATA_UNCACHED:
	case IOMEM_DATA_UC_WR_COMBINE:
	default:
		cmn_err(CE_WARN, "%s: cache_attr=0x%x is ignored.",
		    fname, cache_attr);
	}
}

static vmem_t *little_endian_arena;
static vmem_t *big_endian_arena;

static void *
segkmem_alloc_le(vmem_t *vmp, size_t size, int flag)
{
	return (segkmem_xalloc(vmp, NULL, size, flag, HAT_STRUCTURE_LE,
	    segkmem_page_create, NULL));
}

static void *
segkmem_alloc_be(vmem_t *vmp, size_t size, int flag)
{
	return (segkmem_xalloc(vmp, NULL, size, flag, HAT_STRUCTURE_BE,
	    segkmem_page_create, NULL));
}

void
ka_init(void)
{
	little_endian_arena = vmem_create("little_endian", NULL, 0, 1,
	    segkmem_alloc_le, segkmem_free, heap_arena, 0, VM_SLEEP);
	big_endian_arena = vmem_create("big_endian", NULL, 0, 1,
	    segkmem_alloc_be, segkmem_free, heap_arena, 0, VM_SLEEP);
}

/*
 * Allocate from the system, aligned on a specific boundary.
 * The alignment, if non-zero, must be a power of 2.
 */
static void *
kalloca(size_t size, size_t align, int cansleep, uint_t endian_flags)
{
	size_t *addr, *raddr, rsize;
	size_t hdrsize = 4 * sizeof (size_t);	/* must be power of 2 */

	align = MAX(align, hdrsize);
	ASSERT((align & (align - 1)) == 0);

	/*
	 * We need to allocate
	 *    rsize = size + hdrsize + align - MIN(hdrsize, buffer_alignment)
	 * bytes to be sure we have enough freedom to satisfy the request.
	 * Since the buffer alignment depends on the request size, this is
	 * not straightforward to use directly.
	 *
	 * kmem guarantees that any allocation of a 64-byte multiple will be
	 * 64-byte aligned.  Since rounding up the request could add more
	 * than we save, we compute the size with and without alignment, and
	 * use the smaller of the two.
	 */
	rsize = size + hdrsize + align;

	if (endian_flags == DDI_STRUCTURE_LE_ACC) {
		raddr = vmem_alloc(little_endian_arena, rsize,
		    cansleep ? VM_SLEEP : VM_NOSLEEP);
	} else {
		raddr = vmem_alloc(big_endian_arena, rsize,
		    cansleep ? VM_SLEEP : VM_NOSLEEP);
	}

	if (raddr == NULL)
		return (NULL);

	addr = (size_t *)P2ROUNDUP((uintptr_t)raddr + hdrsize, align);
	ASSERT((uintptr_t)addr + size - (uintptr_t)raddr <= rsize);

	addr[-3] = (size_t)endian_flags;
	addr[-2] = (size_t)raddr;
	addr[-1] = rsize;

	return (addr);
}

static void
kfreea(void *addr)
{
	size_t *saddr = addr;

	if (saddr[-3] == DDI_STRUCTURE_LE_ACC)
		vmem_free(little_endian_arena, (void *)saddr[-2], saddr[-1]);
	else
		vmem_free(big_endian_arena, (void *)saddr[-2], saddr[-1]);
}

int
i_ddi_mem_alloc(dev_info_t *dip, ddi_dma_attr_t *attr,
    size_t length, int cansleep, int flags,
    ddi_device_acc_attr_t *accattrp,
    caddr_t *kaddrp, size_t *real_length, ddi_acc_hdl_t *handlep)
{
	caddr_t a;
	int iomin, align, streaming;
	uint_t endian_flags = DDI_NEVERSWAP_ACC;

#if defined(lint)
	*handlep = *handlep;
#endif

	/*
	 * Check legality of arguments
	 */
	if (length == 0 || kaddrp == NULL || attr == NULL) {
		return (DDI_FAILURE);
	}

	if (attr->dma_attr_minxfer == 0 || attr->dma_attr_align == 0 ||
	    (attr->dma_attr_align & (attr->dma_attr_align - 1)) ||
	    (attr->dma_attr_minxfer & (attr->dma_attr_minxfer - 1))) {
		return (DDI_FAILURE);
	}

	/*
	 * check if a streaming sequential xfer is requested.
	 */
	streaming = (flags & DDI_DMA_STREAMING) ? 1 : 0;

	/*
	 * Drivers for 64-bit capable SBus devices will encode
	 * the burtsizes for 64-bit xfers in the upper 16-bits.
	 * For DMA alignment, we use the most restrictive
	 * alignment of 32-bit and 64-bit xfers.
	 */
	iomin = (attr->dma_attr_burstsizes & 0xffff) |
	    ((attr->dma_attr_burstsizes >> 16) & 0xffff);
	/*
	 * If a driver set burtsizes to 0, we give him byte alignment.
	 * Otherwise align at the burtsizes boundary.
	 */
	if (iomin == 0)
		iomin = 1;
	else
		iomin = 1 << (ddi_fls(iomin) - 1);
	iomin = maxbit(iomin, attr->dma_attr_minxfer);
	iomin = maxbit(iomin, attr->dma_attr_align);
	iomin = ddi_iomin(dip, iomin, streaming);
	if (iomin == 0)
		return (DDI_FAILURE);

	ASSERT((iomin & (iomin - 1)) == 0);
	ASSERT(iomin >= attr->dma_attr_minxfer);
	ASSERT(iomin >= attr->dma_attr_align);

	length = P2ROUNDUP(length, iomin);
	align = iomin;

	if (accattrp != NULL)
		endian_flags = accattrp->devacc_attr_endian_flags;

	a = kalloca(length, align, cansleep, endian_flags);
	if ((*kaddrp = a) == 0) {
		return (DDI_FAILURE);
	} else {
		if (real_length) {
			*real_length = length;
		}
		if (handlep) {
			/*
			 * assign handle information
			 */
			impl_acc_hdl_init(handlep);
		}
		return (DDI_SUCCESS);
	}
}

/*
 * covert old DMA limits structure to DMA attribute structure
 * and continue
 */
int
i_ddi_mem_alloc_lim(dev_info_t *dip, ddi_dma_lim_t *limits,
    size_t length, int cansleep, int streaming,
    ddi_device_acc_attr_t *accattrp, caddr_t *kaddrp,
    uint_t *real_length, ddi_acc_hdl_t *ap)
{
	ddi_dma_attr_t dma_attr, *attrp;
	size_t rlen;
	int ret;

	ASSERT(limits);
	attrp = &dma_attr;
	attrp->dma_attr_version = DMA_ATTR_V0;
	attrp->dma_attr_addr_lo = (uint64_t)limits->dlim_addr_lo;
	attrp->dma_attr_addr_hi = (uint64_t)limits->dlim_addr_hi;
	attrp->dma_attr_count_max = (uint64_t)-1;
	attrp->dma_attr_align = 1;
	attrp->dma_attr_burstsizes = (uint_t)limits->dlim_burstsizes;
	attrp->dma_attr_minxfer = (uint32_t)limits->dlim_minxfer;
	attrp->dma_attr_maxxfer = (uint64_t)-1;
	attrp->dma_attr_seg = (uint64_t)limits->dlim_cntr_max;
	attrp->dma_attr_sgllen = 1;
	attrp->dma_attr_granular = 1;
	attrp->dma_attr_flags = 0;

	ret = i_ddi_mem_alloc(dip, attrp, length, cansleep, streaming,
	    accattrp, kaddrp, &rlen, ap);
	if (ret == DDI_SUCCESS) {
		if (real_length)
			*real_length = (uint_t)rlen;
	}
	return (ret);
}

/* ARGSUSED */
void
i_ddi_mem_free(caddr_t kaddr, ddi_acc_hdl_t *ap)
{
	kfreea(kaddr);
}

/*
 * SECTION: DDI Data Access
 */

static uintptr_t impl_acc_hdl_id = 0;

/*
 * access handle allocator
 */
ddi_acc_hdl_t *
impl_acc_hdl_get(ddi_acc_handle_t hdl)
{
	/*
	 * Extract the access handle address from the DDI implemented
	 * access handle
	 */
	return (&((ddi_acc_impl_t *)hdl)->ahi_common);
}

ddi_acc_handle_t
impl_acc_hdl_alloc(int (*waitfp)(caddr_t), caddr_t arg)
{
	ddi_acc_impl_t *hp;
	on_trap_data_t *otp;
	int sleepflag;

	sleepflag = ((waitfp == (int (*)())KM_SLEEP) ? KM_SLEEP : KM_NOSLEEP);

	/*
	 * Allocate and initialize the data access handle and error status.
	 */
	if ((hp = kmem_zalloc(sizeof (ddi_acc_impl_t), sleepflag)) == NULL)
		goto fail;
	if ((hp->ahi_err = (ndi_err_t *)kmem_zalloc(
	    sizeof (ndi_err_t), sleepflag)) == NULL) {
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		goto fail;
	}
	if ((otp = (on_trap_data_t *)kmem_zalloc(
	    sizeof (on_trap_data_t), sleepflag)) == NULL) {
		kmem_free(hp->ahi_err, sizeof (ndi_err_t));
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		goto fail;
	}
	hp->ahi_err->err_ontrap = otp;
	hp->ahi_common.ah_platform_private = (void *)hp;

	return ((ddi_acc_handle_t)hp);
fail:
	if ((waitfp != (int (*)())KM_SLEEP) &&
	    (waitfp != (int (*)())KM_NOSLEEP))
		ddi_set_callback(waitfp, arg, &impl_acc_hdl_id);
	return (NULL);
}

void
impl_acc_hdl_free(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hp;

	/*
	 * The supplied (ddi_acc_handle_t) is actually a (ddi_acc_impl_t *),
	 * because that's what we allocated in impl_acc_hdl_alloc() above.
	 */
	hp = (ddi_acc_impl_t *)handle;
	if (hp) {
		kmem_free(hp->ahi_err->err_ontrap, sizeof (on_trap_data_t));
		kmem_free(hp->ahi_err, sizeof (ndi_err_t));
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		if (impl_acc_hdl_id)
			ddi_run_callback(&impl_acc_hdl_id);
	}
}

#define	PCI_GET_MP_PFN(mp, page_no)	((mp)->dmai_ndvmapages == 1 ? \
	(pfn_t)(mp)->dmai_iopte:(((pfn_t *)(mp)->dmai_iopte)[page_no]))

/*
 * Function called after a dma fault occurred to find out whether the
 * fault address is associated with a driver that is able to handle faults
 * and recover from faults.
 */
/* ARGSUSED */
int
impl_dma_check(dev_info_t *dip, const void *handle, const void *addr,
    const void *not_used)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	pfn_t fault_pfn = mmu_btop(*(uint64_t *)addr);
	pfn_t comp_pfn;

	/*
	 * The driver has to set DDI_DMA_FLAGERR to recover from dma faults.
	 */
	int page;

	ASSERT(mp);
	for (page = 0; page < mp->dmai_ndvmapages; page++) {
		comp_pfn = PCI_GET_MP_PFN(mp, page);
		if (fault_pfn == comp_pfn)
			return (DDI_FM_NONFATAL);
	}
	return (DDI_FM_UNKNOWN);
}

/*
 * Function used to check if a given access handle owns the failing address.
 * Called by ndi_fmc_error, when we detect a PIO error.
 */
/* ARGSUSED */
static int
impl_acc_check(dev_info_t *dip, const void *handle, const void *addr,
    const void *not_used)
{
	pfn_t pfn, fault_pfn;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get((ddi_acc_handle_t)handle);

	ASSERT(hp);

	if (addr != NULL) {
		pfn = hp->ah_pfn;
		fault_pfn = mmu_btop(*(uint64_t *)addr);
		if (fault_pfn >= pfn && fault_pfn < (pfn + hp->ah_pnum))
			return (DDI_FM_NONFATAL);
	}
	return (DDI_FM_UNKNOWN);
}

void
impl_acc_err_init(ddi_acc_hdl_t *handlep)
{
	int fmcap;
	ndi_err_t *errp;
	on_trap_data_t *otp;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handlep;

	fmcap = ddi_fm_capable(handlep->ah_dip);

	if (handlep->ah_acc.devacc_attr_version < DDI_DEVICE_ATTR_V1 ||
	    !DDI_FM_ACC_ERR_CAP(fmcap)) {
		handlep->ah_acc.devacc_attr_access = DDI_DEFAULT_ACC;
	} else if (DDI_FM_ACC_ERR_CAP(fmcap)) {
		if (handlep->ah_acc.devacc_attr_access == DDI_DEFAULT_ACC) {
			i_ddi_drv_ereport_post(handlep->ah_dip, DVR_EFMCAP,
			    NULL, DDI_NOSLEEP);
		} else {
			errp = hp->ahi_err;
			otp = (on_trap_data_t *)errp->err_ontrap;
			otp->ot_handle = (void *)(hp);
			otp->ot_prot = OT_DATA_ACCESS;
			if (handlep->ah_acc.devacc_attr_access ==
			    DDI_CAUTIOUS_ACC)
				otp->ot_trampoline =
				    (uintptr_t)&i_ddi_caut_trampoline;
			else
				otp->ot_trampoline =
				    (uintptr_t)&i_ddi_prot_trampoline;
			errp->err_status = DDI_FM_OK;
			errp->err_expected = DDI_FM_ERR_UNEXPECTED;
			errp->err_cf = impl_acc_check;
		}
	}
}

void
impl_acc_hdl_init(ddi_acc_hdl_t *handlep)
{
	ddi_acc_impl_t *hp;

	ASSERT(handlep);

	hp = (ddi_acc_impl_t *)handlep;

	/*
	 * check for SW byte-swapping
	 */
	hp->ahi_get8 = i_ddi_get8;
	hp->ahi_put8 = i_ddi_put8;
	hp->ahi_rep_get8 = i_ddi_rep_get8;
	hp->ahi_rep_put8 = i_ddi_rep_put8;
	if (handlep->ah_acc.devacc_attr_endian_flags & DDI_STRUCTURE_LE_ACC) {
		hp->ahi_get16 = i_ddi_swap_get16;
		hp->ahi_get32 = i_ddi_swap_get32;
		hp->ahi_get64 = i_ddi_swap_get64;
		hp->ahi_put16 = i_ddi_swap_put16;
		hp->ahi_put32 = i_ddi_swap_put32;
		hp->ahi_put64 = i_ddi_swap_put64;
		hp->ahi_rep_get16 = i_ddi_swap_rep_get16;
		hp->ahi_rep_get32 = i_ddi_swap_rep_get32;
		hp->ahi_rep_get64 = i_ddi_swap_rep_get64;
		hp->ahi_rep_put16 = i_ddi_swap_rep_put16;
		hp->ahi_rep_put32 = i_ddi_swap_rep_put32;
		hp->ahi_rep_put64 = i_ddi_swap_rep_put64;
	} else {
		hp->ahi_get16 = i_ddi_get16;
		hp->ahi_get32 = i_ddi_get32;
		hp->ahi_get64 = i_ddi_get64;
		hp->ahi_put16 = i_ddi_put16;
		hp->ahi_put32 = i_ddi_put32;
		hp->ahi_put64 = i_ddi_put64;
		hp->ahi_rep_get16 = i_ddi_rep_get16;
		hp->ahi_rep_get32 = i_ddi_rep_get32;
		hp->ahi_rep_get64 = i_ddi_rep_get64;
		hp->ahi_rep_put16 = i_ddi_rep_put16;
		hp->ahi_rep_put32 = i_ddi_rep_put32;
		hp->ahi_rep_put64 = i_ddi_rep_put64;
	}

	/* Legacy fault flags and support */
	hp->ahi_fault_check = i_ddi_acc_fault_check;
	hp->ahi_fault_notify = i_ddi_acc_fault_notify;
	hp->ahi_fault = 0;
	impl_acc_err_init(handlep);
}

void
i_ddi_acc_set_fault(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;

	if (!hp->ahi_fault) {
		hp->ahi_fault = 1;
			(*hp->ahi_fault_notify)(hp);
	}
}

void
i_ddi_acc_clr_fault(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handle;

	if (hp->ahi_fault) {
		hp->ahi_fault = 0;
			(*hp->ahi_fault_notify)(hp);
	}
}

/* ARGSUSED */
void
i_ddi_acc_fault_notify(ddi_acc_impl_t *hp)
{
	/* Default version, does nothing */
}

/*
 * SECTION: Misc functions
 */

/*
 * instance wrappers
 */
/*ARGSUSED*/
uint_t
impl_assign_instance(dev_info_t *dip)
{
	return ((uint_t)-1);
}

/*ARGSUSED*/
int
impl_keep_instance(dev_info_t *dip)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
impl_free_instance(dev_info_t *dip)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
impl_check_cpu(dev_info_t *devi)
{
	return (DDI_SUCCESS);
}


static const char *nocopydevs[] = {
	"SUNW,ffb",
	"SUNW,afb",
	NULL
};

/*
 * Perform a copy from a memory mapped device (whose devinfo pointer is devi)
 * separately mapped at devaddr in the kernel to a kernel buffer at kaddr.
 */
/*ARGSUSED*/
int
e_ddi_copyfromdev(dev_info_t *devi,
    off_t off, const void *devaddr, void *kaddr, size_t len)
{
	const char **argv;

	for (argv = nocopydevs; *argv; argv++)
		if (strcmp(ddi_binding_name(devi), *argv) == 0) {
			bzero(kaddr, len);
			return (0);
		}

	bcopy(devaddr, kaddr, len);
	return (0);
}

/*
 * Perform a copy to a memory mapped device (whose devinfo pointer is devi)
 * separately mapped at devaddr in the kernel from a kernel buffer at kaddr.
 */
/*ARGSUSED*/
int
e_ddi_copytodev(dev_info_t *devi,
    off_t off, const void *kaddr, void *devaddr, size_t len)
{
	const char **argv;

	for (argv = nocopydevs; *argv; argv++)
		if (strcmp(ddi_binding_name(devi), *argv) == 0)
			return (1);

	bcopy(kaddr, devaddr, len);
	return (0);
}

/*
 * Boot Configuration
 */
idprom_t idprom;

/*
 * Configure the hardware on the system.
 * Called before the rootfs is mounted
 */
void
configure(void)
{
	extern void i_ddi_init_root();

	/* We better have released boot by this time! */
	ASSERT(!bootops);

	/*
	 * Determine whether or not to use the fpu, V9 SPARC cpus
	 * always have one. Could check for existence of a fp queue,
	 * Ultra I, II and IIa do not have a fp queue.
	 */
	if (fpu_exists)
		fpu_probe();
	else
		cmn_err(CE_CONT, "FPU not in use\n");

#if 0 /* XXXQ - not necessary for sun4u */
	/*
	 * This following line fixes bugid 1041296; we need to do a
	 * prom_nextnode(0) because this call ALSO patches the DMA+
	 * bug in Campus-B and Phoenix. The prom uncaches the traptable
	 * page as a side-effect of devr_next(0) (which prom_nextnode calls),
	 * so this *must* be executed early on. (XXX This is untrue for sun4u)
	 */
	(void) prom_nextnode((pnode_t)0);
#endif

	/*
	 * Initialize devices on the machine.
	 * Uses configuration tree built by the PROMs to determine what
	 * is present, and builds a tree of prototype dev_info nodes
	 * corresponding to the hardware which identified itself.
	 */
	i_ddi_init_root();

#ifdef	DDI_PROP_DEBUG
	(void) ddi_prop_debug(1);	/* Enable property debugging */
#endif	/* DDI_PROP_DEBUG */
}

/*
 * The "status" property indicates the operational status of a device.
 * If this property is present, the value is a string indicating the
 * status of the device as follows:
 *
 *	"okay"		operational.
 *	"disabled"	not operational, but might become operational.
 *	"fail"		not operational because a fault has been detected,
 *			and it is unlikely that the device will become
 *			operational without repair. no additional details
 *			are available.
 *	"fail-xxx"	not operational because a fault has been detected,
 *			and it is unlikely that the device will become
 *			operational without repair. "xxx" is additional
 *			human-readable information about the particular
 *			fault condition that was detected.
 *
 * The absence of this property means that the operational status is
 * unknown or okay.
 *
 * This routine checks the status property of the specified device node
 * and returns 0 if the operational status indicates failure, and 1 otherwise.
 *
 * The property may exist on plug-in cards the existed before IEEE 1275-1994.
 * And, in that case, the property may not even be a string. So we carefully
 * check for the value "fail", in the beginning of the string, noting
 * the property length.
 */
int
status_okay(int id, char *buf, int buflen)
{
	char status_buf[OBP_MAXPROPNAME];
	char *bufp = buf;
	int len = buflen;
	int proplen;
	static const char *status = "status";
	static const char *fail = "fail";
	size_t fail_len = strlen(fail);

	/*
	 * Get the proplen ... if it's smaller than "fail",
	 * or doesn't exist ... then we don't care, since
	 * the value can't begin with the char string "fail".
	 *
	 * NB: proplen, if it's a string, includes the NULL in the
	 * the size of the property, and fail_len does not.
	 */
	proplen = prom_getproplen((pnode_t)id, (caddr_t)status);
	if (proplen <= fail_len)	/* nonexistent or uninteresting len */
		return (1);

	/*
	 * if a buffer was provided, use it
	 */
	if ((buf == (char *)NULL) || (buflen <= 0)) {
		bufp = status_buf;
		len = sizeof (status_buf);
	}
	*bufp = (char)0;

	/*
	 * Get the property into the buffer, to the extent of the buffer,
	 * and in case the buffer is smaller than the property size,
	 * NULL terminate the buffer. (This handles the case where
	 * a buffer was passed in and the caller wants to print the
	 * value, but the buffer was too small).
	 */
	(void) prom_bounded_getprop((pnode_t)id, (caddr_t)status,
	    (caddr_t)bufp, len);
	*(bufp + len - 1) = (char)0;

	/*
	 * If the value begins with the char string "fail",
	 * then it means the node is failed. We don't care
	 * about any other values. We assume the node is ok
	 * although it might be 'disabled'.
	 */
	if (strncmp(bufp, fail, fail_len) == 0)
		return (0);

	return (1);
}


/*
 * We set the cpu type from the idprom, if we can.
 * Note that we just read out the contents of it, for the most part.
 */
void
setcputype(void)
{
	/*
	 * We cache the idprom info early on so that we don't
	 * rummage through the NVRAM unnecessarily later.
	 */
	(void) prom_getidprom((caddr_t)&idprom, sizeof (idprom));
}

/*
 *  Here is where we actually infer meanings to the members of idprom_t
 */
void
parse_idprom(void)
{
	if (idprom.id_format == IDFORM_1) {
		(void) localetheraddr((struct ether_addr *)idprom.id_ether,
		    (struct ether_addr *)NULL);
		(void) snprintf(hw_serial, HW_HOSTID_LEN, "%u",
		    (idprom.id_machine << 24) + idprom.id_serial);
	} else
		prom_printf("Invalid format code in IDprom.\n");
}

/*
 * Allow for implementation specific correction of PROM property values.
 */
/*ARGSUSED*/
void
impl_fix_props(dev_info_t *dip, dev_info_t *ch_dip, char *name, int len,
    caddr_t buffer)
{
	/*
	 * There are no adjustments needed in this implementation.
	 */
}

/*
 * The following functions ready a cautious request to go up to the nexus
 * driver.  It is up to the nexus driver to decide how to process the request.
 * It may choose to call i_ddi_do_caut_get/put in this file, or do it
 * differently.
 */

static void
i_ddi_caut_getput_ctlops(
    ddi_acc_impl_t *hp, uint64_t host_addr, uint64_t dev_addr, size_t size,
    size_t repcount, uint_t flags, ddi_ctl_enum_t cmd)
{
	peekpoke_ctlops_t	cautacc_ctlops_arg;

	cautacc_ctlops_arg.size = size;
	cautacc_ctlops_arg.dev_addr = dev_addr;
	cautacc_ctlops_arg.host_addr = host_addr;
	cautacc_ctlops_arg.handle = (ddi_acc_handle_t)hp;
	cautacc_ctlops_arg.repcount = repcount;
	cautacc_ctlops_arg.flags = flags;

	(void) ddi_ctlops(hp->ahi_common.ah_dip, hp->ahi_common.ah_dip, cmd,
	    &cautacc_ctlops_arg, NULL);
}

uint8_t
i_ddi_caut_get8(ddi_acc_impl_t *hp, uint8_t *addr)
{
	uint8_t value;
	i_ddi_caut_getput_ctlops(hp, (uint64_t)&value, (uint64_t)addr,
	    sizeof (uint8_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint16_t
i_ddi_caut_get16(ddi_acc_impl_t *hp, uint16_t *addr)
{
	uint16_t value;
	i_ddi_caut_getput_ctlops(hp, (uint64_t)&value, (uint64_t)addr,
	    sizeof (uint16_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint32_t
i_ddi_caut_get32(ddi_acc_impl_t *hp, uint32_t *addr)
{
	uint32_t value;
	i_ddi_caut_getput_ctlops(hp, (uint64_t)&value, (uint64_t)addr,
	    sizeof (uint32_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

uint64_t
i_ddi_caut_get64(ddi_acc_impl_t *hp, uint64_t *addr)
{
	uint64_t value;
	i_ddi_caut_getput_ctlops(hp, (uint64_t)&value, (uint64_t)addr,
	    sizeof (uint64_t), 1, 0, DDI_CTLOPS_PEEK);

	return (value);
}

void
i_ddi_caut_put8(ddi_acc_impl_t *hp, uint8_t *addr, uint8_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)&value, (uint64_t)addr,
	    sizeof (uint8_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put16(ddi_acc_impl_t *hp, uint16_t *addr, uint16_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)&value, (uint64_t)addr,
	    sizeof (uint16_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put32(ddi_acc_impl_t *hp, uint32_t *addr, uint32_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)&value, (uint64_t)addr,
	    sizeof (uint32_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_put64(ddi_acc_impl_t *hp, uint64_t *addr, uint64_t value)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)&value, (uint64_t)addr,
	    sizeof (uint64_t), 1, 0, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_get8(ddi_acc_impl_t *hp, uint8_t *host_addr, uint8_t *dev_addr,
	size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)host_addr, (uint64_t)dev_addr,
	    sizeof (uint8_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get16(ddi_acc_impl_t *hp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)host_addr, (uint64_t)dev_addr,
	    sizeof (uint16_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get32(ddi_acc_impl_t *hp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)host_addr, (uint64_t)dev_addr,
	    sizeof (uint32_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_get64(ddi_acc_impl_t *hp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)host_addr, (uint64_t)dev_addr,
	    sizeof (uint64_t), repcount, flags, DDI_CTLOPS_PEEK);
}

void
i_ddi_caut_rep_put8(ddi_acc_impl_t *hp, uint8_t *host_addr, uint8_t *dev_addr,
	size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)host_addr, (uint64_t)dev_addr,
	    sizeof (uint8_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put16(ddi_acc_impl_t *hp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)host_addr, (uint64_t)dev_addr,
	    sizeof (uint16_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put32(ddi_acc_impl_t *hp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)host_addr, (uint64_t)dev_addr,
	    sizeof (uint32_t), repcount, flags, DDI_CTLOPS_POKE);
}

void
i_ddi_caut_rep_put64(ddi_acc_impl_t *hp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	i_ddi_caut_getput_ctlops(hp, (uint64_t)host_addr, (uint64_t)dev_addr,
	    sizeof (uint64_t), repcount, flags, DDI_CTLOPS_POKE);
}

/*
 * This is called only to process peek/poke when the DIP is NULL.
 * Assume that this is for memory, as nexi take care of device safe accesses.
 */
int
peekpoke_mem(ddi_ctl_enum_t cmd, peekpoke_ctlops_t *in_args)
{
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	/* Set up protected environment. */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		uintptr_t tramp = otd.ot_trampoline;

		if (cmd == DDI_CTLOPS_POKE) {
			otd.ot_trampoline = (uintptr_t)&poke_fault;
			err = do_poke(in_args->size, (void *)in_args->dev_addr,
			    (void *)in_args->host_addr);
		} else {
			otd.ot_trampoline = (uintptr_t)&peek_fault;
			err = do_peek(in_args->size, (void *)in_args->dev_addr,
			    (void *)in_args->host_addr);
		}
		otd.ot_trampoline = tramp;
	} else
		err = DDI_FAILURE;

	/* Take down protected environment. */
	no_trap();

	return (err);
}

/*
 * Platform independent DR routines
 */

static int
ndi2errno(int n)
{
	int err = 0;

	switch (n) {
		case NDI_NOMEM:
			err = ENOMEM;
			break;
		case NDI_BUSY:
			err = EBUSY;
			break;
		case NDI_FAULT:
			err = EFAULT;
			break;
		case NDI_FAILURE:
			err = EIO;
			break;
		case NDI_SUCCESS:
			break;
		case NDI_BADHANDLE:
		default:
			err = EINVAL;
			break;
	}
	return (err);
}

/*
 * Prom tree node list
 */
struct ptnode {
	pnode_t		nodeid;
	struct ptnode	*next;
};

/*
 * Prom tree walk arg
 */
struct pta {
	dev_info_t	*pdip;
	devi_branch_t	*bp;
	uint_t		flags;
	dev_info_t	*fdip;
	struct ptnode	*head;
};

static void
visit_node(pnode_t nodeid, struct pta *ap)
{
	struct ptnode	**nextp;
	int		(*select)(pnode_t, void *, uint_t);

	ASSERT(nodeid != OBP_NONODE && nodeid != OBP_BADNODE);

	select = ap->bp->create.prom_branch_select;

	ASSERT(select);

	if (select(nodeid, ap->bp->arg, 0) == DDI_SUCCESS) {

		for (nextp = &ap->head; *nextp; nextp = &(*nextp)->next)
			;

		*nextp = kmem_zalloc(sizeof (struct ptnode), KM_SLEEP);

		(*nextp)->nodeid = nodeid;
	}

	if ((ap->flags & DEVI_BRANCH_CHILD) == DEVI_BRANCH_CHILD)
		return;

	nodeid = prom_childnode(nodeid);
	while (nodeid != OBP_NONODE && nodeid != OBP_BADNODE) {
		visit_node(nodeid, ap);
		nodeid = prom_nextnode(nodeid);
	}
}

/*
 * NOTE: The caller of this function must check for device contracts
 * or LDI callbacks against this dip before setting the dip offline.
 */
static int
set_infant_dip_offline(dev_info_t *dip, void *arg)
{
	char	*path = (char *)arg;

	ASSERT(dip);
	ASSERT(arg);

	if (i_ddi_node_state(dip) >= DS_ATTACHED) {
		(void) ddi_pathname(dip, path);
		cmn_err(CE_WARN, "Attempt to set offline flag on attached "
		    "node: %s", path);
		return (DDI_FAILURE);
	}

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (!DEVI_IS_DEVICE_OFFLINE(dip))
		DEVI_SET_DEVICE_OFFLINE(dip);
	mutex_exit(&(DEVI(dip)->devi_lock));

	return (DDI_SUCCESS);
}

typedef struct result {
	char	*path;
	int	result;
} result_t;

static int
dip_set_offline(dev_info_t *dip, void *arg)
{
	int end;
	result_t *resp = (result_t *)arg;

	ASSERT(dip);
	ASSERT(resp);

	/*
	 * We stop the walk if e_ddi_offline_notify() returns
	 * failure, because this implies that one or more consumers
	 * (either LDI or contract based) has blocked the offline.
	 * So there is no point in conitnuing the walk
	 */
	if (e_ddi_offline_notify(dip) == DDI_FAILURE) {
		resp->result = DDI_FAILURE;
		return (DDI_WALK_TERMINATE);
	}

	/*
	 * If set_infant_dip_offline() returns failure, it implies
	 * that we failed to set a particular dip offline. This
	 * does not imply that the offline as a whole should fail.
	 * We want to do the best we can, so we continue the walk.
	 */
	if (set_infant_dip_offline(dip, resp->path) == DDI_SUCCESS)
		end = DDI_SUCCESS;
	else
		end = DDI_FAILURE;

	e_ddi_offline_finalize(dip, end);

	return (DDI_WALK_CONTINUE);
}

/*
 * The call to e_ddi_offline_notify() exists for the
 * unlikely error case that a branch we are trying to
 * create already exists and has device contracts or LDI
 * event callbacks against it.
 *
 * We allow create to succeed for such branches only if
 * no constraints block the offline.
 */
static int
branch_set_offline(dev_info_t *dip, char *path)
{
	int		circ;
	int		end;
	result_t	res;


	if (e_ddi_offline_notify(dip) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	if (set_infant_dip_offline(dip, path) == DDI_SUCCESS)
		end = DDI_SUCCESS;
	else
		end = DDI_FAILURE;

	e_ddi_offline_finalize(dip, end);

	if (end == DDI_FAILURE)
		return (DDI_FAILURE);

	res.result = DDI_SUCCESS;
	res.path = path;

	ndi_devi_enter(dip, &circ);
	ddi_walk_devs(ddi_get_child(dip), dip_set_offline, &res);
	ndi_devi_exit(dip, circ);

	return (res.result);
}

/*ARGSUSED*/
static int
create_prom_branch(void *arg, int has_changed)
{
	int		circ;
	int		exists, rv;
	pnode_t		nodeid;
	struct ptnode	*tnp;
	dev_info_t	*dip;
	struct pta	*ap = arg;
	devi_branch_t	*bp;
	char		*path;

	ASSERT(ap);
	ASSERT(ap->fdip == NULL);
	ASSERT(ap->pdip && ndi_dev_is_prom_node(ap->pdip));

	bp = ap->bp;

	nodeid = ddi_get_nodeid(ap->pdip);
	if (nodeid == OBP_NONODE || nodeid == OBP_BADNODE) {
		cmn_err(CE_WARN, "create_prom_branch: invalid "
		    "nodeid: 0x%x", nodeid);
		return (EINVAL);
	}

	ap->head = NULL;

	nodeid = prom_childnode(nodeid);
	while (nodeid != OBP_NONODE && nodeid != OBP_BADNODE) {
		visit_node(nodeid, ap);
		nodeid = prom_nextnode(nodeid);
	}

	if (ap->head == NULL)
		return (ENODEV);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	rv = 0;
	while ((tnp = ap->head) != NULL) {
		ap->head = tnp->next;

		ndi_devi_enter(ap->pdip, &circ);

		/*
		 * Check if the branch already exists.
		 */
		exists = 0;
		dip = e_ddi_nodeid_to_dip(tnp->nodeid);
		if (dip != NULL) {
			exists = 1;

			/* Parent is held busy, so release hold */
			ndi_rele_devi(dip);
#ifdef	DEBUG
			cmn_err(CE_WARN, "create_prom_branch: dip(%p) exists"
			    " for nodeid 0x%x", (void *)dip, tnp->nodeid);
#endif
		} else {
			dip = i_ddi_create_branch(ap->pdip, tnp->nodeid);
		}

		kmem_free(tnp, sizeof (struct ptnode));

		/*
		 * Hold the branch if it is not already held
		 */
		if (dip && !exists) {
			e_ddi_branch_hold(dip);
		}

		ASSERT(dip == NULL || e_ddi_branch_held(dip));

		/*
		 * Set all dips in the newly created branch offline so that
		 * only a "configure" operation can attach
		 * the branch
		 */
		if (dip == NULL || branch_set_offline(dip, path)
		    == DDI_FAILURE) {
			ndi_devi_exit(ap->pdip, circ);
			rv = EIO;
			continue;
		}

		ASSERT(ddi_get_parent(dip) == ap->pdip);

		ndi_devi_exit(ap->pdip, circ);

		if (ap->flags & DEVI_BRANCH_CONFIGURE) {
			int error = e_ddi_branch_configure(dip, &ap->fdip, 0);
			if (error && rv == 0)
				rv = error;
		}

		/*
		 * Invoke devi_branch_callback() (if it exists) only for
		 * newly created branches
		 */
		if (bp->devi_branch_callback && !exists)
			bp->devi_branch_callback(dip, bp->arg, 0);
	}

	kmem_free(path, MAXPATHLEN);

	return (rv);
}

static int
sid_node_create(dev_info_t *pdip, devi_branch_t *bp, dev_info_t **rdipp)
{
	int			rv, circ, len;
	int			i, flags, ret;
	dev_info_t		*dip;
	char			*nbuf;
	char			*path;
	static const char	*noname = "<none>";

	ASSERT(pdip);
	ASSERT(DEVI_BUSY_OWNED(pdip));

	flags = 0;

	/*
	 * Creating the root of a branch ?
	 */
	if (rdipp) {
		*rdipp = NULL;
		flags = DEVI_BRANCH_ROOT;
	}

	ndi_devi_alloc_sleep(pdip, (char *)noname, DEVI_SID_NODEID, &dip);
	rv = bp->create.sid_branch_create(dip, bp->arg, flags);

	nbuf = kmem_alloc(OBP_MAXDRVNAME, KM_SLEEP);

	if (rv == DDI_WALK_ERROR) {
		cmn_err(CE_WARN, "e_ddi_branch_create: Error setting"
		    " properties on devinfo node %p",  (void *)dip);
		goto fail;
	}

	len = OBP_MAXDRVNAME;
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "name", nbuf, &len)
	    != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "e_ddi_branch_create: devinfo node %p has"
		    "no name property", (void *)dip);
		goto fail;
	}

	ASSERT(i_ddi_node_state(dip) == DS_PROTO);
	if (ndi_devi_set_nodename(dip, nbuf, 0) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "e_ddi_branch_create: cannot set name (%s)"
		    " for devinfo node %p", nbuf, (void *)dip);
		goto fail;
	}

	kmem_free(nbuf, OBP_MAXDRVNAME);

	/*
	 * Ignore bind failures just like boot does
	 */
	(void) ndi_devi_bind_driver(dip, 0);

	switch (rv) {
	case DDI_WALK_CONTINUE:
	case DDI_WALK_PRUNESIB:
		ndi_devi_enter(dip, &circ);

		i = DDI_WALK_CONTINUE;
		for (; i == DDI_WALK_CONTINUE; ) {
			i = sid_node_create(dip, bp, NULL);
		}

		ASSERT(i == DDI_WALK_ERROR || i == DDI_WALK_PRUNESIB);
		if (i == DDI_WALK_ERROR)
			rv = i;
		/*
		 * If PRUNESIB stop creating siblings
		 * of dip's child. Subsequent walk behavior
		 * is determined by rv returned by dip.
		 */

		ndi_devi_exit(dip, circ);
		break;
	case DDI_WALK_TERMINATE:
		/*
		 * Don't create children and ask our parent
		 * to not create siblings either.
		 */
		rv = DDI_WALK_PRUNESIB;
		break;
	case DDI_WALK_PRUNECHILD:
		/*
		 * Don't create children, but ask parent to continue
		 * with siblings.
		 */
		rv = DDI_WALK_CONTINUE;
		break;
	default:
		ASSERT(0);
		break;
	}

	if (rdipp)
		*rdipp = dip;

	/*
	 * Set device offline - only the "configure" op should cause an attach.
	 * Note that it is safe to set the dip offline without checking
	 * for either device contract or layered driver (LDI) based constraints
	 * since there cannot be any contracts or LDI opens of this device.
	 * This is because this node is a newly created dip with the parent busy
	 * held, so no other thread can come in and attach this dip. A dip that
	 * has never been attached cannot have contracts since by definition
	 * a device contract (an agreement between a process and a device minor
	 * node) can only be created against a device that has minor nodes
	 * i.e is attached. Similarly an LDI open will only succeed if the
	 * dip is attached. We assert below that the dip is not attached.
	 */
	ASSERT(i_ddi_node_state(dip) < DS_ATTACHED);
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	ret = set_infant_dip_offline(dip, path);
	ASSERT(ret == DDI_SUCCESS);
	kmem_free(path, MAXPATHLEN);

	return (rv);
fail:
	(void) ndi_devi_free(dip);
	kmem_free(nbuf, OBP_MAXDRVNAME);
	return (DDI_WALK_ERROR);
}

static int
create_sid_branch(
	dev_info_t	*pdip,
	devi_branch_t	*bp,
	dev_info_t	**dipp,
	uint_t		flags)
{
	int		rv = 0, state = DDI_WALK_CONTINUE;
	dev_info_t	*rdip;

	while (state == DDI_WALK_CONTINUE) {
		int	circ;

		ndi_devi_enter(pdip, &circ);

		state = sid_node_create(pdip, bp, &rdip);
		if (rdip == NULL) {
			ndi_devi_exit(pdip, circ);
			ASSERT(state == DDI_WALK_ERROR);
			break;
		}

		e_ddi_branch_hold(rdip);

		ndi_devi_exit(pdip, circ);

		if (flags & DEVI_BRANCH_CONFIGURE) {
			int error = e_ddi_branch_configure(rdip, dipp, 0);
			if (error && rv == 0)
				rv = error;
		}

		/*
		 * devi_branch_callback() is optional
		 */
		if (bp->devi_branch_callback)
			bp->devi_branch_callback(rdip, bp->arg, 0);
	}

	ASSERT(state == DDI_WALK_ERROR || state == DDI_WALK_PRUNESIB);

	return (state == DDI_WALK_ERROR ? EIO : rv);
}

int
e_ddi_branch_create(
	dev_info_t	*pdip,
	devi_branch_t	*bp,
	dev_info_t	**dipp,
	uint_t		flags)
{
	int prom_devi, sid_devi, error;

	if (pdip == NULL || bp == NULL || bp->type == 0)
		return (EINVAL);

	prom_devi = (bp->type == DEVI_BRANCH_PROM) ? 1 : 0;
	sid_devi = (bp->type == DEVI_BRANCH_SID) ? 1 : 0;

	if (prom_devi && bp->create.prom_branch_select == NULL)
		return (EINVAL);
	else if (sid_devi && bp->create.sid_branch_create == NULL)
		return (EINVAL);
	else if (!prom_devi && !sid_devi)
		return (EINVAL);

	if (flags & DEVI_BRANCH_EVENT)
		return (EINVAL);

	if (prom_devi) {
		struct pta pta = {0};

		pta.pdip = pdip;
		pta.bp = bp;
		pta.flags = flags;

		error = prom_tree_access(create_prom_branch, &pta, NULL);

		if (dipp)
			*dipp = pta.fdip;
		else if (pta.fdip)
			ndi_rele_devi(pta.fdip);
	} else {
		error = create_sid_branch(pdip, bp, dipp, flags);
	}

	return (error);
}

int
e_ddi_branch_configure(dev_info_t *rdip, dev_info_t **dipp, uint_t flags)
{
	int		circ, rv;
	char		*devnm;
	dev_info_t	*pdip;

	if (dipp)
		*dipp = NULL;

	if (rdip == NULL || flags != 0 || (flags & DEVI_BRANCH_EVENT))
		return (EINVAL);

	pdip = ddi_get_parent(rdip);

	ndi_devi_enter(pdip, &circ);

	if (!e_ddi_branch_held(rdip)) {
		ndi_devi_exit(pdip, circ);
		cmn_err(CE_WARN, "e_ddi_branch_configure: "
		    "dip(%p) not held", (void *)rdip);
		return (EINVAL);
	}

	if (i_ddi_node_state(rdip) < DS_INITIALIZED) {
		/*
		 * First attempt to bind a driver. If we fail, return
		 * success (On some platforms, dips for some device
		 * types (CPUs) may not have a driver)
		 */
		if (ndi_devi_bind_driver(rdip, 0) != NDI_SUCCESS) {
			ndi_devi_exit(pdip, circ);
			return (0);
		}

		if (ddi_initchild(pdip, rdip) != DDI_SUCCESS) {
			rv = NDI_FAILURE;
			goto out;
		}
	}

	ASSERT(i_ddi_node_state(rdip) >= DS_INITIALIZED);

	devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);

	(void) ddi_deviname(rdip, devnm);

	if ((rv = ndi_devi_config_one(pdip, devnm+1, &rdip,
	    NDI_DEVI_ONLINE | NDI_CONFIG)) == NDI_SUCCESS) {
		/* release hold from ndi_devi_config_one() */
		ndi_rele_devi(rdip);
	}

	kmem_free(devnm, MAXNAMELEN + 1);
out:
	if (rv != NDI_SUCCESS && dipp) {
		ndi_hold_devi(rdip);
		*dipp = rdip;
	}
	ndi_devi_exit(pdip, circ);
	return (ndi2errno(rv));
}

void
e_ddi_branch_hold(dev_info_t *rdip)
{
	if (e_ddi_branch_held(rdip)) {
		cmn_err(CE_WARN, "e_ddi_branch_hold: branch already held");
		return;
	}

	mutex_enter(&DEVI(rdip)->devi_lock);
	if ((DEVI(rdip)->devi_flags & DEVI_BRANCH_HELD) == 0) {
		DEVI(rdip)->devi_flags |= DEVI_BRANCH_HELD;
		DEVI(rdip)->devi_ref++;
	}
	ASSERT(DEVI(rdip)->devi_ref > 0);
	mutex_exit(&DEVI(rdip)->devi_lock);
}

int
e_ddi_branch_held(dev_info_t *rdip)
{
	int rv = 0;

	mutex_enter(&DEVI(rdip)->devi_lock);
	if ((DEVI(rdip)->devi_flags & DEVI_BRANCH_HELD) &&
	    DEVI(rdip)->devi_ref > 0) {
		rv = 1;
	}
	mutex_exit(&DEVI(rdip)->devi_lock);

	return (rv);
}
void
e_ddi_branch_rele(dev_info_t *rdip)
{
	mutex_enter(&DEVI(rdip)->devi_lock);
	DEVI(rdip)->devi_flags &= ~DEVI_BRANCH_HELD;
	DEVI(rdip)->devi_ref--;
	mutex_exit(&DEVI(rdip)->devi_lock);
}

int
e_ddi_branch_unconfigure(
	dev_info_t *rdip,
	dev_info_t **dipp,
	uint_t flags)
{
	int	circ, rv;
	int	destroy;
	char	*devnm;
	uint_t	nflags;
	dev_info_t *pdip;

	if (dipp)
		*dipp = NULL;

	if (rdip == NULL)
		return (EINVAL);

	pdip = ddi_get_parent(rdip);

	ASSERT(pdip);

	/*
	 * Check if caller holds pdip busy - can cause deadlocks during
	 * devfs_clean()
	 */
	if (DEVI_BUSY_OWNED(pdip)) {
		cmn_err(CE_WARN, "e_ddi_branch_unconfigure: failed: parent"
		    " devinfo node(%p) is busy held", (void *)pdip);
		return (EINVAL);
	}

	destroy = (flags & DEVI_BRANCH_DESTROY) ? 1 : 0;

	devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);

	ndi_devi_enter(pdip, &circ);
	(void) ddi_deviname(rdip, devnm);
	ndi_devi_exit(pdip, circ);

	/*
	 * ddi_deviname() returns a component name with / prepended.
	 */
	(void) devfs_clean(pdip, devnm + 1, DV_CLEAN_FORCE);

	ndi_devi_enter(pdip, &circ);

	/*
	 * Recreate device name as it may have changed state (init/uninit)
	 * when parent busy lock was dropped for devfs_clean()
	 */
	(void) ddi_deviname(rdip, devnm);

	if (!e_ddi_branch_held(rdip)) {
		kmem_free(devnm, MAXNAMELEN + 1);
		ndi_devi_exit(pdip, circ);
		cmn_err(CE_WARN, "e_ddi_%s_branch: dip(%p) not held",
		    destroy ? "destroy" : "unconfigure", (void *)rdip);
		return (EINVAL);
	}

	/*
	 * Release hold on the branch. This is ok since we are holding the
	 * parent busy. If rdip is not removed, we must do a hold on the
	 * branch before returning.
	 */
	e_ddi_branch_rele(rdip);

	nflags = NDI_DEVI_OFFLINE;
	if (destroy || (flags & DEVI_BRANCH_DESTROY)) {
		nflags |= NDI_DEVI_REMOVE;
		destroy = 1;
	} else {
		nflags |= NDI_UNCONFIG;		/* uninit but don't remove */
	}

	if (flags & DEVI_BRANCH_EVENT)
		nflags |= NDI_POST_EVENT;

	if (i_ddi_devi_attached(pdip) &&
	    (i_ddi_node_state(rdip) >= DS_INITIALIZED)) {
		rv = ndi_devi_unconfig_one(pdip, devnm+1, dipp, nflags);
	} else {
		rv = e_ddi_devi_unconfig(rdip, dipp, nflags);
		if (rv == NDI_SUCCESS) {
			ASSERT(!destroy || ddi_get_child(rdip) == NULL);
			rv = ndi_devi_offline(rdip, nflags);
		}
	}

	if (!destroy || rv != NDI_SUCCESS) {
		/* The dip still exists, so do a hold */
		e_ddi_branch_hold(rdip);
	}
out:
	kmem_free(devnm, MAXNAMELEN + 1);
	ndi_devi_exit(pdip, circ);
	return (ndi2errno(rv));
}

int
e_ddi_branch_destroy(dev_info_t *rdip, dev_info_t **dipp, uint_t flag)
{
	return (e_ddi_branch_unconfigure(rdip, dipp,
	    flag|DEVI_BRANCH_DESTROY));
}

/*
 * Number of chains for hash table
 */
#define	NUMCHAINS	17

/*
 * Devinfo busy arg
 */
struct devi_busy {
	int dv_total;
	int s_total;
	mod_hash_t *dv_hash;
	mod_hash_t *s_hash;
	int (*callback)(dev_info_t *, void *, uint_t);
	void *arg;
};

static int
visit_dip(dev_info_t *dip, void *arg)
{
	uintptr_t sbusy, dvbusy, ref;
	struct devi_busy *bsp = arg;

	ASSERT(bsp->callback);

	/*
	 * A dip cannot be busy if its reference count is 0
	 */
	if ((ref = e_ddi_devi_holdcnt(dip)) == 0) {
		return (bsp->callback(dip, bsp->arg, 0));
	}

	if (mod_hash_find(bsp->dv_hash, dip, (mod_hash_val_t *)&dvbusy))
		dvbusy = 0;

	/*
	 * To catch device opens currently maintained on specfs common snodes.
	 */
	if (mod_hash_find(bsp->s_hash, dip, (mod_hash_val_t *)&sbusy))
		sbusy = 0;

#ifdef	DEBUG
	if (ref < sbusy || ref < dvbusy) {
		cmn_err(CE_WARN, "dip(%p): sopen = %lu, dvopen = %lu "
		    "dip ref = %lu\n", (void *)dip, sbusy, dvbusy, ref);
	}
#endif

	dvbusy = (sbusy > dvbusy) ? sbusy : dvbusy;

	return (bsp->callback(dip, bsp->arg, dvbusy));
}

static int
visit_snode(struct snode *sp, void *arg)
{
	uintptr_t sbusy;
	dev_info_t *dip;
	int count;
	struct devi_busy *bsp = arg;

	ASSERT(sp);

	/*
	 * The stable lock is held. This prevents
	 * the snode and its associated dip from
	 * going away.
	 */
	dip = NULL;
	count = spec_devi_open_count(sp, &dip);

	if (count <= 0)
		return (DDI_WALK_CONTINUE);

	ASSERT(dip);

	if (mod_hash_remove(bsp->s_hash, dip, (mod_hash_val_t *)&sbusy))
		sbusy = count;
	else
		sbusy += count;

	if (mod_hash_insert(bsp->s_hash, dip, (mod_hash_val_t)sbusy)) {
		cmn_err(CE_WARN, "%s: s_hash insert failed: dip=0x%p, "
		    "sbusy = %lu", "e_ddi_branch_referenced",
		    (void *)dip, sbusy);
	}

	bsp->s_total += count;

	return (DDI_WALK_CONTINUE);
}

static void
visit_dvnode(struct dv_node *dv, void *arg)
{
	uintptr_t dvbusy;
	uint_t count;
	struct vnode *vp;
	struct devi_busy *bsp = arg;

	ASSERT(dv && dv->dv_devi);

	vp = DVTOV(dv);

	mutex_enter(&vp->v_lock);
	count = vp->v_count;
	mutex_exit(&vp->v_lock);

	if (!count)
		return;

	if (mod_hash_remove(bsp->dv_hash, dv->dv_devi,
	    (mod_hash_val_t *)&dvbusy))
		dvbusy = count;
	else
		dvbusy += count;

	if (mod_hash_insert(bsp->dv_hash, dv->dv_devi,
	    (mod_hash_val_t)dvbusy)) {
		cmn_err(CE_WARN, "%s: dv_hash insert failed: dip=0x%p, "
		    "dvbusy=%lu", "e_ddi_branch_referenced",
		    (void *)dv->dv_devi, dvbusy);
	}

	bsp->dv_total += count;
}

/*
 * Returns reference count on success or -1 on failure.
 */
int
e_ddi_branch_referenced(
	dev_info_t *rdip,
	int (*callback)(dev_info_t *dip, void *arg, uint_t ref),
	void *arg)
{
	int circ;
	char *path;
	dev_info_t *pdip;
	struct devi_busy bsa = {0};

	ASSERT(rdip);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	ndi_hold_devi(rdip);

	pdip = ddi_get_parent(rdip);

	ASSERT(pdip);

	/*
	 * Check if caller holds pdip busy - can cause deadlocks during
	 * devfs_walk()
	 */
	if (!e_ddi_branch_held(rdip) || DEVI_BUSY_OWNED(pdip)) {
		cmn_err(CE_WARN, "e_ddi_branch_referenced: failed: "
		    "devinfo branch(%p) not held or parent busy held",
		    (void *)rdip);
		ndi_rele_devi(rdip);
		kmem_free(path, MAXPATHLEN);
		return (-1);
	}

	ndi_devi_enter(pdip, &circ);
	(void) ddi_pathname(rdip, path);
	ndi_devi_exit(pdip, circ);

	bsa.dv_hash = mod_hash_create_ptrhash("dv_node busy hash", NUMCHAINS,
	    mod_hash_null_valdtor, sizeof (struct dev_info));

	bsa.s_hash = mod_hash_create_ptrhash("snode busy hash", NUMCHAINS,
	    mod_hash_null_valdtor, sizeof (struct snode));

	if (devfs_walk(path, visit_dvnode, &bsa)) {
		cmn_err(CE_WARN, "e_ddi_branch_referenced: "
		    "devfs walk failed for: %s", path);
		kmem_free(path, MAXPATHLEN);
		bsa.s_total = bsa.dv_total = -1;
		goto out;
	}

	kmem_free(path, MAXPATHLEN);

	/*
	 * Walk the snode table to detect device opens, which are currently
	 * maintained on specfs common snodes.
	 */
	spec_snode_walk(visit_snode, &bsa);

	if (callback == NULL)
		goto out;

	bsa.callback = callback;
	bsa.arg = arg;

	if (visit_dip(rdip, &bsa) == DDI_WALK_CONTINUE) {
		ndi_devi_enter(rdip, &circ);
		ddi_walk_devs(ddi_get_child(rdip), visit_dip, &bsa);
		ndi_devi_exit(rdip, circ);
	}

out:
	ndi_rele_devi(rdip);
	mod_hash_destroy_ptrhash(bsa.s_hash);
	mod_hash_destroy_ptrhash(bsa.dv_hash);
	return (bsa.s_total > bsa.dv_total ? bsa.s_total : bsa.dv_total);
}
