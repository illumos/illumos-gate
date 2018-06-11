/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/sunndi.h>
#include <contrib/dev/acpica/include/acpi.h>

dev_info_t *
vtd_get_dip(ACPI_DMAR_HARDWARE_UNIT *drhd, int unit)
{
	dev_info_t *dip;
	struct ddi_parent_private_data *pdptr;
	struct regspec reg;
	int circ;

	/*
	 * Try to find an existing devinfo node for this vtd unit.
	 */
	ndi_devi_enter(ddi_root_node(), &circ);
	dip = ddi_find_devinfo("vtd", unit, 0);
	ndi_devi_exit(ddi_root_node(), circ);

	if (dip != NULL)
		return (dip);

	/*
	 * None found, construct a devinfo node for this vtd unit.
	 */
	dip = ddi_add_child(ddi_root_node(), "vtd",
	    DEVI_SID_NODEID, unit);

	reg.regspec_bustype = 0;
	reg.regspec_addr = drhd->Address;
	reg.regspec_size = PAGE_SIZE;

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
	pdptr->par_reg->regspec_addr = drhd->Address;
	pdptr->par_reg->regspec_size = PAGE_SIZE;
	ddi_set_parent_data(dip, pdptr);

	return (dip);
}
