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
 * Copyright 2013 Pluribus Networks, Inc.
 */

/*
 * Support for MSI, MSIX and INTx
 */

#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/pci_cap.h>
#include <sys/pci_intr_lib.h>
#include <sys/sunddi.h>
#include <sys/bitmap.h>

/*
 * MSI-X BIR Index Table:
 *
 * BAR indicator register (BIR) to Base Address register.
 */
static	uchar_t pci_msix_bir_index[8] = {0x10, 0x14, 0x18, 0x1c,
					0x20, 0x24, 0xff, 0xff};

/* default class to pil value mapping */
pci_class_val_t pci_default_pil [] = {
	{0x000000, 0xff0000, 0x1},	/* Class code for pre-2.0 devices */
	{0x010000, 0xff0000, 0x5},	/* Mass Storage Controller */
	{0x020000, 0xff0000, 0x6},	/* Network Controller */
	{0x030000, 0xff0000, 0x9},	/* Display Controller */
	{0x040000, 0xff0000, 0x8},	/* Multimedia Controller */
	{0x050000, 0xff0000, 0x9},	/* Memory Controller */
	{0x060000, 0xff0000, 0x9},	/* Bridge Controller */
	{0x0c0000, 0xffff00, 0x9},	/* Serial Bus, FireWire (IEEE 1394) */
	{0x0c0100, 0xffff00, 0x4},	/* Serial Bus, ACCESS.bus */
	{0x0c0200, 0xffff00, 0x4},	/* Serial Bus, SSA */
	{0x0c0300, 0xffff00, 0x9},	/* Serial Bus Universal Serial Bus */
/*
 * XXX - This is a temporary workaround and it will be removed
 *       after x86 interrupt scalability support.
 */
#if defined(__i386) || defined(__amd64)
	{0x0c0400, 0xffff00, 0x5},	/* Serial Bus, Fibre Channel */
#else
	{0x0c0400, 0xffff00, 0x6},	/* Serial Bus, Fibre Channel */
#endif
	{0x0c0600, 0xffff00, 0x6}	/* Serial Bus, Infiniband */
};

/*
 * Default class to intr_weight value mapping (% of CPU).  A driver.conf
 * entry on or above the pci node like
 *
 *	pci-class-intr-weights= 0x020000, 0xff0000, 30;
 *
 * can be used to augment or override entries in the default table below.
 *
 * NB: The values below give NICs preference on redistribution, and provide
 * NICs some isolation from other interrupt sources. We need better interfaces
 * that allow the NIC driver to identify a specific NIC instance as high
 * bandwidth, and thus deserving of separation from other low bandwidth
 * NICs additional isolation from other interrupt sources.
 *
 * NB: We treat Infiniband like a NIC.
 */
pci_class_val_t pci_default_intr_weight [] = {
	{0x020000, 0xff0000, 35},	/* Network Controller */
	{0x010000, 0xff0000, 10},	/* Mass Storage Controller */
	{0x0c0400, 0xffff00, 10},	/* Serial Bus, Fibre Channel */
	{0x0c0600, 0xffff00, 50}	/* Serial Bus, Infiniband */
};

/*
 * Library utility functions
 */

/*
 * pci_get_msi_ctrl:
 *
 *	Helper function that returns with 'cfg_hdl', MSI/X ctrl pointer,
 *	and caps_ptr for MSI/X if these are found.
 */
static int
pci_get_msi_ctrl(dev_info_t *dip, int type, ushort_t *msi_ctrl,
    ushort_t *caps_ptr, ddi_acc_handle_t *h)
{
	*msi_ctrl = *caps_ptr = 0;

	if (pci_config_setup(dip, h) != DDI_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_get_msi_ctrl: "
		    "%s%d can't get config handle",
		    ddi_driver_name(dip), ddi_get_instance(dip)));

		return (DDI_FAILURE);
	}

	if ((PCI_CAP_LOCATE(*h, PCI_CAP_ID_MSI, caps_ptr) == DDI_SUCCESS) &&
	    (type == DDI_INTR_TYPE_MSI)) {
		if ((*msi_ctrl = PCI_CAP_GET16(*h, NULL, *caps_ptr,
		    PCI_MSI_CTRL)) == PCI_CAP_EINVAL16)
			goto done;

		DDI_INTR_NEXDBG((CE_CONT, "pci_get_msi_ctrl: MSI "
		    "caps_ptr=%x msi_ctrl=%x\n", *caps_ptr, *msi_ctrl));

		return (DDI_SUCCESS);
	}

	if ((PCI_CAP_LOCATE(*h, PCI_CAP_ID_MSI_X, caps_ptr) == DDI_SUCCESS) &&
	    (type == DDI_INTR_TYPE_MSIX)) {
		if ((*msi_ctrl = PCI_CAP_GET16(*h, NULL, *caps_ptr,
		    PCI_MSIX_CTRL)) == PCI_CAP_EINVAL16)
			goto done;

		DDI_INTR_NEXDBG((CE_CONT, "pci_get_msi_ctrl: MSI-X "
		    "caps_ptr=%x msi_ctrl=%x\n", *caps_ptr, *msi_ctrl));

		return (DDI_SUCCESS);
	}

done:
	pci_config_teardown(h);
	return (DDI_FAILURE);
}


/*
 * pci_msi_get_cap:
 *
 * Get the capabilities of the MSI/X interrupt
 */
int
pci_msi_get_cap(dev_info_t *rdip, int type, int *flagsp)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_get_cap: rdip = 0x%p\n",
	    (void *)rdip));

	*flagsp = 0;

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (type == DDI_INTR_TYPE_MSI) {
		if (msi_ctrl &  PCI_MSI_64BIT_MASK)
			*flagsp |= DDI_INTR_FLAG_MSI64;
		if (msi_ctrl & PCI_MSI_PVM_MASK)
			*flagsp |= (DDI_INTR_FLAG_MASKABLE |
			    DDI_INTR_FLAG_PENDING);
		else
			*flagsp |= DDI_INTR_FLAG_BLOCK;
	} else if (type == DDI_INTR_TYPE_MSIX) {
		/* MSI-X supports PVM, 64bit by default */
		*flagsp |= (DDI_INTR_FLAG_MASKABLE | DDI_INTR_FLAG_MSI64 |
		    DDI_INTR_FLAG_PENDING);
	}

	*flagsp |= DDI_INTR_FLAG_EDGE;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_get_cap: flags = 0x%x\n", *flagsp));

	pci_config_teardown(&cfg_hdle);
	return (DDI_SUCCESS);
}


/*
 * pci_msi_configure:
 *
 * Configure address/data and number MSI/Xs fields in the MSI/X
 * capability structure.
 */
/* ARGSUSED */
int
pci_msi_configure(dev_info_t *rdip, int type, int count, int inum,
    uint64_t addr, uint64_t data)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	h;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_configure: rdip = 0x%p type 0x%x "
	    "count 0x%x inum 0x%x addr 0x%" PRIx64 " data 0x%" PRIx64 "\n",
	    (void *)rdip, type, count, inum, addr, data));

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &h) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (type == DDI_INTR_TYPE_MSI) {
		/* Set the bits to inform how many MSIs are enabled */
		msi_ctrl |= ((highbit(count) -1) << PCI_MSI_MME_SHIFT);
		PCI_CAP_PUT16(h, NULL, caps_ptr, PCI_MSI_CTRL, msi_ctrl);

		DDI_INTR_NEXDBG((CE_CONT, "pci_msi_configure: msi_ctrl = %x\n",
		    PCI_CAP_GET16(h, NULL, caps_ptr, PCI_MSI_CTRL)));

		/* Set the "data" and "addr" bits */
		PCI_CAP_PUT32(h, NULL, caps_ptr, PCI_MSI_ADDR_OFFSET, addr);

		DDI_INTR_NEXDBG((CE_CONT, "pci_msi_configure: msi_addr = %x\n",
		    PCI_CAP_GET32(h, NULL, caps_ptr, PCI_MSI_ADDR_OFFSET)));

		if (msi_ctrl &  PCI_MSI_64BIT_MASK) {
			PCI_CAP_PUT32(h, NULL, caps_ptr, PCI_MSI_ADDR_OFFSET
			    + 4, addr >> 32);

			DDI_INTR_NEXDBG((CE_CONT, "pci_msi_configure: upper "
			    "32bit msi_addr = %x\n", PCI_CAP_GET32(h, NULL,
			    caps_ptr, PCI_MSI_ADDR_OFFSET + 4)));

			PCI_CAP_PUT16(h, NULL, caps_ptr, PCI_MSI_64BIT_DATA,
			    data);

			DDI_INTR_NEXDBG((CE_CONT, "pci_msi_configure: msi_data "
			    "= %x\n", PCI_CAP_GET16(h, NULL, caps_ptr,
			    PCI_MSI_64BIT_DATA)));
		} else {
			PCI_CAP_PUT16(h, NULL, caps_ptr, PCI_MSI_32BIT_DATA,
			    data);

			DDI_INTR_NEXDBG((CE_CONT, "pci_msi_configure: msi_data "
			    "= %x\n", PCI_CAP_GET16(h, NULL, caps_ptr,
			    PCI_MSI_32BIT_DATA)));
		}
	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t	off;
		ddi_intr_msix_t	*msix_p = i_ddi_get_msix(rdip);

		/* Offset into the "inum"th entry in the MSI-X table */
		off = (uintptr_t)msix_p->msix_tbl_addr +
		    (inum * PCI_MSIX_VECTOR_SIZE);

		/* Set the "data" and "addr" bits */
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_DATA_OFFSET), data);

		/*
		 * Note that the spec only requires 32-bit accesses
		 * to be supported.  Apparently some chipsets don't
		 * support 64-bit accesses.
		 */
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_LOWER_ADDR_OFFSET), addr);
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_UPPER_ADDR_OFFSET),
		    addr >> 32);

		DDI_INTR_NEXDBG((CE_CONT, "pci_msi_configure: "
		    "msix_addr 0x%x.%x msix_data 0x%x\n",
		    ddi_get32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_UPPER_ADDR_OFFSET)),
		    ddi_get32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_LOWER_ADDR_OFFSET)),
		    ddi_get32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_DATA_OFFSET))));
	}

	pci_config_teardown(&h);
	return (DDI_SUCCESS);
}


/*
 * pci_msi_unconfigure:
 *
 * Unconfigure address/data and number MSI/Xs fields in the MSI/X
 * capability structure.
 */
/* ARGSUSED */
int
pci_msi_unconfigure(dev_info_t *rdip, int type, int inum)
{
	ushort_t		msi_ctrl, caps_ptr;
	ddi_acc_handle_t	h;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_unconfigure: rdip = 0x%p type 0x%x "
	    "inum 0x%x\n", (void *)rdip, type, inum));

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl, &caps_ptr, &h) !=
	    DDI_SUCCESS)
		return (DDI_FAILURE);

	if (type == DDI_INTR_TYPE_MSI) {
		msi_ctrl &= (~PCI_MSI_MME_MASK);
		PCI_CAP_PUT16(h, NULL, caps_ptr, PCI_MSI_CTRL, msi_ctrl);

		PCI_CAP_PUT32(h, NULL, caps_ptr, PCI_MSI_ADDR_OFFSET, 0);

		if (msi_ctrl &  PCI_MSI_64BIT_MASK) {
			PCI_CAP_PUT16(h, NULL, caps_ptr, PCI_MSI_64BIT_DATA,
			    0);
			PCI_CAP_PUT32(h, NULL, caps_ptr, PCI_MSI_ADDR_OFFSET
			    + 4, 0);
		} else {
			PCI_CAP_PUT16(h, NULL, caps_ptr, PCI_MSI_32BIT_DATA,
			    0);
		}

		DDI_INTR_NEXDBG((CE_CONT, "pci_msi_unconfigure: msi_ctrl "
		    "= %x\n", PCI_CAP_GET16(h, NULL, caps_ptr, PCI_MSI_CTRL)));

	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t	off;
		ddi_intr_msix_t	*msix_p = i_ddi_get_msix(rdip);

		/* Offset into the "inum"th entry in the MSI-X table */
		off = (uintptr_t)msix_p->msix_tbl_addr +
		    (inum * PCI_MSIX_VECTOR_SIZE);

		/* Reset the "data" and "addr" bits */
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_DATA_OFFSET), 0);

		/*
		 * Note that the spec only requires 32-bit accesses
		 * to be supported.  Apparently some chipsets don't
		 * support 64-bit accesses.
		 */
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_LOWER_ADDR_OFFSET), 0);
		ddi_put32(msix_p->msix_tbl_hdl,
		    (uint32_t *)(off + PCI_MSIX_UPPER_ADDR_OFFSET), 0);
	}

	pci_config_teardown(&h);
	return (DDI_SUCCESS);
}


/*
 * pci_is_msi_enabled:
 *
 * This function returns DDI_SUCCESS if MSI/X is already enabled, otherwise
 * it returns DDI_FAILURE.
 */
int
pci_is_msi_enabled(dev_info_t *rdip, int type)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;
	int			ret = DDI_FAILURE;

	DDI_INTR_NEXDBG((CE_CONT, "pci_is_msi_enabled: rdip = 0x%p, "
	    "type  = 0x%x\n", (void *)rdip, type));

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((type == DDI_INTR_TYPE_MSI) && (msi_ctrl & PCI_MSI_ENABLE_BIT))
		ret = DDI_SUCCESS;

	if ((type == DDI_INTR_TYPE_MSIX) && (msi_ctrl & PCI_MSIX_ENABLE_BIT))
		ret = DDI_SUCCESS;

	pci_config_teardown(&cfg_hdle);
	return (ret);
}


/*
 * pci_msi_enable_mode:
 *
 * This function sets the MSI_ENABLE bit in the capability structure
 * (for MSI) and MSIX_ENABLE bit in the MSI-X capability structure.
 *
 * NOTE: It is the nexus driver's responsibility to clear the MSI/X
 * interrupt's mask bit in the MSI/X capability structure before the
 * interrupt can be used.
 */
int
pci_msi_enable_mode(dev_info_t *rdip, int type)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_enable_mode: rdip = 0x%p\n",
	    (void *)rdip));

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (type == DDI_INTR_TYPE_MSI) {
		if (msi_ctrl & PCI_MSI_ENABLE_BIT)
			goto finished;

		msi_ctrl |= PCI_MSI_ENABLE_BIT;
		PCI_CAP_PUT16(cfg_hdle, NULL, caps_ptr, PCI_MSI_CTRL, msi_ctrl);

	} else if (type == DDI_INTR_TYPE_MSIX) {
		if (msi_ctrl & PCI_MSIX_ENABLE_BIT)
			goto finished;

		msi_ctrl |= PCI_MSIX_ENABLE_BIT;
		PCI_CAP_PUT16(cfg_hdle, NULL, caps_ptr, PCI_MSIX_CTRL,
		    msi_ctrl);
	}

finished:
	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_enable_mode: msi_ctrl = %x\n",
	    msi_ctrl));

	pci_config_teardown(&cfg_hdle);
	return (DDI_SUCCESS);
}


/*
 * pci_msi_disable_mode:
 *
 * This function resets the MSI_ENABLE bit in the capability structure
 * (for MSI) and MSIX_ENABLE bit in the MSI-X capability structure.
 *
 * NOTE: It is the nexus driver's responsibility to set the MSI/X
 * interrupt's mask bit in the MSI/X capability structure before the
 * interrupt can be disabled.
 */
int
pci_msi_disable_mode(dev_info_t *rdip, int type)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_disable_mode: rdip = 0x%p\n",
	    (void *)rdip));

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* Reset the "enable" bit */
	if (type == DDI_INTR_TYPE_MSI) {
		if (!(msi_ctrl & PCI_MSI_ENABLE_BIT))
			goto finished;
		msi_ctrl &= ~PCI_MSI_ENABLE_BIT;
		PCI_CAP_PUT16(cfg_hdle, NULL, caps_ptr, PCI_MSI_CTRL, msi_ctrl);
	} else if (type == DDI_INTR_TYPE_MSIX) {
		if (!(msi_ctrl & PCI_MSIX_ENABLE_BIT))
			goto finished;

		msi_ctrl &= ~PCI_MSIX_ENABLE_BIT;
		PCI_CAP_PUT16(cfg_hdle, NULL, caps_ptr, PCI_MSIX_CTRL,
		    msi_ctrl);
	}

finished:
	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_disable_mode: msi_ctrl = %x\n",
	    msi_ctrl));

	pci_config_teardown(&cfg_hdle);
	return (DDI_SUCCESS);
}


/*
 * pci_msi_set_mask:
 *
 * Set the mask bit in the MSI/X capability structure
 */
/* ARGSUSED */
int
pci_msi_set_mask(dev_info_t *rdip, int type, int inum)
{
	int			offset;
	int			ret = DDI_FAILURE;
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;
	uint32_t		mask_bits;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_set_mask: rdip = 0x%p, "
	    "type = 0x%x\n", (void *)rdip, type));

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (type == DDI_INTR_TYPE_MSI) {
		if (!(msi_ctrl &  PCI_MSI_PVM_MASK))
			goto done;

		offset = (msi_ctrl &  PCI_MSI_64BIT_MASK) ?
		    PCI_MSI_64BIT_MASKBITS : PCI_MSI_32BIT_MASK;

		if ((mask_bits = PCI_CAP_GET32(cfg_hdle, NULL, caps_ptr,
		    offset)) == PCI_CAP_EINVAL32)
			goto done;

		mask_bits |= (1 << inum);

		PCI_CAP_PUT32(cfg_hdle, NULL, caps_ptr, offset, mask_bits);

	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t		off;
		ddi_intr_msix_t		*msix_p;

		/* Set function mask */
		if (msi_ctrl & PCI_MSIX_FUNCTION_MASK) {
			ret = DDI_SUCCESS;
			goto done;
		}

		msix_p = i_ddi_get_msix(rdip);

		/* Offset into the "inum"th entry in the MSI-X table */
		off = (uintptr_t)msix_p->msix_tbl_addr + (inum *
		    PCI_MSIX_VECTOR_SIZE) + PCI_MSIX_VECTOR_CTRL_OFFSET;

		/* Set the Mask bit */
		ddi_put32(msix_p->msix_tbl_hdl, (uint32_t *)off, 0x1);
	}

	ret = DDI_SUCCESS;
done:
	pci_config_teardown(&cfg_hdle);
	return (ret);
}


/*
 * pci_msi_clr_mask:
 *
 * Clear the mask bit in the MSI/X capability structure
 */
/* ARGSUSED */
int
pci_msi_clr_mask(dev_info_t *rdip, int type, int inum)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;
	int			offset;
	int			ret = DDI_FAILURE;
	uint32_t		mask_bits;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_clr_mask: rdip = 0x%p, "
	    "type = 0x%x\n", (void *)rdip, type));

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (type == DDI_INTR_TYPE_MSI) {
		if (!(msi_ctrl &  PCI_MSI_PVM_MASK))
			goto done;

		offset = (msi_ctrl &  PCI_MSI_64BIT_MASK) ?
		    PCI_MSI_64BIT_MASKBITS : PCI_MSI_32BIT_MASK;
		if ((mask_bits = PCI_CAP_GET32(cfg_hdle, NULL, caps_ptr,
		    offset)) == PCI_CAP_EINVAL32)
			goto done;

		mask_bits &= ~(1 << inum);

		PCI_CAP_PUT32(cfg_hdle, NULL, caps_ptr, offset, mask_bits);

	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t		off;
		ddi_intr_msix_t		*msix_p;

		if (msi_ctrl & PCI_MSIX_FUNCTION_MASK) {
			ret = DDI_SUCCESS;
			goto done;
		}

		msix_p = i_ddi_get_msix(rdip);

		/* Offset into the "inum"th entry in the MSI-X table */
		off = (uintptr_t)msix_p->msix_tbl_addr + (inum *
		    PCI_MSIX_VECTOR_SIZE) + PCI_MSIX_VECTOR_CTRL_OFFSET;

		/* Clear the Mask bit */
		ddi_put32(msix_p->msix_tbl_hdl, (uint32_t *)off, 0x0);
	}

	ret = DDI_SUCCESS;
done:
	pci_config_teardown(&cfg_hdle);
	return (ret);
}


/*
 * pci_msi_get_pending:
 *
 * Get the pending bit from the MSI/X capability structure
 */
/* ARGSUSED */
int
pci_msi_get_pending(dev_info_t *rdip, int type, int inum, int *pendingp)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;
	int			offset;
	int			ret = DDI_FAILURE;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_get_pending: rdip = 0x%p\n",
	    (void *)rdip));

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (type == DDI_INTR_TYPE_MSI) {
		uint32_t	pending_bits;

		if (!(msi_ctrl &  PCI_MSI_PVM_MASK)) {
			DDI_INTR_NEXDBG((CE_CONT, "pci_msi_get_pending: "
			    "PVM is not supported\n"));
			goto done;
		}

		offset = (msi_ctrl &  PCI_MSI_64BIT_MASK) ?
		    PCI_MSI_64BIT_PENDING : PCI_MSI_32BIT_PENDING;

		if ((pending_bits = PCI_CAP_GET32(cfg_hdle, NULL, caps_ptr,
		    offset)) == PCI_CAP_EINVAL32)
			goto done;

		*pendingp = pending_bits & ~(1 >> inum);

	} else if (type == DDI_INTR_TYPE_MSIX) {
		uintptr_t	off;
		uint64_t	pending_bits;
		ddi_intr_msix_t	*msix_p = i_ddi_get_msix(rdip);

		/* Offset into the PBA array which has entry for "inum" */
		off = (uintptr_t)msix_p->msix_pba_addr + (inum / 64);

		/* Read the PBA array */
		pending_bits = ddi_get64(msix_p->msix_pba_hdl, (uint64_t *)off);

		*pendingp = pending_bits & ~(1 >> inum);
	}

	ret = DDI_SUCCESS;
done:
	pci_config_teardown(&cfg_hdle);
	return (ret);
}


/*
 * pci_msi_get_nintrs:
 *
 * For a given type (MSI/X) returns the number of interrupts supported
 */
int
pci_msi_get_nintrs(dev_info_t *rdip, int type, int *nintrs)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_get_nintrs: rdip = 0x%p\n",
	    (void *)rdip));

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (type == DDI_INTR_TYPE_MSI) {
		*nintrs = 1 << ((msi_ctrl & PCI_MSI_MMC_MASK) >>
		    PCI_MSI_MMC_SHIFT);
	} else if (type == DDI_INTR_TYPE_MSIX) {
		if (msi_ctrl &  PCI_MSIX_TBL_SIZE_MASK)
			*nintrs = (msi_ctrl & PCI_MSIX_TBL_SIZE_MASK) + 1;
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_get_nintrs: "
	    "nintr = 0x%x\n", *nintrs));

	pci_config_teardown(&cfg_hdle);
	return (DDI_SUCCESS);
}


/*
 * pci_msi_set_nintrs:
 *
 * For a given type (MSI/X) sets the number of interrupts supported
 * by the system.
 * For MSI: Return an error if this func is called for navail > 32
 * For MSI-X: Return an error if this func is called for navail > 2048
 */
int
pci_msi_set_nintrs(dev_info_t *rdip, int type, int navail)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_set_nintrs: rdip = 0x%p, "
	    "navail = 0x%x\n", (void *)rdip, navail));

	/* Check for valid input argument */
	if (((type == DDI_INTR_TYPE_MSI) && (navail > PCI_MSI_MAX_INTRS)) ||
	    ((type == DDI_INTR_TYPE_MSIX) && (navail >  PCI_MSIX_MAX_INTRS)))
		return (DDI_EINVAL);

	if (pci_get_msi_ctrl(rdip, type, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (type == DDI_INTR_TYPE_MSI) {
		msi_ctrl |= ((highbit(navail) -1) << PCI_MSI_MME_SHIFT);

		PCI_CAP_PUT16(cfg_hdle, NULL, caps_ptr, PCI_MSI_CTRL, msi_ctrl);
	} else if (type == DDI_INTR_TYPE_MSIX) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_msi_set_nintrs: unsupported\n"));
	}

	pci_config_teardown(&cfg_hdle);
	return (DDI_SUCCESS);
}


/*
 * pci_msi_get_supported_type:
 *
 * Returns DDI_INTR_TYPE_MSI and/or DDI_INTR_TYPE_MSIX as supported
 * types if device supports them. A DDI_FAILURE is returned otherwise.
 */
int
pci_msi_get_supported_type(dev_info_t *rdip, int *typesp)
{
	ushort_t		caps_ptr, msi_ctrl;
	ddi_acc_handle_t	cfg_hdle;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_get_supported_type: "
	    "rdip = 0x%p\n", (void *)rdip));

	*typesp = 0;

	if (pci_get_msi_ctrl(rdip, DDI_INTR_TYPE_MSI, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) == DDI_SUCCESS) {
		*typesp |= DDI_INTR_TYPE_MSI;
		pci_config_teardown(&cfg_hdle);
	}

	if (pci_get_msi_ctrl(rdip, DDI_INTR_TYPE_MSIX, &msi_ctrl,
	    &caps_ptr, &cfg_hdle) == DDI_SUCCESS) {
		*typesp |= DDI_INTR_TYPE_MSIX;
		pci_config_teardown(&cfg_hdle);
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_msi_get_supported_type: "
	    "rdip = 0x%p types 0x%x\n", (void *)rdip, *typesp));

	return (*typesp == 0 ? DDI_FAILURE : DDI_SUCCESS);
}


/*
 * pci_msix_init:
 *	This function initializes the various handles/addrs etc.
 *	needed for MSI-X support. It also allocates a private
 *	structure to keep track of these.
 */
ddi_intr_msix_t *
pci_msix_init(dev_info_t *rdip)
{
	uint_t			rnumber, breg, nregs;
	size_t			msix_tbl_size;
	size_t			pba_tbl_size;
	ushort_t		caps_ptr, msix_ctrl;
	ddi_intr_msix_t		*msix_p;
	ddi_acc_handle_t	cfg_hdle;
	pci_regspec_t		*rp;
	int			reg_size, addr_space, offset, *regs_list;
	int			i, ret;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: rdip = %p\n", (void *)rdip));

	if (pci_get_msi_ctrl(rdip, DDI_INTR_TYPE_MSIX, &msix_ctrl,
	    &caps_ptr, &cfg_hdle) != DDI_SUCCESS)
		return (NULL);

	msix_p = kmem_zalloc(sizeof (ddi_intr_msix_t), KM_SLEEP);

	/*
	 * Initialize the devacc structure
	 */
	msix_p->msix_dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	msix_p->msix_dev_attr.devacc_attr_endian_flags =
	    DDI_STRUCTURE_LE_ACC;
	msix_p->msix_dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Map the entire MSI-X vector table */
	msix_p->msix_tbl_offset = PCI_CAP_GET32(cfg_hdle, NULL, caps_ptr,
	    PCI_MSIX_TBL_OFFSET);

	if ((breg = pci_msix_bir_index[msix_p->msix_tbl_offset &
	    PCI_MSIX_TBL_BIR_MASK]) == 0xff)
		goto fail1;

	msix_p->msix_tbl_offset = msix_p->msix_tbl_offset &
	    ~PCI_MSIX_TBL_BIR_MASK;
	msix_tbl_size = ((msix_ctrl & PCI_MSIX_TBL_SIZE_MASK) + 1) *
	    PCI_MSIX_VECTOR_SIZE;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: MSI-X table offset 0x%x "
	    "breg 0x%x size 0x%lx\n", msix_p->msix_tbl_offset, breg,
	    msix_tbl_size));

	if ((ret = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "reg", (int **)&regs_list, &nregs))
	    != DDI_PROP_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: "
		    "ddi_prop_lookup_int_array failed %d\n", ret));

		goto fail1;
	}

	reg_size = sizeof (pci_regspec_t) / sizeof (int);

	for (i = 1, rnumber = 0; i < nregs/reg_size; i++) {
		rp = (pci_regspec_t *)&regs_list[i * reg_size];
		addr_space = rp->pci_phys_hi & PCI_ADDR_MASK;
		offset = PCI_REG_REG_G(rp->pci_phys_hi);

		if ((offset == breg) && ((addr_space == PCI_ADDR_MEM32) ||
		    (addr_space == PCI_ADDR_MEM64))) {
			rnumber = i;
			break;
		}
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: MSI-X rnum = %d\n", rnumber));

	if (rnumber == 0) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: "
		    "no mtaching reg number for offset 0x%x\n", breg));

		goto fail2;
	}

	if ((ret = ddi_regs_map_setup(rdip, rnumber,
	    (caddr_t *)&msix_p->msix_tbl_addr, msix_p->msix_tbl_offset,
	    msix_tbl_size, &msix_p->msix_dev_attr,
	    &msix_p->msix_tbl_hdl)) != DDI_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: MSI-X Table "
		    "ddi_regs_map_setup failed %d\n", ret));

		goto fail2;
	}

	/*
	 * Map in the MSI-X Pending Bit Array
	 */
	msix_p->msix_pba_offset = PCI_CAP_GET32(cfg_hdle, NULL, caps_ptr,
	    PCI_MSIX_PBA_OFFSET);

	if ((breg = pci_msix_bir_index[msix_p->msix_pba_offset &
	    PCI_MSIX_PBA_BIR_MASK]) == 0xff)
		goto fail3;

	msix_p->msix_pba_offset = msix_p->msix_pba_offset &
	    ~PCI_MSIX_PBA_BIR_MASK;
	pba_tbl_size = ((msix_ctrl & PCI_MSIX_TBL_SIZE_MASK) + 1)/8;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: PBA table offset 0x%x "
	    "breg 0x%x size 0x%lx\n", msix_p->msix_pba_offset, breg,
	    pba_tbl_size));

	for (i = 1, rnumber = 0; i < nregs/reg_size; i++) {
		rp = (pci_regspec_t *)&regs_list[i * reg_size];
		addr_space = rp->pci_phys_hi & PCI_ADDR_MASK;
		offset = PCI_REG_REG_G(rp->pci_phys_hi);

		if ((offset == breg) && ((addr_space == PCI_ADDR_MEM32) ||
		    (addr_space == PCI_ADDR_MEM64))) {
			rnumber = i;
			break;
		}
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: PBA rnum = %d\n", rnumber));

	if (rnumber == 0) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: "
		    "no matching reg number for offset 0x%x\n", breg));

		goto fail3;
	}

	if ((ret = ddi_regs_map_setup(rdip, rnumber,
	    (caddr_t *)&msix_p->msix_pba_addr, msix_p->msix_pba_offset,
	    pba_tbl_size, &msix_p->msix_dev_attr,
	    &msix_p->msix_pba_hdl)) != DDI_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: PBA "
		    "ddi_regs_map_setup failed %d\n", ret));

		goto fail3;
	}

	DDI_INTR_NEXDBG((CE_CONT, "pci_msix_init: msix_p = 0x%p DONE!!\n",
	    (void *)msix_p));

	ddi_prop_free(regs_list);
	goto done;

fail3:
	ddi_regs_map_free(&msix_p->msix_tbl_hdl);
fail2:
	ddi_prop_free(regs_list);
fail1:
	kmem_free(msix_p, sizeof (ddi_intr_msix_t));
	msix_p = NULL;
done:
	pci_config_teardown(&cfg_hdle);
	return (msix_p);
}


/*
 * pci_msix_fini:
 *	This function cleans up previously allocated handles/addrs etc.
 *	It is only called if no more MSI-X interrupts are being used.
 */
void
pci_msix_fini(ddi_intr_msix_t *msix_p)
{
	DDI_INTR_NEXDBG((CE_CONT, "pci_msix_fini: msix_p = 0x%p\n",
	    (void *)msix_p));

	ddi_regs_map_free(&msix_p->msix_pba_hdl);
	ddi_regs_map_free(&msix_p->msix_tbl_hdl);
	kmem_free(msix_p, sizeof (ddi_intr_msix_t));
}


/*
 * pci_msix_dup:
 *	This function duplicates the address and data pair of one msi-x
 *	vector to another msi-x vector.
 */
int
pci_msix_dup(dev_info_t *rdip, int org_inum, int dup_inum)
{
	ddi_intr_msix_t	*msix_p = i_ddi_get_msix(rdip);
	uint64_t	addr;
	uint64_t	data;
	uintptr_t	off;

	DDI_INTR_NEXDBG((CE_CONT, "pci_msix_dup: dip = %p, inum = 0x%x, "
	    "to_vector = 0x%x\n", (void *)rdip, org_inum, dup_inum));

	/* Offset into the original inum's entry in the MSI-X table */
	off = (uintptr_t)msix_p->msix_tbl_addr +
	    (org_inum * PCI_MSIX_VECTOR_SIZE);

	/*
	 * For the MSI-X number passed in, get the "data" and "addr" fields.
	 *
	 * Note that the spec only requires 32-bit accesses to be supported.
	 * Apparently some chipsets don't support 64-bit accesses.
	 */
	addr = ddi_get32(msix_p->msix_tbl_hdl,
	    (uint32_t *)(off + PCI_MSIX_UPPER_ADDR_OFFSET));
	addr = (addr << 32) | ddi_get32(msix_p->msix_tbl_hdl,
	    (uint32_t *)(off + PCI_MSIX_LOWER_ADDR_OFFSET));

	data = ddi_get32(msix_p->msix_tbl_hdl,
	    (uint32_t *)(off + PCI_MSIX_DATA_OFFSET));

	/* Program new vector with these existing values */
	return (pci_msi_configure(rdip, DDI_INTR_TYPE_MSIX, 1, dup_inum, addr,
	    data));
}


/*
 * Next set of routines are for INTx (legacy) PCI interrupt
 * support only.
 */

/*
 * pci_intx_get_cap:
 *	For non-MSI devices that comply to PCI v2.3 or greater;
 *	read the command register. Bit 10 implies interrupt disable.
 *	Set this bit and then read the status register bit 3.
 *	Bit 3 of status register is Interrupt state.
 *	If it is set; then the device supports 'Masking'
 *
 *	Reset the device back to the original state.
 */
int
pci_intx_get_cap(dev_info_t *dip, int *flagsp)
{
	uint16_t		cmdreg, savereg;
	ddi_acc_handle_t	cfg_hdl;
#ifdef	DEBUG
	uint16_t		statreg;
#endif /* DEBUG */

	*flagsp = 0;
	DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_cap: %s%d: called\n",
	    ddi_driver_name(dip), ddi_get_instance(dip)));

	if (pci_config_setup(dip, &cfg_hdl) != DDI_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_cap: can't get "
		    "config handle\n"));
		return (DDI_FAILURE);
	}

	savereg = pci_config_get16(cfg_hdl, PCI_CONF_COMM);
	DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_cap: "
	    "command register was 0x%x\n", savereg));

	/* Disable the interrupts */
	cmdreg = savereg | PCI_COMM_INTX_DISABLE;
	pci_config_put16(cfg_hdl, PCI_CONF_COMM, cmdreg);

#ifdef	DEBUG
	statreg = pci_config_get16(cfg_hdl, PCI_CONF_STAT);
	DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_cap: "
	    "status register is 0x%x\n", statreg));
#endif /* DEBUG */

	/* Read the bit back */
	cmdreg = pci_config_get16(cfg_hdl, PCI_CONF_COMM);
	DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_cap: "
	    "command register is now 0x%x\n", cmdreg));

	*flagsp = DDI_INTR_FLAG_LEVEL;

	if (cmdreg & PCI_COMM_INTX_DISABLE) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_cap: "
		    "masking supported\n"));
		*flagsp |= (DDI_INTR_FLAG_MASKABLE |
		    DDI_INTR_FLAG_PENDING);
	}

	/* Restore the device back to the original state and return */
	pci_config_put16(cfg_hdl, PCI_CONF_COMM, savereg);

	pci_config_teardown(&cfg_hdl);
	return (DDI_SUCCESS);
}


/*
 * pci_intx_clr_mask:
 *	For non-MSI devices that comply to PCI v2.3 or greater;
 *	clear the bit10 in the command register.
 */
int
pci_intx_clr_mask(dev_info_t *dip)
{
	uint16_t		cmdreg;
	ddi_acc_handle_t	cfg_hdl;

	DDI_INTR_NEXDBG((CE_CONT, "pci_intx_clr_mask: %s%d: called\n",
	    ddi_driver_name(dip), ddi_get_instance(dip)));

	if (pci_config_setup(dip, &cfg_hdl) != DDI_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intx_clr_mask: can't get "
		    "config handle\n"));
		return (DDI_FAILURE);
	}

	cmdreg = pci_config_get16(cfg_hdl, PCI_CONF_COMM);
	DDI_INTR_NEXDBG((CE_CONT, "pci_intx_clr_mask: "
	    "command register was 0x%x\n", cmdreg));

	/* Enable the interrupts */
	cmdreg &= ~PCI_COMM_INTX_DISABLE;
	pci_config_put16(cfg_hdl, PCI_CONF_COMM, cmdreg);
	pci_config_teardown(&cfg_hdl);
	return (DDI_SUCCESS);
}


/*
 * pci_intx_set_mask:
 *	For non-MSI devices that comply to PCI v2.3 or greater;
 *	set the bit10 in the command register.
 */
int
pci_intx_set_mask(dev_info_t *dip)
{
	uint16_t		cmdreg;
	ddi_acc_handle_t	cfg_hdl;

	DDI_INTR_NEXDBG((CE_CONT, "pci_intx_set_mask: %s%d: called\n",
	    ddi_driver_name(dip), ddi_get_instance(dip)));

	if (pci_config_setup(dip, &cfg_hdl) != DDI_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intx_set_mask: can't get "
		    "config handle\n"));
		return (DDI_FAILURE);
	}

	cmdreg = pci_config_get16(cfg_hdl, PCI_CONF_COMM);
	DDI_INTR_NEXDBG((CE_CONT, "pci_intx_set_mask: "
	    "command register was 0x%x\n", cmdreg));

	/* Disable the interrupts */
	cmdreg |= PCI_COMM_INTX_DISABLE;
	pci_config_put16(cfg_hdl, PCI_CONF_COMM, cmdreg);
	pci_config_teardown(&cfg_hdl);
	return (DDI_SUCCESS);
}

/*
 * pci_intx_get_pending:
 *	For non-MSI devices that comply to PCI v2.3 or greater;
 *	read the status register. Bit 3 of status register is
 *	Interrupt state. If it is set; then the interrupt is
 *	'Pending'.
 */
int
pci_intx_get_pending(dev_info_t *dip, int *pendingp)
{
	uint16_t		statreg;
	ddi_acc_handle_t	cfg_hdl;

	*pendingp = 0;
	DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_pending: %s%d: called\n",
	    ddi_driver_name(dip), ddi_get_instance(dip)));

	if (pci_config_setup(dip, &cfg_hdl) != DDI_SUCCESS) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_pending: can't get "
		    "config handle\n"));
		return (DDI_FAILURE);
	}

	statreg = pci_config_get16(cfg_hdl, PCI_CONF_STAT);

	if (statreg & PCI_STAT_INTR) {
		DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_pending: "
		    "interrupt is pending\n"));
		*pendingp = 1;
	}

	pci_config_teardown(&cfg_hdl);
	return (DDI_SUCCESS);
}


/*
 * pci_intx_get_ispec:
 *	Get intrspec for PCI devices (legacy support)
 *	NOTE: This is moved here from x86 pci.c and is
 *	needed here as pci-ide.c uses it as well
 */
/*ARGSUSED*/
ddi_intrspec_t
pci_intx_get_ispec(dev_info_t *dip, dev_info_t *rdip, int inum)
{
	int				*intpriorities;
	uint_t				num_intpriorities;
	struct intrspec			*ispec;
	ddi_acc_handle_t		cfg_hdl;
	struct ddi_parent_private_data	*pdptr;

	if ((pdptr = ddi_get_parent_data(rdip)) == NULL)
		return (NULL);

	ispec = pdptr->par_intr;
	ASSERT(ispec);

	/* check if the intrspec_pri has been initialized */
	if (!ispec->intrspec_pri) {
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, "interrupt-priorities",
		    &intpriorities, &num_intpriorities) == DDI_PROP_SUCCESS) {
			if (inum < num_intpriorities)
				ispec->intrspec_pri = intpriorities[inum];
			ddi_prop_free(intpriorities);
		}

		/* If still no priority, guess based on the class code */
		if (ispec->intrspec_pri == 0)
			ispec->intrspec_pri = pci_class_to_pil(rdip);
	}

	/* Get interrupt line value */
	if (!ispec->intrspec_vec) {
		if (pci_config_setup(rdip, &cfg_hdl) != DDI_SUCCESS) {
			DDI_INTR_NEXDBG((CE_CONT, "pci_intx_get_iline: "
			    "can't get config handle\n"));
			return ((ddi_intrspec_t)ispec);
		}

		ispec->intrspec_vec = pci_config_get8(cfg_hdl, PCI_CONF_ILINE);
		pci_config_teardown(&cfg_hdl);
	}

	return ((ddi_intrspec_t)ispec);
}

static uint32_t
pci_match_class_val(uint32_t key, pci_class_val_t *rec_p, int nrec,
    uint32_t default_val)
{
	int i;

	for (i = 0; i < nrec; rec_p++, i++) {
		if ((rec_p->class_code & rec_p->class_mask) ==
		    (key & rec_p->class_mask))
			return (rec_p->class_val);
	}

	return (default_val);
}

/*
 * Return the configuration value, based on class code and sub class code,
 * from the specified property based or default pci_class_val_t table.
 */
uint32_t
pci_class_to_val(dev_info_t *rdip, char *property_name, pci_class_val_t *rec_p,
    int nrec, uint32_t default_val)
{
	int property_len;
	uint32_t class_code;
	pci_class_val_t *conf;
	uint32_t val = default_val;

	/*
	 * Use the "class-code" property to get the base and sub class
	 * codes for the requesting device.
	 */
	class_code = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS, "class-code", -1);

	if (class_code == -1)
		return (val);

	/* look up the val from the default table */
	val = pci_match_class_val(class_code, rec_p, nrec, val);


	/* see if there is a more specific property specified value */
	if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_NOTPROM,
	    property_name, (caddr_t)&conf, &property_len))
			return (val);

	if ((property_len % sizeof (pci_class_val_t)) == 0)
		val = pci_match_class_val(class_code, conf,
		    property_len / sizeof (pci_class_val_t), val);
	kmem_free(conf, property_len);
	return (val);
}

/*
 * pci_class_to_pil:
 *
 * Return the pil for a given PCI device.
 */
uint32_t
pci_class_to_pil(dev_info_t *rdip)
{
	uint32_t pil;

	/* Default pil is 1 */
	pil = pci_class_to_val(rdip,
	    "pci-class-priorities", pci_default_pil,
	    sizeof (pci_default_pil) / sizeof (pci_class_val_t), 1);

	/* Range check the result */
	if (pil >= 0xf)
		pil = 1;

	return (pil);
}

/*
 * pci_class_to_intr_weight:
 *
 * Return the intr_weight for a given PCI device.
 */
int32_t
pci_class_to_intr_weight(dev_info_t *rdip)
{
	int32_t intr_weight;

	/* default weight is 0% */
	intr_weight = pci_class_to_val(rdip,
	    "pci-class-intr-weights", pci_default_intr_weight,
	    sizeof (pci_default_intr_weight) / sizeof (pci_class_val_t), 0);

	/* range check the result */
	if (intr_weight < 0)
		intr_weight = 0;
	if (intr_weight > 1000)
		intr_weight = 1000;

	return (intr_weight);
}
