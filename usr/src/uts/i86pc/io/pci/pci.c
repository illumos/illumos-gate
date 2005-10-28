/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Host to PCI local bus driver
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/pci_cfgspace.h>
#include <sys/avintr.h>
#include <sys/psm.h>
#include <sys/pci_intr_lib.h>
#include <sys/policy.h>
#include <sys/pci_tools.h>
#include "pci_tools_ext.h"
#include "pci_var.h"

/* Save minimal state. */
void *pci_statep;

/*
 * Bus Operation functions
 */
static int	pci_bus_map(dev_info_t *, dev_info_t *, ddi_map_req_t *,
		    off_t, off_t, caddr_t *);
static int	pci_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t,
		    void *, void *);
static int	pci_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
		    ddi_intr_handle_impl_t *, void *);
static int	pci_get_priority(dev_info_t *, int, int *);
static int	pci_get_nintrs(dev_info_t *, int, int *);
static int	pci_enable_intr(dev_info_t *, dev_info_t *,
		    ddi_intr_handle_impl_t *, uint32_t);
static void	pci_disable_intr(dev_info_t *, dev_info_t *,
		    ddi_intr_handle_impl_t *, uint32_t);

/* Extern decalrations */
extern int	(*psm_intr_ops)(dev_info_t *, ddi_intr_handle_impl_t *,
		    psm_intr_op_t, int *);

struct bus_ops pci_bus_ops = {
	BUSO_REV,
	pci_bus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	ddi_dma_map,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	pci_ctlops,
	ddi_bus_prop_op,
	0,		/* (*bus_get_eventcookie)();	*/
	0,		/* (*bus_add_eventcall)();	*/
	0,		/* (*bus_remove_eventcall)();	*/
	0,		/* (*bus_post_event)();		*/
	0,		/* (*bus_intr_ctl)(); */
	0,		/* (*bus_config)(); */
	0,		/* (*bus_unconfig)(); */
	NULL,		/* (*bus_fm_init)(); */
	NULL,		/* (*bus_fm_fini)(); */
	NULL,		/* (*bus_fm_access_enter)(); */
	NULL,		/* (*bus_fm_access_exit)(); */
	NULL,		/* (*bus_power)(); */
	pci_intr_ops	/* (*bus_intr_op)(); */
};

static int pci_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int pci_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int pci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp);
static int pci_prop_op(dev_t dev, dev_info_t *devi, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);

/*
 * One goal here is to leverage off of the pcihp.c source without making
 * changes to it.  Call into it's cb_ops directly if needed, piggybacking
 * anything else needed by the pci_tools.c module.  Only pci_tools and pcihp
 * will be opening PCI nexus driver file descriptors.
 */

struct cb_ops pci_cb_ops = {
	pci_open,			/* open */
	pci_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	pci_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	pci_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * Device Node Operation functions
 */
static int pci_info(dev_info_t *devi, ddi_info_cmd_t cmd, void *arg,
    void **result);
static int pci_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
static int pci_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);

struct dev_ops pci_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	pci_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	pci_attach,		/* attach */
	pci_detach,		/* detach */
	nulldev,		/* reset */
	&pci_cb_ops,		/* driver operations */
	&pci_bus_ops		/* bus operations */
};

/*
 * This variable controls the default setting of the command register
 * for pci devices.  See pci_initchild() for details.
 */
static ushort_t pci_command_default = PCI_COMM_ME |
					PCI_COMM_MAE |
					PCI_COMM_IO;

/*
 * Internal routines in support of particular pci_ctlops.
 */
static int pci_removechild(dev_info_t *child);
static int pci_initchild(dev_info_t *child);

/*
 * Miscellaneous internal functions
 */
static int pci_get_reg_prop(dev_info_t *dip, pci_regspec_t *pci_rp);

/*
 * These are the access routines.  The pci_bus_map sets the handle
 * to point to these.
 */
static uint8_t pci_config_rd8(ddi_acc_impl_t *hdlp, uint8_t *addr);
static uint16_t pci_config_rd16(ddi_acc_impl_t *hdlp, uint16_t *addr);
static uint32_t pci_config_rd32(ddi_acc_impl_t *hdlp, uint32_t *addr);
static uint64_t pci_config_rd64(ddi_acc_impl_t *hdlp, uint64_t *addr);

static void pci_config_wr8(ddi_acc_impl_t *hdlp, uint8_t *addr,
				uint8_t value);
static void pci_config_wr16(ddi_acc_impl_t *hdlp, uint16_t *addr,
				uint16_t value);
static void pci_config_wr32(ddi_acc_impl_t *hdlp, uint32_t *addr,
				uint32_t value);
static void pci_config_wr64(ddi_acc_impl_t *hdlp, uint64_t *addr,
				uint64_t value);

static void pci_config_rep_rd8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags);
static void pci_config_rep_rd16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags);
static void pci_config_rep_rd32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags);
static void pci_config_rep_rd64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags);

static void pci_config_rep_wr8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags);
static void pci_config_rep_wr16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags);
static void pci_config_rep_wr32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags);
static void pci_config_rep_wr64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags);

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module */
	"host to PCI nexus driver %I%",
	&pci_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int e;

	/*
	 * Initialize per-pci bus soft state pointer.
	 */
	e = ddi_soft_state_init(&pci_statep, sizeof (pci_state_t), 1);
	if (e != 0)
		return (e);

	if ((e = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&pci_statep);

	return (e);
}

int
_fini(void)
{
	int rc;

	rc = mod_remove(&modlinkage);
	if (rc != 0)
		return (rc);

	ddi_soft_state_fini(&pci_statep);

	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
pci_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	/*
	 * Use the minor number as constructed by pcihp, as the index value to
	 * ddi_soft_state_zalloc.
	 */
	int instance = ddi_get_instance(devi);
	pci_state_t *pcip = NULL;

	if (ddi_prop_update_string(DDI_DEV_T_NONE, devi, "device_type", "pci")
	    != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "pci:  'device_type' prop create failed");
	}

	if (ddi_soft_state_zalloc(pci_statep, instance) == DDI_SUCCESS) {
		pcip = ddi_get_soft_state(pci_statep, instance);
	}

	if (pcip == NULL) {
		goto bad_soft_state;
	}

	pcip->pci_dip = devi;

	/*
	 * Initialize hotplug support on this bus. At minimum
	 * (for non hotplug bus) this would create ":devctl" minor
	 * node to support DEVCTL_DEVICE_* and DEVCTL_BUS_* ioctls
	 * to this bus.
	 */
	if (pcihp_init(devi) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pci: Failed to setup hotplug framework");
		goto bad_pcihp_init;
	}

	/* Second arg: initialize for pci, not pci_express */
	if (pcitool_init(devi, B_FALSE) != DDI_SUCCESS) {
		goto bad_pcitool_init;
	}

	ddi_report_dev(devi);

	return (DDI_SUCCESS);

bad_pcitool_init:
	(void) pcihp_uninit(devi);
bad_pcihp_init:
	ddi_soft_state_free(pci_statep, instance);
bad_soft_state:
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
pci_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	/* Uninitialize pcitool support. */
	pcitool_uninit(devi);

	/* Uninitialize hotplug support on this bus. */
	(void) pcihp_uninit(devi);

	ddi_soft_state_free(pci_statep, DIP_TO_MINOR(devi));

	return (DDI_SUCCESS);
}

static int
pci_get_reg_prop(dev_info_t *dip, pci_regspec_t *pci_rp)
{
	pci_regspec_t *assigned_addr;
	int	assigned_addr_len;
	uint_t 	phys_hi;
	int	i;
	int 	rc;
	int 	number;

	phys_hi = pci_rp->pci_phys_hi;
	if (((phys_hi & PCI_REG_ADDR_M) == PCI_ADDR_CONFIG) ||
		(phys_hi & PCI_RELOCAT_B))
		return (DDI_SUCCESS);

	/*
	 * the "reg" property specifies relocatable, get and interpret the
	 * "assigned-addresses" property.
	 */
	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "assigned-addresses",
		(int **)&assigned_addr, (uint_t *)&assigned_addr_len);
	if (rc != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Scan the "assigned-addresses" for one that matches the specified
	 * "reg" property entry.
	 */
	phys_hi &= PCI_CONF_ADDR_MASK;
	number = assigned_addr_len / (sizeof (pci_regspec_t) / sizeof (int));
	for (i = 0; i < number; i++) {
		if ((assigned_addr[i].pci_phys_hi & PCI_CONF_ADDR_MASK) ==
				phys_hi) {
			pci_rp->pci_phys_mid = assigned_addr[i].pci_phys_mid;
			pci_rp->pci_phys_low = assigned_addr[i].pci_phys_low;
			ddi_prop_free(assigned_addr);
			return (DDI_SUCCESS);
		}
	}

	ddi_prop_free(assigned_addr);
	return (DDI_FAILURE);
}

static int
pci_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *vaddrp)
{
	struct regspec reg;
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	ddi_acc_impl_t *ap;
	pci_regspec_t pci_reg;
	pci_regspec_t *pci_rp;
	int 	rnumber;
	int	length;
	int	rc;
	pci_acc_cfblk_t *cfp;
	int	space;


	mr = *mp; /* Get private copy of request */
	mp = &mr;

	/*
	 * check for register number
	 */
	switch (mp->map_type) {
	case DDI_MT_REGSPEC:
		pci_reg = *(pci_regspec_t *)(mp->map_obj.rp);
		pci_rp = &pci_reg;
		if (pci_get_reg_prop(rdip, pci_rp) != DDI_SUCCESS)
			return (DDI_FAILURE);
		break;
	case DDI_MT_RNUMBER:
		rnumber = mp->map_obj.rnumber;
		/*
		 * get ALL "reg" properties for dip, select the one of
		 * of interest. In x86, "assigned-addresses" property
		 * is identical to the "reg" property, so there is no
		 * need to cross check the two to determine the physical
		 * address of the registers.
		 * This routine still performs some validity checks to
		 * make sure that everything is okay.
		 */
		rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
			DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
			(uint_t *)&length);
		if (rc != DDI_PROP_SUCCESS) {
			return (DDI_FAILURE);
		}

		/*
		 * validate the register number.
		 */
		length /= (sizeof (pci_regspec_t) / sizeof (int));
		if (rnumber >= length) {
			ddi_prop_free(pci_rp);
			return (DDI_FAILURE);
		}

		/*
		 * copy the required entry.
		 */
		pci_reg = pci_rp[rnumber];

		/*
		 * free the memory allocated by ddi_prop_lookup_int_array
		 */
		ddi_prop_free(pci_rp);

		pci_rp = &pci_reg;
		if (pci_get_reg_prop(rdip, pci_rp) != DDI_SUCCESS)
			return (DDI_FAILURE);
		mp->map_type = DDI_MT_REGSPEC;
		break;
	default:
		return (DDI_ME_INVAL);
	}

	space = pci_rp->pci_phys_hi & PCI_REG_ADDR_M;

	/*
	 * check for unmap and unlock of address space
	 */
	if ((mp->map_op == DDI_MO_UNMAP) || (mp->map_op == DDI_MO_UNLOCK)) {
		/*
		 * Adjust offset and length
		 * A non-zero length means override the one in the regspec.
		 */
		pci_rp->pci_phys_low += (uint_t)offset;
		if (len != 0)
			pci_rp->pci_size_low = len;

		switch (space) {
		case PCI_ADDR_CONFIG:
			/* No work required on unmap of Config space */
			return (DDI_SUCCESS);

		case PCI_ADDR_IO:
			reg.regspec_bustype = 1;
			break;

		case PCI_ADDR_MEM64:
			/*
			 * MEM64 requires special treatment on map, to check
			 * that the device is below 4G.  On unmap, however,
			 * we can assume that everything is OK... the map
			 * must have succeeded.
			 */
			/* FALLTHROUGH */
		case PCI_ADDR_MEM32:
			reg.regspec_bustype = 0;
			break;

		default:
			return (DDI_FAILURE);
		}
		reg.regspec_addr = pci_rp->pci_phys_low;
		reg.regspec_size = pci_rp->pci_size_low;

		mp->map_obj.rp = &reg;
		return (ddi_map(dip, mp, (off_t)0, (off_t)0, vaddrp));

	}

	/* check for user mapping request - not legal for Config */
	if (mp->map_op == DDI_MO_MAP_HANDLE && space == PCI_ADDR_CONFIG) {
		return (DDI_FAILURE);
	}

	/*
	 * check for config space
	 * On x86, CONFIG is not mapped via MMU and there is
	 * no endian-ness issues. Set the attr field in the handle to
	 * indicate that the common routines to call the nexus driver.
	 */
	if (space == PCI_ADDR_CONFIG) {
		hp = (ddi_acc_hdl_t *)mp->map_handlep;

		if (hp == NULL) {
			/* Can't map config space without a handle */
			return (DDI_FAILURE);
		}

		ap = (ddi_acc_impl_t *)hp->ah_platform_private;

		/* endian-ness check */
		if (hp->ah_acc.devacc_attr_endian_flags == DDI_STRUCTURE_BE_ACC)
			return (DDI_FAILURE);

		/*
		 * range check
		 */
		if ((offset >= 256) || (len > 256) || (offset + len > 256))
			return (DDI_FAILURE);
		*vaddrp = (caddr_t)offset;

		ap->ahi_acc_attr |= DDI_ACCATTR_CONFIG_SPACE;
		ap->ahi_put8 = pci_config_wr8;
		ap->ahi_get8 = pci_config_rd8;
		ap->ahi_put64 = pci_config_wr64;
		ap->ahi_get64 = pci_config_rd64;
		ap->ahi_rep_put8 = pci_config_rep_wr8;
		ap->ahi_rep_get8 = pci_config_rep_rd8;
		ap->ahi_rep_put64 = pci_config_rep_wr64;
		ap->ahi_rep_get64 = pci_config_rep_rd64;
		ap->ahi_get16 = pci_config_rd16;
		ap->ahi_get32 = pci_config_rd32;
		ap->ahi_put16 = pci_config_wr16;
		ap->ahi_put32 = pci_config_wr32;
		ap->ahi_rep_get16 = pci_config_rep_rd16;
		ap->ahi_rep_get32 = pci_config_rep_rd32;
		ap->ahi_rep_put16 = pci_config_rep_wr16;
		ap->ahi_rep_put32 = pci_config_rep_wr32;

		/* Initialize to default check/notify functions */
		ap->ahi_fault_check = i_ddi_acc_fault_check;
		ap->ahi_fault_notify = i_ddi_acc_fault_notify;
		ap->ahi_fault = 0;
		impl_acc_err_init(hp);

		/* record the device address for future reference */
		cfp = (pci_acc_cfblk_t *)&hp->ah_bus_private;
		cfp->c_busnum = PCI_REG_BUS_G(pci_rp->pci_phys_hi);
		cfp->c_devnum = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
		cfp->c_funcnum = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

		return (DDI_SUCCESS);
	}

	/*
	 * range check
	 */
	if ((offset >= pci_rp->pci_size_low) ||
	    (len > pci_rp->pci_size_low) ||
	    (offset + len > pci_rp->pci_size_low)) {
		return (DDI_FAILURE);
	}

	/*
	 * Adjust offset and length
	 * A non-zero length means override the one in the regspec.
	 */
	pci_rp->pci_phys_low += (uint_t)offset;
	if (len != 0)
		pci_rp->pci_size_low = len;

	/*
	 * convert the pci regsec into the generic regspec used by the
	 * parent root nexus driver.
	 */
	switch (space) {
	case PCI_ADDR_IO:
		reg.regspec_bustype = 1;
		break;
	case PCI_ADDR_MEM64:
		/*
		 * We can't handle 64-bit devices that are mapped above
		 * 4G or that are larger than 4G.
		 */
		if (pci_rp->pci_phys_mid != 0 ||
		    pci_rp->pci_size_hi != 0)
			return (DDI_FAILURE);
		/*
		 * Other than that, we can treat them as 32-bit mappings
		 */
		/* FALLTHROUGH */
	case PCI_ADDR_MEM32:
		reg.regspec_bustype = 0;
		break;
	default:
		return (DDI_FAILURE);
	}
	reg.regspec_addr = pci_rp->pci_phys_low;
	reg.regspec_size = pci_rp->pci_size_low;

	mp->map_obj.rp = &reg;
	return (ddi_map(dip, mp, (off_t)0, (off_t)0, vaddrp));
}


/*
 * pci_get_priority:
 *	Figure out the priority of the device
 */
static int
pci_get_priority(dev_info_t *dip, int inum, int *pri)
{
	struct intrspec *ispec;

	DDI_INTR_NEXDBG((CE_CONT, "pci_get_priority: dip = 0x%p\n",
	    (void *)dip));

	if ((ispec = (struct intrspec *)pci_intx_get_ispec(dip, dip, inum)) ==
	    NULL)
		return (DDI_FAILURE);

	*pri = ispec->intrspec_pri;

	return (DDI_SUCCESS);
}


/*
 * pci_get_nintrs:
 *	Figure out how many interrupts the device supports
 */
static int
pci_get_nintrs(dev_info_t *dip, int type, int *nintrs)
{
	int	ret;

	*nintrs = 0;

	if (DDI_INTR_IS_MSI_OR_MSIX(type))
		ret = pci_msi_get_nintrs(dip, type, nintrs);
	else {
		ret = DDI_FAILURE;
		if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "interrupts", -1) != -1) {
			*nintrs = 1;
			ret = DDI_SUCCESS;
		}
	}

	return (ret);
}


/*
 * pci_intr_ops: bus_intr_op() function for interrupt support
 */
/* ARGSUSED */
static int
pci_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
	ddi_intr_handle_impl_t *hdlp, void *result)
{
	int			priority = 0;
	int			psm_status = 0;
	int			pci_status = 0;
	int			pci_rval, psm_rval = PSM_FAILURE;
	int			types = 0;
	int			i, j;
	int			behavior;
	ddi_intrspec_t		isp;
	struct intrspec		*ispec;
	ddi_intr_handle_impl_t	tmp_hdl;
	ddi_intr_msix_t		*msix_p;

	DDI_INTR_NEXDBG((CE_CONT,
	    "pci_intr_ops: pdip 0x%p, rdip 0x%p, op %x handle 0x%p\n",
	    (void *)pdip, (void *)rdip, intr_op, (void *)hdlp));

	/* Process the request */
	switch (intr_op) {
	case DDI_INTROP_SUPPORTED_TYPES:
		/* Fixed supported by default */
		*(int *)result = DDI_INTR_TYPE_FIXED;

		/* Figure out if MSI or MSI-X is supported? */
		if (pci_msi_get_supported_type(rdip, &types) != DDI_SUCCESS)
			return (DDI_SUCCESS);

		if (psm_intr_ops != NULL) {
			/* MSI or MSI-X is supported, OR it in */
			*(int *)result |= types;

			tmp_hdl.ih_type = *(int *)result;
			(void) (*psm_intr_ops)(rdip, &tmp_hdl,
			    PSM_INTR_OP_CHECK_MSI, result);
			DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: rdip: 0x%p "
			    "supported types: 0x%x\n", (void *)rdip,
			    *(int *)result));
		}
		break;
	case DDI_INTROP_NINTRS:
		if (pci_get_nintrs(rdip, hdlp->ih_type, result) != DDI_SUCCESS)
			return (DDI_FAILURE);
		break;
	case DDI_INTROP_ALLOC:
		/*
		 * MSI or MSIX (figure out number of vectors available)
		 * FIXED interrupts: just return available interrupts
		 */
		if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type) &&
		    (psm_intr_ops != NULL) &&
		    (pci_get_priority(rdip, hdlp->ih_inum,
		    &priority) == DDI_SUCCESS)) {
			hdlp->ih_pri = priority;
			behavior = hdlp->ih_scratch2;
			(void) (*psm_intr_ops)(rdip, hdlp,
			    PSM_INTR_OP_ALLOC_VECTORS, result);

			/* verify behavior flag and take appropriate action */
			if ((behavior == DDI_INTR_ALLOC_STRICT) &&
			    (*(int *)result < hdlp->ih_scratch1)) {
				DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: "
				    "behavior %x, couldn't get enough intrs\n",
				    behavior));
				hdlp->ih_scratch1 = *(int *)result;
				(void) (*psm_intr_ops)(rdip, hdlp,
				    PSM_INTR_OP_FREE_VECTORS, NULL);
				return (DDI_EAGAIN);
			}

			if (hdlp->ih_type == DDI_INTR_TYPE_MSIX) {
				if (!(msix_p = i_ddi_get_msix(hdlp->ih_dip))) {
					msix_p = pci_msix_init(hdlp->ih_dip);
					if (msix_p)
						i_ddi_set_msix(hdlp->ih_dip,
						    msix_p);
				}
				msix_p->msix_intrs_in_use += *(int *)result;
			}

		} else if (hdlp->ih_type == DDI_INTR_TYPE_FIXED) {
			/* Figure out if this device supports MASKING */
			pci_rval = pci_intx_get_cap(rdip, &pci_status);
			if (pci_rval == DDI_SUCCESS && pci_status)
				hdlp->ih_cap |= pci_status;
			*(int *)result = 1;	/* DDI_INTR_TYPE_FIXED */
		} else
			return (DDI_FAILURE);
		break;
	case DDI_INTROP_FREE:
		if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type) &&
		    (psm_intr_ops != NULL)) {
			(void) (*psm_intr_ops)(rdip, hdlp,
			    PSM_INTR_OP_FREE_VECTORS, NULL);

			if (hdlp->ih_type == DDI_INTR_TYPE_MSIX) {
				msix_p = i_ddi_get_msix(hdlp->ih_dip);
				if (msix_p &&
				    --msix_p->msix_intrs_in_use == 0) {
					pci_msix_fini(msix_p);
					i_ddi_set_msix(hdlp->ih_dip, NULL);
				}
			}
		}
		break;
	case DDI_INTROP_GETPRI:
		if (pci_get_priority(rdip, hdlp->ih_inum, &priority) !=
		    DDI_SUCCESS)	/* Get the priority */
			return (DDI_FAILURE);
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: priority = 0x%x\n",
		    priority));
		*(int *)result = priority;
		break;
	case DDI_INTROP_SETPRI:
		/* Validate the interrupt priority passed */
		if (*(int *)result > LOCK_LEVEL)
			return (DDI_FAILURE);

		/* Ensure that PSM is all initialized */
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		/* Change the priority */
		if ((*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_SET_PRI, result) ==
		    PSM_FAILURE)
			return (DDI_FAILURE);

		/* update ispec */
		isp = pci_intx_get_ispec(pdip, rdip, (int)hdlp->ih_inum);
		ispec = (struct intrspec *)isp;
		ispec->intrspec_pri = *(int *)result;
		break;
	case DDI_INTROP_ADDISR:
		/* update ispec */
		isp = pci_intx_get_ispec(pdip, rdip, (int)hdlp->ih_inum);
		ispec = (struct intrspec *)isp;
		ispec->intrspec_func = hdlp->ih_cb_func;
		break;
	case DDI_INTROP_REMISR:
		/* Get the interrupt structure pointer */
		isp = pci_intx_get_ispec(pdip, rdip, (int)hdlp->ih_inum);
		ispec = (struct intrspec *)isp;
		ispec->intrspec_func = (uint_t (*)()) 0;
		break;
	case DDI_INTROP_GETCAP:
		/*
		 * First check the config space and/or
		 * MSI capability register(s)
		 */
		if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type))
			pci_rval = pci_msi_get_cap(rdip, hdlp->ih_type,
			    &pci_status);
		else if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			pci_rval = pci_intx_get_cap(rdip, &pci_status);

		/* next check with pcplusmp */
		if (psm_intr_ops != NULL)
			psm_rval = (*psm_intr_ops)(rdip, hdlp,
			    PSM_INTR_OP_GET_CAP, &psm_status);

		DDI_INTR_NEXDBG((CE_CONT, "pci: GETCAP returned psm_rval = %x, "
		    "psm_status = %x, pci_rval = %x, pci_status = %x\n",
		    psm_rval, psm_status, pci_rval, pci_status));

		if (psm_rval == PSM_FAILURE && pci_rval == DDI_FAILURE) {
			*(int *)result = 0;
			return (DDI_FAILURE);
		}

		if (psm_rval == PSM_SUCCESS)
			*(int *)result = psm_status;

		if (pci_rval == DDI_SUCCESS)
			*(int *)result |= pci_status;

		DDI_INTR_NEXDBG((CE_CONT, "pci: GETCAP returned = %x\n",
		    *(int *)result));
		break;
	case DDI_INTROP_SETCAP:
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: SETCAP cap=0x%x\n",
		    *(int *)result));
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		if ((*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_SET_CAP, result)) {
			DDI_INTR_NEXDBG((CE_CONT, "GETCAP: psm_intr_ops"
			    " returned failure\n"));
			return (DDI_FAILURE);
		}
		break;
	case DDI_INTROP_ENABLE:
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: ENABLE\n"));
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		if (pci_enable_intr(pdip, rdip, hdlp, hdlp->ih_inum) !=
		    DDI_SUCCESS)
			return (DDI_FAILURE);

		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: ENABLE vector=0x%x\n",
		    hdlp->ih_vector));
		break;
	case DDI_INTROP_DISABLE:
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: DISABLE\n"));
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		pci_disable_intr(pdip, rdip, hdlp, hdlp->ih_inum);
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: DISABLE vector = %x\n",
		    hdlp->ih_vector));
		break;
	case DDI_INTROP_BLOCKENABLE:
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: BLOCKENABLE\n"));
		if (hdlp->ih_type != DDI_INTR_TYPE_MSI) {
			DDI_INTR_NEXDBG((CE_CONT, "BLOCKENABLE: not MSI\n"));
			return (DDI_FAILURE);
		}

		/* Check if psm_intr_ops is NULL? */
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		for (i = 0; i < hdlp->ih_scratch1; i++) {
			if (pci_enable_intr(pdip, rdip, hdlp,
			    hdlp->ih_inum + i) != DDI_SUCCESS) {
				DDI_INTR_NEXDBG((CE_CONT, "BLOCKENABLE: "
				    "pci_enable_intr failed for %d\n", i));
				for (j = 0; j < i; j++)
					pci_disable_intr(pdip, rdip, hdlp,
					    hdlp->ih_inum + j);
				return (DDI_FAILURE);
			}
			DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: BLOCKENABLE "
			    "inum %x done\n", hdlp->ih_inum + i));
		}
		break;
	case DDI_INTROP_BLOCKDISABLE:
		DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: BLOCKDISABLE\n"));
		if (hdlp->ih_type != DDI_INTR_TYPE_MSI) {
			DDI_INTR_NEXDBG((CE_CONT, "BLOCKDISABLE: not MSI\n"));
			return (DDI_FAILURE);
		}

		/* Check if psm_intr_ops is present */
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		for (i = 0; i < hdlp->ih_scratch1; i++) {
			pci_disable_intr(pdip, rdip, hdlp, hdlp->ih_inum + i);
			DDI_INTR_NEXDBG((CE_CONT, "pci_intr_ops: BLOCKDISABLE "
			    "inum %x done\n", hdlp->ih_inum + i));
		}
		break;
	case DDI_INTROP_SETMASK:
	case DDI_INTROP_CLRMASK:
		/*
		 * First handle in the config space
		 */
		if (intr_op == DDI_INTROP_SETMASK) {
			if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type))
				pci_status = pci_msi_set_mask(rdip,
				    hdlp->ih_type, hdlp->ih_inum);
			else if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
				pci_status = pci_intx_set_mask(rdip);
		} else {
			if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type))
				pci_status = pci_msi_clr_mask(rdip,
				    hdlp->ih_type, hdlp->ih_inum);
			else if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
				pci_status = pci_intx_clr_mask(rdip);
		}

		/* For MSI/X; no need to check with pcplusmp */
		if (hdlp->ih_type != DDI_INTR_TYPE_FIXED)
			return (pci_status);

		/* For fixed interrupts only: handle config space first */
		if (hdlp->ih_type == DDI_INTR_TYPE_FIXED &&
		    pci_status == DDI_SUCCESS)
			break;

		/* For fixed interrupts only: confer with pcplusmp next */
		if (psm_intr_ops != NULL) {
			/* If interrupt is shared; do nothing */
			psm_rval = (*psm_intr_ops)(rdip, hdlp,
			    PSM_INTR_OP_GET_SHARED, &psm_status);

			if (psm_rval == PSM_FAILURE || psm_status == 1)
				return (pci_status);

			/* Now, pcplusmp should try to set/clear the mask */
			if (intr_op == DDI_INTROP_SETMASK)
				psm_rval = (*psm_intr_ops)(rdip, hdlp,
				    PSM_INTR_OP_SET_MASK, NULL);
			else
				psm_rval = (*psm_intr_ops)(rdip, hdlp,
				    PSM_INTR_OP_CLEAR_MASK, NULL);
		}
		return ((psm_rval == PSM_FAILURE) ? DDI_FAILURE : DDI_SUCCESS);
	case DDI_INTROP_GETPENDING:
		/*
		 * First check the config space and/or
		 * MSI capability register(s)
		 */
		if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type))
			pci_rval = pci_msi_get_pending(rdip, hdlp->ih_type,
			    hdlp->ih_inum, &pci_status);
		else if (hdlp->ih_type == DDI_INTR_TYPE_FIXED)
			pci_rval = pci_intx_get_pending(rdip, &pci_status);

		/* On failure; next try with pcplusmp */
		if (pci_rval != DDI_SUCCESS && psm_intr_ops != NULL)
			psm_rval = (*psm_intr_ops)(rdip, hdlp,
			    PSM_INTR_OP_GET_PENDING, &psm_status);

		DDI_INTR_NEXDBG((CE_CONT, "pci: GETPENDING returned "
		    "psm_rval = %x, psm_status = %x, pci_rval = %x, "
		    "pci_status = %x\n", psm_rval, psm_status, pci_rval,
		    pci_status));
		if (psm_rval == PSM_FAILURE && pci_rval == DDI_FAILURE) {
			*(int *)result = 0;
			return (DDI_FAILURE);
		}

		if (psm_rval != PSM_FAILURE)
			*(int *)result = psm_status;
		else if (pci_rval != DDI_FAILURE)
			*(int *)result = pci_status;
		DDI_INTR_NEXDBG((CE_CONT, "pci: GETPENDING returned = %x\n",
		    *(int *)result));
		break;
	case DDI_INTROP_NAVAIL:
		if ((psm_intr_ops != NULL) && (pci_get_priority(rdip,
		    hdlp->ih_inum, &priority) == DDI_SUCCESS)) {
			/* Priority in the handle not initialized yet */
			hdlp->ih_pri = priority;
			(void) (*psm_intr_ops)(rdip, hdlp,
			    PSM_INTR_OP_NAVAIL_VECTORS, result);
		} else {
			*(int *)result = 1;
		}
		DDI_INTR_NEXDBG((CE_CONT, "pci: NAVAIL returned = %x\n",
		    *(int *)result));
		break;
	default:
		return (i_ddi_intr_ops(pdip, rdip, intr_op, hdlp, result));
	}

	return (DDI_SUCCESS);
}


static int
pci_enable_intr(dev_info_t *pdip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp, uint32_t inum)
{
	int		vector;
	struct intrspec	*ispec;

	DDI_INTR_NEXDBG((CE_CONT, "pci_enable_intr: hdlp %p inum %x\n",
	    (void *)hdlp, inum));

	/* Translate the interrupt if needed */
	ispec = (struct intrspec *)pci_intx_get_ispec(pdip, rdip, (int)inum);
	if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type))
		ispec->intrspec_vec = inum;
	hdlp->ih_private = (void *)ispec;

	/* translate the interrupt if needed */
	(void) (*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_XLATE_VECTOR, &vector);
	DDI_INTR_NEXDBG((CE_CONT, "pci_enable_intr: priority=%x vector=%x\n",
	    hdlp->ih_pri, vector));

	/* Add the interrupt handler */
	if (!add_avintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func,
	    DEVI(rdip)->devi_name, vector, hdlp->ih_cb_arg1,
	    hdlp->ih_cb_arg2, rdip))
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}


static void
pci_disable_intr(dev_info_t *pdip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp, uint32_t inum)
{
	int		vector;
	struct intrspec	*ispec;

	DDI_INTR_NEXDBG((CE_CONT, "pci_disable_intr: \n"));
	ispec = (struct intrspec *)pci_intx_get_ispec(pdip, rdip, (int)inum);
	if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type))
		ispec->intrspec_vec = inum;
	hdlp->ih_private = (void *)ispec;

	/* translate the interrupt if needed */
	(void) (*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_XLATE_VECTOR, &vector);

	/* Disable the interrupt handler */
	rem_avintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func, vector);
}


/*ARGSUSED*/
static int
pci_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	pci_regspec_t *drv_regp;
	uint_t	reglen;
	int	rn;
	int	totreg;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?PCI-device: %s@%s, %s%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		return (pci_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (pci_removechild((dev_info_t *)arg));

	case DDI_CTLOPS_SIDDEV:
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);

		*(int *)result = 0;
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
				DDI_PROP_DONTPASS, "reg", (int **)&drv_regp,
				&reglen) != DDI_PROP_SUCCESS) {
			return (DDI_FAILURE);
		}

		totreg = (reglen * sizeof (int)) / sizeof (pci_regspec_t);
		if (ctlop == DDI_CTLOPS_NREGS)
			*(int *)result = totreg;
		else if (ctlop == DDI_CTLOPS_REGSIZE) {
			rn = *(int *)arg;
			if (rn >= totreg) {
				ddi_prop_free(drv_regp);
				return (DDI_FAILURE);
			}
			*(off_t *)result = drv_regp[rn].pci_size_low;
		}
		ddi_prop_free(drv_regp);

		return (DDI_SUCCESS);

	case DDI_CTLOPS_POWER: {
		power_req_t	*reqp = (power_req_t *)arg;
		/*
		 * We currently understand reporting of PCI_PM_IDLESPEED
		 * capability. Everything else is passed up.
		 */
		if ((reqp->request_type == PMR_REPORT_PMCAP) &&
		    (reqp->req.report_pmcap_req.cap ==  PCI_PM_IDLESPEED)) {

			return (DDI_SUCCESS);
		}
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	/* NOTREACHED */

}

/*
 * Assign the address portion of the node name
 */
static int
pci_name_child(dev_info_t *child, char *name, int namelen)
{
	pci_regspec_t *pci_rp;
	char **unit_addr;
	int dev, func, length;
	uint_t n;

	if (ndi_dev_is_persistent_node(child) == 0) {
		/*
		 * For .conf node, use "unit-address" property
		 */
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "unit-address", &unit_addr, &n) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN,
			    "cannot find unit-address in %s.conf",
			    ddi_get_name(child));
			return (DDI_FAILURE);
		}
		if (n != 1 || *unit_addr == NULL || **unit_addr == 0) {
			cmn_err(CE_WARN, "unit-address property in %s.conf"
			    " not well-formed", ddi_get_name(child));
			ddi_prop_free(unit_addr);
			return (DDI_FAILURE);
		}
		(void) snprintf(name, namelen, "%s", *unit_addr);
		ddi_prop_free(unit_addr);
		return (DDI_SUCCESS);
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
	    (uint_t *)&length) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "cannot find reg property in %s",
		    ddi_get_name(child));
		return (DDI_FAILURE);
	}

	/* copy the device identifications */
	dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);

	if (func != 0) {
		(void) snprintf(name, namelen, "%x,%x", dev, func);
	} else {
		(void) snprintf(name, namelen, "%x", dev);
	}

	return (DDI_SUCCESS);
}

static int
pci_initchild(dev_info_t *child)
{
	struct ddi_parent_private_data *pdptr;
	char name[80];
	ddi_acc_handle_t config_handle;
	ushort_t command_preserve, command;

	if (pci_name_child(child, name, 80) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	ddi_set_name_addr(child, name);

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 * The interpretation of the unit-address is DD[,F]
	 * where DD is the device id and F is the function.
	 */
	if (ndi_dev_is_persistent_node(child) == 0) {
		extern int pci_allow_pseudo_children;

		ddi_set_parent_data(child, NULL);

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, pci_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			return (DDI_FAILURE);
		}

		/* workaround for ddivs to run under PCI */
		if (pci_allow_pseudo_children) {
			/*
			 * If the "interrupts" property doesn't exist,
			 * this must be the ddivs no-intr case, and it returns
			 * DDI_SUCCESS instead of DDI_FAILURE.
			 */
			if (ddi_prop_get_int(DDI_DEV_T_ANY, child,
			    DDI_PROP_DONTPASS, "interrupts", -1) == -1)
				return (DDI_SUCCESS);
			/*
			 * Create the ddi_parent_private_data for a pseudo
			 * child.
			 */
			pdptr = (struct ddi_parent_private_data *)kmem_zalloc(
			    (sizeof (struct ddi_parent_private_data) +
			    sizeof (struct intrspec)), KM_SLEEP);
			pdptr->par_intr = (struct intrspec *)(pdptr + 1);
			pdptr->par_nintr = 1;
			ddi_set_parent_data(child, pdptr);
			return (DDI_SUCCESS);
		}

		/*
		 * The child was not merged into a h/w node,
		 * but there's not much we can do with it other
		 * than return failure to cause the node to be removed.
		 */
		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_get_name(child), ddi_get_name_addr(child),
		    ddi_get_name(child));
		ddi_set_name_addr(child, NULL);
		return (DDI_NOT_WELL_FORMED);
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "interrupts", -1) != -1) {
		pdptr = (struct ddi_parent_private_data *)
		    kmem_zalloc((sizeof (struct ddi_parent_private_data) +
		    sizeof (struct intrspec)), KM_SLEEP);
		pdptr->par_intr = (struct intrspec *)(pdptr + 1);
		pdptr->par_nintr = 1;
		ddi_set_parent_data(child, pdptr);
	} else
		ddi_set_parent_data(child, NULL);

	/*
	 * initialize command register
	 */
	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Support for the "command-preserve" property.
	 */
	command_preserve = ddi_prop_get_int(DDI_DEV_T_ANY, child,
						DDI_PROP_DONTPASS,
						"command-preserve", 0);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);
	command &= (command_preserve | PCI_COMM_BACK2BACK_ENAB);
	command |= (pci_command_default & ~command_preserve);
	pci_config_put16(config_handle, PCI_CONF_COMM, command);

	pci_config_teardown(&config_handle);
	return (DDI_SUCCESS);
}

static int
pci_removechild(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr;

	if ((pdptr = ddi_get_parent_data(dip)) != NULL) {
		kmem_free(pdptr, (sizeof (*pdptr) + sizeof (struct intrspec)));
		ddi_set_parent_data(dip, NULL);
	}
	ddi_set_name_addr(dip, NULL);

	/*
	 * Strip the node to properly convert it back to prototype form
	 */
	ddi_remove_minor_node(dip, NULL);

	impl_rem_dev_props(dip);

	return (DDI_SUCCESS);
}


/*
 * These are the get and put functions to be shared with drivers. The
 * mutex locking is done inside the functions referenced, rather than
 * here, and is thus shared across PCI child drivers and any other
 * consumers of PCI config space (such as the ACPI subsystem).
 *
 * The configuration space addresses come in as pointers.  This is fine on
 * a 32-bit system, where the VM space and configuration space are the same
 * size.  It's not such a good idea on a 64-bit system, where memory
 * addresses are twice as large as configuration space addresses.  At some
 * point in the call tree we need to take a stand and say "you are 32-bit
 * from this time forth", and this seems like a nice self-contained place.
 */

static uint8_t
pci_config_rd8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	pci_acc_cfblk_t *cfp;
	uint8_t	rval;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)&hdlp->ahi_common.ah_bus_private;

	rval = (*pci_getb_func)(cfp->c_busnum, cfp->c_devnum, cfp->c_funcnum,
	    reg);

	return (rval);
}

static void
pci_config_rep_rd8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = pci_config_rd8(hdlp, d++);
	else
		for (; repcount; repcount--)
			*h++ = pci_config_rd8(hdlp, d);
}

static uint16_t
pci_config_rd16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	pci_acc_cfblk_t *cfp;
	uint16_t rval;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)&hdlp->ahi_common.ah_bus_private;

	rval = (*pci_getw_func)(cfp->c_busnum, cfp->c_devnum, cfp->c_funcnum,
	    reg);

	return (rval);
}

static void
pci_config_rep_rd16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = pci_config_rd16(hdlp, d++);
	else
		for (; repcount; repcount--)
			*h++ = pci_config_rd16(hdlp, d);
}

static uint32_t
pci_config_rd32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	pci_acc_cfblk_t *cfp;
	uint32_t rval;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)&hdlp->ahi_common.ah_bus_private;

	rval = (*pci_getl_func)(cfp->c_busnum, cfp->c_devnum,
	    cfp->c_funcnum, reg);

	return (rval);
}

static void
pci_config_rep_rd32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = pci_config_rd32(hdlp, d++);
	else
		for (; repcount; repcount--)
			*h++ = pci_config_rd32(hdlp, d);
}


static void
pci_config_wr8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	pci_acc_cfblk_t *cfp;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)&hdlp->ahi_common.ah_bus_private;

	(*pci_putb_func)(cfp->c_busnum, cfp->c_devnum,
	    cfp->c_funcnum, reg, value);
}

static void
pci_config_rep_wr8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			pci_config_wr8(hdlp, d++, *h++);
	else
		for (; repcount; repcount--)
			pci_config_wr8(hdlp, d, *h++);
}

static void
pci_config_wr16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	pci_acc_cfblk_t *cfp;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)&hdlp->ahi_common.ah_bus_private;

	(*pci_putw_func)(cfp->c_busnum, cfp->c_devnum,
	    cfp->c_funcnum, reg, value);
}

static void
pci_config_rep_wr16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			pci_config_wr16(hdlp, d++, *h++);
	else
		for (; repcount; repcount--)
			pci_config_wr16(hdlp, d, *h++);
}

static void
pci_config_wr32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	pci_acc_cfblk_t *cfp;
	int reg;

	ASSERT64(((uintptr_t)addr >> 32) == 0);

	reg = (int)(uintptr_t)addr;

	cfp = (pci_acc_cfblk_t *)&hdlp->ahi_common.ah_bus_private;

	(*pci_putl_func)(cfp->c_busnum, cfp->c_devnum,
	    cfp->c_funcnum, reg, value);
}

static void
pci_config_rep_wr32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			pci_config_wr32(hdlp, d++, *h++);
	else
		for (; repcount; repcount--)
			pci_config_wr32(hdlp, d, *h++);
}

static uint64_t
pci_config_rd64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint32_t lw_val;
	uint32_t hi_val;
	uint32_t *dp;
	uint64_t val;

	dp = (uint32_t *)addr;
	lw_val = pci_config_rd32(hdlp, dp);
	dp++;
	hi_val = pci_config_rd32(hdlp, dp);
	val = ((uint64_t)hi_val << 32) | lw_val;
	return (val);
}

static void
pci_config_wr64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	uint32_t lw_val;
	uint32_t hi_val;
	uint32_t *dp;

	dp = (uint32_t *)addr;
	lw_val = (uint32_t)(value & 0xffffffff);
	hi_val = (uint32_t)(value >> 32);
	pci_config_wr32(hdlp, dp, lw_val);
	dp++;
	pci_config_wr32(hdlp, dp, hi_val);
}

static void
pci_config_rep_rd64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			*host_addr++ = pci_config_rd64(hdlp, dev_addr++);
	} else {
		for (; repcount; repcount--)
			*host_addr++ = pci_config_rd64(hdlp, dev_addr);
	}
}

static void
pci_config_rep_wr64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			pci_config_wr64(hdlp, host_addr++, *dev_addr++);
	} else {
		for (; repcount; repcount--)
			pci_config_wr64(hdlp, host_addr++, *dev_addr);
	}
}

/*
 * When retrofitting this module for pci_tools, functions such as open, close,
 * and ioctl are now pulled into this module.  Before this, the functions in
 * the pcihp module were referenced directly.  Now they are called or
 * referenced through the pcihp cb_ops structure from functions in this module.
 */

static int
pci_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_cb_ops.cb_open)(devp, flags, otyp, credp));
}

static int
pci_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	return ((pcihp_cb_ops.cb_close)(dev, flags, otyp, credp));
}

static int
pci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	minor_t		minor = getminor(dev);
	int		instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(minor);
	pci_state_t	*pci_p = ddi_get_soft_state(pci_statep, instance);
	dev_info_t	*dip = pci_p->pci_dip;
	int		rv = ENOTTY;

	switch (PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:

		switch (cmd) {
		case PCITOOL_DEVICE_SET_REG:
		case PCITOOL_DEVICE_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pcitool_dev_reg_ops(
				    dip, (void *)arg, cmd, mode);
			break;

		case PCITOOL_NEXUS_SET_REG:
		case PCITOOL_NEXUS_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pcitool_bus_reg_ops(
				    dip, (void *)arg, cmd, mode);
			break;
		}
		break;

	case PCI_TOOL_INTR_MINOR_NUM:

		switch (cmd) {
		case PCITOOL_DEVICE_SET_INTR:

			/* Require PRIV_SYS_RES_CONFIG, same as psradm */
			if (secpolicy_ponline(credp)) {
				rv = EPERM;
				break;
			}

		/*FALLTHRU*/
		/* These require no special privileges. */
		case PCITOOL_DEVICE_GET_INTR:
		case PCITOOL_DEVICE_NUM_INTR:
			rv = pcitool_intr_admn(dip, (void *)arg, cmd, mode);
			break;
		}
		break;

	/*
	 * All non-PCItool ioctls go through here, including:
	 *   devctl ioctls with minor number PCIHP_DEVCTL_MINOR and
	 *   those for attachment points with where minor number is the
	 *   device number.
	 */
	default:
		rv = (pcihp_cb_ops.cb_ioctl)(dev, cmd, arg, mode,
		    credp, rvalp);
		break;
	}

	return (rv);
}

static int
pci_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
	int flags, char *name, caddr_t valuep, int *lengthp)
{
	return ((pcihp_cb_ops.cb_prop_op)(dev, dip, prop_op, flags,
	    name, valuep, lengthp));
}

static int
pci_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	return (pcihp_info(dip, cmd, arg, result));
}
