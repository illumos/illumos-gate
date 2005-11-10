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
 *	File that has code which is common between pci(7d) and npe(7d)
 *	It shares the following:
 *	- interrupt code
 *	- pci_tools ioctl code
 *	- name_child code
 *	- set_parent_private_data code
 */

#include <sys/conf.h>
#include <sys/pci.h>
#include <sys/sunndi.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/pci_intr_lib.h>
#include <sys/psm.h>
#include <sys/policy.h>
#include <sys/sysmacros.h>
#include <sys/pci_tools.h>
#include <io/pci/pci_var.h>
#include <io/pci/pci_tools_ext.h>
#include <io/pci/pci_common.h>

/*
 * Function prototypes
 */
static int	pci_get_priority(dev_info_t *, ddi_intr_handle_impl_t *, int *);
static int	pci_get_nintrs(dev_info_t *, int, int *);
static int	pci_enable_intr(dev_info_t *, dev_info_t *,
		    ddi_intr_handle_impl_t *, uint32_t);
static void	pci_disable_intr(dev_info_t *, dev_info_t *,
		    ddi_intr_handle_impl_t *, uint32_t);

/* Extern decalration for pcplusmp module */
extern int	(*psm_intr_ops)(dev_info_t *, ddi_intr_handle_impl_t *,
		    psm_intr_op_t, int *);


/*
 * pci_name_child:
 *
 *	Assign the address portion of the node name
 */
int
pci_common_name_child(dev_info_t *child, char *name, int namelen)
{
	int		dev, func, length;
	char		**unit_addr;
	uint_t		n;
	pci_regspec_t	*pci_rp;

	if (ndi_dev_is_persistent_node(child) == 0) {
		/*
		 * For .conf node, use "unit-address" property
		 */
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "unit-address", &unit_addr, &n) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "cannot find unit-address in %s.conf",
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

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, (uint_t *)&length) != DDI_PROP_SUCCESS) {
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

/*
 * Interrupt related code:
 *
 * The following busop is common to npe and pci drivers
 *	bus_introp
 */

/*
 * Create the ddi_parent_private_data for a pseudo child.
 */
void
pci_common_set_parent_private_data(dev_info_t *dip)
{
	struct ddi_parent_private_data *pdptr;

	pdptr = (struct ddi_parent_private_data *)kmem_zalloc(
	    (sizeof (struct ddi_parent_private_data) +
	sizeof (struct intrspec)), KM_SLEEP);
	pdptr->par_intr = (struct intrspec *)(pdptr + 1);
	pdptr->par_nintr = 1;
	ddi_set_parent_data(dip, pdptr);
}

/*
 * pci_get_priority:
 *	Figure out the priority of the device
 */
static int
pci_get_priority(dev_info_t *dip, ddi_intr_handle_impl_t *hdlp, int *pri)
{
	struct intrspec *ispec;

	DDI_INTR_NEXDBG((CE_CONT, "pci_get_priority: dip = 0x%p, hdlp = %p\n",
	    (void *)dip, (void *)hdlp));

	if ((ispec = (struct intrspec *)pci_intx_get_ispec(dip, dip,
	    hdlp->ih_inum)) == NULL) {
		if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type)) {
			int class = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "class-code", -1);

			*pri = (class == -1) ? 1 : pci_devclass_to_ipl(class);
			pci_common_set_parent_private_data(hdlp->ih_dip);
			ispec = (struct intrspec *)pci_intx_get_ispec(dip, dip,
			    hdlp->ih_inum);
			return (DDI_SUCCESS);
		}
		return (DDI_FAILURE);
	}

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

static int pcie_pci_intr_pri_counter = 0;

/*
 * pci_common_intr_ops: bus_intr_op() function for interrupt support
 */
int
pci_common_intr_ops(dev_info_t *pdip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int			priority = 0;
	int			psm_status = 0;
	int			pci_status = 0;
	int			pci_rval, psm_rval = PSM_FAILURE;
	int			types = 0;
	int			pciepci = 0;
	int			i, j;
	int			behavior;
	ddi_intrspec_t		isp;
	struct intrspec		*ispec;
	ddi_intr_handle_impl_t	tmp_hdl;
	ddi_intr_msix_t		*msix_p;

	DDI_INTR_NEXDBG((CE_CONT,
	    "pci_common_intr_ops: pdip 0x%p, rdip 0x%p, op %x handle 0x%p\n",
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
			DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: "
			    "rdip: 0x%p supported types: 0x%x\n", (void *)rdip,
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
		    (pci_get_priority(rdip, hdlp, &priority) == DDI_SUCCESS)) {
			/*
			 * Following check is a special case for 'pcie_pci'.
			 * This makes sure vectors with the right priority
			 * are allocated for pcie_pci during ALLOC time.
			 */
			if (strcmp(ddi_driver_name(rdip), "pcie_pci") == 0) {
				hdlp->ih_pri =
				    (pcie_pci_intr_pri_counter % 2) ? 4 : 7;
				pciepci = 1;
			} else
				hdlp->ih_pri = priority;
			behavior = hdlp->ih_scratch2;
			(void) (*psm_intr_ops)(rdip, hdlp,
			    PSM_INTR_OP_ALLOC_VECTORS, result);

			/* verify behavior flag and take appropriate action */
			if ((behavior == DDI_INTR_ALLOC_STRICT) &&
			    (*(int *)result < hdlp->ih_scratch1)) {
				DDI_INTR_NEXDBG((CE_CONT,
				    "pci_common_intr_ops: behavior %x, "
				    "couldn't get enough intrs\n", behavior));
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

			if (pciepci) {
				/* update priority in ispec */
				isp = pci_intx_get_ispec(pdip, rdip,
					(int)hdlp->ih_inum);
				ispec = (struct intrspec *)isp;
				if (ispec)
					ispec->intrspec_pri = hdlp->ih_pri;
				++pcie_pci_intr_pri_counter;
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
		/* Get the priority */
		if (pci_get_priority(rdip, hdlp, &priority) != DDI_SUCCESS)
			return (DDI_FAILURE);
		DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: "
		    "priority = 0x%x\n", priority));
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
		if (ispec)
			ispec->intrspec_pri = *(int *)result;
		break;
	case DDI_INTROP_ADDISR:
		/* update ispec */
		isp = pci_intx_get_ispec(pdip, rdip, (int)hdlp->ih_inum);
		ispec = (struct intrspec *)isp;
		if (ispec)
			ispec->intrspec_func = hdlp->ih_cb_func;
		break;
	case DDI_INTROP_REMISR:
		/* Get the interrupt structure pointer */
		isp = pci_intx_get_ispec(pdip, rdip, (int)hdlp->ih_inum);
		ispec = (struct intrspec *)isp;
		if (ispec)
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
		DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: "
		    "SETCAP cap=0x%x\n", *(int *)result));
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		if ((*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_SET_CAP, result)) {
			DDI_INTR_NEXDBG((CE_CONT, "GETCAP: psm_intr_ops"
			    " returned failure\n"));
			return (DDI_FAILURE);
		}
		break;
	case DDI_INTROP_ENABLE:
		DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: ENABLE\n"));
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		if (pci_enable_intr(pdip, rdip, hdlp, hdlp->ih_inum) !=
		    DDI_SUCCESS)
			return (DDI_FAILURE);

		DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: ENABLE "
		    "vector=0x%x\n", hdlp->ih_vector));
		break;
	case DDI_INTROP_DISABLE:
		DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: DISABLE\n"));
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		pci_disable_intr(pdip, rdip, hdlp, hdlp->ih_inum);
		DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: DISABLE "
		    "vector = %x\n", hdlp->ih_vector));
		break;
	case DDI_INTROP_BLOCKENABLE:
		DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: "
		    "BLOCKENABLE\n"));
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
			DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: "
			    "BLOCKENABLE inum %x done\n", hdlp->ih_inum + i));
		}
		break;
	case DDI_INTROP_BLOCKDISABLE:
		DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: "
		    "BLOCKDISABLE\n"));
		if (hdlp->ih_type != DDI_INTR_TYPE_MSI) {
			DDI_INTR_NEXDBG((CE_CONT, "BLOCKDISABLE: not MSI\n"));
			return (DDI_FAILURE);
		}

		/* Check if psm_intr_ops is present */
		if (psm_intr_ops == NULL)
			return (DDI_FAILURE);

		for (i = 0; i < hdlp->ih_scratch1; i++) {
			pci_disable_intr(pdip, rdip, hdlp, hdlp->ih_inum + i);
			DDI_INTR_NEXDBG((CE_CONT, "pci_common_intr_ops: "
			    "BLOCKDISABLE inum %x done\n", hdlp->ih_inum + i));
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
		    hdlp, &priority) == DDI_SUCCESS)) {
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
	if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type) && ispec)
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
	if (DDI_INTR_IS_MSI_OR_MSIX(hdlp->ih_type) && ispec)
		ispec->intrspec_vec = inum;
	hdlp->ih_private = (void *)ispec;

	/* translate the interrupt if needed */
	(void) (*psm_intr_ops)(rdip, hdlp, PSM_INTR_OP_XLATE_VECTOR, &vector);

	/* Disable the interrupt handler */
	rem_avintr((void *)hdlp, hdlp->ih_pri, hdlp->ih_cb_func, vector);
}

/*
 * Miscellaneous library function
 */
int
pci_common_get_reg_prop(dev_info_t *dip, pci_regspec_t *pci_rp)
{
	int		i;
	int 		number;
	int		assigned_addr_len;
	uint_t		phys_hi = pci_rp->pci_phys_hi;
	pci_regspec_t	*assigned_addr;

	if (((phys_hi & PCI_REG_ADDR_M) == PCI_ADDR_CONFIG) ||
	    (phys_hi & PCI_RELOCAT_B))
		return (DDI_SUCCESS);

	/*
	 * the "reg" property specifies relocatable, get and interpret the
	 * "assigned-addresses" property.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (int **)&assigned_addr,
	    (uint_t *)&assigned_addr_len) != DDI_PROP_SUCCESS)
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


/*
 * For pci_tools
 */

int
pci_common_ioctl(dev_info_t *dip, dev_t dev, int cmd, intptr_t arg,
    int mode, cred_t *credp, int *rvalp)
{
	int rv = ENOTTY;

	minor_t minor = getminor(dev);

	switch (PCIHP_AP_MINOR_NUM_TO_PCI_DEVNUM(minor)) {
	case PCI_TOOL_REG_MINOR_NUM:

		switch (cmd) {
		case PCITOOL_DEVICE_SET_REG:
		case PCITOOL_DEVICE_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pcitool_dev_reg_ops(dip, (void *)arg,
				    cmd, mode);
			break;

		case PCITOOL_NEXUS_SET_REG:
		case PCITOOL_NEXUS_GET_REG:

			/* Require full privileges. */
			if (secpolicy_kmdb(credp))
				rv = EPERM;
			else
				rv = pcitool_bus_reg_ops(dip, (void *)arg,
				    cmd, mode);
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
		rv = (pcihp_get_cb_ops())->cb_ioctl(dev, cmd, arg, mode,
		    credp, rvalp);
		break;
	}

	return (rv);
}
