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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

/*
 *	PCI-IDE bus nexus driver
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>
#include <sys/dma_engine.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/mach_intr.h>
#include <sys/kmem.h>
#include <sys/pci.h>
#include <sys/promif.h>
#include <sys/pci_intr_lib.h>
#include <sys/apic.h>

int	pciide_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
int	pciide_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

#define	PCIIDE_NATIVE_MODE(dip)						\
	(!ddi_prop_exists(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS,	\
	"compatibility-mode"))

#define	PCIIDE_PRE26(dip)	\
	ddi_prop_exists(DDI_DEV_T_ANY, (dip), 0, "ignore-hardware-nodes")

#define	PCI_IDE_IF_BM_CAP_MASK	0x80

#define	PCIIDE_PDSIZE	(sizeof (struct ddi_parent_private_data) + \
	sizeof (struct intrspec))

#ifdef DEBUG
static int pci_ide_debug = 0;
#define	PDBG(fmt)				\
		if (pci_ide_debug) {		\
			prom_printf fmt;	\
		}
#else
#define	PDBG(fmt)
#endif

#ifndef	TRUE
#define	TRUE	1
#endif
#ifndef	FALSE
#define	FALSE	0
#endif

/*
 * bus_ops functions
 */

static int		pciide_bus_map(dev_info_t *dip, dev_info_t *rdip,
				ddi_map_req_t *mp, off_t offset, off_t len,
				caddr_t *vaddrp);

static	int		pciide_ddi_ctlops(dev_info_t *dip, dev_info_t *rdip,
				ddi_ctl_enum_t ctlop, void *arg,
				void *result);

static	int		pciide_get_pri(dev_info_t *dip, dev_info_t *rdip,
				ddi_intr_handle_impl_t *hdlp, int *pri);

static	int		pciide_intr_ops(dev_info_t *dip, dev_info_t *rdip,
				ddi_intr_op_t intr_op,
				ddi_intr_handle_impl_t *hdlp, void *result);

static struct intrspec *pciide_get_ispec(dev_info_t *dip, dev_info_t *rdip,
				int inum);

/*
 * Local Functions
 */
static	int	pciide_initchild(dev_info_t *mydip, dev_info_t *cdip);

static	void	pciide_compat_setup(dev_info_t *mydip, dev_info_t *cdip,
				    int dev);
static	int	pciide_pre26_rnumber_map(dev_info_t *mydip, int rnumber);
static	int	pciide_map_rnumber(int canonical_rnumber, int pri_native,
				    int sec_native);
static int pciide_alloc_intr(dev_info_t *, dev_info_t *,
    ddi_intr_handle_impl_t *, void *);
static int pciide_free_intr(dev_info_t *, dev_info_t *,
    ddi_intr_handle_impl_t *);

extern int (*psm_intr_ops)(dev_info_t *, ddi_intr_handle_impl_t *,
    psm_intr_op_t, int *);

/*
 * Config information
 */

struct bus_ops pciide_bus_ops = {
	BUSO_REV,
	pciide_bus_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	0,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	pciide_ddi_ctlops,
	ddi_bus_prop_op,
	0,	/* (*bus_get_eventcookie)();	*/
	0,	/* (*bus_add_eventcall)();	*/
	0,	/* (*bus_remove_eventcall)();	*/
	0,	/* (*bus_post_event)();		*/
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	pciide_intr_ops
};

struct dev_ops pciide_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	pciide_attach,		/* attach */
	pciide_detach,		/* detach */
	nodev,			/* reset */
	(struct cb_ops *)0,	/* driver operations */
	&pciide_bus_ops,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This is PCI-IDE bus driver */
	"pciide nexus driver for 'PCI-IDE' 1.26",
	&pciide_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
pciide_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	uint16_t cmdreg;
	ddi_acc_handle_t conf_hdl = NULL;
	int rc;

	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * Make sure bus-mastering is enabled, even if
		 * BIOS didn't.
		 */
		rc = pci_config_setup(dip, &conf_hdl);

		/*
		 * In case of error, return SUCCESS. This is because
		 * bus-mastering could be already enabled by BIOS.
		 */
		if (rc != DDI_SUCCESS)
			return (DDI_SUCCESS);

		cmdreg = pci_config_get16(conf_hdl, PCI_CONF_COMM);
		if ((cmdreg & PCI_COMM_ME) == 0) {
			pci_config_put16(conf_hdl, PCI_CONF_COMM,
			    cmdreg | PCI_COMM_ME);
		}
		pci_config_teardown(&conf_hdl);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		/* Restore our PCI configuration header */
		if (pci_restore_config_regs(dip) != DDI_SUCCESS) {
			/*
			 * XXXX
			 * This is a pretty bad thing.  However, for some
			 * reason it always happens.  To further complicate
			 * things, it appears if we just ignore this, we
			 * properly resume.  For now, all I want to do is
			 * to generate this message so that it doesn't get
			 * forgotten.
			 */
			cmn_err(CE_WARN,
			    "Couldn't restore PCI config regs for %s(%p)",
			    ddi_node_name(dip), (void *) dip);
		}
#ifdef	DEBUG
		/* Bus mastering should still be enabled */
		if (pci_config_setup(dip, &conf_hdl) != DDI_SUCCESS)
			return (DDI_FAILURE);
		cmdreg = pci_config_get16(conf_hdl, PCI_CONF_COMM);
		ASSERT((cmdreg & PCI_COMM_ME) != 0);
		pci_config_teardown(&conf_hdl);
#endif
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
pciide_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		/* Save our PCI configuration header */
		if (pci_save_config_regs(dip) != DDI_SUCCESS) {
			/* Don't suspend if we cannot save config regs */
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
pciide_ddi_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	dev_info_t *cdip;
	int controller;
	void *pdptr;
	int rnumber;
	off_t tmp;
	int rc;

	PDBG(("pciide_bus_ctl\n"));

	switch (ctlop) {
	case DDI_CTLOPS_INITCHILD:
		cdip = (dev_info_t *)arg;
		return (pciide_initchild(dip, cdip));

	case DDI_CTLOPS_UNINITCHILD:
		cdip = (dev_info_t *)arg;
		pdptr = ddi_get_parent_data(cdip);
		ddi_set_parent_data(cdip, NULL);
		ddi_set_name_addr(cdip, NULL);
		kmem_free(pdptr, PCIIDE_PDSIZE);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:
		*(int *)result = 3;
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
		/*
		 * Adjust the rnumbers based on which controller instance
		 * is requested; adjust for the 2 tuples per controller.
		 */
		if (strcmp("0", ddi_get_name_addr(rdip)) == 0)
			controller = 0;
		else
			controller = 1;


		switch (rnumber = *(int *)arg) {
		case 0:
		case 1:
			rnumber += (2 * controller);
			break;
		case 2:
			rnumber = 4;
			break;
		default:
			PDBG(("pciide_ctlops invalid rnumber\n"));
			return (DDI_FAILURE);
		}


		if (PCIIDE_PRE26(dip)) {
			int	old_rnumber;
			int	new_rnumber;

			old_rnumber = rnumber;
			new_rnumber
			    = pciide_pre26_rnumber_map(dip, old_rnumber);
			PDBG(("pciide rnumber old %d new %d\n",
			    old_rnumber, new_rnumber));
			rnumber = new_rnumber;
		}

		/*
		 * Add 1 to skip over the PCI config space tuple
		 */
		rnumber++;

		/*
		 * If it's not tuple #2 pass the adjusted request to my parent
		 */
		if (*(int *)arg != 2) {
			return (ddi_ctlops(dip, dip, ctlop, &rnumber, result));
		}

		/*
		 * Handle my child's reg-tuple #2 here by splitting my 16 byte
		 * reg-tuple #4 into two 8 byte ranges based on the
		 * the child's controller #.
		 */

		tmp = 8;
		rc = ddi_ctlops(dip, dip, ctlop, &rnumber, &tmp);

		/*
		 * Allow for the possibility of less than 16 bytes by
		 * by checking what's actually returned for my reg-tuple #4.
		 */
		if (controller == 1) {
			if (tmp < 8)
				tmp = 0;
			else
				tmp -= 8;
		}
		if (tmp > 8)
			tmp = 8;
		*(off_t *)result = tmp;

		return (rc);

	case DDI_CTLOPS_ATTACH:
	case DDI_CTLOPS_DETACH:
		/*
		 * Don't pass child ide ATTACH/DETACH to parent
		 */
		return (DDI_SUCCESS);

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

/*
 * IEEE 1275 Working Group Proposal #414 says that the Primary
 * controller is "ata@0" and the Secondary controller "ata@1".
 *
 * By the time we get here, boot Bootconf (2.6+) has created devinfo
 * nodes with the appropriate "reg", "assigned-addresses" and "interrupts"
 * properites on the pci-ide node and both ide child nodes.
 *
 * In compatibility mode the "reg" and "assigned-addresses" properties
 * of the pci-ide node are set up like this:
 *
 *   1. PCI-IDE Nexus
 *
 *	interrupts=0
 *				(addr-hi addr-mid addr-low size-hi  size-low)
 *	reg= assigned-addresses=00000000.00000000.00000000.00000000.00000000
 *				81000000.00000000.000001f0.00000000.00000008
 *				81000000.00000000.000003f4.00000000.00000004
 *				81000000.00000000,00000170.00000000.00000008
 *				81000000.00000000,00000374.00000000.00000004
 *				01000020.00000000,-[BAR4]-.00000000.00000010
 *
 * In native PCI mode the "reg" and "assigned-addresses" properties
 * would be set up like this:
 *
 *   2. PCI-IDE Nexus
 *
 *	interrupts=0
 *	reg= assigned-addresses=00000000.00000000.00000000.00000000.00000000
 *				01000010.00000000.-[BAR0]-.00000000.00000008
 *				01000014,00000000.-[BAR1]-.00000000.00000004
 *				01000018.00000000.-[BAR2]-.00000000.00000008
 *				0100001c.00000000.-[BAR3]-.00000000.00000004
 *				01000020.00000000.-[BAR4]-.00000000.00000010
 *
 *
 * In both modes the child nodes simply have the following:
 *
 *   2. primary controller (compatibility mode)
 *
 *	interrupts=14
 *	reg=00000000
 *
 *   3. secondary controller
 *
 *	interrupts=15
 *	reg=00000001
 *
 * The pciide_bus_map() function is responsible for turning requests
 * to map primary or secondary controller rnumbers into mapping requests
 * of the appropriate regspec on the pci-ide node.
 *
 */

static int
pciide_initchild(dev_info_t *mydip, dev_info_t *cdip)
{
	struct ddi_parent_private_data *pdptr;
	struct intrspec	*ispecp;
	int	vec;
	int	*rp;
	uint_t	proplen;
	char	name[80];
	int	dev;

	PDBG(("pciide_initchild\n"));

	/*
	 * Set the address portion of the node name based on
	 * the controller number (0 or 1) from the 'reg' property.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "reg", &rp, (uint_t *)&proplen) != DDI_PROP_SUCCESS) {
		PDBG(("pciide_intchild prop error\n"));
		return (DDI_NOT_WELL_FORMED);
	}

	/*
	 * copy the controller number and
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	dev = *rp;
	ddi_prop_free(rp);

	/*
	 * I only support two controllers per device, determine
	 * which this one is and set its unit address.
	 */
	if (dev > 1) {
		PDBG(("pciide_initchild bad dev\n"));
		return (DDI_NOT_WELL_FORMED);
	}
	(void) sprintf(name, "%d", dev);
	ddi_set_name_addr(cdip, name);

	/*
	 * determine if this instance is running in native or compat mode
	 */
	pciide_compat_setup(mydip, cdip, dev);

	/* interrupts property is required */
	if (PCIIDE_NATIVE_MODE(cdip)) {
		vec = 1;
	} else {
		/*
		 * In compatibility mode, dev 0 should always be
		 * IRQ 14 and dev 1 is IRQ 15. If for some reason
		 * this needs to be changed, do it via the interrupts
		 * property in the ata.conf file.
		 */
		vec = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "interrupts", -1);
		if (vec == -1) {
			/* setup compatibility mode interrupts */
			if (dev == 0) {
				vec = 14;
			} else if (dev == 1) {
				vec = 15;
			} else {
				PDBG(("pciide_initchild bad intr\n"));
				return (DDI_NOT_WELL_FORMED);
			}
		}
	}

	pdptr = kmem_zalloc(PCIIDE_PDSIZE, KM_SLEEP);
	ispecp = (struct intrspec *)(pdptr + 1);
	pdptr->par_nintr = 1;
	pdptr->par_intr = ispecp;
	ispecp->intrspec_vec = vec;
	ddi_set_parent_data(cdip, pdptr);

	PDBG(("pciide_initchild okay\n"));
	return (DDI_SUCCESS);
}

static int
pciide_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t offset, off_t len, caddr_t *vaddrp)
{
	dev_info_t *pdip;
	int	    rnumber = mp->map_obj.rnumber;
	int	    controller;
	int	    rc;

	PDBG(("pciide_bus_map\n"));

	if (strcmp("0", ddi_get_name_addr(rdip)) == 0)
		controller = 0;
	else
		controller = 1;

	/*
	 * Adjust the rnumbers based on which controller instance
	 * is being mapped; adjust for the 2 tuples per controller.
	 */

	switch (rnumber) {
	case 0:
	case 1:
		mp->map_obj.rnumber += (controller * 2);
		break;
	case 2:
		/*
		 * split the 16 I/O ports into two 8 port ranges
		 */
		mp->map_obj.rnumber = 4;
		if (offset + len > 8) {
			PDBG(("pciide_bus_map offset\n"));
			return (DDI_FAILURE);
		}
		if (len == 0)
			len = 8 - offset;
		offset += 8 * controller;
		break;
	default:
		PDBG(("pciide_bus_map default\n"));
		return (DDI_FAILURE);
	}

	if (PCIIDE_PRE26(dip)) {
		int	old_rnumber;
		int	new_rnumber;

		old_rnumber = mp->map_obj.rnumber;
		new_rnumber = pciide_pre26_rnumber_map(dip, old_rnumber);
		PDBG(("pciide rnumber old %d new %d\n",
		    old_rnumber, new_rnumber));
		mp->map_obj.rnumber = new_rnumber;
	}

	/*
	 * Add 1 to skip over the PCI config space tuple
	 */
	mp->map_obj.rnumber++;


	/*
	 * pass the adjusted request to my parent
	 */
	pdip = ddi_get_parent(dip);
	rc = ((*(DEVI(pdip)->devi_ops->devo_bus_ops->bus_map))
	    (pdip, dip, mp, offset, len, vaddrp));

	PDBG(("pciide_bus_map %s\n", rc == DDI_SUCCESS ? "okay" : "!ok"));

	return (rc);
}


static struct intrspec *
pciide_get_ispec(dev_info_t *dip, dev_info_t *rdip, int inumber)
{
	struct ddi_parent_private_data *ppdptr;

	PDBG(("pciide_get_ispec\n"));

	/*
	 * Native mode PCI-IDE controllers share the parent's
	 * PCI interrupt line.
	 *
	 * Compatibility mode PCI-IDE controllers have their
	 * own intrspec which specifies ISA IRQ 14 or 15.
	 *
	 */
	if (PCIIDE_NATIVE_MODE(rdip)) {
		ddi_intrspec_t is;

		is = pci_intx_get_ispec(dip, dip, inumber);
		PDBG(("pciide_get_ispec okay\n"));
		return ((struct intrspec *)is);
	}

	/* Else compatibility mode, use the ISA IRQ */
	if ((ppdptr = ddi_get_parent_data(rdip)) == NULL) {
		PDBG(("pciide_get_ispec null\n"));
		return (NULL);
	}

	/* validate the interrupt number  */
	if (inumber >= ppdptr->par_nintr) {
		PDBG(("pciide_get_inum\n"));
		return (NULL);
	}

	PDBG(("pciide_get_ispec ok\n"));

	return ((struct intrspec *)&ppdptr->par_intr[inumber]);
}

static	int
pciide_get_pri(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, int *pri)
{
	struct intrspec	*ispecp;
	int		*intpriorities;
	uint_t		 num_intpriorities;

	PDBG(("pciide_get_pri\n"));

	if ((ispecp = pciide_get_ispec(dip, rdip, hdlp->ih_inum)) == NULL) {
		PDBG(("pciide_get_pri null\n"));
		return (DDI_FAILURE);
	}

	if (PCIIDE_NATIVE_MODE(rdip)) {
		*pri = ispecp->intrspec_pri;
		PDBG(("pciide_get_pri ok\n"));
		return (DDI_SUCCESS);
	}

	/* check if the intrspec has been initialized */
	if (ispecp->intrspec_pri != 0) {
		*pri = ispecp->intrspec_pri;
		PDBG(("pciide_get_pri ok2\n"));
		return (DDI_SUCCESS);
	}

	/* Use a default of level 5  */
	ispecp->intrspec_pri = 5;

	/*
	 * If there's an interrupt-priorities property, use it to
	 * over-ride the default interrupt priority.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
	    "interrupt-priorities", &intpriorities, &num_intpriorities) ==
	    DDI_PROP_SUCCESS) {
		if (hdlp->ih_inum < num_intpriorities)
			ispecp->intrspec_pri = intpriorities[hdlp->ih_inum];
		ddi_prop_free(intpriorities);
	}
	*pri = ispecp->intrspec_pri;

	PDBG(("pciide_get_pri ok3\n"));

	return (DDI_SUCCESS);
}

static int
pciide_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	struct intrspec	*ispecp;
	int		rc;
	int		pri = 0;

	PDBG(("pciide_intr_ops: dip %p rdip %p op %x hdlp %p\n",
	    (void *)dip, (void *)rdip, intr_op, (void *)hdlp));

	switch (intr_op) {
	case DDI_INTROP_SUPPORTED_TYPES:
		*(int *)result = DDI_INTR_TYPE_FIXED;
		break;
	case DDI_INTROP_GETCAP:
		*(int *)result = DDI_INTR_FLAG_LEVEL;
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = (!PCIIDE_NATIVE_MODE(rdip)) ?
		    i_ddi_get_intx_nintrs(rdip) : 1;
		break;
	case DDI_INTROP_ALLOC:
		return (pciide_alloc_intr(dip, rdip, hdlp, result));
	case DDI_INTROP_FREE:
		return (pciide_free_intr(dip, rdip, hdlp));
	case DDI_INTROP_GETPRI:
		if (pciide_get_pri(dip, rdip, hdlp, &pri) != DDI_SUCCESS) {
			*(int *)result = 0;
			return (DDI_FAILURE);
		}
		*(int *)result = pri;
		break;
	case DDI_INTROP_ADDISR:
		if ((ispecp = pciide_get_ispec(dip, rdip, hdlp->ih_inum)) ==
		    NULL)
			return (DDI_FAILURE);
		((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp = ispecp;
		ispecp->intrspec_func = hdlp->ih_cb_func;
		break;
	case DDI_INTROP_REMISR:
		if ((ispecp = pciide_get_ispec(dip, rdip, hdlp->ih_inum)) ==
		    NULL)
			return (DDI_FAILURE);
		ispecp->intrspec_func = (uint_t (*)()) 0;
		break;
	case DDI_INTROP_ENABLE:
	/* FALLTHRU */
	case DDI_INTROP_DISABLE:
		if (PCIIDE_NATIVE_MODE(rdip)) {
			rdip = dip;
			dip = ddi_get_parent(dip);
		} else {	/* get ptr to the root node */
			dip = ddi_root_node();
		}

		rc = (*(DEVI(dip)->devi_ops->devo_bus_ops->bus_intr_op))(dip,
		    rdip, intr_op, hdlp, result);

#ifdef	DEBUG
		if (intr_op == DDI_INTROP_ENABLE) {
			PDBG(("pciide_enable rc=%d", rc));
		} else
			PDBG(("pciide_disable rc=%d", rc));
#endif	/* DEBUG */
		return (rc);
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
pciide_alloc_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	struct intrspec		*ispec;
	ddi_intr_handle_impl_t	info_hdl;
	int			ret;
	int			free_phdl = 0;
	apic_get_type_t		type_info;

	if (psm_intr_ops == NULL)
		return (DDI_FAILURE);

	if ((ispec = pciide_get_ispec(dip, rdip, hdlp->ih_inum)) == NULL)
		return (DDI_FAILURE);

	/*
	 * If the PSM module is "APIX" then pass the request for it
	 * to allocate the vector now.
	 */
	bzero(&info_hdl, sizeof (ddi_intr_handle_impl_t));
	info_hdl.ih_private = &type_info;
	if ((*psm_intr_ops)(NULL, &info_hdl, PSM_INTR_OP_APIC_TYPE, NULL) ==
	    PSM_SUCCESS && strcmp(type_info.avgi_type, APIC_APIX_NAME) == 0) {
		if (hdlp->ih_private == NULL) { /* allocate phdl structure */
			free_phdl = 1;
			i_ddi_alloc_intr_phdl(hdlp);
		}
		((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp = ispec;
		if (PCIIDE_NATIVE_MODE(rdip)) {
			rdip = dip;
			dip = ddi_get_parent(dip);
		} else {	/* get ptr to the root node */
			dip = ddi_root_node();
		}
		ret = (*psm_intr_ops)(rdip, hdlp,
		    PSM_INTR_OP_ALLOC_VECTORS, result);
		if (free_phdl) { /* free up the phdl structure */
			free_phdl = 0;
			i_ddi_free_intr_phdl(hdlp);
		}
	} else {
		/*
		 * No APIX module; fall back to the old scheme where the
		 * interrupt vector is allocated during ddi_intr_enable() call.
		 */
		*(int *)result = hdlp->ih_scratch1;
		ret = DDI_SUCCESS;
	}

	return (ret);
}

int
pciide_free_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	struct intrspec			*ispec;
	ddi_intr_handle_impl_t		info_hdl;
	apic_get_type_t			type_info;

	if (psm_intr_ops == NULL)
		return (DDI_FAILURE);

	/*
	 * If the PSM module is "APIX" then pass the request for it
	 * to free up the vector now.
	 */
	bzero(&info_hdl, sizeof (ddi_intr_handle_impl_t));
	info_hdl.ih_private = &type_info;
	if ((*psm_intr_ops)(NULL, &info_hdl, PSM_INTR_OP_APIC_TYPE, NULL) ==
	    PSM_SUCCESS && strcmp(type_info.avgi_type, APIC_APIX_NAME) == 0) {
		if ((ispec = pciide_get_ispec(dip, rdip, hdlp->ih_inum)) ==
		    NULL)
			return (DDI_FAILURE);
		((ihdl_plat_t *)hdlp->ih_private)->ip_ispecp = ispec;
		if (PCIIDE_NATIVE_MODE(rdip)) {
			rdip = dip;
			dip = ddi_get_parent(dip);
		} else {	/* get ptr to the root node */
			dip = ddi_root_node();
		}
		return ((*psm_intr_ops)(rdip, hdlp,
		    PSM_INTR_OP_FREE_VECTORS, NULL));
	}

	/*
	 * No APIX module; fall back to the old scheme where
	 * the interrupt vector was already freed during
	 * ddi_intr_disable() call.
	 */
	return (DDI_SUCCESS);
}

/*
 * This is one of the places where controller specific setup needs to be
 * considered.
 * At this point the controller was already pre-qualified as a known and
 * supported pciide controller.
 * Some controllers do not provide PCI_MASS_IDE sub-class code and IDE
 * programming interface code but rather PCI_MASS_OTHER sub-class code
 * without any additional data.
 * For those controllers IDE programming interface cannot be extracted
 * from PCI class - we assume that they are pci-native type and we fix
 * the programming interface used by other functions.
 * The programming interface byte is set to indicate pci-native mode
 * for both controllers and the Bus Master DMA capabilitiy of the controller.
 */
static void
pciide_compat_setup(dev_info_t *mydip, dev_info_t *cdip, int dev)
{
	int	class_code;
	int	rc = DDI_PROP_SUCCESS;

	class_code = ddi_prop_get_int(DDI_DEV_T_ANY, mydip,
	    DDI_PROP_DONTPASS, "class-code", 0);

	if (((class_code & 0x00FF00) >> 8) == PCI_MASS_IDE) {
		/*
		 * Controller provides PCI_MASS_IDE sub-class code first
		 * (implied IDE programming interface)
		 */
		if ((dev == 0 && !(class_code & PCI_IDE_IF_NATIVE_PRI)) ||
		    (dev == 1 && !(class_code & PCI_IDE_IF_NATIVE_SEC))) {
			rc = ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
			    "compatibility-mode", 1);
			if (rc != DDI_PROP_SUCCESS)
				cmn_err(CE_WARN,
				    "pciide prop error %d compat-mode", rc);
		}
	} else {
		/*
		 * Pci-ide controllers not providing PCI_MASS_IDE sub-class are
		 * assumed to be of pci-native type and bus master DMA capable.
		 * Programming interface part of the class-code property is
		 * fixed here.
		 */
		class_code &= 0x00ffff00;
		class_code |= PCI_IDE_IF_BM_CAP_MASK |
		    PCI_IDE_IF_NATIVE_PRI | PCI_IDE_IF_NATIVE_SEC;
		rc = ddi_prop_update_int(DDI_DEV_T_NONE, mydip,
		    "class-code", class_code);
		if (rc != DDI_PROP_SUCCESS)
			cmn_err(CE_WARN,
			    "pciide prop error %d class-code", rc);
	}
}


static int
pciide_pre26_rnumber_map(dev_info_t *mydip, int rnumber)
{
	int	pri_native;
	int	sec_native;
	int	class_code;

	class_code = ddi_prop_get_int(DDI_DEV_T_ANY, mydip, DDI_PROP_DONTPASS,
	    "class-code", 0);

	pri_native = (class_code & PCI_IDE_IF_NATIVE_PRI) ? TRUE : FALSE;
	sec_native = (class_code & PCI_IDE_IF_NATIVE_SEC) ? TRUE : FALSE;

	return (pciide_map_rnumber(rnumber, pri_native, sec_native));

}

/*
 *	The canonical order of the reg property tuples for the
 *	Base Address Registers is supposed to be:
 *
 *	primary controller (BAR 0)
 *	primary controller (BAR 1)
 *	secondary controller (BAR 2)
 *	secondary controller (BAR 3)
 *	bus mastering regs (BAR 4)
 *
 *	For 2.6, bootconf has been fixed to always generate the
 *	reg property (and assigned-addresses property) tuples
 *	in the above order.
 *
 *	But in releases prior to 2.6 the order varies depending
 *	on whether compatibility or native mode is being used for
 *	each controller. There ends up being four possible
 *	orders:
 *
 *	BM, P0, P1, S0, S1	primary compatible, secondary compatible
 *	S0, S1, BM, P0, P1	primary compatible, secondary native
 *	P0, P1, BM, S0, S1	primary native, secondary compatible
 *	P0, P1, S0, S1, BM	primary native, secondary native
 *
 *	where: Px is the primary tuples, Sx the secondary tuples, and
 *	B the Bus Master tuple.
 *
 *	Here's the results for each of the four states:
 *
 *		0, 1, 2, 3, 4
 *
 *	CC	1, 2, 3, 4, 0
 *	CN	3, 4, 0, 1, 2
 *	NC	0, 1, 3, 4, 2
 *	NN	0, 1, 2, 3, 4
 *
 *	C = compatible(!native) == 0
 *	N = native == 1
 *
 *	Here's the transformation matrix:
 */

static	int	pciide_transform[2][2][5] = {
/*  P  S  */
/* [C][C] */	+1, +1, +1, +1, -4,
/* [C][N] */	+3, +3, -2, -2, -2,
/* [N][C] */	+0, +0, +1, +1, -2,
/* [N][N] */	+0, +0, +0, +0, +0
};


static int
pciide_map_rnumber(int rnumber, int pri_native, int sec_native)
{
	/* transform flags into indexes */
	pri_native = pri_native ? 1 : 0;
	sec_native = sec_native ? 1 : 0;

	rnumber += pciide_transform[pri_native][sec_native][rnumber];
	return (rnumber);
}
