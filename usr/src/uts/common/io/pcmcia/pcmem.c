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


/*
 *  PCMCIA Memory Nexus Driver
 *
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/conf.h>

/*
 * PCMCIA and DDI related header files
 */
#include <sys/pccard.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunndi.h>

#ifdef DEBUG
int  pcmem_debug = 0;
#define	PCMEM_DEBUG(args)  if (pcmem_debug) cmn_err args
#else
#define	PCMEM_DEBUG(args)
#endif

/*
 * Device Operations (dev_ops) Structure
 */
static int pcmem_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pcmem_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 *      bus nexus operations.
 */

static int
pcmem_ctlops(dev_info_t *d, dev_info_t *r, ddi_ctl_enum_t o,
	void *a, void *v);


static struct bus_ops pcmem__bus_ops = {
#if defined(BUSO_REV) && BUSO_REV >= 2
	BUSO_REV,		/* XXX */
	nullbusmap,
	0,			/* ddi_intrspec_t (*bus_get_intrspec)(); */
	0,			/* int (*bus_add_intrspec)(); */
	0,			/* void  (*bus_remove_intrspec)(); */
	i_ddi_map_fault,
	ddi_no_dma_map,
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,
	ddi_no_dma_bindhdl,
	ddi_no_dma_unbindhdl,
	ddi_no_dma_flush,
	ddi_no_dma_win,
	ddi_no_dma_mctl,
	pcmem_ctlops,		/* ddi_ctlops   */
	ddi_bus_prop_op
#else
	nullbusmap,
	0,			/* ddi_intrspec_t (*bus_get_intrspec)(); */
	0,			/* int (*bus_add_intrspec)(); */
	0,			/* void  (*bus_remove_intrspec)(); */
	i_ddi_map_fault,
	ddi_no_dma_map,
	ddi_no_dma_mctl,
	pcmem_ctlops,		/* ddi_ctlops   */
	ddi_bus_prop_op
#endif
};



static struct dev_ops pcmem_ops = {
	DEVO_REV,		/* devo_rev	*/
	0,			/* refcnt	*/
	ddi_no_info,		/* info		*/
	nulldev,		/* identify	*/
	nulldev,		/* probe	*/
	pcmem_attach,		/* attach	*/
	pcmem_detach,		/* detach	*/
	nulldev,		/* reset (currently not supported) */
	(struct cb_ops *)NULL,	/* cb_ops pointer for leaf driver */
	&pcmem__bus_ops,	/* bus_ops pointer for nexus driver */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};



/*
 * Module linkage information for the kernel
 */
extern struct mod_ops mod_driverops;

static struct modldrv md = {
	&mod_driverops,			/* Type of module */
	"PCMCIA Memory Nexus",		/* Name of the module */
	&pcmem_ops,			/* Device Operation Structure */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&md,
	NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}



/*
 * pcmem_attach()
 *
 */
static int
pcmem_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	char		adapter [MODMAXNAMELEN+1];
	static void	pcmem_create_pcram_node(dev_info_t *);

	/* resume from a checkpoint */
	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	}

	(void) pcmem_create_pcram_node(dip);

	(void) strcpy(adapter, "pcram");
	(void) modload("drv", adapter);

	ddi_report_dev(dip);

	PCMEM_DEBUG((CE_CONT, "pcmem_attach - exit\n"));

	return (DDI_SUCCESS);
}


/* ARGSUSED */
static int
pcmem_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{

	/* suspend */
	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	}

	if (cmd != DDI_DETACH) {
		cmn_err(CE_NOTE, "pcmem_detach: cmd != DDI_DETACH\n");
		return (DDI_FAILURE);
	}

	PCMEM_DEBUG((CE_CONT, "pcmem_detach - exit\n"));

	/* Do not need to do ddi_prop_remove_all */
	return (DDI_SUCCESS);
}


/*ARGSUSED*/
static int
pcmem_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{

	char    name[MAXNAMELEN];
	int	techreg, cissp;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0) {
			return (DDI_FAILURE);
		}
		PCMEM_DEBUG((CE_CONT,
		    "?pcmem_ctlops: %s%d at %s in socket %d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip),
		    ddi_get_name(dip),
		    ddi_getprop(DDI_DEV_T_NONE, rdip,
		    DDI_PROP_DONTPASS, "socket", -1)));

		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:

		PCMEM_DEBUG((CE_CONT,
		    "pcmem_ctlops - DDI_CTLOPS_INITCHILD persistent=%x\n",
		    ndi_dev_is_persistent_node((dev_info_t *)arg)));

		if (!ndi_dev_is_persistent_node((dev_info_t *)arg))
			return (DDI_FAILURE);
		/*
		 * XXXX - Read card CIS to determine technology
		 *	region(tn) and CIS space(dn).
		 *	Refer to Bugid 1179336.
		 */

		/*
		 * see cis_handler.h for CISTPL_DEVICE
		 *	and CISTPL_DEVICE_A
		 *
		 * CISTPL_DEVICE_DTYPE_NULL	0x00	NULL device
		 * CISTPL_DEVICE_DTYPE_ROM	0x01	ROM
		 * CISTPL_DEVICE_DTYPE_OTPROM	0x02	OTPROM
		 * CISTPL_DEVICE_DTYPE_EPROM	0x03    EPROM
		 * CISTPL_DEVICE_DTYPE_EEPROM	0x04	EEPROM
		 * CISTPL_DEVICE_DTYPE_FLASH	0x05	FLASH
		 * CISTPL_DEVICE_DTYPE_SRAM	0x06	SRAM
		 * CISTPL_DEVICE_DTYPE_DRAM	0x07	DRAM
		 *
		 */
		/*
		 * XXXX - For now set to default SRAM device
		 */
		techreg = CISTPL_DEVICE_DTYPE_SRAM;
		cissp = 0;
		(void) sprintf(name, "%d,%d", techreg, cissp);
		ddi_set_name_addr((dev_info_t *)arg, name);

		PCMEM_DEBUG((CE_CONT,
		    "pcmem_ctlops - DDI_CTLOPS_INITCHILD name=%s\n", name));

		return (DDI_SUCCESS);

	case DDI_CTLOPS_UNINITCHILD:
		ddi_set_name_addr((dev_info_t *)arg, NULL);

		PCMEM_DEBUG((CE_CONT,
		    "pcmem_ctlops - DDI_CTLOPS_UNINITCHILD child: %s(%d)\n",
		    ddi_node_name(arg), ddi_get_instance(arg)));

		return (DDI_SUCCESS);

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

/*
 *     Create the pcram node with this routine instead of letting the framework
 *     create the node from the pcram.conf file. The pcram.conf file is no
 *     longer required and should be removed.
 */

static void
pcmem_create_pcram_node(dev_info_t *dip)
{
	dev_info_t	*child = NULL;

	PCMEM_DEBUG((CE_CONT,
	    "pcmem_create_pcram_node dip=%p\n", (void *)dip));

	if (ndi_devi_alloc(dip, "pcram", (pnode_t)DEVI_SID_NODEID, &child) !=
	    NDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "pcmem: unable to create node [%s]\n", "pcram");
		return;
	}

	if (ndi_devi_online(child, 0) == NDI_FAILURE) {
		cmn_err(CE_WARN,
		    "pcmem: ndi_devi_online failure\n");
		(void) ndi_devi_free(child);
		return;
	}
}
