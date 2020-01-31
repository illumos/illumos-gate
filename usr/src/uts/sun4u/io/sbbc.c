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
 * Starcat PCI SBBC Nexus Driver.
 *
 * This source code's compiled binary runs on both a Starcat System
 * Controller (SSC) and a Starcat Domain.  One of the SBBC hardware
 * registers is read during attach(9e) in order to determine which
 * environment the driver is executing on.
 *
 * On both the SSC and the Domain, this driver provides nexus driver
 * services to its Device Tree children.  Note that the children in
 * each environment are not necessarily the same.
 *
 * This driver allows one concurrent open(2) of its associated device
 * (/dev/sbbc0).  The client uses the file descriptor to issue
 * ioctl(2)'s in order to read and write from the 2MB (PCI) space
 * reserved for "SBBC Internal Registers".  Among other things,
 * these registers consist of command/control/status registers for
 * devices such as Console Bus, I2C, EPLD, IOSRAM, and JTAG.  The 2MB
 * space is very sparse; EINVAL is returned if a reserved or unaligned
 * address is specified in the ioctl(2).
 *
 * Note that the 2MB region reserved for SBBC Internal Registers is
 * a subset of the 128MB of PCI address space addressable by the SBBC
 * ASIC.  Address space outside of the 2MB (such as the 64MB reserved
 * for the Console Bus) is not accessible via this driver.
 *
 * Also, note that the SBBC Internal Registers are only read and
 * written by the SSC; no process on the Domain accesses these
 * registers.  As a result, the registers are unmapped (when running
 * on the Domain) near the end of attach(9e) processing.  This conserves
 * kernel virtual address space resources (as one instance of the driver
 * is created for each Domain-side IO assembly).  (To be complete, only
 * one instance of the driver is created on the SSC).
 */

#include <sys/types.h>

#include <sys/conf.h>		/* req. by dev_ops flags MTSAFE etc. */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/pci.h>
#include <sys/pci/pci_nexus.h>
#include <sys/autoconf.h>
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/modctl.h>
#include <sys/stat.h>


#include <sys/sbbcreg.h>	/* hw description */
#include <sys/sbbcvar.h>	/* driver description */
#include <sys/sbbcio.h>		/* ioctl description */

#define	getprop(dip, name, addr, intp)		\
		ddi_getlongprop(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS, \
				(name), (caddr_t)(addr), (intp))

/* driver entry point fn definitions */
static int sbbc_open(dev_t *, int, int, cred_t *);
static int sbbc_close(dev_t, int, int, cred_t *);
static int sbbc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/* configuration entry point fn definitions */
static int sbbc_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sbbc_attach(dev_info_t *, ddi_attach_cmd_t);
static int sbbc_detach(dev_info_t *, ddi_detach_cmd_t);

/* local utility routines */
/*
 * NOTE - sbbc_offset_valid contains detailed address information taken from
 * the Serengeti Architecture Programmer's Reference Manual.  If any
 * changes are made to the SBBC registers, this routine may need to be
 * updated.
 */
static int sbbc_offset_valid(uint32_t offset);

/*
 * function prototypes for bus ops routines:
 */
static int sbbc_busmap(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *addrp);
static int sbbc_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result);

static int sbbc_intr_ops(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);
static int sbbc_add_intr_impl(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);
static int sbbc_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);
static int sbbc_update_intr_state(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);

static int sbbc_apply_range(struct sbbcsoft *sbbc_p, dev_info_t *rdip,
    sbbc_child_regspec_t *child_rp, pci_regspec_t *rp);

static int sbbc_init(struct sbbcsoft *);

static uint_t sbbc_intr_wrapper(caddr_t arg);

static int sbbc_get_ranges(struct sbbcsoft *);
static int sbbc_config4pci(struct sbbcsoft *);
static int sbbc_initchild(dev_info_t *, dev_info_t *, dev_info_t *);
static int sbbc_uninitchild(dev_info_t *, dev_info_t *);
static void sbbc_remove_reg_maps(struct sbbcsoft *);

/* debugging functions */
#ifdef DEBUG
uint32_t sbbc_dbg_flags = 0x0;
static void sbbc_dbg(uint32_t flag, dev_info_t *dip, char *fmt,
	uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5);
static void sbbc_dump_devid(dev_info_t *, struct sbbcsoft *, int instance);
#endif

/*
 * For tracing, allocate space for the trace buffer
 */
#if defined(SBBC_TRACE)
struct sbbctrace sbbctrace_buffer[NSBBCTRACE+1];
struct sbbctrace *sbbctrace_ptr;
int sbbctrace_count;
#endif

/*
 * Local declarations and variables
 */

static void *sbbcsoft_statep;

/* Determines whether driver is executing on System Controller or Domain */
int sbbc_scmode = FALSE;

/*
 * ops stuff.
 */
static struct bus_ops sbbc_bus_ops = {
	BUSO_REV,
	sbbc_busmap,
	0,
	0,
	0,
	NULL,			/* (*bus_map_fault)() */
	ddi_no_dma_map,
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,	/* (*bus_dma_freehdl)() */
	ddi_no_dma_bindhdl,	/* (*bus_dma_bindhdl)() */
	ddi_no_dma_unbindhdl,	/* (*bus_dma_unbindhdl)() */
	ddi_no_dma_flush,	/* (*bus_dma_flush)() */
	ddi_no_dma_win,		/* (*bus_dma_win)() */
	ddi_no_dma_mctl,	/* (*bus_dma_ctl)() */
	sbbc_ctlops,
	ddi_bus_prop_op,
	0,			/* (*bus_get_eventcookie)();	*/
	0,			/* (*bus_add_eventcall)();	*/
	0,			/* (*bus_remove_eventcall)();	*/
	0,			/* (*bus_post_event)();		*/
	0,			/* (*bus_intr_ctl)();	*/
	0,			/* (*bus_config)();	*/
	0,			/* (*bus_unconfig)();	*/
	0,			/* (*bus_fm_init)();	*/
	0,			/* (*bus_fm_fini)();	*/
	0,			/* (*bus_fm_access_enter)();	*/
	0,			/* (*bus_fm_access_exit)();	*/
	0,			/* (*bus_power)();	*/
	sbbc_intr_ops		/* (*bus_intr_op)();	*/
};

/*
 * cb_ops
 */
static struct cb_ops sbbc_cb_ops = {
	sbbc_open,		/* cb_open */
	sbbc_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	sbbc_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	(int)(D_NEW | D_MP)	/* cb_flag */
};

/*
 * Declare ops vectors for auto configuration.
 */
struct dev_ops  sbbc_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	sbbc_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	sbbc_attach,		/* devo_attach */
	sbbc_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&sbbc_cb_ops,		/* devo_cb_ops */
	&sbbc_bus_ops,		/* devo_bus_ops */
	nulldev,			/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Loadable module support.
 */
extern struct mod_ops mod_driverops;

static struct modldrv sbbcmodldrv = {
	&mod_driverops,		/* type of module - driver */
	"PCI Sbbc Nexus Driver",
	&sbbc_ops,
};

static struct modlinkage sbbcmodlinkage = {
	MODREV_1,
	&sbbcmodldrv,
	NULL
};

int
_init(void)
{
	int    error;

	if ((error = ddi_soft_state_init(&sbbcsoft_statep,
	    sizeof (struct sbbcsoft), 1)) != 0)
		return (error);
	if ((error = mod_install(&sbbcmodlinkage)) != 0)
		ddi_soft_state_fini(&sbbcsoft_statep);

	return (error);
}

int
_fini(void)
{
	int    error;

	if ((error = mod_remove(&sbbcmodlinkage)) == 0)
		ddi_soft_state_fini(&sbbcsoft_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&sbbcmodlinkage, modinfop));
}

static int
sbbc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	instance;
	char	name[32];
	struct	sbbcsoft *sbbcsoftp;
	struct ddi_device_acc_attr attr;
	uint32_t sbbc_id_reg;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	/* initialize tracing */
	SBBCTRACEINIT();

	SBBC_DBG0(SBBC_DBG_ATTACH, dip, "Attaching\n");

	instance = ddi_get_instance(dip);
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		if (!(sbbcsoftp =
		    ddi_get_soft_state(sbbcsoft_statep, instance))) {
			cmn_err(CE_WARN, "sbbc_attach:resume: unable "
			    "to acquire sbbcsoftp for instance %d",
			    instance);
			return (DDI_FAILURE);
		}
		mutex_enter(&sbbcsoftp->umutex);
		if (!sbbcsoftp->suspended) {
			mutex_exit(&sbbcsoftp->umutex);
			return (DDI_FAILURE);
		}
		sbbcsoftp->suspended = 0;
		mutex_exit(&sbbcsoftp->umutex);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(sbbcsoft_statep, instance) != 0) {
		cmn_err(CE_WARN, "sbbc_attach: Unable to allocate statep "
		    "for instance %d", instance);
		return (DDI_FAILURE);
	}

	sbbcsoftp = ddi_get_soft_state(sbbcsoft_statep, instance);

	if (sbbcsoftp == NULL) {
		cmn_err(CE_WARN, "sbbc_attach: Unable to acquire "
		    "sbbcsoftp for instance %d", instance);
		ddi_soft_state_free(sbbcsoft_statep, instance);
		return (DDI_FAILURE);
	}

	sbbcsoftp->instance = instance;
	sbbcsoftp->dip = dip;
	sbbcsoftp->oflag = FALSE;

	/*
	 * Read our ranges property from OBP to map children space.
	 * And setup the internal structure for a later use when
	 * a child gets initialized.
	 */
	if (sbbc_get_ranges(sbbcsoftp)) {
		cmn_err(CE_WARN, "sbbc_attach: Unable to read sbbc "
		    "ranges from OBP %d", instance);
		ddi_soft_state_free(sbbcsoft_statep, instance);
		return (DDI_FAILURE);
	}

	if (sbbc_config4pci(sbbcsoftp)) {
		cmn_err(CE_WARN, "sbbc_attach: Unable to configure "
		    "sbbc on PCI %d", instance);
		kmem_free(sbbcsoftp->rangep, sbbcsoftp->range_len);
		ddi_soft_state_free(sbbcsoft_statep, instance);
		return (DDI_FAILURE);
	}

	mutex_init(&sbbcsoftp->umutex, NULL, MUTEX_DRIVER, (void *)NULL);
	mutex_init(&sbbcsoftp->sbbc_intr_mutex, NULL,
	    MUTEX_DRIVER, (void *)NULL);

	/* Map SBBC's Internal Registers */
	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&sbbcsoftp->pci_sbbc_map,
	    offsetof(struct pci_sbbc, sbbc_internal_regs),
	    sizeof (struct sbbc_regs_map), &attr,
	    &sbbcsoftp->pci_sbbc_map_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "(%d):sbbc_attach failed to map sbbc_reg",
		    instance);
		goto failed;
	}

	SBBC_DBG1(SBBC_DBG_ATTACH, dip, "Mapped sbbc at %lx\n",
	    sbbcsoftp->pci_sbbc_map);
#ifdef DEBUG
	sbbc_dump_devid(dip, sbbcsoftp, instance);
#endif
	/*
	 * Read a hardware register to determine if we are executing on
	 * a Starcat System Controller or a Starcat Domain.
	 */
	sbbc_id_reg = ddi_get32(sbbcsoftp->pci_sbbc_map_handle,
	    &sbbcsoftp->pci_sbbc_map->device_conf);

	if (sbbc_id_reg & SBBC_SC_MODE) {
		sbbc_scmode = TRUE;
		SBBC_DBG1(SBBC_DBG_ATTACH, dip, "SBBC(%d) nexus running "
		    "in System Controller Mode.\n", instance);

		/* initialize SBBC ASIC */
		if (!sbbc_init(sbbcsoftp)) {
			goto failed;
		}
	} else {
		sbbc_scmode = FALSE;
		SBBC_DBG1(SBBC_DBG_ATTACH, dip, "SBBC(%d) nexus "
		    "running in Domain Mode.\n", instance);

		/* initialize SBBC ASIC before we unmap registers */
		if (!sbbc_init(sbbcsoftp)) {
			goto failed;
		}

		/*
		 * Access to SBBC registers is no longer needed.  Unmap
		 * the registers to conserve kernel virtual address space.
		 */
		SBBC_DBG1(SBBC_DBG_ATTACH, dip, "SBBC(%d): unmap "
		    "SBBC registers\n", instance);
		sbbc_remove_reg_maps(sbbcsoftp);
		sbbcsoftp->pci_sbbc_map = NULL;
	}

	(void) sprintf(name, "sbbc%d", instance);

	if (ddi_create_minor_node(dip, name, S_IFCHR, instance, NULL,
	    0) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		goto failed;
	}

	ddi_report_dev(dip);

	SBBC_DBG0(SBBC_DBG_ATTACH, dip, "Attached successfully\n");

	return (DDI_SUCCESS);

failed:
	mutex_destroy(&sbbcsoftp->sbbc_intr_mutex);
	mutex_destroy(&sbbcsoftp->umutex);

	sbbc_remove_reg_maps(sbbcsoftp);
	kmem_free(sbbcsoftp->rangep, sbbcsoftp->range_len);
	ddi_soft_state_free(sbbcsoft_statep, instance);

	SBBC_DBG0(SBBC_DBG_ATTACH, dip, "Attach failed\n");

	return (DDI_FAILURE);
}

static int
sbbc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	struct sbbcsoft *sbbcsoftp;

	SBBCTRACE(sbbc_detach, 'DETA', dip);

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		if (!(sbbcsoftp =
		    ddi_get_soft_state(sbbcsoft_statep, instance))) {
			cmn_err(CE_WARN,
			    "sbbc_detach: unable to get softstate %p",
			    (void *)sbbcsoftp);
			return (DDI_FAILURE);
		}
		mutex_enter(&sbbcsoftp->umutex);
		if (sbbcsoftp->suspended) {
			mutex_exit(&sbbcsoftp->umutex);
			return (DDI_FAILURE);
		}
		sbbcsoftp->suspended = 1;
		mutex_exit(&sbbcsoftp->umutex);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (!(sbbcsoftp = ddi_get_soft_state(sbbcsoft_statep, instance))) {
		cmn_err(CE_WARN, "sbbc_detach: unable to get softstate %p",
		    (void *)sbbcsoftp);
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(dip, NULL);

	mutex_destroy(&sbbcsoftp->sbbc_intr_mutex);
	mutex_destroy(&sbbcsoftp->umutex);

	sbbc_remove_reg_maps(sbbcsoftp);
	kmem_free(sbbcsoftp->rangep, sbbcsoftp->range_len);

	ddi_soft_state_free(sbbcsoft_statep, instance);

	return (DDI_SUCCESS);

}


/*
 * Translate child's address into parents.
 */
static int
sbbc_busmap(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t off, off_t len, caddr_t *addrp)
{
	struct sbbcsoft *sbbcsoftp;
	sbbc_child_regspec_t *child_rp, *child_regs;
	pci_regspec_t pci_reg;
	ddi_map_req_t p_map_request;
	int rnumber, i, n;
	int rval = DDI_SUCCESS;
	int instance;

	SBBC_DBG4(SBBC_DBG_BUSMAP, dip,
	    "mapping child %s, type %llx, off %llx, len %llx\n",
	    ddi_driver_name(rdip), mp->map_type, off, len);

	SBBCTRACE(sbbc_busmap, 'BMAP', mp);

	/*
	 * Handle the mapping according to its type.
	 */
	instance = ddi_get_instance(dip);
	if (!(sbbcsoftp = ddi_get_soft_state(sbbcsoft_statep, instance)))
		return (DDI_FAILURE);

	switch (mp->map_type) {
	case DDI_MT_REGSPEC:

		/*
		 * We assume the register specification is in sbbc format.
		 * We must convert it into a PCI format regspec and pass
		 * the request to our parent.
		 */
		child_rp = (sbbc_child_regspec_t *)mp->map_obj.rp;
		break;

	case DDI_MT_RNUMBER:

		/*
		 * map_type 0
		 * Get the "reg" property from the device node and convert
		 * it to our parent's format.
		 */
		rnumber = mp->map_obj.rnumber;

		/* get the requester's reg property */
		if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&child_regs, &i) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "SBBC: couldn't get %s ranges property %d",
			    ddi_get_name(sbbcsoftp->dip), instance);
			return (DDI_ME_RNUMBER_RANGE);
		}
		n = i / sizeof (sbbc_child_regspec_t);

		if (rnumber < 0 || rnumber >= n) {
			kmem_free(child_regs, i);
			return (DDI_ME_RNUMBER_RANGE);
		}
		child_rp = &child_regs[rnumber];
		break;

	default:
		return (DDI_ME_INVAL);

	}

	/* Adjust our reg property with offset and length */
	child_rp->addr_low += off;

	if (len)
		child_rp->size = len;

	/*
	 * Combine this reg prop. into our parents PCI address using the ranges
	 * property.
	 */
	rval = sbbc_apply_range(sbbcsoftp, rdip, child_rp, &pci_reg);

	if (mp->map_type == DDI_MT_RNUMBER)
		kmem_free(child_regs, i);

	if (rval != DDI_SUCCESS)
		return (rval);

	p_map_request = *mp;
	p_map_request.map_type = DDI_MT_REGSPEC;
	p_map_request.map_obj.rp = (struct regspec *)&pci_reg;

	/* Send it to PCI nexus to map into the PCI space */
	rval = ddi_map(dip, &p_map_request, 0, 0, addrp);

	return (rval);

}


/* new intr_ops structure */
static int
sbbc_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	int	ret = DDI_SUCCESS;

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		*(int *)result = DDI_INTR_FLAG_LEVEL;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		if (hdlp->ih_pri == 0) {
			hdlp->ih_pri = 0x1;

			cmn_err(CE_WARN, "%s%d assigning default interrupt "
			    "level %d for device %s%d", ddi_driver_name(dip),
			    ddi_get_instance(dip), hdlp->ih_pri,
			    ddi_driver_name(rdip), ddi_get_instance(rdip));
		}

		*(int *)result = hdlp->ih_pri;

		break;
	case DDI_INTROP_ADDISR:
		ret = sbbc_add_intr_impl(dip, rdip, intr_op, hdlp, result);
		break;
	case DDI_INTROP_REMISR:
		ret = sbbc_remove_intr_impl(dip, rdip, intr_op, hdlp, result);
		break;
	case DDI_INTROP_ENABLE:
		ret = sbbc_update_intr_state(dip, rdip, intr_op, hdlp, &result);
		break;
	case DDI_INTROP_DISABLE:
		ret = sbbc_update_intr_state(dip, rdip, intr_op, hdlp, &result);
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
		break;
	case DDI_INTROP_SUPPORTED_TYPES:
		/* PCI nexus driver supports only fixed interrupts */
		*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
		    DDI_INTR_TYPE_FIXED : 0;
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}


static int
sbbc_add_intr_impl(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	sbbcsoft_t *sbbcsoftp;
	sbbc_child_intr_t *childintr;
	int instance, i, rval = DDI_SUCCESS;

	SBBC_DBG2(SBBC_DBG_INTR, dip,
	    "add: rdip 0x%llx hdlp 0x%llx\n", rdip, hdlp);

	/* insert the sbbc isr wrapper instead */
	instance = ddi_get_instance(dip);
	if (!(sbbcsoftp = ddi_get_soft_state(sbbcsoft_statep, instance)))
		return (DDI_FAILURE);

	childintr = kmem_zalloc(sizeof (struct sbbc_child_intr), KM_SLEEP);

	childintr->name = ddi_get_name(rdip);
	childintr->inum = hdlp->ih_inum;
	childintr->intr_handler = hdlp->ih_cb_func;
	childintr->arg1 = hdlp->ih_cb_arg1;
	childintr->arg2 = hdlp->ih_cb_arg2;
	childintr->status = SBBC_INTR_STATE_DISABLE;

	for (i = 0; i < MAX_SBBC_DEVICES; i++) {
		if (sbbcsoftp->child_intr[i] == NULL) {
			sbbcsoftp->child_intr[i] = childintr;
			break;
		}
	}

	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
	    (ddi_intr_handler_t *)sbbc_intr_wrapper,
	    (caddr_t)sbbcsoftp, NULL);

	if ((rval = i_ddi_intr_ops(dip, rdip, intr_op,
	    hdlp, result)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sbbc%d: failed to add intr for %s",
		    instance, ddi_get_name(rdip));
		kmem_free(childintr, sizeof (struct sbbc_child_intr));
		if (i < MAX_SBBC_DEVICES)
			sbbcsoftp->child_intr[i] = NULL;
	}

	/*
	 * Restore original interrupt handler
	 * and arguments in interrupt handle.
	 */
	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp, childintr->intr_handler,
	    childintr->arg1, childintr->arg2);

	return (rval);
}

static int
sbbc_remove_intr_impl(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	sbbcsoft_t *sbbcsoftp;
	sbbc_child_intr_t *childintr;
	int instance, i, rval = DDI_SUCCESS;

	SBBC_DBG2(SBBC_DBG_INTR, dip,
	    "remove: rdip 0x%llx hdlp 0x%llx\n", rdip, hdlp);

	instance = ddi_get_instance(dip);
	if (!(sbbcsoftp = ddi_get_soft_state(sbbcsoft_statep, instance)))
		return (DDI_FAILURE);

	/* remove the sbbc isr wrapper instead */
	for (i = 0; i < MAX_SBBC_DEVICES; i++) {
		if (sbbcsoftp->child_intr[i]) {
			childintr = sbbcsoftp->child_intr[i];
			if (childintr->status == SBBC_INTR_STATE_DISABLE &&
			    childintr->name == ddi_get_name(rdip)) {
				/* put back child's inum */
				hdlp->ih_inum = childintr->inum;
				break;
			}
		}
	}

	if (i >= MAX_SBBC_DEVICES) {
		cmn_err(CE_WARN, "sbbc%d:obound failed to remove intr for %s",
		    instance, ddi_get_name(rdip));
		return (DDI_FAILURE);
	}

	if ((rval = i_ddi_intr_ops(dip, rdip, intr_op,
	    hdlp, result)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sbbc%d: failed to remove intr for %s",
		    instance, ddi_get_name(rdip));
		return (rval);
	}

	kmem_free(childintr, sizeof (struct sbbc_child_intr));
	sbbcsoftp->child_intr[i] = NULL;

	return (rval);
}


static int
sbbc_update_intr_state(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	sbbcsoft_t		*sbbcsoftp;
	sbbc_child_intr_t	*childintr;
	int			instance, i;
	int			ret = DDI_SUCCESS;

	SBBC_DBG2(SBBC_DBG_INTR, dip, "sbbc_update_intr_state: "
	    "rdip 0x%llx hdlp 0x%llx state 0x%x\n", rdip, hdlp);

	instance = ddi_get_instance(dip);
	if (!(sbbcsoftp = ddi_get_soft_state(sbbcsoft_statep, instance)))
		return (DDI_FAILURE);

	for (i = 0; i < MAX_SBBC_DEVICES; i++) {
		if (sbbcsoftp->child_intr[i]) {
			childintr = sbbcsoftp->child_intr[i];
			if (childintr->name == ddi_get_name(rdip))
				break;
		}
	}

	if (i >= MAX_SBBC_DEVICES) {
		cmn_err(CE_WARN, "sbbc%d: failed to update intr state for %s",
		    instance, ddi_get_name(rdip));
		return (DDI_FAILURE);
	}

	if ((ret = i_ddi_intr_ops(dip, rdip, intr_op,
	    hdlp, result)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sbbc%d: failed to update intr state for %s",
		    instance, ddi_get_name(rdip));
		return (ret);
	}

	/* Update the interrupt state */
	childintr->status = (intr_op == DDI_INTROP_ENABLE) ?
	    SBBC_INTR_STATE_ENABLE : SBBC_INTR_STATE_DISABLE;

	return (ret);
}


/*
 * This entry point is called before a child's probe or attach is called.
 * The arg pointer points to child's dev_info_t structure.
 */
static int
sbbc_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op,
    void *arg, void *result)
{
	sbbc_child_regspec_t *child_rp;
	int i, n;

	SBBC_DBG3(SBBC_DBG_CTLOPS, dip,
	    "Initializing %s, arg %x, op %x\n",
	    ddi_driver_name(rdip), arg, op);

	SBBCTRACE(sbbc_ctlops, 'CTLO', arg);

	switch (op) {
	case DDI_CTLOPS_INITCHILD: {
		return (sbbc_initchild(dip, rdip, (dev_info_t *)arg));
	}

	case DDI_CTLOPS_UNINITCHILD: {
		return (sbbc_uninitchild(rdip, (dev_info_t *)arg));
	}

	case DDI_CTLOPS_REPORTDEV:

		cmn_err(CE_CONT, "?%s%d at %s%d: offset %s\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    ddi_get_name_addr(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:

		if (getprop(rdip, "reg", &child_rp, &i) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		n = i / sizeof (sbbc_child_regspec_t);
		if (*(int *)arg < 0 || *(int *)arg >= n) {
			kmem_free(child_rp, i);
			return (DDI_FAILURE);
		}
		*((off_t *)result) = child_rp[*(int *)arg].size;
		kmem_free(child_rp, i);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:

		if (getprop(rdip, "reg", &child_rp, &i) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		*((uint_t *)result) = i / sizeof (sbbc_child_regspec_t);
		kmem_free(child_rp, i);
		return (DDI_SUCCESS);
	}

	/*
	 * Now pass the request up to our parent.
	 */
	SBBC_DBG0(SBBC_DBG_CTLOPS, dip, "Calling ddi_ctlops\n");

	return (ddi_ctlops(dip, rdip, op, arg, result));
}


/*
 * The following routine uses ranges property, that was read earlier, and
 * takes child's reg property, and computes the complete address and size
 * for the PCI parent to map.
 */
static int
sbbc_apply_range(struct sbbcsoft *sbbc_p, dev_info_t *rdip,
    sbbc_child_regspec_t *child_rp, pci_regspec_t *rp)
{
	int b;
	int rval = DDI_SUCCESS;
	struct sbbc_pci_rangespec *rangep = sbbc_p->rangep;
	int nrange = sbbc_p->range_cnt;

	SBBC_DBG4(SBBC_DBG_MAPRANGES, rdip,
	    "Applying ranges for %s, rangep %llx, child_rp %llx, range %x\n",
	    ddi_driver_name(rdip), sbbc_p->rangep, child_rp, nrange);

	SBBCTRACE(sbbc_apply_range, 'APPL', sbbc_p);

	for (b = 0; b < nrange; ++b, ++rangep) {

		/* Make sure the correct range is being mapped */
		if (child_rp->addr_hi == rangep->sbbc_phys_hi)
			/* See if we fit in this range */
			if ((child_rp->addr_low >=
			    rangep->sbbc_phys_low) &&
			    ((child_rp->addr_low + child_rp->size - 1)
			    <= (rangep->sbbc_phys_low +
			    rangep->rng_size - 1))) {
				uint_t addr_offset = child_rp->addr_low -
				    rangep->sbbc_phys_low;
				/*
				 * Use the range entry to translate
				 * the SBBC physical address into the
				 * parents PCI space.
				 */
				rp->pci_phys_hi =
				    rangep->pci_phys_hi;
				rp->pci_phys_mid = rangep->pci_phys_mid;
				rp->pci_phys_low =
				    rangep->pci_phys_low + addr_offset;
				rp->pci_size_hi = 0;
				rp->pci_size_low =
				    min(child_rp->size, (rangep->rng_size -
				    addr_offset));

				break;
			}
	}

	if (b == nrange)  {
		cmn_err(CE_WARN, "out_of_range %s", ddi_get_name(rdip));
		return (DDI_ME_REGSPEC_RANGE);
	}

	return (rval);
}


/*
 * The following routine reads sbbc's ranges property from OBP and sets up
 * its soft structure with it.
 */
static int
sbbc_get_ranges(struct sbbcsoft *sbbcsoftp)
{
	struct sbbc_pci_rangespec *rangep;
	int range_len, nrange;

	if (ddi_getlongprop(DDI_DEV_T_ANY, sbbcsoftp->dip, DDI_PROP_DONTPASS,
	    "ranges", (caddr_t)&rangep, &range_len) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "SBBC: couldn't get %s ranges property %d",
		    ddi_get_name(sbbcsoftp->dip), sbbcsoftp->instance);
		return (DDI_ME_REGSPEC_RANGE);
	}

	nrange = range_len / sizeof (struct sbbc_pci_rangespec);

	if (!nrange) {
		kmem_free(rangep, range_len);
		return (DDI_FAILURE);
	}

	/* setup the soft structure with ranges info. */
	sbbcsoftp->rangep = rangep;
	sbbcsoftp->range_cnt = nrange;
	sbbcsoftp->range_len = range_len;

	return (DDI_SUCCESS);
}


/*
 * Configure the SBBC for PCI
 */
static int
sbbc_config4pci(struct sbbcsoft *sbbcsoftp)
{
	ddi_acc_handle_t conf_handle;
	uint16_t comm, vendid, devid, stat;
	uint8_t revid;

#ifdef DEBUG
	if (sbbc_dbg_flags & SBBC_DBG_PCICONF) {
		cmn_err(CE_CONT,
		    "sbbc_config4pci: sbbcsoftp %p\n", (void *)sbbcsoftp);
	}
#endif
	if (pci_config_setup(sbbcsoftp->dip, &conf_handle) != DDI_SUCCESS)
		return (1);

	vendid = pci_config_get16(conf_handle, PCI_CONF_VENID);
	devid = pci_config_get16(conf_handle, PCI_CONF_DEVID);
	comm = pci_config_get16(conf_handle, PCI_CONF_COMM);
	stat = pci_config_get16(conf_handle, PCI_CONF_STAT);
	revid = pci_config_get8(conf_handle, PCI_CONF_REVID);

#ifdef DEBUG
	if (sbbc_dbg_flags & SBBC_DBG_PCICONF) {
		cmn_err(CE_CONT,
		    "SBBC vendid %x, devid %x, comm %x, stat %x, revid %x\n",
		    vendid, devid, comm, stat, revid);
	}
#endif
	comm = (PCI_COMM_ME | PCI_COMM_MAE | PCI_COMM_SERR_ENABLE |
	    PCI_COMM_PARITY_DETECT);

	pci_config_put16(conf_handle, PCI_CONF_COMM, comm);

	comm = pci_config_get16(conf_handle, PCI_CONF_COMM);

#ifdef DEBUG
	if (sbbc_dbg_flags & SBBC_DBG_PCICONF) {
		cmn_err(CE_CONT, "comm %x\n", comm);
	}
#endif
	pci_config_teardown(&conf_handle);

	return (0);
}


/* ARGSUSED0 */
int
sbbc_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev = (dev_t)arg;
	struct sbbcsoft *sbbcsoftp;
	int	instance, ret;

	instance = getminor(dev);

	SBBCTRACE(sbbc_getinfo, 'GINF', instance);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			sbbcsoftp = (struct sbbcsoft *)
			    ddi_get_soft_state(sbbcsoft_statep, instance);
			if (sbbcsoftp == NULL) {
				*result = (void *) NULL;
				ret = DDI_FAILURE;
			} else {
				*result = sbbcsoftp->dip;
				ret = DDI_SUCCESS;
			}
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(uintptr_t)instance;
			ret = DDI_SUCCESS;
			break;
		default:
			ret = DDI_FAILURE;
			break;
	}

	return (ret);
}

/*ARGSUSED1*/
static int
sbbc_open(dev_t *dev, int flag, int otype, cred_t *credp)
{
	struct sbbcsoft *sbbcsoftp;
	int		instance;

	/* check privilege of caller process */
	if (drv_priv(credp)) {
		return (EPERM);
	}

	instance = getminor(*dev);
	if (instance < 0)
		return (ENXIO);
	sbbcsoftp = (struct sbbcsoft *)ddi_get_soft_state(sbbcsoft_statep,
	    instance);
	SBBCTRACE(sbbc_open, 'OPEN', sbbcsoftp);

	if (sbbcsoftp == NULL)
		return (ENXIO);

	mutex_enter(&sbbcsoftp->umutex);

	/* check for exclusive access */
	if ((sbbcsoftp->oflag == TRUE)) {
		mutex_exit(&sbbcsoftp->umutex);
		return (EBUSY);
	}
	sbbcsoftp->oflag = TRUE;

	mutex_exit(&sbbcsoftp->umutex);

	return (0);
}

/*ARGSUSED1*/
static int
sbbc_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	struct sbbcsoft *sbbcsoftp;
	int		instance;

	instance = getminor(dev);
	if (instance < 0)
		return (ENXIO);
	sbbcsoftp = (struct sbbcsoft *)ddi_get_soft_state(sbbcsoft_statep,
	    instance);
	/* wait till all output activity has ceased */

	mutex_enter(&sbbcsoftp->umutex);

	SBBCTRACE(sbbc_close, 'CLOS', sbbcsoftp);

	sbbcsoftp->oflag = FALSE;

	mutex_exit(&sbbcsoftp->umutex);

	return (0);
}

/*ARGSUSED2*/
static int
sbbc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	struct sbbcsoft *sbbcsoftp;

	SBBCTRACE(sbbc_ioctl, 'IOCT', arg);

	sbbcsoftp = ddi_get_soft_state(sbbcsoft_statep, getminor(dev));

	if (sbbcsoftp == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	case SBBC_SBBCREG_WR:
		{
		struct ssc_sbbc_regio sbbcregs;
		uint64_t offset;

		if (sbbc_scmode == FALSE) {
			/* then we're executing on Domain; Writes not allowed */
			return (EINVAL);
		}

		if (arg == (intptr_t)NULL) {
			return (ENXIO);
		}

		if (ddi_copyin((caddr_t)arg, (caddr_t)&sbbcregs,
				    sizeof (struct ssc_sbbc_regio), mode)) {
			cmn_err(CE_WARN, "sbbc_ioctl: copyin failed arg %p",
			    (void *)arg);
			return (EFAULT);
		}

		/*
		 * Bug #4287186: SBBC driver on cp1500 doesn't check length for
		 *		reads or writes
		 * Note that I've also added a check to make sure the offset is
		 * valid, since misaligned (i.e. not on 16-byte boundary)
		 * accesses or accesses to "Reserved" register offsets are
		 * treated as unmapped by the SBBC.
		 */
		if ((sbbcregs.len != 4) ||
		    !sbbc_offset_valid(sbbcregs.offset)) {
			return (EINVAL);
		}

		offset = (uint64_t)sbbcsoftp->pci_sbbc_map;
		offset += sbbcregs.offset;
		ddi_put32(sbbcsoftp->pci_sbbc_map_handle, (uint32_t *)offset,
		    sbbcregs.value);
		}
		break;
	case SBBC_SBBCREG_RD:
		{
		struct ssc_sbbc_regio sbbcregs;
		uint64_t offset;

		if (sbbc_scmode == FALSE) {
			/* then we're executing on Domain; Reads not allowed */
			return (EINVAL);
		}

		if (arg == (intptr_t)NULL) {
			return (ENXIO);
		}

		if (ddi_copyin((caddr_t)arg, (caddr_t)&sbbcregs,
				    sizeof (struct ssc_sbbc_regio), mode)) {
			cmn_err(CE_WARN, "sbbc_ioctl: copyin failed arg %p",
			    (void *)arg);
			return (EFAULT);
		}

		/*
		 * Bug #4287186: SBBC driver on cp1500 doesn't check length for
		 *		reads or writes
		 * Note that I've also added a check to make sure the offset is
		 * valid, since misaligned (i.e. not on 16-byte boundary)
		 * accesses or accesses to "Reserved" register offsets are
		 * treated as unmapped by the SBBC.
		 */
		if ((sbbcregs.len != 4) ||
		    !sbbc_offset_valid(sbbcregs.offset)) {
			return (EINVAL);
		}

		offset = (uint64_t)sbbcsoftp->pci_sbbc_map;
		offset += sbbcregs.offset;

		sbbcregs.value = ddi_get32(sbbcsoftp->pci_sbbc_map_handle,
		    (uint32_t *)offset);

		if (ddi_copyout((caddr_t)&sbbcregs.value,
		    &((struct ssc_sbbc_regio *)arg)->value,
		    sbbcregs.len, mode)) {
			cmn_err(CE_WARN, "sbbc_ioctl:copyout failed arg %p",
			    (void *)arg);
			return (EFAULT);
		}
		}
		break;
	default:
		cmn_err(CE_WARN, "sbbc_ioctl:Illegal command 0x%08x", cmd);
		return (ENOTTY);
	}

	return (DDI_SUCCESS);
}

static void
sbbc_remove_reg_maps(struct sbbcsoft *sbbcsoftp)
{
	SBBCTRACE(sbbc_remove_reg_maps, 'RMAP', sbbcsoftp);
	if (sbbcsoftp->pci_sbbc_map_handle)
		ddi_regs_map_free(&sbbcsoftp->pci_sbbc_map_handle);
}


static int
sbbc_init(struct sbbcsoft *sbbcsoftp)
{
	/* Mask all the interrupts until we are ready. */
	ddi_put32(sbbcsoftp->pci_sbbc_map_handle,
	    &sbbcsoftp->pci_sbbc_map->sys_intr_enable,
	    0x00000000);

	return (1);
}

/*
 * The following routine is a generic routine to initialize any child of
 * sbbc nexus driver information into parent private data structure.
 */
/* ARGSUSED0 */
static int
sbbc_initchild(dev_info_t *dip, dev_info_t *rdip, dev_info_t *child)
{
	sbbc_child_regspec_t *child_rp;
	int reglen, slot;
	char name[10];

	SBBC_DBG1(SBBC_DBG_INITCHILD, dip, "Initializing %s\n",
	    ddi_driver_name(rdip));

	/*
	 * Initialize a child
	 * Set the address portion of the node name based on the
	 * address/offset.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&child_rp, &reglen) != DDI_SUCCESS) {
		if (strcmp(ddi_node_name(child), "hotplug-controller") == 0) {
			slot = 1;
			(void) sprintf(name, "%x", slot);
			ddi_set_name_addr(child, name);
			return (DDI_SUCCESS);
		}
		return (DDI_FAILURE);
	}

	SBBC_DBG3(SBBC_DBG_INITCHILD, dip, "hi 0x%x, low 0x%x, size 0x%x\n",
	    child_rp->addr_hi, child_rp->addr_low, child_rp->size);

	(void) sprintf(name, "%x,%x", child_rp->addr_hi, child_rp->addr_low);

	/*
	 * set child's addresses from the reg property into parent private
	 * data structure.
	 */
	ddi_set_name_addr(child, name);
	kmem_free(child_rp, reglen);

	ddi_set_parent_data(child, NULL);

	return (DDI_SUCCESS);
}


/* ARGSUSED0 */
static int
sbbc_uninitchild(dev_info_t *rdip, dev_info_t *child)
{

	SBBC_DBG1(SBBC_DBG_UNINITCHILD, rdip, "Uninitializing %s\n",
	    ddi_driver_name(rdip));

	ddi_set_name_addr(child, NULL);
	ddi_remove_minor_node(child, NULL);
	impl_rem_dev_props(child);

	return (DDI_SUCCESS);

}


/*
 * The following routine is an interrupt service routine that is used
 * as a wrapper to all the children requiring interrupt services.
 */
static uint_t
sbbc_intr_wrapper(caddr_t arg)
{

	struct sbbcsoft *sbbcsoftp = (struct sbbcsoft *)arg;
	int i, rval;

	SBBC_DBG1(SBBC_DBG_INTR, sbbcsoftp->dip, "Isr arg 0x%llx\n", arg);

	mutex_enter(&sbbcsoftp->sbbc_intr_mutex);

	for (i = 0; i < MAX_SBBC_DEVICES; i++) {
		/*
		 * Check the interrupt status reg. to determine the cause.
		 */
		/*
		 * Check the error status reg. to determine the cause.
		 */
		if (sbbcsoftp->child_intr[i] &&
		    sbbcsoftp->child_intr[i]->status ==
		    SBBC_INTR_STATE_ENABLE) {
			/*
			 * Dispatch the children interrupt service routines and
			 * look for someone to claim.
			 */
			rval = sbbcsoftp->child_intr[i]->intr_handler(
			    sbbcsoftp->child_intr[i]->arg1,
			    sbbcsoftp->child_intr[i]->arg2);

			if (rval == DDI_INTR_CLAIMED) {
				mutex_exit(&sbbcsoftp->sbbc_intr_mutex);
				return (rval);
			}
		}
	}

	mutex_exit(&sbbcsoftp->sbbc_intr_mutex);

	/* for now do not claim since we know its not enabled */
	return (DDI_INTR_UNCLAIMED);
}


/*
 * This function checks an SBBC register offset to make sure that it is properly
 * aligned (i.e. on a 16-byte boundary) and that it corresponds to an accessible
 * register.  Since the SBBC treates accesses to unaligned or reserved addresses
 * as unmapped, failing to check for these would leave a loophole that could be
 * used to crash the system.
 */
static int
sbbc_offset_valid(uint32_t offset)
{
	/*
	 * Check for proper alignment first.
	 */
	if ((offset % 16) != 0) {
		return (0);
	}

	/*
	 * Now start checking for the various reserved ranges.
	 * While sticking a bunch of constants in the code (rather than
	 * #define'd values) is usually best avoided, it would probably
	 * do more harm than good here.  These values were taken from the
	 * Serengeti Architecture Programmer's Reference Manual dated
	 * August 10, 1999, pages 2-99 through 2-103.  While there are
	 * various "clever" ways this check could be performed that would
	 * be slightly more efficient, arranging the code in this fashion
	 * should maximize maintainability.
	 */
	if (((offset >= 0x001a0) && (offset <= 0x001ff)) ||
	    ((offset >= 0x002a0) && (offset <= 0x002ff)) ||
	    ((offset >= 0x00350) && (offset <= 0x003ff)) ||
	    ((offset >= 0x00500) && (offset <= 0x00fff)) ||
	    ((offset >= 0x01160) && (offset <= 0x011ff)) ||
	    ((offset >= 0x01210) && (offset <= 0x017ff)) ||
	    ((offset >= 0x01810) && (offset <= 0x01fff)) ||
	    ((offset >= 0x02030) && (offset <= 0x022ff)) ||
	    ((offset >= 0x02340) && (offset <= 0x03fff)) ||
	    ((offset >= 0x04030) && (offset <= 0x05fff)) ||
	    ((offset >= 0x060a0) && (offset <= 0x060ff)) ||
	    (offset == 0x06120) ||
	    ((offset >= 0x06190) && (offset <= 0x061ff)) ||
	    ((offset >= 0x06230) && (offset <= 0x062f0)) ||
	    (offset > 0x06320)) {
		return (0);
	}

	return (1);
}

#ifdef DEBUG
void
sbbc_dbg(uint32_t flag, dev_info_t *dip, char *fmt,
    uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	char *s = NULL;

	if (sbbc_dbg_flags && ((sbbc_dbg_flags & flag) == flag)) {
		switch (flag) {
		case SBBC_DBG_ATTACH:
			s = "attach";
			break;
		case SBBC_DBG_DETACH:
			s = "detach";
			break;
		case SBBC_DBG_CTLOPS:
			s = "ctlops";
			break;
		case SBBC_DBG_INITCHILD:
			s = "initchild";
			break;
		case SBBC_DBG_UNINITCHILD:
			s = "uninitchild";
			break;
		case SBBC_DBG_BUSMAP:
			s = "busmap";
			break;
		case SBBC_DBG_INTR:
			s = "intr";
			break;
		case SBBC_DBG_INTROPS:
			s = "intr_ops";
			break;
		case SBBC_DBG_PCICONF:
			s = "pciconfig";
			break;
		case SBBC_DBG_MAPRANGES:
			s = "mapranges";
			break;
		case SBBC_DBG_PROPERTIES:
			s = "properties";
			break;
		case SBBC_DBG_OPEN:
			s = "open";
			break;
		case SBBC_DBG_CLOSE:
			s = "close";
			break;
		case SBBC_DBG_IOCTL:
			s = "ioctl";
			break;
		default:
			s = "Unknown debug flag";
			break;
		}

		cmn_err(CE_CONT, "%s_%s(%d): ", ddi_driver_name(dip), s,
		    ddi_get_instance(dip));
		cmn_err(CE_CONT, fmt, a1, a2, a3, a4, a5);
	}
}

/*
 * Dump the SBBC chip's Device ID Register
 */
static void sbbc_dump_devid(dev_info_t *dip, struct sbbcsoft *sbbcsoftp,
	int instance)
{
	uint32_t sbbc_id_reg;
	uint16_t sbbc_id_reg_partid;
	uint16_t sbbc_id_reg_manfid;

	sbbc_id_reg = ddi_get32(sbbcsoftp->pci_sbbc_map_handle,
	    (uint32_t *)&sbbcsoftp->pci_sbbc_map->devid);

	sbbc_id_reg_partid = ((sbbc_id_reg << 4) >> 16);
	sbbc_id_reg_manfid = ((sbbc_id_reg << 20) >> 21);

	SBBC_DBG4(SBBC_DBG_ATTACH, dip,
	    "FOUND SBBC(%d) Version %x, Partid %x, Manfid %x\n",
	    instance, (sbbc_id_reg >> 28), sbbc_id_reg_partid,
	    sbbc_id_reg_manfid);
}

#endif /* DEBUG */
