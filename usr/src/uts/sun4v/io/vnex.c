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


#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/ddi_impldefs.h>
#include <sys/autoconf.h>
#include <sys/systm.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_subrdefs.h>
#include <sys/promif.h>
#include <sys/machsystm.h>
#include <sys/ddi_intr_impl.h>
#include <sys/hypervisor_api.h>
#include <sys/intr.h>
#include <sys/hsvc.h>

#define	SUN4V_REG_SPEC2CFG_HDL(x)	((x >> 32) & ~(0xfull << 28))

static kmutex_t vnex_id_lock;
/*
 * Vnex name  to pil map
 */
typedef struct vnex_regspec {
	uint64_t physaddr;
	uint64_t size;
} vnex_regspec_t;

struct vnex_pil_map {
	caddr_t	name;
	uint32_t pil;
};

/* vnex interrupt descriptor */
typedef struct vnex_id {
	dev_info_t *vid_dip;
	uint32_t vid_ino;
	uint64_t vid_ihdl;
	uint_t	(*vid_handler)();
	caddr_t	vid_arg1;
	caddr_t	vid_arg2;
	ddi_intr_handle_impl_t *vid_ddi_hdlp;
	uint64_t vid_cfg_hdl;
	struct vnex_id *vid_next;
} vnex_id_t;

/* vnex interrupt descriptor list */
static vnex_id_t *vnex_id_list;

hrtime_t vnex_pending_timeout = 2ull * NANOSEC; /* 2 seconds in nanoseconds */

/*
 * vnex interrupt descriptor list manipulation functions
 */

static vnex_id_t *vnex_locate_id(dev_info_t *dip, uint32_t ino);
static vnex_id_t *vnex_alloc_id(dev_info_t *dip, uint32_t ino,
	uint64_t dhdl);
static void vnex_add_id(vnex_id_t *vid_p);
static void vnex_rem_id(vnex_id_t *vid_p);
static void vnex_free_id(vnex_id_t *vid_p);

uint_t vnex_intr_wrapper(caddr_t arg);

static struct vnex_pil_map vnex_name_to_pil[] = {
	{"console", 	PIL_12},
	{"fma",		PIL_5},
	{"echo", 	PIL_3},
	{"loop", 	PIL_3},
	{"sunmc", 	PIL_3},
	{"sunvts", 	PIL_3},
	{"explorer", 	PIL_3},
	{"ncp", 	PIL_8},
	{"crypto", 	PIL_8}
};

#define	VNEX_MAX_DEVS	(sizeof (vnex_name_to_pil) /	\
			    sizeof (struct vnex_pil_map))

/*
 * Config information
 */
static int vnex_intr_ops(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);

static int
vnex_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *, void *);

static struct bus_ops vnex_bus_ops = {
	BUSO_REV,
	nullbusmap,
	NULL,	/* NO OP */
	NULL,	/* NO OP */
	NULL,	/* NO OP */
	i_ddi_map_fault,
	ddi_no_dma_map,
	ddi_no_dma_allochdl,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	vnex_ctl,
	ddi_bus_prop_op,
	NULL,	/* (*bus_get_eventcookie)();    */
	NULL,	/* (*bus_add_eventcall)();	*/
	NULL,	/* (*bus_remove_eventcall)();   */
	NULL,	/* (*bus_post_event)();		*/
	NULL,	/* (*bus_intr_ctl)();		*/
	NULL,	/* (*bus_config)();		*/
	NULL,	/* (*bus_unconfig)();		*/
	NULL,	/* (*bus_fm_init)();		*/
	NULL,	/* (*bus_fm_fini)();		*/
	NULL,	/* (*bus_fm_access_enter)();	*/
	NULL,	/* (*bus_fm_access_fini)();	*/
	NULL,	/* (*bus_power)();		*/
	vnex_intr_ops	/* (*bus_intr_op)();	*/
};

static int vnex_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int vnex_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops pseudo_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	vnex_attach,		/* attach */
	vnex_detach,		/* detach */
	nodev,			/* reset */
	(struct cb_ops *)0,	/* driver operations */
	&vnex_bus_ops,		/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"sun4v virtual-devices nexus driver",
	&pseudo_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	uint64_t mjrnum;
	uint64_t mnrnum;

	/*
	 * Check HV intr group api versioning.
	 * This driver uses the old interrupt routines which are supported
	 * in old firmware in the CORE API group and in newer firmware in
	 * the INTR API group.  Support for these calls will be dropped
	 * once the INTR API group major goes to 2.
	 */

	if ((hsvc_version(HSVC_GROUP_INTR, &mjrnum, &mnrnum) == 0) &&
	    (mjrnum > 1)) {
		cmn_err(CE_WARN, "niumx: unsupported intr api group: "
		    "maj:0x%lx, min:0x%lx", mjrnum, mnrnum);
		return (ENOTSUP);
	}

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

/*ARGSUSED*/
void
vnex_intr_dist(void *arg)
{
	vnex_id_t *vid_p;
	uint32_t cpuid;
	int	intr_state;
	hrtime_t start;

	mutex_enter(&vnex_id_lock);

	for (vid_p = vnex_id_list; vid_p != NULL;
	    vid_p = vid_p->vid_next) {
		/*
		 * Don't do anything for disabled interrupts.
		 * vnex_enable_intr takes care of redistributing interrupts.
		 */
		if ((hvio_intr_getvalid(vid_p->vid_ihdl,
		    &intr_state) == H_EOK) && (intr_state == HV_INTR_NOTVALID))
				continue;

		cpuid = intr_dist_cpuid();

		(void) hvio_intr_setvalid(vid_p->vid_ihdl, HV_INTR_NOTVALID);
		/*
		 * Make a best effort to wait for pending interrupts to finish.
		 * There is not much we can do if we timeout.
		 */
		start = gethrtime();
		while (!panicstr &&
		    (hvio_intr_getstate(vid_p->vid_ihdl, &intr_state) ==
		    H_EOK) && (intr_state == HV_INTR_DELIVERED_STATE)) {
			if (gethrtime() - start > vnex_pending_timeout) {
				cmn_err(CE_WARN, "vnex_intr_dist: %s%d "
				    "ino 0x%x pending: timedout\n",
				    ddi_driver_name(vid_p->vid_dip),
				    ddi_get_instance(vid_p->vid_dip),
				    vid_p->vid_ino);
				break;
			}
		}
		(void) hvio_intr_settarget(vid_p->vid_ihdl, cpuid);
		(void) hvio_intr_setvalid(vid_p->vid_ihdl, HV_INTR_VALID);
	}
	mutex_exit(&vnex_id_lock);
}

static int
vnex_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * Intitialize interrupt descriptor list
		 * and mutex.
		 */
		vnex_id_list = NULL;
		mutex_init(&vnex_id_lock, NULL, MUTEX_DRIVER, NULL);
		/*
		 * Add interrupt redistribution callback.
		 */
		intr_dist_add(vnex_intr_dist, dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
vnex_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
vnex_ctl(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	char	name[12];	/* enough for a decimal integer */
	int		reglen;
	uint32_t	*vnex_regspec;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?virtual-device: %s%d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;

		if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&vnex_regspec, &reglen) != DDI_SUCCESS)
			return (DDI_FAILURE);

		(void) sprintf(name, "%x", *vnex_regspec);
		ddi_set_name_addr(child, name);
		ddi_set_parent_data(child, NULL);
		kmem_free((caddr_t)vnex_regspec, reglen);
		return (DDI_SUCCESS);

	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		dev_info_t *child = (dev_info_t *)arg;

		ddi_set_name_addr(child, NULL);
		ddi_remove_minor_node(arg, NULL);
		return (DDI_SUCCESS);
	}

	/*
	 * These ops correspond to functions that "shouldn't" be called
	 * by a pseudo driver.  So we whinge when we're called.
	 */
	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_REGSIZE:
	{
		*((off_t *)result) = 0;
		return (DDI_SUCCESS);
	}
	case DDI_CTLOPS_NREGS:
	{
		dev_info_t *child = rdip;
		if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&vnex_regspec, &reglen) != DDI_SUCCESS)
			return (DDI_FAILURE);
		*((uint_t *)result) = reglen / sizeof (uint32_t);
		kmem_free((caddr_t)vnex_regspec, reglen);
		return (DDI_SUCCESS);
	}
	case DDI_CTLOPS_SIDDEV:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_IOMIN:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		cmn_err(CE_CONT, "%s%d: invalid op (%d) from %s%d\n",
		    ddi_get_name(dip), ddi_get_instance(dip),
		    ctlop, ddi_get_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);

	/*
	 * Everything else (e.g. PTOB/BTOP/BTOPR requests) we pass up
	 */
	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

static int
vnex_get_pil(dev_info_t *rdip)
{
	int i;
	caddr_t	name;

	name = ddi_node_name(rdip);
	for (i = 0; i < VNEX_MAX_DEVS; i++) {
		if (strcmp(vnex_name_to_pil[i].name,
		    name) == 0) {
			return (vnex_name_to_pil[i].pil);
		}
	}
	/*
	 * if not found pil is 0
	 */
	return (0);
}

static int
vnex_enable_intr(dev_info_t *rdip, ddi_intr_handle_impl_t *hdlp)
{
	vnex_id_t *vid_p;
	uint32_t cpuid;

	vid_p = vnex_locate_id(rdip, hdlp->ih_vector);

	ASSERT(vid_p != NULL);

	cpuid = intr_dist_cpuid();

	if ((hvio_intr_settarget(vid_p->vid_ihdl, cpuid)) != H_EOK) {
		return (DDI_FAILURE);
	}

	if (hvio_intr_setstate(vid_p->vid_ihdl, HV_INTR_IDLE_STATE) != H_EOK) {
		return (DDI_FAILURE);
	}

	if ((hvio_intr_setvalid(vid_p->vid_ihdl, HV_INTR_VALID)) != H_EOK) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
vnex_disable_intr(dev_info_t *rdip, ddi_intr_handle_impl_t *hdlp)
{
	vnex_id_t *vid_p;

	vid_p = vnex_locate_id(rdip, hdlp->ih_vector);

	ASSERT(vid_p != NULL);

	if (hvio_intr_setvalid(vid_p->vid_ihdl, HV_INTR_NOTVALID) != H_EOK) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
vnex_ino_to_inum(dev_info_t *dip, uint32_t ino)
{
	vnex_id_t		*vid_p;
	ddi_intr_handle_impl_t	*hdlp;

	if ((vid_p = vnex_locate_id(dip, ino)) == NULL)
		return (-1);
	else if ((hdlp = vid_p->vid_ddi_hdlp) == NULL)
		return (-1);
	else
		return (hdlp->ih_inum);
}

static int
vnex_add_intr(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_handle_impl_t *hdlp)
{
	int reglen, ret = DDI_SUCCESS;
	vnex_id_t	*vid_p;
	uint64_t cfg;
	uint32_t ino;
	uint64_t ihdl;
	vnex_regspec_t *reg_p;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (caddr_t)&reg_p,
	    &reglen) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * get the sun4v config handle for this device
	 */

	cfg = SUN4V_REG_SPEC2CFG_HDL(reg_p->physaddr);
	kmem_free(reg_p, reglen);
	ino = hdlp->ih_vector;

	/*
	 * call hv to get vihdl
	 */
	if (hvio_intr_devino_to_sysino(cfg, ino, &ihdl) != H_EOK)
		return (DDI_FAILURE);

	hdlp->ih_vector = ihdl;
	/*
	 * Allocate a interrupt descriptor (id) with the
	 * the interrupt handler and append it to
	 * the id list.
	 */

	vid_p = vnex_alloc_id(rdip, ino, cfg);
	vid_p->vid_ihdl = ihdl;
	vid_p->vid_handler =  hdlp->ih_cb_func;
	vid_p->vid_arg1 =  hdlp->ih_cb_arg1;
	vid_p->vid_arg2 =  hdlp->ih_cb_arg2;
	vid_p->vid_ddi_hdlp =  hdlp;

	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp,
	    (ddi_intr_handler_t *)vnex_intr_wrapper, (caddr_t)vid_p, NULL);

	if (hdlp->ih_pri == 0) {
		hdlp->ih_pri = vnex_get_pil(rdip);
	}

	ret = i_ddi_add_ivintr(hdlp);
	if (ret != DDI_SUCCESS) {
		return (ret);
	}

	DDI_INTR_ASSIGN_HDLR_N_ARGS(hdlp, vid_p->vid_handler,
	    vid_p->vid_arg1, vid_p->vid_arg2);

	return (ret);
}

static int
vnex_remove_intr(dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp)
{
	vnex_id_t *vid_p;
	uint32_t ino;
	int ret = DDI_SUCCESS;

	ino = hdlp->ih_vector;
	vid_p = vnex_locate_id(rdip, ino);

	hdlp->ih_vector = vid_p->vid_ihdl;
	i_ddi_rem_ivintr(hdlp);

	vnex_free_id(vid_p);

	return (ret);
}

static int
vnex_intr_ops(dev_info_t *dip, dev_info_t *rdip,
    ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result)
{
	int	ret = DDI_SUCCESS;

	switch (intr_op) {
		case DDI_INTROP_GETCAP:
			*(int *)result = DDI_INTR_FLAG_LEVEL;
			break;
		case DDI_INTROP_ALLOC:
			*(int *)result = hdlp->ih_scratch1;
			break;
		case DDI_INTROP_GETPRI:
			*(int *)result = hdlp->ih_pri ?
			    hdlp->ih_pri : vnex_get_pil(rdip);
			break;
		case DDI_INTROP_FREE:
			break;
		case DDI_INTROP_SETPRI:
			break;
		case DDI_INTROP_ADDISR:
			ret = vnex_add_intr(dip, rdip, hdlp);
			break;
		case DDI_INTROP_REMISR:
			ret = vnex_remove_intr(rdip, hdlp);
			break;
		case DDI_INTROP_ENABLE:
			ret = vnex_enable_intr(rdip, hdlp);
			break;
		case DDI_INTROP_DISABLE:
			ret = vnex_disable_intr(rdip, hdlp);
			break;
		case DDI_INTROP_NINTRS:
		case DDI_INTROP_NAVAIL:
			*(int *)result = i_ddi_get_intx_nintrs(rdip);
			break;
		case DDI_INTROP_SUPPORTED_TYPES:
			*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
			    DDI_INTR_TYPE_FIXED : 0;
			break;
		default:
			ret = DDI_ENOTSUP;
			break;
	}

	return (ret);
}

vnex_id_t *
vnex_alloc_id(dev_info_t *dip, uint32_t ino, uint64_t dhdl)
{
	vnex_id_t *vid_p = kmem_alloc(sizeof (vnex_id_t), KM_SLEEP);

	vid_p->vid_dip = dip;
	vid_p->vid_ino = ino;
	vid_p->vid_cfg_hdl = dhdl;

	mutex_enter(&vnex_id_lock);
	vnex_add_id(vid_p);
	mutex_exit(&vnex_id_lock);

	return (vid_p);
}

vnex_id_t *
vnex_locate_id(dev_info_t *dip, uint32_t ino)
{
	vnex_id_t *vid_p;

	mutex_enter(&vnex_id_lock);
	vid_p = vnex_id_list;

	while (vid_p != NULL) {
		if (vid_p->vid_dip == dip && vid_p->vid_ino == ino) {
			mutex_exit(&vnex_id_lock);
			return (vid_p);
		}
		vid_p = vid_p->vid_next;
	}
	mutex_exit(&vnex_id_lock);
	return (NULL);
}

static void
vnex_free_id(vnex_id_t *vid_p)
{
	mutex_enter(&vnex_id_lock);
	vnex_rem_id(vid_p);
	mutex_exit(&vnex_id_lock);

	kmem_free(vid_p, sizeof (*vid_p));
}

static void
vnex_rem_id(vnex_id_t *vid_p)
{
	vnex_id_t *prev_p = vnex_id_list;

	if (vnex_id_list == NULL)
		cmn_err(CE_PANIC, "vnex: interrupt list empty");

	if (vid_p == NULL)
		cmn_err(CE_PANIC, "vnex: no element to remove");

	if (vnex_id_list == vid_p) {
		vnex_id_list = vid_p->vid_next;
	} else {
		while (prev_p != NULL && prev_p->vid_next != vid_p)
			prev_p = prev_p->vid_next;

		if (prev_p == NULL)
			cmn_err(CE_PANIC, "vnex: element %p not in list",
			    (void *) vid_p);

		prev_p->vid_next = vid_p->vid_next;
	}
}

static void
vnex_add_id(vnex_id_t *vid_p)
{
	vid_p->vid_next = vnex_id_list;
	vnex_id_list = vid_p;
}

uint_t
vnex_intr_wrapper(caddr_t arg)
{
	vnex_id_t *vid_p = (vnex_id_t *)arg;
	int res;
	uint_t (*handler)();
	caddr_t handler_arg1;
	caddr_t handler_arg2;

	handler = vid_p->vid_handler;
	handler_arg1 = vid_p->vid_arg1;
	handler_arg2 = vid_p->vid_arg2;

	res = (*handler)(handler_arg1, handler_arg2);

	(void) hvio_intr_setstate(vid_p->vid_ihdl, HV_INTR_IDLE_STATE);

	return (res);
}
