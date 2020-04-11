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
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/autoconf.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/sgsbbc_mailbox.h>
#include <sys/sgfrutree.h>
#include <sys/sgfru_priv.h>
#include <sys/sgfru_mbox.h>

/*
 * This driver implements the ioctls for the serengeti frutree picl plugin
 * and the serengeti fruaccess library. These are all private,
 * platform-dependent interfaces.
 */

/* Global Variables */

#ifdef DEBUG
uint_t sgfru_debug = 0;
#endif /* DEBUG */

/* Opaque state structure pointer */
static void *sgfru_statep;	/* sgfru soft state hook */

/*
 * the maximum amount of time this driver is prepared to wait for the mailbox
 * to reply before it decides to timeout.
 */
int sgfru_mbox_wait = SGFRU_DEFAULT_MAX_MBOX_WAIT_TIME;

/* Module Variables */

/*
 * Driver entry points. These are located in sgfru.c so as to
 * not cause a warning for the sgfru adb macro.
 */
static struct cb_ops sgfru_cb_ops = {
	sgfru_open,		/* open */
	sgfru_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nulldev,		/* dump */
	nulldev,		/* read */
	nulldev,		/* write */
	sgfru_ioctl,		/* ioctl */
	nulldev,		/* devmap */
	nulldev,		/* mmap */
	nulldev,		/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops sgfru_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_getinfo_1to1,	/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sgfru_attach,		/* attach */
	sgfru_detach,		/* detach */
	nodev,			/* reset */
	&sgfru_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Loadable module support. This is located in sgfru.c so as to
 * pick up the 1.8 version of sgfru.c.
 */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module.  This one is a pseudo driver */
	"FRU Driver",
	&sgfru_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int error = 0;

	/* Allocate the soft state info and add the module. */
	if ((error = ddi_soft_state_init(&sgfru_statep,
	    sizeof (sgfru_soft_state_t), 1)) == 0 &&
	    (error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&sgfru_statep);
	}
	return (error);
}

int
_fini(void)
{
	int error = 0;

	/* Remove the module and free the soft state info. */
	if ((error = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&sgfru_statep);
	}
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
sgfru_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	sgfru_soft_state_t *softsp;
	int instance;
	int error;
	static fn_t f = "sgfru_attach";

	switch (cmd) {
	case DDI_ATTACH:
		instance = ddi_get_instance(dip);

		error = ddi_soft_state_zalloc(sgfru_statep, instance);
		if (error != DDI_SUCCESS) {
			cmn_err(CE_WARN, "sgfru:%s: cannot allocate fru state "
			    "for inst %d.", f, instance);
			return (DDI_FAILURE);
		}
		softsp = ddi_get_soft_state(sgfru_statep, instance);
		if (softsp == NULL) {
			ddi_soft_state_free(sgfru_statep, instance);
			cmn_err(CE_WARN, "sgfru:%s: could not get state "
			    "structure for inst %d.", f, instance);
			return (DDI_FAILURE);
		}
		softsp->fru_dip = dip;
		softsp->fru_pdip = ddi_get_parent(softsp->fru_dip);
		softsp->instance = instance;

		error = ddi_create_minor_node(dip, SGFRU_DRV_NAME, S_IFCHR,
		    instance, DDI_PSEUDO, 0);
		if (error == DDI_FAILURE) {
			ddi_soft_state_free(sgfru_statep, instance);
			return (DDI_FAILURE);
		}

		ddi_report_dev(dip);

		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
sgfru_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	sgfru_soft_state_t *softsp;
	static fn_t f = "sgfru_detach";

	instance = ddi_get_instance(dip);

	softsp = ddi_get_soft_state(sgfru_statep, instance);
	if (softsp == NULL) {
		cmn_err(CE_WARN, "sgfru:%s: could not get state "
		    "structure for inst %d.", f, instance);
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		ddi_soft_state_free(sgfru_statep, instance);
		ddi_remove_minor_node(dip, NULL);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
sgfru_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	int error = 0;
	int instance = getminor(*dev_p);
	sgfru_soft_state_t *softsp;
	static fn_t f = "sgfru_open";

	if ((error = drv_priv(cred_p)) != 0) {
		cmn_err(CE_WARN, "sgfru:%s: inst %d drv_priv failed",
		    f, instance);
		return (error);
	}
	softsp = (sgfru_soft_state_t *)ddi_get_soft_state(sgfru_statep,
	    instance);
	if (softsp == (sgfru_soft_state_t *)NULL) {
		cmn_err(CE_WARN, "sgfru:%s: inst %d ddi_get_soft_state failed",
		    f, instance);
		return (ENXIO);
	}
	return (error);
}

/*ARGSUSED*/
static int
sgfru_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	int instance = getminor(dev);
	sgfru_soft_state_t *softsp = (sgfru_soft_state_t *)
	    ddi_get_soft_state(sgfru_statep, instance);

	if (softsp == (sgfru_soft_state_t *)NULL)
		return (ENXIO);
	return (DDI_SUCCESS);
}

/*
 * This function disperses the ioctls from the serengeti libpiclfruhier plugin
 * and the serengeti libpiclfruaccess library to the appropriate sub-functions.
 */
/*ARGSUSED*/
static int
sgfru_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
	sgfru_soft_state_t *softsp;
	int instance = getminor(dev);
	sgfru_init_arg_t init_arg;
	int32_t ret = 0;
	static fn_t f = "sgfru_ioctl";


	softsp = ddi_get_soft_state(sgfru_statep, instance);
	if (softsp == NULL) {
		return (ENXIO);
	}
	PR_STATE("sgfru:%s: dev %lx cmd %d, instance %d\n",
	    f, dev, cmd, instance);

	init_arg.dev = dev;
	init_arg.cmd = cmd;
	init_arg.mode = mode;
	init_arg.argp = arg;

	switch (cmd) {

	case SGFRU_GETSECTIONS:
		ret = sgfru_getsections(&init_arg);
		break;

	case SGFRU_GETSEGMENTS:
		ret = sgfru_getsegments(&init_arg);
		break;

	case SGFRU_ADDSEGMENT:
		ret = sgfru_addsegment(&init_arg);
		break;

	case SGFRU_READRAWSEGMENT:
		ret = sgfru_readsegment(&init_arg);
		break;

	case SGFRU_WRITERAWSEGMENT:
		ret = sgfru_writesegment(&init_arg);
		break;

	case SGFRU_GETPACKETS:
		ret = sgfru_getpackets(&init_arg);
		break;

	case SGFRU_APPENDPACKET:
		ret = sgfru_appendpacket(&init_arg);
		break;

	case SGFRU_GETPAYLOAD:
		ret = sgfru_getpayload(&init_arg);
		break;

	case SGFRU_UPDATEPAYLOAD:
		ret = sgfru_updatepayload(&init_arg);
		break;

	case SGFRU_GETNUMSECTIONS:
	case SGFRU_GETNUMSEGMENTS:
	case SGFRU_GETNUMPACKETS:
		ret = sgfru_getnum(&init_arg);
		break;

	case SGFRU_DELETESEGMENT:
	case SGFRU_DELETEPACKET:
		ret = sgfru_delete(&init_arg);
		break;

	case SGFRU_GETCHILDLIST:
		ret = sgfru_getchildlist(&init_arg);
		break;

	case SGFRU_GETCHILDHANDLES:
		ret = sgfru_getchildhandles(&init_arg);
		break;

	case SGFRU_GETNODEINFO:
		ret = sgfru_getnodeinfo(&init_arg);
		break;

	default:
		ret = EINVAL;
		break;
	}

	return (ret);
}

/*
 * Used for private SGFRU_GETCHILDLIST ioctl.
 */
static int
sgfru_getchildlist(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap;
	size_t ssize, size;
	frup_info_t clist;
	fru_cnt_t max_cnt;
	node_t *clistp;
	static fn_t f = "sgfru_getchildlist";

	/* copyin child_info_t aka frup_info_t */
	if (sgfru_copyin_frup(iargp, &clist) != 0) {
		return (EFAULT);
	}

	/* check on kmem_alloc space requirements */
	max_cnt = clist.fru_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_HANDLES)) {
		return (EINVAL);
	}

	/* allocate buffer for unpadded fru_info_t + node_t's */
	size = (size_t)(FRU_INFO_SIZE + (max_cnt * NODE_SIZE));
	datap = kmem_zalloc(size, KM_SLEEP);
	PR_NODE("sgfru:%s: FRU_INFO_SIZE %lu NODE_SIZE %lu size %lu\n",
	    f, FRU_INFO_SIZE, NODE_SIZE, size);
	PR_NODE("sgfru:%s: handle %lx cnt %d buffer 0x%p\n", f,
	    clist.fru_hdl, clist.fru_cnt, clist.frus);

	/* call mailbox */
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &clist.fru_info))
	    != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* allocate buffer for padded node_t's */
	ssize = (size_t)(max_cnt * sizeof (node_t));
	clistp = (node_t *)kmem_zalloc(ssize, KM_SLEEP);

	/* translate unpadded to padded fru_info_t + node_t's */
	if ((ret = sgfru_node_pad(datap, max_cnt, &clist.fru_info, clistp))
	    != 0) {
		kmem_free(datap, size);
		kmem_free(clistp, ssize);
		return (ret);
	}
	/* free node_t buffer */
	kmem_free(datap, size);

	/* copy out fru_info_t */
	if (sgfru_copyout_fru(iargp, &clist.fru_info) != 0) {
		kmem_free(clistp, ssize);
		return (EFAULT);
	}
	/* copyout node_t's */
	if (sgfru_copyout_nodes(iargp, &clist, clistp) != 0) {
		kmem_free(clistp, ssize);
		return (EFAULT);
	}
	/* free node_t buffer */
	kmem_free(clistp, ssize);

	return (ret);
}

/*
 * Used for private SGFRU_GETCHILDHANDLES ioctl.
 */
static int
sgfru_getchildhandles(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	size_t size;
	caddr_t datap, tdatap;
	frup_info_t hdls;
	fru_info_t hinfo;
	fru_cnt_t max_cnt;
	static fn_t f = "sgfru_getchildhandles";

	/* copyin handles_t aka frup_info_t */
	if (sgfru_copyin_frup(iargp, &hdls) != 0) {
		return (EFAULT);
	}
	PR_HANDLE("sgfru:%s: handle %lx\n", f, hdls.fru_hdl);

	/* check on kmem_alloc space requirements */
	max_cnt = hdls.fru_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_HANDLES)) {
		return (EINVAL);
	}

	/* allocate buffer for child fru_hdl_t's */
	size = (size_t)(FRU_INFO_SIZE + (max_cnt * FRU_HDL_SIZE));
	datap = kmem_zalloc(size, KM_SLEEP);

	/* call mailbox */
	ret = sgfru_mbox(iargp->cmd, datap, size, &hdls.fru_info);
	if (ret != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* translate unpadded to fru_info_t */
	tdatap = sgfru_fru_pad(datap, &hinfo);

	/* copyout actual fru_cnt */
	if (sgfru_copyout_fru(iargp, &hinfo) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}
	PR_HANDLE("sgfru:%s: count %x\n", f, hinfo.cnt);

	/* copyout fru_hdl_t's */
	if (sgfru_copyout_handles(iargp, &hdls, (fru_hdl_t *)tdatap) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}

	/* free datap buffer */
	kmem_free(datap, size);

	return (ret);
}

/*
 * Used for private SGFRU_GETNODEINFO ioctl.
 */
static int
sgfru_getnodeinfo(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap;
	size_t size;
	frup_info_t nodeinfo;
	node_t node;
	static fn_t f = "sgfru_getnodeinfo";

	/* copyin node_info_t aka frup_info_t */
	if (sgfru_copyin_frup(iargp, &nodeinfo) != 0) {
		return (EFAULT);
	}

	/* allocate unpadded buffer for node_t */
	size = (size_t)(NODE_SIZE);
	datap = kmem_zalloc(size, KM_SLEEP);

	PR_NODE("sgfru:%s: handle %lx size 0x%lx\n", f, nodeinfo.fru_hdl, size);
	/* call mailbox */
	ret = sgfru_mbox(iargp->cmd, datap, size, &nodeinfo.fru_info);
	if (ret != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* translate unpadded to padded node_t */
	if ((ret = sgfru_node_pad(datap, 0, NULL, &node))
	    != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* free node_t buffer */
	kmem_free(datap, size);

	/* copyout node_t */
	if (sgfru_copyout_nodes(iargp, &nodeinfo, &node) != 0) {
		return (EFAULT);
	}
	PR_NODE("sgfru:%s: handle %lx nodename %s has_children %d class %d\n",
	    f, node.handle, node.nodename, node.has_children, node.class);

	return (ret);
}

/*
 * Used for fru_get_sections().
 */
static int
sgfru_getsections(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap;
	size_t ssize, size;
	frup_info_t sects;
	fru_cnt_t max_cnt;
	section_t *sectp;

	/* copyin sections_t aka frup_info_t */
	if (sgfru_copyin_frup(iargp, &sects) != 0) {
		return (EFAULT);
	}
	/* check on kmem_alloc space requirements */
	max_cnt = sects.fru_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_SECTIONS)) {
		return (EINVAL);
	}

	/* allocate buffer for unpadded fru_info_t + section_t's */
	size = (size_t)(FRU_INFO_SIZE + (max_cnt * SECTION_SIZE));
	datap = kmem_zalloc(size, KM_SLEEP);

	/* call mailbox */
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &sects.fru_info))
	    != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* allocate buffer for padded section_t's */
	ssize = (size_t)(max_cnt * sizeof (section_t));
	sectp = (section_t *)kmem_zalloc(ssize, KM_SLEEP);

	/* translate unpadded to padded fru_info_t + section_t's */
	if ((ret = sgfru_section_pad(datap, max_cnt, &sects.fru_info, sectp))
	    != 0) {
		kmem_free(datap, size);
		kmem_free(sectp, ssize);
		return (ret);
	}
	/* free section_t buffer */
	kmem_free(datap, size);

	/* copy out fru_info_t */
	if (sgfru_copyout_fru(iargp, &sects.fru_info) != 0) {
		kmem_free(sectp, ssize);
		return (EFAULT);
	}
	/* copyout section_t's */
	if (sgfru_copyout_sections(iargp, &sects, sectp) != 0) {
		kmem_free(sectp, ssize);
		return (EFAULT);
	}
	/* free section_t buffer */
	kmem_free(sectp, ssize);

	return (ret);
}

/*
 * Used for fru_get_segments().
 */
static int
sgfru_getsegments(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap;
	size_t ssize, size;
	frup_info_t segs;
	fru_cnt_t max_cnt;
	segment_t *segp;

	/* copyin frup_info_t */
	if (sgfru_copyin_frup(iargp, &segs) != 0) {
		return (EFAULT);
	}
	/* check on kmem_alloc space requirements */
	max_cnt = segs.fru_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_SEGMENTS)) {
		return (EINVAL);
	}

	/* allocate unpadded buffer for fru_info_t + segment_t's */
	size = (size_t)(FRU_INFO_SIZE + (max_cnt * SEGMENT_SIZE));
	datap = kmem_zalloc(size, KM_SLEEP);

	/* call mailbox */
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &segs.fru_info)) != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* allocate buffer for padded segment_t's */
	ssize = (size_t)(max_cnt * sizeof (segment_t));
	segp = (segment_t *)kmem_zalloc(ssize, KM_SLEEP);

	/* translate unpadded to padded fru_info_t + segment_t's */
	if ((ret = sgfru_segment_pad(datap, max_cnt, &segs.fru_info, segp))
	    != 0) {
		kmem_free(datap, size);
		kmem_free(segp, ssize);
		return (ret);
	}
	/* free segment_t buffer */
	kmem_free(datap, size);

	/* copy out fru_info_t */
	if (sgfru_copyout_fru(iargp, &segs.fru_info) != 0) {
		kmem_free(segp, ssize);
		return (EFAULT);
	}
	/* copyout segment_t's */
	if (sgfru_copyout_segments(iargp, &segs, segp) != 0) {
		kmem_free(segp, ssize);
		return (EFAULT);
	}
	/* free segment_t buffer */
	kmem_free(segp, ssize);

	return (ret);
}

static int
sgfru_addsegment(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap;
	size_t size;
	frup_info_t seg;
	segment_t segment;
	fru_hdl_t *hdlp;
	static fn_t f = "sgfru_addsegment";

	/* copyin frup_info_t */
	if (sgfru_copyin_frup(iargp, &seg) != 0) {
		return (EFAULT);
	}
	/* copyin segment_t */
	if (sgfru_copyin_segment(iargp, &seg, &segment) != 0) {
		return (EFAULT);
	}
	PR_SEGMENT("sgfru:%s: handle %lx, max cnt %d\n",
	    f, seg.fru_hdl, seg.fru_cnt);
	PR_SEGMENT("sgfru:%s: handle %lx, name %s, descriptor 0x%x, "
	    "offset 0x%x, length 0x%x\n", f, segment.handle, segment.name,
	    segment.descriptor, segment.offset, segment.length);

	/* allocate buffer for unpadded section_hdl_t + segment_t */
	size = (size_t)(SECTION_HDL_SIZE + SEGMENT_SIZE);
	datap = kmem_zalloc(size, KM_SLEEP);
	/* translate padded to unpadded section_hdl_t + segment_t */
	sgfru_segment_unpad(&seg.fru_info, &segment, datap);

	/* call mailbox */
	ret = sgfru_mbox(iargp->cmd, datap, size, &seg.fru_info);
	if (ret != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* copyout updated section_hdl_t */
	hdlp = (fru_hdl_t *)(datap + sizeof (fru_hdl_t));
	if (sgfru_copyout_handle(iargp, (void *)iargp->argp, hdlp) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}
	/* copyout new segment_hdl_t */
	if (sgfru_copyout_handle(iargp, seg.frus, --hdlp) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}
	/* free segment_t buffer */
	kmem_free(datap, size);

	return (ret);
}

/*
 * Used for fru_read_segment().
 */
static int
sgfru_readsegment(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap, tdatap;
	size_t size;
	frup_info_t segs;
	fru_info_t sinfo;
	fru_cnt_t max_cnt;
	static fn_t f = "sgfru_readsegment";

	/* copyin one segments_t aka frup_info_t */
	if (sgfru_copyin_frup(iargp, &segs) != 0) {
		return (EFAULT);
	}
	/* check on kmem_alloc space requirements */
	max_cnt = segs.fru_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_SEGMENTSIZE)) {
		return (EINVAL);
	}
	PR_SEGMENT("sgfru:%s: handle %lx, max cnt %d\n",
	    f, segs.fru_hdl, segs.fru_cnt);

	/* allocate unpadded buffer for raw data */
	size = (size_t)(FRU_INFO_SIZE + max_cnt);
	datap = kmem_zalloc(size, KM_SLEEP);

	/* call mailbox */
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &segs.fru_info)) != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* translate unpadded to padded fru_info_t */
	tdatap = sgfru_fru_pad(datap, &sinfo);
	PR_SEGMENT("sgfru:%s: handle %lx, actual cnt %d\n",
	    f, sinfo.hdl, sinfo.cnt);

	/* copyout actual fru_cnt */
	if (sgfru_copyout_fru(iargp, &sinfo) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}
	/* copyout raw segment data */
	if (sgfru_copyout_buffer(iargp, &segs, tdatap) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}
	/* free buffer */
	kmem_free(datap, size);

	return (ret);
}

/*
 * Used for fru_write_segment().
 */
static int
sgfru_writesegment(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap, tdatap;
	size_t size;
	frup_info_t segs;
	fru_cnt_t max_cnt;
	static fn_t f = "sgfru_writesegment";

	/* copyin frup_info_t */
	if (sgfru_copyin_frup(iargp, &segs) != 0) {
		return (EFAULT);
	}
	/* check on kmem_alloc space requirements */
	max_cnt = segs.fru_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_SEGMENTSIZE)) {
		return (EINVAL);
	}
	PR_SEGMENT("sgfru:%s: handle %lx, max cnt %d\n",
	    f, segs.fru_hdl, segs.fru_cnt);

	/* allocate unpadded buffer for fru_info_t + raw data */
	size = (size_t)(FRU_INFO_SIZE + max_cnt);
	datap = kmem_zalloc(size, KM_SLEEP);

	/* translate padded to unpadded fru_info_t */
	tdatap = sgfru_fru_unpad(&segs.fru_info, datap);

	/* copyin raw segment data */
	if (sgfru_copyin_buffer(iargp, segs.frus, max_cnt, tdatap) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}

	/* call mailbox */
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &segs.fru_info)) != 0) {
		kmem_free(datap, size);
		return (ret);
	}
	/* free buffer */
	kmem_free(datap, size);

	PR_SEGMENT("sgfru:%s: handle %lx, actual cnt %d\n",
	    f, segs.fru_hdl, segs.fru_cnt);
	/* copyout updated segment handle and actual fru_cnt */
	if (sgfru_copyout_fru(iargp, &segs.fru_info) != 0) {
		return (EFAULT);
	}

	return (ret);
}

/*
 * Used for fru_get_packets().
 */
static int
sgfru_getpackets(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap;
	size_t ssize, size;
	frup_info_t packs;
	fru_cnt_t max_cnt;
	packet_t *packp;

	/* copyin packets_t aka frup_info_t */
	if (sgfru_copyin_frup(iargp, &packs) != 0) {
		return (EFAULT);
	}
	/* check on kmem_alloc space requirements */
	max_cnt = packs.fru_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_PACKETS)) {
		return (EINVAL);
	}

	/* allocate buffer for unpadded fru_info_t + packet_t's */
	size = (size_t)(FRU_INFO_SIZE + (max_cnt * PACKET_SIZE));
	datap = kmem_zalloc(size, KM_SLEEP);

	/* call mailbox */
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &packs.fru_info))
	    != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* allocate buffer for padded packet_t's */
	ssize = (size_t)(max_cnt * sizeof (packet_t));
	packp = (packet_t *)kmem_zalloc(ssize, KM_SLEEP);

	/* translate unpadded to padded fru_info_t + packet_t's */
	if ((ret = sgfru_packet_pad(datap, max_cnt, &packs.fru_info, packp))
	    != 0) {
		kmem_free(datap, size);
		kmem_free(packp, ssize);
		return (ret);
	}
	/* free packet_t buffer */
	kmem_free(datap, size);

	/* copy out fru_info_t */
	if (sgfru_copyout_fru(iargp, &packs.fru_info) != 0) {
		kmem_free(packp, ssize);
		return (EFAULT);
	}
	/* copyout packet_t's */
	if (sgfru_copyout_packets(iargp, &packs, packp) != 0) {
		kmem_free(packp, ssize);
		return (EFAULT);
	}
	/* free packet_t buffer */
	kmem_free(packp, ssize);

	return (ret);
}

/*
 * Used for fru_append_packet().
 */
static int
sgfru_appendpacket(const sgfru_init_arg_t *iargp)
{
	int32_t ret = 0;
	caddr_t datap, tdatap;
	size_t size;
	append_info_t append;
	fru_cnt_t max_cnt;
	fru_hdl_t *hdlp;
	caddr_t addr;

	/* copyin append_info_t */
	if (sgfru_copyin_append(iargp, &append) != 0) {
		return (EFAULT);
	}
	/* check on kmem_alloc space requirements */
	max_cnt = append.payload_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_PAYLOADSIZE)) {
		return (EINVAL);
	}

	/* allocate buffer for unpadded fru_info_t + packet_t + payload */
	size = (size_t)(FRU_INFO_SIZE + PACKET_SIZE + max_cnt);
	datap = kmem_zalloc(size, KM_SLEEP);
	/* translate padded to unpadded fru_info_t plus packet_t */
	tdatap = sgfru_packet_unpad(&append.payload.fru_info, &append.packet,
	    datap);

	/* copyin payload to the end of the unpadded buffer */
	if (sgfru_copyin_buffer(iargp, append.payload_data, append.payload_cnt,
	    tdatap) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}

	/* call mailbox */
	if ((ret = sgfru_mbox(iargp->cmd, datap, size,
	    &append.payload.fru_info)) != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* copyout new packet_hdl_t */
	hdlp = (fru_hdl_t *)datap;
	if (sgfru_copyout_handle(iargp, (void *)iargp->argp, hdlp) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}
	/* copyout updated segment_hdl_t */
	addr = (caddr_t)(iargp->argp + sizeof (packet_t));
	if (sgfru_copyout_handle(iargp, addr, ++hdlp) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}

	/* free buffer */
	kmem_free(datap, size);

	return (ret);
}

/*
 * Used for fru_get_payload().
 */
static int
sgfru_getpayload(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap, tdatap;
	size_t size;
	frup_info_t payld;
	fru_info_t pinfo;
	fru_cnt_t max_cnt;
	static fn_t f = "sgfru_getpayload";

	/* copyin payload_t aka frup_info_t */
	if (sgfru_copyin_frup(iargp, &payld) != 0) {
		return (EFAULT);
	}
	PR_PAYLOAD("sgfru:%s: handle %lx, max cnt %d\n",
	    f, payld.fru_hdl, payld.fru_cnt);

	/* check on kmem_alloc space requirements */
	max_cnt = payld.fru_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_PAYLOADSIZE)) {
		return (EINVAL);
	}

	/* allocate buffer for fru_info_t + payload */
	size = (size_t)(FRU_INFO_SIZE + max_cnt);
	datap = kmem_zalloc(size, KM_SLEEP);

	/* call mailbox */
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &payld.fru_info))
	    != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* translate unpadded to padded fru_info_t */
	tdatap = sgfru_fru_pad(datap, &pinfo);
	PR_PAYLOAD("sgfru:%s: handle %lx, max cnt %d\n",
	    f, pinfo.hdl, pinfo.cnt);

	/* copyout actual fru_cnt */
	if (sgfru_copyout_fru(iargp, &pinfo) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}
	/* copyout raw packet data, aka the payload */
	if (sgfru_copyout_buffer(iargp, &payld, tdatap) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}

	/* free buffer */
	kmem_free(datap, size);

	return (ret);
}

/*
 * Used for fru_update_payload().
 */
static int
sgfru_updatepayload(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap, tdatap;
	size_t size;
	frup_info_t payld;
	fru_cnt_t max_cnt;
	static fn_t f = "sgfru_updatepayload";

	/* copyin frup_info_t */
	if (sgfru_copyin_frup(iargp, &payld) != 0) {
		return (EFAULT);
	}
	/* check on kmem_alloc space requirements */
	max_cnt = payld.fru_cnt;
	if ((max_cnt <= 0) || (max_cnt > MAX_PAYLOADSIZE)) {
		return (EINVAL);
	}

	/* allocate buffer for fru_info_t + payload */
	size = (size_t)(FRU_INFO_SIZE + max_cnt);
	datap = kmem_zalloc(size, KM_SLEEP);

	/* translate padded to unpadded fru_info_t */
	tdatap = sgfru_fru_unpad(&payld.fru_info, datap);

	/* copyin payload */
	if (sgfru_copyin_buffer(iargp, payld.frus, max_cnt, tdatap) != 0) {
		kmem_free(datap, size);
		return (EFAULT);
	}
	PR_PAYLOAD("sgfru_updatepayload: handle %lx, actual cnt %d\n",
	    payld.fru_hdl, payld.fru_cnt);

	/* call mailbox */
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &payld.fru_info))
	    != 0) {
		kmem_free(datap, size);
		return (ret);
	}

	/* free buffer */
	kmem_free(datap, size);

	/* copyout new packet_hdl_t and actual count */
	if (sgfru_copyout_fru(iargp, &payld.fru_info) != 0) {
		return (EFAULT);
	}
	PR_PAYLOAD("sgfru:%s: new handle %lx, cnt %d\n",
	    f, payld.fru_hdl, payld.fru_cnt);

	return (ret);
}

/*
 * Used for fru_get_num_[sections|segments|packets]().
 */
static int
sgfru_getnum(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap;
	size_t size;
	fru_info_t fru_info;

	/* copyin fru_info_t */
	if (sgfru_copyin_fru(iargp, &fru_info) != 0) {
		return (EFAULT);
	}

	size = sizeof (fru_cnt_t);
	datap = (caddr_t)&fru_info.cnt;
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &fru_info)) != 0) {
		return (ret);
	}

	/* copyout fru_info_t */
	if (sgfru_copyout_fru(iargp, &fru_info) != 0) {
		return (EFAULT);
	}
	return (ret);
}

/*
 * Used for fru_delete_[segment|packet].
 */
static int
sgfru_delete(const sgfru_init_arg_t *iargp)
{
	int32_t ret;
	caddr_t datap;
	size_t size;
	fru_info_t fru_info;
	static fn_t f = "sgfru_delete";

	/* copyin fru_info_t */
	if (sgfru_copyin_fru(iargp, &fru_info) != 0) {
		return (EFAULT);
	}
	PR_SEGMENT("sgfru:%s: delete handle %lx\n", f, fru_info.hdl);

	size = sizeof (fru_hdl_t);
	datap = (caddr_t)&fru_info.hdl;
	if ((ret = sgfru_mbox(iargp->cmd, datap, size, &fru_info)) != 0) {
		return (ret);
	}

	PR_SEGMENT("sgfru:%s: new parent handle %lx\n", f, fru_info.hdl);
	/* copyout fru_info_t */
	if (sgfru_copyout_fru(iargp, &fru_info) != 0) {
		return (EFAULT);
	}
	return (ret);
}

/*
 * Calls the sgsbbc mailbox with data, returns data and status info.
 */
static int
sgfru_mbox(const int cmd, char *datap, const size_t size, fru_info_t *fru)
{
	sbbc_msg_t request, *reqp = &request;
	sbbc_msg_t response, *resp = &response;
	fru_hdl_t hdls[2] = {0, 0};
	fru_hdl_t hdl = fru->hdl;
	int rv = 0;
	static fn_t f = "sgfru_mbox";

	bzero((caddr_t)&request, sizeof (sbbc_msg_t));
	reqp->msg_type.type = SGFRU_MBOX;
	bzero((caddr_t)&response, sizeof (sbbc_msg_t));
	resp->msg_type.type = SGFRU_MBOX;
	PR_MBOX("sgfru:%s: cmd 0x%x, size %lu\n", f, cmd, size);

	switch (cmd) {

	case SGFRU_GETCHILDLIST:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETCHILDLIST;
		reqp->msg_len = sizeof (fru_info_t);
		reqp->msg_buf = (caddr_t)fru;
		resp->msg_type.sub_type = SGFRU_MBOX_GETCHILDLIST;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_GETCHILDHANDLES:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETCHILDHANDLES;
		reqp->msg_len = sizeof (fru_info_t);
		reqp->msg_buf = (caddr_t)fru;
		resp->msg_type.sub_type = SGFRU_MBOX_GETCHILDHANDLES;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_GETNODEINFO:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETNODEINFO;
		reqp->msg_len = sizeof (fru_hdl_t);
		reqp->msg_buf = (caddr_t)&hdl;
		resp->msg_type.sub_type = SGFRU_MBOX_GETNODEINFO;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_GETNUMSECTIONS:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETNUMSECTIONS;
		reqp->msg_len = sizeof (fru_hdl_t);
		reqp->msg_buf = (caddr_t)&hdl;
		resp->msg_type.sub_type = SGFRU_MBOX_GETNUMSECTIONS;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_GETNUMSEGMENTS:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETNUMSEGMENTS;
		reqp->msg_len = sizeof (fru_hdl_t);
		reqp->msg_buf = (caddr_t)&hdl;
		resp->msg_type.sub_type = SGFRU_MBOX_GETNUMSEGMENTS;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_GETNUMPACKETS:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETNUMPACKETS;
		reqp->msg_len = sizeof (fru_hdl_t);
		reqp->msg_buf = (caddr_t)&hdl;
		resp->msg_type.sub_type = SGFRU_MBOX_GETNUMPACKETS;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_GETSECTIONS:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETSECTIONS;
		reqp->msg_len = sizeof (fru_info_t);
		reqp->msg_buf = (caddr_t)fru;
		resp->msg_type.sub_type = SGFRU_MBOX_GETSECTIONS;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_GETSEGMENTS:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETSEGMENTS;
		reqp->msg_len = sizeof (fru_info_t);
		reqp->msg_buf = (caddr_t)fru;
		resp->msg_type.sub_type = SGFRU_MBOX_GETSEGMENTS;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_GETPACKETS:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETPACKETS;
		reqp->msg_len = sizeof (fru_info_t);
		reqp->msg_buf = (caddr_t)fru;
		resp->msg_type.sub_type = SGFRU_MBOX_GETPACKETS;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_ADDSEGMENT:
		reqp->msg_type.sub_type = SGFRU_MBOX_ADDSEGMENT;
		reqp->msg_len = size;
		reqp->msg_buf = datap;
		resp->msg_type.sub_type = SGFRU_MBOX_ADDSEGMENT;
		resp->msg_len = sizeof (hdls);
		resp->msg_buf = (caddr_t)&hdls;
		break;

	case SGFRU_APPENDPACKET:
		reqp->msg_type.sub_type = SGFRU_MBOX_APPENDPACKET;
		reqp->msg_len = size;
		reqp->msg_buf = (caddr_t)datap;
		resp->msg_type.sub_type = SGFRU_MBOX_APPENDPACKET;
		resp->msg_len = sizeof (hdls);
		resp->msg_buf = (caddr_t)&hdls;
		break;

	case SGFRU_DELETESEGMENT:
		reqp->msg_type.sub_type = SGFRU_MBOX_DELETESEGMENT;
		reqp->msg_len = size;
		reqp->msg_buf = (caddr_t)datap;
		resp->msg_type.sub_type = SGFRU_MBOX_DELETESEGMENT;
		resp->msg_len = sizeof (fru_hdl_t);
		resp->msg_buf = (caddr_t)&hdl;
		break;

	case SGFRU_READRAWSEGMENT:
		reqp->msg_type.sub_type = SGFRU_MBOX_READRAWSEGMENT;
		reqp->msg_len = sizeof (fru_info_t);
		reqp->msg_buf = (caddr_t)fru;
		resp->msg_type.sub_type = SGFRU_READRAWSEGMENT;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_WRITERAWSEGMENT:
		reqp->msg_type.sub_type = SGFRU_MBOX_WRITERAWSEGMENT;
		reqp->msg_len = size;
		reqp->msg_buf = datap;
		resp->msg_type.sub_type = SGFRU_WRITERAWSEGMENT;
		resp->msg_len = sizeof (fru_info_t);
		resp->msg_buf = (caddr_t)fru;
		break;

	case SGFRU_DELETEPACKET:
		reqp->msg_type.sub_type = SGFRU_MBOX_DELETEPACKET;
		reqp->msg_len = size;
		reqp->msg_buf = (caddr_t)datap;
		resp->msg_type.sub_type = SGFRU_MBOX_DELETEPACKET;
		resp->msg_len = sizeof (fru_hdl_t);
		resp->msg_buf = (caddr_t)&hdl;
		break;

	case SGFRU_GETPAYLOAD:
		reqp->msg_type.sub_type = SGFRU_MBOX_GETPAYLOAD;
		reqp->msg_len = sizeof (fru_info_t);
		reqp->msg_buf = (caddr_t)fru;
		resp->msg_type.sub_type = SGFRU_MBOX_GETPAYLOAD;
		resp->msg_len = size;
		resp->msg_buf = datap;
		break;

	case SGFRU_UPDATEPAYLOAD:
		reqp->msg_type.sub_type = SGFRU_MBOX_UPDATEPAYLOAD;
		reqp->msg_len = size;
		reqp->msg_buf = datap;
		resp->msg_type.sub_type = SGFRU_MBOX_UPDATEPAYLOAD;
		resp->msg_len = sizeof (fru_info_t);
		resp->msg_buf = (caddr_t)fru;
		break;

	default:
		return (EINVAL);
	}

	rv = sbbc_mbox_request_response(reqp, resp, sgfru_mbox_wait);
	PR_MBOX("sgfru:%s: rv %d, msg_status %d\n", f, rv, resp->msg_status);

	if ((rv) || (resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {

		/* errors from sgsbbc */
		if (resp->msg_status > 0) {
			return (resp->msg_status);
		}

		/* errors from SCAPP */
		switch (resp->msg_status) {

		case SG_MBOX_STATUS_COMMAND_FAILURE:
			/* internal SCAPP error */
			return (EINTR);

		case SG_MBOX_STATUS_HARDWARE_FAILURE:
			/* seprom read/write errors */
			return (EIO);

		case SG_MBOX_STATUS_ILLEGAL_PARAMETER:
			/* illegal ioctl parameter */
			return (EINVAL);

		case SG_MBOX_STATUS_BOARD_ACCESS_DENIED:
			/* board access denied */
			return (EACCES);

		case SG_MBOX_STATUS_STALE_CONTENTS:
			/* stale contents */
			return (ESTALE);

		case SG_MBOX_STATUS_STALE_OBJECT:
			/* stale handle */
			return (ENOENT);

		case SG_MBOX_STATUS_NO_SEPROM_SPACE:
			/* seprom lacks space */
			return (ENOSPC);

		case SG_MBOX_STATUS_NO_MEMORY:
			/* user prog. lacks space */
			return (ENOMEM);

		case SG_MBOX_STATUS_NOT_SUPPORTED:
			/* unsupported operation */
			return (ENOTSUP);

		default:
			return (EIO);
		}
	}

	switch (cmd) {

	/*
	 * These two calls get back two handles, a new handle for the
	 * added segment or packet, and an updated parent handle.
	 */
	case SGFRU_ADDSEGMENT:
	case SGFRU_APPENDPACKET:
		bcopy(hdls, datap, sizeof (hdls));
		break;

	/* These two calls get an updated parent handle. */
	case SGFRU_DELETESEGMENT:
	case SGFRU_DELETEPACKET:
		fru->hdl = hdl;
		break;

	default:
		break;
	}

	return (0);
}

/*
 * Used to copy in one frup_info_t from user.
 */
static int
sgfru_copyin_frup(const sgfru_init_arg_t *argp, frup_info_t *frup)
{
	static fn_t f = "sgfru_copyin_frup";

	bzero((caddr_t)frup, sizeof (frup_info_t));
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(argp->mode & FMODELS) == DDI_MODEL_ILP32) {
		frup32_info_t frup32;

		bzero((caddr_t)&frup32, sizeof (frup32_info_t));
		if (ddi_copyin((void *)argp->argp, (void *)&frup32,
		    sizeof (frup32_info_t), argp->mode) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "sgfru:%s: (32 bit) failed to copyin "
			    "frup32_t struct", f);
			return (EFAULT);
		}
		frup->fru_hdl = frup32.fru_hdl;
		frup->fru_cnt = frup32.fru_cnt;
		frup->frus = (void *)(uintptr_t)frup32.frus;
		PR_STATE("sgfru:%s: frus %p %x hdl %lx cnt %d\n",
		    f, frup->frus, frup32.frus, frup->fru_hdl, frup->fru_cnt);

	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)argp->argp, (void *)frup,
	    sizeof (frup_info_t), argp->mode) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "sgfru:%s: failed to copyin frup_info_t struct", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy in one fru_info_t from user.
 */
static int
sgfru_copyin_fru(const sgfru_init_arg_t *argp, fru_info_t *fru)
{
	static fn_t f = "sgfru_copyin_fru";

	bzero((caddr_t)fru, sizeof (fru_info_t));
	if (ddi_copyin((void *)argp->argp, (void *)fru,
	    sizeof (fru_info_t), argp->mode) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "sgfru:%s: failed to copyin fru_info_t struct", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy in segment_t from user.
 */
static int
sgfru_copyin_segment(const sgfru_init_arg_t *argp, const frup_info_t *frup,
    segment_t *segp)
{
	static fn_t f = "sgfru_copyin_segment";

	bzero((caddr_t)segp, sizeof (segment_t));
	if (ddi_copyin((void *)frup->frus, (void *)segp,
	    sizeof (segment_t), argp->mode) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "sgfru:%s: failed to copyin segment_t struct", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy in segment handle, packet and payload data from user.
 */
static int
sgfru_copyin_append(const sgfru_init_arg_t *argp, append_info_t *app)
{
	static fn_t f = "sgfru_copyin_append";

	bzero((caddr_t)app, sizeof (append_info_t));
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(argp->mode & FMODELS) == DDI_MODEL_ILP32) {
		append32_info_t app32;

		bzero((caddr_t)&app32, sizeof (append32_info_t));
		if (ddi_copyin((void *)argp->argp, (void *)&app32,
		    sizeof (append32_info_t), argp->mode) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "sgfru:%s: (32 bit) failed to copyin "
			    "append32_info_t struct", f);
			return (EFAULT);
		}
		app->packet = app32.packet;
		app->payload_hdl = app32.payload_hdl;
		app->payload_cnt = app32.payload_cnt;
		app->payload_data = (void *)(uintptr_t)app32.payload_data;
		PR_PAYLOAD("sgfru:%s:: data %p hdl %lx cnt %d\n",
		    f, app->payload_data, app->payload_hdl, app->payload_cnt);

	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)argp->argp, (void *)app,
	    sizeof (append_info_t), argp->mode) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "sgfru:%s: failed to copyin append_info_t struct", f);
		return (EFAULT);
	}
	PR_PAYLOAD("sgfru:%s: hdl %lx, cnt %d pkt hdl %lx "
	    "tag %lx\n", f, app->payload_hdl, app->payload_cnt,
	    app->packet.handle, app->packet.tag);
	return (0);
}

/*
 * Used to copy in raw segment and payload data from user.
 */
static int
sgfru_copyin_buffer(const sgfru_init_arg_t *argp, const caddr_t data,
    const int cnt, char *buffer)
{
	static fn_t f = "sgfru_copyin_buffer";

	if (ddi_copyin((void *)data, (void *)buffer, cnt, argp->mode)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgfru:%s: failed to copyin buffer", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy out one fru_info_t to user.
 */
static int
sgfru_copyout_fru(const sgfru_init_arg_t *argp, const fru_info_t *frup)
{
	static fn_t f = "sgfru_copyout_fru";

	if (ddi_copyout((void *)frup, (void *)argp->argp,
	    sizeof (fru_info_t), argp->mode) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgfru:%s: failed to copyout fru", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy out one fru_hdl_t to user.
 */
static int
sgfru_copyout_handle(const sgfru_init_arg_t *argp, const void *addr,
    const fru_hdl_t *hdlp)
{
	static fn_t f = "sgfru_copyout_handle";

	if (ddi_copyout((void *)hdlp, (void *)addr, sizeof (fru_hdl_t),
	    argp->mode) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgfru:%s: failed to copyout handle", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy out an array of fru_hdl_t's to user.
 */
static int
sgfru_copyout_handles(const sgfru_init_arg_t *argp, const frup_info_t *frup,
    const fru_hdl_t *hdlp)
{
	static fn_t f = "sgfru_copyout_handles";

	size_t size = (size_t)(frup->fru_cnt * sizeof (fru_hdl_t));
	/* copyout fru_hdl_t's */
	if (ddi_copyout((void *)hdlp, (void *)frup->frus, size, argp->mode)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgfru:%s: failed to copyout handles", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy out one or more node_t's to user.
 */
static int
sgfru_copyout_nodes(const sgfru_init_arg_t *argp, const frup_info_t *frup,
    const node_t *nodep)
{
	static fn_t f = "sgfru_copyout_nodes";

	size_t size = (size_t)(frup->fru_cnt * sizeof (node_t));
	/* copyout node_t's */
	if (ddi_copyout((void *)nodep, (void *)frup->frus, size, argp->mode)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgfru:%s: failed to copyout nodes", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy out section_t's to user.
 */
static int
sgfru_copyout_sections(const sgfru_init_arg_t *argp, const frup_info_t *frup,
    const section_t *sectp)
{
	static fn_t f = "sgfru_copyout_sections";

	size_t size = (size_t)(frup->fru_cnt * sizeof (section_t));
	/* copyout section_t's */
	if (ddi_copyout((void *)sectp, (void *)frup->frus, size, argp->mode)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgfru:%s: failed to copyout sections", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy out segment_t's to user.
 */
static int
sgfru_copyout_segments(const sgfru_init_arg_t *argp, const frup_info_t *frup,
    const segment_t *segp)
{
	static fn_t f = "sgfru_copyout_segments";

	size_t size = (size_t)(frup->fru_cnt * sizeof (segment_t));
	/* copyout segment_t's */
	if (ddi_copyout((void *)segp, (void *)frup->frus, size, argp->mode)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgfru:%s: failed to copyout segments", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy out packet_t's to user.
 */
static int
sgfru_copyout_packets(const sgfru_init_arg_t *argp, const frup_info_t *frup,
    const packet_t *packp)
{
	static fn_t f = "sgfru_copyout_packets";

	size_t size = (size_t)(frup->fru_cnt * sizeof (packet_t));
	/* copyout packet_t's */
	if (ddi_copyout((void *)packp, (void *)frup->frus, size, argp->mode)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgfru:%s: failed to copyout packets", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to copy out raw segment and payload data to user.
 */
static int
sgfru_copyout_buffer(const sgfru_init_arg_t *argp, const frup_info_t *frup,
    const char *buffer)
{
	static fn_t f = "sgfru_copyout_buffer";

	size_t size = (size_t)(frup->fru_cnt);
	/* copyout packet_t */
	if (ddi_copyout((void *)buffer, (void *)frup->frus, size, argp->mode)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgfru:%s: failed to copyout buffer", f);
		return (EFAULT);
	}
	return (0);
}

/*
 * Used to pad a Java (SCAPP) fru_info_t, in preparation for sending it to
 * C (Solaris).  Assumes one fru_info_t.
 */
static caddr_t
sgfru_fru_pad(const caddr_t datap, fru_info_t *fru)
{
	caddr_t tdatap = datap;

	bcopy(tdatap, (caddr_t)&fru->hdl, FRU_HDL_SIZE);
	tdatap += FRU_HDL_SIZE;
	bcopy(tdatap, (caddr_t)&fru->cnt, FRU_CNT_SIZE);
	tdatap += FRU_CNT_SIZE;
	return (tdatap);
}

/*
 * Used to pad a Java (SCAPP) node_t, in preparation for sending it to
 * C (Solaris).  Assumes a fru_info_t and one or more node_t's.
 */
static int
sgfru_node_pad(const caddr_t datap, const int max_cnt, fru_info_t *fru,
    node_t *nodep)
{
	caddr_t tdatap = datap;
	node_t *np;
	int i, cnt = 1;

	if (fru != NULL) {
		tdatap = sgfru_fru_pad(datap, fru);
		if (max_cnt < fru->cnt) {
			return (ENOMEM);
		} else {
			cnt = fru->cnt;
		}
	}
	for (i = 0, np = nodep; i < cnt; i++, np++) {
		bcopy(tdatap, (caddr_t)&np->handle, FRU_HDL_SIZE);
		tdatap += FRU_HDL_SIZE;
		bcopy(tdatap, (caddr_t)&np->nodename, NODENAME_SIZE);
		tdatap += NODENAME_SIZE;
		bcopy(tdatap, (caddr_t)&np->has_children, HASCHILDREN_SIZE);
		tdatap += HASCHILDREN_SIZE;
		bcopy(tdatap, (caddr_t)&np->class, CLASS_SIZE);
		tdatap += CLASS_SIZE;
		if (np->class == LOCATION_CLASS) {
			bcopy(tdatap, (caddr_t)&np->location_slot, SLOT_SIZE);
			tdatap += SLOT_SIZE;
			bcopy(tdatap, (caddr_t)&np->location_label, LABEL_SIZE);
			tdatap += LABEL_SIZE;
		}
	}
	return (0);
}

/*
 * Used to pad a Java (SCAPP) section, in preparation for sending it to
 * C (Solaris).  Assumes a fru_info_t and multiple section_t's.
 */
static int
sgfru_section_pad(const caddr_t datap, const int max_cnt, fru_info_t *fru,
    section_t *sectp)
{
	caddr_t tdatap = datap;
	section_t *sp;
	int i;

	tdatap = sgfru_fru_pad(datap, fru);
	if (max_cnt < fru->cnt)
		return (ENOMEM);
	for (i = 0, sp = sectp; i < fru->cnt; i++, sp++) {
		bcopy(tdatap, (caddr_t)&sp->handle, FRU_HDL_SIZE);
		tdatap += FRU_HDL_SIZE;
		bcopy(tdatap, (caddr_t)&sp->offset, OFFSET_SIZE);
		tdatap += OFFSET_SIZE;
		bcopy(tdatap, (caddr_t)&sp->length, LENGTH_SIZE);
		tdatap += LENGTH_SIZE;
		bcopy(tdatap, (caddr_t)&sp->protected, PROTECTED_SIZE);
		tdatap += PROTECTED_SIZE;
		bcopy(tdatap, (caddr_t)&sp->version, VERSION_SIZE);
		tdatap += VERSION_SIZE;
	}
	return (0);
}

/*
 * Used to pad a Java (SCAPP) segment, in preparation for sending it to
 * C (Solaris).  Assumes a fru_info_t and multiple segment_t's.
 */
static int
sgfru_segment_pad(const caddr_t datap, const int max_cnt, fru_info_t *fru,
    segment_t *segp)
{
	caddr_t tdatap = datap;
	segment_t *sp;
	int i;

	tdatap = sgfru_fru_pad(datap, fru);
	if (max_cnt < fru->cnt)
		return (ENOMEM);
	for (i = 0, sp = segp; i < fru->cnt; i++, sp++) {
		bcopy(tdatap, (caddr_t)&sp->handle, FRU_HDL_SIZE);
		tdatap += FRU_HDL_SIZE;
		bcopy(tdatap, (caddr_t)&sp->name, NAME_SIZE);
		tdatap += NAME_SIZE;
		bcopy(tdatap, (caddr_t)&sp->descriptor, DESCRIPTOR_SIZE);
		tdatap += DESCRIPTOR_SIZE;
		bcopy(tdatap, (caddr_t)&sp->offset, OFFSET_SIZE);
		tdatap += OFFSET_SIZE;
		bcopy(tdatap, (caddr_t)&sp->length, LENGTH_SIZE);
		tdatap += LENGTH_SIZE;
	}
	return (0);
}

/*
 * Used to pad a Java (SCAPP) packet, in preparation for sending it to
 * C (Solaris).  Assumes a fru_info_t and multiple packet_t's.
 */
static int
sgfru_packet_pad(const caddr_t datap, const int max_cnt, fru_info_t *fru,
    packet_t *packp)
{
	caddr_t tdatap = datap;
	packet_t *pp;
	int i;

	tdatap = sgfru_fru_pad(datap, fru);
	if (max_cnt < fru->cnt)
		return (ENOMEM);
	for (i = 0, pp = packp; i < fru->cnt; i++, pp++) {
		bcopy(tdatap, (caddr_t)&pp->handle, FRU_HDL_SIZE);
		tdatap += FRU_HDL_SIZE;
		bcopy(tdatap, (caddr_t)&pp->tag, TAG_SIZE);
		tdatap += TAG_SIZE;
	}
	return (0);
}

/*
 * Used to unpad a C (Solaris) fru_info_t, in preparation for sending it to
 * Java (SCAPP).  Assumes a fru_info_t.
 */
static caddr_t
sgfru_fru_unpad(const fru_info_t *fru, caddr_t datap)
{
	caddr_t tdatap = datap;

	bcopy((caddr_t)&fru->hdl, tdatap, FRU_HDL_SIZE);
	tdatap += FRU_HDL_SIZE;
	bcopy((caddr_t)&fru->cnt, tdatap, FRU_CNT_SIZE);
	tdatap += FRU_CNT_SIZE;
	return (tdatap);
}

/*
 * Used to unpad a C (Solaris) segment, in preparation for sending it to
 * Java (SCAPP). Assumes a section_hdl_t and one segment_t.
 */
static void
sgfru_segment_unpad(const fru_info_t *fru, const segment_t *segp,
    caddr_t datap)
{
	caddr_t tdatap = datap;

	bcopy((caddr_t)&fru->hdl, tdatap, FRU_HDL_SIZE);
	tdatap += FRU_HDL_SIZE;
	bcopy((caddr_t)&segp->handle, tdatap, FRU_HDL_SIZE);
	tdatap += FRU_HDL_SIZE;
	bcopy((caddr_t)&segp->name, tdatap, NAME_SIZE);
	tdatap += NAME_SIZE;
	bcopy((caddr_t)&segp->descriptor, tdatap, DESCRIPTOR_SIZE);
	tdatap += DESCRIPTOR_SIZE;
	bcopy((caddr_t)&segp->offset, tdatap, OFFSET_SIZE);
	tdatap += OFFSET_SIZE;
	bcopy((caddr_t)&segp->length, tdatap, LENGTH_SIZE);
}

/*
 * Used to unpad a C (Solaris) packet, in preparation for sending it to
 * Java (SCAPP).  Assumes a fru_info_t and one packet_t.
 */
static caddr_t
sgfru_packet_unpad(const fru_info_t *fru, const packet_t *packp, caddr_t datap)
{
	caddr_t tdatap = datap;

	bcopy((caddr_t)&fru->hdl, tdatap, FRU_HDL_SIZE);
	tdatap += FRU_HDL_SIZE;
	bcopy((caddr_t)&fru->cnt, tdatap, FRU_CNT_SIZE);
	tdatap += FRU_CNT_SIZE;
	bcopy((caddr_t)&packp->handle, tdatap, FRU_HDL_SIZE);
	tdatap += FRU_HDL_SIZE;
	bcopy((caddr_t)&packp->tag, tdatap, TAG_SIZE);
	tdatap += TAG_SIZE;
	return (tdatap);
}
