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

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>


#include <sys/hdio.h>
#include <sys/dkio.h>
#include <sys/cdio.h>
#include <sys/dktp/dadkio.h>

#include <sys/dklabel.h>

#include <sys/vtoc.h>


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>


/* BSA specific header files */

#include <sys/i2o/i2omstr.h>
#include <sys/i2o/i2omsg.h>
#include <sys/i2o/i2outil.h>
#include <sys/dktp/fdisk.h>
#include <sys/dktp/altsctr.h>
#include "i2o_bs.h"


char _depends_on[] = "misc/i2o_msg";

static	int	bsa_read(dev_t, struct uio *, cred_t *);
static	int	bsa_write(dev_t, struct uio *, cred_t *);
static	int	bsa_strategy(register struct buf *);
static	int	bsa_attach(dev_info_t *, ddi_attach_cmd_t);
static	int	bsa_detach(dev_info_t *, ddi_detach_cmd_t);
static	int	bsa_open(dev_t *, int, int, cred_t *);
static	int	bsa_close(dev_t, int, int, cred_t *);
static	int	bsa_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static	int	bsa_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static	int	bsa_prop_op(dev_t, dev_info_t *, ddi_prop_op_t,
		    int, char *, caddr_t, int *);
static	int	bsa_print(dev_t, char *);
static	int	bsa_dump(dev_t, caddr_t, daddr_t, int);
static	int	create_minor_node(dev_info_t *, bsa_data_t *);
static	int	update_vtoc(struct bsa_data *, dev_t);
static	int	redo_vtoc(struct buf *, struct bsa_data *);


static	int	write_dskvtoc(struct bsa_data *, dev_t, dsk_label_t *,
		    struct vtoc *, struct cb_ops *);
static	int	translate_error(int, int, int);
static	void	bsa_reply(void *, ddi_acc_handle_t);
static	int	BsaPowerMgt(bsa_data_t *, int);
static	int	bsa_buf_setup(void **, dev_t, enum uio_seg, int);
static	void	cap_translation(uint64_t, int *, int *, int *);
static	int	bsa_setup(struct bsa_data *);
static	int	bsa_lbl_ioctl(dev_t, int, int, int);
static	void	geom_prep(struct dk_geom *, struct bsa_unit *);
static	void	BsaMediaUnlock_reply(void *, ddi_acc_handle_t);
static	int	BsaMediaUnlock(bsa_data_t *);
static	void	BsaMediaLock_reply(void *, ddi_acc_handle_t);
static	int	BsaMediaLock(bsa_data_t *);
static	void	BsaPowerMgt_reply(void *, ddi_acc_handle_t);
static	int	BsaPowerMgt(bsa_data_t *, int);
static	void	BsaMediaEject_reply(void *, ddi_acc_handle_t);
static	int	BsaMediaEject(bsa_data_t *);
static  int 	UtilEventRegister(bsa_data_t *, int);
static	void	UtilEventRegister_reply(void *, ddi_acc_handle_t);
static	void	UtilAbort_reply(void *, ddi_acc_handle_t);
static	int	UtilAbort(bsa_data_t *, int, uint8_t, uint64_t);
static	void	UtilNOP(i2o_iop_handle_t, ddi_acc_handle_t,
		i2o_common_message_t *, i2o_msg_handle_t);
static	int	UtilClaim_release(bsa_data_t *);
static	void	UtilClaim_release_reply(void *, ddi_acc_handle_t);
static	int	UtilClaim(bsa_data_t *);
static	void	UtilClaim_reply(void *, ddi_acc_handle_t);
static	void	UtilParamsGet_reply(void *, ddi_acc_handle_t);
static	int	UtilParamsGet(bsa_data_t *);
static	int	parse_lct(void *, size_t, bsa_data_t *, ddi_acc_handle_t);


extern int	parse_fdisk_lbl(struct buf *, dsk_label_t *, struct cb_ops *,
			struct dk_geom *, int);
extern void	dsklbl_read_label(struct buf *, dsk_label_t *, struct cb_ops *,
					struct dk_geom *, int type);
extern int	dsklbl_wrvtoc(dsk_label_t *, struct vtoc *, struct buf *,
					struct cb_ops *);
extern void	dsklbl_ondsklabel_to_vtoc(dsk_label_t *, struct vtoc *);
extern void	dsklbl_dgtoug(struct dk_geom *, struct dk_label *);
extern void	dsklbl_ugtodg(struct dk_geom *, struct dk_label *);

/*
 * Debug flag definitions.
 */
#define	I2O_DEBUG_DIO		0x0001 	/* disk specific info		*/
#define	I2O_DEBUG_DINT		0x0002  /* initialization		*/
#define	I2O_DEBUG_DLBL		0x0004	/* labeling info		*/
#define	I2O_DEBUG_GEN		0x0008	/* general debugging info	*/
#define	I2O_DEBUG_BADBLK	0x0009	/* Bad Block Debug		*/

#ifdef	BSA_DEBUG
int bsa_debug = I2O_DEBUG_DIO;

#define	DEBUGF(flag, args) \
	{ if (bsa_debug & (flag)) cmn_err args; }
#else
#define	DEBUGF(level, args)	/* nothing */
#endif

struct cb_ops bsa_cb_ops = {
		bsa_open,		/* driver open routine		*/
		bsa_close,		/* driver close routine		*/
		bsa_strategy,		/* driver strategy routine	*/
		bsa_print,		/* driver print routine		*/
		bsa_dump,		/* driver dump routine		*/
		bsa_read,		/* driver read routine		*/
		bsa_write,		/* driver write routine		*/
		bsa_ioctl,		/* driver ioctl routine		*/
		nodev,			/* driver devmap routine	*/
		nodev,			/* driver mmap routine		*/
		nodev,			/* driver segmap routine	*/
		nochpoll,		/* driver chpoll routine	*/
		bsa_prop_op,		/* driver prop_op routine	*/
		0,			/* driver cb_str - STREAMS only	*/
		D_64BIT|D_NEW | D_MTSAFE,	/* driver compatibility flag */
	};

static struct dev_ops bsa_ops = {
		DEVO_REV,		/* devo_rev, */
		0,			/* refcnt  */
		bsa_getinfo,		/* info */
		nulldev,		/* identify */
		nulldev,		/* probe */
		bsa_attach,		/* attach */
		bsa_detach,		/* detach */
		nulldev,		/* reset */
		&bsa_cb_ops,		/* driver operations */
		0,
	};

char	*i2o_bsa_name = I2O_BSA_NAME;		/* Global not local */
static void	*bsa_soft = NULL;

/*
 * The following is used for buffers allocated by ddi_dma_mem_alloc()
 */


/*
 * Several bugs in dma the -1 can not be used for sgllen since it is
 * defined as short and the count_max and addr_hi because of the bug
 * in the nexus can not be set to FFFFFFF.  It will over flow.
 */

static ddi_dma_attr_t dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version */
	0,				/* dma_attr_addr_lo */
	(uint64_t)0xFFFFFFFe,		/* dma_attr_addr_hi 64 bit address */
	(uint64_t)0xFFFFFFFe,		/* dma_attr_count_max */
	1,				/* dma_attr_align. We do not care */
	1,				/* dma_attr_burstsizes.We do not care */
	1,				/* dma_attr_minxfer */
	(uint64_t)0xFFFFFFFF,		/* dma_attr_maxxfer 64 bit address */
	(uint64_t)0xFFFFFFFF,		/* dma_attr_seg 64 bit */
	0xFFF,				/* dma_attr_sgllen. No limit in I2O */
	1,				/* dma_attr_granular */
	0,				/* dma_attr_flags */
};


/*
 * For SGL gain,  we need one contiguous buffer
 */
static ddi_dma_attr_t dma_attr_sglfrm = {
	DMA_ATTR_V0,			/* dma_attr version */
	0,				/* dma_attr_addr_lo */
	(uint64_t)0xFFFFFFFe,		/* dma_attr_addr_hi */
	(uint64_t)0xFFFFFFFe,		/* dma_attr_count_max. */
	1,				/* dma_attr_align */
	1,				/* dma_attr_burstsizes */
	1,				/* dma_attr_minxfer */
	(uint64_t)0xFFFFFFFF,		/* dma_attr_maxxfer */
	(uint64_t)0xFFFFFFFF,		/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	1,				/* dma_attr_granular */
	0,				/* dma_attr_flags */
};

/*
 * For LCT table.  We need one contiguous buffer
 */
static ddi_dma_attr_t dma_attr_lcttbl = {
	DMA_ATTR_V0,			/* dma_attr version */
	0,				/* dma_attr_addr_lo */
	(uint64_t)0xFFFFFFFe,		/* dma_attr_addr_hi */
	(uint64_t)0xFFFFFFFe,		/* dma_attr_count_max. 24 bit  */
	1,				/* dma_attr_align */
	1,				/* dma_attr_burstsizes */
	1,				/* dma_attr_minxfer */
	(uint64_t)0xFFFFFFFF,		/* dma_attr_maxxfer */
	(uint64_t)0xFFFFFFFF,		/* dma_attr_seg */
	1,				/* dma_attr_sgllen */
	1,				/* dma_attr_granular */
	0,				/* dma_attr_flags */
};


/* DMA access attributes */
static ddi_device_acc_attr_t accattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
};

#include <sys/modctl.h>

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module. This one is a driver */
	"I2O Block Storage OSM %I%",
	&bsa_ops, /* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * Set up the message
 * - set up the Standard Message frame fields:
 *			MsgFlags, InitiatorContext, Function, msgsize and TID
 *			MsgFlags need to be 0x2 in case of 64 bit
 */

#define	setup_msghdr(func, replyfunc, mp, acc_hdl, veroff, tid,		\
	    msgflags, msgsize)						\
	{								\
	    put_msg_Function((mp), (func), acc_hdl); 			\
	    (mp)->VersionOffset = (veroff);				\
	    (mp)->MsgFlags = (msgflags);				\
	    ddi_put16(acc_handle,					\
		&(mp)->MessageSize, (msgsize) >> 2);			\
	    put_msg_InitiatorAddress((mp), I2O_HOST_TID,		\
		acc_hdl);						\
	    put_msg_TargetAddress((mp), tid, acc_hdl);			\
	    ddi_put32(acc_hdl, (uint32_t *)&(mp)->InitiatorContext.	\
		initiator_context_32bits,  (uint32_t)replyfunc);	\
	}

int
_init(void)
{
	int	status;

	if (status = mod_install(&modlinkage))
		return (status);

	status = ddi_soft_state_init(&bsa_soft, sizeof (struct bsa_data), 1);

	return (status);
}


int
_fini(void)
{
	int	status;

	status = mod_remove(&modlinkage);
	if (!status)
		ddi_soft_state_fini(&bsa_soft);

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * The Block storage strategy routine
 */

int
bsa_strategy(struct buf *bp)
{
	struct bsa_unit *bsa_unit;
	struct bsa_data *bsadata;
	struct bsa_context *tcontextp = NULL;
	int instance;
	daddr_t blkno;
	unsigned long absblkno;

	i2o_msg_handle_t msg_handle;
	ddi_acc_handle_t acc_handle;
	ddi_acc_handle_t sgl_acchdl;
	uint_t nocookies;
	uint_t sgncookies;
	ddi_dma_cookie_t dma_cookie;
	ddi_dma_cookie_t dma_sgcookie;
	int bind = 0;
	int sgbind = 0;
	int flags;
	i2o_sge_simple_element_t  *sglbuf = NULL;
	i2o_sge_simple_element_t  *sgl = NULL;
	i2o_bsa_write_message_t *msgbuf = NULL;
	int	sgsize;
	int	numsgl;
	size_t	real_length;
	ssize_t	resid = 0;
	int	ret = 0;
	int	part;
	long	secnt, count;

#ifdef lint
	sgl_acchdl = NULL;
	acc_handle = sgl_acchdl;
#endif
	/*
	 * get instance number
	 */
	instance = UNIT(bp->b_edev);

	if (!(bsadata = ddi_get_soft_state(bsa_soft, instance))) {
		ret = ENXIO;
		goto out;
	}

	if (bp->b_bcount & (NBPSCTR-1)) {
		ret = ENXIO;
		goto out;
	}


	bsa_unit = &bsadata->unitp;

	DEBUGF(I2O_DEBUG_DIO, (CE_CONT, "?bsa_strategy:cyl = %d acyl = %d"
		" head = %d" "sec = %d\n",
		bsadata->unitp.au_cyl,
		bsadata->unitp.au_acyl,
		bsadata->unitp.au_hd,
		bsadata->unitp.au_sec));

	DEBUGF(I2O_DEBUG_DIO, (CE_CONT, "?bsa_strategy:bp->b_private = %d"
		"\n", bp->b_private));

	/*
	 * Reject CD write commands.
	 */

	if ((bsadata->unitp.au_type == DKC_CDROM) && !(bp->b_flags & B_READ)) {
		ret = EIO;
		goto out;
	}

	if ((bp->b_flags & B_PAGEIO) || (bp->b_flags & B_PHYS))
		bp_mapin(bp);

	bp->b_resid = 0;

	DEBUGF(I2O_DEBUG_GEN, (CE_CONT, "?bsa_strategy: %s request for buf:"
		"%x\n", bp->b_flags & B_READ ? "read" : "write", bp));

	blkno = dkblock(bp);

	part = LPART(bp->b_edev);

	/*
	 * Map block number within partition to absolute
	 * block number.
	 */

	DEBUGF(I2O_DEBUG_DIO, (CE_CONT, "?BS  d%d%c%d: "
			"%s block %d mapped to %ld dev %lx\n",
			instance, (part > 15 ? 'p' : 's'),
			(part > 15 ? part - 16 : part),
			bp->b_flags & B_READ ? "read" : "write", blkno,
			blkno + bsadata->lbl.pmap[part].p_start,
			bp->b_edev));
	DEBUGF(I2O_DEBUG_DIO, (CE_CONT, "? p_size = <%ld> <0x%lx>\n",
			bsadata->lbl.pmap[part].p_size,
			bsadata->lbl.pmap[part].p_size));

	if (bsadata->lbl.pmap[part].p_flag & V_INVALID) {
		ret = ENXIO;

		DEBUGF(I2O_DEBUG_DLBL, (CE_CONT, "?bs_strategy:"
			"invalid slice bp 0x%x\n", bp));
		goto out;
	}


	/*
	 * Make sure we don't run off the end of a partition.
	 */
	if ((bsadata->lbl.vtocread == 1) && (bp->b_private != (void *)0xBEE)) {
		secnt = (bp->b_bcount + (DEV_BSIZE - 1)) >> DEV_BSHIFT;
		count = MIN(secnt, (bsadata->lbl.pmap[part].p_size - blkno));

		DEBUGF(I2O_DEBUG_DLBL, (CE_CONT, "?bs_strategy:"
			"secnt = %d count = %d part = %d b_bcount =%d\n",
			secnt, count, part, bp->b_bcount));

		if (count != secnt) {
			if (count >= 0) {
				resid = (secnt - count) << DEV_BSHIFT;
				cmn_err(CE_CONT, "overrun by %ld sectors\n",
						    secnt - count);
				bp->b_bcount -= resid;
			} else {
				DEBUGF(I2O_DEBUG_DLBL, (CE_CONT,
				"I/O attempted beyond the end of partition"));
				ret = ENXIO;
				goto out;
			}
		}
	}
	absblkno = bsadata->lbl.pmap[part].p_start + blkno;

	/*
	 * Allocate transaction context
	 */

	tcontextp = (struct bsa_context *)kmem_zalloc(sizeof (bsa_context_t),
	    KM_SLEEP);
	tcontextp->bsadata = bsadata;


	bind = 0;
	sgbind = 0;

	if (ddi_dma_alloc_handle(bsadata->dip, &dma_attr, DDI_DMA_SLEEP, 0,
	    &tcontextp->dma_handle) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "?BS_strategy: No resources available\n");
		ret = ENOMEM;
		goto out;
	}

	flags = (bp->b_flags & B_READ) ? DDI_DMA_READ | DDI_DMA_STREAMING:
		DDI_DMA_WRITE | DDI_DMA_STREAMING;

	ret = ddi_dma_buf_bind_handle(tcontextp->dma_handle, bp,
		flags, DDI_DMA_SLEEP, 0, &dma_cookie, &nocookies);

	switch (ret) {
	case DDI_DMA_MAPPED:
		/*
		 * This flag used in case of error to unbind the DMA handle
		 * The address is bound to DMA handle
		 */
		bind = 1;
		break;

	case DDI_DMA_NORESOURCES:
		ret = ENOMEM;
		cmn_err(CE_CONT, "?bsa_strategy: No DMA resources available\n");
		goto out;

	case DDI_DMA_INUSE:
	case DDI_DMA_TOOBIG:
		ret = EINVAL;
		goto out;

	case DDI_DMA_NOMAPPING:
	default:
		ret = EFAULT;
		cmn_err(CE_CONT, "?bsa_strategy: DMA failed 0x%x\n", ret);
		goto out;
	}

	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */

	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?bsa_strategy: Frame buffer "
			"resource not available\n");
		ret = ENOMEM;
		goto out;
	}

	/*
	 * Note that the MessageSize is multiples of 4 byte, hence the shift
	 */

	sgsize = ((ddi_get16(acc_handle,
	    &msgbuf->StdMessageFrame.MessageSize)) << 2) -
	    (sizeof (i2o_message_frame_t) +
	    sizeof (i2o_transaction_context_t) +
	    sizeof (i2o_bsa_read_flags_t) +
	    (2 * (sizeof (uint8_t)))+
	    sizeof (uint32_t)	+
	    sizeof (uint64_t));

	/*
	 * If we can not fit all the SGL elements in the Frame we need to
	 * create a SGL chain which will contain all the SGL elements.
	 */
	if (nocookies <= (sgsize/sizeof (i2o_sge_simple_element_t))) {
		/* we can place the SGL within the MSG frame */
		sgl = &msgbuf->SGL.u1.Simple[0];
		sgl_acchdl =  acc_handle;
		numsgl = nocookies;
	} else {
		i2o_sge_chain_element_t  *sgl_chainp = NULL;

		/*
		 * allocate buffer to hold the SGL list.
		 * I2O only accepts one SGL chain buf.  So we
		 * need one contigous segment.  (1 cookie).
		 */

		if ((ddi_dma_alloc_handle(tcontextp->bsadata->dip,
		    &dma_attr_sglfrm,
		    DDI_DMA_SLEEP, 0, &tcontextp->dma_sghandle))
		    != DDI_SUCCESS) {
			ret = ENOMEM;
			cmn_err(CE_CONT, "?bsa_strategy: No resources "
			    "available\n");
			if (msgbuf)
				UtilNOP(bsadata->iop, acc_handle,
				(i2o_common_message_t *)msgbuf, msg_handle);
			goto out;

		}

		if ((ddi_dma_mem_alloc(tcontextp->dma_sghandle,
		    (size_t)(nocookies * sizeof (i2o_sge_simple_element_t)),
		    &accattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
		    (caddr_t *)&sglbuf, &real_length,
		    &tcontextp->acc_sghandle)) != DDI_SUCCESS) {

			ret = ENOMEM;
			cmn_err(CE_CONT, "?bsa_strategy: No resources "
			    "available\n");
			if (msgbuf)
				UtilNOP(bsadata->iop, acc_handle,
				(i2o_common_message_t *)msgbuf, msg_handle);
			goto out;
		}


		ret = ddi_dma_addr_bind_handle(tcontextp->dma_sghandle, NULL,
			(caddr_t)sglbuf, real_length,
			DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
			&dma_sgcookie, &sgncookies);

		/*
		 * This flag used in case of error to unbind
		 */

		switch (ret) {
		case DDI_DMA_MAPPED:
			/*
			 * This flag used in case of error to unbind the DMA
			 * handle The address is bound to DMA handle
			 */
			sgbind = 1;
			break;
		case DDI_DMA_NORESOURCES:
			ret = ENOMEM;
			cmn_err(CE_CONT, "?bsa_strategy:"
				" No DMA resources available\n");
			if (msgbuf)
				UtilNOP(bsadata->iop, acc_handle,
				(i2o_common_message_t *)msgbuf, msg_handle);
			goto out;

		case DDI_DMA_INUSE:
		case DDI_DMA_TOOBIG:
			ret = ENOMEM;
			if (msgbuf)
				UtilNOP(bsadata->iop, acc_handle,
				(i2o_common_message_t *)msgbuf, msg_handle);
			goto out;

		case DDI_DMA_NOMAPPING:
		default:
			ret = EFAULT;
			cmn_err(CE_CONT, "?bsa_strategy:"
				" DMA failed 0x%x\n", ret);
			if (msgbuf)
				UtilNOP(bsadata->iop, acc_handle,
				(i2o_common_message_t *)msgbuf, msg_handle);

			goto out;
		}

		/*
		 * In the MSG frame initialize the chain element and
		 * followed by sgl_ignore element (this seems necessary?)
		 */
		sgl_chainp = &msgbuf->SGL.u1.Chain;

		put_flags_count_Count(&sgl_chainp[0].FlagsCount,
		    real_length, acc_handle);


		put_flags_count_Flags(&sgl_chainp[0].FlagsCount,
		    I2O_SGL_FLAGS_CHAIN_POINTER_ELEMENT, acc_handle);

		ddi_put32(acc_handle, &sgl_chainp[0].PhysicalAddress,
		    (uint32_t)dma_sgcookie.dmac_address);


		put_flags_count_Count(&sgl_chainp[1].FlagsCount,
		    real_length, acc_handle);


		put_flags_count_Flags(&sgl_chainp[1].FlagsCount,
		    I2O_SGL_FLAGS_IGNORE_ELEMENT | I2O_SGL_FLAGS_LAST_ELEMENT,
		    acc_handle);

		/* set the SGL list pointer to the allocated buffer */
		sgl = (i2o_sge_simple_element_t *)sglbuf;
		sgl_acchdl =  tcontextp->acc_sghandle;
		numsgl = 2;
	}

	/*
	 * copy the cookies to the SGL list.
	 */

	while (nocookies) {
		put_flags_count_Count(&sgl->FlagsCount, dma_cookie.dmac_size,
		    sgl_acchdl);
		put_flags_count_Flags(&sgl->FlagsCount,
		    I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT, sgl_acchdl);
		ddi_put32(acc_handle, &sgl->PhysicalAddress,
		    dma_cookie.dmac_address);

		if (!(--nocookies)) {
		    put_flags_count_Flags(&sgl->FlagsCount,
		    I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT |
		    I2O_SGL_FLAGS_LAST_ELEMENT |
		    I2O_SGL_FLAGS_END_OF_BUFFER, sgl_acchdl);
		    break;
		}

		ddi_dma_nextcookie(tcontextp->dma_handle, &dma_cookie);
		sgl++;
	}


	/*
	 * Set up the Standard Message frame fields
	 */

	setup_msghdr((bp->b_flags & B_READ ? I2O_BSA_BLOCK_READ :
	    I2O_BSA_BLOCK_WRITE), bsa_reply, &msgbuf->StdMessageFrame,
	    acc_handle, 0x81, bsadata->tid, 0,
	    sizeof (i2o_bsa_write_message_t) +
	    (numsgl * sizeof (i2o_sge_simple_element_t)) -
	    sizeof (i2o_sg_element_t));


	ddi_put32(acc_handle, &msgbuf->TransferByteCount, bp->b_bcount);
	ddi_put64(acc_handle, &msgbuf->LogicalByteAddress,
			(((uint64_t)(absblkno)) * bsa_unit->au_blksize));

	ddi_put16(acc_handle, &msgbuf->ControlFlags, 0);
	ddi_put8(acc_handle, &msgbuf->TimeMultiplier, 1);

	/*
	 * Set the Transaction Context field (used for reply correlation)
	 */

#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext,
	    (uint32_t)tcontextp);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
	    (uint32_t)(uintptr_t)tcontextp);
#endif

	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?bsa_strategy: i2o_msg_send failed");
		ret = ENOMEM;
		goto out;
	}

	/*
	 * Wait until the reply is done
	 * do a cv_wait here from reply
	 */
	mutex_enter(&bsadata->bsa_mutex);
	while (!(tcontextp->rwreplyflag & REPLY_DONE))
		cv_wait(&bsadata->rwreply_cv, &bsadata->bsa_mutex);
	mutex_exit(&bsadata->bsa_mutex);

	if ((ret = tcontextp->retval) != 0) {
		cmn_err(CE_CONT, "? bsa_strategy:Error %d. Operation on "
			"block %ld failed. det Error 0x%x."
			"\n", ret, absblkno, tcontextp->deterror);
		DEBUGF(I2O_DEBUG_BADBLK, (CE_CONT, "?bsa_strategy:Error %d."
			"Operation on block <%d> maped to %ld failed."
			"det Error %x.\n", ret, dkblock(bp), absblkno,
			tcontextp->deterror));

		DEBUGF(I2O_DEBUG_BADBLK, (CE_CONT, "?BS  d%d%c%d: "
			"%s block %d mapped to %ld dev %lx\n",
			instance, (part > 15 ? 'p' : 's'),
			(part > 15 ? part - 16 : part),
			bp->b_flags & B_READ ? "read" : "write", dkblock(bp),
			dkblock(bp) + bsadata->lbl.pmap[part].p_start,
			bp->b_edev));
		DEBUGF(I2O_DEBUG_BADBLK, (CE_CONT, "? p_size = <%ld> <0x%lx>\n",
			bsadata->lbl.pmap[part].p_size,
			bsadata->lbl.pmap[part].p_size));

		goto out;
	}

	/*
	 * free up the resources (unbind, free buff, free handle).
	 */
	if (sgbind)
		(void) ddi_dma_unbind_handle(tcontextp->dma_sghandle);
	if (sglbuf)
		ddi_dma_mem_free(&tcontextp->acc_sghandle);
	if (tcontextp)
		if (tcontextp->dma_sghandle)
			ddi_dma_free_handle(&tcontextp->dma_sghandle);
	if (bind)
		(void) ddi_dma_unbind_handle(tcontextp->dma_handle);
	if (tcontextp)
		if (tcontextp->dma_handle)
			ddi_dma_free_handle(&tcontextp->dma_handle);
	if (tcontextp)
		kmem_free(tcontextp, sizeof (bsa_context_t));


	/*
	 * In Intel land if the disk block to be written to is disk block 0,
	 * it would mean the partition table is changing from underneath us
	 * we shoud trap and update the in memory image.
	 * By now the buffer is mapped in and we should be able to
	 * use the contents as the new fdisk partition.
	 */
#if defined(_SUNOS_VTOC_16)
	if (!(bp->b_flags & B_READ) &&
	    ((bp->b_flags & B_ERROR) != B_ERROR) && absblkno == 0) {
		(void) redo_vtoc(bp, bsadata);
	}
#endif
	biodone(bp);
	return (0);

out:
	/* return FAILURE */

	if (sgbind)
		(void) ddi_dma_unbind_handle(tcontextp->dma_sghandle);
	if (sglbuf)
		ddi_dma_mem_free(&tcontextp->acc_sghandle);
	if (tcontextp)
		if (tcontextp->dma_sghandle)
			ddi_dma_free_handle(&tcontextp->dma_sghandle);
	if (bind)
		(void) ddi_dma_unbind_handle(tcontextp->dma_handle);
	if (tcontextp)
		if (tcontextp->dma_handle)
			ddi_dma_free_handle(&tcontextp->dma_handle);
	if (tcontextp)
		kmem_free(tcontextp, sizeof (bsa_context_t));


	bp->b_resid = bp->b_bcount;
	bioerror(bp, ret);
	biodone(bp);
	return (0);
}

/*
 * Redo the vtoc.  This is done whenever the vtoc is changes under us.
 */

static int
redo_vtoc(struct buf *fdiskbp, struct bsa_data *bsadata)
{
	struct dk_geom dkg;
	struct buf *bp;
	int	status;
	dev_t	dev;
	char	*secbuf;


	dev = makedevice(getmajor(fdiskbp->b_edev),
		BSA_SETMINOR(bsadata->instance, FDISK_OFFSET));

	DEBUGF(I2O_DEBUG_DLBL, (CE_CONT, "?redo_vtoc: dev = %x\n", dev));
	/*
	 * Allocate a temporary block for labeling use.
	 */

	secbuf = kmem_zalloc(NBPSCTR, KM_SLEEP);

	bp = getrbuf(KM_SLEEP);

	bp->b_edev = dev;
	bp->b_dev  = cmpdev(dev);
	bp->b_flags = B_BUSY;
	bp->b_resid = 0;
	bp->b_bcount = NBPSCTR;
	bp->b_un.b_addr = (caddr_t)secbuf;

	DEBUGF(I2O_DEBUG_DLBL, (CE_CONT, "?redo_vtoc"
		"edev = %x dev = %x\n", bp->b_edev, bp->b_dev));

	bcopy(fdiskbp->b_un.b_addr, bp->b_un.b_addr, NBPSCTR);

	geom_prep(&dkg, &bsadata->unitp);

	status = parse_fdisk_lbl(bp, &bsadata->lbl,
	    &bsa_cb_ops, &dkg, bsadata->unitp.au_type);

	/*
	 * Free the temporary block allocated for labeling purposes
	 */
	kmem_free(bp->b_un.b_addr, NBPSCTR);
	freerbuf(bp);


	if (status == DDI_FAILURE)
		return (EFAULT);
	else
		return (0);
}

/*
 * Update the vtoc
 */

static int
update_vtoc(struct bsa_data *bsadata, dev_t dev)
{
	struct dk_geom dkg;
	struct buf *bp;
	dev_t	newdev;
	char	*secbuf;

	/*
	 * Get a dev with specific minor number
	 */

	newdev = makedevice(getmajor(dev),
		BSA_SETMINOR(bsadata->instance, FDISK_OFFSET));

	DEBUGF(I2O_DEBUG_DLBL, (CE_CONT, "?update_vtoc newdev = %x\n", newdev));
	/*
	 * Allocate a temporary block for labeling use.
	 */

	secbuf = kmem_zalloc(NBPSCTR, KM_SLEEP);

	bp = getrbuf(KM_SLEEP);

	bp->b_edev = newdev;
	bp->b_dev  = cmpdev(newdev);
	bp->b_flags = B_BUSY;
	bp->b_resid = 0;
	bp->b_bcount = NBPSCTR;
	bp->b_un.b_addr = (caddr_t)secbuf;

	DEBUGF(I2O_DEBUG_DLBL, (CE_CONT, "?update_vtoc:"
		"edev = %x newdev = %x\n", bp->b_edev, bp->b_dev));

	geom_prep(&dkg, &bsadata->unitp);
	dsklbl_read_label(bp, &bsadata->lbl, &bsa_cb_ops, &dkg,
	    bsadata->unitp.au_type);

	/*
	 * Free the temporary block allocated for labeling purposes
	 */
	kmem_free(bp->b_un.b_addr, NBPSCTR);
	freerbuf(bp);

	return (0);
}


/*
 * Write the Vtoc
 */


static int
write_dskvtoc(struct bsa_data *bsadata, dev_t dev, dsk_label_t *lblp,
		struct vtoc *vtocp, struct cb_ops *dev_ops)
{
	struct buf *bp;
	int	status;
	char	*secbuf;


	dev = makedevice(getmajor(dev),
		BSA_SETMINOR(bsadata->instance, FDISK_OFFSET));
	/*
	 * Allocate a temporary block for labeling use.
	 */
	secbuf = kmem_zalloc(NBPSCTR, KM_SLEEP);

	bp = getrbuf(KM_SLEEP);

	bp->b_edev = dev;
	bp->b_dev  = cmpdev(dev);
	bp->b_flags = B_BUSY;
	bp->b_resid = 0;
	bp->b_bcount = NBPSCTR;
	bp->b_un.b_addr = (caddr_t)secbuf;


	DEBUGF(I2O_DEBUG_DLBL, (CE_CONT, "?write_dskvtoc:"
		"edev = %x dev = %x\n", bp->b_edev, bp->b_dev));

	status = dsklbl_wrvtoc(lblp, vtocp, bp, dev_ops);

	/*
	 * Free the temporary block allocated for labeling purposes
	 */
	kmem_free(bp->b_un.b_addr, NBPSCTR);
	freerbuf(bp);

	return (status);
}


/*
 * Reply call back function
 */

static void
bsa_reply(void *msg, ddi_acc_handle_t acc_handle)
{

	bsa_context_t	*tcontextp;	/* Context field	*/
	int detstatus;			/* detailed status	*/
	int reqstatus;			/* request status	*/


	/*
	 * Correlate replies with appropriate request, based on
	 * the content of the Transaction Context field. 3.4.1.2.1
	 * Used context structure in strategy routine. Which bp is part
	 * of it.
	 */

	/*
	 * Get the Transacton Context field
	 */

#if I2O_64BIT_CONTEXT
	tcontextp = (bsa_context_t *)ddi_get64(acc_handle,
	    &(((i2o_single_reply_message_frame_t *)msg)->TransactionContext));
#else
	tcontextp = (bsa_context_t *)(uintptr_t)ddi_get32(acc_handle,
	    &(((i2o_single_reply_message_frame_t *)msg)->TransactionContext));
#endif

	/*
	 * Detailed status
	 */

	detstatus = ddi_get16(acc_handle,
	    &((i2o_single_reply_message_frame_t *)msg)->DetailedStatusCode);

	/*
	 * reply status
	 */
	reqstatus = ((i2o_single_reply_message_frame_t *)msg)->ReqStatus;

	tcontextp->retval = translate_error(reqstatus, detstatus, 0);
	tcontextp->deterror = detstatus;

	/*
	 * Let the strategy routine to continue
	 */

	mutex_enter(&tcontextp->bsadata->bsa_mutex);
	tcontextp->rwreplyflag |= REPLY_DONE;
	cv_broadcast(&tcontextp->bsadata->rwreply_cv);
	mutex_exit(&tcontextp->bsadata->bsa_mutex);
}

/*
 * Translate the error
 */


#ifdef BSA_DEBUG
struct err_map {
	int	errorval;
	char	*errstr;
};

static struct err_map i2o_errtab[] = {
	{ I2O_REPLY_STATUS_SUCCESS,
		"SUCCESS" },
	{ I2O_REPLY_STATUS_ABORT_DIRTY,
		"ABORT_DIRTY" },
	{ I2O_REPLY_STATUS_ABORT_NO_DATA_TRANSFER,
		"ABORT_NO_DATA_TRANSFER" },
	{ I2O_REPLY_STATUS_ABORT_PARTIAL_TRANSFER,
		"ABORT_PARTIAL_TRANSFER" },
	{ I2O_REPLY_STATUS_ERROR_DIRTY,
		"ERROR_DIRTY" },
	{ I2O_REPLY_STATUS_ERROR_NO_DATA_TRANSFER,
		"ERROR_NO_DATA_TRANSFER" },
	{ I2O_REPLY_STATUS_ERROR_PARTIAL_TRANSFER,
		"ERROR_PARTIAL_TRANSFER" },
	{ I2O_REPLY_STATUS_PROCESS_ABORT_DIRTY,
		"PROCESS_ABORT_DIRTY" },
	{ I2O_REPLY_STATUS_PROCESS_ABORT_NO_DATA_TRANSFER,
		"PROCESS_ABORT_NO_DATA_TRANSFER" },
	{ I2O_REPLY_STATUS_PROCESS_ABORT_PARTIAL_TRANSFER,
		"PROCESS_ABORT_PARTIAL_TRANSFER" },
	{ I2O_REPLY_STATUS_TRANSACTION_ERROR,
		"TRANSACTION_ERROR" },
	{ I2O_REPLY_STATUS_PROGRESS_REPORT,
		"PROGRESS_REPORT" },
};



static struct err_map util_errtab[] = {
	{ I2O_DETAIL_STATUS_SUCCESS,
		"SUCCESS" },
	{ I2O_DETAIL_STATUS_BAD_KEY,
		"BAD_KEY" },
	{ I2O_DETAIL_STATUS_TCL_ERROR,
		"TCL_ERROR" },
	{ I2O_DETAIL_STATUS_REPLY_BUFFER_FULL,
		"REPLY_BUFFER_FULL" },
	{ I2O_DETAIL_STATUS_NO_SUCH_PAGE,
		"NO_SUCH_PAGE" },
	{ I2O_DETAIL_STATUS_INSUFFICIENT_RESOURCE_SOFT,
		"INSUFFICIENT_RESOURCE_SOFT" },
	{ I2O_DETAIL_STATUS_INSUFFICIENT_RESOURCE_HARD,
		"INSUFFICIENT_RESOURCE_HARD" },
	{ I2O_DETAIL_STATUS_CHAIN_BUFFER_TOO_LARGE,
		"CHAIN_BUFFER_TOO_LARGE" },
	{ I2O_DETAIL_STATUS_UNSUPPORTED_FUNCTION,
		"UNSUPPORTED_FUNCTION" },
	{ I2O_DETAIL_STATUS_DEVICE_LOCKED,
		"DEVICE_LOCKED" },
	{ I2O_DETAIL_STATUS_DEVICE_RESET,
		"DEVICE_RESET" },
	{ I2O_DETAIL_STATUS_INAPPROPRIATE_FUNCTION,
		"INAPPROPRIATE_FUNCTION" },
	{ I2O_DETAIL_STATUS_INVALID_INITIATOR_ADDRESS,
		"INVALID_INITIATOR_ADDRESS" },
	{ I2O_DETAIL_STATUS_INVALID_MESSAGE_FLAGS,
		"INVALID_MESSAGE_FLAGS" },
	{ I2O_DETAIL_STATUS_INVALID_OFFSET,
		"INVALID_OFFSET" },
	{ I2O_DETAIL_STATUS_INVALID_PARAMETER,
		"INVALID_PARAMETER" },
	{ I2O_DETAIL_STATUS_INVALID_REQUEST,
		"INVALID_REQUEST" },
	{ I2O_DETAIL_STATUS_INVALID_TARGET_ADDRESS,
		"INVALID_TARGET_ADDRESS" },
	{ I2O_DETAIL_STATUS_MESSAGE_TOO_LARGE,
		"MESSAGE_TOO_LARGE" },
	{ I2O_DETAIL_STATUS_MESSAGE_TOO_SMALL,
		"MESSAGE_TOO_SMALL" },
	{ I2O_DETAIL_STATUS_MISSING_PARAMETER,
		"MISSING_PARAMETER" },
	{ I2O_DETAIL_STATUS_TIMEOUT,
		"TIMEOUT" },
	{ I2O_DETAIL_STATUS_UNKNOWN_ERROR,
		"UNKNOWN_ERROR" },
	{ I2O_DETAIL_STATUS_UNKNOWN_FUNCTION,
		"UNKNOWN_FUNCTION" },
	{ I2O_DETAIL_STATUS_UNSUPPORTED_VERSION,
		"UNSUPPORTED_VERSION" },
	{ I2O_DEATIL_STATUS_DEVICE_BUSY,
		"DEVICE_BUSY" },
	{ I2O_DETAIL_STATUS_DEVICE_NOT_AVAILABLE,
		"DEVICE_NOT_AVAILABLE" },
};

static struct err_map bsa_errtab[] = {
	{ I2O_BSA_DSC_SUCCESS,
		"SUCCESS" },
	{ I2O_BSA_DSC_MEDIA_ERROR,
		"MEDIA_ERROR" },
	{ I2O_BSA_DSC_ACCESS_ERROR,
		"ACCESS_ERROR" },
	{ I2O_BSA_DSC_DEVICE_FAILURE,
		"DEVICE_FAILURE" },
	{ I2O_BSA_DSC_DEVICE_NOT_READY,
		"DEVICE_NOT_READY" },
	{ I2O_BSA_DSC_MEDIA_NOT_PRESENT,
		"MEDIA_NOT_PRESENT" },
	{ I2O_BSA_DSC_MEDIA_LOCKED,
		"MEDIA_LOCKED" },
	{ I2O_BSA_DSC_MEDIA_FAILURE,
		"MEDIA_FAILURE" },
	{ I2O_BSA_DSC_PROTOCOL_FAILURE,
		"PROTOCOL_FAILURE" },
	{ I2O_BSA_DSC_BUS_FAILURE,
		"BUS_FAILURE" },
	{ I2O_BSA_DSC_ACCESS_VIOLATION,
		"ACCESS_VIOLATION" },
	{ I2O_BSA_DSC_WRITE_PROTECTED,
		"WRITE_PROTECTED" },
	{ I2O_BSA_DSC_DEVICE_RESET,
		"DEVICE_RESET" },
	{ I2O_BSA_DSC_VOLUME_CHANGED,
		"VOLUME_CHANGED" },
	{ I2O_BSA_DSC_TIMEOUT,
		"TIMEOUT" },
};

#endif

/*
 * Translate the error
 */

/*ARGSUSED*/
static int
translate_error(int reqstatus, int detstatus, int utilflag)
{
#ifdef BSA_DEBUG
	char	*bsastr = "Unknown reason";
	char	*i2ostr = "Unknown reason";
	char	*utilstr = "Unknown reason";
	int	i;
#endif

	if (reqstatus == I2O_REPLY_STATUS_SUCCESS &&
	    detstatus == I2O_BSA_DSC_SUCCESS)
		return (0);

#ifdef BSA_DEBUG

	for (i = 0; i < sizeof (i2o_errtab)/sizeof (struct err_map); i++) {
		if (i2o_errtab[i].errorval == reqstatus) {
			i2ostr = i2o_errtab[i].errstr;
			break;
		}
	}

	/*
	 * Util functions Detailed error
	 */

	if (utilflag) {
		for (i = 0; i < sizeof (util_errtab)/sizeof (struct err_map);
		    i++) {
			if (util_errtab[i].errorval == detstatus) {
				utilstr = util_errtab[i].errstr;
				break;
			}
		}
	} else {

		for (i = 0; i < sizeof (bsa_errtab)/sizeof (struct err_map);
		    i++) {
			if (bsa_errtab[i].errorval == detstatus) {
			bsastr = bsa_errtab[i].errstr;
			break;
			}
		}
	}

	DEBUGF(I2O_DEBUG_GEN, (CE_CONT, "?i2o_bs: %s. Error code = 0x%x\n",
		i2ostr, reqstatus));


	if (utilflag) {
		DEBUGF(I2O_DEBUG_GEN, (CE_CONT, "?I2o_bs: %s. Error code = 0x%x"
			" \n", utilstr, detstatus));
	} else {
		DEBUGF(I2O_DEBUG_GEN, (CE_CONT, "?I2o_bs: %s. Error code = 0x%x"
			" \n", bsastr, detstatus));
	}
#endif
	return (EIO);
}


/*
 * attach routine for Block Stroage
 */


static int
bsa_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{

	i2o_iop_handle_t handle = NULL;	/* IOP handle to be initialized. */
	uint_t	tid;			/* Target id of I2O device	 */
	caddr_t	*buf = NULL;		/* Buffer that keeps the LCT table */
	size_t	real_length;
	int	instance;
	size_t	buf_size = 0;
	size_t	lct_size;
	size_t  real_size;
	int	mask = 0;
	major_t		devmajor;

	ddi_acc_handle_t	acc_handle = NULL;
	ddi_dma_handle_t	dma_handle = NULL; /* DMA Handle */

	struct bsa_data *bsadata = NULL;

	/*
	 * resume from a checkpoint  none of the DDM provided this so just ignor
	 */

	if (cmd == DDI_RESUME) {
		/*
		 * Power Up, load: power up the device completely and load
		 * medium, if present.  We assume all the pointers are
		 * correct. Since we are resuming
		 */

		instance = ddi_get_instance(dip);
		bsadata = ddi_get_soft_state(bsa_soft, instance);

		if (BsaPowerMgt(bsadata, I2O_BSA_POWER_MGT_POWER_UP_LOAD))
			return (DDI_FAILURE);

		return (DDI_SUCCESS);
	}

	if (cmd != DDI_ATTACH) {
		DEBUGF(I2O_DEBUG_GEN, (CE_CONT, "?bs_attach:"
			"returning FAILURE\n"));
		return (DDI_FAILURE);
	}

	/*
	 * register the OSM with the IOP
	 */

	if (i2o_msg_osm_register(dip, &handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "BSA OSM's registeration failed\n");
		return (DDI_FAILURE);
	}

	/*
	 * Get the size of LCT
	 */

	if (i2o_msg_get_lct(handle, NULL, buf_size, &lct_size, &real_size) ==
	    DDI_FAILURE) {
		cmn_err(CE_CONT, "Could not acquire the configuration table\n");
		goto out;
	}

	/*
	 * allocate buffer for LCT table
	 */

	if (ddi_dma_alloc_handle(dip, &dma_attr_lcttbl,
		    DDI_DMA_SLEEP, 0, &dma_handle) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "?bsa_attach: No resources available\n");
		goto out;
	}


	if (ddi_dma_mem_alloc(dma_handle, lct_size,
			&accattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
			(caddr_t *)&buf, &real_length, &acc_handle)
			!= DDI_SUCCESS) {
		cmn_err(CE_CONT, "?bsa_attach: No resources available\n");
		goto out;
	}

	/*
	 * Get a copy of LCT
	 */

	if (i2o_msg_get_lct(handle, buf, lct_size, NULL, NULL) ==
	    DDI_FAILURE) {
		cmn_err(CE_CONT, "could not acquire the configuration table\n");
		goto out;
	}


	if ((tid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "i2o-device-id", -1)) == -1) {

		cmn_err(CE_CONT, "?bsa_attach: unable to get the Tid\n");
		goto out;
	}

	/*
	 * Allocate soft state associated with this instance.
	 */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(bsa_soft, instance) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_GEN, (CE_CONT, "?bsa_attach:"
			"Unable to alloc state\n"));
		goto out;
	}

	/* Initialize the conditional variable and the mutex */
	bsadata = ddi_get_soft_state(bsa_soft, instance);
	bsadata->dip = dip;
	bsadata->instance = instance;
	bsadata->crashbuf = getrbuf(KM_SLEEP);

	bsadata->tid = tid;			/* Target ID of the I2O dev */
	bsadata->iop = handle;			/* IOP access handle	*/
	bsadata->open_flag = 0;			/* open flag	*/

	cv_init(&bsadata->reply_cv, NULL, CV_DRIVER, NULL);
	cv_init(&bsadata->state_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&bsadata->bsa_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&bsadata->lbl.mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * parse the lct table to find out if the device is free or not
	 */

	if (parse_lct(buf, lct_size, bsadata, acc_handle)) {
		goto out;
	}

	ddi_report_dev(dip);  /* announce the drive */

	devmajor = ddi_name_to_major(i2o_bsa_name);

	/*
	 * Create minor nodes.
	 */
	if (create_minor_node(dip, bsadata) == DDI_FAILURE) {
		goto out;
	}

	/* get the capacity and type */

	if (bsa_setup(bsadata)) {

		cmn_err(CE_CONT, "?bsa_attach: Unable to setup geometry\n");
		goto out;
	}

	/*
	 * read the label
	 */
	mutex_enter(&bsadata->lbl.mutex);
	if (update_vtoc(bsadata, makedevice(devmajor,
	    BSA_SETMINOR(bsadata->instance, FDISK_OFFSET)))) {
		mutex_exit(&bsadata->lbl.mutex);
		goto out;
	}
	mutex_exit(&bsadata->lbl.mutex);


	/*
	 * Register to receive event notification
	 */

	mask =  I2O_EVENT_IND_STATE_CHANGE | I2O_EVENT_IND_DEVICE_STATE |
		I2O_EVENT_IND_DEVICE_RESET | I2O_EVENT_IND_CAPABILITY_CHANGE |
		I2O_BSA_EVENT_VOLUME_LOAD  | I2O_BSA_EVENT_CAPACITY_CHANGE |
		I2O_UTIL_EVENT_ACKNOWLEDGE | I2O_BSA_EVENT_VOLUME_UNLOAD;

	if (UtilEventRegister(bsadata, mask))
		cmn_err(CE_CONT, "?Could not register for event notification"
			"for tid = %d\n", bsadata->tid);

	/* free up the resources */
	ddi_dma_mem_free(&acc_handle);
	ddi_dma_free_handle(&dma_handle);

	return (DDI_SUCCESS);

out:
	/*
	 * release all dma resources
	 */

	if (buf)
		ddi_dma_mem_free(&acc_handle);

	if (dma_handle)
		ddi_dma_free_handle(&dma_handle);

	if (bsadata) {
		if (bsadata->flags & CLAIMED)
			if (UtilClaim_release(bsadata)) {
				cmn_err(CE_CONT, "?bsa_attach: Unable to"
					"unclaim the %d device\n",
						bsadata->tid);

			}
		/*
		 * free the soft_state structure here.
		 */
		ddi_soft_state_free(bsa_soft, instance);
	}

	if (handle)
		i2o_msg_osm_unregister(&handle);

	return (DDI_FAILURE);

}

/*
 * The detach routine for Block Storage
 */

static int
bsa_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int	instance = ddi_get_instance(devi);
	struct bsa_data *bsadata;
	int	event;


	bsadata = ddi_get_soft_state(bsa_soft, instance);

	if (cmd == DDI_SUSPEND) {
		/*
		 * Power down, unload: fully power down the device, unloading
		 * the volume, if present.
		 */
		if (BsaPowerMgt(bsadata, I2O_BSA_POWER_MGT_POWER_DOWN_UNLOAD))
			return (DDI_FAILURE);

		return (DDI_SUCCESS);
	}

	if (cmd != DDI_DETACH)
		return (EINVAL);

	/*
	 * Stop receiving any events of any category
	 */
	event = 0;
	if (UtilEventRegister(bsadata, event)) {

		cmn_err(CE_CONT, "?bs_detach: Unable to stop receiving"
			"events from IOP\n");
		return (DDI_FAILURE);


	}

	/*
	 * Clean Wild Abort.  Abort all messages form this initiator
	 * (any function, and TransactionContext).
	 */

	if (UtilAbort(bsadata, I2O_ABORT_TYPE_CLEAN_WILD_ABORT, NULL, NULL)) {
		cmn_err(CE_CONT, "?bs_detach: Unable to abort all messages\n");
		return (DDI_FAILURE);
	}

	/*
	 * Release the device that Claimed in attach
	 */

	if (UtilClaim_release(bsadata)) {
		cmn_err(CE_CONT, "?bs_detach: Unable to unclaim the %d"
			"device\n", bsadata->tid);
		return (DDI_FAILURE);

	}

	i2o_msg_osm_unregister(&bsadata->iop);

	/*
	 * Remove all the minor nodes for this dip
	 */

	ddi_remove_minor_node(devi, NULL);

	mutex_destroy(&bsadata->bsa_mutex);
	mutex_destroy(&bsadata->lbl.mutex);
	/*
	 * free the soft_state structure here.
	 */
	ddi_soft_state_free(bsa_soft, instance);

	DEBUGF(I2O_DEBUG_GEN, (CE_CONT, "?sucessfull detach\n"));

	return (DDI_SUCCESS);
}



/*
 * Parse the LCT to find the target id in bsadata.  If the target id is
 * available claim it.
 */

/*ARGSUSED3*/
static int
parse_lct(void * buf, size_t size, bsa_data_t *bsadata,
			ddi_acc_handle_t acc_handle)
{

	i2o_lct_entry_t	*lctp;	/* pointer to  Logical cofiguration table */
	int	ent;
	int	class;	/* Class of the device */
	int	localtid;	/* The TID of the device */
	int	usertid;	/* User TID		 */
	int	ret = 0;


	bsadata->flags &= ~CLAIMED;
	lctp = ((i2o_lct_t *)buf)->LCTEntry;

	/*
	 * get number of entries in the table
	 */
	ent = (size/sizeof (i2o_lct_entry_t));

	DEBUGF(I2O_DEBUG_DINT, (CE_CONT, "?parse_lct:"
		"parse_lct: number entries in the LCT = %d", ent));

	while (ent) {

		class = get_lct_entry_Class(lctp, acc_handle);
		if (class & I2O_CLASS_RANDOM_BLOCK_STORAGE) {
			localtid = get_lct_entry_LocalTID(lctp,
						acc_handle);

			/* Find the device by matching TID */
			if (localtid == bsadata->tid) {
				usertid = get_lct_entry_UserTID(lctp,
					acc_handle);

				/* If device is available claim it */
				if (usertid == 0xFFF) {

					if (ret = UtilClaim(bsadata)) {
						cmn_err(CE_CONT, "?parse_lct:"
						"could not claim the device"
						"0x%x\n", bsadata->tid);

						return (ret);
					}
					bsadata->flags |= CLAIMED;
				} else {
					cmn_err(CE_CONT, "?parse_lct:"
					"could not claim the device 0x%x."
					"Device not available\n",
					bsadata->tid);
					return (-1);

				}

				break;
			}
		}
		ent--;
		lctp++;
	}

	return (0);
}

/*
 * The open routine for Block storage
 */


/*ARGSUSED*/
static int
bsa_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	bsa_data_t *bsadata;
	register dev_t dev = *dev_p;
	int	instance;
	int	ret = 0;

	/*
	 * get instance number
	 */
	instance = UNIT(dev);

	if ((bsadata = ddi_get_soft_state(bsa_soft, instance)) == NULL) {
		return (ENXIO);
	}

	mutex_enter(&bsadata->lbl.mutex);
	if (bsadata->lbl.vtocread != 1) {
		if (bsadata->lbl.geomread != 1)
			(void) bsa_setup(bsadata);
		(void) update_vtoc(bsadata, dev);
	}
	mutex_exit(&bsadata->lbl.mutex);

	mutex_enter(&bsadata->bsa_mutex);

	if (ISREMOVABLE(bsadata)) {
		if (flag & FWRITE) {
			if (ISCD(bsadata) || ISWRITEPROTECT(bsadata))
				return (EROFS); /* read only filesys */
		}
		/* lock the device (close the door) on first open */
		if (bsadata->open_flag == 0)
			ret = BsaMediaLock(bsadata);
		bsadata->open_flag |= (1 << LPART(dev));
		if (ISCD(bsadata) && ret != 0)
			return (ret);
	}
	mutex_exit(&bsadata->bsa_mutex);

	return (0);
}

/*
 * The close routine for Block Storage
 */

/*ARGSUSED*/
static int
bsa_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	bsa_data_t *bsadata;
	int	instance, ret;


	/*
	 * get instance number
	 */
	instance = UNIT(dev);

	bsadata = ddi_get_soft_state(bsa_soft, instance);
	if (ISREMOVABLE(bsadata)) {
		mutex_enter(&bsadata->bsa_mutex);
		bsadata->open_flag &= ~(1 << LPART(dev));
		if (bsadata->open_flag == 0) {

			ret = BsaMediaUnlock(bsadata);
			if (ISCD(bsadata) && ret != 0) {
				mutex_exit(&(bsadata)->bsa_mutex);
				return (ENXIO);
			}

			if (ISREMOVABLE(bsadata))
				(void) BsaMediaEject(bsadata);

			mutex_exit(&bsadata->bsa_mutex);
		}
	}
	return (0);
}

/*
 * Convert the dev information
 */

/*ARGSUSED*/
static int
bsa_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void * arg,
	void **result)
{
	bsa_data_t *bsadata;

	dev_t dev;
	int instance, error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = UNIT(dev);
		if ((bsadata = ddi_get_soft_state(bsa_soft, instance)) == NULL)
			return (DDI_FAILURE);
		*result = (void *)bsadata->dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = UNIT(dev);
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);

}

static struct driver_minor_data {
	char	*name;
	int	minor;
	int	type;
} bsa_minor_data[] = {
		{ "a",		0,	S_IFBLK},
		{ "b",		1,	S_IFBLK},
		{ "c",		2,	S_IFBLK},
		{ "d",		3,	S_IFBLK},
		{ "e",		4,	S_IFBLK},
		{ "f",		5,	S_IFBLK},
		{ "g",		6,	S_IFBLK},
		{ "h",		7,	S_IFBLK},
		{ "a,raw",	0,	S_IFCHR},
		{ "b,raw",	1,	S_IFCHR},
		{ "c,raw",	2,	S_IFCHR},
		{ "d,raw",	3,	S_IFCHR},
		{ "e,raw",	4,	S_IFCHR},
		{ "f,raw",	5,	S_IFCHR},
		{ "g,raw",	6,	S_IFCHR},
		{ "h,raw",	7,	S_IFCHR},
#if defined(_SUNOS_VTOC_16)
		{ "i",		8,	S_IFBLK},
		{ "j",		9,	S_IFBLK},
		{ "k",		10,	S_IFBLK},
		{ "l",		11,	S_IFBLK},
		{ "m",		12,	S_IFBLK},
		{ "n",		13,	S_IFBLK},
		{ "o",		14,	S_IFBLK},
		{ "p",		15,	S_IFBLK},
		{ "q",		16,	S_IFBLK},
		{ "r",		17,	S_IFBLK},
		{ "s",		18,	S_IFBLK},
		{ "t",		19,	S_IFBLK},
		{ "u",		20,	S_IFBLK},
		{ "i,raw",	8,	S_IFCHR},
		{ "j,raw",	9,	S_IFCHR},
		{ "k,raw",	10,	S_IFCHR},
		{ "l,raw",	11,	S_IFCHR},
		{ "m,raw",	12,	S_IFCHR},
		{ "n,raw",	13,	S_IFCHR},
		{ "o,raw",	14,	S_IFCHR},
		{ "p,raw",	15,	S_IFCHR},
		{ "q,raw",	16,	S_IFCHR},
		{ "r,raw",	17,	S_IFCHR},
		{ "s,raw",	18,	S_IFCHR},
		{ "t,raw",	19,	S_IFCHR},
		{ "u,raw",	20,	S_IFCHR},
#endif
		{0}

		};

/*
 * Create the minor node for Block storage device
 */

static int
create_minor_node(dev_info_t *dip, bsa_data_t *bsadata)
{
	char *node_type;
	char name[48];
	struct driver_minor_data *dmdp;


	if (bsadata->unitp.au_type == DKC_CDROM)
		node_type = DDI_NT_CD;
	else
		node_type = DDI_NT_BLOCK;

	for (dmdp = bsa_minor_data; dmdp->name != NULL; dmdp++) {
		(void) sprintf(name, "%s", dmdp->name);
		if (ddi_create_minor_node(dip, name, dmdp->type,
		    BSA_SETMINOR(bsadata->instance, dmdp->minor),
		    node_type, NULL) == DDI_FAILURE) {
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * Print routine for Block storage device
 */


static int
bsa_print(dev_t dev, char *str)
{
	int		instance;
	struct bsa_data *bsadata;


	/*
	 * get instance number
	 */
	instance = UNIT(dev);

	if (!(bsadata = ddi_get_soft_state(bsa_soft, instance))) {
		return (ENXIO);
	}


	cmn_err(CE_NOTE, "bsa_print: target id %d %s", bsadata->tid, str);
	return (0);

}

/*
 * Used the minphys (MAX transfer for the system) for the MAX transfer since
 * the OSM sends everthing to IOP.  It is the responsibility of HDM or ISM
 * (DDM) to take care of limitation of the device.
 */

static int
bsa_rdrw(dev_t dev, struct uio *uio, int flag)
{
	register int secmask;
	secmask = DEV_BSIZE - 1;

	if (uio->uio_loffset & ((offset_t)(secmask))) {
		DEBUGF(I2O_DEBUG_DIO, (CE_CONT, "?bsa_rdrw:"
		    "file offset not modulo %d\n", DEV_BSIZE));
		return (EINVAL);
	} else if (uio->uio_iov->iov_len & (secmask)) {
		DEBUGF(I2O_DEBUG_DIO, (CE_CONT, "bsa_rdrw:"
		    "transfer length not modulo %d\n", DEV_BSIZE));
		return (EINVAL);
	}
	return (physio(bsa_strategy, (struct buf *)0, dev, flag,
		minphys, uio));
}

/*
 * Read routine for Block Storage device
 */

/*ARGSUSED2*/
static int
bsa_read(dev_t dev, struct uio *uio, cred_t *cred_p)
{
	return (bsa_rdrw(dev, uio, B_READ));
}

/*
 * Write routine for Block Storage device
 */

/*ARGSUSED2*/
static int
bsa_write(dev_t dev, struct uio *uio, cred_t *cred_p)
{
	return (bsa_rdrw(dev, uio, B_WRITE));
}

/*
 * Dump routine for Block Storage device
 */

static int
bsa_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	struct bsa_data *bsadata;
	struct buf *bp;
	int	instance;


	/*
	 * get instance number
	 */
	instance = UNIT(dev);

	bsadata = ddi_get_soft_state(bsa_soft, instance);


	if (!bsadata) {
		return (ENXIO);
	}

	bp = bsadata->crashbuf;
	bp->b_un.b_addr = addr;
	bp->b_edev = dev;
	bp->b_dev = cmpdev(dev);
	bp->b_bcount = nblk * DEV_BSIZE;
	bp->b_flags = B_WRITE | B_PHYS;
	bp->b_blkno = blkno;
	bp->b_private = 0;
	(void) bsa_strategy(bp);

	for (;;) {
		drv_usecwait(1000);
		if (bp->b_flags & B_DONE) {
			if (bp->b_flags & B_ERROR)
				return (bp->b_error);
			else
				return (0);
		}
	}
}


/*
 * Get device parameters. This is where BSA acquire device information
 */
static int
UtilParamsGet(bsa_data_t *bsadata)
{
	i2o_msg_handle_t	msg_handle;
	ddi_acc_handle_t	acc_handle;
	uint_t			versionoffset;
	bsa_context_t		*tcontextp;
	i2o_sge_simple_element_t  *segemp = NULL;
	int			sg2bind = 0;
	int			sgbind = 0;
	void *resbuf, *opbuf = NULL; 	/* result buffer */
	size_t	real_length;
	uint_t sg2ncookies = 0;
	uint_t sgncookies = 0;
	ddi_dma_cookie_t dma_sgcookie;
	ddi_dma_cookie_t dma_sg2cookie;
	struct bsa_unit		*bsa_unitp;	/* phsyical characteristics */
	i2o_util_params_get_message_t *msgbuf = NULL;


	void *resptr;		/* opaque ptr */

	i2o_bsa_device_info_scalar_t *resptr1;
	i2o_param_operation_all_template_t *opbufptr1;
	i2o_param_operations_list_header_t *opbufptr;

	int ret = DDI_SUCCESS;

#if I2O_64BIT_CONTEXT
	versionoffset = 0x71;
#else
	versionoffset = 0x51;
#endif

	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */

	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilParamsGet: Frame buffer "
			"resource not available\n");
		return (-1);

	}

	/*
	 * Set up the Standard Message frame fields
	 */

	setup_msghdr(I2O_UTIL_PARAMS_GET, UtilParamsGet_reply,
	    &msgbuf->StdMessageFrame, acc_handle, versionoffset,
	    bsadata->tid, 0, sizeof (i2o_util_params_get_message_t) +
	    (2 * sizeof (i2o_sge_simple_element_t)) -
	    sizeof (i2o_sg_element_t));

	/*
	 * Set the Transaction Context field (used for reply correlation)
	 */

	tcontextp = (struct bsa_context *)
			kmem_zalloc(sizeof (bsa_context_t), KM_SLEEP);

	tcontextp->bsadata = bsadata;

#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext,
	    (uint64_t)tcontextp);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
	    (uint32_t)(uintptr_t)tcontextp);
#endif

	/*
	 * Allocate buffer for the Operation list which consist of
	 * Operation_list_header and operation_specific_template
	 * Later on may want to use immediate Data Element.
	 */

	if ((ddi_dma_alloc_handle(tcontextp->bsadata->dip, &dma_attr_sglfrm,
	    DDI_DMA_SLEEP, 0, &tcontextp->dma_sghandle)) != DDI_SUCCESS) {

		ret = ENOMEM;
		cmn_err(CE_CONT, "?UtilParamsGet: No resources "
		    "available\n");
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);
		goto out;
	}


	if ((ddi_dma_mem_alloc(tcontextp->dma_sghandle,
	    (sizeof (i2o_param_operations_list_header_t) +
	    sizeof (i2o_param_operation_all_template_t)),
	    &accattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
	    (caddr_t *)&opbuf, &real_length, &tcontextp->acc_sghandle))
	    != DDI_SUCCESS) {

		ret = ENOMEM;
		cmn_err(CE_CONT, "?UtilParamsGet: No resources "
		    "available\n");
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);
		goto out;
	}

	/*
	 * Initialize the Operation Block structure.
	 * We only have one operation (which is for SCALAR INFO) so the
	 * Operationcount is 1
	 */

	ddi_put16(tcontextp->acc_sghandle,
	    &((i2o_param_operations_list_header_t *)opbuf)->OperationCount, 1);

	opbufptr = (void *)((char *)opbuf
				+ sizeof (i2o_param_operations_list_header_t));

	opbufptr1 = (i2o_param_operation_all_template_t *)opbufptr;

	ddi_put16(tcontextp->acc_sghandle,
	    &opbufptr1->Operation, I2O_PARAMS_OPERATION_FIELD_GET);

	ddi_put16(tcontextp->acc_sghandle,
	    &opbufptr1->GroupNumber, I2O_BSA_DEVICE_INFO_GROUP_NO);

	/*
	 * For now lets return all fields we have 64-12 bytes available
	 */

	ddi_put16(tcontextp->acc_sghandle, &opbufptr1->FieldCount, -1);


	ret = ddi_dma_addr_bind_handle(tcontextp->dma_sghandle, NULL,
		(caddr_t)opbuf, real_length,
		DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
		&dma_sgcookie, &sgncookies);

	switch (ret) {
	case DDI_DMA_MAPPED:
		/*
		 * This flag used in case of error to unbind the DMA
		 * handle The address is bound to DMA handle
		 */
		sgbind = 1;
		break;
	case DDI_DMA_NORESOURCES:
		ret = ENOMEM;
		cmn_err(CE_CONT, "?UtilParamsGet:"
			" No DMA resources available\n");
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);
		goto out;

	case DDI_DMA_INUSE:
	case DDI_DMA_TOOBIG:
		ret = ENOMEM;
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);
		goto out;

	case DDI_DMA_NOMAPPING:
	default:
		ret = EFAULT;
		cmn_err(CE_CONT, "?UtilParamsGet:"
			" DMA failed 0x%x\n", ret);
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);

		goto out;
	}


	segemp = msgbuf->SGL.u1.Simple;


	/*
	 * fill out the first SG element in the frame
	 */

	put_flags_count_Count(&segemp->FlagsCount,
	    real_length, acc_handle);

	put_flags_count_Flags(&segemp->FlagsCount,
					I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT |
					I2O_SGL_FLAGS_END_OF_BUFFER,
					acc_handle);

	ddi_put32(acc_handle, &segemp->PhysicalAddress,
	    dma_sgcookie.dmac_address);


	/*
	 * Setup the result buffer.
	 */

	if ((ddi_dma_alloc_handle(tcontextp->bsadata->dip, &dma_attr_sglfrm,
	    DDI_DMA_SLEEP, 0, &tcontextp->dma_sg2handle)) != DDI_SUCCESS) {

		ret = ENOMEM;
		cmn_err(CE_CONT, "?UtilParamsGet: No resources "
		    "available\n");
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);
		goto out;
	}

	/*
	 * allocate the result buffer
	 */
	if ((ddi_dma_mem_alloc(tcontextp->dma_sg2handle,
	    ((sizeof (i2o_param_results_list_header_t)) +
	    (sizeof (i2o_param_read_operation_result_t)) +
	    (sizeof (i2o_bsa_device_info_scalar_t)) +
	    (sizeof (i2o_param_error_info_template_t))),
	    &accattr, DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
	    (caddr_t *)&resbuf, &real_length, &tcontextp->acc_sg2handle))
	    != DDI_SUCCESS) {

		ret = ENOMEM;
		cmn_err(CE_CONT, "?UtilParamsGet: No resources "
		    "available\n");
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);
		goto out;
	}


	ret = ddi_dma_addr_bind_handle(tcontextp->dma_sg2handle, NULL,
		(caddr_t)resbuf, real_length,
		DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP, 0,
		&dma_sg2cookie, &sg2ncookies);

	switch (ret) {
	case DDI_DMA_MAPPED:
		/*
		 * This flag used in case of error to unbind the DMA
		 * handle The address is bound to DMA handle
		 */
		sg2bind = 1;
		break;
	case DDI_DMA_NORESOURCES:
		ret = ENOMEM;
		cmn_err(CE_CONT, "?UtilParamsGet:"
			" No DMA resources available\n");
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);
		goto out;

	case DDI_DMA_INUSE:
	case DDI_DMA_TOOBIG:
		ret = ENOMEM;
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);
		goto out;

	case DDI_DMA_NOMAPPING:
	default:
		ret = EFAULT;
		cmn_err(CE_CONT, "?UtilParamsGet:"
			" DMA failed 0x%x\n", ret);
		if (msgbuf)
			UtilNOP(bsadata->iop, acc_handle,
			(i2o_common_message_t *)msgbuf, msg_handle);
		goto out;
	}

	segemp++;

	/*
	 * fill out the second SG element in the frame (The result buf)
	 */

	put_flags_count_Count(&segemp->FlagsCount,
	    real_length, acc_handle);

	put_flags_count_Flags(&segemp->FlagsCount,
					I2O_SGL_FLAGS_LAST_ELEMENT |
					I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT |
					I2O_SGL_FLAGS_END_OF_BUFFER,
					acc_handle);

	/*
	 * Physical address for resbuf
	 */

	ddi_put32(acc_handle, &segemp->PhysicalAddress,
	    dma_sg2cookie.dmac_address);


	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilParamsGet: i2o_msg_send failed");
		ret = DDI_FAILURE;
		goto out;

	}

	/*
	 * do a cv_wait here for reply
	 */

	mutex_enter(&bsadata->bsa_mutex);
	while (!(tcontextp->replyflag & REPLY_DONE))
		cv_wait(&bsadata->reply_cv, &bsadata->bsa_mutex);
	tcontextp->replyflag &= ~REPLY_DONE;
	mutex_exit(&bsadata->bsa_mutex);

	if ((ret = tcontextp->retval) != 0)
		goto out;

	resptr = (void *)((char *)resbuf
				+ sizeof (i2o_param_results_list_header_t)
				+ sizeof (i2o_param_read_operation_result_t));

	resptr1 = (i2o_bsa_device_info_scalar_t *)resptr;

	/*
	 * Sync the DMA memory
	 */

	(void) ddi_dma_sync(tcontextp->dma_sg2handle, 0, real_length,
	    DDI_DMA_SYNC_FORCPU);

	/*
	 * ParamsGet will be called only from attach(9F).
	 */

	mutex_enter(&tcontextp->bsadata->bsa_mutex);

	bsa_unitp = &tcontextp->bsadata->unitp;

	bsa_unitp->au_blksize = ddi_get32(tcontextp->acc_sg2handle,
	    &resptr1->BlockSize);

	bsa_unitp->au_type = ddi_get8(tcontextp->acc_sg2handle,
	    &resptr1->DeviceType);

	bsa_unitp->au_capacity =
	    ddi_get64(tcontextp->acc_sg2handle,
	    &resptr1->DeviceCapacity);

	bsa_unitp->au_devicecapability =
	    ddi_get32(tcontextp->acc_sg2handle,
	    &resptr1->DeviceCapabilitySupport);

	mutex_exit(&tcontextp->bsadata->bsa_mutex);

	DEBUGF(I2O_DEBUG_DIO, (CE_CONT, "?ParamsGet:"
		"capability = 0x%x capacity = 0x%llx"
		"type = 0x%x block size = <%d> <%x>\n",
		bsa_unitp->au_devicecapability,
		bsa_unitp->au_capacity,
		bsa_unitp->au_type,
		bsa_unitp->au_blksize));


	if (tcontextp->dma_handle) {
		(void) ddi_dma_unbind_handle(tcontextp->dma_handle);
		ddi_dma_free_handle(&tcontextp->dma_handle);
	}


	(void) ddi_dma_unbind_handle(tcontextp->dma_sghandle);

	ddi_dma_mem_free(&tcontextp->acc_sghandle);

	ddi_dma_free_handle(&tcontextp->dma_sghandle);

	(void) ddi_dma_unbind_handle(tcontextp->dma_sg2handle);

	ddi_dma_mem_free(&tcontextp->acc_sg2handle);

	ddi_dma_free_handle(&tcontextp->dma_sg2handle);

	kmem_free(tcontextp, sizeof (bsa_context_t));


	return (DDI_SUCCESS);

out:

	if (tcontextp->dma_handle) {
		(void) ddi_dma_unbind_handle(tcontextp->dma_handle);
		ddi_dma_free_handle(&tcontextp->dma_handle);
	}

	if (sgbind)
		(void) ddi_dma_unbind_handle(tcontextp->dma_sghandle);
	if (opbuf)
		ddi_dma_mem_free(&tcontextp->acc_sghandle);
	if (tcontextp->dma_sghandle)
		ddi_dma_free_handle(&tcontextp->dma_sghandle);

	if (sg2bind)
		(void) ddi_dma_unbind_handle(tcontextp->dma_sg2handle);
	if (resbuf)
		ddi_dma_free_handle(&tcontextp->dma_sg2handle);

	if (tcontextp)
		kmem_free(tcontextp, sizeof (bsa_context_t));

	return (ret);
}

/*
 * The reply message for UtilParamsGet
 */



static void
UtilParamsGet_reply(void *msg, ddi_acc_handle_t acc_handle)
{

	bsa_context_t		*tcontextp;
	int detstatus, reqstatus;

	/*
	 * Get the Transacton Context field
	 */

#if I2O_64BIT_CONTEXT
	tcontextp = (bsa_context_t *)ddi_get64(acc_handle,
	    &(((i2o_single_reply_message_frame_t *)msg)->TransactiontContext));
#else
	tcontextp = (bsa_context_t *)(uintptr_t)ddi_get32(acc_handle,
	    &(((i2o_single_reply_message_frame_t *)msg)->TransactionContext));
#endif

	/*
	 * Detailed status
	 */
	detstatus = ddi_get16(acc_handle,
	    &((i2o_single_reply_message_frame_t *)msg)->DetailedStatusCode);

	/*
	 * reply status
	 */
	reqstatus = ddi_get8(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->ReqStatus);

	tcontextp->retval = translate_error(reqstatus, detstatus, 1);

	mutex_enter(&tcontextp->bsadata->bsa_mutex);
	tcontextp->replyflag |= REPLY_DONE;
	cv_broadcast(&tcontextp->bsadata->reply_cv);
	mutex_exit(&tcontextp->bsadata->bsa_mutex);

}

/*
 * Claim the BSA device.
 */

static int
UtilClaim(bsa_data_t *bsadata)
{
	bsa_context_t		*tcontextp;
	ddi_acc_handle_t acc_handle;
	i2o_msg_handle_t msg_handle;
	i2o_util_claim_message_t *msgbuf;
	int ret = DDI_SUCCESS;

	ret = 0;

	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */

	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilClaim: Frame buffer "
			"resource not available\n");
		return (-1);

	}

	/*
	 * Set up the Standard Message frame fields
	 */

	setup_msghdr(I2O_UTIL_CLAIM, UtilClaim_reply,
	    &msgbuf->StdMessageFrame, acc_handle, 0x01,
	    bsadata->tid, 0, sizeof (i2o_util_claim_message_t));


	/*
	 * For now be the exclusive user
	 */
	ddi_put16(acc_handle, &msgbuf->ClaimFlags,
			I2O_CLAIM_FLAGS_EXCLUSIVE);

	/*
	 * For now be the primary user
	 */
	ddi_put8(acc_handle, &msgbuf->ClaimType,
					I2O_CLAIM_TYPE_PRIMARY_USER);

	/* Set the Transaction Context field (used for reply correlation) */

	tcontextp = (struct bsa_context *)
			kmem_zalloc(sizeof (bsa_context_t), KM_SLEEP);
	tcontextp->bsadata = bsadata;

#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext,
	    (uint64_t)tcontextp);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
	    (uint32_t)(uintptr_t)tcontextp);
#endif

	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilClaim: i2o_msg_send failed");
		return (DDI_FAILURE);
	}

	/*
	 * do a cv_wait here for reply
	 */
	mutex_enter(&bsadata->bsa_mutex);
	while (!(tcontextp->replyflag & REPLY_DONE))
		cv_wait(&bsadata->reply_cv, &bsadata->bsa_mutex);
	tcontextp->replyflag &= ~REPLY_DONE;
	mutex_exit(&bsadata->bsa_mutex);

	ret = tcontextp->retval;

	kmem_free((caddr_t)tcontextp, sizeof (bsa_context_t));

	return (ret);
}

/*
 * Unclaim the device
 */

static int
UtilClaim_release(bsa_data_t *bsadata)
{
	bsa_context_t		*tcontextp;
	ddi_acc_handle_t acc_handle;
	i2o_msg_handle_t msg_handle;

	i2o_util_claim_release_message_t *msgbuf;
	int ret = DDI_SUCCESS;

	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */

	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilClaim_release: Frame buffer "
			"resource not available\n");
		return (-1);

	}

	/*
	 * Set up the Standard Message frame fields
	 */

	setup_msghdr(I2O_UTIL_CLAIM_RELEASE, UtilClaim_release_reply,
	    &msgbuf->StdMessageFrame, acc_handle, 0x01,
	    bsadata->tid, 0, sizeof (i2o_util_claim_release_message_t));


	/*
	 * For now be the primary user
	 */
	ddi_put8(acc_handle, &msgbuf->ClaimType, I2O_CLAIM_TYPE_PRIMARY_USER);

	/*
	 * Set the Transaction Context field (used for reply correlation)
	 */

	tcontextp = (bsa_context_t *)kmem_zalloc(sizeof (bsa_context_t),
	    KM_SLEEP);
	tcontextp->bsadata = bsadata;


#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext,
						(uint64_t)tcontextp);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
						(uint32_t)(uintptr_t)tcontextp);
#endif

	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilClaim_release: i2o_msg_send failed");
		return (DDI_FAILURE);
	}

	/*
	 * do a cv_wait here for reply
	 */
	mutex_enter(&bsadata->bsa_mutex);
	while (!(tcontextp->replyflag & REPLY_DONE))
		cv_wait(&bsadata->reply_cv, &bsadata->bsa_mutex);
	tcontextp->replyflag &= ~REPLY_DONE;
	mutex_exit(&bsadata->bsa_mutex);

	ret = tcontextp->retval;

	kmem_free(tcontextp, sizeof (bsa_context_t));

	return (ret);

}


/*
 * UtilClaim_release reply. The reply routine for UtilClaim_release
 */

static void
UtilClaim_release_reply(void *msg, ddi_acc_handle_t acc_handle)
{

	bsa_context_t		*tcontextp;
	int detstatus, reqstatus;

#if I2O_64BIT_CONTEXT
	tcontextp = (bsa_context_t *)ddi_get64(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactiontContext));
#else
	tcontextp = (bsa_context_t *)(uintptr_t)ddi_get32(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactionContext));
#endif


	/*
	 * Detailed status
	 */
	detstatus = ddi_get16(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->DetailedStatusCode);

	/*
	 * reply status
	 */
	reqstatus = ddi_get8(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->ReqStatus);

	tcontextp->retval = translate_error(reqstatus, detstatus, 1);

	mutex_enter(&tcontextp->bsadata->bsa_mutex);
	tcontextp->replyflag |= REPLY_DONE;
	cv_broadcast(&tcontextp->bsadata->reply_cv);
	mutex_exit(&tcontextp->bsadata->bsa_mutex);
}

/*
 * Reply routine for UtilClaim
 */

static void
UtilClaim_reply(void *msg, ddi_acc_handle_t acc_handle)
{
	bsa_context_t		*tcontextp;
	int detstatus, reqstatus;

#if I2O_64BIT_CONTEXT
	tcontextp = (bsa_context_t *)ddi_get64(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactiontContext));
#else
	tcontextp = (bsa_context_t *)(uintptr_t)ddi_get32(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactionContext));
#endif

	/*
	 * Detailed status
	 */
	detstatus = ddi_get16(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->DetailedStatusCode);
	/*
	 * reply status
	 */
	reqstatus = ddi_get8(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->ReqStatus);

	tcontextp->retval = translate_error(reqstatus, detstatus, 1);

	mutex_enter(&tcontextp->bsadata->bsa_mutex);
	tcontextp->replyflag |= REPLY_DONE;
	cv_broadcast(&tcontextp->bsadata->reply_cv);
	mutex_exit(&tcontextp->bsadata->bsa_mutex);

}

/*
 * Abort specific messages. (ie. TransactionContext)
 */

static int
UtilAbort(bsa_data_t *bsadata, int aborttype, uint8_t functoabort,
	uint64_t TransactionContextToAbort)
{
	bsa_context_t	*tcontextp;
	ddi_acc_handle_t acc_handle;
	i2o_msg_handle_t msg_handle;
	i2o_util_abort_message_t *msgbuf;
	int ret = DDI_SUCCESS;

	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */

	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilAbort: Frame buffer "
			"resource not available\n");
		return (-1);
	}

	/*
	 * Set up the Standard Message frame fields
	 */

	setup_msghdr(I2O_UTIL_ABORT, UtilAbort_reply,
	    &msgbuf->StdMessageFrame, acc_handle, 0x01,
	    bsadata->tid, 0, sizeof (i2o_util_abort_message_t));

	ddi_put8(acc_handle, &msgbuf->AbortType, aborttype);

	ddi_put8(acc_handle, &msgbuf->FunctionToAbort, functoabort);

#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContextToAbort,
				TransactionContextToAbort);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContextToAbort,
				TransactionContextToAbort);

#endif

	/*
	 * Set the Transaction Context field (used for reply correlation)
	 */

	tcontextp = (bsa_context_t *)kmem_zalloc(sizeof (bsa_context_t),
	    KM_SLEEP);
	tcontextp->bsadata = bsadata;


#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext,
						(uint64_t)tcontextp);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
						(uint32_t)(uintptr_t)tcontextp);
#endif

	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilAbort: i2o_msg_send failed");
		return (DDI_FAILURE);
	}

	/*
	 * do a cv_wait here for reply
	 */
	mutex_enter(&bsadata->bsa_mutex);
	while (!(tcontextp->replyflag & REPLY_DONE))
		cv_wait(&bsadata->reply_cv, &bsadata->bsa_mutex);
	tcontextp->replyflag &= ~REPLY_DONE;
	mutex_exit(&bsadata->bsa_mutex);

	kmem_free(tcontextp, sizeof (bsa_context_t));

	return (ret);
}

/*
 * The reply routine for UtilAbort
 */

static void
UtilAbort_reply(void *msg, ddi_acc_handle_t acc_handle)
{

	bsa_context_t		*tcontextp;
	int count;

	/*
	 * Get the Transacton Context field
	 */
#if I2O_64BIT_CONTEXT
	tcontextp = (bsa_context_t *)ddi_get64(acc_handle,
			&(((i2o_util_abort_reply_t *)
						msg)->TransactiontContext));
#else
	tcontextp = (bsa_context_t *)(uintptr_t)ddi_get32(acc_handle,
			&(((i2o_util_abort_reply_t *)
						msg)->TransactionContext));
#endif

	/*
	 * count of aborted messages
	 */
	count = ddi_get32(acc_handle,
			&((i2o_util_abort_reply_t *)
						msg)->CountOfAbortedMessages);

	cmn_err(CE_CONT, "?UtilAbort: number of messages aborted 0x%x", count);

	mutex_enter(&tcontextp->bsadata->bsa_mutex);
	tcontextp->replyflag |= REPLY_DONE;
	cv_broadcast(&tcontextp->bsadata->reply_cv);
	mutex_exit(&tcontextp->bsadata->bsa_mutex);
}

/*
 * Register all the events you want to be informed of
 * Note that a single OSM must use the same InitiatorContext and
 * TransactionCOntext for all UtilEventRegoster requests (6-14)
 */

static int
UtilEventRegister(bsa_data_t *bsadata, int event)
{

	ddi_acc_handle_t acc_handle;
	i2o_msg_handle_t msg_handle;
	i2o_util_event_register_message_t *msgbuf;
	int ret = DDI_SUCCESS;

	mutex_enter(&bsadata->bsa_mutex);

	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */

	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilEventRegister: Frame buffer "
			"resource not available\n");
		return (-1);
	}

	/*
	 * Set up the Standard Message frame fields
	 */

	setup_msghdr(I2O_UTIL_EVENT_REGISTER, UtilEventRegister_reply,
	    &msgbuf->StdMessageFrame, acc_handle, 0x01,
	    bsadata->tid, 0, sizeof (i2o_util_event_register_message_t));


	ddi_put32(acc_handle, &msgbuf->EventMask, event);

	/* Set the Transaction Context field (used for reply correlation) */

#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext,
	    (uint64_t)bsadata);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
	    (uint32_t)(uintptr_t)bsadata);
#endif

	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?UtilEventRegister: i2o_msg_send failed");
		return (DDI_FAILURE);
	}

	mutex_exit(&bsadata->bsa_mutex);

	return (ret);
}

/*
 * Reply routine for UtilEventRegister routine
 */


static void
UtilEventRegister_reply(void *msg, ddi_acc_handle_t acc_handle)
{

	uint32_t eventind;
	uint32_t eventdata;
	bsa_data_t		*bsadata;

	/*
	 * Get the Transacton Context field
	 */
#if I2O_64BIT_CONTEXT
	bsadata = (bsa_context_t *)ddi_get64(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactiontContext));
#else
	bsadata = (bsa_data_t *)(uintptr_t)ddi_get32(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactionContext));
#endif
	/*
	 * Event indicator status
	 */
	eventind = ddi_get32(acc_handle,
				&((i2o_util_event_register_reply_t *)
						msg)->EventIndicator);

	switch (eventind) {

	case I2O_EVENT_IND_STATE_CHANGE:
		eventdata = ddi_get32(acc_handle,
				((i2o_util_event_register_reply_t *)
						msg)->EventData);
		cmn_err(CE_CONT, "? The state of the device has changed"
				"Error Code 0x%x\n", eventdata);
		break;
	case I2O_EVENT_IND_DEVICE_STATE:
		eventdata = ddi_get32(acc_handle,
				((i2o_util_event_register_reply_t *)
						msg)->EventData);
		cmn_err(CE_CONT, "? The generic state of the device"
				"has changed. Error Code 0x%x\n", eventdata);
		break;
	case I2O_EVENT_IND_DEVICE_RESET:
		cmn_err(CE_CONT, "? A device reset has occured\n");
		break;
	case I2O_EVENT_IND_CAPABILITY_CHANGE:
		eventdata = ddi_get32(acc_handle,
				((i2o_util_event_register_reply_t *)
						msg)->EventData);
		cmn_err(CE_WARN, "?One or more capability has changed."
				"Error Code 0x%x\n", eventdata);
		break;
	case I2O_BSA_EVENT_VOLUME_LOAD:
		cmn_err(CE_CONT, "?New medium has been loaded"
		    "onto the device\n");
		mutex_enter(&bsadata->bsa_mutex);
		bsadata->state = DKIO_INSERTED;
		bsadata->flags |= STATE_CHANGE;
		cv_broadcast(&bsadata->state_cv);
		mutex_exit(&bsadata->bsa_mutex);
		break;
	case I2O_BSA_EVENT_CAPACITY_CHANGE:
		cmn_err(CE_WARN, "?The capacity of the device has changed\n");
		break;
	case I2O_BSA_EVENT_VOLUME_UNLOAD:
		cmn_err(CE_CONT, "?The medium on the device has been"
			"unloaded\n");
		mutex_enter(&bsadata->bsa_mutex);
		bsadata->state = DKIO_EJECTED;
		bsadata->flags |= STATE_CHANGE;
		cv_broadcast(&bsadata->state_cv);
		mutex_exit(&bsadata->bsa_mutex);
		break;
	}
}

/*
 * This Media Eject routine
 */


static int
BsaMediaEject(bsa_data_t *bsadata)
{
	bsa_context_t		*tcontextp;
	ddi_acc_handle_t acc_handle;
	i2o_msg_handle_t msg_handle;
	i2o_bsa_media_eject_message_t *msgbuf;
	int ret = DDI_SUCCESS;


	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */

	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?BsaMediaEject: Frame buffer "
			"resource not available\n");
		return (-1);
	}

	/*
	 * Set up the Standard Message frame fields
	 */

	setup_msghdr(I2O_BSA_MEDIA_EJECT, BsaMediaEject_reply,
	    &msgbuf->StdMessageFrame, acc_handle, 0x01,
	    bsadata->tid, 0, sizeof (i2o_bsa_media_eject_message_t));

	/*
	 * Eject whatever currently mounted on the drive
	 */
	ddi_put32(acc_handle, &msgbuf->MediaIdentifier,
				I2O_BSA_MEDIA_ID_CURRENT_MOUNTED);

	/*
	 * Set the Transaction Context field (used for reply correlation)
	 */

	tcontextp = (bsa_context_t *)kmem_zalloc(sizeof (bsa_context_t),
	    KM_SLEEP);
	tcontextp->bsadata = bsadata;


#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext,
	    (uint64_t)tcontextp);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
	    (uint32_t)(uintptr_t)tcontextp);
#endif


	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?BsaMediaEject: i2o_msg_send failed");
		return (DDI_FAILURE);
	}

	/*
	 * do a cv_wait here for reply
	 */
	mutex_enter(&bsadata->bsa_mutex);
	while (!(tcontextp->replyflag & REPLY_DONE))
		cv_wait(&bsadata->reply_cv, &bsadata->bsa_mutex);
	tcontextp->replyflag &= ~REPLY_DONE;
	mutex_exit(&bsadata->bsa_mutex);

	ret = tcontextp->retval;

	kmem_free(tcontextp, sizeof (bsa_context_t));

	return (ret);
}

/*
 * Media Eject reply routine
 */

static void
BsaMediaEject_reply(void *msg, ddi_acc_handle_t acc_handle)
{
	bsa_context_t		*tcontextp;
	int detstatus, reqstatus;

	/*
	 * Get the Transacton Context field
	 */
#if I2O_64BIT_CONTEXT
	tcontextp = (bsa_context_t *)ddi_get64(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactiontContext));
#else
	tcontextp = (bsa_context_t *)(uintptr_t)ddi_get32(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactionContext));
#endif

	/*
	 * Detailed status
	 */
	detstatus = ddi_get16(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->DetailedStatusCode);

	/*
	 * reply status
	 */
	reqstatus = ddi_get8(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->ReqStatus);

	mutex_enter(&tcontextp->bsadata->bsa_mutex);
	if (reqstatus & I2O_REPLY_STATUS_SUCCESS)
		tcontextp->bsadata->state = DKIO_EJECTED;

	tcontextp->retval = translate_error(reqstatus, detstatus, 0);

	tcontextp->replyflag |= REPLY_DONE;
	cv_broadcast(&tcontextp->bsadata->reply_cv);
	mutex_exit(&tcontextp->bsadata->bsa_mutex);
}


/*
 * Power management for I2O
 * DDI_RESUME: I2O_BSA_POWER_MGT_POWER_UP_LOAD:
 *	Power up, load: power up the device completely and load medium,
 *	if present.
 * DDI_SUSPEND: I2O_BSA_POWER_MGT_POWER_DOWN_UNLOAD:
 *	Power down, unload: fully power down the device, unloading the
 *	valume, if present.
 */

static int
BsaPowerMgt(bsa_data_t *bsadata, int operation)
{
	bsa_context_t		*tcontextp;
	ddi_acc_handle_t acc_handle;
	i2o_msg_handle_t msg_handle;
	i2o_bsa_power_management_message_t *msgbuf;
	int ret = DDI_SUCCESS;

	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */

	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?BsaPowerMgt: Frame buffer "
			"resource not available\n");
		return (-1);
	}

	/*
	 * Set up the Standard Message frame fields
	 */

	setup_msghdr(I2O_BSA_POWER_MANAGEMENT, BsaPowerMgt_reply,
	    &msgbuf->StdMessageFrame, acc_handle, 0x01,
	    bsadata->tid, 0, sizeof (i2o_bsa_power_management_message_t));


	ddi_put8(acc_handle, &msgbuf->Operation, operation);

	/*
	 * Set the Transaction Context field (used for reply correlation)
	 */

	tcontextp = (bsa_context_t *)kmem_zalloc(sizeof (bsa_context_t),
	    KM_SLEEP);
	tcontextp->bsadata = bsadata;

#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext,
	    (uint64_t)tcontextp);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
	    (uint32_t)(uintptr_t)tcontextp);
#endif
	ddi_put8(acc_handle, &msgbuf->TimeMultiplier, 1);


	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?BsaPowerMgt: i2o_msg_send failed");
		return (DDI_FAILURE);
	}

	/*
	 * do a cv_wait here from reply
	 */
	mutex_enter(&bsadata->bsa_mutex);
	while (!(tcontextp->replyflag & REPLY_DONE))
		cv_wait(&bsadata->reply_cv, &bsadata->bsa_mutex);
	tcontextp->replyflag &= ~REPLY_DONE;
	mutex_exit(&bsadata->bsa_mutex);

	ret = tcontextp->retval;

	kmem_free(tcontextp, sizeof (bsa_context_t));

	return (ret);
}

/*
 * Power management reply routine
 */

static void
BsaPowerMgt_reply(void *msg, ddi_acc_handle_t acc_handle)
{


	bsa_context_t		*tcontextp;
	int detstatus, reqstatus;


	/*
	 * Get the Transacton Context field
	 */
#if I2O_64BIT_CONTEXT
	tcontextp = (bsa_context_t *)ddi_get64(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactiontContext));
#else
	tcontextp = (bsa_context_t *)(uintptr_t)ddi_get32(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactionContext));
#endif

	/*
	 * Detailed status
	 */
	detstatus = ddi_get16(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->DetailedStatusCode);

	/*
	 * reply status
	 */
	reqstatus = ddi_get8(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->ReqStatus);

	tcontextp->retval = translate_error(reqstatus, detstatus, 0);

	mutex_enter(&tcontextp->bsadata->bsa_mutex);
	tcontextp->replyflag |= REPLY_DONE;
	cv_broadcast(&tcontextp->bsadata->reply_cv);
	mutex_exit(&tcontextp->bsadata->bsa_mutex);
}

/*
 * The Media lock routine for BSA
 */

static int
BsaMediaLock(bsa_data_t *bsadata)
{
	bsa_context_t		*tcontextp;
	ddi_acc_handle_t acc_handle;
	i2o_msg_handle_t msg_handle;
	i2o_bsa_media_lock_message_t *msgbuf;
	int ret = DDI_SUCCESS;

	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */

	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?BsaMediaLock: Frame buffer "
			"resource not available\n");
		return (-1);
	}

	/*
	 * Set up the Standard Message frame fields
	 */

	setup_msghdr(I2O_BSA_MEDIA_LOCK, BsaMediaLock_reply,
	    &msgbuf->StdMessageFrame, acc_handle, 0x01,
	    bsadata->tid, 0, sizeof (i2o_bsa_media_lock_message_t));

	/* Lock whatever currently mounted on the drive */
	ddi_put32(acc_handle, &msgbuf->MediaIdentifier,
				I2O_BSA_MEDIA_ID_CURRENT_MOUNTED);

	/*
	 * Set the Transaction Context field (used for reply correlation)
	 */

	tcontextp = (bsa_context_t *)kmem_zalloc(sizeof (bsa_context_t),
	    KM_SLEEP);

	tcontextp->bsadata = bsadata;

#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext, (unit64_t)
								tcontextp);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
	    (uint32_t)(uintptr_t)tcontextp);
#endif

	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?BsaMediaLock: i2o_msg_send failed ");
		return (DDI_FAILURE);
	}

	/*
	 * do a cv_wait here from reply
	 */
	mutex_enter(&bsadata->bsa_mutex);
	while (!(tcontextp->replyflag & REPLY_DONE))
		cv_wait(&bsadata->reply_cv, &bsadata->bsa_mutex);
	tcontextp->replyflag &= ~REPLY_DONE;
	mutex_exit(&bsadata->bsa_mutex);

	ret = tcontextp->retval;

	kmem_free(tcontextp, sizeof (bsa_context_t));

	return (ret);
}

/*
 * This is the reply routine for BsaMediaLock
 */


static void
BsaMediaLock_reply(void *msg, ddi_acc_handle_t acc_handle)
{


	bsa_context_t		*tcontextp;
	int detstatus, reqstatus;

	/*
	 * Get the Transacton Context field
	 */
#if I2O_64BIT_CONTEXT
	tcontextp = (bsa_context_t *)ddi_get64(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactiontContext));
#else
	tcontextp = (bsa_context_t *)(uintptr_t)ddi_get32(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactionContext));
#endif

	/*
	 * Detailed status
	 */
	detstatus = ddi_get16(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->DetailedStatusCode);

	/*
	 * reply status
	 */
	reqstatus = ddi_get8(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->ReqStatus);

	tcontextp->retval = translate_error(reqstatus, detstatus, 0);

	mutex_enter(&tcontextp->bsadata->bsa_mutex);
	tcontextp->replyflag |= REPLY_DONE;
	cv_broadcast(&tcontextp->bsadata->reply_cv);
	mutex_exit(&tcontextp->bsadata->bsa_mutex);
}

/*
 * Unlock the Media
 */
static int
BsaMediaUnlock(bsa_data_t *bsadata)
{
	bsa_context_t		*tcontextp;
	ddi_acc_handle_t acc_handle;
	i2o_msg_handle_t msg_handle;
	i2o_bsa_media_unlock_message_t *msgbuf;
	int ret = DDI_SUCCESS;

	/*
	 * Allocate a message frame from IOP's inbound queue
	 * Sleep until the resource is available
	 */
	if (i2o_msg_alloc(bsadata->iop, I2O_MSG_SLEEP, NULL, (void **)&msgbuf,
	    &msg_handle, &acc_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?BsaMediaUnlock: Frame buffer "
			"resource not available\n");
		return (-1);
	}

	/*
	 * Set up the Standard Message frame fields
	 */
	setup_msghdr(I2O_BSA_MEDIA_UNLOCK, BsaMediaUnlock_reply,
	    &msgbuf->StdMessageFrame, acc_handle, 0x01,
	    bsadata->tid, 0, sizeof (i2o_bsa_media_unlock_message_t));


	/*
	 * Unlock whatever currently mounted on the drive
	 */
	ddi_put32(acc_handle, &msgbuf->MediaIdentifier,
				I2O_BSA_MEDIA_ID_CURRENT_MOUNTED);

	/*
	 * Set the Transaction Context field (used for reply correlation)
	 */

	tcontextp = (bsa_context_t *)kmem_zalloc(sizeof (bsa_context_t),
	    KM_SLEEP);
	tcontextp->bsadata = bsadata;

#if I2O_64BIT_CONTEXT
	ddi_put64(acc_handle, &msgbuf->TransactionContext, (uint64_t)
								tcontextp);
#else
	ddi_put32(acc_handle, &msgbuf->TransactionContext,
	    (uint32_t)(uintptr_t)tcontextp);
#endif

	if (i2o_msg_send(bsadata->iop, msgbuf, msg_handle) == DDI_FAILURE) {
		cmn_err(CE_CONT, "?BsaMediaUnlock: i2o_msg_send failed");
		return (DDI_FAILURE);
	}

	/*
	 * do a cv_wait here from reply
	 */
	mutex_enter(&bsadata->bsa_mutex);
	while (!(tcontextp->replyflag & REPLY_DONE))
		cv_wait(&bsadata->reply_cv, &bsadata->bsa_mutex);
	tcontextp->replyflag &= ~REPLY_DONE;
	mutex_exit(&bsadata->bsa_mutex);

	ret = tcontextp->retval;

	kmem_free(tcontextp, sizeof (bsa_context_t));

	return (ret);
}

/*
 * This function is the reply function for Media unlock request
 */

static void
BsaMediaUnlock_reply(void *msg, ddi_acc_handle_t acc_handle)
{


	bsa_context_t		*tcontextp;
	int detstatus, reqstatus;

	/*
	 * Get the Transacton Context field
	 */
#if I2O_64BIT_CONTEXT
	tcontextp = (bsa_context_t *)ddi_get64(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactiontContext));
#else
	tcontextp = (bsa_context_t *)(uintptr_t)ddi_get32(acc_handle,
			&(((i2o_single_reply_message_frame_t *)
						msg)->TransactionContext));
#endif
	/*
	 * Detailed status
	 */
	detstatus = ddi_get16(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->DetailedStatusCode);

	/*
	 * reply status
	 */
	reqstatus = ddi_get8(acc_handle,
				&((i2o_single_reply_message_frame_t *)
						msg)->ReqStatus);

	tcontextp->retval = translate_error(reqstatus, detstatus, 0);

	mutex_enter(&tcontextp->bsadata->bsa_mutex);
	tcontextp->replyflag |= REPLY_DONE;
	cv_broadcast(&tcontextp->bsadata->reply_cv);
	mutex_exit(&tcontextp->bsadata->bsa_mutex);
}


/*
 * This function releases the frame which was allocated by the OSM but was
 * not used.  This frame usually is freed by IOP after IOP sent the info to
 * DDM or ISM.  UtilNOP does not have a reply function.
 */
static void
UtilNOP(i2o_iop_handle_t handle, ddi_acc_handle_t acc_handle,
	i2o_common_message_t *msgp, i2o_msg_handle_t msg_handle)
{
	/* send the UtilNop message to return the unused Message frame */
	msgp->StdMessageFrame.VersionOffset = I2O_VERSION_11;
	msgp->StdMessageFrame.MsgFlags = 0;
	ddi_put16(acc_handle, &msgp->StdMessageFrame.MessageSize, 3);
	put_msg_Function(&msgp->StdMessageFrame, I2O_UTIL_NOP, acc_handle);
	put_msg_InitiatorAddress(&msgp->StdMessageFrame,
		I2O_HOST_TID, acc_handle);
	put_msg_TargetAddress(&msgp->StdMessageFrame,
		I2O_IOP_TID, acc_handle);

	(void) i2o_msg_send(handle, msgp, msg_handle);
}

/*
 * Pass the geom information
 */

static void
geom_prep(struct dk_geom *dkg, struct bsa_unit *bsa_unit)
{
	bzero((caddr_t)dkg, sizeof (struct dk_geom));
	dkg->dkg_ncyl	= bsa_unit->au_cyl;
	dkg->dkg_nhead	= bsa_unit->au_hd;
	dkg->dkg_nsect	= bsa_unit->au_sec;
}

#define	COPYOUT(a, b, c, f)	\
	ddi_copyout((caddr_t)(a), (caddr_t)(b), sizeof (c), f)

/*
 * This function performs all the Block storage ioctls
 */

/*ARGSUSED4*/
static int
bsa_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred_p,
								int *rval_p)
{

	register struct bsa_unit *un;
	auto long	data[512 / (sizeof (long))];
	int	instance;
	struct bsa_data *bsadata;
	struct dk_cinfo *info;
	int	i, status, ret;

	/*
	 * get instance number
	 */
	instance = UNIT(dev);

	if (!(bsadata = ddi_get_soft_state(bsa_soft, instance))) {
		return (ENXIO);
	}

#ifdef BSA_DEBUG
	{
		char	*cmdname;

		switch (cmd) {
		case DKIOCINFO:		cmdname = "DKIOCINFO       "; break;
		case DKIOCGGEOM:	cmdname = "DKIOCGGEOM      "; break;
		case DKIOCGAPART:	cmdname = "DKIOCGAPART     "; break;
		case DKIOCSAPART:	cmdname = "DKIOCSAPART     "; break;
		case DKIOCGVTOC:	cmdname = "DKIOCGVTOC      "; break;
		case DKIOCSVTOC:	cmdname = "DKIOCSVTOC      "; break;
		case DKIOCG_VIRTGEOM:	cmdname = "DKIOCG_VIRTGEOM "; break;
		case DKIOCG_PHYGEOM:	cmdname = "DKIOCG_PHYGEOM  "; break;
		case DKIOCEJECT:	cmdname = "DKIOCEJECT     *"; break;
		case DKIOCSGEOM:	cmdname = "DKIOCSGEOM     *"; break;
		case DKIOCSTATE:	cmdname = "DKIOCSTATE     *"; break;
		case DKIOCADDBAD:	cmdname = "DKIOCADDBAD    *"; break;
		case DKIOCGETDEF:	cmdname = "DKIOCGETDEF    *"; break;
		case DKIOCPARTINFO:	cmdname = "DKIOCPARTINFO  *"; break;
		case DIOCTL_RWCMD:	cmdname = "DIOCTL_RWCMD    "; break;
		default:		cmdname = "UNKNOWN	*"; break;
		}
		cmn_err(CE_CONT, "?bsa_ioctl%d: cmd %x(%s) arg %x bsadata %x\n",
				instance, cmd, cmdname, arg, bsadata);
	}
#endif

	un = &bsadata->unitp;
	bzero((caddr_t)data, sizeof (data));

	switch (cmd) {
	case DKIOCGGEOM:
	case DKIOCSGEOM:
	case DKIOCGAPART:
	case DKIOCSAPART:
	case DKIOCGVTOC:
	case DKIOCSVTOC:
		mutex_enter(&bsadata->lbl.mutex);
		status = bsa_lbl_ioctl(dev, cmd, (int)arg, flag);
		mutex_exit(&bsadata->lbl.mutex);
		return (status);
	}

	switch (cmd) {
	case DKIOCSTATE:
		{
			enum dkio_state state;
			mutex_enter(&bsadata->bsa_mutex);
			if (bsadata->state & DKIO_EJECTED)
				state = DKIO_EJECTED;
			else
				state = DKIO_INSERTED;
			while (!(bsadata->flags & STATE_CHANGE))
				cv_wait(&bsadata->state_cv,
					&bsadata->bsa_mutex);
			mutex_exit(&bsadata->bsa_mutex);

			if (bsadata->state & DKIO_EJECTED)
				state = DKIO_EJECTED;
			else
				state = DKIO_INSERTED;

			bsadata->flags &= ~STATE_CHANGE;

			if (ddi_copyout(&state, (caddr_t)arg, sizeof (int),
			    flag)) {
				return (EFAULT);
			}
		}
		break;
	case DKIOCINFO:

		info = (struct dk_cinfo *)data;
		/*
		 * Controller Information
		 */
		info->dki_ctype = un->au_type;
		info->dki_cnum = ddi_get_instance(bsadata->dip);
		(void) strcpy(info->dki_cname,
		    ddi_get_name(ddi_get_parent(bsadata->dip)));
		/*
		 * Unit Information
		 */
		info->dki_unit = ddi_get_instance(bsadata->dip);
		info->dki_slave = 0;
		(void) strcpy(info->dki_dname, "card");
		info->dki_flags = 0;
		info->dki_partition = LPART(dev);

		/*
		 * We can give the OSM's transfer rate, which is
		 * maxphys (maxphys/DEV_BSIZE).
		 */
		info->dki_maxtransfer = maxphys/DEV_BSIZE;

		/*
		 * We can't get from here to there yet
		 */
		info->dki_addr = 0;
		info->dki_space = 0;
		info->dki_prio = 0;
		info->dki_vec = 0;

		if (COPYOUT(data, (uintptr_t)arg, struct dk_cinfo, flag))
			return (EFAULT);
		break;

	case DKIOCG_VIRTGEOM:
	case DKIOCG_PHYGEOM:

		{
		struct dk_geom dkg;

		bzero((caddr_t)&dkg, sizeof (struct dk_geom));

		dkg.dkg_ncyl	= un->au_cyl;
		dkg.dkg_acyl	= un->au_acyl;
		dkg.dkg_pcyl	= un->au_cyl+un->au_acyl;
		dkg.dkg_nhead	= un->au_hd;
		dkg.dkg_nsect	= un->au_sec;

		if (ddi_copyout((caddr_t)&dkg, (caddr_t)arg,
				sizeof (struct dk_geom), flag))
			return (EFAULT);
		else
			return (0);
		}

	case DIOCTL_RWCMD:
		{
			struct	dadkio_rwcmd rwcmd;
			int	status, rw;

			i = sizeof (rwcmd);
			if (ddi_copyin((caddr_t)arg, (caddr_t)&rwcmd, i, flag))
				return (EFAULT);

			switch (rwcmd.cmd) {
			case DADKIO_RWCMD_READ :
			case DADKIO_RWCMD_WRITE:
				rw = ((rwcmd.cmd == DADKIO_RWCMD_WRITE) ?
					B_WRITE : B_READ);
				status = bsa_buf_setup((void **)&rwcmd, dev,
					((flag & FKIOCTL) ? UIO_SYSSPACE :
					UIO_USERSPACE), rw);
				return (status);
			default:
				return (EINVAL);
			}
		}

	case DKIOCADDBAD:
		break;

	/*
	 * Generic lock
	 */
	case DKIOCLOCK:
		return (BsaMediaLock(bsadata));

	/*
	 * Generic unlock
	 */
	case DKIOCUNLOCK:
		return (BsaMediaUnlock(bsadata));

	case DKIOCREMOVABLE:
		{
			int i;

			/*
			 * Get the information from Unit structure.
			 * The information was gathered at attach time
			 * through UtilParamsGet()
			 */

			i = (un->au_devicecapability &
				I2O_BSA_DEV_CAP_REMOVABLE_MEDIA);

			if (ddi_copyout((caddr_t)&i, (caddr_t)arg,
				sizeof (int), flag)) {
				return (EFAULT);

			}
			return (0);
		}

	case DKIOCEJECT:
	case CDROMEJECT:

		/*
		 * If it is not a removable media or device this ioctl
		 * does not exist.
		 */

		if (!(un->au_devicecapability &
			I2O_BSA_DEV_CAP_REMOVABLE_MEDIA ||
		    un->au_devicecapability &
			I2O_BSA_DEV_CAP_REMOVEABLE_DEVICE))

			return (ENOSYS);
		/*
		 * First need to unlock before eject
		 */

		if (ret = (BsaMediaUnlock(bsadata)))
			return (ret);

		return (BsaMediaEject(bsadata));


	case HDKIOCSCMD:
	case HDKIOCGDIAG:
		break;
	default:
		return (ENOTTY);
	}
	return (0);
}


/*
 * This function contains all the ioctls for labeling
 */

static int
bsa_lbl_ioctl(dev_t dev, int cmd, int arg, int flag)
{
	auto long	data[512 / (sizeof (long))];
	int	instance;
	struct bsa_data *bsadata;
	int	i;

	/*
	 * get instance number
	 */
	instance = UNIT(dev);


	if (!(bsadata = ddi_get_soft_state(bsa_soft, instance))) {
		return (ENXIO);
	}
	/*
	 * For future hot plugging make sure the device exist
	 */

	bzero((caddr_t)data, sizeof (data));

	switch (cmd) {
	case DKIOCGGEOM:
	case DKIOCGAPART:
	case DKIOCGVTOC:
		if (update_vtoc(bsadata, dev))
			return (EFAULT);
	}

	switch (cmd) {
	case DKIOCGGEOM:
		{
			struct dk_geom up;

			dsklbl_dgtoug(&up, &bsadata->lbl.ondsklbl);
			if (COPYOUT(&up, (uintptr_t)arg, struct dk_geom,
			    flag))
				return (EFAULT);
			break;
		}

	case DKIOCSGEOM:
		i = sizeof (struct dk_geom);
		if (ddi_copyin((caddr_t)(uintptr_t)arg, (caddr_t)data, i, flag))
			return (EFAULT);
		dsklbl_ugtodg((struct dk_geom *)data, &bsadata->lbl.ondsklbl);
		break;

	case DKIOCGAPART:
		/*
		 * Return the map for all logical partitions.
		 */
		i = NDKMAP * sizeof (struct dk_map);
		if (ddi_copyout((caddr_t)bsadata->lbl.un_map,
		    (caddr_t)(uintptr_t)arg, i, flag)) {
			return (EFAULT);
		}
		break;

	case DKIOCSAPART:
		/*
		 * Set the map for all logical partitions.
		 */
		i = NDKMAP * sizeof (struct dk_map);
		if (ddi_copyin((caddr_t)(uintptr_t)arg, (caddr_t)data, i, flag))
			return (EFAULT);
		bcopy((caddr_t)data, (caddr_t)bsadata->lbl.un_map, i);
		break;

	case DKIOCGVTOC:
		i = sizeof (struct vtoc);
		dsklbl_ondsklabel_to_vtoc(&bsadata->lbl, (struct vtoc *)data);
		if (ddi_copyout((caddr_t)data, (caddr_t)(uintptr_t)arg, i,
		    flag))
			return (EFAULT);
		else
			return (0);
	case DKIOCSVTOC:
		i = sizeof (struct vtoc);
		if (ddi_copyin((caddr_t)(uintptr_t)arg, (caddr_t)data, i,
		    flag))
			return (EFAULT);

		if (write_dskvtoc(bsadata, dev, &bsadata->lbl,
		    (struct vtoc *)data, &bsa_cb_ops)) {
			return (EFAULT);
		}
		break;
	}
	return (0);
}

static int bsa_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int mod_flags, char *name, caddr_t valuep, int *lengthp)
{
	int		instance = ddi_get_instance(dip);
	struct bsa_data *bsadata;
	uint64_t	nblocks64;

	/*
	 * Our dynamic properties are all device specific and size oriented.
	 * Requests issued under conditions where size is valid are passed
	 * to ddi_prop_op_nblocks with the size information, otherwise the
	 * request is passed to ddi_prop_op. Size depends on valid geometry.
	 */
	bsadata = ddi_get_soft_state(bsa_soft, instance);
	if ((dev == DDI_DEV_T_ANY) || (bsadata == NULL) ||
	    !(bsadata->lbl.pmap[LPART(dev)].p_flag & V_INVALID)) {
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));
	} else {
		/* get nblocks value */
		nblocks64 = (ulong_t)bsadata->lbl.pmap[LPART(dev)].p_size;

		return (ddi_prop_op_nblocks(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp, nblocks64));
	}
}

/*
 * Setup the capacity and type information
 */

static int
bsa_setup(struct bsa_data *bsadata)
{

	struct bsa_unit	*bsa_unitp;

	bsa_unitp = &bsadata->unitp;

	/*
	 * Use 6-43 GroupNumber 0000h and GroupType SCALAR and Name: DEVICE
	 * INFORMATION.  Basically need DeviceType and BlockSize and
	 * DeviceCapacity.  Probably want to setup the SGL here and put hte
	 * parameters that want to send.  If provide one SGL buffer the
	 * result will be in the payload reply.  Decide what you want to do
	 */


	if (UtilParamsGet(bsadata))
		return (DDI_FAILURE);

	/*
	 * bsa_setup will be called from attach and whenver receive an event
	 * for change of device parameres
	 */

	mutex_enter(&bsadata->bsa_mutex);

	if (bsa_unitp->au_type == I2O_BSA_DEVICE_TYPE_DIRECT)
		bsa_unitp->au_type = DKC_DIRECT;
	else if (bsa_unitp->au_type == I2O_BSA_DEVICE_TYPE_CDROM)
		bsa_unitp->au_type = DKC_CDROM;
	else {
		/*
		 * In dadk has DDI_PROB_FAILURE These are WORM and OPTICAL
		 * that we do not have support under Solaris.  We may not
		 * need to do any extra stuff. that case DKC_DIRECT should
		 * work.
		 */
		return (DDI_FAILURE);
	}

	if (bsa_unitp->au_capacity > 0)
		cap_translation(bsa_unitp->au_capacity, &(bsa_unitp->au_cyl),
		    &(bsa_unitp->au_hd), &(bsa_unitp->au_sec));
	else
		return (DDI_FAILURE);

	bsa_unitp->au_acyl = 2;

	mutex_exit(&bsadata->bsa_mutex);

	mutex_enter(&bsadata->lbl.mutex);
	bsadata->lbl.geomread = 1;
	mutex_exit(&bsadata->lbl.mutex);

	DEBUGF(I2O_DEBUG_DIO, (CE_CONT, "?bsa_setup:targ = %d cyl = %d"
		"acyl = %d head = %d"
		" sec = %d\n",
		bsadata->tid,
		bsa_unitp->au_cyl,
		bsa_unitp->au_acyl,
		bsa_unitp->au_hd,
		bsa_unitp->au_sec));
	return (DDI_SUCCESS);

}

/*
 * The following is according to Intel's int13 translation for I2O.
 * (This needs more investigation).
 */


#define	MB		(63 * 16 * 512 * 1023LL)	/* 528MB  */
#define	CAPACITY0	(63 * 32 * 512 * 1023LL)	/* (1*GB) */
#define	CAPACITY1	(63 * 64 * 512 * 1023ULL)	/* (2.1*GB) */
#define	CAPACITY2	(63 * 128 * 512 * 1023ULL)  	/* (4.2*GB) */
#define	CAPACITY3	(63 * 255 * 512 * 1023ULL)  	/* (8.4*GB) */
#define	FIXED_SECSIZE	512
#define	FIXED_SECNUM	63
#define	FIXED_MAXHEAD	255

static void
cap_translation(uint64_t capacity, int *cyls, int *hds, int *secs)
{


	*secs = FIXED_SECNUM;
	*hds  = 16;


/*					*/
/*	if (capacity <= (MB))		*/
/*		*hds  = 16;			*/
/*	else if (capacity <= (CAPACITY0))	*/
/*		*hds  *= 2;			*/
/*	else if (capacity <= (CAPACITY1))	*/
/*		*hds  *= 4;			*/
/*	else if (capacity <= (CAPACITY2))	*/
/*		*hds *= 8;			*/
/*	else if (capacity <= (CAPACITY3))	*/
/*		*hds = FIXED_MAXHEAD;		*/
/*	else {  (capacity > CAPACITY3) */
/*		cmn_err(CE_WARN, "?cap_translation: The drive is greater" */
/*			"than 8.4 GB. int13 only support up to 8.4 GB \n"); */
/*		*hds = FIXED_MAXHEAD; */
/*	}				*/



	*cyls = (capacity/(*secs * *hds * FIXED_SECSIZE));

	DEBUGF(I2O_DEBUG_DIO, (CE_CONT, "?translation:capacity =%lld cyl = %d"
		"head = %d"
		" sec = %d\n",
		capacity,
		*cyls,
		*hds,
		*secs));

}


/*
 * Setup the read write buffer
 */

static int
bsa_buf_setup(void **cmdp, dev_t dev, enum uio_seg dataspace, int rw)
{
	register struct dadkio_rwcmd *rwcmdp = (struct dadkio_rwcmd *)cmdp;
	register struct	buf  *bp;
	int	status;
	auto struct iovec aiov;
	auto struct uio auio;
	register struct uio *uio = &auio;

	bp = getrbuf(KM_SLEEP);

	bp->b_back  = (struct buf *)rwcmdp;	/* ioctl packet */
	bp->b_private = (void *)0xBEE;

	bzero((caddr_t)&auio, sizeof (struct uio));
	bzero((caddr_t)&aiov, sizeof (struct iovec));
	aiov.iov_base = rwcmdp->bufaddr;
	aiov.iov_len = rwcmdp->buflen;
	uio->uio_iov = &aiov;

	uio->uio_iovcnt = 1;
	uio->uio_resid = rwcmdp->buflen;
	uio->uio_segflg = dataspace;

	/*
	 * Let physio do the rest...
	 */
	status = physio(bsa_strategy, bp, dev, rw, minphys, uio);

	freerbuf(bp);
	return (status);
}
