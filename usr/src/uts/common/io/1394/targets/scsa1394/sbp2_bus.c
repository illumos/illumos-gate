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
 * 1394 mass storage SBP-2 bus routines
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/sbp2/bus.h>
#include <sys/1394/targets/scsa1394/impl.h>

static ddi_iblock_cookie_t scsa1394_bus_get_iblock_cookie(void *);
static uint_t	scsa1394_bus_get_node_id(void *);
static int	scsa1394_bus_alloc_cmd(void *, void **, int);
static void	scsa1394_bus_free_cmd(void *, void *);
static int	scsa1394_bus_rq(void *, void *, uint64_t, uint32_t *, int *);
static int	scsa1394_bus_rb(void *, void *, uint64_t, mblk_t **, int,
		int *);
static int	scsa1394_bus_wq(void *, void *, uint64_t, uint32_t, int *);
static int	scsa1394_bus_wb(void *, void *, uint64_t, mblk_t *, int,
		int *);
static int	scsa1394_bus_alloc_buf(void *, sbp2_bus_buf_t *);
static int	scsa1394_bus_alloc_buf_phys(void *, sbp2_bus_buf_t *);
static void	scsa1394_bus_free_buf_phys(void *, sbp2_bus_buf_t *);
static int	scsa1394_bus_alloc_buf_normal(void *, sbp2_bus_buf_t *,
		boolean_t);
static void	scsa1394_bus_free_buf_normal(void *, sbp2_bus_buf_t *);
static void	scsa1394_bus_free_buf(void *, sbp2_bus_buf_t *);
static int	scsa1394_bus_sync_buf(void *, sbp2_bus_buf_t *, off_t, size_t,
		int);
static void	scsa1394_bus_buf_rw_done(void *, sbp2_bus_buf_t *, void *, int);

/* callbacks */
static void	scsa1394_bus_recv_read_request(cmd1394_cmd_t *);
static void	scsa1394_bus_recv_write_request(cmd1394_cmd_t *);

sbp2_bus_t scsa1394_sbp2_bus = {
	SBP2_BUS_REV,			/* rev */
	0xFFFFF0000000LL,		/* csr_base */
	IEEE1394_CONFIG_ROM_ADDR,	/* cfgrom_addr */
	scsa1394_bus_get_iblock_cookie,	/* get_iblock_cookie */
	scsa1394_bus_get_node_id,	/* get_node_id */
	scsa1394_bus_alloc_buf,		/* alloc_buf */
	scsa1394_bus_free_buf,		/* free_buf */
	scsa1394_bus_sync_buf,		/* sync_buf */
	scsa1394_bus_buf_rw_done,	/* buf_rd_done */
	scsa1394_bus_buf_rw_done,	/* buf_wr_done */
	scsa1394_bus_alloc_cmd,		/* alloc_cmd */
	scsa1394_bus_free_cmd,		/* free_cmd */
	scsa1394_bus_rq,		/* rq */
	scsa1394_bus_rb,		/* rb */
	scsa1394_bus_wq,		/* wq */
	scsa1394_bus_wb			/* wb */
};

/*
 * fault injector
 *
 * global on/off switch
 */
int scsa1394_bus_fi_on = 0;

/* fault probabilities per operation, in tenths of percent, i.e. 10 is 1% */
int scsa1394_bus_fi_prob_alloc_buf = 10;
int scsa1394_bus_fi_prob_alloc_cmd = 10;
int scsa1394_bus_fi_prob_rq = 10;
int scsa1394_bus_fi_prob_rb = 10;
int scsa1394_bus_fi_prob_wq = 10;
int scsa1394_bus_fi_prob_wb = 10;

#define	SCSA1394_BUS_FI_POSITIVE(p) (scsa1394_bus_fi_on &&	\
	((p) > 0) && ((gethrtime() % (p)) == 0))

/*
 * translate command result to SBP2 error code
 */
static int
scsa1394_bus_rw_result2code(int result)
{
	int	code;

	switch (result) {
	case CMD1394_EDEVICE_BUSY:
		code = SBP2_EBUSY;
		break;
	case CMD1394_EADDRESS_ERROR:
		code = SBP2_EADDR;
		break;
	case CMD1394_ETIMEOUT:
	case CMD1394_ERETRIES_EXCEEDED:
		code = SBP2_ETIMEOUT;
		break;
	case CMD1394_EDEVICE_REMOVED:
		code = SBP2_ENODEV;
		break;
	default:
		code = SBP2_EIO;
		break;
	}
	return (code);
}

static ddi_iblock_cookie_t
scsa1394_bus_get_iblock_cookie(void *hdl)
{
	scsa1394_state_t *sp = hdl;

	return (sp->s_attachinfo.iblock_cookie);
}

static uint_t
scsa1394_bus_get_node_id(void *hdl)
{
	scsa1394_state_t *sp = hdl;

	return (sp->s_attachinfo.localinfo.local_nodeID);
}


/*ARGSUSED*/
static int
scsa1394_bus_alloc_cmd(void *hdl, void **cmdp, int flags)
{
	scsa1394_state_t *sp = hdl;
	cmd1394_cmd_t	*cmd;

	if (SCSA1394_BUS_FI_POSITIVE(scsa1394_bus_fi_prob_alloc_cmd)) {
		return (SBP2_ENOMEM);
	}

	if (t1394_alloc_cmd(sp->s_t1394_hdl, 0, &cmd) != DDI_SUCCESS) {
		return (SBP2_ENOMEM);
	}
	*cmdp = cmd;
	return (SBP2_SUCCESS);
}


static void
scsa1394_bus_free_cmd(void *hdl, void *argcmd)
{
	scsa1394_state_t *sp = hdl;
	cmd1394_cmd_t	*cmd = argcmd;

	(void) t1394_free_cmd(sp->s_t1394_hdl, 0, &cmd);
}


/*ARGSUSED*/
static int
scsa1394_bus_rq(void *hdl, void *argcmd, uint64_t addr, uint32_t *q, int *berr)
{
	scsa1394_state_t *sp = hdl;
	cmd1394_cmd_t	*cmd = argcmd;

	if (SCSA1394_BUS_FI_POSITIVE(scsa1394_bus_fi_prob_rq)) {
		return (SBP2_EIO);
	}

	cmd->cmd_addr = addr;
	cmd->cmd_type = CMD1394_ASYNCH_RD_QUAD;
	cmd->cmd_options = CMD1394_BLOCKING;

	if ((t1394_read(sp->s_t1394_hdl, cmd) != DDI_SUCCESS) ||
	    (cmd->cmd_result != CMD1394_CMDSUCCESS)) {
		*berr = cmd->cmd_result;
		return (scsa1394_bus_rw_result2code(cmd->cmd_result));
	}

	*q = cmd->cmd_u.q.quadlet_data;
	return (SBP2_SUCCESS);
}


/*ARGSUSED*/
static int
scsa1394_bus_rb(void *hdl, void *argcmd, uint64_t addr, mblk_t **bpp, int len,
    int *berr)
{
	scsa1394_state_t *sp = hdl;
	cmd1394_cmd_t	*cmd = argcmd;
	mblk_t		*bp = *bpp;

	/* caller wants us to allocate memory */
	if ((bp == NULL) && ((bp = allocb(len, BPRI_HI)) == NULL)) {
		return (SBP2_ENOMEM);
	}

	cmd->cmd_addr = addr;
	cmd->cmd_type = CMD1394_ASYNCH_RD_BLOCK;
	cmd->cmd_u.b.data_block = bp;
	cmd->cmd_u.b.blk_length = len;
	cmd->cmd_options = CMD1394_BLOCKING;

	if ((t1394_read(sp->s_t1394_hdl, cmd) != DDI_SUCCESS) ||
	    (cmd->cmd_result != CMD1394_CMDSUCCESS)) {
		freeb(bp);
		*berr = cmd->cmd_result;
		return (scsa1394_bus_rw_result2code(cmd->cmd_result));
	}

	*bpp = bp;
	return (SBP2_SUCCESS);
}


/*ARGSUSED*/
static int
scsa1394_bus_wq(void *hdl, void *argcmd, uint64_t addr, uint32_t q, int *berr)
{
	scsa1394_state_t *sp = hdl;
	cmd1394_cmd_t	*cmd = argcmd;

	cmd->cmd_addr = addr;
	cmd->cmd_type = CMD1394_ASYNCH_WR_QUAD;
	cmd->cmd_u.q.quadlet_data = q;
	cmd->cmd_options = CMD1394_BLOCKING;

	if ((t1394_write(sp->s_t1394_hdl, cmd) != DDI_SUCCESS) ||
	    (cmd->cmd_result != CMD1394_CMDSUCCESS)) {
		*berr = cmd->cmd_result;
		return (scsa1394_bus_rw_result2code(cmd->cmd_result));
	}

	return (SBP2_SUCCESS);
}


/*ARGSUSED*/
static int
scsa1394_bus_wb(void *hdl, void *argcmd, uint64_t addr, mblk_t *bp, int len,
    int *berr)
{
	scsa1394_state_t *sp = hdl;
	cmd1394_cmd_t	*cmd = argcmd;

	cmd->cmd_addr = addr;
	cmd->cmd_type = CMD1394_ASYNCH_WR_BLOCK;
	cmd->cmd_u.b.data_block = bp;
	cmd->cmd_u.b.blk_length = len;
	cmd->cmd_options = CMD1394_BLOCKING;

	if ((t1394_write(sp->s_t1394_hdl, cmd) != DDI_SUCCESS) ||
	    (cmd->cmd_result != CMD1394_CMDSUCCESS)) {
		*berr = cmd->cmd_result;
		return (scsa1394_bus_rw_result2code(cmd->cmd_result));
	}

	return (SBP2_SUCCESS);
}


/*ARGSUSED*/
static int
scsa1394_bus_alloc_buf(void *hdl, sbp2_bus_buf_t *buf)
{
	if (SCSA1394_BUS_FI_POSITIVE(scsa1394_bus_fi_prob_alloc_buf)) {
		return (SBP2_ENOMEM);
	}

	if (buf->bb_flags & SBP2_BUS_BUF_DMA) {
		return (scsa1394_bus_alloc_buf_phys(hdl, buf));
	} else {
		return (scsa1394_bus_alloc_buf_normal(hdl, buf,
		    ((buf->bb_flags & SBP2_BUS_BUF_POSTED) != 0)));
	}
}


static void
scsa1394_bus_free_buf(void *hdl, sbp2_bus_buf_t *buf)
{
	if (buf->bb_flags & SBP2_BUS_BUF_DMA) {
		scsa1394_bus_free_buf_phys(hdl, buf);
	} else {
		scsa1394_bus_free_buf_normal(hdl, buf);
	}
}


static int
scsa1394_bus_alloc_buf_phys(void *hdl, sbp2_bus_buf_t *buf)
{
	scsa1394_state_t	*sp = hdl;
	scsa1394_bus_buf_t	*sbb;		/* bus private structure */
	size_t			real_length;	/* real allocated length */
	ddi_dma_cookie_t	cookie;		/* cookies */
	uint_t			ccount;		/* cookie count */
	t1394_alloc_addr_t	aa;
	int			result;

	/* allocate bus private structure */
	sbb = kmem_zalloc(sizeof (scsa1394_bus_buf_t), KM_SLEEP);
	sbb->sbb_state = sp;

	/* allocate DMA resources */
	if (ddi_dma_alloc_handle(sp->s_dip, &sp->s_attachinfo.dma_attr,
	    DDI_DMA_SLEEP, NULL, &sbb->sbb_dma_hdl) != DDI_SUCCESS) {
		kmem_free(sbb, sizeof (scsa1394_bus_buf_t));
		return (SBP2_ENOMEM);
	}

	if (ddi_dma_mem_alloc(sbb->sbb_dma_hdl, buf->bb_len,
	    &sp->s_attachinfo.acc_attr,
	    buf->bb_flags & (DDI_DMA_STREAMING | DDI_DMA_CONSISTENT),
	    DDI_DMA_SLEEP, NULL, &buf->bb_kaddr, &real_length,
	    &sbb->sbb_acc_hdl) != DDI_SUCCESS) {
		ddi_dma_free_handle(&sbb->sbb_dma_hdl);
		kmem_free(sbb, sizeof (scsa1394_bus_buf_t));
		return (SBP2_ENOMEM);
	}

	buf->bb_flags &= ~DDI_DMA_PARTIAL;
	if (ddi_dma_addr_bind_handle(sbb->sbb_dma_hdl, NULL, buf->bb_kaddr,
	    buf->bb_len, buf->bb_flags, DDI_DMA_SLEEP, NULL,
	    &cookie, &ccount) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&sbb->sbb_acc_hdl);
		ddi_dma_free_handle(&sbb->sbb_dma_hdl);
		kmem_free(sbb, sizeof (scsa1394_bus_buf_t));
		return (SBP2_ENOMEM);
	}
	ASSERT(ccount == 1);
	buf->bb_paddr = cookie.dmac_address;	/* 32-bit address */

	/* allocate 1394 resources */
	bzero(&aa, sizeof (aa));
	aa.aa_type = T1394_ADDR_FIXED;
	aa.aa_length = buf->bb_len;
	if (buf->bb_flags & SBP2_BUS_BUF_RD) {
		aa.aa_enable |= T1394_ADDR_RDENBL;
	}
	if (buf->bb_flags & SBP2_BUS_BUF_WR) {
		aa.aa_enable |= T1394_ADDR_WRENBL;
	}
	aa.aa_address = buf->bb_paddr;		/* PCI-1394 mapping is 1-1 */

	if (t1394_alloc_addr(sp->s_t1394_hdl, &aa, 0, &result) != DDI_SUCCESS) {
		(void) ddi_dma_unbind_handle(sbb->sbb_dma_hdl);
		ddi_dma_mem_free(&sbb->sbb_acc_hdl);
		ddi_dma_free_handle(&sbb->sbb_dma_hdl);
		kmem_free(sbb, sizeof (scsa1394_bus_buf_t));
		return (SBP2_ENOMEM);
	}
	sbb->sbb_addr_hdl = aa.aa_hdl;
	buf->bb_baddr = aa.aa_address;

	buf->bb_hdl = sbb;
	return (SBP2_SUCCESS);
}


static void
scsa1394_bus_free_buf_phys(void *hdl, sbp2_bus_buf_t *buf)
{
	scsa1394_state_t	*sp = hdl;
	scsa1394_bus_buf_t	*sbb = buf->bb_hdl;

	(void) t1394_free_addr(sp->s_t1394_hdl, &sbb->sbb_addr_hdl, 0);
	(void) ddi_dma_unbind_handle(sbb->sbb_dma_hdl);
	ddi_dma_mem_free(&sbb->sbb_acc_hdl);
	ddi_dma_free_handle(&sbb->sbb_dma_hdl);
	kmem_free(sbb, sizeof (scsa1394_bus_buf_t));
	buf->bb_hdl = NULL;
}


static int
scsa1394_bus_alloc_buf_normal(void *hdl, sbp2_bus_buf_t *buf, boolean_t posted)
{
	scsa1394_state_t 	*sp = hdl;
	scsa1394_bus_buf_t	*sbb;		/* bus private structure */
	t1394_alloc_addr_t	aa;
	int			result;

	/* allocate bus private structure */
	sbb = kmem_zalloc(sizeof (scsa1394_bus_buf_t), KM_SLEEP);
	sbb->sbb_state = sp;

	/* allocate 1394 resources */
	bzero(&aa, sizeof (aa));
	aa.aa_type = posted ? T1394_ADDR_POSTED_WRITE : T1394_ADDR_NORMAL;
	aa.aa_length = buf->bb_len;
	if (buf->bb_flags & SBP2_BUS_BUF_RD) {
		aa.aa_enable |= T1394_ADDR_RDENBL;
		aa.aa_evts.recv_read_request = scsa1394_bus_recv_read_request;
	}
	if (buf->bb_flags & SBP2_BUS_BUF_WR) {
		aa.aa_enable |= T1394_ADDR_WRENBL;
		aa.aa_evts.recv_write_request = scsa1394_bus_recv_write_request;
	}
	aa.aa_arg = buf;

	if (t1394_alloc_addr(sp->s_t1394_hdl, &aa, 0, &result) != DDI_SUCCESS) {
		kmem_free(sbb, sizeof (scsa1394_bus_buf_t));
		return (SBP2_ENOMEM);
	}
	sbb->sbb_addr_hdl = aa.aa_hdl;
	buf->bb_baddr = aa.aa_address;

	buf->bb_hdl = sbb;
	return (SBP2_SUCCESS);
}

static void
scsa1394_bus_free_buf_normal(void *hdl, sbp2_bus_buf_t *buf)
{
	scsa1394_state_t 	*sp = hdl;
	scsa1394_bus_buf_t	*sbb = buf->bb_hdl;

	(void) t1394_free_addr(sp->s_t1394_hdl, &sbb->sbb_addr_hdl, 0);
	kmem_free(sbb, sizeof (scsa1394_bus_buf_t));
	buf->bb_hdl = NULL;
}

/*ARGSUSED*/
static int
scsa1394_bus_sync_buf(void *hdl, sbp2_bus_buf_t *buf, off_t offset,
    size_t length, int type)
{
	scsa1394_bus_buf_t	*sbb = buf->bb_hdl;

	if (buf->bb_flags & SBP2_BUS_BUF_DMA) {
		return (ddi_dma_sync(sbb->sbb_dma_hdl, offset, length, type));
	} else {
		return (SBP2_SUCCESS);
	}
}

/*ARGSUSED*/
static void
scsa1394_bus_buf_rw_done(void *hdl, sbp2_bus_buf_t *buf, void *reqh, int error)
{
	scsa1394_state_t	*sp = hdl;
	cmd1394_cmd_t		*req = reqh;

	/* complete request */
	switch (error) {
	case SBP2_BUS_BUF_SUCCESS:
		req->cmd_result = IEEE1394_RESP_COMPLETE;
		break;
	case SBP2_BUS_BUF_ELENGTH:
		req->cmd_result = IEEE1394_RESP_DATA_ERROR;
		break;
	case SBP2_BUS_BUF_EBUSY:
		req->cmd_result = IEEE1394_RESP_CONFLICT_ERROR;
		break;
	default:
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	}
	(void) t1394_recv_request_done(sp->s_t1394_hdl, req, 0);
}


/*
 *
 * --- callbacks
 *
 */
static void
scsa1394_bus_recv_read_request(cmd1394_cmd_t *req)
{
	sbp2_bus_buf_t		*buf = req->cmd_callback_arg;
	scsa1394_bus_buf_t	*sbb = buf->bb_hdl;
	scsa1394_state_t	*sp = sbb->sbb_state;

	/* XXX sanity checks: addr, etc */
	if (req->cmd_type == CMD1394_ASYNCH_RD_QUAD) {
		if (buf->bb_rq_cb) {
			buf->bb_rq_cb(buf, req, &req->cmd_u.q.quadlet_data);
			return;
		}
	} else {
		if (buf->bb_rb_cb) {
			buf->bb_rb_cb(buf, req, &req->cmd_u.b.data_block,
			    req->cmd_u.b.blk_length);
			return;
		}
	}
	scsa1394_bus_buf_rw_done(sp, buf, req, SBP2_BUS_BUF_FAILURE);
}


static void
scsa1394_bus_recv_write_request(cmd1394_cmd_t *req)
{
	sbp2_bus_buf_t		*buf = req->cmd_callback_arg;
	scsa1394_bus_buf_t	*sbb = buf->bb_hdl;
	scsa1394_state_t	*sp = sbb->sbb_state;

	/* XXX sanity checks: addr, etc */
	if (req->cmd_type == CMD1394_ASYNCH_WR_QUAD) {
		if (buf->bb_wq_cb) {
			buf->bb_wq_cb(buf, req, req->cmd_u.q.quadlet_data);
			return;
		}
	} else {
		if (buf->bb_wb_cb) {
			buf->bb_wb_cb(buf, req, &req->cmd_u.b.data_block);
			return;
		}
	}
	scsa1394_bus_buf_rw_done(sp, buf, req, SBP2_BUS_BUF_FAILURE);
}
