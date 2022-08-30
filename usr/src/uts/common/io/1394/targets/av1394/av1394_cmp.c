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
 */

/*
 * av1394 CMP (Connection Management Procedures)
 */
#include <sys/1394/targets/av1394/av1394_impl.h>

/* configuration routines */
static void	av1394_cmp_cleanup(av1394_inst_t *icp);

/* ioctl routines */
static int	av1394_ioctl_plug_init_local(av1394_inst_t *,
		iec61883_plug_init_t *);
static int	av1394_ioctl_plug_init_remote(av1394_inst_t *,
		iec61883_plug_init_t *);

/* local PCR routines */
static int	av1394_pcr_init(av1394_inst_t *, int, uint32_t);
static void	av1394_pcr_fini(av1394_inst_t *, int);
static int	av1394_pcr_alloc_addr(av1394_inst_t *, uint64_t,
		t1394_addr_handle_t *);
static void	av1394_pcr_free_addr(av1394_inst_t *, t1394_addr_handle_t *);
static int	av1394_pcr_make_ph(int, int, int);
static int	av1394_pcr_ph2idx(int);
static av1394_pcr_t *av1394_pcr_ph2pcr(av1394_cmp_t *, int);
static uint64_t	av1394_pcr_idx2addr(int);
static int	av1394_pcr_idx2num(int);
static boolean_t av1394_pcr_idx_is_mpr(int);
static boolean_t av1394_pcr_ph_is_mpr(int);
static boolean_t av1394_pcr_ph_is_remote(int);

/* callbacks */
static void	av1394_pcr_recv_read_request(cmd1394_cmd_t *);
static void	av1394_pcr_recv_lock_request(cmd1394_cmd_t *);

/* remote PCR routines */
static int	av1394_pcr_remote_read(av1394_inst_t *, int, uint32_t *);
static int	av1394_pcr_remote_cas(av1394_inst_t *, int, uint32_t *,
		uint32_t, uint32_t);

int
av1394_cmp_init(av1394_inst_t *avp)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	ddi_iblock_cookie_t ibc = avp->av_attachinfo.iblock_cookie;
	int		ret;

	ret = t1394_cmp_register(avp->av_t1394_hdl, NULL, 0);

	if (ret == DDI_SUCCESS) {
		rw_init(&cmp->cmp_pcr_rwlock, NULL, RW_DRIVER, ibc);
	}

	return (ret);
}

void
av1394_cmp_fini(av1394_inst_t *avp)
{
	av1394_cmp_cleanup(avp);
}

void
av1394_cmp_bus_reset(av1394_inst_t *avp)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	int		i;

	/* reset PCR values */
	rw_enter(&cmp->cmp_pcr_rwlock, RW_WRITER);
	for (i = 0; i < NELEM(cmp->cmp_pcr); i++) {
		if ((i == AV1394_OMPR_IDX) || (i == AV1394_IMPR_IDX)) {
			continue;
		}
		if (cmp->cmp_pcr[i]) {
			if (i < AV1394_IMPR_IDX) {
				cmp->cmp_pcr[i]->pcr_val &=
				    ~AV1394_OPCR_BR_CLEAR_MASK;
			} else {
				cmp->cmp_pcr[i]->pcr_val &=
				    ~AV1394_IPCR_BR_CLEAR_MASK;
			}
		}
	}
	rw_exit(&cmp->cmp_pcr_rwlock);
}

/*
 * on close, free iPCRs and oPCRs not finalized by application
 */
void
av1394_cmp_close(av1394_inst_t *avp)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	int		i;

	rw_enter(&cmp->cmp_pcr_rwlock, RW_WRITER);
	for (i = 0; i < NELEM(cmp->cmp_pcr); i++) {
		if ((i == AV1394_OMPR_IDX) || (i == AV1394_IMPR_IDX)) {
			continue;
		}
		if (cmp->cmp_pcr[i]) {
			av1394_pcr_fini(avp, i);
		}
	}
	rw_exit(&cmp->cmp_pcr_rwlock);
}

/*
 *
 * --- ioctls
 *
 * IEC61883_PLUG_INIT
 */
int
av1394_ioctl_plug_init(av1394_inst_t *avp, void *arg, int mode)
{
	int		ret = 0;
	iec61883_plug_init_t pi;

	if (ddi_copyin(arg, &pi, sizeof (pi), mode) != 0) {
		return (EFAULT);
	}

	/* check arguments */
	if (((pi.pi_type != IEC61883_PLUG_IN) &&
	    (pi.pi_type != IEC61883_PLUG_OUT) &&
	    (pi.pi_type != IEC61883_PLUG_MASTER_IN) &&
	    (pi.pi_type != IEC61883_PLUG_MASTER_OUT)) ||
	    (((pi.pi_num < 0) || (pi.pi_num >= AV1394_NPCR)) &&
	    (pi.pi_num != IEC61883_PLUG_ANY))) {
		return (EINVAL);
	}

	if (pi.pi_loc == IEC61883_LOC_LOCAL) {
		ret = av1394_ioctl_plug_init_local(avp, &pi);
	} else if (pi.pi_loc == IEC61883_LOC_REMOTE) {
		ret = av1394_ioctl_plug_init_remote(avp, &pi);
	} else {
		ret = EINVAL;
	}

	if (ret == 0) {
		if (ddi_copyout(&pi, arg, sizeof (pi), mode) != 0) {
			ret = EFAULT;
		}
	}

	return (ret);
}

/*
 * IEC61883_PLUG_FINI
 */
/*ARGSUSED*/
int
av1394_ioctl_plug_fini(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	int		ret;
	int		ph;

	ph = (int)(intptr_t)arg;

	if (av1394_pcr_ph_is_remote(ph) || av1394_pcr_ph_is_mpr(ph)) {
		return (0);
	}

	rw_enter(&cmp->cmp_pcr_rwlock, RW_WRITER);
	if (av1394_pcr_ph2pcr(cmp, ph) != NULL) {
		av1394_pcr_fini(avp, av1394_pcr_ph2idx(ph));
		ret = 0;
	} else {
		ret = EINVAL;
	}
	rw_exit(&cmp->cmp_pcr_rwlock);

	return (ret);
}

/*
 * IEC61883_PLUG_REG_READ
 */
int
av1394_ioctl_plug_reg_read(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	int		ret = 0;
	iec61883_plug_reg_val_t pr;
	int		ph;
	av1394_pcr_t	*pcr;

	if (ddi_copyin(arg, &pr, sizeof (pr), mode) != 0) {
		return (EFAULT);
	}
	ph = pr.pr_handle;

	if (av1394_pcr_ph_is_remote(ph)) {
		ret = av1394_pcr_remote_read(avp, ph, &pr.pr_val);
	} else {
		switch (av1394_pcr_ph2idx(ph)) {
		case AV1394_OMPR_IDX:
			ret = t1394_cmp_read(avp->av_t1394_hdl, T1394_CMP_OMPR,
			    &pr.pr_val);
			break;
		case AV1394_IMPR_IDX:
			ret = t1394_cmp_read(avp->av_t1394_hdl, T1394_CMP_IMPR,
			    &pr.pr_val);
			break;
		default:
			rw_enter(&cmp->cmp_pcr_rwlock, RW_READER);
			if ((pcr = av1394_pcr_ph2pcr(cmp, ph)) != NULL) {
				pr.pr_val = pcr->pcr_val;
			} else {
				ret = EINVAL;
			}
			rw_exit(&cmp->cmp_pcr_rwlock);
		}
	}

	if (ret == 0) {
		if (ddi_copyout(&pr, arg, sizeof (pr), mode) != 0) {
			ret = EFAULT;
		}
	}

	return (ret);
}

/*
 * IEC61883_PLUG_REG_CAS
 */
int
av1394_ioctl_plug_reg_cas(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	int		ret = 0;
	iec61883_plug_reg_lock_t pl;
	int		ph;
	av1394_pcr_t	*pcr;

	if (ddi_copyin(arg, &pl, sizeof (pl), mode) != 0) {
		return (EFAULT);
	}
	ph = pl.pl_handle;

	if (av1394_pcr_ph_is_remote(ph)) {
		ret = av1394_pcr_remote_cas(avp, ph,
		    &pl.pl_old, pl.pl_data, pl.pl_arg);
	} else {
		switch (av1394_pcr_ph2idx(ph)) {
		case AV1394_OMPR_IDX:
			ret = t1394_cmp_cas(avp->av_t1394_hdl, T1394_CMP_OMPR,
			    pl.pl_arg, pl.pl_data, &pl.pl_old);
			break;
		case AV1394_IMPR_IDX:
			ret = t1394_cmp_cas(avp->av_t1394_hdl, T1394_CMP_IMPR,
			    pl.pl_arg, pl.pl_data, &pl.pl_old);
			break;
		default:
			rw_enter(&cmp->cmp_pcr_rwlock, RW_WRITER);
			if ((pcr = av1394_pcr_ph2pcr(cmp, ph)) != NULL) {
				/* compare_swap */
				pl.pl_old = pcr->pcr_val;
				if (pcr->pcr_val == pl.pl_arg) {
					pcr->pcr_val = pl.pl_data;
				}
			} else {
				ret = EINVAL;
			}
			rw_exit(&cmp->cmp_pcr_rwlock);
		}
	}

	if (ret == 0) {
		if (ddi_copyout(&pl, arg, sizeof (pl), mode) != 0) {
			ret = EFAULT;
		}
	}

	return (ret);
}


/*
 *
 * --- configuration routines
 *
 */
static void
av1394_cmp_cleanup(av1394_inst_t *avp)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	int		i;

	rw_enter(&cmp->cmp_pcr_rwlock, RW_WRITER);
	for (i = 0; i < NELEM(cmp->cmp_pcr); i++) {
		if (cmp->cmp_pcr[i]) {
			av1394_pcr_fini(avp, i);
		}
	}
	rw_exit(&cmp->cmp_pcr_rwlock);
	rw_destroy(&cmp->cmp_pcr_rwlock);
	(void) t1394_cmp_unregister(avp->av_t1394_hdl);
}


/*
 *
 * --- ioctl routines
 *
 * IEC61883_PLUG_INIT for local plugs
 */
static int
av1394_ioctl_plug_init_local(av1394_inst_t *avp, iec61883_plug_init_t *pip)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	int		err;
	int		ph;		/* plug handle */
	int		idx, max_idx;	/* plug index */

	/* MPR's are a special case */
	if ((pip->pi_type == IEC61883_PLUG_MASTER_IN) ||
	    (pip->pi_type == IEC61883_PLUG_MASTER_OUT)) {
		pip->pi_handle = av1394_pcr_make_ph(pip->pi_loc,
		    pip->pi_type, 0);
		return (0);
	}

	/* PCR */
	rw_enter(&cmp->cmp_pcr_rwlock, RW_WRITER);
	if (pip->pi_num == IEC61883_PLUG_ANY) {
		if (pip->pi_type == IEC61883_PLUG_OUT) {
			idx = AV1394_OPCR0_IDX;
			max_idx = idx + AV1394_PCR_ADDR_NOPCR - 1;
		} else {
			ASSERT(pip->pi_type == IEC61883_PLUG_IN);
			idx = AV1394_IPCR0_IDX;
			max_idx = idx + AV1394_PCR_ADDR_NIPCR - 1;
		}

		/* find unused PCR */
		for (; idx <= max_idx; idx++) {
			if (cmp->cmp_pcr[idx] != NULL) {
				continue;
			}
			err = av1394_pcr_init(avp, idx, AV1394_PCR_INIT_VAL);
			if (err == DDI_SUCCESS) {
				break;
			}
		}
	} else {
		ph = av1394_pcr_make_ph(pip->pi_loc, pip->pi_type, pip->pi_num);
		idx = max_idx = av1394_pcr_ph2idx(ph);

		/* create PCR if not already */
		if (cmp->cmp_pcr[idx] == NULL) {
			err = av1394_pcr_init(avp, idx, AV1394_PCR_INIT_VAL);
		}
	}

	rw_exit(&cmp->cmp_pcr_rwlock);

	if ((err != DDI_SUCCESS) || (idx > max_idx)) {
		return (EBUSY);
	}
	pip->pi_rnum = av1394_pcr_idx2num(idx);
	pip->pi_handle = av1394_pcr_make_ph(pip->pi_loc, pip->pi_type,
	    pip->pi_rnum);

	return (0);
}

/*
 * IEC61883_PLUG_INIT for remote plugs
 */
static int
av1394_ioctl_plug_init_remote(av1394_inst_t *avp, iec61883_plug_init_t *pip)
{
	int		ph;
	uint32_t	val;
	int		ret;

	if (pip->pi_num == IEC61883_PLUG_ANY) {
		return (EINVAL);
	}

	ph = av1394_pcr_make_ph(pip->pi_loc, pip->pi_type, pip->pi_num);

	/* check PCR existance by attempting to read it */
	if ((ret = av1394_pcr_remote_read(avp, ph, &val)) == 0) {
		pip->pi_handle = ph;
		pip->pi_rnum = pip->pi_num;
	}

	return (ret);
}


/*
 *
 * --- plug routines
 *
 * initialize a PCR
 */
static int
av1394_pcr_init(av1394_inst_t *avp, int idx, uint32_t val)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	av1394_pcr_t	*pcr;
	uint64_t	addr;
	int		ret;

	pcr = kmem_zalloc(sizeof (av1394_pcr_t), KM_SLEEP);
	pcr->pcr_val = val;
	cmp->cmp_pcr[idx] = pcr;

	addr = av1394_pcr_idx2addr(idx);
	ret = av1394_pcr_alloc_addr(avp, addr, &pcr->pcr_addr_hdl);
	if (ret != DDI_SUCCESS) {
		kmem_free(pcr, sizeof (av1394_pcr_t));
		cmp->cmp_pcr[idx] = NULL;
	}

	return (ret);
}

/*
 * finalize a PCR
 */
static void
av1394_pcr_fini(av1394_inst_t *avp, int idx)
{
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;

	av1394_pcr_free_addr(avp, &cmp->cmp_pcr[idx]->pcr_addr_hdl);
	kmem_free(cmp->cmp_pcr[idx], sizeof (av1394_pcr_t));
	cmp->cmp_pcr[idx] = NULL;
}

/*
 * allocate CSR address for a PCR
 */
static int
av1394_pcr_alloc_addr(av1394_inst_t *avp, uint64_t addr,
		t1394_addr_handle_t *hdlp)
{
	t1394_alloc_addr_t aa;
	int		ret;
	int		result;

	bzero(&aa, sizeof (aa));
	aa.aa_address = addr;
	aa.aa_length = 4;
	aa.aa_type = T1394_ADDR_FIXED;
	aa.aa_enable = T1394_ADDR_RDENBL | T1394_ADDR_LKENBL;
	aa.aa_evts.recv_read_request = av1394_pcr_recv_read_request;
	aa.aa_evts.recv_lock_request = av1394_pcr_recv_lock_request;
	aa.aa_arg = avp;

	ret = t1394_alloc_addr(avp->av_t1394_hdl, &aa, 0, &result);
	if (ret == DDI_SUCCESS) {
		*hdlp = aa.aa_hdl;
	}

	return (ret);
}

/*
 * free CSR address occupied by a PCR
 */
static void
av1394_pcr_free_addr(av1394_inst_t *avp, t1394_addr_handle_t *hdlp)
{
	(void) t1394_free_addr(avp->av_t1394_hdl, hdlp, 0);
}

/*
 * make plug handle. range checking should be performed by caller
 */
static int
av1394_pcr_make_ph(int loc, int type, int num)
{
	int	ph;

	switch (type) {
	case IEC61883_PLUG_IN:
		ph = num + AV1394_IPCR0_IDX;
		break;
	case IEC61883_PLUG_OUT:
		ph = num + AV1394_OPCR0_IDX;
		break;
	case IEC61883_PLUG_MASTER_IN:
		ph = AV1394_IMPR_IDX;
		break;
	case IEC61883_PLUG_MASTER_OUT:
		ph = AV1394_OMPR_IDX;
		break;
	default:
		ASSERT(0);
	}

	if (loc == IEC61883_LOC_REMOTE) {
		ph |= AV1394_PCR_REMOTE;
	}

	return (ph);
}

/*
 * convert plug handle to PCR index
 */
static int
av1394_pcr_ph2idx(int ph)
{
	return (ph & ~AV1394_PCR_REMOTE);
}

/*
 * convert plug handle to PCR pointer
 */
static av1394_pcr_t *
av1394_pcr_ph2pcr(av1394_cmp_t *cmp, int ph)
{
	int	idx = av1394_pcr_ph2idx(ph);

	if ((idx >= 0) && (idx < NELEM(cmp->cmp_pcr))) {
		return (cmp->cmp_pcr[idx]);
	} else {
		return (NULL);
	}
}

/*
 * convert PCR index to CSR address
 */
static uint64_t
av1394_pcr_idx2addr(int idx)
{
	return (AV1394_PCR_ADDR_START + idx * 4);
}

/*
 * convert PCR index to number
 */
static int
av1394_pcr_idx2num(int idx)
{
	ASSERT(!av1394_pcr_idx_is_mpr(idx));

	return ((idx - 1) % 32);
}

/*
 * returns B_TRUE if a master plug
 */
static boolean_t
av1394_pcr_idx_is_mpr(int idx)
{
	return (idx % 32 == 0);
}

static boolean_t
av1394_pcr_ph_is_mpr(int ph)
{
	return (av1394_pcr_ph2idx(ph) % 32 == 0);
}

/*
 * returns B_TRUE if a remote plug
 */
static boolean_t
av1394_pcr_ph_is_remote(int ph)
{
	return ((ph & AV1394_PCR_REMOTE) != 0);
}


/*
 *
 * --- callbacks
 *
 */
static void
av1394_pcr_recv_read_request(cmd1394_cmd_t *req)
{
	av1394_inst_t	*avp = req->cmd_callback_arg;
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	int		idx;	/* PCR index */
	av1394_pcr_t	*pcr;

	idx = (req->cmd_addr - AV1394_PCR_ADDR_START) / 4;

	if (req->cmd_type != CMD1394_ASYNCH_RD_QUAD) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	} else if ((idx >= NELEM(cmp->cmp_pcr)) ||
	    ((pcr = cmp->cmp_pcr[idx]) == NULL)) {
		req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
	} else {
		/* read */
		rw_enter(&cmp->cmp_pcr_rwlock, RW_READER);
		req->cmd_u.q.quadlet_data = pcr->pcr_val;
		rw_exit(&cmp->cmp_pcr_rwlock);

		req->cmd_result = IEEE1394_RESP_COMPLETE;
	}

	(void) t1394_recv_request_done(avp->av_t1394_hdl, req, 0);
}

static void
av1394_pcr_recv_lock_request(cmd1394_cmd_t *req)
{
	av1394_inst_t	*avp = req->cmd_callback_arg;
	av1394_cmp_t	*cmp = &avp->av_i.i_cmp;
	int		idx;	/* PCR index */
	av1394_pcr_t	*pcr;

	idx = (req->cmd_addr - AV1394_PCR_ADDR_START) / 4;

	if ((req->cmd_type != CMD1394_ASYNCH_LOCK_32) ||
	    (req->cmd_u.l32.lock_type != CMD1394_LOCK_COMPARE_SWAP)) {
		req->cmd_result = IEEE1394_RESP_TYPE_ERROR;
	} else if ((idx >= NELEM(cmp->cmp_pcr)) ||
	    ((pcr = cmp->cmp_pcr[idx]) == NULL)) {
		req->cmd_result = IEEE1394_RESP_ADDRESS_ERROR;
	} else {
		/* compare_swap */
		rw_enter(&cmp->cmp_pcr_rwlock, RW_WRITER);
		if (pcr->pcr_val == req->cmd_u.l32.arg_value) {
			pcr->pcr_val = req->cmd_u.l32.data_value;
		}
		req->cmd_u.l32.old_value = pcr->pcr_val;
		rw_exit(&cmp->cmp_pcr_rwlock);

		req->cmd_result = IEEE1394_RESP_COMPLETE;
	}

	(void) t1394_recv_request_done(avp->av_t1394_hdl, req, 0);
}


/*
 *
 * --- remote PCR routines
 *
 * read specified PCR on the remote node
 */
static int
av1394_pcr_remote_read(av1394_inst_t *avp, int ph, uint32_t *valp)
{
	cmd1394_cmd_t	*cmd;
	int		ret = 0;
	int		err;

	ret = t1394_alloc_cmd(avp->av_t1394_hdl, 0, &cmd);
	if (ret != DDI_SUCCESS) {
		return (ENOMEM);
	}

	cmd->cmd_addr = av1394_pcr_idx2addr(av1394_pcr_ph2idx(ph));
	cmd->cmd_type = CMD1394_ASYNCH_RD_QUAD;
	cmd->cmd_options = CMD1394_BLOCKING;

	if (((err = t1394_read(avp->av_t1394_hdl, cmd)) == DDI_SUCCESS) &&
	    (cmd->cmd_result == CMD1394_CMDSUCCESS)) {
		*valp = cmd->cmd_u.q.quadlet_data;
	} else {
		ret = EIO;
	}

	err = t1394_free_cmd(avp->av_t1394_hdl, 0, &cmd);
	ASSERT(err == DDI_SUCCESS);

	return (ret);
}

/*
 * compare_swap specified PCR on the remote node
 */
static int
av1394_pcr_remote_cas(av1394_inst_t *avp, int ph, uint32_t *old_valuep,
		uint32_t data_value, uint32_t arg_value)
{
	cmd1394_cmd_t	*cmd;
	int		ret = 0;
	int		err;

	ret = t1394_alloc_cmd(avp->av_t1394_hdl, 0, &cmd);
	if (ret != DDI_SUCCESS) {
		return (ENOMEM);
	}

	cmd->cmd_addr = av1394_pcr_idx2addr(av1394_pcr_ph2idx(ph));
	cmd->cmd_type = CMD1394_ASYNCH_LOCK_32;
	cmd->cmd_u.l32.lock_type = CMD1394_LOCK_COMPARE_SWAP;
	cmd->cmd_u.l32.data_value = data_value;
	cmd->cmd_u.l32.arg_value = arg_value;
	cmd->cmd_u.l32.num_retries = 0;
	cmd->cmd_options = CMD1394_BLOCKING;

	if (((err = t1394_lock(avp->av_t1394_hdl, cmd)) == DDI_SUCCESS) &&
	    (cmd->cmd_result == CMD1394_CMDSUCCESS)) {
		*old_valuep = cmd->cmd_u.l32.old_value;
	} else {
		ret = EIO;
	}

	err = t1394_free_cmd(avp->av_t1394_hdl, 0, &cmd);
	ASSERT(err == DDI_SUCCESS);

	return (ret);
}
