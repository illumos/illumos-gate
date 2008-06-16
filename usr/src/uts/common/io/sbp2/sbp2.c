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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SBP2 module
 */
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/sbp2/impl.h>
#include <sys/1394/ieee1212.h>

/* target routines */
static void	sbp2_tgt_init_sobj(sbp2_tgt_t *);
static void	sbp2_tgt_fini_sobj(sbp2_tgt_t *);
static int	sbp2_tgt_init_params(sbp2_tgt_t *);
static int	sbp2_tgt_init_luns(sbp2_tgt_t *, int);
static void	sbp2_tgt_fini_luns(sbp2_tgt_t *);
static int	sbp2_tgt_init_bus(sbp2_tgt_t *);
static void	sbp2_tgt_fini_bus(sbp2_tgt_t *);
static int	sbp2_tgt_mgt_request(sbp2_tgt_t *, int *);
static int	sbp2_tgt_task_mgt_request(sbp2_tgt_t *, uint16_t, int, uint64_t,
		int *);

/* lun routines */
static void	sbp2_lun_logout_orb(sbp2_lun_t *, sbp2_tgt_t *, int *);
static boolean_t sbp2_lun_accepting_tasks(sbp2_lun_t *);

/* session routines */
static int	sbp2_ses_init(sbp2_ses_t **, sbp2_lun_t *,
		void (*)(void *, sbp2_task_t *), void *);
static void	sbp2_ses_fini(sbp2_ses_t *);
static sbp2_task_t *sbp2_ses_orbp2task(sbp2_ses_t *, uint64_t);
static void	sbp2_ses_append_task(sbp2_ses_t *, sbp2_task_t *);
static void	sbp2_ses_reset_pending_tasks(sbp2_ses_t *, uint16_t);
static int	sbp2_ses_reconnect_orb(sbp2_ses_t *, int *);

/* orb alloc routines */
static sbp2_bus_buf_t *sbp2_orb_freelist_get(sbp2_lun_t *, sbp2_task_t *, int);
static int	sbp2_orb_freelist_put(sbp2_lun_t *, sbp2_bus_buf_t *);
static void	sbp2_orb_freelist_destroy(sbp2_lun_t *);

/* fetch agent routines */
static int	sbp2_agent_init(sbp2_agent_t *, uint64_t, sbp2_tgt_t *tp);
static void	sbp2_agent_fini(sbp2_agent_t *);
static void	sbp2_agent_acquire_locked(sbp2_agent_t *);
static void	sbp2_agent_release_locked(sbp2_agent_t *);
static void	sbp2_agent_acquire(sbp2_agent_t *);
static void	sbp2_agent_release(sbp2_agent_t *);
static int	sbp2_agent_keepalive(sbp2_agent_t *, int *);
static int	sbp2_agent_doorbell(sbp2_agent_t *, int *);
static int	sbp2_agent_write_orbp(sbp2_agent_t *, uint64_t, int *);
static int	sbp2_agent_reset(sbp2_agent_t *, int *);

/* callbacks and timeouts */
static void	sbp2_mgt_status_fifo_wb_cb(sbp2_bus_buf_t *, void *, mblk_t **);
static void	sbp2_task_timeout(void *);
static void	sbp2_status_fifo_wb_cb(sbp2_bus_buf_t *, void *, mblk_t **);

/* other */
static void	sbp2_mgt_agent_acquire(sbp2_tgt_t *);
static void	sbp2_mgt_agent_release(sbp2_tgt_t *);
static void	sbp2_fetch_agent_acquire(sbp2_ses_t *);
static void	sbp2_fetch_agent_release(sbp2_ses_t *);

extern struct mod_ops mod_miscops;

static struct modlmisc sbp2_modlmisc = {
	&mod_miscops,		/* module type */
	"Serial Bus Protocol 2 module" /* module name */
};

static struct modlinkage sbp2_modlinkage = {
	MODREV_1, (void *)&sbp2_modlmisc, NULL
};

/* tunables */
int	sbp2_submit_reset_nretries = 3;
clock_t	sbp2_submit_reset_delay = 10;	/* microsec */

int	sbp2_write_orbp_nretries = 3;
clock_t	sbp2_write_orbp_delay = 10;	/* microsec */

_NOTE(SCHEME_PROTECTS_DATA("unique per call", datab msgb))

/*
 *
 * --- loadable module entry points
 *
 */
int
_init(void)
{
	return (mod_install(&sbp2_modlinkage));
}


int
_fini(void)
{
	return (mod_remove(&sbp2_modlinkage));
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&sbp2_modlinkage, modinfop));
}

/*
 *
 * --- target routines
 *
 */
int
sbp2_tgt_init(void *bus_hdl, sbp2_bus_t *bus, int maxluns, sbp2_tgt_t **tpp)
{
	sbp2_tgt_t	*tp;
	int		ret;

	tp = kmem_zalloc(sizeof (sbp2_tgt_t), KM_SLEEP);
	tp->t_bus = bus;
	tp->t_bus_hdl = bus_hdl;

	sbp2_tgt_init_sobj(tp);

	if ((ret = sbp2_cfgrom_parse(tp, &tp->t_cfgrom)) != SBP2_SUCCESS) {
		sbp2_tgt_fini_sobj(tp);
		kmem_free(tp, sizeof (sbp2_tgt_t));
		return (SBP2_ECFGROM);
	}

	if ((ret = sbp2_tgt_init_params(tp)) != SBP2_SUCCESS) {
		sbp2_cfgrom_free(tp, &tp->t_cfgrom);
		sbp2_tgt_fini_sobj(tp);
		kmem_free(tp, sizeof (sbp2_tgt_t));
		return (ret);
	}

	if ((ret = sbp2_tgt_init_luns(tp, maxluns)) != SBP2_SUCCESS) {
		sbp2_cfgrom_free(tp, &tp->t_cfgrom);
		sbp2_tgt_fini_sobj(tp);
		kmem_free(tp, sizeof (sbp2_tgt_t));
		return (ret);
	}

	if ((ret = sbp2_tgt_init_bus(tp)) != SBP2_SUCCESS) {
		sbp2_tgt_fini_luns(tp);
		sbp2_cfgrom_free(tp, &tp->t_cfgrom);
		sbp2_tgt_fini_sobj(tp);
		kmem_free(tp, sizeof (sbp2_tgt_t));
		return (ret);
	}

	*tpp = tp;
	return (SBP2_SUCCESS);
}

void
sbp2_tgt_fini(sbp2_tgt_t *tp)
{
	sbp2_tgt_fini_bus(tp);
	sbp2_tgt_fini_luns(tp);
	sbp2_cfgrom_free(tp, &tp->t_cfgrom);
	sbp2_tgt_fini_sobj(tp);
	kmem_free(tp, sizeof (sbp2_tgt_t));
}

static void
sbp2_tgt_init_sobj(sbp2_tgt_t *tp)
{
	mutex_init(&tp->t_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&tp->t_mgt_agent_cv, NULL, CV_DRIVER, NULL);
	cv_init(&tp->t_mgt_status_cv, NULL, CV_DRIVER, NULL);
}

static void
sbp2_tgt_fini_sobj(sbp2_tgt_t *tp)
{
	cv_destroy(&tp->t_mgt_status_cv);
	cv_destroy(&tp->t_mgt_agent_cv);
	mutex_destroy(&tp->t_mutex);
}

static int
sbp2_tgt_init_params(sbp2_tgt_t *tp)
{
	sbp2_cfgrom_ent_t *root = &tp->t_cfgrom.cr_root;
	sbp2_cfgrom_ent_t *ent;
	uint32_t	q;

	/* MANAGEMENT_AGENT */
	if ((ent = sbp2_cfgrom_ent_by_key(root, SBP2_KT_MGT_AGENT,
	    SBP2_KV_MGT_AGENT, 0)) == NULL) {
		return (SBP2_ECFGROM);
	}
	tp->t_mgt_agent = SBP2_CSR_BASE(tp) + ent->ce_data.offset * 4;

	/* Unit_Characteristics */
	if ((ent = sbp2_cfgrom_ent_by_key(root, SBP2_KT_UNCHAR,
	    SBP2_KV_UNCHAR, 0)) == NULL) {
		return (SBP2_ECFGROM);
	}
	q = ent->ce_data.imm;

	/* units of 500 ms -> ms */
	tp->t_mot = ((q & SBP2_UNCHAR_MOT) >> SBP2_UNCHAR_MOT_SHIFT) * 500;

	/* quadlets -> bytes */
	tp->t_orb_size = (q & SBP2_UNCHAR_ORB_SIZE) * 4;

	/* some devices return incorrect values */
	if (tp->t_mot < SBP2_MOT_MIN) {
		tp->t_mot = SBP2_MOT_DFLT;
	}
	if (tp->t_orb_size < SBP2_ORB_SIZE_MIN) {
		tp->t_orb_size = SBP2_ORB_SIZE_MIN;
	}

	return (SBP2_SUCCESS);
}


/*ARGSUSED*/
static int
sbp2_tgt_init_luns(sbp2_tgt_t *tp, int maxluns)
{
	sbp2_cfgrom_ent_t *root = &tp->t_cfgrom.cr_root;
	sbp2_cfgrom_ent_t *ent;
	sbp2_lun_t	*lp;
	uint32_t	q;

	ASSERT(tp->t_nluns == 0);

	tp->t_lun = kmem_zalloc(maxluns * sizeof (sbp2_lun_t), KM_SLEEP);
	tp->t_nluns_alloc = maxluns;

	/* search for Logical_Unit_Number's */
	for (tp->t_nluns = 0; tp->t_nluns < maxluns; tp->t_nluns++) {
		if ((ent = sbp2_cfgrom_ent_by_key(root, SBP2_KT_LUN,
		    SBP2_KV_LUN, tp->t_nluns)) == NULL) {
			break;
		}
		q = ent->ce_data.imm;
		lp = &tp->t_lun[tp->t_nluns];
		lp->l_tgt = tp;
		lp->l_lun = q & SBP2_LUN_NUM;
		lp->l_type = (q & SBP2_LUN_TYPE) >> SBP2_LUN_TYPE_SHIFT;
		mutex_init(&lp->l_orb_freelist.bl_mutex, NULL, MUTEX_DRIVER,
		    NULL);
	}

	if (tp->t_nluns > 0) {
		return (SBP2_SUCCESS);
	} else {
		kmem_free(tp->t_lun, tp->t_nluns_alloc * sizeof (sbp2_lun_t));
		return (SBP2_ECFGROM);
	}

}


static void
sbp2_tgt_fini_luns(sbp2_tgt_t *tp)
{
	int		i;
	sbp2_lun_t	*lp;

	/* destroy each lun */
	for (i = 0; i < tp->t_nluns; i++) {
		lp = &tp->t_lun[i];
		sbp2_orb_freelist_destroy(lp);
		mutex_destroy(&lp->l_orb_freelist.bl_mutex);
	}

	kmem_free(tp->t_lun, tp->t_nluns_alloc * sizeof (sbp2_lun_t));
}

/*
 * initialize bus buffers and commands
 */
static int
sbp2_tgt_init_bus(sbp2_tgt_t *tp)
{
	int		ret;

	/*
	 * We serialize management requests and reuse the same buffers.
	 *
	 * mgt ORB
	 */
	tp->t_mgt_orb_buf.bb_len =
	    SBP2_ORB_SIZE_ROUNDUP(tp, sizeof (sbp2_mgt_orb_t));
	tp->t_mgt_orb_buf.bb_flags = SBP2_BUS_BUF_DMA | SBP2_BUS_BUF_RD;
	if ((ret = SBP2_ALLOC_BUF(tp, &tp->t_mgt_orb_buf)) != SBP2_SUCCESS) {
		sbp2_tgt_fini_bus(tp);
		return (ret);
	}

	/*
	 * mgt status FIFO
	 */
	tp->t_mgt_status_fifo_buf.bb_len = sizeof (sbp2_status_t);
	tp->t_mgt_status_fifo_buf.bb_flags = SBP2_BUS_BUF_WR_POSTED;
	tp->t_mgt_status_fifo_buf.bb_wb_cb = sbp2_mgt_status_fifo_wb_cb;
	tp->t_mgt_status_fifo_buf.bb_sbp2_priv = tp;
	if ((ret = SBP2_ALLOC_BUF(tp, &tp->t_mgt_status_fifo_buf)) !=
	    SBP2_SUCCESS) {
		return (ret);
	}

	/*
	 * login response
	 */
	tp->t_mgt_login_resp_buf.bb_len =
	    SBP2_ORB_SIZE_ROUNDUP(tp, sizeof (sbp2_login_resp_t));
	/*
	 * read-only should have been sufficient here, but it causes
	 * DVMA errors on Grover, while read/write works just fine
	 */
	tp->t_mgt_login_resp_buf.bb_flags = SBP2_BUS_BUF_DMA | SBP2_BUS_BUF_RW;
	if ((ret = SBP2_ALLOC_BUF(tp, &tp->t_mgt_login_resp_buf)) !=
	    SBP2_SUCCESS) {
		sbp2_tgt_fini_bus(tp);
		return (ret);
	}

	/*
	 * allocate bus commands
	 */
	if ((ret = SBP2_ALLOC_CMD(tp, &tp->t_mgt_cmd, 0)) != SBP2_SUCCESS) {
		sbp2_tgt_fini_bus(tp);
		return (ret);
	}
	if ((tp->t_mgt_cmd_data = allocb(8, BPRI_HI)) == NULL) {
		sbp2_tgt_fini_bus(tp);
		return (SBP2_ENOMEM);
	}

	return (SBP2_SUCCESS);
}

static void
sbp2_tgt_fini_bus(sbp2_tgt_t *tp)
{
	if (tp->t_mgt_status_fifo_buf.bb_hdl != NULL) {
		SBP2_FREE_BUF(tp, &tp->t_mgt_status_fifo_buf);
	}
	if (tp->t_mgt_orb_buf.bb_hdl != NULL) {
		SBP2_FREE_BUF(tp, &tp->t_mgt_orb_buf);
	}
	if (tp->t_mgt_login_resp_buf.bb_hdl != NULL) {
		SBP2_FREE_BUF(tp, &tp->t_mgt_login_resp_buf);
	}
	if (tp->t_mgt_cmd) {
		SBP2_FREE_CMD(tp, tp->t_mgt_cmd);
		tp->t_mgt_cmd = NULL;
	}
	if (tp->t_mgt_cmd_data) {
		freeb(tp->t_mgt_cmd_data);
		tp->t_mgt_cmd_data = NULL;
	}
}

void
sbp2_tgt_disconnect(sbp2_tgt_t *tp)
{
	sbp2_tgt_fini_bus(tp);
}

int
sbp2_tgt_reconnect(sbp2_tgt_t *tp)
{
	return (sbp2_tgt_init_bus(tp));
}

/*
 * send mgt ORB and wait for status
 *
 * mgt agent should be acquired
 */
static int
sbp2_tgt_mgt_request(sbp2_tgt_t *tp, int *berr)
{
	clock_t		until;
	int		ret;

	/*
	 * When a ctl operation happens from HAL - this could be 0!
	 * This will happen when a device is disconected and then
	 * reconnected. Note  there are problems with not being able
	 * to detach/eject a target before unplugging. That can cause
	 * this to happen... This problem needs some work elseware!
	 * This just prevents a needless panic. If we return failure
	 * the target ultimatly will recover and is usable.
	 */
	if (tp->t_mgt_cmd_data == 0) {
		return (SBP2_FAILURE);
	}

	tp->t_mgt_status_rcvd = B_FALSE;

	/* write ORB address into MANAGEMENT_AGENT */
	SBP2_ADDR_SET(tp->t_mgt_cmd_data->b_rptr, tp->t_mgt_orb_buf.bb_baddr,
	    0);
	tp->t_mgt_cmd_data->b_wptr = tp->t_mgt_cmd_data->b_rptr + 8;

	if ((ret = SBP2_WB(tp, tp->t_mgt_cmd, tp->t_mgt_agent,
	    tp->t_mgt_cmd_data, 8, berr)) != SBP2_SUCCESS) {
		return (ret);
	}

	/* wait for login response */
	mutex_enter(&tp->t_mutex);
	until = ddi_get_lbolt() + drv_usectohz(tp->t_mot * 1000);
	ret = 1;

	while (!tp->t_mgt_status_rcvd && (ret > 0)) {
		ret = cv_timedwait(&tp->t_mgt_status_cv, &tp->t_mutex, until);
	}

	if (!tp->t_mgt_status_rcvd) {
		ret = SBP2_ETIMEOUT;
	} else if ((tp->t_mgt_status.st_param & SBP2_ST_RESP) ==
	    SBP2_ST_RESP_COMPLETE) {
		ret = SBP2_SUCCESS;
	} else {
		ret = SBP2_FAILURE;
	}
	mutex_exit(&tp->t_mutex);

	return (ret);
}

/*
 * Send task management request, one of:
 *
 *	ABORT TASK, ABORT TASK SET, LOGICAL UNIT RESET, TARGET RESET
 */
static int
sbp2_tgt_task_mgt_request(sbp2_tgt_t *tp, uint16_t id, int func, uint64_t orbp,
    int *berr)
{
	sbp2_task_mgt_orb_t *torb;
	int		ret;

	sbp2_mgt_agent_acquire(tp);

	torb = (sbp2_task_mgt_orb_t *)tp->t_mgt_orb_buf.bb_kaddr;
	bzero(torb, sizeof (sbp2_task_mgt_orb_t));
	SBP2_ORBP_SET(torb->to_orb, orbp);
	torb->to_params = SBP2_SWAP16(func | SBP2_ORB_NOTIFY |
	    SBP2_ORB_RQ_FMT_SBP2);
	torb->to_login_id = SBP2_SWAP16(id);
	SBP2_ADDR_SET(torb->to_status_fifo, tp->t_mgt_status_fifo_buf.bb_baddr,
	    0);

	ret = sbp2_tgt_mgt_request(tp, berr);

	sbp2_mgt_agent_release(tp);

	return (ret);
}

int
sbp2_tgt_reset(sbp2_tgt_t *tp, int *berr)
{
	sbp2_lun_t	*lp = &tp->t_lun[0];
	int		ret;

	/* issue TARGET RESET */
	if ((ret = sbp2_tgt_task_mgt_request(tp, lp->l_login_resp.lr_login_id,
	    SBP2_ORB_MGT_FUNC_TARGET_RESET, 0, berr)) != SBP2_SUCCESS) {
		return (ret);
	}

	return (SBP2_SUCCESS);
}

int
sbp2_tgt_get_cfgrom(sbp2_tgt_t *tp, sbp2_cfgrom_t **crpp)
{
	*crpp = &tp->t_cfgrom;
	return (SBP2_SUCCESS);
}

int
sbp2_tgt_get_lun_cnt(sbp2_tgt_t *tp)
{
	return (tp->t_nluns);
}

sbp2_lun_t *
sbp2_tgt_get_lun(sbp2_tgt_t *tp, int num)
{
	if (num < tp->t_nluns) {
		return (&tp->t_lun[num]);
	} else {
		return (NULL);
	}
}

/*
 *
 * --- lun routines
 *
 */
int
sbp2_lun_reset(sbp2_lun_t *lp, int *berr)
{
	sbp2_tgt_t	*tp = lp->l_tgt;
	sbp2_ses_t	*sp = lp->l_ses;
	sbp2_task_t	*task = NULL;
	int		ret;

	/* issue LOGICAL UNIT RESET */
	if ((ret = sbp2_tgt_task_mgt_request(tp, lp->l_login_resp.lr_login_id,
	    SBP2_ORB_MGT_FUNC_LUN_RESET, 0, berr)) != SBP2_SUCCESS) {
		return (ret);
	}

	/* mark all pending tasks reset and notify the driver */
	mutex_enter(&sp->s_task_mutex);
	for (task = sp->s_task_head; task != NULL; task = task->ts_next) {
		if (task->ts_state < SBP2_TASK_COMP) {
			task->ts_error = SBP2_TASK_ERR_LUN_RESET;
			task->ts_state = SBP2_TASK_COMP;
		}
	}
	mutex_exit(&sp->s_task_mutex);

	sp->s_status_cb(sp->s_status_cb_arg, NULL);

	return (SBP2_SUCCESS);
}

int
sbp2_lun_login(sbp2_lun_t *lp, sbp2_ses_t **spp,
    void (*cb)(void *, sbp2_task_t *), void *cb_arg, int *berr)
{
	sbp2_tgt_t	*tp = lp->l_tgt;
	sbp2_ses_t	*sp;
	sbp2_login_orb_t *lorb;
	int		ret;

	if (cb == NULL) {
		return (SBP2_EINVAL);
	}

	/* multiple sessions not supported yet */
	if (lp->l_ses != NULL) {
		return (SBP2_EALREADY);
	}

	if ((ret = sbp2_ses_init(&sp, lp, cb, cb_arg)) != SBP2_SUCCESS) {
		return (ret);
	}
	lp->l_ses = sp;

	sbp2_mgt_agent_acquire(tp);

	/* prepare login ORB */
	mutex_enter(&tp->t_mutex);
	lorb = (sbp2_login_orb_t *)tp->t_mgt_orb_buf.bb_kaddr;
	bzero(lorb, sizeof (sbp2_login_orb_t));
	SBP2_ADDR_SET(lorb->lo_resp, tp->t_mgt_login_resp_buf.bb_baddr, 0);
	lorb->lo_params = SBP2_SWAP16(SBP2_ORB_MGT_FUNC_LOGIN |
	    SBP2_ORB_LOGIN_EXCL | SBP2_ORB_NOTIFY | SBP2_ORB_RQ_FMT_SBP2);
	lorb->lo_lun = SBP2_SWAP16(lp->l_lun);
	lorb->lo_resp_len = SBP2_SWAP16(tp->t_mgt_login_resp_buf.bb_len);
	SBP2_ADDR_SET(lorb->lo_status_fifo, sp->s_status_fifo_buf.bb_baddr, 0);

	bzero(tp->t_mgt_login_resp_buf.bb_kaddr, sizeof (sbp2_login_resp_t));

	lp->l_logged_in = B_FALSE;
	mutex_exit(&tp->t_mutex);

	/* send request */
	if ((ret = sbp2_tgt_mgt_request(tp, berr)) != SBP2_SUCCESS) {
		sbp2_mgt_agent_release(tp);
		sbp2_ses_fini(lp->l_ses);
		lp->l_ses = NULL;
		return (ret);
	}

	/* retrieve response data (XXX sanity checks?) */
	mutex_enter(&tp->t_mutex);
	(void) SBP2_SYNC_BUF(tp, &tp->t_mgt_login_resp_buf, 0, 0,
	    DDI_DMA_SYNC_FORKERNEL);
	bcopy(tp->t_mgt_login_resp_buf.bb_kaddr, &lp->l_login_resp,
	    sizeof (sbp2_login_resp_t));

	/* convert from BE to native endianness */
	SBP2_SWAP16_1(lp->l_login_resp.lr_len);
	SBP2_SWAP16_1(lp->l_login_resp.lr_login_id);
	SBP2_SWAP32_2(lp->l_login_resp.lr_cmd_agent);
	SBP2_SWAP16_1(lp->l_login_resp.lr_reconnect_hold);
	lp->l_login_resp.lr_reconnect_hold++;

	sp->s_agent_offset = SBP2_ADDR2UINT64(lp->l_login_resp.lr_cmd_agent);

	lp->l_logged_in = B_TRUE;
	mutex_exit(&tp->t_mutex);

	sbp2_mgt_agent_release(tp);

	if ((ret = sbp2_agent_init(&sp->s_agent, sp->s_agent_offset, tp)) !=
	    SBP2_SUCCESS) {
		sbp2_ses_fini(sp);
		lp->l_ses = NULL;
		return (ret);
	}

	*spp = lp->l_ses;
	return (SBP2_SUCCESS);
}

/*ARGSUSED*/
int
sbp2_lun_logout(sbp2_lun_t *lp, sbp2_ses_t **sp, int *berr, boolean_t phys)
{
	sbp2_tgt_t	*tp = lp->l_tgt;

	ASSERT(*sp == lp->l_ses);

	mutex_enter(&tp->t_mutex);
	if (lp->l_logged_in) {
		lp->l_logged_in = B_FALSE;
		/* do physical LOGOUT if requested */
		if (phys) {
			mutex_exit(&tp->t_mutex);
			sbp2_lun_logout_orb(lp, tp, berr);
			mutex_enter(&tp->t_mutex);
		}
	}

	sbp2_agent_fini(&lp->l_ses->s_agent);
	sbp2_ses_fini(lp->l_ses);
	lp->l_ses = NULL;
	*sp = NULL;
	mutex_exit(&tp->t_mutex);

	return (SBP2_SUCCESS);
}

/*
 * Issue LOGOUT mgt orb and wait for response. We are not interested in
 * the success at the time, since the device may be disconnected or hung,
 * just trying to make the best effort.
 */
static void
sbp2_lun_logout_orb(sbp2_lun_t *lp, sbp2_tgt_t *tp, int *berr)
{
	sbp2_logout_orb_t *lorb;

	sbp2_mgt_agent_acquire(tp);

	/* prepare logout ORB */
	lorb = (sbp2_logout_orb_t *)tp->t_mgt_orb_buf.bb_kaddr;
	bzero(lorb, sizeof (sbp2_logout_orb_t));
	lorb->lo_params = SBP2_SWAP16(SBP2_ORB_MGT_FUNC_LOGOUT |
	    SBP2_ORB_NOTIFY | SBP2_ORB_RQ_FMT_SBP2);
	lorb->lo_login_id = SBP2_SWAP16(lp->l_login_resp.lr_login_id);
	SBP2_ADDR_SET(lorb->lo_status_fifo, tp->t_mgt_status_fifo_buf.bb_baddr,
	    0);

	/* send request */
	(void) sbp2_tgt_mgt_request(tp, berr);

	sbp2_mgt_agent_release(tp);
}

static boolean_t
sbp2_lun_accepting_tasks(sbp2_lun_t *lp)
{
	sbp2_tgt_t	*tp = lp->l_tgt;
	boolean_t	ret;

	mutex_enter(&tp->t_mutex);
	ret = ((lp->l_ses != NULL) && lp->l_logged_in && !lp->l_reconnecting);
	mutex_exit(&tp->t_mutex);
	return (ret);
}

/*
 *
 * --- session routines
 *
 */
static int
sbp2_ses_init(sbp2_ses_t **spp, sbp2_lun_t *lp,
    void (*cb)(void *, sbp2_task_t *), void *cb_arg)
{
	sbp2_tgt_t	*tp = lp->l_tgt;
	sbp2_ses_t	*sp;
	int		ret;

	sp = kmem_zalloc(sizeof (sbp2_ses_t), KM_SLEEP);

	sp->s_tgt = tp;
	sp->s_lun = lp;
	sp->s_status_cb = cb;
	sp->s_status_cb_arg = cb_arg;

	mutex_init(&sp->s_mutex, NULL, MUTEX_DRIVER,
	    SBP2_GET_IBLOCK_COOKIE(tp));
	mutex_init(&sp->s_task_mutex, NULL, MUTEX_DRIVER,
	    SBP2_GET_IBLOCK_COOKIE(tp));

	/*
	 * status FIFO for block requests
	 */
	sp->s_status_fifo_buf.bb_len = sizeof (sbp2_status_t);
	sp->s_status_fifo_buf.bb_flags = SBP2_BUS_BUF_WR_POSTED;
	sp->s_status_fifo_buf.bb_wb_cb = sbp2_status_fifo_wb_cb;
	sp->s_status_fifo_buf.bb_sbp2_priv = sp;
	if ((ret = SBP2_ALLOC_BUF(tp, &sp->s_status_fifo_buf)) !=
	    SBP2_SUCCESS) {
		sbp2_ses_fini(sp);
		return (ret);
	}

	*spp = sp;
	return (SBP2_SUCCESS);
}


static void
sbp2_ses_fini(sbp2_ses_t *sp)
{
	sbp2_tgt_t	*tp = sp->s_lun->l_tgt;

	if (sp->s_status_fifo_buf.bb_hdl != NULL) {
		SBP2_FREE_BUF(tp, &sp->s_status_fifo_buf);
	}

	mutex_destroy(&sp->s_task_mutex);
	mutex_destroy(&sp->s_mutex);

	kmem_free(sp, sizeof (sbp2_ses_t));
}

int
sbp2_ses_reconnect(sbp2_ses_t *sp, int *berr, uint16_t nodeID)
{
	sbp2_tgt_t	*tp = sp->s_tgt;
	sbp2_lun_t	*lp = sp->s_lun;
	int		ret;

	/* prevent new tasks from being submitted */
	mutex_enter(&tp->t_mutex);
	lp->l_reconnecting = B_TRUE;
	mutex_exit(&tp->t_mutex);

	/*
	 * From 10.5 Task management event matrix:
	 *	Immediately upon detection of a bus reset, all command
	 *	block fetch agents transition to the reset state and
	 *	their associated task sets are cleared without
	 *	the return of completion status.
	 *
	 * Reset pending tasks so we can retry them later.
	 */
	sbp2_ses_reset_pending_tasks(sp, nodeID);

	ret = sbp2_ses_reconnect_orb(sp, berr);

	mutex_enter(&tp->t_mutex);
	lp->l_reconnecting = B_FALSE;
	mutex_exit(&tp->t_mutex);

	return (ret);
}

/*
 * Send reconnect ORB. If operation fails, set lp->l_logged_in = B_FALSE.
 */
static int
sbp2_ses_reconnect_orb(sbp2_ses_t *sp, int *berr)
{
	sbp2_tgt_t	*tp = sp->s_tgt;
	sbp2_lun_t	*lp = sp->s_lun;
	sbp2_agent_t	*ap = &sp->s_agent;
	sbp2_reconnect_orb_t *rorb;
	int		ret;

	sbp2_mgt_agent_acquire(tp);

	/* prepare login ORB */
	rorb = (sbp2_reconnect_orb_t *)tp->t_mgt_orb_buf.bb_kaddr;
	bzero(rorb, sizeof (sbp2_reconnect_orb_t));
	rorb->ro_params = SBP2_SWAP16(SBP2_ORB_MGT_FUNC_RECONNECT |
	    SBP2_ORB_NOTIFY | SBP2_ORB_RQ_FMT_SBP2);
	rorb->ro_login_id = SBP2_SWAP16(lp->l_login_resp.lr_login_id);
	SBP2_ADDR_SET(rorb->ro_status_fifo, tp->t_mgt_status_fifo_buf.bb_baddr,
	    0);

	/* send request */
	if ((ret = sbp2_tgt_mgt_request(tp, berr)) != SBP2_SUCCESS) {
		mutex_enter(&tp->t_mutex);
		lp->l_logged_in = B_FALSE;
		mutex_exit(&tp->t_mutex);
	} else {
		/* after successful reset fetch agent is in RESET state */
		mutex_enter(&ap->a_mutex);
		ap->a_state = SBP2_AGENT_STATE_RESET;
		mutex_exit(&ap->a_mutex);
	}

	sbp2_mgt_agent_release(tp);

	return (ret);
}


static sbp2_task_t *
sbp2_ses_orbp2task(sbp2_ses_t *sp, uint64_t orbp)
{
	sbp2_task_t	*task;

	mutex_enter(&sp->s_task_mutex);
	for (task = sp->s_task_head; task != NULL; task = task->ts_next) {
		if (task->ts_buf->bb_baddr == orbp) {
			break;
		}
	}
	mutex_exit(&sp->s_task_mutex);
	return (task);
}

/*
 * This is where tasks (command ORB's) are signalled to the target.
 * 'task' argument is allowed to be NULL, in which case the task will be
 * taken from the current task list.
 *
 * Tasks are signalled one at a time by writing into ORB_POINTER register.
 * While SBP-2 allows dynamic task list updates and using DOORBELL register,
 * some devices have bugs that prevent using this strategy: e.g. some LaCie
 * HDD's can corrupt data. Data integrity is more important than performance.
 */
int
sbp2_ses_submit_task(sbp2_ses_t *sp, sbp2_task_t *new_task)
{
	sbp2_agent_t	*ap = &sp->s_agent;
	sbp2_tgt_t	*tp = sp->s_tgt;
	sbp2_task_t	*task;		/* task actually being submitted */
	boolean_t	callback;
	timeout_id_t	timeout_id;
	int		ret;

	if (!sbp2_lun_accepting_tasks(sp->s_lun)) {
		return (SBP2_ENODEV);
	}

	sbp2_agent_acquire(ap);	/* serialize */

	mutex_enter(&ap->a_mutex);

	/* if task provided, append it to the list */
	if (new_task != NULL) {
		ASSERT(new_task->ts_state == SBP2_TASK_INIT);
		sbp2_ses_append_task(sp, new_task);
	}

	/* if there is already a task in flight, exit */
	if ((ap->a_active_task != NULL) &&
	    (ap->a_active_task->ts_state == SBP2_TASK_PEND)) {
		mutex_exit(&ap->a_mutex);
		sbp2_agent_release(ap);
		return (SBP2_SUCCESS);
	}

	/* no active task, grab the first one on the list in INIT state */
	ap->a_active_task = sbp2_ses_find_task_state(sp, SBP2_TASK_INIT);
	if (ap->a_active_task == NULL) {
		mutex_exit(&ap->a_mutex);
		sbp2_agent_release(ap);
		return (SBP2_SUCCESS);
	}
	task = ap->a_active_task;
	task->ts_ses = sp;
	task->ts_state = SBP2_TASK_PEND;

	/* can't work with a dead agent */
	if (sbp2_agent_keepalive(ap, &task->ts_bus_error) != SBP2_SUCCESS) {
		task->ts_error = SBP2_TASK_ERR_DEAD;
		goto error;
	}

	/*
	 * In theory, we should schedule task timeout after it's been submitted.
	 * However, some fast tasks complete even before timeout is scheduled.
	 * To avoid additional complications in the code, schedule timeout now.
	 */
	ASSERT(task->ts_timeout_id == 0);
	task->ts_time_start = gethrtime();
	if (task->ts_timeout > 0) {
		task->ts_timeout_id = timeout(sbp2_task_timeout, task,
		    task->ts_timeout * drv_usectohz(1000000));
	}

	/* notify fetch agent */
	ap->a_state = SBP2_AGENT_STATE_ACTIVE;
	mutex_exit(&ap->a_mutex);
	ret = sbp2_agent_write_orbp(ap, task->ts_buf->bb_baddr,
	    &task->ts_bus_error);
	tp->t_stat.stat_submit_orbp++;
	mutex_enter(&ap->a_mutex);

	if (ret != SBP2_SUCCESS) {
		ap->a_state = SBP2_AGENT_STATE_DEAD;
		tp->t_stat.stat_status_dead++;

		if (task->ts_timeout_id != 0) {
			timeout_id = task->ts_timeout_id;
			task->ts_timeout_id = 0;
			(void) untimeout(timeout_id);
		}
		task->ts_error = SBP2_TASK_ERR_BUS;
		goto error;
	}

	mutex_exit(&ap->a_mutex);

	sbp2_agent_release(ap);
	return (SBP2_SUCCESS);

error:
	/*
	 * Return immediate error if failed task is the one being submitted,
	 * otherwise use callback.
	 */
	callback = (ap->a_active_task != new_task);
	ASSERT(task == ap->a_active_task);
	ap->a_active_task = NULL;
	mutex_exit(&ap->a_mutex);
	sbp2_agent_release(ap);

	/*
	 * Remove task from the list. It is important not to change task state
	 * to SBP2_TASK_COMP while it's still on the list, to avoid race with
	 * upper layer driver (e.g. scsa1394).
	 */
	ret = sbp2_ses_remove_task(sp, task);
	ASSERT(ret == SBP2_SUCCESS);
	task->ts_state = SBP2_TASK_COMP;

	if (callback) {
		sp->s_status_cb(sp->s_status_cb_arg, task);
		return (SBP2_SUCCESS);
	} else {
		/* upper layer driver is responsible to call nudge */
		return (SBP2_FAILURE);
	}
}

void
sbp2_ses_nudge(sbp2_ses_t *sp)
{
	(void) sbp2_ses_submit_task(sp, NULL);
}

/*
 * append task to the task list
 */
static void
sbp2_ses_append_task(sbp2_ses_t *sp, sbp2_task_t *task)
{
	sbp2_tgt_t	*tp = sp->s_tgt;

	mutex_enter(&sp->s_task_mutex);
	if (sp->s_task_head == NULL) {
		ASSERT(sp->s_task_tail == NULL);
		ASSERT(sp->s_task_cnt == 0);
		task->ts_prev = task->ts_next = NULL;
		sp->s_task_head = sp->s_task_tail = task;
	} else {
		ASSERT(sp->s_task_cnt > 0);
		task->ts_next = NULL;
		task->ts_prev = sp->s_task_tail;
		sp->s_task_tail->ts_next = task;
		sp->s_task_tail = task;
	}
	ASSERT(task != task->ts_prev);
	ASSERT(task != task->ts_next);

	sp->s_task_cnt++;
	if (sp->s_task_cnt > tp->t_stat.stat_task_max) {
		tp->t_stat.stat_task_max = sp->s_task_cnt;
	}
	mutex_exit(&sp->s_task_mutex);
}

/*
 * remove task from the task list
 */
static int
sbp2_ses_remove_task_locked(sbp2_ses_t *sp, sbp2_task_t *task)
{
	sp->s_task_cnt--;
	if (task == sp->s_task_head) {			/* first */
		ASSERT(task->ts_prev == NULL);
		if (task->ts_next == NULL) {		/*   and last */
			ASSERT(sp->s_task_cnt == 0);
			sp->s_task_head = sp->s_task_tail = NULL;
		} else {				/*   but not last */
			sp->s_task_head = task->ts_next;
			sp->s_task_head->ts_prev = NULL;
		}
	} else if (task == sp->s_task_tail) {		/* last but not first */
		ASSERT(task->ts_next == NULL);
		sp->s_task_tail = task->ts_prev;
		sp->s_task_tail->ts_next = NULL;
	} else {					/* in the middle */
		task->ts_prev->ts_next = task->ts_next;
		task->ts_next->ts_prev = task->ts_prev;
	}
	task->ts_prev = task->ts_next = NULL;
	ASSERT(sp->s_task_cnt >= 0);

	return (SBP2_SUCCESS);
}

int
sbp2_ses_remove_task(sbp2_ses_t *sp, sbp2_task_t *task)
{
	int	ret;

	mutex_enter(&sp->s_task_mutex);
	ret = sbp2_ses_remove_task_locked(sp, task);
	mutex_exit(&sp->s_task_mutex);

	return (ret);
}

/*
 * Return first task on the list in specified state.
 */
sbp2_task_t *
sbp2_ses_find_task_state(sbp2_ses_t *sp, sbp2_task_state_t state)
{
	sbp2_task_t	*task = NULL;

	mutex_enter(&sp->s_task_mutex);
	for (task = sp->s_task_head; task != NULL; task = task->ts_next) {
		if (task->ts_state == state) {
			break;
		}
	}
	mutex_exit(&sp->s_task_mutex);

	return (task);
}

/*
 * Remove first task on the list. Returns pointer to the removed task or NULL.
 */
sbp2_task_t *
sbp2_ses_remove_first_task(sbp2_ses_t *sp)
{
	sbp2_task_t	*task = NULL;

	mutex_enter(&sp->s_task_mutex);
	task = sp->s_task_head;
	if (task != NULL) {
		(void) sbp2_ses_remove_task_locked(sp, task);
	}
	mutex_exit(&sp->s_task_mutex);

	return (task);
}

/*
 * Remove first task on the list only if it's in specified state.
 * Returns pointer to the removed task or NULL.
 */
sbp2_task_t *
sbp2_ses_remove_first_task_state(sbp2_ses_t *sp, sbp2_task_state_t state)
{
	sbp2_task_t	*task = NULL;

	mutex_enter(&sp->s_task_mutex);
	if ((sp->s_task_head != NULL) && (sp->s_task_head->ts_state == state)) {
		task = sp->s_task_head;
		(void) sbp2_ses_remove_task_locked(sp, task);
	}
	mutex_exit(&sp->s_task_mutex);

	return (task);
}

/*
 * Remove first task on the list. If there's timeout, untimeout it.
 * Returns pointer to the removed task or NULL.
 */
sbp2_task_t *
sbp2_ses_cancel_first_task(sbp2_ses_t *sp)
{
	sbp2_task_t	*task = NULL;
	timeout_id_t	timeout_id;

	mutex_enter(&sp->s_task_mutex);
	task = sp->s_task_head;
	if (task != NULL) {
		(void) sbp2_ses_remove_task_locked(sp, task);
	}
	mutex_exit(&sp->s_task_mutex);

	if ((task != NULL) && ((timeout_id = task->ts_timeout_id) != 0)) {
		task->ts_timeout_id = 0;
		(void) untimeout(timeout_id);
	}

	return (task);
}

/*
 * Reset pending tasks on the list to their initial state.
 */
static void
sbp2_ses_reset_pending_tasks(sbp2_ses_t *sp, uint16_t nodeID)
{
	sbp2_agent_t	*ap = &sp->s_agent;
	sbp2_task_t	*task = NULL;
	timeout_id_t	timeout_id;
	sbp2_cmd_orb_t	*orb;

	mutex_enter(&sp->s_task_mutex);
	for (task = sp->s_task_head; task != NULL; task = task->ts_next) {
		task->ts_state = SBP2_TASK_INIT;

		/* cancel timeout */
		if ((timeout_id = task->ts_timeout_id) != 0) {
			task->ts_timeout_id = 0;
			(void) untimeout(timeout_id);
		}

		/* update ORB nodeID */
		orb = (sbp2_cmd_orb_t *)sbp2_task_orb_kaddr(task);
		*(uint16_t *)orb->co_data_descr = SBP2_SWAP16(nodeID);
		sbp2_task_orb_sync(sp->s_lun, task, DDI_DMA_SYNC_FORDEV);
	}
	mutex_exit(&sp->s_task_mutex);

	mutex_enter(&ap->a_mutex);
	ap->a_active_task = NULL;
	mutex_exit(&ap->a_mutex);
}

int
sbp2_ses_agent_reset(sbp2_ses_t *sp, int *berr)
{
	return (sbp2_agent_reset(&sp->s_agent, berr));
}

int
sbp2_ses_abort_task(sbp2_ses_t *sp, sbp2_task_t *task, int *berr)
{
	sbp2_tgt_t	*tp = sp->s_tgt;
	sbp2_lun_t	*lp = sp->s_lun;
	uint16_t	params;
	sbp2_cmd_orb_t	*orb = (sbp2_cmd_orb_t *)task->ts_buf->bb_kaddr;
	int		ret = SBP2_SUCCESS;

	/* mark ORB as dummy ORB */
	params = (orb->co_params & ~SBP2_ORB_RQ_FMT) | SBP2_ORB_RQ_FMT_DUMMY;
	orb->co_params = params;
	(void) SBP2_SYNC_BUF(tp, task->ts_buf, 0, 0, DDI_DMA_SYNC_FORDEV);

	ret = sbp2_tgt_task_mgt_request(tp, lp->l_login_resp.lr_login_id,
	    SBP2_ORB_MGT_FUNC_ABORT_TASK, task->ts_buf->bb_baddr, berr);

	return (ret);
}


int
sbp2_ses_abort_task_set(sbp2_ses_t *sp, int *berr)
{
	sbp2_tgt_t	*tp = sp->s_tgt;
	sbp2_lun_t	*lp = sp->s_lun;
	int		ret;

	ret = sbp2_tgt_task_mgt_request(tp, lp->l_login_resp.lr_login_id,
	    SBP2_ORB_MGT_FUNC_ABORT_TASK_SET, 0, berr);

	return (ret);
}


/*
 *
 * ORB functions
 *
 * allocate ORB resources
 *
 * we maintain a freelist of ORB's for faster allocation
 */
/*ARGSUSED*/
static sbp2_bus_buf_t *
sbp2_orb_freelist_get(sbp2_lun_t *lp, sbp2_task_t *task, int len)
{
	sbp2_buf_list_t	*bl = &lp->l_orb_freelist;
	sbp2_bus_buf_t	*buf = NULL;

	mutex_enter(&bl->bl_mutex);
	if ((bl->bl_head != NULL) && (bl->bl_head->bb_len == len)) {
		buf = bl->bl_head;
		bl->bl_head = buf->bb_next;
		if (bl->bl_tail == buf) {	/* last one? */
			ASSERT(bl->bl_head == NULL);
			bl->bl_tail = NULL;
		}
		bl->bl_len--;
		buf->bb_next = NULL;
	}
	mutex_exit(&bl->bl_mutex);

	return (buf);
}

static int
sbp2_orb_freelist_put(sbp2_lun_t *lp, sbp2_bus_buf_t *buf)
{
	sbp2_buf_list_t	*bl = &lp->l_orb_freelist;
	int		ret;

	mutex_enter(&bl->bl_mutex);
	if (bl->bl_len < SBP2_ORB_FREELIST_MAX) {
		if (bl->bl_head == NULL) {
			ASSERT(bl->bl_tail == NULL);
			bl->bl_head = bl->bl_tail = buf;
		} else {
			bl->bl_tail->bb_next = buf;
			bl->bl_tail = buf;
		}
		buf->bb_next = NULL;
		bl->bl_len++;
		ret = SBP2_SUCCESS;
	} else {
		ret = SBP2_FAILURE;
	}
	mutex_exit(&bl->bl_mutex);

	return (ret);
}

static void
sbp2_orb_freelist_destroy(sbp2_lun_t *lp)
{
	sbp2_tgt_t	*tp = lp->l_tgt;
	sbp2_buf_list_t	*bl = &lp->l_orb_freelist;
	sbp2_bus_buf_t	*buf, *buf_next;

	mutex_enter(&bl->bl_mutex);
	for (buf = bl->bl_head; buf != NULL; ) {
		SBP2_FREE_BUF(tp, buf);
		buf_next = buf->bb_next;
		kmem_free(buf, sizeof (sbp2_bus_buf_t));
		buf = buf_next;
	}
	bl->bl_head = bl->bl_tail = NULL;
	mutex_exit(&bl->bl_mutex);
}

int
sbp2_task_orb_alloc(sbp2_lun_t *lp, sbp2_task_t *task, int len)
{
	sbp2_tgt_t	*tp = lp->l_tgt;
	int		buf_len;
	int		ret;

	buf_len = SBP2_ORB_SIZE_ROUNDUP(tp, len);

	/* try freelist first */
	if ((task->ts_buf = sbp2_orb_freelist_get(lp, task, buf_len)) != NULL) {
		return (SBP2_SUCCESS);
	}

	/* if no free buffers, allocate new */
	task->ts_buf = kmem_zalloc(sizeof (sbp2_bus_buf_t), KM_SLEEP);
	task->ts_buf->bb_len = buf_len;
	task->ts_buf->bb_flags = SBP2_BUS_BUF_DMA | SBP2_BUS_BUF_RD;
	if ((ret = SBP2_ALLOC_BUF(tp, task->ts_buf)) != SBP2_SUCCESS) {
		kmem_free(task->ts_buf, sizeof (sbp2_bus_buf_t));
		task->ts_buf = NULL;
	}

	return (ret);
}

void
sbp2_task_orb_free(sbp2_lun_t *lp, sbp2_task_t *task)
{
	sbp2_tgt_t	*tp = lp->l_tgt;

	if (task->ts_buf != NULL) {
		if (sbp2_orb_freelist_put(lp, task->ts_buf) != SBP2_SUCCESS) {
			SBP2_FREE_BUF(tp, task->ts_buf);
			kmem_free(task->ts_buf, sizeof (sbp2_bus_buf_t));
		}
		task->ts_buf = NULL;
	}
}

void *
sbp2_task_orb_kaddr(sbp2_task_t *task)
{
	return (task->ts_buf->bb_kaddr);
}

void
sbp2_task_orb_sync(sbp2_lun_t *lp, sbp2_task_t *task, int flags)
{
	(void) SBP2_SYNC_BUF(lp->l_tgt, task->ts_buf, 0, 0, flags);
}

/*
 *
 * --- fetch agent routines
 *
 */
static int
sbp2_agent_init(sbp2_agent_t *ap, uint64_t offset, sbp2_tgt_t *tp)
{
	int	ret;

	/* paranoia */
	if (offset == 0) {
		return (SBP2_FAILURE);
	}

	ap->a_tgt = tp;

	ap->a_reg_agent_state = offset + SBP2_AGENT_STATE_OFFSET;
	ap->a_reg_agent_reset = offset + SBP2_AGENT_RESET_OFFSET;
	ap->a_reg_orbp = offset + SBP2_ORB_POINTER_OFFSET;
	ap->a_reg_doorbell = offset + SBP2_DOORBELL_OFFSET;
	ap->a_reg_unsol_status_enable = offset +
	    SBP2_UNSOLICITED_STATUS_ENABLE_OFFSET;

	/*
	 * allocate bus commands
	 */
	if ((ret = SBP2_ALLOC_CMD(tp, &ap->a_cmd, 0)) != SBP2_SUCCESS) {
		return (ret);
	}
	ap->a_cmd_data = allocb(sizeof (sbp2_orbp_t), BPRI_HI);
	if (ap->a_cmd_data == NULL) {
		sbp2_agent_fini(ap);
		return (SBP2_ENOMEM);
	}

	mutex_init(&ap->a_mutex, NULL, MUTEX_DRIVER,
	    SBP2_GET_IBLOCK_COOKIE(tp));
	cv_init(&ap->a_cv, NULL, CV_DRIVER, NULL);

#ifndef __lock_lint
	ap->a_state = SBP2_AGENT_STATE_RESET;
#endif

	return (SBP2_SUCCESS);
}


static void
sbp2_agent_fini(sbp2_agent_t *ap)
{
	sbp2_tgt_t	*tp = ap->a_tgt;

	/* free bus commands */
	if (ap->a_cmd != NULL) {
		SBP2_FREE_CMD(tp, ap->a_cmd);
	}
	if (ap->a_cmd_data != NULL) {
		freeb(ap->a_cmd_data);
	}
	cv_destroy(&ap->a_cv);
	mutex_destroy(&ap->a_mutex);
}


static void
sbp2_agent_acquire_locked(sbp2_agent_t *ap)
{
	while (ap->a_acquired) {
		cv_wait(&ap->a_cv, &ap->a_mutex);
	}
	ap->a_acquired = B_TRUE;
}


static void
sbp2_agent_release_locked(sbp2_agent_t *ap)
{
	ap->a_acquired = B_FALSE;
	cv_signal(&ap->a_cv);		/* wake next waiter */
}


static void
sbp2_agent_acquire(sbp2_agent_t *ap)
{
	mutex_enter(&ap->a_mutex);
	sbp2_agent_acquire_locked(ap);
	mutex_exit(&ap->a_mutex);
}


static void
sbp2_agent_release(sbp2_agent_t *ap)
{
	mutex_enter(&ap->a_mutex);
	sbp2_agent_release_locked(ap);
	mutex_exit(&ap->a_mutex);
}


static int
sbp2_agent_keepalive(sbp2_agent_t *ap, int *berr)
{
	boolean_t	acquired;
	int		ret = SBP2_SUCCESS;

	ASSERT(mutex_owned(&ap->a_mutex));

	if (ap->a_state == SBP2_AGENT_STATE_DEAD) {
		acquired = ap->a_acquired;
		if (!acquired) {
			sbp2_agent_acquire_locked(ap);
		}

		mutex_exit(&ap->a_mutex);
		ret = sbp2_agent_reset(ap, berr);
		mutex_enter(&ap->a_mutex);

		if (!acquired) {
			sbp2_agent_release_locked(ap);
		}
	}

	return (ret);
}

#ifndef __lock_lint
static int
sbp2_agent_doorbell(sbp2_agent_t *ap, int *berr)
{
	return (SBP2_WQ(ap->a_tgt, ap->a_cmd, ap->a_reg_doorbell, 0, berr));
}
#endif

/*
 * write into ORB_POINTER register and make sure it reached target
 *
 * From E.2: "If no acknowledgement is received by the initiator after a write
 * 	to the ORB_POINTER register, the initiator should not retry the write.
 *	The recommended method for error recovery is a write to the AGENT_RESET
 *	register." So we can retry, but not in case of timeout.
 */
static int
sbp2_agent_write_orbp(sbp2_agent_t *ap, uint64_t baddr, int *berr)
{
	int		i = 0;
	int		ret;

	SBP2_ORBP_SET(ap->a_cmd_data->b_rptr, baddr);
	ap->a_cmd_data->b_wptr = ap->a_cmd_data->b_rptr + 8;

	for (;;) {
		ap->a_tgt->t_stat.stat_agent_worbp++;
		if ((ret = SBP2_WB(ap->a_tgt, ap->a_cmd, ap->a_reg_orbp,
		    ap->a_cmd_data, 8, berr)) == SBP2_SUCCESS) {
			return (ret);
		}
		ap->a_tgt->t_stat.stat_agent_worbp_fail++;

		if ((ret == SBP2_ETIMEOUT) ||
		    (++i > sbp2_write_orbp_nretries)) {
			break;
		}
		if (sbp2_write_orbp_delay > 0) {
			drv_usecwait(sbp2_write_orbp_delay);
		}
	}

	return (ret);
}


/*
 * reset fetch agent by writing into AGENT_RESET register
 */
static int
sbp2_agent_reset(sbp2_agent_t *ap, int *berr)
{
	int	i = 0;
	int	ret;

	for (;;) {
		ap->a_tgt->t_stat.stat_agent_wreset++;
		if ((ret = SBP2_WQ(ap->a_tgt, ap->a_cmd, ap->a_reg_agent_reset,
		    0, berr)) == SBP2_SUCCESS) {
			mutex_enter(&ap->a_mutex);
			ap->a_state = SBP2_AGENT_STATE_RESET;
			mutex_exit(&ap->a_mutex);
			break;
		}

		ap->a_tgt->t_stat.stat_agent_wreset_fail++;
		if (++i > sbp2_submit_reset_nretries) {
			break;
		}
		if (sbp2_submit_reset_delay > 0) {
			drv_usecwait(sbp2_submit_reset_delay);
		}
	}
	return (ret);
}

/*
 *
 * --- callbacks and timeouts
 *
 */
/*
 * Status FIFO callback for mgt ORB's.
 */
/*ARGSUSED*/
static void
sbp2_mgt_status_fifo_wb_cb(sbp2_bus_buf_t *buf, void *reqh, mblk_t **bpp)
{
	sbp2_tgt_t	*tp = buf->bb_sbp2_priv;
	int		len;
	sbp2_status_t	*st;
	uint64_t	orbp;

	len = MBLKL(*bpp);

	/* 8 bytes minimum */
	if (len < 8) {
		SBP2_BUF_WR_DONE(tp, buf, reqh, SBP2_BUS_BUF_ELENGTH);
		tp->t_stat.stat_status_short++;
		return;
	}

	/* convert 2-quadlet header from BE to native endianness */
	st = (sbp2_status_t *)(*bpp)->b_rptr;
	SBP2_SWAP16_1(st->st_orb_offset_hi);
	SBP2_SWAP32_1(st->st_orb_offset_lo);
	orbp = ((uint64_t)st->st_orb_offset_hi << 32) | st->st_orb_offset_lo;

	if (orbp != tp->t_mgt_orb_buf.bb_baddr) {
		SBP2_BUF_WR_DONE(tp, buf, reqh, SBP2_BUS_BUF_FAILURE);
		tp->t_stat.stat_status_mgt_notask++;
		return;
	}

	/* make a local copy of status block */
	bzero(&tp->t_mgt_status, sizeof (sbp2_status_t));
	bcopy((*bpp)->b_rptr, &tp->t_mgt_status, len);

	SBP2_BUF_WR_DONE(tp, buf, reqh, SBP2_BUS_BUF_SUCCESS);

	/* wake up waiter */
	mutex_enter(&tp->t_mutex);
	tp->t_mgt_status_rcvd = B_TRUE;
	cv_signal(&tp->t_mgt_status_cv);
	mutex_exit(&tp->t_mutex);
}

static void
sbp2_task_timeout(void *arg)
{
	sbp2_task_t	*task = arg;
	sbp2_ses_t	*sp = task->ts_ses;
	sbp2_agent_t	*ap = &sp->s_agent;

	mutex_enter(&ap->a_mutex);

	/* cancelled? */
	if (task->ts_timeout_id == 0) {
		mutex_exit(&ap->a_mutex);
		return;
	}
	task->ts_timeout_id = 0;
	task->ts_time_comp = gethrtime();

	/* avoid race with other callbacks */
	if (task->ts_state != SBP2_TASK_PEND) {
		mutex_exit(&ap->a_mutex);
		return;
	}

	if (task == ap->a_active_task) {
		ap->a_active_task = NULL;
	}
	task->ts_error = SBP2_TASK_ERR_TIMEOUT;
	task->ts_state = SBP2_TASK_COMP;

	/* we mark agent DEAD so it's reset before next task is submitted */
	ap->a_state = SBP2_AGENT_STATE_DEAD;
	sp->s_tgt->t_stat.stat_status_dead++;
	mutex_exit(&ap->a_mutex);

	sp->s_status_cb(sp->s_status_cb_arg, task);
}

/*
 * Status FIFO callback for command ORB's. Also used for login ORB.
 */
/*ARGSUSED*/
static void
sbp2_status_fifo_wb_cb(sbp2_bus_buf_t *buf, void *reqh, mblk_t **bpp)
{
	sbp2_ses_t	*sp = buf->bb_sbp2_priv;
	sbp2_tgt_t	*tp = sp->s_tgt;
	sbp2_agent_t	*ap = &sp->s_agent;
	int		len;
	sbp2_status_t	*st;
	uint8_t		src;
	uint64_t	orbp;
	sbp2_task_t	*task;
	timeout_id_t	timeout_id;

	len = MBLKL(*bpp);

	/* 8 bytes minimum */
	if (len < 8) {
		SBP2_BUF_WR_DONE(tp, buf, reqh, SBP2_BUS_BUF_ELENGTH);
		tp->t_stat.stat_status_short++;
		return;
	}

	/* convert 2-quadlet header from BE32 to native endianness */
	st = (sbp2_status_t *)(*bpp)->b_rptr;
	SBP2_SWAP16_1(st->st_orb_offset_hi);
	SBP2_SWAP32_1(st->st_orb_offset_lo);

	orbp = ((uint64_t)st->st_orb_offset_hi << 32) | st->st_orb_offset_lo;

	/* login ORB status? */
	if (orbp == tp->t_mgt_orb_buf.bb_baddr) {
		bzero(&tp->t_mgt_status, sizeof (sbp2_status_t));
		bcopy((*bpp)->b_rptr, &tp->t_mgt_status, len);

		SBP2_BUF_WR_DONE(tp, buf, reqh, SBP2_BUS_BUF_SUCCESS);

		/* wake up waiter */
		mutex_enter(&tp->t_mutex);
		tp->t_mgt_status_rcvd = B_TRUE;
		cv_signal(&tp->t_mgt_status_cv);
		mutex_exit(&tp->t_mutex);
		return;
	}

	/* dismiss unsolicited status */
	src = st->st_param & SBP2_ST_SRC;
	if (src == SBP2_ST_SRC_UNSOLICITED) {
		SBP2_BUF_WR_DONE(tp, buf, reqh, SBP2_BUS_BUF_FAILURE);
		tp->t_stat.stat_status_unsolicited++;
		return;
	}

	/* find task corresponding to this ORB pointer */
	if ((task = sbp2_ses_orbp2task(sp, orbp)) == NULL) {
		SBP2_BUF_WR_DONE(tp, buf, reqh, SBP2_BUS_BUF_FAILURE);
		tp->t_stat.stat_status_notask++;
		return;
	}

	/*
	 * Copy status block into a local buffer.
	 *
	 * Note: (ref: B.2) "SBP-2 permits the return of a status block between
	 *	two and eight quadlets in length. When a truncated status block
	 *	is stored, the omited quadlets shall be interpreted as if zero
	 *	values were stored."
	 */
	bzero(&task->ts_status, sizeof (sbp2_status_t));
	bcopy((*bpp)->b_rptr, &task->ts_status, len);

	SBP2_BUF_WR_DONE(tp, buf, reqh, SBP2_BUS_BUF_SUCCESS);

	mutex_enter(&ap->a_mutex);

	if ((timeout_id = task->ts_timeout_id) != 0) {
		task->ts_timeout_id = 0;
		(void) untimeout(timeout_id);
	}

	/* determine agent state */
	if (st->st_param & SBP2_ST_DEAD) {
		ap->a_state = SBP2_AGENT_STATE_DEAD;
		tp->t_stat.stat_status_dead++;
	}

	/* avoid race with other callbacks */
	if (task->ts_state != SBP2_TASK_PEND) {
		mutex_exit(&ap->a_mutex);
		return;
	}

	if (task == ap->a_active_task) {
		ap->a_active_task = NULL;
	}
	task->ts_error = SBP2_TASK_ERR_NONE;
	task->ts_state = SBP2_TASK_COMP;

	mutex_exit(&ap->a_mutex);

	sp->s_status_cb(sp->s_status_cb_arg, task);	/* notify the driver */
}

/*
 *
 * --- other
 *
 * since mgt agent is shared between LUNs and login sessions,
 * it is safer to serialize mgt requests
 */
static void
sbp2_mgt_agent_acquire(sbp2_tgt_t *tp)
{
	mutex_enter(&tp->t_mutex);
	while (tp->t_mgt_agent_acquired) {
		cv_wait(&tp->t_mgt_agent_cv, &tp->t_mutex);
	}
	tp->t_mgt_agent_acquired = B_TRUE;
	mutex_exit(&tp->t_mutex);
}

static void
sbp2_mgt_agent_release(sbp2_tgt_t *tp)
{
	mutex_enter(&tp->t_mutex);
	tp->t_mgt_agent_acquired = B_FALSE;
	cv_signal(&tp->t_mgt_agent_cv);	/* wake next waiter */
	mutex_exit(&tp->t_mutex);
}
