/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020, The University of Queensland
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Mellanox Connect-X 4/5/6 driver.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/cpuvar.h>

#include <sys/pattr.h>
#include <sys/dlpi.h>

#include <sys/mac_provider.h>

#include <sys/random.h>

#include <mlxcx.h>

boolean_t
mlxcx_wq_alloc_dma(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;
	boolean_t ret;
	size_t sz;

	VERIFY0(mlwq->mlwq_state & MLXCX_WQ_ALLOC);

	/* Receive and send queue entries might be different sizes. */
	switch (mlwq->mlwq_type) {
	case MLXCX_WQ_TYPE_SENDQ:
		mlwq->mlwq_entshift = mlxp->mlx_props.mldp_sq_size_shift;
		mlwq->mlwq_nents = (1 << mlwq->mlwq_entshift);
		sz = mlwq->mlwq_nents * sizeof (mlxcx_sendq_ent_t);
		break;
	case MLXCX_WQ_TYPE_RECVQ:
		mlwq->mlwq_entshift = mlxp->mlx_props.mldp_rq_size_shift;
		mlwq->mlwq_nents = (1 << mlwq->mlwq_entshift);
		sz = mlwq->mlwq_nents * sizeof (mlxcx_recvq_ent_t);
		break;
	default:
		VERIFY(0);
		return (B_FALSE);
	}
	ASSERT3U(sz & (MLXCX_HW_PAGE_SIZE - 1), ==, 0);

	mlxcx_dma_acc_attr(mlxp, &acc);
	mlxcx_dma_queue_attr(mlxp, &attr);

	ret = mlxcx_dma_alloc(mlxp, &mlwq->mlwq_dma, &attr, &acc,
	    B_TRUE, sz, B_TRUE);
	if (!ret) {
		mlxcx_warn(mlxp, "failed to allocate WQ memory");
		return (B_FALSE);
	}

	/*
	 * Just set the first pointer in the union. Yes, this is a strict
	 * aliasing violation. No, I don't care.
	 */
	mlwq->mlwq_send_ent = (mlxcx_sendq_ent_t *)mlwq->mlwq_dma.mxdb_va;

	mlxcx_dma_acc_attr(mlxp, &acc);
	mlxcx_dma_qdbell_attr(mlxp, &attr);
	sz = sizeof (mlxcx_workq_doorbell_t);
	ret = mlxcx_dma_alloc(mlxp, &mlwq->mlwq_doorbell_dma, &attr, &acc,
	    B_TRUE, sz, B_TRUE);
	if (!ret) {
		mlxcx_warn(mlxp, "failed to allocate WQ doorbell memory");
		mlxcx_dma_free(&mlwq->mlwq_dma);
		mlwq->mlwq_send_ent = NULL;
		return (B_FALSE);
	}

	mlwq->mlwq_doorbell =
	    (mlxcx_workq_doorbell_t *)mlwq->mlwq_doorbell_dma.mxdb_va;

	mlwq->mlwq_state |= MLXCX_WQ_ALLOC;

	return (B_TRUE);
}

void
mlxcx_wq_rele_dma(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	VERIFY(mlwq->mlwq_state & MLXCX_WQ_ALLOC);
	if (mlwq->mlwq_state & MLXCX_WQ_CREATED)
		VERIFY(mlwq->mlwq_state & MLXCX_WQ_DESTROYED);

	mlxcx_dma_free(&mlwq->mlwq_dma);
	mlwq->mlwq_send_ent = NULL;
	mlxcx_dma_free(&mlwq->mlwq_doorbell_dma);
	mlwq->mlwq_doorbell = NULL;

	mlwq->mlwq_state &= ~MLXCX_CQ_ALLOC;
}

boolean_t
mlxcx_cq_alloc_dma(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq)
{
	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;
	boolean_t ret;
	size_t sz, i;

	VERIFY0(mlcq->mlcq_state & MLXCX_EQ_ALLOC);

	mlcq->mlcq_entshift = mlxp->mlx_props.mldp_cq_size_shift;
	mlcq->mlcq_nents = (1 << mlcq->mlcq_entshift);
	sz = mlcq->mlcq_nents * sizeof (mlxcx_completionq_ent_t);
	ASSERT3U(sz & (MLXCX_HW_PAGE_SIZE - 1), ==, 0);

	mlxcx_dma_acc_attr(mlxp, &acc);
	mlxcx_dma_queue_attr(mlxp, &attr);

	ret = mlxcx_dma_alloc(mlxp, &mlcq->mlcq_dma, &attr, &acc,
	    B_TRUE, sz, B_TRUE);
	if (!ret) {
		mlxcx_warn(mlxp, "failed to allocate CQ memory");
		return (B_FALSE);
	}

	mlcq->mlcq_ent = (mlxcx_completionq_ent_t *)mlcq->mlcq_dma.mxdb_va;

	for (i = 0; i < mlcq->mlcq_nents; ++i) {
		mlcq->mlcq_ent[i].mlcqe_opcode = MLXCX_CQE_OP_INVALID;
		mlcq->mlcq_ent[i].mlcqe_owner = MLXCX_CQE_OWNER_INIT;
	}

	mlxcx_dma_acc_attr(mlxp, &acc);
	mlxcx_dma_qdbell_attr(mlxp, &attr);
	sz = sizeof (mlxcx_completionq_doorbell_t);
	ret = mlxcx_dma_alloc(mlxp, &mlcq->mlcq_doorbell_dma, &attr, &acc,
	    B_TRUE, sz, B_TRUE);
	if (!ret) {
		mlxcx_warn(mlxp, "failed to allocate CQ doorbell memory");
		mlxcx_dma_free(&mlcq->mlcq_dma);
		mlcq->mlcq_ent = NULL;
		return (B_FALSE);
	}

	mlcq->mlcq_doorbell =
	    (mlxcx_completionq_doorbell_t *)mlcq->mlcq_doorbell_dma.mxdb_va;

	mlcq->mlcq_state |= MLXCX_CQ_ALLOC;

	return (B_TRUE);
}

void
mlxcx_cq_rele_dma(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq)
{
	VERIFY(mlcq->mlcq_state & MLXCX_CQ_ALLOC);
	if (mlcq->mlcq_state & MLXCX_CQ_CREATED)
		VERIFY(mlcq->mlcq_state & MLXCX_CQ_DESTROYED);

	mlxcx_dma_free(&mlcq->mlcq_dma);
	mlcq->mlcq_ent = NULL;
	mlxcx_dma_free(&mlcq->mlcq_doorbell_dma);
	mlcq->mlcq_doorbell = NULL;

	mlcq->mlcq_state &= ~MLXCX_CQ_ALLOC;
}

void
mlxcx_wq_teardown(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	mlxcx_completion_queue_t *mlcq;

	/*
	 * If something is holding the lock on a long operation like a
	 * refill, setting this flag asks them to exit early if possible.
	 */
	atomic_or_uint(&mlwq->mlwq_state, MLXCX_WQ_TEARDOWN);

	mutex_enter(&mlwq->mlwq_mtx);

	list_remove(&mlxp->mlx_wqs, mlwq);

	if ((mlwq->mlwq_state & MLXCX_WQ_CREATED) &&
	    !(mlwq->mlwq_state & MLXCX_WQ_DESTROYED)) {
		if (mlwq->mlwq_type == MLXCX_WQ_TYPE_RECVQ &&
		    mlwq->mlwq_state & MLXCX_WQ_STARTED &&
		    !mlxcx_cmd_stop_rq(mlxp, mlwq)) {
			mlxcx_warn(mlxp, "failed to stop "
			    "recv queue num %x", mlwq->mlwq_num);
		}
		if (mlwq->mlwq_type == MLXCX_WQ_TYPE_SENDQ &&
		    mlwq->mlwq_state & MLXCX_WQ_STARTED &&
		    !mlxcx_cmd_stop_sq(mlxp, mlwq)) {
			mlxcx_warn(mlxp, "failed to stop "
			    "send queue num %x", mlwq->mlwq_num);
		}
		if (mlwq->mlwq_type == MLXCX_WQ_TYPE_RECVQ &&
		    !mlxcx_cmd_destroy_rq(mlxp, mlwq)) {
			mlxcx_warn(mlxp, "failed to destroy "
			    "recv queue num %x", mlwq->mlwq_num);
		}
		if (mlwq->mlwq_type == MLXCX_WQ_TYPE_SENDQ &&
		    !mlxcx_cmd_destroy_sq(mlxp, mlwq)) {
			mlxcx_warn(mlxp, "failed to destroy "
			    "send queue num %x", mlwq->mlwq_num);
		}
	}
	if (mlwq->mlwq_state & MLXCX_WQ_ALLOC) {
		mlxcx_wq_rele_dma(mlxp, mlwq);
	}
	mlcq = mlwq->mlwq_cq;

	/* These will be released by mlxcx_teardown_bufs() */
	mlwq->mlwq_bufs = NULL;
	mlwq->mlwq_foreign_bufs = NULL;

	mutex_exit(&mlwq->mlwq_mtx);

	mutex_enter(&mlcq->mlcq_mtx);
	mutex_enter(&mlwq->mlwq_mtx);
	ASSERT3P(mlcq->mlcq_wq, ==, mlwq);
	mlcq->mlcq_wq = NULL;
	mutex_exit(&mlwq->mlwq_mtx);
	mutex_exit(&mlcq->mlcq_mtx);

	mutex_destroy(&mlwq->mlwq_mtx);
}

void
mlxcx_cq_teardown(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq)
{
	mlxcx_event_queue_t *mleq;
	mlxcx_buffer_t *b;

	/*
	 * If something is holding the lock on a long operation like polling
	 * which we're going to abort anyway, this flag asks them to exit
	 * early if possible.
	 */
	atomic_or_uint(&mlcq->mlcq_state, MLXCX_CQ_TEARDOWN);

	mutex_enter(&mlcq->mlcq_mtx);

	list_remove(&mlxp->mlx_cqs, mlcq);

	if ((mlcq->mlcq_state & MLXCX_CQ_CREATED) &&
	    !(mlcq->mlcq_state & MLXCX_CQ_DESTROYED)) {
		if (!mlxcx_cmd_destroy_cq(mlxp, mlcq)) {
			mlxcx_warn(mlxp, "failed to destroy "
			    "completion queue num %u",
			    mlcq->mlcq_num);
		}
	}
	if (mlcq->mlcq_state & MLXCX_CQ_ALLOC) {
		mlxcx_cq_rele_dma(mlxp, mlcq);
	}
	/*
	 * If we're on an EQ AVL tree, then we need to grab
	 * the EQ's mutex to take it off. The ISR always takes
	 * EQ mutex before CQ mutex, so we have to let go of
	 * the CQ mutex then come back again.
	 *
	 * The ISR will bail out if tries to touch this CQ now since
	 * we added the CQ_DESTROYED flag above.
	 */
	if (mlcq->mlcq_state & MLXCX_CQ_EQAVL) {
		mleq = mlcq->mlcq_eq;
	} else {
		mleq = NULL;
	}

	/* Return any outstanding buffers to the free pool. */
	while ((b = list_remove_head(&mlcq->mlcq_buffers)) != NULL) {
		mlxcx_buf_return_chain(mlxp, b, B_FALSE);
	}
	mutex_enter(&mlcq->mlcq_bufbmtx);
	while ((b = list_remove_head(&mlcq->mlcq_buffers_b)) != NULL) {
		mlxcx_buf_return_chain(mlxp, b, B_FALSE);
	}
	mutex_exit(&mlcq->mlcq_bufbmtx);

	/*
	 * Since the interrupt handlers take the EQ lock before the CQ one,
	 * we must do the same here. That means letting go of the lock
	 * for a brief window here (we'll double-check the state when we
	 * get back in).
	 */
	mutex_exit(&mlcq->mlcq_mtx);

	if (mleq != NULL) {
		mutex_enter(&mleq->mleq_mtx);
		mutex_enter(&mlcq->mlcq_mtx);
		/*
		 * Double-check the state, we let go of the
		 * mutex briefly.
		 */
		if (mlcq->mlcq_state & MLXCX_CQ_EQAVL) {
			avl_remove(&mleq->mleq_cqs, mlcq);
			mlcq->mlcq_state &= ~MLXCX_CQ_EQAVL;
		}
		mutex_exit(&mlcq->mlcq_mtx);
		mutex_exit(&mleq->mleq_mtx);
	}

	mutex_enter(&mlcq->mlcq_mtx);
	ASSERT0(mlcq->mlcq_state & ~(MLXCX_CQ_CREATED | MLXCX_CQ_DESTROYED |
	    MLXCX_CQ_TEARDOWN | MLXCX_CQ_ARMED));
	mutex_exit(&mlcq->mlcq_mtx);

	mutex_destroy(&mlcq->mlcq_mtx);
	mutex_destroy(&mlcq->mlcq_bufbmtx);
	list_destroy(&mlcq->mlcq_buffers);
	list_destroy(&mlcq->mlcq_buffers_b);
	kmem_free(mlcq, sizeof (mlxcx_completion_queue_t));
}

static boolean_t
mlxcx_cq_setup(mlxcx_t *mlxp, mlxcx_event_queue_t *eq,
    mlxcx_completion_queue_t **cqp)
{
	mlxcx_completion_queue_t *cq;

	cq = kmem_zalloc(sizeof (mlxcx_completion_queue_t), KM_SLEEP);
	mutex_init(&cq->mlcq_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mlxp->mlx_intr_pri));
	mutex_init(&cq->mlcq_bufbmtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mlxp->mlx_intr_pri));
	list_create(&cq->mlcq_buffers, sizeof (mlxcx_buffer_t),
	    offsetof(mlxcx_buffer_t, mlb_cq_entry));
	list_create(&cq->mlcq_buffers_b, sizeof (mlxcx_buffer_t),
	    offsetof(mlxcx_buffer_t, mlb_cq_entry));

	cq->mlcq_mlx = mlxp;
	list_insert_tail(&mlxp->mlx_cqs, cq);

	mutex_enter(&cq->mlcq_mtx);

	if (!mlxcx_cq_alloc_dma(mlxp, cq)) {
		mutex_exit(&cq->mlcq_mtx);
		return (B_FALSE);
	}

	cq->mlcq_bufhwm = cq->mlcq_nents - MLXCX_CQ_HWM_GAP;
	cq->mlcq_buflwm = cq->mlcq_nents - MLXCX_CQ_LWM_GAP;

	cq->mlcq_uar = &mlxp->mlx_uar;
	cq->mlcq_eq = eq;

	cq->mlcq_cqemod_period_usec = mlxp->mlx_props.mldp_cqemod_period_usec;
	cq->mlcq_cqemod_count = mlxp->mlx_props.mldp_cqemod_count;

	if (!mlxcx_cmd_create_cq(mlxp, cq)) {
		mutex_exit(&cq->mlcq_mtx);
		return (B_FALSE);
	}

	mutex_exit(&cq->mlcq_mtx);

	mutex_enter(&eq->mleq_mtx);
	mutex_enter(&cq->mlcq_mtx);
	ASSERT0(cq->mlcq_state & MLXCX_CQ_EQAVL);
	avl_add(&eq->mleq_cqs, cq);
	cq->mlcq_state |= MLXCX_CQ_EQAVL;
	mlxcx_arm_cq(mlxp, cq);
	mutex_exit(&cq->mlcq_mtx);
	mutex_exit(&eq->mleq_mtx);

	*cqp = cq;
	return (B_TRUE);
}

static boolean_t
mlxcx_rq_setup(mlxcx_t *mlxp, mlxcx_completion_queue_t *cq,
    mlxcx_work_queue_t *wq)
{
	mutex_init(&wq->mlwq_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mlxp->mlx_intr_pri));

	list_insert_tail(&mlxp->mlx_wqs, wq);

	mutex_enter(&wq->mlwq_mtx);

	wq->mlwq_mlx = mlxp;
	wq->mlwq_type = MLXCX_WQ_TYPE_RECVQ;
	wq->mlwq_cq = cq;
	wq->mlwq_pd = &mlxp->mlx_pd;
	wq->mlwq_uar = &mlxp->mlx_uar;

	wq->mlwq_bufs = mlxcx_mlbs_create(mlxp);

	if (!mlxcx_wq_alloc_dma(mlxp, wq)) {
		mutex_exit(&wq->mlwq_mtx);
		return (B_FALSE);
	}

	if (!mlxcx_cmd_create_rq(mlxp, wq)) {
		mutex_exit(&wq->mlwq_mtx);
		return (B_FALSE);
	}

	mutex_exit(&wq->mlwq_mtx);

	mutex_enter(&cq->mlcq_mtx);
	mutex_enter(&wq->mlwq_mtx);
	ASSERT3P(cq->mlcq_wq, ==, NULL);
	cq->mlcq_wq = wq;
	mutex_exit(&wq->mlwq_mtx);
	mutex_exit(&cq->mlcq_mtx);

	return (B_TRUE);
}

static boolean_t
mlxcx_sq_setup(mlxcx_t *mlxp, mlxcx_port_t *port, mlxcx_completion_queue_t *cq,
    mlxcx_tis_t *tis, mlxcx_work_queue_t *wq)
{
	mutex_init(&wq->mlwq_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mlxp->mlx_intr_pri));

	list_insert_tail(&mlxp->mlx_wqs, wq);

	mutex_enter(&wq->mlwq_mtx);

	wq->mlwq_mlx = mlxp;
	wq->mlwq_type = MLXCX_WQ_TYPE_SENDQ;
	wq->mlwq_cq = cq;
	wq->mlwq_pd = &mlxp->mlx_pd;
	wq->mlwq_uar = &mlxp->mlx_uar;
	wq->mlwq_tis = tis;

	wq->mlwq_bufs = mlxcx_mlbs_create(mlxp);
	wq->mlwq_foreign_bufs = mlxcx_mlbs_create(mlxp);

	VERIFY3U(port->mlp_wqe_min_inline, <=, MLXCX_ETH_INLINE_L2);
	wq->mlwq_inline_mode = MLXCX_ETH_INLINE_L2;

	if (!mlxcx_wq_alloc_dma(mlxp, wq)) {
		mutex_exit(&wq->mlwq_mtx);
		return (B_FALSE);
	}

	if (!mlxcx_cmd_create_sq(mlxp, wq)) {
		mutex_exit(&wq->mlwq_mtx);
		return (B_FALSE);
	}

	mutex_exit(&wq->mlwq_mtx);

	mutex_enter(&cq->mlcq_mtx);
	mutex_enter(&wq->mlwq_mtx);
	ASSERT3P(cq->mlcq_wq, ==, NULL);
	cq->mlcq_wq = wq;
	mutex_exit(&wq->mlwq_mtx);
	mutex_exit(&cq->mlcq_mtx);

	return (B_TRUE);
}

void
mlxcx_teardown_rx_group(mlxcx_t *mlxp, mlxcx_ring_group_t *g)
{
	mlxcx_work_queue_t *wq;
	mlxcx_completion_queue_t *cq;
	mlxcx_flow_entry_t *fe;
	mlxcx_flow_group_t *fg;
	mlxcx_flow_table_t *ft;
	uint_t i;

	mutex_enter(&g->mlg_port->mlp_mtx);
	mutex_enter(&g->mlg_mtx);

	if (g->mlg_state & MLXCX_GROUP_FLOWS) {
		mlxcx_remove_all_umcast_entries(mlxp, g->mlg_port, g);

		if (g->mlg_rx_vlan_ft != NULL)
			mlxcx_remove_all_vlan_entries(mlxp, g);

		if (g == &mlxp->mlx_rx_groups[0]) {
			ft = g->mlg_port->mlp_rx_flow;
			mutex_enter(&ft->mlft_mtx);

			fg = g->mlg_port->mlp_bcast;
			fe = list_head(&fg->mlfg_entries);
			if (fe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED) {
				(void) mlxcx_cmd_delete_flow_table_entry(
				    mlxp, fe);
			}

			fg = g->mlg_port->mlp_promisc;
			fe = list_head(&fg->mlfg_entries);
			if (fe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED) {
				(void) mlxcx_cmd_delete_flow_table_entry(
				    mlxp, fe);
			}

			mutex_exit(&ft->mlft_mtx);
		}

		if (g->mlg_rx_vlan_ft != NULL) {
			mutex_enter(&g->mlg_rx_vlan_ft->mlft_mtx);
			ASSERT(list_is_empty(&g->mlg_rx_vlans));
			fg = g->mlg_rx_vlan_def_fg;
			fe = list_head(&fg->mlfg_entries);
			if (fe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED) {
				(void) mlxcx_cmd_delete_flow_table_entry(
				    mlxp, fe);
			}
			fg = g->mlg_rx_vlan_promisc_fg;
			fe = list_head(&fg->mlfg_entries);
			if (fe->mlfe_state & MLXCX_FLOW_ENTRY_CREATED) {
				(void) mlxcx_cmd_delete_flow_table_entry(
				    mlxp, fe);
			}
			mlxcx_teardown_flow_table(mlxp, g->mlg_rx_vlan_ft);
			list_destroy(&g->mlg_rx_vlans);

			g->mlg_rx_vlan_ft = NULL;
		}

		mutex_enter(&g->mlg_rx_hash_ft->mlft_mtx);
		mlxcx_teardown_flow_table(mlxp, g->mlg_rx_hash_ft);
		g->mlg_rx_hash_ft = NULL;

		avl_destroy(&g->mlg_rx_macs);
		g->mlg_state &= ~MLXCX_GROUP_FLOWS;
	}

	if (g->mlg_state & MLXCX_GROUP_RUNNING) {
		for (i = 0; i < g->mlg_nwqs; ++i) {
			wq = &g->mlg_wqs[i];
			mutex_enter(&wq->mlwq_mtx);
			if (wq->mlwq_state & MLXCX_WQ_STARTED &&
			    !mlxcx_cmd_stop_rq(mlxp, wq)) {
				mlxcx_warn(mlxp, "failed to stop rq %x",
				    wq->mlwq_num);
			}
			mutex_exit(&wq->mlwq_mtx);
		}
		g->mlg_state &= ~MLXCX_GROUP_RUNNING;
	}

	if (g->mlg_state & MLXCX_GROUP_TIRTIS) {
		for (i = 0; i < MLXCX_TIRS_PER_GROUP; ++i) {
			mlxcx_tir_t *tir = &g->mlg_tir[i];
			if (tir->mltir_state & MLXCX_TIR_CREATED &&
			    !(tir->mltir_state & MLXCX_TIR_DESTROYED)) {
				if (!mlxcx_cmd_destroy_tir(mlxp, tir)) {
					mlxcx_warn(mlxp,
					    "failed to destroy tir %u "
					    "for rx ring", tir->mltir_num);
				}
			}
		}
		g->mlg_state &= ~MLXCX_GROUP_TIRTIS;
	}

	if (g->mlg_state & MLXCX_GROUP_RQT) {
		if (g->mlg_rqt->mlrqt_state & MLXCX_RQT_CREATED &&
		    !(g->mlg_rqt->mlrqt_state & MLXCX_RQT_DESTROYED)) {
			if (!mlxcx_cmd_destroy_rqt(mlxp, g->mlg_rqt)) {
				mlxcx_warn(mlxp, "failed to destroy rqt %u "
				    "for rx ring", g->mlg_rqt->mlrqt_num);
			}
			kmem_free(g->mlg_rqt->mlrqt_rq,
			    g->mlg_rqt->mlrqt_rq_size);
			g->mlg_rqt->mlrqt_rq = NULL;
			kmem_free(g->mlg_rqt, sizeof (mlxcx_rqtable_t));
			g->mlg_rqt = NULL;
		}
		g->mlg_state &= ~MLXCX_GROUP_RQT;
	}

	for (i = 0; i < g->mlg_nwqs; ++i) {
		wq = &g->mlg_wqs[i];
		cq = wq->mlwq_cq;
		mlxcx_wq_teardown(mlxp, wq);
		if (cq != NULL)
			mlxcx_cq_teardown(mlxp, cq);
	}
	kmem_free(g->mlg_wqs, g->mlg_wqs_size);
	g->mlg_wqs = NULL;
	g->mlg_state &= ~MLXCX_GROUP_WQS;

	mutex_exit(&g->mlg_mtx);
	mutex_exit(&g->mlg_port->mlp_mtx);

	mutex_destroy(&g->mlg_mtx);

	g->mlg_state &= ~MLXCX_GROUP_INIT;
	ASSERT3S(g->mlg_state, ==, 0);
}

void
mlxcx_teardown_tx_group(mlxcx_t *mlxp, mlxcx_ring_group_t *g)
{
	mlxcx_work_queue_t *wq;
	mlxcx_completion_queue_t *cq;
	uint_t i;

	mutex_enter(&g->mlg_mtx);

	if (g->mlg_state & MLXCX_GROUP_WQS) {
		for (i = 0; i < g->mlg_nwqs; ++i) {
			wq = &g->mlg_wqs[i];
			mutex_enter(&wq->mlwq_mtx);
			cq = wq->mlwq_cq;
			if (wq->mlwq_state & MLXCX_WQ_STARTED &&
			    !mlxcx_cmd_stop_sq(mlxp, wq)) {
				mlxcx_warn(mlxp, "failed to stop sq %x",
				    wq->mlwq_num);
			}
			mutex_exit(&wq->mlwq_mtx);
			mlxcx_wq_teardown(mlxp, wq);
			if (cq != NULL)
				mlxcx_cq_teardown(mlxp, cq);
		}
		g->mlg_state &= ~MLXCX_GROUP_RUNNING;
		kmem_free(g->mlg_wqs, g->mlg_wqs_size);
		g->mlg_wqs = NULL;
		g->mlg_state &= ~MLXCX_GROUP_WQS;
	}

	if ((g->mlg_state & MLXCX_GROUP_TIRTIS) &&
	    g->mlg_tis.mltis_state & MLXCX_TIS_CREATED &&
	    !(g->mlg_tis.mltis_state & MLXCX_TIS_DESTROYED)) {
		if (!mlxcx_cmd_destroy_tis(mlxp, &g->mlg_tis)) {
			mlxcx_warn(mlxp, "failed to destroy tis %u for tx ring",
			    g->mlg_tis.mltis_num);
		}
	}
	g->mlg_state &= ~MLXCX_GROUP_TIRTIS;

	mutex_exit(&g->mlg_mtx);
	mutex_destroy(&g->mlg_mtx);
	g->mlg_state &= ~MLXCX_GROUP_INIT;
	ASSERT3S(g->mlg_state, ==, 0);
}

void
mlxcx_teardown_groups(mlxcx_t *mlxp)
{
	mlxcx_ring_group_t *g;
	uint_t i;

	for (i = 0; i < mlxp->mlx_rx_ngroups; ++i) {
		g = &mlxp->mlx_rx_groups[i];
		if (!(g->mlg_state & MLXCX_GROUP_INIT))
			continue;
		ASSERT3S(g->mlg_type, ==, MLXCX_GROUP_RX);
		mlxcx_teardown_rx_group(mlxp, g);
	}
	kmem_free(mlxp->mlx_rx_groups, mlxp->mlx_rx_groups_size);
	mlxp->mlx_rx_groups = NULL;

	for (i = 0; i < mlxp->mlx_tx_ngroups; ++i) {
		g = &mlxp->mlx_tx_groups[i];
		if (!(g->mlg_state & MLXCX_GROUP_INIT))
			continue;
		ASSERT3S(g->mlg_type, ==, MLXCX_GROUP_TX);
		mlxcx_teardown_tx_group(mlxp, g);
	}
	kmem_free(mlxp->mlx_tx_groups, mlxp->mlx_tx_groups_size);
	mlxp->mlx_tx_groups = NULL;
}

boolean_t
mlxcx_rx_group_setup(mlxcx_t *mlxp, mlxcx_ring_group_t *g)
{
	mlxcx_event_queue_t *eq;
	mlxcx_completion_queue_t *cq;
	mlxcx_work_queue_t *rq;
	mlxcx_flow_table_t *ft;
	mlxcx_flow_group_t *fg;
	mlxcx_flow_entry_t *fe;
	uint_t i, j;

	ASSERT3S(g->mlg_state, ==, 0);

	mutex_init(&g->mlg_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mlxp->mlx_intr_pri));
	mutex_enter(&g->mlg_mtx);
	g->mlg_mlx = mlxp;
	g->mlg_type = MLXCX_GROUP_RX;
	g->mlg_port = &mlxp->mlx_ports[0];
	g->mlg_state |= MLXCX_GROUP_INIT;

	g->mlg_nwqs = mlxp->mlx_props.mldp_rx_nrings_per_small_group;
	i = g - &mlxp->mlx_rx_groups[0];
	if (i < mlxp->mlx_props.mldp_rx_ngroups_large)
		g->mlg_nwqs = mlxp->mlx_props.mldp_rx_nrings_per_large_group;

	g->mlg_wqs_size = g->mlg_nwqs * sizeof (mlxcx_work_queue_t);
	g->mlg_wqs = kmem_zalloc(g->mlg_wqs_size, KM_SLEEP);
	g->mlg_state |= MLXCX_GROUP_WQS;

	g->mlg_rqt = kmem_zalloc(sizeof (mlxcx_rqtable_t), KM_SLEEP);
	g->mlg_rqt->mlrqt_max = 2;
	while (g->mlg_rqt->mlrqt_max < g->mlg_nwqs)
		g->mlg_rqt->mlrqt_max <<= 1;
	g->mlg_rqt->mlrqt_rq_size = g->mlg_rqt->mlrqt_max *
	    sizeof (mlxcx_work_queue_t *);
	g->mlg_rqt->mlrqt_rq = kmem_zalloc(g->mlg_rqt->mlrqt_rq_size, KM_SLEEP);
	g->mlg_state |= MLXCX_GROUP_RQT;

	for (i = 0; i < g->mlg_nwqs; ++i) {
		eq = NULL;
		while (eq == NULL) {
			eq = &mlxp->mlx_eqs[mlxp->mlx_next_eq++];
			if (mlxp->mlx_next_eq >= mlxp->mlx_intr_count)
				mlxp->mlx_next_eq = 1;
			if (eq->mleq_type != MLXCX_EQ_TYPE_ANY &&
			    eq->mleq_type != MLXCX_EQ_TYPE_RX) {
				/* Try the next one */
				eq = NULL;
			}
		}

		if (!mlxcx_cq_setup(mlxp, eq, &cq)) {
			g->mlg_nwqs = i;
			break;
		}
		cq->mlcq_stats = &g->mlg_port->mlp_stats;

		rq = &g->mlg_wqs[i];
		if (!mlxcx_rq_setup(mlxp, cq, rq)) {
			g->mlg_nwqs = i;
			break;
		}
		g->mlg_rqt->mlrqt_rq[g->mlg_rqt->mlrqt_used++] = rq;
		g->mlg_rqt->mlrqt_state |= MLXCX_RQT_DIRTY;
		rq->mlwq_group = g;
	}
	if (g->mlg_nwqs == 0) {
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	if (!mlxcx_cmd_create_rqt(mlxp, g->mlg_rqt)) {
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	for (i = 0; i < MLXCX_TIRS_PER_GROUP; ++i) {
		mlxcx_tir_t *tir = &g->mlg_tir[i];
		tir->mltir_tdom = &mlxp->mlx_tdom;
		switch (i) {
		case MLXCX_TIR_ROLE_OTHER:
			tir->mltir_type = MLXCX_TIR_DIRECT;
			tir->mltir_rq = &g->mlg_wqs[0];
			break;
		case MLXCX_TIR_ROLE_IPv4:
		case MLXCX_TIR_ROLE_IPv6:
		case MLXCX_TIR_ROLE_TCPv4:
		case MLXCX_TIR_ROLE_TCPv6:
		case MLXCX_TIR_ROLE_UDPv4:
		case MLXCX_TIR_ROLE_UDPv6:
			tir->mltir_type = MLXCX_TIR_INDIRECT;
			tir->mltir_rqtable = g->mlg_rqt;
			tir->mltir_hash_fn = MLXCX_TIR_HASH_TOEPLITZ;
			(void) random_get_pseudo_bytes(tir->mltir_toeplitz_key,
			    sizeof (tir->mltir_toeplitz_key));
			break;
		}
		switch (i) {
		case MLXCX_TIR_ROLE_OTHER:
			break;
		case MLXCX_TIR_ROLE_IPv4:
		case MLXCX_TIR_ROLE_TCPv4:
		case MLXCX_TIR_ROLE_UDPv4:
			tir->mltir_l3_type = MLXCX_RX_HASH_L3_IPv4;
			tir->mltir_hash_fields =
			    MLXCX_RX_HASH_SRC_IP | MLXCX_RX_HASH_DST_IP;
			break;
		case MLXCX_TIR_ROLE_IPv6:
		case MLXCX_TIR_ROLE_TCPv6:
		case MLXCX_TIR_ROLE_UDPv6:
			tir->mltir_l3_type = MLXCX_RX_HASH_L3_IPv6;
			tir->mltir_hash_fields =
			    MLXCX_RX_HASH_SRC_IP | MLXCX_RX_HASH_DST_IP;
			break;
		}
		switch (i) {
		case MLXCX_TIR_ROLE_OTHER:
		case MLXCX_TIR_ROLE_IPv4:
		case MLXCX_TIR_ROLE_IPv6:
			break;
		case MLXCX_TIR_ROLE_TCPv4:
		case MLXCX_TIR_ROLE_TCPv6:
			tir->mltir_l4_type = MLXCX_RX_HASH_L4_TCP;
			tir->mltir_hash_fields |=
			    MLXCX_RX_HASH_L4_SPORT | MLXCX_RX_HASH_L4_DPORT;
			break;
		case MLXCX_TIR_ROLE_UDPv4:
		case MLXCX_TIR_ROLE_UDPv6:
			tir->mltir_l4_type = MLXCX_RX_HASH_L4_UDP;
			tir->mltir_hash_fields |=
			    MLXCX_RX_HASH_L4_SPORT | MLXCX_RX_HASH_L4_DPORT;
			break;
		}

		if (!mlxcx_cmd_create_tir(mlxp, tir)) {
			mutex_exit(&g->mlg_mtx);
			return (B_FALSE);
		}

		g->mlg_state |= MLXCX_GROUP_TIRTIS;
	}

	/*
	 * Flow table: our RX hashing breakout table for RSS
	 */

	g->mlg_rx_hash_ft = (ft = kmem_zalloc(sizeof (mlxcx_flow_table_t),
	    KM_SLEEP));
	mutex_init(&ft->mlft_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mlxp->mlx_intr_pri));
	avl_create(&g->mlg_rx_macs, mlxcx_grmac_compare,
	    sizeof (mlxcx_group_mac_t),
	    offsetof(mlxcx_group_mac_t, mlgm_group_entry));
	g->mlg_state |= MLXCX_GROUP_FLOWS;

	mutex_enter(&ft->mlft_mtx);

	ft->mlft_type = MLXCX_FLOW_TABLE_NIC_RX;
	ft->mlft_level = 2;
	ft->mlft_port = g->mlg_port;
	ft->mlft_entshift = MLXCX_RX_HASH_FT_SIZE_SHIFT;
	ft->mlft_nents = (1 << ft->mlft_entshift);
	ASSERT3U(ft->mlft_nents, >=, MLXCX_TIRS_PER_GROUP);
	ft->mlft_entsize = ft->mlft_nents * sizeof (mlxcx_flow_entry_t);
	ft->mlft_ent = kmem_zalloc(ft->mlft_entsize, KM_SLEEP);
	list_create(&ft->mlft_groups, sizeof (mlxcx_flow_group_t),
	    offsetof(mlxcx_flow_group_t, mlfg_entry));

	for (j = 0; j < ft->mlft_nents; ++j) {
		ft->mlft_ent[j].mlfe_table = ft;
		ft->mlft_ent[j].mlfe_index = j;
	}

	if (!mlxcx_cmd_create_flow_table(mlxp, ft)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = 1;
	fg->mlfg_mask |= MLXCX_FLOW_MATCH_IP_VER | MLXCX_FLOW_MATCH_IP_PROTO;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	fe = list_head(&fg->mlfg_entries);
	fe->mlfe_ip_version = 6;
	fe->mlfe_ip_proto = IPPROTO_UDP;
	fe->mlfe_action = MLXCX_FLOW_ACTION_FORWARD;
	fe->mlfe_dest[fe->mlfe_ndest++].mlfed_tir =
	    &g->mlg_tir[MLXCX_TIR_ROLE_UDPv6];
	if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = 1;
	fg->mlfg_mask |= MLXCX_FLOW_MATCH_IP_VER | MLXCX_FLOW_MATCH_IP_PROTO;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	fe = list_head(&fg->mlfg_entries);
	fe->mlfe_ip_version = 4;
	fe->mlfe_ip_proto = IPPROTO_UDP;
	fe->mlfe_action = MLXCX_FLOW_ACTION_FORWARD;
	fe->mlfe_dest[fe->mlfe_ndest++].mlfed_tir =
	    &g->mlg_tir[MLXCX_TIR_ROLE_UDPv4];
	if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = 1;
	fg->mlfg_mask |= MLXCX_FLOW_MATCH_IP_VER | MLXCX_FLOW_MATCH_IP_PROTO;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	fe = list_head(&fg->mlfg_entries);
	fe->mlfe_ip_version = 6;
	fe->mlfe_ip_proto = IPPROTO_TCP;
	fe->mlfe_action = MLXCX_FLOW_ACTION_FORWARD;
	fe->mlfe_dest[fe->mlfe_ndest++].mlfed_tir =
	    &g->mlg_tir[MLXCX_TIR_ROLE_TCPv6];
	if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = 1;
	fg->mlfg_mask |= MLXCX_FLOW_MATCH_IP_VER | MLXCX_FLOW_MATCH_IP_PROTO;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	fe = list_head(&fg->mlfg_entries);
	fe->mlfe_ip_version = 4;
	fe->mlfe_ip_proto = IPPROTO_TCP;
	fe->mlfe_action = MLXCX_FLOW_ACTION_FORWARD;
	fe->mlfe_dest[fe->mlfe_ndest++].mlfed_tir =
	    &g->mlg_tir[MLXCX_TIR_ROLE_TCPv4];
	if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = 1;
	fg->mlfg_mask |= MLXCX_FLOW_MATCH_IP_VER;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	fe = list_head(&fg->mlfg_entries);
	fe->mlfe_ip_version = 6;
	fe->mlfe_action = MLXCX_FLOW_ACTION_FORWARD;
	fe->mlfe_dest[fe->mlfe_ndest++].mlfed_tir =
	    &g->mlg_tir[MLXCX_TIR_ROLE_IPv6];
	if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = 1;
	fg->mlfg_mask |= MLXCX_FLOW_MATCH_IP_VER;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	fe = list_head(&fg->mlfg_entries);
	fe->mlfe_ip_version = 4;
	fe->mlfe_action = MLXCX_FLOW_ACTION_FORWARD;
	fe->mlfe_dest[fe->mlfe_ndest++].mlfed_tir =
	    &g->mlg_tir[MLXCX_TIR_ROLE_IPv4];
	if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = 1;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	fe = list_head(&fg->mlfg_entries);
	fe->mlfe_action = MLXCX_FLOW_ACTION_FORWARD;
	fe->mlfe_dest[fe->mlfe_ndest++].mlfed_tir =
	    &g->mlg_tir[MLXCX_TIR_ROLE_OTHER];
	if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	mutex_exit(&ft->mlft_mtx);

	/*
	 * Flow table: the VLAN breakout table for doing VLAN filtering after
	 * we've matched a MAC address.
	 */

	g->mlg_rx_vlan_ft = (ft = kmem_zalloc(sizeof (mlxcx_flow_table_t),
	    KM_SLEEP));
	mutex_init(&ft->mlft_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mlxp->mlx_intr_pri));
	list_create(&g->mlg_rx_vlans, sizeof (mlxcx_group_vlan_t),
	    offsetof(mlxcx_group_vlan_t, mlgv_entry));

	mutex_enter(&ft->mlft_mtx);

	ft->mlft_type = MLXCX_FLOW_TABLE_NIC_RX;
	ft->mlft_level = 1;
	ft->mlft_port = g->mlg_port;
	ft->mlft_entshift = mlxp->mlx_props.mldp_ftbl_vlan_size_shift;
	ft->mlft_nents = (1 << ft->mlft_entshift);
	ft->mlft_entsize = ft->mlft_nents * sizeof (mlxcx_flow_entry_t);
	ft->mlft_ent = kmem_zalloc(ft->mlft_entsize, KM_SLEEP);
	list_create(&ft->mlft_groups, sizeof (mlxcx_flow_group_t),
	    offsetof(mlxcx_flow_group_t, mlfg_entry));

	for (j = 0; j < ft->mlft_nents; ++j) {
		fe = &ft->mlft_ent[j];
		fe->mlfe_table = ft;
		fe->mlfe_index = j;
		fe->mlfe_action = MLXCX_FLOW_ACTION_FORWARD;
		fe->mlfe_dest[fe->mlfe_ndest++].mlfed_flow = g->mlg_rx_hash_ft;
	}

	if (!mlxcx_cmd_create_flow_table(mlxp, ft)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	/* First group is all actual matched VLANs */
	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	g->mlg_rx_vlan_fg = fg;
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = ft->mlft_nents - 2;
	fg->mlfg_mask |= MLXCX_FLOW_MATCH_VLAN;
	fg->mlfg_mask |= MLXCX_FLOW_MATCH_VID;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	/*
	 * Then the "default" entry which we enable when we have no VLAN IDs
	 * added to the group (we start with this enabled).
	 */
	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	g->mlg_rx_vlan_def_fg = fg;
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = 1;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	fe = list_head(&fg->mlfg_entries);
	if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	/*
	 * Finally, the promisc entry which points at the *hash ft* from the
	 * default group. We only enable this when we have promisc on.
	 */
	fg = kmem_zalloc(sizeof (mlxcx_flow_group_t), KM_SLEEP);
	g->mlg_rx_vlan_promisc_fg = fg;
	list_insert_tail(&ft->mlft_groups, fg);
	fg->mlfg_table = ft;
	fg->mlfg_size = 1;
	if (!mlxcx_setup_flow_group(mlxp, ft, fg)) {
		mutex_exit(&ft->mlft_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	fe = list_head(&fg->mlfg_entries);
	fe->mlfe_ndest = 1;
	fe->mlfe_dest[0].mlfed_flow = mlxp->mlx_rx_groups[0].mlg_rx_hash_ft;

	mutex_exit(&ft->mlft_mtx);

	mutex_exit(&g->mlg_mtx);

	return (B_TRUE);
}

boolean_t
mlxcx_rx_ring_start(mlxcx_t *mlxp, mlxcx_ring_group_t *g,
    mlxcx_work_queue_t *rq)
{
	uint_t j;
	mlxcx_buffer_t *b;
	mlxcx_completion_queue_t *cq;

	mutex_enter(&g->mlg_mtx);
	/*
	 * Sadly, even though MAC has the mgi_start callback, it is not always
	 * called -- in particular when we are being managed under an aggr, the
	 * mgi_start callback will only ever be called on the default group.
	 *
	 * So instead of asserting about the group state here, we have to
	 * check it and call group start if needed.
	 */
	if (!(g->mlg_state & MLXCX_GROUP_RUNNING)) {
		mutex_exit(&g->mlg_mtx);
		if (!mlxcx_rx_group_start(mlxp, g))
			return (B_FALSE);
		mutex_enter(&g->mlg_mtx);
	}
	ASSERT(g->mlg_state & MLXCX_GROUP_RUNNING);

	cq = rq->mlwq_cq;
	ASSERT(cq != NULL);

	mutex_enter(&cq->mlcq_mtx);
	mutex_enter(&rq->mlwq_mtx);

	if (rq->mlwq_state & MLXCX_WQ_STARTED) {
		mutex_exit(&rq->mlwq_mtx);
		mutex_exit(&cq->mlcq_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_TRUE);
	}

	if (!mlxcx_cmd_start_rq(mlxp, rq)) {
		mutex_exit(&rq->mlwq_mtx);
		mutex_exit(&cq->mlcq_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	ASSERT(rq->mlwq_state & MLXCX_WQ_STARTED);

	ASSERT0(rq->mlwq_state & MLXCX_WQ_BUFFERS);
	rq->mlwq_state |= MLXCX_WQ_BUFFERS;

	for (j = 0; j < rq->mlwq_nents; ++j) {
		if (!mlxcx_buf_create(mlxp, rq->mlwq_bufs, &b))
			break;
		mlxcx_buf_return(mlxp, b);
	}
	for (j = 0; j < rq->mlwq_nents / 2; ++j) {
		if (!mlxcx_buf_create(mlxp, rq->mlwq_bufs, &b))
			break;
		mlxcx_buf_return(mlxp, b);
	}

	mlxcx_rq_refill(mlxp, rq);

	mutex_exit(&rq->mlwq_mtx);
	mutex_exit(&cq->mlcq_mtx);
	mutex_exit(&g->mlg_mtx);

	return (B_TRUE);
}

boolean_t
mlxcx_rx_group_start(mlxcx_t *mlxp, mlxcx_ring_group_t *g)
{
	mlxcx_flow_table_t *ft;
	mlxcx_flow_group_t *fg;
	mlxcx_flow_entry_t *fe;

	mutex_enter(&g->mlg_mtx);

	if (g->mlg_state & MLXCX_GROUP_RUNNING) {
		mutex_exit(&g->mlg_mtx);
		return (B_TRUE);
	}

	ASSERT0(g->mlg_state & MLXCX_GROUP_RUNNING);

	g->mlg_state |= MLXCX_GROUP_RUNNING;

	if (g == &mlxp->mlx_rx_groups[0]) {
		ft = g->mlg_port->mlp_rx_flow;
		mutex_enter(&ft->mlft_mtx);

		/*
		 * Broadcast and promisc entries go directly to group 0's
		 * RSS hash fanout flow table. They bypass VLAN filtering.
		 */
		fg = g->mlg_port->mlp_bcast;
		fe = list_head(&fg->mlfg_entries);
		fe->mlfe_dest[fe->mlfe_ndest++].mlfed_flow = g->mlg_rx_hash_ft;
		if (!mlxcx_cmd_set_flow_table_entry(mlxp, fe)) {
			mutex_exit(&ft->mlft_mtx);
			mutex_exit(&g->mlg_mtx);
			return (B_FALSE);
		}

		fg = g->mlg_port->mlp_promisc;
		fe = list_head(&fg->mlfg_entries);
		fe->mlfe_dest[fe->mlfe_ndest++].mlfed_flow = g->mlg_rx_hash_ft;
		/*
		 * Don't actually set the promisc entry until promisc is
		 * enabled.
		 */

		mutex_exit(&ft->mlft_mtx);
	}

	mutex_exit(&g->mlg_mtx);

	return (B_TRUE);
}

boolean_t
mlxcx_tx_group_setup(mlxcx_t *mlxp, mlxcx_ring_group_t *g)
{
	mlxcx_event_queue_t *eq;
	mlxcx_completion_queue_t *cq;
	mlxcx_work_queue_t *sq;
	uint_t i;

	ASSERT3S(g->mlg_state, ==, 0);

	mutex_init(&g->mlg_mtx, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(mlxp->mlx_intr_pri));
	g->mlg_state |= MLXCX_GROUP_INIT;
	mutex_enter(&g->mlg_mtx);

	g->mlg_mlx = mlxp;
	g->mlg_type = MLXCX_GROUP_TX;
	g->mlg_port = &mlxp->mlx_ports[0];

	g->mlg_nwqs = mlxp->mlx_props.mldp_tx_nrings_per_group;
	g->mlg_wqs_size = g->mlg_nwqs * sizeof (mlxcx_work_queue_t);
	g->mlg_wqs = kmem_zalloc(g->mlg_wqs_size, KM_SLEEP);
	g->mlg_state |= MLXCX_GROUP_WQS;

	g->mlg_tis.mltis_tdom = &mlxp->mlx_tdom;

	if (!mlxcx_cmd_create_tis(mlxp, &g->mlg_tis)) {
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}

	g->mlg_state |= MLXCX_GROUP_TIRTIS;

	for (i = 0; i < g->mlg_nwqs; ++i) {
		eq = NULL;
		while (eq == NULL) {
			eq = &mlxp->mlx_eqs[mlxp->mlx_next_eq++];
			if (mlxp->mlx_next_eq >= mlxp->mlx_intr_count)
				mlxp->mlx_next_eq = 1;
			if (eq->mleq_type != MLXCX_EQ_TYPE_ANY &&
			    eq->mleq_type != MLXCX_EQ_TYPE_TX) {
				/* Try the next one */
				eq = NULL;
			}
		}

		if (!mlxcx_cq_setup(mlxp, eq, &cq))
			return (B_FALSE);
		cq->mlcq_stats = &g->mlg_port->mlp_stats;

		sq = &g->mlg_wqs[i];
		if (!mlxcx_sq_setup(mlxp, g->mlg_port, cq, &g->mlg_tis, sq)) {
			mutex_exit(&g->mlg_mtx);
			return (B_FALSE);
		}
		sq->mlwq_group = g;
	}

	mutex_exit(&g->mlg_mtx);

	return (B_TRUE);
}

boolean_t
mlxcx_tx_ring_start(mlxcx_t *mlxp, mlxcx_ring_group_t *g,
    mlxcx_work_queue_t *sq)
{
	uint_t i;
	mlxcx_buffer_t *b;
	mlxcx_completion_queue_t *cq;

	mutex_enter(&g->mlg_mtx);

	cq = sq->mlwq_cq;
	ASSERT(cq != NULL);

	mutex_enter(&cq->mlcq_mtx);
	mutex_enter(&sq->mlwq_mtx);
	if (sq->mlwq_state & MLXCX_WQ_STARTED) {
		mutex_exit(&sq->mlwq_mtx);
		mutex_exit(&cq->mlcq_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_TRUE);
	}

	ASSERT0(sq->mlwq_state & MLXCX_WQ_BUFFERS);
	for (i = 0; i < sq->mlwq_nents; ++i) {
		if (!mlxcx_buf_create_foreign(mlxp, sq->mlwq_foreign_bufs, &b))
			break;
		mlxcx_buf_return(mlxp, b);
	}
	for (i = 0; i < sq->mlwq_nents / 2; ++i) {
		if (!mlxcx_buf_create_foreign(mlxp, sq->mlwq_foreign_bufs, &b))
			break;
		mlxcx_buf_return(mlxp, b);
	}
	for (i = 0; i < sq->mlwq_nents; ++i) {
		if (!mlxcx_buf_create(mlxp, sq->mlwq_bufs, &b))
			break;
		mlxcx_buf_return(mlxp, b);
	}
	sq->mlwq_state |= MLXCX_WQ_BUFFERS;

	if (!mlxcx_cmd_start_sq(mlxp, sq)) {
		mutex_exit(&sq->mlwq_mtx);
		mutex_exit(&cq->mlcq_mtx);
		mutex_exit(&g->mlg_mtx);
		return (B_FALSE);
	}
	g->mlg_state |= MLXCX_GROUP_RUNNING;

	(void) mlxcx_sq_add_nop(mlxp, sq);

	mutex_exit(&sq->mlwq_mtx);
	mutex_exit(&cq->mlcq_mtx);
	mutex_exit(&g->mlg_mtx);

	return (B_TRUE);
}

static boolean_t
mlxcx_sq_ring_dbell(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq, uint_t first)
{
	uint_t idx;
	mlxcx_bf_t *bf;
	ddi_fm_error_t err;
	uint_t try = 0;

	ASSERT3U(mlwq->mlwq_type, ==, MLXCX_WQ_TYPE_SENDQ);
	ASSERT(mutex_owned(&mlwq->mlwq_mtx));

	mlwq->mlwq_doorbell->mlwqd_send_counter = to_be16(mlwq->mlwq_pc);

	ASSERT(mlwq->mlwq_cq != NULL);
	ASSERT(mlwq->mlwq_cq->mlcq_eq != NULL);
	idx = mlwq->mlwq_cq->mlcq_eq->mleq_intr_index & MLXCX_BF_PER_UAR_MASK;
	bf = &mlwq->mlwq_uar->mlu_bf[idx];

retry:
	MLXCX_DMA_SYNC(mlwq->mlwq_doorbell_dma, DDI_DMA_SYNC_FORDEV);
	ddi_fm_dma_err_get(mlwq->mlwq_doorbell_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK) {
		if (try++ < mlxcx_doorbell_tries) {
			ddi_fm_dma_err_clear(
			    mlwq->mlwq_doorbell_dma.mxdb_dma_handle,
			    DDI_FME_VERSION);
			goto retry;
		} else {
			goto err;
		}
	}

	mlxcx_put64(mlxp, bf->mbf_even, from_be64(
	    mlwq->mlwq_bf_ent[first].mlsqbf_qwords[0]));
	ddi_fm_acc_err_get(mlxp->mlx_regs_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status == DDI_FM_OK)
		return (B_TRUE);
	if (try++ < mlxcx_doorbell_tries) {
		ddi_fm_acc_err_clear(mlxp->mlx_regs_handle, DDI_FME_VERSION);
		goto retry;
	}

err:
	ddi_fm_service_impact(mlxp->mlx_dip, DDI_SERVICE_LOST);
	return (B_FALSE);
}

boolean_t
mlxcx_sq_add_nop(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	uint_t index, start_pc;
	mlxcx_sendq_ent_t *ent0;
	ddi_fm_error_t err;

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));

	index = mlwq->mlwq_pc & (mlwq->mlwq_nents - 1);
	ent0 = &mlwq->mlwq_send_ent[index];
	start_pc = mlwq->mlwq_pc;
	++mlwq->mlwq_pc;

	bzero(ent0, sizeof (mlxcx_sendq_ent_t));
	ent0->mlsqe_control.mlcs_opcode = MLXCX_WQE_OP_NOP;
	ent0->mlsqe_control.mlcs_qp_or_sq = to_be24(mlwq->mlwq_num);
	ent0->mlsqe_control.mlcs_wqe_index = to_be16(start_pc);

	set_bits8(&ent0->mlsqe_control.mlcs_flags,
	    MLXCX_SQE_FENCE_MODE, MLXCX_SQE_FENCE_NONE);
	set_bits8(&ent0->mlsqe_control.mlcs_flags,
	    MLXCX_SQE_COMPLETION_MODE, MLXCX_SQE_CQE_ALWAYS);

	ent0->mlsqe_control.mlcs_ds = 1;

	VERIFY0(ddi_dma_sync(mlwq->mlwq_dma.mxdb_dma_handle,
	    (uintptr_t)ent0 - (uintptr_t)mlwq->mlwq_send_ent,
	    sizeof (mlxcx_sendq_ent_t), DDI_DMA_SYNC_FORDEV));
	ddi_fm_dma_err_get(mlwq->mlwq_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK) {
		return (B_FALSE);
	}
	if (!mlxcx_sq_ring_dbell(mlxp, mlwq, index)) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

boolean_t
mlxcx_sq_add_buffer(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq,
    uint8_t *inlinehdrs, size_t inlinelen, uint32_t chkflags,
    mlxcx_buffer_t *b0)
{
	uint_t index, first, ents = 0;
	mlxcx_completion_queue_t *cq;
	mlxcx_sendq_ent_t *ent0;
	mlxcx_sendq_extra_ent_t *ent;
	mlxcx_wqe_data_seg_t *seg;
	uint_t ptri, nptr;
	const ddi_dma_cookie_t *c;
	size_t rem;
	mlxcx_buffer_t *b;
	ddi_fm_error_t err;

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	ASSERT3P(b0->mlb_tx_head, ==, b0);
	ASSERT3U(b0->mlb_state, ==, MLXCX_BUFFER_ON_WQ);
	cq = mlwq->mlwq_cq;

	index = mlwq->mlwq_pc & (mlwq->mlwq_nents - 1);
	ent0 = &mlwq->mlwq_send_ent[index];
	b0->mlb_wqe_index = mlwq->mlwq_pc;
	++mlwq->mlwq_pc;
	++ents;

	first = index;

	mutex_enter(&cq->mlcq_bufbmtx);
	list_insert_tail(&cq->mlcq_buffers_b, b0);
	atomic_inc_64(&cq->mlcq_bufcnt);
	mutex_exit(&cq->mlcq_bufbmtx);

	bzero(ent0, sizeof (mlxcx_sendq_ent_t));
	ent0->mlsqe_control.mlcs_opcode = MLXCX_WQE_OP_SEND;
	ent0->mlsqe_control.mlcs_qp_or_sq = to_be24(mlwq->mlwq_num);
	ent0->mlsqe_control.mlcs_wqe_index = to_be16(b0->mlb_wqe_index);

	set_bits8(&ent0->mlsqe_control.mlcs_flags,
	    MLXCX_SQE_FENCE_MODE, MLXCX_SQE_FENCE_WAIT_OTHERS);
	set_bits8(&ent0->mlsqe_control.mlcs_flags,
	    MLXCX_SQE_COMPLETION_MODE, MLXCX_SQE_CQE_ALWAYS);

	VERIFY3U(inlinelen, <=, sizeof (ent0->mlsqe_eth.mles_inline_headers));
	set_bits16(&ent0->mlsqe_eth.mles_szflags,
	    MLXCX_SQE_ETH_INLINE_HDR_SZ, inlinelen);
	if (inlinelen > 0) {
		bcopy(inlinehdrs, ent0->mlsqe_eth.mles_inline_headers,
		    inlinelen);
	}

	ent0->mlsqe_control.mlcs_ds =
	    offsetof(mlxcx_sendq_ent_t, mlsqe_data) / 16;

	if (chkflags & HCK_IPV4_HDRCKSUM) {
		ASSERT(mlxp->mlx_caps->mlc_checksum);
		set_bit8(&ent0->mlsqe_eth.mles_csflags,
		    MLXCX_SQE_ETH_CSFLAG_L3_CHECKSUM);
	}
	if (chkflags & HCK_FULLCKSUM) {
		ASSERT(mlxp->mlx_caps->mlc_checksum);
		set_bit8(&ent0->mlsqe_eth.mles_csflags,
		    MLXCX_SQE_ETH_CSFLAG_L4_CHECKSUM);
	}

	b = b0;
	ptri = 0;
	nptr = sizeof (ent0->mlsqe_data) / sizeof (mlxcx_wqe_data_seg_t);
	seg = ent0->mlsqe_data;
	while (b != NULL) {
		rem = b->mlb_used;

		c = NULL;
		while (rem > 0 &&
		    (c = mlxcx_dma_cookie_iter(&b->mlb_dma, c)) != NULL) {
			if (ptri >= nptr) {
				index = mlwq->mlwq_pc & (mlwq->mlwq_nents - 1);
				ent = &mlwq->mlwq_send_extra_ent[index];
				++mlwq->mlwq_pc;
				++ents;

				seg = ent->mlsqe_data;
				ptri = 0;
				nptr = sizeof (ent->mlsqe_data) /
				    sizeof (mlxcx_wqe_data_seg_t);
			}

			seg->mlds_lkey = to_be32(mlxp->mlx_rsvd_lkey);
			if (c->dmac_size > rem) {
				seg->mlds_byte_count = to_be32(rem);
				rem = 0;
			} else {
				seg->mlds_byte_count = to_be32(c->dmac_size);
				rem -= c->dmac_size;
			}
			seg->mlds_address = to_be64(c->dmac_laddress);
			++seg;
			++ptri;
			++ent0->mlsqe_control.mlcs_ds;

			ASSERT3U(ent0->mlsqe_control.mlcs_ds, <=,
			    MLXCX_SQE_MAX_DS);
		}

		if (b == b0) {
			b = list_head(&b0->mlb_tx_chain);
		} else {
			b = list_next(&b0->mlb_tx_chain, b);
		}
	}

	for (; ptri < nptr; ++ptri, ++seg) {
		seg->mlds_lkey = to_be32(MLXCX_NULL_LKEY);
		seg->mlds_byte_count = to_be32(0);
		seg->mlds_address = to_be64(0);
	}

	/*
	 * Make sure the workqueue entry is flushed out before updating
	 * the doorbell.
	 */
	VERIFY0(ddi_dma_sync(mlwq->mlwq_dma.mxdb_dma_handle,
	    (uintptr_t)ent0 - (uintptr_t)mlwq->mlwq_send_ent,
	    ents * sizeof (mlxcx_sendq_ent_t), DDI_DMA_SYNC_FORDEV));
	ddi_fm_dma_err_get(mlwq->mlwq_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK) {
		return (B_FALSE);
	}
	if (!mlxcx_sq_ring_dbell(mlxp, mlwq, first)) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

boolean_t
mlxcx_rq_add_buffer(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq,
    mlxcx_buffer_t *buf)
{
	return (mlxcx_rq_add_buffers(mlxp, mlwq, &buf, 1));
}

boolean_t
mlxcx_rq_add_buffers(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq,
    mlxcx_buffer_t **bufs, size_t nbufs)
{
	uint_t index;
	mlxcx_recvq_ent_t *ent;
	mlxcx_completion_queue_t *cq;
	mlxcx_wqe_data_seg_t *seg;
	uint_t bi, ptri;
	const ddi_dma_cookie_t *c;
	mlxcx_buffer_t *buf;
	ddi_fm_error_t err;

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	cq = mlwq->mlwq_cq;
	ASSERT(mutex_owned(&cq->mlcq_mtx));

	for (bi = 0; bi < nbufs; ++bi) {
		buf = bufs[bi];
		bufs[bi] = NULL;
		ASSERT3U(buf->mlb_state, ==, MLXCX_BUFFER_ON_WQ);

		index = mlwq->mlwq_pc & (mlwq->mlwq_nents - 1);
		ent = &mlwq->mlwq_recv_ent[index];
		buf->mlb_wqe_index = mlwq->mlwq_pc;

		++mlwq->mlwq_pc;

		mutex_enter(&cq->mlcq_bufbmtx);
		list_insert_tail(&cq->mlcq_buffers, buf);
		atomic_inc_64(&cq->mlcq_bufcnt);
		mutex_exit(&cq->mlcq_bufbmtx);

		ASSERT3U(buf->mlb_dma.mxdb_ncookies, <=, MLXCX_RECVQ_MAX_PTRS);
		ptri = 0;
		c = NULL;
		while ((c = mlxcx_dma_cookie_iter(&buf->mlb_dma, c)) != NULL) {
			seg = &ent->mlrqe_data[ptri++];
			seg->mlds_lkey = to_be32(mlxp->mlx_rsvd_lkey);
			seg->mlds_byte_count = to_be32(c->dmac_size);
			seg->mlds_address = to_be64(c->dmac_laddress);
		}
		/*
		 * Fill any unused scatter pointers with the special null
		 * value.
		 */
		for (; ptri < MLXCX_RECVQ_MAX_PTRS; ++ptri) {
			seg = &ent->mlrqe_data[ptri];
			seg->mlds_lkey = to_be32(MLXCX_NULL_LKEY);
			seg->mlds_byte_count = to_be32(0);
			seg->mlds_address = to_be64(0);
		}

		/*
		 * Make sure the workqueue entry is flushed out before updating
		 * the doorbell.
		 */
		VERIFY0(ddi_dma_sync(mlwq->mlwq_dma.mxdb_dma_handle,
		    (uintptr_t)ent - (uintptr_t)mlwq->mlwq_recv_ent,
		    sizeof (mlxcx_recvq_ent_t), DDI_DMA_SYNC_FORDEV));
		ddi_fm_dma_err_get(mlwq->mlwq_dma.mxdb_dma_handle, &err,
		    DDI_FME_VERSION);
		if (err.fme_status != DDI_FM_OK) {
			return (B_FALSE);
		}
	}

	mlwq->mlwq_doorbell->mlwqd_recv_counter = to_be16(mlwq->mlwq_pc);
	/*
	 * Flush the CQ doorbell as well so that HW knows how many
	 * completions we've consumed.
	 */
	MLXCX_DMA_SYNC(cq->mlcq_doorbell_dma, DDI_DMA_SYNC_FORDEV);
	ddi_fm_dma_err_get(cq->mlcq_doorbell_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK) {
		return (B_FALSE);
	}
	MLXCX_DMA_SYNC(mlwq->mlwq_doorbell_dma, DDI_DMA_SYNC_FORDEV);
	ddi_fm_dma_err_get(mlwq->mlwq_doorbell_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

void
mlxcx_rq_refill(mlxcx_t *mlxp, mlxcx_work_queue_t *mlwq)
{
	size_t target, current, want, done, n;
	mlxcx_completion_queue_t *cq;
	mlxcx_buffer_t *b[MLXCX_RQ_REFILL_STEP];
	uint_t i;

	ASSERT(mutex_owned(&mlwq->mlwq_mtx));
	cq = mlwq->mlwq_cq;
	ASSERT(mutex_owned(&cq->mlcq_mtx));

	ASSERT(mlwq->mlwq_state & MLXCX_WQ_BUFFERS);

	target = mlwq->mlwq_nents - MLXCX_RQ_REFILL_STEP;
	cq = mlwq->mlwq_cq;

	if (cq->mlcq_state & MLXCX_CQ_TEARDOWN)
		return;

	current = cq->mlcq_bufcnt;

	if (current >= target - MLXCX_RQ_REFILL_STEP)
		return;

	want = target - current;
	done = 0;

	while (!(mlwq->mlwq_state & MLXCX_WQ_TEARDOWN) && done < want) {
		n = mlxcx_buf_take_n(mlxp, mlwq, b, MLXCX_RQ_REFILL_STEP);
		if (n == 0) {
			mlxcx_warn(mlxp, "!exiting rq refill early, done %u "
			    "but wanted %u", done, want);
			return;
		}
		if (mlwq->mlwq_state & MLXCX_WQ_TEARDOWN) {
			for (i = 0; i < n; ++i)
				mlxcx_buf_return(mlxp, b[i]);
			return;
		}
		if (!mlxcx_rq_add_buffers(mlxp, mlwq, b, n)) {
			/*
			 * mlxcx_rq_add_buffers NULLs out the buffers as it
			 * enqueues them, so any that are non-NULL we have to
			 * free now. The others now belong to the WQ, even if
			 * we failed.
			 */
			for (i = 0; i < n; ++i) {
				if (b[i] != NULL) {
					mlxcx_buf_return(mlxp, b[i]);
				}
			}
			return;
		}
		done += n;
	}
}

static const char *
mlxcx_cq_err_syndrome_string(mlxcx_cq_error_syndrome_t sy)
{
	switch (sy) {
	case MLXCX_CQ_ERR_LOCAL_LENGTH:
		return ("LOCAL_LENGTH");
	case MLXCX_CQ_ERR_LOCAL_QP_OP:
		return ("LOCAL_QP_OP");
	case MLXCX_CQ_ERR_LOCAL_PROTECTION:
		return ("LOCAL_PROTECTION");
	case MLXCX_CQ_ERR_WR_FLUSHED:
		return ("WR_FLUSHED");
	case MLXCX_CQ_ERR_MEM_WINDOW_BIND:
		return ("MEM_WINDOW_BIND");
	case MLXCX_CQ_ERR_BAD_RESPONSE:
		return ("BAD_RESPONSE");
	case MLXCX_CQ_ERR_LOCAL_ACCESS:
		return ("LOCAL_ACCESS");
	case MLXCX_CQ_ERR_XPORT_RETRY_CTR:
		return ("XPORT_RETRY_CTR");
	case MLXCX_CQ_ERR_RNR_RETRY_CTR:
		return ("RNR_RETRY_CTR");
	case MLXCX_CQ_ERR_ABORTED:
		return ("ABORTED");
	default:
		return ("UNKNOWN");
	}
}

static void
mlxcx_fm_cqe_ereport(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq,
    mlxcx_completionq_error_ent_t *ent)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];
	const char *name = mlxcx_cq_err_syndrome_string(ent->mlcqee_syndrome);

	if (!DDI_FM_EREPORT_CAP(mlxp->mlx_fm_caps))
		return;

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
	    MLXCX_FM_SERVICE_MLXCX, "cqe.err");
	ena = fm_ena_generate(0, FM_ENA_FMT1);

	ddi_fm_ereport_post(mlxp->mlx_dip, buf, ena, DDI_NOSLEEP,
	    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
	    "syndrome", DATA_TYPE_STRING, name,
	    "syndrome_num", DATA_TYPE_UINT8, ent->mlcqee_syndrome,
	    "vendor_syndrome", DATA_TYPE_UINT8,
	    ent->mlcqee_vendor_error_syndrome,
	    "wqe_counter", DATA_TYPE_UINT16, from_be16(ent->mlcqee_wqe_counter),
	    "wq_type", DATA_TYPE_STRING,
	    (mlcq->mlcq_wq->mlwq_type == MLXCX_WQ_TYPE_SENDQ) ? "send": "recv",
	    "cq_num", DATA_TYPE_UINT32, mlcq->mlcq_num,
	    "wq_num", DATA_TYPE_UINT32, mlcq->mlcq_wq->mlwq_num,
	    NULL);
	ddi_fm_service_impact(mlxp->mlx_dip, DDI_SERVICE_DEGRADED);
}

void
mlxcx_tx_completion(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq,
    mlxcx_completionq_ent_t *ent, mlxcx_buffer_t *buf)
{
	ASSERT(mutex_owned(&mlcq->mlcq_mtx));
	if (ent->mlcqe_opcode == MLXCX_CQE_OP_REQ_ERR) {
		mlxcx_completionq_error_ent_t *eent =
		    (mlxcx_completionq_error_ent_t *)ent;
		mlxcx_fm_cqe_ereport(mlxp, mlcq, eent);
		mlxcx_buf_return_chain(mlxp, buf, B_FALSE);
		mutex_enter(&mlcq->mlcq_wq->mlwq_mtx);
		mlxcx_check_sq(mlxp, mlcq->mlcq_wq);
		mutex_exit(&mlcq->mlcq_wq->mlwq_mtx);
		return;
	}

	if (ent->mlcqe_opcode != MLXCX_CQE_OP_REQ) {
		mlxcx_warn(mlxp, "!got weird cq opcode: %x", ent->mlcqe_opcode);
		mlxcx_buf_return_chain(mlxp, buf, B_FALSE);
		return;
	}

	if (ent->mlcqe_send_wqe_opcode != MLXCX_WQE_OP_SEND) {
		mlxcx_warn(mlxp, "!got weird cq wqe opcode: %x",
		    ent->mlcqe_send_wqe_opcode);
		mlxcx_buf_return_chain(mlxp, buf, B_FALSE);
		return;
	}

	if (ent->mlcqe_format != MLXCX_CQE_FORMAT_BASIC) {
		mlxcx_warn(mlxp, "!got weird cq format: %x", ent->mlcqe_format);
		mlxcx_buf_return_chain(mlxp, buf, B_FALSE);
		return;
	}

	mlxcx_buf_return_chain(mlxp, buf, B_FALSE);
}

mblk_t *
mlxcx_rx_completion(mlxcx_t *mlxp, mlxcx_completion_queue_t *mlcq,
    mlxcx_completionq_ent_t *ent, mlxcx_buffer_t *buf)
{
	uint32_t chkflags = 0;
	ddi_fm_error_t err;

	ASSERT(mutex_owned(&mlcq->mlcq_mtx));

	if (ent->mlcqe_opcode == MLXCX_CQE_OP_RESP_ERR) {
		mlxcx_completionq_error_ent_t *eent =
		    (mlxcx_completionq_error_ent_t *)ent;
		mlxcx_fm_cqe_ereport(mlxp, mlcq, eent);
		mlxcx_buf_return(mlxp, buf);
		mutex_enter(&mlcq->mlcq_wq->mlwq_mtx);
		mlxcx_check_rq(mlxp, mlcq->mlcq_wq);
		mutex_exit(&mlcq->mlcq_wq->mlwq_mtx);
		return (NULL);
	}

	if (ent->mlcqe_opcode != MLXCX_CQE_OP_RESP) {
		mlxcx_warn(mlxp, "!got weird cq opcode: %x", ent->mlcqe_opcode);
		mlxcx_buf_return(mlxp, buf);
		return (NULL);
	}

	if (ent->mlcqe_format != MLXCX_CQE_FORMAT_BASIC) {
		mlxcx_warn(mlxp, "!got weird cq format: %x", ent->mlcqe_format);
		mlxcx_buf_return(mlxp, buf);
		return (NULL);
	}

	if (ent->mlcqe_rx_drop_counter > 0) {
		atomic_add_64(&mlcq->mlcq_stats->mlps_rx_drops,
		    ent->mlcqe_rx_drop_counter);
	}

	MLXCX_DMA_SYNC(buf->mlb_dma, DDI_DMA_SYNC_FORCPU);
	ddi_fm_dma_err_get(buf->mlb_dma.mxdb_dma_handle, &err,
	    DDI_FME_VERSION);
	if (err.fme_status != DDI_FM_OK) {
		ddi_fm_dma_err_clear(buf->mlb_dma.mxdb_dma_handle,
		    DDI_FME_VERSION);
		mlxcx_buf_return(mlxp, buf);
		return (NULL);
	}

	if (!mlxcx_buf_loan(mlxp, buf)) {
		mlxcx_warn(mlxp, "!loan failed, dropping packet");
		mlxcx_buf_return(mlxp, buf);
		return (NULL);
	}

	buf->mlb_mp->b_next = NULL;
	buf->mlb_mp->b_cont = NULL;
	buf->mlb_mp->b_wptr = buf->mlb_mp->b_rptr +
	    from_be32(ent->mlcqe_byte_cnt);

	if (get_bit8(ent->mlcqe_csflags, MLXCX_CQE_CSFLAGS_L4_OK)) {
		chkflags |= HCK_FULLCKSUM_OK;
	}
	if (get_bit8(ent->mlcqe_csflags, MLXCX_CQE_CSFLAGS_L3_OK)) {
		chkflags |= HCK_IPV4_HDRCKSUM_OK;
	}
	if (chkflags != 0) {
		mac_hcksum_set(buf->mlb_mp, 0, 0, 0,
		    from_be16(ent->mlcqe_checksum), chkflags);
	}

	/*
	 * Don't check if a refill is needed on every single completion,
	 * since checking involves taking the RQ lock.
	 */
	if ((buf->mlb_wqe_index & 0x7) == 0) {
		mlxcx_work_queue_t *wq = mlcq->mlcq_wq;
		ASSERT(wq != NULL);
		mutex_enter(&wq->mlwq_mtx);
		if (!(wq->mlwq_state & MLXCX_WQ_TEARDOWN))
			mlxcx_rq_refill(mlxp, wq);
		mutex_exit(&wq->mlwq_mtx);
	}

	return (buf->mlb_mp);
}

static void
mlxcx_buf_mp_return(caddr_t arg)
{
	mlxcx_buffer_t *b = (mlxcx_buffer_t *)arg;
	mlxcx_t *mlxp = b->mlb_mlx;

	if (b->mlb_state != MLXCX_BUFFER_ON_LOAN) {
		b->mlb_mp = NULL;
		return;
	}
	/*
	 * The mblk for this buffer_t (in its mlb_mp field) has been used now,
	 * so NULL it out.
	 */
	b->mlb_mp = NULL;
	mlxcx_buf_return(mlxp, b);
}

boolean_t
mlxcx_buf_create(mlxcx_t *mlxp, mlxcx_buf_shard_t *shard, mlxcx_buffer_t **bp)
{
	mlxcx_buffer_t *b;
	ddi_device_acc_attr_t acc;
	ddi_dma_attr_t attr;
	boolean_t ret;

	b = kmem_cache_alloc(mlxp->mlx_bufs_cache, KM_SLEEP);
	b->mlb_shard = shard;
	b->mlb_foreign = B_FALSE;

	mlxcx_dma_acc_attr(mlxp, &acc);
	mlxcx_dma_buf_attr(mlxp, &attr);

	ret = mlxcx_dma_alloc_offset(mlxp, &b->mlb_dma, &attr, &acc,
	    B_FALSE, mlxp->mlx_ports[0].mlp_mtu, 2, B_TRUE);
	if (!ret) {
		kmem_cache_free(mlxp->mlx_bufs_cache, b);
		return (B_FALSE);
	}

	b->mlb_frtn.free_func = mlxcx_buf_mp_return;
	b->mlb_frtn.free_arg = (caddr_t)b;
	b->mlb_mp = desballoc((unsigned char *)b->mlb_dma.mxdb_va,
	    b->mlb_dma.mxdb_len, 0, &b->mlb_frtn);

	*bp = b;

	return (B_TRUE);
}

boolean_t
mlxcx_buf_create_foreign(mlxcx_t *mlxp, mlxcx_buf_shard_t *shard,
    mlxcx_buffer_t **bp)
{
	mlxcx_buffer_t *b;
	ddi_dma_attr_t attr;
	boolean_t ret;

	b = kmem_cache_alloc(mlxp->mlx_bufs_cache, KM_SLEEP);
	b->mlb_shard = shard;
	b->mlb_foreign = B_TRUE;

	mlxcx_dma_buf_attr(mlxp, &attr);

	ret = mlxcx_dma_init(mlxp, &b->mlb_dma, &attr, B_TRUE);
	if (!ret) {
		kmem_cache_free(mlxp->mlx_bufs_cache, b);
		return (B_FALSE);
	}

	*bp = b;

	return (B_TRUE);
}

static void
mlxcx_buf_take_foreign(mlxcx_t *mlxp, mlxcx_work_queue_t *wq,
    mlxcx_buffer_t **bp)
{
	mlxcx_buffer_t *b;
	mlxcx_buf_shard_t *s = wq->mlwq_foreign_bufs;

	mutex_enter(&s->mlbs_mtx);
	while (list_is_empty(&s->mlbs_free))
		cv_wait(&s->mlbs_free_nonempty, &s->mlbs_mtx);
	b = list_remove_head(&s->mlbs_free);
	ASSERT3U(b->mlb_state, ==, MLXCX_BUFFER_FREE);
	ASSERT(b->mlb_foreign);
	b->mlb_state = MLXCX_BUFFER_ON_WQ;
	list_insert_tail(&s->mlbs_busy, b);
	mutex_exit(&s->mlbs_mtx);

	*bp = b;
}

boolean_t
mlxcx_buf_bind_or_copy(mlxcx_t *mlxp, mlxcx_work_queue_t *wq,
    mblk_t *mpb, size_t off, mlxcx_buffer_t **bp)
{
	mlxcx_buffer_t *b, *b0 = NULL;
	boolean_t first = B_TRUE;
	ddi_fm_error_t err;
	mblk_t *mp;
	uint8_t *rptr;
	size_t sz;
	size_t ncookies = 0;
	boolean_t ret;
	uint_t attempts = 0;

	for (mp = mpb; mp != NULL; mp = mp->b_cont) {
		rptr = mp->b_rptr;
		sz = MBLKL(mp);

		if (off > 0)
			ASSERT3U(off, <, sz);
		rptr += off;
		sz -= off;

		if (sz < mlxp->mlx_props.mldp_tx_bind_threshold)
			goto copyb;

		mlxcx_buf_take_foreign(mlxp, wq, &b);
		ret = mlxcx_dma_bind_mblk(mlxp, &b->mlb_dma, mp, off, B_FALSE);

		if (!ret) {
			mlxcx_buf_return(mlxp, b);

copyb:
			mlxcx_buf_take(mlxp, wq, &b);
			ASSERT3U(b->mlb_dma.mxdb_len, >=, sz);
			bcopy(rptr, b->mlb_dma.mxdb_va, sz);
			MLXCX_DMA_SYNC(b->mlb_dma, DDI_DMA_SYNC_FORDEV);
			ddi_fm_dma_err_get(b->mlb_dma.mxdb_dma_handle, &err,
			    DDI_FME_VERSION);
			if (err.fme_status != DDI_FM_OK) {
				ddi_fm_dma_err_clear(b->mlb_dma.mxdb_dma_handle,
				    DDI_FME_VERSION);
				mlxcx_buf_return(mlxp, b);
				if (++attempts > MLXCX_BUF_BIND_MAX_ATTEMTPS) {
					*bp = NULL;
					return (B_FALSE);
				}
				goto copyb;
			}
		}

		/*
		 * We might overestimate here when we've copied data, since
		 * the buffer might be longer than what we copied into it. This
		 * is safe since it's always wrong in the conservative
		 * direction (and we will blow up later when we actually
		 * generate the WQE anyway).
		 *
		 * If the assert below ever blows, we'll have to come and fix
		 * this up so we can transmit these packets.
		 */
		ncookies += b->mlb_dma.mxdb_ncookies;

		if (first)
			b0 = b;

		if (!first)
			b->mlb_state = MLXCX_BUFFER_ON_CHAIN;

		b->mlb_tx_mp = mp;
		b->mlb_tx_head = b0;
		b->mlb_used = sz;

		if (!first)
			list_insert_tail(&b0->mlb_tx_chain, b);
		first = B_FALSE;
		off = 0;
	}

	ASSERT3U(ncookies, <=, MLXCX_SQE_MAX_PTRS);

	*bp = b0;
	return (B_TRUE);
}

void
mlxcx_buf_take(mlxcx_t *mlxp, mlxcx_work_queue_t *wq, mlxcx_buffer_t **bp)
{
	mlxcx_buffer_t *b;
	mlxcx_buf_shard_t *s = wq->mlwq_bufs;

	mutex_enter(&s->mlbs_mtx);
	while (list_is_empty(&s->mlbs_free))
		cv_wait(&s->mlbs_free_nonempty, &s->mlbs_mtx);
	b = list_remove_head(&s->mlbs_free);
	ASSERT3U(b->mlb_state, ==, MLXCX_BUFFER_FREE);
	b->mlb_state = MLXCX_BUFFER_ON_WQ;
	list_insert_tail(&s->mlbs_busy, b);
	mutex_exit(&s->mlbs_mtx);

	*bp = b;
}

#define	MLXCX_BUF_TAKE_N_TIMEOUT_USEC		5000
#define	MLXCX_BUF_TAKE_N_MAX_RETRIES		3

size_t
mlxcx_buf_take_n(mlxcx_t *mlxp, mlxcx_work_queue_t *wq,
    mlxcx_buffer_t **bp, size_t nbufs)
{
	mlxcx_buffer_t *b;
	size_t done = 0, empty = 0;
	clock_t wtime = drv_usectohz(MLXCX_BUF_TAKE_N_TIMEOUT_USEC);
	mlxcx_buf_shard_t *s;

	s = wq->mlwq_bufs;

	mutex_enter(&s->mlbs_mtx);
	while (done < nbufs) {
		while (list_is_empty(&s->mlbs_free)) {
			(void) cv_reltimedwait(&s->mlbs_free_nonempty,
			    &s->mlbs_mtx, wtime, TR_MILLISEC);
			if (list_is_empty(&s->mlbs_free) &&
			    empty++ >= MLXCX_BUF_TAKE_N_MAX_RETRIES) {
				mutex_exit(&s->mlbs_mtx);
				return (done);
			}
		}
		b = list_remove_head(&s->mlbs_free);
		ASSERT3U(b->mlb_state, ==, MLXCX_BUFFER_FREE);
		b->mlb_state = MLXCX_BUFFER_ON_WQ;
		list_insert_tail(&s->mlbs_busy, b);
		bp[done++] = b;
	}
	mutex_exit(&s->mlbs_mtx);
	return (done);
}

boolean_t
mlxcx_buf_loan(mlxcx_t *mlxp, mlxcx_buffer_t *b)
{
	VERIFY3U(b->mlb_state, ==, MLXCX_BUFFER_ON_WQ);
	ASSERT3P(b->mlb_mlx, ==, mlxp);

	if (b->mlb_mp == NULL) {
		b->mlb_mp = desballoc((unsigned char *)b->mlb_dma.mxdb_va,
		    b->mlb_dma.mxdb_len, 0, &b->mlb_frtn);
		if (b->mlb_mp == NULL)
			return (B_FALSE);
	}

	b->mlb_state = MLXCX_BUFFER_ON_LOAN;
	b->mlb_wqe_index = 0;
	return (B_TRUE);
}

void
mlxcx_buf_return_chain(mlxcx_t *mlxp, mlxcx_buffer_t *b0, boolean_t keepmp)
{
	mlxcx_buffer_t *b;

	if (b0->mlb_tx_head != b0) {
		mlxcx_buf_return(mlxp, b0);
		return;
	}

	while ((b = list_head(&b0->mlb_tx_chain)) != NULL) {
		mlxcx_buf_return(mlxp, b);
	}
	if (keepmp) {
		b0->mlb_tx_mp = NULL;
		b0->mlb_tx_head = NULL;
	}
	mlxcx_buf_return(mlxp, b0);
}

void
mlxcx_buf_return(mlxcx_t *mlxp, mlxcx_buffer_t *b)
{
	mlxcx_buffer_state_t oldstate = b->mlb_state;
	mlxcx_buffer_t *txhead = b->mlb_tx_head;
	mlxcx_buf_shard_t *s = b->mlb_shard;
	mblk_t *mp = b->mlb_tx_mp;

	VERIFY3U(oldstate, !=, MLXCX_BUFFER_FREE);
	ASSERT3P(b->mlb_mlx, ==, mlxp);
	b->mlb_state = MLXCX_BUFFER_FREE;
	b->mlb_wqe_index = 0;
	b->mlb_tx_head = NULL;
	b->mlb_tx_mp = NULL;
	b->mlb_used = 0;
	ASSERT(list_is_empty(&b->mlb_tx_chain));

	mutex_enter(&s->mlbs_mtx);
	switch (oldstate) {
	case MLXCX_BUFFER_INIT:
		break;
	case MLXCX_BUFFER_ON_WQ:
		list_remove(&s->mlbs_busy, b);
		break;
	case MLXCX_BUFFER_ON_LOAN:
		ASSERT(!b->mlb_foreign);
		list_remove(&s->mlbs_busy, b);
		break;
	case MLXCX_BUFFER_FREE:
		VERIFY(0);
		break;
	case MLXCX_BUFFER_ON_CHAIN:
		ASSERT(txhead != NULL);
		list_remove(&txhead->mlb_tx_chain, b);
		list_remove(&s->mlbs_busy, b);
		break;
	}

	if (b->mlb_foreign) {
		if (b->mlb_dma.mxdb_flags & MLXCX_DMABUF_BOUND) {
			mlxcx_dma_unbind(mlxp, &b->mlb_dma);
		}
	}

	list_insert_tail(&s->mlbs_free, b);
	cv_signal(&s->mlbs_free_nonempty);

	mutex_exit(&s->mlbs_mtx);

	/*
	 * For TX chain heads, free the mblk_t after we let go of the lock.
	 * This might be a borrowed buf that we in turn loaned to MAC, in which
	 * case calling freemsg() on it will re-enter this very function -- so
	 * we better not be holding the lock!
	 */
	if (txhead == b)
		freemsg(mp);
}

void
mlxcx_buf_destroy(mlxcx_t *mlxp, mlxcx_buffer_t *b)
{
	mlxcx_buf_shard_t *s = b->mlb_shard;
	VERIFY(b->mlb_state == MLXCX_BUFFER_FREE ||
	    b->mlb_state == MLXCX_BUFFER_INIT);
	ASSERT(mutex_owned(&s->mlbs_mtx));
	if (b->mlb_state == MLXCX_BUFFER_FREE)
		list_remove(&s->mlbs_free, b);

	/*
	 * This is going back to the kmem cache, so it needs to be set up in
	 * the same way we expect a new buffer to come out (state INIT, other
	 * fields NULL'd)
	 */
	b->mlb_state = MLXCX_BUFFER_INIT;
	b->mlb_shard = NULL;
	if (b->mlb_mp != NULL) {
		freeb(b->mlb_mp);
		ASSERT(b->mlb_mp == NULL);
	}
	mlxcx_dma_free(&b->mlb_dma);
	ASSERT(list_is_empty(&b->mlb_tx_chain));

	kmem_cache_free(mlxp->mlx_bufs_cache, b);
}
