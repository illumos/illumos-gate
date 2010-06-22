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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <sys/ib/clients/rdsv3/ib.h>
#include <sys/ib/clients/rdsv3/rdsv3_af_thr_impl.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

extern pri_t maxclsyspri;
extern kmutex_t cpu_lock;

int rdsv3_enable_snd_cq = 0;
int rdsv3_intr_line_up_mode = 0;
static kmutex_t rdsv3_cpuid_pool_lock;

void
rdsv3_af_init(dev_info_t *dip)
{
	int i;
	cpu_t *cp;
	int *msix;
	uint_t nmsix;
	extern int ncpus;

	mutex_init(&rdsv3_cpuid_pool_lock, NULL, MUTEX_DEFAULT, NULL);
	if (ncpus < RDSV3_CPUID_POOL_MAX)
		rdsv3_cpuid_pool_cnt = ncpus;
	else
		rdsv3_cpuid_pool_cnt = RDSV3_CPUID_POOL_MAX;

	/* hold cpu_lock before calling cpu_get and cpu_is_online */
	mutex_enter(&cpu_lock);
	for (i = 0; i < rdsv3_cpuid_pool_cnt; i++) {
		cp = cpu_get((processorid_t)i);
		if (cp == NULL || !cpu_is_online(cp))
			rdsv3_cpuid_pool[i] = RDSV3_CPUFLAGS_OFF;
		else
			rdsv3_cpuid_pool[i] = RDSV3_CPUFLAGS_ON;
	}
	mutex_exit(&cpu_lock);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "HcaMsix", (int **)&msix, &nmsix) == DDI_PROP_SUCCESS) {
		/* remove the hca MSI-x interrupt cpu's */
		for (i = 0; i < nmsix; i++) {
			rdsv3_cpuid_pool[msix[i]] |= RDSV3_CPUFLAGS_INTR;
			rdsv3_msix_pool[i] = msix[i];
		}
		rdsv3_msix_pool_cnt = nmsix;
		ddi_prop_free(msix);
	}
	rdsv3_enable_snd_cq = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "EnableSendCQ", 0);
	rdsv3_intr_line_up_mode = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "IntrLineUpMode", 0);
}

static void
rdsv3_af_cpu_assign(rdsv3_af_grp_t *hcagp)
{
	int i, j, k, idx;

	RDSV3_DPRINTF2("rdsv3_af_cpu_assign", "hcagp %p", hcagp);

	mutex_enter(&rdsv3_cpuid_pool_lock);
	for (i = 0; i < rdsv3_cpuid_pool_cnt; i++) {
		if (!(rdsv3_cpuid_pool[i] & (RDSV3_CPUFLAGS_UNAVAIL |
		    RDSV3_CPUFLAGS_ASSIGNED | RDSV3_CPUFLAGS_HCA))) {
			rdsv3_cpuid_pool[i] |= RDSV3_CPUFLAGS_HCA;
			hcagp->g_hca_cpuid = i;
			break;
		}
		/* share an assigned cpu */
		for (j = 0; j < rdsv3_cpuid_pool_cnt; j++) {
			if (!(rdsv3_cpuid_pool[j] & (RDSV3_CPUFLAGS_UNAVAIL |
			    RDSV3_CPUFLAGS_HCA))) {
				hcagp->g_hca_cpuid = j;
				break;
			}
		}
		/* if the code comes down here, cpu 0 will be used */
	}

	for (j = 0; j < RDSV3_AFT_CONN_CPU_POOL; j++) {
		/* initialize to be an out-of-bound cpuid, no binding */
		hcagp->g_conn_cpuid_pool[j] = rdsv3_cpuid_pool_cnt;
		for (i = 0; i < rdsv3_cpuid_pool_cnt; i++) {
			if (!(rdsv3_cpuid_pool[i] & (RDSV3_CPUFLAGS_UNAVAIL |
			    RDSV3_CPUFLAGS_ASSIGNED | RDSV3_CPUFLAGS_HCA))) {
				rdsv3_cpuid_pool[i] |= RDSV3_CPUFLAGS_ASSIGNED;
				hcagp->g_conn_cpuid_pool[j] = i;
				break;
			}
		}
		if (i >= rdsv3_cpuid_pool_cnt)
			break;
	}
	if (j >= RDSV3_AFT_CONN_CPU_POOL) {
		mutex_exit(&rdsv3_cpuid_pool_lock);
		return;
	}
	/* avoid the primary group */
	for (k = 0, idx = 0; k < 2; k++) {
		/* search to the start of an hca group */
		for (i = idx; i < rdsv3_cpuid_pool_cnt; i++) {
			if (rdsv3_cpuid_pool[i] & RDSV3_CPUFLAGS_HCA) {
				idx = i + 1;
				break;
			}
		}
	}
	/* share an assigned cpu */
	for (; j < RDSV3_AFT_CONN_CPU_POOL; j++) {
		for (i = idx; i < rdsv3_cpuid_pool_cnt; i++) {
			if (!(rdsv3_cpuid_pool[i] & (RDSV3_CPUFLAGS_UNAVAIL |
			    RDSV3_CPUFLAGS_HCA))) {
				hcagp->g_conn_cpuid_pool[j] = i;
				idx = i + 1;
				break;
			}
		}
	}
	mutex_exit(&rdsv3_cpuid_pool_lock);
}

rdsv3_af_grp_t *
rdsv3_af_grp_create(ibt_hca_hdl_t hca, uint64_t id)
{
	char name[128];
	ibt_cq_sched_attr_t cq_sched_attr;
	ibt_status_t status;
	rdsv3_af_grp_t *hcagp;
	uint64_t l_id = id;

	hcagp = kmem_zalloc(sizeof (*hcagp), KM_NOSLEEP);
	if (!hcagp)
		return (NULL);
	hcagp->g_hca_hdl = hca;

	rdsv3_af_cpu_assign(hcagp);
	return (hcagp);
}

void
rdsv3_af_grp_destroy(rdsv3_af_grp_t *hcagp)
{
	if (hcagp == NULL)
		return;

	kmem_free(hcagp, sizeof (*hcagp));
}

void
rdsv3_af_grp_draw(rdsv3_af_grp_t *hcagp)
{
	rdsv3_af_grp_t *l_hcagp = hcagp;
}

ibt_sched_hdl_t
rdsv3_af_grp_get_sched(rdsv3_af_grp_t *hcagp)
{
	return (hcagp->g_sched_hdl);
}

rdsv3_af_thr_t *
rdsv3_af_intr_thr_create(rdsv3_af_thr_drain_func_t fn, void *data, uint_t flag,
    rdsv3_af_grp_t *hcagp, ibt_cq_hdl_t ibt_cq_hdl)
{
	rdsv3_af_thr_t *ringp;
	processorid_t cpuid;

	if (ibt_cq_hdl == NULL)
		return (NULL);
	ringp = rdsv3_af_thr_create(fn, data, flag, hcagp);
	if (ringp == NULL)
		return (NULL);

	mutex_enter(&cpu_lock);
	if (hcagp->g_conn_cpuid_idx >= RDSV3_AFT_CONN_CPU_POOL)
		hcagp->g_conn_cpuid_idx = 0;
	cpuid =  hcagp->g_conn_cpuid_pool[hcagp->g_conn_cpuid_idx++];
	(void) rdsv3_af_thr_bind(ringp, cpuid);
	mutex_exit(&cpu_lock);

	if (ringp->aft_intr) {
		if (rdsv3_intr_line_up_mode) {
			(void) ddi_intr_set_affinity(ringp->aft_intr, cpuid);
		} else {
			(void) ddi_intr_set_affinity(ringp->aft_intr,
			    rdsv3_msix_pool[0]);
		}
	}
	return (ringp);
}

rdsv3_af_thr_t *
rdsv3_af_thr_create(rdsv3_af_thr_drain_func_t fn, void *data, uint_t flag,
    rdsv3_af_grp_t *hcagp)
{
	rdsv3_af_thr_t *ringp;
	pri_t pri;
	uint_t l_flags = flag;
	rdsv3_af_grp_t *l_hcagp = hcagp;

	ringp = kmem_zalloc(sizeof (rdsv3_af_thr_t), KM_NOSLEEP);
	if (ringp == NULL)
		return (NULL);

	ringp->aft_grp = hcagp;
	mutex_init(&ringp->aft_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ringp->aft_async, NULL, CV_DEFAULT, NULL);
	if (flag & SCQ_WRK_BIND_CPU)
		pri = maxclsyspri;
	else
		pri = maxclsyspri;
	ringp->aft_worker = thread_create(NULL, 0,
	    rdsv3_af_thr_worker, ringp, 0, &p0, TS_RUN, pri);
	ringp->aft_data = data;
	ringp->aft_drain_func = (rdsv3_af_thr_drain_func_t)fn;

	/* set the bind CPU to -1 to indicate no thread affinity set */
	ringp->aft_cpuid = -1;
	ringp->aft_state = 0;
	ringp->aft_cflag = flag;

	if (flag & SCQ_BIND_CPU) {
		mutex_enter(&cpu_lock);
		if (flag & SCQ_HCA_BIND_CPU) {
			(void) rdsv3_af_thr_bind(ringp, hcagp->g_hca_cpuid);
		} else if (flag & SCQ_WRK_BIND_CPU) {
			(void) rdsv3_af_thr_bind(ringp, hcagp->g_hca_cpuid);
		}
		mutex_exit(&cpu_lock);
	}

	RDSV3_DPRINTF2("rdsv3_af_thr_create", "af_thr %p ic %p", ringp, data);
	return (ringp);
}

void
rdsv3_af_thr_destroy(rdsv3_af_thr_t *ringp)
{
	RDSV3_DPRINTF2("rdsv3_af_thr_destroy", "af_thr %p", ringp);

	/* wait until the af_thr has gone to sleep */
	mutex_enter(&ringp->aft_lock);
	while (ringp->aft_state & AFT_PROC) {
		mutex_exit(&ringp->aft_lock);
		delay(drv_usectohz(1000));
		mutex_enter(&ringp->aft_lock);
	}
	ringp->aft_state |= AFT_CONDEMNED;
	if (!(ringp->aft_state & AFT_PROC)) {
		cv_signal(&ringp->aft_async);
	}
	mutex_exit(&ringp->aft_lock);
}

void
rdsv3_af_thr_fire(rdsv3_af_thr_t *ringp)
{
	mutex_enter(&ringp->aft_lock);
	ringp->aft_state |= AFT_ARMED;
	if (!(ringp->aft_state & AFT_PROC)) {
		cv_signal(&ringp->aft_async);
	}
	mutex_exit(&ringp->aft_lock);
}

static void
rdsv3_af_thr_worker(rdsv3_af_thr_t *ringp)
{
	kmutex_t *lock = &ringp->aft_lock;
	kcondvar_t *async = &ringp->aft_async;
	callb_cpr_t cprinfo;

	RDSV3_DPRINTF4("rdsv3_af_thr_worker", "Enter af_thr %p", ringp);

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "rdsv3_af_thr");
	mutex_enter(lock);
	for (;;) {
		while (!(ringp->aft_state & (AFT_ARMED | AFT_CONDEMNED))) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(async, lock);
			CALLB_CPR_SAFE_END(&cprinfo, lock);
		}
		ringp->aft_state &= ~AFT_ARMED;

		/*
		 * Either we have work to do, or we have been asked to
		 * shutdown
		 */
		if (ringp->aft_state & AFT_CONDEMNED)
			goto done;
		ASSERT(!(ringp->aft_state & AFT_PROC));
		ringp->aft_state |= AFT_PROC;
		mutex_exit(&ringp->aft_lock);

		ringp->aft_drain_func(ringp->aft_data);

		mutex_enter(&ringp->aft_lock);
		ringp->aft_state &= ~AFT_PROC;
	}
done:
	CALLB_CPR_EXIT(&cprinfo);
	RDSV3_DPRINTF2("rdsv3_af_thr_worker", "Exit af_thr %p", ringp);
	cv_destroy(&ringp->aft_async);
	mutex_destroy(&ringp->aft_lock);
	kmem_free(ringp, sizeof (rdsv3_af_thr_t));
	thread_exit();
}


int rdsv3_af_thr_thread_bind = 1;

/*
 * Bind a soft ring worker thread to supplied CPU.
 */
cpu_t *
rdsv3_af_thr_bind(rdsv3_af_thr_t *ringp, processorid_t cpuid)
{
	cpu_t *cp;
	boolean_t clear = B_FALSE;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (rdsv3_af_thr_thread_bind == 0) {
		return (NULL);
	}

	cp = cpu_get(cpuid);
	if (cp == NULL || !cpu_is_online(cp))
		return (NULL);

	mutex_enter(&ringp->aft_lock);
	ringp->aft_state |= AFT_BOUND;
	if (ringp->aft_cpuid != -1)
		clear = B_TRUE;
	ringp->aft_cpuid = cpuid;
	mutex_exit(&ringp->aft_lock);

	if (clear)
		thread_affinity_clear(ringp->aft_worker);

	RDSV3_DPRINTF4("rdsv3_af_thr_bind", "Bound af_thr %p to cpu %d",
	    ringp, cpuid);
	thread_affinity_set(ringp->aft_worker, cpuid);
	return (cp);
}

/*
 * Un Bind a soft ring worker thread.
 */
static void
rdsv3_af_thr_unbind(rdsv3_af_thr_t *ringp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	mutex_enter(&ringp->aft_lock);
	if (!(ringp->aft_state & AFT_BOUND)) {
		ASSERT(ringp->aft_cpuid == -1);
		mutex_exit(&ringp->aft_lock);
		return;
	}

	ringp->aft_cpuid = -1;
	ringp->aft_state &= ~AFT_BOUND;
	thread_affinity_clear(ringp->aft_worker);
	mutex_exit(&ringp->aft_lock);
}
