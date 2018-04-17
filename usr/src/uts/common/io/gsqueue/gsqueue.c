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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Serialization queues are a technique used in illumos to provide what's
 * commonly known as a 'vertical' perimeter. The idea (described a bit in
 * uts/common/inet/squeue.c) is to provide a means to make sure that message
 * blocks (mblk_t) are processed in a specific order. Subsystems like ip and vnd
 * consume these on different policies, ip on a conn_t basis, vnd on a per
 * device basis, and use this to ensure that only one packet is being processed
 * at a given time.
 *
 * Serialization queues were originally used by ip. As part of that
 * implementation, many of the details of ip were baked into it. That includes
 * things like conn_t, ip receive attributes, and the notion of sets. While an
 * individual serialization queue, or gsqueue_t, is a useful level of
 * abstraction, it isn't the basis on which monst consumers want to manage them.
 * Instead, we have the notion of a set of serialization queues. These sets are
 * DR (CPU Dynamic reconfiguration) aware, and allow consumers to have a
 * gsqueue_t per CPU to fanout on without managing them all itself. In the
 * original implementation, this existed, but they were heavily tied into the
 * infrastructure of IP, and its notion of polling on the underlying MAC
 * devices.
 *
 * The result of that past is a new interface to serialization queues and a
 * similar, but slightly different, abstraction to sets of these
 * (gsqueue_set_t).  When designing this there are two different approaches that
 * one could consider. The first is that the system has one gsqueue_set_t that
 * the entire world shares, whether IP or some other consumer. The other is that
 * every consumer has their own set.
 *
 * The trade offs between these two failure modes are the pathological failure
 * modes. There is no guarantee that any two consumers here are equivalent. In
 * fact, they very likely have very different latency profiles. If they are
 * being processed in the same queue, that can lead to very odd behaviors. More
 * generally, if we have a series of processing functions from one consumer
 * which are generally short, and another which are generally long, that'll
 * cause undue latency that's harder to observe. If we instead take the approach
 * that each consumer should have its own set that it fans out over then we
 * won't end up with the problem that a given serialization queue will have
 * multiple latency profiles, but instead we'll see cpu contention for the bound
 * gsqueue_t worker thread. Keep in mind though, that only the gsqueue_t worker
 * thread is bound and it is in fact possible for it to be processed by other
 * threads on other CPUs.
 *
 * We've opted to go down the second path, so each consumer has its own
 * independent set of serialization queues that it is bound over.
 *
 * Structure Hierarchies
 * ---------------------
 *
 * At the top level, we have a single list of gsqueue_set_t. The gsqueue_set_t
 * encapsulates all the per-CPU gsqueue_t that exist in the form of
 * gsqueue_cpu_t.  The gsqueue_cpu_t has been designed such that it could
 * accommodate more than one gsqueue_t, but today there is a one to one mapping.
 *
 * We maintain two different lists of gsqueue_cpu_t, the active and defunct
 * sets. The active set is maintained in the array `gs_cpus`. There are NCPU
 * entries available in `gs_cpus` with the total number of currently active cpus
 * described in `gs_ncpus`. The ordering of `gs_cpus` is unimportant.  When
 * there is no longer a need for a given binding (see the following section for
 * more explanation on when this is the case) then we move the entry to the
 * `gs_defunct` list which is just a list_t of gsqueue_cpu_t.
 *
 * In addition, each gsqueue_set_t can have a series of callbacks registered
 * with it. These are described in the following section. Graphically, a given
 * gsqueue_set_t looks roughly like the following:
 *
 *     +---------------+
 *     | gsqueue_set_t |
 *     +---------------+
 *       |    |     |
 *       |    |     * . . . gs_cpus
 *       |    |     |
 *       |    |     |    +-------------------------------------------------+
 *       |    |     +--->| gsqueue_cpu_t || gsqueue_cpu_t || gsqueue_cpu_t |...
 *       |    |          +-------------------------------------------------+
 *       |    |
 *       |    * . . . gs_defunct
 *       |    |
 *       |    |    +---------------+   +---------------+   +---------------+
 *       |    +--->| gsqueue_cpu_t |-->| gsqueue_cpu_t |-->| gsqueue_cpu_t |...
 *       |         +---------------+   +---------------+   +---------------+
 *       * . . . gs_cbs
 *       |
 *       |    +--------------+   +--------------+  +--------------+
 *       +--->| gsqueue_cb_t |-->| gsqueue_cb_t |->| gsqueue_cb_t |...
 *            +--------------+   +--------------+  +--------------+
 *
 * CPU DR, gsqueue_t, and gsqueue_t
 * --------------------------------
 *
 * Recall, that every serialization queue (gsqueue_t or squeue_t) has a worker
 * thread that may end up doing work. As part of supporting fanout, we have one
 * gsqueue_t per CPU, and its worker thread is bound to that CPU. Because of
 * this binding, we need to deal with CPU DR changes.
 *
 * The gsqueue driver maintains a single CPU DR callback that is used for the
 * entire sub-system. We break down CPU DR events into three groups. Offline
 * events, online events, and events we can ignore. When the first group occurs,
 * we need to go through every gsqueue_t, find the gsqueue_cpu_t that
 * corresponds to that processor id, and unbind all of its gsqueue_t's. It's
 * rather important that we only unbind the gsqueue_t's and not actually destroy
 * them. When this happens, they could very easily have data queued inside of
 * them and it's unreasonable to just throw out everything in them at this
 * point. The data remains intact and service continues uinterrupted.
 *
 * When we receive an online event, we do the opposite. We try to find a
 * gsqueue_cpu_t that previously was bound to this CPU (by leaving its gqc_cpuid
 * field intact) in the defunct list. If we find one, we remove it from the
 * defunct list and add it to the active list as well as binding the gsqueue_t
 * to the CPU in question. If we don't find one, then we create a new one.
 *
 * To deal with these kinds of situations, we allow a consumer to register
 * callbacks for the gsqueue_t that they are interested in. These callbacks will
 * fire whenever we are handling a topology change. The design of the callbacks
 * is not that the user can take any administrative action during them, but
 * rather set something for them to do asynchronously. It is illegal to make any
 * calls into the gsqueue system while you are in a callback.
 *
 * Locking
 * -------
 *
 * The lock ordering here is fairly straightforward. Due to our use of CPU
 * binding and the CPU DR callbacks, we have an additional lock to consider
 * cpu_lock. Because of that, the following are the rules for locking:
 *
 *
 *   o If performing binding operations, you must grab cpu_lock. cpu_lock is
 *     also at the top of the order.
 *
 *   o cpu_lock > gsqueue_lock > gsqueue_t`gs_lock > squeue_t`sq_lock
 *     If you need to take multiple locks, you must take the greatest
 *     (left-most) one first.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/cpuvar.h>
#include <sys/list.h>
#include <sys/sysmacros.h>

#include <sys/gsqueue.h>
#include <sys/squeue_impl.h>

typedef struct gsqueue_cb {
	struct gsqueue_cb *gcb_next;
	gsqueue_cb_f gcb_func;
	void *gcb_arg;
} gsqueue_cb_t;

typedef struct gsqueue_cpu {
	list_node_t gqc_lnode;
	squeue_t *gqc_head;
	processorid_t gqc_cpuid;
} gsqueue_cpu_t;

struct gsqueue_set {
	list_node_t gs_next;
	pri_t gs_wpri;
	kmutex_t gs_lock;
	int gs_ncpus;
	gsqueue_cpu_t **gs_cpus;
	list_t gs_defunct;
	gsqueue_cb_t *gs_cbs;
};

static kmutex_t gsqueue_lock;
static list_t gsqueue_list;
static kmem_cache_t *gsqueue_cb_cache;
static kmem_cache_t *gsqueue_cpu_cache;
static kmem_cache_t *gsqueue_set_cache;

static gsqueue_cpu_t *
gsqueue_cpu_create(pri_t wpri, processorid_t cpuid)
{
	gsqueue_cpu_t *scp;

	scp = kmem_cache_alloc(gsqueue_cpu_cache, KM_SLEEP);

	list_link_init(&scp->gqc_lnode);
	scp->gqc_cpuid = cpuid;
	scp->gqc_head = squeue_create(wpri, B_FALSE);
	scp->gqc_head->sq_state = SQS_DEFAULT;
	squeue_bind(scp->gqc_head, cpuid);

	return (scp);
}

static void
gsqueue_cpu_destroy(gsqueue_cpu_t *scp)
{
	squeue_destroy(scp->gqc_head);
	kmem_cache_free(gsqueue_cpu_cache, scp);
}

gsqueue_set_t *
gsqueue_set_create(pri_t wpri)
{
	int i;
	gsqueue_set_t *gssp;

	gssp = kmem_cache_alloc(gsqueue_set_cache, KM_SLEEP);
	gssp->gs_wpri = wpri;
	gssp->gs_ncpus = 0;

	/*
	 * We're grabbing CPU lock. Once we let go of it we have to ensure all
	 * set up of the gsqueue_set_t is complete, as it'll be in there for the
	 * various CPU DR bits.
	 */
	mutex_enter(&cpu_lock);

	for (i = 0; i < NCPU; i++) {
		gsqueue_cpu_t *scp;
		cpu_t *cp = cpu_get(i);
		if (cp != NULL && CPU_ACTIVE(cp) &&
		    cp->cpu_flags & CPU_EXISTS) {
			scp = gsqueue_cpu_create(wpri, cp->cpu_id);
			gssp->gs_cpus[gssp->gs_ncpus] = scp;
			gssp->gs_ncpus++;
		}
	}

	/* Finally we can add it to our global list and be done */
	mutex_enter(&gsqueue_lock);
	list_insert_tail(&gsqueue_list, gssp);
	mutex_exit(&gsqueue_lock);
	mutex_exit(&cpu_lock);

	return (gssp);
}

void
gsqueue_set_destroy(gsqueue_set_t *gssp)
{
	int i;
	gsqueue_cpu_t *scp;

	/*
	 * Go through and unbind all of the squeues while cpu_lock is held and
	 * move them to the defunct list. Once that's done, we don't need to do
	 * anything else with cpu_lock.
	 */
	mutex_enter(&cpu_lock);
	mutex_enter(&gsqueue_lock);
	list_remove(&gsqueue_list, gssp);
	mutex_exit(&gsqueue_lock);

	mutex_enter(&gssp->gs_lock);

	for (i = 0; i < gssp->gs_ncpus; i++) {
		scp = gssp->gs_cpus[i];
		squeue_unbind(scp->gqc_head);
		list_insert_tail(&gssp->gs_defunct, scp);
		gssp->gs_cpus[i] = NULL;
	}
	gssp->gs_ncpus = 0;

	mutex_exit(&gssp->gs_lock);
	mutex_exit(&cpu_lock);

	while ((scp = list_remove_head(&gssp->gs_defunct)) != NULL) {
		gsqueue_cpu_destroy(scp);
	}

	while (gssp->gs_cbs != NULL) {
		gsqueue_cb_t *cbp;

		cbp = gssp->gs_cbs;
		gssp->gs_cbs = cbp->gcb_next;
		kmem_cache_free(gsqueue_cb_cache, cbp);
	}

	ASSERT3U(gssp->gs_ncpus, ==, 0);
	ASSERT3P(list_head(&gssp->gs_defunct), ==, NULL);
	ASSERT3P(gssp->gs_cbs, ==, NULL);
	kmem_cache_free(gsqueue_set_cache, gssp);
}

gsqueue_t *
gsqueue_set_get(gsqueue_set_t *gssp, uint_t index)
{
	squeue_t *sqp;
	gsqueue_cpu_t *scp;

	mutex_enter(&gssp->gs_lock);
	scp = gssp->gs_cpus[index % gssp->gs_ncpus];
	sqp = scp->gqc_head;
	mutex_exit(&gssp->gs_lock);
	return ((gsqueue_t *)sqp);
}

uintptr_t
gsqueue_set_cb_add(gsqueue_set_t *gssp, gsqueue_cb_f cb, void *arg)
{
	gsqueue_cb_t *cbp;

	cbp = kmem_cache_alloc(gsqueue_cb_cache, KM_SLEEP);
	cbp->gcb_func = cb;
	cbp->gcb_arg = arg;

	mutex_enter(&gssp->gs_lock);
	cbp->gcb_next = gssp->gs_cbs;
	gssp->gs_cbs = cbp;
	mutex_exit(&gssp->gs_lock);
	return ((uintptr_t)cbp);
}

int
gsqueue_set_cb_remove(gsqueue_set_t *gssp, uintptr_t id)
{
	gsqueue_cb_t *cbp, *prev;
	mutex_enter(&gssp->gs_lock);
	cbp = gssp->gs_cbs;
	prev = NULL;
	while (cbp != NULL) {
		if ((uintptr_t)cbp != id) {
			prev = cbp;
			cbp = cbp->gcb_next;
			continue;
		}

		if (prev == NULL) {
			gssp->gs_cbs = cbp->gcb_next;
		} else {
			prev->gcb_next = cbp->gcb_next;
		}

		mutex_exit(&gssp->gs_lock);
		kmem_cache_free(gsqueue_cb_cache, cbp);
		return (0);
	}
	mutex_exit(&gssp->gs_lock);
	return (-1);
}

void
gsqueue_enter_one(gsqueue_t *gsp, mblk_t *mp, gsqueue_proc_f func, void *arg,
    int flags, uint8_t tag)
{
	squeue_t *sqp = (squeue_t *)gsp;

	ASSERT(mp->b_next == NULL);
	ASSERT(mp->b_prev == NULL);
	mp->b_queue = (queue_t *)func;
	mp->b_prev = arg;
	sqp->sq_enter(sqp, mp, mp, 1, NULL, flags, tag);
}

static void
gsqueue_notify(gsqueue_set_t *gssp, squeue_t *sqp, boolean_t online)
{
	gsqueue_cb_t *cbp;

	ASSERT(MUTEX_HELD(&gssp->gs_lock));
	cbp = gssp->gs_cbs;
	while (cbp != NULL) {
		cbp->gcb_func(gssp, (gsqueue_t *)sqp, cbp->gcb_arg, online);
		cbp = cbp->gcb_next;
	}

}

/*
 * When we online a processor we need to go through and either bind a defunct
 * squeue or create a new one. We'll try to reuse a gsqueue_cpu_t from the
 * defunct list that used to be on that processor. If no such gsqueue_cpu_t
 * exists, then we'll create a new one. We'd rather avoid taking over an
 * existing defunct one that used to be on another CPU, as its not unreasonable
 * to believe that its CPU will come back. More CPUs are offlined and onlined by
 * the administrator or by creating cpu sets than actually get offlined by FMA.
 */
static void
gsqueue_handle_online(processorid_t id)
{
	gsqueue_set_t *gssp;

	ASSERT(MUTEX_HELD(&cpu_lock));
	mutex_enter(&gsqueue_lock);
	for (gssp = list_head(&gsqueue_list); gssp != NULL;
	    gssp = list_next(&gsqueue_list, gssp)) {
		gsqueue_cpu_t *scp;

		mutex_enter(&gssp->gs_lock);
		for (scp = list_head(&gssp->gs_defunct); scp != NULL;
		    scp = list_next(&gssp->gs_defunct, scp)) {
			if (scp->gqc_cpuid == id) {
				list_remove(&gssp->gs_defunct, scp);
				break;
			}
		}

		if (scp == NULL) {
			scp = gsqueue_cpu_create(gssp->gs_wpri, id);
		} else {
			squeue_bind(scp->gqc_head, id);
		}

		ASSERT(gssp->gs_ncpus < NCPU);
		gssp->gs_cpus[gssp->gs_ncpus] = scp;
		gssp->gs_ncpus++;
		gsqueue_notify(gssp, scp->gqc_head, B_TRUE);
		mutex_exit(&gssp->gs_lock);
	}
	mutex_exit(&gsqueue_lock);
}

static void
gsqueue_handle_offline(processorid_t id)
{
	gsqueue_set_t *gssp;

	ASSERT(MUTEX_HELD(&cpu_lock));
	mutex_enter(&gsqueue_lock);
	for (gssp = list_head(&gsqueue_list); gssp != NULL;
	    gssp = list_next(&gsqueue_list, gssp)) {
		int i;
		gsqueue_cpu_t *scp = NULL;

		mutex_enter(&gssp->gs_lock);
		for (i = 0; i < gssp->gs_ncpus; i++) {
			if (gssp->gs_cpus[i]->gqc_cpuid == id) {
				scp = gssp->gs_cpus[i];
				break;
			}
		}

		if (scp != NULL) {
			squeue_unbind(scp->gqc_head);
			list_insert_tail(&gssp->gs_defunct, scp);
			gssp->gs_cpus[i] = gssp->gs_cpus[gssp->gs_ncpus-1];
			gssp->gs_ncpus--;
			gsqueue_notify(gssp, scp->gqc_head, B_FALSE);
		}
		mutex_exit(&gssp->gs_lock);
	}
	mutex_exit(&gsqueue_lock);
}

/* ARGSUSED */
static int
gsqueue_cpu_setup(cpu_setup_t what, int id, void *unused)
{
	cpu_t *cp;

	ASSERT(MUTEX_HELD(&cpu_lock));
	cp = cpu_get(id);
	switch (what) {
	case CPU_CONFIG:
	case CPU_ON:
	case CPU_INIT:
	case CPU_CPUPART_IN:
		if (cp != NULL && CPU_ACTIVE(cp) && cp->cpu_flags & CPU_EXISTS)
			gsqueue_handle_online(cp->cpu_id);
		break;
	case CPU_UNCONFIG:
	case CPU_OFF:
	case CPU_CPUPART_OUT:
		gsqueue_handle_offline(cp->cpu_id);
		break;
	default:
		break;
	}

	return (0);
}


/* ARGSUSED */
static int
gsqueue_set_cache_construct(void *buf, void *arg, int kmflags)
{
	gsqueue_set_t *gssp = buf;

	gssp->gs_cpus = kmem_alloc(sizeof (gsqueue_cpu_t *) * NCPU, kmflags);
	if (gssp->gs_cpus == NULL)
		return (-1);

	mutex_init(&gssp->gs_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&gssp->gs_defunct, sizeof (gsqueue_cpu_t),
	    offsetof(gsqueue_cpu_t, gqc_lnode));
	gssp->gs_ncpus = 0;
	gssp->gs_cbs = NULL;

	return (0);
}

/* ARGSUSED */
static void
gsqueue_set_cache_destruct(void *buf, void *arg)
{
	gsqueue_set_t *gssp = buf;

	kmem_free(gssp->gs_cpus, sizeof (gsqueue_cpu_t *) * NCPU);
	gssp->gs_cpus = NULL;
	list_destroy(&gssp->gs_defunct);
	mutex_destroy(&gssp->gs_lock);
}

static void
gsqueue_ddiinit(void)
{
	list_create(&gsqueue_list, sizeof (gsqueue_set_t),
	    offsetof(gsqueue_set_t, gs_next));
	mutex_init(&gsqueue_lock, NULL, MUTEX_DRIVER, NULL);

	gsqueue_cb_cache = kmem_cache_create("gsqueue_cb_cache",
	    sizeof (gsqueue_cb_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);
	gsqueue_cpu_cache = kmem_cache_create("gsqueue_cpu_cache",
	    sizeof (gsqueue_cpu_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);
	gsqueue_set_cache = kmem_cache_create("squeue_set_cache",
	    sizeof (gsqueue_set_t),
	    0, gsqueue_set_cache_construct, gsqueue_set_cache_destruct,
	    NULL, NULL, NULL, 0);


	mutex_enter(&cpu_lock);
	register_cpu_setup_func(gsqueue_cpu_setup, NULL);
	mutex_exit(&cpu_lock);
}

static int
gsqueue_ddifini(void)
{
	mutex_enter(&gsqueue_lock);
	if (list_is_empty(&gsqueue_list) == 0) {
		mutex_exit(&gsqueue_lock);
		return (EBUSY);
	}
	list_destroy(&gsqueue_list);
	mutex_exit(&gsqueue_lock);

	mutex_enter(&cpu_lock);
	register_cpu_setup_func(gsqueue_cpu_setup, NULL);
	mutex_exit(&cpu_lock);

	kmem_cache_destroy(gsqueue_set_cache);
	kmem_cache_destroy(gsqueue_cpu_cache);
	kmem_cache_destroy(gsqueue_cb_cache);

	mutex_destroy(&gsqueue_lock);

	return (0);
}

static struct modlmisc		gsqueue_modmisc = {
	&mod_miscops,
	"gsqueue"
};

static struct modlinkage	gsqueue_modlinkage = {
	MODREV_1,
	&gsqueue_modmisc,
	NULL
};

int
_init(void)
{
	int ret;

	gsqueue_ddiinit();
	if ((ret = mod_install(&gsqueue_modlinkage)) != 0) {
		VERIFY(gsqueue_ddifini() == 0);
		return (ret);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&gsqueue_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = gsqueue_ddifini()) != 0)
		return (ret);

	if ((ret = mod_remove(&gsqueue_modlinkage)) != 0)
		return (ret);

	return (0);
}
