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

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/sdt.h>
#include <sys/conf.h>
#include <sys/dlpi.h>
#include <sys/ddi.h>
#include <sys/kstat.h>
#include <sys/strsun.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/note.h>
#include <sys/policy.h>
#include <net/ppp_defs.h>
#include <net/pppio.h>
#include <net/sppptun.h>
#include <net/pppoe.h>
#include <netinet/in.h>

#include "s_common.h"
#include "sppptun_mod.h"
#include "sppptun_impl.h"

#define	NTUN_INITIAL 16			/* Initial number of sppptun slots */
#define	NTUN_PERCENT 5			/* Percent of memory to use */

/*
 * This is used to tag official Solaris sources.  Please do not define
 * "INTERNAL_BUILD" when building this software outside of Sun
 * Microsystems.
 */
#ifdef INTERNAL_BUILD
/* MODINFO is limited to 32 characters. */
const char sppptun_driver_description[] = "PPP 4.0 tunnel driver";
const char sppptun_module_description[] = "PPP 4.0 tunnel module";
#else
const char sppptun_driver_description[] = "ANU PPP tundrv";
const char sppptun_module_description[] = "ANU PPP tunmod";

/* LINTED */
static const char buildtime[] = "Built " __DATE__ " at " __TIME__
#ifdef DEBUG
" DEBUG"
#endif
"\n";
#endif

/*
 * Tunable values; these are similar to the values used in ptms_conf.c.
 * Override these settings via /etc/system.
 */
uint_t	sppptun_cnt = 0;		/* Minimum number of tunnels */
size_t	sppptun_max_pty = 0;		/* Maximum number of tunnels */
uint_t	sppptun_init_cnt = NTUN_INITIAL; /* Initial number of tunnel slots */
uint_t	sppptun_pctofmem = NTUN_PERCENT; /* Percent of memory to use */

typedef struct ether_dest_s {
	ether_addr_t addr;
	ushort_t type;
} ether_dest_t;

/* Allows unaligned access. */
#define	GETLONG(x)	(((x)[0]<<24)|((x)[1]<<16)|((x)[2]<<8)|(x)[3])

static const char *tll_kstats_list[] = { TLL_KSTATS_NAMES };
static const char *tcl_kstats_list[] = { TCL_KSTATS_NAMES };

#define	KREF(p, m, vn)	p->m.vn.value.ui64
#define	KINCR(p, m, vn)	++KREF(p, m, vn)
#define	KDECR(p, m, vn)	--KREF(p, m, vn)

#define	KLINCR(vn)	KINCR(tll, tll_kstats, vn)
#define	KLDECR(vn)	KDECR(tll, tll_kstats, vn)

#define	KCINCR(vn)	KINCR(tcl, tcl_kstats, vn)
#define	KCDECR(vn)	KDECR(tcl, tcl_kstats, vn)

static int	sppptun_open(queue_t *, dev_t *, int, int, cred_t *);
static int	sppptun_close(queue_t *, int, cred_t *);
static void	sppptun_urput(queue_t *, mblk_t *);
static void	sppptun_uwput(queue_t *, mblk_t *);
static int	sppptun_ursrv(queue_t *);
static int	sppptun_uwsrv(queue_t *);
static void	sppptun_lrput(queue_t *, mblk_t *);
static void	sppptun_lwput(queue_t *, mblk_t *);

/*
 * This is the hash table of clients.  Clients are the programs that
 * open /dev/sppptun as a device.  There may be a large number of
 * these; one per tunneled PPP session.
 *
 * Note: slots are offset from minor node value by 1 because
 * vmem_alloc returns 0 for failure.
 *
 * The tcl_slots array entries are modified only when exclusive on
 * both inner and outer perimeters.  This ensures that threads on
 * shared perimeters always view this as unchanging memory with no
 * need to lock around accesses.  (Specifically, the tcl_slots array
 * is modified by entry to sppptun_open, sppptun_close, and _fini.)
 */
static tuncl_t **tcl_slots = NULL;	/* Slots for tuncl_t */
static size_t tcl_nslots = 0;		/* Size of slot array */
static size_t tcl_minormax = 0;		/* Maximum number of tunnels */
static size_t tcl_inuse = 0;		/* # of tunnels currently allocated */
static krwlock_t tcl_rwlock;
static struct kmem_cache *tcl_cache = NULL;	/* tunnel cache */
static vmem_t *tcl_minor_arena = NULL; /* Arena for device minors */

/*
 * This is the simple list of lower layers.  For PPPoE, there is one
 * of these per Ethernet interface.  Lower layers are established by
 * "plumbing" -- using I_PLINK to connect the tunnel multiplexor to
 * the physical interface.
 */
static struct qelem tunll_list;
static int tunll_index;

/* Test value; if all zeroes, then address hasn't been set yet. */
static const ether_addr_t zero_mac_addr = { 0, 0, 0, 0, 0, 0 };

#define	MIN_SET_FASTPATH_UNITDATAREQ_SIZE	\
	(sizeof (dl_unitdata_req_t) + 4)

#define	TUN_MI_ID	2104	/* officially allocated module ID */
#define	TUN_MI_MINPSZ	(0)
#define	TUN_MI_MAXPSZ	(PPP_MAXMTU)
#define	TUN_MI_HIWAT	(PPP_MTU * 8)
#define	TUN_MI_LOWAT	(128)

static struct module_info sppptun_modinfo = {
	TUN_MI_ID,		/* mi_idnum */
	PPP_TUN_NAME,		/* mi_idname */
	TUN_MI_MINPSZ,		/* mi_minpsz */
	TUN_MI_MAXPSZ,		/* mi_maxpsz */
	TUN_MI_HIWAT,		/* mi_hiwat */
	TUN_MI_LOWAT		/* mi_lowat */
};

static struct qinit sppptun_urinit = {
	(int (*)())sppptun_urput, /* qi_putp */
	sppptun_ursrv,		/* qi_srvp */
	sppptun_open,		/* qi_qopen */
	sppptun_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sppptun_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit sppptun_uwinit = {
	(int (*)())sppptun_uwput, /* qi_putp */
	sppptun_uwsrv,		/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sppptun_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit sppptun_lrinit = {
	(int (*)())sppptun_lrput, /* qi_putp */
	NULL,			/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sppptun_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

static struct qinit sppptun_lwinit = {
	(int (*)())sppptun_lwput, /* qi_putp */
	NULL,			/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&sppptun_modinfo,	/* qi_minfo */
	NULL			/* qi_mstat */
};

/*
 * This is referenced in sppptun_mod.c.
 */
struct streamtab sppptun_tab = {
	&sppptun_urinit,	/* st_rdinit */
	&sppptun_uwinit,	/* st_wrinit */
	&sppptun_lrinit,	/* st_muxrinit */
	&sppptun_lwinit		/* st_muxwrinit */
};

/*
 * Allocate another slot table twice as large as the original one
 * (limited to global maximum).  Migrate all tunnels to the new slot
 * table and free the original one.  Assumes we're exclusive on both
 * inner and outer perimeters, and thus there are no other users of
 * the tcl_slots array.
 */
static minor_t
tcl_grow(void)
{
	minor_t old_size = tcl_nslots;
	minor_t new_size = 2 * old_size;
	tuncl_t **tcl_old = tcl_slots;
	tuncl_t **tcl_new;
	void  *vaddr;			/* vmem_add return value */

	ASSERT(RW_LOCK_HELD(&tcl_rwlock));

	/* Allocate new ptms array */
	tcl_new = kmem_zalloc(new_size * sizeof (tuncl_t *), KM_NOSLEEP);
	if (tcl_new == NULL)
		return ((minor_t)0);

	/* Increase clone index space */
	vaddr = vmem_add(tcl_minor_arena, (void*)((uintptr_t)old_size + 1),
	    new_size - old_size, VM_NOSLEEP);

	if (vaddr == NULL) {
		kmem_free(tcl_new, new_size * sizeof (tuncl_t *));
		return ((minor_t)0);
	}

	/* Migrate tuncl_t entries to a new location */
	tcl_nslots = new_size;
	bcopy(tcl_old, tcl_new, old_size * sizeof (tuncl_t *));
	tcl_slots = tcl_new;
	kmem_free(tcl_old, old_size * sizeof (tuncl_t *));

	/* Allocate minor number and return it */
	return ((minor_t)(uintptr_t)vmem_alloc(tcl_minor_arena, 1, VM_NOSLEEP));
}

/*
 * Allocate new minor number and tunnel client entry.  Returns the new
 * entry or NULL if no memory or maximum number of entries reached.
 * Assumes we're exclusive on both inner and outer perimeters, and
 * thus there are no other users of the tcl_slots array.
 */
static tuncl_t *
tuncl_alloc(int wantminor)
{
	minor_t dminor;
	tuncl_t *tcl = NULL;

	rw_enter(&tcl_rwlock, RW_WRITER);

	ASSERT(tcl_slots != NULL);

	/*
	 * Always try to allocate new pty when sppptun_cnt minimum
	 * limit is not achieved. If it is achieved, the maximum is
	 * determined by either user-specified value (if it is
	 * non-zero) or our memory estimations - whatever is less.
	 */
	if (tcl_inuse >= sppptun_cnt) {
		/*
		 * When system achieved required minimum of tunnels,
		 * check for the denial of service limits.
		 *
		 * Get user-imposed maximum, if configured, or
		 * calculated memory constraint.
		 */
		size_t user_max = (sppptun_max_pty == 0 ? tcl_minormax :
		    min(sppptun_max_pty, tcl_minormax));

		/* Do not try to allocate more than allowed */
		if (tcl_inuse >= user_max) {
			rw_exit(&tcl_rwlock);
			return (NULL);
		}
	}
	tcl_inuse++;

	/*
	 * Allocate new minor number. If this fails, all slots are
	 * busy and we need to grow the hash.
	 */
	if (wantminor <= 0) {
		dminor = (minor_t)(uintptr_t)vmem_alloc(tcl_minor_arena, 1,
		    VM_NOSLEEP);
		if (dminor == 0) {
			/* Grow the cache and retry allocation */
			dminor = tcl_grow();
		}
	} else {
		dminor = (minor_t)(uintptr_t)vmem_xalloc(tcl_minor_arena, 1,
		    0, 0, 0, (void *)(uintptr_t)wantminor,
		    (void *)((uintptr_t)wantminor+1), VM_NOSLEEP);
		if (dminor != 0 && dminor != wantminor) {
			vmem_free(tcl_minor_arena, (void *)(uintptr_t)dminor,
			    1);
			dminor = 0;
		}
	}

	if (dminor == 0) {
		/* Not enough memory now */
		tcl_inuse--;
		rw_exit(&tcl_rwlock);
		return (NULL);
	}

	tcl = kmem_cache_alloc(tcl_cache, KM_NOSLEEP);
	if (tcl == NULL) {
		/* Not enough memory - this entry can't be used now. */
		vmem_free(tcl_minor_arena, (void *)(uintptr_t)dminor, 1);
		tcl_inuse--;
	} else {
		bzero(tcl, sizeof (*tcl));
		tcl->tcl_lsessid = dminor;
		ASSERT(tcl_slots[dminor - 1] == NULL);
		tcl_slots[dminor - 1] = tcl;
	}

	rw_exit(&tcl_rwlock);
	return (tcl);
}

/*
 * This routine frees an upper level (client) stream by removing it
 * from the minor number pool and freeing the state structure storage.
 * Assumes we're exclusive on both inner and outer perimeters, and
 * thus there are no other concurrent users of the tcl_slots array or
 * of any entry in that array.
 */
static void
tuncl_free(tuncl_t *tcl)
{
	rw_enter(&tcl_rwlock, RW_WRITER);
	ASSERT(tcl->tcl_lsessid <= tcl_nslots);
	ASSERT(tcl_slots[tcl->tcl_lsessid - 1] == tcl);
	ASSERT(tcl_inuse > 0);
	tcl_inuse--;
	tcl_slots[tcl->tcl_lsessid - 1] = NULL;

	if (tcl->tcl_ksp != NULL) {
		kstat_delete(tcl->tcl_ksp);
		tcl->tcl_ksp = NULL;
	}

	/* Return minor number to the pool of minors */
	vmem_free(tcl_minor_arena, (void *)(uintptr_t)tcl->tcl_lsessid, 1);

	/* Return tuncl_t to the cache */
	kmem_cache_free(tcl_cache, tcl);
	rw_exit(&tcl_rwlock);
}

/*
 * Get tuncl_t structure by minor number.  Returns NULL when minor is
 * out of range.  Note that lookup of tcl pointers (and use of those
 * pointers) is safe because modification is done only when exclusive
 * on both inner and outer perimeters.
 */
static tuncl_t *
tcl_by_minor(minor_t dminor)
{
	tuncl_t *tcl = NULL;

	if ((dminor >= 1) && (dminor <= tcl_nslots) && tcl_slots != NULL) {
		tcl = tcl_slots[dminor - 1];
	}

	return (tcl);
}

/*
 * Set up kstats for upper or lower stream.
 */
static kstat_t *
kstat_setup(kstat_named_t *knt, const char **names, int nstat,
    const char *modname, int unitnum)
{
	kstat_t *ksp;
	char unitname[KSTAT_STRLEN];
	int i;

	for (i = 0; i < nstat; i++) {
		kstat_set_string(knt[i].name, names[i]);
		knt[i].data_type = KSTAT_DATA_UINT64;
	}
	(void) sprintf(unitname, "%s" "%d", modname, unitnum);
	ksp = kstat_create(modname, unitnum, unitname, "net",
	    KSTAT_TYPE_NAMED, nstat, KSTAT_FLAG_VIRTUAL);
	if (ksp != NULL) {
		ksp->ks_data = (void *)knt;
		kstat_install(ksp);
	}
	return (ksp);
}

/*
 * sppptun_open()
 *
 * MT-Perimeters:
 *    exclusive inner, exclusive outer.
 *
 * Description:
 *    Common open procedure for module and driver.
 */
static int
sppptun_open(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	_NOTE(ARGUNUSED(oflag))

	/* Allow a re-open */
	if (q->q_ptr != NULL)
		return (0);

	/* In the off chance that we're on our way out, just return error */
	if (tcl_slots == NULL)
		return (EINVAL);

	if (sflag & MODOPEN) {
		tunll_t *tll;
		char *cp;

		/* ordinary users have no need to push this module */
		if (secpolicy_ppp_config(credp) != 0)
			return (EPERM);

		tll = kmem_zalloc(sizeof (tunll_t), KM_SLEEP);

		tll->tll_index = tunll_index++;

		tll->tll_wq = WR(q);
		tll->tll_zoneid = crgetzoneid(credp);

		/* Insert at end of list */
		insque(&tll->tll_next, tunll_list.q_back);
		q->q_ptr = WR(q)->q_ptr = tll;

		tll->tll_style = PTS_PPPOE;
		tll->tll_alen = sizeof (tll->tll_lcladdr.pta_pppoe);

		tll->tll_ksp = kstat_setup((kstat_named_t *)&tll->tll_kstats,
		    tll_kstats_list, Dim(tll_kstats_list), "tll",
		    tll->tll_index);

		/*
		 * Find the name of the driver somewhere beneath us.
		 * Note that we have no driver under us until after
		 * qprocson().
		 */
		qprocson(q);
		for (q = WR(q); q->q_next != NULL; q = q->q_next)
			;
		cp = NULL;
		if (q->q_qinfo != NULL && q->q_qinfo->qi_minfo != NULL)
			cp = q->q_qinfo->qi_minfo->mi_idname;
		if (cp != NULL && *cp == '\0')
			cp = NULL;

		/* Set initial name; user should overwrite. */
		if (cp == NULL)
			(void) snprintf(tll->tll_name, sizeof (tll->tll_name),
			    PPP_TUN_NAME "%d", tll->tll_index);
		else
			(void) snprintf(tll->tll_name, sizeof (tll->tll_name),
			    "%s:tun%d", cp, tll->tll_index);
	} else {
		tuncl_t	*tcl;

		ASSERT(devp != NULL);
		if (sflag & CLONEOPEN) {
			tcl = tuncl_alloc(-1);
		} else {
			minor_t mn;

			/*
			 * Support of non-clone open (ie, mknod with
			 * defined minor number) is supported for
			 * testing purposes so that 'arbitrary' minor
			 * numbers can be used.
			 */
			mn = getminor(*devp);
			if (mn == 0 || (tcl = tcl_by_minor(mn)) != NULL) {
				return (EPERM);
			}
			tcl = tuncl_alloc(mn);
		}
		if (tcl == NULL)
			return (ENOSR);
		tcl->tcl_rq = q;		/* save read queue pointer */
		tcl->tcl_flags |= TCLF_ISCLIENT;	/* sanity check */
		tcl->tcl_zoneid = crgetzoneid(credp);

		q->q_ptr = WR(q)->q_ptr = (caddr_t)tcl;
		*devp = makedevice(getmajor(*devp), tcl->tcl_lsessid);

		tcl->tcl_ksp = kstat_setup((kstat_named_t *)&tcl->tcl_kstats,
		    tcl_kstats_list, Dim(tcl_kstats_list), "tcl",
		    tcl->tcl_lsessid);

		qprocson(q);
	}
	return (0);
}

/*
 * Create an appropriate control message for this client event.
 */
static mblk_t *
make_control(tuncl_t *tclabout, tunll_t *tllabout, int action, tuncl_t *tclto)
{
	struct ppptun_control *ptc;
	mblk_t *mp = allocb(sizeof (*ptc), BPRI_HI);

	if (mp != NULL) {
		MTYPE(mp) = M_PROTO;
		ptc = (struct ppptun_control *)mp->b_wptr;
		bzero(ptc, sizeof (*ptc));
		mp->b_wptr += sizeof (*ptc);
		if (tclabout != NULL) {
			ptc->ptc_rsessid = tclabout->tcl_rsessid;
			ptc->ptc_address = tclabout->tcl_address;
		}
		ptc->ptc_discrim = tclto->tcl_ctlval;
		ptc->ptc_action = action;
		if (tllabout != NULL) {
			(void) strncpy(ptc->ptc_name, tllabout->tll_name,
			    sizeof (ptc->ptc_name));
		}
	}
	return (mp);
}

/*
 * Send an appropriate control message up this client session.
 */
static void
send_control(tuncl_t *tclabout, tunll_t *tllabout, int action, tuncl_t *tcl)
{
	mblk_t *mp;

	if (tcl->tcl_rq != NULL) {
		mp = make_control(tclabout, tllabout, action, tcl);
		if (mp != NULL) {
			KCINCR(cks_octrl_spec);
			putnext(tcl->tcl_rq, mp);
		}
	}
}

/*
 * If a lower stream is being unplumbed, then the upper streams
 * connected to this lower stream must be disconnected.  This routine
 * accomplishes this by sending M_HANGUP to data streams and M_PROTO
 * messages to control streams.  This is called by vmem_walk, and
 * handles a span of minor node numbers.
 *
 * No need to update lks_clients here; the lower stream is on its way
 * out.
 */
static void
tclvm_remove_tll(void *arg, void *firstv, size_t numv)
{
	tunll_t *tll = (tunll_t *)arg;
	int minorn = (int)(uintptr_t)firstv;
	int minormax = minorn + numv;
	tuncl_t *tcl;
	mblk_t *mp;

	while (minorn < minormax) {
		tcl = tcl_slots[minorn - 1];
		ASSERT(tcl != NULL);
		if (tcl->tcl_data_tll == tll && tcl->tcl_rq != NULL) {
			tcl->tcl_data_tll = NULL;
			mp = allocb(0, BPRI_HI);
			if (mp != NULL) {
				MTYPE(mp) = M_HANGUP;
				putnext(tcl->tcl_rq, mp);
				if (tcl->tcl_ctrl_tll == tll)
					tcl->tcl_ctrl_tll = NULL;
			}
		}
		if (tcl->tcl_ctrl_tll == tll) {
			send_control(tcl, tll, PTCA_UNPLUMB, tcl);
			tcl->tcl_ctrl_tll = NULL;
		}
		minorn++;
	}
}

/*
 * sppptun_close()
 *
 * MT-Perimeters:
 *    exclusive inner, exclusive outer.
 *
 * Description:
 *    Common close procedure for module and driver.
 */
/* ARGSUSED */
static int
sppptun_close(queue_t *q, int flags __unused, cred_t *credp __unused)
{
	int err;
	void *qptr;
	tunll_t *tll;
	tuncl_t *tcl;

	qptr = q->q_ptr;

	err = 0;
	tll = qptr;
	if (!(tll->tll_flags & TLLF_NOTLOWER)) {
		/* q_next is set on modules */
		ASSERT(WR(q)->q_next != NULL);

		/* unlink any clients using this lower layer. */
		vmem_walk(tcl_minor_arena, VMEM_ALLOC, tclvm_remove_tll, tll);

		/* tell daemon that this has been removed. */
		if ((tcl = tll->tll_defcl) != NULL)
			send_control(NULL, tll, PTCA_UNPLUMB, tcl);

		tll->tll_flags |= TLLF_CLOSING;
		while (!(tll->tll_flags & TLLF_CLOSE_DONE)) {
			qenable(tll->tll_wq);
			qwait(tll->tll_wq);
		}
		tll->tll_error = 0;
		while (!(tll->tll_flags & TLLF_SHUTDOWN_DONE)) {
			if (!qwait_sig(tll->tll_wq))
				break;
		}

		qprocsoff(q);
		q->q_ptr = WR(q)->q_ptr = NULL;
		tll->tll_wq = NULL;
		remque(&tll->tll_next);
		err = tll->tll_error;
		if (tll->tll_ksp != NULL)
			kstat_delete(tll->tll_ksp);
		kmem_free(tll, sizeof (*tll));
	} else {
		tcl = qptr;

		/* devices are end of line; no q_next. */
		ASSERT(WR(q)->q_next == NULL);

		qprocsoff(q);
		DTRACE_PROBE1(sppptun__client__close, tuncl_t *, tcl);
		tcl->tcl_rq = NULL;
		q->q_ptr = WR(q)->q_ptr = NULL;

		tll = TO_TLL(tunll_list.q_forw);
		while (tll != TO_TLL(&tunll_list)) {
			if (tll->tll_defcl == tcl)
				tll->tll_defcl = NULL;
			if (tll->tll_lastcl == tcl)
				tll->tll_lastcl = NULL;
			tll = TO_TLL(tll->tll_next);
		}
		/*
		 * If this was a normal session, then tell the daemon.
		 */
		if (!(tcl->tcl_flags & TCLF_DAEMON) &&
		    (tll = tcl->tcl_ctrl_tll) != NULL &&
		    tll->tll_defcl != NULL) {
			send_control(tcl, tll, PTCA_DISCONNECT,
			    tll->tll_defcl);
		}

		/* Update statistics for references being dropped. */
		if ((tll = tcl->tcl_data_tll) != NULL) {
			KLDECR(lks_clients);
		}
		if ((tll = tcl->tcl_ctrl_tll) != NULL) {
			KLDECR(lks_clients);
		}

		tuncl_free(tcl);
	}

	return (err);
}

/*
 * Allocate and initialize a DLPI or TPI template of the specified
 * length.
 */
static mblk_t *
pi_alloc(size_t len, int prim)
{
	mblk_t	*mp;

	mp = allocb(len, BPRI_MED);
	if (mp != NULL) {
		MTYPE(mp) = M_PROTO;
		mp->b_wptr = mp->b_rptr + len;
		bzero(mp->b_rptr, len);
		*(int *)mp->b_rptr = prim;
	}
	return (mp);
}

#define	dlpi_alloc(l, p)	pi_alloc((l), (p))

/*
 * Prepend some room to an mblk.  Try to reuse the existing buffer, if
 * at all possible, rather than allocating a new one.  (Fast-path
 * output should be able to use this.)
 *
 * (XXX why isn't this a library function ...?)
 */
static mblk_t *
prependb(mblk_t *mp, size_t len, size_t align)
{
	mblk_t *newmp;


	if (align == 0)
		align = 8;
	if (DB_REF(mp) > 1 || mp->b_datap->db_base+len > mp->b_rptr ||
	    ((uint_t)((uintptr_t)mp->b_rptr - len) % align) != 0) {
		if ((newmp = allocb(len, BPRI_LO)) == NULL) {
			freemsg(mp);
			return (NULL);
		}
		newmp->b_wptr = newmp->b_rptr + len;
		newmp->b_cont = mp;
		return (newmp);
	}
	mp->b_rptr -= len;
	return (mp);
}

/*
 * sppptun_outpkt()
 *
 * MT-Perimeters:
 *	shared inner, shared outer (if called from sppptun_uwput),
 *	exclusive inner, shared outer (if called from sppptun_uwsrv).
 *
 * Description:
 *    Called from sppptun_uwput or sppptun_uwsrv when processing a
 *    M_DATA, M_PROTO, or M_PCPROTO message.  For all cases, it tries
 *    to prepare the data to be sent to the module below this driver
 *    if there is a lower stream linked underneath.  If no lower
 *    stream exists, then the data will be discarded and an ENXIO
 *    error returned.
 *
 * Returns:
 *	pointer to queue if caller should do putnext, otherwise
 *	*mpp != NULL if message should be enqueued, otherwise
 *	*mpp == NULL if message is gone.
 */
static queue_t *
sppptun_outpkt(queue_t *q, mblk_t **mpp)
{
	mblk_t *mp;
	tuncl_t *tcl;
	tunll_t *tll;
	mblk_t *encmb;
	mblk_t *datamb;
	dl_unitdata_req_t *dur;
	queue_t *lowerq;
	poep_t *poep;
	int len;
	ether_dest_t *edestp;
	enum { luNone, luCopy, luSend } loopup;
	boolean_t isdata;
	struct ppptun_control *ptc;

	mp = *mpp;
	tcl = q->q_ptr;

	*mpp = NULL;
	if (!(tcl->tcl_flags & TCLF_ISCLIENT)) {
		/* This should never happen on a lower layer stream */
		freemsg(mp);
		return (NULL);
	}

	isdata = (MTYPE(mp) == M_DATA);
	if (isdata) {
		tll = tcl->tcl_data_tll;
		ptc = NULL;
	} else {
		/*
		 * If data are unaligned or otherwise unsuitable, then
		 * discard.
		 */
		if (MBLKL(mp) != sizeof (*ptc) || DB_REF(mp) > 1 ||
		    !IS_P2ALIGNED(mp->b_rptr, sizeof (ptc))) {
			KCINCR(cks_octrl_drop);
			DTRACE_PROBE2(sppptun__bad__control, tuncl_t *, tcl,
			    mblk_t *, mp);
			send_control(tcl, tcl->tcl_ctrl_tll, PTCA_BADCTRL, tcl);
			freemsg(mp);
			return (NULL);
		}
		ptc = (struct ppptun_control *)mp->b_rptr;

		/* Set stream discriminator value if not yet set. */
		if (tcl->tcl_ctlval == 0)
			tcl->tcl_ctlval = ptc->ptc_discrim;

		/* If this is a test message, then reply to caller. */
		if (ptc->ptc_action == PTCA_TEST) {
			DTRACE_PROBE2(sppptun__test, tuncl_t *, tcl,
			    struct ppptun_control *, ptc);
			if (mp->b_cont != NULL) {
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
			}
			ptc->ptc_discrim = tcl->tcl_ctlval;
			putnext(RD(q), mp);
			return (NULL);
		}

		/* If this one isn't for us, then discard it */
		if (tcl->tcl_ctlval != ptc->ptc_discrim) {
			DTRACE_PROBE2(sppptun__bad__discrim, tuncl_t *, tcl,
			    struct ppptun_control *, ptc);
			freemsg(mp);
			return (NULL);
		}

		/* Don't allow empty control packets. */
		tll = tcl->tcl_ctrl_tll;
		if (mp->b_cont == NULL) {
			KCINCR(cks_octrl_drop);
			DTRACE_PROBE2(sppptun__bad__control, tuncl_t *, tcl,
			    mblk_t *, mp);
			send_control(tcl, tll, PTCA_BADCTRL, tcl);
			freemsg(mp);
			return (NULL);
		}
	}

	if (tll == NULL || (lowerq = tll->tll_wq) == NULL) {
		DTRACE_PROBE3(sppptun__cannot__send, tuncl_t *, tcl,
		    tunll_t *, tll, mblk_t *, mp);
		send_control(tcl, tll, PTCA_UNPLUMB, tcl);
		freemsg(mp);
		if (isdata) {
			tcl->tcl_stats.ppp_oerrors++;
		} else {
			KCINCR(cks_octrl_drop);
		}
		return (NULL);
	}

	/*
	 * If so, then try to send it down.  The lower queue is only
	 * ever detached while holding an exclusive lock on the whole
	 * driver, so we can be confident that the lower queue is
	 * still there.
	 */
	if (!bcanputnext(lowerq, mp->b_band)) {
		DTRACE_PROBE3(sppptun__flow__control, tuncl_t *, tcl,
		    tunll_t *, tll, mblk_t *, mp);
		*mpp = mp;
		return (NULL);
	}

	/*
	 * Note: DLPI and TPI expect that the first buffer contains
	 * the control (unitdata-req) header, destination address, and
	 * nothing else.  Any protocol headers must go in the next
	 * buffer.
	 */
	loopup = luNone;
	encmb = NULL;
	if (isdata) {
		if (tll->tll_alen != 0 &&
		    bcmp(&tcl->tcl_address, &tll->tll_lcladdr,
		    tll->tll_alen) == 0)
			loopup = luSend;
		switch (tll->tll_style) {
		case PTS_PPPOE:
			/* Strip address and control fields if present. */
			if (mp->b_rptr[0] == 0xFF) {
				if (MBLKL(mp) < 3) {
					encmb = msgpullup(mp, 3);
					freemsg(mp);
					if ((mp = encmb) == NULL)
						break;
				}
				mp->b_rptr += 2;
			}
			/* Broadcasting data is probably not a good idea. */
			if (tcl->tcl_address.pta_pppoe.ptma_mac[0] & 1)
				break;
			encmb = dlpi_alloc(sizeof (*dur) + sizeof (*edestp),
			    DL_UNITDATA_REQ);
			if (encmb == NULL)
				break;

			dur = (dl_unitdata_req_t *)encmb->b_rptr;
			dur->dl_dest_addr_length = sizeof (*edestp);
			dur->dl_dest_addr_offset = sizeof (*dur);
			edestp = (ether_dest_t *)(dur + 1);
			ether_copy(tcl->tcl_address.pta_pppoe.ptma_mac,
			    edestp->addr);
			/* DLPI SAPs are in host byte order! */
			edestp->type = tll->tll_sap;

			/* Make sure the protocol field isn't compressed. */
			len = (*mp->b_rptr & 1);
			mp = prependb(mp, sizeof (*poep) + len, POE_HDR_ALIGN);
			if (mp == NULL)
				break;
			poep = (poep_t *)mp->b_rptr;
			poep->poep_version_type = POE_VERSION;
			poep->poep_code = POECODE_DATA;
			poep->poep_session_id = htons(tcl->tcl_rsessid);
			poep->poep_length = htons(msgsize(mp) -
			    sizeof (*poep));
			if (len > 0)
				*(char *)(poep + 1) = '\0';
			break;

		default:
			ASSERT(0);
		}
	} else {
		/*
		 * Control side encapsulation.
		 */
		if (bcmp(&ptc->ptc_address, &tll->tll_lcladdr, tll->tll_alen)
		    == 0)
			loopup = luSend;
		datamb = mp->b_cont;
		switch (tll->tll_style) {
		case PTS_PPPOE:
			/*
			 * Don't allow a loopback session to establish
			 * itself.  PPPoE is broken; it uses only one
			 * session ID for both data directions, so the
			 * loopback data path can simply never work.
			 */
			if (loopup == luSend &&
			    ((poep_t *)datamb->b_rptr)->poep_code ==
			    POECODE_PADR)
				break;
			encmb = dlpi_alloc(sizeof (*dur) + sizeof (*edestp),
			    DL_UNITDATA_REQ);
			if (encmb == NULL)
				break;
			dur = (dl_unitdata_req_t *)encmb->b_rptr;
			dur->dl_dest_addr_length = sizeof (*edestp);
			dur->dl_dest_addr_offset = sizeof (*dur);

			edestp = (ether_dest_t *)(dur + 1);
			/* DLPI SAPs are in host byte order! */
			edestp->type = tll->tll_sap;

			/*
			 * If destination isn't set yet, then we have to
			 * allow anything at all.  Otherwise, force use
			 * of configured peer address.
			 */
			if (bcmp(tcl->tcl_address.pta_pppoe.ptma_mac,
			    zero_mac_addr, sizeof (zero_mac_addr)) == 0 ||
			    (tcl->tcl_flags & TCLF_DAEMON)) {
				ether_copy(ptc->ptc_address.pta_pppoe.ptma_mac,
				    edestp->addr);
			} else {
				ether_copy(tcl->tcl_address.pta_pppoe.ptma_mac,
				    edestp->addr);
			}
			/* Reflect multicast/broadcast back up. */
			if (edestp->addr[0] & 1)
				loopup = luCopy;
			break;

		case PTS_PPTP:
			/*
			 * PPTP's control side is actually done over
			 * separate TCP connections.
			 */
		default:
			ASSERT(0);
		}
		freeb(mp);
		mp = datamb;
	}
	if (mp == NULL || encmb == NULL) {
		DTRACE_PROBE1(sppptun__output__failure, tuncl_t *, tcl);
		freemsg(mp);
		freemsg(encmb);
		if (isdata) {
			tcl->tcl_stats.ppp_oerrors++;
		} else {
			KCINCR(cks_octrl_drop);
			KLINCR(lks_octrl_drop);
		}
		lowerq = NULL;
	} else {
		if (isdata) {
			tcl->tcl_stats.ppp_obytes += msgsize(mp);
			tcl->tcl_stats.ppp_opackets++;
		} else {
			KCINCR(cks_octrls);
			KLINCR(lks_octrls);
		}
		if (encmb != mp)
			encmb->b_cont = mp;
		switch (loopup) {
		case luNone:
			*mpp = encmb;
			break;
		case luCopy:
			mp = copymsg(encmb);
			if (mp != NULL)
				sppptun_urput(RD(lowerq), mp);
			*mpp = encmb;
			break;
		case luSend:
			sppptun_urput(RD(lowerq), encmb);
			lowerq = NULL;
			break;
		}
	}
	return (lowerq);
}

/*
 * Enqueue a message to be sent when the lower stream is closed.  This
 * is done so that we're guaranteed that we always have the necessary
 * resources to properly detach ourselves from the system.  (If we
 * waited until the close was done to allocate these messages, then
 * the message allocation could fail, and we'd be unable to properly
 * detach.)
 */
static void
save_for_close(tunll_t *tll, mblk_t *mp)
{
	mblk_t *onc;

	if ((onc = tll->tll_onclose) == NULL)
		tll->tll_onclose = mp;
	else {
		while (onc->b_next != NULL)
			onc = onc->b_next;
		onc->b_next = mp;
	}
}

/*
 * Given the lower stream name, locate the state structure.  Note that
 * lookup of tcl pointers (and use of those pointers) is safe because
 * modification is done only when exclusive on both inner and outer
 * perimeters.
 */
static tunll_t *
tll_lookup_on_name(const char *dname, zoneid_t zoneid)
{
	tunll_t *tll;

	tll = TO_TLL(tunll_list.q_forw);
	for (; tll != TO_TLL(&tunll_list); tll = TO_TLL(tll->tll_next))
		if (tll->tll_zoneid == zoneid &&
		    strcmp(dname, tll->tll_name) == 0)
			return (tll);
	return (NULL);
}

/*
 * sppptun_inner_ioctl()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Called by qwriter from sppptun_ioctl as the result of receiving
 *    a handled ioctl.
 */
static void
sppptun_inner_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iop;
	int rc = 0;
	int len = 0;
	int i;
	tuncl_t *tcl;
	tunll_t *tll;
	union ppptun_name *ptn;
	struct ppptun_info *pti;
	struct ppptun_peer *ptp;
	mblk_t *mptmp;
	ppptun_atype *pap;
	struct ppp_stats64 *psp;
	zoneid_t zoneid;

	iop = (struct iocblk *)mp->b_rptr;
	tcl = NULL;
	tll = q->q_ptr;
	if (tll->tll_flags & TLLF_NOTLOWER) {
		tcl = (tuncl_t *)tll;
		tll = NULL;
	}

	DTRACE_PROBE3(sppptun__ioctl, tuncl_t *, tcl, tunll_t *, tll,
	    struct iocblk *, iop);

	switch (iop->ioc_cmd) {
	case PPPIO_DEBUG:
		/*
		 * Debug requests are now ignored; use dtrace or wireshark
		 * instead.
		 */
		break;

	case PPPIO_GETSTAT:
		rc = EINVAL;
		break;

	case PPPIO_GETSTAT64:
		/* Client (device) side only */
		if (tcl == NULL) {
			rc = EINVAL;
			break;
		}
		mptmp = allocb(sizeof (*psp), BPRI_HI);
		if (mptmp == NULL) {
			rc = ENOSR;
			break;
		}
		freemsg(mp->b_cont);
		mp->b_cont = mptmp;

		psp = (struct ppp_stats64 *)mptmp->b_wptr;
		bzero((caddr_t)psp, sizeof (*psp));
		psp->p = tcl->tcl_stats;

		len = sizeof (*psp);
		break;

	case PPPTUN_SNAME:
		/* This is done on the *module* (lower level) side. */
		if (tll == NULL || mp->b_cont == NULL ||
		    iop->ioc_count != sizeof (*ptn) ||
		    *mp->b_cont->b_rptr == '\0') {
			rc = EINVAL;
			break;
		}

		ptn = (union ppptun_name *)mp->b_cont->b_rptr;
		ptn->ptn_name[sizeof (ptn->ptn_name) - 1] = '\0';

		tll = tll_lookup_on_name(ptn->ptn_name, tll->tll_zoneid);
		if (tll != NULL) {
			rc = EEXIST;
			break;
		}
		tll = (tunll_t *)q->q_ptr;
		(void) strcpy(tll->tll_name, ptn->ptn_name);
		break;

	case PPPTUN_SINFO:
	case PPPTUN_GINFO:
		/* Either side */
		if (mp->b_cont == NULL || iop->ioc_count != sizeof (*pti)) {
			rc = EINVAL;
			break;
		}
		pti = (struct ppptun_info *)mp->b_cont->b_rptr;
		if (pti->pti_name[0] != '\0')
			tll = tll_lookup_on_name(pti->pti_name,
			    tcl == NULL ? tll->tll_zoneid : tcl->tcl_zoneid);
		if (tll == NULL) {
			/* Driver (client) side must have name */
			if (tcl != NULL && pti->pti_name[0] == '\0')
				rc = EINVAL;
			else
				rc = ESRCH;
			break;
		}
		if (iop->ioc_cmd == PPPTUN_GINFO) {
			pti->pti_muxid = tll->tll_muxid;
			pti->pti_style = tll->tll_style;
			len = sizeof (*pti);
			break;
		}
		tll->tll_muxid = pti->pti_muxid;
		tll->tll_style = pti->pti_style;
		switch (tll->tll_style) {
		case PTS_PPPOE:		/* DLPI type */
			tll->tll_alen = sizeof (tll->tll_lcladdr.pta_pppoe);
			mptmp = dlpi_alloc(sizeof (dl_unbind_req_t),
			    DL_UNBIND_REQ);
			if (mptmp == NULL) {
				rc = ENOSR;
				break;
			}
			save_for_close(tll, mptmp);
			mptmp = dlpi_alloc(sizeof (dl_detach_req_t),
			    DL_DETACH_REQ);
			if (mptmp == NULL) {
				rc = ENOSR;
				break;
			}
			save_for_close(tll, mptmp);
			break;
		default:
			tll->tll_style = PTS_NONE;
			tll->tll_alen = 0;
			rc = EINVAL;
			break;
		}
		break;

	case PPPTUN_GNNAME:
		/* This can be done on either side. */
		if (mp->b_cont == NULL || iop->ioc_count < sizeof (uint32_t)) {
			rc = EINVAL;
			break;
		}
		zoneid = tcl == NULL ? tll->tll_zoneid : tcl->tcl_zoneid;
		ptn = (union ppptun_name *)mp->b_cont->b_rptr;
		i = ptn->ptn_index;
		tll = TO_TLL(tunll_list.q_forw);
		while (tll != TO_TLL(&tunll_list)) {
			if (tll->tll_zoneid == zoneid && --i < 0)
				break;
			tll = TO_TLL(tll->tll_next);
		}
		if (tll != TO_TLL(&tunll_list)) {
			bcopy(tll->tll_name, ptn->ptn_name,
			    sizeof (ptn->ptn_name));
		} else {
			bzero(ptn, sizeof (*ptn));
		}
		len = sizeof (*ptn);
		break;

	case PPPTUN_LCLADDR:
		/* This is done on the *module* (lower level) side. */
		if (tll == NULL || mp->b_cont == NULL) {
			rc = EINVAL;
			break;
		}

		pap = &tll->tll_lcladdr;
		len = tll->tll_alen;
		if (len == 0 || len > iop->ioc_count) {
			rc = EINVAL;
			break;
		}
		bcopy(mp->b_cont->b_rptr, pap, len);
		len = 0;
		break;

	case PPPTUN_SPEER:
		/* Client (device) side only; before SDATA */
		if (tcl == NULL || mp->b_cont == NULL ||
		    iop->ioc_count != sizeof (*ptp)) {
			rc = EINVAL;
			break;
		}
		if (tcl->tcl_data_tll != NULL) {
			rc = EINVAL;
			break;
		}
		ptp = (struct ppptun_peer *)mp->b_cont->b_rptr;
		DTRACE_PROBE2(sppptun__speer, tuncl_t *, tcl,
		    struct ppptun_peer *, ptp);
		/* Once set, the style cannot change. */
		if (tcl->tcl_style != PTS_NONE &&
		    tcl->tcl_style != ptp->ptp_style) {
			rc = EINVAL;
			break;
		}
		if (ptp->ptp_flags & PTPF_DAEMON) {
			/* User requests registration for tunnel 0 */
			if ((tcl->tcl_flags & TCLF_SPEER_DONE) ||
			    ptp->ptp_ltunid != 0 || ptp->ptp_rtunid != 0 ||
			    ptp->ptp_lsessid != 0 || ptp->ptp_rsessid != 0) {
				rc = EINVAL;
				break;
			}
			tcl->tcl_flags |= TCLF_DAEMON;
		} else {
			/* Normal client connection */
			if (tcl->tcl_flags & TCLF_DAEMON) {
				rc = EINVAL;
				break;
			}
			if (ptp->ptp_lsessid != 0 &&
			    ptp->ptp_lsessid != tcl->tcl_lsessid) {
				rc = EINVAL;
				break;
			}
			/*
			 * If we're reassigning the peer data, then
			 * the previous assignment must have been for
			 * a client control connection.  Check that.
			 */
			if ((tcl->tcl_flags & TCLF_SPEER_DONE) &&
			    ((tcl->tcl_ltunid != 0 &&
			    tcl->tcl_ltunid != ptp->ptp_ltunid) ||
			    (tcl->tcl_rtunid != 0 &&
			    tcl->tcl_rtunid != ptp->ptp_rtunid) ||
			    (tcl->tcl_rsessid != 0 &&
			    tcl->tcl_rsessid != ptp->ptp_rsessid))) {
				rc = EINVAL;
				break;
			}
			if ((tcl->tcl_ltunid = ptp->ptp_ltunid) == 0 &&
			    tcl->tcl_style == PTS_L2FTP)
				tcl->tcl_ltunid = ptp->ptp_lsessid;
			tcl->tcl_rtunid = ptp->ptp_rtunid;
			tcl->tcl_rsessid = ptp->ptp_rsessid;
		}
		tcl->tcl_flags |= TCLF_SPEER_DONE;
		tcl->tcl_style = ptp->ptp_style;
		tcl->tcl_address = ptp->ptp_address;
		goto fill_in_peer;

	case PPPTUN_GPEER:
		/* Client (device) side only */
		if (tcl == NULL) {
			rc = EINVAL;
			break;
		}
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = allocb(sizeof (*ptp), BPRI_HI);
		if (mp->b_cont == NULL) {
			rc = ENOSR;
			break;
		}
		ptp = (struct ppptun_peer *)mp->b_cont->b_rptr;
	fill_in_peer:
		ptp->ptp_style = tcl->tcl_style;
		ptp->ptp_flags = (tcl->tcl_flags & TCLF_DAEMON) ? PTPF_DAEMON :
		    0;
		ptp->ptp_ltunid = tcl->tcl_ltunid;
		ptp->ptp_rtunid = tcl->tcl_rtunid;
		ptp->ptp_lsessid = tcl->tcl_lsessid;
		ptp->ptp_rsessid = tcl->tcl_rsessid;
		ptp->ptp_address = tcl->tcl_address;
		len = sizeof (*ptp);
		break;

	case PPPTUN_SDATA:
	case PPPTUN_SCTL:
		/* Client (device) side only; must do SPEER first */
		if (tcl == NULL || mp->b_cont == NULL ||
		    iop->ioc_count != sizeof (*ptn) ||
		    *mp->b_cont->b_rptr == '\0') {
			rc = EINVAL;
			break;
		}
		if (!(tcl->tcl_flags & TCLF_SPEER_DONE)) {
			rc = EINVAL;
			break;
		}
		ptn = (union ppptun_name *)mp->b_cont->b_rptr;
		ptn->ptn_name[sizeof (ptn->ptn_name) - 1] = '\0';
		tll = tll_lookup_on_name(ptn->ptn_name, tcl->tcl_zoneid);
		if (tll == NULL) {
			rc = ESRCH;
			break;
		}
		if (tll->tll_style != tcl->tcl_style) {
			rc = ENXIO;
			break;
		}
		if (iop->ioc_cmd == PPPTUN_SDATA) {
			if (tcl->tcl_data_tll != NULL) {
				rc = EEXIST;
				break;
			}
			/* server daemons cannot use regular data */
			if (tcl->tcl_flags & TCLF_DAEMON) {
				rc = EINVAL;
				break;
			}
			tcl->tcl_data_tll = tll;
		} else if (tcl->tcl_flags & TCLF_DAEMON) {
			if (tll->tll_defcl != NULL && tll->tll_defcl != tcl) {
				rc = EEXIST;
				break;
			}
			tll->tll_defcl = tcl;
			if (tcl->tcl_ctrl_tll != NULL) {
				KDECR(tcl->tcl_ctrl_tll, tll_kstats,
				    lks_clients);
			}
			tcl->tcl_ctrl_tll = tll;
		} else {
			if (tcl->tcl_ctrl_tll != NULL) {
				rc = EEXIST;
				break;
			}
			tcl->tcl_ctrl_tll = tll;
		}
		KLINCR(lks_clients);
		break;

	case PPPTUN_GDATA:
	case PPPTUN_GCTL:
		/* Client (device) side only */
		if (tcl == NULL) {
			rc = EINVAL;
			break;
		}
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = allocb(sizeof (*ptn), BPRI_HI);
		if (mp->b_cont == NULL) {
			rc = ENOSR;
			break;
		}
		ptn = (union ppptun_name *)mp->b_cont->b_rptr;
		if (iop->ioc_cmd == PPPTUN_GDATA)
			tll = tcl->tcl_data_tll;
		else
			tll = tcl->tcl_ctrl_tll;
		if (tll == NULL)
			bzero(ptn, sizeof (*ptn));
		else
			bcopy(tll->tll_name, ptn->ptn_name,
			    sizeof (ptn->ptn_name));
		len = sizeof (*ptn);
		break;

	case PPPTUN_DCTL:
		/* Client (device) side daemon mode only */
		if (tcl == NULL || mp->b_cont == NULL ||
		    iop->ioc_count != sizeof (*ptn) ||
		    !(tcl->tcl_flags & TCLF_DAEMON)) {
			rc = EINVAL;
			break;
		}
		ptn = (union ppptun_name *)mp->b_cont->b_rptr;
		ptn->ptn_name[sizeof (ptn->ptn_name) - 1] = '\0';
		tll = tll_lookup_on_name(ptn->ptn_name, tcl->tcl_zoneid);
		if (tll == NULL || tll->tll_defcl != tcl) {
			rc = ESRCH;
			break;
		}
		tll->tll_defcl = NULL;
		break;

	case PPPTUN_SSAP:
		/* This is done on the *module* (lower level) side. */
		if (tll == NULL || mp->b_cont == NULL ||
		    iop->ioc_count != sizeof (uint_t)) {
			rc = EINVAL;
			break;
		}

		tll->tll_sap = *(uint_t *)mp->b_cont->b_rptr;
		break;

	default:
		/* Caller should already have checked command value */
		ASSERT(0);
	}
	if (rc != 0) {
		miocnak(q, mp, 0, rc);
	} else {
		if (len > 0)
			mp->b_cont->b_wptr = mp->b_cont->b_rptr + len;
		miocack(q, mp, len, 0);
	}
}

/*
 * sppptun_ioctl()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Called by sppptun_uwput as the result of receiving a M_IOCTL command.
 */
static void
sppptun_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iop;
	int rc = 0;
	int len = 0;
	uint32_t val = 0;
	tunll_t *tll;

	iop = (struct iocblk *)mp->b_rptr;

	switch (iop->ioc_cmd) {
	case PPPIO_DEBUG:
	case PPPIO_GETSTAT:
	case PPPIO_GETSTAT64:
	case PPPTUN_SNAME:
	case PPPTUN_SINFO:
	case PPPTUN_GINFO:
	case PPPTUN_GNNAME:
	case PPPTUN_LCLADDR:
	case PPPTUN_SPEER:
	case PPPTUN_GPEER:
	case PPPTUN_SDATA:
	case PPPTUN_GDATA:
	case PPPTUN_SCTL:
	case PPPTUN_GCTL:
	case PPPTUN_DCTL:
	case PPPTUN_SSAP:
		qwriter(q, mp, sppptun_inner_ioctl, PERIM_INNER);
		return;

	case PPPIO_GCLEAN:	/* always clean */
		val = RCV_B7_1 | RCV_B7_0 | RCV_ODDP | RCV_EVNP;
		len = sizeof (uint32_t);
		break;

	case PPPIO_GTYPE:	/* we look like an async driver. */
		val = PPPTYP_AHDLC;
		len = sizeof (uint32_t);
		break;

	case PPPIO_CFLAGS:	/* never compress headers */
		val = 0;
		len = sizeof (uint32_t);
		break;

		/* quietly ack PPP things we don't need to do. */
	case PPPIO_XFCS:
	case PPPIO_RFCS:
	case PPPIO_XACCM:
	case PPPIO_RACCM:
	case PPPIO_LASTMOD:
	case PPPIO_MUX:
	case I_PLINK:
	case I_PUNLINK:
	case I_LINK:
	case I_UNLINK:
		break;

	default:
		tll = (tunll_t *)q->q_ptr;
		if (!(tll->tll_flags & TLLF_NOTLOWER)) {
			/* module side; pass this through. */
			putnext(q, mp);
			return;
		}
		rc = EINVAL;
		break;
	}
	if (rc == 0 && len == sizeof (uint32_t)) {
		if (mp->b_cont != NULL)
			freemsg(mp->b_cont);
		mp->b_cont = allocb(sizeof (uint32_t), BPRI_HI);
		if (mp->b_cont == NULL) {
			rc = ENOSR;
		} else {
			*(uint32_t *)mp->b_cont->b_wptr = val;
			mp->b_cont->b_wptr += sizeof (uint32_t);
		}
	}
	if (rc == 0) {
		miocack(q, mp, len, 0);
	} else {
		miocnak(q, mp, 0, rc);
	}
}

/*
 * sppptun_inner_mctl()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Called by qwriter (via sppptun_uwput) as the result of receiving
 *    an M_CTL.  Called only on the client (driver) side.
 */
static void
sppptun_inner_mctl(queue_t *q, mblk_t *mp)
{
	int msglen;
	tuncl_t *tcl;

	tcl = q->q_ptr;

	if (!(tcl->tcl_flags & TCLF_ISCLIENT)) {
		freemsg(mp);
		return;
	}

	msglen = MBLKL(mp);
	switch (*mp->b_rptr) {
	case PPPCTL_UNIT:
		if (msglen == 2)
			tcl->tcl_unit = mp->b_rptr[1];
		else if (msglen == 8)
			tcl->tcl_unit = ((uint32_t *)mp->b_rptr)[1];
		break;
	}
	freemsg(mp);
}

/*
 * sppptun_uwput()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *	Regular output data and controls pass through here.
 */
static void
sppptun_uwput(queue_t *q, mblk_t *mp)
{
	queue_t *nextq;
	tuncl_t *tcl;

	ASSERT(q->q_ptr != NULL);

	switch (MTYPE(mp)) {
	case M_DATA:
	case M_PROTO:
	case M_PCPROTO:
		if (q->q_first == NULL &&
		    (nextq = sppptun_outpkt(q, &mp)) != NULL) {
			putnext(nextq, mp);
		} else if (mp != NULL && !putq(q, mp)) {
			freemsg(mp);
		}
		break;
	case M_IOCTL:
		sppptun_ioctl(q, mp);
		break;
	case M_CTL:
		qwriter(q, mp, sppptun_inner_mctl, PERIM_INNER);
		break;
	default:
		tcl = (tuncl_t *)q->q_ptr;
		/*
		 * If we're the driver, then discard unknown junk.
		 * Otherwise, if we're the module, then forward along.
		 */
		if (tcl->tcl_flags & TCLF_ISCLIENT)
			freemsg(mp);
		else
			putnext(q, mp);
		break;
	}
}

/*
 * Send a DLPI/TPI control message to the driver but make sure there
 * is only one outstanding message.  Uses tll_msg_pending to tell when
 * it must queue.  sppptun_urput calls message_done() when an ACK or a
 * NAK is received to process the next queued message.
 */
static void
message_send(tunll_t *tll, mblk_t *mp)
{
	mblk_t **mpp;

	if (tll->tll_msg_pending) {
		/* Must queue message. Tail insertion */
		mpp = &tll->tll_msg_deferred;
		while (*mpp != NULL)
			mpp = &((*mpp)->b_next);
		*mpp = mp;
		return;
	}
	tll->tll_msg_pending = 1;
	putnext(tll->tll_wq, mp);
}

/*
 * Called when an DLPI/TPI control message has been acked or nacked to
 * send down the next queued message (if any).
 */
static void
message_done(tunll_t *tll)
{
	mblk_t *mp;

	ASSERT(tll->tll_msg_pending);
	tll->tll_msg_pending = 0;
	mp = tll->tll_msg_deferred;
	if (mp != NULL) {
		tll->tll_msg_deferred = mp->b_next;
		mp->b_next = NULL;
		tll->tll_msg_pending = 1;
		putnext(tll->tll_wq, mp);
	}
}

/*
 * Send down queued "close" messages to lower stream.  These were
 * enqueued right after the stream was originally allocated, when the
 * tll_style was set by PPPTUN_SINFO.
 */
static int
tll_close_req(tunll_t *tll)
{
	mblk_t *mb, *mbnext;

	if ((mb = tll->tll_onclose) == NULL)
		tll->tll_flags |= TLLF_SHUTDOWN_DONE;
	else {
		tll->tll_onclose = NULL;
		while (mb != NULL) {
			mbnext = mb->b_next;
			mb->b_next = NULL;
			message_send(tll, mb);
			mb = mbnext;
		}
	}
	return (0);
}

/*
 * This function is called when a backenable occurs on the write side of a
 * lower stream.  It walks over the client streams, looking for ones that use
 * the given tunll_t lower stream.  Each client is then backenabled.
 */
static void
tclvm_backenable(void *arg, void *firstv, size_t numv)
{
	tunll_t *tll = arg;
	int minorn = (int)(uintptr_t)firstv;
	int minormax = minorn + numv;
	tuncl_t *tcl;
	queue_t *q;

	while (minorn < minormax) {
		tcl = tcl_slots[minorn - 1];
		if ((tcl->tcl_data_tll == tll ||
		    tcl->tcl_ctrl_tll == tll) &&
		    (q = tcl->tcl_rq) != NULL) {
			qenable(OTHERQ(q));
		}
		minorn++;
	}
}

/*
 * sppptun_uwsrv()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Upper write-side service procedure.  In addition to the usual
 *    STREAMS queue service handling, this routine also handles the
 *    transmission of the unbind/detach messages to the lower stream
 *    driver when a lower stream is being closed.  (See the use of
 *    qenable/qwait in sppptun_close().)
 */
static int
sppptun_uwsrv(queue_t *q)
{
	tuncl_t	*tcl;
	mblk_t *mp;
	queue_t *nextq;

	tcl = q->q_ptr;
	if (!(tcl->tcl_flags & TCLF_ISCLIENT)) {
		tunll_t *tll = (tunll_t *)tcl;

		if ((tll->tll_flags & (TLLF_CLOSING|TLLF_CLOSE_DONE)) ==
		    TLLF_CLOSING) {
			tll->tll_error = tll_close_req(tll);
			tll->tll_flags |= TLLF_CLOSE_DONE;
		} else {
			/*
			 * We've been enabled here because of a backenable on
			 * output flow control.  Backenable clients using this
			 * lower layer.
			 */
			vmem_walk(tcl_minor_arena, VMEM_ALLOC, tclvm_backenable,
			    tll);
		}
		return (0);
	}

	while ((mp = getq(q)) != NULL) {
		if ((nextq = sppptun_outpkt(q, &mp)) != NULL) {
			putnext(nextq, mp);
		} else if (mp != NULL) {
			(void) putbq(q, mp);
			break;
		}
	}
	return (0);
}

/*
 * sppptun_lwput()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Lower write-side put procedure.  Nothing should be sending
 *    packets down this stream.
 */
static void
sppptun_lwput(queue_t *q, mblk_t *mp)
{
	switch (MTYPE(mp)) {
	case M_PROTO:
		putnext(q, mp);
		break;
	default:
		freemsg(mp);
		break;
	}
}

/*
 * sppptun_lrput()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Lower read-side put procedure.  Nothing should arrive here.
 */
static void
sppptun_lrput(queue_t *q, mblk_t *mp)
{
	tuncl_t *tcl;

	switch (MTYPE(mp)) {
	case M_IOCTL:
		miocnak(q, mp, 0, EINVAL);
		return;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR) {
			flushq(q, FLUSHDATA);
		}
		if (*mp->b_rptr & FLUSHW) {
			*mp->b_rptr &= ~FLUSHR;
			qreply(q, mp);
		} else {
			freemsg(mp);
		}
		return;
	}
	/*
	 * Try to forward the message to the put procedure for the upper
	 * control stream for this lower stream. If there are already messages
	 * queued here, queue this one up to preserve message ordering.
	 */
	if ((tcl = (tuncl_t *)q->q_ptr) == NULL || tcl->tcl_rq == NULL) {
		freemsg(mp);
		return;
	}
	if (queclass(mp) == QPCTL ||
	    (q->q_first == NULL && canput(tcl->tcl_rq))) {
		put(tcl->tcl_rq, mp);
	} else {
		if (!putq(q, mp))
			freemsg(mp);
	}
}

/*
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 *    Handle non-data DLPI messages.  Used with PPPoE, which runs over
 *    Ethernet only.
 */
static void
urput_dlpi(queue_t *q, mblk_t *mp)
{
	int err;
	union DL_primitives *dlp = (union DL_primitives *)mp->b_rptr;
	tunll_t *tll = q->q_ptr;
	size_t mlen = MBLKL(mp);

	switch (dlp->dl_primitive) {
	case DL_UDERROR_IND:
		break;

	case DL_ERROR_ACK:
		if (mlen < DL_ERROR_ACK_SIZE)
			break;
		err = dlp->error_ack.dl_unix_errno ?
		    dlp->error_ack.dl_unix_errno : ENXIO;
		switch (dlp->error_ack.dl_error_primitive) {
		case DL_UNBIND_REQ:
			message_done(tll);
			break;
		case DL_DETACH_REQ:
			message_done(tll);
			tll->tll_error = err;
			tll->tll_flags |= TLLF_SHUTDOWN_DONE;
			break;
		case DL_PHYS_ADDR_REQ:
			message_done(tll);
			break;
		case DL_INFO_REQ:
		case DL_ATTACH_REQ:
		case DL_BIND_REQ:
			message_done(tll);
			tll->tll_error = err;
			break;
		}
		break;

	case DL_INFO_ACK:
		message_done(tll);
		break;

	case DL_BIND_ACK:
		message_done(tll);
		break;

	case DL_PHYS_ADDR_ACK:
		break;

	case DL_OK_ACK:
		if (mlen < DL_OK_ACK_SIZE)
			break;
		switch (dlp->ok_ack.dl_correct_primitive) {
		case DL_UNBIND_REQ:
			message_done(tll);
			break;
		case DL_DETACH_REQ:
			tll->tll_flags |= TLLF_SHUTDOWN_DONE;
			break;
		case DL_ATTACH_REQ:
			message_done(tll);
			break;
		}
		break;
	}
	freemsg(mp);
}

/* Search structure used with PPPoE only; see tclvm_pppoe_search(). */
struct poedat {
	uint_t sessid;
	tunll_t *tll;
	const void *srcaddr;
	int isdata;
	tuncl_t *tcl;
};

/*
 * This function is called by vmem_walk from within sppptun_recv.  It
 * iterates over a span of allocated minor node numbers to search for
 * the appropriate lower stream, session ID, and peer MAC address.
 *
 * (This is necessary due to a design flaw in the PPPoE protocol
 * itself.  The protocol assigns session IDs from the server side
 * only.  Both server and client use the same number.  Thus, if there
 * are multiple clients on a single host, there can be session ID
 * conflicts between servers and there's no way to detangle them
 * except by looking at the remote MAC address.)
 *
 * (This could have been handled by linking together sessions that
 * differ only in the remote MAC address.  This isn't done because it
 * would involve extra per-session storage and it's very unlikely that
 * PPPoE would be used this way.)
 */
static void
tclvm_pppoe_search(void *arg, void *firstv, size_t numv)
{
	struct poedat *poedat = (struct poedat *)arg;
	int minorn = (int)(uintptr_t)firstv;
	int minormax = minorn + numv;
	tuncl_t *tcl;

	if (poedat->tcl != NULL)
		return;
	while (minorn < minormax) {
		tcl = tcl_slots[minorn - 1];
		ASSERT(tcl != NULL);
		if (tcl->tcl_rsessid == poedat->sessid &&
		    ((!poedat->isdata && tcl->tcl_ctrl_tll == poedat->tll) ||
		    (poedat->isdata && tcl->tcl_data_tll == poedat->tll)) &&
		    bcmp(tcl->tcl_address.pta_pppoe.ptma_mac,
		    poedat->srcaddr,
		    sizeof (tcl->tcl_address.pta_pppoe.ptma_mac)) == 0) {
			poedat->tcl = tcl;
			break;
		}
		minorn++;
	}
}

/*
 * sppptun_recv()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Receive function called by sppptun_urput, which is called when
 *    the lower read-side put or service procedure sends a message
 *    upstream to the a device user (PPP).  It attempts to find an
 *    appropriate queue on the module above us (depending on what the
 *    associated upper stream for the protocol would be), and if not
 *    possible, it will find an upper control stream for the protocol.
 *    Returns a pointer to the upper queue_t, or NULL if the message
 *    has been discarded.
 *
 * About demultiplexing:
 *
 *	All four protocols (L2F, PPTP, L2TP, and PPPoE) support a
 *	locally assigned ID for demultiplexing incoming traffic.  For
 *	L2F, this is called the Client ID, for PPTP the Call ID, for
 *	L2TP the Session ID, and for PPPoE the SESSION_ID.  This is a
 *	16 bit number for all four protocols, and is used to directly
 *	index into a list of upper streams.  With the upper stream in
 *	hand, we verify that this is the right stream and deliver the
 *	data.
 *
 *	L2TP has a Tunnel ID, which represents a bundle of PPP
 *	sessions between the peers.  Because we always assign unique
 *	session ID numbers, we merely check that the given ID matches
 *	the assigned ID for the upper stream.
 *
 *	L2F has a Multiplex ID, which is unique per connection.  It
 *	does not have L2TP's concept of multiple-connections-within-
 *	a-tunnel.  The same checking is done.
 *
 *	PPPoE is a horribly broken protocol.  Only one ID is assigned
 *	per connection.  The client must somehow demultiplex based on
 *	an ID number assigned by the server.  It's not necessarily
 *	unique.  The search is done based on {ID,peerEthernet} (using
 *	tcl_rsessid) for all packet types except PADI and PADS.
 *
 *	Neither PPPoE nor PPTP supports additional ID numbers.
 *
 *	Both L2F and L2TP come in over UDP.  They are distinguished by
 *	looking at the GRE version field -- 001 for L2F and 010 for
 *	L2TP.
 */
static queue_t *
sppptun_recv(queue_t *q, mblk_t **mpp, const void *srcaddr)
{
	mblk_t *mp;
	tunll_t *tll;
	tuncl_t *tcl;
	int sessid;
	int remlen;
	int msglen;
	int isdata;
	int i;
	const uchar_t *ucp;
	const poep_t *poep;
	mblk_t *mnew;
	ppptun_atype *pap;

	mp = *mpp;

	tll = q->q_ptr;
	ASSERT(!(tll->tll_flags & TLLF_NOTLOWER));

	tcl = NULL;
	switch (tll->tll_style) {
	case PTS_PPPOE:
		/* Note that poep_t alignment is uint16_t */
		if ((!IS_P2ALIGNED(mp->b_rptr, sizeof (uint16_t)) ||
		    MBLKL(mp) < sizeof (poep_t)) &&
		    !pullupmsg(mp, sizeof (poep_t)))
			break;
		poep = (const poep_t *)mp->b_rptr;
		if (poep->poep_version_type != POE_VERSION)
			break;
		/*
		 * First, extract a session ID number.  All protocols have
		 * this.
		 */
		isdata = (poep->poep_code == POECODE_DATA);
		sessid = ntohs(poep->poep_session_id);
		remlen = sizeof (*poep);
		msglen = ntohs(poep->poep_length);
		i = poep->poep_code;
		if (i == POECODE_PADI || i == POECODE_PADR) {
			/* These go to the server daemon only. */
			tcl = tll->tll_defcl;
		} else if (i == POECODE_PADO || i == POECODE_PADS) {
			/*
			 * These go to a client only, and are demuxed
			 * by the Host-Uniq field (into which we stuff
			 * our local ID number when generating
			 * PADI/PADR).
			 */
			ucp = (const uchar_t *)(poep + 1);
			i = msglen;
			while (i > POET_HDRLEN) {
				if (POET_GET_TYPE(ucp) == POETT_END) {
					i = 0;
					break;
				}
				if (POET_GET_TYPE(ucp) == POETT_UNIQ &&
				    POET_GET_LENG(ucp) >= sizeof (uint32_t))
					break;
				i -= POET_GET_LENG(ucp) + POET_HDRLEN;
				ucp = POET_NEXT(ucp);
			}
			if (i >= POET_HDRLEN + 4)
				sessid = GETLONG(ucp + POET_HDRLEN);
			tcl = tcl_by_minor((minor_t)sessid);
		} else {
			/*
			 * Try minor number as session ID first, since
			 * it's used that way on server side.  It's
			 * not used that way on the client, though, so
			 * this might not work.  If this isn't the
			 * right one, then try the tll cache.  If
			 * neither is right, then search all open
			 * clients.  Did I mention that the PPPoE
			 * protocol is badly designed?
			 */
			tcl = tcl_by_minor((minor_t)sessid);
			if (tcl == NULL ||
			    (!isdata && tcl->tcl_ctrl_tll != tll) ||
			    (isdata && tcl->tcl_data_tll != tll) ||
			    sessid != tcl->tcl_rsessid ||
			    bcmp(srcaddr, tcl->tcl_address.pta_pppoe.ptma_mac,
			    sizeof (tcl->tcl_address.pta_pppoe.ptma_mac)) != 0)
				tcl = tll->tll_lastcl;
			if (tcl == NULL ||
			    (!isdata && tcl->tcl_ctrl_tll != tll) ||
			    (isdata && tcl->tcl_data_tll != tll) ||
			    sessid != tcl->tcl_rsessid ||
			    bcmp(srcaddr, tcl->tcl_address.pta_pppoe.ptma_mac,
			    sizeof (tcl->tcl_address.pta_pppoe.ptma_mac)) != 0)
				tcl = NULL;
			if (tcl == NULL && sessid != 0) {
				struct poedat poedat;

				/*
				 * Slow mode.  Too bad.  If you don't like it,
				 * you can always choose a better protocol.
				 */
				poedat.sessid = sessid;
				poedat.tll = tll;
				poedat.srcaddr = srcaddr;
				poedat.tcl = NULL;
				poedat.isdata = isdata;
				vmem_walk(tcl_minor_arena, VMEM_ALLOC,
				    tclvm_pppoe_search, &poedat);
				KLINCR(lks_walks);
				if ((tcl = poedat.tcl) != NULL) {
					tll->tll_lastcl = tcl;
					KCINCR(cks_walks);
				}
			}
		}
		break;
	}

	if (tcl == NULL || tcl->tcl_rq == NULL) {
		DTRACE_PROBE3(sppptun__recv__discard, int, sessid,
		    tuncl_t *, tcl, mblk_t *, mp);
		if (tcl == NULL) {
			KLINCR(lks_in_nomatch);
		}
		if (isdata) {
			KLINCR(lks_indata_drops);
			if (tcl != NULL)
				tcl->tcl_stats.ppp_ierrors++;
		} else {
			KLINCR(lks_inctrl_drops);
			if (tcl != NULL) {
				KCINCR(cks_inctrl_drops);
			}
		}
		freemsg(mp);
		return (NULL);
	}

	if (tcl->tcl_data_tll == tll && isdata) {
		if (!adjmsg(mp, remlen) ||
		    (i = msgsize(mp)) < msglen ||
		    (i > msglen && !adjmsg(mp, msglen - i))) {
			KLINCR(lks_indata_drops);
			tcl->tcl_stats.ppp_ierrors++;
			freemsg(mp);
			return (NULL);
		}
		/* XXX -- address/control handling in pppd needs help. */
		if (*mp->b_rptr != 0xFF) {
			if ((mp = prependb(mp, 2, 1)) == NULL) {
				KLINCR(lks_indata_drops);
				tcl->tcl_stats.ppp_ierrors++;
				return (NULL);
			}
			mp->b_rptr[0] = 0xFF;
			mp->b_rptr[1] = 0x03;
		}
		MTYPE(mp) = M_DATA;
		tcl->tcl_stats.ppp_ibytes += msgsize(mp);
		tcl->tcl_stats.ppp_ipackets++;
		KLINCR(lks_indata);
	} else {
		if (isdata || tcl->tcl_ctrl_tll != tll ||
		    (mnew = make_control(tcl, tll, PTCA_CONTROL, tcl)) ==
		    NULL) {
			KLINCR(lks_inctrl_drops);
			KCINCR(cks_inctrl_drops);
			freemsg(mp);
			return (NULL);
		}
		/* Fix up source address; peer might not be set yet. */
		pap = &((struct ppptun_control *)mnew->b_rptr)->ptc_address;
		bcopy(srcaddr, pap->pta_pppoe.ptma_mac,
		    sizeof (pap->pta_pppoe.ptma_mac));
		mnew->b_cont = mp;
		mp = mnew;
		KLINCR(lks_inctrls);
		KCINCR(cks_inctrls);
	}
	*mpp = mp;
	return (tcl->tcl_rq);
}

/*
 * sppptun_urput()
 *
 * MT-Perimeters:
 *    shared inner, shared outer.
 *
 * Description:
 *    Upper read-side put procedure.  Messages from the underlying
 *    lower stream driver arrive here.  See sppptun_recv for the
 *    demultiplexing logic.
 */
static void
sppptun_urput(queue_t *q, mblk_t *mp)
{
	union DL_primitives *dlprim;
	mblk_t *mpnext;
	tunll_t *tll;
	queue_t *nextq;

	tll = q->q_ptr;
	ASSERT(!(tll->tll_flags & TLLF_NOTLOWER));

	switch (MTYPE(mp)) {
	case M_DATA:
		/*
		 * When we're bound over IP, data arrives here.  The
		 * packet starts with the IP header itself.
		 */
		if ((nextq = sppptun_recv(q, &mp, NULL)) != NULL)
			putnext(nextq, mp);
		break;

	case M_PROTO:
	case M_PCPROTO:
		/* Data arrives here for UDP or raw Ethernet, not IP. */
		switch (tll->tll_style) {
			/* PPTP control messages are over TCP only. */
		case PTS_PPTP:
		default:
			ASSERT(0);	/* how'd that happen? */
			break;

		case PTS_PPPOE:		/* DLPI message */
			if (MBLKL(mp) < sizeof (t_uscalar_t))
				break;
			dlprim = (union DL_primitives *)mp->b_rptr;
			switch (dlprim->dl_primitive) {
			case DL_UNITDATA_IND: {
				size_t mlen = MBLKL(mp);

				if (mlen < DL_UNITDATA_IND_SIZE)
					break;
				if (dlprim->unitdata_ind.dl_src_addr_offset <
				    DL_UNITDATA_IND_SIZE ||
				    dlprim->unitdata_ind.dl_src_addr_offset +
				    dlprim->unitdata_ind.dl_src_addr_length >
				    mlen)
					break;
			}
				/* FALLTHROUGH */
			case DL_UNITDATA_REQ:	/* For loopback support. */
				if (dlprim->dl_primitive == DL_UNITDATA_REQ &&
				    MBLKL(mp) < DL_UNITDATA_REQ_SIZE)
					break;
				if ((mpnext = mp->b_cont) == NULL)
					break;
				MTYPE(mpnext) = M_DATA;
				nextq = sppptun_recv(q, &mpnext,
				    dlprim->dl_primitive == DL_UNITDATA_IND ?
				    mp->b_rptr +
				    dlprim->unitdata_ind.dl_src_addr_offset :
				    tll->tll_lcladdr.pta_pppoe.ptma_mac);
				if (nextq != NULL)
					putnext(nextq, mpnext);
				freeb(mp);
				return;

			default:
				urput_dlpi(q, mp);
				return;
			}
			break;
		}
		freemsg(mp);
		break;

	default:
		freemsg(mp);
		break;
	}
}

/*
 * sppptun_ursrv()
 *
 * MT-Perimeters:
 *    exclusive inner, shared outer.
 *
 * Description:
 *    Upper read-side service procedure.  This procedure services the
 *    client streams.  We get here because the client (PPP) asserts
 *    flow control down to us.
 */
static int
sppptun_ursrv(queue_t *q)
{
	mblk_t		*mp;

	ASSERT(q->q_ptr != NULL);

	while ((mp = getq(q)) != NULL) {
		if (canputnext(q)) {
			putnext(q, mp);
		} else {
			(void) putbq(q, mp);
			break;
		}
	}
	return (0);
}

/*
 * Dummy constructor/destructor functions for kmem_cache_create.
 * We're just using kmem as an allocator of integers, not real
 * storage.
 */

/*ARGSUSED*/
static int
tcl_constructor(void *maddr, void *arg, int kmflags)
{
	return (0);
}

/*ARGSUSED*/
static void
tcl_destructor(void *maddr, void *arg)
{
}

/*
 * Total size occupied by one tunnel client.  Each tunnel client
 * consumes one pointer for tcl_slots array, one tuncl_t structure and
 * two messages preallocated for close.
 */
#define	TUNCL_SIZE (sizeof (tuncl_t) + sizeof (tuncl_t *) + \
			2 * sizeof (dblk_t))

/*
 * Clear all bits of x except the highest bit
 */
#define	truncate(x) 	((x) <= 2 ? (x) : (1 << (highbit(x) - 1)))

/*
 * This function initializes some well-known global variables inside
 * the module.
 *
 * Called by sppptun_mod.c:_init() before installing the module.
 */
void
sppptun_init(void)
{
	tunll_list.q_forw = tunll_list.q_back = &tunll_list;
}

/*
 * This function allocates the initial internal storage for the
 * sppptun driver.
 *
 * Called by sppptun_mod.c:_init() after installing module.
 */
void
sppptun_tcl_init(void)
{
	uint_t i, j;

	rw_init(&tcl_rwlock, NULL, RW_DRIVER, NULL);
	rw_enter(&tcl_rwlock, RW_WRITER);
	tcl_nslots = sppptun_init_cnt;
	tcl_slots = kmem_zalloc(tcl_nslots * sizeof (tuncl_t *), KM_SLEEP);

	tcl_cache = kmem_cache_create("sppptun_map", sizeof (tuncl_t), 0,
	    tcl_constructor, tcl_destructor, NULL, NULL, NULL, 0);

	/* Allocate integer space for minor numbers */
	tcl_minor_arena = vmem_create("sppptun_minor", (void *)1, tcl_nslots,
	    1, NULL, NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);

	/*
	 * Calculate available number of tunnels - how many tunnels
	 * can we allocate in sppptun_pctofmem % of available
	 * memory.  The value is rounded up to the nearest power of 2.
	 */
	i = (sppptun_pctofmem * kmem_maxavail()) / (100 * TUNCL_SIZE);
	j = truncate(i);	/* i with non-high bits stripped */
	if (i != j)
		j *= 2;
	tcl_minormax = j;
	rw_exit(&tcl_rwlock);
}

/*
 * This function checks that there are no plumbed streams or other users.
 *
 * Called by sppptun_mod.c:_fini().  Assumes that we're exclusive on
 * both perimeters.
 */
int
sppptun_tcl_fintest(void)
{
	if (tunll_list.q_forw != &tunll_list || tcl_inuse > 0)
		return (EBUSY);
	else
		return (0);
}

/*
 * If no lower streams are plumbed, then this function deallocates all
 * internal storage in preparation for unload.
 *
 * Called by sppptun_mod.c:_fini().  Assumes that we're exclusive on
 * both perimeters.
 */
void
sppptun_tcl_fini(void)
{
	if (tcl_minor_arena != NULL) {
		vmem_destroy(tcl_minor_arena);
		tcl_minor_arena = NULL;
	}
	if (tcl_cache != NULL) {
		kmem_cache_destroy(tcl_cache);
		tcl_cache = NULL;
	}
	kmem_free(tcl_slots, tcl_nslots * sizeof (tuncl_t *));
	tcl_slots = NULL;
	rw_destroy(&tcl_rwlock);
	ASSERT(tcl_slots == NULL);
	ASSERT(tcl_cache == NULL);
	ASSERT(tcl_minor_arena == NULL);
}
