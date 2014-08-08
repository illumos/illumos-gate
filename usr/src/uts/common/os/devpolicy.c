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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Device policy implementation.
 *
 * Maintains the device policy table and defines the lookup functions.
 *
 * The table contains one entry for each major device number; each
 * major bucket has a list of minor number specific entries.  First
 * match gets it.  Not even simple minor names are expanded as that
 * would cause the device to be loaded.  Non-wildcard entries are expanded
 * on first match. Wildcard entries are matched each open but the actual
 * policy is cached with the common snode, so the matching code will
 * probably be called infrequently.  The trivial wildcard ``*'' does
 * not cause expensive string expansions and matches.
 *
 * When the policy is updated, the the generation count is increased;
 * whenever a cached policy is used, the generation count is compared;
 * if there's no match, the device policy is refreshed.
 *
 * The special policy "nullpolicy" is used to mean "no checking beyond DAC
 * needed".  It too will change when the policy is rev'ed to make sure
 * that devices with nullpolicy are also refreshed.
 *
 * The special policy "dfltpolicy" is used for those devices with no
 * matching policy.  On boot, it is "all privileges required".
 * This restriction on boot functions as a fail-safe; if no device policy
 * is loaded a "no restriction policy" would lead to security problems that
 * are not immediately noticable.
 */

#include <sys/priv_impl.h>
#include <sys/policy.h>
#include <sys/atomic.h>
#include <sys/autoconf.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/devpolicy.h>
#include <sys/priv.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/errno.h>
#include <sys/sunddi.h>
#include <c2/audit.h>
#include <sys/fs/dv_node.h>

/*
 * Internal data structures definitions.
 */

typedef struct devplcyent devplcyent_t;

/*
 * The device policy entry; if there is an expression string, the
 * minor numbers are not relevant.  This is indicated by dpe_len > 0.
 */
struct devplcyent {
	devplcyent_t	*dpe_next;	/* next entry in this list */
	devplcy_t	*dpe_plcy;	/* policy for this entry */
	char		*dpe_expr;	/* expression matching minor mode */
	int		dpe_len;	/* size of allocated mem for expr */
	uint32_t	dpe_flags;	/* flags */
	minor_t		dpe_lomin;	/* expanded: low minor number */
	minor_t		dpe_himin;	/* expanded: high minor number */
	vtype_t		dpe_spec;	/* expanded: VBLK or VCHR */
};

#define	DPE_WILDC	0x01		/* Expression has wildcard */
#define	DPE_ALLMINOR	0x02		/* Matches all minor numbers */
#define	DPE_EXPANDED	0x04		/* Minor numbers expanded */

typedef struct tableent {
	devplcyent_t	*t_ent;		/* list of policies by minor */
	major_t		t_major;	/* device major number */
} tableent_t;

/*
 * The data store.
 */

static int ntabent;		/* # of major numbers */
static int totitems;		/* Number of entries in all buckets + dflt */
static tableent_t *devpolicy;	/* The device policy itself */

static krwlock_t policyrw;	/* protects the table */
static kmutex_t policymutex;	/* allows only one concurrent devpolicy_load */

devplcy_t *nullpolicy;		/* public because it's used for shortcuts */
static devplcy_t *dfltpolicy;
static devplcy_t *netpolicy;

/*
 * Device policy generation count; only device policies matching the
 * generation count are still valid.
 */
volatile uint32_t devplcy_gen;

/*
 * Tunable: maximum number of device policy entries to load in
 * a system call.  (Protects KM_SLEEP call)
 */
int maxdevpolicy = MAXDEVPOLICY;

/*
 * Initialize the device policy code
 */
void
devpolicy_init(void)
{
	rw_init(&policyrw, NULL, RW_DRIVER, NULL);
	mutex_init(&policymutex, NULL, MUTEX_DRIVER, NULL);

	/* The mutex is held here in order to satisfy the ASSERT in dpget() */
	mutex_enter(&policymutex);

	nullpolicy = dpget();
	dfltpolicy = dpget();
	netpolicy = dpget();

	/*
	 * Initially, we refuse access to all devices except
	 * to processes with all privileges.
	 */
	priv_fillset(&dfltpolicy->dp_rdp);
	priv_fillset(&dfltpolicy->dp_wrp);

	totitems = 1;

	devplcy_gen++;
	mutex_exit(&policymutex);

	/* initialize default network privilege */
	priv_emptyset(&netpolicy->dp_rdp);
	priv_emptyset(&netpolicy->dp_wrp);
	priv_addset(&netpolicy->dp_rdp, PRIV_NET_RAWACCESS);
	priv_addset(&netpolicy->dp_wrp, PRIV_NET_RAWACCESS);
}

/*
 * Devpolicy reference counting/allocation routines.
 * cf. crget()/crhold()/crfree().
 */
devplcy_t *
dpget(void)
{
	devplcy_t *dp = kmem_zalloc(sizeof (*dp), KM_SLEEP);

	ASSERT(MUTEX_HELD(&policymutex));

	dp->dp_ref = 1;
	/* New ones belong to the next generation */
	dp->dp_gen = devplcy_gen + 1;
	return (dp);
}

void
dphold(devplcy_t *dp)
{
	ASSERT(dp->dp_ref != 0xdeadbeef && dp->dp_ref != 0);
	atomic_inc_32(&dp->dp_ref);
}

void
dpfree(devplcy_t *dp)
{
	ASSERT(dp->dp_ref != 0xdeadbeef && dp->dp_ref != 0);
	if (atomic_dec_32_nv(&dp->dp_ref) == 0)
		kmem_free(dp, sizeof (*dp));
}

/*
 * Find the policy that matches this device.
 */
static devplcy_t *
match_policy(devplcyent_t *de, dev_t dev, vtype_t spec)
{
	char *mname = NULL;
	minor_t min = getminor(dev);

	for (; de != NULL; de = de->dpe_next) {
		if (de->dpe_flags & DPE_ALLMINOR)
			break;

		if (de->dpe_flags & DPE_EXPANDED) {
			if (min >= de->dpe_lomin && min <= de->dpe_himin &&
			    spec == de->dpe_spec) {
				break;
			} else {
				continue;
			}
		}

		/*
		 * We now need the minor name to match string or
		 * simle regexp.  Could we use csp->s_dip and not
		 * allocate a string here?
		 */
		if (mname == NULL &&
		    ddi_lyr_get_minor_name(dev, spec, &mname) != DDI_SUCCESS)
			/* mname can be set after the function fails */
			return (dfltpolicy);

		/* Simple wildcard, with only one ``*'' */
		if (de->dpe_flags & DPE_WILDC) {
			int plen = de->dpe_len - 1;
			int slen = strlen(mname);
			char *pp = de->dpe_expr;
			char *sp = mname;

			/* string must be at least as long as pattern w/o '*' */
			if (slen < plen - 1)
				continue;

			/* skip prefix */
			while (*pp == *sp && *pp != '\0') {
				pp++;
				sp++;
			}
			/* matched single '*' */
			if (*pp == '\0')
				if (*sp == '\0')
					break;
				else
					continue;
			if (*pp != '*')
				continue;

			pp++;
			/*
			 * skip characters matched by '*': difference of
			 * length of s and length of pattern sans '*'
			 */
			sp += slen - (plen - 1);
			if (strcmp(pp, sp) == 0) 	/* match! */
				break;

		} else if (strcmp(de->dpe_expr, mname) == 0) {
			/* Store minor number, if no contention */
			if (rw_tryupgrade(&policyrw)) {
				de->dpe_lomin = de->dpe_himin = min;
				de->dpe_spec = spec;
				de->dpe_flags |= DPE_EXPANDED;
			}
			break;
		}

	}

	if (mname != NULL)
		kmem_free(mname, strlen(mname) + 1);

	return (de != NULL ? de->dpe_plcy : dfltpolicy);
}

static int
devpolicyent_bymajor(major_t maj)
{
	int lo, hi;

	ASSERT(RW_LOCK_HELD(&policyrw));

	lo = 0;
	hi = ntabent - 1;

	/* Binary search for major number */
	while (lo <= hi) {
		int mid = (lo + hi) / 2;

		if (devpolicy[mid].t_major == maj)
			return (mid);
		else if (maj < devpolicy[mid].t_major)
			hi = mid - 1;
		else
			lo = mid + 1;
	}
	return (-1);
}

/*
 * Returns held device policy for the specific device node.
 * Note devfs_devpolicy returns with a hold on the policy.
 */
devplcy_t *
devpolicy_find(vnode_t *vp)
{
	dev_t dev = vp->v_rdev;
	vtype_t spec = vp->v_type;
	major_t maj = getmajor(dev);
	int i;
	devplcy_t *res;

	if (maj == clone_major)
		maj = getminor(dev);

	rw_enter(&policyrw, RW_READER);

	i = devpolicyent_bymajor(maj);

	if (i != -1) {
		res = match_policy(devpolicy[i].t_ent, dev, spec);
		dphold(res);
	} else if (devfs_devpolicy(vp, &res) != 0) {
		res = NETWORK_DRV(maj) ? netpolicy : dfltpolicy;
		dphold(res);
	}

	rw_exit(&policyrw);

	return (res);
}

static devplcyent_t *
parse_policy(devplcysys_t *ds, devplcy_t *nullp, devplcy_t *defp)
{
	devplcyent_t *de = kmem_zalloc(sizeof (*de), KM_SLEEP);
	devplcy_t *np;

	if (priv_isemptyset(&ds->dps_rdp) && priv_isemptyset(&ds->dps_wrp))
		dphold(np = nullp);
	else if (defp != nullp &&
	    priv_isequalset(&ds->dps_rdp, &defp->dp_rdp) &&
	    priv_isequalset(&ds->dps_wrp, &defp->dp_wrp))
		dphold(np = defp);
	else {
		np = dpget();
		np->dp_rdp = ds->dps_rdp;
		np->dp_wrp = ds->dps_wrp;
	}

	if (ds->dps_minornm[0] != '\0') {
		de->dpe_len = strlen(ds->dps_minornm) + 1;

		if (strchr(ds->dps_minornm, '*') != NULL) {
			if (de->dpe_len == 2) {		/* "*\0" */
				de->dpe_flags = DPE_ALLMINOR;
				de->dpe_len = 0;
			} else
				de->dpe_flags = DPE_WILDC;
		}
		if (de->dpe_len != 0) {
			de->dpe_expr = kmem_alloc(de->dpe_len, KM_SLEEP);
			(void) strcpy(de->dpe_expr, ds->dps_minornm);
		}
	} else {
		de->dpe_lomin = ds->dps_lomin;
		de->dpe_himin = ds->dps_himin;
		de->dpe_flags = DPE_EXPANDED;
		de->dpe_spec = ds->dps_isblock ? VBLK : VCHR;
	}
	de->dpe_plcy = np;

	ASSERT((de->dpe_flags & (DPE_ALLMINOR|DPE_EXPANDED)) ||
	    de->dpe_expr != NULL);

	return (de);
}

static void
freechain(devplcyent_t *de)
{
	devplcyent_t *dn;

	do {
		dn = de->dpe_next;
		dpfree(de->dpe_plcy);
		if (de->dpe_len != 0)
			kmem_free(de->dpe_expr, de->dpe_len);
		kmem_free(de, sizeof (*de));
		de = dn;
	} while (de != NULL);
}

/*
 * Load the device policy.
 * The device policy currently makes nu distinction between the
 * block and characters devices; that is generally not a problem
 * as the names of those devices cannot clash.
 */
int
devpolicy_load(int nitems, size_t sz, devplcysys_t *uitmp)
{
	int i, j;
	int nmaj = 0;
	major_t lastmajor;
	devplcysys_t *items;
	size_t mem;
	major_t curmaj;
	devplcyent_t **last, *de;

	tableent_t *newpolicy, *oldpolicy;
	devplcy_t *newnull, *newdflt, *oldnull, *olddflt;
	int oldcnt;
	int lastlen;
	int lastwild;

#ifdef lint
	/* Lint can't figure out that the "i == 1" test protects all */
	lastlen = 0;
	lastwild = 0;
	lastmajor = 0;
#endif
	/*
	 * The application must agree with the kernel on the size of each
	 * item; it must not exceed the maximum number and must be
	 * at least 1 item in size.
	 */
	if (sz != sizeof (devplcysys_t) || nitems > maxdevpolicy || nitems < 1)
		return (EINVAL);

	mem = nitems * sz;

	items = kmem_alloc(mem, KM_SLEEP);

	if (copyin(uitmp, items, mem)) {
		kmem_free(items, mem);
		return (EFAULT);
	}

	/* Check for default policy, it must exist and be sorted first */
	if (items[0].dps_maj != DEVPOLICY_DFLT_MAJ) {
		kmem_free(items, mem);
		return (EINVAL);
	}

	/*
	 * Application must deliver entries sorted.
	 * Sorted meaning here:
	 *	In major number order
	 *	For each major number, we first need to have the explicit
	 *	entries, then the wild card entries, longest first.
	 */
	for (i = 1; i < nitems; i++) {
		int len, wild;
		char *tmp;

		curmaj = items[i].dps_maj;
		len = strlen(items[i].dps_minornm);
		wild = len > 0 &&
		    (tmp = strchr(items[i].dps_minornm, '*')) != NULL;

		/* Another default major, string too long or too many ``*'' */
		if (curmaj == DEVPOLICY_DFLT_MAJ ||
		    len >= sizeof (items[i].dps_minornm) ||
		    wild && strchr(tmp + 1, '*') != NULL) {
			kmem_free(items, mem);
			return (EINVAL);
		}
		if (i == 1 || lastmajor < curmaj) {
			lastmajor = curmaj;
			nmaj++;
		} else if (lastmajor > curmaj || lastwild > wild ||
		    lastwild && lastlen < len) {
			kmem_free(items, mem);
			return (EINVAL);
		}
		lastlen = len;
		lastwild = wild;
	}

	if (AU_AUDITING())
		audit_devpolicy(nitems, items);

	/*
	 * Parse the policy.  We create an array for all major numbers
	 * and in each major number bucket we'll have a linked list of
	 * entries.  Each item may contain either a lo,hi minor pair
	 * or a string/wild card matching a minor node.
	 */
	if (nmaj > 0)
		newpolicy = kmem_zalloc(nmaj * sizeof (tableent_t), KM_SLEEP);

	/*
	 * We want to lock out concurrent updates but we don't want to
	 * lock out device opens while we still need to allocate memory.
	 * As soon as we allocate new devplcy_t's we commit to the next
	 * generation number, so we must lock out other updates from here.
	 */
	mutex_enter(&policymutex);

	/* New default and NULL policy */
	newnull = dpget();

	if (priv_isemptyset(&items[0].dps_rdp) &&
	    priv_isemptyset(&items[0].dps_wrp)) {
		newdflt = newnull;
		dphold(newdflt);
	} else {
		newdflt = dpget();
		newdflt->dp_rdp = items[0].dps_rdp;
		newdflt->dp_wrp = items[0].dps_wrp;
	}

	j = -1;

	/* Userland made sure sorting was ok */
	for (i = 1; i < nitems; i++) {
		de = parse_policy(&items[i], newnull, newdflt);

		if (j == -1 || curmaj != items[i].dps_maj) {
			j++;
			newpolicy[j].t_major = curmaj = items[i].dps_maj;
			last = &newpolicy[j].t_ent;
		}
		*last = de;
		last = &de->dpe_next;
	}

	/* Done parsing, throw away input */
	kmem_free(items, mem);

	/* Lock out all devpolicy_find()s */
	rw_enter(&policyrw, RW_WRITER);

	/* Install the new global data */
	oldnull = nullpolicy;
	nullpolicy = newnull;

	olddflt = dfltpolicy;
	dfltpolicy = newdflt;

	oldcnt = ntabent;
	ntabent = nmaj;

	totitems = nitems;

	oldpolicy = devpolicy;
	devpolicy = newpolicy;

	/* Force all calls by devpolicy_find() */
	devplcy_gen++;

	/* Reenable policy finds */
	rw_exit(&policyrw);
	mutex_exit(&policymutex);

	/* Free old stuff */
	if (oldcnt != 0) {
		for (i = 0; i < oldcnt; i++)
			freechain(oldpolicy[i].t_ent);
		kmem_free(oldpolicy, oldcnt * sizeof (*oldpolicy));
	}

	dpfree(oldnull);
	dpfree(olddflt);

	return (0);
}

/*
 * Get device policy: argument one is a pointer to an integer holding
 * the number of items allocated for the 3rd argument; the size argument
 * is a revision check between kernel and userland.
 */
int
devpolicy_get(int *nitemp, size_t sz, devplcysys_t *uitmp)
{
	int i;
	devplcyent_t *de;
	devplcysys_t *itmp;
	int ind;
	int nitems;
	int err = 0;
	size_t alloced;

	if (sz != sizeof (devplcysys_t))
		return (EINVAL);

	if (copyin(nitemp, &nitems, sizeof (nitems)))
		return (EFAULT);

	rw_enter(&policyrw, RW_READER);

	if (copyout(&totitems, nitemp, sizeof (totitems)))
		err = EFAULT;
	else if (nitems < totitems)
		err = ENOMEM;

	if (err != 0) {
		rw_exit(&policyrw);
		return (err);
	}

	alloced = totitems * sizeof (devplcysys_t);
	itmp = kmem_zalloc(alloced, KM_SLEEP);

	itmp[0].dps_rdp = dfltpolicy->dp_rdp;
	itmp[0].dps_wrp = dfltpolicy->dp_wrp;
	itmp[0].dps_maj = DEVPOLICY_DFLT_MAJ;

	ind = 1;

	for (i = 0; i < ntabent; i++) {
		for (de = devpolicy[i].t_ent; de != NULL; de = de->dpe_next) {
			itmp[ind].dps_maj = devpolicy[i].t_major;
			itmp[ind].dps_rdp = de->dpe_plcy->dp_rdp;
			itmp[ind].dps_wrp = de->dpe_plcy->dp_wrp;
			if (de->dpe_len)
				(void) strcpy(itmp[ind].dps_minornm,
				    de->dpe_expr);
			else if (de->dpe_flags & DPE_ALLMINOR)
				(void) strcpy(itmp[ind].dps_minornm, "*");
			else {
				itmp[ind].dps_lomin = de->dpe_lomin;
				itmp[ind].dps_himin = de->dpe_himin;
				itmp[ind].dps_isblock = de->dpe_spec == VBLK;
			}
			ind++;
		}
	}

	rw_exit(&policyrw);

	if (copyout(itmp, uitmp, alloced))
		err = EFAULT;

	kmem_free(itmp, alloced);
	return (err);
}

/*
 * Get device policy by device name.
 * This is the implementation of MODGETDEVPOLICYBYNAME
 */
int
devpolicy_getbyname(size_t sz, devplcysys_t *uitmp, char *devname)
{
	devplcysys_t itm;
	devplcy_t *plcy;
	vtype_t spec;
	vnode_t *vp;

	if (sz != sizeof (devplcysys_t))
		return (EINVAL);

	if (lookupname(devname, UIO_USERSPACE, FOLLOW,
	    NULLVPP, &vp) != 0)
		return (EINVAL);

	spec = vp->v_type;
	if (spec != VBLK && spec != VCHR) {
		VN_RELE(vp);
		return (EINVAL);
	}

	plcy = devpolicy_find(vp);
	VN_RELE(vp);

	bzero(&itm, sizeof (itm));

	/* These are the only values of interest */
	itm.dps_rdp = plcy->dp_rdp;
	itm.dps_wrp = plcy->dp_wrp;

	dpfree(plcy);

	if (copyout(&itm, uitmp, sz))
		return (EFAULT);
	else
		return (0);
}

static void
priv_str_to_set(const char *priv_name, priv_set_t *priv_set)
{
	if (priv_name == NULL || strcmp(priv_name, "none") == 0) {
		priv_emptyset(priv_set);
	} else if (strcmp(priv_name, "all") == 0) {
		priv_fillset(priv_set);
	} else {
		int priv;
		priv = priv_getbyname(priv_name, PRIV_ALLOC);
		if (priv < 0) {
			cmn_err(CE_WARN, "fail to allocate privilege: %s",
			    priv_name);
			return;
		}
		priv_emptyset(priv_set);
		priv_addset(priv_set, priv);
	}
}

/*
 * Return device privileges by privilege name
 * Called by ddi_create_priv_minor_node()
 */
devplcy_t *
devpolicy_priv_by_name(const char *read_priv, const char *write_priv)
{
	devplcy_t *dp;
	mutex_enter(&policymutex);
	dp = dpget();
	mutex_exit(&policymutex);
	priv_str_to_set(read_priv, &dp->dp_rdp);
	priv_str_to_set(write_priv, &dp->dp_wrp);

	return (dp);
}
