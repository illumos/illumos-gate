/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*
 * ipfilter kernel module mutexes and locking:
 *
 * Enabling ipfilter creates a per-netstack ipf_stack_t object that is
 * stored in the ipf_stacks list, which is protected by ipf_stack_lock.
 * ipf_stack_t objects are accessed in three contexts:
 *
 * 1) administering that filter (eg: ioctls handled with iplioctl())
 * 2) reading log data (eg: iplread() / iplwrite())
 * 3) filtering packets (eg: ipf_hook4_* and ipf_hook6_* pfhooks
 *    functions)
 *
 * Each ipf_stack_t has a RW lock, ifs_ipf_global, protecting access to the
 * whole structure. The structure also has locks protecting the various
 * data structures used for filtering. The following guidelines should be
 * followed for ipf_stack_t locks:
 *
 * - ipf_stack_lock must be held when accessing the ipf_stacks list
 * - ipf_stack_lock should be held before acquiring ifs_ipf_global for
 *   a stack (the exception to this is ipf_stack_destroy(), which removes
 *   the ipf_stack_t from the list, then drops ipf_stack_lock before
 *   acquiring ifs_ipf_global)
 * - ifs_ipf_global must be held when accessing an ipf_stack_t in that list:
 *   - The write lock is held only during stack creation / destruction
 *   - The read lock should be held for all other accesses
 * - To alter the filtering data in the administrative context, one must:
 *   - acquire the read lock for ifs_ipf_global
 *   - then acquire the write lock for the data in question
 * - In the filtering path, the read lock needs to be held for each type of
 *   filtering data used
 * - ifs_ipf_global does not need to be held in the filtering path:
 *   - The filtering hooks don't need to modify the stack itself
 *   - The ipf_stack_t will not be destroyed until the hooks are unregistered.
 *     This requires a write lock on the hook, ensuring that no active hooks
 *     (eg: the filtering path) are running, and that the hooks won't be run
 *     afterward.
 *
 * Note that there is a deadlock possible when calling net_hook_register()
 * or net_hook_unregister() with ifs_ipf_global held: see the comments in
 * iplattach() and ipldetach() for details.
 */

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/poll.h>
#include <sys/autoconf.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/kstat.h>
#include <sys/sockio.h>
#include <sys/neti.h>
#include <sys/hook.h>
#include <net/if.h>
#if SOLARIS2 >= 6
#include <net/if_types.h>
#endif
#include <net/af.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/tcpip.h>
#include <netinet/ip_icmp.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include "netinet/ip_compat.h"
#include "netinet/ipl.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_auth.h"
#include "netinet/ip_state.h"
#include "netinet/ipf_stack.h"

extern	int	iplwrite __P((dev_t, struct uio *, cred_t *));

static	int	ipf_getinfo __P((dev_info_t *, ddi_info_cmd_t,
		    void *, void **));
#if SOLARIS2 < 10
static	int	ipf_identify __P((dev_info_t *));
#endif
static	int	ipf_attach __P((dev_info_t *, ddi_attach_cmd_t));
static	int	ipf_detach __P((dev_info_t *, ddi_detach_cmd_t));
static	void	*ipf_stack_create __P((const netid_t));
static	void	ipf_stack_destroy __P((const netid_t, void *));
static	void	ipf_stack_shutdown __P((const netid_t, void *));
static	int	ipf_property_g_update __P((dev_info_t *));
static	char	*ipf_devfiles[] = { IPL_NAME, IPNAT_NAME, IPSTATE_NAME,
				    IPAUTH_NAME, IPSYNC_NAME, IPSCAN_NAME,
				    IPLOOKUP_NAME, NULL };
extern void 	*ipf_state;	/* DDI state */
extern vmem_t	*ipf_minor;	/* minor number arena */

static struct cb_ops ipf_cb_ops = {
	iplopen,
	iplclose,
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	iplread,
	iplwrite,	/* write */
	iplioctl,	/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_MTSAFE,
#if SOLARIS2 > 4
	CB_REV,
	nodev,		/* aread */
	nodev,		/* awrite */
#endif
};

static struct dev_ops ipf_ops = {
	DEVO_REV,
	0,
	ipf_getinfo,
#if SOLARIS2 >= 10
	nulldev,
#else
	ipf_identify,
#endif
	nulldev,
	ipf_attach,
	ipf_detach,
	nodev,		/* reset */
	&ipf_cb_ops,
	(struct bus_ops *)0,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};


static net_instance_t *ipfncb = NULL;
static ipf_stack_t *ipf_stacks = NULL;
static kmutex_t ipf_stack_lock;
extern struct mod_ops mod_driverops;
static struct modldrv iplmod = {
	&mod_driverops, IPL_VERSION, &ipf_ops };
static struct modlinkage modlink1 = { MODREV_1, &iplmod, NULL };

#if SOLARIS2 >= 6
static	size_t	hdrsizes[57][2] = {
	{ 0, 0 },
	{ IFT_OTHER, 0 },
	{ IFT_1822, 0 },
	{ IFT_HDH1822, 0 },
	{ IFT_X25DDN, 0 },
	{ IFT_X25, 0 },
	{ IFT_ETHER, 14 },
	{ IFT_ISO88023, 0 },
	{ IFT_ISO88024, 0 },
	{ IFT_ISO88025, 0 },
	{ IFT_ISO88026, 0 },
	{ IFT_STARLAN, 0 },
	{ IFT_P10, 0 },
	{ IFT_P80, 0 },
	{ IFT_HY, 0 },
	{ IFT_FDDI, 24 },
	{ IFT_LAPB, 0 },
	{ IFT_SDLC, 0 },
	{ IFT_T1, 0 },
	{ IFT_CEPT, 0 },
	{ IFT_ISDNBASIC, 0 },
	{ IFT_ISDNPRIMARY, 0 },
	{ IFT_PTPSERIAL, 0 },
	{ IFT_PPP, 0 },
	{ IFT_LOOP, 0 },
	{ IFT_EON, 0 },
	{ IFT_XETHER, 0 },
	{ IFT_NSIP, 0 },
	{ IFT_SLIP, 0 },
	{ IFT_ULTRA, 0 },
	{ IFT_DS3, 0 },
	{ IFT_SIP, 0 },
	{ IFT_FRELAY, 0 },
	{ IFT_RS232, 0 },
	{ IFT_PARA, 0 },
	{ IFT_ARCNET, 0 },
	{ IFT_ARCNETPLUS, 0 },
	{ IFT_ATM, 0 },
	{ IFT_MIOX25, 0 },
	{ IFT_SONET, 0 },
	{ IFT_X25PLE, 0 },
	{ IFT_ISO88022LLC, 0 },
	{ IFT_LOCALTALK, 0 },
	{ IFT_SMDSDXI, 0 },
	{ IFT_FRELAYDCE, 0 },
	{ IFT_V35, 0 },
	{ IFT_HSSI, 0 },
	{ IFT_HIPPI, 0 },
	{ IFT_MODEM, 0 },
	{ IFT_AAL5, 0 },
	{ IFT_SONETPATH, 0 },
	{ IFT_SONETVT, 0 },
	{ IFT_SMDSICIP, 0 },
	{ IFT_PROPVIRTUAL, 0 },
	{ IFT_PROPMUX, 0 },
};
#endif /* SOLARIS2 >= 6 */

dev_info_t *ipf_dev_info = NULL;

static const filter_kstats_t ipf_kstat_tmp = {
	{ "pass",			KSTAT_DATA_ULONG },
	{ "block",			KSTAT_DATA_ULONG },
	{ "nomatch",			KSTAT_DATA_ULONG },
	{ "short",			KSTAT_DATA_ULONG },
	{ "pass, logged",		KSTAT_DATA_ULONG },
	{ "block, logged",		KSTAT_DATA_ULONG },
	{ "nomatch, logged",		KSTAT_DATA_ULONG },
	{ "logged",			KSTAT_DATA_ULONG },
	{ "skip",			KSTAT_DATA_ULONG },
	{ "return sent",		KSTAT_DATA_ULONG },
	{ "acct",			KSTAT_DATA_ULONG },
	{ "bad frag state alloc",	KSTAT_DATA_ULONG },
	{ "new frag state kept",	KSTAT_DATA_ULONG },
	{ "new frag state compl. pkt",	KSTAT_DATA_ULONG },
	{ "bad pkt state alloc",	KSTAT_DATA_ULONG },
	{ "new pkt kept state",		KSTAT_DATA_ULONG },
	{ "cachehit",			KSTAT_DATA_ULONG },
	{ "tcp cksum bad",		KSTAT_DATA_ULONG },
	{{ "pullup ok",			KSTAT_DATA_ULONG },
	{ "pullup nok",			KSTAT_DATA_ULONG }},
	{ "src != route",		KSTAT_DATA_ULONG },
	{ "ttl invalid",		KSTAT_DATA_ULONG },
	{ "bad ip pkt",			KSTAT_DATA_ULONG },
	{ "ipv6 pkt",			KSTAT_DATA_ULONG },
	{ "dropped:pps ceiling",	KSTAT_DATA_ULONG },
	{ "ip upd. fail",		KSTAT_DATA_ULONG }
};


static int	ipf_kstat_update(kstat_t *ksp, int rwflag);

static void
ipf_kstat_init(ipf_stack_t *ifs, boolean_t from_gz)
{
	ifs->ifs_kstatp[0] = net_kstat_create(ifs->ifs_netid,
	    (from_gz ? "ipf_gz" : "ipf"),
	    0, "inbound", "net", KSTAT_TYPE_NAMED,
	    sizeof (filter_kstats_t) / sizeof (kstat_named_t), 0);
	if (ifs->ifs_kstatp[0] != NULL) {
		bcopy(&ipf_kstat_tmp, ifs->ifs_kstatp[0]->ks_data,
		    sizeof (filter_kstats_t));
		ifs->ifs_kstatp[0]->ks_update = ipf_kstat_update;
		ifs->ifs_kstatp[0]->ks_private = &ifs->ifs_frstats[0];
		kstat_install(ifs->ifs_kstatp[0]);
	}

	ifs->ifs_kstatp[1] = net_kstat_create(ifs->ifs_netid,
	    (from_gz ? "ipf_gz" : "ipf"),
	    0, "outbound", "net", KSTAT_TYPE_NAMED,
	    sizeof (filter_kstats_t) / sizeof (kstat_named_t), 0);
	if (ifs->ifs_kstatp[1] != NULL) {
		bcopy(&ipf_kstat_tmp, ifs->ifs_kstatp[1]->ks_data,
		    sizeof (filter_kstats_t));
		ifs->ifs_kstatp[1]->ks_update = ipf_kstat_update;
		ifs->ifs_kstatp[1]->ks_private = &ifs->ifs_frstats[1];
		kstat_install(ifs->ifs_kstatp[1]);
	}

#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_kstat_init(%p) installed %p, %p",
	    ifs, ifs->ifs_kstatp[0], ifs->ifs_kstatp[1]);
#endif
}


static void
ipf_kstat_fini(ipf_stack_t *ifs)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (ifs->ifs_kstatp[i] != NULL) {
			net_kstat_delete(ifs->ifs_netid, ifs->ifs_kstatp[i]);
			ifs->ifs_kstatp[i] = NULL;
		}
	}
}


static int
ipf_kstat_update(kstat_t *ksp, int rwflag)
{
	filter_kstats_t	*fkp;
	filterstats_t	*fsp;

	if (ksp == NULL || ksp->ks_data == NULL)
		return (EIO);

	if (rwflag == KSTAT_WRITE)
		return (EACCES);

	fkp = ksp->ks_data;
	fsp = ksp->ks_private;

	fkp->fks_pass.value.ul		= fsp->fr_pass;
	fkp->fks_block.value.ul		= fsp->fr_block;
	fkp->fks_nom.value.ul		= fsp->fr_nom;
	fkp->fks_short.value.ul		= fsp->fr_short;
	fkp->fks_ppkl.value.ul		= fsp->fr_ppkl;
	fkp->fks_bpkl.value.ul		= fsp->fr_bpkl;
	fkp->fks_npkl.value.ul		= fsp->fr_npkl;
	fkp->fks_pkl.value.ul		= fsp->fr_pkl;
	fkp->fks_skip.value.ul		= fsp->fr_skip;
	fkp->fks_ret.value.ul		= fsp->fr_ret;
	fkp->fks_acct.value.ul		= fsp->fr_acct;
	fkp->fks_bnfr.value.ul		= fsp->fr_bnfr;
	fkp->fks_nfr.value.ul		= fsp->fr_nfr;
	fkp->fks_cfr.value.ul		= fsp->fr_cfr;
	fkp->fks_bads.value.ul		= fsp->fr_bads;
	fkp->fks_ads.value.ul		= fsp->fr_ads;
	fkp->fks_chit.value.ul		= fsp->fr_chit;
	fkp->fks_tcpbad.value.ul 	= fsp->fr_tcpbad;
	fkp->fks_pull[0].value.ul 	= fsp->fr_pull[0];
	fkp->fks_pull[1].value.ul 	= fsp->fr_pull[1];
	fkp->fks_badsrc.value.ul 	= fsp->fr_badsrc;
	fkp->fks_badttl.value.ul 	= fsp->fr_badttl;
	fkp->fks_bad.value.ul		= fsp->fr_bad;
	fkp->fks_ipv6.value.ul		= fsp->fr_ipv6;
	fkp->fks_ppshit.value.ul 	= fsp->fr_ppshit;
	fkp->fks_ipud.value.ul		= fsp->fr_ipud;

	return (0);
}

int
_init()
{
	int ipfinst;

	ipfinst = mod_install(&modlink1);
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: _init() = %d", ipfinst);
#endif
	mutex_init(&ipf_stack_lock, NULL, MUTEX_DRIVER, NULL);
	return (ipfinst);
}


int
_fini(void)
{
	int ipfinst;

	ipfinst = mod_remove(&modlink1);
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: _fini() = %d", ipfinst);
#endif
	return (ipfinst);
}


int
_info(modinfop)
struct modinfo *modinfop;
{
	int ipfinst;

	ipfinst = mod_info(&modlink1, modinfop);
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: _info(%p) = %d", modinfop, ipfinst);
#endif
	return (ipfinst);
}


#if SOLARIS2 < 10
static int ipf_identify(dip)
dev_info_t *dip;
{
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_identify(%p)", dip);
#endif
	if (strcmp(ddi_get_name(dip), "ipf") == 0)
		return (DDI_IDENTIFIED);
	return (DDI_NOT_IDENTIFIED);
}
#endif

/*
 * Initialize things for IPF for each stack instance
 */
static void *
ipf_stack_create_one(const netid_t id, const zoneid_t zid, boolean_t from_gz,
    ipf_stack_t *ifs_gz)
{
	ipf_stack_t	*ifs;

#ifdef IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter:stack_create_one id=%d global=%d", id,
	    global);
#endif

	ifs = (ipf_stack_t *)kmem_alloc(sizeof (*ifs), KM_SLEEP);
	bzero(ifs, sizeof (*ifs));

	ifs->ifs_hook4_physical_in	= B_FALSE;
	ifs->ifs_hook4_physical_out	= B_FALSE;
	ifs->ifs_hook4_nic_events	= B_FALSE;
	ifs->ifs_hook4_loopback_in	= B_FALSE;
	ifs->ifs_hook4_loopback_out	= B_FALSE;
	ifs->ifs_hook6_physical_in	= B_FALSE;
	ifs->ifs_hook6_physical_out	= B_FALSE;
	ifs->ifs_hook6_nic_events	= B_FALSE;
	ifs->ifs_hook6_loopback_in	= B_FALSE;
	ifs->ifs_hook6_loopback_out	= B_FALSE;

	/*
	 * Initialize mutex's
	 */
	RWLOCK_INIT(&ifs->ifs_ipf_global, "ipf filter load/unload mutex");
	RWLOCK_INIT(&ifs->ifs_ipf_mutex, "ipf filter rwlock");
	RWLOCK_INIT(&ifs->ifs_ipf_frcache, "ipf cache rwlock");
	ifs->ifs_netid = id;
	ifs->ifs_zone = zid;
	ifs->ifs_gz_controlled = from_gz;
	ifs->ifs_gz_cont_ifs = ifs_gz;

	ipf_kstat_init(ifs, from_gz);

#ifdef IPFDEBUG
	cmn_err(CE_CONT, "IP Filter:stack_create zone=%d", ifs->ifs_zone);
#endif

	/*
	 * Lock people out while we set things up.
	 */
	WRITE_ENTER(&ifs->ifs_ipf_global);
	ipftuneable_alloc(ifs);
	RWLOCK_EXIT(&ifs->ifs_ipf_global);

	/* Limit to global stack */
	if (ifs->ifs_zone == GLOBAL_ZONEID)
		cmn_err(CE_CONT, "!%s, running.\n", ipfilter_version);

	mutex_enter(&ipf_stack_lock);
	if (ipf_stacks != NULL)
		ipf_stacks->ifs_pnext = &ifs->ifs_next;
	ifs->ifs_next = ipf_stacks;
	ifs->ifs_pnext = &ipf_stacks;
	ipf_stacks = ifs;
	mutex_exit(&ipf_stack_lock);

	return (ifs);
}

static void *
ipf_stack_create(const netid_t id)
{
	ipf_stack_t	*ifs = NULL;
	zoneid_t	zid = net_getzoneidbynetid(id);

	/*
	 * Create two ipfilter stacks for a zone - the first can only be
	 * controlled from the global zone, and the second is owned by
	 * the zone itself. There is no need to create a GZ-controlled
	 * stack for the global zone, since we're already in the global
	 * zone. See the "GZ-controlled and per-zone stacks" comment block in
	 * ip_fil_solaris.c for details.
	 */
	if (zid != GLOBAL_ZONEID)
		ifs = ipf_stack_create_one(id, zid, B_TRUE, NULL);

	return (ipf_stack_create_one(id, zid, B_FALSE, ifs));
}

/*
 * Find an ipfilter stack for the given zone. Return the GZ-controlled or
 * per-zone stack if set by an earlier SIOCIPFZONESET ioctl call. See the
 * "GZ-controlled and per-zone stacks" comment block in ip_fil_solaris.c for
 * details.
 *
 * This function returns with the ipf_stack_t's ifs_ipf_global
 * read lock held (if the stack is found). See the "ipfilter kernel module
 * mutexes and locking" comment block at the top of this file.
 */
ipf_stack_t *
ipf_find_stack(const zoneid_t orig_zone, ipf_devstate_t *isp)
{
	ipf_stack_t *ifs;
	boolean_t gz_stack;
	zoneid_t zone;

	/*
	 * If we're in the GZ, determine if we're acting on a zone's stack,
	 * and whether or not that stack is the GZ-controlled or in-zone
	 * one.  See the "GZ and per-zone stacks" note at the top of this
	 * file.
	 */
	if (orig_zone == GLOBAL_ZONEID &&
	    (isp->ipfs_zoneid != IPFS_ZONE_UNSET)) {
		/* Global zone, and we've set the zoneid for this fd already */

		if (orig_zone == isp->ipfs_zoneid) {
			/* There's only a per-zone stack for the GZ */
			gz_stack = B_FALSE;
		} else {
			gz_stack = isp->ipfs_gz;
		}

		zone = isp->ipfs_zoneid;
	} else {
		/*
		 * Non-global zone or GZ without having set a zoneid: act on
		 * the per-zone stack of the zone that this ioctl originated
		 * from.
		 */
		gz_stack = B_FALSE;
		zone = orig_zone;
	}

	mutex_enter(&ipf_stack_lock);
	for (ifs = ipf_stacks; ifs != NULL; ifs = ifs->ifs_next) {
		if (ifs->ifs_zone == zone && ifs->ifs_gz_controlled == gz_stack)
			break;
	}

	if (ifs != NULL) {
		READ_ENTER(&ifs->ifs_ipf_global);
	}
	mutex_exit(&ipf_stack_lock);
	return (ifs);
}

static int ipf_detach_check_zone(ipf_stack_t *ifs)
{
	/*
	 * Make sure we're the only one's modifying things.  With
	 * this lock others should just fall out of the loop.
	 */
	READ_ENTER(&ifs->ifs_ipf_global);
	if (ifs->ifs_fr_running == 1) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		return (-1);
	}

	/*
	 * Make sure there is no active filter rule.
	 */
	if (ifs->ifs_ipfilter[0][ifs->ifs_fr_active] ||
	    ifs->ifs_ipfilter[1][ifs->ifs_fr_active] ||
	    ifs->ifs_ipfilter6[0][ifs->ifs_fr_active] ||
	    ifs->ifs_ipfilter6[1][ifs->ifs_fr_active]) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		return (-1);
	}

	RWLOCK_EXIT(&ifs->ifs_ipf_global);

	return (0);
}


static int ipf_detach_check_all()
{
	ipf_stack_t *ifs;

	mutex_enter(&ipf_stack_lock);
	for (ifs = ipf_stacks; ifs != NULL; ifs = ifs->ifs_next)
		if (ipf_detach_check_zone(ifs) != 0)
			break;
	mutex_exit(&ipf_stack_lock);
	return ((ifs == NULL) ? 0 : -1);
}


/*
 * Remove ipf kstats for both the per-zone ipf stack and the
 * GZ-controlled stack for the same zone, if it exists.
 */
/* ARGSUSED */
static void
ipf_stack_shutdown(const netid_t id, void *arg)
{
	ipf_stack_t *ifs = (ipf_stack_t *)arg;

	/*
	 * The GZ-controlled stack
	 */
	if (ifs->ifs_gz_cont_ifs != NULL)
		ipf_kstat_fini(ifs->ifs_gz_cont_ifs);

	/*
	 * The per-zone stack
	 */
	ipf_kstat_fini(ifs);
}


/*
 * Destroy things for ipf for one stack.
 */
/* ARGSUSED */
static void
ipf_stack_destroy_one(const netid_t id, ipf_stack_t *ifs)
{
	timeout_id_t tid;

#ifdef IPFDEBUG
	(void) printf("ipf_stack_destroy_one(%p)\n", (void *)ifs);
#endif

	/*
	 * Make sure we're the only one's modifying things.  With
	 * this lock others should just fall out of the loop.
	 */
	WRITE_ENTER(&ifs->ifs_ipf_global);
	if (ifs->ifs_fr_running == -2) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		return;
	}
	ifs->ifs_fr_running = -2;
	tid = ifs->ifs_fr_timer_id;
	ifs->ifs_fr_timer_id = NULL;
	RWLOCK_EXIT(&ifs->ifs_ipf_global);

	mutex_enter(&ipf_stack_lock);
	if (ifs->ifs_next != NULL)
		ifs->ifs_next->ifs_pnext = ifs->ifs_pnext;
	*ifs->ifs_pnext = ifs->ifs_next;
	mutex_exit(&ipf_stack_lock);

	if (tid != NULL)
		(void) untimeout(tid);

	WRITE_ENTER(&ifs->ifs_ipf_global);
	if (ipldetach(ifs) != 0) {
		printf("ipf_stack_destroy_one: ipldetach failed\n");
	}

	ipftuneable_free(ifs);

	RWLOCK_EXIT(&ifs->ifs_ipf_global);
	RW_DESTROY(&ifs->ifs_ipf_mutex);
	RW_DESTROY(&ifs->ifs_ipf_frcache);
	RW_DESTROY(&ifs->ifs_ipf_global);

	KFREE(ifs);
}


/*
 * Destroy things for ipf for both the per-zone ipf stack and the
 * GZ-controlled stack for the same zone, if it exists. See the "GZ-controlled
 * and per-zone stacks" comment block in ip_fil_solaris.c for details.
 */
/* ARGSUSED */
static void
ipf_stack_destroy(const netid_t id, void *arg)
{
	ipf_stack_t *ifs = (ipf_stack_t *)arg;

	/*
	 * The GZ-controlled stack
	 */
	if (ifs->ifs_gz_cont_ifs != NULL)
		ipf_stack_destroy_one(id, ifs->ifs_gz_cont_ifs);

	/*
	 * The per-zone stack
	 */
	ipf_stack_destroy_one(id, ifs);
}


static int ipf_attach(dip, cmd)
dev_info_t *dip;
ddi_attach_cmd_t cmd;
{
	char *s;
	int i;
	int instance;

#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_attach(%p,%x)", dip, cmd);
#endif

	switch (cmd)
	{
	case DDI_ATTACH:
		instance = ddi_get_instance(dip);
		/* Only one instance of ipf (instance 0) can be attached. */
		if (instance > 0)
			return (DDI_FAILURE);

#ifdef	IPFDEBUG
		cmn_err(CE_CONT, "IP Filter: attach ipf instance %d", instance);
#endif

		(void) ipf_property_g_update(dip);

		if (ddi_soft_state_init(&ipf_state, sizeof (ipf_devstate_t), 1)
		    != 0) {
			ddi_prop_remove_all(dip);
			return (DDI_FAILURE);
		}

		for (i = 0; ((s = ipf_devfiles[i]) != NULL); i++) {
			s = strrchr(s, '/');
			if (s == NULL)
				continue;
			s++;
			if (ddi_create_minor_node(dip, s, S_IFCHR, i,
			    DDI_PSEUDO, 0) == DDI_FAILURE)
				goto attach_failed;
		}

		ipf_dev_info = dip;

		ipfncb = net_instance_alloc(NETINFO_VERSION);
		if (ipfncb == NULL)
			goto attach_failed;

		ipfncb->nin_name = "ipf";
		ipfncb->nin_create = ipf_stack_create;
		ipfncb->nin_destroy = ipf_stack_destroy;
		ipfncb->nin_shutdown = ipf_stack_shutdown;
		if (net_instance_register(ipfncb) == DDI_FAILURE) {
			net_instance_free(ipfncb);
			goto attach_failed;
		}

		ipf_minor = vmem_create("ipf_minor", (void *)1, UINT32_MAX - 1,
		    1, NULL, NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);

#ifdef IPFDEBUG
		cmn_err(CE_CONT, "IP Filter:stack_create callback_reg=%d", i);
#endif

		return (DDI_SUCCESS);
		/* NOTREACHED */
	default:
		break;
	}

attach_failed:
	ddi_remove_minor_node(dip, NULL);
	ddi_prop_remove_all(dip);
	ddi_soft_state_fini(&ipf_state);
	return (DDI_FAILURE);
}


static int ipf_detach(dip, cmd)
dev_info_t *dip;
ddi_detach_cmd_t cmd;
{
	int i;

#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_detach(%p,%x)", dip, cmd);
#endif
	switch (cmd) {
	case DDI_DETACH:
		if (ipf_detach_check_all() != 0)
			return (DDI_FAILURE);

		/*
		 * Undo what we did in ipf_attach, freeing resources
		 * and removing things we installed.  The system
		 * framework guarantees we are not active with this devinfo
		 * node in any other entry points at this time.
		 */
		ddi_prop_remove_all(dip);
		i = ddi_get_instance(dip);
		ddi_remove_minor_node(dip, NULL);
		if (i > 0) {
			cmn_err(CE_CONT, "IP Filter: still attached (%d)\n", i);
			return (DDI_FAILURE);
		}

		vmem_destroy(ipf_minor);
		ddi_soft_state_fini(&ipf_state);

		(void) net_instance_unregister(ipfncb);
		net_instance_free(ipfncb);

		return (DDI_SUCCESS);
		/* NOTREACHED */
	default:
		break;
	}
	cmn_err(CE_NOTE, "IP Filter: failed to detach\n");
	return (DDI_FAILURE);
}


/*ARGSUSED*/
static int ipf_getinfo(dip, infocmd, arg, result)
dev_info_t *dip;
ddi_info_cmd_t infocmd;
void *arg, **result;
{
	int error;

	error = DDI_FAILURE;
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_getinfo(%p,%x,%p)", dip, infocmd, arg);
#endif
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = ipf_dev_info;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}
	return (error);
}


/*
 * Fetch configuration file values that have been entered into the ipf.conf
 * driver file.
 */
static int ipf_property_g_update(dip)
dev_info_t *dip;
{
#ifdef DDI_NO_AUTODETACH
	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
				DDI_NO_AUTODETACH, 1) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "!updating DDI_NO_AUTODETACH failed");
		return (DDI_FAILURE);
	}
#else
	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
				"ddi-no-autodetach", 1) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "!updating ddi-no-autodetach failed");
		return (DDI_FAILURE);
	}
#endif

	return (DDI_SUCCESS);
}

int
ipf_property_update(dip, ifs)
dev_info_t *dip;
ipf_stack_t *ifs;
{
	ipftuneable_t *ipft;
	char *name;
	uint_t one;
	int *i32p;
	int err, rv = 0;

	for (ipft = ifs->ifs_ipf_tuneables;
		(name = ipft->ipft_name) != NULL; ipft++) {
		one = 1;
		i32p = NULL;
		err = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
						0, name, &i32p, &one);
		if (err == DDI_PROP_NOT_FOUND)
			continue;
#ifdef	IPFDEBUG
		cmn_err(CE_CONT, "IP Filter: lookup_int(%s) = %d\n",
			name, err);
#endif
		if (err != DDI_PROP_SUCCESS) {
			rv = err;
			continue;
		}

		if (*i32p >= ipft->ipft_min &&
		    *i32p <= ipft->ipft_max) {
			if (ipft->ipft_sz == sizeof (uint32_t)) {
				*ipft->ipft_pint = *i32p;
			} else if (ipft->ipft_sz == sizeof (uint64_t)) {
				*ipft->ipft_plong = *i32p;
			}
		}

		ddi_prop_free(i32p);
	}

	return (rv);
}
