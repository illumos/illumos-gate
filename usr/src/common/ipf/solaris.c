/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/stream.h>
#include <sys/poll.h>
#include <sys/autoconf.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/sockio.h>
#include <net/if.h>
#if SOLARIS2 >= 6
# include <net/if_types.h>
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
#include "ip_compat.h"
#include "ipl.h"
#include "ip_fil.h"
#include "ip_nat.h"
#include "ip_frag.h"
#include "ip_auth.h"
#include "ip_state.h"
#if SOLARIS2 >= 10
#include "pfild.h"
#endif


extern	struct	filterstats	frstats[];
extern	ipfrwlock_t	ipf_mutex, ipf_nat, ipf_global;
extern	ipfmutex_t	ipf_rw, ipf_timeoutlock;
extern	int	fr_running;
extern	int	fr_flags;
#ifdef IPFILTER_SYNC
extern	int	iplwrite __P((dev_t, struct uio *, cred_t *));
#endif

extern ipnat_t *nat_list;

static	int	ipf_getinfo __P((dev_info_t *, ddi_info_cmd_t,
				 void *, void **));
#if SOLARIS2 < 10
static	int	ipf_identify __P((dev_info_t *));
#endif
static	int	ipf_attach __P((dev_info_t *, ddi_attach_cmd_t));
static	int	ipf_detach __P((dev_info_t *, ddi_detach_cmd_t));
static	int	fr_qifsync __P((ip_t *, int, void *, int, qif_t *, mblk_t **));
static	char	*ipf_devfiles[] = { IPL_NAME, IPNAT_NAME, IPSTATE_NAME,
				    IPAUTH_NAME, IPSYNC_NAME, IPSCAN_NAME,
				    IPLOOKUP_NAME, NULL };


#if SOLARIS2 >= 7
void	fr_slowtimer __P((void *));
timeout_id_t	fr_timer_id;
static	timeout_id_t	synctimeoutid = 0;
#else
void	fr_slowtimer __P((void));
int	fr_timer_id;
static	int	synctimeoutid = 0;
#endif

#ifndef IRE_ILL_CN
#ifdef	IPFDEBUG
void	printire __P((ire_t *));
#endif
#endif

static struct cb_ops ipf_cb_ops = {
	iplopen,
	iplclose,
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	iplread,
#ifdef IPFILTER_SYNC
	iplwrite,	/* write */
#else
	nodev,		/* write */
#endif
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
	(struct bus_ops *)0
};

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

static dev_info_t *ipf_dev_info = NULL;


int _init()
{
	int status;

	/*
	 * Initialize mutex's
	 */
	RWLOCK_INIT(&ipf_global, "ipf filter load/unload mutex");
	RWLOCK_INIT(&ipf_mutex, "ipf filter rwlock");
	status = mod_install(&modlink1);
	if (status != 0) {
		RW_DESTROY(&ipf_mutex);
		RW_DESTROY(&ipf_global);
	}
	return status;
}


int _fini(void)
{
	int status;

	status = mod_remove(&modlink1);
	if (status != 0)
		return status;
	RW_DESTROY(&ipf_mutex);
	RW_DESTROY(&ipf_global);
	return status;
}


int _info(modinfop)
struct modinfo *modinfop;
{
	int status;

	status = mod_info(&modlink1, modinfop);
	return status;
}


#if SOLARIS2 < 10
static int ipf_identify(dip)
dev_info_t *dip;
{
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_identify(%x)", dip);
#endif
	if (strcmp(ddi_get_name(dip), "ipf") == 0)
		return (DDI_IDENTIFIED);
	return (DDI_NOT_IDENTIFIED);
}
#endif


static int ipf_attach(dip, cmd)
dev_info_t *dip;
ddi_attach_cmd_t cmd;
{
	char *s;
	int i;
	int instance;

#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_attach(%x,%x)", dip, cmd);
#endif


	switch (cmd)
	{
	case DDI_ATTACH:
		instance = ddi_get_instance(dip);
		/* Only one instance of ipf (instance 0) can be attached.*/
		if (instance > 0)
			return DDI_FAILURE;
		if (fr_running != 0)
			return DDI_FAILURE;

		if (pfilinterface != PFIL_INTERFACE) {
#ifdef	IPFDEBUG
			cmn_err(CE_NOTE, "pfilinterface(%d) != %d",
			    pfilinterface, PFIL_INTERFACE);
#endif
			return DDI_FAILURE;
		}

		if (ddi_prop_update_int(DDI_DEV_T_NONE, dip, DDI_NO_AUTODETACH,
				        1) != DDI_PROP_SUCCESS) {
#ifdef	IPFDEBUG
			cmn_err(CE_WARN, "!updating %s failed",
				DDI_NO_AUTODETACH);
#endif
			return DDI_FAILURE;
		}

		for (i = 0; ((s = ipf_devfiles[i]) != NULL); i++) {
			s = strrchr(s, '/');
			if (s == NULL)
				continue;
			s++;
			if (ddi_create_minor_node(dip, s, S_IFCHR, i,
						  DDI_PSEUDO, 0) ==
			    DDI_FAILURE) {
				ddi_remove_minor_node(dip, NULL);
				return DDI_FAILURE;
			}
		}

		ipf_dev_info = dip;
		/*
		 * Lock people out while we set things up.
		 */
		WRITE_ENTER(&ipf_global);
		if ((fr_running != 0) || (iplattach() == -1)) {
			RWLOCK_EXIT(&ipf_global);
#ifdef	IPFDEBUG
			cmn_err(CE_NOTE, "IP Filter: iplattach() failed");
#endif
			goto attach_failed;
		}

		if (pfil_add_hook(fr_check, PFIL_IN|PFIL_OUT, &pfh_inet4)) {
			RWLOCK_EXIT(&ipf_global);
			goto attach_failed;
		}

#ifdef USE_INET6
		if (pfil_add_hook(fr_check, PFIL_IN|PFIL_OUT, &pfh_inet6)) {
			RWLOCK_EXIT(&ipf_global);
			goto attach_failed;
		}
#endif
		
		if (pfil_add_hook(fr_qifsync, PFIL_IN|PFIL_OUT, &pfh_sync)) {
			RWLOCK_EXIT(&ipf_global);
			goto attach_failed;
		}

		fr_timer_id = timeout(fr_slowtimer, NULL,
				      drv_usectohz(500000));

		fr_running = 1;

		RWLOCK_EXIT(&ipf_global);

		cmn_err(CE_CONT, "!%s, running.\n", ipfilter_version);

		return DDI_SUCCESS;
		/* NOTREACHED */
	default:
		return DDI_FAILURE;
	}

attach_failed:
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: failed to attach");
#endif
	/*
	 * Use our own detach routine to toss
	 * away any stuff we allocated above.
	 */
	(void) ipf_detach(dip, DDI_DETACH);
	return DDI_FAILURE;
}


static int ipf_detach(dip, cmd)
dev_info_t *dip;
ddi_detach_cmd_t cmd;
{
	int i;

#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_detach(%x,%x)", dip, cmd);
#endif
	switch (cmd) {
	case DDI_DETACH:
		if (fr_running == -2 || fr_running == 0) {
#ifdef	IPFDEBUG
			cmn_err(CE_NOTE, "IP Filter:  not yet attached  "
			   "or already detached");
#endif
			break;
		}
		/*
		 * Make sure we're the only one's modifying things.  With
		 * this lock others should just fall out of the loop.
		 */
		WRITE_ENTER(&ipf_global);
		if (fr_running <= 0) {
			RWLOCK_EXIT(&ipf_global);
			return DDI_FAILURE;
		}
		fr_running = -2;

		(void) pfil_remove_hook(fr_check, PFIL_IN|PFIL_OUT, &pfh_inet4);
#ifdef USE_INET6
		(void) pfil_remove_hook(fr_check, PFIL_IN|PFIL_OUT, &pfh_inet6);
#endif
		(void) pfil_remove_hook(fr_qifsync, PFIL_IN|PFIL_OUT, &pfh_sync);

		RWLOCK_EXIT(&ipf_global);

		if (fr_timer_id != 0) {
			(void) untimeout(fr_timer_id);
			fr_timer_id = 0;
		}

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
#ifdef	IPFDEBUG
			cmn_err(CE_CONT, "IP Filter: still attached (%d)\n", i);
#endif
			return DDI_FAILURE;
		}

		WRITE_ENTER(&ipf_global);
		if (!ipldetach()) {
			RWLOCK_EXIT(&ipf_global);
#ifdef	IPFDEBUG
			cmn_err(CE_CONT, "!%s detached.\n", ipfilter_version);
#endif
			return (DDI_SUCCESS);
		}
		RWLOCK_EXIT(&ipf_global);
#ifdef	IPFDEBUG
		cmn_err(CE_NOTE, "IP Filter: ipldetach() failed");
#endif
		break;
	default:
		return DDI_FAILURE;
	}
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: failed to detach");
#endif
	return DDI_FAILURE;
}


/*ARGSUSED*/
static int ipf_getinfo(dip, infocmd, arg, result)
dev_info_t *dip;
ddi_info_cmd_t infocmd;
void *arg, **result;
{
	int error;

	if (fr_running <= 0)
		return DDI_FAILURE;
	error = DDI_FAILURE;
#ifdef	IPFDEBUG
	cmn_err(CE_NOTE, "IP Filter: ipf_getinfo(%x,%x,%x)", dip, infocmd, arg);
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
 * look for bad consistancies between the list of interfaces the filter knows
 * about and those which are currently configured.
 */
/*ARGSUSED*/
static int fr_qifsync(ip, hlen, il, out, qif, mp)
ip_t *ip;
int hlen;
void *il;
int out;
qif_t *qif;
mblk_t **mp;
{

	frsync();
	/*
	 * Resync. any NAT `connections' using this interface and its IP #.
	 */
	fr_natsync(il);
	fr_statesync(il);
	return 0;
}	  


/*
 * look for bad consistancies between the list of interfaces the filter knows
 * about and those which are currently configured.
 */
int ipfsync()
{
	qif_t *qf;

	frsync();
	/*
	 * Resync. any NAT `connections' using this interface and its IP #.
	 */
	qf = NULL;
	while (qif_walk(&qf))
		(void) fr_qifsync(NULL, 0, (void *)qf->qf_ill, -1, qf, NULL);
	return 0;
}

#ifndef IRE_ILL_CN
#ifdef	IPFDEBUG
void printire(ire)
ire_t *ire;
{
	printf("ire: ll_hdr_mp %p rfq %p stq %p src_addr %x max_frag %d\n",
# if SOLARIS2 >= 8
		NULL,
# else
		ire->ire_ll_hdr_mp,
# endif
		ire->ire_rfq, ire->ire_stq,
		ire->ire_src_addr, ire->ire_max_frag);
	printf("ire: mask %x addr %x gateway_addr %x type %d\n",
		ire->ire_mask, ire->ire_addr, ire->ire_gateway_addr,
		ire->ire_type);
	printf("ire: ll_hdr_length %d ll_hdr_saved_mp %p\n",
		ire->ire_ll_hdr_length,
# if SOLARIS2 >= 8
		NULL
# else
		ire->ire_ll_hdr_saved_mp
# endif
		);

}
#endif
#endif  /* IRE_ILL_CN */

/*
 * Function:	fr_fastroute
 * Returns:	 0: success;
 *		-1: failed
 * Parameters:
 *	mb: the message block where ip head starts
 *	mpp: the pointer to the pointer of the orignal
 *		packet message
 *	fin: packet information
 *	fdp: destination interface information
 *	if it is NULL, no interface information provided.
 *
 * This function is for fastroute/to/dup-to rules. It calls
 * pfil_make_lay2_packet to search route, make lay-2 header
 * ,and identify output queue for the IP packet.
 * The destination address depends on the following conditions:
 * 1: for fastroute rule, fdp is passed in as NULL, so the
 *	destination address is the IP Packet's destination address
 * 2: for to/dup-to rule, if an ip address is specified after
 *	the interface name, this address is the as destination
 *	address. Otherwise IP Packet's destination address is used
 */
int fr_fastroute(mb, mpp, fin, fdp)
mblk_t *mb, **mpp;
fr_info_t *fin;
frdest_t *fdp;
{
#ifndef IRE_ILL_CN
	ire_t *ir, *dir;
	struct in_addr dst;
	ill_t *ifp;
	u_char *s;
	size_t hlen = 0;
	frdest_t fd;
#else
	void *target = NULL;
	char *ifname = NULL;
#endif
	queue_t *q = NULL;
	mblk_t *mp = NULL;
	frentry_t *fr = fin->fin_fr;
	qif_t *qf;
	ip_t *ip;
#ifndef	sparc
	u_short __iplen, __ipoff;
#endif
#ifndef IRE_ILL_CN
#ifdef	USE_INET6
	ip6_t *ip6 = (ip6_t *)fin->fin_ip;
#endif
#endif
	ip = fin->fin_ip;
	qf = fin->fin_qif;

	/*
	 * If this is a duplicate mblk then we want ip to point at that
	 * data, not the original, if and only if it is already pointing at
	 * the current mblk data.
	 */
	if (ip == (ip_t *)qf->qf_m->b_rptr && qf->qf_m != mb)
		ip = (ip_t *)mb->b_rptr;

	/*
	 * If there is another M_PROTO, we don't want it
	 */
	if (*mpp != mb) {
		mp = unlinkb(*mpp);
		freeb(*mpp);
		*mpp = mp;
	}


	/*
	 * In case we're here due to "to <if>" being used with
	 * "keep state", check that we're going in the correct
	 * direction.
	 */
	if (fdp != NULL) {
		if ((fr != NULL) && (fdp->fd_ifp != NULL) &&
			(fin->fin_rev != 0) && (fdp == &fr->fr_tif))
			goto bad_fastroute;
	}

#ifndef IRE_ILL_CN
	if (!fdp) {
		ipif_t *ipif;

		ifp = fin->fin_ifp;
		ipif = ifp->ill_ipif;
		if (!ipif)
			goto bad_fastroute;
#if SOLARIS2 > 5
		ir = ire_ctable_lookup(ipif->ipif_local_addr, 0, IRE_LOCAL,
			NULL, NULL, MATCH_IRE_TYPE);
#else
		ir = ire_lookup_myaddr(ipif->ipif_local_addr);
#endif
		if (!ir)
			ir = (ire_t *)-1;

		fd.fd_ifp = (struct ifnet *)ir;
		fd.fd_ip = ip->ip_dst;
		fdp = &fd;
	}

	ir = (ire_t *)fdp->fd_ifp;

	if (fdp->fd_ip.s_addr)
		dst = fdp->fd_ip;
	else
		dst.s_addr = fin->fin_fi.fi_daddr;

#if SOLARIS2 >= 6
	if (fin->fin_v == 4) {
		dir = ire_route_lookup(dst.s_addr, 0xffffffff, 0, 0, NULL,
					NULL, NULL, MATCH_IRE_DSTONLY|
					MATCH_IRE_DEFAULT|MATCH_IRE_RECURSIVE);
	}
#ifdef	USE_INET6
	else if (fin->fin_v == 6) {
		dir = ire_route_lookup_v6(&ip6->ip6_dst, NULL, 0, 0,
					NULL, NULL, NULL, MATCH_IRE_DSTONLY|
					MATCH_IRE_DEFAULT|MATCH_IRE_RECURSIVE);
	}
#endif
#else
	dir = ire_lookup(dst.s_addr);
#endif
#if SOLARIS2 < 8
	if (dir)
		if (!dir->ire_ll_hdr_mp || !dir->ire_ll_hdr_length)
			dir = NULL;
#else
	if (dir)
		if (!dir->ire_fp_mp || !dir->ire_dlureq_mp)
			dir = NULL;
#endif

	if (!ir)
		ir = dir;

	if (!ir || !dir)
		goto bad_fastroute;

#if SOLARIS2 < 8
	mp = dir->ire_ll_hdr_mp;
	hlen = dir->ire_ll_hdr_length;
#else
	mp = dir->ire_fp_mp;
	hlen = mp ? mp->b_wptr - mp->b_rptr : 0;
	if (mp == NULL)
		mp = dir->ire_dlureq_mp;
#endif
	if (mp != NULL) {
		s = mb->b_rptr;
		if (
#if SOLARIS2 >= 6
			(dohwcksum &&
			ifp->ill_ick.ick_magic == ICK_M_CTL_MAGIC) ||
#endif
			(hlen && (s - mb->b_datap->db_base) >= hlen)) {
			s -= hlen;
			mb->b_rptr = (u_char *)s;
			bcopy((char *)mp->b_rptr, (char *)s, hlen);
		} else {
			mblk_t	*mp2;

			mp2 = copyb(mp);
			if (!mp2)
				goto bad_fastroute;
			linkb(mp2, mb);
			mb = mp2;
		}
	}

	if (ir->ire_stq)
		q = ir->ire_stq;
	else if (ir->ire_rfq)
		q = WR(ir->ire_rfq);
	if (q)
		q = q->q_next;
	if (!q)
		goto bad_fastroute;

	ifp = ire_to_ill(ir);
	if (ifp == NULL)
		goto bad_fastroute;

	fin->fin_ifp = ifp;
#else /* IRE_ILL_CN */
	if (fin->fin_v == 4) {
		if (fdp && (fdp->fd_ip.s_addr != 0))
			target = &fdp->fd_ip;
	}
#ifdef USE_INET6
	else if (fin->fin_v == 6) {
		if (fdp && !IN6_IS_ADDR_UNSPECIFIED(&fdp->fd_ip6.in6))
			target = &fdp->fd_ip6.in6;
	}
#endif
	else
		goto bad_fastroute;

	if (fdp && fdp->fd_ifname[0] != 0)
		ifname = fdp->fd_ifname;

	mp = pfil_make_dl_packet(mb, ip, target, ifname, &q);
	if (mp == NULL)
	{
		goto bad_fastroute;
	}
	mb = mp;
	/*
	 * TODO: assign fin->fin_ifp = ?
	 * The ? can be get from mb->b_queue depending on
	 * what will be done when replacing of s_ill_t.
	 */
#endif /* IRE_ILL_CN */

	mb->b_queue = q;
	*mpp = mb;

	if (fin->fin_out == 0) {
		u_32_t pass;

		(void)fr_acctpkt(fin, &pass);
		fin->fin_fr = NULL;
		if (!fr || !(fr->fr_flags & FR_RETMASK))
			(void) fr_checkstate(fin, &pass);
		(void) fr_checknatout(fin, NULL);
	}
#ifndef	sparc
	if (fin->fin_v == 4) {
		__iplen = (u_short)ip->ip_len,
		__ipoff = (u_short)ip->ip_off;

		ip->ip_len = htons(__iplen);
		ip->ip_off = htons(__ipoff);
	}
#endif

#ifndef IRE_ILL_CN
#if SOLARIS2 >= 6
	if ((p == IPPROTO_TCP) && dohwcksum &&
	    (ifp->ill_ick.ick_magic == ICK_M_CTL_MAGIC)) {
		tcphdr_t *tcp;
		u_32_t t;

		tcp = (tcphdr_t *)((char *)ip + fin->fin_hlen);
		t = ip->ip_src.s_addr;
		t += ip->ip_dst.s_addr;
		t += 30;
		t = (t & 0xffff) + (t >> 16);
		tcp->th_sum = t & 0xffff;
	}
#endif
	RWLOCK_EXIT(&ipf_global);
	putnext(q, mb);
	READ_ENTER(&ipf_global);
#else /* IRE_ILL_CN */
	pfil_send_dl_packet(q, mb);
#endif /* IRE_ILL_CN */
	fr_frouteok[0]++;
	return 0;
bad_fastroute:
	freemsg(mb);
	fr_frouteok[1]++;
	return -1;
}

#if SOLARIS2 >= 10
/*
 * Function:	addrset_match_v4
 * Returns:	boolean_t
 * Parameters:	addr - the IP address of interest
 *		setp - pointer to an address set (generated by pfild)
 *
 * Support function for fr_verifysrc used on Solaris 10 and later.
 * Try to match an IPv4 address against an address set.
 * Returns true iff the specified address is a member of the set.
 * Note that addr is passed in network byte order; we convert it to host byte
 * order for searching the table.
 */
static boolean_t addrset_match_v4(setp, addr)
struct pfil_ifaddrset *setp;
struct in_addr addr;
{
	uint32_t haddr = ntohl(addr.s_addr);
	unsigned int low, high, mid;
	struct pfil_v4span *spans = (struct pfil_v4span *)(setp + 1);

	/* binary search */
	low = 0;
	high = setp->nspans;
	while (low < high) {
		mid = (high + low) / 2;
		if (haddr > spans[mid].last)
			low = mid + 1;
		else if (haddr < spans[mid].first)
			high = mid;
		else
			return B_TRUE;
	}
	return B_FALSE;
}

/*
 * Function:	addrset_match_v6
 * Returns:	boolean_t
 * Parameters:	addr - the IP address of interest
 *		setp - pointer to an address set (generated by pfild)
 *
 * Support function for fr_verifysrc used on Solaris 10 and later.
 * Try to match an IPv6 address against an address set.
 * Returns true iff the specified address is a member of the set.
 */
static boolean_t addrset_match_v6(setp, addr)
struct pfil_ifaddrset *setp;
struct in6_addr addr;
{
	unsigned int low, high, mid;
	struct pfil_v6span *spans = (struct pfil_v6span *)(setp + 1);

	/* binary search */
	low = 0;
	high = setp->nspans;
	while (low < high) {
		mid = (high + low) / 2;
		if (IP6_GT(&addr, &spans[mid].last))
			low = mid + 1;
		else if (IP6_LT(&addr, &spans[mid].first))
			high = mid;
		else
			return B_TRUE;
	}
	return B_FALSE;
}
#endif

/*
 * Function:	fr_verifysrc
 * Returns:	int (really boolean)
 * Parameters:	fin - packet information
 *
 * Check whether the packet has a valid source address for the interface on
 * which the packet arrived, implementing the "fr_chksrc" feature.
 * Returns true iff the packet's source address is valid.
 * Pre-Solaris 10, we call into the routing code to make the determination.
 * On Solaris 10 and later, we have a valid address set from pfild to check
 * against.
 */
int fr_verifysrc(fin)
fr_info_t *fin;
{
#if SOLARIS2 >= 10
	qif_t *qf = fin->fin_qif;
	struct pfil_ifaddrset *setp;

	if (qf->qf_addrset == NULL) {
		/* Warn here?  pfild might not be running. */
		return 0;
	}

	setp = (struct pfil_ifaddrset *)qf->qf_addrset->b_rptr;
	if (!setp)
		return 0;

	if  (fin->fin_v == IPVERSION && setp->af == AF_INET) {
		if (qf->qf_addrset->b_wptr - qf->qf_addrset->b_rptr <
		    sizeof (*setp) + setp->nspans * sizeof (struct pfil_v4span))
			return 0;		/* malformed set */

		return addrset_match_v4(setp, fin->fin_src);
	} else if (fin->fin_v == IPV6_VERSION && setp->af == AF_INET6) {
		if (qf->qf_addrset->b_wptr - qf->qf_addrset->b_rptr <
		    sizeof (*setp) + setp->nspans * sizeof (struct pfil_v6span))
			return 0;		/* malformed set */

		return addrset_match_v6(setp, fin->fin_src6);
	} else
		return 0;

#else
	ire_t *ir, *dir;

#if SOLARIS2 >= 6
	dir = ire_route_lookup(fin->fin_saddr, 0xffffffff, 0, 0, NULL,
			       NULL, NULL, MATCH_IRE_DSTONLY|MATCH_IRE_DEFAULT|
			       MATCH_IRE_RECURSIVE);
#else
	dir = ire_lookup(fin->fin_saddr);
#endif

	if (!dir)
		return 0;
	return (ire_to_ill(dir) == fin->fin_ifp);
#endif /* SOLARIS2 >= 10 */
}


#if (SOLARIS2 < 7)
void fr_slowtimer()
#else
/*ARGSUSED*/
void fr_slowtimer __P((void *ptr))
#endif
{

	WRITE_ENTER(&ipf_global);
	if (fr_running <= 0) {
		if (fr_running == -1)
			fr_timer_id = timeout(fr_slowtimer, NULL,
					      drv_usectohz(500000));
		else
			fr_timer_id = NULL;
		RWLOCK_EXIT(&ipf_global);
		return;
	}
	MUTEX_DOWNGRADE(&ipf_global);

	fr_fragexpire();
	fr_timeoutstate();
	fr_natexpire();
	fr_authexpire();
	fr_ticks++;
	if (fr_running == -1 || fr_running == 1)
		fr_timer_id = timeout(fr_slowtimer, NULL, drv_usectohz(500000));
	else
		fr_timer_id = NULL;
	RWLOCK_EXIT(&ipf_global);
}
