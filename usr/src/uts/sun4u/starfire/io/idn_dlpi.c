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
 * IDN DLPI support (based on QE implementation).
 */
#include <sys/types.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#ifdef xxx_trace
#include <sys/vtrace.h>
#endif /* xxx_trace */
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/dlpi.h>
#include <sys/time.h>
#include <sys/cpuvar.h>

#include <sys/idn.h>

#ifdef	IPV6
#define	IS_ETHERTYPE_IPV4(x)	((x) == ETHERTYPE_IP)
#define	IS_ETHERTYPE_IPV6(x)	((x) == ETHERTYPE_IPV6)
#define	IS_ETHERTYPE_IP(x)	(IS_ETHERTYPE_IPV4(x) || IS_ETHERTYPE_IPV6(x))
#else
#define	IS_ETHERTYPE_IPV4(x)	((x) == ETHERTYPE_IP)
#define	IS_ETHERTYPE_IPV6(x)	(0)
#define	IS_ETHERTYPE_IP		IS_ETHERTYPE_IPV4
#endif /* IPV6 */

#ifdef IDN_TRACE
/*
 * This stuff should go into <sys/vtrace.h>
 */
#define	TR_FAC_IDN		100
/*
 * TR_FAC_IDN tags
 */
#define	TR_IDN_OPEN		0
#define	TR_IDN_CLOSE		1
#define	TR_IDN_WPUT_START	2
#define	TR_IDN_WPUT_END		3
#define	TR_IDN_WSRV_START	4
#define	TR_IDN_WSRV_END		5
#define	TR_IDN_START_START	6
#define	TR_IDN_START_END	7
#define	TR_IDN_INTR_START	8
#define	TR_IDN_INTR_END		9
#define	TR_IDN_READ_START	10
#define	TR_IDN_READ_END		11
#define	TR_IDN_SENDUP_START	12
#define	TR_IDN_SENDUP_END	13
#define	TR_IDN_ADDUDIND_START	14
#define	TR_IDN_ADDUDIND_END	15
#define	TR_IDN_GETBUF_START	16
#define	TR_IDN_GETBUF_END	17
#define	TR_IDN_FREEBUF_START	18
#define	TR_IDN_FREEBUF_END	19
#define	TR_IDN_PROTO_START	20
#define	TR_IDN_PROTO_END	21
#define	TR_IDN_INIT_START	22
#define	TR_IDN_INIT_END		23
#define	TR_IDN_PROTO_IN		24
#define	TR_IDN_PROTO_OUT	25

#define	IDNTRACE(fac, tag)	(printf("idn.TRACE: "))

#define	TRACE_0(fac, tag, name) \
	IDNTRACE((fac), (tag)); \
	printf(name); printf("\n");

#define	TRACE_1(fac, tag, name, d1) \
	IDNTRACE((fac), (tag)); \
	printf(name, (d1)); printf("\n");

#define	TRACE_2(fac, tag, name, d1, d2) \
	IDNTRACE((fac), (tag)); \
	printf(name, (d1), (d2)); printf("\n");

#define	TRACE_3(fac, tag, name, d1, d2, d3) \
	IDNTRACE((fac), (tag)); \
	printf(name, (d1), (d2), (d3)); printf("\n");

#define	TRACE_4(fac, tag, name, d1, d2, d3, d4) \
	IDNTRACE((fac), (tag)); \
	printf(name, (d1), (d2), (d3), (d4)); printf("\n");

#define	TRACE_5(fac, tag, name, d1, d2, d3, d4, d5) \
	IDNTRACE((fac), (tag)); \
	printf(name, (d1), (d2), (d3), (d4), (d5)); printf("\n");

#else /* IDN_TRACE */

#define	TRACE_0(fac, tag, name) 			{}
#define	TRACE_1(fac, tag, name, d1) 			{}
#define	TRACE_2(fac, tag, name, d1, d2) 		{}
#define	TRACE_3(fac, tag, name, d1, d2, d3) 		{}
#define	TRACE_4(fac, tag, name, d1, d2, d3, d4) 	{}
#define	TRACE_5(fac, tag, name, d1, d2, d3, d4, d5) 	{}

#endif /* IDN_TRACE */

#ifdef DEBUG
#define	DLERRORACK(qq, mm, cc, ee, xx) \
{ \
	PR_DLPI("dlpi: ERRORACK: 0x%x(%s), err = 0x%x(%s)\n", \
		(uint_t)(cc), dlprim2str(cc), \
		(uint_t)(ee), dlerr2str((int)(ee))); \
	dlerrorack((qq), (mm), (cc), (ee), (xx)); \
}
#define	DLOKACK(qq, mm, cc) \
{ \
	PR_DLPI("dlpi: OKACK: 0x%x(%s)\n", (cc), dlprim2str(cc)); \
	dlokack((qq), (mm), (cc)); \
}
#define	DLBINDACK(qq, mm, ss, aa, ll, xx, yy) \
{ \
	PR_DLPI("dlpi: BINDACK: eth=%x:%x:%x:%x:%x:%x, sap=0x%x, l=%d\n", \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[0], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[1], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[2], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[3], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[4], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[5], \
		(uint_t)(ss), (int)(ll)); \
	dlbindack((qq), (mm), (ss), (aa), (ll), (xx), (yy)); \
}
#define	DLPHYSADDRACK(qq, mm, aa, ll) \
{ \
	PR_DLPI("dlpi: PHYSACK: eth=%x:%x:%x:%x:%x:%x, l=%d\n", \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[0], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[1], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[2], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[3], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[4], \
		((struct idndladdr *)(aa))->dl_phys.ether_addr_octet[5], \
		(ll)); \
	dlphysaddrack((qq), (mm), (aa), (ll)); \
}

static char *dlerrstr[] = {
	"DL_BADSAP",
	"DL_BADADDR",
	"DL_ACCESS",
	"DL_OUTSTATE",
	"DL_SYSERR",
	"DL_BADCORR",
	"DL_BADDATA",
	"DL_UNSUPPORTED",
	"DL_BADPPA",
	"DL_BADPRIM",
	"DL_BADQOSPARAM",
	"DL_BADQOSTYPE",
	"DL_BADTOKEN",
	"DL_BOUND",
	"DL_INITFAILED",
	"DL_NOADDR",
	"DL_NOTINIT",
	"DL_UNDELIVERABLE",
	"DL_NOTSUPPORTED",
	"DL_TOOMANY",
	"DL_NOTENAB",
	"DL_BUSY",
	"DL_NOAUTO",
	"DL_NOXIDAUTO",
	"DL_NOTESTAUTO",
	"DL_XIDAUTO",
	"DL_TESTAUTO",
	"DL_PENDING"
};
static int dlerrnum = (sizeof (dlerrstr) / sizeof (char *));

static char *
dlerr2str(int err)
{
	if ((err < 0) || (err >= dlerrnum))
		return ("unknown");
	else
		return (dlerrstr[err]);
}

static char *
dlprim2str(int prim)
{
	char	*pstr;

	switch (prim) {
	case DL_UNITDATA_REQ:	pstr = "UNITDATA_REQ";		break;
	case DL_ATTACH_REQ:	pstr = "ATTACH_REQ";		break;
	case DL_DETACH_REQ:	pstr = "DETACH_REQ";		break;
	case DL_BIND_REQ:	pstr = "BIND_REQ";		break;
	case DL_UNBIND_REQ:	pstr = "UNBIND_REQ";		break;
	case DL_INFO_REQ:	pstr = "INFO_REQ";		break;
	case DL_PROMISCON_REQ:	pstr = "PROMISCON_REQ";		break;
	case DL_PROMISCOFF_REQ:	pstr = "PROMISCOFF_REQ";	break;
	case DL_ENABMULTI_REQ:	pstr = "ENABMULTI_REQ";		break;
	case DL_DISABMULTI_REQ:	pstr = "DISABMULTI_REQ";	break;
	case DL_PHYS_ADDR_REQ:	pstr = "PHYS_ADDR_REQ";		break;
	case DL_SET_PHYS_ADDR_REQ:
				pstr = "SET_PHYS_ADDR_REQ";	break;
	default:		pstr = "unsupported";		break;
	}
	return (pstr);
}
#else /* DEBUG */
#define	DLERRORACK(qq, mm, cc, ee, xx) \
			(dlerrorack((qq), (mm), (cc), (ee), (xx)))
#define	DLOKACK(qq, mm, cc) \
			(dlokack((qq), (mm), (cc)))
#define	DLBINDACK(qq, mm, ss, aa, ll, xx, yy) \
			(dlbindack((qq), (mm), (ss), (aa), (ll), (xx), (yy)))
#define	DLPHYSADDRACK(qq, mm, aa, ll) \
			(dlphysaddrack((qq), (mm), (aa), (ll)))
#endif /* DEBUG */

#define	IDNDL_ADDR_IS_MULTICAST(ap)	(((ap)->ether_addr_octet[0] & 01) == 1)
/*
 * MIB II broadcast/multicast packets
 */
#define	IS_BROADCAST(ehp) \
		(ether_cmp(&(ehp)->ether_dhost, &etherbroadcastaddr) == 0)
#define	IS_MULTICAST(ehp) \
		IDNDL_ADDR_IS_MULTICAST(&(ehp)->ether_dhost)
#define	BUMP_InNUcast(sip, ehp)					\
		if (IS_BROADCAST(ehp)) {			\
			(sip)->si_kstat.si_brdcstrcv++;		\
		} else if (IS_MULTICAST(ehp)) {			\
			(sip)->si_kstat.si_multircv++;		\
		}
#define	BUMP_OutNUcast(sip, ehp)				\
		if (IS_BROADCAST(ehp)) {			\
			(sip)->si_kstat.si_brdcstxmt++;		\
		} else if (IS_MULTICAST(ehp)) {			\
			(sip)->si_kstat.si_multixmt++;		\
		}

/*
 * Function prototypes.
 */
static int	idndl_ioc_hdr_info(queue_t *, mblk_t *, int *);
static void	idndl_areq(queue_t *, mblk_t *);
static void	idndl_dreq(queue_t *, mblk_t *);
static void	idndl_breq(queue_t *, mblk_t *);
static void	idndl_ubreq(queue_t *, mblk_t *);
static void	idndl_ireq(queue_t *, mblk_t *);
static void	idndl_ponreq(queue_t *, mblk_t *);
static void	idndl_poffreq(queue_t *, mblk_t *);
static void	idndl_emreq(queue_t *, mblk_t *);
static void	idndl_dmreq(queue_t *, mblk_t *);
static void	idndl_pareq(queue_t *, mblk_t *);
#ifdef notdef
static void	idndl_spareq(queue_t *, mblk_t *);
#endif /* notdef */
static void	idndl_udreq(queue_t *, mblk_t *);
static void	serror(dev_info_t *dip, int idnerr, char *fmt, ...);
static mblk_t	*idndl_addudind(struct idn *, mblk_t *, struct ether_addr *,
				struct ether_addr *, int, ulong_t);
static void	idndl_setipq(struct idn *);
static int	idndl_mcmatch(struct idnstr *, struct ether_addr *);
static int	idndl_stat_kstat_update(kstat_t *ksp, int rw);

static int		_idndl_ether2domain(struct ether_addr *eap);
static struct idn	*_idndl_ether2sip(struct ether_addr *eap);


#define	IDNSAPMATCH(sap, type, flags) ((sap == type)? 1 : \
	((flags & IDNSALLSAP)? 1 : \
	((sap <= ETHERMTU) && sap && (type <= ETHERMTU))? 1 : 0))

/*
 * Our DL_INFO_ACK template.
 */
static	dl_info_ack_t idninfoack = {
	DL_INFO_ACK,			/* dl_primitive */
	0,				/* dl_max_sdu (see idndl_dlpi_init()) */
	0,				/* dl_min_sdu */
	IDNADDRL,			/* dl_addr_length */
	DL_ETHER, /* DL_OTHER, */	/* dl_mac_type */
	0,				/* dl_reserved */
	0,				/* dl_current_state */
	-2,				/* dl_sap_length */
	DL_CLDLS, /* DL_CODLS? */	/* dl_service_mode */
	0,				/* dl_qos_length */
	0,				/* dl_qos_offset */
	0,				/* dl_range_length */
	0,				/* dl_range_offset */
	DL_STYLE2,			/* dl_provider_style */
	sizeof (dl_info_ack_t),		/* dl_addr_offset */
	DL_VERSION_2,			/* dl_version */
	ETHERADDRL,			/* dl_brdcst_addr_length */
	sizeof (dl_info_ack_t) + IDNADDRL,	/* dl_brdcst_addr_offset */
	0				/* dl_growth */
};

/*
 * Ethernet broadcast address definition.
 */
static struct ether_addr	etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/*
 * --------------------------------------------------
 */
void
idndl_localetheraddr(struct idn *sip, struct ether_addr *eap)
{
	int		rv;
	int		instance;
	procname_t	proc = "idndl_localetheraddr";

	ASSERT(sip && sip->si_dip && eap);

	instance = ddi_get_instance(sip->si_dip);

	PR_DLPI("%s: getting local etheraddr...\n", proc);

	rv = idndl_domain_etheraddr(idn.localid, instance, eap);
	ASSERT(rv == 0);
}

int
idndl_domain_etheraddr(int domid, int channel, struct ether_addr *eap)
{
	uchar_t		netid;
	procname_t	proc = "idndl_domain_etheraddr";

	if (idn_domain[domid].dcpu == IDN_NIL_DCPU)
		return (-1);

	netid = (uchar_t)idn_domain[domid].dnetid;

	PR_DLPI("%s: dnetid = 0x%x, channel = 0x%x\n",
		proc, (uint_t)netid, channel);

#ifdef notdef
	localetheraddr(NULL, eap);

	PR_DLPI("%s: localetheraddr = %x:%x:%x:%x:%x:%x\n",
		proc, eap->ether_addr_octet[0], eap->ether_addr_octet[1],
		eap->ether_addr_octet[2], eap->ether_addr_octet[3],
		eap->ether_addr_octet[4], eap->ether_addr_octet[5]):
#endif /* notdef */

	eap->ether_addr_octet[IDNETHER_ZERO] = 0;
	eap->ether_addr_octet[IDNETHER_COOKIE1] = IDNETHER_COOKIE1_VAL;
	eap->ether_addr_octet[IDNETHER_COOKIE2] = IDNETHER_COOKIE2_VAL;
	eap->ether_addr_octet[IDNETHER_NETID] = netid;
	eap->ether_addr_octet[IDNETHER_CHANNEL] = (uchar_t)channel;
	eap->ether_addr_octet[IDNETHER_RESERVED] = IDNETHER_RESERVED_VAL;

	PR_DLPI("%s: domain %d: etheraddr = %x:%x:%x:%x:%x:%x\n",
		proc, domid,
		eap->ether_addr_octet[0], eap->ether_addr_octet[1],
		eap->ether_addr_octet[2], eap->ether_addr_octet[3],
		eap->ether_addr_octet[4], eap->ether_addr_octet[5]);

	return (0);
}

#ifdef DEBUG
/*
 */
static int
_idndl_ether2domain(struct ether_addr *eap)
{
	uchar_t	*eaop;

	eaop = eap->ether_addr_octet;

	ASSERT(IDNDL_ADDR_IS_MULTICAST(eap) ||
		((eaop[IDNETHER_COOKIE1] == IDNETHER_COOKIE1_VAL) &&
		    (eaop[IDNETHER_COOKIE2] == IDNETHER_COOKIE2_VAL)) ||
		((eaop[IDNETHER_COOKIE1] == 0xff) &&
		    (eaop[IDNETHER_COOKIE2] == 0xff)));
	/*
	 * Note that (IDN_NIL_DOMID) will be returned if ether address is
	 * a broadcast 0xff.
	 */
	return (IDN_NETID2DOMID(eaop[IDNETHER_NETID]));
}

/*
 */
static struct idn *
_idndl_ether2sip(struct ether_addr *eap)
{
	int		instance;
	struct idn	*sip;
	uchar_t		*eaop;
	procname_t	proc = "_idndl_ether2sip";

	eaop = eap->ether_addr_octet;

	if (!IDNDL_ADDR_IS_MULTICAST(eap) &&
	    (((eaop[IDNETHER_COOKIE1] != IDNETHER_COOKIE1_VAL) ||
	    (eaop[IDNETHER_COOKIE2] != IDNETHER_COOKIE2_VAL)) &&
	    ((eaop[IDNETHER_COOKIE1] != 0xff) ||
		(eaop[IDNETHER_COOKIE2] != 0xff)))) {

		cmn_err(CE_WARN,
			"IDN: 400: corrupted MAC header "
			"(exp %x or 0xffff, act 0x%x)",
			(IDNETHER_COOKIE1_VAL << 8) |
				IDNETHER_COOKIE2_VAL,
			(eaop[IDNETHER_COOKIE1] << 8) |
				eaop[IDNETHER_COOKIE2]);

		return (NULL);
	}

	if (IDNDL_ADDR_IS_MULTICAST(eap)) {
		PR_DLPI("%s: MULTICAST ADDR *** ERROR ***\n", proc);
		sip = NULL;
	} else if (eaop[IDNETHER_CHANNEL] == 0xff) {
		/*
		 * Received a broadcast.  Need to manually
		 * find anybody the first running sip and use it.
		 * XXX - kind of kludgy - single threads broadcasts.
		 */
		PR_DLPI("%s: BROADCAST CHANNEL *** ERROR ***\n", proc);
		sip = NULL;
	} else {
		instance = (int)eaop[IDNETHER_CHANNEL];

		sip = IDN_INST2SIP(instance);
	}

	return (sip);
}
#endif /* DEBUG */

void
idndl_dlpi_init()
{
	procname_t	proc = "idndl_dlpi_init";

	PR_DLPI("%s: setting dl_max_sdu to %ld (0x%lx) bytes\n",
		proc, IDN_MTU, IDN_MTU);
	/*
	 * This field is dynamic because the user may
	 * want to dynamically set it _before_ an IDNnet
	 * has been established via ndd(1M).
	 */
	idninfoack.dl_max_sdu = IDN_MTU;
}

static int
idndl_stat_kstat_update(kstat_t *ksp, int rw)
{
	struct idn	*sip;
	struct idn_kstat_named	*skp;

	sip = (struct idn *)ksp->ks_private;
	skp = (struct idn_kstat_named *)ksp->ks_data;

	if (rw == KSTAT_WRITE) {
#if 0
		bzero(&sg_kstat.gk_kstat, sizeof (sg_kstat.gk_kstat));
#endif /* 0 */
		bzero(&sip->si_kstat, sizeof (sip->si_kstat));

		sip->si_kstat.si_ipackets 	= skp->sk_ipackets.value.ul;
		sip->si_kstat.si_ierrors	= skp->sk_ierrors.value.ul;
		sip->si_kstat.si_opackets 	= skp->sk_opackets.value.ul;
		sip->si_kstat.si_oerrors	= skp->sk_oerrors.value.ul;
		sip->si_kstat.si_txcoll		= skp->sk_txcoll.value.ul;
		sip->si_kstat.si_rxcoll		= skp->sk_rxcoll.value.ul;
		sip->si_kstat.si_crc		= skp->sk_crc.value.ul;
		sip->si_kstat.si_buff		= skp->sk_buff.value.ul;
		sip->si_kstat.si_nolink		= skp->sk_nolink.value.ul;
		sip->si_kstat.si_linkdown	= skp->sk_linkdown.value.ul;
		sip->si_kstat.si_inits		= skp->sk_inits.value.ul;
		sip->si_kstat.si_nocanput	= skp->sk_nocanput.value.ul;
		sip->si_kstat.si_allocbfail	= skp->sk_allocbfail.value.ul;
		sip->si_kstat.si_notbufs	= skp->sk_notbufs.value.ul;
		sip->si_kstat.si_reclaim	= skp->sk_reclaim.value.ul;
		sip->si_kstat.si_smraddr	= skp->sk_smraddr.value.ul;
		sip->si_kstat.si_txmax		= skp->sk_txmax.value.ul;
		sip->si_kstat.si_txfull		= skp->sk_txfull.value.ul;
		sip->si_kstat.si_xdcall		= skp->sk_xdcall.value.ul;
		sip->si_kstat.si_sigsvr		= skp->sk_sigsvr.value.ul;
		sip->si_kstat.si_mboxcrc	= skp->sk_mboxcrc.value.ul;
		/*
		 * MIB II kstat variables
		 */
		sip->si_kstat.si_rcvbytes	= skp->sk_rcvbytes.value.ul;
		sip->si_kstat.si_xmtbytes	= skp->sk_xmtbytes.value.ul;
		sip->si_kstat.si_multircv	= skp->sk_multircv.value.ul;
		sip->si_kstat.si_multixmt	= skp->sk_multixmt.value.ul;
		sip->si_kstat.si_brdcstrcv	= skp->sk_brdcstrcv.value.ul;
		sip->si_kstat.si_brdcstxmt	= skp->sk_brdcstxmt.value.ul;
		sip->si_kstat.si_norcvbuf	= skp->sk_norcvbuf.value.ul;
		sip->si_kstat.si_noxmtbuf	= skp->sk_noxmtbuf.value.ul;
		/*
		 * PSARC 1997/198 : 64bit kstats
		 */
		sip->si_kstat.si_ipackets64	= skp->sk_ipackets64.value.ull;
		sip->si_kstat.si_opackets64	= skp->sk_opackets64.value.ull;
		sip->si_kstat.si_rbytes64	= skp->sk_rbytes64.value.ull;
		sip->si_kstat.si_obytes64	= skp->sk_obytes64.value.ull;
		/*
		 * PSARC 1997/247 : RFC 1643
		 */
		sip->si_kstat.si_fcs_errors	= skp->sk_fcs_errors.value.ul;
		sip->si_kstat.si_macxmt_errors	=
						skp->sk_macxmt_errors.value.ul;
		sip->si_kstat.si_toolong_errors	=
						skp->sk_toolong_errors.value.ul;
		sip->si_kstat.si_macrcv_errors	=
						skp->sk_macrcv_errors.value.ul;

		return (0);
	}

	skp->sk_ipackets.value.ul 	= sip->si_kstat.si_ipackets;
	skp->sk_ierrors.value.ul	= sip->si_kstat.si_ierrors;
	skp->sk_opackets.value.ul	= sip->si_kstat.si_opackets;
	skp->sk_oerrors.value.ul	= sip->si_kstat.si_oerrors;
	skp->sk_txcoll.value.ul		= sip->si_kstat.si_txcoll;
	skp->sk_rxcoll.value.ul		= sip->si_kstat.si_rxcoll;
	skp->sk_crc.value.ul		= sip->si_kstat.si_crc;
	skp->sk_buff.value.ul		= sip->si_kstat.si_buff;
	skp->sk_nolink.value.ul		= sip->si_kstat.si_nolink;
	skp->sk_linkdown.value.ul	= sip->si_kstat.si_linkdown;
	skp->sk_inits.value.ul		= sip->si_kstat.si_inits;
	skp->sk_nocanput.value.ul	= sip->si_kstat.si_nocanput;
	skp->sk_allocbfail.value.ul	= sip->si_kstat.si_allocbfail;
	skp->sk_notbufs.value.ul	= sip->si_kstat.si_notbufs;
	skp->sk_reclaim.value.ul	= sip->si_kstat.si_reclaim;
	skp->sk_smraddr.value.ul	= sip->si_kstat.si_smraddr;
	skp->sk_txfull.value.ul		= sip->si_kstat.si_txfull;
	skp->sk_txmax.value.ul		= sip->si_kstat.si_txmax;
	skp->sk_xdcall.value.ul		= sip->si_kstat.si_xdcall;
	skp->sk_sigsvr.value.ul		= sip->si_kstat.si_sigsvr;
	skp->sk_mboxcrc.value.ul	= sip->si_kstat.si_mboxcrc;
	/*
	 * MIB II kstat variables
	 */
	skp->sk_rcvbytes.value.ul	= sip->si_kstat.si_rcvbytes;
	skp->sk_xmtbytes.value.ul	= sip->si_kstat.si_xmtbytes;
	skp->sk_multircv.value.ul	= sip->si_kstat.si_multircv;
	skp->sk_multixmt.value.ul	= sip->si_kstat.si_multixmt;
	skp->sk_brdcstrcv.value.ul	= sip->si_kstat.si_brdcstrcv;
	skp->sk_brdcstxmt.value.ul	= sip->si_kstat.si_brdcstxmt;
	skp->sk_norcvbuf.value.ul	= sip->si_kstat.si_norcvbuf;
	skp->sk_noxmtbuf.value.ul	= sip->si_kstat.si_noxmtbuf;
	/*
	 * PSARC 1997/198 : 64bit kstats
	 */
	skp->sk_ipackets64.value.ull	= sip->si_kstat.si_ipackets64;
	skp->sk_opackets64.value.ull	= sip->si_kstat.si_opackets64;
	skp->sk_rbytes64.value.ull	= sip->si_kstat.si_rbytes64;
	skp->sk_obytes64.value.ull	= sip->si_kstat.si_obytes64;
	/*
	 * PSARC 1997/247 : RFC 1643
	 */
	skp->sk_fcs_errors.value.ul	= sip->si_kstat.si_fcs_errors;
	skp->sk_macxmt_errors.value.ul	= sip->si_kstat.si_macxmt_errors;
	skp->sk_toolong_errors.value.ul	= sip->si_kstat.si_toolong_errors;
	skp->sk_macrcv_errors.value.ul	= sip->si_kstat.si_macrcv_errors;

	return (0);
}

void
idndl_statinit(struct idn *sip)
{
	struct	kstat		*ksp;
	struct	idn_kstat_named	*skp;

#ifdef	kstat
	if ((ksp = kstat_create(IDNNAME, ddi_get_instance(sip->si_dip),
		NULL, "net", KSTAT_TYPE_NAMED,
		sizeof (struct idn_kstat_named) / sizeof (kstat_named_t),
		KSTAT_FLAG_PERSISTENT)) == NULL) {
#else
	if ((ksp = kstat_create(IDNNAME, ddi_get_instance(sip->si_dip),
		NULL, "net", KSTAT_TYPE_NAMED,
		sizeof (struct idn_kstat_named) /
		sizeof (kstat_named_t), 0)) == NULL) {
#endif	/* kstat */
		serror(sip->si_dip, 450, "kstat_create failed");
		return;
	}

	sip->si_ksp = ksp;
	skp = (struct idn_kstat_named *)(ksp->ks_data);
	kstat_named_init(&skp->sk_ipackets,		"ipackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_ierrors,		"ierrors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_opackets,		"opackets",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_oerrors,		"oerrors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_txcoll,		"collisions",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_rxcoll,		"rx_collisions",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_crc,			"crc",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_buff,			"buff",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_nolink,		"nolink",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_linkdown,		"linkdown",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_inits,		"inits",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_nocanput,		"nocanput",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_allocbfail,		"allocbfail",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_notbufs,		"notbufs",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_reclaim,		"reclaim",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_smraddr,		"smraddr",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_txmax,		"txmax",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_txfull,		"txfull",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_xdcall,		"xdcall",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_sigsvr,		"sigsvr",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_mboxcrc,		"mboxcrc",
		KSTAT_DATA_ULONG);
	/*
	 * MIB II kstat variables
	 */
	kstat_named_init(&skp->sk_rcvbytes,		"rbytes",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_xmtbytes,		"obytes",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_multircv,		"multircv",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_multixmt,		"multixmt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_brdcstrcv,		"brdcstrcv",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_brdcstxmt,		"brdcstxmt",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_norcvbuf,		"norcvbuf",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_noxmtbuf,		"noxmtbuf",
		KSTAT_DATA_ULONG);
	/*
	 * PSARC 1997/198 : 64bit kstats
	 */
	kstat_named_init(&skp->sk_ipackets64,		"ipackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&skp->sk_opackets64,		"opackets64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&skp->sk_rbytes64,		"rbytes64",
		KSTAT_DATA_ULONGLONG);
	kstat_named_init(&skp->sk_obytes64,		"obytes64",
		KSTAT_DATA_ULONGLONG);
	/*
	 * PSARC 1997/247 : RFC 1643
	 */
	kstat_named_init(&skp->sk_fcs_errors,		"fcs_errors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_macxmt_errors,	"macxmt_errors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_toolong_errors,	"toolong_errors",
		KSTAT_DATA_ULONG);
	kstat_named_init(&skp->sk_macrcv_errors,	"macrcv_errors",
		KSTAT_DATA_ULONG);

	ksp->ks_update = idndl_stat_kstat_update;
	ksp->ks_private = (void *)sip;
	kstat_install(ksp);
}

void
idndl_proto(queue_t *wq, mblk_t *mp)
{
	union DL_primitives	*dlp;
	struct idnstr		*stp;
	t_uscalar_t		prim;
	procname_t		proc = "idndl_proto";

	stp = (struct idnstr *)wq->q_ptr;
	if (MBLKL(mp) < sizeof (t_uscalar_t)) {
		/*
		 * Gotta at least have enough room to hold
		 * the primitive!
		 */
		DLERRORACK(wq, mp, -1, DL_BADPRIM, 0);
		return;
	}
	dlp = (union DL_primitives *)mp->b_rptr;
	prim = dlp->dl_primitive;

	TRACE_2(TR_FAC_IDN, TR_IDN_PROTO_START,
		"idndl_proto start:  wq %p dlprim %X", wq, prim);

#ifdef DEBUG
	PR_DLPI("%s: stp = 0x%p, wq = 0x%p, dlprim = 0x%x(%s)\n",
		proc, (void *)stp, (void *)wq, prim, dlprim2str(prim));
#endif /* DEBUG */

	rw_enter(&stp->ss_rwlock, RW_WRITER);

	switch (prim) {
	case DL_UNITDATA_REQ:
		idndl_udreq(wq, mp);
		break;

	case DL_ATTACH_REQ:
		idndl_areq(wq, mp);
		break;

	case DL_DETACH_REQ:
		idndl_dreq(wq, mp);
		break;

	case DL_BIND_REQ:
		idndl_breq(wq, mp);
		break;

	case DL_UNBIND_REQ:
		idndl_ubreq(wq, mp);
		break;

	case DL_INFO_REQ:
		idndl_ireq(wq, mp);
		break;

	case DL_PROMISCON_REQ:
		idndl_ponreq(wq, mp);
		break;

	case DL_PROMISCOFF_REQ:
		idndl_poffreq(wq, mp);
		break;

	case DL_ENABMULTI_REQ:
		idndl_emreq(wq, mp);
		break;

	case DL_DISABMULTI_REQ:
		idndl_dmreq(wq, mp);
		break;

	case DL_PHYS_ADDR_REQ:
		idndl_pareq(wq, mp);
		break;

#ifdef notdef
	/*
	 * We cannot allow this in IDN-land because we
	 * rely on the ethernet (physical) address to determine
	 * where to target the message.  Recall that unlike
	 * ethernet we simply cannot dump junk on the wire and
	 * expect it to automatically find its destination.
	 * In the IDN we need to target the destination.
	 * Note that if we used POINT-TO-POINT then we wouldn't
	 * have to worry about the physical address since each
	 * domain connection would have a separate queue.
	 * However, ptp then requires multiple interfaces at
	 * the appl level as opposed to a single one for all
	 * of idn.  We opt for the simpler single interface (idn0).
	 */
	case DL_SET_PHYS_ADDR_REQ:
		idndl_spareq(wq, mp);
		break;
#endif /* notdef */

	default:
		DLERRORACK(wq, mp, prim, DL_UNSUPPORTED, 0);
		break;
	}

	TRACE_2(TR_FAC_IDN, TR_IDN_PROTO_END,
		"idnproto end:  wq %p dlprim %X", wq, prim);

	rw_exit(&stp->ss_rwlock);
}

int
idnioc_dlpi(queue_t *wq, mblk_t *mp, int *argsizep)
{
	int	rv = 0;
	struct	iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	struct	idnstr	*stp  = (struct idnstr *)wq->q_ptr;
	procname_t	proc = "idnioc_dlpi";

	*argsizep = 0;

	switch (iocp->ioc_cmd) {
	case DLIOCRAW:			/* raw M_DATA mode */
		PR_DLPI("%s: cmd = DLIOCRAW\n", proc);
		stp->ss_flags |= IDNSRAW;
		break;

	case DL_IOC_HDR_INFO:		/* M_DATA "fastpath" info request */
		PR_DLPI("%s: cmd = DL_IOC_HDR_INFO\n", proc);
		rv = idndl_ioc_hdr_info(wq, mp, argsizep);
		break;

	default:
		PR_DLPI("%s: invalid cmd 0x%x\n", proc, iocp->ioc_cmd);
		rv = EINVAL;
		break;
	}
	return (rv);
}

/*
 * M_DATA "fastpath" info request.
 * Following the M_IOCTL mblk should come a DL_UNITDATA_REQ mblk.
 * We ack with an M_IOCACK pointing to the original DL_UNITDATA_REQ mblk
 * followed by an mblk containing the raw ethernet header corresponding
 * to the destination address.  Subsequently, we may receive M_DATA
 * msgs which start with this header and may send up
 * up M_DATA msgs with b_rptr pointing to a (ulong) group address
 * indicator followed by the network-layer data (IP packet header).
 * This is all selectable on a per-Stream basis.
 */
static int
idndl_ioc_hdr_info(queue_t *wq, mblk_t *mp, int *argsizep)
{
	mblk_t			*nmp;
	struct idnstr		*stp;
	struct idndladdr	*dlap;
	dl_unitdata_req_t	*dludp;
	struct ether_header	*headerp;
	struct idn		*sip;
	int	off, len;
	int	padding = 0;
	int	error;
	procname_t		proc = "idndl_ioc_hdr_info";

	stp = (struct idnstr *)wq->q_ptr;
	sip = stp->ss_sip;
	if (sip == NULL) {
		PR_DLPI("%s: NULL sip (ret EINVAL)\n", proc);
		return (EINVAL);
	}

	error = miocpullup(mp, sizeof (dl_unitdata_req_t) + IDNADDRL);
	if (error != 0) {
		PR_DLPI("%s: sanity error (ret %d)\n", proc, error);
		return (error);
	}

	/*
	 * Sanity check the DL_UNITDATA_REQ destination address
	 * offset and length values.
	 */
	dludp = (dl_unitdata_req_t *)mp->b_cont->b_rptr;
	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;
	if (dludp->dl_primitive != DL_UNITDATA_REQ ||
	    !MBLKIN(mp->b_cont, off, len) || len != IDNADDRL) {
		PR_DLPI("%s: off(0x%x)/len(%d) error (ret EINVAL)\n",
		    proc, off, len);
		return (EINVAL);
	}

	dlap = (struct idndladdr *)(mp->b_cont->b_rptr + off);

	/*
	 * Allocate a new mblk to hold the ether header.
	 */
	nmp = allocb(sizeof (struct ether_header) + padding, BPRI_MED);
	if (nmp == NULL) {
		IDN_KSTAT_INC(sip, si_allocbfail);
		return (ENOMEM);
	}
	nmp->b_rptr += padding;
	nmp->b_wptr = nmp->b_rptr + sizeof (struct ether_header);

	/*
	 * Fill in the ether header.
	 */
	headerp = (struct ether_header *)nmp->b_rptr;
	ether_copy(&dlap->dl_phys, &headerp->ether_dhost);
	ether_copy(&sip->si_ouraddr, &headerp->ether_shost);
	headerp->ether_type = dlap->dl_sap;

	/*
	 * Link new mblk in after the "request" mblks.
	 */
	linkb(mp, nmp);

	stp->ss_flags |= IDNSFAST;

	/*
	 * XXX Don't bother calling idndl_setipq() here.
	 */

	if (argsizep)
		*argsizep = msgsize(mp->b_cont);

	return (0);
}

static void
idndl_areq(queue_t *wq, mblk_t *mp)
{
	struct idnstr		*stp;
	union DL_primitives	*dlp;
	struct idn		*sip;
	int	ppa;
	procname_t	proc = "idndl_areq";

	stp = (struct idnstr *)wq->q_ptr;
	dlp = (union DL_primitives *)mp->b_rptr;

	if (MBLKL(mp) < DL_ATTACH_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_ATTACH_REQ, DL_BADPRIM, 0);
		return;
	}

	if (stp->ss_state != DL_UNATTACHED) {
		DLERRORACK(wq, mp, DL_ATTACH_REQ, DL_OUTSTATE, 0);
		return;
	}

	ppa = dlp->attach_req.dl_ppa;

	/*
	 * Valid ppa?
	 */
	if (ppa == -1 || qassociate(wq, ppa) != 0) {
		PR_DLPI("%s: bad ppa %d\n", proc, ppa);
		DLERRORACK(wq, mp, dlp->dl_primitive, DL_BADPPA, 0);
		return;
	}
	mutex_enter(&idn.siplock);
	for (sip = idn.sip; sip; sip = sip->si_nextp) {
		if (ppa == ddi_get_instance(sip->si_dip))
			break;
	}
	mutex_exit(&idn.siplock);
	ASSERT(sip != NULL);	/* qassociate() succeeded */

	/*
	 * Has device been initialized?  Do so if necessary.
	 */
	if ((sip->si_flags & IDNRUNNING) == 0) {
		if (idndl_init(sip)) {
			DLERRORACK(wq, mp, dlp->dl_primitive,
					DL_INITFAILED, 0);
			(void) qassociate(wq, -1);
			return;
		}
	}

	/*
	 * Set link to device and update our state.
	 */
	stp->ss_sip = sip;
	stp->ss_state = DL_UNBOUND;

	DLOKACK(wq, mp, DL_ATTACH_REQ);
}

static void
idndl_dreq(queue_t *wq, mblk_t *mp)
{
	struct idnstr	*stp;

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_DETACH_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_DETACH_REQ, DL_BADPRIM, 0);
		return;
	}

	if (stp->ss_state != DL_UNBOUND) {
		DLERRORACK(wq, mp, DL_DETACH_REQ, DL_OUTSTATE, 0);
		return;
	}

	idndl_dodetach(stp);
	(void) qassociate(wq, -1);
	DLOKACK(wq, mp, DL_DETACH_REQ);
}

/*
 * Detach a Stream from an interface.
 */
void
idndl_dodetach(struct idnstr *stp)
{
	struct idnstr	*tstp;
	struct idn	*sip;
	int		reinit = 0;

	ASSERT(stp->ss_sip);

	sip = stp->ss_sip;
	stp->ss_sip = NULL;

	/*
	 * Disable promiscuous mode if on.
	 */
	if (stp->ss_flags & IDNSALLPHYS) {
		stp->ss_flags &= ~IDNSALLPHYS;
		reinit = 1;
	}

	/*
	 * Disable ALLMULTI mode if on.
	 */
	if (stp->ss_flags & IDNSALLMULTI) {
		stp->ss_flags &= ~IDNSALLMULTI;
		reinit = 1;
	}

	/*
	 * Disable any Multicast Addresses.
	 */
	stp->ss_mccount = 0;
	if (stp->ss_mctab) {
		kmem_free(stp->ss_mctab, IDNMCALLOC);
		stp->ss_mctab = NULL;
		reinit = 1;
	}

	/*
	 * Detach from device structure.
	 * Uninit the device when no other streams are attached to it.
	 */
	rw_enter(&idn.struprwlock, RW_READER);
	for (tstp = idn.strup; tstp; tstp = tstp->ss_nextp)
		if (tstp->ss_sip == sip)
			break;
	rw_exit(&idn.struprwlock);

	if (tstp == NULL)
		idndl_uninit(sip);
	else if (reinit)
		(void) idndl_init(sip);

	stp->ss_state = DL_UNATTACHED;

	idndl_setipq(sip);
}

static void
idndl_breq(queue_t *wq, mblk_t *mp)
{
	struct idnstr		*stp;
	union DL_primitives	*dlp;
	struct idn		*sip;
	struct idndladdr	idnaddr;
	t_uscalar_t		sap;
	int		xidtest;
	procname_t	proc = "idndl_breq";

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_BIND_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_BIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (stp->ss_state != DL_UNBOUND) {
		DLERRORACK(wq, mp, DL_BIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;

	if (dlp->bind_req.dl_service_mode != idninfoack.dl_service_mode) {
		DLERRORACK(wq, mp, DL_BIND_REQ, DL_UNSUPPORTED, 0);
		return;
	}

	sip = stp->ss_sip;
	sap = dlp->bind_req.dl_sap;
	xidtest = dlp->bind_req.dl_xidtest_flg;

	ASSERT(sip);

	if (xidtest) {
		DLERRORACK(wq, mp, DL_BIND_REQ, DL_NOAUTO, 0);
		return;
	}

	if (sap > ETHERTYPE_MAX) {
		DLERRORACK(wq, mp, dlp->dl_primitive, DL_BADSAP, 0);
		return;
	}

	/*
	 * Save SAP value for this Stream and change state.
	 */
	stp->ss_sap = sap;
	stp->ss_state = DL_IDLE;

	idnaddr.dl_sap = sap;
	ether_copy(&sip->si_ouraddr, &idnaddr.dl_phys);

	if (IS_ETHERTYPE_IP(sap)) {
		int	channel;

		channel =
			(int)sip->si_ouraddr.ether_addr_octet[IDNETHER_CHANNEL];
		PR_DLPI("%s: IP SAP, opening channel %d\n", proc, channel);
		if (idn_open_channel(channel)) {
			PR_DLPI("%s: FAILED TO OPEN CHANNEL %d\n",
				proc, channel);
			DLERRORACK(wq, mp, dlp->dl_primitive, DL_NOADDR, 0);
			return;
		}
	}
	DLBINDACK(wq, mp, sap, &idnaddr, IDNADDRL, 0, 0);

	idndl_setipq(sip);
}

static void
idndl_ubreq(queue_t *wq, mblk_t *mp)
{
	struct idnstr	*stp;
	procname_t	proc = "idndl_ubreq";

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_UNBIND_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_UNBIND_REQ, DL_BADPRIM, 0);
		return;
	}

	if (stp->ss_state != DL_IDLE) {
		DLERRORACK(wq, mp, DL_UNBIND_REQ, DL_OUTSTATE, 0);
		return;
	}

	stp->ss_state = DL_UNBOUND;

	if (IS_ETHERTYPE_IP(stp->ss_sap)) {
		struct idn	*sip;
		int		channel;

		sip = stp->ss_sip;
		channel =
			(int)sip->si_ouraddr.ether_addr_octet[IDNETHER_CHANNEL];
		PR_DLPI("%s: IP SAP, unbinding channel %d\n", proc, channel);
		/*
		 * We need to do an "soft" close since there's a
		 * potential that we've been called by one of the
		 * IDN data server/dispatcher threads!  We'll deadlock
		 * if we attempt a "hard" close of the channel from here.
		 */
		idn_close_channel(channel, IDNCHAN_SOFT_CLOSE);
	}

	stp->ss_sap = 0;

	DLOKACK(wq, mp, DL_UNBIND_REQ);

	idndl_setipq(stp->ss_sip);
}

static void
idndl_ireq(queue_t *wq, mblk_t *mp)
{
	struct idnstr		*stp;
	dl_info_ack_t		*dlip;
	struct idndladdr	*dlap;
	struct ether_addr	*ep;
	int	size;

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_INFO_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_INFO_REQ, DL_BADPRIM, 0);
		return;
	}

	/*
	 * Exchange current msg for a DL_INFO_ACK.
	 */
	size = sizeof (dl_info_ack_t) + IDNADDRL + ETHERADDRL;
	if ((mp = mexchange(wq, mp, size, M_PCPROTO, DL_INFO_ACK)) == NULL)
		return;

	/*
	 * Fill in the DL_INFO_ACK fields and reply.
	 */
	dlip = (dl_info_ack_t *)mp->b_rptr;
	ASSERT(idninfoack.dl_max_sdu);
	*dlip = idninfoack;
	dlip->dl_current_state = stp->ss_state;
	dlap = (struct idndladdr *)(mp->b_rptr + dlip->dl_addr_offset);
	dlap->dl_sap = stp->ss_sap;
	if (stp->ss_sip) {
		ether_copy(&stp->ss_sip->si_ouraddr, &dlap->dl_phys);
	} else {
		bzero(&dlap->dl_phys, ETHERADDRL);
	}
	ep = (struct ether_addr *)(mp->b_rptr + dlip->dl_brdcst_addr_offset);
	ether_copy(&etherbroadcastaddr, ep);

	qreply(wq, mp);
}

static void
idndl_ponreq(queue_t *wq, mblk_t *mp)
{
	struct idnstr	*stp;

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCON_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_PROMISCON_REQ, DL_BADPRIM, 0);
		return;
	}

	switch (((dl_promiscon_req_t *)mp->b_rptr)->dl_level) {
	case DL_PROMISC_PHYS:
		stp->ss_flags |= IDNSALLPHYS;
		break;

	case DL_PROMISC_SAP:
		stp->ss_flags |= IDNSALLSAP;
		break;

	case DL_PROMISC_MULTI:
		stp->ss_flags |= IDNSALLMULTI;
		break;

	default:
		DLERRORACK(wq, mp, DL_PROMISCON_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	if (stp->ss_sip)
		(void) idndl_init(stp->ss_sip);

	if (stp->ss_sip)
		idndl_setipq(stp->ss_sip);

	DLOKACK(wq, mp, DL_PROMISCON_REQ);
}

static void
idndl_poffreq(queue_t *wq, mblk_t *mp)
{
	struct idnstr	*stp;
	int		flag;

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_PROMISCOFF_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_PROMISCOFF_REQ, DL_BADPRIM, 0);
		return;
	}

	switch (((dl_promiscoff_req_t *)mp->b_rptr)->dl_level) {
	case DL_PROMISC_PHYS:
		flag = IDNSALLPHYS;
		break;

	case DL_PROMISC_SAP:
		flag = IDNSALLSAP;
		break;

	case DL_PROMISC_MULTI:
		flag = IDNSALLMULTI;
		break;

	default:
		DLERRORACK(wq, mp, DL_PROMISCOFF_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	if ((stp->ss_flags & flag) == 0) {
		DLERRORACK(wq, mp, DL_PROMISCOFF_REQ, DL_NOTENAB, 0);
		return;
	}

	stp->ss_flags &= ~flag;

	if (stp->ss_sip)
		(void) idndl_init(stp->ss_sip);

	if (stp->ss_sip)
		idndl_setipq(stp->ss_sip);

	DLOKACK(wq, mp, DL_PROMISCOFF_REQ);
}

static void
idndl_emreq(queue_t *wq, mblk_t *mp)
{
	struct idnstr		*stp;
	union DL_primitives	*dlp;
	struct ether_addr	*addrp;
	int	off;
	int	len;
	int	i;

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_ENABMULTI_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_ENABMULTI_REQ, DL_BADPRIM, 0);
		return;
	}

	if (stp->ss_state == DL_UNATTACHED) {
		DLERRORACK(wq, mp, DL_ENABMULTI_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->enabmulti_req.dl_addr_length;
	off = dlp->enabmulti_req.dl_addr_offset;
	addrp = (struct ether_addr *)(mp->b_rptr + off);

	if ((len != ETHERADDRL) ||
		!MBLKIN(mp, off, len) ||
		!IDNDL_ADDR_IS_MULTICAST(addrp)) {
		DLERRORACK(wq, mp, DL_ENABMULTI_REQ, DL_BADADDR, 0);
		return;
	}

	if ((stp->ss_mccount + 1) >= IDNMAXMC) {
		DLERRORACK(wq, mp, DL_ENABMULTI_REQ, DL_TOOMANY, 0);
		return;
	}

	/*
	 * Allocate table on first request.
	 */
	if (stp->ss_mctab == NULL)
		stp->ss_mctab = kmem_alloc(IDNMCALLOC, KM_SLEEP);

	/*
	 * Check to see if the address is already in the table.
	 * Bug 1209733:
	 * If present in the table, add the entry to the end of the table
	 * and return without initializing the hardware.
	 */
	for (i = 0; i < stp->ss_mccount; i++) {
		if (ether_cmp(&stp->ss_mctab[i], addrp) == 0) {
			stp->ss_mctab[stp->ss_mccount++] = *addrp;
			DLOKACK(wq, mp, DL_ENABMULTI_REQ);
			return;
		}
	}

	stp->ss_mctab[stp->ss_mccount++] = *addrp;

	(void) idndl_init(stp->ss_sip);

	DLOKACK(wq, mp, DL_ENABMULTI_REQ);
}

static void
idndl_dmreq(queue_t *wq, mblk_t *mp)
{
	struct idnstr		*stp;
	union DL_primitives	*dlp;
	struct ether_addr	*addrp;
	int	off;
	int	len;
	int	i;

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_DISABMULTI_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_DISABMULTI_REQ, DL_BADPRIM, 0);
		return;
	}

	if (stp->ss_state == DL_UNATTACHED) {
		DLERRORACK(wq, mp, DL_DISABMULTI_REQ, DL_OUTSTATE, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->disabmulti_req.dl_addr_length;
	off = dlp->disabmulti_req.dl_addr_offset;
	addrp = (struct ether_addr *)(mp->b_rptr + off);

	if ((len != ETHERADDRL) || !MBLKIN(mp, off, len)) {
		DLERRORACK(wq, mp, DL_DISABMULTI_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * Find the address in the multicast table for this Stream
	 * and delete it by shifting all subsequent multicast
	 * table entries over one.
	 */
	for (i = 0; i < stp->ss_mccount; i++)
		if (ether_cmp(addrp, &stp->ss_mctab[i]) == 0) {
			bcopy(&stp->ss_mctab[i+1],
				&stp->ss_mctab[i],
				((stp->ss_mccount - i) *
				sizeof (struct ether_addr)));
			stp->ss_mccount--;
			(void) idndl_init(stp->ss_sip);
			DLOKACK(wq, mp, DL_DISABMULTI_REQ);
			return;
		}
	DLERRORACK(wq, mp, DL_DISABMULTI_REQ, DL_NOTENAB, 0);
}

static void
idndl_pareq(queue_t *wq, mblk_t *mp)
{
	struct idnstr		*stp;
	union DL_primitives	*dlp;
	int			type;
	struct idn		*sip;
	struct ether_addr	addr;

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_PHYS_ADDR_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlp  = (union DL_primitives *)mp->b_rptr;
	type = dlp->physaddr_req.dl_addr_type;
	sip  = stp->ss_sip;

	if (sip == NULL) {
		DLERRORACK(wq, mp, DL_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	switch (type) {
	case DL_FACT_PHYS_ADDR:
		idndl_localetheraddr(sip, &addr);
		break;

	case DL_CURR_PHYS_ADDR:
		ether_copy(&sip->si_ouraddr, &addr);
		break;

	default:
		DLERRORACK(wq, mp, DL_PHYS_ADDR_REQ, DL_NOTSUPPORTED, 0);
		return;
	}

	DLPHYSADDRACK(wq, mp, &addr, ETHERADDRL);
}

#ifdef notdef
static void
idndl_spareq(queue_t *wq, mblk_t *mp)
{
	struct idnstr		*stp;
	union DL_primitives	*dlp;
	int	off;
	int	len;
	struct ether_addr	*addrp;
	struct idn		*sip;

	stp = (struct idnstr *)wq->q_ptr;

	if (MBLKL(mp) < DL_SET_PHYS_ADDR_REQ_SIZE) {
		DLERRORACK(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	dlp = (union DL_primitives *)mp->b_rptr;
	len = dlp->set_physaddr_req.dl_addr_length;
	off = dlp->set_physaddr_req.dl_addr_offset;

	if (!MBLKIN(mp, off, len)) {
		DLERRORACK(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADPRIM, 0);
		return;
	}

	addrp = (struct ether_addr *)(mp->b_rptr + off);

	/*
	 * Error if length of address isn't right or the address
	 * specified is a multicast or broadcast address.
	 */
	if ((len != ETHERADDRL) ||
	    IDNDL_ADDR_IS_MULTICAST(addrp) ||
	    (ether_cmp(addrp, &etherbroadcastaddr) == 0)) {
		DLERRORACK(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_BADADDR, 0);
		return;
	}

	/*
	 * Error if this stream is not attached to a device.
	 */
	if ((sip = stp->ss_sip) == NULL) {
		DLERRORACK(wq, mp, DL_SET_PHYS_ADDR_REQ, DL_OUTSTATE, 0);
		return;
	}

	/*
	 * Set new interface local address and re-init device.
	 * This is destructive to any other streams attached
	 * to this device.
	 */
	ether_copy(addrp, &sip->si_ouraddr);
	(void) idndl_init(stp->ss_sip);

	DLOKACK(wq, mp, DL_SET_PHYS_ADDR_REQ);
}
#endif /* notdef */

static void
idndl_udreq(queue_t *wq, mblk_t *mp)
{
	struct idnstr			*stp;
	register struct idn		*sip;
	register dl_unitdata_req_t	*dludp;
	mblk_t				*nmp;
	struct idndladdr	*dlap;
	struct ether_header	*headerp;
	t_uscalar_t		off, len;
	t_uscalar_t		sap;

	stp = (struct idnstr *)wq->q_ptr;
	sip = stp->ss_sip;

	if (stp->ss_state != DL_IDLE) {
		DLERRORACK(wq, mp, DL_UNITDATA_REQ, DL_OUTSTATE, 0);
		return;
	}

	dludp = (dl_unitdata_req_t *)mp->b_rptr;

	off = dludp->dl_dest_addr_offset;
	len = dludp->dl_dest_addr_length;

	/*
	 * Validate destination address format.
	 */
	if (!MBLKIN(mp, off, len) || (len != IDNADDRL)) {
		dluderrorind(wq, mp, mp->b_rptr + off, len, DL_BADADDR, 0);
		return;
	}

	/*
	 * Error if no M_DATA follows.
	 */
	nmp = mp->b_cont;
	if (nmp == NULL) {
		dluderrorind(wq, mp, mp->b_rptr + off, len, DL_BADDATA, 0);
		return;
	}

	dlap = (struct idndladdr *)(mp->b_rptr + off);

	/*
	 * Create ethernet header by either prepending it onto the
	 * next mblk if potential, or reusing the M_PROTO block if not.
	 */
	if ((DB_REF(nmp) == 1) &&
	    (MBLKHEAD(nmp) >= sizeof (struct ether_header)) &&
	    (((ulong_t)nmp->b_rptr & 0x1) == 0)) {
		nmp->b_rptr -= sizeof (struct ether_header);
		headerp = (struct ether_header *)nmp->b_rptr;
		ether_copy(&dlap->dl_phys, &headerp->ether_dhost);
		ether_copy(&sip->si_ouraddr, &headerp->ether_shost);
		sap = dlap->dl_sap;
		freeb(mp);
		mp = nmp;
	} else {
		DB_TYPE(mp) = M_DATA;
		headerp = (struct ether_header *)mp->b_rptr;
		mp->b_wptr = mp->b_rptr + sizeof (struct ether_header);
		ether_copy(&dlap->dl_phys, &headerp->ether_dhost);
		ether_copy(&sip->si_ouraddr, &headerp->ether_shost);
		sap = dlap->dl_sap;
	}

	/*
	 * For transmitting, the driver looks at the
	 * sap field of the DL_BIND_REQ being 0 in addition to the type
	 * field in the range [0-1500]. If either is true, then the driver
	 * computes the length of the message, not including initial M_PROTO
	 * mblk (message block), of all subsequent DL_UNITDATA_REQ messages and
	 * transmits 802.3 frames that have this value in the MAC frame header
	 * length field.
	 */
	if ((sap <= ETHERMTU) || (stp->ss_sap == 0))
		headerp->ether_type = (msgsize(mp) -
					sizeof (struct ether_header));
	else
		headerp->ether_type = sap;

	/*
	 * The data transfer code requires only READ access (idn_wput_data).
	 */
	rw_downgrade(&stp->ss_rwlock);
	(void) idndl_start(wq, mp, sip);
}

int
idndl_start(queue_t *wq, register mblk_t *mp, register struct idn *sip)
{
	int		rv = 0;
	int		flags;
	int		broadcast = 0;
	int		goagain = 0;
	int		goqueue = 0;
	int		msgcount;
	char		channel;
	mblk_t		*nmp = NULL;
	int		domid;
	domainset_t	domset;
	idn_netaddr_t	netaddr;
	struct idnstr	*stp;
	struct ether_header	*ehp;
	procname_t	proc = "idndl_start";

	ASSERT(DB_TYPE(mp) == M_DATA);

	stp = (struct idnstr *)wq->q_ptr;
	ASSERT(sip == stp->ss_sip);
	flags = sip->si_flags;
	channel = (char)sip->si_ouraddr.ether_addr_octet[IDNETHER_CHANNEL];

	ASSERT(RW_READ_HELD(&stp->ss_rwlock));

	if ((flags & (IDNRUNNING|IDNPROMISC)) != IDNRUNNING) {
		if (!(flags & IDNRUNNING))
			goto requeue;
	}

	/*
	 * Translate an IDN ethernet address into a domainid
	 * and idnaddr.
	 */
	ehp = (struct ether_header *)mp->b_rptr;
	domid = IDNDL_ETHER2DOMAIN(&ehp->ether_dhost);

	/*
	 * update MIB II statistics
	 */
	BUMP_OutNUcast(sip, ehp);

	PR_DLPI("%s: ether %x:%x:%x:%x:%x:%x (domid = %d)\n",
		proc, ehp->ether_dhost.ether_addr_octet[0],
		ehp->ether_dhost.ether_addr_octet[1],
		ehp->ether_dhost.ether_addr_octet[2],
		ehp->ether_dhost.ether_addr_octet[3],
		ehp->ether_dhost.ether_addr_octet[4],
		ehp->ether_dhost.ether_addr_octet[5],
		domid);

	netaddr.net.chan = channel;
	PR_DLPI("%s: source channel = %d\n", proc, (int)channel);

	if ((ether_cmp(&ehp->ether_dhost, &etherbroadcastaddr) == 0) ||
			IDNDL_ADDR_IS_MULTICAST(&ehp->ether_dhost)) {
		/*
		 * Caller wants to broadcast!
		 * XXX - Send to everybody but ourself???
		 */
		PR_DLPI("%s: broadcast/multicast requested!!!\n", proc);
		domset = ~DOMAINSET(idn.localid);
		broadcast = 1;
		netaddr.net.netid = IDN_BROADCAST_ALLNETID;
		if ((flags & IDNPROMISC) &&
		    ((nmp = copymsg(mp)) == NULL)) {
			IDN_KSTAT_INC(sip, si_allocbfail);
		}

	} else if (domid != IDN_NIL_DOMID) {
		domset = DOMAINSET(domid);
		netaddr.net.netid = idn_domain[domid].dnetid;
		if ((flags & IDNPROMISC) &&
		    ((nmp = copymsg(mp)) == NULL)) {
			IDN_KSTAT_INC(sip, si_allocbfail);
		}
	} else {
#ifdef DEBUG
		int	netid;

		netid = (int)
			ehp->ether_dhost.ether_addr_octet[IDNETHER_NETID];
		PR_DLPI("%s: no domain found for netid 0x%x\n",
			proc, netid);
#endif /* DEBUG */
		goto bad;
	}

	PR_DLPI("%s: target domainset = 0x%x\n", proc, domset);

	if ((domset == 0) && (domid == IDN_NIL_DOMID)) {
		PR_DLPI("%s: not connected to any domains!!  Bailing\n",
			proc);
		goto bad;
	}
	/*
	 * XXX - Need to find a better way to handle broadcasting.
	 *	 Should be able to take advantage of the fact that
	 *	 we can broadcast XDC's (xdc_some).  Need to use
	 *	 atomic counter (semaphore) instead of binary
	 *	 "owner" flag, or perhaps domain specific owner bytes.
	 *
	 * Transfer the data.
	 */
	msgcount = 0;
	if (!broadcast)
		goto noloop;

	for (domid = 0; domid < MAX_DOMAINS; domid++) {
		if (!DOMAIN_IN_SET(domset, domid))
			continue;

noloop:

		if (idn_domain[domid].dcpu == IDN_NIL_DCPU) {
			if (broadcast)
				continue;
			else
				break;
		}

		rv = idn_send_data(domid, netaddr, wq, mp);

		switch (rv) {
		case IDNXMIT_LOOP:	/* handled in loopback */
			msgcount++;
			break;

		case IDNXMIT_OKAY:	/* handled, okay to free */
			msgcount++;
			break;

		case IDNXMIT_RETRY:
			if (!broadcast)
				goto tryagain;
			goagain++;
			break;

		case IDNXMIT_REQUEUE:
			if (!broadcast)
				goto requeue;
			goqueue++;
			break;

		default:
			if (!broadcast)
				goto bad;
			break;
		}
		if (!broadcast)
			break;
	}

	if (msgcount == 0)
		if (goqueue)
			goto requeue;
		else if (goagain)
			goto tryagain;
		else
			goto bad;

	if ((flags & IDNPROMISC) && nmp)
		idndl_sendup(sip, nmp, idndl_paccept);

	freemsg(mp);

	PR_DLPI("%s: successful transmit to domainset 0x%x.\n",
		proc, domset);

	return (0);

bad:
	PR_DLPI("%s: bad transmission to domainset 0x%x, dropping msg.\n",
		proc, domset);
	if (nmp)
		freemsg(nmp);
	freemsg(mp);
	qenable(wq);
	return (1);

requeue:
	PR_DLPI("%s: requeue for domainset 0x%x, no qenable\n",
		proc, domset);
	if (nmp)
		freemsg(nmp);
	if (putbq(wq, mp) == 0)
		freemsg(mp);
	return (1);

tryagain:
	PR_DLPI("%s: try again to domainset 0x%x, putbq.\n",
		proc, domset);
	if (nmp)
		freemsg(nmp);
	if (putbq(wq, mp) == 0)
		freemsg(mp);
	qenable(wq);
	return (1);
}

/*
 * Called by:	idnh_recv_data, idn_recv_mboxdata.
 */
void
idndl_read(struct idn *sip, mblk_t *mp)
{
	struct ether_header	*ehp;
	queue_t			*ip4q;
	queue_t			*ip6q;
	int		pktlen;
	procname_t	proc = "idndl_read";

	PR_DLPI("%s: incoming msgsize = %lu, msgdsize = %lu\n",
		proc, msgsize(mp), msgdsize(mp));

	ehp = (struct ether_header *)mp->b_rptr;
	if (sip == NULL)
		sip = IDNDL_ETHER2SIP(&ehp->ether_dhost);
	if (sip == NULL) {
		/*
		 * If the sip is NULL, then I don't have a connection
		 * for this network.  No point in sending the message
		 * up.
		 */
		PR_DLPI("%s: no plumbing to send message through.\n",
			proc);
		freemsg(mp);
		return;
	}
	IDN_KSTAT_INC(sip, si_ipackets);
	IDN_KSTAT_INC(sip, si_ipackets64);
	/*
	 * update MIB II statistics
	 */
	pktlen = mp->b_wptr - mp->b_rptr;
	BUMP_InNUcast(sip, ehp);
	IDN_KSTAT_ADD(sip, si_rcvbytes, pktlen);
	IDN_KSTAT_ADD(sip, si_rbytes64, (uint64_t)pktlen);

	ip4q = sip->si_ip4q;
	ip6q = sip->si_ip6q;

	if (IS_ETHERTYPE_IPV4(ehp->ether_type) &&
			!IDNDL_ADDR_IS_MULTICAST(&ehp->ether_dhost) &&
			ip4q &&
			canputnext(ip4q)) {
		mp->b_rptr += sizeof (struct ether_header);
		(void) putnext(ip4q, mp);
		/*LINTED*/
	} else if (IS_ETHERTYPE_IPV6(ehp->ether_type) &&
			!IDNDL_ADDR_IS_MULTICAST(&ehp->ether_dhost) &&
			ip6q &&
			canputnext(ip6q)) {
		mp->b_rptr += sizeof (struct ether_header);
		(void) putnext(ip6q, mp);
	} else {
		/*
		 * Strip the PADs for 802.3
		 */
		pktlen = ehp->ether_type + sizeof (struct ether_header);
		PR_DLPI("%s: stripping PADs for 802.3 (pktlen=%d)\n",
			proc, pktlen);
		if (pktlen < ETHERMIN)
			mp->b_wptr = mp->b_rptr + pktlen;
		idndl_sendup(sip, mp, idndl_accept);
	}
}

int
idndl_init(struct idn *sip)
{
	struct idnstr	*stp;

	if (sip->si_flags & IDNSUSPENDED)
		(void) ddi_dev_is_needed(sip->si_dip, 0, 1);

	sip->si_flags = 0;
	sip->si_wantw = 0;

	IDN_KSTAT_INC(sip, si_inits);

	rw_enter(&idn.struprwlock, RW_WRITER);

	for (stp = idn.strup; stp; stp = stp->ss_nextp) {
		if ((stp->ss_sip == sip) && (stp->ss_flags & IDNSALLPHYS)) {
			sip->si_flags |= IDNPROMISC;
			break;
		}
	}

	sip->si_flags |= IDNRUNNING;

	mutex_enter(&idn.sipwenlock);
	idndl_wenable(sip);
	mutex_exit(&idn.sipwenlock);

	rw_exit(&idn.struprwlock);

	return (!(sip->si_flags & IDNRUNNING));
}

void
idndl_uninit(struct idn *sip)
{
	int		channel;
	procname_t	proc = "idndl_uninit";

	sip->si_flags &= ~IDNRUNNING;

	channel = (int)sip->si_ouraddr.ether_addr_octet[IDNETHER_CHANNEL];
	PR_DLPI("%s: IP SAP, uninit channel %d\n", proc, channel);
	/*
	 * A uninit is a hard close of an interface.
	 */
	idn_close_channel(channel, IDNCHAN_HARD_CLOSE);
}

/*
 * Send packet upstream.
 * Assume mp->b_rptr points to ether_header.
 */
void
idndl_sendup(struct idn *sip, mblk_t *mp, struct idnstr *(*acceptfunc)())
{
	int			type;
	struct ether_addr	*dhostp, *shostp;
	struct idnstr		*stp, *nstp;
	mblk_t 		*nmp;
	ulong_t		isgroupaddr;

	TRACE_0(TR_FAC_IDN, TR_IDN_SENDUP_START, "idnsendup start");

	dhostp = &((struct ether_header *)mp->b_rptr)->ether_dhost;
	shostp = &((struct ether_header *)mp->b_rptr)->ether_shost;
	type = ((struct ether_header *)mp->b_rptr)->ether_type;

	isgroupaddr = IDNDL_ADDR_IS_MULTICAST(dhostp);

	/*
	 * While holding a reader lock on the linked list of streams structures,
	 * attempt to match the address criteria for each stream
	 * and pass up the raw M_DATA ("fastpath") or a DL_UNITDATA_IND.
	 */

	rw_enter(&idn.struprwlock, RW_READER);

	if ((stp = (*acceptfunc)(idn.strup, sip, type, dhostp)) == NULL) {
		rw_exit(&idn.struprwlock);
		freemsg(mp);
		TRACE_0(TR_FAC_IDN, TR_IDN_SENDUP_END, "idnsendup end");
		return;
	}

	/*
	 * Loop on matching open streams until (*acceptfunc)() returns NULL.
	 */
	for (; nstp = (*acceptfunc)(stp->ss_nextp, sip, type, dhostp);
		stp = nstp) {

		if (canputnext(stp->ss_rq) == 0) {
			IDN_KSTAT_INC(sip, si_nocanput);
			continue;
		}
		if ((nmp = dupmsg(mp)) == NULL)
			nmp = copymsg(mp);
		if (nmp) {
			if ((stp->ss_flags & IDNSFAST) && !isgroupaddr) {
				nmp->b_rptr += sizeof (struct ether_header);
				(void) putnext(stp->ss_rq, nmp);
			} else if (stp->ss_flags & IDNSRAW) {
				(void) putnext(stp->ss_rq, nmp);
			} else if ((nmp = idndl_addudind(sip, nmp, shostp,
						dhostp, type, isgroupaddr))) {
				(void) putnext(stp->ss_rq, nmp);
			}
		} else {
			IDN_KSTAT_INC(sip, si_allocbfail);
		}
	}


	/*
	 * Do the last one.
	 */
	if (canputnext(stp->ss_rq)) {
		if ((stp->ss_flags & IDNSFAST) && !isgroupaddr) {
			mp->b_rptr += sizeof (struct ether_header);
			(void) putnext(stp->ss_rq, mp);
		} else if (stp->ss_flags & IDNSRAW) {
			(void) putnext(stp->ss_rq, mp);
		} else if ((mp = idndl_addudind(sip, mp, shostp, dhostp,
					    type, isgroupaddr))) {
			(void) putnext(stp->ss_rq, mp);
		}
	} else {
		freemsg(mp);
		IDN_KSTAT_INC(sip, si_nocanput);
		IDN_KSTAT_INC(sip, si_norcvbuf);	/* MIB II */
	}

	rw_exit(&idn.struprwlock);
	TRACE_0(TR_FAC_IDN, TR_IDN_SENDUP_END, "idnsendup end");
}

/*
 * Test upstream destination sap and address match.
 */
struct idnstr *
idndl_accept(register struct idnstr *stp, register struct idn *sip,
	    int type, struct ether_addr *addrp)
{
	t_uscalar_t	sap;
	uint_t		flags;

	for (; stp; stp = stp->ss_nextp) {
		sap   = stp->ss_sap;
		flags = stp->ss_flags;

		if ((stp->ss_sip == sip) && IDNSAPMATCH(sap, type, flags))
			if ((ether_cmp(addrp, &sip->si_ouraddr) == 0) ||
			    (ether_cmp(addrp, &etherbroadcastaddr) == 0) ||
			    (flags & IDNSALLPHYS) ||
			    idndl_mcmatch(stp, addrp))
				return (stp);
	}

	return (NULL);
}

/*
 * Test upstream destination sap and address match for IDNSALLPHYS only.
 */
/* ARGSUSED3 */
struct idnstr *
idndl_paccept(register struct idnstr *stp, register struct idn *sip,
	    int type, struct ether_addr *addrp)
{
	t_uscalar_t	sap;
	uint_t		flags;

	for (; stp; stp = stp->ss_nextp) {
		sap   = stp->ss_sap;
		flags = stp->ss_flags;

		if ((stp->ss_sip == sip) &&
		    IDNSAPMATCH(sap, type, flags) &&
		    (flags & IDNSALLPHYS))
			return (stp);
	}

	return (NULL);
}

/*
 * Set or clear the device ipq pointer.
 * Assumes IPv4 and IPv6 are IDNSFAST.
 */
static void
idndl_setipq(struct idn *sip)
{
	struct idnstr	*stp;
	int		ok4 = 1;
	int		ok6 = 1;
	queue_t		*ip4q = NULL;
	queue_t		*ip6q = NULL;

	rw_enter(&idn.struprwlock, RW_READER);

	for (stp = idn.strup; stp; stp = stp->ss_nextp) {
		if (stp->ss_sip == sip) {
			if (stp->ss_flags & (IDNSALLPHYS|IDNSALLSAP)) {
				ok4 = 0;
				ok6 = 0;
				break;
			}
			if (IS_ETHERTYPE_IPV4(stp->ss_sap)) {
				if (ip4q == NULL)
					ip4q = stp->ss_rq;
				else
					ok4 = 0;
				/*LINTED*/
			} else if (IS_ETHERTYPE_IPV6(stp->ss_sap)) {
				if (ip6q == NULL)
					ip6q = stp->ss_rq;
				else
					ok6 = 0;
			}
		}
	}

	rw_exit(&idn.struprwlock);

	if (ok4)
		sip->si_ip4q = ip4q;
	else
		sip->si_ip4q = NULL;
	if (ok6)
		sip->si_ip6q = ip6q;
	else
		sip->si_ip6q = NULL;
}

/*
 * Prefix msg with a DL_UNITDATA_IND mblk and return the new msg.
 */
static mblk_t *
idndl_addudind(struct idn *sip, mblk_t *mp,
	    struct ether_addr *shostp, struct ether_addr *dhostp,
	    int type, ulong_t isgroupaddr)
{
	dl_unitdata_ind_t	*dludindp;
	struct idndladdr	*dlap;
	mblk_t	*nmp;
	int	size;

	TRACE_0(TR_FAC_IDN, TR_IDN_ADDUDIND_START, "idndl_addudind start");

	mp->b_rptr += sizeof (struct ether_header);

	/*
	 * Allocate an M_PROTO mblk for the DL_UNITDATA_IND.
	 */
	size = sizeof (dl_unitdata_ind_t) + IDNADDRL + IDNADDRL;
	nmp = allocb(IDNROUNDUP(IDNHEADROOM + size, sizeof (double)), BPRI_LO);
	if (nmp == NULL) {
		IDN_KSTAT_INC(sip, si_allocbfail);
		IDN_KSTAT_INC(sip, si_ierrors);
		if (idn_debug)
			serror(sip->si_dip, 451, "allocb failed");
		freemsg(mp);
		TRACE_0(TR_FAC_IDN, TR_IDN_ADDUDIND_END, "idndl_addudind end");
		return (NULL);
	}
	DB_TYPE(nmp) = M_PROTO;
	nmp->b_wptr = nmp->b_datap->db_lim;
	nmp->b_rptr = nmp->b_wptr - size;

	/*
	 * Construct a DL_UNITDATA_IND primitive.
	 */
	dludindp = (dl_unitdata_ind_t *)nmp->b_rptr;
	dludindp->dl_primitive = DL_UNITDATA_IND;
	dludindp->dl_dest_addr_length = IDNADDRL;
	dludindp->dl_dest_addr_offset = sizeof (dl_unitdata_ind_t);
	dludindp->dl_src_addr_length = IDNADDRL;
	dludindp->dl_src_addr_offset = sizeof (dl_unitdata_ind_t) + IDNADDRL;
	dludindp->dl_group_address = isgroupaddr;

	dlap = (struct idndladdr *)(nmp->b_rptr + sizeof (dl_unitdata_ind_t));
	ether_copy(dhostp, &dlap->dl_phys);
	dlap->dl_sap = (ushort_t)type;

	dlap = (struct idndladdr *)(nmp->b_rptr + sizeof (dl_unitdata_ind_t)
					+ IDNADDRL);
	ether_copy(shostp, &dlap->dl_phys);
	dlap->dl_sap = (ushort_t)type;

	/*
	 * Link the M_PROTO and M_DATA together.
	 */
	nmp->b_cont = mp;
	TRACE_0(TR_FAC_IDN, TR_IDN_ADDUDIND_END, "idndl_addudind end");
	return (nmp);
}

/*
 * Return TRUE if the given multicast address is one
 * of those that this particular Stream is interested in.
 */
static int
idndl_mcmatch(register struct idnstr *stp, register struct ether_addr *addrp)
{
	register struct ether_addr	*mctab;
	register int	mccount;
	register int	i;

	/*
	 * Return FALSE if not a multicast address.
	 */
	if (!IDNDL_ADDR_IS_MULTICAST(addrp))
		return (0);

	/*
	 * Check if all multicasts have been enabled for this Stream
	 */
	if (stp->ss_flags & IDNSALLMULTI)
		return (1);

	/*
	 * Return FALSE if no multicast addresses enabled for this Stream.
	 */
	if (stp->ss_mccount == 0)
		return (0);

	/*
	 * Otherwise, find it in the table.
	 */

	mccount = stp->ss_mccount;
	mctab = stp->ss_mctab;

	for (i = 0; i < mccount; i++)
		if (!ether_cmp(addrp, &mctab[i]))
			return (1);

	return (0);
}

/*
 * Start xmit on any msgs previously enqueued on any write queues.
 * If the caller passes NULL, then we need to check all
 * our interfaces.
 */
void
idndl_wenable(struct idn *sip)
{
	struct idnstr	*stp;
	queue_t		*wq;

	/*
	 * Order of wantw accesses is important.
	 */
	ASSERT((sip == NULL) ? RW_LOCK_HELD(&idn.struprwlock) : 1);
	ASSERT(MUTEX_HELD(&idn.sipwenlock));

	do {
		if (sip)
			sip->si_wantw = 0;
		for (stp = idn.strup; stp; stp = stp->ss_nextp) {
			if ((!sip || (stp->ss_sip == sip)) &&
			    stp->ss_rq && ((wq = WR(stp->ss_rq))->q_first))
				qenable(wq);
		}
	} while (sip && sip->si_wantw);
}

/*VARARGS*/
static void
serror(dev_info_t *dip, int idnerr, char *fmt, ...)
{
	static	long	last;
	static	char	*lastfmt;
	char		msg_buffer[255];
	va_list ap;
	time_t	now;

	/*
	 * Don't print same error message too often.
	 */
	now = gethrestime_sec();
	if ((last == (now & ~1)) && (lastfmt == fmt))
		return;

	last = now & ~1;
	lastfmt = fmt;

	va_start(ap, fmt);
	(void) vsprintf(msg_buffer, fmt, ap);
	cmn_err(CE_CONT, "IDN: %d: %s%d: %s\n",
		idnerr, ddi_get_name(dip),
		ddi_get_instance(dip), msg_buffer);
	va_end(ap);
}
