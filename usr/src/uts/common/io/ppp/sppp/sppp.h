/*
 * sppp.h - Solaris STREAMS PPP multiplexing pseudo-driver definitions
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE FOR
 * ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING, MODIFYING OR
 * DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * Copyright (c) 1994 The Australian National University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * This driver is derived from the original SVR4 STREAMS PPP driver
 * originally written by Paul Mackerras <paul.mackerras@cs.anu.edu.au>.
 *
 * Adi Masputra <adi.masputra@sun.com> rewrote and restructured the code
 * for improved performance and scalability.
 *
 * $Id: sppp.h,v 1.0 2000/05/08 01:10:12 masputra Exp $
 */

#ifndef __SPPP_H
#define	__SPPP_H

#include <sys/dlpi.h>
#include <net/ppp_defs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(ETHERTYPE_IP)
#define	ETHERTYPE_IP	0x800
#endif

#if !defined(ETHERTYPE_IPV6)
#define	ETHERTYPE_IPV6	0x86dd
#endif

#if !defined(ETHERTYPE_PPP)
#define	ETHERTYPE_PPP	0x880b
#endif

#if !defined(ETHERTYPE_ALLSAP)
#define	ETHERTYPE_ALLSAP	0
#endif

#if !defined(PPP_ALLSAP)
#define	PPP_ALLSAP	PPP_ALLSTATIONS
#endif

/*
 * DLPI handler (function table item).
 */
struct  sppp_dlpi_pinfo_t {
	int	pi_minlen;		/* minimum primitive length */
	int	pi_state;		/* acceptable starting state */
	int	(*pi_funcp)();		/* function() to call */
};

#ifndef DL_MAXPRIM
#define	DL_MAXPRIM DL_GET_STATISTICS_ACK
#endif

/*
 * Per-attachment kstats.
 */
typedef struct sppp_kstats {
	kstat_named_t	allocbfail;
	kstat_named_t	rbytes;
	kstat_named_t	ierrors;
	kstat_named_t	ierrors_lower;
	kstat_named_t	ioctlsfwd;
	kstat_named_t	ioctlsfwdok;
	kstat_named_t	ioctlsfwderr;
	kstat_named_t	ipackets;
	kstat_named_t	ipackets_ctl;
	kstat_named_t	iqdropped;
	kstat_named_t	irunts;
	kstat_named_t	itoolongs;
	kstat_named_t	lsneedup;
	kstat_named_t	lsdown;
	kstat_named_t	mctlsfwd;
	kstat_named_t	mctlsfwderr;
	kstat_named_t	mctlsknown;
	kstat_named_t	mctlsunknown;
	kstat_named_t	obytes;
	kstat_named_t	oerrors;
	kstat_named_t	oerrors_lower;
	kstat_named_t	opackets;
	kstat_named_t	opackets_ctl;
	kstat_named_t	oqdropped;
	kstat_named_t	otoolongs;
	kstat_named_t	orunts;

	/* 64 bit entries */
	kstat_named_t	ipackets64;
	kstat_named_t	opackets64;
	kstat_named_t	rbytes64;
	kstat_named_t	obytes64;
} sppp_kstats_t;

/*
 * Same order as above.  Note that for netstat -i to work, there needs
 * to be "ipackets", "opackets", "ierrors", and "oerrors" kstat named
 * variables.
 */
#define	SPPP_KSTATS_NAMES	\
	"allocbfail", "rbytes", "ierrors", "ierrors_lower", "ioctlsfwd", \
	"ioctlsfwdok", "ioctlsfwderr", "ipackets", "ipkts_ctl", \
	"ipkts_qdropped", "ipkts_runts", "ipkts_toolong", "lsneedup", \
	"lsdown", "mctlsfwd", "mctlsfwderr", "mctlsknown", "mctlsunknown", \
	"obytes", "oerrors", "oerrors_lower", "opackets", "opkts_ctl", \
	"opkts_qdropped", "opkts_toolong", "opkts_runts"

#define	SPPP_KSTATS64_NAMES	\
	"ipackets64", "opackets64", "rbytes64", "obytes64"

/*
 * dl_addr_length needs to be equal to the absolute value of dl_sap_length,
 * in order for IP to derive a default setting for IFF_POINTOPOINT flag.
 */
typedef t_uscalar_t	spppreqsap_t;
#define	SPPP_SAPL	sizeof (spppreqsap_t)
#define	SPPP_ADDRL	SPPP_SAPL

/*
 * Per-Stream instance state information.
 *
 * Each instance is dynamically allocated at open() and free'd at close().
 * Each per-Stream instance points to at most one per-attachment structure
 * using the sps_ppa field. All instances are threaded together into one
 * list of active instances ordered on minor device number, using the
 * sps_nextmn field.
 */
typedef struct spppstr {
	/*
	 * Note that EX_st_nextmn field should never be referenced other
	 * than by the routines manipulating the global upper streams list,
	 * by first obtaining exclusive access at the outer perimeter.
	 */
	struct spppstr	*sps_nextmn;	/* next minor in global list */
	/*
	 * These fields are common to all upper streams. If this stream
	 * is attached to a ppa, then the sps_ppa field will point to the
	 * ppa structure associated with this particular upper stream.
	 */
	minor_t		sps_mn_id;	/* minor device number of this stream */
	queue_t		*sps_rq;	/* pointer to the read queue */
	uint32_t	sps_flags;	/* miscellaneous flags */
	uint32_t	sps_ioc_id;	/* last ioctl ID for this stream */
	struct sppa	*sps_ppa;	/* pointer to ppa structure */
	/*
	 * sps_nextsib is protected by the ppa's sibling lock (ppa_sib_lock),
	 * and access made to it should only be done by first ensuring that
	 * the sps_ppa field is valid, i.e., this stream has been attached.
	 */
	struct spppstr	*sps_nextsib;	/* next stream of same ppa (sibling) */
	/*
	 * These fields are common to all non-control streams, i.e., those
	 * in which a PPPIO_NEWPPA has not been issued on. Non-control
	 * streams are valid candidates for network streams, and they can
	 * only be considered network streams (ones which carry IP packets)
	 * if they are attached and bound. The only mandatory requirement
	 * for control stream is that its sps_npmode field should always
	 * be equal to NPMODE_PASS, as we obviously will never block the
	 * control stream from sending or receiving packets.
	 */
	t_scalar_t	sps_sap;	/* bound sap */
	spppreqsap_t	sps_req_sap;	/* requested sap */
	enum NPmode	sps_npmode;	/* network protocol mode */
	/*
	 * sps_dlstate is only valid for network streams in which DLPI
	 * is intended to be used to transfer network-layer data. It is set
	 * to DL_UNATTACHED for all other streams.
	 */
	t_uscalar_t	sps_dlstate;	/* current DLPI state */
	mblk_t		*sps_hangup;	/* preallocated M_HANGUP message */

	zoneid_t	sps_zoneid;	/* zone in which we were opened */
} spppstr_t;

/*
 * Values for sps_flags, and their descriptions.
 */
/*			0x00000001	unused */
#define	SPS_CONTROL	0x00000002	/* stream is a control stream */
#define	SPS_FASTPATH	0x00000004	/* stream uses IP fastpath */
#define	SPS_PROMISC	0x00000008	/* stream is promiscuous */
#define	SPS_RAWDATA	0x00000010	/* raw M_DATA, no DLPI header */
#define	SPS_PIOATTACH	0x00000020	/* attached using PPPIO_ATTACH */
#define	SPS_KDEBUG	0x00000040	/* stream has kdebug turned on */
#define	SPS_CACHED	0x00000080	/* network stream pointer is cached */
#define	SPS_IOCQ	0x00000100	/* queue ioctls */

#define	IS_SPS_CONTROL(x)	\
	((x)->sps_flags & SPS_CONTROL)
#define	IS_SPS_FASTPATH(x)	\
	((x)->sps_flags & SPS_FASTPATH)
#define	IS_SPS_PROMISC(x)	\
	((x)->sps_flags & SPS_PROMISC)
#define	IS_SPS_RAWDATA(x)	\
	((x)->sps_flags & SPS_RAWDATA)
#define	IS_SPS_PIOATTACH(x)	\
	((x)->sps_flags & SPS_PIOATTACH)
#define	IS_SPS_KDEBUG(x)	\
	((x)->sps_flags & SPS_KDEBUG)
#define	IS_SPS_CACHED(x)	\
	((x)->sps_flags & SPS_CACHED)
#define	IS_SPS_IOCQ(x)		\
	((x)->sps_flags & SPS_IOCQ)

/*
 * Bit format (octal based) string for cmn_err, which represents the flags.
 */
#define	SPS_FLAGS_STR	\
	"\020"		\
	"\1priv"	\
	"\2control"	\
	"\3fastpath"	\
	"\4promisc"	\
	"\5rawdata"	\
	"\6pioattach"	\
	"\7kdebug"	\
	"\10cached"

/*
 * Per-Attachment instance state information.
 *
 * Each instance is dynamically allocated on first attach (PPPIO_NEWPPA).
 * Allocation of this structure is only done once per control stream. A ppa
 * instance may be shared by two or more upper streams, and it is always
 * linked to the upper stream marked as the control stream (SPS_CONTROL)
 * via the ppa_ctl field.  Non-control streams are linked to ppa_streams.
 */
typedef struct sppa {
	/*
	 * Note that EX_st_nextppa field should only be accessed (walked)
	 * by the ppa manipulation routines, i.e, those which affect
	 * the global ppa list, e.g: open, close, new_ppa, and XX_attach_upper.
	 */
	struct sppa	*ppa_nextppa;	/* next attachment instance */
	/*
	 * ppa_sib_lock guards the linkages between all upper streams related
	 * to this ppa. Walking the sps_nextsib of any upper streams should
	 * be done by first holding this lock.
	 */
	krwlock_t	ppa_sib_lock;	/* lock for sibling upper streams */
	uint32_t	ppa_flags;	/* miscellaneous flags */
	int32_t		ppa_refcnt;	/* upper stream reference count */
	uint32_t	ppa_ppa_id;	/* unique attachment id */
	spppstr_t	*ppa_streams;	/* list of all non-control streams */
	spppstr_t	*ppa_ctl;	/* back pointer to control stream */
	queue_t		*ppa_lower_wq;	/* pointer to lower write queue */
	uint16_t	ppa_mru;	/* link layer maximum receive unit */
	uint16_t	ppa_mtu;	/* link layer maximum transmit unit */
	hrtime_t	ppa_lasttx;	/* last transmit time for a packet */
	hrtime_t	ppa_lastrx;	/* last receive time for a packet */
	int32_t		ppa_promicnt;	/* promiscous stream count */
	/*
	 * ppa_sta_lock mutex guards the statistic fields of this ppa, since
	 * this structure is shared by upper streams of the same ppa.
	 */
	kmutex_t	ppa_sta_lock;	/* mutex to lock structure */
	struct ppp_stats64 ppa_stats;	/* legacy stats structure */
	uint32_t	ppa_allocbfail;	/* memory allocation failure count */
	uint32_t	ppa_ierr_low;	/* errors from below during receive */
	uint32_t	ppa_ioctlsfwd;	/* total ioctl forwarded down */
	uint32_t	ppa_ioctlsfwdok;  /* and the reply sent upward */
	uint32_t	ppa_ioctlsfwderr; /* or discarded replies */
	uint32_t	ppa_ipkt_ctl;	/* received control pkts */
	uint32_t	ppa_iqdropped;	/* msg dropped due to putq error */
	uint32_t	ppa_irunts;	/* packet rcvd is too short */
	uint32_t	ppa_itoolongs;	/* packet rcvd is larger than MRU */
	uint32_t	ppa_lsneedup;	/* total LINKSTAT_NEEDUP msg sent up */
	uint32_t	ppa_lsdown;	/* total LINKSTAT_DOWN msg sent up */
	uint32_t	ppa_mctlsfwd;	/* total M_{PC}PROTO forwarded down */
	uint32_t	ppa_mctlsfwderr; /*   and discarded count */
	uint32_t	ppa_mctlsknown;	/* total known M_CTL messages */
	uint32_t	ppa_mctlsunknown; /* total unknown M_CTL messages */
	uint32_t	ppa_oerr_low;	/* errors from below during transmit */
	uint32_t	ppa_opkt_ctl;	/* transmitted control pkts */
	uint32_t	ppa_oqdropped;	/* msg dropped due to putq error */
	uint32_t	ppa_orunts;	/* packet sent is too short */
	uint32_t	ppa_otoolongs;	/* packet sent is larger than MTU */
	kstat_t		*ppa_kstats;	/* pointer to kstats structure */
	/*
	 * We keep the following pointers for performance reasons. Instead
	 * of walking the list of attached upper streams to find the
	 * destination upper stream everytime we need to send a packet up,
	 * we keep them here for easy access.
	 */
	spppstr_t	*ppa_ip_cache;	/* ptr to PPP_IP upper stream */
	spppstr_t	*ppa_ip6_cache;	/* ptr to PPP_IPV6 upper stream */

	kmutex_t	ppa_npmutex;	/* protects the 2 fields below */
	uint32_t	ppa_npflag;	/* network protocols blocked */
	uint32_t	ppa_holdpkts[3]; /* # of packets blocked per np */

	zoneid_t	ppa_zoneid;	/* zone where PPA is in use */
} sppa_t;

/* bit position (in ppa_npflag) for each ppp_protocol that can be blocked */
#define	NP_IP	1
#define	NP_IPV6	2

/*
 * Values for ppa_flags, and their descriptions.
 */
#define	PPA_LASTMOD	0x00000001	/* last PPP entity on the stream */
#define	PPA_TIMESTAMP	0x00000002	/* time-stamp each packet */

#define	IS_PPA_LASTMOD(x)	\
	((x)->ppa_flags & PPA_LASTMOD)
#define	IS_PPA_TIMESTAMP(x)	\
	((x)->ppa_flags & PPA_TIMESTAMP)

/*
 * Bit format (octal based) string for cmn_err, which represents the flags.
 */
#define	PPA_FLAGS_STR	\
	"\020"		\
	"\1lastmod"	\
	"\2timestamp"

/*
 * General macros.
 */
#define	SPDEBUG	printf

/*
 * Function declarations.
 */
extern int	sppp_close(queue_t *, int, cred_t *);
extern mblk_t	*sppp_dladdud(spppstr_t *, mblk_t *, t_scalar_t, boolean_t);
extern void	sppp_dlpi_pinfoinit(void);
extern void	sppp_dlprsendup(spppstr_t *, mblk_t *, t_scalar_t, boolean_t);
extern int	sppp_lrput(queue_t *, mblk_t *);
extern int	sppp_lrsrv(queue_t *);
extern int	sppp_lwsrv(queue_t *);
extern int	sppp_mproto(queue_t *, mblk_t *, spppstr_t *);
extern int	sppp_open(queue_t *, dev_t *, int, int, cred_t *);
extern int	sppp_uwput(queue_t *, mblk_t *);
extern int	sppp_uwsrv(queue_t *);
extern void	sppp_remove_ppa(spppstr_t *sps);
extern sppa_t	*sppp_find_ppa(uint32_t ppa_id);
extern sppa_t	*sppp_create_ppa(uint32_t ppa_id, zoneid_t zoneid);

#ifdef	__cplusplus
}
#endif

#endif /* __SPPP_H */
