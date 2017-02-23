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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 *
 * Inter-Domain Network
 */

#ifndef	_SYS_IDN_H
#define	_SYS_IDN_H

#ifndef _ASM

#ifdef _KERNEL

#include <sys/note.h>

#include <sys/cmn_err.h>
#include <sys/dditypes.h>
#include <sys/stream.h>
#include <sys/machsystm.h>
#include <sys/ethernet.h>
#include <sys/dlpi.h>
#include <sys/time.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/cpuvar.h>

#include <sys/idn_sigb.h>
#include <sys/idn_smr.h>
#endif /* _KERNEL */

#ifdef	__cplusplus
extern "C" {
#endif

typedef const char * const	procname_t;

#define	MB2B(m)		((size_t)(m) << 20)	/* MBytes to Bytes */
#define	B2MB(b)		((uint_t)((b) >> 20))	/* Bytes to MBytes */

#ifdef _KERNEL

/*
 * IDN_PROP_SMRSIZE	- User specified size in MBytes.
 * IDN_PROP_SMRADDR	- OBP's internal physical address of the region.
 *
 *	OBP properties of "memory" node that define the SMR space.
 */
#define	IDN_PROP_SMRSIZE	"idn-smr-size"
#define	IDN_PROP_SMRADDR	"idn-smr-addr"

/*
 * IDN_AWOLMSG_INTERVAL	(driver.conf)
 *
 *	Number of seconds between AWOL messages on a per-domain basis.
 *	The purpose is to throttle the frequency at which these
 *	messages appear.
 *
 * IDN_MSGWAIT_NEGO	(driver.conf)
 * IDN_MSGWAIT_CFG
 * IDN_MSGWAIT_CON
 * IDN_MSGWAIT_FIN
 * IDN_MSGWAIT_CMD
 * IDN_MSGWAIT_DATA
 *
 *	Number of seconds to wait for response to respective
 *	message type.
 *
 * IDN_RETRYFREQ_NEGO	(driver.conf)
 * IDN_RETRYFREQ_CON
 * IDN_RETRYFREQ_FIN
 *
 *	Number of seconds to wait between retries of the respective
 *	message type.
 *
 * IDN_SMR_ALIGN	(not tunable)
 *
 *	The hardware registers that describe the SMR are based on a 64K
 *	aligned physical address.
 *
 * IDN_SMR_SIZE		(OBP [only])
 *
 *	Total size of the SMR (Shared Memory Region) in bytes.
 *
 * IDN_NWR_SIZE		(driver.conf)
 *
 *	Total size of the NWR (NetWork Region) portion of the SMR which
 *	is actually used to support network activity.  The NWR is managed
 *	as simply a pool of I/O buffers which are distributed by the
 *	Master domain to the Slaves for the purpose of communicating
 *	between each other.  If not set then the entire SMR is used
 *	as the NWR.
 *	Req: IDN_NWR_SIZE <= IDN_SMR_SIZE
 *
 * IDN_SMR_BUFSIZE	(driver.conf)
 *
 *	Size of individual SMR buffers.  The SMR is divided into chunks
 *	of IDN_SMR_BUFSIZE bytes.  The IDN_MTU is based on this size
 *	and thus the IDN_SMR_BUFSIZE should be chosen based on performance.
 *
 * IDN_DATA_SIZE	(NOT tunable)
 *
 *	Portion of IDN_SMR_BUFSIZE that can contain raw non-IDN dependent
 *	data.  We subtract IDN_ALIGNSIZE bytes to allow for fast bcopy
 *	alignment.
 *	Req: IDN_DATA_SIZE <=
 *		(IDN_SMR_BUFSIZE - sizeof (smr_pkthdr_t) - IDN_ALIGNSIZE)
 *
 * IDN_MTU		(indirectly tunable via IDN_SMR_BUFSIZE)
 *
 * 	This size represents the portion of an SMR I/O buffers that can
 *	contain (ethernet headerless) data.
 *	Req: IDN_MTU <= IDN_DATA_SIZE - sizeof (ether_header)
 *
 * IDN_WINDOW_MAX	(driver.conf)
 *
 *	Maximum number of outstanding packets that are allowed per
 *	domain.  If this value is exceeded for a particular domain
 *	no further I/Os will be transmitted to that domain until it
 *	has acknowledged enough of the previous transmission to bring
 *	down its outstanding I/O count (idn_domain.dio) below this
 *	value.  In addition, if this value is exceeded then a Timer
 *	is scheduled to check for any response from the remote domain.
 *
 * IDN_WINDOW_INCR	(driver.conf)
 *
 *	As more channels/nets are activated on a particular domain
 *	the greater the number of possible outstanding data packets
 *	that can be outstanding to a given domain.  Since this natural
 *	occurence can result in the outstanding-I/O count to a given
 *	domain to increase we run the risk of dropping into the
 *	IDN_WINDOW_MAX region even though the receiving domain
 *	may be fine with handling the load.  In order to compensate
 *	for this increased activity and to not incur unjustified
 *	slips into the IDN_WINDOW_MAX region, the IDN_WINDOW_MAX
 *	value is adjusted by IDN_WINDOW_INCR for each channel/net
 *	that is activated for a given domain.
 *
 * IDN_WINDOW_EMAX	(not tunable)
 *
 *	The effective value of IDN_WINDOW_MAX once it has
 *	been adjusted by IDN_WINDOW_INCR.
 *
 * IDN_RECLAIM_MIN	(driver.conf)
 *
 *	Minimum number of outstanding packets that our allowed
 *	before subsequent sends will attempt to reclaim some number
 *	of outstanding data packets.
 *
 * IDN_RECLAIM_MAX	(driver.conf)
 *	This value represents the maximum number of outstanding
 *	packets we will try to reclaim during a send once we've
 *	passed the IDN_RECLAIM_MIN boundary.
 *
 * IDN_MODUNLOADABLE	(ndd)
 *
 *	By default the IDN driver is unloadable.  Setting this
 *	variable will allow the IDN driver to be unloaded provided
 *	it's not in use.
 *
 * IDN_LOWAT/IDN_HIWAT	(driver.conf)
 *
 *	Low/High water marks for the STREAM interface to IDN.
 *
 * IDN_MBOX_PER_NET	(driver.conf)
 *
 *	Number of mailbox entries that are allocated per channel/net.
 *	This value effectively represents the amount of outstanding
 *	activity that can reside at a domain.  Increasing this value
 *	allows more packets to be in transit to a domain, however
 *	at some point there are diminishing returns since the receiver
 *	can only consume packets so fast.
 *
 * IDN_MAX_NETS		(driver.conf)
 *
 *	Maximum number of network interfaces (channels) that IDN
 *	is currently configured to allow.  The absolute max is
 *	IDN_MAXMAX_NETS.  We don't automatically default IDN_MAX_NETS
 *	to IDN_MAXMAX_NETS because it would mean wasted space in
 *	the mailbox region having to reserve mailboxes that will
 *	very likely go unused.  The smaller this value the fewer
 *	the number of mailboxes in the SMR and thus the greater the
 *	number of possible I/O buffers available.
 *	Req: IDN_MAX_NETS <= IDN_MAXMAX_NETS
 *
 * IDN_CHECKSUM		(driver.conf)
 *
 *	If enabled, IDN validates the smr_pkthdr_t of incoming packets
 *	via a checksum, and calculates the checksum for outgoing packets.
 *	Only the first 3 fields of smr_pkthdr_t are checksummed and
 *	must be set to their expected values prior to calculating the
 *	checksum.  Turned OFF by default when compiled DEBUG.
 *
 * IDN_SMR_MAXSIZE	(not tunable)
 *
 *	The absolute maximum size of the SMR region that we'll allow.
 *	Note that the virtual address space comes out kernelmap.
 */
#define	IDN_AWOLMSG_INTERVAL	60		/* seconds */
#define	IDN_MSGWAIT_NEGO	20		/* seconds */
#define	IDN_MSGWAIT_CFG		40
#define	IDN_MSGWAIT_CON		20
#define	IDN_MSGWAIT_FIN		40
#define	IDN_MSGWAIT_CMD		40
#define	IDN_MSGWAIT_DATA	30
#define	IDN_RETRYFREQ_NEGO	2
#define	IDN_RETRYFREQ_CON	2
#define	IDN_RETRYFREQ_FIN	3

#define	IDN_SMR_BUFSIZE_MIN	512
#define	IDN_SMR_BUFSIZE_MAX	(512*1024)
#define	IDN_SMR_BUFSIZE_DEF	(16*1024)

#define	IDN_SMR_SHIFT		(16)
#define	IDN_SMR_ALIGN		(1 << IDN_SMR_SHIFT)	/* 64K */
#define	IDN_SMR_SIZE		idn_smr_size
#define	IDN_NWR_SIZE		idn_nwr_size
#define	IDN_SMR_BUFSIZE		idn_smr_bufsize
#define	IDN_DATA_SIZE		(IDN_SMR_BUFSIZE \
				    - sizeof (smr_pkthdr_t) \
				    - IDN_ALIGNSIZE)
#define	IDN_MTU			(IDN_DATA_SIZE - sizeof (struct ether_header))
#define	IDN_WINDOW_MAX		idn_window_max
#define	IDN_WINDOW_INCR		idn_window_incr
#define	IDN_WINDOW_EMAX		idn_window_emax
#define	IDN_RECLAIM_MIN		idn_reclaim_min
#define	IDN_RECLAIM_MAX		idn_reclaim_max
#define	IDN_MODUNLOADABLE	idn_modunloadable
#define	IDN_LOWAT		idn_lowat
#define	IDN_HIWAT		idn_hiwat
#define	IDN_MBOX_PER_NET	idn_mbox_per_net
#define	IDN_MAX_NETS		idn_max_nets
#define	IDN_CHECKSUM		idn_checksum
#define	IDN_SMR_MAXSIZE		96
#define	_IDN_SMR_SIZE		32			/* 32M */
#define	_IDN_NWR_SIZE		_IDN_SMR_SIZE		/* 32M */
#define	_IDN_SMR_BUFSIZE	(16 * 1024)		/* 16K */


#define	IDN_TUNEVAR_NAME(v)	(*(char **)((ulong_t)&(v)+(sizeof (ulong_t))))
#define	IDN_TUNEVAR_VALUE(v)	(v)

/*
 * History structure to support problem analysis.
 */
#define	IDN_HISTORY_NUM		1024
#define	IDN_HISTORY_LOG(op, d0, d1, d2) \
	if (idn_history) { \
		mutex_enter(&idnhlog.h_mutex); \
		idnhlog.h_log[idnhlog.h_index].e_time = TIMESTAMP(); \
		idnhlog.h_log[idnhlog.h_index].e_op = (ushort_t)(op); \
		idnhlog.h_log[idnhlog.h_index].e_data[0] = (ushort_t)(d0); \
		idnhlog.h_log[idnhlog.h_index].e_data[1] = (ushort_t)(d1); \
		idnhlog.h_log[idnhlog.h_index].e_data[2] = (ushort_t)(d2); \
		idnhlog.h_index++; \
		idnhlog.h_index &= (IDN_HISTORY_NUM - 1); \
		mutex_exit(&idnhlog.h_mutex); \
	}

#define	IDNH_GSTATE	0x0001	/* d0=gstate, d1=, d2= */
#define	IDNH_DSTATE	0x0002	/* d0=domid, d1=dstate, d2=cpuid */
#define	IDNH_AWOL	0x0003	/* d0=domid, d1=dstate, d2=cpuid */
#define	IDNH_MASTERID	0x0004	/* d0=masterid, d1=oldid, d2= */
#define	IDNH_NEGO	0x0005	/* d0=domid, d1=ds_trans_on, d2=ds_connected */
#define	IDNH_FIN	0x0006	/* d0=domid, d1=finstate, d2= */
#define	IDNH_RELINK	0x0007	/* d0=domid, d1=dstate, d2=ds_relink */

struct idn_h_entry {
	hrtime_t	e_time;
	ushort_t	e_op;
	ushort_t	e_data[3];
};

struct idn_history {
	kmutex_t		h_mutex;
	int			h_index;
	struct idn_h_entry	h_log[IDN_HISTORY_NUM];
};
#endif /* _KERNEL */

/*
 * IDN_SIGBPIL - Interrupt level at which IDN driver
 *		 wakes up idn_sigbhandler_thread
 */
#define	IDN_SIGBPIL	PIL_3

/*
 * Definition of sigbintr.sb_busy values which
 * represents state of idn_sigbhandler.
 */
#define	IDNSIGB_NOTREADY	((uchar_t)0)
#define	IDNSIGB_INACTIVE	((uchar_t)1)
#define	IDNSIGB_STARTED		((uchar_t)2)
#define	IDNSIGB_ACTIVE		((uchar_t)3)
#define	IDNSIGB_DIE		((uchar_t)4)

/*
 * Some Xfire based macros that assume 4 cpus per board.
 */
#define	CPUID_TO_BOARDID(c)	((c) >> 2)
#define	MAX_CPU_PER_BRD		4
#define	CPUSET_TO_BOARDSET(cset, bset) \
	{ \
		register int	c, b; \
		(bset) = 0; \
		for (b = 0; b < MAX_BOARDS; b++) \
			for (c = 0; c < MAX_CPU_PER_BRD; c++) \
				if (CPU_IN_SET((cset), \
						(b * MAX_CPU_PER_BRD) + c)) \
					(bset) |= 1 << b; \
	}

/*
 * Macros to manipulate boardset and domainset masks.
 */
typedef ushort_t boardset_t;	/* assumes max of 16 boards */
typedef ushort_t domainset_t;	/* assumes max of 16 domains */

#define	BOARDSET(brd)		((boardset_t)(1 << (brd)))
#define	BOARDSET_ALL		((boardset_t)~0)
#define	BOARD_IN_SET(set, brd)	((set) & BOARDSET(brd))
#define	BOARDSET_ADD(set, brd)	((set) |= BOARDSET(brd))
#define	BOARDSET_DEL(set, brd)	((set) &= ~BOARDSET(brd))
#define	DOMAINSET(d)		((domainset_t)1 << (d))
#define	DOMAINSET_ALL		((domainset_t)~0)
#define	DOMAIN_IN_SET(s, d)	((s) & DOMAINSET(d))
#define	DOMAINSET_ADD(s, d)	((s) |= DOMAINSET(d))
#define	DOMAINSET_DEL(s, d)	((s) &= ~DOMAINSET(d))

/*
 * PFN_TO_SMADDR macro converts a PFN to a IDN_SMR_ALIGN'ed
 * address suitable for the CIC bar/lar registers.
 */
#if (IDN_SMR_SHIFT <= MMU_PAGESHIFT)
#define	PFN_TO_SMADDR(pfn)	((pfn) << (MMU_PAGESHIFT - IDN_SMR_SHIFT))
#else
#define	PFN_TO_SMADDR(pfn)	((pfn) >> (IDN_SMR_SHIFT - MMU_PAGESHIFT))
#endif

/*
 * Translate a physical address to a unique domain identifier.
 * IMPORTANT - Assumes each board's memory is configured on a 8GB
 *	       boundary. PA(8G) = PFN(1M).
 */
#define	MEM8G_SHIFT			33	/* (1 << 33) == 8G */
#define	PADDR_TO_DOMAINID(paddr)	((int)((paddr) >> MEM8G_SHIFT) & 0xf)

#define	VALID_NWROFFSET(off, align)	\
				(((uint_t)(off) >= 0) && \
				((size_t)(off) < MB2B(IDN_NWR_SIZE)) && \
				!((uint_t)(off) & ((align) - 1)))
#define	VALID_NWRADDR(addr, align) \
		(((caddr_t)(addr) >= idn.smr.vaddr) && \
		VALID_NWROFFSET(((caddr_t)(addr) - idn.smr.vaddr), (align)))
#define	VALID_DOMAINID(d)	(((d) >= 0) && ((d) < MAX_DOMAINS))
#define	VALID_UDOMAINID(d)	((d) < MAX_DOMAINS)
#define	VALID_CPUID(c)		(((c) >= 0) && ((c) < NCPU))
#define	VALID_CHANNEL(c)	(((c) >= 0) && ((c) < IDN_MAX_NETS))
#define	VALID_UCHANNEL(c)	((c) < IDN_MAX_NETS)

/*
 * The following are bit values of idn_debug, currently
 * only useful if compiled with DEBUG.
 */
#ifdef DEBUG
#define	STRING(sss)		char sss[20]
#define	INUM2STR(mm, ss)	inum2str((mm), (ss))

#define	IDNDBG_XDC	0x00000001
#define	IDNDBG_XF	0x00000002
#define	IDNDBG_REGS	0x00000004
#define	IDNDBG_SMR	0x00000008
#define	IDNDBG_PROTO	0x00000010
#define	IDNDBG_STR	0x00000020
#define	IDNDBG_DRV	0x00000040
#define	IDNDBG_DATA	0x00000080
#define	IDNDBG_STATE	0x00000100
#define	IDNDBG_DLPI	0x00000200
#define	IDNDBG_KERN	0x00000400
#define	IDNDBG_ALLOC	0x00000800
#define	IDNDBG_REMAP	0x00001000
#define	IDNDBG_TIMER	0x00002000
#define	IDNDBG_CHAN	0x00004000
#define	IDNDBG_AWOL	0x00008000
#define	IDNDBG_SYNC	0x00010000
#define	_IDNDBG_UNUSED0	0x00020000
#define	IDNDBG_HITLIST	0x00040000
#define	IDNDBG_XMON	0x00080000
#define	IDNDBG_TEST	0x80000000
#define	IDNDBG_ALL	((uint_t)-1)

#define	PR_ALL		if (idn_debug)	printf
#define	PR_XDC		if (idn_debug & IDNDBG_XDC)	printf
#define	PR_XF		if (idn_debug & IDNDBG_XF)	printf
#define	PR_REGS		if (idn_debug & IDNDBG_REGS)	printf
#define	PR_SMR		if (idn_debug & IDNDBG_SMR)	printf
#define	PR_PROTO	if (idn_debug & IDNDBG_PROTO)	printf
#define	PR_STR		if (idn_debug & IDNDBG_STR)	printf
#define	PR_DRV		if (idn_debug & IDNDBG_DRV)	printf
#define	PR_DATA		if (idn_debug & IDNDBG_DATA)	printf
#define	PR_STATE	if (idn_debug & IDNDBG_STATE)	printf
#define	PR_DLPI		if (idn_debug & IDNDBG_DLPI)	printf
#define	PR_KERN		if (idn_debug & IDNDBG_KERN)	printf
#define	PR_ALLOC	if (idn_debug & IDNDBG_ALLOC)	printf
#define	PR_REMAP	if (idn_debug & (IDNDBG_SMR|IDNDBG_REMAP))	printf
#define	PR_TIMER	if (idn_debug & IDNDBG_TIMER)	printf
#define	PR_CHAN		if (idn_debug & IDNDBG_CHAN)	printf
#define	PR_AWOL		if (idn_debug & (IDNDBG_PROTO|IDNDBG_AWOL))	printf
#define	PR_SYNC		if (idn_debug & IDNDBG_SYNC)	printf
#define	_PR_UNUSED0	if (idn_debug & _IDNDBG_UNUSED0)	printf
#define	PR_HITLIST	if (idn_debug & IDNDBG_HITLIST)	printf
#define	PR_XMON		if (idn_debug & IDNDBG_XMON)	printf
#define	PR_TEST		if (idn_debug & IDNDBG_TEST)	printf
#else
#define	STRING(sss)	char *sss = ""
#define	INUM2STR(mm, ss)

#define	PR_ALL		if (0) printf
#define	PR_XDC		PR_ALL
#define	PR_XF		PR_ALL
#define	PR_REGS		PR_ALL
#define	PR_SMR		PR_ALL
#define	PR_PROTO	PR_ALL
#define	PR_STR		PR_ALL
#define	PR_DRV		PR_ALL
#define	PR_DATA		PR_ALL
#define	PR_STATE	PR_ALL
#define	PR_DLPI		PR_ALL
#define	PR_KERN		PR_ALL
#define	PR_ALLOC	PR_ALL
#define	PR_REMAP	PR_ALL
#define	PR_TIMER	PR_ALL
#define	PR_CHAN		PR_ALL
#define	PR_AWOL		PR_ALL
#define	PR_SYNC		PR_ALL
#define	PR_SNOOP	PR_ALL
#define	PR_HITLIST	PR_ALL
#define	PR_XMON		PR_ALL
#define	PR_TEST		PR_ALL
#endif /* DEBUG */

#ifdef _KERNEL
/*
 * IDN drivers fields.
 *
 * IDNMINPSZ	Minimum packet size the IDN supports.
 *
 * IDNMAXPSZ 	Maximum packet size that IDN supports from upper
 *		layers.  Is equal to IDN_MTU + ether_header.  Note
 *		that the IDN driver could support larger packets
 *		however the infrastructure to support fragmentation
 *		does not (and should not) exist with respect to
 *		ethernet packet types.
 */
#ifdef DEBUG
#define	IDNDESC		"Inter-Domain Network (DEBUG)"
#else
#define	IDNDESC		"Inter-Domain Network"
#endif /* DEBUG */

#define	IDNIDNUM		8264
#define	IDNNAME			"idn"
#define	IDNMINPSZ		0	/* set at idnopen() */
#define	IDNMAXPSZ		0	/* set at idnopen() */

#endif /* _KERNEL */

/*
 * IDN Global States.
 */
typedef enum {
/*  0 */	IDNGS_OFFLINE = 0,	/* idle */
/*  1 */	IDNGS_CONNECT,		/* connecting initial domain */
/*  2 */	IDNGS_ONLINE,		/* master selected */
/*  3 */	IDNGS_DISCONNECT,	/* local is unlinking */
/*  4 */	IDNGS_RECONFIG,		/* selecting new master */
/*  5 */	_IDNGS_UNUNSED5,
/*  6 */	_IDNGS_UNUNSED6,
/*  7 */	_IDNGS_UNUNSED7,
/*  8 */	_IDNGS_UNUNSED8,
/*  9 */	_IDNGS_UNUNSED9,
/* 10 */	IDNGS_IGNORE		/* ignore requests (fault injection) */
} idn_gstate_t;

#ifdef _KERNEL

#define	TIMESTAMP()	(gethrtime() / 1000000ull)

/*
 * Spaced defined in:
 *	sigblkp[cpu0.cpu_id]->sigb_idn.reserved1.
 */
#define	IDNSB_GSTATE_NEW	0
#define	IDNSB_GSTATE_OLD	1
#define	IDNSB_MASTERCPU		2
#define	IDNSB_RESERVED		3

#define	IDNSB_HWCHKPT_MAX	4

#define	IDNSB_SIZE		72
/*
 * This structure gets overlay onto:
 *	sigblkp[cpu0.cpu_id]->sigb_idn.reserved1.
 *
 * This structure must be exactly IDNSB_SIZE bytes.
 */
typedef struct idnsb {
	uchar_t		id_gstate;
	uchar_t		id_pgstate;
	uchar_t		id_master_board;
	uchar_t		id_pmaster_board;

	uchar_t		reserved_DO_NOT_USE[24];	/* idnevent_t field */

	struct {
		uchar_t	d_board;
		uchar_t	d_state;
	} id_status[MAX_DOMAINS];
	uint_t		id_hwstate;
	ushort_t	id_hwchkpt[IDNSB_HWCHKPT_MAX];
} idnsb_t;	/* sizeof = 72 (0x48) 18X bytes */


#define	IDNSB_DOMAIN_UPDATE(dp) \
	{ \
		mutex_enter(&idn.idnsb_mutex); \
		if (idn.idnsb) { \
			int	domid = (dp)->domid; \
			if ((dp)->dcpu == IDN_NIL_DCPU) \
				idn.idnsb->id_status[domid].d_board = \
						(uchar_t)0xff; \
			else if ((dp)->dvote.v.board == 0) \
				idn.idnsb->id_status[domid].d_board = \
					(uchar_t)CPUID_TO_BOARDID((dp)->dcpu); \
			else \
				idn.idnsb->id_status[domid].d_board = \
						(uchar_t)(dp)->dvote.v.board; \
			idn.idnsb->id_status[domid].d_state = \
				(uchar_t)(dp)->dstate; \
		} \
		mutex_exit(&idn.idnsb_mutex); \
	}
/*
 * The following definitions and macros pertain to the
 * id_hwstate and id_hwchkpt[] fields.
 *
 * id_hwstate (m = mark: 1=open, 2=close)
 *	  0   1   2   3   4   5   6   7
 *	---------------------------------
 *	| m | m | m | m | XX unused XXX |
 *	---------------------------------
 *	  |   |   |   |
 *	  |   |   |   +- CACHE
 *	  |   |   +- CHAN
 *	  |   +- LINK
 *	  +- SMR
 *
 * Note that nibble 4 is used in DEBUG for noting cache
 * flush progress through idnxf_flushall_ecache().  This
 * will override id_hwchkpt[] since it only has room for
 * 4 items, however the BBSRAM space is there and
 * unofficially available :-o
 *
 * id_hwchkpt[0] = SMR boardset
 * id_hwchkpt[1] = LINK boardset
 * id_hwchkpt[2] = CHAN boardset
 * id_hwchkpt[3] = CACHE boardset.
 */
#define	IDNSB_CHKPT_SMR		0
#define	IDNSB_CHKPT_LINK	1
#define	IDNSB_CHKPT_CHAN	2
#define	IDNSB_CHKPT_CACHE	3
#define	IDNSB_CHKPT_UNUSED	4	/* This is the max you can have */

#define	_CHKPT_MARKIT(item, mark) \
	{ \
		uint_t	mk = (((uint_t)((mark) & 0xf)) << \
			(((sizeof (uint_t) << 1) - 1 - (item)) << 2)); \
		uint_t	*sp = &idn.idnsb->id_hwstate; \
		ASSERT(idn.idnsb); \
		*sp &= ~(((uint_t)0xf) << (((sizeof (uint_t) << 1) \
			- 1 - (item)) << 2)); \
		*sp |= mk; \
	}

#define	CHECKPOINT_OPENED(item, bset, mark) \
	{ \
		mutex_enter(&idn.idnsb_mutex); \
		if (idn.idnsb) { \
			ushort_t *sp = &idn.idnsb->id_hwchkpt[0]; \
			_CHKPT_MARKIT((item), (mark));  \
			sp[item] |= ((ushort_t)(bset)); \
		} \
		mutex_exit(&idn.idnsb_mutex); \
	}

#define	CHECKPOINT_CLOSED(item, bset, mark) \
	{ \
		mutex_enter(&idn.idnsb_mutex); \
		if (idn.idnsb) { \
			ushort_t *sp = &idn.idnsb->id_hwchkpt[0]; \
			_CHKPT_MARKIT((item), (mark));  \
			sp[item] &= (ushort_t)~(bset); \
		} \
		mutex_exit(&idn.idnsb_mutex); \
	}

#define	CHECKPOINT_CLEAR(item, mark) \
	{ \
		mutex_enter(&idn.idnsb_mutex); \
		if (idn.idnsb) { \
			ushort_t *sp = &idn.idnsb->id_hwchkpt[0]; \
			_CHKPT_MARKIT((item), (mark));  \
			sp[item] = 0; \
		} \
		mutex_exit(&idn.idnsb_mutex); \
	}
#ifdef DEBUG
#define	CHECKPOINT_CACHE_CLEAR_DEBUG(mark) \
			CHECKPOINT_CLEAR(IDNSB_CHKPT_UNUSED, (mark))
#define	CHECKPOINT_CACHE_STEP_DEBUG(bset, mark) \
			CHECKPOINT_OPENED(IDNSB_CHKPT_UNUSED, (bset), (mark))
#else
#define	CHECKPOINT_CACHE_CLEAR_DEBUG(mark)
#define	CHECKPOINT_CACHE_STEP_DEBUG(bset, mark)
#endif /* DEBUG */


#ifdef DEBUG
#define	IDN_GSTATE_TRANSITION(ns) \
	{ \
		hrtime_t	tstamp; \
		/*LINTED*/ \
		IDN_HISTORY_LOG(IDNH_GSTATE, (ns), 0, 0); \
		tstamp = TIMESTAMP(); \
		ASSERT(IDN_GLOCK_IS_EXCL()); \
		PR_STATE("GSTATE:%ld: (l=%d) %s(%d) -> %s(%d)\n", \
			(uint64_t)tstamp, __LINE__, \
			idngs_str[idn.state], idn.state, \
			idngs_str[ns], (ns)); \
		mutex_enter(&idn.idnsb_mutex); \
		if (idn.idnsb) { \
			idn.idnsb->id_pgstate = (uchar_t)idn.state; \
			idn.idnsb->id_gstate = (uchar_t)(ns); \
		} \
		mutex_exit(&idn.idnsb_mutex); \
		idn.state = (ns); \
	}
#else
#define	IDN_GSTATE_TRANSITION(ns) \
	{ \
		IDN_HISTORY_LOG(IDNH_GSTATE, (ns), 0, 0); \
		mutex_enter(&idn.idnsb_mutex); \
		if (idn.idnsb) { \
			idn.idnsb->id_pgstate = (uchar_t)idn.state; \
			idn.idnsb->id_gstate = (uchar_t)(ns); \
		} \
		mutex_exit(&idn.idnsb_mutex); \
		idn.state = (ns); \
	}
#endif /* DEBUG */

/*
 * IDN link/unlink operations occur asynchronously with respect to the
 * caller.  The following definitions are to support the return of
 * success/failure back to the original requesting thread.  It's
 * unlikely to have multiple outstanding link/unlink requests so we
 * just provide a very small cache of waiting list entries.  If the
 * cache becomes exhausted then additional ones are kmem_alloc'd.
 */
#define	IDNOP_CACHE_SIZE	3
#define	IDNOP_IN_CACHE(dwl)	\
	(((dwl) >= &idn.dopers->_dop_wcache[0]) && \
	((dwl) < &idn.dopers->_dop_wcache[IDNOP_CACHE_SIZE]))

typedef struct dop_waitlist {
	struct dop_waitlist	*dw_next;
	domainset_t	dw_reqset;
	domainset_t	dw_domset;
	short		dw_op;
	domainset_t	dw_errset;
	idnsb_error_t	*dw_idnerr;
	short		dw_errors[MAX_DOMAINS];
} dop_waitlist_t;

typedef uint_t	idn_xdcargs_t[4];
typedef uint_t	idn_chanset_t;

/*
 * Types of synchronization zones which a connection
 * could be in.
 */
typedef enum {
	IDNSYNC_NIL,
	IDNSYNC_CONNECT,
	IDNSYNC_DISCONNECT
} idn_synccmd_t;

/*
 * Type of sync-registration that is being requested.
 */
typedef enum {
	IDNSYNC_REG_REG,
	IDNSYNC_REG_NEW,
	IDNSYNC_REG_QUERY
} idn_syncreg_t;

#define	IDN_SYNC_NUMZONE	3
#define	IDN_SYNC_GETZONE(s)	((((s) != IDNSYNC_CONNECT) && \
				((s) != IDNSYNC_DISCONNECT)) ? \
				-1 : (int)(s) - 1)
#define	IDN_SYNC_GETTRANS(s)	(((s) == IDNSYNC_CONNECT) ? \
				idn.domset.ds_trans_on : \
				((s) == IDNSYNC_DISCONNECT) ? \
				idn.domset.ds_trans_off : 0)

/*
 * Generic states when in a state transition region.
 * These ultimately map to domain states via
 * a idn_xphase_t definition.  General model:
 *
 *		PEND
 *		 /\
 *	        /  \
 *	       |    |
 *             V    V
 *          SENT--->RCVD
 *	       \    /
 *	        \  /
 *	         VV
 *		FINAL
 *
 * Start these types with PEND = 0 so that they're
 * compatible with idnxs_state_table[] and idn_xphase_t
 * phases that use the value as an index.
 */
typedef enum {
/* 0 */		IDNXS_PEND = 0,
/* 1 */		IDNXS_SENT,
/* 2 */		IDNXS_RCVD,
/* 3 */		IDNXS_FINAL,
/* 4 */		IDNXS_NIL
} idn_xstate_t;

/*
 * Locking protocol:
 *
 *	Each routine is called with SYNC_LOCK and
 *	the respective domain's DLOCK(EXCL) held.
 *	The routines must return with these locks
 *	still held.
 */
struct idn_msgtype;

typedef struct {
	int	t_state;
	int	(*t_check)(int domid, struct idn_msgtype *mtp,
				idn_xdcargs_t xargs);
	void	(*t_action)(int domid, struct idn_msgtype *mtp,
				idn_xdcargs_t xargs);
	void	(*t_error)(int domid, struct idn_msgtype *mtp,
				idn_xdcargs_t xargs);
} idn_trans_t;

/*
 * The callback routines (xt_final & xt_exit) are called with
 * DLOCK and SYNC_LOCK held and they are required to return
 * with these locks still held.
 */
typedef struct {
	uint_t		xt_msgtype;
	idn_trans_t	xt_trans[4];
	void		(*xt_final)(int domid);
	void		(*xt_exit)(int domid, uint_t msgtype);
} idn_xphase_t;

/*
 * Synchronization entry representing the synchronization
 * state with respect to a given domain for a given zone.
 */
typedef struct idn_syncop {
	struct idn_syncop	*s_next;
	int			s_domid;
	idn_synccmd_t		s_cmd;
	int			s_msg;

	domainset_t		s_set_exp;
	domainset_t		s_set_rdy;
	int			(*s_transfunc)(int domid, void *arg);
	void			*s_transarg;
#ifdef DEBUG
	int			s_query[MAX_DOMAINS];
#endif /* DEBUG */
} idn_syncop_t;

#ifdef DEBUG
#define	IDN_SYNC_QUERY_INIT(d) \
			(bzero((caddr_t)idn_domain[d].dsync.s_query, \
				sizeof (idn_domain[d].dsync.s_query)))
#define	IDN_SYNC_QUERY_UPDATE(md, sd)	(idn_domain[md].dsync.s_query[sd]++)
#else /* DEBUG */
#define	IDN_SYNC_QUERY_INIT(d)
#define	IDN_SYNC_QUERY_UPDATE(md, sd)
#endif /* DEBUG */

typedef struct {
	idn_syncop_t	*sc_op;
	int		sc_cnt;
} idn_synczone_t;

#endif /* _KERNEL */

/*
 * Vote Ticket used during negotiations and elections.
 *
 * 31					  0
 * -----------------------------------------
 * |m...|....|pppp|....|Cbbb|bccc|cccB|BBB1|
 * -----------------------------------------
 * m	[31]	= master/slave
 * .	[30:24]	= unused
 * p	[23:20]	= priority
 * .	[19:16]	= unused
 * C	[15]    = connected (has master)
 * b	[14:11]	= nmembrds-1
 * c	[10:5]	= ncpus-1
 * B	[4:1]	= board_id
 * 1	[0]	= one
 */
typedef union {
	struct {
		uint_t	master    :1;
		uint_t	unused0   :7;
		uint_t	priority  :4;
		uint_t	unused1   :4;
		uint_t	connected :1;
		uint_t	nmembrds  :4;
		uint_t	ncpus	  :6;
		uint_t	board	  :4;
		uint_t	one	  :1;
	} v;
	uint_t	ticket;
} idn_vote_t;

#define	IDNVOTE_PRI_MASK	0xf
#define	IDNVOTE_MAXPRI		0xf
#define	IDNVOTE_MINPRI		0
#define	IDNVOTE_DEFPRI		1	/* must be larger than MINPRI */
/*
 * Initially:
 *	vote.v.priority = IDNVOTE_DEFPRI
 *	vote.v.one	= 1
 */
#define	IDNVOTE_INITIAL_TICKET	((IDNVOTE_DEFPRI << 20) | 1)
#define	IDNVOTE_PRIVALUE(vvv) \
	((int)vvv.v.priority + ((int)vvv.v.master ? IDNVOTE_MAXPRI : 0))

/*
 * During elections we only use the "elect" attributes of the
 * election ticket, i.e. those physical attributes pertaining
 * to the individual domain (priority, nboards, ncpus, board).
 */
#define	IDNVOTE_ELECT_MASK	0x00f07fff
#define	IDNVOTE_ELECT(tkt)	((tkt).ticket & IDNVOTE_ELECT_MASK)
#define	IDNVOTE_BASICS_MASK	0x00f0ffff
#define	IDNVOTE_BASICS(tkt)	((tkt).ticket & IDNVOTE_BASICS_MASK)

/*
 * Values used in idn_select_master().
 */
#define	MASTER_IS_NONE		0	/* index into master_select_table */
#define	MASTER_IS_OTHER		1
#define	MASTER_IS_LOCAL		2
#define	MASTER_IS_REMOTE	3

typedef enum {
	MASTER_SELECT_VOTE,
	MASTER_SELECT_VOTE_RCFG,
	MASTER_SELECT_CONNECT,
	MASTER_SELECT_REMOTE,
	MASTER_SELECT_LOCAL,
	MASTER_SELECT_WAIT,
	MASTER_SELECT_ERROR
} idn_master_select_t;

/*
 * Used to synchronize completion of link/unlink with respect to
 * the original requester (user).  Necessary since link establishment
 * occurs asynchronously.
 */
typedef enum {
/*  0 */	IDNOP_DISCONNECTED,	/* successfully disconnected */
/*  1 */	IDNOP_CONNECTED,	/* successfully established */
/*  2 */	IDNOP_ERROR		/* error trying to link/unlink */
} idn_opflag_t;

/*
 * IDN Protocol Messages.
 * These are IDN version (IDN_VERSION) dependent.
 *
 *	----- 7, --- 6,5.................0
 *	|  ack | nack | IDN message type |
 *	----------------------------------
 */
#define	IDN_VERSION	1

/*
 * Must be no more than 6-bits.  See DMV private data.
 */
#define	IDNP_ACK	0x20
#define	IDNP_NACK	0x10
#define	IDNP_NULL	0x00
#define	IDNP_NEGO	0x01
#define	IDNP_CON	0x02
#define	IDNP_CFG	0x03
#define	IDNP_FIN	0x04
#define	IDNP_CMD	0x05
#define	IDNP_DATA	0x06

#define	IDN_NUM_MSGTYPES	7
#define	IDNP_ACKNACK_MASK	(IDNP_ACK | IDNP_NACK)
#define	IDNP_MSGTYPE_MASK	0x0f
#define	VALID_MSGTYPE(m)	(((m) >= IDNP_NEGO) && ((m) < IDN_NUM_MSGTYPES))

typedef struct idn_msgtype {
	ushort_t	mt_mtype;
	ushort_t	mt_atype;
	ushort_t	mt_cookie;
} idn_msgtype_t;

/*
 * IDN private data section of DMV layout (48 bits).
 *
 * 47......40,39.....34,33.....28,27..24,23......16,15..............0
 * | version | msgtype | acktype |  did |   cpuid  |     cookie     |
 * ------------------------------------------------------------------
 *
 * version	Local domain's version of IDN software.
 * msgtype	Type of IDN message, e.g. nego, syn, etc.
 * acktype	If msgtype is a ACK or NACK, then acktype is the
 *		type of ack that we're receiving, e.g. ack/nego|ack.
 * did		Local domain's ID (netid) - system-wide unique.
 * cpuid	Local domain's CPU->cpu_id that sending message.
 * cookie	Cookie assigned by remote domain for authentication.
 *		For NEGO & NEGO+ACK messages, it's the cookie that
 *		the sender expects the receiver to use in subsequent
 *		messages.  The upper-eight bits represent a timer
 *		cookie to associate timers with expected messages.
 */
#endif /* !_ASM */

#ifdef _KERNEL

#define	_IDNPD_COOKIE_MASK	0xffff
#define	_IDNPD_COOKIE_SHIFT	32
#define	_IDNPD_VER_MASK		0xff
#define	_IDNPD_VER_SHIFT	24
#define	_IDNPD_MTYPE_MASK	0x3f
#define	_IDNPD_MTYPE_SHIFT	18
#define	_IDNPD_ATYPE_MASK	0x3f
#define	_IDNPD_ATYPE_SHIFT	12
#define	_IDNPD_DOMID_MASK	0xf
#define	_IDNPD_DOMID_SHIFT	8
#define	_IDNPD_CPUID_MASK	0xff
#define	_IDNPD_CPUID_SHIFT	0

#define	_IDNPD_COOKIE_LEN	16

#ifndef _ASM

#define	IDN_PD2COOKIE(pdata) \
	(((uint_t)((pdata) >> _IDNPD_COOKIE_SHIFT)) & _IDNPD_COOKIE_MASK)
#define	IDN_PD2VER(pdata) \
	(((uint_t)((pdata) >> _IDNPD_VER_SHIFT)) & _IDNPD_VER_MASK)
#define	IDN_PD2MTYPE(pdata) \
	(((uint_t)((pdata) >> _IDNPD_MTYPE_SHIFT)) & _IDNPD_MTYPE_MASK)
#define	IDN_PD2ATYPE(pdata) \
	(((uint_t)((pdata) >> _IDNPD_ATYPE_SHIFT)) & _IDNPD_ATYPE_MASK)
#define	IDN_PD2DOMID(pdata) \
	(((uint_t)((pdata) >> _IDNPD_DOMID_SHIFT)) & _IDNPD_DOMID_MASK)
#define	IDN_PD2CPUID(pdata) \
	(((uint_t)((pdata) >> _IDNPD_CPUID_SHIFT)) & _IDNPD_CPUID_MASK)

#define	IDN_MAKE_PDATA(mtype, atype, cookie) \
	((((uint64_t)(cookie) & UINT64_C(_IDNPD_COOKIE_MASK))	<< \
					_IDNPD_COOKIE_SHIFT)	| \
	(((uint64_t)idn.version & UINT64_C(_IDNPD_VER_MASK))	<< \
					_IDNPD_VER_SHIFT)	| \
	(((uint64_t)(mtype) & UINT64_C(_IDNPD_MTYPE_MASK))	<< \
					_IDNPD_MTYPE_SHIFT)	| \
	(((uint64_t)(atype) & UINT64_C(_IDNPD_ATYPE_MASK))	<< \
					_IDNPD_ATYPE_SHIFT)	| \
	(((uint64_t)idn.localid & UINT64_C(_IDNPD_DOMID_MASK))	<< \
					_IDNPD_DOMID_SHIFT)	| \
	(((uint64_t)CPU->cpu_id & UINT64_C(_IDNPD_CPUID_MASK))	<< \
					_IDNPD_CPUID_SHIFT))

#define	IDN_TCOOKIE(ck)		(((ck) >> 8) & 0xff)
#define	IDN_DCOOKIE(ck)		((ck) & 0xff)
#define	IDN_MAKE_COOKIE(d, t)	((((t) & 0xff) << 8) | ((d) & 0xff))

/*
 * IDNP_NEGO
 *
 * 127........96,95........64,63........32,31.........0
 * |   vote     |             domainset               |
 * ----------------------------------------------------
 * vote		Local/Remote domain's vote ticket.
 * domainset	Mask of cpuids of domains to which
 *		sender is connected.  Position in domainset
 *		designates respective domainid.
 *		E.g. domainset[6] = 20 -> domainid 6 is
 *		accessible via cpuid 20.
 *		The slot for the receiving domain
 *		contains the masterid of the sending
 *		domain.  If the sending domain does
 *		not have a master then the entry will
 *		contain IDNNEG_NO_MASTER.
 *
 * These macros insert a domainid-cpuid pair into the
 * domainset to be subsequently passed in a NEGO message,
 * also retrieve the cpuid from the domainset for a
 * given domainid.
 *
 * Usage:
 *	Sending:
 *		mask = IDNNEG_DSET_MYMASK();
 *		IDNNEG_DSET_INIT(dset, mask)
 *		for (all domains except self)
 *			IDNNEG_DSET_SET(dset, domain, cpuid, mask);
 *
 *	Receiving:
 *		IDNNEG_DSET_GET_MASK(dset, recv_domid, recv_mask);
 *		for (all domains except recv_domid)
 *			IDNNEG_DSET_GET(dset, domid, cpuid, recv_mask);
 */
typedef uint_t	idnneg_dset_t[3];

#define	IDNNEG_NO_MASTER		0x3f
#define	__IDNNEG_DSET_CLEAR(dset)	(bzero((caddr_t)(dset), \
						sizeof (idnneg_dset_t)))
#define	IDNNEG_DSET_MYMASK()		(idn_domain[idn.localid].dcpu)

#define	IDNNEG_DSET_INIT(dset, mask) \
	{ \
		__IDNNEG_DSET_CLEAR(dset); \
		IDNNEG_DSET_SET((dset), idn.localid, (mask), idn.localid); \
	}

#define	IDNNEG_DSET_SET(dset, domid, cpuid, mask) \
	{ \
		uint_t	_s = ((domid) & 0xf) * 6; \
		int	_i = _s >> 5; \
		uint_t	_s0 = _s & 0x1f; \
		uint_t	_t = ((cpuid) ^ (mask)) & 0x3f; \
		/*LINTED*/ \
		ASSERT(((domid) == idn.localid) ? \
			((mask) == idn.localid) : ((cpuid) != (mask))); \
		(dset)[_i] |= _t << _s0; \
		if ((_s0 + 6) > 32) \
			(dset)[_i + 1] |= _t >> (32 - _s0);  \
	}

#define	__IDNNEG_DSET_GET(dset, domid, cpuid, mask, uncond) \
	{ \
		uint_t	_s = ((domid) & 0xf) * 6; \
		int	_i = _s >> 5; \
		uint_t	_s0 = _s & 0x1f; \
		uint_t	_s1 = (_s + 6) & 0x1f; \
		(cpuid) = ((dset)[_i] >> _s0) & 0x3f; \
		if ((_s0 + 6) > 32) \
			(cpuid) |= ((dset)[_i + 1] << (6 - _s1)) & 0x3f; \
		if ((cpuid) || (uncond)) \
			(cpuid) ^= (mask) & 0x3f; \
		else \
			(cpuid) = -1; \
	}

#define	IDNNEG_DSET_GET_MASK(dset, domid, mask) \
		__IDNNEG_DSET_GET((dset), (domid), (mask), (domid), 1)

#define	IDNNEG_DSET_GET_MASTER(dset, master) \
		__IDNNEG_DSET_GET((dset), idn.localid, (master), \
				idn.localid+MAX_DOMAINS, 0)

#define	IDNNEG_DSET_SET_MASTER(dset, domid, master) \
		IDNNEG_DSET_SET((dset), (domid), (master), \
				(domid)+MAX_DOMAINS)

#define	IDNNEG_DSET_GET(dset, domid, cpuid, mask) \
		__IDNNEG_DSET_GET((dset), (domid), (cpuid), (mask), 0)

/*
 * IDNP_CFG sub-types.
 *
 * Format of first 32 bit word in XDC:
 *	stX  = sub-type.
 *	staX = sub-type arg.
 *	X    = position in idn_cfgsubtype_t.param.p[] array.
 *	num  = number of parameters in this XDC (0-3)
 *
 *      31...28,27...24,23...20,19...16,15...12,11....8,7.....3,2....0
 *	|  st0 .  sta0 |   st1 .  sta1 |   st2 .  sta2 | phase | num |
 *	--------------------------------------------------------------
 *
 * Note that since the first 32-bit word in a (IDNP_CFG) XDC is used
 * for a sub-type, subsequent three 32-bits words are used for data that
 * pertains to respective sub-type, i.e. first sub-type corresponds
 * to first of the 3x32-bit words (pos=0), second sub-type corresponds
 * to second of the 3x32-bit words (pos=1), etc.  Obviously, a max of
 * only three sub-types can be sent per xdc.
 */
#define	IDNCFG_BARLAR		0x1	/* SMR base/limit pfn */
#define	  IDNCFGARG_BARLAR_BAR		0	/* BAR */
#define	  IDNCFGARG_BARLAR_LAR		1	/* LAR */
#define	IDNCFG_MCADR		0x2	/* MC ADR, arg = board number */
#define	IDNCFG_NMCADR		0x3	/* Number of MC ADRs to expect */
#define	IDNCFG_CPUSET		0x4	/* dcpuset of remote domain */
#define	  IDNCFGARG_CPUSET_UPPER  	0	/* 1st word */
#define	  IDNCFGARG_CPUSET_LOWER  	1	/* 2nd word */
#define	IDNCFG_NETID		0x5	/* dnetid, arg = 0 */
#define	IDNCFG_BOARDSET		0x6	/* board set, arg = 0 */
#define	IDNCFG_SIZE		0x7	/* SMR size parameters */
#define	  IDNCFGARG_SIZE_MTU		0	/* IDN_MTU */
#define	  IDNCFGARG_SIZE_BUF		1	/* IDN_SMR_BUFSIZE */
#define	  IDNCFGARG_SIZE_SLAB		2	/* IDN_SLAB_BUFCOUNT */
#define	  IDNCFGARG_SIZE_NWR		3	/* IDN_NWR_SIZE */
#define	IDNCFG_DATAMBOX		0x8	/* SMR data mailbox info */
#define	  IDNCFGARG_DATAMBOX_TABLE  	0	/* recvmbox table */
#define	  IDNCFGARG_DATAMBOX_DOMAIN	1	/* domain's recvmbox */
#define	  IDNCFGARG_DATAMBOX_INDEX	2	/* domain's index into table */
#define	IDNCFG_DATASVR		0x9	/* Data server info */
#define	  IDNCFGARG_DATASVR_MAXNETS	0	/* max # of nets/channels */
#define	  IDNCFGARG_DATASVR_MBXPERNET	1	/* # mbox per net/channel */
#define	IDNCFG_OPTIONS		0xa	/* various options */
#define	  IDNCFGARG_CHECKSUM		0	/* IDN_CHECKSUM */

#define	IDN_CFGPARAM(st, sta)	((uchar_t)((((st) & 0xf) << 4) | ((sta) & 0xf)))
#define	IDN_CFGPARAM_TYPE(p)	(((p) >> 4) & 0xf)
#define	IDN_CFGPARAM_ARG(p)	((p) & 0xf)

typedef union {
	struct {
		uchar_t	p[3];
		uchar_t	_num_phase;	/* info.num, info.phase used instead */
	} param;
	struct {
		uint_t	_p	: 24;	/* param.p[] used instead */
		uint_t	num	: 2;
		uint_t	phase	: 6;
	} info;
	uint_t	val;
} idn_cfgsubtype_t;

/*
 * IDN_MASTER_NCFGITEMS
 *	Minimum number of config items expected from master.
 *
 * IDN_SLAVE_NCFGITEMS
 *	Number of config items expected from slave.
 */
#define	IDN_MASTER_NCFGITEMS	17	/* max = +14 (mcadrs) */
#define	IDN_SLAVE_NCFGITEMS	12

/*
 * IDNP_CMD sub-types.
 */
typedef enum {
/*  1 */	IDNCMD_SLABALLOC = 1,	/* Request to allocate a slab */
/*  2 */	IDNCMD_SLABFREE,	/* Request to free a slab */
/*  3 */	IDNCMD_SLABREAP,	/* Reap any free slabs */
/*  4 */	IDNCMD_NODENAME		/* Query nodename of domain */
} idn_cmd_t;

#define	VALID_IDNCMD(c)		(((int)(c) >= (int)IDNCMD_SLABALLOC) && \
					((int)(c) <= (int)IDNCMD_NODENAME))
/*
 * IDNP_NACK
 */
typedef enum {
/*  1 */	IDNNACK_NOCONN = 1,
/*  2 */	IDNNACK_BADCHAN,
/*  3 */	IDNNACK_BADCFG,
/*  4 */	IDNNACK_BADCMD,
/*  5 */	IDNNACK_RETRY,
/*  6 */	IDNNACK_DUP,
/*  7 */	IDNNACK_EXIT,
/*  8 */	IDNNACK_RESERVED1,
/*  9 */	IDNNACK_RESERVED2,
/* 10 */	IDNNACK_RESERVED3
} idn_nack_t;

/*
 * IDNP_CON sub-types.
 */
typedef enum {
/*  0 */	IDNCON_OFF = 0,
/*  1 */	IDNCON_NORMAL,		/* regular connect sequence */
/*  2 */	IDNCON_QUERY		/* query for connect info */
} idn_con_t;

/*
 * IDNP_FIN sub-types.
 */
typedef enum {
/*  0 */	IDNFIN_OFF = 0,		/* active, no fin */
/*  1 */	IDNFIN_NORMAL,		/* normal disconnect req */
/*  2 */	IDNFIN_FORCE_SOFT,	/* normal dis, force if goes AWOL */
/*  3 */	IDNFIN_FORCE_HARD,	/* force disconnect of AWOL domain */
/*  4 */	IDNFIN_QUERY		/* query for fin info */
} idn_fin_t;

#define	VALID_FIN(f)		(((int)(f) > 0) && \
					((int)(f) < (int)IDNFIN_QUERY))
#define	FIN_IS_FORCE(f)		(((f) == IDNFIN_FORCE_SOFT) || \
					((f) == IDNFIN_FORCE_HARD))

/*
 * FIN ARG types - reasons a FIN was sent.
 */
typedef enum {
/*  0 */	IDNFIN_ARG_NONE = 0,		/* no argument */
/*  1 */	IDNFIN_ARG_SMRBAD,		/* SMR is corrupted */
/*  2 */	IDNFIN_ARG_CPUCFG,		/* missing cpu per board */
/*  3 */	IDNFIN_ARG_HWERR,		/* error programming hardware */
/*  4 */	IDNFIN_ARG_CFGERR_FATAL,	/* Fatal error during CONFIG */
/*  5 */	IDNFIN_ARG_CFGERR_MTU,		/* MTU sizes conflict */
/*  6 */	IDNFIN_ARG_CFGERR_BUF,		/* SMR_BUF_SIZE conflicts */
/*  7 */	IDNFIN_ARG_CFGERR_SLAB,		/* SLAB sizes conflict */
/*  8 */	IDNFIN_ARG_CFGERR_NWR,		/* NWR sizes conflict */
/*  9 */	IDNFIN_ARG_CFGERR_NETS,		/* MAX_NETS conflict */
/* 10 */	IDNFIN_ARG_CFGERR_MBOX,		/* MBOX_PER_NET conflict */
/* 11 */	IDNFIN_ARG_CFGERR_NMCADR,	/* NMCADR mismatches actual */
/* 12 */	IDNFIN_ARG_CFGERR_MCADR,	/* missing some MCADRs */
/* 13 */	IDNFIN_ARG_CFGERR_CKSUM,	/* checksum settings conflict */
/* 14 */	IDNFIN_ARG_CFGERR_SMR		/* SMR sizes conflict */
} idn_finarg_t;

#define	IDNFIN_ARG_IS_FATAL(fa)	((fa) > IDNFIN_ARG_NONE)

#define	SET_FIN_TYPE(x, t) \
		((x) &= 0xffff, (x) |= (((uint_t)(t) & 0xffff) << 16))
#define	SET_FIN_ARG(x, a) \
		((x) &= ~0xffff, (x) |= ((uint_t)(a) & 0xffff))
#define	GET_FIN_TYPE(x)		((idn_fin_t)(((x) >> 16) & 0xffff))
#define	GET_FIN_ARG(x)		((idn_finarg_t)((x) & 0xffff))

#define	FINARG2IDNKERR(fa) \
	(((fa) == IDNFIN_ARG_SMRBAD)	   ? IDNKERR_SMR_CORRUPTED : \
	((fa) == IDNFIN_ARG_CPUCFG)	   ? IDNKERR_CPU_CONFIG	   : \
	((fa) == IDNFIN_ARG_HWERR)	   ? IDNKERR_HW_ERROR	   : \
	((fa) == IDNFIN_ARG_CFGERR_FATAL)  ? IDNKERR_HW_ERROR	   : \
	((fa) == IDNFIN_ARG_CFGERR_MTU)    ? IDNKERR_CONFIG_MTU	   : \
	((fa) == IDNFIN_ARG_CFGERR_BUF)    ? IDNKERR_CONFIG_BUF	   : \
	((fa) == IDNFIN_ARG_CFGERR_SLAB)   ? IDNKERR_CONFIG_SLAB   : \
	((fa) == IDNFIN_ARG_CFGERR_NWR)    ? IDNKERR_CONFIG_NWR    : \
	((fa) == IDNFIN_ARG_CFGERR_NETS)   ? IDNKERR_CONFIG_NETS   : \
	((fa) == IDNFIN_ARG_CFGERR_MBOX)   ? IDNKERR_CONFIG_MBOX   : \
	((fa) == IDNFIN_ARG_CFGERR_NMCADR) ? IDNKERR_CONFIG_NMCADR : \
	((fa) == IDNFIN_ARG_CFGERR_MCADR)  ? IDNKERR_CONFIG_MCADR  : \
	((fa) == IDNFIN_ARG_CFGERR_CKSUM)  ? IDNKERR_CONFIG_CKSUM  : \
	((fa) == IDNFIN_ARG_CFGERR_SMR)	   ? IDNKERR_CONFIG_SMR    : 0)

/*
 * FIN SYNC types.
 */
#define	IDNFIN_SYNC_OFF		0	/* not set */
#define	IDNFIN_SYNC_NO		1	/* no-sync necessary */
#define	IDNFIN_SYNC_YES		2	/* do fin synchronously */

typedef short	idn_finsync_t;

/*
 * IDNP_FIN options.
 */
typedef enum {
/*  0 */	IDNFIN_OPT_NONE = 0,	/* none (used w/query) */
/*  1 */	IDNFIN_OPT_UNLINK,	/* normal unlink request */
/*  2 */	IDNFIN_OPT_RELINK	/* disconnect and retry link */
} idn_finopt_t;

#define	VALID_FINOPT(f)		(((f) == IDNFIN_OPT_UNLINK) || \
				((f) == IDNFIN_OPT_RELINK))

#define	FIN_MASTER_DOMID(x)	(((((x) >> 16) & 0xffff) == 0xffff) ? \
				IDN_NIL_DOMID : (((x) >> 16) & 0xffff))
#define	FIN_MASTER_CPUID(x)	((((x) & 0xffff) == 0xffff) ? \
				IDN_NIL_DCPU : ((x) & 0xfff))
#define	MAKE_FIN_MASTER(d, c)	((((uint_t)(d) & 0xffff) << 16) | \
				((uint_t)(c) & 0xffff))
#define	NIL_FIN_MASTER		MAKE_FIN_MASTER(IDN_NIL_DOMID, IDN_NIL_DCPU)

#ifdef DEBUG
#define	IDN_FSTATE_TRANSITION(dp, ns) \
	{ \
		int	_id; \
		_id = (dp)->domid; \
		if ((dp)->dfin != (ns)) { \
			hrtime_t	tstamp; \
			tstamp = TIMESTAMP(); \
			IDN_HISTORY_LOG(IDNH_FIN, _id, (ns), 0); \
			PR_STATE("FSTATE:%ld:%d: (l=%d, b/p=%d/%d) " \
				"%s(%d) -> %s(%d)\n", \
				(uint64_t)tstamp, _id, \
				__LINE__, \
				((dp)->dcpu == IDN_NIL_DCPU) ? -1 : \
					CPUID_TO_BOARDID((dp)->dcpu), \
				(dp)->dcpu, \
				idnfin_str[(dp)->dfin], (dp)->dfin, \
				idnfin_str[ns], (ns)); \
			(dp)->dfin = (ns); \
		} \
	}
#else
#define	IDN_FSTATE_TRANSITION(dp, ns) \
	{ \
		IDN_HISTORY_LOG(IDNH_FIN, (dp)->domid, (ns), 0); \
		(dp)->dfin = (ns); \
	}
#endif /* DEBUG */

#endif /* !_ASM */
#endif /* _KERNEL */

#ifndef _ASM
/*
 * IDN Per-Domain States.
 */
typedef enum {
/*  0 */	IDNDS_CLOSED,		/* idle */
/*  1 */	IDNDS_NEGO_PEND,	/* link initiating */
/*  2 */	IDNDS_NEGO_SENT,	/* link initiated, nego sent */
/*  3 */	IDNDS_NEGO_RCVD,	/* link wanted, nego+ack sent */
/*  4 */	IDNDS_CONFIG,		/* passing config info, prgm hw */
/*  5 */	IDNDS_CON_PEND,		/* connection pending */
/*  6 */	IDNDS_CON_SENT,		/* con sent */
/*  7 */	IDNDS_CON_RCVD,		/* con sent & received */
/*  8 */	IDNDS_CON_READY,	/* ready to establish link */
/*  9 */	IDNDS_CONNECTED,	/* established - linked */
/* 10 */	IDNDS_FIN_PEND,		/* unlink initiating */
/* 11 */	IDNDS_FIN_SENT,		/* unlink initiated, fin sent */
/* 12 */	IDNDS_FIN_RCVD,		/* unlink wanted by remote */
/* 13 */	IDNDS_DMAP		/* deprogramming hw */
} idn_dstate_t;

#define	IDNDS_IS_CLOSED(dp)	(((dp)->dstate == IDNDS_CLOSED) || \
				((dp)->dstate == IDNDS_DMAP))
#define	IDNDS_IS_CONNECTING(dp) (((dp)->dstate > IDNDS_CLOSED) && \
				((dp)->dstate < IDNDS_CONNECTED))
#define	IDNDS_IS_DISCONNECTING(dp)	((dp)->dstate > IDNDS_CONNECTED)
#define	IDNDS_CONFIG_DONE(dp)	(((dp)->dstate == IDNDS_CLOSED) || \
				((dp)->dstate > IDNDS_CONFIG))
#define	IDNDS_SYNC_TYPE(dp)	(((dp)->dfin_sync != IDNFIN_SYNC_OFF) ? \
				(dp)->dfin_sync : \
					((dp)->dstate < IDNDS_CON_READY) ? \
					IDNFIN_SYNC_NO : IDNFIN_SYNC_YES)

#endif /* !_ASM */

#ifdef _KERNEL
#ifndef _ASM
/*
 * ---------------------------------------------------------------------
 */
typedef struct idn_timer {
	struct idn_timer	*t_forw,
				*t_back;
	struct idn_timerq	*t_q;

	timeout_id_t		t_id;
	short			t_domid;
	short			t_onq;
	ushort_t		t_type;
	ushort_t		t_subtype;
	uint_t			t_cookie;
#ifdef DEBUG
	hrtime_t		t_posttime;
	hrtime_t		t_exectime;
#endif /* DEBUG */
} idn_timer_t;

#define	IDN_TIMER_PUBLIC_COOKIE		0xf

#define	IDN_TIMERQ_IS_LOCKED(tq)	(MUTEX_HELD(&(tq)->tq_mutex))
#define	IDN_TIMERQ_LOCK(tq)		(mutex_enter(&(tq)->tq_mutex))
#define	IDN_TIMERQ_UNLOCK(tq)		(mutex_exit(&(tq)->tq_mutex))

#define	IDN_TIMERQ_INIT(tq) 		(idn_timerq_init(tq))
#define	IDN_TIMERQ_DEINIT(tq) 		(idn_timerq_deinit(tq))
#define	IDN_TIMER_ALLOC()		(idn_timer_alloc())
#define	IDN_TIMER_FREE(tp)		(idn_timer_free(tp))

#define	IDN_TIMER_START(tq, tp, tim) \
			(idn_timer_start((tq), (tp), (tim)))
#define	IDN_TIMER_STOP(tq, typ, ck) \
			((void) idn_timer_stop((tq), (typ), (ck)))
#define	IDN_TIMER_STOPALL(tp) \
			((void) idn_timer_stopall(tp))
#define	IDN_TIMER_GET(tq, typ, tp, ck) \
	{ \
		mutex_enter(&((tq)->tq_mutex)); \
		(tp) = idn_timer_get((tq), (typ), (ck)); \
		mutex_exit(&((tq)->tq_mutex)); \
	}
#define	IDN_TIMER_DEQUEUE(tq, tp) \
			(idn_timer_dequeue((tq), (tp)))
#ifdef DEBUG
#define	IDN_TIMER_POST(tp) \
	((tp)->t_posttime = gethrtime(), (tp)->t_exectime = 0)
#define	IDN_TIMER_EXEC(tp)	((tp)->t_exectime = gethrtime())
#else /* DEBUG */
#define	IDN_TIMER_POST(tp)
#define	IDN_TIMER_EXEC(tp)
#endif /* DEBUG */

#define	IDN_MSGTIMER_START(domid, typ, subtyp, tim, ckp) \
	{ \
		idn_timer_t	*_tp; \
		char		_str[15]; \
		ushort_t	*_ckp = (ckp); \
		inum2str((typ), _str); \
		PR_TIMER("msgtimer:%d: START: type = %s (0x%x)\n", \
				(domid), _str, (typ)); \
		_tp = IDN_TIMER_ALLOC(); \
		_tp->t_type	= (ushort_t)(typ); \
		_tp->t_subtype	= (ushort_t)(subtyp); \
		_tp->t_domid	= (short)(domid); \
		_tp->t_cookie	= (_ckp) ? *(_ckp) : 0; \
		IDN_TIMER_POST(_tp); \
		if (_ckp) { \
			*(_ckp) = IDN_TIMER_START(&idn_domain[domid].dtimerq, \
						_tp, (tim)); \
		} else { \
			(void) IDN_TIMER_START(&idn_domain[domid].dtimerq, \
						_tp, (tim)); \
		} \
	}
#define	IDN_MSGTIMER_STOP(domid, typ, ck) \
	{ \
		char	_str[15]; \
		inum2str((typ), _str); \
		PR_TIMER("msgtimer:%d: STOP: type = %s (0x%x), " \
			"cookie = 0x%x\n", \
				(domid), _str, (typ), (ck)); \
		IDN_TIMER_STOP(&idn_domain[domid].dtimerq, (typ), (ck)); \
	}
#define	IDN_MSGTIMER_GET(dp, typ, tp, ck) \
			IDN_TIMER_GET(&(dp)->dtimerq, (typ), (tp), (ck))

/*
 * IDN_SLABALLOC_WAITTIME
 *		Max wait time in ticks that local domains waits for
 *		master to respond to a slab allocation request.  Has
 *		to be at least as long as wait time for a response to
 *		the command.
 */
#define	IDN_SLABALLOC_WAITTIME	((3 * idn_msg_waittime[IDNP_CMD]) / 2)

/*
 * Domain state transition macros.
 */
#ifdef DEBUG
#define	IDN_DSTATE_TRANSITION(dp, ns) \
	{ \
		int		id; \
		hrtime_t	tstamp; \
		tstamp = TIMESTAMP(); \
		ASSERT(RW_WRITE_HELD(&(dp)->drwlock)); \
		id = (dp)->domid; \
		IDN_HISTORY_LOG(IDNH_DSTATE, id, (ns), \
				(uint_t)(dp)->dcpu); \
		PR_STATE("DSTATE:%ld:%d: (l=%d, b/p=%d/%d) " \
			"%s(%d) -> %s(%d)\n", \
			(uint64_t)tstamp, id, \
			__LINE__, \
			((dp)->dcpu == IDN_NIL_DCPU) ? \
				-1 : CPUID_TO_BOARDID((dp)->dcpu), \
			(dp)->dcpu, \
			idnds_str[(dp)->dstate], (dp)->dstate, \
			idnds_str[ns], (ns)); \
		(dp)->dstate = (ns); \
		IDNSB_DOMAIN_UPDATE(dp); \
	}
#else
#define	IDN_DSTATE_TRANSITION(dp, ns) \
	{ \
		IDN_HISTORY_LOG(IDNH_DSTATE, (dp)->domid, \
			(ns), (uint_t)(dp)->dcpu); \
		(dp)->dstate = (ns); \
		IDNSB_DOMAIN_UPDATE(dp); \
	}
#endif /* DEBUG */

#define	IDN_XSTATE_TRANSITION(dp, xs) \
	{ \
		int	_xs = (xs); \
		(dp)->dxstate = _xs; \
		if (_xs != IDNXS_NIL) { \
			ASSERT((dp)->dxp); \
			IDN_DSTATE_TRANSITION((dp), \
				(dp)->dxp->xt_trans[_xs].t_state); \
		} \
	}

/*
 * ---------------------------------------------------------------------
 * IDN Per-Domain Data
 *
 * The comment to the right of the respective field represents
 * what lock protects that field.  If there is no comment then
 * no lock is required to access the field.
 * ---------------------------------------------------------------------
 */

#define	MAXDNAME	32

typedef struct idn_domain {
	krwlock_t	drwlock;
			/*
			 * Assigned domid for domain.  Never
			 * changes once idn_domain[] is
			 * initialized.  We are guaranteed that
			 * all domains in IDN will have a
			 * uniqueue domid in the range (0-15).
			 */
	int		domid;
	idn_dstate_t	dstate;			/* drwlock */
	idn_xstate_t	dxstate;		/* drwlock */
			/*
			 * Gotten from uname -n for local
			 * domain.  Remote domains pass
			 * theirs during Config phase.
			 */
	char		dname[MAXDNAME];	/* drwlock */
			/*
			 * IDN-wide unique identifier for the
			 * given domain.  This value will be
			 * the same as the domid.
			 */
	ushort_t	dnetid;			/* drwlock */
	idn_vote_t	dvote;			/* drwlock */
			/*
			 * Used during FIN sequenece to
			 * determine what type of shutdown
			 * (unlink) we're executing with
			 * respect to the given domain.
			 */
	idn_fin_t	dfin;			/* drwlock */
			/*
			 * A non-zero value for dfin_sync
			 * indicates that unlink of respective
			 * domain does not need to be performed
			 * synchronously among all the IDN
			 * member domains.
			 */
	short		dfin_sync;		/* grwlock */
			/*
			 * Cookie used to determine the
			 * proper context in which we're
			 * receiving messages from the given
			 * domain.  Assigned cookies are exchanged
			 * during initial NEGO messages.
			 */
	ushort_t	dcookie_send;		/* drwlock */
	ushort_t	dcookie_recv;		/* drwlock */
	short		dcookie_err;		/* drwlock */
	int		dcookie_errcnt;		/* drwlock */
			/*
			 * Primary target cpu for sending
			 * messages.  Can change to help
			 * distribute interrupts on receiving
			 * side.
			 */
	int		dcpu;			/* drwlock */
			/*
			 * Used to store dcpu from a previous
			 * life.  Only used when requesting
			 * a RELINK with a domain we were just
			 * previously linked with.  Thus, it
			 * does represent a valid cpu in the
			 * remote domain.
			 */
	int		dcpu_save;		/* drwlock */
			/*
			 * Used to store from which cpu the
			 * last message was received.
			 */
	int		dcpu_last;
			/*
			 * Transition phase area.  This field
			 * points to the proper phase structure
			 * depending on what stage the given
			 * domain is in.
			 */
	idn_xphase_t	*dxp;			/* drwlock */
			/*
			 * Actual synchronization object for
			 * the given domain.
			 */
	idn_syncop_t	dsync;	/* drwlock & idn.sync.sz_mutex */
			/*
			 * Slab information for given domain.
			 * If the local domain is a master,
			 * then this field in each domain is used
			 * to store which slabs have been assigned
			 * to given domain.  If the local domain
			 * is a slave, then this information is
			 * NULL for all remote idn_domain[]
			 * entries, but for local domain holds
			 * those slabs assigned to local domain.
			 */
	smr_slab_t	*dslab;			/* dslab_rwlock */
	short		dnslabs;		/* dslab_rwlock */
	short		dslab_state;		/* dslab_rwlock */
	krwlock_t	dslab_rwlock;
			/*
			 * Set of cpus belonging to domain.
			 */
	cpuset_t	dcpuset;		/* drwlock */

	int		dncpus;			/* drwlock */
			/*
			 * Index into dcpumap to determine
			 * which cpu to target next for
			 * interrupt.  Intended to allow fair
			 * distribution of interrupts on
			 * remote domain.
			 */
	uint_t		dcpuindex;		/* drwlock */
			/*
			 * Quick look-up map of cpus belonging
			 * to domain.  Used to select next target.
			 */
	uchar_t		*dcpumap;		/* drwlock */
			/*
			 * Non-zero indicates outstanding
			 * I/O's to given domain.
			 */
	int		dio;			/* drwlock */
	int		dioerr;			/* drwlock */
			/*
			 * Set when we fail to allocate a buffer
			 * for a domain.  Dictates whether to
			 * reclaim max buffers or not.
			 */
	lock_t		diowanted;
			/*
			 * Set when remote domain does not
			 * seem to be picking up messages sent
			 * to it.  Non-zero indicates we have
			 * an outstanding "ping" to domain.
			 */
	lock_t		diocheck;		/* drwlock */
	short		dslabsize;		/* drwlock */
	uint_t		dmtu;			/* drwlock */

	uint_t		dbufsize;		/* drwlock */
	short		dnwrsize;		/* drwlock */
	lock_t		dreclaim_inprogress;	/* drwlock */
	uchar_t		dreclaim_index;		/* drwlock */
			/*
			 * The following field is primarily
			 * used during CFG exchange to keep
			 * track of certain per-domain information.
			 */
	union {					/* all - drwlock */
		struct {
			uint_t	_dcfgphase	: 6;
			uint_t	_dcfgsnddone	: 1;
			uint_t	_dcfgrcvdone	: 1;
			uint_t	_dcksum		: 2;
			uint_t	_dmaxnets	: 6;
			uint_t	_dmboxpernet	: 9;
			uint_t	_dncfgitems	: 6;
			uint_t	_drecfg		: 1;
			} _s;
		int	_dtmp;
	} _u;
			/*
			 * Each domain entry maintains a
			 * timer queue holding timers for
			 * messages outstanding to that domain.
			 */
	struct idn_timerq {
		int		tq_cookie;	/* tq_mutex */
		kmutex_t	tq_mutex;
		int		tq_count;	/* tq_mutex */
		idn_timer_t	*tq_queue;	/* tq_mutex */
	} dtimerq;
			/*
			 * dawol is used to keep
			 * track of AWOL details for
			 * given domain when it is
			 * non-responsive.
			 */
	struct {
		int		a_count;	/* drwlock */
		clock_t		a_time;		/* drwlock */
		clock_t		a_last;		/* drwlock */
		clock_t		a_msg;		/* drwlock */
	} dawol;

	struct hwconfig	{
		short		dh_nboards;	/* drwlock */
		short		dh_nmcadr;	/* drwlock */
		boardset_t	dh_boardset;	/* drwlock */
		uint_t		dh_mcadr[MAX_BOARDS];	/* drwlock */
	} dhw;
			/*
			 * Mailbox information used to
			 * send/recv messages to given domain.
			 */
	struct {
		kmutex_t		m_mutex;
		struct idn_mboxtbl	*m_tbl;		/* m_mutex */
		struct idn_mainmbox	*m_send;	/* m_mutex */
		struct idn_mainmbox	*m_recv;	/* m_mutex */
	} dmbox;
} idn_domain_t;

typedef struct idn_timerq	idn_timerq_t;

#define	dcfgphase	_u._s._dcfgphase
#define	dcfgsnddone	_u._s._dcfgsnddone
#define	dcfgrcvdone	_u._s._dcfgrcvdone
#define	dcksum		_u._s._dcksum
#define	dmaxnets	_u._s._dmaxnets
#define	dmboxpernet	_u._s._dmboxpernet
#define	dncfgitems	_u._s._dncfgitems
#define	drecfg		_u._s._drecfg
#define	dbindport	_u._dbindport
#define	dconnected	_u._dconnected
#define	dtmp		_u._dtmp

#define	IDN_DLOCK_EXCL(dd)	(rw_enter(&idn_domain[dd].drwlock, RW_WRITER))
#define	IDN_DLOCK_SHARED(dd)	(rw_enter(&idn_domain[dd].drwlock, RW_READER))
#define	IDN_DLOCK_TRY_SHARED(dd) \
				(rw_tryenter(&idn_domain[dd].drwlock, \
						RW_READER))
#define	IDN_DLOCK_DOWNGRADE(dd)	(rw_downgrade(&idn_domain[dd].drwlock))
#define	IDN_DUNLOCK(dd)		(rw_exit(&idn_domain[dd].drwlock))
#define	IDN_DLOCK_IS_EXCL(dd)	(RW_WRITE_HELD(&idn_domain[dd].drwlock))
#define	IDN_DLOCK_IS_SHARED(dd)	(RW_READ_HELD(&idn_domain[dd].drwlock))
#define	IDN_DLOCK_IS_HELD(dd)	(RW_LOCK_HELD(&idn_domain[dd].drwlock))

#define	IDN_MBOX_LOCK(dd)	(mutex_enter(&idn_domain[dd].dmbox.m_mutex))
#define	IDN_MBOX_UNLOCK(dd)	(mutex_exit(&idn_domain[dd].dmbox.m_mutex))

#define	IDN_RESET_COOKIES(dd) \
	(idn_domain[dd].dcookie_send = idn_domain[dd].dcookie_recv = 0)

#define	DSLAB_STATE_UNKNOWN	0
#define	DSLAB_STATE_LOCAL	1
#define	DSLAB_STATE_REMOTE	2

#define	DSLAB_READ_HELD(d)	RW_READ_HELD(&idn_domain[d].dslab_rwlock)
#define	DSLAB_WRITE_HELD(d)	RW_WRITE_HELD(&idn_domain[d].dslab_rwlock)

#define	DSLAB_LOCK_EXCL(d) \
		rw_enter(&idn_domain[d].dslab_rwlock, RW_WRITER)
#define	DSLAB_LOCK_SHARED(d) \
		rw_enter(&idn_domain[d].dslab_rwlock, RW_READER)
#define	DSLAB_LOCK_TRYUPGRADE(d) \
		rw_tryupgrade(&idn_domain[d].dslab_rwlock)
#define	DSLAB_UNLOCK(d)		rw_exit(&idn_domain[d].dslab_rwlock)

/*
 * ---------------------------------------------------------------------
 * Macro to pick another target for the given domain.  This hopefully
 * improves performance by better distributing the SSI responsibilities
 * at the target domain.
 * ---------------------------------------------------------------------
 */
#define	BUMP_INDEX(set, index) \
	{ \
		register int	p; \
		for (p = (index)+1; p < NCPU; p++) \
			if (CPU_IN_SET((set), p)) \
				break; \
		if (p >= NCPU) \
			for (p = 0; p <= (index); p++) \
				if (CPU_IN_SET((set), p)) \
					break; \
		if (!CPU_IN_SET((set), p)) { \
			uint_t	_u32, _l32; \
			_u32 = UPPER32_CPUMASK(set); \
			_l32 = LOWER32_CPUMASK(set); \
			cmn_err(CE_PANIC, \
				"IDN: cpu %d not in cpuset 0x%x.%0x\n", \
				p, _u32, _l32); \
		} \
		(index) = p; \
	}

#define	IDN_ASSIGN_DCPU(dp, cookie) \
		((dp)->dcpu = (int)((dp)->dcpumap[(cookie) & (NCPU-1)]))

/*
 * ---------------------------------------------------------------------
 * Atomic increment/decrement, swap, compare-swap functions.
 * ---------------------------------------------------------------------
 */
#define	ATOMIC_INC(v)		atomic_inc_32((uint_t *)&(v))
#define	ATOMIC_DEC(v)		atomic_dec_32((uint_t *)&(v))
#define	ATOMIC_SUB(v, n)	atomic_add_32((uint_t *)&(v), -(n))
#define	ATOMIC_CAS(a, c, n)	atomic_cas_32((uint32_t *)(a), (uint32_t)(c), \
								(uint32_t)(n))
#define	ATOMIC_SWAPL(a, v)	atomic_swap_32((uint32_t *)(a), (uint32_t)(v))

/*
 * DMV vector interrupt support.
 *
 * A fixed-size circular buffer is maintained as a queue of
 * incoming interrupts.  The low-level idn_dmv_handler() waits
 * for an entry to become FREE and will atomically mark it INUSE.
 * Once it has filled in the appropriate fields it will be marked
 * as READY.  The high-level idn_handler() will be invoked and will
 * process all messages in the queue that are READY.  Each message
 * is marked PROCESS, a protojob job created and filled in, and
 * then the interrupt message is marked FREE for use in the next
 * interrupt.  The iv_state field is used to hold the relevant
 * state and is updated atomically.
 */
#define	IDN_PIL			PIL_8
#define	IDN_DMV_PENDING_MAX	128	/* per cpu */

#endif /* !_ASM */

#ifndef _ASM

/*
 * The size of this structure must be a power of 2
 * so that we can do a simple shift to calculate
 * our offset into based on cpuid.
 */
typedef struct idn_dmv_cpu {
	uint32_t	idn_dmv_current;
	int32_t		idn_dmv_lostintr;
	lock_t		idn_dmv_active;
	char		_padding[(2 * sizeof (uint64_t)) - \
				sizeof (uint32_t) - \
				sizeof (lock_t) - \
				sizeof (int32_t)];
} idn_dmv_cpu_t;

typedef struct idn_dmv_data {
	uint64_t	idn_soft_inum;
	uint64_t	idn_dmv_qbase;
	idn_dmv_cpu_t	idn_dmv_cpu[NCPU];
} idn_dmv_data_t;

/*
 * Requirements of the following data structure:
 *	- MUST be double-word (8 bytes) aligned.
 *	- _iv_head field MUST start on double-word boundary.
 *	- iv_xargs0 MUST start on double-word boundary
 *	  with iv_xargs1 immediately following.
 *	- iv_xargs2 MUST start on double-word boundary
 *	  with iv_xargs3 immediately following.
 */
typedef struct idn_dmv_msg {
	uint32_t	iv_next;	/* offset */
	uchar_t		iv_inuse;
	uchar_t		iv_ready;
	ushort_t	_padding;
	uint32_t	iv_head	  : 16;
	uint32_t	iv_cookie : 16;
	uint32_t	iv_ver    : 8;
	uint32_t	iv_mtype  : 6;
	uint32_t	iv_atype  : 6;
	uint32_t	iv_domid  : 4;
	uint32_t	iv_cpuid  : 8;
	uint32_t	iv_xargs0;
	uint32_t	iv_xargs1;
	uint32_t	iv_xargs2;
	uint32_t	iv_xargs3;
} idn_dmv_msg_t;

extern uint_t	idn_dmv_inum;
extern uint_t	idn_soft_inum;

/*
 * An IDN-network address has the following format:
 *
 *	31......16,15........0
 *	| channel |  dnetid  |
 *	----------------------
 * channel	- network interface.
 * netid	- idn_domain[].dnetid
 */
#define	IDN_MAXMAX_NETS		32
#define	IDN_BROADCAST_ALLCHAN	((ushort_t)-1)
#define	IDN_BROADCAST_ALLNETID	((ushort_t)-1)

typedef union {
	struct {
		ushort_t	chan;
		ushort_t	netid;
	} net;
	uint_t	netaddr;
} idn_netaddr_t;

#define	CHANSET_ALL	(~((idn_chanset_t)0))
#define	CHANSET(c) \
		((idn_chanset_t)1 << ((c) & 31))
#define	CHAN_IN_SET(m, c) \
		(((m) & ((idn_chanset_t)1 << ((c) & 31))) != 0)
#define	CHANSET_ADD(m, c) \
		((m) |= ((idn_chanset_t)1 << ((c) & 31)))
#define	CHANSET_DEL(m, c) \
		((m) &= ~((idn_chanset_t)1 << ((c) & 31)))
#define	CHANSET_ZERO(m)	((m) = 0)

typedef enum {
/*  0 */	IDNCHAN_OPEN,
/*  1 */	IDNCHAN_SOFT_CLOSE,
/*  2 */	IDNCHAN_HARD_CLOSE,
/*  3 */	IDNCHAN_OFFLINE,
/*  4 */	IDNCHAN_ONLINE
} idn_chanop_t;

/*
 * Retry support.
 */
#define	IDN_RETRY_TOKEN(d, x)		((((d) & 0xf) << 16) | \
					(0xffff & (uint_t)(x)))
#define	IDN_RETRY_TOKEN2DOMID(t)	((int)(((t) >> 16) & 0xf))
#define	IDN_RETRY_TOKEN2TYPE(t)		((idn_retry_t)((t) & 0xffff))
#define	IDN_RETRY_TYPEALL		((idn_retry_t)0xffff)
#define	IDN_RETRY_INTERVAL		hz	/* 1 sec */
#define	IDN_RETRY_RECFG_MULTIPLE	10

#define	IDN_RETRYINTERVAL_NEGO		(2 * hz)
#define	IDN_RETRYINTERVAL_CON		(2 * hz)
#define	IDN_RETRYINTERVAL_FIN		(2 * hz)

typedef struct idn_retry_job {
	struct idn_retry_job	*rj_prev;
	struct idn_retry_job	*rj_next;
	void			(*rj_func)(uint_t token, void *arg);
	void			*rj_arg;
	uint_t			rj_token;
	short			rj_onq;
	timeout_id_t		rj_id;
} idn_retry_job_t;

#define	IDNRETRY_ALLOCJOB() \
	((idn_retry_job_t *)kmem_cache_alloc(idn.retryqueue.rq_cache, KM_SLEEP))
#define	IDNRETRY_FREEJOB(j) \
	(kmem_cache_free(idn.retryqueue.rq_cache, (void *)(j)))

typedef enum {
/*  0 */	IDNRETRY_NIL = 0,
/*  1 */	IDNRETRY_NEGO,
/*  2 */	IDNRETRY_CON,
/*  3 */	IDNRETRY_CONQ,		/* for CON queries */
/*  4 */	IDNRETRY_FIN,
/*  5 */	IDNRETRY_FINQ,		/* for FIN queries */
/*  6 */	IDN_NUM_RETRYTYPES
} idn_retry_t;

/*
 * ---------------------------------------------------------------------
 */
typedef struct {
	int		m_domid;
	int		m_cpuid;
	ushort_t	m_msgtype;
	ushort_t	m_acktype;
	ushort_t	m_cookie;
	idn_xdcargs_t	m_xargs;
} idn_protomsg_t;

typedef struct idn_protojob {
	struct idn_protojob	*j_next;
	int			j_cache;
	idn_protomsg_t		j_msg;
} idn_protojob_t;

typedef struct idn_protoqueue {
	struct idn_protoqueue	*q_next;
	idn_protojob_t		*q_joblist;
	idn_protojob_t		*q_joblist_tail;
	int			q_die;
	int			q_id;
	ksema_t			*q_morgue;
	kthread_id_t		q_threadp;
	kcondvar_t		q_cv;
	kmutex_t		q_mutex;
} idn_protoqueue_t;

#define	IDN_PROTOCOL_NSERVERS		4
#define	IDN_PROTOCOL_SERVER_HASH(d)	((d) % idn.nservers)
#define	IDN_PROTOJOB_CHUNKS		(idn.nservers)

/*
 * ---------------------------------------------------------------------
 * Data Server definitions.
 *
 *	idn_datasvr_t 	- Describes data server thread.
 *	. ds_id			- Per-domain identifier for data server.
 *	. ds_domid		- Domain which data server is handling.
 *	. ds_state		- Flag to enable/disable/terminate
 *				  data server.
 *	. ds_mboxp		- Pointer to data server's (local)
 *				  mailbox to be serviced.
 *	. ds_waittime		- cv_timedwait sleep time before
 *				  checking respective mailbox.
 *	. ds_threadp		- Pointer to data server thread.
 *	. ds_cv			- Condvar for sleeping.
 *	. ds_morguep		- Semaphore for terminating thread.
 *
 *	idn_mboxhdr_t	- Resides in SMR space (MUST be cache_linesize).
 *	. mh_svr_active		- Non-zero indicates data server is
 *				  actively reading mailbox for messages.
 *	. mh_svr_ready		- Non-zero indicates data server has
 *				  allocated and is ready to accept data.
 *	. mh_cookie		- Identifier primarily for debug purposes.
 *
 *	idn_mboxmsg_t	- Entry in the SMR space circular queue use to
 *			  represent a data packet.
 *	. mm_owner		- Non-zero indicates entry is available
 *				  to be processed by receiver's data server.
 *	. mm_flag		- Indicates whether entry needs to be
 *				  reclaimed by the sender.  Also holds error
 *				  indications (e.g. bad offset).
 *	. mm_offset		- SMR offset of respective data packet.
 *
 *	idn_mboxtbl_t	- Encapsulation of a per-domain mailbox (SMR space).
 *	. mt_header		- Header information for synchronization.
 *	. mt_queue		- Circular queue of idn_mboxmsg_t entries.
 *
 *	idn_mainmbox_t	- Encapsulation of main SMR recv/send mailboxes.
 *	. mm_mutex		- Protects mm_* entries, enqueuing, and
 *				  dequeuing of messages.  Also protects
 *				  updates to the route table pointed to
 *				  by mm_routetbl.
 *	. mm_count		- send: Current number of messages
 *					enqueued.
 *				- recv: Cumulative number of messages
 *					processed.
 *	. mm_max_count		- send: Maximum number of messages
 *					enqueued per iteration.
 *				  recv: Maximum number of messages
 *					dequeued per iteration.
 *	. mm_smr_mboxp		- Pointer to SMR (vaddr) space where
 *				  respective mailbox resides.
 * ---------------------------------------------------------------------
 */
#define	IDN_MBOXHDR_COOKIE_TOP		((uint_t)0xc0c0)
#define	IDN_MAKE_MBOXHDR_COOKIE(pd, sd, ch) \
				((IDN_MBOXHDR_COOKIE_TOP << 16) \
				| (((uint_t)(pd) & 0xf) << 12) \
				| (((uint_t)(sd) & 0xf) << 8) \
				| ((uint_t)(ch) & 0xf))
#define	IDN_GET_MBOXHDR_COOKIE(mhp) \
				((mhp)->mh_cookie & ~0xff00)
#define	VALID_MBOXHDR(mhp, ch, cksum) \
	((IDN_GET_MBOXHDR_COOKIE(mhp) == \
			IDN_MAKE_MBOXHDR_COOKIE(0, 0, (ch))) && \
	((cksum) == (*(mhp)).mh_cksum))
/*
 * The number of entries in a mailbox queue must be chosen so
 * that (IDN_MMBOX_NUMENTRIES * sizeof (idn_mboxmsg_t)) is a multiple
 * of a cacheline size (64).
 */
#define	IDN_MMBOX_NUMENTRIES		IDN_MBOX_PER_NET
/*
 * We step through the mailboxes in effectively cacheline size
 * incremenents so that the source and receiving cpus are not competing
 * for the same cacheline when transmitting/receiving messages into/from
 * the mailboxes.  The hard requirement is that the step value be even
 * since the mailbox size will be chosen odd.  This allows us to wraparound
 * the mailbox uniquely touching each entry until we've exhausted them
 * all at which point we'll end up where we initially started and repeat
 * again.
 */
#define	IDN_MMBOXINDEX_STEP	(((64 / sizeof (idn_mboxmsg_t)) + 1) & 0xfffe)
#define	IDN_MMBOXINDEX_INC(i) \
	{ \
		if (((i) += IDN_MMBOXINDEX_STEP) >= IDN_MMBOX_NUMENTRIES) \
			(i) -= IDN_MMBOX_NUMENTRIES; \
	}

#define	IDN_MMBOXINDEX_DIFF(i, j) \
	(((i) >= (j)) ? (((i) - (j)) / IDN_MMBOXINDEX_STEP) \
		: ((((i) + IDN_MMBOX_NUMENTRIES) - (j)) / IDN_MMBOXINDEX_STEP))

/*
 * Require IDN_MBOXAREA_SIZE <= IDN_SLAB_SIZE so we don't waste
 * slab space.
 *
 * Each domain maintains a MAX_DOMAIN(16) entry mbox_table.  Each
 * entry represents a receive mailbox for a possible domain to which
 * the given domain may have a connection.  The send mailbox for each
 * respective domain is given to the local domain at the time of
 * connection establishment.
 */

/*
 * ---------------------------------------------------------------------
 */
#define	IDN_MBOXTBL_SIZE \
	(IDNROUNDUP(((IDN_MBOX_PER_NET * sizeof (idn_mboxmsg_t)) \
			+ sizeof (idn_mboxhdr_t)), IDN_ALIGNSIZE))

/*
 * ---------------------------------------------------------------------
 * Each domain has idn_max_nets worth of possible mailbox tables
 * for each domain to which it might possibly be connected.
 * ---------------------------------------------------------------------
 */
#define	IDN_MBOXAREA_SIZE \
	(IDN_MBOXTBL_SIZE * IDN_MAX_NETS * MAX_DOMAINS * MAX_DOMAINS)
#define	IDN_MBOXAREA_OFFSET(d) \
	((d) * IDN_MBOXTBL_SIZE * IDN_MAX_NETS * MAX_DOMAINS)

/*
 * ---------------------------------------------------------------------
 * Return the base of the mailbox area (set of tables) assigned
 * to the given domain id.
 * ---------------------------------------------------------------------
 */
#define	IDN_MBOXAREA_BASE(m, d) \
	((idn_mboxtbl_t *)(((ulong_t)(m)) + IDN_MBOXAREA_OFFSET(d)))

/*
 * ---------------------------------------------------------------------
 * Return the pointer to the respective receive mailbox (table set)
 * for the given domain id relative to the given base mailbox table.
 * ---------------------------------------------------------------------
 */
#define	IDN_MBOXTBL_PTR(t, d)	\
	((idn_mboxtbl_t *)(((ulong_t)(t)) + ((d) * IDN_MBOXTBL_SIZE \
				* IDN_MAX_NETS)))
/*
 * ---------------------------------------------------------------------
 * Return the pointer to the actual target mailbox based on the
 * given channel in the given mailbox table.
 * ---------------------------------------------------------------------
 */
#define	IDN_MBOXTBL_PTR_CHAN(t, c) \
	((idn_mboxtbl_t *)(((ulong_t)(t)) + ((c) * IDN_MBOXTBL_SIZE)))

#define	IDN_MBOXTBL_PTR_INC(t)	\
	((t) = (idn_mboxtbl_t *)(((ulong_t)(t)) + IDN_MBOXTBL_SIZE))

#define	IDN_MBOXCHAN_INC(i) \
	{ \
		if (++(i) == IDN_MAX_NETS) \
			(i) = 0; \
	}

/*
 * ---------------------------------------------------------------------
 * Return the absolute location within the entire mailbox area
 * of the mboxtbl for the given primary and secondary domain and
 * channel.  Only relevant when done by the master.
 * ---------------------------------------------------------------------
 */
#define	IDN_MBOXTBL_ABS_PTR(mt, pd, sd, ch) \
		(IDN_MBOXTBL_PTR_CHAN( \
			IDN_MBOXTBL_PTR( \
				IDN_MBOXAREA_BASE((mt), (pd)), \
				(sd)), \
			(ch)))

#define	IDN_BFRAME_SHIFT	idn.bframe_shift
#define	IDN_BFRAME2OFFSET(bf)	((bf) << IDN_BFRAME_SHIFT)
#define	IDN_BFRAME2ADDR(bf)	IDN_OFFSET2ADDR(IDN_BFRAME2OFFSET(bf))
#define	IDN_OFFSET2BFRAME(off)	(((off) >> IDN_BFRAME_SHIFT) & 0xffffff)
#define	IDN_ADDR2BFRAME(addr)	IDN_OFFSET2BFRAME(IDN_ADDR2OFFSET(addr))

typedef struct idn_mboxmsg {
	uint_t		ms_owner  : 1,
			ms_flag   : 7,
			ms_bframe : 24;
} idn_mboxmsg_t;

typedef idn_mboxmsg_t	idn_mboxq_t[1];

#define	IDN_CKSUM_MBOX_COUNT	(offsetof(idn_mboxhdr_t, mh_svr_ready) / 2)

#define	IDN_CKSUM_MBOX(h)	\
			(IDN_CHECKSUM ? \
			idn_cksum((ushort_t *)(h), IDN_CKSUM_MBOX_COUNT) : 0)

typedef struct idn_mboxhdr {
	uint_t		mh_cookie;
	uint_t		mh_svr_ready_ptr;
	uint_t		mh_svr_active_ptr;
	ushort_t	mh_svr_ready;
	ushort_t	mh_svr_active;

	uint_t		_padding[(64 -
				(4*sizeof (uint_t)) -
				(2*sizeof (ushort_t))) / sizeof (uint_t)];

	uint_t		mh_cksum;
} idn_mboxhdr_t;

typedef struct idn_mboxtbl {
	idn_mboxhdr_t	mt_header;
	idn_mboxq_t	mt_queue;
} idn_mboxtbl_t;

#define	IDN_CHAN_DOMAIN_REGISTER(csp, dom) \
	(DOMAINSET_ADD((csp)->ch_reg_domset, (dom)))

#define	IDN_CHAN_DOMAIN_UNREGISTER(csp, dom) \
	(DOMAINSET_DEL((csp)->ch_reg_domset, (dom)))

#define	IDN_CHAN_DOMAIN_IS_REGISTERED(csp, dom) \
	(DOMAIN_IN_SET((csp)->ch_reg_domset, (dom)))

#define	IDN_CHANSVR_SCANSET_ADD_PENDING(csp, dom) \
	{ \
		register int _d; \
		register uint64_t _domset; \
		(dom) &= MAX_DOMAINS - 1;   	/* Assumes power of 2 */ \
		_domset = 0ull; \
		for (_d = 0; _d < (csp)->ch_recv_domcount; _d++) { \
			if ((int)(((csp)->ch_recv_scanset_pending >> \
						(_d * 4)) & 0xf) == (dom)) \
				break; \
			else \
				_domset = (_domset << 4) | 0xfull; \
		} \
		if (_d == (csp)->ch_recv_domcount) { \
			_domset &= (csp)->ch_recv_scanset_pending; \
			_domset |= (uint64_t)(dom) << \
					((csp)->ch_recv_domcount * 4); \
			(csp)->ch_recv_domcount++; \
			(csp)->ch_recv_scanset_pending = 0ull; \
			for (_d = 0; _d < 16; \
					_d += (csp)->ch_recv_domcount) { \
				(csp)->ch_recv_scanset_pending |= _domset; \
				_domset <<= (csp)->ch_recv_domcount * 4; \
			} \
		} \
	}
#define	IDN_CHANSVR_SCANSET_DEL_PENDING(csp, dom) \
	{ \
		register int _d; \
		register uint64_t _domset; \
		(dom) &= MAX_DOMAINS - 1;	/* Assumes power of 2 */ \
		_domset = 0ull; \
		for (_d = 0; _d < (csp)->ch_recv_domcount; _d++) { \
			if ((int)(((csp)->ch_recv_scanset_pending >> \
						(_d * 4)) & 0xf) == (dom)) \
				break; \
			else \
				_domset = (_domset << 4) | 0xfull; \
		} \
		if (_d < (csp)->ch_recv_domcount) { \
			_domset &= (csp)->ch_recv_scanset_pending; \
			(csp)->ch_recv_scanset_pending >>= 4; \
			(csp)->ch_recv_domcount--; \
			for (; _d < (csp)->ch_recv_domcount; _d++) \
				_domset |= (csp)->ch_recv_scanset_pending &\
						(0xfull << (_d * 4)); \
			(csp)->ch_recv_scanset_pending = 0ull; \
			if ((csp)->ch_recv_domcount) { \
				for (_d = 0; _d < 16; \
					_d += (csp)->ch_recv_domcount) { \
					(csp)->ch_recv_scanset_pending |= \
						_domset; \
					_domset <<= \
						(csp)->ch_recv_domcount * 4; \
				} \
			} \
		} \
	}

#define	IDN_CHAN_TRYLOCK_GLOBAL(csp)	\
		mutex_tryenter(&(csp)->ch_mutex)
#define	IDN_CHAN_LOCK_GLOBAL(csp)	\
		mutex_enter(&(csp)->ch_mutex)
#define	IDN_CHAN_UNLOCK_GLOBAL(csp)	\
		mutex_exit(&(csp)->ch_mutex)
#define	IDN_CHAN_GLOBAL_IS_LOCKED(csp)	\
		(MUTEX_HELD(&(csp)->ch_mutex))

#define	IDN_CHAN_LOCAL_IS_LOCKED(csp)	\
		(MUTEX_HELD(&(csp)->ch_send.c_mutex) && \
		MUTEX_HELD(&(csp)->ch_recv.c_mutex))
#define	IDN_CHAN_LOCK_LOCAL(csp)	\
		(mutex_enter(&(csp)->ch_recv.c_mutex, \
		mutex_enter(&(csp)->ch_send.c_mutex))
#define	IDN_CHAN_UNLOCK_LOCAL(csp) 	\
		(mutex_exit(&(csp)->ch_send.c_mutex), \
		mutex_exit(&(csp)->ch_recv.c_mutex))

#define	IDN_CHAN_RECV_IS_LOCKED(csp)	\
		(MUTEX_HELD(&(csp)->ch_recv.c_mutex))
#define	IDN_CHAN_TRYLOCK_RECV(csp) 	\
		(mutex_tryenter(&(csp)->ch_recv.c_mutex))
#define	IDN_CHAN_LOCK_RECV(csp) 	\
		(mutex_enter(&(csp)->ch_recv.c_mutex))
#define	IDN_CHAN_UNLOCK_RECV(csp) 	\
		(mutex_exit(&(csp)->ch_recv.c_mutex))

#define	IDN_CHAN_SEND_IS_LOCKED(csp)	\
		(MUTEX_HELD(&(csp)->ch_send.c_mutex))
#define	IDN_CHAN_TRYLOCK_SEND(csp) 	\
		(mutex_tryenter(&(csp)->ch_send.c_mutex))
#define	IDN_CHAN_LOCK_SEND(csp) 	\
		(mutex_enter(&(csp)->ch_send.c_mutex))
#define	IDN_CHAN_UNLOCK_SEND(csp) 	\
		(mutex_exit(&(csp)->ch_send.c_mutex))

/*
 * A channel table is an array of pointers to mailboxes
 * for the respective domains for the given channel.
 * Used a cache for the frequently used items.  Respective
 * fields in mainmbox are updated just prior to sleeping.
 */

/*
 * Reading c_state requires either c_mutex or ch_mutex.
 * Writing c_state requires both c_mutex and ch_mutex in the order:
 *	ch_mutex
 *	c_mutex
 */
typedef struct idn_chaninfo {
	kmutex_t	c_mutex;
	uchar_t		c_state;	/* protected by c_mutex */
	uchar_t		c_checkin;	/* asynchronous flag */
	kcondvar_t	c_cv;
	ushort_t	c_waiters;	/* protected by c_mutex */
	ushort_t	c_inprogress;	/* protected by c_mutex */
} idn_chaninfo_t;

/*
 * Reading/Writing ch_state requires ch_mutex.
 * When updating both recv and send c_state's for the locks
 * must be grabbed in the following order:
 *	ch_mutex
 *	ch_recv.c_mutex
 *	ch_send.c_mutex
 * This order is necessary to prevent deadlocks.
 * In general ch_state is intended to represent c_state of
 * individual send/recv sides.  During state transitions the
 * ch_state and c_state values may be slightly different,
 * but eventually should end up identical.
 */
typedef struct idn_chansvr {
	uchar_t		ch_id;
	uchar_t		ch_state;	/* protected by ch_mutex */
	lock_t		ch_initlck;
	lock_t		ch_actvlck;
	domainset_t	ch_reg_domset;
	kmutex_t	ch_mutex;

	idn_chaninfo_t	ch_send;
	int		_padding2[(64 -
				(2*sizeof (uchar_t)) - (2*sizeof (lock_t)) -
				sizeof (uint_t) - sizeof (kmutex_t) -
				sizeof (idn_chaninfo_t)) / sizeof (int)];

	idn_chaninfo_t	ch_recv;

	uint64_t	ch_recv_scanset;
	uint64_t	ch_recv_scanset_pending;

	domainset_t	ch_recv_domset;
	domainset_t	ch_recv_domset_pending;
	short		ch_recv_domcount;
	kcondvar_t	ch_recv_cv;
	int		ch_recv_waittime;
	int		ch_recv_changed;

	kthread_id_t	ch_recv_threadp;
	ksema_t		*ch_recv_morguep;
	int		ch_bound_cpuid;
	int		ch_bound_cpuid_pending;
} idn_chansvr_t;

typedef struct idn_mainmbox {
	kmutex_t	mm_mutex;
	short		mm_channel;
	short		mm_domid;
	ushort_t	mm_flags;
	short		mm_type;

	idn_chansvr_t	*mm_csp;	/* non-NULL indicates reg'd */
	int		mm_count;
	int		mm_dropped;
	idn_mboxtbl_t	*mm_smr_mboxp;		/* SMR vaddr */

	ushort_t	*mm_smr_activep;	/* SMR pointer */
	ushort_t	*mm_smr_readyp;		/* SMR pointer */
	int		mm_qiget;	/* next msg to get */
	int		mm_qiput;	/* next slot to put msg */
} idn_mainmbox_t;

/*
 * mm_flags
 */
#define	IDNMMBOX_FLAG_CORRUPTED		0x01
/*
 * mm_type
 */
#define	IDNMMBOX_TYPE_RECV		0x1
#define	IDNMMBOX_TYPE_SEND		0x2

#define	IDNMBOX_IS_RECV(m)	((m) == IDNMMBOX_TYPE_RECV)
#define	IDNMBOX_IS_SEND(m)	((m) == IDNMMBOX_TYPE_SEND)

/*
 * Period between sending wakeup xdc's to remote domain.
 */
#define	IDN_CHANNEL_WAKEUP_PERIOD	(hz >> 1)
/*
 * ms_flag bit values.
 */
#define	IDN_MBOXMSG_FLAG_RECLAIM	0x1	/* needs to be reclaimed */
#define	IDN_MBOXMSG_FLAG_INPROCESS	0x2
#define	IDN_MBOXMSG_FLAG_ERR_BADOFFSET	0x4
#define	IDN_MBOXMSG_FLAG_ERR_NOMBOX	0x8
#define	IDN_MBOXMSG_FLAG_ERRMASK	0xc
/*
 * ch_state/c_state bit values.
 */
#define	IDN_CHANSVC_STATE_ATTACHED	0x01
#define	IDN_CHANSVC_STATE_ENABLED	0x02
#define	IDN_CHANSVC_STATE_ACTIVE	0x04
#define	IDN_CHANSVC_STATE_FLUSH		0x10
#define	IDN_CHANSVC_STATE_CORRUPTED	0x20
#define	IDN_CHANSVC_STATE_MASK		0x07	/* ATTACHED/ENABLED/ACTIVE */

#define	IDN_CHANSVC_PENDING_BITS	(IDN_CHANSVC_STATE_ATTACHED | \
					IDN_CHANSVC_STATE_ENABLED)

/*
 * GLOBAL
 */
#define	IDN_CHANNEL_IS_ATTACHED(csp)	\
		((csp)->ch_state & IDN_CHANSVC_STATE_ATTACHED)
#define	IDN_CHANNEL_IS_DETACHED(csp)	\
		(!IDN_CHANNEL_IS_ATTACHED(csp))
#define	IDN_CHANNEL_IS_PENDING(csp)	\
		(((csp)->ch_state & IDN_CHANSVC_STATE_MASK) == \
			IDN_CHANSVC_PENDING_BITS)
#define	IDN_CHANNEL_IS_ACTIVE(csp)	\
		((csp)->ch_state & IDN_CHANSVC_STATE_ACTIVE)
#define	IDN_CHANNEL_IS_ENABLED(csp)	\
		((csp)->ch_state & IDN_CHANSVC_STATE_ENABLED)
/*
 * SEND
 */
#define	IDN_CHANNEL_IS_SEND_ACTIVE(csp)	\
		((csp)->ch_send.c_state & IDN_CHANSVC_STATE_ACTIVE)
/*
 * RECV
 */
#define	IDN_CHANNEL_IS_RECV_ACTIVE(csp)	\
		((csp)->ch_recv.c_state & IDN_CHANSVC_STATE_ACTIVE)
#define	IDN_CHANNEL_IS_RECV_CORRUPTED(csp) \
		((csp)->ch_recv.c_state & IDN_CHANSVC_STATE_CORRUPTED)


#define	IDN_CHAN_SEND_INPROGRESS(csp)	((csp)->ch_send.c_inprogress++)
#define	IDN_CHAN_SEND_DONE(csp) \
	{ \
		ASSERT((csp)->ch_send.c_inprogress > 0); \
		if ((--((csp)->ch_send.c_inprogress) == 0) && \
					((csp)->ch_send.c_waiters != 0)) \
			cv_broadcast(&(csp)->ch_send.c_cv); \
	}
#define	IDN_CHAN_RECV_INPROGRESS(csp)	((csp)->ch_recv.c_inprogress++)
#define	IDN_CHAN_RECV_DONE(csp) \
	{ \
		ASSERT((csp)->ch_recv.c_inprogress > 0); \
		if ((--((csp)->ch_recv.c_inprogress) == 0) && \
					((csp)->ch_recv.c_waiters != 0)) \
			cv_broadcast(&(csp)->ch_recv.c_cv); \
	}

#define	IDN_CHANSVC_MARK_ATTACHED(csp)	\
		((csp)->ch_state = IDN_CHANSVC_STATE_ATTACHED)
#define	IDN_CHANSVC_MARK_DETACHED(csp)	\
		((csp)->ch_state = 0)
#define	IDN_CHANSVC_MARK_PENDING(csp)	\
		((csp)->ch_state |= IDN_CHANSVC_STATE_ENABLED)
#define	IDN_CHANSVC_MARK_DISABLED(csp)	\
		((csp)->ch_state &= ~IDN_CHANSVC_STATE_ENABLED)
#define	IDN_CHANSVC_MARK_ACTIVE(csp)	\
		((csp)->ch_state |= IDN_CHANSVC_STATE_ACTIVE)
#define	IDN_CHANSVC_MARK_IDLE(csp)	\
		((csp)->ch_state &= ~IDN_CHANSVC_STATE_ACTIVE)

#define	IDN_CHANSVC_MARK_RECV_ACTIVE(csp)	\
		((csp)->ch_recv.c_state |= IDN_CHANSVC_STATE_ACTIVE)
#define	IDN_CHANSVC_MARK_RECV_CORRUPTED(csp)	\
		((csp)->ch_recv.c_state |= IDN_CHANSVC_STATE_CORRUPTED)
#define	IDN_CHANSVC_MARK_SEND_ACTIVE(csp)	\
		((csp)->ch_send.c_state |= IDN_CHANSVC_STATE_ACTIVE)

typedef enum {
	IDNCHAN_ACTION_DETACH,		/* DETACH (ATTACHED = 0) */
	IDNCHAN_ACTION_STOP,		/* DISABLE (ENABLED = 0) */
	IDNCHAN_ACTION_SUSPEND,		/* IDLE (ACTIVE = 0) */
	IDNCHAN_ACTION_RESUME,
	IDNCHAN_ACTION_RESTART,
	IDNCHAN_ACTION_ATTACH
} idn_chanaction_t;

#define	IDN_CHANNEL_SUSPEND(c, w)	\
		(idn_chan_action((c), IDNCHAN_ACTION_SUSPEND, (w)))
#define	IDN_CHANNEL_RESUME(c)		\
		(idn_chan_action((c), IDNCHAN_ACTION_RESUME, 0))
#define	IDN_CHANNEL_STOP(c, w)	\
		(idn_chan_action((c), IDNCHAN_ACTION_STOP, (w)))
#define	IDN_CHANNEL_RESTART(c)		\
		(idn_chan_action((c), IDNCHAN_ACTION_RESTART, 0))
#define	IDN_CHANNEL_DETACH(c, w)	\
		(idn_chan_action((c), IDNCHAN_ACTION_DETACH, (w)))
#define	IDN_CHANNEL_ATTACH(c)		\
		(idn_chan_action((c), IDNCHAN_ACTION_ATTACH, 0))

/*
 * ds_waittime range values.
 * When a packet arrives the waittime starts at MIN and gradually
 * shifts up to MAX until another packet arrives.  If still no
 * packet arrives then we go to a hard sleep
 */
#define	IDN_NETSVR_SPIN_COUNT		idn_netsvr_spin_count
#define	IDN_NETSVR_WAIT_MIN		idn_netsvr_wait_min
#define	IDN_NETSVR_WAIT_MAX		idn_netsvr_wait_max
#define	IDN_NETSVR_WAIT_SHIFT		idn_netsvr_wait_shift

/*
 * ---------------------------------------------------------------------
 * IDN Global Data
 *
 * The comment to the right of the respective field represents
 * what lock protects that field.  If there is no comment then
 * no lock is required to access the field.
 * ---------------------------------------------------------------------
 */
typedef struct idn_global {				/* protected by... */
	krwlock_t	grwlock;
			/*
			 * Global state of IDN w.r.t.
			 * the local domain.
			 */
	idn_gstate_t	state;			/* grwlock */
			/*
			 * Version of the IDN driver.
			 * Is passed in DMV header so that
			 * other domains can validate they
			 * support protocol used by local
			 * domain.
			 */
	int		version;
			/*
			 * Set to 1 if SMR region properly
			 * allocated and available.
			 */
	int		enabled;
			/*
			 * Local domains "domain id".
			 */
	int		localid;
			/*
			 * Domain id of the Master domain.
			 * Set to IDN_NIL_DOMID if none
			 * currently exists.
			 */
	int		masterid;		/* grwlock */
			/*
			 * Primarily used during Reconfiguration
			 * to track the expected new Master.
			 * Once the current IDN is dismantled
			 * the local domain will attempt to
			 * connect to this new domain.
			 */
	int		new_masterid;		/* grwlock */
			/*
			 * Number of protocol servers configured.
			 */
	int		nservers;

	dev_info_t	*dip;

	struct {
		/*
		 * dmv_inum
		 *	Interrupt number assigned by
		 *	DMV subsystem to IDN's DMV
		 *	handler.
		 * soft_inum
		 *	Soft interrupt number assigned
		 *	by OS (add_softintr) for Soft
		 *	interrupt dispatched by DMV
		 *	handler.
		 */
		uint_t	dmv_inum;
		uint64_t soft_inum;
		caddr_t	dmv_data;
		size_t	dmv_data_len;
	} intr;
			/*
			 * first_swlink
			 *	Used as synchronization to
			 *	know whether channels need
			 *	to be activated or not.
			 * first_hwlink
			 *	Used as mechanism to determine
			 *	whether local domain needs
			 *	to publicize its SMR, assuming
			 *	it is the Master.
			 * first_hwmaster
			 *	Domainid of the domain that
			 *	was the master at the time
			 * 	the hardware was programmed.
			 *	We need to keep this so that
			 *	we deprogram with respect to
			 *	the correct domain that the
			 *	hardware was originally
			 *	programmed to.
			 */
	lock_t		first_swlink;
	lock_t		first_hwlink;
	short		first_hwmasterid;
			/*
			 * The xmit* fields are used to set-up a background
			 * thread to monitor when a channel is ready to be
			 * enabled again.  This is necessary since IDN
			 * can't rely on hardware to interrupt it when
			 * things are ready to go.  We need this ability
			 * to wakeup our STREAMS queues.
			 * Criteria for reenabling queues.
			 *	gstate == IDNGS_ONLINE
			 *	channel = !check-in
			 *	buffers are available
			 *
			 * xmit_chanset_wanted
			 *	Indicates which channels wish to have
			 *	their queues reenabled when ready.
			 * xmit_tid
			 *	Timeout-id of monitor.
			 */
	kmutex_t	xmit_lock;
	idn_chanset_t	xmit_chanset_wanted;	/* xmit_lock */
	timeout_id_t	xmit_tid;		/* xmit_lock */

	struct {
		/*
		 * ready
		 *	Indicates SMR region allocated
		 *	and available from OBP.
		 * vaddr
		 *	Virtual address assigned to SMR.
		 * locpfn
		 *	Page Frame Number associated
		 *	with local domain's SMR.
		 * rempfn
		 *	Page Frame Number associated
		 *	with remote (Master) domain's SMR.
		 * rempfnlim
		 *	PFN past end of remote domain's
		 *	SMR.
		 * prom_paddr/prom_size
		 *	Physical address and size of
		 *	SMR that were assigned by OBP.
		 */
		int		ready;
		caddr_t		vaddr;
		pfn_t		locpfn;
		pfn_t		rempfn;		/* grwlock */

		pfn_t		rempfnlim;	/* grwlock */
		uint64_t	prom_paddr;

		uint64_t	prom_size;
	} smr;

			/*
			 * idnsb_mutex
			 *	Protects access to IDN's
			 *	sigblock area.
			 * idnsb_eventp
			 *	IDN's private area in sigblock
			 *	used for signaling events
			 *	regarding IDN state to SSP.
			 * idnsb
			 *	Area within IDN's private
			 *	sigblock area used for tracking
			 *	certain IDN state which might
			 *	be useful during arbstop
			 *	conditions (if caused by IDN!).
			 */
	kmutex_t	idnsb_mutex;
	idnsb_event_t	*idnsb_eventp;
	idnsb_t		*idnsb;

	struct sigbintr {
		/*
		 * sb_mutex
		 *	Protects sigbintr elements
		 *	to synchronize execution of
		 *	sigblock (IDN) mailbox handling.
		 * sb_cpuid
		 *	Cpu whose sigblock mailbox
		 *	originally received IDN request
		 *	from SSP.  Necessary to know
		 *	where to put response.
		 * sb_busy
		 *	Flag indicating state of
		 *	sigblock handler thread.
		 *	Synchronize activity between
		 *	SSP and current IDN requests that
		 *	are in progress.
		 * sb_cv
		 *	Condition variable for sigblock
		 *	handler thread to wait on.
		 * sb_inum
		 *	Soft interrupt number assigned
		 *	by OS to handle soft interrupt
		 *	request make by low-level (IDN)
		 *	sigblock handler to dispatch actual
		 *	processing of sigblock (mailbox)
		 *	request.
		 */
		kmutex_t	sb_mutex;
		uchar_t		sb_cpuid;	/* sigbintr.sb_mutex */
		uchar_t		sb_busy;	/* sigbintr.sb_mutex */
		kcondvar_t	sb_cv;		/* sigbintr.sb_mutex */
		uint64_t	sb_inum;	/* sigbintr.sb_mutex */
	} sigbintr;

			/*
			 * struprwlock, strup, sip, siplock
			 *	Standard network streams
			 *	handling structures to manage
			 *	instances of IDN driver.
			 */
	krwlock_t	struprwlock;
	struct idnstr	*strup;			/* struprwlock */

	struct idn	*sip;			/* siplock */
	kmutex_t	sipwenlock;
	kmutex_t	siplock;

			/*
			 * Area where IDN maintains its kstats.
			 */
	kstat_t		*ksp;
			/*
			 * Number of domains that local domain
			 * has "open".
			 */
	int		ndomains;		/* grwlock */
			/*
			 * Number of domains that local domain
			 * has registered as non-responsive.
			 */
	int		nawols;			/* grwlock */
			/*
			 * Number of network channels (interfaces)
			 * which are currently active.
			 */
	int		nchannels;		/* grwlock */
			/*
			 * Bitmask representing channels
			 * that are currently active.
			 */
	idn_chanset_t	chanset;		/* grwlock */
			/*
			 * Array of channel (network/data) servers
			 * that have been created.  Not necessarily
			 * all active.
			 */
	idn_chansvr_t	*chan_servers;		/* elmts = ch_mutex */
			/*
			 * Pointer to sigblock handler thread
			 * which ultimately processes SSP
			 * IDN requests.
			 */
	kthread_id_t	sigb_threadp;
			/*
			 * Pointer to area used by Master
			 * to hold mailbox structures.
			 * Actual memory is in SMR.
			 */
	idn_mboxtbl_t	*mboxarea;		/* grwlock */

	struct {
		/*
		 * IDN_SYNC_LOCK - Provides serialization
		 * mechanism when performing synchronous
		 * operations across domains.
		 */
		kmutex_t	sz_mutex;
		/*
		 * Actual synchronization zones for
		 * CONNECT/DISCONNECT phases.
		 */
		idn_synczone_t	sz_zone[IDN_SYNC_NUMZONE];
	} sync;					/* sz_mutex */

	struct {
		/*
		 * ds_trans_on
		 *	Set of domains which are trying
		 *	to establish a link w/local.
		 * ds_ready_on
		 *	Set of domains which local knows
		 *	are ready for linking, but has
		 *	not yet confirmed w/peers.
		 * ds_connected
		 *	Set of domains that local has
		 *	confirmed as being ready.
		 * ds_trans_off
		 *	Set of domains which are trying
		 *	to unlink from local.
		 * ds_ready_off
		 *	Set of domains which local knows
		 *	are ready for unlink, but has
		 *	not yet confirmed w/peers.
		 * ds_relink
		 *	Set of domains we're expecting
		 *	to relink with subsequent to
		 *	a RECONFIG (new master selection).
		 * ds_hwlinked
		 *	Set of domains for which local
		 *	has programmed its hardware.
		 * ds_flush
		 *	Set of domains requiring that
		 *	local flush its ecache prior
		 *	to unlinking.
		 * ds_awol
		 *	Set of domains believed to be
		 *	AWOL - haven't responded to
		 *	any queries.
		 * ds_hitlist
		 *	Set of domains which local domain
		 *	is unlinking from and wishes to ignore
		 *	any extraneous indirect link requests
		 *	from other domains, e.g. during a
		 *	Reconfig.
		 */
		domainset_t	ds_trans_on;	/* sz_mutex */
		domainset_t	ds_ready_on;	/* sz_mutex */

		domainset_t	ds_connected;	/* sz_mutex */
		domainset_t	ds_trans_off;	/* sz_mutex */

		domainset_t	ds_ready_off;	/* sz_mutex */
		domainset_t	ds_relink;	/* sz_mutex */

		domainset_t	ds_hwlinked;	/* sz_mutex */
		domainset_t	ds_flush;	/* sz_mutex */

		domainset_t	ds_awol;	/* sz_mutex */
		domainset_t	ds_hitlist;	/* sz_mutex */
	} domset;
			/*
			 * Bitmask identifying all cpus in
			 * the local IDN.
			 */
	cpuset_t	dc_cpuset;
			/*
			 * Bitmask identifying all boards in
			 * the local IDN.
			 */
	boardset_t	dc_boardset;

	struct dopers {
		/*
		 * Waiting area for IDN requests,
		 * i.e. link & unlinks.  IDN requests
		 * are performed asynchronously so
		 * we need a place to wait until the
		 * operation has completed.
		 *
		 * dop_domset
		 *	Identifies which domains the
		 *	current waiter is interested in.
		 * dop_waitcount
		 *	Number of waiters in the room.
		 * dop_waitlist
		 *	Actual waiting area.
		 * dop_freelist
		 *	Freelist (small cache) of
		 *	structs for waiting area.
		 */
		kmutex_t	dop_mutex;
		kcondvar_t	dop_cv;		/* dop_mutex */
		domainset_t	dop_domset;	/* dop_mutex */
		int		dop_waitcount;	/* dop_mutex */
		dop_waitlist_t	*dop_waitlist;	/* dop_mutex */
		dop_waitlist_t	*dop_freelist;	/* dop_mutex */
							/* dop_mutex */
		dop_waitlist_t	_dop_wcache[IDNOP_CACHE_SIZE];
	} *dopers;

	struct {
		/*
		 * Protocol Server:
		 *
		 * p_server
		 *	Linked list of queues
		 *	describing protocol
		 *	servers in use.
		 * p_jobpool
		 *	Kmem cache of structs
		 *	used to enqueue protocol
		 *	jobs for protocol servers.
		 * p_morgue
		 *	Synchronization (check-in)
		 *	area used when terminating
		 *	protocol servers (threads).
		 */
		struct idn_protoqueue	*p_serverq;
		kmem_cache_t		*p_jobpool;
		ksema_t			p_morgue;
	} protocol;

	struct idn_retry_queue {
		/*
		 * rq_jobs
		 *	Queue of Retry jobs
		 *	that are outstanding.
		 * rq_count
		 *	Number of jobs on retry
		 *	queue.
		 * rq_cache
		 *	Kmem cache for structs
		 *	used to describe retry
		 *	jobs.
		 */
		idn_retry_job_t	*rq_jobs;	/* rq_mutex */
		int		rq_count;	/* rq_mutex */
		kmutex_t	rq_mutex;	/* rq_mutex */

		kcondvar_t	rq_cv;		/* rq_mutex */
		kmem_cache_t	*rq_cache;
	} retryqueue;

	struct slabpool {
		/*
		 * Slabpool:
		 *
		 * ntotslabs
		 *	Total number of slabs
		 *	in SMR (free & in-use).
		 * npools
		 *	Number of pools available
		 *	in list.  One smr_slabtbl
		 *	exists for each pool.
		 */
		int		ntotslabs;
		int		npools;
		struct smr_slabtbl {
			/*
			 * sarray
			 *	Array of slab structs
			 *	representing slabs in SMR.
			 * nfree
			 *	Number of slabs actually
			 *	available in sarray.
			 * nslabs
			 *	Number of slabs represented
			 *	in sarray (free & in-use).
			 */
			smr_slab_t	*sarray;
			int		nfree;
			int		nslabs;
		} *pool;
		/*
		 * Holds array of smr_slab_t structs kmem_alloc'd
		 * for slabpool.
		 */
		smr_slab_t	*savep;
	} *slabpool;

	struct slabwaiter {
		/*
		 * Waiting area for threads
		 * requesting slab allocations.
		 * Used by Slaves for all requests,
		 * but used by Master only for
		 * redundant requests, i.e. multiple
		 * requests on behalf of the same
		 * domain.  One slabwaiter area
		 * exist for each possible domain.
		 *
		 * w_nwaiters
		 *	Number of threads waiting
		 *	in waiting area.
		 * w_done
		 *	Flag to indicate that
		 *	allocation request has
		 *	completed.
		 * w_serrno
		 *	Non-zero indicates an
		 *	errno value to represent
		 *	error that occurred during
		 *	attempt to allocate slab.
		 * w_closed
		 *	Indicates that waiting area is
		 *	closed and won't allow any new
		 *	waiters.  This occurs during
		 *	the small window where we're
		 *	trying to suspend a channel.
		 * w_cv
		 *	Condvar for waiting on.
		 * w_sp
		 *	Holds slab structure of
		 *	successfully allocated slab.
		 */
		kmutex_t	w_mutex;
		short		w_nwaiters;	/* w_mutex */
		short		w_done;		/* w_mutex */
		short		w_serrno;	/* w_mutex */
		short		w_closed;	/* w_mutex */
		kcondvar_t	w_cv;		/* w_mutex */
		smr_slab_t	*w_sp;		/* w_mutex */
	} *slabwaiter;
			/*
			 * Kmem cache used for allocating
			 * timer structures for outstanding
			 * IDN requests.
			 */
	kmem_cache_t	*timer_cache;
			/*
			 * Effectively constant used in
			 * translating buffer frames in
			 * mailbox message frames to
			 * offsets within SMR.
			 */
	int		bframe_shift;
} idn_global_t;

typedef struct idn_retry_queue	idn_retry_queue_t;

#define	IDN_GET_MASTERID()	(idn.masterid)
#define	IDN_SET_MASTERID(mid) \
	{ \
		int	_mid = (mid); \
		mutex_enter(&idn.idnsb_mutex); \
		if (idn.idnsb) { \
			idn.idnsb->id_pmaster_board = \
					idn.idnsb->id_master_board; \
			if (_mid == IDN_NIL_DOMID) \
				idn.idnsb->id_master_board = (uchar_t)0xff; \
			else \
				idn.idnsb->id_master_board = \
				(uchar_t)idn_domain[_mid].dvote.v.board; \
		} \
		mutex_exit(&idn.idnsb_mutex); \
		IDN_HISTORY_LOG(IDNH_MASTERID, _mid, idn.masterid, 0); \
		PR_STATE("%d: MASTERID %d -> %d\n", __LINE__, \
			idn.masterid, _mid); \
		idn.masterid = _mid; \
	}
#define	IDN_GET_NEW_MASTERID()	(idn.new_masterid)
#define	IDN_SET_NEW_MASTERID(mid) \
	{ \
		PR_STATE("%d: NEW MASTERID %d -> %d\n", __LINE__, \
			idn.new_masterid, (mid)); \
		idn.new_masterid = (mid); \
	}

#define	IDN_GLOCK_EXCL()	(rw_enter(&idn.grwlock, RW_WRITER))
#define	IDN_GLOCK_SHARED()	(rw_enter(&idn.grwlock, RW_READER))
#define	IDN_GLOCK_TRY_SHARED()	(rw_tryenter(&idn.grwlock, RW_READER))
#define	IDN_GLOCK_DOWNGRADE()	(rw_downgrade(&idn.grwlock))
#define	IDN_GUNLOCK()		(rw_exit(&idn.grwlock))
#define	IDN_GLOCK_IS_EXCL()	(RW_WRITE_HELD(&idn.grwlock))
#define	IDN_GLOCK_IS_SHARED()	(RW_READ_HELD(&idn.grwlock))
#define	IDN_GLOCK_IS_HELD()	(RW_LOCK_HELD(&idn.grwlock))

#define	IDN_SYNC_LOCK()		(mutex_enter(&idn.sync.sz_mutex))
#define	IDN_SYNC_TRYLOCK()	(mutex_tryenter(&idn.sync.sz_mutex))
#define	IDN_SYNC_UNLOCK()	(mutex_exit(&idn.sync.sz_mutex))
#define	IDN_SYNC_IS_LOCKED()	(MUTEX_HELD(&idn.sync.sz_mutex))

/*
 * Macro to reset some globals necessary in preparing
 * for initialization of HW for IDN.
 */
#define	IDN_PREP_HWINIT() \
	{ \
		ASSERT(IDN_GLOCK_IS_EXCL()); \
		lock_clear(&idn.first_swlink); \
		lock_clear(&idn.first_hwlink); \
		idn.first_hwmasterid = (short)IDN_NIL_DOMID; \
	}

/*
 * Return values of idn_send_data.
 */
#define	IDNXMIT_OKAY	0	/* xmit successful */
#define	IDNXMIT_LOOP	1	/* loopback */
#define	IDNXMIT_DROP	2	/* drop packet */
#define	IDNXMIT_RETRY	3	/* retry packet (requeue and qenable) */
#define	IDNXMIT_REQUEUE	4	/* requeue packet, but don't qenable */

/*
 * ---------------------------------------------------------------------
 * ss_rwlock must be acquired _before_ any idn_domain locks are
 * acquired if both structs need to be accessed.
 * idn.struprwlock is acquired when traversing IDN's strup list
 * and when adding or deleting entries.
 *
 * ss_nextp	Linked list of streams.
 * ss_rq	Respective read queue.
 * ss_sip	Attached device.
 * ss_state	Current DL state.
 * ss_sap	Bound SAP.
 * ss_flags	Misc. flags.
 * ss_mccount	# enabled multicast addrs.
 * ss_mctab	Table of multicast addrs.
 * ss_minor	Minor device number.
 * ss_rwlock	Protects ss_linkup fields and DLPI state machine.
 * ss_linkup	Boolean flag indicating whether particular (domain) link
 *		is up.
 * ---------------------------------------------------------------------
 */
struct idnstr {				/* gets shoved into q_ptr */
	struct idnstr	*ss_nextp;
	queue_t		*ss_rq;
	struct idn	*ss_sip;
	t_uscalar_t	ss_state;
	t_uscalar_t	ss_sap;
	uint_t		ss_flags;
	uint_t		ss_mccount;
	struct ether_addr	*ss_mctab;
	minor_t		ss_minor;
	krwlock_t	ss_rwlock;
};

/*
 * idnstr.ss_flags - Per-stream flags
 */
#define	IDNSFAST	0x01		/* "M_DATA fastpath" mode */
#define	IDNSRAW		0x02		/* M_DATA plain raw mode */
#define	IDNSALLPHYS	0x04		/* "promiscuous mode" */
#define	IDNSALLMULTI	0x08		/* enable all multicast addresses */
#define	IDNSALLSAP	0x10		/* enable all ether type values */

/*
 * Maximum number of multicast address per stream.
 */
#define	IDNMAXMC	64
#define	IDNMCALLOC	(IDNMAXMC * sizeof (struct ether_addr))

/*
 * Full DLSAP address length (in struct dladdr format).
 */
#define	IDNADDRL	(ETHERADDRL + sizeof (ushort_t))

struct idndladdr {
	struct ether_addr	dl_phys;
	ushort_t		dl_sap;
};

#define	IDNHEADROOM		64
#define	IDNROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))

/*
 * Respective interpretation of bytes in 6 byte ethernet address.
 */
#define	IDNETHER_ZERO		0
#define	IDNETHER_COOKIE1	1
#define	  IDNETHER_COOKIE1_VAL		0xe5
#define	IDNETHER_COOKIE2	2
#define	  IDNETHER_COOKIE2_VAL		0x82
#define	IDNETHER_NETID		3
#define	IDNETHER_CHANNEL	4
#define	IDNETHER_RESERVED	5
#define	  IDNETHER_RESERVED_VAL		0x64

/*
 * IDN driver supports multliple instances, however they
 * still all refer to the same "physical" device.  Multiple
 * instances are supported primarily to allow increased
 * STREAMs bandwidth since each instance has it's own IP queue.
 * This structure is primarily defined to be consistent with
 * other network drivers and also to hold the kernel stats.
 */
struct idn_kstat {
	ulong_t		si_ipackets;	/* # packets received */
	ulong_t		si_ierrors;	/* # total input errors */
	ulong_t		si_opackets;	/* # packets sent */
	ulong_t		si_oerrors;	/* # total output errors */

	ulong_t		si_txcoll;	/* # xmit collisions */
	ulong_t		si_rxcoll;	/* # recv collisions */
	ulong_t		si_crc;		/* # recv crc errors */
	ulong_t		si_buff;	/* # recv pkt sz > buf sz */

	ulong_t		si_nolink;	/* # loss of connection */
	ulong_t		si_linkdown;	/* # link is down */
	ulong_t		si_inits;	/* # driver inits */
	ulong_t		si_nocanput;	/* # canput() failures */

	ulong_t		si_allocbfail;	/* # allocb() failures */
	ulong_t		si_notbufs;	/* # out of xmit buffers */
	ulong_t		si_reclaim;	/* # reclaim failures */
	ulong_t		si_smraddr;	/* # bad SMR addrs */

	ulong_t		si_txmax;	/* # xmit over limit */
	ulong_t		si_txfull;	/* # xmit mbox full */
	ulong_t		si_xdcall;	/* # xdcalls sent */
	ulong_t		si_sigsvr;	/* # data server wakeups */

	ulong_t		si_mboxcrc;	/* # send mbox crc errors */
	/*
	 * MIB II kstat variables
	 */
	ulong_t		si_rcvbytes;	/* # bytes received */
	ulong_t		si_xmtbytes;	/* # bytes transmitted */
	ulong_t		si_multircv;	/* # multicast packets received */

	ulong_t		si_multixmt;	/* # multicast packets for xmit */
	ulong_t		si_brdcstrcv;	/* # broadcast packets received */
	ulong_t		si_brdcstxmt;	/* # broadcast packets for xmit */
	ulong_t		si_norcvbuf;	/* # rcv packets discarded */

	ulong_t		si_noxmtbuf;	/* # xmit packets discarded */
	/*
	 * PSARC 1997/198 : 64 bit kstats
	 */
	uint64_t	si_ipackets64;	/* # packets received */
	uint64_t	si_opackets64;	/* # packets transmitted */
	uint64_t	si_rbytes64;	/* # bytes received */
	uint64_t	si_obytes64;	/* # bytes transmitted */
	/*
	 * PSARC 1997/247 : RFC 1643	dot3Stats...
	 */
	ulong_t	si_fcs_errors;		/* FCSErrors */
	ulong_t	si_macxmt_errors;	/* InternalMacTransmitErrors */
	ulong_t	si_toolong_errors;	/* FrameTooLongs */
	ulong_t	si_macrcv_errors;	/* InternalMacReceiveErrors */
};

/*
 * Per logical interface private data structure.
 */
struct idn {
	struct idn		*si_nextp;	/* linked instances */
	dev_info_t		*si_dip;	/* assoc. dev_info */
	struct ether_addr	si_ouraddr;	/* enet address */

	uint_t			si_flags;	/* misc. flags */
	uint_t			si_wantw;	/* xmit: out of res. */
	queue_t			*si_ip4q;	/* ip (v4) read queue */
	queue_t			*si_ip6q;	/* ip (v6) read queue */

	kstat_t			*si_ksp;	/* kstat pointer */
	struct idn_kstat	si_kstat;	/* per-inst kstat */
};

struct idn_gkstat {
	ulong_t		gk_reconfigs;		/* # reconfigs */
	ulong_t		gk_reconfig_last;	/* timestamep */
	ulong_t		gk_reaps;		/* # of reap request */
	ulong_t		gk_reap_last;		/* timestamep */

	ulong_t		gk_links;		/* # of IDN links */
	ulong_t		gk_link_last;		/* timestamep */
	ulong_t		gk_unlinks;		/* # of IDN unlinks */
	ulong_t		gk_unlink_last;		/* timestamep */

	ulong_t		gk_buffail;		/* # bad bufalloc */
	ulong_t		gk_buffail_last;	/* timestamp */
	ulong_t		gk_slabfail;		/* # bad slaballoc */
	ulong_t		gk_slabfail_last;	/* timestamp */

	ulong_t		gk_reap_count;		/* # of slabs reaped */
	ulong_t		gk_dropped_intrs;	/* dropped intrs */
};

extern struct idn_gkstat	sg_kstat;

#ifdef IDN_NO_KSTAT

#define	IDN_KSTAT_INC(s, i)
#define	IDN_KSTAT_ADD(s, i, n)
#define	IDN_GKSTAT_INC(i)
#define	IDN_GKSTAT_ADD(vvv, iii)
#define	IDN_GKSTAT_GLOBAL_EVENT(vvv, nnn)

#else /* IDN_NO_KSTAT */

#define	IDN_KSTAT_INC(sss, vvv) \
		((((struct idn *)(sss))->si_kstat.vvv)++)
#define	IDN_KSTAT_ADD(sss, vvv, nnn) \
		((((struct idn *)(sss))->si_kstat.vvv) += (nnn))
#define	IDN_GKSTAT_INC(vvv)		((sg_kstat.vvv)++)
#define	IDN_GKSTAT_ADD(vvv, iii)	((sg_kstat.vvv) += (iii))
#define	IDN_GKSTAT_GLOBAL_EVENT(vvv, ttt) \
		((sg_kstat.vvv)++, ((sg_kstat.ttt) = ddi_get_lbolt()))

#endif /* IDN_NO_KSTAT */

/*
 * idn.si_flags
 */
#define	IDNRUNNING		0x01		/* IDNnet is UP */
#define	IDNPROMISC		0x02		/* promiscuous mode enabled */
#define	IDNSUSPENDED		0x04		/* suspended (DR) */

typedef struct kstat_named	kstate_named_t;

struct idn_kstat_named {
	kstat_named_t	sk_ipackets;	/* # packets received */
	kstat_named_t	sk_ierrors;	/* # total input errors */
	kstat_named_t	sk_opackets;	/* # packets sent */
	kstat_named_t	sk_oerrors;	/* # total output errors */

	kstat_named_t	sk_txcoll;	/* # xmit collisions */
	kstat_named_t	sk_rxcoll;	/* # recv collisions */
	kstat_named_t	sk_crc;		/* # recv crc errors */
	kstat_named_t	sk_buff;	/* # recv pkt sz > buf sz */

	kstat_named_t	sk_nolink;	/* # loss of connection */
	kstat_named_t	sk_linkdown;	/* # link is down */
	kstat_named_t	sk_inits;	/* # driver inits */
	kstat_named_t	sk_nocanput;	/* # canput() failures */

	kstat_named_t	sk_allocbfail;	/* # allocb() failures */
	kstat_named_t	sk_notbufs;	/* # out of xmit buffers */
	kstat_named_t	sk_reclaim;	/* # reclaim failures */
	kstat_named_t	sk_smraddr;	/* # bad SMR addrs */

	kstat_named_t	sk_txmax;	/* # xmit over limit */
	kstat_named_t	sk_txfull;	/* # xmit mbox full */
	kstat_named_t	sk_xdcall;	/* # xdcalls sent */
	kstat_named_t	sk_sigsvr;	/* # data server wakeups */

	kstat_named_t	sk_mboxcrc;	/* # send mbox crc errors */
	/*
	 * MIB II kstat variables
	 */
	kstat_named_t	sk_rcvbytes;	/* # bytes received */
	kstat_named_t	sk_xmtbytes;	/* # bytes transmitted */
	kstat_named_t	sk_multircv;	/* # multicast packets received */

	kstat_named_t	sk_multixmt;	/* # multicast packets for xmit */
	kstat_named_t	sk_brdcstrcv;	/* # broadcast packets received */
	kstat_named_t	sk_brdcstxmt;	/* # broadcast packets for xmit */
	kstat_named_t	sk_norcvbuf;	/* # rcv packets discarded */

	kstat_named_t	sk_noxmtbuf;	/* # xmit packets discarded */
	/*
	 * PSARC 1997/198 : 64bit kstats
	 */
	kstat_named_t	sk_ipackets64;	/* # packets received */
	kstat_named_t	sk_opackets64;	/* # packets transmitted */
	kstat_named_t	sk_rbytes64;	/* # bytes received */
	kstat_named_t	sk_obytes64;	/* # bytes transmitted */
	/*
	 * PSARC 1997/247 : RFC 1643	dot3Stats...
	 */
	kstat_named_t	sk_fcs_errors;		/* FCSErr */
	kstat_named_t	sk_macxmt_errors;	/* InternalMacXmtErr */
	kstat_named_t	sk_toolong_errors;	/* FrameTooLongs */
	kstat_named_t	sk_macrcv_errors;	/* InternalMacRcvErr */
};

/*
 * Stats for global events of interest (non-counters).
 */
struct idn_gkstat_named {
	kstat_named_t	sk_curtime;		/* current time */
	kstat_named_t	sk_reconfigs;		/* # master recfgs */
	kstat_named_t	sk_reconfig_last;	/* timestamp */
	kstat_named_t	sk_reaps;		/* # of reap req */
	kstat_named_t	sk_reap_last;		/* timestamp */
	kstat_named_t	sk_links;		/* # of links */
	kstat_named_t	sk_link_last;		/* timestamp */
	kstat_named_t	sk_unlinks;		/* # of unlinks */
	kstat_named_t	sk_unlink_last;		/* timestamp */
	kstat_named_t	sk_buffail;		/* # bad buf alloc */
	kstat_named_t	sk_buffail_last;	/* timestamp */
	kstat_named_t	sk_slabfail;		/* # bad buf alloc */
	kstat_named_t	sk_slabfail_last;	/* timestamp */
	kstat_named_t	sk_reap_count;		/* # slabs reaped */
	kstat_named_t	sk_dropped_intrs;	/* intrs dropped */
};

/*
 * ---------------------------------------------------------------------
 */
#ifdef DEBUG
#define	IDNXDC(d, mt, a1, a2, a3, a4) \
	((void) debug_idnxdc("idnxdc", (int)(d), (mt), \
		(uint_t)(a1), (uint_t)(a2), (uint_t)(a3), (uint_t)(a4)))
#else /* DEBUG */
#define	IDNXDC(d, mt, a1, a2, a3, a4) \
	(idnxdc((int)(d), (mt), \
		(uint_t)(a1), (uint_t)(a2), (uint_t)(a3), (uint_t)(a4)))
#endif /* DEBUG */
#define	IDNXDC_BROADCAST(ds, mt, a1, a2, a3, a4) \
	(idnxdc_broadcast((domainset_t)(ds), (mt), \
		(uint_t)(a1), (uint_t)(a2), (uint_t)(a3), (uint_t)(a4)))

/*
 * ---------------------------------------------------------------------
 */
#define	SET_XARGS(x, a0, a1, a2, a3) \
	((x)[0] = (uint_t)(a0), (x)[1] = (uint_t)(a1), \
	(x)[2] = (uint_t)(a2), (x)[3] = (uint_t)(a3))

#define	GET_XARGS(x, a0, a1, a2, a3) \
	((*(uint_t *)(a0) = (x)[0]), \
	(*(uint_t *)(a1) = (x)[1]), \
	(*(uint_t *)(a2) = (x)[2]), \
	(*(uint_t *)(a3) = (x)[3]))

#define	CLR_XARGS(x) \
		((x)[0] = (x)[1] = (x)[2] = (x)[3] = 0)

#define	GET_XARGS_NEGO_TICKET(x)	((uint_t)(x)[0])
#define	GET_XARGS_NEGO_DSET(x, d) \
		((d)[0] = (x)[1], (d)[1] = (x)[2], (d)[2] = (x)[3])
#define	SET_XARGS_NEGO_TICKET(x, t)	((x)[0] = (uint_t)(t))
#define	SET_XARGS_NEGO_DSET(x, d) \
		((x)[1] = (uint_t)(d)[0], \
		(x)[2] = (uint_t)(d)[1], \
		(x)[3] = (uint_t)(d)[2])

#define	GET_XARGS_CON_TYPE(x)		((idn_con_t)(x)[0])
#define	GET_XARGS_CON_DOMSET(x)		((domainset_t)(x)[1])
#define	SET_XARGS_CON_TYPE(x, t)	((x)[0] = (uint_t)(t))
#define	SET_XARGS_CON_DOMSET(x, s)	((x)[1] = (uint_t)(s))

#define	GET_XARGS_FIN_TYPE(x)		GET_FIN_TYPE((x)[0])
#define	GET_XARGS_FIN_ARG(x)		GET_FIN_ARG((x)[0])
#define	GET_XARGS_FIN_DOMSET(x)		((domainset_t)(x)[1])
#define	GET_XARGS_FIN_OPT(x)		((idn_finopt_t)(x)[2])
#define	GET_XARGS_FIN_MASTER(x)		((uint_t)(x)[3])
#define	SET_XARGS_FIN_TYPE(x, t)	SET_FIN_TYPE((x)[0], (t))
#define	SET_XARGS_FIN_ARG(x, a)		SET_FIN_ARG((x)[0], (a))
#define	SET_XARGS_FIN_DOMSET(x, s)	((x)[1] = (uint_t)(s))
#define	SET_XARGS_FIN_OPT(x, o)		((x)[2] = (uint_t)(o))
#define	SET_XARGS_FIN_MASTER(x, m)	((x)[3] = (uint_t)(m))

#define	GET_XARGS_NACK_TYPE(x)		((idn_nack_t)(x)[0])
#define	GET_XARGS_NACK_ARG1(x)		((x)[1])
#define	GET_XARGS_NACK_ARG2(x)		((x)[2])
#define	SET_XARGS_NACK_TYPE(x, t)	((x)[0] = (uint_t)(t))
#define	SET_XARGS_NACK_ARG1(x, a1)	((x)[1] = (uint_t)(a1))
#define	SET_XARGS_NACK_ARG2(x, a2)	((x)[2] = (uint_t)(a2))

#define	GET_XARGS_CFG_PHASE(x)		((int)(x)[0])
#define	SET_XARGS_CFG_PHASE(x, p)	((x)[0] = (uint_t)(p))

/*
 * ---------------------------------------------------------------------
 */
/*
 * Device instance to SIP (IDN instance pointer).
 */
#ifdef DEBUG
#define	IDN_INST2SIP(i) \
		(ASSERT(((i) >= 0) && ((i) < (IDN_MAXMAX_NETS << 1))), \
			idn_i2s_table[i])
#else /* DEBUG */
#define	IDN_INST2SIP(i)		(idn_i2s_table[i])
#endif /* DEBUG */

#define	IDN_SET_INST2SIP(i, s) \
	{ \
		ASSERT(((i) >= 0) && ((i) < (IDN_MAXMAX_NETS << 1))); \
		idn_i2s_table[i] = (s); \
	}

#define	IDN_NETID2DOMID(n)	(VALID_UDOMAINID(n) ? \
					((int)(n)) : IDN_NIL_DOMID)
#define	IDN_DOMID2NETID(d)	((ushort_t)(d))

#ifdef DEBUG
#define	IDNDL_ETHER2DOMAIN(eap) \
		(_idndl_ether2domain(eap))
#define	IDNDL_ETHER2SIP(eap) \
		(_idndl_ether2sip(eap))
#else
/*
 * The following values can be returned from IDNDL_ETHER2DOMAIN:
 *	IDN_NIL_DOMID
 *		Ether address is broadcast (0xff) or domain doesn't exist.
 *	domid	Domain id with drwlock(reader) held.
 */
#define	IDNDL_ETHER2DOMAIN(eap) \
	(IDN_NETID2DOMID((eap)->ether_addr_octet[IDNETHER_NETID]))
#define	IDNDL_ETHER2SIP(eap) \
		(((eap)->ether_addr_octet[IDNETHER_CHANNEL] == 0xff) ? NULL : \
		IDN_INST2SIP((int)(eap)->ether_addr_octet[IDNETHER_CHANNEL]))
#endif /* DEBUG */

#define	UPPER32_CPUMASK(s)	_upper32cpumask(s)
#define	LOWER32_CPUMASK(s)	_lower32cpumask(s)
#define	MAKE64_CPUMASK(s, u, l)	_make64cpumask(&(s), (u), (l))

#ifdef DEBUG
extern caddr_t	_idn_getstruct(char *structname, int size);
extern void	_idn_freestruct(caddr_t ptr, char *structname, int size);

#define	GETSTRUCT(structure, num) \
	((structure *)_idn_getstruct("structure", sizeof (structure)*(num)))
#define	FREESTRUCT(ptr, structure, num) \
	(_idn_freestruct((caddr_t)ptr, "structure", sizeof (structure)*(num)))
#else /* DEBUG */
#define	GETSTRUCT(structure, num) \
	((structure *)kmem_zalloc((uint_t)(sizeof (structure) * (num)), \
				    KM_SLEEP))
#define	FREESTRUCT(ptr, structure, num) \
	(kmem_free((caddr_t)(ptr), sizeof (structure) * (num)))
#endif /* DEBUG */

extern int		idn_debug;
extern idn_global_t	idn;
extern idn_domain_t	idn_domain[];
extern struct idn	*idn_i2s_table[];
extern int		idn_history;
extern struct idn_history	idnhlog;

extern int		idn_smr_size;
extern int		idn_nwr_size;
extern int		idn_protocol_nservers;
extern int		idn_awolmsg_interval;
extern int		idn_smr_bufsize;
extern int		idn_slab_bufcount;
extern int		idn_slab_prealloc;
extern int		idn_slab_mintotal;
extern int		idn_window_max;
extern int		idn_window_incr;
extern int		idn_reclaim_min;
extern int		idn_reclaim_max;
extern int		idn_mbox_per_net;
extern int		idn_max_nets;

extern int		idn_netsvr_spin_count;
extern int		idn_netsvr_wait_min;
extern int		idn_netsvr_wait_max;
extern int		idn_netsvr_wait_shift;

extern int		idn_checksum;

extern int		idn_msgwait_nego;
extern int		idn_msgwait_cfg;
extern int		idn_msgwait_con;
extern int		idn_msgwait_fin;
extern int		idn_msgwait_cmd;
extern int		idn_msgwait_data;

extern int		idn_retryfreq_nego;
extern int		idn_retryfreq_con;
extern int		idn_retryfreq_fin;

extern int		idn_window_emax;	/* calculated */
extern int		idn_slab_maxperdomain;	/* calculated */

/*
 * ---------------------------------------------------------------------
 * io/idn.c
 * ---------------------------------------------------------------------
 */
extern int	board_to_ready_cpu(int board, cpuset_t cpuset);
extern int	idn_open_domain(int domid, int cpuid, uint_t ticket);
extern void 	idn_close_domain(int domid);
extern void	inum2str(uint_t inum, char str[]);
extern idn_timer_t	*idn_timer_alloc();
extern void	idn_timer_free(idn_timer_t *tp);
extern void	idn_timerq_init(idn_timerq_t *tq);
extern void	idn_timerq_deinit(idn_timerq_t *tq);
extern void	idn_timerq_free(idn_timerq_t *tq);
extern ushort_t	idn_timer_start(idn_timerq_t *tq, idn_timer_t *tp,
				clock_t tval);
extern int	idn_timer_stopall(idn_timer_t *tp);
extern void	idn_timer_dequeue(idn_timerq_t *tq, idn_timer_t *tp);
extern void	idn_timer_stop(idn_timerq_t *tq, int subtype, ushort_t tcookie);
extern idn_timer_t	*idn_timer_get(idn_timerq_t *tq, int subtype,
				ushort_t tcookie);
extern void	idn_domain_resetentry(idn_domain_t *dp);
extern void	idn_strlinks_enable(uint_t netaddr, int domid);
extern void	idn_strlinks_disable(uint_t domset, uint_t netaddr,
				int disconnect);
extern void	idn_dopcache_init();
extern void	idn_dopcache_deinit();
extern void 	*idn_init_op(idn_opflag_t opflag, boardset_t boardset,
				idnsb_error_t *sep);
extern void	idn_add_op(idn_opflag_t opflag, domainset_t domset);
extern void	idn_update_op(idn_opflag_t opflag, domainset_t domset,
				idnsb_error_t *sep);
extern void	idn_deinit_op(void *cookie);
extern int	idn_wait_op(void *cookie, boardset_t *domsetp,
				int wait_timeout);
extern int	idn_wakeup_op(boardset_t boardset, uint_t domset,
				idn_opflag_t opflag, int error);
extern void	idn_error_op(uint_t domset, boardset_t boardset, int error);
extern void	cpuset2str(cpuset_t cset, char buffer[]);
extern void	domainset2str(domainset_t dset, char buffer[]);
extern void	boardset2str(boardset_t bset, char buffer[]);
extern void	mask2str(uint_t mask, char buffer[], int maxnum);
extern int	idnxdc(int domid, idn_msgtype_t *mtp,
				uint_t arg1, uint_t arg2,
				uint_t arg3, uint_t arg4);
extern void	idnxdc_broadcast(domainset_t domset, idn_msgtype_t *mtp,
				uint_t arg1, uint_t arg2,
				uint_t arg3, uint_t arg4);
extern void	idn_awol_event_set(boardset_t boardset);
extern void	idn_awol_event_clear(boardset_t boardset);
#ifdef DEBUG
extern int	debug_idnxdc(char *f, int domid, idn_msgtype_t *mtp,
				uint_t arg1, uint_t arg2,
				uint_t arg3, uint_t arg4);
#endif /* DEBUG */
extern boardset_t	cpuset2boardset(cpuset_t portset);
extern uint_t	_upper32cpumask(cpuset_t cset);
extern uint_t	_lower32cpumask(cpuset_t cset);
extern void	_make64cpumask(cpuset_t *csetp, uint_t upper, uint_t lower);

/*
 * ---------------------------------------------------------------------
 * io/idn_proto.c
 * ---------------------------------------------------------------------
 */
extern void	idn_assign_cookie(int domid);
extern int	idn_rput_data(queue_t *q, mblk_t *mp, int isput);
extern int	idn_wput_data(queue_t *q, mblk_t *mp, int isput);
extern int	idn_send_data(int dst_domid, idn_netaddr_t dst_netaddr,
				queue_t *wq, mblk_t *mp);
extern void 	idn_recv_signal(mblk_t *mp);
extern int 	idn_link(int domid, int cpuid, int pri, int waittime,
				idnsb_error_t *sep);
extern int 	idn_unlink(int domid, boardset_t idnset, idn_fin_t fintype,
				idn_finopt_t finopt, int waittime,
				idnsb_error_t *sep);
extern int	idnh_recv_dataack(int domid, int src_proc,
				uint_t acknack, idn_xdcargs_t xargs);
extern int 	idnh_recv_other(int sourceid, int src_proc, int dst_proc,
				uint_t inum, uint_t acknack,
				idn_xdcargs_t xargs);
extern void 	idn_send_cmd(int domid, idn_cmd_t cmdtype,
				uint_t arg1, uint_t arg2, uint_t arg3);
extern void	idn_send_cmdresp(int domid, idn_msgtype_t *mtp,
				idn_cmd_t cmdtype, uint_t arg1,
				uint_t arg2, uint_t cerrno);
extern void 	idn_broadcast_cmd(idn_cmd_t cmdtype,
				uint_t arg1, uint_t arg2, uint_t arg3);
extern int	idn_reclaim_mboxdata(int domid, int channel, int nbufs);
extern void	idn_clear_awol(int domid);
extern int	idn_protocol_init(int nservers);
extern void	idn_protocol_deinit();
extern void	idn_timer_expired(void *arg);
extern int	idn_open_channel(int channel);
extern void	idn_close_channel(int channel, idn_chanop_t chanop);
extern idn_mainmbox_t	*idn_mainmbox_init(int domid, int mbx);
extern void	idn_mainmbox_deinit(int domid, idn_mainmbox_t *mmp);
extern void	idn_signal_data_server(int domid, ushort_t channel);
extern int	idn_chanservers_init();
extern void	idn_chanservers_deinit();
extern void	idn_chanserver_bind(int net, int cpuid);
extern int	idn_retry_terminate(uint_t token);
extern idn_protojob_t	*idn_protojob_alloc(int kmflag);
extern void	idn_protojob_submit(int cookie, idn_protojob_t *jp);
extern int	idn_domain_is_registered(int domid, int channel,
				idn_chanset_t *chansetp);
extern void	idn_xmit_monitor_kickoff(int chan_wanted);
extern void	idn_sync_exit(int domid, idn_synccmd_t cmd);
/*
 * ---------------------------------------------------------------------
 * io/idn_xf.c
 * ---------------------------------------------------------------------
 */
extern void	idnxf_flushall_ecache();
extern int	idnxf_shmem_add(int is_master, boardset_t boardset,
				pfn_t pfnbase, pfn_t pfnlimit,
				uint_t *mcadr);
extern int	idnxf_shmem_sub(int is_master, boardset_t boardset);
extern int	idn_cpu_per_board(void *p2o, cpuset_t cset,
				struct hwconfig *hwp);
/*
 * ---------------------------------------------------------------------
 * io/idn_dlpi.c
 * ---------------------------------------------------------------------
 */
extern int	idndl_init(struct idn *sip);
extern void	idndl_uninit(struct idn *sip);
extern void	idndl_statinit(struct idn *sip);
extern void	idndl_dodetach(struct idnstr *);
extern int	idnioc_dlpi(queue_t *wq, mblk_t *mp, int *argsize);
extern void	idndl_localetheraddr(struct idn *sip, struct ether_addr *eap);
extern int	idndl_domain_etheraddr(int domid, int instance,
				struct ether_addr *eap);
extern void	idndl_dlpi_init();
extern int	idndl_start(queue_t *wq, mblk_t *mp, struct idn *sip);
extern void	idndl_read(struct idn *sip, mblk_t *mp);
extern void	idndl_proto(queue_t *wq, mblk_t *mp);
extern void	idndl_sendup(struct idn *, mblk_t *, struct idnstr *(*)());
extern struct idnstr *idndl_accept(struct idnstr *, struct idn *, int,
				struct ether_addr *);
extern struct idnstr *idndl_paccept(struct idnstr *, struct idn *, int,
				struct ether_addr *);
extern void	idndl_wenable(struct idn *);
/*
 * ---------------------------------------------------------------------
 * io/idn_smr.c
 * ---------------------------------------------------------------------
 */
extern void	smr_slabwaiter_open(domainset_t domset);
extern void	smr_slabwaiter_close(domainset_t domset);
/*
 * ---------------------------------------------------------------------
 */
extern void	idn_smrsize_init();
extern void	idn_init_autolink();
extern void	idn_deinit_autolink();

extern void	idn_dmv_handler(void *arg);
extern void	idnxf_init_mondo(uint64_t dmv_word0,
				uint64_t dmv_word1, uint64_t dmv_word2);
extern int	idnxf_send_mondo(int upaid);

extern clock_t	idn_msg_waittime[];
extern clock_t	idn_msg_retrytime[];

#endif /* !_ASM */
#endif /* _KERNEL */

#ifndef _ASM
/*
 * ---------------------------------------------------------------------
 */
#define	IDN_NIL_DOMID		-1
#define	IDN_NIL_DCPU		-1

/*
 * ---------------------------------------------------------------------
 */

/*
 * IOCTL Interface
 *
 * Commands must stay in the range (1 - 4096) since only 12 bits
 * are allotted.
 */
#define	_IDN(n)			(('I' << 20) | ('D' << 12) | (n))
#define	IDNIOC_LINK		_IDN(1)		/* domain_link */
#define	IDNIOC_UNLINK		_IDN(2)		/* domain_unlink */
#define	IDNIOC_unused0		_IDN(3)
#define	IDNIOC_unused1		_IDN(4)
#define	IDNIOC_unused2		_IDN(5)
#define	IDNIOC_unused3		_IDN(6)
#define	IDNIOC_unused4		_IDN(7)
#define	IDNIOC_DLPI_ON		_IDN(8)		/* Turn ON DLPI on str */
#define	IDNIOC_DLPI_OFF		_IDN(9)		/* Turn OFF DLPI on str */
#define	IDNIOC_PING		_IDN(10)	/* For latency testing */
#define	IDNIOC_PING_INIT	_IDN(11)
#define	IDNIOC_PING_DEINIT	_IDN(12)
#define	IDNIOC_MEM_RW		_IDN(13)	/* Random R/W of SMR */


#define	VALID_NDOP(op)		(((op) == ND_SET) || ((op) == ND_GET))

#define	VALID_DLPIOP(op)	(((op) == DLIOCRAW) || \
				((op) == DL_IOC_HDR_INFO))

#define	VALID_IDNOP(op)		(((op) >= _IDN(1)) && ((op) <= _IDN(13)))

#define	VALID_IDNIOCTL(op)	(VALID_IDNOP(op) || \
				VALID_NDOP(op) || \
				VALID_DLPIOP(op))

typedef union idnop {
	struct {
		int		domid;		/* input */
		int		cpuid;		/* input */
		int		master;		/* input */
		int		wait;		/* input */
	} link;
	struct {
		int		domid;		/* input */
		int		cpuid;		/* input */
		int		force;		/* input */
		int		wait;		/* input */
	} unlink;
	struct {
		int		domid;		/* input */
		int		cpuid;		/* input */
	} ping;
	struct {
		uint_t		lo_off;		/* input */
		uint_t		hi_off;		/* input */
		int		blksize;	/* input */
		int		num;		/* input */
		int		rw;		/* input */
		int		goawol;		/* input */
	} rwmem;
} idnop_t;

#ifdef _KERNEL
/*
 * ndd support for IDN tunables.
 */
typedef struct idnparam {
	ulong_t	sp_min;
	ulong_t	sp_max;
	ulong_t	sp_val;
	char	*sp_name;
} idnparam_t;

extern idnparam_t	idn_param_arr[];

#define	idn_modunloadable		idn_param_arr[0].sp_val
#ifdef IDN_PERF
#define	_LP	0
#define	_xxx_tbd			idn_param_arr[_LP+1].sp_val
#endif /* IDN_PERF */

/*
 * =====================================================================
 */

/*
 * Some junk to pretty print board lists and cpu lists in
 * log/console messages.  Length is big enough to display 64 double
 * digit cpus separated by a command and single space.  (Board list
 * is similar, but only 16 entries possible.
 */
#define	_DSTRLEN		400
#define	ALLOC_DISPSTRING()	((char *)kmem_alloc(_DSTRLEN, KM_NOSLEEP))
#define	FREE_DISPSTRING(b)	(kmem_free((void *)(b), _DSTRLEN))

/*
 * These are declared in idn.c.
 */
extern const char	*idnds_str[];
extern const char	*idnxs_str[];
extern const char	*idngs_str[];
extern const char	*idncmd_str[];
extern const char	*idncon_str[];
extern const char	*idnfin_str[];
extern const char	*idnfinarg_str[];
extern const char	*idnfinopt_str[];
extern const char	*idnreg_str[];
extern const char	*idnnack_str[];
extern const char	*idnop_str[];
extern const char	*idnsync_str[];
extern const char	*chanop_str[];
extern const char	*chanaction_str[];
extern const char	*inum_str[];
extern const int	inum_bump;
extern const int	inum_max;
extern const int	acknack_shift;

extern const char	*timer_str[];
extern const char	*res_str[];

#endif /* _KERNEL */
#endif /* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_IDN_H */
