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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/buf.h>
#include <sys/disp.h>
#include <sys/kmem.h>
/* #include <sys/ddi.h> */
/* #include <sys/sunddi.h> */
#include <sys/debug.h>

#include <sys/time.h>
#include <sys/pathname.h>
#include <sys/netconfig.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/clnt_soc.h>
#include <rpc/pmap_prot.h>	/* PMAPPORT */
#include <rpc/rpc.h>
#include <rpc/rpcb_prot.h>
#include <rpc/xdr.h>		/* This also gets us htonl() et al. */


#include <sys/lvm/mdmed.h>

#define	MDDB
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_crc.h>
#include <sys/callb.h>

/*
 * Flag to turn off the kernel RPC client delay code. This only takes effect
 * if the route to the remote node is marked as RTF_REJECT and the RPC path
 * manager has been flushed such that any 'old' path information is no longer
 * present.
 */
static	bool_t		clset = TRUE;

extern	int		md_nmedh;			/* declared in md.c */
extern	char		*md_med_trans_lst;
extern md_set_t		md_set[];			/* declared in md.c */

/*
 * Structures used only by mediators
 */
typedef	struct	med_thr_a_args {
	uint_t			mtaa_mag;
	char			*mtaa_h_nm;
	in_addr_t		mtaa_h_ip;
	uint_t			mtaa_h_flags;
	int			(*mtaa_err_func)(struct med_thr_a_args *);
	struct med_thr_h_args	*mtaa_mthap;
	int			mtaa_flags;
	rpcprog_t		mtaa_prog;
	rpcvers_t		mtaa_vers;
	rpcproc_t		mtaa_proc;
	xdrproc_t		mtaa_inproc;
	caddr_t			mtaa_in;
	xdrproc_t		mtaa_outproc;
	caddr_t			mtaa_out;
	struct	timeval		*mtaa_timout;
	int			mtaa_err;
} med_thr_a_args_t;

#define	MTAA_MAGIC		0xbadbabed
#define	MDT_A_OK		0x00000001

typedef	struct	med_thr_h_args {
	uint_t			mtha_mag;
	md_hi_t			*mtha_mhp;
	char			*mtha_setname;
	med_data_t		*mtha_meddp;
	struct	med_thr		*mtha_mtp;
	int			mtha_flags;
	set_t			mtha_setno;
	int			mtha_a_cnt;
	kcondvar_t		mtha_a_cv;
	kmutex_t		mtha_a_mx;
	uint_t			mtha_a_nthr;
	med_thr_a_args_t	mtha_a_args[MAX_HOST_ADDRS];
} med_thr_h_args_t;

#define	MTHA_MAGIC		0xbadbabee
#define	MDT_H_OK		0x00000001

typedef	struct	med_thr	{
	uint_t			mt_mag;
	kmutex_t		mt_mx;
	kcondvar_t		mt_cv;
	uint_t			mt_nthr;
	med_thr_h_args_t	*mt_h_args[MED_MAX_HOSTS];
} med_thr_t;

#define	MTH_MAGIC		0xbadbabef

#ifdef DEBUG

static	struct	timeval	btv;
static	struct	timeval	etv;

#define	DBGLVL_NONE	0x00000000
#define	DBGLVL_MAJOR	0x00000100
#define	DBGLVL_MINOR	0x00000200
#define	DBGLVL_MINUTE	0x00000400
#define	DBGLVL_TRIVIA	0x00000800
#define	DBGLVL_HIDEOUS	0x00001000

#define	DBGFLG_NONE		0x00000000
#define	DBGFLG_NOPANIC		0x00000001
#define	DBGFLG_LVLONLY		0x00000002
#define	DBGFLG_FIXWOULDPANIC	0x00000004

#define	DBGFLG_FLAGMASK		0x0000000F
#define	DBGFLG_LEVELMASK	~DBGFLG_FLAGMASK

#define	DEBUG_FLAGS	(md_medup_failure_dbg & DBGFLG_FLAGMASK)
#define	DEBUG_LEVEL	(md_medup_failure_dbg & DBGFLG_LEVELMASK)

#ifdef JEC
unsigned int md_medup_failure_dbg =	DBGLVL_MINOR | DBGFLG_NONE;
#else	/* ! JEC */
unsigned int md_medup_failure_dbg =	DBGLVL_NONE | DBGFLG_NONE;
#endif	/* JEC */

#define	DCALL(dbg_level, call)						\
	{								\
		if (DEBUG_LEVEL != DBGLVL_NONE) {			\
			if (DEBUG_FLAGS & DBGFLG_LVLONLY) {		\
				if (DEBUG_LEVEL & dbg_level) {		\
					call;				\
				}					\
			} else {					\
				if (dbg_level <= DEBUG_LEVEL) {		\
					call;				\
				}					\
			}						\
		}							\
	}

#define	DPRINTF(dbg_level, msg)		DCALL(dbg_level, printf msg)

#define	MAJOR(msg)			DPRINTF(DBGLVL_MAJOR, msg)
#define	MINOR(msg)			DPRINTF(DBGLVL_MINOR, msg)
#define	MINUTE(msg)			DPRINTF(DBGLVL_MINUTE, msg)
#define	TRIVIA(msg)			DPRINTF(DBGLVL_TRIVIA, msg)
#define	HIDEOUS(msg)			DPRINTF(DBGLVL_HIDEOUS, msg)
#define	BSTAMP				{ uniqtime(&btv); }

#define	ESTAMP(msg)							\
	{								\
		time_t	esec, eusec;					\
									\
		uniqtime(&etv);						\
									\
		eusec = etv.tv_usec - btv.tv_usec;			\
		esec = etv.tv_sec - btv.tv_sec;				\
		if (eusec < 0) {					\
			eusec += MICROSEC;				\
			esec--;						\
		}							\
		MINOR(("%s: sec=%ld, usec=%ld\n", msg, esec, eusec));	\
	}

#else	/* ! DEBUG */

#define	DCALL(ignored_dbg_level, ignored_routine)
#define	MAJOR(ignored)
#define	MINOR(ignored)
#define	MINUTE(ignored)
#define	TRIVIA(ignored)
#define	HIDEOUS(ignored)
#define	BSTAMP		{ }
#define	ESTAMP(msg)	{ }

#endif /* DEBUG */

static	int		md_med_protocol_retry = 2;
static	int		md_med_transdevs_set = 0;

/*
 * Definitions and declarations.
 */
kmutex_t		med_lck;

struct med_client {
	rpcprog_t prog;
	rpcvers_t vers;
	struct netbuf addr;	/* Address to this <prog,vers> */
	CLIENT *client;
};

/*
 * unrecoverable RPC status codes; cf. rfscall()
 */
#define	MED_IS_UNRECOVERABLE_RPC(s)	(((s) == RPC_AUTHERROR) || \
	((s) == RPC_CANTENCODEARGS) || \
	((s) == RPC_CANTDECODERES) || \
	((s) == RPC_VERSMISMATCH) || \
	((s) == RPC_PROCUNAVAIL) || \
	((s) == RPC_PROGUNAVAIL) || \
	((s) == RPC_PROGVERSMISMATCH) || \
	((s) == RPC_CANTDECODEARGS))

/*
 * When trying to contact a portmapper that doesn't speak the version we're
 * using, we should theoretically get back RPC_PROGVERSMISMATCH.
 * Unfortunately, some (all?) 4.x hosts return an accept_stat of
 * PROG_UNAVAIL, which gets mapped to RPC_PROGUNAVAIL, so we have to check
 * for that, too.
 */
#define	PMAP_WRONG_VERSION(s)	((s) == RPC_PROGVERSMISMATCH || \
	(s) == RPC_PROGUNAVAIL)

#define	NULLSTR(str)	(! (str) || *(str) == '\0'? "<null>" : (str))
#define	NULSTRING	""

/* Flags used in med_addr (netconfig) table */

#define	UAFLG_NONE		0x00000000
#define	UAFLG_SKIP		0x00000001
#define	UAFLG_ERROR		0x00000002
#define	UAFLG_RPCERROR		0x00000004
#define	UAFLG_LOOPBACK		0x00000008
#define	UAFLG_LOCKINIT		0x00000010

/*
 * most of this data is static.  The mutex protects the changable items:
 *	ua_flags
 */
static struct med_addr {
	struct knetconfig	ua_kn;
	char			*ua_devname;	/* const */
	char			*ua_netid;	/* const */
	uint_t			ua_flags;
	kmutex_t		ua_mutex;
} med_addr_tab[] =

/*
 * The order of the entries in this table is the order in
 * which we'll try to connect to the user-level daemon.
 * The final entry must have a NULL ua_devname.
 *
 * This is basically a tablified version of /etc/netconfig
 * (with additional entries for loopback TCP and UDP networks
 * that are missing from the user-level version.)
 */
{

/* loopback UDP */
	/* semantics	protofmly	proto,		dev_t */
{	{ NC_TPI_CLTS,	NC_INET,	NC_UDP,		NODEV },
	/* devname	netid		flags */
	"/dev/udp",	"udp-loopback",	UAFLG_LOOPBACK
},

/* UDP */
	/* semantics	protofmly	proto,		dev_t */
{	{ NC_TPI_CLTS,	NC_INET,	NC_UDP,		NODEV },
	/* devname	netid		flags */
	"/dev/udp",	"udp", 		UAFLG_NONE
},

/* loopback TCP */
	/* semantics	protofmly	proto,		dev_t */
{	{ NC_TPI_COTS_ORD, NC_INET,	NC_TCP,		NODEV },
	/* devname	netid		flags */
	"/dev/tcp",	"tcp-loopback",	UAFLG_LOOPBACK
},

/* TCP */
	/* semantics	protofmly	proto,		dev_t */
{	{ NC_TPI_COTS_ORD, NC_INET,	NC_TCP,		NODEV },
	/* devname	netid		flags */
	"/dev/tcp",	"tcp",		UAFLG_NONE
},

/* ticlts */
	/* semantics	protofmly	proto,		dev_t */
{	{ NC_TPI_CLTS,	NC_LOOPBACK,	NC_NOPROTO,	NODEV },
	/* devname	netid		flags */
	"/dev/ticlts",	"ticlts",	UAFLG_LOOPBACK
},

/* ticotsord */
	/* semantics	protofmly	proto,		dev_t */
{	{ NC_TPI_COTS_ORD, NC_LOOPBACK,	NC_NOPROTO,	NODEV },
	/* devname	  netid		flags */
	"/dev/ticotsord", "ticotsord",	UAFLG_LOOPBACK
},

/* ticots */
	/* semantics	protofmly	proto,		dev_t */
{	{ NC_TPI_COTS,	NC_LOOPBACK,	NC_NOPROTO,	NODEV },
	/* devname	netid		flags */
	"/dev/ticots",	"ticots",	UAFLG_LOOPBACK
}
};

/* The number of entries in the table */
int	med_addr_tab_nents = sizeof (med_addr_tab) / sizeof (med_addr_tab[0]);

/*
 * Private Functions
 */

/* A useful utility. */
static char *
med_dup(void *str, int len)
{
	char *s = (char *)kmem_zalloc(len, KM_SLEEP);

	if (s == NULL)
		return (NULL);

	bcopy(str, s, len);

	return (s);
}

/*
 * Utilities for manipulating netbuf's.
 * These utilities are the only knc_protofmly specific functions in the MED.
 */

/*
 * Utilities to patch a port number (for NC_INET protocols) or a
 *	port name (for NC_LOOPBACK) into a network address.
 */
static void
med_put_inet_port(struct netbuf *addr, ushort_t port)
{
	/*
	 * Easy - we always patch an unsigned short on top of an
	 * unsigned short.  No changes to addr's len or maxlen are
	 * necessary.
	 */
	/*LINTED*/
	((struct sockaddr_in *)(addr->buf))->sin_port = port;
}

static void
med_put_loopback_port(struct netbuf *addr, char *port)
{
	char *dot;
	char *newbuf;
	int newlen;

	/*
	 * We must make sure the addr has enough space for us,
	 * patch in `port', and then adjust addr's len and maxlen
	 * to reflect the change.
	 */
	if ((dot = strchr(addr->buf, '.')) == (char *)NULL) {
		TRIVIA(("put_loopb_port - malformed loopback addr %s\n",
		    addr->buf));
		return;
	}

	newlen = (int)((dot - addr->buf + 1) + strlen(port));
	if (newlen > addr->maxlen) {
		newbuf = (char *)kmem_zalloc((size_t)newlen, KM_SLEEP);
		(void) bcopy(addr->buf, newbuf, (size_t)addr->len);
		kmem_free(addr->buf, (size_t)addr->maxlen);
		addr->buf = newbuf;
		addr->len = addr->maxlen = (uint_t)newlen;
		dot = strchr(addr->buf, '.');
	} else {
		addr->len = newlen;
	}

	(void) strncpy(++dot, port, strlen(port));

}

/*
 * Make sure the given netbuf has a maxlen at least as big as the given
 * length.
 */
static void
grow_netbuf(struct netbuf *nb, size_t length)
{
	char *newbuf;

	if (nb->maxlen >= length)
		return;

	newbuf = kmem_zalloc(length, KM_SLEEP);
	bcopy(nb->buf, newbuf, (size_t)nb->len);
	kmem_free(nb->buf, (size_t)nb->maxlen);
	nb->buf = newbuf;
	nb->maxlen = (uint_t)length;
}

/*
 * Convert a loopback universal address to a loopback transport address.
 */
static void
loopb_u2t(const char *ua, struct netbuf *addr)
{
	size_t stringlen = strlen(ua) + 1;
	const char *univp;		/* ptr into universal addr */
	char *transp;			/* ptr into transport addr */

	/* Make sure the netbuf will be big enough. */
	if (addr->maxlen < stringlen) {
		grow_netbuf(addr, stringlen);
	}

	univp = ua;
	transp = addr->buf;
	while (*univp != NULL) {
		if (*univp == '\\' && *(univp+1) == '\\') {
			*transp = '\\';
			univp += 2;
		} else if (*univp == '\\') {
			/* octal character */
			*transp = (((*(univp+1) - '0') & 3) << 6) +
			    (((*(univp+2) - '0') & 7) << 3) +
			    ((*(univp+3) - '0') & 7);
			univp += 4;
		} else {
			*transp = *univp;
			univp++;
		}
		transp++;
	}

	addr->len = (uint_t)(transp - addr->buf);
	ASSERT(addr->len <= addr->maxlen);
}


/*
 * xdr_md_pmap
 *
 * Taken from libnsl/rpc/pmap_prot.c
 */
bool_t
xdr_md_pmap(xdrs, regs)
	XDR *xdrs;
	struct pmap *regs;
{
	if (xdr_u_int(xdrs, &regs->pm_prog) &&
		xdr_u_int(xdrs, &regs->pm_vers) &&
		xdr_u_int(xdrs, &regs->pm_prot))
		return (xdr_u_int(xdrs, &regs->pm_port));
	return (FALSE);
}

/*
 * We need an version of CLNT_DESTROY which also frees the auth structure.
 */
static void
med_clnt_destroy(CLIENT **clp)
{
	if (*clp) {
		if ((*clp)->cl_auth) {
			AUTH_DESTROY((*clp)->cl_auth);
			(*clp)->cl_auth = NULL;
		}
		CLNT_DESTROY(*clp);
		*clp = NULL;
	}
}

/*
 * Release this med_client entry.
 * Do also destroy the entry if there was an error != EINTR,
 * and mark the entry as not-valid, by setting time=0.
 */
static void
med_rel_client(struct med_client *medc, int error)
{
	TRIVIA(("rel_client - addr = (%p, %u %u)\n",
	    (void *) medc->addr.buf, medc->addr.len, medc->addr.maxlen));
	/*LINTED*/
	if (1 || error && error != EINTR) {
		TRIVIA(("rel_client - destroying addr = (%p, %u %u)\n",
		    (void *) medc->addr.buf, medc->addr.len,
		    medc->addr.maxlen));
		med_clnt_destroy(&medc->client);
		if (medc->addr.buf) {
			kmem_free(medc->addr.buf, medc->addr.maxlen);
			medc->addr.buf = NULL;
		}
	}
}

/*
 * Try to get the address for the desired service by using the old
 * portmapper protocol.  Ignores signals.
 *
 * Returns RPC_UNKNOWNPROTO if the request uses the loopback transport.
 * Use med_get_rpcb_addr instead.
 */
static enum clnt_stat
med_get_pmap_addr(
	struct	knetconfig	*kncfp,
	rpcprog_t		prog,
	rpcvers_t		vers,
	struct	netbuf		*addr
)
{
	ushort_t			port = 0;
	int			error;
	enum	clnt_stat	status;
	CLIENT			*client = NULL;
	struct	pmap		parms;
	struct	timeval		tmo;
	k_sigset_t		oldmask;
	k_sigset_t		newmask;

	/*
	 * Call rpcbind version 2 or earlier (SunOS portmapper, remote
	 * only) to get an address we can use in an RPC client handle.
	 * We simply obtain a port no. for <prog, vers> and plug it
	 * into `addr'.
	 */
	if (strcmp(kncfp->knc_protofmly, NC_INET) == 0) {
		med_put_inet_port(addr, htons(PMAPPORT));
	} else {
		TRIVIA(("get_pmap_addr - unsupported protofmly %s\n",
		    kncfp->knc_protofmly));
		status = RPC_UNKNOWNPROTO;
		goto out;
	}

	TRIVIA(("get_pmap_addr - semantics=%u, protofmly=%s, proto=%s\n",
	    kncfp->knc_semantics, kncfp->knc_protofmly, kncfp->knc_proto));

	/*
	 * Mask signals for the duration of the handle creation and
	 * RPC call.  This allows relatively normal operation with a
	 * signal already posted to our thread.
	 *
	 * Any further exit paths from this routine must restore
	 * the original signal mask.
	 */
	sigfillset(&newmask);
	sigreplace(&newmask, &oldmask);

	if ((error = clnt_tli_kcreate(kncfp, addr, PMAPPROG, PMAPVERS,
	    0, 0, kcred, &client)) != RPC_SUCCESS) {
		status = RPC_TLIERROR;
		sigreplace(&oldmask, (k_sigset_t *)NULL);
		MINUTE(("get_pmap_addr - kcreate() returned %d\n", error));
		goto out;
	}

	if (!CLNT_CONTROL(client, CLSET_NODELAYONERR, (char *)&clset)) {
		MINUTE(("get_pmap_addr - unable to set CLSET_NODELAYONERR\n"));
	}

	client->cl_auth = authkern_create();

	parms.pm_prog = prog;
	parms.pm_vers = vers;
	if (strcmp(kncfp->knc_proto, NC_TCP) == 0) {
		parms.pm_prot = IPPROTO_TCP;
	} else {
		parms.pm_prot = IPPROTO_UDP;
	}
	parms.pm_port = 0;
	tmo = md_med_pmap_timeout;

	if ((status = CLNT_CALL(client, PMAPPROC_GETPORT,
	    xdr_md_pmap, (char *)&parms,
	    xdr_u_short, (char *)&port,
	    tmo)) != RPC_SUCCESS) {
		sigreplace(&oldmask, (k_sigset_t *)NULL);
		MINUTE(("get_pmap_addr - CLNT_CALL(GETPORT) returned %d\n",
		    status));
		goto out;
	}

	sigreplace(&oldmask, (k_sigset_t *)NULL);

	/* A zero value of port indicates a mapping failure */
	if (port == 0) {
		status = RPC_PROGNOTREGISTERED;
		MINUTE(("get_pmap_addr - program not registered\n"));
		goto out;
	}

	TRIVIA(("get_pmap_addr - port=%d\n", port));
	med_put_inet_port(addr, ntohs(port));

out:
	if (client)
		med_clnt_destroy(&client);
	return (status);
}

/*
 * Try to get the address for the desired service by using the rpcbind
 * protocol.  Ignores signals.
 */
static enum clnt_stat
med_get_rpcb_addr(
	struct	knetconfig	*kncfp,
	rpcprog_t		prog,
	rpcvers_t		vers,
	struct	netbuf		 *addr
)
{
	int			error;
	char			*ua = NULL;
	enum	clnt_stat	status;
	RPCB			parms;
	struct	timeval		tmo;
	CLIENT			*client = NULL;
	k_sigset_t		oldmask;
	k_sigset_t		newmask;
	ushort_t			port;

	/*
	 * Call rpcbind (local or remote) to get an address we can use
	 * in an RPC client handle.
	 */
	tmo = md_med_pmap_timeout;
	parms.r_prog = prog;
	parms.r_vers = vers;
	parms.r_addr = parms.r_owner = "";

	if (strcmp(kncfp->knc_protofmly, NC_INET) == 0) {
		if (strcmp(kncfp->knc_proto, NC_TCP) == 0) {
			parms.r_netid = "tcp";
		} else {
			parms.r_netid = "udp";
		}
		med_put_inet_port(addr, htons(PMAPPORT));
	} else if (strcmp(kncfp->knc_protofmly, NC_LOOPBACK) == 0) {
		parms.r_netid = "ticlts";
		med_put_loopback_port(addr, "rpc");
		TRIVIA((
		    "get_rpcb_addr - semantics=%s, protofmly=%s, proto=%s\n",
		    (kncfp->knc_semantics == NC_TPI_CLTS ?
		    "NC_TPI_CLTS" : "?"),
		    kncfp->knc_protofmly, kncfp->knc_proto));
	} else {
		TRIVIA(("get_rpcb_addr - unsupported protofmly %s\n",
		    kncfp->knc_protofmly));
		status = RPC_UNKNOWNPROTO;
		goto out;
	}

	/*
	 * Mask signals for the duration of the handle creation and
	 * RPC calls.  This allows relatively normal operation with a
	 * signal already posted to our thread.
	 *
	 * Any further exit paths from this routine must restore
	 * the original signal mask.
	 */
	sigfillset(&newmask);
	sigreplace(&newmask, &oldmask);

	if ((error = clnt_tli_kcreate(kncfp, addr, RPCBPROG, RPCBVERS,
	    0, 0, kcred, &client)) != 0) {
		status = RPC_TLIERROR;
		sigreplace(&oldmask, (k_sigset_t *)NULL);
		MINUTE(("get_rpcb_addr - kcreate() returned %d\n", error));
		goto out;
	}

	if (!CLNT_CONTROL(client, CLSET_NODELAYONERR, (char *)&clset)) {
		MINUTE(("get_rpcb_addr - unable to set CLSET_NODELAYONERR\n"));
	}

	client->cl_auth = authkern_create();

	if ((status = CLNT_CALL(client, RPCBPROC_GETADDR,
	    xdr_rpcb, (char *)&parms, xdr_wrapstring, (char *)&ua,
	    tmo)) != RPC_SUCCESS) {
		sigreplace(&oldmask, (k_sigset_t *)NULL);
		MINUTE(("get_rpcb_addr - CLNT_CALL(GETADDR) returned %d\n",
		    status));
		goto out;
	}

	sigreplace(&oldmask, (k_sigset_t *)NULL);

	if (ua == NULL || *ua == NULL) {
		status = RPC_PROGNOTREGISTERED;
		MINUTE(("get_rpcb_addr - program not registered\n"));
		goto out;
	}

	/*
	 * Convert the universal address to the transport address.
	 * Theoretically, we should call the local rpcbind to translate
	 * from the universal address to the transport address, but it gets
	 * complicated (e.g., there's no direct way to tell rpcbind that we
	 * want an IP address instead of a loopback address).  Note that
	 * the transport address is potentially host-specific, so we can't
	 * just ask the remote rpcbind, because it might give us the wrong
	 * answer.
	 */
	if (strcmp(kncfp->knc_protofmly, NC_INET) == 0) {
		port = rpc_uaddr2port(AF_INET, ua);
		med_put_inet_port(addr, ntohs(port));
	} else if (strcmp(kncfp->knc_protofmly, NC_LOOPBACK) == 0) {
		loopb_u2t(ua, addr);
	} else {
		/* "can't happen" - should have been checked for above */
		cmn_err(CE_PANIC, "med_get_rpcb_addr: bad protocol family");
	}

out:
	if (client != NULL)
		med_clnt_destroy(&client);
	if (ua != NULL)
		xdr_free(xdr_wrapstring, (char *)&ua);
	return (status);
}

/*
 * Get the RPC client handle to talk to the service at addrp.
 * Returns:
 * RPC_SUCCESS		Success.
 * RPC_RPCBFAILURE	Couldn't talk to the remote portmapper (e.g.,
 * 			timeouts).
 * RPC_INTR		Caught a signal before we could successfully return.
 * RPC_TLIERROR		Couldn't initialize the handle after talking to the
 * 			remote portmapper (shouldn't happen).
 */
static enum clnt_stat
med_get_rpc_handle(
	struct	knetconfig	*kncfp,
	struct	netbuf		*addrp,
	rpcprog_t		prog,
	rpcvers_t		vers,
	CLIENT			**clientp
)
{
	enum	clnt_stat	status;
	k_sigset_t		oldmask;
	k_sigset_t		newmask;
	int			error;

	/*
	 * Try to get the address from either portmapper or rpcbind.
	 * We check for posted signals after trying and failing to
	 * contact the portmapper since it can take uncomfortably
	 * long for this entire procedure to time out.
	 */
	BSTAMP
	status = med_get_pmap_addr(kncfp, prog, vers, addrp);
	if (MED_IS_UNRECOVERABLE_RPC(status) && status != RPC_UNKNOWNPROTO &&
	    ! PMAP_WRONG_VERSION(status)) {
		status = RPC_RPCBFAILURE;
		goto bailout;
	}

	if (status == RPC_SUCCESS)
		ESTAMP("done OK med_get_pmap_addr")
	else
		ESTAMP("done Not OK med_get_pmap_addr")

	if (status != RPC_SUCCESS) {
		BSTAMP
		status = med_get_rpcb_addr(kncfp, prog, vers, addrp);
		if (status != RPC_SUCCESS) {
			ESTAMP("done Not OK med_get_rpcb_addr")
			MINOR((
		    "get_rpc_handle - can't contact portmapper or rpcbind\n"));
			status = RPC_RPCBFAILURE;
			goto bailout;
		}
	}
	ESTAMP("done OK med_get_rpcb_addr")

	med_clnt_destroy(clientp);

	/*
	 * Mask signals for the duration of the handle creation,
	 * allowing relatively normal operation with a signal
	 * already posted to our thread.
	 *
	 * Any further exit paths from this routine must restore
	 * the original signal mask.
	 */
	sigfillset(&newmask);
	sigreplace(&newmask, &oldmask);

	if ((error = clnt_tli_kcreate(kncfp, addrp, prog, vers,
	    0, 0, kcred, clientp)) != 0) {
		status = RPC_TLIERROR;
		sigreplace(&oldmask, (k_sigset_t *)NULL);
		MINUTE(("get_rpc_handle - kcreate(prog) returned %d\n", error));
		goto bailout;
	}

	if (!CLNT_CONTROL(*clientp, CLSET_NODELAYONERR, (char *)&clset)) {
		MINUTE(("get_rpc_handle - unable to set CLSET_NODELAYONERR\n"));
	}

	(*clientp)->cl_auth = authkern_create();

	sigreplace(&oldmask, (k_sigset_t *)NULL);

bailout:
	return (status);
}

/*
 * Return a med_client to the <prog,vers>.
 * The med_client found is marked as in_use.
 * It is the responsibility of the caller to release the med_client by
 * calling med_rel_client().
 *
 * Returns:
 * RPC_SUCCESS		Success.
 * RPC_CANTSEND		Temporarily cannot send.
 * RPC_TLIERROR		Unspecified TLI error.
 * RPC_UNKNOWNPROTO	kncfp is from an unrecognised protocol family.
 * RPC_PROGNOTREGISTERED The prog `prog' isn't registered on the server.
 * RPC_RPCBFAILURE	Couldn't contact portmapper on remote host.
 * Any unsuccessful return codes from CLNT_CALL().
 */
static enum clnt_stat
med_get_client(
	struct	knetconfig	*kncfp,
	struct	netbuf		*addrp,
	rpcprog_t		prog,
	rpcvers_t		vers,
	struct	med_client	**mcp
)
{
	struct	med_client	*med_clnt = NULL;
	enum	clnt_stat	status = RPC_SUCCESS;

	mutex_enter(&med_lck);

	/*
	 * Create an med_client
	 */
	med_clnt = kmem_zalloc(sizeof (*med_clnt), KM_SLEEP);
	med_clnt->client = NULL;
	med_clnt->prog = prog;
	med_clnt->vers = vers;
	med_clnt->addr.buf = med_dup(addrp->buf, addrp->maxlen);
	med_clnt->addr.len = addrp->len;
	med_clnt->addr.maxlen = addrp->maxlen;

	mutex_exit(&med_lck);

	status = med_get_rpc_handle(kncfp, &med_clnt->addr, prog, vers,
	    &med_clnt->client);

out:
	TRIVIA(("get_client - End: med_clnt=%p status=%d, client=%p\n",
	    (void *)med_clnt, status,
	    (med_clnt ? med_clnt->client : (void *) -1L)));

	if (status == RPC_SUCCESS) {
		*mcp = med_clnt;
	} else {
		/* Cleanup */
		if (med_clnt) {
			mutex_enter(&med_lck);
			med_rel_client(med_clnt, EINVAL);
			kmem_free(med_clnt, sizeof (*med_clnt));
			mutex_exit(&med_lck);
		}
		*mcp = NULL;
	}

	return (status);
}

/*
 * Make an RPC call to addr via config.
 *
 * Returns:
 * 0		Success.
 * EIO		Couldn't get client handle, timed out, or got unexpected
 *		RPC status within md_med_protocol_retry attempts.
 * EINVAL	Unrecoverable error in RPC call.  Causes client handle
 *		to be destroyed.
 * EINTR	RPC call was interrupted within md_med_protocol_retry attempts.
 */
static int
med_callrpc(
	struct	knetconfig	*kncfp,
	struct	netbuf		*addrp,
	rpcprog_t		prog,
	rpcvers_t		vers,
	rpcproc_t		proc,
	xdrproc_t		inproc,
	caddr_t			in,
	xdrproc_t		outproc,
	caddr_t			out,
	struct	timeval		*timout
)
{
	struct	med_client	*med_clnt = NULL;
	enum	clnt_stat	cl_stat;
	int			tries = md_med_protocol_retry;
	int			error;
	k_sigset_t		oldmask;
	k_sigset_t		newmask;

	MINUTE(("med_callrpc - Calling [%u, %u, %u]\n", prog, vers, proc));

	sigfillset(&newmask);

	while (tries--) {
		error = 0;
		cl_stat = med_get_client(kncfp, addrp, prog, vers, &med_clnt);
		if (MED_IS_UNRECOVERABLE_RPC(cl_stat)) {
			error = EINVAL;
			goto rel_client;
		} else if (cl_stat != RPC_SUCCESS) {
			error = EIO;
			continue;
		}

		ASSERT(med_clnt != NULL);
		ASSERT(med_clnt->client != NULL);

		sigreplace(&newmask, &oldmask);
		cl_stat = CLNT_CALL(med_clnt->client, proc, inproc, in,
		    outproc, out, *timout);
		sigreplace(&oldmask, (k_sigset_t *)NULL);

		switch (cl_stat) {
		case RPC_SUCCESS:
			/*
			 * Update the timestamp on the client cache entry.
			 */
			error = 0;
			break;

		case RPC_TIMEDOUT:
			MINOR(("med_callrpc - RPC_TIMEDOUT\n"));
			if (timout == 0) {
				/*
				 * We will always time out when timout == 0.
				 */
				error = 0;
				break;
			}
			/* FALLTHROUGH */
		case RPC_CANTSEND:
		case RPC_XPRTFAILED:
		default:
			if (MED_IS_UNRECOVERABLE_RPC(cl_stat)) {
				error = EINVAL;
			} else {
				error = EIO;
			}
		}

rel_client:
		MINOR(("med_callrpc - RPC cl_stat=%d error=%d\n",
		    cl_stat, error));
		if (med_clnt != NULL) {
			med_rel_client(med_clnt, error);
			kmem_free(med_clnt, sizeof (*med_clnt));
		}

		/*
		 * If EIO, loop else we're done.
		 */
		if (error != EIO) {
			break;
		}
	}

	MINUTE(("med_callrpc - End: error=%d, tries=%d\n", error, tries));

	return (error);
}

/*
 * Try various transports to get the rpc call through.
 */
static int
med_net_callrpc(
	char			*h_nm,
	in_addr_t		h_ip,
	uint_t			h_flags,
	rpcprog_t		prog,
	rpcvers_t		vers,
	rpcproc_t		proc,
	xdrproc_t		inproc,
	caddr_t			in,
	xdrproc_t		outproc,
	caddr_t			out,
	struct	timeval		*timout
)
{
	int			err;
	struct	med_addr	*uap;
	int			uapi;
	struct	netbuf		dst;
	int			done = 0;

	ASSERT(h_nm != NULL);
	ASSERT(h_ip != 0);

	/*
	 * Loop through our table of transports and try to get the data out.
	 */
	for (uapi = 0; uapi < med_addr_tab_nents && ! done; uapi++) {

		/* Shorthand */
		uap = &med_addr_tab[uapi];

		/*
		 * UAFLG_SKIP is used for debugging and by the protocol
		 * selection code.
		 */
		if (uap->ua_flags & UAFLG_SKIP) {
			MINUTE(("med_net_callrpc - %s - marked \"skip\"\n",
			    uap->ua_netid));
			continue;
		}

		/*
		 * If we are not talking to this host, we can skip all LOOPBACK
		 * transport options.
		 */
		if (! (h_flags & NMIP_F_LOCAL) &&
		    (uap->ua_flags & UAFLG_LOOPBACK))
			continue;

		if (uap->ua_flags & UAFLG_ERROR)
			continue;

		if (uap->ua_flags & UAFLG_RPCERROR)
			continue;

		/* Unknown protocol, skip it */
		if (! uap->ua_kn.knc_protofmly) {
			MINUTE(("med_net_callrpc - bad protofmly\n"));
			continue;
		}

		if (strcmp(uap->ua_kn.knc_protofmly, NC_LOOPBACK) == 0) {
			/*
			 * strlen("localhost.") is 10
			 */
			dst.len = dst.maxlen = 10;
			dst.buf = kmem_alloc(dst.len, KM_SLEEP);
			(void) strncpy(dst.buf, "localhost.", dst.len);
		} else if (strcmp(uap->ua_kn.knc_protofmly, NC_INET) == 0) {
			struct sockaddr_in	*s;

			/*
			 * If we have not allocated a buffer for an INET addrs
			 * or the buffer allocated will not contain an INET
			 * addr, allocate or re-allocate.
			 */
			dst.buf = kmem_zalloc(sizeof (struct sockaddr_in),
			    KM_SLEEP);
			dst.maxlen = sizeof (struct sockaddr_in);

			/* Short hand */
			/*LINTED*/
			s = (struct sockaddr_in *)dst.buf;

			/* Initialize the socket */
			if (uap->ua_flags & UAFLG_LOOPBACK)
				s->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			else
				s->sin_addr.s_addr = h_ip;
			s->sin_port = 0;
			s->sin_family = AF_INET;
		}

		dst.len = dst.maxlen;

		MINOR(("med_net_callrpc - Trying %s\n", uap->ua_netid));

		err = med_callrpc(&uap->ua_kn, &dst, prog, vers, proc, inproc,
		    in, outproc, out, timout);

		if (dst.buf) {
			kmem_free(dst.buf, dst.maxlen);
			dst.buf = NULL;
			dst.len = 0;
			dst.maxlen = 0;
		}

		if (err) {
			MINUTE(("med_net_callrpc - %s failed\n\n",
			    uap->ua_netid));
			continue;
		}

		MINUTE(("med_net_callrpc - %s OK\n\n", uap->ua_netid));
		done = 1;
	}

	/*
	 * Print a message if we could not reach a host.
	 */
	if (! done) {
		cmn_err(CE_WARN, "%s on host %s not responding", MED_SERVNAME,
		    h_nm);
		return (1);
	}

	return (0);
}

/*
 * Validate the mediator data
 */
static int
med_ok(set_t setno, med_data_t *meddp)
{
	/* Not initialized, or not a mediator data record */
	if (meddp->med_dat_mag != MED_DATA_MAGIC)
		goto fail;

	MINUTE(("Magic OK\n"));

	/* Mismatch in revisions */
	if (meddp->med_dat_rev != MED_DATA_REV)
		goto fail;

	MINUTE(("Revision OK\n"));

	/* Not for the right set, this is paranoid */
	if (setno != meddp->med_dat_sn)
		goto fail;

	MINUTE(("Setno OK\n"));

	/* The record checksum is not correct */
	if (crcchk(meddp, &meddp->med_dat_cks, sizeof (med_data_t), NULL))
		goto fail;

	MINUTE(("Mediator validated\n"));

	return (1);

fail:
	return (0);
}

static void
med_adl(med_data_lst_t **meddlpp, med_data_t *meddp)
{
	/*
	 * Run to the end of the list
	 */
	for (/* void */; (*meddlpp != NULL); meddlpp = &(*meddlpp)->mdl_nx)
		/* void */;

	*meddlpp = (med_data_lst_t *)kmem_zalloc(sizeof (med_data_lst_t),
	    KM_SLEEP);

	(*meddlpp)->mdl_med = (med_data_t *)med_dup(meddp, sizeof (med_data_t));
}

static void
mtaa_upd_init(med_thr_a_args_t *mtaap, med_thr_h_args_t *mthap)
{
	med_upd_data_args_t	*argsp;
	med_err_t		*resp;

	argsp = kmem_zalloc(sizeof (med_upd_data_args_t), KM_SLEEP);
	argsp->med.med_setno = mthap->mtha_setno;
	if (MD_MNSET_SETNO(argsp->med.med_setno)) {
		/*
		 * In MN diskset, use a generic nodename, multiowner, in the
		 * mediator record which allows any node to access mediator
		 * information.  MN diskset reconfig cycle forces consistent
		 * view of set/node/drive/mediator information across all nodes
		 * in the MN diskset.  This allows the relaxation of
		 * node name checking in rpc.metamedd for MN disksets.
		 */
		argsp->med.med_caller = md_strdup(MED_MN_CALLER);
	} else {
		argsp->med.med_caller = md_strdup(utsname.nodename);
	}
	argsp->med.med_setname = md_strdup(mthap->mtha_setname);
	argsp->med_data = *mthap->mtha_meddp;

	resp = kmem_zalloc(sizeof (med_err_t), KM_SLEEP);

	mtaap->mtaa_mag = MTAA_MAGIC;
	mtaap->mtaa_mthap = mthap;
	mtaap->mtaa_prog = MED_PROG;
	mtaap->mtaa_vers = MED_VERS;
	mtaap->mtaa_proc = MED_UPD_DATA;
	mtaap->mtaa_inproc = xdr_med_upd_data_args_t;
	mtaap->mtaa_in = (caddr_t)argsp;
	mtaap->mtaa_outproc = xdr_med_err_t;
	mtaap->mtaa_out = (caddr_t)resp;
	mtaap->mtaa_timout = (struct timeval *)&md_med_def_timeout;
}

static void
mtaa_upd_free(med_thr_a_args_t *mtaap)
{
	med_upd_data_args_t	*argsp = (med_upd_data_args_t *)mtaap->mtaa_in;
	med_err_t		*resp = (med_err_t *)mtaap->mtaa_out;

	freestr(argsp->med.med_caller);
	freestr(argsp->med.med_setname);
	kmem_free(argsp, sizeof (med_upd_data_args_t));

	if (mtaap->mtaa_flags & MDT_A_OK)
		xdr_free(mtaap->mtaa_outproc, mtaap->mtaa_out);

	kmem_free(resp, sizeof (med_err_t));
}

static int
mtaa_upd_err(med_thr_a_args_t *mtaap)
{
	/*LINTED*/
	med_err_t		*resp = (med_err_t *)mtaap->mtaa_out;

	if (resp->med_errno == MDE_MED_NOERROR) {
		MAJOR(("upd_med_hosts - %s - OK\n\n", mtaap->mtaa_h_nm));
		return (0);
	} else {
		MAJOR(("upd_med_hosts - %s - errno=%d\n\n", mtaap->mtaa_h_nm,
		    resp->med_errno));
		return (1);
	}
}

static void
mtaa_get_init(med_thr_a_args_t *mtaap, med_thr_h_args_t *mthap)
{
	med_args_t		*argsp;
	med_get_data_res_t	*resp;

	argsp = kmem_zalloc(sizeof (med_args_t), KM_SLEEP);
	argsp->med.med_setno = mthap->mtha_setno;
	if (MD_MNSET_SETNO(argsp->med.med_setno)) {
		/*
		 * In MN diskset, use a generic nodename, multiowner, in the
		 * mediator record which allows any node to access mediator
		 * information.  MN diskset reconfig cycle forces consistent
		 * view of set/node/drive/mediator information across all nodes
		 * in the MN diskset.  This allows the relaxation of
		 * node name checking in rpc.metamedd for MN disksets.
		 */
		argsp->med.med_caller = md_strdup(MED_MN_CALLER);
	} else {
		argsp->med.med_caller = md_strdup(utsname.nodename);
	}

	argsp->med.med_setname = md_strdup(mthap->mtha_setname);

	resp = kmem_zalloc(sizeof (med_get_data_res_t), KM_SLEEP);

	mtaap->mtaa_mag = MTAA_MAGIC;
	mtaap->mtaa_mthap = mthap;
	mtaap->mtaa_prog = MED_PROG;
	mtaap->mtaa_vers = MED_VERS;
	mtaap->mtaa_proc = MED_GET_DATA;
	mtaap->mtaa_inproc = xdr_med_args_t;
	mtaap->mtaa_in = (caddr_t)argsp;
	mtaap->mtaa_outproc = xdr_med_get_data_res_t;
	mtaap->mtaa_out = (caddr_t)resp;
	mtaap->mtaa_timout = (struct timeval *)&md_med_def_timeout;
}

static void
mtaa_get_free(med_thr_a_args_t *mtaap)
{
	/*LINTED*/
	med_args_t		*argsp = (med_args_t *)mtaap->mtaa_in;
	/*LINTED*/
	med_get_data_res_t	*resp = (med_get_data_res_t *)mtaap->mtaa_out;

	freestr(argsp->med.med_caller);
	freestr(argsp->med.med_setname);
	kmem_free(argsp, sizeof (med_args_t));

	if (mtaap->mtaa_flags & MDT_A_OK)
		xdr_free(mtaap->mtaa_outproc, mtaap->mtaa_out);

	kmem_free(resp, sizeof (med_get_data_res_t));
}

static int
mtaa_get_err(med_thr_a_args_t *mtaap)
{
	/*LINTED*/
	med_get_data_res_t	*resp = (med_get_data_res_t *)mtaap->mtaa_out;

	if (resp->med_status.med_errno == MDE_MED_NOERROR) {
		MAJOR(("get_med_host_data - %s - OK\n\n", mtaap->mtaa_h_nm));
		return (0);
	} else {
		MAJOR(("get_med_host_data - %s - errno=%d\n\n",
		    mtaap->mtaa_h_nm, resp->med_status.med_errno));
		return (1);
	}
}

static void
mtha_init(
	med_thr_t		*mtp,
	med_thr_h_args_t	*mthap,
	md_hi_t			*mhp,
	char			*setname,
	med_data_t		*meddp,
	set_t			setno,
	void			(*mtaa_init_func)(med_thr_a_args_t *,
				    med_thr_h_args_t *),
	int			(*mtaa_err_func)(med_thr_a_args_t *)
)
{
	int		j;

	mthap->mtha_mag		= MTHA_MAGIC;
	mthap->mtha_mtp 	= mtp;
	mthap->mtha_mhp 	= mhp;
	mthap->mtha_setname	= md_strdup(setname);
	if (meddp)
		mthap->mtha_meddp	= meddp;
	else
		mthap->mtha_meddp	= NULL;
	mthap->mtha_setno 	= setno;
	mthap->mtha_a_cnt 	= mhp->a_cnt;
	mthap->mtha_a_nthr	= 0;

	mutex_init(&mthap->mtha_a_mx, NULL, MUTEX_DEFAULT,
	    NULL);
	cv_init(&mthap->mtha_a_cv, NULL, CV_DEFAULT, NULL);

	j = MIN(mthap->mtha_a_cnt, MAX_HOST_ADDRS) - 1;
	for (; j >= 0; j--) {
		(*mtaa_init_func)(&mthap->mtha_a_args[j], mthap);
		mthap->mtha_a_args[j].mtaa_h_nm = mhp->a_nm[j];
		mthap->mtha_a_args[j].mtaa_h_ip = mhp->a_ip[j];
		mthap->mtha_a_args[j].mtaa_h_flags = mhp->a_flg;
		mthap->mtha_a_args[j].mtaa_err_func = mtaa_err_func;
	}
}

static void
mtha_free(
	med_thr_h_args_t	*mthap,
	void			(*mtaa_free_func)(med_thr_a_args_t *)
)
{
	int		j;

	freestr(mthap->mtha_setname);

	j = MIN(mthap->mtha_a_cnt, MAX_HOST_ADDRS) - 1;
	for (; j >= 0; j--)
		(*mtaa_free_func)(&mthap->mtha_a_args[j]);

	mutex_destroy(&mthap->mtha_a_mx);
	cv_destroy(&mthap->mtha_a_cv);
}

static void
med_a_thr(med_thr_a_args_t *mtaap)
{
	callb_cpr_t	cprinfo;

	/*
	 * Register cpr callback
	 */
	CALLB_CPR_INIT(&cprinfo, &mtaap->mtaa_mthap->mtha_a_mx,
	    callb_generic_cpr, "med_a_thr");

	mutex_enter(&mtaap->mtaa_mthap->mtha_a_mx);
	if (mtaap->mtaa_mthap->mtha_flags & MDT_H_OK)
		goto done;

	mutex_exit(&mtaap->mtaa_mthap->mtha_a_mx);

	mtaap->mtaa_err = med_net_callrpc(
	    mtaap->mtaa_h_nm, mtaap->mtaa_h_ip, mtaap->mtaa_h_flags,
	    mtaap->mtaa_prog, mtaap->mtaa_vers, mtaap->mtaa_proc,
	    mtaap->mtaa_inproc, mtaap->mtaa_in,
	    mtaap->mtaa_outproc, mtaap->mtaa_out,
	    mtaap->mtaa_timout);

	mutex_enter(&mtaap->mtaa_mthap->mtha_a_mx);

	if (mtaap->mtaa_err) {
		MAJOR(("med_net_callrpc(%u, %u, %u) - %s - failed\n\n",
		    mtaap->mtaa_prog, mtaap->mtaa_vers, mtaap->mtaa_proc,
		    mtaap->mtaa_h_nm));
		xdr_free(mtaap->mtaa_outproc, mtaap->mtaa_out);
	} else {
		if ((*mtaap->mtaa_err_func)(mtaap) == 0) {
			if (! (mtaap->mtaa_mthap->mtha_flags & MDT_H_OK)) {
				mtaap->mtaa_mthap->mtha_flags |= MDT_H_OK;
				mtaap->mtaa_flags |= MDT_A_OK;
			} else
				xdr_free(mtaap->mtaa_outproc, mtaap->mtaa_out);
		} else
			xdr_free(mtaap->mtaa_outproc, mtaap->mtaa_out);
	}

done:
	mtaap->mtaa_mthap->mtha_a_nthr--;
	cv_signal(&mtaap->mtaa_mthap->mtha_a_cv);

	/*
	 * CALLB_CPR_EXIT will do mutex_exit(&mtaap->mtaa_mthap->mtha_a_mx)
	 */
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

static void
med_h_thr(med_thr_h_args_t *mthap)
{
	int		j;
	callb_cpr_t	cprinfo;

	/*
	 * Register cpr callback
	 */
	CALLB_CPR_INIT(&cprinfo, &mthap->mtha_mtp->mt_mx, callb_generic_cpr,
	    "med_a_thr");
	/*
	 * Lock mthap->mtha_mtp->mt_mx is held early to avoid releasing the
	 * locks out of order.
	 */
	mutex_enter(&mthap->mtha_mtp->mt_mx);
	mutex_enter(&mthap->mtha_a_mx);

	j = MIN(mthap->mtha_a_cnt, MAX_HOST_ADDRS) - 1;
	for (; j >= 0; j--) {
		(void) thread_create(NULL, 0, med_a_thr,
		    &mthap->mtha_a_args[j], 0, &p0, TS_RUN, minclsyspri);
		mthap->mtha_a_nthr++;
	}

	/*
	 * cpr safe to suspend while waiting for other threads
	 */
	CALLB_CPR_SAFE_BEGIN(&cprinfo);
	while (mthap->mtha_a_nthr > 0)
		cv_wait(&mthap->mtha_a_cv, &mthap->mtha_a_mx);
	mutex_exit(&mthap->mtha_a_mx);
	CALLB_CPR_SAFE_END(&cprinfo, &mthap->mtha_mtp->mt_mx);


	mthap->mtha_mtp->mt_nthr--;
	cv_signal(&mthap->mtha_mtp->mt_cv);

	/*
	 * set up cpr exit
	 * CALLB_CPR_EXIT will do mutex_exit(&mtaap->mta_mtp->mt_mx)
	 */
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

static med_get_data_res_t *
mtaa_get_resp(med_thr_h_args_t *mthap)
{
	med_thr_a_args_t	*mtaap;
	int			j;

	j = MIN(mthap->mtha_a_cnt, MAX_HOST_ADDRS) - 1;
	for (; j >= 0; j--) {
		mtaap = &mthap->mtha_a_args[j];
		if (mtaap->mtaa_flags & MDT_A_OK)
			/*LINTED*/
			return ((med_get_data_res_t *)mtaap->mtaa_out);
	}
	return ((med_get_data_res_t *)NULL);
}

/*
 * Public Functions
 */

/*
 * initializes med structs, locks, etc
 */
void
med_init(void)
{
	int		uapi;

	TRIVIA(("[med_init"));

	for (uapi = 0; uapi < med_addr_tab_nents; uapi++) {
		struct	med_addr	*uap = &med_addr_tab[uapi];

		/* If the protocol is skipped, the mutex is not needed either */
		if (md_med_trans_lst != NULL &&
		    strstr(md_med_trans_lst, uap->ua_kn.knc_proto) == NULL &&
		    strstr(md_med_trans_lst, uap->ua_netid) == NULL) {
			uap->ua_flags |= UAFLG_SKIP;
			continue;
		}

		mutex_init(&uap->ua_mutex, NULL, MUTEX_DEFAULT, NULL);
		uap->ua_flags |= UAFLG_LOCKINIT;
		bzero((caddr_t)&uap->ua_kn.knc_unused,
		    sizeof (uap->ua_kn.knc_unused));
	}

	TRIVIA(("]\n"));
}

/*
 * free any med structs, locks, etc
 */
void
med_fini(void)
{
	int	uapi;

	TRIVIA(("[med_fini"));

	for (uapi = 0; uapi < med_addr_tab_nents; uapi++) {
		struct med_addr *uap = &med_addr_tab[uapi];

		if (uap->ua_flags & UAFLG_LOCKINIT) {
			mutex_destroy(&uap->ua_mutex);
			uap->ua_flags &= ~UAFLG_LOCKINIT;
		}
	}

	TRIVIA(("]\n"));
}

/*
 * Update all the mediators
 */
int
upd_med_hosts(
	md_hi_arr_t		*mp,
	char			*setname,
	med_data_t		*meddp,
	char			*caller
)
{
	med_thr_t		*mtp;
	med_thr_h_args_t	*mthap;
	int			i;
	int			medok = 0;

	MAJOR(("upd_med_hosts - called from <%s>\n", NULLSTR(caller)));

	/* No mediators, were done */
	if (mp->n_cnt == 0)
		return (0);

	mtp = kmem_zalloc(sizeof (med_thr_t), KM_SLEEP);
	ASSERT(mtp != NULL);

	mutex_init(&mtp->mt_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&mtp->mt_cv, NULL, CV_DEFAULT, NULL);
	mtp->mt_mag = MTH_MAGIC;

	mutex_enter(&mtp->mt_mx);

	mtp->mt_nthr = 0;

	/* Loop through our list of mediator hosts, start a thread per host */
	for (i = 0; i < md_nmedh; i++) {

		if (mp->n_lst[i].a_cnt == 0)
			continue;

		mtp->mt_h_args[i] = kmem_zalloc(sizeof (med_thr_h_args_t),
		    KM_SLEEP);
		mthap = mtp->mt_h_args[i];
		ASSERT(mthap != NULL);
		mtha_init(mtp, mthap, &mp->n_lst[i], setname, meddp,
		    meddp->med_dat_sn, mtaa_upd_init, mtaa_upd_err);

		MAJOR(("upd_med_hosts - updating %s\n",
		    NULLSTR(mp->n_lst[i].a_nm[0])));

		(void) thread_create(NULL, 0, med_h_thr, mthap, 0, &p0,
		    TS_RUN, minclsyspri);

		mtp->mt_nthr++;
	}

	while (mtp->mt_nthr > 0)
		cv_wait(&mtp->mt_cv, &mtp->mt_mx);

	mutex_exit(&mtp->mt_mx);

	for (i = 0; i < md_nmedh; i++) {
		mthap = mtp->mt_h_args[i];
		if (mthap != NULL) {
			if (mthap->mtha_flags & MDT_H_OK)
				medok++;
			mtha_free(mthap, mtaa_upd_free);
			kmem_free(mthap, sizeof (med_thr_h_args_t));
		}
	}

	mutex_destroy(&mtp->mt_mx);
	cv_destroy(&mtp->mt_cv);

	kmem_free(mtp, sizeof (med_thr_t));

	return (medok);
}

/*
 * Get the mediator data.
 */
med_data_lst_t *
get_med_host_data(
	md_hi_arr_t		*mp,
	char			*setname,
	set_t			setno
)
{
	med_thr_t		*mtp;
	med_thr_h_args_t	*mthap;
	med_get_data_res_t	*resp;
	med_data_lst_t		*retval = NULL;
	int			i;

	/* No mediators, were done */
	if (mp->n_cnt == 0)
		return (NULL);

	mtp = kmem_zalloc(sizeof (med_thr_t), KM_SLEEP);
	ASSERT(mtp != NULL);

	mutex_init(&mtp->mt_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&mtp->mt_cv, NULL, CV_DEFAULT, NULL);

	mutex_enter(&mtp->mt_mx);

	mtp->mt_nthr = 0;

	/* Loop through our list of mediator hosts, start a thread per host */
	for (i = 0; i < md_nmedh; i++) {

		if (mp->n_lst[i].a_cnt == 0)
			continue;

		mtp->mt_h_args[i] = kmem_zalloc(sizeof (med_thr_h_args_t),
		    KM_SLEEP);
		mthap = mtp->mt_h_args[i];
		ASSERT(mthap != NULL);
		mtha_init(mtp, mthap, &mp->n_lst[i], setname, NULL, setno,
		    mtaa_get_init, mtaa_get_err);

		MAJOR(("get_med_host_data from %s\n",
		    NULLSTR(mp->n_lst[i].a_nm[0])));

		(void) thread_create(NULL, 0, med_h_thr, mthap, 0, &p0,
		    TS_RUN, minclsyspri);

		mtp->mt_nthr++;
	}

	while (mtp->mt_nthr > 0)
		cv_wait(&mtp->mt_cv, &mtp->mt_mx);

	mutex_exit(&mtp->mt_mx);

	for (i = 0; i < md_nmedh; i++) {
		mthap = mtp->mt_h_args[i];
		if (mthap != NULL) {
			if (mthap->mtha_flags & MDT_H_OK) {
				resp = mtaa_get_resp(mthap);
				ASSERT(resp != NULL);

				if (med_ok(setno, &resp->med_data))
					med_adl(&retval, &resp->med_data);
			}
			mtha_free(mthap, mtaa_get_free);
			kmem_free(mthap, sizeof (med_thr_h_args_t));
		}
	}

	mutex_destroy(&mtp->mt_mx);
	cv_destroy(&mtp->mt_cv);

	kmem_free(mtp, sizeof (med_thr_t));

	return (retval);
}

int
med_get_t_size_ioctl(mddb_med_t_parm_t *tpp, int mode)
{
	md_error_t	*ep = &tpp->med_tp_mde;

	mdclrerror(ep);

	if ((mode & FREAD) == 0)
		return (mdsyserror(ep, EACCES));

	tpp->med_tp_nents = med_addr_tab_nents;
	tpp->med_tp_setup = md_med_transdevs_set;

	return (0);
}

int
med_get_t_ioctl(mddb_med_t_parm_t *tpp, int mode)
{
	md_error_t	*ep = &tpp->med_tp_mde;
	int		uapi = 0;

	mdclrerror(ep);

	if ((mode & FREAD) == 0)
		return (mdsyserror(ep, EACCES));

	for (uapi = 0; uapi < med_addr_tab_nents; uapi++) {
		struct	med_addr	*uap = &med_addr_tab[uapi];

		(void) strncpy(tpp->med_tp_ents[uapi].med_te_nm,
		    uap->ua_devname, MED_TE_NM_LEN);
		tpp->med_tp_ents[uapi].med_te_dev =
		    (md_dev64_t)uap->ua_kn.knc_rdev;
	}

	tpp->med_tp_nents = med_addr_tab_nents;

	return (0);
}

int
med_set_t_ioctl(mddb_med_t_parm_t *tpp, int mode)
{
	md_error_t	*ep = &tpp->med_tp_mde;
	int		uapi = 0;

	mdclrerror(ep);

	if ((mode & FWRITE) == 0)
		return (mdsyserror(ep, EACCES));

	for (uapi = 0; uapi < med_addr_tab_nents; uapi++) {
		struct	med_addr	*uap = &med_addr_tab[uapi];

		mutex_enter(&uap->ua_mutex);
		uap->ua_kn.knc_rdev = md_dev64_to_dev(
		    tpp->med_tp_ents[uapi].med_te_dev);
		mutex_exit(&uap->ua_mutex);
	}

	md_med_transdevs_set = 1;

	return (0);
}
