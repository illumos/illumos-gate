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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/debug.h>
#include <sys/tiuser.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/t_kuser.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/netconfig.h>
#include <sys/ethernet.h>
#include <sys/dlpi.h>
#include <sys/vfs.h>
#include <sys/sysmacros.h>
#include <sys/bootconf.h>
#include <sys/bootprops.h>
#include <sys/cmn_err.h>
#include <sys/promif.h>
#include <sys/mount.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/arp.h>
#include <netinet/dhcp.h>
#include <netinet/inetutil.h>
#include <dhcp_impl.h>
#include <sys/sunos_dhcp_class.h>

#include <rpc/types.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/pmap_clnt.h>
#include <rpc/pmap_rmt.h>
#include <rpc/pmap_prot.h>
#include <rpc/bootparam.h>
#include <rpc/rpcb_prot.h>

#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/nfs_clnt.h>
#include <nfs/mount.h>
#include <sys/mntent.h>

#include <sys/kstr.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/esunddi.h>

#include <sys/errno.h>
#include <sys/modctl.h>

/*
 * RPC timers and retries
 */
#define	PMAP_RETRIES	5
#define	DEFAULT_RETRIES	3
#define	GETFILE_RETRIES	2

#define	DEFAULT_TIMEO	3
#define	WHOAMI_TIMEO	20
#define	REVARP_TIMEO	5
#define	GETFILE_TIMEO	1

/*
 * These are from the rpcgen'd version of mount.h XXX
 */
#define	MOUNTPROG 100005
#define	MOUNTPROC_MNT		1
#define	MOUNTVERS		1
#define	MOUNTVERS_POSIX		2
#define	MOUNTVERS3		3

struct fhstatus {
	int fhs_status;
	fhandle_t fhs_fh;
};

#define	FHSIZE3 64

struct fhandle3 {
	uint_t fhandle3_len;
	char *fhandle3_val;
};

enum mountstat3 {
	MNT_OK = 0,
	MNT3ERR_PERM = 1,
	MNT3ERR_NOENT = 2,
	MNT3ERR_IO = 5,
	MNT3ERR_ACCES = 13,
	MNT3ERR_NOTDIR = 20,
	MNT3ERR_INVAL = 22,
	MNT3ERR_NAMETOOLONG = 63,
	MNT3ERR_NOTSUPP = 10004,
	MNT3ERR_SERVERFAULT = 10006
};

struct mountres3_ok {
	struct fhandle3 fhandle;
	struct {
		uint_t auth_flavors_len;
		int *auth_flavors_val;
	} auth_flavors;
};

struct mountres3 {
	enum mountstat3 fhs_status;
	union {
		struct mountres3_ok mountinfo;
	} mountres3_u;
};

/*
 * DLPI address format.
 */
struct	dladdr {
	uchar_t		dl_phys[6];
	ushort_t	dl_sap;
};

static struct modlmisc modlmisc = {
	&mod_miscops, "Boot diskless"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static int	dldebug;

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static enum clnt_stat	pmap_rmt_call(struct knetconfig *, struct netbuf *,
			    bool_t, rpcprog_t, rpcvers_t, rpcproc_t, xdrproc_t,
			    caddr_t, xdrproc_t, caddr_t, struct timeval,
			    struct netbuf *);
static bool_t		myxdr_rmtcall_args(XDR *, struct rmtcallargs *);
static bool_t		myxdr_rmtcallres(XDR *, struct rmtcallres *);
static bool_t		myxdr_pmap(XDR *, struct pmap *);
static bool_t		myxdr_fhstatus(XDR *xdrs, struct fhstatus *fhsp);
static bool_t		myxdr_fhandle(XDR *xdrs, fhandle_t *fh);
static bool_t		myxdr_mountres3(XDR *xdrs, struct mountres3 *objp);
static bool_t		myxdr_mountstat3(XDR *xdrs, enum mountstat3 *objp);
static bool_t		myxdr_mountres3_ok(XDR *xdrs,
			    struct mountres3_ok *objp);
static bool_t		myxdr_fhandle3(XDR *xdrs, struct fhandle3 *objp);
static enum clnt_stat	pmap_kgetport(struct knetconfig *, struct netbuf *,
			    rpcprog_t, rpcvers_t, rpcprot_t);
static enum clnt_stat	mycallrpc(struct knetconfig *, struct netbuf *,
			    rpcprog_t, rpcvers_t, rpcproc_t, xdrproc_t,
			    char *, xdrproc_t, char *, int, int);
static int		ifioctl(TIUSER *, int, struct netbuf *);
static int		getfile(char *, char *, struct netbuf *, char *);
static int		ping_prog(struct netbuf *, uint_t prog, uint_t vers,
			    int proto, enum clnt_stat *);
static int		mountnfs(struct netbuf *, char *, char *,
			    fhandle_t *, int *);
static int		mountnfs3(struct netbuf *, char *, char *,
			    nfs_fh3 *, int *);
static int		init_mountopts(struct nfs_args *, int,
			    struct knetconfig **, int *);
static int		revarp_myaddr(TIUSER *);
static void		revarp_start(ldi_handle_t, struct netbuf *);
static void		revarpinput(ldi_handle_t, struct netbuf *);
static void		init_netbuf(struct netbuf *);
static void		free_netbuf(struct netbuf *);
static int		rtioctl(TIUSER *, int, struct rtentry *);
static void		init_config(void);

static void		cacheinit(void);
static int		cacheinfo(char *, int, struct netbuf *, char *, int);
static int		dlifconfig(TIUSER *, struct in_addr *, struct in_addr *,
			    struct in_addr *, uint_t);
static int		setifflags(TIUSER *, uint_t);

static char		*inet_ntoa(struct in_addr);
static int		inet_aton(char *, uchar_t *);
static int		isdigit(int);

/*
 * Should be in some common
 * ethernet source file.
 */
static struct ether_addr etherbroadcastaddr = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static struct ether_addr myether;

/*
 * "ifname" is the interface name/unit as read from the boot
 * arguments.
 * "ndev" is the major device number of the network interface
 * used to boot from.
 * "ifunit" it the physical point of attachment for the network
 * interface used to boot from.
 *
 * Both of these are initialized in "init_config()".
 */

static char	ifname[IFNAMSIZ];
static char	ndev_path[MAXPATHLEN];
static int	ifunit;

/*
 * XXX these should be shared
 */
static struct knetconfig dl_udp_netconf = {
	NC_TPI_CLTS,			/* semantics */
	NC_INET,			/* family */
	NC_UDP,				/* protocol */
	0,				/* device */
};

static struct knetconfig dl_tcp_netconf = {
	NC_TPI_COTS,			/* semantics */
	NC_INET,			/* family */
	NC_TCP,				/* protocol */
	0,				/* device */
};

/* parameters from DHCP or bootparamd */
static PKT_LIST	*pl = NULL;
static uchar_t server_ip[4];
static uchar_t dhcp_server_ip[4];
static char *server_name_c, *server_path_c;
static char rootopts[256];

/*
 * XXX Until we get the nfsmapid deadlocks all fixed, don't allow
 * XXX a v4 root mount.
 */
int nfs4_no_diskless_root_support = 1;

int
mount_root(char *name, char *path, int version, struct nfs_args *args,
    int *vfsflags)
{
	int rc;
	int proto;
	struct knetconfig *dl_cf;
	static int init_done = 0;
	enum clnt_stat stat;

	if (dldebug)
		printf("mount_root: name=%s\n", name);

	if (init_done == 0) {
		init_config();
		init_done = 1;
	}

	init_netbuf(args->addr);

	do {
		rc = getfile(name, args->hostname, args->addr, path);
	} while (rc == ETIMEDOUT);

	if (rc) {
		free_netbuf(args->addr);
		return (rc);
	}

	ASSERT(args->knconf->knc_protofmly != NULL);
	ASSERT(args->knconf->knc_proto != NULL);

	switch (version) {
	case NFS_VERSION:
		rc = mountnfs(args->addr, args->hostname, path,
		    (fhandle_t *)args->fh, &proto);
		break;
	case NFS_V3:
		rc = mountnfs3(args->addr, args->hostname, path,
		    (nfs_fh3 *)args->fh, &proto);
		break;
	case NFS_V4:
		((struct sockaddr_in *)args->addr->buf)->sin_port =
		    htons(NFS_PORT);
		if (ping_prog(args->addr, NFS_PROGRAM, NFS_V4, IPPROTO_TCP,
		    &stat)) {
			proto = IPPROTO_TCP;
			rc = 0;
		} else {
			switch (stat) {
			case RPC_PROGVERSMISMATCH:
			case RPC_XPRTFAILED:
				/*
				 * Common failures if v4 unsupported or no TCP
				 */
				rc = EPROTONOSUPPORT;
				break;
			default:
				rc = ENXIO;
			}
		}
		if (nfs4_no_diskless_root_support)
			rc = EPROTONOSUPPORT;
		break;
	default:
		rc = EPROTONOSUPPORT;
		break;
	}

	if (rc)
		goto errout;

	switch (proto) {
	case IPPROTO_TCP:
		dl_cf = &dl_tcp_netconf;
		break;
	case IPPROTO_UDP:
	default:
		dl_cf = &dl_udp_netconf;
		break;
	}

	rc = init_mountopts(args, version, &dl_cf, vfsflags);

	/*
	 * Copy knetconfig information from the template, note that the
	 * rdev field has been set by init_config above.
	 */
	args->knconf->knc_semantics = dl_cf->knc_semantics;
	args->knconf->knc_rdev = dl_cf->knc_rdev;
	(void) strcpy(args->knconf->knc_protofmly, dl_cf->knc_protofmly);
	(void) strcpy(args->knconf->knc_proto, dl_cf->knc_proto);

errout:
	if (dldebug) {
		if (rc)
			nfs_perror(rc, "mount_root: mount %s:%s failed: %m\n",
			    args->hostname, path);
		else
			printf("mount_root: leaving\n");
	}

	return (rc);
}

/*
 * Call mount daemon on server `sa' to mount path.
 * `port' is set to nfs port and fh is the fhandle
 * returned from the server.
 */
static int
mountnfs(struct netbuf *sa, char *server,
    char *path, fhandle_t *fh, int *proto)
{
	struct fhstatus fhs;
	enum clnt_stat stat;

	if (dldebug)
		printf("mountnfs: entered\n");

	/*
	 * Get the port number for the mount program.
	 * pmap_kgetport first tries a SunOS portmapper
	 * and, if no reply is received, will try a
	 * SVR4 rpcbind. Either way, `sa' is set to
	 * the correct address.
	 */
	do {
		stat = pmap_kgetport(&dl_udp_netconf, sa, (rpcprog_t)MOUNTPROG,
		    (rpcvers_t)MOUNTVERS, (rpcprot_t)IPPROTO_UDP);

		if (stat == RPC_TIMEDOUT) {
			cmn_err(CE_WARN,
			    "mountnfs: %s:%s portmap not responding",
			    server, path);
		} else if (stat != RPC_SUCCESS) {
			cmn_err(CE_WARN,
			    "mountnfs: pmap_kgetport RPC error %d (%s).",
			    stat, clnt_sperrno(stat));
			return (ENXIO);	/* XXX */
		}
	} while (stat == RPC_TIMEDOUT);

	/*
	 * The correct port number has been
	 * put into `sa' by pmap_kgetport().
	 */
	do {
		stat = mycallrpc(&dl_udp_netconf, sa, (rpcprog_t)MOUNTPROG,
		    (rpcvers_t)MOUNTVERS, (rpcproc_t)MOUNTPROC_MNT,
		    xdr_bp_path_t, (char *)&path,
		    myxdr_fhstatus, (char *)&fhs,
		    DEFAULT_TIMEO, DEFAULT_RETRIES);
		if (stat == RPC_TIMEDOUT) {
			cmn_err(CE_WARN,
			    "mountnfs: %s:%s mount server not responding",
			    server, path);
		}
	} while (stat == RPC_TIMEDOUT);

	if (stat != RPC_SUCCESS) {
		cmn_err(CE_WARN, "mountnfs: RPC failed: error %d (%s).",
		    stat, clnt_sperrno(stat));
		return (ENXIO);	/* XXX */
	}

	((struct sockaddr_in *)sa->buf)->sin_port = htons(NFS_PORT);

	*fh = fhs.fhs_fh;
	if (fhs.fhs_status != 0) {
		if (dldebug)
			printf("mountnfs: fhs_status %d\n", fhs.fhs_status);
		return (ENXIO);		/* XXX */
	}

	*proto = IPPROTO_UDP;

	if (ping_prog(sa, NFS_PROGRAM, NFS_VERSION, IPPROTO_TCP, NULL))
		*proto = IPPROTO_TCP;

	if (dldebug)
		printf("mountnfs: leaving\n");
	return (0);
}

/*
 * Call mount daemon on server `sa' to mount path.
 * `port' is set to nfs port and fh is the fhandle
 * returned from the server.
 */
static int
mountnfs3(struct netbuf *sa, char *server,
    char *path, nfs_fh3 *fh, int *proto)
{
	struct mountres3 mountres3;
	enum clnt_stat stat;
	int ret = 0;

	if (dldebug)
		printf("mountnfs3: entered\n");

	/*
	 * Get the port number for the mount program.
	 * pmap_kgetport first tries a SunOS portmapper
	 * and, if no reply is received, will try a
	 * SVR4 rpcbind. Either way, `sa' is set to
	 * the correct address.
	 */
	do {
		stat = pmap_kgetport(&dl_udp_netconf, sa, (rpcprog_t)MOUNTPROG,
		    (rpcvers_t)MOUNTVERS3, (rpcprot_t)IPPROTO_UDP);

		if (stat == RPC_PROGVERSMISMATCH) {
			if (dldebug)
				printf("mountnfs3: program/version mismatch\n");
			return (EPROTONOSUPPORT); /* XXX */
		} else if (stat == RPC_TIMEDOUT) {
			cmn_err(CE_WARN,
			    "mountnfs3: %s:%s portmap not responding",
			    server, path);
		} else if (stat != RPC_SUCCESS) {
			cmn_err(CE_WARN,
			    "mountnfs3: pmap_kgetport RPC error %d (%s).",
			    stat, clnt_sperrno(stat));
			return (ENXIO);	/* XXX */
		}
	} while (stat == RPC_TIMEDOUT);

	mountres3.mountres3_u.mountinfo.fhandle.fhandle3_val = NULL;
	mountres3.mountres3_u.mountinfo.auth_flavors.auth_flavors_val = NULL;

	/*
	 * The correct port number has been
	 * put into `sa' by pmap_kgetport().
	 */
	do {
		stat = mycallrpc(&dl_udp_netconf, sa, (rpcprog_t)MOUNTPROG,
		    (rpcvers_t)MOUNTVERS3, (rpcproc_t)MOUNTPROC_MNT,
		    xdr_bp_path_t, (char *)&path,
		    myxdr_mountres3, (char *)&mountres3,
		    DEFAULT_TIMEO, DEFAULT_RETRIES);
		if (stat == RPC_TIMEDOUT) {
			cmn_err(CE_WARN,
			    "mountnfs3: %s:%s mount server not responding",
			    server, path);
		}
	} while (stat == RPC_TIMEDOUT);

	if (stat == RPC_PROGVERSMISMATCH) {
		if (dldebug)
			printf("mountnfs3: program/version mismatch\n");
		ret = EPROTONOSUPPORT;
		goto out;
	}
	if (stat != RPC_SUCCESS) {
		cmn_err(CE_WARN, "mountnfs3: RPC failed: error %d (%s).",
		    stat, clnt_sperrno(stat));
		ret = ENXIO;	/* XXX */
		goto out;
	}

	if (mountres3.fhs_status != MNT_OK) {
		if (dldebug)
			printf("mountnfs3: fhs_status %d\n",
			    mountres3.fhs_status);
		ret = ENXIO;	/* XXX */
		goto out;
	}

	((struct sockaddr_in *)sa->buf)->sin_port = htons(NFS_PORT);

	*proto = IPPROTO_UDP;

	if (ping_prog(sa, NFS_PROGRAM, NFS_V3, IPPROTO_TCP, NULL)) {
		*proto = IPPROTO_TCP;
	}

	fh->fh3_length = mountres3.mountres3_u.mountinfo.fhandle.fhandle3_len;
	bcopy(mountres3.mountres3_u.mountinfo.fhandle.fhandle3_val,
	    fh->fh3_u.data, fh->fh3_length);

out:
	xdr_free(myxdr_mountres3, (caddr_t)&mountres3);

	if (dldebug)
		printf("mountnfs3: leaving\n");
	return (ret);
}

static int
ping_prog(struct netbuf *call_addr, uint_t prog, uint_t vers, int proto,
    enum clnt_stat *statp)
{
	struct knetconfig *knconf;
	enum clnt_stat stat;
	int retries = DEFAULT_RETRIES;

	switch (proto) {
	case IPPROTO_TCP:
		knconf = &dl_tcp_netconf;
		break;
	case IPPROTO_UDP:
		knconf = &dl_udp_netconf;
		break;
	default:
		return (0);
	}

	do {
		stat = mycallrpc(knconf, call_addr, prog, vers, NULLPROC,
		    xdr_void, NULL, xdr_void, NULL,
		    DEFAULT_TIMEO, DEFAULT_RETRIES);

		if (dldebug)
			printf("ping_prog: %d return %d (%s)\n", proto, stat,
			    clnt_sperrno(stat));
		/*
		 * Special case for TCP, it may "timeout" because it failed
		 * to establish an initial connection but it doesn't
		 * actually retry, so we do the retry.
		 * Persistence pays in diskless.
		 */
	} while (stat == RPC_TIMEDOUT && proto == IPPROTO_TCP && retries--);

	if (statp != NULL)
		*statp = stat;

	if (stat != RPC_SUCCESS)
		return (0);
	return (1);
}

static struct netbuf bootparam_addr;

/*
 * Returns after filling in the following global variables:
 *	bootparam_addr,
 *	utsname.nodename,
 *	srpc_domain.
 */
static int
whoami(void)
{
	TIUSER *tiptr;
	struct netbuf sa;
	struct netbuf req;
	struct bp_whoami_arg arg;
	struct bp_whoami_res res;
	struct timeval tv;
	enum clnt_stat stat;
	int rc;
	size_t namelen;
	int printed_waiting_msg;

	if ((rc = t_kopen((file_t *)NULL, dl_udp_netconf.knc_rdev,
	    FREAD|FWRITE, &tiptr, CRED())) != 0) {
		nfs_perror(rc, "whoami: t_kopen udp failed: %m.\n");
	}

	/*
	 * Find out our local (IP) address.
	 */
	if (rc = revarp_myaddr(tiptr)) {
		nfs_perror(rc, "whoami: revarp_myaddr failed: %m.\n");
		(void) t_kclose(tiptr, 0);
		return (rc);
	}

	/* explicitly use the limited broadcast address */
	init_netbuf(&sa);
	((struct sockaddr_in *)sa.buf)->sin_family = AF_INET;
	((struct sockaddr_in *)sa.buf)->sin_addr.s_addr =
	    htonl(INADDR_BROADCAST);
	sa.len = sizeof (struct sockaddr_in);

	/*
	 * Pick up our local (IP) address.
	 */
	init_netbuf(&req);
	if (rc = ifioctl(tiptr, SIOCGIFADDR, &req)) {
		nfs_perror(rc,
		    "whoami: couldn't get my IP address: %m.\n");
		free_netbuf(&sa);
		free_netbuf(&req);
		(void) t_kclose(tiptr, 0);
		return (rc);
	}

	/*
	 * Set up the arguments expected by bootparamd.
	 */
	arg.client_address.address_type = IP_ADDR_TYPE;
	bcopy(&((struct sockaddr_in *)req.buf)->sin_addr,
	    &arg.client_address.bp_address.ip_addr, sizeof (struct in_addr));

	free_netbuf(&req);

	init_netbuf(&bootparam_addr);

	/*
	 * Initial retransmission interval
	 */
	tv.tv_sec = DEFAULT_TIMEO;
	tv.tv_usec = 0;
	res.client_name = kmem_alloc(MAX_MACHINE_NAME + 1, KM_SLEEP);
	res.domain_name = kmem_alloc(MAX_MACHINE_NAME + 1, KM_SLEEP);

	/*
	 * Do a broadcast call to find a bootparam daemon that
	 * will tell us our hostname, domainname and any
	 * router that we have to use to talk to our NFS server.
	 */
	printed_waiting_msg = 0;
	do {
		/*
		 * pmap_rmt_call will first try the SunOS portmapper
		 * and if no reply is received will then try the SVR4
		 * rpcbind.
		 * Either way, `bootparam_addr' will be set to the
		 * correct address for the bootparamd that responds.
		 */
		stat = pmap_rmt_call(&dl_udp_netconf, &sa, TRUE, BOOTPARAMPROG,
		    BOOTPARAMVERS, BOOTPARAMPROC_WHOAMI,
		    xdr_bp_whoami_arg, (caddr_t)&arg,
		    xdr_bp_whoami_res, (caddr_t)&res,
		    tv, &bootparam_addr);
		if (stat == RPC_TIMEDOUT && !printed_waiting_msg) {
			cmn_err(CE_WARN,
			    "No bootparam server responding; still trying");
			printed_waiting_msg = 1;
		}
		/*
		 * Retransmission interval for second and subsequent tries.
		 * We expect first pmap_rmt_call to retransmit and backoff to
		 * at least this value.
		 */
		tv.tv_sec = WHOAMI_TIMEO;
		tv.tv_usec = 0;
	} while (stat == RPC_TIMEDOUT);

	if (printed_waiting_msg)
		printf("Bootparam response received\n");

	if (stat != RPC_SUCCESS) {
		/* XXX should get real error here */
		rc = ENXIO;
		cmn_err(CE_WARN,
		    "whoami: bootparam RPC failed: error %d (%s).",
		    stat, clnt_sperrno(stat));
		goto done;
	}

	namelen = strlen(res.client_name);
	if (namelen > sizeof (utsname.nodename)) {
		printf("whoami: hostname too long");
		rc = ENAMETOOLONG;
		goto done;
	}
	if (namelen != 0) {
		bcopy(res.client_name, &utsname.nodename, namelen);
		cmn_err(CE_CONT, "?hostname: %s\n", utsname.nodename);
	} else {
		printf("whoami: no host name\n");
		rc = ENXIO;
		goto done;
	}

	namelen = strlen(res.domain_name);
	if (namelen != 0) {
		if (namelen > SYS_NMLN) {
			printf("whoami: domainname too long");
			rc = ENAMETOOLONG;
			goto done;
		}
		bcopy(res.domain_name, &srpc_domain, namelen);
		cmn_err(CE_CONT, "?domainname: %s\n", srpc_domain);
	} else {
		printf("whoami: no domain name\n");
	}

	if (res.router_address.address_type == IP_ADDR_TYPE) {
		struct rtentry		rtentry;
		struct sockaddr_in	*sin;
		struct in_addr		ipaddr;

		bcopy(&res.router_address.bp_address.ip_addr, &ipaddr,
		    sizeof (struct in_addr));

		if (ipaddr.s_addr != (uint32_t)0) {
			sin = (struct sockaddr_in *)&rtentry.rt_dst;
			bzero(sin, sizeof (*sin));
			sin->sin_family = AF_INET;

			sin = (struct sockaddr_in *)&rtentry.rt_gateway;
			bzero(sin, sizeof (*sin));
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = ipaddr.s_addr;

			rtentry.rt_flags = RTF_GATEWAY | RTF_UP;

			if (rc = rtioctl(tiptr, SIOCADDRT, &rtentry)) {
				nfs_perror(rc,
				    "whoami: couldn't add route: %m.\n");
				goto done;
			}
		}
	} else {
		printf("whoami: unknown gateway addr family %d\n",
		    res.router_address.address_type);
	}
done:
	kmem_free(res.client_name, MAX_MACHINE_NAME + 1);
	kmem_free(res.domain_name, MAX_MACHINE_NAME + 1);
	free_netbuf(&sa);
	(void) t_kclose(tiptr, 0);
	return (rc);
}

/*
 * Returns:
 *	1) The ascii form of our root servers name in `server_name'.
 *	2) Actual network address of our root server in `server_address'.
 *	3) Whatever BOOTPARAMPROC_GETFILE returns for the fileid key, in
 *	   `server_path'.  If fileid is "root", it is the pathname of our
 *	   root on the server.
 */
static int
getfile(char *fileid,
    char *server_name, struct netbuf *server_address, char *server_path)
{
	struct bp_getfile_arg arg;
	struct bp_getfile_res res;
	enum clnt_stat stat;
	int root = FALSE;
	static int using_cache = FALSE;
	struct in_addr ipaddr;
	int timeo = DEFAULT_TIMEO;
	int retries = DEFAULT_RETRIES;

	if (dldebug)
		printf("getfile: entered\n");

	/*
	 * Call cacheinfo() to see whether we can satisfy this request by using
	 * the information cached in memory by the boot program's DHCP
	 * implementation or boot properties rather than consult BOOTPARAMS,
	 * but while preserving the semantics of getfile(). We know that
	 * the server name is SYS_NMLN in length, and server_path is
	 * MAXPATHLEN (pn_alloc).
	 */
	if (strcmp(fileid, "root") == 0) {
		if (cacheinfo(server_name, SYS_NMLN, server_address,
		    server_path, MAXPATHLEN) == 0) {
			using_cache = TRUE;
			return (0);
		}
		root = TRUE;
	}

	/*
	 * If using cache, rootopts is already available.
	 */
	if (strcmp(fileid, "rootopts") == 0 && using_cache == TRUE) {
		return (rootopts[0] != 0 ? 0 : ENXIO);
	}

	if (bootparam_addr.len == 0) {
		return (ENXIO);
	}
	arg.client_name = (caddr_t)&utsname.nodename;
	arg.file_id = fileid;

	bzero(&res, sizeof (res));
	res.server_name = kmem_alloc(MAX_MACHINE_NAME + 1, KM_SLEEP);
	res.server_path = kmem_alloc(MAX_MACHINE_NAME + 1, KM_SLEEP);

	/*
	 * If we are not looking up the root file, we are looking
	 * up a non-critical option that should timeout quickly.
	 */
	if (!root) {
		timeo = GETFILE_TIMEO;
		retries = GETFILE_RETRIES;
	}

	/*
	 * bootparam_addr was filled in by the call to
	 * whoami(), so now send an rpc message to the
	 * bootparam daemon requesting our server information.
	 * Use UDP to talk to bootparms.
	 */
	stat = mycallrpc(&dl_udp_netconf, &bootparam_addr,
	    (rpcprog_t)BOOTPARAMPROG, (rpcvers_t)BOOTPARAMVERS,
	    (rpcproc_t)BOOTPARAMPROC_GETFILE,
	    xdr_bp_getfile_arg, (caddr_t)&arg,
	    xdr_bp_getfile_res, (caddr_t)&res,
	    timeo, retries);

	if (stat == RPC_SUCCESS) {
		(void) strcpy(server_name, res.server_name);
		(void) strcpy(server_path, res.server_path);
	}

	kmem_free(res.server_name, MAX_MACHINE_NAME + 1);
	kmem_free(res.server_path, MAX_MACHINE_NAME + 1);

	if (stat != RPC_SUCCESS) {
		if (root)
			cmn_err(CE_WARN, "getfile: RPC failed: error %d (%s).",
			    stat, clnt_sperrno(stat));
		return ((stat == RPC_TIMEDOUT) ? ETIMEDOUT : ENXIO); /* XXX */
	}

	if (*server_path == '\0')
		return (EINVAL);

	/*
	 * If the fileid is "root", we must get back a server name, for
	 * other parameters a server name is not required
	 */
	if (!root) {
		if (dldebug)
			printf("getfile: leaving: non-root\n");
		return (0);
	}

	if (*server_name == '\0')
		return (EINVAL);

	switch (res.server_address.address_type) {
	case IP_ADDR_TYPE:
		/*
		 * server_address is where we will get our root
		 * from.
		 */
		((struct sockaddr_in *)server_address->buf)->sin_family =
		    AF_INET;
		bcopy(&res.server_address.bp_address.ip_addr,
		    &ipaddr, sizeof (ipaddr));
		if (ipaddr.s_addr == 0)
			return (EINVAL);

		((struct sockaddr_in *)server_address->buf)->sin_addr.s_addr =
		    ipaddr.s_addr;
		server_address->len = sizeof (struct sockaddr_in);
		break;

	default:
		printf("getfile: unknown address type %d\n",
		    res.server_address.address_type);
		return (EPROTONOSUPPORT);
	}
	if (dldebug)
		printf("getfile: leaving\n");
	return (0);
}

/*
 * If the boot property "bootp-response" exists, then OBP performed a
 * successful DHCP lease acquisition for us and left the resultant ACK packet
 * encoded at that location.
 *
 * If no such property exists (or the information is incomplete or garbled),
 * the function returns -1.
 */
int
dhcpinit(void)
{
	int rc, i;
	char *p;
	struct in_addr braddr;
	struct in_addr subnet;
	DHCP_OPT *doptp;
	TIUSER *tiptr;
	struct sockaddr_in *sin;
	static int once_only = 0;

	if (once_only == 1) {
		return (0);
	}
	once_only = 1;

	if (dhcack == NULL) {
		return (-1);
	}

	if (dldebug) {
		printf("dhcp:  dhcack %p, len %d\n", (void *)dhcack,
		    dhcacklen);
	}

	pl = kmem_alloc(sizeof (PKT_LIST), KM_SLEEP);
	pl->len = dhcacklen;
	pl->pkt = kmem_alloc(pl->len, KM_SLEEP);
	bcopy(dhcack, pl->pkt, dhcacklen);

	/*
	 * For x86, ifname is not initialized
	 * in the netinstall case and dhcack interface name is
	 * set in strplumb(). So we only copy the name if ifname
	 * is set properly.
	 */
	if (ifname[0])
		(void) strlcpy(dhcifname, ifname, sizeof (dhcifname));

	/* remember the server_ip in dhcack */
	bcopy((uchar_t *)pl->pkt + 20, dhcp_server_ip, 4);
	bzero(pl->opts, (DHCP_LAST_OPT + 1) * sizeof (DHCP_OPT *));
	bzero(pl->vs, (VS_OPTION_END - VS_OPTION_START + 1) *
	    sizeof (DHCP_OPT *));

	if (dhcp_options_scan(pl, B_TRUE) != 0) {
		/* garbled packet */
		cmn_err(CE_WARN, "dhcp: DHCP packet parsing failed");
		kmem_free(pl->pkt, pl->len);
		kmem_free(pl, sizeof (PKT_LIST));
		pl = NULL;
		return (-1);
	}

	/* set node name */
	if (pl->opts[CD_HOSTNAME] != NULL) {
		doptp = pl->opts[CD_HOSTNAME];
		i = doptp->len;
		if (i >= SYS_NMLN) {
			cmn_err(CE_WARN, "dhcp: Hostname is too long");
		} else {
			bcopy(doptp->value, utsname.nodename, i);
			utsname.nodename[i] = '\0';
			if (dldebug) {
				printf("hostname is %s\n",
				    utsname.nodename);
			}
		}
	}

	/* Set NIS domain name. */
	p = NULL;
	if (pl->opts[CD_NIS_DOMAIN] != NULL) {
		doptp = pl->opts[CD_NIS_DOMAIN];
		i = doptp->len;
		p = (caddr_t)doptp->value;
	}
	if (p != NULL) {
		if (i > SYS_NMLN) {
			cmn_err(CE_WARN,
			    "dhcp: NIS domainname too long.");
		} else {
			bcopy(p, srpc_domain, i);
			srpc_domain[i] = '\0';
			if (dldebug)
				printf("dhcp: NIS domain name is %s\n",
				    srpc_domain);
		}
	}

	/* fetch netmask */
	if (pl->opts[CD_SUBNETMASK] != NULL) {
		doptp = pl->opts[CD_SUBNETMASK];
		if (doptp->len != sizeof (struct in_addr)) {
			pl->opts[CD_SUBNETMASK] = NULL;
			cmn_err(CE_WARN, "dhcp: netmask option malformed");
		} else {
			bcopy(doptp->value, &subnet, sizeof (struct in_addr));
			if (dldebug)
				printf("dhcp:  setting netmask to: %s\n",
				    inet_ntoa(subnet));
		}
	} else {
		struct in_addr myIPaddr;

		myIPaddr.s_addr = pl->pkt->yiaddr.s_addr;
		cmn_err(CE_WARN, "dhcp:  no subnet mask supplied - inferring");
		if (IN_CLASSA(ntohl(myIPaddr.s_addr)))
			subnet.s_addr = htonl(IN_CLASSA_NET);
		else if (IN_CLASSB(ntohl(myIPaddr.s_addr)))
			subnet.s_addr = htonl(IN_CLASSB_NET);
		else if (IN_CLASSC(ntohl(myIPaddr.s_addr)))
			subnet.s_addr = htonl(IN_CLASSC_NET);
		else if (IN_CLASSD(ntohl(myIPaddr.s_addr)))
			cmn_err(CE_WARN, "dhcp:  bad IP address (%s)",
			    inet_ntoa(myIPaddr));
		else
			subnet.s_addr = htonl(IN_CLASSE_NET);
	}
	/* and broadcast address */
	if (pl->opts[CD_BROADCASTADDR] != NULL) {
		doptp = pl->opts[CD_BROADCASTADDR];
		if (doptp->len != sizeof (struct in_addr)) {
			pl->opts[CD_BROADCASTADDR] = NULL;
			if (dldebug)
				printf("dhcp:  broadcast address len %d\n",
				    doptp->len);
		} else {
			bcopy(doptp->value, &braddr, sizeof (struct in_addr));
			if (dldebug)
				printf("dhcp:  setting broadcast addr to: %s\n",
				    inet_ntoa(braddr));
		}
	} else {
		if (dldebug)
			printf("dhcp:  no broadcast address supplied\n");
		braddr.s_addr = htonl(INADDR_BROADCAST);
	}
	/* and plumb and initialize interface */
	if ((rc = t_kopen((file_t *)NULL, dl_udp_netconf.knc_rdev,
	    FREAD|FWRITE, &tiptr, CRED())) == 0) {
		if (rc = dlifconfig(tiptr, &pl->pkt->yiaddr, &subnet,
		    &braddr, IFF_DHCPRUNNING)) {
			nfs_perror(rc, "dhcp: dlifconfig failed: %m\n");
			kmem_free(pl->pkt, pl->len);
			kmem_free(pl, sizeof (PKT_LIST));
			pl = NULL;
			(void) t_kclose(tiptr, 0);
			return (-1);
		}

		/* add routes */
		if (pl->opts[CD_ROUTER] != NULL) {
			doptp = pl->opts[CD_ROUTER];
			if ((doptp->len % sizeof (struct in_addr)) != 0) {
				pl->opts[CD_ROUTER] = NULL;
			} else {
				int nrouters;
				uchar_t *tp;

				nrouters = doptp->len / sizeof (struct in_addr);
				for (tp = doptp->value, i = 0; i < nrouters;
				    i++) {
					struct in_addr defr;
					struct rtentry	rtentry;

					bcopy(tp, &defr,
					    sizeof (struct in_addr));
					if (defr.s_addr == 0)
						continue;

					sin = (struct
					    sockaddr_in *)&rtentry.rt_dst;

					bzero(sin, sizeof (*sin));
					sin->sin_family = AF_INET;

					sin = (struct
					    sockaddr_in *)&rtentry.rt_gateway;
					bzero(sin, sizeof (*sin));
					sin->sin_family = AF_INET;
					sin->sin_addr = defr;

					rtentry.rt_flags = RTF_GATEWAY | RTF_UP;

					if (rc = rtioctl(tiptr, SIOCADDRT,
					    &rtentry)) {
						nfs_perror(rc,
						    "dhcp: couldn't add route "
						    "to %s: %m.\n",
						    inet_ntoa(defr));
							continue;
					}
					if (dldebug) {
						printf("dhcp: added route %s\n",
						    inet_ntoa(defr));
					}
					tp += sizeof (struct in_addr);
				}
			}
		}

		(void) t_kclose(tiptr, 0);
	}

	if (dldebug)
		printf("dhcpinit: leaving\n");

	return (0);
}

/*
 * Initialize nfs mount info from properties and dhcp response.
 */
static void
cacheinit(void)
{
	char *str;
	DHCP_OPT *doptp;

	(void) ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_SERVER_PATH, &server_path_c);
	(void) ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_SERVER_NAME, &server_name_c);
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_SERVER_ROOTOPTS, &str) == DDI_SUCCESS) {
		(void) strncpy(rootopts, str, 255);
		ddi_prop_free(str);
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_SERVER_IP, &str) == DDI_SUCCESS) {
		if (inet_aton(str, server_ip) != 0)
			cmn_err(CE_NOTE, "server_ipaddr %s is invalid",
			    str);
		ddi_prop_free(str);
		if (dldebug)
			printf("server ip is %s\n",
			    inet_ntoa(*(struct in_addr *)server_ip));
	}

	if (pl == NULL)
		return;

	/* extract root path in server_path */
	if (server_path_c == NULL) {
		doptp = pl->vs[VS_NFSMNT_ROOTPATH];
		if (doptp == NULL)
			doptp = pl->opts[CD_ROOT_PATH];
		if (doptp != NULL) {
			int len, size;
			uint8_t c, *source;

			str = NULL;
			source = doptp->value;
			size = doptp->len;
			c = ':';

			/*
			 * We have to consider three cases for root path:
			 * "nfs://server_ip/path"
			 * "server_ip:/path"
			 * "/path"
			 */
			if (bcmp(source, "nfs://", 6) == 0) {
				source += 6;
				size -= 6;
				c = '/';
			}
			/*
			 * Search for next char after ':' or first '/'.
			 * Note, the '/' is part of the path, but we do
			 * not need to preserve the ':'.
			 */
			for (len = 0; len < size; len++) {
				if (source[len] == c) {
					if (c == ':') {
						str = (char *)(&source[++len]);
					} else {
						str = (char *)(&source[len++]);
						size++;
					}
					break;
				}
			}
			if (str != NULL) {
				/* Do not override server_ip from property. */
				if ((*(uint_t *)server_ip) == 0) {
					char *ip = kmem_alloc(len, KM_SLEEP);
					bcopy(source, ip, len);
					ip[len - 1] = '\0';
					if (inet_aton((ip), server_ip) != 0) {
						cmn_err(CE_NOTE,
						    "server_ipaddr %s is "
						    "invalid", ip);
					}
					kmem_free(ip, len);
					if (dldebug) {
						printf("server ip is %s\n",
						    inet_ntoa(
						    *(struct in_addr *)
						    server_ip));
					}
				}
				len = size - len;
			} else {
				str = (char *)doptp->value;
				len = doptp->len;
			}
			server_path_c = kmem_alloc(len + 1, KM_SLEEP);
			bcopy(str, server_path_c, len);
			server_path_c[len] = '\0';
			if (dldebug)
				printf("dhcp:  root path %s\n", server_path_c);
		} else {
			cmn_err(CE_WARN, "dhcp: root server path missing");
		}
	}

	/* set server_name */
	if (server_name_c == NULL) {
		doptp = pl->vs[VS_NFSMNT_ROOTSRVR_NAME];
		if (doptp != NULL) {
			server_name_c = kmem_alloc(doptp->len + 1, KM_SLEEP);
			bcopy(doptp->value, server_name_c, doptp->len);
			server_name_c[doptp->len] = '\0';
			if (dldebug)
				printf("dhcp: root server name %s\n",
				    server_name_c);
		} else {
			cmn_err(CE_WARN, "dhcp: root server name missing");
		}
	}

	/* set root server_address */
	if ((*(uint_t *)server_ip) == 0) {
		doptp = pl->vs[VS_NFSMNT_ROOTSRVR_IP];
		if (doptp) {
			bcopy(doptp->value, server_ip, sizeof (server_ip));
			if (dldebug) {
				printf("dhcp:  root server IP address %s\n",
				    inet_ntoa(*(struct in_addr *)server_ip));
			}
		} else {
			if (dldebug)
				cmn_err(CE_CONT,
				    "dhcp: file server ip address missing,"
				    " fallback to dhcp server as file server");
			bcopy(dhcp_server_ip, server_ip, sizeof (server_ip));
		}
	}

	/* set root file system mount options */
	if (rootopts[0] == 0) {
		doptp = pl->vs[VS_NFSMNT_ROOTOPTS];
		if (doptp != NULL && doptp->len < 255) {
			bcopy(doptp->value, rootopts, doptp->len);
			rootopts[doptp->len] = '\0';
			if (dldebug)
				printf("dhcp:  rootopts %s\n", rootopts);
		} else if (dldebug) {
			printf("dhcp:  no rootopts or too long\n");
			/* not an error */
		}
	}

	/* now we are done with pl, just free it */
	kmem_free(pl->pkt, pl->len);
	kmem_free(pl, sizeof (PKT_LIST));
	pl = NULL;
}

static int
cacheinfo(char *name, int namelen,
    struct netbuf *server_address, char *rootpath, int pathlen)
{
	static int init_done = 0;
	struct sockaddr_in *sin;

	if (init_done == 0) {
		cacheinit();
		init_done = 1;
	}

	/* server_path is a reliable indicator of cache availability */
	if (server_path_c == NULL)
		return (-1);

	(void) strncpy(rootpath, server_path_c, pathlen);
	if (server_name_c) {
		(void) strncpy(name, server_name_c, namelen);
	} else {
		(void) strncpy(name, "unknown", namelen);
	}

	sin = (struct sockaddr_in *)server_address->buf;
	sin->sin_family = AF_INET;
	server_address->len = sizeof (struct sockaddr_in);
	bcopy(server_ip, &sin->sin_addr, sizeof (struct in_addr));
	return (0);
}

/*
 *	Set this interface's IP address and netmask, and bring it up.
 */
static int
dlifconfig(TIUSER *tiptr, struct in_addr *myIPaddr, struct in_addr *mymask,
    struct in_addr *mybraddr, uint_t flags)
{
	int rc;
	struct netbuf sbuf;
	struct sockaddr_in sin;

	if (dldebug) {
		printf("dlifconfig:  entered\n");
		printf("dlifconfig:  addr %s\n", inet_ntoa(*myIPaddr));
		printf("dlifconfig:  mask %s\n", inet_ntoa(*mymask));
		printf("dlifconfig:  broadcast %s\n", inet_ntoa(*mybraddr));
	}

	bcopy(myIPaddr, &sin.sin_addr, sizeof (struct in_addr));
	sin.sin_family = AF_INET;
	sbuf.buf = (caddr_t)&sin;
	sbuf.maxlen = sbuf.len = sizeof (sin);
	if (rc = ifioctl(tiptr, SIOCSIFADDR, &sbuf)) {
		nfs_perror(rc,
		    "dlifconfig: couldn't set interface net address: %m\n");
		return (rc);
	}

	if (mybraddr->s_addr != INADDR_BROADCAST) {
		bcopy(mybraddr, &sin.sin_addr, sizeof (struct in_addr));
		sin.sin_family = AF_INET;
		sbuf.buf = (caddr_t)&sin;
		sbuf.maxlen = sbuf.len = sizeof (sin);
		if (rc = ifioctl(tiptr, SIOCSIFBRDADDR, &sbuf)) {
			nfs_perror(rc,
		    "dlifconfig: couldn't set interface broadcast addr: %m\n");
			return (rc);
		}
	}

	bcopy(mymask, &sin.sin_addr, sizeof (struct in_addr));
	sin.sin_family = AF_INET;
	sbuf.buf = (caddr_t)&sin;
	sbuf.maxlen = sbuf.len = sizeof (sin);
	if (rc = ifioctl(tiptr, SIOCSIFNETMASK, &sbuf)) {
		nfs_perror(rc,
		    "dlifconfig: couldn't set interface net address: %m\n");
		return (rc);
	}

	/*
	 * Now turn on the interface.
	 */
	if (rc = setifflags(tiptr, IFF_UP | flags)) {
		nfs_perror(rc,
		    "dlifconfig: couldn't enable network interface: %m\n");
		return (rc);
	}

	if (dldebug)
		printf("dlifconfig:  returned\n");
	return (0);
}

static char *
inet_ntoa(struct in_addr in)
{
	static char b[18];
	unsigned char *p;

	p = (unsigned char *)&in;
	(void) sprintf(b, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return (b);
}

/* We only deal with a.b.c.d decimal format. ip points to 4 byte storage */
static int
inet_aton(char *ipstr, uchar_t *ip)
{
	int i = 0;
	uchar_t val[4] = {0};
	char c = *ipstr;

	for (;;) {
		if (!isdigit(c))
			return (-1);
		for (;;) {
			if (!isdigit(c))
				break;
			val[i] = val[i] * 10 + (c - '0');
			c = *++ipstr;
		}
		i++;
		if (i == 4)
			break;
		if (c != '.')
			return (-1);
		c = *++ipstr;
	}
	if (c != 0)
		return (-1);
	bcopy(val, ip, 4);
	return (0);
}

#define	MAX_ADDR_SIZE	128

/*
 * Initialize a netbuf suitable for
 * describing an address for the
 * transport defined by `tiptr'.
 */
static void
init_netbuf(struct netbuf *nbuf)
{
	nbuf->buf = kmem_zalloc(MAX_ADDR_SIZE, KM_SLEEP);
	nbuf->maxlen = MAX_ADDR_SIZE;
	nbuf->len = 0;
}

static void
free_netbuf(struct netbuf *nbuf)
{
	kmem_free(nbuf->buf, nbuf->maxlen);
	nbuf->buf = NULL;
	nbuf->maxlen = 0;
	nbuf->len = 0;
}

static int
rtioctl(TIUSER *tiptr, int cmd, struct rtentry *rtentry)
{
	struct strioctl iocb;
	int rc;
	vnode_t *vp;

	iocb.ic_cmd = cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = sizeof (struct rtentry);
	iocb.ic_dp = (caddr_t)rtentry;

	vp = tiptr->fp->f_vnode;
	rc = kstr_ioctl(vp, I_STR, (intptr_t)&iocb);
	if (rc)
		nfs_perror(rc, "rtioctl: kstr_ioctl failed: %m\n");
	return (rc);
}

/*
 * Send an ioctl down the stream defined
 * by `tiptr'.
 *
 * We isolate the ifreq dependencies in here. The
 * ioctl really ought to take a netbuf and be of
 * type TRANSPARENT - one day.
 */
static int
ifioctl(TIUSER *tiptr, int cmd, struct netbuf *nbuf)
{
	struct strioctl iocb;
	int rc;
	vnode_t *vp;
	struct ifreq ifr;

	/*
	 * Now do the one requested.
	 */
	if (nbuf->len)
		ifr.ifr_addr = *(struct sockaddr *)nbuf->buf;
	(void) strncpy((caddr_t)&ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	iocb.ic_cmd = cmd;
	iocb.ic_timout = 0;
	iocb.ic_len = sizeof (ifr);
	iocb.ic_dp = (caddr_t)&ifr;

	vp = tiptr->fp->f_vnode;
	rc = kstr_ioctl(vp, I_STR, (intptr_t)&iocb);
	if (rc) {
		nfs_perror(rc, "ifioctl: kstr_ioctl failed: %m\n");
		return (rc);
	}

	/*
	 * Set reply length.
	 */
	if (nbuf->len == 0) {
		/*
		 * GET type.
		 */
		nbuf->len = sizeof (struct sockaddr);
		*(struct sockaddr *)nbuf->buf = ifr.ifr_addr;
	}

	return (0);
}

static int
setifflags(TIUSER *tiptr, uint_t value)
{
	struct ifreq ifr;
	int rc;
	struct strioctl iocb;

	(void) strncpy((caddr_t)&ifr.ifr_name, ifname, sizeof (ifr.ifr_name));
	iocb.ic_cmd = SIOCGIFFLAGS;
	iocb.ic_timout = 0;
	iocb.ic_len = sizeof (ifr);
	iocb.ic_dp = (caddr_t)&ifr;
	if (rc = kstr_ioctl(tiptr->fp->f_vnode, I_STR, (intptr_t)&iocb))
		return (rc);

	ifr.ifr_flags |= value;
	iocb.ic_cmd = SIOCSIFFLAGS;
	return (kstr_ioctl(tiptr->fp->f_vnode, I_STR, (intptr_t)&iocb));
}

/*
 * REVerse Address Resolution Protocol (revarp)
 * is used by a diskless client to find out its
 * IP address when all it knows is its Ethernet address.
 *
 * Open the ethernet driver, attach and bind
 * (DL_BIND_REQ) it, and then format a broadcast RARP
 * message for it to send. We pick up the reply and
 * let the caller set the interface address using SIOCSIFADDR.
 */
static int
revarp_myaddr(TIUSER *tiptr)
{
	int			rc;
	dl_info_ack_t		info;
	struct sockaddr_in	sin;
	struct netbuf		sbuf;
	ldi_handle_t		lh;
	ldi_ident_t		li;
	struct netbuf		myaddr = {0, 0, NULL};

	if (dldebug)
		printf("revarp_myaddr: entered\n");

	if (rc = ldi_ident_from_mod(&modlinkage, &li)) {
		nfs_perror(rc,
		    "revarp_myaddr: ldi_ident_from_mod failed: %m\n");
		return (rc);
	}

	rc = ldi_open_by_name(ndev_path, FREAD|FWRITE, CRED(), &lh, li);
	ldi_ident_release(li);
	if (rc) {
		nfs_perror(rc,
		    "revarp_myaddr: ldi_open_by_name failed: %m\n");
		return (rc);
	}

	if (rc = dl_attach(lh, ifunit, NULL)) {
		nfs_perror(rc, "revarp_myaddr: dl_attach failed: %m\n");
		(void) ldi_close(lh, FREAD|FWRITE, CRED());
		return (rc);
	}

	if (rc = dl_bind(lh, ETHERTYPE_REVARP, NULL)) {
		nfs_perror(rc, "revarp_myaddr: dl_bind failed: %m\n");
		(void) ldi_close(lh, FREAD|FWRITE, CRED());
		return (rc);
	}

	if (rc = dl_info(lh, &info, NULL, NULL, NULL)) {
		nfs_perror(rc, "revarp_myaddr: dl_info failed: %m\n");
		(void) ldi_close(lh, FREAD|FWRITE, CRED());
		return (rc);
	}

	/* Initialize myaddr */
	myaddr.maxlen = info.dl_addr_length;
	myaddr.buf = kmem_alloc(myaddr.maxlen, KM_SLEEP);

	revarp_start(lh, &myaddr);

	bcopy(myaddr.buf, &sin.sin_addr, myaddr.len);
	sin.sin_family = AF_INET;

	sbuf.buf = (caddr_t)&sin;
	sbuf.maxlen = sbuf.len = sizeof (sin);
	if (rc = ifioctl(tiptr, SIOCSIFADDR, &sbuf)) {
		nfs_perror(rc,
		    "revarp_myaddr: couldn't set interface net address: %m\n");
		(void) ldi_close(lh, FREAD|FWRITE, CRED());
		kmem_free(myaddr.buf, myaddr.maxlen);
		return (rc);
	}

	/* Now turn on the interface */
	if (rc = setifflags(tiptr, IFF_UP)) {
		nfs_perror(rc,
		    "revarp_myaddr: couldn't enable network interface: %m\n");
	}

	(void) ldi_close(lh, FREAD|FWRITE, CRED());
	kmem_free(myaddr.buf, myaddr.maxlen);
	return (rc);
}

static void
revarp_start(ldi_handle_t lh, struct netbuf *myaddr)
{
	struct ether_arp *ea;
	int rc;
	dl_unitdata_req_t *dl_udata;
	mblk_t *bp;
	mblk_t *mp;
	struct dladdr *dlsap;
	static int done = 0;
	size_t addrlen = ETHERADDRL;

	if (dl_phys_addr(lh, (uchar_t *)&myether, &addrlen, NULL) != 0 ||
	    addrlen != ETHERADDRL) {
		/* Fallback using per-node address */
		(void) localetheraddr((struct ether_addr *)NULL, &myether);
		cmn_err(CE_CONT, "?DLPI failed to get Ethernet address. Using "
		    "system wide Ethernet address %s\n",
		    ether_sprintf(&myether));
	}

getreply:
	if (myaddr->len != 0) {
		cmn_err(CE_CONT, "?Found my IP address: %x (%d.%d.%d.%d)\n",
		    *(int *)myaddr->buf,
		    (uchar_t)myaddr->buf[0], (uchar_t)myaddr->buf[1],
		    (uchar_t)myaddr->buf[2], (uchar_t)myaddr->buf[3]);
		return;
	}

	if (done++ == 0)
		cmn_err(CE_CONT, "?Requesting Internet address for %s\n",
		    ether_sprintf(&myether));

	/*
	 * Send another RARP request.
	 */
	if ((mp = allocb(sizeof (dl_unitdata_req_t) + sizeof (*dlsap),
	    BPRI_HI)) == NULL) {
		cmn_err(CE_WARN, "revarp_myaddr: allocb no memory");
		return;
	}
	if ((bp = allocb(sizeof (struct ether_arp), BPRI_HI)) == NULL) {
		cmn_err(CE_WARN, "revarp_myaddr: allocb no memory");
		return;
	}

	/*
	 * Format the transmit request part.
	 */
	mp->b_datap->db_type = M_PROTO;
	dl_udata = (dl_unitdata_req_t *)mp->b_wptr;
	mp->b_wptr += sizeof (dl_unitdata_req_t) + sizeof (*dlsap);
	dl_udata->dl_primitive = DL_UNITDATA_REQ;
	dl_udata->dl_dest_addr_length = sizeof (*dlsap);
	dl_udata->dl_dest_addr_offset = sizeof (*dl_udata);
	dl_udata->dl_priority.dl_min = 0;
	dl_udata->dl_priority.dl_max = 0;

	dlsap = (struct dladdr *)(mp->b_rptr + sizeof (*dl_udata));
	bcopy(&etherbroadcastaddr, &dlsap->dl_phys,
	    sizeof (etherbroadcastaddr));
	dlsap->dl_sap = ETHERTYPE_REVARP;

	/*
	 * Format the actual REVARP request.
	 */
	bzero(bp->b_wptr, sizeof (struct ether_arp));
	ea = (struct ether_arp *)bp->b_wptr;
	bp->b_wptr += sizeof (struct ether_arp);
	ea->arp_hrd = htons(ARPHRD_ETHER);
	ea->arp_pro = htons(ETHERTYPE_IP);
	ea->arp_hln = sizeof (ea->arp_sha);	/* hardware address length */
	ea->arp_pln = sizeof (ea->arp_spa);	/* protocol address length */
	ea->arp_op = htons(REVARP_REQUEST);
	ether_copy(&myether, &ea->arp_sha);
	ether_copy(&myether, &ea->arp_tha);

	mp->b_cont = bp;

	if ((rc = ldi_putmsg(lh, mp)) != 0) {
		nfs_perror(rc, "revarp_start: ldi_putmsg failed: %m\n");
		return;
	}
	revarpinput(lh, myaddr);

	goto getreply;
}

/*
 * Client side Reverse-ARP input
 * Server side is handled by user level server
 */
static void
revarpinput(ldi_handle_t lh, struct netbuf *myaddr)
{
	struct ether_arp *ea;
	mblk_t *bp;
	mblk_t *mp;
	int rc;
	timestruc_t tv, give_up, now;

	/*
	 * Choose the time at which we will give up, and resend our
	 * request.
	 */
	gethrestime(&give_up);
	give_up.tv_sec += REVARP_TIMEO;
wait:
	/*
	 * Compute new timeout value.
	 */
	tv = give_up;
	gethrestime(&now);
	timespecsub(&tv, &now);
	/*
	 * If we don't have at least one full second remaining, give up.
	 * This means we might wait only just over 4.0 seconds, but that's
	 * okay.
	 */
	if (tv.tv_sec <= 0)
		return;
	rc = ldi_getmsg(lh, &mp, &tv);
	if (rc == ETIME) {
		goto out;
	} else if (rc != 0) {
		nfs_perror(rc, "revarpinput: ldi_getmsg failed: %m\n");
		return;
	}

	if (mp->b_cont == NULL) {
		printf("revarpinput: b_cont == NULL\n");
		goto out;
	}

	if (mp->b_datap->db_type != M_PROTO) {
		printf("revarpinput: bad header type %d\n",
		    mp->b_datap->db_type);
		goto out;
	}

	bp = mp->b_cont;

	if (bp->b_wptr - bp->b_rptr < sizeof (*ea)) {
		printf("revarpinput: bad data len %d, expect %d\n",
		    (int)(bp->b_wptr - bp->b_rptr),  (int)sizeof (*ea));
		goto out;
	}

	ea = (struct ether_arp *)bp->b_rptr;

	if ((ushort_t)ntohs(ea->arp_pro) != ETHERTYPE_IP) {
		/* We could have received another broadcast arp packet. */
		if (dldebug)
			printf("revarpinput: bad type %x\n",
			    (ushort_t)ntohs(ea->arp_pro));
		freemsg(mp);
		goto wait;
	}
	if ((ushort_t)ntohs(ea->arp_op) != REVARP_REPLY) {
		/* We could have received a broadcast arp request. */
		if (dldebug)
			printf("revarpinput: bad op %x\n",
			    (ushort_t)ntohs(ea->arp_op));
		freemsg(mp);
		goto wait;
	}

	if (!ether_cmp(&ea->arp_tha, &myether)) {
		bcopy(&ea->arp_tpa, myaddr->buf, sizeof (ea->arp_tpa));
		myaddr->len = sizeof (ea->arp_tpa);
	} else {
		/* We could have gotten a broadcast arp response. */
		if (dldebug)
			printf("revarpinput: got reply, but not my address\n");
		freemsg(mp);
		goto wait;
	}
out:
	freemsg(mp);
}

/*
 * From rpcsvc/mountxdr.c in SunOS. We can't
 * put this into the rpc directory because
 * it calls xdr_fhandle() which is in a
 * loadable module.
 */
static bool_t
myxdr_fhstatus(XDR *xdrs, struct fhstatus *fhsp)
{

	if (!xdr_int(xdrs, &fhsp->fhs_status))
		return (FALSE);
	if (fhsp->fhs_status == 0) {
		if (!myxdr_fhandle(xdrs, &fhsp->fhs_fh))
			return (FALSE);
	}
	return (TRUE);
}

/*
 * From nfs_xdr.c.
 *
 * File access handle
 * The fhandle struct is treated a opaque data on the wire
 */
static bool_t
myxdr_fhandle(XDR *xdrs, fhandle_t *fh)
{
	return (xdr_opaque(xdrs, (caddr_t)fh, NFS_FHSIZE));
}

static bool_t
myxdr_mountres3(XDR *xdrs, struct mountres3 *objp)
{
	if (!myxdr_mountstat3(xdrs, &objp->fhs_status))
		return (FALSE);
	switch (objp->fhs_status) {
	case MNT_OK:
		if (!myxdr_mountres3_ok(xdrs, &objp->mountres3_u.mountinfo))
			return (FALSE);
		break;
	default:
		break;
	}
	return (TRUE);
}

static bool_t
myxdr_mountstat3(XDR *xdrs, enum mountstat3 *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

static bool_t
myxdr_mountres3_ok(XDR *xdrs, struct mountres3_ok *objp)
{
	if (!myxdr_fhandle3(xdrs, &objp->fhandle))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->auth_flavors.auth_flavors_val,
	    (uint_t *)&objp->auth_flavors.auth_flavors_len, ~0,
	    sizeof (int), (xdrproc_t)xdr_int))
		return (FALSE);
	return (TRUE);
}

static bool_t
myxdr_fhandle3(XDR *xdrs, struct fhandle3 *objp)
{
	return (xdr_bytes(xdrs, (char **)&objp->fhandle3_val,
	    (uint_t *)&objp->fhandle3_len, FHSIZE3));
}

/*
 * From SunOS pmap_clnt.c
 *
 * Port mapper routines:
 *	pmap_kgetport() - get port number.
 *	pmap_rmt_call()  - indirect call via port mapper.
 *
 */
static enum clnt_stat
pmap_kgetport(struct knetconfig *knconf, struct netbuf *call_addr,
    rpcprog_t prog, rpcvers_t vers, rpcprot_t prot)
{
	ushort_t port;
	int tries;
	enum clnt_stat stat;
	struct pmap	pmap_parms;
	RPCB		rpcb_parms;
	char		*ua = NULL;

	port = 0;

	((struct sockaddr_in *)call_addr->buf)->sin_port = htons(PMAPPORT);

	pmap_parms.pm_prog = prog;
	pmap_parms.pm_vers = vers;
	pmap_parms.pm_prot = prot;
	pmap_parms.pm_port = 0;
	for (tries = 0; tries < 5; tries++) {
		stat = mycallrpc(knconf, call_addr,
		    PMAPPROG, PMAPVERS, PMAPPROC_GETPORT,
		    myxdr_pmap, (char *)&pmap_parms,
		    xdr_u_short, (char *)&port,
		    DEFAULT_TIMEO, DEFAULT_RETRIES);

		if (stat != RPC_TIMEDOUT)
			break;
		cmn_err(CE_WARN,
		    "pmap_kgetport: Portmapper not responding; still trying");
	}

	if (stat == RPC_PROGUNAVAIL) {
		cmn_err(CE_WARN,
		    "pmap_kgetport: Portmapper failed - trying rpcbind");

		rpcb_parms.r_prog = prog;
		rpcb_parms.r_vers = vers;
		rpcb_parms.r_netid = knconf->knc_proto;
		rpcb_parms.r_addr = rpcb_parms.r_owner = "";

		for (tries = 0; tries < 5; tries++) {
			stat = mycallrpc(knconf, call_addr,
			    RPCBPROG, RPCBVERS, RPCBPROC_GETADDR,
			    xdr_rpcb, (char *)&rpcb_parms,
			    xdr_wrapstring, (char *)&ua,
			    DEFAULT_TIMEO, DEFAULT_RETRIES);

			if (stat != RPC_TIMEDOUT)
				break;
			cmn_err(CE_WARN,
			"pmap_kgetport: rpcbind not responding; still trying");
		}

		if (stat == RPC_SUCCESS) {
			if ((ua != NULL) && (ua[0] != NULL)) {
				port = rpc_uaddr2port(AF_INET, ua);
			} else {
				/* Address unknown */
				stat = RPC_PROGUNAVAIL;
			}
		}
	}

	if (stat == RPC_SUCCESS)
		((struct sockaddr_in *)call_addr->buf)->sin_port = ntohs(port);

	return (stat);
}

/*
 * pmapper remote-call-service interface.
 * This routine is used to call the pmapper remote call service
 * which will look up a service program in the port maps, and then
 * remotely call that routine with the given parameters.  This allows
 * programs to do a lookup and call in one step. In addition to the call_addr,
 * the caller provides a boolean hint about the destination address (TRUE if
 * address is a broadcast address, FALSE otherwise).
 *
 * On return, `call addr' contains the port number for the
 * service requested, and `resp_addr' contains its IP address.
 */
static enum clnt_stat
pmap_rmt_call(struct knetconfig *knconf, struct netbuf *call_addr,
    bool_t bcast, rpcprog_t progn, rpcvers_t versn, rpcproc_t procn,
    xdrproc_t xdrargs, caddr_t argsp, xdrproc_t xdrres, caddr_t resp,
    struct timeval tout, struct netbuf *resp_addr)
{
	CLIENT *cl;
	enum clnt_stat stat;
	rpcport_t port;
	int rc;
	struct rmtcallargs	pmap_args;
	struct rmtcallres	pmap_res;
	struct rpcb_rmtcallargs	rpcb_args;
	struct rpcb_rmtcallres	rpcb_res;
	char			ua[100];	/* XXX */

	((struct sockaddr_in *)call_addr->buf)->sin_port = htons(PMAPPORT);

	rc = clnt_tli_kcreate(knconf, call_addr, PMAPPROG, PMAPVERS,
	    0, PMAP_RETRIES, CRED(), &cl);
	if (rc != 0) {
		nfs_perror(rc,
		    "pmap_rmt_call: clnt_tli_kcreate failed: %m\n");
		return (RPC_SYSTEMERROR);	/* XXX */
	}
	if (cl == (CLIENT *)NULL) {
		panic("pmap_rmt_call: clnt_tli_kcreate failed");
		/* NOTREACHED */
	}

	(void) CLNT_CONTROL(cl, CLSET_BCAST, (char *)&bcast);

	pmap_args.prog = progn;
	pmap_args.vers = versn;
	pmap_args.proc = procn;
	pmap_args.args_ptr = argsp;
	pmap_args.xdr_args = xdrargs;
	pmap_res.port_ptr = &port;
	pmap_res.results_ptr = resp;
	pmap_res.xdr_results = xdrres;
	stat = clnt_clts_kcallit_addr(cl, PMAPPROC_CALLIT,
	    myxdr_rmtcall_args, (caddr_t)&pmap_args,
	    myxdr_rmtcallres, (caddr_t)&pmap_res,
	    tout, resp_addr);

	if (stat == RPC_SUCCESS) {
		((struct sockaddr_in *)resp_addr->buf)->sin_port =
		    htons((ushort_t)port);
	}
	CLNT_DESTROY(cl);

	if (stat != RPC_PROGUNAVAIL)
		return (stat);

	cmn_err(CE_WARN, "pmap_rmt_call: Portmapper failed - trying rpcbind");

	rc = clnt_tli_kcreate(knconf, call_addr, RPCBPROG, RPCBVERS,
	    0, PMAP_RETRIES, CRED(), &cl);
	if (rc != 0) {
		nfs_perror(rc, "pmap_rmt_call: clnt_tli_kcreate failed: %m\n");
		return (RPC_SYSTEMERROR);	/* XXX */
	}

	if (cl == NULL) {
		panic("pmap_rmt_call: clnt_tli_kcreate failed");
		/* NOTREACHED */
	}

	rpcb_args.prog = progn;
	rpcb_args.vers = versn;
	rpcb_args.proc = procn;
	rpcb_args.args_ptr = argsp;
	rpcb_args.xdr_args = xdrargs;
	rpcb_res.addr_ptr = ua;
	rpcb_res.results_ptr = resp;
	rpcb_res.xdr_results = xdrres;
	stat = clnt_clts_kcallit_addr(cl, PMAPPROC_CALLIT,
	    xdr_rpcb_rmtcallargs, (caddr_t)&rpcb_args,
	    xdr_rpcb_rmtcallres, (caddr_t)&rpcb_res,
	    tout, resp_addr);

	if (stat == RPC_SUCCESS)
		((struct sockaddr_in *)resp_addr->buf)->sin_port =
		    rpc_uaddr2port(AF_INET, ua);
	CLNT_DESTROY(cl);

	return (stat);
}

/*
 * XDR remote call arguments
 * written for XDR_ENCODE direction only
 */
static bool_t
myxdr_rmtcall_args(XDR *xdrs, struct rmtcallargs *cap)
{
	uint_t lenposition;
	uint_t argposition;
	uint_t position;

	if (xdr_rpcprog(xdrs, &(cap->prog)) &&
	    xdr_rpcvers(xdrs, &(cap->vers)) &&
	    xdr_rpcproc(xdrs, &(cap->proc))) {
		lenposition = XDR_GETPOS(xdrs);
		if (!xdr_u_int(xdrs, &cap->arglen))
			return (FALSE);
		argposition = XDR_GETPOS(xdrs);
		if (!(*(cap->xdr_args))(xdrs, cap->args_ptr))
			return (FALSE);
		position = XDR_GETPOS(xdrs);
		cap->arglen = (uint_t)position - (uint_t)argposition;
		XDR_SETPOS(xdrs, lenposition);
		if (!xdr_u_int(xdrs, &cap->arglen))
			return (FALSE);
		XDR_SETPOS(xdrs, position);
		return (TRUE);
	}
	return (FALSE);
}

/*
 * XDR remote call results
 * written for XDR_DECODE direction only
 */
static bool_t
myxdr_rmtcallres(XDR *xdrs, struct rmtcallres *crp)
{
	caddr_t port_ptr;

	port_ptr = (caddr_t)crp->port_ptr;
	if (xdr_reference(xdrs, &port_ptr, sizeof (uint_t), xdr_u_int) &&
	    xdr_u_int(xdrs, &crp->resultslen)) {
		crp->port_ptr = (rpcport_t *)port_ptr;
		return ((*(crp->xdr_results))(xdrs, crp->results_ptr));
	}
	return (FALSE);
}

static bool_t
myxdr_pmap(XDR *xdrs, struct pmap *regs)
{
	if (xdr_rpcprog(xdrs, &regs->pm_prog) &&
	    xdr_rpcvers(xdrs, &regs->pm_vers) &&
	    xdr_rpcprot(xdrs, &regs->pm_prot))
		return (xdr_rpcport(xdrs, &regs->pm_port));

	return (FALSE);
}

/*
 * From SunOS callrpc.c
 */
static enum clnt_stat
mycallrpc(struct knetconfig *knconf, struct netbuf *call_addr,
    rpcprog_t prognum, rpcvers_t versnum, rpcproc_t procnum,
    xdrproc_t inproc, char *in, xdrproc_t outproc, char *out,
    int timeo, int retries)
{
	CLIENT *cl;
	struct timeval tv;
	enum clnt_stat cl_stat;
	int rc;

	rc = clnt_tli_kcreate(knconf, call_addr, prognum, versnum,
	    0, retries, CRED(), &cl);
	if (rc) {
		nfs_perror(rc, "mycallrpc: clnt_tli_kcreate failed: %m\n");
		return (RPC_SYSTEMERROR);	/* XXX */
	}
	tv.tv_sec = timeo;
	tv.tv_usec = 0;
	cl_stat = CLNT_CALL(cl, procnum, inproc, in, outproc, out, tv);
	AUTH_DESTROY(cl->cl_auth);
	CLNT_DESTROY(cl);
	return (cl_stat);
}

/*
 * Configure the 'default' interface based on existing boot properties.
 */
static int
bp_netconfig(void)
{
	char *str;
	struct in_addr my_ip, my_netmask, my_router, my_broadcast;
	struct sockaddr_in *sin;
	TIUSER *tiptr;
	int rc;
	struct rtentry rtentry;

	my_ip.s_addr = my_netmask.s_addr = my_router.s_addr = 0;

	/*
	 * No way of getting this right now.  Collude with dlifconfig()
	 * to let the protocol stack choose.
	 */
	my_broadcast.s_addr = INADDR_BROADCAST;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_HOST_IP, &str) == DDI_SUCCESS) {
		if (inet_aton(str, (uchar_t *)&my_ip) != 0)
			cmn_err(CE_NOTE, "host-ip %s is invalid\n",
			    str);
		ddi_prop_free(str);
		if (dldebug)
			printf("host ip is %s\n",
			    inet_ntoa(my_ip));
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_SUBNET_MASK, &str) == DDI_SUCCESS) {
		if (inet_aton(str, (uchar_t *)&my_netmask) != 0)
			cmn_err(CE_NOTE, "subnet-mask %s is invalid\n",
			    str);
		ddi_prop_free(str);
		if (dldebug)
			printf("subnet mask is %s\n",
			    inet_ntoa(my_netmask));
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_ROUTER_IP, &str) == DDI_SUCCESS) {
		if (inet_aton(str, (uchar_t *)&my_router) != 0)
			cmn_err(CE_NOTE, "router-ip %s is invalid\n",
			    str);
		ddi_prop_free(str);
		if (dldebug)
			printf("router ip is %s\n",
			    inet_ntoa(my_router));
	}
	(void) ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_SERVER_PATH, &server_path_c);
	(void) ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_SERVER_NAME, &server_name_c);
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_SERVER_ROOTOPTS, &str) == DDI_SUCCESS) {
		(void) strlcpy(rootopts, str, sizeof (rootopts));
		ddi_prop_free(str);
	}
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, BP_SERVER_IP, &str) == DDI_SUCCESS) {
		if (inet_aton(str, server_ip) != 0)
			cmn_err(CE_NOTE, "server-ip %s is invalid\n",
			    str);
		ddi_prop_free(str);
		if (dldebug)
			printf("server ip is %s\n",
			    inet_ntoa(*(struct in_addr *)server_ip));
	}

	/*
	 * We need all of these to configure based on properties.
	 */
	if ((my_ip.s_addr == 0) ||
	    (my_netmask.s_addr == 0) ||
	    (server_path_c == NULL) ||
	    (server_name_c == NULL) ||
	    (*(uint_t *)server_ip == 0))
		return (-1);

	cmn_err(CE_CONT, "?IP address: %s\n", inet_ntoa(my_ip));
	cmn_err(CE_CONT, "?IP netmask: %s\n", inet_ntoa(my_netmask));
	if (my_router.s_addr != 0)
		cmn_err(CE_CONT, "?IP router: %s\n", inet_ntoa(my_router));
	cmn_err(CE_CONT, "?NFS server: %s (%s)\n", server_name_c,
	    inet_ntoa(*(struct in_addr *)server_ip));
	cmn_err(CE_CONT, "?NFS path: %s\n", server_path_c);

	/*
	 * Configure the interface.
	 */
	if ((rc = t_kopen((file_t *)NULL, dl_udp_netconf.knc_rdev,
	    FREAD|FWRITE, &tiptr, CRED())) != 0) {
		nfs_perror(rc, "bp_netconfig: t_kopen udp failed: %m.\n");
		return (rc);
	}

	if ((rc = dlifconfig(tiptr, &my_ip, &my_netmask, &my_broadcast,
	    0)) < 0) {
		nfs_perror(rc, "bp_netconfig: dlifconfig failed: %m.\n");
		(void) t_kclose(tiptr, 0);
		return (rc);
	}

	if (my_router.s_addr != 0) {
		/*
		 * Add a default route.
		 */
		sin = (struct sockaddr_in *)&rtentry.rt_dst;
		bzero(sin, sizeof (*sin));
		sin->sin_family = AF_INET;

		sin = (struct sockaddr_in *)&rtentry.rt_gateway;
		bzero(sin, sizeof (*sin));
		sin->sin_family = AF_INET;
		sin->sin_addr = my_router;

		rtentry.rt_flags = RTF_GATEWAY | RTF_UP;

		if ((rc = rtioctl(tiptr, SIOCADDRT, &rtentry)) != 0) {
			nfs_perror(rc,
			    "bp_netconfig: couldn't add route: %m.\n");
			(void) t_kclose(tiptr, 0);
			return (rc);
		}
	}

	(void) t_kclose(tiptr, 0);

	return (0);
}

/*
 * The network device we will use to boot from is plumbed. Extract the details
 * from rootfs.
 */
static void
init_config(void)
{
	(void) strlcpy(ndev_path, rootfs.bo_devname, sizeof (ndev_path));
	(void) strlcpy(ifname, rootfs.bo_ifname, sizeof (ifname));
	ifunit = rootfs.bo_ppa;

	/*
	 * Assumes only one linkage array element.
	 */
	dl_udp_netconf.knc_rdev =
	    makedevice(clone_major, ddi_name_to_major("udp"));
	dl_tcp_netconf.knc_rdev =
	    makedevice(clone_major, ddi_name_to_major("tcp"));

	/*
	 * Now we bringup the interface.
	 * Try cached dhcp response first. If it fails, do rarp.
	 */
	if ((bp_netconfig() != 0) &&
	    (dhcpinit() != 0) &&
	    (whoami() != 0))
		cmn_err(CE_WARN,
		    "%s: no response from interface", ifname);
	else if (dldebug)
		printf("init_config: ifname %s is up\n", ifname);
}

/*
 * These options are duplicated in cmd/fs.d/nfs/mount/mount.c
 * Changes must be made to both lists.
 */
static char *optlist[] = {
#define	OPT_RO		0
	MNTOPT_RO,
#define	OPT_RW		1
	MNTOPT_RW,
#define	OPT_QUOTA	2
	MNTOPT_QUOTA,
#define	OPT_NOQUOTA	3
	MNTOPT_NOQUOTA,
#define	OPT_SOFT	4
	MNTOPT_SOFT,
#define	OPT_HARD	5
	MNTOPT_HARD,
#define	OPT_SUID	6
	MNTOPT_SUID,
#define	OPT_NOSUID	7
	MNTOPT_NOSUID,
#define	OPT_GRPID	8
	MNTOPT_GRPID,
#define	OPT_REMOUNT	9
	MNTOPT_REMOUNT,
#define	OPT_NOSUB	10
	MNTOPT_NOSUB,
#define	OPT_INTR	11
	MNTOPT_INTR,
#define	OPT_NOINTR	12
	MNTOPT_NOINTR,
#define	OPT_PORT	13
	MNTOPT_PORT,
#define	OPT_SECURE	14
	MNTOPT_SECURE,
#define	OPT_RSIZE	15
	MNTOPT_RSIZE,
#define	OPT_WSIZE	16
	MNTOPT_WSIZE,
#define	OPT_TIMEO	17
	MNTOPT_TIMEO,
#define	OPT_RETRANS	18
	MNTOPT_RETRANS,
#define	OPT_ACTIMEO	19
	MNTOPT_ACTIMEO,
#define	OPT_ACREGMIN	20
	MNTOPT_ACREGMIN,
#define	OPT_ACREGMAX	21
	MNTOPT_ACREGMAX,
#define	OPT_ACDIRMIN	22
	MNTOPT_ACDIRMIN,
#define	OPT_ACDIRMAX	23
	MNTOPT_ACDIRMAX,
#define	OPT_BG		24
	MNTOPT_BG,
#define	OPT_FG		25
	MNTOPT_FG,
#define	OPT_RETRY	26
	MNTOPT_RETRY,
#define	OPT_NOAC	27
	MNTOPT_NOAC,
#define	OPT_NOCTO	28
	MNTOPT_NOCTO,
#define	OPT_LLOCK	29
	MNTOPT_LLOCK,
#define	OPT_POSIX	30
	MNTOPT_POSIX,
#define	OPT_VERS	31
	MNTOPT_VERS,
#define	OPT_PROTO	32
	MNTOPT_PROTO,
#define	OPT_SEMISOFT	33
	MNTOPT_SEMISOFT,
#define	OPT_NOPRINT	34
	MNTOPT_NOPRINT,
#define	OPT_SEC		35
	MNTOPT_SEC,
#define	OPT_LARGEFILES	36
	MNTOPT_LARGEFILES,
#define	OPT_NOLARGEFILES	37
	MNTOPT_NOLARGEFILES,
#define	OPT_PUBLIC	38
	MNTOPT_PUBLIC,
#define	OPT_DIRECTIO	39
	MNTOPT_FORCEDIRECTIO,
#define	OPT_NODIRECTIO	40
	MNTOPT_NOFORCEDIRECTIO,
#define	OPT_XATTR	41
	MNTOPT_XATTR,
#define	OPT_NOXATTR	42
	MNTOPT_NOXATTR,
#define	OPT_DEVICES	43
	MNTOPT_DEVICES,
#define	OPT_NODEVICES	44
	MNTOPT_NODEVICES,
#define	OPT_SETUID	45
	MNTOPT_SETUID,
#define	OPT_NOSETUID	46
	MNTOPT_NOSETUID,
#define	OPT_EXEC	47
	MNTOPT_EXEC,
#define	OPT_NOEXEC	48
	MNTOPT_NOEXEC,
	NULL
};

static int
isdigit(int ch)
{
	return (ch >= '0' && ch <= '9');
}

#define	isspace(c)	((c) == ' ' || (c) == '\t' || (c) == '\n')
#define	bad(val)	(val == NULL || !isdigit(*val))

static int
atoi(const char *p)
{
	int n;
	int c, neg = 0;

	if (!isdigit(c = *p)) {
		while (isspace(c))
			c = *++p;
		switch (c) {
		case '-':
			neg++;
			/* FALLTHROUGH */
		case '+':
			c = *++p;
		}
		if (!isdigit(c))
			return (0);
	}
	for (n = '0' - c; isdigit(c = *++p); ) {
		n *= 10; /* two steps to avoid unnecessary overflow */
		n += '0' - c; /* accum neg to avoid surprises at MAX */
	}
	return (neg ? n : -n);
}

/*
 * Default root read tsize XXX
 */
int nfs_root_rsize = 8 * 1024;		/* conservative for dumb NICs */
int nfs4_root_rsize = 32 * 1024;	/* only runs on TCP be aggressive */

/*
 * Default flags: NFSMNT_NOCTO|NFSMNT_LLOCK|NFSMNT_INT
 */
int nfs_rootopts = NFSMNT_NOCTO|NFSMNT_LLOCK|NFSMNT_INT;

static int
init_mountopts(struct nfs_args *args, int version, struct knetconfig **dl_cf,
    int *vfsflags)
{
	char servername[SYS_NMLN];
	static int first = 0;
	struct netbuf server_address;
	char *opts, *val;
	int vers;
	struct knetconfig *cf = *dl_cf;
	char rootoptsbuf[256];

	/*
	 * Set default mount options
	 */
	args->flags = nfs_rootopts;
	args->rsize = 0;
	args->flags |= NFSMNT_ACREGMIN;
	args->acregmin = ACMINMAX;
	args->flags |= NFSMNT_ACREGMAX;
	args->acregmax = ACMAXMAX;
	args->flags |= NFSMNT_ACDIRMIN;
	args->acdirmin = ACMINMAX;
	args->flags |= NFSMNT_ACDIRMAX;
	args->acdirmax = ACMAXMAX;

	*vfsflags = 0;

	/*
	 * Only look up the rootopts the first time, we store this in
	 * a static buffer but we are guaranteed to be single threaded
	 * and not reentrant.
	 */
	if (first == 0) {
		first++;

		init_netbuf(&server_address);

		if (getfile("rootopts", servername, &server_address,
		    rootopts)) {
			rootopts[0] = '\0';
			free_netbuf(&server_address);
			goto sanity;
		}
		free_netbuf(&server_address);
	}

	if (dldebug)
		printf("rootopts = %s\n", rootopts);

	/*
	 * We have to preserve rootopts for second time.
	 */
	(void) strncpy(rootoptsbuf, rootopts, sizeof (rootoptsbuf));
	rootoptsbuf[sizeof (rootoptsbuf) - 1] = '\0';
	opts = rootoptsbuf;
	while (*opts) {
		int opt;

		switch (opt = getsubopt(&opts, optlist, &val)) {
		/*
		 * Options that are defaults or meaningless so ignored
		 */
		case OPT_QUOTA:
		case OPT_NOQUOTA:
		case OPT_SUID:
		case OPT_DEVICES:
		case OPT_SETUID:
		case OPT_BG:
		case OPT_FG:
		case OPT_RETRY:
		case OPT_POSIX:
		case OPT_LARGEFILES:
		case OPT_XATTR:
		case OPT_NOXATTR:
		case OPT_EXEC:
			break;
		case OPT_RO:
			*vfsflags |= MS_RDONLY;
			break;
		case OPT_RW:
			*vfsflags &= ~(MS_RDONLY);
			break;
		case OPT_SOFT:
			args->flags |= NFSMNT_SOFT;
			args->flags &= ~(NFSMNT_SEMISOFT);
			break;
		case OPT_SEMISOFT:
			args->flags |= NFSMNT_SOFT;
			args->flags |= NFSMNT_SEMISOFT;
			break;
		case OPT_HARD:
			args->flags &= ~(NFSMNT_SOFT);
			args->flags &= ~(NFSMNT_SEMISOFT);
			break;
		case OPT_NOSUID:
		case OPT_NODEVICES:
		case OPT_NOSETUID:
		case OPT_NOEXEC:
			cmn_err(CE_WARN,
			    "nfs_dlboot: may not set root partition %s",
			    optlist[opt]);
			break;
		case OPT_GRPID:
			args->flags |= NFSMNT_GRPID;
			break;
		case OPT_REMOUNT:
			cmn_err(CE_WARN,
			    "nfs_dlboot: may not remount root partition");
			break;
		case OPT_INTR:
			args->flags |= NFSMNT_INT;
			break;
		case OPT_NOINTR:
			args->flags &= ~(NFSMNT_INT);
			break;
		case OPT_NOAC:
			args->flags |= NFSMNT_NOAC;
			break;
		case OPT_PORT:
			cmn_err(CE_WARN,
			    "nfs_dlboot: may not change root port number");
			break;
		case OPT_SECURE:
			cmn_err(CE_WARN,
			"nfs_dlboot: root mounted auth_unix, secure ignored");
			break;
		case OPT_NOCTO:
			args->flags |= NFSMNT_NOCTO;
			break;
		case OPT_RSIZE:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: rsize");
				break;
			}
			args->flags |= NFSMNT_RSIZE;
			args->rsize = atoi(val);
			break;
		case OPT_WSIZE:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: wsize");
				break;
			}
			args->flags |= NFSMNT_WSIZE;
			args->wsize = atoi(val);
			break;
		case OPT_TIMEO:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: timeo");
				break;
			}
			args->flags |= NFSMNT_TIMEO;
			args->timeo = atoi(val);
			break;
		case OPT_RETRANS:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: retrans");
				break;
			}
			args->flags |= NFSMNT_RETRANS;
			args->retrans = atoi(val);
			break;
		case OPT_ACTIMEO:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: actimeo");
				break;
			}
			args->flags |= NFSMNT_ACDIRMAX;
			args->flags |= NFSMNT_ACREGMAX;
			args->flags |= NFSMNT_ACDIRMIN;
			args->flags |= NFSMNT_ACREGMIN;
			args->acdirmin = args->acregmin = args->acdirmax =
			    args->acregmax = atoi(val);
			break;
		case OPT_ACREGMIN:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: acregmin");
				break;
			}
			args->flags |= NFSMNT_ACREGMIN;
			args->acregmin = atoi(val);
			break;
		case OPT_ACREGMAX:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: acregmax");
				break;
			}
			args->flags |= NFSMNT_ACREGMAX;
			args->acregmax = atoi(val);
			break;
		case OPT_ACDIRMIN:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: acdirmin");
				break;
			}
			args->flags |= NFSMNT_ACDIRMIN;
			args->acdirmin = atoi(val);
			break;
		case OPT_ACDIRMAX:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: acdirmax");
				break;
			}
			args->flags |= NFSMNT_ACDIRMAX;
			args->acdirmax = atoi(val);
			break;
		case OPT_LLOCK:
			args->flags |= NFSMNT_LLOCK;
			break;
		case OPT_VERS:
			if (bad(val)) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: invalid option: vers");
				break;
			}
			vers = atoi(val);
			/*
			 * If the requested version is less than what we
			 * chose, pretend the chosen version doesn't exist
			 */
			if (vers < version) {
				return (EPROTONOSUPPORT);
			}
			if (vers > version) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: version %d unavailable",
				    vers);
				return (EINVAL);
			}
			break;
		case OPT_PROTO:
			/*
			 * NFSv4 can only run over TCP, if they requested
			 * UDP pretend v4 doesn't exist, they might not have
			 * specified a version allowing a fallback to v2 or v3.
			 */
			if (version == NFS_V4 && strcmp(val, NC_UDP) == 0)
				return (EPROTONOSUPPORT);
			/*
			 * TCP is always chosen over UDP, so if the
			 * requested is the same as the chosen either
			 * they chose TCP when available or UDP on a UDP
			 * only server.
			 */
			if (strcmp(cf->knc_proto, val) == 0)
				break;
			/*
			 * If we chose UDP, they must have requested TCP
			 */
			if (strcmp(cf->knc_proto, NC_TCP) != 0) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: TCP protocol unavailable");
				return (EINVAL);
			}
			/*
			 * They can only have requested UDP
			 */
			if (strcmp(val, NC_UDP) != 0) {
				cmn_err(CE_WARN,
				    "nfs_dlboot: unknown protocol");
				return (EINVAL);
			}
			*dl_cf = &dl_udp_netconf;
			break;
		case OPT_NOPRINT:
			args->flags |= NFSMNT_NOPRINT;
			break;
		case OPT_NOLARGEFILES:
			cmn_err(CE_WARN,
			    "nfs_dlboot: NFS can't support nolargefiles");
			break;
		case OPT_SEC:
			cmn_err(CE_WARN,
			    "nfs_dlboot: root mounted auth_unix, sec ignored");
			break;

		case OPT_DIRECTIO:
			args->flags |= NFSMNT_DIRECTIO;
			break;

		case OPT_NODIRECTIO:
			args->flags &= ~(NFSMNT_DIRECTIO);
			break;

		default:
			cmn_err(CE_WARN,
			    "nfs_dlboot: ignoring invalid option \"%s\"", val);
			break;
		}
	}
sanity:
	/*
	 * Set some sane limits on read size
	 */
	if (!(args->flags & NFSMNT_RSIZE) || args->rsize == 0) {
		/*
		 * Establish defaults
		 */
		args->flags |= NFSMNT_RSIZE;
		if (version == NFS_V4)
			args->rsize = nfs4_root_rsize;
		else
			args->rsize = nfs_root_rsize;
		return (0);
	}
	/*
	 * No less than 512 bytes, otherwise it will take forever to boot
	 */
	if (args->rsize < 512)
		args->rsize = 512;
	/*
	 * If we are running over UDP, we cannot exceed 64KB, trim
	 * to 56KB to allow room for headers.
	 */
	if (*dl_cf == &dl_udp_netconf && args->rsize > (56 * 1024))
		args->rsize = 56 * 1024;
	return (0);
}
