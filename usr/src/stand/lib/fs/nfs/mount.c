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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T */
/*	All Rights Reserved */

#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <sys/t_lock.h>
#include <netdb.h>
#include "clnt.h"
#include <rpc/xdr.h>
#include <rpc/rpc_msg.h>
#include <rpc/rpc.h>
#include "brpc.h"
#include "auth_inet.h"
#include "pmap.h"
#include <rpcsvc/nfs_prot.h>
#include <rpcsvc/nfs4_prot.h>
#include "nfs_inet.h"
#include <rpcsvc/bootparam.h>
#include <dhcp_impl.h>
#include <rpcsvc/mount.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include "socket_inet.h"
#include "ipv4.h"
#include "mac.h"
#include <sys/bootdebug.h>
#include <errno.h>
#include "dhcpv4.h"
#include <sys/mntent.h>

/* ARP timeout in milliseconds for BOOTP/RARP */
#define	ARP_INETBOOT_TIMEOUT 1000

struct nfs_file		roothandle;			/* root file handle */
static char		root_hostname[SYS_NMLN];	/* server hostname */
static char		my_hostname[MAXHOSTNAMELEN];
static char		root_pathbuf[NFS_MAXPATHLEN];	/* the root's path */
static char		root_boot_file[NFS_MAXPATHLEN];	/* optional boot file */
static struct sockaddr_in root_to;			/* server sock ip */
							/* in network order */
CLIENT			*root_CLIENT = NULL;		/* CLIENT handle */
int dontroute = FALSE;	/* In case rarp/bootparams was selected */
char			rootopts[MAX_PATH_LEN];
static gid_t		fake_gids = 1;	/* fake gids list for auth_unix */

extern void set_default_filename(char *);	/* boot.c */

/*
 * xdr routines used by mount.
 */

bool_t
xdr_fhstatus(XDR *xdrs, struct fhstatus *fhsp)
{
	if (!xdr_int(xdrs, (int *)&fhsp->fhs_status))
		return (FALSE);
	if (fhsp->fhs_status == 0) {
		return (xdr_fhandle(xdrs, fhsp->fhstatus_u.fhs_fhandle));
	}
	return (TRUE);
}

bool_t
xdr_fhandle(XDR *xdrs, fhandle fhp)
{
	return (xdr_opaque(xdrs, (char *)fhp, NFS_FHSIZE));
}

bool_t
xdr_path(XDR *xdrs, char **pathp)
{
	return (xdr_string(xdrs, pathp, MNTPATHLEN));
}

bool_t
xdr_fhandle3(XDR *xdrs, fhandle3 *objp)
{
	return (xdr_bytes(xdrs, (char **)&objp->fhandle3_val,
				(uint_t *)&objp->fhandle3_len, FHSIZE3));
}

bool_t
xdr_mountstat3(XDR *xdrs, mountstat3 *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
xdr_mountres3_ok(XDR *xdrs, mountres3_ok *objp)
{
	if (!xdr_fhandle3(xdrs, &objp->fhandle))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->auth_flavors.auth_flavors_val,
			(uint_t *)&objp->auth_flavors.auth_flavors_len, ~0,
			sizeof (int), (xdrproc_t)xdr_int));
}

bool_t
xdr_mountres3(XDR *xdrs, mountres3 *objp)
{
	if (!xdr_mountstat3(xdrs, &objp->fhs_status))
		return (FALSE);
	if (objp->fhs_status == MNT_OK)
		return (xdr_mountres3_ok(xdrs, &objp->mountres3_u.mountinfo));
	return (TRUE);
}

static int
nfsmountroot(char *path, struct nfs_file *filep)
{
	int		rexmit;
	int		resp_wait;
	enum clnt_stat	status;
	struct fhstatus	root_tmp;			/* to pass to rpc/xdr */

	/*
	 * Wait up to 16 secs for first response, retransmitting expon.
	 */
	rexmit = 0;	/* default retransmission interval */
	resp_wait = 16;

	do {
		status = brpc_call((rpcprog_t)MOUNTPROG, (rpcvers_t)MOUNTVERS,
		    (rpcproc_t)MOUNTPROC_MNT, xdr_path, (caddr_t)&path,
		    xdr_fhstatus, (caddr_t)&(root_tmp), rexmit, resp_wait,
		    &root_to, NULL, AUTH_UNIX);
		if (status == RPC_TIMEDOUT) {
			dprintf("boot: %s:%s mount server not responding.\n",
			    root_hostname, path);
		}
		rexmit = resp_wait;
		resp_wait = 0;	/* use default wait time. */
	} while (status == RPC_TIMEDOUT);

	if ((status != RPC_SUCCESS) || (root_tmp.fhs_status != 0)) {
		nfs_error(root_tmp.fhs_status);
		root_to.sin_port = 0;
		return (-1);
	}

	/*
	 * Since the mount succeeded, we'll mark the filep's
	 * status as NFS_OK, and its type as NFDIR. If these
	 * points aren't the case, then we wouldn't be here.
	 */
	bcopy(&root_tmp.fhstatus_u.fhs_fhandle, &filep->fh.fh2, FHSIZE);
	filep->ftype.type2 = NFDIR;
	filep->version = NFS_VERSION;
	nfs_readsize = nfs_readsize <  NFS_MAXDATA ? nfs_readsize : NFS_MAXDATA;
	/*
	 * Set a reasonable lower limit on readsize
	 */
	nfs_readsize = (nfs_readsize != 0 && nfs_readsize < 512) ?
							512 : nfs_readsize;
	return (0);
}

int
setup_root_vars(void)
{
	size_t		buflen;
	uint16_t	readsize;

	/*
	 * Root server name. Required.
	 */
	buflen = sizeof (root_hostname);
	if (dhcp_getinfo(DSYM_VENDOR, VS_NFSMNT_ROOTSRVR_NAME, 0,
	    root_hostname, &buflen)) {
		root_hostname[buflen] = '\0';
	} else {
		dprintf("BOUND: Missing Root Server Name Option\n");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Root server IP. Required.
	 */
	buflen = sizeof (root_to.sin_addr);
	if (!dhcp_getinfo(DSYM_VENDOR, VS_NFSMNT_ROOTSRVR_IP, 0,
	    &root_to.sin_addr, &buflen)) {
		dprintf("BOUND: Missing Root Server IP Option\n");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Root path Required.
	 */
	buflen = sizeof (root_pathbuf);
	if (dhcp_getinfo(DSYM_VENDOR, VS_NFSMNT_ROOTPATH, 0,
	    root_pathbuf, &buflen)) {
		root_pathbuf[buflen] = '\0';
	} else {
		dprintf("BOUND: Missing Root Path Option\n");
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Optional Bootfile path.
	 */
	buflen = sizeof (root_boot_file);
	if (dhcp_getinfo(DSYM_VENDOR, VS_NFSMNT_BOOTFILE, 0,
		    root_boot_file, &buflen)) {
		root_boot_file[buflen] = '\0';
		dprintf("BOUND: Optional Boot File is: %s\n", root_boot_file);
	}

	/* if we got a boot file name, use it as the default */
	if (root_boot_file[0] != '\0')
		set_default_filename(root_boot_file);

	/*
	 * Set the NFS read size. The mount code will adjust it to
	 * the maximum size.
	 */
	buflen = sizeof (readsize);
	if (dhcp_getinfo(DSYM_VENDOR, VS_BOOT_NFS_READSIZE, 0,
	    &readsize, &buflen)) {
		nfs_readsize = ntohs(readsize);
		if (boothowto & RB_VERBOSE) {
			printf("Boot NFS read size: %d\n", nfs_readsize);
		}
	}

	/*
	 * Optional rootopts.
	 */
	buflen = sizeof (rootopts);
	if (dhcp_getinfo(DSYM_VENDOR, VS_NFSMNT_ROOTOPTS, 0,
	    rootopts, &buflen)) {
		rootopts[buflen] = '\0';
		dprintf("BOUND: Optional Rootopts is: %s\n", rootopts);
	}

	return (0);
}

static void
mnt3_error(enum mountstat3 status)
{
	if (!(boothowto & RB_DEBUG))
		return;

	switch (status) {
	case MNT_OK:
		printf("Mount: No error.\n");
		break;
	case MNT3ERR_PERM:
		printf("Mount: Not owner.\n");
		break;
	case MNT3ERR_NOENT:
		printf("Mount: No such file or directory.\n");
		break;
	case MNT3ERR_IO:
		printf("Mount: I/O error.\n");
		break;
	case MNT3ERR_ACCES:
		printf("Mount: Permission denied.\n");
		break;
	case MNT3ERR_NOTDIR:
		printf("Mount: Not a directory.\n");
		break;
	case MNT3ERR_INVAL:
		printf("Mount: Invalid argument.\n");
		break;
	case MNT3ERR_NAMETOOLONG:
		printf("Mount: File name too long.\n");
		break;
	case MNT3ERR_NOTSUPP:
		printf("Mount: Operation not supported.\n");
		break;
	case MNT3ERR_SERVERFAULT:
		printf("Mount: Server fault.\n");
		break;
	default:
		printf("Mount: unknown error.\n");
		break;
	}
}

static int
nfs3mountroot(char *path, struct nfs_file *filep)
{
	int		rexmit;
	int		resp_wait;
	struct mountres3 res3;
	enum clnt_stat	status;

	/*
	 * Wait up to 16 secs for first response, retransmitting expon.
	 */
	rexmit = 0;	/* default retransmission interval */
	resp_wait = 16;

	/*
	 * Try to mount using V3
	 */
	do {
		bzero(&res3, sizeof (struct mountres3));

		status = brpc_call((rpcprog_t)MOUNTPROG, (rpcvers_t)MOUNTVERS3,
		    (rpcproc_t)MOUNTPROC_MNT, xdr_path, (caddr_t)&path,
		    xdr_mountres3, (caddr_t)&res3, rexmit, resp_wait,
		    &root_to, NULL, AUTH_UNIX);

		if (status != RPC_TIMEDOUT)
			break;

		dprintf("boot: %s:%s mount server not responding.\n",
			    root_hostname, path);

		rexmit = resp_wait;
		resp_wait = 0;	/* use default wait time. */

		xdr_free(xdr_mountres3, (caddr_t)&res3);
	} while (status == RPC_TIMEDOUT);

	if ((status != RPC_SUCCESS) || (res3.fhs_status != MNT_OK)) {
		mnt3_error(res3.fhs_status);
		root_to.sin_port = 0;
		return (-1);
	}

	/*
	 * Since the mount succeeded, we'll mark the filep's
	 * status as NFS_OK, and its type as NF3DIR. If these
	 * points aren't the case, then we wouldn't be here.
	 */
	filep->fh.fh3.len = res3.mountres3_u.mountinfo.fhandle.fhandle3_len;
	bcopy(res3.mountres3_u.mountinfo.fhandle.fhandle3_val,
			filep->fh.fh3.data,
			filep->fh.fh3.len);
	filep->ftype.type3 = NF3DIR;
	filep->version = NFS_V3;
	/*
	 * Hardwire in a known reasonable upper limit of 32K
	 */
	nfs_readsize = nfs_readsize <  32 * 1024 ? nfs_readsize : 32 * 1024;
	/*
	 * Set a reasonable lower limit on readsize
	 */
	nfs_readsize = (nfs_readsize != 0 && nfs_readsize < 512) ?
							512 : nfs_readsize;
	xdr_free(xdr_mountres3, (caddr_t)&res3);
	return (0);
}

/*
 * Setup v4 client for inetboot
 */
static int
nfs4init(char *path, uint16_t nfs_port)
{
	struct timeval	wait;
	int		fd = -1;
	int		error = 0;
	enum clnt_stat	rpc_stat;
	struct nfs_file	rootpath;

	wait.tv_sec = RPC_RCVWAIT_MSEC / 1000;
	wait.tv_usec = 0;

	/*
	 * If we haven't explicitly set the port number, set to the standard
	 * 2049 and don't cause a rpcbind request.
	 */
	if (nfs_port == 0)
		nfs_port = 2049;

	root_to.sin_port = htons(nfs_port);

	/*
	 * Support TCP only
	 */
	root_CLIENT = clntbtcp_create(&root_to, NFS_PROGRAM,
					NFS_V4, wait, &fd,
					NFS4BUF_SIZE, NFS4BUF_SIZE);

	if (root_CLIENT == NULL) {
		root_to.sin_port = 0;
		return (-1);
	}

	root_CLIENT->cl_auth =
			authunix_create(my_hostname, 0, 1, 1, &fake_gids);

	/*
	 * Send NULL proc the server first to see if V4 exists
	 */
	rpc_stat = CLNT_CALL(root_CLIENT, NFSPROC4_NULL, xdr_void, NULL,
				xdr_void, NULL, wait);

	if (rpc_stat != RPC_SUCCESS) {
		dprintf("boot: NULL proc failed NFSv4 service not available\n");
		AUTH_DESTROY(root_CLIENT->cl_auth);
		CLNT_DESTROY(root_CLIENT);
		root_to.sin_port = 0;
		return (-1);
	}

	/*
	 * Do a lookup to get to the root_path.  This is nice since it can
	 * handle multicomponent lookups.
	 */
	roothandle.version = NFS_V4;
	roothandle.ftype.type4 = NF4DIR;
	roothandle.fh.fh4.len = 0;		/* Force a PUTROOTFH */
	roothandle.offset = (uint_t)0;		/* it's a directory! */
	error = lookup(path, &rootpath, TRUE);

	if (error) {
		printf("boot: lookup %s failed\n", path);
		return (-1);
	}
	roothandle = rootpath;	/* structure copy */

	/*
	 * Hardwire in a known reasonable upper limit of 32K
	 */
	nfs_readsize = nfs_readsize <  32 * 1024 ? nfs_readsize : 32 * 1024;
	/*
	 * Set a reasonable lower limit on readsize
	 */
	nfs_readsize = (nfs_readsize != 0 && nfs_readsize < 512) ?
							512 : nfs_readsize;

	return (0);
}

static int
atoi(const char *p)
{
	int n;
	int c, neg = 0;

	if (!isdigit(c = *p)) {
		while (c == ' ' || c == '\t' || c == '\n')
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
 * Parse suboptions from a string.
 * Same as getsubopt(3C).
 */
static int
getsubopt(char **optionsp, char * const *tokens, char **valuep)
{
	char *s = *optionsp, *p;
	int i;
	size_t optlen;

	*valuep = NULL;
	if (*s == '\0')
		return (-1);
	p = strchr(s, ',');		/* find next option */
	if (p == NULL) {
		p = s + strlen(s);
	} else {
		*p++ = '\0';		/* mark end and point to next */
	}
	*optionsp = p;			/* point to next option */
	p = strchr(s, '=');		/* find value */
	if (p == NULL) {
		optlen = strlen(s);
		*valuep = NULL;
	} else {
		optlen = p - s;
		*valuep = ++p;
	}
	for (i = 0; tokens[i] != NULL; i++) {
		if ((optlen == strlen(tokens[i])) &&
		    (strncmp(s, tokens[i], optlen) == 0))
			return (i);
	}
	/* no match, point value at option and return error */
	*valuep = s;
	return (-1);
}

/*
 * The only interesting NFS mount options for initiating the kernel
 * all others are ignored.
 */
static char *optlist[] = {
#define	OPT_RSIZE	0
	MNTOPT_RSIZE,
#define	OPT_TIMEO	1
	MNTOPT_TIMEO,
#define	OPT_VERS	2
	MNTOPT_VERS,
#define	OPT_PROTO	3
	MNTOPT_PROTO,
#define	OPT_PORT	4
	MNTOPT_PORT,
	NULL
};

/*
 * This routine will open a device as it is known by the V2 OBP. It
 * then goes thru the stuff necessary to initialize the network device,
 * get our network parameters, (using DHCP or rarp/bootparams), and
 * finally actually go and get the root filehandle. Sound like fun?
 * Suuurrrree. Take a look.
 *
 * Returns 0 if things worked. -1 if we crashed and burned.
 */
int
boot_nfs_mountroot(char *str)
{
	int		status;
	enum clnt_stat	rpc_stat;
	char		*root_path = &root_pathbuf[0];	/* to make XDR happy */
	struct timeval	wait;
	int		fd;
	int		bufsize;
	char		*opts, *val;
	int		nfs_version = 0;
	int		istcp = 1;
	int		nfs_port = 0;	/* Cause pmap to get port */
	struct sockaddr_in tmp_addr;	/* throw away */

	if (root_CLIENT != NULL) {
		AUTH_DESTROY(root_CLIENT->cl_auth);
		CLNT_DESTROY(root_CLIENT);
		root_CLIENT = NULL;
	}

	root_to.sin_family = AF_INET;
	root_to.sin_addr.s_addr = htonl(INADDR_ANY);
	root_to.sin_port = htons(0);

	mac_init(str);

	(void) ipv4_setpromiscuous(TRUE);

	if (get_netconfig_strategy() == NCT_BOOTP_DHCP) {
		if (boothowto & RB_VERBOSE)
			printf("Using BOOTP/DHCP...\n");
		if (dhcp() != 0 || setup_root_vars() != 0) {
			(void) ipv4_setpromiscuous(FALSE);
			if (boothowto & RB_VERBOSE)
				printf("BOOTP/DHCP configuration failed!\n");
			return (-1);
		}

		/* now that we have an IP address, turn off promiscuous mode */
		(void) ipv4_setpromiscuous(FALSE);
	} else {
		/* Use RARP/BOOTPARAMS. RARP will try forever... */
		if (boothowto & RB_VERBOSE)
			printf("Using RARP/BOOTPARAMS...\n");
		mac_call_rarp();

		/*
		 * Since there is no way to determine our netmask, and therefore
		 * figure out if the router we got is useful, we assume all
		 * services are local. Use DHCP if this bothers you.
		 */
		dontroute = TRUE;
		/*
		 * We are trying to keep the ARP response
		 * timeout on the lower side with BOOTP/RARP.
		 * We are doing this for BOOTP/RARP where policy
		 * doesn't allow to route the packets outside
		 * the subnet as it has no idea about the
		 * netmask. By doing so, we are reducing
		 * ARP response timeout for any packet destined
		 * for outside booting clients subnet. Client can
		 * not expect such ARP replies and will finally
		 * timeout after a long delay. This would cause
		 * booting client to get stalled for a longer
		 * time. We can not avoid accepting any outside
		 * subnet packets accidentally destined for the
		 * booting client.
		 */
		mac_set_arp_timeout(ARP_INETBOOT_TIMEOUT);

		/* now that we have an IP address, turn off promiscuous mode */
		(void) ipv4_setpromiscuous(FALSE);

		/* get our hostname */
		if (whoami() == FALSE)
			return (-1);

		/* get our bootparams. */
		if (getfile("root", root_hostname, &root_to.sin_addr,
		    root_pathbuf) == FALSE)
			return (-1);

		/* get our rootopts. */
		(void) getfile("rootopts", root_hostname, &tmp_addr.sin_addr,
		    rootopts);
	}

	/* mount root */
	if (boothowto & RB_VERBOSE) {
		printf("root server: %s (%s)\n", root_hostname,
		    inet_ntoa(root_to.sin_addr));
		printf("root directory: %s\n", root_pathbuf);
	}

	/*
	 * Assumes we've configured the stack and thus know our
	 * IP address/hostname, either by using DHCP or rarp/bootparams.
	 */
	(void) gethostname(my_hostname, sizeof (my_hostname));

	wait.tv_sec = RPC_RCVWAIT_MSEC / 1000;
	wait.tv_usec = 0;

	/*
	 * Parse out the interesting root options, if an invalid
	 * or unknown option is provided, silently ignore it and
	 * use the defaults.
	 */
	opts = rootopts;
	while (*opts) {
		int ival;
		switch (getsubopt(&opts, optlist, &val)) {
		case OPT_RSIZE:
			if (val == NULL || !isdigit(*val))
				break;
			nfs_readsize = atoi(val);
			break;
		case OPT_TIMEO:
			if (val == NULL || !isdigit(*val))
				break;
			ival = atoi(val);
			wait.tv_sec = ival / 10;
			wait.tv_usec = (ival % 10) * 100000;
			break;
		case OPT_VERS:
			if (val == NULL || !isdigit(*val))
				break;
			nfs_version = atoi(val);
			break;
		case OPT_PROTO:
			if (val == NULL || isdigit(*val))
				break;
			if ((strncmp(val, "udp", 3) == 0))
				istcp = 0;
			else
				istcp = 1;	/* must be tcp */
			break;
		case OPT_PORT:
			if (val == NULL || !isdigit(*val))
				break;
			nfs_port = atoi(val);

			/*
			 * Currently nfs_dlinet.c doesn't support setting
			 * the root NFS port. Delete this when it does.
			 */
			nfs_port = 0;
			break;
		default:
			/*
			 * Unknown options are silently ignored
			 */
			break;
		}
	}

	/*
	 * If version is set, then try that version first.
	 */
	switch (nfs_version) {
	case NFS_VERSION:
		if (nfsmountroot(root_path, &roothandle) == 0)
			goto domount;
		break;
	case NFS_V3:
		if (nfs3mountroot(root_path, &roothandle) == 0)
			goto domount;
		break;
	case NFS_V4:
		/*
		 * With v4 we skip the mount and go straight to
		 * setting the root filehandle.  Because of this we
		 * do things slightly differently and obtain our
		 * client handle first.
		 */
		if (istcp && nfs4init(root_path, nfs_port) == 0) {
			/*
			 * If v4 init succeeded then we are done.  Just return.
			 */
			return (0);
		}
	}

	/*
	 * If there was no chosen version or the chosen version failed
	 * try all versions in order, this may still fail to boot
	 * at the kernel level if the options are not right, but be
	 * generous at this early stage.
	 */
	if (istcp && nfs4init(root_path, nfs_port) == 0) {
		/*
		 * If v4 init succeeded then we are done.  Just return.
		 */
		return (0);
	}

	if (nfs3mountroot(root_path, &roothandle) == 0)
		goto domount;

	if ((status = nfsmountroot(root_path, &roothandle)) != 0)
		return (status);

domount:
	/*
	 * Only v2 and v3 go on from here.
	 */
	roothandle.offset = (uint_t)0;		/* it's a directory! */
	root_to.sin_port = htons(nfs_port);	/* NFS is next after mount */

	/*
	 * Create the CLIENT handle for NFS operations
	 */
	if (roothandle.version == NFS_VERSION)
		bufsize = NFSBUF_SIZE;
	else
		bufsize = NFS3BUF_SIZE;

	/*
	 * First try TCP then UDP (unless UDP asked for explicitly), if mountd
	 * alows this version but neither transport is available we are stuck.
	 */
	if (istcp) {
		fd = -1;
		root_CLIENT = clntbtcp_create(&root_to, NFS_PROGRAM,
			roothandle.version, wait, &fd, bufsize, bufsize);
		if (root_CLIENT != NULL) {
			root_CLIENT->cl_auth =
			    authunix_create(my_hostname, 0, 1, 1, &fake_gids);
			/*
			 * Send NULL proc, check if the server really exists
			 */
			rpc_stat = CLNT_CALL(root_CLIENT, 0,
					xdr_void, NULL, xdr_void, NULL, wait);

			if (rpc_stat == RPC_SUCCESS)
				return (0);

			AUTH_DESTROY(root_CLIENT->cl_auth);
			CLNT_DESTROY(root_CLIENT);
			root_CLIENT = NULL;
		}
		/* Fall through to UDP case */
	}

	fd = -1;
	root_CLIENT = clntbudp_bufcreate(&root_to, NFS_PROGRAM,
			roothandle.version, wait, &fd, bufsize, bufsize);
	if (root_CLIENT == NULL)
		return (-1);

	root_CLIENT->cl_auth =
			    authunix_create(my_hostname, 0, 1, 1, &fake_gids);
	/*
	 * Send NULL proc, check if the server really exists
	 */
	rpc_stat = CLNT_CALL(root_CLIENT, 0,
				xdr_void, NULL, xdr_void, NULL, wait);

	if (rpc_stat == RPC_SUCCESS)
		return (0);

	AUTH_DESTROY(root_CLIENT->cl_auth);
	CLNT_DESTROY(root_CLIENT);
	root_CLIENT = NULL;
	return (-1);
}
