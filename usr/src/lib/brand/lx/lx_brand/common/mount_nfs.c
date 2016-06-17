/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * NFS mount syscall support
 *
 * All of the Linux NFS mount RPC support is handled within the kernel whereas
 * on Illumos the NFS mount command performs the initial RPC calls to contact
 * the server's mountd, get the file handle, and negotiate security before
 * making the actual 'mount' syscall. Thus we emulate the Linux in-kernel
 * RPC behavior here using code that is partially based on the code from our
 * user-level NFS mount command. This code also includes the nullproc RPC
 * function calls
 *
 * In addition to the code described above we also have brand-specific code to
 * convert the Linux mount arguments into our native format.
 *
 * Because libnsl (which we need to make RPCs) depends on the netconfig table
 * (which won't exist inside an lx zone) we provide a built-in default
 * netconfig table which we hook into libnsl via the brand callbacks. See
 *	_nsl_brand_set_hooks(lx_nsl_set_sz_func, lx_get_ent_func)
 * in lx_nfs_mount().
 *
 * Finally, in most of the functions below, when the code refers to the
 * hostname we're really working with the IP addr that the Linux user-level
 * mount command passed in to us.
 */

/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#define	NFSCLIENT
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <netdb.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <nfs/nfs.h>
#include <nfs/mount.h>
#include <rpcsvc/mount.h>
#include <sys/pathconf.h>
#include <netdir.h>
#include <netconfig.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <nfs/nfs_sec.h>
#include <rpcsvc/daemon_utils.h>
#include <rpcsvc/nfs4_prot.h>
#include <limits.h>
#include <nfs/nfssys.h>
#include <strings.h>
#include <assert.h>
#include <sys/lx_mount.h>
#include <sys/lx_misc.h>

#ifndef	NFS_VERSMAX
#define	NFS_VERSMAX	4
#endif
#ifndef	NFS_VERSMIN
#define	NFS_VERSMIN	2
#endif

#define	RET_OK		0
#define	RET_RETRY	32
#define	RET_ERR		33
#define	RET_PROTOUNSUPP	34
#define	RET_MNTERR	1000
#define	ERR_PROTO_NONE		0
#define	ERR_PROTO_INVALID	901
#define	ERR_PROTO_UNSUPP	902
#define	ERR_NETPATH		903
#define	ERR_NOHOST		904
#define	ERR_RPCERROR		905

typedef struct err_ret {
	int error_type;
	int error_value;
} err_ret_t;

#define	SET_ERR_RET(errst, etype, eval) \
	{ \
	(errst)->error_type = etype; \
	(errst)->error_value = eval; \
	}

/*
 * Built-in netconfig table.
 */
#define	N_NETCONF_ENTS	4
static struct netconfig nca[N_NETCONF_ENTS] = {
	{"udp6", NC_TPI_CLTS,     1, "inet6", "udp", "/dev/udp6", 0, NULL},
	{"tcp6", NC_TPI_COTS_ORD, 1, "inet6", "tcp", "/dev/tcp6", 0, NULL},
	{"udp",  NC_TPI_CLTS,     1, "inet",  "udp", "/dev/udp", 0, NULL},
	{"tcp",  NC_TPI_COTS_ORD, 1, "inet",  "tcp", "/dev/tcp", 0, NULL}
};

/*
 * Mapping table of Linux NFS mount options to the corresponding Illumos
 * option. The nmo_argtyp field tells us how to handle the argument.
 */
typedef enum map_mount_opt_type {
	MOUNT_OPT_INVALID	= 0,
	MOUNT_OPT_PASTHRU	= 1,
	MOUNT_OPT_IGNORE	= 2,
	MOUNT_OPT_TOKEN		= 3,
	MOUNT_OPT_HAS_ARG	= 4
} map_mount_opt_type_t;

typedef struct nfs_map_opt {
	char			*nmo_lx_opt;
	char			*nmo_il_opt;
	map_mount_opt_type_t	nmo_argtyp;
} nfs_map_opt_t;

static nfs_map_opt_t nmo_tab[] = {
	{"ac",		NULL,		MOUNT_OPT_IGNORE},
	{"acdirmax",	NULL,		MOUNT_OPT_PASTHRU},
	{"acdirmin",	NULL,		MOUNT_OPT_PASTHRU},
	{"acl",		NULL,		MOUNT_OPT_INVALID},
	{"acregmax",	NULL,		MOUNT_OPT_PASTHRU},
	{"acregmin",	NULL,		MOUNT_OPT_PASTHRU},
	{"actimeo",	NULL,		MOUNT_OPT_PASTHRU},
	{"bg",		NULL,		MOUNT_OPT_PASTHRU},
	{"cto",		NULL,		MOUNT_OPT_IGNORE},
	{"fg",		NULL,		MOUNT_OPT_PASTHRU},
	{"fsc",		NULL,		MOUNT_OPT_IGNORE},
	{"hard",	NULL,		MOUNT_OPT_PASTHRU},
	{"intr",	NULL,		MOUNT_OPT_PASTHRU},
	{"lock",	NULL,		MOUNT_OPT_IGNORE},
	{"lookupcache",	NULL,		MOUNT_OPT_INVALID},
	{"local_lock=%s", NULL,		MOUNT_OPT_INVALID },
	{"migration",	NULL,		MOUNT_OPT_INVALID},
	{"minorversion", NULL,		MOUNT_OPT_INVALID},
	{"mountaddr",	NULL,		MOUNT_OPT_INVALID},
	{"mounthost",	NULL,		MOUNT_OPT_INVALID},
	{"mountport",	NULL,		MOUNT_OPT_PASTHRU},
	{"mountproto",	NULL,		MOUNT_OPT_PASTHRU},
	{"mountvers",	NULL,		MOUNT_OPT_PASTHRU},
	{"namlen",	NULL,		MOUNT_OPT_INVALID},
	{"nfsvers",	NULL,		MOUNT_OPT_INVALID},
	{"noac",	NULL,		MOUNT_OPT_PASTHRU},
	{"noacl",	NULL,		MOUNT_OPT_INVALID},
	{"nocto",	NULL,		MOUNT_OPT_PASTHRU},
	{"nofsc",	NULL,		MOUNT_OPT_IGNORE},
	{"nointr",	NULL,		MOUNT_OPT_PASTHRU},
	{"nolock",	"llock",	MOUNT_OPT_TOKEN},
	{"nomigration",	NULL,		MOUNT_OPT_INVALID},
	{"noposix",	NULL,		MOUNT_OPT_IGNORE},
	{"nordirplus",	NULL,		MOUNT_OPT_IGNORE},
	{"noresvport",	NULL,		MOUNT_OPT_INVALID},
	{"nosharecache", NULL,		MOUNT_OPT_IGNORE},
	{"port",	NULL,		MOUNT_OPT_PASTHRU},
	{"posix",	NULL,		MOUNT_OPT_PASTHRU},
	{"proto",	NULL,		MOUNT_OPT_PASTHRU},
	{"rdirplus",	NULL,		MOUNT_OPT_IGNORE},
	{"rdma",	"proto=rdma",	MOUNT_OPT_TOKEN},
	{"resvport",	NULL,		MOUNT_OPT_IGNORE},
	{"retrans",	NULL,		MOUNT_OPT_PASTHRU},
	{"retry",	NULL,		MOUNT_OPT_PASTHRU},
	{"rsize",	NULL,		MOUNT_OPT_PASTHRU},
	{"sec",		NULL,		MOUNT_OPT_PASTHRU},
	{"sharecache",	NULL,		MOUNT_OPT_IGNORE},
	{"sloppy",	NULL,		MOUNT_OPT_IGNORE},
	{"soft",	NULL,		MOUNT_OPT_PASTHRU},
	{"tcp",		"proto=tcp",	MOUNT_OPT_TOKEN},
	{"timeo",	NULL,		MOUNT_OPT_PASTHRU},
	{"udp",		"proto=udp",	MOUNT_OPT_TOKEN},
	{"vers",	NULL,		MOUNT_OPT_PASTHRU},
	{"wsize",	NULL,		MOUNT_OPT_PASTHRU},
	{NULL,		NULL,		MOUNT_OPT_INVALID}
};

/*
 * This struct is used to keep track of misc. variables which are set deep
 * in one function then referenced someplace else. We pass this around to
 * avoid the use of global variables as is done the the NFS mount command.
 *
 * The nfsvers variables control the NFS version number to be used.
 *
 * nmd_nfsvers defaults to 0 which means to use the highest number that
 * both the client and the server support.  It can also be set to
 * a particular value, either 2, 3, or 4 to indicate the version
 * number of choice.  If the server (or the client) do not support
 * the version indicated, then the mount attempt will be failed.
 *
 * nmd_nfsvers_to_use is the actual version number found to use.  It
 * is determined in get_fh by pinging the various versions of the
 * NFS service on the server to see which responds positively.
 *
 * nmd_nfsretry_vers is the version number set when we retry the mount
 * command with the version decremented from nmd_nfsvers_to_use.
 * nmd_nfsretry_vers is set from nmd_nfsvers_to_use when we retry the mount
 * for errors other than RPC errors; it helps us know why we are
 * retrying. It is an indication that the retry is due to non-RPC errors.
 */
typedef struct nfs_mnt_data {
	int		nmd_bg;
	int		nmd_posix;
	int		nmd_retries;
	ushort_t	nmd_nfs_port;
	char		*nmd_nfs_proto;
	char		*nmd_fstype;
	seconfig_t	nmd_nfs_sec;
	int		nmd_sec_opt;	/* any security option ? */
	rpcvers_t	nmd_nfsvers;
	rpcvers_t	nmd_nfsvers_to_use;
	rpcvers_t	nmd_nfsretry_vers;
} nfs_mnt_data_t;

/* number of transports to try */
#define	MNT_PREF_LISTLEN	2
#define	FIRST_TRY		1
#define	SECOND_TRY		2

#define	BIGRETRY	10000

/* maximum length of RPC header for NFS messages */
#define	NFS_RPC_HDR	432

#define	NFS_ARGS_EXTB_secdata(args, secdata) \
	{ (args)->nfs_args_ext = NFS_ARGS_EXTB, \
	(args)->nfs_ext_u.nfs_extB.secdata = secdata; }

extern int __clnt_bindresvport(CLIENT *);

static int retry(struct mnttab *, int, nfs_mnt_data_t *);
static int set_args(int *, struct nfs_args *, char *, struct mnttab *,
    nfs_mnt_data_t *);
static int get_fh(struct nfs_args *, char *, char *, int *,
	struct netconfig **, ushort_t, nfs_mnt_data_t *);
static int make_secure(struct nfs_args *, char *, struct netconfig *,
	rpcvers_t, nfs_mnt_data_t *);
static int mount_nfs(struct mnttab *, int, err_ret_t *, nfs_mnt_data_t *);
static int getaddr_nfs(struct nfs_args *, char *, struct netconfig **,
	ushort_t, err_ret_t *, bool_t, nfs_mnt_data_t *);
static struct netbuf *get_addr(char *, rpcprog_t, rpcvers_t,
	struct netconfig **, char *, ushort_t, struct t_info *, err_ret_t *);
static struct netbuf *get_the_addr(char *, rpcprog_t, rpcvers_t,
	struct netconfig *, ushort_t, struct t_info *, err_ret_t *);

static int lx_nsl_set_sz_func(void);
static struct netconfig *lx_get_ent_func(int);

/*
 * These are the defaults (range) for the client when determining
 * which NFS version to use when probing the server (see above).
 * These will only be used when the vers mount option is not used.
 */
#define	vers_max_default NFS_VERSMAX_DEFAULT
#define	vers_min_default NFS_VERSMIN_DEFAULT

/*
 * The wnl/WNL* definitions come from cmd/fs.d/nfs/mount/webnfs.h. We
 * incorporate those here since the cmd src tree hierarchy is not built when
 * we're compiling the lib portion of the src tree and since these definitions
 * are a fundamental part of the protocol spec, there is no risk of these
 * changing (i.e. we're just like the Linux kernel here, which has these
 * built-in). We only need the bare minimum set of definitions to make RPCs to
 * the NFS server to negotiate the mount.
 */

/* The timeout for our mount null proc pings is always 5 seconds. */
static struct timeval TIMEOUT = { 5, 0 };
#define	WNLPROC_NULL	0
#define	WNLPROC3_NULL	0
#define	WNLPROC4_NULL	0
#define	WNL_FHSIZE	32

static enum clnt_stat
wnlproc_null_2(void *argp, void *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, WNLPROC_NULL, (xdrproc_t)xdr_void,
	    (caddr_t)argp, (xdrproc_t)xdr_void, (caddr_t)clnt_res, TIMEOUT));
}

static enum clnt_stat
wnlproc3_null_3(void *argp, void *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, WNLPROC3_NULL, (xdrproc_t)xdr_void,
	    (caddr_t)argp, (xdrproc_t)xdr_void, (caddr_t)clnt_res, TIMEOUT));
}

static enum clnt_stat
wnlproc4_null_4(void *argp, void *clnt_res, CLIENT *clnt)
{
	return (clnt_call(clnt, WNLPROC4_NULL, (xdrproc_t)xdr_void,
	    (caddr_t)argp, (xdrproc_t)xdr_void, (caddr_t)clnt_res, TIMEOUT));
}

static void
log_err(const char *fmt, ...)
{
	va_list ap;
	char buf[128];
	int fd;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	if ((fd = open("/dev/conslog", O_WRONLY)) != -1) {
		(void) write(fd, buf, strlen(buf));
		(void) close(fd);
	}
}

static int
i_add_option(char *option, char *buf, size_t buf_size)
{
	int len;
	char *fmt_str = NULL;

	if (buf[0] == '\0') {
		fmt_str = "%s";
	} else {
		fmt_str = ",%s";
	}

	len = strlen(buf);
	buf_size -= len;
	buf += len;

	/*LINTED*/
	if (snprintf(buf, buf_size, fmt_str, option) > (buf_size - 1))
		return (-EOVERFLOW);
	return (0);
}

/*
 * We can return a negative error value which is the errno we need to return to
 * lx or we can return a positive error value which is primarily used to
 * indicate retry (otherwise we map to -EINVAL in the caller). Returning 0
 * indicates success.
 */
static int
mount_nfs(struct mnttab *mntp, int mntflags, err_ret_t *retry_error,
    nfs_mnt_data_t *nmdp)
{
	struct nfs_args *argp = NULL;
	struct netconfig *nconf = NULL;
	int vers = 0;
	int r = 0;
	ushort_t port;
	char *colonp;
	char *path;
	char *host;
	char spec_buf[MAXPATHLEN + LX_NMD_MAXHOSTNAMELEN + 1];

	mntp->mnt_fstype = MNTTYPE_NFS;

	(void) strlcpy(spec_buf, mntp->mnt_special, sizeof (spec_buf));
	colonp = strchr(spec_buf, ':');
	if (colonp == NULL)
		return (-EINVAL);

	*colonp = '\0';
	host = spec_buf;
	path = colonp + 1;

	argp = (struct nfs_args *)malloc(sizeof (*argp));
	if (argp == NULL)
		return (-ENOMEM);

	(void) memset(argp, 0, sizeof (*argp));
	(void) memset(&nmdp->nmd_nfs_sec, 0, sizeof (seconfig_t));
	nmdp->nmd_sec_opt = 0;
	port = 0;

	/* returns a negative errno */
	if ((r = set_args(&mntflags, argp, host, mntp, nmdp)) != 0)
		goto out;

	if (port == 0) {
		port = nmdp->nmd_nfs_port;
	} else if (nmdp->nmd_nfs_port != 0 && nmdp->nmd_nfs_port != port) {
		r = -EINVAL;
		goto out;
	}

	/* returns a negative errno or positive EAGAIN for retry */
	r = get_fh(argp, host, path, &vers, &nconf, port, nmdp);
	if (r != 0) {
		/* All attempts failed */
		goto out;
	}

	/*
	 * Call to get_fh() above may have obtained the netconfig info and NULL
	 * proc'd the server. This would be the case with v4
	 */
	if (!(argp->flags & NFSMNT_KNCONF)) {
		nconf = NULL;
		/* returns a negative errno or positive EAGAIN for retry */
		r = getaddr_nfs(argp, host, &nconf, port, retry_error, TRUE,
		    nmdp);
		if (r != 0) {
			goto out;
		}
	}

	if (make_secure(argp, host, nconf, vers, nmdp) < 0) {
		r = -EAGAIN;
		goto out;
	}

	mntflags |= MS_DATA | MS_OPTIONSTR;

	r = mount(mntp->mnt_special, mntp->mnt_mountp, mntflags,
	    nmdp->nmd_fstype, argp, sizeof (*argp), mntp->mnt_mntopts,
	    MAX_MNTOPT_STR);
	if (r != 0)
		r = -errno;
out:
	if (argp->fh)
		free(argp->fh);
	if (argp->pathconf)
		free(argp->pathconf);
	if (argp->knconf)
		free(argp->knconf);
	if (argp->addr) {
		free(argp->addr->buf);
		free(argp->addr);
	}
	nfs_free_secdata(argp->nfs_ext_u.nfs_extB.secdata);
	if (argp->syncaddr) {
		free(argp->syncaddr->buf);
		free(argp->syncaddr);
	}
	if (argp->netname)
		free(argp->netname);
	free(argp);

	return (r);
}

/*
 * These options are duplicated in uts/common/fs/nfs/nfs_dlinet.c
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
#define	OPT_NOLARGEFILES 37
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
convert_int(int *val, char *str)
{
	long lval;

	if (str == NULL || !isdigit(*str))
		return (-1);

	lval = strtol(str, &str, 10);
	if (*str != '\0' || lval > INT_MAX)
		return (-2);

	*val = (int)lval;
	return (0);
}

static int
set_args(int *mntflags, struct nfs_args *args, char *fshost, struct mnttab *mnt,
    nfs_mnt_data_t *nmdp)
{
	char *saveopt, *optstr, *opts, *newopts, *val;
	int num;
	int largefiles = 0;
	int invalid = 0;
	int attrpref = 0;
	int optlen, oldlen;

	args->flags = NFSMNT_INT;	/* default is "intr" */
	args->flags |= NFSMNT_HOSTNAME;
	args->flags |= NFSMNT_NEWARGS;	/* using extented nfs_args structure */
	args->hostname = fshost;

	optstr = opts = strdup(mnt->mnt_mntopts);
	oldlen = strlen(mnt->mnt_mntopts);
	/* sizeof (MNTOPT_XXX) includes one extra byte we may need for "," */
	optlen = oldlen + sizeof (MNTOPT_XATTR) + 1;
	if (optlen > MAX_MNTOPT_STR)
		return (-EINVAL);

	newopts = malloc(optlen);
	if (opts == NULL || newopts == NULL) {
		if (opts)
			free(opts);
		if (newopts)
			free(newopts);
		return (-EINVAL);
	}
	newopts[0] = '\0';

	while (*opts) {
		invalid = 0;
		saveopt = opts;
		switch (getsubopt(&opts, optlist, &val)) {
		case OPT_RO:
			*mntflags |= MS_RDONLY;
			break;
		case OPT_RW:
			*mntflags &= ~(MS_RDONLY);
			break;
		case OPT_QUOTA:
		case OPT_NOQUOTA:
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
		case OPT_SUID:
			*mntflags &= ~(MS_NOSUID);
			break;
		case OPT_NOSUID:
			*mntflags |= MS_NOSUID;
			break;
		case OPT_GRPID:
			args->flags |= NFSMNT_GRPID;
			break;
		case OPT_REMOUNT:
			*mntflags |= MS_REMOUNT;
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
			if (convert_int(&num, val) != 0)
				goto badopt;
			nmdp->nmd_nfs_port = htons((ushort_t)num);
			break;

		case OPT_NOCTO:
			args->flags |= NFSMNT_NOCTO;
			break;

		case OPT_RSIZE:
			if (convert_int(&args->rsize, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_RSIZE;
			break;
		case OPT_WSIZE:
			if (convert_int(&args->wsize, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_WSIZE;
			break;
		case OPT_TIMEO:
			if (convert_int(&args->timeo, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_TIMEO;
			break;
		case OPT_RETRANS:
			if (convert_int(&args->retrans, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_RETRANS;
			break;
		case OPT_ACTIMEO:
			if (convert_int(&args->acregmax, val) != 0)
				goto badopt;
			args->acdirmin = args->acregmin = args->acdirmax
			    = args->acregmax;
			args->flags |= NFSMNT_ACDIRMAX;
			args->flags |= NFSMNT_ACREGMAX;
			args->flags |= NFSMNT_ACDIRMIN;
			args->flags |= NFSMNT_ACREGMIN;
			break;
		case OPT_ACREGMIN:
			if (convert_int(&args->acregmin, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_ACREGMIN;
			break;
		case OPT_ACREGMAX:
			if (convert_int(&args->acregmax, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_ACREGMAX;
			break;
		case OPT_ACDIRMIN:
			if (convert_int(&args->acdirmin, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_ACDIRMIN;
			break;
		case OPT_ACDIRMAX:
			if (convert_int(&args->acdirmax, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_ACDIRMAX;
			break;
		case OPT_BG:
			nmdp->nmd_bg++;
			break;
		case OPT_FG:
			nmdp->nmd_bg = 0;
			break;
		case OPT_RETRY:
			if (convert_int(&nmdp->nmd_retries, val) != 0)
				goto badopt;
			break;
		case OPT_LLOCK:
			args->flags |= NFSMNT_LLOCK;
			break;
		case OPT_POSIX:
			nmdp->nmd_posix = 1;
			break;
		case OPT_VERS:
			if (convert_int(&num, val) != 0)
				goto badopt;
			nmdp->nmd_nfsvers = (rpcvers_t)num;
			break;
		case OPT_PROTO:
			if (val == NULL)
				goto badopt;

			nmdp->nmd_nfs_proto = (char *)malloc(strlen(val)+1);
			if (!nmdp->nmd_nfs_proto)
				return (-EINVAL);

			(void) strncpy(nmdp->nmd_nfs_proto, val, strlen(val)+1);
			break;

		case OPT_NOPRINT:
			args->flags |= NFSMNT_NOPRINT;
			break;

		case OPT_LARGEFILES:
			largefiles = 1;
			break;

		case OPT_NOLARGEFILES:
			free(optstr);
			return (-EINVAL);

		case OPT_SEC:
			if (val == NULL)
				return (-EINVAL);
			/*
			 * We initialize the nfs_sec struct as if we had the
			 * basic /etc/nffssec.conf file.
			 */
			if (strcmp(val, "none") == 0) {
				(void) strlcpy(nmdp->nmd_nfs_sec.sc_name,
				    "none", MAX_NAME_LEN);
				nmdp->nmd_nfs_sec.sc_nfsnum =
				    nmdp->nmd_nfs_sec.sc_rpcnum = 0;
			} else if (strcmp(val, "sys") == 0) {
				(void) strlcpy(nmdp->nmd_nfs_sec.sc_name,
				    "sys", MAX_NAME_LEN);
				nmdp->nmd_nfs_sec.sc_nfsnum =
				    nmdp->nmd_nfs_sec.sc_rpcnum = 1;
			} else if (strcmp(val, "dh") == 0) {
				(void) strlcpy(nmdp->nmd_nfs_sec.sc_name,
				    "dh", MAX_NAME_LEN);
				nmdp->nmd_nfs_sec.sc_nfsnum =
				    nmdp->nmd_nfs_sec.sc_rpcnum = 3;
			} else {
				return (-EINVAL);
			}
			nmdp->nmd_sec_opt++;
			break;

		case OPT_DIRECTIO:
			args->flags |= NFSMNT_DIRECTIO;
			break;

		case OPT_NODIRECTIO:
			args->flags &= ~(NFSMNT_DIRECTIO);
			break;

		case OPT_XATTR:
		case OPT_NOXATTR:
			/*
			 * VFS options; just need to get them into the
			 * new mount option string and note we've seen them
			 */
			attrpref = 1;
			break;
		default:
			invalid = 1;
			break;
		}
		if (!invalid) {
			if (newopts[0] != '\0') {
				(void) strlcat(newopts, ",", optlen);
			}
			(void) strlcat(newopts, saveopt, optlen);
		}
	}
	/* Default is to turn extended attrs on */
	if (!attrpref) {
		if (newopts[0]) {
			(void) strlcat(newopts, ",", optlen);
		}
		(void) strlcat(newopts, MNTOPT_XATTR, optlen);
	}
	(void) strlcpy(mnt->mnt_mntopts, newopts, oldlen);
	free(newopts);
	free(optstr);

	/* ensure that only one secure mode is requested */
	if (nmdp->nmd_sec_opt > 1)
		return (-EINVAL);

	/* ensure that the user isn't trying to get large files over V2 */
	if (nmdp->nmd_nfsvers == NFS_VERSION && largefiles)
		return (-EINVAL);

	if (nmdp->nmd_nfsvers == NFS_V4 && nmdp->nmd_nfs_proto != NULL &&
	    strncasecmp(nmdp->nmd_nfs_proto, NC_UDP, strlen(NC_UDP)) == 0)
		return (-EINVAL);

	return (0);

badopt:
	free(optstr);
	return (-EINVAL);
}

/*
 *  NFS project private API.
 *
 *  Free an sec_data structure.
 *  Free the parts that nfs_clnt_secdata allocates.
 */
void
nfs_free_secdata(sec_data_t *secdata)
{
	dh_k4_clntdata_t *dkdata;

	if (!secdata)
		return;

	switch (secdata->rpcflavor) {
		case AUTH_UNIX:
		case AUTH_NONE:
			break;

		case AUTH_DES:
			/* LINTED pointer alignment */
			dkdata = (dh_k4_clntdata_t *)secdata->data;
			if (dkdata) {
				if (dkdata->netname)
					free(dkdata->netname);
				if (dkdata->syncaddr.buf)
					free(dkdata->syncaddr.buf);
				free(dkdata);
			}
			break;

		default:
			break;
	}

	free(secdata);
}

/*
 *  Make an client side sec_data structure and fill in appropriate value
 *  based on its rpc security flavor.
 *
 *  It is caller's responsibility to allocate space for seconfig_t,
 *  and this routine will allocate space for the sec_data structure
 *  and related data field.
 *
 *  Return the sec_data_t on success.
 *  If fail, return NULL pointer.
 */
sec_data_t *
nfs_clnt_secdata(seconfig_t *secp, char *hostname, struct knetconfig *knconf,
    struct netbuf *syncaddr, int flags)
{
	char netname[MAXNETNAMELEN+1];
	sec_data_t *secdata;
	dh_k4_clntdata_t *dkdata;

	secdata = malloc(sizeof (sec_data_t));
	if (!secdata)
		return (NULL);

	(void) memset(secdata, 0, sizeof (sec_data_t));

	secdata->secmod = secp->sc_nfsnum;
	secdata->rpcflavor = secp->sc_rpcnum;
	secdata->uid = secp->sc_uid;
	secdata->flags = flags;

	/*
	 *  Now, fill in the information for client side secdata :
	 *
	 *  For AUTH_UNIX, AUTH_DES
	 *  hostname can be in the form of
	 *    nodename or
	 *    nodename.domain
	 */
	switch (secp->sc_rpcnum) {
		case AUTH_UNIX:
		case AUTH_NONE:
			secdata->data = NULL;
			break;

		case AUTH_DES:
			if (!host2netname(netname, hostname, NULL))
				goto err_out;

			dkdata = malloc(sizeof (dh_k4_clntdata_t));
			if (!dkdata)
				goto err_out;

			(void) memset((char *)dkdata, 0,
			    sizeof (dh_k4_clntdata_t));
			if ((dkdata->netname = strdup(netname)) == NULL)
				goto err_out;

			dkdata->netnamelen = strlen(netname);
			dkdata->knconf = knconf;
			dkdata->syncaddr = *syncaddr;
			dkdata->syncaddr.buf = malloc(syncaddr->len);
			if (dkdata->syncaddr.buf == NULL)
				goto err_out;

			(void) memcpy(dkdata->syncaddr.buf, syncaddr->buf,
			    syncaddr->len);
			secdata->data = (caddr_t)dkdata;
			break;

		default:
			goto err_out;
	}

	return (secdata);

err_out:
	free(secdata);
	return (NULL);
}

static int
make_secure(struct nfs_args *args, char *hostname, struct netconfig *nconf,
    rpcvers_t vers, nfs_mnt_data_t *nmdp)
{
	sec_data_t *secdata;
	int flags;
	struct netbuf *syncaddr = NULL;
	struct nd_addrlist *retaddrs = NULL;
	char netname[MAXNETNAMELEN+1];

	/*
	 * check to see if any secure mode is requested.
	 * if not, use default security mode.
	 */
	if (!nmdp->nmd_sec_opt) {
		/* AUTH_UNIX is the default. */
		(void) strlcpy(nmdp->nmd_nfs_sec.sc_name, "sys", MAX_NAME_LEN);
		nmdp->nmd_nfs_sec.sc_nfsnum = 1;
		args->flags |= NFSMNT_SECDEFAULT;
	}

	/*
	 * Get the network address for the time service on the server.
	 * If an RPC based time service is not available then try the
	 * IP time service.
	 *
	 * This is for AUTH_DH processing. We will also pass down syncaddr
	 * and netname for NFS V4 even if AUTH_DH is not requested right now.
	 * NFS V4 does security negotiation in the kernel via SECINFO.
	 * This information might be needed later in the kernel.
	 */
	flags = 0;
	syncaddr = NULL;

	if (nmdp->nmd_nfs_sec.sc_rpcnum == AUTH_DH || vers == NFS_V4) {
		/*
		 * If using nfsv4, we will not contact the remote RPCBINDer,
		 * since it is possibly behind a firewall.
		 */
		if (vers != NFS_V4)
			syncaddr = get_the_addr(hostname, RPCBPROG, RPCBVERS,
			    nconf, 0, NULL, NULL);

		if (syncaddr != NULL) {
			/* for flags in sec_data */
			flags |= AUTH_F_RPCTIMESYNC;
		} else {
			/*
			 * TBD:
			 * For AUTH_DH (AUTH_DES) netdir_getbyname wants to
			 * lookup the timeserver entry in the /etc/services
			 * file (but our libnsl to do this won't work in Linux).
			 * That entry is:
			 *	timed    525/udp    timeserver
			 * Since we haven't implemented the emulation for that
			 * aspect of netdir_getbyname yet, we'll simply return
			 * an error.
			 */
			struct nd_hostserv hs;
			int error;

			hs.h_host = hostname;
			hs.h_serv = "timserver";

			if (nmdp->nmd_nfs_sec.sc_rpcnum == AUTH_DH)
				return (-1);

			error = netdir_getbyname(nconf, &hs, &retaddrs);

			if (error != ND_OK &&
			    (nmdp->nmd_nfs_sec.sc_rpcnum == AUTH_DH))
				return (-1);

			if (error == ND_OK)
				syncaddr = retaddrs->n_addrs;

			/*
			 * For NFS_V4 if AUTH_DH is negotiated later in the
			 * kernel thru SECINFO, it will need syncaddr
			 * and netname data.
			 */
			if (vers == NFS_V4 && syncaddr &&
			    host2netname(netname, hostname, NULL)) {
				args->syncaddr = malloc(sizeof (struct netbuf));
				args->syncaddr->buf = malloc(syncaddr->len);
				(void) memcpy(args->syncaddr->buf,
				    syncaddr->buf, syncaddr->len);
				args->syncaddr->len = syncaddr->len;
				args->syncaddr->maxlen = syncaddr->maxlen;
				args->netname = strdup(netname);
				args->flags |= NFSMNT_SECURE;
			}
		}
	}

	/*
	 * For the initial chosen flavor (any flavor defined in nfssec.conf),
	 * the data will be stored in the sec_data structure via
	 * nfs_clnt_secdata() and be passed to the kernel via nfs_args_*
	 * extended data structure.
	 */
	if (!(secdata = nfs_clnt_secdata(&nmdp->nmd_nfs_sec, hostname,
	    args->knconf, syncaddr, flags))) {
		if (flags & AUTH_F_RPCTIMESYNC) {
			free(syncaddr->buf);
			free(syncaddr);
		} else if (retaddrs)
			netdir_free((void *)retaddrs, ND_ADDRLIST);
		return (-1);
	}

	NFS_ARGS_EXTB_secdata(args, secdata);
	if (flags & AUTH_F_RPCTIMESYNC) {
		free(syncaddr->buf);
		free(syncaddr);
	} else if (retaddrs)
		netdir_free((void *)retaddrs, ND_ADDRLIST);
	return (0);
}

/*
 * Get the network address on "hostname" for program "prog"
 * with version "vers" by using the nconf configuration data
 * passed in.
 *
 * If the address of a netconfig pointer is null then
 * information is not sufficient and no netbuf will be returned.
 *
 * Finally, ping the null procedure of that service.
 *
 * A similar routine is also defined in ../../autofs/autod_nfs.c.
 * This is a potential routine to move to ../lib for common usage.
 */
static struct netbuf *
get_the_addr(char *hostname, rpcprog_t prog, rpcvers_t vers,
    struct netconfig *nconf, ushort_t port, struct t_info *tinfo,
    err_ret_t *error)
{
	struct netbuf *nb = NULL;
	struct t_bind *tbind = NULL;
	CLIENT *cl = NULL;
	int fd = -1;
	AUTH *ah = NULL;
	AUTH *new_ah = NULL;
	struct rpc_err r_err;
	enum clnt_stat rc;

	if (nconf == NULL)
		return (NULL);

	if ((fd = t_open(nconf->nc_device, O_RDWR, tinfo)) == -1)
		goto done;

	/* LINTED pointer alignment */
	if ((tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR)) == NULL)
		goto done;

	if (vers == NFS_V4) {
		struct nd_hostserv hs;
		struct nd_addrlist *retaddrs;
		int retval;
		hs.h_host = hostname;

		/* NFS where vers==4 does not support UDP */
		if (strncasecmp(nconf->nc_proto, NC_UDP,
		    strlen(NC_UDP)) == 0) {
			SET_ERR_RET(error, ERR_PROTO_UNSUPP, 0);
			goto done;
		}

		if (port == 0)
			hs.h_serv = "nfs";
		else
			hs.h_serv = NULL;

		if ((retval = netdir_getbyname(nconf, &hs, &retaddrs))
		    != ND_OK) {
			/*
			 * Carefully set the error value here. Want to signify
			 * that the error was an unknown host.
			 */
			if (retval == ND_NOHOST) {
				SET_ERR_RET(error, ERR_NOHOST, retval);
			}

			goto done;
		}
		(void) memcpy(tbind->addr.buf, retaddrs->n_addrs->buf,
		    retaddrs->n_addrs->len);
		tbind->addr.len = retaddrs->n_addrs->len;
		netdir_free((void *)retaddrs, ND_ADDRLIST);
		(void) netdir_options(nconf, ND_SET_RESERVEDPORT, fd, NULL);

	} else {
		if (rpcb_getaddr(prog, vers, nconf, &tbind->addr,
		    hostname) == FALSE) {
			goto done;
		}
	}

	if (port) {
		if (strcmp(nconf->nc_protofmly, NC_INET) == 0) {
			/* LINTED alignment */
			((struct sockaddr_in *)tbind->addr.buf)->sin_port
			    = port;
		} else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0) {
			/* LINTED alignment */
			((struct sockaddr_in6 *)tbind->addr.buf)->sin6_port
			    = port;
		}

	}

	cl = clnt_tli_create(fd, nconf, &tbind->addr, prog, vers, 0, 0);
	if (cl == NULL) {
		/*
		 * clnt_tli_create() returns either RPC_SYSTEMERROR,
		 * RPC_UNKNOWNPROTO or RPC_TLIERROR. The RPC_TLIERROR translates
		 * to "Misc. TLI error". This is not too helpful. Most likely
		 * the connection to the remote server timed out, so this
		 * error is at least less perplexing.
		 * See: usr/src/cmd/rpcinfo/rpcinfo.c
		 */
		if (rpc_createerr.cf_stat == RPC_TLIERROR) {
			SET_ERR_RET(error, ERR_RPCERROR, RPC_PMAPFAILURE);
		} else {
			SET_ERR_RET(error, ERR_RPCERROR, rpc_createerr.cf_stat);
		}
		goto done;
	}

	ah = authsys_create_default();
	if (ah != NULL)
		cl->cl_auth = ah;

	/*
	 * NULL procedures need not have an argument or
	 * result param.
	 */
	if (vers == NFS_VERSION)
		rc = wnlproc_null_2(NULL, NULL, cl);
	else if (vers == NFS_V3)
		rc = wnlproc3_null_3(NULL, NULL, cl);
	else
		rc = wnlproc4_null_4(NULL, NULL, cl);

	if (rc != RPC_SUCCESS) {
		clnt_geterr(cl, &r_err);
		if (strcmp(nconf->nc_protofmly, NC_LOOPBACK) == 0) {
			switch (r_err.re_status) {
			case RPC_TLIERROR:
			case RPC_CANTRECV:
			case RPC_CANTSEND:
				r_err.re_status = RPC_PROGVERSMISMATCH;
				break;
			default:
				break;
			}
		}
		SET_ERR_RET(error, ERR_RPCERROR, r_err.re_status);
		goto done;
	}

	/*
	 * Make a copy of the netbuf to return
	 */
	nb = (struct netbuf *)malloc(sizeof (*nb));
	if (nb == NULL)
		goto done;

	*nb = tbind->addr;
	nb->buf = (char *)malloc(nb->maxlen);
	if (nb->buf == NULL) {
		free(nb);
		nb = NULL;
		goto done;
	}
	(void) memcpy(nb->buf, tbind->addr.buf, tbind->addr.len);

done:
	if (cl) {
		if (ah != NULL) {
			if (new_ah != NULL)
				AUTH_DESTROY(ah);
			AUTH_DESTROY(cl->cl_auth);
			cl->cl_auth = NULL;
		}
		clnt_destroy(cl);
		cl = NULL;
	}
	if (tbind) {
		(void) t_free((char *)tbind, T_BIND);
		tbind = NULL;
	}
	if (fd >= 0)
		(void) t_close(fd);
	return (nb);
}

static int
check_nconf(struct netconfig *nconf, int nthtry, int *valid_proto)
{
	int	try_test = 0;
	char	*proto = NULL;

	if (nthtry == FIRST_TRY) {
		try_test = ((nconf->nc_semantics == NC_TPI_COTS_ORD) ||
		    (nconf->nc_semantics == NC_TPI_COTS));
		proto = NC_TCP;
	} else if (nthtry == SECOND_TRY) {
		try_test = (nconf->nc_semantics == NC_TPI_CLTS);
		proto = NC_UDP;
	}

	if (proto &&
	    (strcmp(nconf->nc_protofmly, NC_INET) == 0 ||
	    strcmp(nconf->nc_protofmly, NC_INET6) == 0) &&
	    (strcmp(nconf->nc_proto, proto) == 0))
		*valid_proto = TRUE;
	else
		*valid_proto = FALSE;

	return (try_test);
}

static struct netconfig *
netconfig_dup(struct netconfig *netconfigp)
{
	struct netconfig *nconf;

	nconf = calloc(1, sizeof (struct netconfig));
	if (nconf == NULL)
		goto nomem;

	if ((nconf->nc_netid = strdup(netconfigp->nc_netid)) == NULL)
		goto nomem;

	if ((nconf->nc_protofmly = strdup(netconfigp->nc_protofmly)) == NULL)
		goto nomem;

	if ((nconf->nc_proto = strdup(netconfigp->nc_proto)) == NULL)
		goto nomem;

	if ((nconf->nc_device = strdup(netconfigp->nc_device)) == NULL)
		goto nomem;

	nconf->nc_lookups = NULL;
	nconf->nc_nlookups = netconfigp->nc_nlookups;
	nconf->nc_flag = netconfigp->nc_flag;
	nconf->nc_semantics = netconfigp->nc_semantics;
	return (nconf);

nomem:
	if (nconf != NULL) {
		free(nconf->nc_netid);
		free(nconf->nc_protofmly);
		free(nconf->nc_proto);
		free(nconf->nc_device);
		free(nconf);
	}
	return (NULL);
}

/*
 * Get a network address on "hostname" for program "prog"
 * with version "vers".  If the port number is specified (non zero)
 * then try for a TCP/UDP transport and set the port number of the
 * resulting IP address.
 *
 * If the address of a netconfig pointer was passed and
 * if it's not null, use it as the netconfig otherwise
 * assign the address of the netconfig that was used to
 * establish contact with the service.
 *
 * "error" refers to a more descriptive term when get_addr fails
 * and returns NULL: ERR_PROTO_NONE if no error introduced by
 * -o proto option, ERR_NETPATH if error found in NETPATH
 * environment variable, ERR_PROTO_INVALID if an unrecognized
 * protocol is specified by user, and ERR_PROTO_UNSUPP for a
 * recognized but invalid protocol (eg. ticlts, ticots, etc.).
 * "error" is ignored if get_addr returns non-NULL result.
 *
 */
static struct netbuf *
get_addr(char *hostname, rpcprog_t prog, rpcvers_t vers,
    struct netconfig **nconfp, char *proto, ushort_t port,
    struct t_info *tinfo, err_ret_t *error)
{
	struct netbuf *nb = NULL;
	struct netconfig *nconf = NULL;
	int nci;
	int nthtry = FIRST_TRY;
	err_ret_t errsave_nohost, errsave_rpcerr;

	SET_ERR_RET(&errsave_nohost, ERR_PROTO_NONE, 0);
	SET_ERR_RET(&errsave_rpcerr, ERR_PROTO_NONE, 0);

	SET_ERR_RET(error, ERR_PROTO_NONE, 0);

	if (nconfp && *nconfp)
		return (get_the_addr(hostname, prog, vers, *nconfp, port,
		    tinfo, error));
	/*
	 * No nconf passed in.
	 *
	 * First search for COTS, second for CLTS unless proto
	 * is specified.  When we retry, we reset the
	 * netconfig list so that we would search the whole list
	 * all over again.
	 */

	/*
	 * If proto is specified, then only search for the match,
	 * otherwise try COTS first, if failed, try CLTS.
	 */
	if (proto) {
		/* no matching proto name */
		SET_ERR_RET(error, ERR_PROTO_INVALID, 0);

		for (nci = 0; nci < N_NETCONF_ENTS; nci++) {
			nconf = &nca[nci];
			if (strcmp(nconf->nc_netid, proto) != 0)
				continue;

			/* may be unsupported */
			SET_ERR_RET(error, ERR_PROTO_UNSUPP, 0);

			nb = get_the_addr(hostname, prog, vers, nconf, port,
			    tinfo, error);
			if (nb != NULL)
				break;

			/* nb is NULL - deal with errors */
			if (error) {
				if (error->error_type == ERR_NOHOST) {
					SET_ERR_RET(&errsave_nohost,
					    error->error_type,
					    error->error_value);
				}
				if (error->error_type == ERR_RPCERROR) {
					SET_ERR_RET(&errsave_rpcerr,
					    error->error_type,
					    error->error_value);
				}
			}

			/* continue with same protocol selection */
			continue;
		} /* end of while */

		if (nci >= N_NETCONF_ENTS)
			goto done;

		if (nb == NULL &&
		    (nb = get_the_addr(hostname, prog, vers, nconf, port,
		    tinfo, error)) == NULL)
			goto done;
	} else {
retry:
		SET_ERR_RET(error, ERR_NETPATH, 0);
		for (nci = 0; nci < N_NETCONF_ENTS; nci++) {
			int	valid_proto;

			nconf = &nca[nci];
			SET_ERR_RET(error, ERR_PROTO_NONE, 0);

			if (check_nconf(nconf, nthtry, &valid_proto)) {
				if (port != 0 && valid_proto != TRUE)
					continue;

				nb = get_the_addr(hostname, prog, vers, nconf,
				    port, tinfo, error);
				if (nb != NULL)
					break;

				/* nb is NULL - deal with errors */
				if (error) {
					if (error->error_type == ERR_NOHOST) {
						SET_ERR_RET(&errsave_nohost,
						    error->error_type,
						    error->error_value);
					}

					if (error->error_type == ERR_RPCERROR) {
						SET_ERR_RET(&errsave_rpcerr,
						    error->error_type,
						    error->error_value);
					}
				}

				/*
				 * Continue the same search path in the
				 * netconfig db until no more matched
				 * nconf.
				 */
			}
		}

		if (nci >= N_NETCONF_ENTS) {
			if (++nthtry <= MNT_PREF_LISTLEN)
				goto retry;
			goto done;
		}

	}
	SET_ERR_RET(error, ERR_PROTO_NONE, 0);

	/*
	 * Got nconf and nb. Now dup the netconfig structure
	 * and return it thru nconfp.
	 */
	*nconfp = netconfig_dup(nconf);
	if (*nconfp == NULL) {
		free(nb);
		nb = NULL;
	}
done:
	if (nb == NULL) {
		/*
		 * Check the saved errors. The RPC error has
		 * precedence over the no host error.
		 */
		if (errsave_nohost.error_type != ERR_PROTO_NONE) {
			SET_ERR_RET(error, errsave_nohost.error_type,
			    errsave_nohost.error_value);
		}

		if (errsave_rpcerr.error_type != ERR_PROTO_NONE) {
			SET_ERR_RET(error, errsave_rpcerr.error_type,
			    errsave_rpcerr.error_value);
		}
	}

	return (nb);
}

static int
lx_nsl_set_sz_func()
{
	return (N_NETCONF_ENTS);
}

static struct netconfig *
lx_get_ent_func(int pos)
{
	struct netconfig *nconf;

	if (pos < 0 || pos >= N_NETCONF_ENTS)
		return (NULL);

	nconf = &nca[pos];
	return (nconf);
}

/*
 * Roughly based on the NFSv4 try_failover_table but used here for generic
 * errno translation.
 */
static int
rpcerr2errno(int rpcerr)
{
	switch (rpcerr) {
	case RPC_INTR:
		return (EINTR);
	case RPC_TIMEDOUT:
		return (ETIMEDOUT);
	case RPC_VERSMISMATCH:
	case RPC_PROGVERSMISMATCH:
	case RPC_PROGUNAVAIL:
	case RPC_PROCUNAVAIL:
	case RPC_PMAPFAILURE:
	case RPC_PROGNOTREGISTERED:
		return (EPROTONOSUPPORT);
	case RPC_AUTHERROR:
		return (EACCES);
	case RPC_UNKNOWNPROTO:
	case RPC_UNKNOWNHOST:
		return (EHOSTUNREACH);
	case RPC_CANTENCODEARGS:
	case RPC_CANTDECODERES:
	case RPC_CANTDECODEARGS:
	case RPC_CANTSEND:
	case RPC_CANTRECV:
		return (ECOMM);
	case RPC_SYSTEMERROR:
		return (ENOSR);
	default:
		return (EIO);
	}
}

static int
err2errno(int err)
{
	assert(err != ERR_RPCERROR);
	switch (err) {
	case ERR_PROTO_NONE:
	case ERR_PROTO_INVALID:
	case ERR_PROTO_UNSUPP:
		return (EPROTONOSUPPORT);
	case ERR_NETPATH:
		return (ENOSR);
	case ERR_NOHOST:
		return (EHOSTUNREACH);
	default:
		return (EIO);
	}
}

/*
 * get fhandle of remote path from server's mountd
 *
 * Return a positive EAGAIN if the caller should retry and a -EAGAIN to
 * indicate a fatal (Linux-oriented) error condition. Return other negative
 * errno values to indicate different fatal errors.
 */
static int
get_fh(struct nfs_args *args, char *fshost, char *fspath, int *versp,
    struct netconfig **nconfp, ushort_t port, nfs_mnt_data_t *nmdp)
{
	struct fhstatus fhs;
	struct mountres3 mountres3;
	struct pathcnf p;
	nfs_fh3 *fh3p;
	struct timeval timeout = { 25, 0};
	CLIENT *cl;
	enum clnt_stat rpc_stat;
	rpcvers_t outvers = 0;
	rpcvers_t vers_to_try;
	rpcvers_t vers_min = vers_min_default;
	int count, i, *auths;

	bzero(&fhs, sizeof (fhs));
	bzero(&mountres3, sizeof (mountres3));
	bzero(&p, sizeof (p));

	switch (nmdp->nmd_nfsvers) {
	case 2: /* version 2 specified try that only */
		vers_to_try = MOUNTVERS_POSIX;
		vers_min = MOUNTVERS;
		break;
	case 3: /* version 3 specified try that only */
		vers_to_try = MOUNTVERS3;
		vers_min = MOUNTVERS3;
		break;
	case 4: /* version 4 specified try that only */
		/*
		 * This assignment is in the wrong version sequence.
		 * The above are MOUNT program and this is NFS
		 * program.  However, it happens to work out since the
		 * two don't collide for NFSv4.
		 */
		vers_to_try = NFS_V4;
		vers_min = NFS_V4;
		break;
	default: /* no version specified, start with default */
		/*
		 * If the retry version is set, use that. This will
		 * be set if the last mount attempt returned any other
		 * besides an RPC error.
		 */
		if (nmdp->nmd_nfsretry_vers)
			vers_to_try = nmdp->nmd_nfsretry_vers;
		else {
			vers_to_try = vers_max_default;
			vers_min = vers_min_default;
		}

		break;
	}

	/*
	 * In the case of version 4, just NULL proc the server since
	 * there is no MOUNT program.  If this fails, then decrease
	 * vers_to_try and continue on with regular MOUNT program
	 * processing.
	 */
	if (vers_to_try == NFS_V4) {
		int savevers = nmdp->nmd_nfsvers_to_use;
		err_ret_t error;
		int retval;
		SET_ERR_RET(&error, ERR_PROTO_NONE, 0);

		/* Let's hope for the best */
		nmdp->nmd_nfsvers_to_use = NFS_V4;
		retval = getaddr_nfs(args, fshost, nconfp,
		    port, &error, vers_min == NFS_V4, nmdp);

		if (retval == RET_OK) {
			*versp = nmdp->nmd_nfsvers_to_use = NFS_V4;
			nmdp->nmd_fstype = MNTTYPE_NFS4;
			args->fh = strdup(fspath);
			if (args->fh == NULL) {
				*versp = nmdp->nmd_nfsvers_to_use = savevers;
				return (-EAGAIN);
			}
			return (0);
		}
		nmdp->nmd_nfsvers_to_use = savevers;

		if (retval == RET_ERR && error.error_type == ERR_RPCERROR &&
		    error.error_value == RPC_PROGVERSMISMATCH &&
		    nmdp->nmd_nfsvers != 0) {
			/*
			 * We had an explicit vers=N mount request which locked
			 * us in to that version, however the server does not
			 * support that version (and responded to tell us that).
			 */
			return (-EPROTONOSUPPORT);
		}

		vers_to_try--;
		/* If no more versions to try, let the user know. */
		if (vers_to_try < vers_min) {
			if (error.error_value == 0)
				return (-EPROTONOSUPPORT);
			return (-rpcerr2errno(error.error_value));
		}

		/*
		 * If we are here, there are more versions to try but
		 * there has been an error of some sort.  If it is not
		 * an RPC error (e.g. host unknown), we just stop and
		 * return the error since the other versions would see
		 * the same error as well.
		 */
		if (retval == RET_ERR && error.error_type != ERR_RPCERROR)
			return (-err2errno(error.error_type));
	}

	while ((cl = clnt_create_vers(fshost, MOUNTPROG, &outvers,
	    vers_min, vers_to_try, NULL)) == NULL) {
		if (rpc_createerr.cf_stat == RPC_UNKNOWNHOST)
			return (-EAGAIN);

		/*
		 * We don't want to downgrade version on lost packets
		 */
		if ((rpc_createerr.cf_stat == RPC_TIMEDOUT) ||
		    (rpc_createerr.cf_stat == RPC_PMAPFAILURE))
			return (EAGAIN);

		/*
		 * back off and try the previous version - patch to the
		 * problem of version numbers not being contigous and
		 * clnt_create_vers failing (SunOS4.1 clients & SGI servers)
		 * The problem happens with most non-Sun servers who
		 * don't support mountd protocol #2. So, in case the
		 * call fails, we re-try the call anyway.
		 */
		vers_to_try--;
		if (vers_to_try < vers_min) {
			if (rpc_createerr.cf_stat == RPC_PROGVERSMISMATCH)
				return (-EAGAIN);

			return (EAGAIN);
		}
	}
	if (nmdp->nmd_posix && outvers < MOUNTVERS_POSIX) {
		clnt_destroy(cl);
		return (-EAGAIN);
	}

	if (__clnt_bindresvport(cl) < 0) {
		clnt_destroy(cl);
		return (EAGAIN);
	}

	if ((cl->cl_auth = authsys_create_default()) == NULL) {
		clnt_destroy(cl);
		return (EAGAIN);
	}

	switch (outvers) {
	case MOUNTVERS:
	case MOUNTVERS_POSIX:
		*versp = nmdp->nmd_nfsvers_to_use = NFS_VERSION;
		rpc_stat = clnt_call(cl, MOUNTPROC_MNT, xdr_dirpath,
		    (caddr_t)&fspath, xdr_fhstatus, (caddr_t)&fhs, timeout);
		if (rpc_stat != RPC_SUCCESS) {
			log_err("%s:%s: server not responding %s\n",
			    fshost, fspath, clnt_sperror(cl, ""));
			clnt_destroy(cl);
			return (EAGAIN);
		}

		if ((errno = fhs.fhs_status) != MNT_OK) {
			clnt_destroy(cl);
			return (-fhs.fhs_status);
		}
		args->fh = malloc(sizeof (fhs.fhstatus_u.fhs_fhandle));
		if (args->fh == NULL)
			return (-EAGAIN);

		(void) memcpy((caddr_t)args->fh,
		    (caddr_t)&fhs.fhstatus_u.fhs_fhandle,
		    sizeof (fhs.fhstatus_u.fhs_fhandle));
		if (!errno && nmdp->nmd_posix) {
			rpc_stat = clnt_call(cl, MOUNTPROC_PATHCONF,
			    xdr_dirpath, (caddr_t)&fspath, xdr_ppathcnf,
			    (caddr_t)&p, timeout);
			if (rpc_stat != RPC_SUCCESS) {
				log_err("%s:%s: server not responding %s\n",
				    fshost, fspath, clnt_sperror(cl, ""));
				free(args->fh);
				clnt_destroy(cl);
				return (EAGAIN);
			}
			if (_PC_ISSET(_PC_ERROR, p.pc_mask)) {
				free(args->fh);
				clnt_destroy(cl);
				return (-EAGAIN);
			}
			args->flags |= NFSMNT_POSIX;
			args->pathconf = malloc(sizeof (p));
			if (args->pathconf == NULL) {
				free(args->fh);
				clnt_destroy(cl);
				return (-EAGAIN);
			}
			(void) memcpy((caddr_t)args->pathconf, (caddr_t)&p,
			    sizeof (p));
		}
		break;

	case MOUNTVERS3:
		*versp = nmdp->nmd_nfsvers_to_use = NFS_V3;
		rpc_stat = clnt_call(cl, MOUNTPROC_MNT, xdr_dirpath,
		    (caddr_t)&fspath, xdr_mountres3, (caddr_t)&mountres3,
		    timeout);
		if (rpc_stat != RPC_SUCCESS) {
			log_err("%s:%s: server not responding %s\n",
			    fshost, fspath, clnt_sperror(cl, ""));
			clnt_destroy(cl);
			return (EAGAIN);
		}

		/*
		 * Assume here that most of the MNT3ERR_*
		 * codes map into E* errors. See the nfsstat enum for values.
		 */
		if ((errno = mountres3.fhs_status) != MNT_OK) {
			clnt_destroy(cl);
			return (-mountres3.fhs_status);
		}

		fh3p = (nfs_fh3 *)malloc(sizeof (*fh3p));
		if (fh3p == NULL)
			return (-EAGAIN);

		fh3p->fh3_length =
		    mountres3.mountres3_u.mountinfo.fhandle.fhandle3_len;
		(void) memcpy(fh3p->fh3_u.data,
		    mountres3.mountres3_u.mountinfo.fhandle.fhandle3_val,
		    fh3p->fh3_length);
		args->fh = (caddr_t)fh3p;
		nmdp->nmd_fstype = MNTTYPE_NFS3;

		/*
		 * Check the security flavor to be used.
		 *
		 * If "secure" or "sec=flavor" is a mount
		 * option, check if the server supports the "flavor".
		 * If the server does not support the flavor, return
		 * error.
		 *
		 * If no mount option is given then look for default auth
		 * (default auth entry in /etc/nfssec.conf) in the auth list
		 * returned from server. If default auth not found, then use
		 * the first supported security flavor (by the client) in the
		 * auth list returned from the server.
		 *
		 */
		auths =
		    mountres3.mountres3_u.mountinfo.auth_flavors
		    .auth_flavors_val;
		count =
		    mountres3.mountres3_u.mountinfo.auth_flavors
		    .auth_flavors_len;

		if (count <= 0) {
			clnt_destroy(cl);
			return (-EAGAIN);
		}

		if (nmdp->nmd_sec_opt) {
			for (i = 0; i < count; i++) {
				if (auths[i] == nmdp->nmd_nfs_sec.sc_nfsnum)
					break;
			}
			if (i == count)
				goto autherr;
		} else {
			/* AUTH_UNIX is the default. */
			(void) strlcpy(nmdp->nmd_nfs_sec.sc_name, "sys",
			    MAX_NAME_LEN);
			nmdp->nmd_nfs_sec.sc_nfsnum = 1;
		}
		break;
	default:
		clnt_destroy(cl);
		return (-EAGAIN);
	}

	clnt_destroy(cl);
	return (0);

autherr:
	clnt_destroy(cl);
	return (-EAGAIN);
}

/*
 * Fill in the address for the server's NFS service and fill in a knetconfig
 * structure for the transport that the service is available on.
 *
 * Return a positive EAGAIN if the caller should retry and a -EAGAIN to
 * indicate a fatal (Linux-oriented) error condition. Return other negative
 * errno values to indicate different fatal errors.
 */
static int
getaddr_nfs(struct nfs_args *args, char *fshost, struct netconfig **nconfp,
    ushort_t port, err_ret_t *error, bool_t print_rpcerror,
    nfs_mnt_data_t *nmdp)
{
	struct stat sb;
	struct netconfig *nconf;
	struct knetconfig *knconfp;
	struct t_info tinfo;
	err_ret_t addr_error;

	SET_ERR_RET(error, ERR_PROTO_NONE, 0);
	SET_ERR_RET(&addr_error, ERR_PROTO_NONE, 0);

	args->addr = get_addr(fshost, NFS_PROGRAM, nmdp->nmd_nfsvers_to_use,
	    nconfp, nmdp->nmd_nfs_proto, port, &tinfo, &addr_error);

	if (args->addr == NULL) {
		switch (addr_error.error_type) {
		case 0:
			break;
		case ERR_RPCERROR:
			if (!print_rpcerror)
				/* no error print at this time */
				break;
			log_err("%s NFS service not available %s\n", fshost,
			    clnt_sperrno(addr_error.error_value));
			break;
		case ERR_NETPATH:
			log_err("%s: Error in NETPATH.\n", fshost);
			break;
		case ERR_PROTO_INVALID:
			log_err("%s: NFS service does not recognize "
			    "protocol: %s.\n", fshost, nmdp->nmd_nfs_proto);
			break;
		case ERR_PROTO_UNSUPP:
			if (nmdp->nmd_nfsvers ||
			    nmdp->nmd_nfsvers_to_use == NFS_VERSMIN) {
				log_err("%s: NFS service does"
				    " not support protocol: %s.\n",
				    fshost, nmdp->nmd_nfs_proto);
			}
			break;
		case ERR_NOHOST:
			log_err("%s: %s\n", fshost, "Unknown host");
			break;
		default:
			/* case ERR_PROTO_NONE falls through */
			log_err("%s: NFS service not responding\n", fshost);
			break;
		}

		SET_ERR_RET(error,
		    addr_error.error_type, addr_error.error_value);
		if (addr_error.error_type == ERR_PROTO_NONE) {
			return (EAGAIN);
		} else if (addr_error.error_type == ERR_RPCERROR &&
		    !IS_UNRECOVERABLE_RPC(addr_error.error_value)) {
			return (EAGAIN);
		} else if (nmdp->nmd_nfsvers == 0 &&
		    addr_error.error_type == ERR_PROTO_UNSUPP &&
		    nmdp->nmd_nfsvers_to_use != NFS_VERSMIN) {
			/*
			 * If no version is specified, and the error is due
			 * to an unsupported transport, then decrement the
			 * version and retry.
			 */
			return (EAGAIN);
		} else if (addr_error.error_type != ERR_RPCERROR) {
			return (-err2errno(addr_error.error_type));
		} else {
			return (-rpcerr2errno(addr_error.error_value));
		}
	}
	nconf = *nconfp;

	if (stat(nconf->nc_device, &sb) < 0)
		return (-ENOSR);

	knconfp = (struct knetconfig *)malloc(sizeof (*knconfp));
	if (!knconfp)
		return (-ENOMEM);

	knconfp->knc_semantics = nconf->nc_semantics;
	knconfp->knc_protofmly = nconf->nc_protofmly;
	knconfp->knc_proto = nconf->nc_proto;
	knconfp->knc_rdev = sb.st_rdev;

	/* make sure we don't overload the transport */
	if (tinfo.tsdu > 0 && tinfo.tsdu < NFS_MAXDATA + NFS_RPC_HDR) {
		args->flags |= (NFSMNT_RSIZE | NFSMNT_WSIZE);
		if (args->rsize == 0 || args->rsize > tinfo.tsdu - NFS_RPC_HDR)
			args->rsize = tinfo.tsdu - NFS_RPC_HDR;
		if (args->wsize == 0 || args->wsize > tinfo.tsdu - NFS_RPC_HDR)
			args->wsize = tinfo.tsdu - NFS_RPC_HDR;
	}

	args->flags |= NFSMNT_KNCONF;
	args->knconf = knconfp;
	return (0);
}

static int
retry(struct mnttab *mntp, int mntflags, nfs_mnt_data_t *nmdp)
{
	int delay = 5;
	int count = nmdp->nmd_retries;
	int r = -EAGAIN;
	char *p;

	if (nmdp->nmd_bg) {
		if (fork() > 0)
			return (0);
	} else {
		p = strchr(mntp->mnt_special, ':');
		if (p != NULL)
			*p = '\0';
		log_err("%s: server not responding\n", mntp->mnt_special);
		if (p != NULL)
			*p = ':';
	}

	while (count--) {
		err_ret_t retry_error;

		if ((r = mount_nfs(mntp, mntflags, &retry_error, nmdp)) == 0)
			return (0);

		if (r != EAGAIN)
			break;

		if (count > 0) {
			(void) sleep(delay);
			delay *= 2;
			if (delay > 120)
				delay = 120;
		}
		p = strchr(mntp->mnt_special, ':');
		if (p != NULL)
			*p = '\0';
		log_err("%s: server not responding\n", mntp->mnt_special);
		if (p != NULL)
			*p = ':';
	}

	if (!nmdp->nmd_nfsretry_vers)
		log_err("giving up on: %s\n", mntp->mnt_mountp);

	if (r > 0)
		r = -EAGAIN;
	return (r);
}

static int
append_opt(char *optstr, int len, char *k, char *v)
{
	int i;

	for (i = 0; nmo_tab[i].nmo_lx_opt != NULL; i++) {
		if (strcmp(k, nmo_tab[i].nmo_lx_opt) == 0) {
			switch (nmo_tab[i].nmo_argtyp) {
			case MOUNT_OPT_INVALID:
				lx_unsupported("invalid NFS mount option: %s",
				    k);
				return (-EINVAL);

			case MOUNT_OPT_PASTHRU:
				if (*optstr != '\0')
					(void) strlcat(optstr, ",", len);
				if (v == NULL) {
					(void) strlcat(optstr, k, len);
				} else {
					(void) strlcat(optstr, k, len);
					(void) strlcat(optstr, "=", len);
					(void) strlcat(optstr, v, len);
				}
				break;

			case MOUNT_OPT_IGNORE:
				break;

			case MOUNT_OPT_TOKEN:
				if (*optstr != '\0')
					(void) strlcat(optstr, ",", len);
				(void) strlcat(optstr,
				    nmo_tab[i].nmo_il_opt, len);
				break;

			case MOUNT_OPT_HAS_ARG:
				if (*optstr != '\0')
					(void) strlcat(optstr, ",", len);
				(void) strlcat(optstr,
				    nmo_tab[i].nmo_il_opt, len);
				(void) strlcat(optstr, "=", len);
				(void) strlcat(optstr, v, len);
				break;
			}
			break;
		}
	}

	return (0);
}

static int
get_nfs_kv(char *vs, char **kp, char **vp)
{
	char *p;

	p = strchr(vs, '=');
	if (p == NULL) {
		*kp = vs;
		return (1);
	}

	*vp = p + 1;
	*p = '\0';
	*kp = vs;
	return (0);
}

/*
 * Convert the Linux-specific opt string into an Illumos opt string. We also
 * fix up the special string (host:/path) to use the address that the
 * user-level mount code has looked up. This overwrites both the srcp special
 * string and the mntopts string.
 *
 * example input string, given 'nolock' as the only user-level option:
 *     nolock,vers=4,addr=127.0.0.1,clientaddr=0.0.0.0
 *
 * opt string (all one line) from a Centos 6 distro given 'nolock,vers=3' as
 * the explicit options:
 *     nolock,addr=127.0.0.1,vers=3,proto=tcp,mountvers=3,mountproto=tcp,
 *     mountport=1892
 *
 * This is an example emitted by the Ubuntu 14.04 automounter for an explicit
 * v3 mount:
 *	timeo=60,soft,intr,sloppy,addr=10.88.88.200,vers=3,proto=tcp,
 *	mountvers=3,mountproto=tcp,mountport=63484
 */
static int
convert_nfs_arg_str(char *srcp, char *mntopts)
{
	char *key, *val, *p;
	char tmpbuf[MAX_MNTOPT_STR];
	char *tbp = tmpbuf;
	boolean_t no_sec = B_TRUE;

	(void) strlcpy(tmpbuf, mntopts, sizeof (tmpbuf));
	*mntopts = '\0';

	while ((p = strsep(&tbp, ",")) != NULL) {
		int tok;

		tok = get_nfs_kv(p, &key, &val);

		if (tok == 0) {
			if (strcmp(key, "addr") == 0) {
				/*
				 * The Linux user-level code looked up the
				 * address of the NFS server. We need to
				 * substitute that into the special string.
				 */
				char *pp;
				char spec[MAXPATHLEN + LX_NMD_MAXHOSTNAMELEN
				    + 1];

				(void) strlcpy(spec, srcp, sizeof (spec));
				pp = strchr(spec, ':');
				if (pp == NULL)
					return (-EINVAL);

				pp++;
				(void) snprintf(srcp,
				    MAXPATHLEN + LX_NMD_MAXHOSTNAMELEN + 1,
				    "%s:%s", val, pp);
			} else if (strcmp(key, "clientaddr") == 0) {
				/*
				 * Ignore, this is an artifact of the
				 * user-level lx mount code.
				 */
				/* EMPTY */
			} else if (strcmp(key, "vers") == 0) {
				/*
				 * This may be implicitly or explicitly passed.
				 * Check for the versions we want to support.
				 */
				int r;
				int v = atoi(val);

				if (v != 3 && v != 4)
					return (-EINVAL);

				r = append_opt(mntopts, MAX_MNTOPT_STR,
				    key, val);
				if (r != 0)
					return (r);

			} else if (strcmp(key, "sec") == 0) {
				no_sec = B_FALSE;
			} else {
				int r;

				r = append_opt(mntopts, MAX_MNTOPT_STR,
				    key, val);
				if (r != 0)
					return (r);
			}
		} else {
			int r;

			r = append_opt(mntopts, MAX_MNTOPT_STR, key, NULL);
			if (r != 0)
				return (r);
		}
	}

	if (no_sec) {
		/*
		 * XXX Temporarily work around missing DES auth by defaulting
		 * to sec=sys.
		 */
		int r;

		r = append_opt(mntopts, MAX_MNTOPT_STR, "sec", "sys");
		if (r != 0)
			return (r);
	}

	return (0);
}

/* ARGSUSED2 */
int
lx_nfs_mount(char *srcp, char *mntp, char *fst, int lx_flags, char *opts)
{
	struct mnttab mnt;
	int r;
	int il_flags = 0;
	err_ret_t retry_error;
	nfs_mnt_data_t nmd;

	_nsl_brand_set_hooks(lx_nsl_set_sz_func, lx_get_ent_func);

	bzero(&nmd, sizeof (nmd));
	nmd.nmd_retries = BIGRETRY;
	nmd.nmd_fstype = MNTTYPE_NFS;

	/*
	 * This will modify the special string so that the hostname passed
	 * in will be replaced with the host address that the user-land code
	 * looked up. Thus the rest of the code down the mount_nfs path will
	 * be working with that IP address in places were it references the
	 * 'hostname'. This also converts the opts string so that we'll be
	 * dealing with Illumos options after this.
	 */
	if ((r = convert_nfs_arg_str(srcp, opts)) < 0) {
		return (r);
	}


	/* Linux seems to always allow overlay mounts */
	il_flags |= MS_OVERLAY;

	/* Convert some Linux flags to Illumos flags. */
	if (lx_flags & LX_MS_RDONLY)
		il_flags |= MS_RDONLY;
	if (lx_flags & LX_MS_NOSUID)
		il_flags |= MS_NOSUID;
	if (lx_flags & LX_MS_REMOUNT)
		il_flags |= MS_REMOUNT;

	/*
	 * Convert some Linux flags to Illumos option strings.
	 */
	if (lx_flags & LX_MS_STRICTATIME) {
		/*
		 * The "strictatime" mount option ensures that none of the
		 * weaker atime-related mode options are in effect.
		 */
		lx_flags &= ~(LX_MS_RELATIME | LX_MS_NOATIME);
	}
	if ((lx_flags & LX_MS_NODEV) &&
	    ((r = i_add_option("nodev", opts, MAX_MNTOPT_STR)) != 0))
		return (r);
	if ((lx_flags & LX_MS_NOEXEC) &&
	    ((r = i_add_option("noexec", opts, MAX_MNTOPT_STR)) != 0))
		return (r);
	if ((lx_flags & LX_MS_NOATIME) &&
	    ((r = i_add_option("noatime", opts, MAX_MNTOPT_STR)) != 0))
		return (r);

	mnt.mnt_special = srcp;
	mnt.mnt_mountp = mntp;
	mnt.mnt_mntopts = opts;

	SET_ERR_RET(&retry_error, ERR_PROTO_NONE, 0);
	r = mount_nfs(&mnt, il_flags, &retry_error, &nmd);

	/* A negative errno return means we're done. */
	if (r < 0)
		return (r);

	if (r == EAGAIN && nmd.nmd_retries) {
		/*
		 * Check the error code from the last mount attempt. If it was
		 * an RPC error, then retry as is. Otherwise we retry with the
		 * nmd_nfsretry_vers set. It is set by decrementing
		 * nmd_nfsvers_to_use.
		 */
		if (retry_error.error_type != 0) {
			if (retry_error.error_type != ERR_RPCERROR) {
				nmd.nmd_nfsretry_vers =
				    nmd.nmd_nfsvers_to_use =
				    nmd.nmd_nfsvers_to_use - 1;
				if (nmd.nmd_nfsretry_vers < NFS_VERSMIN)
					return (-EAGAIN);
			}
		}

		r = retry(&mnt, il_flags, &nmd);
	}

	/* Convert positve EAGAIN into a valid errno. */
	if (r > 0)
		return (-EAGAIN);

	return (0);
}
