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
 * The illumos NFS user-level mount code encapsulates a significant amount of
 * functionality into librpc and libnsl. This includes a variety of functions
 * to perform lookups in the various /etc configuration files. For v2/v3 in
 * particular, the library code must make a call to the server's 'mountd' to
 * obtain a file handle to pass into the mount(2) syscall. There can be a
 * variety of calls to the server's 'rpcbind' made by the libraries during the
 * preliminaries before calling mount(2). All of the logic for falling back
 * when determining which version to use (when none is explicitly provided), as
 * well as retries when the server is not responding, is encapsulated in the
 * libraries.
 *
 * For Linux, much of this functionality is also included in the user-level
 * mount code, and thus not of concern to us at the Linux syscall level. The
 * major difference is that the RPC to the 'mountd' to get the file handle for
 * v2/v3 is made within the kernel as part of the mount(2) syscall. However,
 * the Linux user-level code will perform all of the logical name lookups (e.g.
 * hostname to IP address), will make the 'rpcbind' call to determine the
 * server's 'mountd' protocol and port, and will handle the retry logic.
 *
 * Thus, when we reach our code here, we don't need to do any name lookups in
 * any of the /etc files and we never need to call 'rpcbind'. We only need to
 * make the RPC to get the file handle for v2/v3 mounts. We're still dependent
 * on librpc/libnsl to make this RPC, but our overall complexity is much less
 * than what is seen with the native mount library usage. In addition, we also
 * have to convert the Linux mount arguments into our native format. Because
 * we're really just making the RPC to get a file handle and reformatting the
 * mount arguments, this code should be amenable to living in-kernel at some
 * point.
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
 * Copyright 2017 Joyent, Inc.
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
#include <sys/syscall.h>

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
	{"bg",		NULL,		MOUNT_OPT_IGNORE},
	{"cto",		NULL,		MOUNT_OPT_IGNORE},
	{"fg",		NULL,		MOUNT_OPT_IGNORE},
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
	{"retry",	NULL,		MOUNT_OPT_IGNORE},
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
 */
typedef struct nfs_mnt_data {
	int		nmd_posix;
	ushort_t	nmd_nfs_port;
	char		*nmd_nfs_proto;
	ushort_t	nmd_mnt_port;
	char		*nmd_mnt_proto;
	char		*nmd_fstype;
	seconfig_t	nmd_nfs_sec;
	int		nmd_sec_opt;	/* any security option ? */
	int		nmd_nolock_opt;	/* 'nolock' specified */
	rpcvers_t	nmd_mnt_vers;
	rpcvers_t	nmd_nfsvers;
} nfs_mnt_data_t;

/* number of transports to try */
#define	MNT_PREF_LISTLEN	2
#define	FIRST_TRY		1
#define	SECOND_TRY		2

#define	BIGRETRY	10000

/* maximum length of RPC header for NFS messages */
#define	NFS_RPC_HDR	432

extern int __clnt_bindresvport(CLIENT *);

static int set_args(int *, struct nfs_args *, char *, char *, nfs_mnt_data_t *);
static int get_fh(struct nfs_args *, char *, char *, nfs_mnt_data_t *);
static int make_secure(struct nfs_args *, nfs_mnt_data_t *);
static int getaddr_nfs(struct nfs_args *, char *, struct netconfig **,
	nfs_mnt_data_t *);

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
 * These options were initially derived from uts/common/fs/nfs/nfs_dlinet.c
 * but have been extended to add additional Linux options.
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
#define	OPT_MNT_VERS	49
	"mountvers",
#define	OPT_MNT_PORT	50
	"mountport",
#define	OPT_MNT_PROTO	51
	"mountproto",

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
set_args(int *mntflags, struct nfs_args *args, char *fshost, char *mntopts,
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

	oldlen = strlen(mntopts);
	optstr = opts = strdup(mntopts);
	if (opts == NULL)
		return (-ENOMEM);
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
			nmdp->nmd_nfs_port = num;
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
			/* Ignored as does Linux kernel */
			break;
		case OPT_FG:
			/* Ignored as does Linux kernel */
			break;
		case OPT_RETRY:
			/* Ignored as does Linux kernel */
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
			 * basic /etc/nfssec.conf file.
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

		case OPT_MNT_VERS:
			if (convert_int(&num, val) != 0)
				goto badopt;
			nmdp->nmd_mnt_vers = (rpcvers_t)num;
			invalid = 1;	/* Invalid as a native option */
			break;

		case OPT_MNT_PORT:
			if (convert_int(&num, val) != 0)
				goto badopt;
			nmdp->nmd_mnt_port = num;
			invalid = 1;	/* Invalid as a native option */
			break;

		case OPT_MNT_PROTO:
			if (val == NULL)
				goto badopt;
			nmdp->nmd_mnt_proto = strdup(val);
			if (nmdp->nmd_mnt_proto == NULL)
				return (-ENOMEM);
			invalid = 1;	/* Invalid as a native option */
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
	(void) strlcpy(mntopts, newopts, oldlen);
	free(newopts);
	free(optstr);

	/* ensure that only one secure mode is requested */
	if (nmdp->nmd_sec_opt > 1)
		return (-EINVAL);

	/* ensure that the user isn't trying to get large files over V2 */
	if (nmdp->nmd_nfsvers == NFS_VERSION && largefiles)
		return (-EINVAL);

	if (nmdp->nmd_nfsvers == NFS_V4) {
		/*
		 * NFSv4 specifies the TCP protocol and port 2049 - default to
		 * these. The user-level mount code is not expected to pass
		 * these in, but if it did, validate the proto value.
		 */
		if (nmdp->nmd_nfs_proto == NULL) {
			nmdp->nmd_nfs_proto = strdup(NC_TCP);
			if (nmdp->nmd_nfs_proto == NULL)
				return (-ENOMEM);

		} else if (strcmp(nmdp->nmd_nfs_proto, NC_TCP) != 0) {
			return (-EINVAL);
		}

	} else {
		/*
		 * The user-level mount code normally passes in the proto, but
		 * if it didn't for some reason, use a sensible default.
		 * Otherwise we normally just validate the proto value and we
		 * only support TCP or UDP.
		 */
		if (nmdp->nmd_nfs_proto == NULL) {
			nmdp->nmd_nfs_proto = strdup(NC_TCP);
			if (nmdp->nmd_nfs_proto == NULL)
				return (-ENOMEM);

		} else if (strcmp(nmdp->nmd_nfs_proto, NC_TCP) != 0 &&
		    strcmp(nmdp->nmd_nfs_proto, NC_UDP) != 0) {
			return (-EINVAL);
		}
	}

	/*
	 * The user-level mount code only passes the port when it is
	 * non-standard.
	 */
	if (nmdp->nmd_nfs_port == 0) {
		nmdp->nmd_nfs_port = NFS_PORT;
	}

	return (0);

badopt:
	free(optstr);
	return (-EINVAL);
}

static int
make_secure(struct nfs_args *args, nfs_mnt_data_t *nmdp)
{
	sec_data_t *secdata;

	/*
	 * Check to see if any secure mode is requested. If not, use default
	 * security mode. Note: we currently only support sec=none and sec=sys.
	 */
	if (nmdp->nmd_sec_opt == 0) {
		/* AUTH_UNIX is the default. */
		(void) strlcpy(nmdp->nmd_nfs_sec.sc_name, "sys", MAX_NAME_LEN);
		nmdp->nmd_nfs_sec.sc_nfsnum = nmdp->nmd_nfs_sec.sc_rpcnum = 1;
		args->flags |= NFSMNT_SECDEFAULT;
	}

	secdata = malloc(sizeof (sec_data_t));
	if (secdata == NULL)
		return (-ENOMEM);

	(void) memset(secdata, 0, sizeof (sec_data_t));

	secdata->secmod = nmdp->nmd_nfs_sec.sc_nfsnum;
	secdata->rpcflavor = nmdp->nmd_nfs_sec.sc_rpcnum;
	secdata->uid = nmdp->nmd_nfs_sec.sc_uid;
	secdata->flags = 0;
	secdata->data = NULL;

	args->nfs_args_ext = NFS_ARGS_EXTB;
	args->nfs_ext_u.nfs_extB.secdata = secdata;

	return (0);
}

/*
 * Use our built-in netconfig table to lookup and construct a netconfig struct
 * for the given netid.
 */
static struct netconfig *
get_netconf(char *id)
{
	int i;
	struct netconfig *nconf, *np;

	if ((nconf = calloc(1, sizeof (struct netconfig))) == NULL)
		return (NULL);

	for (i = 0; i < N_NETCONF_ENTS; i++) {
		np = &nca[i];
		if (strcmp(np->nc_netid, id) != 0)
			continue;

		nconf->nc_semantics = np->nc_semantics;
		if ((nconf->nc_netid = strdup(np->nc_netid)) == NULL)
			goto out;
		if ((nconf->nc_protofmly = strdup(np->nc_protofmly)) == NULL)
			goto out;
		if ((nconf->nc_proto = strdup(np->nc_proto)) == NULL)
			goto out;
		if ((nconf->nc_device = strdup(np->nc_device)) == NULL)
			goto out;

		return (nconf);
	}

out:
	freenetconfigent(nconf);
	return (NULL);
}

/*
 * If the user provided a logical name for the NFS server, then the user-level
 * mount command will have already resolved that name and passed it in using
 * the 'addr' option (see convert_nfs_arg_str where we've already handled this).
 * We construct a netbuf from that provided IP and a given port option.
 *
 * Note: this code may need to be revisited when we add IPv6 support.
 */
static struct netbuf *
get_netbuf(struct netconfig *nconf, char *ip, ushort_t port)
{
	char buf[64];

	assert(port != 0);
	(void) snprintf(buf, sizeof (buf), "%s.%d.%d", ip,
	    port >> 8 & 0xff, port & 0xff);
	return (uaddr2taddr(nconf, buf));
}

/*
 * Construct a CLIENT handle to talk to the mountd without having to contact
 * the rpcbind daemon on the server. This works for both the TCP and UDP cases,
 * but it is primarily intended to the handle the TCP case. As an aside, note
 * that TCP is never used by the native NFS mount client, even when the
 * 'proto=tcp' argument is given to the mount command. The native mount code
 * always uses UDP to get a file handle from the mountd.
 */
static CLIENT *
get_mountd_client(char *fshost, nfs_mnt_data_t *nmdp, int *fdp)
{
	struct netconfig *nconf;
	struct netbuf *srvaddr;
	CLIENT *cl = NULL;
	rpcvers_t vers;
	int fd;
	struct t_bind *tbind = NULL;
	struct t_info tinfo;

	vers = nmdp->nmd_mnt_vers;
	*fdp = -1;

	if ((nconf = get_netconf(nmdp->nmd_mnt_proto)) == NULL)
		return (NULL);

	if ((srvaddr = get_netbuf(nconf, fshost, nmdp->nmd_mnt_port)) == NULL) {
		freenetconfigent(nconf);
		return (NULL);
	}

	tinfo.tsdu = 0;
	if ((fd = t_open(nconf->nc_device, O_RDWR, &tinfo)) == -1)
		goto done;

	/* LINTED pointer alignment */
	if ((tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR)) == NULL) {
		(void) t_close(fd);
		goto done;
	}

	/* assign our srvaddr to tbind addr */
	(void) memcpy(tbind->addr.buf, srvaddr->buf, srvaddr->len);
	tbind->addr.len = srvaddr->len;

	/*
	 * For compatibility, the mountd call to get the file handle must come
	 * from a privileged port.
	 */
	(void) netdir_options(nconf, ND_SET_RESERVEDPORT, fd, NULL);

	cl = clnt_tli_create(fd, nconf, &tbind->addr, MOUNTPROG, vers, 0, 0);
	if (cl == NULL) {
		(void) t_close(fd);
		/*
		 * Unfortunately, a failure in the:
		 *    clnt_tli_create -> set_up_connection -> t_connect
		 * call path doesn't return any useful information about why we
		 * had an error. We basically see the following rpc_createerr
		 * status for a variety of conditions (e.g. invalid port, no
		 * service at IP, timeout, etc.):
		 *    rpc_createerr.cf_stat == RPC_TLIERROR
		 *    rpc_createerr.cf_error.re_terrno == 9 (TLOOK)
		 *    rpc_createerr.cf_error.re_errno == 0
		 */
	} else {
		*fdp = fd;
	}

done:
	if (tbind != NULL)
		(void) t_free((char *)tbind, T_BIND);
	free(srvaddr->buf);
	free(srvaddr);
	freenetconfigent(nconf);

	return (cl);
}

static int
get_fh_cleanup(CLIENT *cl, int fd, int err)
{
	if (cl != NULL)
		clnt_destroy(cl);
	if (fd != -1)
		(void) t_close(fd);
	assert(err <= 0);
	return (err);
}

/*
 * Get fhandle of remote path from server's mountd. This is only applicable to
 * v2 or v3.
 */
static int
get_fh(struct nfs_args *args, char *fshost, char *fspath, nfs_mnt_data_t *nmdp)
{
	struct fhstatus fhs;
	struct mountres3 mountres3;
	struct pathcnf p;
	nfs_fh3 *fh3p;
	struct timeval timeout = { 25, 0};
	CLIENT *cl = NULL;
	int fd = -1;
	enum clnt_stat rpc_stat;
	int count, i, *auths;

	bzero(&fhs, sizeof (fhs));
	bzero(&mountres3, sizeof (mountres3));
	bzero(&p, sizeof (p));

	/*
	 * The user-level mount code should have contacted the server's rpcbind
	 * daemon and passed us the mount protocol and port.
	 */
	if (nmdp->nmd_mnt_port == 0 || nmdp->nmd_mnt_proto == NULL ||
	    nmdp->nmd_mnt_vers == 0) {
		return (-EAGAIN);
	}

	cl = get_mountd_client(fshost, nmdp, &fd);
	if (cl == NULL) {
		/*
		 * As noted in get_mountd_client, we don't get a good indication
		 * as to why the connection failed. Linux returns ETIMEDOUT
		 * under many of the same conditions, and our native code notes
		 * that this is a common reason, so we do that here too.
		 */
		return (-ETIMEDOUT);
	}

	if ((cl->cl_auth = authsys_create_default()) == NULL) {
		return (get_fh_cleanup(cl, fd, -EAGAIN));
	}

	if (nmdp->nmd_mnt_vers == 2) {
		rpc_stat = clnt_call(cl, MOUNTPROC_MNT, xdr_dirpath,
		    (caddr_t)&fspath, xdr_fhstatus, (caddr_t)&fhs, timeout);
		if (rpc_stat != RPC_SUCCESS) {
			log_err("%s:%s: server not responding %s\n",
			    fshost, fspath, clnt_sperror(cl, ""));
			return (get_fh_cleanup(cl, fd, -EAGAIN));
		}

		if ((errno = fhs.fhs_status) != MNT_OK) {
			return (get_fh_cleanup(cl, fd, -fhs.fhs_status));
		}
		args->fh = malloc(sizeof (fhs.fhstatus_u.fhs_fhandle));
		if (args->fh == NULL)
			return (get_fh_cleanup(cl, fd, -EAGAIN));

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
				return (get_fh_cleanup(cl, fd, -EAGAIN));
			}
			if (_PC_ISSET(_PC_ERROR, p.pc_mask)) {
				free(args->fh);
				return (get_fh_cleanup(cl, fd, -EAGAIN));
			}
			args->flags |= NFSMNT_POSIX;
			args->pathconf = malloc(sizeof (p));
			if (args->pathconf == NULL) {
				free(args->fh);
				return (get_fh_cleanup(cl, fd, -EAGAIN));
			}
			(void) memcpy((caddr_t)args->pathconf, (caddr_t)&p,
			    sizeof (p));
		}

	} else { /* nmdp->nmd_mnt_vers == 3 */

		rpc_stat = clnt_call(cl, MOUNTPROC_MNT, xdr_dirpath,
		    (caddr_t)&fspath, xdr_mountres3, (caddr_t)&mountres3,
		    timeout);
		if (rpc_stat != RPC_SUCCESS) {
			log_err("%s:%s: server not responding %s\n",
			    fshost, fspath, clnt_sperror(cl, ""));
			return (get_fh_cleanup(cl, fd, -EAGAIN));
		}

		/*
		 * Assume here that most of the MNT3ERR_*
		 * codes map into E* errors. See the nfsstat enum for values.
		 */
		if ((errno = mountres3.fhs_status) != MNT_OK) {
			return (get_fh_cleanup(cl, fd, -mountres3.fhs_status));
		}

		fh3p = (nfs_fh3 *)malloc(sizeof (*fh3p));
		if (fh3p == NULL)
			return (get_fh_cleanup(cl, fd, -EAGAIN));

		fh3p->fh3_length =
		    mountres3.mountres3_u.mountinfo.fhandle.fhandle3_len;
		(void) memcpy(fh3p->fh3_u.data,
		    mountres3.mountres3_u.mountinfo.fhandle.fhandle3_val,
		    fh3p->fh3_length);
		args->fh = (caddr_t)fh3p;
		nmdp->nmd_fstype = MNTTYPE_NFS3;

		/*
		 * If "sec=flavor" is a mount option, check if the server
		 * supports the "flavor". If the server does not support the
		 * flavor, return error. It is unlikely that the server will
		 * not support "sys", although "none" may not be allowed.
		 */
		auths =
		    mountres3.mountres3_u.mountinfo.auth_flavors
		    .auth_flavors_val;
		count =
		    mountres3.mountres3_u.mountinfo.auth_flavors
		    .auth_flavors_len;

		if (count <= 0) {
			return (get_fh_cleanup(cl, fd, -EAGAIN));
		}

		if (nmdp->nmd_sec_opt) {
			for (i = 0; i < count; i++) {
				if (auths[i] == nmdp->nmd_nfs_sec.sc_nfsnum)
					break;
			}
			if (i == count)
				return (get_fh_cleanup(cl, fd, -EACCES));
		} else {
			/* AUTH_SYS is our default. */
			(void) strlcpy(nmdp->nmd_nfs_sec.sc_name, "sys",
			    MAX_NAME_LEN);
			nmdp->nmd_nfs_sec.sc_nfsnum =
			    nmdp->nmd_nfs_sec.sc_rpcnum = 1;
		}
	}

	return (get_fh_cleanup(cl, fd, 0));
}

/*
 * Fill in the address for the server's NFS service and fill in a knetconfig
 * structure for the transport that the service is available on.
 */
static int
getaddr_nfs(struct nfs_args *args, char *fshost, struct netconfig **nconfp,
    nfs_mnt_data_t *nmdp)
{
	struct stat sb;
	struct netconfig *nconf = NULL;
	struct knetconfig *knconfp;
	struct t_info tinfo;
	err_ret_t addr_error;

	SET_ERR_RET(&addr_error, ERR_PROTO_NONE, 0);

	/*
	 * Given the values passed in from the user-land mount command (or our
	 * built-in defaults), we should have the necessary NFS host address
	 * info. We have already validated that we have a supported
	 * nmd_nfs_proto.
	 */
	assert(nmdp->nmd_nfs_port != 0);
	assert(nmdp->nmd_nfs_proto != NULL);
	nconf = get_netconf(nmdp->nmd_nfs_proto);
	assert(nconf != NULL);
	args->addr = get_netbuf(nconf, fshost, nmdp->nmd_nfs_port);
	if (args->addr == NULL)
		return (-ENOMEM);
	*nconfp = nconf;
	tinfo.tsdu = 0;

	/* This shouldn't fail unless the zone is misconfigured */
	if (stat(nconf->nc_device, &sb) < 0)
		return (-ENOSR);

	knconfp = (struct knetconfig *)malloc(sizeof (*knconfp));
	if (!knconfp)
		return (-ENOMEM);

	knconfp->knc_semantics = nconf->nc_semantics;
	knconfp->knc_protofmly = nconf->nc_protofmly;
	knconfp->knc_proto = nconf->nc_proto;
	knconfp->knc_rdev = sb.st_rdev;
	args->flags |= NFSMNT_KNCONF;
	args->knconf = knconfp;

	/* make sure we don't overload the transport */
	if (tinfo.tsdu > 0 && tinfo.tsdu < NFS_MAXDATA + NFS_RPC_HDR) {
		args->flags |= (NFSMNT_RSIZE | NFSMNT_WSIZE);
		if (args->rsize == 0 || args->rsize > tinfo.tsdu - NFS_RPC_HDR)
			args->rsize = tinfo.tsdu - NFS_RPC_HDR;
		if (args->wsize == 0 || args->wsize > tinfo.tsdu - NFS_RPC_HDR)
			args->wsize = tinfo.tsdu - NFS_RPC_HDR;
	}

	return (0);
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
convert_nfs_arg_str(char *srcp, char *mntopts, nfs_mnt_data_t *nmdp)
{
	char *key, *val, *p;
	char tmpbuf[MAX_MNTOPT_STR];
	char *tbp = tmpbuf;
	boolean_t no_sec = B_TRUE;
	boolean_t no_addr = B_TRUE;

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

				no_addr = B_FALSE;
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
				/*
				 * Linux supports: none, sys, krb5, krb5i, and
				 * krb5p. Of these, only none and sys overlap
				 * with our current support. Anything else is
				 * an error.
				 */
				int r;

				if (strcmp(val, "none") != 0 &&
				    strcmp(val, "sys") != 0)
					return (-EINVAL);
				r = append_opt(mntopts, MAX_MNTOPT_STR, key,
				    val);
				if (r != 0)
					return (r);
				no_sec = B_FALSE;
			} else if (strcmp(key, "nolock") == 0) {
				int r;
				nmdp->nmd_nolock_opt = 1;
				r = append_opt(mntopts, MAX_MNTOPT_STR, key,
				    val);
				if (r != 0)
					return (r);
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

	if (no_addr) {
		/*
		 * The Linux kernel requires an 'addr' option and will return
		 * EINVAL if one has not been provided. In particular, this
		 * behavior can be seen when the package which delivers NFS CLI
		 * support (e.g. nfs-common on Ubuntu, nfs-utils on Centos,
		 * etc.) is not installed. The generic mount command will not
		 * implicitly pass in the 'addr' option, the kernel will return
		 * EINVAL, and the mount will fail.
		 */
		return (-EINVAL);
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

int
lx_nfs_mount(char *srcp, char *mntp, char *fst, int lx_flags, char *opts)
{
	int r;
	int il_flags = 0;
	nfs_mnt_data_t nmd, *nmdp = &nmd;
	struct nfs_args *argp = NULL;
	struct netconfig *nconf = NULL;
	char *colonp;
	char *path;
	char *host;
	char spec_buf[MAXPATHLEN + LX_NMD_MAXHOSTNAMELEN + 1];

	bzero(&nmd, sizeof (nmd));
	nmd.nmd_fstype = MNTTYPE_NFS;

	/*
	 * This will modify the special string so that the hostname passed
	 * in will be replaced with the host address that the user-land code
	 * looked up. This also converts the opts string so that we'll be
	 * dealing with illumos options after this.
	 */
	if ((r = convert_nfs_arg_str(srcp, opts, nmdp)) < 0) {
		return (r);
	}

	if (strcmp(fst, "nfs4") == 0)
		nmdp->nmd_nfsvers = NFS_V4;

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

	(void) strlcpy(spec_buf, srcp, sizeof (spec_buf));
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

	/* returns a negative errno */
	if ((r = set_args(&il_flags, argp, host, opts, nmdp)) != 0)
		goto out;

	if (nmdp->nmd_nfsvers == NFS_V4) {
		/*
		 * In the case of version 4 there is no MOUNT program, thus no
		 * need for an RPC to get a file handle.
		 */
		nmdp->nmd_fstype = MNTTYPE_NFS4;
		argp->fh = strdup(path);
		if (argp->fh == NULL) {
			r = -ENOMEM;
			goto out;
		}
	} else {
		if ((r = get_fh(argp, host, path, nmdp)) < 0)
			goto out;
	}

	if ((r = getaddr_nfs(argp, host, &nconf, nmdp)) < 0)
		goto out;

	if ((r = make_secure(argp, nmdp)) < 0)
		goto out;

	il_flags |= MS_DATA | MS_OPTIONSTR;

	r = mount(srcp, mntp, il_flags, nmdp->nmd_fstype, argp, sizeof (*argp),
	    opts, MAX_MNTOPT_STR);
	if (r != 0) {
		r = -errno;
	} else if (nmdp->nmd_nolock_opt == 0) {
		(void) syscall(SYS_brand, B_START_NFS_LOCKD);
	}

out:
	if (nconf != NULL)
		freenetconfigent(nconf);
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
	if (argp->nfs_ext_u.nfs_extB.secdata)
		free(argp->nfs_ext_u.nfs_extB.secdata);
	if (argp->syncaddr) {
		free(argp->syncaddr->buf);
		free(argp->syncaddr);
	}
	if (argp->netname)
		free(argp->netname);
	free(argp);
	if (nmdp->nmd_nfs_proto != NULL)
		free(nmdp->nmd_nfs_proto);

	return (r);
}
