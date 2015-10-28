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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.
 */

#include <alloca.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <nfs/mount.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/lx_autofs.h>
#include <sys/lx_debug.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>
#include <sys/lx_mount.h>

/*
 * support definitions
 */
union fh_buffer {
	struct nfs_fid	fh2;
	struct nfs_fh3	fh3;
	char		fh_data[NFS3_FHSIZE + 2];
};

typedef enum mount_opt_type {
	MOUNT_OPT_INVALID	= 0,
	MOUNT_OPT_NORMAL	= 1,	/* option value: none */
	MOUNT_OPT_UINT		= 2,	/* option value: unsigned int */
	MOUNT_OPT_BYTESIZE	= 3	/* option value: byte size, e.g. 25m */
} mount_opt_type_t;

typedef struct mount_opt {
	char			*mo_name;
	mount_opt_type_t	mo_type;
} mount_opt_t;


/*
 * Globals
 */
mount_opt_t lofs_options[] = {
	{ NULL,			MOUNT_OPT_INVALID }
};

mount_opt_t lx_proc_options[] = {
	{ NULL,			MOUNT_OPT_INVALID }
};

mount_opt_t lx_sysfs_options[] = {
	{ NULL,			MOUNT_OPT_INVALID }
};

mount_opt_t lx_tmpfs_options[] = {
	{ "size",		MOUNT_OPT_BYTESIZE },
	{ "mode",		MOUNT_OPT_UINT },
	{ "uid",		MOUNT_OPT_UINT },
	{ "gid",		MOUNT_OPT_UINT },
	{ NULL,			MOUNT_OPT_INVALID }
};

mount_opt_t lx_autofs_options[] = {
	{ LX_MNTOPT_FD,		MOUNT_OPT_UINT },
	{ LX_MNTOPT_PGRP,	MOUNT_OPT_UINT },
	{ LX_MNTOPT_MINPROTO,	MOUNT_OPT_UINT },
	{ LX_MNTOPT_MAXPROTO,	MOUNT_OPT_UINT },
	{ LX_MNTOPT_INDIRECT,	MOUNT_OPT_NORMAL },
	{ LX_MNTOPT_DIRECT,	MOUNT_OPT_NORMAL },
	{ NULL,			MOUNT_OPT_INVALID }
};


/*
 * i_lx_opt_verify() - Check the mount options.
 *
 * You might wonder why we're being so strict about the mount options
 * we allow.  The reason is that normally all mount option verification
 * is done by the Solaris userland mount command.  Once mount options
 * are passed to the kernel, invalid options are simply ignored.  So
 * if we actually want to catch requests for functionality that we
 * don't support, or if we want to make sure that we don't randomly
 * enable options that we haven't check to make sure they have the
 * same syntax on Linux and Solaris, we need to reject any options
 * we don't know to be ok here.
 */
static int
i_lx_opt_verify(char *opts, mount_opt_t *mop)
{
	int	opts_len = strlen(opts);
	char	*opts_tmp, *opt;
	int	opt_len, i;

	assert((opts != NULL) && (mop != NULL));

	/* If no options were specified, there's no problem. */
	if (opts_len == 0) {
		errno = 0;
		return (0);
	}

	/* If no options are allowed, fail. */
	if (mop[0].mo_name == NULL) {
		errno = ENOTSUP;
		return (-1);
	}

	/* Don't accept leading or trailing ','. */
	if ((opts[0] == ',') || (opts[opts_len] == ',')) {
		errno = EINVAL;
		return (-1);
	}

	/* Don't accept sequential ','. */
	for (i = 1; i < opts_len; i++) {
		if ((opts[i - 1] ==  ',') && (opts[i] ==  ',')) {
			errno = EINVAL;
			return (-1);
		}
	}

	/*
	 * We're going to use strtok() which modifies the target
	 * string so make a temporary copy.
	 */
	opts_tmp = SAFE_ALLOCA(opts_len);
	if (opts_tmp == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	bcopy(opts, opts_tmp, opts_len + 1);

	/* Verify each prop one at a time. */
	opt = strtok(opts_tmp, ",");
	opt_len = strlen(opt);
	for (;;) {

		/* Check for matching option/value pair. */
		for (i = 0; mop[i].mo_name != NULL; i++) {
			char	*ovalue;
			int	ovalue_len, mo_len;

			/* If the options is too short don't bother comparing */
			mo_len = strlen(mop[i].mo_name);
			if (opt_len < mo_len) {
				/* Keep trying to find a match. */
				continue;
			}

			/* Compare the option to an allowed option. */
			if (strncmp(mop[i].mo_name, opt, mo_len) != 0) {
				/* Keep trying to find a match. */
				continue;
			}

			if (mop[i].mo_type == MOUNT_OPT_NORMAL) {
				/* The option doesn't take a value. */
				if (opt_len == mo_len) {
					/* This option is ok. */
					break;
				} else {
					/* Keep trying to find a match. */
					continue;
				}
			}

			/* This options takes a value. */
			if ((opt_len == mo_len) || (opt[mo_len] != '=')) {
				/* Keep trying to find a match. */
				continue;
			}

			/* We have an option match.  Verify option value. */
			ovalue = &opt[mo_len] + 1;
			ovalue_len = strlen(ovalue);

			/* Value can't be zero length string. */
			if (ovalue_len == 0) {
				errno = EINVAL;
				return (-1);
			}

			if (mop[i].mo_type == MOUNT_OPT_UINT) {
				int j;
				/* Verify that value is an unsigned int. */
				for (j = 0; j < ovalue_len; j++) {
					if (!isdigit(ovalue[j])) {
						errno = EINVAL;
						return (-1);
					}
				}
			} else if (mop[i].mo_type == MOUNT_OPT_BYTESIZE) {
				int j;
				int stage = 0;

				/*
				 * Verify that the value is an unsigned integer
				 * that ends in a magnitude suffix (i.e. 'k'
				 * or 'm') or a '%' character.
				 */
				for (j = 0; j < ovalue_len; j++) {
					switch (stage) {
					case 0:
						/*
						 * Look for at least one digit.
						 */
						if (!isdigit(ovalue[j])) {
							errno = EINVAL;
							return (-1);
						}
						stage = 1;
						break;
					case 1:
						/*
						 * Allow an unlimited number of
						 * digits.
						 */
						if (isdigit(ovalue[j])) {
							break;
						}
						/*
						 * Allow one (valid) byte
						 * magnitude character.
						 */
						if (ovalue[j] == 'm' ||
						    ovalue[j] == 'k' ||
						    ovalue[j] == '\%') {
							stage = 2;
							break;
						}
						errno = EINVAL;
						return (-1);
					case 2:
						/*
						 * Invalid trailing characters.
						 */
						errno = EINVAL;
						return (-1);
					}
				}

				if (stage < 1) {
					errno = EINVAL;
					return (-1);
				}
			} else {
				/* Unknown option type specified. */
				assert(0);
			}

			/* The option is ok. */
			break;
		}

		/* If there were no matches this is an unsupported option. */
		if (mop[i].mo_name == NULL) {
			errno = EINVAL;
			return (-1);
		}

		/* This option is ok, move onto the next option. */
		if ((opt = strtok(NULL, ",")) == NULL)
			break;
		opt_len = strlen(opt);
	};

	/* We verified all the options. */
	return (0);
}

/*
 * Remove an option from the string and save it in the provided buffer.
 * The option string should have already been verified as valid.
 * Return 0 if not present, -1 if error, and 1 if present and fine.
 */
static int
opt_rm(char *opts, char *rmopt, char *retstr, int retlen)
{
	int	opts_len = strlen(opts);
	char	*optstart, *optend;
	int	optlen;

	assert((opts != NULL) && (rmopt != NULL));

	retstr[0] = '\0';

	/* If no options were specified, there's no problem. */
	if (opts_len == 0)
		return (0);

	if ((optstart = strstr(opts, rmopt)) == NULL)
		return (0);

	for (optend = optstart; *optend != ',' && *optend != '\0'; optend++)
		;

	optlen = optend - optstart;
	if (optlen >= retlen)
		return (-1);
	strncpy(retstr, optstart, optlen);
	retstr[optlen] = '\0';

	if (*optend == ',')
		optend++;

	optlen = strlen(optend) + 1;
	bcopy(optend, optstart, optlen);

	if (*optstart == '\0' && optstart != opts) {
		/* removed last opt and it had a preceeding opt, remove comma */
		*(optstart - 1) = '\0';
	}

	return (1);
}

static int
opt_id_val(char *opt, int *valp)
{
	char *vp;
	long lval;

	if ((vp = strchr(opt, '=')) == NULL)
		return (-1);

	vp++;
	if (!isdigit(*vp))
		return (-1);

	lval = strtol(vp, &vp, 10);
	if (*vp != '\0' || lval > INT_MAX)
		return (-1);

	*valp = (int)lval;
	return (0);
}

static int
i_add_option(char *option, char *buf, size_t buf_size)
{
	char *fmt_str = NULL;

	assert((option != NULL) && (strlen(option) > 0));
	assert((buf != NULL) && (buf_size > 0));

	if (buf[0] == '\0') {
		fmt_str = "%s";
	} else {
		fmt_str = ",%s";
	}

	buf_size -= strlen(buf);
	buf += strlen(buf);

	/*LINTED*/
	if (snprintf(buf, buf_size, fmt_str, option) > (buf_size - 1))
		return (-EOVERFLOW);
	return (0);
}

static int
i_add_option_int(char *option, int val, char *buf, size_t buf_size)
{
	char *fmt_str = NULL;

	assert((option != NULL) && (strlen(option) > 0));
	assert((buf != NULL) && (buf_size > 0));

	if (buf[0] == '\0') {
		fmt_str = "%s=%d";
	} else {
		fmt_str = ",%s=%d";
	}

	buf_size -= strlen(buf);
	buf += strlen(buf);

	/*LINTED*/
	if (snprintf(buf, buf_size, fmt_str, option, val) > (buf_size - 1))
		return (-EOVERFLOW);
	return (0);
}

static int
i_make_nfs_args(lx_nfs_mount_data_t *lx_nmd, struct nfs_args *nfs_args,
    struct netbuf *nfs_args_addr, struct knetconfig *nfs_args_knconf,
    union fh_buffer *nfs_args_fh, struct sec_data *nfs_args_secdata,
    char *fstype, char *options, int options_size)
{
	struct stat	statbuf;
	int		i, rv, use_tcp;

	/* Sanity check the incomming Linux request. */
	if ((lx_nmd->nmd_rsize < 0) || (lx_nmd->nmd_wsize < 0) ||
	    (lx_nmd->nmd_timeo < 0) || (lx_nmd->nmd_retrans < 0) ||
	    (lx_nmd->nmd_acregmin < 0) || (lx_nmd->nmd_acregmax < 0) ||
	    (lx_nmd->nmd_acdirmax < 0)) {
		return (-EINVAL);
	}

	/*
	 * Additional sanity checks of incomming request.
	 *
	 * Some of the sanity checks below should probably return
	 * EINVAL (or some other error code) instead or ENOTSUP,
	 * but without experiminting on Linux to see how it
	 * deals with certain strange values there is no way
	 * to really know what we should return, hence we return
	 * ENOTSUP to tell us that eventually if we see some
	 * application hitting the problem we can go to a real
	 * Linux system, figure out how it deals with the situation
	 * and update our code to handle it in the same fashion.
	 */
	if (lx_nmd->nmd_version != 4) {
		lx_unsupported("unsupported nfs mount request, "
		    "unrecognized NFS mount structure: %d\n",
		    lx_nmd->nmd_version);
		return (-ENOTSUP);
	}
	if ((lx_nmd->nmd_flags & ~LX_NFS_MOUNT_SUPPORTED) != 0) {
		lx_unsupported("unsupported nfs mount request, "
		    "flags: 0x%x\n", lx_nmd->nmd_flags);
		return (-ENOTSUP);
	}
	if (lx_nmd->nmd_addr.sin_family != AF_INET) {
		lx_unsupported("unsupported nfs mount request, "
		    "transport address family: 0x%x\n",
		    lx_nmd->nmd_addr.sin_family);
		return (-ENOTSUP);
	}
	for (i = 0; i < LX_NMD_MAXHOSTNAMELEN; i++) {
		if (lx_nmd->nmd_hostname[i] == '\0')
			break;
	}
	if (i == 0) {
		lx_unsupported("unsupported nfs mount request, "
		    "no hostname specified\n");
		return (-ENOTSUP);
	}
	if (i == LX_NMD_MAXHOSTNAMELEN) {
		lx_unsupported("unsupported nfs mount request, "
		    "hostname not terminated\n");
		return (-ENOTSUP);
	}
	if (lx_nmd->nmd_namlen < i) {
		lx_unsupported("unsupported nfs mount request, "
		    "invalid namlen value: 0x%x\n", lx_nmd->nmd_namlen);
		return (-ENOTSUP);
	}
	if (lx_nmd->nmd_bsize != 0) {
		lx_unsupported("unsupported nfs mount request, "
		    "bsize value: 0x%x\n", lx_nmd->nmd_bsize);
		return (-ENOTSUP);
	}

	/* Initialize and clear the output structure pointers passed in. */
	bzero(nfs_args, sizeof (*nfs_args));
	bzero(nfs_args_addr, sizeof (*nfs_args_addr));
	bzero(nfs_args_knconf, sizeof (*nfs_args_knconf));
	bzero(nfs_args_fh, sizeof (*nfs_args_fh));
	bzero(nfs_args_secdata, sizeof (*nfs_args_secdata));
	nfs_args->addr = nfs_args_addr;
	nfs_args->knconf = nfs_args_knconf;
	nfs_args->fh = (caddr_t)nfs_args_fh;
	nfs_args->nfs_ext_u.nfs_extB.secdata = nfs_args_secdata;

	/* Check if we're using tcp. */
	use_tcp = (lx_nmd->nmd_flags & LX_NFS_MOUNT_TCP) ? 1 : 0;

	/*
	 * These seem to be the default flags used by Solaris for v2 and v3
	 * nfs mounts.
	 *
	 * Don't bother with NFSMNT_TRYRDMA since we always specify a
	 * transport (either udp or tcp).
	 */
	nfs_args->flags = NFSMNT_NEWARGS | NFSMNT_KNCONF | NFSMNT_INT |
	    NFSMNT_HOSTNAME;

	/* Translate some Linux mount flags into Solaris mount flags. */
	if (lx_nmd->nmd_flags & LX_NFS_MOUNT_SOFT)
		nfs_args->flags |= NFSMNT_SOFT;
	if (lx_nmd->nmd_flags & LX_NFS_MOUNT_INTR)
		nfs_args->flags |= NFSMNT_INT;
	if (lx_nmd->nmd_flags & LX_NFS_MOUNT_POSIX)
		nfs_args->flags |= NFSMNT_POSIX;
	if (lx_nmd->nmd_flags & LX_NFS_MOUNT_NOCTO)
		nfs_args->flags |= NFSMNT_NOCTO;
	if (lx_nmd->nmd_flags & LX_NFS_MOUNT_NOAC)
		nfs_args->flags |= NFSMNT_NOAC;
	if (lx_nmd->nmd_flags & LX_NFS_MOUNT_NONLM)
		nfs_args->flags |= NFSMNT_LLOCK;

	if ((lx_nmd->nmd_flags & LX_NFS_MOUNT_VER3) != 0) {
		(void) strcpy(fstype, "nfs3");
		if ((rv = i_add_option_int("vers", 3,
		    options, options_size)) != 0)
			return (rv);

		if (lx_nmd->nmd_root.lx_fh3_length >
		    sizeof (nfs_args_fh->fh3.fh3_u.data)) {
			lx_unsupported("unsupported nfs mount request, "
			    "nfs file handle length: 0x%x\n",
			    lx_nmd->nmd_root.lx_fh3_length);
			return (-ENOTSUP);
		}

		/* Set the v3 file handle info. */
		nfs_args_fh->fh3.fh3_length = lx_nmd->nmd_root.lx_fh3_length;
		bcopy(&lx_nmd->nmd_root.lx_fh3_data,
		    nfs_args_fh->fh3.fh3_u.data,
		    lx_nmd->nmd_root.lx_fh3_length);
	} else {
		/*
		 * Assume nfs v2.  Note that this could also be a v1
		 * mount request but there doesn't seem to be any difference
		 * in the parameters passed to the Linux mount system
		 * call for v1 or v2 mounts so there is no way of really
		 * knowing.
		 */
		(void) strcpy(fstype, "nfs");
		if ((rv = i_add_option_int("vers", 2,
		    options, options_size)) != 0)
			return (rv);

		/* Solaris seems to add this flag when using v2. */
		nfs_args->flags |= NFSMNT_SECDEFAULT;

		/* Set the v2 file handle info. */
		bcopy(&lx_nmd->nmd_old_root,
		    nfs_args_fh, sizeof (nfs_args_fh->fh2));
	}

	/*
	 * We can't use getnetconfig() here because there is no netconfig
	 * database in linux.
	 */
	nfs_args_knconf->knc_protofmly = "inet";
	if (use_tcp) {
		/*
		 * TCP uses NC_TPI_COTS_ORD semantics.
		 * See /etc/netconfig.
		 */
		nfs_args_knconf->knc_semantics = NC_TPI_COTS_ORD;
		nfs_args_knconf->knc_proto = "tcp";
		if ((rv = i_add_option("proto=tcp",
		    options, options_size)) != 0)
			return (rv);
		if (stat("/dev/tcp", &statbuf) != 0)
			return (-errno);
		nfs_args_knconf->knc_rdev = statbuf.st_rdev;
	} else {
		/*
		 * Assume UDP.  UDP uses NC_TPI_CLTS semantics.
		 * See /etc/netconfig.
		 */
		nfs_args_knconf->knc_semantics = NC_TPI_CLTS;
		nfs_args_knconf->knc_proto = "udp";
		if ((rv = i_add_option("proto=udp",
		    options, options_size)) != 0)
			return (rv);
		if (stat("/dev/udp", &statbuf) != 0)
			return (-errno);
		nfs_args_knconf->knc_rdev = statbuf.st_rdev;
	}

	/* Set the server address. */
	nfs_args_addr->maxlen = nfs_args_addr->len =
	    sizeof (struct sockaddr_in);
	nfs_args_addr->buf = (char *)&lx_nmd->nmd_addr;

	/* Set the server hostname string. */
	nfs_args->hostname = lx_nmd->nmd_hostname;

	/* Translate Linux nfs mount parameters into Solaris mount options. */
	if (lx_nmd->nmd_rsize != LX_NMD_DEFAULT_RSIZE) {
		if ((rv = i_add_option_int("rsize", lx_nmd->nmd_rsize,
		    options, options_size)) != 0)
			return (rv);
		nfs_args->rsize = lx_nmd->nmd_rsize;
		nfs_args->flags |= NFSMNT_RSIZE;
	}
	if (lx_nmd->nmd_wsize != LX_NMD_DEFAULT_WSIZE) {
		if ((rv = i_add_option_int("wsize", lx_nmd->nmd_wsize,
		    options, options_size)) != 0)
			return (rv);
		nfs_args->wsize = lx_nmd->nmd_wsize;
		nfs_args->flags |= NFSMNT_WSIZE;
	}
	if ((rv = i_add_option_int("timeo", lx_nmd->nmd_timeo,
	    options, options_size)) != 0)
		return (rv);
	nfs_args->timeo = lx_nmd->nmd_timeo;
	nfs_args->flags |= NFSMNT_TIMEO;
	if ((rv = i_add_option_int("retrans", lx_nmd->nmd_retrans,
	    options, options_size)) != 0)
		return (rv);
	nfs_args->retrans = lx_nmd->nmd_retrans;
	nfs_args->flags |= NFSMNT_RETRANS;
	if ((rv = i_add_option_int("acregmin", lx_nmd->nmd_acregmin,
	    options, options_size)) != 0)
		return (rv);
	nfs_args->acregmin = lx_nmd->nmd_acregmin;
	nfs_args->flags |= NFSMNT_ACREGMIN;
	if ((rv = i_add_option_int("acregmax", lx_nmd->nmd_acregmax,
	    options, options_size)) != 0)
		return (rv);
	nfs_args->acregmax = lx_nmd->nmd_acregmax;
	nfs_args->flags |= NFSMNT_ACREGMAX;
	if ((rv = i_add_option_int("acdirmin", lx_nmd->nmd_acdirmin,
	    options, options_size)) != 0)
		return (rv);
	nfs_args->acdirmin = lx_nmd->nmd_acdirmin;
	nfs_args->flags |= NFSMNT_ACDIRMIN;
	if ((rv = i_add_option_int("acdirmax", lx_nmd->nmd_acdirmax,
	    options, options_size)) != 0)
		return (rv);
	nfs_args->acdirmax = lx_nmd->nmd_acdirmax;
	nfs_args->flags |= NFSMNT_ACDIRMAX;

	/* We only support nfs with a security type of AUTH_SYS. */
	nfs_args->nfs_args_ext = NFS_ARGS_EXTB;
	nfs_args_secdata->secmod = AUTH_SYS;
	nfs_args_secdata->rpcflavor = AUTH_SYS;
	nfs_args_secdata->flags = 0;
	nfs_args_secdata->uid = 0;
	nfs_args_secdata->data = NULL;
	nfs_args->nfs_ext_u.nfs_extB.next = NULL;

	/*
	 * The Linux nfs mount command seems to pass an open socket fd
	 * to the kernel during the mount system call.  We don't need
	 * this fd on Solaris so just close it.
	 */
	(void) close(lx_nmd->nmd_fd);

	return (0);
}

static int
run_cgrp_mgr(char *mntpnt)
{
	const char *cmd = "/native/usr/lib/brand/lx/cgrpmgr";
	char *argv[] = { "cgrpmgr", NULL, NULL };

	argv[1] = mntpnt;

	switch (fork1()) {
	case 0:
		/* child */
		execv(cmd, argv);
		exit(1);
		break;

	case -1:
		return (-1);

	default:
		/* the cgroup manager process runs until we unmount */
		break;
	}

	return (0);
}

long
lx_mount(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
    uintptr_t p5)
{
	/* Linux input arguments. */
	const char		*sourcep = (const char *)p1;
	const char		*targetp = (const char *)p2;
	const char		*fstypep = (const char *)p3;
	unsigned int		flags = (unsigned int)p4;
	const void		*datap = (const void *)p5;

	/* Variables needed for all mounts. */
	char			source[MAXPATHLEN + LX_NMD_MAXHOSTNAMELEN + 1];
	char			target[MAXPATHLEN];
	char			fstype[MAXPATHLEN], options[MAX_MNTOPT_STR];
	int			sflags, rv;
	long			res;
	boolean_t		is_tmpfs = B_FALSE;
	boolean_t		is_cgrp = B_FALSE;

	/* Variable for tmpfs mounts. */
	int			uid = -1;
	int			gid = -1;

	/* Variables needed for nfs mounts. */
	lx_nfs_mount_data_t	lx_nmd;
	struct nfs_args		nfs_args;
	struct netbuf 		nfs_args_addr;
	struct knetconfig	nfs_args_knconf;
	union fh_buffer		nfs_args_fh;
	struct sec_data		nfs_args_secdata;
	char			*sdataptr = NULL;
	int			sdatalen = 0;

	/* Initialize Solaris mount arguments. */
	sflags = MS_OPTIONSTR;
	options[0] = '\0';
	sdatalen = 0;

	/* Copy in parameters that are always present. */
	rv = uucopystr((void *)sourcep, &source, sizeof (source));
	if ((rv == -1) || (rv == sizeof (source)))
		return (-EFAULT);

	rv = uucopystr((void *)targetp, &target, sizeof (target));
	if ((rv == -1) || (rv == sizeof (target)))
		return (-EFAULT);

	rv = uucopystr((void *)fstypep, &fstype, sizeof (fstype));
	if ((rv == -1) || (rv == sizeof (fstype)))
		return (-EFAULT);

	lx_debug("\tlinux mount source: %s", source);
	lx_debug("\tlinux mount target: %s", target);
	lx_debug("\tlinux mount fstype: %s", fstype);

	/* Make sure we support the requested mount flags. */
	if ((flags & ~LX_MS_SUPPORTED) != 0) {
		lx_unsupported("unsupported mount flags: 0x%x", flags);
		return (-ENOTSUP);
	}

	/* Do filesystem specific mount work. */
	if (flags & LX_MS_BIND) {

		/* If MS_BIND is set, we turn this into a lofs mount.  */
		(void) strcpy(fstype, "lofs");

		/* Copy in Linux mount options. */
		if (datap != NULL) {
			rv = uucopystr((void *)datap,
			    options, sizeof (options));
			if ((rv == -1) || (rv == sizeof (options)))
				return (-EFAULT);
		}
		lx_debug("\tlinux mount options: \"%s\"", options);

		/* Verify Linux mount options. */
		if (i_lx_opt_verify(options, lofs_options) != 0) {
			lx_unsupported("unsupported lofs mount options: %s",
			    options);
			return (-errno);
		}
	} else if (strcmp(fstype, "tmpfs") == 0) {
		char	idstr[64];

		/* Copy in Linux mount options. */
		if (datap != NULL) {
			rv = uucopystr((void *)datap,
			    options, sizeof (options));
			if ((rv == -1) || (rv == sizeof (options)))
				return (-EFAULT);
		}
		lx_debug("\tlinux mount options: \"%s\"", options);

		/* Verify Linux mount options. */
		if (i_lx_opt_verify(options, lx_tmpfs_options) != 0) {
			lx_unsupported("unsupported tmpfs mount options: %s",
			    options);
			return (-errno);
		}

		/*
		 * Linux defaults to mode=1777 for tmpfs mounts.
		 */
		if (strstr(options, "mode=") == NULL) {
			if (options[0] != '\0')
				(void) strlcat(options, ",", sizeof (options));
			(void) strlcat(options, "mode=1777", sizeof (options));
		}

		switch (opt_rm(options, "uid=", idstr, sizeof (idstr))) {
		case 0:
			uid = -1;
			break;
		case 1:
			if (opt_id_val(idstr, &uid) < 0)
				return (-EINVAL);
			break;
		default:
			return (-E2BIG);
		}
		switch (opt_rm(options, "gid=", idstr, sizeof (idstr))) {
		case 0:
			gid = -1;
			break;
		case 1:
			if (opt_id_val(idstr, &gid) < 0)
				return (-EINVAL);
			break;
		default:
			return (-E2BIG);
		}

		/*
		 * Linux seems to always allow overlay mounts. We allow this
		 * everywhere except under /dev where it interferes with device
		 * emulation.
		 */
		if (strcmp(targetp, "/dev") != 0 &&
		    strncmp(targetp, "/dev/", 5) != 0)
			sflags |= MS_OVERLAY;

		is_tmpfs = B_TRUE;

	} else if (strcmp(fstype, "proc") == 0) {
		struct stat64	sb;

		/* Translate proc mount requests to lx_proc requests. */
		(void) strcpy(fstype, "lx_proc");

		/* Copy in Linux mount options. */
		if (datap != NULL) {
			rv = uucopystr((void *)datap,
			    options, sizeof (options));
			if ((rv == -1) || (rv == sizeof (options)))
				return (-EFAULT);
		}
		lx_debug("\tlinux mount options: \"%s\"", options);

		/* Verify Linux mount options. */
		if (i_lx_opt_verify(options, lx_proc_options) != 0) {
			lx_unsupported("unsupported proc mount options: %s",
			    options);
			return (-errno);
		}

		/* If mounting proc over itself, just return ok */
		if (stat64(target, &sb) == 0 &&
		    strcmp(sb.st_fstype, "lx_proc") == 0) {
			return (0);
		}
	} else if (strcmp(fstype, "sysfs") == 0) {
		/* Translate sysfs mount requests to lx_sysfs requests. */
		(void) strcpy(fstype, "lx_sysfs");

		/* Copy in Linux mount options. */
		if (datap != NULL) {
			rv = uucopystr((void *)datap,
			    options, sizeof (options));
			if ((rv == -1) || (rv == sizeof (options)))
				return (-EFAULT);
		}
		lx_debug("\tlinux mount options: \"%s\"", options);

		/* Verify Linux mount options. */
		if (i_lx_opt_verify(options, lx_sysfs_options) != 0) {
			lx_unsupported("unsupported sysfs mount options: %s",
			    options);
			return (-errno);
		}
	} else if (strcmp(fstype, "cgroup") == 0) {
		/* Translate cgroup mount requests to lx_cgroup requests. */
		(void) strcpy(fstype, "lx_cgroup");

		/* Copy in Linux mount options. */
		if (datap != NULL) {
			rv = uucopystr((void *)datap,
			    options, sizeof (options));
			if ((rv == -1) || (rv == sizeof (options)))
				return (-EFAULT);
		}
		lx_debug("\tlinux mount options: \"%s\"", options);

		is_cgrp = B_TRUE;

		/*
		 * Currently don't verify Linux mount options since we can
		 * have asubsystem string provided.
		 */

	} else if (strcmp(fstype, "autofs") == 0) {

		/* Translate autofs mount requests to lxautofs requests. */
		(void) strcpy(fstype, LX_AUTOFS_NAME);

		/* Copy in Linux mount options. */
		if (datap != NULL) {
			rv = uucopystr((void *)datap,
			    options, sizeof (options));
			if ((rv == -1) || (rv == sizeof (options)))
				return (-EFAULT);
		}
		lx_debug("\tlinux mount options: \"%s\"", options);

		/* Verify Linux mount options. */
		if (i_lx_opt_verify(options, lx_autofs_options) != 0) {
			lx_unsupported("unsupported autofs mount options: %s",
			    options);
			return (-errno);
		}

		/* Linux seems to always allow overlay mounts */
		sflags |= MS_OVERLAY;

	} else if (strcmp(fstype, "nfs") == 0) {

		/*
		 * Copy in Linux mount options. Note that for older Linux
		 * kernels (pre 2.6.23) the mount options pointer (which
		 * normally points to a string) points to a structure which
		 * is populated by the user-level code after it has done the
		 * preliminary RPCs (similar to how our NFS mount cmd works).
		 * For newer kernels the options pointer is just a string of
		 * options. We're unlikely to actually emulate a kernel that
		 * uses the old style but support is kept and handled in
		 * i_make_nfs_args(). The new style handling is implemented in
		 * nfs_pre_mount(). The user-level mount caller is in charge of
		 * determining the format in which it passes the data parameter.
		 */
		int vers;

		if (uucopy((void *)datap, &vers, sizeof (int)) < 0)
			return (-errno);

		/*
		 * As described above, the data parameter might be a versioned
		 * lx_nmd structure or (most likely) it is just a string.
		 */
		switch (vers) {
		case 1:
		case 2:
		case 3:
		case 5:
		case 6:
			lx_unsupported("unsupported nfs mount request "
			    "version: %d\n", vers);
			return (-ENOTSUP);

		case 4:
			if (uucopy((void *)datap, &lx_nmd, sizeof (lx_nmd)) < 0)
				return (-errno);

			/*
			 * For Illumos nfs mounts, the kernel expects a special
			 * structure, but a pointer to this structure is passed
			 * in via an extra parameter (sdataptr below.)
			 */
			if ((rv = i_make_nfs_args(&lx_nmd, &nfs_args,
			    &nfs_args_addr, &nfs_args_knconf, &nfs_args_fh,
			    &nfs_args_secdata, fstype, options,
			    sizeof (options))) != 0)
				return (rv);

			break;

		default:
			/*
			 * Handle new style with options as a string, make
			 * the preliminary RPC calls and do the native mount
			 * all within lx_nfs_mount().
			 */
			if (uucopystr((void *)datap, options,
			    sizeof (options)) < 0)
				return (-errno);
			return (lx_nfs_mount(source, target, fstype, flags,
			    options));
			break;
		}

		/*
		 * For nfs mounts we need to tell the mount system call
		 * to expect extra parameters.
		 */
		sflags |= MS_DATA;
		sdataptr = (char *)&nfs_args;
		sdatalen = sizeof (nfs_args);

		/* Linux seems to always allow overlay mounts */
		sflags |= MS_OVERLAY;

	} else {
		lx_unsupported("unsupported mount filesystem type: %s", fstype);
		return (-ENODEV);
	}

	/* Convert some Linux flags to Illumos flags. */
	if (flags & LX_MS_RDONLY)
		sflags |= MS_RDONLY;
	if (flags & LX_MS_NOSUID)
		sflags |= MS_NOSUID;
	if (flags & LX_MS_REMOUNT)
		sflags |= MS_REMOUNT;

	/*
	 * Convert some Linux flags to Illumos option strings.
	 */
	if (flags & LX_MS_STRICTATIME) {
		/*
		 * The "strictatime" mount option ensures that none of the
		 * weaker atime-related mode options are in effect.
		 */
		flags &= ~(LX_MS_RELATIME | LX_MS_NOATIME);
	}
	if ((flags & LX_MS_NODEV) &&
	    ((rv = i_add_option("nodev", options, sizeof (options))) != 0))
		return (rv);
	if ((flags & LX_MS_NOEXEC) &&
	    ((rv = i_add_option("noexec", options, sizeof (options))) != 0))
		return (rv);
	if ((flags & LX_MS_NOATIME) &&
	    ((rv = i_add_option("noatime", options, sizeof (options))) != 0))
		return (rv);

	lx_debug("\tsolaris mount fstype: %s", fstype);
	lx_debug("\tsolaris mount options: \"%s\"", options);

	res = mount(source, target, sflags, fstype, sdataptr, sdatalen,
	    options, sizeof (options));

	if (res == 0) {
		if (is_cgrp && run_cgrp_mgr(target) != 0) {
			/*
			 * Forking the cgrp manager failed, unmount and return
			 * an ENOMEM error as the best approximation that we're
			 * out of resources.
			 */
			(void) umount(target);
			return (-ENOMEM);
		} else if (is_tmpfs) {
			/* Handle uid/gid mount options. */
			if (uid != -1 || gid != -1)
				(void) chown(target, uid, gid);
			return (0);

		} else {
			return (0);
		}
	} else {
		return (-errno);
	}
}

/*
 * umount() is identical, though it is implemented on top of umount2() in
 * Solaris so it cannot be a pass-thru system call.
 */
long
lx_umount(uintptr_t p1)
{
	return (umount((char *)p1) ? -errno : 0);
}

/*
 * The Linux umount2() system call is identical but has a different value for
 * MNT_FORCE (the logical equivalent to MS_FORCE).
 */
#define	LX_MNT_FORCE	0x1

long
lx_umount2(uintptr_t p1, uintptr_t p2)
{
	char *path = (char *)p1;
	int flags = 0;

	if (p2 & ~LX_MNT_FORCE)
		return (-EINVAL);

	if (p2 & LX_MNT_FORCE)
		flags |= MS_FORCE;

	return (umount2(path, flags) ? -errno : 0);
}
