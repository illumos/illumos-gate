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
 * Copyright 2017 Joyent, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <strings.h>
#include <nfs/mount.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

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

/*
 * The user-level mount(2) code is only used to support NFS mounts. All other
 * fstypes are handled in-kernel.
 */
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

	char			source[MAXPATHLEN + LX_NMD_MAXHOSTNAMELEN + 1];
	char			target[MAXPATHLEN];
	char			fstype[8], options[MAX_MNTOPT_STR];
	int			sflags, rv;
	long			res;

	lx_nfs_mount_data_t	lx_nmd;
	struct nfs_args		nfs_args;
	struct netbuf 		nfs_args_addr;
	struct knetconfig	nfs_args_knconf;
	union fh_buffer		nfs_args_fh;
	struct sec_data		nfs_args_secdata;
	char			*sdataptr = NULL;
	int			sdatalen = 0;
	int			vers;

	/* Initialize illumos mount arguments. */
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

	/* The in-kernel mount code should only call us for an NFS mount. */
	assert(strcmp(fstype, "nfs") == 0 || strcmp(fstype, "nfs4") == 0);

	/*
	 * While SunOS is picky about mount(2) target paths being absolute,
	 * Linux is not so strict.  In order to facilitate this looser
	 * requirement, the cwd is prepended to non-absolute target paths.
	 */
	if (target[0] != '/') {
		char *cpath, *buf = NULL;
		int len;

		if ((cpath = getcwd(NULL, MAXPATHLEN)) == NULL) {
			return (-ENOMEM);
		}
		len = asprintf(&buf, "%s/%s", cpath, target);
		free(cpath);
		if (len < 0) {
			return (-ENOMEM);
		} else if (len >= MAXPATHLEN) {
			free(buf);
			return (-ENAMETOOLONG);
		}
		(void) strlcpy(target, buf, sizeof (target));
		free(buf);
	}

	/* Make sure we support the requested mount flags. */
	if ((flags & ~LX_MS_SUPPORTED) != 0) {
		lx_unsupported("unsupported mount flags: 0x%x", flags);
		return (-ENOTSUP);
	}

	/*
	 * Copy in Linux mount options. Note that for older Linux kernels
	 * (pre 2.6.23) the mount options pointer (which normally points to a
	 * string) points to a structure which is populated by the user-level
	 * code after it has done the preliminary RPCs (similar to how our NFS
	 * mount cmd works). For newer kernels the options pointer is just a
	 * string of options. We're unlikely to actually emulate a kernel that
	 * uses the old style but support is kept and handled in
	 * i_make_nfs_args(). The new style handling is implemented in
	 * lx_nfs_mount(). The user-level mount caller is in charge of
	 * determining the format in which it passes the data parameter.
	 */
	if (datap == NULL)
		return (-EINVAL);
	if (uucopy((void *)datap, &vers, sizeof (int)) < 0)
		return (-errno);

	/*
	 * As described above, the data parameter might be a versioned lx_nmd
	 * structure or (most likely on a modern distribution) it is a string.
	 */
	if (vers < 1 || vers > 6) {
		/*
		 * Handle the modern style with options as a string, make the
		 * preliminary RPC calls and do the native mount all within
		 * lx_nfs_mount().
		 */
		if (uucopystr((void *)datap, options, sizeof (options)) < 0)
			return (-errno);
		return (lx_nfs_mount(source, target, fstype, flags, options));
	}

	/*
	 * This is an old style NFS mount call and we only support v4.
	 */
	if (vers != 4) {
		lx_unsupported("unsupported nfs mount request version: %d\n",
		    vers);
		return (-ENOTSUP);
	}

	if (uucopy((void *)datap, &lx_nmd, sizeof (lx_nmd)) < 0)
		return (-errno);

	/*
	 * For illumos NFS mounts, the kernel expects a special structure, but
	 * a pointer to this structure is passed in via an extra parameter
	 * (sdataptr below.)
	 */
	if ((rv = i_make_nfs_args(&lx_nmd, &nfs_args, &nfs_args_addr,
	    &nfs_args_knconf, &nfs_args_fh, &nfs_args_secdata, fstype, options,
	    sizeof (options))) != 0)
		return (rv);

	/*
	 * For the following old-style NFS mount we need to tell the mount
	 * system call to expect extra parameters.
	 */
	sflags |= MS_DATA;
	sdataptr = (char *)&nfs_args;
	sdatalen = sizeof (nfs_args);

	/* Linux seems to always allow overlay mounts */
	sflags |= MS_OVERLAY;

	/* Convert some Linux flags to illumos flags. */
	if (flags & LX_MS_RDONLY)
		sflags |= MS_RDONLY;
	if (flags & LX_MS_NOSUID)
		sflags |= MS_NOSUID;
	if (flags & LX_MS_REMOUNT)
		sflags |= MS_REMOUNT;

	/*
	 * Convert some Linux flags to illumos option strings.
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

	return ((res == 0) ? 0 : -errno);
}
