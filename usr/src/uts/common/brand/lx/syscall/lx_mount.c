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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/ctype.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/types.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_syscalls.h>
#include <sys/lx_autofs.h>

#define	tolower(x)	(((x) >= 'A' && (x) <= 'Z') ? (x) - 'A' + 'a' : (x))

/*
 * mount(2) is significantly different between Linux and illumos. One of the
 * main differences is between the set of flags.  Some flags on Linux can be
 * translated to an illumos equivalent, some are converted to a
 * filesystem-specific option, while others have no equivalent whatsoever.
 *
 * Another big difference is that mounting NFS is fully handled in the kernel on
 * Linux whereas on illumos a lot of preliminary work is done by the NFS mount
 * command before calling mount(2). As a simplification, we forward NFS
 * mount calls back out to the user-level library which does the same kind of
 * preliminary processing that is done by the native user-level NFS mount code.
 */
#define	LX_MS_MGC_VAL		0xC0ED0000
#define	LX_MS_RDONLY		0x00000001
#define	LX_MS_NOSUID		0x00000002
#define	LX_MS_NODEV		0x00000004
#define	LX_MS_NOEXEC		0x00000008
#define	LX_MS_SYNCHRONOUS	0x00000010
#define	LX_MS_REMOUNT		0x00000020
#define	LX_MS_MANDLOCK		0x00000040
#define	LX_MS_NOATIME		0x00000400
#define	LX_MS_NODIRATIME	0x00000800
#define	LX_MS_BIND		0x00001000
#define	LX_MS_MOVE		0x00002000
#define	LX_MS_REC		0x00004000
#define	LX_MS_SILENT		0x00008000
#define	LX_MS_POSIXACL		0x00010000
#define	LX_MS_UNBINDABLE	0x00020000
#define	LX_MS_PRIVATE		0x00040000
#define	LX_MS_SLAVE		0x00080000
#define	LX_MS_SHARED		0x00100000
#define	LX_MS_RELATIME		0x00200000
#define	LX_MS_KERNMOUNT		0x00400000
#define	LX_MS_I_VERSION		0x00800000
#define	LX_MS_STRICTATIME	0x01000000
#define	LX_MS_LAZYTIME		0x02000000

/* Linux kernel-internal flags - ignored if passed in */
#define	LX_MS_NOSEC		0x10000000
#define	LX_MS_BORN		0x20000000
#define	LX_MS_ACTIVE		0x40000000
#define	LX_MS_NOUSER		0x80000000

#define	LX_MS_SUPPORTED		(LX_MS_MGC_VAL | \
				LX_MS_RDONLY | LX_MS_NOSUID | \
				LX_MS_NODEV | LX_MS_NOEXEC | \
				LX_MS_REMOUNT | LX_MS_NOATIME | \
				LX_MS_BIND | LX_MS_SILENT | \
				LX_MS_STRICTATIME | LX_MS_NOSEC | \
				LX_MS_BORN | LX_MS_ACTIVE | LX_MS_NOUSER)

/*
 * support definitions
 */
typedef enum mount_opt_type {
	MOUNT_OPT_INVALID	= 0,
	MOUNT_OPT_NORMAL	= 1,	/* option value: none */
	MOUNT_OPT_UINT		= 2,	/* option value: unsigned int */
	MOUNT_OPT_PASSTHRU	= 3	/* option value: validated downstream */
} mount_opt_type_t;

typedef struct mount_opt {
	char			*mo_name;
	mount_opt_type_t	mo_type;
} mount_opt_t;

/* From uts/common/syscall/umount.c */
extern int umount2(char *, int);

/* From lx_chown.c */
extern long lx_vn_chown(vnode_t *, uid_t, gid_t);

/*
 * Globals
 */
static mount_opt_t lofs_options[] = {
	{ NULL,			MOUNT_OPT_INVALID }
};

static mount_opt_t lx_proc_options[] = {
	{ NULL,			MOUNT_OPT_INVALID }
};

static mount_opt_t lx_sysfs_options[] = {
	{ NULL,			MOUNT_OPT_INVALID }
};

static mount_opt_t lx_tmpfs_options[] = {
	{ "size",		MOUNT_OPT_PASSTHRU },
	{ "mode",		MOUNT_OPT_UINT },
	{ "uid",		MOUNT_OPT_UINT },
	{ "gid",		MOUNT_OPT_UINT },
	{ NULL,			MOUNT_OPT_INVALID }
};

static mount_opt_t lx_autofs_options[] = {
	{ LX_MNTOPT_FD,		MOUNT_OPT_UINT },
	{ LX_MNTOPT_PGRP,	MOUNT_OPT_UINT },
	{ LX_MNTOPT_MINPROTO,	MOUNT_OPT_UINT },
	{ LX_MNTOPT_MAXPROTO,	MOUNT_OPT_UINT },
	{ LX_MNTOPT_INDIRECT,	MOUNT_OPT_NORMAL },
	{ LX_MNTOPT_DIRECT,	MOUNT_OPT_NORMAL },
	{ LX_MNTOPT_OFFSET,	MOUNT_OPT_NORMAL },
	{ NULL,			MOUNT_OPT_INVALID }
};


/*
 * Check the mount options.
 *
 * On illumos all mount option verification is done by the user-level mount
 * command. Invalid options are simply ignored by domount(). Thus, we check
 * here for invalid/unsupported options.
 */
static int
lx_mnt_opt_verify(char *opts, mount_opt_t *mop)
{
	int	opts_len = strlen(opts);
	char	*opt, *tp;
	int	opt_len, i;
	boolean_t last = B_FALSE;

	ASSERT((opts != NULL) && (mop != NULL));

	/* If no options were specified, nothing to do. */
	if (opts_len == 0)
		return (0);

	/* If no options are allowed, fail. */
	if (mop[0].mo_name == NULL)
		return (ENOTSUP);

	/* Don't accept leading or trailing ','. */
	if ((opts[0] == ',') || (opts[opts_len] == ','))
		return (EINVAL);

	/* Don't accept sequential ','. */
	for (i = 1; i < opts_len; i++) {
		if ((opts[i - 1] ==  ',') && (opts[i] ==  ','))
			return (EINVAL);
	}

	/*
	 * Verify each prop one at a time. There is no strtok in the kernel but
	 * it's easy to tokenize the entry ourselves.
	 */
	opt = opts;
	for (tp = opt; *tp != ',' && *tp != '\0'; tp++)
		;
	if (*tp == ',') {
		*tp = '\0';
	} else {
		last = B_TRUE;
	}
	for (;;) {
		opt_len = strlen(opt);

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
				goto bad;
			}

			if (mop[i].mo_type == MOUNT_OPT_UINT) {
				int j;
				/* Verify that value is an unsigned int. */
				for (j = 0; j < ovalue_len; j++) {
					if (!ISDIGIT(ovalue[j])) {
						goto bad;
					}
				}
			} else if (mop[i].mo_type == MOUNT_OPT_PASSTHRU) {
				/* Filesystem will do its own validation. */
				break;
			} else {
				/* Unknown option type specified. */
				goto bad;
			}

			/* The option is ok. */
			break;
		}

		/* If there were no matches this is an unsupported option. */
		if (mop[i].mo_name == NULL) {
			goto bad;
		}

		/*
		 * This option is ok, either we're done or move on to the next
		 * option.
		 */
		if (last)
			break;

		*tp = ',';
		opt = tp + 1;
		for (tp = opt; *tp != ',' && *tp != '\0'; tp++)
			;
		if (*tp == ',') {
			*tp = '\0';
		} else {
			last = B_TRUE;
		}
	};

	/* We verified all the options. */
	return (0);

bad:
	if (!last) {
		*tp = ',';
	}
	return (EINVAL);
}

/*
 * Remove an option from the string and save it in the provided buffer.
 * The option string should have already been verified as valid.
 * Return 0 if not present, -1 if error, and 1 if present and fine.
 */
static int
lx_mnt_opt_rm(char *opts, char *rmopt, char *retstr, int retlen)
{
	int	opts_len = strlen(opts);
	char	*optstart, *optend;
	int	optlen;

	ASSERT((opts != NULL) && (rmopt != NULL));

	retstr[0] = '\0';

	/* If no options were specified, there's no problem. */
	if (opts_len == 0)
		return (0);

	if ((optstart = strstr(opts, rmopt)) == NULL)
		return (0);

	for (optend = optstart; *optend != ',' && *optend != '\0'; optend++)
		;

	/*LINTED*/
	optlen = optend - optstart;
	if (optlen >= retlen)
		return (-1);
	(void) strncpy(retstr, optstart, optlen);
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
lx_mnt_opt_val(char *opt, int *valp)
{
	char *op, *ep;
	long lval;

	if ((op = strchr(opt, '=')) == NULL)
		return (-1);

	op++;
	if (!ISDIGIT(*op))
		return (-1);

	if (ddi_strtoul(op, &ep, 10, (ulong_t *)&lval) != 0 || lval > INT_MAX) {
		return (-1);
	}

	if (*ep != '\0')
		return (-1);

	*valp = (int)lval;
	return (0);
}

static int
lx_mnt_add_opt(char *option, char *buf, size_t buf_size)
{
	char *fmt_str = NULL;
	size_t len;

	ASSERT((option != NULL) && (strlen(option) > 0));
	ASSERT((buf != NULL) && (buf_size > 0));

	if (buf[0] == '\0') {
		fmt_str = "%s";
	} else {
		fmt_str = ",%s";
	}

	len = strlen(buf);
	VERIFY(len <= buf_size);
	buf_size -= len;
	buf += len;

	if (snprintf(buf, buf_size, fmt_str, option) > (buf_size - 1))
		return (EOVERFLOW);
	return (0);
}

static int
lx_mnt_copyin_arg(const char *from, char *to, size_t len)
{
	size_t	slen;
	int	rv;

	rv = copyinstr(from, to, len, &slen);
	if (rv == ENAMETOOLONG || slen == len)
		return (ENAMETOOLONG);
	if (rv != 0)
		return (EFAULT);

	return (0);
}

long
lx_mount(const char *sourcep, const char *targetp, const char *fstypep,
    uint_t flags, const void *datap)
{
	char			fstype[16];
	char			source[MAXPATHLEN];
	char			target[MAXPATHLEN];
	char			options[MAX_MNTOPT_STR];
	int			sflags, rv;
	struct mounta		ma, *map = &ma;
	vfs_t			*vfsp;
	vnode_t			*vp = NULL;
	int			uid = -1;
	int			gid = -1;

	if ((rv = lx_mnt_copyin_arg(fstypep, fstype, sizeof (fstype))) != 0) {
		if (rv == ENAMETOOLONG)
			return (set_errno(ENODEV));
		return (set_errno(rv));
	}

	/*
	 * Vector back out to userland emulation for NFS.
	 */
	if (strcmp(fstype, "nfs") == 0) {
		uintptr_t uargs[5] = {(uintptr_t)sourcep, (uintptr_t)targetp,
		    (uintptr_t)fstypep, (uintptr_t)flags, (uintptr_t)datap};

		/* The userspace emulation will do the lx_syscall_return() */
		ttolxlwp(curthread)->br_eosys = JUSTRETURN;

#if defined(_LP64)
		if (get_udatamodel() != DATAMODEL_NATIVE) {
			lx_emulate_user32(ttolwp(curthread), LX_SYS32_mount,
			    uargs);
		} else
#endif
		{
			lx_emulate_user(ttolwp(curthread), LX_SYS_mount, uargs);
		}
		return (0);
	}

	sflags = MS_SYSSPACE | MS_OPTIONSTR;
	options[0] = '\0';

	/* Copy in parameters that are always present. */
	if ((rv = lx_mnt_copyin_arg(sourcep, source, sizeof (source))) != 0)
		return (set_errno(rv));

	if ((rv = lx_mnt_copyin_arg(targetp, target, sizeof (target))) != 0)
		return (set_errno(rv));

	/*
	 * While SunOS is picky about mount(2) target paths being absolute,
	 * Linux is not so strict. In order to facilitate this looser
	 * requirement we must lookup the full path.
	 */
	if (target[0] != '/') {
		vnode_t *vp;

		if ((rv = lookupnameatcred(target, UIO_SYSSPACE, FOLLOW,
		    NULLVPP, &vp, NULL, CRED())) != 0)
			return (set_errno(rv));

		rv = vnodetopath(NULL, vp, target, MAXPATHLEN, CRED());
		VN_RELE(vp);
		if (rv != 0)
			return (set_errno(rv));
	}

	/* Make sure we support the requested mount flags. */
	if ((flags & ~LX_MS_SUPPORTED) != 0)
		return (set_errno(ENOTSUP));

	/* Copy in Linux mount options. */
	if (datap != NULL &&
	    (rv = lx_mnt_copyin_arg(datap, options, sizeof (options))) != 0)
		return (set_errno(rv));

	/* Do filesystem specific mount work. */
	if (flags & LX_MS_BIND) {
		/* If MS_BIND is set, we turn this into a lofs mount.  */
		(void) strcpy(fstype, "lofs");

		/* Verify Linux mount options. */
		if ((rv = lx_mnt_opt_verify(options, lofs_options)) != 0)
			return (set_errno(rv));
	} else if (strcmp(fstype, "tmpfs") == 0) {
		char	idstr[64];

		/* Verify Linux mount options. */
		if ((rv = lx_mnt_opt_verify(options, lx_tmpfs_options)) != 0)
			return (set_errno(rv));

		/*
		 * Linux defaults to mode=1777 for tmpfs mounts.
		 */
		if (strstr(options, "mode=") == NULL) {
			if (options[0] != '\0')
				(void) strlcat(options, ",", sizeof (options));
			(void) strlcat(options, "mode=1777", sizeof (options));
		}

		switch (lx_mnt_opt_rm(options, "uid=", idstr, sizeof (idstr))) {
		case 0:
			uid = -1;
			break;
		case 1:
			if (lx_mnt_opt_val(idstr, &uid) < 0)
				return (set_errno(EINVAL));
			break;
		default:
			return (set_errno(E2BIG));
		}
		switch (lx_mnt_opt_rm(options, "gid=", idstr, sizeof (idstr))) {
		case 0:
			gid = -1;
			break;
		case 1:
			if (lx_mnt_opt_val(idstr, &gid) < 0)
				return (set_errno(EINVAL));
			break;
		default:
			return (set_errno(E2BIG));
		}

		/*
		 * Linux seems to always allow overlay mounts. We allow this
		 * everywhere except under /dev where it interferes with device
		 * emulation.
		 */
		if (strcmp(target, "/dev") != 0 &&
		    strncmp(target, "/dev/", 5) != 0)
			sflags |= MS_OVERLAY;
	} else if (strcmp(fstype, "proc") == 0) {
		/* Translate proc mount requests to lx_proc requests. */
		(void) strcpy(fstype, "lx_proc");

		/* Verify Linux mount options. */
		if ((rv = lx_mnt_opt_verify(options, lx_proc_options)) != 0)
			return (set_errno(rv));
	} else if (strcmp(fstype, "sysfs") == 0) {
		/* Translate sysfs mount requests to lx_sysfs requests. */
		(void) strcpy(fstype, "lx_sysfs");

		/* Verify Linux mount options. */
		if ((rv = lx_mnt_opt_verify(options, lx_sysfs_options)) != 0)
			return (set_errno(rv));
	} else if (strcmp(fstype, "cgroup") == 0) {
		/* Translate cgroup mount requests to lx_cgroup requests. */
		(void) strcpy(fstype, "lx_cgroup");

		/*
		 * Currently don't verify Linux mount options since we can
		 * have a subsystem string provided.
		 */
	} else if (strcmp(fstype, "autofs") == 0) {
		/* Translate autofs mount requests to lxautofs requests. */
		(void) strcpy(fstype, LX_AUTOFS_NAME);

		/* Verify Linux mount options. */
		if ((rv = lx_mnt_opt_verify(options, lx_autofs_options)) != 0)
			return (set_errno(rv));

		/* Linux seems to always allow overlay mounts */
		sflags |= MS_OVERLAY;
	} else {
		return (set_errno(ENODEV));
	}

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
	    (rv = lx_mnt_add_opt("nodev", options, sizeof (options))) != 0)
		return (set_errno(rv));
	if ((flags & LX_MS_NOEXEC) &&
	    (rv = lx_mnt_add_opt("noexec", options, sizeof (options))) != 0)
		return (set_errno(rv));
	if ((flags & LX_MS_NOATIME) &&
	    (rv = lx_mnt_add_opt("noatime", options, sizeof (options))) != 0)
		return (set_errno(rv));

	if ((rv = lookupname(target, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp)) != 0)
		return (set_errno(rv));

	/* If mounting proc over itself, just return ok */
	if (strcmp(fstype, "lx_proc") == 0 && strcmp("lx_proc",
	    vfssw[vp->v_vfsp->vfs_fstype].vsw_name) == 0) {
		VN_RELE(vp);
		return (0);
	}

	map->spec = source;
	map->dir = target;
	map->flags = sflags;
	map->fstype = fstype;
	map->dataptr = NULL;
	map->datalen = 0;
	map->optptr = options;
	map->optlen = sizeof (options);

	rv = domount(NULL, map, vp, CRED(), &vfsp);
	VN_RELE(vp);
	if (rv != 0)
		return (set_errno(rv));

	VFS_RELE(vfsp);
	if (strcmp(fstype, "tmpfs") == 0 && (uid != -1 || gid != -1)) {
		/* Handle tmpfs uid/gid mount options. */
		if (lookupname(target, UIO_SYSSPACE, FOLLOW, NULLVPP,
		    &vp) == 0) {
			(void) lx_vn_chown(vp, (uid_t)uid, (gid_t)gid);
			VN_RELE(vp);
		}
	}

	return (0);
}

/*
 * umount() is identical to illumos, though implemented on top of umount2().
 */
long
lx_umount(char *path)
{
	return (umount2(path, 0));
}

/*
 * The Linux umount2() system call is identical to illumos but has a different
 * value for MNT_FORCE (the logical equivalent to MS_FORCE).
 */
#define	LX_MNT_FORCE	0x1

long
lx_umount2(char *path, int flg)
{
	int flags = 0;

	if (flg & ~LX_MNT_FORCE)
		return (set_errno(EINVAL));

	if (flg & LX_MNT_FORCE)
		flags |= MS_FORCE;

	return (umount2(path, flags));
}
