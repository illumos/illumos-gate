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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/model.h>
#include <sys/mode.h>
#include <sys/stat.h>
#include <sys/lx_brand.h>
#include <sys/lx_fcntl.h>
#include <sys/lx_types.h>
#include <sys/lx_impl.h>
#include <sys/brand.h>

/* From "uts/common/syscall/stat.c" */
extern int cstatat_getvp(int, char *, int, vnode_t **, cred_t **);

typedef struct lx_timespec32 {
	int32_t	ts_sec;
	int32_t	ts_nsec;
} lx_timespec32_t;

typedef struct lx_timespec64 {
	int64_t	ts_sec;
	int64_t	ts_nsec;
}lx_timespec64_t;

struct lx_stat32 {
	uint16_t	st_dev;
	uint16_t	st_pad1;
	uint32_t	st_ino;
	uint16_t	st_mode;
	uint16_t	st_nlink;
	uint16_t	st_uid;
	uint16_t	st_gid;
	uint16_t	st_rdev;
	uint16_t 	st_pad2;
	uint32_t	st_size;
	uint32_t	st_blksize;
	uint32_t	st_blocks;
	lx_timespec32_t	st_atime;
	lx_timespec32_t	st_mtime;
	lx_timespec32_t	st_ctime;
	uint32_t	st_pad3;
	uint32_t	st_pad4;
};

#pragma pack(4)
struct lx_stat64_32 {
	uint64_t	st_dev;
	uint32_t	st_pad1;
	uint32_t	st_small_ino;
	uint32_t	st_mode;
	uint32_t	st_nlink;
	uint32_t	st_uid;
	uint32_t	st_gid;
	uint64_t	st_rdev;
	uint32_t	st_pad2;
	uint64_t	st_size;
	uint32_t	st_blksize;
	uint64_t	st_blocks;
	lx_timespec32_t	st_atime;
	lx_timespec32_t	st_mtime;
	lx_timespec32_t	st_ctime;
	uint64_t	st_ino;
};
#pragma pack()

#if defined(_LP64)
struct lx_stat64_64 {
	uint64_t	st_dev;
	uint64_t	st_ino;
	uint64_t	st_nlink;	/* yes, the order really is */
	uint32_t	st_mode;	/* different for these two */
	uint32_t	st_uid;
	uint32_t	st_gid;
	uint32_t	st_pad0;
	uint64_t	st_rdev;
	int64_t		st_size;
	int64_t		st_blksize;
	int64_t		st_blocks;
	lx_timespec64_t	st_atime;
	lx_timespec64_t	st_mtime;
	lx_timespec64_t	st_ctime;
	int64_t		st_unused[3];
};
#endif /* defined(_LP64) */

typedef enum lx_stat_fmt {
	LXF_STAT32,
	LXF_STAT64_32,
	LXF_STAT64_64
} lx_stat_fmt_t;


static long
lx_stat_common(vnode_t *vp, cred_t *cr, void *outp, lx_stat_fmt_t fmt)
{
	vattr_t vattr;
	mode_t mode;
	int error;

	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;
	if ((error = VOP_GETATTR(vp, &vattr, 0, cr, NULL)) != 0) {
		return (error);
	}

	mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	if ((mode & S_IFMT) == S_IFBLK) {
		/* Linux seems to report a 0 st_size for all block devices */
		vattr.va_size = 0;
	}
	if (vattr.va_rdev == NODEV) {
		/* Linux leaves st_rdev zeroed when it is absent */
		vattr.va_rdev = 0;
	}

	if (fmt == LXF_STAT32) {
		struct lx_stat32 sb;

		if (vattr.va_fsid > USHRT_MAX || vattr.va_rdev > USHRT_MAX ||
		    vattr.va_nlink > USHRT_MAX || vattr.va_size > INT_MAX) {
			return (EOVERFLOW);
		}

		bzero(&sb, sizeof (sb));
		sb.st_dev = vattr.va_fsid;
		sb.st_ino = vattr.va_nodeid;
		sb.st_mode = mode;
		sb.st_nlink = vattr.va_nlink;
		sb.st_uid = LX_UID32_TO_UID16(vattr.va_uid);
		sb.st_gid = LX_GID32_TO_GID16(vattr.va_gid);
		sb.st_rdev = vattr.va_rdev;
		sb.st_size = vattr.va_size;
		sb.st_blksize = vattr.va_blksize;
		sb.st_blocks = vattr.va_nblocks;
		sb.st_atime.ts_sec = vattr.va_atime.tv_sec;
		sb.st_atime.ts_nsec = vattr.va_atime.tv_nsec;
		sb.st_mtime.ts_sec = vattr.va_mtime.tv_sec;
		sb.st_mtime.ts_nsec = vattr.va_mtime.tv_nsec;
		sb.st_ctime.ts_sec = vattr.va_ctime.tv_sec;
		sb.st_ctime.ts_nsec = vattr.va_ctime.tv_nsec;
		if (copyout(&sb, outp, sizeof (sb)) != 0) {
			return (EFAULT);
		}
		return (0);
	} else if (fmt == LXF_STAT64_32) {
		struct lx_stat64_32 sb;

		bzero(&sb, sizeof (sb));
		sb.st_dev = vattr.va_fsid;
		sb.st_ino = vattr.va_nodeid;
		sb.st_small_ino = (vattr.va_nodeid & UINT_MAX);
		sb.st_mode = mode;
		sb.st_nlink = vattr.va_nlink;
		sb.st_uid = vattr.va_uid;
		sb.st_gid = vattr.va_gid;
		sb.st_rdev = vattr.va_rdev;
		sb.st_size = vattr.va_size;
		sb.st_blksize = vattr.va_blksize;
		sb.st_blocks = vattr.va_nblocks;
		sb.st_atime.ts_sec = vattr.va_atime.tv_sec;
		sb.st_atime.ts_nsec = vattr.va_atime.tv_nsec;
		sb.st_mtime.ts_sec = vattr.va_mtime.tv_sec;
		sb.st_mtime.ts_nsec = vattr.va_mtime.tv_nsec;
		sb.st_ctime.ts_sec = vattr.va_ctime.tv_sec;
		sb.st_ctime.ts_nsec = vattr.va_ctime.tv_nsec;
		if (copyout(&sb, outp, sizeof (sb)) != 0) {
			return (EFAULT);
		}
		return (0);
	} else if (fmt == LXF_STAT64_64) {
#if defined(_LP64)
		struct lx_stat64_64 sb;

		bzero(&sb, sizeof (sb));
		sb.st_dev = vattr.va_fsid;
		sb.st_ino = vattr.va_nodeid;
		sb.st_mode = mode;
		sb.st_nlink = vattr.va_nlink;
		sb.st_uid = vattr.va_uid;
		sb.st_gid = vattr.va_gid;
		sb.st_rdev = vattr.va_rdev;
		sb.st_size = vattr.va_size;
		sb.st_blksize = vattr.va_blksize;
		sb.st_blocks = vattr.va_nblocks;
		sb.st_atime.ts_sec = vattr.va_atime.tv_sec;
		sb.st_atime.ts_nsec = vattr.va_atime.tv_nsec;
		sb.st_mtime.ts_sec = vattr.va_mtime.tv_sec;
		sb.st_mtime.ts_nsec = vattr.va_mtime.tv_nsec;
		sb.st_ctime.ts_sec = vattr.va_ctime.tv_sec;
		sb.st_ctime.ts_nsec = vattr.va_ctime.tv_nsec;
		if (copyout(&sb, outp, sizeof (sb)) != 0) {
			return (EFAULT);
		}
		return (0);
#else
		/* Invalid output format on 32-bit */
		VERIFY(0);
#endif
	}

	/* Invalid output format */
	VERIFY(0);
	return (0);
}

long
lx_stat32(char *name, void *outp)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	int error;

	if ((error = cstatat_getvp(AT_FDCWD, name, FOLLOW, &vp, &cr)) != 0) {
		return (set_errno(error));
	}
	error = lx_stat_common(vp, cr, outp, LXF_STAT32);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_fstat32(int fd, void *outp)
{
	file_t *fp;
	int error;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}
	error = lx_stat_common(fp->f_vnode, fp->f_cred, outp, LXF_STAT32);
	releasef(fd);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_lstat32(char *name, void *outp)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	int error;

	if ((error = cstatat_getvp(AT_FDCWD, name, NO_FOLLOW, &vp, &cr)) != 0) {
		return (set_errno(error));
	}
	error = lx_stat_common(vp, cr, outp, LXF_STAT32);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_stat64(char *name, void *outp)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	model_t model = get_udatamodel();
	int error;

	if ((error = cstatat_getvp(AT_FDCWD, name, FOLLOW, &vp, &cr)) != 0) {
		return (set_errno(error));
	}
	error = lx_stat_common(vp, cr, outp,
	    (model == DATAMODEL_LP64) ? LXF_STAT64_64 : LXF_STAT64_32);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_fstat64(int fd, void *outp)
{
	file_t *fp;
	model_t model = get_udatamodel();
	int error;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}
	error = lx_stat_common(fp->f_vnode, fp->f_cred, outp,
	    (model == DATAMODEL_LP64) ? LXF_STAT64_64 : LXF_STAT64_32);
	releasef(fd);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

#define	LX_FSTATAT_ALLOWED	(LX_AT_SYMLINK_NOFOLLOW | LX_AT_EMPTY_PATH | \
    LX_AT_NO_AUTOMOUNT)

long
lx_fstatat64(int fd, char *name, void *outp, int flag)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	model_t model = get_udatamodel();
	enum symfollow follow = FOLLOW;
	int error;
	char c;

	if (fd == LX_AT_FDCWD) {
		fd = AT_FDCWD;
	}
	if ((flag & ~LX_FSTATAT_ALLOWED) != 0) {
		return (set_errno(EINVAL));
	}
	if ((flag & LX_AT_NO_AUTOMOUNT) != 0) {
		/*
		 * While AT_NO_AUTOMOUNT is a legal flag for fstatat64, it is
		 * not yet supported by lx_autofs.
		 */
		lx_unsupported("fstatat(AT_NO_AUTOMOUNT)");
		return (set_errno(EINVAL));
	}
	if ((flag & LX_AT_SYMLINK_NOFOLLOW) != 0) {
		follow = NO_FOLLOW;
	}

	if (copyin(name, &c, sizeof (c)) != 0) {
		return (set_errno(EFAULT));
	}
	if (c == '\0') {
		if ((flag & LX_AT_EMPTY_PATH) == 0) {
			return (set_errno(ENOENT));
		}

		/*
		 * When AT_EMPTY_PATH is set and and empty string has been
		 * passed for the name parameter, direct the lookup against the
		 * vnode for that fd.
		 */
		if (fd == AT_FDCWD) {
			vp = PTOU(curproc)->u_cdir;
			VN_HOLD(vp);
			cr = CRED();
			crhold(cr);
		} else {
			file_t *fp;

			if ((fp = getf(fd)) == NULL) {
				return (set_errno(EBADF));
			}
			vp = fp->f_vnode;
			VN_HOLD(vp);
			cr = fp->f_cred;
			crhold(cr);
			releasef(fd);
		}
	} else {
		if ((error = cstatat_getvp(fd, name, follow, &vp, &cr)) != 0) {
			return (set_errno(error));
		}
	}

	error = lx_stat_common(vp, cr, outp,
	    (model == DATAMODEL_LP64) ? LXF_STAT64_64 : LXF_STAT64_32);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}

long
lx_lstat64(char *name, void *outp)
{
	vnode_t *vp = NULL;
	cred_t *cr = NULL;
	model_t model = get_udatamodel();
	int error;

	if ((error = cstatat_getvp(AT_FDCWD, name, NO_FOLLOW, &vp, &cr)) != 0) {
		return (set_errno(error));
	}
	error = lx_stat_common(vp, cr, outp,
	    (model == DATAMODEL_LP64) ? LXF_STAT64_64 : LXF_STAT64_32);
	VN_RELE(vp);
	crfree(cr);
	if (error != 0) {
		return (set_errno(error));
	}
	return (0);
}
