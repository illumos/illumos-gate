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
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/filio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inttypes.h>
#include <sys/vnode.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>

#include <sys/lx_types.h>
#include <sys/lx_misc.h>

#define	LX_NAMEMAX	256

#define	LX_GETDENTS_MAX_BUFSZ	65536

/*
 * Because the Linux dirent has an extra field (d_type), it's possible that
 * each entry will be 8 bytes larger (and aligned to 8 bytes) due to padding.
 * To prevent overrun during translation, the illumos-native buffer is sized
 * pessimistically.
 */
#define	LTOS_GETDENTS_BUFSZ(bufsz, datasz)	\
	(((bufsz) / (((datasz) + 15) & ~7)) * sizeof (struct dirent))

/*
 * Record must be long enough to house d_name string, null terminator and
 * d_type field.  It's then padded to nearest 8-byte boundary
 */
#define	LX_RECLEN(l, t)	\
	((offsetof(t, d_name) + 2 + (l) + 7) & ~7)

/*
 * Bytes after d_name string until d_reclen should be zeroed.
 * Includes zero-terminating d_name
 */
#define	LX_ZEROLEN(l, t)	\
	(LX_RECLEN(l, t) -	\
	((offsetof(t, d_name) + (l))))

/* The output format of getdents differs if the caller is 32 or 64 bit. */
struct lx_dirent_32 {
	uint32_t	d_ino;
	int32_t		d_off;
	ushort_t	d_reclen;
	char		d_name[1];
	uchar_t		d_type;
};

struct lx_dirent_64 {
	uint64_t	d_ino;
	int64_t		d_off;
	ushort_t	d_reclen;
	char		d_name[1];
	uchar_t		d_type;
};

static long
lx_getdents_common(int fd, caddr_t uptr, size_t count,
    unsigned int lx_size, int (*outcb)(caddr_t, caddr_t, int))
{
	vnode_t *vp;
	file_t *fp;
	struct uio auio;
	struct iovec aiov;
	int error;
	int sbufsz, lbufsz, bufsz;
	void *lbuf, *sbuf;
	size_t outb = 0;

	if (count < lx_size) {
		return (set_errno(EINVAL));
	}
	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}
	vp = fp->f_vnode;
	if (vp->v_type != VDIR) {
		releasef(fd);
		return (set_errno(ENOTDIR));
	}
	if (!(fp->f_flag & FREAD)) {
		releasef(fd);
		return (set_errno(EBADF));
	}

	if (count > LX_GETDENTS_MAX_BUFSZ) {
		/*
		 * If the target buffer passed to us is huge, keep the
		 * translation buffers moderate in size.  Iteration will be
		 * used to fill the request.
		 */
		lbufsz = LX_GETDENTS_MAX_BUFSZ;
		sbufsz = LTOS_GETDENTS_BUFSZ(LX_GETDENTS_MAX_BUFSZ, lx_size);
	} else if (count < (lx_size + MAXPATHLEN)) {
		/*
		 * If the target buffer is tiny, allocate a Linux-format buffer
		 * big enough to hold at least one max-length row while keeping
		 * the illumos-format buffer pesimistic in size.
		 *
		 * Assuming the buffer is truely tiny, it's likely that the
		 * result will not fit and an EINVAL will be tossed.
		 */
		lbufsz = (lx_size + MAXPATHLEN);
		sbufsz = MAX((LTOS_GETDENTS_BUFSZ(count, lx_size)),
		    sizeof (struct dirent));
	} else {
		lbufsz = count;
		sbufsz = LTOS_GETDENTS_BUFSZ(count, lx_size);
	}
	bufsz = sbufsz;
	lbuf = kmem_alloc(lbufsz, KM_SLEEP);
	sbuf = kmem_alloc(sbufsz, KM_SLEEP);

	aiov.iov_base = sbuf;
	aiov.iov_len = sbufsz;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = fp->f_offset;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_resid = sbufsz;
	auio.uio_fmode = 0;
	auio.uio_extflg = UIO_COPY_CACHED;

	/*
	 * Since we use a conservative buffer allocation for the differing
	 * struct sizing and Linux places fewer limits on getdents buffers in
	 * general, there's a chance we'll undershoot on the record count.
	 * When this happens, we can simply repeat the READDIR operation until
	 * the available records are exhausted or we've filled the user buffer.
	 */
	while (1) {
		int at_eof, res;
		(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);
		error = VOP_READDIR(vp, &auio, fp->f_cred, &at_eof, NULL, 0);
		VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
		if (error != 0 || auio.uio_resid == sbufsz) {
			break;
		}
		res = outcb(sbuf, lbuf, bufsz - auio.uio_resid);
		VERIFY(res <= lbufsz);
		if (res == 0) {
			/* no records to copyout from this batch */
			break;
		} else if (res > count) {
			/*
			 * For very small buffer sizes, it's possible that a
			 * single record is too large due to a long filename.
			 */
			error = EINVAL;
			break;
		}

		VERIFY(outb + res <= count);
		if (copyout(lbuf, (void *)(uptr + outb), res) != 0) {
			error = EFAULT;
			break;
		}
		outb += res;

		if (at_eof != 0 || (count - outb) < (lx_size + MAXPATHLEN)) {
			/*
			 * If there are no records left or the remaining buffer
			 * space is not large enough to hold a max-length
			 * filename, do not continue iteration.
			 */
			break;
		}

		/*
		 * We undershot the request buffer.
		 * Reset for another READDIR, taking care not to overshoot.
		 */
		bufsz = MIN(sbufsz, LTOS_GETDENTS_BUFSZ(count - outb, lx_size));
		auio.uio_resid = bufsz;
		aiov.iov_len = bufsz;
		aiov.iov_base = sbuf;
	}

	kmem_free(lbuf, lbufsz);
	kmem_free(sbuf, sbufsz);

	if (error) {
		releasef(fd);
		return (set_errno(error));
	}

	fp->f_offset = auio.uio_loffset;
	releasef(fd);
	return (outb);
}


static int
lx_getdents_format32(caddr_t sbuf, caddr_t lbuf, int len)
{
	struct dirent *sd;
	struct lx_dirent_32 *ld;
	int namelen;
	int size = 0;

	while (len > 0) {
		sd = (struct dirent *)sbuf;
		ld = (struct lx_dirent_32 *)lbuf;
		namelen = MIN(strlen(sd->d_name), LX_NAMEMAX - 1);

		ld->d_ino = sd->d_ino;
		ld->d_off = sd->d_off;
		(void) strncpy(ld->d_name, sd->d_name, namelen);
		ld->d_name[namelen] = 0;
		ld->d_reclen = (ushort_t)LX_RECLEN(namelen,
		    struct lx_dirent_32);
		/* Zero out any alignment padding and d_type */
		bzero(ld->d_name + namelen,
		    LX_ZEROLEN(namelen, struct lx_dirent_32));

		len -= sd->d_reclen;
		size += ld->d_reclen;
		sbuf += sd->d_reclen;
		lbuf += ld->d_reclen;
	}
	return (size);
}

static int
lx_getdents_format64(caddr_t sbuf, caddr_t lbuf, int len)
{
	struct dirent *sd;
	struct lx_dirent_64 *ld;
	int namelen;
	int size = 0;

	while (len > 0) {
		sd = (struct dirent *)sbuf;
		ld = (struct lx_dirent_64 *)lbuf;
		namelen = MIN(strlen(sd->d_name), LX_NAMEMAX - 1);

		ld->d_ino = sd->d_ino;
		ld->d_off = sd->d_off;
		(void) strncpy(ld->d_name, sd->d_name, namelen);
		ld->d_name[namelen] = 0;
		ld->d_reclen = (ushort_t)LX_RECLEN(namelen,
		    struct lx_dirent_64);
		/* Zero out any alignment padding and d_type */
		bzero(ld->d_name + namelen,
		    LX_ZEROLEN(namelen, struct lx_dirent_64));

		len -= sd->d_reclen;
		size += ld->d_reclen;
		sbuf += sd->d_reclen;
		lbuf += ld->d_reclen;
	}
	return (size);
}

long
lx_getdents_32(int fd, caddr_t buf, size_t count)
{
	return (lx_getdents_common(fd, buf, count,
	    sizeof (struct lx_dirent_32), lx_getdents_format32));
}

long
lx_getdents_64(int fd, caddr_t buf, size_t count)
{
	return (lx_getdents_common(fd, buf, count,
	    sizeof (struct lx_dirent_64), lx_getdents_format64));
}

struct lx_dirent64 {
	uint64_t	d_ino;
	int64_t		d_off;
	ushort_t	d_reclen;
	uchar_t		d_type;
	char		d_name[1];
};

#define	LX_RECLEN64(namelen)	\
	((offsetof(struct lx_dirent64, d_name) + 1 + (namelen) + 7) & ~7)

#define	LX_ZEROLEN64(namelen)	\
	(LX_RECLEN64(namelen) -	\
	((offsetof(struct lx_dirent64, d_name) + (namelen))))

static int
lx_getdents64_format(caddr_t sbuf, caddr_t lbuf, int len)
{
	struct dirent *sd;
	struct lx_dirent64 *ld;
	int namelen;
	int size = 0;

	while (len > 0) {
		sd = (struct dirent *)sbuf;
		ld = (struct lx_dirent64 *)lbuf;
		namelen = MIN(strlen(sd->d_name), LX_NAMEMAX - 1);

		ld->d_ino = sd->d_ino;
		ld->d_off = sd->d_off;
		ld->d_type = 0;
		(void) strncpy(ld->d_name, sd->d_name, namelen);
		ld->d_name[namelen] = 0;
		ld->d_reclen = (ushort_t)LX_RECLEN64(namelen);
		/* Zero out any alignment padding */
		bzero(ld->d_name + namelen, LX_ZEROLEN64(namelen));

		len -= sd->d_reclen;
		size += ld->d_reclen;
		sbuf += sd->d_reclen;
		lbuf += ld->d_reclen;
	}
	return (size);
}


long
lx_getdents64(int fd, caddr_t buf, size_t count)
{
	return (lx_getdents_common(fd, buf, count,
	    sizeof (struct lx_dirent64), lx_getdents64_format));
}
