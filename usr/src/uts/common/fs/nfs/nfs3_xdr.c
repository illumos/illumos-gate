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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/dirent.h>
#include <sys/vfs.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/debug.h>
#include <sys/t_lock.h>
#include <sys/cmn_err.h>
#include <sys/dnlc.h>
#include <sys/cred.h>
#include <sys/time.h>
#include <sys/sdt.h>

#include <rpc/types.h>
#include <rpc/xdr.h>

#include <nfs/nfs.h>
#include <nfs/rnode.h>
#include <rpc/rpc_rdma.h>

/*
 * These are the XDR routines used to serialize and deserialize
 * the various structures passed as parameters across the network
 * between NFS clients and servers.
 */

/*
 * XDR null terminated ASCII strings
 * xdr_string3 deals with "C strings" - arrays of bytes that are
 * terminated by a NULL character.  The parameter cpp references a
 * pointer to storage; If the pointer is null, then the necessary
 * storage is allocated.  The last parameter is the max allowed length
 * of the string as allowed by the system.  The NFS Version 3 protocol
 * does not place limits on strings, but the implementation needs to
 * place a reasonable limit to avoid problems.
 */
bool_t
xdr_string3(XDR *xdrs, char **cpp, uint_t maxsize)
{
	char *sp;
	uint_t size;
	uint_t nodesize;
	bool_t mem_alloced = FALSE;

	/*
	 * first deal with the length since xdr strings are counted-strings
	 */
	sp = *cpp;
	switch (xdrs->x_op) {
	case XDR_FREE:
		if (sp == NULL || sp == nfs3nametoolong)
			return (TRUE);	/* already free */
		/* FALLTHROUGH */

	case XDR_ENCODE:
		size = (uint_t)strlen(sp);
		break;

	case XDR_DECODE:
		break;
	}

	if (!xdr_u_int(xdrs, &size))
		return (FALSE);

	/*
	 * now deal with the actual bytes
	 */
	switch (xdrs->x_op) {
	case XDR_DECODE:
		if (size >= maxsize) {
			*cpp = nfs3nametoolong;
			if (!XDR_CONTROL(xdrs, XDR_SKIPBYTES, &size))
				return (FALSE);
			return (TRUE);
		}
		nodesize = size + 1;
		if (nodesize == 0)
			return (TRUE);
		if (sp == NULL) {
			sp = kmem_alloc(nodesize, KM_NOSLEEP);
			*cpp = sp;
			if (sp == NULL)
				return (FALSE);
			mem_alloced = TRUE;
		}
		sp[size] = 0;

		if (xdr_opaque(xdrs, sp, size)) {
			if (strlen(sp) != size) {
				if (mem_alloced)
					kmem_free(sp, nodesize);
				*cpp = NULL;
				return (FALSE);
			}
		} else {
			if (mem_alloced)
				kmem_free(sp, nodesize);
			*cpp = NULL;
			return (FALSE);
		}
		return (TRUE);

	case XDR_ENCODE:
		return (xdr_opaque(xdrs, sp, size));

	case XDR_FREE:
		nodesize = size + 1;
		kmem_free(sp, nodesize);
		*cpp = NULL;
		return (TRUE);
	}

	return (FALSE);
}

/*
 * XDR_INLINE decode a filehandle.
 */
bool_t
xdr_inline_decode_nfs_fh3(uint32_t *ptr, nfs_fh3 *fhp, uint32_t fhsize)
{
	uchar_t *bp = (uchar_t *)ptr;
	uchar_t *cp;
	uint32_t dsize;
	uintptr_t resid;

	/*
	 * Check to see if what the client sent us is bigger or smaller
	 * than what we can ever possibly send out. NFS_FHMAXDATA is
	 * unfortunately badly named as it is no longer the max and is
	 * really the min of what is sent over the wire.
	 */
	if (fhsize > sizeof (fhandle3_t) || fhsize < (sizeof (fsid_t) +
	    sizeof (ushort_t) + NFS_FHMAXDATA +
	    sizeof (ushort_t) + NFS_FHMAXDATA)) {
		return (FALSE);
	}

	/*
	 * All internal parts of a filehandle are in native byte order.
	 *
	 * Decode what should be fh3_fsid, it is aligned.
	 */
	fhp->fh3_fsid.val[0] = *(uint32_t *)bp;
	bp += BYTES_PER_XDR_UNIT;
	fhp->fh3_fsid.val[1] = *(uint32_t *)bp;
	bp += BYTES_PER_XDR_UNIT;

	/*
	 * Decode what should be fh3_len.  fh3_len is two bytes, so we're
	 * unaligned now.
	 */
	cp = (uchar_t *)&fhp->fh3_len;
	*cp++ = *bp++;
	*cp++ = *bp++;
	fhsize -= 2 * BYTES_PER_XDR_UNIT + sizeof (ushort_t);

	/*
	 * For backwards compatability, the fid length may be less than
	 * NFS_FHMAXDATA, but it was always encoded as NFS_FHMAXDATA bytes.
	 */
	dsize = fhp->fh3_len < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh3_len;

	/*
	 * Make sure the client isn't sending us a bogus length for fh3x_data.
	 */
	if (fhsize < dsize)
		return (FALSE);
	bcopy(bp, fhp->fh3_data, dsize);
	bp += dsize;
	fhsize -= dsize;

	if (fhsize < sizeof (ushort_t))
		return (FALSE);
	cp = (uchar_t *)&fhp->fh3_xlen;
	*cp++ = *bp++;
	*cp++ = *bp++;
	fhsize -= sizeof (ushort_t);

	dsize = fhp->fh3_xlen < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh3_xlen;

	/*
	 * Make sure the client isn't sending us a bogus length for fh3x_xdata.
	 */
	if (fhsize < dsize)
		return (FALSE);
	bcopy(bp, fhp->fh3_xdata, dsize);
	fhsize -= dsize;
	bp += dsize;

	/*
	 * We realign things on purpose, so skip any padding
	 */
	resid = (uintptr_t)bp % BYTES_PER_XDR_UNIT;
	if (resid != 0) {
		if (fhsize < (BYTES_PER_XDR_UNIT - resid))
			return (FALSE);
		bp += BYTES_PER_XDR_UNIT - resid;
		fhsize -= BYTES_PER_XDR_UNIT - resid;
	}

	/*
	 * Make sure client didn't send extra bytes
	 */
	if (fhsize != 0)
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_decode_nfs_fh3(XDR *xdrs, nfs_fh3 *objp)
{
	uint32_t fhsize;		/* filehandle size */
	uint32_t bufsize;
	rpc_inline_t *ptr;
	uchar_t *bp;

	ASSERT(xdrs->x_op == XDR_DECODE);

	/*
	 * Retrieve the filehandle length.
	 */
	if (!XDR_GETINT32(xdrs, (int32_t *)&fhsize))
		return (FALSE);

	bzero(objp->fh3_u.data, sizeof (objp->fh3_u.data));
	objp->fh3_length = 0;

	/*
	 * Check to see if what the client sent us is bigger or smaller
	 * than what we can ever possibly send out. NFS_FHMAXDATA is
	 * unfortunately badly named as it is no longer the max and is
	 * really the min of what is sent over the wire.
	 */
	if (fhsize > sizeof (fhandle3_t) || fhsize < (sizeof (fsid_t) +
	    sizeof (ushort_t) + NFS_FHMAXDATA +
	    sizeof (ushort_t) + NFS_FHMAXDATA)) {
		if (!XDR_CONTROL(xdrs, XDR_SKIPBYTES, &fhsize))
			return (FALSE);
		return (TRUE);
	}

	/*
	 * bring in fhsize plus any padding
	 */
	bufsize = RNDUP(fhsize);
	ptr = XDR_INLINE(xdrs, bufsize);
	bp = (uchar_t *)ptr;
	if (ptr == NULL) {
		bp = kmem_alloc(bufsize, KM_SLEEP);
		if (!xdr_opaque(xdrs, (char *)bp, bufsize)) {
			kmem_free(bp, bufsize);
			return (FALSE);
		}
	}

	objp->fh3_length = sizeof (fhandle3_t);

	if (xdr_inline_decode_nfs_fh3((uint32_t *)bp, objp, fhsize) == FALSE) {
		/*
		 * If in the process of decoding we find the file handle
		 * is not correctly formed, we need to continue decoding
		 * and trigger an NFS layer error. Set the nfs_fh3_len to
		 * zero so it gets caught as a bad length.
		 */
		bzero(objp->fh3_u.data, sizeof (objp->fh3_u.data));
		objp->fh3_length = 0;
	}

	if (ptr == NULL)
		kmem_free(bp, bufsize);
	return (TRUE);
}

/*
 * XDR_INLINE encode a filehandle.
 */
bool_t
xdr_inline_encode_nfs_fh3(uint32_t **ptrp, uint32_t *ptr_redzone,
	nfs_fh3 *fhp)
{
	uint32_t *ptr = *ptrp;
	uchar_t *cp;
	uint_t otw_len, fsize, xsize;   /* otw, file, and export sizes */
	uint32_t padword;

	fsize = fhp->fh3_len < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh3_len;
	xsize = fhp->fh3_xlen < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh3_xlen;

	/*
	 * First get the initial and variable sized part of the filehandle.
	 */
	otw_len = sizeof (fhp->fh3_fsid) +
	    sizeof (fhp->fh3_len) + fsize +
	    sizeof (fhp->fh3_xlen) + xsize;

	/*
	 * Round out to a full word.
	 */
	otw_len = RNDUP(otw_len);
	padword = (otw_len / BYTES_PER_XDR_UNIT);	/* includes fhlen */

	/*
	 * Make sure we don't exceed our buffer.
	 */
	if ((ptr + (otw_len / BYTES_PER_XDR_UNIT) + 1) > ptr_redzone)
		return (FALSE);

	/*
	 * Zero out the pading.
	 */
	ptr[padword] = 0;

	IXDR_PUT_U_INT32(ptr, otw_len);

	/*
	 * The rest of the filehandle is in native byteorder
	 */
	/* fh3_fsid */
	*ptr++ = (uint32_t)fhp->fh3_fsid.val[0];
	*ptr++ = (uint32_t)fhp->fh3_fsid.val[1];

	/*
	 * Since the next pieces are unaligned, we need to
	 * do bytewise copies.
	 */
	cp = (uchar_t *)ptr;

	/* fh3_len + fh3_data */
	bcopy(&fhp->fh3_len, cp, sizeof (fhp->fh3_len) + fsize);
	cp += sizeof (fhp->fh3_len) + fsize;

	/* fh3_xlen + fh3_xdata */
	bcopy(&fhp->fh3_xlen, cp, sizeof (fhp->fh3_xlen) + xsize);
	cp += sizeof (fhp->fh3_xlen) + xsize;

	/* do necessary rounding/padding */
	cp = (uchar_t *)RNDUP((uintptr_t)cp);
	ptr = (uint32_t *)cp;

	/*
	 * With the above padding, we're word aligned again.
	 */
	ASSERT(((uintptr_t)ptr % BYTES_PER_XDR_UNIT) == 0);

	*ptrp = ptr;

	return (TRUE);
}

static bool_t
xdr_encode_nfs_fh3(XDR *xdrs, nfs_fh3 *objp)
{
	uint_t otw_len, fsize, xsize;   /* otw, file, and export sizes */
	bool_t ret;
	rpc_inline_t *ptr;
	rpc_inline_t *buf = NULL;
	uint32_t *ptr_redzone;

	ASSERT(xdrs->x_op == XDR_ENCODE);

	fsize = objp->fh3_len < NFS_FHMAXDATA ? NFS_FHMAXDATA : objp->fh3_len;
	xsize = objp->fh3_xlen < NFS_FHMAXDATA ? NFS_FHMAXDATA : objp->fh3_xlen;

	/*
	 * First get the over the wire size, it is the 4 bytes
	 * for the length, plus the combined size of the
	 * file handle components.
	 */
	otw_len = BYTES_PER_XDR_UNIT + sizeof (objp->fh3_fsid) +
	    sizeof (objp->fh3_len) + fsize +
	    sizeof (objp->fh3_xlen) + xsize;
	/*
	 * Round out to a full word.
	 */
	otw_len = RNDUP(otw_len);

	/*
	 * Next try to inline the XDR stream, if that fails (rare)
	 * allocate a buffer to encode the file handle and then
	 * copy it using xdr_opaque and free the buffer.
	 */
	ptr = XDR_INLINE(xdrs, otw_len);
	if (ptr == NULL)
		ptr = buf = kmem_alloc(otw_len, KM_SLEEP);

	ptr_redzone = (uint32_t *)(ptr + (otw_len / BYTES_PER_XDR_UNIT));
	ret = xdr_inline_encode_nfs_fh3((uint32_t **)&ptr, ptr_redzone, objp);

	if (buf != NULL) {
		if (ret == TRUE)
			ret = xdr_opaque(xdrs, (char *)buf, otw_len);
		kmem_free(buf, otw_len);
	}
	return (ret);
}

/*
 * XDR a NFSv3 filehandle the naive way.
 */
bool_t
xdr_nfs_fh3(XDR *xdrs, nfs_fh3 *objp)
{
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (!xdr_u_int(xdrs, &objp->fh3_length))
		return (FALSE);

	if (objp->fh3_length > NFS3_FHSIZE)
		return (FALSE);

	return (xdr_opaque(xdrs, objp->fh3_u.data, objp->fh3_length));
}

/*
 * XDR a NFSv3 filehandle with intelligence on the server.
 * Encoding goes from our in-memory structure to wire format.
 * Decoding goes from wire format to our in-memory structure.
 */
bool_t
xdr_nfs_fh3_server(XDR *xdrs, nfs_fh3 *objp)
{
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		if (objp->fh3_flags & FH_WEBNFS)
			return (xdr_nfs_fh3(xdrs, objp));
		else
			return (xdr_encode_nfs_fh3(xdrs, objp));
	case XDR_DECODE:
		return (xdr_decode_nfs_fh3(xdrs, objp));
	case XDR_FREE:
		if (objp->fh3_u.data != NULL)
			bzero(objp->fh3_u.data, sizeof (objp->fh3_u.data));
		return (TRUE);
	}
	return (FALSE);
}

bool_t
xdr_diropargs3(XDR *xdrs, diropargs3 *objp)
{
	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, objp->dirp))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->dir))
			return (FALSE);
		break;
	}
	return (xdr_string3(xdrs, &objp->name, MAXNAMELEN));
}

static bool_t
xdr_fattr3(XDR *xdrs, fattr3 *na)
{
	int32_t *ptr;

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	ptr = XDR_INLINE(xdrs, NFS3_SIZEOF_FATTR3 * BYTES_PER_XDR_UNIT);
	if (ptr != NULL) {
		if (xdrs->x_op == XDR_DECODE) {
			na->type = IXDR_GET_ENUM(ptr, enum ftype3);
			na->mode = IXDR_GET_U_INT32(ptr);
			na->nlink = IXDR_GET_U_INT32(ptr);
			na->uid = IXDR_GET_U_INT32(ptr);
			na->gid = IXDR_GET_U_INT32(ptr);
			IXDR_GET_U_HYPER(ptr, na->size);
			IXDR_GET_U_HYPER(ptr, na->used);
			na->rdev.specdata1 = IXDR_GET_U_INT32(ptr);
			na->rdev.specdata2 = IXDR_GET_U_INT32(ptr);
			IXDR_GET_U_HYPER(ptr, na->fsid);
			IXDR_GET_U_HYPER(ptr, na->fileid);
			na->atime.seconds = IXDR_GET_U_INT32(ptr);
			na->atime.nseconds = IXDR_GET_U_INT32(ptr);
			na->mtime.seconds = IXDR_GET_U_INT32(ptr);
			na->mtime.nseconds = IXDR_GET_U_INT32(ptr);
			na->ctime.seconds = IXDR_GET_U_INT32(ptr);
			na->ctime.nseconds = IXDR_GET_U_INT32(ptr);
		} else {
			IXDR_PUT_ENUM(ptr, na->type);
			IXDR_PUT_U_INT32(ptr, na->mode);
			IXDR_PUT_U_INT32(ptr, na->nlink);
			IXDR_PUT_U_INT32(ptr, na->uid);
			IXDR_PUT_U_INT32(ptr, na->gid);
			IXDR_PUT_U_HYPER(ptr, na->size);
			IXDR_PUT_U_HYPER(ptr, na->used);
			IXDR_PUT_U_INT32(ptr, na->rdev.specdata1);
			IXDR_PUT_U_INT32(ptr, na->rdev.specdata2);
			IXDR_PUT_U_HYPER(ptr, na->fsid);
			IXDR_PUT_U_HYPER(ptr, na->fileid);
			IXDR_PUT_U_INT32(ptr, na->atime.seconds);
			IXDR_PUT_U_INT32(ptr, na->atime.nseconds);
			IXDR_PUT_U_INT32(ptr, na->mtime.seconds);
			IXDR_PUT_U_INT32(ptr, na->mtime.nseconds);
			IXDR_PUT_U_INT32(ptr, na->ctime.seconds);
			IXDR_PUT_U_INT32(ptr, na->ctime.nseconds);
		}
		return (TRUE);
	}
	if (!(xdr_enum(xdrs, (enum_t *)&na->type) &&
	    xdr_u_int(xdrs, &na->mode) &&
	    xdr_u_int(xdrs, &na->nlink) &&
	    xdr_u_int(xdrs, &na->uid) &&
	    xdr_u_int(xdrs, &na->gid) &&
	    xdr_u_longlong_t(xdrs, &na->size) &&
	    xdr_u_longlong_t(xdrs, &na->used) &&
	    xdr_u_int(xdrs, &na->rdev.specdata1) &&
	    xdr_u_int(xdrs, &na->rdev.specdata2) &&
	    xdr_u_longlong_t(xdrs, &na->fsid) &&
	    xdr_u_longlong_t(xdrs, &na->fileid) &&
	    xdr_u_int(xdrs, &na->atime.seconds) &&
	    xdr_u_int(xdrs, &na->atime.nseconds) &&
	    xdr_u_int(xdrs, &na->mtime.seconds) &&
	    xdr_u_int(xdrs, &na->mtime.nseconds) &&
	    xdr_u_int(xdrs, &na->ctime.seconds) &&
	    xdr_u_int(xdrs, &na->ctime.nseconds)))
			return (FALSE);
	return (TRUE);
}

/*
 * Fast decode of an fattr3 to a vattr
 * Only return FALSE on decode error, all other fattr to vattr translation
 * failures set status.
 *
 * Callers must catch the following errors:
 *	EFBIG - file size will not fit in va_size
 *	EOVERFLOW - time will not fit in va_*time
 */
static bool_t
xdr_fattr3_to_vattr(XDR *xdrs, fattr3_res *objp)
{
	int32_t *ptr;
	size3 used;
	specdata3 rdev;
	uint32_t ntime;
	vattr_t *vap = objp->vap;

	/*
	 * DECODE only
	 */
	ASSERT(xdrs->x_op == XDR_DECODE);

	/* On success, all attributes will be decoded */
	vap->va_mask = AT_ALL;

	objp->status = 0;
	ptr = XDR_INLINE(xdrs, NFS3_SIZEOF_FATTR3 * BYTES_PER_XDR_UNIT);
	if (ptr != NULL) {
		/*
		 * Common case
		 */
		vap->va_type = IXDR_GET_ENUM(ptr, enum vtype);
		if ((ftype3)vap->va_type < NF3REG ||
		    (ftype3)vap->va_type > NF3FIFO)
			vap->va_type = VBAD;
		else
			vap->va_type = nf3_to_vt[vap->va_type];
		vap->va_mode = IXDR_GET_U_INT32(ptr);
		vap->va_nlink = IXDR_GET_U_INT32(ptr);
		vap->va_uid = (uid_t)IXDR_GET_U_INT32(ptr);
		if (vap->va_uid == NFS_UID_NOBODY)
			vap->va_uid = UID_NOBODY;
		vap->va_gid = (gid_t)IXDR_GET_U_INT32(ptr);
		if (vap->va_gid == NFS_GID_NOBODY)
			vap->va_gid = GID_NOBODY;
		IXDR_GET_U_HYPER(ptr, vap->va_size);
		/*
		 * If invalid size, stop decode, set status, and
		 * return TRUE, x_handy will be correct, caller must ignore vap.
		 */
		if (!NFS3_SIZE_OK(vap->va_size)) {
			objp->status = EFBIG;
			return (TRUE);
		}
		IXDR_GET_U_HYPER(ptr, used);
		rdev.specdata1 = IXDR_GET_U_INT32(ptr);
		rdev.specdata2 = IXDR_GET_U_INT32(ptr);
		/* fsid is ignored */
		ptr += 2;
		IXDR_GET_U_HYPER(ptr, vap->va_nodeid);

		/*
		 * nfs protocol defines times as unsigned so don't
		 * extend sign, unless sysadmin set nfs_allow_preepoch_time.
		 * The inline macros do the equivilant of NFS_TIME_T_CONVERT
		 */
		if (nfs_allow_preepoch_time) {
			vap->va_atime.tv_sec = IXDR_GET_INT32(ptr);
			vap->va_atime.tv_nsec = IXDR_GET_U_INT32(ptr);
			vap->va_mtime.tv_sec = IXDR_GET_INT32(ptr);
			vap->va_mtime.tv_nsec = IXDR_GET_U_INT32(ptr);
			vap->va_ctime.tv_sec = IXDR_GET_INT32(ptr);
			vap->va_ctime.tv_nsec = IXDR_GET_U_INT32(ptr);
		} else {
			/*
			 * Check if the time would overflow on 32-bit
			 */
			ntime = IXDR_GET_U_INT32(ptr);
			/*CONSTCOND*/
			if (NFS3_TIME_OVERFLOW(ntime)) {
				objp->status = EOVERFLOW;
				return (TRUE);
			}
			vap->va_atime.tv_sec = ntime;
			vap->va_atime.tv_nsec = IXDR_GET_U_INT32(ptr);

			ntime = IXDR_GET_U_INT32(ptr);
			/*CONSTCOND*/
			if (NFS3_TIME_OVERFLOW(ntime)) {
				objp->status = EOVERFLOW;
				return (TRUE);
			}
			vap->va_mtime.tv_sec = ntime;
			vap->va_mtime.tv_nsec = IXDR_GET_U_INT32(ptr);

			ntime = IXDR_GET_U_INT32(ptr);
			/*CONSTCOND*/
			if (NFS3_TIME_OVERFLOW(ntime)) {
				objp->status = EOVERFLOW;
				return (TRUE);
			}
			vap->va_ctime.tv_sec = ntime;
			vap->va_ctime.tv_nsec = IXDR_GET_U_INT32(ptr);
		}

	} else {
		uint64 fsid;

		/*
		 * Slow path
		 */
		if (!(xdr_enum(xdrs, (enum_t *)&vap->va_type) &&
		    xdr_u_int(xdrs, &vap->va_mode) &&
		    xdr_u_int(xdrs, &vap->va_nlink) &&
		    xdr_u_int(xdrs, (uint_t *)&vap->va_uid) &&
		    xdr_u_int(xdrs, (uint_t *)&vap->va_gid) &&
		    xdr_u_longlong_t(xdrs, &vap->va_size) &&
		    xdr_u_longlong_t(xdrs, &used) &&
		    xdr_u_int(xdrs, &rdev.specdata1) &&
		    xdr_u_int(xdrs, &rdev.specdata2) &&
		    xdr_u_longlong_t(xdrs, &fsid) &&	/* ignored */
		    xdr_u_longlong_t(xdrs, &vap->va_nodeid)))
				return (FALSE);

		if (nfs_allow_preepoch_time) {
			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			vap->va_atime.tv_sec = (int32_t)ntime;
			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			vap->va_atime.tv_nsec = ntime;

			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			vap->va_mtime.tv_sec = (int32_t)ntime;
			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			vap->va_mtime.tv_nsec = ntime;

			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			vap->va_ctime.tv_sec = (int32_t)ntime;
			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			vap->va_ctime.tv_nsec = ntime;
		} else {
			/*
			 * Check if the time would overflow on 32-bit
			 * Set status and keep decoding stream.
			 */
			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			/*CONSTCOND*/
			if (NFS3_TIME_OVERFLOW(ntime)) {
				objp->status = EOVERFLOW;
			}
			vap->va_atime.tv_sec = ntime;
			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			vap->va_atime.tv_nsec = ntime;

			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			/*CONSTCOND*/
			if (NFS3_TIME_OVERFLOW(ntime)) {
				objp->status = EOVERFLOW;
			}
			vap->va_mtime.tv_sec = ntime;
			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			vap->va_mtime.tv_nsec = ntime;

			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			/*CONSTCOND*/
			if (NFS3_TIME_OVERFLOW(ntime)) {
				objp->status = EOVERFLOW;
			}
			vap->va_ctime.tv_sec = ntime;
			if (!xdr_u_int(xdrs, &ntime))
				return (FALSE);
			vap->va_ctime.tv_nsec = ntime;
		}

		/*
		 * Fixup as needed
		 */
		if ((ftype3)vap->va_type < NF3REG ||
		    (ftype3)vap->va_type > NF3FIFO)
			vap->va_type = VBAD;
		else
			vap->va_type = nf3_to_vt[vap->va_type];
		if (vap->va_uid == NFS_UID_NOBODY)
			vap->va_uid = UID_NOBODY;
		if (vap->va_gid == NFS_GID_NOBODY)
			vap->va_gid = GID_NOBODY;
		/*
		 * If invalid size, set status, and
		 * return TRUE, caller must ignore vap.
		 */
		if (!NFS3_SIZE_OK(vap->va_size)) {
			objp->status = EFBIG;
			return (TRUE);
		}
	}

	/*
	 * Fill in derived fields
	 */
	vap->va_fsid = objp->vp->v_vfsp->vfs_dev;
	vap->va_seq = 0;

	/*
	 * Common case values
	 */
	vap->va_rdev = 0;
	vap->va_blksize = MAXBSIZE;
	vap->va_nblocks = 0;

	switch (vap->va_type) {
	case VREG:
	case VDIR:
	case VLNK:
		vap->va_nblocks = (u_longlong_t)
		    ((used + (size3)DEV_BSIZE - (size3)1) /
		    (size3)DEV_BSIZE);
		break;
	case VBLK:
		vap->va_blksize = DEV_BSIZE;
		/* FALLTHRU */
	case VCHR:
		vap->va_rdev = makedevice(rdev.specdata1, rdev.specdata2);
		break;
	case VSOCK:
	case VFIFO:
	default:
		break;
	}

	return (TRUE);
}

static bool_t
xdr_post_op_vattr(XDR *xdrs, post_op_vattr *objp)
{
	/*
	 * DECODE only
	 */
	ASSERT(xdrs->x_op == XDR_DECODE);

	if (!xdr_bool(xdrs, &objp->attributes))
		return (FALSE);

	if (objp->attributes == FALSE)
		return (TRUE);

	if (objp->attributes != TRUE)
		return (FALSE);

	if (!xdr_fattr3_to_vattr(xdrs, &objp->fres))
		return (FALSE);

	/*
	 * The file size may cause an EFBIG or the time values
	 * may cause EOVERFLOW, if so simply drop the attributes.
	 */
	if (objp->fres.status != NFS3_OK)
		objp->attributes = FALSE;

	return (TRUE);
}

bool_t
xdr_post_op_attr(XDR *xdrs, post_op_attr *objp)
{
	if (!xdr_bool(xdrs, &objp->attributes))
		return (FALSE);

	if (objp->attributes == FALSE)
		return (TRUE);

	if (objp->attributes != TRUE)
		return (FALSE);

	if (!xdr_fattr3(xdrs, &objp->attr))
		return (FALSE);

	/*
	 * Check that we don't get a file we can't handle through
	 *	existing interfaces (especially stat64()).
	 * Decode only check since on encode the data has
	 * been dealt with in the above call to xdr_fattr3().
	 */
	if (xdrs->x_op == XDR_DECODE) {
		/* Set attrs to false if invalid size or time */
		if (!NFS3_SIZE_OK(objp->attr.size)) {
			objp->attributes = FALSE;
			return (TRUE);
		}
#ifndef _LP64
		if (!NFS3_FATTR_TIME_OK(&objp->attr))
			objp->attributes = FALSE;
#endif
	}
	return (TRUE);
}

static bool_t
xdr_wcc_data(XDR *xdrs, wcc_data *objp)
{
	int32_t *ptr;
	wcc_attr *attrp;

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (xdrs->x_op == XDR_DECODE) {
		/* pre_op_attr */
		if (!xdr_bool(xdrs, &objp->before.attributes))
			return (FALSE);

		switch (objp->before.attributes) {
		case TRUE:
			attrp = &objp->before.attr;
			ptr = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
			if (ptr != NULL) {
				IXDR_GET_U_HYPER(ptr, attrp->size);
				attrp->mtime.seconds = IXDR_GET_U_INT32(ptr);
				attrp->mtime.nseconds = IXDR_GET_U_INT32(ptr);
				attrp->ctime.seconds = IXDR_GET_U_INT32(ptr);
				attrp->ctime.nseconds = IXDR_GET_U_INT32(ptr);
			} else {
				if (!xdr_u_longlong_t(xdrs, &attrp->size))
					return (FALSE);
				if (!xdr_u_int(xdrs, &attrp->mtime.seconds))
					return (FALSE);
				if (!xdr_u_int(xdrs, &attrp->mtime.nseconds))
					return (FALSE);
				if (!xdr_u_int(xdrs, &attrp->ctime.seconds))
					return (FALSE);
				if (!xdr_u_int(xdrs, &attrp->ctime.nseconds))
					return (FALSE);
			}

#ifndef _LP64
			/*
			 * check time overflow.
			 */
			if (!NFS3_TIME_OK(attrp->mtime.seconds) ||
			    !NFS3_TIME_OK(attrp->ctime.seconds))
				objp->before.attributes = FALSE;
#endif
			break;
		case FALSE:
			break;
		default:
			return (FALSE);
		}
	}

	if (xdrs->x_op == XDR_ENCODE) {
		/* pre_op_attr */
		if (!xdr_bool(xdrs, &objp->before.attributes))
			return (FALSE);

		switch (objp->before.attributes) {
		case TRUE:
			attrp = &objp->before.attr;

			ptr = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
			if (ptr != NULL) {
				IXDR_PUT_U_HYPER(ptr, attrp->size);
				IXDR_PUT_U_INT32(ptr, attrp->mtime.seconds);
				IXDR_PUT_U_INT32(ptr, attrp->mtime.nseconds);
				IXDR_PUT_U_INT32(ptr, attrp->ctime.seconds);
				IXDR_PUT_U_INT32(ptr, attrp->ctime.nseconds);
			} else {
				if (!xdr_u_longlong_t(xdrs, &attrp->size))
					return (FALSE);
				if (!xdr_u_int(xdrs, &attrp->mtime.seconds))
					return (FALSE);
				if (!xdr_u_int(xdrs, &attrp->mtime.nseconds))
					return (FALSE);
				if (!xdr_u_int(xdrs, &attrp->ctime.seconds))
					return (FALSE);
				if (!xdr_u_int(xdrs, &attrp->ctime.nseconds))
					return (FALSE);
			}
			break;
		case FALSE:
			break;
		default:
			return (FALSE);
		}
	}
	return (xdr_post_op_attr(xdrs, &objp->after));
}

bool_t
xdr_post_op_fh3(XDR *xdrs, post_op_fh3 *objp)
{
	if (!xdr_bool(xdrs, &objp->handle_follows))
		return (FALSE);
	switch (objp->handle_follows) {
	case TRUE:
		switch (xdrs->x_op) {
		case XDR_ENCODE:
			if (!xdr_nfs_fh3_server(xdrs, &objp->handle))
				return (FALSE);
			break;
		case XDR_FREE:
		case XDR_DECODE:
			if (!xdr_nfs_fh3(xdrs, &objp->handle))
				return (FALSE);
			break;
		}
		return (TRUE);
	case FALSE:
		return (TRUE);
	default:
		return (FALSE);
	}
}

static bool_t
xdr_sattr3(XDR *xdrs, sattr3 *objp)
{
	/* set_mode3 */
	if (!xdr_bool(xdrs, &objp->mode.set_it))
		return (FALSE);
	if (objp->mode.set_it)
		if (!xdr_u_int(xdrs, &objp->mode.mode))
			return (FALSE);
	/* set_uid3 */
	if (!xdr_bool(xdrs, &objp->uid.set_it))
		return (FALSE);
	if (objp->uid.set_it)
		if (!xdr_u_int(xdrs, &objp->uid.uid))
			return (FALSE);
	/* set_gid3 */
	if (!xdr_bool(xdrs, &objp->gid.set_it))
		return (FALSE);
	if (objp->gid.set_it)
		if (!xdr_u_int(xdrs, &objp->gid.gid))
			return (FALSE);

	/* set_size3 */
	if (!xdr_bool(xdrs, &objp->size.set_it))
		return (FALSE);
	if (objp->size.set_it)
		if (!xdr_u_longlong_t(xdrs, &objp->size.size))
			return (FALSE);

	/* set_atime */
	if (!xdr_enum(xdrs, (enum_t *)&objp->atime.set_it))
		return (FALSE);
	if (objp->atime.set_it == SET_TO_CLIENT_TIME) {
		if (!xdr_u_int(xdrs, &objp->atime.atime.seconds))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->atime.atime.nseconds))
			return (FALSE);
	}

	/* set_mtime */
	if (!xdr_enum(xdrs, (enum_t *)&objp->mtime.set_it))
		return (FALSE);
	if (objp->mtime.set_it == SET_TO_CLIENT_TIME) {
		if (!xdr_u_int(xdrs, &objp->mtime.mtime.seconds))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->mtime.mtime.nseconds))
			return (FALSE);
	}

	return (TRUE);
}

bool_t
xdr_GETATTR3res(XDR *xdrs, GETATTR3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS3_OK)
		return (TRUE);
	/* xdr_GETATTR3resok */
	return (xdr_fattr3(xdrs, &objp->resok.obj_attributes));
}

bool_t
xdr_GETATTR3vres(XDR *xdrs, GETATTR3vres *objp)
{
	/*
	 * DECODE or FREE only
	 */
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);

	if (objp->status != NFS3_OK)
		return (TRUE);

	return (xdr_fattr3_to_vattr(xdrs, &objp->fres));
}


bool_t
xdr_SETATTR3args(XDR *xdrs, SETATTR3args *objp)
{
	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->object))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->object))
			return (FALSE);
		break;
	}
	if (!xdr_sattr3(xdrs, &objp->new_attributes))
		return (FALSE);

	/* sattrguard3 */
	if (!xdr_bool(xdrs, &objp->guard.check))
		return (FALSE);
	switch (objp->guard.check) {
	case TRUE:
		if (!xdr_u_int(xdrs, &objp->guard.obj_ctime.seconds))
			return (FALSE);
		return (xdr_u_int(xdrs, &objp->guard.obj_ctime.nseconds));
	case FALSE:
		return (TRUE);
	default:
		return (FALSE);
	}
}

bool_t
xdr_SETATTR3res(XDR *xdrs, SETATTR3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		return (xdr_wcc_data(xdrs, &objp->resok.obj_wcc));
	default:
		return (xdr_wcc_data(xdrs, &objp->resfail.obj_wcc));
	}
}

bool_t
xdr_LOOKUP3res(XDR *xdrs, LOOKUP3res *objp)
{
	LOOKUP3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);

	if (objp->status != NFS3_OK)
		return (xdr_post_op_attr(xdrs, &objp->resfail.dir_attributes));

	/* xdr_LOOKUP3resok */
	resokp = &objp->resok;
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		if (!xdr_nfs_fh3_server(xdrs, &resokp->object))
			return (FALSE);
		break;
	case XDR_FREE:
	case XDR_DECODE:
		if (!xdr_nfs_fh3(xdrs, &resokp->object))
			return (FALSE);
		break;
	}
	if (!xdr_post_op_attr(xdrs, &resokp->obj_attributes))
		return (FALSE);
	return (xdr_post_op_attr(xdrs, &resokp->dir_attributes));
}

bool_t
xdr_LOOKUP3vres(XDR *xdrs, LOOKUP3vres *objp)
{
	/*
	 * DECODE or FREE only
	 */
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);

	if (objp->status != NFS3_OK)
		return (xdr_post_op_vattr(xdrs, &objp->dir_attributes));

	if (!xdr_nfs_fh3(xdrs, &objp->object))
		return (FALSE);
	if (!xdr_post_op_vattr(xdrs, &objp->obj_attributes))
		return (FALSE);
	return (xdr_post_op_vattr(xdrs, &objp->dir_attributes));
}

bool_t
xdr_ACCESS3args(XDR *xdrs, ACCESS3args *objp)
{
	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->object))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->object))
			return (FALSE);
		break;
	}
	return (xdr_u_int(xdrs, &objp->access));
}


bool_t
xdr_ACCESS3res(XDR *xdrs, ACCESS3res *objp)
{
	ACCESS3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS3_OK)
		return (xdr_post_op_attr(xdrs, &objp->resfail.obj_attributes));

	/* xdr_ACCESS3resok */
	resokp = &objp->resok;
	if (!xdr_post_op_attr(xdrs, &resokp->obj_attributes))
		return (FALSE);
	return (xdr_u_int(xdrs, &resokp->access));
}

bool_t
xdr_READLINK3args(XDR *xdrs,  READLINK3args *objp)
{
	rdma_chunkinfo_t rci;
	struct xdr_ops *xops = xdrrdma_xops();

	if ((xdrs->x_ops == &xdrrdma_ops || xdrs->x_ops == xops) &&
	    xdrs->x_op == XDR_ENCODE) {
		rci.rci_type = RCI_REPLY_CHUNK;
		rci.rci_len = MAXPATHLEN;
		XDR_CONTROL(xdrs, XDR_RDMA_ADD_CHUNK, &rci);
	}
	if (!xdr_nfs_fh3(xdrs, (nfs_fh3 *)objp))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_READLINK3res(XDR *xdrs, READLINK3res *objp)
{

	READLINK3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS3_OK)
		return (xdr_post_op_attr(xdrs,
		    &objp->resfail.symlink_attributes));

	/* xdr_READLINK3resok */
	resokp = &objp->resok;
	if (!xdr_post_op_attr(xdrs, &resokp->symlink_attributes))
		return (FALSE);
	return (xdr_string3(xdrs, &resokp->data, MAXPATHLEN));
}

bool_t
xdr_READ3args(XDR *xdrs, READ3args *objp)
{
	rdma_chunkinfo_t rci;
	rdma_wlist_conn_info_t rwci;
	struct xdr_ops *xops = xdrrdma_xops();

	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->file))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->file))
			return (FALSE);
		break;
	}
	if (!xdr_u_longlong_t(xdrs, &objp->offset))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->count))
		return (FALSE);

	DTRACE_PROBE1(xdr__i__read3_buf_len, int, objp->count);

	objp->wlist = NULL;

	/* if xdrrdma_sizeof in progress, then store the size */
	if (xdrs->x_ops == xops && xdrs->x_op == XDR_ENCODE) {
		rci.rci_type = RCI_WRITE_ADDR_CHUNK;
		rci.rci_len = objp->count;
		(void) XDR_CONTROL(xdrs, XDR_RDMA_ADD_CHUNK, &rci);
	}

	if (xdrs->x_ops != &xdrrdma_ops || xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (xdrs->x_op == XDR_ENCODE) {

		if (objp->res_uiop != NULL) {
			rci.rci_type = RCI_WRITE_UIO_CHUNK;
			rci.rci_a.rci_uiop = objp->res_uiop;
			rci.rci_len = objp->count;
			rci.rci_clpp = &objp->wlist;
		} else {
			rci.rci_type = RCI_WRITE_ADDR_CHUNK;
			rci.rci_a.rci_addr = objp->res_data_val_alt;
			rci.rci_len = objp->count;
			rci.rci_clpp = &objp->wlist;
		}

		return (XDR_CONTROL(xdrs, XDR_RDMA_ADD_CHUNK, &rci));
	}

	/* XDR_DECODE case */
	(void) XDR_CONTROL(xdrs, XDR_RDMA_GET_WCINFO, &rwci);
	objp->wlist = rwci.rwci_wlist;
	objp->conn = rwci.rwci_conn;

	return (TRUE);
}

bool_t
xdr_READ3res(XDR *xdrs, READ3res *objp)
{
	READ3resok *resokp;
	bool_t ret;
	mblk_t *mp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);

	if (objp->status != NFS3_OK)
		return (xdr_post_op_attr(xdrs, &objp->resfail.file_attributes));

	resokp = &objp->resok;

	if (xdr_post_op_attr(xdrs, &resokp->file_attributes) == FALSE ||
	    xdr_u_int(xdrs, &resokp->count) == FALSE ||
	    xdr_bool(xdrs, &resokp->eof) == FALSE) {
		return (FALSE);
	}

	if (xdrs->x_op == XDR_ENCODE) {

		mp = resokp->data.mp;
		if (mp != NULL) {
			if (xdrs->x_ops == &xdrmblk_ops) {
				if (xdrmblk_putmblk(xdrs, mp, resokp->count)) {
					resokp->data.mp = NULL;
					return (TRUE);
				} else {
					return (FALSE);
				}
			} else if (mp->b_cont != NULL) {
				/*
				 * We have read results in an mblk chain, but
				 * the encoding operations don't handle mblks
				 * (they'll operate on data.data_val rather
				 * than data.mp).  Because data_val can only
				 * point at a single data buffer, we need to
				 * pullup the read results into a single data
				 * block and reset data_val to point to it.
				 *
				 * This happens with RPC GSS where the wrapping
				 * function does XDR serialization into a
				 * temporary buffer prior to applying GSS.
				 * Because we're not in a performance sensitive
				 * path, the pullupmsg() here shouldn't hurt us
				 * too badly.
				 */
				if (pullupmsg(mp, -1) == 0)
					return (FALSE);
				resokp->data.data_val = (caddr_t)mp->b_rptr;
			}
		} else {
			if (xdr_u_int(xdrs, &resokp->count) == FALSE) {
				return (FALSE);
			}
			/*
			 * If read data sent by wlist (RDMA_WRITE), don't do
			 * xdr_bytes() below.   RDMA_WRITE transfers the data.
			 * Note: this is encode-only because the client code
			 * uses xdr_READ3vres/xdr_READ3uiores to decode results.
			 */
			if (resokp->wlist) {
				if (resokp->count != 0) {
					return (xdrrdma_send_read_data(
					    xdrs, resokp->count,
					    resokp->wlist));
				}
				return (TRUE);
			}
		}
		/*
		 * Fall thru for the xdr_bytes()
		 *
		 * note: the mblk will be freed in
		 * rfs3_read_free.
		 */
	}

	/* no RDMA_WRITE transfer -- send data inline */

	ret = xdr_bytes(xdrs, (char **)&resokp->data.data_val,
	    &resokp->data.data_len, nfs3tsize());

	return (ret);
}

bool_t
xdr_READ3vres(XDR *xdrs, READ3vres *objp)
{
	count3 ocount;
	/*
	 * DECODE or FREE only
	 */
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);

	if (!xdr_post_op_vattr(xdrs, &objp->pov))
		return (FALSE);

	if (objp->status != NFS3_OK)
		return (TRUE);

	if (!xdr_u_int(xdrs, &objp->count))
		return (FALSE);

	if (!xdr_bool(xdrs, &objp->eof))
		return (FALSE);

	/*
	 * If read data received via RDMA_WRITE, don't do xdr_bytes().
	 * RDMA_WRITE already moved the data so decode length of RDMA_WRITE.
	 */
	if (xdrs->x_ops == &xdrrdma_ops) {
		struct clist *cl;

		XDR_CONTROL(xdrs, XDR_RDMA_GET_WLIST, &cl);

		if (cl) {
			if (!xdr_u_int(xdrs, &ocount)) {
				return (FALSE);
			}
			if (ocount != objp->count) {
				DTRACE_PROBE2(xdr__e__read3vres_fail,
				    int, ocount, int, objp->count);
				objp->wlist = NULL;
				return (FALSE);
			}

			objp->wlist_len = clist_len(cl);
			objp->data.data_len = ocount;

			if (objp->wlist_len !=
			    roundup(objp->data.data_len, BYTES_PER_XDR_UNIT)) {
				DTRACE_PROBE2(
				    xdr__e__read3vres_fail,
				    int, ocount,
				    int, objp->data.data_len);
				objp->wlist = NULL;
				return (FALSE);
			}
			return (TRUE);
		}
	}

	return (xdr_bytes(xdrs, (char **)&objp->data.data_val,
	    &objp->data.data_len, nfs3tsize()));
}

bool_t
xdr_READ3uiores(XDR *xdrs, READ3uiores *objp)
{
	count3 ocount;
	bool_t attributes;
	mblk_t *mp;
	size_t n;
	int error;
	int size = (int)objp->size;
	struct uio *uiop = objp->uiop;
	int32_t fattr3_len = NFS3_SIZEOF_FATTR3 * BYTES_PER_XDR_UNIT;
	int32_t *ptr;

	/*
	 * DECODE or FREE only
	 */
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	if (!XDR_GETINT32(xdrs, (int32_t *)&objp->status))
		return (FALSE);

	if (!XDR_GETINT32(xdrs, (int32_t *)&attributes))
		return (FALSE);

	/*
	 * For directio we just skip over attributes if present
	 */
	switch (attributes) {
	case TRUE:
		if (!XDR_CONTROL(xdrs, XDR_SKIPBYTES, &fattr3_len))
			return (FALSE);
		break;
	case FALSE:
		break;
	default:
		return (FALSE);
	}

	if (objp->status != NFS3_OK)
		return (TRUE);

	if (!XDR_GETINT32(xdrs, (int32_t *)&objp->count))
		return (FALSE);

	if (!XDR_GETINT32(xdrs, (int32_t *)&objp->eof))
		return (FALSE);

	if (xdrs->x_ops == &xdrmblk_ops) {
		if (!xdrmblk_getmblk(xdrs, &mp, &objp->size))
			return (FALSE);

		if (objp->size == 0)
			return (TRUE);

		if (objp->size > size)
			return (FALSE);

		size = (int)objp->size;
		do {
			n = MIN(size, mp->b_wptr - mp->b_rptr);
			if ((n = MIN(uiop->uio_resid, n)) != 0) {

				error = uiomove((char *)mp->b_rptr, n, UIO_READ,
				    uiop);
				if (error)
					return (FALSE);
				mp->b_rptr += n;
				size -= n;
			}

			while (mp && (mp->b_rptr >= mp->b_wptr))
				mp = mp->b_cont;
		} while (mp && size > 0 && uiop->uio_resid > 0);

		return (TRUE);
	}

	if (xdrs->x_ops == &xdrrdma_ops) {
		struct clist *cl;

		XDR_CONTROL(xdrs, XDR_RDMA_GET_WLIST, &cl);

		objp->wlist = cl;

		if (objp->wlist) {
			if (!xdr_u_int(xdrs, &ocount)) {
				objp->wlist = NULL;
				return (FALSE);
			}

			if (ocount != objp->count) {
				DTRACE_PROBE2(xdr__e__read3uiores_fail,
				    int, ocount, int, objp->count);
				objp->wlist = NULL;
				return (FALSE);
			}

			objp->wlist_len = clist_len(cl);

			uiop->uio_resid -= objp->count;
			uiop->uio_iov->iov_len -= objp->count;
			uiop->uio_iov->iov_base += objp->count;
			uiop->uio_loffset += objp->count;

			/*
			 * XXX: Assume 1 iov, needs to be changed.
			 */
			objp->size = objp->count;

			return (TRUE);
		}
	}

	/*
	 * This isn't an xdrmblk stream nor RDMA.
	 * Handle the likely case that it can be
	 * inlined (ex. xdrmem).
	 */
	if (!XDR_GETINT32(xdrs, (int32_t *)&objp->size))
		return (FALSE);

	if (objp->size == 0)
		return (TRUE);

	if (objp->size > size)
		return (FALSE);

	size = (int)objp->size;
	if ((ptr = XDR_INLINE(xdrs, size)) != NULL)
		return (uiomove(ptr, size, UIO_READ, uiop) ? FALSE : TRUE);

	/*
	 * Handle some other (unlikely) stream type that will need a copy.
	 */
	if ((ptr = kmem_alloc(size, KM_NOSLEEP)) == NULL)
		return (FALSE);

	if (!XDR_GETBYTES(xdrs, (caddr_t)ptr, size)) {
		kmem_free(ptr, size);
		return (FALSE);
	}
	error = uiomove(ptr, size, UIO_READ, uiop);
	kmem_free(ptr, size);

	return (error ? FALSE : TRUE);
}

bool_t
xdr_WRITE3args(XDR *xdrs, WRITE3args *objp)
{
	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->file))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->file))
			return (FALSE);
		break;
	}
	if (!xdr_u_longlong_t(xdrs, &objp->offset))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->count))
		return (FALSE);
	if (!xdr_enum(xdrs, (enum_t *)&objp->stable))
		return (FALSE);

	if (xdrs->x_op == XDR_DECODE) {
		if (xdrs->x_ops == &xdrmblk_ops) {
			if (xdrmblk_getmblk(xdrs, &objp->mblk,
			    &objp->data.data_len) == TRUE) {
				objp->data.data_val = NULL;
				return (TRUE);
			}
		}
		objp->mblk = NULL;

		if (xdrs->x_ops == &xdrrdmablk_ops) {
			if (xdrrdma_getrdmablk(xdrs, &objp->rlist,
			    &objp->data.data_len,
			    &objp->conn, nfs3tsize()) == TRUE) {
				objp->data.data_val = NULL;
				if (xdrrdma_read_from_client(
				    objp->rlist,
				    &objp->conn,
				    objp->count) == FALSE) {
					return (FALSE);
				}
				return (TRUE);
			}
		}
		objp->rlist = NULL;

		/* Else fall thru for the xdr_bytes(). */
	}

	if (xdrs->x_op == XDR_FREE) {
		if (objp->rlist != NULL) {
			(void) xdrrdma_free_clist(objp->conn, objp->rlist);
			objp->rlist = NULL;
			objp->data.data_val = NULL;
			return (TRUE);
		}
	}

	DTRACE_PROBE1(xdr__i__write3_buf_len,
	    int, objp->data.data_len);

	return (xdr_bytes(xdrs, (char **)&objp->data.data_val,
	    &objp->data.data_len, nfs3tsize()));
}

bool_t
xdr_WRITE3res(XDR *xdrs, WRITE3res *objp)
{
	WRITE3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS3_OK) /* xdr_WRITE3resfail */
		return (xdr_wcc_data(xdrs, &objp->resfail.file_wcc));

	/* xdr_WRITE3resok */
	resokp = &objp->resok;
	if (!xdr_wcc_data(xdrs, &resokp->file_wcc))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->count))
		return (FALSE);
	if (!xdr_enum(xdrs, (enum_t *)&resokp->committed))
		return (FALSE);
	/*
	 * writeverf3 is really an opaque 8 byte
	 * quantity, but we will treat it as a
	 * hyper for efficiency, the cost of
	 * a byteswap here saves bcopys elsewhere
	 */
	return (xdr_u_longlong_t(xdrs, &resokp->verf));
}

bool_t
xdr_CREATE3args(XDR *xdrs, CREATE3args *objp)
{
	createhow3 *howp;

	if (!xdr_diropargs3(xdrs, &objp->where))
		return (FALSE);

	/* xdr_createhow3 */
	howp = &objp->how;

	if (!xdr_enum(xdrs, (enum_t *)&howp->mode))
		return (FALSE);
	switch (howp->mode) {
	case UNCHECKED:
	case GUARDED:
		return (xdr_sattr3(xdrs, &howp->createhow3_u.obj_attributes));
	case EXCLUSIVE:
		/*
		 * createverf3 is really an opaque 8 byte
		 * quantity, but we will treat it as a
		 * hyper for efficiency, the cost of
		 * a byteswap here saves bcopys elsewhere
		 */
		return (xdr_u_longlong_t(xdrs, &howp->createhow3_u.verf));
	default:
		return (FALSE);
	}
}

bool_t
xdr_CREATE3res(XDR *xdrs, CREATE3res *objp)
{
	CREATE3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		/* xdr_CREATE3resok */
		resokp = &objp->resok;

		if (!xdr_post_op_fh3(xdrs, &resokp->obj))
			return (FALSE);
		if (!xdr_post_op_attr(xdrs, &resokp->obj_attributes))
			return (FALSE);
		return (xdr_wcc_data(xdrs, &resokp->dir_wcc));
	default:
		/* xdr_CREATE3resfail */
		return (xdr_wcc_data(xdrs, &objp->resfail.dir_wcc));
	}
}

bool_t
xdr_MKDIR3args(XDR *xdrs, MKDIR3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->where))
		return (FALSE);
	return (xdr_sattr3(xdrs, &objp->attributes));
}

bool_t
xdr_MKDIR3res(XDR *xdrs, MKDIR3res *objp)
{
	MKDIR3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		/* xdr_MKDIR3resok */
		resokp = &objp->resok;

		if (!xdr_post_op_fh3(xdrs, &resokp->obj))
			return (FALSE);
		if (!xdr_post_op_attr(xdrs, &resokp->obj_attributes))
			return (FALSE);
		return (xdr_wcc_data(xdrs, &resokp->dir_wcc));
	default:
		return (xdr_wcc_data(xdrs, &objp->resfail.dir_wcc));
	}
}

bool_t
xdr_SYMLINK3args(XDR *xdrs, SYMLINK3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->where))
		return (FALSE);
	if (!xdr_sattr3(xdrs, &objp->symlink.symlink_attributes))
		return (FALSE);
	return (xdr_string3(xdrs, &objp->symlink.symlink_data, MAXPATHLEN));
}

bool_t
xdr_SYMLINK3res(XDR *xdrs, SYMLINK3res *objp)
{
	SYMLINK3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		resokp = &objp->resok;
		/* xdr_SYMLINK3resok */
		if (!xdr_post_op_fh3(xdrs, &resokp->obj))
			return (FALSE);
		if (!xdr_post_op_attr(xdrs, &resokp->obj_attributes))
			return (FALSE);
		return (xdr_wcc_data(xdrs, &resokp->dir_wcc));
	default:
		return (xdr_wcc_data(xdrs, &objp->resfail.dir_wcc));
	}
}

bool_t
xdr_MKNOD3args(XDR *xdrs, MKNOD3args *objp)
{
	mknoddata3 *whatp;
	devicedata3 *nod_objp;

	if (!xdr_diropargs3(xdrs, &objp->where))
		return (FALSE);

	whatp = &objp->what;
	if (!xdr_enum(xdrs, (enum_t *)&whatp->type))
		return (FALSE);
	switch (whatp->type) {
	case NF3CHR:
	case NF3BLK:
		/* xdr_devicedata3 */
		nod_objp = &whatp->mknoddata3_u.device;
		if (!xdr_sattr3(xdrs, &nod_objp->dev_attributes))
			return (FALSE);
		if (!xdr_u_int(xdrs, &nod_objp->spec.specdata1))
			return (FALSE);
		return (xdr_u_int(xdrs, &nod_objp->spec.specdata2));
	case NF3SOCK:
	case NF3FIFO:
		return (xdr_sattr3(xdrs, &whatp->mknoddata3_u.pipe_attributes));
	default:
		break;
	}
	return (TRUE);
}

bool_t
xdr_MKNOD3res(XDR *xdrs, MKNOD3res *objp)
{
	MKNOD3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		/* xdr_MKNOD3resok */
		resokp = &objp->resok;
		if (!xdr_post_op_fh3(xdrs, &resokp->obj))
			return (FALSE);
		if (!xdr_post_op_attr(xdrs, &resokp->obj_attributes))
			return (FALSE);
		return (xdr_wcc_data(xdrs, &resokp->dir_wcc));
	default:
		return (xdr_wcc_data(xdrs, &objp->resfail.dir_wcc));
	}
}

bool_t
xdr_REMOVE3res(XDR *xdrs, REMOVE3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		return (xdr_wcc_data(xdrs, &objp->resok.dir_wcc));
	default:
		return (xdr_wcc_data(xdrs, &objp->resfail.dir_wcc));
	}
}

bool_t
xdr_RMDIR3res(XDR *xdrs, RMDIR3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		return (xdr_wcc_data(xdrs, &objp->resok.dir_wcc));
	default:
		return (xdr_wcc_data(xdrs, &objp->resfail.dir_wcc));
	}
}

bool_t
xdr_RENAME3args(XDR *xdrs, RENAME3args *objp)
{
	if (!xdr_diropargs3(xdrs, &objp->from))
		return (FALSE);
	return (xdr_diropargs3(xdrs, &objp->to));
}

bool_t
xdr_RENAME3res(XDR *xdrs, RENAME3res *objp)
{
	RENAME3resok *resokp;
	RENAME3resfail *resfailp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		/* xdr_RENAME3resok */
		resokp = &objp->resok;

		if (!xdr_wcc_data(xdrs, &resokp->fromdir_wcc))
			return (FALSE);
		return (xdr_wcc_data(xdrs, &resokp->todir_wcc));
	default:
		/* xdr_RENAME3resfail */
		resfailp = &objp->resfail;
		if (!xdr_wcc_data(xdrs, &resfailp->fromdir_wcc))
			return (FALSE);
		return (xdr_wcc_data(xdrs, &resfailp->todir_wcc));
	}
}

bool_t
xdr_LINK3args(XDR *xdrs, LINK3args *objp)
{
	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->file))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->file))
			return (FALSE);
		break;
	}
	return (xdr_diropargs3(xdrs, &objp->link));
}

bool_t
xdr_LINK3res(XDR *xdrs, LINK3res *objp)
{
	LINK3resok *resokp;
	LINK3resfail *resfailp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		/* xdr_LINK3resok */
		resokp = &objp->resok;
		if (!xdr_post_op_attr(xdrs, &resokp->file_attributes))
			return (FALSE);
		return (xdr_wcc_data(xdrs, &resokp->linkdir_wcc));
	default:
		/* xdr_LINK3resfail */
		resfailp = &objp->resfail;
		if (!xdr_post_op_attr(xdrs, &resfailp->file_attributes))
			return (FALSE);
		return (xdr_wcc_data(xdrs, &resfailp->linkdir_wcc));
	}
}

bool_t
xdr_READDIR3args(XDR *xdrs, READDIR3args *objp)
{
	rdma_chunkinfo_t rci;
	struct xdr_ops *xops = xdrrdma_xops();

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->dir))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->dir))
			return (FALSE);
		break;
	}
	if ((xdrs->x_ops == &xdrrdma_ops || xdrs->x_ops == xops) &&
	    xdrs->x_op == XDR_ENCODE) {
		rci.rci_type = RCI_REPLY_CHUNK;
		rci.rci_len = objp->count;
		XDR_CONTROL(xdrs, XDR_RDMA_ADD_CHUNK, &rci);
	}

	if (!xdr_u_longlong_t(xdrs, &objp->cookie))
		return (FALSE);
	/*
	 * cookieverf is really an opaque 8 byte
	 * quantity, but we will treat it as a
	 * hyper for efficiency, the cost of
	 * a byteswap here saves bcopys elsewhere
	 */
	if (!xdr_u_longlong_t(xdrs, &objp->cookieverf))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->count));
}

#ifdef	nextdp
#undef	nextdp
#endif
#define	nextdp(dp)	((struct dirent64 *)((char *)(dp) + (dp)->d_reclen))
#ifdef	roundup
#undef	roundup
#endif
#define	roundup(x, y)	((((x) + ((y) - 1)) / (y)) * (y))

/*
 * ENCODE ONLY
 */
static bool_t
xdr_putdirlist(XDR *xdrs, READDIR3resok *objp)
{
	struct dirent64 *dp;
	char *name;
	int size;
	int bufsize;
	uint_t namlen;
	bool_t true = TRUE;
	bool_t false = FALSE;
	int entrysz;
	int tofit;
	fileid3 fileid;
	cookie3 cookie;

	if (xdrs->x_op != XDR_ENCODE)
		return (FALSE);

	/*
	 * bufsize is used to keep track of the size of the response.
	 * It is primed with:
	 *	1 for the status +
	 *	1 for the dir_attributes.attributes boolean +
	 *	2 for the cookie verifier
	 * all times BYTES_PER_XDR_UNIT to convert from XDR units
	 * to bytes.  If there are directory attributes to be
	 * returned, then:
	 *	NFS3_SIZEOF_FATTR3 for the dir_attributes.attr fattr3
	 * time BYTES_PER_XDR_UNIT is added to account for them.
	 */
	bufsize = (1 + 1 + 2) * BYTES_PER_XDR_UNIT;
	if (objp->dir_attributes.attributes)
		bufsize += NFS3_SIZEOF_FATTR3 * BYTES_PER_XDR_UNIT;
	for (size = objp->size, dp = (struct dirent64 *)objp->reply.entries;
	    size > 0;
	    size -= dp->d_reclen, dp = nextdp(dp)) {
		if (dp->d_reclen == 0)
			return (FALSE);
		if (dp->d_ino == 0)
			continue;
		name = dp->d_name;
		namlen = (uint_t)strlen(dp->d_name);
		/*
		 * An entry is composed of:
		 *	1 for the true/false list indicator +
		 *	2 for the fileid +
		 *	1 for the length of the name +
		 *	2 for the cookie +
		 * all times BYTES_PER_XDR_UNIT to convert from
		 * XDR units to bytes, plus the length of the name
		 * rounded up to the nearest BYTES_PER_XDR_UNIT.
		 */
		entrysz = (1 + 2 + 1 + 2) * BYTES_PER_XDR_UNIT +
		    roundup(namlen, BYTES_PER_XDR_UNIT);
		/*
		 * We need to check to see if the number of bytes left
		 * to go into the buffer will actually fit into the
		 * buffer.  This is calculated as the size of this
		 * entry plus:
		 *	1 for the true/false list indicator +
		 *	1 for the eof indicator
		 * times BYTES_PER_XDR_UNIT to convert from from
		 * XDR units to bytes.
		 */
		tofit = entrysz + (1 + 1) * BYTES_PER_XDR_UNIT;
		if (bufsize + tofit > objp->count) {
			objp->reply.eof = FALSE;
			break;
		}
		fileid = (fileid3)(dp->d_ino);
		cookie = (cookie3)(dp->d_off);
		if (!xdr_bool(xdrs, &true) ||
		    !xdr_u_longlong_t(xdrs, &fileid) ||
		    !xdr_bytes(xdrs, &name, &namlen, ~0) ||
		    !xdr_u_longlong_t(xdrs, &cookie)) {
			return (FALSE);
		}
		bufsize += entrysz;
	}
	if (!xdr_bool(xdrs, &false))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->reply.eof))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_READDIR3res(XDR *xdrs, READDIR3res *objp)
{
	READDIR3resok *resokp;

	/*
	 * ENCODE or FREE only
	 */
	if (xdrs->x_op == XDR_DECODE)
		return (FALSE);

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS3_OK)
		return (xdr_post_op_attr(xdrs, &objp->resfail.dir_attributes));

	/* xdr_READDIR3resok */
	resokp = &objp->resok;
	if (!xdr_post_op_attr(xdrs, &resokp->dir_attributes))
		return (FALSE);
	if (xdrs->x_op != XDR_ENCODE)
		return (TRUE);
	/*
	 * cookieverf is really an opaque 8 byte
	 * quantity, but we will treat it as a
	 * hyper for efficiency, the cost of
	 * a byteswap here saves bcopys elsewhere
	 */
	if (!xdr_u_longlong_t(xdrs, &resokp->cookieverf))
		return (FALSE);
	return (xdr_putdirlist(xdrs, resokp));
}

bool_t
xdr_READDIR3vres(XDR *xdrs, READDIR3vres *objp)
{
	dirent64_t *dp;
	uint_t entries_size;
	int outcount = 0;

	/*
	 * DECODE or FREE only
	 */
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);

	if (!xdr_post_op_vattr(xdrs, &objp->dir_attributes))
		return (FALSE);

	if (objp->status != NFS3_OK)
		return (TRUE);

	/*
	 * cookieverf is really an opaque 8 byte
	 * quantity, but we will treat it as a
	 * hyper for efficiency, the cost of
	 * a byteswap here saves bcopys elsewhere
	 */
	if (!xdr_u_longlong_t(xdrs, &objp->cookieverf))
		return (FALSE);

	entries_size = objp->entries_size;
	dp = objp->entries;

	for (;;) {
		uint_t this_reclen;
		bool_t valid;
		uint_t namlen;
		ino64_t fileid;

		if (!XDR_GETINT32(xdrs, (int32_t *)&valid))
			return (FALSE);
		if (!valid) {
			/*
			 * We have run out of entries, decode eof.
			 */
			if (!XDR_GETINT32(xdrs, (int32_t *)&objp->eof))
				return (FALSE);

			break;
		}

		/*
		 * fileid3 fileid
		 */
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&fileid))
			return (FALSE);

		/*
		 * filename3 name
		 */
		if (!XDR_GETINT32(xdrs, (int32_t *)&namlen))
			return (FALSE);
		this_reclen = DIRENT64_RECLEN(namlen);

		/*
		 * If this will overflow buffer, stop decoding
		 */
		if ((outcount + this_reclen) > entries_size) {
			objp->eof = FALSE;
			break;
		}
		dp->d_reclen = this_reclen;
		dp->d_ino = fileid;

		if (!xdr_opaque(xdrs, dp->d_name, namlen))
			return (FALSE);
		bzero(&dp->d_name[namlen],
		    DIRENT64_NAMELEN(this_reclen) - namlen);

		/*
		 * cookie3 cookie
		 */
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&dp->d_off))
			return (FALSE);
		objp->loff = dp->d_off;

		outcount += this_reclen;
		dp = (dirent64_t *)((intptr_t)dp + this_reclen);
	}

	objp->size = outcount;
	return (TRUE);
}

bool_t
xdr_READDIRPLUS3args(XDR *xdrs, READDIRPLUS3args *objp)
{
	rdma_chunkinfo_t rci;
	struct xdr_ops *xops = xdrrdma_xops();

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->dir))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->dir))
			return (FALSE);
		break;
	}
	if ((xdrs->x_ops == &xdrrdma_ops || xdrs->x_ops == xops) &&
	    xdrs->x_op == XDR_ENCODE) {
		rci.rci_type = RCI_REPLY_CHUNK;
		rci.rci_len = objp->maxcount;
		XDR_CONTROL(xdrs, XDR_RDMA_ADD_CHUNK, &rci);
	}

	if (!xdr_u_longlong_t(xdrs, &objp->cookie))
		return (FALSE);
	/*
	 * cookieverf is really an opaque 8 byte
	 * quantity, but we will treat it as a
	 * hyper for efficiency, the cost of
	 * a byteswap here saves bcopys elsewhere
	 */
	if (!xdr_u_longlong_t(xdrs, &objp->cookieverf))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->dircount))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->maxcount));
}

/*
 * ENCODE ONLY
 */
static bool_t
xdr_putdirpluslist(XDR *xdrs, READDIRPLUS3resok *objp)
{
	struct dirent64 *dp;
	char *name;
	int nents;
	bool_t true = TRUE;
	bool_t false = FALSE;
	fileid3 fileid;
	cookie3 cookie;
	entryplus3_info *infop;

	if (xdrs->x_op != XDR_ENCODE)
		return (FALSE);

	dp = (struct dirent64 *)objp->reply.entries;
	nents = objp->size;
	infop = objp->infop;

	while (nents > 0) {
		if (dp->d_reclen == 0)
			return (FALSE);
		if (dp->d_ino != 0) {
			name = dp->d_name;
			fileid = (fileid3)(dp->d_ino);
			cookie = (cookie3)(dp->d_off);
			if (!xdr_bool(xdrs, &true) ||
			    !xdr_u_longlong_t(xdrs, &fileid) ||
			    !xdr_bytes(xdrs, &name, &infop->namelen, ~0) ||
			    !xdr_u_longlong_t(xdrs, &cookie) ||
			    !xdr_post_op_attr(xdrs, &infop->attr) ||
			    !xdr_post_op_fh3(xdrs, &infop->fh)) {
				return (FALSE);
			}
		}
		dp = nextdp(dp);
		infop++;
		nents--;
	}

	if (!xdr_bool(xdrs, &false))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->reply.eof))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_READDIRPLUS3res(XDR *xdrs, READDIRPLUS3res *objp)
{
	READDIRPLUS3resok *resokp;

	/*
	 * ENCODE or FREE only
	 */
	if (xdrs->x_op == XDR_DECODE)
		return (FALSE);

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		/* xdr_READDIRPLUS3resok */
		resokp = &objp->resok;
		if (!xdr_post_op_attr(xdrs, &resokp->dir_attributes))
			return (FALSE);
		/*
		 * cookieverf is really an opaque 8 byte
		 * quantity, but we will treat it as a
		 * hyper for efficiency, the cost of
		 * a byteswap here saves bcopys elsewhere
		 */
		if (!xdr_u_longlong_t(xdrs, &resokp->cookieverf))
			return (FALSE);
		if (xdrs->x_op == XDR_ENCODE) {
			if (!xdr_putdirpluslist(xdrs, resokp))
				return (FALSE);
		}
		break;
	default:
		return (xdr_post_op_attr(xdrs, &objp->resfail.dir_attributes));
	}
	return (TRUE);
}

/*
 * Decode readdirplus directly into a dirent64_t and do the DNLC caching.
 */
bool_t
xdr_READDIRPLUS3vres(XDR *xdrs, READDIRPLUS3vres *objp)
{
	dirent64_t *dp;
	vnode_t *dvp;
	uint_t entries_size;
	int outcount = 0;
	vnode_t *nvp;
	rnode_t *rp;
	post_op_vattr pov;
	vattr_t va;

	/*
	 * DECODE or FREE only
	 */
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	if (!XDR_GETINT32(xdrs, (int32_t *)&objp->status))
		return (FALSE);

	if (!xdr_post_op_vattr(xdrs, &objp->dir_attributes))
		return (FALSE);

	if (objp->status != NFS3_OK)
		return (TRUE);

	/*
	 * cookieverf is really an opaque 8 byte
	 * quantity, but we will treat it as a
	 * hyper for efficiency, the cost of
	 * a byteswap here saves bcopys elsewhere
	 */
	if (!xdr_u_longlong_t(xdrs, &objp->cookieverf))
		return (FALSE);

	dvp = objp->dir_attributes.fres.vp;
	rp = VTOR(dvp);

	pov.fres.vap = &va;
	pov.fres.vp = dvp;

	entries_size = objp->entries_size;
	dp = objp->entries;

	for (;;) {
		uint_t this_reclen;
		bool_t valid;
		uint_t namlen;
		nfs_fh3 fh;
		int va_valid;
		int fh_valid;
		ino64_t fileid;

		if (!XDR_GETINT32(xdrs, (int32_t *)&valid))
			return (FALSE);
		if (!valid) {
			/*
			 * We have run out of entries, decode eof.
			 */
			if (!XDR_GETINT32(xdrs, (int32_t *)&objp->eof))
				return (FALSE);

			break;
		}

		/*
		 * fileid3 fileid
		 */
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&fileid))
			return (FALSE);

		/*
		 * filename3 name
		 */
		if (!XDR_GETINT32(xdrs, (int32_t *)&namlen))
			return (FALSE);
		this_reclen = DIRENT64_RECLEN(namlen);

		/*
		 * If this will overflow buffer, stop decoding
		 */
		if ((outcount + this_reclen) > entries_size) {
			objp->eof = FALSE;
			break;
		}
		dp->d_reclen = this_reclen;
		dp->d_ino = fileid;

		if (!xdr_opaque(xdrs, dp->d_name, namlen))
			return (FALSE);
		bzero(&dp->d_name[namlen],
		    DIRENT64_NAMELEN(this_reclen) - namlen);

		/*
		 * cookie3 cookie
		 */
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&dp->d_off))
			return (FALSE);
		objp->loff = dp->d_off;

		/*
		 * post_op_attr name_attributes
		 */
		if (!xdr_post_op_vattr(xdrs, &pov))
			return (FALSE);

		if (pov.attributes == TRUE &&
		    pov.fres.status == NFS3_OK)
			va_valid = TRUE;
		else
			va_valid = FALSE;

		/*
		 * post_op_fh3 name_handle
		 */
		if (!XDR_GETINT32(xdrs, (int32_t *)&fh_valid))
			return (FALSE);

		/*
		 * By definition of the standard fh_valid can be 0 (FALSE) or
		 * 1 (TRUE), but we have to account for it being anything else
		 * in case some other system didn't follow the standard.  Note
		 * that this is why the else checks if the fh_valid variable
		 * is != FALSE.
		 */
		if (fh_valid == TRUE) {
			if (!xdr_nfs_fh3(xdrs, &fh))
				return (FALSE);
		} else {
			if (fh_valid != FALSE)
				return (FALSE);
		}

		/*
		 * If the name is "." or there are no attributes,
		 * don't polute the DNLC with "." entries or files
		 * we cannot determine the type for.
		 */
		if (!(namlen == 1 && dp->d_name[0] == '.') &&
		    va_valid && fh_valid) {

			/*
			 * Do the DNLC caching
			 */
			nvp = makenfs3node_va(&fh, &va, dvp->v_vfsp,
			    objp->time, objp->credentials,
			    rp->r_path, dp->d_name);
			dnlc_update(dvp, dp->d_name, nvp);
			VN_RELE(nvp);
		}

		outcount += this_reclen;
		dp = (dirent64_t *)((intptr_t)dp + this_reclen);
	}

	objp->size = outcount;
	return (TRUE);
}

bool_t
xdr_FSSTAT3res(XDR *xdrs, FSSTAT3res *objp)
{
	FSSTAT3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS3_OK)
		return (xdr_post_op_attr(xdrs, &objp->resfail.obj_attributes));

	/* xdr_FSSTAT3resok */
	resokp = &objp->resok;
	if (!xdr_post_op_attr(xdrs, &resokp->obj_attributes))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &resokp->tbytes))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &resokp->fbytes))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &resokp->abytes))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &resokp->tfiles))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &resokp->ffiles))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &resokp->afiles))
		return (FALSE);
	return (xdr_u_int(xdrs, &resokp->invarsec));
}

bool_t
xdr_FSINFO3res(XDR *xdrs, FSINFO3res *objp)
{
	FSINFO3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS3_OK) /* xdr_FSSTAT3resfail */
		return (xdr_post_op_attr(xdrs, &objp->resfail.obj_attributes));

	/* xdr_FSINFO3resok */
	resokp = &objp->resok;
	if (!xdr_post_op_attr(xdrs, &resokp->obj_attributes))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->rtmax))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->rtpref))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->rtmult))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->wtmax))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->wtpref))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->wtmult))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->dtpref))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &resokp->maxfilesize))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->time_delta.seconds))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->time_delta.nseconds))
		return (FALSE);
	return (xdr_u_int(xdrs, &resokp->properties));
}

bool_t
xdr_PATHCONF3res(XDR *xdrs, PATHCONF3res *objp)
{
	PATHCONF3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS3_OK)
		return (xdr_post_op_attr(xdrs, &objp->resfail.obj_attributes));

	/* xdr_PATHCONF3resok */
	resokp = &objp->resok;
	if (!xdr_post_op_attr(xdrs, &resokp->obj_attributes))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->info.link_max))
		return (FALSE);
	if (!xdr_u_int(xdrs, &resokp->info.name_max))
		return (FALSE);
	if (!xdr_bool(xdrs, &resokp->info.no_trunc))
		return (FALSE);
	if (!xdr_bool(xdrs, &resokp->info.chown_restricted))
		return (FALSE);
	if (!xdr_bool(xdrs, &resokp->info.case_insensitive))
		return (FALSE);
	return (xdr_bool(xdrs, &resokp->info.case_preserving));
}

bool_t
xdr_COMMIT3args(XDR *xdrs, COMMIT3args *objp)
{
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->file))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->file))
			return (FALSE);
		break;
	}
	if (!xdr_u_longlong_t(xdrs, &objp->offset))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->count));
}

bool_t
xdr_COMMIT3res(XDR *xdrs, COMMIT3res *objp)
{
	COMMIT3resok *resokp;

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS3_OK)
		return (xdr_wcc_data(xdrs, &objp->resfail.file_wcc));

	/* xdr_COMMIT3resok */
	resokp = &objp->resok;
	if (!xdr_wcc_data(xdrs, &resokp->file_wcc))
		return (FALSE);
	/*
	 * writeverf3 is really an opaque 8 byte
	 * quantity, but we will treat it as a
	 * hyper for efficiency, the cost of
	 * a byteswap here saves bcopys elsewhere
	 */
	return (xdr_u_longlong_t(xdrs, &resokp->verf));
}
