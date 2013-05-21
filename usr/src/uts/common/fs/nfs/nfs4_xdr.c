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
/*
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

/*
 * A handcoded version based on the original rpcgen code.
 *
 * Note: All future NFS4 protocol changes should be added by hand
 * to this file.
 *
 * CAUTION: All protocol changes must also be propagated to:
 *     usr/src/cmd/cmd-inet/usr.sbin/snoop/nfs4_xdr.c
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/dnlc.h>
#include <nfs/nfs.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_clnt.h>
#include <sys/sdt.h>
#include <sys/mkdev.h>
#include <rpc/rpc_rdma.h>
#include <rpc/xdr.h>

#define	xdr_dev_t xdr_u_int

extern bool_t xdr_netbuf(XDR *, struct netbuf *);
extern bool_t xdr_vector(XDR *, char *, const uint_t, const uint_t,
	const xdrproc_t);
bool_t xdr_knetconfig(XDR *, struct knetconfig *);

bool_t
xdr_bitmap4(XDR *xdrs, bitmap4 *objp)
{
	int32_t len, size;

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	/*
	 * Simplified bitmap4 processing, always encode from uint64_t
	 * to 2 uint32_t's, always decode first 2 uint32_t's into a
	 * uint64_t and ignore all of the rest.
	 */
	if (xdrs->x_op == XDR_ENCODE) {
		len = 2;

		if (!XDR_PUTINT32(xdrs, &len))
			return (FALSE);

#if defined(_LITTLE_ENDIAN)
		if (XDR_PUTINT32(xdrs, (int32_t *)((char *)objp +
		    BYTES_PER_XDR_UNIT)) == TRUE) {
			return (XDR_PUTINT32(xdrs, (int32_t *)objp));
		}
#elif defined(_BIG_ENDIAN)
		if (XDR_PUTINT32(xdrs, (int32_t *)objp) == TRUE) {
			return (XDR_PUTINT32(xdrs, (int32_t *)((char *)objp +
			    BYTES_PER_XDR_UNIT)));
		}
#endif
		return (FALSE);
	}

	if (!XDR_GETINT32(xdrs, &len))
		return (FALSE);

	/*
	 * Common fast DECODE cases
	 */
	if (len == 2) {
#if defined(_LITTLE_ENDIAN)
		if (XDR_GETINT32(xdrs, (int32_t *)((char *)objp +
		    BYTES_PER_XDR_UNIT)) == TRUE) {
			return (XDR_GETINT32(xdrs, (int32_t *)objp));
		}
#elif defined(_BIG_ENDIAN)
		if (XDR_GETINT32(xdrs, (int32_t *)objp) == TRUE) {
			return (XDR_GETINT32(xdrs, (int32_t *)((char *)objp +
			    BYTES_PER_XDR_UNIT)));
		}
#endif
		return (FALSE);
	}

	*objp = 0;
	if (len == 0)
		return (TRUE);

	/*
	 * The not so common DECODE cases, len == 1 || len > 2
	 */
#if defined(_LITTLE_ENDIAN)
	if (!XDR_GETINT32(xdrs, (int32_t *)((char *)objp + BYTES_PER_XDR_UNIT)))
		return (FALSE);
	if (--len == 0)
		return (TRUE);
	if (!XDR_GETINT32(xdrs, (int32_t *)objp))
		return (FALSE);
#elif defined(_BIG_ENDIAN)
	if (!XDR_GETINT32(xdrs, (int32_t *)objp))
		return (FALSE);
	if (--len == 0)
		return (TRUE);
	if (!XDR_GETINT32(xdrs, (int32_t *)((char *)objp + BYTES_PER_XDR_UNIT)))
		return (FALSE);
#else
	return (FALSE);
#endif

	if (--len == 0)
		return (TRUE);

	size = len * BYTES_PER_XDR_UNIT;
	return (XDR_CONTROL(xdrs, XDR_SKIPBYTES, &size));
}

/* Called by xdr_array, nfsid_map_xdr */
bool_t
xdr_utf8string(XDR *xdrs, utf8string *objp)
{
	if (xdrs->x_op != XDR_FREE)
		return (xdr_bytes(xdrs, (char **)&objp->utf8string_val,
		    (uint_t *)&objp->utf8string_len, NFS4_MAX_UTF8STRING));

	if (objp->utf8string_val != NULL) {
		kmem_free(objp->utf8string_val, objp->utf8string_len);
		objp->utf8string_val = NULL;
	}
	return (TRUE);
}

/*
 * used by NFSv4 referrals to get info needed for NFSv4 referral mount.
 */
bool_t
xdr_nfs_fsl_info(XDR *xdrs, struct nfs_fsl_info *objp)
{

	if (!xdr_u_int(xdrs, &objp->netbuf_len))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->netnm_len))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->knconf_len))
		return (FALSE);

#if defined(_LP64)
	/*
	 * The object can come from a 32-bit binary; nfsmapid.
	 * To be safe we double the size of the knetconfig to
	 * allow some buffering for decoding.
	 */
	if (xdrs->x_op == XDR_DECODE)
		objp->knconf_len += sizeof (struct knetconfig);
#endif

	if (!xdr_string(xdrs, &objp->netname, ~0))
		return (FALSE);
	if (!xdr_pointer(xdrs, (char **)&objp->addr, objp->netbuf_len,
	    (xdrproc_t)xdr_netbuf))
		return (FALSE);
	if (!xdr_pointer(xdrs, (char **)&objp->knconf,
	    objp->knconf_len, (xdrproc_t)xdr_knetconfig))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_knetconfig(XDR *xdrs, struct knetconfig *objp)
{
	rpc_inline_t *buf;
	u_longlong_t dev64;
#if !defined(_LP64)
	uint32_t major, minor;
#endif
	int i;

	if (!xdr_u_int(xdrs, &objp->knc_semantics))
		return (FALSE);
	if (xdrs->x_op == XDR_DECODE) {
		objp->knc_protofmly = (((char *)objp) +
		    sizeof (struct knetconfig));
		objp->knc_proto = objp->knc_protofmly + KNC_STRSIZE;
	}
	if (!xdr_opaque(xdrs, objp->knc_protofmly, KNC_STRSIZE))
		return (FALSE);
	if (!xdr_opaque(xdrs, objp->knc_proto, KNC_STRSIZE))
		return (FALSE);

	/*
	 * For interoperability between 32-bit daemon and 64-bit kernel,
	 * we always treat dev_t as 64-bit number and do the expanding
	 * or compression of dev_t as needed.
	 * We have to hand craft the conversion since there is no available
	 * function in ddi.c. Besides ddi.c is available only in the kernel
	 * and we want to keep both user and kernel of xdr_knetconfig() the
	 * same for consistency.
	 */
	if (xdrs->x_op == XDR_ENCODE) {
#if defined(_LP64)
		dev64 = objp->knc_rdev;
#else
		major = (objp->knc_rdev >> NBITSMINOR32) & MAXMAJ32;
		minor = objp->knc_rdev & MAXMIN32;
		dev64 = (((unsigned long long)major) << NBITSMINOR64) | minor;
#endif
		if (!xdr_u_longlong_t(xdrs, &dev64))
			return (FALSE);
	}
	if (xdrs->x_op == XDR_DECODE) {
#if defined(_LP64)
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->knc_rdev))
			return (FALSE);
#else
		if (!xdr_u_longlong_t(xdrs, &dev64))
			return (FALSE);

		major = (dev64 >> NBITSMINOR64) & L_MAXMAJ32;
		minor = dev64 & L_MAXMIN32;
		objp->knc_rdev = (major << L_BITSMINOR32) | minor;
#endif
	}

	if (xdrs->x_op == XDR_ENCODE) {
		buf = XDR_INLINE(xdrs, (8) * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_vector(xdrs, (char *)objp->knc_unused, 8,
			    sizeof (uint_t), (xdrproc_t)xdr_u_int))
				return (FALSE);
		} else {
			uint_t *genp;

			for (i = 0, genp = objp->knc_unused;
			    i < 8; i++) {
#if defined(_LP64) || defined(_KERNEL)
				IXDR_PUT_U_INT32(buf, *genp++);
#else
				IXDR_PUT_U_LONG(buf, *genp++);
#endif
			}
		}
		return (TRUE);
	} else if (xdrs->x_op == XDR_DECODE) {
		buf = XDR_INLINE(xdrs, (8) * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_vector(xdrs, (char *)objp->knc_unused, 8,
			    sizeof (uint_t), (xdrproc_t)xdr_u_int))
				return (FALSE);
		} else {
			uint_t *genp;

			for (i = 0, genp = objp->knc_unused;
			    i < 8; i++) {
#if defined(_LP64) || defined(_KERNEL)
					*genp++ = IXDR_GET_U_INT32(buf);
#else
					*genp++ = IXDR_GET_U_LONG(buf);
#endif
			}
		}
		return (TRUE);
	}

	if (!xdr_vector(xdrs, (char *)objp->knc_unused, 8,
	    sizeof (uint_t), (xdrproc_t)xdr_u_int))
		return (FALSE);
	return (TRUE);
}

/*
 * XDR_INLINE decode a filehandle.
 */
bool_t
xdr_inline_decode_nfs_fh4(uint32_t *ptr, nfs_fh4_fmt_t *fhp, uint32_t fhsize)
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
	if (fhsize > sizeof (nfs_fh4_fmt_t) || fhsize < (sizeof (fsid_t) +
	    sizeof (ushort_t) + NFS_FHMAXDATA +
	    sizeof (ushort_t) + NFS_FHMAXDATA)) {
		return (FALSE);
	}

	/*
	 * All internal parts of a filehandle are in native byte order.
	 *
	 * Decode what should be fh4_fsid, it is aligned.
	 */
	fhp->fh4_fsid.val[0] = *(uint32_t *)bp;
	bp += BYTES_PER_XDR_UNIT;
	fhp->fh4_fsid.val[1] = *(uint32_t *)bp;
	bp += BYTES_PER_XDR_UNIT;

	/*
	 * Decode what should be fh4_len.  fh4_len is two bytes, so we're
	 * unaligned now.
	 */
	cp = (uchar_t *)&fhp->fh4_len;
	*cp++ = *bp++;
	*cp++ = *bp++;
	fhsize -= 2 * BYTES_PER_XDR_UNIT + sizeof (ushort_t);

	/*
	 * For backwards compatibility, the fid length may be less than
	 * NFS_FHMAXDATA, but it was always encoded as NFS_FHMAXDATA bytes.
	 */
	dsize = fhp->fh4_len < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh4_len;

	/*
	 * Make sure the client isn't sending us a bogus length for fh4_data.
	 */
	if (fhsize < dsize)
		return (FALSE);
	bcopy(bp, fhp->fh4_data, dsize);
	bp += dsize;
	fhsize -= dsize;

	if (fhsize < sizeof (ushort_t))
		return (FALSE);
	cp = (uchar_t *)&fhp->fh4_xlen;
	*cp++ = *bp++;
	*cp++ = *bp++;
	fhsize -= sizeof (ushort_t);

	dsize = fhp->fh4_xlen < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh4_xlen;

	/*
	 * Make sure the client isn't sending us a bogus length for fh4_xdata.
	 */
	if (fhsize < dsize)
		return (FALSE);
	bcopy(bp, fhp->fh4_xdata, dsize);
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

	if (fhsize < BYTES_PER_XDR_UNIT)
		return (FALSE);
	fhp->fh4_flag = *(uint32_t *)bp;
	bp += BYTES_PER_XDR_UNIT;
	fhsize -= BYTES_PER_XDR_UNIT;

#ifdef VOLATILE_FH_TEST
	if (fhsize < BYTES_PER_XDR_UNIT)
		return (FALSE);
	fhp->fh4_volatile_id = *(uint32_t *)bp;
	bp += BYTES_PER_XDR_UNIT;
	fhsize -= BYTES_PER_XDR_UNIT;
#endif
	/*
	 * Make sure client didn't send extra bytes
	 */
	if (fhsize != 0)
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_decode_nfs_fh4(XDR *xdrs, nfs_fh4 *objp)
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

	objp->nfs_fh4_val = NULL;
	objp->nfs_fh4_len = 0;

	/*
	 * Check to see if what the client sent us is bigger or smaller
	 * than what we can ever possibly send out. NFS_FHMAXDATA is
	 * unfortunately badly named as it is no longer the max and is
	 * really the min of what is sent over the wire.
	 */
	if (fhsize > sizeof (nfs_fh4_fmt_t) || fhsize < (sizeof (fsid_t) +
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

	objp->nfs_fh4_val = kmem_zalloc(sizeof (nfs_fh4_fmt_t), KM_SLEEP);
	objp->nfs_fh4_len = sizeof (nfs_fh4_fmt_t);

	if (xdr_inline_decode_nfs_fh4((uint32_t *)bp,
	    (nfs_fh4_fmt_t *)objp->nfs_fh4_val, fhsize) == FALSE) {
		/*
		 * If in the process of decoding we find the file handle
		 * is not correctly formed, we need to continue decoding
		 * and trigger an NFS layer error. Set the nfs_fh4_len to
		 * zero so it gets caught as a bad length.
		 */
		kmem_free(objp->nfs_fh4_val, objp->nfs_fh4_len);
		objp->nfs_fh4_val = NULL;
		objp->nfs_fh4_len = 0;
	}

	if (ptr == NULL)
		kmem_free(bp, bufsize);
	return (TRUE);
}

/*
 * XDR_INLINE encode a filehandle.
 */
bool_t
xdr_inline_encode_nfs_fh4(uint32_t **ptrp, uint32_t *ptr_redzone,
	nfs_fh4_fmt_t *fhp)
{
	uint32_t *ptr = *ptrp;
	uchar_t *cp;
	uint_t otw_len, fsize, xsize;   /* otw, file, and export sizes */
	uint32_t padword;

	fsize = fhp->fh4_len < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh4_len;
	xsize = fhp->fh4_xlen < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh4_xlen;

	/*
	 * First get the initial and variable sized part of the filehandle.
	 */
	otw_len = sizeof (fhp->fh4_fsid) +
	    sizeof (fhp->fh4_len) + fsize +
	    sizeof (fhp->fh4_xlen) + xsize;

	/*
	 * Round out to a full word.
	 */
	otw_len = RNDUP(otw_len);
	padword = (otw_len / BYTES_PER_XDR_UNIT);	/* includes fhlen */

	/*
	 * Add in the fixed sized pieces.
	 */
	otw_len += sizeof (fhp->fh4_flag);
#ifdef VOLATILE_FH_TEST
	otw_len += sizeof (fhp->fh4_volatile_id);
#endif

	/*
	 * Make sure we don't exceed our buffer.
	 */
	if ((ptr + (otw_len / BYTES_PER_XDR_UNIT) + 1) > ptr_redzone)
		return (FALSE);

	/*
	 * Zero out the padding.
	 */
	ptr[padword] = 0;

	IXDR_PUT_U_INT32(ptr, otw_len);

	/*
	 * The rest of the filehandle is in native byteorder
	 */
	/* fh4_fsid */
	*ptr++ = (uint32_t)fhp->fh4_fsid.val[0];
	*ptr++ = (uint32_t)fhp->fh4_fsid.val[1];

	/*
	 * Since the next pieces are unaligned, we need to
	 * do bytewise copies.
	 */
	cp = (uchar_t *)ptr;

	/* fh4_len + fh4_data */
	bcopy(&fhp->fh4_len, cp, sizeof (fhp->fh4_len) + fsize);
	cp += sizeof (fhp->fh4_len) + fsize;

	/* fh4_xlen + fh4_xdata */
	bcopy(&fhp->fh4_xlen, cp, sizeof (fhp->fh4_xlen) + xsize);
	cp += sizeof (fhp->fh4_xlen) + xsize;

	/* do necessary rounding/padding */
	cp = (uchar_t *)RNDUP((uintptr_t)cp);
	ptr = (uint32_t *)cp;

	/*
	 * With the above padding, we're word aligned again.
	 */
	ASSERT(((uintptr_t)ptr % BYTES_PER_XDR_UNIT) == 0);

	/* fh4_flag */
	*ptr++ = (uint32_t)fhp->fh4_flag;

#ifdef VOLATILE_FH_TEST
	/* fh4_volatile_id */
	*ptr++ = (uint32_t)fhp->fh4_volatile_id;
#endif
	*ptrp = ptr;

	return (TRUE);
}

static bool_t
xdr_encode_nfs_fh4(XDR *xdrs, nfs_fh4 *objp)
{
	uint_t otw_len, fsize, xsize;   /* otw, file, and export sizes */
	bool_t ret;
	rpc_inline_t *ptr;
	rpc_inline_t *buf = NULL;
	uint32_t *ptr_redzone;
	nfs_fh4_fmt_t *fhp;

	ASSERT(xdrs->x_op == XDR_ENCODE);

	fhp = (nfs_fh4_fmt_t *)objp->nfs_fh4_val;
	fsize = fhp->fh4_len < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh4_len;
	xsize = fhp->fh4_xlen < NFS_FHMAXDATA ? NFS_FHMAXDATA : fhp->fh4_xlen;

	/*
	 * First get the over the wire size, it is the 4 bytes
	 * for the length, plus the combined size of the
	 * file handle components.
	 */
	otw_len = BYTES_PER_XDR_UNIT + sizeof (fhp->fh4_fsid) +
	    sizeof (fhp->fh4_len) + fsize +
	    sizeof (fhp->fh4_xlen) + xsize +
	    sizeof (fhp->fh4_flag);
#ifdef VOLATILE_FH_TEST
	otw_len += sizeof (fhp->fh4_volatile_id);
#endif
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
	ret = xdr_inline_encode_nfs_fh4((uint32_t **)&ptr, ptr_redzone, fhp);

	if (buf != NULL) {
		if (ret == TRUE)
			ret = xdr_opaque(xdrs, (char *)buf, otw_len);
		kmem_free(buf, otw_len);
	}
	return (ret);
}

/*
 * XDR a NFSv4 filehandle.
 * Encoding interprets the contents (server).
 * Decoding the contents are opaque (client).
 */
bool_t
xdr_nfs_fh4(XDR *xdrs, nfs_fh4 *objp)
{
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		return (xdr_encode_nfs_fh4(xdrs, objp));
	case XDR_DECODE:
		return (xdr_bytes(xdrs, (char **)&objp->nfs_fh4_val,
		    (uint_t *)&objp->nfs_fh4_len, NFS4_FHSIZE));
	case XDR_FREE:
		if (objp->nfs_fh4_val != NULL) {
			kmem_free(objp->nfs_fh4_val, objp->nfs_fh4_len);
			objp->nfs_fh4_val = NULL;
		}
		return (TRUE);
	}
	return (FALSE);
}

/* Called by xdr_array */
static bool_t
xdr_fs_location4(XDR *xdrs, fs_location4 *objp)
{
	if (xdrs->x_op == XDR_DECODE) {
		objp->server_val = NULL;
		objp->rootpath.pathname4_val = NULL;
	}
	if (!xdr_array(xdrs, (char **)&objp->server_val,
	    (uint_t *)&objp->server_len, NFS4_MAX_UTF8STRING,
	    sizeof (utf8string), (xdrproc_t)xdr_utf8string))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->rootpath.pathname4_val,
	    (uint_t *)&objp->rootpath.pathname4_len,
	    NFS4_MAX_PATHNAME4,
	    sizeof (utf8string), (xdrproc_t)xdr_utf8string));
}

/* Called by xdr_array */
static bool_t
xdr_nfsace4(XDR *xdrs, nfsace4 *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_u_int(xdrs, &objp->type))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->flag))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->access_mask))
			return (FALSE);

		if (xdrs->x_op == XDR_DECODE) {
			objp->who.utf8string_val = NULL;
			objp->who.utf8string_len = 0;
		}

		return (xdr_bytes(xdrs, (char **)&objp->who.utf8string_val,
		    (uint_t *)&objp->who.utf8string_len,
		    NFS4_MAX_UTF8STRING));
	}

	/*
	 * Optimized free case
	 */
	if (objp->who.utf8string_val != NULL) {
		kmem_free(objp->who.utf8string_val, objp->who.utf8string_len);
		objp->who.utf8string_val = NULL;
	}
	return (TRUE);
}

/*
 * These functions are called out of nfs4_attr.c
 */
bool_t
xdr_fattr4_fsid(XDR *xdrs, fattr4_fsid *objp)
{
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->major))
		return (FALSE);
	return (xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->minor));
}


bool_t
xdr_fattr4_acl(XDR *xdrs, fattr4_acl *objp)
{
	return (xdr_array(xdrs, (char **)&objp->fattr4_acl_val,
	    (uint_t *)&objp->fattr4_acl_len, NFS4_ACL_LIMIT,
	    sizeof (nfsace4), (xdrproc_t)xdr_nfsace4));
}

bool_t
xdr_fattr4_fs_locations(XDR *xdrs, fattr4_fs_locations *objp)
{
	if (xdrs->x_op == XDR_DECODE) {
		objp->fs_root.pathname4_len = 0;
		objp->fs_root.pathname4_val = NULL;
		objp->locations_val = NULL;
	}
	if (!xdr_array(xdrs, (char **)&objp->fs_root.pathname4_val,
	    (uint_t *)&objp->fs_root.pathname4_len,
	    NFS4_MAX_PATHNAME4,
	    sizeof (utf8string), (xdrproc_t)xdr_utf8string))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->locations_val,
	    (uint_t *)&objp->locations_len, NFS4_FS_LOCATIONS_LIMIT,
	    sizeof (fs_location4), (xdrproc_t)xdr_fs_location4));
}

bool_t
xdr_fattr4_rawdev(XDR *xdrs, fattr4_rawdev *objp)
{
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (!xdr_u_int(xdrs, &objp->specdata1))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->specdata2));
}

bool_t
xdr_nfstime4(XDR *xdrs, nfstime4 *objp)
{
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (!xdr_longlong_t(xdrs, (longlong_t *)&objp->seconds))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->nseconds));
}


/*
 * structured used for calls into xdr_ga_fattr_res() as a means
 * to do an immediate/short-term cache of owner/group strings
 * for callers like the readdir processing.  In the case of readdir,
 * it is likely that the directory objects will be owned by the same
 * owner/group and if so there is no need to call into the uid/gid
 * mapping code.  While the uid/gid interfaces have their own cache
 * having one here will reduct pathlength further.
 */
#define	MAX_OG_NAME 100
typedef struct ug_cache
{
	uid_t	uid;
	gid_t	gid;
	utf8string u_curr, u_last;
	utf8string g_curr, g_last;
	char	u_buf1[MAX_OG_NAME];
	char	u_buf2[MAX_OG_NAME];
	char	g_buf1[MAX_OG_NAME];
	char	g_buf2[MAX_OG_NAME];
} ug_cache_t;

#define	U_SWAP_CURR_LAST(ug) \
	(ug)->u_last.utf8string_len = (ug)->u_curr.utf8string_len;	\
	if ((ug)->u_last.utf8string_val == (ug)->u_buf1) {		\
		(ug)->u_last.utf8string_val = (ug)->u_buf2;		\
		(ug)->u_curr.utf8string_val = (ug)->u_buf1;		\
	} else {							\
		(ug)->u_last.utf8string_val = (ug)->u_buf1;		\
		(ug)->u_curr.utf8string_val = (ug)->u_buf2;		\
	}

#define	G_SWAP_CURR_LAST(ug) \
	(ug)->g_last.utf8string_len = (ug)->g_curr.utf8string_len;	\
	if ((ug)->g_last.utf8string_val == (ug)->g_buf1) {		\
		(ug)->g_last.utf8string_val = (ug)->g_buf2;		\
		(ug)->g_curr.utf8string_val = (ug)->g_buf1;		\
	} else {							\
		(ug)->g_last.utf8string_val = (ug)->g_buf1;		\
		(ug)->g_curr.utf8string_val = (ug)->g_buf2;		\
	}

static ug_cache_t *
alloc_ugcache()
{
	ug_cache_t *pug = kmem_alloc(sizeof (ug_cache_t), KM_SLEEP);

	pug->uid = pug->gid = 0;
	pug->u_curr.utf8string_len = 0;
	pug->u_last.utf8string_len = 0;
	pug->g_curr.utf8string_len = 0;
	pug->g_last.utf8string_len = 0;
	pug->u_curr.utf8string_val = pug->u_buf1;
	pug->u_last.utf8string_val = pug->u_buf2;
	pug->g_curr.utf8string_val = pug->g_buf1;
	pug->g_last.utf8string_val = pug->g_buf2;

	return (pug);
}

static void
xdr_ga_prefill_vattr(struct nfs4_ga_res *garp, struct mntinfo4 *mi)
{
	static vattr_t s_vattr = {
		AT_ALL,		/* va_mask */
		VNON,		/* va_type */
		0777,		/* va_mode */
		UID_NOBODY,	/* va_uid */
		GID_NOBODY,	/* va_gid */
		0,		/* va_fsid */
		0,		/* va_nodeid */
		1,		/* va_nlink */
		0,		/* va_size */
		{0, 0},		/* va_atime */
		{0, 0},		/* va_mtime */
		{0, 0},		/* va_ctime */
		0,		/* va_rdev */
		MAXBSIZE,	/* va_blksize */
		0,		/* va_nblocks */
		0		/* va_seq */
	};


	garp->n4g_va = s_vattr;
	garp->n4g_va.va_fsid = mi->mi_vfsp->vfs_dev;
	hrt2ts(gethrtime(), &garp->n4g_va.va_atime);
	garp->n4g_va.va_mtime = garp->n4g_va.va_ctime = garp->n4g_va.va_atime;
}

static void
xdr_ga_prefill_statvfs(struct nfs4_ga_ext_res *gesp, struct mntinfo4 *mi)
{
	static statvfs64_t s_sb = {
		MAXBSIZE,	/* f_bsize */
		DEV_BSIZE,	/* f_frsize */
		(fsfilcnt64_t)-1, /* f_blocks */
		(fsfilcnt64_t)-1, /* f_bfree */
		(fsfilcnt64_t)-1, /* f_bavail */
		(fsfilcnt64_t)-1, /* f_files */
		(fsfilcnt64_t)-1, /* f_ffree */
		(fsfilcnt64_t)-1, /* f_favail */
		0,		/* f_fsid */
		"\0",		/* f_basetype */
		0,		/* f_flag */
		MAXNAMELEN,	/* f_namemax */
		"\0",		/* f_fstr */
	};

	gesp->n4g_sb = s_sb;
	gesp->n4g_sb.f_fsid = mi->mi_vfsp->vfs_fsid.val[0];
}

static bool_t
xdr_ga_fattr_res(XDR *xdrs, struct nfs4_ga_res *garp, bitmap4 resbmap,
		bitmap4 argbmap, struct mntinfo4 *mi, ug_cache_t *pug)
{
	int truefalse;
	struct nfs4_ga_ext_res ges, *gesp;
	vattr_t *vap = &garp->n4g_va;
	vsecattr_t *vsap = &garp->n4g_vsa;

	ASSERT(xdrs->x_op == XDR_DECODE);

	if (garp->n4g_ext_res)
		gesp = garp->n4g_ext_res;
	else
		gesp = &ges;

	vap->va_mask = 0;

	/* Check to see if the vattr should be pre-filled */
	if (argbmap & NFS4_VATTR_MASK)
		xdr_ga_prefill_vattr(garp, mi);

	if (argbmap & NFS4_STATFS_ATTR_MASK)
		xdr_ga_prefill_statvfs(gesp, mi);

	if (resbmap &
	    (FATTR4_SUPPORTED_ATTRS_MASK |
	    FATTR4_TYPE_MASK |
	    FATTR4_FH_EXPIRE_TYPE_MASK |
	    FATTR4_CHANGE_MASK |
	    FATTR4_SIZE_MASK |
	    FATTR4_LINK_SUPPORT_MASK |
	    FATTR4_SYMLINK_SUPPORT_MASK |
	    FATTR4_NAMED_ATTR_MASK)) {

		if (resbmap & FATTR4_SUPPORTED_ATTRS_MASK) {
			if (!xdr_bitmap4(xdrs, &gesp->n4g_suppattrs))
				return (FALSE);
		}
		if (resbmap & FATTR4_TYPE_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&vap->va_type))
				return (FALSE);

			if ((nfs_ftype4)vap->va_type < NF4REG ||
			    (nfs_ftype4)vap->va_type > NF4NAMEDATTR)
				vap->va_type = VBAD;
			else
				vap->va_type = nf4_to_vt[vap->va_type];
			if (vap->va_type == VBLK)
				vap->va_blksize = DEV_BSIZE;

			vap->va_mask |= AT_TYPE;
		}
		if (resbmap & FATTR4_FH_EXPIRE_TYPE_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&gesp->n4g_fet))
				return (FALSE);
		}
		if (resbmap & FATTR4_CHANGE_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&garp->n4g_change))
				return (FALSE);
			garp->n4g_change_valid = 1;
		}
		if (resbmap & FATTR4_SIZE_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&vap->va_size))
				return (FALSE);
			if (!NFS4_SIZE_OK(vap->va_size)) {
				garp->n4g_attrerr = EFBIG;
				garp->n4g_attrwhy = NFS4_GETATTR_ATSIZE_ERR;
			} else {
				vap->va_mask |= AT_SIZE;
			}
		}
		if (resbmap & FATTR4_LINK_SUPPORT_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_link_support =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_SYMLINK_SUPPORT_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_symlink_support =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_NAMED_ATTR_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_xattr_exists = TRUE;
			gesp->n4g_pc4.pc4_xattr_exists =
			    (truefalse ? TRUE : FALSE);
		}
	}
	if (resbmap &
	    (FATTR4_FSID_MASK |
	    FATTR4_UNIQUE_HANDLES_MASK |
	    FATTR4_LEASE_TIME_MASK |
	    FATTR4_RDATTR_ERROR_MASK)) {

		if (resbmap & FATTR4_FSID_MASK) {
			if ((!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&garp->n4g_fsid.major)) ||
			    (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&garp->n4g_fsid.minor)))
				return (FALSE);
			garp->n4g_fsid_valid = 1;
		}
		if (resbmap & FATTR4_UNIQUE_HANDLES_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_unique_handles =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_LEASE_TIME_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&gesp->n4g_leasetime))
				return (FALSE);
		}
		if (resbmap & FATTR4_RDATTR_ERROR_MASK) {
			if (!XDR_GETINT32(xdrs,
			    (int *)&gesp->n4g_rdattr_error))
				return (FALSE);
		}
	}
	if (resbmap &
	    (FATTR4_ACL_MASK |
	    FATTR4_ACLSUPPORT_MASK |
	    FATTR4_ARCHIVE_MASK |
	    FATTR4_CANSETTIME_MASK)) {

		if (resbmap & FATTR4_ACL_MASK) {
			fattr4_acl	acl;

			acl.fattr4_acl_val = NULL;
			acl.fattr4_acl_len = 0;

			if (!xdr_fattr4_acl(xdrs, &acl))
				return (FALSE);

			vsap->vsa_aclcnt = acl.fattr4_acl_len;
			vsap->vsa_aclentp = acl.fattr4_acl_val;
			vsap->vsa_mask = VSA_ACE | VSA_ACECNT;
			vsap->vsa_aclentsz = vsap->vsa_aclcnt * sizeof (ace_t);

		}
		if (resbmap & FATTR4_ACLSUPPORT_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&gesp->n4g_aclsupport))
				return (FALSE);
		}
		if (resbmap & FATTR4_ARCHIVE_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_CANSETTIME_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_cansettime =
			    (truefalse ? TRUE : FALSE);
		}
	}
	if (resbmap &
	    (FATTR4_CASE_INSENSITIVE_MASK |
	    FATTR4_CASE_PRESERVING_MASK |
	    FATTR4_CHOWN_RESTRICTED_MASK |
	    FATTR4_FILEHANDLE_MASK |
	    FATTR4_FILEID_MASK |
	    FATTR4_FILES_AVAIL_MASK |
	    FATTR4_FILES_FREE_MASK |
	    FATTR4_FILES_TOTAL_MASK)) {

		if (resbmap & FATTR4_CASE_INSENSITIVE_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_case_insensitive =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_CASE_PRESERVING_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_case_preserving =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_CHOWN_RESTRICTED_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_chown_restricted =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_FILEHANDLE_MASK) {
			gesp->n4g_fh_u.nfs_fh4_alt.len = 0;
			gesp->n4g_fh_u.nfs_fh4_alt.val =
			    gesp->n4g_fh_u.nfs_fh4_alt.data;
			if (!xdr_bytes(xdrs,
			    (char **)&gesp->n4g_fh_u.n4g_fh.nfs_fh4_val,
			    (uint_t *)&gesp->n4g_fh_u.n4g_fh.nfs_fh4_len,
			    NFS4_FHSIZE))
				return (FALSE);
		}
		if (resbmap & FATTR4_FILEID_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&vap->va_nodeid))
				return (FALSE);
			vap->va_mask |= AT_NODEID;
		}
		if (resbmap & FATTR4_FILES_AVAIL_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_sb.f_favail))
				return (FALSE);
		}
		if (resbmap & FATTR4_FILES_FREE_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_sb.f_ffree))
				return (FALSE);
		}
		if (resbmap & FATTR4_FILES_TOTAL_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_sb.f_files))
				return (FALSE);
		}
	}
	if (resbmap &
	    (FATTR4_FS_LOCATIONS_MASK |
	    FATTR4_HIDDEN_MASK |
	    FATTR4_HOMOGENEOUS_MASK)) {

		if (resbmap & FATTR4_FS_LOCATIONS_MASK) {
			if (!xdr_fattr4_fs_locations(xdrs,
			    &gesp->n4g_fslocations))
				return (FALSE);
		}
		if (resbmap & FATTR4_HIDDEN_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_HOMOGENEOUS_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_homogeneous =
			    (truefalse ? TRUE : FALSE);
		}
	}
	if (resbmap &
	    (FATTR4_MAXFILESIZE_MASK |
	    FATTR4_MAXLINK_MASK |
	    FATTR4_MAXNAME_MASK |
	    FATTR4_MAXREAD_MASK |
	    FATTR4_MAXWRITE_MASK)) {

		if (resbmap & FATTR4_MAXFILESIZE_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_maxfilesize))
				return (FALSE);
		}
		if (resbmap & FATTR4_MAXLINK_MASK) {
			if (!XDR_GETINT32(xdrs,
			    (int *)&gesp->n4g_pc4.pc4_link_max))
				return (FALSE);
		}
		if (resbmap & FATTR4_MAXNAME_MASK) {
			if (!XDR_GETINT32(xdrs,
			    (int *)&gesp->n4g_pc4.pc4_name_max))
				return (FALSE);
			gesp->n4g_sb.f_namemax = gesp->n4g_pc4.pc4_name_max;
		}
		if (resbmap & FATTR4_MAXREAD_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_maxread))
				return (FALSE);
		}
		if (resbmap & FATTR4_MAXWRITE_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_maxwrite))
				return (FALSE);
		}
	}
	if (resbmap &
	    (FATTR4_MIMETYPE_MASK |
	    FATTR4_MODE_MASK |
	    FATTR4_NO_TRUNC_MASK |
	    FATTR4_NUMLINKS_MASK)) {

		if (resbmap & FATTR4_MIMETYPE_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_MODE_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&vap->va_mode))
				return (FALSE);
			vap->va_mask |= AT_MODE;
		}
		if (resbmap & FATTR4_NO_TRUNC_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&truefalse))
				return (FALSE);
			gesp->n4g_pc4.pc4_no_trunc =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_NUMLINKS_MASK) {
			if (!XDR_GETINT32(xdrs, (int *)&vap->va_nlink))
				return (FALSE);
			vap->va_mask |= AT_NLINK;
		}
	}
	if (resbmap &
	    (FATTR4_OWNER_MASK |
	    FATTR4_OWNER_GROUP_MASK |
	    FATTR4_QUOTA_AVAIL_HARD_MASK |
	    FATTR4_QUOTA_AVAIL_SOFT_MASK)) {

		if (resbmap & FATTR4_OWNER_MASK) {
			uint_t *owner_length, ol;
			char *owner_val = NULL;
			char *owner_alloc = NULL;
			utf8string ov;
			int error;

			/* get the OWNER_LENGTH */
			if (!xdr_u_int(xdrs, &ol))
				return (FALSE);

			/* Manage the owner length location */
			if (pug && ol <= MAX_OG_NAME) {
				owner_length = &pug->u_curr.utf8string_len;
				*owner_length = ol;
			} else {
				owner_length = &ol;
			}

			/* find memory to store the decode */
			if (*owner_length > MAX_OG_NAME || pug == NULL)
				owner_val = owner_alloc =
				    kmem_alloc(*owner_length, KM_SLEEP);
			else
				owner_val = pug->u_curr.utf8string_val;

			/* get the OWNER string */
			if (!xdr_opaque(xdrs, owner_val, *owner_length)) {
				if (owner_alloc)
					kmem_free(owner_alloc, *owner_length);
				return (FALSE);
			}

			/* Optimize for matching if called for */
			if (pug &&
			    *owner_length == pug->u_last.utf8string_len &&
			    bcmp(owner_val, pug->u_last.utf8string_val,
			    *owner_length) == 0) {
				vap->va_uid = pug->uid;
				vap->va_mask |= AT_UID;
			} else {
				uid_t uid;

				ov.utf8string_len = *owner_length;
				ov.utf8string_val = owner_val;
				error = nfs_idmap_str_uid(&ov, &uid, FALSE);
				/*
				 * String was mapped, but to nobody because
				 * we are nfsmapid, indicate it should not
				 * be cached.
				 */
				if (error == ENOTSUP) {
					error = 0;
					garp->n4g_attrwhy =
					    NFS4_GETATTR_NOCACHE_OK;
				}

				if (error) {
					garp->n4g_attrerr = error;
					garp->n4g_attrwhy =
					    NFS4_GETATTR_ATUID_ERR;
				} else {
					vap->va_uid = uid;
					vap->va_mask |= AT_UID;
					if (pug && ol <= MAX_OG_NAME) {
						pug->uid = uid;
						U_SWAP_CURR_LAST(pug);
					}
				}
				if (owner_alloc)
					kmem_free(owner_alloc, *owner_length);
			}
		}
		if (resbmap & FATTR4_OWNER_GROUP_MASK) {
			uint_t *group_length, gl;
			char *group_val = NULL;
			char *group_alloc = NULL;
			utf8string gv;
			int error;

			/* get the OWNER_GROUP_LENGTH */
			if (!xdr_u_int(xdrs, &gl))
				return (FALSE);

			/* Manage the group length location */
			if (pug && gl <= MAX_OG_NAME) {
				group_length = &pug->g_curr.utf8string_len;
				*group_length = gl;
			} else {
				group_length = &gl;
			}

			/* find memory to store the decode */
			if (*group_length > MAX_OG_NAME || pug == NULL)
				group_val = group_alloc =
				    kmem_alloc(*group_length, KM_SLEEP);
			else
				group_val = pug->g_curr.utf8string_val;

			/* get the OWNER_GROUP string */
			if (!xdr_opaque(xdrs, group_val, *group_length)) {
				if (group_alloc)
					kmem_free(group_alloc, *group_length);
				return (FALSE);
			}

			/* Optimize for matching if called for */
			if (pug &&
			    *group_length == pug->g_last.utf8string_len &&
			    bcmp(group_val, pug->g_last.utf8string_val,
			    *group_length) == 0) {
				vap->va_gid = pug->gid;
				vap->va_mask |= AT_GID;
			} else {
				uid_t gid;

				gv.utf8string_len = *group_length;
				gv.utf8string_val = group_val;
				error = nfs_idmap_str_gid(&gv, &gid, FALSE);
				/*
				 * String was mapped, but to nobody because
				 * we are nfsmapid, indicate it should not
				 * be cached.
				 */
				if (error == ENOTSUP) {
					error = 0;
					garp->n4g_attrwhy =
					    NFS4_GETATTR_NOCACHE_OK;
				}

				if (error) {
					garp->n4g_attrerr = error;
					garp->n4g_attrwhy =
					    NFS4_GETATTR_ATGID_ERR;
				} else {
					vap->va_gid = gid;
					vap->va_mask |= AT_GID;
					if (pug && gl <= MAX_OG_NAME) {
						pug->gid = gid;
						G_SWAP_CURR_LAST(pug);
					}
				}
				if (group_alloc) {
					kmem_free(group_alloc, *group_length);
				}
			}
		}
		if (resbmap & FATTR4_QUOTA_AVAIL_HARD_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_QUOTA_AVAIL_SOFT_MASK) {
			ASSERT(0);
		}
	}
	if (resbmap &
	    (FATTR4_QUOTA_USED_MASK |
	    FATTR4_SPACE_AVAIL_MASK |
	    FATTR4_SPACE_FREE_MASK |
	    FATTR4_SPACE_TOTAL_MASK |
	    FATTR4_SPACE_USED_MASK |
	    FATTR4_SYSTEM_MASK)) {

		if (resbmap & FATTR4_QUOTA_USED_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_RAWDEV_MASK) {
			fattr4_rawdev rawdev;
			if (!xdr_fattr4_rawdev(xdrs, &rawdev))
				return (FALSE);

			if (vap->va_type == VCHR || vap->va_type == VBLK) {
				vap->va_rdev = makedevice(rawdev.specdata1,
				    rawdev.specdata2);
			} else {
				vap->va_rdev = 0;
			}
			vap->va_mask |= AT_RDEV;
		}
		if (resbmap & FATTR4_SPACE_AVAIL_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_sb.f_bavail))
				return (FALSE);
			gesp->n4g_sb.f_bavail /= DEV_BSIZE;
		}
		if (resbmap & FATTR4_SPACE_FREE_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_sb.f_bfree))
				return (FALSE);
			gesp->n4g_sb.f_bfree /= DEV_BSIZE;
		}
		if (resbmap & FATTR4_SPACE_TOTAL_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_sb.f_blocks))
				return (FALSE);
			gesp->n4g_sb.f_blocks /= DEV_BSIZE;
		}
		if (resbmap & FATTR4_SPACE_USED_MASK) {
			uint64_t space_used;
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&space_used))
				return (FALSE);

			/* Compute space depending on device type */
			ASSERT((vap->va_mask & AT_TYPE));
			if (vap->va_type == VREG || vap->va_type == VDIR ||
			    vap->va_type == VLNK) {
				vap->va_nblocks = (u_longlong_t)
				    ((space_used + (offset4)DEV_BSIZE -
				    (offset4)1) / (offset4)DEV_BSIZE);
			} else {
				vap->va_nblocks = 0;
			}
			vap->va_mask |= AT_NBLOCKS;
		}
		if (resbmap & FATTR4_SYSTEM_MASK) {
			ASSERT(0);
		}
	}
	if (resbmap &
	    (FATTR4_TIME_ACCESS_MASK |
	    FATTR4_TIME_ACCESS_SET_MASK |
	    FATTR4_TIME_BACKUP_MASK |
	    FATTR4_TIME_CREATE_MASK |
	    FATTR4_TIME_DELTA_MASK |
	    FATTR4_TIME_METADATA_MASK |
	    FATTR4_TIME_MODIFY_MASK |
	    FATTR4_TIME_MODIFY_SET_MASK |
	    FATTR4_MOUNTED_ON_FILEID_MASK)) {

		if (resbmap & FATTR4_TIME_ACCESS_MASK) {
			nfstime4 atime;
			int error;

			if (!xdr_longlong_t(xdrs,
			    (longlong_t *)&atime.seconds))
				return (FALSE);
			if (!XDR_GETINT32(xdrs, (int *)&atime.nseconds))
				return (FALSE);
			error = nfs4_time_ntov(&atime, &vap->va_atime);
			if (error) {
				garp->n4g_attrerr = error;
				garp->n4g_attrwhy = NFS4_GETATTR_ATATIME_ERR;
			}
			vap->va_mask |= AT_ATIME;
		}
		if (resbmap & FATTR4_TIME_ACCESS_SET_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_TIME_BACKUP_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_TIME_CREATE_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_TIME_DELTA_MASK) {
			if ((!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&gesp->n4g_delta.seconds)) ||
			    (!xdr_u_int(xdrs, &gesp->n4g_delta.nseconds)))
				return (FALSE);
		}
		if (resbmap & FATTR4_TIME_METADATA_MASK) {
			nfstime4 mdt;
			int error;

			if (!xdr_longlong_t(xdrs, (longlong_t *)&mdt.seconds))
				return (FALSE);
			if (!XDR_GETINT32(xdrs, (int32_t *)&mdt.nseconds))
				return (FALSE);
			error = nfs4_time_ntov(&mdt, &vap->va_ctime);
			if (error) {
				garp->n4g_attrerr = error;
				garp->n4g_attrwhy = NFS4_GETATTR_ATCTIME_ERR;
			}
			vap->va_mask |= AT_CTIME;
		}
		if (resbmap & FATTR4_TIME_MODIFY_MASK) {
			nfstime4 mtime;
			int error;

			if (!xdr_longlong_t(xdrs,
			    (longlong_t *)&mtime.seconds))
				return (FALSE);
			if (!XDR_GETINT32(xdrs, (int32_t *)&mtime.nseconds))
				return (FALSE);
			error = nfs4_time_ntov(&mtime, &vap->va_mtime);
			if (error) {
				garp->n4g_attrerr = error;
				garp->n4g_attrwhy = NFS4_GETATTR_ATMTIME_ERR;
			}
			vap->va_mask |= AT_MTIME;
		}
		if (resbmap & FATTR4_TIME_MODIFY_SET_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_MOUNTED_ON_FILEID_MASK) {
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&garp->n4g_mon_fid))
				return (FALSE);
			garp->n4g_mon_fid_valid = 1;
		}
	}

	if (resbmap & ~(NFS4_VATTR_MASK | FATTR4_ACL_MASK)) {
		/* copy only if not provided */
		if (garp->n4g_ext_res == NULL) {
			garp->n4g_ext_res = kmem_alloc(sizeof (ges), KM_SLEEP);
			bcopy(&ges, garp->n4g_ext_res, sizeof (ges));
		}
	}

	return (TRUE);
}

/*
 * Inlined version of get_bitmap4 processing
 */
bitmap4
xdr_get_bitmap4_inline(uint32_t **iptr)
{
	uint32_t resbmaplen;
	bitmap4 bm;
	uint32_t *ptr = *iptr;

	/* bitmap LENGTH */
	resbmaplen = IXDR_GET_U_INT32(ptr);

	/* Inline the bitmap and attrlen for common case of two word map */
	if (resbmaplen == 2) {
		IXDR_GET_HYPER(ptr, bm);
		*iptr = ptr;
		return (bm);
	}

#if defined(_LITTLE_ENDIAN)
	bm = IXDR_GET_U_INT32(ptr);
	if (--resbmaplen == 0) {
		*iptr = ptr;
		return (bm);
	}
	*((uint32_t *)&bm) |= IXDR_GET_U_INT32(ptr);
	if (--resbmaplen == 0) {
		*iptr = ptr;
		return (bm);
	}
	ptr += resbmaplen;
	*iptr = ptr;
	return (bm);
#elif defined(_BIG_ENDIAN)
	*((uint32_t *)&bm) = IXDR_GET_U_INT32(ptr);
	if (--resbmaplen == 0) {
		*iptr = ptr;
		return (bm);
	}
	bm |= IXDR_GET_U_INT32(ptr);
	if (--resbmaplen == 0) {
		*iptr = ptr;
		return (bm);
	}
	ptr += resbmaplen;
	*iptr = ptr;
	return (bm);
#else
	ASSERT(0);
	ptr += resbmaplen;
	*iptr = ptr;
	return (0);
#endif
}

static bool_t
xdr_ga_fattr_res_inline(uint32_t *ptr, struct nfs4_ga_res *garp,
			bitmap4 resbmap, bitmap4 argbmap, struct mntinfo4 *mi,
			ug_cache_t *pug)
{
	int truefalse;
	struct nfs4_ga_ext_res ges, *gesp;
	vattr_t *vap = &garp->n4g_va;

	if (garp->n4g_ext_res)
		gesp = garp->n4g_ext_res;
	else
		gesp = &ges;

	vap->va_mask = 0;

	/* Check to see if the vattr should be pre-filled */
	if (argbmap & NFS4_VATTR_MASK)
		xdr_ga_prefill_vattr(garp, mi);

	if (argbmap & NFS4_STATFS_ATTR_MASK)
		xdr_ga_prefill_statvfs(gesp, mi);

	if (resbmap &
	    (FATTR4_SUPPORTED_ATTRS_MASK |
	    FATTR4_TYPE_MASK |
	    FATTR4_FH_EXPIRE_TYPE_MASK |
	    FATTR4_CHANGE_MASK |
	    FATTR4_SIZE_MASK |
	    FATTR4_LINK_SUPPORT_MASK |
	    FATTR4_SYMLINK_SUPPORT_MASK |
	    FATTR4_NAMED_ATTR_MASK)) {

		if (resbmap & FATTR4_SUPPORTED_ATTRS_MASK) {
			gesp->n4g_suppattrs = xdr_get_bitmap4_inline(&ptr);
		}
		if (resbmap & FATTR4_TYPE_MASK) {
			vap->va_type = IXDR_GET_U_INT32(ptr);

			if ((nfs_ftype4)vap->va_type < NF4REG ||
			    (nfs_ftype4)vap->va_type > NF4NAMEDATTR)
				vap->va_type = VBAD;
			else
				vap->va_type = nf4_to_vt[vap->va_type];
			if (vap->va_type == VBLK)
				vap->va_blksize = DEV_BSIZE;

			vap->va_mask |= AT_TYPE;
		}
		if (resbmap & FATTR4_FH_EXPIRE_TYPE_MASK) {
			gesp->n4g_fet = IXDR_GET_U_INT32(ptr);
		}
		if (resbmap & FATTR4_CHANGE_MASK) {
			IXDR_GET_U_HYPER(ptr, garp->n4g_change);
			garp->n4g_change_valid = 1;
		}
		if (resbmap & FATTR4_SIZE_MASK) {
			IXDR_GET_U_HYPER(ptr, vap->va_size);

			if (!NFS4_SIZE_OK(vap->va_size)) {
				garp->n4g_attrerr = EFBIG;
				garp->n4g_attrwhy = NFS4_GETATTR_ATSIZE_ERR;
			} else {
				vap->va_mask |= AT_SIZE;
			}
		}
		if (resbmap & FATTR4_LINK_SUPPORT_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_link_support =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_SYMLINK_SUPPORT_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_symlink_support =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_NAMED_ATTR_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_xattr_exists = TRUE;
			gesp->n4g_pc4.pc4_xattr_exists =
			    (truefalse ? TRUE : FALSE);
		}
	}
	if (resbmap &
	    (FATTR4_FSID_MASK |
	    FATTR4_UNIQUE_HANDLES_MASK |
	    FATTR4_LEASE_TIME_MASK |
	    FATTR4_RDATTR_ERROR_MASK)) {

		if (resbmap & FATTR4_FSID_MASK) {
			IXDR_GET_U_HYPER(ptr, garp->n4g_fsid.major);
			IXDR_GET_U_HYPER(ptr, garp->n4g_fsid.minor);
			garp->n4g_fsid_valid = 1;
		}
		if (resbmap & FATTR4_UNIQUE_HANDLES_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_unique_handles =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_LEASE_TIME_MASK) {
			gesp->n4g_leasetime = IXDR_GET_U_INT32(ptr);
		}
		if (resbmap & FATTR4_RDATTR_ERROR_MASK) {
			gesp->n4g_rdattr_error = IXDR_GET_U_INT32(ptr);
		}
	}
	if (resbmap &
	    (FATTR4_ACL_MASK |
	    FATTR4_ACLSUPPORT_MASK |
	    FATTR4_ARCHIVE_MASK |
	    FATTR4_CANSETTIME_MASK)) {

		if (resbmap & FATTR4_ACL_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_ACLSUPPORT_MASK) {
			gesp->n4g_aclsupport = IXDR_GET_U_INT32(ptr);
		}
		if (resbmap & FATTR4_ARCHIVE_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_CANSETTIME_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_cansettime =
			    (truefalse ? TRUE : FALSE);
		}
	}
	if (resbmap &
	    (FATTR4_CASE_INSENSITIVE_MASK |
	    FATTR4_CASE_PRESERVING_MASK |
	    FATTR4_CHOWN_RESTRICTED_MASK |
	    FATTR4_FILEHANDLE_MASK |
	    FATTR4_FILEID_MASK |
	    FATTR4_FILES_AVAIL_MASK |
	    FATTR4_FILES_FREE_MASK |
	    FATTR4_FILES_TOTAL_MASK)) {

		if (resbmap & FATTR4_CASE_INSENSITIVE_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_case_insensitive =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_CASE_PRESERVING_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_case_preserving =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_CHOWN_RESTRICTED_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_chown_restricted =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_FILEHANDLE_MASK) {
			int len = IXDR_GET_U_INT32(ptr);

			gesp->n4g_fh_u.nfs_fh4_alt.len = 0;
			gesp->n4g_fh_u.nfs_fh4_alt.val =
			    gesp->n4g_fh_u.nfs_fh4_alt.data;
			gesp->n4g_fh_u.n4g_fh.nfs_fh4_len = len;

			bcopy(ptr, gesp->n4g_fh_u.n4g_fh.nfs_fh4_val, len);

			ptr += RNDUP(len) / BYTES_PER_XDR_UNIT;
		}
		if (resbmap & FATTR4_FILEID_MASK) {
			IXDR_GET_U_HYPER(ptr, vap->va_nodeid);
			vap->va_mask |= AT_NODEID;
		}
		if (resbmap & FATTR4_FILES_AVAIL_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_sb.f_favail);
		}
		if (resbmap & FATTR4_FILES_FREE_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_sb.f_ffree);
		}
		if (resbmap & FATTR4_FILES_TOTAL_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_sb.f_files);
		}
	}
	if (resbmap &
	    (FATTR4_FS_LOCATIONS_MASK |
	    FATTR4_HIDDEN_MASK |
	    FATTR4_HOMOGENEOUS_MASK)) {

		if (resbmap & FATTR4_FS_LOCATIONS_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_HIDDEN_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_HOMOGENEOUS_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_homogeneous =
			    (truefalse ? TRUE : FALSE);
		}
	}
	if (resbmap &
	    (FATTR4_MAXFILESIZE_MASK |
	    FATTR4_MAXLINK_MASK |
	    FATTR4_MAXNAME_MASK |
	    FATTR4_MAXREAD_MASK |
	    FATTR4_MAXWRITE_MASK)) {

		if (resbmap & FATTR4_MAXFILESIZE_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_maxfilesize);
		}
		if (resbmap & FATTR4_MAXLINK_MASK) {
			gesp->n4g_pc4.pc4_link_max = IXDR_GET_U_INT32(ptr);
		}
		if (resbmap & FATTR4_MAXNAME_MASK) {
			gesp->n4g_pc4.pc4_name_max = IXDR_GET_U_INT32(ptr);
			gesp->n4g_sb.f_namemax = gesp->n4g_pc4.pc4_name_max;
		}
		if (resbmap & FATTR4_MAXREAD_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_maxread);
		}
		if (resbmap & FATTR4_MAXWRITE_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_maxwrite);
		}
	}
	if (resbmap &
	    (FATTR4_MIMETYPE_MASK |
	    FATTR4_MODE_MASK |
	    FATTR4_NO_TRUNC_MASK |
	    FATTR4_NUMLINKS_MASK)) {

		if (resbmap & FATTR4_MIMETYPE_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_MODE_MASK) {
			vap->va_mode = IXDR_GET_U_INT32(ptr);
			vap->va_mask |= AT_MODE;
		}
		if (resbmap & FATTR4_NO_TRUNC_MASK) {
			truefalse = IXDR_GET_U_INT32(ptr);
			gesp->n4g_pc4.pc4_no_trunc =
			    (truefalse ? TRUE : FALSE);
		}
		if (resbmap & FATTR4_NUMLINKS_MASK) {
			vap->va_nlink = IXDR_GET_U_INT32(ptr);
			vap->va_mask |= AT_NLINK;
		}
	}
	if (resbmap &
	    (FATTR4_OWNER_MASK |
	    FATTR4_OWNER_GROUP_MASK |
	    FATTR4_QUOTA_AVAIL_HARD_MASK |
	    FATTR4_QUOTA_AVAIL_SOFT_MASK)) {

		if (resbmap & FATTR4_OWNER_MASK) {
			uint_t *owner_length, ol;
			char *owner_val = NULL;
			utf8string ov;
			int error;

			/* get the OWNER_LENGTH */
			ol = IXDR_GET_U_INT32(ptr);

			/* Manage the owner length location */
			if (pug && ol <= MAX_OG_NAME) {
				owner_length = &pug->u_curr.utf8string_len;
				*owner_length = ol;
			} else {
				owner_length = &ol;
			}

			/* find memory to store the decode */
			if (*owner_length > MAX_OG_NAME || pug == NULL)
				owner_val = (char *)ptr;
			else
				owner_val = (char *)ptr;

			/* Optimize for matching if called for */
			if (pug &&
			    *owner_length == pug->u_last.utf8string_len &&
			    bcmp(owner_val, pug->u_last.utf8string_val,
			    *owner_length) == 0) {
				vap->va_uid = pug->uid;
				vap->va_mask |= AT_UID;
			} else {
				uid_t uid;

				ov.utf8string_len = *owner_length;
				ov.utf8string_val = owner_val;
				error = nfs_idmap_str_uid(&ov, &uid, FALSE);
				/*
				 * String was mapped, but to nobody because
				 * we are nfsmapid, indicate it should not
				 * be cached.
				 */
				if (error == ENOTSUP) {
					error = 0;
					garp->n4g_attrwhy =
					    NFS4_GETATTR_NOCACHE_OK;
				}

				if (error) {
					garp->n4g_attrerr = error;
					garp->n4g_attrwhy =
					    NFS4_GETATTR_ATUID_ERR;
				} else {
					vap->va_uid = uid;
					vap->va_mask |= AT_UID;
					/* save the results for next time */
					if (pug && ol <= MAX_OG_NAME) {
						pug->uid = uid;
						pug->u_curr.utf8string_len =
						    ov.utf8string_len;
						bcopy(owner_val,
						    pug->u_curr.utf8string_val,
						    ol);
						U_SWAP_CURR_LAST(pug);
					}
				}
			}
			ptr += RNDUP(ol) / BYTES_PER_XDR_UNIT;
		}
		if (resbmap & FATTR4_OWNER_GROUP_MASK) {
			uint_t *group_length, gl;
			char *group_val = NULL;
			utf8string gv;
			int error;

			/* get the OWNER_GROUP_LENGTH */
			gl = IXDR_GET_U_INT32(ptr);

			/* Manage the group length location */
			if (pug && gl <= MAX_OG_NAME) {
				group_length = &pug->g_curr.utf8string_len;
				*group_length = gl;
			} else {
				group_length = &gl;
			}

			/* find memory to store the decode */
			if (*group_length > MAX_OG_NAME || pug == NULL)
				group_val = (char *)ptr;
			else
				group_val = (char *)ptr;

			/* Optimize for matching if called for */
			if (pug &&
			    *group_length == pug->g_last.utf8string_len &&
			    bcmp(group_val, pug->g_last.utf8string_val,
			    *group_length) == 0) {
				vap->va_gid = pug->gid;
				vap->va_mask |= AT_GID;
			} else {
				uid_t gid;

				gv.utf8string_len = *group_length;
				gv.utf8string_val = group_val;
				error = nfs_idmap_str_gid(&gv, &gid, FALSE);
				/*
				 * String was mapped, but to nobody because
				 * we are nfsmapid, indicate it should not
				 * be cached.
				 */
				if (error == ENOTSUP) {
					error = 0;
					garp->n4g_attrwhy =
					    NFS4_GETATTR_NOCACHE_OK;
				}

				if (error) {
					garp->n4g_attrerr = error;
					garp->n4g_attrwhy =
					    NFS4_GETATTR_ATGID_ERR;
				} else {
					vap->va_gid = gid;
					vap->va_mask |= AT_GID;
					if (pug && gl <= MAX_OG_NAME) {
						pug->gid = gid;
						pug->g_curr.utf8string_len =
						    gv.utf8string_len;
						bcopy(group_val,
						    pug->g_curr.utf8string_val,
						    gl);
						G_SWAP_CURR_LAST(pug);
					}
				}
			}
			ptr += RNDUP(gl) / BYTES_PER_XDR_UNIT;
		}
		if (resbmap & FATTR4_QUOTA_AVAIL_HARD_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_QUOTA_AVAIL_SOFT_MASK) {
			ASSERT(0);
		}
	}
	if (resbmap &
	    (FATTR4_QUOTA_USED_MASK |
	    FATTR4_SPACE_AVAIL_MASK |
	    FATTR4_SPACE_FREE_MASK |
	    FATTR4_SPACE_TOTAL_MASK |
	    FATTR4_SPACE_USED_MASK |
	    FATTR4_SYSTEM_MASK)) {

		if (resbmap & FATTR4_QUOTA_USED_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_RAWDEV_MASK) {
			fattr4_rawdev rawdev;

			rawdev.specdata1 = IXDR_GET_U_INT32(ptr);
			rawdev.specdata2 = IXDR_GET_U_INT32(ptr);

			if (vap->va_type == VCHR || vap->va_type == VBLK) {
				vap->va_rdev = makedevice(rawdev.specdata1,
				    rawdev.specdata2);
			} else {
				vap->va_rdev = 0;
			}
			vap->va_mask |= AT_RDEV;
		}
		if (resbmap & FATTR4_SPACE_AVAIL_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_sb.f_bavail);
			gesp->n4g_sb.f_bavail /= DEV_BSIZE;
		}
		if (resbmap & FATTR4_SPACE_FREE_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_sb.f_bfree);
			gesp->n4g_sb.f_bfree /= DEV_BSIZE;
		}
		if (resbmap & FATTR4_SPACE_TOTAL_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_sb.f_blocks);
			gesp->n4g_sb.f_blocks /= DEV_BSIZE;
		}
		if (resbmap & FATTR4_SPACE_USED_MASK) {
			uint64_t space_used;
			IXDR_GET_U_HYPER(ptr, space_used);

			/* Compute space depending on device type */
			ASSERT((vap->va_mask & AT_TYPE));
			if (vap->va_type == VREG || vap->va_type == VDIR ||
			    vap->va_type == VLNK) {
				vap->va_nblocks = (u_longlong_t)
				    ((space_used + (offset4)DEV_BSIZE -
				    (offset4)1) / (offset4)DEV_BSIZE);
			} else {
				vap->va_nblocks = 0;
			}
			vap->va_mask |= AT_NBLOCKS;
		}
		if (resbmap & FATTR4_SYSTEM_MASK) {
			ASSERT(0);
		}
	}
	if (resbmap &
	    (FATTR4_TIME_ACCESS_MASK |
	    FATTR4_TIME_ACCESS_SET_MASK |
	    FATTR4_TIME_BACKUP_MASK |
	    FATTR4_TIME_CREATE_MASK |
	    FATTR4_TIME_DELTA_MASK |
	    FATTR4_TIME_METADATA_MASK |
	    FATTR4_TIME_MODIFY_MASK |
	    FATTR4_TIME_MODIFY_SET_MASK |
	    FATTR4_MOUNTED_ON_FILEID_MASK)) {

		if (resbmap & FATTR4_TIME_ACCESS_MASK) {
			nfstime4 atime;
			int error;

			IXDR_GET_U_HYPER(ptr, atime.seconds);
			atime.nseconds = IXDR_GET_U_INT32(ptr);

			error = nfs4_time_ntov(&atime, &vap->va_atime);
			if (error) {
				garp->n4g_attrerr = error;
				garp->n4g_attrwhy = NFS4_GETATTR_ATATIME_ERR;
			}
			vap->va_mask |= AT_ATIME;
		}
		if (resbmap & FATTR4_TIME_ACCESS_SET_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_TIME_BACKUP_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_TIME_CREATE_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_TIME_DELTA_MASK) {
			IXDR_GET_U_HYPER(ptr, gesp->n4g_delta.seconds);
			gesp->n4g_delta.nseconds = IXDR_GET_U_INT32(ptr);
		}
		if (resbmap & FATTR4_TIME_METADATA_MASK) {
			nfstime4 mdt;
			int error;

			IXDR_GET_U_HYPER(ptr, mdt.seconds);
			mdt.nseconds = IXDR_GET_U_INT32(ptr);

			error = nfs4_time_ntov(&mdt, &vap->va_ctime);
			if (error) {
				garp->n4g_attrerr = error;
				garp->n4g_attrwhy = NFS4_GETATTR_ATCTIME_ERR;
			}
			vap->va_mask |= AT_CTIME;
		}
		if (resbmap & FATTR4_TIME_MODIFY_MASK) {
			nfstime4 mtime;
			int error;

			IXDR_GET_U_HYPER(ptr, mtime.seconds);
			mtime.nseconds = IXDR_GET_U_INT32(ptr);

			error = nfs4_time_ntov(&mtime, &vap->va_mtime);
			if (error) {
				garp->n4g_attrerr = error;
				garp->n4g_attrwhy = NFS4_GETATTR_ATMTIME_ERR;
			}
			vap->va_mask |= AT_MTIME;
		}
		if (resbmap & FATTR4_TIME_MODIFY_SET_MASK) {
			ASSERT(0);
		}
		if (resbmap & FATTR4_MOUNTED_ON_FILEID_MASK) {
			IXDR_GET_U_HYPER(ptr, garp->n4g_mon_fid);
			garp->n4g_mon_fid_valid = 1;
		}
	}

	/*
	 * FATTR4_ACL_MASK is not yet supported by this function, but
	 * we check against it anyway, in case it ever is.
	 */
	if (resbmap & ~(NFS4_VATTR_MASK | FATTR4_ACL_MASK)) {
		/* copy only if not provided */
		if (garp->n4g_ext_res == NULL) {
			garp->n4g_ext_res = kmem_alloc(sizeof (ges), KM_SLEEP);
			bcopy(&ges, garp->n4g_ext_res, sizeof (ges));
		}
	}

	return (TRUE);
}


/*
 * "." and ".." buffers for filling in on read and readdir
 * calls. Intialize the first time and fill in on every
 * call to to readdir.
 */
char	*nfs4_dot_entries;
char	*nfs4_dot_dot_entry;

/*
 * Create the "." or ".." and pad the buffer once so they are
 * copied out as required into the user supplied buffer everytime.
 * DIRENT64_RECLEN(sizeof (".") - 1) = DIRENT64_RECLEN(1)
 * DIRENT64_RECLEN(sizeof ("..") - 1) = DIRENT64_RECLEN(2)
 */
void
nfs4_init_dot_entries()
{
	struct dirent64 *odp;

	/*
	 * zalloc it so it zeros the buffer out. Need
	 * to just do it once.
	 */
	nfs4_dot_entries = kmem_zalloc(DIRENT64_RECLEN(1) + DIRENT64_RECLEN(2),
	    KM_SLEEP);

	odp = (struct dirent64 *)nfs4_dot_entries;
	odp->d_off = 1; /* magic cookie for "." entry */
	odp->d_reclen = DIRENT64_RECLEN(1);
	odp->d_name[0] = '.';
	odp->d_name[1] = '\0';

	nfs4_dot_dot_entry = nfs4_dot_entries + DIRENT64_RECLEN(1);
	odp = (struct dirent64 *)nfs4_dot_dot_entry;

	odp->d_off = 2;
	odp->d_reclen = DIRENT64_RECLEN(2);
	odp->d_name[0] = '.';
	odp->d_name[1] = '.';
	odp->d_name[2] = '\0';
}

void
nfs4_destroy_dot_entries()
{
	if (nfs4_dot_entries)
		kmem_free(nfs4_dot_entries, DIRENT64_RECLEN(1) +
		    DIRENT64_RECLEN(2));

	nfs4_dot_entries = nfs4_dot_dot_entry = NULL;
}

bool_t
xdr_READDIR4res_clnt(XDR *xdrs, READDIR4res_clnt *objp, READDIR4args *aobjp)
{
	bool_t more_data;
	rddir4_cache *rdc = aobjp->rdc;
	dirent64_t *dp = NULL;
	int entry_length = 0;
	int space_left = 0;
	bitmap4 resbmap;
	uint32_t attrlen;
	nfs4_ga_res_t gar;
	struct nfs4_ga_ext_res ges;
	uint64_t last_cookie = 0;
	int skip_to_end;
	ug_cache_t *pug = NULL;

	ASSERT(xdrs->x_op == XDR_DECODE);
	ASSERT(rdc->entries == NULL);
	ASSERT(aobjp->dircount > 0);

	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);

	gar.n4g_va.va_mask = 0;
	gar.n4g_change_valid = 0;
	gar.n4g_mon_fid_valid = 0;
	gar.n4g_fsid_valid = 0;
	gar.n4g_vsa.vsa_mask = 0;
	gar.n4g_attrwhy = NFS4_GETATTR_OP_OK;
	ges.n4g_pc4.pc4_cache_valid = 0;
	ges.n4g_pc4.pc4_xattr_valid = 0;
	gar.n4g_ext_res = &ges;

	/* READDIR4res_clnt_free needs to kmem_free this buffer */
	rdc->entries = kmem_alloc(aobjp->dircount, KM_SLEEP);

	dp = (dirent64_t *)rdc->entries;
	rdc->entlen = rdc->buflen = space_left = aobjp->dircount;

	/* Fill in dot and dot-dot if needed */
	if (rdc->nfs4_cookie == (nfs_cookie4) 0 ||
	    rdc->nfs4_cookie == (nfs_cookie4) 1) {

		if (rdc->nfs4_cookie == (nfs_cookie4)0) {
			bcopy(nfs4_dot_entries, rdc->entries,
			    DIRENT64_RECLEN(1) + DIRENT64_RECLEN(2));
			objp->dotp = dp;
			dp = (struct dirent64 *)(((char *)dp) +
			    DIRENT64_RECLEN(1));
			objp->dotdotp = dp;
			dp = (struct dirent64 *)(((char *)dp) +
			    DIRENT64_RECLEN(2));
			space_left -= DIRENT64_RECLEN(1) + DIRENT64_RECLEN(2);

		} else	{	/* for ".." entry */
			bcopy(nfs4_dot_dot_entry, rdc->entries,
			    DIRENT64_RECLEN(2));
			objp->dotp = NULL;
			objp->dotdotp = dp;
			dp = (struct dirent64 *)(((char *)dp) +
			    DIRENT64_RECLEN(2));
			space_left -= DIRENT64_RECLEN(2);
		}
		/* Magic NFSv4 number for entry after start */
		last_cookie = 2;
	}

	/* Get the cookie VERIFIER */
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->cookieverf))
		goto noentries;

	/* Get the do-we-have-a-next-entry BOOL */
	if (!xdr_bool(xdrs, &more_data))
		goto noentries;

	if (aobjp->attr_request & (FATTR4_OWNER_MASK | FATTR4_OWNER_GROUP_MASK))
		pug = alloc_ugcache();

	skip_to_end = 0;
	while (more_data) {
		uint_t namelen;
		uint64_t cookie;

		/* Get the COOKIE */
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&cookie))
			goto noentries;

		/* Get the LENGTH of the entry name */
		if (!xdr_u_int(xdrs, &namelen))
			goto noentries;

		if (!skip_to_end) {
			/*
			 * With the length of the directory entry name
			 * in hand, figure out if there is room left
			 * to encode it for the requestor.  If not,
			 * that is okay, but the rest of the readdir
			 * operation result must be decoded in the
			 * case there are following operations
			 * in the compound request.  Therefore, mark
			 * the rest of the response as "skip" and
			 * decode or skip the remaining data
			 */
			entry_length = DIRENT64_RECLEN(namelen);
			if (space_left < entry_length)
				skip_to_end = 1;
		}

		/* Get the NAME of the entry */
		if (!skip_to_end) {
			if (!xdr_opaque(xdrs, dp->d_name, namelen))
				goto noentries;
			bzero(&dp->d_name[namelen],
			    DIRENT64_NAMELEN(entry_length) - namelen);
			dp->d_off = last_cookie = cookie;
			dp->d_reclen = entry_length;
		} else {
			if (!XDR_CONTROL(xdrs, XDR_SKIPBYTES, &namelen))
				goto noentries;
		}

		/* Get the attribute BITMAP */
		if (!xdr_bitmap4(xdrs, &resbmap))
			goto noentries;
		/* Get the LENGTH of the attributes */
		if (!xdr_u_int(xdrs, (uint_t *)&attrlen))
			goto noentries;

		/* Get the ATTRIBUTES */
		if (!skip_to_end) {
			uint32_t *ptr;

			if (!(resbmap & FATTR4_ACL_MASK) &&
			    (ptr = (uint32_t *)XDR_INLINE(xdrs, attrlen))
			    != NULL) {
				if (!xdr_ga_fattr_res_inline(ptr, &gar, resbmap,
				    aobjp->attr_request, aobjp->mi, pug))
					goto noentries;
			} else {
				if (!xdr_ga_fattr_res(xdrs, &gar, resbmap,
				    aobjp->attr_request, aobjp->mi, pug))
					goto noentries;
			}

			/* Fill in the d_ino per the server's fid values */
			/*
			 * Important to note that the mounted on fileid
			 * is returned in d_ino if supported.  This is
			 * expected, readdir returns the mounted on fileid
			 * while stat() returns the fileid of the object
			 * on "top" of the mount.
			 */
			if (gar.n4g_mon_fid_valid)
				dp->d_ino = gar.n4g_mon_fid;
			else if (gar.n4g_va.va_mask & AT_NODEID)
				dp->d_ino = gar.n4g_va.va_nodeid;
			else
				dp->d_ino = 0;

			/* See about creating an rnode for this entry */
			if ((resbmap &
			    (NFS4_VATTR_MASK | FATTR4_FILEHANDLE_MASK)) ==
			    (NFS4_VATTR_MASK | FATTR4_FILEHANDLE_MASK)) {
				nfs4_sharedfh_t *sfhp;
				vnode_t *vp;

				sfhp = sfh4_put(&ges.n4g_fh_u.n4g_fh,
				    aobjp->mi, NULL);
				vp = makenfs4node(sfhp, &gar,
				    aobjp->dvp->v_vfsp,
				    aobjp->t,
				    aobjp->cr,
				    aobjp->dvp,
				    fn_get(VTOSV(aobjp->dvp)->sv_name,
				    dp->d_name, sfhp));
				sfh4_rele(&sfhp);
				dnlc_update(aobjp->dvp, dp->d_name, vp);
				VN_RELE(vp);
			}

			dp = (struct dirent64 *)(((caddr_t)dp) + dp->d_reclen);

			space_left -= entry_length;

		} else {
			if (!XDR_CONTROL(xdrs, XDR_SKIPBYTES, &attrlen))
				goto noentries;
		}

		/* Get the do-we-have-a-next-entry BOOL */
		if (!xdr_bool(xdrs, &more_data))
			goto noentries;
	}

	if (pug) {
		kmem_free(pug, sizeof (ug_cache_t));
		pug = NULL;
	}

	/*
	 * Finish up the rddir cache
	 * If no entries were returned, free up buffer &
	 * set ncookie to the starting cookie for this
	 * readdir request so that the direof caching
	 * will work properly.
	 */
	ASSERT(rdc->entries);
	if (last_cookie == 0) {
		kmem_free(rdc->entries, rdc->entlen);
		rdc->entries = NULL;
		last_cookie = rdc->nfs4_cookie;
	}

	rdc->actlen = rdc->entlen - space_left;
	rdc->nfs4_ncookie = last_cookie;

	/* Get the EOF marker */
	if (!xdr_bool(xdrs, &objp->eof))
		goto noentries;

	/*
	 * If the server returns eof and there were no
	 * skipped entries, set eof
	 */
	rdc->eof = (objp->eof && !skip_to_end) ? TRUE : FALSE;

	/*
	 * If we encoded entries we are done
	 */
	if (rdc->entries) {
		rdc->error = 0;
		return (TRUE);
	}

	/*
	 * If there were no entries and we skipped because
	 * there was not enough space, return EINVAL
	 */
	if (skip_to_end) {
		rdc->error = EINVAL;
		return (TRUE);
	}

	/*
	 * No entries, nothing skipped, and EOF, return OK.
	 */
	if (objp->eof == TRUE) {
		rdc->error = 0;
		return (TRUE);
	}

	/*
	 * No entries, nothing skipped, and not EOF
	 * probably a bad cookie, return ENOENT.
	 */
	rdc->error = ENOENT;
	return (TRUE);

noentries:
	if (rdc->entries) {
		kmem_free(rdc->entries, rdc->entlen);
		rdc->entries = NULL;
	}
	if (pug)
		kmem_free(pug, sizeof (ug_cache_t));
	rdc->error = EIO;
	return (FALSE);
}

/*
 * xdr_ga_res
 *
 * Returns: FALSE on raw data processing errors, TRUE otherwise.
 *
 * This function pre-processes the OP_GETATTR response, and then
 * calls common routines to process the GETATTR fattr4 results into
 * vnode attributes and other components that the client is interested
 * in. If an error other than an RPC error is encountered, the details
 * of the error are filled into objp, although the result of the
 * processing is set to TRUE.
 */
static bool_t
xdr_ga_res(XDR *xdrs, GETATTR4res *objp, GETATTR4args *aobjp)
{
#ifdef INLINE
	uint32_t *ptr;
#endif
	bitmap4 resbmap;
	uint32_t attrlen;

	ASSERT(xdrs->x_op == XDR_DECODE);

	/* Initialize objp attribute error values */
	objp->ga_res.n4g_attrerr =
	    objp->ga_res.n4g_attrwhy = NFS4_GETATTR_OP_OK;

	if (!xdr_bitmap4(xdrs, &resbmap))
		return (FALSE);

	/* save the response bitmap for the caller */
	objp->ga_res.n4g_resbmap = resbmap;

	/* attrlen */
	if (!XDR_GETINT32(xdrs, (int32_t *)&attrlen))
		return (FALSE);

	/*
	 * Handle case where request and response bitmaps don't match.
	 */
	if (aobjp->attr_request && aobjp->attr_request != resbmap) {
		bitmap4 deltabmap;

		/*
		 * Return error for case where server sent extra attributes
		 * because the "unknown" attributes may be anywhere in the
		 * xdr stream and can't be properly processed.
		 */
		deltabmap = ((aobjp->attr_request ^ resbmap) & resbmap);
		if (deltabmap) {
			objp->ga_res.n4g_attrerr = EINVAL;
			objp->ga_res.n4g_attrwhy = NFS4_GETATTR_BITMAP_ERR;
			return (TRUE);
		}

		/*
		 * Return error for case where there is a mandatory
		 * attribute missing in the server response. Note that
		 * missing recommended attributes are evaluated in the
		 * specific routines that decode the server response.
		 */
		deltabmap = ((aobjp->attr_request ^ resbmap)
		    & aobjp->attr_request);
		if ((deltabmap & FATTR4_MANDATTR_MASK)) {
			objp->ga_res.n4g_attrerr = EINVAL;
			objp->ga_res.n4g_attrwhy = NFS4_GETATTR_MANDATTR_ERR;
			return (TRUE);
		}
	}

	/* Check to see if the attrs can be inlined and go for it if so */
#ifdef INLINE
	if (!(resbmap & FATTR4_ACL_MASK) &&
	    (ptr = (uint32_t *)XDR_INLINE(xdrs, attrlen)) != NULL)
		return (xdr_ga_fattr_res_inline(ptr, &objp->ga_res,
		    resbmap, aobjp->attr_request, aobjp->mi, NULL));
	else
#endif
		return (xdr_ga_fattr_res(xdrs, &objp->ga_res,
		    resbmap, aobjp->attr_request, aobjp->mi, NULL));
}

#if defined(DEBUG) && !defined(lint)
/*
 * We assume that an enum is a 32-bit value, check it once
 */
static enum szchk { SZVAL } szchkvar;
#endif

bool_t
xdr_settime4(XDR *xdrs, settime4 *objp)
{
#if defined(DEBUG) && !defined(lint)
	ASSERT(sizeof (szchkvar) == sizeof (int32_t));
#endif
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	if (!xdr_int(xdrs, (int *)&objp->set_it))
		return (FALSE);
	if (objp->set_it != SET_TO_CLIENT_TIME4)
		return (TRUE);
	/* xdr_nfstime4 */
	if (!xdr_longlong_t(xdrs, (longlong_t *)&objp->time.seconds))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->time.nseconds));
}

static bool_t
xdr_fattr4(XDR *xdrs, fattr4 *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_bitmap4(xdrs, &objp->attrmask))
			return (FALSE);
		return (xdr_bytes(xdrs, (char **)&objp->attrlist4,
		    (uint_t *)&objp->attrlist4_len, NFS4_FATTR4_LIMIT));
	}

	/*
	 * Optimized free case
	 */
	if (objp->attrlist4 != NULL)
		kmem_free(objp->attrlist4, objp->attrlist4_len);
	return (TRUE);
}

static bool_t
xdr_ACCESS4res(XDR *xdrs, ACCESS4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (!xdr_u_int(xdrs, &objp->supported))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->access));
}

static bool_t
xdr_CLOSE4args(XDR *xdrs, CLOSE4args *objp)
{
	if (!xdr_u_int(xdrs, &objp->seqid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->open_stateid.seqid))
		return (FALSE);
	return (xdr_opaque(xdrs, objp->open_stateid.other, 12));
}

static bool_t
xdr_CLOSE4res(XDR *xdrs, CLOSE4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (!xdr_u_int(xdrs, &objp->open_stateid.seqid))
		return (FALSE);
	return (xdr_opaque(xdrs, objp->open_stateid.other, 12));
}

static bool_t
xdr_CREATE4args(XDR *xdrs, CREATE4args *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_int(xdrs, (int32_t *)&objp->type))
			return (FALSE);
		switch (objp->type) {
		case NF4LNK:
			if (!xdr_bytes(xdrs,
			    (char **)&objp->ftype4_u.linkdata.utf8string_val,
			    (uint_t *)&objp->ftype4_u.linkdata.utf8string_len,
			    NFS4_MAX_UTF8STRING))
				return (FALSE);
			break;
		case NF4BLK:
		case NF4CHR:
			if (!xdr_u_int(xdrs, &objp->ftype4_u.devdata.specdata1))
				return (FALSE);
			if (!xdr_u_int(xdrs, &objp->ftype4_u.devdata.specdata2))
				return (FALSE);
			break;
		case NF4SOCK:
		case NF4FIFO:
		case NF4DIR:
		default:
			break;	/* server should return NFS4ERR_BADTYPE */
		}
		if (!xdr_bytes(xdrs, (char **)&objp->objname.utf8string_val,
		    (uint_t *)&objp->objname.utf8string_len,
		    NFS4_MAX_UTF8STRING))
			return (FALSE);
		return (xdr_fattr4(xdrs, &objp->createattrs));
	}

	/*
	 * Optimized free case
	 */
	if (objp->type == NF4LNK) {
		if (objp->ftype4_u.linkdata.utf8string_val != NULL)
			kmem_free(objp->ftype4_u.linkdata.utf8string_val,
			    objp->ftype4_u.linkdata.utf8string_len);
	}
	if (objp->objname.utf8string_val != NULL)
		kmem_free(objp->objname.utf8string_val,
		    objp->objname.utf8string_len);
	return (xdr_fattr4(xdrs, &objp->createattrs));
}

static bool_t
xdr_CREATE4cargs(XDR *xdrs, CREATE4cargs *objp)
{
	int len;

	ASSERT(xdrs->x_op == XDR_ENCODE);

	if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->type))
		return (FALSE);
	switch (objp->type) {
	case NF4LNK:
		len = strlen(objp->ftype4_u.clinkdata);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, &len))
			return (FALSE);
		if (!xdr_opaque(xdrs, objp->ftype4_u.clinkdata, len))
			return (FALSE);
		break;
	case NF4BLK:
	case NF4CHR:
		if (!XDR_PUTINT32(xdrs,
		    (int32_t *)&objp->ftype4_u.devdata.specdata1))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs,
		    (int32_t *)&objp->ftype4_u.devdata.specdata2))
			return (FALSE);
		break;
	case NF4SOCK:
	case NF4FIFO:
	case NF4DIR:
	default:
		break;	/* server should return NFS4ERR_BADTYPE */
	}

	len = strlen(objp->cname);
	if (len > NFS4_MAX_UTF8STRING)
		return (FALSE);
	if (!XDR_PUTINT32(xdrs, &len))
		return (FALSE);
	if (!xdr_opaque(xdrs, objp->cname, len))
		return (FALSE);

	return (xdr_fattr4(xdrs, &objp->createattrs));
}

static bool_t
xdr_CREATE4res(XDR *xdrs, CREATE4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (!xdr_bool(xdrs, &objp->cinfo.atomic))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->cinfo.before))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->cinfo.after))
		return (FALSE);
	return (xdr_bitmap4(xdrs, &objp->attrset));
}

static bool_t
xdr_LINK4res(XDR *xdrs, LINK4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (!xdr_bool(xdrs, &objp->cinfo.atomic))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->cinfo.before))
		return (FALSE);
	return (xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->cinfo.after));
}

static bool_t
xdr_LOCK4args(XDR *xdrs, LOCK4args *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_int(xdrs, (int *)&objp->locktype))
			return (FALSE);
		if (!xdr_bool(xdrs, &objp->reclaim))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->offset))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->length))
			return (FALSE);
		if (!xdr_bool(xdrs, &objp->locker.new_lock_owner))
			return (FALSE);
		if (objp->locker.new_lock_owner == TRUE) {
			if (!xdr_u_int(xdrs, &objp->locker.locker4_u.open_owner.
			    open_seqid))
				return (FALSE);
			if (!xdr_u_int(xdrs, &objp->locker.locker4_u.open_owner.
			    open_stateid.seqid))
				return (FALSE);
			if (!xdr_opaque(xdrs, objp->locker.locker4_u.open_owner.
			    open_stateid.other, 12))
				return (FALSE);
			if (!xdr_u_int(xdrs, &objp->locker.locker4_u.open_owner.
			    lock_seqid))
				return (FALSE);
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&objp->locker.locker4_u.
			    open_owner.lock_owner.clientid))
				return (FALSE);
			return (xdr_bytes(xdrs,
			    (char **)&objp->locker.locker4_u.open_owner.
			    lock_owner.owner_val,
			    (uint_t *)&objp->locker.locker4_u.open_owner.
			    lock_owner.owner_len,
			    NFS4_OPAQUE_LIMIT));
		}

		if (objp->locker.new_lock_owner != FALSE)
			return (FALSE);

		if (!xdr_u_int(xdrs, &objp->locker.locker4_u.lock_owner.
		    lock_stateid.seqid))
			return (FALSE);
		if (!xdr_opaque(xdrs, objp->locker.locker4_u.lock_owner.
		    lock_stateid.other, 12))
			return (FALSE);
		return (xdr_u_int(xdrs, &objp->locker.locker4_u.lock_owner.
		    lock_seqid));
	}

	/*
	 * Optimized free case
	 */
	if (objp->locker.new_lock_owner == TRUE) {
		if (objp->locker.locker4_u.open_owner.lock_owner.owner_val !=
		    NULL) {
			kmem_free(objp->locker.locker4_u.open_owner.lock_owner.
			    owner_val,
			    objp->locker.locker4_u.open_owner.lock_owner.
			    owner_len);
		}
	}

	return (TRUE);
}

static bool_t
xdr_LOCK4res(XDR *xdrs, LOCK4res *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_int(xdrs, (int32_t *)&objp->status))
			return (FALSE);
		if (objp->status == NFS4_OK) {
			if (!xdr_u_int(xdrs,
			    &objp->LOCK4res_u.lock_stateid.seqid))
				return (FALSE);
			return (xdr_opaque(xdrs,
			    objp->LOCK4res_u.lock_stateid.other, 12));
		}
		if (objp->status != NFS4ERR_DENIED)
			return (TRUE);

		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->LOCK4res_u.
		    denied.offset))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->LOCK4res_u.
		    denied.length))
			return (FALSE);
		if (!xdr_int(xdrs, (int *)&objp->LOCK4res_u.denied.locktype))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->LOCK4res_u.
		    denied.owner.clientid))
			return (FALSE);
		return (xdr_bytes(xdrs,
		    (char **)&objp->LOCK4res_u.denied.owner.owner_val,
		    (uint_t *)&objp->LOCK4res_u.denied.owner.owner_len,
		    NFS4_OPAQUE_LIMIT));
	}

	/*
	 * Optimized free case
	 */
	if (objp->status == NFS4_OK || objp->status != NFS4ERR_DENIED)
		return (TRUE);

	if (objp->LOCK4res_u.denied.owner.owner_val != NULL)
		kmem_free(objp->LOCK4res_u.denied.owner.owner_val,
		    objp->LOCK4res_u.denied.owner.owner_len);
	return (TRUE);
}

static bool_t
xdr_LOCKT4args(XDR *xdrs, LOCKT4args *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_int(xdrs, (int *)&objp->locktype))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->offset))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->length))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->owner.clientid))
			return (FALSE);
		return (xdr_bytes(xdrs, (char **)&objp->owner.owner_val,
		    (uint_t *)&objp->owner.owner_len,
		    NFS4_OPAQUE_LIMIT));
	}

	/*
	 * Optimized free case
	 */
	if (objp->owner.owner_val != NULL)
		kmem_free(objp->owner.owner_val, objp->owner.owner_len);
	return (TRUE);
}

static bool_t
xdr_LOCKT4res(XDR *xdrs, LOCKT4res *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_int(xdrs, (int32_t *)&objp->status))
			return (FALSE);
		if (objp->status == NFS4_OK)
			return (TRUE);
		if (objp->status != NFS4ERR_DENIED)
			return (TRUE);
		/* xdr_LOCK4denied */
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->denied.offset))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->denied.length))
			return (FALSE);
		if (!xdr_int(xdrs, (int *)&objp->denied.locktype))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->denied.owner.clientid))
			return (FALSE);
		return (xdr_bytes(xdrs,
		    (char **)&objp->denied.owner.owner_val,
		    (uint_t *)&objp->denied.owner.owner_len,
		    NFS4_OPAQUE_LIMIT));
	}

	/*
	 * Optimized free case
	 */
	if (objp->status == NFS4_OK || objp->status != NFS4ERR_DENIED)
		return (TRUE);
	if (objp->denied.owner.owner_val != NULL)
		kmem_free(objp->denied.owner.owner_val,
		    objp->denied.owner.owner_len);
	return (TRUE);
}

static bool_t
xdr_LOCKU4args(XDR *xdrs, LOCKU4args *objp)
{
	if (!xdr_int(xdrs, (int *)&objp->locktype))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->seqid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->lock_stateid.seqid))
		return (FALSE);
	if (!xdr_opaque(xdrs, objp->lock_stateid.other, 12))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->offset))
		return (FALSE);
	return (xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->length));
}

static bool_t
xdr_OPEN4args(XDR *xdrs, OPEN4args *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_u_int(xdrs, &objp->seqid))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->share_access))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->share_deny))
			return (FALSE);

		/* xdr_open_owner4 */
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->owner.clientid))
			return (FALSE);
		if (!xdr_bytes(xdrs, (char **)&objp->owner.owner_val,
		    (uint_t *)&objp->owner.owner_len,
		    NFS4_OPAQUE_LIMIT))
			return (FALSE);

		/* xdr_openflag4 */
		if (!xdr_int(xdrs, (int *)&objp->opentype))
			return (FALSE);
		if (objp->opentype == OPEN4_CREATE) {

			/* xdr_createhow4 */
			if (!xdr_int(xdrs, (int *)&objp->mode))
				return (FALSE);
			switch (objp->mode) {
			case UNCHECKED4:
			case GUARDED4:
				if (!xdr_fattr4(xdrs,
				    &objp->createhow4_u.createattrs))
					return (FALSE);
				break;
			case EXCLUSIVE4:
				if (!xdr_u_longlong_t(xdrs,
				    (u_longlong_t *)&objp->createhow4_u.
				    createverf))
					return (FALSE);
				break;
			default:
				return (FALSE);
			}
		}

		/* xdr_open_claim4 */
		if (!xdr_int(xdrs, (int *)&objp->claim))
			return (FALSE);

		switch (objp->claim) {
		case CLAIM_NULL:
			return (xdr_bytes(xdrs, (char **)&objp->open_claim4_u.
			    file.utf8string_val,
			    (uint_t *)&objp->open_claim4_u.file.
			    utf8string_len,
			    NFS4_MAX_UTF8STRING));
		case CLAIM_PREVIOUS:
			return (xdr_int(xdrs,
			    (int *)&objp->open_claim4_u.delegate_type));
		case CLAIM_DELEGATE_CUR:
			if (!xdr_u_int(xdrs, (uint_t *)&objp->open_claim4_u.
			    delegate_cur_info.delegate_stateid.seqid))
				return (FALSE);
			if (!xdr_opaque(xdrs, objp->open_claim4_u.
			    delegate_cur_info.delegate_stateid.other,
			    12))
				return (FALSE);
			return (xdr_bytes(xdrs, (char **)&objp->open_claim4_u.
			    delegate_cur_info.file.utf8string_val,
			    (uint_t *)&objp->open_claim4_u.
			    delegate_cur_info.file.utf8string_len,
			    NFS4_MAX_UTF8STRING));
		case CLAIM_DELEGATE_PREV:
			return (xdr_bytes(xdrs, (char **)&objp->open_claim4_u.
			    file_delegate_prev.utf8string_val,
			    (uint_t *)&objp->open_claim4_u.
			    file_delegate_prev.utf8string_len,
			    NFS4_MAX_UTF8STRING));
		default:
			return (FALSE);
		}
	}

	/*
	 * Optimized free case
	 */
	if (objp->owner.owner_val != NULL)
		kmem_free(objp->owner.owner_val, objp->owner.owner_len);

	if (objp->opentype == OPEN4_CREATE) {
		switch (objp->mode) {
		case UNCHECKED4:
		case GUARDED4:
			(void) xdr_fattr4(xdrs,
			    &objp->createhow4_u.createattrs);
			break;
		case EXCLUSIVE4:
		default:
			break;
		}
	}

	switch (objp->claim) {
	case CLAIM_NULL:
		if (objp->open_claim4_u.file.utf8string_val != NULL)
			kmem_free(objp->open_claim4_u.file.utf8string_val,
			    objp->open_claim4_u.file.utf8string_len);
		return (TRUE);
	case CLAIM_PREVIOUS:
		return (TRUE);
	case CLAIM_DELEGATE_CUR:
		if (objp->open_claim4_u.delegate_cur_info.file.utf8string_val !=
		    NULL) {
			kmem_free(objp->open_claim4_u.delegate_cur_info.file.
			    utf8string_val,
			    objp->open_claim4_u.delegate_cur_info.file.
			    utf8string_len);
		}
		return (TRUE);
	case CLAIM_DELEGATE_PREV:
		if (objp->open_claim4_u.file_delegate_prev.utf8string_val !=
		    NULL) {
			kmem_free(objp->open_claim4_u.file_delegate_prev.
			    utf8string_val,
			    objp->open_claim4_u.file_delegate_prev.
			    utf8string_len);
		}
		return (TRUE);
	default:
		return (TRUE);
	}
}

static bool_t
xdr_OPEN4cargs(XDR *xdrs, OPEN4cargs *objp)
{
	int op;
	int len;
	rpc_inline_t *ptr;

	ASSERT(xdrs->x_op == XDR_ENCODE);

	/*
	 * We must always define the client's open_owner to be
	 * 4 byte aligned and sized.
	 */
	ASSERT(objp->owner.owner_len <= NFS4_OPAQUE_LIMIT);
	ASSERT(!(objp->owner.owner_len % BYTES_PER_XDR_UNIT));

	len = objp->owner.owner_len;
	if ((ptr = XDR_INLINE(xdrs, 8 * BYTES_PER_XDR_UNIT + len)) != NULL) {
		int i;
		int32_t *ip;

		IXDR_PUT_U_INT32(ptr, OP_OPEN);
		IXDR_PUT_U_INT32(ptr, objp->seqid);
		IXDR_PUT_U_INT32(ptr, objp->share_access);
		IXDR_PUT_U_INT32(ptr, objp->share_deny);

		/* xdr_open_owner4 */
		IXDR_PUT_HYPER(ptr, objp->owner.clientid);
		IXDR_PUT_U_INT32(ptr, objp->owner.owner_len);
		/* We know this is very short so don't bcopy */
		ip = (int32_t *)objp->owner.owner_val;
		len /= BYTES_PER_XDR_UNIT;
		for (i = 0; i < len; i++)
			*ptr++ = *ip++;

		/* xdr_openflag4 */
		IXDR_PUT_U_INT32(ptr, objp->opentype);
	} else {
		op = OP_OPEN;
		if (!XDR_PUTINT32(xdrs, (int32_t *)&op))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->seqid))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->share_access))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->share_deny))
			return (FALSE);

		/* xdr_open_owner4 */
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->owner.clientid))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->owner.owner_len))
			return (FALSE);
		if (!xdr_opaque(xdrs, objp->owner.owner_val,
		    objp->owner.owner_len))
			return (FALSE);

		/* xdr_openflag4 */
		if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->opentype))
			return (FALSE);
	}

	if (objp->opentype == OPEN4_CREATE) {
		/* xdr_createhow4 */
		if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->mode))
			return (FALSE);
		switch (objp->mode) {
		case UNCHECKED4:
		case GUARDED4:
			if (!xdr_fattr4(xdrs,
			    &objp->createhow4_u.createattrs))
				return (FALSE);
			break;
		case EXCLUSIVE4:
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&objp->createhow4_u.
			    createverf))
				return (FALSE);
			break;
		default:
			return (FALSE);
		}
	}

	/* xdr_open_claim4 */
	if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->claim))
		return (FALSE);

	switch (objp->claim) {
	case CLAIM_NULL:
		len = strlen(objp->open_claim4_u.cfile);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		if (XDR_PUTINT32(xdrs, &len)) {
			return (xdr_opaque(xdrs,
			    objp->open_claim4_u.cfile, len));
		}
		return (FALSE);
	case CLAIM_PREVIOUS:
		return (XDR_PUTINT32(xdrs,
		    (int32_t *)&objp->open_claim4_u.delegate_type));
	case CLAIM_DELEGATE_CUR:
		if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->open_claim4_u.
		    delegate_cur_info.delegate_stateid.seqid))
			return (FALSE);
		if (!xdr_opaque(xdrs, objp->open_claim4_u.
		    delegate_cur_info.delegate_stateid.other,
		    12))
			return (FALSE);
		len = strlen(objp->open_claim4_u.delegate_cur_info.cfile);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		if (XDR_PUTINT32(xdrs, &len)) {
			return (xdr_opaque(xdrs,
			    objp->open_claim4_u.delegate_cur_info.cfile,
			    len));
		}
		return (FALSE);
	case CLAIM_DELEGATE_PREV:
		len = strlen(objp->open_claim4_u.cfile_delegate_prev);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		if (XDR_PUTINT32(xdrs, &len)) {
			return (xdr_opaque(xdrs,
			    objp->open_claim4_u.cfile_delegate_prev, len));
		}
		return (FALSE);
	default:
		return (FALSE);
	}
}

static bool_t
xdr_OPEN4res(XDR *xdrs, OPEN4res *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_int(xdrs, (int32_t *)&objp->status))
			return (FALSE);
		if (objp->status != NFS4_OK)
			return (TRUE);
		if (!xdr_u_int(xdrs, &objp->stateid.seqid))
			return (FALSE);
		if (!xdr_opaque(xdrs, objp->stateid.other, 12))
			return (FALSE);
		if (!xdr_bool(xdrs, &objp->cinfo.atomic))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->cinfo.before))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->cinfo.after))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->rflags))
			return (FALSE);
		if (!xdr_bitmap4(xdrs, &objp->attrset))
			return (FALSE);
		if (!xdr_int(xdrs,
		    (int *)&objp->delegation.delegation_type))
			return (FALSE);
		switch (objp->delegation.delegation_type) {
		case OPEN_DELEGATE_NONE:
			return (TRUE);
		case OPEN_DELEGATE_READ:
			if (!xdr_u_int(xdrs, &objp->delegation.
			    open_delegation4_u.read.stateid.seqid))
				return (FALSE);
			if (!xdr_opaque(xdrs, objp->delegation.
			    open_delegation4_u.read.stateid.other,
			    12))
				return (FALSE);
			if (!xdr_bool(xdrs, &objp->delegation.
			    open_delegation4_u.read.recall))
				return (FALSE);
			return (xdr_nfsace4(xdrs, &objp->delegation.
			    open_delegation4_u.read.permissions));
		case OPEN_DELEGATE_WRITE:
			if (!xdr_u_int(xdrs, &objp->delegation.
			    open_delegation4_u.write.stateid.seqid))
				return (FALSE);
			if (!xdr_opaque(xdrs, objp->delegation.
			    open_delegation4_u.write.stateid.other,
			    12))
				return (FALSE);
			if (!xdr_bool(xdrs, &objp->delegation.
			    open_delegation4_u.write.recall))
				return (FALSE);
			if (!xdr_int(xdrs, (int *)&objp->delegation.
			    open_delegation4_u.write.space_limit.
			    limitby))
				return (FALSE);
			switch (objp->delegation.
			    open_delegation4_u.write.space_limit.
			    limitby) {
			case NFS_LIMIT_SIZE:
				if (!xdr_u_longlong_t(xdrs,
				    (u_longlong_t *)&objp->delegation.
				    open_delegation4_u.write.space_limit.
				    nfs_space_limit4_u.filesize))
					return (FALSE);
				break;
			case NFS_LIMIT_BLOCKS:
				if (!xdr_u_int(xdrs,
				    &objp->delegation.open_delegation4_u.write.
				    space_limit.nfs_space_limit4_u.
				    mod_blocks.num_blocks))
					return (FALSE);
				if (!xdr_u_int(xdrs, &objp->delegation.
				    open_delegation4_u.write.space_limit.
				    nfs_space_limit4_u.mod_blocks.
				    bytes_per_block))
					return (FALSE);
				break;
			default:
				return (FALSE);
			}
			return (xdr_nfsace4(xdrs, &objp->delegation.
			    open_delegation4_u.write.permissions));
		}
		return (FALSE);
	}

	/*
	 * Optimized free case
	 */
	if (objp->status != NFS4_OK)
		return (TRUE);

	switch (objp->delegation.delegation_type) {
	case OPEN_DELEGATE_NONE:
		return (TRUE);
	case OPEN_DELEGATE_READ:
		return (xdr_nfsace4(xdrs, &objp->delegation.
		    open_delegation4_u.read.permissions));
	case OPEN_DELEGATE_WRITE:
		switch (objp->delegation.
		    open_delegation4_u.write.space_limit.limitby) {
		case NFS_LIMIT_SIZE:
		case NFS_LIMIT_BLOCKS:
			break;
		default:
			return (FALSE);
		}
		return (xdr_nfsace4(xdrs, &objp->delegation.
		    open_delegation4_u.write.permissions));
	}
	return (FALSE);
}

static bool_t
xdr_OPEN_CONFIRM4res(XDR *xdrs, OPEN_CONFIRM4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (!xdr_u_int(xdrs, &objp->open_stateid.seqid))
		return (FALSE);
	return (xdr_opaque(xdrs, objp->open_stateid.other, 12));
}

static bool_t
xdr_OPEN_DOWNGRADE4args(XDR *xdrs, OPEN_DOWNGRADE4args *objp)
{
	if (!xdr_u_int(xdrs, &objp->open_stateid.seqid))
		return (FALSE);
	if (!xdr_opaque(xdrs, objp->open_stateid.other, 12))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->seqid))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->share_access))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->share_deny));
}

static bool_t
xdr_OPEN_DOWNGRADE4res(XDR *xdrs, OPEN_DOWNGRADE4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (!xdr_u_int(xdrs, &objp->open_stateid.seqid))
		return (FALSE);
	return (xdr_opaque(xdrs, objp->open_stateid.other, 12));
}

static bool_t
xdr_READ4args(XDR *xdrs, READ4args *objp)
{
	rdma_chunkinfo_t rci;
	rdma_wlist_conn_info_t rwci;
	struct xdr_ops *xops = xdrrdma_xops();

	if (!xdr_u_int(xdrs, &objp->stateid.seqid))
		return (FALSE);
	if (!xdr_opaque(xdrs, objp->stateid.other, 12))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->offset))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->count))
		return (FALSE);

	DTRACE_PROBE1(xdr__i__read4args_buf_len,
	    int, objp->count);

	objp->wlist = NULL;

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

static bool_t
xdr_READ4res(XDR *xdrs, READ4res *objp)
{
	mblk_t *mp;

	if (xdrs->x_op == XDR_DECODE)
		return (FALSE);

	if (xdrs->x_op == XDR_FREE) {
		/*
		 * Optimized free case
		 */
		if (objp->status != NFS4_OK)
			return (TRUE);
		if (objp->data_val != NULL)
			kmem_free(objp->data_val, objp->data_len);
		return (TRUE);
	}

	/* on with ENCODE paths */
	if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);

	if (!XDR_PUTINT32(xdrs, &objp->eof))
		return (FALSE);

	mp = objp->mblk;
	if (mp != NULL) {
		if (xdrs->x_ops == &xdrmblk_ops) {
			if (xdrmblk_putmblk(xdrs, mp, objp->data_len)) {
				objp->mblk = NULL;
				return (TRUE);
			} else {
				return (FALSE);
			}
		} else if (mp->b_cont != NULL) {
			/*
			 * See xdr_READ3res() for an explanation of why we need
			 * to do a pullup here.
			 */
			if (pullupmsg(mp, -1) == 0)
				return (FALSE);
			objp->data_val = (caddr_t)mp->b_rptr;
		}
	} else {
		if (xdr_u_int(xdrs, &objp->data_len) == FALSE) {
			return (FALSE);
		}
		/*
		 * If read data sent by wlist (RDMA_WRITE), don't do
		 * xdr_bytes() below.   RDMA_WRITE transfers the data.
		 * Note: this is encode-only because the client code
		 * uses xdr_READ4res_clnt to decode results.
		 */
		if (objp->wlist) {
			if (objp->data_len != 0) {
				return (xdrrdma_send_read_data(
				    xdrs, objp->data_len, objp->wlist));
			}
			return (TRUE);
		}
	}

	return (xdr_bytes(xdrs, (char **)&objp->data_val,
	    (uint_t *)&objp->data_len,
	    objp->data_len));
}

static bool_t
xdr_READ4res_clnt(XDR *xdrs, READ4res *objp, READ4args *aobjp)
{
	mblk_t *mp;
	size_t n;
	int error;
	uint_t size = aobjp->res_maxsize;
	count4 ocount;

	if (xdrs->x_op == XDR_ENCODE)
		return (FALSE);

	if (xdrs->x_op == XDR_FREE) {
		/*
		 * Optimized free case
		 */
		if (objp->status != NFS4_OK)
			return (TRUE);
		if (objp->data_val != NULL)
			kmem_free(objp->data_val, objp->data_len);
		return (TRUE);
	}

	if (!XDR_GETINT32(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);

	if (!XDR_GETINT32(xdrs, &objp->eof))
		return (FALSE);


	/*
	 * This is a special case such that the caller is providing a
	 * uio as a guide to eventual data location; this is used for
	 * handling DIRECTIO reads.
	 */
	if (aobjp->res_uiop != NULL) {
		struct uio *uiop = aobjp->res_uiop;
		int32_t *ptr;

		if (xdrs->x_ops == &xdrmblk_ops) {
			if (!xdrmblk_getmblk(xdrs, &mp, &objp->data_len))
				return (FALSE);

			if (objp->data_len == 0)
				return (TRUE);

			if (objp->data_len > size)
				return (FALSE);

			size = objp->data_len;
			do {
				n = MIN(size, mp->b_wptr - mp->b_rptr);
				if ((n = MIN(uiop->uio_resid, n)) != 0) {

					error =	uiomove((char *)mp->b_rptr, n,
					    UIO_READ, uiop);
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
				/* opaque count */
				if (!xdr_u_int(xdrs, &ocount)) {
					objp->wlist = NULL;
					return (FALSE);
				}

				objp->wlist_len = clist_len(cl);
				objp->data_len = ocount;

				if (objp->wlist_len !=
				    roundup(
				    objp->data_len, BYTES_PER_XDR_UNIT)) {
					DTRACE_PROBE2(
					    xdr__e__read4resuio_clnt_fail,
					    int, ocount,
					    int, objp->data_len);
					objp->wlist = NULL;
					return (FALSE);
				}

				uiop->uio_resid -= objp->data_len;
				uiop->uio_iov->iov_len -= objp->data_len;
				uiop->uio_iov->iov_base += objp->data_len;
				uiop->uio_loffset += objp->data_len;

				objp->wlist = NULL;
				return (TRUE);
			}
		}

		/*
		 * This isn't an xdrmblk stream nor RDMA.
		 * Handle the likely case that it can be
		 * inlined (ex. xdrmem).
		 */
		if (!XDR_GETINT32(xdrs, (int32_t *)&objp->data_len))
			return (FALSE);

		if (objp->data_len == 0)
			return (TRUE);

		if (objp->data_len > size)
			return (FALSE);

		size = (int)objp->data_len;
		if ((ptr = XDR_INLINE(xdrs, size)) != NULL)
			return (uiomove(ptr, size, UIO_READ, uiop) ?
			    FALSE : TRUE);

		/*
		 * Handle some other (unlikely) stream type that will
		 * need a copy.
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

	/*
	 * Check for the other special case of the caller providing
	 * the target area for the data.
	 */
	if (aobjp->res_data_val_alt == NULL)
		return (FALSE);

	/*
	 * If read data received via RDMA_WRITE, don't do xdr_bytes().
	 * RDMA_WRITE already moved the data so decode length of
	 * RDMA_WRITE.
	 */
	if (xdrs->x_ops == &xdrrdma_ops) {
		struct clist *cl;

		XDR_CONTROL(xdrs, XDR_RDMA_GET_WLIST, &cl);

		objp->wlist = cl;

		/*
		 * Data transferred through inline if
		 * objp->wlist == NULL
		 */
		if (objp->wlist) {
			/* opaque count */
			if (!xdr_u_int(xdrs, &ocount)) {
				objp->wlist = NULL;
				return (FALSE);
			}

			objp->wlist_len = clist_len(cl);
			objp->data_len = ocount;

			if (objp->wlist_len !=
			    roundup(
			    objp->data_len, BYTES_PER_XDR_UNIT)) {
				DTRACE_PROBE2(
				    xdr__e__read4res_clnt_fail,
				    int, ocount,
				    int, objp->data_len);
				objp->wlist = NULL;
				return (FALSE);
			}

			objp->wlist = NULL;
			return (TRUE);
		}
	}

	return (xdr_bytes(xdrs, (char **)&aobjp->res_data_val_alt,
	    (uint_t *)&objp->data_len,
	    aobjp->res_maxsize));
}

static bool_t
xdr_READDIR4args(XDR *xdrs, READDIR4args *objp)
{
	rdma_chunkinfo_t rci;
	struct xdr_ops *xops = xdrrdma_xops();

	if ((xdrs->x_ops == &xdrrdma_ops || xdrs->x_ops == xops) &&
	    xdrs->x_op == XDR_ENCODE) {
		rci.rci_type = RCI_REPLY_CHUNK;
		rci.rci_len = objp->maxcount;
		XDR_CONTROL(xdrs, XDR_RDMA_ADD_CHUNK, &rci);
	}

	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->cookie))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->cookieverf))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->dircount))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->maxcount))
		return (FALSE);
	return (xdr_bitmap4(xdrs, &objp->attr_request));
}

/* ARGSUSED */
static bool_t
xdrmblk_putmblk_rd(XDR *xdrs, mblk_t *m)
{
	if (((m->b_wptr - m->b_rptr) % BYTES_PER_XDR_UNIT) != 0)
		return (FALSE);

	/* LINTED pointer alignment */
	((mblk_t *)xdrs->x_base)->b_cont = m;
	xdrs->x_base = (caddr_t)m;
	xdrs->x_handy = 0;
	return (TRUE);
}

bool_t
xdr_READDIR4res(XDR *xdrs, READDIR4res *objp)
{
	mblk_t *mp = objp->mblk;
	bool_t ret_val;
	uint_t flags = 0;

	ASSERT(xdrs->x_op == XDR_ENCODE);

	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (mp == NULL)
		return (FALSE);

	if (xdrs->x_ops == &xdrmblk_ops) {
		if (xdrmblk_putmblk_rd(xdrs, mp)
		    == TRUE) {
			/* mblk successfully inserted into outgoing chain */
			objp->mblk = NULL;
			return (TRUE);
		}
	}

	ASSERT(mp->b_cont == NULL);

	/*
	 * If transport is RDMA, the pre-encoded m_blk needs to be moved
	 * without being chunked.
	 * Check if chunking is enabled for the xdr stream.
	 * If it is enabled, disable it temporarily for this op,
	 * then re-enable.
	 */
	XDR_CONTROL(xdrs, XDR_RDMA_GET_FLAGS, &flags);

	if (!(flags & XDR_RDMA_CHUNK))
		return (xdr_opaque(xdrs, (char *)mp->b_rptr, objp->data_len));

	flags &= ~XDR_RDMA_CHUNK;

	(void) XDR_CONTROL(xdrs, XDR_RDMA_SET_FLAGS, &flags);

	ret_val = xdr_opaque(xdrs, (char *)mp->b_rptr, objp->data_len);

	flags |= XDR_RDMA_CHUNK;

	(void) XDR_CONTROL(xdrs, XDR_RDMA_SET_FLAGS, &flags);

	return (ret_val);
}

static bool_t
xdr_READLINK4res(XDR *xdrs, READLINK4res *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_int(xdrs, (int32_t *)&objp->status))
			return (FALSE);
		if (objp->status != NFS4_OK)
			return (TRUE);
		return (xdr_bytes(xdrs, (char **)&objp->link.utf8string_val,
		    (uint_t *)&objp->link.utf8string_len,
		    NFS4_MAX_UTF8STRING));
	}

	/*
	 * Optimized free case
	 */
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (objp->link.utf8string_val != NULL)
		kmem_free(objp->link.utf8string_val, objp->link.utf8string_len);
	return (TRUE);
}

static bool_t
xdr_REMOVE4res(XDR *xdrs, REMOVE4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (!xdr_bool(xdrs, &objp->cinfo.atomic))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->cinfo.before))
		return (FALSE);
	return (xdr_u_longlong_t(xdrs,
	    (u_longlong_t *)&objp->cinfo.after));
}

static bool_t
xdr_RENAME4res(XDR *xdrs, RENAME4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (!xdr_bool(xdrs, &objp->source_cinfo.atomic))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs,
	    (u_longlong_t *)&objp->source_cinfo.before))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs,
	    (u_longlong_t *)&objp->source_cinfo.after))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->target_cinfo.atomic))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs,
	    (u_longlong_t *)&objp->target_cinfo.before))
		return (FALSE);
	return (xdr_u_longlong_t(xdrs,
	    (u_longlong_t *)&objp->target_cinfo.after));
}

static bool_t
xdr_secinfo4(XDR *xdrs, secinfo4 *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_u_int(xdrs, &objp->flavor))
			return (FALSE);
		if (objp->flavor != RPCSEC_GSS)
			return (TRUE);
		if (!xdr_bytes(xdrs,
		    (char **)&objp->flavor_info.oid.sec_oid4_val,
		    (uint_t *)&objp->flavor_info.oid.sec_oid4_len,
		    NFS4_MAX_SECOID4))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->flavor_info.qop))
			return (FALSE);
		return (xdr_int(xdrs, (int *)&objp->flavor_info.service));
	}

	/*
	 * Optimized free path
	 */
	if (objp->flavor != RPCSEC_GSS)
		return (TRUE);

	if (objp->flavor_info.oid.sec_oid4_val != NULL)
		kmem_free(objp->flavor_info.oid.sec_oid4_val,
		    objp->flavor_info.oid.sec_oid4_len);
	return (TRUE);
}

static bool_t
xdr_SETCLIENTID4args(XDR *xdrs, SETCLIENTID4args *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->client.verifier))
			return (FALSE);
		if (!xdr_bytes(xdrs, (char **)&objp->client.id_val,
		    (uint_t *)&objp->client.id_len, NFS4_OPAQUE_LIMIT))
			return (FALSE);
		if (!xdr_u_int(xdrs, &objp->callback.cb_program))
			return (FALSE);
		if (!xdr_string(xdrs, &objp->callback.cb_location.r_netid,
		    NFS4_OPAQUE_LIMIT))
			return (FALSE);
		if (!xdr_string(xdrs, &objp->callback.cb_location.r_addr,
		    NFS4_OPAQUE_LIMIT))
			return (FALSE);
		return (xdr_u_int(xdrs, &objp->callback_ident));
	}

	/*
	 * Optimized free case
	 */
	if (objp->client.id_val != NULL)
		kmem_free(objp->client.id_val, objp->client.id_len);
	(void) xdr_string(xdrs, &objp->callback.cb_location.r_netid,
	    NFS4_OPAQUE_LIMIT);
	return (xdr_string(xdrs, &objp->callback.cb_location.r_addr,
	    NFS4_OPAQUE_LIMIT));
}

static bool_t
xdr_SETCLIENTID4res(XDR *xdrs, SETCLIENTID4res *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_int(xdrs, (int32_t *)&objp->status))
			return (FALSE);
		switch (objp->status) {
		case NFS4_OK:
			if (!xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&objp->SETCLIENTID4res_u.resok4.
			    clientid))
				return (FALSE);
			return (xdr_u_longlong_t(xdrs,
			    (u_longlong_t *)&objp->SETCLIENTID4res_u.
			    resok4.setclientid_confirm));
		case NFS4ERR_CLID_INUSE:
			if (!xdr_string(xdrs,
			    &objp->SETCLIENTID4res_u.client_using.
			    r_netid, NFS4_OPAQUE_LIMIT))
				return (FALSE);
			return (xdr_string(xdrs,
			    &objp->SETCLIENTID4res_u.client_using.
			    r_addr, NFS4_OPAQUE_LIMIT));
		}
		return (TRUE);
	}

	/*
	 * Optimized free case
	 */
	if (objp->status != NFS4ERR_CLID_INUSE)
		return (TRUE);

	if (!xdr_string(xdrs, &objp->SETCLIENTID4res_u.client_using.r_netid,
	    NFS4_OPAQUE_LIMIT))
		return (FALSE);
	return (xdr_string(xdrs, &objp->SETCLIENTID4res_u.client_using.r_addr,
	    NFS4_OPAQUE_LIMIT));
}

static bool_t
xdr_WRITE4args(XDR *xdrs, WRITE4args *objp)
{
	if (xdrs->x_op != XDR_FREE) {
		if (!xdr_u_int(xdrs, &objp->stateid.seqid))
			return (FALSE);
		if (!xdr_opaque(xdrs, objp->stateid.other, 12))
			return (FALSE);
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->offset))
			return (FALSE);
		if (!xdr_int(xdrs, (int *)&objp->stable))
			return (FALSE);
		if (xdrs->x_op == XDR_DECODE) {
			if (xdrs->x_ops == &xdrmblk_ops) {
				objp->data_val = NULL;
				return (xdrmblk_getmblk(xdrs, &objp->mblk,
				    &objp->data_len));
			}
			objp->mblk = NULL;
			if (xdrs->x_ops == &xdrrdmablk_ops) {
				int retval;
				retval = xdrrdma_getrdmablk(xdrs,
				    &objp->rlist,
				    &objp->data_len,
				    &objp->conn, NFS4_DATA_LIMIT);
				if (retval == FALSE)
					return (FALSE);
				return (xdrrdma_read_from_client(objp->rlist,
				    &objp->conn, objp->data_len));
			}
		}
		/* Else fall thru for the xdr_bytes(). */
		return (xdr_bytes(xdrs, (char **)&objp->data_val,
		    (uint_t *)&objp->data_len, NFS4_DATA_LIMIT));
	}
	if (objp->rlist != NULL) {
		(void) xdrrdma_free_clist(objp->conn, objp->rlist);
		objp->rlist = NULL;
		objp->data_val = NULL;

		return (TRUE);
	}

	/*
	 * Optimized free case
	 */
	if (objp->data_val != NULL)
		kmem_free(objp->data_val, objp->data_len);
	return (TRUE);
}

static bool_t
xdr_WRITE4res(XDR *xdrs, WRITE4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (objp->status != NFS4_OK)
		return (TRUE);
	if (!xdr_u_int(xdrs, &objp->count))
		return (FALSE);
	if (!xdr_int(xdrs, (int *)&objp->committed))
		return (FALSE);
	return (xdr_u_longlong_t(xdrs,
	    (u_longlong_t *)&objp->writeverf));
}

static bool_t
xdr_snfs_argop4_free(XDR *xdrs, nfs_argop4 **arrayp, int len)
{
	int i;
	nfs_argop4 *array = *arrayp;

	/*
	 * Optimized XDR_FREE only args array
	 */
	ASSERT(xdrs->x_op == XDR_FREE);

	/*
	 * Nothing to do?
	 */
	if (array == NULL)
		return (TRUE);

	for (i = 0; i < len; i++) {
		/*
		 * These should be ordered by frequency of use
		 */
		switch (array[i].argop) {
		case OP_PUTFH: {
			nfs_fh4 *objp = &array[i].nfs_argop4_u.opputfh.object;

			if (objp->nfs_fh4_val != NULL) {
				kmem_free(objp->nfs_fh4_val, objp->nfs_fh4_len);
			}
			continue;
		}
		case OP_GETATTR:
		case OP_GETFH:
			continue;
		case OP_LOOKUP:
			if (array[i].nfs_argop4_u.oplookup.objname.
			    utf8string_val != NULL) {
				kmem_free(array[i].nfs_argop4_u.oplookup.
				    objname.utf8string_val,
				    array[i].nfs_argop4_u.oplookup.
				    objname.utf8string_len);
			}
			continue;
		case OP_OPEN:
			(void) xdr_OPEN4args(xdrs,
			    &array[i].nfs_argop4_u.opopen);
			continue;
		case OP_CLOSE:
		case OP_ACCESS:
		case OP_READ:
			continue;
		case OP_WRITE:
			(void) xdr_WRITE4args(xdrs,
			    &array[i].nfs_argop4_u.opwrite);
			continue;
		case OP_DELEGRETURN:
		case OP_LOOKUPP:
		case OP_READDIR:
			continue;
		case OP_REMOVE:
			if (array[i].nfs_argop4_u.opremove.target.
			    utf8string_val != NULL) {
				kmem_free(array[i].nfs_argop4_u.opremove.target.
				    utf8string_val,
				    array[i].nfs_argop4_u.opremove.target.
				    utf8string_len);
			}
			continue;
		case OP_COMMIT:
			continue;
		case OP_CREATE:
			(void) xdr_CREATE4args(xdrs,
			    &array[i].nfs_argop4_u.opcreate);
			continue;
		case OP_DELEGPURGE:
			continue;
		case OP_LINK:
			if (array[i].nfs_argop4_u.oplink.newname.
			    utf8string_val != NULL) {
				kmem_free(array[i].nfs_argop4_u.oplink.newname.
				    utf8string_val,
				    array[i].nfs_argop4_u.oplink.newname.
				    utf8string_len);
			}
			continue;
		case OP_LOCK:
			(void) xdr_LOCK4args(xdrs,
			    &array[i].nfs_argop4_u.oplock);
			continue;
		case OP_LOCKT:
			(void) xdr_LOCKT4args(xdrs,
			    &array[i].nfs_argop4_u.oplockt);
			continue;
		case OP_LOCKU:
			continue;
		case OP_NVERIFY:
			(void) xdr_fattr4(xdrs,
			    &array[i].nfs_argop4_u.opnverify.obj_attributes);
			continue;
		case OP_OPENATTR:
		case OP_OPEN_CONFIRM:
		case OP_OPEN_DOWNGRADE:
		case OP_PUTPUBFH:
		case OP_PUTROOTFH:
		case OP_READLINK:
			continue;
		case OP_RENAME:
			if (array[i].nfs_argop4_u.oprename.oldname.
			    utf8string_val != NULL) {
				kmem_free(array[i].nfs_argop4_u.oprename.
				    oldname.utf8string_val,
				    array[i].nfs_argop4_u.oprename.
				    oldname.utf8string_len);
			}
			if (array[i].nfs_argop4_u.oprename.newname.
			    utf8string_val != NULL) {
				kmem_free(array[i].nfs_argop4_u.oprename.
				    newname.utf8string_val,
				    array[i].nfs_argop4_u.oprename.
				    newname.utf8string_len);
			}
			continue;
		case OP_RENEW:
		case OP_RESTOREFH:
		case OP_SAVEFH:
			continue;
		case OP_SECINFO:
			if (array[i].nfs_argop4_u.opsecinfo.name.
			    utf8string_val != NULL) {
				kmem_free(array[i].nfs_argop4_u.opsecinfo.name.
				    utf8string_val,
				    array[i].nfs_argop4_u.opsecinfo.name.
				    utf8string_len);
			}
			continue;
		case OP_SETATTR:
			(void) xdr_fattr4(xdrs,
			    &array[i].nfs_argop4_u.opsetattr.obj_attributes);
			continue;
		case OP_SETCLIENTID:
			(void) xdr_SETCLIENTID4args(xdrs,
			    &array[i].nfs_argop4_u.opsetclientid);
			continue;
		case OP_SETCLIENTID_CONFIRM:
			continue;
		case OP_VERIFY:
			(void) xdr_fattr4(xdrs,
			    &array[i].nfs_argop4_u.opverify.obj_attributes);
			continue;
		case OP_RELEASE_LOCKOWNER:
			if (array[i].nfs_argop4_u.oprelease_lockowner.
			    lock_owner.owner_val != NULL) {
				kmem_free(array[i].nfs_argop4_u.
				    oprelease_lockowner.lock_owner.owner_val,
				    array[i].nfs_argop4_u.
				    oprelease_lockowner.lock_owner.owner_len);
			}
			continue;
		case OP_ILLEGAL:
			continue;
		default:
			/*
			 * An invalid op is a coding error, it should never
			 * have been decoded.
			 * Don't error because the caller cannot finish
			 * freeing the residual memory of the array.
			 */
			continue;
		}
	}

	kmem_free(*arrayp, len * sizeof (nfs_argop4));
	*arrayp = NULL;
	return (TRUE);
}

static bool_t
xdr_nfs_argop4(XDR *xdrs, nfs_argop4 *objp)
{
	rdma_chunkinfo_t rci;
	struct xdr_ops *xops = xdrrdma_xops();

	/*
	 * These should be ordered by frequency of use
	 */
	switch (objp->argop) {
	case OP_PUTFH:
		return (xdr_bytes(xdrs,
		    (char **)&objp->nfs_argop4_u.opputfh.object.nfs_fh4_val,
		    (uint_t *)&objp->nfs_argop4_u.opputfh.object.nfs_fh4_len,
		    NFS4_FHSIZE));
	case OP_GETATTR:
		/*
		 * ACLs can become relatively large ( > 8K) and the default
		 * 8K reply chunk of RDMA may not suffice. Check for
		 * get ACL bit and if it's RDMA, add a chunk equal the size
		 * of the transfer size to the reply chunk list.
		 */
		if ((xdrs->x_ops == &xdrrdma_ops || xdrs->x_ops == xops) &&
		    (xdrs->x_op == XDR_ENCODE) &&
		    (objp->nfs_argop4_u.opgetattr.attr_request &
		    FATTR4_ACL_MASK)) {
			rci.rci_type = RCI_REPLY_CHUNK;
			rci.rci_len = objp->nfs_argop4_u.opgetattr.mi->mi_tsize;
			XDR_CONTROL(xdrs, XDR_RDMA_ADD_CHUNK, &rci);

			DTRACE_PROBE1(xdr__i__argop4__getattr, int,
			    rci.rci_len);
		}
		return (xdr_bitmap4(xdrs,
		    &objp->nfs_argop4_u.opgetattr.attr_request));
	case OP_GETFH:
		return (TRUE);
	case OP_LOOKUP:
		return (xdr_bytes(xdrs, (char **)&objp->nfs_argop4_u.oplookup.
		    objname.utf8string_val,
		    (uint_t *)&objp->nfs_argop4_u.oplookup.
		    objname.utf8string_len,
		    NFS4_MAX_UTF8STRING));
	case OP_OPEN:
		return (xdr_OPEN4args(xdrs, &objp->nfs_argop4_u.opopen));
	case OP_CLOSE:
		return (xdr_CLOSE4args(xdrs, &objp->nfs_argop4_u.opclose));
	case OP_ACCESS:
		return (xdr_u_int(xdrs,
		    &objp->nfs_argop4_u.opaccess.access));
	case OP_READ:
		return (xdr_READ4args(xdrs, &objp->nfs_argop4_u.opread));
	case OP_WRITE:
		return (xdr_WRITE4args(xdrs, &objp->nfs_argop4_u.opwrite));
	case OP_DELEGRETURN:
		if (!xdr_u_int(xdrs,
		    &objp->nfs_argop4_u.opdelegreturn.deleg_stateid.seqid))
			return (FALSE);
		return (xdr_opaque(xdrs,
		    objp->nfs_argop4_u.opdelegreturn.deleg_stateid.other, 12));
	case OP_LOOKUPP:
		return (TRUE);
	case OP_READDIR:
		return (xdr_READDIR4args(xdrs, &objp->nfs_argop4_u.opreaddir));
	case OP_REMOVE:
		return (xdr_bytes(xdrs, (char **)&objp->nfs_argop4_u.opremove.
		    target.utf8string_val,
		    (uint_t *)&objp->nfs_argop4_u.opremove.
		    target.utf8string_len,
		    NFS4_MAX_UTF8STRING));
	case OP_COMMIT:
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->nfs_argop4_u.opcommit.offset))
			return (FALSE);
		return (xdr_u_int(xdrs, &objp->nfs_argop4_u.opcommit.count));
	case OP_CREATE:
		return (xdr_CREATE4args(xdrs, &objp->nfs_argop4_u.opcreate));
	case OP_DELEGPURGE:
		return (xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->nfs_argop4_u.opdelegpurge.clientid));
	case OP_LINK:
		return (xdr_bytes(xdrs,
		    (char **)&objp->nfs_argop4_u.oplink.newname.utf8string_val,
		    (uint_t *)&objp->nfs_argop4_u.oplink.newname.utf8string_len,
		    NFS4_MAX_UTF8STRING));
	case OP_LOCK:
		return (xdr_LOCK4args(xdrs, &objp->nfs_argop4_u.oplock));
	case OP_LOCKT:
		return (xdr_LOCKT4args(xdrs, &objp->nfs_argop4_u.oplockt));
	case OP_LOCKU:
		return (xdr_LOCKU4args(xdrs, &objp->nfs_argop4_u.oplocku));
	case OP_NVERIFY:
		return (xdr_fattr4(xdrs,
		    &objp->nfs_argop4_u.opnverify.obj_attributes));
	case OP_OPENATTR:
		return (xdr_bool(xdrs,
		    &objp->nfs_argop4_u.opopenattr.createdir));
	case OP_OPEN_CONFIRM:
		if (!xdr_u_int(xdrs, &objp->nfs_argop4_u.opopen_confirm.
		    open_stateid.seqid))
			return (FALSE);
		if (!xdr_opaque(xdrs, objp->nfs_argop4_u.opopen_confirm.
		    open_stateid.other, 12))
			return (FALSE);
		return (xdr_u_int(xdrs, &objp->nfs_argop4_u.opopen_confirm.
		    seqid));
	case OP_OPEN_DOWNGRADE:
		return (xdr_OPEN_DOWNGRADE4args(xdrs,
		    &objp->nfs_argop4_u.opopen_downgrade));
	case OP_PUTPUBFH:
		return (TRUE);
	case OP_PUTROOTFH:
		return (TRUE);
	case OP_READLINK:
		if ((xdrs->x_ops == &xdrrdma_ops || xdrs->x_ops == xops) &&
		    xdrs->x_op == XDR_ENCODE) {
			rci.rci_type = RCI_REPLY_CHUNK;
			rci.rci_len = MAXPATHLEN;
			XDR_CONTROL(xdrs, XDR_RDMA_ADD_CHUNK, &rci);
		}
		return (TRUE);
	case OP_RENAME:
		if (!xdr_bytes(xdrs, (char **)&objp->nfs_argop4_u.oprename.
		    oldname.utf8string_val,
		    (uint_t *)&objp->nfs_argop4_u.oprename.
		    oldname.utf8string_len,
		    NFS4_MAX_UTF8STRING))
			return (FALSE);
		return (xdr_bytes(xdrs, (char **)&objp->nfs_argop4_u.oprename.
		    newname.utf8string_val,
		    (uint_t *)&objp->nfs_argop4_u.oprename.
		    newname.utf8string_len,
		    NFS4_MAX_UTF8STRING));
	case OP_RENEW:
		return (xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->nfs_argop4_u.oprenew.clientid));
	case OP_RESTOREFH:
		return (TRUE);
	case OP_SAVEFH:
		return (TRUE);
	case OP_SECINFO:
		return (xdr_bytes(xdrs,
		    (char **)&objp->nfs_argop4_u.opsecinfo.name.utf8string_val,
		    (uint_t *)&objp->nfs_argop4_u.opsecinfo.name.utf8string_len,
		    NFS4_MAX_UTF8STRING));
	case OP_SETATTR:
		if (!xdr_u_int(xdrs, &objp->nfs_argop4_u.opsetattr.
		    stateid.seqid))
			return (FALSE);
		if (!xdr_opaque(xdrs, objp->nfs_argop4_u.opsetattr.
		    stateid.other, 12))
			return (FALSE);
		return (xdr_fattr4(xdrs, &objp->nfs_argop4_u.opsetattr.
		    obj_attributes));
	case OP_SETCLIENTID:
		return (xdr_SETCLIENTID4args(xdrs,
		    &objp->nfs_argop4_u.opsetclientid));
	case OP_SETCLIENTID_CONFIRM:
		if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->nfs_argop4_u.
		    opsetclientid_confirm.clientid))
			return (FALSE);
		return (xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->nfs_argop4_u.
		    opsetclientid_confirm.setclientid_confirm));
	case OP_VERIFY:
		return (xdr_fattr4(xdrs,
		    &objp->nfs_argop4_u.opverify.obj_attributes));
	case OP_RELEASE_LOCKOWNER:
		if (!xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->nfs_argop4_u.
		    oprelease_lockowner.lock_owner.clientid))
			return (FALSE);
		return (xdr_bytes(xdrs,
		    (char **)&objp->nfs_argop4_u.oprelease_lockowner.
		    lock_owner.owner_val,
		    (uint_t *)&objp->nfs_argop4_u.oprelease_lockowner.
		    lock_owner.owner_len, NFS4_OPAQUE_LIMIT));
	case OP_ILLEGAL:
		return (TRUE);
	}
	return (FALSE);
}

static bool_t
xdr_cnfs_argop4_wrap(XDR *xdrs, nfs_argop4 *objp)
{
	if (!xdr_int(xdrs, (int *)&objp->argop))
		return (FALSE);

	return (xdr_nfs_argop4(xdrs, objp));
}

static bool_t
xdr_snfs_argop4(XDR *xdrs, nfs_argop4 *objp)
{
	if (!xdr_int(xdrs, (int *)&objp->argop))
		return (FALSE);

	switch (objp->argop) {
	case OP_PUTFH:
		return (xdr_decode_nfs_fh4(xdrs,
		    &objp->nfs_argop4_u.opputfh.object));
	default:
		return (xdr_nfs_argop4(xdrs, objp));
	}
}

/*
 * Client side encode only arg op processing
 */
static bool_t
xdr_cnfs_argop4(XDR *xdrs, nfs_argop4 *objp)
{
	int len;
	int op;
	nfs4_sharedfh_t *sfh;
	mntinfo4_t *mi;
	rpc_inline_t *ptr;

	ASSERT(xdrs->x_op == XDR_ENCODE);

	/*
	 * Special case the private pseudo ops
	 */
	if (!(objp->argop & SUNW_PRIVATE_OP))
		return (xdr_cnfs_argop4_wrap(xdrs, objp));

	/*
	 * These should be ordered by frequency of use
	 */
	switch (objp->argop) {
	case OP_CPUTFH:
		/*
		 * We are passed in the file handle as a nfs4_sharedfh_t *
		 * We need to acquire the correct locks so we can copy it out.
		 */
		sfh = (nfs4_sharedfh_t *)objp->nfs_argop4_u.opcputfh.sfh;
		mi = sfh->sfh_mi;
		(void) nfs_rw_enter_sig(&mi->mi_fh_lock, RW_READER, 0);

		len = sfh->sfh_fh.nfs_fh4_len;
		ASSERT(len <= NFS4_FHSIZE);

		/*
		 * First try and inline the copy
		 * Must first be a multiple of BYTES_PER_XDR_UNIT
		 */
		if (!(len % BYTES_PER_XDR_UNIT) &&
		    (ptr = XDR_INLINE(xdrs, 2 * BYTES_PER_XDR_UNIT + len)) !=
		    NULL) {
			IXDR_PUT_U_INT32(ptr, OP_PUTFH);
			IXDR_PUT_U_INT32(ptr, len);
			bcopy(sfh->sfh_fh.nfs_fh4_val, ptr, len);
			nfs_rw_exit(&mi->mi_fh_lock);
			return (TRUE);
		}

		op = OP_PUTFH;
		if (!XDR_PUTINT32(xdrs, &op)) {
			nfs_rw_exit(&mi->mi_fh_lock);
			return (FALSE);
		}
		if (!XDR_PUTINT32(xdrs, &len)) {
			nfs_rw_exit(&mi->mi_fh_lock);
			return (FALSE);
		}
		if (!(len % BYTES_PER_XDR_UNIT)) {
			if (XDR_PUTBYTES(xdrs, sfh->sfh_fh.nfs_fh4_val, len)) {
				nfs_rw_exit(&mi->mi_fh_lock);
				return (TRUE);
			}
		} else if (xdr_opaque(xdrs, sfh->sfh_fh.nfs_fh4_val, len)) {
			nfs_rw_exit(&mi->mi_fh_lock);
			return (TRUE);
		}
		nfs_rw_exit(&mi->mi_fh_lock);
		return (FALSE);
	case OP_CLOOKUP:
		len = strlen(objp->nfs_argop4_u.opclookup.cname);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		op = OP_LOOKUP;
		if (XDR_PUTINT32(xdrs, &op)) {
			if (XDR_PUTINT32(xdrs, &len)) {
				return (xdr_opaque(xdrs,
				    objp->nfs_argop4_u.opclookup.cname,
				    len));
			}
		}
		return (FALSE);
	case OP_COPEN:
		/* op processing inlined in xdr_OPEN4cargs */
		return (xdr_OPEN4cargs(xdrs, &objp->nfs_argop4_u.opcopen));
	case OP_CREMOVE:
		len = strlen(objp->nfs_argop4_u.opcremove.ctarget);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		op = OP_REMOVE;
		if (XDR_PUTINT32(xdrs, &op)) {
			if (XDR_PUTINT32(xdrs, &len)) {
				return (xdr_opaque(xdrs,
				    objp->nfs_argop4_u.opcremove.ctarget,
				    len));
			}
		}
		return (FALSE);
	case OP_CCREATE:
		op = OP_CREATE;
		if (!XDR_PUTINT32(xdrs, &op))
			return (FALSE);
		return (xdr_CREATE4cargs(xdrs, &objp->nfs_argop4_u.opccreate));
	case OP_CLINK:
		len = strlen(objp->nfs_argop4_u.opclink.cnewname);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		op = OP_LINK;
		if (XDR_PUTINT32(xdrs, &op)) {
			if (XDR_PUTINT32(xdrs, &len)) {
				return (xdr_opaque(xdrs,
				    objp->nfs_argop4_u.opclink.cnewname,
				    len));
			}
		}
		return (FALSE);
	case OP_CRENAME:
		len = strlen(objp->nfs_argop4_u.opcrename.coldname);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		op = OP_RENAME;
		if (!XDR_PUTINT32(xdrs, &op))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, &len))
			return (FALSE);
		if (!xdr_opaque(xdrs,
		    objp->nfs_argop4_u.opcrename.coldname, len))
			return (FALSE);
		len = strlen(objp->nfs_argop4_u.opcrename.cnewname);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		if (XDR_PUTINT32(xdrs, &len)) {
			return (xdr_opaque(xdrs,
			    objp->nfs_argop4_u.opcrename.cnewname, len));
		}
		return (FALSE);
	case OP_CSECINFO:
		len = strlen(objp->nfs_argop4_u.opcsecinfo.cname);
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		op = OP_SECINFO;
		if (XDR_PUTINT32(xdrs, &op)) {
			if (XDR_PUTINT32(xdrs, &len)) {
				return (xdr_opaque(xdrs,
				    objp->nfs_argop4_u.opcsecinfo.cname,
				    len));
			}
		}
		return (FALSE);
	}
	return (FALSE);
}

/*
 * Note that the len and decode_len will only be different in the case
 * of the client's use of this free function.  If the server is
 * freeing results, then the len/decode_len will always match.
 */
static bool_t
xdr_nfs_resop4_free(XDR *xdrs, nfs_resop4 **arrayp, int len, int decode_len)
{
	int i;
	nfs_resop4 *array = *arrayp;
	nfs4_ga_res_t *gr;

	/*
	 * Optimized XDR_FREE only results array
	 */
	ASSERT(xdrs->x_op == XDR_FREE);

	if (array == NULL)
		return (TRUE);

	for (i = 0; i < decode_len; i++) {
		/*
		 * These should be ordered by frequency of use
		 */
		switch (array[i].resop) {
		case OP_PUTFH:
			continue;
		case OP_GETATTR:
			if (array[i].nfs_resop4_u.opgetattr.status != NFS4_OK)
				continue;

			gr = &array[i].nfs_resop4_u.opgetattr.ga_res;
			if (gr->n4g_ext_res) {
				if (gr->n4g_resbmap & FATTR4_FS_LOCATIONS_MASK)
					(void) xdr_fattr4_fs_locations(xdrs,
					    &gr->n4g_ext_res->n4g_fslocations);
				kmem_free(gr->n4g_ext_res,
				    sizeof (struct nfs4_ga_ext_res));
			}
			continue;
		case OP_GETFH:
			if (array[i].nfs_resop4_u.opgetfh.status != NFS4_OK)
				continue;
			if (array[i].nfs_resop4_u.opgetfh.object.nfs_fh4_val !=
			    NULL) {
				kmem_free(array[i].nfs_resop4_u.opgetfh.object.
				    nfs_fh4_val,
				    array[i].nfs_resop4_u.opgetfh.object.
				    nfs_fh4_len);
			}
			continue;
		case OP_LOOKUP:
			continue;
		case OP_OPEN:
			(void) xdr_OPEN4res(xdrs, &array[i].nfs_resop4_u.
			    opopen);
			continue;
		case OP_CLOSE:
		case OP_ACCESS:
			continue;
		case OP_READ:
			(void) xdr_READ4res(xdrs,
			    &array[i].nfs_resop4_u.opread);
			continue;
		case OP_WRITE:
		case OP_DELEGRETURN:
		case OP_LOOKUPP:
		case OP_READDIR:
		case OP_REMOVE:
		case OP_COMMIT:
		case OP_CREATE:
		case OP_DELEGPURGE:
		case OP_LINK:
			continue;
		case OP_LOCK:
			(void) xdr_LOCK4res(xdrs, &array[i].nfs_resop4_u.
			    oplock);
			continue;
		case OP_LOCKT:
			(void) xdr_LOCKT4res(xdrs, &array[i].nfs_resop4_u.
			    oplockt);
			continue;
		case OP_LOCKU:
		case OP_NVERIFY:
		case OP_OPENATTR:
		case OP_OPEN_CONFIRM:
		case OP_OPEN_DOWNGRADE:
		case OP_PUTPUBFH:
		case OP_PUTROOTFH:
		case OP_RENAME:
		case OP_RENEW:
		case OP_RESTOREFH:
		case OP_SAVEFH:
			continue;
		case OP_READLINK:
			(void) xdr_READLINK4res(xdrs, &array[i].nfs_resop4_u.
			    opreadlink);
			continue;
		case OP_SECINFO:
			(void) xdr_array(xdrs,
			    (char **)&array[i].nfs_resop4_u.opsecinfo.
			    SECINFO4resok_val,
			    (uint_t *)&array[i].nfs_resop4_u.opsecinfo.
			    SECINFO4resok_len,
			    NFS4_SECINFO_LIMIT, sizeof (secinfo4),
			    (xdrproc_t)xdr_secinfo4);
			continue;
		case OP_SETCLIENTID:
			(void) xdr_SETCLIENTID4res(xdrs,
			    &array[i].nfs_resop4_u.opsetclientid);
			continue;
		case OP_SETATTR:
		case OP_SETCLIENTID_CONFIRM:
		case OP_VERIFY:
		case OP_RELEASE_LOCKOWNER:
		case OP_ILLEGAL:
			continue;
		default:
			/*
			 * An invalid op is a coding error, it should never
			 * have been decoded.
			 * Don't error because the caller cannot finish
			 * freeing the residual memory of the array.
			 */
			continue;
		}
	}

	kmem_free(*arrayp, len * sizeof (nfs_resop4));
	*arrayp = NULL;
	return (TRUE);
}

static bool_t
xdr_snfs_resop4_free(XDR *xdrs, nfs_resop4 **arrayp, int len, int decode_len)
{
	return (xdr_nfs_resop4_free(xdrs, arrayp, len, decode_len));
}

static bool_t
xdr_nfs_resop4(XDR *xdrs, nfs_resop4 *objp)
{
	/*
	 * These should be ordered by frequency of use
	 */
	switch (objp->resop) {
	case OP_PUTFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opputfh.status));
	case OP_GETATTR:
		if (!xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opgetattr.status))
			return (FALSE);
		if (objp->nfs_resop4_u.opgetattr.status != NFS4_OK)
			return (TRUE);
		return (xdr_fattr4(xdrs,
		    &objp->nfs_resop4_u.opgetattr.obj_attributes));
	case OP_GETFH:
		if (!xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opgetfh.status))
			return (FALSE);
		if (objp->nfs_resop4_u.opgetfh.status != NFS4_OK)
			return (TRUE);
		return (xdr_bytes(xdrs,
		    (char **)&objp->nfs_resop4_u.opgetfh.object.nfs_fh4_val,
		    (uint_t *)&objp->nfs_resop4_u.opgetfh.object.nfs_fh4_len,
		    NFS4_FHSIZE));
	case OP_LOOKUP:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oplookup.status));
	case OP_OPEN:
		return (xdr_OPEN4res(xdrs, &objp->nfs_resop4_u.opopen));
	case OP_CLOSE:
		return (xdr_CLOSE4res(xdrs, &objp->nfs_resop4_u.opclose));
	case OP_ACCESS:
		return (xdr_ACCESS4res(xdrs, &objp->nfs_resop4_u.opaccess));
	case OP_READ:
		return (xdr_READ4res(xdrs, &objp->nfs_resop4_u.opread));
	case OP_WRITE:
		return (xdr_WRITE4res(xdrs, &objp->nfs_resop4_u.opwrite));
	case OP_DELEGRETURN:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opdelegreturn.status));
	case OP_LOOKUPP:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oplookupp.status));
	case OP_READDIR:
		return (xdr_READDIR4res(xdrs, &objp->nfs_resop4_u.opreaddir));
	case OP_REMOVE:
		return (xdr_REMOVE4res(xdrs, &objp->nfs_resop4_u.opremove));

	case OP_COMMIT:
		if (!xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opcommit.status))
			return (FALSE);
		if (objp->nfs_resop4_u.opcommit.status != NFS4_OK)
			return (TRUE);
		return (xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->nfs_resop4_u.opcommit.
		    writeverf));
	case OP_CREATE:
		return (xdr_CREATE4res(xdrs, &objp->nfs_resop4_u.opcreate));
	case OP_DELEGPURGE:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opdelegpurge.status));
	case OP_LINK:
		return (xdr_LINK4res(xdrs, &objp->nfs_resop4_u.oplink));
	case OP_LOCK:
		return (xdr_LOCK4res(xdrs, &objp->nfs_resop4_u.oplock));
	case OP_LOCKT:
		return (xdr_LOCKT4res(xdrs, &objp->nfs_resop4_u.oplockt));
	case OP_LOCKU:
		if (!xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oplocku.status))
			return (FALSE);
		if (objp->nfs_resop4_u.oplocku.status != NFS4_OK)
			return (TRUE);
		if (!xdr_u_int(xdrs,
		    &objp->nfs_resop4_u.oplocku.lock_stateid.seqid))
			return (FALSE);
		return (xdr_opaque(xdrs,
		    objp->nfs_resop4_u.oplocku.lock_stateid.other,
		    12));
	case OP_NVERIFY:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opnverify.status));
	case OP_OPENATTR:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opopenattr.status));
	case OP_OPEN_CONFIRM:
		return (xdr_OPEN_CONFIRM4res(xdrs,
		    &objp->nfs_resop4_u.opopen_confirm));
	case OP_OPEN_DOWNGRADE:
		return (xdr_OPEN_DOWNGRADE4res(xdrs,
		    &objp->nfs_resop4_u.opopen_downgrade));
	case OP_PUTPUBFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opputpubfh.status));
	case OP_PUTROOTFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opputrootfh.status));
	case OP_READLINK:
		return (xdr_READLINK4res(xdrs, &objp->nfs_resop4_u.opreadlink));
	case OP_RENAME:
		return (xdr_RENAME4res(xdrs, &objp->nfs_resop4_u.oprename));
	case OP_RENEW:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oprenew.status));
	case OP_RESTOREFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oprestorefh.status));
	case OP_SAVEFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opsavefh.status));
	case OP_SECINFO:
		if (!xdr_int(xdrs, (int32_t *)&objp->nfs_resop4_u.opsecinfo.
		    status))
			return (FALSE);
		if (objp->nfs_resop4_u.opsecinfo.status != NFS4_OK)
			return (TRUE);
		return (xdr_array(xdrs, (char **)&objp->nfs_resop4_u.opsecinfo.
		    SECINFO4resok_val,
		    (uint_t *)&objp->nfs_resop4_u.opsecinfo.
		    SECINFO4resok_len,
		    NFS4_SECINFO_LIMIT, sizeof (secinfo4),
		    (xdrproc_t)xdr_secinfo4));
	case OP_SETATTR:
		if (!xdr_int(xdrs, (int32_t *)&objp->nfs_resop4_u.opsetattr.
		    status))
			return (FALSE);
		return (xdr_bitmap4(xdrs,
		    &objp->nfs_resop4_u.opsetattr.attrsset));
	case OP_SETCLIENTID:
		return (xdr_SETCLIENTID4res(xdrs,
		    &objp->nfs_resop4_u.opsetclientid));
	case OP_SETCLIENTID_CONFIRM:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opsetclientid_confirm.
		    status));
	case OP_VERIFY:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opverify.status));
	case OP_RELEASE_LOCKOWNER:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oprelease_lockowner.status));
	case OP_ILLEGAL:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opillegal.status));
	}
	return (FALSE);
}

static bool_t
xdr_snfs_resop4(XDR *xdrs, nfs_resop4 *objp)
{
	if (!xdr_int(xdrs, (int *)&objp->resop))
		return (FALSE);

	switch (objp->resop) {
	case OP_GETFH:
		if (!XDR_PUTINT32(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opgetfh.status))
			return (FALSE);
		if (objp->nfs_resop4_u.opgetfh.status != NFS4_OK)
			return (TRUE);
		return (xdr_encode_nfs_fh4(xdrs,
		    &objp->nfs_resop4_u.opgetfh.object));
	default:
		return (xdr_nfs_resop4(xdrs, objp));
	}
}

static bool_t
xdr_nfs_resop4_clnt(XDR *xdrs, nfs_resop4 *objp, nfs_argop4 *aobjp)
{
	if (!xdr_int(xdrs, (int *)&objp->resop))
		return (FALSE);
	/*
	 * These should be ordered by frequency of use
	 */
	switch (objp->resop) {
	case OP_PUTFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opputfh.status));
	case OP_GETATTR:
		if (!xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opgetattr.status))
			return (FALSE);
		if (objp->nfs_resop4_u.opgetattr.status != NFS4_OK)
			return (TRUE);
		return (xdr_ga_res(xdrs,
		    (GETATTR4res *)&objp->nfs_resop4_u.opgetattr,
		    &aobjp->nfs_argop4_u.opgetattr));
	case OP_GETFH:
		if (!xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opgetfh.status))
			return (FALSE);
		if (objp->nfs_resop4_u.opgetfh.status != NFS4_OK)
			return (TRUE);
		return (xdr_bytes(xdrs,
		    (char **)&objp->nfs_resop4_u.opgetfh.object.nfs_fh4_val,
		    (uint_t *)&objp->nfs_resop4_u.opgetfh.object.nfs_fh4_len,
		    NFS4_FHSIZE));
	case OP_LOOKUP:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oplookup.status));
	case OP_NVERIFY:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opnverify.status));
	case OP_OPEN:
		return (xdr_OPEN4res(xdrs, &objp->nfs_resop4_u.opopen));
	case OP_CLOSE:
		return (xdr_CLOSE4res(xdrs, &objp->nfs_resop4_u.opclose));
	case OP_ACCESS:
		return (xdr_ACCESS4res(xdrs, &objp->nfs_resop4_u.opaccess));
	case OP_READ:
		return (xdr_READ4res_clnt(xdrs, &objp->nfs_resop4_u.opread,
		    &aobjp->nfs_argop4_u.opread));
	case OP_WRITE:
		return (xdr_WRITE4res(xdrs, &objp->nfs_resop4_u.opwrite));
	case OP_DELEGRETURN:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opdelegreturn.status));
	case OP_LOOKUPP:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oplookupp.status));
	case OP_READDIR:
		return (xdr_READDIR4res_clnt(xdrs,
		    &objp->nfs_resop4_u.opreaddirclnt,
		    &aobjp->nfs_argop4_u.opreaddir));
	case OP_REMOVE:
		return (xdr_REMOVE4res(xdrs, &objp->nfs_resop4_u.opremove));

	case OP_COMMIT:
		if (!xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opcommit.status))
			return (FALSE);
		if (objp->nfs_resop4_u.opcommit.status != NFS4_OK)
			return (TRUE);
		return (xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&objp->nfs_resop4_u.opcommit.
		    writeverf));
	case OP_CREATE:
		return (xdr_CREATE4res(xdrs, &objp->nfs_resop4_u.opcreate));
	case OP_DELEGPURGE:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opdelegpurge.status));
	case OP_LINK:
		return (xdr_LINK4res(xdrs, &objp->nfs_resop4_u.oplink));
	case OP_LOCK:
		return (xdr_LOCK4res(xdrs, &objp->nfs_resop4_u.oplock));
	case OP_LOCKT:
		return (xdr_LOCKT4res(xdrs, &objp->nfs_resop4_u.oplockt));
	case OP_LOCKU:
		if (!xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oplocku.status))
			return (FALSE);
		if (objp->nfs_resop4_u.oplocku.status != NFS4_OK)
			return (TRUE);
		if (!xdr_u_int(xdrs,
		    &objp->nfs_resop4_u.oplocku.lock_stateid.seqid))
			return (FALSE);
		return (xdr_opaque(xdrs,
		    objp->nfs_resop4_u.oplocku.lock_stateid.other,
		    12));
	case OP_OPENATTR:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opopenattr.status));
	case OP_OPEN_CONFIRM:
		return (xdr_OPEN_CONFIRM4res(xdrs,
		    &objp->nfs_resop4_u.opopen_confirm));
	case OP_OPEN_DOWNGRADE:
		return (xdr_OPEN_DOWNGRADE4res(xdrs,
		    &objp->nfs_resop4_u.opopen_downgrade));
	case OP_PUTPUBFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opputpubfh.status));
	case OP_PUTROOTFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opputrootfh.status));
	case OP_READLINK:
		return (xdr_READLINK4res(xdrs, &objp->nfs_resop4_u.opreadlink));
	case OP_RENAME:
		return (xdr_RENAME4res(xdrs, &objp->nfs_resop4_u.oprename));
	case OP_RENEW:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oprenew.status));
	case OP_RESTOREFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oprestorefh.status));
	case OP_SAVEFH:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opsavefh.status));
	case OP_SECINFO:
		if (!xdr_int(xdrs, (int32_t *)&objp->nfs_resop4_u.opsecinfo.
		    status))
			return (FALSE);
		if (objp->nfs_resop4_u.opsecinfo.status != NFS4_OK)
			return (TRUE);
		return (xdr_array(xdrs, (char **)&objp->nfs_resop4_u.opsecinfo.
		    SECINFO4resok_val,
		    (uint_t *)&objp->nfs_resop4_u.opsecinfo.
		    SECINFO4resok_len,
		    ~0, sizeof (secinfo4), (xdrproc_t)xdr_secinfo4));
	case OP_SETATTR:
		if (!xdr_int(xdrs, (int32_t *)&objp->nfs_resop4_u.opsetattr.
		    status))
			return (FALSE);
		return (xdr_bitmap4(xdrs,
		    &objp->nfs_resop4_u.opsetattr.attrsset));
	case OP_SETCLIENTID:
		return (xdr_SETCLIENTID4res(xdrs,
		    &objp->nfs_resop4_u.opsetclientid));
	case OP_SETCLIENTID_CONFIRM:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opsetclientid_confirm.
		    status));
	case OP_VERIFY:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opverify.status));
	case OP_RELEASE_LOCKOWNER:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.oprelease_lockowner.status));
	case OP_ILLEGAL:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_resop4_u.opillegal.status));
	}
	return (FALSE);
}

bool_t
xdr_COMPOUND4args_clnt(XDR *xdrs, COMPOUND4args_clnt *objp)
{
	static int32_t twelve = 12;
	static int32_t minorversion = NFS4_MINORVERSION;
	uint32_t *ctagp;
	rpc_inline_t *ptr;
	rdma_chunkinfo_t rci;
	struct xdr_ops *xops = xdrrdma_xops();

	/*
	 * XDR_ENCODE only
	 */
	if (xdrs->x_op == XDR_FREE)
		return (TRUE);
	if (xdrs->x_op == XDR_DECODE)
		return (FALSE);

	ctagp = (uint32_t *)&nfs4_ctags[objp->ctag].ct_tag;

	if ((ptr = XDR_INLINE(xdrs, 5 * BYTES_PER_XDR_UNIT)) != NULL) {
		/*
		 * Efficiently encode fixed length tags, could be longlongs
		 * but 8 byte XDR alignment not assured
		 */
		IXDR_PUT_U_INT32(ptr, 12);
		IXDR_PUT_U_INT32(ptr, ctagp[0]);
		IXDR_PUT_U_INT32(ptr, ctagp[1]);
		IXDR_PUT_U_INT32(ptr, ctagp[2]);

		/*
		 * Fixed minor version for now
		 */
		IXDR_PUT_U_INT32(ptr, NFS4_MINORVERSION);
	} else {
		if (!XDR_PUTINT32(xdrs, &twelve))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, (int32_t *)&ctagp[0]))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, (int32_t *)&ctagp[1]))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, (int32_t *)&ctagp[2]))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, (int32_t *)&minorversion))
			return (FALSE);
	}
	if (xdrs->x_ops == &xdrrdma_ops || xdrs->x_ops == xops) {
		rci.rci_type = RCI_REPLY_CHUNK;
		rci.rci_len = MAXPATHLEN * 2;
		XDR_CONTROL(xdrs, XDR_RDMA_ADD_CHUNK, &rci);
	}

	return (xdr_array(xdrs, (char **)&objp->array,
	    (uint_t *)&objp->array_len, NFS4_COMPOUND_LIMIT,
	    sizeof (nfs_argop4), (xdrproc_t)xdr_cnfs_argop4));
}

bool_t
xdr_COMPOUND4args_srv(XDR *xdrs, COMPOUND4args *objp)
{
	if (!xdr_bytes(xdrs, (char **)&objp->tag.utf8string_val,
	    (uint_t *)&objp->tag.utf8string_len,
	    NFS4_MAX_UTF8STRING))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->minorversion))
		return (FALSE);
	if (xdrs->x_op != XDR_FREE)
		return (xdr_array(xdrs, (char **)&objp->array,
		    (uint_t *)&objp->array_len, NFS4_COMPOUND_LIMIT,
		    sizeof (nfs_argop4), (xdrproc_t)xdr_snfs_argop4));

	return (xdr_snfs_argop4_free(xdrs, &objp->array, objp->array_len));
}

bool_t
xdr_COMPOUND4res_clnt(XDR *xdrs, COMPOUND4res_clnt *objp)
{
	uint32_t len;
	int32_t *ptr;
	nfs_argop4 *argop;
	nfs_resop4 *resop;

	/*
	 * No XDR_ENCODE
	 */
	if (xdrs->x_op == XDR_ENCODE)
		return (FALSE);

	if (xdrs->x_op != XDR_FREE) {
		if ((ptr = XDR_INLINE(xdrs, 2 * BYTES_PER_XDR_UNIT)) != NULL) {
			objp->status = IXDR_GET_U_INT32(ptr);
			len = IXDR_GET_U_INT32(ptr);
		} else {
			if (!xdr_int(xdrs, (int32_t *)&objp->status))
				return (FALSE);
			if (!xdr_u_int(xdrs, (uint32_t *)&len))
				return (FALSE);
		}
		if (len > NFS4_MAX_UTF8STRING)
			return (FALSE);
		/*
		 * Ignore the tag
		 */
		if (!XDR_CONTROL(xdrs, XDR_SKIPBYTES, &len))
			return (FALSE);

		if (!xdr_int(xdrs, (int32_t *)&objp->array_len))
			return (FALSE);

		if (objp->array_len > objp->argsp->array_len)
			return (FALSE);

		if (objp->status == NFS4_OK &&
		    objp->array_len != objp->argsp->array_len)
			return (FALSE);

		/* Alloc the results array */
		argop = objp->argsp->array;
		len = objp->array_len * sizeof (nfs_resop4);
		objp->decode_len = 0;
		objp->array = resop = kmem_zalloc(len, KM_SLEEP);

		for (len = 0; len < objp->array_len;
		    len++, resop++, argop++, objp->decode_len++) {
			if (!xdr_nfs_resop4_clnt(xdrs, resop, argop)) {
				/*
				 * Make sure to free anything that may
				 * have been allocated along the way.
				 */
				xdrs->x_op = XDR_FREE;
				(void) xdr_nfs_resop4_free(xdrs, &objp->array,
				    objp->array_len,
				    objp->decode_len);
				return (FALSE);
			}
		}
		return (TRUE);
	}
	return (xdr_nfs_resop4_free(xdrs, &objp->array,
	    objp->array_len, objp->decode_len));
}

bool_t
xdr_COMPOUND4res_srv(XDR *xdrs, COMPOUND4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (!xdr_bytes(xdrs, (char **)&objp->tag.utf8string_val,
	    (uint_t *)&objp->tag.utf8string_len,
	    NFS4_MAX_UTF8STRING))
		return (FALSE);

	if (xdrs->x_op != XDR_FREE)
		return (xdr_array(xdrs, (char **)&objp->array,
		    (uint_t *)&objp->array_len, NFS4_COMPOUND_LIMIT,
		    sizeof (nfs_resop4), (xdrproc_t)xdr_snfs_resop4));

	return (xdr_snfs_resop4_free(xdrs, &objp->array,
	    objp->array_len, objp->array_len));
}

/*
 * NFS server side callback, initiating the callback request so it
 * is the RPC client. Must convert from server's internal filehandle
 * format to wire format.
 */
static bool_t
xdr_snfs_cb_argop4(XDR *xdrs, nfs_cb_argop4 *objp)
{
	CB_GETATTR4args *gargs;
	CB_RECALL4args *rargs;

	ASSERT(xdrs->x_op == XDR_ENCODE);

	if (!XDR_PUTINT32(xdrs, (int32_t *)&objp->argop))
		return (FALSE);

	switch (objp->argop) {
	case OP_CB_GETATTR:
		gargs = &objp->nfs_cb_argop4_u.opcbgetattr;

		if (!xdr_encode_nfs_fh4(xdrs, &gargs->fh))
			return (FALSE);
		return (xdr_bitmap4(xdrs, &gargs->attr_request));
	case OP_CB_RECALL:
		rargs = &objp->nfs_cb_argop4_u.opcbrecall;

		if (!XDR_PUTINT32(xdrs, (int32_t *)&rargs->stateid.seqid))
			return (FALSE);
		if (!xdr_opaque(xdrs, rargs->stateid.other, 12))
			return (FALSE);
		if (!XDR_PUTINT32(xdrs, (int32_t *)&rargs->truncate))
			return (FALSE);
		return (xdr_encode_nfs_fh4(xdrs, &rargs->fh));
	case OP_CB_ILLEGAL:
		return (TRUE);
	}
	return (FALSE);
}

/*
 * NFS client side callback, receiving the callback request so it
 * is the RPC server. Must treat the file handles as opaque.
 */
static bool_t
xdr_cnfs_cb_argop4(XDR *xdrs, nfs_cb_argop4 *objp)
{
	CB_GETATTR4args *gargs;
	CB_RECALL4args *rargs;

	ASSERT(xdrs->x_op != XDR_ENCODE);

	if (!xdr_u_int(xdrs, &objp->argop))
		return (FALSE);
	switch (objp->argop) {
	case OP_CB_GETATTR:
		gargs = &objp->nfs_cb_argop4_u.opcbgetattr;

		if (!xdr_bytes(xdrs, (char **)&gargs->fh.nfs_fh4_val,
		    (uint_t *)&gargs->fh.nfs_fh4_len, NFS4_FHSIZE))
			return (FALSE);
		return (xdr_bitmap4(xdrs, &gargs->attr_request));
	case OP_CB_RECALL:
		rargs = &objp->nfs_cb_argop4_u.opcbrecall;

		if (!xdr_u_int(xdrs, &rargs->stateid.seqid))
			return (FALSE);
		if (!xdr_opaque(xdrs, rargs->stateid.other, 12))
			return (FALSE);
		if (!xdr_bool(xdrs, &rargs->truncate))
			return (FALSE);
		return (xdr_bytes(xdrs, (char **)&rargs->fh.nfs_fh4_val,
		    (uint_t *)&rargs->fh.nfs_fh4_len, NFS4_FHSIZE));
	case OP_CB_ILLEGAL:
		return (TRUE);
	}
	return (FALSE);
}

static bool_t
xdr_nfs_cb_resop4(XDR *xdrs, nfs_cb_resop4 *objp)
{
	if (!xdr_u_int(xdrs, &objp->resop))
		return (FALSE);
	switch (objp->resop) {
	case OP_CB_GETATTR:
		if (!xdr_int(xdrs,
		    (int32_t *)&objp->nfs_cb_resop4_u.opcbgetattr.
		    status))
			return (FALSE);
		if (objp->nfs_cb_resop4_u.opcbgetattr.status != NFS4_OK)
			return (TRUE);
		return (xdr_fattr4(xdrs,
		    &objp->nfs_cb_resop4_u.opcbgetattr.
		    obj_attributes));
	case OP_CB_RECALL:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_cb_resop4_u.opcbrecall.status));
	case OP_CB_ILLEGAL:
		return (xdr_int(xdrs,
		    (int32_t *)&objp->nfs_cb_resop4_u.opcbillegal.status));
	}
	return (FALSE);
}

/*
 * The NFS client side callback, RPC server
 */
bool_t
xdr_CB_COMPOUND4args_clnt(XDR *xdrs, CB_COMPOUND4args *objp)
{
	if (!xdr_bytes(xdrs, (char **)&objp->tag.utf8string_val,
	    (uint_t *)&objp->tag.utf8string_len,
	    NFS4_MAX_UTF8STRING))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->minorversion))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->callback_ident))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->array,
	    (uint_t *)&objp->array_len, NFS4_COMPOUND_LIMIT,
	    sizeof (nfs_cb_argop4), (xdrproc_t)xdr_cnfs_cb_argop4));
}

/*
 * The NFS server side callback, RPC client
 */
bool_t
xdr_CB_COMPOUND4args_srv(XDR *xdrs, CB_COMPOUND4args *objp)
{
	if (!xdr_bytes(xdrs, (char **)&objp->tag.utf8string_val,
	    (uint_t *)&objp->tag.utf8string_len,
	    NFS4_MAX_UTF8STRING))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->minorversion))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->callback_ident))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->array,
	    (uint_t *)&objp->array_len, NFS4_COMPOUND_LIMIT,
	    sizeof (nfs_cb_argop4), (xdrproc_t)xdr_snfs_cb_argop4));
}

bool_t
xdr_CB_COMPOUND4res(XDR *xdrs, CB_COMPOUND4res *objp)
{
	if (!xdr_int(xdrs, (int32_t *)&objp->status))
		return (FALSE);
	if (!xdr_bytes(xdrs, (char **)&objp->tag.utf8string_val,
	    (uint_t *)&objp->tag.utf8string_len,
	    NFS4_MAX_UTF8STRING))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->array,
	    (uint_t *)&objp->array_len, NFS4_COMPOUND_LIMIT,
	    sizeof (nfs_cb_resop4), (xdrproc_t)xdr_nfs_cb_resop4));
}
