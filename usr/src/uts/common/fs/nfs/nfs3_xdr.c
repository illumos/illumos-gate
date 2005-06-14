/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <rpc/types.h>
#include <rpc/xdr.h>

#include <nfs/nfs.h>
#include <nfs/rnode.h>

/* Checks if the fh is 32 bytes and returns TRUE if it is, otherwise FALSE */
#define	XDR_CHECKFHSIZE(x, len, sz)	\
	(((int32_t)ntohl(len) == NFS3_CURFHSIZE) ? TRUE : \
	(xdr_rewind(x, sz), FALSE))

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
 * If the filehandle is not equal to NFS3_CURFHSIZE then
 * rewind/set the pointer back to it's previous location prior to
 * the call.
 * Inlining is only being done for 32 byte fhandles since
 * predominantly the size of the fh is 32 and thus
 * optimizing only this case would be the best.
 */
static void
xdr_rewind(register XDR *xdrs, uint_t inl_sz)
{
	uint_t curpos;

	curpos = XDR_GETPOS(xdrs);
	(void) XDR_SETPOS(xdrs, curpos - inl_sz);
}

bool_t
xdr_nfs_fh3(XDR *xdrs, nfs_fh3 *objp)
{
	int32_t *ptr;
	int32_t *fhp;
	uint_t len;
	uint_t in_size;

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	in_size = RNDUP(sizeof (fhandle_t)) +	1 * BYTES_PER_XDR_UNIT;

	ptr = XDR_INLINE(xdrs, in_size);
	if (ptr != NULL) {
		len = ((xdrs->x_op == XDR_DECODE) ? *ptr : objp->fh3_length);

		if (XDR_CHECKFHSIZE(xdrs, len, in_size)) {
			fhp = (int32_t *)&(objp->fh3_u.data);
			if (xdrs->x_op == XDR_DECODE) {
				objp->fh3_length = IXDR_GET_U_INT32(ptr);
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp = *ptr;
			} else {
				IXDR_PUT_U_INT32(ptr, objp->fh3_length);
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr = *fhp;
			}
			return (TRUE);
		}
	}

	if (!xdr_u_int(xdrs, &objp->fh3_length))
		return (FALSE);

	if (objp->fh3_length > NFS3_FHSIZE)
		return (FALSE);

	return (xdr_opaque(xdrs, objp->fh3_u.data, objp->fh3_length));
}

/*
 * Will only consider the DECODE case for the fast way
 * since it does not require any additional allocation of
 * memory and thus can just assign the objp to point to
 * the data returned from XDR_INLINE
 */
bool_t
xdr_fastnfs_fh3(register XDR *xdrs, nfs_fh3 **objp)
{
	int32_t *ptr;
	uint_t in_size;

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	in_size = RNDUP(sizeof (fhandle_t)) + 1 * BYTES_PER_XDR_UNIT;

	ptr = XDR_INLINE(xdrs, in_size);

	if ((ptr != NULL) && (XDR_CHECKFHSIZE(xdrs, *ptr, in_size))) {
#ifdef _LITTLE_ENDIAN
		/* Decode the length */
		*ptr = (int32_t)ntohl(*(uint32_t *)ptr);
#endif
		*objp = (nfs_fh3 *) ptr;
		return (TRUE);
	}
	return (FALSE);
}

bool_t
xdr_diropargs3(XDR *xdrs, diropargs3 *objp)
{
	uint32_t size;
	int32_t *ptr;
	int32_t *fhp;
	uint32_t nodesize;
	uint32_t in_size;
	int rndup, i;
	char *cptr;

	if (xdrs->x_op == XDR_DECODE) {
		objp->dirp = &objp->dir;
		/* includes: fh, length of fh, and length of name */
		in_size = RNDUP(sizeof (fhandle_t)) + 2 * BYTES_PER_XDR_UNIT;

		ptr = XDR_INLINE(xdrs, in_size);

		if (ptr != NULL) {
		    if (XDR_CHECKFHSIZE(xdrs, *ptr, in_size)) {
			    fhp = (int32_t *)(objp->dir.fh3_u.data);
			    /* Get length of fhandle and then fh. */
			    objp->dir.fh3_length = IXDR_GET_U_INT32(ptr);
			    *fhp++ = *ptr++;
			    *fhp++ = *ptr++;
			    *fhp++ = *ptr++;
			    *fhp++ = *ptr++;
			    *fhp++ = *ptr++;
			    *fhp++ = *ptr++;
			    *fhp++ = *ptr++;
			    *fhp = *ptr++;

			    size = IXDR_GET_U_INT32(ptr);

			    if (size >= MAXNAMELEN) {
				    objp->name = nfs3nametoolong;
				    if (!XDR_CONTROL(xdrs, XDR_SKIPBYTES,
						&size))
					    return (FALSE);
				    return (TRUE);
			    }
			    nodesize = size+1;
			    if (nodesize == 0)
				    return (TRUE);
			    if (objp->name == NULL) {
				    objp->name = (char *)kmem_alloc(nodesize,
								    KM_NOSLEEP);
				    if (objp->name == NULL)
					    return (FALSE);
				    objp->flags |= DA_FREENAME;
			    }
			    ptr = XDR_INLINE(xdrs, RNDUP(size));
			    if (ptr == NULL) {
				if (! xdr_opaque(xdrs, objp->name, size)) {
					if (objp->flags & DA_FREENAME) {
						kmem_free(objp->name,
							nodesize);
						objp->name = NULL;
					}
					return (FALSE);
				}
				objp->name[size] = '\0';
				if (strlen(objp->name) != size) {
					if (objp->flags & DA_FREENAME) {
						kmem_free(objp->name,
							nodesize);
						objp->name = NULL;
					}
					return (FALSE);
				}
				return (TRUE);
			    }
			    bcopy((char *)ptr, objp->name, size);
			    objp->name[size] = '\0';
			    if (strlen(objp->name) != size) {
				    if (objp->flags & DA_FREENAME) {
					    kmem_free(objp->name,
						nodesize);
					    objp->name = NULL;
				    }
				    return (FALSE);
			    }
			    return (TRUE);
		    }
		}
		if (objp->name == NULL)
			objp->flags |= DA_FREENAME;
	}

	if ((xdrs->x_op == XDR_ENCODE) &&
	    (objp->dirp->fh3_length == NFS3_CURFHSIZE)) {
		fhp = (int32_t *)(objp->dirp->fh3_u.data);
		size = strlen(objp->name);
		in_size = RNDUP(sizeof (fhandle_t)) +
			(2 * BYTES_PER_XDR_UNIT) + RNDUP(size);

		ptr = XDR_INLINE(xdrs, in_size);
		if (ptr != NULL) {
			IXDR_PUT_U_INT32(ptr, objp->dirp->fh3_length);
			*ptr++ = *fhp++;
			*ptr++ = *fhp++;
			*ptr++ = *fhp++;
			*ptr++ = *fhp++;
			*ptr++ = *fhp++;
			*ptr++ = *fhp++;
			*ptr++ = *fhp++;
			*ptr++ = *fhp;

			IXDR_PUT_U_INT32(ptr, (uint32_t)size);

			bcopy(objp->name, (char *)ptr, size);
			rndup = BYTES_PER_XDR_UNIT -
				(size % BYTES_PER_XDR_UNIT);
			if (rndup != BYTES_PER_XDR_UNIT) {
				cptr = (char *)ptr + size;
				for (i = 0; i < rndup; i++)
					*cptr++ = '\0';
			}
			return (TRUE);
		}
	}
	if (xdrs->x_op == XDR_FREE) {
		if ((objp->name == NULL) || (objp->name == nfs3nametoolong))
			return (TRUE);
		size = strlen(objp->name);
		if (objp->flags & DA_FREENAME)
			kmem_free(objp->name, size + 1);
		objp->name = NULL;
		return (TRUE);
	}
	/* Normal case */
	if (!xdr_nfs_fh3(xdrs, objp->dirp))
		return (FALSE);
	return (xdr_string3(xdrs, &objp->name, MAXNAMELEN));
}

bool_t
xdr_fastdiropargs3(XDR *xdrs, diropargs3 **objp)
{
	int32_t *ptr;
	uint_t size;
	uint_t nodesize;
	struct diropargs3 *da;
	uint_t in_size;
	uint_t skipsize;

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	in_size = RNDUP(sizeof (fhandle_t)) +	1 * BYTES_PER_XDR_UNIT;

	/* includes the fh and fh length */
	ptr = XDR_INLINE(xdrs, in_size);

	if ((ptr != NULL) && (XDR_CHECKFHSIZE(xdrs, *ptr, in_size))) {
		da = *objp;
#ifdef _LITTLE_ENDIAN
		*ptr = (int32_t)ntohl(*(uint32_t *)ptr);
#endif
		da->dirp = (nfs_fh3 *)ptr;
		da->name = NULL;
		da->flags = 0;
		if (!XDR_CONTROL(xdrs, XDR_PEEK, (void *)&size)) {
			da->flags |= DA_FREENAME;
			return (xdr_string3(xdrs, &da->name, MAXNAMELEN));
		}
		if (size >= MAXNAMELEN) {
			da->name = nfs3nametoolong;
			skipsize = RNDUP(size) + (1 * BYTES_PER_XDR_UNIT);
			if (!XDR_CONTROL(xdrs, XDR_SKIPBYTES, &skipsize))
				return (FALSE);
			return (TRUE);
		}
		nodesize = size + 1;
		if (nodesize == 0)
			return (TRUE);
		ptr = XDR_INLINE(xdrs, 1 * BYTES_PER_XDR_UNIT + RNDUP(size));
		if (ptr != NULL) {
			if ((size % BYTES_PER_XDR_UNIT) != 0)
				/* Plus 1 skips the size */
				da->name = (char *)(ptr + 1);
			else {
				da->name = (char *)ptr;
				bcopy((char *)(ptr + 1), da->name, size);
			}
			da->name[size] = '\0';
			return (TRUE);
		}
		da->flags |= DA_FREENAME;
		return (xdr_string3(xdrs, &da->name, MAXNAMELEN));
	}
	return (FALSE);
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

	objp->status = 0;
	ptr = XDR_INLINE(xdrs, NFS3_SIZEOF_FATTR3 * BYTES_PER_XDR_UNIT);
	if (ptr != NULL) {
		/*
		 * Common case
		 */
		vap->va_type = IXDR_GET_ENUM(ptr, enum vtype);
		if (vap->va_type < NF3REG || vap->va_type > NF3FIFO)
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
		if (vap->va_type < NF3REG || vap->va_type > NF3FIFO)
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
		return (xdr_nfs_fh3(xdrs, &objp->handle));
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
	if (!xdr_nfs_fh3(xdrs, &objp->object))
		return (FALSE);
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
	if (!xdr_nfs_fh3(xdrs, &resokp->object))
		return (FALSE);
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
	int32_t *ptr;
	int32_t *fhp;
	int len;
	uint_t in_size;

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	in_size = RNDUP(sizeof (fhandle_t)) +	2 * BYTES_PER_XDR_UNIT;
	ptr = XDR_INLINE(xdrs, in_size);

	if (ptr != NULL) {
		len =  (xdrs->x_op == XDR_DECODE) ?
			*ptr : objp->object.fh3_length;

		if (XDR_CHECKFHSIZE(xdrs, len, in_size)) {
			fhp = (int32_t *)&(objp->object.fh3_u.data);
			if (xdrs->x_op == XDR_DECODE) {
				objp->object.fh3_length = IXDR_GET_U_INT32(ptr);
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp = *ptr++;
				objp->access = IXDR_GET_U_INT32(ptr);
			} else {
				IXDR_PUT_U_INT32(ptr, objp->object.fh3_length);
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp;
				IXDR_PUT_U_INT32(ptr, objp->access);
			}
			return (TRUE);
		}
	}

	if (!xdr_nfs_fh3(xdrs, &objp->object))
		return (FALSE);
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
	int32_t *ptr;
	int32_t *fhp;
	uint_t in_size;
	int len;

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	in_size = RNDUP(sizeof (fhandle_t)) + 4 * BYTES_PER_XDR_UNIT;
	ptr = XDR_INLINE(xdrs, in_size);
	if (ptr != NULL) {
		len = (xdrs->x_op == XDR_DECODE) ?
			*ptr : objp->file.fh3_length;

		if (XDR_CHECKFHSIZE(xdrs, len, in_size)) {
			fhp = (int32_t *)& objp->file.fh3_u.data;
			if (xdrs->x_op == XDR_DECODE) {
				objp->file.fh3_length = IXDR_GET_U_INT32(ptr);
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp = *ptr++;
				IXDR_GET_U_HYPER(ptr, objp->offset);
				objp->count = IXDR_GET_U_INT32(ptr);
			} else {
				IXDR_PUT_U_INT32(ptr, objp->file.fh3_length);
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp;
				IXDR_PUT_U_HYPER(ptr, objp->offset);
				IXDR_PUT_U_INT32(ptr, objp->count);
			}
			return (TRUE);
		}
	}

	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, &objp->offset))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->count));
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
		int i, rndup;

		mp = resokp->data.mp;
		if (mp != NULL && xdrs->x_ops == &xdrmblk_ops) {
			mp->b_wptr += resokp->count;
			rndup = BYTES_PER_XDR_UNIT -
				(resokp->data.data_len % BYTES_PER_XDR_UNIT);
			if (rndup != BYTES_PER_XDR_UNIT)
				for (i = 0; i < rndup; i++)
					*mp->b_wptr++ = '\0';
			if (xdrmblk_putmblk(xdrs, mp, resokp->count) == TRUE) {
				resokp->data.mp = NULL;
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

	ret = xdr_bytes(xdrs, (char **)&resokp->data.data_val,
	    &resokp->data.data_len, nfs3tsize());

	return (ret);
}

bool_t
xdr_READ3vres(XDR *xdrs, READ3vres *objp)
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

	if (!xdr_post_op_vattr(xdrs, &objp->pov))
		return (FALSE);

	if (objp->status != NFS3_OK)
		return (TRUE);

	if (!xdr_u_int(xdrs, &objp->count))
		return (FALSE);

	if (!xdr_bool(xdrs, &objp->eof))
		return (FALSE);

	return (xdr_bytes(xdrs, (char **)&objp->data.data_val,
	    &objp->data.data_len, nfs3tsize()));
}

bool_t
xdr_READ3uiores(XDR *xdrs, READ3uiores *objp)
{
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

	/*
	 * This isn't an xdrmblk stream.   Handle the likely
	 * case that it can be inlined (ex. xdrmem).
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
	int32_t *ptr;
	int32_t *fhp;
	uint_t in_size;
	int len;

	in_size = RNDUP(sizeof (fhandle_t)) + 5 * BYTES_PER_XDR_UNIT;
	ptr = XDR_INLINE(xdrs, in_size);

	if (ptr != NULL) {
		len = (xdrs->x_op == XDR_DECODE) ? *ptr : objp->file.fh3_length;

		if (XDR_CHECKFHSIZE(xdrs, len, in_size)) {
			fhp = (int32_t *)&(objp->file.fh3_u.data);
			if (xdrs->x_op == XDR_DECODE) {
				objp->file.fh3_length = IXDR_GET_U_INT32(ptr);
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp = *ptr++;
				IXDR_GET_U_HYPER(ptr, objp->offset);
				objp->count = IXDR_GET_U_INT32(ptr);
				objp->stable = IXDR_GET_ENUM(ptr,
						enum stable_how);
				if (xdrs->x_ops == &xdrmblk_ops)
					return (xdrmblk_getmblk(xdrs,
					&objp->mblk,
					(uint_t *)&objp->data.data_len));
				/*
				 * It is just as efficient to xdr_bytes
				 * an array of unknown length as to inline
				 * copy it.
				 */
				return (xdr_bytes(xdrs, &objp->data.data_val,
						(uint_t *)&objp->data.data_len,
						nfs3tsize()));
			}

			if (xdrs->x_op == XDR_ENCODE) {
				IXDR_PUT_U_INT32(ptr, objp->file.fh3_length);
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp;
				IXDR_PUT_U_HYPER(ptr, objp->offset);
				IXDR_PUT_U_INT32(ptr, objp->count);
				IXDR_PUT_ENUM(ptr, objp->stable);
				return (xdr_bytes(xdrs,
					(char **)&objp->data.data_val,
					(uint_t *)&objp->data.data_len,
					nfs3tsize()));
			}

			ASSERT(xdrs->x_op == XDR_FREE);
			if (objp->data.data_val != NULL) {
				kmem_free(objp->data.data_val,
					(uint_t)objp->data.data_len);
				objp->data.data_val = NULL;
			}
			return (TRUE);
		}
	}

	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
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
		/* Else fall thru for the xdr_bytes(). */
	}

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
	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
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
	int32_t *ptr;
	int32_t *fhp;
	uint_t in_size;
	int len;

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	in_size = RNDUP(sizeof (fhandle_t)) + NFS3_COOKIEVERFSIZE +
		4 * BYTES_PER_XDR_UNIT;
	ptr = XDR_INLINE(xdrs, in_size);

	if (ptr != NULL) {
		len = (xdrs->x_op == XDR_DECODE) ? *ptr : objp->dir.fh3_length;

		if (XDR_CHECKFHSIZE(xdrs, len, in_size)) {

			fhp = (int32_t *)&(objp->dir.fh3_u.data);

			if (xdrs->x_op == XDR_DECODE) {
				objp->dir.fh3_length = IXDR_GET_U_INT32(ptr);
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp = *ptr++;
				IXDR_GET_U_HYPER(ptr, objp->cookie);
				/*
				 * cookieverf is really an opaque 8 byte
				 * quantity, but we will treat it as a
				 * hyper for efficiency, the cost of
				 * a byteswap here saves bcopys elsewhere
				 */
				IXDR_GET_U_HYPER(ptr, objp->cookieverf);
				objp->count = IXDR_GET_U_INT32(ptr);
			} else {
				IXDR_PUT_U_INT32(ptr, objp->dir.fh3_length);
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp;
				IXDR_PUT_U_HYPER(ptr, objp->cookie);
				/*
				 * cookieverf is really an opaque 8 byte
				 * quantity, but we will treat it as a
				 * hyper for efficiency, the cost of
				 * a byteswap here saves bcopys elsewhere
				 */
				IXDR_PUT_U_HYPER(ptr, objp->cookieverf);
				IXDR_PUT_U_INT32(ptr, objp->count);
			}
			return (TRUE);
		}
	}

	if (!xdr_nfs_fh3(xdrs, &objp->dir))
		return (FALSE);
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
	int32_t *ptr;
	int32_t *fhp;
	uint_t in_size;
	int len;

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	in_size = RNDUP(sizeof (fhandle_t)) + NFS3_COOKIEVERFSIZE +
		5 * BYTES_PER_XDR_UNIT;

	ptr = XDR_INLINE(xdrs, in_size);
	if (ptr != NULL) {
		len = (xdrs->x_op == XDR_DECODE) ? *ptr : objp->dir.fh3_length;

		if (XDR_CHECKFHSIZE(xdrs, len, in_size)) {

			fhp = (int32_t *)&(objp->dir.fh3_u.data);

			if (xdrs->x_op == XDR_DECODE) {
				objp->dir.fh3_length = IXDR_GET_U_INT32(ptr);
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp = *ptr++;
				IXDR_GET_U_HYPER(ptr, objp->cookie);
				/*
				 * cookieverf is really an opaque 8 byte
				 * quantity, but we will treat it as a
				 * hyper for efficiency, the cost of
				 * a byteswap here saves bcopys elsewhere
				 */
				IXDR_GET_U_HYPER(ptr, objp->cookieverf);
				objp->dircount = IXDR_GET_U_INT32(ptr);
				objp->maxcount = IXDR_GET_U_INT32(ptr);
			} else {
				IXDR_PUT_U_INT32(ptr, objp->dir.fh3_length);
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp;
				IXDR_PUT_U_HYPER(ptr, objp->cookie);
				/*
				 * cookieverf is really an opaque 8 byte
				 * quantity, but we will treat it as a
				 * hyper for efficiency, the cost of
				 * a byteswap here saves bcopys elsewhere
				 */
				IXDR_PUT_U_HYPER(ptr, objp->cookieverf);
				IXDR_PUT_U_INT32(ptr, objp->dircount);
				IXDR_PUT_U_INT32(ptr, objp->maxcount);
			}
			return (TRUE);
		}
	}

	if (!xdr_nfs_fh3(xdrs, &objp->dir))
		return (FALSE);
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
	int32_t *ptr;
	int32_t *fhp;
	int len;
	uint_t in_size;

	if (xdrs->x_op == XDR_FREE)
		return (TRUE);

	in_size = RNDUP(sizeof (fhandle_t)) +	4 * BYTES_PER_XDR_UNIT;
	ptr = XDR_INLINE(xdrs, in_size);

	if (ptr != NULL) {
		len = (xdrs->x_op == XDR_DECODE) ? *ptr : objp->file.fh3_length;

		if (XDR_CHECKFHSIZE(xdrs, len, in_size)) {
			fhp = (int32_t *)&(objp->file.fh3_u.data);
			if (xdrs->x_op == XDR_DECODE) {
				objp->file.fh3_length = IXDR_GET_U_INT32(ptr);
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp++ = *ptr++;
				*fhp = *ptr++;
				IXDR_GET_U_HYPER(ptr, objp->offset);
				objp->count = IXDR_GET_U_INT32(ptr);
			} else {
				IXDR_PUT_U_INT32(ptr, objp->file.fh3_length);
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp++;
				*ptr++ = *fhp;
				IXDR_PUT_U_HYPER(ptr, objp->offset);
				IXDR_PUT_U_INT32(ptr, objp->count);
			}
			return (TRUE);
		}
	}

	if (!xdr_nfs_fh3(xdrs, &objp->file))
		return (FALSE);
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
