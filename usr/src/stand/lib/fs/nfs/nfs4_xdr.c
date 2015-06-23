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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/salib.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs4_prot.h>
#include "nfs_inet.h"

#define	dprintf if (boothowto & RB_DEBUG) printf

/*
 * XDR routines for NFSv4 ops.
 */
static bool_t
xdr_b_utf8string(XDR *xdrs, utf8string *objp)
{
	return (xdr_bytes(xdrs, (char **)&objp->utf8string_val,
	    (uint_t *)&objp->utf8string_len, NFS4_MAX_UTF8STRING));
}

static bool_t
xdr_nfs_bfh4(XDR *xdrs, struct nfs_bfh4 *objp)
{
	char *data = (char *)&objp->data;
	return (xdr_bytes(xdrs, (char **)&data, (uint_t *)&objp->len,
	    NFS4_FHSIZE));
}

static bool_t
xdr_b_putfh4_args(XDR *xdrs, putfh4arg_t *objp)
{
	if (!xdr_u_int(xdrs, (uint_t *)&objp->pf_opnum))
		return (FALSE);
	return (xdr_nfs_bfh4(xdrs, (struct nfs_bfh4 *)&objp->pf_filehandle));
}

/*
 * Common xdr routines for compound.  Let the specific op routines handle
 * op specific portions of the compound.
 */
static bool_t
xdr_b_compound_args(XDR *xdrs, b_compound_t *objp)
{
	if (!xdr_b_utf8string(xdrs, &objp->ca_tag)) {
		return (FALSE);
	}
	if (!xdr_u_int(xdrs, &objp->ca_minorversion))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->ca_argarray_len))
		return (FALSE);
	if (objp->ca_isputrootfh)
		return (xdr_u_int(xdrs, &objp->ca_opputfh.pf_opnum));
	return (xdr_b_putfh4_args(xdrs, &objp->ca_opputfh));
}

static bool_t
xdr_b_compound_res(XDR *xdrs, b_compound_t *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->cr_status))
		return (FALSE);
	if (!xdr_b_utf8string(xdrs, &objp->cr_tag))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->cr_resarray_len))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->cr_opputfh))
		return (FALSE);
	return (xdr_enum(xdrs, (enum_t *)&objp->cr_putfh_status));
}

static bool_t
xdr_b_bitmap4(XDR *xdrs, b_bitmap4_t *objp)
{
	char *arp = (char *)&objp->b_bitmap_val;
	return (xdr_array(xdrs, (char **)&arp,
	    (uint_t *)&objp->b_bitmap_len, ~0,
	    sizeof (uint_t), (xdrproc_t)xdr_u_int));
}

static bool_t
xdr_b_stateid4(XDR *xdrs, stateid4 *objp)
{
	if (!xdr_u_int(xdrs, (uint_t *)&objp->seqid))
		return (FALSE);
	return (xdr_opaque(xdrs, objp->other, NFS4_OTHER_SIZE));
}

bool_t
xdr_getattr4_args(XDR *xdrs, getattr4arg_t *objp)
{
	if (!xdr_b_compound_args(xdrs, (b_compound_t *)&objp->ga_arg))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->ga_opgetattr))
		return (FALSE);
	return (xdr_b_bitmap4(xdrs, (b_bitmap4_t *)&objp->ga_attr_req));
}

static bool_t
xdr_b_getattr_res_common(XDR *xdrs, getattrres_cmn_t *objp)
{
	if (!xdr_u_int(xdrs, (uint_t *)&objp->gc_opgetattr))
		return (FALSE);
	if (!xdr_enum(xdrs, (enum_t *)&objp->gc_attr_status))
		return (FALSE);

	/*
	 * If the getattr suceeded, proceed and begin to decode the attributes.
	 */
	if (objp->gc_attr_status == NFS4_OK) {
		char		attrvals[sizeof (b_fattr4_t)];
		char		*ap = attrvals;

		if (!xdr_b_bitmap4(xdrs, (b_bitmap4_t *)&objp->gc_retattr))
			return (FALSE);

		bzero(&attrvals, sizeof (attrvals));
		if (!xdr_bytes(xdrs, (char **)&ap,
		    (uint_t *)&objp->gc_attrlist_len, sizeof (b_fattr4_t)))
			return (FALSE);
#ifdef DEBUG
		printf("xdr_b_getattr_res_common: attrlist_len = %d\n",
		    objp->gc_attrlist_len);
#endif
		/*
		 * Go through the bitmap and see if the server
		 * sent us anything.
		 */
		if (objp->gc_attrlist_len > 0) {
			XDR		mxdrs;
			b_fattr4_t	*fattrp = &objp->gc_attrs;
			attr4_bitmap1_t bitmap1;
			attr4_bitmap2_t bitmap2;
#ifdef DEBUG
			int i;

			printf("dumping contents of attr buffer\n");
			for (i = 0; i < objp->gc_attrlist_len; i++) {
				printf("[%d] = 0x%x\n", i, ap[i]);
			}
#endif
			bitmap1.word = objp->gc_retattr.b_bitmap_val[0];
			bitmap2.word = objp->gc_retattr.b_bitmap_val[1];

#ifdef DEBUG
			printf("xdr_b_getattr_res_common: bitmap1 = %d "
			    "			bitmap2 = %d\n",
			    bitmap1.word, bitmap2.word);
#endif
			xdrmem_create(&mxdrs, ap, objp->gc_attrlist_len,
			    XDR_DECODE);

			/*
			 * Start with the first bitmap
			 */
			if (bitmap1.word > 0) {
				if (bitmap1.bm_supported_attrs) {
					if (!xdr_b_bitmap4(&mxdrs,
					    (b_bitmap4_t *)&fattrp->
					    b_supported_attrs))
						return (FALSE);
				}

				if (bitmap1.bm_fattr4_type) {
					if (!xdr_enum(&mxdrs,
				(enum_t *)&fattrp->b_fattr4_type)) {
						return (FALSE);
					}
				}
				if (bitmap1.bm_fattr4_size) {
					if (!xdr_u_longlong_t(&mxdrs,
					    (u_longlong_t *)&fattrp->
					    b_fattr4_size))
						return (FALSE);
				}

				if (bitmap1.bm_fattr4_fsid) {
					if (!xdr_u_longlong_t(&mxdrs,
					    (u_longlong_t *)&fattrp->
					    b_fattr4_fsid.major))
						return (FALSE);

					if (!xdr_u_longlong_t(&mxdrs,
					    (u_longlong_t *)&fattrp->
					    b_fattr4_fsid.minor))
						return (FALSE);
				}
				if (bitmap1.bm_fattr4_filehandle) {
					if (!xdr_nfs_bfh4(&mxdrs,
					    (struct nfs_bfh4 *)&fattrp->
					    b_fattr4_filehandle))
						return (FALSE);
				}
				if (bitmap1.bm_fattr4_fileid) {
					if (!xdr_u_longlong_t(&mxdrs,
					    (u_longlong_t *)&fattrp->
					    b_fattr4_fileid))
						return (FALSE);
				}
			}

			/*
			 * Now the second bitmap
			 */
			if (bitmap2.word > 0) {
				if (bitmap2.bm_fattr4_mode) {
					if (!xdr_u_int(&mxdrs, (uint_t *)&objp->
					    gc_attrs.b_fattr4_mode))
						return (FALSE);
				}

				if (bitmap2.bm_fattr4_time_access) {
					if (!xdr_longlong_t(&mxdrs,
					    (longlong_t *)&objp->gc_attrs.
					    b_fattr4_time_access.seconds))
						return (FALSE);
					if (!xdr_u_int(&mxdrs,
					    (uint_t *)&objp->gc_attrs.
					    b_fattr4_time_access.nseconds))
						return (FALSE);
				}

				if (bitmap2.bm_fattr4_time_metadata) {
					if (!xdr_longlong_t(&mxdrs,
					    (longlong_t *)&objp->gc_attrs.
					    b_fattr4_time_metadata.seconds))
						return (FALSE);
					if (!xdr_u_int(&mxdrs,
					    (uint_t *)&objp->gc_attrs.
					    b_fattr4_time_metadata.nseconds))
						return (FALSE);
				}

				if (bitmap2.bm_fattr4_time_modify) {
					if (!xdr_longlong_t(&mxdrs,
					    (longlong_t *)&objp->gc_attrs.
					    b_fattr4_time_modify.seconds))
						return (FALSE);
					if (!xdr_u_int(&mxdrs,
					    (uint_t *)&objp->gc_attrs.
					    b_fattr4_time_modify.nseconds))
						return (FALSE);
				}
			}
		}
	}
	return (TRUE);
}

bool_t
xdr_getattr4_res(XDR *xdrs, getattr4res_t *objp)
{
	if (!xdr_b_compound_res(xdrs, (b_compound_t *)&objp->gr_res))
		return (FALSE);
	return (xdr_b_getattr_res_common(xdrs,
	    (getattrres_cmn_t *)&objp->gr_cmn));
}

bool_t
xdr_lookup4_args(XDR *xdrs, lookup4arg_t *objp)
{
	if (!xdr_b_compound_args(xdrs, (b_compound_t *)&objp->la_arg))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->la_oplookup))
		return (FALSE);
	if (!xdr_b_utf8string(xdrs, (utf8string *)&objp->la_pathname))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->la_opgetattr))
		return (FALSE);
	return (xdr_b_bitmap4(xdrs, (b_bitmap4_t *)&objp->la_attr_req));
}

bool_t
xdr_lookup4_res(XDR *xdrs, lookup4res_t *objp)
{
	if (!xdr_b_compound_res(xdrs, (b_compound_t *)&objp->lr_res))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->lr_oplookup))
		return (FALSE);
	if (!xdr_enum(xdrs, (enum_t *)&objp->lr_lookup_status))
		return (FALSE);
	if (objp->lr_lookup_status == NFS4_OK) {
		return (xdr_b_getattr_res_common(xdrs,
		    (getattrres_cmn_t *)&objp->lr_gcmn));
	}
	return (TRUE);
}

bool_t
xdr_lookupp4_args(XDR *xdrs, lookupp4arg_t *objp)
{
	if (!xdr_b_compound_args(xdrs, (b_compound_t *)&objp->la_arg))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->la_oplookupp))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->la_opgetattr))
		return (FALSE);
	return (xdr_b_bitmap4(xdrs, (b_bitmap4_t *)&objp->la_attr_req));
}

bool_t
xdr_read4_args(XDR *xdrs, read4arg_t *objp)
{
	if (!xdr_b_compound_args(xdrs, (b_compound_t *)&objp->r_arg))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->r_opread))
		return (FALSE);
	if (!xdr_b_stateid4(xdrs, (stateid4 *)&objp->r_stateid))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->r_offset))
		return (FALSE);
	return (xdr_u_int(xdrs, (uint_t *)&objp->r_count));
}

bool_t
xdr_read4_res(XDR *xdrs, read4res_t *objp)
{
	if (!xdr_b_compound_res(xdrs, (b_compound_t *)&objp->r_res))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->r_opread))
		return (FALSE);
	if (!xdr_enum(xdrs, (enum_t *)&objp->r_status))
		return (FALSE);
	if (objp->r_status == NFS4_OK) {
		if (!xdr_bool(xdrs, (bool_t *)&objp->r_eof))
			return (FALSE);
		return (xdr_bytes(xdrs, (char **)&objp->r_data_val,
		    (uint_t *)&objp->r_data_len, ~0));
	}
	return (TRUE);
}

bool_t
xdr_readdir4_args(XDR *xdrs, readdir4arg_t *objp)
{
	if (!xdr_b_compound_args(xdrs, (b_compound_t *)&objp->rd_arg))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->rd_opreaddir))
		return (FALSE);
	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->rd_cookie))
		return (FALSE);
	if (!xdr_opaque(xdrs, objp->rd_cookieverf, NFS4_VERIFIER_SIZE))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->rd_dircount))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->rd_maxcount))
		return (FALSE);
	return (xdr_b_bitmap4(xdrs, (b_bitmap4_t *)&objp->rd_attr_req));
}

static bool_t
xdr_b_entry4(XDR *xdrs, b_entry4_t *objp)
{
	uint_t		attrlen;
	char		attrvals[sizeof (b_fattr4_t)];
	char		*ap = attrvals;
	XDR		mxdrs;

	if (!xdr_u_longlong_t(xdrs, (u_longlong_t *)&objp->b_cookie))
		return (FALSE);
	if (!xdr_b_utf8string(xdrs, &objp->b_name))
		return (FALSE);

	bzero(&attrvals, sizeof (attrvals));
	if (!xdr_bytes(xdrs, (char **)&ap, (uint_t *)&attrlen,
	    sizeof (b_fattr4_t)))
		return (FALSE);

	/*
	 * We are *only* interested in the fileid, so just extract that.
	 */
	if (attrlen < sizeof (uint64_t))
		return (FALSE);

	xdrmem_create(&mxdrs, ap, attrlen, XDR_DECODE);

	if (!xdr_u_longlong_t(&mxdrs, (u_longlong_t *)&objp->b_fileid))
		return (FALSE);
	return (xdr_pointer(xdrs, (char **)&objp->b_nextentry,
	    sizeof (b_entry4_t), (xdrproc_t)xdr_b_entry4));
}

bool_t
xdr_readdir4_res(XDR *xdrs, readdir4res_t *objp)
{
	if (!xdr_b_compound_res(xdrs, (b_compound_t *)&objp->rd_res))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->rd_opreaddir))
		return (FALSE);
	if (!xdr_enum(xdrs, (enum_t *)&objp->rd_status))
		return (FALSE);
	if (objp->rd_status == NFS4_OK) {
		if (!xdr_opaque(xdrs, objp->rd_cookieverf, NFS4_VERIFIER_SIZE))
			return (FALSE);
		if (!xdr_pointer(xdrs, (char **)&objp->rd_entries,
		    sizeof (b_entry4_t), (xdrproc_t)xdr_b_entry4))
			return (FALSE);
		return (xdr_bool(xdrs, &objp->rd_eof));
	}
	return (TRUE);
}

bool_t
xdr_readlink4_args(XDR *xdrs, readlink4arg_t *objp)
{
	if (!xdr_b_compound_args(xdrs, (b_compound_t *)&objp->rl_arg))
		return (FALSE);
	return (xdr_u_int(xdrs, (uint_t *)&objp->rl_opreadlink));
}

bool_t
xdr_readlink4_res(XDR *xdrs, readlink4res_t *objp)
{
	if (!xdr_b_compound_res(xdrs, (b_compound_t *)&objp->rl_res))
		return (FALSE);
	if (!xdr_u_int(xdrs, (uint_t *)&objp->rl_opreadlink))
		return (FALSE);
	if (!xdr_enum(xdrs, (enum_t *)&objp->rl_status))
		return (FALSE);
	if (objp->rl_status == NFS4_OK)
		return (xdr_b_utf8string(xdrs, (utf8string *)&objp->rl_link));
	return (TRUE);
}
