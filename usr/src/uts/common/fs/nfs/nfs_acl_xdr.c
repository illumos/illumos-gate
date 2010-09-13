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
 */

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
#include <sys/acl.h>

#include <rpc/types.h>
#include <rpc/xdr.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs_acl.h>

/*
 * These are the XDR routines used to serialize and deserialize
 * the various structures passed as parameters accross the network
 * between ACL clients and servers.
 */

bool_t
xdr_uid(XDR *xdrs, uid32_t *objp)
{
	if (!xdr_u_int(xdrs, objp))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_o_mode(XDR *xdrs, o_mode *objp)
{

	if (!xdr_u_short(xdrs, (ushort_t *)objp))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_aclent(XDR *xdrs, aclent_t *objp)
{

	if (!xdr_int(xdrs, &objp->a_type))
		return (FALSE);
	if (!xdr_uid(xdrs, &objp->a_id))
		return (FALSE);
	if (!xdr_o_mode(xdrs, &objp->a_perm))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_secattr(XDR *xdrs, vsecattr_t *objp)
{
	uint_t count;

	if (!xdr_u_int(xdrs, &objp->vsa_mask))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->vsa_aclcnt))
		return (FALSE);
	if (objp->vsa_aclentp != NULL)
		count = (uint_t)objp->vsa_aclcnt;
	else
		count = 0;
	if (!xdr_array(xdrs, (char **)&objp->vsa_aclentp, &count,
	    NFS_ACL_MAX_ENTRIES, sizeof (aclent_t), (xdrproc_t)xdr_aclent))
		return (FALSE);
	if (count != 0 && count != (uint_t)objp->vsa_aclcnt) {
		/*
		 * Assign the actual array size to vsa_aclcnt before
		 * aborting on error
		 */
		objp->vsa_aclcnt = (int)count;
		return (FALSE);
	}
	if (!xdr_int(xdrs, &objp->vsa_dfaclcnt))
		return (FALSE);
	if (objp->vsa_dfaclentp != NULL)
		count = (uint_t)objp->vsa_dfaclcnt;
	else
		count = 0;
	if (!xdr_array(xdrs, (char **)&objp->vsa_dfaclentp, &count,
	    NFS_ACL_MAX_ENTRIES, sizeof (aclent_t), (xdrproc_t)xdr_aclent))
		return (FALSE);
	if (count != 0 && count != (uint_t)objp->vsa_dfaclcnt) {
		/*
		 * Assign the actual array size to vsa_dfaclcnt before
		 * aborting on error
		 */
		objp->vsa_dfaclcnt = (int)count;
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_GETACL2args(XDR *xdrs, GETACL2args *objp)
{

	if (!xdr_fhandle(xdrs, &objp->fh))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->mask))
		return (FALSE);
	return (TRUE);
}
bool_t
xdr_fastGETACL2args(XDR *xdrs, GETACL2args **objpp)
{
	int32_t *ptr;
#ifdef _LITTLE_ENDIAN
	GETACL2args *objp;
#endif

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	ptr = XDR_INLINE(xdrs, RNDUP(sizeof (GETACL2args)));
	if (ptr != NULL) {
		*objpp = (GETACL2args *)ptr;
#ifdef _LITTLE_ENDIAN
		objp = (GETACL2args *)ptr;
		objp->mask = ntohl(objp->mask);
#endif
		return (TRUE);
	}

	return (FALSE);
}

bool_t
xdr_GETACL2resok(XDR *xdrs, GETACL2resok *objp)
{

	if (!xdr_fattr(xdrs, &objp->attr))
		return (FALSE);
	if (!xdr_secattr(xdrs, &objp->acl))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_GETACL2res(XDR *xdrs, GETACL2res *objp)
{

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS_OK:
		if (!xdr_GETACL2resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_SETACL2args(XDR *xdrs, SETACL2args *objp)
{

	if (!xdr_fhandle(xdrs, &objp->fh))
		return (FALSE);
	if (!xdr_secattr(xdrs, &objp->acl))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_SETACL2resok(XDR *xdrs, SETACL2resok *objp)
{

	if (!xdr_fattr(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}
#ifdef _LITTLE_ENDIAN
bool_t
xdr_fastSETACL2resok(XDR *xdrs, SETACL2resok *objp)
{

	if (!xdr_fastfattr(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}
#endif

bool_t
xdr_SETACL2res(XDR *xdrs, SETACL2res *objp)
{

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS_OK:
		if (!xdr_SETACL2resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	}
	return (TRUE);
}
#ifdef _LITTLE_ENDIAN
bool_t
xdr_fastSETACL2res(XDR *xdrs, SETACL2res *objp)
{

	if (!xdr_fastenum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS_OK:
		if (!xdr_fastSETACL2resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	}
	return (TRUE);
}
#endif

bool_t
xdr_GETATTR2args(XDR *xdrs, GETATTR2args *objp)
{

	if (!xdr_fhandle(xdrs, &objp->fh))
		return (FALSE);
	return (TRUE);
}
bool_t
xdr_fastGETATTR2args(XDR *xdrs, GETATTR2args **objpp)
{
	int32_t *ptr;

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	ptr = XDR_INLINE(xdrs, RNDUP(sizeof (GETATTR2args)));
	if (ptr != NULL) {
		*objpp = (GETATTR2args *)ptr;
		return (TRUE);
	}

	return (FALSE);
}

bool_t
xdr_GETATTR2resok(XDR *xdrs, GETATTR2resok *objp)
{

	if (!xdr_fattr(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}
#ifdef _LITTLE_ENDIAN
bool_t
xdr_fastGETATTR2resok(XDR *xdrs, GETATTR2resok *objp)
{

	if (!xdr_fastfattr(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}
#endif

bool_t
xdr_GETATTR2res(XDR *xdrs, GETATTR2res *objp)
{

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS_OK:
		if (!xdr_GETATTR2resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	}
	return (TRUE);
}
#ifdef _LITTLE_ENDIAN
bool_t
xdr_fastGETATTR2res(XDR *xdrs, GETATTR2res *objp)
{

	if (!xdr_fastenum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS_OK:
		if (!xdr_fastGETATTR2resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	}
	return (TRUE);
}
#endif

bool_t
xdr_ACCESS2args(XDR *xdrs, ACCESS2args *objp)
{

	if (!xdr_fhandle(xdrs, &objp->fh))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->access))
		return (FALSE);
	return (TRUE);
}
bool_t
xdr_fastACCESS2args(XDR *xdrs, ACCESS2args **objpp)
{
	int32_t *ptr;
#ifdef _LITTLE_ENDIAN
	ACCESS2args *objp;
#endif

	if (xdrs->x_op != XDR_DECODE)
		return (FALSE);

	ptr = XDR_INLINE(xdrs, RNDUP(sizeof (ACCESS2args)));
	if (ptr != NULL) {
		*objpp = (ACCESS2args *)ptr;
#ifdef _LITTLE_ENDIAN
		objp = (ACCESS2args *)ptr;
		objp->access = ntohl(objp->access);
#endif
		return (TRUE);
	}

	return (FALSE);
}

bool_t
xdr_ACCESS2resok(XDR *xdrs, ACCESS2resok *objp)
{

	if (!xdr_fattr(xdrs, &objp->attr))
		return (FALSE);
	if (!xdr_uint32(xdrs, &objp->access))
		return (FALSE);
	return (TRUE);
}
#ifdef _LITTLE_ENDIAN
bool_t
xdr_fastACCESS2resok(XDR *xdrs, ACCESS2resok *objp)
{

	if (!xdr_fastfattr(xdrs, &objp->attr))
		return (FALSE);
	objp->access = ntohl(objp->access);
	return (TRUE);
}
#endif

bool_t
xdr_ACCESS2res(XDR *xdrs, ACCESS2res *objp)
{

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS_OK:
		if (!xdr_ACCESS2resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	}
	return (TRUE);
}
#ifdef _LITTLE_ENDIAN
bool_t
xdr_fastACCESS2res(XDR *xdrs, ACCESS2res *objp)
{

	if (!xdr_fastenum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS_OK:
		if (!xdr_fastACCESS2resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	}
	return (TRUE);
}
#endif

bool_t
xdr_GETXATTRDIR2args(XDR *xdrs, GETXATTRDIR2args *objp)
{
	if (!xdr_fhandle(xdrs, &objp->fh))
		return (FALSE);
	if (!xdr_bool(xdrs, &objp->create))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_GETXATTRDIR2resok(XDR *xdrs, GETXATTRDIR2resok *objp)
{
	if (!xdr_fhandle(xdrs, &objp->fh))
		return (FALSE);
	if (!xdr_fattr(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_GETXATTRDIR2res(XDR *xdrs, GETXATTRDIR2res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS_OK:
		if (!xdr_GETXATTRDIR2resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_GETACL3args(XDR *xdrs, GETACL3args *objp)
{

	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->fh))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->fh))
			return (FALSE);
		break;
	}
	if (!xdr_u_int(xdrs, &objp->mask))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_GETACL3resok(XDR *xdrs, GETACL3resok *objp)
{

	if (!xdr_post_op_attr(xdrs, &objp->attr))
		return (FALSE);
	if (!xdr_secattr(xdrs, &objp->acl))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_GETACL3resfail(XDR *xdrs, GETACL3resfail *objp)
{

	if (!xdr_post_op_attr(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_GETACL3res(XDR *xdrs, GETACL3res *objp)
{

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_GETACL3resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	default:
		if (!xdr_GETACL3resfail(xdrs, &objp->resfail))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_SETACL3args(XDR *xdrs, SETACL3args *objp)
{

	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->fh))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->fh))
			return (FALSE);
		break;
	}
	if (!xdr_secattr(xdrs, &objp->acl))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_SETACL3resok(XDR *xdrs, SETACL3resok *objp)
{

	if (!xdr_post_op_attr(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_SETACL3resfail(XDR *xdrs, SETACL3resfail *objp)
{

	if (!xdr_post_op_attr(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_SETACL3res(XDR *xdrs, SETACL3res *objp)
{

	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS3_OK:
		if (!xdr_SETACL3resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	default:
		if (!xdr_SETACL3resfail(xdrs, &objp->resfail))
			return (FALSE);
		break;
	}
	return (TRUE);
}

bool_t
xdr_GETXATTRDIR3args(XDR *xdrs, GETXATTRDIR3args *objp)
{
	switch (xdrs->x_op) {
	case XDR_FREE:
	case XDR_ENCODE:
		if (!xdr_nfs_fh3(xdrs, &objp->fh))
			return (FALSE);
		break;
	case XDR_DECODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->fh))
			return (FALSE);
		break;
	}
	if (!xdr_bool(xdrs, &objp->create))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_GETXATTRDIR3resok(XDR *xdrs, GETXATTRDIR3resok *objp)
{
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		if (!xdr_nfs_fh3_server(xdrs, &objp->fh))
			return (FALSE);
		break;
	case XDR_FREE:
	case XDR_DECODE:
		if (!xdr_nfs_fh3(xdrs, &objp->fh))
			return (FALSE);
		break;
	}
	if (!xdr_post_op_attr(xdrs, &objp->attr))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_GETXATTRDIR3res(XDR *xdrs, GETXATTRDIR3res *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->status))
		return (FALSE);
	switch (objp->status) {
	case NFS_OK:
		if (!xdr_GETXATTRDIR3resok(xdrs, &objp->resok))
			return (FALSE);
		break;
	}
	return (TRUE);
}
