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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Originally generated using rpcgen.
 */

#include "mt.h"
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>

bool_t
xdr_nis_attr(XDR *xdrs, nis_attr *objp)
{
	if (!xdr_string(xdrs, &objp->zattr_ndx, ~0))
		return (FALSE);
	return (xdr_bytes(xdrs, (char **)&objp->zattr_val.zattr_val_val,
		(uint_t *)&objp->zattr_val.zattr_val_len, ~0));
}

bool_t
xdr_nis_name(XDR *xdrs, nis_name *objp)
{
	return (xdr_string(xdrs, objp, ~0));
}

bool_t
xdr_zotypes(XDR *xdrs, zotypes *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
xdr_nstype(XDR *xdrs, nstype *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
xdr_oar_mask(XDR *xdrs, oar_mask *objp)
{
	if (!xdr_u_int(xdrs, &objp->oa_rights))
		return (FALSE);
	return (xdr_zotypes(xdrs, &objp->oa_otype));
}

bool_t
xdr_endpoint(XDR *xdrs, endpoint *objp)
{
	if (!xdr_string(xdrs, &objp->uaddr, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->family, ~0))
		return (FALSE);
	return (xdr_string(xdrs, &objp->proto, ~0));
}

bool_t
xdr_nis_server(XDR *xdrs, nis_server *objp)
{
	if (!xdr_nis_name(xdrs, &objp->name))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->ep.ep_val,
			(uint_t *)&objp->ep.ep_len, ~0,
			sizeof (endpoint), (xdrproc_t)xdr_endpoint))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->key_type))
		return (FALSE);
	return (xdr_netobj(xdrs, &objp->pkey));
}

bool_t
xdr_directory_obj(XDR *xdrs, directory_obj *objp)
{
	if (!xdr_nis_name(xdrs, &objp->do_name))
		return (FALSE);
	if (!xdr_nstype(xdrs, &objp->do_type))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->do_servers.do_servers_val,
			(uint_t *)&objp->do_servers.do_servers_len, ~0,
			sizeof (nis_server), (xdrproc_t)xdr_nis_server))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->do_ttl))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->do_armask.do_armask_val,
		(uint_t *)&objp->do_armask.do_armask_len, ~0,
		sizeof (oar_mask), (xdrproc_t)xdr_oar_mask));
}

bool_t
xdr_entry_col(XDR *xdrs, entry_col *objp)
{
	if (!xdr_u_int(xdrs, &objp->ec_flags))
		return (FALSE);
	return (xdr_bytes(xdrs, (char **)&objp->ec_value.ec_value_val,
		(uint_t *)&objp->ec_value.ec_value_len, ~0));
}

bool_t
xdr_entry_obj(XDR *xdrs, entry_obj *objp)
{
	if (!xdr_string(xdrs, &objp->en_type, ~0))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->en_cols.en_cols_val,
		(uint_t *)&objp->en_cols.en_cols_len, ~0,
		sizeof (entry_col), (xdrproc_t)xdr_entry_col));
}

bool_t
xdr_group_obj(XDR *xdrs, group_obj *objp)
{
	if (!xdr_u_int(xdrs, &objp->gr_flags))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->gr_members.gr_members_val,
		(uint_t *)&objp->gr_members.gr_members_len, ~0,
		sizeof (nis_name), (xdrproc_t)xdr_nis_name));
}

bool_t
xdr_link_obj(XDR *xdrs, link_obj *objp)
{
	if (!xdr_zotypes(xdrs, &objp->li_rtype))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->li_attrs.li_attrs_val,
			(uint_t *)&objp->li_attrs.li_attrs_len, ~0,
			sizeof (nis_attr), (xdrproc_t)xdr_nis_attr))
		return (FALSE);
	return (xdr_nis_name(xdrs, &objp->li_name));
}

bool_t
xdr_table_col(XDR *xdrs, table_col *objp)
{
	if (!xdr_string(xdrs, &objp->tc_name, 64))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->tc_flags))
		return (FALSE);
	return (xdr_u_int(xdrs, &objp->tc_rights));
}

bool_t
xdr_table_obj(XDR *xdrs, table_obj *objp)
{
	if (!xdr_string(xdrs, &objp->ta_type, 64))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->ta_maxcol))
		return (FALSE);
	if (!xdr_u_char(xdrs, &objp->ta_sep))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->ta_cols.ta_cols_val,
			(uint_t *)&objp->ta_cols.ta_cols_len, ~0,
			sizeof (table_col), (xdrproc_t)xdr_table_col))
		return (FALSE);
	return (xdr_string(xdrs, &objp->ta_path, ~0));
}

bool_t
xdr_objdata(XDR *xdrs, objdata *objp)
{
	if (!xdr_zotypes(xdrs, &objp->zo_type))
		return (FALSE);

	switch (objp->zo_type) {
	case NIS_DIRECTORY_OBJ:
		return (xdr_directory_obj(xdrs, &objp->objdata_u.di_data));
	case NIS_GROUP_OBJ:
		return (xdr_group_obj(xdrs, &objp->objdata_u.gr_data));
	case NIS_TABLE_OBJ:
		return (xdr_table_obj(xdrs, &objp->objdata_u.ta_data));
	case NIS_ENTRY_OBJ:
		return (xdr_entry_obj(xdrs, &objp->objdata_u.en_data));
	case NIS_LINK_OBJ:
		return (xdr_link_obj(xdrs, &objp->objdata_u.li_data));
	case NIS_PRIVATE_OBJ:
		return (xdr_bytes(xdrs,
			(char **)&objp->objdata_u.po_data.po_data_val,
			(uint_t *)&objp->objdata_u.po_data.po_data_len, ~0));
	case NIS_NO_OBJ:
		return (TRUE);
	case NIS_BOGUS_OBJ:
		return (TRUE);
	}
	return (TRUE);
}

bool_t
xdr_nis_oid(XDR *xdrs, nis_oid *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->ctime))
		return (FALSE);
	return (xdr_uint32_t(xdrs, &objp->mtime));
}

bool_t
xdr_nis_object(XDR *xdrs, nis_object *objp)
{
	if (!xdr_nis_oid(xdrs, &objp->zo_oid))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->zo_name))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->zo_owner))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->zo_group))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->zo_domain))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->zo_access))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->zo_ttl))
		return (FALSE);
	return (xdr_objdata(xdrs, &objp->zo_data));
}

bool_t
xdr_nis_error(XDR *xdrs, nis_error *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
xdr_nis_result(XDR *xdrs, nis_result *objp)
{
	if (!xdr_nis_error(xdrs, &objp->status))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->objects.objects_val,
			(uint_t *)&objp->objects.objects_len, ~0,
			sizeof (nis_object), (xdrproc_t)xdr_nis_object))
		return (FALSE);
	if (!xdr_netobj(xdrs, &objp->cookie))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->zticks))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->dticks))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->aticks))
		return (FALSE);
	return (xdr_uint32_t(xdrs, &objp->cticks));
}

bool_t
xdr_ns_request(XDR *xdrs, ns_request *objp)
{
	if (!xdr_nis_name(xdrs, &objp->ns_name))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->ns_object.ns_object_val,
		(uint_t *)&objp->ns_object.ns_object_len, 1,
		sizeof (nis_object), (xdrproc_t)xdr_nis_object));
}

bool_t
xdr_ib_request(XDR *xdrs, ib_request *objp)
{
	if (!xdr_nis_name(xdrs, &objp->ibr_name))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->ibr_srch.ibr_srch_val,
			(uint_t *)&objp->ibr_srch.ibr_srch_len, ~0,
			sizeof (nis_attr), (xdrproc_t)xdr_nis_attr))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->ibr_flags))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->ibr_obj.ibr_obj_val,
			(uint_t *)&objp->ibr_obj.ibr_obj_len, 1,
			sizeof (nis_object), (xdrproc_t)xdr_nis_object))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->ibr_cbhost.ibr_cbhost_val,
			(uint_t *)&objp->ibr_cbhost.ibr_cbhost_len, 1,
			sizeof (nis_server), (xdrproc_t)xdr_nis_server))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->ibr_bufsize))
		return (FALSE);
	return (xdr_netobj(xdrs, &objp->ibr_cookie));
}

bool_t
xdr_ping_args(XDR *xdrs, ping_args *objp)
{
	if (!xdr_nis_name(xdrs, &objp->dir))
		return (FALSE);
	return (xdr_uint32_t(xdrs, &objp->stamp));
}

bool_t
xdr_log_entry_t(XDR *xdrs, log_entry_t *objp)
{
	return (xdr_enum(xdrs, (enum_t *)objp));
}

bool_t
xdr_log_entry(XDR *xdrs, log_entry *objp)
{
	if (!xdr_uint32_t(xdrs, &objp->le_time))
		return (FALSE);
	if (!xdr_log_entry_t(xdrs, &objp->le_type))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->le_princp))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->le_name))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->le_attrs.le_attrs_val,
			(uint_t *)&objp->le_attrs.le_attrs_len, ~0,
			sizeof (nis_attr), (xdrproc_t)xdr_nis_attr))
		return (FALSE);
	return (xdr_nis_object(xdrs, &objp->le_object));
}

bool_t
xdr_log_result(XDR *xdrs, log_result *objp)
{
	if (!xdr_nis_error(xdrs, &objp->lr_status))
		return (FALSE);
	if (!xdr_netobj(xdrs, &objp->lr_cookie))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->lr_entries.lr_entries_val,
		(uint_t *)&objp->lr_entries.lr_entries_len, ~0,
		sizeof (log_entry), (xdrproc_t)xdr_log_entry));
}

bool_t
xdr_cp_result(XDR *xdrs, cp_result *objp)
{
	if (!xdr_nis_error(xdrs, &objp->cp_status))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->cp_zticks))
		return (FALSE);
	return (xdr_uint32_t(xdrs, &objp->cp_dticks));
}

bool_t
xdr_nis_tag(XDR *xdrs, nis_tag *objp)
{
	if (!xdr_u_int(xdrs, &objp->tag_type))
		return (FALSE);
	return (xdr_string(xdrs, &objp->tag_val, ~0));
}

bool_t
xdr_nis_taglist(XDR *xdrs, nis_taglist *objp)
{
	return (xdr_array(xdrs, (char **)&objp->tags.tags_val,
		(uint_t *)&objp->tags.tags_len, ~0,
		sizeof (nis_tag), (xdrproc_t)xdr_nis_tag));
}

bool_t
xdr_dump_args(XDR *xdrs, dump_args *objp)
{
	if (!xdr_nis_name(xdrs, &objp->da_dir))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->da_time))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->da_cbhost.da_cbhost_val,
		(uint_t *)&objp->da_cbhost.da_cbhost_len, 1,
		sizeof (nis_server), (xdrproc_t)xdr_nis_server));
}

bool_t
xdr_fd_args(XDR *xdrs, fd_args *objp)
{
	if (!xdr_nis_name(xdrs, &objp->dir_name))
		return (FALSE);
	return (xdr_nis_name(xdrs, &objp->requester));
}

bool_t
xdr_fd_result(XDR *xdrs, fd_result *objp)
{
	if (!xdr_nis_error(xdrs, &objp->status))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->source))
		return (FALSE);
	if (!xdr_bytes(xdrs, (char **)&objp->dir_data.dir_data_val,
			(uint_t *)&objp->dir_data.dir_data_len, ~0))
		return (FALSE);
	return (xdr_bytes(xdrs, (char **)&objp->signature.signature_val,
		(uint_t *)&objp->signature.signature_len, ~0));
}
/*
 * Structures used for server binding.
 */

bool_t
xdr_nis_bound_endpoint(XDR *xdrs, nis_bound_endpoint *objp)
{
	rpc_inline_t *buf;

	if (xdrs->x_op == XDR_ENCODE) {
		if (!xdr_endpoint(xdrs, &objp->ep))
			return (FALSE);
		buf = XDR_INLINE(xdrs, 5 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_int(xdrs, &objp->generation))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->rank))
				return (FALSE);
			if (!xdr_u_int(xdrs, &objp->flags))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->hostnum))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->epnum))
				return (FALSE);

		} else {
#if defined(_LP64)
			IXDR_PUT_INT32(buf, objp->generation);
			IXDR_PUT_INT32(buf, objp->rank);
			IXDR_PUT_U_INT32(buf, objp->flags);
			IXDR_PUT_INT32(buf, objp->hostnum);
			IXDR_PUT_INT32(buf, objp->epnum);
#else
			IXDR_PUT_LONG(buf, objp->generation);
			IXDR_PUT_LONG(buf, objp->rank);
			IXDR_PUT_U_LONG(buf, objp->flags);
			IXDR_PUT_LONG(buf, objp->hostnum);
			IXDR_PUT_LONG(buf, objp->epnum);
#endif
		}
		if (!xdr_nis_name(xdrs, &objp->uaddr))
			return (FALSE);
		return (xdr_endpoint(xdrs, &objp->cbep));
	}
	if (xdrs->x_op == XDR_DECODE) {
		if (!xdr_endpoint(xdrs, &objp->ep))
			return (FALSE);
		buf = XDR_INLINE(xdrs, 5 * BYTES_PER_XDR_UNIT);
		if (buf == NULL) {
			if (!xdr_int(xdrs, &objp->generation))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->rank))
				return (FALSE);
			if (!xdr_u_int(xdrs, &objp->flags))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->hostnum))
				return (FALSE);
			if (!xdr_int(xdrs, &objp->epnum))
				return (FALSE);

		} else {
#if defined(_LP64)
			objp->generation = IXDR_GET_INT32(buf);
			objp->rank = IXDR_GET_INT32(buf);
			objp->flags = IXDR_GET_U_INT32(buf);
			objp->hostnum = IXDR_GET_INT32(buf);
			objp->epnum = IXDR_GET_INT32(buf);
#else
			objp->generation = IXDR_GET_LONG(buf);
			objp->rank = IXDR_GET_LONG(buf);
			objp->flags = IXDR_GET_U_LONG(buf);
			objp->hostnum = IXDR_GET_LONG(buf);
			objp->epnum = IXDR_GET_LONG(buf);
#endif
		}
		if (!xdr_nis_name(xdrs, &objp->uaddr))
			return (FALSE);
		return (xdr_endpoint(xdrs, &objp->cbep));
	}

	if (!xdr_endpoint(xdrs, &objp->ep))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->generation))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->rank))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->flags))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->hostnum))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->epnum))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->uaddr))
		return (FALSE);
	return (xdr_endpoint(xdrs, &objp->cbep));
}

bool_t
xdr_nis_bound_directory(XDR *xdrs, nis_bound_directory *objp)
{
	if (!xdr_int(xdrs, &objp->generation))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->min_rank))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->optimal_rank))
		return (FALSE);
	if (!xdr_directory_obj(xdrs, &objp->dobj))
		return (FALSE);
	return (xdr_array(xdrs, (char **)&objp->BEP.BEP_val,
		(uint_t *)&objp->BEP.BEP_len, ~0,
		sizeof (nis_bound_endpoint),
		(xdrproc_t)xdr_nis_bound_endpoint));
}

bool_t
xdr_nis_active_endpoint(XDR *xdrs, nis_active_endpoint *objp)
{
	if (!xdr_endpoint(xdrs, &objp->ep))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->hostname))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->rank))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->uaddr_generation))
		return (FALSE);
	if (!xdr_nis_name(xdrs, &objp->uaddr))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->cbep_generation))
		return (FALSE);
	return (xdr_endpoint(xdrs, &objp->cbep));
}
