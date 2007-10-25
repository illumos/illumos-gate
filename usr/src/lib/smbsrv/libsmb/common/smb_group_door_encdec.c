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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_door_svc.h>

/*
 * smb_grplist_mkselfrel
 *
 * encode: structure -> flat buffer (buffer size)
 * Pre-condition: obj is non-null.
 */
static uint8_t *
smb_grplist_mkselfrel(ntgrp_list_t *obj, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	if (!obj) {
		syslog(LOG_ERR, "smb_grplist_mkselfrel: invalid parameter");
		return (NULL);
	}
	*len = xdr_sizeof(xdr_ntgrp_list_t, obj);
	buf = (uint8_t *)malloc(*len);

	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);

	if (!xdr_ntgrp_list_t(&xdrs, obj)) {
		syslog(LOG_ERR, "smb_grplist_mkselfrel: XDR encode error");
		free(buf);
		*len = 0;
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

/*
 * smb_grplist_mkabsolute
 *
 * decode: flat buffer -> structure
 */
static ntgrp_list_t *
smb_grplist_mkabsolute(uint8_t *buf, uint32_t len)
{
	ntgrp_list_t *obj;
	XDR xdrs;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);

	if ((obj = (ntgrp_list_t *)
	    malloc(sizeof (ntgrp_list_t))) == 0) {
		syslog(LOG_ERR, "smb_grplist_mkabsolute: resource shortage");
		xdr_destroy(&xdrs);
		return (NULL);
	}
	bzero(obj, sizeof (ntgrp_list_t));
	if (!xdr_ntgrp_list_t(&xdrs, obj)) {
		syslog(LOG_ERR, "smb_grplist_mkabsolute: XDR decode error");
		smb_group_free_list(obj, 1);
		obj = NULL;
	}

	xdr_destroy(&xdrs);
	return (obj);
}

/*
 * smb_grpmemberlist_mkselfrel
 *
 * encode: structure -> flat buffer (buffer size)
 * Pre-condition: obj is non-null.
 */
static uint8_t *
smb_grpmemberlist_mkselfrel(ntgrp_member_list_t *obj, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	if (!obj) {
		syslog(LOG_ERR,
		    "smb_grpmemberlist_mkselfrel: invalid parameter");
		return (NULL);
	}
	*len = xdr_sizeof(xdr_ntgrp_member_list_t, obj);
	buf = (uint8_t *)malloc(*len);
	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);
	if (!xdr_ntgrp_member_list_t(&xdrs, obj)) {
		syslog(LOG_ERR,
		    "smb_grpmemberlist_mkselfrel: XDR encode error");
		free(buf);
		*len = 0;
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

/*
 * ntgrp_list_mkabsolute
 *
 * decode: flat buffer -> structure
 */
static ntgrp_member_list_t *
smb_grpmemberlist_mkabsolute(uint8_t *buf, uint32_t len)
{
	ntgrp_member_list_t *obj = NULL;
	XDR xdrs;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);

	if ((obj = (ntgrp_member_list_t *)
	    malloc(sizeof (ntgrp_member_list_t))) == 0) {
		xdr_destroy(&xdrs);
		syslog(LOG_ERR,
		    "smb_grpmemberlist_mkabsolute: resource shortage");
		return (NULL);
	}
	bzero(obj, sizeof (ntgrp_member_list_t));
	bzero(obj->members, SMB_GROUP_PER_LIST * sizeof (members_list));
	if (!xdr_ntgrp_member_list_t(&xdrs, obj)) {
		syslog(LOG_ERR,
		    "smb_grpmemberlist_mkabsolute: XDR decode error");
		smb_group_free_memberlist(obj, 1);
		obj = NULL;
	}

	xdr_destroy(&xdrs);
	return (obj);
}

/*
 * smb_privlist_mkselfrel
 *
 * encode: structure -> flat buffer (buffer size)
 * Pre-condition: obj is non-null.
 */
static uint8_t *
smb_grpprivlist_mkselfrel(ntpriv_list_t *obj, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	if (!obj) {
		syslog(LOG_ERR,
		    "smb_grpprivlist_mkselfrel: invalid parameter");
		return (NULL);
	}
	*len = xdr_sizeof(xdr_ntpriv_list_t, obj);
	buf = (uint8_t *)malloc(*len);
	if (!buf) {
		syslog(LOG_ERR,
		    "smb_grpprivlist_mkselfrel: resource shortage");
		return (NULL);
	}
	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);
	if (!xdr_ntpriv_list_t(&xdrs, obj)) {
		syslog(LOG_ERR,
		    "smb_grpprivlist_mkselfrel: XDR encode error");
		*len = 0;
		free(buf);
		buf = NULL;
	}
	xdr_destroy(&xdrs);
	return (buf);
}

/*
 * smb_privlist_mkabsolute
 *
 * decode: flat buffer -> structure
 */
static ntpriv_list_t *
smb_grpprivlist_mkabsolute(uint8_t *buf, uint32_t len)
{
	ntpriv_list_t *obj = NULL;
	XDR xdrs;
	uint32_t status;
	int length = 0, num_privs = 0;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);
	status = smb_group_priv_num(&num_privs);
	if (status != 0) {
		syslog(LOG_ERR,
		    "smb_grpprivlist_mkabsolute: Cannot get privlist.");
		xdr_destroy(&xdrs);
		return (NULL);
	}

	if (num_privs > 0) {
		length = sizeof (int) + (num_privs * sizeof (privs_t));
		if ((obj = (ntpriv_list_t *)malloc(length)) == 0) {
			syslog(LOG_ERR,
			    "smb_grpprivlist_mkabsolute: resource shortage");
			xdr_destroy(&xdrs);
			return (NULL);
		}
	}
	bzero(obj, sizeof (ntpriv_list_t));
	bzero(obj->privs, num_privs * sizeof (privs_t));
	if (!xdr_ntpriv_list_t(&xdrs, obj)) {
		syslog(LOG_ERR, "smb_grpprivlist_mkabsolute: XDR decode error");
		smb_group_free_privlist(obj, 1);
		obj = NULL;
	}
	xdr_destroy(&xdrs);
	return (obj);
}

char *
smb_dr_encode_grp_list(uint32_t opcode, ntgrp_list_t *list,
    size_t *len)
{
	char *buf;
	smb_dr_bytes_t arg;

	arg.bytes_val = smb_grplist_mkselfrel(list, &arg.bytes_len);

	buf = smb_dr_encode_common(opcode, &arg, xdr_smb_dr_bytes_t, len);
	free(arg.bytes_val);
	return (buf);
}

ntgrp_list_t *
smb_dr_decode_grp_list(char *buf, size_t len)
{
	smb_dr_bytes_t arg;
	ntgrp_list_t *list;

	bzero(&arg, sizeof (smb_dr_bytes_t));
	if (smb_dr_decode_common(buf, len, xdr_smb_dr_bytes_t, &arg)
	    != 0) {
		syslog(LOG_ERR, "smb_dr_decode_grplist: XDR decode error");
		xdr_free(xdr_smb_dr_bytes_t, (char *)&arg);
		return (NULL);
	}
	list = smb_grplist_mkabsolute(arg.bytes_val, arg.bytes_len);
	xdr_free(xdr_smb_dr_bytes_t, (char *)&arg);
	return (list);
}

char *
smb_dr_encode_grp_memberlist(uint32_t opcode,
    ntgrp_member_list_t *list, size_t *len)
{
	char *buf;
	smb_dr_bytes_t arg;

	arg.bytes_val = smb_grpmemberlist_mkselfrel(list, &arg.bytes_len);

	buf = smb_dr_encode_common(opcode, &arg, xdr_smb_dr_bytes_t, len);
	free(arg.bytes_val);
	return (buf);
}

ntgrp_member_list_t *
smb_dr_decode_grp_memberlist(char *buf, size_t len)
{
	smb_dr_bytes_t arg;
	ntgrp_member_list_t *list;

	bzero(&arg, sizeof (smb_dr_bytes_t));
	if (smb_dr_decode_common(buf, len, xdr_smb_dr_bytes_t, &arg)
	    != 0) {
		syslog(LOG_ERR,
		    "smb_dr_decode_grpmemberlist: XDR decode error");
		xdr_free(xdr_smb_dr_bytes_t, (char *)&arg);
		return (NULL);
	}
	list = smb_grpmemberlist_mkabsolute(arg.bytes_val, arg.bytes_len);
	xdr_free(xdr_smb_dr_bytes_t, (char *)&arg);
	return (list);
}

char *
smb_dr_encode_grp_privlist(uint32_t opcode,
    ntpriv_list_t *list, size_t *len)
{
	char *buf;
	smb_dr_bytes_t arg;

	arg.bytes_val = smb_grpprivlist_mkselfrel(list, &arg.bytes_len);

	buf = smb_dr_encode_common(opcode, &arg, xdr_smb_dr_bytes_t, len);
	free(arg.bytes_val);
	return (buf);
}

ntpriv_list_t *
smb_dr_decode_grp_privlist(char *buf, size_t len)
{
	smb_dr_bytes_t arg;
	ntpriv_list_t *list;

	bzero(&arg, sizeof (smb_dr_bytes_t));
	if (smb_dr_decode_common(buf, len, xdr_smb_dr_bytes_t, &arg)
	    != 0) {
		syslog(LOG_ERR, "smb_dr_decode_grp_privlist: XDR decode error");
		xdr_free(xdr_smb_dr_bytes_t, (char *)&arg);
		return (NULL);
	}
	list = smb_grpprivlist_mkabsolute(arg.bytes_val, arg.bytes_len);
	xdr_free(xdr_smb_dr_bytes_t, (char *)&arg);
	return (list);
}
