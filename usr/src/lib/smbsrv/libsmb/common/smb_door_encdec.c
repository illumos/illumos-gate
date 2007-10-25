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

#include <stdlib.h>
#include <strings.h>
#include <rpc/xdr.h>
#include <errno.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/smb_door_svc.h>

/*
 * smb_dr_decode_common
 *
 * This function can be used to decode both door request and result buffer.
 * pre-condition: data is non-null pointer, and is bzero'd.
 */
int
smb_dr_decode_common(char *buf, size_t len, xdrproc_t proc, void *data)
{
	XDR xdrs;
	int rc = 0;

	if (!data) {
		syslog(LOG_ERR, "smb_dr_decode_common: invalid param");
		return (-1);
	}

	xdrmem_create(&xdrs, buf, len, XDR_DECODE);
	if (!proc(&xdrs, data)) {
		rc = -1;
	}
	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * smb_dr_encode_common
 *
 * This function can be used to encode both request and result door buffer.
 * The 'opcode' paramater is set to the 'opcode' of the operation to be invoked
 * on the server, by the client. The server sets the same 'opcode' paramater
 * to indicate the 'status' of the door call.
 *
 * This function will first encode integer value 'opcode' (opcode/status),
 * followed by the data (which will be encoded via the specified XDR routine).
 *
 * Returns encoded buffer upon success. Otherwise, returns NULL.
 */
char *
smb_dr_encode_common(uint_t opcode, void *data, xdrproc_t proc, size_t *len)
{
	XDR xdrs;
	char *buf;

	if (proc && !data) {
		syslog(LOG_ERR, "smb_dr_encode_common: invalid param");
		*len = 0;
		return (NULL);
	}

	*len = xdr_sizeof(xdr_uint32_t, &opcode);
	if (proc)
		*len += xdr_sizeof(proc, data);
	buf = (char *)malloc(*len);
	if (!buf) {
		syslog(LOG_ERR, "smb_dr_encode_common: resource shortage");
		*len = 0;
		return (NULL);
	}
	xdrmem_create(&xdrs, buf, *len, XDR_ENCODE);
	if (!xdr_uint32_t(&xdrs, &opcode)) {
		syslog(LOG_DEBUG, "smb_dr_encode_common: encode error 1");
		free(buf);
		*len = 0;
		xdr_destroy(&xdrs);
		return (NULL);
	}

	if (proc && !proc(&xdrs, data)) {
		syslog(LOG_DEBUG, "smb_dr_encode_common: encode error 2");
		free(buf);
		buf = NULL;
		*len = 0;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

/*
 * Get the opcode of the door argument buffer.
 */
int
smb_dr_get_opcode(char *argp, size_t arg_size)
{
	int opcode;

	if (smb_dr_decode_common(argp, arg_size, xdr_uint32_t, &opcode) != 0)
		opcode = -1;
	return (opcode);
}

/*
 * Set the opcode of the door argument buffer.
 */
char *
smb_dr_set_opcode(uint32_t opcode, size_t *len)
{
	char *buf;

	buf = smb_dr_encode_common(opcode, NULL, NULL, len);
	return (buf);
}

/*
 * Get the status of the door result buffer.
 */
int
smb_dr_get_res_stat(char *rbufp, size_t rbuf_size)
{
	int stat;
	if (smb_dr_decode_common(rbufp, rbuf_size, xdr_uint32_t, &stat) != 0)
		stat = -1;
	return (stat);
}

/*
 * Set the status of the door result buffer.
 */
char *
smb_dr_set_res_stat(uint32_t stat, size_t *len)
{
	char *buf;

	buf = smb_dr_encode_common(stat, NULL, NULL, len);
	return (buf);
}

char *
smb_dr_encode_res_token(smb_token_t *token, size_t *len)
{
	smb_dr_bytes_t res;
	char *buf = NULL;

	res.bytes_val = smb_token_mkselfrel(token, &res.bytes_len);
	if (!res.bytes_val) {
		syslog(LOG_ERR, "smb_dr_encode_res_token: mkselfrel error");
		*len = 0;
		return (NULL);
	}

	if ((buf = smb_dr_encode_common(SMB_DR_OP_SUCCESS, &res,
	    xdr_smb_dr_bytes_t, len)) == NULL) {
		syslog(LOG_ERR, "smb_dr_encode_res_token: failed");
		*len = 0;
		free(res.bytes_val);
		return (NULL);

	}
	free(res.bytes_val);
	return (buf);
}

char *
smb_dr_encode_kshare(smb_dr_kshare_t *kshare, size_t *buflen)
{
	smb_dr_bytes_t res;
	char *buf = NULL;

	res.bytes_val = smb_kshare_mkselfrel(kshare, &res.bytes_len);

	free(kshare->k_path);
	free(kshare->k_sharename);

	if (!res.bytes_val)
		return (NULL);

	buf = smb_dr_encode_common(SMB_KDR_SHARE, &res, xdr_smb_dr_bytes_t,
	    buflen);

	free(res.bytes_val);

	return (buf);
}

/*
 * smb_kshare_mkselfrel
 *
 * encode: structure -> flat buffer (buffer size)
 * Pre-condition: kshare is non-null.
 */

uint8_t *
smb_kshare_mkselfrel(smb_dr_kshare_t *kshare, uint32_t *len)
{
	uint8_t *buf;
	XDR xdrs;

	if (!kshare)
		return (NULL);

	*len = xdr_sizeof(xdr_smb_dr_kshare_t, kshare);
	buf = (uint8_t *)malloc(*len);
	if (!buf)
		return (NULL);

	xdrmem_create(&xdrs, (const caddr_t)buf, *len, XDR_ENCODE);

	if (!xdr_smb_dr_kshare_t(&xdrs, kshare)) {
		*len = 0;
		free(buf);
		buf = NULL;
	}

	xdr_destroy(&xdrs);
	return (buf);
}

char *
smb_dr_encode_string(uint32_t opcode, char *str, size_t *len)
{
	char *buf;
	smb_dr_string_t res;

	res.buf = str;

	if ((buf = smb_dr_encode_common(opcode, &res,
	    xdr_smb_dr_string_t, len)) == NULL)
		syslog(LOG_ERR, "smb_dr_encode_string: failed");
	return (buf);
}

char *
smb_dr_decode_string(char *buf, size_t len)
{
	smb_dr_string_t res;
	char *str = NULL;

	bzero(&res, sizeof (smb_dr_string_t));
	if (smb_dr_decode_common(buf, len, xdr_smb_dr_string_t,
	    &res) == 0) {
		str = res.buf;
	} else {
		syslog(LOG_ERR, "smb_dr_decode_string: failed");
	}
	return (str);
}

netr_client_t *
smb_dr_decode_arg_get_token(char *buf, size_t len)
{
	smb_dr_bytes_t arg;
	netr_client_t *clnt_info;

	bzero(&arg, sizeof (smb_dr_bytes_t));
	if (smb_dr_decode_common(buf, len, xdr_smb_dr_bytes_t, &arg)
	    != 0) {
		syslog(LOG_ERR, "smb_dr_decode_arg_get_token: failed");
		xdr_free(xdr_smb_dr_bytes_t, (char *)&arg);
		return (NULL);
	}
	clnt_info = netr_client_mkabsolute(arg.bytes_val,
	    arg.bytes_len);
	xdr_free(xdr_smb_dr_bytes_t, (char *)&arg);
	return (clnt_info);
}

void
smb_dr_ulist_free(smb_dr_ulist_t *ulist)
{
	int i;
	smb_dr_user_ctx_t *uinfo;

	if (!ulist)
		return;

	for (i = 0; i < ulist->dul_cnt; i++) {
		uinfo = &ulist->dul_users[i];

		if (!uinfo)
			continue;

		xdr_free(xdr_smb_dr_ulist_t, (char *)ulist);
	}

	free(ulist);
}
