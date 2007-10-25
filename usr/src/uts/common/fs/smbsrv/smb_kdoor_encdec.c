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

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_xdr.h>


/*
 * smb_kdr_decode_common
 *
 * This function can be used for decoding both door request and result buffer.
 * pre-condition: data is non-null pointer, and is bzero'd.
 */
int
smb_kdr_decode_common(char *buf, size_t len, xdrproc_t proc, void *data)
{
	XDR xdrs;
	int rc = 0;

	if (!data) {
		cmn_err(CE_WARN, "smb_kdr_decode_common: invalid param");
		return (-1);
	}

	xdrmem_create(&xdrs, buf, len, XDR_DECODE);
	if (!proc(&xdrs, data))
		rc = -1;

	xdr_destroy(&xdrs);
	return (rc);
}

/*
 * smb_kdr_encode_common
 *
 * This function is used for encoding both request/result door buffer.
 * This function will first encode integer value 'reserved' (opcode/status),
 * followed by the data (which will be encoded via the specified XDR routine.
 *
 * Returns encoded buffer upon success. Otherwise, returns NULL.
 */
char *
smb_kdr_encode_common(uint_t reserved, void *data, xdrproc_t proc, size_t *len)
{
	XDR xdrs;
	char *buf;

	if (proc && !data) {
		cmn_err(CE_WARN, "smb_kdr_encode_common: invalid param");
		*len = 0;
		return (NULL);
	}

	*len = xdr_sizeof(xdr_uint32_t, &reserved);
	if (proc)
		*len += xdr_sizeof(proc, data);
	buf = kmem_alloc(*len, KM_SLEEP);
	xdrmem_create(&xdrs, buf, *len, XDR_ENCODE);
	if (!xdr_uint32_t(&xdrs, &reserved)) {
		cmn_err(CE_WARN, "smb_kdr_encode_common: encode error 1");
		kmem_free(buf, *len);
		*len = 0;
		xdr_destroy(&xdrs);
		return (NULL);
	}

	if (proc && !proc(&xdrs, data)) {
		cmn_err(CE_WARN, "smb_kdr_encode_common: encode error 2");
		kmem_free(buf, *len);
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

	if (smb_kdr_decode_common(argp, arg_size, xdr_uint32_t, &opcode) != 0)
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

	buf = smb_kdr_encode_common(opcode, NULL, NULL, len);
	return (buf);
}

/*
 * Get the status of the door result buffer.
 */
int
smb_dr_get_res_stat(char *rbufp, size_t rbuf_size)
{
	int stat;
	if (smb_kdr_decode_common(rbufp, rbuf_size, xdr_uint32_t, &stat) != 0)
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

	buf = smb_kdr_encode_common(stat, NULL, NULL, len);
	return (buf);
}

char *
smb_dr_encode_arg_get_token(netr_client_t *clnt_info, size_t *len)
{

	char *buf;
	smb_dr_bytes_t arg;
	uint_t opcode = SMB_DR_USER_AUTH_LOGON;

	arg.bytes_val = netr_client_mkselfrel(clnt_info,
	    &arg.bytes_len);

	buf = smb_kdr_encode_common(opcode, &arg, xdr_smb_dr_bytes_t, len);
	kmem_free(arg.bytes_val, arg.bytes_len);
	return (buf);
}

smb_token_t *
smb_dr_decode_res_token(char *buf, size_t len)
{
	smb_dr_bytes_t res;
	smb_token_t *token;

	bzero(&res, sizeof (smb_dr_bytes_t));
	if (smb_kdr_decode_common(buf, len, xdr_smb_dr_bytes_t, &res) !=
	    0) {
		cmn_err(CE_WARN, "smb_dr_decode_res_token: failed");
		xdr_free(xdr_smb_dr_bytes_t, (char *)&res);
		return (NULL);
	}
	token = smb_token_mkabsolute(res.bytes_val, res.bytes_len);
	xdr_free(xdr_smb_dr_bytes_t, (char *)&res);

	return (token);
}

char *
smb_dr_encode_string(uint32_t reserved, char *str, size_t *len)
{
	char *buf = NULL;
	smb_dr_string_t res;

	if (!str) {
		*len = 0;
		return (buf);
	}

	res.buf = str;
	if ((buf = smb_kdr_encode_common(reserved, &res,
	    xdr_smb_dr_string_t, len)) == 0)
		cmn_err(CE_WARN, "smb_dr_encode_string: failed");
	return (buf);
}

/*
 * smb_dr_decode_kshare()
 *
 * The kshare information arrives encoded in a flat buffer, so retrieve
 * the flat buffer and convert it to an smb_dr_kshare structure.
 */

smb_dr_kshare_t *
smb_dr_decode_kshare(char *buf, size_t len)
{
	smb_dr_bytes_t res;
	smb_dr_kshare_t *kshare;

	bzero(&res, sizeof (smb_dr_bytes_t));
	if (smb_kdr_decode_common(buf, len, xdr_smb_dr_bytes_t, &res) !=
	    0) {
		cmn_err(CE_WARN, "smb_dr_decode_kshare: failed");
		xdr_free(xdr_smb_dr_bytes_t, (char *)&res);
		return (NULL);
	}
	kshare = smb_share_mkabsolute(res.bytes_val, res.bytes_len);
	xdr_free(xdr_smb_dr_bytes_t, (char *)&res);

	return (kshare);
}

/*
 * smb_share_mkabsolute
 *
 * decode: flat buffer -> structure
 */

smb_dr_kshare_t *
smb_share_mkabsolute(uint8_t *buf, uint32_t len)
{
	smb_dr_kshare_t *obj;
	XDR xdrs;

	xdrmem_create(&xdrs, (const caddr_t)buf, len, XDR_DECODE);
	obj = kmem_zalloc(sizeof (smb_dr_kshare_t), KM_SLEEP);

	if (!xdr_smb_dr_kshare_t(&xdrs, obj)) {
		kmem_free(obj, sizeof (smb_dr_kshare_t));
		obj = NULL;
	}

	xdr_destroy(&xdrs);
	return (obj);
}

void
smb_dr_kshare_free(smb_dr_kshare_t *kshare)
{
	if (!kshare)
		return;

	xdr_free(xdr_smb_dr_kshare_t, (char *)kshare);
	kmem_free(kshare, sizeof (smb_dr_kshare_t));
}
