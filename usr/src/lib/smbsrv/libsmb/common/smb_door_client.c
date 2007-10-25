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

/*
 * User-space door client for SMBd
 */

#include <fcntl.h>
#include <syslog.h>
#include <door.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>

#include <smbsrv/smbinfo.h>
#include <smbsrv/wintypes.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/alloc.h>
#include <smbsrv/smb_common_door.h>

#include <smbsrv/libsmb.h>

static int smb_door_fildes = -1;

static char *smbd_desc[] = {
	"",
	"SmbdJoinDomain",
	"SmbdGetParam",
	"SmbdSetParam",
	"SmbdNetbiosReconfig",
	0
};

/*
 * Returns 0 on success. Otherwise, -1.
 */
static int
smbd_door_open(int opcode)
{
	int rc = 0;

	if (smb_door_fildes == -1 &&
	    (smb_door_fildes = open(SMBD_DOOR_NAME, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "%s: open %s failed %s", smbd_desc[opcode],
		    SMBD_DOOR_NAME, strerror(errno));
		rc = -1;
	}

	return (rc);
}

/*
 * Return 0 upon success. Otherwise, -1.
 */
static int
smbd_door_check_srv_status(int opcode, smb_dr_ctx_t *dec_ctx)
{
	int status = smb_dr_get_int32(dec_ctx);
	int err;
	int rc = -1;

	switch (status) {
	case SMBD_DOOR_SRV_SUCCESS:
		rc = 0;
		break;

	case SMBD_DOOR_SRV_ERROR:
		err = smb_dr_get_uint32(dec_ctx);
		syslog(LOG_ERR, "%s: Encountered door server error %s",
		    smbd_desc[opcode], strerror(err));
		break;

	default:
		syslog(LOG_ERR, "%s: Unknown door server status",
		    smbd_desc[opcode]);
	}

	if (rc != 0) {
		if ((err = smb_dr_decode_finish(dec_ctx)) != 0) {
			syslog(LOG_ERR, "%s: Decode error %s",
			    smbd_desc[opcode], strerror(err));
		}
	}

	return (rc);
}

uint32_t
smb_join(smb_joininfo_t *jdi)
{
	door_arg_t arg;
	char *buf;
	uint32_t used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	uint32_t rc;
	int opcode = SMBD_DOOR_JOIN;

	if ((jdi == 0) || (*jdi->domain_name == 0)) {
		syslog(LOG_ERR, "%s: invalid parameter(s)", smbd_desc[opcode]);
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if (smbd_door_open(opcode) == -1) {
		syslog(LOG_ERR, "%s: cannot open the door", smbd_desc[opcode]);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	buf = MEM_MALLOC("smb_door_client", SMBD_DOOR_SIZE);
	if (!buf) {
		syslog(LOG_ERR, "%s: resource shortage", smbd_desc[opcode]);
		return (NT_STATUS_NO_MEMORY);
	}

	enc_ctx = smb_dr_encode_start(buf, SMBD_DOOR_SIZE);
	if (enc_ctx == 0) {
		syslog(LOG_ERR, "%s: encode start failed", smbd_desc[opcode]);
		MEM_FREE("smb_door_client", buf);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_uint32(enc_ctx, jdi->mode);
	smb_dr_put_string(enc_ctx, jdi->domain_name);
	smb_dr_put_string(enc_ctx, jdi->domain_username);
	smb_dr_put_string(enc_ctx, jdi->domain_passwd);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    smbd_desc[opcode], strerror(status));
		MEM_FREE("smb_door_client", buf);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = SMBD_DOOR_SIZE;

	if (door_call(smb_door_fildes, &arg) < 0) {
		syslog(LOG_ERR, "%s: Door call failed %s", smbd_desc[opcode],
		    strerror(errno));
		MEM_FREE("smb_door_client", buf);
		smb_door_fildes = -1;
		return (NT_STATUS_INTERNAL_ERROR);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	if (smbd_door_check_srv_status(opcode, dec_ctx) != 0) {
		MEM_FREE("smb_door_client", buf);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    smbd_desc[opcode], strerror(status));
		MEM_FREE("smb_door_client", buf);
		return (NT_STATUS_INTERNAL_ERROR);
	}

	MEM_FREE("smb_door_client", buf);
	return (rc);
}

int
smbd_netbios_reconfig()
{
	door_arg_t arg;
	char *buf;
	uint32_t used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	DWORD rc;
	int opcode = SMBD_DOOR_NETBIOS_RECONFIG;

	if (smbd_door_open(opcode) == -1) {
		syslog(LOG_ERR, "%s: cannot open the door", smbd_desc[opcode]);
		return (1);
	}

	buf = MEM_MALLOC("smb_door_client", SMBD_DOOR_SIZE);
	if (!buf) {
		syslog(LOG_ERR, "%s: resource shortage", smbd_desc[opcode]);
		return (1);
	}

	enc_ctx = smb_dr_encode_start(buf, SMBD_DOOR_SIZE);
	if (enc_ctx == 0) {
		syslog(LOG_ERR, "%s: encode start failed", smbd_desc[opcode]);
		MEM_FREE("smb_door_client", buf);
		return (1);
	}

	smb_dr_put_uint32(enc_ctx, opcode);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    smbd_desc[opcode], strerror(status));
		MEM_FREE("smb_door_client", buf);
		return (1);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = SMBD_DOOR_SIZE;

	if (door_call(smb_door_fildes, &arg) < 0) {
		syslog(LOG_ERR, "%s: Door call failed %s", smbd_desc[opcode],
		    strerror(errno));
		MEM_FREE("smb_door_client", buf);
		smb_door_fildes = -1;
		return (1);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	rc = smb_dr_get_uint32(dec_ctx);

	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    smbd_desc[opcode], strerror(status));
		MEM_FREE("smb_door_client", buf);
		return (1);
	}
	MEM_FREE("smb_door_client", buf);
	return (rc);
}

int
smbd_set_param(smb_cfg_id_t id, char *value)
{
	door_arg_t arg;
	char *buf;
	uint32_t used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	DWORD rc;
	int opcode = SMBD_DOOR_PARAM_SET;

	if (smbd_door_open(opcode) == -1) {
		syslog(LOG_ERR, "%s: cannot open the door", smbd_desc[opcode]);
		return (1);
	}

	buf = MEM_MALLOC("smb_door_client", SMBD_DOOR_SIZE);
	if (!buf) {
		syslog(LOG_ERR, "%s: resource shortage", smbd_desc[opcode]);
		return (1);
	}

	enc_ctx = smb_dr_encode_start(buf, SMBD_DOOR_SIZE);
	if (enc_ctx == 0) {
		syslog(LOG_ERR, "%s: encode start failed", smbd_desc[opcode]);
		MEM_FREE("smb_door_client", buf);
		return (1);
	}

	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_uint32(enc_ctx, id);
	smb_dr_put_string(enc_ctx, value);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    smbd_desc[opcode], strerror(status));
		MEM_FREE("smb_door_client", buf);
		return (1);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = SMBD_DOOR_SIZE;

	if (door_call(smb_door_fildes, &arg) < 0) {
		syslog(LOG_ERR, "%s: Door call failed %s", smbd_desc[opcode],
		    strerror(errno));
		MEM_FREE("smb_door_client", buf);
		smb_door_fildes = -1;
		return (1);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	rc = smb_dr_get_uint32(dec_ctx);

	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    smbd_desc[opcode], strerror(status));
		MEM_FREE("smb_door_client", buf);
		return (1);
	}
	MEM_FREE("smb_door_client", buf);
	return (rc);
}

int
smbd_get_param(smb_cfg_id_t id, char *value)
{
	door_arg_t arg;
	char *buf;
	char *tmp = NULL;
	uint32_t used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	int status;
	DWORD rc;
	int opcode = SMBD_DOOR_PARAM_GET;

	if (smbd_door_open(opcode) == -1) {
		syslog(LOG_ERR, "%s: cannot open the door", smbd_desc[opcode]);
		return (1);
	}

	buf = MEM_MALLOC("smb_door_client", SMBD_DOOR_SIZE);
	if (!buf) {
		syslog(LOG_ERR, "%s: resource shortage", smbd_desc[opcode]);
		return (1);
	}

	enc_ctx = smb_dr_encode_start(buf, SMBD_DOOR_SIZE);
	if (enc_ctx == 0) {
		syslog(LOG_ERR, "%s: encode start failed", smbd_desc[opcode]);
		MEM_FREE("smb_door_client", buf);
		return (1);
	}

	smb_dr_put_uint32(enc_ctx, opcode);
	smb_dr_put_uint32(enc_ctx, id);

	if ((status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		syslog(LOG_ERR, "%s: Encode error %s",
		    smbd_desc[opcode], strerror(status));
		MEM_FREE("smb_door_client", buf);
		return (1);
	}

	arg.data_ptr = buf;
	arg.data_size = used;
	arg.desc_ptr = NULL;
	arg.desc_num = 0;
	arg.rbuf = buf;
	arg.rsize = SMBD_DOOR_SIZE;

	if (door_call(smb_door_fildes, &arg) < 0) {
		syslog(LOG_ERR, "%s: Door call failed %s", smbd_desc[opcode],
		    strerror(errno));
		MEM_FREE("smb_door_client", buf);
		smb_door_fildes = -1;
		return (1);
	}

	dec_ctx = smb_dr_decode_start(arg.data_ptr, arg.data_size);
	rc = smb_dr_get_uint32(dec_ctx);
	tmp = smb_dr_get_string(dec_ctx);
	(void) strcpy(value, tmp);

	if ((status = smb_dr_decode_finish(dec_ctx)) != 0) {
		syslog(LOG_ERR, "%s: Decode error %s",
		    smbd_desc[opcode], strerror(status));
		MEM_FREE("smb_door_client", buf);
		return (1);
	}
	MEM_FREE("smb_door_client", buf);
	return (rc);
}

int
smbd_get_security_mode(int *mode)
{
	char buf[64];
	int rc;

	buf[0] = '\0';
	rc = smbd_get_param(SMB_CI_SECURITY, buf);
	*mode = smb_config_secmode_fromstr(buf);
	return (rc);
}
