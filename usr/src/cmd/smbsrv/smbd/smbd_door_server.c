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
 * SMBd door server
 */

#include <door.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <varargs.h>
#include <stdio.h>
#include <synch.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <syslog.h>
#include <assert.h>
#include <alloca.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libsmbrdr.h>

#include <smbsrv/smb_common_door.h>

static int smb_door_fildes = -1;
static mutex_t smb_doorsrv_mutex;

void smb_srv_door(void *, char *, size_t, door_desc_t *, uint_t);

extern uint32_t smbd_join(smb_joininfo_t *);

/*
 * smb_doorsrv_start
 *
 * Start the SMBd door service.
 * Returns 0 on success. Otherwise, -1.
 */
int
smb_doorsrv_start()
{
	int newfd;

	(void) mutex_lock(&smb_doorsrv_mutex);

	if (smb_door_fildes != -1) {
		syslog(LOG_ERR, "smb_doorsrv_start: duplicate");
		(void) mutex_unlock(&smb_doorsrv_mutex);
		return (0);
	}

	if ((smb_door_fildes = door_create(smb_srv_door,
	    SMBD_DOOR_COOKIE, DOOR_UNREF)) < 0) {
		syslog(LOG_ERR, "smb_doorsrv_start: door_create failed %s",
		    strerror(errno));
		(void) mutex_unlock(&smb_doorsrv_mutex);
		return (-1);
	}

	(void) unlink(SMBD_DOOR_NAME);

	if ((newfd = creat(SMBD_DOOR_NAME, 0644)) < 0) {
		syslog(LOG_ERR, "smb_doorsrv_start: open failed %s",
		    strerror(errno));
		(void) door_revoke(smb_door_fildes);
		smb_door_fildes = -1;
		(void) mutex_unlock(&smb_doorsrv_mutex);
		return (-1);
	}

	(void) close(newfd);
	(void) fdetach(SMBD_DOOR_NAME);

	if (fattach(smb_door_fildes, SMBD_DOOR_NAME) < 0) {
		syslog(LOG_ERR, "smb_doorsrv_start: fattach failed %s",
		    strerror(errno));
		(void) door_revoke(smb_door_fildes);
		smb_door_fildes = -1;
		(void) mutex_unlock(&smb_doorsrv_mutex);
		return (-1);
	}

	(void) mutex_unlock(&smb_doorsrv_mutex);
	return (0);
}


/*
 * smb_doorsrv_stop
 *
 * Stop the smbd door service.
 */
void
smb_doorsrv_stop(void)
{
	(void) mutex_lock(&smb_doorsrv_mutex);

	if (smb_door_fildes != -1) {
		(void) fdetach(SMBD_DOOR_NAME);
		(void) door_revoke(smb_door_fildes);
		smb_door_fildes = -1;
	}

	(void) mutex_unlock(&smb_doorsrv_mutex);
}


/*
 * smb_srv_door
 *
 */
/*ARGSUSED*/
void
smb_srv_door(void *cookie, char *ptr, size_t size, door_desc_t *dp,
		uint_t n_desc)
{
	int req_type, rc;
	char *buf;
	int buflen;
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int dec_status;
	unsigned int enc_status;
	char *domain;
	char *user;
	char *passwd;
	smb_joininfo_t jdi;


	dec_ctx = smb_dr_decode_start(ptr, size);

	if (dec_ctx == 0)
		return;

	req_type = smb_dr_get_uint32(dec_ctx);
	buflen = SMBD_DOOR_SIZE;

	if ((buf = alloca(buflen)) == NULL) {
		syslog(LOG_ERR, "SmbdDoorSrv: resource shortage");
		(void) smb_dr_decode_finish(dec_ctx);
		return;
	}

	enc_ctx = smb_dr_encode_start(buf, buflen);
	if (enc_ctx == 0) {
		syslog(LOG_ERR, "SmbdDoorSrv: encode start failed");
		(void) smb_dr_decode_finish(dec_ctx);
		return;
	}

	switch (req_type) {
	case SMBD_DOOR_PARAM_GET: {
		smb_cfg_id_t id;
		char *value = NULL;
		char *empty = "";

		id = smb_dr_get_uint32(dec_ctx);

		dec_status = smb_dr_decode_finish(dec_ctx);
		if (dec_status != 0) {
			goto decode_error;
		}

		smb_config_rdlock();
		value = smb_config_getstr(id);
		smb_dr_put_int32(enc_ctx, SMBD_DOOR_SRV_SUCCESS);

		if (value)
			smb_dr_put_string(enc_ctx, value);
		else
			smb_dr_put_string(enc_ctx, empty);
		smb_config_unlock();
		break;
	}

	case SMBD_DOOR_PARAM_SET: {
		smb_cfg_id_t id;
		char *value = NULL;

		id = smb_dr_get_uint32(dec_ctx);
		value = smb_dr_get_string(dec_ctx);

		dec_status = smb_dr_decode_finish(dec_ctx);
		if (dec_status != 0) {
			smb_dr_free_string(value);
			goto decode_error;
		}

		smb_config_wrlock();
		if (smb_config_set(id, value) == 0) {
			smb_dr_put_int32(enc_ctx, SMBD_DOOR_SRV_SUCCESS);
		} else {
			smb_dr_put_int32(enc_ctx, SMBD_DOOR_SRV_ERROR);
		}
		smb_config_unlock();
		smb_dr_free_string(value);
		break;
	}

	case SMBD_DOOR_NETBIOS_RECONFIG: {
		smb_netbios_name_reconfig();
		smb_dr_put_int32(enc_ctx, SMBD_DOOR_SRV_SUCCESS);
		break;
	}

	case SMBD_DOOR_JOIN:
		jdi.mode = smb_dr_get_uint32(dec_ctx);
		domain = smb_dr_get_string(dec_ctx);
		user = smb_dr_get_string(dec_ctx);
		passwd = smb_dr_get_string(dec_ctx);

		dec_status = smb_dr_decode_finish(dec_ctx);
		if (dec_status != 0 ||
		    domain == 0 || user == 0 || passwd == 0) {
			smb_dr_free_string(domain);
			smb_dr_free_string(user);
			smb_dr_free_string(passwd);
			goto decode_error;
		}

		(void) strlcpy(jdi.domain_name, domain,
		    sizeof (jdi.domain_name));
		(void) strlcpy(jdi.domain_username, user,
		    sizeof (jdi.domain_username));
		(void) strlcpy(jdi.domain_passwd, passwd,
		    sizeof (jdi.domain_passwd));

		smb_dr_free_string(domain);
		smb_dr_free_string(user);
		smb_dr_free_string(passwd);

		rc = smbd_join(&jdi);
		smb_dr_put_int32(enc_ctx, SMBD_DOOR_SRV_SUCCESS);
		smb_dr_put_int32(enc_ctx, rc);
		break;

	case SMBD_DOOR_ADS_DOMAIN_CHANGED:
		domain = smb_dr_get_string(dec_ctx);
		dec_status = smb_dr_decode_finish(dec_ctx);
		if (dec_status != 0) {
			smb_dr_free_string(domain);
			goto decode_error;
		}

		rc = ads_domain_change_notify_handler(domain);
		smb_dr_put_int32(enc_ctx, SMBD_DOOR_SRV_SUCCESS);
		smb_dr_put_int32(enc_ctx, rc);
		smb_dr_free_string(domain);
		break;

	default:
		goto decode_error;
	}

	if ((enc_status = smb_dr_encode_finish(enc_ctx, &used)) != 0)
		goto encode_error;

	(void) door_return(buf, used, NULL, 0);

	return;

decode_error:
	(void) smb_dr_put_int32(enc_ctx, SMBD_DOOR_SRV_ERROR);
	(void) smb_dr_put_uint32(enc_ctx, dec_status);
	(void) smb_dr_encode_finish(enc_ctx, &used);
	(void) door_return(buf, used, NULL, 0);
	return;

encode_error:
	enc_ctx = smb_dr_encode_start(buf, buflen);
	(void) smb_dr_put_int32(enc_ctx, SMBD_DOOR_SRV_ERROR);
	(void) smb_dr_put_uint32(enc_ctx, enc_status);
	(void) smb_dr_encode_finish(enc_ctx, &used);

	(void) door_return(buf, used, NULL, 0);
}
