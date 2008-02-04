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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * LanMan share door server
 */

#include <door.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <pthread.h>

#include <smbsrv/libsmb.h>

#include <smbsrv/lmshare.h>
#include <smbsrv/lmshare_door.h>
#include <smbsrv/smbinfo.h>

static smb_kmod_cfg_t smb_kcfg;

static int smb_lmshrd_fildes = -1;
static pthread_mutex_t smb_lmshrd_srv_mutex = PTHREAD_MUTEX_INITIALIZER;

/* forward declaration */
static void smb_lmshrd_srv_door(void *cookie, char *ptr, size_t size,
    door_desc_t *dp, uint_t n_desc);
static int smb_lmshrd_srv_check(int opcode, char *sharename);

/*
 * smb_lmshrd_srv_start
 *
 * Start the LanMan share door service.
 * Returns 0 on success. Otherwise, -1.
 */
int
smb_lmshrd_srv_start()
{
	int newfd;

	(void) pthread_mutex_lock(&smb_lmshrd_srv_mutex);

	if (smb_lmshrd_fildes != -1) {
		syslog(LOG_ERR, "smb_lmshrd_srv_start: duplicate");
		(void) pthread_mutex_unlock(&smb_lmshrd_srv_mutex);
		return (0);
	}

	if ((smb_lmshrd_fildes = door_create(smb_lmshrd_srv_door,
	    LMSHR_DOOR_COOKIE, (DOOR_UNREF | DOOR_REFUSE_DESC))) < 0) {
		syslog(LOG_ERR, "smb_lmshrd_srv_start: door_create: %s",
		    strerror(errno));
		(void) pthread_mutex_unlock(&smb_lmshrd_srv_mutex);
		return (-1);
	}

	(void) unlink(LMSHR_DOOR_NAME);

	if ((newfd = creat(LMSHR_DOOR_NAME, 0644)) < 0) {
		syslog(LOG_ERR, "smb_lmshrd_srv_start: open: %s",
		    strerror(errno));
		(void) door_revoke(smb_lmshrd_fildes);
		smb_lmshrd_fildes = -1;
		(void) pthread_mutex_unlock(&smb_lmshrd_srv_mutex);
		return (-1);
	}

	(void) close(newfd);
	(void) fdetach(LMSHR_DOOR_NAME);

	if (fattach(smb_lmshrd_fildes, LMSHR_DOOR_NAME) < 0) {
		syslog(LOG_ERR, "smb_lmshrd_srv_start: fattach: %s",
		    strerror(errno));
		(void) door_revoke(smb_lmshrd_fildes);
		smb_lmshrd_fildes = -1;
		(void) pthread_mutex_unlock(&smb_lmshrd_srv_mutex);
		return (-1);
	}

	(void) pthread_mutex_unlock(&smb_lmshrd_srv_mutex);
	return (0);
}


/*
 * smb_lmshrd_srv_stop
 *
 * Stop the LanMan share door service.
 */
void
smb_lmshrd_srv_stop(void)
{
	(void) pthread_mutex_lock(&smb_lmshrd_srv_mutex);

	if (smb_lmshrd_fildes != -1) {
		(void) fdetach(LMSHR_DOOR_NAME);
		(void) door_revoke(smb_lmshrd_fildes);
		smb_lmshrd_fildes = -1;
	}

	(void) pthread_mutex_unlock(&smb_lmshrd_srv_mutex);
}


/*
 * smb_lmshrd_srv_door
 *
 * This function with which the LMSHARE door is associated
 * will invoke the appropriate CIFS share management function
 * based on the request type of the door call.
 */
/*ARGSUSED*/
void
smb_lmshrd_srv_door(void *cookie, char *ptr, size_t size, door_desc_t *dp,
    uint_t n_desc)
{
	DWORD rc;
	int req_type, mode, rc2;
	char buf[LMSHR_DOOR_SIZE];
	unsigned int used;
	smb_dr_ctx_t *dec_ctx = smb_dr_decode_start(ptr, size);
	smb_dr_ctx_t *enc_ctx = smb_dr_encode_start(buf, sizeof (buf));
	unsigned int dec_status;
	unsigned int enc_status;
	char *sharename, *sharename2;
	lmshare_info_t lmshr_info;
	lmshare_info_t *lmshr_infop;
	lmshare_iterator_t *lmshr_iter;
	int offset;
	lmshare_list_t lmshr_list;

	req_type = smb_dr_get_uint32(dec_ctx);

	switch (req_type) {
	case LMSHR_DOOR_OPEN_ITERATOR:
		mode = smb_dr_get_int32(dec_ctx);

		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		lmshr_iter = lmshare_open_iterator(mode);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_lmshr_iterator(enc_ctx,
		    (uint64_t)(uintptr_t)lmshr_iter);

		break;

	case LMSHR_DOOR_CLOSE_ITERATOR:
		lmshr_iter = (lmshare_iterator_t *)(uintptr_t)
		    smb_dr_get_lmshr_iterator(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		lmshare_close_iterator(lmshr_iter);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		break;

	case LMSHR_DOOR_ITERATE:
		lmshr_iter = (lmshare_iterator_t *)(uintptr_t)
		    smb_dr_get_lmshr_iterator(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		lmshr_infop = lmshare_iterate(lmshr_iter);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_lmshare(enc_ctx, lmshr_infop);
		break;

	case LMSHR_DOOR_NUM_SHARES:
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		rc = lmshare_num_shares();
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		break;

	case LMSHR_DOOR_DELETE:
		sharename = smb_dr_get_string(dec_ctx);

		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			goto decode_error;
		}

		rc = lmshare_delete(sharename, 0);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_free_string(sharename);
		break;

	case LMSHR_DOOR_RENAME:
		sharename = smb_dr_get_string(dec_ctx);
		sharename2 = smb_dr_get_string(dec_ctx);

		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			smb_dr_free_string(sharename2);
			goto decode_error;
		}

		rc = lmshare_rename(sharename, sharename2, 0);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_free_string(sharename);
		smb_dr_free_string(sharename2);
		break;

	case LMSHR_DOOR_GETINFO:
		sharename = smb_dr_get_string(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			goto decode_error;
		}

		rc = lmshare_getinfo(sharename, &lmshr_info);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_put_lmshare(enc_ctx, &lmshr_info);
		smb_dr_free_string(sharename);
		break;

	case LMSHR_DOOR_ADD:
		smb_dr_get_lmshare(dec_ctx, &lmshr_info);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		rc = lmshare_add(&lmshr_info, 0);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_put_lmshare(enc_ctx, &lmshr_info);
		break;

	case LMSHR_DOOR_SETINFO:
		smb_dr_get_lmshare(dec_ctx, &lmshr_info);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		rc = lmshare_setinfo(&lmshr_info, 0);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		break;

	case LMSHR_DOOR_EXISTS:
	case LMSHR_DOOR_IS_SPECIAL:
	case LMSHR_DOOR_IS_RESTRICTED:
	case LMSHR_DOOR_IS_ADMIN:
	case LMSHR_DOOR_IS_VALID:
	case LMSHR_DOOR_IS_DIR:
		sharename = smb_dr_get_string(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			goto decode_error;
		}

		rc2 = smb_lmshrd_srv_check(req_type, sharename);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_uint32(enc_ctx, rc2);
		smb_dr_free_string(sharename);
		break;

	case LMSHR_DOOR_LIST:
		offset = smb_dr_get_int32(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		rc = lmshare_list(offset, &lmshr_list);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_put_lmshr_list(enc_ctx, &lmshr_list);
		break;

	case SMB_GET_KCONFIG:
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		smb_load_kconfig(&smb_kcfg);
		smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_SUCCESS);
		smb_dr_put_kconfig(enc_ctx, &smb_kcfg);
		break;

	default:
		dec_status = smb_dr_decode_finish(dec_ctx);
		goto decode_error;
	}

	if ((enc_status = smb_dr_encode_finish(enc_ctx, &used)) != 0)
		goto encode_error;

	(void) door_return(buf, used, NULL, 0);

	return;

decode_error:
	smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_ERROR);
	smb_dr_put_uint32(enc_ctx, dec_status);
	(void) smb_dr_encode_finish(enc_ctx, &used);
	(void) door_return(buf, used, NULL, 0);
	return;

encode_error:
	enc_ctx = smb_dr_encode_start(buf, sizeof (buf));
	smb_dr_put_int32(enc_ctx, LMSHR_DOOR_SRV_ERROR);
	smb_dr_put_uint32(enc_ctx, enc_status);
	(void) smb_dr_encode_finish(enc_ctx, &used);
	(void) door_return(buf, used, NULL, 0);
}

/*
 * smb_lmshrd_srv_check
 *
 * Depending upon the opcode, this function will
 * either check the existence of a share/dir or
 * the the type of the specified share.
 */
static int
smb_lmshrd_srv_check(int opcode, char *sharename)
{
	int rc;

	switch (opcode) {
	case LMSHR_DOOR_EXISTS:
		rc = lmshare_exists(sharename);
		break;

	case LMSHR_DOOR_IS_SPECIAL:
		rc = lmshare_is_special(sharename);
		break;

	case LMSHR_DOOR_IS_RESTRICTED:
		rc = lmshare_is_restricted(sharename);
		break;

	case LMSHR_DOOR_IS_ADMIN:
		rc = lmshare_is_admin(sharename);
		break;

	case LMSHR_DOOR_IS_VALID:
		rc = lmshare_is_valid(sharename);
		break;

	case LMSHR_DOOR_IS_DIR:
		rc = lmshare_is_dir(sharename);
	}

	return (rc);
}
