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

#pragma ident	"@(#)smbd_share_doorsvc.c	1.6	08/08/05 SMI"

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
#include <strings.h>
#include <pthread.h>

#include <smbsrv/libsmb.h>

#include <smbsrv/smb_share.h>
#include <smbsrv/smbinfo.h>

#define	SMB_SHARE_DSRV_VERSION	1
#define	SMB_SHARE_DSRV_COOKIE	((void*)(0xdeadbeef^SMB_SHARE_DSRV_VERSION))

static int smb_share_dsrv_fd = -1;
static pthread_mutex_t smb_share_dsrv_mtx = PTHREAD_MUTEX_INITIALIZER;

static void smb_share_dsrv_dispatch(void *, char *, size_t, door_desc_t *,
    uint_t);
static int smb_share_dsrv_enum(smb_enumshare_info_t *esi);

/*
 * smb_share_dsrv_start
 *
 * Start the LanMan share door service.
 * Returns 0 on success. Otherwise, -1.
 */
int
smb_share_dsrv_start(void)
{
	int	newfd;

	(void) pthread_mutex_lock(&smb_share_dsrv_mtx);

	if (smb_share_dsrv_fd != -1) {
		syslog(LOG_ERR, "smb_share_dsrv_start: duplicate");
		(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
		return (smb_share_dsrv_fd);
	}

	if ((smb_share_dsrv_fd = door_create(smb_share_dsrv_dispatch,
	    SMB_SHARE_DSRV_COOKIE, (DOOR_UNREF | DOOR_REFUSE_DESC))) < 0) {
		syslog(LOG_ERR, "smb_share_dsrv_start: door_create: %s",
		    strerror(errno));
		(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
		return (-1);
	}

	(void) unlink(SMB_SHARE_DNAME);

	if ((newfd = creat(SMB_SHARE_DNAME, 0644)) < 0) {
		syslog(LOG_ERR, "smb_share_dsrv_start: open: %s",
		    strerror(errno));
		(void) door_revoke(smb_share_dsrv_fd);
		smb_share_dsrv_fd = -1;
		(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
		return (-1);
	}

	(void) close(newfd);
	(void) fdetach(SMB_SHARE_DNAME);

	if (fattach(smb_share_dsrv_fd, SMB_SHARE_DNAME) < 0) {
		syslog(LOG_ERR, "smb_share_dsrv_start: fattach: %s",
		    strerror(errno));
		(void) door_revoke(smb_share_dsrv_fd);
		smb_share_dsrv_fd = -1;
		(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
		return (-1);
	}

	(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
	return (smb_share_dsrv_fd);
}

/*
 * smb_share_dsrv_stop
 *
 * Stop the LanMan share door service.
 */
void
smb_share_dsrv_stop(void)
{
	(void) pthread_mutex_lock(&smb_share_dsrv_mtx);

	if (smb_share_dsrv_fd != -1) {
		(void) fdetach(SMB_SHARE_DNAME);
		(void) door_revoke(smb_share_dsrv_fd);
		smb_share_dsrv_fd = -1;
	}

	(void) pthread_mutex_unlock(&smb_share_dsrv_mtx);
}

/*
 * smb_share_dsrv_dispatch
 *
 * This function with which the LMSHARE door is associated
 * will invoke the appropriate CIFS share management function
 * based on the request type of the door call.
 */
/*ARGSUSED*/
static void
smb_share_dsrv_dispatch(void *cookie, char *ptr, size_t size, door_desc_t *dp,
    uint_t n_desc)
{
	uint32_t rc;
	int req_type;
	char buf[SMB_SHARE_DSIZE];
	unsigned int used;
	smb_dr_ctx_t *dec_ctx;
	smb_dr_ctx_t *enc_ctx;
	unsigned int dec_status;
	unsigned int enc_status;
	char *sharename, *sharename2;
	char *cmnt, *ad_container;
	smb_share_t lmshr_info;
	smb_shrlist_t lmshr_list;
	smb_enumshare_info_t esi;
	int offset;

	if ((cookie != SMB_SHARE_DSRV_COOKIE) || (ptr == NULL) ||
	    (size < sizeof (uint32_t))) {
		(void) door_return(NULL, 0, NULL, 0);
	}

	dec_ctx = smb_dr_decode_start(ptr, size);
	enc_ctx = smb_dr_encode_start(buf, sizeof (buf));
	req_type = smb_dr_get_uint32(dec_ctx);

	switch (req_type) {
	case SMB_SHROP_NUM_SHARES:
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		rc = smb_shr_count();
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		break;

	case SMB_SHROP_DELETE:
		sharename = smb_dr_get_string(dec_ctx);

		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			goto decode_error;
		}

		rc = smb_shr_delete(sharename, B_FALSE);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_free_string(sharename);
		break;

	case SMB_SHROP_RENAME:
		sharename = smb_dr_get_string(dec_ctx);
		sharename2 = smb_dr_get_string(dec_ctx);

		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			smb_dr_free_string(sharename2);
			goto decode_error;
		}

		rc = smb_shr_rename(sharename, sharename2);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_free_string(sharename);
		smb_dr_free_string(sharename2);
		break;

	case SMB_SHROP_GETINFO:
		sharename = smb_dr_get_string(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			goto decode_error;
		}

		rc = smb_shr_get(sharename, &lmshr_info);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_put_share(enc_ctx, &lmshr_info);
		smb_dr_free_string(sharename);
		break;

	case SMB_SHROP_ADD:
		smb_dr_get_share(dec_ctx, &lmshr_info);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		rc = smb_shr_create(&lmshr_info, B_FALSE);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		smb_dr_put_share(enc_ctx, &lmshr_info);
		break;

	case SMB_SHROP_MODIFY:
		sharename = smb_dr_get_string(dec_ctx);
		cmnt = smb_dr_get_string(dec_ctx);
		ad_container = smb_dr_get_string(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(sharename);
			smb_dr_free_string(cmnt);
			smb_dr_free_string(ad_container);
			goto decode_error;
		}

		rc = smb_shr_modify(sharename, cmnt, ad_container, B_FALSE);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);

		smb_dr_free_string(sharename);
		smb_dr_free_string(cmnt);
		smb_dr_free_string(ad_container);
		break;

	case SMB_SHROP_LIST:
		offset = smb_dr_get_int32(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0)
			goto decode_error;

		smb_shr_list(offset, &lmshr_list);
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_buf(enc_ctx, (unsigned char *)&lmshr_list,
		    sizeof (smb_shrlist_t));
		break;

	case SMB_SHROP_ENUM:
		esi.es_bufsize = smb_dr_get_ushort(dec_ctx);
		esi.es_username = smb_dr_get_string(dec_ctx);
		if ((dec_status = smb_dr_decode_finish(dec_ctx)) != 0) {
			smb_dr_free_string(esi.es_username);
			goto decode_error;
		}

		rc = smb_share_dsrv_enum(&esi);

		smb_dr_free_string(esi.es_username);

		smb_dr_put_int32(enc_ctx, SMB_SHARE_DSUCCESS);
		smb_dr_put_uint32(enc_ctx, rc);
		if (rc == NERR_Success) {
			smb_dr_put_ushort(enc_ctx, esi.es_ntotal);
			smb_dr_put_ushort(enc_ctx, esi.es_nsent);
			smb_dr_put_ushort(enc_ctx, esi.es_datasize);
			smb_dr_put_buf(enc_ctx,
			    (unsigned char *)esi.es_buf, esi.es_bufsize);
			free(esi.es_buf);
		}
		break;

	default:
		dec_status = smb_dr_decode_finish(dec_ctx);
		goto decode_error;
	}

	if ((enc_status = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		enc_ctx = smb_dr_encode_start(buf, sizeof (buf));
		smb_dr_put_int32(enc_ctx, SMB_SHARE_DERROR);
		smb_dr_put_uint32(enc_ctx, enc_status);
		(void) smb_dr_encode_finish(enc_ctx, &used);
	}

	(void) door_return(buf, used, NULL, 0);
	return;

decode_error:
	smb_dr_put_int32(enc_ctx, SMB_SHARE_DERROR);
	smb_dr_put_uint32(enc_ctx, dec_status);
	(void) smb_dr_encode_finish(enc_ctx, &used);
	(void) door_return(buf, used, NULL, 0);
}

/*
 * smb_share_dsrv_enum
 *
 * This function builds a response for a NetShareEnum RAP request which
 * originates from smbsrv kernel module. A response buffer is allocated
 * with the specified size in esi->es_bufsize. List of shares is scanned
 * twice. In the first round the total number of shares which their OEM
 * name is shorter than 13 chars (esi->es_ntotal) and also the number of
 * shares that fit in the given buffer are calculated. In the second
 * round the shares data are encoded in the buffer.
 *
 * The data associated with each share has two parts, a fixed size part and
 * a variable size part which is share's comment. The outline of the response
 * buffer is so that fixed part for all the shares will appear first and follows
 * with the comments for all those shares and that's why the data cannot be
 * encoded in one round without unnecessarily complicating the code.
 */
static int
smb_share_dsrv_enum(smb_enumshare_info_t *esi)
{
	smb_shriter_t shi;
	smb_share_t *si;
	int remained;
	uint16_t infolen = 0;
	uint16_t cmntlen = 0;
	uint16_t sharelen;
	uint16_t clen;
	uint32_t cmnt_offs;
	smb_msgbuf_t info_mb;
	smb_msgbuf_t cmnt_mb;
	boolean_t autohome_added = B_FALSE;

	esi->es_ntotal = esi->es_nsent = 0;

	if ((esi->es_buf = malloc(esi->es_bufsize)) == NULL)
		return (NERR_InternalError);

	bzero(esi->es_buf, esi->es_bufsize);
	remained = esi->es_bufsize;

	/* Do the necessary calculations in the first round */
	smb_shr_iterinit(&shi);

	while ((si = smb_shr_iterate(&shi)) != NULL) {
		if (si->shr_flags & SMB_SHRF_LONGNAME)
			continue;

		if ((si->shr_flags & SMB_SHRF_AUTOHOME) && !autohome_added) {
			if (strcasecmp(esi->es_username, si->shr_name) == 0)
				autohome_added = B_TRUE;
			else
				continue;
		}

		esi->es_ntotal++;

		if (remained <= 0)
			continue;

		clen = strlen(si->shr_cmnt) + 1;
		sharelen = SHARE_INFO_1_SIZE + clen;

		if (sharelen <= remained) {
			infolen += SHARE_INFO_1_SIZE;
			cmntlen += clen;
		}

		remained -= sharelen;
	}

	esi->es_datasize = infolen + cmntlen;

	smb_msgbuf_init(&info_mb, (uint8_t *)esi->es_buf, infolen, 0);
	smb_msgbuf_init(&cmnt_mb, (uint8_t *)esi->es_buf + infolen, cmntlen, 0);
	cmnt_offs = infolen;

	/* Encode the data in the second round */
	smb_shr_iterinit(&shi);
	autohome_added = B_FALSE;

	while ((si = smb_shr_iterate(&shi)) != NULL) {
		if (si->shr_flags & SMB_SHRF_LONGNAME)
			continue;

		if ((si->shr_flags & SMB_SHRF_AUTOHOME) && !autohome_added) {
			if (strcasecmp(esi->es_username, si->shr_name) == 0)
				autohome_added = B_TRUE;
			else
				continue;
		}

		if (smb_msgbuf_encode(&info_mb, "13c.wl",
		    si->shr_oemname, si->shr_type, cmnt_offs) < 0)
			break;

		if (smb_msgbuf_encode(&cmnt_mb, "s", si->shr_cmnt) < 0)
			break;

		cmnt_offs += strlen(si->shr_cmnt) + 1;
		esi->es_nsent++;
	}

	smb_msgbuf_term(&info_mb);
	smb_msgbuf_term(&cmnt_mb);

	return (NERR_Success);
}
