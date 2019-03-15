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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Functions to setup connections (TCP and/or NetBIOS)
 * This has the fall-back logic for IP6, IP4, NBT
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <libintl.h>
#include <xti.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/byteorder.h>
#include <sys/socket.h>
#include <sys/fcntl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include <netsmb/mchain.h>
#include <netsmb/netbios.h>
#include <netsmb/nb_lib.h>
#include <netsmb/smb_dev.h>

#include <cflib.h>

#include "charsets.h"
#include "private.h"
#include "smb_crypt.h"

static int
smb__ssnsetup(struct smb_ctx *ctx,
	struct mbdata *mbc1, struct mbdata *mbc2);

int smb_ssnsetup_spnego(struct smb_ctx *, struct mbdata *);

const char *
smb_iod_state_name(enum smbiod_state st)
{
	const char *n = "(?)";

	switch (st) {
	case SMBIOD_ST_UNINIT:
		n = "UNINIT!";
		break;
	case SMBIOD_ST_IDLE:
		n = "IDLE";
		break;
	case SMBIOD_ST_RECONNECT:
		n = "RECONNECT";
		break;
	case SMBIOD_ST_RCFAILED:
		n = "RCFAILED";
		break;
	case SMBIOD_ST_CONNECTED:
		n = "CONNECTED";
		break;
	case SMBIOD_ST_NEGOTIATED:
		n = "NEGOTIATED";
		break;
	case SMBIOD_ST_AUTHCONT:
		n = "AUTHCONT";
		break;
	case SMBIOD_ST_AUTHFAIL:
		n = "AUTHFAIL";
		break;
	case SMBIOD_ST_AUTHOK:
		n = "AUTHOK";
		break;
	case SMBIOD_ST_VCACTIVE:
		n = "VCACTIVE";
		break;
	case SMBIOD_ST_DEAD:
		n = "DEAD";
		break;
	}

	return (n);
}

/*
 * Make a new connection, or reconnect.
 *
 * This is called first from the door service thread in smbiod
 * (so that can report success or failure to the door client)
 * and thereafter it's called when we need to reconnect after a
 * network outage (or whatever might cause connection loss).
 */
int
smb_iod_connect(smb_ctx_t *ctx)
{
	smbioc_ossn_t *ossn = &ctx->ct_ssn;
	smbioc_ssn_work_t *work = &ctx->ct_work;
	char *uuid_str;
	int err;
	struct mbdata blob;
	char *nego_buf = NULL;
	uint32_t nego_len;

	memset(&blob, 0, sizeof (blob));

	if (ctx->ct_srvname[0] == '\0') {
		DPRINT("sername not set!");
		return (EINVAL);
	}
	DPRINT("server: %s", ctx->ct_srvname);

	if (smb_debug)
		dump_ctx("smb_iod_connect", ctx);

	/*
	 * Get local machine name.
	 * Full name - not a NetBIOS name.
	 */
	if (ctx->ct_locname == NULL) {
		err = smb_getlocalname(&ctx->ct_locname);
		if (err) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "can't get local name"), err);
			return (err);
		}
	}

	/*
	 * Get local machine uuid.
	 */
	uuid_str = cf_get_client_uuid();
	if (uuid_str == NULL) {
		err = EINVAL;
		smb_error(dgettext(TEXT_DOMAIN,
		    "can't get local UUID"), err);
			return (err);
	}
	(void) uuid_parse(uuid_str, ctx->ct_work.wk_cl_guid);
	free(uuid_str);
	uuid_str = NULL;

	/*
	 * We're called with each IP address
	 * already copied into ct_srvaddr.
	 */
	ctx->ct_flags |= SMBCF_RESOLVED;

	/*
	 * Ask the drvier to connect.
	 */
	DPRINT("Try ioctl connect...");
	if (nsmb_ioctl(ctx->ct_dev_fd, SMBIOC_IOD_CONNECT, work) < 0) {
		err = errno;
		smb_error(dgettext(TEXT_DOMAIN,
		    "%s: connect failed"),
		    err, ossn->ssn_srvname);
		return (err);
	}
	DPRINT("Connect OK, new state=%s",
	    smb_iod_state_name(work->wk_out_state));

	/*
	 * Setup a buffer to recv the nego. hint.
	 */
	nego_len = 4096;
	err = mb_init_sz(&blob, nego_len);
	if (err)
		goto out;
	nego_buf = blob.mb_top->m_data;
	work->wk_u_auth_rbuf.lp_ptr = nego_buf;
	work->wk_u_auth_rlen = nego_len;

	/*
	 * Ask the driver for SMB negotiate
	 */
	DPRINT("Try ioctl negotiate...");
	if (nsmb_ioctl(ctx->ct_dev_fd, SMBIOC_IOD_NEGOTIATE, work) < 0) {
		err = errno;
		smb_error(dgettext(TEXT_DOMAIN,
		    "%s: negotiate failed"),
		    err, ossn->ssn_srvname);
		goto out;
	}
	DPRINT("Negotiate OK, new state=%s",
	    smb_iod_state_name(work->wk_out_state));

	nego_len = work->wk_u_auth_rlen;
	blob.mb_top->m_len = nego_len;

	if (smb_debug) {
		DPRINT("Sec. blob: %d", nego_len);
		smb_hexdump(nego_buf, nego_len);
	}

	/*
	 * Do SMB Session Setup (authenticate)
	 * Always "extended security" now (SPNEGO)
	 */
	DPRINT("Do session setup...");
	err = smb_ssnsetup_spnego(ctx, &blob);
	if (err != 0) {
		DPRINT("Session setup err=%d", err);
		goto out;
	}

	/*
	 * Success! We return zero now, and our caller (normally
	 * the smbiod program) will then call smb_iod_work in a
	 * new thread to service this VC as long as necessary.
	 */
	DPRINT("Session setup OK");

out:
	mb_done(&blob);

	return (err);
}

/*
 * smb_ssnsetup_spnego
 *
 * This does an SMB session setup sequence using SPNEGO.
 * The state changes seen during this sequence are there
 * just to help track what's going on.
 */
int
smb_ssnsetup_spnego(struct smb_ctx *ctx, struct mbdata *hint_mb)
{
	struct mbdata send_mb, recv_mb;
	smbioc_ssn_work_t *work = &ctx->ct_work;
	int		err;

	bzero(&send_mb, sizeof (send_mb));
	bzero(&recv_mb, sizeof (recv_mb));

	err = ssp_ctx_create_client(ctx, hint_mb);
	if (err)
		goto out;

	/* NULL input indicates first call. */
	err = ssp_ctx_next_token(ctx, NULL, &send_mb);
	if (err) {
		DPRINT("smb__ssnsetup, ssp next, err=%d", err);
		goto out;
	}
	for (;;) {
		err = smb__ssnsetup(ctx, &send_mb, &recv_mb);
		DPRINT("smb__ssnsetup rc=%d, new state=%s", err,
		    smb_iod_state_name(work->wk_out_state));

		if (err == 0) {
			/*
			 * Session setup complete w/ success.
			 * Should have state AUTHOK
			 */
			if (work->wk_out_state != SMBIOD_ST_AUTHOK) {
				DPRINT("Wrong state (expected AUTHOK)");
			}
			break;
		}

		if (err != EINPROGRESS) {
			/*
			 * Session setup complete w/ failure.
			 * Should have state AUTHFAIL
			 */
			if (work->wk_out_state != SMBIOD_ST_AUTHFAIL) {
				DPRINT("Wrong state (expected AUTHFAIL)");
			}
			goto out;
		}

		/*
		 * err == EINPROGRESS
		 * Session setup continuing.
		 * Should have state AUTHCONT
		 */
		if (work->wk_out_state != SMBIOD_ST_AUTHCONT) {
			DPRINT("Wrong state (expected AUTHCONT)");
		}

		/* middle calls get both in, out */
		err = ssp_ctx_next_token(ctx, &recv_mb, &send_mb);
		if (err) {
			DPRINT("smb__ssnsetup, ssp next, err=%d", err);
			goto out;
		}
	}

	/*
	 * Only get here via break in the err==0 case above,
	 * so we're finalizing a successful session setup.
	 *
	 * NULL output token here indicates the final call.
	 */
	(void) ssp_ctx_next_token(ctx, &recv_mb, NULL);

	/*
	 * The session key is in ctx->ct_ssnkey_buf
	 * (a.k.a. ct_work.wk_u_ssn_key_buf)
	 */

out:
	/* Done with ctx->ct_ssp_ctx */
	ssp_ctx_destroy(ctx);

	return (err);
}

int smb_max_authtok_sz = 0x10000;

/*
 * Session Setup function, calling the nsmb driver.
 *
 * Args
 *	send_mb: [in]  outgoing blob data to send
 *	recv_mb: [out] received blob data buffer
 */
static int
smb__ssnsetup(struct smb_ctx *ctx,
	struct mbdata *send_mb, struct mbdata *recv_mb)
{
	smbioc_ossn_t *ossn = &ctx->ct_ssn;
	smbioc_ssn_work_t *work = &ctx->ct_work;
	mbuf_t *m;
	int err;

	/* Setup receive buffer for the auth data. */
	err = mb_init_sz(recv_mb, smb_max_authtok_sz);
	if (err != 0)
		return (err);
	m = recv_mb->mb_top;
	work->wk_u_auth_rbuf.lp_ptr = m->m_data;
	work->wk_u_auth_rlen        = m->m_maxlen;

	/* ... and the auth data to send. */
	m = send_mb->mb_top;
	work->wk_u_auth_wbuf.lp_ptr = m->m_data;
	work->wk_u_auth_wlen        = m->m_len;

	DPRINT("Session setup ioctl...");
	if (nsmb_ioctl(ctx->ct_dev_fd, SMBIOC_IOD_SSNSETUP, work) < 0) {
		err = errno;
		if (err != 0 && err != EINPROGRESS) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "%s: session setup "),
			    err, ossn->ssn_srvname);
		}
	}
	DPRINT("Session setup ret %d", err);

	/* Free the auth data we sent. */
	mb_done(send_mb);

	/* Setup length of received auth data */
	m = recv_mb->mb_top;
	m->m_len = work->wk_u_auth_rlen;

	return (err);
}
