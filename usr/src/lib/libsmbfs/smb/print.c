/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: print.c,v 1.1.1.3 2001/07/06 22:38:43 conrad Exp $
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>
#include "private.h"

int
smb_printer_open(struct smb_ctx *ctx, int setuplen, int mode,
	const char *ident, int *fhp)
{
	struct smb_rq *rqp;
	struct mbdata *mbp;
	int error, flags2, uc;
	uint16_t fh;
	uint8_t wc;

	flags2 = smb_ctx_flags2(ctx);
	if (flags2 == -1)
		return (EIO);
	uc = flags2 & SMB_FLAGS2_UNICODE;

	error = smb_rq_init(ctx, SMB_COM_OPEN_PRINT_FILE, &rqp);
	if (error)
		return (error);
	mbp = smb_rq_getrequest(rqp);
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, setuplen);
	mb_put_uint16le(mbp, mode);
	smb_rq_wend(rqp);
	smb_rq_bstart(rqp);
	mb_put_uint8(mbp, SMB_DT_ASCII);
	mb_put_string(mbp, ident, uc);
	smb_rq_bend(rqp);
	error = smb_rq_simple(rqp);
	if (error)
		goto out;

	mbp = smb_rq_getreply(rqp);
	error = md_get_uint8(mbp, &wc);
	if (error || wc < 1) {
		error = EBADRPC;
		goto out;
	}
	md_get_uint16le(mbp, &fh);
	*fhp = fh;
	error = 0;

out:
	smb_rq_done(rqp);
	return (error);
}

/*
 * Similar to smb_fh_close
 */
int
smb_printer_close(struct smb_ctx *ctx, int fh)
{
	struct smb_rq *rqp;
	struct mbdata *mbp;
	int error;

	error = smb_rq_init(ctx, SMB_COM_CLOSE_PRINT_FILE, &rqp);
	if (error)
		return (error);
	mbp = smb_rq_getrequest(rqp);
	smb_rq_wstart(rqp);
	mb_put_uint16le(mbp, (uint16_t)fh);
	smb_rq_wend(rqp);
	mb_put_uint16le(mbp, 0);	/* byte count */

	error = smb_rq_simple(rqp);
	smb_rq_done(rqp);

	return (error);
}
