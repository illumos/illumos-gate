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
 * $Id: file.c,v 1.4 2004/12/13 00:25:21 lindak Exp $
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <strings.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <libintl.h>

#include <sys/types.h>
#include <sys/file.h>

#include <netsmb/smb_lib.h>
#include <cflib.h>

#include "charsets.h"
#include "private.h"

int
smb_fh_close(struct smb_ctx *ctx, smbfh fh)
{
	struct smb_rq	*rqp;
	struct mbdata	*mbp;
	int serr;

	serr = smb_rq_init(ctx, SMB_COM_CLOSE, 0, &rqp);
	if (serr != 0)
		return (serr);
	mbp = smb_rq_getrequest(rqp);
	mb_put_uint16le(mbp, fh);
	mb_put_uint32le(mbp, 0);	/* time stamp */
	smb_rq_wend(rqp);
	serr = smb_rq_simple(rqp);
	if (serr != 0) {
		smb_rq_done(rqp);
		return (serr);
	}
	mbp = smb_rq_getreply(rqp);
	smb_rq_done(rqp);

	return (serr);
}

int
smb_fh_ntcreate(
	struct smb_ctx *ctx, char *path,
	int flags, int req_acc, int efattr,
	int share_acc, int open_disp,
	int create_opts, int impersonation,
	smbfh *fhp, uint32_t *action_taken)
{
	struct smb_rq	*rqp;
	struct mbdata	*mbp;
	uint8_t		wc;
	size_t		pathlen, pathsize;
	int		error, flags2;
	uint16_t	*upath = NULL;

	flags2 = smb_ctx_flags2(ctx);
	if (flags2 == -1)
		return (EIO);

	error = smb_rq_init(ctx, SMB_COM_NT_CREATE_ANDX, 42, &rqp);
	if (error != 0)
		return (error);

	if (flags2 & SMB_FLAGS2_UNICODE) {
		upath = convert_utf8_to_leunicode(path);
		if (upath == NULL) {
			smb_error(dgettext(TEXT_DOMAIN,
			    "%s: failed converting to UCS-2"), 0, path);
			error = EINVAL;
			goto out;
		}
		pathlen = unicode_strlen(upath);
		pathsize = (pathlen + 1) * 2;
	} else {
		pathlen = strlen(path);
		pathsize = pathlen + 1;
	}

	mbp = smb_rq_getrequest(rqp);
	mb_put_uint8(mbp, 0xff);	/* secondary command */
	mb_put_uint8(mbp, 0);		/* MBZ */
	mb_put_uint16le(mbp, 0);	/* offset to next command (none) */
	mb_put_uint8(mbp, 0);		/* MBZ */
	mb_put_uint16le(mbp, pathsize);	/* path size (bytes) */
	mb_put_uint32le(mbp, 0);	/* create flags (oplock) */
	mb_put_uint32le(mbp, 0);	/* FID - basis for path if not root */
	mb_put_uint32le(mbp, req_acc);
	mb_put_uint64le(mbp, 0);		/* initial alloc. size */
	mb_put_uint32le(mbp, efattr);		/* ext. file attributes */
	mb_put_uint32le(mbp, share_acc);	/* share access mode */
	mb_put_uint32le(mbp, open_disp);	/* open disposition */
	mb_put_uint32le(mbp, create_opts);  /* create_options */
	mb_put_uint32le(mbp, NTCREATEX_IMPERSONATION_IMPERSONATION); /* (?) */
	mb_put_uint8(mbp, 0);	/* security flags (?) */
	smb_rq_wend(rqp);

	/* XXX: Need a "put string" function. */
	if (flags2 & SMB_FLAGS2_UNICODE) {
		mb_put_uint8(mbp, 0);	/* pad byte - align(2) for Unicode */
		mb_put_mem(mbp, (char *)upath, pathsize);
	} else
		mb_put_mem(mbp, path, pathsize);

	error = smb_rq_simple(rqp);
	if (error)
		goto out;

	mbp = smb_rq_getreply(rqp);
	/*
	 * spec says 26 for word count, but 34 words are defined
	 * and observed from win2000
	 */
	wc = rqp->rq_wcount;
	if (wc < 26) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "%s: open failed, bad word count"), 0, path);
		error = EBADRPC;
		goto out;
	}
	mb_get_uint8(mbp, NULL);	/* secondary cmd */
	mb_get_uint8(mbp, NULL);	/* mbz */
	mb_get_uint16le(mbp, NULL);	/* andxoffset */
	mb_get_uint8(mbp, NULL);	/* oplock lvl granted */
	mb_get_uint16le(mbp, fhp);	/* FID */
	mb_get_uint32le(mbp, action_taken);
#if 0	/* skip decoding the rest */
	mb_get_uint64le(mbp, NULL);	/* creation time */
	mb_get_uint64le(mbp, NULL);	/* access time */
	mb_get_uint64le(mbp, NULL);	/* write time */
	mb_get_uint64le(mbp, NULL);	/* change time */
	mb_get_uint32le(mbp, NULL);	/* attributes */
	mb_get_uint64le(mbp, NULL);	/* allocation size */
	mb_get_uint64le(mbp, NULL);	/* EOF */
	mb_get_uint16le(mbp, NULL);	/* file type */
	mb_get_uint16le(mbp, NULL);	/* device state */
	mb_get_uint8(mbp, NULL);	/* directory (boolean) */
#endif	/* skip decoding */

out:
	if (upath)
		free(upath);
	smb_rq_done(rqp);

	return (0);
}

/*
 * Conveinence wrapper for smb_fh_ntcreate
 * Converts Unix-style open call to NTCreate.
 */
int
smb_fh_open(struct smb_ctx *ctx, const char *path, int oflag, smbfh *fhp)
{
	int error, mode, open_disp, req_acc, share_acc;
	char *p, *ntpath = NULL;

	/*
	 * Map O_RDONLY, O_WRONLY, O_RDWR
	 * to FREAD, FWRITE
	 */
	mode = (oflag & 3) + 1;

	/*
	 * Compute requested access, share access.
	 */
	req_acc = (
	    STD_RIGHT_READ_CONTROL_ACCESS |
	    STD_RIGHT_SYNCHRONIZE_ACCESS);
	share_acc = NTCREATEX_SHARE_ACCESS_NONE;
	if (mode & FREAD) {
		req_acc |= (
		    SA_RIGHT_FILE_READ_DATA |
		    SA_RIGHT_FILE_READ_EA |
		    SA_RIGHT_FILE_READ_ATTRIBUTES);
		share_acc |= NTCREATEX_SHARE_ACCESS_READ;
	}
	if (mode & FWRITE) {
		req_acc |= (
		    SA_RIGHT_FILE_WRITE_DATA |
		    SA_RIGHT_FILE_APPEND_DATA |
		    SA_RIGHT_FILE_WRITE_EA |
		    SA_RIGHT_FILE_WRITE_ATTRIBUTES);
		share_acc |= NTCREATEX_SHARE_ACCESS_WRITE;
	}

	/*
	 * Compute open disposition
	 */
	if (oflag & FCREAT) {
		/* Creat if necessary. */
		if (oflag & FEXCL) {
			/* exclusive */
			open_disp = NTCREATEX_DISP_CREATE;
		} else if (oflag & FTRUNC)
			open_disp = NTCREATEX_DISP_OVERWRITE_IF;
		else
			open_disp = NTCREATEX_DISP_OPEN_IF;
	} else {
		/* Not creating. */
		if (oflag & FTRUNC)
			open_disp = NTCREATEX_DISP_OVERWRITE;
		else
			open_disp = NTCREATEX_DISP_OPEN;
	}

	/*
	 * Convert Unix path to NT (backslashes)
	 */
	ntpath = strdup(path);
	if (ntpath == NULL)
		return (ENOMEM);
	for (p = ntpath; *p; p++)
		if (*p == '/')
			*p = '\\';

	error = smb_fh_ntcreate(ctx, ntpath, 0, /* flags */
	    req_acc, SMB_EFA_NORMAL, share_acc, open_disp,
	    NTCREATEX_OPTIONS_NON_DIRECTORY_FILE,
	    NTCREATEX_IMPERSONATION_IMPERSONATION,
	    fhp, NULL);
	free(ntpath);

	return (error);
}

int
smb_fh_read(struct smb_ctx *ctx, smbfh fh, off_t offset, size_t count,
	char *dst)
{
	struct smbioc_rw rwrq;

	bzero(&rwrq, sizeof (rwrq));
	rwrq.ioc_fh = fh;
	rwrq.ioc_base = dst;
	rwrq.ioc_cnt = count;
	rwrq.ioc_offset = offset;
	if (ioctl(ctx->ct_fd, SMBIOC_READ, &rwrq) == -1) {
		return (-1);
	}
	return (rwrq.ioc_cnt);
}

int
smb_fh_write(struct smb_ctx *ctx, smbfh fh, off_t offset, size_t count,
	const char *src)
{
	struct smbioc_rw rwrq;

	bzero(&rwrq, sizeof (rwrq));
	rwrq.ioc_fh = fh;
	rwrq.ioc_base = (char *)src;
	rwrq.ioc_cnt = count;
	rwrq.ioc_offset = offset;
	if (ioctl(ctx->ct_fd, SMBIOC_WRITE, &rwrq) == -1) {
		return (-1);
	}
	return (rwrq.ioc_cnt);
}

/*
 * Do a TRANSACT_NAMED_PIPE, which is basically just a
 * pipe write and pipe read, all in one round trip.
 *
 * tdlen, tdata describe the data to send.
 * rdlen, rdata on input describe the receive buffer,
 * and on output *rdlen is the received length.
 */
int
smb_fh_xactnp(struct smb_ctx *ctx, smbfh fh,
	int tdlen, const char *tdata,	/* transmit */
	int *rdlen, char *rdata,	/* receive */
	int *more)
{
	int		err, rparamcnt;
	uint16_t	setup[2];

	setup[0] = TRANS_TRANSACT_NAMED_PIPE;
	setup[1] = fh;
	rparamcnt = 0;

	err = smb_t2_request(ctx, 2, setup, "\\PIPE\\",
	    0, NULL,	/* TX paramcnt, params */
	    tdlen, (void *)tdata,
	    &rparamcnt, NULL,	/* no RX params */
	    rdlen, rdata, more);

	if (err)
		*rdlen = 0;

	return (err);
}
