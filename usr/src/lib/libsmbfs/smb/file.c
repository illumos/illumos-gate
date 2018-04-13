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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>

#include "private.h"

int
smb_fh_close(int fd)
{
	return (close(fd));
}

int
smb_fh_ntcreate(
	struct smb_ctx *ctx, char *path,
	int req_acc, int efattr, int share_acc,
	int open_disp, int create_opts)
{
	smbioc_ntcreate_t ioc;
	int err, nmlen;
	int new_fd = -1;
	int32_t from_fd;

	nmlen = strlen(path);
	if (nmlen >= SMBIOC_MAX_NAME) {
		err = EINVAL;
		goto errout;
	}

	/*
	 * Will represent this SMB-level open as a new
	 * open device handle.  Get one, then duplicate
	 * the driver session and tree bindings.
	 */
	new_fd = smb_open_driver();
	if (new_fd < 0) {
		err = errno;
		goto errout;
	}
	from_fd = ctx->ct_dev_fd;
	if (ioctl(new_fd, SMBIOC_DUP_DEV, &from_fd) == -1) {
		err = errno;
		goto errout;
	}

	/*
	 * Do the SMB-level open with the new dev handle.
	 */
	bzero(&ioc, sizeof (ioc));
	strlcpy(ioc.ioc_name, path, SMBIOC_MAX_NAME);
	ioc.ioc_req_acc = req_acc;
	ioc.ioc_efattr = efattr;
	ioc.ioc_share_acc = share_acc;
	ioc.ioc_open_disp = open_disp;
	ioc.ioc_creat_opts = create_opts;
	if (ioctl(new_fd, SMBIOC_NTCREATE, &ioc) == -1) {
		err = errno;
		goto errout;
	}

	return (new_fd);

errout:
	if (new_fd != -1)
		close(new_fd);
	errno = err;
	return (-1);
}

/*
 * Conveinence wrapper for smb_fh_ntcreate
 * Converts Unix-style open call to NTCreate.
 */
int
smb_fh_open(struct smb_ctx *ctx, const char *path, int oflag)
{
	int mode, open_disp, req_acc, share_acc;
	char *p, *ntpath = NULL;
	int fd = -1;

	/*
	 * Convert Unix path to NT (backslashes)
	 */
	ntpath = strdup(path);
	if (ntpath == NULL)
		return (-1);	/* errno was set */
	for (p = ntpath; *p; p++)
		if (*p == '/')
			*p = '\\';

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

	fd = smb_fh_ntcreate(ctx, ntpath,
	    req_acc, SMB_EFA_NORMAL, share_acc, open_disp,
	    NTCREATEX_OPTIONS_NON_DIRECTORY_FILE);

	free(ntpath);
	return (fd);
}

int
smb_fh_read(int fd, off64_t offset, size_t count,
	char *dst)
{
	struct smbioc_rw rwrq;

	bzero(&rwrq, sizeof (rwrq));
	rwrq.ioc_fh = -1;	/* tell driver to supply this */
	rwrq.ioc_base = dst;
	rwrq.ioc_cnt = count;
	rwrq.ioc_offset = offset;
	if (ioctl(fd, SMBIOC_READ, &rwrq) == -1) {
		return (-1);
	}
	return (rwrq.ioc_cnt);
}

int
smb_fh_write(int fd, off64_t offset, size_t count,
	const char *src)
{
	struct smbioc_rw rwrq;

	bzero(&rwrq, sizeof (rwrq));
	rwrq.ioc_fh = -1;	/* tell driver to supply this */
	rwrq.ioc_base = (char *)src;
	rwrq.ioc_cnt = count;
	rwrq.ioc_offset = offset;
	if (ioctl(fd, SMBIOC_WRITE, &rwrq) == -1) {
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
smb_fh_xactnp(int fd,
	int tdlen, const char *tdata,	/* transmit */
	int *rdlen, char *rdata,	/* receive */
	int *more)
{
	int		err, rparamcnt;
	uint16_t	setup[2];

	setup[0] = TRANS_TRANSACT_NAMED_PIPE;
	setup[1] = 0xFFFF; /* driver replaces this */
	rparamcnt = 0;

	err = smb_t2_request(fd, 2, setup, "\\PIPE\\",
	    0, NULL,	/* TX paramcnt, params */
	    tdlen, (void *)tdata,
	    &rparamcnt, NULL,	/* no RX params */
	    rdlen, rdata, more);

	if (err)
		*rdlen = 0;

	return (err);
}
