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

/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
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

#include <netsmb/smb.h>
#include <netsmb/smb_lib.h>

#include "private.h"

/*
 * Replacing invalid characters in print job titles:
 *
 * The spec. is unclear about what characters are allowed in a
 * print job title (used with NtCreate) so out of caution this
 * makes sure the title contains none of the characters that
 * are known to be illegal in a file name component.
 */
static const char invalid_chars[] = SMB_FILENAME_INVALID_CHARS;

int
smb_open_printer(struct smb_ctx *ctx, const char *title,
	int setuplen, int mode)
{
	smbioc_printjob_t ioc;
	char *p;
	int err, tlen;
	int new_fd = -1;
	int32_t from_fd;

	tlen = strlen(title);
	if (tlen >= SMBIOC_MAX_NAME)
		return (EINVAL);

	/*
	 * Will represent this SMB-level open as a new
	 * open device handle.  Get one, then duplicate
	 * the driver session and tree bindings.
	 */
	new_fd = smb_open_driver();
	if (new_fd < 0)
		return (errno);
	from_fd = ctx->ct_dev_fd;
	if (nsmb_ioctl(new_fd, SMBIOC_DUP_DEV, &from_fd) == -1) {
		err = errno;
		goto errout;
	}

	/*
	 * Do the SMB-level open with the new dev handle.
	 */
	bzero(&ioc, sizeof (ioc));
	ioc.ioc_setuplen = setuplen;
	ioc.ioc_prmode = mode;
	strlcpy(ioc.ioc_title, title, SMBIOC_MAX_NAME);

	/*
	 * The title is used in NtCreate so sanitize by
	 * replacing any illegal chars with spaces.
	 */
	for (p = ioc.ioc_title; *p != '\0'; p++)
		if (strchr(invalid_chars, *p) != NULL)
			*p = ' ';

	if (nsmb_ioctl(new_fd, SMBIOC_PRINTJOB, &ioc) == -1) {
		err = errno;
		goto errout;
	}

	return (new_fd);

errout:
	nsmb_close(new_fd);
	errno = err;
	return (-1);
}
