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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Test program for the smbfs named pipe API.
 */

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <ctype.h>

#include <netsmb/smb_lib.h>

/*
 * This is a quick hack for testing client-side named pipes.
 * Its purpose is to test SMB named-pipe interface separately
 * from the RPC implementation.  It's a "hack" because it uses
 * hand-crafted RPC messages (extracted from network traffic).
 */

/* This is a DCE/RPC bind call for "srvsvc". */
static const uchar_t
srvsvc_bind[] = {
	0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
	0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x10, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
	0x03, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
	0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
	0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 };

/* This is a srvsvc "enum servers" call, in two parts */
static const uchar_t
srvsvc_enum1[] = {
	0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
#define	ENUM_RPCLEN_OFF	8
	/* V - RPC frag length */
	0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* ... and the operation number is: VVVV */
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0f, 0x00,
#define	ENUM_SLEN1_OFF	28
#define	ENUM_SLEN2_OFF	36
	/* server name, length 14 vv ... */
	0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00 };
	/* UNC server here, i.e.: "\\192.168.1.6" */

static const uchar_t
srvsvc_enum2[] = {
	0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 };

static uchar_t sendbuf[1024];
static uchar_t recvbuf[4096];

/*
 * Print strings found in the buffer.
 */
static void
pstrings(const uchar_t *buf, int len)
{
	const uchar_t *p = buf;
	uint16_t u2;
	boolean_t instr = B_FALSE;

	while (len > 2) {
		u2 = *p++;
		u2 |= (*p++) << 8;
		len -= 2;

		if ((u2 & 0xFF80) == 0 && isprint(u2)) {
			/* printable */
			instr = B_TRUE;
			putchar(u2);
		} else {
			/* not printalbe */
			if (instr)
				putchar('\n');
			instr = B_FALSE;
		}
	}
	if (instr)
		putchar('\n');
}

/*
 * Put a unicode UNC server name, including the null.
 * Quick-n-dirty, just for this test...
 */
static int
put_uncserver(const char *s, uchar_t *buf)
{
	uchar_t *p = buf;
	char c;

	*p++ = '\\'; *p++ = '\0';
	*p++ = '\\'; *p++ = '\0';

	do {
		c = *s++;
		if (c == '/')
			c = '\\';
		*p++ = c;
		*p++ = '\0';

	} while (c != 0);

	return (p - buf);
}

/*
 * Send the bind and read the ack.
 * This tests smb_fh_xactnp.
 */
static int
do_bind(int fid)
{
	int err, len, more;

	more = 0;
	len = sizeof (recvbuf);
	err = smb_fh_xactnp(fid,
	    sizeof (srvsvc_bind), (char *)srvsvc_bind,
	    &len, (char *)recvbuf, &more);
	if (err) {
		printf("xact bind, err=%d\n", err);
		return (err);
	}
	if (more > 0) {
		if (more > sizeof (recvbuf)) {
			printf("bogus more=%d\n", more);
			more = sizeof (recvbuf);
		}
		len = smb_fh_read(fid, 0,
		    more, (char *)recvbuf);
		if (len == -1) {
			err = EIO;
			printf("read enum resp, err=%d\n", err);
			return (err);
		}
	}

	return (0);
}

static int
do_enum(char *server, int fid)
{
	int err, len, rlen, wlen;
	uchar_t *p;

	/*
	 * Build the enum request - three parts.
	 * See above: srvsvc_enum1, srvsvc_enum2
	 *
	 * First part: RPC header, etc.
	 */
	p = sendbuf;
	len = sizeof (srvsvc_enum1); /* 40 */
	memcpy(p, srvsvc_enum1, len);
	p += len;

	/* Second part: UNC server name */
	len = put_uncserver(server, p);
	p += len;
	sendbuf[ENUM_SLEN1_OFF] = len / 2;
	sendbuf[ENUM_SLEN2_OFF] = len / 2;

	/* Third part: level, etc. (align4) */
	for (len = (p - sendbuf) & 3; len; len--)
		*p++ = '\0';
	len = sizeof (srvsvc_enum2); /* 28 */
	memcpy(p, srvsvc_enum2, len);
	p += len;

	/*
	 * Compute total length, and fixup RPC header.
	 */
	len = p - sendbuf;
	sendbuf[ENUM_RPCLEN_OFF] = len;

	/*
	 * Send the enum request, read the response.
	 * This tests smb_fh_write, smb_fh_read.
	 */
	wlen = smb_fh_write(fid, 0, len, (char *)sendbuf);
	if (wlen == -1) {
		err = errno;
		printf("write enum req, err=%d\n", err);
		return (err);
	}
	if (wlen != len) {
		printf("write enum req, short write %d\n", wlen);
		return (EIO);
	}

	rlen = smb_fh_read(fid, 0,
	    sizeof (recvbuf), (char *)recvbuf);
	if (rlen == -1) {
		err = errno;
		printf("read enum resp, err=%d\n", err);
		return (err);
	}

	/*
	 * Just dump strings found in the response data.
	 * Skip the first 0x90 (RPC wrappers).
	 */
	printf("enum strings\n");
	pstrings(recvbuf + 0x90, rlen - 0x90);

	return (0);
}

int
list_shares(struct smb_ctx *ctx)
{
	static char path[] = "/srvsvc";
	static uchar_t key[16];
	char *server = ctx->ct_srvname;
	int err, fd;

	printf("open pipe: %s\n", path);
	fd = smb_fh_open(ctx, path, O_RDWR);
	if (fd < 0) {
		perror(path);
		return (errno);
	}

	/* Test this too. */
	err = smb_fh_getssnkey(fd, key, sizeof (key));
	if (err) {
		printf("getssnkey: %d\n", err);
		goto out;
	}

	err = do_bind(fd);
	if (err) {
		printf("do_bind: %d\n", err);
		goto out;
	}
	err = do_enum(server, fd);
	if (err)
		printf("do_enum: %d\n", err);

out:
	smb_fh_close(fd);
	return (0);
}
