/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef lint
static char sccsid[] = "%Z%%M% %I% %E% SMI";
#endif

#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mkdev.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>

#include "praudit.h"

extern char *sys_errlist[];
extern int  sys_nerr;

static int au_fetch_char();
static int au_fetch_short();
static int au_fetch_int32();
static int au_fetch_int64();
static int au_fetch_bytes();
static char *get_Hname();
static void convertascii();
static int convert_char_to_string();
static int convert_int32_to_string();
static int convert_int64_to_string();
static int convertbinary();
static char *hexconvert();
static char *pa_gettokenstring();

/*
 * au_read_rec:
 *	If the file pointer or the record buffer passed in are NULL,
 *	free up the static space and return an error code < 0.
 *	Otherwise, attempt to read an audit record from the file pointer.
 *
 *	If successful:
 *		Set recbuf to the pointer to the space holding the record.
 *		Advance in the stream(fp).
 *		Return 0.
 *
 *	If failed:
 *		Don't alter recbuf.
 *		Don't advance the stream.
 *		Return error code < 0.
 */

int
au_read_rec(FILE *fp, char **recbuf)
{
	static char	*p_space = NULL; /* pointer to a record buffer */
	static int	cur_size = 0;	/* size of p_space in bytes */

	adr_t		adr;
	adrf_t		adrf;
	char		tokenid;	/* token (attribute) identifier */
	uint32_t	record_size;	/* length of a header attr record */
	ushort_t	name_len;	/* length of a file attribute record */
	long		start_pos;	/* initial position in fp */
	int		new_size;	/* size of the new space in bytes */

	if (fp == NULL || recbuf == NULL) {
		cur_size = 0;
		free(p_space);
		return (-1);
	}

	/*
	 * Use the adr routines for reading the audit trail.
	 * They have a bit of overhead, but the already do
	 * the byte stream conversions that we will need.
	 */
	adrf_start(&adrf, &adr, fp);

	/*
	 * Save the current position in the file.
	 * We`ll need to back up to here before
	 * reading in the entire record.
	 */
	start_pos = ftell(fp);

	/* Determine the amount of space needed for the record... */

	/* Skip passed the token id */
	if (adrf_char(adrf, &tokenid, 1) != 0) {
		return (-2);
	}

	/* Read in the size of the record */
	if (tokenid == AUT_HEADER32 || tokenid == AUT_HEADER64) {
		if (adrf_u_int32(adrf, &record_size, 1) != 0) {
			fseek(fp, start_pos, SEEK_SET);
			return (-4);
		}
	} else if (tokenid == AUT_OTHER_FILE32) {
		int32_t date_time[2];

		if (adrf_int32(adrf, date_time, 8) != 0) {
			fseek(fp, start_pos, SEEK_SET);
			return (-5);
		}
		if (adrf_u_short(adrf, &name_len, 1) != 0) {
			fseek(fp, start_pos, SEEK_SET);
			return (-6);
		}
		/* 11 is the size of an attr id, */
		/* date&time32, and name length */
		record_size = (uint_t)name_len + 11;
	} else if (tokenid == AUT_OTHER_FILE64) {
		int64_t date_time[2];

		if (adrf_int64(adrf, date_time, 2) != 0) {
			fseek(fp, start_pos, SEEK_SET);
			return (-5);
		}
		if (adrf_u_short(adrf, &name_len, 1) != 0) {
			fseek(fp, start_pos, SEEK_SET);
			return (-6);
		}
		/* 19 is the size of an date&time64 */
		record_size = (uint_t)name_len + 19;
	} else {
		fseek(fp, start_pos, SEEK_SET);
		return (-7);
	}

	/* Go back to the starting point so we can read in the entire record */
	fseek(fp, start_pos, SEEK_SET);

	/*
	 * If the current size of the static p_space cannot hold
	 * the entire record, make it larger.
	 */
	new_size = cur_size;
	while (new_size < record_size) {
		new_size += 512;
		/*
		 * If we need more than a megabyte to hold a single record
		 * something is amiss.
		 */
		if (new_size > 1000000) {
			return (-8);
		}
	}
	if (new_size != cur_size) {
		cur_size = 0;
		free(p_space);
		if ((p_space = (char *)malloc(new_size)) == NULL) {
			return (-9);
		}
		cur_size = new_size;
	}

	/* Do what we came here for; read an audit record */
	if (fread(p_space, record_size, 1, fp) != 1) {
		fseek(fp, start_pos, SEEK_SET);
		return (-10);
	}

	/* Pad the buffer with zeroes */
	memset(p_space + record_size, '\0', cur_size - record_size);

	*recbuf = (char *)p_space;
	return (0);
}

/*
 * au_fetch_tok():
 *
 * Au_fetch_tok() behaves like strtok(3).  On the first call, a buffer
 * is passed in.  On subsequent calls, NULL is passed in as buffer.
 * Au_fetch_tok() manages the buffer pointer offset and returns tokens
 * until the end of the buffer is reached.  The user of the routine must
 * guarantee that the buffer starts with and contains at least one full
 * audit record.  This type of assurance is provided by au_read_rec().
 */

int
au_fetch_tok(au_token_t *tok, char *buf, int flags)
{
	static char *invalid_txt = "invalid token id";
	static int len_invalid_txt = 17;
	static char *old_buf = NULL; /* position in buf at end of last fetch */
	char *orig_buf; /* position in buf when fetch entered */
	char *cur_buf; /* current location in buf */
	int length;
	int i;
	int valid_id;

	/* Check flags, one should be on.  */
	i = 0;
	if (flags & AUF_POINT) {
		i++;
	}
	if (flags & AUF_DUP) {
		i++;
	}
	if (flags & AUF_COPY_IN) {
		i++;
	}
	if (i != 1) {
		return (-1);
	}
	/* Skip not implemented, yet */
	if (flags & AUF_SKIP) {
		return (-2);
	}

	if (buf == NULL) {
		orig_buf = old_buf;
		cur_buf = old_buf;
	} else {
		orig_buf = buf;
		cur_buf = buf;
	}

	tok->data = cur_buf;
	au_fetch_char(&tok->id, &cur_buf, flags);
	tok->next = NULL;
	tok->prev = NULL;

	valid_id = 1;

	switch (tok->id) {
		case AUT_OTHER_FILE32:
			(void) au_fetch_int32(&tok->un.file32.time, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.file32.msec, &cur_buf,
			    flags);
			(void) au_fetch_short(&tok->un.file32.length, &cur_buf,
			    flags);
			(void) au_fetch_bytes(&tok->un.file32.fname, &cur_buf,
			    tok->un.file32.length, flags);
			tok->size = 11 + tok->un.file32.length;
		break;
		case AUT_OTHER_FILE64:
			(void) au_fetch_int64(&tok->un.file64.time, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.file64.msec, &cur_buf,
			    flags);
			(void) au_fetch_short(&tok->un.file64.length, &cur_buf,
			    flags);
			(void) au_fetch_bytes(&tok->un.file64.fname, &cur_buf,
			    tok->un.file64.length, flags);
			tok->size = 19 + tok->un.file64.length;
		break;
		case AUT_HEADER32:
			(void) au_fetch_int32(&tok->un.header32.length,
			    &cur_buf, flags);
			(void) au_fetch_char(&tok->un.header32.version,
			    &cur_buf, flags);
			(void) au_fetch_short(&tok->un.header32.event,
			    &cur_buf, flags);
			(void) au_fetch_short(&tok->un.header32.emod, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.header32.time, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.header32.msec, &cur_buf,
			    flags);
			tok->size = 18;
		break;
		case AUT_HEADER64:
			(void) au_fetch_int32(&tok->un.header64.length,
			    &cur_buf, flags);
			(void) au_fetch_char(&tok->un.header64.version,
			    &cur_buf, flags);
			(void) au_fetch_short(&tok->un.header64.event,
			    &cur_buf, flags);
			(void) au_fetch_short(&tok->un.header64.emod, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.header64.time, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.header64.msec, &cur_buf,
			    flags);
			tok->size = 26;
		break;
		case AUT_TRAILER:
			(void) au_fetch_short(&tok->un.trailer.magic, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.trailer.length, flags);
			tok->size = 7;
		break;
		case AUT_DATA:
			(void) au_fetch_char(&tok->un.data.pfmt, &cur_buf,
			    flags);
			(void) au_fetch_char(&tok->un.data.size, &cur_buf,
			    flags);
			(void) au_fetch_char(&tok->un.data.number, &cur_buf,
			    flags);
			length = (int)tok->un.data.size *
			    (int)tok->un.data.number;
			(void) au_fetch_bytes(&tok->un.data.data, &cur_buf,
			    length, flags);
			tok->size = 4 + length;
		break;
		case AUT_IPC:
			(void) au_fetch_int32(&tok->un.ipc.id, &cur_buf, flags);
			tok->size = 5;
		break;
		case AUT_PATH:
			(void) au_fetch_short(&tok->un.path.length, &cur_buf,
				flags);
			(void) au_fetch_bytes(&tok->un.path.name, &cur_buf,
			    tok->un.path.length, flags);
			tok->size = 3 + tok->un.path.length;
		break;
		case AUT_SUBJECT32:
			(void) au_fetch_int32(&tok->un.subj32.auid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj32.euid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj32.egid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj32.ruid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj32.rgid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj32.pid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj32.sid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj32.tid.port,
			    &cur_buf, flags);
			(void) au_fetch_int32(&tok->un.subj32.tid.machine,
			    &cur_buf, flags);
			tok->size = 37;
		break;
		case AUT_SUBJECT64:
			(void) au_fetch_int32(&tok->un.subj64.auid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj64.euid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj64.egid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj64.ruid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj64.rgid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj64.pid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.subj64.sid, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.subj64.tid.port,
			    &cur_buf, flags);
			(void) au_fetch_int32(&tok->un.subj64.tid.machine,
			    &cur_buf, flags);
			tok->size = 41;
		break;
		case AUT_PROCESS32:
			(void) au_fetch_int32(&tok->un.proc32.auid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc32.euid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc32.ruid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc32.rgid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc32.pid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc32.sid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc32.tid.port,
			    &cur_buf, flags);
			(void) au_fetch_int32(&tok->un.proc32.tid.machine,
			    &cur_buf, flags);
			tok->size = 33;
		case AUT_PROCESS64:
			(void) au_fetch_int32(&tok->un.proc64.auid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc64.euid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc64.ruid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc64.rgid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc64.pid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.proc64.sid, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.proc64.tid.port,
			    &cur_buf, flags);
			(void) au_fetch_int32(&tok->un.proc64.tid.machine,
			    &cur_buf, flags);
			tok->size = 37;
		break;
		case AUT_RETURN32:
			(void) au_fetch_char(&tok->un.ret32.error, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.ret32.retval, &cur_buf,
			    flags);
			tok->size = 6;
		break;
		case AUT_RETURN64:
			(void) au_fetch_char(&tok->un.ret64.error, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.ret64.retval, &cur_buf,
			    flags);
			tok->size = 10;
		break;
		case AUT_TEXT:
			(void) au_fetch_short(&tok->un.text.length, &cur_buf,
			    flags);
			(void) au_fetch_bytes(&tok->un.text.data, &cur_buf,
			    tok->un.text.length, flags);
			tok->size = 3 + tok->un.text.length;
		break;
		case AUT_OPAQUE:
			(void) au_fetch_short(&tok->un.opaque.length, &cur_buf,
			    flags);
			(void) au_fetch_bytes(&tok->un.opaque.data, &cur_buf,
			    tok->un.opaque.length, flags);
			tok->size = 3 + tok->un.opaque.length;
		break;
		case AUT_IN_ADDR:
			(void) au_fetch_int32(&tok->un.inaddr.ia.s_addr,
			    &cur_buf, flags);
			tok->size = 5;
		break;
		case AUT_IP:
			(void) au_fetch_char(&tok->un.ip.version, &cur_buf,
			    flags);
			(void) au_fetch_char(&tok->un.ip.ip.ip_tos, &cur_buf,
			    flags);
			(void) au_fetch_short(&tok->un.ip.ip.ip_len, &cur_buf,
			    flags);
			(void) au_fetch_short(&tok->un.ip.ip.ip_id, &cur_buf,
			    flags);
			(void) au_fetch_short(&tok->un.ip.ip.ip_off, &cur_buf,
			    flags);
			(void) au_fetch_char(&tok->un.ip.ip.ip_ttl, &cur_buf,
			    flags);
			(void) au_fetch_char(&tok->un.ip.ip.ip_p, &cur_buf,
			    flags);
			(void) au_fetch_short(&tok->un.ip.ip.ip_sum, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.ip.ip.ip_src.s_addr,
			    &cur_buf, flags);
			(void) au_fetch_int32(&tok->un.ip.ip.ip_dst.s_addr,
			    &cur_buf, flags);
			tok->size = 21;
		break;
		case AUT_IPORT:
			(void) au_fetch_short(&tok->un.iport.iport, &cur_buf,
			    flags);
			tok->size = 3;
		break;
		case AUT_ARG32:
			(void) au_fetch_char(&tok->un.arg32.num, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.arg32.val, &cur_buf,
			    flags);
			(void) au_fetch_short(&tok->un.arg32.length, &cur_buf,
			    flags);
			(void) au_fetch_bytes(&tok->un.arg32.data, &cur_buf,
			    tok->un.arg32.length, flags);
			tok->size = 8 + tok->un.arg32.length;
		case AUT_ARG64:
			(void) au_fetch_char(&tok->un.arg64.num, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.arg64.val, &cur_buf,
			    flags);
			(void) au_fetch_short(&tok->un.arg64.length, &cur_buf,
			    flags);
			(void) au_fetch_bytes(&tok->un.arg64.data, &cur_buf,
			    tok->un.arg64.length, flags);
			tok->size = 12 + tok->un.arg64.length;
		break;
		case AUT_SOCKET:
			(void) au_fetch_short(&tok->un.socket.type, &cur_buf,
			    flags);
			(void) au_fetch_short(&tok->un.socket.lport, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.socket.laddr.s_addr,
			    &cur_buf, flags);
			(void) au_fetch_short(&tok->un.socket.fport, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.socket.faddr.s_addr,
			    &cur_buf, flags);
			tok->size = 15;
		break;
		case AUT_SEQ:
			(void) au_fetch_int32(&tok->un.seq.num, &cur_buf,
			    flags);
			tok->size = 5;
		break;
		case AUT_ACL:
			(void) au_fetch_int32(&tok->un.acl.type,
			    &cur_buf, flags);
			(void) au_fetch_int32(&tok->un.acl.id, &cur_buf, flags);
			(void) au_fetch_int32(&tok->un.acl.mode,
			    &cur_buf, flags);
			tok->size = 13;
		break;
		case AUT_ATTR32:
			(void) au_fetch_int32(&tok->un.attr32.mode, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.attr32.uid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.attr32.gid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.attr32.fs, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.attr32.node, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.attr32.dev, &cur_buf,
			    flags);
			tok->size = 29;
		case AUT_ATTR64:
			(void) au_fetch_int32(&tok->un.attr64.mode, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.attr64.uid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.attr64.gid, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.attr64.fs, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.attr64.node, &cur_buf,
			    flags);
			(void) au_fetch_int64(&tok->un.attr64.dev, &cur_buf,
			    flags);
			tok->size = 33;
		break;
		case AUT_IPC_PERM:
			(void) au_fetch_int32(
			    &tok->un.ipc_perm.ipc_perm.ipc_uid,
			    &cur_buf, flags);
			(void) au_fetch_int32(
			    &tok->un.ipc_perm.ipc_perm.ipc_gid,
			    &cur_buf, flags);
			(void) au_fetch_int32(
			    &tok->un.ipc_perm.ipc_perm.ipc_cuid,
			    &cur_buf, flags);
			(void) au_fetch_int32(
			    &tok->un.ipc_perm.ipc_perm.ipc_cgid,
			    &cur_buf, flags);
			(void) au_fetch_int32(
			    &tok->un.ipc_perm.ipc_perm.ipc_mode,
			    &cur_buf, flags);
			(void) au_fetch_int32(
			    &tok->un.ipc_perm.ipc_perm.ipc_seq,
			    &cur_buf, flags);
			(void) au_fetch_int32(
			    &tok->un.ipc_perm.ipc_perm.ipc_key,
			    &cur_buf, flags);
			tok->size = 29;
		break;
		case AUT_GROUPS:
			for (i = 0; i < NGROUPS_MAX; i++) {
				(void) au_fetch_int32(&tok->un.groups.groups[i],
				    &cur_buf, flags);
			}
			tok->size = 1 + (NGROUPS_MAX * sizeof (gid_t));
		break;
		case AUT_EXIT:
			(void) au_fetch_int32(&tok->un.exit.status, &cur_buf,
			    flags);
			(void) au_fetch_int32(&tok->un.exit.retval, &cur_buf,
			    flags);
			tok->size = 9;
		break;
		case AUT_UAUTH:
			(void) au_fetch_short(&tok->un.uauth.length, &cur_buf,
			    flags);
			(void) au_fetch_bytes(&tok->un.uauth.data, &cur_buf,
			    tok->un.uauth.length, flags);
			tok->size = 3 + tok->un.uauth.length;
		break;
		case AUT_INVALID:
		default:
			au_fetch_bytes(&tok->un.invalid.data, &invalid_txt,
			    len_invalid_txt, flags);
			tok->un.invalid.length = len_invalid_txt;
			tok->size = len_invalid_txt;
			valid_id = 0;
	}
	if (valid_id == 0) {
		old_buf = orig_buf;
		return (-3);
	}
	old_buf = cur_buf;
	return (0);
}

static int au_fetch_char(char *result, char **buf, int flags)
{
	*result = **buf;
	(*buf)++;
	return (0);
}

static int au_fetch_short(short *result, char **buf, int flags)
{
	*result = **buf << 8;
	(*buf)++;
	*result |= **buf & 0x0ff;
	(*buf)++;
	return (0);
}

static int au_fetch_int32(int32_t *result, char **buf, int flags)
{
	int i;

	for (i = 0; i < sizeof (int); i++) {
		*result <<= 8;
		*result |= **buf & 0x000000ff;
		(*buf)++;
	}
	return (0);
}

static int au_fetch_int64(int64_t *result, char **buf, int flags)
{
	int i;

	for (i = 0; i < sizeof (int64_t); i++) {
		*result <<= 8;
		*result |= **buf & 0x00000000000000ff;
		(*buf)++;
	}
	return (0);
}

static int au_fetch_bytes(char **result, char **buf, int len, int flags)
{
	if (flags & AUF_POINT) {
		*result = *buf;
		(*buf) += len;
		return (0);
	}
	if (flags & AUF_DUP) {
		*result = (char *)malloc(len);
		memcpy(*result, *buf, len);
		(*buf) += len;
		return (0);
	}
	if (flags & AUF_COPY_IN) {
		memcpy(*result, *buf, len);
		(*buf) += len;
		return (0);
	}
	return (-1);
}

/*
 * The following defines and functions are for work with device major
 * and minor numbers independently from libc, because it doesn't support
 * such work for 32- and 64-bit format at the same time. This implementation
 * depends on sys/mkdev.h and on format of dev_t type.
 */

#define	NBITSMAJOR64	32	/* # of major device bits in 64-bit Solaris */
#define	NBITSMINOR64	32	/* # of minor device bits in 64-bit Solaris */
#define	MAXMAJ64	0xfffffffful	/* max major value */
#define	MAXMIN64	0xfffffffful	/* max minor value */

#define	NBITSMAJOR32	14	/* # of SVR4 major device bits */
#define	NBITSMINOR32	18	/* # of SVR4 minor device bits */
#define	NMAXMAJ32	0x3fff	/* SVR4 max major value */
#define	NMAXMIN32	0x3ffff	/* MAX minor for 3b2 software drivers. */


static int32_t
minor_64(uint64_t dev)
{
	if (dev == NODEV) {
		errno = EINVAL;
		return (NODEV);
	}
	return (int32_t)(dev & MAXMIN64);
}

static int32_t
major_64(uint64_t dev)
{
	uint32_t maj;

	maj = (uint32_t)(dev >> NBITSMINOR64);

	if (dev == NODEV || maj > MAXMAJ64) {
		errno = EINVAL;
		return (NODEV);
	}
	return (int32_t)(maj);
}

static int32_t
minor_32(uint32_t dev)
{
	if (dev == NODEV) {
		errno = EINVAL;
		return (NODEV);
	}
	return (int32_t)(dev & MAXMIN32);
}

static int32_t
major_32(uint32_t dev)
{
	uint32_t maj;

	maj = (uint32_t)(dev >> NBITSMINOR32);

	if (dev == NODEV || maj > MAXMAJ32) {
		errno = EINVAL;
		return (NODEV);
	}
	return (int32_t)(maj);
}


int
au_fprint_tok(FILE *fp, au_token_t *tok, char *b, char *m, char *e, int flags)
{
	char *s1, *s2;
	char s3[80], s4[80];
	char p[80];
	au_event_ent_t *p_event;
	int i;
	char *p_data;
	char c1;
	short c2;
	int c3;
	struct in_addr ia;
	char *hostname;
	char *ipstring;
	struct passwd *p_pwd;
	struct group *p_grp;

	if (flags == 0)
	    switch (tok->id) {
		case AUT_OTHER_FILE32: {
			time_t time = (time_t)tok->un.file32.time;
			s1 = ctime(&time);
			s1[24] = '\0';
			fprintf(fp, "%s%s%s%s%s + %d msec%s", b, "file32", m,
			    s1, m, (int)tok->un.file32.msec, e);
			free(s1);
			return (0);
		}
		case AUT_OTHER_FILE64: {
			time_t time = (time_t)tok->un.file64.time;
			s1 = ctime(&time);
			s1[24] = '\0';
			fprintf(fp, "%s%s%s%s%s + %d msec%s", b, "file64", m,
			    s1, m, (int)tok->un.file64.msec, e);
			free(s1);
			return (0);
		}
		case AUT_HEADER32: {
			time_t time = (time_t)tok->un.header32.time;
			s1 = ctime(&time);
			s1[24] = '\0';
			i = cacheauevent(&p_event, tok->un.header32.event);
			fprintf(fp, "%s%s%s%d%s%d%s%s%s%d%s%s%s + %d msec%s",
			    b, "header32", m, tok->un.header32.length, m,
			    tok->un.header32.version, m, p_event->ae_desc, m,
			    tok->un.header32.emod, m, s1, m,
			    tok->un.header32.msec, e);
			free(s1);
			return (0);
		}
		case AUT_HEADER64: {
			time_t time = (time_t)tok->un.header64.time;
			s1 = ctime(&time);
			s1[24] = '\0';
			i = cacheauevent(&p_event, tok->un.header64.event);
			fprintf(fp, "%s%s%s%d%s%d%s%s%s%d%s%s%s + %d msec%s",
			    b, "header64", m, tok->un.header64.length, m,
			    tok->un.header64.version, m, p_event->ae_desc, m,
			    tok->un.header64.emod, m, s1, m,
			    tok->un.header64.msec, e);
			free(s1);
			return (0);
		}
		case AUT_TRAILER:
			if (tok->un.trailer.magic != AUT_TRAILER_MAGIC) {
				return (-2);
			}
			fprintf(fp, "%s%s%s%d%s", b, "trailer", m,
			    tok->un.trailer.length, e);
			return (0);
		case AUT_DATA:
			switch (tok->un.data.pfmt) {
				case AUP_BINARY:
					s1 = "binary";
					break;
				case AUP_OCTAL:
					s1 = "octal";
					break;
				case AUP_DECIMAL:
					s1 = "decimal";
					break;
				case AUP_HEX:
					s1 = "hex";
					break;
				case AUP_STRING:
					s1 = "string";
					break;
				default:
					s1 = "unknown print suggestion";
					break;
			}
			switch (tok->un.data.size) {
				/* case AUR_BYTE: */
				case AUR_CHAR:
					s2 = "char";
					break;
				case AUR_SHORT:
					s2 = "short";
					break;
				case AUR_INT32:
					s2 = "int32_t";
					break;
				case AUR_INT64:
					s2 = "int64_t";
					break;
				default:
					s2 = "unknown basic unit type";
					break;
			}
			fprintf(fp, "%s%s%s%s%s%s%s", b, "data", m, s1, m, s2,
			    m);

			p_data = tok->un.data.data;
			for (i = 1; i <= (int)tok->un.data.number; i++) {
			    switch (tok->un.data.size) {
				case AUR_CHAR:
					if (au_fetch_char(&c1, &p_data, 0) ==
					    0) {
						convert_char_to_string(
						    tok->un.data.pfmt, c1, p);
					} else {
						return (-3);
					}
				break;
				case AUR_SHORT:
					if (au_fetch_short(&c2, &p_data, 0) ==
					    0) {
						convert_short_to_string(
						    tok->un.data.pfmt, c2, p);
					} else {
						return (-4);
					}
				break;
				case AUR_INT32:
					if (au_fetch_int32(&c3, &p_data, 0) ==
					    0) {
						convert_int32_to_string(
						    tok->un.data.pfmt, c3, p);
					} else {
						return (-5);
					}
				break;
				case AUR_INT64:
					if (au_fetch_int64(&c3, &p_data, 0) ==
					    0) {
						convert_int64_to_string(
							tok->un.data.pfmt,
							    c3, p);
					} else {
						return (-9);
					}
				break;
				default:
					return (-6);
					break;
			    }
			    fprintf(fp, "%s%s", p,
				i == tok->un.data.number ? m : e);
			}
			return (0);

		case AUT_IPC:
			fprintf(fp, "%s%s%s%d%s", b, "IPC", m, tok->un.ipc.id,
			    e);
			return (0);

		case AUT_PATH:
			fprintf(fp, "%s%s%s%s%s", b, "path", m,
			    tok->un.path.name, e);
			return (0);

		case AUT_SUBJECT32:
			hostname = get_Hname(tok->un.subj32.tid.machine);
			ia.s_addr = tok->un.subj32.tid.machine;
			if ((s1 = inet_ntoa(ia)) == NULL) {
				s1 = "bad machine id";
			}
			fprintf(fp,
			    "%s%s%s%d%s%d%s%d%s%d%s%d%s%d%s%d%s%d%s%d"
			    "%s%s%s%s%s", b, "subject32", m,
			    tok->un.subj32.auid, m, tok->un.subj32.euid, m,
			    tok->un.subj32.egid, m, tok->un.subj32.ruid, m,
			    tok->un.subj32.rgid, m, tok->un.subj32.pid, m,
			    tok->un.subj32.sid, m,
			    major_32(tok->un.subj32.tid.port), m,
			    minor_32(tok->un.subj32.tid.port), m, hostname, m,
			    s1, e);

		case AUT_SUBJECT64:
			hostname = get_Hname(tok->un.subj64.tid.machine);
			ia.s_addr = tok->un.subj64.tid.machine;
			if ((s1 = inet_ntoa(ia)) == NULL) {
				s1 = "bad machine id";
			}
			fprintf(fp,
			    "%s%s%s%d%s%d%s%d%s%d%s%d%s%d%s%d%s%d%s%d"
			    "%s%s%s%s%s", b, "subject64", m,
			    tok->un.subj64.auid, m, tok->un.subj64.euid, m,
			    tok->un.subj64.egid, m, tok->un.subj64.ruid, m,
			    tok->un.subj64.rgid, m, tok->un.subj64.pid, m,
			    tok->un.subj64.sid, m,
			    major_64(tok->un.subj64.tid.port), m,
			    minor_64(tok->un.subj64.tid.port), m, hostname, m,
			    s1, e);
			return (0);

		case AUT_PROCESS32:
			hostname = get_Hname(tok->un.proc32.tid.machine);
			ia.s_addr = tok->un.proc32.tid.machine;
			if ((s1 = inet_ntoa(ia)) == NULL) {
				s1 = "bad machine id";
			}
			fprintf(fp,
			    "%s%s%s%d%s%d%s%d%s%d%s%d%s%d%s%d%s%d%s%d"
			    "%s%s%s%s%s", b, "process32", m,
			    tok->un.proc32.auid, m, tok->un.proc32.euid, m,
			    tok->un.proc32.egid, m, tok->un.proc32.ruid, m,
			    tok->un.proc32.rgid, m, tok->un.proc32.pid, m,
			    tok->un.proc32.sid, m,
			    major_32(tok->un.proc32.tid.port), m,
			    minor_32(tok->un.proc32.tid.port), m, hostname, m,
			    s1, e);
			return (0);

		case AUT_PROCESS64:
			hostname = get_Hname(tok->un.proc64.tid.machine);
			ia.s_addr = tok->un.proc64.tid.machine;
			if ((s1 = inet_ntoa(ia)) == NULL) {
				s1 = "bad machine id";
			}
			fprintf(fp,
			    "%s%s%s%d%s%d%s%d%s%d%s%d%s%d%s%d%s%d%s%d"
			    "%s%s%s%s%s", b, "process64", m,
			    tok->un.proc64.auid, m, tok->un.proc64.euid, m,
			    tok->un.proc64.egid, m, tok->un.proc64.ruid, m,
			    tok->un.proc64.rgid, m, tok->un.proc64.pid, m,
			    tok->un.proc64.sid, m,
			    major_64(tok->un.proc64.tid.port), m,
			    minor_64(tok->un.proc64.tid.port), m, hostname, m,
			    s1, e);
			return (0);
		case AUT_RETURN32:
			if (tok->un.ret32.error == 0) {
				(void) strcpy(s3, "success");
			} else if (tok->un.ret32.error == -1) {
				(void) strcpy(s3, "failure");
			} else {
				if (tok->un.ret32.error < (uchar_t)sys_nerr) {
					sprintf(s3, "failure: %s",
					    sys_errlist[tok->un.ret32.error]);
				} else {
					(void) strcpy(s3, "Unknown errno");
				}
			}

			fprintf(fp, "%s%s%s%s%s%d%s", b, "return32", m, s3, m,
			    tok->un.ret32.retval, e);
			return (0);
		case AUT_RETURN64:
			if (tok->un.ret64.error == 0) {
				(void) strcpy(s3, "success");
			} else if (tok->un.ret64.error == -1) {
				(void) strcpy(s3, "failure");
			} else {
				if (tok->un.ret64.error < (uchar_t)sys_nerr) {
					sprintf(s3, "failure: %s",
					    sys_errlist[tok->un.ret64.error]);
				} else {
					(void) strcpy(s3, "Unknown errno");
				}
			}

			fprintf(fp, "%s%s%s%s%s%"PRI64d"%s", b, "return64", m,
			    s3, m, tok->un.ret64.retval, e);
			return (0);
		case AUT_TEXT:
			fprintf(fp, "%s%s%s%s%s", b, "text", m,
			    tok->un.text.data, e);
			return (0);
		case AUT_OPAQUE:
			s1 = hexconvert(tok->un.opaque.data,
			    tok->un.opaque.length, 0);
			fprintf(fp, "%s%s%s%s%s",
				b, "opaque", m,
				s1, e);
			free(s1);
			return (0);

		case AUT_IN_ADDR:
			s1 = get_Hname(tok->un.inaddr.ia);
			fprintf(fp, "%s%s%s%s%s",
				b, "ip address", m,
				s1, e);
			return (0);

		case AUT_IP:
			fprintf(fp,
			    "%s%s%s%x%s%x%s%d%s%d%s%d%s%x%s%x%s%d%s%x%s%x%s",
			    b, "ip", m, (int)tok->un.ip.version, m,
			    (int)tok->un.ip.ip.ip_tos, m,
			    tok->un.ip.ip.ip_len, m, tok->un.ip.ip.ip_id, m,
			    tok->un.ip.ip.ip_off, m,
			    (int)tok->un.ip.ip.ip_ttl, m,
			    (int)tok->un.ip.ip.ip_p, m,
			    tok->un.ip.ip.ip_sum, m, tok->un.ip.ip.ip_src, m,
			    tok->un.ip.ip.ip_dst, e);
			return (0);
		case AUT_IPORT:
			fprintf(fp, "%s%s%s%x%s", b, "ip port", m,
			    (int)tok->un.iport.iport, e);
			return (0);
		case AUT_ARG32:
			fprintf(fp, "%s%s%s%d%s%x%s%s%s", b, "argument32", m,
			    tok->un.arg32.num, m, tok->un.arg32.val, m,
			    tok->un.arg32.data, e);
			return (0);
		case AUT_ARG64:
			fprintf(fp, "%s%s%s%d%s%"PRIx64"%s%s%s", b,
			    "argument64", m, tok->un.arg64.num, m,
			    tok->un.arg64.val, m, tok->un.arg64.data, e);
			return (0);
		case AUT_SOCKET:
			s1 = get_Hname(tok->un.socket.laddr);
			s2 = get_Hname(tok->un.socket.faddr);
			fprintf(fp, "%s%s%s%x%s%x%s%s%s%x%s%s%s", b, "socket",
			    m, (int)tok->un.socket.type, m,
			    (int)tok->un.socket.lport, m, s1, m,
			    (int)tok->un.socket.fport, m, s2, e);
			free(s1);
			free(s2);
			return (0);
		case AUT_SEQ:
			fprintf(fp, "%s%s%s%d%s", b, "sequence", m,
			    tok->un.seq.num, e);
			return (0);
		case AUT_ACL:
			sprintf(s3, "%d", tok->un.acl.type);

			if (tok->un.acl.type & (USER_OBJ|USER)) {
				setpwent();
				p_pwd = getpwuid(tok->un.acl.id);
				if (p_pwd == NULL) {
					sprintf(s4, "%d", tok->un.acl.uid);
				else
					(void) strcpy(s4, p_pwd->pw_name);
				endpwent();
			} else if (tok->un.acl.type & (GROUP_OBJ|GROUP)) {
				setgrent();
				p_grp = getgrgid(tok->un.acl.id);
				if (p_grp == NULL)
					sprintf(s4, "%d", tok->un.acl.uid);
				else
					(void) strcpy(s4, p_grp->gr_name);
				endpwent();
			} else {
				sprintf(s4, "%d", tok->un.acl.uid);
			}
			fprintf(fp, "%s%s%s%s%s%s%s%o%s", b, "acl", m, s3, m,
			    s4, m, tok->un.acl.mode, e);
			return (0);
		case AUT_ATTR32:
			setpwent();
			if ((p_pwd = getpwuid(tok->un.attr32.uid)) == NULL) {
				sprintf(s3, "%d", tok->un.attr32.uid);
			} else {
				(void) strcpy(s3, p_pwd->pw_name);
			}
			endpwent();
			setgrent();
			if ((p_grp = getgrgid(tok->un.attr32.gid)) == NULL) {
				sprintf(s4, "%d", tok->un.attr32.gid);
			} else {
				(void) strcpy(s4, p_grp->gr_name);
			}
			endgrent();
			fprintf(fp, "%s%s%s%o%s%s%s%s%s%d%s%"PRI64d"%s%u%s", b,
			    "attribute32", m, tok->un.attr32.mode, m, s3, m,
			    s4, m, tok->un.attr32.fs, m, tok->un.attr32.node,
			    m, tok->un.attr32.dev, e);
			return (0);
		case AUT_ATTR64:
			setpwent();
			if ((p_pwd = getpwuid(tok->un.attr64.uid)) == NULL) {
				sprintf(s3, "%d", tok->un.attr64.uid);
			} else {
				(void) strcpy(s3, p_pwd->pw_name);
			}
			endpwent();
			setgrent();
			if ((p_grp = getgrgid(tok->un.attr64.gid)) == NULL) {
				sprintf(s4, "%d", tok->un.attr64.gid);
			} else {
				(void) strcpy(s4, p_grp->gr_name);
			}
			endgrent();
			fprintf(fp,
			    "%s%s%s%o%s%s%s%s%s%d%s%"PRI64d"%s%"PRI64d"%s", b,
			    "attribute64", m, tok->un.attr64.mode, m, s3, m,
			    s4, m, tok->un.attr64.fs, m, tok->un.attr64.node,
			    m, tok->un.attr64.dev, e);
			return (0);
		case AUT_IPC_PERM:
			setpwent();
			p_pwd = getpwuid(tok->un.ipc_perm.ipc_perm.ipc_uid);
			if (p_pwd == NULL) {
				(void) sprintf(s3, "%d",
				    tok->un.ipc_perm.ipc_perm.ipc_uid);
			} else {
				(void) strcpy(s3, p_pwd->pw_name);
			}
			endpwent();
			setgrent();
			p_grp = getgrgid(tok->un.ipc_perm.ipc_perm.ipc_gid);
			if (p_grp == NULL) {
				(void) sprintf(s4, "%d",
				    tok->un.ipc_perm.ipc_perm.ipc_gid);
			} else {
				(void) strcpy(s4, p_grp->gr_name);
			}
			endgrent();
			fprintf(fp, "%s%s%s%s%s%s%s%s%s%s%s%o%s%d%s%x%s",
				b, "IPC perm", m,
				s3, m,
				s4, m);
			setpwent();
			p_pwd = getpwuid(tok->un.ipc_perm.ipc_perm.ipc_cuid);
			if (p_pwd == NULL) {
				(void) sprintf(s3, "%d",
				    tok->un.ipc_perm.ipc_perm.ipc_cuid);
			} else {
				(void) strcpy(s3, p_pwd->pw_name);
			}
			endpwent();
			setgrent();
			p_grp = getgrgid(tok->un.ipc_perm.ipc_perm.ipc_cgid);
			if (p_grp == NULL) {
				(void) sprintf(s4, "%d",
				    tok->un.ipc_perm.ipc_perm.ipc_cgid);
			} else {
				(void) strcpy(s4, p_grp->gr_name);
			}
			endgrent();
			fprintf(fp, "%s%s%s%s%o%s%d%s%x%s", s3, m, s4, m,
			    tok->un.ipc_perm.ipc_perm.ipc_mode, m,
			    tok->un.ipc_perm.ipc_perm.ipc_seq, m,
			    tok->un.ipc_perm.ipc_perm.ipc_key, e);
			return (0);
		case AUT_GROUPS:
			fprintf(fp, "%s%s%s", b, "group", m);
			for (i = 0; i < NGROUPS_MAX; i++) {
				setgrent();
				if ((p_grp = getgrgid(tok->un.groups.groups[i]))
				    == NULL) {
					sprintf(s4, "%d",
					    tok->un.groups.groups[i]);
				} else {
					(void) strcpy(s4, p_grp->gr_name);
				}
				endgrent();
				fprintf(fp, "%s%s", s3,
				    i == NGROUPS_MAX - 1 ? m : e);
			}
		case AUT_EXIT:
			if ((tok->un.exit.retval < -1) &&
			    (tok->un.exit.retval < sys_nerr)) {
				sprintf(s3, "%s",
				    sys_errlist[tok->un.exit.retval]);
			} else {
				sprintf(s3, "%s", "Unknown errno");
			}
			fprintf(fp, "%s%s%s%s%s%d%s", b, "exit", m, s3, m,
			    tok->un.exit.status, e);
			return (0);
		case AUT_UAUTH:
			fprintf(fp, "%s%s%s%s%s", b, "uauth", m,
			    tok->un.uauth.data, e);
			return (0);
		case AUT_INVALID:
		default:
			fprintf(fp, "%s%s%s", b, "invalid token", e);
			return (-1);
		break;
	}
}


void
au_fprint_tok_hex(FILE *fp, au_token_t *tok, char b, char m, char e, int flags)
{
	char *str;
	char *prefix;

	str = hexconvert(tok->data, tok->size, tok->size);

	switch (tok->id) {
		case AUT_ARG32:
			prefix = "arg32";
			break;
		case AUT_ARG64:
			prefix = "arg64";
			break;
		case AUT_ATTR32:
			prefix = "attr32";
			break;
		case AUT_ATTR64:
			prefix = "attr64";
			break;
		case AUT_DATA:
			prefix = "data";
			break;
		case AUT_EXIT:
			prefix = "exit";
			break;
		case AUT_GROUPS:
			prefix = "groups";
			break;
		case AUT_HEADER32:
			prefix = "header32";
			break;
		case AUT_HEADER64:
			prefix = "header64";
			break;
		case AUT_INVALID:
			prefix = "invalid";
			break;
		case AUT_IN_ADDR:
			prefix = "in_addr";
			break;
		case AUT_IP:
			prefix = "ip";
			break;
		case AUT_IPC:
			prefix = "ipc";
			break;
		case AUT_IPC_PERM:
			prefix = "ipc_perm";
			break;
		case AUT_IPORT:
			prefix = "iport";
			break;
		case AUT_OPAQUE:
			prefix = "opaque";
			break;
		case AUT_OTHER_FILE32:
			prefix = "file32";
			break;
		case AUT_OTHER_FILE64:
			prefix = "file364";
			break;
		case AUT_PATH:
			prefix = "path";
			break;
		case AUT_PROCESS32:
			prefix = "process32";
			break;
		case AUT_PROCESS64:
			prefix = "process64";
			break;
		case AUT_RETURN32:
			prefix = "return32";
			break;
		case AUT_RETURN64:
			prefix = "return64";
			break;
		case AUT_SEQ:
			prefix = "seq";
			break;
		case AUT_SOCKET:
			prefix = "socket";
			break;
		case AUT_SUBJECT32:
			prefix = "subject32";
			break;
		case AUT_SUBJECT64:
			prefix = "subject64";
			break;
		case AUT_TEXT:
			prefix = "text";
			break;
		case AUT_TRAILER:
			prefix = "trailer";
			break;
		case AUT_UAUTH:
			prefix = "uauth";
			break;
		default:
			prefix = "invalid";
			break;
	}
	fprintf(fp, "%s:%s\n", prefix, str);
}

/*
 * Convert binary data to ASCII for printing.
 */
static void
convertascii(char *p, char *c, int size)
{
	register int i;

	for (i = 0; i < size; i++) {
		*(c+i) = (char)toascii(*(c+i));
		if ((int)iscntrl(*(c+i))) {
			*p++ = '^';
			*p++ = (char)(*(c+i)+0x40);
		} else
			*p++ = *(c+i);
	}

	*p = '\0';
}

/*
 * =========================================================
 * convert_char_to_string:
 * Converts a byte to string depending on the print mode
 * input	: printmode, which may be one of AUP_BINARY,
 *		  AUP_OCTAL, AUP_DECIMAL, and AUP_HEX
 *		  c, which is the byte to convert
 * output	: p, which is a pointer to the location where
 *		  the resulting string is to be stored
 * ==========================================================
 */

static int
convert_char_to_string(char printmode, char c, char *p)
{
	union {
		char c1[4];
		int c2;
	} dat;

	dat.c2 = 0;
	dat.c1[3] = c;

	if (printmode == AUP_BINARY)
		convertbinary(p, &c, sizeof (char));
	else if (printmode == AUP_OCTAL)
		sprintf(p, "%o", dat.c2);
	else if (printmode == AUP_DECIMAL)
		sprintf(p, "%d", c);
	else if (printmode == AUP_HEX)
		sprintf(p, "0x%x", dat.c2);
	else if (printmode == AUP_STRING)
		convertascii(p, &c, sizeof (char));
	return (0);
}

/*
 * ==============================================================
 * convert_short_to_string:
 * Converts a short integer to string depending on the print mode
 * input	: printmode, which may be one of AUP_BINARY,
 *		  AUP_OCTAL, AUP_DECIMAL, and AUP_HEX
 *		  c, which is the short integer to convert
 * output	: p, which is a pointer to the location where
 *		  the resulting string is to be stored
 * ===============================================================
 */
static int
convert_short_to_string(char printmode, short c, char *p)
{
	union {
		short c1[2];
		int c2;
	} dat;

	dat.c2 = 0;
	dat.c1[1] = c;

	if (printmode == AUP_BINARY)
		convertbinary(p, &c, sizeof (short));
	else if (printmode == AUP_OCTAL)
		sprintf(p, "%o", dat.c2);
	else if (printmode == AUP_DECIMAL)
		sprintf(p, "%hd", c);
	else if (printmode == AUP_HEX)
		sprintf(p, "0x%x", dat.c2);
	else if (printmode == AUP_STRING)
		convertascii(p, &c, sizeof (short));
	return (0);
}

/*
 * =========================================================
 * convert_intXX_to_string:
 * Converts a integer to string depending on the print mode
 * input	: printmode, which may be one of AUP_BINARY,
 *		  AUP_OCTAL, AUP_DECIMAL, and AUP_HEX
 *		  c, which is the integer to convert
 * output	: p, which is a pointer to the location where
 *		  the resulting string is to be stored
 * ==========================================================
 */
static int
convert_int32_to_string(char printmode, int32_t c, char *p)
{
	if (printmode == AUP_BINARY)
		convertbinary(p, &c, sizeof (int32_t));
	else if (printmode == AUP_OCTAL)
		sprintf(p, "%o", c);
	else if (printmode == AUP_DECIMAL)
		sprintf(p, "%d", c);
	else if (printmode == AUP_HEX)
		sprintf(p, "0x%x", c);
	else if (printmode == AUP_STRING)
		convertascii(p, &c, sizeof (int32_t));
	return (0);
}

static int
convert_int64_to_string(char printmode, int c, char *p)
{
	if (printmode == AUP_BINARY)
		convertbinary(p, &c, sizeof (int64_t));
	else if (printmode == AUP_OCTAL)
		sprintf(p, "%"PRIo, c);
	else if (printmode == AUP_DECIMAL)
		sprintf(p, "%"PRId, c);
	else if (printmode == AUP_HEX)
		sprintf(p, "0x%"PRIx, c);
	else if (printmode == AUP_STRING)
		convertascii(p, &c, sizeof (int64_t));
	return (0);
}

/*
 * ===========================================================
 * convertbinary:
 * Converts a unit c of 'size' bytes long into a binary string
 * and returns it into the position pointed to by p
 * ============================================================
 */
static int
convertbinary(char *p, char *c, int size)
{
	char *s, *t;
	int i, j;

	if ((s = (char *)malloc(8*size + 1)) == NULL)
		return (0);

	/* first convert to binary */
	t = s;
	for (i = 0; i < size; i++) {
		for (j = 0; j < 8; j++)
			sprintf(t++, "%d", ((*c >> (7-j)) & (0x01)));
		c++;
	}
	*t = '\0';

	/* now string leading zero's if any */
	j = strlen(s) - 1;
	for (i = 0; i < j; i++) {
		if (*s != '0')
			break;
		else
			s++;
	}

	/* now copy the contents of s to p */
	t = p;
	for (i = 0; i < (8*size + 1); i++) {
		if (*s == '\0') {
			*t = '\0';
			break;
		}
		*t++ = *s++;
	}
	free(s);

	return (1);
}

static char *
hexconvert(uchar_t *c, int size, int chunk)
{
	register char *s, *t;
	register int i, j, k;
	int numchunks;
	int leftovers;

	if ((s = (char *)malloc((size*5)+1)) == NULL)
		return (NULL);

	if (size <= 0)
		return (NULL);

	if (chunk > size || chunk <= 0)
		chunk = size;

	numchunks = size/chunk;
	leftovers = size % chunk;

	t = s;
	for (i = j = 0; i < numchunks; i++) {
		if (j++) {
			*t = ' ';
			t++;
		}
		(void) sprintf(t, "0x");
		t += 2;
		for (k = 0; k < chunk; k++) {
			sprintf(t, "%02x", *c++);
			t += 2;
		}
	}

	if (leftovers) {
		*t++ = ' ';
		*t++ = '0';
		*t++ = 'x';
		for (i = 0; i < leftovers; i++) {
			sprintf(t, "%02x", *c++);
			t += 2;
		}
	}

	*t = '\0';
	return (s);
}

static char *
get_Hname(uint32_t addr)
{
	extern char *inet_ntoa(const struct in_addr);
	struct hostent *phe;
	static char buf[256];
	struct in_addr ia;

	phe = gethostbyaddr((const char *)&addr, 4, AF_INET);
	if (phe == (struct hostent *)0) {
		ia.s_addr = addr;
		(void) sprintf(buf, "%s", inet_ntoa(ia));
		return (buf);
	}
	ia.s_addr = addr;
	(void) sprintf(buf, "%s", phe->h_name);
	return (buf);
}

static char *
pa_gettokenstring(int tokenid)
{
	int i;
	struct tokentable *k;

	for (i = 0; i < numtokenentries; i++) {
		k = &(tokentab[i]);
		if ((k->tokenid) == tokenid)
			return (k->tokentype);
	}
	/* here if token id is not in table */
	return (NULL);
}
