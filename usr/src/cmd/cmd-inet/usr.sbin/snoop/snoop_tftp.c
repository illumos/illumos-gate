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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <fcntl.h>
#include <arpa/tftp.h>
#include "snoop.h"

struct tftp_options {
	int blksize;
	int tsize;
};

extern char *dlc_header;
static char *tftperror(unsigned short);
static char *show_type(int);
static char *tftp_parse_oack(char *, size_t, struct tftp_options *);

int
interpret_tftp(int flags, void *data, int fraglen)
{
	char *name, *mode;
	extern int src_port, dst_port;
	int blocksize = fraglen - 4;
	struct tftp_options opts;
	struct ttable *tt;
	struct tftphdr *tftp = data;

	opts.tsize = 0;
	opts.blksize = 512;

	switch (ntohs(tftp->th_opcode)) {
	case RRQ:
	case WRQ:
		add_transient(src_port, interpret_tftp);
		break;
	case ERROR:
		del_transient(src_port);
		break;
	case OACK:
		tt = is_transient(dst_port);
		if (tt != NULL)
			tt->blksize = opts.blksize;
		break;
	case DATA:
		tt = is_transient(dst_port);
		if (tt != NULL)
			opts.blksize = tt->blksize;
		break;
	default:
		break;
	}

	if (flags & F_SUM) {
		switch (ntohs(tftp->th_opcode)) {
		case RRQ:
			name = (char *)&tftp->th_stuff;
			mode = name + (strlen(name) + 1);
			(void) sprintf(get_sum_line(),
			    "TFTP Read \"%s\" (%s)", name, mode);
			break;
		case WRQ:
			name = (char *)&tftp->th_stuff;
			mode = name + (strlen(name) + 1);
			(void) sprintf(get_sum_line(),
			    "TFTP Write \"%s\" (%s)", name, mode);
			break;
		case DATA:
			(void) sprintf(get_sum_line(),
			    "TFTP Data block %u (%d bytes)%s",
			    ntohs(tftp->th_block), blocksize,
			    blocksize < opts.blksize ? " (last block)":"");
			break;
		case ACK:
			(void) sprintf(get_sum_line(), "TFTP Ack block %d",
			    ntohs(tftp->th_block));
			break;
		case ERROR:
			(void) sprintf(get_sum_line(), "TFTP Error: %s",
			    tftperror(ntohs(tftp->th_code)));
			break;
		case OACK:
			(void) sprintf(get_sum_line(), "TFTP OACK: %s",
			    tftp_parse_oack((char *)&tftp->th_stuff,
			    fraglen - sizeof (tftp->th_opcode), &opts));
			if (tt != NULL)
				tt->blksize = opts.blksize;
			break;
		}
	}

	if (flags & F_DTAIL) {
		show_header("TFTP:  ", "Trivial File Transfer Protocol",
		    fraglen);
		show_space();
		(void) sprintf(get_line((char *)(uintptr_t)tftp->th_opcode -
		    dlc_header, 2), "Opcode = %d (%s)", ntohs(tftp->th_opcode),
		    show_type(ntohs(tftp->th_opcode)));

		switch (ntohs(tftp->th_opcode)) {
		case RRQ:
		case WRQ:
			name = (char *)&tftp->th_stuff;
			mode = name + (strlen(name) + 1);
			(void) sprintf(
			    get_line(name - dlc_header, strlen(name) + 1),
			    "File name = \"%s\"", name);
			(void) sprintf(
			    get_line(mode - dlc_header, strlen(mode) + 1),
			    "Transfer mode = %s", mode);
			break;

		case DATA:
			(void) sprintf(get_line(
			    (char *)(uintptr_t)tftp->th_block - dlc_header, 2),
			    "Data block = %d%s", ntohs(tftp->th_block),
			    blocksize < opts.blksize ? " (last block)" : "");
			(void) sprintf(get_line(
			    (char *)(uintptr_t)tftp->th_data - dlc_header,
			    blocksize), "[ %d bytes of data ]", blocksize);
			break;

		case ACK:
			(void) sprintf(get_line(
			    (char *)(uintptr_t)tftp->th_block - dlc_header, 2),
			    "Acknowledge block = %d", ntohs(tftp->th_block));
			break;

		case ERROR:
			(void) sprintf(get_line(
			    (char *)(uintptr_t)tftp->th_code - dlc_header, 2),
			    "Error = %d (%s)", ntohs(tftp->th_code),
			    tftperror(ntohs(tftp->th_code)));
			(void) sprintf(get_line(
			    (char *)(uintptr_t)tftp->th_data -
			    dlc_header, strlen(tftp->th_data) + 1),
			    "Error string = \"%s\"", tftp->th_data);
			break;
		case OACK:
			(void) sprintf(get_line(
			    (char *)(uintptr_t)tftp->th_code - dlc_header, 2),
			    "TFTP OACK: %s",
			    tftp_parse_oack((char *)&tftp->th_stuff,
			    fraglen - sizeof (tftp->th_opcode), &opts));
			if (tt != NULL)
				tt->blksize = opts.blksize;
			break;
		}
	}

	return (fraglen);
}

static char *
show_type(int t)
{
	switch (t) {
	case RRQ:	return ("read request");
	case WRQ:	return ("write request");
	case DATA:	return ("data packet");
	case ACK:	return ("acknowledgement");
	case ERROR:	return ("error");
	case OACK:	return ("option acknowledgement");
	}
	return ("?");
}

static char *
tftperror(unsigned short code)
{
	static char buf[128];

	switch (code) {
	case EUNDEF:	return ("not defined");
	case ENOTFOUND:	return ("file not found");
	case EACCESS:	return ("access violation");
	case ENOSPACE:	return ("disk full or allocation exceeded");
	case EBADOP:	return ("illegal TFTP operation");
	case EBADID:	return ("unknown transfer ID");
	case EEXISTS:	return ("file already exists");
	case ENOUSER:	return ("no such user");
	}
	(void) sprintf(buf, "%d", code);

	return (buf);
}

static char *
tftp_parse_oack(char *buf, size_t size, struct tftp_options *opts)
{
	static char tftp_options[128];
	int i, idx;

	tftp_options[0] = '\0';
	idx = 0;

	while (size > 0 && idx < sizeof (tftp_options)) {
		if (idx > 0) {
			tftp_options[idx++] = ' ';
			tftp_options[idx] = '\0';
		}

		/* get name */
		if (idx + strnlen(buf, size) + 1 > sizeof (tftp_options))
			break;
		for (i = 0; i < size; i++) {
			tftp_options[idx] = buf[i];
			if (tftp_options[idx] == '\0') {
				i++;
				break;
			}
			idx++;
		}
		size -= i;
		/*
		 * RFC 2348 requires this case in-sensitive.
		 */
		if (strcasecmp(buf, "blksize") == 0) {
			int blksize = strtol(buf + i, NULL, 0);

			if (blksize >= 8)
				opts->blksize = blksize;
		}
		buf += i;

		/* can we store separator? */
		if (idx + 3 > sizeof (tftp_options))
			break;
		strcat(tftp_options, ": ");
		idx += 2;

		/* get value */
		if (idx + strnlen(buf, size) + 1 > sizeof (tftp_options))
			break;

		for (i = 0; i < size; i++) {
			tftp_options[idx] = buf[i];
			if (tftp_options[idx] == '\0') {
				i++;
				break;
			}
			idx++;
		}
		size -= i;
		buf += i;
	}
	return (tftp_options);
}
