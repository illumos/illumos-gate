/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License (), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <err.h>

#include <sys/debug.h>

#include "cryptotest.h"
#include "parser_runner.h"

#define	DATA_PATH	"/opt/crypto-tests/share"

/*
 * Parse NIST test vector data into a format that is simple to run the digest
 * tests against.  The parsing logic is not meant to be especially robust given
 * that we control the data fed into it.
 */

struct parser_ctx {
	FILE	*pc_file;
	size_t	pc_hash_sz;
	char	*pc_line_buf;
	size_t	pc_line_sz;
};

parser_ctx_t *
parser_init(const char *path, size_t hash_len, int *errp)
{
	FILE *fp;
	parser_ctx_t *ctx;

	/* sanity check for SHA1 -> SHA512 */
	ASSERT(hash_len >= 20 && hash_len <= 64);

	fp = fopen(path, "r");
	if (fp == NULL) {
		*errp = errno;
		return (NULL);
	}
	ctx = malloc(sizeof (*ctx));
	if (ctx == NULL) {
		*errp = ENOMEM;
		(void) fclose(fp);
		return (NULL);
	}
	ctx->pc_file = fp;
	ctx->pc_hash_sz = hash_len;
	ctx->pc_line_buf = NULL;
	ctx->pc_line_sz = 0;

	return (ctx);
}

void
parser_fini(parser_ctx_t *ctx)
{
	free(ctx->pc_line_buf);
	(void) fclose(ctx->pc_file);
	free(ctx);
}

static size_t
hex2bytes(const char *hexbuf, size_t hexlen, uchar_t *outbuf, size_t outlen)
{
	size_t count = 0;
	/* naive and lazy conversion */
	errno = 0;
	while (hexlen > 1) {
		long res;
		char buf[3] = {hexbuf[0], hexbuf[1], '\0'};

		res = strtol(buf, NULL, 16);
		if (errno != 0) {
			break;
		}
		*outbuf = res & 0xff;

		hexbuf += 2;
		hexlen -= 2;
		outbuf += 1;
		outlen += 1;
		count++;

		if (outbuf == 0) {
			break;
		}
	}

	return (count);
}

static int
read_len(parser_ctx_t *ctx, size_t *lenp, size_t *szp)
{
	ssize_t sz;
	long parsed;
	const char *search = "Len = ";
	const size_t search_len = strlen(search);

	errno = 0;
	sz = getline(&ctx->pc_line_buf, &ctx->pc_line_sz, ctx->pc_file);
	if (sz < 1) {
		int err = errno;

		if (err == 0 || err == ENOENT) {
			/* EOF reached, bail */
			return (-1);
		} else {
			return (err);
		}
	}
	*szp = sz;
	if (strncmp(ctx->pc_line_buf, search, search_len) != 0) {
		return (-1);
	}

	errno = 0;
	parsed = strtol(ctx->pc_line_buf + search_len, NULL, 10);
	if (parsed == 0 && errno != 0) {
		return (errno);
	}
	if (parsed < 0) {
		return (EINVAL);
	}

	/* length in file is in bits, while we want bytes */
	*lenp = (size_t)parsed / 8;
	return (0);
}

static int
read_msg(parser_ctx_t *ctx, uchar_t *msgbuf, size_t msglen)
{
	ssize_t sz;
	const char *search = "Msg = ";
	const size_t search_len = strlen(search);

	sz = getline(&ctx->pc_line_buf, &ctx->pc_line_sz, ctx->pc_file);
	if (sz < 0) {
		return (errno);
	}
	if (strncmp(ctx->pc_line_buf, search, search_len) != 0) {
		return (-1);
	}

	if (msgbuf == NULL) {
		ASSERT(msglen == 0);
		return (0);
	}

	size_t parsed;
	parsed = hex2bytes(ctx->pc_line_buf + search_len, sz - search_len,
	    msgbuf, msglen);
	if (parsed != msglen) {
		ASSERT3U(parsed, <, msglen);
		return (-1);
	}

	return (0);
}

static int
read_md(parser_ctx_t *ctx, uchar_t *mdbuf, size_t mdlen)
{
	ssize_t sz;
	const char *search = "MD = ";
	const size_t search_len = strlen(search);

	sz = getline(&ctx->pc_line_buf, &ctx->pc_line_sz, ctx->pc_file);
	if (sz < 0) {
		return (errno);
	}
	if (strncmp(ctx->pc_line_buf, search, search_len) != 0) {
		return (-1);
	}

	size_t parsed;
	parsed = hex2bytes(ctx->pc_line_buf + search_len, sz - search_len,
	    mdbuf, mdlen);
	if (parsed != mdlen) {
		ASSERT3U(parsed, <, mdlen);
		return (-1);
	}

	return (0);
}

parser_entry_t *
parser_read(parser_ctx_t *ctx, int *errp)
{
	int err = 0;
	parser_entry_t *res = NULL;
	uchar_t *msgbuf = NULL;
	uchar_t *mdbuf = NULL;

	while (feof(ctx->pc_file) == 0) {
		int ret;
		size_t msglen, sz;

		ret = read_len(ctx, &msglen, &sz);
		if (ret == -1) {
			/*
			 * Did not find a properly formatted "Len = <num>", but
			 * no hard errors were incurred while looking for one,
			 * so continue searching.
			 */
			continue;
		} else if (ret != 0) {
			err = ret;
			break;
		}

		if (msglen != 0) {
			msgbuf = calloc(msglen, 1);
			if (msgbuf == NULL) {
				err = ENOMEM;
				break;
			}
		}

		ret = read_msg(ctx, msgbuf, msglen);
		if (ret == -1) {
			/*
			 * Did not find properly formatted "Msg = <hex data>".
			 * Restart the search for a new record.
			 */
			free(msgbuf);
			msgbuf = NULL;
			continue;
		} else if (ret != 0) {
			err = ret;
			break;
		}

		mdbuf = calloc(1, ctx->pc_hash_sz);
		if (mdbuf == NULL) {
			err = ENOMEM;
			break;
		}
		ret = read_md(ctx, mdbuf, ctx->pc_hash_sz);
		if (ret == -1) {
			/*
			 * Did not find properly formatted "MD = <hash>".
			 * Restart search for new record.
			 */
			free(msgbuf);
			free(mdbuf);
			msgbuf = mdbuf = NULL;
			continue;
		} else if (ret != 0) {
			err = ret;
			break;
		}

		res = malloc(sizeof (*res));
		if (res == NULL) {
			err = ENOMEM;
			break;
		}
		res->pe_msg = msgbuf;
		res->pe_msglen = msglen;
		res->pe_hash = mdbuf;
		break;
	}

	if (err != 0) {
		ASSERT(res == NULL);
		free(msgbuf);
		free(mdbuf);
	}

	/* EOF status indicated by err == 0 and res == NULL */
	*errp = err;
	return (res);
}

void
parser_free(parser_entry_t *ent)
{
	free(ent->pe_msg);
	free(ent->pe_hash);
	free(ent);
}

/*
 * With the above parser, run a the vectors through a given crypto test.
 */
int
digest_runner(char *mech_name, const char *input_file, size_t digest_len)
{
	int fails = 0, error;
	uint8_t N[1024];
	size_t updatelens[] = {
		1, 8, 33, 67, CTEST_UPDATELEN_WHOLE, CTEST_UPDATELEN_END
	};
	cryptotest_t args = {
		.out = N,
		.outlen = sizeof (N),
		.mechname = mech_name,
		.updatelens = updatelens
	};
	parser_ctx_t *ctx;
	parser_entry_t *ent;

	/*
	 * XXX: This could be changed to generate a path relative to that of
	 * the executable to find the data files
	 */
	char *path = NULL;
	if (asprintf(&path, "%s/%s", DATA_PATH, input_file) < 0) {
		err(EXIT_FAILURE, NULL);
	}

	ctx = parser_init(path, digest_len, &error);
	if (ctx == NULL) {
		err(EXIT_FAILURE, "%s", path);
	}
	free(path);

	error = 0;
	while ((ent = parser_read(ctx, &error)) != NULL) {
		args.in = ent->pe_msg;
		args.inlen = ent->pe_msglen;

		fails += run_test(&args, ent->pe_hash, digest_len, DIGEST_FG);
		parser_free(ent);
	}
	if (error != 0) {
		err(EXIT_FAILURE, NULL);
	}
	parser_fini(ctx);

	return (fails);
}
