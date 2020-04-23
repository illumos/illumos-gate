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
 * Copyright 2020 Oxide Computer Company
 */

#ifndef _PARSER_RUNNER_H_
#define	_PARSER_RUNNER_H_

#include <sys/types.h>

struct parser_ctx;

struct parser_entry {
	uchar_t	*pe_msg;
	size_t	pe_msglen;
	uchar_t	*pe_hash;
};

typedef struct parser_ctx parser_ctx_t;
typedef struct parser_entry parser_entry_t;

parser_ctx_t *parser_init(const char *, size_t, int *);
void parser_fini(parser_ctx_t *);
parser_entry_t *parser_read(parser_ctx_t *, int *);
void parser_free(parser_entry_t *);

int digest_runner(char *, const char *, size_t);

#endif /* _PARSER_RUNNER_H_ */
