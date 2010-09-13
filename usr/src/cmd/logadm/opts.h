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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * logadm/opts.h -- public definitions for opts module
 */

#ifndef	_LOGADM_OPTS_H
#define	_LOGADM_OPTS_H

#ifdef	__cplusplus
extern "C" {
#endif

/* various types of options we allow */
enum opttype {
	OPTTYPE_BOOLEAN,	/* simple boolean flag */
	OPTTYPE_INT,		/* simple number */
	OPTTYPE_STRING		/* string (like a pathname) */
};

struct opts;

/* info that drives option parsing (table of these is passed to opts_init()) */
struct optinfo {
	char *oi_o;	/* the option */
	enum opttype oi_t;	/* the type of this option */
	/* parser, if set, is called to parse optarg */
	off_t (*oi_parser)(const char *o, const char *optarg);
	int oi_flags;
};

/* flags for struct optinfo */
#define	OPTF_CLI	1
#define	OPTF_CONF	2

void opts_init(struct optinfo *table, int numentries);
struct opts *opts_parse(struct opts *, char **args, int flags);
void opts_free(struct opts *opts);
void opts_set(struct opts *opts, const char *o, const char *optarg);
int opts_count(struct opts *opts, const char *options);
const char *opts_optarg(struct opts *opts, const char *o);
off_t opts_optarg_int(struct opts *opts, const char *o);
struct fn_list *opts_cmdargs(struct opts *opts);
struct opts *opts_merge(struct opts *back, struct opts *front);

#define	OPTP_NOW (-1)
#define	OPTP_NEVER (-2)

void opts_print(struct opts *opts, FILE *stream, char *exclude);
void opts_printword(const char *word, FILE *stream);

extern struct optinfo Opttable[];
extern int Opttable_cnt;

#ifdef	__cplusplus
}
#endif

#endif	/* _LOGADM_OPTS_H */
