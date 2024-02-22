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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_GNU_MSGFMT_H
#define	_GNU_MSGFMT_H

#include <stdio.h>
#include <limits.h>
#include <stdarg.h>
#include <locale.h>
#include <libintl.h>
#include <string.h>
#include <stdlib.h>
#include <iconv.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <alloca.h>
#include <unistd.h>
#include <errno.h>
#include "gnu_errmsg.h"
#include "common.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define	_ENCODING_ALIAS_PATH	"/usr/lib/iconv/alias"
#define	DEST_CHARSET	"UTF-8"
#define	CHARSET_STR	"charset="
#define	CHARSET_LEN	8
#define	NPLURALS_STR	"nplurals="
#define	NPLURALS_LEN	9

#define	CBUFSIZE	128
#define	MBUFSIZE	128
#define	KBUFSIZE	16
#define	NBUFSIZE	8

#define	cur_po	(po_names[cur_po_index])

struct loc {
	off_t	off;	/* offset to the string */
	size_t	len;	/* length of the string including null-termination */
	unsigned int	num;	/* line number */
};

struct entry {
	int	no;			/* # of plural forms */
	unsigned int	num;	/* line number */
	char	*str;	/* string */
	size_t	len;	/* length of the string including null-termination */
	struct loc	*pos;
};

struct messages {
	char	*id;			/* msgid + (msgid_plural) */
	char	*str;			/* msgstr + (msgstr[n]) */
	size_t	id_len;			/* length of id */
	size_t	str_len;		/* length of str */
	unsigned int	hash;	/* hash value of msgid */
	unsigned int	num;	/* line number */
	int	po;		/* po index */
};

#define	DEF_MSG_NUM	100

struct catalog {
	int	header;			/* 1: header found, 0: header missing */
	char	*fname;			/* mo filename */
	struct messages	*msg;	/* ptr to the messages struct array */
	unsigned int	nmsg;	/* # of messages */
	unsigned int	msg_size;	/* message_size */
	unsigned int	fnum;	/* # of fuzzy translations */
	unsigned int	unum;	/* # of untranslated msgs */
	unsigned int	hash_size;	/* hash table size */
	unsigned int	nplurals;	/* # of plural forms */
	unsigned int	*thash;
	unsigned int	thash_size;
	struct catalog	*next;		/* next catalog */
};

struct msgtbl {
	unsigned int	len;
	unsigned int	offset;
};

extern int	yyparse(void);
extern int	yylex(void);
extern int	yyerror(const char *) __NORETURN;
extern void	handle_domain(char *);
extern void	handle_comment(char *);
extern void	handle_message(struct entry *, struct entry *);
extern void	clear_state(void);
extern void	po_init(const char *);
extern void	po_fini(void);
extern void	catalog_init(const char *);

extern struct messages *search_msg(struct catalog *,
	const char *, unsigned int);
extern unsigned int	hashpjw(const char *);
extern unsigned int	find_prime(unsigned int);
extern void	output_all_gnu_mo_files(void);
extern unsigned int	get_hash_index(unsigned int *,
	unsigned int, unsigned int);
extern void	check_format(struct entry *, struct entry *, int);

extern char	**po_names;
extern int	cur_po_index;
extern int	po_error;
extern char	*inputdir;
extern char	*outfile;
extern int	cur_line;
extern int	fuzzy_flag;
extern int	verbose_flag;
extern int	strict_flag;
extern struct catalog	*catalog_head;
extern FILE	*fp;
extern iconv_t	cd;

#ifdef	__cplusplus
}
#endif

#endif /* _GNU_MSGFMT_H */
