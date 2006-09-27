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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BART_H
#define	_BART_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <md5.h>
#include <ftw.h>
#include <libintl.h>
#include "msgs.h"

#define	EXIT		0
#define	WARNING_EXIT	1
#define	FATAL_EXIT	2

#define	CHECK		0
#define	NOCHECK		1

#define	CHECK_KEYWORD(s)	(strcmp(s, "CHECK") == 0)
#define	IGNORE_KEYWORD(s)	(strcmp(s, "IGNORE") == 0)

#define	ALL_KEYWORD		"all"
#define	CONTENTS_KEYWORD	"contents"
#define	TYPE_KEYWORD		"type"
#define	SIZE_KEYWORD		"size"
#define	MODE_KEYWORD		"mode"
#define	ACL_KEYWORD		"acl"
#define	UID_KEYWORD		"uid"
#define	GID_KEYWORD		"gid"
#define	MTIME_KEYWORD		"mtime"
#define	LNMTIME_KEYWORD		"lnmtime"
#define	DIRMTIME_KEYWORD	"dirmtime"
#define	DEST_KEYWORD		"dest"
#define	DEVNODE_KEYWORD		"devnode"
#define	ADD_KEYWORD		"add"
#define	DELETE_KEYWORD		"delete"

#define	MANIFEST_VER	"! Version 1.0\n"
#define	FORMAT_STR	"# Format:\n\
#fname D size mode acl dirmtime uid gid\n\
#fname P size mode acl mtime uid gid\n\
#fname S size mode acl mtime uid gid\n\
#fname F size mode acl mtime uid gid contents\n\
#fname L size mode acl lnmtime uid gid dest\n\
#fname B size mode acl mtime uid gid devnode\n\
#fname C size mode acl mtime uid gid devnode\n"

/*
 * size of buffer - used in several places
 */
#define	BUF_SIZE	65536

/*
 * size of ACL buffer - used in several places
 */
#define	ACL_SIZE	1024

/*
 * size of MISC buffer - used in several places
 */
#define	MISC_SIZE	20

/*
 * size of TYPE buffer - used in several places
 */
#define	TYPE_SIZE	2

struct tree_modifier {
	char			*mod_str;
	int			include;
	struct tree_modifier	*next;
};

struct attr_keyword {
	char    *ak_name;
	int	ak_flags;
};


#define	ATTR_ALL ((uint_t)~0)
#define	ATTR_CONTENTS 0x0001
#define	ATTR_TYPE 0x0002
#define	ATTR_SIZE 0x0004
#define	ATTR_MODE 0x0008
#define	ATTR_UID 0x0010
#define	ATTR_GID 0x0020
#define	ATTR_ACL 0x0040
#define	ATTR_DEST 0x0080
#define	ATTR_DEVNODE 0x0100
#define	ATTR_MTIME 0x0200
#define	ATTR_LNMTIME 0x0400
#define	ATTR_DIRMTIME 0x0800
#define	ATTR_ADD 0x1000
#define	ATTR_DELETE 0x2000

struct rule {
	char			subtree[PATH_MAX];
	uint_t			attr_list;
	struct tree_modifier	*modifiers;
	struct rule		*next;
	struct rule		*prev;
};

struct dir_component {
	char			dirname[PATH_MAX];
	struct dir_component	*next;
};


struct attr_keyword *attr_keylookup(char *);
void usage(void);
int bart_create(int, char **);
int bart_compare(int, char **);
struct rule *check_rules(const char *, char);
int exclude_fname(const char *, char, struct rule *);
struct rule *get_first_subtree(void);
struct rule *get_next_subtree(struct rule *);
void process_glob_ignores(char *, uint_t *);
void *safe_calloc(size_t);
char *safe_strdup(char *);
int read_rules(FILE *, char *, uint_t, int);
int read_line(FILE *, char *, int, int, char **, char *);
#ifdef	__cplusplus
}
#endif

#endif	/* _BART_H */
