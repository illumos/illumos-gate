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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * In this mode, we generate forthdebug macros as requested by the input
 * template, the format of which is given below.
 *
 * These templates have the following elements:
 *
 * 1. Macro creation
 *
 *    Given the name of a structure, union, or enum type, a forthdebug macro
 *    is created that will dump the members of the type.  The type can be
 *    specified as a standalone structure, union, or enum, or it can be
 *    described relative to another structure or union as "type.member".
 *
 *    By default, all struct members, union members, or enum values, as
 *    appropriate, will be printed.  An alternate form allows specific members
 *    of struct or union types to be printed.  Both forms must be followed by a
 *    blank line.  In the specific-member case, an optional format specifier can
 *    be provided that will be used to dump the contents of the member.
 *    Builtins `d' and `x' can be used to dump the member in decimal or
 *    hexadecimal, respectively.  Alternatively, a custom formatter can be
 *    specified.
 *
 * 2. Model-specific sections
 *
 *    `model_start' / `model_end' pairs function as an #ifdef for the ctfstabs
 *    tool.  They take, as an argument, either `ilp32' or `lp64'.  If a 64-bit
 *    macro is being generated (if a 64-bit object file is being used), lines
 *    between `lp64' model pairs will be processed, but lines between `ilp32'
 *    pairs will be omitted.  The reverse is true for 32-bit macros.
 *
 * 3. Literal sections
 *
 *    Portions of the input template file enclosed within `forth_start' /
 *    `forth_end' pairs and between `verbatim_begin' / `verbatim_end' pairs
 *    will be copied as-is to the output file.
 *
 * 4. Comments
 *
 *    Lines beginning with backslashes are ignored.
 *
 * Example:
 *
 *    \ dump the `foo' structure
 *    foo
 *
 *    \ dump the `a' and `b' members of the `bar' structure.  dump member `b'
 *    \ in hexadecimal
 *    bar
 *	a
 *	b	x
 *
 *    \ dump the `big' member of the `baz' structure in 64-bit macros, and
 *    \ the `small' member in 32-bit macros.
 *    baz
 *    model_start lp64
 *	big
 *    model_end
 *    model_start ilp32
 *	small
 *    model_end
 *
 *    \ copy `literal 1' and `literal 2' to the output file
 *    verbatim_begin
 *    literal 1
 *    verbatim_end
 *    forth_start
 *    literal 2
 *    forth_end
 *
 * For a more complex example, see common.fdbg.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ctf_headers.h"
#include "ctfstabs.h"
#include "forth.h"
#include "utils.h"
#include "memory.h"

char *fth_curtype;			/* name of the type being processed */
static fth_type_ops_t *fth_type_ops;	/* see forth.h */

static char *fth_model;		/* the current macro type - for model_start */
static int fth_ignoring;	/* in a non-matching model_start/end pair */
static int fth_copying;		/* in a verbatim_* or forth_* pair */

static int
fth_init(char *model)
{
	fth_model = model;

	return (0);
}

/*ARGSUSED*/
static int
fth_null_header(ctf_id_t tid)
{
	return (0);
}

/*ARGSUSED*/
static int
fth_null_members(char *memfilter, char *format)
{
	return (0);
}

static int
fth_null_trailer(void)
{
	return (0);
}

static fth_type_ops_t fth_null_ops = {
	fth_null_header,
	fth_null_members,
	fth_null_trailer
};

/*ARGSUSED2*/
static int
find_member_cb(const char *memname, ctf_id_t tid, ulong_t off, void *arg)
{
	char *memtofind = arg;

	if (strcmp(memname, memtofind) == 0)
		return (tid);

	return (0);
}

/* find the tid of a specified member */
static ctf_id_t
find_member(ctf_id_t tid, char *memname)
{
	return (ctf_member_iter(ctf, tid, find_member_cb, memname));
}

/*
 * Begin a macro.
 *
 * Once we figure out the type of the thing that we're supposed to dump (struct,
 * union, or enum), we select the proper type-specific ops-vector for dumping.
 */
static int
fth_section_init(char *fullname)
{
	ctf_id_t ltid = 0, tid;
	char *curtype, *lpart, *part, *npart;
	int lkind = 0, kind;

	curtype = xstrdup(fullname);
	lpart = NULL;
	part = strtok(fullname, ".");

	/*
	 * First figure out what sort of type we're looking at.  Life would be
	 * simple if we were only going to get type names, but it's not - we
	 * could also get `type.member'.  In that case, we need to figure out
	 * (and dump) the type of `member' instead.
	 */
	for (;;) {
		if (lpart == NULL) {
			/* First part - the struct name */
			if ((tid = find_type(part)) == CTF_ERR ||
			    (tid = ctf_type_resolve(ctf, tid)) == CTF_ERR ||
			    (kind = ctf_type_kind(ctf, tid)) == CTF_ERR) {
				free(curtype);
				return (parse_warn("Couldn't find %s: %s",
				    part, ctf_errmsg(ctf_errno(ctf))));
			}
		} else {
			/* Second (or more) part - the member name */
			if (lkind != CTF_K_STRUCT && lkind != CTF_K_UNION) {
				free(curtype);
				return (parse_warn("%s isn't a struct/union",
				    lpart));
			}

			if ((tid = find_member(ltid, part)) <= 0) {
				free(curtype);
				return (parse_warn("%s isn't a member of %s",
				    part, lpart));
			}

			if ((kind = ctf_type_kind(ctf, tid)) == CTF_ERR) {
				free(curtype);
				return (parse_warn("Can't get kind for %s",
				    part));
			}
		}

		/*
		 * Stop if there aren't any more parts.  We use `npart' here
		 * because we don't want to clobber part - we need it later.
		 */
		if ((npart = strtok(NULL, ".")) == NULL)
			break;

		lpart = part;
		ltid = tid;
		lkind = kind;

		part = npart;
	}

	/*
	 * Pick the right ops vector for dumping.
	 */
	switch (kind) {
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		fth_type_ops = &fth_struct_ops;
		break;

	case CTF_K_ENUM:
		fth_type_ops = &fth_enum_ops;
		break;

	default:
		fth_type_ops = &fth_null_ops;
		free(curtype);
		return (parse_warn("%s isn't a struct, union, or enum", part));
	}

	fth_curtype = curtype;

	return (fth_type_ops->fto_header(tid));
}

static int
fth_section_add_member(char *name, char *format)
{
	if (fth_curtype == NULL)
		return (fth_section_init(name));

	if (fth_type_ops->fto_members(name, format) < 0)
		return (-1);

	return (0);
}

static int
fth_section_end(void)
{
	if (fth_curtype == NULL)
		return (0);

	if (fth_type_ops->fto_trailer() < 0)
		return (-1);

	free(fth_curtype);
	fth_curtype = NULL;

	return (0);
}

static int
fth_process_line(char *line)
{
	char *format = NULL;
	char *word, *name, *c;
	int nblank = 0;
	int n;

	if (strlen(line) == 0) {
		if (fth_section_end() < 0)
			return (-1);

		if (fth_copying == 1 || nblank++ == 1)
			(void) fprintf(out, "\n");
		return (0);
	} else
		nblank = 0;

	/* skip comments */
	if (line[0] == '\\')
		return (0);

	if (strcmp(line, "model_end") == 0) {
		fth_ignoring = 0;
		return (0);
	}

	if (fth_ignoring == 1)
		return (0);

	word = "model_start ";
	if (strncmp(line, word, strlen(word)) == 0) {
		for (c = line + strlen(word); isspace(*c); c++);
		if (strlen(c) == strlen(fth_model) &&
		    strncmp(c, fth_model, strlen(fth_model)) == 0)
			/* EMPTY - match */;
		else
			fth_ignoring = 1;
		return (0);
	}

	if (strcmp(line, "verbatim_end") == 0 ||
	    strcmp(line, "forth_end") == 0) {
		char *start = (strcmp(line, "verbatim_end") == 0 ?
		    "verbatim_begin" : "forth_start");

		if (fth_copying == 0) {
			(void) parse_warn("Found %s without matching %s",
			    line, start);
			if (fth_curtype != NULL)
				(void) fth_section_end();
			return (-1);
		}
		fth_copying = 0;
		return (0);
	}

	if (fth_copying == 1) {
		(void) fprintf(out, "%s\n", line);
		return (0);
	}

	if (strcmp(line, "verbatim_begin") == 0 ||
	    strcmp(line, "forth_start") == 0) {
		if (fth_curtype != NULL) {
			(void) parse_warn("Expected blank line between %s "
			    "macro and %s", fth_curtype, line);
			return (fth_section_end());
		}

		fth_copying = 1;
		return (0);
	}

	for (n = 1, word = strtok(line, " \t"); word != NULL;
	    word = strtok(NULL, " \t"), n++) {
		if (n == 1)
			name = word;
		else if (n == 2)
			format = word;
		else
			(void) parse_warn("Too many words");
	}

	return (fth_section_add_member(name, format));
}

static int
fth_fini(void)
{
	return (fth_section_end());
}

proc_ops_t fth_ops = {
	fth_init,
	fth_process_line,
	fth_fini
};
