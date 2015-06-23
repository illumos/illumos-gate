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

/*
 * In this mode, we generate header files containg various #defines which can
 * be used to access members of various structures, and to walk through arrays.
 * The input template specifies the structures and members for whom #defines
 * are to be generated.
 *
 * The template has the following elements
 *
 * 1. Given the name of a structure or union, #defines can be generated that
 *    describe the type.  If requested, #defines that give the size and the
 *    log2 (shift) of the structure will be generated.  The latter can only
 *    be requested for structures whose size is a power of two.
 *
 *    Per-member #defines are also generated.  The value of these defines will
 *    be the offsets necessary to access the members they describe.  By
 *    default, the name of the #define will be the name of the member, in upper
 *    case, but a user-supplied version can be used instead.  If the member is
 *    an array, an extra #define will be generated that will give the increment
 *    needed to access individual array elements.  The name of the increment
 *    #define will be identical to that of the member #define, but with an
 *    "_INCR" suffix.
 *
 * 2. Literal cpp directives
 *
 *    Lines beginning with "\#" are copied directly to the output file.
 *
 * 3. Comments
 *
 *    Lines beginning with backslashes (excluding the literal cpp directives
 *    described above) are ignored.
 *
 * Example input:
 *
 *    \ Dump the `foo' structure, creating a size #define called FOO_SIZE, and a
 *    \ shift #define called FOO_SHIFT.  `foo' has one member called `mem'.
 *    foo FOO_SIZE FOO_SHIFT
 *
 *    \ Dump the `a' and `b' members of the `bar' structure.  the offset
 *    \ #defines for these members should be `FRED' and `BOB', respectively.
 *    \ Both members are of type `char'
 *    bar
 *	a	FRED
 *	b	BOB
 *
 * Example output:
 *
 *    #define FOO_SIZE	0x4
 *    #define FOO_SHIFT	0x2
 *    #define FRED	0x0
 *    #define FRED_INCR	0x1
 *    #define BOB	0x4
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>

#include "ctf_headers.h"
#include "utils.h"
#include "ctfstabs.h"

static int
ga_parse_tokens(char *line, int max, char ***wret)
{
	char *c = line;
	char *word;
	int n;

	while (isspace(*c))
		c++;

	for (n = 1, word = strtok(line, " \t"); word != NULL;
	    word = strtok(NULL, " \t"), n++) {
		if (n > max)
			return (-1);

		*(wret[n - 1]) = word;
	}

	return (n - 1);
}

static int
ga_parse_common(char *line, int min, int max, char **w1, char **w2, char **w3)
{
	char **wret[3];
	int nread;

	wret[0] = w1;
	wret[1] = w2;
	wret[2] = w3;

	if ((nread = ga_parse_tokens(line, max, wret)) < min)
		return (-1);

	if (nread < 3 && wret[2] != NULL)
		*wret[2] = (char *)NULL;
	if (nread < 2 && wret[1] != NULL)
		*wret[1] = (char *)NULL;
	if (nread < 1 && wret[0] != NULL)
		*wret[0] = (char *)NULL;

	return (nread);
}

/*
 * Valid format:	typename [sizedefname [shiftdefname]]
 */
static int
ga_parse_name(char *line, char **cnp, char **szdp, char **shdp)
{
	return (ga_parse_common(line, 1, 3, cnp, szdp, shdp));
}

/*
 * Valid format:	memname [offdefname]
 */
static int
ga_parse_member(char *line, char **mnp, char **offp)
{
	return (ga_parse_common(line, 1, 2, mnp, offp, NULL));
}

/*
 * Used to begin a new structure/union block, and to print the optional size
 * and optional shift constants.
 */
static int
ga_process_name(char *line)
{
	char *curname, *sizedef, *shdef;
	ctf_id_t curtype;
	ssize_t sz, shift;

	if (ga_parse_name(line, &curname, &sizedef, &shdef) < 0)
		return (parse_warn("Couldn't parse name"));

	if ((curtype = find_type(curname)) == CTF_ERR)
		return (parse_warn("Couldn't find type %s", curname));

	if (sizedef != NULL) {
		if ((sz = ctf_type_size(ctf, curtype)) < 0) {
			return (parse_warn("Couldn't get size for type %s",
			    curname));
		} else if (sz == 0) {
			return (parse_warn("Invalid type size 0 for %s",
			    curname));
		}

		(void) fprintf(out, "#define\t%s\t0x%x\n", sizedef, sz);
	}

	if (shdef != NULL) {
		ssize_t tsz;

		for (shift = -1, tsz = sz; tsz > 0; tsz >>= 1, shift++)
			;
		if (shift < 0 || 1 << shift != sz) {
			return (parse_warn("Can't make shift #define: %s size "
			    "(%d) isn't a power of 2", curname, sz));
		}

		(void) fprintf(out, "#define\t%s\t0x%x\n", shdef, shift);
	}

	return (curtype);
}

/*
 * ga_process_member() and ga_member_cb() are used to print the offset and
 * possibly array increment values for a given structure member.  A specific
 * member is requested via ga_process_member(), and ga_member_cb() is used
 * to iterate through the members of the current structure type, looking for
 * that member.  This is not the most efficient way to do things, but the
 * lists involved are generally short.
 */
typedef struct ga_member_cb_data {
	char *gmcb_memname;
	char *gmcb_submem;
	char *gmcb_offdef;
	size_t gmcb_off;
} ga_member_cb_data_t;

static int ga_member_find(ctf_id_t, ga_member_cb_data_t *);

static int
ga_member_cb(const char *name, ctf_id_t type, ulong_t off, void *arg)
{
	ga_member_cb_data_t *md = arg;
	ctf_arinfo_t arinfo;
	char *label;

	if (strcmp(name, md->gmcb_memname) != 0)
		return (0);

	md->gmcb_off += off / 8;	/* off is in bits */

	if (md->gmcb_submem != NULL) {
		/*
		 * The user requested foo.bar.  We've found foo, and now need to
		 * recurse down to bar.
		 */
		ga_member_cb_data_t smd;

		smd.gmcb_memname = md->gmcb_submem;
		smd.gmcb_submem = NULL;
		smd.gmcb_offdef = md->gmcb_offdef;
		smd.gmcb_off = md->gmcb_off;

		return (ga_member_find(type, &smd));
	}

	if (md->gmcb_offdef == NULL) {
		int i;

		label = md->gmcb_memname;
		for (i = 0; i < strlen(label); i++)
			label[i] = toupper(label[i]);
	} else
		label = md->gmcb_offdef;

	/* offsets are in bits - we need bytes */
	(void) fprintf(out, "#define\t%s\t0x%lx\n", label,
	    (ulong_t)md->gmcb_off);

	if ((type = ctf_type_resolve(ctf, type)) == CTF_ERR)
		return (parse_warn("Couldn't resolve type %s", name));

	if (ctf_array_info(ctf, type, &arinfo) == 0) {
		ssize_t sz;

		if ((sz = ctf_type_size(ctf, arinfo.ctr_contents)) < 0)
			return (parse_warn("Couldn't get array elem size"));

		(void) fprintf(out, "#define\t%s_INCR\t0x%x\n", label, sz);
	}

	return (1);
}

static int
ga_member_find(ctf_id_t curtype, ga_member_cb_data_t *md)
{
	char *c;
	int rc;

	if ((c = strchr(md->gmcb_memname, '.')) != NULL)
		*c++ = '\0';
	md->gmcb_submem = c;

	if ((rc = ctf_member_iter(ctf, curtype, ga_member_cb, md)) == 0) {
		return (parse_warn("Couldn't find member named %s",
		    md->gmcb_memname));
	} else if (rc != 1)
		return (parse_warn("Can't parse"));

	return (1);
}

static int
ga_process_member(ctf_id_t curtype, char *line)
{
	ga_member_cb_data_t md = { 0 };

	if (ga_parse_member(line, &md.gmcb_memname, &md.gmcb_offdef) < 0)
		return (parse_warn("Couldn't parse member"));

	return (ga_member_find(curtype, &md));
}

static int
ga_process_line(char *line)
{
	static int curtype = -1;
	static int blanks = 0;

	if (strlen(line) == 0) {
		blanks++;
		return (1);
	} else if (blanks) {
		if (!isspace(line[0]))
			curtype = -1;
		blanks = 0;
	}

	if (line[0] == '\\') {
		if (line[1] == '#') {
			/* dump, verbatim, lines that begin with "\#" */
			(void) fprintf(out, "%s\n", line + 1);
		}
		return (1);

	} else if (line[0] == '#') {
		/*
		 * This is a comment of some sort; is it a line number
		 * comment?  Those look like '# 53 "filename.c"'.  GCC
		 * sometimes inserts them and removes all other vertical
		 * whitespace, so they should be treated as a "type
		 * terminator" like a blank line is.
		 */
		if (isdigit(line[2])) {
			/* line number, terminate type */
			curtype = -1;
		}
		return (1);
	}
	if (curtype == -1)
		return ((curtype = ga_process_name(line)));
	else
		return (ga_process_member(curtype, line));
}

proc_ops_t ga_ops = {
	NULL,
	ga_process_line,
	NULL
};
