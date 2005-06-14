/*
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>
#include <ctype.h>

#include "prof_int.h"

#define SECTION_SEP_CHAR '/'

#define STATE_INIT_COMMENT	1
#define STATE_STD_LINE		2
#define STATE_GET_OBRACE	3

struct parse_state {
	int	state;
	int	group_level;
	struct profile_node *root_section;
	struct profile_node *current_section;
};

static char *skip_over_blanks(cp)
	char	*cp;
{
	while (*cp && isspace(*cp))
		cp++;
	return cp;
}

static void strip_line(line)
	char	*line;
{
	char	*p;

	while (*line) {
		p = line + strlen(line) - 1;
		if ((*p == '\n') || (*p == '\r'))
			*p = 0;
		else
			break;
	}
}

static void parse_quoted_string(char *str)
{
	char *to, *from;

	to = from = str;

	for (to = from = str; *from && *from != '"'; to++, from++) {
		if (*from == '\\') {
			from++;
			switch (*from) {
			case 'n':
				*to = '\n';
				break;
			case 't':
				*to = '\t';
				break;
			case 'b':
				*to = '\b';
				break;
			default:
				*to = *from;
			}
			continue;
		}
		*to = *from;
	}
	*to = '\0';
}


static errcode_t parse_init_state(state)
	struct parse_state *state;
{
	state->state = STATE_INIT_COMMENT;
	state->group_level = 0;

	return profile_create_node("(root)", 0, &state->root_section);
}

static errcode_t parse_std_line(line, state)
	char	*line;
	struct parse_state *state;
{
	char	*cp, ch, *tag, *value;
	char	*p;
	errcode_t retval;
	struct profile_node	*node;
	int do_subsection = 0;
	void *iter = 0;
	
	if (*line == 0)
		return 0;
	if (line[0] == ';' || line[0] == '#')
		return 0;
	strip_line(line);
	cp = skip_over_blanks(line);
	ch = *cp;
	if (ch == 0)
		return 0;
	if (ch == '[') {
		if (state->group_level > 0)
			return PROF_SECTION_NOTOP;
		cp++;
		p = strchr(cp, ']');
		if (p == NULL)
			return PROF_SECTION_SYNTAX;
		*p = '\0';
		retval = profile_find_node_subsection(state->root_section,
						 cp, &iter, 0,
						 &state->current_section);
		if (retval == PROF_NO_SECTION) {
			retval = profile_add_node(state->root_section,
						  cp, 0,
						  &state->current_section);
			if (retval)
				return retval;
		} else if (retval)
			return retval;

		/*
		 * Finish off the rest of the line.
		 */
		cp = p+1;

		if (*cp == '*') {
			profile_make_node_final(state->current_section);
			cp++;
		}

		/*
		 * A space after ']' should not be fatal
		 */
		cp = skip_over_blanks(cp);
		if (*cp)
			return PROF_SECTION_SYNTAX;
		return 0;
	}
	if (ch == '}') {
		if (state->group_level == 0)
			return PROF_EXTRA_CBRACE;
		if (*(cp+1) == '*')
			profile_make_node_final(state->current_section);
		retval = profile_get_node_parent(state->current_section,
						 &state->current_section);
		if (retval)
			return retval;
		state->group_level--;
		return 0;
	}
	/*
	 * Parse the relations
	 */
	tag = cp;
	cp = strchr(cp, '=');
	if (!cp)
		return PROF_RELATION_SYNTAX;
	*cp = '\0';
	p = strchr(tag, ' ');
	if (p) {
		*p = '\0';
		p = skip_over_blanks(p+1);
		if (p != cp)
			return PROF_RELATION_SYNTAX;
	}
	cp = skip_over_blanks(cp+1);
	value = cp;
	if (value[0] == '"') {
		value++;
		parse_quoted_string(value);
	} else if (value[0] == 0) {
		do_subsection++;
		state->state = STATE_GET_OBRACE;
	} else if (value[0] == '{' && value[1] == 0)
		do_subsection++;
	else {
		/*
		 * Skip over trailing whitespace characters
		 */
		cp = value + strlen(value) - 1;
		while ((cp > value) && isspace(*cp))
			*cp-- = 0;
	}

	if (do_subsection) {
		p = strchr(tag, '*');
		if (p)
			*p = '\0';
		retval = profile_add_node(state->current_section,
					  tag, 0, &state->current_section);
		if (retval)
			return retval;
		if (p)
			profile_make_node_final(state->current_section);
		state->group_level++;
		return 0;
	}
	p = strchr(tag, '*');
	if (p)
		*p = '\0';
	profile_add_node(state->current_section, tag, value, &node);
	if (p)
		profile_make_node_final(node);
	return 0;
}

static errcode_t parse_line(line, state)
	char	*line;
	struct parse_state *state;
{
	char	*cp;
	
	switch (state->state) {
	case STATE_INIT_COMMENT:
		if (line[0] != '[')
			return 0;
		state->state = STATE_STD_LINE;
		/*FALLTHRU*/
	case STATE_STD_LINE:
		return parse_std_line(line, state);
	case STATE_GET_OBRACE:
		cp = skip_over_blanks(line);
		if (*cp != '{')
			return PROF_MISSING_OBRACE;
		state->state = STATE_STD_LINE;
		/*FALLTHRU*/
	}
	return 0;
}

errcode_t profile_parse_file(f, root)
	FILE	*f;
	struct profile_node **root;
{
#define BUF_SIZE	2048
	char *bptr;
	errcode_t retval;
	struct parse_state state;

	bptr = (char *) malloc (BUF_SIZE);
	if (!bptr)
		return ENOMEM;

	retval = parse_init_state(&state);
	if (retval) {
		free (bptr);
		return retval;
	}
	while (!feof(f)) {
		if (fgets(bptr, BUF_SIZE, f) == NULL)
			break;
		retval = parse_line(bptr, &state);
		if (retval) {
			/* check if an unconfigured file */
			if (strstr(bptr, "___"))
				retval = PROF_NO_PROFILE;
			free (bptr);
			return retval;
		}
	}
	*root = state.root_section;

	free (bptr);
	return 0;
}

/*
 * Return TRUE if the string begins or ends with whitespace
 */
static int need_double_quotes(str)
	char *str;
{
	if (!str || !*str)
		return 0;
	if (isspace(*str) ||isspace(*(str + strlen(str) - 1)))
		return 1;
	if (strchr(str, '\n') || strchr(str, '\t') || strchr(str, '\b'))
		return 1;
	return 0;
}

/*
 * Output a string with double quotes, doing appropriate backquoting
 * of characters as necessary.
 */
static void output_quoted_string(str, f)
	char	*str;
	FILE	*f;
{
	char	ch;
	
	fputc('"', f);
	if (!str) {
		fputc('"', f);
		return;
	}
	while ((ch = *str++)) {
		switch (ch) {
		case '\\':
			fputs("\\\\", f);
			break;
		case '\n':
			fputs("\\n", f);
			break;
		case '\t':
			fputs("\\t", f);
			break;
		case '\b':
			fputs("\\b", f);
			break;
		default:
			fputc(ch, f);
			break;
		}
	}
	fputc('"', f);
}



#if defined(_MSDOS) || defined(_WIN32)
#define EOL "\r\n"
#endif

#ifdef macintosh
#define EOL "\r"
#endif

#ifndef EOL
#define EOL "\n"
#endif

static void dump_profile_to_file(root, level, dstfile)
	struct profile_node *root;
	int level;
	FILE *dstfile;
{
	int i;
	struct profile_node *p;
	void *iter;
	long retval;
	char *name, *value;
	
	iter = 0;
	do {
		retval = profile_find_node_relation(root, 0, &iter,
						    &name, &value);
		if (retval)
			break;
		for (i=0; i < level; i++)
			fprintf(dstfile, "\t");
		if (need_double_quotes(value)) {
			fputs(name, dstfile);
			fputs(" = ", dstfile);
			output_quoted_string(value, dstfile);
			fputs(EOL, dstfile);
		} else
			fprintf(dstfile, "%s = %s%s", name, value, EOL);
	} while (iter != 0);

	iter = 0;
	do {
		retval = profile_find_node_subsection(root, 0, &iter,
						      &name, &p);
		if (retval)
			break;
		if (level == 0)	{ /* [xxx] */
			for (i=0; i < level; i++)
				fprintf(dstfile, "\t");
			fprintf(dstfile, "[%s]%s%s", name,
				profile_is_node_final(p) ? "*" : "", EOL);
			dump_profile_to_file(p, level+1, dstfile);
			fprintf(dstfile, EOL);
		} else { 	/* xxx = { ... } */
			for (i=0; i < level; i++)
				fprintf(dstfile, "\t");
			fprintf(dstfile, "%s = {%s", name, EOL);
			dump_profile_to_file(p, level+1, dstfile);
			for (i=0; i < level; i++)
				fprintf(dstfile, "\t");
			fprintf(dstfile, "}%s%s",
				profile_is_node_final(p) ? "*" : "", EOL);
		}
	} while (iter != 0);
}

errcode_t profile_write_tree_file(root, dstfile)
	struct profile_node *root;
	FILE		*dstfile;
{
	dump_profile_to_file(root, 0, dstfile);
	return 0;
}
