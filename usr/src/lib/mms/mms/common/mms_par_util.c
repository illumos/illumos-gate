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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <mms_list.h>
#include <mms_sym.h>
#include <mms_parser.h>
#include <mms_par_impl.h>
#include <mms_sym.h>
#include <msg_sub.h>
#include <mms_trace.h>

static int mms_pn_token_start_xml(mms_par_node_t *node,
		char *line, int level, int len);
static int mms_pn_token_end_xml(mms_par_node_t *node,
		char *line, int level, int len);
static int mms_pn_token_end_text(mms_par_node_t *node, char *line, int len);
static int mms_pn_token_start_text(mms_par_node_t *node, char *line, int len);
static mms_par_node_t *mms_pn_lookup_aux(mms_par_node_t *top,
		mms_par_node_t *start, char *str, int type, int self);
static int mms_pn_cmd_len_xml_aux(mms_par_node_t *top, int level);

static int mms_pn_build_cmd_xml_aux(mms_par_node_t *top, char *line,
		int level, int len);
static void mms_pn_fini_aux(mms_par_node_t *root);

int		mms_symtab_initialized = 0;
extern mutex_t	mms_par_mutex;
extern mms_pw_t *mms_pw;

#define					MMS_FUZZ	5

/*
 * Translate chars &, <. >, " and ' to xml mms_escape sequence
 */
typedef struct mms_escape_seq {
	char		*es_char;
	char		*es_seq;
	int		es_len;
}	mms_escape_seq_t;

#define	MMS_SEMICOLON	"\073"	/* Have to do this to suppress cstyle */
				/* from complaining */
static mms_escape_seq_t mms_esseq[] = {
	"\"", "&quot" MMS_SEMICOLON, 6,
	"'", "&apos" MMS_SEMICOLON, 6,
	">", "&gt" MMS_SEMICOLON, 4,
	"<", "&lt" MMS_SEMICOLON, 4,
	"&", "&amp" MMS_SEMICOLON, 5,
};
static int	mms_num_esseq = sizeof (mms_esseq) / sizeof (mms_escape_seq_t);

static void
mms_par_indent(char *line, int level)
{
	int		i;
	for (i = 0; i < level; i++) {
		line[i] = ' ';
	}
}

void
mms_par_list_insert_tail(mms_list_t *list, void *node)
{
	if (node != NULL) {
		mms_list_insert_tail(list, node);
	}
}

void
mms_pe_destroy(mms_list_t *err_list)
{
	mms_par_err_t	*err, *tmp;

	mms_list_foreach_safe(err_list, err, tmp) {
		mms_list_remove(err_list, err);
		mms_pe_free(err);
	}
}

void
mms_pe_free(mms_par_err_t *err)
{
	if (err->pe_msg)
		free(err->pe_msg);
	if (err->pe_token)
		free(err->pe_token);
	free(err);
}

mms_par_node_t	*
mms_par_alloc_node(enum mms_pn_type type, char *str)
{
	mms_par_node_t	*node;

	node = (mms_par_node_t *)malloc(sizeof (mms_par_node_t));
	if (node == NULL) {
		return (NULL);
	}
	(void) memset(node, 0, sizeof (mms_par_node_t));
	node->pn_type = type;
	mms_list_create(&node->pn_arglist, sizeof (mms_par_node_t),
	    offsetof(mms_par_node_t, pn_next));
	mms_list_create(&node->pn_attrlist, sizeof (mms_par_node_t),
	    offsetof(mms_par_node_t, pn_attrlist));
	mms_list_create(&node->pn_memlist, sizeof (mms_par_node_t),
	    offsetof(mms_par_node_t, pn_memnext));
	node->pn_string = strdup(str);
	if (mms_pn_token(node) == NULL) {
		free(node);
		return (NULL);
	}
	return (node);
}

void
mms_pn_destroy(mms_par_node_t *node)
{
	mms_par_node_t	*obj;
	mms_par_node_t	*tmp;

	if (node == NULL)
		return;

	mms_list_foreach_safe(&node->pn_memlist, obj, tmp) {
		mms_list_remove(&node->pn_memlist, obj);
		if (obj->pn_string) {
			free(obj->pn_string);
			obj->pn_string = NULL;
		}
		free(obj);
	}
	if (node->pn_string) {
		free(node->pn_string);
		node->pn_string = NULL;
	}
	free(node);
}

/*
 * mms_pn_len_xml - return the length needed to convert this node to text
 */
int
mms_pn_len_xml(mms_par_node_t *node, int level)
{
	int		len = 0;
	int		i, j;
	char		*str;

	len = strlen(mms_pn_token(node));
	switch (mms_pn_type(node)) {
	case MMS_PN_CMD:
		len = 2 * len + 7 + level;
		break;
	case MMS_PN_OPS:
		len = 2 * len + 7 + level;
		break;
	case MMS_PN_CLAUSE:
		len = 2 * len + 7 + level;
		break;
	case MMS_PN_RANGE:
		len = 2 * len + 7 + level;
		break;
	case MMS_PN_OBJ:
		len = len + 19 + level;
		break;
	case MMS_PN_ATTR:
		len = len + 8;
		break;
	case MMS_PN_STRING:
		len = len * 5 + 16 + level;
		break;
	case MMS_PN_NUMERIC | MMS_PN_STRING:
		len = len + 16 + level;
		break;
	case MMS_PN_NULLSTR | MMS_PN_STRING:
		len = len + 8 + level;
		break;
	case MMS_PN_KEYWORD:
		len = len + 4 + level;
		break;
	default:
		len += 1;
		break;
	}

	str = mms_pn_token(node);
	for (i = 0; i < strlen(str); i++) {
		for (j = 0; j < mms_num_esseq; j++) {
			if (str[i] == mms_esseq[j].es_char[0]) {
				len += 10;
			}
		}
	}
	return (len + MMS_FUZZ);
}

/*
 * mms_pn_cmd_len_xml - return the length needed to convert this node
 *                        and the list of nodes attached to this node.
 */
int
mms_pn_cmd_len_xml(mms_par_node_t *top)
{
	return (mms_pn_cmd_len_xml_aux(top, 0));
}

static int
mms_pn_cmd_len_xml_aux(mms_par_node_t *top, int level)
{
	mms_par_node_t	*node;
	int		len;

	len = mms_pn_len_xml(top, level);
	mms_list_foreach(&top->pn_arglist, node) {
		len += mms_pn_cmd_len_xml_aux(node, level + 1);
	}
	return (len);
}

/*
 * par_node_to_text_start - convert the beginning part of this node
 */
static int
mms_pn_token_start_xml(mms_par_node_t *node, char *line, int level, int len)
{
	char		*start = line + level;
	char		*text;

	switch (mms_pn_type(node)) {
	case MMS_PN_CMD:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "<%s>\n", mms_pn_token(node));
		break;
	case MMS_PN_OPS:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "<%s>\n", mms_pn_token(node));
		break;
	case MMS_PN_CLAUSE:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "<%s>\n", mms_pn_token(node));
		break;
	case MMS_PN_RANGE:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "<%s>\n", mms_pn_token(node));
		break;
	case MMS_PN_OBJ:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "<object name=\"%s\"", mms_pn_token(node));
		break;
	case MMS_PN_ATTR:
		(void) snprintf(line, len - level,
		    " attr=\"%s\"", mms_pn_token(node));
		break;
	case MMS_PN_STRING:
		mms_par_indent(line, level);
		text = mms_par_char_to_xml_escape(mms_pn_token(node));
		if (text == NULL) {
			text = "\n****** OUT OF MEMORY ******\n\n";
		}
		(void) snprintf(start, len - level,
		    "<arg value=\"%s\"/>\n", text);
		break;
	case MMS_PN_KEYWORD:
	case MMS_PN_NULLSTR | MMS_PN_STRING:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "<%s/>\n", mms_pn_token(node));
		break;
	case MMS_PN_NUMERIC | MMS_PN_STRING:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "<arg value=\"%s\"/>\n", mms_pn_token(node));
		break;
	default:
		(void) snprintf(line, len - level, "%s", " ");
		break;
	}
	return (strlen(line));
}

/*
 * par_node_to_text_end - terminate the converted text.
 */
static int
mms_pn_token_end_xml(mms_par_node_t *node, char *line, int level, int len)
{
	char		*start = line + level;

	switch (mms_pn_type(node)) {
	case MMS_PN_CMD:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "</%s>\n", mms_pn_token(node));
		break;
	case MMS_PN_OPS:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "</%s>\n", mms_pn_token(node));
		break;
	case MMS_PN_CLAUSE:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "</%s>\n", mms_pn_token(node));
		break;
	case MMS_PN_RANGE:
		mms_par_indent(line, level);
		(void) snprintf(start, len - level,
		    "</%s>\n", mms_pn_token(node));
		break;
	case MMS_PN_OBJ:
		(void) snprintf(line, len - level, "%s", "/>\n");
		break;
	case MMS_PN_ATTR:
		break;
	case MMS_PN_STRING:
		break;
	case MMS_PN_KEYWORD:
		break;
	case MMS_PN_NUMERIC | MMS_PN_STRING:
		break;
	}
	return (strlen(line));
}

/*
 * mms_pn_build_cmd_xml - convert a node structure to a line of text
 */
char		*
mms_pn_build_cmd_xml(mms_par_node_t *top)
{
	int		len;
	int		off;
	char		*prolog = "<?xml version=\"1.0\"?>\n";
	char		*buf;

	len = mms_pn_cmd_len_xml(top) + strlen(prolog) + 100;

	buf = malloc(len);
	if (buf == NULL) {
		return (NULL);
	}
	off = snprintf(buf, len, "%s", prolog);

	(void) mms_pn_build_cmd_xml_aux(top, buf + off, 0, len);
	return (buf);
}

static int
mms_pn_build_cmd_xml_aux(mms_par_node_t *top, char *line, int level, int size)
{
	mms_par_node_t	*node;
	int		len = 0;

	if (top == NULL)
		return (0);

	line[0] = '\0';

	len += mms_pn_token_start_xml(top, line, level, size);

	mms_list_foreach(&top->pn_arglist, node) {
		len += mms_pn_build_cmd_xml_aux(node, line + len, level + 1,
		    size);
	}
	len += mms_pn_token_end_xml(top, line + len, level, size);
	return (len);
}


char		*
mms_pn_build_cmd_text(mms_par_node_t *top)
{
	int		len = 0;
	char		*line;

	len = mms_pn_cmd_len_text(top);
	line = (char *)malloc(len + 200);
	if (line == NULL) {
		return (NULL);
	}
	line[0] = '\0';

	(void) mms_pn_build_cmd_text_aux(top, line, len);
	return (line);
}

int
mms_pn_build_cmd_text_aux(mms_par_node_t *top, char *line, int size)
{
	int		len;
	mms_par_node_t	*node;

	len = mms_pn_token_start_text(top, line, size);

	mms_list_foreach(&top->pn_arglist, node) {
		if (mms_pn_type(node) == MMS_PN_RANGE &&
		    strcmp(mms_pn_token(node), "..") == 0) {
			mms_par_node_t	*tmp;

			tmp = mms_list_head(&node->pn_arglist);
			len += mms_pn_token_start_text(tmp, line + len, size);
			if (line[len - 1] == ' ') {
				len--;
			}
			len += mms_pn_token_start_text(node, line + len, size);
			tmp = mms_list_next(&node->pn_arglist, tmp);
			len += mms_pn_token_start_text(tmp, line + len, size);
		} else {
			len += mms_pn_build_cmd_text_aux(node, line + len,
			    size);
		}
	}
	len += mms_pn_token_end_text(top, line + len, size);
	return (len);
}

int
mms_pn_cmd_len_text(mms_par_node_t *top)
{
	mms_par_node_t	*node;
	int		len;

	len = mms_pn_len_text(top);
	mms_list_foreach(&top->pn_arglist, node) {
		len += mms_pn_cmd_len_text(node);
	}
	return (len);
}

int
mms_pn_len_text(mms_par_node_t *node)
{
	int		len = 0;

	len = strlen(mms_pn_token(node));
	switch (mms_pn_type(node)) {
	case MMS_PN_CMD:
		len += 2;
		break;
	case MMS_PN_OPS:
		len += 3;
		break;
	case MMS_PN_CLAUSE:
		len += 3;
		break;
	case MMS_PN_OBJ:
		len += 1;
		break;
	case MMS_PN_ATTR:
		len += 4;
		break;
	case MMS_PN_STRING:
		len += 3;
		break;
	case MMS_PN_NUMERIC | MMS_PN_STRING:
		len += 3;
		break;
	case MMS_PN_NULLSTR | MMS_PN_STRING:
		len += 3;
		break;
	case MMS_PN_KEYWORD:
		len += 3;
		break;
	default:
		len += 1;
		break;
	}
	return (len + MMS_FUZZ);
}

static int
mms_pn_token_end_text(mms_par_node_t *node, char *line, int len)
{
	switch (mms_pn_type(node)) {
	case MMS_PN_CMD:
		(void) snprintf(line, len, "%c", ';');
		break;
	case MMS_PN_OPS:
		if (line[-1] == ' ')
			(void) snprintf(line - 1, len, "%c ", ')');
		else
			(void) snprintf(line, len, "%c ", ')');
		break;
	case MMS_PN_CLAUSE:
		if (line[-1] == ' ')
			(void) snprintf(line - 1, len, "%c ", ']');
		else
			(void) snprintf(line, len, "%c ", ']');
		break;
	case MMS_PN_OBJ:
		break;
	case MMS_PN_ATTR:
		break;
	case MMS_PN_STRING:
		break;
	case MMS_PN_KEYWORD:
		break;
	case MMS_PN_NUMERIC | MMS_PN_STRING:
		break;
	case MMS_PN_RANGE:
		break;
	}
	return (strlen(line));
}

static int
mms_pn_token_start_text(mms_par_node_t *node, char *line, int len)
{

	switch (mms_pn_type(node)) {
	case MMS_PN_CMD:
		(void) snprintf(line, len, "%s ", mms_pn_token(node));
		break;
	case MMS_PN_OPS:
		(void) snprintf(line, len, "%s(", mms_pn_token(node));
		break;
	case MMS_PN_CLAUSE:
		(void) snprintf(line, len, "%s[", mms_pn_token(node));
		break;
	case MMS_PN_OBJ:
		(void) snprintf(line, len, "%s ", mms_pn_token(node));
		break;
	case MMS_PN_ATTR:
		/* Back up over blank following object name */
		(void) snprintf(line - 1, len, ".'%s' ", mms_pn_token(node));
		break;
	case MMS_PN_STRING:
		(void) snprintf(line, len, "'%s' ", mms_pn_token(node));
		break;
	case MMS_PN_KEYWORD:
		(void) snprintf(line, len, "%s ", mms_pn_token(node));
		break;
	case MMS_PN_NUMERIC | MMS_PN_STRING:
		(void) snprintf(line, len, "'%s' ", mms_pn_token(node));
		break;
	case MMS_PN_NULLSTR | MMS_PN_STRING:
		(void) snprintf(line, len, "%s", mms_pn_token(node));
		break;
	case MMS_PN_RANGE:
		(void) snprintf(line, len, "%s", mms_pn_token(node));
		break;
	default:
		(void) snprintf(line, len, " ");
		break;
	}
	return (strlen(line));
}

mms_par_node_t *
mms_pn_lookup_arg(mms_par_node_t *top, char *str,
    int type, mms_par_node_t **prev)
{
	mms_par_node_t	*start;

	if (prev == NULL || *prev == NULL) {
		/* first time */
		start = mms_list_head(&top->pn_arglist);
	} else {
		start = mms_list_next(&top->pn_arglist, *prev);
	}

	for (; start != NULL;
	    start = mms_list_next(&top->pn_arglist, start)) {
		if ((str == NULL || str[0] == '\0' ||
		    strcmp(mms_pn_token(start), str) == 0) &&
		    ((type == 0 || (start->pn_type & type)))) {
			/* Found a matching start */
			if (prev != NULL) {
				*prev = start;
			}
			return (start);
		}
	}

	/*
	 * No matching node
	 */
	return (NULL);
}

mms_par_node_t	*
mms_pn_lookup(mms_par_node_t *top, char *str, int type, mms_par_node_t **prev)
{
	mms_par_node_t	*root = top;
	mms_par_node_t	*node = NULL;
	mms_par_node_t	*start = top;
	int		self = 1;

	if (top == NULL) {				/* no tree to lookup */
		return (NULL);
	}

	if (prev != NULL && (*prev) != NULL) {
		start = *prev;
		self = 0;
		root = start->pn_list;
		if (root == NULL) {
			root = start;
		}
	}

	node = mms_pn_lookup_aux(root, start, str, type, self);

	while (root != top && node == NULL) {
		/*
		 * Go up 1 level and get the next node to start
		 */
		start = root;
		root = root->pn_list;
		node = NULL;
		if (start->pn_flags & MMS_PN_ATTR_LIST) {
			node = mms_list_next(&root->pn_attrlist, start);
			if (node == NULL) {
				node = mms_list_head(&root->pn_arglist);
			}
		} else {
			node = mms_list_next(&root->pn_arglist, start);
		}

		if (node == NULL) {
			/*
			 * No more node at this level
			 */
			start = root;
			continue;
		}

		start = node;
		self = 1;
		node = mms_pn_lookup_aux(root, start, str, type, self);
		if (node != NULL) {
			/*
			 * Found a matching node
			 */
			break;
		}
	}

	if (prev != NULL && node != NULL) {
		*prev = node;
	}
	return (node);
}

static mms_par_node_t *
mms_pn_lookup_aux(mms_par_node_t *top, mms_par_node_t *start,
    char *str, int type,
    int self)
{
	mms_par_node_t	*node;
	mms_par_node_t	*result;
	mms_list_t		*list;

	if (top == NULL || start == NULL) {
		return (NULL);
	}

	/*
	 * Start from the start node
	 */
	if (self == 1) {
		/*
		 * Do self check
		 */
		if (type == 0 || (type & mms_pn_type(start))) {
			if (str == NULL || str[0] == '\0' ||
			    strcmp(str, mms_pn_token(start)) == 0) {
				/* found a matching node */
				return (start);
			}
		}
		/*
		 * Already did self check, don't do it again
		 */
		self = 0;
	}

	/*
	 * Check each of the attributes of this node.
	 */
	list = &top->pn_attrlist;
	if (top == start) {
		start = mms_list_head(list);
		/*
		 * Have a new start node, do self check on this one
		 */
		self = 1;
	}
	if (start != NULL && (start->pn_flags & MMS_PN_ATTR_LIST)) {
		for (node = start;
		    node != NULL;
		    node = mms_list_next(list, node)) {
			result = mms_pn_lookup_aux(node, node, str, type,
			    self);
			if (result != NULL) {
				/* found a matching node */
				return (result);
			}
			/*
			 * Do self check from now on
			 */
			self = 1;
		}
		start = NULL;
	}
	/*
	 * Start search of arglist
	 */
	list = &top->pn_arglist;
	if (start == NULL) {
		start = mms_list_head(list);
		/*
		 * Have a new start node, do self check on this one
		 */
		self = 1;
	}
	for (node = start; node != NULL; node = mms_list_next(list, node)) {
		result = mms_pn_lookup_aux(node, node, str, type, self);
		if (result != NULL) {
			/* found a matching node */
			return (result);
		}
		/*
		 * Do self check from now on
		 */
		self = 1;
	}

	/*
	 * Can't find a matching node.
	 */
	return (NULL);
}

mms_sym_t		*
mms_par_lookup_sym(char *mms_sym, mms_pw_t *wka)
{
	mms_sym_t		*syment;

	if (wka->par_wka_flags & MMS_PW_DEPEND) {
		wka->par_wka_flags &= ~MMS_PW_DEPEND;
		/*
		 * Look in parser dependent table first
		 */
		syment = mms_lookup_sym_token(mms_sym,
		    wka->par_wka_symtab_depend,
		    wka->par_wka_num_syms_depend);
		if (syment != NULL) {
			return (syment);
		}
		syment = mms_lookup_sym_token(mms_sym, wka->par_wka_symtab,
		    wka->par_wka_num_syms);
		if (syment != NULL) {
			return (syment);
		}
	} else {
		syment = mms_lookup_sym_token(mms_sym, wka->par_wka_symtab,
		    wka->par_wka_num_syms);
		if (syment != NULL) {
			return (syment);
		}
		syment = mms_lookup_sym_token(mms_sym,
		    wka->par_wka_symtab_depend,
		    wka->par_wka_num_syms_depend);
		if (syment != NULL) {
			return (syment);
		}
	}
	return (NULL);
}

char		*
mms_par_char_to_xml_escape(char *src)
{
	int		out_incr;
	int		out_len;
	int		out_off;
	char		*out;
	int		in_len;
	int		in_off;
	char		*in;
	int		esc_len;
	int		i;

	in = src;
	in_len = strlen(in);
	in_off = 0;

	out_len = strlen(in) * 2;	/* get more space */
	out_off = 0;
	out = malloc(out_len + 1);
	if (out == NULL) {	/* can't get out buffer */
		return (NULL);
	}
	for (in_off = 0, out_off = 0;
	    in_off < in_len;
	    in_off++, out_off += out_incr) {
		out_incr = 1;
		for (i = 0; i < mms_num_esseq; i++) {
			if (in[in_off] == mms_esseq[i].es_char[0]) {
				esc_len = mms_esseq[i].es_len;
				break;
			}
		}

		if (i == mms_num_esseq) {
			/* No need to mms_escape */
			out[out_off] = in[in_off];
		} else {
			/* mms_escape this char */
			while ((out_len - out_off) <
			    (in_len - in_off - 1 + esc_len)) {
				/*
				 * If output buf cannot hold the remaining
				 * input and the escapeext length, then
				 * get more space
				 */
				char		*new;
				char		new_len = out_len * 2;

				new = realloc(out, new_len);
				if (new == NULL) {
					free(out);
					return (NULL);
				}
				free(out);
				out = new;
				out_len = new_len;
			}
			(void) strcpy(out + out_off, mms_esseq[i].es_seq);
			out_incr = esc_len;
		}
	}
	out[out_off] = '\0';
	return (out);
}

char		*
mms_par_xml_escape_to_char(char *src)
{
	int		out_len;
	int		out_off;
	char		*out;
	int		in_incr;
	int		in_len;
	int		in_off;
	char		*in;
	int		esc_len;
	int		i;

	in = src;
	in_len = strlen(in);
	in_off = 0;

	out_len = strlen(in) * 2;	/* get more space */
	out_off = 0;
	out = malloc(out_len + 1);
	if (out == NULL) {	/* can't get out buffer */
		return (NULL);
	}
	for (in_off = 0, out_off = 0;
	    in_off < in_len;
	    in_off += in_incr, out_off++) {
		in_incr = 1;
		for (i = 0; i < mms_num_esseq; i++) {
			esc_len = mms_esseq[i].es_len;
			if (strncmp(in + in_off, mms_esseq[i].es_seq, esc_len)
			    == 0) {
				break;
			}
		}

		if (i == mms_num_esseq) {
			/* No need to mms_escape */
			out[out_off] = in[in_off];
		} else {
			/* found an mms_escape sequence */
			out[out_off] = mms_esseq[i].es_char[0];
			in_incr = esc_len;
		}
	}
	out[out_off] = '\0';
	return (out);
}

void
mms_par_error(mms_pw_t *wka, char *msg)
{
	mms_par_err_t	*err;
	char		msgtext[500];

	/*
	 * Do this only once.
	 */
	wka->par_wka_err_count++;
	err = (mms_par_err_t *)malloc(sizeof (mms_par_err_t));
	if (err == NULL) {
		if (wka->par_wka_error == 0) {
			wka->par_wka_error = MMS_PE_NOMEM;
			return;
		}
	}
	(void) memset(err, 0, sizeof (mms_par_err_t));
	err->pe_line = wka->par_wka_line;
	err->pe_col = wka->par_wka_col;
	err->pe_token = strdup(wka->par_wka_token
	    [(wka->par_wka_token_index - 1) % 2]);
	(void) snprintf(msgtext, sizeof (msgtext),
	    "%s: %s", wka->par_wka_parser, msg);
	err->pe_msg = strdup(msgtext);
	mms_par_list_insert_tail(wka->par_wka_err_list, err);
	if (wka->par_wka_error == 0) {
		wka->par_wka_error = MMS_PE_SYNTAX;
	}
	err->pe_code = wka->par_wka_error;
}

void
mms_pn_fini(mms_par_node_t *root)
{
	if (root != NULL) {
		root->pn_list = NULL;
		mms_pn_fini_aux(root);
	}
}

void
mms_pn_fini_aux(mms_par_node_t *list)
{
	mms_par_node_t	*node;

	/*
	 * Check each of the attributes of this node.
	 */
	mms_list_foreach(&list->pn_attrlist, node) {
		node->pn_list = list;
		node->pn_flags |= MMS_PN_ATTR_LIST;
		mms_pn_fini_aux(node);
	}

	/*
	 * Check each of the arguements of this node.
	 */
	mms_list_foreach(&list->pn_arglist, node) {
		node->pn_list = list;
		node->pn_flags |= MMS_PN_ARG_LIST;
		mms_pn_fini_aux(node);
	}
}
