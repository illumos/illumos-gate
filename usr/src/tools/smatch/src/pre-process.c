/*
 * Do C preprocessing, based on a token list gathered by
 * the tokenizer.
 *
 * This may not be the smartest preprocessor on the planet.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003-2004 Linus Torvalds
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>

#include "lib.h"
#include "allocate.h"
#include "parse.h"
#include "token.h"
#include "symbol.h"
#include "expression.h"
#include "scope.h"

static struct ident_list *macros;	// only needed for -dD
static int false_nesting = 0;
static int counter_macro = 0;		// __COUNTER__ expansion
static int include_level = 0;

#define INCLUDEPATHS 300
const char *includepath[INCLUDEPATHS+1] = {
	"",
	"/usr/include",
	"/usr/local/include",
	NULL
};

static const char **quote_includepath = includepath;
static const char **angle_includepath = includepath + 1;
static const char **isys_includepath   = includepath + 1;
static const char **sys_includepath   = includepath + 1;
static const char **dirafter_includepath = includepath + 3;

#define dirty_stream(stream)				\
	do {						\
		if (!stream->dirty) {			\
			stream->dirty = 1;		\
			if (!stream->ifndef)		\
				stream->protect = NULL;	\
		}					\
	} while(0)

#define end_group(stream)					\
	do {							\
		if (stream->ifndef == stream->top_if) {		\
			stream->ifndef = NULL;			\
			if (!stream->dirty)			\
				stream->protect = NULL;		\
			else if (stream->protect)		\
				stream->dirty = 0;		\
		}						\
	} while(0)

#define nesting_error(stream)		\
	do {				\
		stream->dirty = 1;	\
		stream->ifndef = NULL;	\
		stream->protect = NULL;	\
	} while(0)

static struct token *alloc_token(struct position *pos)
{
	struct token *token = __alloc_token(0);

	token->pos.stream = pos->stream;
	token->pos.line = pos->line;
	token->pos.pos = pos->pos;
	token->pos.whitespace = 1;
	return token;
}

/* Expand symbol 'sym' at '*list' */
static int expand(struct token **, struct symbol *);

static void replace_with_string(struct token *token, const char *str)
{
	int size = strlen(str) + 1;
	struct string *s = __alloc_string(size);

	s->length = size;
	memcpy(s->data, str, size);
	token_type(token) = TOKEN_STRING;
	token->string = s;
}

static void replace_with_integer(struct token *token, unsigned int val)
{
	char *buf = __alloc_bytes(11);
	sprintf(buf, "%u", val);
	token_type(token) = TOKEN_NUMBER;
	token->number = buf;
}

static struct symbol *lookup_macro(struct ident *ident)
{
	struct symbol *sym = lookup_symbol(ident, NS_MACRO | NS_UNDEF);
	if (sym && sym->namespace != NS_MACRO)
		sym = NULL;
	return sym;
}

static int token_defined(struct token *token)
{
	if (token_type(token) == TOKEN_IDENT) {
		struct symbol *sym = lookup_macro(token->ident);
		if (sym) {
			sym->used_in = file_scope;
			return 1;
		}
		return 0;
	}

	sparse_error(token->pos, "expected preprocessor identifier");
	return 0;
}

static void replace_with_bool(struct token *token, bool val)
{
	static const char *string[] = { "0", "1" };

	token_type(token) = TOKEN_NUMBER;
	token->number = string[val];
}

static void replace_with_defined(struct token *token)
{
	replace_with_bool(token, token_defined(token));
}

static void replace_with_has_builtin(struct token *token)
{
	struct symbol *sym = lookup_symbol(token->ident, NS_SYMBOL);
	replace_with_bool(token, sym && sym->builtin);
}

static void replace_with_has_attribute(struct token *token)
{
	struct symbol *sym = lookup_symbol(token->ident, NS_KEYWORD);
	replace_with_bool(token, sym && sym->op && sym->op->attribute);
}

static void expand_line(struct token *token)
{
	replace_with_integer(token, token->pos.line);
}

static void expand_file(struct token *token)
{
	replace_with_string(token, stream_name(token->pos.stream));
}

static void expand_basefile(struct token *token)
{
	replace_with_string(token, base_filename);
}

static time_t t = 0;
static void expand_date(struct token *token)
{
	static char buffer[12]; /* __DATE__: 3 + ' ' + 2 + ' ' + 4 + '\0' */

	if (!t)
		time(&t);
	strftime(buffer, 12, "%b %e %Y", localtime(&t));
	replace_with_string(token, buffer);
}

static void expand_time(struct token *token)
{
	static char buffer[9]; /* __TIME__: 2 + ':' + 2 + ':' + 2 + '\0' */

	if (!t)
		time(&t);
	strftime(buffer, 9, "%T", localtime(&t));
	replace_with_string(token, buffer);
}

static void expand_counter(struct token *token)
{
	replace_with_integer(token, counter_macro++);
}

static void expand_include_level(struct token *token)
{
	replace_with_integer(token, include_level - 1);
}

static int expand_one_symbol(struct token **list)
{
	struct token *token = *list;
	struct symbol *sym;

	if (token->pos.noexpand)
		return 1;

	sym = lookup_macro(token->ident);
	if (!sym)
		return 1;
	store_macro_pos(token);
	if (sym->expander) {
		sym->expander(token);
		return 1;
	} else {
		sym->used_in = file_scope;
		return expand(list, sym);
	}
}

static inline struct token *scan_next(struct token **where)
{
	struct token *token = *where;
	if (token_type(token) != TOKEN_UNTAINT)
		return token;
	do {
		token->ident->tainted = 0;
		token = token->next;
	} while (token_type(token) == TOKEN_UNTAINT);
	*where = token;
	return token;
}

static void expand_list(struct token **list)
{
	struct token *next;
	while (!eof_token(next = scan_next(list))) {
		if (token_type(next) != TOKEN_IDENT || expand_one_symbol(list))
			list = &next->next;
	}
}

static void preprocessor_line(struct stream *stream, struct token **line);

static struct token *collect_arg(struct token *prev, int vararg, struct position *pos, int count)
{
	struct stream *stream = input_streams + prev->pos.stream;
	struct token **p = &prev->next;
	struct token *next;
	int nesting = 0;

	while (!eof_token(next = scan_next(p))) {
		if (next->pos.newline && match_op(next, '#')) {
			if (!next->pos.noexpand) {
				sparse_error(next->pos,
					     "directive in argument list");
				preprocessor_line(stream, p);
				__free_token(next);	/* Free the '#' token */
				continue;
			}
		}
		switch (token_type(next)) {
		case TOKEN_STREAMEND:
		case TOKEN_STREAMBEGIN:
			*p = &eof_token_entry;
			return next;
		case TOKEN_STRING:
		case TOKEN_WIDE_STRING:
			if (count > 1)
				next->string->immutable = 1;
			break;
		}
		if (false_nesting) {
			*p = next->next;
			__free_token(next);
			continue;
		}
		if (match_op(next, '(')) {
			nesting++;
		} else if (match_op(next, ')')) {
			if (!nesting--)
				break;
		} else if (match_op(next, ',') && !nesting && !vararg) {
			break;
		}
		next->pos.stream = pos->stream;
		next->pos.line = pos->line;
		next->pos.pos = pos->pos;
		p = &next->next;
	}
	*p = &eof_token_entry;
	return next;
}

/*
 * We store arglist as <counter> [arg1] <number of uses for arg1> ... eof
 */

struct arg {
	struct token *arg;
	struct token *expanded;
	struct token *str;
	int n_normal;
	int n_quoted;
	int n_str;
};

static int collect_arguments(struct token *start, struct token *arglist, struct arg *args, struct token *what)
{
	int wanted = arglist->count.normal;
	struct token *next = NULL;
	int count = 0;

	arglist = arglist->next;	/* skip counter */

	if (!wanted) {
		next = collect_arg(start, 0, &what->pos, 0);
		if (eof_token(next))
			goto Eclosing;
		if (!eof_token(start->next) || !match_op(next, ')')) {
			count++;
			goto Emany;
		}
	} else {
		for (count = 0; count < wanted; count++) {
			struct argcount *p = &arglist->next->count;
			next = collect_arg(start, p->vararg, &what->pos, p->normal);
			if (eof_token(next))
				goto Eclosing;
			if (p->vararg && wanted == 1 && eof_token(start->next))
				break;
			arglist = arglist->next->next;
			args[count].arg = start->next;
			args[count].n_normal = p->normal;
			args[count].n_quoted = p->quoted;
			args[count].n_str = p->str;
			if (match_op(next, ')')) {
				count++;
				break;
			}
			start = next;
		}
		if (count == wanted && !match_op(next, ')'))
			goto Emany;
		if (count == wanted - 1) {
			struct argcount *p = &arglist->next->count;
			if (!p->vararg)
				goto Efew;
			args[count].arg = NULL;
			args[count].n_normal = p->normal;
			args[count].n_quoted = p->quoted;
			args[count].n_str = p->str;
		}
		if (count < wanted - 1)
			goto Efew;
	}
	what->next = next->next;
	return 1;

Efew:
	sparse_error(what->pos, "macro \"%s\" requires %d arguments, but only %d given",
		show_token(what), wanted, count);
	goto out;
Emany:
	while (match_op(next, ',')) {
		next = collect_arg(next, 0, &what->pos, 0);
		count++;
	}
	if (eof_token(next))
		goto Eclosing;
	sparse_error(what->pos, "macro \"%s\" passed %d arguments, but takes just %d",
		show_token(what), count, wanted);
	goto out;
Eclosing:
	sparse_error(what->pos, "unterminated argument list invoking macro \"%s\"",
		show_token(what));
out:
	what->next = next->next;
	return 0;
}

static struct token *dup_list(struct token *list)
{
	struct token *res = NULL;
	struct token **p = &res;

	while (!eof_token(list)) {
		struct token *newtok = __alloc_token(0);
		*newtok = *list;
		*p = newtok;
		p = &newtok->next;
		list = list->next;
	}
	return res;
}

static const char *show_token_sequence(struct token *token, int quote)
{
	static char buffer[MAX_STRING];
	char *ptr = buffer;
	int whitespace = 0;

	if (!token && !quote)
		return "<none>";
	while (!eof_token(token)) {
		const char *val = quote ? quote_token(token) : show_token(token);
		int len = strlen(val);

		if (ptr + whitespace + len >= buffer + sizeof(buffer)) {
			sparse_error(token->pos, "too long token expansion");
			break;
		}

		if (whitespace)
			*ptr++ = ' ';
		memcpy(ptr, val, len);
		ptr += len;
		token = token->next;
		whitespace = token->pos.whitespace;
	}
	*ptr = 0;
	return buffer;
}

static struct token *stringify(struct token *arg)
{
	const char *s = show_token_sequence(arg, 1);
	int size = strlen(s)+1;
	struct token *token = __alloc_token(0);
	struct string *string = __alloc_string(size);

	memcpy(string->data, s, size);
	string->length = size;
	token->pos = arg->pos;
	token_type(token) = TOKEN_STRING;
	token->string = string;
	token->next = &eof_token_entry;
	return token;
}

static void expand_arguments(int count, struct arg *args)
{
	int i;
	for (i = 0; i < count; i++) {
		struct token *arg = args[i].arg;
		if (!arg)
			arg = &eof_token_entry;
		if (args[i].n_str)
			args[i].str = stringify(arg);
		if (args[i].n_normal) {
			if (!args[i].n_quoted) {
				args[i].expanded = arg;
				args[i].arg = NULL;
			} else if (eof_token(arg)) {
				args[i].expanded = arg;
			} else {
				args[i].expanded = dup_list(arg);
			}
			expand_list(&args[i].expanded);
		}
	}
}

/*
 * Possibly valid combinations:
 *  - ident + ident -> ident
 *  - ident + number -> ident unless number contains '.', '+' or '-'.
 *  - 'L' + char constant -> wide char constant
 *  - 'L' + string literal -> wide string literal
 *  - number + number -> number
 *  - number + ident -> number
 *  - number + '.' -> number
 *  - number + '+' or '-' -> number, if number used to end on [eEpP].
 *  - '.' + number -> number, if number used to start with a digit.
 *  - special + special -> either special or an error.
 */
static enum token_type combine(struct token *left, struct token *right, char *p)
{
	int len;
	enum token_type t1 = token_type(left), t2 = token_type(right);

	if (t1 != TOKEN_IDENT && t1 != TOKEN_NUMBER && t1 != TOKEN_SPECIAL)
		return TOKEN_ERROR;

	if (t1 == TOKEN_IDENT && left->ident == &L_ident) {
		if (t2 >= TOKEN_CHAR && t2 < TOKEN_WIDE_CHAR)
			return t2 + TOKEN_WIDE_CHAR - TOKEN_CHAR;
		if (t2 == TOKEN_STRING)
			return TOKEN_WIDE_STRING;
	}

	if (t2 != TOKEN_IDENT && t2 != TOKEN_NUMBER && t2 != TOKEN_SPECIAL)
		return TOKEN_ERROR;

	strcpy(p, show_token(left));
	strcat(p, show_token(right));
	len = strlen(p);

	if (len >= 256)
		return TOKEN_ERROR;

	if (t1 == TOKEN_IDENT) {
		if (t2 == TOKEN_SPECIAL)
			return TOKEN_ERROR;
		if (t2 == TOKEN_NUMBER && strpbrk(p, "+-."))
			return TOKEN_ERROR;
		return TOKEN_IDENT;
	}

	if (t1 == TOKEN_NUMBER) {
		if (t2 == TOKEN_SPECIAL) {
			switch (right->special) {
			case '.':
				break;
			case '+': case '-':
				if (strchr("eEpP", p[len - 2]))
					break;
			default:
				return TOKEN_ERROR;
			}
		}
		return TOKEN_NUMBER;
	}

	if (p[0] == '.' && isdigit((unsigned char)p[1]))
		return TOKEN_NUMBER;

	return TOKEN_SPECIAL;
}

static int merge(struct token *left, struct token *right)
{
	static char buffer[512];
	enum token_type res = combine(left, right, buffer);
	int n;

	switch (res) {
	case TOKEN_IDENT:
		left->ident = built_in_ident(buffer);
		left->pos.noexpand = 0;
		return 1;

	case TOKEN_NUMBER:
		token_type(left) = TOKEN_NUMBER;	/* could be . + num */
		left->number = xstrdup(buffer);
		return 1;

	case TOKEN_SPECIAL:
		if (buffer[2] && buffer[3])
			break;
		for (n = SPECIAL_BASE; n < SPECIAL_ARG_SEPARATOR; n++) {
			if (!memcmp(buffer, combinations[n-SPECIAL_BASE], 3)) {
				left->special = n;
				return 1;
			}
		}
		break;

	case TOKEN_WIDE_CHAR:
	case TOKEN_WIDE_STRING:
		token_type(left) = res;
		left->pos.noexpand = 0;
		left->string = right->string;
		return 1;

	case TOKEN_WIDE_CHAR_EMBEDDED_0 ... TOKEN_WIDE_CHAR_EMBEDDED_3:
		token_type(left) = res;
		left->pos.noexpand = 0;
		memcpy(left->embedded, right->embedded, 4);
		return 1;

	default:
		;
	}
	sparse_error(left->pos, "'##' failed: concatenation is not a valid token");
	return 0;
}

static struct token *dup_token(struct token *token, struct position *streampos)
{
	struct token *alloc = alloc_token(streampos);
	token_type(alloc) = token_type(token);
	alloc->pos.newline = token->pos.newline;
	alloc->pos.whitespace = token->pos.whitespace;
	alloc->number = token->number;
	alloc->pos.noexpand = token->pos.noexpand;
	return alloc;	
}

static struct token **copy(struct token **where, struct token *list, int *count)
{
	int need_copy = --*count;
	while (!eof_token(list)) {
		struct token *token;
		if (need_copy)
			token = dup_token(list, &list->pos);
		else
			token = list;
		if (token_type(token) == TOKEN_IDENT && token->ident->tainted)
			token->pos.noexpand = 1;
		*where = token;
		where = &token->next;
		list = list->next;
	}
	*where = &eof_token_entry;
	return where;
}

static int handle_kludge(struct token **p, struct arg *args)
{
	struct token *t = (*p)->next->next;
	while (1) {
		struct arg *v = &args[t->argnum];
		if (token_type(t->next) != TOKEN_CONCAT) {
			if (v->arg) {
				/* ignore the first ## */
				*p = (*p)->next;
				return 0;
			}
			/* skip the entire thing */
			*p = t;
			return 1;
		}
		if (v->arg && !eof_token(v->arg))
			return 0; /* no magic */
		t = t->next->next;
	}
}

static struct token **substitute(struct token **list, struct token *body, struct arg *args)
{
	struct position *base_pos = &(*list)->pos;
	int *count;
	enum {Normal, Placeholder, Concat} state = Normal;

	for (; !eof_token(body); body = body->next) {
		struct token *added, *arg;
		struct token **tail;
		struct token *t;

		switch (token_type(body)) {
		case TOKEN_GNU_KLUDGE:
			/*
			 * GNU kludge: if we had <comma>##<vararg>, behaviour
			 * depends on whether we had enough arguments to have
			 * a vararg.  If we did, ## is just ignored.  Otherwise
			 * both , and ## are ignored.  Worse, there can be
			 * an arbitrary number of ##<arg> in between; if all of
			 * those are empty, we act as if they hadn't been there,
			 * otherwise we act as if the kludge didn't exist.
			 */
			t = body;
			if (handle_kludge(&body, args)) {
				if (state == Concat)
					state = Normal;
				else
					state = Placeholder;
				continue;
			}
			added = dup_token(t, base_pos);
			token_type(added) = TOKEN_SPECIAL;
			tail = &added->next;
			break;

		case TOKEN_STR_ARGUMENT:
			arg = args[body->argnum].str;
			count = &args[body->argnum].n_str;
			goto copy_arg;

		case TOKEN_QUOTED_ARGUMENT:
			arg = args[body->argnum].arg;
			count = &args[body->argnum].n_quoted;
			if (!arg || eof_token(arg)) {
				if (state == Concat)
					state = Normal;
				else
					state = Placeholder;
				continue;
			}
			goto copy_arg;

		case TOKEN_MACRO_ARGUMENT:
			arg = args[body->argnum].expanded;
			count = &args[body->argnum].n_normal;
			if (eof_token(arg)) {
				state = Normal;
				continue;
			}
		copy_arg:
			tail = copy(&added, arg, count);
			added->pos.newline = body->pos.newline;
			added->pos.whitespace = body->pos.whitespace;
			break;

		case TOKEN_CONCAT:
			if (state == Placeholder)
				state = Normal;
			else
				state = Concat;
			continue;

		case TOKEN_IDENT:
			added = dup_token(body, base_pos);
			if (added->ident->tainted)
				added->pos.noexpand = 1;
			tail = &added->next;
			break;

		default:
			added = dup_token(body, base_pos);
			tail = &added->next;
			break;
		}

		/*
		 * if we got to doing real concatenation, we already have
		 * added something into the list, so containing_token() is OK.
		 */
		if (state == Concat && merge(containing_token(list), added)) {
			*list = added->next;
			if (tail != &added->next)
				list = tail;
		} else {
			*list = added;
			list = tail;
		}
		state = Normal;
	}
	*list = &eof_token_entry;
	return list;
}

static int expand(struct token **list, struct symbol *sym)
{
	struct token *last;
	struct token *token = *list;
	struct ident *expanding = token->ident;
	struct token **tail;
	int nargs = sym->arglist ? sym->arglist->count.normal : 0;
	struct arg args[nargs];

	if (expanding->tainted) {
		token->pos.noexpand = 1;
		return 1;
	}

	if (sym->arglist) {
		if (!match_op(scan_next(&token->next), '('))
			return 1;
		if (!collect_arguments(token->next, sym->arglist, args, token))
			return 1;
		expand_arguments(nargs, args);
	}

	expanding->tainted = 1;

	last = token->next;
	tail = substitute(list, sym->expansion, args);
	/*
	 * Note that it won't be eof - at least TOKEN_UNTAINT will be there.
	 * We still can lose the newline flag if the sucker expands to nothing,
	 * but the price of dealing with that is probably too high (we'd need
	 * to collect the flags during scan_next())
	 */
	(*list)->pos.newline = token->pos.newline;
	(*list)->pos.whitespace = token->pos.whitespace;
	*tail = last;

	return 0;
}

static const char *token_name_sequence(struct token *token, int endop, struct token *start)
{
	static char buffer[256];
	char *ptr = buffer;

	while (!eof_token(token) && !match_op(token, endop)) {
		int len;
		const char *val = token->string->data;
		if (token_type(token) != TOKEN_STRING)
			val = show_token(token);
		len = strlen(val);
		memcpy(ptr, val, len);
		ptr += len;
		token = token->next;
	}
	*ptr = 0;
	if (endop && !match_op(token, endop))
		sparse_error(start->pos, "expected '>' at end of filename");
	return buffer;
}

static int already_tokenized(const char *path)
{
	int stream, next;

	for (stream = *hash_stream(path); stream >= 0 ; stream = next) {
		struct stream *s = input_streams + stream;

		next = s->next_stream;
		if (s->once) {
			if (strcmp(path, s->name))
				continue;
			return 1;
		}
		if (s->constant != CONSTANT_FILE_YES)
			continue;
		if (strcmp(path, s->name))
			continue;
		if (s->protect && !lookup_macro(s->protect))
			continue;
		return 1;
	}
	return 0;
}

/* Handle include of header files.
 * The relevant options are made compatible with gcc. The only options that
 * are not supported is -withprefix and friends.
 *
 * Three set of include paths are known:
 * quote_includepath:	Path to search when using #include "file.h"
 * angle_includepath:	Paths to search when using #include <file.h>
 * isys_includepath:	Paths specified with -isystem, come before the
 *			built-in system include paths. Gcc would suppress
 *			warnings from system headers. Here we separate
 *			them from the angle_ ones to keep search ordering.
 *
 * sys_includepath:	Built-in include paths.
 * dirafter_includepath Paths added with -dirafter.
 *
 * The above is implemented as one array with pointers
 *                         +--------------+
 * quote_includepath --->  |              |
 *                         +--------------+
 *                         |              |
 *                         +--------------+
 * angle_includepath --->  |              |
 *                         +--------------+
 * isys_includepath  --->  |              |
 *                         +--------------+
 * sys_includepath   --->  |              |
 *                         +--------------+
 * dirafter_includepath -> |              |
 *                         +--------------+
 *
 * -I dir insert dir just before isys_includepath and move the rest
 * -I- makes all dirs specified with -I before to quote dirs only and
 *   angle_includepath is set equal to isys_includepath.
 * -nostdinc removes all sys dirs by storing NULL in entry pointed
 *   to by * sys_includepath. Note that this will reset all dirs built-in
 *   and added before -nostdinc by -isystem and -idirafter.
 * -isystem dir adds dir where isys_includepath points adding this dir as
 *   first systemdir
 * -idirafter dir adds dir to the end of the list
 */

static void set_stream_include_path(struct stream *stream)
{
	const char *path = stream->path;
	if (!path) {
		const char *p = strrchr(stream->name, '/');
		path = "";
		if (p) {
			int len = p - stream->name + 1;
			char *m = malloc(len+1);
			/* This includes the final "/" */
			memcpy(m, stream->name, len);
			m[len] = 0;
			path = m;
		}
		stream->path = path;
	}
	includepath[0] = path;
}

#ifndef PATH_MAX
#define PATH_MAX 4096	// for Hurd where it's not defined
#endif

static int try_include(const char *path, const char *filename, int flen, struct token **where, const char **next_path)
{
	int fd;
	int plen = strlen(path);
	static char fullname[PATH_MAX];

	memcpy(fullname, path, plen);
	if (plen && path[plen-1] != '/') {
		fullname[plen] = '/';
		plen++;
	}
	memcpy(fullname+plen, filename, flen);
	if (already_tokenized(fullname))
		return 1;
	fd = open(fullname, O_RDONLY);
	if (fd >= 0) {
		char *streamname = xmemdup(fullname, plen + flen);
		*where = tokenize(streamname, fd, *where, next_path);
		close(fd);
		return 1;
	}
	return 0;
}

static int do_include_path(const char **pptr, struct token **list, struct token *token, const char *filename, int flen)
{
	const char *path;

	while ((path = *pptr++) != NULL) {
		if (!try_include(path, filename, flen, list, pptr))
			continue;
		return 1;
	}
	return 0;
}

static int free_preprocessor_line(struct token *token)
{
	while (token_type(token) != TOKEN_EOF) {
		struct token *free = token;
		token = token->next;
		__free_token(free);
	};
	return 1;
}

const char *find_include(const char *skip, const char *look_for)
{
	DIR *dp;
	struct dirent *entry;
	struct stat statbuf;
	const char *ret;
	char cwd[PATH_MAX];
	static char buf[PATH_MAX + 1];

	dp = opendir(".");
	if (!dp)
		return NULL;

	if (!getcwd(cwd, sizeof(cwd)))
		goto close;

	while ((entry = readdir(dp))) {
		lstat(entry->d_name, &statbuf);

		if (strcmp(entry->d_name, look_for) == 0) {
			snprintf(buf, sizeof(buf), "%s/%s", cwd, entry->d_name);
			closedir(dp);
			return buf;
		}

		if (S_ISDIR(statbuf.st_mode)) {
			/* Found a directory, but ignore . and .. */
			if (strcmp(".", entry->d_name) == 0 ||
			    strcmp("..", entry->d_name) == 0 ||
			    strcmp(skip, entry->d_name) == 0)
				continue;

			chdir(entry->d_name);
			ret = find_include("", look_for);
			chdir("..");
			if (ret) {
				closedir(dp);
				return ret;
			}
		}
	}
close:
	closedir(dp);

	return NULL;
}

const char *search_dir(const char *stop, const char *look_for)
{
	char cwd[PATH_MAX];
	int len;
	const char *ret;
	int cnt = 0;

	if (!getcwd(cwd, sizeof(cwd)))
		return NULL;

	len = strlen(cwd);
	while (len >= 0) {
		ret = find_include(cnt++ ? cwd + len + 1 : "", look_for);
		if (ret)
			return ret;

		if (strcmp(cwd, stop) == 0 ||
		    strcmp(cwd, "/usr/include") == 0 ||
		    strcmp(cwd, "/usr/local/include") == 0 ||
		    strlen(cwd) <= 10 ||  /* heck...  don't search /usr/lib/ */
		    strcmp(cwd, "/") == 0)
			return NULL;

		while (--len >= 0) {
			if (cwd[len] == '/') {
				cwd[len] = '\0';
				break;
			}
		}

		chdir("..");
	}
	return NULL;
}

static void use_best_guess_header_file(struct token *token, const char *filename, struct token **list)
{
	char cwd[PATH_MAX];
	char dir_part[PATH_MAX];
	const char *file_part;
	const char *include_name;
	static int cnt;
	int len;

	/* Avoid guessing includes recursively. */
	if (cnt++ > 1000)
		return;

	if (!filename || filename[0] == '\0')
		return;

	file_part = filename;
	while ((filename = strchr(filename, '/'))) {
		++filename;
		if (filename[0])
			file_part = filename;
	}

	snprintf(dir_part, sizeof(dir_part), "%s", stream_name(token->pos.stream));
	len = strlen(dir_part);
	while (--len >= 0) {
		if (dir_part[len] == '/') {
			dir_part[len] = '\0';
			break;
		}
	}
	if (len < 0)
		sprintf(dir_part, ".");

	if (!getcwd(cwd, sizeof(cwd)))
		return;

	chdir(dir_part);
	include_name = search_dir(cwd, file_part);
	chdir(cwd);
	if (!include_name)
		return;
	sparse_error(token->pos, "using '%s'", include_name);

	try_include("", include_name, strlen(include_name), list, includepath);
}

static int handle_include_path(struct stream *stream, struct token **list, struct token *token, int how)
{
	const char *filename;
	struct token *next;
	const char **path;
	int expect;
	int flen;

	next = token->next;
	expect = '>';
	if (!match_op(next, '<')) {
		expand_list(&token->next);
		expect = 0;
		next = token;
		if (match_op(token->next, '<')) {
			next = token->next;
			expect = '>';
		}
	}

	token = next->next;
	filename = token_name_sequence(token, expect, token);
	flen = strlen(filename) + 1;

	/* Absolute path? */
	if (filename[0] == '/') {
		if (try_include("", filename, flen, list, includepath))
			return 0;
		goto out;
	}

	switch (how) {
	case 1:
		path = stream->next_path;
		break;
	case 2:
		includepath[0] = "";
		path = includepath;
		break;
	default:
		/* Dir of input file is first dir to search for quoted includes */
		set_stream_include_path(stream);
		path = expect ? angle_includepath : quote_includepath;
		break;
	}
	/* Check the standard include paths.. */
	if (do_include_path(path, list, token, filename, flen))
		return 0;
out:
	sparse_error(token->pos, "unable to open '%s'", filename);
	use_best_guess_header_file(token, filename, list);
	return 0;
}

static int handle_include(struct stream *stream, struct token **list, struct token *token)
{
	return handle_include_path(stream, list, token, 0);
}

static int handle_include_next(struct stream *stream, struct token **list, struct token *token)
{
	return handle_include_path(stream, list, token, 1);
}

static int handle_argv_include(struct stream *stream, struct token **list, struct token *token)
{
	return handle_include_path(stream, list, token, 2);
}

static int token_different(struct token *t1, struct token *t2)
{
	int different;

	if (token_type(t1) != token_type(t2))
		return 1;

	switch (token_type(t1)) {
	case TOKEN_IDENT:
		different = t1->ident != t2->ident;
		break;
	case TOKEN_ARG_COUNT:
	case TOKEN_UNTAINT:
	case TOKEN_CONCAT:
	case TOKEN_GNU_KLUDGE:
		different = 0;
		break;
	case TOKEN_NUMBER:
		different = strcmp(t1->number, t2->number);
		break;
	case TOKEN_SPECIAL:
		different = t1->special != t2->special;
		break;
	case TOKEN_MACRO_ARGUMENT:
	case TOKEN_QUOTED_ARGUMENT:
	case TOKEN_STR_ARGUMENT:
		different = t1->argnum != t2->argnum;
		break;
	case TOKEN_CHAR_EMBEDDED_0 ... TOKEN_CHAR_EMBEDDED_3:
	case TOKEN_WIDE_CHAR_EMBEDDED_0 ... TOKEN_WIDE_CHAR_EMBEDDED_3:
		different = memcmp(t1->embedded, t2->embedded, 4);
		break;
	case TOKEN_CHAR:
	case TOKEN_WIDE_CHAR:
	case TOKEN_STRING:
	case TOKEN_WIDE_STRING: {
		struct string *s1, *s2;

		s1 = t1->string;
		s2 = t2->string;
		different = 1;
		if (s1->length != s2->length)
			break;
		different = memcmp(s1->data, s2->data, s1->length);
		break;
	}
	default:
		different = 1;
		break;
	}
	return different;
}

static int token_list_different(struct token *list1, struct token *list2)
{
	for (;;) {
		if (list1 == list2)
			return 0;
		if (!list1 || !list2)
			return 1;
		if (token_different(list1, list2))
			return 1;
		list1 = list1->next;
		list2 = list2->next;
	}
}

static inline void set_arg_count(struct token *token)
{
	token_type(token) = TOKEN_ARG_COUNT;
	token->count.normal = token->count.quoted =
	token->count.str = token->count.vararg = 0;
}

static struct token *parse_arguments(struct token *list)
{
	struct token *arg = list->next, *next = list;
	struct argcount *count = &list->count;

	set_arg_count(list);

	if (match_op(arg, ')')) {
		next = arg->next;
		list->next = &eof_token_entry;
		return next;
	}

	while (token_type(arg) == TOKEN_IDENT) {
		if (arg->ident == &__VA_ARGS___ident)
			goto Eva_args;
		if (!++count->normal)
			goto Eargs;
		next = arg->next;

		if (match_op(next, ',')) {
			set_arg_count(next);
			arg = next->next;
			continue;
		}

		if (match_op(next, ')')) {
			set_arg_count(next);
			next = next->next;
			arg->next->next = &eof_token_entry;
			return next;
		}

		/* normal cases are finished here */

		if (match_op(next, SPECIAL_ELLIPSIS)) {
			if (match_op(next->next, ')')) {
				set_arg_count(next);
				next->count.vararg = 1;
				next = next->next;
				arg->next->next = &eof_token_entry;
				return next->next;
			}

			arg = next;
			goto Enotclosed;
		}

		if (eof_token(next)) {
			goto Enotclosed;
		} else {
			arg = next;
			goto Ebadstuff;
		}
	}

	if (match_op(arg, SPECIAL_ELLIPSIS)) {
		next = arg->next;
		token_type(arg) = TOKEN_IDENT;
		arg->ident = &__VA_ARGS___ident;
		if (!match_op(next, ')'))
			goto Enotclosed;
		if (!++count->normal)
			goto Eargs;
		set_arg_count(next);
		next->count.vararg = 1;
		next = next->next;
		arg->next->next = &eof_token_entry;
		return next;
	}

	if (eof_token(arg)) {
		arg = next;
		goto Enotclosed;
	}
	if (match_op(arg, ','))
		goto Emissing;
	else
		goto Ebadstuff;


Emissing:
	sparse_error(arg->pos, "parameter name missing");
	return NULL;
Ebadstuff:
	sparse_error(arg->pos, "\"%s\" may not appear in macro parameter list",
		show_token(arg));
	return NULL;
Enotclosed:
	sparse_error(arg->pos, "missing ')' in macro parameter list");
	return NULL;
Eva_args:
	sparse_error(arg->pos, "__VA_ARGS__ can only appear in the expansion of a C99 variadic macro");
	return NULL;
Eargs:
	sparse_error(arg->pos, "too many arguments in macro definition");
	return NULL;
}

static int try_arg(struct token *token, enum token_type type, struct token *arglist)
{
	struct ident *ident = token->ident;
	int nr;

	if (!arglist || token_type(token) != TOKEN_IDENT)
		return 0;

	arglist = arglist->next;

	for (nr = 0; !eof_token(arglist); nr++, arglist = arglist->next->next) {
		if (arglist->ident == ident) {
			struct argcount *count = &arglist->next->count;
			int n;

			token->argnum = nr;
			token_type(token) = type;
			switch (type) {
			case TOKEN_MACRO_ARGUMENT:
				n = ++count->normal;
				break;
			case TOKEN_QUOTED_ARGUMENT:
				n = ++count->quoted;
				break;
			default:
				n = ++count->str;
			}
			if (n)
				return count->vararg ? 2 : 1;
			/*
			 * XXX - need saner handling of that
			 * (>= 1024 instances of argument)
			 */
			token_type(token) = TOKEN_ERROR;
			return -1;
		}
	}
	return 0;
}

static struct token *handle_hash(struct token **p, struct token *arglist)
{
	struct token *token = *p;
	if (arglist) {
		struct token *next = token->next;
		if (!try_arg(next, TOKEN_STR_ARGUMENT, arglist))
			goto Equote;
		next->pos.whitespace = token->pos.whitespace;
		__free_token(token);
		token = *p = next;
	} else {
		token->pos.noexpand = 1;
	}
	return token;

Equote:
	sparse_error(token->pos, "'#' is not followed by a macro parameter");
	return NULL;
}

/* token->next is ## */
static struct token *handle_hashhash(struct token *token, struct token *arglist)
{
	struct token *last = token;
	struct token *concat;
	int state = match_op(token, ',');
	
	try_arg(token, TOKEN_QUOTED_ARGUMENT, arglist);

	while (1) {
		struct token *t;
		int is_arg;

		/* eat duplicate ## */
		concat = token->next;
		while (match_op(t = concat->next, SPECIAL_HASHHASH)) {
			token->next = t;
			__free_token(concat);
			concat = t;
		}
		token_type(concat) = TOKEN_CONCAT;

		if (eof_token(t))
			goto Econcat;

		if (match_op(t, '#')) {
			t = handle_hash(&concat->next, arglist);
			if (!t)
				return NULL;
		}

		is_arg = try_arg(t, TOKEN_QUOTED_ARGUMENT, arglist);

		if (state == 1 && is_arg) {
			state = is_arg;
		} else {
			last = t;
			state = match_op(t, ',');
		}

		token = t;
		if (!match_op(token->next, SPECIAL_HASHHASH))
			break;
	}
	/* handle GNU ,##__VA_ARGS__ kludge, in all its weirdness */
	if (state == 2)
		token_type(last) = TOKEN_GNU_KLUDGE;
	return token;

Econcat:
	sparse_error(concat->pos, "'##' cannot appear at the ends of macro expansion");
	return NULL;
}

static struct token *parse_expansion(struct token *expansion, struct token *arglist, struct ident *name)
{
	struct token *token = expansion;
	struct token **p;

	if (match_op(token, SPECIAL_HASHHASH))
		goto Econcat;

	for (p = &expansion; !eof_token(token); p = &token->next, token = *p) {
		if (match_op(token, '#')) {
			token = handle_hash(p, arglist);
			if (!token)
				return NULL;
		}
		if (match_op(token->next, SPECIAL_HASHHASH)) {
			token = handle_hashhash(token, arglist);
			if (!token)
				return NULL;
		} else {
			try_arg(token, TOKEN_MACRO_ARGUMENT, arglist);
		}
		switch (token_type(token)) {
		case TOKEN_ERROR:
			goto Earg;

		case TOKEN_STRING:
		case TOKEN_WIDE_STRING:
			token->string->immutable = 1;
			break;
		}
	}
	token = alloc_token(&expansion->pos);
	token_type(token) = TOKEN_UNTAINT;
	token->ident = name;
	token->next = *p;
	*p = token;
	return expansion;

Econcat:
	sparse_error(token->pos, "'##' cannot appear at the ends of macro expansion");
	return NULL;
Earg:
	sparse_error(token->pos, "too many instances of argument in body");
	return NULL;
}

static int do_define(struct position pos, struct token *token, struct ident *name,
		     struct token *arglist, struct token *expansion, int attr)
{
	struct symbol *sym;
	int ret = 1;

	expansion = parse_expansion(expansion, arglist, name);
	if (!expansion)
		return 1;

	sym = lookup_symbol(name, NS_MACRO | NS_UNDEF);
	if (sym) {
		int clean;

		if (attr < sym->attr)
			goto out;

		clean = (attr == sym->attr && sym->namespace == NS_MACRO);

		if (token_list_different(sym->expansion, expansion) ||
		    token_list_different(sym->arglist, arglist)) {
			ret = 0;
			if ((clean && attr == SYM_ATTR_NORMAL)
					|| sym->used_in == file_scope) {
				warning(pos, "preprocessor token %.*s redefined",
						name->len, name->name);
				info(sym->pos, "this was the original definition");
			}
		} else if (clean)
			goto out;
	}

	if (!sym || sym->scope != file_scope) {
		sym = alloc_symbol(pos, SYM_NODE);
		bind_symbol(sym, name, NS_MACRO);
		add_ident(&macros, name);
		ret = 0;
	}

	if (!ret) {
		sym->expansion = expansion;
		sym->arglist = arglist;
		if (token) /* Free the "define" token, but not the rest of the line */
			__free_token(token);
	}

	sym->namespace = NS_MACRO;
	sym->used_in = NULL;
	sym->attr = attr;
out:
	return ret;
}

///
// predefine a macro with a printf-formatted value
// @name: the name of the macro
// @weak: 0/1 for a normal or a weak define
// @fmt: the printf format followed by it's arguments.
//
// The type of the value is automatically infered:
// TOKEN_NUMBER if it starts by a digit, TOKEN_IDENT otherwise.
// If @fmt is null or empty, the macro is defined with an empty definition.
void predefine(const char *name, int weak, const char *fmt, ...)
{
	struct ident *ident = built_in_ident(name);
	struct token *value = &eof_token_entry;
	int attr = weak ? SYM_ATTR_WEAK : SYM_ATTR_NORMAL;

	if (fmt && fmt[0]) {
		static char buf[256];
		va_list ap;

		va_start(ap, fmt);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(ap);

		value = __alloc_token(0);
		if (isdigit(buf[0])) {
			token_type(value) = TOKEN_NUMBER;
			value->number = xstrdup(buf);
		} else {
			token_type(value) = TOKEN_IDENT;
			value->ident = built_in_ident(buf);
		}
		value->pos.whitespace = 1;
		value->next = &eof_token_entry;
	}

	do_define(value->pos, NULL, ident, NULL, value, attr);
}

///
// like predefine() but only if one of the non-standard dialect is chosen
void predefine_nostd(const char *name)
{
	if ((standard & STANDARD_GNU) || (standard == STANDARD_NONE))
		predefine(name, 1, "1");
}

static int do_handle_define(struct stream *stream, struct token **line, struct token *token, int attr)
{
	struct token *arglist, *expansion;
	struct token *left = token->next;
	struct ident *name;

	if (token_type(left) != TOKEN_IDENT) {
		sparse_error(token->pos, "expected identifier to 'define'");
		return 1;
	}

	name = left->ident;

	arglist = NULL;
	expansion = left->next;
	if (!expansion->pos.whitespace) {
		if (match_op(expansion, '(')) {
			arglist = expansion;
			expansion = parse_arguments(expansion);
			if (!expansion)
				return 1;
		} else if (!eof_token(expansion)) {
			warning(expansion->pos,
				"no whitespace before object-like macro body");
		}
	}

	return do_define(left->pos, token, name, arglist, expansion, attr);
}

static int handle_define(struct stream *stream, struct token **line, struct token *token)
{
	return do_handle_define(stream, line, token, SYM_ATTR_NORMAL);
}

static int handle_weak_define(struct stream *stream, struct token **line, struct token *token)
{
	return do_handle_define(stream, line, token, SYM_ATTR_WEAK);
}

static int handle_strong_define(struct stream *stream, struct token **line, struct token *token)
{
	return do_handle_define(stream, line, token, SYM_ATTR_STRONG);
}

static int do_handle_undef(struct stream *stream, struct token **line, struct token *token, int attr)
{
	struct token *left = token->next;
	struct symbol *sym;

	if (token_type(left) != TOKEN_IDENT) {
		sparse_error(token->pos, "expected identifier to 'undef'");
		return 1;
	}

	sym = lookup_symbol(left->ident, NS_MACRO | NS_UNDEF);
	if (sym) {
		if (attr < sym->attr)
			return 1;
		if (attr == sym->attr && sym->namespace == NS_UNDEF)
			return 1;
	} else if (attr <= SYM_ATTR_NORMAL)
		return 1;

	if (!sym || sym->scope != file_scope) {
		sym = alloc_symbol(left->pos, SYM_NODE);
		bind_symbol(sym, left->ident, NS_MACRO);
	}

	sym->namespace = NS_UNDEF;
	sym->used_in = NULL;
	sym->attr = attr;

	return 1;
}

static int handle_undef(struct stream *stream, struct token **line, struct token *token)
{
	return do_handle_undef(stream, line, token, SYM_ATTR_NORMAL);
}

static int handle_strong_undef(struct stream *stream, struct token **line, struct token *token)
{
	return do_handle_undef(stream, line, token, SYM_ATTR_STRONG);
}

static int preprocessor_if(struct stream *stream, struct token *token, int cond)
{
	token_type(token) = false_nesting ? TOKEN_SKIP_GROUPS : TOKEN_IF;
	free_preprocessor_line(token->next);
	token->next = stream->top_if;
	stream->top_if = token;
	if (false_nesting || cond != 1)
		false_nesting++;
	return 0;
}

static int handle_ifdef(struct stream *stream, struct token **line, struct token *token)
{
	struct token *next = token->next;
	int arg;
	if (token_type(next) == TOKEN_IDENT) {
		arg = token_defined(next);
	} else {
		dirty_stream(stream);
		if (!false_nesting)
			sparse_error(token->pos, "expected preprocessor identifier");
		arg = -1;
	}
	return preprocessor_if(stream, token, arg);
}

static int handle_ifndef(struct stream *stream, struct token **line, struct token *token)
{
	struct token *next = token->next;
	int arg;
	if (token_type(next) == TOKEN_IDENT) {
		if (!stream->dirty && !stream->ifndef) {
			if (!stream->protect) {
				stream->ifndef = token;
				stream->protect = next->ident;
			} else if (stream->protect == next->ident) {
				stream->ifndef = token;
				stream->dirty = 1;
			}
		}
		arg = !token_defined(next);
	} else {
		dirty_stream(stream);
		if (!false_nesting)
			sparse_error(token->pos, "expected preprocessor identifier");
		arg = -1;
	}

	return preprocessor_if(stream, token, arg);
}

static const char *show_token_sequence(struct token *token, int quote);

/*
 * Expression handling for #if and #elif; it differs from normal expansion
 * due to special treatment of "defined".
 */
static int expression_value(struct token **where)
{
	struct expression *expr;
	struct token *p;
	struct token **list = where, **beginning = NULL;
	long long value;
	int state = 0;

	while (!eof_token(p = scan_next(list))) {
		switch (state) {
		case 0:
			if (token_type(p) != TOKEN_IDENT)
				break;
			if (p->ident == &defined_ident) {
				state = 1;
				beginning = list;
				break;
			} else if (p->ident == &__has_builtin_ident) {
				state = 4;
				beginning = list;
				break;
			} else if (p->ident == &__has_attribute_ident) {
				state = 6;
				beginning = list;
				break;
			}
			if (!expand_one_symbol(list))
				continue;
			if (token_type(p) != TOKEN_IDENT)
				break;
			token_type(p) = TOKEN_ZERO_IDENT;
			break;
		case 1:
			if (match_op(p, '(')) {
				state = 2;
			} else {
				state = 0;
				replace_with_defined(p);
				*beginning = p;
			}
			break;
		case 2:
			if (token_type(p) == TOKEN_IDENT)
				state = 3;
			else
				state = 0;
			replace_with_defined(p);
			*beginning = p;
			break;
		case 3:
			state = 0;
			if (!match_op(p, ')'))
				sparse_error(p->pos, "missing ')' after \"defined\"");
			*list = p->next;
			continue;

		// __has_builtin(x) or __has_attribute(x)
		case 4: case 6:
			if (match_op(p, '(')) {
				state++;
			} else {
				sparse_error(p->pos, "missing '(' after \"__has_%s\"",
					state == 4 ? "builtin" : "attribute");
				state = 0;
			}
			*beginning = p;
			break;
		case 5: case 7:
			if (token_type(p) != TOKEN_IDENT) {
				sparse_error(p->pos, "identifier expected");
				state = 0;
				break;
			}
			if (!match_op(p->next, ')'))
				sparse_error(p->pos, "missing ')' after \"__has_%s\"",
					state == 5 ? "builtin" : "attribute");
			if (state == 5)
				replace_with_has_builtin(p);
			else
				replace_with_has_attribute(p);
			state = 8;
			*beginning = p;
			break;
		case 8:
			state = 0;
			*list = p->next;
			continue;
		}
		list = &p->next;
	}

	p = constant_expression(*where, &expr);
	if (!eof_token(p))
		sparse_error(p->pos, "garbage at end: %s", show_token_sequence(p, 0));
	value = get_expression_value(expr);
	return value != 0;
}

static int handle_if(struct stream *stream, struct token **line, struct token *token)
{
	int value = 0;
	if (!false_nesting)
		value = expression_value(&token->next);

	dirty_stream(stream);
	return preprocessor_if(stream, token, value);
}

static int handle_elif(struct stream * stream, struct token **line, struct token *token)
{
	struct token *top_if = stream->top_if;
	end_group(stream);

	if (!top_if) {
		nesting_error(stream);
		sparse_error(token->pos, "unmatched #elif within stream");
		return 1;
	}

	if (token_type(top_if) == TOKEN_ELSE) {
		nesting_error(stream);
		sparse_error(token->pos, "#elif after #else");
		if (!false_nesting)
			false_nesting = 1;
		return 1;
	}

	dirty_stream(stream);
	if (token_type(top_if) != TOKEN_IF)
		return 1;
	if (false_nesting) {
		false_nesting = 0;
		if (!expression_value(&token->next))
			false_nesting = 1;
	} else {
		false_nesting = 1;
		token_type(top_if) = TOKEN_SKIP_GROUPS;
	}
	return 1;
}

static int handle_else(struct stream *stream, struct token **line, struct token *token)
{
	struct token *top_if = stream->top_if;
	end_group(stream);

	if (!top_if) {
		nesting_error(stream);
		sparse_error(token->pos, "unmatched #else within stream");
		return 1;
	}

	if (token_type(top_if) == TOKEN_ELSE) {
		nesting_error(stream);
		sparse_error(token->pos, "#else after #else");
	}
	if (false_nesting) {
		if (token_type(top_if) == TOKEN_IF)
			false_nesting = 0;
	} else {
		false_nesting = 1;
	}
	token_type(top_if) = TOKEN_ELSE;
	return 1;
}

static int handle_endif(struct stream *stream, struct token **line, struct token *token)
{
	struct token *top_if = stream->top_if;
	end_group(stream);
	if (!top_if) {
		nesting_error(stream);
		sparse_error(token->pos, "unmatched #endif in stream");
		return 1;
	}
	if (false_nesting)
		false_nesting--;
	stream->top_if = top_if->next;
	__free_token(top_if);
	return 1;
}

static int handle_warning(struct stream *stream, struct token **line, struct token *token)
{
	warning(token->pos, "%s", show_token_sequence(token->next, 0));
	return 1;
}

static int handle_error(struct stream *stream, struct token **line, struct token *token)
{
	sparse_error(token->pos, "%s", show_token_sequence(token->next, 0));
	return 1;
}

static int handle_nostdinc(struct stream *stream, struct token **line, struct token *token)
{
	/*
	 * Do we have any non-system includes?
	 * Clear them out if so..
	 */
	*sys_includepath = NULL;
	return 1;
}

static inline void update_inc_ptrs(const char ***where)
{

	if (*where <= dirafter_includepath) {
		dirafter_includepath++;
		/* If this was the entry that we prepend, don't
		 * rise the lower entries, even if they are at
		 * the same level. */
		if (where == &dirafter_includepath)
			return;
	}
	if (*where <= sys_includepath) {
		sys_includepath++;
		if (where == &sys_includepath)
			return;
	}
	if (*where <= isys_includepath) {
		isys_includepath++;
		if (where == &isys_includepath)
			return;
	}

	/* angle_includepath is actually never updated, since we
	 * don't suppport -iquote rught now. May change some day. */
	if (*where <= angle_includepath) {
		angle_includepath++;
		if (where == &angle_includepath)
			return;
	}
}

/* Add a path before 'where' and update the pointers associated with the
 * includepath array */
static void add_path_entry(struct token *token, const char *path,
	const char ***where)
{
	const char **dst;
	const char *next;

	/* Need one free entry.. */
	if (includepath[INCLUDEPATHS-2])
		error_die(token->pos, "too many include path entries");

	/* check that this is not a duplicate */
	dst = includepath;
	while (*dst) {
		if (strcmp(*dst, path) == 0)
			return;
		dst++;
	}
	next = path;
	dst = *where;

	update_inc_ptrs(where);

	/*
	 * Move them all up starting at dst,
	 * insert the new entry..
	 */
	do {
		const char *tmp = *dst;
		*dst = next;
		next = tmp;
		dst++;
	} while (next);
}

static int handle_add_include(struct stream *stream, struct token **line, struct token *token)
{
	for (;;) {
		token = token->next;
		if (eof_token(token))
			return 1;
		if (token_type(token) != TOKEN_STRING) {
			warning(token->pos, "expected path string");
			return 1;
		}
		add_path_entry(token, token->string->data, &isys_includepath);
	}
}

static int handle_add_isystem(struct stream *stream, struct token **line, struct token *token)
{
	for (;;) {
		token = token->next;
		if (eof_token(token))
			return 1;
		if (token_type(token) != TOKEN_STRING) {
			sparse_error(token->pos, "expected path string");
			return 1;
		}
		add_path_entry(token, token->string->data, &sys_includepath);
	}
}

static int handle_add_system(struct stream *stream, struct token **line, struct token *token)
{
	for (;;) {
		token = token->next;
		if (eof_token(token))
			return 1;
		if (token_type(token) != TOKEN_STRING) {
			sparse_error(token->pos, "expected path string");
			return 1;
		}
		add_path_entry(token, token->string->data, &dirafter_includepath);
	}
}

/* Add to end on includepath list - no pointer updates */
static void add_dirafter_entry(struct token *token, const char *path)
{
	const char **dst = includepath;

	/* Need one free entry.. */
	if (includepath[INCLUDEPATHS-2])
		error_die(token->pos, "too many include path entries");

	/* Add to the end */
	while (*dst)
		dst++;
	*dst = path;
	dst++;
	*dst = NULL;
}

static int handle_add_dirafter(struct stream *stream, struct token **line, struct token *token)
{
	for (;;) {
		token = token->next;
		if (eof_token(token))
			return 1;
		if (token_type(token) != TOKEN_STRING) {
			sparse_error(token->pos, "expected path string");
			return 1;
		}
		add_dirafter_entry(token, token->string->data);
	}
}

static int handle_split_include(struct stream *stream, struct token **line, struct token *token)
{
	/*
	 * -I-
	 *  From info gcc:
	 *  Split the include path.  Any directories specified with `-I'
	 *  options before `-I-' are searched only for headers requested with
	 *  `#include "FILE"'; they are not searched for `#include <FILE>'.
	 *  If additional directories are specified with `-I' options after
	 *  the `-I-', those directories are searched for all `#include'
	 *  directives.
	 *  In addition, `-I-' inhibits the use of the directory of the current
	 *  file directory as the first search directory for `#include "FILE"'.
	 */
	quote_includepath = includepath+1;
	angle_includepath = sys_includepath;
	return 1;
}

/*
 * We replace "#pragma xxx" with "__pragma__" in the token
 * stream. Just as an example.
 *
 * We'll just #define that away for now, but the theory here
 * is that we can use this to insert arbitrary token sequences
 * to turn the pragmas into internal front-end sequences for
 * when we actually start caring about them.
 *
 * So eventually this will turn into some kind of extended
 * __attribute__() like thing, except called __pragma__(xxx).
 */
static int handle_pragma(struct stream *stream, struct token **line, struct token *token)
{
	struct token *next = *line;

	if (match_ident(token->next, &once_ident) && eof_token(token->next->next)) {
		stream->once = 1;
		return 1;
	}
	token->ident = &pragma_ident;
	token->pos.newline = 1;
	token->pos.whitespace = 1;
	token->pos.pos = 1;
	*line = token;
	token->next = next;
	return 0;
}

/*
 * We ignore #line for now.
 */
static int handle_line(struct stream *stream, struct token **line, struct token *token)
{
	return 1;
}

static int handle_ident(struct stream *stream, struct token **line, struct token *token)
{
	return 1;
}

static int handle_nondirective(struct stream *stream, struct token **line, struct token *token)
{
	sparse_error(token->pos, "unrecognized preprocessor line '%s'", show_token_sequence(token, 0));
	return 1;
}


static void init_preprocessor(void)
{
	int i;
	int stream = init_stream("preprocessor", -1, includepath);
	static struct {
		const char *name;
		int (*handler)(struct stream *, struct token **, struct token *);
	} normal[] = {
		{ "define",		handle_define },
		{ "weak_define",	handle_weak_define },
		{ "strong_define",	handle_strong_define },
		{ "undef",		handle_undef },
		{ "strong_undef",	handle_strong_undef },
		{ "warning",		handle_warning },
		{ "error",		handle_error },
		{ "include",		handle_include },
		{ "include_next",	handle_include_next },
		{ "pragma",		handle_pragma },
		{ "line",		handle_line },
		{ "ident",		handle_ident },

		// our internal preprocessor tokens
		{ "nostdinc",	   handle_nostdinc },
		{ "add_include",   handle_add_include },
		{ "add_isystem",   handle_add_isystem },
		{ "add_system",    handle_add_system },
		{ "add_dirafter",  handle_add_dirafter },
		{ "split_include", handle_split_include },
		{ "argv_include",  handle_argv_include },
	}, special[] = {
		{ "ifdef",	handle_ifdef },
		{ "ifndef",	handle_ifndef },
		{ "else",	handle_else },
		{ "endif",	handle_endif },
		{ "if",		handle_if },
		{ "elif",	handle_elif },
	};
	static struct {
		const char *name;
		void (*expander)(struct token *);
	} dynamic[] = {
		{ "__LINE__",		expand_line },
		{ "__FILE__",		expand_file },
		{ "__BASE_FILE__",	expand_basefile },
		{ "__DATE__",		expand_date },
		{ "__TIME__",		expand_time },
		{ "__COUNTER__",	expand_counter },
		{ "__INCLUDE_LEVEL__",	expand_include_level },
	};

	for (i = 0; i < ARRAY_SIZE(normal); i++) {
		struct symbol *sym;
		sym = create_symbol(stream, normal[i].name, SYM_PREPROCESSOR, NS_PREPROCESSOR);
		sym->handler = normal[i].handler;
		sym->normal = 1;
	}
	for (i = 0; i < ARRAY_SIZE(special); i++) {
		struct symbol *sym;
		sym = create_symbol(stream, special[i].name, SYM_PREPROCESSOR, NS_PREPROCESSOR);
		sym->handler = special[i].handler;
		sym->normal = 0;
	}
	for (i = 0; i < ARRAY_SIZE(dynamic); i++) {
		struct symbol *sym;
		sym = create_symbol(stream, dynamic[i].name, SYM_NODE, NS_MACRO);
		sym->expander = dynamic[i].expander;
	}

	counter_macro = 0;
}

static void handle_preprocessor_line(struct stream *stream, struct token **line, struct token *start)
{
	int (*handler)(struct stream *, struct token **, struct token *);
	struct token *token = start->next;
	int is_normal = 1;

	if (eof_token(token))
		return;

	if (token_type(token) == TOKEN_IDENT) {
		struct symbol *sym = lookup_symbol(token->ident, NS_PREPROCESSOR);
		if (sym) {
			handler = sym->handler;
			is_normal = sym->normal;
		} else {
			handler = handle_nondirective;
		}
	} else if (token_type(token) == TOKEN_NUMBER) {
		handler = handle_line;
	} else {
		handler = handle_nondirective;
	}

	if (is_normal) {
		dirty_stream(stream);
		if (false_nesting)
			goto out;
	}
	if (!handler(stream, line, token))	/* all set */
		return;

out:
	free_preprocessor_line(token);
}

static void preprocessor_line(struct stream *stream, struct token **line)
{
	struct token *start = *line, *next;
	struct token **tp = &start->next;

	for (;;) {
		next = *tp;
		if (next->pos.newline)
			break;
		tp = &next->next;
	}
	*line = next;
	*tp = &eof_token_entry;
	handle_preprocessor_line(stream, line, start);
}

static void do_preprocess(struct token **list)
{
	struct token *next;

	while (!eof_token(next = scan_next(list))) {
		struct stream *stream = input_streams + next->pos.stream;

		if (next->pos.newline && match_op(next, '#')) {
			if (!next->pos.noexpand) {
				preprocessor_line(stream, list);
				__free_token(next);	/* Free the '#' token */
				continue;
			}
		}

		switch (token_type(next)) {
		case TOKEN_STREAMEND:
			if (stream->top_if) {
				nesting_error(stream);
				sparse_error(stream->top_if->pos, "unterminated preprocessor conditional");
				stream->top_if = NULL;
				false_nesting = 0;
			}
			if (!stream->dirty)
				stream->constant = CONSTANT_FILE_YES;
			*list = next->next;
			include_level--;
			continue;
		case TOKEN_STREAMBEGIN:
			*list = next->next;
			include_level++;
			continue;

		default:
			dirty_stream(stream);
			if (false_nesting) {
				*list = next->next;
				__free_token(next);
				continue;
			}

			if (token_type(next) != TOKEN_IDENT ||
			    expand_one_symbol(list))
				list = &next->next;
		}
	}
}

void init_include_path(void)
{
	FILE *fp;
	char path[256];
	char arch[32];
	char os[32];

	fp = popen("/bin/uname -m", "r");
	if (!fp)
		return;
	if (!fgets(arch, sizeof(arch) - 1, fp))
		return;
	pclose(fp);
	if (arch[strlen(arch) - 1] == '\n')
		arch[strlen(arch) - 1] = '\0';

	fp = popen("/bin/uname -o", "r");
	if (!fp)
		return;
	fgets(os, sizeof(os) - 1, fp);
	pclose(fp);

	if (strcmp(os, "GNU/Linux\n") != 0)
		return;
	strcpy(os, "linux-gnu");

	snprintf(path, sizeof(path), "/usr/include/%s-%s/", arch, os);
	add_pre_buffer("#add_system \"%s/\"\n", path);
}

struct token * preprocess(struct token *token)
{
	preprocessing = 1;
	init_preprocessor();
	do_preprocess(&token);

	// Drop all expressions from preprocessing, they're not used any more.
	// This is not true when we have multiple files, though ;/
	// clear_expression_alloc();
	preprocessing = 0;

	return token;
}

static int is_VA_ARGS_token(struct token *token)
{
	return (token_type(token) == TOKEN_IDENT) &&
		(token->ident == &__VA_ARGS___ident);
}

static void dump_macro(struct symbol *sym)
{
	int nargs = sym->arglist ? sym->arglist->count.normal : 0;
	struct token *args[nargs];
	struct token *token;

	printf("#define %s", show_ident(sym->ident));
	token = sym->arglist;
	if (token) {
		const char *sep = "";
		int narg = 0;
		putchar('(');
		for (; !eof_token(token); token = token->next) {
			if (token_type(token) == TOKEN_ARG_COUNT)
				continue;
			if (is_VA_ARGS_token(token))
				printf("%s...", sep);
			else
				printf("%s%s", sep, show_token(token));
			args[narg++] = token;
			sep = ",";
		}
		putchar(')');
	}

	token = sym->expansion;
	while (token_type(token) != TOKEN_UNTAINT) {
		struct token *next = token->next;
		if (token->pos.whitespace)
			putchar(' ');
		switch (token_type(token)) {
		case TOKEN_CONCAT:
			printf("##");
			break;
		case TOKEN_STR_ARGUMENT:
			printf("#");
			/* fall-through */
		case TOKEN_QUOTED_ARGUMENT:
		case TOKEN_MACRO_ARGUMENT:
			token = args[token->argnum];
			/* fall-through */
		default:
			printf("%s", show_token(token));
		}
		token = next;
	}
	putchar('\n');
}

void dump_macro_definitions(void)
{
	struct ident *name;

	FOR_EACH_PTR(macros, name) {
		struct symbol *sym = lookup_macro(name);
		if (sym)
			dump_macro(sym);
	} END_FOR_EACH_PTR(name);
}
