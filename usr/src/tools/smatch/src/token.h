#ifndef TOKEN_H
#define TOKEN_H
/*
 * Basic tokenization structures. NOTE! Those tokens had better
 * be pretty small, since we're going to keep them all in memory
 * indefinitely.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003 Linus Torvalds
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

#include <sys/types.h>
#include "lib.h"

/*
 * This describes the pure lexical elements (tokens), with
 * no semantic meaning. In other words, an identifier doesn't
 * have a type or meaning, it is only a specific string in
 * the input stream.
 *
 * Semantic meaning is handled elsewhere.
 */

enum constantfile {
  CONSTANT_FILE_MAYBE,    // To be determined, not inside any #ifs in this file
  CONSTANT_FILE_IFNDEF,   // To be determined, currently inside #ifndef
  CONSTANT_FILE_NOPE,     // No
  CONSTANT_FILE_YES       // Yes
};

extern const char *includepath[];

struct stream {
	int fd;
	const char *name;
	const char *path;    // input-file path - see set_stream_include_path()
	const char **next_path;

	/* Use these to check for "already parsed" */
	enum constantfile constant;
	int dirty, next_stream, once;
	struct ident *protect;
	struct token *ifndef;
	struct token *top_if;
};

extern int input_stream_nr;
extern struct stream *input_streams;
extern unsigned int tabstop;
extern int no_lineno;
extern int *hash_stream(const char *name);

struct ident {
	struct ident *next;	/* Hash chain of identifiers */
	struct symbol *symbols;	/* Pointer to semantic meaning list */
	unsigned char len;	/* Length of identifier name */
	unsigned char tainted:1,
	              reserved:1,
		      keyword:1;
	char name[];		/* Actual identifier */
};

enum token_type {
	TOKEN_EOF,
	TOKEN_BAD,
	TOKEN_ERROR,
	TOKEN_IDENT,
	TOKEN_ZERO_IDENT,
	TOKEN_NUMBER,
	TOKEN_CHAR,
	TOKEN_CHAR_EMBEDDED_0,
	TOKEN_CHAR_EMBEDDED_1,
	TOKEN_CHAR_EMBEDDED_2,
	TOKEN_CHAR_EMBEDDED_3,
	TOKEN_WIDE_CHAR,
	TOKEN_WIDE_CHAR_EMBEDDED_0,
	TOKEN_WIDE_CHAR_EMBEDDED_1,
	TOKEN_WIDE_CHAR_EMBEDDED_2,
	TOKEN_WIDE_CHAR_EMBEDDED_3,
	TOKEN_STRING,
	TOKEN_WIDE_STRING,
	TOKEN_SPECIAL,
	TOKEN_STREAMBEGIN,
	TOKEN_STREAMEND,
	TOKEN_MACRO_ARGUMENT,
	TOKEN_STR_ARGUMENT,
	TOKEN_QUOTED_ARGUMENT,
	TOKEN_CONCAT,
	TOKEN_GNU_KLUDGE,
	TOKEN_UNTAINT,
	TOKEN_ARG_COUNT,
	TOKEN_IF,
	TOKEN_SKIP_GROUPS,
	TOKEN_ELSE,
};

/* Combination tokens */
#define COMBINATION_STRINGS {	\
	"+=", "++",		\
	"-=", "--", "->",	\
	"*=",			\
	"/=",			\
	"%=",			\
	"<=", ">=",		\
	"==", "!=",		\
	"&&", "&=",		\
	"||", "|=",		\
	"^=", "##",		\
	"<<", ">>", "..",	\
	"<<=", ">>=", "...",	\
	"",			\
	"<", ">", "<=", ">="	\
}

extern unsigned char combinations[][4];

enum special_token {
	SPECIAL_BASE = 256,
	SPECIAL_ADD_ASSIGN = SPECIAL_BASE,
	SPECIAL_INCREMENT,
	SPECIAL_SUB_ASSIGN,
	SPECIAL_DECREMENT,
	SPECIAL_DEREFERENCE,
	SPECIAL_MUL_ASSIGN,
	SPECIAL_DIV_ASSIGN,
	SPECIAL_MOD_ASSIGN,
	SPECIAL_LTE,
	SPECIAL_GTE,
	SPECIAL_EQUAL,
	SPECIAL_NOTEQUAL,
	SPECIAL_LOGICAL_AND,
	SPECIAL_AND_ASSIGN,
	SPECIAL_LOGICAL_OR,
	SPECIAL_OR_ASSIGN,
	SPECIAL_XOR_ASSIGN,
	SPECIAL_HASHHASH,
	SPECIAL_LEFTSHIFT,
	SPECIAL_RIGHTSHIFT,
	SPECIAL_DOTDOT,
	SPECIAL_SHL_ASSIGN,
	SPECIAL_SHR_ASSIGN,
	SPECIAL_ELLIPSIS,
	SPECIAL_ARG_SEPARATOR,
	SPECIAL_UNSIGNED_LT,
	SPECIAL_UNSIGNED_GT,
	SPECIAL_UNSIGNED_LTE,
	SPECIAL_UNSIGNED_GTE,
};

struct string {
	unsigned int length:31;
	unsigned int immutable:1;
	char data[];
};

/* will fit into 32 bits */
struct argcount {
	unsigned normal:10;
	unsigned quoted:10;
	unsigned str:10;
	unsigned vararg:1;
};

/*
 * This is a very common data structure, it should be kept
 * as small as humanly possible. Big (rare) types go as
 * pointers.
 */
struct token {
	struct position pos;
	struct token *next;
	union {
		const char *number;
		struct ident *ident;
		unsigned int special;
		struct string *string;
		int argnum;
		struct argcount count;
		char embedded[4];
	};
};

#define MAX_STRING 8191

static inline struct token *containing_token(struct token **p)
{
	void *addr = (char *)p - ((char *)&((struct token *)0)->next - (char *)0);
	return addr;
}

#define token_type(x) ((x)->pos.type)

/*
 * Last token in the stream - points to itself.
 * This allows us to not test for NULL pointers
 * when following the token->next chain..
 */
extern struct token eof_token_entry;
#define eof_token(x) ((x) == &eof_token_entry)

extern int init_stream(const char *, int fd, const char **next_path);
extern const char *stream_name(int stream);
extern struct ident *hash_ident(struct ident *);
extern struct ident *built_in_ident(const char *);
extern struct token *built_in_token(int, struct ident *);
extern const char *show_special(int);
extern const char *show_ident(const struct ident *);
extern const char *show_string(const struct string *string);
extern const char *show_token(const struct token *);
extern const char *quote_token(const struct token *);
extern struct token * tokenize(const char *, int, struct token *, const char **next_path);
extern struct token * tokenize_buffer(void *, unsigned long, struct token **);

extern void show_identifier_stats(void);
extern void init_include_path(void);
extern struct token *preprocess(struct token *);

extern void store_all_tokens(struct token *token);
extern struct token *pos_get_token(struct position pos);
extern char *pos_ident(struct position pos);

extern void store_macro_pos(struct token *);
extern char *get_macro_name(struct position pos);
extern char *get_inner_macro(struct position pos);
extern struct string_list *get_all_macros(struct position pos);

static inline int match_op(struct token *token, unsigned int op)
{
	return token->pos.type == TOKEN_SPECIAL && token->special == op;
}

static inline int match_ident(struct token *token, struct ident *id)
{
	return token->pos.type == TOKEN_IDENT && token->ident == id;
}

#endif
