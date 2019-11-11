#ifndef SCOPE_H
#define SCOPE_H
/*
 * Symbol scoping is pretty simple.
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

struct symbol;
struct position;

struct scope {
	struct token *token;
	struct symbol_list *symbols;	/* List of symbols in this scope */
	struct scope *next;
};

extern struct scope
		*block_scope,
		*function_scope,
		*file_scope,
		*global_scope;

static inline int toplevel(struct scope *scope)
{
	return scope == file_scope || scope == global_scope;
}

extern void start_file_scope(void);
extern void end_file_scope(void);
extern void new_file_scope(void);

extern void start_symbol_scope(struct position pos);
extern void end_symbol_scope(void);

extern void start_function_scope(struct position pos);
extern void end_function_scope(void);

extern void bind_scope(struct symbol *, struct scope *);
extern void rebind_scope(struct symbol *, struct scope *);

extern int is_outer_scope(struct scope *);
#endif
