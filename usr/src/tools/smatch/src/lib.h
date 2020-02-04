#ifndef LIB_H
#define LIB_H

#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>

/*
 * Basic helper routine descriptions for 'sparse'.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003 Linus Torvalds
 *               2004 Christopher Li
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

#include "compat.h"
#include "ptrlist.h"
#include "utils.h"
#include "bits.h"

#define DO_STRINGIFY(x) #x
#define STRINGIFY(x) DO_STRINGIFY(x)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#endif

extern int verbose, optimize_level, optimize_size, preprocessing;
extern int die_if_error;
extern int parse_error;
extern int repeat_phase;
extern int do_output;
extern int gcc_major, gcc_minor, gcc_patchlevel;

extern const char *base_filename;

extern unsigned int hexval(unsigned int c);

struct position {
	unsigned int type:6,
		     stream:14,
		     newline:1,
		     whitespace:1,
		     pos:10;
	unsigned int line:31,
		     noexpand:1;
};

struct ident;
struct token;
struct symbol;
struct statement;
struct expression;
struct basic_block;
struct entrypoint;
struct instruction;
struct multijmp;
struct pseudo;

DECLARE_PTR_LIST(symbol_list, struct symbol);
DECLARE_PTR_LIST(statement_list, struct statement);
DECLARE_PTR_LIST(expression_list, struct expression);
DECLARE_PTR_LIST(basic_block_list, struct basic_block);
DECLARE_PTR_LIST(instruction_list, struct instruction);
DECLARE_PTR_LIST(multijmp_list, struct multijmp);
DECLARE_PTR_LIST(pseudo_list, struct pseudo);
DECLARE_PTR_LIST(ident_list, struct ident);
DECLARE_PTR_LIST(string_list, char);

typedef struct pseudo *pseudo_t;

struct token *skip_to(struct token *, int);
struct token *expect(struct token *, int, const char *);
void unexpected(struct token *, const char *errmsg);

#ifdef __GNUC__
#define FORMAT_ATTR(pos) __attribute__ ((__format__ (__printf__, pos, pos+1)))
#define NORETURN_ATTR __attribute__ ((__noreturn__))
#define SENTINEL_ATTR __attribute__ ((__sentinel__))
#else
#define FORMAT_ATTR(pos)
#define NORETURN_ATTR
#define SENTINEL_ATTR
#endif

FORMAT_ATTR(1) NORETURN_ATTR
extern void die(const char *, ...);

FORMAT_ATTR(2) NORETURN_ATTR
extern void error_die(struct position, const char *, ...);

extern void info(struct position, const char *, ...) FORMAT_ATTR(2);
extern void warning(struct position, const char *, ...) FORMAT_ATTR(2);
extern void sparse_error(struct position, const char *, ...) FORMAT_ATTR(2);
extern void expression_error(struct expression *, const char *, ...) FORMAT_ATTR(2);

#define	ERROR_CURR_PHASE	(1 << 0)
#define	ERROR_PREV_PHASE	(1 << 1)
extern int has_error;


enum phase {
	PASS__PARSE,
	PASS__LINEARIZE,
	PASS__MEM2REG,
	PASS__OPTIM,
	PASS__FINAL,
};

#define	PASS_PARSE		(1UL << PASS__PARSE)
#define	PASS_LINEARIZE		(1UL << PASS__LINEARIZE)
#define	PASS_MEM2REG		(1UL << PASS__MEM2REG)
#define	PASS_OPTIM		(1UL << PASS__OPTIM)
#define	PASS_FINAL		(1UL << PASS__FINAL)


extern void add_pre_buffer(const char *fmt, ...) FORMAT_ATTR(1);
extern void predefine(const char *name, int weak, const char *fmt, ...) FORMAT_ATTR(3);
extern void predefine_nostd(const char *name);

extern int preprocess_only;

extern int Waddress;
extern int Waddress_space;
extern int Wbitwise;
extern int Wbitwise_pointer;
extern int Wcast_from_as;
extern int Wcast_to_as;
extern int Wcast_truncate;
extern int Wconstant_suffix;
extern int Wconstexpr_not_const;
extern int Wcontext;
extern int Wdecl;
extern int Wdeclarationafterstatement;
extern int Wdefault_bitfield_sign;
extern int Wdesignated_init;
extern int Wdo_while;
extern int Wenum_mismatch;
extern int Wexternal_function_has_definition;
extern int Wsparse_error;
extern int Wimplicit_int;
extern int Winit_cstring;
extern int Wint_to_pointer_cast;
extern int Wmemcpy_max_count;
extern int Wnon_pointer_null;
extern int Wold_initializer;
extern int Wold_style_definition;
extern int Wone_bit_signed_bitfield;
extern int Woverride_init;
extern int Woverride_init_all;
extern int Woverride_init_whole_range;
extern int Wparen_string;
extern int Wpointer_arith;
extern int Wpointer_to_int_cast;
extern int Wptr_subtraction_blows;
extern int Wreturn_void;
extern int Wshadow;
extern int Wshift_count_negative;
extern int Wshift_count_overflow;
extern int Wsizeof_bool;
extern int Wstrict_prototypes;
extern int Wtautological_compare;
extern int Wtransparent_union;
extern int Wtypesign;
extern int Wundef;
extern int Wuninitialized;
extern int Wunknown_attribute;
extern int Wvla;

extern int dump_macro_defs;
extern int dump_macros_only;

extern int dbg_compound;
extern int dbg_dead;
extern int dbg_domtree;
extern int dbg_entry;
extern int dbg_ir;
extern int dbg_postorder;

extern unsigned int fmax_warnings;
extern int fmem_report;
extern unsigned long fdump_ir;
extern unsigned long long fmemcpy_max_count;
extern unsigned long fpasses;
extern int funsigned_char;

extern int arch_m64;
extern int arch_msize_long;
extern int arch_big_endian;
extern int arch_mach;

enum standard {
	STANDARD_NONE,
	STANDARD_GNU,
	STANDARD_C89,
	STANDARD_GNU89 = STANDARD_C89 | STANDARD_GNU,
	STANDARD_C94,
	STANDARD_GNU94 = STANDARD_C94 | STANDARD_GNU,
	STANDARD_C99,
	STANDARD_GNU99 = STANDARD_C99 | STANDARD_GNU,
	STANDARD_C11,
	STANDARD_GNU11 = STANDARD_C11 | STANDARD_GNU,
};
extern enum standard standard;

extern void dump_macro_definitions(void);
extern struct symbol_list *sparse_initialize(int argc, char **argv, struct string_list **files);
extern struct symbol_list *__sparse(char *filename);
extern struct symbol_list *sparse_keep_tokens(char *filename);
extern struct symbol_list *sparse(char *filename);
extern void report_stats(void);

static inline int symbol_list_size(struct symbol_list *list)
{
	return ptr_list_size((struct ptr_list *)(list));
}

static inline int statement_list_size(struct statement_list *list)
{
	return ptr_list_size((struct ptr_list *)(list));
}

static inline int expression_list_size(struct expression_list *list)
{
	return ptr_list_size((struct ptr_list *)(list));
}

static inline int instruction_list_size(struct instruction_list *list)
{
	return ptr_list_size((struct ptr_list *)(list));
}

static inline int pseudo_list_size(struct pseudo_list *list)
{
	return ptr_list_size((struct ptr_list *)(list));
}

static inline int bb_list_size(struct basic_block_list *list)
{
	return ptr_list_size((struct ptr_list *)(list));
}

static inline void free_instruction_list(struct instruction_list **head)
{
	free_ptr_list(head);
}

static inline struct instruction * delete_last_instruction(struct instruction_list **head)
{
	return undo_ptr_list_last((struct ptr_list **)head);
}

static inline struct basic_block *first_basic_block(struct basic_block_list *head)
{
	return first_ptr_list((struct ptr_list *)head);
}
static inline struct instruction *last_instruction(struct instruction_list *head)
{
	return last_ptr_list((struct ptr_list *)head);
}

static inline struct instruction *first_instruction(struct instruction_list *head)
{
	return first_ptr_list((struct ptr_list *)head);
}

static inline struct expression *first_expression(struct expression_list *head)
{
	return first_ptr_list((struct ptr_list *)head);
}

static inline pseudo_t first_pseudo(struct pseudo_list *head)
{
	return first_ptr_list((struct ptr_list *)head);
}

static inline void concat_symbol_list(struct symbol_list *from, struct symbol_list **to)
{
	concat_ptr_list((struct ptr_list *)from, (struct ptr_list **)to);
}

static inline void concat_basic_block_list(struct basic_block_list *from, struct basic_block_list **to)
{
	concat_ptr_list((struct ptr_list *)from, (struct ptr_list **)to);
}

static inline void concat_instruction_list(struct instruction_list *from, struct instruction_list **to)
{
	concat_ptr_list((struct ptr_list *)from, (struct ptr_list **)to);
}

static inline void add_symbol(struct symbol_list **list, struct symbol *sym)
{
	add_ptr_list(list, sym);
}

static inline void add_statement(struct statement_list **list, struct statement *stmt)
{
	add_ptr_list(list, stmt);
}

static inline void add_expression(struct expression_list **list, struct expression *expr)
{
	add_ptr_list(list, expr);
}

static inline void add_ident(struct ident_list **list, struct ident *ident)
{
	add_ptr_list(list, ident);
}

#define hashval(x) ((unsigned long)(x))

#endif
