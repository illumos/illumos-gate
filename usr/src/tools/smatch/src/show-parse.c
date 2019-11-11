/*
 * sparse/show-parse.c
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
 *
 * Print out results of parsing for debugging and testing.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "parse.h"
#include "symbol.h"
#include "scope.h"
#include "expression.h"
#include "target.h"

static int show_symbol_expr(struct symbol *sym);
static int show_string_expr(struct expression *expr);

static void do_debug_symbol(struct symbol *sym, int indent)
{
	static const char indent_string[] = "                                  ";
	static const char *typestr[] = {
		[SYM_UNINITIALIZED] = "none",
		[SYM_PREPROCESSOR] = "cpp.",
		[SYM_BASETYPE] = "base",
		[SYM_NODE] = "node",
		[SYM_PTR] = "ptr.",
		[SYM_FN] = "fn..",
		[SYM_ARRAY] = "arry",
		[SYM_STRUCT] = "strt",
		[SYM_UNION] = "unin",
		[SYM_ENUM] = "enum",
		[SYM_TYPEDEF] = "tdef",
		[SYM_TYPEOF] = "tpof",
		[SYM_MEMBER] = "memb",
		[SYM_BITFIELD] = "bitf",
		[SYM_LABEL] = "labl",
		[SYM_RESTRICT] = "rstr",
		[SYM_FOULED] = "foul",
		[SYM_BAD] = "bad.",
	};
	struct context *context;
	int i;

	if (!sym)
		return;
	fprintf(stderr, "%.*s%s%3d:%lu %s %s (as: %s) %p (%s:%d:%d) %s\n",
		indent, indent_string, typestr[sym->type],
		sym->bit_size, sym->ctype.alignment,
		modifier_string(sym->ctype.modifiers), show_ident(sym->ident),
		show_as(sym->ctype.as),
		sym, stream_name(sym->pos.stream), sym->pos.line, sym->pos.pos,
		builtin_typename(sym) ?: "");
	i = 0;
	FOR_EACH_PTR(sym->ctype.contexts, context) {
		/* FIXME: should print context expression */
		fprintf(stderr, "< context%d: in=%d, out=%d\n",
			i, context->in, context->out);
		fprintf(stderr, "  end context%d >\n", i);
		i++;
	} END_FOR_EACH_PTR(context);
	if (sym->type == SYM_FN) {
		struct symbol *arg;
		i = 0;
		FOR_EACH_PTR(sym->arguments, arg) {
			fprintf(stderr, "< arg%d:\n", i);
			do_debug_symbol(arg, 0);
			fprintf(stderr, "  end arg%d >\n", i);
			i++;
		} END_FOR_EACH_PTR(arg);
	}
	do_debug_symbol(sym->ctype.base_type, indent+2);
}

void debug_symbol(struct symbol *sym)
{
	do_debug_symbol(sym, 0);
}

/*
 * Symbol type printout. The type system is by far the most
 * complicated part of C - everything else is trivial.
 */
const char *modifier_string(unsigned long mod)
{
	static char buffer[100];
	int len = 0;
	int i;
	struct mod_name {
		unsigned long mod;
		const char *name;
	} *m;

	static struct mod_name mod_names[] = {
		{MOD_AUTO,		"auto"},
		{MOD_REGISTER,		"register"},
		{MOD_STATIC,		"static"},
		{MOD_EXTERN,		"extern"},
		{MOD_CONST,		"const"},
		{MOD_VOLATILE,		"volatile"},
		{MOD_RESTRICT,		"restrict"},
		{MOD_ATOMIC,		"[atomic]"},
		{MOD_SIGNED,		"[signed]"},
		{MOD_UNSIGNED,		"[unsigned]"},
		{MOD_CHAR,		"[char]"},
		{MOD_SHORT,		"[short]"},
		{MOD_LONG,		"[long]"},
		{MOD_LONGLONG,		"[long long]"},
		{MOD_LONGLONGLONG,	"[long long long]"},
		{MOD_TLS,		"[tls]"},
		{MOD_INLINE,		"inline"},
		{MOD_ADDRESSABLE,	"[addressable]"},
		{MOD_NOCAST,		"[nocast]"},
		{MOD_NODEREF,		"[noderef]"},
		{MOD_TOPLEVEL,		"[toplevel]"},
		{MOD_ASSIGNED,		"[assigned]"},
		{MOD_TYPE,		"[type]"},
		{MOD_SAFE,		"[safe]"},
		{MOD_USERTYPE,		"[usertype]"},
		{MOD_NORETURN,		"[noreturn]"},
		{MOD_EXPLICITLY_SIGNED,	"[explicitly-signed]"},
		{MOD_BITWISE,		"[bitwise]"},
		{MOD_PURE,		"[pure]"},
	};

	for (i = 0; i < ARRAY_SIZE(mod_names); i++) {
		m = mod_names + i;
		if (mod & m->mod) {
			char c;
			const char *name = m->name;
			while ((c = *name++) != '\0' && len + 2 < sizeof buffer)
				buffer[len++] = c;
			buffer[len++] = ' ';
		}
	}
	buffer[len] = 0;
	return buffer;
}

static void show_struct_member(struct symbol *sym)
{
	printf("\t%s:%d:%ld at offset %ld.%d", show_ident(sym->ident), sym->bit_size, sym->ctype.alignment, sym->offset, sym->bit_offset);
	printf("\n");
}

void show_symbol_list(struct symbol_list *list, const char *sep)
{
	struct symbol *sym;
	const char *prepend = "";

	FOR_EACH_PTR(list, sym) {
		puts(prepend);
		prepend = ", ";
		show_symbol(sym);
	} END_FOR_EACH_PTR(sym);
}

const char *show_as(struct ident *as)
{
	if (!as)
		return "";
	return show_ident(as);
}

struct type_name {
	char *start;
	char *end;
};

static void FORMAT_ATTR(2) prepend(struct type_name *name, const char *fmt, ...)
{
	static char buffer[512];
	int n;

	va_list args;
	va_start(args, fmt);
	n = vsprintf(buffer, fmt, args);
	va_end(args);

	name->start -= n;
	memcpy(name->start, buffer, n);
}

static void FORMAT_ATTR(2) append(struct type_name *name, const char *fmt, ...)
{
	static char buffer[512];
	int n;

	va_list args;
	va_start(args, fmt);
	n = vsprintf(buffer, fmt, args);
	va_end(args);

	memcpy(name->end, buffer, n);
	name->end += n;
}

static struct ctype_name {
	struct symbol *sym;
	const char *name;
	const char *suffix;
} typenames[] = {
	{ & char_ctype,  "char", "" },
	{ &schar_ctype,  "signed char", "" },
	{ &uchar_ctype,  "unsigned char", "" },
	{ & short_ctype, "short", "" },
	{ &sshort_ctype, "signed short", "" },
	{ &ushort_ctype, "unsigned short", "" },
	{ & int_ctype,   "int", "" },
	{ &sint_ctype,   "signed int", "" },
	{ &uint_ctype,   "unsigned int", "U" },
	{ & long_ctype,  "long", "L" },
	{ &slong_ctype,  "signed long", "L" },
	{ &ulong_ctype,  "unsigned long", "UL" },
	{ & llong_ctype, "long long", "LL" },
	{ &sllong_ctype, "signed long long", "LL" },
	{ &ullong_ctype, "unsigned long long", "ULL" },
	{ & lllong_ctype, "long long long", "LLL" },
	{ &slllong_ctype, "signed long long long", "LLL" },
	{ &ulllong_ctype, "unsigned long long long", "ULLL" },

	{ &void_ctype,   "void", "" },
	{ &bool_ctype,   "bool", "" },

	{ &float_ctype,  "float", "F" },
	{ &double_ctype, "double", "" },
	{ &ldouble_ctype,"long double", "L" },
	{ &incomplete_ctype, "incomplete type", "" },
	{ &int_type, "abstract int", "" },
	{ &fp_type, "abstract fp", "" },
	{ &label_ctype, "label type", "" },
	{ &bad_ctype, "bad type", "" },
};

const char *builtin_typename(struct symbol *sym)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(typenames); i++)
		if (typenames[i].sym == sym)
			return typenames[i].name;
	return NULL;
}

const char *builtin_type_suffix(struct symbol *sym)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(typenames); i++)
		if (typenames[i].sym == sym)
			return typenames[i].suffix;
	return NULL;
}

const char *builtin_ctypename(struct ctype *ctype)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(typenames); i++)
		if (&typenames[i].sym->ctype == ctype)
			return typenames[i].name;
	return NULL;
}

static void do_show_type(struct symbol *sym, struct type_name *name)
{
	const char *typename;
	unsigned long mod = 0;
	struct ident *as = NULL;
	int was_ptr = 0;
	int restr = 0;
	int fouled = 0;

deeper:
	if (!sym || (sym->type != SYM_NODE && sym->type != SYM_ARRAY &&
		     sym->type != SYM_BITFIELD)) {
		const char *s;
		size_t len;

		if (as)
			prepend(name, "%s ", show_as(as));

		if (sym->type == SYM_BASETYPE || sym->type == SYM_ENUM)
			mod &= ~MOD_SPECIFIER;
		s = modifier_string(mod);
		len = strlen(s);
		name->start -= len;    
		memcpy(name->start, s, len);  
		mod = 0;
		as = NULL;
	}

	if (!sym)
		goto out;

	if ((typename = builtin_typename(sym))) {
		int len = strlen(typename);
		if (name->start != name->end)
			*--name->start = ' ';
		name->start -= len;
		memcpy(name->start, typename, len);
		goto out;
	}

	/* Prepend */
	switch (sym->type) {
	case SYM_PTR:
		prepend(name, "*");
		mod = sym->ctype.modifiers;
		as = sym->ctype.as;
		was_ptr = 1;
		break;

	case SYM_FN:
		if (was_ptr) {
			prepend(name, "( ");
			append(name, " )");
			was_ptr = 0;
		}
		append(name, "( ... )");
		break;

	case SYM_STRUCT:
		if (name->start != name->end)
			*--name->start = ' ';
		prepend(name, "struct %s", show_ident(sym->ident));
		goto out;

	case SYM_UNION:
		if (name->start != name->end)
			*--name->start = ' ';
		prepend(name, "union %s", show_ident(sym->ident));
		goto out;

	case SYM_ENUM:
		prepend(name, "enum %s ", show_ident(sym->ident));
		break;

	case SYM_NODE:
		if (sym->ident)
			append(name, "%s", show_ident(sym->ident));
		mod |= sym->ctype.modifiers;
		combine_address_space(sym->pos, &as, sym->ctype.as);
		break;

	case SYM_BITFIELD:
		mod |= sym->ctype.modifiers;
		combine_address_space(sym->pos, &as, sym->ctype.as);
		append(name, ":%d", sym->bit_size);
		break;

	case SYM_LABEL:
		append(name, "label(%s:%p)", show_ident(sym->ident), sym);
		return;

	case SYM_ARRAY:
		mod |= sym->ctype.modifiers;
		combine_address_space(sym->pos, &as, sym->ctype.as);
		if (was_ptr) {
			prepend(name, "( ");
			append(name, " )");
			was_ptr = 0;
		}
		append(name, "[%lld]", get_expression_value(sym->array_size));
		break;

	case SYM_RESTRICT:
		if (!sym->ident) {
			restr = 1;
			break;
		}
		if (name->start != name->end)
			*--name->start = ' ';
		prepend(name, "restricted %s", show_ident(sym->ident));
		goto out;

	case SYM_FOULED:
		fouled = 1;
		break;

	default:
		if (name->start != name->end)
			*--name->start = ' ';
		prepend(name, "unknown type %d", sym->type);
		goto out;
	}

	sym = sym->ctype.base_type;
	goto deeper;

out:
	if (restr)
		prepend(name, "restricted ");
	if (fouled)
		prepend(name, "fouled ");

	// strip trailing space
	if (name->end > name->start && name->end[-1] == ' ')
		name->end--;
}

void show_type(struct symbol *sym)
{
	char array[200];
	struct type_name name;

	name.start = name.end = array+100;
	do_show_type(sym, &name);
	*name.end = 0;
	printf("%s", name.start);
}

const char *show_typename(struct symbol *sym)
{
	static char array[200];
	struct type_name name;

	name.start = name.end = array+100;
	do_show_type(sym, &name);
	*name.end = 0;
	return name.start;
}

void show_symbol(struct symbol *sym)
{
	struct symbol *type;

	if (!sym)
		return;

	if (sym->ctype.alignment)
		printf(".align %ld\n", sym->ctype.alignment);

	show_type(sym);
	type = sym->ctype.base_type;
	if (!type) {
		printf("\n");
		return;
	}

	/*
	 * Show actual implementation information
	 */
	switch (type->type) {
		struct symbol *member;

	case SYM_STRUCT:
	case SYM_UNION:
		printf(" {\n");
		FOR_EACH_PTR(type->symbol_list, member) {
			show_struct_member(member);
		} END_FOR_EACH_PTR(member);
		printf("}\n");
		break;

	case SYM_FN: {
		struct statement *stmt = type->stmt;
		printf("\n");
		if (stmt) {
			int val;
			val = show_statement(stmt);
			if (val)
				printf("\tmov.%d\t\tretval,%d\n", stmt->ret->bit_size, val);
			printf("\tret\n");
		}
		break;
	}

	default:
		printf("\n");
		break;
	}

	if (sym->initializer) {
		printf(" = \n");
		show_expression(sym->initializer);
	}
}

static int show_symbol_init(struct symbol *sym);

static int new_pseudo(void)
{
	static int nr = 0;
	return ++nr;
}

static int new_label(void)
{
	static int label = 0;
	return ++label;
}

static void show_switch_statement(struct statement *stmt)
{
	int val = show_expression(stmt->switch_expression);
	struct symbol *sym;
	printf("\tswitch v%d\n", val);

	/*
	 * Debugging only: Check that the case list is correct
	 * by printing it out.
	 *
	 * This is where a _real_ back-end would go through the
	 * cases to decide whether to use a lookup table or a
	 * series of comparisons etc
	 */
	printf("# case table:\n");
	FOR_EACH_PTR(stmt->switch_case->symbol_list, sym) {
		struct statement *case_stmt = sym->stmt;
		struct expression *expr = case_stmt->case_expression;
		struct expression *to = case_stmt->case_to;

		if (!expr) {
			printf("    default");
		} else {
			if (expr->type == EXPR_VALUE) {
				printf("    case %lld", expr->value);
				if (to) {
					if (to->type == EXPR_VALUE) {
						printf(" .. %lld", to->value);
					} else {
						printf(" .. what?");
					}
				}
			} else
				printf("    what?");
		}
		printf(": .L%p\n", sym);
	} END_FOR_EACH_PTR(sym);
	printf("# end case table\n");

	show_statement(stmt->switch_statement);

	if (stmt->switch_break->used)
		printf(".L%p:\n", stmt->switch_break);
}

static void show_symbol_decl(struct symbol_list *syms)
{
	struct symbol *sym;
	FOR_EACH_PTR(syms, sym) {
		show_symbol_init(sym);
	} END_FOR_EACH_PTR(sym);
}

static int show_return_stmt(struct statement *stmt);

/*
 * Print out a statement
 */
int show_statement(struct statement *stmt)
{
	if (!stmt)
		return 0;
	switch (stmt->type) {
	case STMT_DECLARATION:
		show_symbol_decl(stmt->declaration);
		return 0;
	case STMT_RETURN:
		return show_return_stmt(stmt);
	case STMT_COMPOUND: {
		struct statement *s;
		int last = 0;

		if (stmt->inline_fn) {
			show_statement(stmt->args);
			printf("\tbegin_inline \t%s\n", show_ident(stmt->inline_fn->ident));
		}
		FOR_EACH_PTR(stmt->stmts, s) {
			last = show_statement(s);
		} END_FOR_EACH_PTR(s);
		if (stmt->ret) {
			int addr, bits;
			printf(".L%p:\n", stmt->ret);
			addr = show_symbol_expr(stmt->ret);
			bits = stmt->ret->bit_size;
			last = new_pseudo();
			printf("\tld.%d\t\tv%d,[v%d]\n", bits, last, addr);
		}
		if (stmt->inline_fn)
			printf("\tend_inlined\t%s\n", show_ident(stmt->inline_fn->ident));
		return last;
	}

	case STMT_EXPRESSION:
		return show_expression(stmt->expression);
	case STMT_IF: {
		int val, target;
		struct expression *cond = stmt->if_conditional;

/* This is only valid if nobody can jump into the "dead" statement */
#if 0
		if (cond->type == EXPR_VALUE) {
			struct statement *s = stmt->if_true;
			if (!cond->value)
				s = stmt->if_false;
			show_statement(s);
			break;
		}
#endif
		val = show_expression(cond);
		target = new_label();
		printf("\tje\t\tv%d,.L%d\n", val, target);
		show_statement(stmt->if_true);
		if (stmt->if_false) {
			int last = new_label();
			printf("\tjmp\t\t.L%d\n", last);
			printf(".L%d:\n", target);
			target = last;
			show_statement(stmt->if_false);
		}
		printf(".L%d:\n", target);
		break;
	}
	case STMT_SWITCH:
		show_switch_statement(stmt);
		break;

	case STMT_CASE:
		printf(".L%p:\n", stmt->case_label);
		show_statement(stmt->case_statement);
		break;

	case STMT_ITERATOR: {
		struct statement  *pre_statement = stmt->iterator_pre_statement;
		struct expression *pre_condition = stmt->iterator_pre_condition;
		struct statement  *statement = stmt->iterator_statement;
		struct statement  *post_statement = stmt->iterator_post_statement;
		struct expression *post_condition = stmt->iterator_post_condition;
		int val, loop_top = 0, loop_bottom = 0;

		show_symbol_decl(stmt->iterator_syms);
		show_statement(pre_statement);
		if (pre_condition) {
			if (pre_condition->type == EXPR_VALUE) {
				if (!pre_condition->value) {
					loop_bottom = new_label();   
					printf("\tjmp\t\t.L%d\n", loop_bottom);
				}
			} else {
				loop_bottom = new_label();
				val = show_expression(pre_condition);
				printf("\tje\t\tv%d, .L%d\n", val, loop_bottom);
			}
		}
		if (!post_condition || post_condition->type != EXPR_VALUE || post_condition->value) {
			loop_top = new_label();
			printf(".L%d:\n", loop_top);
		}
		show_statement(statement);
		if (stmt->iterator_continue->used)
			printf(".L%p:\n", stmt->iterator_continue);
		show_statement(post_statement);
		if (!post_condition) {
			printf("\tjmp\t\t.L%d\n", loop_top);
		} else if (post_condition->type == EXPR_VALUE) {
			if (post_condition->value)
				printf("\tjmp\t\t.L%d\n", loop_top);
		} else {
			val = show_expression(post_condition);
			printf("\tjne\t\tv%d, .L%d\n", val, loop_top);
		}
		if (stmt->iterator_break->used)
			printf(".L%p:\n", stmt->iterator_break);
		if (loop_bottom)
			printf(".L%d:\n", loop_bottom);
		break;
	}
	case STMT_NONE:
		break;
	
	case STMT_LABEL:
		printf(".L%p:\n", stmt->label_identifier);
		show_statement(stmt->label_statement);
		break;

	case STMT_GOTO:
		if (stmt->goto_expression) {
			int val = show_expression(stmt->goto_expression);
			printf("\tgoto\t\t*v%d\n", val);
		} else {
			printf("\tgoto\t\t.L%p\n", stmt->goto_label);
		}
		break;
	case STMT_ASM:
		printf("\tasm( .... )\n");
		break;
	case STMT_CONTEXT: {
		int val = show_expression(stmt->expression);
		printf("\tcontext( %d )\n", val);
		break;
	}
	case STMT_RANGE: {
		int val = show_expression(stmt->range_expression);
		int low = show_expression(stmt->range_low);
		int high = show_expression(stmt->range_high);
		printf("\trange( %d %d-%d)\n", val, low, high); 
		break;
	}	
	}
	return 0;
}

static int show_call_expression(struct expression *expr)
{
	struct symbol *direct;
	struct expression *arg, *fn;
	int fncall, retval;
	int framesize;

	if (!expr->ctype) {
		warning(expr->pos, "\tcall with no type!");
		return 0;
	}

	framesize = 0;
	FOR_EACH_PTR_REVERSE(expr->args, arg) {
		int new = show_expression(arg);
		int size = arg->ctype->bit_size;
		printf("\tpush.%d\t\tv%d\n", size, new);
		framesize += bits_to_bytes(size);
	} END_FOR_EACH_PTR_REVERSE(arg);

	fn = expr->fn;

	/* Remove dereference, if any */
	direct = NULL;
	if (fn->type == EXPR_PREOP) {
		if (fn->unop->type == EXPR_SYMBOL) {
			struct symbol *sym = fn->unop->symbol;
			if (sym->ctype.base_type->type == SYM_FN)
				direct = sym;
		}
	}
	if (direct) {
		printf("\tcall\t\t%s\n", show_ident(direct->ident));
	} else {
		fncall = show_expression(fn);
		printf("\tcall\t\t*v%d\n", fncall);
	}
	if (framesize)
		printf("\tadd.%d\t\tvSP,vSP,$%d\n", bits_in_pointer, framesize);

	retval = new_pseudo();
	printf("\tmov.%d\t\tv%d,retval\n", expr->ctype->bit_size, retval);
	return retval;
}

static int show_comma(struct expression *expr)
{
	show_expression(expr->left);
	return show_expression(expr->right);
}

static int show_binop(struct expression *expr)
{
	int left = show_expression(expr->left);
	int right = show_expression(expr->right);
	int new = new_pseudo();
	const char *opname;
	static const char *name[] = {
		['+'] = "add", ['-'] = "sub",
		['*'] = "mul", ['/'] = "div",
		['%'] = "mod", ['&'] = "and",
		['|'] = "lor", ['^'] = "xor"
	};
	unsigned int op = expr->op;

	opname = show_special(op);
	if (op < ARRAY_SIZE(name))
		opname = name[op];
	printf("\t%s.%d\t\tv%d,v%d,v%d\n", opname,
		expr->ctype->bit_size,
		new, left, right);
	return new;
}

static int show_slice(struct expression *expr)
{
	int target = show_expression(expr->base);
	int new = new_pseudo();
	printf("\tslice.%d\t\tv%d,v%d,%d\n", expr->r_nrbits, target, new, expr->r_bitpos);
	return new;
}

static int show_regular_preop(struct expression *expr)
{
	int target = show_expression(expr->unop);
	int new = new_pseudo();
	static const char *name[] = {
		['!'] = "nonzero", ['-'] = "neg",
		['~'] = "not",
	};
	unsigned int op = expr->op;
	const char *opname;

	opname = show_special(op);
	if (op < ARRAY_SIZE(name))
		opname = name[op];
	printf("\t%s.%d\t\tv%d,v%d\n", opname, expr->ctype->bit_size, new, target);
	return new;
}

/*
 * FIXME! Not all accesses are memory loads. We should
 * check what kind of symbol is behind the dereference.
 */
static int show_address_gen(struct expression *expr)
{
	return show_expression(expr->unop);
}

static int show_load_gen(int bits, struct expression *expr, int addr)
{
	int new = new_pseudo();

	printf("\tld.%d\t\tv%d,[v%d]\n", bits, new, addr);
	return new;
}

static void show_store_gen(int bits, int value, struct expression *expr, int addr)
{
	/* FIXME!!! Bitfield store! */
	printf("\tst.%d\t\tv%d,[v%d]\n", bits, value, addr);
}

static int show_assignment(struct expression *expr)
{
	struct expression *target = expr->left;
	int val, addr, bits;

	if (!expr->ctype)
		return 0;

	bits = expr->ctype->bit_size;
	val = show_expression(expr->right);
	addr = show_address_gen(target);
	show_store_gen(bits, val, target, addr);
	return val;
}

static int show_return_stmt(struct statement *stmt)
{
	struct expression *expr = stmt->ret_value;
	struct symbol *target = stmt->ret_target;

	if (expr && expr->ctype) {
		int val = show_expression(expr);
		int bits = expr->ctype->bit_size;
		int addr = show_symbol_expr(target);
		show_store_gen(bits, val, NULL, addr);
	}
	printf("\tret\t\t(%p)\n", target);
	return 0;
}

static int show_initialization(struct symbol *sym, struct expression *expr)
{
	int val, addr, bits;

	if (!expr->ctype)
		return 0;

	bits = expr->ctype->bit_size;
	val = show_expression(expr);
	addr = show_symbol_expr(sym);
	// FIXME! The "target" expression is for bitfield store information.
	// Leave it NULL, which works fine.
	show_store_gen(bits, val, NULL, addr);
	return 0;
}

static int show_access(struct expression *expr)
{
	int addr = show_address_gen(expr);
	return show_load_gen(expr->ctype->bit_size, expr, addr);
}

static int show_inc_dec(struct expression *expr, int postop)
{
	int addr = show_address_gen(expr->unop);
	int retval, new;
	const char *opname = expr->op == SPECIAL_INCREMENT ? "add" : "sub";
	int bits = expr->ctype->bit_size;

	retval = show_load_gen(bits, expr->unop, addr);
	new = retval;
	if (postop)
		new = new_pseudo();
	printf("\t%s.%d\t\tv%d,v%d,$1\n", opname, bits, new, retval);
	show_store_gen(bits, new, expr->unop, addr);
	return retval;
}	

static int show_preop(struct expression *expr)
{
	/*
	 * '*' is an lvalue access, and is fundamentally different
	 * from an arithmetic operation. Maybe it should have an
	 * expression type of its own..
	 */
	if (expr->op == '*')
		return show_access(expr);
	if (expr->op == SPECIAL_INCREMENT || expr->op == SPECIAL_DECREMENT)
		return show_inc_dec(expr, 0);
	return show_regular_preop(expr);
}

static int show_postop(struct expression *expr)
{
	return show_inc_dec(expr, 1);
}	

static int show_symbol_expr(struct symbol *sym)
{
	int new = new_pseudo();

	if (sym->initializer && sym->initializer->type == EXPR_STRING)
		return show_string_expr(sym->initializer);

	if (sym->ctype.modifiers & (MOD_TOPLEVEL | MOD_EXTERN | MOD_STATIC)) {
		printf("\tmovi.%d\t\tv%d,$%s\n", bits_in_pointer, new, show_ident(sym->ident));
		return new;
	}
	if (sym->ctype.modifiers & MOD_ADDRESSABLE) {
		printf("\taddi.%d\t\tv%d,vFP,$%lld\n", bits_in_pointer, new, 0LL);
		return new;
	}
	printf("\taddi.%d\t\tv%d,vFP,$offsetof(%s:%p)\n", bits_in_pointer, new, show_ident(sym->ident), sym);
	return new;
}

static int show_symbol_init(struct symbol *sym)
{
	struct expression *expr = sym->initializer;

	if (expr) {
		int val, addr, bits;

		bits = expr->ctype->bit_size;
		val = show_expression(expr);
		addr = show_symbol_expr(sym);
		show_store_gen(bits, val, NULL, addr);
	}
	return 0;
}

static int show_cast_expr(struct expression *expr)
{
	struct symbol *old_type, *new_type;
	int op = show_expression(expr->cast_expression);
	int oldbits, newbits;
	int new, is_signed;

	old_type = expr->cast_expression->ctype;
	new_type = expr->cast_type;
	
	oldbits = old_type->bit_size;
	newbits = new_type->bit_size;
	if (oldbits >= newbits)
		return op;
	new = new_pseudo();
	is_signed = is_signed_type(old_type);
	if (is_signed) {
		printf("\tsext%d.%d\tv%d,v%d\n", oldbits, newbits, new, op);
	} else {
		printf("\tandl.%d\t\tv%d,v%d,$%lu\n", newbits, new, op, (1UL << oldbits)-1);
	}
	return new;
}

static int show_value(struct expression *expr)
{
	int new = new_pseudo();
	unsigned long long value = expr->value;

	printf("\tmovi.%d\t\tv%d,$%llu\n", expr->ctype->bit_size, new, value);
	return new;
}

static int show_fvalue(struct expression *expr)
{
	int new = new_pseudo();
	long double value = expr->fvalue;

	printf("\tmovf.%d\t\tv%d,$%Le\n", expr->ctype->bit_size, new, value);
	return new;
}

static int show_string_expr(struct expression *expr)
{
	int new = new_pseudo();

	printf("\tmovi.%d\t\tv%d,&%s\n", bits_in_pointer, new, show_string(expr->string));
	return new;
}

static int show_label_expr(struct expression *expr)
{
	int new = new_pseudo();
	printf("\tmovi.%d\t\tv%d,.L%p\n",bits_in_pointer, new, expr->label_symbol);
	return new;
}

static int show_conditional_expr(struct expression *expr)
{
	int cond = show_expression(expr->conditional);
	int valt = show_expression(expr->cond_true);
	int valf = show_expression(expr->cond_false);
	int new = new_pseudo();

	printf("[v%d]\tcmov.%d\t\tv%d,v%d,v%d\n", cond, expr->ctype->bit_size, new, valt, valf);
	return new;
}

static int show_statement_expr(struct expression *expr)
{
	return show_statement(expr->statement);
}

static int show_position_expr(struct expression *expr, struct symbol *base)
{
	int new = show_expression(expr->init_expr);
	struct symbol *ctype = expr->init_expr->ctype;
	int bit_offset;

	bit_offset = ctype ? ctype->bit_offset : -1;

	printf("\tinsert v%d at [%d:%d] of %s\n", new,
		expr->init_offset, bit_offset,
		show_ident(base->ident));
	return 0;
}

static int show_initializer_expr(struct expression *expr, struct symbol *ctype)
{
	struct expression *entry;

	FOR_EACH_PTR(expr->expr_list, entry) {

again:
		// Nested initializers have their positions already
		// recursively calculated - just output them too
		if (entry->type == EXPR_INITIALIZER) {
			show_initializer_expr(entry, ctype);
			continue;
		}

		// Initializer indexes and identifiers should
		// have been evaluated to EXPR_POS
		if (entry->type == EXPR_IDENTIFIER) {
			printf(" AT '%s':\n", show_ident(entry->expr_ident));
			entry = entry->ident_expression;
			goto again;
		}
			
		if (entry->type == EXPR_INDEX) {
			printf(" AT '%d..%d:\n", entry->idx_from, entry->idx_to);
			entry = entry->idx_expression;
			goto again;
		}
		if (entry->type == EXPR_POS) {
			show_position_expr(entry, ctype);
			continue;
		}
		show_initialization(ctype, entry);
	} END_FOR_EACH_PTR(entry);
	return 0;
}

int show_symbol_expr_init(struct symbol *sym)
{
	struct expression *expr = sym->initializer;

	if (expr)
		show_expression(expr);
	return show_symbol_expr(sym);
}

/*
 * Print out an expression. Return the pseudo that contains the
 * variable.
 */
int show_expression(struct expression *expr)
{
	if (!expr)
		return 0;

	if (!expr->ctype) {
		struct position *pos = &expr->pos;
		printf("\tno type at %s:%d:%d\n",
			stream_name(pos->stream),
			pos->line, pos->pos);
		return 0;
	}
		
	switch (expr->type) {
	case EXPR_CALL:
		return show_call_expression(expr);
		
	case EXPR_ASSIGNMENT:
		return show_assignment(expr);

	case EXPR_COMMA:
		return show_comma(expr);
	case EXPR_BINOP:
	case EXPR_COMPARE:
	case EXPR_LOGICAL:
		return show_binop(expr);
	case EXPR_PREOP:
		return show_preop(expr);
	case EXPR_POSTOP:
		return show_postop(expr);
	case EXPR_SYMBOL:
		return show_symbol_expr(expr->symbol);
	case EXPR_DEREF:
	case EXPR_SIZEOF:
	case EXPR_PTRSIZEOF:
	case EXPR_ALIGNOF:
	case EXPR_OFFSETOF:
		warning(expr->pos, "invalid expression after evaluation");
		return 0;
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
	case EXPR_IMPLIED_CAST:
		return show_cast_expr(expr);
	case EXPR_VALUE:
		return show_value(expr);
	case EXPR_FVALUE:
		return show_fvalue(expr);
	case EXPR_STRING:
		return show_string_expr(expr);
	case EXPR_INITIALIZER:
		return show_initializer_expr(expr, expr->ctype);
	case EXPR_SELECT:
	case EXPR_CONDITIONAL:
		return show_conditional_expr(expr);
	case EXPR_STATEMENT:
		return show_statement_expr(expr);
	case EXPR_LABEL:
		return show_label_expr(expr);
	case EXPR_SLICE:
		return show_slice(expr);

	// None of these should exist as direct expressions: they are only
	// valid as sub-expressions of initializers.
	case EXPR_POS:
		warning(expr->pos, "unable to show plain initializer position expression");
		return 0;
	case EXPR_IDENTIFIER:
		warning(expr->pos, "unable to show identifier expression");
		return 0;
	case EXPR_INDEX:
		warning(expr->pos, "unable to show index expression");
		return 0;
	case EXPR_TYPE:
		warning(expr->pos, "unable to show type expression");
		return 0;
	case EXPR_ASM_OPERAND:
		warning(expr->pos, "unable to show asm operand expression");
		return 0;
	}
	return 0;
}
