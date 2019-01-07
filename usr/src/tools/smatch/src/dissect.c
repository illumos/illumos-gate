/*
 * sparse/dissect.c
 *
 * Started by Oleg Nesterov <oleg@redhat.com>
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

#include "dissect.h"

#define	U_VOID	 0x00
#define	U_SELF	((1 << U_SHIFT) - 1)
#define	U_MASK	(U_R_VAL | U_W_VAL | U_R_AOF)

#define	DO_LIST(l__, p__, expr__)		\
	do {					\
		typeof(l__->list[0]) p__;	\
		FOR_EACH_PTR(l__, p__)		\
			expr__;			\
		END_FOR_EACH_PTR(p__);		\
	} while (0)

#define	DO_2_LIST(l1__,l2__, p1__,p2__, expr__)	\
	do {					\
		typeof(l1__->list[0]) p1__;	\
		typeof(l2__->list[0]) p2__;	\
		PREPARE_PTR_LIST(l1__, p1__);	\
		FOR_EACH_PTR(l2__, p2__)	\
			expr__;			\
			NEXT_PTR_LIST(p1__);	\
		END_FOR_EACH_PTR(p2__);		\
		FINISH_PTR_LIST(p1__);		\
	} while (0)


typedef unsigned usage_t;

static struct reporter *reporter;
static struct symbol *return_type;

static void do_sym_list(struct symbol_list *list);

static struct symbol
	*base_type(struct symbol *sym),
	*do_initializer(struct symbol *type, struct expression *expr),
	*do_expression(usage_t mode, struct expression *expr),
	*do_statement(usage_t mode, struct statement *stmt);

static inline int is_ptr(struct symbol *type)
{
	return type->type == SYM_PTR || type->type == SYM_ARRAY;
}

static inline usage_t u_rval(usage_t mode)
{
	return mode & (U_R_VAL | (U_MASK << U_SHIFT))
		? U_R_VAL : 0;
}

static inline usage_t u_addr(usage_t mode)
{
	return mode = mode & U_MASK
		? U_R_AOF | (mode & U_W_AOF) : 0;
}

static usage_t u_lval(struct symbol *type)
{
	int wptr = is_ptr(type) && !(type->ctype.modifiers & MOD_CONST);
	return wptr || type == &bad_ctype
		? U_W_AOF | U_R_VAL : U_R_VAL;
}

static usage_t fix_mode(struct symbol *type, usage_t mode)
{
	mode &= (U_SELF | (U_SELF << U_SHIFT));

	switch (type->type) {
		case SYM_BASETYPE:
			if (!type->ctype.base_type)
				break;
		case SYM_ENUM:
		case SYM_BITFIELD:
			if (mode & U_MASK)
				mode &= U_SELF;
		default:

		break; case SYM_FN:
			if (mode & U_R_VAL)
				mode |= U_R_AOF;
			mode &= ~(U_R_VAL | U_W_AOF);

		break; case SYM_ARRAY:
			if (mode & (U_MASK << U_SHIFT))
				mode >>= U_SHIFT;
			else if (mode != U_W_VAL)
				mode = u_addr(mode);
	}

	if (!(mode & U_R_AOF))
		mode &= ~U_W_AOF;

	return mode;
}

static inline struct symbol *no_member(struct ident *name)
{
	static struct symbol sym = {
		.type = SYM_BAD,
	};

	sym.ctype.base_type = &bad_ctype;
	sym.ident = name;

	return &sym;
}

static struct symbol *report_member(usage_t mode, struct position *pos,
					struct symbol *type, struct symbol *mem)
{
	struct symbol *ret = mem->ctype.base_type;

	if (reporter->r_member)
		reporter->r_member(fix_mode(ret, mode), pos, type, mem);

	return ret;
}

static void report_implicit(usage_t mode, struct position *pos, struct symbol *type)
{
	if (type->type != SYM_STRUCT && type->type != SYM_UNION)
		return;

	if (!reporter->r_member)
		return;

	if (type->ident != NULL)
		reporter->r_member(mode, pos, type, NULL);

	DO_LIST(type->symbol_list, mem,
		report_implicit(mode, pos, base_type(mem)));
}

static inline struct symbol *expr_symbol(struct expression *expr)
{
	struct symbol *sym = expr->symbol;

	if (!sym) {
		sym = lookup_symbol(expr->symbol_name, NS_SYMBOL);

		if (!sym) {
			sym = alloc_symbol(expr->pos, SYM_BAD);
			bind_symbol(sym, expr->symbol_name, NS_SYMBOL);
			sym->ctype.modifiers = MOD_EXTERN;
		}
	}

	if (!sym->ctype.base_type)
		sym->ctype.base_type = &bad_ctype;

	return sym;
}

static struct symbol *report_symbol(usage_t mode, struct expression *expr)
{
	struct symbol *sym = expr_symbol(expr);
	struct symbol *ret = base_type(sym);

	if (0 && ret->type == SYM_ENUM)
		return report_member(mode, &expr->pos, ret, expr->symbol);

	if (reporter->r_symbol)
		reporter->r_symbol(fix_mode(ret, mode), &expr->pos, sym);

	return ret;
}

static inline struct ident *mk_name(struct ident *root, struct ident *node)
{
	char name[256];

	snprintf(name, sizeof(name), "%.*s:%.*s",
			root ? root->len : 0, root ? root->name : "",
			node ? node->len : 0, node ? node->name : "");

	return built_in_ident(name);
}

static void examine_sym_node(struct symbol *node, struct ident *root)
{
	struct symbol *base;
	struct ident *name;

	if (node->examined)
		return;

	node->examined = 1;
	name = node->ident;

	while ((base = node->ctype.base_type) != NULL)
		switch (base->type) {
		case SYM_TYPEOF:
			node->ctype.base_type =
				do_expression(U_VOID, base->initializer);
			break;

		case SYM_ARRAY:
			do_expression(U_R_VAL, base->array_size);
		case SYM_PTR: case SYM_FN:
			node = base;
			break;

		case SYM_STRUCT: case SYM_UNION: //case SYM_ENUM:
			if (base->evaluated)
				return;
			if (!base->symbol_list)
				return;
			base->evaluated = 1;

			if (!base->ident && name)
				base->ident = mk_name(root, name);
			if (base->ident && reporter->r_symdef)
				reporter->r_symdef(base);
			DO_LIST(base->symbol_list, mem,
				examine_sym_node(mem, base->ident ?: root));
		default:
			return;
		}
}

static struct symbol *base_type(struct symbol *sym)
{
	if (!sym)
		return &bad_ctype;

	if (sym->type == SYM_NODE)
		examine_sym_node(sym, NULL);

	return sym->ctype.base_type	// builtin_fn_type
		?: &bad_ctype;
}

static struct symbol *__lookup_member(struct symbol *type, struct ident *name, int *p_addr)
{
	struct symbol *node;
	int addr = 0;

	FOR_EACH_PTR(type->symbol_list, node)
		if (!name) {
			if (addr == *p_addr)
				return node;
		}
		else if (node->ident == NULL) {
			node = __lookup_member(node->ctype.base_type, name, NULL);
			if (node)
				goto found;
		}
		else if (node->ident == name) {
found:
			if (p_addr)
				*p_addr = addr;
			return node;
		}
		addr++;
	END_FOR_EACH_PTR(node);

	return NULL;
}

static struct symbol *lookup_member(struct symbol *type, struct ident *name, int *addr)
{
	return __lookup_member(type, name, addr)
		?: no_member(name);
}

static struct expression *peek_preop(struct expression *expr, int op)
{
	do {
		if (expr->type != EXPR_PREOP)
			break;
		if (expr->op == op)
			return expr->unop;
		if (expr->op == '(')
			expr = expr->unop;
		else
			break;
	} while (expr);

	return NULL;
}

static struct symbol *do_expression(usage_t mode, struct expression *expr)
{
	struct symbol *ret = &int_ctype;

again:
	if (expr) switch (expr->type) {
	default:
		warning(expr->pos, "bad expr->type: %d", expr->type);

	case EXPR_TYPE:		// [struct T]; Why ???
	case EXPR_VALUE:
	case EXPR_FVALUE:

	break; case EXPR_LABEL:
		ret = &label_ctype;

	break; case EXPR_STRING:
		ret = &string_ctype;

	break; case EXPR_STATEMENT:
		ret = do_statement(mode, expr->statement);

	break; case EXPR_SIZEOF: case EXPR_ALIGNOF: case EXPR_PTRSIZEOF:
		do_expression(U_VOID, expr->cast_expression);

	break; case EXPR_COMMA:
		do_expression(U_VOID, expr->left);
		ret = do_expression(mode, expr->right);

	break; case EXPR_CAST: case EXPR_FORCE_CAST: //case EXPR_IMPLIED_CAST:
		ret = base_type(expr->cast_type);
		do_initializer(ret, expr->cast_expression);

	break; case EXPR_COMPARE: case EXPR_LOGICAL:
		mode = u_rval(mode);
		do_expression(mode, expr->left);
		do_expression(mode, expr->right);

	break; case EXPR_CONDITIONAL: //case EXPR_SELECT:
		do_expression(expr->cond_true
					? U_R_VAL : U_R_VAL | mode,
				expr->conditional);
		ret = do_expression(mode, expr->cond_true);
		ret = do_expression(mode, expr->cond_false);

	break; case EXPR_CALL:
		ret = do_expression(U_R_PTR, expr->fn);
		if (is_ptr(ret))
			ret = ret->ctype.base_type;
		DO_2_LIST(ret->arguments, expr->args, arg, val,
			do_expression(u_lval(base_type(arg)), val));
		ret = ret->type == SYM_FN ? base_type(ret)
			: &bad_ctype;

	break; case EXPR_ASSIGNMENT:
		mode |= U_W_VAL | U_R_VAL;
		if (expr->op == '=')
			mode &= ~U_R_VAL;
		ret = do_expression(mode, expr->left);
		report_implicit(mode, &expr->pos, ret);
		mode = expr->op == '='
			? u_lval(ret) : U_R_VAL;
		do_expression(mode, expr->right);

	break; case EXPR_BINOP: {
		struct symbol *l, *r;
		mode |= u_rval(mode);
		l = do_expression(mode, expr->left);
		r = do_expression(mode, expr->right);
		if (expr->op != '+' && expr->op != '-')
			;
		else if (!is_ptr_type(r))
			ret = l;
		else if (!is_ptr_type(l))
			ret = r;
	}

	break; case EXPR_PREOP: case EXPR_POSTOP: {
		struct expression *unop = expr->unop;

		switch (expr->op) {
		case SPECIAL_INCREMENT:
		case SPECIAL_DECREMENT:
			mode |= U_W_VAL | U_R_VAL;
		default:
			mode |= u_rval(mode);
		case '(':
			ret = do_expression(mode, unop);

		break; case '&':
			if ((expr = peek_preop(unop, '*')))
				goto again;
			ret = alloc_symbol(unop->pos, SYM_PTR);
			ret->ctype.base_type =
				do_expression(u_addr(mode), unop);

		break; case '*':
			if ((expr = peek_preop(unop, '&')))
				goto again;
			if (mode & (U_MASK << U_SHIFT))
				mode |= U_R_VAL;
			mode <<= U_SHIFT;
			if (mode & (U_R_AOF << U_SHIFT))
				mode |= U_R_VAL;
			if (mode & (U_W_VAL << U_SHIFT))
				mode |= U_W_AOF;
			ret = do_expression(mode, unop);
			ret = is_ptr(ret) ? base_type(ret)
				: &bad_ctype;
		}
	}

	break; case EXPR_DEREF: {
		struct symbol *p_type;
		usage_t p_mode;

		p_mode = mode & U_SELF;
		if (!(mode & U_MASK) && (mode & (U_MASK << U_SHIFT)))
			p_mode = U_R_VAL;
		p_type = do_expression(p_mode, expr->deref);

		ret = report_member(mode, &expr->pos, p_type,
			lookup_member(p_type, expr->member, NULL));
	}

	break; case EXPR_OFFSETOF: {
		struct symbol *in = base_type(expr->in);

		do {
			if (expr->op == '.') {
				in = report_member(U_VOID, &expr->pos, in,
					lookup_member(in, expr->ident, NULL));
			} else {
				do_expression(U_R_VAL, expr->index);
				in = in->ctype.base_type;
			}
		} while ((expr = expr->down));
	}

	break; case EXPR_SYMBOL:
		ret = report_symbol(mode, expr);
	}

	return ret;
}

static void do_asm_xputs(usage_t mode, struct expression_list *xputs)
{
	int nr = 0;

	DO_LIST(xputs, expr,
		if (++nr % 3 == 0)
			do_expression(U_W_AOF | mode, expr));
}

static struct symbol *do_statement(usage_t mode, struct statement *stmt)
{
	struct symbol *ret = &void_ctype;

	if (stmt) switch (stmt->type) {
	default:
		warning(stmt->pos, "bad stmt->type: %d", stmt->type);

	case STMT_NONE:
	case STMT_RANGE:
	case STMT_CONTEXT:

	break; case STMT_DECLARATION:
		do_sym_list(stmt->declaration);

	break; case STMT_EXPRESSION:
		ret = do_expression(mode, stmt->expression);

	break; case STMT_RETURN:
		do_expression(u_lval(return_type), stmt->expression);

	break; case STMT_ASM:
		do_expression(U_R_VAL, stmt->asm_string);
		do_asm_xputs(U_W_VAL, stmt->asm_outputs);
		do_asm_xputs(U_R_VAL, stmt->asm_inputs);

	break; case STMT_COMPOUND: {
		int count;

		count = statement_list_size(stmt->stmts);
		DO_LIST(stmt->stmts, st,
			ret = do_statement(--count ? U_VOID : mode, st));
	}

	break; case STMT_ITERATOR:
		do_sym_list(stmt->iterator_syms);
		do_statement(U_VOID, stmt->iterator_pre_statement);
		do_expression(U_R_VAL, stmt->iterator_pre_condition);
		do_statement(U_VOID, stmt->iterator_post_statement);
		do_statement(U_VOID, stmt->iterator_statement);
		do_expression(U_R_VAL, stmt->iterator_post_condition);

	break; case STMT_IF:
		do_expression(U_R_VAL, stmt->if_conditional);
		do_statement(U_VOID, stmt->if_true);
		do_statement(U_VOID, stmt->if_false);

	break; case STMT_SWITCH:
		do_expression(U_R_VAL, stmt->switch_expression);
		do_statement(U_VOID, stmt->switch_statement);

	break; case STMT_CASE:
		do_expression(U_R_VAL, stmt->case_expression);
		do_expression(U_R_VAL, stmt->case_to);
		do_statement(U_VOID, stmt->case_statement);

	break; case STMT_GOTO:
		do_expression(U_R_PTR, stmt->goto_expression);

	break; case STMT_LABEL:
		do_statement(mode, stmt->label_statement);

	}

	return ret;
}

static struct symbol *do_initializer(struct symbol *type, struct expression *expr)
{
	struct symbol *m_type;
	struct expression *m_expr;
	int m_addr;

	if (expr) switch (expr->type) {
	default:
		do_expression(u_lval(type), expr);

	break; case EXPR_INDEX:
		do_initializer(base_type(type), expr->idx_expression);

	break; case EXPR_INITIALIZER:
		m_addr = 0;
		FOR_EACH_PTR(expr->expr_list, m_expr) {
			if (type->type == SYM_ARRAY) {
				m_type = base_type(type);
				if (m_expr->type == EXPR_INDEX)
					m_expr = m_expr->idx_expression;
			} else {
				int *m_atop = &m_addr;

				m_type = type;
				while (m_expr->type == EXPR_IDENTIFIER) {
					m_type = report_member(U_W_VAL, &m_expr->pos, m_type,
							lookup_member(m_type, m_expr->expr_ident, m_atop));
					m_expr = m_expr->ident_expression;
					m_atop = NULL;
				}

				if (m_atop) {
					m_type = report_member(U_W_VAL, &m_expr->pos, m_type,
							lookup_member(m_type, NULL, m_atop));
				}

				if (m_expr->type != EXPR_INITIALIZER)
					report_implicit(U_W_VAL, &m_expr->pos, m_type);
			}
			do_initializer(m_type, m_expr);
			m_addr++;
		} END_FOR_EACH_PTR(m_expr);
	}

	return type;
}

static inline struct symbol *do_symbol(struct symbol *sym)
{
	struct symbol *type;

	type = base_type(sym);

	if (reporter->r_symdef)
		reporter->r_symdef(sym);

	switch (type->type) {
	default:
		if (!sym->initializer)
			break;
		if (reporter->r_symbol)
			reporter->r_symbol(U_W_VAL, &sym->pos, sym);
		do_initializer(type, sym->initializer);

	break; case SYM_FN:
		do_sym_list(type->arguments);
		return_type = base_type(type);
		do_statement(U_VOID, sym->ctype.modifiers & MOD_INLINE
					? type->inline_stmt
					: type->stmt);
	}

	return type;
}

static void do_sym_list(struct symbol_list *list)
{
	DO_LIST(list, sym, do_symbol(sym));
}

void dissect(struct symbol_list *list, struct reporter *rep)
{
	reporter = rep;
	do_sym_list(list);
}
