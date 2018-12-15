#include "smatch.h"
#include "smatch_extra.h"

DECLARE_ALLOCATOR(sname);
__ALLOCATOR(struct expression, "temporary expr", tmp_expression);

static struct position get_cur_pos(void)
{
	static struct position pos;
	static struct position none;
	struct expression *expr;
	struct statement *stmt;

	expr = last_ptr_list((struct ptr_list *)big_expression_stack);
	stmt = last_ptr_list((struct ptr_list *)big_statement_stack);
	if (expr)
		pos = expr->pos;
	else if (stmt)
		pos = stmt->pos;
	else
		pos = none;
	return pos;
}

struct expression *alloc_tmp_expression(struct position pos, int type)
{
	struct expression *expr;

	expr = __alloc_tmp_expression(0);
	expr->smatch_flags |= Fake;
	expr->type = type;
	expr->pos = pos;
	return expr;
}

void free_tmp_expressions(void)
{
	clear_tmp_expression_alloc();
}

struct expression *zero_expr(void)
{
	struct expression *zero;

	zero = alloc_tmp_expression(get_cur_pos(), EXPR_VALUE);
	zero->value = 0;
	zero->ctype = &int_ctype;
	return zero;
}

struct expression *value_expr(long long val)
{
	struct expression *expr;

	if (!val)
		return zero_expr();

	expr = alloc_tmp_expression(get_cur_pos(), EXPR_VALUE);
	expr->value = val;
	expr->ctype = &llong_ctype;
	return expr;
}

struct expression *member_expression(struct expression *deref, int op, struct ident *member)
{
	struct expression *expr;

	expr = alloc_tmp_expression(deref->pos, EXPR_DEREF);
	expr->op = op;
	expr->deref = deref;
	expr->member = member;
	expr->member_offset = -1;
	return expr;
}

struct expression *preop_expression(struct expression *expr, int op)
{
	struct expression *preop;

	preop = alloc_tmp_expression(expr->pos, EXPR_PREOP);
	preop->unop = expr;
	preop->op = op;
	return preop;
}

struct expression *deref_expression(struct expression *expr)
{
	return preop_expression(expr, '*');
}

struct expression *assign_expression(struct expression *left, int op, struct expression *right)
{
	struct expression *expr;

	if (!right)
		return NULL;

	/* FIXME: make this a tmp expression. */
	expr = alloc_expression(right->pos, EXPR_ASSIGNMENT);
	expr->op = op;
	expr->left = left;
	expr->right = right;
	return expr;
}

struct expression *binop_expression(struct expression *left, int op, struct expression *right)
{
	struct expression *expr;

	expr = alloc_tmp_expression(right->pos, EXPR_BINOP);
	expr->op = op;
	expr->left = left;
	expr->right = right;
	return expr;
}

struct expression *array_element_expression(struct expression *array, struct expression *offset)
{
	struct expression *expr;

	expr = binop_expression(array, '+', offset);
	return deref_expression(expr);
}

struct expression *symbol_expression(struct symbol *sym)
{
	struct expression *expr;

	expr = alloc_tmp_expression(sym->pos, EXPR_SYMBOL);
	expr->symbol = sym;
	expr->symbol_name = sym->ident;
	return expr;
}

struct expression *compare_expression(struct expression *left, int op, struct expression *right)
{
	struct expression *expr;

	expr = alloc_tmp_expression(get_cur_pos(), EXPR_COMPARE);
	expr->op = op;
	expr->left = left;
	expr->right = right;
	return expr;
}

struct expression *string_expression(char *str)
{
	struct expression *ret;
	struct string *string;
	int len;

	len = strlen(str) + 1;
	string = (void *)__alloc_sname(4 + len);
	string->length = len;
	string->immutable = 0;
	memcpy(string->data, str, len);

	ret = alloc_tmp_expression(get_cur_pos(), EXPR_STRING);
	ret->wide = 0;
	ret->string = string;

	return ret;
}

struct expression *gen_expression_from_key(struct expression *arg, const char *key)
{
	struct expression *ret;
	struct token *token, *end;
	const char *p = key;
	char buf[4095];
	char *alloc;
	size_t len;

	/* The idea is that we can parse either $0->foo or $->foo */
	if (key[0] != '$')
		return NULL;
	p++;
	while (*p >= '0' && *p <= '9')
		p++;
	len = snprintf(buf, sizeof(buf), "%s\n", p);
	alloc = alloc_string(buf);

	token = tokenize_buffer(alloc, len, &end);
	if (!token)
		return NULL;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return NULL;
	token = token->next;

	ret = arg;
	while (token_type(token) == TOKEN_SPECIAL &&
	       token->special == SPECIAL_DEREFERENCE) {
		token = token->next;
		if (token_type(token) != TOKEN_IDENT)
			return NULL;
		ret = deref_expression(ret);
		ret = member_expression(ret, '*', token->ident);
		token = token->next;
	}

	if (token_type(token) != TOKEN_STREAMEND)
		return NULL;

	return ret;
}

void expr_set_parent_expr(struct expression *expr, struct expression *parent)
{
	if (!expr)
		return;
	if (parent->smatch_flags & Fake)
		return;

	expr->parent = (unsigned long)parent | 0x1UL;
}

void expr_set_parent_stmt(struct expression *expr, struct statement *parent)
{
	if (!expr)
		return;
	expr->parent = (unsigned long)parent;
}

struct expression *expr_get_parent_expr(struct expression *expr)
{
	if (!expr)
		return NULL;
	if (!(expr->parent & 0x1UL))
		return NULL;
	return (struct expression *)(expr->parent & ~0x1UL);
}

struct statement *expr_get_parent_stmt(struct expression *expr)
{
	if (!expr)
		return NULL;
	if (expr->parent & 0x1UL)
		return NULL;
	return (struct statement *)expr->parent;
}

