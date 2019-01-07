
#include "token.h"
#include "parse.h"
#include "symbol.h"
#include "ast-inspect.h"
#include "expression.h"

static inline void inspect_ptr_list(AstNode *node, const char *name, void (*inspect)(AstNode *))
{
	struct ptr_list *ptrlist = node->ptr;
	void *ptr;
	int i = 0;

	node->text = g_strdup_printf("%s %s:", node->text, name);
	FOR_EACH_PTR(ptrlist, ptr) {
		char *index = g_strdup_printf("%d: ", i++);
		ast_append_child(node, index, ptr, inspect);
	} END_FOR_EACH_PTR(ptr);
}


static const char *statement_type_name(enum statement_type type)
{
	static const char *statement_type_name[] = {
		[STMT_NONE] = "STMT_NONE",
		[STMT_DECLARATION] = "STMT_DECLARATION",
		[STMT_EXPRESSION] = "STMT_EXPRESSION",
		[STMT_COMPOUND] = "STMT_COMPOUND",
		[STMT_IF] = "STMT_IF",
		[STMT_RETURN] = "STMT_RETURN",
		[STMT_CASE] = "STMT_CASE",
		[STMT_SWITCH] = "STMT_SWITCH",
		[STMT_ITERATOR] = "STMT_ITERATOR",
		[STMT_LABEL] = "STMT_LABEL",
		[STMT_GOTO] = "STMT_GOTO",
		[STMT_ASM] = "STMT_ASM",
		[STMT_CONTEXT] = "STMT_CONTEXT",
		[STMT_RANGE] = "STMT_RANGE",
	};
	return statement_type_name[type] ?: "UNKNOWN_STATEMENT_TYPE";
}

void inspect_statement(AstNode *node)
{
	struct statement *stmt = node->ptr;
	node->text = g_strdup_printf("%s %s:", node->text, statement_type_name(stmt->type));
	switch (stmt->type) {
		case STMT_COMPOUND:
			ast_append_child(node, "stmts:", stmt->stmts, inspect_statement_list);
			break;
		case STMT_EXPRESSION:
			ast_append_child(node, "expression:", stmt->expression, inspect_expression);
			break;
		case STMT_IF:
			ast_append_child(node, "conditional:", stmt->if_conditional, inspect_expression);
			ast_append_child(node, "if_true:", stmt->if_true, inspect_statement);
			ast_append_child(node, "if_false:", stmt->if_false, inspect_statement);
			break;
		case STMT_ITERATOR:
			ast_append_child(node, "break:", stmt->iterator_break, inspect_symbol);
			ast_append_child(node, "continue:", stmt->iterator_continue, inspect_symbol);
			ast_append_child(node, "pre_statement:", stmt->iterator_pre_statement,
					 inspect_statement);
			ast_append_child(node, "statement:", stmt->iterator_statement,
					 inspect_statement);
			ast_append_child(node, "post_statement:", stmt->iterator_post_statement,
					 inspect_statement);
			break;

		case STMT_SWITCH:
			ast_append_child(node, "switch_expression:", stmt->switch_expression, inspect_expression);
			ast_append_child(node, "switch_statement:", stmt->switch_statement, inspect_statement);
			ast_append_child(node, "switch_break:", stmt->switch_break, inspect_symbol);
			ast_append_child(node, "switch_case:", stmt->switch_case, inspect_symbol);
			break;
		case STMT_CASE:
			ast_append_child(node, "case_expression:", stmt->case_expression, inspect_expression);
			ast_append_child(node, "case_to:", stmt->case_to, inspect_expression);
			ast_append_child(node, "case_statement:", stmt->case_statement, inspect_statement);
			ast_append_child(node, "case_label:", stmt->case_label, inspect_symbol);
			break;
		case STMT_RETURN:
			ast_append_child(node, "ret_value:", stmt->ret_value, inspect_expression);
			ast_append_child(node, "ret_target:", stmt->ret_target, inspect_symbol);
			break;

		default:
			break;
	}
}


void inspect_statement_list(AstNode *node)
{
	inspect_ptr_list(node, "statement_list", inspect_statement);
}


static const char *symbol_type_name(enum type type)
{
	static const char *type_name[] = {
		[SYM_UNINITIALIZED] = "SYM_UNINITIALIZED",
		[SYM_PREPROCESSOR] = "SYM_PREPROCESSOR",
		[SYM_BASETYPE] = "SYM_BASETYPE",
		[SYM_NODE] = "SYM_NODE",
		[SYM_PTR] = "SYM_PTR",
		[SYM_FN] = "SYM_FN",
		[SYM_ARRAY] = "SYM_ARRAY",
		[SYM_STRUCT] = "SYM_STRUCT",
		[SYM_UNION] = "SYM_UNION",
		[SYM_ENUM] = "SYM_ENUM",
		[SYM_TYPEDEF] = "SYM_TYPEDEF",
		[SYM_TYPEOF] = "SYM_TYPEOF",
		[SYM_MEMBER] = "SYM_MEMBER",
		[SYM_BITFIELD] = "SYM_BITFIELD",
		[SYM_LABEL] = "SYM_LABEL",
		[SYM_RESTRICT] = "SYM_RESTRICT",
		[SYM_FOULED] = "SYM_FOULED",
		[SYM_KEYWORD] = "SYM_KEYWORD",
		[SYM_BAD] = "SYM_BAD",
	};
	return type_name[type] ?: "UNKNOWN_TYPE";
}


void inspect_symbol(AstNode *node)
{
	struct symbol *sym = node->ptr;
	node->text = g_strdup_printf("%s %s: %s", node->text, symbol_type_name(sym->type),
				      builtin_typename(sym) ?: show_ident(sym->ident));
	ast_append_child(node, "ctype.base_type:", sym->ctype.base_type,inspect_symbol);

	switch (sym->namespace) {
		case NS_PREPROCESSOR:
			break;
		default:
			ast_append_child(node, "arguments:", sym->arguments, inspect_symbol_list);
			ast_append_child(node, "symbol_list:", sym->symbol_list, inspect_symbol_list);
			ast_append_child(node, "stmt:", sym->stmt, inspect_statement);
			break;
	}
}


void inspect_symbol_list(AstNode *node)
{
	inspect_ptr_list(node, "symbol_list", inspect_symbol);
}


static const char *expression_type_name(enum expression_type type)
{
	static const char *expression_type_name[] = {
		[EXPR_VALUE] = "EXPR_VALUE",
		[EXPR_STRING] = "EXPR_STRING",
		[EXPR_SYMBOL] = "EXPR_SYMBOL",
		[EXPR_TYPE] = "EXPR_TYPE",
		[EXPR_BINOP] = "EXPR_BINOP",
		[EXPR_ASSIGNMENT] = "EXPR_ASSIGNMENT",
		[EXPR_LOGICAL] = "EXPR_LOGICAL",
		[EXPR_DEREF] = "EXPR_DEREF",
		[EXPR_PREOP] = "EXPR_PREOP",
		[EXPR_POSTOP] = "EXPR_POSTOP",
		[EXPR_CAST] = "EXPR_CAST",
		[EXPR_FORCE_CAST] = "EXPR_FORCE_CAST",
		[EXPR_IMPLIED_CAST] = "EXPR_IMPLIED_CAST",
		[EXPR_SIZEOF] = "EXPR_SIZEOF",
		[EXPR_ALIGNOF] = "EXPR_ALIGNOF",
		[EXPR_PTRSIZEOF] = "EXPR_PTRSIZEOF",
		[EXPR_CONDITIONAL] = "EXPR_CONDITIONAL",
		[EXPR_SELECT] = "EXPR_SELECT",
		[EXPR_STATEMENT] = "EXPR_STATEMENT",
		[EXPR_CALL] = "EXPR_CALL",
		[EXPR_COMMA] = "EXPR_COMMA",
		[EXPR_COMPARE] = "EXPR_COMPARE",
		[EXPR_LABEL] = "EXPR_LABEL",
		[EXPR_INITIALIZER] = "EXPR_INITIALIZER",
		[EXPR_IDENTIFIER] = "EXPR_IDENTIFIER",
		[EXPR_INDEX] = "EXPR_INDEX",
		[EXPR_POS] = "EXPR_POS",
		[EXPR_FVALUE] = "EXPR_FVALUE",
		[EXPR_SLICE] = "EXPR_SLICE",
		[EXPR_OFFSETOF] = "EXPR_OFFSETOF",
	};
	return expression_type_name[type] ?: "UNKNOWN_EXPRESSION_TYPE";
}

void inspect_expression(AstNode *node)
{
	struct expression *expr = node->ptr;
	node->text = g_strdup_printf("%s %s", node->text, expression_type_name(expr->type));
	switch (expr->type) {
		case EXPR_STATEMENT:
			ast_append_child(node, "statement:", expr->statement, inspect_statement);
			break;
		case EXPR_BINOP:
		case EXPR_COMMA:
		case EXPR_COMPARE:
		case EXPR_LOGICAL:
		case EXPR_ASSIGNMENT:
			ast_append_child(node, "left:", expr->left, inspect_expression);
			ast_append_child(node, "right:", expr->right, inspect_expression);
			break;

		case EXPR_CAST:
		case EXPR_FORCE_CAST:
		case EXPR_IMPLIED_CAST:
			ast_append_child(node, "cast_type:", expr->cast_type, inspect_symbol);
			ast_append_child(node, "cast_expression:", expr->cast_expression, inspect_expression);
			break;

		case EXPR_PREOP:
			ast_append_child(node, "unop:", expr->unop, inspect_expression);
			break;
		
		default:
			break;
	}
}



