#include "smatch.h"
#include "linearize.h"

static int my_id;
static struct symbol *cur_syscall;

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

static inline void prefix() {
	printf("%s:%d %s() ", get_filename(), get_lineno(), get_function());
}

static void match_syscall_definition(struct symbol *sym)
{
	// struct symbol *arg;
	char *macro;
	char *name;
	int is_syscall = 0;

	macro = get_macro_name(sym->pos);
	if (macro &&
	    (strncmp("SYSCALL_DEFINE", macro, strlen("SYSCALL_DEFINE")) == 0 ||
	     strncmp("COMPAT_SYSCALL_DEFINE", macro, strlen("COMPAT_SYSCALL_DEFINE")) == 0))
		is_syscall = 1;

	name = get_function();
	
	/* 
	if (!option_no_db && get_state(my_id, "this_function", NULL) != &called) {
		if (name && strncmp(name, "sys_", 4) == 0)
			is_syscall = 1;
	}
	*/

	/* Ignore compat_sys b/c syzkaller doesn't fuzz these?
	if (name && strncmp(name, "compat_sys_", 11) == 0)
		is_syscall = 1;
	*/

	if (!is_syscall)
		return;
	printf("-------------------------\n");	
	printf("\nsyscall found: %s at: ", name);
	prefix(); printf("\n");
	cur_syscall = sym;

	/*
	FOR_EACH_PTR(sym->ctype.base_type->arguments, arg) {
		set_state(my_id, arg->ident->name, arg, &user_data_set);
	} END_FOR_EACH_PTR(arg);
	*/
}

static void match_after_syscall(struct symbol *sym) {
    if (cur_syscall && sym == cur_syscall) {
	printf("\n"); prefix();
	printf("exiting scope of syscall %s\n", get_function());
	printf("-------------------------\n");	
	cur_syscall = NULL;
    }
}

static void print_member_type(struct expression *expr)
{
	char *member;

	member = get_member_name(expr);
	if (!member)
		return;
	// sm_msg("info: uses %s", member);
	prefix();
	printf("info: uses %s\n", member);
	free_string(member);
}

static void match_condition(struct expression *expr) {
    if (!cur_syscall)
	return;
    
    /*
    prefix();
    printf("found conditional %s on line %d\n", expression_type_name(expr->type), get_lineno());
    printf("expr_str: %s\n", expr_to_str(expr));
    */

    /* 
    switch (expr->type) {
	case EXPR_COMPARE:
	    match_condition(expr->left);
	    match_condition(expr->right);
	    break;
	case EXPR_SYMBOL:
	    printf("symbol: %s\n", expr->symbol_name->name);
	    break;
	case EXPR_CALL:
	    break;
    }
    */

    prefix(); printf("-- condition found\n");

    if (expr->type == EXPR_COMPARE || expr->type == EXPR_BINOP
	    || expr->type == EXPR_LOGICAL
	    || expr->type == EXPR_ASSIGNMENT
	    || expr->type == EXPR_COMMA) {
	    match_condition(expr->left);
	    match_condition(expr->right);
	    return;
    }
    print_member_type(expr);

}

static void match_function_call(struct expression *expr) {
    if (!cur_syscall)
	return;
    prefix();
    printf("function call %s\n", expression_type_name(expr->type)); 
}

void check_implicit_dependencies_tester(int id)
{
    my_id = id;

    if (option_project != PROJ_KERNEL)
	return;

    add_hook(&match_syscall_definition, AFTER_DEF_HOOK);
    add_hook(&match_after_syscall, AFTER_FUNC_HOOK);
    add_hook(&match_condition, CONDITION_HOOK);
    add_hook(&match_function_call, FUNCTION_CALL_HOOK);
}

