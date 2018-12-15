#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

/* If set, we ignore struct type symbols as implicit dependencies */
static int ignore_structs;

static struct symbol *cur_syscall;
/* note: cannot track return type and remove from implicit dependencies,
 * because every syscall returns a long, and we don't have a good way to know
 * whether or not this is a resource. The only example I can think of is open
 * returning a filedescriptor, so in the implicit dep parsing, we will just
 * blacklist struct fd --> file
 */
static struct symbol *cur_return_type;
static char *syscall_name;

static struct tracker_list *read_list;	// what fields does syscall branch on?
static struct tracker_list *write_list; // what fields does syscall modify?
static struct tracker_list *arg_list;	// what struct arguments does the syscall take?
static struct tracker_list *parsed_syscalls; // syscalls we have already checked

static inline void prefix(void)
{
	printf("%s:%d %s() ", get_filename(), get_lineno(), get_function());
}

static void match_syscall_definition(struct symbol *sym)
{
	struct symbol *arg;
	struct tracker *tracker;
	char *macro;
	char *name;
	int is_syscall = 0;

	macro = get_macro_name(sym->pos);
	if (macro &&
	    (strncmp("SYSCALL_DEFINE", macro, strlen("SYSCALL_DEFINE")) == 0 ||
	     strncmp("COMPAT_SYSCALL_DEFINE", macro, strlen("COMPAT_SYSCALL_DEFINE")) == 0))
		is_syscall = 1;

	name = get_function();

	if (name && strncmp(name, "sys_", 4) == 0)
		is_syscall = 1;

	if (name && strncmp(name, "compat_sys_", 11) == 0)
		is_syscall = 1;

	if (!is_syscall)
		return;

	FOR_EACH_PTR(parsed_syscalls, tracker) {
		if (tracker->sym == sym) // don't re-parse
			return;
	} END_FOR_EACH_PTR(tracker);

	syscall_name = name;
	cur_syscall = sym;

	cur_return_type = cur_func_return_type();
	if (cur_return_type && cur_return_type->ident)
		sm_msg("return type: %s\n", cur_return_type->ident->name);


	FOR_EACH_PTR(sym->ctype.base_type->arguments, arg) {
		// set_state(my_id, arg->ident->name, arg, &user_data_set);
		sm_msg("=======check_impl: arguments for call %s=========\n", syscall_name);
		if (arg->type == SYM_STRUCT)
			arg = get_real_base_type(arg);
		if (cur_return_type && cur_return_type->ident)
			sm_msg("arg type: %s\n", cur_return_type->ident->name);
		// add_tracker(&arg_list, my_id, member, arg);
		sm_msg("=================================\n");
	} END_FOR_EACH_PTR(arg);
}

static void print_read_list(void)
{
    struct tracker *tracker;
    int i = 0;

    FOR_EACH_PTR(read_list, tracker) {
	    if (i == 0)
		    sm_printf("%s read_list: [", syscall_name);
	    sm_printf("%s, ", tracker->name);
	    i++;
    } END_FOR_EACH_PTR(tracker);

    if (i > 0)
	    sm_printf("]\n");
}

static void print_write_list(void)
{
	struct tracker *tracker;
	int i = 0;

	FOR_EACH_PTR(write_list, tracker) {
		if (i == 0)
			sm_printf("%s write_list: [", syscall_name);
		sm_printf("%s, ", tracker->name);
		i++;
	} END_FOR_EACH_PTR(tracker);

	if (i > 0)
		sm_printf("]\n");
}

static void print_arg_list(void)
{
	struct tracker *tracker;
	int i = 0;

	FOR_EACH_PTR(write_list, tracker) {
		if (i == 0)
			sm_printf("%s arg_list: [", syscall_name);
		sm_printf("%s, ", tracker->name);
		i++;
	} END_FOR_EACH_PTR(tracker);

	if (i > 0)
		sm_printf("]\n");
}

static void match_after_syscall(struct symbol *sym)
{
	if (!cur_syscall || sym != cur_syscall)
		return;
	// printf("\n"); prefix();
	// printf("exiting scope of syscall %s\n", get_function());
	// printf("-------------------------\n");
	print_read_list();
	print_write_list();
	print_arg_list();
	free_trackers_and_list(&read_list);
	free_trackers_and_list(&write_list);
	free_trackers_and_list(&arg_list);
	add_tracker(&parsed_syscalls, my_id, syscall_name, sym);
	cur_syscall = NULL;
	cur_return_type = NULL;
	syscall_name = NULL;
}

static void print_read_member_type(struct expression *expr)
{
	char *member;
	struct symbol *sym;
	struct symbol *member_sym;

	member = get_member_name(expr);
	if (!member)
		return;

	sym = get_type(expr->deref);
	member_sym = get_type(expr);

	if (member_sym->type == SYM_PTR)
		member_sym = get_real_base_type(member_sym);

	/*
	if (member_sym->type == SYM_STRUCT)
		printf("found struct type %s\n", member);
	else
		printf("found non-struct type %s with enum value%d\n", member, member_sym->type);
	*/

	if (ignore_structs && member_sym->type == SYM_STRUCT) {
		// printf("ignoring %s\n", member);
		return;
	}

	add_tracker(&read_list, my_id, member, sym);
	// sm_msg("info: uses %s", member);
	// prefix();
	// printf("info: uses %s\n", member);
	free_string(member);
}

static void print_write_member_type(struct expression *expr)
{
	char *member;
	struct symbol *sym;
	struct symbol *member_sym;

	member = get_member_name(expr);
	if (!member)
		return;

	sym = get_type(expr->deref);
	member_sym = get_type(expr);

	if (member_sym->type == SYM_PTR)
		member_sym = get_real_base_type(member_sym);

	/*
	if (member_sym->type == SYM_STRUCT)
		printf("found struct type %s\n", member);
	else
		printf("found non-struct type %s with enum value%d\n", member, member_sym->type);
	*/

	if (ignore_structs && member_sym->type == SYM_STRUCT) {
		// printf("ignoring %s\n", member);
		return;
	}

	add_tracker(&write_list, my_id, member, sym);
	free_string(member);
}

static void match_condition(struct expression *expr)
{
	struct expression *arg;

	if (!cur_syscall)
		return;

	// prefix(); printf("-- condition found\n");

	if (expr->type == EXPR_COMPARE ||
	    expr->type == EXPR_BINOP ||
	    expr->type == EXPR_LOGICAL ||
	    expr->type == EXPR_ASSIGNMENT ||
	    expr->type == EXPR_COMMA) {
		match_condition(expr->left);
		match_condition(expr->right);
		return;
	}

	if (expr->type == EXPR_CALL) {
		FOR_EACH_PTR(expr->args, arg) {
			// if we find deref in conditional call,
			// mark it as a read dependency
			print_read_member_type(arg);
		} END_FOR_EACH_PTR(arg);
		return;
	}

	print_read_member_type(expr);
}


/* when we are parsing an inline function and can no longer nest,
 * assume that all struct fields passed to nested inline functions
 * are read dependencies
 */
static void match_call_info(struct expression *expr)
{
	struct expression *arg;
	int i;

	if (!__inline_fn || !cur_syscall)
		return;

	// prefix(); printf("fn: %s\n", expr->fn->symbol->ident->name);

	i = 0;
	FOR_EACH_PTR(expr->args, arg) {
		/*
		   if (arg->type == EXPR_DEREF)
		   printf("arg %d is deref\n", i);
		 */
		print_read_member_type(arg);
		i++;
	} END_FOR_EACH_PTR(arg);
}

static void match_assign_value(struct expression *expr)
{
	if (!cur_syscall)
		return;
	print_write_member_type(expr->left);
}

static void unop_expr(struct expression *expr)
{
	if (!cur_syscall)
		return;

	if (expr->op == SPECIAL_ADD_ASSIGN || expr->op == SPECIAL_INCREMENT ||
	    expr->op == SPECIAL_SUB_ASSIGN || expr->op == SPECIAL_DECREMENT ||
	    expr->op == SPECIAL_MUL_ASSIGN || expr->op == SPECIAL_DIV_ASSIGN ||
	    expr->op == SPECIAL_MOD_ASSIGN || expr->op == SPECIAL_AND_ASSIGN ||
	    expr->op == SPECIAL_OR_ASSIGN || expr->op == SPECIAL_XOR_ASSIGN ||
	    expr->op == SPECIAL_SHL_ASSIGN || expr->op == SPECIAL_SHR_ASSIGN)
		print_write_member_type(strip_expr(expr->unop));
}

void check_implicit_dependencies(int id)
{
	my_id = id;
	ignore_structs = 0;

	if (option_project != PROJ_KERNEL)
		return;
	if (!option_info)
		return;

	add_hook(&match_syscall_definition, AFTER_DEF_HOOK);
	add_hook(&match_after_syscall, AFTER_FUNC_HOOK);
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_call_info, FUNCTION_CALL_HOOK);

	/* hooks to track written fields */
	add_hook(&match_assign_value, ASSIGNMENT_HOOK_AFTER);
	add_hook(&unop_expr, OP_HOOK);
}
