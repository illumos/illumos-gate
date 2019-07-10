/*
 * Copyright (C) 2006 Dan Carpenter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/gpl.txt
 *
 * Copyright 2019 Joyent, Inc.
 */

#ifndef   	SMATCH_H_
# define   	SMATCH_H_

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/time.h>
#include <sqlite3.h>
#include "lib.h"
#include "allocate.h"
#include "scope.h"
#include "parse.h"
#include "expression.h"
#include "avl.h"

typedef struct {
	struct symbol *type;
	union {
		long long value;
		unsigned long long uvalue;
	};
} sval_t;

typedef long long mtag_t;

struct smatch_state {
	const char *name;
	void *data;
};
#define STATE(_x) static struct smatch_state _x = { .name = #_x }
extern struct smatch_state undefined;
extern struct smatch_state ghost;
extern struct smatch_state merged;
extern struct smatch_state true_state;
extern struct smatch_state false_state;
DECLARE_ALLOCATOR(smatch_state);

static inline void *INT_PTR(int i)
{
	return (void *)(long)i;
}

static inline int PTR_INT(void *p)
{
	return (int)(long)p;
}

struct tracker {
	char *name;
	struct symbol *sym;
	unsigned short owner;
};
DECLARE_ALLOCATOR(tracker);
DECLARE_PTR_LIST(tracker_list, struct tracker);
DECLARE_PTR_LIST(stree_stack, struct stree);

/* The first 3 struct members must match struct tracker */
struct sm_state {
	const char *name;
	struct symbol *sym;
	unsigned short owner;
	unsigned short merged:1;
	unsigned short skip_implications:1;
	unsigned int nr_children;
	unsigned int line;
  	struct smatch_state *state;
	struct stree *pool;
	struct sm_state *left;
	struct sm_state *right;
	struct state_list *possible;
};

struct var_sym {
	char *var;
	struct symbol *sym;
};
DECLARE_ALLOCATOR(var_sym);
DECLARE_PTR_LIST(var_sym_list, struct var_sym);

struct constraint {
	int op;
	int id;
};
DECLARE_PTR_LIST(constraint_list, struct constraint);

enum hook_type {
	EXPR_HOOK,
	STMT_HOOK,
	STMT_HOOK_AFTER,
	SYM_HOOK,
	STRING_HOOK,
	DECLARATION_HOOK,
	ASSIGNMENT_HOOK,
	ASSIGNMENT_HOOK_AFTER,
	RAW_ASSIGNMENT_HOOK,
	GLOBAL_ASSIGNMENT_HOOK,
	LOGIC_HOOK,
	CONDITION_HOOK,
	PRELOOP_HOOK,
	SELECT_HOOK,
	WHOLE_CONDITION_HOOK,
	FUNCTION_CALL_HOOK_BEFORE,
	FUNCTION_CALL_HOOK,
	CALL_HOOK_AFTER_INLINE,
	FUNCTION_CALL_HOOK_AFTER_DB,
	CALL_ASSIGNMENT_HOOK,
	MACRO_ASSIGNMENT_HOOK,
	BINOP_HOOK,
	OP_HOOK,
	DEREF_HOOK,
	CASE_HOOK,
	ASM_HOOK,
	CAST_HOOK,
	SIZEOF_HOOK,
	BASE_HOOK,
	FUNC_DEF_HOOK,
	AFTER_DEF_HOOK,
	END_FUNC_HOOK,
	AFTER_FUNC_HOOK,
	RETURN_HOOK,
	INLINE_FN_START,
	INLINE_FN_END,
	END_FILE_HOOK,
	NUM_HOOKS,
};

#define TRUE 1
#define FALSE 0

struct range_list;

void add_hook(void *func, enum hook_type type);
typedef struct smatch_state *(merge_func_t)(struct smatch_state *s1, struct smatch_state *s2);
typedef struct smatch_state *(unmatched_func_t)(struct sm_state *state);
void add_merge_hook(int client_id, merge_func_t *func);
void add_unmatched_state_hook(int client_id, unmatched_func_t *func);
void add_pre_merge_hook(int client_id, void (*hook)(struct sm_state *sm));
typedef void (scope_hook)(void *data);
void add_scope_hook(scope_hook *hook, void *data);
typedef void (func_hook)(const char *fn, struct expression *expr, void *data);
typedef void (implication_hook)(const char *fn, struct expression *call_expr,
				struct expression *assign_expr, void *data);
typedef void (return_implies_hook)(struct expression *call_expr,
				   int param, char *key, char *value);
typedef int (implied_return_hook)(struct expression *call_expr, void *info, struct range_list **rl);
void add_function_hook(const char *look_for, func_hook *call_back, void *data);

void add_function_assign_hook(const char *look_for, func_hook *call_back,
			      void *info);
void add_implied_return_hook(const char *look_for,
			     implied_return_hook *call_back,
			     void *info);
void add_macro_assign_hook(const char *look_for, func_hook *call_back,
			      void *info);
void add_macro_assign_hook_extra(const char *look_for, func_hook *call_back,
			      void *info);
void return_implies_state(const char *look_for, long long start, long long end,
			 implication_hook *call_back, void *info);
void select_return_states_hook(int type, return_implies_hook *callback);
void select_return_states_before(void (*fn)(void));
void select_return_states_after(void (*fn)(void));
int get_implied_return(struct expression *expr, struct range_list **rl);
void allocate_hook_memory(void);

struct modification_data {
	struct smatch_state *prev;
	struct expression *cur;
};

typedef void (modification_hook)(struct sm_state *sm, struct expression *mod_expr);
void add_modification_hook(int owner, modification_hook *call_back);
void add_modification_hook_late(int owner, modification_hook *call_back);
struct smatch_state *get_modification_state(struct expression *expr);

int outside_of_function(void);
const char *get_filename(void);
const char *get_base_file(void);
char *get_function(void);
int get_lineno(void);
extern int final_pass;
extern struct symbol *cur_func_sym;
extern int option_debug;
extern int local_debug;
extern int option_info;
extern int option_spammy;
extern int option_timeout;
extern char *trace_variable;
extern struct stree *global_states;
int is_skipped_function(void);
int is_silenced_function(void);

/* smatch_impossible.c */
int is_impossible_path(void);
void set_path_impossible(void);

extern FILE *sm_outfd;
extern FILE *sql_outfd;
extern FILE *caller_info_fd;
extern int sm_nr_checks;
extern int sm_nr_errors;
extern const char *progname;

/*
 * How to use these routines:
 *
 * sm_fatal(): an internal error of some kind that should immediately exit
 * sm_ierror(): an internal error
 * sm_perror(): an internal error from parsing input source
 * sm_error(): an error from input source
 * sm_warning(): a warning from input source
 * sm_info(): info message (from option_info)
 * sm_debug(): debug message
 * sm_msg(): other message (please avoid using this)
 */

#define sm_printf(msg...) do { if (final_pass || option_debug || local_debug) fprintf(sm_outfd, msg); } while (0)

static inline void sm_prefix(void)
{
	sm_printf("%s: %s:%d %s() ", progname, get_filename(), get_lineno(), get_function());
}

static inline void print_implied_debug_msg();

extern bool __silence_warnings_for_stmt;

#define sm_print_msg(type, msg...) \
do {                                                           \
	print_implied_debug_msg();                             \
	if (!final_pass && !option_debug && !local_debug)      \
		break;                                         \
	if (__silence_warnings_for_stmt && !option_debug && !local_debug) \
		break;					       \
	if (!option_info && is_silenced_function())	       \
		break;					       \
	sm_prefix();					       \
	if (type == 1) {				       \
		sm_printf("warn: ");			       \
		sm_nr_checks++;			    	       \
	} else if (type == 2) {				       \
		sm_printf("error: ");			       \
		sm_nr_checks++;				       \
	} else if (type == 3) {				       \
		sm_printf("parse error: ");		       \
		sm_nr_errors++;				       \
	}						       \
        sm_printf(msg);                                        \
        sm_printf("\n");                                       \
} while (0)

#define sm_msg(msg...) do { sm_print_msg(0, msg); } while (0)

#define local_debug(msg...)					\
do {								\
	if (local_debug)					\
		sm_msg(msg);					\
} while (0)

extern char *implied_debug_msg;
static inline void print_implied_debug_msg(void)
{
	static struct symbol *last_printed = NULL;

	if (!implied_debug_msg)
		return;
	if (last_printed == cur_func_sym)
		return;
	last_printed = cur_func_sym;
	sm_msg("%s", implied_debug_msg);
}

#define sm_debug(msg...) do { if (option_debug) sm_printf(msg); } while (0)

#define sm_info(msg...) do {					\
	if (option_debug || (option_info && final_pass)) {	\
		sm_prefix();					\
		sm_printf("info: ");				\
		sm_printf(msg);					\
		sm_printf("\n");				\
	}							\
} while(0)

#define sm_warning(msg...) do { sm_print_msg(1, msg); } while (0)
#define sm_error(msg...) do { sm_print_msg(2, msg); } while (0)
#define sm_perror(msg...) do { sm_print_msg(3, msg); } while (0)

static inline void sm_fatal(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(sm_outfd, fmt, args);
	va_end(args);

	fprintf(sm_outfd, "\n");

	exit(1);
}

static inline void sm_ierror(const char *fmt, ...)
{
	va_list args;

	sm_nr_errors++;

	fprintf(sm_outfd, "internal error: ");

	va_start(args, fmt);
	vfprintf(sm_outfd, fmt, args);
	va_end(args);

	fprintf(sm_outfd, "\n");
}
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

struct smatch_state *__get_state(int owner, const char *name, struct symbol *sym);
struct smatch_state *get_state(int owner, const char *name, struct symbol *sym);
struct smatch_state *get_state_expr(int owner, struct expression *expr);
struct state_list *get_possible_states(int owner, const char *name,
				       struct symbol *sym);
struct state_list *get_possible_states_expr(int owner, struct expression *expr);
struct sm_state *set_state(int owner, const char *name, struct symbol *sym,
	       struct smatch_state *state);
struct sm_state *set_state_expr(int owner, struct expression *expr,
		struct smatch_state *state);
void delete_state(int owner, const char *name, struct symbol *sym);
void delete_state_expr(int owner, struct expression *expr);
void __delete_all_states_sym(struct symbol *sym);
void set_true_false_states(int owner, const char *name, struct symbol *sym,
			   struct smatch_state *true_state,
			   struct smatch_state *false_state);
void set_true_false_states_expr(int owner, struct expression *expr,
			   struct smatch_state *true_state,
			   struct smatch_state *false_state);

struct stree *get_all_states_from_stree(int owner, struct stree *source);
struct stree *get_all_states_stree(int id);
struct stree *__get_cur_stree(void);
int is_reachable(void);
void add_get_state_hook(void (*fn)(int owner, const char *name, struct symbol *sym));

/* smatch_helper.c */
DECLARE_PTR_LIST(int_stack, int);
char *alloc_string(const char *str);
void free_string(char *str);
void append(char *dest, const char *data, int buff_len);
void remove_parens(char *str);
struct smatch_state *alloc_state_num(int num);
struct smatch_state *alloc_state_str(const char *name);
struct smatch_state *alloc_state_expr(struct expression *expr);
struct expression *get_argument_from_call_expr(struct expression_list *args,
					       int num);

char *expr_to_var(struct expression *expr);
struct symbol *expr_to_sym(struct expression *expr);
char *expr_to_str(struct expression *expr);
char *expr_to_str_sym(struct expression *expr,
				     struct symbol **sym_ptr);
char *expr_to_var_sym(struct expression *expr,
			     struct symbol **sym_ptr);
char *expr_to_known_chunk_sym(struct expression *expr, struct symbol **sym);
char *expr_to_chunk_sym_vsl(struct expression *expr, struct symbol **sym, struct var_sym_list **vsl);
int get_complication_score(struct expression *expr);

int sym_name_is(const char *name, struct expression *expr);
int get_const_value(struct expression *expr, sval_t *sval);
int get_value(struct expression *expr, sval_t *val);
int get_implied_value(struct expression *expr, sval_t *val);
int get_implied_min(struct expression *expr, sval_t *sval);
int get_implied_max(struct expression *expr, sval_t *val);
int get_hard_max(struct expression *expr, sval_t *sval);
int get_fuzzy_min(struct expression *expr, sval_t *min);
int get_fuzzy_max(struct expression *expr, sval_t *max);
int get_absolute_min(struct expression *expr, sval_t *sval);
int get_absolute_max(struct expression *expr, sval_t *sval);
int parse_call_math(struct expression *expr, char *math, sval_t *val);
int parse_call_math_rl(struct expression *call, char *math, struct range_list **rl);
char *get_value_in_terms_of_parameter_math(struct expression *expr);
char *get_value_in_terms_of_parameter_math_var_sym(const char *var, struct symbol *sym);
int is_zero(struct expression *expr);
int known_condition_true(struct expression *expr);
int known_condition_false(struct expression *expr);
int implied_condition_true(struct expression *expr);
int implied_condition_false(struct expression *expr);
int can_integer_overflow(struct symbol *type, struct expression *expr);
void clear_math_cache(void);

int is_array(struct expression *expr);
struct expression *get_array_base(struct expression *expr);
struct expression *get_array_offset(struct expression *expr);
const char *show_state(struct smatch_state *state);
struct statement *get_expression_statement(struct expression *expr);
struct expression *strip_parens(struct expression *expr);
struct expression *strip_expr(struct expression *expr);
struct expression *strip_expr_set_parent(struct expression *expr);
void scoped_state(int my_id, const char *name, struct symbol *sym);
int is_error_return(struct expression *expr);
int getting_address(void);
int get_struct_and_member(struct expression *expr, const char **type, const char **member);
char *get_member_name(struct expression *expr);
char *get_fnptr_name(struct expression *expr);
int cmp_pos(struct position pos1, struct position pos2);
int positions_eq(struct position pos1, struct position pos2);
struct statement *get_current_statement(void);
struct statement *get_prev_statement(void);
struct expression *get_last_expr_from_expression_stmt(struct expression *expr);
int get_param_num_from_sym(struct symbol *sym);
int get_param_num(struct expression *expr);
int ms_since(struct timeval *start);
int parent_is_gone_var_sym(const char *name, struct symbol *sym);
int parent_is_gone(struct expression *expr);
int invert_op(int op);
int expr_equiv(struct expression *one, struct expression *two);
void push_int(struct int_stack **stack, int num);
int pop_int(struct int_stack **stack);

/* smatch_type.c */
struct symbol *get_real_base_type(struct symbol *sym);
int type_bytes(struct symbol *type);
int array_bytes(struct symbol *type);
struct symbol *get_pointer_type(struct expression *expr);
struct symbol *get_type(struct expression *expr);
struct symbol *get_final_type(struct expression *expr);
struct symbol *get_promoted_type(struct symbol *left, struct symbol *right);
int type_signed(struct symbol *base_type);
int expr_unsigned(struct expression *expr);
int expr_signed(struct expression *expr);
int returns_unsigned(struct symbol *base_type);
int is_pointer(struct expression *expr);
int returns_pointer(struct symbol *base_type);
sval_t sval_type_max(struct symbol *base_type);
sval_t sval_type_min(struct symbol *base_type);
int nr_bits(struct expression *expr);
int is_void_pointer(struct expression *expr);
int is_char_pointer(struct expression *expr);
int is_string(struct expression *expr);
int is_static(struct expression *expr);
int is_local_variable(struct expression *expr);
int types_equiv(struct symbol *one, struct symbol *two);
int fn_static(void);
const char *global_static();
struct symbol *cur_func_return_type(void);
struct symbol *get_arg_type(struct expression *fn, int arg);
struct symbol *get_member_type_from_key(struct expression *expr, const char *key);
struct symbol *get_arg_type_from_key(struct expression *fn, int param, struct expression *arg, const char *key);
int is_struct(struct expression *expr);
char *type_to_str(struct symbol *type);

/* smatch_ignore.c */
void add_ignore(int owner, const char *name, struct symbol *sym);
int is_ignored(int owner, const char *name, struct symbol *sym);
void add_ignore_expr(int owner, struct expression *expr);
int is_ignored_expr(int owner, struct expression *expr);

/* smatch_var_sym */
struct var_sym *alloc_var_sym(const char *var, struct symbol *sym);
struct var_sym_list *expr_to_vsl(struct expression *expr);
void add_var_sym(struct var_sym_list **list, const char *var, struct symbol *sym);
void add_var_sym_expr(struct var_sym_list **list, struct expression *expr);
void del_var_sym(struct var_sym_list **list, const char *var, struct symbol *sym);
int in_var_sym_list(struct var_sym_list *list, const char *var, struct symbol *sym);
struct var_sym_list *clone_var_sym_list(struct var_sym_list *from_vsl);
void merge_var_sym_list(struct var_sym_list **dest, struct var_sym_list *src);
struct var_sym_list *combine_var_sym_lists(struct var_sym_list *one, struct var_sym_list *two);
int var_sym_lists_equiv(struct var_sym_list *one, struct var_sym_list *two);
void free_var_sym_list(struct var_sym_list **list);
void free_var_syms_and_list(struct var_sym_list **list);

/* smatch_tracker */
struct tracker *alloc_tracker(int owner, const char *name, struct symbol *sym);
void add_tracker(struct tracker_list **list, int owner, const char *name,
		struct symbol *sym);
void add_tracker_expr(struct tracker_list **list, int owner, struct expression *expr);
void del_tracker(struct tracker_list **list, int owner, const char *name,
		struct symbol *sym);
int in_tracker_list(struct tracker_list *list, int owner, const char *name,
		struct symbol *sym);
void free_tracker_list(struct tracker_list **list);
void free_trackers_and_list(struct tracker_list **list);

/* smatch_conditions */
int in_condition(void);

/* smatch_flow.c */

extern int __in_fake_assign;
extern int __in_fake_parameter_assign;
extern int __in_fake_struct_assign;
extern int in_fake_env;
void smatch (int argc, char **argv);
int inside_loop(void);
int definitely_inside_loop(void);
struct expression *get_switch_expr(void);
int in_expression_statement(void);
void __process_post_op_stack(void);
void __split_expr(struct expression *expr);
void __split_label_stmt(struct statement *stmt);
void __split_stmt(struct statement *stmt);
extern int __in_function_def;
extern int option_assume_loops;
extern int option_two_passes;
extern int option_no_db;
extern int option_file_output;
extern int option_time;
extern struct expression_list *big_expression_stack;
extern struct expression_list *big_condition_stack;
extern struct statement_list *big_statement_stack;
int is_assigned_call(struct expression *expr);
int inlinable(struct expression *expr);
extern int __inline_call;
extern struct expression *__inline_fn;
extern int __in_pre_condition;
extern int __bail_on_rest_of_function;
extern struct statement *__prev_stmt;
extern struct statement *__cur_stmt;
extern struct statement *__next_stmt;
void init_fake_env(void);
void end_fake_env(void);
int time_parsing_function(void);

/* smatch_struct_assignment.c */
struct expression *get_faked_expression(void);
void __fake_struct_member_assignments(struct expression *expr);

/* smatch_project.c */
int is_no_inline_function(const char *function);

/* smatch_conditions */
void __split_whole_condition(struct expression *expr);
void __handle_logic(struct expression *expr);
int is_condition(struct expression *expr);
int __handle_condition_assigns(struct expression *expr);
int __handle_select_assigns(struct expression *expr);
int __handle_expr_statement_assigns(struct expression *expr);

/* smatch_implied.c */
extern int option_debug_implied;
extern int option_debug_related;
struct range_list_stack;
void param_limit_implications(struct expression *expr, int param, char *key, char *value);
struct stree *__implied_case_stree(struct expression *switch_expr,
				   struct range_list *case_rl,
				   struct range_list_stack **remaining_cases,
				   struct stree **raw_stree);
void overwrite_states_using_pool(struct sm_state *gate_sm, struct sm_state *pool_sm);
int assume(struct expression *expr);
void end_assume(void);
int impossible_assumption(struct expression *left, int op, sval_t sval);

/* smatch_extras.c */
#define SMATCH_EXTRA 5 /* this is my_id from smatch extra set in smatch.c */
extern int RETURN_ID;

struct data_range {
	sval_t min;
	sval_t max;
};

#define MTAG_ALIAS_BIT (1ULL << 63)
#define MTAG_OFFSET_MASK 0xfffULL

extern long long valid_ptr_min, valid_ptr_max;
extern sval_t valid_ptr_min_sval, valid_ptr_max_sval;
extern struct range_list *valid_ptr_rl;
static const sval_t array_min_sval = {
	.type = &ptr_ctype,
	{.value = 100000},
};
static const sval_t array_max_sval = {
	.type = &ptr_ctype,
	{.value = 199999},
};
static const sval_t text_seg_min = {
	.type = &ptr_ctype,
	{.value = 100000000},
};
static const sval_t text_seg_max = {
	.type = &ptr_ctype,
	{.value = 177777777},
};
static const sval_t data_seg_min = {
	.type = &ptr_ctype,
	{.value = 200000000},
};
static const sval_t data_seg_max = {
	.type = &ptr_ctype,
	{.value = 277777777},
};
static const sval_t bss_seg_min = {
	.type = &ptr_ctype,
	{.value = 300000000},
};
static const sval_t bss_seg_max = {
	.type = &ptr_ctype,
	{.value = 377777777},
};
static const sval_t stack_seg_min = {
	.type = &ptr_ctype,
	{.value = 400000000},
};
static const sval_t stack_seg_max = {
	.type = &ptr_ctype,
	{.value = 477777777},
};
static const sval_t kmalloc_seg_min = {
	.type = &ptr_ctype,
	{.value = 500000000},
};
static const sval_t kmalloc_seg_max = {
	.type = &ptr_ctype,
	{.value = 577777777},
};
static const sval_t vmalloc_seg_min = {
	.type = &ptr_ctype,
	{.value = 600000000},
};
static const sval_t vmalloc_seg_max = {
	.type = &ptr_ctype,
	{.value = 677777777},
};
static const sval_t fn_ptr_min = {
	.type = &ptr_ctype,
	{.value = 700000000},
};
static const sval_t fn_ptr_max = {
	.type = &ptr_ctype,
	{.value = 777777777},
};

char *get_other_name_sym(const char *name, struct symbol *sym, struct symbol **new_sym);
char *map_call_to_other_name_sym(const char *name, struct symbol *sym, struct symbol **new_sym);
char *map_long_to_short_name_sym(const char *name, struct symbol *sym, struct symbol **new_sym);
char *map_long_to_short_name_sym_nostack(const char *name, struct symbol *sym, struct symbol **new_sym);

#define STRLEN_MAX_RET 1010101

/* smatch_absolute.c */
int get_absolute_min_helper(struct expression *expr, sval_t *sval);
int get_absolute_max_helper(struct expression *expr, sval_t *sval);

/* smatch_local_values.c */
int get_local_rl(struct expression *expr, struct range_list **rl);
int get_local_max_helper(struct expression *expr, sval_t *sval);
int get_local_min_helper(struct expression *expr, sval_t *sval);

/* smatch_type_value.c */
int get_db_type_rl(struct expression *expr, struct range_list **rl);
/* smatch_data_val.c */
int get_mtag_rl(struct expression *expr, struct range_list **rl);
/* smatch_array_values.c */
int get_array_rl(struct expression *expr, struct range_list **rl);

/* smatch_states.c */
void __swap_cur_stree(struct stree *stree);
void __push_fake_cur_stree();
struct stree *__pop_fake_cur_stree();
void __free_fake_cur_stree();
void __set_fake_cur_stree_fast(struct stree *stree);
void __pop_fake_cur_stree_fast(void);
void __merge_stree_into_cur(struct stree *stree);

int unreachable(void);
void __set_sm(struct sm_state *sm);
void __set_sm_cur_stree(struct sm_state *sm);
void __set_sm_fake_stree(struct sm_state *sm);
void __set_true_false_sm(struct sm_state *true_state,
			struct sm_state *false_state);
void nullify_path(void);
void __match_nullify_path_hook(const char *fn, struct expression *expr,
			       void *unused);
void __unnullify_path(void);
int __path_is_null(void);
void save_all_states(void);
void restore_all_states(void);
void free_goto_stack(void);
void clear_all_states(void);

struct sm_state *get_sm_state(int owner, const char *name,
				struct symbol *sym);
struct sm_state *get_sm_state_expr(int owner, struct expression *expr);
void __push_true_states(void);
void __use_false_states(void);
void __discard_false_states(void);
void __merge_false_states(void);
void __merge_true_states(void);

void __negate_cond_stacks(void);
void __use_pre_cond_states(void);
void __use_cond_true_states(void);
void __use_cond_false_states(void);
void __push_cond_stacks(void);
void __fold_in_set_states(void);
void __free_set_states(void);
struct stree *__copy_cond_true_states(void);
struct stree *__copy_cond_false_states(void);
struct stree *__pop_cond_true_stack(void);
struct stree *__pop_cond_false_stack(void);
void __and_cond_states(void);
void __or_cond_states(void);
void __save_pre_cond_states(void);
void __discard_pre_cond_states(void);
struct stree *__get_true_states(void);
struct stree *__get_false_states(void);
void __use_cond_states(void);
extern struct state_list *__last_base_slist;

void __push_continues(void);
void __discard_continues(void);
void __process_continues(void);
void __merge_continues(void);

void __push_breaks(void);
void __process_breaks(void);
int __has_breaks(void);
void __merge_breaks(void);
void __use_breaks(void);

void __save_switch_states(struct expression *switch_expr);
void __discard_switches(void);
int have_remaining_cases(void);
void __merge_switches(struct expression *switch_expr, struct range_list *case_rl);
void __push_default(void);
void __set_default(void);
int __pop_default(void);

void __push_conditions(void);
void __discard_conditions(void);

void __save_gotos(const char *name, struct symbol *sym);
void __merge_gotos(const char *name, struct symbol *sym);

void __print_cur_stree(void);

/* smatch_hooks.c */
void __pass_to_client(void *data, enum hook_type type);
void __pass_to_client_no_data(enum hook_type type);
void __pass_case_to_client(struct expression *switch_expr,
			   struct range_list *rl);
int __has_merge_function(int client_id);
struct smatch_state *__client_merge_function(int owner,
					     struct smatch_state *s1,
					     struct smatch_state *s2);
struct smatch_state *__client_unmatched_state_function(struct sm_state *sm);
void call_pre_merge_hook(struct sm_state *sm);
void __push_scope_hooks(void);
void __call_scope_hooks(void);

/* smatch_function_hooks.c */
void create_function_hook_hash(void);
void __match_initializer_call(struct symbol *sym);

/* smatch_db.c */
enum info_type {
	INTERNAL	= 0,
	/*
	 * Changing these numbers is a pain.  Don't do it.  If you ever use a
	 * number it can't be re-used right away so there may be gaps.
	 * We select these in order by type so if the order matters, then give
	 * it a number below 100-999,9000-9999 ranges. */

	PARAM_CLEARED	= 101,
	PARAM_LIMIT	= 103,
	PARAM_FILTER	= 104,

	PARAM_VALUE	= 1001,
	BUF_SIZE	= 1002,
	USER_DATA	= 1003,
	CAPPED_DATA	= 1004,
	RETURN_VALUE	= 1005,
	DEREFERENCE	= 1006,
	RANGE_CAP	= 1007,
	LOCK_HELD	= 1008,
	LOCK_RELEASED	= 1009,
	ABSOLUTE_LIMITS	= 1010,
	PARAM_ADD	= 1012,
	PARAM_FREED	= 1013,
	DATA_SOURCE	= 1014,
	FUZZY_MAX	= 1015,
	STR_LEN		= 1016,
	ARRAY_LEN	= 1017,
	CAPABLE		= 1018,
	NS_CAPABLE	= 1019,
	CONTAINER	= 1020,
	CASTED_CALL	= 1021,
	TYPE_LINK	= 1022,
	UNTRACKED_PARAM = 1023,
	CULL_PATH	= 1024,
	PARAM_SET	= 1025,
	PARAM_USED	= 1026,
	BYTE_UNITS      = 1027,
	COMPARE_LIMIT	= 1028,
	PARAM_COMPARE	= 1029,
	CONSTRAINT	= 1031,
	PASSES_TYPE	= 1032,
	CONSTRAINT_REQUIRED = 1033,
	NOSPEC		= 1035,
	NOSPEC_WB	= 1036,
	STMT_CNT	= 1037,
	TERMINATED	= 1038,

	/* put random temporary stuff in the 7000-7999 range for testing */
	USER_DATA3	= 8017,
	USER_DATA3_SET	= 9017,
	NO_OVERFLOW	= 8018,
	NO_OVERFLOW_SIMPLE = 8019,
	LOCKED		= 8020,
	UNLOCKED	= 8021,
	SET_FS		= 8022,
	ATOMIC_INC	= 8023,
	ATOMIC_DEC	= 8024,
	NO_SIDE_EFFECT  = 8025,
	FN_ARG_LINK	= 8028,
	DATA_VALUE	= 8029,
	ARRAYSIZE_ARG	= 8033,
	SIZEOF_ARG	= 8034,
	MEMORY_TAG	= 8036,
	MTAG_ASSIGN	= 8035,
	STRING_VALUE	= 8041,
};

extern struct sqlite3 *smatch_db;
extern struct sqlite3 *mem_db;
extern struct sqlite3 *cache_db;

void db_ignore_states(int id);
void select_caller_info_hook(void (*callback)(const char *name, struct symbol *sym, char *key, char *value), int type);
void add_member_info_callback(int owner, void (*callback)(struct expression *call, int param, char *printed_name, struct sm_state *sm));
void add_split_return_callback(void (*fn)(int return_id, char *return_ranges, struct expression *returned_expr));
void add_returned_member_callback(int owner, void (*callback)(int return_id, char *return_ranges, struct expression *expr, char *printed_name, struct smatch_state *state));
void select_call_implies_hook(int type, void (*callback)(struct expression *call, struct expression *arg, char *key, char *value));
void select_return_implies_hook(int type, void (*callback)(struct expression *call, struct expression *arg, char *key, char *value));
struct range_list *db_return_vals(struct expression *expr);
struct range_list *db_return_vals_from_str(const char *fn_name);
char *return_state_to_var_sym(struct expression *expr, int param, const char *key, struct symbol **sym);
char *get_chunk_from_key(struct expression *arg, char *key, struct symbol **sym, struct var_sym_list **vsl);
char *get_variable_from_key(struct expression *arg, const char *key, struct symbol **sym);
const char *state_name_to_param_name(const char *state_name, const char *param_name);
const char *get_param_name_var_sym(const char *name, struct symbol *sym);
const char *get_param_name(struct sm_state *sm);
const char *get_mtag_name_var_sym(const char *state_name, struct symbol *sym);
const char *get_mtag_name_expr(struct expression *expr);
char *get_data_info_name(struct expression *expr);

char *escape_newlines(const char *str);
void sql_exec(struct sqlite3 *db, int (*callback)(void*, int, char**, char**), void *data, const char *sql);

#define sql_helper(db, call_back, data, sql...)					\
do {										\
	char sql_txt[1024];							\
										\
	sqlite3_snprintf(sizeof(sql_txt), sql_txt, sql);			\
	sm_debug("debug: %s\n", sql_txt);					\
	sql_exec(db, call_back, data, sql_txt);					\
} while (0)


#define run_sql(call_back, data, sql...)					\
do {										\
	if (option_no_db)							\
		break;								\
	sql_helper(smatch_db, call_back, data, sql);				\
} while (0)

#define mem_sql(call_back, data, sql...)					\
	sql_helper(mem_db, call_back, data, sql)

#define cache_sql(call_back, data, sql...)					\
	sql_helper(cache_db, call_back, data, sql)

#define sql_insert_helper(table, db, ignore, late, values...)			\
do {										\
	struct sqlite3 *_db = db;						\
										\
	if (__inline_fn && !_db)						\
		_db = mem_db;							\
	if (_db) {								\
		char buf[1024];							\
		char *err, *p = buf;						\
		int rc;								\
										\
		p += snprintf(p, buf + sizeof(buf) - p,				\
			      "insert %sinto %s values (",			\
			      ignore ? "or ignore " : "", #table);		\
		p += snprintf(p, buf + sizeof(buf) - p, values);		\
		p += snprintf(p, buf + sizeof(buf) - p, ");");			\
		sm_debug("mem-db: %s\n", buf);					\
		rc = sqlite3_exec(_db, buf, NULL, NULL, &err);			\
		if (rc != SQLITE_OK) {						\
			sm_ierror("SQL error #2: %s", err);			\
			sm_ierror("SQL: '%s'", buf);				\
			parse_error = 1;					\
		}								\
		break;								\
	}									\
	if (option_info) {							\
		FILE *tmp_fd = sm_outfd;					\
		sm_outfd = sql_outfd;						\
		sm_prefix();							\
	        sm_printf("SQL%s: insert %sinto " #table " values(",		\
			  late ? "_late" : "", ignore ? "or ignore " : "");	\
	        sm_printf(values);						\
	        sm_printf(");\n");						\
		sm_outfd = tmp_fd;						\
	}									\
} while (0)

#define sql_insert(table, values...) sql_insert_helper(table, 0, 0, 0, values);
#define sql_insert_or_ignore(table, values...) sql_insert_helper(table, 0, 1, 0, values);
#define sql_insert_late(table, values...) sql_insert_helper(table, 0, 0, 1, values);
#define sql_insert_cache(table, values...) sql_insert_helper(table, cache_db, 1, 0, values);

char *get_static_filter(struct symbol *sym);

void sql_insert_return_states(int return_id, const char *return_ranges,
		int type, int param, const char *key, const char *value);
void sql_insert_caller_info(struct expression *call, int type, int param,
		const char *key, const char *value);
void sql_insert_function_ptr(const char *fn, const char *struct_name);
void sql_insert_return_values(const char *return_values);
void sql_insert_return_implies(int type, int param, const char *key, const char *value);
void sql_insert_function_type_size(const char *member, const char *ranges);
void sql_insert_function_type_info(int type, const char *struct_type, const char *member, const char *value);
void sql_insert_type_info(int type, const char *member, const char *value);
void sql_insert_local_values(const char *name, const char *value);
void sql_insert_function_type_value(const char *type, const char *value);
void sql_insert_function_type(int param, const char *value);
void sql_insert_parameter_name(int param, const char *value);
void sql_insert_data_info(struct expression *data, int type, const char *value);
void sql_insert_data_info_var_sym(const char *var, struct symbol *sym, int type, const char *value);
void sql_save_constraint(const char *con);
void sql_save_constraint_required(const char *data, int op, const char *limit);
void sql_copy_constraint_required(const char *new_limit, const char *old_limit);
void sql_insert_fn_ptr_data_link(const char *ptr, const char *data);
void sql_insert_fn_data_link(struct expression *fn, int type, int param, const char *key, const char *value);
void sql_insert_mtag_about(mtag_t tag, const char *left_name, const char *right_name);
void insert_mtag_data(sval_t sval, struct range_list *rl);
void sql_insert_mtag_map(mtag_t tag, int offset, mtag_t container);
void sql_insert_mtag_alias(mtag_t orig, mtag_t alias);
int mtag_map_select_container(mtag_t tag, int offset, mtag_t *container);
int mtag_map_select_tag(mtag_t container, int offset, mtag_t *tag);

void sql_select_return_states(const char *cols, struct expression *call,
	int (*callback)(void*, int, char**, char**), void *info);
void sql_select_call_implies(const char *cols, struct expression *call,
	int (*callback)(void*, int, char**, char**));

void open_smatch_db(char *db_file);

/* smatch_files.c */
int open_data_file(const char *filename);
int open_schema_file(const char *schema);
struct token *get_tokens_file(const char *filename);

/* smatch.c */
extern char *option_debug_check;
extern char *option_project_str;
extern char *bin_dir;
extern char *data_dir;
extern int option_no_data;
extern int option_full_path;
extern int option_param_mapper;
extern int option_call_tree;
extern int num_checks;

enum project_type {
	PROJ_NONE,
	PROJ_KERNEL,
	PROJ_WINE,
	PROJ_ILLUMOS_KERNEL,
	PROJ_ILLUMOS_USER,
	PROJ_UNKNOWN,
};
extern enum project_type option_project;
const char *check_name(unsigned short id);
int id_from_name(const char *name);


/* smatch_buf_size.c */
int get_array_size(struct expression *expr);
int get_array_size_bytes(struct expression *expr);
int get_array_size_bytes_min(struct expression *expr);
int get_array_size_bytes_max(struct expression *expr);
struct range_list *get_array_size_bytes_rl(struct expression *expr);
int get_real_array_size(struct expression *expr);
int last_member_is_resizable(struct symbol *type);
/* smatch_strlen.c */
int get_implied_strlen(struct expression *expr, struct range_list **rl);
int get_size_from_strlen(struct expression *expr);

/* smatch_capped.c */
int is_capped(struct expression *expr);
int is_capped_var_sym(const char *name, struct symbol *sym);

/* check_user_data.c */
int is_user_macro(struct expression *expr);
int is_user_data(struct expression *expr);
int is_capped_user_data(struct expression *expr);
int implied_user_data(struct expression *expr, struct range_list **rl);
struct stree *get_user_stree(void);
int get_user_rl(struct expression *expr, struct range_list **rl);
int get_user_rl_spammy(struct expression *expr, struct range_list **rl);
int is_user_rl(struct expression *expr);
int get_user_rl_var_sym(const char *name, struct symbol *sym, struct range_list **rl);

/* check_locking.c */
void print_held_locks();

/* check_assigned_expr.c */
struct expression *get_assigned_expr(struct expression *expr);
struct expression *get_assigned_expr_name_sym(const char *name, struct symbol *sym);
/* smatch_return_to_param.c */
void __add_return_to_param_mapping(struct expression *assign, const char *return_string);
char *map_call_to_param_name_sym(struct expression *expr, struct symbol **sym);

/* smatch_comparison.c */
struct compare_data {
	/* The ->left and ->right expression pointers might be NULL (I'm lazy) */
	struct expression *left;
	const char *left_var;
	struct var_sym_list *left_vsl;
	int comparison;
	struct expression *right;
	const char *right_var;
	struct var_sym_list *right_vsl;
};
DECLARE_ALLOCATOR(compare_data);
struct smatch_state *alloc_compare_state(
		struct expression *left,
		const char *left_var, struct var_sym_list *left_vsl,
		int comparison,
		struct expression *right,
		const char *right_var, struct var_sym_list *right_vsl);
int filter_comparison(int orig, int op);
int merge_comparisons(int one, int two);
int combine_comparisons(int left_compare, int right_compare);
int state_to_comparison(struct smatch_state *state);
struct smatch_state *merge_compare_states(struct smatch_state *s1, struct smatch_state *s2);
int get_comparison(struct expression *left, struct expression *right);
int get_comparison_strings(const char *one, const char *two);
int possible_comparison(struct expression *a, int comparison, struct expression *b);
struct state_list *get_all_comparisons(struct expression *expr);
struct state_list *get_all_possible_equal_comparisons(struct expression *expr);
void __add_return_comparison(struct expression *call, const char *range);
void __add_comparison_info(struct expression *expr, struct expression *call, const char *range);
char *get_printed_param_name(struct expression *call, const char *param_name, struct symbol *param_sym);
char *name_sym_to_param_comparison(const char *name, struct symbol *sym);
char *expr_equal_to_param(struct expression *expr, int ignore);
char *expr_lte_to_param(struct expression *expr, int ignore);
char *expr_param_comparison(struct expression *expr, int ignore);
int flip_comparison(int op);
int negate_comparison(int op);
int remove_unsigned_from_comparison(int op);
int param_compare_limit_is_impossible(struct expression *expr, int left_param, char *left_key, char *value);
void filter_by_comparison(struct range_list **rl, int comparison, struct range_list *right);
struct sm_state *comparison_implication_hook(struct expression *expr,
			struct state_list **true_stack,
			struct state_list **false_stack);
void __compare_param_limit_hook(struct expression *left_expr, struct expression *right_expr,
				const char *state_name,
				struct smatch_state *true_state, struct smatch_state *false_state);
int impossibly_high_comparison(struct expression *expr);

/* smatch_sval.c */
sval_t *sval_alloc(sval_t sval);
sval_t *sval_alloc_permanent(sval_t sval);
sval_t sval_blank(struct expression *expr);
sval_t sval_type_val(struct symbol *type, long long val);
sval_t sval_from_val(struct expression *expr, long long val);
int sval_is_ptr(sval_t sval);
int sval_unsigned(sval_t sval);
int sval_signed(sval_t sval);
int sval_bits(sval_t sval);
int sval_bits_used(sval_t sval);
int sval_is_negative(sval_t sval);
int sval_is_positive(sval_t sval);
int sval_is_min(sval_t sval);
int sval_is_max(sval_t sval);
int sval_is_a_min(sval_t sval);
int sval_is_a_max(sval_t sval);
int sval_is_negative_min(sval_t sval);
int sval_cmp_t(struct symbol *type, sval_t one, sval_t two);
int sval_cmp_val(sval_t one, long long val);
sval_t sval_min(sval_t one, sval_t two);
sval_t sval_max(sval_t one, sval_t two);
int sval_too_low(struct symbol *type, sval_t sval);
int sval_too_high(struct symbol *type, sval_t sval);
int sval_fits(struct symbol *type, sval_t sval);
sval_t sval_cast(struct symbol *type, sval_t sval);
sval_t sval_preop(sval_t sval, int op);
sval_t sval_binop(sval_t left, int op, sval_t right);
int sval_binop_overflows(sval_t left, int op, sval_t right);
int sval_binop_overflows_no_sign(sval_t left, int op, sval_t right);
unsigned long long fls_mask(unsigned long long uvalue);
unsigned long long sval_fls_mask(sval_t sval);
const char *sval_to_str(sval_t sval);
const char *sval_to_numstr(sval_t sval);
sval_t ll_to_sval(long long val);

/* smatch_string_list.c */
int list_has_string(struct string_list *str_list, const char *str);
void insert_string(struct string_list **str_list, const char *str);
struct string_list *clone_str_list(struct string_list *orig);
struct string_list *combine_string_lists(struct string_list *one, struct string_list *two);

/* smatch_start_states.c */
struct stree *get_start_states(void);

/* smatch_recurse.c */
int has_symbol(struct expression *expr, struct symbol *sym);
int has_variable(struct expression *expr, struct expression *var);
int has_inc_dec(struct expression *expr);

/* smatch_stored_conditions.c */
struct smatch_state *get_stored_condition(struct expression *expr);
struct expression_list *get_conditions(struct expression *expr);
struct sm_state *stored_condition_implication_hook(struct expression *expr,
			struct state_list **true_stack,
			struct state_list **false_stack);

/* check_string_len.c */
int get_formatted_string_size(struct expression *call, int arg);

/* smatch_param_set.c */
int param_was_set(struct expression *expr);
int param_was_set_var_sym(const char *name, struct symbol *sym);
/* smatch_param_filter.c */
int param_has_filter_data(struct sm_state *sm);

/* smatch_links.c */
void set_up_link_functions(int id, int linkid);
struct smatch_state *merge_link_states(struct smatch_state *s1, struct smatch_state *s2);
void store_link(int link_id, const char *name, struct symbol *sym, const char *link_name, struct symbol *link_sym);

/* smatch_auto_copy.c */
void set_auto_copy(int owner);

/* check_buf_comparison */
struct expression *get_size_variable(struct expression *buf);
struct expression *get_array_variable(struct expression *size);

/* smatch_untracked_param.c */
void mark_untracked(struct expression *expr, int param, const char *key, const char *value);
void add_untracked_param_hook(void (func)(struct expression *call, int param));
void mark_all_params_untracked(int return_id, char *return_ranges, struct expression *expr);

/* smatch_strings.c */
struct state_list *get_strings(struct expression *expr);
struct expression *fake_string_from_mtag(mtag_t tag);

/* smatch_estate.c */
int estate_get_single_value(struct smatch_state *state, sval_t *sval);

/* smatch_address.c */
int get_address_rl(struct expression *expr, struct range_list **rl);
int get_member_offset(struct symbol *type, const char *member_name);
int get_member_offset_from_deref(struct expression *expr);

/* for now this is in smatch_used_parameter.c */
void __get_state_hook(int owner, const char *name, struct symbol *sym);

/* smatch_buf_comparison.c */
int db_var_is_array_limit(struct expression *array, const char *name, struct var_sym_list *vsl);

struct stree *get_all_return_states(void);
struct stree_stack *get_all_return_strees(void);
int on_atomic_dec_path(void);
int was_inced(const char *name, struct symbol *sym);

/* smatch_constraints.c */
char *get_constraint_str(struct expression *expr);
struct constraint_list *get_constraints(struct expression *expr);
char *unmet_constraint(struct expression *data, struct expression *offset);
char *get_required_constraint(const char *data_str);

/* smatch_container_of.c */
int get_param_from_container_of(struct expression *expr);
int get_offset_from_container_of(struct expression *expr);

/* smatch_mtag.c */
int get_string_mtag(struct expression *expr, mtag_t *tag);
int get_toplevel_mtag(struct symbol *sym, mtag_t *tag);
int get_mtag(struct expression *expr, mtag_t *tag);
int get_mtag_offset(struct expression *expr, mtag_t *tag, int *offset);
int create_mtag_alias(mtag_t tag, struct expression *expr, mtag_t *new);
int expr_to_mtag_offset(struct expression *expr, mtag_t *tag, int *offset);
void update_mtag_data(struct expression *expr);
int get_mtag_sval(struct expression *expr, sval_t *sval);
int get_mtag_addr_sval(struct expression *expr, sval_t *sval);

/* Trinity fuzzer stuff */
const char *get_syscall_arg_type(struct symbol *sym);

/* smatch_mem_tracker.c */
extern int option_mem;
unsigned long get_max_memory(void);

/* check_is_nospec.c */
bool is_nospec(struct expression *expr);

/* smatch_nul_terminator.c */
bool is_nul_terminated(struct expression *expr);

static inline int type_bits(struct symbol *type)
{
	if (!type)
		return 0;
	if (type->type == SYM_PTR)  /* Sparse doesn't set this for &pointers */
		return bits_in_pointer;
	if (type->type == SYM_ARRAY)
		return bits_in_pointer;
	if (!type->examined)
		examine_symbol_type(type);
	return type->bit_size;
}

static inline bool type_is_ptr(struct symbol *type)
{
	return type && (type->type == SYM_PTR || type->type == SYM_ARRAY);
}

static inline int type_unsigned(struct symbol *base_type)
{
	if (!base_type)
		return 0;
	if (base_type->ctype.modifiers & MOD_UNSIGNED)
		return 1;
	return 0;
}

static inline int type_positive_bits(struct symbol *type)
{
	if (!type)
		return 0;
	if (type->type == SYM_ARRAY)
		return bits_in_pointer - 1;
	if (type_unsigned(type))
		return type_bits(type);
	return type_bits(type) - 1;
}

static inline int sval_positive_bits(sval_t sval)
{
	return type_positive_bits(sval.type);
}

/*
 * Returns -1 if one is smaller, 0 if they are the same and 1 if two is larger.
 */
static inline int sval_cmp(sval_t one, sval_t two)
{
	struct symbol *type;

	type = one.type;
	if (sval_positive_bits(two) > sval_positive_bits(one))
		type = two.type;
	if (type_bits(type) < 31)
		type = &int_ctype;

	one = sval_cast(type, one);
	two = sval_cast(type, two);

	if (type_unsigned(type)) {
		if (one.uvalue < two.uvalue)
			return -1;
		if (one.uvalue == two.uvalue)
			return 0;
		return 1;
	}
	/* fix me handle type promotion and unsigned values */
	if (one.value < two.value)
		return -1;
	if (one.value == two.value)
		return 0;
	return 1;
}

#endif 	    /* !SMATCH_H_ */
