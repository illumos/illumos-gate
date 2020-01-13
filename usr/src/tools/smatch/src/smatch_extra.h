/*
 * Copyright (C) 2009 Dan Carpenter.
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
 */

DECLARE_PTR_LIST(range_list, struct data_range);
DECLARE_PTR_LIST(range_list_stack, struct range_list);

struct relation {
	char *name;
	struct symbol *sym;
};

DECLARE_PTR_LIST(related_list, struct relation);

struct data_info {
	struct related_list *related;
	struct range_list *value_ranges;
	sval_t fuzzy_max;
	unsigned int hard_max:1;
	unsigned int capped:1;
	unsigned int treat_untagged:1;
};
DECLARE_ALLOCATOR(data_info);

extern struct string_list *__ignored_macros;

/* these are implemented in smatch_ranges.c */
struct range_list *rl_zero(void);
struct range_list *rl_one(void);
char *show_rl(struct range_list *list);
int str_to_comparison_arg(const char *c, struct expression *call, int *comparison, struct expression **arg);
void str_to_rl(struct symbol *type, char *value, struct range_list **rl);
void call_results_to_rl(struct expression *call, struct symbol *type, const char *value, struct range_list **rl);

struct data_range *alloc_range(sval_t min, sval_t max);
struct data_range *alloc_range_perm(sval_t min, sval_t max);

int rl_fits_in_type(struct range_list *rl, struct symbol *type);

struct range_list *alloc_rl(sval_t min, sval_t max);
struct range_list *clone_rl(struct range_list *list);
struct range_list *clone_rl_permanent(struct range_list *list);
struct range_list *alloc_whole_rl(struct symbol *type);

void add_range(struct range_list **list, sval_t min, sval_t max);
struct range_list *remove_range(struct range_list *list, sval_t min, sval_t max);
void tack_on(struct range_list **list, struct data_range *drange);

int true_comparison_range(struct data_range *left, int comparison, struct data_range *right);
int true_comparison_range_LR(int comparison, struct data_range *var, struct data_range *val, int left);
int false_comparison_range_LR(int comparison, struct data_range *var, struct data_range *val, int left);

int possibly_true(struct expression *left, int comparison, struct expression *right);
int possibly_true_rl(struct range_list *left_ranges, int comparison, struct range_list *right_ranges);
int possibly_true_rl_LR(int comparison, struct range_list *a, struct range_list *b, int left);

int possibly_false(struct expression *left, int comparison, struct expression *right);
int possibly_false_rl(struct range_list *left_ranges, int comparison, struct range_list *right_ranges);
int possibly_false_rl_LR(int comparison, struct range_list *a, struct range_list *b, int left);

int rl_has_sval(struct range_list *rl, sval_t sval);
int ranges_equiv(struct data_range *one, struct data_range *two);

bool is_err_ptr(sval_t sval);

int rl_equiv(struct range_list *one, struct range_list *two);
int is_whole_rl(struct range_list *rl);
int is_unknown_ptr(struct range_list *rl);
int is_whole_rl_non_zero(struct range_list *rl);
int estate_is_unknown(struct smatch_state *state);

sval_t rl_min(struct range_list *rl);
sval_t rl_max(struct range_list *rl);
int rl_to_sval(struct range_list *rl, sval_t *sval);
struct symbol *rl_type(struct range_list *rl);

struct range_list *rl_filter(struct range_list *rl, struct range_list *filter);
struct range_list *rl_intersection(struct range_list *one, struct range_list *two);
struct range_list *rl_union(struct range_list *one, struct range_list *two);
struct range_list *rl_binop(struct range_list *left, int op, struct range_list *right);

void push_rl(struct range_list_stack **rl_stack, struct range_list *rl);
struct range_list *pop_rl(struct range_list_stack **rl_stack);
struct range_list *top_rl(struct range_list_stack *rl_stack);
void filter_top_rl(struct range_list_stack **rl_stack, struct range_list *filter);

struct range_list *rl_truncate_cast(struct symbol *type, struct range_list *rl);
struct range_list *cast_rl(struct symbol *type, struct range_list *rl);
int get_implied_rl(struct expression *expr, struct range_list **rl);
int get_absolute_rl(struct expression *expr, struct range_list **rl);
int get_real_absolute_rl(struct expression *expr, struct range_list **rl);
struct range_list *var_to_absolute_rl(struct expression *expr);
int custom_get_absolute_rl(struct expression *expr,
			   struct range_list *(*fn)(struct expression *expr),
			   struct range_list **rl);
int get_implied_rl_var_sym(const char *var, struct symbol *sym, struct range_list **rl);
void split_comparison_rl(struct range_list *left_orig, int op, struct range_list *right_orig,
		struct range_list **left_true_rl, struct range_list **left_false_rl,
		struct range_list **right_true_rl, struct range_list **right_false_rl);

void free_data_info_allocs(void);
void free_all_rl(void);

/* smatch_estate.c */

struct smatch_state *alloc_estate_empty(void);
struct smatch_state *alloc_estate_sval(sval_t sval);
struct smatch_state *alloc_estate_range(sval_t min, sval_t max);
struct smatch_state *alloc_estate_rl(struct range_list *rl);
struct smatch_state *alloc_estate_whole(struct symbol *type);
struct smatch_state *clone_estate(struct smatch_state *state);
struct smatch_state *clone_estate_cast(struct symbol *type, struct smatch_state *state);
struct smatch_state *clone_partial_estate(struct smatch_state *state, struct range_list *rl);

struct smatch_state *merge_estates(struct smatch_state *s1, struct smatch_state *s2);

int estates_equiv(struct smatch_state *one, struct smatch_state *two);
int estate_is_whole(struct smatch_state *state);
int estate_is_empty(struct smatch_state *state);

struct range_list *estate_rl(struct smatch_state *state);
struct related_list *estate_related(struct smatch_state *state);

sval_t estate_min(struct smatch_state *state);
sval_t estate_max(struct smatch_state *state);
struct symbol *estate_type(struct smatch_state *state);

int estate_has_fuzzy_max(struct smatch_state *state);
sval_t estate_get_fuzzy_max(struct smatch_state *state);
void estate_set_fuzzy_max(struct smatch_state *state, sval_t max);
void estate_copy_fuzzy_max(struct smatch_state *new, struct smatch_state *old);
void estate_clear_fuzzy_max(struct smatch_state *state);
int estate_has_hard_max(struct smatch_state *state);
void estate_set_hard_max(struct smatch_state *state);
void estate_clear_hard_max(struct smatch_state *state);
int estate_get_hard_max(struct smatch_state *state, sval_t *sval);
bool estate_capped(struct smatch_state *state);
void estate_set_capped(struct smatch_state *state);
bool estate_treat_untagged(struct smatch_state *state);
void estate_set_treat_untagged(struct smatch_state *state);

int estate_get_single_value(struct smatch_state *state, sval_t *sval);
struct smatch_state *get_implied_estate(struct expression *expr);

struct smatch_state *estate_filter_sval(struct smatch_state *orig, sval_t filter);
struct data_info *clone_dinfo_perm(struct data_info *dinfo);
struct smatch_state *clone_estate_perm(struct smatch_state *state);

/* smatch_extra.c */
bool is_impossible_variable(struct expression *expr);
struct sm_state *get_extra_sm_state(struct expression *expr);
struct smatch_state *get_extra_state(struct expression *expr);
void call_extra_mod_hooks(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state);
void set_extra_mod(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state);
void set_extra_expr_mod(struct expression *expr, struct smatch_state *state);
void set_extra_nomod(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state);
void set_extra_nomod_vsl(const char *name, struct symbol *sym, struct var_sym_list *vsl, struct expression *expr, struct smatch_state *state);
void set_extra_expr_nomod(struct expression *expr, struct smatch_state *state);
void set_extra_mod_helper(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state);

struct data_info *get_dinfo(struct smatch_state *state);

void add_extra_mod_hook(void (*fn)(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state));
void add_extra_nomod_hook(void (*fn)(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state));
int implied_not_equal(struct expression *expr, long long val);
int implied_not_equal_name_sym(char *name, struct symbol *sym, long long val);
int parent_is_null_var_sym(const char *name, struct symbol *sym);
int parent_is_null(struct expression *expr);
int parent_is_free_var_sym_strict(const char *name, struct symbol *sym);
int parent_is_free_var_sym(const char *name, struct symbol *sym);
int parent_is_free(struct expression *expr);

struct sm_state *__extra_handle_canonical_loops(struct statement *loop, struct stree **stree);
int __iterator_unchanged(struct sm_state *sm);
void __extra_pre_loop_hook_after(struct sm_state *sm,
				struct statement *iterator,
				struct expression *condition);

/* smatch_equiv.c */
void set_equiv(struct expression *left, struct expression *right);
void set_related(struct smatch_state *estate, struct related_list *rlist);
struct related_list *get_shared_relations(struct related_list *one,
					      struct related_list *two);
struct related_list *clone_related_list(struct related_list *related);
void remove_from_equiv(const char *name, struct symbol *sym);
void remove_from_equiv_expr(struct expression *expr);
void set_equiv_state_expr(int id, struct expression *expr, struct smatch_state *state);

/* smatch_function_hooks.c */
void function_comparison(struct expression *left, int comparison, struct expression *right);

/* smatch_expressions.c */
struct expression *zero_expr();
struct expression *value_expr(long long val);
struct expression *member_expression(struct expression *deref, int op, struct ident *member);
struct expression *preop_expression(struct expression *expr, int op);
struct expression *deref_expression(struct expression *expr);
struct expression *assign_expression(struct expression *left, int op, struct expression *right);
struct expression *binop_expression(struct expression *left, int op, struct expression *right);
struct expression *array_element_expression(struct expression *array, struct expression *offset);
struct expression *symbol_expression(struct symbol *sym);
struct expression *string_expression(char *str);
struct expression *compare_expression(struct expression *left, int op, struct expression *right);
struct expression *call_expression(struct expression *fn, struct expression_list *args);
struct expression *unknown_value_expression(struct expression *expr);
int is_fake_call(struct expression *expr);
struct expression *gen_expression_from_name_sym(const char *name, struct symbol *sym);
struct expression *gen_expression_from_key(struct expression *arg, const char *key);
void free_tmp_expressions(void);
void expr_set_parent_expr(struct expression *expr, struct expression *parent);
void expr_set_parent_stmt(struct expression *expr, struct statement *parent);
struct expression *expr_get_parent_expr(struct expression *expr);
struct statement *expr_get_parent_stmt(struct expression *expr);

/* smatch_param_limit.c */
struct smatch_state *get_orig_estate(const char *name, struct symbol *sym);

/* smatch_real_absolute.c */
struct smatch_state *get_real_absolute_state(struct expression *expr);
struct smatch_state *get_real_absolute_state_var_sym(const char *name, struct symbol *sym);

/* smatch_imaginary_absolute.c */
void __save_imaginary_state(struct expression *expr, struct range_list *true_rl, struct range_list *false_rl);
int get_imaginary_absolute(struct expression *expr, struct range_list **rl);

