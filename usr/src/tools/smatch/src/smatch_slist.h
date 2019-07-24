struct stree;

extern int unfree_stree;

DECLARE_PTR_LIST(state_list, struct sm_state);
DECLARE_PTR_LIST(state_list_stack, struct state_list);

struct named_stree {
	char *name;
	struct symbol *sym;
	struct stree *stree;
};
DECLARE_ALLOCATOR(named_stree);
DECLARE_PTR_LIST(named_stree_stack, struct named_stree);


extern struct state_list_stack *implied_pools;
extern int __stree_id;
extern int sm_state_counter;

const char *show_sm(struct sm_state *sm);
void __print_stree(struct stree *stree);
void add_history(struct sm_state *sm);
int cmp_tracker(const struct sm_state *a, const struct sm_state *b);
char *alloc_sname(const char *str);
struct sm_state *alloc_sm_state(int owner, const char *name,
				struct symbol *sym, struct smatch_state *state);

void free_every_single_sm_state(void);
struct sm_state *clone_sm(struct sm_state *s);
int is_merged(struct sm_state *sm);
int is_leaf(struct sm_state *sm);
struct state_list *clone_slist(struct state_list *from_slist);

int slist_has_state(struct state_list *slist, struct smatch_state *state);

int too_many_possible(struct sm_state *sm);
void add_possible_sm(struct sm_state *to, struct sm_state *new);
struct sm_state *merge_sm_states(struct sm_state *one, struct sm_state *two);
struct smatch_state *get_state_stree(struct stree *stree, int owner, const char *name,
		    struct symbol *sym);

struct sm_state *get_sm_state_stree(struct stree *stree, int owner, const char *name,
		    struct symbol *sym);

void overwrite_sm_state_stree(struct stree **stree, struct sm_state *sm);
void overwrite_sm_state_stree_stack(struct stree_stack **stack, struct sm_state *sm);
struct sm_state *set_state_stree(struct stree **stree, int owner, const char *name,
		     struct symbol *sym, struct smatch_state *state);
void set_state_stree_perm(struct stree **stree, int owner, const char *name,
		     struct symbol *sym, struct smatch_state *state);
void delete_state_stree(struct stree **stree, int owner, const char *name,
			struct symbol *sym);

void delete_state_stree_stack(struct stree_stack **stack, int owner, const char *name,
			struct symbol *sym);

void push_stree(struct stree_stack **list_stack, struct stree *stree);
struct stree *pop_stree(struct stree_stack **list_stack);
struct stree *top_stree(struct stree_stack *stack);

void free_slist(struct state_list **slist);
void free_stree_stack(struct stree_stack **stack);
void free_stack_and_strees(struct stree_stack **stree_stack);
unsigned long get_pool_count(void);

struct sm_state *set_state_stree_stack(struct stree_stack **stack, int owner, const char *name,
				struct symbol *sym, struct smatch_state *state);

struct sm_state *get_sm_state_stree_stack(struct stree_stack *stack,
				int owner, const char *name,
				struct symbol *sym);
struct smatch_state *get_state_stree_stack(struct stree_stack *stack, int owner,
				const char *name, struct symbol *sym);

int out_of_memory(void);
int low_on_memory(void);
void merge_stree(struct stree **to, struct stree *stree);
void merge_stree_no_pools(struct stree **to, struct stree *stree);
void merge_stree(struct stree **to, struct stree *right);
void merge_fake_stree(struct stree **to, struct stree *stree);
void filter_stree(struct stree **stree, struct stree *filter);
void and_stree_stack(struct stree_stack **stree_stack);

void or_stree_stack(struct stree_stack **pre_conds,
		    struct stree *cur_stree,
		    struct stree_stack **stack);

struct stree **get_named_stree(struct named_stree_stack *stack,
			       const char *name,
			       struct symbol *sym);

void overwrite_stree(struct stree *from, struct stree **to);

/* add stuff smatch_returns.c here */

void all_return_states_hook(void (*callback)(void));

void allocate_dynamic_states_array(int num_checks);
