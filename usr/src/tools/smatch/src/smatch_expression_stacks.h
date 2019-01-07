void push_expression(struct expression_list **estack, struct expression *expr);
struct expression *pop_expression(struct expression_list **estack);
struct expression *top_expression(struct expression_list *estack);
void free_expression_stack(struct expression_list **estack);
