/*
 *   ast-model.c 
 *
 *   A custom tree model to simplify viewing of AST objects.
 *   Modify from the Gtk+ tree view tutorial, custom-list.c
 *   by Tim-Philipp Mueller < tim at centricular dot net >
 *
 *   Copyright (C) 2010 Christopher Li
 */


#include "ast-model.h"
#include "stdint.h"

/* boring declarations of local functions */

static void ast_init(AstNode *pkg_tree);
static void ast_class_init(AstNodeClass *klass);
static void ast_tree_model_init(GtkTreeModelIface *iface);
static void ast_finalize(GObject *object);
static GtkTreeModelFlags ast_get_flags(GtkTreeModel *tree_model);
static gint ast_get_n_columns(GtkTreeModel *tree_model);
static GType ast_get_column_type(GtkTreeModel *tree_model, gint index);
static gboolean ast_get_iter(GtkTreeModel *tree_model, GtkTreeIter *iter,
				  GtkTreePath *path);
static GtkTreePath *ast_get_path(GtkTreeModel *tree_model, GtkTreeIter *iter); 
static void ast_get_value(GtkTreeModel *tree_model, GtkTreeIter *iter,
			       gint column, GValue *value);
static gboolean ast_iter_next(GtkTreeModel *tree_model, GtkTreeIter *iter);
static gboolean ast_iter_children(GtkTreeModel *tree_model,
                                       GtkTreeIter *iter,
                                       GtkTreeIter *parent);
static gboolean ast_iter_has_child(GtkTreeModel *tree_model, GtkTreeIter *iter);
static gint ast_iter_n_children (GtkTreeModel *tree_model, GtkTreeIter *iter);
static gboolean ast_iter_nth_child(GtkTreeModel *tree_model, GtkTreeIter *iter,
                                        GtkTreeIter *parent, gint n);
static gboolean ast_iter_parent(GtkTreeModel *tree_model,
                                     GtkTreeIter *iter,
                                     GtkTreeIter *child);

static GObjectClass *parent_class = NULL;  /* GObject stuff - nothing to worry about */

static inline
void inspect_child_node(AstNode *node)
{
	if (node->inspect) {
		node->inspect(node);
		node->inspect = NULL;
	}
}


static inline
AstNode* ast_nth_child(AstNode *node, int n)
{
	if (!node)
		return NULL;

	inspect_child_node(node);

	if (n >= node->childnodes->len)
		return NULL;
	return g_array_index(node->childnodes, AstNode *, n);
}


static inline
gboolean ast_set_iter(GtkTreeIter *iter, AstNode *node)
{
	iter->user_data = node;
	iter->user_data2 = iter->user_data3 = NULL;
	return node != NULL;
}


/*****************************************************************************
 *
 *  ast_get_type: here we register our new type and its interfaces
 *                with the type system. If you want to implement
 *                additional interfaces like GtkTreeSortable, you
 *                will need to do it here.
 *
 *****************************************************************************/

GType
ast_get_type (void)
{
	static GType ast_type = 0;
	static const GTypeInfo ast_info = {
		sizeof (AstNodeClass),
		NULL,                                         /* base_init */
		NULL,                                         /* base_finalize */
		(GClassInitFunc) ast_class_init,
		NULL,                                         /* class finalize */
		NULL,                                         /* class_data */
		sizeof (AstNode),
		0,                                           /* n_preallocs */
		(GInstanceInitFunc) ast_init
	};
	static const GInterfaceInfo tree_model_info = {
		(GInterfaceInitFunc) ast_tree_model_init,
		NULL,
		NULL
	};



	if (ast_type)
		return ast_type;

	/* Some boilerplate type registration stuff */
	ast_type = g_type_register_static(G_TYPE_OBJECT, "AstNode",
						&ast_info, (GTypeFlags)0);

	/* Here we register our GtkTreeModel interface with the type system */
	g_type_add_interface_static(ast_type, GTK_TYPE_TREE_MODEL, &tree_model_info);

	return ast_type;
}


/*****************************************************************************
 *
 *  ast_class_init: more boilerplate GObject/GType stuff.
 *                  Init callback for the type system,
 *                  called once when our new class is created.
 *
 *****************************************************************************/

static void
ast_class_init (AstNodeClass *klass)
{
	GObjectClass *object_class;

	parent_class = (GObjectClass*) g_type_class_peek_parent (klass);
	object_class = (GObjectClass*) klass;

	object_class->finalize = ast_finalize;
}

/*****************************************************************************
 *
 *  ast_tree_model_init: init callback for the interface registration
 *                       in ast_get_type. Here we override
 *                       the GtkTreeModel interface functions that
 *                       we implement.
 *
 *****************************************************************************/

static void
ast_tree_model_init (GtkTreeModelIface *iface)
{
	iface->get_flags       = ast_get_flags;
	iface->get_n_columns   = ast_get_n_columns;
	iface->get_column_type = ast_get_column_type;
	iface->get_iter        = ast_get_iter;
	iface->get_path        = ast_get_path;
	iface->get_value       = ast_get_value;
	iface->iter_next       = ast_iter_next;
	iface->iter_children   = ast_iter_children;
	iface->iter_has_child  = ast_iter_has_child;
	iface->iter_n_children = ast_iter_n_children;
	iface->iter_nth_child  = ast_iter_nth_child;
	iface->iter_parent     = ast_iter_parent;
}


/*****************************************************************************
 *
 *  ast_init: this is called every time a new ast node object
 *            instance is created (we do that in ast_new).
 *            Initialise the list structure's fields here.
 *
 *****************************************************************************/

static void
ast_init (AstNode *node)
{
	node->childnodes = g_array_new(FALSE, TRUE, sizeof(AstNode *));
	node->stamp    = g_random_int(); /* Random int to check whether iters belong to out model */
}


/*****************************************************************************
 *
 *  ast_finalize: this is called just before an ast node is
 *                destroyed. Free dynamically allocated memory here.
 *
 *****************************************************************************/

static void
ast_finalize (GObject *object)
{
	/*  AstNode *node = AST_NODE(object); */

	/* FIXME: free all node memory */

	/* must chain up - finalize parent */
	(* parent_class->finalize) (object);
}


/*****************************************************************************
 *
 *  ast_get_flags: tells the rest of the world whether our tree model
 *                 has any special characteristics. In our case,
 *                 we have a list model (instead of a tree), and each
 *                 tree iter is valid as long as the row in question
 *                 exists, as it only contains a pointer to our struct.
 *
 *****************************************************************************/

static GtkTreeModelFlags
ast_get_flags(GtkTreeModel *tree_model)
{
	return (GTK_TREE_MODEL_ITERS_PERSIST);
}


/*****************************************************************************
 *
 *  ast_get_n_columns: tells the rest of the world how many data
 *                          columns we export via the tree model interface
 *
 *****************************************************************************/

static gint
ast_get_n_columns(GtkTreeModel *tree_model)
{
	return 1;
}


/*****************************************************************************
 *
 *  ast_get_column_type: tells the rest of the world which type of
 *                       data an exported model column contains
 *
 *****************************************************************************/

static GType
ast_get_column_type(GtkTreeModel *tree_model,
                         gint index)
{
	return G_TYPE_STRING;
}


/*****************************************************************************
 *
 *  ast_get_iter: converts a tree path (physical position) into a
 *                tree iter structure (the content of the iter
 *                fields will only be used internally by our model).
 *                We simply store a pointer to our AstNodeItem
 *                structure that represents that row in the tree iter.
 *
 *****************************************************************************/

static gboolean
ast_get_iter(GtkTreeModel *tree_model,
                  GtkTreeIter  *iter,
                  GtkTreePath  *path)
{
	AstNode    *node;
	gint          *indices, depth;
	int i;

	node = AST_NODE(tree_model);
	indices = gtk_tree_path_get_indices(path);
	depth   = gtk_tree_path_get_depth(path);

	for (i = 0; i < depth; i++)
		node = ast_nth_child(node, indices[i]);

	return ast_set_iter(iter, node);
}


/*****************************************************************************
 *
 *  ast_get_path: converts a tree iter into a tree path (ie. the
 *                physical position of that row in the list).
 *
 *****************************************************************************/

static GtkTreePath *
ast_get_path(GtkTreeModel *tree_model,
                  GtkTreeIter  *iter)
{
	GtkTreePath  *path;
	AstNode   *root = AST_NODE(tree_model);
	AstNode   *node = AST_NODE(iter->user_data);

	path = gtk_tree_path_new();
	while (node != root) {
		gtk_tree_path_prepend_index(path, node->index);
		node = node->parent;
	}
	return path;
}


/*****************************************************************************
 *
 *  ast_get_value: Returns a row's exported data columns
 *                 (_get_value is what gtk_tree_model_get uses)
 *
 *****************************************************************************/

static void
ast_get_value(GtkTreeModel *tree_model,
                   GtkTreeIter  *iter,
                   gint          column,
                   GValue       *value)
{
	AstNode    *node = iter->user_data;

	g_assert(AST_IS_NODE(tree_model));
	if (column != 1)
		return;

	inspect_child_node(node);

	g_value_init(value, G_TYPE_STRING);
	g_value_set_string(value, node->text);
	return;
}


/*****************************************************************************
 *
 *  ast_iter_next: Takes an iter structure and sets it to point
 *                 to the next row.
 *
 *****************************************************************************/

static gboolean
ast_iter_next(GtkTreeModel  *tree_model,
                   GtkTreeIter   *iter)
{
	AstNode    *node = iter->user_data;
	
	g_assert(AST_IS_NODE (tree_model));

	node = ast_nth_child(node->parent, node->index + 1);
	return ast_set_iter(iter, node);
}


/*****************************************************************************
 *
 *  ast_iter_children: Returns TRUE or FALSE depending on whether
 *                     the row specified by 'parent' has any children.
 *                     If it has children, then 'iter' is set to
 *                     point to the first child. Special case: if
 *                     'parent' is NULL, then the first top-level
 *                     row should be returned if it exists.
 *
 *****************************************************************************/

static gboolean
ast_iter_children(GtkTreeModel *tree_model,
                       GtkTreeIter  *iter,
                       GtkTreeIter  *parent)
{
	return ast_iter_nth_child(tree_model, iter, parent, 0);
}


/*****************************************************************************
 *
 *  ast_iter_has_child: Returns TRUE or FALSE depending on whether
 *                      the row specified by 'iter' has any children.
 *                      We only have a list and thus no children.
 *
 *****************************************************************************/

static gboolean
ast_iter_has_child (GtkTreeModel *tree_model,
                         GtkTreeIter  *iter)
{
	AstNode    *node = iter->user_data;
	inspect_child_node(node);
	return node->childnodes->len > 0;
}


/*****************************************************************************
 *
 *  ast_iter_n_children: Returns the number of children the row
 *                       specified by 'iter' has. This is usually 0,
 *                       as we only have a list and thus do not have
 *                       any children to any rows. A special case is
 *                       when 'iter' is NULL, in which case we need
 *                       to return the number of top-level node,
 *                       ie. the number of rows in our list.
 *
 *****************************************************************************/

static gint
ast_iter_n_children (GtkTreeModel *tree_model,
                          GtkTreeIter  *iter)
{
	AstNode  *node = iter ? iter->user_data
				: AST_NODE(tree_model);

	inspect_child_node(node);
	return node->childnodes->len;
}


/*****************************************************************************
 *
 *  ast_iter_nth_child: If the row specified by 'parent' has any
 *                      children, set 'iter' to the n-th child and
 *                      return TRUE if it exists, otherwise FALSE.
 *                      A special case is when 'parent' is NULL, in
 *                      which case we need to set 'iter' to the n-th
 *                      row if it exists.
 *
 *****************************************************************************/

static gboolean
ast_iter_nth_child(GtkTreeModel *tree_model,
                        GtkTreeIter  *iter,
                        GtkTreeIter  *parent,
                        gint          n)
{
	AstNode    *node = parent ? parent->user_data : (AstNode*) tree_model;
	GArray *array = node->childnodes;
	if (n >= array->len)
		return FALSE;
	iter->user_data = g_array_index(array, AstNode *, n);
	return TRUE;
}


/*****************************************************************************
 *
 *  ast_iter_parent: Point 'iter' to the parent node of 'child'. As
 *                   we have a list and thus no children and no
 *                   parents of children, we can just return FALSE.
 *
 *****************************************************************************/

static gboolean
ast_iter_parent (GtkTreeModel *tree_model,
                      GtkTreeIter  *iter,
                      GtkTreeIter  *child)
{
	AstNode *node = (AstNode *) child->user_data;
	iter->user_data = node->parent;
	return node->parent != NULL;
}


AstNode *
ast_new (AstNode *parent, int index, const char *text, void *ptr, void (*inspect)(AstNode*))
{
	AstNode *node = (AstNode*) g_object_new (AST_TYPE_NODE, NULL);
	g_assert(node != NULL);
	node->parent = parent;
	node->index = index;
	node->text = text;
	node->inspect = inspect;
	node->ptr = ptr;
	return node;
}

