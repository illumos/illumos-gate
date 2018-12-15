
/*
 * ast-model.h
 *
 * Copyright (C) 2010 Christopher Li.
 *
 */

#ifndef _ast_model_h_
#define _ast_model_h_

#include <stdint.h>
#include <gtk/gtk.h>
#include "lib.h"

#define AST_TYPE_NODE                  (ast_get_type ())
#define AST_NODE(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), AST_TYPE_NODE, AstNode))
#define AST_NODE_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass),  AST_TYPE_NODE, AstNodeClass))
#define AST_IS_NODE(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), AST_TYPE_NODE))
#define AST_IS_NODE_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass),  AST_TYPE_NODE))
#define AST_NODE_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj),  AST_TYPE_NODE, AstNodeClass))

enum
{
	AST_COL_RECORD = 0,
	AST_COL_NAME,
	AST_N_COLUMNS,
} ;


typedef struct AstNode AstNode;
typedef struct AstNodeClass AstNodeClass;



/* AstNode: this structure contains everything we need for our
 *             model implementation. You can add extra fields to
 *             this structure, e.g. hashtables to quickly lookup
 *             rows or whatever else you might need, but it is
 *             crucial that 'parent' is the first member of the
 *             structure.                                          */

struct AstNode
{
	GObject         base;      /* this MUST be the first member */

	AstNode	*parent;
	int index;
	const gchar *text;
	void (*inspect)(struct AstNode* node);
	void *ptr;
	GArray *childnodes;
	gint stamp;
};



/* AstNodeClass: more boilerplate GObject stuff */

struct AstNodeClass
{
	GObjectClass base_class;
};


GType ast_get_type(void);
AstNode* ast_new(AstNode *parent, int index, const char *prefix, void *ptr, void (*expand)(AstNode*));


static inline
AstNode* ast_append_child(AstNode *parent, const char *text,
			   void *ptr, void (*inspect)(AstNode*))
{
	if (ptr) {
		AstNode *child = ast_new(parent, parent->childnodes->len,
						text, ptr, inspect);
		g_array_append_val(parent->childnodes, child);
		return child;
	}
	return NULL;
}

static inline
void ast_append_attribute(AstNode *parent, const char *text)
{
	AstNode *child = ast_new(parent, parent->childnodes->len, text, NULL, NULL);
	g_array_append_val(parent->childnodes, child);
}

#endif /* _ast_h_*/
