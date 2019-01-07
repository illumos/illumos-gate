
#include <stdlib.h>
#include "ast-model.h"
#include "ast-inspect.h"
#include "ast-view.h"

static GtkWidget *
create_view_and_model (void *ptr)
{
	GtkTreeViewColumn   *text;
	GtkCellRenderer *renderer;
	AstNode *root;
	GtkWidget *view;

	root = ast_new(NULL, 0, "", ptr, inspect_symbol_list);

	view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(root));

	g_object_unref(root); /* destroy store automatically with view */

	renderer = gtk_cell_renderer_text_new();
	text = gtk_tree_view_column_new_with_attributes("Node", renderer,
						       "text", AST_COL_NAME,
						       NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(view), text);

	return view;
}

void
treeview_main (struct symbol_list *syms)
{
	GtkWidget *window, *view, *scrollwin;

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size (GTK_WINDOW(window), 600, 800);
	g_signal_connect(window, "delete_event", gtk_main_quit, NULL);

	scrollwin = gtk_scrolled_window_new(NULL,NULL);

	view = create_view_and_model(syms);

	gtk_container_add(GTK_CONTAINER(scrollwin), view);
	gtk_container_add(GTK_CONTAINER(window), scrollwin);

	gtk_widget_show_all(window);

	gtk_main();
}
