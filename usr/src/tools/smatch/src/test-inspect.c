
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "parse.h"
#include "symbol.h"
#include "expression.h"

#include "ast-view.h"

static void expand_symbols(struct symbol_list *list)
{
	struct symbol *sym;
	FOR_EACH_PTR(list, sym) {
		expand_symbol(sym);
	} END_FOR_EACH_PTR(sym);
}

int main(int argc, char **argv)
{
	struct string_list *filelist = NULL;
	char *file;
	struct symbol_list *view_syms = NULL;

	gtk_init(&argc,&argv);
	expand_symbols(sparse_initialize(argc, argv, &filelist));
	FOR_EACH_PTR_NOTAG(filelist, file) {
		struct symbol_list *syms = sparse(file);
		expand_symbols(syms);
		concat_symbol_list(syms, &view_syms);
	} END_FOR_EACH_PTR_NOTAG(file);
	treeview_main(view_syms);
	return 0;
}
 
