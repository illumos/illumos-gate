#include <stdio.h>
#include <assert.h>

#include "symbol.h"
#include "expression.h"
#include "linearize.h"
#include "flow.h"


static void output_bb(struct basic_block *bb, unsigned long generation)
{
	struct instruction *insn;

	bb->generation = generation;
	printf("%s\n", show_label(bb));

	FOR_EACH_PTR(bb->insns, insn) {
		if (!insn->bb)
			continue;
		printf("\t%s\n", show_instruction(insn));
	}
	END_FOR_EACH_PTR(insn);

	printf("\n");
}

static void output_fn(struct entrypoint *ep)
{
	struct basic_block *bb;
	unsigned long generation = ++bb_generation;
	struct symbol *sym = ep->name;
	const char *name = show_ident(sym->ident);

	if (sym->ctype.modifiers & MOD_STATIC)
		printf("\n\n%s:\n", name);
	else
		printf("\n\n.globl %s\n%s:\n", name, name);

	unssa(ep);

	FOR_EACH_PTR(ep->bbs, bb) {
		if (bb->generation == generation)
			continue;
		output_bb(bb, generation);
	}
	END_FOR_EACH_PTR(bb);
}

static int output_data(struct symbol *sym)
{
	printf("symbol %s:\n", show_ident(sym->ident));
	printf("\ttype = %d\n", sym->ctype.base_type->type);
	printf("\tmodif= %lx\n", sym->ctype.modifiers);

	return 0;
}

static int compile(struct symbol_list *list)
{
	struct symbol *sym;
	FOR_EACH_PTR(list, sym) {
		struct entrypoint *ep;
		expand_symbol(sym);
		ep = linearize_symbol(sym);
		if (!(fdump_ir & PASS_FINAL))
			continue;
		if (ep)
			output_fn(ep);
		else
			output_data(sym);
	}
	END_FOR_EACH_PTR(sym);

	return 0;
}

int main(int argc, char **argv)
{
	struct string_list * filelist = NULL;
	char *file;

	compile(sparse_initialize(argc, argv, &filelist));
	FOR_EACH_PTR(filelist, file) {
		compile(sparse(file));
	} END_FOR_EACH_PTR(file);

	report_stats();
	return 0;
}
