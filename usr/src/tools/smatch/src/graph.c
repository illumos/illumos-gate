/* Copyright © International Business Machines Corp., 2006
 *              Adelard LLP, 2007
 *
 * Author: Josh Triplett <josh@freedesktop.org>
 *         Dan Sheridan <djs@adelard.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
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
#include "linearize.h"


/* Draw the subgraph for a given entrypoint. Includes details of loads
 * and stores for globals, and marks return bbs */
static void graph_ep(struct entrypoint *ep)
{
	struct basic_block *bb;
	struct instruction *insn;

	const char *fname, *sname;

	fname = show_ident(ep->name->ident);
	sname = stream_name(ep->entry->bb->pos.stream);

	printf("subgraph cluster%p {\n"
	       "    color=blue;\n"
	       "    label=<<TABLE BORDER=\"0\" CELLBORDER=\"0\">\n"
	       "             <TR><TD>%s</TD></TR>\n"
	       "             <TR><TD><FONT POINT-SIZE=\"21\">%s()</FONT></TD></TR>\n"
	       "           </TABLE>>;\n"
	       "    file=\"%s\";\n"
	       "    fun=\"%s\";\n"
	       "    ep=bb%p;\n",
	       ep, sname, fname, sname, fname, ep->entry->bb);

	FOR_EACH_PTR(ep->bbs, bb) {
		struct basic_block *child;
		int ret = 0;
		const char * s = ", ls=\"[";

		/* Node for the bb */
		printf("    bb%p [shape=ellipse,label=%d,line=%d,col=%d",
		       bb, bb->pos.line, bb->pos.line, bb->pos.pos);


		/* List loads and stores */
		FOR_EACH_PTR(bb->insns, insn) {
			switch(insn->opcode) {
			case OP_STORE:
				if (insn->symbol->type == PSEUDO_SYM) {
				  printf("%s store(%s)", s, show_ident(insn->symbol->sym->ident));
				  s = ",";
				}
				break;

			case OP_LOAD:
				if (insn->symbol->type == PSEUDO_SYM) {
				  printf("%s load(%s)", s, show_ident(insn->symbol->sym->ident));
				  s = ",";
				}
				break;

			case OP_RET:
				ret = 1;
				break;

			}
		} END_FOR_EACH_PTR(insn);
		if (s[1] == 0)
			printf("]\"");
		if (ret)
			printf(",op=ret");
		printf("];\n");

		/* Edges between bbs; lower weight for upward edges */
		FOR_EACH_PTR(bb->children, child) {
			printf("    bb%p -> bb%p [op=br, %s];\n", bb, child,
			       (bb->pos.line > child->pos.line) ? "weight=5" : "weight=10");
		} END_FOR_EACH_PTR(child);
	} END_FOR_EACH_PTR(bb);

	printf("}\n");
}


/* Insert edges for intra- or inter-file calls, depending on the value
 * of internal. Bold edges are used for calls with destinations;
 * dashed for calls to external functions */
static void graph_calls(struct entrypoint *ep, int internal)
{
	struct basic_block *bb;
	struct instruction *insn;

	show_ident(ep->name->ident);
	stream_name(ep->entry->bb->pos.stream);

	FOR_EACH_PTR(ep->bbs, bb) {
		if (!bb)
			continue;
		if (!bb->parents && !bb->children && !bb->insns && verbose < 2)
			continue;

		FOR_EACH_PTR(bb->insns, insn) {
			if (insn->opcode == OP_CALL &&
			    internal == !(insn->func->sym->ctype.modifiers & MOD_EXTERN)) {

				/* Find the symbol for the callee's definition */
				struct symbol * sym;
				if (insn->func->type == PSEUDO_SYM) {
					for (sym = insn->func->sym->ident->symbols;
					     sym; sym = sym->next_id) {
						if (sym->namespace & NS_SYMBOL && sym->ep)
							break;
					}

					if (sym)
						printf("bb%p -> bb%p"
						       "[label=%d,line=%d,col=%d,op=call,style=bold,weight=30];\n",
						       bb, sym->ep->entry->bb,
						       insn->pos.line, insn->pos.line, insn->pos.pos);
					else
						printf("bb%p -> \"%s\" "
						       "[label=%d,line=%d,col=%d,op=extern,style=dashed];\n",
						       bb, show_pseudo(insn->func),
						       insn->pos.line, insn->pos.line, insn->pos.pos);
				}
			}
		} END_FOR_EACH_PTR(insn);
	} END_FOR_EACH_PTR(bb);
}

int main(int argc, char **argv)
{
	struct string_list *filelist = NULL;
	char *file;
	struct symbol *sym;

	struct symbol_list *fsyms, *all_syms=NULL;

	printf("digraph call_graph {\n");
	fsyms = sparse_initialize(argc, argv, &filelist);
	concat_symbol_list(fsyms, &all_syms);

	/* Linearize all symbols, graph internal basic block
	 * structures and intra-file calls */
	FOR_EACH_PTR_NOTAG(filelist, file) {

		fsyms = sparse(file);
		concat_symbol_list(fsyms, &all_syms);

		FOR_EACH_PTR(fsyms, sym) {
			expand_symbol(sym);
			linearize_symbol(sym);
		} END_FOR_EACH_PTR(sym);

		FOR_EACH_PTR(fsyms, sym) {
			if (sym->ep) {
				graph_ep(sym->ep);
				graph_calls(sym->ep, 1);
			}
		} END_FOR_EACH_PTR_NOTAG(sym);

	} END_FOR_EACH_PTR_NOTAG(file);

	/* Graph inter-file calls */
	FOR_EACH_PTR(all_syms, sym) {
		if (sym->ep)
			graph_calls(sym->ep, 0);
	} END_FOR_EACH_PTR_NOTAG(sym);

	printf("}\n");
	return 0;
}
