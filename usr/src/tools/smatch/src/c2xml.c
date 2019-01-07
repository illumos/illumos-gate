/*
 * Sparse c2xml
 *
 * Dumps the parse tree as an xml document
 *
 * Copyright (C) 2007 Rob Taylor
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "expression.h"
#include "parse.h"
#include "scope.h"
#include "symbol.h"

static xmlDocPtr doc = NULL;       /* document pointer */
static xmlNodePtr root_node = NULL;/* root node pointer */
static int idcount = 0;

static void examine_symbol(struct symbol *sym, xmlNodePtr node);

static xmlAttrPtr newProp(xmlNodePtr node, const char *name, const char *value)
{
	return xmlNewProp(node, BAD_CAST name, BAD_CAST value);
}

static xmlAttrPtr newNumProp(xmlNodePtr node, const char *name, int value)
{
	char buf[256];
	snprintf(buf, 256, "%d", value);
	return newProp(node, name, buf);
}

static xmlAttrPtr newIdProp(xmlNodePtr node, const char *name, unsigned int id)
{
	char buf[256];
	snprintf(buf, 256, "_%d", id);
	return newProp(node, name, buf);
}

static xmlNodePtr new_sym_node(struct symbol *sym, const char *name, xmlNodePtr parent)
{
	xmlNodePtr node;
	const char *ident = show_ident(sym->ident);

	assert(name != NULL);
	assert(sym != NULL);
	assert(parent != NULL);

	node = xmlNewChild(parent, NULL, BAD_CAST "symbol", NULL);

	newProp(node, "type", name);

	newIdProp(node, "id", idcount);

	if (sym->ident && ident)
		newProp(node, "ident", ident);
	newProp(node, "file", stream_name(sym->pos.stream));

	newNumProp(node, "start-line", sym->pos.line);
	newNumProp(node, "start-col", sym->pos.pos);

	if (sym->endpos.type) {
		newNumProp(node, "end-line", sym->endpos.line);
		newNumProp(node, "end-col", sym->endpos.pos);
		if (sym->pos.stream != sym->endpos.stream)
			newProp(node, "end-file", stream_name(sym->endpos.stream));
        }
	sym->aux = node;

	idcount++;

	return node;
}

static inline void examine_members(struct symbol_list *list, xmlNodePtr node)
{
	struct symbol *sym;

	FOR_EACH_PTR(list, sym) {
		examine_symbol(sym, node);
	} END_FOR_EACH_PTR(sym);
}

static void examine_modifiers(struct symbol *sym, xmlNodePtr node)
{
	const char *modifiers[] = {
			"auto",
			"register",
			"static",
			"extern",
			"const",
			"volatile",
			"signed",
			"unsigned",
			"char",
			"short",
			"long",
			"long-long",
			"typedef",
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			"inline",
			"addressable",
			"nocast",
			"noderef",
			"accessed",
			"toplevel",
			"label",
			"assigned",
			"type-type",
			"safe",
			"user-type",
			"force",
			"explicitly-signed",
			"bitwise"};

	int i;

	if (sym->namespace != NS_SYMBOL)
		return;

	/*iterate over the 32 bit bitfield*/
	for (i=0; i < 32; i++) {
		if ((sym->ctype.modifiers & 1<<i) && modifiers[i])
			newProp(node, modifiers[i], "1");
	}
}

static void
examine_layout(struct symbol *sym, xmlNodePtr node)
{
	examine_symbol_type(sym);

	newNumProp(node, "bit-size", sym->bit_size);
	newNumProp(node, "alignment", sym->ctype.alignment);
	newNumProp(node, "offset", sym->offset);
	if (is_bitfield_type(sym)) {
		newNumProp(node, "bit-offset", sym->bit_offset);
	}
}

static void examine_symbol(struct symbol *sym, xmlNodePtr node)
{
	xmlNodePtr child = NULL;
	const char *base;
	int array_size;

	if (!sym)
		return;
	if (sym->aux)		/*already visited */
		return;

	if (sym->ident && sym->ident->reserved)
		return;

	child = new_sym_node(sym, get_type_name(sym->type), node);
	examine_modifiers(sym, child);
	examine_layout(sym, child);

	if (sym->ctype.base_type) {
		if ((base = builtin_typename(sym->ctype.base_type)) == NULL) {
			if (!sym->ctype.base_type->aux) {
				examine_symbol(sym->ctype.base_type, root_node);
			}
			xmlNewProp(child, BAD_CAST "base-type",
			           xmlGetProp((xmlNodePtr)sym->ctype.base_type->aux, BAD_CAST "id"));
		} else {
			newProp(child, "base-type-builtin", base);
		}
	}
	if (sym->array_size) {
		/* TODO: modify get_expression_value to give error return */
		array_size = get_expression_value(sym->array_size);
		newNumProp(child, "array-size", array_size);
	}


	switch (sym->type) {
	case SYM_STRUCT:
	case SYM_UNION:
		examine_members(sym->symbol_list, child);
		break;
	case SYM_FN:
		examine_members(sym->arguments, child);
		break;
	case SYM_UNINITIALIZED:
		newProp(child, "base-type-builtin", builtin_typename(sym));
		break;
	default:
		break;
	}
	return;
}

static struct position *get_expansion_end (struct token *token)
{
	struct token *p1, *p2;

	for (p1=NULL, p2=NULL;
	     !eof_token(token);
	     p2 = p1, p1 = token, token = token->next);

	if (p2)
		return &(p2->pos);
	else
		return NULL;
}

static void examine_macro(struct symbol *sym, xmlNodePtr node)
{
	struct position *pos;

	/* this should probably go in the main codebase*/
	pos = get_expansion_end(sym->expansion);
	if (pos)
		sym->endpos = *pos;
	else
		sym->endpos = sym->pos;

	new_sym_node(sym, "macro", node);
}

static void examine_namespace(struct symbol *sym)
{
	if (sym->ident && sym->ident->reserved)
		return;

	switch(sym->namespace) {
	case NS_MACRO:
		examine_macro(sym, root_node);
		break;
	case NS_TYPEDEF:
	case NS_STRUCT:
	case NS_SYMBOL:
		examine_symbol(sym, root_node);
		break;
	case NS_NONE:
	case NS_LABEL:
	case NS_ITERATOR:
	case NS_UNDEF:
	case NS_PREPROCESSOR:
	case NS_KEYWORD:
		break;
	default:
		die("Unrecognised namespace type %d",sym->namespace);
	}

}

static int get_stream_id (const char *name)
{
	int i;
	for (i=0; i<input_stream_nr; i++) {
		if (strcmp(name, stream_name(i))==0)
			return i;
	}
	return -1;
}

static inline void examine_symbol_list(const char *file, struct symbol_list *list)
{
	struct symbol *sym;
	int stream_id = get_stream_id (file);

	if (!list)
		return;
	FOR_EACH_PTR(list, sym) {
		if (sym->pos.stream == stream_id)
			examine_namespace(sym);
	} END_FOR_EACH_PTR(sym);
}

int main(int argc, char **argv)
{
	struct string_list *filelist = NULL;
	struct symbol_list *symlist = NULL;
	char *file;

	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "parse");
	xmlDocSetRootElement(doc, root_node);

/* - A DTD is probably unnecessary for something like this

	dtd = xmlCreateIntSubset(doc, "parse", "http://www.kernel.org/pub/software/devel/sparse/parse.dtd" NULL, "parse.dtd");

	ns = xmlNewNs (root_node, "http://www.kernel.org/pub/software/devel/sparse/parse.dtd", NULL);

	xmlSetNs(root_node, ns);
*/
	symlist = sparse_initialize(argc, argv, &filelist);

	FOR_EACH_PTR_NOTAG(filelist, file) {
		examine_symbol_list(file, symlist);
		sparse_keep_tokens(file);
		examine_symbol_list(file, file_scope->symbols);
		examine_symbol_list(file, global_scope->symbols);
	} END_FOR_EACH_PTR_NOTAG(file);


	xmlSaveFormatFileEnc("-", doc, "UTF-8", 1);
	xmlFreeDoc(doc);
	xmlCleanupParser();

	return 0;
}
