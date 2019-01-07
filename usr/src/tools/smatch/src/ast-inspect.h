
#ifndef _AST_INSPECT_H_
#define _AST_INSPECT_H_

#include "ast-model.h"

void inspect_symbol(AstNode *node);
void inspect_symbol_list(AstNode *node);

void inspect_statement(AstNode *node);
void inspect_statement_list(AstNode *node);

void inspect_expression(AstNode *node);
void inspect_expression_list(AstNode *node);


#endif
