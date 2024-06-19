%{
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/* This is the yacc grammar for the libfru NamingSyntax */
#include <assert.h>
#include <stdio.h>

#include "Parser.h"

//#define YYDEBUG 1

// Parser Globals.
extern fru_errno_t gParserErrno;
extern char *gParserString;
extern Ancestor *gParserAnts;
extern PathDef *gParserHead;
extern int *gParserAbs;

#ifdef	__cplusplus
extern "C" {
#endif
extern int yyerror(const char *msg);
extern int yylex(void);
extern int yywrap (void);
#ifdef	__cplusplus
}
#endif

%}

%union {
   int      num;
   char    *name;
   PathDef *pathDef;
}

%token SEPIDENT ITERBEGIN ITEREND
%token LAST ADD
%token <num> NUMBER
%token <name> NAME

%type <pathDef> recordpath element
%type <num> itercount

%left SEPIDENT

%%
fullpath   : recordpath
           {
              gParserHead = $1;
              gParserAnts
		= Ancestor::listTaggedAncestors((char *)$1->def->name);
           }
           ;

recordpath : element
           {
               $$ = $1;
           }
           | element SEPIDENT recordpath
           {
              if ($1->def->dataType != FDTYPE_Record)
              {
                 (void) yyerror (NULL);
                 YYABORT;
              }
              int found = 0;
              for ( int i=0;i<$1->def->enumCount;i++)
              {
                 if ( strcmp ($3->def->name, $1->def->enumTable[i].text) == 0 )
                    found = 1;
              }
              if ( !found )
              {
                 (void) yyerror (NULL);
                 YYABORT;
              }
              // insert it in the list.
              $1->next = $3;
              // return the head of the list.
              $$ = $1;
           }
           | SEPIDENT recordpath
           {
              // absolute path definitions MUST start with tagged elements.
              if ( $2->def->tagType == FRU_X )
              {
                 (void) yyerror ("First Element of absolute path MUST be tagged");
                 YYABORT;
              }
              *gParserAbs = 1;
              $$ = $2;
           }
           ;

element    : NAME
           {
              const fru_regdef_t *def = fru_reg_lookup_def_by_name($1);
              if ( def == NULL )
              {
                 (void) yyerror (NULL);
                 gParserErrno = FRU_NOREGDEF;
                 free ($1); // the lexer allocates this memory.
                 YYABORT;
              }
              PathDef *pathDef = new PathDef;
              pathDef->def = (fru_regdef_t *)def;
              pathDef->iterIndex = 0;
              pathDef->next = NULL;
              free ($1); // the lexer allocates this memory.
              $$ = pathDef;
           }
           | NAME ITERBEGIN itercount ITEREND
           {
              const fru_regdef_t *def = fru_reg_lookup_def_by_name($1);
              if ( def == NULL )
              {
                 (void) yyerror (NULL);
                 gParserErrno = FRU_NOREGDEF;
                 free ($1); // the lexer allocates this memory.
                 YYABORT;
              }
              if ( def->iterationType == FRU_NOT_ITERATED )
              {
                 (void) yyerror (NULL);
                 free ($1); // the lexer allocates this memory.
                 YYABORT;
              }
              if ( ($3 != PathDef::lastIteration) &&
			($3 != PathDef::addIteration) )
              {
                 if ( ($3 >= def->iterationCount) || ($3 < 0) )
                 {
                    (void) yyerror (NULL);
                    free ($1); // the lexer allocates this memory.
                    YYABORT;
                 }
              }
              PathDef *pathDef = new PathDef;
              pathDef->def = (fru_regdef_t *)def;
              pathDef->iterIndex = $3;
              pathDef->next = NULL;
              free ($1); // the lexer allocates this memory.
              $$ = pathDef;
           }
           ;

itercount : NUMBER
            { $$ = $1; }
          | LAST
            { $$ = PathDef::lastIteration; }
          | ADD
            { $$ = PathDef::addIteration; }
          ;

%%

int
yyerror (const char *msg)
{
	gParserErrno = FRU_INVALPATH;
	return (0);
}

// just to override what the library should have done.
int yywrap (void)
{
	return (1);
}
