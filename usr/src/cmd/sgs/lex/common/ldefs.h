/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	All Rights Reserved	*/

#ifndef	_LDEFS_H
#define	_LDEFS_H

#include <stdio.h>
#include <stdlib.h>

#include <widec.h>
#include <wctype.h>
#include "sgs.h"

#define	CHR wchar_t
#define	BYTE char
#define	Boolean char
#define	LONG_WCHAR_T 1

#define	PP 1
#ifdef u370
#define	CWIDTH 8
#define	CMASK 0377
#define	ASCII 1
#else

#ifdef unix
#define	CWIDTH 7
#define	CMASK 0177
#define	ASCII 1
#endif

#ifdef gcos
#define	CWIDTH 9
#define	CMASK 0777
#define	ASCII 1
#endif

#ifdef ibm
#define	CWIDTH 8
#define	CMASK 0377
#define	EBCDIC 1
#endif
#endif

#define	NCH 256
#define	TOKENSIZE 10000
#define	DEFSIZE 1000
#define	DEFCHAR 2000
#define	BUF_SIZ 2000
#define	STARTCHAR 2560
#define	STARTSIZE 256
#define	CCLSIZE 20000


#ifdef SMALL
#define	TREESIZE 600
#define	NTRANS 1500
#define	NSTATES 300
#define	MAXPOS 1500
#define	MAXPOSSTATE 500
#define	NOUTPUT 1500
#endif

#ifndef SMALL
#define	TREESIZE 1000
#define	NSTATES 500
#define	MAXPOS 2500
#define	MAXPOSSTATE 4*1000
#define	NTRANS 2000
#define	NOUTPUT 4*3000
#endif
#define	NACTIONS 4*1000
#define	ALITTLEEXTRA 300

#define	RCCL		0x4000
#define	RNCCL		0x4001
#define	RSTR		0x4002
#define	RSCON		0x4003
/* XCU4: add RXSCON */
#define	RXSCON		0x4011
#define	RNEWE		0x4004
#define	FINAL		0x4005
#define	RNULLS		0x4006
#define	RCAT		0x4007
#define	STAR		0x4008
#define	PLUS		0x4009
#define	QUEST		0x400a
#define	DIV		0x400b
#define	BAR		0x400c
#define	CARAT		0x400d
#define	S1FINAL		0x400e
#define	S2FINAL		0x400f
#define	DOT		0x4010
#define	ISOPERATOR(n)	((n & 0xc080) == 0x4000)

/*
 * New to JLE; this is not really a node tag.
 * This is used in a string pointed to by
 * the leaf of an RCCL or RNCCL node as a
 * special prefix code that substitutes
 * the infix '-' range operator.  For
 * example, a lex character class "[_0-9a-zA-Z]"
 * would be translated to the intermidiate
 * form:
 *	RCCL
 *	 |
 *	 |
 *	 v
 *       "_<RANGE>09<RANGE>a-z<RANGE>A-Z"
 */
#define	RANGE		0x40ff

#define	MAXNCG 1000
extern int ncgidtbl;
extern int ncg; /* ncg == ncgidtbl * 2 */
typedef unsigned long lchar;
extern lchar yycgidtbl[];
extern int yycgid(wchar_t);
extern Boolean handleeuc; /* TRUE iff -w or -e option is specified. */
extern Boolean widecio; /* TRUE iff -w option is specified. */

#define	DEFSECTION 1
#define	RULESECTION 2
#define	ENDSECTION 5

#define	PC 1
#define	PS 1

#ifdef DEBUG
#define	LINESIZE 110
extern int yydebug;
extern int debug;		/* 1 = on */
extern int charc;
#endif

#ifndef DEBUG
#define	freturn(s) s
#endif


extern int optind;
extern int no_input;
extern int sargc;
extern char **sargv;
extern char *v_stmp;
extern char *release_string;
extern CHR buf[];
extern int ratfor;		/* 1 = ratfor, 0 = C */
extern int fatal;
extern int n_error;
extern int copy_line;
extern int yyline;		/* line number of file */
extern int sect;
extern int eof;
extern int lgatflg;
extern int divflg;
extern int funcflag;
extern int pflag;
extern int casecount;
extern int chset;	/* 1 = CHR set modified */
extern FILE *fin, *fout, *fother, *errorf;
extern int fptr;
extern int prev;	/* previous input character */
extern int pres;	/* present input character */
extern int peek;	/* next input character */
extern int *name;
extern int *left;
extern int *right;
extern int *parent;
extern Boolean *nullstr;
extern int tptr;
extern CHR pushc[TOKENSIZE];
extern CHR *pushptr;
extern CHR slist[STARTSIZE];
extern CHR *slptr;
extern CHR **def, **subs, *dchar;
extern CHR **sname, *schar;
/* XCU4: %x exclusive start */
extern int *exclusive;
extern CHR *ccl;
extern CHR *ccptr;
extern CHR *dp, *sp;
extern int dptr, sptr;
extern CHR *bptr;		/* store input position */
extern CHR *tmpstat;
extern int count;
extern int **foll;
extern int *nxtpos;
extern int *positions;
extern int *gotof;
extern int *nexts;
extern CHR *nchar;
extern int **state;
extern int *sfall;		/* fallback state num */
extern Boolean *cpackflg;	/* true if state has been character packed */
extern int *atable, aptr;
extern int nptr;
extern Boolean symbol[MAXNCG];
extern CHR cindex[MAXNCG];
extern int xstate;
extern int stnum;
extern int ctable[];
extern int ZCH;
extern int ccount;
extern CHR match[MAXNCG];
extern BYTE extra[];
extern CHR *pcptr, *pchar;
extern int pchlen;
extern int nstates, maxpos;
extern int yytop;
extern int report;
extern int ntrans, treesize, outsize;
extern long rcount;
extern int optim;
extern int *verify, *advance, *stoff;
extern int scon;
extern CHR *psave;
extern CHR *getl();
extern BYTE *myalloc();

void phead1(void);
void phead2(void);
void ptail(void);
void statistics(void);
void error_tail(void) __NORETURN;
void error(char *, ...);
void warning(char *, ...);
void lgate(void);
void scopy(CHR *s, CHR *t);
void cclinter(int sw);
void cpycom(CHR *p);
void munput(int t, CHR *p);
void cfoll(int v);
void cgoto(void);
void mkmatch(void);
void layout(void);
void remch(wchar_t c);
void sortcgidtbl(void);
void repbycgid(void);
int gch(void);
int slength(CHR *s);
int yyparse(void);
int scomp(CHR *x, CHR *y);
int space(int ch);
int siconv(CHR *t);
int digit(int c);
int ctrans(CHR **ss);
int cpyact(void);
int lookup(CHR *s, CHR **t);
int usescape(int c);
int alpha(int c);
int mn2(int a, int d, int c);
int mn1(int a, int d);
int mn0(int a);
int dupl(int n);

extern int isArray;		/* XCU4: for %array %pointer */

#endif	/* _LDEFS_H */
