%{
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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include "y.tab.h"

extern int base;

int	cmd_no = 1;

%}

%e 2000

WS	[ \t]

%%

\n		{ cmd_no++; return NL; }
\.		{ return DOT; }

;{WS}*:{WS}*base{WS}*			{ return BASE; }
^{WS}*:{WS}*base{WS}*			{ return BASE; }
{WS}*:{WS}*block{WS}*			{ return BLOCK; }
;{WS}*:{WS}*cd				{ return CD; }
^{WS}*:{WS}*cd				{ return CD; }
:{WS}*directory{WS}*			{ return DIRECTORY; }
:{WS}*file{WS}*			{ return TFILE; }
;{WS}*:{WS}*find{WS}*			{ return FIND; }
^{WS}*:{WS}*find{WS}*			{ return FIND; }
{WS}*:{WS}*fill{WS}*			{ return FILL; }
:{WS}*inode{WS}*			{ return INODE; }
;{WS}*:{WS}*ls			{ return LS; }
^{WS}*:{WS}*ls			{ return LS; }
;{WS}*:{WS}*override{WS}*		{ return OVERRIDE; }
^{WS}*:{WS}*override{WS}*		{ return OVERRIDE; }
;{WS}*:{WS}*prompt{WS}*		{ return PROMPT; }
^{WS}*:{WS}*prompt{WS}*		{ return PROMPT; }
;{WS}*:{WS}*pwd{WS}*			{ return PWD; }
^{WS}*:{WS}*pwd{WS}*			{ return PWD; }
;{WS}*:{WS}*quit{WS}*			{ return QUIT; }
^{WS}*:{WS}*quit{WS}*			{ return QUIT; }
:{WS}*tag{WS}*			{ return TAG; }
;{WS}*:{WS}*!{WS}*			{ return BANG; }
^{WS}*:{WS}*!{WS}*			{ return BANG; }


:{WS}*avd			{ return AVD; }
:{WS}*mvds			{ return MVDS; }
:{WS}*rvds			{ return RVDS; }
:{WS}*ints			{ return INTS; }
:{WS}*fsds			{ return FSDS; }
:{WS}*root			{ return ROOT; }

:{WS}*attz			{ return ATTZ; }
:{WS}*atye			{ return ATYE; }
:{WS}*atmo			{ return ATMO; }
:{WS}*atda			{ return ATDA; }
:{WS}*atho			{ return ATHO; }
:{WS}*atmi			{ return ATMI; }
:{WS}*atse			{ return ATSE; }
:{WS}*atce			{ return ATCE; }
:{WS}*athu			{ return ATHU; }
:{WS}*atmic			{ return ATMIC; }

:{WS}*cttz			{ return CTTZ; }
:{WS}*ctye			{ return CTYE; }
:{WS}*ctmo			{ return CTMO; }
:{WS}*ctda			{ return CTDA; }
:{WS}*ctho			{ return CTHO; }
:{WS}*ctmi			{ return CTMI; }
:{WS}*ccte			{ return CTSE; }
:{WS}*ctce			{ return CTCE; }
:{WS}*cthu			{ return CTHU; }
:{WS}*ctmic			{ return CTMIC; }

:{WS}*mttz			{ return MTTZ; }
:{WS}*mtye			{ return MTYE; }
:{WS}*mtmo			{ return MTMO; }
:{WS}*mtda			{ return MTDA; }
:{WS}*mtho			{ return MTHO; }
:{WS}*mtmi			{ return MTMI; }
:{WS}*mtse			{ return MTSE; }
:{WS}*mtce			{ return MTCE; }
:{WS}*mthu			{ return MTHU; }
:{WS}*mtmic			{ return MTMIC; }


:{WS}*gid			{ return GID; }
:{WS}*ln			{ return LN; }
:{WS}*md			{ return MD; }
:{WS}*maj			{ return MAJ; }
:{WS}*min			{ return MIO; }
:{WS}*nm			{ return NM; }
:{WS}*sz			{ return SZ; }
:{WS}*uid			{ return UID; }
:{WS}*uniq			{ return UNIQ; }


[-0-9a-zA-Z._]+		{ yylval.strval = yytext; return WORD; }

.		{ return yytext[0]; }

%%

void
yyerror()
{
	fprintf(stderr,
		gettext("Syntax error line : %d token : %s \n"),
		cmd_no, yytext);
}

/*
:{WS}*fsds			{ return FSDS; }
:{WS}*root			{ return ROOT; }
*/
