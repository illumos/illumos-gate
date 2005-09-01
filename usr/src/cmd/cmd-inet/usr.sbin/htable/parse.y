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
 */
%}
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

%{
#ident	"%Z%%M%	%I%	%E% SMI"

#include "htable.h"
%}

%union {
	int	number;
	struct	addr *addrlist;
	struct	name *namelist;
}
%start Table

%token			END
%token <number>		NUMBER KEYWORD
%token <namelist>	NAME

%type <namelist>	Names Cputype Opsys Protos Proto
%type <addrlist>	Addresses Address
%%
Table	:	Entry
	|	Table Entry
	;

Entry	:	KEYWORD ':' Addresses ':' Names ':' END
	= {
		do_entry($1, $3, $5, NONAME, NONAME, NONAME);
	}
	|	KEYWORD ':' Addresses ':' Names ':' Cputype ':' END
	= {
		do_entry($1, $3, $5, $7, NONAME, NONAME);
	}
	|	KEYWORD ':' Addresses ':' Names ':' Cputype ':' Opsys ':' END
	= {
		do_entry($1, $3, $5, $7, $9, NONAME);
	}
	|	KEYWORD ':' Addresses ':' Names ':' Cputype ':' Opsys ':' ':' END
	= {
		do_entry($1, $3, $5, $7, $9, NONAME);
	}
	|	KEYWORD ':' Addresses ':' Names ':' Cputype ':' Opsys ':' Protos ':' END
	= {
		do_entry($1, $3, $5, $7, $9, $11);
	}
	|	error END
	|	END		/* blank line */
	;

Addresses:	Address
	= {
		$$ = $1;
	}
	|	Address ',' Addresses
	= {
		$1->addr_link = $3;
		$$ = $1;
	}
	;

Address	:	NUMBER '.' NUMBER '.' NUMBER '.' NUMBER
	= {
		char *a;

		$$ = (struct addr *)malloc(sizeof (struct addr));
		a = (char *)&($$->addr_val);
		a[0] = $1; a[1] = $3; a[2] = $5; a[3] = $7;
		$$->addr_link = NOADDR;
	}
	;

Names	:	NAME
	= {
		$$ = $1;
	}
	|	NAME ',' Names
	= {
		$1->name_link = $3;
		$$ = $1;
	}
	;

Cputype :	/* empty */
	= {
		$$ = NONAME;
	}
	|	NAME
	= {
		$$ = $1;
	}
	;

Opsys	:	/* empty */
	= {
		$$ = NONAME;
	}
	|	NAME
	= {
		$$ = $1;
	}
	;

Protos	:	Proto
	= {
		$$ = $1;
	}
	|	Proto ',' Protos
	= {
		$1->name_link = $3;
		$$ = $1;
	}
	;

Proto	:	NAME
	= {
		$$ = $1;
	}
	;
%%

#include <stdio.h>

extern int yylineno;

void
yyerror(msg)
	char *msg;
{
	fprintf(stderr, "\"%s\", line %d: %s\n", infile, yylineno, msg);
}
