#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# lex generates a lex.yy.c for use in building applications.  A number of
# interfaces within this file are intended for libl.so to bind to, and thus
# should remain exported from any application using lex.yy.c.
{
	global:
		yyback;
		yyextra;
		yyfnd;
		yyinput;
		yyleng;
		yylex;
		yylsp;
		yylstate;
		yyolsp;
		yyout;
		yyprevious;
		yytext;
		yyunput;
};

# Some applications use the -e option of lex, which generates additional lex
# interfaces that are not defined in the generic $(MAPFILE.LEX).  Export the
# following interfaces to satisfy -e use.
#{
#	global:
#		yywinput;
#		yywleng;
#		yywtext;
#		yywunput;
#};
