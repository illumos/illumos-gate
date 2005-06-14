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
/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 *	Copyright (c) 1999 by Sun Microsystems, Inc.
 *	All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI" 	/* SVr4.0 1.2	*/

#include	"elf_dem.h"
#include	<string.h>
#include	"msg.h"

struct name_pair {
#ifdef __lint
	char	* s1, * s2;
#else
	int	s1, s2;
#endif
};

struct name_pair nplist[100] = {
	/* MSG_ORIG(MSG_STR_LT)		MSG_ORIG(MSG_STR_OPNANGBRAK) */
	{ MSG_STR_LT,	MSG_STR_OPNANGBRAK },
	/* MSG_ORIG(MSG_STR_LS)		MSG_ORIG(MSG_STR_DBLOPNANGBRAK) */
	{ MSG_STR_LS,	MSG_STR_DBLOPNANGBRAK },
	/* MSG_ORIG(MSG_STR_DV)		MSG_ORIG(MSG_STR_SLASH) */
	{ MSG_STR_DV,	MSG_STR_SLASH },
	/* MSG_ORIG(MSG_STR_GT)		MSG_ORIG(MSG_STR_CLOANGBRAK) */
	{ MSG_STR_GT,	MSG_STR_CLOANGBRAK },
	/* MSG_ORIG(MSG_STR_RS)		MSG_ORIG(MSG_STR_DBLCLOANGBRAK) */
	{ MSG_STR_RS,	MSG_STR_DBLCLOANGBRAK },
	/* MSG_ORIG(MSG_STR_MD)		MSG_ORIG(MSG_STR_PERCENT) */
	{ MSG_STR_MD,	MSG_STR_PERCENT },
	/* MSG_ORIG(MSG_STR_LE)		MSG_ORIG(MSG_STR_OPNANGBRAKEQU) */
	{ MSG_STR_LE,	MSG_STR_OPNANGBRAKEQU },
	/* MSG_ORIG(MSG_STR_ML)		MSG_ORIG(MSG_STR_STAR) */
	{ MSG_STR_ML,	MSG_STR_STAR },
	/* MSG_ORIG(MSG_STR_PL)		MSG_ORIG(MSG_STR_PLUS) */
	{ MSG_STR_PL,	MSG_STR_PLUS },
	/* MSG_ORIG(MSG_STR_GE)		MSG_ORIG(MSG_STR_CLOANGBRAKEQU) */
	{ MSG_STR_GE,	MSG_STR_CLOANGBRAKEQU },
	/* MSG_ORIG(MSG_STR_AD)		MSG_ORIG(MSG_STR_AMP) */
	{ MSG_STR_AD,	MSG_STR_AMP },
	/* MSG_ORIG(MSG_STR_MI)		MSG_ORIG(MSG_STR_MINUS) */
	{ MSG_STR_MI,	MSG_STR_MINUS },
	/* MSG_ORIG(MSG_STR_NE)		MSG_ORIG(MSG_STR_BANGEQU) */
	{ MSG_STR_NE,	MSG_STR_BANGEQU },
	/* MSG_ORIG(MSG_STR_OR)		MSG_ORIG(MSG_STR_PIPE) */
	{ MSG_STR_OR,	MSG_STR_PIPE },
	/* MSG_ORIG(MSG_STR_ER)		MSG_ORIG(MSG_STR_CARAT) */
	{ MSG_STR_ER,	MSG_STR_CARAT },
	/* MSG_ORIG(MSG_STR_AA)		MSG_ORIG(MSG_STR_DBLAMP) */
	{ MSG_STR_AA,	MSG_STR_DBLAMP },
	/* MSG_ORIG(MSG_STR_OO)		MSG_ORIG(MSG_STR_DBLPIPE) */
	{ MSG_STR_OO,	MSG_STR_DBLPIPE },
	/* MSG_ORIG(MSG_STR_AS)		MSG_ORIG(MSG_STR_EQU) */
	{ MSG_STR_AS,	MSG_STR_EQU },
	/* MSG_ORIG(MSG_STR_APL)	MSG_ORIG(MSG_STR_PLUSEQU) */
	{ MSG_STR_APL,	MSG_STR_PLUSEQU },
	/* MSG_ORIG(MSG_STR_AMI)	MSG_ORIG(MSG_STR_MINUSEQU) */
	{ MSG_STR_AMI,	MSG_STR_MINUSEQU },
	/* MSG_ORIG(MSG_STR_AMU)	MSG_ORIG(MSG_STR_STARTEQU) */
	{ MSG_STR_AMU,	MSG_STR_STARTEQU },
	/* MSG_ORIG(MSG_STR_ADV)	MSG_ORIG(MSG_STR_SLASHEQU) */
	{ MSG_STR_ADV,	MSG_STR_SLASHEQU },
	/* MSG_ORIG(MSG_STR_AMD)	MSG_ORIG(MSG_STR_PERCENTEQU) */
	{ MSG_STR_AMD,	MSG_STR_PERCENTEQU },
	/* MSG_ORIG(MSG_STR_AAD)	MSG_ORIG(MSG_STR_AMPEQU) */
	{ MSG_STR_AAD,	MSG_STR_AMPEQU },
	/* MSG_ORIG(MSG_STR_AOR)	MSG_ORIG(MSG_STR_PIPEEQU) */
	{ MSG_STR_AOR,	MSG_STR_PIPEEQU },
	/* MSG_ORIG(MSG_STR_AER)	MSG_ORIG(MSG_STR_CARATEQU) */
	{ MSG_STR_AER,	MSG_STR_CARATEQU },
	/* MSG_ORIG(MSG_STR_ALS)	MSG_ORIG(MSG_STR_DBLOPENABKEQU) */
	{ MSG_STR_ALS,	MSG_STR_DBLOPENABKEQU },
	/* MSG_ORIG(MSG_STR_ARS)	MSG_ORIG(MSG_STR_DBLCLOSABKEQU) */
	{ MSG_STR_ARS,	MSG_STR_DBLCLOSABKEQU },
	/* MSG_ORIG(MSG_STR_PP)		MSG_ORIG(MSG_STR_DBLPLUS) */
	{ MSG_STR_PP,	MSG_STR_DBLPLUS },
	/* MSG_ORIG(MSG_STR_MM)		MSG_ORIG(MSG_STR_DBLMINUS) */
	{ MSG_STR_MM,	MSG_STR_DBLMINUS },
	/* MSG_ORIG(MSG_STR_VC)		MSG_ORIG(MSG_STR_OPENCLOBRAK) */
	{ MSG_STR_VC,	MSG_STR_OPENCLOBRAK },
	/* MSG_ORIG(MSG_STR_CL)		MSG_ORIG(MSG_STR_OPENCLOSEPAR) */
	{ MSG_STR_CL,	MSG_STR_OPENCLOSEPAR },
	/* MSG_ORIG(MSG_STR_RF)		MSG_ORIG(MSG_STR_MINUSCLOANGBK) */
	{ MSG_STR_RF,	MSG_STR_MINUSCLOANGBK },
	/* MSG_ORIG(MSG_STR_EQ)		MSG_ORIG(MSG_STR_DBLEQU) */
	{ MSG_STR_EQ,	MSG_STR_DBLEQU },
	/* MSG_ORIG(MSG_STR_CO)		MSG_ORIG(MSG_STR_TILDE) */
	{ MSG_STR_CO,	MSG_STR_TILDE },
	/* MSG_ORIG(MSG_STR_NT)		MSG_ORIG(MSG_STR_BANG) */
	{ MSG_STR_NT,	MSG_STR_BANG },
	/* MSG_ORIG(MSG_STR_NW)		MSG_ORIG(MSG_STR_NEW) */
	{ MSG_STR_NW,	MSG_STR_NEW },
	/* MSG_ORIG(MSG_STR_DL)		MSG_ORIG(MSG_STR_DELETE) */
	{ MSG_STR_DL,	MSG_STR_DELETE },
	{ 0,		0 }
};

/* This routine demangles an overloaded operator function */
const char *
findop(char * c, int * oplen)
{
	register int i, opl;

	for (opl = 0; c[opl] && c[opl] != '_'; opl++)
		;
	*oplen = opl;

	for (i = 0; nplist[i].s1; i++) {
		if (strncmp(MSG_ORIG(nplist[i].s1), c, opl) == 0)
			return (MSG_ORIG(nplist[i].s2));
	}
	return (0);
}
