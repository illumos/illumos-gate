/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
/*
 * generate sfio _Sftable static initializers
 */

#include "FEATURE/common"
#include "FEATURE/float"

int
main()
{
	register int	i;
#if _ast_fltmax_double
	char*		fs = "";
	char*		ds = "";
	char*		ls = "";
#else
	char*		fs = "F";
	char*		ds = "";
	char*		ls = "L";
#endif

	printf("\nstatic const float sf_flt_pow10[] =\n{\n");
	for (i = 0; i <= FLT_MAX_10_EXP; i++)
		printf("\t1E%d%s,\n", i, fs);
	printf("};\n");
	printf("\nstatic const double sf_dbl_pow10[] =\n{\n");
	for (i = 0; i <= DBL_MAX_10_EXP; i++)
		printf("\t1E%d%s,\n", i, ds);
	printf("};\n");
#if !_ast_fltmax_double
	printf("\nstatic const _ast_fltmax_t sf_ldbl_pow10[] =\n{\n");
	for (i = 0; i <= LDBL_MAX_10_EXP; i++)
		printf("\t1E%d%s,\n", i, ls);
	printf("};\n");
#endif
	printf("\nSftab_t _Sftable =\n{\n");
	printf("\t{ 1E1%s, 1E2%s, 1E4%s, 1E8%s, 1E16%s, 1E32%s },\n", ls, ls, ls, ls, ls, ls);
	printf("\t{ 1E-1%s, 1E-2%s, 1E-4%s, 1E-8%s, 1E-16%s, 1E-32%s },\n", ls, ls, ls, ls, ls, ls);
	printf("\t{ '0','0', '0','1', '0','2', '0','3', '0','4',\n");
	printf("\t  '0','5', '0','6', '0','7', '0','8', '0','9',\n");
	printf("\t  '1','0', '1','1', '1','2', '1','3', '1','4',\n");
	printf("\t  '1','5', '1','6', '1','7', '1','8', '1','9',\n");
	printf("\t  '2','0', '2','1', '2','2', '2','3', '2','4',\n");
	printf("\t  '2','5', '2','6', '2','7', '2','8', '2','9',\n");
	printf("\t  '3','0', '3','1', '3','2', '3','3', '3','4',\n");
	printf("\t  '3','5', '3','6', '3','7', '3','8', '3','9',\n");
	printf("\t  '4','0', '4','1', '4','2', '4','3', '4','4',\n");
	printf("\t  '4','5', '4','6', '4','7', '4','8', '4','9',\n");
	printf("\t  '5','0', '5','1', '5','2', '5','3', '5','4',\n");
	printf("\t  '5','5', '5','6', '5','7', '5','8', '5','9',\n");
	printf("\t  '6','0', '6','1', '6','2', '6','3', '6','4',\n");
	printf("\t  '6','5', '6','6', '6','7', '6','8', '6','9',\n");
	printf("\t  '7','0', '7','1', '7','2', '7','3', '7','4',\n");
	printf("\t  '7','5', '7','6', '7','7', '7','8', '7','9',\n");
	printf("\t  '8','0', '8','1', '8','2', '8','3', '8','4',\n");
	printf("\t  '8','5', '8','6', '8','7', '8','8', '8','9',\n");
	printf("\t  '9','0', '9','1', '9','2', '9','3', '9','4',\n");
	printf("\t  '9','5', '9','6', '9','7', '9','8', '9','9',\n");
	printf("\t},\n");
	printf("\t\"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_\",\n");
	printf("\tsfcvinit, 0,\n");
	printf("\tsffmtpos,\n");
	printf("\tsffmtint,\n");
	printf("\t(float*)&sf_flt_pow10[0],\n");
	printf("\t(double*)&sf_dbl_pow10[0],\n");
#if _ast_fltmax_double
	printf("\t0,\n");
#else
	printf("\t(_ast_fltmax_t*)&sf_ldbl_pow10[0],\n");
#endif
	printf("};\n");
	return 0;
}
