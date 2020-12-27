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
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * apply file permission expression expr to perm
 *
 * each expression term must match
 *
 *	[ugoa]*[-&+|^=]?[rwxst0-7]*
 *
 * terms may be combined using ,
 *
 * if non-null, e points to the first unrecognized char in expr
 */

#include <ast.h>
#include <ls.h>
#include <modex.h>

int
strperm(const char* aexpr, char** e, register int perm)
{
	register char*	expr = (char*)aexpr;
	register int	c;
	register int	typ;
	register int	who;
	int		num;
	int		op;
	int		mask;
	int		masked;

	if (perm == -1)
	{
		perm = 0;
		masked = 1;
		mask = ~0;
	}
	else
		masked = 0;
	for (;;)
	{
		op = num = who = typ = 0;
		for (;;)
		{
			switch (c = *expr++)
			{
			case 'u':
				who |= S_ISVTX|S_ISUID|S_IRWXU;
				continue;
			case 'g':
				who |= S_ISVTX|S_ISGID|S_IRWXG;
				continue;
			case 'o':
				who |= S_ISVTX|S_IRWXO;
				continue;
			case 'a':
				who = S_ISVTX|S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO;
				continue;
			default:
				if (c >= '0' && c <= '7')
				{
					if (!who)
						who = S_ISVTX|S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO;
					c = '=';
				}
				expr--;
				/*FALLTHROUGH*/
			case '=':
				if (who)
					perm &= ~who;
				else
					perm = 0;
				/*FALLTHROUGH*/
			case '+':
			case '|':
			case '-':
			case '&':
			case '^':
				op = c;
				for (;;)
				{
					switch (c = *expr++)
					{
					case 'r':
						typ |= S_IRUSR|S_IRGRP|S_IROTH;
						continue;
					case 'w':
						typ |= S_IWUSR|S_IWGRP|S_IWOTH;
						continue;
					case 'X':
						if (!S_ISDIR(perm) && !(perm & (S_IXUSR|S_IXGRP|S_IXOTH)))
							continue;
						/*FALLTHROUGH*/
					case 'x':
						typ |= S_IXUSR|S_IXGRP|S_IXOTH;
						continue;
					case 's':
						typ |= S_ISUID|S_ISGID;
						continue;
					case 't':
						typ |= S_ISVTX;
						continue;
					case 'l':
						if (perm & S_IXGRP)
						{
							if (e)
								*e = expr - 1;
							return perm & S_IPERM;
						}
						typ |= S_ISGID;
						continue;
					case '=':
					case '+':
					case '|':
					case '-':
					case '&':
					case '^':
					case ',':
					case 0:
						if (who)
							typ &= who;
						else
							switch (op)
							{
							case '=':
							case '+':
							case '|':
							case '-':
							case '&':
								if (!masked)
								{
									masked = 1;
									umask(mask = umask(0));
									mask = ~mask;
								}
								typ &= mask;
								break;
							}
						switch (op)
						{
						default:
							if (who)
								perm &= ~who;
							else
								perm = 0;
							/*FALLTHROUGH*/
						case '+':
						case '|':
							perm |= typ;
							typ = 0;
							break;
						case '-':
							perm &= ~typ;
							typ = 0;
							break;
						case '&':
							perm &= typ;
							typ = 0;
							break;
						case '^':
							if (typ &= perm)
							{
								/*
								 * propagate least restrictive to most restrictive
								 */

								if (typ & S_IXOTH)
									perm |= who & (S_IXUSR|S_IXGRP);
								if (typ & S_IWOTH)
									perm |= who & (S_IWUSR|S_IWGRP);
								if (typ & S_IROTH)
									perm |= who & (S_IRUSR|S_IRGRP);
								if (typ & S_IXGRP)
									perm |= who & S_IXUSR;
								if (typ & S_IWGRP)
									perm |= who & S_IWUSR;
								if (typ & S_IRGRP)
									perm |= who & S_IRUSR;

								/*
								 * if any execute then read => execute
								 */

								if ((typ |= perm) & (S_IXUSR|S_IXGRP|S_IXOTH))
								{
									if (typ & S_IRUSR)
										perm |= who & S_IXUSR;
									if (typ & S_IRGRP)
										perm |= who & S_IXGRP;
									if (typ & S_IROTH)
										perm |= who & S_IXOTH;
								}
								typ = 0;
							}
							break;
						}
						switch (c)
						{
						case '=':
						case '+':
						case '|':
						case '-':
						case '&':
						case '^':
							op = c;
							typ = 0;
							continue;
						}
						if (c)
							break;
						/*FALLTHROUGH*/
					default:
						if (c < '0' || c > '7')
						{
							if (e)
								*e = expr - 1;
							if (typ)
							{
								if (who)
								{
									typ &= who;
									perm &= ~who;
								}
								perm |= typ;
							}
							return perm & S_IPERM;
						}
						num = (num << 3) | (c - '0');
						if (!who && (op == '+' || op == '-'))
							who = S_ISVTX|S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO;
						if (*expr < '0' || *expr > '7')
						{
							typ |= modei(num);
							num = 0;
						}
						continue;
					}
					break;
				}
				break;
			}
			break;
		}
	}
}
