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
 * Copyright 2017 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 *
 * UNIX shell
 *
 */


#include	"defs.h"
#include	<errno.h>
#include	"sym.h"
#include	"hash.h"
#include	<sys/types.h>
#include	<sys/times.h>

pid_t parent;

void execprint(unsigned char **);

/* ========	command execution	======== */

/*VARARGS3*/
int
execute(argt, xflags, errorflg, pf1, pf2)
struct trenod *argt;
int xflags, errorflg;
int *pf1, *pf2;
{
	/*
	 * `stakbot' is preserved by this routine
	 */
	struct trenod	*t;
	unsigned char		*sav = savstak();

	sigchk();
	if (!errorflg)
		flags &= ~errflg;

	if ((t = argt) && execbrk == 0) {
		int treeflgs;
		unsigned char **com;
		int type;
		short pos;

		treeflgs = t->tretyp;
		type = treeflgs & COMMSK;

		switch (type)
		{
		case TFND:
			{
				struct fndnod	*f = fndptr(t);
				struct namnod	*n = lookup(f->fndnam);

				exitval = 0;

				if (n->namflg & N_RDONLY)
					failed(n->namid, wtfailed);

				if (flags & rshflg && (n == &pathnod ||
					eq(n->namid, "SHELL")))
					failed(n->namid, restricted);
				/*
				 * If function of same name is previously
				 * defined, it will no longer be used.
				 */
				if (n->namflg & N_FUNCTN) {
					freefunc(n);
				} else {
					free(n->namval);
					free(n->namenv);

					n->namval = 0;
					n->namflg &= ~(N_EXPORT | N_ENVCHG);
				}
				/*
				 * If function is defined within function,
				 * we don't want to free it along with the
				 * free of the defining function. If we are
				 * in a loop, fndnod may be reused, so it
				 * should never be freed.
				 */
				if (funcnt != 0 || loopcnt != 0)
					f->fndref++;

				/*
				 * We hang a fndnod on the namenv so that
				 * ref cnt(fndref) can be increased while
				 * running in the function.
				 */
				n->namenv = (unsigned char *)f;
				attrib(n, N_FUNCTN);
				hash_func(n->namid);
				break;
			}

		case TCOM:
			{
				unsigned char	*name;
				int	argn, internal;
				struct argnod	*schain = gchain;
				struct ionod	*io = t->treio;
				short 	cmdhash;
				short	comtype;

				exitval = 0;

				gchain = 0;
				argn = getarg(t);
				com = scan(argn);
				gchain = schain;

				if (argn != 0)
					cmdhash = pathlook(com[0], 1, comptr(t)->comset);

				if (argn == 0 || (comtype = hashtype(cmdhash)) == BUILTIN) {
					setlist(comptr(t)->comset, 0);
				}

				if (argn && (flags&noexec) == 0)
				{

					/* print command if execpr */
					if (flags & execpr)
						execprint(com);

					if (comtype == NOTFOUND)
					{
						pos = hashdata(cmdhash);
						if (pos == 1)
							failure(*com, notfound);
						else if (pos == 2)
							failure(*com, badexec);
						else
							failure(*com, badperm);
						break;
					}

					else if (comtype == PATH_COMMAND)
					{
						pos = -1;
					}

					else if (comtype & (COMMAND | REL_COMMAND))
					{
						pos = hashdata(cmdhash);
					}

					else if (comtype == BUILTIN) {
						builtin(hashdata(cmdhash),argn,com,t);
						freejobs();
						break;
					}
					else if (comtype == FUNCTION)
					{
						struct dolnod *olddolh;
						struct namnod *n, *opt;
						struct fndnod *f;
						short index;
						unsigned char **olddolv = dolv;
						int olddolc = dolc;

						n = findnam(com[0]);
						f = fndptr(n->namenv);
						/* just in case */
						if (f == NULL)
							break;
					/* save current positional parameters */
						olddolh = (struct dolnod *)savargs(funcnt);
						f->fndref++;
						funcnt++;
						index = initio(io, 1);
						setargs(com);
						execute(f->fndval, xflags,
						    errorflg, pf1, pf2);
						execbrk = 0;
						restore(index);
						(void) restorargs(olddolh, funcnt);
						dolv = olddolv;
						dolc = olddolc;
						funcnt--;
						/*
						 * n->namenv may have been
						 * pointing different func.
						 * Therefore, we can't use
						 * freefunc(n).
						 */
						freetree((struct trenod *)f);

						break;
					}
				}
				else if (t->treio == 0)
				{
					chktrap();
					break;
				}

			}

		case TFORK:
		{
			int monitor = 0;
			int linked = 0;

			exitval = 0;

			if (!(xflags & XEC_EXECED) || treeflgs&(FPOU|FAMP))
			{

				int forkcnt = 1;

				if (!(treeflgs&FPOU))
				{
					monitor = (!(xflags & XEC_NOSTOP)
					  && (flags&(monitorflg|jcflg|jcoff))
					  == (monitorflg|jcflg));
					if (monitor) {
						int savefd;
						unsigned char *savebot;
						savefd = setb(-1);
						savebot = stakbot;
						prcmd(t);
						(void)setb(savefd);
						allocjob(savebot, cwdget(), monitor);
					} else
						allocjob("", "", 0);

				}

				if (treeflgs & (FPOU|FAMP)) {
					link_iodocs(iotemp);
					linked = 1;
				}

				while ((parent = fork()) == -1)
				{
				/*
				 * FORKLIM is the max period between forks -
				 * power of 2 usually.	Currently shell tries
				 * after 2,4,8,16, and 32 seconds and then quits
				 */

				if ((forkcnt = (forkcnt * 2)) > FORKLIM)
				{
					switch (errno)
					{
					case ENOMEM:
						deallocjob();
						error(noswap);
						break;
					default:
						deallocjob();
						error(nofork);
						break;
					}
				} else if (errno == EPERM) {
					deallocjob();
					error(eacces);
					break;
				}
				sigchk();
				sh_sleep(forkcnt);
				}

				if (parent) {
					if (monitor)
						setpgid(parent, 0);
					if (treeflgs & FPIN)
						closepipe(pf1);
					if (!(treeflgs&FPOU)) {
						postjob(parent,!(treeflgs&FAMP));
						freejobs();
					}
					chktrap();
					break;
				}
				mypid = getpid();
			}

			/*
			 * Forked process:  assume it is not a subshell for
			 * now.  If it is, the presence of a left parenthesis
			 * will trigger the jcoff flag to be turned off.
			 * When jcoff is turned on, monitoring is not going on
			 * and waitpid will not look for WUNTRACED.
			 */

			flags |= (forked|jcoff);

			fiotemp  = 0;

			if (linked == 1) {
				swap_iodoc_nm(iotemp);
				xflags |= XEC_LINKED;
			} else if (!(xflags & XEC_LINKED))
				iotemp = 0;
#ifdef ACCT
			suspacct();
#endif
			settmp();
			oldsigs();

			if (!(treeflgs & FPOU))
				makejob(monitor, !(treeflgs & FAMP));

			/*
			 * pipe in or out
			 */
			if (treeflgs & FPIN)
			{
				renamef(pf1[INPIPE], 0);
				close(pf1[OTPIPE]);
			}

			if (treeflgs & FPOU)
			{
				close(pf2[INPIPE]);
				renamef(pf2[OTPIPE], 1);
			}

			/*
			 * io redirection
			 */
			initio(t->treio, 0);

			if (type == TFORK)
				execute(forkptr(t)->forktre, xflags | XEC_EXECED, errorflg);
			else if (com[0] != ENDARGS)
			{
				eflag = 0;
				setlist(comptr(t)->comset, N_EXPORT);
				rmtemp(0);
				clearjobs();
				execa(com, pos);
			}
			done(0);
		}

		case TPAR:
			/* Forked process is subshell:  may want job control */
			flags &= ~jcoff;
			clearjobs();
			execute(parptr(t)->partre, xflags, errorflg);
			done(0);

		case TFIL:
			{
				int pv[2];

				chkpipe(pv);
				if (execute(lstptr(t)->lstlef, xflags & XEC_NOSTOP, errorflg, pf1, pv) == 0)
					execute(lstptr(t)->lstrit, xflags, errorflg, pv, pf2);
				else
					closepipe(pv);
			}
			break;

		case TLST:
			execute(lstptr(t)->lstlef, xflags&XEC_NOSTOP, errorflg);
			/* Update errorflg if set -e is invoked in the sub-sh*/
			execute(lstptr(t)->lstrit, xflags, (errorflg | (eflag & errflg)));
			break;

		case TAND:
		case TORF:
		{
			int xval;
			xval = execute(lstptr(t)->lstlef, XEC_NOSTOP, 0);
			if ((xval == 0) == (type == TAND))
				execute(lstptr(t)->lstrit, xflags|XEC_NOSTOP, errorflg);
			break;
		}

		case TFOR:
			{
				struct namnod *n = lookup(forptr(t)->fornam);
				unsigned char	**args;
				struct dolnod *argsav = 0;

				if (forptr(t)->forlst == 0)
				{
					args = dolv + 1;
					argsav = useargs();
				}
				else
				{
					struct argnod *schain = gchain;

					gchain = 0;
					args = scan(getarg(forptr(t)->forlst));
					gchain = schain;
				}
				loopcnt++;
				while (*args != ENDARGS && execbrk == 0)
				{
					assign(n, *args++);
					execute(forptr(t)->fortre, XEC_NOSTOP, errorflg);
					if (breakcnt < 0)
						execbrk = (++breakcnt != 0);
				}
				if (breakcnt > 0)
						execbrk = (--breakcnt != 0);

				loopcnt--;
				if(argsav)
					argfor = (struct dolnod *)freeargs(argsav);
			}
			break;

		case TWH:
		case TUN:
			{
				int	i = 0;

				loopcnt++;
				while (execbrk == 0 && (execute(whptr(t)->whtre,
				    XEC_NOSTOP, 0) == 0) == (type == TWH) &&
				    (flags&noexec) == 0)
{
					i = execute(whptr(t)->dotre, XEC_NOSTOP, errorflg);
					if (breakcnt < 0)
						execbrk = (++breakcnt != 0);
				}
				if (breakcnt > 0)
						execbrk = (--breakcnt != 0);

				loopcnt--;
				exitval = i;
			}
			break;

		case TIF:
			if (execute(ifptr(t)->iftre, XEC_NOSTOP, 0) == 0)
				execute(ifptr(t)->thtre, xflags|XEC_NOSTOP, errorflg);
			else if (ifptr(t)->eltre)
				execute(ifptr(t)->eltre, xflags|XEC_NOSTOP, errorflg);
			else
				exitval = 0;	/* force zero exit for if-then-fi */
			break;

		case TSW:
			{
				unsigned char	*r = mactrim(swptr(t)->swarg);
				struct regnod *regp;

				regp = swptr(t)->swlst;
				while (regp)
				{
					struct argnod *rex = regp->regptr;

					while (rex)
					{
						unsigned char	*s;

						if (gmatch(r, s = macro(rex->argval)) || (trim(s), eq(r, s)))
						{
							execute(regp->regcom, XEC_NOSTOP, errorflg);
							regp = 0;
							break;
						}
						else
							rex = rex->argnxt;
					}
					if (regp)
						regp = regp->regnxt;
				}
			}
			break;
		}
		exitset();
	}
	sigchk();
	tdystak(sav);
	flags |= eflag;
	return(exitval);
}

void
execexp(unsigned char *s, int f)
{
	struct fileblk	fb;

	push(&fb);
	if (s)
	{
		estabf(s);
		fb.feval = (unsigned char **)(f);
	}
	else if (f >= 0)
		initf(f);
	execute(cmd(NL, NLFLG | MTFLG), 0, (int)(flags & errflg));
	pop();
}

void
execprint(unsigned char **com)
{
	int 	argn = 0;
	unsigned char	*s;

	prs(_gettext(execpmsg));
	while(com[argn] != ENDARGS)
	{
		s = com[argn++];
		write(output, s, length(s) - 1);
		blank();
	}

	newline();
}
