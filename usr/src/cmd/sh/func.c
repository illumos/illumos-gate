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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * UNIX shell
 */

#include	"defs.h"

static void free_arg(struct argnod *);
static void freeio(struct ionod *);
static void freereg(struct regnod *);
static void prarg(struct argnod *argp);
static void prio(struct ionod *iop);

void
freefunc(struct namnod 	*n)
{
	freetree((struct trenod *)(n->namenv));
}

void
freetree(struct trenod *t)
{
	if (t)
	{
		int type;

		type = t->tretyp & COMMSK;

		switch (type)
		{
			case TFND: {
				struct fndnod *f = fndptr(t);

				if (f->fndref > 0) {
					f->fndref--;
					return;
				}
				free(f->fndnam);
				freetree(f->fndval);
				break;
			}

			case TCOM:
				freeio(comptr(t)->comio);
				free_arg(comptr(t)->comarg);
				free_arg(comptr(t)->comset);
				break;

			case TFORK:
				freeio(forkptr(t)->forkio);
				freetree(forkptr(t)->forktre);
				break;

			case TPAR:
				freetree(parptr(t)->partre);
				break;

			case TFIL:
			case TLST:
			case TAND:
			case TORF:
				freetree(lstptr(t)->lstlef);
				freetree(lstptr(t)->lstrit);
				break;

			case TFOR:
			{
				struct fornod *f = (struct fornod *)t;

				free(f->fornam);
				freetree(f->fortre);
				if (f->forlst)
				{
					freeio(f->forlst->comio);
					free_arg(f->forlst->comarg);
					free_arg(f->forlst->comset);
					free(f->forlst);
				}
			}
			break;

			case TWH:
			case TUN:
				freetree(whptr(t)->whtre);
				freetree(whptr(t)->dotre);
				break;

			case TIF:
				freetree(ifptr(t)->iftre);
				freetree(ifptr(t)->thtre);
				freetree(ifptr(t)->eltre);
				break;

			case TSW:
				free(swptr(t)->swarg);
				freereg(swptr(t)->swlst);
				break;
		}
		free(t);
	}
}

static void
free_arg(struct argnod *argp)
{
	struct argnod 	*sav;

	while (argp)
	{
		sav = argp->argnxt;
		free(argp);
		argp = sav;
	}
}

void
freeio(struct ionod *iop)
{
	struct ionod *sav;

	while (iop)
	{
		if (iop->iofile & IODOC)
		{

#ifdef DEBUG
			prs("unlinking ");
			prs(iop->ioname);
			newline();
#endif

			unlink(iop->ioname);

			if (fiotemp == iop)
				fiotemp = iop->iolst;
			else
			{
				struct ionod *fiop = fiotemp;

				while (fiop->iolst != iop)
					fiop = fiop->iolst;

				fiop->iolst = iop->iolst;
			}
		}
		free(iop->ioname);
		free(iop->iolink);
		sav = iop->ionxt;
		free(iop);
		iop = sav;
	}
}

static void
freereg(struct regnod *regp)
{
	struct regnod 	*sav;

	while (regp)
	{
		free_arg(regp->regptr);
		freetree(regp->regcom);
		sav = regp->regnxt;
		free(regp);
		regp = sav;
	}
}


static int nonl = 0;

void
prbgnlst(void)
{
	if (nonl)
		prc_buff(SPACE);
	else
		prc_buff(NL);
}

void
prendlst(void)
{
	if (nonl) {
		prc_buff(';');
		prc_buff(SPACE);
	}
	else
		prc_buff(NL);
}

void
prcmd(struct trenod *t)
{
	nonl++;
	prf(t);
	nonl = 0;
}

void
prf(struct trenod *t)
{
	sigchk();

	if (t)
	{
		int	type;

		type = t->tretyp & COMMSK;

		switch(type)
		{
			case TFND:
			{
				struct fndnod *f = (struct fndnod *)t;

				prs_buff(f->fndnam);
				prs_buff("(){");
				prbgnlst();
				prf(f->fndval);
				prbgnlst();
				prs_buff("}");
				break;
			}

			case TCOM:
				if (comptr(t)->comset) {
					prarg(comptr(t)->comset);
					prc_buff(SPACE);
				}
				prarg(comptr(t)->comarg);
				prio(comptr(t)->comio);
				break;

			case TFORK:
				prf(forkptr(t)->forktre);
				prio(forkptr(t)->forkio);
				if (forkptr(t)->forktyp & FAMP)
					prs_buff(" &");
				break;

			case TPAR:
				prs_buff("(");
				prf(parptr(t)->partre);
				prs_buff(")");
				break;

			case TFIL:
				prf(lstptr(t)->lstlef);
				prs_buff(" | ");
				prf(lstptr(t)->lstrit);
				break;

			case TLST:
				prf(lstptr(t)->lstlef);
				prendlst();
				prf(lstptr(t)->lstrit);
				break;

			case TAND:
				prf(lstptr(t)->lstlef);
				prs_buff(" && ");
				prf(lstptr(t)->lstrit);
				break;

			case TORF:
				prf(lstptr(t)->lstlef);
				prs_buff(" || ");
				prf(lstptr(t)->lstrit);
				break;

			case TFOR:
				{
					struct argnod	*arg;
					struct fornod 	*f = (struct fornod *)t;

					prs_buff("for ");
					prs_buff(f->fornam);

					if (f->forlst)
					{
						arg = f->forlst->comarg;
						prs_buff(" in");

						while(arg != ENDARGS)
						{
							prc_buff(SPACE);
							prs_buff(arg->argval);
							arg = arg->argnxt;
						}
					}

					prendlst();
					prs_buff("do");
					prbgnlst();
					prf(f->fortre);
					prendlst();
					prs_buff("done");
				}
				break;

			case TWH:
			case TUN:
				if (type == TWH)
					prs_buff("while ");
				else
					prs_buff("until ");
				prf(whptr(t)->whtre);
				prendlst();
				prs_buff("do");
				prbgnlst();
				prf(whptr(t)->dotre);
				prendlst();
				prs_buff("done");
				break;

			case TIF:
			{
				struct ifnod *f = (struct ifnod *)t;

				prs_buff("if ");
				prf(f->iftre);
				prendlst();
				prs_buff("then");
				prendlst();
				prf(f->thtre);

				if (f->eltre)
				{
					prendlst();
					prs_buff("else");
					prendlst();
					prf(f->eltre);
				}

				prendlst();
				prs_buff("fi");
				break;
			}

			case TSW:
				{
					struct regnod 	*swl;

					prs_buff("case ");
					prs_buff(swptr(t)->swarg);

					swl = swptr(t)->swlst;
					while(swl)
					{
						struct argnod	*arg = swl->regptr;

						if (arg)
						{
							prs_buff(arg->argval);
							arg = arg->argnxt;
						}

						while(arg)
						{
							prs_buff(" | ");
							prs_buff(arg->argval);
							arg = arg->argnxt;
						}

						prs_buff(")");
						prf(swl->regcom);
						prs_buff(";;");
						swl = swl->regnxt;
					}
				}
				break;
			}
		}

	sigchk();
}

static void
prarg(struct argnod *argp)
{
	while (argp)
	{
		prs_buff(argp->argval);
		argp=argp->argnxt;
		if (argp)
			prc_buff(SPACE);
	}
}

static void
prio(struct ionod *iop)
{
	int	iof;
	unsigned char	*ion;

	while (iop)
	{
		iof = iop->iofile;
		ion = (unsigned char *) iop->ioname;

		if (*ion)
		{
			prc_buff(SPACE);

			prn_buff(iof & IOUFD);

			if (iof & IODOC)
				prs_buff("<<");
			else if (iof & IOMOV)
			{
				if (iof & IOPUT)
					prs_buff(">&");
				else
					prs_buff("<&");

			}
			else if ((iof & IOPUT) == 0)
				prc_buff('<');
			else if (iof & IOAPP)
				prs_buff(">>");
			else
				prc_buff('>');

			prs_buff(ion);
		}
		iop = iop->ionxt;
	}
}
