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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	All Rights Reserved	*/

#include "ldefs.h"

static void add(int **array, int n);
static void follow(int v);
static void first(int v);
static void nextstate(int s, int c);
static void packtrans(int st, CHR *tch, int *tst, int cnt, int tryit);
static void acompute(int s);
static void rprint(int *a, char *s, int n);
static void shiftr(int *a, int n);
static void upone(int *a, int n);
static void bprint(char *a, char *s, int n);
static int notin(int n);
static int member(int d, CHR *t);

#ifdef PP
static void padd(int **array, int n);
#endif

void
cfoll(int v)
{
	int i, j, k;
	CHR *p;
	i = name[v];
	if (!ISOPERATOR(i))
		i = 1;
	switch (i) {
		case 1: case RSTR: case RCCL: case RNCCL: case RNULLS:
			for (j = 0; j < tptr; j++)
				tmpstat[j] = FALSE;
			count = 0;
			follow(v);
#ifdef PP
			padd(foll, v); /* packing version */
#else
			add(foll, v); /* no packing version */
#endif
			if (i == RSTR)
				cfoll(left[v]);
			else if (i == RCCL || i == RNCCL) {
				for (j = 1; j < ncg; j++)
					symbol[j] = (i == RNCCL);
				p = (CHR *) left[v];
				while (*p)
					symbol[*p++] = (i == RCCL);
				p = pcptr;
				for (j = 1; j < ncg; j++)
					if (symbol[j]) {
						for (k = 0; p + k < pcptr; k++)
							if (cindex[j] ==
							    *(p + k))
								break;
						if (p + k >= pcptr)
							*pcptr++ = cindex[j];
					}
				*pcptr++ = 0;
				if (pcptr > pchar + pchlen)
					error(
					"Too many packed character classes");
				left[v] = (int)p;
				name[v] = RCCL;	/* RNCCL eliminated */
#ifdef DEBUG
				if (debug && *p) {
					(void) printf("ccl %d: %d", v, *p++);
					while (*p)
						(void) printf(", %d", *p++);
					(void) putchar('\n');
				}
#endif
			}
			break;
		case CARAT:
			cfoll(left[v]);
			break;

		/* XCU4: add RXSCON */
		case RXSCON:

		case STAR: case PLUS: case QUEST: case RSCON:
			cfoll(left[v]);
			break;
		case BAR: case RCAT: case DIV: case RNEWE:
			cfoll(left[v]);
			cfoll(right[v]);
			break;
#ifdef DEBUG
		case FINAL:
		case S1FINAL:
		case S2FINAL:
			break;
		default:
			warning("bad switch cfoll %d", v);
#endif
	}
}

#ifdef DEBUG
void
pfoll(void)
{
	int i, k, *p;
	int j;
	/* print sets of chars which may follow positions */
	(void) printf("pos\tchars\n");
	for (i = 0; i < tptr; i++)
		if (p = foll[i]) {
			j = *p++;
			if (j >= 1) {
				(void) printf("%d:\t%d", i, *p++);
				for (k = 2; k <= j; k++)
					(void) printf(", %d", *p++);
				(void) putchar('\n');
			}
		}
}
#endif

static void
add(int **array, int n)
{
	int i, *temp;
	CHR *ctemp;
	temp = nxtpos;
	ctemp = tmpstat;
	array[n] = nxtpos;	/* note no packing is done in positions */
	*temp++ = count;
	for (i = 0; i < tptr; i++)
		if (ctemp[i] == TRUE)
			*temp++ = i;
	nxtpos = temp;
	if (nxtpos >= positions+maxpos)
		error(
		"Too many positions %s",
		    (maxpos == MAXPOS ? "\nTry using %p num" : ""));
}

static void
follow(int v)
{
	int p;
	if (v >= tptr-1)
		return;
	p = parent[v];
	if (p == 0)
		return;
	switch (name[p]) {
	/* will not be CHAR RNULLS FINAL S1FINAL S2FINAL RCCL RNCCL */
	case RSTR:
		if (tmpstat[p] == FALSE) {
			count++;
			tmpstat[p] = TRUE;
		}
		break;
	case STAR: case PLUS:
		first(v);
		follow(p);
		break;
	case BAR: case QUEST: case RNEWE:
		follow(p);
		break;
	case RCAT: case DIV:
		if (v == left[p]) {
			if (nullstr[right[p]])
				follow(p);
			first(right[p]);
		}
		else
			follow(p);
		break;
	/* XCU4: add RXSCON */
	case RXSCON:
	case RSCON: case CARAT:
		follow(p);
		break;
#ifdef DEBUG
	default:
		warning("bad switch follow %d", p);
#endif
	}
}

/*
 * Check if I have a RXSCON in my upper node
 */
static int
check_me(int v)
{
	int tmp = parent[v];

	while (name[tmp] != RNEWE) {
		if (name[tmp] == RXSCON)
			return (1);
		tmp = parent[tmp];
	}
	return (0);
}

/* calculate set of positions with v as root which can be active initially */
static void
first(int v)
{
	int i;
	CHR *p;
	i = name[v];
	if (!ISOPERATOR(i))
		i = 1;
	switch (i) {
	case 1: case RCCL: case RNCCL:
	case RNULLS: case FINAL:
	case S1FINAL: case S2FINAL:
	/*
	 * XCU4: if we are working on an exclusive start state and
	 * the parent of this position is not RXSCON or RSTR this
	 * is not an active position.
	 *
	 * (There is a possibility that RSXCON appreas as the
	 *  (parent)* node. Check it by check_me().)
	 */
		if ((exclusive[stnum/2]) &&
		    ISOPERATOR(name[parent[v]]) &&
		    (name[parent[v]] != RXSCON) &&
		    (name[parent[v]] != RSTR) &&
		    (check_me(v) == 0)) {
				break;
		}
		if (tmpstat[v] == FALSE) {
			count++;
			tmpstat[v] = TRUE;
		}
		break;
	case BAR: case RNEWE:
		first(left[v]);
		first(right[v]);
		break;
	case CARAT:
		if (stnum % 2 == 1)
			first(left[v]);
		break;
	/* XCU4: add RXSCON */
	case RXSCON:
	case RSCON:
		i = stnum/2 +1;
		p = (CHR *) right[v];
		while (*p)
			if (*p++ == i) {
				first(left[v]);
				break;
			}
		break;
	case STAR: case QUEST:
	case PLUS:  case RSTR:
	/*
	 * XCU4: if we are working on an exclusive start state and
	 * the parent of this position is not RXSCON or RSTR this
	 * is not an active position.
	 *
	 * (There is a possibility that RSXCON appreas as the
	 *  (parent)* node. Check it by check_me().)
	 */
		if ((exclusive[stnum/2]) &&
		    ISOPERATOR(name[parent[v]]) &&
		    (name[parent[v]] != RXSCON) &&
		    (name[parent[v]] != RSTR) &&
		    (check_me(v) == 0)) {
				break;
		}
		first(left[v]);
		break;
	case RCAT: case DIV:
		first(left[v]);
		if (nullstr[left[v]])
			first(right[v]);
		break;
#ifdef DEBUG
	default:
		warning("bad switch first %d", v);
#endif
	}
}

void
cgoto(void)
{
	int i, j;
	static int s;
	int npos, curpos, n;
	int tryit;
	CHR tch[MAXNCG];
	int tst[MAXNCG];
	CHR *q;
	/* generate initial state, for each start condition */
	if (ratfor) {
		(void) fprintf(fout, "blockdata\n");
		(void) fprintf(fout, "common /Lvstop/ vstop\n");
		(void) fprintf(fout, "define Svstop %d\n", nstates+1);
		(void) fprintf(fout, "integer vstop(Svstop)\n");
	} else
		(void) fprintf(fout, "int yyvstop[] = {\n0,\n");
	while (stnum < 2 || stnum/2 < sptr) {
		for (i = 0; i < tptr; i++)
			tmpstat[i] = 0;
		count = 0;
		if (tptr > 0)
			first(tptr-1);
		add(state, stnum);
#ifdef DEBUG
		if (debug) {
			if (stnum > 1)
				(void) printf("%ws:\n", sname[stnum/2]);
			pstate(stnum);
		}
#endif
		stnum++;
	}
	stnum--;
	/* even stnum = might not be at line begin */
	/* odd stnum  = must be at line begin */
	/* even states can occur anywhere, odd states only at line begin */
	for (s = 0; s <= stnum; s++) {
		tryit = FALSE;
		cpackflg[s] = FALSE;
		sfall[s] = -1;
		acompute(s);
		for (i = 0; i < ncg; i++)
			symbol[i] = 0;
		npos = *state[s];
		for (i = 1; i <= npos; i++) {
			curpos = *(state[s]+i);
			if (!ISOPERATOR(name[curpos]))
				symbol[name[curpos]] = TRUE;
			else {
				switch (name[curpos]) {
				case RCCL:
					tryit = TRUE;
					q = (CHR *)left[curpos];
					while (*q) {
						for (j = 1; j < ncg; j++)
							if (cindex[j] == *q)
								symbol[j] =
								    TRUE;
						q++;
					}
					break;
				case RSTR:
					symbol[right[curpos]] = TRUE;
					break;
#ifdef DEBUG
				case RNULLS:
				case FINAL:
				case S1FINAL:
				case S2FINAL:
					break;
				default:
					warning(
					"bad switch cgoto %d state %d",
					    curpos, s);
					break;
#endif
				}
			}
		}
#ifdef DEBUG
		if (debug) {
			printf("State %d transitions on char-group {", s);
			charc = 0;
			for (i = 1; i < ncg; i++) {
				if (symbol[i]) {
					printf("%d,", i);
				}
				if (i == ncg-1)
					printf("}\n");
				if (charc > LINESIZE/4) {
					charc = 0;
					printf("\n\t");
				}
			}
		}
#endif
		/* for each char, calculate next state */
		n = 0;
		for (i = 1; i < ncg; i++) {
			if (symbol[i]) {
				/* executed for each state, transition pair */
				nextstate(s, i);
				xstate = notin(stnum);
				if (xstate == -2)
					warning("bad state  %d %o", s, i);
				else if (xstate == -1) {
					if (stnum+1 >= nstates) {
						stnum++;
						error("Too many states %s",
						    (nstates == NSTATES ?
						    "\nTry using %n num":""));
					}
					add(state, ++stnum);
#ifdef DEBUG
					if (debug)
						pstate(stnum);
#endif
					tch[n] = i;
					tst[n++] = stnum;
				} else { /* xstate >= 0 ==> state exists */
					tch[n] = i;
					tst[n++] = xstate;
				}
			}
		}
		tch[n] = 0;
		tst[n] = -1;
		/* pack transitions into permanent array */
		if (n > 0)
			packtrans(s, tch, tst, n, tryit);
		else
			gotof[s] = -1;
	}
	(void) (ratfor ? fprintf(fout, "end\n") : fprintf(fout, "0};\n"));
}

/*
 * Beware -- 70% of total CPU time is spent in this subroutine -
 * if you don't believe me - try it yourself !
 */
static void
nextstate(int s, int c)
{
	int j, *newpos;
	CHR *temp, *tz;
	int *pos, i, *f, num, curpos, number;
	/* state to goto from state s on char c */
	num = *state[s];
	temp = tmpstat;
	pos = state[s] + 1;
	for (i = 0; i < num; i++) {
		curpos = *pos++;
		j = name[curpos];
		if ((!ISOPERATOR(j)) && j == c ||
		    j == RSTR && c == right[curpos] ||
		    j == RCCL && member(c, (CHR *) left[curpos])) {
			f = foll[curpos];
			number = *f;
			newpos = f+1;
			for (j = 0; j < number; j++)
				temp[*newpos++] = 2;
		}
	}
	j = 0;
	tz = temp + tptr;
	while (temp < tz) {
		if (*temp == 2) {
			j++;
			*temp++ = 1;
		}
		else
			*temp++ = 0;
	}
	count = j;
}

/* see if tmpstat occurs previously */
static int
notin(int n)
{
	int *j, k;
	CHR *temp;
	int i;

	if (count == 0)
		return (-2);
	temp = tmpstat;
	for (i = n; i >= 0; i--) { /* for each state */
		j = state[i];
		if (count == *j++) {
			for (k = 0; k < count; k++)
				if (!temp[*j++])
					break;
			if (k >= count)
				return (i);
		}
	}
	return (-1);
}

static void
packtrans(int st, CHR *tch, int *tst, int cnt, int tryit)
{
	/*
	 * pack transitions into nchar, nexts
	 * nchar is terminated by '\0', nexts uses cnt, followed by elements
	 * gotof[st] = index into nchr, nexts for state st
	 * sfall[st] =  t implies t is fall back state for st
	 * == -1 implies no fall back
	 */

	int cmin, cval, tcnt, diff, p, *ast;
	int i, j, k;
	CHR *ach;
	int go[MAXNCG], temp[MAXNCG], index, c;
	int swork[MAXNCG];
	CHR cwork[MAXNCG];
	int upper;

	rcount += (long)cnt;
	cmin = -1;
	cval = ncg;
	ast = tst;
	ach = tch;
	/* try to pack transitions using ccl's */
	if (!optim)
		goto nopack; /* skip all compaction */
	if (tryit) { /* ccl's used */
		for (i = 1; i < ncg; i++) {
			go[i] = temp[i] = -1;
			symbol[i] = 1;
		}
		for (i = 0; i < cnt; i++) {
			index = (unsigned char) tch[i];
			if ((index >= 0) && (index < NCH)) {
				go[index] = tst[i];
				symbol[index] = 0;
			} else {
				(void) fprintf(stderr,
"lex`sub2`packtran: tch[%d] out of bounds (%d)\n",
				    i, (int)tch[i]);
			}
		}
		for (i = 0; i < cnt; i++) {
			c = match[tch[i]];
			if (go[c] != tst[i] || c == tch[i])
				temp[tch[i]] = tst[i];
		}
		/* fill in error entries */
		for (i = 1; i < ncg; i++)
			if (symbol[i])
				temp[i] = -2;	/* error trans */
		/* count them */
		k = 0;
		for (i = 1; i < ncg; i++)
			if (temp[i] != -1)
				k++;
		if (k < cnt) { /* compress by char */
#ifdef DEBUG
			if (debug)
				(void) printf(
				"use compression  %d,  %d vs %d\n", st, k, cnt);
#endif
			k = 0;
			for (i = 1; i < ncg; i++)
				if (temp[i] != -1) {
					cwork[k] = i;
					swork[k++] =
					    (temp[i] == -2 ? -1 : temp[i]);
				}
			cwork[k] = 0;
#ifdef PC
			ach = cwork;
			ast = swork;
			cnt = k;
			cpackflg[st] = TRUE;
#endif
		}
	}
	/*
	 * get most similar state
	 * reject state with more transitions,
	 * state already represented by a third state,
	 * and state which is compressed by char if ours is not to be
	 */
	for (i = 0; i < st; i++) {
		if (sfall[i] != -1)
			continue;
		if (cpackflg[st] == 1)
			if (!(cpackflg[i] == 1))
				continue;
		p = gotof[i];
		if (p == -1) /* no transitions */
			continue;
		tcnt = nexts[p];
		if (tcnt > cnt)
			continue;
		diff = 0;
		k = 0;
		j = 0;
		upper = p + tcnt;
		while (ach[j] && p < upper) {
			while (ach[j] < nchar[p] && ach[j]) {
				diff++;
				j++;
			}
			if (ach[j] == 0)
				break;
			if (ach[j] > nchar[p]) {
				diff = ncg;
				break;
			}
			/* ach[j] == nchar[p] */
			if (ast[j] != nexts[++p] ||
			    ast[j] == -1 ||
			    (cpackflg[st] && ach[j] != match[ach[j]]))
				diff++;
			j++;
		}
		while (ach[j]) {
			diff++;
			j++;
		}
		if (p < upper)
			diff = ncg;
		if (diff < cval && diff < tcnt) {
			cval = diff;
			cmin = i;
			if (cval == 0)
				break;
		}
	}
	/* cmin = state "most like" state st */
#ifdef DEBUG
	if (debug)
		(void) printf("select st %d for st %d diff %d\n",
		    cmin, st, cval);
#endif
#ifdef PS
	if (cmin != -1) { /* if we can use st cmin */
		gotof[st] = nptr;
		k = 0;
		sfall[st] = cmin;
		p = gotof[cmin] + 1;
		j = 0;
		while (ach[j]) {
			/* if cmin has a transition on c, then so will st */
			/* st may be "larger" than cmin, however */
			while (ach[j] < nchar[p-1] && ach[j]) {
				k++;
				nchar[nptr] = ach[j];
				nexts[++nptr] = ast[j];
				j++;
			}
			if (nchar[p-1] == 0)
				break;
			if (ach[j] > nchar[p-1]) {
				warning("bad transition %d %d", st, cmin);
				goto nopack;
			}
			/* ach[j] == nchar[p-1] */
			if (ast[j] != nexts[p] ||
			    ast[j] == -1 ||
			    (cpackflg[st] && ach[j] != match[ach[j]])) {
				k++;
				nchar[nptr] = ach[j];
				nexts[++nptr] = ast[j];
			}
			p++;
			j++;
		}
		while (ach[j]) {
			nchar[nptr] = ach[j];
			nexts[++nptr] = ast[j++];
			k++;
		}
		nexts[gotof[st]] = cnt = k;
		nchar[nptr++] = 0;
	} else {
#endif
nopack:
	/* stick it in */
		gotof[st] = nptr;
		nexts[nptr] = cnt;
		for (i = 0; i < cnt; i++) {
			nchar[nptr] = ach[i];
			nexts[++nptr] = ast[i];
		}
		nchar[nptr++] = 0;
#ifdef PS
	}
#endif
	if (cnt < 1) {
		gotof[st] = -1;
		nptr--;
	} else
		if (nptr > ntrans)
			error(
			"Too many transitions %s",
			    (ntrans == NTRANS ? "\nTry using %a num" : ""));
}

#ifdef DEBUG
void
pstate(int s)
{
	int *p, i, j;
	(void) printf("State %d:\n", s);
	p = state[s];
	i = *p++;
	if (i == 0)
		return;
	(void) printf("%4d", *p++);
	for (j = 1; j < i; j++) {
		(void) printf(", %4d", *p++);
		if (j%30 == 0)
			(void) putchar('\n');
	}
	(void) putchar('\n');
}
#endif

static int
member(int d, CHR *t)
{
	int c;
	CHR *s;
	c = d;
	s = t;
	c = cindex[c];
	while (*s)
		if (*s++ == c)
			return (1);
	return (0);
}

#ifdef DEBUG
void
stprt(int i)
{
	int p, t;
	(void) printf("State %d:", i);
	/* print actions, if any */
	t = atable[i];
	if (t != -1)
		(void) printf(" final");
	(void) putchar('\n');
	if (cpackflg[i] == TRUE)
		(void) printf("backup char in use\n");
	if (sfall[i] != -1)
		(void) printf("fall back state %d\n", sfall[i]);
	p = gotof[i];
	if (p == -1)
		return;
	(void) printf("(%d transitions)\n", nexts[p]);
	while (nchar[p]) {
		charc = 0;
		if (nexts[p+1] >= 0)
			(void) printf("%d\t", nexts[p+1]);
		else
			(void) printf("err\t");
		allprint(nchar[p++]);
		while (nexts[p] == nexts[p+1] && nchar[p]) {
			if (charc > LINESIZE) {
				charc = 0;
				(void) printf("\n\t");
			}
			allprint(nchar[p++]);
		}
		(void) putchar('\n');
	}
	(void) putchar('\n');
}
#endif

/* compute action list = set of poss. actions */
static void
acompute(int s)
{
	int *p, i, j;
	int q, r;
	int cnt, m;
	int temp[MAXPOSSTATE], k, neg[MAXPOSSTATE], n;
	k = 0;
	n = 0;
	p = state[s];
	cnt = *p++;
	if (cnt > MAXPOSSTATE)
		error("Too many positions for one state - acompute");
	for (i = 0; i < cnt; i++) {
		q = *p;
		if (name[q] == FINAL)
			temp[k++] = left[q];
		else if (name[q] == S1FINAL) {
			temp[k++] = left[q];
			if ((r = left[q]) >= NACTIONS)
				error(
				"INTERNAL ERROR:left[%d]==%d>=NACTIONS", q, r);
			extra[r] = 1;
		} else if (name[q] == S2FINAL)
			neg[n++] = left[q];
		p++;
	}
	atable[s] = -1;
	if (k < 1 && n < 1)
		return;
#ifdef DEBUG
	if (debug)
		(void) printf("final %d actions:", s);
#endif
	/* sort action list */
	for (i = 0; i < k; i++)
		for (j = i+1; j < k; j++)
			if (temp[j] < temp[i]) {
				m = temp[j];
				temp[j] = temp[i];
				temp[i] = m;
			}
	/* remove dups */
	for (i = 0; i < k-1; i++)
		if (temp[i] == temp[i+1])
			temp[i] = 0;
	/* copy to permanent quarters */
	atable[s] = aptr;
#ifdef DEBUG
	if (!ratfor)
		(void) fprintf(fout, "/* actions for state %d */", s);
#endif
	(void) putc('\n', fout);
	for (i = 0; i < k; i++)
		if (temp[i] != 0) {
			(void) (ratfor ?
			    fprintf(fout, "data vstop(%d)/%d/\n",
			    aptr, temp[i]) :
			    fprintf(fout, "%d,\n", temp[i]));
#ifdef DEBUG
			if (debug)
				(void) printf("%d ", temp[i]);
#endif
			aptr++;
		}
	for (i = 0; i < n; i++) { /* copy fall back actions - all neg */
		ratfor ?
		    (void) fprintf(fout, "data vstop(%d)/%d/\n", aptr, neg[i]) :
		    (void) fprintf(fout, "%d,\n", neg[i]);
		aptr++;
#ifdef DEBUG
		if (debug)
			(void) printf("%d ", neg[i]);
#endif
		}
#ifdef DEBUG
	if (debug)
		(void) putchar('\n');
#endif
	(void) (ratfor ? fprintf(fout, "data vstop (%d)/0/\n", aptr) :
	    fprintf(fout, "0, \n"));
	aptr++;
}

#ifdef DEBUG
void
pccl(void)
{
	/* print character class sets */
	int i, j;
	(void) printf("char class intersection\n");
	for (i = 0; i < ccount; i++) {
		charc = 0;
		(void) printf("class %d:\n\t", i);
		for (j = 1; j < ncg; j++)
			if (cindex[j] == i) {
				allprint(j);
				if (charc > LINESIZE) {
					(void) printf("\n\t");
					charc = 0;
				}
			}
		(void) putchar('\n');
	}
	charc = 0;
	(void) printf("match:\n");
	for (i = 0; i < ncg; i++) {
		allprint(match[i]);
		if (charc > LINESIZE) {
			(void) putchar('\n');
			charc = 0;
		}
	}
	(void) putchar('\n');
}
#endif

void
mkmatch(void)
{
	int i;
	CHR tab[MAXNCG];
	for (i = 0; i < ccount; i++)
		tab[i] = 0;
	for (i = 1; i < ncg; i++)
		if (tab[cindex[i]] == 0)
			tab[cindex[i]] = i;
	/* tab[i] = principal char for new ccl i */
	for (i = 1; i < ncg; i++)
		match[i] = tab[cindex[i]];
}

void
layout(void)
{
	/* format and output final program's tables */
	int i, j, k;
	int  top, bot, startup, omin;
	startup = 0;
	for (i = 0; i < outsize; i++)
		verify[i] = advance[i] = 0;
	omin = 0;
	yytop = 0;
	for (i = 0; i <= stnum; i++) { /* for each state */
		j = gotof[i];
		if (j == -1) {
			stoff[i] = 0;
			continue;
		}
		bot = j;
		while (nchar[j])
			j++;
		top = j - 1;
#if DEBUG
		if (debug) {
			(void) printf("State %d: (layout)\n", i);
			for (j = bot; j <= top; j++) {
				(void) printf("  %o", nchar[j]);
				if (j % 10 == 0)
					(void) putchar('\n');
			}
			(void) putchar('\n');
		}
#endif
		while (verify[omin+ZCH])
			omin++;
		startup = omin;
#if DEBUG
		if (debug)
			(void) printf(
			"bot,top %d, %d startup begins %d\n",
			    bot, top, startup);
#endif
		if (chset) {
			do {
				startup += 1;
				if (startup > outsize - ZCH)
					error("output table overflow");
				for (j = bot; j <= top; j++) {
					k = startup+ctable[nchar[j]];
					if (verify[k])
						break;
				}
			} while (j <= top);
#if DEBUG
			if (debug)
				(void) printf(" startup will be %d\n",
				    startup);
#endif
			/* have found place */
			for (j = bot; j <= top; j++) {
				k = startup + ctable[nchar[j]];
				if (ctable[nchar[j]] <= 0)
					(void) printf(
					"j %d nchar %d ctable.nch %d\n",
					    j, (int)nchar[j], ctable[nchar[k]]);
				verify[k] = i + 1;	/* state number + 1 */
				advance[k] = nexts[j+1]+1;
				if (yytop < k)
					yytop = k;
			}
		} else {
			do {
				startup += 1;
				if (startup > outsize - ZCH)
					error("output table overflow");
				for (j = bot; j <= top; j++) {
					k = startup + nchar[j];
					if (verify[k])
						break;
				}
			} while (j <= top);
			/* have found place */
#if DEBUG
	if (debug)
		(void) printf(" startup going to be %d\n", startup);
#endif
			for (j = bot; j <= top; j++) {
				k = startup + nchar[j];
				verify[k] = i+1; /* state number + 1 */
				advance[k] = nexts[j+1] + 1;
				if (yytop < k)
					yytop = k;
			}
		}
		stoff[i] = startup;
	}

	/* stoff[i] = offset into verify, advance for trans for state i */
	/* put out yywork */
	if (ratfor) {
		(void) fprintf(fout, "define YYTOPVAL %d\n", yytop);
		rprint(verify, "verif", yytop+1);
		rprint(advance, "advan", yytop+1);
		shiftr(stoff, stnum);
		rprint(stoff, "stoff", stnum+1);
		shiftr(sfall, stnum);
		upone(sfall, stnum+1);
		rprint(sfall, "fall", stnum+1);
		bprint(extra, "extra", casecount+1);
		bprint((char *)match, "match", ncg);
		shiftr(atable, stnum);
		rprint(atable, "atable", stnum+1);
	}
	(void) fprintf(fout,
	"# define YYTYPE %s\n", stnum+1 >= NCH ? "int" : "unsigned char");
	(void) fprintf(fout,
	"struct yywork { YYTYPE verify, advance; } yycrank[] = {\n");
	for (i = 0; i <= yytop; i += 4) {
		for (j = 0; j < 4; j++) {
			k = i+j;
			if (verify[k])
				(void) fprintf(fout,
				"{ %d,%d },\t", verify[k], advance[k]);
			else
				(void) fprintf(fout, "{ 0,0 },\t");
		}
		(void) putc('\n', fout);
	}
	(void) fprintf(fout, "{ 0,0 } };\n");

	/* put out yysvec */

	(void) fprintf(fout, "struct yysvf yysvec[] = {\n");
	(void) fprintf(fout, "{ 0,\t0,\t0 },\n");
	for (i = 0; i <= stnum; i++) {	/* for each state */
		if (cpackflg[i])
			stoff[i] = -stoff[i];
		(void) fprintf(fout, "{ yycrank+%d,\t", stoff[i]);
		if (sfall[i] != -1)
			(void) fprintf(fout,
			"yysvec+%d,\t", sfall[i]+1); /* state + 1 */
		else
			(void) fprintf(fout, "0,\t\t");
		if (atable[i] != -1)
			(void) fprintf(fout, "yyvstop+%d },", atable[i]);
		else
			(void) fprintf(fout, "0 },\t");
#ifdef DEBUG
		(void) fprintf(fout, "\t\t/* state %d */", i);
#endif
		(void) putc('\n', fout);
	}
	(void) fprintf(fout, "{ 0,\t0,\t0 } };\n");

	/* put out yymatch */

	(void) fprintf(fout, "struct yywork *yytop = yycrank+%d;\n", yytop);
	(void) fprintf(fout, "struct yysvf *yybgin = yysvec+1;\n");
	if (optim) {
		if (handleeuc) {
			(void) fprintf(fout, "int yymatch[] = {\n");
		} else {
			(void) fprintf(fout, "char yymatch[] = {\n");
		}
		if (chset == 0) { /* no chset, put out in normal order */
			for (i = 0; i < ncg; i += 8) {
				for (j = 0; j < 8; j++) {
					int fbch;
					fbch = match[i+j];
					(void) fprintf(fout, "%3d, ", fbch);
				}
				(void) putc('\n', fout);
			}
		} else {
			int *fbarr;
			/*LINTED: E_BAD_PTR_CAST_ALIGN*/
			fbarr = (int *)myalloc(2*MAXNCG, sizeof (*fbarr));
			if (fbarr == 0)
				error("No space for char table reverse", 0);
			for (i = 0; i < MAXNCG; i++)
				fbarr[i] = 0;
			for (i = 0; i < ncg; i++)
				fbarr[ctable[i]] = ctable[match[i]];
			for (i = 0; i < ncg; i += 8) {
				for (j = 0; j < 8; j++)
					(void) fprintf(fout, "0%-3o,",
					    fbarr[i+j]);
				(void) putc('\n', fout);
			}
			free(fbarr);
		}
		(void) fprintf(fout, "0};\n");
	}
	/* put out yyextra */
	(void) fprintf(fout, "char yyextra[] = {\n");
	for (i = 0; i < casecount; i += 8) {
		for (j = 0; j < 8; j++)
			(void) fprintf(fout, "%d,", i+j < NACTIONS ?
			    extra[i+j] : 0);
		(void) putc('\n', fout);
	}
	(void) fprintf(fout, "0};\n");
	if (handleeuc) {
		/* Put out yycgidtbl */
		(void) fprintf(fout, "#define YYNCGIDTBL %d\n", ncgidtbl);
		(void) fprintf(fout, "\tunsigned long yycgidtbl[]={");
		/*
		 * Use "unsigned long" instead of "lchar" to minimize
		 * the name-space polution for the application program.
		 */
		for (i = 0; i < ncgidtbl; ++i) {
			if (i%8 == 0)
				(void) fprintf(fout, "\n\t\t");
			(void) fprintf(fout, "0x%08x, ",  (int)yycgidtbl[i]);
		}
		(void) fprintf(fout, "\n\t0};\n");
	}
}

static void
rprint(int *a, char *s, int n)
{
	int i;
	(void) fprintf(fout, "block data\n");
	(void) fprintf(fout, "common /L%s/ %s\n", s, s);
	(void) fprintf(fout, "define S%s %d\n", s, n);
	(void) fprintf(fout, "integer %s (S%s)\n", s, s);
	for (i = 1; i <= n; i++) {
		if (i%8 == 1)
			(void) fprintf(fout, "data ");
		(void) fprintf(fout, "%s (%d)/%d/", s, i, a[i]);
		(void) fprintf(fout, (i%8 && i < n) ? ", " : "\n");
	}
	(void) fprintf(fout, "end\n");
}

static void
shiftr(int *a, int n)
{
	int i;
	for (i = n; i >= 0; i--)
		a[i+1] = a[i];
}

static void
upone(int *a, int n)
{
	int i;
	for (i = 0; i <= n; i++)
		a[i]++;
}

static void
bprint(char *a, char *s, int n)
{
	int i, j, k;
	(void) fprintf(fout, "block data\n");
	(void) fprintf(fout, "common /L%s/ %s\n", s, s);
	(void) fprintf(fout, "define S%s %d\n", s, n);
	(void) fprintf(fout, "integer %s (S%s)\n", s, s);
	for (i = 1; i < n; i += 8) {
		(void) fprintf(fout, "data %s (%d)/%d/", s, i, a[i]);
		for (j = 1; j < 8; j++) {
			k = i+j;
			if (k < n)
				(void) fprintf(fout,
				    ", %s (%d)/%d/", s, k, a[k]);
		}
		(void) putc('\n', fout);
	}
	(void) fprintf(fout, "end\n");
}

#ifdef PP
static void
padd(int **array, int n)
{
	int i, *j, k;
	array[n] = nxtpos;
	if (count == 0) {
		*nxtpos++ = 0;
		return;
	}
	for (i = tptr-1; i >= 0; i--) {
		j = array[i];
		if (j && *j++ == count) {
			for (k = 0; k < count; k++)
				if (!tmpstat[*j++])
					break;
			if (k >= count) {
				array[n] = array[i];
				return;
			}
		}
	}
	add(array, n);
}
#endif
