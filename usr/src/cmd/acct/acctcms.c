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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	acctcms [-a] [-c] [-j] [-n] [-s] [-p] [-o] [-t] [file...]
 *	summarize per-process accounting
 *	-a	output in ascii, rather than [pt]cms.h format
 *	-c	sort by total cpu, rather than total kcore-minutes
 *	-j	anything used only once -> ***other
 *	-n	sort by number of processes
 *	-s	any following files already in pcms.h format
 *      -p      output prime time command summary (only with -a)
 *      -o      output non-prime time (offshift) command summary (only
 *		with -a option)
 *	-t	process records in total (old) style (tcms.h) format
 *	file	file in [pt]cms.h (if -s seen already) or acct.h (if not)
 *	expected use:
 *	acctcms /var/adm/pacct? > today; acctcms -s old today >new
 *	cp new old; rm new
 *	acctcms -a today; acctcms -a old
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include "acctdef.h"
#include <ctype.h>
#include <string.h>
#include <sys/acct.h>
#include <stdlib.h>

int	csize = CSIZE;

/*
 *  Total cms records format
 */
struct tcms {
	char	tcm_comm[8];	/* command name */
	long	tcm_pc;		/* number of processes */
	float	tcm_cpu;	/* cpu time(min) */
	float	tcm_real;	/* real time(min) */
	float	tcm_kcore;	/* kcore-minutes */
	ulong_t	tcm_io;		/* chars transferred */
	ulong_t	tcm_rw;		/* blocks read */
} ;
struct tcms	*tcm;
/*
 * prime/nonprime CMS record format
 */
struct pcms {
	char	pcm_comm[8];	/* command name */
	long	pcm_pc[2];	/* number of processes */
	float	pcm_cpu[2];	/* cpu time(min) */
	float	pcm_real[2];	/* real time(min) */
	float	pcm_kcore[2];	/* kcore-minutes */
	float	pcm_io[2];	/* chars transferred */
	float	pcm_rw[2];	/* blocks read */
} ;
struct pcms	*pcm;
struct  tcms    tcmtmp  = {{'*','*','*','o','t','h','e','r'}};
struct  pcms    pcmtmp  = {{'*','*','*','o','t','h','e','r'}};
int	aflg;
int	cflg;
int	jflg;
int	nflg;
int	sflg;
int	pflg;
int	oflg;
int	tflg;
int	errflg;

#ifdef uts
float   expand();
#else
ulong_t	expand();
#endif

void outputc(void);
void totprnt(struct pcms *);
void pprint(struct pcms *);
void prnt(struct pcms *, int);
void print(struct pcms *);
void outputa(void);
void toutptc(void);
void tprint(struct tcms *);
void toutpta(void);
int ncmp(struct pcms *, struct pcms *);
int tncmp(struct tcms *, struct tcms *);
int tccmp(struct tcms *, struct tcms *);
int tkcmp(struct tcms *, struct tcms *);
int ccmp(struct pcms *, struct pcms *);
int kcmp(struct pcms *, struct pcms *);
void tdofile(char *);
void dofile(char *);
void tfixjunk(void);
void fixjunk(void);
void tcmadd(struct tcms *, struct tcms *);
void pcmadd(struct pcms *, struct pcms *);
void tsqueeze(void);
void squeeze(void);

/*  Format specification for ASCII printing */

char	*fmtcmd =	"%-8.8s",
	*fmtcnt =	"%8ld",
	*fmtkcore =	" %11.2f",
	*fmtcpu =	" %9.2f",
	*fmtreal =	" %12.2f",
	*fmtmsz =	" %7.2f",
	*fmtmcpu =	" %6.2f",
	*fmthog =	" %5.2f",
	*fmtcharx =	" %12.0f",
	*fmtblkx =	" %10.0f" ;

int
main(int argc, char **argv)
{
	int	c;

	while((c = getopt(argc, argv, "acjnspot")) != EOF)
	switch(c) {
		case 'a':
			aflg++;
			continue;
		case 'c':
			cflg++;
			continue;
		case 'j':
			jflg++;
			continue;
		case 'n':
			nflg++;
			continue;
		case 's':
			sflg++;
			continue;
		case 'p':
			pflg++;
			continue;
		case 'o':
			oflg++;
			continue;
		case 't':
			tflg++;
			continue;
		default:
			errflg++;
			continue;
	}
	if(errflg){
		fprintf(stderr, "Usage: %s [-acjnspot] [file ...]\n", argv[0]);
		exit(1);
	}
	if(tflg) {
		if( (tcm = (struct tcms *)calloc(CSIZE, sizeof(struct tcms))) == NULL) {
			fprintf(stderr, "%s: Cannot allocate memory\n", argv[0]);
			exit(5);
		}
		for(; optind < argc; optind++)
			tdofile(argv[optind]);
		if (jflg)
			tfixjunk();
		tsqueeze();
		qsort(tcm, csize, sizeof(tcm[0]),
		    (int (*)(const void *, const void *))
		     ( nflg ? tncmp: (cflg? tccmp: tkcmp)));
		if (aflg)
			toutpta();
		else
			toutptc();
	} else {
		if( (pcm = (struct pcms *)calloc(CSIZE, sizeof(struct pcms))) == NULL) {
			fprintf(stderr, "%s: Cannot allocate memory\n", argv[0]);
			exit(6);
		}
		for(; optind < argc; optind++)
			dofile(argv[optind]);
		if (jflg)
			fixjunk();
		squeeze();
		qsort(pcm, csize, sizeof(pcm[0]),
		    (int (*)(const void *, const void *))
		    (nflg? ncmp: (cflg? ccmp: kcmp)));
		if (aflg)
			outputa();
		else
			outputc();
	}
	exit(0);

}

void
tdofile(char *fname)
{
	struct tcms cmt;
	union {
		struct acct ab;		/* SVR4 acct structure */
		struct o_acct oab;	/* SVR3 acct structure */
	} acct;
	int ver = 0;
	ulong_t	mem;
	ulong_t	cpu;
	ulong_t	real;

	if (freopen(fname, "r", stdin) == NULL) {
		fprintf(stderr,  "acctcms: cannot open %s\n", fname);
		return;
	}

	if (sflg)
		while (fread(&cmt, sizeof(cmt), 1, stdin) == 1)
			tenter(&cmt);
	else {
		if (fread(&acct.ab, sizeof(acct.ab), 1, stdin) == 1)
			/* check for expanded account structure flag */
			if (acct.ab.ac_flag & AEXPND)
				ver = 2;		/* 4.0 acct file */
			else
				ver = 1;		/* SVR3.x acct file */

		rewind(stdin);	/* reset file pointer */

 		switch(ver) {

		default:
				/* this can't happen */
			fprintf(stderr, "acctcms: encountered bad version number\n");
			return;
		case 1 :
			while (fread(&acct.oab, sizeof(acct.oab), 1, stdin) == 1) {
				CPYN(cmt.tcm_comm, acct.oab.ac_comm);
				cmt.tcm_pc = 1;
				cpu = expand(acct.oab.ac_stime)+
					expand(acct.oab.ac_utime);
				cmt.tcm_cpu = MINT(cpu);
				real = expand(acct.oab.ac_etime);
				cmt.tcm_real = MINT(real);
				mem = expand(acct.oab.ac_mem);
				cmt.tcm_kcore = MINT(KCORE(mem));
				cmt.tcm_io = expand(acct.oab.ac_io);
				cmt.tcm_rw = expand(acct.oab.ac_rw);
				tenter(&cmt);
			}
			break;
		case 2 :

			while (fread(&acct.ab, sizeof(acct.ab), 1, stdin) == 1) {
				CPYN(cmt.tcm_comm, acct.ab.ac_comm);
				cmt.tcm_pc = 1;
				cpu = expand(acct.oab.ac_stime)+
					expand(acct.oab.ac_utime);
				cmt.tcm_cpu = MINT(cpu);
				real = expand(acct.ab.ac_etime);
				cmt.tcm_real = MINT(real);
				mem = expand(acct.ab.ac_mem);
				cmt.tcm_kcore = MINT(KCORE(mem));
				cmt.tcm_io = expand(acct.ab.ac_io);
				cmt.tcm_rw = expand(acct.ab.ac_rw);
				tenter(&cmt);
			}
			break;
		}
	}
}

void
dofile(char *fname)
{
	union {
		struct acct ab;
		struct o_acct oab;
	} acct;
	struct pcms 	pcmt;
	double		ratio;
	long		elaps[2];
	ulong_t		etime;
	double	dtmp;
	unsigned long	ltmp;
	ulong_t	mem;
	ulong_t	cpu;
	ulong_t	real;

	if (freopen(fname, "r", stdin) == NULL) {
		fprintf(stderr,  "acctcms: cannot open %s\n", fname);
		return;
	}

	if (sflg)
		while (fread(&pcmt, sizeof(pcmt), 1, stdin) == 1)
			enter(&pcmt);
	else {
		int ver = 0;

		if (fread(&acct.ab, sizeof(acct.ab), 1, stdin) == 1)
			/* check for expanded account structure flag */
			if (acct.ab.ac_flag & AEXPND)
				ver = 2;		/* 4.0 acct file */
			else
				ver = 1;		/* SVR3.x acct file */

		rewind(stdin);	/* reset file pointer */

		switch(ver) {

		default :
 				/* this can't happen */
			fprintf(stderr, "acctcms: encountered bad version number\n");
			return;
		case 1 :
	
			while (fread(&acct.oab, sizeof(acct.oab), 1, stdin) == 1) {
				CPYN(pcmt.pcm_comm, acct.oab.ac_comm);
			/*
			** Approximate P/NP split as same as elapsed time
		 	*/
				if((etime = SECS(expand(acct.oab.ac_etime))) == 0)
					etime = 1;
				if (pnpsplit(acct.oab.ac_btime, etime, elaps)
				    == 0) {
					(void) fprintf(stderr, "acctcms: could "
					    "not calculate prime/non-prime "
					    "hours\n");
					exit(1);
				}
				ratio = (double)elaps[PRIME]/(double)etime;
				if(elaps[PRIME] > elaps[NONPRIME]) {
					pcmt.pcm_pc[PRIME] = 1;
					pcmt.pcm_pc[NONPRIME] = 0;
				} else {
					pcmt.pcm_pc[PRIME] = 0;
					pcmt.pcm_pc[NONPRIME] = 1;
				}
				cpu = expand(acct.oab.ac_stime)+
					expand(acct.oab.ac_utime);
				dtmp = MINT(cpu);
				pcmt.pcm_cpu[PRIME] = dtmp * ratio;
				pcmt.pcm_cpu[NONPRIME] = (ratio == 1.0) ? 0.0 :
					(dtmp - pcmt.pcm_cpu[PRIME]);
				real = expand(acct.oab.ac_etime);
				dtmp = MINT(real);
				pcmt.pcm_real[PRIME] = dtmp * ratio;
				pcmt.pcm_real[NONPRIME] = (ratio == 1.0) ? 0.0 :
					(dtmp - pcmt.pcm_real[PRIME]);
				mem = expand(acct.oab.ac_mem);
				dtmp = MINT(KCORE(mem));
				pcmt.pcm_kcore[PRIME] = dtmp * ratio;
				pcmt.pcm_kcore[NONPRIME] = (ratio == 1.0) ? 0.0 :
					(dtmp - pcmt.pcm_kcore[PRIME]);
				ltmp = expand(acct.oab.ac_io);
				pcmt.pcm_io[PRIME] = (double)ltmp * ratio;
				pcmt.pcm_io[NONPRIME] = (ratio == 1.0) ? 0.0 :
					((double)ltmp - pcmt.pcm_io[PRIME]);
				ltmp = expand(acct.oab.ac_rw);
				pcmt.pcm_rw[PRIME] = (double)ltmp * ratio;
				pcmt.pcm_rw[NONPRIME] = (ratio == 1.0) ? 0.0 :
					((double)ltmp - pcmt.pcm_rw[PRIME]);
				enter(&pcmt);
			}

			break;
		case 2 :
			while (fread(&acct.ab, sizeof(acct.ab), 1, stdin) == 1) {
				CPYN(pcmt.pcm_comm, acct.ab.ac_comm);
				/*
				** Approximate P/NP split as same as elapsed time
		 		*/
				if((etime = SECS(expand(acct.ab.ac_etime))) == 0)
					etime = 1;
				if(pnpsplit(acct.ab.ac_btime, etime, elaps) == 0) {
					fprintf(stderr, "acctcms: could not calculate prime/non-prime hours\n");
					exit(1);
				}
				ratio = (double)elaps[PRIME]/(double)etime;
				if(elaps[PRIME] > elaps[NONPRIME]) {
					pcmt.pcm_pc[PRIME] = 1;
					pcmt.pcm_pc[NONPRIME] = 0;
				} else {
					pcmt.pcm_pc[PRIME] = 0;
					pcmt.pcm_pc[NONPRIME] = 1;
				}
				cpu = expand(acct.ab.ac_stime)+
					expand(acct.ab.ac_utime);
				dtmp = MINT(cpu);
				pcmt.pcm_cpu[PRIME] = dtmp * ratio;
				pcmt.pcm_cpu[NONPRIME] = (ratio == 1.0) ? 0.0 :
					(dtmp - pcmt.pcm_cpu[PRIME]);
				real = expand(acct.ab.ac_etime);
				dtmp = MINT(real);
				pcmt.pcm_real[PRIME] = dtmp * ratio;
				pcmt.pcm_real[NONPRIME] = (ratio == 1.0) ? 0.0 :
					(dtmp - pcmt.pcm_real[PRIME]);
				mem = expand(acct.ab.ac_mem);
				dtmp = MINT(KCORE(mem));
				pcmt.pcm_kcore[PRIME] = dtmp * ratio;
				pcmt.pcm_kcore[NONPRIME] = (ratio == 1.0) ? 0.0 :
					(dtmp - pcmt.pcm_kcore[PRIME]);
				ltmp = expand(acct.ab.ac_io);
				pcmt.pcm_io[PRIME] = (double)ltmp * ratio;
				pcmt.pcm_io[NONPRIME] = (ratio == 1.0) ? 0.0 :
					((double)ltmp - pcmt.pcm_io[PRIME]);
				ltmp = expand(acct.ab.ac_rw);
				pcmt.pcm_rw[PRIME] = (double)ltmp * ratio;
				pcmt.pcm_rw[NONPRIME] = (ratio == 1.0) ? 0.0 :
					((double)ltmp - pcmt.pcm_rw[PRIME]);
				enter(&pcmt);
			}

			break;
		}
	}
}

int
tenter(struct tcms *p)
{
	int i;
	int j;
	struct tcms *ntcm;
	for (i = j = 0; j < sizeof(p->tcm_comm); j++) {
		if (p->tcm_comm[j] && p->tcm_comm[j] <= 037)
			p->tcm_comm[j] = '?';
		i = i*7 + p->tcm_comm[j];	/* hash function */
	}
	if (i < 0)
		i = -i;
	for (i %= csize, j = 0; tcm[i].tcm_comm[0] && j != csize; i = (i+1)%csize, j++)
		if (EQN(p->tcm_comm, tcm[i].tcm_comm))
			break;
	if(j == csize) {
		if ((ntcm = (struct tcms *) realloc(tcm,
			(csize + CSIZE - 1) * sizeof (struct tcms))) == NULL) {
			fprintf(stderr,
				"acctcms: Cannot reallocate memory (tcm)\n");
			return(-1);
		} else {
			memset(&ntcm[csize], 0, CSIZE - 1);
			tcm = ntcm;
			if (!EQN(p->tcm_comm, tcm[i].tcm_comm))
				i = csize;
			csize = csize + CSIZE - 1;
		}
	}
	if (tcm[i].tcm_comm[0] == 0)
		CPYN(tcm[i].tcm_comm, p->tcm_comm);
	tcmadd(&tcm[i], p);
	return(i);
}

int
enter(struct pcms *p)
{
	int i;
	int j;
	struct pcms *npcm;
	for (i = j = 0; j < sizeof(p->pcm_comm); j++) {
		if (p->pcm_comm[j] && p->pcm_comm[j] <= 037)
			p->pcm_comm[j] = '?';
		i = i*7 + p->pcm_comm[j];	/* hash function */
	}
	if (i < 0)
		i = -i;
	for (i %= csize, j = 0; pcm[i].pcm_comm[0] && j != csize; i = (i+1)%csize, j++)
		if (EQN(p->pcm_comm, pcm[i].pcm_comm))
			break;
	if(j == csize) {
		if ((npcm = (struct pcms *) realloc(pcm,
			(csize + CSIZE - 1) * sizeof (struct pcms))) == NULL) {
			fprintf(stderr,
				"acctcms: Cannot reallocate memory (pcm)\n");
			return(-1);
		} else {
			memset(&npcm[csize], 0, CSIZE - 1);
			pcm = npcm;
			if (!EQN(p->pcm_comm, pcm[i].pcm_comm))
				i = csize;
			csize = csize + CSIZE - 1;
		}
	}
	if (pcm[i].pcm_comm[0] == 0)
		CPYN(pcm[i].pcm_comm, p->pcm_comm);
	pcmadd(&pcm[i], p);
	return(i);
}

void
tfixjunk(void)	/* combine commands used only once */
{
	int i, j;
	j = tenter(&tcmtmp);
	for (i = 0; i < csize; i++)
		if (i != j && tcm[i].tcm_comm[0] && tcm[i].tcm_pc <= 1) {
			tcmadd(&tcm[j], &tcm[i]);
			tcm[i].tcm_comm[0] = 0;
		}
}

void
fixjunk(void)	/* combine commands used only once */
{
	int i, j;
	j = enter(&pcmtmp);
	for (i = 0; i < csize; i++)
		if (i != j && pcm[i].pcm_comm[0] && (pcm[i].pcm_pc[PRIME] + pcm[i].pcm_pc[NONPRIME]) <= 1) {
			pcmadd(&pcm[j], &pcm[i]);
			pcm[i].pcm_comm[0] = 0;
		}
}

void
tcmadd(struct tcms *p1, struct tcms *p2)
{
	p1->tcm_pc += p2->tcm_pc;
	p1->tcm_cpu = p1->tcm_cpu + p2->tcm_cpu;
	p1->tcm_real = p1->tcm_real + p2->tcm_real;
	p1->tcm_kcore = p1->tcm_kcore + p2->tcm_kcore;
	p1->tcm_io += p2->tcm_io;
	p1->tcm_rw += p2->tcm_rw;
}

void
pcmadd(struct pcms *p1, struct pcms *p2)
{
	p1->pcm_pc[PRIME] += p2->pcm_pc[PRIME];
	p1->pcm_pc[NONPRIME] += p2->pcm_pc[NONPRIME];
	p1->pcm_cpu[PRIME] += p2->pcm_cpu[PRIME];
	p1->pcm_cpu[NONPRIME] += p2->pcm_cpu[NONPRIME];
	p1->pcm_real[PRIME] += p2->pcm_real[PRIME];
	p1->pcm_real[NONPRIME] += p2->pcm_real[NONPRIME];
	p1->pcm_kcore[PRIME] += p2->pcm_kcore[PRIME];
	p1->pcm_kcore[NONPRIME] += p2->pcm_kcore[NONPRIME];
	p1->pcm_io[PRIME] += p2->pcm_io[PRIME];
	p1->pcm_io[NONPRIME] += p2->pcm_io[NONPRIME];
	p1->pcm_rw[PRIME] += p2->pcm_rw[PRIME];
	p1->pcm_rw[NONPRIME] += p2->pcm_rw[NONPRIME];
}

void
tsqueeze(void)	/* get rid of holes in hash table */
{
	int i, k;

	for (i = k = 0; i < csize; i++)
		if (tcm[i].tcm_comm[0]) {
			CPYN(tcm[k].tcm_comm, tcm[i].tcm_comm);
			tcm[k].tcm_pc = tcm[i].tcm_pc;
			tcm[k].tcm_cpu = tcm[i].tcm_cpu;
			tcm[k].tcm_real = tcm[i].tcm_real;
			tcm[k].tcm_kcore = tcm[i].tcm_kcore;
			tcm[k].tcm_io = tcm[i].tcm_io;
			tcm[k].tcm_rw = tcm[i].tcm_rw;
			k++;
		}
	csize = k;
}

void
squeeze(void)	/* get rid of holes in hash table */
{
	int i, k;

	for (i = k = 0; i < csize; i++)
		if (pcm[i].pcm_comm[0]) {
			CPYN(pcm[k].pcm_comm, pcm[i].pcm_comm);
			pcm[k].pcm_pc[PRIME] = pcm[i].pcm_pc[PRIME];
			pcm[k].pcm_pc[NONPRIME] = pcm[i].pcm_pc[NONPRIME];
			pcm[k].pcm_cpu[PRIME] = pcm[i].pcm_cpu[PRIME];
			pcm[k].pcm_cpu[NONPRIME] = pcm[i].pcm_cpu[NONPRIME];
			pcm[k].pcm_real[PRIME] = pcm[i].pcm_real[PRIME];
			pcm[k].pcm_real[NONPRIME] = pcm[i].pcm_real[NONPRIME];
			pcm[k].pcm_kcore[PRIME] = pcm[i].pcm_kcore[PRIME];
			pcm[k].pcm_kcore[NONPRIME] = pcm[i].pcm_kcore[NONPRIME];
			pcm[k].pcm_io[PRIME] = pcm[i].pcm_io[PRIME];
			pcm[k].pcm_io[NONPRIME] = pcm[i].pcm_io[NONPRIME];
			pcm[k].pcm_rw[PRIME] = pcm[i].pcm_rw[PRIME];
			pcm[k].pcm_rw[NONPRIME] = pcm[i].pcm_rw[NONPRIME];
			k++;
		}
	csize = k;
}

int
tccmp(struct tcms *p1, struct tcms *p2)
{
	if (p1->tcm_cpu == p2->tcm_cpu)
		return(0);
	return ((p2->tcm_cpu > p1->tcm_cpu)? 1 : -1);
}

int
ccmp(struct pcms *p1, struct pcms *p2)
{
	int	index;

	if( (pflg && oflg) || (!pflg && !oflg) ) {
		if (p1->pcm_cpu[PRIME] + p1->pcm_cpu[NONPRIME] == p2->pcm_cpu[PRIME] + p2->pcm_cpu[NONPRIME])
			return(0);
		return ((p2->pcm_cpu[PRIME] + p2->pcm_cpu[NONPRIME] > p1->pcm_cpu[PRIME] + p1->pcm_cpu[NONPRIME])? 1 : -1);
	}
	index = pflg ? PRIME : NONPRIME;
	if (p1->pcm_cpu[index] == p2->pcm_cpu[index])
		return(0);
	return ((p2->pcm_cpu[index] > p1->pcm_cpu[index])? 1 : -1);
}

int
tkcmp(struct tcms *p1, struct tcms *p2)
{
	if (p1->tcm_kcore == p2->tcm_kcore)
		return(0);
	return ((p2->tcm_kcore > p1->tcm_kcore)? 1 : -1);
}

int
kcmp(struct pcms *p1, struct pcms *p2)
{
	int	index;

	if( (pflg && oflg) || (!pflg && !pflg) ){
		if (p1->pcm_kcore[PRIME] + p1->pcm_kcore[NONPRIME] == p2->pcm_kcore[PRIME] + p2->pcm_kcore[NONPRIME])
			return(0);
		return ((p2->pcm_kcore[PRIME] + p2->pcm_kcore[NONPRIME] > p1->pcm_kcore[PRIME] + p1->pcm_kcore[NONPRIME])? 1 : -1);
	}
	index = pflg ? PRIME : NONPRIME;
	if (p1->pcm_kcore[index] == p2->pcm_kcore[index])
		return(0);
	return ((p2->pcm_kcore[index] > p1->pcm_kcore[index])? 1 : -1);
}

int
tncmp(struct tcms *p1, struct tcms *p2)
{
	if (p1->tcm_pc == p2->tcm_pc)
		return(0);
	return ((p2->tcm_pc > p1->tcm_pc)? 1 : -1);
}

int
ncmp(struct pcms *p1, struct pcms *p2)
{
	int	index;

	if( (pflg && oflg) || (!pflg && !oflg) ) {
		if (p1->pcm_pc[PRIME] + p1->pcm_pc[NONPRIME] == p2->pcm_pc[PRIME] + p2->pcm_pc[NONPRIME])
			return(0);
		return ((p2->pcm_pc[PRIME] + p2->pcm_pc[NONPRIME] > p1->pcm_pc[PRIME] + p1->pcm_pc[NONPRIME])? 1 : -1);
	}
	index =  pflg ? PRIME : NONPRIME;
	if (p1->pcm_pc[index] == p2->pcm_pc[index])
		return(0);
	return ((p2->pcm_pc[index] > p1->pcm_pc[index])? 1 : -1);
}

char	thd1[] =
"COMMAND   NUMBER      TOTAL       TOTAL       TOTAL   MEAN     MEAN     HOG      CHARS        BLOCKS\n";
char	thd2[] =
"NAME        CMDS    KCOREMIN     CPU-MIN     REAL-MIN SIZE-K  CPU-MIN  FACTOR   TRNSFD         READ\n";

void
toutpta(void)
{
	int i;

	printf(thd1);
	printf(thd2);
	printf("\n");
	for (i = 0; i < csize; i++)
		tcmadd(&tcmtmp, &tcm[i]);
	CPYN(tcmtmp.tcm_comm, "TOTALS");
	tprint(&tcmtmp);
	printf("\n");
	for (i = 0; i < csize; i++)
		tprint(&tcm[i]);
}

void
tprint(struct tcms *p)
{
	printf("%-8.8s", p->tcm_comm);
	printf(" %7ld", p->tcm_pc);
	printf(" %11.2f", p->tcm_kcore);
	printf(" %10.2f", p->tcm_cpu);
	printf(" %12.2f", p->tcm_real);
	if(p->tcm_cpu == 0)  p->tcm_cpu = 1;
	printf(" %6.2f", p->tcm_kcore/p->tcm_cpu);
	if(p->tcm_pc == 0)  p->tcm_pc = 1;
	printf(" %7.2f", p->tcm_cpu/p->tcm_pc);
	if (p->tcm_real == 0)
		p->tcm_real = 1;
	printf(" %8.2f", p->tcm_cpu/p->tcm_real);
	printf(" %11lu", p->tcm_io);
	printf(" %11lu\n", p->tcm_rw);
}

void
toutptc(void)
{
	int i;

	for (i = 0; i < csize; i++)
		fwrite(&tcm[i], sizeof(tcm[i]), 1, stdout);
}

char	hd1[] =
"COMMAND   NUMBER      TOTAL       TOTAL       TOTAL   MEAN    MEAN     HOG         CHARS     BLOCKS\n";
char	hd2[] =
"NAME        CMDS    KCOREMIN     CPU-MIN   REAL-MIN  SIZE-K  CPU-MIN  FACTOR      TRNSFD      READ\n";
char	hd3[] =
"COMMAND        NUMBER         TOTAL          CPU-MIN                 REAL-MIN        MEAN    MEAN      HOG       CHARS       BLOCKS\n";
char	hd4[] =
"NAME         (P)    (NP)   KCOREMIN       (P)      (NP)          (P)         (NP)  SIZE-K  CPU-MIN   FACTOR     TRNSFD        READ\n";
char	hdprime[] =
"                                   PRIME TIME COMMAND SUMMARY\n";
char	hdnonprime[] =
"                                  NON-PRIME TIME COMMAND SUMMARY\n";
char	hdtot[] =
"                                     TOTAL COMMAND SUMMARY\n";
char	hdp[] =
"                                PRIME/NON-PRIME TIME COMMAND SUMMARY\n";

void
outputa(void)
{
	int i;

	if( pflg && oflg ) printf(hdp);
	else if(pflg) printf(hdprime);
	else if(oflg) printf(hdnonprime);
	else printf(hdtot);
	if( (!pflg && !oflg) || (pflg ^ oflg)) {
		printf(hd1);
		printf(hd2);
	}
	else {
		printf(hd3);
		printf(hd4);
	}
	printf("\n");
	for (i = 0; i < csize; i++)
		pcmadd(&pcmtmp, &pcm[i]);
	CPYN(pcmtmp.pcm_comm, "TOTALS");
	print(&pcmtmp);
	printf("\n");
	for (i = 0; i < csize; i++)
		print(&pcm[i]);
}

void
print(struct pcms *p)
{
	if(pflg && oflg) pprint(p);
	else if(pflg || oflg) prnt(p, pflg ? PRIME : NONPRIME);
	else totprnt(p);
}

void
prnt(struct pcms *p, int hr)
{
	if(p->pcm_pc[hr] == 0) return;
	printf(fmtcmd, p->pcm_comm);
	printf(fmtcnt, p->pcm_pc[hr]);
	printf(fmtkcore, p->pcm_kcore[hr]);
	printf(fmtcpu, p->pcm_cpu[hr]);
	printf(fmtreal, p->pcm_real[hr]);
	if(p->pcm_cpu[hr] == 0)  p->pcm_cpu[hr] = 1;
	printf(fmtmsz, p->pcm_kcore[hr]/p->pcm_cpu[hr]);
	if(p->pcm_pc[hr] == 0)  p->pcm_pc[hr] = 1;
	printf(fmtmcpu, p->pcm_cpu[hr]/p->pcm_pc[hr]);
	if (p->pcm_real[hr] == 0)
		p->pcm_real[hr] = 1;
	printf(fmthog, p->pcm_cpu[hr]/p->pcm_real[hr]);
	printf(fmtcharx,p->pcm_io[hr]);
	printf(fmtblkx,p->pcm_rw[hr]);
	printf("\n");
}

void
pprint(struct pcms *p)
{
	printf(fmtcmd, p->pcm_comm);
	printf(fmtcnt, p->pcm_pc[PRIME]);
	printf(fmtcnt, p->pcm_pc[NONPRIME]);
	printf(fmtkcore, TOTAL(p->pcm_kcore));
	printf(fmtcpu, p->pcm_cpu[PRIME]);
	printf(fmtcpu, p->pcm_cpu[NONPRIME]);
	printf(fmtreal, p->pcm_real[PRIME]);
	printf(fmtreal, p->pcm_real[NONPRIME]);
	if(TOTAL(p->pcm_cpu) == 0)  p->pcm_cpu[PRIME] = 1;
	printf(fmtmsz, TOTAL(p->pcm_kcore)/TOTAL(p->pcm_cpu));
	if(TOTAL(p->pcm_pc) == 0)  p->pcm_pc[PRIME] = 1;
	printf(fmtmcpu, TOTAL(p->pcm_cpu)/TOTAL(p->pcm_pc));
	if ( TOTAL(p->pcm_real) == 0)
		p->pcm_real[PRIME] = 1;
	printf(fmthog, TOTAL(p->pcm_cpu)/TOTAL(p->pcm_real));
	printf(fmtcharx,TOTAL(p->pcm_io));
	printf(fmtblkx, TOTAL(p->pcm_rw));
	printf("\n");
}

void
totprnt(struct pcms *p)
{
	printf(fmtcmd, p->pcm_comm);
	printf(fmtcnt, TOTAL(p->pcm_pc));
	printf(fmtkcore, TOTAL(p->pcm_kcore));
	printf(fmtcpu, TOTAL(p->pcm_cpu));
	printf(fmtreal, TOTAL(p->pcm_real));
	if(TOTAL(p->pcm_cpu) == 0)  p->pcm_cpu[PRIME] = 1;
	printf(fmtmsz, TOTAL(p->pcm_kcore)/TOTAL(p->pcm_cpu));
	if(TOTAL(p->pcm_pc) == 0)  p->pcm_pc[PRIME] = 1;
	printf(fmtmcpu, TOTAL(p->pcm_cpu)/TOTAL(p->pcm_pc));
	if (TOTAL(p->pcm_real) == 0)
		p->pcm_real[PRIME] = 1;
	printf(fmthog, TOTAL(p->pcm_cpu)/TOTAL(p->pcm_real));
	printf(fmtcharx,TOTAL(p->pcm_io));
	printf(fmtblkx,TOTAL(p->pcm_rw));
	printf("\n");
}

void
outputc(void)
{
	int i;

	for (i = 0; i < csize; i++)
		fwrite(&pcm[i], sizeof(pcm[i]), 1, stdout);
}
