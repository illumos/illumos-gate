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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "kvm.h"

#include <nlist.h>
#include <sys/thread.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/elf.h>

#ifdef __sparc
#include <sys/stack.h>		/* for STACK_BIAS */
#else
#define	STACK_BIAS		0
#endif

kvm_t *cookie;

struct proc *tst_getproc(pid_t);
struct proc *tst_nextproc(void);
struct user *tst_getu(struct proc *);
int tst_setproc(void);
int tst_getcmd(struct proc *, struct user *);
void tst_segkp(void);
void tst_nlist(struct nlist nl[]);
void tst_open(char *, char *, char *, int);
void tst_close(void);
ssize_t tst_read(uintptr_t, void *, size_t);
ssize_t tst_write(uintptr_t, void *, size_t);
int tst_getcmd(struct proc *, struct user *);
void tst_segkvp(void);

char *name;
char *core;
char *swap;
int wflag;

struct nlist nl[] = {
	{"free"},
	{"fragtbl"},
	{"freemem"},
	{"allthreads"},
	{"nbuckets"},
	{"cputype"},
	{0}
};

int
main(int argc, char *argv[], char *envp[])
{
	int c, errflg = 0;
	long xx;
	struct nlist *nlp;
	struct proc *proc;
	struct user *u;
	int envc, ccnt;

	for (envc = 0; *envp++ != NULL; envc++)
		continue;
	envp -= 2;
	ccnt = (*envp - *argv) + strlen(*envp) + 1;
	printf("pid %d:: %d args; %d envs; %d chars (%p - %p)\n",
	    getpid(), argc, envc, ccnt,
	    &argv[0], *envp + strlen(*envp));

	while ((c = getopt(argc, argv, "w")) != EOF)
		switch (c) {
		case 'w':
			wflag++;
			break;
		case '?':
			errflg++;
		}
	if (errflg) {
		fprintf(stderr, "usage: %s [-w] [name] [core] [swap]\n",
		    argv[0]);
		return (2);
	}
	if (optind < argc) {
		name = argv[optind++];
		if (*name == '\0')
			name = NULL;
	} else
		name = NULL;
	if (optind < argc) {
		core = argv[optind++];
		if (*core == '\0')
			core = NULL;
	} else
		core = NULL;
	if (optind < argc) {
		swap = argv[optind++];
		if (*swap == '\0')
			swap = NULL;
	} else
		swap = NULL;

	tst_open(name, core, swap, (wflag ? O_RDWR : O_RDONLY));
	if (cookie == NULL)
		return (1);

	tst_nlist(nl);

	for (nlp = nl; nlp[0].n_type != 0; nlp++)
		tst_read(nlp[0].n_value, &xx, sizeof (xx));

	while ((proc = tst_nextproc()) != NULL) {
		struct pid pid;
		if (kvm_read(cookie, (uintptr_t)proc->p_pidp, &pid,
		    sizeof (pid)) != sizeof (pid)) {
			printf("ERROR: couldn't get pid\n");
			break;
		}
		tst_getproc(pid.pid_id);
	}

	tst_setproc();

	while ((proc = tst_nextproc()) != NULL) {
		if ((u = tst_getu(proc)) != NULL)
			(void) tst_getcmd(proc, u);
	}

	tst_segkp();
	tst_close();

	return (0);
}

void
tst_open(char *namelist, char *corefile, char *swapfile, int flag)
{
	printf("kvm_open(%s, %s, %s, %s)\n",
	    (namelist == NULL) ? "LIVE_KERNEL" : namelist,
	    (corefile == NULL) ? "LIVE_KERNEL" : corefile,
	    (swapfile == NULL) ?
		((corefile == NULL) ? "LIVE_KERNEL" : "(none)") : swapfile,
	    (flag == O_RDONLY) ? "O_RDONLY" : ((flag == O_RDWR) ?
	    "O_RDWR" : "???"));

	if ((cookie = kvm_open(namelist, corefile,
	    swapfile, flag, "libkvm test")) == NULL)
		printf("ERROR: kvm_open returned %p\n", cookie);
}

void
tst_close(void)
{
	int i;

	printf("kvm_close()\n");
	if ((i = kvm_close(cookie)) != 0)
		printf("ERROR: kvm_close returned %d\n", i);
}

void
tst_nlist(struct nlist nl[])
{
	int i;
	char *t, *s;

	printf("kvm_nlist([nl])\n");
	if ((i = kvm_nlist(cookie, nl)) != 0)
		printf("ERROR: kvm_nlist returned %d\n", i);
	for (i = 0; nl[i].n_name != 0 && nl[i].n_name[0] != '\0'; i++) {
		/*
		 * Debug:
		 * n_value gets filled in with st_value,
		 * n_type gets filled in w/ELF32_ST_TYPE(sym->st_info)
		 * n_scnum gets filled in w/st_shndx
		 */
		switch (nl[i].n_type) {
		case STT_NOTYPE:
			t = "NOTYPE";
			break;
		case STT_OBJECT:
			t = "OBJECT";
			break;
		case STT_FUNC:
			t = "FUNC";
			break;
		case STT_SECTION:
			t = "SECTION";
			break;
		case STT_FILE:
			t = "FILE";
			break;
		case STT_NUM:
			t = "NUM";
			break;
		default:
			t = "???";
		}

		switch ((unsigned)nl[i].n_scnum) {
			static char strbuf[40];

		case SHN_UNDEF:
			s = "UNDEF";
			break;
		case SHN_LORESERVE:
			s = "LORESERVE";
			break;
		case SHN_ABS:
			s = "ABS";
			break;
		case SHN_COMMON:
			s = "COMMON";
			break;
		case SHN_HIRESERVE:
			s = "HIRESERVE";
			break;
		default:
			(void) sprintf(strbuf, "unknown (%d)", nl[i].n_scnum);
			s = strbuf;
			break;
		}

		printf("%s: %lx (%s, %s)\n",
		    nl[i].n_name, nl[i].n_value, s, t);
	}
}

ssize_t
tst_read(uintptr_t addr, void *buf, size_t nbytes)
{
	ssize_t e;
	int i;
	char *b;

	printf("kvm_read(%lx, [buf], %lu)\n", addr, nbytes);
	if ((e = kvm_read(cookie, addr, buf, nbytes)) != nbytes)
		printf("ERROR: kvm_read returned %ld instead of %lu\n",
		    e, nbytes);
	for (b = buf, i = 0; i < nbytes; b++, i++)
		printf("%lx: %02x (%04o)\n", addr + i,
		    *b & 0xff, *b & 0xff);

	return (e);
}

ssize_t
tst_write(uintptr_t addr, void *buf, size_t nbytes)
{
	ssize_t e;
	ssize_t i;
	void *b;

	printf("kvm_write(%lx, [buf], %lu)\n", addr, nbytes);
	if ((e = kvm_write(cookie, addr, buf, nbytes)) != nbytes)
		printf("ERROR: kvm_write returned %ld instead of %lu\n",
		    e, nbytes);
	if ((b = malloc(nbytes)) == 0)
		printf("ERROR: malloc for readback failed\n");
	else {
		if ((i = kvm_read(cookie, addr, b, nbytes)) != nbytes)
			printf("ERROR: readback returned %ld\n", i);
		else if (memcmp(b, buf, nbytes))
			printf("ERROR: write check failed!\n");
		(void) free(b);
	}
	return (e);
}

struct proc *
tst_getproc(pid_t pid)
{
	struct proc *proc;
	struct pid pidbuf;

	printf("kvm_getproc(%d)\n", pid);
	if ((proc = kvm_getproc(cookie, pid)) == NULL) {
		printf("ERROR: kvm_getproc returned NULL\n");
		return (proc);
	}

	if (kvm_read(cookie, (uintptr_t)proc->p_pidp, &pidbuf,
	    sizeof (pidbuf)) != sizeof (pidbuf)) {
		printf("ERROR: couldn't get pid\n");
		return (proc);
	}

	printf("p_pid: %d\n", pidbuf.pid_id);
	return (proc);
}

struct proc *
tst_nextproc(void)
{
	struct proc *proc;
	struct pid pidbuf;

	printf("kvm_nextproc()\n");
	if ((proc = kvm_nextproc(cookie)) == NULL) {
		printf("kvm_nextproc returned NULL\n");
		return (proc);
	}

	/*
	 * p_pid is now a macro which turns into a ptr dereference;
	 * must do a kvm_read to get contents.
	 */
	if (kvm_read(cookie, (u_long)proc->p_pidp, (char *)&pidbuf,
	    sizeof (struct pid)) != sizeof (struct pid)) {
		printf("ERROR: couldn't get pid\n");
	}
	printf("p_pid: %d\n", pidbuf.pid_id);

	return (proc);
}

int
tst_setproc(void)
{
	int i;

	printf("kvm_setproc()\n");
	if ((i = kvm_setproc(cookie)) != 0)
		printf("ERROR: kvm_setproc returned %d\n", i);
	return (i);
}

struct user *
tst_getu(struct proc *proc)
{
	register int e;
	struct proc tp;
	struct user *u;
	struct pid pidbuf;

	if (kvm_read(cookie, (uintptr_t)proc->p_pidp, &pidbuf,
	    sizeof (pidbuf)) != sizeof (pidbuf))
		printf("ERROR: couldn't get pid\n");

	printf("kvm_getu(pid:%d)\n", pidbuf.pid_id);
	if ((u = kvm_getu(cookie, proc)) == NULL)
		printf("ERROR: kvm_getu returned NULL\n");
	return (u);
}

static void
safe_printf(const char *s)
{
	char buf[BUFSIZ], *p;

	(void) strncpy(buf, s, BUFSIZ - 1);
	buf[BUFSIZ - 1] = '\0';

	for (p = buf; *p != '\0'; p++) {
		if (!isprint(*p))
			*p = ' ';
	}

	(void) printf("\"%s\"\n", buf);
}

int
tst_getcmd(struct proc *proc, struct user *u)
{
	char **arg;
	char **env;
	int i;
	char **p;
	struct pid pidbuf;

	if (kvm_kread(cookie, (uintptr_t)proc->p_pidp, &pidbuf,
	    sizeof (pidbuf)) != sizeof (pidbuf)) {
		printf("ERROR: couldn't get pid\n");
		return (-1);
	}

	printf("kvm_getcmd(pid:%d, [u], arg, env)\n", pidbuf.pid_id);
	if ((i = kvm_getcmd(cookie, proc, u, &arg, &env)) != 0) {
		printf("kvm_getcmd returned %d\n", i);
		return (i);
	}

	printf("Args:  ");
	for (p = arg; *p != NULL; p++)
		safe_printf(*p);
	printf("Env:  ");
	for (p = env; *p != NULL; p++)
		safe_printf(*p);

	(void) free(arg);
	(void) free(env);

	return (0);
}

void
tst_segkp(void)
{
	kthread_t t;
	caddr_t tp, alltp;
	uintptr_t stk[16];
	int i;

	if (kvm_read(cookie, nl[3].n_value, &alltp, sizeof (alltp))
	    != sizeof (alltp)) {
		printf("ERROR: couldn't read allthread, addr 0x%lx\n",
		    nl[3].n_value);
		return;
	}
	printf("allthreads 0x%lx\n", nl[3].n_value);
	printf("next offset 0x%lx\n",
	    (uintptr_t)&(t.t_next) - (uintptr_t)&t);

	for (tp = alltp; tp; tp = (caddr_t)(t.t_next)) {
		if (kvm_read(cookie,
		    (uintptr_t)tp, &t, sizeof (t)) != sizeof (t)) {
			printf("ERROR: couldn't read thread, addr 0x%p\n", tp);
			return;
		}

		printf("thread 0x%p\n", tp);
		printf("\tstk 0x%p sp 0x%lx tid %d next 0x%p prev 0x%p\n",
		    tp, t.t_stk, t.t_pcb.val[1], t.t_tid, t.t_next, t.t_prev);

		if (kvm_read(cookie, t.t_pcb.val[1] + STACK_BIAS, stk,
		    sizeof (stk)) != sizeof (stk)) {
			printf("ERROR: couldn't read stack, taddr 0x%p\n", tp);
			continue;
		}
		for (i = 0; i < 16; i++) {
			printf("%-16lx ", stk[i]);
			if (((i + 1) % 4) == 0)
				printf("\n");
		}

		if ((caddr_t)(t.t_next) == alltp)
			break;
	}
}
