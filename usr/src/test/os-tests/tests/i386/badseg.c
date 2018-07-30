/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

#include <stdlib.h>
#include <ucontext.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/regset.h>

/*
 * Load a bunch of bad selectors into the seg regs: this will typically cause
 * the child process to core dump, but it shouldn't panic the kernel...
 *
 * It's especially interesting to run this on CPU0.
 */

unsigned short selector;

static void badds(void)
{
	__asm__ volatile("movw %0, %%ds" : : "r" (selector));
}

static void bades(void)
{
	__asm__ volatile("movw %0, %%es" : : "r" (selector));
}

static void badfs(void)
{
	__asm__ volatile("movw %0, %%fs" : : "r" (selector));
}

static void badgs(void)
{
	__asm__ volatile("movw %0, %%gs" : : "r" (selector));
}

static void badss(void)
{
	__asm__ volatile("movw %0, %%ss" : : "r" (selector));
}

static void
resetseg(uint_t seg)
{
	ucontext_t ucp;
	int done = 0;

	int rc = getcontext(&ucp);
	if (done) {
		rc = getcontext(&ucp);
		return;
	}

	done = 1;
	ucp.uc_mcontext.gregs[seg] = selector;
	setcontext(&ucp);
	abort();
}

static void
resetcs(void)
{
	return (resetseg(CS));
}

static void
resetds(void)
{
	return (resetseg(DS));
}

static void
resetes(void)
{
	return (resetseg(ES));
}

static void
resetfs(void)
{
	return (resetseg(FS));
}

static void
resetgs(void)
{
	return (resetseg(GS));
}

static void
resetss(void)
{
	return (resetseg(SS));
}

static void
inchild(void (*func)())
{
	pid_t pid;

	switch ((pid = fork())) {
	case 0:
		func();
		exit(0);
	case -1:
		exit(1);
	default:
		(void) waitpid(pid, NULL, 0);
		return;
	}

}

int
main(int argc, char *argv[])
{
	for (selector = 0; selector < 8194; selector++) {
		inchild(resetcs);
		inchild(resetds);
		inchild(resetes);
		inchild(resetfs);
		inchild(resetgs);
		inchild(resetss);
		inchild(badds);
		inchild(bades);
		inchild(badfs);
		inchild(badgs);
		inchild(badss);
	}

	exit(0);
}
