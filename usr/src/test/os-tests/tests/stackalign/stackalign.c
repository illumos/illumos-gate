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
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Test that the stack is aligned to expected values.
 */

#include <stdio.h>
#include <pthread.h>
#include <thread.h>
#include <door.h>
#include <stdlib.h>
#include <unistd.h>
#include <ucontext.h>

#include <sys/stack.h>

/*
 * The introduction of SSE led to the IA32 ABI changing the required stack
 * alignment from 4 bytes to 16 bytes. Compilers assume this when using SSE.
 */
#if defined(__i386)
#undef STACK_ALIGN
#define	STACK_ALIGN 16
#endif

#define	ALIGN_ERR_IMPL(align, text)				\
	"stack was not aligned to " #align " on " text "\n"
#define	ALIGN_ERR_HELP(align, text) ALIGN_ERR_IMPL(align, text)
#define	ALIGN_ERR(text) ALIGN_ERR_HELP(STACK_ALIGN, text)

#define	STACK_SIZE 16*1024

typedef struct test_ctx {
	void (*func)(uintptr_t, char *);
	char *text;
} test_ctx_t;

extern void get_stack_at_entry(test_ctx_t *);

void
teststack(uintptr_t stack, char *arg)
{
	if ((stack & (STACK_ALIGN - 1)) != 0) {
		fprintf(stderr, ALIGN_ERR("%s"), (char *)arg);
		exit(1);
	}
}

void
initmain(uintptr_t stack)
{
	teststack(stack, "section .init");
}

void
initarray(uintptr_t stack)
{
	teststack(stack, "section .init_array");
}

void
doorstack(uintptr_t stack, char *arg)
{
	teststack(stack, arg);
	(void) door_return(NULL, 0, NULL, 0);
}

char door_arg[] = "DOOR ARG";

int
main(int argc, char *argv[])
{
	door_arg_t da = {
	    .data_ptr = (void *)door_arg,
	    .data_size = sizeof (door_arg)
	};
	test_ctx_t arg = {
	    .func = teststack,
	    .text = "pthread_create()"
	};
	ucontext_t back, uc;
	pthread_t tid;
	int door_fd, rc;

#if defined(__sparc)
	/*
	 * This hasn't been implemented for SPARC, so skip.
	 */
	fprintf(stderr, "No SPARC implementation of get_stack_at_entry\n");
	return (3);
#else
	if (pthread_create(&tid, NULL,
	    (void *(*)(void *))get_stack_at_entry, &arg) != 0) {
		perror("pthread_create() failed:");
		exit(-2);
	}
	(void) pthread_join(tid, NULL);

	arg.text = "thr_create()";

	if (thr_create(NULL, 0, (void *(*)(void *))get_stack_at_entry,
	    &arg, 0, &tid) != 0) {
		perror("thr_create() failed:");
		exit(-3);
	}
	(void) thr_join(tid, NULL, NULL);

	if (getcontext(&uc) < 0) {
		perror("getcontext() failed");
		exit(-4);
	}

	uc.uc_link = &back;
	uc.uc_stack.ss_size = STACK_SIZE;
	uc.uc_stack.ss_flags = 0;
	if ((uc.uc_stack.ss_sp = malloc(STACK_SIZE)) == NULL) {
		perror("failed to allocate stack");
		exit(-5);
	}

	arg.text = "swapcontext()";
	makecontext(&uc, (void (*)(void *))get_stack_at_entry, 1, &arg);
	if (swapcontext(&back, &uc) < 0) {
		perror("swapcontext() failed");
		exit(-6);
	}

	arg.func = doorstack;
	arg.text = "door_call()";

	if ((door_fd = door_create(
	    (door_server_procedure_t *)get_stack_at_entry,
	    &arg, 0)) < 0) {
		perror("failed to create door");
		exit(-7);
	}

	rc = door_call(door_fd, &da);

	if (rc < 0) {
		perror("door call #1 failed");
		exit(-8);
	}

	da.data_size += 5;
	rc = door_call(door_fd, &da);

	if (rc < 0) {
		perror("door call #2 failed");
		exit(-9);
	}

	(void) close(door_fd);

	return (0);
#endif
}
