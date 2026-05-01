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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Verify that a process born via posix_spawn(3C) comes to life with a correctly
 * initialised FPU.
 *
 * Unlike a fork(2) child, a spawned process is created as a bare kernel thread
 * that never passes through forklwp()/fp_new_lwp(), so it inherits neither FPU
 * register state nor the FPU thread context operations from its parent. Both
 * are instead established from scratch by fp_exec() when the child execs its
 * target, which is the same path the kernel uses to bring up init. This test
 * confirms, from inside a spawned child, that:
 *
 *   o the initial x87 control word and MXCSR are the architectural defaults,
 *     proving fp_exec()/fpinit() ran for the spawned LWP;
 *   o the full vector register file survives context switches while sibling
 *     threads hammer the FPU, making it very likely that the context
 *     operations were installed and actually save and restore our state.
 *
 * A fork(2)+exec(2) child is run through the identical checks first as a
 * control. The test needs xsave + AVX (it reuses the xsave test support
 * library) and is gated on that hardware by xsu_hwtype in the runfile.
 */

#include <err.h>
#include <errno.h>
#include <ieeefp.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <thread.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/fp.h>
#include <sys/processor.h>
#include <sys/procset.h>
#include <sys/time.h>
#include <sys/wait.h>

#include "xsave_util.h"

extern char **environ;

/*
 * How long to spend repeatedly reloading and verifying the vector register
 * file while the sibling threads create FPU contention.
 */
#define	SPAWN_FPU_RUNTIME_MS	500

/*
 * Number of FPU-hammering sibling threads to share the bound CPU with the
 * thread under test. Pinning a handful to a single CPU gives reasonably
 * reliable contention.
 */
#define	SPAWN_FPU_NRUNNERS	4

static uint_t failures;

typedef struct {
	uint32_t	fra_hwsup;
	processorid_t	fra_cpu;
} fpu_runner_arg_t;

/*
 * Continually load the vector registers with a distinct pattern. Run by the
 * sibling threads purely to dirty the physical registers so that, on a kernel
 * that failed to install the spawned thread's FPU context operations, a context
 * switch would leak this state into the thread under test.
 */
static void *
fpu_runner(void *arg)
{
	const fpu_runner_arg_t *ra = arg;
	uint32_t seed = 0x80000000;
	xsu_fpu_t buf;

	if (ra->fra_cpu != -1)
		(void) processor_bind(P_LWPID, P_MYID, ra->fra_cpu, NULL);

	for (;;) {
		xsu_fill(&buf, ra->fra_hwsup, seed);
		xsu_setfpu(&buf, ra->fra_hwsup);
		seed += 0x1000;
	}

	/* NOTREACHED */
	return (NULL);
}

static processorid_t
bind_to_cpu(void)
{
	long maxcpu = sysconf(_SC_CPUID_MAX);

	for (processorid_t cpu = 0; cpu <= maxcpu; cpu++) {
		if (processor_bind(P_LWPID, P_MYID, cpu, NULL) == 0)
			return (cpu);
	}

	return (-1);
}

/*
 * Snapshot the calling thread's initial FPU control word and MXCSR.
 * getcontext() forces an FPU save, after which we read them from the saved
 * state. Keeping this in its own function means getcontext(), which the
 * compiler treats like setjmp(), does not force the caller's locals volatile.
 */
static void
read_initial_fpu(uint32_t *cwp, uint32_t *mxcsrp)
{
	ucontext_t uc;

	if (getcontext(&uc) != 0)
		err(EXIT_FAILURE, "getcontext failed");

	/*
	 * The x87 control word is a named field on amd64. On i386 the
	 * fpchip_state is the opaque legacy save area, so we overlay the ILP32
	 * struct _fpstate to read it, as xsave_util.c does.
	 */
#ifdef __amd64
	*cwp = uc.uc_mcontext.fpregs.fp_reg_set.fpchip_state.cw & 0xffff;
#else
	struct _fpstate fps;

	(void) memcpy(&fps, &uc.uc_mcontext.fpregs.fp_reg_set.fpchip_state,
	    sizeof (fps));
	*cwp = fps.cw & 0xffff;
#endif
	*mxcsrp = uc.uc_mcontext.fpregs.fp_reg_set.fpchip_state.mxcsr;
}

static int
fpu_child(void)
{
	static fpu_runner_arg_t ra;
	uint32_t hwsup, cw, mxcsr;
	uint32_t seed = 1;
	long ncpu;
	uint_t nrun;
	hrtime_t end;
	int ret = EXIT_SUCCESS;

	read_initial_fpu(&cw, &mxcsr);

	hwsup = xsu_hwsupport();

	if (cw != FPU_CW_INIT) {
		warnx("initial x87 control word is %#x, expected %#x", cw,
		    FPU_CW_INIT);
		ret = EXIT_FAILURE;
	}
	if (mxcsr != SSE_MXCSR_INIT) {
		warnx("initial MXCSR is %#x, expected %#x", mxcsr,
		    SSE_MXCSR_INIT);
		ret = EXIT_FAILURE;
	}

	/*
	 * Force the thread under test to share a CPU with FPU-hammering
	 * siblings.
	 */
	ra.fra_hwsup = hwsup;
	ra.fra_cpu = bind_to_cpu();
	if (ra.fra_cpu != -1) {
		nrun = SPAWN_FPU_NRUNNERS;
	} else {
		ncpu = sysconf(_SC_NPROCESSORS_ONLN);
		if (ncpu < 1)
			ncpu = 1;
		nrun = 2 * (uint_t)ncpu;
	}

	for (uint_t i = 0; i < nrun; i++) {
		thread_t tid;
		int e = thr_create(NULL, 0, fpu_runner, &ra, THR_DETACHED,
		    &tid);
		if (e != 0)
			errc(EXIT_FAILURE, e, "failed to create FPU runner");
	}

	/*
	 * Load a known pattern and read it straight back. There is no
	 * FPU-clobbering call between the two so the pattern should
	 * survive even if we are preempted in the window.
	 */
	end = gethrtime() + (hrtime_t)SPAWN_FPU_RUNTIME_MS *
	    (NANOSEC / MILLISEC);
	do {
		xsu_fpu_t set, got;

		xsu_fill(&set, hwsup, seed);
		xsu_setfpu(&set, hwsup);

		/*
		 * Widen the window in which our vector state has to survive a
		 * context switch. This spin only touches integer registers, so
		 * it cannot disturb the FPU state we just loaded.
		 */
		for (volatile uint_t d = 0; d < 10000; d++)
			continue;

		xsu_getfpu(&got, hwsup);
		if (!xsu_same(&set, &got, hwsup)) {
			warnx("vector register state was not preserved across "
			    "a context switch (seed %#x)", seed);
			ret = EXIT_FAILURE;
			break;
		}
		seed += 0x40;
	} while (gethrtime() < end);

	return (ret);
}

static void
run_child(const char *desc, bool use_spawn, const char *path)
{
	char *argv[] = { (char *)path, "child", NULL };
	pid_t pid;
	int status;

	if (use_spawn) {
		int e = posix_spawn(&pid, path, NULL, NULL, argv, environ);
		if (e != 0)
			errc(EXIT_FAILURE, e, "posix_spawn of %s failed", path);
	} else {
		pid = fork();
		if (pid == -1)
			err(EXIT_FAILURE, "fork failed");
		if (pid == 0) {
			(void) execv(path, argv);
			err(127, "execv of %s failed", path);
		}
	}

	while (waitpid(pid, &status, 0) != pid) {
		if (errno != EINTR)
			err(EXIT_FAILURE, "waitpid failed");
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
		(void) fprintf(stderr, "TEST FAILED: %s: child status %#x\n",
		    desc, status);
		failures++;
		return;
	}

	(void) printf("TEST PASSED: %s\n", desc);
}

int
main(int argc, char *argv[])
{
	const char *path;

	if (argc > 1 && strcmp(argv[1], "child") == 0)
		return (fpu_child());

	path = getexecname();
	if (path == NULL)
		errx(EXIT_FAILURE, "could not determine own path");

	run_child("fork+exec child FPU initialisation", false, path);
	run_child("posix_spawn child FPU initialisation", true, path);

	if (failures != 0) {
		(void) fprintf(stderr, "%u test(s) failed\n", failures);
		return (EXIT_FAILURE);
	}

	(void) printf("All tests passed\n");
	return (EXIT_SUCCESS);
}
