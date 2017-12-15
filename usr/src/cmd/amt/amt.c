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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Abstract Machine Test; executes memory access tests to show
 * compliance with Common Criteria object reuse and process address
 * space separation requirements.
 */
#include <errno.h>
#include <fcntl.h>
#include <iso/stdlib_iso.h>
#include <libelf.h>
#include <libintl.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>

#define	NOT_SILENT 0
#define	SILENT_MODE 1

#define	CHILD_SLEEP_PERIOD 2
#define	PARENT_SLEEP_PERIOD 1
#define	SIG_EVENT SIGUSR1

#define	PASS	   0		/* test passed, no SEGV */
#define	FAIL_ZERO  1		/* expected to read zero, didn't */
#define	FAIL_SEGV  2		/* expected good read or write, didn't */
#define	PASS_SEGV  3		/* expected SEGV, got it */
#define	FAIL_ABORT 4		/* test logic error */

#define	PH_VALID   0		/* arg for probe_hole -- do valid memory */
				/* access */
#define	PH_INVALID 1		/* do illegal memory access */

#define	WASTE_PAGES   8		/* a guess at where virgin stack space */
				/* is likely to exist */
#define	STACK_SLOP  256		/* a guess at how far below current end */
				/* of stack I'll find unused space */

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

extern int _end;	/* first address after the end of initialized data */

static int  data_boundary_test();
static void handler(int);
static int  memory_not_shared_after_use();
static int  memory_allocation_not_shared();
static int  memory_type(const char *);
static void print_message(char *);
static void probe_data_area(void);
static void probe_hole(int);
static void probe_stack(void);
static void probe_text_area(void);
static void segv_action(int, siginfo_t *, void *);
static void set_handler(int);
static int  test_stack_end_of_hole();
static int  text_area_not_writeable();

static int done_memory_grab = 0;
static int silent;
static int handler_exit_code;

/*
 * Main Routine
 */
int
main(int argc, char *argv[])
{
	int fail_count = 0;
	int status = 0;
	int bitsize;

	/* Internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	silent = NOT_SILENT;

	if (argc == 2) {
		/* Pull out argument provided		 */
		/* -s	silent mode, no status or error messages. */
		if (strncmp(argv[1], "-s", 4) == 0)
			silent = SILENT_MODE;
		else {
			/* Wrong argument */
			(void) fprintf(stderr, gettext(
			    "Wrong argument, USAGE: amt [-s]\n"));
			exit(EXIT_FAILURE);
		}
	} else if (argc != 1) {
		/* Illegal number of arguments. */
		(void) fprintf(stderr, gettext(
		    "Wrong usage, USAGE: amt [-s]\n"));
		exit(EXIT_FAILURE);
	}
	bitsize = memory_type(argv[0]);

	if (silent == NOT_SILENT)
		(void) printf(gettext(
		    "\n\nAMT Test Program -- %d bit application\n"
		    "================\n"), bitsize);
	/*
	 * test_stack_end_of_hole must be the first test, or the stack
	 * is of an unknown size.
	 */
	if ((status = test_stack_end_of_hole()) == EXIT_FAILURE) {
		/* Normal fail */
		fail_count++;
		print_message(gettext("TEST 1 FAILED\n"));
	} else if (status == FAIL_ABORT) {
		/* Test logic failure */
		fail_count++;
		print_message(gettext("FAIL: Logic error in test\n"));
	} else if (status == EXIT_SUCCESS)
		print_message(gettext("TEST 1 PASSED\n"));

	/* Carry out test 2 */
	if (data_boundary_test() != EXIT_SUCCESS) {
		fail_count++;
		print_message(gettext("TEST 2 FAILED\n"));
	} else
		print_message(gettext("TEST 2 PASSED\n"));

	/* Carry out test 3 */
	if (text_area_not_writeable() != EXIT_SUCCESS) {
		fail_count++;
		print_message(gettext("TEST 3 FAILED\n"));
	} else
		print_message(gettext("TEST 3 PASSED\n"));

	/* Carry out test 4 */
	if (memory_not_shared_after_use() != EXIT_SUCCESS) {
		fail_count++;
		print_message(gettext("TEST 4 FAILED\n"));
	} else
		print_message(gettext("TEST 4 PASSED\n"));

	/* Carry out test 5 */
	if (memory_allocation_not_shared() != EXIT_SUCCESS) {
		fail_count++;
		print_message(gettext("TEST 5 FAILED\n"));
	} else
		print_message(gettext("TEST 5 PASSED\n"));

	if (silent == NOT_SILENT) {
		if (fail_count > 0)
			(void) printf(gettext("\n %d TESTS FAILED\n\n"),
			    fail_count);
		else
			(void) printf(gettext("\nTESTS SUCCEEDED\n\n"));
	}
	return (fail_count);
}

/*
 * Test the data boundaries. First test inside the data area at the boundary
 * of the "hole" area. Second test inside the data area at the text area
 * boundary. Both should pass.
 */
static int
data_boundary_test()
{
	int exit_status = EXIT_SUCCESS;
	pid_t pid;
	int status;

	print_message(gettext("\n\nTest 2- Data Side Boundary Test.\n"));

	if ((pid = fork()) == -1) {
		print_message(gettext("Fork failed\n"));
		return (EXIT_FAILURE);
	} else if (pid == 0) { /* Am I my child? */
		set_handler(SIGSEGV);

		/* probe_data_area() does exit() */
		probe_data_area();
	}
	/* still parent */
	(void) wait(&status);
	status = WEXITSTATUS(status);

	if (status == PASS)
		print_message(gettext(
		    "PASS: Successful read/write in data area.\n"));
	else if (status == FAIL_SEGV) {
		print_message(gettext(
		    "FAIL: Caught a segmentation fault while "
		    "attempting to write to the data area.\n"));
		exit_status = EXIT_FAILURE;
	} else {
		(void) printf(gettext("Test program failure: %d\n"),
		    status);
		exit_status = EXIT_FAILURE;
	}
	return (exit_status);
}

static void
probe_data_area()
{
	int *p;
	/* LINTED */
	volatile int p1 __unused;
	void *address;

	/* set handler status */
	handler_exit_code = FAIL_SEGV;

	/*
	 * Get an address in the data area, near to the "hole".
	 * sbrk returns prior address value; rather than calculating
	 * the sbrk result, sbrk is called twice, so address points
	 * to the new end of data
	 */
	(void) sbrk(PAGESIZE);
	address = sbrk(0);
	/*
	 * Get to the inside edge of a page boundary
	 * two integer words short of a new page
	 */
	p = ((int *)P2ROUNDUP((uintptr_t)address, PAGESIZE)) - 2;

	/* Try writing to it, shouldn't cause a segmentation fault. */
	*p = 9999;

	/* Should be able to read back with no problems. */
	p1 = *p;

	/*
	 * Get an address near the text area boundary, but in the data
	 * area.  _etext rounded up a page isn't correct since the
	 * initialized data area isn't writeable.
	 *
	 * Future versions should consider handling initialized data
	 * separately -- writing to initialized data should generate
	 * a fault.
	 */
	p = &_end;

	/* Try writing to it, should succeed. */
	*p = 9898;

	/* Should be able to read back with no problems. */
	p1 = *p;

	exit(EXIT_SUCCESS);
}

/*
 * Test that we cannot write to the text area. An attempt to write to
 * the text area will result in a segmentation fault. So if we catch it,
 * test has succeed, else it has failed.
 */
static int
text_area_not_writeable()
{
	int exit_status = EXIT_SUCCESS;
	pid_t pid;
	int status;

	print_message(gettext(
	    "\n\nTest 3- Text Area Not Writeable\n"
	    "Verify that a write to the text space does not cause "
	    "a write to the executable\n"
	    "file from which it came, or to another process which "
	    "shares that text.\n"));

	if ((pid = fork()) == -1) {
		print_message(gettext("Fork failed\n"));
		return (EXIT_FAILURE);
	} else if (pid == 0) { /* Am I my child? */
		set_handler(SIGSEGV);

		/* probe_text_area() does exit() */
		probe_text_area();
	}
	/* still parent */
	(void) wait(&status);
	status = WEXITSTATUS(status);

	if (status == PASS) {
		print_message(gettext(
		    "FAIL: We did not cause a segmentation fault.\n"));
		exit_status = EXIT_FAILURE;
	} else if (status == FAIL_SEGV) {
		print_message(gettext(
		    "PASS: Caught the segmentation fault, "
		    "meaning we can't write to text area.\n"));
	} else {
		(void) printf(gettext(
		    "Test program failure: %d\n"), status);
		exit_status = EXIT_FAILURE;
	}
	return (exit_status);
}

/*
 * write to text area, trigger a SEGV
 */
static void
probe_text_area()
{
	handler_exit_code = FAIL_SEGV;
	*(caddr_t)probe_text_area = 0xff;
	exit(EXIT_FAILURE);
}

/*
 * Test that when we set some values and fork a process, when the child
 * writes to these inherited values, the parents copies are not changed.
 */
static int
memory_not_shared_after_use()
{
	pid_t pid;
	int x = 1000;
	int exit_status = EXIT_SUCCESS;

	print_message(gettext("\n\nTest 4- Memory Not Shared After Write\n"
	    "Verify that anonymous memory initially shared by two "
	    "processes (e.g. after a\n"
	    "fork) is not shared after either process writes "
	    "to it.\n"));

	if ((pid = fork()) == -1) {
		print_message(gettext("Fork failed\n"));
		return (EXIT_FAILURE);
	} else if (pid == 0) { /* I am the child. */
		/*
		 * Change child value; this should not change
		 * parent value.
		 */
		x = 2000;

		/* Wait for parent to test value */
		(void) sleep(CHILD_SLEEP_PERIOD);

		exit(EXIT_SUCCESS);
	}
	/* Wait for child to do its stuff. */
	(void) sleep(PARENT_SLEEP_PERIOD);

	if (x == 1000)
		exit_status = EXIT_SUCCESS;
	else
		exit_status = EXIT_FAILURE;

	return (exit_status);
}

/*
 * If we fork a process and then allocate some memory in that process,
 * we should not see any memory changes in the parent.
 */
static int
memory_allocation_not_shared()
{
	pid_t pid;
	pid_t parent_pid;
	int exit_status = 0;
	caddr_t address;
	caddr_t hole_start;
	caddr_t hole_after;
	void (*old_handler) ();

	print_message(gettext(
	    "\n\nTest 5- Memory Allocation is Not Shared\n"
	    "Verify that newly allocated memory in one of two "
	    "processes created by forking\n"
	    "does not result in newly allocated memory in the other.\n"));

	/* Save Size of data area and 1st block address of "hole" */
	hole_start = (caddr_t)sbrk(0);

	if (silent == NOT_SILENT)
		(void) printf(gettext(
		    "Parent address of hole before child change: %08X\n"),
		    hole_start);

	/* Set handler for signal SIG_EVENT (define at start) */
	old_handler = signal(SIG_EVENT, &handler);
	if (old_handler == SIG_ERR) {
		print_message(gettext(
		    "Can't establish signal handler, test failed\n"));
		return (EXIT_FAILURE);
	}

	if ((pid = fork()) == -1) {
		print_message(gettext("Fork failed\n"));
		return (EXIT_FAILURE);
	} else if (pid == 0) { /* We are the child. */
		address = sbrk(0);
		if (silent == NOT_SILENT)
			(void) printf(gettext(
			    "Child end of hole before change:  %08X\n"),
			    address);

		if (brk((address+PAGESIZE)) != 0) {
			print_message(gettext(
			    "Can't change start of hole address.\n"));
			exit(EXIT_FAILURE);
		}

		address = sbrk(0);
		if (silent == NOT_SILENT)
			(void) printf(gettext(
			    "Child end of hole after change: %08X\n"),
			    address);

		/* Tell the parent we're done. */
		parent_pid = getppid();
		if (sigsend(P_PID, parent_pid, SIG_EVENT) != 0) {
			print_message(gettext("Can't send signal to parent, "
			    "test failed\n"));
			exit(EXIT_FAILURE);
		}

		/* Sleep before exiting to allow parent to finish processing. */
		(void) sleep(CHILD_SLEEP_PERIOD);
		exit(EXIT_SUCCESS);
	}
	/* Wait for child to do its work. */
	(void) sleep(PARENT_SLEEP_PERIOD);

	if (done_memory_grab != 1) {
		print_message(gettext(
		    "Child failed to do memory alterations, "
		    "exiting\n"));
		return (EXIT_FAILURE);
	}

	hole_after = sbrk(0);
	if (silent == NOT_SILENT)
		(void) printf(gettext(
		    "Parent address of hole after child change: "
		    "%08X\n"), hole_after);

	/* Test size of hole and data region. */
	if (hole_start == hole_after)
		print_message(gettext(
		    "PASS: Hole is same size in parent.\n"));
	else {
		print_message(gettext(
		    "FAIL: Hole is a different size.\n"));
		exit_status = EXIT_FAILURE;
	}

	/* Wait for child to finish. */
	(void) wait(0);

	if (signal(SIG_EVENT, old_handler) == SIG_ERR) {
		print_message(gettext("Couldn't put back old signal handler, "
		    "test failed.\n"));
		return (EXIT_FAILURE);
	}
	return (exit_status);
}

static void
print_message(char *message)
{
	if (silent == NOT_SILENT)
		(void) printf("%s", message);
}

static int
test_stack_end_of_hole()
{
	pid_t pid;
	int status;
	int exit_status = EXIT_SUCCESS;

	print_message(gettext("\n\nTest 1- stack Side Boundary Test\n"));

	/* sub test 1:  the space the stack grows into is zero */

	if ((pid = fork()) == -1) {
		print_message(gettext("Fork failed\n"));
		return (EXIT_FAILURE);
	} else if (pid == 0) { /* Am I my child? */
		set_handler(SIGSEGV);

		/* probe_stack() does exit */
		probe_stack();
	}
	/* still parent */
	(void) wait(&status);
	status = WEXITSTATUS(status);

	if (status == FAIL_ZERO) {
		print_message(gettext("Fail with non-zero read.\n"));
		exit_status = EXIT_FAILURE;
	} else if (status != PASS) {
		print_message(gettext("Test program failure\n"));
		exit_status = EXIT_FAILURE;
	}
	/* sub test 2:  the space in hole is not readable */

	if ((pid = fork()) == -1) {
		print_message(gettext("Fork failed\n"));
		return (EXIT_FAILURE);
	} else if (pid == 0) { /* Am I my child? */
		set_handler(SIGSEGV);

		/* probe_hole does exit */
		probe_hole(PH_INVALID);
	}
	/* still parent */
	(void) wait(&status);
	status = WEXITSTATUS(status);

	if (status == FAIL_SEGV) {
		print_message(
		    gettext("Fail (SEGV expected, not received).\n"));
		exit_status = EXIT_FAILURE;
	} else if (status != PASS_SEGV) {
		print_message(gettext("Test program failure.\n"));
		exit_status = EXIT_FAILURE;
	}

	/* sub test 3:  the space in new page below hole is zero */

	if ((pid = fork()) == -1) {
		print_message(gettext("Fork failed\n"));
		return (EXIT_FAILURE);
	} else if (pid == 0) { /* Am I my child? */
		set_handler(SIGSEGV);

		/* probe_hole does exit */
		probe_hole(PH_VALID);
	}
	/* still parent */
	(void) wait(&status);
	status = WEXITSTATUS(status);

	if (status == FAIL_SEGV) {
		print_message(gettext("Fail (got SEGV).\n"));
		exit_status = EXIT_FAILURE;
	} else if (status != PASS) {
		print_message(gettext("Test program failure.\n"));
		exit_status = EXIT_FAILURE;
	}
	return (exit_status);
}


/*
 * set_handler
 */
static void
set_handler(int sig)
{
	struct sigaction act;

	act.sa_handler = NULL;
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = segv_action;
	(void) sigemptyset(&(act.sa_mask));

	if (sigaction(sig, &act, NULL) < 0) {
		if (silent == NOT_SILENT) {
			(void) fprintf(stderr, gettext(
			    "sigaction() returned error: %s\n"),
			    strerror(errno));
		}
		exit(EXIT_FAILURE);
	}
}


/*ARGSUSED*/
static void
segv_action(int which_sig, siginfo_t *t1, void *t2)
{
	exit(handler_exit_code);
}

/*
 * probe_stack
 *
 * Warning -- if you do a printf or fprintf prior to the actual
 * reading from the stack, you've changed the stack to an unknown
 * state.  (stack memory isn't free'd automatically and this function
 * needs to touch virgin stack space.)
 */
static void
probe_stack(void)
{
	unsigned char *end;	/* end of stack */
	unsigned char probe;
	long i;
	int j;
	unsigned char last_fail, *last_fail_address;
	unsigned char mark = 0xAA;	/* roughly the end of stack */
	handler_exit_code = FAIL_SEGV;

	end = &mark;
	/* stack growth is negative */
	end -= (WASTE_PAGES * PAGESIZE) + STACK_SLOP;

	for (i = 0, j = 0; i < PAGESIZE; i++) {
		if ((probe = *end) != 0) {
			j++;
			last_fail = probe;
			last_fail_address = end;
		}
		end--;
	}

	if (j != 0) {
		if (silent == NOT_SILENT)
			(void) fprintf(stderr, gettext(
			    "probe_stack failed. address=0x%08X; "
			    "probe=0x%02X; content = %d\n"),
			    (caddr_t)last_fail_address, last_fail, j);

		exit(FAIL_ZERO);    /* test failed at least once */
	}
	exit(EXIT_SUCCESS);
}

static void
probe_hole(int test_type)
{
	long i;
	/* LINTED */
	volatile unsigned char probe __unused;
	unsigned char *probe_adr;
	void *address;

	address = sbrk(0);  /* current end data + 1 */

	if (address == (void *)-1) {
		print_message(gettext("Test program logic error\n"));
		exit(FAIL_ABORT);
	}
	if (test_type == PH_VALID) {
		/* show that access works inside the  hole */
		handler_exit_code = FAIL_SEGV;

		probe_adr =  (unsigned char *)address - sizeof (char);

		for (i = 0; i < PAGESIZE; i++)
			probe = *probe_adr--;

		exit(EXIT_SUCCESS);
	} else {
		/* show that a trap occurs in the  hole */
		handler_exit_code = PASS_SEGV;

		address = (void *)P2ROUNDUP((uintptr_t)address, PAGESIZE);
		probe_adr = (unsigned char *)address;

		probe = *probe_adr;
		exit(FAIL_SEGV);	/* expected SEGV, didn't get it */
	}
}

/*
 * Catch signal, child to parent
 */
/*ARGSUSED*/
void
handler(int signal)
{
	done_memory_grab = 1;
}
/*
 * memory_type:  Determine whether a given executable file is compiled
 * as 32 or 64 bit.
 *
 * The following code was stolen from isainfo (1)
 */

static int
memory_type(const char *path)
{
	char *idarray;
	Elf *elf;
	int d;
	int bits = 0;

	if ((d = open(path, O_RDONLY)) < 0) {
		(void) fprintf(stderr,
		    "cannot open: %s -- %s\n",
		    path, strerror(errno));
		return (bits);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr,
		    "internal error: ELF library out of date?\n");
		(void) close(d);
		return (bits);
	}

	elf = elf_begin(d, ELF_C_READ, (Elf *)0);
	if (elf_kind(elf) != ELF_K_ELF) {
		(void) elf_end(elf);
		(void) close(d);
		return (bits);
	}

	idarray = elf_getident(elf, 0);

	if (idarray[EI_CLASS] == ELFCLASS32) {
		bits = 32;
	} else if (idarray[EI_CLASS] == ELFCLASS64) {
		bits = 64;
	}

	(void) elf_end(elf);
	(void) close(d);
	return (bits);
}
