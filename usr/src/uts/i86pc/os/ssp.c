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
 * Copyright 2015 Alex Wilson, the University of Queensland
 * Use is subject to license terms.
 */

/*
 * Support functions for stack smashing protection (-fstack-protector
 * and family)
 *
 * The principle behind SSP is to place a "canary" value on the stack
 * just below the arguments to a given function (which are in turn
 * below the previous %rbp and return pointer). We write it onto the
 * stack at the start of a function, and then at the end just before
 * we execute "leave" and "ret", we check that the value is still there.
 *
 * If the check fails, we jump immediately to a handler (which typically
 * just executes panic() straight away).
 *
 * Since an attacker will not know the value of the "canary", they will
 * not be able to repair it correctly when overwriting the stack (and in
 * almost all cases they must overwrite the canary to get to the return
 * pointer), and the check will fail (and safely panic) instead of
 * letting them gain control over %rip in a kernel thread.
 *
 * To debugging tools the canary just looks like another local variable
 * (since it's placed below the normal argument space), and so there
 * should be minimal/no impact on things that try to parse the
 * function preamble.
 *
 * Of course, adding these guards to every single function does not come
 * without a price in performance, so normally only a subset of functions
 * in a given program are guarded. Selecting which subset, and adding the
 * guards is all handled automatically by the compiler.
 *
 * There are 3 (or 4) major relevant compiler options in GCC:
 *     * -fstack-protector
 *     * -fstack-protector-strong (only in GCC >= 4.9)
 *     * -fstack-protector-all
 *     * -fno-stack-protector
 *
 * The only differences between -fstack-protector, -strong and -all is in
 * which functions are selected for adding guards.
 *
 * -fstack-protector adds guards to functions that make use of a stack-
 * allocated char array (or aggregate containing one) of at least 8 bytes
 * in length.
 *
 * -fstack-protector-strong adds guards everywhere -fstack-protector
 * does, and also adds guards to all functions that take or pass an address
 * to a stack-allocated array of any type (eg arr, &arr[1] etc), as well as
 * functions containing certain kinds of pointer arithmetic.
 *
 * -fstack-protector-all (as the name suggests) adds guards to every single
 * function.
 *
 * There is also another variant, in the ProPolice patches which are used
 * by some members of the BSD family (eg OpenBSD), which also guards any
 * functions that store function pointers on the stack, as well as a few
 * other heuristics (like re-ordering variables so arrays are as close as
 * possible to the canary)
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/note.h>

/*
 * The symbol __stack_chk_guard contains the magic guard value used
 * to check stack integrity before returning from selected functions.
 *
 * Its value is set at startup to a "random" number -- this does not have
 * to be cryptographically secure, but it does have to be done before
 * calling any C functions that the stack guards may have been generated
 * for.
 *
 * For this reason, the uts/i86pc/os directory is always built *without*
 * stack protection enabled so that we can bootstrap.
 */

uintptr_t __stack_chk_guard = 0;

/*
 * The function __stack_chk_fail is called whenever a guard check fails.
 */
void
__stack_chk_fail(void)
{
	/*
	 * Currently we just panic, but some more debug info could be useful.
	 * Note that we absolutely cannot trust any part of our stack at this
	 * point (we already know there's an attack in progress).
	 */
	panic("Stack smashing detected");
}

static void salsa_hash(unsigned int *);

#ifdef __sparc
extern uint64_t ultra_gettick(void);
#define	SSP_GET_TICK ultra_gettick
#else
extern hrtime_t tsc_read(void);
#define	SSP_GET_TICK tsc_read
#endif /* __sparc */

/* called from os/startup.c */
void
ssp_init(void)
{
	int i;

	if (__stack_chk_guard == 0) {
		union {
			unsigned int state[16];
			hrtime_t ts[8];
			uintptr_t g;
		} s;

		for (i = 0; i < 8; ++i)
			s.ts[i] = SSP_GET_TICK();

		salsa_hash(s.state);

		__stack_chk_guard = s.g;
	}
}

/*
 * Stealing the chacha/salsa hash function. It's simple, fast and
 * public domain. We don't need/want the full cipher (which would
 * belong in crypto) and we can't use the fully fledged PRNG
 * framework either, since ssp_init has to be called extremely
 * early in startup.
 *
 * Since we don't have to be cryptographically secure, just using
 * this to hash some high res timer values should be good enough.
 */
#define	QR(a, b, c, d)	do {  \
				a += b; d ^= a; d <<= 16;	\
				c += d; b ^= c; b <<= 12;	\
				a += b; d ^= a; d <<= 8;	\
				c += d; b ^= c; b <<= 7;	\
			_NOTE(CONSTANTCONDITION)		\
			} while (0)

static inline void
salsa_dr(unsigned int *state)
{
	QR(state[0], state[4], state[ 8], state[12]);
	QR(state[1], state[5], state[ 9], state[13]);
	QR(state[2], state[6], state[10], state[14]);
	QR(state[3], state[7], state[11], state[15]);
	QR(state[0], state[5], state[10], state[15]);
	QR(state[1], state[6], state[11], state[12]);
	QR(state[2], state[7], state[ 8], state[13]);
	QR(state[3], state[4], state[ 9], state[14]);
}

static void
salsa_hash(unsigned int *state)
{
	/* 10x applications of salsa doubleround */
	salsa_dr(state);
	salsa_dr(state);
	salsa_dr(state);
	salsa_dr(state);
	salsa_dr(state);
	salsa_dr(state);
	salsa_dr(state);
	salsa_dr(state);
	salsa_dr(state);
	salsa_dr(state);
}
