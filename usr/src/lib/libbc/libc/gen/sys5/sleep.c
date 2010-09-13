/*
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/time.h>
#include <signal.h>

#define	setvec(vec, a) \
	vec.sv_handler = a; vec.sv_mask = vec.sv_onstack = 0

static void	sleepx(void);

/*
 * sleep(n)
 *
 * return 0 if n seconds passed
 * return n - t if t seconds passed
 *
 * this code is gross and works just barely.  
 * it would be nice if someone rewrote it.
 */
unsigned
sleep(unsigned n)
{
	int omask;
	struct itimerval new, old, zero;
	struct itimerval *newp = &new;
	struct timeval left_over;
	int alrm_flg;
	struct sigvec vec, ovec;

	if (n == 0)
		return(0);
	timerclear(&newp->it_interval);
	timerclear(&newp->it_value);
	if (setitimer(ITIMER_REAL, newp, &old) < 0)
		return(n);
	newp->it_value.tv_sec = n;
	alrm_flg = 0;
	timerclear(&left_over);
	if (timerisset(&old.it_value)) {
		if (timercmp(&old.it_value, &newp->it_value, >)) {
			old.it_value.tv_sec -= newp->it_value.tv_sec;
			++alrm_flg;
		} else {
			left_over.tv_sec = newp->it_value.tv_sec
			    - old.it_value.tv_sec;
			if (old.it_value.tv_usec != 0) {
				left_over.tv_sec--;
				left_over.tv_usec = 1000000
				    - old.it_value.tv_usec;
			}
			newp->it_value = old.it_value;
			timerclear(&old.it_value);
			--alrm_flg;
		}
	}
	if (alrm_flg >= 0) {
		setvec(vec, sleepx);
		(void) sigvec(SIGALRM, &vec, &ovec);
	}
	omask = sigblock(sigmask(SIGALRM));
	(void) setitimer(ITIMER_REAL, newp, (struct itimerval *)0);
	sigpause(omask &~ sigmask(SIGALRM));
	timerclear(&zero.it_value);
	timerclear(&zero.it_interval);
	(void) setitimer(ITIMER_REAL, &zero, newp);
	if (alrm_flg >= 0)
		(void) sigvec(SIGALRM, &ovec, (struct sigvec *)0);
	(void) sigsetmask(omask);
	if (alrm_flg > 0 || (alrm_flg < 0 && timerisset(&newp->it_value))) {
		struct itimerval reset;
		 
		/*
		 * I use reset instead of what new points to because the
		 * code that calculates the return value depends on the
		 * old value of *newp.
		 */
		reset = *newp;
		newp = &reset;
		newp->it_value.tv_usec += old.it_value.tv_usec;
		newp->it_value.tv_sec += old.it_value.tv_sec;
		if (newp->it_value.tv_usec >= 1000000) {
			newp->it_value.tv_usec -= 1000000;
			newp->it_value.tv_sec++;
		}
		(void) setitimer(ITIMER_REAL, newp, (struct itimerval *)0);
		newp = &new;
	}
	left_over.tv_sec += newp->it_value.tv_sec;
	left_over.tv_usec += newp->it_value.tv_usec;
	if (left_over.tv_usec >= 1000000) {
		left_over.tv_sec++;
		left_over.tv_usec -= 1000000;
	}
	if (left_over.tv_usec >= 500000)
		left_over.tv_sec++;
	return(left_over.tv_sec);
}

static void
sleepx(void)
{
}
