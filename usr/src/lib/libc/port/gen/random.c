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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <limits.h>

/*
 * random.c:
 * An improved random number generation package.  In addition to the standard
 * rand()/srand() like interface, this package also has a special state info
 * interface.  The initstate() routine is called with a seed, an array of
 * bytes, and a count of how many bytes are being passed in; this array is then
 * initialized to contain information for random number generation with that
 * much state information.  Good sizes for the amount of state information are
 * 32, 64, 128, and 256 bytes.  The state can be switched by calling the
 * setstate() routine with the same array as was initiallized with initstate().
 * By default, the package runs with 128 bytes of state information and
 * generates far better random numbers than a linear congruential generator.
 * If the amount of state information is less than 32 bytes, a simple linear
 * congruential R.N.G. is used.
 * Internally, the state information is treated as an array of ints; the
 * zeroeth element of the array is the type of R.N.G. being used (small
 * integer); the remainder of the array is the state information for the
 * R.N.G.  Thus, 32 bytes of state information will give 7 ints worth of
 * state information, which will allow a degree seven polynomial.  (Note: the
 * zeroeth word of state information also has some other information stored
 * in it -- see setstate() for details).
 * The random number generation technique is a linear feedback shift register
 * approach, employing trinomials (since there are fewer terms to sum up that
 * way).  In this approach, the least significant bit of all the numbers in
 * the state table will act as a linear feedback shift register, and will have
 * period 2^deg - 1 (where deg is the degree of the polynomial being used,
 * assuming that the polynomial is irreducible and primitive).  The higher
 * order bits will have longer periods, since their values are also influenced
 * by pseudo-random carries out of the lower bits.  The total period of the
 * generator is approximately deg*(2**deg - 1); thus doubling the amount of
 * state information has a vast influence on the period of the generator.
 * Note: the deg*(2**deg - 1) is an approximation only good for large deg,
 * when the period of the shift register is the dominant factor.  With deg
 * equal to seven, the period is actually much longer than the 7*(2**7 - 1)
 * predicted by this formula.
 */



/*
 * For each of the currently supported random number generators, we have a
 * break value on the amount of state information (you need at least this
 * many bytes of state info to support this random number generator), a degree
 * for the polynomial (actually a trinomial) that the R.N.G. is based on, and
 * the separation between the two lower order coefficients of the trinomial.
 */

#define		TYPE_0		0		/* linear congruential */
#define		BREAK_0		8
#define		DEG_0		0
#define		SEP_0		0

#define		TYPE_1		1		/* x**7 + x**3 + 1 */
#define		BREAK_1		32
#define		DEG_1		7
#define		SEP_1		3

#define		TYPE_2		2		/* x**15 + x + 1 */
#define		BREAK_2		64
#define		DEG_2		15
#define		SEP_2		1

#define		TYPE_3		3		/* x**31 + x**3 + 1 */
#define		BREAK_3		128
#define		DEG_3		31
#define		SEP_3		3

#define		TYPE_4		4		/* x**63 + x + 1 */
#define		BREAK_4		256
#define		DEG_4		63
#define		SEP_4		1


/*
 * Array versions of the above information to make code run faster -- relies
 * on fact that TYPE_i == i.
 */

#define		MAX_TYPES	5		/* max number of types above */

static struct _randomjunk {
	unsigned int	degrees[MAX_TYPES];
	unsigned int	seps[MAX_TYPES];
	unsigned int	randtbl[ DEG_3 + 1 ];
/*
 * fptr and rptr are two pointers into the state info, a front and a rear
 * pointer.  These two pointers are always rand_sep places aparts, as they cycle
 * cyclically through the state information.  (Yes, this does mean we could get
 * away with just one pointer, but the code for random() is more efficient this
 * way).  The pointers are left positioned as they would be from the call
 *			initstate( 1, randtbl, 128 )
 * (The position of the rear pointer, rptr, is really 0 (as explained above
 * in the initialization of randtbl) because the state table pointer is set
 * to point to randtbl[1] (as explained below).
 */
	unsigned int	*fptr, *rptr;
/*
 * The following things are the pointer to the state information table,
 * the type of the current generator, the degree of the current polynomial
 * being used, and the separation between the two pointers.
 * Note that for efficiency of random(), we remember the first location of
 * the state information, not the zeroeth.  Hence it is valid to access
 * state[-1], which is used to store the type of the R.N.G.
 * Also, we remember the last location, since this is more efficient than
 * indexing every time to find the address of the last element to see if
 * the front and rear pointers have wrapped.
 */
	unsigned int	*state;
	unsigned int	rand_type, rand_deg, rand_sep;
	unsigned int	*end_ptr;
} *__randomjunk, *_randomjunk(void), _randominit = {
	/*
	 * Initially, everything is set up as if from :
	 *		initstate( 1, &randtbl, 128 );
	 * Note that this initialization takes advantage of the fact
	 * that srandom() advances the front and rear pointers 10*rand_deg
	 * times, and hence the rear pointer which starts at 0 will also
	 * end up at zero; thus the zeroeth element of the state
	 * information, which contains info about the current
	 * position of the rear pointer is just
	 *	MAX_TYPES*(rptr - state) + TYPE_3 == TYPE_3.
	 */
	{ DEG_0, DEG_1, DEG_2, DEG_3, DEG_4 },
	{ SEP_0, SEP_1, SEP_2, SEP_3, SEP_4 },
	{ TYPE_3,
	    0x9a319039U, 0x32d9c024U, 0x9b663182U, 0x5da1f342U,
	    0xde3b81e0U, 0xdf0a6fb5U, 0xf103bc02U, 0x48f340fbU,
	    0x7449e56bU, 0xbeb1dbb0U, 0xab5c5918U, 0x946554fdU,
	    0x8c2e680fU, 0xeb3d799fU, 0xb11ee0b7U, 0x2d436b86U,
	    0xda672e2aU, 0x1588ca88U, 0xe369735dU, 0x904f35f7U,
	    0xd7158fd6U, 0x6fa6f051U, 0x616e6b96U, 0xac94efdcU,
	    0x36413f93U, 0xc622c298U, 0xf5a42ab8U, 0x8a88d77bU,
			0xf5ad9d0eU, 0x8999220bU, 0x27fb47b9U },
	&_randominit.randtbl[ SEP_3 + 1 ],
	&_randominit.randtbl[ 1 ],
	&_randominit.randtbl[ 1 ],
	TYPE_3, DEG_3, SEP_3,
	&_randominit.randtbl[ DEG_3 + 1]
};

static struct _randomjunk *
_randomjunk(void)
{
	struct _randomjunk *rp = __randomjunk;

	if (rp == NULL) {
		rp = (struct _randomjunk *)malloc(sizeof (*rp));
		if (rp == NULL)
			return (NULL);
		(void) memcpy(rp, &_randominit, sizeof (*rp));
		__randomjunk = rp;
	}
	return (rp);
}


/*
 * initstate:
 * Initialize the state information in the given array of n bytes for
 * future random number generation.  Based on the number of bytes we
 * are given, and the break values for the different R.N.G.'s, we choose
 * the best (largest) one we can and set things up for it.  srandom() is
 * then called to initialize the state information.
 * Note that on return from srandom(), we set state[-1] to be the type
 * multiplexed with the current value of the rear pointer; this is so
 * successive calls to initstate() won't lose this information and will
 * be able to restart with setstate().
 * Note: the first thing we do is save the current state, if any, just like
 * setstate() so that it doesn't matter when initstate is called.
 * Returns a pointer to the old state.
 */

char  *
initstate(
	unsigned int seed,	/* seed for R. N. G. */
	char *arg_state,	/* pointer to state array */
	size_t size)		/* # bytes of state info */
{
	unsigned int n;
	struct _randomjunk *rp = _randomjunk();
	char		*ostate;

	if (size > UINT_MAX)
		n = UINT_MAX;
	else
		n = (unsigned int)size;

	if (rp == NULL)
		return (NULL);
	ostate = (char *)(&rp->state[ -1 ]);

	if (rp->rand_type  ==  TYPE_0)  rp->state[ -1 ] = rp->rand_type;
	else  rp->state[ -1 ] =
	    (unsigned int)(MAX_TYPES*(rp->rptr - rp->state) + rp->rand_type);
	if (n  <  BREAK_1)  {
	    if (n  <  BREAK_0)  {
		return (NULL);
	    }
	    rp->rand_type = TYPE_0;
	    rp->rand_deg = DEG_0;
	    rp->rand_sep = SEP_0;
	} else  {
	    if (n  <  BREAK_2)  {
		rp->rand_type = TYPE_1;
		rp->rand_deg = DEG_1;
		rp->rand_sep = SEP_1;
	    } else  {
		if (n  <  BREAK_3)  {
		    rp->rand_type = TYPE_2;
		    rp->rand_deg = DEG_2;
		    rp->rand_sep = SEP_2;
		} else  {
		    if (n  <  BREAK_4)  {
			rp->rand_type = TYPE_3;
			rp->rand_deg = DEG_3;
			rp->rand_sep = SEP_3;
		    } else  {
			rp->rand_type = TYPE_4;
			rp->rand_deg = DEG_4;
			rp->rand_sep = SEP_4;
		    }
		}
	    }
	}
	/* first location */
	rp->state = &(((unsigned int *)(uintptr_t)arg_state)[1]);
	/* must set end_ptr before srandom */
	rp->end_ptr = &rp->state[rp->rand_deg];
	srandom(seed);
	if (rp->rand_type  ==  TYPE_0)  rp->state[ -1 ] = rp->rand_type;
	else
		rp->state[-1] = (unsigned int)(MAX_TYPES*
		    (rp->rptr - rp->state) + rp->rand_type);
	return (ostate);
}



/*
 * setstate:
 * Restore the state from the given state array.
 * Note: it is important that we also remember the locations of the pointers
 * in the current state information, and restore the locations of the pointers
 * from the old state information.  This is done by multiplexing the pointer
 * location into the zeroeth word of the state information.
 * Note that due to the order in which things are done, it is OK to call
 * setstate() with the same state as the current state.
 * Returns a pointer to the old state information.
 */

char  *
setstate(const char *arg_state)
{
	struct _randomjunk *rp = _randomjunk();
	unsigned int	*new_state;
	unsigned int	type;
	unsigned int	rear;
	char		*ostate;

	if (rp == NULL)
		return (NULL);
	new_state = (unsigned int *)(uintptr_t)arg_state;
	type = new_state[0]%MAX_TYPES;
	rear = new_state[0]/MAX_TYPES;
	ostate = (char *)(&rp->state[ -1 ]);

	if (rp->rand_type  ==  TYPE_0) rp->state[ -1 ] = rp->rand_type;
	else
		rp->state[-1] = (unsigned int)(MAX_TYPES*
		    (rp->rptr - rp->state) + rp->rand_type);
	switch (type)  {
	    case  TYPE_0:
	    case  TYPE_1:
	    case  TYPE_2:
	    case  TYPE_3:
	    case  TYPE_4:
		rp->rand_type = type;
		rp->rand_deg = rp->degrees[ type ];
		rp->rand_sep = rp->seps[ type ];
		break;

	    default:
		return (NULL);
	}
	rp->state = &new_state[ 1 ];
	if (rp->rand_type  !=  TYPE_0)  {
	    rp->rptr = &rp->state[ rear ];
	    rp->fptr = &rp->state[ (rear + rp->rand_sep)%rp->rand_deg ];
	}
	rp->end_ptr = &rp->state[ rp->rand_deg ];	/* set end_ptr too */
	return (ostate);
}



/*
 * random:
 * If we are using the trivial TYPE_0 R.N.G., just do the old linear
 * congruential bit.  Otherwise, we do our fancy trinomial stuff, which is the
 * same in all ther other cases due to all the global variables that have been
 * set up.  The basic operation is to add the number at the rear pointer into
 * the one at the front pointer.  Then both pointers are advanced to the next
 * location cyclically in the table.  The value returned is the sum generated,
 * reduced to 31 bits by throwing away the "least random" low bit.
 * Note: the code takes advantage of the fact that both the front and
 * rear pointers can't wrap on the same call by not testing the rear
 * pointer if the front one has wrapped.
 * Returns a 31-bit random number.
 */

long
random(void)
{
	struct _randomjunk *rp = _randomjunk();
	unsigned int	i;

	if (rp == NULL)
		return (0L);
	if (rp->rand_type  ==  TYPE_0)  {
	    i = rp->state[0] = (rp->state[0]*1103515245 + 12345)&0x7fffffff;
	} else  {
	    *rp->fptr += *rp->rptr;
	    i = (*rp->fptr >> 1)&0x7fffffff;	/* chucking least random bit */
	    if (++rp->fptr  >=  rp->end_ptr)  {
		rp->fptr = rp->state;
		++rp->rptr;
	    } else  {
		if (++rp->rptr  >=  rp->end_ptr)  rp->rptr = rp->state;
	    }
	}
	return ((long)i);
}

/*
 * srandom:
 * Initialize the random number generator based on the given seed.  If the
 * type is the trivial no-state-information type, just remember the seed.
 * Otherwise, initializes state[] based on the given "seed" via a linear
 * congruential generator.  Then, the pointers are set to known locations
 * that are exactly rand_sep places apart.  Lastly, it cycles the state
 * information a given number of times to get rid of any initial dependencies
 * introduced by the L.C.R.N.G.
 * Note that the initialization of randtbl[] for default usage relies on
 * values produced by this routine.
 */

void
srandom(unsigned int x)
{
	struct _randomjunk *rp = _randomjunk();
	unsigned int	i;

	if (rp == NULL)
		return;
	if (rp->rand_type  ==  TYPE_0)  {
	    rp->state[ 0 ] = x;
	} else  {
	    rp->state[ 0 ] = x;
	    for (i = 1; i < rp->rand_deg; i++)  {
		rp->state[i] = 1103515245*rp->state[i - 1] + 12345;
	    }
	    rp->fptr = &rp->state[ rp->rand_sep ];
	    rp->rptr = &rp->state[ 0 ];
	    for (i = 0; i < 10*rp->rand_deg; i++)  (void)random();
	}
}
