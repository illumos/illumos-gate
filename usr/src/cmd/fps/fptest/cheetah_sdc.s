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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include "cheetah_sdc.h"

/*
 * TARGET_REG and TEMP_REG are macros defined in cheetah_sdc.h
 * They are set based on some compile time values
 * for eg. 
 * as -xarch=v8 -P -D_ASM -DLOCALS -DL0 cheetah_sdc.s -o ch_sdc_l0.o
 * ch_sdc_l0.o will contain code to test %l0 register
 * The functions are named after the register it is testing (l1(), l2() etc)
 *
 * Algorithm
 * Use TARGET_REGISTER
 * Do some random stuff on TEMP_REGISTER
 * Do some operations on TARGET_REGISTER
 * Test 
 *
 * TARGET_REG(unsigned long, unsigned long*, unsigned long*)
 * Registers :
 * i0 = contains the pattern
 * i1 = location for the observed value
 * i2 = location for the expected value
 */

#ifdef __lint

/*ARGSUSED*/
int
g1(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
g2(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
g3(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
g4(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
l0(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
l1(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
l2(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
l3(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
l4(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
l5(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
l6(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
l7(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
o0(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
o1(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
o2(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
o3(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
o4(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
o5(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

/*ARGSUSED*/
int
o7(unsigned long arg1, unsigned long *arg2, unsigned long *arg3)
{
	return (0);
}

#else /* LINT */

	.align 64
ENTRY(TARGET_REG)

	save	%sp, -SA(MINFRAME), %sp

	setn	0x12345678, %g1, %TARGET_REG 	! initialize the TARGET_REG
						! with a known value

#ifdef	_sparc64
	stx	%i0, [%i1] 	! store the pattern to the first location
#else
	st	%i0, [%i1]
#endif

	nop
	nop
	nop
	nop

	nop
	nop
	nop
	nop
#ifdef	_sparc64
	stx	%g0, [%i2]
	stx	%g0, [%i2]
#else
	st	%g0, [%i2]
	st	%g0, [%i2]
#endif


!!
	clr	%TEMP_REG
	clr	%TEMP_REG

#ifdef	_sparc64
	st	%g0, [%i2]
#else
	st	%g0, [%i2]
#endif
	inc	%g0
	inc	%g0
	or	%TEMP_REG, %g0, %TEMP_REG
	or	%TEMP_REG, %g0, %TEMP_REG
	

!!
#ifdef	_sparc64
	ldx	[%i1], %TARGET_REG
#else
	ld	[%i1], %TARGET_REG
#endif
	mov	%TARGET_REG, %CHECK_REG1	! CHECK_REG1 should contain the 
						! most recent value of TARGET_REG.
						 
	mov	%TARGET_REG, %CHECK_REG2	! CHECK_REG2 should have the same
						! value as CHECK_REG1
! ==
	cmp	%CHECK_REG1, %CHECK_REG2	! comparison should pass in non-faulty
						! hardware

	be	Done
	mov	0, %i0

#ifdef	_sparc64
	stx	%CHECK_REG1, [%i1]			
	stx	%CHECK_REG2, [%i2]
#else
	st	%CHECK_REG1, [%i1]
	st	%CHECK_REG2, [%i2]
#endif

	mov	1, %i0

Done :

	ret
	restore
SET_SIZE(TARGET_REG)

#endif /* LINT */
