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
 * Copyright 2008 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include<sys/asm_linkage.h>


!=============================================================================
! 	File: fpu-if64.s
!=============================================================================


!--------------------------------------------------------------------------
! Name:		Get the Floating point Status Register
! Function:	return a copy of the FSR to caller
! Calling:	none
! Returns:	i0 = fsr contents
! Convention:	fsr_value = get_fsr() ** 
!--------------------------------------------------------------------------
	.section	".data"
	.align		8
.Lgfsr:
	.skip	8

ENTRY_NP(get_fsr)
	save	%sp, -SA(MINFRAME), %sp	! save the registers & stack frame
	setn	.Lgfsr,%l6,%l0 	! .. set the address of the result holder
	stx	%fsr, [%l0]	! .. set the contents of the FSR register
	ldx	[%l0], %i0	! .. return the fsr to caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(get_fsr)

!--------------------------------------------------------------------------
! Name:		Set Floating point Status Register
! Function:	Set the FSR
! Calling:	i0 = value to write to fsr
! Returns:	none
! Convention:	set_fsr(get_fsr() ** || <userVal>) ** 
!               Please note that the user is expected to OR the new value
!               with the current FSR content and pass the result to 
!               set_fsr().
!--------------------------------------------------------------------------
	.section	".data"
	.align		8
.Lsfsr:
	.skip	8

ENTRY_NP(set_fsr)
	save	%sp, -SA(MINFRAME), %sp	! save the registers & stack frame
	setn	.Lsfsr,%l6,%l0 	! .. set the address of the result holder
	stx	%i0, [%l0]	! .. save the value in memory
	ldx	[%l0], %fsr	! .. get the contents of the FSR register
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(set_fsr)


!--------------------------------------------------------------------------
! Name:		Get the Graphics Status Register
! Function:	return a copy of the GSR to caller
! Calling:	none
! Returns:	i0 = gsr contents
! Convention:	gsr_value = get_gsr() ** 
!--------------------------------------------------------------------------
ENTRY_NP(get_gsr)
	save	%sp, -SA(MINFRAME), %sp	! save the registers & stack frame
	rd      %gsr, %i0
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(get_gsr)

!--------------------------------------------------------------------------
! Name:		Set Graphics Status Register
! Function:	Set the GSR
! Calling:	i0 = value to write to gsr
! Returns:	none
! Convention:	set_gsr(get_gsr() || <userVal>)
!               Please note that the user is expected to OR the new value
!               with the current GSR content and pass the result to 
!               set_gsr().
!--------------------------------------------------------------------------
ENTRY_NP(set_gsr)
	save	%sp, -SA(MINFRAME), %sp	! save the registers & stack frame
	wr      %i0, %g0, %gsr
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(set_gsr)



!**************************************************************************
!*			Data Conversion Functions			 *
!**************************************************************************

!--------------------------------------------------------------------------
! Name:		Integer to Float (Single)
! Function:	Convert an integer value to a single precision floating point 
!		value
! Calling:	in0 = value to convert
! Returns:	in0 = converted value
! Convention:	Real = int_float_s(Int) ** 
!--------------------------------------------------------------------------
	.section	".data"
	.align		4
.Lfls:
	.word   0
.Lfls1:
	.word   0

ENTRY_NP(int_float_s)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lfls1,%l6,%o5	! .. set the address of the result holder
	setn	.Lfls,%l6,%o4	! .. set address of temp. mem reg
	st	%i0, [%o4]	! .. put the passed value into memory
	ld	[%o4], %f0	! .. get the value from memory into FPU register
	fitos   %f0, %f2	! .. get the integer into float into fpu r1
	st	%f2, [%o5]	! .. store into the location
	ld	[%o5], %i0	! .. put the value for return
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(int_float_s)

!--------------------------------------------------------------------------
! Name:		Integer to Float (double)
! Function:	Convert an integer value to a double precision floating point 
!		value
! Calling:	in0 = value to convert
! Returns:	in0 = converted value
! Convention:	Real = int_float_d(Int) ** 
!--------------------------------------------------------------------------
	.section	".data"
	.align	4
.Lfld:
	.word   0

	.align	8

.Lfld1:
	.skip	8

ENTRY_NP(int_float_d)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lfld1,%l6,%o5	! .. get the address of temp2
	setn	.Lfld,%l6,%o4	! .. get the address of temp
	st	%i0, [%o4]	! .. get the user value
	ld	[%o4], %f0	! .. into the float register
	fitod   %f0, %f2	! .... have the fpu perform the operation
	std	%f2, [%o5]	! .. save the result
	ldx	[%o5], %i0	! .. and return it to caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(int_float_d)


!--------------------------------------------------------------------------
! Name:		float to integer (single)
! Function:	Convert a real value to an integer
! Calling:	in0 = Value
! Returns:	in0 = Value
! Convention:	Int = float_int_s(real) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  4
.Lflnts:
	.word   0
.Lflnts1:
	.word   0

ENTRY_NP(float_int_s)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lflnts1,%l6,%o5	! .. get the address of temp2
	setn	.Lflnts,%l6,%o4	! .... and temp
	st	%i0, [%o4]	! .. get the users value
	ld	[%o4], %f0	! .. into the float register
	fstoi   %f0, %f2	! .... have the fpu perform the operation
	st	%f2, [%o5]	! .. save the result
	ld	[%o5], %i0	! .. and return it to the user
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(float_int_s)

!--------------------------------------------------------------------------
! Name:		Float to Integer conversion (double)
! Function:	Convert a real value to an integer
! Calling:	in0 = value
! Returns:	in0 = value
! Convention:	Int = float_int_d(real) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Lflntd:
	.skip	8
.Lflntd1:
	.skip	4

ENTRY_NP(float_int_d)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack 
	setn	.Lflntd1,%l6,%o5 	! .. get the address of temp2
	setn	.Lflntd,%l6,%o4 	! .. and temp
	stx     %i0, [%o4] 	! .. get the callers value
	ldd     [%o4], %f0 	! .. into the float register
	fdtoi   %f0, %f2 	! .... have the fpu perform the operation
	st      %f2, [%o5] 	! .. save the result
	ld      [%o5], %i0 	! .... and return it to caller
	ret 			! Delayed return (get user ret addr)
	restore 		! .. restore the frame window
SET_SIZE(float_int_d)

!--------------------------------------------------------------------------
! Name:		Convert Single to double precision
! Function:	<as the name says>
! Calling:	in0 = value
! Returns:	in0 = result
! Convention:	result = convert_sp_dp(value) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Lspdp:
	.skip 	8
.Lspdp1:
	.skip 	4

ENTRY_NP(convert_sp_dp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lspdp1,%l6,%l0	! .. get the address of temp2
	setn	.Lspdp,%l6,%l1	! .. get the address of temp
	st	%i0, [%l0]	! .. get the callers value
	ld	[%l0], %f0	! .. into the float register
	fstod   %f0, %f2	! .... have the fpu perform the operation
	std	%f2, [%l1]	! .. save the result
	ldx	[%l1], %i0	! .... and return it to the caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(convert_sp_dp)

!--------------------------------------------------------------------------
! Name:		Convert Double to Single precision
! Function:	..
! Calling:	in0 = double precision value
! Returns:	in0 = result
! Convention:	result = convert_dp_sp(value) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  4
.Ldpsp:
	.skip	4

        .align  8

.Ldpsp1:
	.skip	8

ENTRY_NP(convert_dp_sp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Ldpsp1,%l6,%l0	! .. get the address of temp2
	setn	.Ldpsp,%l6,%l1	! .. and temp
	stx	%i0, [%l0]	! .. get the users value
	ldd	[%l0], %f0	! .. move it to a float register
	fdtos	%f0, %f2	! .... have the fpu perform the operation
	st	%f2, [%l1]	! .. save the result
	ld	[%l1], %i0	! .... and return it to the caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(convert_dp_sp)


!--------------------------------------------------------------------------
! Name:		Negate a value (Single-precision)
! Function:	Compliments the Sign bit
! Calling:	in0 = number to cross her
! Returns:	in0 = result
! Convention:	result = negate_value_sp(value) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Lneg:
	.skip	8
.Lneg1:
	.skip	8

ENTRY_NP(negate_value_sp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lneg1,%l6,%l0	! .. get the address of .Lneg 
	setn	.Lneg,%l6,%l1	! .. and of .Lneg1
	st	%i0, [%l0]	! .. get the callers value
	ld	[%l0], %f0	! .. into the float register
	fnegs   %f0, %f2	! .... have the fpu perform the operation
	st	%f2, [%l1]	! .. save the result
	ld	[%l1], %i0 	! .... and return it to the caller
	ret 			! Delayed return (get user ret addr)
	restore 		! .. restore the frame window
SET_SIZE(negate_value_sp)


!--------------------------------------------------------------------------
! Name:		Negate a value (Double-precision)
! Function:	Compliments the Sign bit
! Calling:	in0 = number to cross her
! Returns:	in0 = result
! Convention:	result = negate_value_dp(value) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Lneg2:
	.skip	8
.Lneg3:
	.skip	8

ENTRY_NP(negate_value_dp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lneg3,%l6,%l0	! .. get the address of .Lneg 
	setn	.Lneg1,%l6,%l1	! .. and of .Lneg1
	stx	%i0, [%l0]	! .. get the callers value
	ldd	[%l0], %f0	! .. into the float register
	fnegd   %f0, %f2	! .... have the fpu perform the operation
	std	%f2, [%l1]	! .. save the result
	ldx	[%l1], %i0 	! .... and return it to the caller
	ret 			! Delayed return (get user ret addr)
	restore 		! .. restore the frame window
SET_SIZE(negate_value_dp)

!--------------------------------------------------------------------------
! Name:		Absolute Value (Single-precision)
! Function:	Convert a SP value to its absolute value (clears sign bit)
! Calling:	in0 = value
! Returns:	in0 = result
! Convention:	result = absolute_value_sp(value) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Labs:
	.skip	8
.Labs1:
	.skip	8

ENTRY_NP(absolute_value_sp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack 
	setn	.Labs1,%l6,%l0 	! .. get the address of temp2
	setn	.Labs,%l6,%l1 	! .. and temp
	st	%i0, [%l0] 	! .. get the users value
	ld	[%l0], %f0 	! .. into a float register
	fabss	%f0, %f2 	! .... have the fpu perform the operation
	st	%f2, [%l1] 	! .. save the result
	ld	[%l1], %i0  	! .... and return it to caller
	ret  			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(absolute_value_sp)


!--------------------------------------------------------------------------
! Name:		Absolute Value (Double-precision)
! Function:	Convert a DP value to its absolute value (clears sign bit)
! Calling:	in0 = value
! Returns:	in0 = result
! Convention:	result = absolute_value_dp(value) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Labs2:
	.skip	8
.Labs3:
	.skip	8

ENTRY_NP(absolute_value_dp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack 
	setn	.Labs3,%l6,%l0 	! .. get the address of temp2
	setn	.Labs2,%l6,%l1 	! .. and temp
	stx	%i0, [%l0] 	! .. get the users value
	ldd	[%l0], %f0 	! .. into a float register
	fabsd	%f0, %f2 	! .... have the fpu perform the operation
	std	%f2, [%l1] 	! .. save the result
	ldx	[%l1], %i0  	! .... and return it to caller
	ret  			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(absolute_value_dp)

!**************************************************************************
!*				Arithmetic Functions			 *
!**************************************************************************

!--------------------------------------------------------------------------
! Name:		Single-precision square-root
! Function:	Calculate the square-root of a Single precision value
! Calling:	in0 = value
! Returns:	in0 = result
! Convention:	result = sqrt_sp(value) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  4
.Lsqsp:
	.skip	4
.Lsqsp1:
	.skip	4

ENTRY_NP(sqrt_sp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lsqsp1,%l6,%l0	! .. get the address of temp2
	setn	.Lsqsp,%l6,%l1	! .. and temp
	st	%i0, [%l0]	! .. get the callers value
	ld	[%l0], %f0	! .. into the float register
	fsqrts  %f0, %f2	! .... have the fpu perform the operation
	st	%f2, [%l1]	! .. save the result
	ld	[%l1], %i0	! .... and return it to caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(sqrt_sp)

!--------------------------------------------------------------------------
! Name:		Double-precision square-root
! Function:	Calculate the square-root of a double precision value
! Calling:	in0 = value
! Returns:	in0 = result
! Convention:	result = sqrt_dp(value) ** 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Lsqdp:
	.skip	8
.Lsqdp1:
	.skip	8

ENTRY_NP(sqrt_dp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack 
	setn	.Lsqdp1,%l6,%l0 	! .. get the address of temp2
	setn	.Lsqdp,%l6,%l1 	! .. and temp
	stx		%i0, [%l0] 	! .. get the callers value
	ldd		[%l0], %f0 	! .. into a float register
	fsqrtd  %f0, %f2	! .... have the fpu perform the operation
	std		%f2, [%l1] 	! .. save the result
	ldx		[%l1], %i0 	! .... and return it to the caller
	ret 			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(sqrt_dp)



!--------------------------------------------------------------------------
! Name:		Add single precision
! Function:	Add two values
! Calling:	in0 = value1,  in1 = value2
! Returns:	in0 = result
! Convention:	result = add_sp(value1,value2); 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  4
.Laddsp:
	.skip	4
.Laddsp1:
	.skip	4
.Laddsp2:
	.skip	4

ENTRY_NP(add_sp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack  
	setn	.Laddsp2,%l6,%l0  	! .. get the address of temp2
	setn	.Laddsp1,%l6,%l1	! .. and temp1
	setn	.Laddsp,%l6,%l2	! .. and temp
	st	%i0, [%l0]	! .. get the users value1
	st	%i1, [%l1]	! .. and value2
	ld	[%l0], %f0	! .. into the float registers
	ld	[%l1], %f2	! ......
	fadds   %f0, %f2, %f4	! .... have the fpu perform the operation
	st	%f4, [%l2]	! .. save the result
	ld	[%l2], %i0	! .... and return it to caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(add_sp)

!--------------------------------------------------------------------------
! Name:		Add double precision 
! Function:	Add two 64 bit values
! Calling:	in0 = value1, in1 = value2
! Returns:	in0.1 = result
! Convention:	result = add_dp(value1,value2); 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Ladddp:
	.skip	8
.Ladddp1:
	.skip	8
.Ladddp2:
	.skip	8

ENTRY_NP(add_dp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack   
	setn	.Ladddp2,%l6,%l0   	! .. get the address of temp2
	setn	.Ladddp1,%l6,%l1 	! .. and temp1
	setn	.Ladddp,%l6,%l2 	! .. and temp
	stx	%i0, [%l0] 	! .. get the user value1
	stx	%i1, [%l1]	! .. get the user value2
	ldd	[%l0], %f0 	! .. set them in float registers
	ldd	[%l1], %f2	! .... both values
	faddd	%f0, %f2, %f4	! .... have the fpu perform the operation
	std	%f4, [%l2] 	! .. save the result
	ldx	[%l2], %i0 	! .... and return it to the caller
	ret 			! Delayed return (get user ret addr)
	restore 		! .. restore the frame window
SET_SIZE(add_dp)

!--------------------------------------------------------------------------
! Name:		Subtract Single Precision
! Function:	Subtract two single precision values from each other
! Calling:	in0 = Value1, in1 = value2
! Returns:	in0 = result
! Convention:	result = sub_sp(value1, value2);
!--------------------------------------------------------------------------
        .section        ".data"
        .align  4
.Lsbsp:
	.skip	4
.Lsbsp1:
	.skip	4
.Lsbsp2:
	.skip	4

ENTRY_NP(sub_sp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack   
	setn	.Lsbsp2,%l6,%l0   	! set the address of the result holder
	setn	.Lsbsp1,%l6,%l1 	! .. get the address of temp1 (holder)
	setn	.Lsbsp,%l6,%l2 	! .. get the address of temp
	st	%i0, [%l0] 	! .. save the value in memory
	st	%i1, [%l1] 	! .. save the value in memory
	ld	[%l0], %f0 	! .. load the fpu register
	ld	[%l1], %f2 	! .. load the fpu register
	fsubs	%f0, %f2, %f4 	! .... have the fpu perform the operation
	st	%f4, [%l2] 	! .. save the result
	ld	[%l2], %i0 	! .. return the result to the caller
	ret 			! Delayed return (get user ret addr)
	restore 		! .. restore the frame window
SET_SIZE(sub_sp)

!--------------------------------------------------------------------------
! Name:		Subtract Double Precision
! Function:	Subtract two double precision values
! Calling:	in0 = Value1, in1 = Value2
! Returns:	in0 = Result
! Convention:	Result = sub_dp(Value1,Value2);
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Lsbdp:
	.skip	8
.Lsbdp1:
	.skip	8
.Lsbdp2:
	.skip	8

ENTRY_NP(sub_dp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack    
	setn	.Lsbdp2,%l6,%l0    	! set the address of the result holder
	setn	.Lsbdp1,%l6,%l1  	! .. get the address of temp1 (holder)
	setn	.Lsbdp,%l6,%l2  	! .. get the address of temp
	stx	%i0, [%l0]  	! .. save the value in memory
	stx	%i1, [%l1] 	! .. save the value in memory
	ldd	[%l0], %f0  	! .. load the fpu register
	ldd	[%l1], %f2 	! .. load the fpu register
	fsubd	%f0, %f2, %f4 	! .... have the fpu perform the operation
	std	%f4, [%l2]  	! .. save the result
	ldx	[%l2], %i0  	! .. return the result to the caller
	ret  			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(sub_dp)

!--------------------------------------------------------------------------
! Name:		Multiply Single Precision
! Function:	Multiply two single precision values
! Calling:	in0 = Value1, in1 = value2
! Returns:	in0 = Result
! Convention:	Result = mult_sp(Value1,Value2);
!--------------------------------------------------------------------------
        .section        ".data"
        .align  4
.Lmlsp:
	.skip	4
.Lmlsp1:
	.skip	4
.Lmlsp2:
	.skip	4

ENTRY_NP(mult_sp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lmlsp2,%l6,%l0	! .. get the address of temp2
	setn	.Lmlsp1,%l6,%l1	! .. and temp1
	setn	.Lmlsp,%l6,%l2	! .. and temp
	st	%i0, [%l0]	! .. Get the callers value1 into temp2
	st	%i1, [%l1]	! .. Get the callers value2 into temp1
	ld	[%l0], %f0	! .. then load Value1
	ld	[%l1], %f2	! .. and Value2
	fmuls   %f0, %f2, %f4	! .... have the fpu perform the operation
	st	%f4, [%l2]	! .. save the result
	ld	[%l2], %i0	! .... and return it to the caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(mult_sp)

!--------------------------------------------------------------------------
! Name:		Multiply Double Precision
! Function:	Multiply two values and return the result
! Calling:	i0 = value1, i1 = value2
! Returns:	i0 = result
! Convention:	result = mul_dp(value1, value2); 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Lmldp:
	.skip	8
.Lmldp1:
	.skip	8
.Lmldp2:
	.skip	8

ENTRY_NP(mult_dp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack   
	setn	.Lmldp2,%l6,%l0     	! set the address of the result holder
	setn	.Lmldp1,%l6,%l1     	! .. get the address of temp1 (holder)
	setn	.Lmldp,%l6,%l2	! .. get the address of temp
	stx		%i0, [%l0]	! .. save the value in memory
	stx		%i1, [%l1]	! .. save the value in memory
	ldd		[%l0], %f0	! .. load the fpu register
	ldd		[%l1], %f2	! .. load the fpu register
	fmuld   %f0, %f2, %f4  	! .... have the fpu perform the operation
	std		%f4, [%l2]	! .. save the result
	ldx		[%l2], %i0	! .. return the result to the caller
	ret    			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(mult_dp)

!--------------------------------------------------------------------------
! Name:		Divide Single Precision
! Function:	Divide two value and return the result
! Calling:	i0 = value1, i1 = value2
! Returns:	i0 = result
! Convention:	result = div_sp(value1, value2); 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  4
.Ldvsp:
	.word   0
.Ldvsp1:
	.word   0
.Ldvsp2:
	.word   0

ENTRY_NP(div_sp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack   
	setn	.Ldvsp2,%l6,%l0	! .. get the address of temp2
	setn	.Ldvsp1,%l6,%l1     	! .. get the address of temp1 (holder)
	setn	.Ldvsp,%l6,%l2	! .. get the address of temp
	st	%i0, [%l0]	! .. save the value in memory
	st	%i1, [%l1]	! .. save the value in memory
	ld	[%l0], %f0     	! .. load the fpu register
	ld	[%l1], %f2     	! .. load the fpu register

	fdivs   %f0, %f2, %f4  	! .... have the fpu perform the operation
	st	%f4, [%l2]	! .. save the result
	ld	[%l2], %i0	! .. return the result to the caller

	ret    			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(div_sp)

!--------------------------------------------------------------------------
! Name:		Divide Double Precision
! Function:	Divide two value and return the result
! Calling:	i0 = value1, i1 = value2
! Returns:	i0 = result
! Convention:	result = div_dp(value1, value2); 
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Ldvdp:
	.skip	8
.Ldvdp1:
	.skip	8
.Ldvdp2:
	.skip	8

ENTRY_NP(div_dp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack   
	setn	.Ldvdp2,%l6,%l0     	! .. get the address of temp2
	setn	.Ldvdp1,%l6,%l1     	! .. get the address of temp1 (holder)
	setn	.Ldvdp,%l6,%l2	! .. get the address of temp
	stx	%i0, [%l0]	! .. save the value in memory
	stx	%i1, [%l1]	! .. save the value in memory
	ldd	[%l0], %f0     	! .. load the fpu register
	ldd	[%l1], %f2     	! .. load the fpu register
	fdivd   %f0, %f2, %f4  	! .... have the fpu perform the operation
	std	%f4, [%l2]	! .. save the result
	ldx	[%l2], %i0	! .. return the result to the caller
	ret    			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(div_dp)

!**************************************************************************
!*			Data Comparison Functions			 *
!**************************************************************************

!--------------------------------------------------------------------------
! Name:		Compare Single and Exception if Unordered
! Function:	Compare two values and return the FSR flags
! Warning:	
! Calling:	i0 = value1, i2 = value2
! Returns:	i0 = flags
! Convention:	flagsresult  = cmp_s_ex(value1, value2);
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Lcpsx:
	.skip	8
.Lcpsx1:
	.skip	4
.Lcpsx2:
	.skip	4

ENTRY_NP(cmp_s_ex)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lcpsx2,%l6,%l0	! .. get the address of temp2
	setn	.Lcpsx1,%l6,%l1	! .. get the address of temp
	setn	.Lcpsx,%l6,%l2	! .. get the address of temp
	st	%i0, [%l0]	! .. save the value in memory
	st	%i1, [%l1]	! .. save the value in memory
	ld	[%l0], %f0	! .. load the fpu register
	ld	[%l1], %f2	! .. load the fpu register
	fcmpes  %f0, %f2	! .... have the fpu perform the operation
	nop			! .. delay
	stx	%fsr, [%l2]	! .. get the contents of the FSR register
	ldx	[%l2], %i0	! .. return the result to the caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(cmp_s_ex)

!--------------------------------------------------------------------------
! Name:		Compare Double and Exception if Unordered
! Function:	Compare two values and return the FSR flags
! Warning:
! Calling:	i0 = value1, i2 = value2
! Returns:	i0 = flags
! Convention:	flagsresult  = cmp_d_ex(value1, value2);
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8
.Lcpdx:
	.skip	8
.Lcpdx1:
	.skip	8
.Lcpdx2:
	.skip	8

ENTRY_NP(cmp_d_ex)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack   
	setn	.Lcpdx2,%l6,%l0     	! .. get the address of temp2
	setn	.Lcpdx1,%l6,%l1     	! .. get the address of temp1 (holder)
	setn	.Lcpdx,%l6,%l2  	! .. get the address of temp
	stx		%i0, [%l0]	! .. save the value in memory
	stx		%i1, [%l1]	! .. save the value in memory
	ldd		[%l0], %f0     	! .. load the fpu register
	ldd		[%l1], %f2	! .. load the fpu register
	fcmped  %f0, %f2	! .... have the FPU do it
	nop			! .. delay
	stx	%fsr, [%l2]	! .. get the contents of the FSR register
	ldx	[%l2], %i0	! .. return the result to the caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(cmp_d_ex)

!--------------------------------------------------------------------------
! Name:		Float to long conversion (single)
! Function:	Convert a real single-precision value to a long
! Calling:	in0 = value
! Returns:	in0 = value
! Convention:	long = float_long_s(real) ** 
!--------------------------------------------------------------------------

        .data
        .align  4

.Lfllngs:
    .skip   4

        .align  8

.Lfllngs1:
    .skip   8

ENTRY_NP(float_long_s)
    save    %sp, -SA(MINFRAME), %sp
    setn    .Lfllngs1,%l6,%o5    ! .. get the address of temp2
    setn    .Lfllngs,%l6,%o4     ! .. and temp

    st      %i0, [%o4]  ! .. get the callers value
    ld      [%o4], %f0  ! .. into the float register
    fstox   %f0, %f2    ! .... have the fpu perform the operation
    std     %f2, [%o5]  ! .. save the result
    ldx     [%o5], %i0  ! .... and return it to caller

    ret
    restore
SET_SIZE(float_long_s)



!--------------------------------------------------------------------------
! Name:		Float to long conversion (double)
! Function:	Convert a real value to a long
! Calling:	in0 = value
! Returns:	in0 = value
! Convention:	long = float_long_d(real) ** 
!--------------------------------------------------------------------------

        .data
        .align  8

.Lfllngd:
    .skip   8
.Lfllngd1:
    .skip   8

ENTRY_NP(float_long_d)
    save    %sp, -SA(MINFRAME), %sp
    setn    .Lfllngd1,%l6,%o5    ! .. get the address of temp2
    setn    .Lfllngd,%l6,%o4     ! .. and temp

    stx     %i0, [%o4]  ! .. get the callers value
    ldd     [%o4], %f0  ! .. into the float register
    fdtox   %f0, %f2    ! .... have the fpu perform the operation
    std     %f2, [%o5]  ! .. save the result
    ldx     [%o5], %i0  ! .... and return it to caller

    ret
    restore
SET_SIZE(float_long_d)



!--------------------------------------------------------------------------
! Name:		Long to Float (Single)
! Function:	Convert an integer value to a single precision floating point 
!		value
! Calling:	in0 = value to convert
! Returns:	in0 = converted value
! Convention:	Real = long_float_s(Int) ** 
!--------------------------------------------------------------------------

        .data
	.align	8

.Llngfls:
	.skip	8
.Llngfls1:
	.skip	4

ENTRY_NP(long_float_s)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Llngfls1,%l6,%o5	! .. set the address of the result holder
	setn	.Llngfls,%l6,%o4	! .. set address of temp. mem reg
	stx	%i0, [%o4]	! .. put the passed value into memory
	ldd	[%o4], %f0	! .. get the value from memory into FPU register
	fxtos   %f0, %f2	! .. get the integer into float into fpu r1
	st	%f2, [%o5]	! .. store into the location
	ld	[%o5], %i0	! .. put the value for return
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(long_float_s)

!--------------------------------------------------------------------------
! Name:		Long to Float (double)
! Function:	Convert an integer value to a double precision floating point 
!		value
! Calling:	in0 = value to convert
! Returns:	in0 = converted value
! Convention:	Real = long_float_d(Int) ** 
!--------------------------------------------------------------------------

        .data
	.align	8

.Llngfld:
	.skip	8
.Llngfld1:
	.skip	8

ENTRY_NP(long_float_d)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Llngfld1,%l6,%o5	! .. get the address of temp2
	setn	.Llngfld,%l6,%o4	! .. get the address of temp
	stx	%i0, [%o4]	! .. get the user value
	ldd	[%o4], %f0	! .. into the float register
	fxtod   %f0, %f2	! .... have the fpu perform the operation
	std	%f2, [%o5]	! .. save the result
	ldx	[%o5], %i0	! .. and return it to caller
	ret			! Delayed return (get user ret addr)
	restore			! .. restore the frame window
SET_SIZE(long_float_d)
