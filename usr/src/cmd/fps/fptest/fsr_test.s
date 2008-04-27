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

/*
 * Assembly routines used in the FSR testing.
 */


/*
 *  DCTI couple for instruction picking
 *  ===================================
 *
 *  The routines fcmps_fcc() and fcmpd_fcc() use a DCTI couple
 *  for choosing a specific instruction from a set of instructions.
 *  DCTI : Delayed Control Transfer Instruction. A DCTI couple
 *  contains a control transfer instruction in the delay slot of
 *  another control transfer instruction and the entire setup
 *  looks something like this :
 *
 *		jmp	<tgt1>
 *		ba	<tgt2>
 *
 *		.  .  .
 *
 *	table :		! Table of instructions. tgt1 will be pointing
 *			! to one of the instructions in it.
 *
 *		.  .  .
 *
 *	tgt2 :
 *		.  .  .
 *
 *  This functionality is explained below using the value of PC and
 *  nPC. We start with the jmp instruction.
 *
 *	step1 :  PC='jmp'    nPC='ba'
 *	step2 :  PC='ba'     nPC='tgt1'  ! jmp changes the nPC
 *	step3 :  PC='tgt1'   nPC='tgt2'  ! ba changes the nPC
 *	step4 :  PC='tgt2'   nPC=...
 *
 */


# include <sys/asm_linkage.h>



/*
 *  uint64_t res_fsr = fcmps_fcc(unsigned int val1, unsigned int val2, 
 *                               unsigned int fcc);
 *
 *  Single-precision FP comparision.
 *
 *  Operand 'fcc' indicates which fcc field of FSR to use.
 */

	.data

fcmps_opr1 : .word 0
.type fcmps_opr1,#object

fcmps_opr2 : .word 0
.type fcmps_opr2,#object

fcmps_result : .word 0,0
.type fcmps_result,#object

ENTRY_NP(fcmps_fcc)
  save    %sp, -SA(MINFRAME), %sp

  setn fcmps_opr1, %l0, %l1	! Get addr of operand 1 holder
  setn fcmps_opr2, %l0, %l2	! Get addr of operand 2 holder
  setn fcmps_result, %l0, %l3   ! Get addr of result holder
  setn fccn1, %l0, %o0		! Get addr of label fccn1

  st   %i0, [%l1]		! Store operand 1 in memory
  st   %i1, [%l2]		! Store operand 2 in memory
  ld   [%l1], %f2		! Load operand 1 into FP reg
  ld   [%l2], %f4		! Load operand 2 into FP reg

  sll  %i2, 2, %o1		! Calculate the offset


  ! DCTI couple
  jmp  %o0 + %o1		! Jump to fccn1+offset
  ba %ncc, fini			! After executing the target
				! instruction of 'jmp', go to the
				! end of the routine.


fccn1 :

  fcmps %fcc0, %f2, %f4

  fcmps %fcc1, %f2, %f4

  fcmps %fcc2, %f2, %f4

  fcmps %fcc3, %f2, %f4


fini :
  stx %fsr, [%l3]
  ldx [%l3], %i0

  ret
  restore
SET_SIZE(fcmps_fcc)



/*
 *  uint64_t res_fsr = fcmpd_fcc(uint64_t val1, uint64_t val2, 
 *                               unsigned int fcc);
 *
 *  Double-precision FP comparision.
 *
 *  Operand 'fcc' indicates which fcc field of FSR to use.
 *
 *  In SPARC V8, uint64_t parameters are split and stored in
 *  consecutive registers. For example, the first uint64_t
 *  parameter of the function will be stored in %i0 and %i1.
 *  This is not done in SPARC V9 as the registers are 64-bit.
 */

	.data
	.align 8

fcmpd_opr1 : .word 0,0
.type fcmpd_opr1,#object

fcmpd_opr2 : .word 0,0
.type fcmpd_opr2,#object

fcmpd_result : .word 0,0
.type fcmpd_result,#object

ENTRY_NP(fcmpd_fcc)
  save    %sp, -SA(MINFRAME), %sp

  setn fcmpd_opr1, %l0, %l1	! Get addr of operand 1 holder
  setn fcmpd_opr2, %l0, %l2	! Get addr of operand 2 holder
  setn fcmpd_result, %l0, %l3   ! Get addr of result holder
  setn fccn2, %l0, %o0		! Get addr of label fccn2

  stx   %i0, [%l1]		! Store operand 1 in memory
  stx   %i1, [%l2]		! Store operand 2 in memory

  ldd   [%l1], %f2		! Load operand 1 into FP reg
  ldd   [%l2], %f4		! Load operand 2 into FP reg

  sll  %i2, 2, %o1		! Calculate the offset

  ! DCTI couple
  jmp  %o0 + %o1		! Jump to fccn2+offset
  ba %ncc, egress 		! After executing the target
				! instruction of 'jmp', go to the
				! end of the routine.


fccn2 :

  fcmpd %fcc0, %f2, %f4

  fcmpd %fcc1, %f2, %f4

  fcmpd %fcc2, %f2, %f4

  fcmpd %fcc3, %f2, %f4


egress :

  stx %fsr, [%l3]
  ldx [%l3], %i0


  ret
  restore
SET_SIZE(fcmpd_fcc)
