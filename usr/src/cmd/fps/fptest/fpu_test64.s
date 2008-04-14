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

! Usage of %ncc
!
! When the branch instructions were modified from Bicc to BPcc format,
! the pseudo-op %ncc was used. This will be converted by the assembler
! to %icc or %xcc depending on whether the compilation is being done
! for 32-bit or 64-bit platforms.


#include<sys/asm_linkage.h>


!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:	        datap_add()	
! Function:	This routine test the data path of the adder for single 
!		precision.
! Calling:	i0 = value
! Returns:	
! Convention:	
!--------------------------------------------------------------------------
!
!		f0 = value
!		f1 = 0
!	add =   f2 = value
!
	.section	".data"
	.align	4

.Ldadd:
	.skip	4
.Ldadd1:
	.skip   4

ENTRY_NP(datap_add)
	save    %sp, -SA(MINFRAME), %sp	! save the stack frame
	setn	.Ldadd,%l6,%l0	! get a memory address
	setn    .Ldadd1,%l6,%l1 ! .. one for the result
	mov     %g0,%l3         ! .. get a zero
	st      %l3, [%l1]      ! .... and store it in memory
	st	%i0, [%l0]	! .... store the value passed 
	ld	[%l0], %f0	! .... put the passed value into f0
	ld	[%l1], %f1	! .... put value 0 into reg f1
	fadds   %f0, %f1, %f2   ! ...... add zero and value into f2
	fcmps	%fcc0, %f0, %f2	! .... check the value passed and added value 
	fbe,a	%fcc0, datap_ok	! .. if they are equal
	nop			! .... delay

	st	%f2, [%l1]	! return the result on error

datap_ok:
	ld	[%l1], %i0	! then return a zero
	ret			! .... delay
	restore
SET_SIZE(datap_add)


!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		
! Function:	
! Calling:	
! Returns:	
! Convention:	
!--------------------------------------------------------------------------
! 
! This routine test the data path of multiplier for single precision
!              f0 = value
!              f1 = 1 
!      mult =  f2 = f0 * f1
!
        .section        ".data"
        .align  4      

.Ldtmlt:
	.skip	4
.Ldtmlt1:
	.skip	4

ENTRY_NP(datap_mult)
	save    %sp, -SA(MINFRAME), %sp
        setn    .Ldtmlt,%l6,%l0
        setn    .Ldtmlt1,%l6,%l1
        setn    0x3F800000,%l6,%l3      ! put value 1 into memory
	st      %l3, [%l1] 
        st      %i0, [%l0]      ! store the value passed into memory location
        ld      [%l0], %f0      ! put the passed value into f0 
        ld      [%l1], %f1      ! put value 1 into reg f1 
        fmuls   %f0, %f1, %f2	! multiply value with 1 , it has to be same
	fcmps   %fcc0, %f0, %f2

	fbne,a	%fcc0, datap_mult_done
	st	%f2, [%l1]	! executed only when the conditional
				! branch is taken as annul bit is set.
				! This branch will be taken under
				! an error condition (%f0 != %f2).
				! Then we need to return the result.

	mov	%g0,%l3
	st	%l3, [%l1]
	
datap_mult_done :
	ld	[%l1], %i0
	ret
	restore
SET_SIZE(datap_mult)


!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		
! Function:	
! Calling:	
! Returns:	
! Convention:	
!--------------------------------------------------------------------------
!
!	This routine tests the data path of the weitek multiplier for 
!	double precision. Single-precision load and store are being
!       used as the input double-precision value is taken as two SP
!       arguments
!
!               f0 = msw value
!		f1 = lsw value
!		f2 = 0
!		f3 = 0
!	add =   f4 = f0 + f2
!
        .section        ".data"
        .align  8       

.Ldtadddp:
	.skip	8
.Ldtadddp1:
	.skip	8
.Ldtadddp2:
	.skip	8
.Lamsw:
	.skip	8
.Lalsw:
	.skip	8

ENTRY_NP(datap_add_dp)
	save    %sp, -SA(MINFRAME), %sp  
        setn    .Ldtadddp,%l6,%l0       
        setn    .Ldtadddp1,%l6,%l1  
	setn	.Ldtadddp2,%l6,%l2
	setn	.Lamsw,%l6,%l4
	setn	.Lalsw,%l6,%l5
	mov	%g0,%l3	! put value 0 into memory      
        st      %l3, [%l1]
	st	%i0, [%l0]	! msw of value
        st	%i1, [%l2]	! lsw of value
	ld	[%l0], %f0	! put the msw into f0
	ld	[%l2], %f1	! put the lsw into f1
	ld	[%l1], %f2	! put 0 into f2
	ld	[%l1], %f3	! put 0 into f3
	faddd   %f0, %f2, %f4	! add value + 0 into f4
	fcmpd   %fcc0, %f0, %f4	! now compare the result

	fbe,a	%fcc0, datap_add_dp_ok	! good
	nop

	mov	0x1,%l3
	st	%l3, [%l1]

datap_add_dp_ok :
	ld	[%l1], %i0
	ret
	restore
	
SET_SIZE(datap_add_dp)

!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		
! Function:	
! Calling:	
! Returns:	
! Convention:	
!--------------------------------------------------------------------------
!
!  This routine tests the data path of the weitek multiplier for 
!  double precision. Single-precision load and store are being
!  used as the input double-precision value is taken as two SP
!  arguments.
!
!              f0 = msw value 
!              f1 = lsw value 
!              f2 = 0
!              f3 = 0
!	mult = f4 = f0 * f2
!
        .section        ".data"
        .align  8       

.Ldtmdp:
	.skip	8
.Ldtmdp1:
	.skip	8
.Ldtmdp2:
	.skip	8
.Lmmsw:
	.skip	8
.Lmlsw:
	.skip	8

ENTRY_NP(datap_mult_dp)
	save    %sp, -SA(MINFRAME), %sp  
        setn    .Ldtmdp,%l6,%l0       
        setn    .Ldtmdp1,%l6,%l1      
        setn    .Ldtmdp2,%l6,%l2      
        setn    .Lmmsw,%l6,%l4
	setn	.Lmlsw,%l6,%l5
        setn    0x3FF00000,%l6,%l3 ! put msw value  of DP 1  into memory      
        st      %l3, [%l1]     
        st      %i0, [%l0]      ! msw of value 
        st      %i1, [%l2]      ! lsw of value 
        ld      [%l0], %f0      ! put the msw into f0  
        ld      [%l2], %f1      ! put the lsw into f1  
        ld      [%l1], %f2      ! put msw of DP 1 into f2
	mov	%g0,%l3
	st	%l3, [%l1]
        ld      [%l1], %f3	! put 0 into f3, i.e f2|f3 = 0x3ff0000000000000 (dp 1) 
	fmuld	%f0, %f2, %f4   ! mult value * 1 into f4
	fcmpd   %fcc0, %f0, %f4	! now compare the result

        fbe,a     %fcc0, datap_mult_dp_ok        ! good
	nop 

        mov     0x1,%l3         
        st      %l3, [%l1]     

datap_mult_dp_ok :
	ld	[%l1], %i0
	ret
	restore
	
SET_SIZE(datap_mult_dp)

!
! for add routine all the f registers from 0 - 19 will be filled with numbers
! and the result should be 10.
!

        .section        ".data"
        .align  4       

.Ltmasp:
	.skip	4
.Ltmasp1:
	.skip	4
.Ltmasp2:
	.skip	4

ENTRY_NP(timing_add_sp)
	save    %sp, -SA(MINFRAME), %sp		! save the registers, stacck
        setn    .Ltmasp,%l6,%l0
	setn	.Ltmasp1,%l6,%l1
	setn	.Ltmasp2,%l6,%l2
	mov	%g0,%l3
	setn    0x3f800000,%l6,%l4 	! put value 1 
	setn	0x41200000,%l6,%l5		! put value 10 into local 5
	st	%l5, [%l0]
	st	%l4, [%l1]
	st	%l3, [%l2]
	ld	[%l0], %f31		! register 31 has 10
	ld	[%l1], %f30		! register 30 has 1

	ld	[%l2], %f0		! reg 0 has 0
	fmovs   %f31, %f1		! reg1 has 10
	fsubs   %f31, %f30, %f18	! reg 18 has 9
	fmovs   %f18, %f3		! reg 3 has 9
	fmovs   %f30, %f2		! reg 2 has 1
	fmovs   %f30, %f19		! reg 19 has 1
	fsubs   %f18, %f19, %f16	! reg 16 has 8
	fmovs   %f16, %f5		! reg 5 has 8
	fsubs   %f31, %f16, %f17	! reg 17 has 2
	fmovs	%f17, %f4		! reg 4 has 2
	fsubs   %f16, %f30, %f14	! reg 14 has 7 
	fmovs   %f14, %f7		! reg 7 has 7
	fsubs   %f31, %f14, %f15	! reg 15 has 3
	fmovs	%f15, %f6		! reg 6 has 3
	fsubs   %f14, %f30, %f12	! reg 12 has 6
	fmovs	%f12, %f9		! reg 9 has 6
	fsubs   %f31, %f12, %f13	! reg 13 has 4
	fmovs	%f13, %f8		! reg 8 has 4
	fsubs   %f12, %f30, %f10	! reg 10 has 5
	fmovs	%f10, %f11		! reg 11 has 5

	fadds	%f0, %f1, %f20		! reg 0 + reg 1 = reg 20 = 10
	fadds   %f2, %f3, %f21		! reg 2 + reg 3 = reg 21 = 10
	fadds   %f4, %f5, %f22		! reg 4 + reg 5 = reg 22 = 10
	fadds   %f6, %f7, %f23		! reg 6 + reg 7 = reg 23 = 10
	fadds   %f8, %f9, %f24		! reg 8 + reg 9 = reg 24 = 10
	fadds   %f10, %f11, %f25	! reg 10 + reg 11 = reg 25 = 10
	fadds   %f12, %f13, %f26	! reg 12 + reg 13 = reg 26 = 10
	fadds   %f14, %f15, %f27	! reg 14 + reg 15 = reg 27 = 10
	fadds   %f16, %f17, %f28	! reg 16 + reg 17 = reg 28 = 10
	fadds   %f18, %f19, %f29	! reg 18 + reg 19 = reg 29 = 10

	!  Now additions are done check it out
	fcmps	%fcc0, %f31, %f20
	fbne,a,pn	%fcc0, done_t_add_sp	! If not equal, go to the end.
	st	%f20, [%l2] 	! Executed only when the conditional
				! branch is taken as annul bit is set.
				! This branch will be taken under
				! an error condition.
	
	! No errors. Move on to the next register

	fcmps	%fcc0, %f31, %f21
	fbne,a,pn	%fcc0, done_t_add_sp
	st	%f21, [%l2]      

        
	fcmps   %fcc0, %f31, %f22
	fbne,a,pn	%fcc0, done_t_add_sp
	st	%f22, [%l2]            

        
	fcmps	%fcc0, %f31, %f23
	fbne,a,pn	%fcc0, done_t_add_sp
        st      %f23, [%l2]             

        
        fcmps   %fcc0, %f31, %f24 
        fbne,a,pn	%fcc0, done_t_add_sp
        st      %f24, [%l2]              

        
        fcmps   %fcc0, %f31, %f25  
        fbne,a,pn	%fcc0, done_t_add_sp   
        st      %f25, [%l2]               

        
        fcmps   %fcc0, %f31, %f26   
        fbne,a,pn	%fcc0, done_t_add_sp    
        st      %f26, [%l2]                
        

        fcmps   %fcc0, %f31, %f27    
        fbne,a,pn	%fcc0, done_t_add_sp     
        st      %f27, [%l2]                 

        
        fcmps   %fcc0, %f31, %f28     
        fbne,a,pn	%fcc0, done_t_add_sp      
        st      %f28, [%l2]                  

        
	! Though this is the last set of compare instructions
	! we cannot fall through as the store needs to be done
	! only when the registers are not equal. That is why
	! we need the unconditional branch with the annul bit set.
        fcmps   %fcc0, %f31, %f29      
        fbne,a,pn	%fcc0, done_t_add_sp
	st	%f29, [%l2]

done_t_add_sp:
	ld	[%l2], %i0
	ret
        restore
SET_SIZE(timing_add_sp)

!
!	for mult routine all the f registers from 0 - 19 will be filled 
!	with numbers and the result should be the number.
!
        .section        ".data"
        .align  4       

.Ltmmsp:
	.skip	4
.Ltmmsp1:
	.skip	4
.Ltmmsp2:
	.skip	4

ENTRY_NP(timing_mult_sp)
	save    %sp, -SA(MINFRAME), %sp           ! save the registers, stacck
        setn    .Ltmmsp,%l6, %l0
        setn    .Ltmmsp1,%l6, %l1
        setn    .Ltmmsp2,%l6, %l2
        mov     %g0, %l3
	setn	0x3f800000,%l6, %l4         ! put value 1 
        setn    0x41200000,%l6, %l5         ! put value 10 into local 5
        st      %l5, [%l0]
        st      %l4, [%l1]
        st      %l3, [%l2]
        ld      [%l0], %f31             ! register 31 has 10
        ld      [%l1], %f1              ! register 1 has 1
	fmovs   %f1, %f3
	fmovs   %f1, %f5
	fmovs   %f1, %f7
	fmovs   %f1, %f9
	fmovs   %f1, %f11	! register 1, 3, 5, 7, 9, 11, 13, 15, 17, 19
	fmovs   %f1, %f13	! has a value of 1
	fmovs   %f1, %f15
	fmovs   %f1, %f17
	fmovs   %f1, %f19	!
	fmovs	%f1, %f0
	fmovs   %f31, %f18	! reg 18 has 10
	fsubs	%f31, %f0, %f16		! reg 16  has 9
	fsubs   %f16, %f0, %f14		! reg 14 has 8
	fsubs   %f14, %f0, %f12		! reg 12 has 7
	fsubs   %f12, %f0, %f10		! reg 10 has 6
	fsubs   %f10, %f0, %f8		! reg 8 has 5
	fsubs   %f8, %f0, %f6		! reg 6 has 4
	fsubs   %f6, %f0, %f4		! reg 4 has 3
	fsubs   %f4, %f0, %f2		! reg 2 has 2

	fmuls   %f0, %f1, %f20          ! reg 0 * reg 1 = reg 20 = 1
        fmuls   %f2, %f3, %f21          ! reg 2 * reg 3 = reg 21 = 2 
        fmuls   %f4, %f5, %f22          ! reg 4 * reg 5 = reg 22 = 3 
        fmuls   %f6, %f7, %f23          ! reg 6 * reg 7 = reg 23 = 4 
        fmuls   %f8, %f9, %f24          ! reg 8 * reg 9 = reg 24 = 5 
        fmuls   %f10, %f11, %f25        ! reg 10 * reg 11 = reg 25 = 6 
        fmuls   %f12, %f13, %f26        ! reg 12 * reg 13 = reg 26 = 7 
        fmuls   %f14, %f15, %f27        ! reg 14 * reg 15 = reg 27 = 8  
        fmuls   %f16, %f17, %f28        ! reg 16 * reg 17 = reg 28 = 9 
        fmuls   %f18, %f19, %f29        ! reg 18 * reg 19 = reg 29 = 10

	fcmps	%fcc0, %f0, %f20
	fbne,a,pn	%fcc0, done_t_mult_sp
	st	%f20, [%l2] 	! Executed only when the conditional
				! branch is taken as annul bit is set.
				! This branch will be taken under
				! an error condition.
	
	! No errors. Move on to the next register
	
	fcmps	%fcc0, %f2, %f21
	fbne,a,pn	%fcc0, done_t_mult_sp
	st	%f21, [%l2]      

	
	fcmps   %fcc0, %f4, %f22
	fbne,a,pn 	%fcc0, done_t_mult_sp
	st	%f22, [%l2]            

	
	fcmps	%fcc0, %f6, %f23
	fbne,a,pn	%fcc0, done_t_mult_sp
        st      %f23, [%l2]             
	

	fcmps	%fcc0, %f8, %f24
	fbne,a,pn	%fcc0, done_t_mult_sp
        st      %f24, [%l2]              
	

	fcmps	%fcc0, %f10, %f25
	fbne,a,pn	%fcc0, done_t_mult_sp
        st      %f25, [%l2]               
	

	fcmps	%fcc0, %f12, %f26
	fbne,a,pn	%fcc0, done_t_mult_sp
        st      %f26, [%l2]                
	

	fcmps	%fcc0, %f14, %f27
	fbne,a,pn	%fcc0, done_t_mult_sp
        st      %f27, [%l2]                 
	

	fcmps	%fcc0, %f16, %f28
	fbne,a,pn	%fcc0, done_t_mult_sp
        st      %f28, [%l2]                  
	

	! Though this is the last set of compare instructions
	! we cannot fall through as the store needs to be done
	! only when the registers are not equal. That is why
	! we need the unconditional branch with the annul bit set.
	fcmps	%fcc0, %f18, %f29
	fbne,a,pn	%fcc0, done_t_mult_sp
	st	%f29, [%l2]

	
done_t_mult_sp:
	ld	[%l2], %i0
	ret
        restore
SET_SIZE(timing_mult_sp)

!
!	same thing for double precision
!
        .section        ".data"
        .align  8       

.Ltmadp:
	.skip	8
.Ltmadp1:
	.skip	8
.Ltmadp2:
	.skip	8

ENTRY_NP(timing_add_dp)
	save    %sp, -SA(MINFRAME), %sp           ! save the registers, stacck
        setn    .Ltmadp,%l6, %l0
        setn    .Ltmadp1,%l6, %l1
        setn    .Ltmadp2,%l6, %l2
        mov     %g0, %l3
	setn	0x3ff0000000000000,%l6, %l4         ! put value 1 
        setn    0x4024000000000000,%l6, %l5         ! put value 10 into local 5
        stx     %l5, [%l0]
        stx     %l4, [%l1]
        stx     %l3, [%l2]
	ldd	[%l0], %f30             ! register 30 has 10
	fmovd   %f30, %f2		! reg 2 has 10
	ldd	[%l2], %f0		! reg 0 has 0
	ldd	[%l1], %f4		! reg 4 has 1
	fsubd	%f30, %f4, %f6		! reg 6 has 9
	fsubd	%f6, %f4, %f10		! reg 10 has 8
	fsubd   %f30, %f10, %f8		! reg 8 has 2
	fsubd	%f10, %f4, %f14		! reg 14 has 7
	fsubd   %f30, %f14, %f12	! reg 12 has 3
	fsubd	%f14, %f4, %f18		! reg 18 has 6
	fsubd	%f30, %f18, %f16	! reg 16 has 4
!
	faddd	%f0, %f2, %f20		! reg 20 has 10
	faddd   %f4, %f6, %f22		! reg 22 has 10
	faddd   %f8, %f10, %f24		! reg 24 has 10
	faddd   %f12, %f14, %f26	! reg 26 has 10
	faddd   %f16, %f18, %f28	! reg 28 has 10
!
	fcmpd	%fcc0, %f30, %f20
	fbne,a,pn	%fcc0, done_t_add_dp
	std	%f20, [%l2]
	
	fcmpd	%fcc0, %f30, %f22
	fbne,a,pn	%fcc0, done_t_add_dp
	std	%f22, [%l2]      
        
	fcmpd   %fcc0, %f30, %f24     
        fbne,a,pn     %fcc0, done_t_add_dp
        std      %f24, [%l2]            
        
        fcmpd   %fcc0, %f30, %f26     
        fbne,a,pn     %fcc0, done_t_add_dp    
        std      %f26, [%l2]            
        
	! Though this is the last set of compare instructions
	! we cannot fall through as the store needs to be done
	! only when the registers are not equal. That is why
	! we need the unconditional branch with the annul bit set.
	fcmpd	%fcc0, %f30, %f28
	fbne,a	%fcc0, done_t_add_dp	
	std	%f28, [%l2]   

done_t_add_dp:
	ldx	[%l2], %i0
	
	ret
	restore
SET_SIZE(timing_add_dp)

				
!	Now for mult
!
        .section        ".data"
        .align  8       

.Ltmmdp:
	.skip	8
.Ltmmdp1:
	.skip	8
.Ltmmdp2:
	.skip	8

ENTRY_NP(timing_mult_dp)
	save    %sp, -SA(MINFRAME), %sp           ! save the registers, stacck
        setn    .Ltmmdp,%l6, %l0
        setn    .Ltmmdp1,%l6, %l1
        setn    .Ltmmdp2,%l6, %l2
        mov     %g0, %l3
        setn    0x3ff0000000000000,%l6, %l4         ! put value 1 
        setn    0x4034000000000000,%l6, %l5         ! put value 20 into local 5
        stx      %l5, [%l0]
        stx      %l4, [%l1]
        stx      %l3, [%l2]
	ldd      [%l0], %f30             ! register 30 has 20
	ldd	[%l1], %f2		! register  2 has 1
	fmovd   %f30, %f0		! register  0 has 20
	faddd	%f2, %f2, %f10		! register 10 has 2
	fmovd   %f10, %f16		! register 16 has 2
	faddd	%f10, %f16, %f4		! register 4 has 4
	faddd   %f4, %f2, %f6		! register 6 has 5
	fmovd	%f6, %f12		! reg. 12 has 5
	fmovd	%f4, %f14		! reg 14 has 4
	faddd	%f12, %f6, %f18		! reg 18 has 10
	fmovd	%f18, %f8		! reg 8 has 10
!
! 	now everything is set
!
	fmuld   %f0, %f2, %f20          ! reg 20 has 20	
	fmuld	%f4, %f6, %f22          ! reg 22 has 20
	fmuld	%f8, %f10, %f24         ! reg 24 has 20
	fmuld	%f12, %f14, %f26        ! reg 26 has 20
	fmuld	%f16, %f18, %f28        ! reg 28 has 20
!
	fcmpd   %fcc0, %f30, %f20
	fbne,a,pn	%fcc0, done_t_mult_dp
        std      %f20, [%l2]
        
	fcmpd   %fcc0, %f30, %f22
        fbne,a,pn     %fcc0, done_t_mult_dp
        std      %f22, [%l2]      
        
	fcmpd   %fcc0, %f30, %f24     
        fbne,a,pn     %fcc0, done_t_mult_dp
        std      %f24, [%l2]            
        
        fcmpd   %fcc0, %f30, %f26     
        fbne,a,pn     %fcc0, done_t_mult_dp    
        std      %f26, [%l2]            
        
	! Though this is the last set of compare instructions
	! we cannot fall through as the store needs to be done
	! only when the registers are not equal. That is why
	! we need the unconditional branch with the annul bit set.
        fcmpd   %fcc0, %f30, %f28
        fbne,a     %fcc0, done_t_mult_dp
        std      %f28, [%l2]   
	
done_t_mult_dp:
	ldx	[%l2], %i0
	
	ret
	restore
SET_SIZE(timing_mult_dp)

	
!--------------------------------------------------------------------------
! The following routines are for testing the IEEE754 exception fields
! of the FSR (cexc, aexc)
!	The input is : i0 = amsw
!		       i1 = bmsw or alsw (for double precision)
!	  	       i2 = bmsw (for dp)
!		       i3 = blsw (for dp)
!
!	The output is  i0 = value of FSR register
!

        .section        ".data"
        .align  8       

.Lwadds:
	.word 	0
.Lwadds1:
	.word 	0
.Lwadds2:
	.xword	0    ! For the FSR contents


ENTRY_NP(wadd_sp)
	save    %sp, -SA(MINFRAME), %sp
        setn    .Lwadds,%l6, %l0
        setn    .Lwadds1,%l6, %l1
	setn	.Lwadds2,%l6, %l2	

	st	%i0, [%l0]		! get the first value
	st	%i1, [%l1]		! get the second value
	ld	[%l0], %f0		! f0 has the first value
	ld 	[%l1], %f2		! f2 has the second value

	fadds   %f0, %f2, %f3		! now do the instruction
	stx	%fsr, [%l2]		! get the fsr value

	ldx     [%l2], %i0
	ret
	restore
SET_SIZE(wadd_sp)


!
!	same thing for add double precision
!
        .section        ".data"
        .align  8       

.Ladddp:
	.word	0
.Ladddp1:
	.word	0
.Ladddp2:
	.xword	0    ! For the FSR contents

ENTRY_NP(wadd_dp)
	save    %sp, -SA(MINFRAME), %sp
        setn    .Ladddp,%l6, %l0
        setn    .Ladddp1,%l6, %l1
        setn    .Ladddp2,%l6, %l2 

	st	%i0, [%l0]              ! get the first value
        st      %i1, [%l1]              ! get the lsw of first value
	ld	[%l0], %f0
	ld	[%l1], %f1
	st      %i2, [%l0]              ! get the second value
	st      %i3, [%l1]              ! get the lsw of second value
	ld	[%l0], %f2
	ld	[%l1], %f3

	faddd	%f0, %f2, %f4		! now do the instruction
        stx      %fsr, [%l2]             ! get the fsr value 

	ldx     [%l2], %i0
	ret
	restore
	
SET_SIZE(wadd_dp)


!
!
!	for divide single precision
!
        .section        ".data"
        .align  8       

.Ldvsp:
	.word	0
.Ldvsp1:
	.word	0
.Ldvsp2:
	.xword	0    ! For the FSR contents

ENTRY_NP(wdiv_sp)
	save    %sp, -SA(MINFRAME), %sp
        setn    .Ldvsp,%l6, %l0
        setn    .Ldvsp1,%l6, %l1
        setn    .Ldvsp2,%l6, %l2        

        st      %i0, [%l0]              ! get the first value
        st      %i1, [%l1]              ! get the second value
        ld      [%l0], %f0              ! f0 has the first value
        ld      [%l1], %f2              ! f2 has the second value 

        fdivs	%f0, %f2, %f3           ! now do the instruction
        stx      %fsr, [%l2]             ! get the fsr value 

	ldx     [%l2], %i0
	ret
	restore
	
SET_SIZE(wdiv_sp)


!
!
!	for divide double precision
!
        .section        ".data"
        .align  8       

.Ldvdp:
	.word	0
.Ldvdp1:
	.word	0
.Ldvdp2:
	.xword	0    ! For the FSR contents

ENTRY_NP(wdiv_dp)
	save    %sp, -SA(MINFRAME), %sp  
        setn    .Ldvdp,%l6, %l0       
        setn    .Ldvdp1,%l6, %l1      
        setn    .Ldvdp2,%l6, %l2      

        st      %i0, [%l0]              ! get the first value  
        st      %i1, [%l1]              ! get the lsw of first value   
        ld      [%l0], %f0     
        ld      [%l1], %f1     
        st      %i2, [%l0]              ! get the second value 
        st      %i3, [%l1]              ! get the lsw of second value  
        ld      [%l0], %f2     
        ld      [%l1], %f3     

        fdivd	%f0, %f2, %f4           ! now do the instruction       
        stx      %fsr, [%l2]             ! get the fsr value    

	ldx     [%l2], %i0
	ret
	restore
	
SET_SIZE(wdiv_dp)


!
!
!       for multiply single precision   
!
        .section        ".data"
        .align  8       

.Lmltsp:
	.word	0
.Lmltsp1:
	.word	0
.Lmltsp2:
	.xword	0    ! For the FSR contents

ENTRY_NP(wmult_sp)
	save    %sp, -SA(MINFRAME), %sp 
        setn    .Lmltsp,%l6, %l0 
        setn    .Lmltsp1,%l6, %l1 
        setn    .Lmltsp2,%l6, %l2         

        st      %i0, [%l0]              ! get the first value 
        st      %i1, [%l1]              ! get the second value 
        ld      [%l0], %f0              ! f0 has the first value 
        ld      [%l1], %f2              ! f2 has the second value  

        fmuls   %f0, %f2, %f3           ! now do the instruction
        stx      %fsr, [%l2]             ! get the fsr value  

	ldx     [%l2], %i0
	ret
	restore
	
SET_SIZE(wmult_sp)


! 
! 
!       for multiply double precision 
! 
        .section        ".data"
        .align  8       

.Lmltdp:
	.word	0
.Lmltdp1:
	.word	0
.Lmltdp2:
	.xword	0    ! For the FSR contents

ENTRY_NP(wmult_dp)
        save    %sp, -SA(MINFRAME), %sp   
        setn    .Lmltdp,%l6, %l0        
        setn    .Lmltdp1,%l6, %l1       
        setn    .Lmltdp2,%l6, %l2       

        st      %i0, [%l0]		! get the first value   
        st      %i1, [%l1]		! get the lsw of first value    
        ld      [%l0], %f0      
        ld      [%l1], %f1      
        st      %i2, [%l0]		! get the second value  
        st      %i3, [%l1]		! get the lsw of second value   
        ld      [%l0], %f2      
        ld      [%l1], %f3      

        fmuld	 %f0, %f2, %f4		! now do the instruction         
        stx      %fsr, [%l2]		! get the fsr value    

	ldx     [%l2], %i0
	ret
	restore
	
SET_SIZE(wmult_dp)


! 
! 
!       for square-root single precision 
! 
        .section        ".data"
        .align  4
.Lsqsp_opr:
		.word	0

        .align  8
.Lsqsp_fsr:
		.xword	0	! For the FSR contents

ENTRY_NP(wsqrt_sp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack
	setn	.Lsqsp_opr,%l6,%l0	! .. get the address of temp2
	setn	.Lsqsp_fsr,%l6,%l2	! .. and temp

	st	%i0, [%l0]	! .. get the callers value
	ld	[%l0], %f0	! .. into the float register

	fsqrts  %f0, %f2	! .... have the fpu perform the operation
        stx     %fsr, [%l2]		! get the fsr value    

	ldx     [%l2], %i0
	ret
	restore
	
SET_SIZE(wsqrt_sp)


! 
! 
!       for square-root double precision 
! 
        .section        ".data"
        .align  8
.Lsqdp_opr:
		.xword	0
.Lsqdp_fsr:
		.xword	0	! For the FSR contents

ENTRY_NP(wsqrt_dp)
	save	%sp, -SA(MINFRAME), %sp	! save the registers, stack 
	setn	.Lsqdp_opr,%l6,%l0 	! .. get the address of temp2
	setn	.Lsqdp_fsr,%l6,%l2 	! .. and temp

	stx	%i0, [%l0] 	! .. get the callers value
	ldd	[%l0], %f0 	! .. into a float register

	fsqrtd  %f0, %f2	! .... have the fpu perform the operation
        stx     %fsr, [%l2]	! get the fsr value    

	ldx     [%l2], %i0
	ret
	restore
	
SET_SIZE(wsqrt_dp)


!
!	
!	Chaining test.
!	 
        .section        ".data"
        .align  8       

.Lchsp:
	.word	0
.Lchsp1:
	.word	0

ENTRY_NP(chain_sp)
	save    %sp, -SA(MINFRAME), %sp
        setn    .Lchsp,%l6, %l0
        setn    .Lchsp1,%l6, %l1
	st	%i0, [%l0]	! store the value
	ld	[%l0], %f0
	fitos   %f0, %f2	! convert integer into single
	fmovs   %f2, %f0	! f0 has the same value  x
	fadds	%f0, %f2, %f4   ! f4 will have 2x
	fsubs   %f4, %f0, %f6   ! f6 will have x
	fmuls   %f6, %f4, %f8   ! f8 will have (2x * x)
	fdivs   %f8, %f4, %f10  ! f10 will have (2x * x) / 2x = x
	fstoi	%f10, %f12

	st	%f12, [%l1]
	ld	[%l1], %i0

	ret
        restore
SET_SIZE(chain_sp)


!
!
        .section        ".data"
        .align  8       

.Lchdp:
	.word	0
.Lchdp1:
	.word	0

ENTRY_NP(chain_dp)
	save    %sp, -SA(MINFRAME), %sp
        setn    .Lchdp,%l6, %l0
        setn    .Lchdp1,%l6, %l1
        st      %i0, [%l0]      ! store the value
        ld      [%l0], %f0
        fitod   %f0, %f2        ! convert integer into double
	fmovs   %f2, %f0        ! f0 has the same value  x
        faddd   %f0, %f2, %f4   ! f4 will have 2x
        fsubd   %f4, %f0, %f6   ! f6 will have x
        fmuld   %f6, %f4, %f8   ! f8 will have (2x * x)
        fdivd   %f8, %f4, %f10  ! f10 will have (2x * x) / 2x = x
        fdtoi   %f10, %f12

	st	%f12, [%l1]
	ld	[%l1], %i0

	ret
        restore
SET_SIZE(chain_dp)


!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		Initialize all SP Registers
! Function:	Loads the callers value into all SP floating point registers.
! Calling:	in0 = Value
! Returns:	All float register = Value
! Convention:	init_regs(val);
! Method:	Copys the user value into each fp reg in sequence.
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8       

.Lclrg:
	.skip	8

ENTRY_NP(init_regs)
	save    %sp, -SA(MINFRAME), %sp	! save the registers, stack
        setn    .Lclrg,%l6,%l0	! load the address of temp2 in local0
	st	%i0, [%l0]	! load the value in temp2 via local0
	ld	[%l0], %f0	! .. load the value
	ld	[%l0], %f1	! .. load the value
        ld      [%l0], %f2	! .. load the value
        ld      [%l0], %f3	! .. load the value
        ld      [%l0], %f4	! .. load the value
	ld	[%l0], %f5	! .. load the value
        ld      [%l0], %f6 	! .. load the value
        ld      [%l0], %f7 	! .. load the value
        ld      [%l0], %f8 	! .. load the value
        ld      [%l0], %f9 	! .. load the value
        ld      [%l0], %f10 	! .. load the value
        ld      [%l0], %f11 	! .. load the value
        ld      [%l0], %f12 	! .. load the value
        ld      [%l0], %f13 	! .. load the value
        ld      [%l0], %f14 	! .. load the value
        ld      [%l0], %f15 	! .. load the value
        ld      [%l0], %f16 	! .. load the value
        ld      [%l0], %f17 	! .. load the value
        ld      [%l0], %f18 	! .. load the value
        ld      [%l0], %f19 	! .. load the value
        ld      [%l0], %f20 	! .. load the value
        ld      [%l0], %f21 	! .. load the value
        ld      [%l0], %f22 	! .. load the value
        ld      [%l0], %f23 	! .. load the value
        ld      [%l0], %f24 	! .. load the value
        ld      [%l0], %f25 	! .. load the value
        ld      [%l0], %f26 	! .. load the value
        ld      [%l0], %f27 	! .. load the value
        ld      [%l0], %f28 	! .. load the value
        ld      [%l0], %f29 	! .. load the value
        ld      [%l0], %f30 	! .. load the value
        ld      [%l0], %f31	! .. load the value
	ret
        restore
SET_SIZE(init_regs)



!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		Initialize all double precision Registers
! Function:	Loads the callers value into all floating point registers.
! Calling:	in0 = Value
! Returns:	All float register = Value
! Convention:	init_regs_dp(val);
! Method:	Copys the user value into each fp reg in sequence.
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8       

.Lclrg_dp:
	.skip	16

ENTRY_NP(init_regs_dp)
	save    %sp, -SA(MINFRAME), %sp	
								! save the registers, stack
        setx    .Lclrg_dp,%l6,%l0	! load the address of temp2 in local0
	stx	%i0, [%l0]		! load the value in temp2 via local0
	ldd	[%l0], %f0		! .. load the value
	ldd	[%l0], %f2		! .. load the value
        ldd     [%l0], %f4		! .. load the value
        ldd     [%l0], %f6		! .. load the value
        ldd     [%l0], %f8		! .. load the value
	ldd	[%l0], %f10		! .. load the value
        ldd     [%l0], %f12		! .. load the value
        ldd     [%l0], %f14		! .. load the value
        ldd     [%l0], %f16		! .. load the value
        ldd     [%l0], %f18		! .. load the value
        ldd     [%l0], %f20 	! .. load the value
        ldd     [%l0], %f22 	! .. load the value
        ldd     [%l0], %f24 	! .. load the value
        ldd     [%l0], %f26 	! .. load the value
        ldd     [%l0], %f28 	! .. load the value
        ldd     [%l0], %f30 	! .. load the value
        ldd     [%l0], %f32 	! .. load the value
        ldd     [%l0], %f34 	! .. load the value
        ldd     [%l0], %f36 	! .. load the value
        ldd     [%l0], %f38 	! .. load the value
        ldd     [%l0], %f40 	! .. load the value
        ldd     [%l0], %f42 	! .. load the value
        ldd     [%l0], %f44 	! .. load the value
        ldd     [%l0], %f46 	! .. load the value
        ldd     [%l0], %f48 	! .. load the value
        ldd     [%l0], %f50 	! .. load the value
        ldd     [%l0], %f52 	! .. load the value
        ldd     [%l0], %f54 	! .. load the value
        ldd     [%l0], %f56 	! .. load the value
        ldd     [%l0], %f58 	! .. load the value
        ldd     [%l0], %f60 	! .. load the value
        ldd     [%l0], %f62		! .. load the value
	ret
        restore
SET_SIZE(init_regs_dp)



!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		
! Function:	
! Calling:	
! Returns:	
! Convention:	
!--------------------------------------------------------------------------

        .section        ".data"
        .align  4

.Lrgtst1:
	.skip	4
.Lrgtst2:
	.skip	4

ENTRY_NP(register_test)
	save    %sp, -SA(MINFRAME), %sp

	setn	.Lrgtst1,%l6,%l1
	setn	.Lrgtst2,%l6,%l2


	setn	regTable, %l6, %o0
	mulx	%i0, 12, %o1		! Table entries are 12 bytes each.

	! Jump to the appropriate set of instructions
	jmp	%o0+%o1
	st	%i1,  [%l1]		! save the pattern to be written


! If the number of instructions in this macro are changed,
! please ensure that the second operand for the mulx above
! is also updated. We can calculate this during run-time but
! that will mean extra instructions and time.
#define	TEST_REG(reg_num)		\
	ld	[%l1], %f/**/reg_num;	\
	ba	%ncc, reg_done;		\
	st	%f/**/reg_num, [%l2]

regTable :

	TEST_REG(0)
	TEST_REG(1)
	TEST_REG(2)
	TEST_REG(3)
	TEST_REG(4)
	TEST_REG(5)
	TEST_REG(6)
	TEST_REG(7)
	TEST_REG(8)
	TEST_REG(9)
	TEST_REG(10)
	TEST_REG(11)
	TEST_REG(12)
	TEST_REG(13)
	TEST_REG(14)
	TEST_REG(15)
	TEST_REG(16)
	TEST_REG(17)
	TEST_REG(18)
	TEST_REG(19)
	TEST_REG(20)
	TEST_REG(21)
	TEST_REG(22)
	TEST_REG(23)
	TEST_REG(24)
	TEST_REG(25)
	TEST_REG(26)
	TEST_REG(27)
	TEST_REG(28)
	TEST_REG(29)
	TEST_REG(30)

	! No need for a branch here as this the last entry in
	! the table and the label is will be reached by falling
	! through.
	ld	[%l1], %f31
	st	%f31, [%l2]

reg_done:
	ld	[%l2], %i0

	ret
	restore
SET_SIZE(register_test)


!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		
! Function:	
! Calling:	
! Returns:	
! Convention:	
!--------------------------------------------------------------------------
    	.section        ".data"
	.align  8       

.Lrgtst1_dp:
	.skip	8
.Lrgtst2_dp:
	.skip	8

ENTRY_NP(register_test_dp)
	save    %sp, -SA(MINFRAME), %sp

	setx	.Lrgtst1_dp,%l6,%l1
	setx	.Lrgtst2_dp,%l6,%l2

	setn	regTable_dp, %l6, %o0
	mulx	%i0, 6, %o1	! Registers are 64-bit and hence the
				! register numbers given will be even.
				! Each table entry is 12 bytes. 
				! Multiplying the even register number
				! by 6 will give the correct offset.


	! Jump to the appropriate set of instructions
	jmp	%o0+%o1
	stx	%i1,  [%l1]		!save the pattern to be written

! If the number of instructions in this macro are changed,
! please ensure that the second operand for the mulx above
! is also updated. We can calculate this during run-time but
! that will mean extra instructions and time.
#define TEST_REG_DP(reg_num)		\
	ldd	[%l1], %f/**/reg_num;	\
	ba	%ncc, reg_done_dp;	\
	std	%f/**/reg_num, [%l2]

regTable_dp :

	TEST_REG_DP(0)
	TEST_REG_DP(2)
	TEST_REG_DP(4)
	TEST_REG_DP(6)
	TEST_REG_DP(8)
	TEST_REG_DP(10)
	TEST_REG_DP(12)
	TEST_REG_DP(14)
	TEST_REG_DP(16)
	TEST_REG_DP(18)
	TEST_REG_DP(20)
	TEST_REG_DP(22)
	TEST_REG_DP(24)
	TEST_REG_DP(26)
	TEST_REG_DP(28)
	TEST_REG_DP(30)
	TEST_REG_DP(32)
	TEST_REG_DP(34)
	TEST_REG_DP(36)
	TEST_REG_DP(38)
	TEST_REG_DP(40)
	TEST_REG_DP(42)
	TEST_REG_DP(44)
	TEST_REG_DP(46)
	TEST_REG_DP(48)
	TEST_REG_DP(50)
	TEST_REG_DP(52)
	TEST_REG_DP(54)
	TEST_REG_DP(56)
	TEST_REG_DP(58)
	TEST_REG_DP(60)

	! No need for a branch here as this the last entry in
	! the table and the label is will be reached by falling
	! through.
	ldd	[%l1], %f62
	std	%f62, [%l2]

reg_done_dp:
	ldx	[%l2], %i0

	ret
	restore
SET_SIZE(register_test_dp)



!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		Move Registers
! Function:	Move a value thru the float registers
! Calling:	in0 = value
! Returns:	in0 = result 
! Convention:	if (result != move_regs(value)) 
!                   error(result-value);
!--------------------------------------------------------------------------
        .section        ".data"
        .align  4

.Lmvrg:
	.skip	4
.Lmvrg1:
	.skip 	4

ENTRY_NP(move_regs)
	save    %sp, -SA(MINFRAME), %sp	! save the registers, stack
        setn    .Lmvrg1,%l6,%l0	! get the address to temp2
        setn    .Lmvrg,%l6,%l1	! .. and temp
        st      %i0, [%l0]	! get the callers value
        ld      [%l0], %f0	! .. into a float register
	fmovs   %f0, %f1	! copy from 1 register to the next
	fmovs   %f1, %f2	! .. to the next
	fmovs   %f2, %f3	! .. to the next
	fmovs   %f3, %f4	! .. to the next
	fmovs   %f4, %f5	! .. to the next
	fmovs   %f5, %f6	! .. to the next
	fmovs   %f6, %f7	! .. to the next
	fmovs   %f7, %f8	! .. to the next
	fmovs   %f8, %f9	! .. to the next
	fmovs   %f9, %f10	! .. to the next
	fmovs   %f10, %f11	! .. to the next
	fmovs   %f11, %f12	! .. to the next
	fmovs   %f12, %f13	! .. to the next
	fmovs   %f13, %f14	! .. to the next
	fmovs   %f14, %f15	! .. to the next
	fmovs   %f15, %f16	! .. to the next
	fmovs   %f16, %f17	! .. to the next
	fmovs   %f17, %f18	! .. to the next
	fmovs   %f18, %f19	! .. to the next
	fmovs   %f19, %f20	! .. to the next
	fmovs   %f20, %f21	! .. to the next
	fmovs   %f21, %f22	! .. to the next
	fmovs   %f22, %f23	! .. to the next
	fmovs   %f23, %f24	! .. to the next
	fmovs   %f24, %f25	! .. to the next
	fmovs   %f25, %f26	! .. to the next
	fmovs   %f26, %f27	! .. to the next
	fmovs   %f27, %f28	! .. to the next
	fmovs   %f28, %f29	! .. to the next
	fmovs   %f29, %f30	! .. to the next
	fmovs   %f30, %f31	! .. to the next
	st	%f31, [%l1]	! .... save the result
	ld	[%l1], %i0	! .. and return it to the caller
	ret
        restore
SET_SIZE(move_regs)



!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		Move Registers Double Precision
! Function:	Move a value thru the float registers
! Calling:	in0 = value
! Returns:	in0 = result 
! Convention:	if (result != move_regs_dp(value)) 
!                   error(result-value);
!--------------------------------------------------------------------------
        .section        ".data"
        .align  8       

.Lmvrg_dp:
	.skip	8
.Lmvrg1_dp:
	.skip 	8

ENTRY_NP(move_regs_dp)
    	save    %sp, -SA(MINFRAME), %sp	! save the registers, stack
    	setx    .Lmvrg1_dp,%l6,%l0	! get the address to temp2
    	setx    .Lmvrg_dp,%l6,%l1	! .. and temp
    	stx     %i0, [%l0]	! get the callers value
    	ldd     [%l0], %f0	! .. into a float register
    	fmovd   %f0, %f2	! copy from 1 register to the next
	fmovd   %f2, %f4	! .. to the next
	fmovd   %f4, %f6	! .. to the next
	fmovd   %f6, %f8	! .. to the next
	fmovd   %f8, %f10	! .. to the next
	fmovd   %f10, %f12	! .. to the next
	fmovd   %f12, %f14	! .. to the next
	fmovd   %f14, %f16	! .. to the next
	fmovd   %f16, %f18	! .. to the next
	fmovd   %f18, %f20	! .. to the next
	fmovd   %f20, %f22	! .. to the next
	fmovd   %f22, %f24	! .. to the next
	fmovd   %f24, %f26	! .. to the next
	fmovd   %f26, %f28	! .. to the next
	fmovd   %f28, %f30	! .. to the next
	fmovd   %f30, %f32	! .. to the next
	fmovd   %f32, %f34	! .. to the next
	fmovd   %f34, %f36	! .. to the next
	fmovd   %f36, %f38	! .. to the next
	fmovd   %f38, %f40	! .. to the next
	fmovd   %f40, %f42	! .. to the next
	fmovd   %f42, %f44	! .. to the next
	fmovd   %f44, %f46	! .. to the next
	fmovd   %f46, %f48	! .. to the next
	fmovd   %f48, %f50	! .. to the next
	fmovd   %f50, %f52	! .. to the next
	fmovd   %f52, %f54	! .. to the next
	fmovd   %f54, %f56	! .. to the next
	fmovd   %f56, %f58	! .. to the next
	fmovd   %f58, %f60	! .. to the next
	fmovd   %f60, %f62	! .. to the next
	std		%f62, [%l1]	! .... save the result
	ldx		[%l1], %i0	! .. and return it to the caller
	ret
    restore
SET_SIZE(move_regs_dp)



!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
! Name:		
! Function:	
! Calling:	
! Returns:	
! Convention:	
!--------------------------------------------------------------------------
!
! 	The following routine checks the branching is done accordingly
!	to the ficc bits.
!	input	%i0 = 0 = branch unordered
!		      1 = branch greater
!		      2 = branch unordered or greater
!		      3 = branch less
!		      4 = branch unordered or less
!		      5 = branch less or greater
!		      6 = branch not equal
!		      7 = branch equal
!		      8 = branch unordered or equal
!		    . 9 = branch greater or equal
!		     10 = branch branch unordered or greater or equal
!		     11 = branch less or equal
!		     12 = branch unordered or or less or equal
!		     13 = branch ordered
!		     14 = branch always
!		     15 = branch never
!
!	ouput : %i0 = 0 = good
!		    = 1 = error
!

        .section        ".data"
        .align  8       

.Lbr:
	.skip	8
.Lbr1:
	.skip	8

ENTRY_NP(branches)
	save    %sp, -SA(MINFRAME), %sp           ! save the registers, stacck
        setn    .Lbr1,%l6,%l1
        setn    .Lbr,%l6,%l2
        st      %i1, [%l1]
	st	%i2, [%l2]
	ld      [%l1], %f0
        ld      [%l2], %f2

	setn	brn_0, %l6, %o0
	mulx	%i0, 12, %o1


	jmp	%o0+%o1
	fcmps	%fcc0, %f0, %f2		! compare the values  to get ficc
!	
!				branch unordered
brn_0:
	fbu,a	%fcc0, br_good
	nop
	ba,a	%ncc, br_error
	
!				branch greater
brn_1:
	fbg,a	%fcc0, br_good
	nop
	ba,a	%ncc, br_error
	
!				branch unordered or greater
brn_2:
	fbug,a	%fcc0, br_good
	nop
	ba,a	%ncc, br_error
	
!				branch less
brn_3:
	fbl,a	%fcc0, br_good
	nop
	ba,a	%ncc, br_error
	
!				branch unorderd or less
brn_4:
	fbul,a	%fcc0, br_good
	nop
	ba,a	%ncc, br_error
	
!				branch less or greater
brn_5:
	fblg,a	%fcc0, br_good
	nop
	ba,a	%ncc, br_error
	
!				branch not equal
brn_6:
	fbne,a	%fcc0, br_good	
	nop
	ba,a	%ncc, br_error
	
!                               branch equal
brn_7:
	fbe,a	%fcc0, br_good  
        nop 
	ba,a	%ncc, br_error
	
!                               branch unordered or equal
brn_8:
	fbue,a	%fcc0, br_good   
        nop  
	ba,a	%ncc, br_error
	
!                               branch greater or equal
brn_9:
	fbge,a	%fcc0, br_good    
        nop   
	ba,a	%ncc, br_error
	
!                               branch unordered or greater or equal
brn_10:
	fbuge,a	%fcc0, br_good     
        nop    
	ba,a	%ncc, br_error
	
!                               branch less or equal
brn_11:
	fble,a	%fcc0, br_good      
        nop     
	ba,a	%ncc, br_error
	
!                               branch unordered or less or equal
brn_12:
	fbule,a	%fcc0, br_good       
        nop      
	ba,a	%ncc, br_error
	
!                               branch ordered
brn_13:
	fbo,a	%fcc0, br_good
	nop
	ba,a	%ncc, br_error
	
!				branch always
brn_14:
	fba,a	%fcc0, br_good
	nop
	ba,a	%ncc, br_error
	
!				branch never
brn_15:
	fbn,a	%fcc0, br_error	
	nop

br_good:
	mov	%g0, %i0	! Branch worked as expected

	ret
	restore	
        
br_error:
	mov	0xff, %i0	! set the flag that it is error
 
        ret
        restore	
SET_SIZE(branches)


!void read_fpreg(pf, n)
!       FPU_REGS_TYPE   *pf;    /* Old freg value. */
!       unsigned        n;      /* Want to read register n. */
!
!{
!       *pf = %f[n];
!}

ENTRY_NP(read_fpreg)
	save    %sp, -SA(MINFRAME), %sp
        mulx    %i1, 12, %i1            ! Table entries are 12 bytes each.
        setn    stable, %l1, %g1        ! g1 gets base of table.
        jmp     %g1 + %i1               ! Jump into table
        nop                             ! Can't follow CTI by CTI.

#define STOREFP(n) st %f/**/n, [%i0]; ret; restore

stable:
	STOREFP(0)
	STOREFP(1)
	STOREFP(2)
	STOREFP(3)
	STOREFP(4)
	STOREFP(5)
	STOREFP(6)
	STOREFP(7)
	STOREFP(8)
	STOREFP(9)
	STOREFP(10)
	STOREFP(11)
	STOREFP(12)
	STOREFP(13)
	STOREFP(14)
	STOREFP(15)
	STOREFP(16)
	STOREFP(17)
	STOREFP(18)
	STOREFP(19)
	STOREFP(20)
	STOREFP(21)
	STOREFP(22)
	STOREFP(23)
	STOREFP(24)
	STOREFP(25)
	STOREFP(26)
	STOREFP(27)
	STOREFP(28)
	STOREFP(29)
	STOREFP(30)
	STOREFP(31)
SET_SIZE(read_fpreg)


ENTRY_NP(read_fpreg_dp)
	save    %sp, -SA(MINFRAME), %sp
        mulx    %i1, 6, %i1             ! Table entries are 12 bytes each.
										! But o1 will have even numbered 
										! index
        setn    stable_dp, %l0, %g1			! g1 gets base of table.
        jmp     %g1 + %i1               ! Jump into table
        nop                             ! Can't follow CTI by CTI.

#define STOREFP_DP(n) std %f/**/n, [%i0]; ret; restore

stable_dp:
	STOREFP_DP(0)
	STOREFP_DP(2)
	STOREFP_DP(4)
	STOREFP_DP(6)
	STOREFP_DP(8)
	STOREFP_DP(10)
	STOREFP_DP(12)
	STOREFP_DP(14)
	STOREFP_DP(16)
	STOREFP_DP(18)
	STOREFP_DP(20)
	STOREFP_DP(22)
	STOREFP_DP(24)
	STOREFP_DP(26)
	STOREFP_DP(28)
	STOREFP_DP(30)
	STOREFP_DP(32)
	STOREFP_DP(34)
	STOREFP_DP(36)
	STOREFP_DP(38)
	STOREFP_DP(40)
	STOREFP_DP(42)
	STOREFP_DP(44)
	STOREFP_DP(46)
	STOREFP_DP(48)
	STOREFP_DP(50)
	STOREFP_DP(52)
	STOREFP_DP(54)
	STOREFP_DP(56)
	STOREFP_DP(58)
	STOREFP_DP(60)
	STOREFP_DP(62)

SET_SIZE(read_fpreg_dp)

!
!void
!write_fpreg(pf, n)
!       FPU_REGS_TYPE   *pf;    /* New freg value. */
!       unsigned        n;      /* Want to read register n. */
!
!{
!       %f[n] = *pf;
!}
          
ENTRY_NP(write_fpreg)
        sll     %o1, 3, %o1             ! Table entries are 8 bytes each.
        setn     ltable, %l0,  %g1       ! g1 gets base of table.
        jmp     %g1 + %o1               ! Jump into table
        nop                             ! Can't follow CTI by CTI.


#define LOADFP(n) jmp %o7+8 ; ld [%o0],%f/**/n

ltable:
	LOADFP(0)
	LOADFP(1)
	LOADFP(2)
	LOADFP(3)
	LOADFP(4)
	LOADFP(5)
	LOADFP(6)
	LOADFP(7)
	LOADFP(8)
	LOADFP(9)
	LOADFP(10)
	LOADFP(11)
	LOADFP(12)
	LOADFP(13)
	LOADFP(14)
	LOADFP(15)
	LOADFP(16)
	LOADFP(17)
	LOADFP(18)
	LOADFP(19)
	LOADFP(20)
	LOADFP(21)
	LOADFP(22)
	LOADFP(23)
	LOADFP(24)
	LOADFP(25)
	LOADFP(26)
	LOADFP(27)
	LOADFP(28)
	LOADFP(29)
	LOADFP(30)
	LOADFP(31)
SET_SIZE(write_fpreg)
