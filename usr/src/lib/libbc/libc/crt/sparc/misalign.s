!	.text
!	.asciz ident	"%Z%%M%	%I%	%E% SMI"
!	.align	4
!	.seg	"text"

!	 Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
!	 Use is subject to license terms.
!	
!	 CDDL HEADER START
!	
!	 The contents of this file are subject to the terms of the
!	 Common Development and Distribution License, Version 1.0 only
!	 (the "License").  You may not use this file except in compliance
!	 with the License.
!	
!	 You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
!	 or http://www.opensolaris.org/os/licensing.
!	 See the License for the specific language governing permissions
!	 and limitations under the License.
!	
!	 When distributing Covered Code, include this CDDL HEADER in each
!	 file and include the License file at usr/src/OPENSOLARIS.LICENSE.
!	 If applicable, add the following below this CDDL HEADER, with the
!	 fields enclosed by brackets "[]" replaced with your own identifying
!	 information: Portions Copyright [yyyy] [name of copyright owner]
!	
!	 CDDL HEADER END
!	

!
! C library routines for compiler support of misaligned memory
! references.  These are called when an in-line test reveals a
! misaligned address.
!

	.file	"misalign.s"

#include <SYS.h>

!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

!
! int ld_int(p)
! char *p;
! {
!	/*
!	 * load 32-bit int from misaligned address
!	 * cost(16-bit aligned case): 9 cycles
!	 * cost(8-bit aligned case): 18 cycles
!	 */
! }
!
	RTENTRY(.ld_int)
	andcc	%o0,1,%g0	! test 16-bit alignment
	be,a	1f		! fast case: two loads;
	lduh	[%o0+2],%o1	! do first one in delay slot
!
	ldub	[%o0+3],%o3	! slow case: load 4 bytes in <o0,o1,o2,o3>
	ldub	[%o0+2],%o2
	ldub	[%o0+1],%o1
	ldub	[%o0],%o0	! note this has to be done last.
	sll	%o2,8,%o2
	sll	%o1,16,%o1
	sll	%o0,24,%o0
	or	%o1,%o0,%o0	! put the pieces together.
	or	%o2,%o0,%o0
	retl
	or	%o3,%o0,%o0
1:
	lduh	[%o0],%o0	! 2nd half of fast case
	sll	%o0,16,%o0	! shift, concat, done.
	retl
	or	%o0,%o1,%o0
	SET_SIZE(.ld_int)

!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

!
! float ld_float(p)
! char *p;
! {
!	/* load 32-bit float (not double!) from misaligned address */
! }
!
	RTENTRY(.ld_float)
	save	%sp,-SA(MINFRAME+8),%sp
	andcc	%i0,1,%g0	! test for short alignment
	be,a	1f
	lduh	[%i0],%o0	! short aligned case: 2 loads, 2 stores
!
	ldub	[%i0],%o0	! byte aligned case: 4 loads, 4 stores
	ldub	[%i0+1],%o1
	ldub	[%i0+2],%o2
	ldub	[%i0+3],%o3
	stb	%o0,[%fp-4]
	stb	%o1,[%fp-3]
	stb	%o2,[%fp-2]
	b	2f
	stb	%o3,[%fp-1]
1:
	lduh	[%i0+2],%o1	! rest of short aligned case
	sth	%o0,[%fp-4]
	sth	%o1,[%fp-2]
2:
	ld	[%fp-4],%f0	! load FPU reg, done
	ret
	restore
	SET_SIZE(.ld_float)

!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

!
! double ld_double(p)
! char *p;
! {
!	/* load 64-bit float from misaligned address */
! }
!
	RTENTRY(.ld_double)
	save	%sp,-SA(MINFRAME+8),%sp
	andcc	%i0,3,%g0	! test for long alignment
	be,a	1f		! long aligned case: 2 loads, no stores
	ld	[%i0],%f0
!
	andcc	%i0,1,%g0	! test for short alignment
	be,a	2f		! short aligned case: 4 loads, 4 stores
	lduh	[%i0],%o0
!
	ldub	[%i0],%o0	! worst case: byte alignment
	ldub	[%i0+1],%o1	! 8 loads, 8 stores
	ldub	[%i0+2],%o2
	ldub	[%i0+3],%o3
	stb	%o0,[%fp-8]
	stb	%o1,[%fp-7]
	stb	%o2,[%fp-6]
	stb	%o3,[%fp-5]
	ldub	[%i0+4],%o0
	ldub	[%i0+5],%o1
	ldub	[%i0+6],%o2
	ldub	[%i0+7],%o3
	stb	%o0,[%fp-4]
	stb	%o1,[%fp-3]
	stb	%o2,[%fp-2]
	stb	%o3,[%fp-1]
	ldd	[%fp-8],%f0	! load f0-f1, done
	ret
	restore
2:
	lduh	[%i0+2],%o1	! rest of short aligned case
	lduh	[%i0+4],%o2
	lduh	[%i0+6],%o3
	sth	%o0,[%fp-8]
	sth	%o1,[%fp-6]
	sth	%o2,[%fp-4]
	sth	%o3,[%fp-2]
	ldd	[%fp-8],%f0	! load f0-f1, done
	ret
	restore
1:
	ld	[%i0+4],%f1	! rest of long aligned case
	ret
	restore
	SET_SIZE(.ld_double)

!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

!
! int st_int(x,p)
! int x;
! char *p;
! {
!	/* store 32-bit int from misaligned address;
!	   return stored value */
! }
!
	RTENTRY(.st_int)
	andcc	%o1,1,%g0	! test for short alignment
	be,a	1f
	srl	%o0,16,%o4
!
	srl	%o0,24,%o5	! byte aligned case
	stb	%o5,[%o1]
	srl	%o0,16,%o2
	stb	%o2,[%o1+1]
	srl	%o0,8,%o3
	stb	%o3,[%o1+2]
	retl
	stb	%o0,[%o1+3]
1:
	sth	%o4,[%o1]	! rest of short aligned case
	retl
	sth	%o0,[%o1+2]
	SET_SIZE(.st_int)

!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

!
! float st_float(x,p)
! float x;
! char *p;
! {
!	/* store 32-bit float from misaligned address;
!	   return stored value */
! }
!
	RTENTRY(.st_float)
	save	%sp,-SA(MINFRAME+8),%sp
	andcc	%i1,1,%g0	! test for short alignment
	be,a	1f		! short aligned case
	srl	%i0,16,%o0
!
	srl	%i0,24,%o0	! byte aligned case
	srl	%i0,16,%o1
	srl	%i0,8,%o2
	stb	%o0,[%i1]
	stb	%o1,[%i1+1]
	stb	%o2,[%i1+2]
	stb	%i0,[%i1+3]
	st	%i0,[%fp-4]	! store temp, load f0, done
	ld	[%fp-4],%f0
	ret
	restore
1:
	sth	%o0,[%i1]	! rest of short aligned case
	sth	%i0,[%i1+2]
	st	%i0,[%fp-4]
	ld	[%fp-4],%f0
	ret
	restore
	SET_SIZE(.st_float)

!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

!
! double st_double(x,p)
! double x;
! char *p;
! {
!	/* store 64-bit float from misaligned address;
!	   return stored value */
! }
!
	RTENTRY(.st_double)
	save	%sp,-SA(MINFRAME+8),%sp
	andcc	%i2,3,%g0	! test for long alignment
	be,a	1f		! long aligned case: 2 stores, 2 loads
	st	%i0,[%i2]
!
	andcc	%i2,1,%g0	! test for short alignment
	be,a	2f		! short aligned case: 4 stores, 4 loads
	srl	%i0,16,%o0
!				! byte aligned case: the pits
	srl	%i0,24,%o0
	srl	%i0,16,%o1
	srl	%i0,8,%o2
	stb	%o0,[%i2]	! store first word, a byte at a time
	stb	%o1,[%i2+1]
	stb	%o2,[%i2+2]
	stb	%i0,[%i2+3]
	srl	%i1,24,%o0
	srl	%i1,16,%o1
	srl	%i1,8,%o2
	stb	%o0,[%i2+4]	! store second word, a byte at a time
	stb	%o1,[%i2+5]
	stb	%o2,[%i2+6]
	stb	%i1,[%i2+7]
	std	%i0,[%fp-8]	! since dest is misaligned, must use temp
	ldd	[%fp-8],%f0	! load f0,f1 from double-aligned temp, done
	ret
	restore
2:				! rest of short aligned case
	srl	%i1,16,%o1
	sth	%o0,[%i2]	! store two words, a half word at a time
	sth	%i0,[%i2+2]
	sth	%o1,[%i2+4]
	sth	%i1,[%i2+6]
	std	%i0,[%fp-8]	! since dest is misaligned, must use temp
	ldd	[%fp-8],%f0	! load f0,f1 from double-aligned temp, done
	ret
	restore
1:				! rest of long aligned case
	st	%i1,[%i2+4]
	ld	[%i2],%f0	! load f0,f1 from long-aligned memory, done
	ld	[%i2+4],%f1
	ret
	restore
	SET_SIZE(.st_double)

!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

!
! void st_float_foreff(x,p)
! float x;
! char *p;
! {
!	/* store 32-bit float from misaligned address */
! }
!
	RTENTRY(.st_float_foreff)
	andcc	%o1,1,%g0	! test for short alignment
	be,a	1f
	srl	%o0,16,%o2
!
	srl	%o0,24,%o2	! byte aligned case
	srl	%o0,16,%o3
	srl	%o0,8,%o4
	stb	%o2,[%o1]
	stb	%o3,[%o1+1]
	stb	%o4,[%o1+2]
	retl
	stb	%o0,[%o1+3]
1:				! rest of short aligned case
	sth	%o2,[%o1]
	retl
	sth	%o0,[%o1+2]
	SET_SIZE(.st_float_foreff)

!- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

!
! void st_double_foreff(x,p)
! double x;
! char *p;
! {
!	/* store 64-bit float from misaligned address;
!	   return stored value */
! }
!
	RTENTRY(.st_double_foreff)
	andcc	%o2,3,%g0	! test for long alignment
	be,a	1f		! long aligned case: 2 stores
	st	%o0,[%o2]
!
	andcc	%o2,1,%g0	! test for short alignment
	be,a	2f		! short aligned case: 4 stores
	srl	%o0,16,%o3
!
	srl	%o0,24,%o3	! byte aligned case: 8 stores
	srl	%o0,16,%o4
	srl	%o0,8,%o5
	stb	%o3,[%o2]
	stb	%o4,[%o2+1]
	stb	%o5,[%o2+2]
	stb	%o0,[%o2+3]
	srl	%o1,24,%o3
	srl	%o1,16,%o4
	srl	%o1,8,%o5
	stb	%o3,[%o2+4]
	stb	%o4,[%o2+5]
	stb	%o5,[%o2+6]
	retl
	stb	%o1,[%o2+7]
2:				! rest of short aligned case
	srl	%o1,16,%o4
	sth	%o3,[%o2]
	sth	%o0,[%o2+2]
	sth	%o4,[%o2+4]
	retl
	sth	%o1,[%o2+6]
1:				! rest of long aligned case
	retl
	st	%o1,[%o2+4]
	SET_SIZE(.st_double_foreff)
