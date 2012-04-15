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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ONTRAP_H
#define	_ONTRAP_H

#if !defined(_ASM)
#include <sys/types.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * on_trap() provides protection against various kinds of machine exceptions,
 * and must be used with extreme caution.  Like setjmp(), on_trap() returns
 * zero when explicitly called and non-zero when it returns as the result of
 * an exception.  The caller should not attempt to interpret the actual integer
 * return value except to test whether it is zero or non-zero.  on_trap() and
 * no_trap() are NOT DDI interfaces for public consumption.  For now, the
 * on_trap() mechanism is separate from on_fault() protection and the t_lofault
 * protection used by the various copy routines.
 *
 * Calls to on_trap() may be nested, but only the most recently installed bits
 * apply.  Protection bits may be OR-ed together if the caller wishes to
 * protect against more than one type of trap.  If on_trap() returns non-zero,
 * the bit corresponding to the trap that triggered return to on_trap() will
 * be stored in the ot_trap field of the caller's on_trap_data.
 *
 * After calling on_trap(), the caller may elect to modify ot_trampoline to
 * install a custom trampoline routine prior to executing the protected code
 * region.  No other fields of the on_trap_data should be modified by the
 * caller.  The trampoline may not be applicable on all platforms.
 *
 * The on_trap_data structures are kept in a stack (linked list) whose top
 * is pointed to by the current thread's t_ontrap field.  A no_trap() call
 * pops the top element from the stack and resets t_ontrap to ot_prev.
 * We assume the caller has allocated the on_trap_data on the stack or
 * made other arrangements, so we do not need to worry about deallocation.
 *
 * If repeated calls to on_trap() are made using the same on_trap_data address,
 * the topmost stack element is modified in-place (the same on_trap_data is
 * not pushed twice), allowing callers to use on_trap() in a loop.  The act
 * of catching an exception does NOT modify t_ontrap.  Even if on_trap()
 * returns non-zero, the caller must use no_trap() to clear trap protection.
 *
 * Calls to no_trap() are permitted when the on_trap_data stack is empty; they
 * have no effect.  no_trap() only modifies t_ontrap; it does not modify the
 * internals of the topmost on_trap_data element.  It is therefore legal for
 * callers to examine the contents of the on_trap_data (specifically ot_trap)
 * after the data is popped using no_trap().
 *
 * A given platform may not implement all the forms of on_trap() protection.
 * The on_trap_data will be pushed on the t_ontrap stack with ot_prot set
 * regardless.  We must guarantee that if the platform does not implement
 * a trap protection, the exceptional condition will trigger a panic.  We do
 * not permit a platform to allow the exceptional condition to occur silently
 * and then continue to execute the caller's protected code region.
 */

#define	OT_DATA_ACCESS	0x01		/* data access exception protection */
#define	OT_DATA_EC	0x02		/* error correction trap protection */

#if defined(__x86)
#define	OT_SEGMENT_ACCESS 0x03		/* segmentation exception */
#endif

#if !defined(_ASM)

typedef struct on_trap_data {
	ushort_t ot_prot;		/* active protection bits (see above) */
	ushort_t ot_trap;		/* bit of actual trap that occurred */
	uintptr_t ot_trampoline;	/* %pc for trap return (if any) */
	label_t ot_jmpbuf;		/* label for longjmp back to on_trap */
	struct on_trap_data *ot_prev;	/* pointer to previous on_trap_data */
	void *ot_handle;		/* access handle */
	void *ot_pad1;			/* reserved for future use */
} on_trap_data_t;

#if defined(_KERNEL)

extern int on_trap(on_trap_data_t *, uint_t) __RETURNS_TWICE;
#pragma	unknown_control_flow(on_trap)
extern void no_trap(void);

extern void on_trap_trampoline(void);	/* default trampoline */

#endif	/* _KERNEL */
#endif	/* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _ONTRAP_H */
