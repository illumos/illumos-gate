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
 * Copyright 2020 Joyent, Inc.
 */

#ifndef _SYS_KFPU_H
#define	_SYS_KFPU_H

/*
 * This header file provides a means for the kernel to opt into using the FPU.
 * Care should be exercised when using the FPU.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kfpu_state kfpu_state_t;

/*
 * Allocate a new kernel FPU state. This may be allocated at a time independent
 * from its use. It will stay around until such a time as kernel_fpu_free() is
 * called. A given kernel FPU state may only be used by a single thread at any
 * time; however, it is not bound to a given thread.
 */
extern kfpu_state_t *kernel_fpu_alloc(int);
extern void kernel_fpu_free(kfpu_state_t *);

/*
 * These functions begin and end the use of the kernel FPU. Once this is called,
 * a given kernel thread will be allowed to use the FPU. This will be saved and
 * restored across context switches.
 */
extern void kernel_fpu_begin(kfpu_state_t *, uint_t);
extern void kernel_fpu_end(kfpu_state_t *, uint_t);

/*
 * Internal validation function.
 */
extern void kernel_fpu_no_swtch(void);

/*
 * Flag definitions for kernel_fpu_begin and kernel_fpu_end.
 */
#define	KFPU_NO_STATE	0x01	/* kfpu_state_t not passed; use preemption */
#define	KFPU_USE_LWP	0x02	/* kfpu_state_t not passed; use lwp */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KFPU_H */
