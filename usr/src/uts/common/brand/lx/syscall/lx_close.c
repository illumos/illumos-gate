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
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/brand.h>

#include <sys/lx_brand.h>
#include <sys/lx_syscalls.h>


extern int close(int);

long
lx_close(int fdes)
{
	lx_proc_data_t *lxpd = ptolxproc(curproc);
	boolean_t aio_used;
	uintptr_t uargs[1] = {(uintptr_t)fdes};

	mutex_enter(&curproc->p_lock);
	aio_used = ((lxpd->l_flags & LX_PROC_AIO_USED) != 0);
	mutex_exit(&curproc->p_lock);

	if (!aio_used) {
		return (close(fdes));
	}

	/*
	 * If the process potentially has any AIO contexts open, the userspace
	 * emulation must be used so that libc can properly maintain its state.
	 */

	ttolxlwp(curthread)->br_eosys = JUSTRETURN;
#if defined(_LP64)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		lx_emulate_user32(ttolwp(curthread), LX_SYS32_close, uargs);
	} else
#endif
	{
		lx_emulate_user(ttolwp(curthread), LX_SYS_close, uargs);
	}
	/* NOTREACHED */
	return (0);
}
