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


#if defined(_LP64)
#define	LX_SYS_IO_SETUP		206
#define	LX_SYS32_IO_SETUP	245
#else
#define	LX_SYS_IO_SETUP		245
#endif

long
lx_io_setup(unsigned int nr_events, void **ctxp)
{
	lx_proc_data_t *lxpd = ptolxproc(curproc);
	uintptr_t uargs[2] = {(uintptr_t)nr_events, (uintptr_t)ctxp};

	mutex_enter(&curproc->p_lock);
	lxpd->l_flags |= LX_PROC_AIO_USED;
	mutex_exit(&curproc->p_lock);

	ttolxlwp(curthread)->br_eosys = JUSTRETURN;
#if defined(_LP64)
	if (get_udatamodel() != DATAMODEL_NATIVE) {
		lx_emulate_user32(ttolwp(curthread), LX_SYS32_IO_SETUP, uargs);
	} else
#endif
	{
		lx_emulate_user(ttolwp(curthread), LX_SYS_IO_SETUP, uargs);
	}
	/* NOTREACHED */
	return (0);
}
