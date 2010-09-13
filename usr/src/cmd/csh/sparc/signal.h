/*
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef CSH_SIGNAL_H
#define CSH_SIGNAL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * 4.3BSD signal compatibility header
 *
 */
#define sigmask(m)	(m > 32 ? 0 : (1 << ((m)-1)))

/*
 * 4.3BSD signal vector structure used in sigvec call.
 */
struct  sigvec {
        void    (*sv_handler)();        /* signal handler */
        int     sv_mask;                /* signal mask to apply */
        int     sv_flags;               /* see signal options below */
};

#define SV_ONSTACK      0x0001  /* take signal on signal stack */
#define SV_INTERRUPT    0x0002  /* do not restart system on signal return */
#define SV_RESETHAND    0x0004  /* reset handler to SIG_DFL when signal taken */

#define sv_onstack sv_flags

/*
 * Machine dependent data structure
 */
struct  sigcontext {
        int     sc_onstack;             /* sigstack state to restore */
        int     sc_mask;                /* signal mask to restore */
#define MAXWINDOW       31              /* max usable windows in sparc */
	long	sc_sp;			/* sp to restore */
	long	sc_pc;			/* pc to retore */
	long	sc_npc;                 /* next pc to restore */
	long	sc_psr;                 /* psr to restore */
	long	sc_g1;                  /* register that must be restored */
	long	sc_o0;
	long	sc_wbcnt;               /* number of outstanding windows */
	long	*sc_spbuf[MAXWINDOW];   /* sp's for each wbuf */
	long	sc_wbuf[MAXWINDOW][16]; /* outstanding window save buffer */
};

#define SI_DFLCODE	1

#define BUS_HWERR	BUS_ADRERR	/* misc hardware error (e.g. timeout) */
#define BUS_ALIGN	BUS_ADRALN	/* hardware alignment error */

#define SEGV_NOMAP	SEGV_MAPERR	/* no mapping at the fault address */
#define SEGV_PROT	SEGV_ACCERR	/* access exceeded protections */

/*
 * The SEGV_CODE(code) will be SEGV_NOMAP, SEGV_PROT, or SEGV_OBJERR.
 * In the SEGV_OBJERR case, doing a SEGV_ERRNO(code) gives an errno value
 * reported by the underlying file object mapped at the fault address.
 */

#define SIG_NOADDR	((char *)~0)

#define	SEGV_MAKE_ERR(e) (((e) << 8) | SEGV_MAPERR)

#endif	/* CSH_SIGNAL_H */
