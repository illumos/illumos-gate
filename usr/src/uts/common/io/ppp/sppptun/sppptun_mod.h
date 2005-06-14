/*
 * sppptun_mod.h - References between sppptun.c and sppptun_mod.c
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SPPPTUN_MOD_H
#define	_SPPPTUN_MOD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern struct streamtab sppptun_tab;
extern void sppptun_init(void);
extern void sppptun_tcl_init(void);
extern int sppptun_tcl_fintest(void);
extern void sppptun_tcl_fini(void);

/*
 * Description strings kept in sppptun.c because we're more interested
 * in the revision of that module.
 */
extern const char sppptun_driver_description[];
extern const char sppptun_module_description[];

#if 0
#define	DBGPLUMB(x)	cmn_err x
#else
#define	DBGPLUMB(x)	((void) 0)
#endif

#if 0
#define	DBGENTRY(x)	cmn_err x
#else
#define	DBGENTRY(x)	((void) 0)
#endif

#if 0
#define	DBGERROR(x)	cmn_err x
#else
#define	DBGERROR(x)	((void) 0)
#endif

#if 0
#define	DBGNORMAL(x)	cmn_err x
#else
#define	DBGNORMAL(x)	((void) 0)
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _SPPPTUN_MOD_H */
