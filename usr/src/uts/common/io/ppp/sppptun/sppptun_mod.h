/*
 * sppptun_mod.h - References between sppptun.c and sppptun_mod.c
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#ifdef	__cplusplus
}
#endif

#endif /* _SPPPTUN_MOD_H */
