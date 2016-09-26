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
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

#ifndef _FICLPLATFORM_EMU_H
#define	_FICLPLATFORM_EMU_H

/*
 * BootForth Emulator entry points.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern ficlVm *bf_init(const char *, ficlOutputFunction);
extern void bf_fini(void);
extern int bf_run(char *);


#ifdef __cplusplus
}
#endif

#endif /* _FICLPLATFORM_EMU_H */
