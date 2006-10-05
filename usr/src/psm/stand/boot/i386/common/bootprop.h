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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BOOTPROP_H
#define	_BOOTPROP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Global variables which will be exported as boot properties in
 * i386_bootprop.c.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/bootconf.h>
#include <sys/obpdefs.h>
#include <sys/param.h>

extern char *impl_arch_name;
extern char *module_path;

/*
 * bootenv.rc properties
 */
extern char *bootfile_prop;
extern char *inputdevice_prop;
extern char *outputdevice_prop;
extern char *console_prop;

/* These are actually in intel/bootprop.c. */
extern int bgetproplen(struct bootops *, char *);
extern int bgetprop(struct bootops *, char *, void *);
extern int bsetprop(struct bootops *, char *, void *, int);
extern char *bnextprop(struct bootops *, char *);

extern void setup_bootdev_props(void);
extern void setup_bootprop(void);
extern void get_grub_bootargs(char *);
extern void get_eeprom_bootargs(char *);

#ifdef __cplusplus
}
#endif

#endif /* _BOOTPROP_H */
