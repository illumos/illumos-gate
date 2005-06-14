/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BSM_DEVICES_H
#define	_BSM_DEVICES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {		/* see getdmapent(3) */
	char *dmap_devname;
	char *dmap_devtype;
	char *dmap_devlist;
} devmap_t;

devmap_t *getdmapent(void);
devmap_t *getdmaptype(char *);
devmap_t *getdmapnam(char *);
devmap_t *getdmapdev(char *);
void setdmapent(void);
void enddmapent(void);
void setdmapfile(char *);

typedef struct {		/* see getdaent(3) */
	char *da_devname;
	char *da_devtype;
	char *da_devmin;
	char *da_devmax;
	char *da_devauth;
	char *da_devexec;
} devalloc_t;

devalloc_t *getdaent(void);
devalloc_t *getdatype(char *);
devalloc_t *getdanam(char *);
devalloc_t *getdadev(char *);
void setdaent(void);
void enddaent(void);
void setdafile(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _BSM_DEVICES_H */
