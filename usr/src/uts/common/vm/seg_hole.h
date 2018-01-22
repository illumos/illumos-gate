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
 * Copyright 2018 Joyent, Inc.
 */

#ifndef	_VM_SEG_HOLE_H
#define	_VM_SEG_HOLE_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct seghole_crargs {
	const char *name;
} seghole_crargs_t;

typedef struct seghole_data {
	const char	*shd_name;
} seghole_data_t;

extern int seghole_create(struct seg **, void *);

#define	AS_MAP_CHECK_SEGHOLE(crfp)		\
	((crfp) == (segcreate_func_t)seghole_create)

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_SEG_HOLE_H */
