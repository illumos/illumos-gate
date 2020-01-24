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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef	_PROC_FD_H
#define	_PROC_FD_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Private functions */
extern int proc_fdinfo_from_core(const prfdinfo_core_t *, prfdinfo_t **);
extern int proc_fdinfo_to_core(const prfdinfo_t *, prfdinfo_core_t *);
extern prfdinfo_t *proc_fdinfo_dup(const prfdinfo_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PROC_FD_H */
