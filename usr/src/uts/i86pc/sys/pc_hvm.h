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
 * Copyright 2017 Joyent, Inc.
 */


#ifndef _PC_HVM_H
#define	_PC_HVM_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_KERNEL)

extern boolean_t hvm_excl_hold(const char *);
extern void hvm_excl_rele(const char *);

#endif /* defined(_KERNEL) */

#ifdef __cplusplus
}
#endif

#endif /* _PC_HVM_H */
