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
 * Copyright 2014 Pluribus Networks Inc.
 */

#ifndef _FREEBSD_VM_VM_H_
#define	_FREEBSD_VM_VM_H_

#include <machine/vm.h>

typedef u_char vm_prot_t;

#define	VM_PROT_NONE		((vm_prot_t) 0x00)
#define	VM_PROT_READ		((vm_prot_t) 0x01)
#define	VM_PROT_WRITE		((vm_prot_t) 0x02)
#define	VM_PROT_EXECUTE		((vm_prot_t) 0x04)

#define	VM_PROT_ALL		(VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)
#define	VM_PROT_RW		(VM_PROT_READ|VM_PROT_WRITE)

/*
 * <sys/promif.h> contains a troublesome preprocessor define for BYTE.
 * Do this ugly workaround to avoid it.
 */
#define	_SYS_PROMIF_H
#include <vm/hat_i86.h>
#undef	_SYS_PROMIF_H

#endif	/* _FREEBSD_VM_VM_H_ */
