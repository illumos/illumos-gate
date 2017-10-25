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
 * Copyright 2013 Pluribus Networks Inc.
 */

#ifndef _COMPAT_FREEBSD_AMD64_MACHINE_SMP_H_
#define	_COMPAT_FREEBSD_AMD64_MACHINE_SMP_H_

#ifdef _KERNEL

/*
 * APIC-related definitions would normally be stored in x86/include/apicvar.h,
 * accessed here via x86/include/x86_smp.h.  Until it becomes necessary to
 * implment that whole chain of includes, those definitions are short-circuited
 * into this file.
 */

#define	IDTVEC(name)	idtvec_ ## name

extern int idtvec_justreturn;

extern int lapic_ipi_alloc(int *);
extern void lapic_ipi_free(int vec);


#endif /* _KERNEL */

#endif	/* _COMPAT_FREEBSD_AMD64_MACHINE_SMP_H_ */
