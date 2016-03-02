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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/auxv.h>
#include <sys/lx_brand.h>


int
lx_auxv_stol(const auxv_t *ap, auxv_t *oap, const lx_elf_data_t *edp)
{
	switch (ap->a_type) {
	case AT_BASE:
		oap->a_un.a_val = edp->ed_base;
		break;
	case AT_ENTRY:
		oap->a_un.a_val = edp->ed_entry;
		break;
	case AT_PHDR:
		oap->a_un.a_val = edp->ed_phdr;
		break;
	case AT_PHENT:
		oap->a_un.a_val = edp->ed_phent;
		break;
	case AT_PHNUM:
		oap->a_un.a_val = edp->ed_phnum;
		break;
	case AT_SUN_BRAND_LX_SYSINFO_EHDR:
		if (edp->ed_vdso != 0) {
			oap->a_type = AT_SYSINFO_EHDR;
			oap->a_un.a_val = edp->ed_vdso;
			return (0);
		} else {
			/* No vDSO for i386 */
			return (1);
		}
	case AT_SUN_BRAND_LX_CLKTCK:
		oap->a_type = AT_CLKTCK;
		oap->a_un.a_val = ap->a_un.a_val;
		return (0);
	case AT_SUN_AUXFLAGS:
		if ((ap->a_un.a_val & AF_SUN_SETUGID) != 0) {
			oap->a_type = AT_SECURE;
			oap->a_un.a_val = 1;
			return (0);
		} else {
			return (1);
		}
	case AT_SUN_GID:
		oap->a_type = AT_LX_EGID;
		oap->a_un.a_val = ap->a_un.a_val;
		return (0);
	case AT_SUN_RGID:
		oap->a_type = AT_LX_GID;
		oap->a_un.a_val = ap->a_un.a_val;
		return (0);
	case AT_SUN_UID:
		oap->a_type = AT_LX_EUID;
		oap->a_un.a_val = ap->a_un.a_val;
		return (0);
	case AT_SUN_RUID:
		oap->a_type = AT_LX_UID;
		oap->a_un.a_val = ap->a_un.a_val;
		return (0);
	case AT_EXECFD:
	case AT_PAGESZ:
	case AT_FLAGS:
	case AT_RANDOM:
	case AT_NULL:
		/* No translate needed */
		oap->a_un.a_val = ap->a_un.a_val;
		break;
	default:
		/* All other unrecognized entries are ignored */
		return (1);
	}
	oap->a_type = ap->a_type;
	return (0);
}
