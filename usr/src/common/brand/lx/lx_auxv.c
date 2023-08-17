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
 * Copyright 2023 MNX Cloud, Inc.
 */

#include <sys/auxv.h>
#include <sys/lx_brand.h>

/*
 * Linux does not make the distinction between 'int' and 'long' when it comes
 * to the format of the aux vector.  In order to properly clear the struct
 * padding present in the native auxv_t in 64-bit, we employ the Linux format.
 */
struct lx_auxv {
	long la_type;
	long la_val;
};

int
lx_auxv_stol(const auxv_t *ap, auxv_t *oap, const lx_elf_data_t *edp)
{
	struct lx_auxv *loap = (struct lx_auxv *)oap;

	switch (ap->a_type) {
	case AT_BASE:
		loap->la_val = edp->ed_base;
		break;
	case AT_ENTRY:
		loap->la_val = edp->ed_entry;
		break;
	case AT_PHDR:
		loap->la_val = edp->ed_phdr;
		break;
	case AT_PHENT:
		loap->la_val = edp->ed_phent;
		break;
	case AT_PHNUM:
		loap->la_val = edp->ed_phnum;
		break;
	case AT_SUN_BRAND_LX_SYSINFO_EHDR:
		loap->la_type = AT_SYSINFO_EHDR;
		loap->la_val = ap->a_un.a_val;
		return (0);
	case AT_SUN_BRAND_LX_CLKTCK:
		loap->la_type = AT_CLKTCK;
		loap->la_val = ap->a_un.a_val;
		return (0);
	case AT_SUN_AUXFLAGS:
		loap->la_type = AT_SECURE;
		if ((ap->a_un.a_val & AF_SUN_SETUGID) != 0) {
			loap->la_val = 1;
		} else {
			loap->la_val = 0;
		}
		return (0);
	case AT_SUN_GID:
		loap->la_type = AT_LX_EGID;
		loap->la_val = ap->a_un.a_val;
		return (0);
	case AT_SUN_RGID:
		loap->la_type = AT_LX_GID;
		loap->la_val = ap->a_un.a_val;
		return (0);
	case AT_SUN_UID:
		loap->la_type = AT_LX_EUID;
		loap->la_val = ap->a_un.a_val;
		return (0);
	case AT_SUN_RUID:
		loap->la_type = AT_LX_UID;
		loap->la_val = ap->a_un.a_val;
		return (0);
	case AT_EXECFD:
	case AT_PAGESZ:
	case AT_FLAGS:
	case AT_RANDOM:
	case AT_NULL:
		/* No translate needed */
		loap->la_val = ap->a_un.a_val;
		break;
	default:
		/* All other unrecognized entries are ignored */
		return (1);
	}
	loap->la_type = ap->a_type;
	return (0);
}
