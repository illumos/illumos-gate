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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/zone.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_types.h>

struct lx_utsname {
	char lxu_sysname[LX_SYS_UTS_LN];
	char lxu_nodename[LX_SYS_UTS_LN];
	char lxu_release[LX_SYS_UTS_LN];
	char lxu_version[LX_SYS_UTS_LN];
	char lxu_machine[LX_SYS_UTS_LN];
	char lxu_domainname[LX_SYS_UTS_LN];
};

long
lx_uname(void *uptr)
{
	proc_t *p = curproc;
	lx_proc_data_t *lxpd = ptolxproc(p);
	lx_zone_data_t *lxzd = ztolxzd(p->p_zone);
	struct lx_utsname un;

	bzero(&un, sizeof (un));

	(void) strlcpy(un.lxu_sysname, LX_UNAME_SYSNAME, LX_SYS_UTS_LN);
	(void) strlcpy(un.lxu_nodename, p->p_zone->zone_nodename,
	    LX_SYS_UTS_LN);

	mutex_enter(&lxzd->lxzd_lock);

	if (lxpd->l_uname_release[0] != '\0') {
		(void) strlcpy(un.lxu_release, lxpd->l_uname_release,
		    LX_SYS_UTS_LN);
	} else {
		(void) strlcpy(un.lxu_release, lxzd->lxzd_kernel_release,
		    LX_SYS_UTS_LN);
	}
	if (lxpd->l_uname_version[0] != '\0') {
		(void) strlcpy(un.lxu_version, lxpd->l_uname_version,
		    LX_SYS_UTS_LN);
	} else {
		(void) strlcpy(un.lxu_version, lxzd->lxzd_kernel_version,
		    LX_SYS_UTS_LN);
	}

	mutex_exit(&lxzd->lxzd_lock);

	if (get_udatamodel() == DATAMODEL_LP64) {
		(void) strlcpy(un.lxu_machine, LX_UNAME_MACHINE64,
		    LX_SYS_UTS_LN);
	} else {
		(void) strlcpy(un.lxu_machine, LX_UNAME_MACHINE32,
		    LX_SYS_UTS_LN);
	}
	(void) strlcpy(un.lxu_domainname, p->p_zone->zone_domain,
	    LX_SYS_UTS_LN);

	if (copyout(&un, uptr, sizeof (un)) != 0) {
		return (set_errno(EFAULT));
	}

	return (0);
}
