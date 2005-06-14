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
 * Copyright 1994, 1999, 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * error functions
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/lvm/mdvar.h>

/*
 * null error constant
 */
const md_error_t	mdnullerror = {{MDEC_VOID}, NULL, NULL, NULL};

/*
 * clear error
 */
void
mdclrerror(
	md_error_t	*ep
)
{
	bzero((caddr_t)ep, sizeof (*ep));
}

/*
 * steal (copy) an error code safely
 */
int
mdstealerror(
	md_error_t	*to,
	md_error_t	*from
)
{
	mdclrerror(to);
	*to = *from;
	(void) bzero((caddr_t)from, sizeof (*from));
	return (0);
}

/*
 * simple error
 */
int
mderror(
	md_error_t	*ep,
	md_void_errno_t	errnum
)
{
	md_void_error_t	*ip = &ep->info.md_error_info_t_u.void_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_VOID;
	ip->errnum = errnum;

	return (0);
}

/*
 * system error
 */
int
mdsyserror(
	md_error_t	*ep,
	int		errnum
)
{
	md_sys_error_t	*ip = &ep->info.md_error_info_t_u.sys_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_SYS;
	ip->errnum = errnum;

	return (0);
}

/*
 * device error
 */
int
mddeverror(
	md_error_t	*ep,
	md_dev_errno_t	errnum,
	md_dev64_t	dev
)
{
	md_dev_error_t	*ip = &ep->info.md_error_info_t_u.dev_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_DEV;
	ip->errnum = errnum;
	ip->dev = (md_dev64_t)dev;

	return (0);
}

/*
 * metadevice error
 */
int
mdmderror(
	md_error_t	*ep,
	md_md_errno_t	errnum,
	minor_t		mnum
)
{
	md_md_error_t	*ip = &ep->info.md_error_info_t_u.md_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_MD;
	ip->errnum = errnum;
	ip->mnum = mnum;

	return (0);
}

/*
 * component error
 */
int
mdcomperror(
	md_error_t	*ep,
	md_comp_errno_t	errnum,
	minor_t		mnum,
	md_dev64_t	dev
)
{
	md_comp_error_t	*ip = &ep->info.md_error_info_t_u.comp_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_COMP;
	ip->errnum = errnum;
	ip->comp.mnum = mnum;
	ip->comp.dev = dev;

	return (0);
}

/*
 * hotspare pool error
 */
int
mdhsperror(
	md_error_t	*ep,
	md_hsp_errno_t	errnum,
	hsp_t		hsp
)
{
	md_hsp_error_t	*ip = &ep->info.md_error_info_t_u.hsp_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_HSP;
	ip->errnum = errnum;
	ip->hsp = hsp;

	return (0);
}

/*
 * hotspare error
 */
int
mdhserror(
	md_error_t	*ep,
	md_hs_errno_t	errnum,
	hsp_t		hsp,
	md_dev64_t	dev
)
{
	md_hs_error_t	*ip = &ep->info.md_error_info_t_u.hs_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_HS;
	ip->errnum = errnum;
	ip->hs.hsp = hsp;
	ip->hs.dev = dev;

	return (0);
}

/*
 * MDDB error
 */
int
mdmddberror(
	md_error_t	*ep,
	md_mddb_errno_t	errnum,
	minor_t		mnum,
	set_t		setno
)
{
	md_mddb_error_t	*ip = &ep->info.md_error_info_t_u.mddb_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_MDDB;
	ip->errnum = errnum;
	ip->mnum = mnum;
	ip->setno = setno;

	return (0);
}

int
mddbstatus2error(
	md_error_t	*ep,
	int		status,
	minor_t		mnum,
	set_t		setno
)
{
	md_mddb_errno_t	errnum;

	switch (status) {
	case MDDB_E_INVALID:
		errnum = MDE_DB_INVALID;
		break;
	case MDDB_E_EXISTS:
		errnum = MDE_DB_EXISTS;
		break;
	case MDDB_E_MASTER:
		errnum = MDE_DB_MASTER;
		break;
	case MDDB_E_TOOSMALL:
		errnum = MDE_DB_TOOSMALL;
		break;
	case MDDB_E_NORECORD:
		errnum = MDE_DB_NORECORD;
		break;
	case MDDB_E_NOSPACE:
		errnum = MDE_DB_NOSPACE;
		break;
	case MDDB_E_NOTNOW:
		errnum = MDE_DB_NOTNOW;
		break;
	case MDDB_E_NODB:
		errnum = MDE_DB_NODB;
		break;
	case MDDB_E_NOTOWNER:
		errnum = MDE_DB_NOTOWNER;
		break;
	case MDDB_E_STALE:
		errnum = MDE_DB_STALE;
		break;
	case MDDB_E_TOOFEW:
		errnum = MDE_DB_TOOFEW;
		break;
	case MDDB_E_TAGDATA:
		errnum = MDE_DB_TAGDATA;
		break;
	case MDDB_E_ACCOK:
		errnum = MDE_DB_ACCOK;
		break;
	case MDDB_E_NTAGDATA:
		errnum = MDE_DB_NTAGDATA;
		break;
	case MDDB_E_ACCNOTOK:
		errnum = MDE_DB_ACCNOTOK;
		break;
	case MDDB_E_NOLOCBLK:
		errnum = MDE_DB_NOLOCBLK;
		break;
	case MDDB_E_NOLOCNMS:
		errnum = MDE_DB_NOLOCNMS;
		break;
	case MDDB_E_NODIRBLK:
		errnum = MDE_DB_NODIRBLK;
		break;
	case MDDB_E_NOTAGREC:
		errnum = MDE_DB_NOTAGREC;
		break;
	case MDDB_E_NOTAG:
		errnum = MDE_DB_NOTAG;
		break;
	default:
		ASSERT(0);
		errnum = (md_mddb_errno_t)status;
		break;
	}
	return (mdmddberror(ep, errnum, mnum, setno));
}
