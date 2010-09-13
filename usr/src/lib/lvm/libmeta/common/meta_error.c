/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * print metedevice errors
 */

#include <meta.h>
#include <sys/lvm/md_mddb.h>

#include <syslog.h>

/*
 * clear error
 */
void
mdclrerror(
	md_error_t	*ep
)
{
	if (ep->name != NULL)
		Free(ep->name);
	if (ep->host != NULL)
		Free(ep->host);
	if (ep->extra != NULL)
		Free(ep->extra);
	(void) memset(ep, '\0', sizeof (*ep));
}

/*
 * cook names
 */
static char *
md_name(
	minor_t	mnum
)
{
	char	*name;

	/* get name, or fake it */
	if ((name = get_mdname(NULL, mnum)) == NULL) {
		char	buf[40];

		(void) sprintf(buf, "%lu/%lu", MD_MIN2SET(mnum),
		    MD_MIN2UNIT(mnum));
		return (Strdup(buf));
	}
	return (Strdup(name));
}

static char *
dev_name(
	set_t	setno,
	md_dev64_t dev
)
{
	char	*name;

	/* get name or fake it */
	if (dev == NODEV64)
		return (Strdup(dgettext(TEXT_DOMAIN, "unknown device")));
	if ((name = get_devname(setno, dev)) == NULL) {
		char	buf[40];

		(void) sprintf(buf, "%lu.%lu", meta_getmajor(dev),
		    meta_getminor(dev));
		return (Strdup(buf));
	}
	return (Strdup(name));
}

static char *
hsp_name(
	hsp_t	hsp
)
{
	char	*name;

	if ((name = get_hspname(NULL, hsp)) == NULL) {
		char	buf[40];

		(void) sprintf(buf, "%u/%u", HSP_SET(hsp), HSP_ID(hsp));
		return (Strdup(buf));
	}
	return (Strdup(name));
}

static char *
set_name(
	set_t		setno
)
{
	mdsetname_t	*sp;
	md_error_t	xep = mdnullerror;

	if (setno == MD_SET_BAD)
		return (NULL);

	if ((sp = metasetnosetname(setno, &xep)) == NULL) {
		char	buf[40];

		mdclrerror(&xep);
		(void) sprintf(buf, "setno %u", setno);
		return (Strdup(buf));
	}
	return (Strdup(sp->setname));
}

/*
 * fill in all the appropriate md_error_t fields
 */
static void
metacookerror(
	md_error_t	*ep,		/* generic error */
	char		*name		/* optional name or host */
)
{
	/* get host name */
	if (ep->host != NULL) {
		Free(ep->host);
		ep->host = NULL;
	}
	if ((ep->info.errclass == MDEC_RPC) &&
	    (name != NULL) && (*name != '\0')) {
		ep->host = Strdup(name);
		name = NULL;
	} else
		ep->host = Strdup(mynode());

	/* get appropriate name */
	if (ep->name != NULL) {
		Free(ep->name);
		ep->name = NULL;
	}
	if ((name != NULL) && (*name != '\0')) {
		ep->name = Strdup(name);
	} else {
		switch (ep->info.errclass) {

		/* can't do anything about these */
		case MDEC_VOID:
		case MDEC_SYS:
		case MDEC_RPC:
		default:
			break;

		/* device name */
		case MDEC_DEV:
		{
			md_dev_error_t	*ip =
			    &ep->info.md_error_info_t_u.dev_error;

			ep->name = dev_name(MD_SET_BAD, ip->dev);
			break;
		}

		/* device name */
		case MDEC_USE:
		{
			md_use_error_t	*ip =
			    &ep->info.md_error_info_t_u.use_error;

			ep->name = dev_name(MD_SET_BAD, ip->dev);
			if (ip->where == NULL) {
				ip->where = Strdup(dgettext(TEXT_DOMAIN,
				    "unknown"));
			}
			break;
		}

		/* metadevice name */
		case MDEC_MD:
		{
			md_md_error_t	*ip =
			    &ep->info.md_error_info_t_u.md_error;

			ep->name = md_name(ip->mnum);
			break;
		}

		/* component name */
		case MDEC_COMP:
		{
			md_comp_error_t	*ip =
			    &ep->info.md_error_info_t_u.comp_error;
			char		*mdname, *devname;
			size_t 		len;

			mdname = md_name(ip->comp.mnum);
			devname = dev_name(MD_MIN2SET(ip->comp.mnum),
			    ip->comp.dev);
			len = strlen(mdname) + strlen(": ")
			    + strlen(devname) + 1;
			ep->name = Malloc(len);
			(void) snprintf(ep->name, len, "%s: %s",
			    mdname, devname);
			Free(mdname);
			Free(devname);
			break;
		}

		/* hotspare pool name */
		case MDEC_HSP:
		{
			md_hsp_error_t	*ip =
			    &ep->info.md_error_info_t_u.hsp_error;

			ep->name = hsp_name(ip->hsp);
			break;
		}

		/* hotspare name */
		case MDEC_HS:
		{
			md_hs_error_t	*ip =
			    &ep->info.md_error_info_t_u.hs_error;
			char		*hspname, *devname;
			size_t 		len;

			hspname = hsp_name(ip->hs.hsp);
			devname = dev_name(HSP_SET(ip->hs.hsp), ip->hs.dev);
			len = strlen(hspname) + strlen(": ")
			    + strlen(devname) + 1;
			ep->name = Malloc(len);
			(void) snprintf(ep->name, len, "%s: %s",
			    hspname, devname);
			Free(hspname);
			Free(devname);
			break;
		}

		/* mddb name */
		case MDEC_MDDB:
		{
			md_mddb_error_t	*ip =
			    &ep->info.md_error_info_t_u.mddb_error;
			if (ip->mnum != NODEV32)
				ep->name = md_name(ip->mnum);
			ep->name = set_name(ip->setno);
			break;
		}

		/* set name */
		case MDEC_DS:
		{
			md_ds_error_t	*ip =
			    &ep->info.md_error_info_t_u.ds_error;

			ep->name = set_name(ip->setno);
			break;
		}
		}
	}
}

/*
 * simple error
 */
int
mderror(
	md_error_t	*ep,
	md_void_errno_t	errnum,
	char		*name
)
{
	md_void_error_t	*ip = &ep->info.md_error_info_t_u.void_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_VOID;
	ip->errnum = errnum;

	metacookerror(ep, name);
	return (-1);
}

/*
 * system error
 */
int
mdsyserror(
	md_error_t	*ep,
	int		errnum,
	char		*name
)
{
	md_sys_error_t	*ip = &ep->info.md_error_info_t_u.sys_error;

	mdclrerror(ep);
	if (errnum != 0) {
		ep->info.errclass = MDEC_SYS;
		ip->errnum = errnum;
	}

	metacookerror(ep, name);
	return (-1);
}

/*
 * RPC error
 */
int
mdrpcerror(
	md_error_t	*ep,
	CLIENT		*clntp,
	char		*host,
	char		*extra
)
{
	md_rpc_error_t	*ip = &ep->info.md_error_info_t_u.rpc_error;
	struct rpc_err	rpcerr;

	mdclrerror(ep);
	clnt_geterr(clntp, &rpcerr);
	ep->info.errclass = MDEC_RPC;
	ip->errnum = rpcerr.re_status;

	metacookerror(ep, host);
	mderrorextra(ep, extra);
	return (-1);
}

/*
 * RPC create error
 */
int
mdrpccreateerror(
	md_error_t	*ep,
	char		*host,
	char		*extra
)
{
	md_rpc_error_t	*ip = &ep->info.md_error_info_t_u.rpc_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_RPC;
	ip->errnum = rpc_createerr.cf_stat;

	metacookerror(ep, host);
	mderrorextra(ep, extra);
	return (-1);
}

/*
 * device error
 */
int
mddeverror(
	md_error_t	*ep,
	md_dev_errno_t	errnum,
	md_dev64_t	dev,
	char		*name
)
{
	md_dev_error_t	*ip = &ep->info.md_error_info_t_u.dev_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_DEV;
	ip->errnum = errnum;
	ip->dev = dev;

	metacookerror(ep, name);
	return (-1);
}

/*
 * use error
 */
int
mduseerror(
	md_error_t	*ep,
	md_use_errno_t	errnum,
	md_dev64_t	dev,
	char		*where,
	char		*name
)
{
	md_use_error_t	*ip = &ep->info.md_error_info_t_u.use_error;

	assert(where != NULL);
	mdclrerror(ep);
	ep->info.errclass = MDEC_USE;
	ip->errnum = errnum;
	ip->dev = dev;
	ip->where = Strdup(where);

	metacookerror(ep, name);
	return (-1);
}

/*
 * overlap error
 */
int
mdoverlaperror(
	md_error_t		*ep,
	md_overlap_errno_t	errnum,
	char			*name,
	char			*where,
	char			*overlap
)
{
	md_overlap_error_t *ip =
	    &ep->info.md_error_info_t_u.overlap_error;

	assert(overlap != NULL);
	mdclrerror(ep);
	ep->info.errclass = MDEC_OVERLAP;
	ip->errnum = errnum;
	ip->overlap = Strdup(overlap);
	ip->where = NULL;
	if (where != NULL)
		ip->where = Strdup(where);

	metacookerror(ep, name);
	return (-1);
}

/*
 * metadevice error
 */
int
mdmderror(
	md_error_t	*ep,
	md_md_errno_t	errnum,
	minor_t		mnum,
	char		*name
)
{
	md_md_error_t	*ip = &ep->info.md_error_info_t_u.md_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_MD;
	ip->errnum = errnum;
	ip->mnum = mnum;

	metacookerror(ep, name);
	return (-1);
}

/*
 * component error
 */
int
mdcomperror(
	md_error_t	*ep,
	md_comp_errno_t	errnum,
	minor_t		mnum,
	md_dev64_t	dev,
	char		*name
)
{
	md_comp_error_t	*ip = &ep->info.md_error_info_t_u.comp_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_COMP;
	ip->errnum = errnum;
	ip->comp.mnum = mnum;
	ip->comp.dev = dev;

	metacookerror(ep, name);
	return (-1);
}

/*
 * hotspare pool error
 */
int
mdhsperror(
	md_error_t	*ep,
	md_hsp_errno_t	errnum,
	hsp_t		hsp,
	char		*name
)
{
	md_hsp_error_t	*ip = &ep->info.md_error_info_t_u.hsp_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_HSP;
	ip->errnum = errnum;
	ip->hsp = hsp;

	metacookerror(ep, name);
	return (-1);
}

/*
 * hotspare error
 */
int
mdhserror(
	md_error_t	*ep,
	md_hs_errno_t	errnum,
	hsp_t		hsp,
	md_dev64_t	dev,
	char		*name
)
{
	md_hs_error_t	*ip = &ep->info.md_error_info_t_u.hs_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_HS;
	ip->errnum = errnum;
	ip->hs.hsp = hsp;
	ip->hs.dev = dev;

	metacookerror(ep, name);
	return (-1);
}

/*
 * MDDB error
 */
int
mdmddberror(
	md_error_t	*ep,
	md_mddb_errno_t	errnum,
	minor_t		mnum,
	set_t		setno,
	size_t		size,
	char		*name
)
{
	md_mddb_error_t	*ip = &ep->info.md_error_info_t_u.mddb_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_MDDB;
	ip->errnum = errnum;
	ip->mnum = mnum;
	ip->setno = setno;
	ip->size = size;

	metacookerror(ep, name);
	return (-1);
}

/*
 * metadevice diskset (ds) error
 */
int
mddserror(
	md_error_t	*ep,
	md_ds_errno_t	errnum,
	set_t		setno,
	char		*node,
	char		*drive,
	char		*name
)
{
	md_ds_error_t	*ip = &ep->info.md_error_info_t_u.ds_error;

	mdclrerror(ep);
	ep->info.errclass = MDEC_DS;
	ip->errnum = errnum;
	ip->setno = setno;
	ip->node = ((node != NULL) ? Strdup(node) : NULL);
	ip->drive = ((drive != NULL) ? Strdup(drive) : NULL);

	metacookerror(ep, name);
	return (-1);
}

/*
 * clear/attach extra context information
 */
void
mderrorextra(
	md_error_t	*ep,
	char		*extra
)
{
	if (ep->extra != NULL)
		Free(ep->extra);
	if (extra != NULL)
		ep->extra = Strdup(extra);
	else
		ep->extra = NULL;
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
	(void) memset(from, '\0', sizeof (*from));
	return (-1);
}

/*
 * do an ioctl, cook the error, and return status
 */
int
metaioctl(
	int		cmd,
	void		*data,
	md_error_t	*ep,
	char		*name
)
{
	int		fd;

	/* open admin device */
	if ((fd = open_admin(ep)) < 0)
		return (-1);

	/* do ioctl */
	mdclrerror(ep);
	if (ioctl(fd, cmd, data) != 0) {
		return (mdsyserror(ep, errno, name));
	} else if (! mdisok(ep)) {
		metacookerror(ep, name);
		return (-1);
	}

	/* return success */
	return (0);
}

/*
 * print void class errors
 */
static char *
void_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_void_error_t	*ip = &ep->info.md_error_info_t_u.void_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_NONE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "no error"));
		break;
	case MDE_UNIT_NOT_FOUND:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unit not found"));
		break;
	case MDE_DUPDRIVE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "drive specified more than once"));
		break;
	case MDE_INVAL_HSOP:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "illegal hot spare operation"));
		break;
	case MDE_NO_SET:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "no such set"));
		break;
	case MDE_SET_DIFF:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "set name is inconsistent"));
		break;
	case MDE_BAD_RD_OPT:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid read option"));
		break;
	case MDE_BAD_WR_OPT:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid write option"));
		break;
	case MDE_BAD_PASS_NUM:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid pass number"));
		break;
	case MDE_BAD_RESYNC_OPT:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid resync option"));
		break;
	case MDE_BAD_INTERLACE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid interlace"));
		break;
	case MDE_NO_HSPS:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "no hotspare pools found"));
		break;
	case MDE_NOTENOUGH_DB:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "must have at least 1 database (-f overrides)"));
		break;
	case MDE_DELDB_NOTALLOWED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "cannot delete the last database replica in the diskset"));
		break;
	case MDE_DEL_VALIDDB_NOTALLOWED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Deleting specified valid replicas results in stale "
		    "state database. Configuration changes with stale "
		    "database result in panic(-f overrides)"));
		break;
	case MDE_SYSTEM_FILE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "error in system file"));
		break;
	case MDE_MDDB_FILE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "error in mddb.cf file"));
		break;
	case MDE_MDDB_CKSUM:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "checksum error in mddb.cf file"));
		break;
	case MDE_VFSTAB_FILE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "error in vfstab file"));
		break;
	case MDE_NOSLICE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "invalid slice number for drive name"));
		break;
	case MDE_SYNTAX:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "syntax error"));
		break;
	case MDE_OPTION:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "illegal option"));
		break;
	case MDE_TAKE_OWN:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "failed to reserve any drives"));
		break;
	case MDE_NOT_DRIVENAME:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "not a valid drive name"));
		break;
	case MDE_RESERVED:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "reserved by another host"));
		break;
	case MDE_DVERSION:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "driver version mismatch"));
		break;
	case MDE_MVERSION:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "metadevice state database version mismatch"));
		break;
	case MDE_TESTERROR:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "TEST ERROR MESSAGE"));
		break;
	case MDE_BAD_ORIG_NCOL:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid column count"));
		break;
	case MDE_RAID_INVALID:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "devices were not RAIDed previously or "
		    "are specified in the wrong order"));
		break;
	case MDE_MED_ERROR:
		break;
	case MDE_TOOMANYMED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "too many mediator hosts requested"));
		break;
	case MDE_NOMED:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "no mediator hosts found"));
		break;
	case MDE_ONLYNODENAME:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "only the nodename of a host is required for deletes"));
		break;
	case MDE_RAID_BAD_PW_CNT:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "simultaneous writes out of range"));
		break;
	case MDE_DEVID_TOOBIG:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "relocation information size is greater than reported"));
		break;
	case MDE_NOPERM:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Permission denied.  You must have root privilege "
		    "to execute this command."));
		break;
	case MDE_NODEVID:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Device relocation information not available "
		    "for this device"));
		break;
	case MDE_NOROOT:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no root filesystem in /etc/mnttab"));
		break;
	case MDE_EOF_TRANS:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    MD_EOF_TRANS_MSG));
		break;
	case MDE_NOT_MN:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "option only valid within a multi-owner set"));
		break;
	case MDE_ABR_SET:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Invalid command for mirror with ABR set"));
		break;
	case MDE_INVAL_MNOP:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Invalid operation on multi-owner set"));
		break;
	case MDE_MNSET_NOTRANS:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Trans metadevice not supported on multi-owner set"));
		break;
	case MDE_MNSET_NORAID:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "RAID-5 metadevice not supported on multi-owner set"));
		break;
	case MDE_FORCE_DEL_ALL_DRV:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Must specify -f option to delete all drives from set"));
		break;
	case MDE_STRIPE_TRUNC_SINGLE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "The necessary rounding would result in data loss.  "
		    "You can avoid this by concatenating additional devices "
		    "totaling at least %s blocks, or by increasing the size "
		    "of the specified component by exactly %s blocks."),
		    ep->extra, ep->extra);
		break;
	case MDE_STRIPE_TRUNC_MULTIPLE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "The necessary rounding would result in data loss.  "
		    "You can avoid this by concatenating additional devices "
		    "totaling at least %s blocks."), ep->extra);
		break;
	case MDE_SMF_FAIL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "failed to enable/disable SVM service"));
		break;
	case MDE_SMF_NO_SERVICE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "service(s) not online in SMF"));
		break;
	case MDE_AMBIGUOUS_DEV:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Specify complete path to avoid ambiguity."));
		break;
	case MDE_NAME_IN_USE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Name already in use for metadevice or hot spare pool."));
		break;
	case MDE_NAME_ILLEGAL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Invalid name for metadevice or hot spare pool."));
		break;
	case MDE_ZONE_ADMIN:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		"Volume administration unavailable within non-global zones."));
		break;
	case MDE_MISSING_DEVID_DISK:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "device id does not exist."));
		break;
	default:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unknown void error code %d"), ip->errnum);
		break;
	}

	return (buf);
}

/*
 * print sys class errors
 */
static char *
sys_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_sys_error_t	*ip = &ep->info.md_error_info_t_u.sys_error;
	char		*emsg;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	if ((emsg = strerror(ip->errnum)) == NULL) {
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unknown errno %d out of range"),
		    ip->errnum);
	} else {
		(void) snprintf(p, psize, "%s", emsg);
	}

	return (buf);
}

/*
 * print RPC class errors
 */
static char *
rpc_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_rpc_error_t	*ip = &ep->info.md_error_info_t_u.rpc_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	(void) snprintf(p, psize, "%s", clnt_sperrno(ip->errnum));
	return (buf);
}

/*
 * print dev class errors
 */
static char *
dev_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_dev_error_t	*ip = &ep->info.md_error_info_t_u.dev_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_INVAL_HS:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "hotspare doesn't exist"));
		break;
	case MDE_FIX_INVAL_STATE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "cannot enable hotspared device"));
		break;
	case MDE_FIX_INVAL_HS_STATE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "hotspare isn't broken, can't enable"));
		break;
	case MDE_NOT_META:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "not a metadevice"));
		break;
	case MDE_IS_DUMP:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "is a dump device"));
		break;
	case MDE_IS_META:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "is a metadevice"));
		break;
	case MDE_IS_SWAPPED:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "is swapped on"));
		break;
	case MDE_NAME_SPACE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "namespace error"));
		break;
	case MDE_IN_SHARED_SET:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "device in shared set"));
		break;
	case MDE_NOT_IN_SET:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "device not in set"));
		break;
	case MDE_NOT_DISK:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "not a disk device"));
		break;
	case MDE_CANT_CONFIRM:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "can't confirm device"));
		break;
	case MDE_INVALID_PART:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid partition"));
		break;
	case MDE_HAS_MDDB:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "has a metadevice database replica"));
		break;
	case MDE_NO_DB:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no metadevice database replica on device"));
		break;
	case MDE_CANTVERIFY_VTOC:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unable to verify the vtoc"));
		break;
	case MDE_NOT_LOCAL:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "not in local set"));
		break;
	case MDE_DEVICES_NAME:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "can't parse /devices name"));
		break;
	case MDE_REPCOMP_INVAL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "replica slice is not usable as a metadevice component"));
		break;
	case MDE_REPCOMP_ONLY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "only replica slice is usable for a diskset "
		    "database replica"));
		break;
	case MDE_INV_ROOT:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "invalid root device for this operation"));
		break;
	case MDE_MULTNM:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "multiple entries for device in Solaris Volume Manager "
		    "configuration"));
		break;
	case MDE_TOO_MANY_PARTS:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Disks with more than %d partitions are not supported "
		    "in Solaris Volume Manager"), MD_MAX_PARTS);
		break;
	case MDE_REPART_REPLICA:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "cannot repartition a slice with an existing replica"));
		break;
	case MDE_DISKNAMETOOLONG:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "disk name is too long with device ids disabled "
		    "in Solaris Volume Manager. Check /kernel/drv/md.conf "
		    "for md_devid_destroy, remove it and reboot"));
		break;
	default:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unknown dev error code %d"),
		    ip->errnum);
		break;
	}

	return (buf);
}

/*
 * print overlap class errors
 */
static char *
overlap_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_overlap_error_t	*ip =
	    &ep->info.md_error_info_t_u.overlap_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_OVERLAP_MOUNTED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "overlaps with %s which is mounted as \'%s\'"),
		    ip->overlap, ip->where);
		break;
	case MDE_OVERLAP_SWAP:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "overlaps with %s which is a swap device"), ip->overlap);
		break;
	case MDE_OVERLAP_DUMP:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "overlaps with %s which is the dump device"), ip->overlap);
		break;
	default:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unknown overlap error code %d"), ip->errnum);
		break;
	}

	return (buf);
}

/*
 * print use class errors
 */
static char *
use_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_use_error_t	*ip = &ep->info.md_error_info_t_u.use_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_IS_MOUNTED:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "is mounted on %s"),
		    ip->where);
		break;
	case MDE_ALREADY:
		/*
		 * when the object of the error (existing device that
		 * would being used by SVM) is the metadb then it is necessary
		 * to explicitly specify the string in the error message so
		 * that it can be successfully localized for the Asian locales.
		 */
		if (strcmp(ip->where, MDB_STR) != 0) {
			(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
			    "has appeared more than once in the "
			    "specification of %s"), ip->where);
		} else {
			(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
			    "has appeared more than once in the "
			    "specification of " MDB_STR));
		}
		break;
	case MDE_OVERLAP:
		/*
		 * when the object of the error (existing device that
		 * would overlap) is the metadb then it is necessary
		 * to explicitly specify the string in the error message so
		 * that it can be successfully localized for the Asian locales.
		 */
		if (strcmp(ip->where, MDB_STR) != 0) {
			(void) snprintf(p, psize,
			    dgettext(TEXT_DOMAIN, "overlaps with device in %s"),
			    ip->where);
		} else {
			(void) snprintf(p, psize,
			    dgettext(TEXT_DOMAIN, "overlaps with device in "
			    MDB_STR));
		}
		break;
	case MDE_SAME_DEVID:
		/*
		 * when the object of the error (existing device in the
		 * metaconfiguration that has the same devid)
		 * is the metadb then it is necessary
		 * to explicitly specify the string in the error message so
		 * that it can be successfully localized for the Asian locales.
		 */
		if (strcmp(ip->where, MDB_STR) != 0) {
			(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
			    "identical devid detected on %s"), ip->where);
		} else {
			(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
			    "identical devid detected in " MDB_STR));
		}
		break;
	default:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unknown dev error code %d"), ip->errnum);
		break;
	}

	return (buf);
}

/*
 * print md class errors
 */
static char *
md_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_md_error_t	*ip = &ep->info.md_error_info_t_u.md_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_INVAL_UNIT:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid unit"));
		break;
	case MDE_UNIT_NOT_SETUP:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unit not set up"));
		break;
	case MDE_UNIT_ALREADY_SETUP:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unit already set up"));
		break;
	case MDE_NOT_MM:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unit is not a mirror"));
		break;
	case MDE_IS_SM:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "illegal to clear submirror"));
		break;
	case MDE_IS_OPEN:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "metadevice is open"));
		break;
	case MDE_C_WITH_INVAL_SM:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "attempted to clear mirror with submirror(s) "
		    "in invalid state"));
		break;
	case MDE_RESYNC_ACTIVE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "resync in progress"));
		break;
	case MDE_LAST_SM_RE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "attempt to replace a component on the last "
		    "running submirror"));
		break;
	case MDE_MIRROR_FULL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "mirror has maximum number of submirrors"));
		break;
	case MDE_IN_UNAVAIL_STATE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "component is in unavailable state; run 'metastat -i'"));
		break;
	case MDE_IN_USE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "metadevice in use"));
		break;
	case MDE_SM_TOO_SMALL:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "submirror too small to attach"));
		break;
	case MDE_NO_LABELED_SM:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "can't attach labeled submirror to an unlabeled mirror"));
		break;
	case MDE_SM_OPEN_ERR:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "submirror open error"));
		break;
	case MDE_CANT_FIND_SM:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "can't find submirror in mirror"));
		break;
	case MDE_LAST_SM:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "attempt to detach last running submirror"));
		break;
	case MDE_NO_READABLE_SM:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "operation would result in no readable submirrors"));
		break;
	case MDE_SM_FAILED_COMPS:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "attempt an operation on a submirror "
		    "that has erred components"));
		break;
	case MDE_ILLEGAL_SM_STATE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "attempt operation on a submirror in illegal state"));
		break;
	case MDE_RR_ALLOC_ERROR:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "attach failed, unable to allocate new resync info"));
		break;
	case MDE_MIRROR_OPEN_FAILURE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "insufficient devices to open"));
		break;
	case MDE_MIRROR_THREAD_FAILURE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "mirror thread failure"));
		break;
	case MDE_GROW_DELAYED:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "growing of metadevice delayed"));
		break;
	case MDE_NOT_MT:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unit is not a trans"));
		break;
	case MDE_HS_IN_USE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "can't modify hot spare pool, hot spare in use"));
		break;
	case MDE_HAS_LOG:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "already has log"));
		break;
	case MDE_UNKNOWN_TYPE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unknown metadevice type"));
		break;
	case MDE_NOT_STRIPE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unit is not a concat/stripe"));
		break;
	case MDE_NOT_RAID:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unit is not a RAID"));
		break;
	case MDE_NROWS:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "not enough stripes specified"));
		break;
	case MDE_NCOMPS:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "not enough components specified"));
		break;
	case MDE_NSUBMIRS:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "not enough submirrors specified"));
		break;
	case MDE_BAD_STRIPE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid stripe configuration"));
		break;
	case MDE_BAD_MIRROR:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid mirror configuration"));
		break;
	case MDE_BAD_TRANS:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid trans configuration"));
		break;
	case MDE_BAD_RAID:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "invalid RAID configuration"));
		break;
	case MDE_RAID_OPEN_FAILURE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "resync unable to open RAID unit"));
		break;
	case MDE_RAID_THREAD_FAILURE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "attempt to start resync thread failed"));
		break;
	case MDE_RAID_NEED_FORCE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "operation requires -f (force) flag"));
		break;
	case MDE_NO_LOG:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "log has already been detached"));
		break;
	case MDE_RAID_DOI:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "only valid action is metaclear"));
		break;
	case MDE_RAID_LAST_ERRED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "in Last Erred state, "
		    "errored components must be replaced"));
		break;
	case MDE_RAID_NOT_OKAY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "all components must be Okay to perform this operation"));
		break;
	case MDE_RENAME_BUSY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "metadevice is temporarily too busy for renames"));
		break;
	case MDE_RENAME_SOURCE_BAD:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "source metadevice is not able to be renamed"));
		break;
	case MDE_RENAME_TARGET_BAD:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "target metadevice is not able to be renamed"));
		break;
	case MDE_RENAME_TARGET_UNRELATED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "target metadevice is not related to source metadevice"));
		break;
	case MDE_RENAME_CONFIG_ERROR:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "metadevice driver configuration error; "
		    "rename can't occur"));
		break;
	case MDE_RENAME_ORDER:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "units may not be renamed in that order"));
		break;
	case MDE_RECOVER_FAILED:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "recovery failed"));
		break;
	case MDE_SP_NOSPACE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "not enough space available for request"));
		break;
	case MDE_SP_BADWMREAD:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "error reading extent header"));
		break;
	case MDE_SP_BADWMWRITE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "error writing extent header"));
		break;
	case MDE_SP_BADWMMAGIC:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "bad magic number in extent header"));
		break;
	case MDE_SP_BADWMCRC:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "bad checksum in extent header"));
		break;
	case MDE_NOT_SP:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unit is not a soft partition"));
		break;
	case MDE_SP_OVERLAP:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "overlapping extents specified"));
		break;
	case MDE_SP_BAD_LENGTH:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "bad length specified"));
		break;
	case MDE_SP_NOSP:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "no soft partitions on this device"));
		break;
	case MDE_UNIT_TOO_LARGE:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "Volume size cannot exceed 1 TByte"));
		break;
	case MDE_LOG_TOO_LARGE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Trans log size must be less than 1 TByte"));
		break;
	default:
		(void) snprintf(p, psize,
		    dgettext(TEXT_DOMAIN, "unknown md error code %d"),
		    ip->errnum);
		break;
	}

	return (buf);
}

/*
 * print comp class errors
 */
static char *
comp_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_comp_error_t	*ip = &ep->info.md_error_info_t_u.comp_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_CANT_FIND_COMP:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "can't find component in unit"));
		break;
	case MDE_REPL_INVAL_STATE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "component in invalid state to replace - "
		    "Replace \"Maintenance\" components first"));
		break;
	case MDE_COMP_TOO_SMALL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "replace failure, new component is too small"));
		break;
	case MDE_COMP_OPEN_ERR:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unable to open concat/stripe component"));
		break;
	case MDE_RAID_COMP_ERRED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "must replace errored component first"));
		break;
	case MDE_MAXIO:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "maxtransfer is too small"));
		break;
	case MDE_SP_COMP_OPEN_ERR:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "error opening device under soft partition. Check"
		    " device status, then use metadevadm(1M)."));
		break;
	default:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unknown comp error code %d"), ip->errnum);
		break;
	}

	return (buf);
}

/*
 * print hsp class errors
 */
static char *
hsp_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_hsp_error_t	*ip = &ep->info.md_error_info_t_u.hsp_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_HSP_CREATE_FAILURE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "hotspare pool database create failure"));
		break;
	case MDE_HSP_IN_USE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "hotspare pool in use"));
		break;
	case MDE_INVAL_HSP:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "invalid hotspare pool"));
		break;
	case MDE_HSP_BUSY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "hotspare pool is busy"));
		break;
	case MDE_HSP_REF:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "hotspare pool is referenced"));
		break;
	case MDE_HSP_ALREADY_SETUP:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "hotspare pool is already setup"));
		break;
	case MDE_BAD_HSP:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "invalid hotspare pool configuration"));
		break;
	case MDE_HSP_UNIT_TOO_LARGE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "units in the hotspare pool cannot exceed 1 TByte"));
		break;
	default:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unknown hsp error code %d"), ip->errnum);
		break;
	}

	return (buf);
}

/*
 * print hs class errors
 */
static char *
hs_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_hs_error_t	*ip = &ep->info.md_error_info_t_u.hs_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_HS_RESVD:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "hotspare is in use"));
		break;
	case MDE_HS_CREATE_FAILURE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "hotspare database create failure"));
		break;
	case MDE_HS_INUSE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "add or replace failed, hot spare is already in use"));
		break;
	case MDE_HS_UNIT_TOO_LARGE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "hotspare size cannot exceed 1 TByte"));
		break;
	default:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unknown hs error code %d"), ip->errnum);
		break;
	}

	return (buf);
}

/*
 * print mddb class errors
 */
static char *
mddb_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_mddb_error_t	*ip = &ep->info.md_error_info_t_u.mddb_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_TOOMANY_REPLICAS:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
	"%d metadevice database replicas is too many; the maximum is %d"),
		    ip->size, MDDB_NLB);
		break;
	case MDE_REPLICA_TOOSMALL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
	"device size %d is too small for metadevice database replica"),
		    ip->size);
		break;
	case MDE_NOTVERIFIED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "data not returned correctly from disk"));
		break;
	case MDE_DB_INVALID:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "invalid argument"));
		break;
	case MDE_DB_EXISTS:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "metadevice database replica exists on device"));
		break;
	case MDE_DB_MASTER:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "has bad master block on device"));
		break;
	case MDE_DB_TOOSMALL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "device is too small"));
		break;
	case MDE_DB_NORECORD:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no such metadevice database record"));
		break;
	case MDE_DB_NOSPACE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "metadevice database is full, can't create new records"));
		break;
	case MDE_DB_NOTNOW:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "metadevice database has too few replicas, for "
		    "metadevice database operation"));
		break;
	case MDE_DB_NODB:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "there are no existing databases"));
		break;
	case MDE_DB_NOTOWNER:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "not owner of metadevice database"));
		break;
	case MDE_DB_STALE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "stale databases"));
		break;
	case MDE_DB_TOOFEW:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "not enough databases"));
		break;
	case MDE_DB_TAGDATA:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "tagged data detected, user intervention required"));
		break;
	case MDE_DB_ACCOK:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "50% replicas & 50% mediator hosts available, "
		    "user intervention required"));
		break;
	case MDE_DB_NTAGDATA:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no tagged data available or only one tag found"));
		break;
	case MDE_DB_ACCNOTOK:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "50% replicas & 50% mediator hosts not available"));
		break;
	case MDE_DB_NOLOCBLK:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no valid locator blocks were found"));
		break;
	case MDE_DB_NOLOCNMS:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no valid locator name information was found"));
		break;
	case MDE_DB_NODIRBLK:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no valid directory blocks were found"));
		break;
	case MDE_DB_NOTAGREC:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no tag record was allocated, so data "
		    "tagging is disabled"));
		break;
	case MDE_DB_NOTAG:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no tag records exist or no matching tag was found"));
		break;
	case MDE_DB_BLKRANGE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "logical block number %d out of range"), ip->size);
		break;
	default:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unknown mddb error code %d"), ip->errnum);
		break;
	}

	return (buf);
}

/*
 * print diskset (ds) class errors
 */
static char *
ds_to_str(
	md_error_t	*ep,
	char		*buf,
	size_t		size
)
{
	md_ds_error_t	*ip = &ep->info.md_error_info_t_u.ds_error;
	char		*p = buf + strlen(buf);
	size_t		psize = size - strlen(buf);

	switch (ip->errnum) {
	case MDE_DS_DUPHOST:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host %s is specified more than once"), ip->node);
		break;
	case MDE_DS_NOTNODENAME:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "\"%s\" is not a nodename, but a network name"), ip->node);
		break;
	case MDE_DS_SELFNOTIN:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "nodename of host %s creating the set must be included"),
		    ip->node);
		break;
	case MDE_DS_NODEHASSET:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host %s already has set"), ip->node);
		break;
	case MDE_DS_NODENOSET:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host %s does not have set"), ip->node);
		break;
	case MDE_DS_NOOWNER:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "must be owner of the set for this command"));
		break;
	case MDE_DS_NOTOWNER:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "only the current owner %s may operate on this set"),
		    ip->node);
		break;
	case MDE_DS_NODEISNOTOWNER:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host %s is not the owner"), ip->node);
		break;
	case MDE_DS_NODEINSET:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host %s is already in the set"), ip->node);
		break;
	case MDE_DS_NODENOTINSET:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host %s is not in the set"), ip->node);
		break;
	case MDE_DS_SETNUMBUSY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host %s already has a set numbered %ld"),
		    ip->node, ip->setno);
		break;
	case MDE_DS_SETNUMNOTAVAIL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "no available set numbers"));
		break;
	case MDE_DS_SETNAMEBUSY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "set name is in-use or invalid on host %s"), ip->node);
		break;
	case MDE_DS_DRIVENOTCOMMON:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "drive %s is not common with host %s"),
		    ip->drive, ip->node);
		break;
	case MDE_DS_DRIVEINSET:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "drive %s is in set %s"), ip->drive, ip->node);
		break;
	case MDE_DS_DRIVENOTINSET:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "drive %s is not in set"), ip->drive);
		break;
	case MDE_DS_DRIVEINUSE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "drive %s is in use"), ip->drive);
		break;
	case MDE_DS_DUPDRIVE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "drive %s is specified more than once"), ip->drive);
		break;
	case MDE_DS_INVALIDSETNAME:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "set name contains invalid characters"));
		break;
	case MDE_DS_HASDRIVES:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unable to delete set, it still has drives"));
		break;
	case MDE_DS_SIDENUMNOTAVAIL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "maximum number of nodenames exceeded"));
		break;
	case MDE_DS_SETNAMETOOLONG:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "set name is too long"));
		break;
	case MDE_DS_NODENAMETOOLONG:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host name %s is too long"), ip->node);
		break;
	case MDE_DS_OHACANTDELSELF:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
"administrator host %s deletion disallowed in one host admin mode"),
		    ip->node);
		break;
	case MDE_DS_HOSTNOSIDE:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "side information missing for host %s"), ip->node);
		break;
	case MDE_DS_SETLOCKED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
	    "host %s is modifying set - try later or restart rpc.metad"),
		    ip->drive);
		break;
	case MDE_DS_ULKSBADKEY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "set unlock failed - bad key"));
		break;
	case MDE_DS_LKSBADKEY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "set lock failed - bad key"));
		break;
	case MDE_DS_WRITEWITHSULK:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "write operation attempted on set with set unlocked"));
		break;
	case MDE_DS_SETCLEANUP:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "set \"%s\" is out of date - cleaning up - take failed"),
		    ip->node);
		break;
	case MDE_DS_CANTDELSELF:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
"administrator host %s can't be deleted, other hosts still in set\n"
"Use -f to override"), ip->node);
		break;
	case MDE_DS_HASMED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unable to delete set, it still has mediator hosts"));
		break;
	case MDE_DS_TOOMANYALIAS:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "%s causes there to be more aliases than allowed"),
		    ip->node);
		break;
	case MDE_DS_ISMED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "%s is already a mediator host"), ip->node);
		break;
	case MDE_DS_ISNOTMED:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "%s is not a mediator host"), ip->node);
		break;
	case MDE_DS_INVALIDMEDNAME:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "mediator name \"%s\" contains invalid characters"),
		    ip->node);
		break;
	case MDE_DS_ALIASNOMATCH:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "mediator alias \"%s\" is not an alias for host "
		    "\"%s\""), ip->node, ip->drive);
		break;
	case MDE_DS_NOMEDONHOST:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unable to contact %s on host \"%s\""),
		    MED_SERVNAME, ip->node);
		break;
	case MDE_DS_DRIVENOTONHOST:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "drive %s is not present on host %s"),
		    ip->drive, ip->node);
		break;
	case MDE_DS_CANTDELMASTER:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "master %s can't be deleted, other hosts still in set"),
		    ip->node);
		break;
	case MDE_DS_NOTINMEMBERLIST:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "node %s is not in membership list"),
		    ip->node);
		break;
	case MDE_DS_MNCANTDELSELF:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host %s can't delete self from multi-owner set\n"
		    "while other hosts still in set"),
		    ip->node);
		break;
	case MDE_DS_RPCVERSMISMATCH:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "host %s does not support multi-owner diskset"),
		    ip->node);
		break;
	case MDE_DS_WITHDRAWMASTER:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "master host %s cannot withdraw from multi-owner diskset "
		    "when other owner nodes are still present in diskset"),
		    ip->node);
		break;
	case MDE_DS_CANTRESNARF:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "imported set could not be loaded"));
		break;
	case MDE_DS_INSUFQUORUM:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "insufficient replica quorum detected. Use "
		    "-f to force import of the set"));
		break;
	case MDE_DS_EXTENDEDNM:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "multiple namespace records detected"));
		break;
	case MDE_DS_COMMDCTL_SUSPEND_NYD:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "rpc.mdcommd on host %s is not yet drained during "
		    "suspend operation"),
		    ip->node);
		break;
	case MDE_DS_COMMDCTL_SUSPEND_FAIL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "rpc.mdcommd on host %s failed suspend operation"),
		    ip->node);
		break;
	case MDE_DS_COMMDCTL_REINIT_FAIL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "rpc.mdcommd on host %s failed reinitialization operation"),
		    ip->node);
		break;
	case MDE_DS_COMMDCTL_RESUME_FAIL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "rpc.mdcommd on host %s failed resume operation"),
		    ip->node);
		break;
	case MDE_DS_NOTNOW_RECONFIG:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "command terminated, host %s starting reconfig cycle"),
		    ip->node);
		break;
	case MDE_DS_NOTNOW_CMD:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "metaset or metadb command already running on diskset "
		    "on host %s"), ip->node);
		break;
	case MDE_DS_COMMD_SEND_FAIL:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "rpc.mdcommd on host %s failed operation"),
		    ip->node);
		break;
	case MDE_DS_MASTER_ONLY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "this command must be run on the master node of the set,"
		    " which is currently %s"), ip->node);
		break;
	case MDE_DS_SINGLEHOST:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "diskset is auto-take; cannot accept additional hosts"));
		break;
	case MDE_DS_AUTONOTSET:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "auto-take is not enabled on diskset"));
		break;
	case MDE_DS_INVALIDDEVID:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Invalid device id on drive %s on host %s"), ip->drive,
		    ip->node);
		break;
	case MDE_DS_SETNOTIMP:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Unable to import set on node %s"), ip->node);
		break;
	case MDE_DS_NOTSELFIDENTIFY:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "Drive %s won't be self identifying"), ip->drive);
		break;
	default:
		(void) snprintf(p, psize, dgettext(TEXT_DOMAIN,
		    "unknown diskset error code %d"), ip->errnum);
		break;
	}

	return (buf);
}

/*
 * convert error to printable string
 */
static char *
mde_to_str(
	md_error_t	*ep
)
{
	static char	buf[BUFSIZ];
	size_t		bufsz;

	/* intialize buf */
	buf[0] = '\0';
	bufsz  = sizeof (buf);

	/* class specific */
	switch (ep->info.errclass) {
	case MDEC_VOID:
		return (void_to_str(ep, buf, bufsz));
	case MDEC_SYS:
		return (sys_to_str(ep, buf, bufsz));
	case MDEC_RPC:
		return (rpc_to_str(ep, buf, bufsz));
	case MDEC_DEV:
		return (dev_to_str(ep, buf, bufsz));
	case MDEC_USE:
		return (use_to_str(ep, buf, bufsz));
	case MDEC_MD:
		return (md_to_str(ep, buf, bufsz));
	case MDEC_COMP:
		return (comp_to_str(ep, buf, bufsz));
	case MDEC_HSP:
		return (hsp_to_str(ep, buf, bufsz));
	case MDEC_HS:
		return (hs_to_str(ep, buf, bufsz));
	case MDEC_MDDB:
		return (mddb_to_str(ep, buf, bufsz));
	case MDEC_DS:
		return (ds_to_str(ep, buf, bufsz));
	case MDEC_OVERLAP:
		return (overlap_to_str(ep, buf, bufsz));
	default:
		(void) snprintf(buf, bufsz,
		    dgettext(TEXT_DOMAIN, "unknown error class %d"),
		    ep->info.errclass);
		return (buf);
	}
}

/*
 * print log prefix
 */
void
md_logpfx(
	FILE		*fp
)
{
	time_t		t;
	struct tm	*tm;
	char		buf[100];

	if ((time(&t) != (time_t)-1) &&
	    ((tm = localtime(&t)) != NULL) &&
	    (strftime(buf, sizeof (buf), (char *)0, tm) < sizeof (buf))) {
		(void) fprintf(fp, "%s: ", buf);
	}
	(void) fprintf(fp, "%s: ", myname);
}

/*
 * varargs sperror()
 */
/*PRINTFLIKE2*/
static char *
mde_vsperror(
	md_error_t	*ep,
	const char	*fmt,
	va_list		ap
)
{
	static char	buf[BUFSIZ];
	size_t		bufsz = sizeof (buf);
	char		*p = buf;
	char		*host1 = "";
	char		*host2 = "";
	char		*extra1 = "";
	char		*extra2 = "";
	char		*name1 = "";
	char		*name2 = "";

	/* get stuff */
	if ((ep->host != NULL) && (*(ep->host) != '\0')) {
		host1 = ep->host;
		host2 = ": ";
	}
	if ((ep->extra != NULL) && (*(ep->extra) != '\0')) {
		extra1 = ep->extra;
		extra2 = ": ";
	}
	if ((ep->name != NULL) && (*(ep->name) != '\0')) {
		name1 = ep->name;
		name2 = ": ";
	}

	/* context */
	(void) snprintf(p, bufsz, "%s%s%s%s%s%s",
	    host1, host2, extra1, extra2, name1, name2);
	p = &buf[strlen(buf)];
	bufsz -= strlen(buf);

	/* user defined part */
	if ((fmt != NULL) && (*fmt != '\0')) {
		(void) vsnprintf(p, bufsz, fmt, ap);
		p = &buf[strlen(buf)];
		bufsz = sizeof (buf) - strlen(buf);
		(void) snprintf(p, bufsz, ": ");
		p = &buf[strlen(buf)];
		bufsz = sizeof (buf) - strlen(buf);
	}

	/* error code */
	(void) snprintf(p, bufsz, "%s\n", mde_to_str(ep));

	/* return error message */
	return (buf);
}

/*
 * printf-like sperror()
 */
/*PRINTFLIKE2*/
char *
mde_sperror(
	md_error_t	*ep,
	const char	*fmt,
	...
)
{
	va_list		ap;
	char		*emsg;

	va_start(ap, fmt);
	emsg = mde_vsperror(ep, fmt, ap);
	va_end(ap);
	return (emsg);
}

/*
 * printf-like perror()
 */
/*PRINTFLIKE2*/
void
mde_perror(
	md_error_t	*ep,
	const char	*fmt,
	...
)
{
	va_list		ap;
	char		*emsg;

	/* get error message */
	va_start(ap, fmt);
	emsg = mde_vsperror(ep, fmt, ap);
	va_end(ap);
	assert((emsg != NULL) && (*emsg != '\0'));

	/* stderr */
	(void) fprintf(stderr, "%s: %s\n", myname, emsg);
	(void) fflush(stderr);

	/* metalog */
	if (metalogfp != NULL) {
		md_logpfx(metalogfp);
		(void) fprintf(metalogfp, "%s\n", emsg);
		(void) fflush(metalogfp);
		(void) fsync(fileno(metalogfp));
	}

	/* syslog */
	if (metasyslog) {
		syslog(LOG_ERR, emsg);
	}
}

/*
 * printf-like perror()
 */
/*PRINTFLIKE1*/
void
md_perror(
	const char	*fmt,
	...
)
{
	md_error_t	status = mdnullerror;
	va_list		ap;
	char		*emsg;

	/* get error message */
	(void) mdsyserror(&status, errno, NULL);
	va_start(ap, fmt);
	emsg = mde_vsperror(&status, fmt, ap);
	va_end(ap);
	assert((emsg != NULL) && (*emsg != '\0'));
	mdclrerror(&status);

	/* stderr */
	(void) fprintf(stderr, "%s: %s\n", myname, emsg);
	(void) fflush(stderr);

	/* metalog */
	if (metalogfp != NULL) {
		md_logpfx(metalogfp);
		(void) fprintf(metalogfp, "%s\n", emsg);
		(void) fflush(metalogfp);
		(void) fsync(fileno(metalogfp));
	}

	/* syslog */
	if (metasyslog) {
		syslog(LOG_ERR, emsg);
	}
}

/*
 * printf-like log
 */
/*PRINTFLIKE1*/
void
md_eprintf(
	const char	*fmt,
	...
)
{
	va_list		ap;

	/* begin */
	va_start(ap, fmt);

	/* stderr */
	(void) fprintf(stderr, "%s: ", myname);
	(void) vfprintf(stderr, fmt, ap);
	(void) fflush(stderr);

	/* metalog */
	if (metalogfp != NULL) {
		md_logpfx(metalogfp);
		(void) vfprintf(metalogfp, fmt, ap);
		(void) fflush(metalogfp);
		(void) fsync(fileno(metalogfp));
	}

	/* syslog */
	if (metasyslog) {
		vsyslog(LOG_ERR, fmt, ap);
	}

	/* end */
	va_end(ap);
}

/*
 * metaclust timing messages logging routine
 *
 * level	- The class of the message to be logged. Message will be logged
 *		  if this is less than or equal to the verbosity level.
 */
void
meta_mc_log(int level, const char *fmt, ...)
{
	va_list	args;

	va_start(args, fmt);
	/*
	 * Log all messages upto MC_LOG2 to syslog regardless of the
	 * verbosity level
	 */
	if (metasyslog && (level <= MC_LOG2)) {
		if (level <= MC_LOG1)
			(void) vsyslog(LOG_ERR, fmt, args);
		else
			(void) vsyslog(LOG_INFO, fmt, args);
	}
	/*
	 * Print all messages to stderr provided the message level is
	 * within the verbosity level
	 */
	if (level <= verbosity) {
		(void) fprintf(stderr, "%s: ", myname);
		(void) vfprintf(stderr, fmt, args);
		(void) fprintf(stderr, "\n");
		(void) fflush(stderr);
	}
	va_end(args);
}
