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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * preenlib interface for SVM.
 *
 * On startup fsck attempts to check filesystems in parallel. However
 * running mutiple fscks on the same disk at the same time
 * significantly degrades the performance. fsck code avoids such
 * behavior. To analyse such patterns it needs the physical disk
 * instance. preen_build_devs provides that information for
 * filesystems that are on top of metadevices.
 */

#include <ctype.h>
#include <meta.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <zone.h>

#include <sdssc.h>

#define	MAX_N2M_ALIAS_LINE	(2*FILENAME_MAX + 1)
#define	NAME_TO_MAJOR		"/etc/name_to_major"
#define	MD_MODULE		"md"

/*
 *	Macros to produce a quoted string containing the value of a
 *	preprocessor macro. For example, if SIZE is defined to be 256,
 *	VAL2STR(SIZE) is "256". This is used to construct format
 *	strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

extern	void	preen_addunit(void *cookie, char *dname, int (*cf)(),
		    void *datap, uint_t unit);
extern	int	preen_subdev(char *name, struct dk_cinfo *dkiop, void *dp);

static	int	is_blank(char *);

/*
 * is_blank() returns 1 (true) if a line specified is composed of
 * whitespace characters only. otherwise, it returns 0 (false).
 *
 * Note. the argument (line) must be null-terminated.
 */
static int
is_blank(char *line)
{
	for (/* nothing */; *line != '\0'; line++)
		if (!isspace(*line))
			return (0);
	return (1);
}

static int
get_major_from_n2m(char *modname, int *major)
{
	FILE *fp;
	char drv[FILENAME_MAX + 1];
	int entry;
	int found = 0;
	char line[MAX_N2M_ALIAS_LINE], *cp;
	int status = 0;

	if ((fp = fopen(NAME_TO_MAJOR, "r")) == NULL) {
		return (-1);
	}

	while ((fgets(line, sizeof (line), fp) != NULL) &&
						status == 0) {
		/* cut off comments starting with '#' */
		if ((cp = strchr(line, '#')) != NULL)
			*cp = '\0';
		/* ignore comment or blank lines */
		if (is_blank(line))
			continue;
		/* sanity-check */
		if (sscanf(line, "%" VAL2STR(FILENAME_MAX) "s %d",
		    drv, &entry) != 2) {
			status = -1;
		}
		if (strcmp(drv, modname) == 0) {
			*major = entry;
			found = 1;
			break;
		}
	}

	/*
	 * if no match is found return -1
	 */
	if (found == 0)
		status = -1;

	(void) fclose(fp);
	return (status);
}

/*
 * This routine is called from preenlib the first time. It is then
 * recursively called through preen_subdev.
 *
 * The argument passed in (uname) starts with the special device from
 * /etc/vfstab. Recursive calls pass in the underlying physical device
 * names.
 */
void
preen_build_devs(
	char		*uname,		/* name of metadevice */
	struct dk_cinfo	*dkiop,		/* associated controller info */
	void		*dp		/* magic info */
)
{
	char		*setname = NULL;
	char		*tname = NULL;
	mdsetname_t	*sp;
	mdname_t	*namep;		/* metadevice name */
	mdnamelist_t	*nlp = NULL;	/* list of real devices */
	mdnamelist_t	*p;
	devid_nmlist_t	*nm_list = NULL;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		ep_valid = 0;	/* does ep contain a real error */
	struct stat	statb;
	static int	md_major = -1;
	side_t		sideno;

	/*
	 * The rest of the code in this library can't work within a
	 * non-global zone so we just return the top level metadevice back
	 * to be fscked.
	 */
	if (getzoneid() != GLOBAL_ZONEID) {
		preen_addunit(dp, dkiop->dki_dname, NULL, NULL,
		    dkiop->dki_unit);
		return;
	}

	if (stat(uname, &statb) != 0)
		return;

	if (md_major == -1 &&
		get_major_from_n2m(MD_MODULE, &md_major) != 0)
		return;

	/*
	 * If the path passed in is not a metadevice, then add that
	 * device to the list (preen_addunit) since it has to be a
	 * physical device.
	 */

	if (major(statb.st_rdev) != md_major) {
		preen_addunit(dp, dkiop->dki_dname, NULL, NULL,
		    dkiop->dki_unit);
		return;
	}
	/*
	 * Bind to the cluster library
	 */

	if (sdssc_bind_library() == SDSSC_ERROR)
		return;

	if (md_init_daemon("fsck", ep) != 0) {
		ep_valid = 1;
		goto out;
	}

	/*
	 * parse the path name to get the diskset name.
	 */
	parse_device(NULL, uname, &tname, &setname);
	Free(tname);
	if ((sp = metasetname(setname, ep)) == NULL) {
		ep_valid = 1;
		goto out;
	}

	/* check for ownership */
	if (meta_check_ownership(sp, ep) != 0) {
		/*
		 * Don't own the set but we are here implies
		 * that this is a clustered proxy device. Simply add
		 * the unit.
		 */
		preen_addunit(dp, dkiop->dki_dname, NULL, NULL,
		    dkiop->dki_unit);
		ep_valid = 1;
		goto out;
	}

	/*
	 * get list of underlying physical devices.
	 */
	if ((namep = metaname(&sp, uname, UNKNOWN, ep)) == NULL) {
		ep_valid = 1;
		goto out;
	}

	if (namep->dev == NODEV64) {
		goto out;
	}

	if (meta_getdevs(sp, namep, &nlp, ep) != 0) {
		ep_valid = 1;
		goto out;
	}

	if ((sideno = getmyside(sp, ep)) == MD_SIDEWILD) {
		ep_valid = 1;
		goto out;
	}

	/* gather and add the underlying devs */
	for (p = nlp; (p != NULL); p = p->next) {
		mdname_t	*devnp = p->namep;
		int		fd;
		struct dk_cinfo	cinfo;
		ddi_devid_t	md_did;
		char		*devname;
		char		*minor_name = NULL;
		char		mname[MAXPATHLEN];

		/*
		 * we don't want to use the rname anymore because
		 * that may have changed. Use the device id information
		 * to find the correct ctd name and open based on that.
		 * If there isn't a devid or we have a did device, then
		 * use the rname. In clustering, it's corrected for us.
		 * If no devid it's at least worth a try.
		 */
		if (((md_did = meta_getdidbykey(sp->setno, sideno,
		    devnp->key, ep)) == NULL) || ((minor_name =
		    meta_getdidminorbykey(sp->setno, sideno,
		    devnp->key, ep)) == NULL)) {
			devname = devnp->rname;
			if (md_did)
				Free(md_did);
		} else {
			if (strstr(minor_name, ",raw") == NULL) {
				(void) snprintf(mname, MAXPATHLEN, "%s,raw",
				    minor_name);
			} else {
				(void) snprintf(mname, MAXPATHLEN, "%s",
				    minor_name);
			}

			/*
			 * We need to make sure we call this with a specific
			 * mname (raw mname) so that we get the exact slice
			 * with the given device id. Otherwise we could try
			 * to open a slice that doesn't really exist.
			 */
			if (meta_deviceid_to_nmlist("/dev", md_did,
			    mname, &nm_list) != 0) {
				(void) mdsyserror(ep, errno, devnp->rname);
				ep_valid = 1;
				Free(md_did);
				Free(minor_name);
				goto out;
			}
			devname = Strdup(nm_list->devname);
			Free(md_did);
			Free(minor_name);
			devid_free_nmlist(nm_list);
		}
		/* get device name and (real) cinfo */
		if ((fd = open(devname, O_RDONLY, 0)) < 0) {
			(void) mdsyserror(ep, errno, devname);
			ep_valid = 1;
			/*
			 * We need to scan all sub devices even if some fail
			 * since exit here would end up in not finishing fsck
			 * on all devices and prevent us from going into
			 * multiuser mode.
			 */
			continue;
		}

		if (ioctl(fd, DKIOCINFO, &cinfo) != 0) {
			(void) mdsyserror(ep, errno, devname);
			(void) close(fd);
			ep_valid = 1;
			/* Continue here too. See comment from before */
			continue;
		}
		(void) close(fd);	/* sd/ssd bug */

		/*
		 * preen_subdev fails when the device name has been
		 * resolved to the physical layer. Hence it is added
		 * to preen_addunit.
		 */
		if (preen_subdev(devname, &cinfo, dp) != 0) {
			preen_addunit(dp, cinfo.dki_dname, NULL, NULL,
			    cinfo.dki_unit);
		}
	}

	/* cleanup, if we fail, just add this composite device to the list */
out:
	if (setname != NULL)
		Free(setname);
	if (ep_valid != 0) {
		mde_perror(&status, "");
		mdclrerror(&status);
	}
	metafreenamelist(nlp);
}
