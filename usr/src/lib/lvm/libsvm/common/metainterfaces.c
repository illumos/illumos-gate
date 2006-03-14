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

#include <stdio.h>
#include <string.h>
#include <sys/vfstab.h>
#include <meta.h>
#include <libsvm.h>
#include <svm.h>
#include <sdssc.h>


extern int mod_unload(char *modname);
static int inited = 0;

/*
 * FUNCTION: init_metalib
 *	initialize libmeta only once.
 *
 * RETURN VALUES:
 *	0 - SUCCESS
 *     -1 - FAIL
 */

static int
init_metalib()
{
	int largc = 1;
	char *largv = "libsvm";
	md_error_t status = mdnullerror;

	if (!inited) {
		if (md_init_nosig(largc, &largv, 0, 1, &status) != 0 ||
				meta_check_root(&status) != 0) {
			return (-1);
		}
		inited = 1;
	}
	return (RET_SUCCESS);
}

/*
 * FUNCTION: reset_metalib
 *
 * INPUT: ptr to md_error_t
 */

static void
reset_metalib(md_error_t *ep)
{
	inited = 0;
	(void) close_admin(ep);
}

/*
 * FUNCTION: metahalt
 *	halt the metadb
 *
 */

static void
metahalt()
{
	mdsetname_t	*sp;
	md_error_t status = mdnullerror;

	(void) init_metalib();
	if ((sp = metasetname(MD_LOCAL_NAME, &status)) == NULL) {
		return;
	}
	if (meta_lock(sp, TRUE, &status)) {
		return;
	}
	if (metaioctl(MD_HALT, NULL, &status, NULL) != 0) {
		debug_printf("metahalt(): errno %d\n",
			status.info.md_error_info_t_u.sys_error.errnum);
	}
	(void) meta_unlock(sp, &status);
	reset_metalib(&status);
}

/*
 * FUNCTION: svm_stop
 *	Halt the SDS/SVM configuration and unload md module.
 *
 * RETURN VALUES:
 *	0 - SUCCESS
 *	RET_ERROR
 */

#define	MAX_TIMEOUT 1800
int
svm_stop()
{
	int rval = RET_SUCCESS;
	int timeval = 0;
	int sleep_int = 5;

	metahalt();

	if ((rval = mod_unload(MD_MODULE)) != 0) {
		timeval += sleep_int;
		(void) sleep(sleep_int);
		while (timeval < MAX_TIMEOUT) {
			if ((rval = mod_unload(MD_MODULE)) == 0) {
				debug_printf("svm_stop(): mod_unload succeeded."
						" Time %d\n", timeval);

				break;
			}

			debug_printf("svm_stop(): mod_unload failed. Trying "
				"in  %d s (%d)\n", sleep_int, timeval);

			timeval += sleep_int;
			(void) sleep(sleep_int);
			metahalt();
		}

		if (rval != 0) {
			rval = RET_ERROR;
			debug_printf("svm_stop(): mod_unload FAILED!\n");
		}
	}

	return (rval);
}

/*
 * FUNCTION: get_rootmetadevice
 *	parses the vfstab to return the metadevice
 *
 * INPUT:
 *	mount point
 *	mdname	- pointer to string pointer that will contain the
 *		  metadevice name. Caller must free the allocated space.
 * RETURN VALUES:
 *	mdname - md root device name
 *	0 - SUCCESS
 *	!0 - FAIL
 *		> 0 errno
 *		RET_ERROR
 */

int
get_rootmetadevice(char *mntpath, char **mdname)
{
	struct	vfstab v;
	FILE	*fp;
	int	rval = RET_SUCCESS;
	char	*cp;
	char	vfstab_name[PATH_MAX + 1];

	if (mdname == NULL)
		return (EINVAL);

	*mdname = NULL;

	if (snprintf(vfstab_name, PATH_MAX + 1, "%s%s", mntpath, VFSTAB) < 0)
		return (ENOMEM);

	debug_printf("get_rootmetadevice(): mntpath %s %s\n", mntpath,
		vfstab_name);

	if ((fp = fopen(vfstab_name, "r")) == NULL) {
		rval = errno;
		return (rval);
	}

	if ((rval = getvfsfile(fp, &v, ROOT_MNTPT)) != 0) {
		goto out;
	}


	debug_printf("get_rootmetadevice(): vfs_special %s\n", v.vfs_special);
	if (strstr(v.vfs_special, ROOT_METADEVICE) == NULL) {
		/* md device not found */
		rval = RET_ERROR;
		goto out;
	}

	/* found a match fill it and return */
	cp = v.vfs_special + strlen(ROOT_METADEVICE);

	*mdname = (char *)malloc(strlen(cp) + 1);

	if (*mdname == NULL) {
		rval = ENOMEM;
		goto out;
	}
	(void) strcpy(*mdname, cp);
	debug_printf("get_rootmetadevice(): *mdname %s rval %d\n",
							*mdname, rval);
out:
	(void) fclose(fp);
	return (rval);
}

/*
 * FUNCTION: create_diskset_links
 * 	Create the diskset name symlinks in /dev/md from the diskset
 *	names found in the set records.  These are normally created
 *	in rpc.metad when you create the set but those symlinks are
 *	sitting out on the real system disk and we're running off the
 *	devfs that got created when we booted off the install image.
 */

void
create_diskset_links()
{
	int		max_sets;
	int		i;
	md_error_t	error = mdnullerror;

	/*
	 * Resolve the function pointers for libsds_sc so that we can
	 * snarf the set records.
	 */
	(void) sdssc_bind_library();
	(void) init_metalib();

	if ((max_sets = get_max_sets(&error)) == 0) {
		debug_printf("create_diskset_links(): get_max_sets failed\n");
		mdclrerror(&error);
		return;
	}

	for (i = 1; i < max_sets; i++) {
		md_set_record	*sr;
		char		setname[MAXPATHLEN];
		char		setnum[MAXPATHLEN];

		if ((sr = metad_getsetbynum(i, &error)) == NULL) {
			mdclrerror(&error);
			continue;
		}

		(void) snprintf(setname, MAXPATHLEN, "/dev/md/%s",
		    sr->sr_setname);
		(void) snprintf(setnum, MAXPATHLEN, "shared/%d", i);
		/*
		 * Ignore failures to create the symlink.  This could
		 * happen because suninstall is restartable so the
		 * symlink might have already been created.
		 */
		(void) symlink(setnum, setname);
	}
}

/*
 * FUNCTION: svm_alloc
 * 	Return a pointer to an opaque piece of zeroed memory.
 *
 * RETURN VALUES:
 *	Non null - SUCCESS
 *	NULL - FAIL
 */

svm_info_t *
svm_alloc()
{
	return ((svm_info_t *)calloc(1, sizeof (svm_info_t)));
}

/*
 * FUNCTION: svm_free
 *
 * INPUT: pointer to struct svm_info
 */

void
svm_free(svm_info_t *svmp)
{
	int i;

	if (svmp == NULL)
		return;

	for (i = 0; i < svmp->count; i++) {
		free(svmp->md_comps[i]);
	}
	free(svmp->root_md);
	free(svmp);
}

/*
 * FUNCTION: get_mdcomponents
 *	Given "uname" metadevice, return the physical components
 *      of that metadevice.
 *
 * INPUT:
 *	uname - metadevice name
 *
 * RETURN VALUES:
 *	svmp - structure containing md name and components
 *	RET_SUCCESS
 *	RET_ERROR
 *
 */

int
get_mdcomponents(char *uname, svm_info_t **svmpp)
{

	svm_info_t	*svmp;
	md_error_t	status, *ep;
	mdname_t	*namep;
	mdnamelist_t	*nlp = NULL;
	mdnamelist_t	*p;
	mdsetname_t	*sp = NULL;
	char		*strp = NULL;
	int		rval, cnt;

	rval = RET_SUCCESS;
	cnt = 0;
	status = mdnullerror;
	ep = &status;
	svmp = *svmpp;

	(void) init_metalib();

	debug_printf("get_mdcomponents(): Enter unit name %s\n", uname);

	if (((namep = metaname(&sp, uname, META_DEVICE, ep)) == NULL) ||
					(metachkmeta(namep, ep) != 0)) {
		debug_printf("get_mdcomponents(): "
				"metaname or metachkmeta failed\n");
		mdclrerror(ep);
		return (RET_ERROR);
	}

	debug_printf("get_mdcomponents(): meta_getdevs %s\n", namep->cname);

	if ((meta_getdevs(sp, namep, &nlp, ep)) < 0) {
		debug_printf("get_mdcomponents(): "
				"comp %s - meta_getdevs failed\n", uname);
		metafreenamelist(nlp);
		mdclrerror(ep);
		return (RET_ERROR);
	}

	/* compute the number of devices */

	for (p = nlp, cnt = 0; p != NULL;  p = p->next, cnt++)
		;

	/*
	 * Need to add n -1 components since slvmp already has space
	 * for one device.
	 */

	svmp = (svm_info_t *)realloc(svmp, sizeof (svm_info_t) +
		(sizeof (char *) * (cnt - 1)));

	if (svmp == NULL) {
		debug_printf("get_mdcomponents(): realloc of svmp failed\n");
		metafreenamelist(nlp);
		return (RET_ERROR);
	}


	for (p = nlp, cnt = 0; p != NULL; p = p->next, cnt++) {
		mdname_t	*devnp = p->namep;

		if ((strp = strdup(devnp->cname)) == NULL) {
			rval = RET_ERROR;
			break;
		}
		svmp->md_comps[cnt] = strp;
	}

	/* count is set to the number of devices in the list */

	svmp->count = cnt;
	svmp->root_md = strdup(uname);
	if (rval == RET_SUCCESS && svmp->root_md != NULL) {
		debug_printf("get_mdcomponents(): root_md %s count %d \n",
			svmp->root_md, svmp->count);
		for (cnt = 0; cnt < svmp->count; cnt++)
			debug_printf("get_mdcomponents(): %s\n",
							svmp->md_comps[cnt]);
	} else {
		rval = RET_ERROR;
		svm_free(svmp);
		svmp = NULL;
		debug_printf("get_mdcomponents(): malloc failed\n");

	}


	metafreenamelist(nlp);
	*svmpp = svmp;
	return (rval);
}


/*
 * FUNCTION: svm_get_components
 *	return svm_infop with the components of a metadevice.
 *
 * INPUT:
 *	md_device - eg. /dev/md/dsk/d10, /dev/md/foo/dsk/d10, or
 *			/dev/md/shared/1/dsk/d10
 *
 * RETURN:
 *	0 - SUCCESS
 *     !0 - FAIL
 */

int
svm_get_components(char *md_device, svm_info_t **svmpp)
{
	int	len;

	/*
	 * If this is a named diskset with a shared name
	 * (e.g. /dev/md/shared/1/dsk/d10) call get_mdcomponents with
	 * the diskset and metadevice name (e.g. foo/d10).
	 * Otherwise this is a regular name (e.g. /dev/md/dsk/d10 or
	 * /dev/md/foo/dsk/d10 or d10 or foo/d10) all of which
	 * get_mdcomponents can handle directly.
	 */

	len = strlen("/dev/md/shared/");
	if (strncmp(md_device, "/dev/md/shared/", len) == 0) {
	    int		numlen;
	    int		setnum;
	    char	*cp;
	    char	*slashp;
	    char	mdname[MAXPATHLEN];
	    mdsetname_t	*sp;
	    md_error_t	error = mdnullerror;

	    cp = md_device + len;

	    if ((slashp = strstr(cp, "/")) == NULL)
		return (RET_ERROR);
	    numlen = slashp - cp;
	    if (numlen >= MAXPATHLEN - 1)
		return (RET_ERROR);

	    (void) strlcpy(mdname, cp, numlen + 1);
	    /* setnum now contains the diskset number */
	    setnum = atoi(mdname);
	    if ((sp = metasetnosetname(setnum, &error)) == NULL ||
		!mdisok(&error))
		return (RET_ERROR);

	    cp = slashp + 1;
	    /* cp now pointing at dsk/... */
	    if ((slashp = strstr(cp, "/")) == NULL)
		return (RET_ERROR);

	    (void) snprintf(mdname, MAXPATHLEN, "%s/%s", sp->setname,
		slashp + 1);
	    /* mdname now contains diskset and metadevice name e.g. foo/d10 */

	    debug_printf("svm_get_components(): mdname %s\n", mdname);
	    return (get_mdcomponents(mdname, svmpp));

	} else {
	    debug_printf("svm_get_components(): md_device %s\n", md_device);
	    return (get_mdcomponents(md_device, svmpp));
	}
}
