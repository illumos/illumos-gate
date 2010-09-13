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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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
 * MH ioctl functions
 */

#include <meta.h>
#include <metamhd.h>
#include <string.h>

#include "meta_runtime.h"

#define	DEFAULTDEV "/dev/rdsk"
/*
 * default timeout values
 */
mhd_mhiargs_t	defmhiargs = {
	1000,			/* failfast */
	{ 6000, 6000, 30000 }	/* take ownership */
};

/* RPC timeouts */
static md_timeval32_t	tk_own_timeout  = { 24 * 60 * 60, 0 };	/* 1 day */
static md_timeval32_t	rel_own_timeout = { 24 * 60 * 60, 0 };	/* 1 day */

/*
 * RPC handle
 */
typedef struct {
	char	*hostname;
	CLIENT	*clientp;
} mhd_handle_t;

/*
 * close RPC connection
 */
static void
close_metamhd(
	mhd_handle_t	*hp
)
{
	assert(hp != NULL);
	if (hp->hostname != NULL) {
		Free(hp->hostname);
	}
	if (hp->clientp != NULL) {
		auth_destroy(hp->clientp->cl_auth);
		clnt_destroy(hp->clientp);
	}
	Free(hp);
}

/*
 * open RPC connection to rpc.metamhd
 */
static mhd_handle_t *
open_metamhd(
	char		*hostname,
	md_error_t	*ep
)
{
	CLIENT		*clientp;
	mhd_handle_t	*hp;

	/* default to local host */
	if ((hostname == NULL) || (*hostname == '\0'))
		hostname = mynode();

	/* open RPC connection */
	assert(hostname != NULL);
	if ((clientp = meta_client_create(hostname, METAMHD, METAMHD_VERSION,
	    "tcp")) == NULL) {
		clnt_pcreateerror(hostname);
		(void) mdrpccreateerror(ep, hostname, "metamhd clnt_create");
		return (NULL);
	} else {
		auth_destroy(clientp->cl_auth);
		clientp->cl_auth = authsys_create_default();
		assert(clientp->cl_auth != NULL);
	}

	/* return connection */
	hp = Zalloc(sizeof (*hp));
	hp->hostname = Strdup(hostname);
	hp->clientp = clientp;
	return (hp);
}

/*
 * steal and convert mherror_t
 */
int
mhstealerror(
	mhd_error_t	*mhep,
	md_error_t	*ep
)
{
	int		rval = -1;

	/* no error */
	if (mhep->errnum == 0) {
		/* assert(mhep->name == NULL); */
		rval = 0;
		goto out;
	}

	/* steal error */
	switch (mhep->errnum) {
	case MHD_E_MAJORITY:
		(void) mderror(ep, MDE_TAKE_OWN, mhep->name);
		break;
	case MHD_E_RESERVED:
		(void) mderror(ep, MDE_RESERVED, mhep->name);
		break;
	default:
		(void) mdsyserror(ep, mhep->errnum, mhep->name);
		break;
	}

	/* cleanup, return success */
out:
	if (mhep->name != NULL)
		Free(mhep->name);
	(void) memset(mhep, 0, sizeof (*mhep));
	return (rval);
}

/*
 * should we do MHIOCTLs ?
 */
static int
do_mhioctl()
{
	if (getenv("MD_NOMHIOCTL") != NULL) {
		(void) fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "NOT doing MH ioctls\n"));
		(void) fflush(stderr);
		return (0);
	}
	return (1);
}

/*
 * take ownership of drives
 */
int
meta_take_own(
	char			*sname,
	mddrivenamelist_t	*dnlp,
	mhd_mhiargs_t		*mhiargsp,
	int			partial_set,
	md_error_t		*ep
)
{
	mddrivenamelist_t	*p;
	uint_t			ndev = 0;
	mhd_tkown_args_t	args;
	mhd_error_t		mherror;
	mhd_set_t		*mhsp = &args.set;
	uint_t			i;
	char			*e;
	mhd_handle_t		*hp = NULL;
	int			rval = -1;

	/*
	 * RFE 4126509.  Check the runtime parameters to see if
	 * they're set to disable MHIOCTKOWN ioctl() operations
	 * on the disks.  If so, return immediately without
	 * performing the operations.
	 */

	if (do_owner_ioctls() == B_FALSE) {
		return (0);
	}

	/* count drives, get set */
	for (p = dnlp; (p != NULL); p = p->next)
		++ndev;
	if (ndev == 0)
		return (0);

	/* initialize */
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&mherror, 0, sizeof (mherror));

	/* build arguments */
	mhsp->setname = Strdup(sname);
	mhsp->drives.drives_len = ndev;
	mhsp->drives.drives_val
	    = Calloc(ndev, sizeof (*mhsp->drives.drives_val));
	for (p = dnlp, i = 0; (i < ndev); p = p->next, ++i) {
		mhsp->drives.drives_val[i] = Strdup(p->drivenamep->rname);
	}
	args.timeouts = *mhiargsp;
	args.ff_mode = MHD_FF_DRIVER;
	if (((e = getenv("MD_DEBUG")) != NULL) &&
	    ((e = strstr(e, "FAILFAST=")) != NULL) &&
	    ((e = strchr(e, '=')) != NULL)) {
		++e;
		if (strcmp(e, "NONE") == 0)
			args.ff_mode = MHD_FF_NONE;
		else if (strcmp(e, "DRIVER") == 0)
			args.ff_mode = MHD_FF_DRIVER;
		else if (strcmp(e, "DEBUG") == 0)
			args.ff_mode = MHD_FF_DEBUG;
		else if (strcmp(e, "HALT") == 0)
			args.ff_mode = MHD_FF_HALT;
		else if (strcmp(e, "PANIC") == 0)
			args.ff_mode = MHD_FF_PANIC;
	}
	if (partial_set)
		args.options |= MHD_PARTIAL_SET;
	if (((e = getenv("MD_DEBUG")) != NULL) &&
	    (strstr(e, "NOTHREAD") != NULL)) {
		args.options |= MHD_SERIAL;
	}

	/* open connection */
	if ((hp = open_metamhd(NULL, ep)) == NULL)
		return (-1);
	clnt_control(hp->clientp, CLSET_TIMEOUT, (char *)&tk_own_timeout);

	/* take ownership */
	if (mhd_tkown_1(&args, &mherror, hp->clientp) != RPC_SUCCESS) {
		(void) mdrpcerror(ep, hp->clientp, hp->hostname,
		    "metamhd tkown");
	} else if (mhstealerror(&mherror, ep) == 0) {
		rval = 0;	/* success */
	}

	/* cleanup, return success */
out:
	xdr_free(xdr_mhd_tkown_args_t, (char *)&args);
	xdr_free(xdr_mhd_error_t, (char *)&mherror);
	if (hp != NULL)
		close_metamhd(hp);
	return (rval);
}

/*
 * take ownership of drives
 */
int
tk_own_bydd(
	mdsetname_t		*sp,
	md_drive_desc		*ddlp,
	mhd_mhiargs_t		*mhiargsp,
	int			partial_set,
	md_error_t		*ep
)
{
	mddrivenamelist_t	*dnlp = NULL;
	mddrivenamelist_t	**tailpp = &dnlp;
	md_drive_desc		*p;
	int			rval;

	/*
	 * Add the drivename struct to the end of the
	 * drivenamelist but keep a pointer to the last
	 * element so that we don't incur the overhead
	 * of traversing the list each time
	 */
	for (p = ddlp; (p != NULL); p = p->dd_next)
		tailpp = meta_drivenamelist_append_wrapper(tailpp, p->dd_dnp);

	/* take ownership */
	rval = meta_take_own(sp->setname, dnlp, mhiargsp, partial_set, ep);

	/* cleanup, return success */
	metafreedrivenamelist(dnlp);
	return (rval);
}

/*
 * release ownership of drives
 */
int
meta_rel_own(
	char			*sname,
	mddrivenamelist_t	*dnlp,
	int			partial_set,
	md_error_t		*ep
)
{
	mddrivenamelist_t	*p;
	uint_t			ndev = 0;
	mhd_relown_args_t	args;
	mhd_error_t		mherror;
	mhd_set_t		*mhsp = &args.set;
	uint_t			i;
	char			*e;
	mhd_handle_t		*hp = NULL;
	int			rval = -1;

	/*
	 * RFE 4126509.  Check the runtime parameters to see if
	 * they're set to disable MHIOCRELEASE and MHIOCENFAILFAST
	 * ioctl() operations on the disks.  If so, return
	 * immediately without performing the operations.
	 */

	if (do_owner_ioctls() == B_FALSE) {
		return (0);
	}

	/*
	 * if not doing ioctls (HK 98/10/28: the following code tests
	 * an environment variable, and was apparently inserted to
	 * make testing easier.)
	 */

	if (! do_mhioctl())
		return (0);

	/* count drives, get set */
	for (p = dnlp; (p != NULL); p = p->next)
		++ndev;
	if (ndev == 0)
		return (0);

	/* initialize */
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&mherror, 0, sizeof (mherror));

	/* build arguments */
	mhsp->setname = Strdup(sname);
	mhsp->drives.drives_len = ndev;
	mhsp->drives.drives_val
	    = Calloc(ndev, sizeof (*mhsp->drives.drives_val));
	for (p = dnlp, i = 0; (i < ndev); p = p->next, ++i) {
		mhsp->drives.drives_val[i] = Strdup(p->drivenamep->rname);
	}
	if (partial_set)
		args.options |= MHD_PARTIAL_SET;
	if (((e = getenv("MD_DEBUG")) != NULL) &&
	    (strstr(e, "NOTHREAD") != NULL)) {
		args.options |= MHD_SERIAL;
	}

	/* open connection */
	if ((hp = open_metamhd(NULL, ep)) == NULL)
		return (-1);
	clnt_control(hp->clientp, CLSET_TIMEOUT, (char *)&rel_own_timeout);

	/* take ownership */
	if (mhd_relown_1(&args, &mherror, hp->clientp) != RPC_SUCCESS) {
		(void) mdrpcerror(ep, hp->clientp, hp->hostname,
		    "metamhd relown");
	} else if (mhstealerror(&mherror, ep) == 0) {
		rval = 0;	/* success */
	}

	/* cleanup, return success */
out:
	xdr_free(xdr_mhd_relown_args_t, (char *)&args);
	xdr_free(xdr_mhd_error_t, (char *)&mherror);
	if (hp != NULL)
		close_metamhd(hp);
	return (rval);
}

/*
 * release ownership of drives
 */
int
rel_own_bydd(
	mdsetname_t		*sp,
	md_drive_desc		*ddlp,
	int			partial_set,
	md_error_t		*ep
)
{
	mddrivenamelist_t	*dnlp = NULL;
	mddrivenamelist_t	**tailpp = &dnlp;
	md_drive_desc		*p;
	int			rval;

	/*
	 * Add the drivename struct to the end of the
	 * drivenamelist but keep a pointer to the last
	 * element so that we don't incur the overhead
	 * of traversing the list each time
	 */
	for (p = ddlp; (p != NULL); p = p->dd_next)
		tailpp = meta_drivenamelist_append_wrapper(tailpp, p->dd_dnp);

	/* release ownership */
	rval = meta_rel_own(sp->setname, dnlp, partial_set, ep);

	/* cleanup, return success */
	metafreedrivenamelist(dnlp);
	return (rval);
}

/*
 * get status of drives
 */
int
meta_status_own(
	char			*sname,
	md_disk_status_list_t	*dslp,
	int			partial_set,
	md_error_t		*ep
)
{
	md_disk_status_list_t	*p;
	uint_t			ndev = 0;
	mhd_status_args_t	args;
	mhd_status_res_t	results;
	mhd_error_t		*mhep = &results.status;
	mhd_set_t		*mhsp = &args.set;
	uint_t			i;
	char			*e;
	mhd_handle_t		*hp = NULL;
	int			rval = -1;

	/* if not doing ioctls */
	if (! do_mhioctl())
		return (0);

	/* count drives, get set */
	for (p = dslp; (p != NULL); p = p->next)
		++ndev;
	if (ndev == 0)
		return (0);

	/* initialize */
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&results, 0, sizeof (results));

	/* build arguments */
	mhsp->setname = Strdup(sname);
	mhsp->drives.drives_len = ndev;
	mhsp->drives.drives_val
	    = Calloc(ndev, sizeof (*mhsp->drives.drives_val));
	for (p = dslp, i = 0; (i < ndev); p = p->next, ++i) {
		mhsp->drives.drives_val[i] = Strdup(p->drivenamep->rname);
	}
	if (partial_set)
		args.options |= MHD_PARTIAL_SET;
	if (((e = getenv("MD_DEBUG")) != NULL) &&
	    (strstr(e, "NOTHREAD") != NULL)) {
		args.options |= MHD_SERIAL;
	}

	/* open connection */
	if ((hp = open_metamhd(NULL, ep)) == NULL)
		return (-1);
	clnt_control(hp->clientp, CLSET_TIMEOUT, (char *)&tk_own_timeout);

	/* get status */
	if (mhd_status_1(&args, &results, hp->clientp) != RPC_SUCCESS) {
		(void) mdrpcerror(ep, hp->clientp, hp->hostname,
		    dgettext(TEXT_DOMAIN, "metamhd status"));
		goto out;
	} else if (mhstealerror(mhep, ep) != 0) {
		goto out;
	}

	/* do something with it */
	assert(results.results.results_len == ndev);
	for (p = dslp, i = 0; (i < ndev); p = p->next, ++i) {
		mhd_drive_status_t	*resp = &results.results.results_val[i];
		mddrivename_t		*dp = p->drivenamep;
		mhd_error_t		mherror;

		/* make sure we have the right drive */
		assert(strcmp(dp->rname, resp->drive) == 0);

		/* copy status */
		if (resp->errnum != 0) {
			(void) memset(&mherror, 0, sizeof (mherror));
			mherror.errnum = resp->errnum;
			mherror.name = Strdup(resp->drive);
			(void) mhstealerror(&mherror, &p->status);
		}
	}
	rval = 0;		/* success */

	/* cleanup, return success */
out:
	xdr_free(xdr_mhd_status_args_t, (char *)&args);
	xdr_free(xdr_mhd_status_res_t, (char *)&results);
	if (hp != NULL)
		close_metamhd(hp);
	return (rval);
}

/*
 * build disk status list from drivename list
 */
md_disk_status_list_t *
meta_drive_to_disk_status_list(
	mddrivenamelist_t	*dnlp
)
{
	md_disk_status_list_t	*head = NULL;
	md_disk_status_list_t	**tailp = &head;
	mddrivenamelist_t	*p;

	/* copy list */
	for (p = dnlp; (p != NULL); p = p->next) {
		md_disk_status_list_t	*dsp;

		dsp = *tailp = Zalloc(sizeof (*dsp));
		tailp = &dsp->next;
		dsp->drivenamep = p->drivenamep;
	}

	/* return list */
	return (head);
}

/*
 * free disk status list
 */
void
meta_free_disk_status_list(
	md_disk_status_list_t	*dslp
)
{
	md_disk_status_list_t	*next = NULL;

	for (/* void */; (dslp != NULL); dslp = next) {
		next = dslp->next;
		mdclrerror(&dslp->status);
		Free(dslp);
	}
}

/*
 * free drive info list
 */
void
meta_free_drive_info_list(
	mhd_drive_info_list_t	*listp
)
{
	xdr_free(xdr_mhd_drive_info_list_t, (char *)listp);
	(void) memset(listp, 0, sizeof (*listp));
}

/*
 * sort drive info list
 */
static int
compare_drives(
	const void		*p1,
	const void		*p2
)
{
	const mhd_drive_info_t	*di1 = p1;
	const mhd_drive_info_t	*di2 = p2;
	const char		*n1 = di1->dif_name;
	const char		*n2 = di2->dif_name;
	uint_t			c1 = 0, t1 = 0, d1 = 0, s1 = 0;
	uint_t			c2 = 0, t2 = 0, d2 = 0, s2 = 0;
	uint_t			l, cl;

	if (n1 == NULL)
		n1 = "";
	if (n2 == NULL)
		n2 = "";

	/* attempt to sort correctly for c0t1d0s0 .vs. c0t18d0s0 */
	if ((n1 = strrchr(n1, '/')) == NULL)
		goto u;
	n1 += (n1[1] != 'c') ? 2 : 1;
	cl = strlen(n1);
	if ((sscanf(n1, "c%ut%ud%us%u%n", &c1, &t1, &d1, &s1, &l) != 4 &&
	    sscanf(n1, "c%ud%us%u%n", &c1, &d1, &s1, &l) != 3 &&
	    sscanf(n1, "c%ut%ud%u%n", &c1, &t1, &d1, &l) != 3 &&
	    sscanf(n1, "c%ud%u%n", &c1, &d1, &l) != 2) || (l != cl))
		goto u;

	if ((n2 = strrchr(n2, '/')) == NULL)
		goto u;
	n2 += (n2[1] != 'c') ? 2 : 1;
	cl = strlen(n2);
	if ((sscanf(n2, "c%ut%ud%us%u%n", &c2, &t2, &d2, &s2, &l) != 4 &&
	    sscanf(n2, "c%ud%us%u%n", &c2, &d2, &s2, &l) != 3 &&
	    sscanf(n2, "c%ut%ud%u%n", &c2, &t2, &d2, &l) != 3 &&
	    sscanf(n2, "c%ud%u%n", &c2, &d2, &l) != 2) || (l != cl))
		goto u;
	if (c1 != c2)
		return ((c1 > c2) ? 1 : -1);
	if (t1 != t2)
		return ((t1 > t2) ? 1 : -1);
	if (d1 != d2)
		return ((d1 > d2) ? 1 : -1);
	if (s1 != s2)
		return ((s1 > s2) ? 1 : -1);
	return (0);

u:	return (strcmp(di1->dif_name, di2->dif_name));
}

static void
sort_drives(
	mhd_drive_info_list_t	*listp
)
{
	qsort(listp->mhd_drive_info_list_t_val,
	    listp->mhd_drive_info_list_t_len,
	    sizeof (*listp->mhd_drive_info_list_t_val),
	    compare_drives);
}

/*
 * return list of all drives
 */
int
meta_list_drives(
	char			*hostname,
	char			*path,
	mhd_did_flags_t		flags,
	mhd_drive_info_list_t	*listp,
	md_error_t		*ep
)
{
	mhd_list_args_t		args;
	mhd_list_res_t		results;
	mhd_error_t		*mhep = &results.status;
	mhd_handle_t		*hp = NULL;
	int			rval = -1;

	/* if not doing ioctls */
	if (! do_mhioctl())
		return (0);

	/* initialize */
	(void) memset(&args, 0, sizeof (args));
	(void) memset(&results, 0, sizeof (results));

	/* build arguments */
	if (path == NULL)
		path = getenv("MD_DRIVE_ROOT");
	if ((path != NULL) && (*path != '\0'))
		args.path = Strdup(path);
	args.flags = flags;

	/* open connection */
	if ((hp = open_metamhd(hostname, ep)) == NULL)
		return (-1);
	clnt_control(hp->clientp, CLSET_TIMEOUT, (char *)&tk_own_timeout);

	/* get list */
	if (mhd_list_1(&args, &results, hp->clientp) != RPC_SUCCESS) {
		(void) mdrpcerror(ep, hp->clientp, hp->hostname,
		    dgettext(TEXT_DOMAIN, "metamhd list"));
		goto out;
	} else if (mhstealerror(mhep, ep) != 0) {
		goto out;
	}

	/* sort list */
	sort_drives(&results.results);

	/* steal list */
	*listp = results.results;
	results.results.mhd_drive_info_list_t_len = 0;
	results.results.mhd_drive_info_list_t_val = NULL;
	rval = listp->mhd_drive_info_list_t_len;	/* success */

	/* cleanup, return success */
out:
	xdr_free(xdr_mhd_list_args_t, (char *)&args);
	xdr_free(xdr_mhd_list_res_t, (char *)&results);
	if (hp != NULL)
		close_metamhd(hp);
	return (rval);
}

static void
load_paths_to_metamhd()
{
	FILE			*cfp;		/* config file pointer */
	char			buf[BUFSIZ],
				*p,
				*x;
	mhd_drive_info_list_t	list;
	md_error_t		ep;
	mhd_did_flags_t		flags = MHD_DID_SERIAL;

	if ((cfp = fopen(METADEVPATH, "r")) != NULL) {
		/*
		 * Read each line from the file. Lines will be either
		 * comments or path names to pass to rpc.metamhd. If
		 * path names check to see if their a colon seperate
		 * list of names which must be processed one at a time.
		 */

		while (fgets(buf, BUFSIZ, cfp) != NULL) {
			if (buf[0] == '#') {
				/*
				 * Ignore comment lines
				 */
				continue;

			} else if (strchr(buf, ':') != NULL) {
				p = buf;
				while ((x = strchr(p, ':')) != NULL) {
					*x = '\0';
					(void) memset(&ep, '\0', sizeof (ep));
					(void) meta_list_drives(NULL, p, 0,
					    &list, &ep);
					meta_free_drive_info_list(&list);
					p = x + 1;
				}
				/*
				 * We won't pick up the last path name
				 * because the line ends with a newline
				 * not a ':'. So p will still point to
				 * a valid path in this case. Copy the
				 * data that p points to to the beginning
				 * of the buf and let the default case
				 * handle this buffer.
				 * NOTE:
				 * If the file does end with a ":\n", p at
				 * will point to the newline. The default
				 * cause would then set the newline to a
				 * NULL which is okay because meta_list_drives
				 * interprets a null string as /dev/rdsk.
				 */
				(void) memcpy(buf, p, strlen(p));
			}
			/*
			 * Remove any newlines in the buffer.
			 */
			if ((p = strchr(buf, '\n')) != NULL)
				*p = '\0';
			(void) memset(&ep, '\0', sizeof (ep));
			(void) memset(&list, '\0', sizeof (list));
			(void) meta_list_drives(NULL, buf, flags, &list, &ep);
			meta_free_drive_info_list(&list);
		}
		(void) fclose(cfp);
	}
}

/*
 * build list of all drives in set
 */
/*ARGSUSED*/
int
meta_get_drive_names(
	mdsetname_t		*sp,
	mddrivenamelist_t	**dnlpp,
	int			options,
	md_error_t		*ep
)
{
	mhd_did_flags_t		flags = MHD_DID_SERIAL;
	mhd_drive_info_list_t	list;
	mhd_drive_info_t	*mp;
	uint_t			i;
	unsigned		cnt = 0;
	int			rval = -1;
	mddrivenamelist_t	**tailpp = dnlpp;

	/* must have a set */
	assert(sp != NULL);

	load_paths_to_metamhd();
	(void) memset(&list, 0, sizeof (list));
	if ((meta_list_drives(NULL, NULL, flags, &list, ep)) < 0)
		return (-1);

	/* find drives in set */
	for (i = 0; (i < list.mhd_drive_info_list_t_len); ++i) {
		mddrivename_t		*dnp;
		mdname_t		*np;

		mp = &list.mhd_drive_info_list_t_val[i];

		if (mp->dif_id.did_flags & MHD_DID_DUPLICATE)
			continue;

		/* quietly skip drives which don't conform */
		if ((dnp = metadrivename(&sp, mp->dif_name, ep)) == NULL) {
			mdclrerror(ep);
			continue;
		}

		/* check in set */
		if ((np = metaslicename(dnp, MD_SLICE0, ep)) == NULL)
			goto out;
		if (meta_check_inset(sp, np, ep) != 0) {
			mdclrerror(ep);
			continue;
		}

		/*
		 * Add the drivename struct to the end of the
		 * drivenamelist but keep a pointer to the last
		 * element so that we don't incur the overhead
		 * of traversing the list each time
		 */
		tailpp = meta_drivenamelist_append_wrapper(tailpp, dnp);
		++cnt;
	}
	rval = cnt;

	/* cleanup, return error */
out:
	meta_free_drive_info_list(&list);
	return (rval);
}
