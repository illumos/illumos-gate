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
 * Creates and maintains a cache of slices used by SVM.
 */

#include <meta.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libintl.h>
#include <synch.h>
#include <thread.h>
#include <dlfcn.h>
#include <link.h>
#include <libsysevent.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/sysevent/eventdefs.h>

#include "libdiskmgt.h"
#include "disks_private.h"

/*
 * The list of SVM slices in use.
 */

struct svm_list {
	struct svm_list	*next;
	char		*slice;
	char		*name;
	char		*type;
};

static struct svm_list	*svm_listp = NULL;
static rwlock_t		svm_lock = DEFAULTRWLOCK;
static int		initialized = 0;
static mutex_t		init_lock = DEFAULTMUTEX;

static int	add_use_record(char *devname, char *type, char *mname);
static int	diskset_info(mdsetname_t *sp);
static int	drive_in_diskset(char *dpath, char *setname);
static void	event_handler();
static void	free_names(mdnamelist_t *nlp);
static void	free_svm(struct svm_list *listp);
static int	init_svm();
static int	load_svm();
static int	new_entry(char *sname, char *type, char *mname,
			    mdsetname_t *sp);

/*
 * Pointers to libmeta functions that we dynamically resolve.
 */
static set_t		(*mdl_get_max_sets)(md_error_t *ep);
static void		(*mdl_mdclrerror)(md_error_t *ep);
static md_error_t	*mdl_mdnullerror;
static void		(*mdl_metaflushnames)(int flush_sr_cache);
static void		(*mdl_metaflushsetname)(mdsetname_t *sp);
static void		(*mdl_metafreenamelist)(mdnamelist_t *nlp);
static void		(*mdl_metafreereplicalist)(md_replicalist_t *rlp);
static md_drive_desc	*(*mdl_metaget_drivedesc)(mdsetname_t *sp, int flags,
			    md_error_t *ep);
static mdname_t		*(*mdl_metaname)(mdsetname_t **spp, char *uname,
			    meta_device_type_t uname_type, md_error_t *ep);
static int		(*mdl_metareplicalist)(mdsetname_t *sp, int flags,
			    md_replicalist_t **rlpp, md_error_t *ep);
static mdsetname_t	*(*mdl_metasetnosetname)(set_t setno, md_error_t *ep);
static int		(*mdl_meta_get_hotspare_names)(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
static md_raid_t	*(*mdl_meta_get_raid)(mdsetname_t *sp, mdname_t *raidnp,
			    md_error_t *ep);
static int		(*mdl_meta_get_raid_names)(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
static md_sp_t		*(*mdl_meta_get_sp)(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
static int		(*mdl_meta_get_sp_names)(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
static md_stripe_t	*(*mdl_meta_get_stripe)(mdsetname_t *sp,
			    mdname_t *stripenp, md_error_t *ep);
static int		(*mdl_meta_get_stripe_names)(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
static int		(*mdl_meta_get_trans_names)(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
static void		(*mdl_meta_invalidate_name)(mdname_t *np);
static void		(*mdl_sdssc_bind_library)();

/*
 * Search the list of devices under SVM for the specified device.
 */
int
inuse_svm(char *slice, nvlist_t *attrs, int *errp)
{
	struct svm_list	*listp;
	int		found = 0;

	*errp = 0;
	if (slice == NULL) {
	    return (found);
	}

	(void) mutex_lock(&init_lock);
	if (!initialized) {
		/* dynamically load libmeta */
		if (init_svm()) {
			/*
			 * need to initialize the cluster library to
			 * avoid seg faults
			 */
			(mdl_sdssc_bind_library)();

			/* load the SVM cache */
			*errp = load_svm();

			if (*errp == 0) {
				/* start a thread to monitor the svm config */
				sysevent_handle_t *shp;
				const char *subclass_list[1];
				/*
				 * Only start the svmevent thread if
				 * we are not doing an install
				 */

				if (getenv("_LIBDISKMGT_INSTALL") == NULL) {
					shp = sysevent_bind_handle(
					    event_handler);
					if (shp != NULL) {
						subclass_list[0] = EC_SUB_ALL;
						if (sysevent_subscribe_event(
						    shp, EC_SVM_CONFIG,
						    subclass_list, 1) != 0) {
							*errp = errno;
						}
					} else {
						*errp = errno;
					}
					if (*errp) {
						/*
						 * If the sysevent thread fails,
						 * log the error but continue
						 * on. This failing to start
						 * is not catastrophic in
						 * particular for short lived
						 * consumers of libdiskmgt.
						 */
						syslog(LOG_WARNING,
						    dgettext(TEXT_DOMAIN,
						    "libdiskmgt: sysevent "
						    "thread for SVM failed "
						    "to start\n"));
						*errp = 0;
					}
				}
			}
		}

		if (*errp == 0) {
			initialized = 1;
		}
	}
	(void) mutex_unlock(&init_lock);

	(void) rw_rdlock(&svm_lock);
	listp = svm_listp;
	while (listp != NULL) {
	    if (strcmp(slice, listp->slice) == 0) {
		libdiskmgt_add_str(attrs, DM_USED_BY, DM_USE_SVM, errp);
		if (strcmp(listp->type, "mdb") == 0 ||
		    strcmp(listp->type, "hs") == 0) {

		    libdiskmgt_add_str(attrs, DM_USED_NAME, listp->type, errp);
		} else {
		    char name[MAXPATHLEN];
		    (void) snprintf(name, MAXPATHLEN, "%s:%s", listp->type,
			listp->name);
		    libdiskmgt_add_str(attrs, DM_USED_NAME, name, errp);
		}
		found = 1;
		break;
	    }
	    listp = listp->next;
	}
	(void) rw_unlock(&svm_lock);

	return (found);
}

static int
add_use_record(char *devname, char *type, char *mname)
{
	struct svm_list *sp;

	/* If prev. record is a dup, skip it. */
	if (svm_listp != NULL && strcmp(svm_listp->slice, devname) == 0 &&
	    strcmp(svm_listp->type, type) == 0) {
	    return (0);
	}

	sp = (struct svm_list *)malloc(sizeof (struct svm_list));
	if (sp == NULL) {
	    return (ENOMEM);
	}

	if ((sp->slice = strdup(devname)) == NULL) {
	    free(sp);
	    return (ENOMEM);
	}

	if ((sp->name = strdup(mname)) == NULL) {
	    free(sp->slice);
	    free(sp);
	    return (ENOMEM);
	}

	if ((sp->type = strdup(type)) == NULL) {
	    free(sp->slice);
	    free(sp->name);
	    free(sp);
	    return (ENOMEM);
	}

	sp->next = svm_listp;
	svm_listp = sp;

	return (0);
}

static int
diskset_info(mdsetname_t *sp)
{
	md_error_t		error = *mdl_mdnullerror;
	md_replicalist_t	*replica_list = NULL;
	mdnamelist_t		*trans_list = NULL;
	mdnamelist_t		*raid_list = NULL;
	mdnamelist_t		*stripe_list = NULL;
	mdnamelist_t		*sp_list = NULL;
	mdnamelist_t		*spare_list = NULL;

	if ((mdl_metareplicalist)(sp, MD_BASICNAME_OK, &replica_list, &error)
	    >= 0) {
	    md_replicalist_t	*nlp;

	    for (nlp = replica_list; nlp != NULL; nlp = nlp->rl_next) {
		if (new_entry(nlp->rl_repp->r_namep->bname, "mdb",
		    nlp->rl_repp->r_namep->cname, sp)) {
		    (mdl_metafreereplicalist)(replica_list);
		    return (ENOMEM);
		}
	    }
	    (mdl_metafreereplicalist)(replica_list);

	} else {
	    (mdl_mdclrerror)(&error);
	    /* there are no metadb's; that is ok, no need to check the rest */
	    return (0);
	}
	(mdl_mdclrerror)(&error);

	if ((mdl_meta_get_trans_names)(sp, &trans_list, 0, &error) >= 0) {
	    mdnamelist_t *nlp;

	    for (nlp = trans_list; nlp != NULL; nlp = nlp->next) {
		if (new_entry(nlp->namep->bname, "trans", nlp->namep->cname,
		    sp)) {
		    free_names(trans_list);
		    return (ENOMEM);
		}
	    }

	    free_names(trans_list);
	}
	(mdl_mdclrerror)(&error);

	if ((mdl_meta_get_raid_names)(sp, &raid_list, 0, &error) >= 0) {
	    mdnamelist_t *nlp;

	    for (nlp = raid_list; nlp != NULL; nlp = nlp->next) {
		mdname_t	*mdn;
		md_raid_t	*raid;

		mdn = (mdl_metaname)(&sp, nlp->namep->cname,
		    META_DEVICE, &error);
		(mdl_mdclrerror)(&error);
		if (mdn == NULL) {
		    continue;
		}

		raid = (mdl_meta_get_raid)(sp, mdn, &error);
		(mdl_mdclrerror)(&error);

		if (raid != NULL) {
		    int i;

		    for (i = 0; i < raid->cols.cols_len; i++) {
			if (new_entry(raid->cols.cols_val[i].colnamep->bname,
			    "raid", nlp->namep->cname, sp)) {
			    free_names(raid_list);
			    return (ENOMEM);
			}
		    }
		}
	    }

	    free_names(raid_list);
	}
	(mdl_mdclrerror)(&error);

	if ((mdl_meta_get_stripe_names)(sp, &stripe_list, 0, &error) >= 0) {
	    mdnamelist_t *nlp;

	    for (nlp = stripe_list; nlp != NULL; nlp = nlp->next) {
		mdname_t	*mdn;
		md_stripe_t	*stripe;

		mdn = (mdl_metaname)(&sp, nlp->namep->cname,
		    META_DEVICE, &error);
		(mdl_mdclrerror)(&error);
		if (mdn == NULL) {
		    continue;
		}

		stripe = (mdl_meta_get_stripe)(sp, mdn, &error);
		(mdl_mdclrerror)(&error);

		if (stripe != NULL) {
		    int i;

		    for (i = 0; i < stripe->rows.rows_len; i++) {
			md_row_t	*rowp;
			int		j;

			rowp = &stripe->rows.rows_val[i];

			for (j = 0; j < rowp->comps.comps_len; j++) {
			    md_comp_t	*component;

			    component = &rowp->comps.comps_val[j];
			    if (new_entry(component->compnamep->bname, "stripe",
				nlp->namep->cname, sp)) {
				free_names(stripe_list);
				return (ENOMEM);
			    }
			}
		    }
		}
	    }

	    free_names(stripe_list);
	}
	(mdl_mdclrerror)(&error);

	if ((mdl_meta_get_sp_names)(sp, &sp_list, 0, &error) >= 0) {
	    mdnamelist_t *nlp;

	    for (nlp = sp_list; nlp != NULL; nlp = nlp->next) {
		mdname_t	*mdn;
		md_sp_t		*soft_part;

		mdn = (mdl_metaname)(&sp, nlp->namep->cname,
		    META_DEVICE, &error);
		(mdl_mdclrerror)(&error);
		if (mdn == NULL) {
		    continue;
		}

		soft_part = (mdl_meta_get_sp)(sp, mdn, &error);
		(mdl_mdclrerror)(&error);

		if (soft_part != NULL) {
		    if (new_entry(soft_part->compnamep->bname, "sp",
			nlp->namep->cname, sp)) {
			free_names(sp_list);
			return (ENOMEM);
		    }
		}
	    }

	    free_names(sp_list);
	}
	(mdl_mdclrerror)(&error);

	if ((mdl_meta_get_hotspare_names)(sp, &spare_list, 0, &error) >= 0) {
	    mdnamelist_t *nlp;

	    for (nlp = spare_list; nlp != NULL; nlp = nlp->next) {
		if (new_entry(nlp->namep->bname, "hs", nlp->namep->cname, sp)) {
		    free_names(spare_list);
		    return (ENOMEM);
		}
	    }

	    free_names(spare_list);
	}

	(mdl_mdclrerror)(&error);

	return (0);
}

/*
 * SVM uses "drive names" (ctd name without trailing slice) for drives
 * in disksets.  Since it massages these names there is no direct correspondence
 * with the slice device names in /dev.  So, we need to massage these names
 * back to something we can match on when a slice comes in.  We create an
 * entry for each possible slice since we don't know what slices actually
 * exist.  Slice 0 & 7 are probably enough, but the user could have
 * repartitioned the drive after they added it to the diskset and removed the
 * mdb.
 */
static int
drive_in_diskset(char *dpath, char *setname)
{
	int i;
	char path[MAXPATHLEN];

	(void) strlcpy(path, dpath, sizeof (path));
	if (strncmp(path, "/dev/rdsk/", 10) == 0) {
	    /* change rdsk to dsk */
	    char *p;

	    /* start p pointing to r in rdsk */
	    for (p = path + 5; *p; p++) {
		*p = *(p + 1);
	    }
	} else if (strncmp(path, "/dev/did/rdsk/", 14) == 0) {
	    /* change rdsk to dsk */
	    char *p;

	    /* start p pointing to r in rdsk */
	    for (p = path + 9; *p; p++) {
		*p = *(p + 1);
	    }
	}

	for (i = 0; i < 8; i++) {
	    char slice[MAXPATHLEN];

	    (void) snprintf(slice, sizeof (slice), "%ss%d", path, i);
	    if (add_use_record(slice, "diskset", setname)) {
		return (ENOMEM);
	    }
	}

	return (0);
}

static void
event_handler()
{
	(void) rw_wrlock(&svm_lock);
	free_svm(svm_listp);
	svm_listp = NULL;
	(mdl_metaflushnames)(0);
	(void) load_svm();
	(void) rw_unlock(&svm_lock);
}

static void
free_names(mdnamelist_t *nlp)
{
	mdnamelist_t *p;

	for (p = nlp; p != NULL; p = p->next) {
	    (mdl_meta_invalidate_name)(p->namep);
	    p->namep = NULL;
	}
	(mdl_metafreenamelist)(nlp);
}

/*
 * Free the list of SVM entries.
 */
static void
free_svm(struct svm_list *listp) {

	struct svm_list	*nextp;

	while (listp != NULL) {
	    nextp = listp->next;
	    free((void *)listp->slice);
	    free((void *)listp->name);
	    free((void *)listp->type);
	    free((void *)listp);
	    listp = nextp;
	}
}

/*
 * Try to dynamically link the libmeta functions we need.
 */
static int
init_svm()
{
	void	*lh;

	if ((lh = dlopen("/usr/lib/libmeta.so", RTLD_NOW)) == NULL) {
	    return (0);
	}

	mdl_get_max_sets = (set_t (*)(md_error_t *))dlsym(lh, "get_max_sets");

	mdl_mdclrerror = (void(*)(md_error_t *))dlsym(lh, "mdclrerror");

	mdl_mdnullerror = (md_error_t *)dlsym(lh, "mdnullerror");

	mdl_metaflushnames = (void (*)(int))dlsym(lh, "metaflushnames");

	mdl_metaflushsetname = (void (*)(mdsetname_t *))dlsym(lh,
	    "metaflushsetname");

	mdl_metafreenamelist = (void (*)(mdnamelist_t *))dlsym(lh,
	    "metafreenamelist");

	mdl_metafreereplicalist = (void (*)(md_replicalist_t *))dlsym(lh,
	    "metafreereplicalist");

	mdl_metaget_drivedesc = (md_drive_desc *(*)(mdsetname_t *, int,
	    md_error_t *))dlsym(lh, "metaget_drivedesc");

	mdl_metaname = (mdname_t *(*)(mdsetname_t **, char *,
	    meta_device_type_t, md_error_t *))dlsym(lh, "metaname");

	mdl_metareplicalist = (int (*)(mdsetname_t *, int, md_replicalist_t **,
	    md_error_t *))dlsym(lh, "metareplicalist");

	mdl_metasetnosetname = (mdsetname_t *(*)(set_t, md_error_t *))dlsym(lh,
	    "metasetnosetname");

	mdl_meta_get_hotspare_names = (int (*)(mdsetname_t *, mdnamelist_t **,
	    int, md_error_t *))dlsym(lh, "meta_get_hotspare_names");

	mdl_meta_get_raid = (md_raid_t *(*)(mdsetname_t *, mdname_t *,
	    md_error_t *))dlsym(lh, "meta_get_raid");

	mdl_meta_get_raid_names = (int (*)(mdsetname_t *, mdnamelist_t **,
	    int, md_error_t *))dlsym(lh, "meta_get_raid_names");

	mdl_meta_get_sp = (md_sp_t *(*)(mdsetname_t *, mdname_t *,
	    md_error_t *))dlsym(lh, "meta_get_sp");

	mdl_meta_get_sp_names = (int (*)(mdsetname_t *, mdnamelist_t **,
	    int, md_error_t *))dlsym(lh, "meta_get_sp_names");

	mdl_meta_get_stripe = (md_stripe_t *(*)(mdsetname_t *, mdname_t *,
	    md_error_t *))dlsym(lh, "meta_get_stripe");

	mdl_meta_get_stripe_names = (int (*)(mdsetname_t *, mdnamelist_t **,
	    int, md_error_t *))dlsym(lh, "meta_get_stripe_names");

	mdl_meta_get_trans_names = (int (*)(mdsetname_t *, mdnamelist_t **,
	    int, md_error_t *))dlsym(lh, "meta_get_trans_names");

	mdl_meta_invalidate_name = (void (*)(mdname_t *))dlsym(lh,
	    "meta_invalidate_name");

	mdl_sdssc_bind_library = (void (*)())dlsym(lh, "sdssc_bind_library");

	return (1);
}

/*
 * Create a list of SVM devices
 */
static int
load_svm()
{
	int		max_sets;
	md_error_t	error = *mdl_mdnullerror;
	int		i;

	if ((max_sets = (mdl_get_max_sets)(&error)) == 0) {
	    return (0);
	}

	if (!mdisok(&error)) {
	    (mdl_mdclrerror)(&error);
	    return (0);
	}

	/* for each possible set number, see if we really have a diskset */
	for (i = 0; i < max_sets; i++) {
	    mdsetname_t	*sp;

	    if ((sp = (mdl_metasetnosetname)(i, &error)) == NULL) {

		if (!mdisok(&error) &&
		    mdisrpcerror(&error, RPC_PROGNOTREGISTERED)) {
		    /* metad rpc program not registered - no metasets */
		    break;
		}

		(mdl_mdclrerror)(&error);
		continue;
	    }
	    (mdl_mdclrerror)(&error);

	    /* pick up drives in disksets with no mdbs/metadevices */
	    if (sp->setno != 0) {
		md_drive_desc	*dd;

		dd = (mdl_metaget_drivedesc)(sp, MD_BASICNAME_OK | PRINT_FAST,
		    &error);
		(mdl_mdclrerror)(&error);
		for (; dd != NULL; dd = dd->dd_next) {
		    if (drive_in_diskset(dd->dd_dnp->rname, sp->setname)) {
			(mdl_metaflushsetname)(sp);
			return (ENOMEM);
		    }
		}
	    }

	    if (diskset_info(sp)) {
		(mdl_metaflushsetname)(sp);
		return (ENOMEM);
	    }

	    (mdl_metaflushsetname)(sp);
	}

	(mdl_mdclrerror)(&error);

	return (0);
}

static int
new_entry(char *sname, char *type, char *mname, mdsetname_t *sp)
{
	mdname_t	*mdn;
	md_error_t	 error = *mdl_mdnullerror;

	mdn = (mdl_metaname)(&sp, sname, UNKNOWN, &error);
	if (!mdisok(&error)) {
	    (mdl_mdclrerror)(&error);
	    return (0);
	}

	if (mdn != NULL && (
	    mdn->drivenamep->type == MDT_ACCES ||
	    mdn->drivenamep->type == MDT_COMP ||
	    mdn->drivenamep->type == MDT_FAST_COMP)) {

	    return (add_use_record(mdn->bname, type, mname));
	}

	return (0);
}
