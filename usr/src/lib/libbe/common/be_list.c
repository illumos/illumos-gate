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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 * Copyright 2015 Gary Mills
 * Copyright (c) 2016 Martin Matuska. All rights reserved.
 */

#include <assert.h>
#include <libintl.h>
#include <libnvpair.h>
#include <libzfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include <libbe.h>
#include <libbe_priv.h>

/*
 * Callback data used for zfs_iter calls.
 */
typedef struct list_callback_data {
	char *zpool_name;
	char *be_name;
	be_node_list_t *be_nodes_head;
	be_node_list_t *be_nodes;
	char current_be[MAXPATHLEN];
} list_callback_data_t;

/*
 * Private function prototypes
 */
static int be_add_children_callback(zfs_handle_t *zhp, void *data);
static int be_get_list_callback(zpool_handle_t *, void *);
static int be_get_node_data(zfs_handle_t *, be_node_list_t *, char *,
    const char *, char *, char *);
static int be_get_zone_node_data(be_node_list_t *, char *);
static int be_get_ds_data(zfs_handle_t *, char *, be_dataset_list_t *,
    be_node_list_t *);
static int be_get_ss_data(zfs_handle_t *, char *, be_snapshot_list_t *,
    be_node_list_t *);
static int be_sort_list(be_node_list_t **,
    int (*)(const void *, const void *));
static int be_qsort_compare_BEs_name(const void *, const void *);
static int be_qsort_compare_BEs_name_rev(const void *, const void *);
static int be_qsort_compare_BEs_date(const void *, const void *);
static int be_qsort_compare_BEs_date_rev(const void *, const void *);
static int be_qsort_compare_BEs_space(const void *, const void *);
static int be_qsort_compare_BEs_space_rev(const void *, const void *);
static int be_qsort_compare_snapshots(const void *x, const void *y);
static int be_qsort_compare_datasets(const void *x, const void *y);
static void *be_list_alloc(int *, size_t);

/*
 * Private data.
 */
static char be_container_ds[MAXPATHLEN];
static boolean_t zone_be = B_FALSE;

/* ******************************************************************** */
/*			Public Functions				*/
/* ******************************************************************** */

/*
 * Function:	be_list
 * Description:	Calls _be_list which finds all the BEs on the system and
 *		returns the datasets and snapshots belonging to each BE.
 *		Also data, such as dataset and snapshot properties,
 *		for each BE and their snapshots and datasets is
 *		returned. The data returned is as described in the
 *		be_dataset_list_t, be_snapshot_list_t and be_node_list_t
 *		structures.
 * Parameters:
 *		be_name - The name of the BE to look up.
 *			  If NULL a list of all BEs will be returned.
 *		be_nodes - A reference pointer to the list of BEs. The list
 *			   structure will be allocated by _be_list and must
 *			   be freed by a call to be_free_list. If there are no
 *			   BEs found on the system this reference will be
 *			   set to NULL.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Public
 */
int
be_list(char *be_name, be_node_list_t **be_nodes)
{
	int	ret = BE_SUCCESS;

	/* Initialize libzfs handle */
	if (!be_zfs_init())
		return (BE_ERR_INIT);

	/* Validate be_name if its not NULL */
	if (be_name != NULL) {
		if (!be_valid_be_name(be_name)) {
			be_print_err(gettext("be_list: "
			    "invalid BE name %s\n"), be_name);
			return (BE_ERR_INVAL);
		}
	}

	ret = _be_list(be_name, be_nodes);

	be_zfs_fini();

	return (ret);
}

/*
 * Function:	be_sort
 * Description:	Sort BE node list
 * Parameters:
 *		pointer to address of list head
 *		sort order type
 * Return:
 *              BE_SUCCESS - Success
 *              be_errno_t - Failure
 * Side effect:
 *		node list sorted by name
 * Scope:
 *		Public
 */
int
be_sort(be_node_list_t **be_nodes, int order)
{
	int (*compar)(const void *, const void *) = be_qsort_compare_BEs_date;

	if (be_nodes == NULL)
		return (BE_ERR_INVAL);

	switch (order) {
	case BE_SORT_UNSPECIFIED:
	case BE_SORT_DATE:
		compar = be_qsort_compare_BEs_date;
		break;
	case BE_SORT_DATE_REV:
		compar = be_qsort_compare_BEs_date_rev;
		break;
	case BE_SORT_NAME:
		compar = be_qsort_compare_BEs_name;
		break;
	case BE_SORT_NAME_REV:
		compar = be_qsort_compare_BEs_name_rev;
		break;
	case BE_SORT_SPACE:
		compar = be_qsort_compare_BEs_space;
		break;
	case BE_SORT_SPACE_REV:
		compar = be_qsort_compare_BEs_space_rev;
		break;
	default:
		be_print_err(gettext("be_sort: invalid sort order %d\n"),
		    order);
		return (BE_ERR_INVAL);
	}

	return (be_sort_list(be_nodes, compar));
}

/* ******************************************************************** */
/*			Semi-Private Functions				*/
/* ******************************************************************** */

/*
 * Function:	_be_list
 * Description:	This does the actual work described in be_list.
 * Parameters:
 *		be_name - The name of the BE to look up.
 *			  If NULL a list of all BEs will be returned.
 *		be_nodes - A reference pointer to the list of BEs. The list
 *			   structure will be allocated here and must
 *			   be freed by a call to be_free_list. If there are no
 *			   BEs found on the system this reference will be
 *			   set to NULL.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
_be_list(char *be_name, be_node_list_t **be_nodes)
{
	list_callback_data_t cb = { 0 };
	be_transaction_data_t bt = { 0 };
	int ret = BE_SUCCESS;
	int sret;
	zpool_handle_t *zphp;
	char *rpool = NULL;
	struct be_defaults be_defaults;

	if (be_nodes == NULL)
		return (BE_ERR_INVAL);

	be_get_defaults(&be_defaults);

	if (be_find_current_be(&bt) != BE_SUCCESS) {
		/*
		 * We were unable to find a currently booted BE which
		 * probably means that we're not booted in a BE envoronment.
		 * None of the BE's will be marked as the active BE.
		 */
		(void) strcpy(cb.current_be, "-");
	} else {
		(void) strncpy(cb.current_be, bt.obe_name,
		    sizeof (cb.current_be));
		rpool = bt.obe_zpool;
	}

	/*
	 * If be_name is NULL we'll look for all BE's on the system.
	 * If not then we will only return data for the specified BE.
	 */
	if (be_name != NULL)
		cb.be_name = strdup(be_name);

	if (be_defaults.be_deflt_rpool_container && rpool != NULL) {
		if ((zphp = zpool_open(g_zfs, rpool)) == NULL) {
			be_print_err(gettext("be_list: failed to "
			    "open rpool (%s): %s\n"), rpool,
			    libzfs_error_description(g_zfs));
			free(cb.be_name);
			return (zfs_err_to_be_err(g_zfs));
		}

		ret = be_get_list_callback(zphp, &cb);
	} else {
		if ((zpool_iter(g_zfs, be_get_list_callback, &cb)) != 0) {
			if (cb.be_nodes_head != NULL) {
				be_free_list(cb.be_nodes_head);
				cb.be_nodes_head = NULL;
				cb.be_nodes = NULL;
			}
			ret = BE_ERR_BE_NOENT;
		}
	}

	if (cb.be_nodes_head == NULL) {
		if (be_name != NULL)
			be_print_err(gettext("be_list: BE (%s) does not "
			    "exist\n"), be_name);
		else
			be_print_err(gettext("be_list: No BE's found\n"));
		ret = BE_ERR_BE_NOENT;
	}

	*be_nodes = cb.be_nodes_head;

	free(cb.be_name);

	sret = be_sort(be_nodes, BE_SORT_DATE);

	return ((ret == BE_SUCCESS) ? sret : ret);
}

/*
 * Function:	be_free_list
 * Description:	Frees up all the data allocated for the list of BEs,
 *		datasets and snapshots returned by be_list.
 * Parameters:
 *		be_node - be_nodes_t structure returned from call to be_list.
 * Returns:
 *		none
 * Scope:
 *		Semi-private (library wide use only)
 */
void
be_free_list(be_node_list_t *be_nodes)
{
	be_node_list_t *temp_node = NULL;
	be_node_list_t *list = be_nodes;

	while (list != NULL) {
		be_dataset_list_t *datasets = list->be_node_datasets;
		be_snapshot_list_t *snapshots = list->be_node_snapshots;

		while (datasets != NULL) {
			be_dataset_list_t *temp_ds = datasets;
			datasets = datasets->be_next_dataset;
			free(temp_ds->be_dataset_name);
			free(temp_ds->be_ds_mntpt);
			free(temp_ds->be_ds_plcy_type);
			free(temp_ds);
		}

		while (snapshots != NULL) {
			be_snapshot_list_t *temp_ss = snapshots;
			snapshots = snapshots->be_next_snapshot;
			free(temp_ss->be_snapshot_name);
			free(temp_ss->be_snapshot_type);
			free(temp_ss);
		}

		temp_node = list;
		list = list->be_next_node;
		free(temp_node->be_node_name);
		free(temp_node->be_root_ds);
		free(temp_node->be_rpool);
		free(temp_node->be_mntpt);
		free(temp_node->be_policy_type);
		free(temp_node->be_uuid_str);
		free(temp_node);
	}
}

/*
 * Function:	be_get_zone_be_list
 * Description:	Finds all the BEs for this zone on the system.
 * Parameters:
 *		zone_be_name - The name of the BE to look up.
 *              zone_be_container_ds - The dataset for the zone.
 *		zbe_nodes - A reference pointer to the list of BEs. The list
 *			   structure will be allocated here and must
 *			   be freed by a call to be_free_list. If there are no
 *			   BEs found on the system this reference will be
 *			   set to NULL.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Semi-private (library wide use only)
 */
int
be_get_zone_be_list(
/* LINTED */
	char *zone_be_name,
	char *zone_be_container_ds,
	be_node_list_t **zbe_nodes)
{
	zfs_handle_t *zhp = NULL;
	list_callback_data_t cb = { 0 };
	int ret = BE_SUCCESS;

	if (zbe_nodes == NULL)
		return (BE_ERR_INVAL);

	if (!zfs_dataset_exists(g_zfs, zone_be_container_ds,
	    ZFS_TYPE_FILESYSTEM)) {
		return (BE_ERR_BE_NOENT);
	}

	zone_be = B_TRUE;

	if ((zhp = zfs_open(g_zfs, zone_be_container_ds,
	    ZFS_TYPE_FILESYSTEM)) == NULL) {
		be_print_err(gettext("be_get_zone_be_list: failed to open "
		    "the zone BE dataset %s: %s\n"), zone_be_container_ds,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		goto cleanup;
	}

	(void) strcpy(be_container_ds, zone_be_container_ds);

	if (cb.be_nodes_head == NULL) {
		if ((cb.be_nodes_head = be_list_alloc(&ret,
		    sizeof (be_node_list_t))) == NULL) {
			ZFS_CLOSE(zhp);
			goto cleanup;
		}
		cb.be_nodes = cb.be_nodes_head;
	}
	if (ret == 0)
		ret = zfs_iter_filesystems(zhp, be_add_children_callback, &cb);
	ZFS_CLOSE(zhp);

	*zbe_nodes = cb.be_nodes_head;

cleanup:
	zone_be = B_FALSE;

	return (ret);
}

/* ******************************************************************** */
/*			Private Functions				*/
/* ******************************************************************** */

/*
 * Function:	be_get_list_callback
 * Description:	Callback function used by zfs_iter to look through all
 *		the pools on the system looking for BEs. If a BE name was
 *		specified only that BE's information will be collected and
 *		returned.
 * Parameters:
 *		zlp - handle to the first zfs dataset. (provided by the
 *		      zfs_iter_* call)
 *		data - pointer to the callback data and where we'll pass
 *		       the BE information back.
 * Returns:
 *		0 - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_get_list_callback(zpool_handle_t *zlp, void *data)
{
	list_callback_data_t *cb = (list_callback_data_t *)data;
	char be_ds[MAXPATHLEN];
	char *open_ds = NULL;
	char *rpool = NULL;
	zfs_handle_t *zhp = NULL;
	int ret = 0;

	cb->zpool_name = rpool =  (char *)zpool_get_name(zlp);

	/*
	 * Generate string for the BE container dataset
	 */
	be_make_container_ds(rpool, be_container_ds,
	    sizeof (be_container_ds));

	/*
	 * If a BE name was specified we use it's root dataset in place of
	 * the container dataset. This is because we only want to collect
	 * the information for the specified BE.
	 */
	if (cb->be_name != NULL) {
		if (!be_valid_be_name(cb->be_name))
			return (BE_ERR_INVAL);
		/*
		 * Generate string for the BE root dataset
		 */
		be_make_root_ds(rpool, cb->be_name, be_ds, sizeof (be_ds));
		open_ds = be_ds;
	} else {
		open_ds = be_container_ds;
	}

	/*
	 * Check if the dataset exists
	 */
	if (!zfs_dataset_exists(g_zfs, open_ds,
	    ZFS_TYPE_FILESYSTEM)) {
		/*
		 * The specified dataset does not exist in this pool or
		 * there are no valid BE's in this pool. Try the next zpool.
		 */
		zpool_close(zlp);
		return (0);
	}

	if ((zhp = zfs_open(g_zfs, open_ds, ZFS_TYPE_FILESYSTEM)) == NULL) {
		be_print_err(gettext("be_get_list_callback: failed to open "
		    "the BE dataset %s: %s\n"), open_ds,
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
		zpool_close(zlp);
		return (ret);
	}

	/*
	 * If a BE name was specified we iterate through the datasets
	 * and snapshots for this BE only. Otherwise we will iterate
	 * through the next level of datasets to find all the BE's
	 * within the pool
	 */
	if (cb->be_name != NULL) {
		if (cb->be_nodes_head == NULL) {
			if ((cb->be_nodes_head = be_list_alloc(&ret,
			    sizeof (be_node_list_t))) == NULL) {
				ZFS_CLOSE(zhp);
				zpool_close(zlp);
				return (ret);
			}
			cb->be_nodes = cb->be_nodes_head;
		}

		if ((ret = be_get_node_data(zhp, cb->be_nodes, cb->be_name,
		    rpool, cb->current_be, be_ds)) != BE_SUCCESS) {
			ZFS_CLOSE(zhp);
			zpool_close(zlp);
			return (ret);
		}
		ret = zfs_iter_snapshots(zhp, B_FALSE, be_add_children_callback,
		    cb);
	}

	if (ret == 0)
		ret = zfs_iter_filesystems(zhp, be_add_children_callback, cb);
	ZFS_CLOSE(zhp);

	zpool_close(zlp);
	return (ret);
}

/*
 * Function:	be_add_children_callback
 * Description:	Callback function used by zfs_iter to look through all
 *		the datasets and snapshots for each BE and add them to
 *		the lists of information to be passed back.
 * Parameters:
 *		zhp - handle to the first zfs dataset. (provided by the
 *		      zfs_iter_* call)
 *		data - pointer to the callback data and where we'll pass
 *		       the BE information back.
 * Returns:
 *		0 - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_add_children_callback(zfs_handle_t *zhp, void *data)
{
	list_callback_data_t	*cb = (list_callback_data_t *)data;
	char			*str = NULL, *ds_path = NULL;
	int			ret = 0;
	struct be_defaults be_defaults;

	be_get_defaults(&be_defaults);

	ds_path = str = strdup(zfs_get_name(zhp));

	/*
	 * get past the end of the container dataset plus the trailing "/"
	 */
	str = str + (strlen(be_container_ds) + 1);
	if (be_defaults.be_deflt_rpool_container) {
		/* just skip if invalid */
		if (!be_valid_be_name(str))
			return (BE_SUCCESS);
	}

	if (cb->be_nodes_head == NULL) {
		if ((cb->be_nodes_head = be_list_alloc(&ret,
		    sizeof (be_node_list_t))) == NULL) {
			ZFS_CLOSE(zhp);
			return (ret);
		}
		cb->be_nodes = cb->be_nodes_head;
	}

	if (zfs_get_type(zhp) == ZFS_TYPE_SNAPSHOT && !zone_be) {
		be_snapshot_list_t *snapshots = NULL;
		if (cb->be_nodes->be_node_snapshots == NULL) {
			if ((cb->be_nodes->be_node_snapshots =
			    be_list_alloc(&ret, sizeof (be_snapshot_list_t)))
			    == NULL || ret != BE_SUCCESS) {
				ZFS_CLOSE(zhp);
				return (ret);
			}
			cb->be_nodes->be_node_snapshots->be_next_snapshot =
			    NULL;
			snapshots = cb->be_nodes->be_node_snapshots;
		} else {
			for (snapshots = cb->be_nodes->be_node_snapshots;
			    snapshots != NULL;
			    snapshots = snapshots->be_next_snapshot) {
				if (snapshots->be_next_snapshot != NULL)
					continue;
				/*
				 * We're at the end of the list add the
				 * new snapshot.
				 */
				if ((snapshots->be_next_snapshot =
				    be_list_alloc(&ret,
				    sizeof (be_snapshot_list_t))) == NULL ||
				    ret != BE_SUCCESS) {
					ZFS_CLOSE(zhp);
					return (ret);
				}
				snapshots = snapshots->be_next_snapshot;
				snapshots->be_next_snapshot = NULL;
				break;
			}
		}
		if ((ret = be_get_ss_data(zhp, str, snapshots,
		    cb->be_nodes)) != BE_SUCCESS) {
			ZFS_CLOSE(zhp);
			return (ret);
		}
	} else if (strchr(str, '/') == NULL) {
		if (cb->be_nodes->be_node_name != NULL) {
			if ((cb->be_nodes->be_next_node =
			    be_list_alloc(&ret, sizeof (be_node_list_t))) ==
			    NULL || ret != BE_SUCCESS) {
				ZFS_CLOSE(zhp);
				return (ret);
			}
			cb->be_nodes = cb->be_nodes->be_next_node;
			cb->be_nodes->be_next_node = NULL;
		}

		/*
		 * If this is a zone root dataset then we only need
		 * the name of the zone BE at this point. We grab that
		 * and return.
		 */
		if (zone_be) {
			ret = be_get_zone_node_data(cb->be_nodes, str);
			ZFS_CLOSE(zhp);
			return (ret);
		}

		if ((ret = be_get_node_data(zhp, cb->be_nodes, str,
		    cb->zpool_name, cb->current_be, ds_path)) != BE_SUCCESS) {
			ZFS_CLOSE(zhp);
			return (ret);
		}
	} else if (strchr(str, '/') != NULL && !zone_be) {
		be_dataset_list_t *datasets = NULL;
		if (cb->be_nodes->be_node_datasets == NULL) {
			if ((cb->be_nodes->be_node_datasets =
			    be_list_alloc(&ret, sizeof (be_dataset_list_t)))
			    == NULL || ret != BE_SUCCESS) {
				ZFS_CLOSE(zhp);
				return (ret);
			}
			cb->be_nodes->be_node_datasets->be_next_dataset = NULL;
			datasets = cb->be_nodes->be_node_datasets;
		} else {
			for (datasets = cb->be_nodes->be_node_datasets;
			    datasets != NULL;
			    datasets = datasets->be_next_dataset) {
				if (datasets->be_next_dataset != NULL)
					continue;
				/*
				 * We're at the end of the list add
				 * the new dataset.
				 */
				if ((datasets->be_next_dataset =
				    be_list_alloc(&ret,
				    sizeof (be_dataset_list_t)))
				    == NULL || ret != BE_SUCCESS) {
					ZFS_CLOSE(zhp);
					return (ret);
				}
				datasets = datasets->be_next_dataset;
				datasets->be_next_dataset = NULL;
				break;
			}
		}

		if ((ret = be_get_ds_data(zhp, str,
		    datasets, cb->be_nodes)) != BE_SUCCESS) {
			ZFS_CLOSE(zhp);
			return (ret);
		}
	}
	ret = zfs_iter_children(zhp, be_add_children_callback, cb);
	if (ret != 0) {
		be_print_err(gettext("be_add_children_callback: "
		    "encountered error: %s\n"),
		    libzfs_error_description(g_zfs));
		ret = zfs_err_to_be_err(g_zfs);
	}
	ZFS_CLOSE(zhp);
	return (ret);
}

/*
 * Function:	be_sort_list
 * Description:	Sort BE node list
 * Parameters:
 *		pointer to address of list head
 *		compare function
 * Return:
 *              BE_SUCCESS - Success
 *              be_errno_t - Failure
 * Side effect:
 *		node list sorted by name
 * Scope:
 *		Private
 */
static int
be_sort_list(be_node_list_t **pstart, int (*compar)(const void *, const void *))
{
	int ret = BE_SUCCESS;
	size_t ibe, nbe;
	be_node_list_t *p = NULL;
	be_node_list_t **ptrlist = NULL;
	be_node_list_t **ptrtmp;

	if (pstart == NULL) /* Nothing to sort */
		return (BE_SUCCESS);
	/* build array of linked list BE struct pointers */
	for (p = *pstart, nbe = 0; p != NULL; nbe++, p = p->be_next_node) {
		ptrtmp = realloc(ptrlist,
		    sizeof (be_node_list_t *) * (nbe + 2));
		if (ptrtmp == NULL) { /* out of memory */
			be_print_err(gettext("be_sort_list: memory "
			    "allocation failed\n"));
			ret = BE_ERR_NOMEM;
			goto free;
		}
		ptrlist = ptrtmp;
		ptrlist[nbe] = p;
	}
	if (nbe == 0) /* Nothing to sort */
		return (BE_SUCCESS);
	/* in-place list quicksort using qsort(3C) */
	if (nbe > 1)	/* no sort if less than 2 BEs */
		qsort(ptrlist, nbe, sizeof (be_node_list_t *), compar);

	ptrlist[nbe] = NULL; /* add linked list terminator */
	*pstart = ptrlist[0]; /* set new linked list header */
	/* for each BE in list */
	for (ibe = 0; ibe < nbe; ibe++) {
		size_t k, ns;	/* subordinate index, count */

		/* rewrite list pointer chain, including terminator */
		ptrlist[ibe]->be_next_node = ptrlist[ibe + 1];
		/* sort subordinate snapshots */
		if (ptrlist[ibe]->be_node_num_snapshots > 1) {
			const size_t nmax = ptrlist[ibe]->be_node_num_snapshots;
			be_snapshot_list_t ** const slist =
			    malloc(sizeof (be_snapshot_list_t *) * (nmax + 1));
			be_snapshot_list_t *p;

			if (slist == NULL) {
				ret = BE_ERR_NOMEM;
				continue;
			}
			/* build array of linked list snapshot struct ptrs */
			for (ns = 0, p = ptrlist[ibe]->be_node_snapshots;
			    ns < nmax && p != NULL;
			    ns++, p = p->be_next_snapshot) {
				slist[ns] = p;
			}
			if (ns < 2)
				goto end_snapshot;
			slist[ns] = NULL; /* add terminator */
			/* in-place list quicksort using qsort(3C) */
			qsort(slist, ns, sizeof (be_snapshot_list_t *),
			    be_qsort_compare_snapshots);
			/* rewrite list pointer chain, including terminator */
			ptrlist[ibe]->be_node_snapshots = slist[0];
			for (k = 0; k < ns; k++)
				slist[k]->be_next_snapshot = slist[k + 1];
end_snapshot:
			free(slist);
		}
		/* sort subordinate datasets */
		if (ptrlist[ibe]->be_node_num_datasets > 1) {
			const size_t nmax = ptrlist[ibe]->be_node_num_datasets;
			be_dataset_list_t ** const slist =
			    malloc(sizeof (be_dataset_list_t *) * (nmax + 1));
			be_dataset_list_t *p;

			if (slist == NULL) {
				ret = BE_ERR_NOMEM;
				continue;
			}
			/* build array of linked list dataset struct ptrs */
			for (ns = 0, p = ptrlist[ibe]->be_node_datasets;
			    ns < nmax && p != NULL;
			    ns++, p = p->be_next_dataset) {
				slist[ns] = p;
			}
			if (ns < 2) /* subordinate datasets < 2 - no sort */
				goto end_dataset;
			slist[ns] = NULL; /* add terminator */
			/* in-place list quicksort using qsort(3C) */
			qsort(slist, ns, sizeof (be_dataset_list_t *),
			    be_qsort_compare_datasets);
			/* rewrite list pointer chain, including terminator */
			ptrlist[ibe]->be_node_datasets = slist[0];
			for (k = 0; k < ns; k++)
				slist[k]->be_next_dataset = slist[k + 1];
end_dataset:
			free(slist);
		}
	}
free:
	free(ptrlist);
	return (ret);
}

/*
 * Function:	be_qsort_compare_BEs_date
 * Description:	compare BE creation times for qsort(3C)
 *		will sort BE list from oldest to most recent
 * Parameters:
 *		x,y - BEs with names to compare
 * Returns:
 *		positive if x>y, negative if y>x, 0 if equal
 * Scope:
 *		Private
 */
static int
be_qsort_compare_BEs_date(const void *x, const void *y)
{
	be_node_list_t *p = *(be_node_list_t **)x;
	be_node_list_t *q = *(be_node_list_t **)y;

	assert(p != NULL);
	assert(q != NULL);

	if (p->be_node_creation > q->be_node_creation)
		return (1);
	if (p->be_node_creation < q->be_node_creation)
		return (-1);
	return (0);
}

/*
 * Function:	be_qsort_compare_BEs_date_rev
 * Description:	compare BE creation times for qsort(3C)
 *		will sort BE list from recent to oldest
 * Parameters:
 *		x,y - BEs with names to compare
 * Returns:
 *		positive if y>x, negative if x>y, 0 if equal
 * Scope:
 *		Private
 */
static int
be_qsort_compare_BEs_date_rev(const void *x, const void *y)
{
	return (be_qsort_compare_BEs_date(y, x));
}

/*
 * Function:	be_qsort_compare_BEs_name
 * Description:	lexical compare of BE names for qsort(3C)
 * Parameters:
 *		x,y - BEs with names to compare
 * Returns:
 *		positive if x>y, negative if y>x, 0 if equal
 * Scope:
 *		Private
 */
static int
be_qsort_compare_BEs_name(const void *x, const void *y)
{
	be_node_list_t *p = *(be_node_list_t **)x;
	be_node_list_t *q = *(be_node_list_t **)y;

	assert(p != NULL);
	assert(p->be_node_name != NULL);
	assert(q != NULL);
	assert(q->be_node_name != NULL);

	return (strcmp(p->be_node_name, q->be_node_name));
}

/*
 * Function:	be_qsort_compare_BEs_name_rev
 * Description:	reverse lexical compare of BE names for qsort(3C)
 * Parameters:
 *		x,y - BEs with names to compare
 * Returns:
 *		positive if y>x, negative if x>y, 0 if equal
 * Scope:
 *		Private
 */
static int
be_qsort_compare_BEs_name_rev(const void *x, const void *y)
{
	return (be_qsort_compare_BEs_name(y, x));
}

/*
 * Function:	be_qsort_compare_BEs_space
 * Description:	compare BE sizes for qsort(3C)
 *		will sort BE list in growing order
 * Parameters:
 *		x,y - BEs with names to compare
 * Returns:
 *		positive if x>y, negative if y>x, 0 if equal
 * Scope:
 *		Private
 */
static int
be_qsort_compare_BEs_space(const void *x, const void *y)
{
	be_node_list_t *p = *(be_node_list_t **)x;
	be_node_list_t *q = *(be_node_list_t **)y;

	assert(p != NULL);
	assert(q != NULL);

	if (p->be_space_used > q->be_space_used)
		return (1);
	if (p->be_space_used < q->be_space_used)
		return (-1);
	return (0);
}

/*
 * Function:	be_qsort_compare_BEs_space_rev
 * Description:	compare BE sizes for qsort(3C)
 *		will sort BE list in shrinking
 * Parameters:
 *		x,y - BEs with names to compare
 * Returns:
 *		positive if y>x, negative if x>y, 0 if equal
 * Scope:
 *		Private
 */
static int
be_qsort_compare_BEs_space_rev(const void *x, const void *y)
{
	return (be_qsort_compare_BEs_space(y, x));
}

/*
 * Function:	be_qsort_compare_snapshots
 * Description:	lexical compare of BE names for qsort(3C)
 * Parameters:
 *		x,y - BE snapshots with names to compare
 * Returns:
 *		positive if y>x, negative if x>y, 0 if equal
 * Scope:
 *		Private
 */
static int
be_qsort_compare_snapshots(const void *x, const void *y)
{
	be_snapshot_list_t *p = *(be_snapshot_list_t **)x;
	be_snapshot_list_t *q = *(be_snapshot_list_t **)y;

	if (p == NULL || p->be_snapshot_name == NULL)
		return (1);
	if (q == NULL || q->be_snapshot_name == NULL)
		return (-1);
	return (strcmp(p->be_snapshot_name, q->be_snapshot_name));
}

/*
 * Function:	be_qsort_compare_datasets
 * Description:	lexical compare of dataset names for qsort(3C)
 * Parameters:
 *		x,y - BE snapshots with names to compare
 * Returns:
 *		positive if y>x, negative if x>y, 0 if equal
 * Scope:
 *		Private
 */
static int
be_qsort_compare_datasets(const void *x, const void *y)
{
	be_dataset_list_t *p = *(be_dataset_list_t **)x;
	be_dataset_list_t *q = *(be_dataset_list_t **)y;

	if (p == NULL || p->be_dataset_name == NULL)
		return (1);
	if (q == NULL || q->be_dataset_name == NULL)
		return (-1);
	return (strcmp(p->be_dataset_name, q->be_dataset_name));
}

/*
 * Function:	be_get_node_data
 * Description:	Helper function used to collect all the information to fill
 *		in the be_node_list structure to be returned by be_list.
 * Parameters:
 *		zhp - Handle to the root dataset for the BE whose information
 *		      we're collecting.
 *		be_node - a pointer to the node structure we're filling in.
 *		be_name - The BE name of the node whose information we're
 *		          collecting.
 *		current_be - the name of the currently active BE.
 *		be_ds - The dataset name for the BE.
 *
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_get_node_data(
	zfs_handle_t *zhp,
	be_node_list_t *be_node,
	char *be_name,
	const char *rpool,
	char *current_be,
	char *be_ds)
{
	char prop_buf[MAXPATHLEN];
	nvlist_t *userprops = NULL;
	nvlist_t *propval = NULL;
	nvlist_t *zone_propval = NULL;
	char *prop_str = NULL;
	char *zone_prop_str = NULL;
	char *grub_default_bootfs = NULL;
	zpool_handle_t *zphp = NULL;
	int err = 0;

	if (be_node == NULL || be_name == NULL || current_be == NULL ||
	    be_ds == NULL) {
		be_print_err(gettext("be_get_node_data: invalid arguments, "
		    "can not be NULL\n"));
		return (BE_ERR_INVAL);
	}

	errno = 0;

	be_node->be_root_ds = strdup(be_ds);
	if ((err = errno) != 0 || be_node->be_root_ds == NULL) {
		be_print_err(gettext("be_get_node_data: failed to "
		    "copy root dataset name\n"));
		return (errno_to_be_err(err));
	}

	be_node->be_node_name = strdup(be_name);
	if ((err = errno) != 0 || be_node->be_node_name == NULL) {
		be_print_err(gettext("be_get_node_data: failed to "
		    "copy BE name\n"));
		return (errno_to_be_err(err));
	}
	if (strncmp(be_name, current_be, MAXPATHLEN) == 0)
		be_node->be_active = B_TRUE;
	else
		be_node->be_active = B_FALSE;

	be_node->be_rpool = strdup(rpool);
	if (be_node->be_rpool == NULL || (err = errno) != 0) {
		be_print_err(gettext("be_get_node_data: failed to "
		    "copy root pool name\n"));
		return (errno_to_be_err(err));
	}

	be_node->be_space_used = zfs_prop_get_int(zhp, ZFS_PROP_USED);

	if (getzoneid() == GLOBAL_ZONEID) {
		if ((zphp = zpool_open(g_zfs, rpool)) == NULL) {
			be_print_err(gettext("be_get_node_data: failed to open "
			    "pool (%s): %s\n"), rpool,
			    libzfs_error_description(g_zfs));
			return (zfs_err_to_be_err(g_zfs));
		}

		(void) zpool_get_prop(zphp, ZPOOL_PROP_BOOTFS, prop_buf,
		    ZFS_MAXPROPLEN, NULL, B_FALSE);
		if (be_has_grub() && (be_default_grub_bootfs(rpool,
		    &grub_default_bootfs) == BE_SUCCESS) &&
		    grub_default_bootfs != NULL)
			if (strcmp(grub_default_bootfs, be_ds) == 0)
				be_node->be_active_on_boot = B_TRUE;
			else
				be_node->be_active_on_boot = B_FALSE;
		else if (prop_buf != NULL && strcmp(prop_buf, be_ds) == 0)
			be_node->be_active_on_boot = B_TRUE;
		else
			be_node->be_active_on_boot = B_FALSE;

		be_node->be_global_active = B_TRUE;

		free(grub_default_bootfs);
		zpool_close(zphp);
	} else {
		if (be_zone_compare_uuids(be_node->be_root_ds))
			be_node->be_global_active = B_TRUE;
		else
			be_node->be_global_active = B_FALSE;
	}

	/*
	 * If the dataset is mounted use the mount point
	 * returned from the zfs_is_mounted call. If the
	 * dataset is not mounted then pull the mount
	 * point information out of the zfs properties.
	 */
	be_node->be_mounted = zfs_is_mounted(zhp,
	    &(be_node->be_mntpt));
	if (!be_node->be_mounted) {
		if (zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, prop_buf,
		    ZFS_MAXPROPLEN, NULL, NULL, 0, B_FALSE) == 0)
			be_node->be_mntpt = strdup(prop_buf);
		else
			return (zfs_err_to_be_err(g_zfs));
	}

	be_node->be_node_creation = (time_t)zfs_prop_get_int(zhp,
	    ZFS_PROP_CREATION);

	/* Get all user properties used for libbe */
	if ((userprops = zfs_get_user_props(zhp)) == NULL) {
		be_node->be_policy_type = strdup(be_default_policy());
	} else {
		if (getzoneid() != GLOBAL_ZONEID) {
			if (nvlist_lookup_nvlist(userprops,
			    BE_ZONE_ACTIVE_PROPERTY, &zone_propval) != 0 ||
			    zone_propval == NULL) {
				be_node->be_active_on_boot = B_FALSE;
			} else {
				verify(nvlist_lookup_string(zone_propval,
				    ZPROP_VALUE, &zone_prop_str) == 0);
				if (strcmp(zone_prop_str, "on") == 0) {
					be_node->be_active_on_boot = B_TRUE;
				} else {
					be_node->be_active_on_boot = B_FALSE;
				}
			}
		}

		if (nvlist_lookup_nvlist(userprops, BE_POLICY_PROPERTY,
		    &propval) != 0 || propval == NULL) {
			be_node->be_policy_type =
			    strdup(be_default_policy());
		} else {
			verify(nvlist_lookup_string(propval, ZPROP_VALUE,
			    &prop_str) == 0);
			if (prop_str == NULL || strcmp(prop_str, "-") == 0 ||
			    strcmp(prop_str, "") == 0)
				be_node->be_policy_type =
				    strdup(be_default_policy());
			else
				be_node->be_policy_type = strdup(prop_str);
		}
		if (getzoneid() != GLOBAL_ZONEID) {
			if (nvlist_lookup_nvlist(userprops,
			    BE_ZONE_PARENTBE_PROPERTY, &propval) != 0 &&
			    nvlist_lookup_string(propval, ZPROP_VALUE,
			    &prop_str) == 0) {
				be_node->be_uuid_str = strdup(prop_str);
			}
		} else {
			if (nvlist_lookup_nvlist(userprops, BE_UUID_PROPERTY,
			    &propval) == 0 && nvlist_lookup_string(propval,
			    ZPROP_VALUE, &prop_str) == 0) {
				be_node->be_uuid_str = strdup(prop_str);
			}
		}
	}

	/*
	 * Increment the dataset counter to include the root dataset
	 * of the BE.
	 */
	be_node->be_node_num_datasets++;

	return (BE_SUCCESS);
}

/*
 * Function:	be_get_ds_data
 * Description:	Helper function used by be_add_children_callback to collect
 *		the dataset related information that will be returned by
 *		be_list.
 * Parameters:
 *		zhp - Handle to the zfs dataset whose information we're
 *		      collecting.
 *		name - The name of the dataset we're processing.
 *		dataset - A pointer to the be_dataset_list structure
 *			  we're filling in.
 *		node - The node structure that this dataset belongs to.
 * Return:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_get_ds_data(
	zfs_handle_t *zfshp,
	char *name,
	be_dataset_list_t *dataset,
	be_node_list_t *node)
{
	char			prop_buf[ZFS_MAXPROPLEN];
	nvlist_t		*propval = NULL;
	nvlist_t		*userprops = NULL;
	char			*prop_str = NULL;
	int			err = 0;

	if (zfshp == NULL || name == NULL || dataset == NULL || node == NULL) {
		be_print_err(gettext("be_get_ds_data: invalid arguments, "
		    "can not be NULL\n"));
		return (BE_ERR_INVAL);
	}

	errno = 0;

	dataset->be_dataset_name = strdup(name);
	if ((err = errno) != 0) {
		be_print_err(gettext("be_get_ds_data: failed to copy "
		    "dataset name\n"));
		return (errno_to_be_err(err));
	}

	dataset->be_ds_space_used = zfs_prop_get_int(zfshp, ZFS_PROP_USED);

	/*
	 * If the dataset is mounted use the mount point
	 * returned from the zfs_is_mounted call. If the
	 * dataset is not mounted then pull the mount
	 * point information out of the zfs properties.
	 */
	if (!(dataset->be_ds_mounted = zfs_is_mounted(zfshp,
	    &(dataset->be_ds_mntpt)))) {
		if (zfs_prop_get(zfshp, ZFS_PROP_MOUNTPOINT,
		    prop_buf, ZFS_MAXPROPLEN, NULL, NULL, 0,
		    B_FALSE) == 0)
			dataset->be_ds_mntpt = strdup(prop_buf);
		else
			return (zfs_err_to_be_err(g_zfs));
	}
	dataset->be_ds_creation =
	    (time_t)zfs_prop_get_int(zfshp, ZFS_PROP_CREATION);

	/*
	 * Get the user property used for the libbe
	 * cleaup policy
	 */
	if ((userprops = zfs_get_user_props(zfshp)) == NULL) {
		dataset->be_ds_plcy_type =
		    strdup(node->be_policy_type);
	} else {
		if (nvlist_lookup_nvlist(userprops,
		    BE_POLICY_PROPERTY, &propval) != 0 ||
		    propval == NULL) {
			dataset->be_ds_plcy_type =
			    strdup(node->be_policy_type);
		} else {
			verify(nvlist_lookup_string(propval,
			    ZPROP_VALUE, &prop_str) == 0);
			if (prop_str == NULL ||
			    strcmp(prop_str, "-") == 0 ||
			    strcmp(prop_str, "") == 0)
				dataset->be_ds_plcy_type
				    = strdup(node->be_policy_type);
			else
				dataset->be_ds_plcy_type = strdup(prop_str);
		}
	}

	node->be_node_num_datasets++;
	return (BE_SUCCESS);
}

/*
 * Function:	be_get_ss_data
 * Description: Helper function used by be_add_children_callback to collect
 *		the dataset related information that will be returned by
 *		be_list.
 * Parameters:
 *		zhp - Handle to the zfs snapshot whose information we're
 *		      collecting.
 *		name - The name of the snapshot we're processing.
 *		shapshot - A pointer to the be_snapshot_list structure
 *			   we're filling in.
 *		node - The node structure that this snapshot belongs to.
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 */
static int
be_get_ss_data(
	zfs_handle_t *zfshp,
	char *name,
	be_snapshot_list_t *snapshot,
	be_node_list_t *node)
{
	nvlist_t	*propval = NULL;
	nvlist_t	*userprops = NULL;
	char		*prop_str = NULL;
	int		err = 0;

	if (zfshp == NULL || name == NULL || snapshot == NULL || node == NULL) {
		be_print_err(gettext("be_get_ss_data: invalid arguments, "
		    "can not be NULL\n"));
		return (BE_ERR_INVAL);
	}

	errno = 0;

	snapshot->be_snapshot_name = strdup(name);
	if ((err = errno) != 0) {
		be_print_err(gettext("be_get_ss_data: failed to copy name\n"));
		return (errno_to_be_err(err));
	}

	snapshot->be_snapshot_creation = (time_t)zfs_prop_get_int(zfshp,
	    ZFS_PROP_CREATION);

	/*
	 * Try to get this snapshot's cleanup policy from its
	 * user properties first.  If not there, use default
	 * cleanup policy.
	 */
	if ((userprops = zfs_get_user_props(zfshp)) != NULL &&
	    nvlist_lookup_nvlist(userprops, BE_POLICY_PROPERTY,
	    &propval) == 0 && nvlist_lookup_string(propval,
	    ZPROP_VALUE, &prop_str) == 0) {
		snapshot->be_snapshot_type =
		    strdup(prop_str);
	} else {
		snapshot->be_snapshot_type =
		    strdup(be_default_policy());
	}

	snapshot->be_snapshot_space_used = zfs_prop_get_int(zfshp,
	    ZFS_PROP_USED);

	node->be_node_num_snapshots++;
	return (BE_SUCCESS);
}

/*
 * Function:	be_list_alloc
 * Description: Helper function used to allocate memory for the various
 *		sructures that make up a BE node.
 * Parameters:
 *		err - Used to return any errors encountered.
 *			BE_SUCCESS - Success
 *			BE_ERR_NOMEM - Allocation failure
 *		size - The size of memory to allocate.
 * Returns:
 *		Success - A pointer to the allocated memory
 * 		Failure - NULL
 * Scope:
 *		Private
 */
static void*
be_list_alloc(int *err, size_t size)
{
	void *bep = NULL;

	bep = calloc(1, size);
	if (bep == NULL) {
		be_print_err(gettext("be_list_alloc: memory "
		    "allocation failed\n"));
		*err = BE_ERR_NOMEM;
	}
	*err = BE_SUCCESS;
	return (bep);
}

/*
 * Function:	be_get_zone_node_data
 * Description:	Helper function used to collect all the information to
 *		fill in the be_node_list structure to be returned by
 *              be_get_zone_list.
 * Parameters:
 *		be_node - a pointer to the node structure we're filling in.
 *		be_name - The BE name of the node whose information we're
 * Returns:
 *		BE_SUCCESS - Success
 *		be_errno_t - Failure
 * Scope:
 *		Private
 *
 * NOTE: This function currently only collects the zone BE name but when
 *       support for beadm/libbe in a zone is provided it will need to fill
 *       in the rest of the information needed for a zone BE.
 */
static int
be_get_zone_node_data(be_node_list_t *be_node, char *be_name)
{
	if ((be_node->be_node_name = strdup(be_name)) != NULL)
		return (BE_SUCCESS);
	return (BE_ERR_NOMEM);
}
