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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <locale.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <zone.h>
#include <sys/crypto/ioctladmin.h>
#include "cryptoadm.h"

#define	DEFAULT_DEV_NUM 5
#define	DEFAULT_SOFT_NUM 10

static crypto_get_soft_info_t *setup_get_soft_info(char *, int);

/*
 * Prepare the argument for the LOAD_SOFT_CONFIG ioctl call for the
 * provider pointed by pent.  Return NULL if out of memory.
 */
crypto_load_soft_config_t *
setup_soft_conf(entry_t *pent)
{
	crypto_load_soft_config_t	*pload_soft_conf;
	mechlist_t	*plist;
	uint_t		sup_count;
	size_t		extra_mech_size = 0;
	int		i;

	if (pent == NULL) {
		return (NULL);
	}

	sup_count = pent->sup_count;
	if (sup_count > 1) {
		extra_mech_size = sizeof (crypto_mech_name_t) *
		    (sup_count - 1);
	}

	pload_soft_conf = malloc(sizeof (crypto_load_soft_config_t) +
	    extra_mech_size);
	if (pload_soft_conf == NULL) {
		cryptodebug("out of memory.");
		return (NULL);
	}

	(void) strlcpy(pload_soft_conf->sc_name, pent->name, MAXNAMELEN);
	pload_soft_conf->sc_count = sup_count;

	i = 0;
	plist =  pent->suplist;
	while (i < sup_count) {
		(void) strlcpy(pload_soft_conf->sc_list[i++],
		    plist->name, CRYPTO_MAX_MECH_NAME);
		plist = plist->next;
	}

	return (pload_soft_conf);
}


/*
 * Prepare the argument for the LOAD_SOFT_DISABLED ioctl call for the
 * provider pointed by pent.  Return NULL if out of memory.
 */
crypto_load_soft_disabled_t *
setup_soft_dis(entry_t *pent)
{
	crypto_load_soft_disabled_t	*pload_soft_dis = NULL;
	mechlist_t	*plist = NULL;
	size_t		extra_mech_size = 0;
	uint_t		dis_count;
	int		i;

	if (pent == NULL) {
		return (NULL);
	}

	dis_count = pent->dis_count;
	if (dis_count > 1) {
		extra_mech_size = sizeof (crypto_mech_name_t) *
		    (dis_count - 1);
	}

	pload_soft_dis = malloc(sizeof (crypto_load_soft_disabled_t) +
	    extra_mech_size);
	if (pload_soft_dis == NULL) {
		cryptodebug("out of memory.");
		return (NULL);
	}

	(void) strlcpy(pload_soft_dis->sd_name, pent->name, MAXNAMELEN);
	pload_soft_dis->sd_count = dis_count;

	i = 0;
	plist =  pent->dislist;
	while (i < dis_count) {
		(void) strlcpy(pload_soft_dis->sd_list[i++],
		    plist->name, CRYPTO_MAX_MECH_NAME);
		plist = plist->next;
	}

	return (pload_soft_dis);
}


/*
 * Prepare the argument for the LOAD_DEV_DISABLED ioctl call for the
 * provider pointed by pent.  Return NULL if out of memory.
 */
crypto_load_dev_disabled_t *
setup_dev_dis(entry_t *pent)
{
	crypto_load_dev_disabled_t	*pload_dev_dis = NULL;
	mechlist_t	*plist = NULL;
	size_t		extra_mech_size = 0;
	uint_t		dis_count;
	int		i;
	char		pname[MAXNAMELEN];
	int		inst_num;

	if (pent == NULL) {
		return (NULL);
	}

	/* get the device name and the instance number */
	if (split_hw_provname(pent->name, pname, &inst_num) == FAILURE) {
		return (NULL);
	}

	/* allocate space for pload_dev_des */
	dis_count = pent->dis_count;
	if (dis_count > 1) {
		extra_mech_size = sizeof (crypto_mech_name_t) *
		    (dis_count - 1);
	}

	pload_dev_dis = malloc(sizeof (crypto_load_dev_disabled_t) +
	    extra_mech_size);
	if (pload_dev_dis == NULL) {
		cryptodebug("out of memory.");
		return (NULL);
	}

	/* set the values for pload_dev_dis */
	(void) strlcpy(pload_dev_dis->dd_dev_name, pname, MAXNAMELEN);
	pload_dev_dis->dd_dev_instance = inst_num;
	pload_dev_dis->dd_count = dis_count;

	i = 0;
	plist =  pent->dislist;
	while (i < dis_count) {
		(void) strlcpy(pload_dev_dis->dd_list[i++],
		    plist->name, CRYPTO_MAX_MECH_NAME);
		plist = plist->next;
	}

	return (pload_dev_dis);
}


/*
 * Prepare the calling argument of the UNLOAD_SOFT_MODULE ioctl call for the
 * provider pointed by pent.  Return NULL if out of memory.
 */
crypto_unload_soft_module_t *
setup_unload_soft(entry_t *pent)
{
	crypto_unload_soft_module_t *punload_soft;

	if (pent == NULL) {
		return (NULL);
	}

	punload_soft = malloc(sizeof (crypto_unload_soft_module_t));
	if (punload_soft == NULL) {
		cryptodebug("out of memory.");
		return (NULL);
	}

	(void) strlcpy(punload_soft->sm_name, pent->name, MAXNAMELEN);

	return (punload_soft);
}


/*
 * Prepare the calling argument for the GET_SOFT_INFO call for the provider
 * with the number of mechanisms specified in the second argument.
 *
 * Called by get_soft_info().
 */
static crypto_get_soft_info_t *
setup_get_soft_info(char *provname, int count)
{
	crypto_get_soft_info_t	*psoft_info;
	size_t			extra_mech_size = 0;

	if (provname == NULL) {
		return (NULL);
	}

	if (count > 1) {
		extra_mech_size = sizeof (crypto_mech_name_t) * (count - 1);
	}

	psoft_info = malloc(sizeof (crypto_get_soft_info_t) + extra_mech_size);
	if (psoft_info == NULL) {
		cryptodebug("out of memory.");
		return (NULL);
	}

	(void) strlcpy(psoft_info->si_name, provname, MAXNAMELEN);
	psoft_info->si_count = count;

	return (psoft_info);
}


/*
 * Get the device list from kernel.
 */
int
get_dev_list(crypto_get_dev_list_t **ppdevlist)
{
	crypto_get_dev_list_t	*pdevlist;
	int			fd = -1;
	int			count = DEFAULT_DEV_NUM;

	pdevlist = malloc(sizeof (crypto_get_dev_list_t) +
	    sizeof (crypto_dev_list_entry_t) * (count - 1));
	if (pdevlist == NULL) {
		cryptodebug("out of memory.");
		return (FAILURE);
	}

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDONLY)) == -1) {
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(errno));
		free(pdevlist);
		return (FAILURE);
	}

	pdevlist->dl_dev_count = count;
	if (ioctl(fd, CRYPTO_GET_DEV_LIST, pdevlist) == -1) {
		cryptodebug("CRYPTO_GET_DEV_LIST ioctl failed: %s",
		    strerror(errno));
		free(pdevlist);
		(void) close(fd);
		return (FAILURE);
	}

	/* BUFFER is too small, get the number of devices and retry it. */
	if (pdevlist->dl_return_value == CRYPTO_BUFFER_TOO_SMALL) {
		count = pdevlist->dl_dev_count;
		free(pdevlist);
		pdevlist = malloc(sizeof (crypto_get_dev_list_t) +
		    sizeof (crypto_dev_list_entry_t) * (count - 1));
		if (pdevlist == NULL) {
			cryptodebug("out of memory.");
			(void) close(fd);
			return (FAILURE);
		}

		if (ioctl(fd, CRYPTO_GET_DEV_LIST, pdevlist) == -1) {
			cryptodebug("CRYPTO_GET_DEV_LIST ioctl failed: %s",
			    strerror(errno));
			free(pdevlist);
			(void) close(fd);
			return (FAILURE);
		}
	}

	if (pdevlist->dl_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_GET_DEV_LIST ioctl failed, "
		    "return_value = %d", pdevlist->dl_return_value);
		free(pdevlist);
		(void) close(fd);
		return (FAILURE);
	}

	*ppdevlist = pdevlist;
	(void) close(fd);
	return (SUCCESS);
}


/*
 * Get all the mechanisms supported by the hardware provider.
 * The result will be stored in the second argument.
 */
int
get_dev_info(char *devname, int inst_num, int count, mechlist_t **ppmechlist)
{
	crypto_get_dev_info_t	*dev_info;
	mechlist_t	*phead;
	mechlist_t	*pcur;
	mechlist_t	*pmech;
	int		fd = -1;
	int		i;
	int		rc;

	if (devname == NULL || count < 1) {
		cryptodebug("get_dev_info(): devname is NULL or bogus count");
		return (FAILURE);
	}

	/* Set up the argument for the CRYPTO_GET_DEV_INFO ioctl call */
	dev_info = malloc(sizeof (crypto_get_dev_info_t) +
	    sizeof (crypto_mech_name_t) * (count - 1));
	if (dev_info == NULL) {
		cryptodebug("out of memory.");
		return (FAILURE);
	}
	(void) strlcpy(dev_info->di_dev_name, devname, MAXNAMELEN);
	dev_info->di_dev_instance = inst_num;
	dev_info->di_count = count;

	/* Open the ioctl device */
	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDONLY)) == -1) {
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(errno));
		free(dev_info);
		return (FAILURE);
	}

	if (ioctl(fd, CRYPTO_GET_DEV_INFO, dev_info) == -1) {
		cryptodebug("CRYPTO_GET_DEV_INFO ioctl failed: %s",
		    strerror(errno));
		free(dev_info);
		(void) close(fd);
		return (FAILURE);
	}

	if (dev_info->di_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_GET_DEV_INFO ioctl failed, "
		    "return_value = %d", dev_info->di_return_value);
		free(dev_info);
		(void) close(fd);
		return (FAILURE);
	}

	phead = pcur = NULL;
	rc = SUCCESS;
	for (i = 0; i < dev_info->di_count; i++) {
		pmech = create_mech(&dev_info->di_list[i][0]);
		if (pmech == NULL) {
			rc = FAILURE;
			break;
		} else {
			if (phead == NULL) {
				phead = pcur = pmech;
			} else {
				pcur->next = pmech;
				pcur = pmech;
			}
		}
	}

	if (rc == SUCCESS) {
		*ppmechlist = phead;
	} else {
		free_mechlist(phead);
	}

	free(dev_info);
	(void) close(fd);
	return (rc);
}


/*
 * Get the supported mechanism list of the software provider from kernel.
 *
 * Parameters phardlist and psoftlist are supplied by get_kcfconf_info().
 * If NULL, this function calls get_kcfconf_info() internally.
 */
int
get_soft_info(char *provname, mechlist_t **ppmechlist,
	entrylist_t *phardlist, entrylist_t *psoftlist)
{
	boolean_t		in_kernel = B_FALSE;
	crypto_get_soft_info_t	*psoft_info;
	mechlist_t		*phead;
	mechlist_t		*pmech;
	mechlist_t		*pcur;
	entry_t			*pent = NULL;
	int			count;
	int			fd = -1;
	int			rc;
	int			i;

	if (provname == NULL) {
		return (FAILURE);
	}

	if (getzoneid() == GLOBAL_ZONEID) {
		/* use kcf.conf for kernel software providers in global zone */
		if ((pent = getent_kef(provname, phardlist, psoftlist)) ==
		    NULL) {

			/* No kcf.conf entry for this provider */
			if (check_kernel_for_soft(provname, NULL, &in_kernel)
			    == FAILURE) {
				return (FAILURE);
			} else if (in_kernel == B_FALSE) {
				cryptoerror(LOG_STDERR,
				    gettext("%s does not exist."), provname);
				return (FAILURE);
			}

			/*
			 * Set mech count to 1.  It will be reset to the
			 * correct value later if the setup buffer is too small.
			 */
			count = 1;
		} else {
			count = pent->sup_count;
			free_entry(pent);
		}
	} else {
		/*
		 * kcf.conf not there in non-global zone: set mech count to 1.
		 * It will be reset to the correct value later if the setup
		 * buffer is too small.
		 */
		count = 1;
	}

	if ((psoft_info = setup_get_soft_info(provname, count)) == NULL) {
		return (FAILURE);
	}

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDONLY)) == -1) {
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(errno));
		free(psoft_info);
		return (FAILURE);
	}

	/* make GET_SOFT_INFO ioctl call */
	if ((rc = ioctl(fd, CRYPTO_GET_SOFT_INFO, psoft_info)) == -1) {
		cryptodebug("CRYPTO_GET_SOFT_INFO ioctl failed: %s",
		    strerror(errno));
		(void) close(fd);
		free(psoft_info);
		return (FAILURE);
	}

	/* BUFFER is too small, get the number of mechanisms and retry it. */
	if (psoft_info->si_return_value == CRYPTO_BUFFER_TOO_SMALL) {
		count = psoft_info->si_count;
		free(psoft_info);
		if ((psoft_info = setup_get_soft_info(provname, count))
		    == NULL) {
			(void) close(fd);
			return (FAILURE);
		} else {
			rc = ioctl(fd, CRYPTO_GET_SOFT_INFO, psoft_info);
			if (rc == -1) {
				cryptodebug("CRYPTO_GET_SOFT_INFO ioctl "
				    "failed: %s", strerror(errno));
				(void) close(fd);
				free(psoft_info);
				return (FAILURE);
			}
		}
	}

	(void) close(fd);
	if (psoft_info->si_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_GET_SOFT_INFO ioctl failed, "
		    "return_value = %d", psoft_info->si_return_value);
		free(psoft_info);
		return (FAILURE);
	}


	/* Build the mechanism linked list and return it */
	rc = SUCCESS;
	phead = pcur = NULL;
	for (i = 0; i < psoft_info->si_count; i++) {
		pmech = create_mech(&psoft_info->si_list[i][0]);
		if (pmech == NULL) {
			rc = FAILURE;
			break;
		} else {
			if (phead == NULL) {
				phead = pcur = pmech;
			} else {
				pcur->next = pmech;
				pcur = pmech;
			}
		}
	}

	if (rc == FAILURE) {
		free_mechlist(phead);
	} else {
		*ppmechlist = phead;
	}

	free(psoft_info);
	return (rc);
}


/*
 * Get the kernel software provider list from kernel.
 */
int
get_soft_list(crypto_get_soft_list_t **ppsoftlist)
{
	crypto_get_soft_list_t *psoftlist = NULL;
	int	count = DEFAULT_SOFT_NUM;
	int	len;
	int	fd = -1;

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDONLY)) == -1) {
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(errno));
		return (FAILURE);
	}

	len = MAXNAMELEN * count;
	psoftlist = malloc(sizeof (crypto_get_soft_list_t) + len);
	if (psoftlist == NULL) {
		cryptodebug("out of memory.");
		(void) close(fd);
		return (FAILURE);
	}
	psoftlist->sl_soft_names = (caddr_t)(psoftlist + 1);
	psoftlist->sl_soft_count = count;
	psoftlist->sl_soft_len = len;

	if (ioctl(fd, CRYPTO_GET_SOFT_LIST, psoftlist) == -1) {
		cryptodebug("CRYPTO_GET_SOFT_LIST ioctl failed: %s",
		    strerror(errno));
		free(psoftlist);
		(void) close(fd);
		return (FAILURE);
	}

	/*
	 * if BUFFER is too small, get the number of software providers and
	 * the minimum length needed for names and length and retry it.
	 */
	if (psoftlist->sl_return_value == CRYPTO_BUFFER_TOO_SMALL) {
		count = psoftlist->sl_soft_count;
		len = psoftlist->sl_soft_len;
		free(psoftlist);
		psoftlist = malloc(sizeof (crypto_get_soft_list_t) + len);
		if (psoftlist == NULL) {
			cryptodebug("out of memory.");
			(void) close(fd);
			return (FAILURE);
		}
		psoftlist->sl_soft_names = (caddr_t)(psoftlist + 1);
		psoftlist->sl_soft_count = count;
		psoftlist->sl_soft_len = len;

		if (ioctl(fd, CRYPTO_GET_SOFT_LIST, psoftlist) == -1) {
			cryptodebug("CRYPTO_GET_SOFT_LIST ioctl failed:"
			    "%s", strerror(errno));
			free(psoftlist);
			(void) close(fd);
			return (FAILURE);
		}
	}

	if (psoftlist->sl_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_GET_SOFT_LIST ioctl failed, "
		    "return_value = %d", psoftlist->sl_return_value);
		free(psoftlist);
		(void) close(fd);
		return (FAILURE);
	}

	*ppsoftlist = psoftlist;
	(void) close(fd);
	return (SUCCESS);
}
