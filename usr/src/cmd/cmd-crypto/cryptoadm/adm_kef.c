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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <locale.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/crypto/ioctladmin.h>
#include <signal.h>
#include <sys/crypto/elfsign.h>
#include "cryptoadm.h"

static int check_hardware_provider(char *, char *, int *, int *);

/*
 * Display the mechanism list for a kernel software provider.
 * This implements part of the "cryptoadm list -m" command.
 *
 * Parameters phardlist and psoftlist are supplied by
 * get_soft_info().
 * If NULL, this function obtains it by calling getent_kef() and
 * then get_kcfconf_info() via get_soft_info() internally.
 */
int
list_mechlist_for_soft(char *provname,
    entrylist_t *phardlist, entrylist_t *psoftlist)
{
	mechlist_t	*pmechlist = NULL;
	int		rc;

	if (provname == NULL) {
		return (FAILURE);
	}

	rc = get_soft_info(provname, &pmechlist, phardlist, psoftlist);
	if (rc == SUCCESS) {
		(void) filter_mechlist(&pmechlist, RANDOM);
		print_mechlist(provname, pmechlist);
		free_mechlist(pmechlist);
	} else {
		cryptoerror(LOG_STDERR, gettext(
		    "failed to retrieve the mechanism list for %s."),
		    provname);
	}

	return (rc);
}

/*
 * Display the mechanism list for a kernel hardware provider.
 * This implements part of the "cryptoadm list -m" command.
 */
int
list_mechlist_for_hard(char *provname)
{
	mechlist_t	*pmechlist = NULL;
	char		devname[MAXNAMELEN];
	int		inst_num;
	int		count;
	int		rc = SUCCESS;

	if (provname == NULL) {
		return (FAILURE);
	}

	/*
	 * Check if the provider is valid. If it is valid, get the number of
	 * mechanisms also.
	 */
	if (check_hardware_provider(provname, devname, &inst_num, &count) ==
	    FAILURE) {
		return (FAILURE);
	}

	/* Get the mechanism list for the kernel hardware provider */
	if ((rc = get_dev_info(devname, inst_num, count, &pmechlist)) ==
	    SUCCESS) {
		(void) filter_mechlist(&pmechlist, RANDOM);
		print_mechlist(provname, pmechlist);
		free_mechlist(pmechlist);
	}

	return (rc);
}


/*
 * Display the policy information for a kernel software provider.
 * This implements part of the "cryptoadm list -p" command.
 *
 * Parameters phardlist and psoftlist are supplied by
 * getent_kef().
 * If NULL, this function obtains it by calling get_kcfconf_info()
 * via getent_kef() internally.
 */
int
list_policy_for_soft(char *provname,
    entrylist_t *phardlist, entrylist_t *psoftlist)
{
	int		rc;
	entry_t		*pent = NULL;
	mechlist_t	*pmechlist = NULL;
	boolean_t	has_random = B_FALSE;
	boolean_t	has_mechs = B_FALSE;
	boolean_t	in_kernel = B_FALSE;

	if (provname == NULL) {
		return (FAILURE);
	}

	if (check_kernel_for_soft(provname, NULL, &in_kernel) == FAILURE) {
		return (FAILURE);
	} else if (in_kernel == B_FALSE) {
		cryptoerror(LOG_STDERR, gettext("%s does not exist."),
		    provname);
		return (FAILURE);
	}
	pent = getent_kef(provname, phardlist, psoftlist);

	rc = get_soft_info(provname, &pmechlist, phardlist, psoftlist);
	if (rc == SUCCESS) {
		has_random = filter_mechlist(&pmechlist, RANDOM);
		if (pmechlist != NULL) {
			has_mechs = B_TRUE;
			free_mechlist(pmechlist);
		}
	} else {
		cryptoerror(LOG_STDERR, gettext(
		    "failed to retrieve the mechanism list for %s."),
		    provname);
		return (rc);
	}

	print_kef_policy(provname, pent, has_random, has_mechs);
	free_entry(pent);
	return (SUCCESS);
}



/*
 * Display the policy information for a kernel hardware provider.
 * This implements part of the "cryptoadm list -p" command.
 *
 * Parameters phardlist and psoftlist are supplied by getent_kef().
 * If NULL, this function obtains it by calling get_kcfconf_info() via
 * getent_kef() internally.
 * Parameter pdevlist is supplied by check_kernel_for_hard().
 * If NULL, this function obtains it by calling get_dev_list() via
 * check_kernel_for_hard() internally.
 */
int
list_policy_for_hard(char *provname,
	entrylist_t *phardlist, entrylist_t *psoftlist,
	crypto_get_dev_list_t *pdevlist)
{
	entry_t		*pent = NULL;
	boolean_t	in_kernel;
	mechlist_t	*pmechlist = NULL;
	char		devname[MAXNAMELEN];
	int		inst_num;
	int		count;
	int		rc = SUCCESS;
	boolean_t	has_random = B_FALSE;
	boolean_t 	has_mechs = B_FALSE;

	if (provname == NULL) {
		return (FAILURE);
	}

	/*
	 * Check if the provider is valid. If it is valid, get the number of
	 * mechanisms also.
	 */
	if (check_hardware_provider(provname, devname, &inst_num, &count) ==
	    FAILURE) {
		return (FAILURE);
	}

	/* Get the mechanism list for the kernel hardware provider */
	if ((rc = get_dev_info(devname, inst_num, count, &pmechlist)) ==
	    SUCCESS) {
		has_random = filter_mechlist(&pmechlist, RANDOM);

		if (pmechlist != NULL) {
			has_mechs = B_TRUE;
			free_mechlist(pmechlist);
		}
	} else {
		cryptoerror(LOG_STDERR, gettext(
		    "failed to retrieve the mechanism list for %s."),
		    devname);
		return (rc);
	}

	/*
	 * If the hardware provider has an entry in the kcf.conf file,
	 * some of its mechanisms must have been disabled.  Print out
	 * the disabled list from the config file entry.  Otherwise,
	 * if it is active, then all the mechanisms for it are enabled.
	 */
	if ((pent = getent_kef(provname, phardlist, psoftlist)) != NULL) {
		print_kef_policy(provname, pent, has_random, has_mechs);
		free_entry(pent);
		return (SUCCESS);
	} else {
		if (check_kernel_for_hard(provname, pdevlist,
		    &in_kernel) == FAILURE) {
			return (FAILURE);
		} else if (in_kernel == B_TRUE) {
			(void) printf(gettext(
			    "%s: all mechanisms are enabled."), provname);
			if (has_random)
				/*
				 * TRANSLATION_NOTE
				 * "random" is a keyword and not to be
				 * translated.
				 */
				(void) printf(gettext(" %s is enabled.\n"),
				    "random");
			else
				(void) printf("\n");
			return (SUCCESS);
		} else {
			cryptoerror(LOG_STDERR,
			    gettext("%s does not exist."), provname);
			return (FAILURE);
		}
	}
}


/*
 * Disable a kernel hardware provider.
 * This implements the "cryptoadm disable" command for
 * kernel hardware providers.
 */
int
disable_kef_hardware(char *provname, boolean_t rndflag, boolean_t allflag,
    mechlist_t *dislist)
{
	crypto_load_dev_disabled_t	*pload_dev_dis = NULL;
	mechlist_t			*infolist = NULL;
	entry_t				*pent = NULL;
	boolean_t			new_dev_entry = B_FALSE;
	char				devname[MAXNAMELEN];
	int				inst_num;
	int				count;
	int				fd = -1;
	int				rc = SUCCESS;

	if (provname == NULL) {
		return (FAILURE);
	}

	/*
	 * Check if the provider is valid. If it is valid, get the number of
	 * mechanisms also.
	 */
	if (check_hardware_provider(provname, devname, &inst_num, &count)
	    == FAILURE) {
		return (FAILURE);
	}

	/* Get the mechanism list for the kernel hardware provider */
	if (get_dev_info(devname, inst_num, count, &infolist) == FAILURE) {
		return (FAILURE);
	}

	/*
	 * Get the entry of this hardware provider from the config file.
	 * If there is no entry yet, create one for it.
	 */
	if ((pent = getent_kef(provname, NULL, NULL)) == NULL) {
		if ((pent = create_entry(provname)) == NULL) {
			cryptoerror(LOG_STDERR, gettext("out of memory."));
			free_mechlist(infolist);
			return (FAILURE);
		}
		new_dev_entry = B_TRUE;
	}

	/*
	 * kCF treats random as an internal mechanism. So, we need to
	 * filter it from the mechanism list here, if we are NOT disabling
	 * or enabling the random feature. Note that we map random feature at
	 * cryptoadm(8) level to the "random" mechanism in kCF.
	 */
	if (!rndflag) {
		(void) filter_mechlist(&dislist, RANDOM);
	}

	/* Calculate the new disabled list */
	if (disable_mechs(&pent, infolist, allflag, dislist) == FAILURE) {
		free_mechlist(infolist);
		free_entry(pent);
		return (FAILURE);
	}
	free_mechlist(infolist);

	/* If no mechanisms are to be disabled, return */
	if (pent->dis_count == 0) {
		free_entry(pent);
		return (SUCCESS);
	}

	/* Update the config file with the new entry or the updated entry */
	if (new_dev_entry) {
		rc = update_kcfconf(pent, ADD_MODE);
	} else {
		rc = update_kcfconf(pent, MODIFY_MODE);
	}

	if (rc == FAILURE) {
		free_entry(pent);
		return (FAILURE);
	}

	/* Inform kernel about the new disabled mechanism list */
	if ((pload_dev_dis = setup_dev_dis(pent)) == NULL) {
		free_entry(pent);
		return (FAILURE);
	}
	free_entry(pent);

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(errno));
		free(pload_dev_dis);
		return (FAILURE);
	}

	if (ioctl(fd, CRYPTO_LOAD_DEV_DISABLED, pload_dev_dis) == -1) {
		cryptodebug("CRYPTO_LOAD_DEV_DISABLED ioctl failed: %s",
		    strerror(errno));
		free(pload_dev_dis);
		(void) close(fd);
		return (FAILURE);
	}

	if (pload_dev_dis->dd_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_LOAD_DEV_DISABLED ioctl return_value = "
		    "%d", pload_dev_dis->dd_return_value);
		free(pload_dev_dis);
		(void) close(fd);
		return (FAILURE);
	}

	free(pload_dev_dis);
	(void) close(fd);
	return (SUCCESS);
}


/*
 * Disable a kernel software provider.
 * This implements the "cryptoadm disable" command for
 * kernel software providers.
 */
int
disable_kef_software(char *provname, boolean_t rndflag, boolean_t allflag,
    mechlist_t *dislist)
{
	crypto_load_soft_disabled_t	*pload_soft_dis = NULL;
	mechlist_t			*infolist = NULL;
	entry_t				*pent = NULL;
	entrylist_t			*phardlist = NULL;
	entrylist_t			*psoftlist = NULL;
	boolean_t			in_kernel = B_FALSE;
	int				fd = -1;
	int				rc = SUCCESS;

	if (provname == NULL) {
		return (FAILURE);
	}

	/*
	 * Check if the kernel software provider is currently unloaded.
	 * If it is unloaded, return FAILURE, because the disable subcommand
	 * can not perform on inactive (unloaded) providers.
	 */
	if (check_kernel_for_soft(provname, NULL, &in_kernel) == FAILURE) {
		return (FAILURE);
	} else if (in_kernel == B_FALSE) {
		cryptoerror(LOG_STDERR,
		    gettext("%s is not loaded or does not exist."),
		    provname);
		return (FAILURE);
	}

	if (get_kcfconf_info(&phardlist, &psoftlist) == FAILURE) {
		cryptoerror(LOG_ERR,
		    "failed to retrieve the providers' "
		    "information from the configuration file - %s.",
		    _PATH_KCF_CONF);
		return (FAILURE);
	}

	/*
	 * Get the entry of this provider from the kcf.conf file, if any.
	 * Otherwise, create a new kcf.conf entry for writing back to the file.
	 */
	pent = getent_kef(provname, phardlist, psoftlist);
	if (pent == NULL) { /* create a new entry */
		pent = create_entry(provname);
		if (pent == NULL) {
			cryptodebug("out of memory.");
			rc = FAILURE;
			goto out;
		}
	}

	/* Get the mechanism list for the software provider from the kernel */
	if (get_soft_info(provname, &infolist, phardlist, psoftlist) ==
	    FAILURE) {
		rc = FAILURE;
		goto out;
	}

	if ((infolist != NULL) && (infolist->name[0] != '\0')) {
		/*
		 * Replace the supportedlist from kcf.conf with possibly
		 * more-up-to-date list from the kernel.  This is the case
		 * for default software providers that had more mechanisms
		 * added in the current version of the kernel.
		 */
		free_mechlist(pent->suplist);
		pent->suplist = infolist;
	}

	/*
	 * kCF treats random as an internal mechanism. So, we need to
	 * filter it from the mechanism list here, if we are NOT disabling
	 * or enabling the random feature. Note that we map random feature at
	 * cryptoadm(8) level to the "random" mechanism in kCF.
	 */
	if (!rndflag) {
		(void) filter_mechlist(&infolist, RANDOM);
	}

	/* Calculate the new disabled list */
	if (disable_mechs(&pent, infolist, allflag, dislist) == FAILURE) {
		rc = FAILURE;
		goto out;
	}

	/* Update the kcf.conf file with the updated entry */
	if (update_kcfconf(pent, MODIFY_MODE) == FAILURE) {
		rc = FAILURE;
		goto out;
	}

	/* Setup argument to inform kernel about the new disabled list. */
	if ((pload_soft_dis = setup_soft_dis(pent)) == NULL) {
		rc = FAILURE;
		goto out;
	}

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to open %s for RW: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(errno));
		rc = FAILURE;
		goto out;
	}

	/* Inform kernel about the new disabled list. */
	if (ioctl(fd, CRYPTO_LOAD_SOFT_DISABLED, pload_soft_dis) == -1) {
		cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl failed: %s",
		    strerror(errno));
		rc = FAILURE;
		goto out;
	}

	if (pload_soft_dis->sd_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl return_value = "
		    "%d", pload_soft_dis->sd_return_value);
		rc = FAILURE;
		goto out;
	}

out:
	free_entrylist(phardlist);
	free_entrylist(psoftlist);
	free_mechlist(infolist);
	free_entry(pent);
	free(pload_soft_dis);
	if (fd != -1)
		(void) close(fd);
	return (rc);
}


/*
 * Enable a kernel software or hardware provider.
 * This implements the "cryptoadm enable" command for kernel providers.
 */
int
enable_kef(char *provname, boolean_t rndflag, boolean_t allflag,
    mechlist_t *mlist)
{
	crypto_load_soft_disabled_t	*pload_soft_dis = NULL;
	crypto_load_dev_disabled_t	*pload_dev_dis = NULL;
	entry_t				*pent = NULL;
	boolean_t			redo_flag = B_FALSE;
	boolean_t			in_kernel = B_FALSE;
	int				fd = -1;
	int				rc = SUCCESS;


	/* Get the entry of this provider from the kcf.conf file, if any. */
	pent = getent_kef(provname, NULL, NULL);

	if (is_device(provname)) {
		if (pent == NULL) {
			/*
			 * This device doesn't have an entry in the config
			 * file, therefore nothing is disabled.
			 */
			cryptoerror(LOG_STDERR, gettext(
			    "all mechanisms are enabled already for %s."),
			    provname);
			free_entry(pent);
			return (SUCCESS);
		}
	} else { /* a software module */
		if (check_kernel_for_soft(provname, NULL, &in_kernel) ==
		    FAILURE) {
			free_entry(pent);
			return (FAILURE);
		} else if (in_kernel == B_FALSE) {
			cryptoerror(LOG_STDERR, gettext("%s does not exist."),
			    provname);
			free_entry(pent);
			return (FAILURE);
		} else if ((pent == NULL) || (pent->dis_count == 0)) {
			/* nothing to be enabled. */
			cryptoerror(LOG_STDERR, gettext(
			    "all mechanisms are enabled already for %s."),
			    provname);
			free_entry(pent);
			return (SUCCESS);
		}
	}

	/*
	 * kCF treats random as an internal mechanism. So, we need to
	 * filter it from the mechanism list here, if we are NOT disabling
	 * or enabling the random feature. Note that we map random feature at
	 * cryptoadm(8) level to the "random" mechanism in kCF.
	 */
	if (!rndflag) {
		redo_flag = filter_mechlist(&pent->dislist, RANDOM);
		if (redo_flag)
			pent->dis_count--;
	}

	/* Update the entry by enabling mechanisms for this provider */
	if ((rc = enable_mechs(&pent, allflag, mlist)) != SUCCESS) {
		free_entry(pent);
		return (rc);
	}

	if (redo_flag) {
		mechlist_t *tmp;

		if ((tmp = create_mech(RANDOM)) == NULL) {
			free_entry(pent);
			return (FAILURE);
		}
		tmp->next = pent->dislist;
		pent->dislist = tmp;
		pent->dis_count++;
	}

	/*
	 * Update the kcf.conf file with the updated entry.
	 * For a hardware provider, if there is no more disabled mechanism,
	 * remove the entire kcf.conf entry.
	 */
	if (is_device(pent->name) && (pent->dis_count == 0)) {
		rc = update_kcfconf(pent, DELETE_MODE);
	} else {
		rc = update_kcfconf(pent, MODIFY_MODE);
	}

	if (rc == FAILURE) {
		free_entry(pent);
		return (FAILURE);
	}


	/* Inform Kernel about the policy change */

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(errno));
		free_entry(pent);
		return (FAILURE);
	}

	if (is_device(provname)) {
		/*  LOAD_DEV_DISABLED */
		if ((pload_dev_dis = setup_dev_dis(pent)) == NULL) {
			free_entry(pent);
			return (FAILURE);
		}

		if (ioctl(fd, CRYPTO_LOAD_DEV_DISABLED, pload_dev_dis) == -1) {
			cryptodebug("CRYPTO_LOAD_DEV_DISABLED ioctl failed: "
			    "%s", strerror(errno));
			free_entry(pent);
			free(pload_dev_dis);
			(void) close(fd);
			return (FAILURE);
		}

		if (pload_dev_dis->dd_return_value != CRYPTO_SUCCESS) {
			cryptodebug("CRYPTO_LOAD_DEV_DISABLED ioctl "
			    "return_value = %d",
			    pload_dev_dis->dd_return_value);
			free_entry(pent);
			free(pload_dev_dis);
			(void) close(fd);
			return (FAILURE);
		}

	} else { /* a software module */
		/* LOAD_SOFT_DISABLED */
		if ((pload_soft_dis = setup_soft_dis(pent)) == NULL) {
			free_entry(pent);
			return (FAILURE);
		}

		if (ioctl(fd, CRYPTO_LOAD_SOFT_DISABLED, pload_soft_dis)
		    == -1) {
			cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl failed: "
			    "%s", strerror(errno));
			free_entry(pent);
			free(pload_soft_dis);
			(void) close(fd);
			return (FAILURE);
		}

		if (pload_soft_dis->sd_return_value != CRYPTO_SUCCESS) {
			cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl "
			    "return_value = %d",
			    pload_soft_dis->sd_return_value);
			free_entry(pent);
			free(pload_soft_dis);
			(void) close(fd);
			return (FAILURE);
		}
	}

	free_entry(pent);
	free(pload_soft_dis);
	(void) close(fd);
	return (SUCCESS);
}


/*
 * Install a software module with the specified mechanism list into the system.
 * This routine adds an entry into the config file for this software module
 * first, then makes a CRYPTO_LOAD_SOFT_CONFIG ioctl call to inform kernel
 * about the new addition.
 */
int
install_kef(char *provname, mechlist_t *mlist)
{
	crypto_load_soft_config_t	*pload_soft_conf = NULL;
	boolean_t			found;
	entry_t				*pent = NULL;
	FILE				*pfile = NULL;
	FILE				*pfile_tmp = NULL;
	char				tmpfile_name[MAXPATHLEN];
	char				*ptr;
	char				*str;
	char				*name;
	char				buffer[BUFSIZ];
	char				buffer2[BUFSIZ];
	int				found_count;
	int				fd = -1;
	int				rc = SUCCESS;
	int				err;

	if ((provname == NULL) || (mlist == NULL)) {
		return (FAILURE);
	}

	/* Check if the provider already exists */
	if ((pent = getent_kef(provname, NULL, NULL)) != NULL) {
		cryptoerror(LOG_STDERR, gettext("%s exists already."),
		    provname);
		free_entry(pent);
		return (FAILURE);
	}

	/* Create an entry with provname and mlist. */
	if ((pent = create_entry(provname)) == NULL) {
		cryptoerror(LOG_STDERR, gettext("out of memory."));
		return (FAILURE);
	}
	pent->sup_count = get_mech_count(mlist);
	pent->suplist = mlist;

	/* Append an entry for this software module to the kcf.conf file. */
	if ((str = ent2str(pent)) == NULL) {
		free_entry(pent);
		return (FAILURE);
	}

	if ((pfile = fopen(_PATH_KCF_CONF, "r+")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to open %s for write.", _PATH_KCF_CONF);
		free_entry(pent);
		return (FAILURE);
	}

	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to lock the configuration - %s"),
		    strerror(err));
		free_entry(pent);
		(void) fclose(pfile);
		return (FAILURE);
	}

	/*
	 * Create a temporary file in the /etc/crypto directory.
	 */
	(void) strlcpy(tmpfile_name, TMPFILE_TEMPLATE, sizeof (tmpfile_name));
	if (mkstemp(tmpfile_name) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to create a temporary file - %s"),
		    strerror(err));
		free_entry(pent);
		(void) fclose(pfile);
		return (FAILURE);
	}

	if ((pfile_tmp = fopen(tmpfile_name, "w")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s - %s"),
		    tmpfile_name, strerror(err));
		free_entry(pent);
		(void) fclose(pfile);
		return (FAILURE);
	}


	/*
	 * Loop thru the config file. If the provider was reserved within a
	 * package bracket, just uncomment it.  Otherwise, append it at
	 * the end.  The resulting file will be saved in the temp file first.
	 */
	found_count = 0;
	rc = SUCCESS;
	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		found = B_FALSE;
		if (buffer[0] == '#') {
			(void) strlcpy(buffer2, buffer, BUFSIZ);
			ptr = buffer2;
			ptr++;
			if ((name = strtok(ptr, SEP_COLON)) == NULL) {
				rc = FAILURE;
				break;
			} else if (strcmp(provname, name) == 0) {
				found = B_TRUE;
				found_count++;
			}
		}

		if (found == B_FALSE) {
			if (fputs(buffer, pfile_tmp) == EOF) {
				rc = FAILURE;
			}
		} else {
			if (found_count == 1) {
				if (fputs(str, pfile_tmp) == EOF) {
					rc = FAILURE;
				}
			} else {
				/*
				 * Found a second entry with #libname.
				 * Should not happen. The kcf.conf file
				 * is corrupted. Give a warning and skip
				 * this entry.
				 */
				cryptoerror(LOG_STDERR, gettext(
				    "(Warning) Found an additional reserved "
				    "entry for %s."), provname);
			}
		}

		if (rc == FAILURE) {
			break;
		}
	}
	(void) fclose(pfile);

	if (rc == FAILURE) {
		cryptoerror(LOG_STDERR, gettext("write error."));
		(void) fclose(pfile_tmp);
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"), tmpfile_name,
			    strerror(err));
		}
		free_entry(pent);
		return (FAILURE);
	}

	if (found_count == 0) {
		/*
		 * This libname was not in package before, append it to the
		 * end of the temp file.
		 */
		if (fputs(str, pfile_tmp) == EOF) {
			cryptoerror(LOG_STDERR, gettext(
			    "failed to write to %s: %s"), tmpfile_name,
			    strerror(errno));
			(void) fclose(pfile_tmp);
			if (unlink(tmpfile_name) != 0) {
				err = errno;
				cryptoerror(LOG_STDERR, gettext(
				    "(Warning) failed to remove %s: %s"),
				    tmpfile_name, strerror(err));
			}
			free_entry(pent);
			return (FAILURE);
		}
	}

	if (fclose(pfile_tmp) != 0) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to close %s: %s"), tmpfile_name,
		    strerror(err));
		free_entry(pent);
		return (FAILURE);
	}

	if (rename(tmpfile_name, _PATH_KCF_CONF) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to rename %s to %s: %s", tmpfile_name,
		    _PATH_KCF_CONF, strerror(err));
		rc = FAILURE;
	} else if (chmod(_PATH_KCF_CONF,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to chmod to %s: %s", _PATH_KCF_CONF,
		    strerror(err));
		rc = FAILURE;
	} else {
		rc = SUCCESS;
	}

	if (rc == FAILURE) {
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"),
			    tmpfile_name, strerror(err));
		}
		free_entry(pent);
		return (FAILURE);
	}


	/* Inform kernel of this new software module. */

	if ((pload_soft_conf = setup_soft_conf(pent)) == NULL) {
		free_entry(pent);
		return (FAILURE);
	}

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(errno));
		free_entry(pent);
		free(pload_soft_conf);
		return (FAILURE);
	}

	if (ioctl(fd, CRYPTO_LOAD_SOFT_CONFIG, pload_soft_conf) == -1) {
		cryptodebug("CRYPTO_LOAD_SOFT_CONFIG ioctl failed: %s",
		    strerror(errno));
		free_entry(pent);
		free(pload_soft_conf);
		(void) close(fd);
		return (FAILURE);
	}

	if (pload_soft_conf->sc_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_LOAD_SOFT_CONFIG ioctl failed, "
		    "return_value = %d", pload_soft_conf->sc_return_value);
		free_entry(pent);
		free(pload_soft_conf);
		(void) close(fd);
		return (FAILURE);
	}

	free_entry(pent);
	free(pload_soft_conf);
	(void) close(fd);
	return (SUCCESS);
}

/*
 * Uninstall the software module. This routine first unloads the software
 * module with 3 ioctl calls, then deletes its entry from the config file.
 * Removing an entry from the config file needs to be done last to ensure
 * that there is still an entry if the earlier unload failed for any reason.
 */
int
uninstall_kef(char *provname)
{
	entry_t		*pent = NULL;
	int		rc = SUCCESS;
	boolean_t	in_kernel = B_FALSE;
	boolean_t	in_kcfconf = B_FALSE;
	int		fd = -1;
	crypto_load_soft_config_t *pload_soft_conf = NULL;

	/* Check to see if the provider exists first. */
	if (check_kernel_for_soft(provname, NULL, &in_kernel) == FAILURE) {
		return (FAILURE);
	} else if (in_kernel == B_FALSE) {
		cryptoerror(LOG_STDERR, gettext("%s does not exist."),
		    provname);
		return (FAILURE);
	}

	/*
	 * If it is loaded, unload it first.  This does 2 ioctl calls:
	 * CRYPTO_UNLOAD_SOFT_MODULE and CRYPTO_LOAD_SOFT_DISABLED.
	 */
	if (unload_kef_soft(provname) == FAILURE) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to unload %s during uninstall.\n"),
		    provname);
		return (FAILURE);
	}

	/*
	 * Inform kernel to remove the configuration of this software module.
	 */

	/* Setup ioctl() parameter */
	pent = getent_kef(provname, NULL, NULL);
	if (pent != NULL) { /* in kcf.conf */
		in_kcfconf = B_TRUE;
		free_mechlist(pent->suplist);
		pent->suplist = NULL;
		pent->sup_count = 0;
	} else if ((pent = create_entry(provname)) == NULL) {
		cryptoerror(LOG_STDERR, gettext("out of memory."));
		return (FAILURE);
	}
	if ((pload_soft_conf = setup_soft_conf(pent)) == NULL) {
		free_entry(pent);
		return (FAILURE);
	}

	/* Open the /dev/cryptoadm device */
	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		int	err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(err));
		free_entry(pent);
		free(pload_soft_conf);
		return (FAILURE);
	}

	if (ioctl(fd, CRYPTO_LOAD_SOFT_CONFIG,
	    pload_soft_conf) == -1) {
		cryptodebug("CRYPTO_LOAD_SOFT_CONFIG ioctl failed: %s",
		    strerror(errno));
		free_entry(pent);
		free(pload_soft_conf);
		(void) close(fd);
		return (FAILURE);
	}

	if (pload_soft_conf->sc_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_LOAD_SOFT_CONFIG ioctl = return_value = %d",
		    pload_soft_conf->sc_return_value);
		free_entry(pent);
		free(pload_soft_conf);
		(void) close(fd);
		return (FAILURE);
	}

	/* ioctl cleanup */
	free(pload_soft_conf);
	(void) close(fd);


	/* Finally, remove entry from kcf.conf, if present */
	if (in_kcfconf && (pent != NULL)) {
		rc = update_kcfconf(pent, DELETE_MODE);
	}

	free_entry(pent);
	return (rc);
}


/*
 * Implement the "cryptoadm refresh" command for global zones.
 * That is, send the current contents of kcf.conf to the kernel via ioctl().
 */
int
refresh(void)
{
	crypto_load_soft_config_t	*pload_soft_conf = NULL;
	crypto_load_soft_disabled_t	*pload_soft_dis = NULL;
	crypto_load_dev_disabled_t	*pload_dev_dis = NULL;
	entrylist_t			*pdevlist = NULL;
	entrylist_t			*psoftlist = NULL;
	entrylist_t			*ptr;
	int				fd = -1;
	int				rc = SUCCESS;
	int				err;

	if (get_kcfconf_info(&pdevlist, &psoftlist) == FAILURE) {
		cryptoerror(LOG_ERR, "failed to retrieve the providers' "
		    "information from the configuration file - %s.",
		    _PATH_KCF_CONF);
		return (FAILURE);
	}

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(err));
		free(psoftlist);
		free(pdevlist);
		return (FAILURE);
	}

	/*
	 * For each software provider module, pass two sets of information to
	 * the kernel: the supported list and the disabled list.
	 */
	for (ptr = psoftlist; ptr != NULL; ptr = ptr->next) {
		entry_t		*pent = ptr->pent;

		/* load the supported list */
		if ((pload_soft_conf = setup_soft_conf(pent)) == NULL) {
			cryptodebug("setup_soft_conf() failed");
			rc = FAILURE;
			break;
		}

		if (!pent->load) { /* unloaded--mark as loaded */
			pent->load = B_TRUE;
			rc = update_kcfconf(pent, MODIFY_MODE);
			if (rc != SUCCESS) {
				free(pload_soft_conf);
				break;
			}
		}

		if (ioctl(fd, CRYPTO_LOAD_SOFT_CONFIG, pload_soft_conf)
		    == -1) {
			cryptodebug("CRYPTO_LOAD_SOFT_CONFIG ioctl failed: %s",
			    strerror(errno));
			free(pload_soft_conf);
			rc = FAILURE;
			break;
		}

		if (pload_soft_conf->sc_return_value != CRYPTO_SUCCESS) {
			cryptodebug("CRYPTO_LOAD_SOFT_CONFIG ioctl "
			    "return_value = %d",
			    pload_soft_conf->sc_return_value);
			free(pload_soft_conf);
			rc = FAILURE;
			break;
		}

		free(pload_soft_conf);

		/* load the disabled list */
		if (ptr->pent->dis_count != 0) {
			pload_soft_dis = setup_soft_dis(ptr->pent);
			if (pload_soft_dis == NULL) {
				cryptodebug("setup_soft_dis() failed");
				free(pload_soft_dis);
				rc = FAILURE;
				break;
			}

			if (ioctl(fd, CRYPTO_LOAD_SOFT_DISABLED,
			    pload_soft_dis) == -1) {
				cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl "
				    "failed: %s", strerror(errno));
				free(pload_soft_dis);
				rc = FAILURE;
				break;
			}

			if (pload_soft_dis->sd_return_value !=
			    CRYPTO_SUCCESS) {
				cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl "
				    "return_value = %d",
				    pload_soft_dis->sd_return_value);
				free(pload_soft_dis);
				rc = FAILURE;
				break;
			}
			free(pload_soft_dis);
		}
	}

	if (rc != SUCCESS) {
		(void) close(fd);
		return (rc);
	}


	/*
	 * For each hardware provider module, pass the disabled list
	 * information to the kernel.
	 */
	for (ptr = pdevlist; ptr != NULL; ptr = ptr->next) {
		/* load the disabled list */
		if (ptr->pent->dis_count != 0) {
			pload_dev_dis = setup_dev_dis(ptr->pent);
			if (pload_dev_dis == NULL) {
				rc = FAILURE;
				break;
			}

			if (ioctl(fd, CRYPTO_LOAD_DEV_DISABLED, pload_dev_dis)
			    == -1) {
				cryptodebug("CRYPTO_LOAD_DEV_DISABLED ioctl "
				    "failed: %s", strerror(errno));
				free(pload_dev_dis);
				rc = FAILURE;
				break;
			}

			if (pload_dev_dis->dd_return_value != CRYPTO_SUCCESS) {
				cryptodebug("CRYPTO_LOAD_DEV_DISABLED ioctl "
				    "return_value = %d",
				    pload_dev_dis->dd_return_value);
				free(pload_dev_dis);
				rc = FAILURE;
				break;
			}
			free(pload_dev_dis);
		}
	}

	(void) close(fd);
	return (rc);
}

/*
 * Unload the kernel software provider. Before calling this function, the
 * caller should check to see if the provider is in the kernel.
 *
 * This routine makes 2 ioctl calls to remove it completely from the kernel:
 *	CRYPTO_UNLOAD_SOFT_MODULE - does a modunload of the KCF module
 *	CRYPTO_LOAD_SOFT_DISABLED - updates kernel disabled mechanism list
 *
 * This implements part of "cryptoadm unload" and "cryptoadm uninstall".
 */
int
unload_kef_soft(char *provname)
{
	crypto_unload_soft_module_t	*punload_soft = NULL;
	crypto_load_soft_disabled_t	*pload_soft_dis = NULL;
	entry_t				*pent = NULL;
	int				fd = -1;
	int				err;

	if (provname == NULL) {
		cryptoerror(LOG_STDERR, gettext("internal error."));
		return (FAILURE);
	}

	pent = getent_kef(provname, NULL, NULL);
	if (pent == NULL) { /* not in kcf.conf */
		/* Construct an entry using the provname */
		pent = create_entry(provname);
		if (pent == NULL) {
			cryptoerror(LOG_STDERR, gettext("out of memory."));
			return (FAILURE);
		}
	}

	/* Open the admin_ioctl_device */
	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(err));
		free_entry(pent);
		return (FAILURE);
	}

	/* Inform kernel to unload this software module */
	if ((punload_soft = setup_unload_soft(pent)) == NULL) {
		free_entry(pent);
		(void) close(fd);
		return (FAILURE);
	}

	if (ioctl(fd, CRYPTO_UNLOAD_SOFT_MODULE, punload_soft) == -1) {
		cryptodebug("CRYPTO_UNLOAD_SOFT_MODULE ioctl failed: %s",
		    strerror(errno));
		free_entry(pent);
		free(punload_soft);
		(void) close(fd);
		return (FAILURE);
	}

	if (punload_soft->sm_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_UNLOAD_SOFT_MODULE ioctl return_value = "
		    "%d", punload_soft->sm_return_value);
		/*
		 * If the return value is CRYPTO_UNKNOWN_PROVIDER, it means
		 * that the provider is not registered yet.  Should just
		 * continue.
		 */
		if (punload_soft->sm_return_value != CRYPTO_UNKNOWN_PROVIDER) {
			free_entry(pent);
			free(punload_soft);
			(void) close(fd);
			return (FAILURE);
		}
	}

	free(punload_soft);

	/* Inform kernel to remove the disabled entries if any */
	if (pent->dis_count == 0) {
		free_entry(pent);
		(void) close(fd);
		return (SUCCESS);
	} else {
		free_mechlist(pent->dislist);
		pent->dislist = NULL;
		pent->dis_count = 0;
	}

	if ((pload_soft_dis = setup_soft_dis(pent)) == NULL) {
		free_entry(pent);
		(void) close(fd);
		return (FAILURE);
	}

	/* pent is no longer needed; free it */
	free_entry(pent);

	if (ioctl(fd, CRYPTO_LOAD_SOFT_DISABLED, pload_soft_dis) == -1) {
		cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl failed: %s",
		    strerror(errno));
		free(pload_soft_dis);
		(void) close(fd);
		return (FAILURE);
	}

	if (pload_soft_dis->sd_return_value != CRYPTO_SUCCESS) {
		cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl return_value = "
		    "%d", pload_soft_dis->sd_return_value);
		free(pload_soft_dis);
		(void) close(fd);
		return (FAILURE);
	}

	free(pload_soft_dis);
	(void) close(fd);
	return (SUCCESS);
}


/*
 * Check if a hardware provider is valid.  If it is valid, returns its device
 * name,  instance number and the number of mechanisms it supports.
 */
static int
check_hardware_provider(char *provname, char *pname, int *pnum, int *pcount)
{
	crypto_get_dev_list_t *dev_list = NULL;
	int	i;

	if (provname == NULL) {
		return (FAILURE);
	}

	/* First, get the device name and the instance number from provname */
	if (split_hw_provname(provname, pname, pnum) == FAILURE) {
		return (FAILURE);
	}

	/*
	 * Get the complete device list from kernel and check if this provider
	 * is in the list.
	 */
	if (get_dev_list(&dev_list) == FAILURE) {
		return (FAILURE);
	}

	for (i = 0; i < dev_list->dl_dev_count; i++) {
		if ((strcmp(dev_list->dl_devs[i].le_dev_name, pname) == 0) &&
		    (dev_list->dl_devs[i].le_dev_instance == *pnum)) {
			break;
		}
	}

	if (i == dev_list->dl_dev_count) {
		/* didn't find this provider in the kernel device list */
		cryptoerror(LOG_STDERR, gettext("%s does not exist."),
		    provname);
		free(dev_list);
		return (FAILURE);
	}

	/* This provider is valid.  Get its mechanism count */
	*pcount = dev_list->dl_devs[i].le_mechanism_count;

	free(dev_list);
	return (SUCCESS);
}
