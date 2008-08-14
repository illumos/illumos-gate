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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

static int err; /* to store the value of errno in case being overwritten */
static int check_hardware_provider(char *, char *, int *, int *);

/*
 * Display the mechanism list for a kernel software provider.
 */
int
list_mechlist_for_soft(char *provname)
{
	mechlist_t *pmechlist;
	int rc;

	if (provname == NULL) {
		return (FAILURE);
	}

	rc = get_soft_info(provname, &pmechlist);
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
 */
int
list_mechlist_for_hard(char *provname)
{
	mechlist_t *pmechlist;
	char	devname[MAXNAMELEN];
	int	inst_num;
	int	count;
	int rc = SUCCESS;

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
 */
int
list_policy_for_soft(char *provname)
{
	int rc;
	entry_t *pent = NULL;
	mechlist_t *pmechlist;
	boolean_t has_random = B_FALSE;
	boolean_t has_mechs = B_FALSE;

	if (provname == NULL) {
		return (FAILURE);
	}

	if ((pent = getent_kef(provname)) == NULL) {
		cryptoerror(LOG_STDERR, gettext("%s does not exist."),
		    provname);
		return (FAILURE);
	}

	rc = get_soft_info(provname, &pmechlist);
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

	print_kef_policy(pent, has_random, has_mechs);
	free_entry(pent);
	return (SUCCESS);
}



/*
 * Display the policy information for a kernel hardware provider.
 */
int
list_policy_for_hard(char *provname)
{
	entry_t *pent;
	boolean_t is_active;
	mechlist_t *pmechlist;
	char	devname[MAXNAMELEN];
	int	inst_num;
	int	count;
	int rc = SUCCESS;
	boolean_t has_random = B_FALSE;
	boolean_t has_mechs = B_FALSE;

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
	if ((pent = getent_kef(provname)) != NULL) {
		print_kef_policy(pent, has_random, has_mechs);
		free_entry(pent);
		return (SUCCESS);
	} else {
		if (check_active_for_hard(provname, &is_active) ==
		    FAILURE) {
			return (FAILURE);
		} else if (is_active == B_TRUE) {
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



int
disable_kef_hardware(char *provname, boolean_t rndflag, boolean_t allflag,
    mechlist_t *dislist)
{
	crypto_load_dev_disabled_t	*pload_dev_dis;
	mechlist_t 	*infolist;
	entry_t		*pent;
	boolean_t	new_dev_entry = B_FALSE;
	char	devname[MAXNAMELEN];
	int	inst_num;
	int	count;
	int	fd;
	int	rc = SUCCESS;

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
	if ((pent = getent_kef(provname)) == NULL) {
		if ((pent = malloc(sizeof (entry_t))) == NULL) {
			cryptoerror(LOG_STDERR, gettext("out of memory."));
			free_mechlist(infolist);
			return (FAILURE);
		}
		new_dev_entry = B_TRUE;
		(void) strlcpy(pent->name, provname, MAXNAMELEN);
		pent->suplist = NULL;
		pent->sup_count = 0;
		pent->dislist = NULL;
		pent->dis_count = 0;
	}

	/*
	 * kCF treats random as an internal mechanism. So, we need to
	 * filter it from the mechanism list here, if we are NOT disabling
	 * or enabling the random feature. Note that we map random feature at
	 * cryptoadm(1M) level to the "random" mechanism in kCF.
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



int
disable_kef_software(char *provname, boolean_t rndflag, boolean_t allflag,
    mechlist_t *dislist)
{
	crypto_load_soft_disabled_t	*pload_soft_dis = NULL;
	mechlist_t 	*infolist;
	entry_t		*pent;
	boolean_t	is_active;
	int	fd;

	if (provname == NULL) {
		return (FAILURE);
	}

	/* Get the entry of this provider from the config file. */
	if ((pent = getent_kef(provname)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("%s does not exist."), provname);
		return (FAILURE);
	}

	/*
	 * Check if the kernel software provider is currently unloaded.
	 * If it is unloaded, return FAILURE, because the disable subcommand
	 * can not perform on inactive (unloaded) providers.
	 */
	if (check_active_for_soft(provname, &is_active) == FAILURE) {
		free_entry(pent);
		return (FAILURE);
	} else if (is_active == B_FALSE) {
		/*
		 * TRANSLATION_NOTE
		 * "disable" is a keyword and not to be translated.
		 */
		cryptoerror(LOG_STDERR,
		    gettext("can not do %1$s on an unloaded "
		    "kernel software provider -- %2$s."), "disable", provname);
		free_entry(pent);
		return (FAILURE);
	}

	/* Get the mechanism list for the software provider */
	if (get_soft_info(provname, &infolist) == FAILURE) {
		free(pent);
		return (FAILURE);
	}

	/* See comments in disable_kef_hardware() */
	if (!rndflag) {
		(void) filter_mechlist(&infolist, RANDOM);
	}

	/* Calculate the new disabled list */
	if (disable_mechs(&pent, infolist, allflag, dislist) == FAILURE) {
		free_entry(pent);
		free_mechlist(infolist);
		return (FAILURE);
	}

	/* infolist is no longer needed; free it */
	free_mechlist(infolist);

	/* Update the kcf.conf file with the updated entry */
	if (update_kcfconf(pent, MODIFY_MODE) == FAILURE) {
		free_entry(pent);
		return (FAILURE);
	}

	/* Inform kernel about the new disabled list. */
	if ((pload_soft_dis = setup_soft_dis(pent)) == NULL) {
		free_entry(pent);
		return (FAILURE);
	}

	/* pent is no longer needed; free it. */
	free_entry(pent);

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to open %s for RW: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(errno));
		free(pload_soft_dis);
		return (FAILURE);
	}

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


int
enable_kef(char *provname, boolean_t rndflag, boolean_t allflag,
    mechlist_t *mlist)
{
	crypto_load_soft_disabled_t	*pload_soft_dis = NULL;
	crypto_load_dev_disabled_t	*pload_dev_dis = NULL;
	entry_t		*pent;
	boolean_t redo_flag = B_FALSE;
	int	fd;
	int	rc = SUCCESS;


	/* Get the entry with the provider name from the kcf.conf file */
	pent = getent_kef(provname);

	if (is_device(provname)) {
		if (pent == NULL) {
			/*
			 * This device doesn't have an entry in the config
			 * file, therefore nothing is disabled.
			 */
			cryptoerror(LOG_STDERR, gettext(
			    "all mechanisms are enabled already for %s."),
			    provname);
			return (SUCCESS);
		}
	} else { /* a software module */
		if (pent == NULL) {
			cryptoerror(LOG_STDERR,
			    gettext("%s does not exist."), provname);
			return (FAILURE);
		} else if (pent->dis_count == 0) {
			/* nothing to be enabled. */
			cryptoerror(LOG_STDERR, gettext(
			    "all mechanisms are enabled already for %s."),
			    provname);
			free_entry(pent);
			return (SUCCESS);
		}
	}

	if (!rndflag) {
		/* See comments in disable_kef_hardware() */
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
	 * Update the kcf.conf file  with the updated entry.
	 * For a hardware provider, if there is no more disabled mechanism,
	 * the entire entry in the config file should be removed.
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
		return (FAILURE);
	}

	if (is_device(provname)) {
		/*  LOAD_DEV_DISABLED */
		if ((pload_dev_dis = setup_dev_dis(pent)) == NULL) {
			return (FAILURE);
		}

		if (ioctl(fd, CRYPTO_LOAD_DEV_DISABLED, pload_dev_dis) == -1) {
			cryptodebug("CRYPTO_LOAD_DEV_DISABLED ioctl failed: "
			    "%s", strerror(errno));
			free(pload_dev_dis);
			(void) close(fd);
			return (FAILURE);
		}

		if (pload_dev_dis->dd_return_value != CRYPTO_SUCCESS) {
			cryptodebug("CRYPTO_LOAD_DEV_DISABLED ioctl "
			    "return_value = %d",
			    pload_dev_dis->dd_return_value);
			free(pload_dev_dis);
			(void) close(fd);
			return (FAILURE);
		}

	} else {
		/* LOAD_SOFT_DISABLED */
		if ((pload_soft_dis = setup_soft_dis(pent)) == NULL) {
			return (FAILURE);
		}

		if (ioctl(fd, CRYPTO_LOAD_SOFT_DISABLED, pload_soft_dis)
		    == -1) {
			cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl failed: "
			    "%s", strerror(errno));
			free(pload_soft_dis);
			(void) close(fd);
			return (FAILURE);
		}

		if (pload_soft_dis->sd_return_value != CRYPTO_SUCCESS) {
			cryptodebug("CRYPTO_LOAD_SOFT_DISABLED ioctl "
			    "return_value = %d",
			    pload_soft_dis->sd_return_value);
			free(pload_soft_dis);
			(void) close(fd);
			return (FAILURE);
		}
	}

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
	boolean_t	found;
	entry_t	*pent;
	FILE	*pfile;
	FILE	*pfile_tmp;
	char	tmpfile_name[MAXPATHLEN];
	char	*ptr;
	char	*str;
	char	*name;
	char	buffer[BUFSIZ];
	char	buffer2[BUFSIZ];
	int	found_count;
	int	fd;
	int	rc = SUCCESS;

	if ((provname == NULL) || (mlist == NULL)) {
		return (FAILURE);
	}

	/* Check if the provider already exists */
	if ((pent = getent_kef(provname)) != NULL) {
		cryptoerror(LOG_STDERR, gettext("%s exists already."),
		    provname);
		free_entry(pent);
		return (FAILURE);
	}

	/* Create an entry with provname and mlist. */
	if ((pent = malloc(sizeof (entry_t))) == NULL) {
		cryptoerror(LOG_STDERR, gettext("out of memory."));
		return (FAILURE);
	}

	(void) strlcpy(pent->name, provname, MAXNAMELEN);
	pent->sup_count = get_mech_count(mlist);
	pent->suplist = mlist;
	pent->dis_count = 0;
	pent->dislist = NULL;

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
				 * Should not happen. The kcf.conf ffile
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
	entry_t		*pent;
	boolean_t	is_active;
	boolean_t	in_package;
	boolean_t	found;
	FILE	*pfile;
	FILE	*pfile_tmp;
	char	tmpfile_name[MAXPATHLEN];
	char	*name;
	char	strbuf[BUFSIZ];
	char	buffer[BUFSIZ];
	char	buffer2[BUFSIZ];
	char	*str;
	int	len;
	int	rc = SUCCESS;


	/* Check if it is in the kcf.conf file first. */
	if ((pent = getent_kef(provname)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("%s does not exist."), provname);
		return (FAILURE);
	}


	/*
	 * Get rid of the disabled list for the provider and get the converted
	 * string for the entry.  This is to prepare the string for a provider
	 * that is in a package.
	 */
	free_mechlist(pent->dislist);
	pent->dis_count = 0;
	pent->dislist = NULL;
	str = ent2str(pent);
	free_entry(pent);
	if (str == NULL) {
		cryptoerror(LOG_STDERR, gettext("internal error."));
		return (FAILURE);
	}
	(void) snprintf(strbuf, sizeof (strbuf), "%s%s", "#", str);
	free(str);

	/* If it is not loaded, unload it first  */
	if (check_active_for_soft(provname, &is_active) == FAILURE) {
		return (FAILURE);
	} else if ((is_active == B_TRUE) &&
	    (unload_kef_soft(provname, B_TRUE) == FAILURE)) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to uninstall %s.\n"), provname);
		return (FAILURE);
	}

	/*
	 * Remove the entry from the config file.  If the provider to be
	 * uninstalled is in a package, just comment it off.
	 */
	if ((pfile = fopen(_PATH_KCF_CONF, "r+")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to open %s for write.", _PATH_KCF_CONF);
		return (FAILURE);
	}

	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to lock the configuration - %s"),
		    strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}

	/*
	 * Create a temporary file in the /etc/crypto directory to save
	 * the new configuration file first.
	 */
	(void) strlcpy(tmpfile_name, TMPFILE_TEMPLATE, sizeof (tmpfile_name));
	if (mkstemp(tmpfile_name) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to create a temporary file - %s"),
		    strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}

	if ((pfile_tmp = fopen(tmpfile_name, "w")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s - %s"),
		    tmpfile_name, strerror(err));
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"), tmpfile_name,
			    strerror(err));
		}
		(void) fclose(pfile);
		return (FAILURE);
	}

	/*
	 * Loop thru the config file.  If the kernel software provider
	 * to be uninstalled is in a package, just comment it off.
	 */
	in_package = B_FALSE;
	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		found = B_FALSE;
		if (!(buffer[0] == ' ' || buffer[0] == '\n' ||
		    buffer[0] == '\t')) {
			if (strstr(buffer, " Start ") != NULL) {
				in_package = B_TRUE;
			} else if (strstr(buffer, " End ") != NULL) {
				in_package = B_FALSE;
			} else if (buffer[0] != '#') {
				(void) strlcpy(buffer2, buffer, BUFSIZ);

				/* get rid of trailing '\n' */
				len = strlen(buffer2);
				if (buffer2[len-1] == '\n') {
					len--;
				}
				buffer2[len] = '\0';

				if ((name = strtok(buffer2, SEP_COLON))
				    == NULL) {
					rc = FAILURE;
					break;
				} else if (strcmp(provname, name) == 0) {
					found = B_TRUE;
				}
			}
		}

		if (found) {
			if (in_package) {
				if (fputs(strbuf, pfile_tmp) == EOF) {
					rc = FAILURE;
				}
			}
		} else {
			if (fputs(buffer, pfile_tmp) == EOF) {
				rc = FAILURE;
			}
		}

		if (rc == FAILURE) {
			break;
		}
	}

	if (rc == FAILURE) {
		cryptoerror(LOG_STDERR, gettext("write error."));
		(void) fclose(pfile);
		(void) fclose(pfile_tmp);
		if (unlink(tmpfile_name) != 0) {
			err = errno;
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) failed to remove %s: %s"), tmpfile_name,
			    strerror(err));
		}
		return (FAILURE);
	}

	(void) fclose(pfile);
	if (fclose(pfile_tmp) != 0) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to close %s: %s"), tmpfile_name,
		    strerror(err));
		return (FAILURE);
	}

	/* Now update the real config file */
	if (rename(tmpfile_name, _PATH_KCF_CONF) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to rename %1$s to %2$s: %3$s", tmpfile,
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

	if ((rc == FAILURE) && (unlink(tmpfile_name) != 0)) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext(
		    "(Warning) failed to remove %s: %s"), tmpfile_name,
		    strerror(err));
	}

	return (rc);

}


int
refresh(void)
{
	crypto_get_soft_list_t		*psoftlist_kernel = NULL;
	crypto_load_soft_config_t	*pload_soft_conf = NULL;
	crypto_load_soft_disabled_t	*pload_soft_dis = NULL;
	crypto_load_dev_disabled_t	*pload_dev_dis = NULL;
	entrylist_t	*pdevlist = NULL;
	entrylist_t	*psoftlist = NULL;
	entrylist_t	*ptr;
	boolean_t	found;
	char 	*psoftname;
	int	fd;
	int	rc = SUCCESS;
	int	i;

	if (get_soft_list(&psoftlist_kernel) == FAILURE) {
		cryptoerror(LOG_ERR, gettext("Failed to retrieve the "
		    "software provider list from kernel."));
		return (FAILURE);
	}

	if (get_kcfconf_info(&pdevlist, &psoftlist) == FAILURE) {
		cryptoerror(LOG_ERR, "failed to retrieve the providers' "
		    "information from the configuration file - %s.",
		    _PATH_KCF_CONF);
		return (FAILURE);
	}

	/*
	 * If a kernel software provider is in kernel, but it is not in the
	 * kcf.conf file, it must have been pkgrm'ed and needs to be unloaded
	 * now.
	 */
	if (psoftlist_kernel->sl_soft_count > 0) {
		psoftname = psoftlist_kernel->sl_soft_names;
		for (i = 0; i < psoftlist_kernel->sl_soft_count; i++) {
			ptr = psoftlist;
			found = B_FALSE;
			while (ptr != NULL) {
				if (strcmp(psoftname, ptr->pent->name) == 0) {
					found = B_TRUE;
					break;
				}
				ptr = ptr->next;
			}

			if (!found) {
				rc = unload_kef_soft(psoftname, B_FALSE);
				if (rc == FAILURE) {
					cryptoerror(LOG_ERR, gettext(
					    "WARNING - the provider %s is "
					    "still in kernel."), psoftname);
				}
			}
			psoftname = psoftname + strlen(psoftname) + 1;
		}
	}
	free(psoftlist_kernel);

	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(err));
		free(psoftlist);
		free(pdevlist);
		return (FAILURE);
	}

	/*
	 * For each software module, pass two sets of information to kernel
	 * - the supported list and the disabled list
	 */
	ptr = psoftlist;
	while (ptr != NULL) {
		/* load the supported list */
		if ((pload_soft_conf = setup_soft_conf(ptr->pent)) == NULL) {
			rc = FAILURE;
			break;
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

		/* load the disabled list */
		if (ptr->pent->dis_count != 0) {
			pload_soft_dis = setup_soft_dis(ptr->pent);
			if (pload_soft_dis == NULL) {
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

		free(pload_soft_conf);
		ptr = ptr->next;
	}

	if (rc != SUCCESS) {
		(void) close(fd);
		return (rc);
	}


	/* Pass the disabledlist information for Device to kernel */
	ptr = pdevlist;
	while (ptr != NULL) {
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

		ptr = ptr->next;
	}

	(void) close(fd);
	return (rc);
}

/*
 * Unload the kernel software provider. Before calling this function, the
 * caller should check if the provider is in the config file and if it
 * is kernel. This routine makes 3 ioctl calls to remove it from kernel
 * completely. The argument do_check set to B_FALSE means that the
 * caller knows the provider is not the config file and hence the check
 * is skipped.
 */
int
unload_kef_soft(char *provname, boolean_t do_check)
{
	crypto_unload_soft_module_t 	*punload_soft = NULL;
	crypto_load_soft_config_t	*pload_soft_conf = NULL;
	crypto_load_soft_disabled_t	*pload_soft_dis = NULL;
	entry_t	*pent = NULL;
	int	fd;

	if (provname == NULL) {
		cryptoerror(LOG_STDERR, gettext("internal error."));
		return (FAILURE);
	}

	if (!do_check) {
		/* Construct an entry using the provname */
		pent = calloc(1, sizeof (entry_t));
		if (pent == NULL) {
			cryptoerror(LOG_STDERR, gettext("out of memory."));
			return (FAILURE);
		}
		(void) strlcpy(pent->name, provname, MAXNAMELEN);
	} else if ((pent = getent_kef(provname)) == NULL) {
		cryptoerror(LOG_STDERR, gettext("%s does not exist."),
		    provname);
		return (FAILURE);
	}

	/* Open the admin_ioctl_device */
	if ((fd = open(ADMIN_IOCTL_DEVICE, O_RDWR)) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR, gettext("failed to open %s: %s"),
		    ADMIN_IOCTL_DEVICE, strerror(err));
		return (FAILURE);
	}

	/* Inform kernel to unload this software module */
	if ((punload_soft = setup_unload_soft(pent)) == NULL) {
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

	/*
	 * Inform kernel to remove the configuration of this software
	 * module.
	 */
	free_mechlist(pent->suplist);
	pent->suplist = NULL;
	pent->sup_count = 0;
	if ((pload_soft_conf = setup_soft_conf(pent)) == NULL) {
		free_entry(pent);
		(void) close(fd);
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
		cryptodebug("CRYPTO_LOAD_SOFT_CONFIG ioctl return_value = "
		    "%d", pload_soft_conf->sc_return_value);
		free_entry(pent);
		free(pload_soft_conf);
		(void) close(fd);
		return (FAILURE);
	}

	free(pload_soft_conf);

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
