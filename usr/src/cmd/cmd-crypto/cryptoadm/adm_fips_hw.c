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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <zone.h>
#include <sys/crypto/ioctladmin.h>
#include "cryptoadm.h"

#define	HW_CONF_DIR	"/platform/sun4v/kernel/drv"


/* Get FIPS-140 status from .conf */
int
fips_hw_status(char *filename, char *property, int *hw_fips_mode)
{
	FILE	*pfile;
	char	buffer[BUFSIZ];
	char	*str = NULL;
	char	*cursor = NULL;

	/* Open the .conf file */
	if ((pfile = fopen(filename, "r")) == NULL) {
		cryptodebug("failed to open %s for write.", filename);
		return (FAILURE);
	}

	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		if (buffer[0] == '#') {
			/* skip comments */
			continue;
		}

		/* find the property string */
		if ((str = strstr(buffer, property)) == NULL) {
			/* didn't find the property string in this line */
			continue;
		}

		cursor = strtok(str, "= ;");
		cursor = strtok(NULL, "= ;");
		if (cursor == NULL) {
			cryptoerror(LOG_STDERR, gettext(
			    "Invalid config file contents: %s."), filename);
			(void) fclose(pfile);
			return (FAILURE);
		}
		*hw_fips_mode = atoi(cursor);
		(void) fclose(pfile);
		return (SUCCESS);
	}

	/*
	 * If the fips property is not found in the config file,
	 * FIPS mode is false by default.
	 */
	*hw_fips_mode = CRYPTO_FIPS_MODE_DISABLED;
	(void) fclose(pfile);

	return (SUCCESS);
}

/*
 * Update the HW .conf file with the updated entry.
 */
int
fips_update_hw_conf(char *filename, char *property, int action)
{
	FILE		*pfile;
	FILE		*pfile_tmp;
	char		buffer[BUFSIZ];
	char		buffer2[BUFSIZ];
	char		*tmpfile_name = NULL;
	char		*str = NULL;
	char		*cursor = NULL;
	int		rc = SUCCESS;
	boolean_t	found = B_FALSE;

	/* Open the .conf file */
	if ((pfile = fopen(filename, "r+")) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(errno));
		cryptodebug("failed to open %s for write.", filename);
		return (FAILURE);
	}

	/* Lock the .conf file */
	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(errno));
		cryptodebug(gettext("failed to lock %s"), filename);
		(void) fclose(pfile);
		return (FAILURE);
	}

	/*
	 * Create a temporary file to save updated configuration file first.
	 */
	tmpfile_name = tempnam(HW_CONF_DIR, NULL);
	if ((pfile_tmp = fopen(tmpfile_name, "w")) == NULL) {
		cryptoerror(LOG_STDERR, gettext("failed to open %s - %s"),
		    tmpfile_name, strerror(errno));
		free(tmpfile_name);
		(void) fclose(pfile);
		return (FAILURE);
	}


	/*
	 * Loop thru entire .conf file, update the entry to be
	 * updated and save the updated file to the temporary file first.
	 */
	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		if (buffer[0] == '#') {
			/* comments: write to the file without modification */
			goto write_to_tmp;
		}

		(void) strlcpy(buffer2, buffer, BUFSIZ);

		/* find the property string */
		if ((str = strstr(buffer2, property)) == NULL) {
			/*
			 * Didn't find the property string in this line.
			 * Write to the file without modification.
			 */
			goto write_to_tmp;
		}

		found = B_TRUE;

		cursor = strtok(str, "= ;");
		cursor = strtok(NULL, "= ;");
		if (cursor == NULL) {
			cryptoerror(LOG_STDERR, gettext(
			    "Invalid config file contents %s: %s."),
			    filename, strerror(errno));
			goto errorexit;
		}

		cursor = buffer + (cursor - buffer2);
		*cursor = (action == FIPS140_ENABLE) ? '1' : '0';

write_to_tmp:

		if (fputs(buffer, pfile_tmp) == EOF) {
			cryptoerror(LOG_STDERR, gettext(
			    "failed to write to a temp file: %s."),
			    strerror(errno));
			goto errorexit;
		}
	}

	/* if the fips mode property is not specified, FALSE by default */
	if (found == B_FALSE) {
		(void) snprintf(buffer, BUFSIZ, "%s=%c;\n",
		    property, (action == FIPS140_ENABLE) ? '1' : '0');
		if (fputs(buffer, pfile_tmp) == EOF) {
			cryptoerror(LOG_STDERR, gettext(
			    "failed to write to a tmp file: %s."),
			    strerror(errno));
			goto errorexit;
		}
	}

	(void) fclose(pfile);
	if (fclose(pfile_tmp) != 0) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to close %s: %s"), tmpfile_name,
		    strerror(errno));
		free(tmpfile_name);
		return (FAILURE);
	}

	/* Copy the temporary file to the .conf file */
	if (rename(tmpfile_name, filename) == -1) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(errno));
		cryptodebug("failed to rename %s to %s: %s", tmpfile_name,
		    filename, strerror(errno));
		rc = FAILURE;
	} else if (chmod(filename,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) == -1) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(errno));
		cryptodebug("failed to chmod to %s: %s", filename,
		    strerror(errno));
		rc = FAILURE;
	} else {
		rc = SUCCESS;
	}

	if ((rc == FAILURE) && (unlink(tmpfile_name) != 0)) {
		cryptoerror(LOG_STDERR, gettext(
		    "(Warning) failed to remove %s: %s"),
		    tmpfile_name, strerror(errno));
	}

	free(tmpfile_name);
	return (rc);

errorexit:
	(void) fclose(pfile);
	(void) fclose(pfile_tmp);
	free(tmpfile_name);

	return (FAILURE);
}


/*
 * Perform the FIPS related actions
 */
int
do_fips_hw_actions(int action, int provider)
{
	int			rc = SUCCESS;
	int			fips_mode = 0;
	char			*filename;
	char			*propname;
	char			*provname;

	switch (provider) {
	case HW_PROVIDER_NCP:
		filename = "/platform/sun4v/kernel/drv/ncp.conf";
		propname = "ncp-fips-140";
		provname = "ncp";
		break;
	case HW_PROVIDER_N2CP:
		filename = "/platform/sun4v/kernel/drv/n2cp.conf";
		propname = "n2cp-fips-140";
		provname = "n2cp";
		break;
	case HW_PROVIDER_N2RNG:
		filename = "/platform/sun4v/kernel/drv/n2rng.conf";
		propname = "n2rng-fips-140";
		provname = "n2rng";
		break;
	default:
		(void) printf(gettext("Internal Error: Invalid HW "
		    "provider [%d] specified.\n"));
		return (FAILURE);
	}

	/* Get FIPS-140 status from .conf */
	if (fips_hw_status(filename, propname, &fips_mode) != SUCCESS) {
		return (FAILURE);
	}

	if (action == FIPS140_STATUS) {
		if (fips_mode == CRYPTO_FIPS_MODE_ENABLED)
			(void) printf(gettext(
			    "%s: FIPS-140 mode is enabled.\n"), provname);
		else
			(void) printf(gettext(
			    "%s: FIPS-140 mode is disabled.\n"), provname);
		return (SUCCESS);
	}

	/* Is it a duplicate operation? */
	if ((action == FIPS140_ENABLE) &&
	    (fips_mode == CRYPTO_FIPS_MODE_ENABLED)) {
		(void) printf(
		    gettext("%s: FIPS-140 mode has already been enabled.\n"),
		    provname);
		return (FAILURE);
	}

	if ((action == FIPS140_DISABLE) &&
	    (fips_mode == CRYPTO_FIPS_MODE_DISABLED)) {
		(void) printf(
		    gettext("%s: FIPS-140 mode has already been disabled.\n"),
		    provname);
		return (FAILURE);
	}

	if ((action == FIPS140_ENABLE) || (action == FIPS140_DISABLE)) {
		/* Update .conf */
		if ((rc = fips_update_hw_conf(filename, propname, action))
		    != SUCCESS)
			return (rc);
	}

	/* No need to inform kernel */
	if (action == FIPS140_ENABLE) {
		(void) printf(gettext(
		    "%s: FIPS-140 mode was enabled successfully.\n"),
		    provname);
	} else {
		(void) printf(gettext(
		    "%s: FIPS-140 mode was disabled successfully.\n"),
		    provname);
	}

	return (SUCCESS);
}
