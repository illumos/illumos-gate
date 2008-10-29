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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <locale.h>
#include <sys/types.h>
#include <zone.h>
#include <sys/stat.h>
#include "cryptoadm.h"

static int err; /* To store errno which may be overwritten by gettext() */
static int build_entrylist(entry_t *, entrylist_t **);
static entry_t *dup_entry(entry_t *);
static mechlist_t *dup_mechlist(mechlist_t *);
static entry_t *getent(char *, entrylist_t *);
static int interpret(char *, entry_t **);
static int parse_sup_dis_list(char *, entry_t *);


/*
 * Duplicate the mechanism list.  A null pointer is returned if the storage
 * space available is insufficient or the input argument is NULL.
 */
static mechlist_t *
dup_mechlist(mechlist_t *plist)
{
	mechlist_t	*pres = NULL;
	mechlist_t	*pcur;
	mechlist_t	*ptmp;
	int		rc = SUCCESS;

	while (plist != NULL) {
		if (!(ptmp = create_mech(plist->name))) {
			rc = FAILURE;
			break;
		}

		if (pres == NULL) {
			pres = pcur = ptmp;
		} else {
			pcur->next = ptmp;
			pcur = pcur->next;
		}
		plist = plist->next;
	}

	if (rc != SUCCESS) {
		free_mechlist(pres);
		return (NULL);
	}

	return (pres);
}


/*
 * Get the number of mechanisms in the mechanism list.
 */
int
get_mech_count(mechlist_t *plist)
{
	int count = 0;

	while (plist != NULL) {
		count++;
		plist = plist->next;
	}
	return (count);
}

/*
 * Create one item of type entry_t with the provider name.
 * Return NULL if there's not enough memory or provname is NULL.
 */
entry_t *
create_entry(char *provname)
{
	entry_t		*pent = NULL;

	if (provname == NULL) {
		return (NULL);
	}

	pent = calloc(1, sizeof (entry_t));
	if (pent == NULL) {
		cryptodebug("out of memory.");
		return (NULL);
	}

	(void) strlcpy(pent->name, provname, MAXNAMELEN);
	pent->suplist = NULL;
	pent->sup_count = 0;
	pent->dislist = NULL;
	pent->dis_count = 0;
	pent->load = B_TRUE;

	return (pent);
}

/*
 * Duplicate an entry for a provider from kcf.conf.
 * Return NULL if memory is insufficient or the input argument is NULL.
 * Called by getent().
 */
static entry_t *
dup_entry(entry_t *pent1)
{
	entry_t	*pent2 = NULL;

	if (pent1 == NULL) {
		return (NULL);
	}

	if ((pent2 = create_entry(pent1->name)) == NULL) {
		cryptodebug("out of memory.");
		return (NULL);
	}

	pent2->sup_count = pent1->sup_count;
	pent2->dis_count = pent1->dis_count;
	pent2->load = pent1->load;
	if (pent1->suplist != NULL) {
		pent2->suplist = dup_mechlist(pent1->suplist);
		if (pent2->suplist == NULL) {
			free_entry(pent2);
			return (NULL);
		}
	}
	if (pent1->dislist != NULL) {
		pent2->dislist = dup_mechlist(pent1->dislist);
		if (pent2->dislist == NULL) {
			free_entry(pent2);
			return (NULL);
		}
	}

	return (pent2);
}


/*
 * This routine parses the disabledlist or the supportedlist of an entry
 * in the kcf.conf configuration file.
 *
 * Arguments:
 *	buf: an input argument which is a char string with the format of
 *	     "disabledlist=m1,m2,..." or "supportedlist=m1,m2,..."
 *	pent: the entry for the disabledlist.  This is an IN/OUT argument.
 *
 * Return value: SUCCESS or FAILURE.
 */
static int
parse_sup_dis_list(char *buf, entry_t *pent)
{
	mechlist_t	*pmech = NULL;
	mechlist_t	*phead = NULL;
	char		*next_token;
	char		*value;
	int		count;
	int		supflag = B_FALSE;
	int		disflag = B_FALSE;
	int		rc = SUCCESS;

	if (strncmp(buf, EF_SUPPORTED, strlen(EF_SUPPORTED)) == 0) {
		supflag = B_TRUE;
	} else if (strncmp(buf, EF_DISABLED, strlen(EF_DISABLED)) == 0) {
		disflag = B_TRUE;
	} else {
		/* should not come here */
		return (FAILURE);
	}

	if (value = strpbrk(buf, SEP_EQUAL)) {
		value++; /* get rid of = */
	} else {
		cryptodebug("failed to parse the kcf.conf file.");
		return (FAILURE);
	}

	if ((next_token = strtok(value, SEP_COMMA)) == NULL) {
		cryptodebug("failed to parse the kcf.conf file.");
		return (FAILURE);
	}

	if ((pmech = create_mech(next_token)) == NULL) {
		return (FAILURE);
	}

	if (supflag) {
		pent->suplist = phead = pmech;
	} else if (disflag) {
		pent->dislist = phead = pmech;
	}

	count = 1;
	while (next_token) {
		if (next_token = strtok(NULL, SEP_COMMA)) {
			if ((pmech = create_mech(next_token)) == NULL) {
				rc = FAILURE;
				break;
			}
			count++;
			phead->next = pmech;
			phead = phead->next;
		}
	}

	if (rc == SUCCESS) {
		if (supflag) {
			pent->sup_count = count;
		} else if (disflag) {
			pent->dis_count = count;
		}
	} else {
		free_mechlist(phead);
	}

	return (rc);
}


/*
 * Convert a char string containing a line about a provider
 * from kcf.conf into an entry_t structure.
 *
 * See ent2str(), the reverse of this function, for the format of
 * kcf.conf lines.
 */
static int
interpret(char *buf, entry_t **ppent)
{
	entry_t	*pent = NULL;
	char	*token1;
	char	*token2;
	char	*token3;
	int	rc;

	/* Get provider name */
	if ((token1 = strtok(buf, SEP_COLON)) == NULL) { /* buf is NULL */
		return (FAILURE);
	};

	pent = create_entry(token1);
	if (pent == NULL) {
		cryptodebug("out of memory.");
		return (FAILURE);
	}

	if ((token2 = strtok(NULL, SEP_SEMICOLON)) == NULL) {
		/* The entry contains a provider name only */
		free_entry(pent);
		return (FAILURE);
	}

	if (strncmp(token2, EF_UNLOAD, strlen(EF_UNLOAD)) == 0) {
		pent->load = B_FALSE; /* cryptoadm unload */
		if ((token2 = strtok(NULL, SEP_SEMICOLON)) == NULL) {
			/* The entry contains a provider name:unload only */
			free_entry(pent);
			return (FAILURE);
		}
	}

	/* need to get token3 first to satisfy nested strtok invocations */
	token3 = strtok(NULL, SEP_SEMICOLON); /* optional */

	/* parse supportedlist (or disabledlist if no supportedlist) */
	if ((token2 != NULL) && ((rc = parse_sup_dis_list(token2, pent)) !=
	    SUCCESS)) {
		free_entry(pent);
		return (rc);
	}

	/* parse disabledlist (if there's a supportedlist) */
	if ((token3 != NULL) && ((rc = parse_sup_dis_list(token3, pent)) !=
	    SUCCESS)) {
		free_entry(pent);
		return (rc);
	}

	*ppent = pent;
	return (SUCCESS);
}


/*
 * Add an entry about a provider from kcf.conf to the end of an entry list.
 * If the entry list pplist is NULL, create the linked list with pent as the
 * first element.
 */
static int
build_entrylist(entry_t *pent, entrylist_t **pplist)
{
	entrylist_t	*pentlist;
	entrylist_t	*pcur = NULL;

	pentlist = malloc(sizeof (entrylist_t));
	if (pentlist == NULL) {
		cryptodebug("out of memory.");
		return (FAILURE);
	}
	pentlist->pent = pent;
	pentlist->next = NULL;

	if (*pplist) {
		pcur = *pplist;
		while (pcur->next != NULL)
			pcur = pcur->next;
		pcur->next = pentlist;
	} else { /* empty list */
		*pplist = pentlist;
	}

	return (SUCCESS);
}



/*
 * Find the entry with the "provname" name from the entry list and duplicate
 * it.  Called by getent_kef().
 */
static entry_t *
getent(char *provname, entrylist_t *entrylist)
{
	boolean_t	found = B_FALSE;
	entry_t		*pent1 = NULL;

	if ((provname == NULL) || (entrylist == NULL)) {
		return (NULL);
	}

	while (!found && entrylist) {
		if (strcmp(entrylist->pent->name, provname) == 0) {
			found = B_TRUE;
			pent1 = entrylist->pent;
		} else {
			entrylist = entrylist->next;
		}
	}

	if (!found) {
		return (NULL);
	}

	/* duplicate the entry to be returned */
	return (dup_entry(pent1));
}


/*
 * Free memory in entry_t.
 * That is, the supported and disabled lists for a provider
 * from kcf.conf.
 */
void
free_entry(entry_t  *pent)
{
	if (pent == NULL) {
		return;
	} else {
		free_mechlist(pent->suplist);
		free_mechlist(pent->dislist);
		free(pent);
	}
}


/*
 * Free elements in a entrylist_t linked list,
 * which lists providers in kcf.conf.
 */
void
free_entrylist(entrylist_t *entrylist)
{
	entrylist_t *pnext;

	while (entrylist != NULL) {
		pnext = entrylist->next;
		free_entry(entrylist->pent);
		entrylist = pnext;
	}
}


/*
 * Convert an entry to a string.  This routine builds a string for the entry
 * to be inserted in the kcf.conf file.  Based on the content of each entry,
 * the result string can be one of these 6 forms:
 *  - name:supportedlist=m1,m2,...,mj
 *  - name:disabledlist=m1,m2,...,mj
 *  - name:supportedlist=m1,...,mj;disabledlist=m1,m2,...,mk
 *
 *  - name:unload;supportedlist=m1,m2,...,mj
 *  - name:unload;disabledlist=m1,m2,...,mj
 *  - name:unload;supportedlist=m1,...,mj;disabledlist=m1,m2,...,mk
 *
 * Note that the caller is responsible for freeing the returned string
 * (with free_entry()).
 * See interpret() for the reverse of this function: converting a string
 * to an entry_t.
 */
char *
ent2str(entry_t *pent)
{
	char		*buf;
	mechlist_t	*pcur = NULL;
	boolean_t	semicolon_separator = B_FALSE;


	if (pent == NULL) {
		return (NULL);
	}

	if ((buf = malloc(BUFSIZ)) == NULL) {
		return (NULL);
	}

	/* convert the provider name */
	if (strlcpy(buf, pent->name, BUFSIZ) >= BUFSIZ) {
		free(buf);
		return (NULL);
	}

	if (!pent->load) { /* add "unload" keyword */
		if (strlcat(buf, SEP_COLON, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (strlcat(buf, EF_UNLOAD, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		semicolon_separator = B_TRUE;
	}

	/* convert the supported list if any */
	pcur = pent->suplist;
	if (pcur != NULL) {
		if (strlcat(buf,
		    semicolon_separator ? SEP_SEMICOLON : SEP_COLON,
		    BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (strlcat(buf, EF_SUPPORTED, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		while (pcur != NULL) {
			if (strlcat(buf, pcur->name, BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}

			pcur = pcur->next;
			if (pcur != NULL) {
				if (strlcat(buf, SEP_COMMA, BUFSIZ)
				    >= BUFSIZ) {
					free(buf);
					return (NULL);
				}
			}
		}
		semicolon_separator = B_TRUE;
	}

	/* convert the disabled list if any */
	pcur = pent->dislist;
	if (pcur != NULL) {
		if (strlcat(buf,
		    semicolon_separator ? SEP_SEMICOLON : SEP_COLON,
		    BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		if (strlcat(buf, EF_DISABLED, BUFSIZ) >= BUFSIZ) {
			free(buf);
			return (NULL);
		}

		while (pcur != NULL) {
			if (strlcat(buf, pcur->name, BUFSIZ) >= BUFSIZ) {
				free(buf);
				return (NULL);
			}

			pcur = pcur->next;
			if (pcur != NULL) {
				if (strlcat(buf, SEP_COMMA, BUFSIZ)
				    >= BUFSIZ) {
					free(buf);
					return (NULL);
				}
			}
		}
		semicolon_separator = B_TRUE;
	}

	if (strlcat(buf, "\n", BUFSIZ) >= BUFSIZ) {
		free(buf);
		return (NULL);
	}

	return (buf);
}


/*
 * Enable the mechanisms for the provider pointed by *ppent.  If allflag is
 * TRUE, enable all.  Otherwise, enable the mechanisms specified in the 3rd
 * argument "mlist".  The result will be stored in ppent also.
 */
int
enable_mechs(entry_t **ppent, boolean_t allflag, mechlist_t *mlist)
{
	entry_t		*pent;
	mechlist_t	*phead; /* the current and resulting disabled list */
	mechlist_t	*ptr = NULL;
	mechlist_t	*pcur = NULL;
	boolean_t	found;

	pent = *ppent;
	if (pent == NULL) {
		return (FAILURE);
	}

	if (allflag) {
		free_mechlist(pent->dislist);
		pent->dis_count = 0;
		pent->dislist = NULL;
		return (SUCCESS);
	}

	/*
	 * for each mechanism in the to-be-enabled mechanism list,
	 * -	check if it is in the current disabled list
	 * -	if found, delete it from the disabled list
	 *	otherwise, give a warning.
	 */
	ptr = mlist;
	while (ptr != NULL) {
		found = B_FALSE;
		phead = pcur =  pent->dislist;
		while (!found && pcur) {
			if (strcmp(pcur->name, ptr->name) == 0) {
				found = B_TRUE;
			} else {
				phead = pcur;
				pcur = pcur->next;
			}
		}

		if (found) {
			if (phead == pcur) {
				pent->dislist = pent->dislist->next;
				free(pcur);
			} else {
				phead->next = pcur->next;
				free(pcur);
			}
			pent->dis_count--;
		} else {
			cryptoerror(LOG_STDERR, gettext(
			    "(Warning) %1$s is either enabled already or not "
			    "a valid mechanism for %2$s"), ptr->name,
			    pent->name);
		}
		ptr = ptr->next;
	}

	if (pent->dis_count == 0) {
		pent->dislist = NULL;
	}

	return (SUCCESS);

}


/*
 * Determine if the kernel provider name, path, is a device
 * (that is, it contains a slash character (e.g., "mca/0").
 * If so, it is a hardware provider; otherwise it is a software provider.
 */
boolean_t
is_device(char *path)
{
	if (strchr(path, SEP_SLASH) != NULL) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

/*
 * Split a hardware provider name with the "name/inst_num" format into
 * a name and a number (e.g., split "mca/0" into "mca" instance 0).
 */
int
split_hw_provname(char *provname, char *pname, int *inst_num)
{
	char	name[MAXNAMELEN];
	char	*inst_str;

	if (provname == NULL) {
		return (FAILURE);
	}

	(void) strlcpy(name, provname, MAXNAMELEN);
	if (strtok(name, "/") == NULL) {
		return (FAILURE);
	}

	if ((inst_str = strtok(NULL, "/")) == NULL) {
		return (FAILURE);
	}

	(void) strlcpy(pname, name, MAXNAMELEN);
	*inst_num = atoi(inst_str);

	return (SUCCESS);
}


/*
 * Retrieve information from kcf.conf and build a hardware device entry list
 * and a software entry list of kernel crypto providers.
 *
 * This list is usually incomplete, as kernel crypto providers only have to
 * be listed in kcf.conf if a mechanism is disabled (by cryptoadm) or
 * if the kernel provider module is not one of the default kernel providers.
 *
 * The kcf.conf file is available only in the global zone.
 */
int
get_kcfconf_info(entrylist_t **ppdevlist, entrylist_t **ppsoftlist)
{
	FILE	*pfile = NULL;
	char	buffer[BUFSIZ];
	int	len;
	entry_t	*pent = NULL;
	int	rc = SUCCESS;

	if ((pfile = fopen(_PATH_KCF_CONF, "r")) == NULL) {
		cryptodebug("failed to open the kcf.conf file for read only");
		return (FAILURE);
	}

	*ppdevlist = NULL;
	*ppsoftlist = NULL;
	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		if (buffer[0] == '#' || buffer[0] == ' ' ||
		    buffer[0] == '\n'|| buffer[0] == '\t') {
			continue;   /* ignore comment lines */
		}

		len = strlen(buffer);
		if (buffer[len - 1] == '\n') { /* get rid of trailing '\n' */
			len--;
		}
		buffer[len] = '\0';

		if ((rc = interpret(buffer,  &pent)) == SUCCESS) {
			if (is_device(pent->name)) {
				rc = build_entrylist(pent, ppdevlist);
			} else {
				rc = build_entrylist(pent, ppsoftlist);
			}
		} else {
			cryptoerror(LOG_STDERR, gettext(
			    "failed to parse configuration."));
		}

		if (rc != SUCCESS) {
			free_entrylist(*ppdevlist);
			free_entrylist(*ppsoftlist);
			free_entry(pent);
			break;
		}
	}

	(void) fclose(pfile);
	return (rc);
}

/*
 * Retrieve information from admin device and build a device entry list and
 * a software entry list.  This is used where there is no kcf.conf, e.g., the
 * non-global zone.
 */
int
get_admindev_info(entrylist_t **ppdevlist, entrylist_t **ppsoftlist)
{
	crypto_get_dev_list_t	*pdevlist_kernel = NULL;
	crypto_get_soft_list_t	*psoftlist_kernel = NULL;
	char			*devname;
	int			inst_num;
	int			mcount;
	mechlist_t		*pmech = NULL;
	entry_t			*pent_dev = NULL, *pent_soft = NULL;
	int			i;
	char			*psoftname;
	entrylist_t		*tmp_pdev = NULL;
	entrylist_t		*tmp_psoft = NULL;
	entrylist_t		*phardlist = NULL, *psoftlist = NULL;

	/*
	 * Get hardware providers
	 */
	if (get_dev_list(&pdevlist_kernel) != SUCCESS) {
		cryptodebug("failed to get hardware provider list from kernel");
		return (FAILURE);
	}

	for (i = 0; i < pdevlist_kernel->dl_dev_count; i++) {
		devname = pdevlist_kernel->dl_devs[i].le_dev_name;
		inst_num = pdevlist_kernel->dl_devs[i].le_dev_instance;
		mcount = pdevlist_kernel->dl_devs[i].le_mechanism_count;

		pmech = NULL;
		if (get_dev_info(devname, inst_num, mcount, &pmech) !=
		    SUCCESS) {
			cryptodebug(
			    "failed to retrieve the mechanism list for %s/%d.",
			    devname, inst_num);
			goto fail_out;
		}

		if ((pent_dev = create_entry(devname)) == NULL) {
			cryptodebug("out of memory.");
			free_mechlist(pmech);
			goto fail_out;
		}
		pent_dev->suplist = pmech;
		pent_dev->sup_count = mcount;

		if (build_entrylist(pent_dev, &tmp_pdev) != SUCCESS) {
			goto fail_out;
		}
	}

	free(pdevlist_kernel);
	pdevlist_kernel = NULL;

	/*
	 * Get software providers
	 */
	if (getzoneid() == GLOBAL_ZONEID) {
		if (get_kcfconf_info(&phardlist, &psoftlist) != SUCCESS) {
			goto fail_out;
		}
	}

	if (get_soft_list(&psoftlist_kernel) != SUCCESS) {
		cryptodebug("failed to get software provider list from kernel");
		goto fail_out;
	}

	for (i = 0, psoftname = psoftlist_kernel->sl_soft_names;
	    i < psoftlist_kernel->sl_soft_count;
	    i++, psoftname = psoftname + strlen(psoftname) + 1) {
		pmech = NULL;
		if (get_soft_info(psoftname, &pmech, phardlist, psoftlist) !=
		    SUCCESS) {
			cryptodebug(
			    "failed to retrieve the mechanism list for %s.",
			    psoftname);
			goto fail_out;
		}

		if ((pent_soft = create_entry(psoftname)) == NULL) {
			cryptodebug("out of memory.");
			free_mechlist(pmech);
			goto fail_out;
		}
		pent_soft->suplist = pmech;
		pent_soft->sup_count = get_mech_count(pmech);

		if (build_entrylist(pent_soft, &tmp_psoft) != SUCCESS) {
			goto fail_out;
		}
	}

	free(psoftlist_kernel);
	psoftlist_kernel = NULL;

	*ppdevlist = tmp_pdev;
	*ppsoftlist = tmp_psoft;

	return (SUCCESS);

fail_out:
	if (pent_dev != NULL)
		free_entry(pent_dev);
	if (pent_soft != NULL)
		free_entry(pent_soft);

	free_entrylist(tmp_pdev);
	free_entrylist(tmp_psoft);

	if (pdevlist_kernel != NULL)
		free(pdevlist_kernel);
	if (psoftlist_kernel != NULL)
		free(psoftlist_kernel);

	return (FAILURE);
}

/*
 * Return configuration information for a kernel provider from kcf.conf.
 * For kernel software providers return a enabled list and disabled list.
 * For kernel hardware providers return just a disabled list.
 *
 * Parameters phardlist and psoftlist are supplied by get_kcfconf_info().
 * If NULL, this function calls get_kcfconf_info() internally.
 */
entry_t *
getent_kef(char *provname, entrylist_t *phardlist, entrylist_t *psoftlist)
{
	entry_t		*pent = NULL;
	boolean_t	memory_allocated = B_FALSE;

	if ((phardlist == NULL) || (psoftlist == NULL)) {
		if (get_kcfconf_info(&phardlist, &psoftlist) != SUCCESS) {
			return (NULL);
		}
		memory_allocated = B_TRUE;
	}

	if (is_device(provname)) {
		pent = getent(provname, phardlist);
	} else {
		pent = getent(provname, psoftlist);
	}

	if (memory_allocated) {
		free_entrylist(phardlist);
		free_entrylist(psoftlist);
	}

	return (pent);
}

/*
 * Print out the provider name and the mechanism list.
 */
void
print_mechlist(char *provname, mechlist_t *pmechlist)
{
	mechlist_t *ptr = NULL;

	if (provname == NULL) {
		return;
	}

	(void) printf("%s: ", provname);
	if (pmechlist == NULL) {
		(void) printf(gettext("No mechanisms presented.\n"));
		return;
	}

	ptr = pmechlist;
	while (ptr != NULL) {
		(void) printf("%s", ptr->name);
		ptr = ptr->next;
		if (ptr == NULL) {
			(void) printf("\n");
		} else {
			(void) printf(",");
		}
	}
}


/*
 * Update the kcf.conf file based on the update mode:
 * - If update_mode is MODIFY_MODE, modify the entry with the same name.
 *   If not found, append a new entry to the kcf.conf file.
 * - If update_mode is DELETE_MODE, delete the entry with the same name.
 * - If update_mode is ADD_MODE, append a new entry to the kcf.conf file.
 */
int
update_kcfconf(entry_t *pent, int update_mode)
{
	boolean_t	add_it = B_FALSE;
	boolean_t	delete_it = B_FALSE;
	boolean_t	found_entry = B_FALSE;
	FILE		*pfile = NULL;
	FILE		*pfile_tmp = NULL;
	char		buffer[BUFSIZ];
	char		buffer2[BUFSIZ];
	char		tmpfile_name[MAXPATHLEN];
	char		*name;
	char		*new_str = NULL;
	int		rc = SUCCESS;

	if (pent == NULL) {
		cryptoerror(LOG_STDERR, gettext("internal error."));
		return (FAILURE);
	}

	/* Check the update_mode */
	switch (update_mode) {
	case ADD_MODE:
		add_it = B_TRUE;
		/* FALLTHROUGH */
	case MODIFY_MODE:
		/* Convert the entry a string to add to kcf.conf  */
		if ((new_str = ent2str(pent)) == NULL) {
			return (FAILURE);
		}
		break;
	case DELETE_MODE:
		delete_it = B_TRUE;
		break;
	default:
		cryptoerror(LOG_STDERR, gettext("internal error."));
		return (FAILURE);
	}

	/* Open the kcf.conf file */
	if ((pfile = fopen(_PATH_KCF_CONF, "r+")) == NULL) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to open %s for write.", _PATH_KCF_CONF);
		return (FAILURE);
	}

	/* Lock the kcf.conf file */
	if (lockf(fileno(pfile), F_TLOCK, 0) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		(void) fclose(pfile);
		return (FAILURE);
	}

	/*
	 * Create a temporary file in the /etc/crypto directory to save
	 * updated configuration file first.
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
		(void) fclose(pfile);
		return (FAILURE);
	}

	/*
	 * Loop thru the entire kcf.conf file, insert, modify or delete
	 * an entry.
	 */
	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		if (add_it) {
			if (fputs(buffer, pfile_tmp) == EOF) {
				err = errno;
				cryptoerror(LOG_STDERR, gettext(
				    "failed to write to a temp file: %s."),
				    strerror(err));
				rc = FAILURE;
				break;
			}

		} else { /* modify or delete */
			found_entry = B_FALSE;

			if (!(buffer[0] == '#' || buffer[0] == ' ' ||
			    buffer[0] == '\n'|| buffer[0] == '\t')) {
				/*
				 * Get the provider name from this line and
				 * check if this is the entry to be updated
				 * or deleted. Note: can not use "buffer"
				 * directly because strtok will change its
				 * value.
				 */
				(void) strlcpy(buffer2, buffer, BUFSIZ);
				if ((name = strtok(buffer2, SEP_COLON)) ==
				    NULL) {
					rc = FAILURE;
					break;
				}

				if (strcmp(pent->name, name) == 0) {
					found_entry = B_TRUE;
				}
			}

			if (found_entry && !delete_it) {
				/*
				 * This is the entry to be updated; get the
				 * updated string and place into buffer.
				 */
				(void) strlcpy(buffer, new_str, BUFSIZ);
				free(new_str);
			}

			if (!(found_entry && delete_it)) {
				/* This is the entry to be updated/reserved */
				if (fputs(buffer, pfile_tmp) == EOF) {
					err = errno;
					cryptoerror(LOG_STDERR, gettext(
					    "failed to write to a temp file: "
					    "%s."), strerror(err));
					rc = FAILURE;
					break;
				}
			}
		}
	}

	if ((!delete_it) && (rc != FAILURE)) {
		if (add_it || !found_entry) {
			/* append new entry to end of file */
			if (fputs(new_str, pfile_tmp) == EOF) {
				err = errno;
				cryptoerror(LOG_STDERR, gettext(
				    "failed to write to a temp file: %s."),
				    strerror(err));
				rc = FAILURE;
			}
			free(new_str);
		}
	}

	(void) fclose(pfile);
	if (fclose(pfile_tmp) != 0) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to close %s: %s"), tmpfile_name,
		    strerror(err));
		return (FAILURE);
	}

	/* Copy the temporary file to the kcf.conf file */
	if (rename(tmpfile_name, _PATH_KCF_CONF) == -1) {
		err = errno;
		cryptoerror(LOG_STDERR,
		    gettext("failed to update the configuration - %s"),
		    strerror(err));
		cryptodebug("failed to rename %s to %s: %s", tmpfile,
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
		    "(Warning) failed to remove %s: %s"),
		    tmpfile_name, strerror(err));
	}

	return (rc);
}


/*
 * Disable the mechanisms for the provider pointed by *ppent.  If allflag is
 * TRUE, disable all.  Otherwise, disable the mechanisms specified in the
 * dislist argument.  The "infolist" argument contains the mechanism list
 * supported by this provider.
 */
int
disable_mechs(entry_t **ppent, mechlist_t *infolist, boolean_t allflag,
mechlist_t *dislist)
{
	entry_t		*pent;
	mechlist_t	*plist = NULL;
	mechlist_t	*phead = NULL;
	mechlist_t	*pmech = NULL;
	int		rc = SUCCESS;

	pent = *ppent;
	if (pent == NULL) {
		return (FAILURE);
	}

	if (allflag) {
		free_mechlist(pent->dislist);
		pent->dis_count = get_mech_count(infolist);
		if (!(pent->dislist = dup_mechlist(infolist))) {
			return (FAILURE);
		} else {
			return (SUCCESS);
		}
	}

	/*
	 * Not disable all. Now loop thru the mechanisms specified in the
	 * dislist.  If the mechanism is not supported by the provider,
	 * ignore it with a warning.  If the mechanism is disabled already,
	 * do nothing. Otherwise, prepend it to the beginning of the disabled
	 * list of the provider.
	 */
	plist = dislist;
	while (plist != NULL) {
		if (!is_in_list(plist->name, infolist)) {
			cryptoerror(LOG_STDERR, gettext("(Warning) "
			    "%1$s is not a valid mechanism for %2$s."),
			    plist->name, pent->name);
		} else if (!is_in_list(plist->name, pent->dislist)) {
			/* Add this mechanism into the disabled list */
			if ((pmech = create_mech(plist->name)) == NULL) {
				rc = FAILURE;
				break;
			}

			if (pent->dislist == NULL) {
				pent->dislist = pmech;
			} else {
				phead = pent->dislist;
				pent->dislist = pmech;
				pmech->next = phead;
			}
			pent->dis_count++;
		}
		plist = plist->next;
	}

	return (rc);
}

/*
 * Remove the mechanism passed, specified by mech, from the list of
 * mechanisms, if present in the list. Else, do nothing.
 *
 * Returns B_TRUE if mechanism is present in the list.
 */
boolean_t
filter_mechlist(mechlist_t **pmechlist, const char *mech)
{
	int		cnt = 0;
	mechlist_t	*ptr, *pptr;
	boolean_t	mech_present = B_FALSE;

	ptr = pptr = *pmechlist;

	while (ptr != NULL) {
		if (strncmp(ptr->name, mech, sizeof (mech_name_t)) == 0) {
			mech_present = B_TRUE;
			if (ptr == *pmechlist) {
				pptr = *pmechlist = ptr->next;
				free(ptr);
				ptr = pptr;
			} else {
				pptr->next = ptr->next;
				free(ptr);
				ptr = pptr->next;
			}
		} else {
			pptr = ptr;
			ptr = ptr->next;
			cnt++;
		}
	}

	/* Only one entry is present */
	if (cnt == 0)
		*pmechlist = NULL;

	return (mech_present);
}



/*
 * Print out the mechanism policy for a kernel provider that has an entry
 * in the kcf.conf file.
 *
 * The flag has_random is set to B_TRUE if the provider does random
 * numbers. The flag has_mechs is set by the caller to B_TRUE if the provider
 * has some mechanisms.
 *
 * If pent is NULL, the provider doesn't have a kcf.conf entry.
 */
void
print_kef_policy(char *provname, entry_t *pent, boolean_t has_random,
    boolean_t has_mechs)
{
	mechlist_t	*ptr = NULL;
	boolean_t	rnd_disabled = B_FALSE;

	if (pent != NULL) {
		rnd_disabled = filter_mechlist(&pent->dislist, RANDOM);
		ptr = pent->dislist;
	}

	(void) printf("%s:", provname);

	if (has_mechs == B_TRUE) {
		/*
		 * TRANSLATION_NOTE
		 * This code block may need to be modified a bit to avoid
		 * constructing the text message on the fly.
		 */
		(void) printf(gettext(" all mechanisms are enabled"));
		if (ptr != NULL)
			(void) printf(gettext(", except "));
		while (ptr != NULL) {
			(void) printf("%s", ptr->name);
			ptr = ptr->next;
			if (ptr != NULL)
				(void) printf(",");
		}
		if (ptr == NULL)
			(void) printf(".");
	}

	/*
	 * TRANSLATION_NOTE
	 * "random" is a keyword and not to be translated.
	 */
	if (rnd_disabled)
		(void) printf(gettext(" %s is disabled."), "random");
	else if (has_random)
		(void) printf(gettext(" %s is enabled."), "random");
	(void) printf("\n");
}


/*
 * Check if a kernel software provider is in the kernel.
 *
 * Parameters:
 * provname		Provider name
 * psoftlist_kernel	Optional software provider list.  If NULL, it will be
 *			obtained from get_soft_list().
 * in_kernel		Set to B_TRUE if device is in the kernel, else B_FALSE
 */
int
check_kernel_for_soft(char *provname, crypto_get_soft_list_t *psoftlist_kernel,
    boolean_t *in_kernel)
{
	char		*ptr;
	int		i;
	boolean_t	psoftlist_allocated = B_FALSE;

	if (provname == NULL) {
		cryptoerror(LOG_STDERR, gettext("internal error."));
		return (FAILURE);
	}

	if (psoftlist_kernel == NULL) {
		if (get_soft_list(&psoftlist_kernel) == FAILURE) {
			cryptodebug("failed to get the software provider list"
			" from kernel.");
			return (FAILURE);
		}
		psoftlist_allocated = B_TRUE;
	}

	*in_kernel = B_FALSE;
	ptr = psoftlist_kernel->sl_soft_names;
	for (i = 0; i < psoftlist_kernel->sl_soft_count; i++) {
		if (strcmp(provname, ptr) == 0) {
			*in_kernel = B_TRUE;
			break;
		}
		ptr = ptr + strlen(ptr) + 1;
	}

	if (psoftlist_allocated)
		free(psoftlist_kernel);

	return (SUCCESS);
}


/*
 * Check if a kernel hardware provider is in the kernel.
 *
 * Parameters:
 * provname	Provider name
 * pdevlist	Optional Hardware Crypto Device List.  If NULL, it will be
 *		obtained from get_dev_list().
 * in_kernel	Set to B_TRUE if device is in the kernel, otherwise B_FALSE
 */
int
check_kernel_for_hard(char *provname,
    crypto_get_dev_list_t *pdevlist, boolean_t *in_kernel)
{
	char		devname[MAXNAMELEN];
	int		inst_num;
	int		i;
	boolean_t	dev_list_allocated = B_FALSE;

	if (provname == NULL) {
		cryptoerror(LOG_STDERR, gettext("internal error."));
		return (FAILURE);
	}

	if (split_hw_provname(provname, devname, &inst_num) == FAILURE) {
		return (FAILURE);
	}

	if (pdevlist == NULL) {
		if (get_dev_list(&pdevlist) == FAILURE) {
			cryptoerror(LOG_STDERR, gettext("internal error."));
			return (FAILURE);
		}
		dev_list_allocated = B_TRUE;
	}

	*in_kernel = B_FALSE;
	for (i = 0; i < pdevlist->dl_dev_count; i++) {
		if ((strcmp(pdevlist->dl_devs[i].le_dev_name, devname) == 0) &&
		    (pdevlist->dl_devs[i].le_dev_instance == inst_num)) {
			*in_kernel = B_TRUE;
			break;
		}
	}

	if (dev_list_allocated)
		free(pdevlist);

	return (SUCCESS);
}
