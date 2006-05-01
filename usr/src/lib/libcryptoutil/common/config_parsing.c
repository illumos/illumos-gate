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
#include <errno.h>
#include <strings.h>
#include <locale.h>
#include <stdlib.h>
#include "cryptoutil.h"

static int uef_interpret(char *, uentry_t **);
static int parse_policylist(char *, uentry_t *);

/*
 * Retrieve the user-level provider info from the pkcs11.conf file.
 * If successful, the result is returned from the ppliblist argument.
 * This function returns SUCCESS if successfully done; otherwise it returns
 * FAILURE.
 */
int
get_pkcs11conf_info(uentrylist_t **ppliblist)
{
	FILE *pfile;
	char buffer[BUFSIZ];
	size_t len;
	uentry_t *pent;
	uentrylist_t *pentlist;
	uentrylist_t *pcur;
	int rc = SUCCESS;

	*ppliblist = NULL;
	if ((pfile = fopen(_PATH_PKCS11_CONF, "rF")) == NULL) {
		cryptoerror(LOG_ERR, "failed to open %s.\n", _PATH_PKCS11_CONF);
		return (FAILURE);
	}

	while (fgets(buffer, BUFSIZ, pfile) != NULL) {
		if (buffer[0] == '#' || buffer[0] == ' ' ||
		    buffer[0] == '\n'|| buffer[0] == '\t') {
			continue;   /* ignore comment lines */
		}

		len = strlen(buffer);
		if (buffer[len-1] == '\n') { /* get rid of trailing '\n' */
			len--;
		}
		buffer[len] = '\0';

		if ((rc = uef_interpret(buffer,  &pent)) != SUCCESS) {
			break;
		}

		/* append pent into ppliblist */
		pentlist = malloc(sizeof (uentrylist_t));
		if (pentlist == NULL) {
			cryptoerror(LOG_ERR, "parsing %s, out of memory.\n",
			    _PATH_PKCS11_CONF);
			free_uentry(pent);
			rc = FAILURE;
			break;
		}
		pentlist->puent = pent;
		pentlist->next = NULL;

		if (*ppliblist == NULL) {
			*ppliblist = pcur = pentlist;
		} else {
			pcur->next = pentlist;
			pcur = pcur->next;
		}
	}

	(void) fclose(pfile);

	if (rc != SUCCESS) {
		free_uentrylist(*ppliblist);
		*ppliblist = NULL;
	}

	return (rc);
}


/*
 * This routine converts a char string into a uentry_t structure
 * The input string "buf" should be one of the following:
 *	library_name
 *	library_name:NO_RANDOM
 *	library_name:disabledlist=m1,m2,...,mk
 *	library_name:disabledlist=m1,m2,...,mk;NO_RANDOM
 *	library_name:enabledlist=
 *	library_name:enabledlist=;NO_RANDOM
 *	library_name:enabledlist=m1,m2,...,mk
 *	library_name:enabledlist=m1,m2,...,mk;NO_RANDOM
 *	metaslot:status=enabled;enabledlist=m1,m2,....;slot=<slot-description>;\
 *	token=<token-label>
 *
 * Note:
 *	The mechanisms m1,..mk are in hex form. For example, "0x00000210"
 *	for CKM_MD5.
 *
 *	For the metaslot entry, "enabledlist", "slot", "auto_key_migrate"
 * 	or "token" is optional
 */
static int
uef_interpret(char *buf, uentry_t **ppent)
{
	uentry_t *pent;
	char	*token1;
	char	*token2;
	char	*lasts;
	int	rc;

	*ppent = NULL;
	if ((token1 = strtok_r(buf, SEP_COLON, &lasts)) == NULL) {
		/* buf is NULL */
		return (FAILURE);
	};

	pent = calloc(sizeof (uentry_t), 1);
	if (pent == NULL) {
		cryptoerror(LOG_ERR, "parsing %s, out of memory.\n",
		    _PATH_PKCS11_CONF);
		return (FAILURE);
	}
	(void) strlcpy(pent->name, token1, sizeof (pent->name));
	/*
	 * in case metaslot_auto_key_migrate is not specified, it should
	 * be default to true
	 */
	pent->flag_metaslot_auto_key_migrate = B_TRUE;

	while ((token2 = strtok_r(NULL, SEP_SEMICOLON, &lasts)) != NULL) {
		if ((rc = parse_policylist(token2, pent)) != SUCCESS) {
			free_uentry(pent);
			return (rc);
		}
	}

	*ppent = pent;
	return (SUCCESS);
}


/*
 * This routine parses the policy list and stored the result in the argument
 * pent.
 *
 * 	Arg buf: input only, its format should be one of the following:
 *     		enabledlist=
 *		enabledlist=m1,m2,...,mk
 *		disabledlist=m1,m2,...,mk
 *		NO_RANDOM
 *		metaslot_status=enabled|disabled
 *		metaslot_token=<token-label>
 *		metaslot_slot=<slot-description.
 *
 *	Arg pent: input/output
 *
 *      return: SUCCESS or FAILURE
 */
static int
parse_policylist(char *buf, uentry_t *pent)
{
	umechlist_t *phead = NULL;
	umechlist_t *pcur = NULL;
	umechlist_t *pmech;
	char *next_token;
	char *value;
	char *lasts;
	int count = 0;
	int rc = SUCCESS;

	if (pent == NULL) {
		return (FAILURE);
	}

	if (strncmp(buf, EF_DISABLED, sizeof (EF_DISABLED) - 1) == 0) {
		pent->flag_enabledlist = B_FALSE;
	} else if (strncmp(buf, EF_ENABLED, sizeof (EF_ENABLED) - 1) == 0) {
		pent->flag_enabledlist = B_TRUE;
	} else if (strncmp(buf, EF_NORANDOM, sizeof (EF_NORANDOM) - 1) == 0) {
		pent->flag_norandom = B_TRUE;
		return (rc);
	} else if (strncmp(buf, METASLOT_TOKEN,
	    sizeof (METASLOT_TOKEN) - 1) == 0) {
		if (value = strpbrk(buf, SEP_EQUAL)) {
			value++; /* get rid of = */
			(void) strlcpy((char *)pent->metaslot_ks_token, value,
			    TOKEN_LABEL_SIZE);
			return (SUCCESS);
		} else {
			cryptoerror(LOG_ERR, "failed to parse %s.\n",
			    _PATH_PKCS11_CONF);
			return (FAILURE);
		}
	} else if (strncmp(buf, METASLOT_SLOT,
	    sizeof (METASLOT_SLOT) - 1) == 0) {
		if (value = strpbrk(buf, SEP_EQUAL)) {
			value++; /* get rid of = */
			(void) strlcpy((char *)pent->metaslot_ks_slot, value,
			    SLOT_DESCRIPTION_SIZE);
			return (SUCCESS);
		} else {
			cryptoerror(LOG_ERR, "failed to parse %s.\n",
			    _PATH_PKCS11_CONF);
			return (FAILURE);
		}
	} else if (strncmp(buf, METASLOT_STATUS,
	    sizeof (METASLOT_STATUS) - 1) == 0) {
		if (value = strpbrk(buf, SEP_EQUAL)) {
			value++; /* get rid of = */
			if (strcmp(value, METASLOT_DISABLED) == 0) {
				pent->flag_metaslot_enabled = B_FALSE;
			} else if (strcmp(value, METASLOT_ENABLED) == 0) {
				pent->flag_metaslot_enabled = B_TRUE;
			} else {
				cryptoerror(LOG_ERR, "failed to parse %s.\n",
				    _PATH_PKCS11_CONF);
				return (FAILURE);
			}
			return (SUCCESS);
		} else {
			cryptoerror(LOG_ERR, "failed to parse %s.\n",
			    _PATH_PKCS11_CONF);
			return (FAILURE);
		}
	} else if (strncmp(buf, METASLOT_AUTO_KEY_MIGRATE,
	    sizeof (METASLOT_AUTO_KEY_MIGRATE) - 1) == 0) {
		if (value = strpbrk(buf, SEP_EQUAL)) {
			value++; /* get rid of = */
			if (strcmp(value, METASLOT_DISABLED) == 0) {
				pent->flag_metaslot_auto_key_migrate = B_FALSE;
			} else if (strcmp(value, METASLOT_ENABLED) == 0) {
				pent->flag_metaslot_auto_key_migrate = B_TRUE;
			} else {
				cryptoerror(LOG_ERR, "failed to parse %s.\n",
				    _PATH_PKCS11_CONF);
				return (FAILURE);
			}
			return (SUCCESS);
		} else {
			cryptoerror(LOG_ERR, "failed to parse %s.\n",
			    _PATH_PKCS11_CONF);
			return (FAILURE);
		}
	} else {
		cryptoerror(LOG_ERR, "failed to parse %s.\n",
		    _PATH_PKCS11_CONF);
		return (FAILURE);
	}

	if (value = strpbrk(buf, SEP_EQUAL)) {
		value++; /* get rid of = */
	}

	if ((next_token = strtok_r(value, SEP_COMMA, &lasts)) == NULL) {
		if (pent->flag_enabledlist) {
			return (SUCCESS);
		} else {
			cryptoerror(LOG_ERR, "failed to parse %s.\n",
			    _PATH_PKCS11_CONF);
			return (FAILURE);
		}
	}

	while (next_token) {
		if ((pmech = create_umech(next_token)) == NULL) {
			cryptoerror(LOG_ERR, "parsing %s, out of memory.\n",
			    _PATH_PKCS11_CONF);
			rc = FAILURE;
			break;
		}

		if (phead == NULL) {
			phead = pcur = pmech;
		} else {
			pcur->next = pmech;
			pcur = pcur->next;
		}
		count++;
		next_token = strtok_r(NULL, SEP_COMMA, &lasts);
	}

	if (rc == SUCCESS) {
		pent->policylist = phead;
		pent->count = count;
	} else {
		free_umechlist(phead);
	}

	return (rc);
}


/*
 * Create one item of type umechlist_t with the mechanism name.  A NULL is
 * returned when the input name is NULL or the heap memory is insufficient.
 */
umechlist_t *
create_umech(char *name)
{
	umechlist_t *pmech = NULL;

	if (name == NULL) {
		return (NULL);
	}

	if ((pmech = malloc(sizeof (umechlist_t))) != NULL) {
		(void) strlcpy(pmech->name, name, sizeof (pmech->name));
		pmech->next = NULL;
	}

	return (pmech);
}


void
free_umechlist(umechlist_t *plist)
{
	umechlist_t *pnext;

	while (plist != NULL) {
		pnext = plist->next;
		free(plist);
		plist = pnext;
	}
}


void
free_uentry(uentry_t  *pent)
{
	if (pent == NULL) {
		return;
	} else {
		free_umechlist(pent->policylist);
		free(pent);
	}
}


void
free_uentrylist(uentrylist_t *entrylist)
{
	uentrylist_t *pnext;

	while (entrylist != NULL) {
		pnext = entrylist->next;
		free_uentry(entrylist->puent);
		free(entrylist);
		entrylist = pnext;
	}
}
