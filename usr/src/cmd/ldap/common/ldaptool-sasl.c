/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * File for ldaptool routines for SASL
 */

#include <ldap.h>
#include "ldaptool-sasl.h"
#ifdef SOLARIS_LDAP_CMD
#include <sasl/sasl.h>
#include <locale.h>
#include "ldaptool.h"
#else
#include <sasl.h>
#endif	/* SOLARIS_LDAP_CMD */
#include <stdio.h>

#ifndef SOLARIS_LDAP_CMD
#define gettext(s) s
#endif

#ifdef HAVE_SASL_OPTIONS

#define SASL_PROMPT	"SASL"

typedef struct {
        char *mech;
        char *authid;
        char *username;
        char *passwd;
        char *realm;
} ldaptoolSASLdefaults;

static int get_default(ldaptoolSASLdefaults *defaults, sasl_interact_t *interact);
static int get_new_value(sasl_interact_t *interact, unsigned flags);

void *
ldaptool_set_sasl_defaults ( LDAP *ld, char *mech, char *authid, char *username,
				 char *passwd, char *realm )
{
        ldaptoolSASLdefaults *defaults;

        if ((defaults = calloc(sizeof(defaults[0]), 1)) == NULL)
		return NULL;

	if (mech)
		defaults->mech = mech;
	else
		ldap_get_option(ld, LDAP_OPT_X_SASL_MECH, &defaults->mech);

	if (authid)
		defaults->authid = authid;
	else
		ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHCID, &defaults->authid);

	if (username)
		defaults->username = username;
	else
		ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHZID, &defaults->username);

        defaults->passwd = passwd;

	if (realm)
		defaults->realm = realm;
	else
		ldap_get_option(ld, LDAP_OPT_X_SASL_REALM, &defaults->realm);

        return defaults;
}

int
ldaptool_sasl_interact( LDAP *ld, unsigned flags, void *defaults, void *prompts ) {
	sasl_interact_t		*interact;
	ldaptoolSASLdefaults	*sasldefaults = defaults;
	int			rc;

	if (prompts == NULL || flags != LDAP_SASL_INTERACTIVE)
		return (LDAP_PARAM_ERROR);

	for (interact = prompts; interact->id != SASL_CB_LIST_END; interact++) {
		/* Obtain the default value */
		if ((rc = get_default(sasldefaults, interact)) != LDAP_SUCCESS)
			return (rc);

		/* If no default, get the new value from stdin */
		if (interact->result == NULL) {
			if ((rc = get_new_value(interact, flags)) != LDAP_SUCCESS)
				return (rc);
		}

	}
	return (LDAP_SUCCESS);
}

static int
get_default(ldaptoolSASLdefaults *defaults, sasl_interact_t *interact) {
	const char	*defvalue = interact->defresult;

	if (defaults != NULL) {
		switch( interact->id ) {
        	case SASL_CB_AUTHNAME:
			defvalue = defaults->authid;
			break;
        	case SASL_CB_USER:
			defvalue = defaults->username;
			break;
        	case SASL_CB_PASS:
			defvalue = defaults->passwd;
			break;
        	case SASL_CB_GETREALM:
			defvalue = defaults->realm;
			break;
		}
	}

	if (defvalue != NULL) {
		interact->result = (char *)malloc(strlen(defvalue)+1);
		if ((char *)interact->result != NULL) {
			strcpy((char *)interact->result,defvalue);
			interact->len = strlen((char *)(interact->result));
		}

		/* Clear passwd */
		if (interact->id == SASL_CB_PASS && defaults != NULL) {
			/* At this point defaults->passwd is not NULL */
            		memset( defaults->passwd, '\0', strlen(defaults->passwd));
		}

		if ((char *)interact->result == NULL) {
			return (LDAP_NO_MEMORY);
		}
	}
	return (LDAP_SUCCESS);
}

static int
get_new_value(sasl_interact_t *interact, unsigned flags) {
	char	*newvalue, str[1024];
	int	len;

#ifdef SOLARIS_LDAP_CMD
	char	*tmpstr;
#endif

	if (interact->id == SASL_CB_ECHOPROMPT || interact->id == SASL_CB_NOECHOPROMPT) {
		if (interact->challenge)
			fprintf(stderr, gettext("Challenge:%s\n"), interact->challenge);
	}

#ifdef SOLARIS_LDAP_CMD
	tmpstr = ldaptool_UTF82local(interact->prompt);
	snprintf(str, sizeof(str), "%s:", tmpstr?tmpstr:SASL_PROMPT);
	if (tmpstr != NULL)
		free(tmpstr);
#else
#ifdef HAVE_SNPRINTF
	snprintf(str, sizeof(str), "%s:", interact->prompt?interact->prompt:SASL_PROMPT);
#else
	sprintf(str, "%s:", interact->prompt?interact->prompt:SASL_PROMPT);
#endif
#endif	/* SOLARIS_LDAP_CMD */

	/* Get the new value */
	if (interact->id == SASL_CB_PASS || interact->id == SASL_CB_NOECHOPROMPT) {
#if defined(_WIN32)
		char pbuf[257];
		fputs(str,stdout);
		fflush(stdout);
		if (fgets(pbuf,256,stdin) == NULL) {
			newvalue = NULL;
		} else {
			char *tmp;

			tmp = strchr(pbuf,'\n');
			if (tmp) *tmp = '\0';
			tmp = strchr(pbuf,'\r');
			if (tmp) *tmp = '\0';
			newvalue = strdup(pbuf);
		}
		if ( newvalue == NULL) {
#else
#if defined(SOLARIS)
		if ((newvalue = (char *)getpassphrase(str)) == NULL) {
#else
		if ((newvalue = (char *)getpass(str)) == NULL) {
#endif
#endif
			return (LDAP_UNAVAILABLE);
		}
		len = strlen(newvalue);
	} else {
		fputs(str, stderr);
		if ((newvalue = fgets(str, sizeof(str), stdin)) == NULL)
			return (LDAP_UNAVAILABLE);
		len = strlen(str);
		if (len > 0 && str[len - 1] == '\n')
			str[len - 1] = 0;
	}

	interact->result = (char *) strdup(newvalue);
	memset(newvalue, '\0', len);
	if (interact->result == NULL)
		return (LDAP_NO_MEMORY);
	interact->len = len;
	return (LDAP_SUCCESS);
}
#endif	/* HAVE_SASL_OPTIONS */
