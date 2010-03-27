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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <thread.h>
#include <synch.h>
#include <sasl/sasl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <ctype.h>
#include <libscf.h>
#include <libintl.h>
#include <locale.h>
#include "ns_sldap.h"
#include "ns_internal.h"

static int self_gssapi_only = 0;
static mutex_t self_gssapi_only_lock = DEFAULTMUTEX;

#define	DNS_FMRI	"svc:/network/dns/client:default"
#define	MSGSIZE		256

#define	NSSWITCH_CONF	"/etc/nsswitch.conf"

/*
 * Error Handling
 */
#define	CLIENT_FPRINTF if (mode_verbose && !mode_quiet) (void) fprintf

/*
 * One time initializtion
 */
int		sasl_gssapi_inited = 0;
static mutex_t	sasl_gssapi_lock = DEFAULTMUTEX;
int
__s_api_sasl_gssapi_init(void) {
	int rc = NS_LDAP_SUCCESS;
	(void) mutex_lock(&sasl_gssapi_lock);
	if (!sasl_gssapi_inited) {
			if (getuid() == 0) {
				if (system(
					"/usr/sbin/cryptoadm disable metaslot")
					== 0) {
					syslog(LOG_WARNING,
						"libsldap: Metaslot disabled "
						"for self credential mode");
					sasl_gssapi_inited = 1;
				} else {
					syslog(LOG_ERR,
						"libsldap: Can't disable "
						"Metaslot for self credential "
						"mode");
					rc = NS_LDAP_INTERNAL;
				}
			}
	}
	(void) mutex_unlock(&sasl_gssapi_lock);

	return (rc);
}

/*
 * nscd calls this function to set self_gssapi_only flag so libsldap performs
 * sasl/GSSAPI bind only. Also see comments of __ns_ldap_self_gssapi_config.
 *
 * Input: flag 0 use any kind of connection
 *             1 use self/gssapi connection only
 */
void
__ns_ldap_self_gssapi_only_set(int flag) {
	(void) mutex_lock(&self_gssapi_only_lock);
	self_gssapi_only = flag;
	(void) mutex_unlock(&self_gssapi_only_lock);
}
/*
 * Get the flag value of self_gssapi_only
 */
int
__s_api_self_gssapi_only_get(void) {
	int flag;
	(void) mutex_lock(&self_gssapi_only_lock);
	flag = self_gssapi_only;
	(void) mutex_unlock(&self_gssapi_only_lock);
	return (flag);
}
/*
 * nscd calls this function to detect the current native ldap configuration.
 * The output are
 * NS_LDAP_SELF_GSSAPI_CONFIG_NONE: No credential level self and
 *                                  no authentication method sasl/GSSAPI is
 *                                  configured.
 * NS_LDAP_SELF_GSSAPI_CONFIG_ONLY: Only credential level self and
 *                                  authentication method sasl/GSSAPI are
 *                                  configured.
 * NS_LDAP_SELF_GSSAPI_CONFIG_MIXED: More than one credential level are
 *                                   configured, including self.
 *                                   More than one authentication method
 *                                   are configured, including sasl/GSSAPI.
 *
 * __s_api_crosscheck makes sure self and sasl/GSSAPI pair up if they do
 * get configured.
 *
 * When nscd detects it's MIXED case, it calls __ns_ldap_self_gssapi_only_set
 * to force libsldap to do sasl/GSSAPI bind only for per-user lookup.
 *
 * Return: NS_LDAP_SUCCESS
 *         OTHERWISE - FAILURE
 *
 * Output: config. See comments above.
 *
 */
int
__ns_ldap_self_gssapi_config(ns_ldap_self_gssapi_config_t *config) {
	int	self = 0, other_level = 0, gssapi = 0, other_method = 0;
	ns_auth_t	**aMethod = NULL, **aNext = NULL;
	int		**cLevel = NULL, **cNext = NULL, rc;
	ns_ldap_error_t	*errp = NULL;
	FILE		*fp;

	if (config == NULL)
		return (NS_LDAP_INVALID_PARAM);
	else
		*config = NS_LDAP_SELF_GSSAPI_CONFIG_NONE;

	/*
	 * If config files don't exist, return NS_LDAP_CONFIG.
	 * It's the same return code __ns_ldap_getParam
	 * returns in the same situation.
	 */
	if ((fp = fopen(NSCONFIGFILE, "rF")) == NULL)
		return (NS_LDAP_CONFIG);
	else
		(void) fclose(fp);
	if ((fp = fopen(NSCREDFILE, "rF")) == NULL)
		return (NS_LDAP_CONFIG);
	else
		(void) fclose(fp);

	/* Get the credential level list */
	if ((rc = __ns_ldap_getParam(NS_LDAP_CREDENTIAL_LEVEL_P,
		(void ***)&cLevel, &errp)) != NS_LDAP_SUCCESS) {
		if (errp)
			(void) __ns_ldap_freeError(&errp);
		if (cLevel)
			(void) __ns_ldap_freeParam((void ***)&cLevel);
		return (rc);
	}
	if (errp)
		(void) __ns_ldap_freeError(&errp);
	/* Get the authentication method list */
	if ((rc = __ns_ldap_getParam(NS_LDAP_AUTH_P,
		(void ***)&aMethod, &errp)) != NS_LDAP_SUCCESS) {
		if (errp)
			(void) __ns_ldap_freeError(&errp);
		if (cLevel)
			(void) __ns_ldap_freeParam((void ***)&cLevel);
		if (aMethod)
			(void) __ns_ldap_freeParam((void ***)&aMethod);
		return (rc);
	}
	if (errp)
		(void) __ns_ldap_freeError(&errp);

	if (cLevel == NULL || aMethod == NULL) {
		if (cLevel)
			(void) __ns_ldap_freeParam((void ***)&cLevel);
		if (aMethod)
			(void) __ns_ldap_freeParam((void ***)&aMethod);
		return (NS_LDAP_SUCCESS);
	}

	for (cNext = cLevel; *cNext != NULL; cNext++) {
		if (**cNext == NS_LDAP_CRED_SELF)
			self++;
		else
			other_level++;
	}
	for (aNext = aMethod; *aNext != NULL; aNext++) {
		if ((*aNext)->saslmech == NS_LDAP_SASL_GSSAPI)
			gssapi++;
		else
			other_method++;
	}

	if (self > 0 && gssapi > 0) {
		if (other_level == 0 && other_method == 0)
			*config = NS_LDAP_SELF_GSSAPI_CONFIG_ONLY;
		else
			*config = NS_LDAP_SELF_GSSAPI_CONFIG_MIXED;
	}

	if (cLevel)
		(void) __ns_ldap_freeParam((void ***)&cLevel);
	if (aMethod)
		(void) __ns_ldap_freeParam((void ***)&aMethod);
	return (NS_LDAP_SUCCESS);
}

int
__s_api_sasl_bind_callback(
	/* LINTED E_FUNC_ARG_UNUSED */
	LDAP		*ld,
	/* LINTED E_FUNC_ARG_UNUSED */
	unsigned	flags,
	void		*defaults,
	void		*in)
{
	char		*ret = NULL;
	sasl_interact_t *interact = in;
	ns_sasl_cb_param_t	*cred = (ns_sasl_cb_param_t *)defaults;


	while (interact->id != SASL_CB_LIST_END) {

		switch (interact->id) {

		case SASL_CB_GETREALM:
			ret =   cred->realm;
			break;
		case SASL_CB_AUTHNAME:
			ret = cred->authid;
			break;
		case SASL_CB_PASS:
			ret = cred->passwd;
			break;
		case SASL_CB_USER:
			ret = cred->authzid;
			break;
		case SASL_CB_NOECHOPROMPT:
		case SASL_CB_ECHOPROMPT:
		default:
			break;
		}

		if (ret) {
			/*
			 * No need to do strdup(ret), the data is always
			 * available in 'defaults' and libldap won't
			 * free it either. strdup(ret) causes memory
			 * leak.
			 */
			interact->result = ret;
			interact->len = strlen(ret);
		} else {
			interact->result = NULL;
			interact->len = 0;
		}
		interact++;
	}

	return (LDAP_SUCCESS);
}

/*
 * Find "dbase: service1 [...] services2" in fname and return
 * " service1 [...] services2"
 * e.g.
 * Find "hosts: files dns" and return " files dns"
 */
static char *
__ns_nsw_getconfig(const char *dbase, const char *fname, int *errp)
{
	FILE *fp = NULL;
	char *linep, *retp = NULL;
	char lineq[BUFSIZ], db_colon[BUFSIZ];

	if ((fp = fopen(fname, "rF")) == NULL) {
		*errp = NS_LDAP_CONFIG;
		return (NULL);
	}
	*errp = NS_LDAP_SUCCESS;

	while (linep = fgets(lineq, BUFSIZ, fp)) {
		char			*tokenp, *comment;

		/*
		 * Ignore portion of line following the comment character '#'.
		 */
		if ((comment = strchr(linep, '#')) != NULL) {
			*comment = '\0';
		}
		if ((*linep == '\0') || isspace(*linep)) {
			continue;
		}
		(void) snprintf(db_colon, BUFSIZ, "%s:", dbase);
		if ((tokenp = strstr(linep, db_colon)) == NULL) {
			continue; /* ignore this line */
		} else {
			/* skip "dbase:" */
			retp = strdup(tokenp + strlen(db_colon));
			if (retp == NULL)
				*errp = NS_LDAP_MEMORY;
		}
	}

	(void) fclose(fp);
	return (retp);
}
/*
 *  Test the configurations of the "hosts" and "ipnodes"
 *  dns has to be present and appear before ldap
 *  e.g.
 *  "dns" , "dns files" "dns ldap files", "files dns" are allowed.
 *
 *  Kerberos requires dns or it'd fail.
 */
static int
test_dns_nsswitch(int foreground,
		const char *fname,
		ns_ldap_error_t **errpp) {
	int	ldap, dns, i, pserr, rc = NS_LDAP_SUCCESS;
	char	*db[3] = {"hosts", "ipnodes", NULL};
	char	buf[MSGSIZE], *conf = NULL, *token = NULL, *last = NULL;

	for (i = 0; db[i] != NULL; i++) {
		conf = __ns_nsw_getconfig(db[i], fname, &pserr);

		if (conf == NULL) {
			(void) snprintf(buf, MSGSIZE,
				gettext("Parsing %s to find \"%s:\" "
					"failed. err: %d"),
					fname, db[i], pserr);
			if (foreground) {
				(void) fprintf(stderr, "%s\n", buf);
			} else {
				MKERROR(LOG_ERR, *errpp, NS_LDAP_CONFIG,
					strdup(buf), NS_LDAP_MEMORY);
			}
			return (pserr);
		}
		ldap = dns = 0;
		token = strtok_r(conf, " ", &last);
		while (token != NULL) {
			if (strncmp(token, "dns", 3) == 0) {
				if (ldap) {
					(void) snprintf(buf, MSGSIZE,
						gettext("%s: ldap can't appear "
						"before dns"), db[i]);
					if (foreground) {
						(void) fprintf(stderr,
								"start: %s\n",
								buf);
					} else {
						MKERROR(LOG_ERR, *errpp,
							NS_LDAP_CONFIG,
							strdup(buf),
							NS_LDAP_MEMORY);
					}
					free(conf);
					return (NS_LDAP_CONFIG);
				} else {
					dns++;
				}
			} else if (strncmp(token, "ldap", 4) == 0) {
				ldap++;
			}
			/* next token */
			token = strtok_r(NULL, " ", &last);
		}
		if (conf) {
			free(conf);
			conf = NULL;
		}
		if (!dns) {
			(void) snprintf(buf, MSGSIZE,
				gettext("%s: dns is not defined in "
				"%s"), db[i], fname);
			if (foreground) {
				(void) fprintf(stderr, "start: %s\n", buf);
			} else {
				MKERROR(LOG_ERR, *errpp, NS_LDAP_CONFIG,
					strdup(buf), NS_LDAP_MEMORY);
			}
			rc = NS_LDAP_CONFIG;
			break;
		}
	}
	return (rc);
}

static boolean_t
is_service(const char *fmri, const char *state) {
	char		*st;
	boolean_t	result = B_FALSE;

	if ((st = smf_get_state(fmri)) != NULL) {
		if (strcmp(st, state) == 0)
			result = B_TRUE;
		free(st);
	}
	return (result);
}


/*
 * This function checks dns prerequisites for sasl/GSSAPI bind.
 * It's called only if config == NS_LDAP_SELF_GSSAPI_CONFIG_ONLY ||
 *   config == NS_LDAP_SELF_GSSAPI_CONFIG_MIXED.
 */
int
__ns_ldap_check_dns_preq(int foreground,
		int mode_verbose,
		int mode_quiet,
		const char *fname,
		ns_ldap_self_gssapi_config_t config,
		ns_ldap_error_t **errpp) {

	char	buf[MSGSIZE];
	int	retcode = NS_LDAP_SUCCESS;
	int	loglevel;

	if (errpp)
		*errpp = NULL;
	else
		return (NS_LDAP_INVALID_PARAM);

	if (config == NS_LDAP_SELF_GSSAPI_CONFIG_NONE)
		/* Shouldn't happen. Check this value just in case  */
		return (NS_LDAP_SUCCESS);

	if ((retcode = test_dns_nsswitch(foreground, fname, errpp)) !=
							NS_LDAP_SUCCESS)
		return (retcode);

	if (is_service(DNS_FMRI, SCF_STATE_STRING_ONLINE)) {
		if (foreground) {
			CLIENT_FPRINTF(stdout, "start: %s\n",
					gettext("DNS client is enabled"));
		} else {
			syslog(LOG_INFO, "libsldap: %s",
					gettext("DNS client is enabled"));
		}
		return (NS_LDAP_SUCCESS);
	} else {
		if (config == NS_LDAP_SELF_GSSAPI_CONFIG_ONLY) {
			(void) snprintf(buf, MSGSIZE,
				gettext("%s: DNS client is not enabled. "
					"Run \"svcadm enable %s\". %s."),
					"Error", DNS_FMRI, "Abort");
			loglevel = LOG_ERR;
			retcode = NS_LDAP_CONFIG;
		} else if (config == NS_LDAP_SELF_GSSAPI_CONFIG_MIXED) {
			(void) snprintf(buf, MSGSIZE,
				gettext("%s: DNS client is not enabled. "
					"Run \"svcadm enable %s\". %s."
					"Fall back to other cred level/bind. "),
					"Warning", DNS_FMRI, "Continue");
			loglevel = LOG_INFO;
			retcode = NS_LDAP_SUCCESS;
		}

		if (foreground) {
			(void) fprintf(stderr, "start: %s\n", buf);
		} else {
			MKERROR(loglevel, *errpp, retcode, strdup(buf),
				NS_LDAP_MEMORY);
		}
		return (retcode);
	}
}

/*
 * Check if sasl/GSSAPI works
 */
int
__ns_ldap_check_gssapi_preq(int foreground,
		int mode_verbose,
		int mode_quiet,
		ns_ldap_self_gssapi_config_t config,
		ns_ldap_error_t **errpp) {

	int	rc;
	char	*attr[2] = {"dn", NULL}, buf[MSGSIZE];
	ns_cred_t	cred;
	ns_ldap_result_t *result = NULL;
	int	loglevel;

	if (errpp)
		*errpp = NULL;
	else
		return (NS_LDAP_INVALID_PARAM);

	if (config == NS_LDAP_SELF_GSSAPI_CONFIG_NONE)
		/* Don't need to check */
		return (NS_LDAP_SUCCESS);

	(void) memset(&cred, 0, sizeof (ns_cred_t));

	cred.auth.type = NS_LDAP_AUTH_SASL;
	cred.auth.tlstype = NS_LDAP_TLS_NONE;
	cred.auth.saslmech = NS_LDAP_SASL_GSSAPI;

	rc = __ns_ldap_list(NULL, (const char *)"objectclass=*",
		NULL, (const char **)attr, &cred,
		NS_LDAP_SCOPE_BASE, &result, errpp, NULL, NULL);
	if (result)
		(void) __ns_ldap_freeResult(&result);

	if (rc == NS_LDAP_SUCCESS) {
		if (foreground) {
			CLIENT_FPRINTF(stdout, "start: %s\n",
					gettext("sasl/GSSAPI bind works"));
		} else {
			syslog(LOG_INFO, "libsldap: %s",
					gettext("sasl/GSSAPI bind works"));
		}
		return (NS_LDAP_SUCCESS);
	} else {
		if (config == NS_LDAP_SELF_GSSAPI_CONFIG_ONLY) {
			(void) snprintf(buf, MSGSIZE,
				gettext("%s: sasl/GSSAPI bind is not "
					"working. %s."),
					"Error", "Abort");
			loglevel = LOG_ERR;
		} else if (config == NS_LDAP_SELF_GSSAPI_CONFIG_MIXED) {
			(void) snprintf(buf, MSGSIZE,
				gettext("%s: sasl/GSSAPI bind is not "
					"working. Fall back to other cred "
					"level/bind. %s."),
					"Warning", "Continue");
			loglevel = LOG_INFO;
			/* reset return code */
			rc = NS_LDAP_SUCCESS;
		}

		if (foreground) {
			(void) fprintf(stderr, "start: %s\n", buf);
		} else {
			MKERROR(loglevel, *errpp, rc, strdup(buf),
				NS_LDAP_MEMORY);
		}
		return (rc);
	}
}
/*
 * This is called by ldap_cachemgr to check dns and gssapi prequisites.
 */
int
__ns_ldap_check_all_preq(int foreground,
		int mode_verbose,
		int mode_quiet,
		ns_ldap_self_gssapi_config_t config,
		ns_ldap_error_t **errpp) {

	int	rc;

	if (errpp)
		*errpp = NULL;
	else
		return (NS_LDAP_INVALID_PARAM);

	if (config == NS_LDAP_SELF_GSSAPI_CONFIG_NONE)
		/* Don't need to check */
		return (NS_LDAP_SUCCESS);

	if ((rc = __ns_ldap_check_dns_preq(foreground,
			mode_verbose, mode_quiet, NSSWITCH_CONF,
			config, errpp)) != NS_LDAP_SUCCESS)
		return (rc);
	if ((rc = __ns_ldap_check_gssapi_preq(foreground,
			mode_verbose, mode_quiet, config, errpp)) !=
			NS_LDAP_SUCCESS)
		return (rc);

	return (NS_LDAP_SUCCESS);
}
