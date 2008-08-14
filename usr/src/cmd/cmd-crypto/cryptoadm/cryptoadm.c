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
#include <zone.h>
#include <sys/crypto/ioctladmin.h>
#include <cryptoutil.h>
#include "cryptoadm.h"

#define	REQ_ARG_CNT	2

/* subcommand index */
enum subcommand_index {
	CRYPTO_LIST,
	CRYPTO_DISABLE,
	CRYPTO_ENABLE,
	CRYPTO_INSTALL,
	CRYPTO_UNINSTALL,
	CRYPTO_UNLOAD,
	CRYPTO_REFRESH,
	CRYPTO_START,
	CRYPTO_STOP,
	CRYPTO_HELP };

/*
 * TRANSLATION_NOTE
 * Command keywords are not to be translated.
 */
static char *cmd_table[] = {
	"list",
	"disable",
	"enable",
	"install",
	"uninstall",
	"unload",
	"refresh",
	"start",
	"stop",
	"--help" };

/* provider type */
enum provider_type_index {
	PROV_UEF_LIB,
	PROV_KEF_SOFT,
	PROV_KEF_HARD,
	METASLOT,
	PROV_BADNAME };

typedef struct {
	char cp_name[MAXPATHLEN];
	enum provider_type_index cp_type;
} cryptoadm_provider_t;

/*
 * TRANSLATION_NOTE
 * Operand keywords are not to be translated.
 */
static const char *KN_PROVIDER = "provider=";
static const char *KN_MECH = "mechanism=";
static const char *KN_ALL = "all";
static const char *KN_TOKEN = "token=";
static const char *KN_SLOT = "slot=";
static const char *KN_DEFAULT_KS = "default-keystore";
static const char *KN_AUTO_KEY_MIGRATE = "auto-key-migrate";

/* static variables */
static boolean_t	allflag = B_FALSE;
static boolean_t	rndflag = B_FALSE;
static mechlist_t	*mecharglist = NULL;

/* static functions */
static void usage(void);
static int get_provider_type(char *);
static int process_mech_operands(int, char **, boolean_t);
static int do_list(int, char **);
static int do_disable(int, char **);
static int do_enable(int, char **);
static int do_install(int, char **);
static int do_uninstall(int, char **);
static int do_unload(int, char **);
static int do_refresh(int);
static int do_start(int);
static int do_stop(int);
static int list_simple_for_all(boolean_t);
static int list_mechlist_for_all(boolean_t);
static int list_policy_for_all(void);

int
main(int argc, char *argv[])
{
	char	*subcmd;
	int	cmdnum;
	int	cmd_index = 0;
	int	rc = SUCCESS;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	cryptodebug_init(basename(argv[0]));

	if (argc < REQ_ARG_CNT) {
		usage();
		return (ERROR_USAGE);
	}

	/* get the subcommand index */
	cmd_index = 0;
	subcmd = argv[1];
	cmdnum = sizeof (cmd_table)/sizeof (cmd_table[0]);

	while ((cmd_index < cmdnum) &&
	    (strcmp(subcmd, cmd_table[cmd_index]) != 0)) {
		cmd_index++;
	}
	if (cmd_index >= cmdnum) {
		usage();
		return (ERROR_USAGE);
	}

	/* do the subcommand */
	switch (cmd_index) {
	case CRYPTO_LIST:
		rc = do_list(argc, argv);
		break;
	case CRYPTO_DISABLE:
		rc = do_disable(argc, argv);
		break;
	case CRYPTO_ENABLE:
		rc = do_enable(argc, argv);
		break;
	case CRYPTO_INSTALL:
		rc = do_install(argc, argv);
		break;
	case CRYPTO_UNINSTALL:
		rc = do_uninstall(argc, argv);
		break;
	case CRYPTO_UNLOAD:
		rc = do_unload(argc, argv);
		break;
	case CRYPTO_REFRESH:
		rc = do_refresh(argc);
		break;
	case CRYPTO_START:
		rc = do_start(argc);
		break;
	case CRYPTO_STOP:
		rc = do_stop(argc);
		break;
	case CRYPTO_HELP:
		usage();
		rc = SUCCESS;
		break;
	default: /* should not come here */
		usage();
		rc = ERROR_USAGE;
		break;
	}
	return (rc);
}


static void
usage(void)
{
	/*
	 * TRANSLATION_NOTE
	 * Command usage is not to be translated.  Only the word "Usage:"
	 * along with localized expressions indicating what kind of value
	 * is expected for arguments.
	 */
	(void) fprintf(stderr, gettext("Usage:\n"));
	(void) fprintf(stderr,
	    "  cryptoadm list [-mpv] [provider=<%s> | metaslot]"
	    " [mechanism=<%s>]\n",
	    gettext("provider-name"), gettext("mechanism-list"));
	(void) fprintf(stderr,
	    "  cryptoadm disable provider=<%s>"
	    " mechanism=<%s> | random | all\n",
	    gettext("provider-name"), gettext("mechanism-list"));
	(void) fprintf(stderr,
	    "  cryptoadm disable metaslot"
	    " [auto-key-migrate] [mechanism=<%s>]\n",
	    gettext("mechanism-list"));
	(void) fprintf(stderr,
	    "  cryptoadm enable provider=<%s>"
	    " mechanism=<%s> | random | all\n",
	    gettext("provider-name"), gettext("mechanism-list"));
	(void) fprintf(stderr,
	    "  cryptoadm enable metaslot [mechanism=<%s>]"
	    " [[token=<%s>] [slot=<%s>]"
	    " | [default-keystore]] | [auto-key-migrate]\n",
	    gettext("mechanism-list"), gettext("token-label"),
	    gettext("slot-description"));
	(void) fprintf(stderr,
	    "  cryptoadm install provider=<%s>\n",
	    gettext("provider-name"));
	(void) fprintf(stderr,
	    "  cryptoadm install provider=<%s> [mechanism=<%s>]\n",
	    gettext("provider-name"), gettext("mechanism-list"));
	(void) fprintf(stderr,
	    "  cryptoadm uninstall provider=<%s>\n",
	    gettext("provider-name"));
	(void) fprintf(stderr,
	    "  cryptoadm unload provider=<%s>\n",
	    gettext("provider-name"));
	(void) fprintf(stderr,
	    "  cryptoadm refresh\n"
	    "  cryptoadm start\n"
	    "  cryptoadm stop\n"
	    "  cryptoadm --help\n");
}


/*
 * Get the provider type.  This function returns
 * - PROV_UEF_LIB if provname contains an absolute path name
 * - PROV_KEF_SOFT if provname is a base name only
 * - PROV_KEF_HARD if provname contains one slash only and the slash is not
 *	the 1st character.
 * - PROV_BADNAME otherwise.
 */
static int
get_provider_type(char *provname)
{
	char *pslash1;
	char *pslash2;

	if (provname == NULL) {
		return (FAILURE);
	}

	if (provname[0] == '/') {
		return (PROV_UEF_LIB);
	} else if ((pslash1 = strchr(provname, SEP_SLASH)) == NULL) {
		/* no slash */
		return (PROV_KEF_SOFT);
	} else {
		pslash2 = strrchr(provname, SEP_SLASH);
		if (pslash1 == pslash2) {
			return (PROV_KEF_HARD);
		} else {
			return (PROV_BADNAME);
		}
	}
}

/*
 * Get the provider structure.  This function returns NULL if no valid
 * provider= is found in argv[], otherwise a cryptoadm_provider_t is returned.
 * If provider= is found but has no argument, then a cryptoadm_provider_t
 * with cp_type = PROV_BADNAME is returned.
 */
static cryptoadm_provider_t *
get_provider(int argc, char **argv)
{
	int c = 0;
	boolean_t found = B_FALSE;
	cryptoadm_provider_t *provider = NULL;
	char *provstr = NULL, *savstr;
	boolean_t is_metaslot = B_FALSE;

	while (!found && ++c < argc) {
		if (strncmp(argv[c], METASLOT_KEYWORD,
		    strlen(METASLOT_KEYWORD)) == 0) {
			is_metaslot = B_TRUE;
			found = B_TRUE;
		} else if (strncmp(argv[c], KN_PROVIDER,
		    strlen(KN_PROVIDER)) == 0 &&
		    strlen(argv[c]) > strlen(KN_PROVIDER)) {
			if ((provstr = strdup(argv[c])) == NULL) {
				int err = errno;
				/*
				 * TRANSLATION_NOTE
				 * "get_provider" is a function name and should
				 * not be translated.
				 */
				cryptoerror(LOG_STDERR, "get_provider: %s.",
				    strerror(err));
				return (NULL);
			}
			found = B_TRUE;
		}
	}
	if (!found)
		return (NULL);

	provider = malloc(sizeof (cryptoadm_provider_t));
	if (provider == NULL) {
		cryptoerror(LOG_STDERR, gettext("out of memory."));
		if (provstr) {
			free(provstr);
		}
		return (NULL);
	}

	if (is_metaslot) {
		(void) strlcpy(provider->cp_name, METASLOT_KEYWORD,
		    strlen(METASLOT_KEYWORD));
		provider->cp_type = METASLOT;
	} else {

		savstr = provstr;
		(void) strtok(provstr, "=");
		provstr = strtok(NULL, "=");
		if (provstr == NULL) {
			cryptoerror(LOG_STDERR, gettext("bad provider name."));
			provider->cp_type = PROV_BADNAME;
			free(savstr);
			return (provider);
		}

		(void) strlcpy(provider->cp_name, provstr,
		    sizeof (provider->cp_name));
		provider->cp_type = get_provider_type(provider->cp_name);

		free(savstr);
	}
	return (provider);
}

/*
 * Process the "feature" operands.
 *
 * "argc" and "argv" contain values specified on the command line.
 * All other arguments are used for returning parsing results.
 * If any of these arguments are NULL, that keyword is not expected,
 * and FAILURE will be returned.
 */
static int
process_metaslot_operands(int argc, char **argv, char **meta_ks_token,
    char **meta_ks_slot, boolean_t *use_default,
    boolean_t *auto_key_migrate_flag)
{
	int c = 2;
	int rc = SUCCESS;

	while (++c < argc) {
		if ((strncmp(argv[c], KN_MECH, strlen(KN_MECH)) == 0) &&
		    strlen(argv[c]) > strlen(KN_MECH)) {

			/* process mechanism operands */
			if ((rc = process_mech_operands(argc, argv, B_TRUE))
			    != SUCCESS) {
				goto finish;
			}

		} else if ((strncmp(argv[c], KN_TOKEN,
		    strlen(KN_TOKEN)) == 0) &&
		    strlen(argv[c]) > strlen(KN_TOKEN)) {
			if ((meta_ks_token) && (strtok(argv[c], "=") != NULL)) {
				char *tmp;
				if ((tmp = strtok(NULL, "=")) != NULL) {
					*meta_ks_token = strdup(tmp);
				} else {
					return (FAILURE);
				}
			} else {
				return (FAILURE);
			}

		} else if ((strncmp(argv[c], KN_SLOT,
		    strlen(KN_SLOT)) == 0) &&
		    strlen(argv[c]) > strlen(KN_SLOT)) {

			if ((meta_ks_slot) && (strtok(argv[c], "=") != NULL)) {
				char *tmp;
				if ((tmp = strtok(NULL, "=")) != NULL) {
					*meta_ks_slot = strdup(tmp);
				} else {
					return (FAILURE);
				}
			} else {
				return (FAILURE);
			}

		} else if (strncmp(argv[c], KN_DEFAULT_KS,
		    strlen(KN_DEFAULT_KS)) == 0) {

			if (use_default) {
				*use_default = B_TRUE;
			} else {
				return (FAILURE);
			}
		} else if (strncmp(argv[c], KN_AUTO_KEY_MIGRATE,
		    strlen(KN_AUTO_KEY_MIGRATE)) == 0) {

			if (auto_key_migrate_flag) {
				*auto_key_migrate_flag = B_TRUE;
			} else {
				return (FAILURE);
			}
		} else {
			return (FAILURE);
		}
	}
finish:
	return (rc);
}

/*
 * Process the "feature" operands.
 */
static int
process_feature_operands(int argc, char **argv)
{
	int c = 2;

	while (++c < argc) {
		if (strcmp(argv[c], KN_ALL) == 0) {
			allflag = B_TRUE;
			rndflag = B_TRUE; /* all includes random also. */
		} else if (strcmp(argv[c], RANDOM) == 0) {
			rndflag = B_TRUE;
		}
	}
	return (SUCCESS);
}

/*
 * Process the mechanism operands for the disable, enable and install
 * subcommands.  This function sets the static variable allflag to be B_TRUE
 * if the keyword "all" is specified, otherwise builds a link list of the
 * mechanism operands and save it in the static variable mecharglist.
 *
 * This function returns
 * 	ERROR_USAGE: mechanism operand is missing.
 * 	FAILURE: out of memory.
 * 	SUCCESS: otherwise.
 */
static int
process_mech_operands(int argc, char **argv, boolean_t quiet)
{
	mechlist_t *pmech;
	mechlist_t *pcur = NULL;
	mechlist_t *phead = NULL;
	boolean_t found = B_FALSE;
	char *mechliststr = NULL;
	char *curmech = NULL;
	int c = -1;
	int rc = SUCCESS;

	while (!found && ++c < argc) {
		if ((strncmp(argv[c], KN_MECH, strlen(KN_MECH)) == 0) &&
		    strlen(argv[c]) > strlen(KN_MECH)) {
			found = B_TRUE;
		}
	}
	if (!found) {
		if (!quiet)
			/*
			 * TRANSLATION_NOTE
			 * "mechanism" could be either a literal keyword
			 * and hence not to be translated, or a descriptive
			 * word and translatable.  A choice was made to
			 * view it as a literal keyword.
			 */
			cryptoerror(LOG_STDERR,
				gettext("the %s operand is missing.\n"),
				"mechanism");
		return (ERROR_USAGE);
	}
	(void) strtok(argv[c], "=");
	mechliststr = strtok(NULL, "=");

	if (strcmp(mechliststr, "all") == 0) {
		allflag = B_TRUE;
		mecharglist = NULL;
		return (SUCCESS);
	}

	curmech = strtok(mechliststr, ",");
	do {
		if ((pmech = create_mech(curmech)) == NULL) {
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
	} while ((curmech = strtok(NULL, ",")) != NULL);

	if (rc == FAILURE) {
		cryptoerror(LOG_STDERR, gettext("out of memory."));
		free_mechlist(phead);
	} else {
		mecharglist = phead;
		rc = SUCCESS;
	}
	return (rc);
}



/*
 * The top level function for the list subcommand and options.
 */
static int
do_list(int argc, char **argv)
{
	boolean_t	mflag = B_FALSE;
	boolean_t	pflag = B_FALSE;
	boolean_t	vflag = B_FALSE;
	char	ch;
	cryptoadm_provider_t 	*prov = NULL;
	int	rc = SUCCESS;

	argc -= 1;
	argv += 1;

	if (argc == 1) {
		rc = list_simple_for_all(B_FALSE);
		goto out;
	}

	/*
	 * [-v] [-m] [-p] [provider=<>] [mechanism=<>]
	 */
	if (argc > 5) {
		usage();
		return (rc);
	}

	while ((ch = getopt(argc, argv, "mpv")) != EOF) {
		switch (ch) {
		case 'm':
			mflag = B_TRUE;
			if (pflag) {
				rc = ERROR_USAGE;
			}
			break;
		case 'p':
			pflag = B_TRUE;
			if (mflag || vflag) {
				rc = ERROR_USAGE;
			}
			break;
		case 'v':
			vflag = B_TRUE;
			if (pflag)
				rc = ERROR_USAGE;
			break;
		default:
			rc = ERROR_USAGE;
			break;
		}
	}

	if (rc == ERROR_USAGE) {
		usage();
		return (rc);
	}

	if ((rc = process_feature_operands(argc, argv)) != SUCCESS) {
		goto out;
	}

	prov = get_provider(argc, argv);

	if (mflag || vflag) {
		if (argc > 0) {
			rc = process_mech_operands(argc, argv, B_TRUE);
			if (rc == FAILURE)
				goto out;
			/* "-m" is implied when a mechanism list is given */
			if (mecharglist != NULL || allflag)
				mflag = B_TRUE;
		}
	}

	if (prov == NULL) {
		if (mflag) {
			rc = list_mechlist_for_all(vflag);
		} else if (pflag) {
			rc = list_policy_for_all();
		} else if (vflag) {
			rc = list_simple_for_all(vflag);
		}
	} else if (prov->cp_type == METASLOT) {
		if ((!mflag) && (!vflag) && (!pflag)) {
			/* no flag is specified, just list metaslot status */
			rc = list_metaslot_info(mflag, vflag, mecharglist);
		} else if (mflag || vflag) {
			rc = list_metaslot_info(mflag, vflag, mecharglist);
		} else if (pflag) {
			rc = list_metaslot_policy();
		} else {
			/* error message */
			usage();
			rc = ERROR_USAGE;
		}
	} else if (prov->cp_type == PROV_BADNAME) {
		usage();
		rc = ERROR_USAGE;
		goto out;
	} else { /* do the listing for a provider only */
		if (mflag || vflag) {
			if (vflag)
				(void) printf(gettext("Provider: %s\n"),
					prov->cp_name);
			switch (prov->cp_type) {
			case PROV_UEF_LIB:
				rc = list_mechlist_for_lib(prov->cp_name,
					mecharglist, NULL, B_FALSE,
					vflag, mflag);
				break;
			case PROV_KEF_SOFT:
				rc = list_mechlist_for_soft(prov->cp_name);
				break;
			case PROV_KEF_HARD:
				rc = list_mechlist_for_hard(prov->cp_name);
				break;
			default: /* should not come here */
				rc = FAILURE;
				break;
			}
		} else if (pflag) {
			switch (prov->cp_type) {
			case PROV_UEF_LIB:
				rc = list_policy_for_lib(prov->cp_name);
				break;
			case PROV_KEF_SOFT:
				if (getzoneid() == GLOBAL_ZONEID) {
					rc = list_policy_for_soft(
					    prov->cp_name);
				} else {
					/*
					 * TRANSLATION_NOTE
					 * "global" is keyword and not to
					 * be translated.
					 */
					cryptoerror(LOG_STDERR, gettext(
					    "policy information for kernel "
					    "providers is available "
					    "in the %s zone only"), "global");
					rc = FAILURE;
				}
				break;
			case PROV_KEF_HARD:
				if (getzoneid() == GLOBAL_ZONEID) {
					rc = list_policy_for_hard(
					    prov->cp_name);
				} else {
					/*
					 * TRANSLATION_NOTE
					 * "global" is keyword and not to
					 * be translated.
					 */
					cryptoerror(LOG_STDERR, gettext(
					    "policy information for kernel "
					    "providers is available "
					    "in the %s zone only"), "global");
					rc = FAILURE;
				}

				break;
			default: /* should not come here */
				rc = FAILURE;
				break;
			}
		} else {
			/* error message */
			usage();
			rc = ERROR_USAGE;
		}
	}

out:
	if (prov != NULL)
		free(prov);

	if (mecharglist != NULL)
		free_mechlist(mecharglist);
	return (rc);
}


/*
 * The top level function for the disable subcommand.
 */
static int
do_disable(int argc, char **argv)
{
	cryptoadm_provider_t	*prov = NULL;
	int	rc = SUCCESS;
	boolean_t auto_key_migrate_flag = B_FALSE;

	if ((argc < 3) || (argc > 5)) {
		usage();
		return (ERROR_USAGE);
	}

	prov = get_provider(argc, argv);
	if (prov == NULL) {
		usage();
		return (ERROR_USAGE);
	}
	if (prov->cp_type == PROV_BADNAME) {
		return (FAILURE);
	}

	if ((rc = process_feature_operands(argc, argv)) != SUCCESS) {
		goto out;
	}

	/*
	 * If allflag or rndflag has already been set there is no reason to
	 * process mech=
	 */
	if (prov->cp_type == METASLOT) {
		if ((argc > 3) &&
		    (rc = process_metaslot_operands(argc, argv,
		    NULL, NULL, NULL, &auto_key_migrate_flag)) != SUCCESS) {
			usage();
			return (rc);
		}
	} else if (!allflag && !rndflag &&
		(rc = process_mech_operands(argc, argv, B_FALSE)) != SUCCESS) {
			return (rc);
	}

	switch (prov->cp_type) {
	case METASLOT:
		rc = disable_metaslot(mecharglist, allflag,
		    auto_key_migrate_flag);
		break;
	case PROV_UEF_LIB:
		rc = disable_uef_lib(prov->cp_name, rndflag, allflag,
		    mecharglist);
		break;
	case PROV_KEF_SOFT:
		if (rndflag && !allflag) {
			if ((mecharglist = create_mech(RANDOM)) == NULL) {
				rc = FAILURE;
				break;
			}
		}
		if (getzoneid() == GLOBAL_ZONEID) {
			rc = disable_kef_software(prov->cp_name, rndflag,
			    allflag, mecharglist);
		} else {
			/*
			 * TRANSLATION_NOTE
			 * "disable" could be either a literal keyword
			 * and hence not to be translated, or a verb and
			 * translatable.  A choice was made to view it as
			 * a literal keyword.  "global" is keyword and not
			 * to be translated.
			 */
			cryptoerror(LOG_STDERR, gettext("%1$s for kernel "
			    "providers is supported in the %2$s zone only"),
			    "disable", "global");
			rc = FAILURE;
		}
		break;
	case PROV_KEF_HARD:
		if (rndflag && !allflag) {
			if ((mecharglist = create_mech(RANDOM)) == NULL) {
				rc = FAILURE;
				break;
			}
		}
		if (getzoneid() == GLOBAL_ZONEID) {
			rc = disable_kef_hardware(prov->cp_name, rndflag,
			    allflag, mecharglist);
		} else {
			/*
			 * TRANSLATION_NOTE
			 * "disable" could be either a literal keyword
			 * and hence not to be translated, or a verb and
			 * translatable.  A choice was made to view it as
			 * a literal keyword.  "global" is keyword and not
			 * to be translated.
			 */
			cryptoerror(LOG_STDERR, gettext("%1$s for kernel "
			    "providers is supported in the %2$s zone only"),
			    "disable", "global");
			rc = FAILURE;
		}
		break;
	default: /* should not come here */
		rc = FAILURE;
		break;
	}

out:
	free(prov);
	if (mecharglist != NULL) {
		free_mechlist(mecharglist);
	}
	return (rc);
}


/*
 * The top level function fo the enable subcommand.
 */
static int
do_enable(int argc, char **argv)
{
	cryptoadm_provider_t 	*prov = NULL;
	int	rc = SUCCESS;
	char *alt_token = NULL, *alt_slot = NULL;
	boolean_t use_default = B_FALSE, auto_key_migrate_flag = B_FALSE;

	if ((argc < 3) || (argc > 6)) {
		usage();
		return (ERROR_USAGE);
	}

	prov = get_provider(argc, argv);
	if (prov == NULL) {
		usage();
		return (ERROR_USAGE);
	}
	if ((prov->cp_type != METASLOT) && (argc != 4)) {
		usage();
		return (ERROR_USAGE);
	}
	if (prov->cp_type == PROV_BADNAME) {
		rc = FAILURE;
		goto out;
	}


	if (prov->cp_type == METASLOT) {
		if ((rc = process_metaslot_operands(argc, argv, &alt_token,
		    &alt_slot, &use_default, &auto_key_migrate_flag))
		    != SUCCESS) {
			usage();
			goto out;
		}
		if ((alt_slot || alt_token) && use_default) {
			usage();
			rc = FAILURE;
			goto out;
		}
	} else {
		if ((rc = process_feature_operands(argc, argv)) != SUCCESS) {
			goto out;
		}

		/*
		 * If allflag or rndflag has already been set there is
		 * no reason to process mech=
		 */
		if (!allflag && !rndflag &&
		    (rc = process_mech_operands(argc, argv, B_FALSE))
		    != SUCCESS) {
			goto out;
		}
	}

	switch (prov->cp_type) {
	case METASLOT:
		rc = enable_metaslot(alt_token, alt_slot, use_default,
		    mecharglist, allflag, auto_key_migrate_flag);
		break;
	case PROV_UEF_LIB:
		rc = enable_uef_lib(prov->cp_name, rndflag, allflag,
		    mecharglist);
		break;
	case PROV_KEF_SOFT:
	case PROV_KEF_HARD:
		if (rndflag && !allflag) {
			if ((mecharglist = create_mech(RANDOM)) == NULL) {
				rc = FAILURE;
				break;
			}
		}
		if (getzoneid() == GLOBAL_ZONEID) {
			rc = enable_kef(prov->cp_name, rndflag, allflag,
			    mecharglist);
		} else {
			/*
			 * TRANSLATION_NOTE
			 * "enable" could be either a literal keyword
			 * and hence not to be translated, or a verb and
			 * translatable.  A choice was made to view it as
			 * a literal keyword.  "global" is keyword and not
			 * to be translated.
			 */
			cryptoerror(LOG_STDERR, gettext("%1$s for kernel "
			    "providers is supported in the %2$s zone only"),
			    "enable", "global");
			rc = FAILURE;
		}
		break;
	default: /* should not come here */
		rc = FAILURE;
		break;
	}
out:
	free(prov);
	if (mecharglist != NULL) {
		free_mechlist(mecharglist);
	}
	if (alt_token != NULL) {
		free(alt_token);
	}
	if (alt_slot != NULL) {
		free(alt_slot);
	}
	return (rc);
}



/*
 * The top level function fo the install subcommand.
 */
static int
do_install(int argc, char **argv)
{
	cryptoadm_provider_t 	*prov = NULL;
	int	rc;

	if (argc < 3) {
		usage();
		return (ERROR_USAGE);
	}

	prov = get_provider(argc, argv);
	if (prov == NULL ||
	    prov->cp_type == PROV_BADNAME || prov->cp_type == PROV_KEF_HARD) {
		/*
		 * TRANSLATION_NOTE
		 * "install" could be either a literal keyword and hence
		 * not to be translated, or a verb and translatable.  A
		 * choice was made to view it as a literal keyword.
		 */
		cryptoerror(LOG_STDERR,
		    gettext("bad provider name for %s."), "install");
		rc = FAILURE;
		goto out;
	}

	if (prov->cp_type == PROV_UEF_LIB) {
		rc = install_uef_lib(prov->cp_name);
		goto out;
	}

	/* It is the PROV_KEF_SOFT type now  */

	/* check if there are mechanism operands */
	if (argc < 4) {
		/*
		 * TRANSLATION_NOTE
		 * "mechanism" could be either a literal keyword and hence
		 * not to be translated, or a descriptive word and
		 * translatable.  A choice was made to view it as a literal
		 * keyword.
		 */
		cryptoerror(LOG_STDERR,
		    gettext("need %s operands for installing a"
		    " kernel software provider."), "mechanism");
		rc = ERROR_USAGE;
		goto out;
	}

	if ((rc = process_mech_operands(argc, argv, B_FALSE)) != SUCCESS) {
		goto out;
	}

	if (allflag == B_TRUE) {
		/*
		 * TRANSLATION_NOTE
		 * "all", "mechanism", and "install" are all keywords and
		 * not to be translated.
		 */
		cryptoerror(LOG_STDERR,
		    gettext("can not use the %1$s keyword for %2$s "
		    "in the %3$s subcommand."), "all", "mechanism", "install");
		rc = ERROR_USAGE;
		goto out;
	}

	if (getzoneid() == GLOBAL_ZONEID) {
		rc = install_kef(prov->cp_name, mecharglist);
	} else {
		/*
		 * TRANSLATION_NOTE
		 * "install" could be either a literal keyword and hence
		 * not to be translated, or a verb and translatable.  A
		 * choice was made to view it as a literal keyword.
		 * "global" is keyword and not to be translated.
		 */
		cryptoerror(LOG_STDERR, gettext("%1$s for kernel providers "
		    "is supported in the %2$s zone only"), "install", "global");
		rc = FAILURE;
	}
out:
	free(prov);
	return (rc);
}



/*
 * The top level function for the uninstall subcommand.
 */
static int
do_uninstall(int argc, char **argv)
{
	cryptoadm_provider_t 	*prov = NULL;
	int	rc = SUCCESS;

	if (argc != 3) {
		usage();
		return (ERROR_USAGE);
	}

	prov = get_provider(argc, argv);
	if (prov == NULL ||
	    prov->cp_type == PROV_BADNAME || prov->cp_type == PROV_KEF_HARD) {
		/*
		 * TRANSLATION_NOTE
		 * "uninstall" could be either a literal keyword and hence
		 * not to be translated, or a verb and translatable.  A
		 * choice was made to view it as a literal keyword.
		 */
		cryptoerror(LOG_STDERR,
		    gettext("bad provider name for %s."), "uninstall");
		free(prov);
		return (FAILURE);
	}

	if (prov->cp_type == PROV_UEF_LIB) {
		rc = uninstall_uef_lib(prov->cp_name);
	} else if (prov->cp_type == PROV_KEF_SOFT) {
		if (getzoneid() == GLOBAL_ZONEID) {
			rc = uninstall_kef(prov->cp_name);
		} else {
			/*
			 * TRANSLATION_NOTE
			 * "uninstall" could be either a literal keyword and
			 * hence not to be translated, or a verb and
			 * translatable.  A choice was made to view it as a
			 * literal keyword.  "global" is keyword and not to
			 * be translated.
			 */
			cryptoerror(LOG_STDERR, gettext("%1$s for kernel "
			    "providers is supported in the %2$s zone only"),
			    "uninstall", "global");
			rc = FAILURE;
		}
	}

	free(prov);
	return (rc);
}


/*
 * The top level function for the unload subcommand.
 */
static int
do_unload(int argc, char **argv)
{
	cryptoadm_provider_t 	*prov = NULL;
	entry_t	*pent;
	boolean_t	is_active;
	int rc = SUCCESS;

	if (argc != 3) {
		usage();
		return (ERROR_USAGE);
	}

	/* check if it is a kernel software provider */
	prov = get_provider(argc, argv);
	if (prov == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("unable to determine provider name."));
		goto out;
	}
	if (prov->cp_type != PROV_KEF_SOFT) {
		cryptoerror(LOG_STDERR,
		    gettext("%s is not a valid kernel software provider."),
		    prov->cp_name);
		rc = FAILURE;
		goto out;
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		/*
		 * TRANSLATION_NOTE
		 * "unload" could be either a literal keyword and hence
		 * not to be translated, or a verb and translatable.
		 * A choice was made to view it as a literal keyword.
		 * "global" is keyword and not to be translated.
		 */
		cryptoerror(LOG_STDERR, gettext("%1$s for kernel providers "
		    "is supported in the %2$s zone only"), "unload", "global");
		rc = FAILURE;
		goto out;
	}

	/* Check if it is in the kcf.conf file first */
	if ((pent = getent_kef(prov->cp_name)) == NULL) {
		cryptoerror(LOG_STDERR,
		    gettext("provider %s does not exist."), prov->cp_name);
		rc = FAILURE;
		goto out;
	}
	free_entry(pent);

	/* If it is unloaded already, return  */
	if (check_active_for_soft(prov->cp_name, &is_active) == FAILURE) {
		cryptodebug("internal error");
		cryptoerror(LOG_STDERR,
		    gettext("failed to unload %s."), prov->cp_name);
		rc = FAILURE;
		goto out;
	}

	if (is_active == B_FALSE) { /* unloaded already */
		rc = SUCCESS;
		goto out;
	} else if (unload_kef_soft(prov->cp_name, B_TRUE) == FAILURE) {
		cryptoerror(LOG_STDERR,
		    gettext("failed to unload %s."), prov->cp_name);
		rc = FAILURE;
	} else {
		rc = SUCCESS;
	}
out:
	free(prov);
	return (rc);
}



/*
 * The top level function for the refresh subcommand.
 */
static int
do_refresh(int argc)
{
	if (argc != 2) {
		usage();
		return (ERROR_USAGE);
	}

	/*
	 * Note:  in non-global zone, this must silently return SUCCESS
	 * due to integration with SMF, for "svcadm refresh cryptosvc"
	 */
	if (getzoneid() != GLOBAL_ZONEID)
		return (SUCCESS);

	return (refresh());
}


/*
 * The top level function for the start subcommand.
 */
static int
do_start(int argc)
{
	int ret;

	if (argc != 2) {
		usage();
		return (ERROR_USAGE);
	}

	ret = do_refresh(argc);
	if (ret != SUCCESS)
		return (ret);

	return (start_daemon());
}

/*
 * The top level function for the stop subcommand.
 */
static int
do_stop(int argc)
{
	if (argc != 2) {
		usage();
		return (ERROR_USAGE);
	}

	return (stop_daemon());
}



/*
 * List all the providers.
 */
static int
list_simple_for_all(boolean_t verbose)
{
	uentrylist_t	*pliblist;
	uentrylist_t	*plibptr;
	entrylist_t	*pdevlist_conf;
	entrylist_t	*psoftlist_conf;
	entrylist_t	*pdevlist_zone;
	entrylist_t	*psoftlist_zone;
	entrylist_t	*ptr;
	crypto_get_dev_list_t	*pdevlist_kernel = NULL;
	boolean_t	is_active;
	int	ru = SUCCESS;
	int	rs = SUCCESS;
	int	rd = SUCCESS;
	int	i;

	/* get user-level providers */
	(void) printf(gettext("\nUser-level providers:\n"));
	if (get_pkcs11conf_info(&pliblist) != SUCCESS) {
		cryptoerror(LOG_STDERR, gettext(
		    "failed to retrieve the list of user-level providers."));
		ru = FAILURE;
	}
	plibptr = pliblist;
	while (plibptr != NULL) {
		if (strcmp(plibptr->puent->name, METASLOT_KEYWORD) != 0) {
			(void) printf(gettext("Provider: %s\n"),
			    plibptr->puent->name);
			if (verbose) {
				(void) list_mechlist_for_lib(
				    plibptr->puent->name, mecharglist, NULL,
				    B_FALSE, verbose, B_FALSE);
				(void) printf("\n");
			}
		}
		plibptr = plibptr->next;
	}
	free_uentrylist(pliblist);

	/* get kernel software providers */
	(void) printf(gettext("\nKernel software providers:\n"));

	if (getzoneid() == GLOBAL_ZONEID) {
		/* use kcf.conf for kernel software providers in global zone */
		pdevlist_conf = NULL;
		psoftlist_conf = NULL;

		if (get_kcfconf_info(&pdevlist_conf, &psoftlist_conf) !=
		    SUCCESS) {
			cryptoerror(LOG_STDERR,
			    gettext("failed to retrieve the "
			    "list of kernel software providers.\n"));
			rs = FAILURE;
		}

		ptr = psoftlist_conf;
		while (ptr != NULL) {
			if (check_active_for_soft(ptr->pent->name, &is_active)
			    == FAILURE) {
				rs = FAILURE;
				cryptoerror(LOG_STDERR, gettext("failed to "
				    "get the state of a kernel software "
				    "providers.\n"));
				break;
			}

			(void) printf("\t%s", ptr->pent->name);
			if (is_active == B_FALSE) {
				(void) printf(gettext(" (inactive)\n"));
			} else {
				(void) printf("\n");
			}
			ptr = ptr->next;
		}

		free_entrylist(pdevlist_conf);
		free_entrylist(psoftlist_conf);
	} else {
		/* kcf.conf not there in non-global zone, use /dev/cryptoadm */
		pdevlist_zone = NULL;
		psoftlist_zone = NULL;

		if (get_admindev_info(&pdevlist_zone, &psoftlist_zone) !=
		    SUCCESS) {
			cryptoerror(LOG_STDERR,
			    gettext("failed to retrieve the "
			    "list of kernel software providers.\n"));
			rs = FAILURE;
		}

		ptr = psoftlist_zone;
		while (ptr != NULL) {
			(void) printf("\t%s\n", ptr->pent->name);
			ptr = ptr->next;
		}

		free_entrylist(pdevlist_zone);
		free_entrylist(psoftlist_zone);
	}

	/* get kernel hardware providers */
	(void) printf(gettext("\nKernel hardware providers:\n"));
	if (get_dev_list(&pdevlist_kernel) == FAILURE) {
		cryptoerror(LOG_STDERR, gettext("failed to retrieve "
		    "the list of kernel hardware providers.\n"));
		rd = FAILURE;
	} else {
		for (i = 0; i < pdevlist_kernel->dl_dev_count; i++) {
			(void) printf("\t%s/%d\n",
			    pdevlist_kernel->dl_devs[i].le_dev_name,
			    pdevlist_kernel->dl_devs[i].le_dev_instance);
		}
	}
	free(pdevlist_kernel);

	if (ru == FAILURE || rs == FAILURE || rd == FAILURE) {
		return (FAILURE);
	} else {
		return (SUCCESS);
	}
}



/*
 * List all the providers. And for each provider, list the mechanism list.
 */
static int
list_mechlist_for_all(boolean_t verbose)
{
	crypto_get_dev_list_t	*pdevlist_kernel;
	uentrylist_t	*pliblist;
	uentrylist_t	*plibptr;
	entrylist_t	*pdevlist_conf;
	entrylist_t	*psoftlist_conf;
	entrylist_t	*pdevlist_zone;
	entrylist_t	*psoftlist_zone;
	entrylist_t	*ptr;
	mechlist_t	*pmechlist;
	boolean_t	is_active;
	char	provname[MAXNAMELEN];
	char	devname[MAXNAMELEN];
	int 	inst_num;
	int	count;
	int	i;
	int	rv;
	int	rc = SUCCESS;

	/* get user-level providers */
	(void) printf(gettext("\nUser-level providers:\n"));
	/*
	 * TRANSLATION_NOTE
	 * Strictly for appearance's sake, this line should be as long as
	 * the length of the translated text above.
	 */
	(void) printf(gettext("=====================\n"));
	if (get_pkcs11conf_info(&pliblist) != SUCCESS) {
		cryptoerror(LOG_STDERR, gettext("failed to retrieve "
		    "the list of user-level providers.\n"));
		rc = FAILURE;
	}

	plibptr = pliblist;
	while (plibptr != NULL) {
		/* skip metaslot entry */
		if (strcmp(plibptr->puent->name, METASLOT_KEYWORD) != 0) {
			(void) printf(gettext("\nProvider: %s\n"),
			    plibptr->puent->name);
			rv = list_mechlist_for_lib(plibptr->puent->name,
			    mecharglist, NULL, B_FALSE, verbose, B_TRUE);
			if (rv == FAILURE) {
				rc = FAILURE;
			}
		}
		plibptr = plibptr->next;
	}
	free_uentrylist(pliblist);

	/* get kernel software providers */
	(void) printf(gettext("\nKernel software providers:\n"));
	/*
	 * TRANSLATION_NOTE
	 * Strictly for appearance's sake, this line should be as long as
	 * the length of the translated text above.
	 */
	(void) printf(gettext("==========================\n"));
	if (getzoneid() == GLOBAL_ZONEID) {
		/* use kcf.conf for kernel software providers in global zone */
		pdevlist_conf = NULL;
		psoftlist_conf = NULL;

		if (get_kcfconf_info(&pdevlist_conf, &psoftlist_conf) !=
		    SUCCESS) {
			cryptoerror(LOG_STDERR, gettext("failed to retrieve "
			    "the list of kernel software providers.\n"));
			rc = FAILURE;
		}

		ptr = psoftlist_conf;
		while (ptr != NULL) {
			if (check_active_for_soft(ptr->pent->name, &is_active)
			    == SUCCESS) {
				if (is_active) {
					rv = list_mechlist_for_soft(
					    ptr->pent->name);
					if (rv == FAILURE) {
						rc = FAILURE;
					}
				} else {
					(void) printf(gettext(
					    "%s: (inactive)\n"),
					    ptr->pent->name);
				}
			} else {
				/* should not happen */
				(void) printf(gettext(
				    "%s: failed to get the mechanism list.\n"),
				    ptr->pent->name);
				rc = FAILURE;
			}
			ptr = ptr->next;
		}

		free_entrylist(pdevlist_conf);
		free_entrylist(psoftlist_conf);
	} else {
		/* kcf.conf not there in non-global zone, use /dev/cryptoadm */
		pdevlist_zone = NULL;
		psoftlist_zone = NULL;

		if (get_admindev_info(&pdevlist_zone, &psoftlist_zone) !=
		    SUCCESS) {
			cryptoerror(LOG_STDERR, gettext("failed to retrieve "
			    "the list of kernel software providers.\n"));
			rc = FAILURE;
		}

		ptr = psoftlist_zone;
		while (ptr != NULL) {
			rv = list_mechlist_for_soft(ptr->pent->name);
			if (rv == FAILURE) {
				(void) printf(gettext(
				    "%s: failed to get the mechanism list.\n"),
				    ptr->pent->name);
				rc = FAILURE;
			}
			ptr = ptr->next;
		}

		free_entrylist(pdevlist_zone);
		free_entrylist(psoftlist_zone);
	}

	/* Get kernel hardware providers and their mechanism lists */
	(void) printf(gettext("\nKernel hardware providers:\n"));
	/*
	 * TRANSLATION_NOTE
	 * Strictly for appearance's sake, this line should be as long as
	 * the length of the translated text above.
	 */
	(void) printf(gettext("==========================\n"));
	if (get_dev_list(&pdevlist_kernel) != SUCCESS) {
		cryptoerror(LOG_STDERR, gettext("failed to retrieve "
		    "the list of hardware providers.\n"));
		return (FAILURE);
	}

	for (i = 0; i < pdevlist_kernel->dl_dev_count; i++) {
		(void) strlcpy(devname,
		    pdevlist_kernel->dl_devs[i].le_dev_name, MAXNAMELEN);
		inst_num = pdevlist_kernel->dl_devs[i].le_dev_instance;
		count = pdevlist_kernel->dl_devs[i].le_mechanism_count;
		(void) snprintf(provname, sizeof (provname), "%s/%d", devname,
		    inst_num);
		if (get_dev_info(devname, inst_num, count, &pmechlist) ==
		    SUCCESS) {
			(void) filter_mechlist(&pmechlist, RANDOM);
			print_mechlist(provname, pmechlist);
			free_mechlist(pmechlist);
		} else {
			(void) printf(gettext("%s: failed to get the mechanism"
			    " list.\n"), provname);
			rc = FAILURE;
		}
	}
	free(pdevlist_kernel);
	return (rc);
}


/*
 * List all the providers. And for each provider, list the policy information.
 */
static int
list_policy_for_all(void)
{
	crypto_get_dev_list_t	*pdevlist_kernel;
	uentrylist_t	*pliblist;
	uentrylist_t	*plibptr;
	entrylist_t	*pdevlist_conf;
	entrylist_t	*psoftlist_conf;
	entrylist_t	*ptr;
	entrylist_t	*phead;
	boolean_t	found;
	char	provname[MAXNAMELEN];
	int	i;
	int	rc = SUCCESS;

	/* Get user-level providers */
	(void) printf(gettext("\nUser-level providers:\n"));
	/*
	 * TRANSLATION_NOTE
	 * Strictly for appearance's sake, this line should be as long as
	 * the length of the translated text above.
	 */
	(void) printf(gettext("=====================\n"));
	if (get_pkcs11conf_info(&pliblist) == FAILURE) {
		cryptoerror(LOG_STDERR, gettext("failed to retrieve "
		    "the list of user-level providers.\n"));
	} else {
		plibptr = pliblist;
		while (plibptr != NULL) {
			/* skip metaslot entry */
			if (strcmp(plibptr->puent->name,
			    METASLOT_KEYWORD) != 0) {
				if (print_uef_policy(plibptr->puent)
				    == FAILURE) {
					rc = FAILURE;
				}
			}
			plibptr = plibptr->next;
		}
		free_uentrylist(pliblist);
	}

	/* kernel software providers */
	(void) printf(gettext("\nKernel software providers:\n"));
	/*
	 * TRANSLATION_NOTE
	 * Strictly for appearance's sake, this line should be as long as
	 * the length of the translated text above.
	 */
	(void) printf(gettext("==========================\n"));

	/* Get all entries from the kcf.conf file */
	pdevlist_conf = NULL;
	if (getzoneid() == GLOBAL_ZONEID) {
		/* use kcf.conf for kernel software providers in global zone */
		psoftlist_conf = NULL;

		if (get_kcfconf_info(&pdevlist_conf, &psoftlist_conf) ==
		    FAILURE) {
			cryptoerror(LOG_STDERR, gettext(
			    "failed to retrieve the list of kernel "
			    "providers.\n"));
			return (FAILURE);
		}

		ptr = psoftlist_conf;
		while (ptr != NULL) {
			(void) list_policy_for_soft(ptr->pent->name);
			ptr = ptr->next;
		}

		free_entrylist(psoftlist_conf);
	} else {
		/* kcf.conf not there in non-global zone, no policy info */

		/*
		 * TRANSLATION_NOTE
		 * "global" is keyword and not to be translated.
		 */
		cryptoerror(LOG_STDERR, gettext(
		    "policy information for kernel software providers is "
		    "available in the %s zone only"), "global");
	}

	/* Kernel hardware providers */
	(void) printf(gettext("\nKernel hardware providers:\n"));
	/*
	 * TRANSLATION_NOTE
	 * Strictly for appearance's sake, this line should be as long as
	 * the length of the translated text above.
	 */
	(void) printf(gettext("==========================\n"));

	if (getzoneid() != GLOBAL_ZONEID) {
		/*
		 * TRANSLATION_NOTE
		 * "global" is keyword and not to be translated.
		 */
		cryptoerror(LOG_STDERR, gettext(
		    "policy information for kernel hardware providers is "
		    "available in the %s zone only"), "global");
		return (FAILURE);
	}

	/* Get the hardware provider list from kernel */
	if (get_dev_list(&pdevlist_kernel) != SUCCESS) {
		cryptoerror(LOG_STDERR, gettext(
		    "failed to retrieve the list of hardware providers.\n"));
		free_entrylist(pdevlist_conf);
		return (FAILURE);
	}

	/*
	 * For each hardware provider from kernel, check if it has an entry
	 * in the config file.  If it has an entry, print out the policy from
	 * config file and remove the entry from the hardware provider list
	 * of the config file.  If it does not have an entry in the config
	 * file, no mechanisms of it have been disabled. But, we still call
	 * list_policy_for_hard() to account for the "random" feature.
	 */
	for (i = 0; i < pdevlist_kernel->dl_dev_count; i++) {
		(void) snprintf(provname, sizeof (provname), "%s/%d",
		    pdevlist_kernel->dl_devs[i].le_dev_name,
		    pdevlist_kernel->dl_devs[i].le_dev_instance);
		found = B_FALSE;
		phead = ptr = pdevlist_conf;
		while (!found && ptr) {
			if (strcmp(ptr->pent->name, provname) == 0) {
				found = B_TRUE;
			} else {
				phead = ptr;
				ptr = ptr->next;
			}
		}

		if (found) {
			(void) list_policy_for_hard(ptr->pent->name);
			if (phead == ptr) {
				pdevlist_conf = pdevlist_conf->next;
			} else {
				phead->next = ptr->next;
			}
			free_entry(ptr->pent);
			free(ptr);
		} else {
			(void) list_policy_for_hard(provname);
		}
	}

	/*
	 * If there are still entries left in the pdevlist_conf list from
	 * the config file, these providers must have been detached.
	 * Should print out their policy information also.
	 */
	ptr = pdevlist_conf;
	while (ptr != NULL) {
		print_kef_policy(ptr->pent, B_FALSE, B_TRUE);
		ptr = ptr->next;
	}

	free_entrylist(pdevlist_conf);
	free(pdevlist_kernel);

	return (rc);
}
