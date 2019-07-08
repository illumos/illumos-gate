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

/*
 * This is the main program file for the configuration administration
 * command as set out in manual page cfgadm(1M).  It uses the configuration
 * administration library interface, libcfgadm, as set out in manual
 * page config_admin(3X).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <langinfo.h>
#include <time.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/sunddi.h>
#include <sys/openpromio.h>
#include <sys/ddi_impldefs.h>
#include <sys/systeminfo.h>
#include <ctype.h>
#include <zone.h>

#include <config_admin.h>
#include "cfgadm.h"

#define	S_FREE(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)
#define	GET_DYN(a)	(strstr((a), CFGA_DYN_SEP))
/*
 * forward declarations
 */
static char *basename(char *);
static void cfgadm_error(int, char *);
static int confirm_interactive(void *, const char *);
static int confirm_no(void *, const char *);
static int confirm_yes(void *, const char *);
static void usage(void);
static void usage_field(void);
static int extract_list_suboptions(char *, char **, char **, char **,
    int *, char **, char **, char **);
static int message_output(void *appdata_ptr, const char *message);
static void *config_calloc_check(size_t, size_t);
static cfga_ap_types_t find_arg_type(const char *);
static int yesno(char *, char *);


static int compare_ap_id(cfga_list_data_t *, cfga_list_data_t *, match_type_t);
static int compare_r_state(cfga_list_data_t *, cfga_list_data_t *,
    match_type_t);
static int compare_o_state(cfga_list_data_t *, cfga_list_data_t *,
    match_type_t);
static int compare_cond(cfga_list_data_t *, cfga_list_data_t *, match_type_t);
static int compare_time(cfga_list_data_t *, cfga_list_data_t *, match_type_t);
static int compare_info(cfga_list_data_t *, cfga_list_data_t *, match_type_t);
static int compare_type(cfga_list_data_t *, cfga_list_data_t *, match_type_t);
static int compare_busy(cfga_list_data_t *, cfga_list_data_t *, match_type_t);
static int compare_class(cfga_list_data_t *, cfga_list_data_t *, match_type_t);
static int compare_null(cfga_list_data_t *, cfga_list_data_t *, match_type_t);
static void print_log_id(cfga_list_data_t *, int, char *);
static void print_r_state(cfga_list_data_t *, int, char *);
static void print_o_state(cfga_list_data_t *, int, char *);
static void print_cond(cfga_list_data_t *, int, char *);
static void print_time(cfga_list_data_t *, int, char *);
static void print_time_p(cfga_list_data_t *, int, char *);
static void print_info(cfga_list_data_t *, int, char *);
static void print_type(cfga_list_data_t *, int, char *);
static void print_busy(cfga_list_data_t *, int, char *);
static void print_phys_id(cfga_list_data_t *, int, char *);
static void print_class(cfga_list_data_t *, int, char *);
static void print_null(cfga_list_data_t *, int, char *);
static int count_fields(char *, char);
static int process_sort_fields(int, struct sort_el *, char *);
static int process_fields(int, struct print_col *, int, char *);
static cfga_err_t print_fields(int, struct print_col *, int, int, char *,
    cfga_list_data_t *, FILE *);
static int ldata_compare(const void *, const void *);

static void arg_got_resp(ap_arg_t *inp, ap_out_t *out_array, int nouts,
    int dyn_exp);
static void out_was_req(ap_out_t *outp, ap_arg_t *in_array, int nargs,
    int no_dyn);
static void report_no_response(ap_arg_t *arg_array, int napids_to_list);

static cfga_err_t set_log_flt(cfga_list_data_t *p, const char *val);
static cfga_err_t set_type_flt(cfga_list_data_t *p, const char *val);
static cfga_err_t set_class_flt(cfga_list_data_t *p, const char *val);

static char *get_dyn(const char *ap_id);
static void remove_dyn(char *ap_id);
static char *s_strdup(char *str);

/*
 * global data
 */
/* command name for messages */
static char *cmdname;

/*
 * control for comparing, printing and filtering cfga_list_data
 * NOTE:Field names (i.e. member 0 of field_info struct) may not contain '('.
 *	The post filtering code depends on it.
 * NOTE:A NULL value for the set_filter member indicates that filtering based
 *	on that field is currently not supported.
 */
static struct field_info all_fields[] = {
{"ap_id", "Ap_Id", SZ_EL(ap_log_id), compare_ap_id, print_log_id, set_log_flt},
{"r_state", "Receptacle", STATE_WIDTH, compare_r_state, print_r_state, NULL},
{"o_state", "Occupant", STATE_WIDTH, compare_o_state, print_o_state, NULL},
{"condition", "Condition", COND_WIDTH, compare_cond, print_cond, NULL},
{"status_time", "When", TIME_WIDTH, compare_time, print_time, NULL},
{"status_time_p", "When", TIME_P_WIDTH, compare_time, print_time_p, NULL},
{"info", "Information", SZ_EL(ap_info), compare_info, print_info, NULL},
{"type", "Type", SZ_EL(ap_type), compare_type, print_type, set_type_flt},
{"busy", "Busy", 8, compare_busy, print_busy, NULL},
{"physid", "Phys_Id", SZ_EL(ap_phys_id), compare_ap_id, print_phys_id, NULL},
{"class", "Class", SZ_EL(ap_class), compare_class, print_class, set_class_flt}
};

#define	PREFILT_CLASS_STR	"class="

typedef struct {
	cfga_list_data_t ldata;			/* Selection criteria */
	match_type_t match_type_p[N_FIELDS];	/* Type of match */
} post_filter_t;

static struct field_info null_field =
	{"null", "", 0, compare_null, print_null, NULL};

static struct sort_el *sort_list;	/* Used in ldata_compare() */
static int nsort_list;
static char unk_field[] = "%s: field \"%s\" unknown\n";

static char aptype_no_dyn[] = "%s: Invalid ap_id: %s\n";

/* strings that make up the usage message */
static char *usage_tab[] = {
" %s [-f] [-y|-n] [-v] [-o hardware_opts ] -c function ap_id [ap_id...]\n",
" %s [-f] [-y|-n] [-v] [-o hardware_opts ] -x function ap_id [ap_id...]\n",
" %s [-v] [-s listing_options ] [-o hardware_opts ] [-a]\n"
"\t[-l [ap_id|ap_type...]]\n",
" %s [-v] [-o hardware_opts ] -t ap_id [ap_id...]\n",
" %s [-v] [-o hardware_opts ] -h [ap_id|ap_type...]\n",
};

/* Type of matches currently supported by the select sub-option */
static match_cvt_t match_type_array[] = {
	{"partial", CFGA_MATCH_PARTIAL},
	{"exact", CFGA_MATCH_EXACT}
};

#define	N_MATCH_TYPES	(sizeof (match_type_array)/sizeof (match_type_array[0]))

static cfga_err_t setup_filter(const char *selectp, const char *matchp,
    post_filter_t *post_filtp, char **prefilt_optpp);
static cfga_err_t parse_select_opt(const char *selectp,
    post_filter_t *post_filtp, match_type_t match_type);
static int do_config_list(int, char *[], cfga_list_data_t *, int, char *,
    char *, char *, int, char *, post_filter_t *, int);
static void do_post_filter(ap_out_t *outp, post_filter_t *post_filtp, int *jp);


/*
 * main - the main routine of cfgadm, processes the command line
 * and dispatches functions off to libraries.
 */
int
main(
	int argc,
	char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;
	char *subopts;
	char *subvalue;
	char *const *ap_args = NULL;
	cfga_cmd_t sc_opt = 0;
	struct cfga_confirm confirm;
	struct cfga_msg message;
	int ret = CFGA_ERROR;
	int i;
	char *estrp = NULL;
	cfga_op_t action = CFGA_OP_NONE;
	char *plat_opts = NULL;
	char *act_arg = NULL;
	enum confirm confarg = CONFIRM_DEFAULT;
	char *list_opts = NULL;
	cfga_flags_t flags = 0;
	int arg_error = 0;
	int dyn_exp = 0;

	estrp = NULL;
	if (argc > 0)
		cmdname = basename(argv[0]);
	else
		cmdname = "cfgadm";
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, OPTIONS)) != EOF) {
		static char dup_action[] =
"%s: more than one action specified (-c,-l,-t,-x)\n";
		static char dup_option[] =
"%s: more than one -%c option specified\n";
		switch (c) {
		case 'a':
			if (dyn_exp) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_option),
				    cmdname, c);
			}
			dyn_exp = 1;
			break;
		case 'c':
			if (action != CFGA_OP_NONE) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_action),
				    cmdname);
			}
			action = CFGA_OP_CHANGE_STATE;
			subopts = optarg;
			subvalue = NULL;
			/*
			 * Reject -c suboption if they are unrecognized
			 * or more than one or have a associated value.
			 */
			if ((sc_opt = getsubopt(&subopts, state_opts,
			    &subvalue)) == -1 || *subopts != '\0' ||
			    subvalue != NULL) {
				arg_error = 1;
				break;
			}
			break;
		case 'f':
			if ((flags & CFGA_FLAG_FORCE) != 0) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_option),
				    cmdname, c);
			}
			flags |= CFGA_FLAG_FORCE;
			break;
		case 'h':
			if (action != CFGA_OP_NONE) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_action),
				    cmdname);
			}
			action = CFGA_OP_HELP;
			break;
		case 'l':
			if (action != CFGA_OP_NONE) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_action),
				    cmdname);
			}
			action = CFGA_OP_LIST;
			break;
		case 'n':
			if (confarg != CONFIRM_DEFAULT) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_option),
				    cmdname, c);
			}
			confarg = CONFIRM_NO;
			break;
		case 'o':
			if (plat_opts != NULL) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_option),
				    cmdname, c);
			}
			plat_opts = optarg;
			break;
		case 's':
			if (list_opts != NULL) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_option),
				    cmdname, c);
			}
			list_opts = optarg;
			break;
		case 't':
			if (action != CFGA_OP_NONE) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_action),
				    cmdname);
			}
			action = CFGA_OP_TEST;
			break;
		case 'x':
			if (action != CFGA_OP_NONE) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_action),
				    cmdname);
			}
			action = CFGA_OP_PRIVATE;
			act_arg = optarg;
			break;
		case 'v':
			if ((flags & CFGA_FLAG_VERBOSE) != 0) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_option),
				    cmdname, c);
			}
			flags |= CFGA_FLAG_VERBOSE;
			break;
		case 'y':
			if (confarg != CONFIRM_DEFAULT) {
				arg_error = 1;
				(void) fprintf(stderr, gettext(dup_option),
				    cmdname, c);
			}
			confarg = CONFIRM_YES;
			break;
		case '?':	/* getopts issues message is this case */
		default:	/* catch programming errors */
			arg_error = 1;
			break;
		}
	}

	/* default action is list */
	if (action == CFGA_OP_NONE)
		action = CFGA_OP_LIST;

	/* -s and -a option only for list */
	if (action != CFGA_OP_LIST && (list_opts != NULL || dyn_exp)) {
		arg_error = 1;
	}

	if (arg_error) {
		usage();
		exit(EXIT_ARGERROR);
		/*NOTREACHED*/
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		cfgadm_error(CFGA_NOTSUPP,
		    gettext("cfgadm can only be run from the global zone"));
		exit(EXIT_NOTSUPP);
	}

	ap_args = &argv[optind];

	/*
	 * If neither -n of -y was specified, interactive confirmation
	 * is used.  Check if the program has terminal I/O and
	 * enforce -n if not.
	 */
	(void) memset(&confirm, 0, sizeof (confirm));
	if (action == CFGA_OP_CHANGE_STATE || action == CFGA_OP_PRIVATE) {
		if (confarg == CONFIRM_DEFAULT &&
		    !(isatty(fileno(stdin)) && isatty(fileno(stderr))))
			confarg = CONFIRM_NO;
		switch (confarg) {
		case CONFIRM_DEFAULT:
			confirm.confirm = confirm_interactive;
			break;
		case CONFIRM_NO:
			confirm.confirm = confirm_no;
			break;
		case CONFIRM_YES:
			confirm.confirm = confirm_yes;
			break;
		default:	/* paranoia */
			abort();
			/*NOTREACHED*/
		}
	}

	/*
	 * set up message output routine
	 */
	message.message_routine = message_output;

	switch (action) {
	case CFGA_OP_CHANGE_STATE:
		/* Sanity check - requires an argument */
		if ((argc - optind) <= 0) {
			usage();
			break;
		}
		/* Sanity check - args cannot be ap_types */
		for (i = 0; i < (argc - optind); i++) {
			if (find_arg_type(ap_args[i]) == AP_TYPE) {
				usage();
				exit(EXIT_ARGERROR);
				/*NOTREACHED*/
			}
		}
		ret = config_change_state(sc_opt, argc - optind, ap_args,
		    plat_opts, &confirm, &message, &estrp, flags);
		if (ret != CFGA_OK)
			cfgadm_error(ret, estrp);
		break;
	case CFGA_OP_PRIVATE:
		/* Sanity check - requires an argument */
		if ((argc - optind) <= 0) {
			usage();
			break;
		}
		/* Sanity check - args cannot be ap_types */
		for (i = 0; i < (argc - optind); i++) {
			if (find_arg_type(ap_args[i]) == AP_TYPE) {
				usage();
				exit(EXIT_ARGERROR);
				/*NOTREACHED*/
			}
		}

		ret = config_private_func(act_arg, argc - optind, ap_args,
		    plat_opts, &confirm, &message, &estrp, flags);

		if (ret != CFGA_OK)
			cfgadm_error(ret, estrp);
		break;
	case CFGA_OP_TEST:
		/* Sanity check - requires an argument */
		if ((argc - optind) <= 0) {
			usage();
			break;
		}

		if ((flags & ~CFGA_FLAG_VERBOSE) != 0) {
			usage();
			exit(EXIT_ARGERROR);
			/*NOTREACHED*/
		}

		/* Sanity check - args cannot be ap_types */
		for (i = 0; i < (argc - optind); i++) {
			if (find_arg_type(ap_args[i]) == AP_TYPE) {
				usage();
				exit(EXIT_ARGERROR);
				/*NOTREACHED*/
			}
		}
		ret = config_test(argc - optind, ap_args, plat_opts, &message,
		    &estrp, flags);
		if (ret != CFGA_OK)
			cfgadm_error(ret, estrp);
		break;
	case CFGA_OP_HELP:

		if ((flags & ~CFGA_FLAG_VERBOSE) != 0) {
			usage();
			exit(EXIT_ARGERROR);
			/*NOTREACHED*/
		}

		/* always do usage? */
		usage();
		ret = config_help(argc - optind, ap_args, &message, plat_opts,
		    flags);
		if (ret != CFGA_OK)
			cfgadm_error(ret, estrp);
		break;

	case CFGA_OP_LIST: {
		/*
		 * Note that we leak the strdup strings below (we never free
		 * them). This is ok in this context since cfgadm is
		 * a short lived process that will exit shortly freeing
		 * the memory.
		 */
		cfga_list_data_t *list_array = NULL;
		int nlist = 0;
		char *sort_fields = s_strdup(DEF_SORT_FIELDS);
		char *cols = s_strdup(DEF_COLS);
		char *cols2 = s_strdup(DEF_COLS2);
		int noheadings = 0;
		char *delim = s_strdup(DEF_DELIM);
		int exitcode = EXIT_OK;
		int i;
		int type = 0;
		char *selectp = NULL, *matchp = NULL, *prefilt_optp = NULL;
		post_filter_t *post_filtp = NULL;

		if ((flags & ~CFGA_FLAG_VERBOSE) != 0) {
			usage();
			exit(EXIT_ARGERROR);
			/*NOTREACHED*/
		}

		if (flags & CFGA_FLAG_VERBOSE) {
			cols = s_strdup(DEF_COLS_VERBOSE);
			cols2 = s_strdup(DEF_COLS2_VERBOSE);
		}

		if (list_opts != NULL && !extract_list_suboptions(list_opts,
		    &sort_fields, &cols, &cols2, &noheadings, &delim,
		    &selectp, &matchp)) {
			usage_field();
			exit(EXIT_ARGERROR);
			/*NOTREACHED*/
		}

		/*
		 * Scan any args and see if there are any ap_types.
		 * If there are we get all attachment point stats and
		 * then filter what gets printed.
		 */

		type = 0;
		for (i = 0; i < (argc - optind); i++) {
			if (find_arg_type(ap_args[i]) == AP_TYPE) {
				type = 1;
				/* ap_types cannot have dynamic components */
				if (get_dyn(ap_args[i]) != NULL) {
					(void) fprintf(stderr,
					    gettext(aptype_no_dyn),
					    cmdname, ap_args[i]);
					exit(EXIT_ARGERROR);
					/*NOTREACHED*/
				}
				break;
			}
		}

		/* Setup filter */
		post_filtp = config_calloc_check(1, sizeof (*post_filtp));
		if (post_filtp == NULL) {
			exit(EXIT_OPFAILED);
			/*NOTREACHED*/
		}
		if (setup_filter(selectp, matchp, post_filtp, &prefilt_optp)
		    != CFGA_OK) {
			S_FREE(post_filtp);
			exit(EXIT_ARGERROR);
			/*NOTREACHED*/
		}

		list_array = NULL;
		exitcode = EXIT_OK;

		/*
		 * Check for args. No args means find all libs
		 * and call the cfga_list_ext routine with no ap_ids specified.
		 * With args, if any one of the args are ap_types we
		 * again find all attachment points as in the
		 * no-args case above and then select which attachment points
		 * are actually displayed.
		 */
		if (((argc - optind) == 0) || (type == 1)) {
			/*
			 * No args, or atleast 1 ap_type arg
			 */
			ret = config_list_ext(0, NULL, &list_array,
			    &nlist, plat_opts, prefilt_optp, &estrp,
			    dyn_exp ? CFGA_FLAG_LIST_ALL : 0);
		} else {
			/*
			 * If the args are all ap_ids (no ap_types) we call the
			 * cfga_list_ext routine with those specific ap_ids.
			 */
			ret = config_list_ext(argc - optind, ap_args,
			    &list_array, &nlist, plat_opts, prefilt_optp,
			    &estrp, dyn_exp ? CFGA_FLAG_LIST_ALL : 0);
		}

		S_FREE(prefilt_optp);

		if (ret == CFGA_OK) {

			if (do_config_list(
			    (argc - optind), &argv[optind], list_array, nlist,
			    sort_fields, cols, cols2, noheadings, delim,
			    post_filtp, dyn_exp) != CFGA_OK) {
				exitcode = EXIT_ARGERROR;
			} else {
				exitcode = EXIT_OK;
			}

			S_FREE(list_array);
			S_FREE(post_filtp);

			if (estrp != NULL && *estrp != '\0')
				cfgadm_error(CFGA_NOTSUPP, estrp);
			if (exitcode != EXIT_OK) {
				exit(exitcode);
				/*NOTREACHED*/
			}
		} else {

			S_FREE(post_filtp);
			cfgadm_error(ret, estrp);
		}
		break;
	}
	default:	/* paranoia */
		abort();
		/*NOTREACHED*/
	}

	if (ret == CFGA_NOTSUPP) {
		return (EXIT_NOTSUPP);
	} else if (ret != CFGA_OK) {
		return (EXIT_OPFAILED);
	} else {
		return (EXIT_OK);
	}
	/*NOTREACHED*/
}

/*
 * usage - outputs the usage help message.
 */
static void
usage(void)
{
	int i;

	(void) fprintf(stderr, "%s\n", gettext("Usage:"));
	for (i = 0; i < sizeof (usage_tab)/sizeof (usage_tab[0]); i++) {
		(void) fprintf(stderr, gettext(usage_tab[i]), cmdname);
	}
}

/*
 * Emit an error message.
 * As a side-effect the hardware specific error message is deallocated
 * as described in config_admin(3X).
 */
static void
cfgadm_error(int errnum, char *estrp)
{
	const char *ep;

	ep = config_strerror(errnum);
	if (ep == NULL)
		ep = gettext("configuration administration unknown error");
	if (estrp != NULL && *estrp != '\0') {
		(void) fprintf(stderr, "%s: %s: %s\n", cmdname, ep, estrp);
	} else {
		(void) fprintf(stderr, "%s: %s\n", cmdname, ep);
	}
	if (estrp != NULL)
		free((void *)estrp);
	if (errnum == CFGA_INVAL)
		usage();
}

/*
 * confirm_interactive - prompt user for confirmation
 */
static int
confirm_interactive(
	void *appdata_ptr,
	const char *message)
{
	static char yeschr[YESNO_STR_MAX + 2];
	static char nochr[YESNO_STR_MAX + 2];
	static int inited = 0;
	int isyes;

#ifdef lint
	appdata_ptr = appdata_ptr;
#endif /* lint */
	/*
	 * First time through initialisation.  In the original
	 * version of this command this function is only called once,
	 * but this function is generalized for the future.
	 */
	if (!inited) {
		(void) strncpy(yeschr, nl_langinfo(YESSTR), YESNO_STR_MAX + 1);
		(void) strncpy(nochr, nl_langinfo(NOSTR), YESNO_STR_MAX + 1);
		inited = 1;
	}

	do {
		(void) fprintf(stderr, "%s (%s/%s)? ", message, yeschr, nochr);
		isyes = yesno(yeschr, nochr);
	} while (isyes == -1);
	return (isyes);
}

/*
 * If any text is input it must sub-string match either yes or no.
 * Failure of this match is indicated by return of -1.
 * If an empty line is input, this is taken as no.
 */
static int
yesno(
	char *yesp,
	char *nop)
{
	int	i, b;
	char	ans[YESNO_STR_MAX + 1];

	i = 0;

	/*CONSTCOND*/
	while (1) {
		b = getc(stdin);	/* more explicit that rm.c version */
		if (b == '\n' || b == '\0' || b == EOF) {
			if (i < YESNO_STR_MAX)	/* bug fix to rm.c version */
				ans[i] = 0;
			break;
		}
		if (i < YESNO_STR_MAX)
			ans[i] = b;
		i++;
	}
	if (i >= YESNO_STR_MAX) {
		i = YESNO_STR_MAX;
		ans[YESNO_STR_MAX] = 0;
	}
	/* changes to rm.c version follow */
	if (i == 0)
		return (0);
	if (strncmp(nop, ans, i) == 0)
		return (0);
	if (strncmp(yesp, ans, i) == 0)
		return (1);
	return (-1);
}

/*ARGSUSED*/
static int
confirm_no(
	void *appdata_ptr,
	const char *message)
{
	return (0);
}

/*ARGSUSED*/
static int
confirm_yes(
	void *appdata_ptr,
	const char *message)
{
	return (1);
}

/*
 * Find base name of filename.
 */
static char *
basename(
	char *cp)
{
	char *sp;

	if ((sp = strrchr(cp, '/')) != NULL)
		return (sp + 1);
	return (cp);
}

/*ARGSUSED*/
static int
message_output(
	void *appdata_ptr,
	const char *message)
{
	(void) fprintf(stderr, "%s", message);
	return (CFGA_OK);

}

/*
 * extract_list_suboptions - process list option string
 */
static int
extract_list_suboptions(
	char *arg,
	char **sortpp,
	char **colspp,
	char **cols2pp,
	int *noheadingsp,
	char **delimpp,
	char **selectpp,
	char **matchpp)
{
	char *value = NULL;
	int subopt = 0;
	int err = 0;

	while (*arg != '\0') {
		static char need_value[] =
"%s: sub-option \"%s\" requires a value\n";
		static char no_value[] =
"%s: sub-option \"%s\" does not take a value\n";
		static char unk_subopt[] =
"%s: sub-option \"%s\" unknown\n";
		char **pptr;

		subopt = getsubopt(&arg, list_options, &value);
		switch (subopt) {
		case LIST_SORT:
			pptr = sortpp;
			goto valcom;
		case LIST_COLS:
			pptr = colspp;
			goto valcom;
		case LIST_COLS2:
			pptr = cols2pp;
			goto valcom;
		case LIST_SELECT:
			pptr = selectpp;
			goto valcom;
		case LIST_MATCH:
			pptr = matchpp;
			goto valcom;
		case LIST_DELIM:
			pptr = delimpp;
		valcom:
			if (value == NULL) {
				(void) fprintf(stderr, gettext(need_value),
				    cmdname, list_options[subopt]);
				err = 1;
			} else
				*pptr = value;
			break;
		case LIST_NOHEADINGS:
			if (value != NULL) {
				(void) fprintf(stderr, gettext(no_value),
				    cmdname, list_options[subopt]);
				err = 1;
			} else
				*noheadingsp = 1;
			break;
		default:
			(void) fprintf(stderr, gettext(unk_subopt),
			    cmdname, value);
			err = 1;
			break;
		}
	}
	return (err == 0);
}

static cfga_err_t
setup_prefilter(post_filter_t *post_filtp, char **prefilt_optpp)
{
	size_t len;
	const char *clopt = PREFILT_CLASS_STR;
	int idx;


	*prefilt_optpp = NULL;

	/* Get the index for the "class" field */
	for (idx = 0; idx < N_FIELDS; idx++) {
		if (strcmp(all_fields[idx].name, PREFILT_CLASS_STR) == 0)
			break;
	}

	/*
	 * Currently pre-filter available only for class fld w/ EXACT match
	 */
	if (idx >= N_FIELDS ||
	    post_filtp->match_type_p[idx] != CFGA_MATCH_EXACT) {
		return (CFGA_OK);
	}

	len = strlen(clopt) + strlen(post_filtp->ldata.ap_class) + 1;
	if ((*prefilt_optpp = config_calloc_check(1, len)) == NULL) {
		return (CFGA_LIB_ERROR);
	}

	(void) strcpy(*prefilt_optpp, clopt);
	(void) strcat(*prefilt_optpp, post_filtp->ldata.ap_class);

	/*
	 * Since it is being pre-filtered, this attribute does not need
	 * post-filtering.
	 */
	post_filtp->match_type_p[idx] = CFGA_MATCH_NOFILTER;
	if (all_fields[idx].set_filter != NULL) {
		(void) all_fields[idx].set_filter(&post_filtp->ldata, "");
	}

	return (CFGA_OK);
}

static cfga_err_t
set_attrval(
	const char *attr,
	const char *val,
	post_filter_t *post_filtp,
	match_type_t match_type)
{
	int fld = 0;
	cfga_err_t ret = CFGA_ERROR;

	for (fld = 0; fld < N_FIELDS; fld++) {
		if (strcmp(attr, all_fields[fld].name) == 0)
			break;
	}

	/* Valid field or is the select option supported for this field */
	if (fld >= N_FIELDS || all_fields[fld].set_filter == NULL) {
		return (CFGA_ATTR_INVAL);
	}

	if ((ret = all_fields[fld].set_filter(&post_filtp->ldata, val))
	    == CFGA_OK) {
		post_filtp->match_type_p[fld] = match_type;
	}

	return (ret);

}

static char inval_optarg[] =
	"%s: invalid value \"%s\" for %s suboption.\n";

/*
 * Parses the "select" string and fills in the post_filter structure
 */
static cfga_err_t
parse_select_opt(
	const char *selectp,
	post_filter_t *post_filtp,
	match_type_t match_type)
{
	parse_state_t state = CFGA_PSTATE_INIT;
	char *cp = NULL, *optstr = NULL, *attr = NULL, *val = NULL;
	int bal = 0;	/* Tracks balancing */
	char chr;
	cfga_err_t ret;


	if (selectp == NULL || post_filtp == NULL) {
		return (CFGA_ERROR);
	}

	optstr = config_calloc_check(1, strlen(selectp) + 1);
	if (optstr == NULL) {
		return (CFGA_LIB_ERROR);
	}

	(void) strcpy(optstr, selectp);

	/* Init */
	ret = CFGA_ATTR_INVAL;
	bal = 0;
	cp = attr = optstr;
	state = CFGA_PSTATE_INIT;

	for (; *cp != '\0'; cp++) {
		switch (state) {
		case CFGA_PSTATE_INIT:
			if (*cp != LEFT_PAREN)
				break;
			*cp = '\0';
			val = cp + 1;
			bal = 1;
			state = CFGA_PSTATE_ATTR_DONE;
			break;
		case CFGA_PSTATE_ATTR_DONE:
			chr = *cp;
			switch (chr) {
			case LEFT_PAREN:
				bal++;
				break;
			case RIGHT_PAREN:
				bal--;
				if (bal == 0) {
					*cp = '\0';
					state = CFGA_PSTATE_VAL_DONE;
				}
				break;
			}
			break;
		case CFGA_PSTATE_VAL_DONE:
			if (*cp != ':') {
				state = CFGA_PSTATE_ERR;
				goto out;
			}

			*cp = '\0';
			if (set_attrval(attr, val, post_filtp,
			    match_type) != CFGA_OK) {
				state = CFGA_PSTATE_ERR;
				goto out;
			}
			state = CFGA_PSTATE_INIT;
			attr = cp + 1;
			break;
		default:
			state = CFGA_PSTATE_ERR;
			/* FALLTHROUGH */
		case CFGA_PSTATE_ERR:
			goto out;
		}
	}

	/*FALLTHRU*/
out:
	if (state == CFGA_PSTATE_VAL_DONE) {
		ret = set_attrval(attr, val, post_filtp, match_type);
	} else {
		ret = CFGA_ATTR_INVAL;
	}

	if (ret != CFGA_OK) {
		(void) fprintf(stderr, gettext(inval_optarg), cmdname,
		    selectp, list_options[LIST_SELECT]);
	}

	S_FREE(optstr);
	return (ret);
}



static cfga_err_t
setup_filter(
	const char *selectp,
	const char *matchp,
	post_filter_t *post_filtp,
	char **prefilt_optpp)
{
	cfga_err_t ret = CFGA_ERROR;
	match_type_t match_type = CFGA_MATCH_NOFILTER;
	int i;

	static char match_needs_select[] =
	    "%s: %s suboption can only be used with %s suboption.\n";


	*prefilt_optpp = NULL;

	/*
	 * Initial: no filtering.
	 * CFGA_MATCH_NOFILTER is NOT a valid user input
	 */
	for (i = 0; i < N_FIELDS; i++) {
		post_filtp->match_type_p[i] = CFGA_MATCH_NOFILTER;
	}

	/* Determine type of match */
	if (matchp == NULL && selectp == NULL) {
		/* No filtering */
		return (CFGA_OK);
	} else if (matchp == NULL && selectp != NULL) {
		match_type = CFGA_DEFAULT_MATCH;
	} else if (matchp != NULL && selectp == NULL) {
		/* If only match specified, select criteria also needed */
		(void) fprintf(stderr, gettext(match_needs_select),
		    cmdname, list_options[LIST_MATCH],
		    list_options[LIST_SELECT]);
		return (CFGA_ERROR);
	} else {
		for (i = 0; i < N_MATCH_TYPES; i++) {
			if (strcmp(matchp, match_type_array[i].str) == 0) {
				match_type = match_type_array[i].type;
				break;
			}
		}
		if (i >= N_MATCH_TYPES) {
			(void) fprintf(stderr, gettext(inval_optarg), cmdname,
			    matchp, list_options[LIST_MATCH]);
			return (CFGA_ERROR);
		}
	}

	if ((ret = parse_select_opt(selectp, post_filtp, match_type))
	    != CFGA_OK) {
		return (ret);
	}

	/* Handle pre-filtering. */
	if ((ret = setup_prefilter(post_filtp, prefilt_optpp)) != CFGA_OK) {
		/* Cleanup */
		for (i = 0; i < N_FIELDS; i++) {
			post_filtp->match_type_p[i] = CFGA_MATCH_NOFILTER;
		}
		return (ret);
	}


	return (CFGA_OK);
}

/*
 * compare_ap_id - compare two ap_id's
 *
 * For partial matches, argument order is significant. The filtering criterion
 * should be the first argument.
 */

static int
compare_ap_id(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{

	switch (match_type) {
		case CFGA_MATCH_NOFILTER:
			return (0);	/* No filtering. all pass */
		case CFGA_MATCH_PARTIAL:
			return (strncmp(p1->ap_log_id, p2->ap_log_id,
			    strlen(p1->ap_log_id)));
		case CFGA_MATCH_EXACT:
			return (strcmp(p1->ap_log_id, p2->ap_log_id));
		case CFGA_MATCH_ORDER:
		default:
			return (config_ap_id_cmp(p1->ap_log_id, p2->ap_log_id));
	}
}

/*
 * print_log_id - print logical ap_id
 */
static void
print_log_id(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	(void) sprintf(lp, "%-*.*s", width, sizeof (p->ap_log_id),
	    p->ap_log_id);
}

/*
 * set_log_flt - Setup filter for logical ap_id
 */
static cfga_err_t
set_log_flt(
	cfga_list_data_t *p,
	const char *val)
{
	if (strlen(val) > sizeof (p->ap_log_id) - 1)
		return (CFGA_ATTR_INVAL);

	(void) strcpy(p->ap_log_id, val);

	return (CFGA_OK);
}

/*
 * set_type_flt - Setup filter for type field
 */

static cfga_err_t
set_type_flt(
	cfga_list_data_t *p,
	const char *val)
{
	if (strlen(val) > sizeof (p->ap_type) - 1)
		return (CFGA_ATTR_INVAL);

	(void) strcpy(p->ap_type, val);

	return (CFGA_OK);
}

/*
 * set_class_flt - Setup filter for class field
 */
static cfga_err_t
set_class_flt(
	cfga_list_data_t *p,
	const char *val)
{
	if (strlen(val) > sizeof (p->ap_class) - 1)
		return (CFGA_ATTR_INVAL);

	(void) strcpy(p->ap_class, val);

	return (CFGA_OK);
}


/*
 * compare_r_state - compare receptacle state of two ap_id's
 */
static int
compare_r_state(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{
	switch (match_type) {
	case CFGA_MATCH_NOFILTER:  /* no filtering. pass all */
		return (0);
	case CFGA_MATCH_ORDER:
	default:
		return (p1->ap_r_state - p2->ap_r_state);
	}
}

/*
 * compare_o_state - compare occupant state of two ap_id's
 */
static int
compare_o_state(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{
	switch (match_type) {
	case CFGA_MATCH_NOFILTER:	/* no filtering. all pass */
		return (0);
	case CFGA_MATCH_ORDER:
	default:
		return (p1->ap_o_state - p2->ap_o_state);
	}
}

/*
 * compare_busy - compare busy field of two ap_id's
 */
static int
compare_busy(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{

	switch (match_type) {
	case CFGA_MATCH_NOFILTER:	/* no filtering. all pass */
		return (0);
	case CFGA_MATCH_ORDER:
	default:
		return (p1->ap_busy - p2->ap_busy);
	}
}

/*
 * print_r_state - print receptacle state
 */
static void
print_r_state(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	char *cp;

	switch (p->ap_r_state) {
	case CFGA_STAT_EMPTY:
		cp = "empty";
		break;
	case CFGA_STAT_CONNECTED:
		cp = "connected";
		break;
	case CFGA_STAT_DISCONNECTED:
		cp = "disconnected";
		break;
	default:
		cp = "???";
		break;
	}
	(void) sprintf(lp, "%-*s", width, cp);
}

/*
 * print_o_state - print occupant state
 */
static void
print_o_state(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	char *cp;

	switch (p->ap_o_state) {
	case CFGA_STAT_UNCONFIGURED:
		cp = "unconfigured";
		break;
	case CFGA_STAT_CONFIGURED:
		cp = "configured";
		break;
	default:
		cp = "???";
		break;
	}
	(void) sprintf(lp, "%-*s", width, cp);
}

/*
 * compare_cond - compare condition field of two ap_id's
 */
static int
compare_cond(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{

	switch (match_type) {
	case CFGA_MATCH_NOFILTER:
		return (0);
	case CFGA_MATCH_ORDER:
	default:
		return (p1->ap_cond - p2->ap_cond);
	}
}

/*
 * print_cond - print attachment point condition
 */
static void
print_cond(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	char *cp;

	switch (p->ap_cond) {
	case CFGA_COND_UNKNOWN:
		cp = "unknown";
		break;
	case CFGA_COND_UNUSABLE:
		cp = "unusable";
		break;
	case CFGA_COND_FAILING:
		cp = "failing";
		break;
	case CFGA_COND_FAILED:
		cp = "failed";
		break;
	case CFGA_COND_OK:
		cp = "ok";
		break;
	default:
		cp = "???";
		break;
	}
	(void) sprintf(lp, "%-*s", width, cp);
}

/*
 * compare_time - compare time field of two ap_id's
 */
static int
compare_time(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{
	switch (match_type) {
	case CFGA_MATCH_NOFILTER:
		return (0);
	case CFGA_MATCH_ORDER:
	default:
		return (p1->ap_status_time - p2->ap_status_time);
	}
}


/*
 * print_time - print time from cfga_list_data.
 * Time print based on ls(1).
 */
static void
print_time(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	static time_t   year, now;
	time_t stime;
	char	time_buf[50];	/* array to hold day and time */

	if (year == 0) {
		now = time((long *)NULL);
		year = now - 6L*30L*24L*60L*60L; /* 6 months ago */
		now = now + 60;
	}
	stime = p->ap_status_time;
	if (stime == (time_t)-1) {
		(void) sprintf(lp, "%-*s", width, gettext("unavailable"));
		return;
	}

	if ((stime < year) || (stime > now)) {
		(void) strftime(time_buf, sizeof (time_buf),
		    dcgettext(NULL, FORMAT1, LC_TIME), localtime(&stime));
	} else {
		(void) strftime(time_buf, sizeof (time_buf),
		    dcgettext(NULL, FORMAT2, LC_TIME), localtime(&stime));
	}
	(void) sprintf(lp, "%-*s", width, time_buf);
}

/*
 * print_time_p - print time from cfga_list_data.
 */
static void
print_time_p(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	struct tm *tp;
	char tstr[TIME_P_WIDTH+1];

	tp = localtime(&p->ap_status_time);
	(void) sprintf(tstr, "%04d%02d%02d%02d%02d%02d", tp->tm_year + 1900,
	    tp->tm_mon + 1, tp->tm_mday, tp->tm_hour, tp->tm_min, tp->tm_sec);
	(void) sprintf(lp, "%-*s", width, tstr);
}

/*
 * compare_info - compare info from two cfga_list_data structs
 */
static int
compare_info(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{
	switch (match_type) {
	case CFGA_MATCH_NOFILTER:
		return (0);
	case CFGA_MATCH_ORDER:
	default:
		return (strncmp(p1->ap_info, p2->ap_info,
		    sizeof (p2->ap_info)));
	}
}

/*
 * print_info - print info from cfga_list_data struct
 */
static void
print_info(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	(void) sprintf(lp, "%-*.*s", width, sizeof (p->ap_info), p->ap_info);
}

/*
 * compare_type - compare type from two cfga_list_data structs
 *
 * For partial matches, argument order is significant. The filtering criterion
 * should be the first argument.
 */
static int
compare_type(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{
	switch (match_type) {
	case CFGA_MATCH_NOFILTER:
		return (0);
	case CFGA_MATCH_PARTIAL:
		return (strncmp(p1->ap_type, p2->ap_type, strlen(p1->ap_type)));
	case CFGA_MATCH_EXACT:
	case CFGA_MATCH_ORDER:
	default:
		return (strncmp(p1->ap_type, p2->ap_type,
		    sizeof (p2->ap_type)));
	}
}

/*
 * print_type - print type from cfga_list_data struct
 */
static void
print_type(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	(void) sprintf(lp, "%-*.*s", width, sizeof (p->ap_type), p->ap_type);
}


/*
 * compare_class - compare class from two cfga_list_data structs
 *
 * For partial matches, argument order is significant. The filtering criterion
 * should be the first argument.
 */
static int
compare_class(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{

	switch (match_type) {
	case CFGA_MATCH_NOFILTER:
		return (0);
	case CFGA_MATCH_PARTIAL:
		return (strncmp(p1->ap_class, p2->ap_class,
		    strlen(p1->ap_class)));
	case CFGA_MATCH_EXACT:
	case CFGA_MATCH_ORDER:
	default:
		return (strncmp(p1->ap_class, p2->ap_class,
		    sizeof (p2->ap_class)));
	}
}

/*
 * print_class - print class from cfga_list_data struct
 */
static void
print_class(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	(void) sprintf(lp, "%-*.*s", width, sizeof (p->ap_class), p->ap_class);
}
/*
 * print_busy - print busy from cfga_list_data struct
 */
/* ARGSUSED */
static void
print_busy(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	if (p->ap_busy)
		(void) sprintf(lp, "%-*.*s", width, width, "y");
	else
		(void) sprintf(lp, "%-*.*s", width, width, "n");
}

/*
 * print_phys_id - print physical ap_id
 */
static void
print_phys_id(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	(void) sprintf(lp, "%-*.*s", width, sizeof (p->ap_phys_id),
	    p->ap_phys_id);
}


/*
 * find_field - find the named field
 */
static struct field_info *
find_field(char *fname)
{
	struct field_info *fldp;

	for (fldp = all_fields; fldp < &all_fields[N_FIELDS]; fldp++)
		if (strcmp(fname, fldp->name) == 0)
			return (fldp);
	return (NULL);
}

/*
 * usage_field - print field usage
 */
static void
usage_field()
{
	struct field_info *fldp = NULL;
	const char *sep;
	static char field_list[] = "%s: print or sort fields must be one of:";

	(void) fprintf(stderr, gettext(field_list), cmdname);
	sep = "";

	for (fldp = all_fields; fldp < &all_fields[N_FIELDS]; fldp++) {
		(void) fprintf(stderr, "%s %s", sep, fldp->name);
		sep = ",";
	}
	(void) fprintf(stderr, "\n");
}

/*
 * compare_null - null comparison routine
 */
/*ARGSUSED*/
static int
compare_null(
	cfga_list_data_t *p1,
	cfga_list_data_t *p2,
	match_type_t match_type)
{
	return (0);
}

/*
 * print_null - print out a field of spaces
 */
/*ARGSUSED*/
static void
print_null(
	cfga_list_data_t *p,
	int width,
	char *lp)
{
	(void) sprintf(lp, "%-*s", width, "");
}

/*
 * do_config_list - directs the output of the listing functions
 */
static int
do_config_list(
	int l_argc,
	char *l_argv[],
	cfga_list_data_t *statlist,
	int nlist,
	char *sortp,
	char *colsp,
	char *cols2p,
	int noheadings,
	char *delimp,
	post_filter_t *post_filtp,
	int dyn_exp)
{
	int nprcols = 0, ncols2 = 0;
	struct print_col *prnt_list = NULL;
	int napids_to_list = 0;
	FILE *fp = NULL;
	int f_err;
	cfga_list_data_t **sel_boards = NULL;
	int nsel = 0;
	int i, j;
	cfga_err_t ret;

	ap_arg_t *arg_array = NULL;
	ap_out_t *out_array = NULL;


	sort_list = NULL;
	f_err = 0;
	fp = stdout;
	nsort_list = count_fields(sortp, FDELIM);
	if (nsort_list != 0) {
		sort_list = config_calloc_check(nsort_list,
		    sizeof (*sort_list));
		if (sort_list == NULL) {
			ret = CFGA_LIB_ERROR;
			goto out;
		}
		f_err |= process_sort_fields(nsort_list, sort_list, sortp);
	} else
		sort_list = NULL;

	nprcols = count_fields(colsp, FDELIM);
	if ((ncols2 = count_fields(cols2p, FDELIM)) > nprcols)
		nprcols = ncols2;
	if (nprcols != 0) {
		prnt_list = config_calloc_check(nprcols, sizeof (*prnt_list));
		if (prnt_list == NULL) {
			ret = CFGA_LIB_ERROR;
			goto out;
		}
		f_err |= process_fields(nprcols, prnt_list, 0, colsp);
		if (ncols2 != 0)
			f_err |= process_fields(nprcols, prnt_list, 1, cols2p);
	} else
		prnt_list = NULL;

	if (f_err) {
		usage_field();
		ret = CFGA_ERROR;
		goto out;
	}

	/* Create an array of all user args (if any) */
	if (l_argc != 0) {
		int i, j;

		napids_to_list = 0;

		for (i = 0; i < l_argc; i++) {
			napids_to_list += count_fields(l_argv[i], ARG_DELIM);
		}

		arg_array = config_calloc_check(napids_to_list,
		    sizeof (*arg_array));
		if (arg_array == NULL) {
			ret = CFGA_LIB_ERROR;
			goto out;
		}

		for (i = 0, j = 0; i < l_argc; i++) {
			int n;

			n = count_fields(l_argv[i], ARG_DELIM);
			if (n == 0) {
				continue;
			} else if (n == 1) {
				arg_array[j].arg = l_argv[i];
				arg_array[j].resp = 0;
				j++;
			} else {
				char *cp, *ncp;

				cp = l_argv[i];
				for (;;) {
					arg_array[j].arg = cp;
					arg_array[j].resp = 0;
					j++;
					ncp = strchr(cp, ARG_DELIM);
					if (ncp == NULL)
						break;
					*ncp = '\0';
					cp = ncp + 1;
				}
			}
		}
		assert(j == napids_to_list);
	} else {
		napids_to_list = 0;
		arg_array = NULL;
	}

	assert(nlist != 0);

	out_array = config_calloc_check(nlist, sizeof (*out_array));
	if (out_array == NULL) {
		ret = CFGA_LIB_ERROR;
		goto out;
	}


	/* create a list of output stat data */
	for (i = 0; i < nlist; i++) {
		out_array[i].ldatap = &statlist[i];
		out_array[i].req = 0;
	}

	/*
	 * Mark all user input which got atleast 1 stat data in response
	 */
	for (i = 0; i < napids_to_list; i++) {
		arg_got_resp(&arg_array[i], out_array, nlist, dyn_exp);
	}

	/*
	 * Process output data
	 */
	nsel = 0;
	for (i = 0; i < nlist; i++) {
		/*
		 * Mark all the stats which were actually requested by user
		 */
		out_was_req(&out_array[i], arg_array, napids_to_list, 0);
		if (out_array[i].req == 0 && dyn_exp) {
			/*
			 * Try again without the dynamic component for the
			 * if dynamic expansion was requested.
			 */
			out_was_req(&out_array[i], arg_array,
			    napids_to_list, 1);
		}

		/*
		 * post filter data which was actually requested
		 */
		if (out_array[i].req == 1) {
			do_post_filter(&out_array[i], post_filtp, &nsel);
		}
	}

	sel_boards = config_calloc_check(nsel, sizeof (*sel_boards));
	if (sel_boards == NULL) {
		ret = CFGA_LIB_ERROR;
		goto out;
	}

	for (i = 0, j = 0; i < nlist; i++) {
		if (out_array[i].req == 1) {
			sel_boards[j] = out_array[i].ldatap;
			j++;
		}
	}

	assert(j == nsel);

	/*
	 * Print headings even if no list entries - Bug or feature ?
	 */
	if (!noheadings && prnt_list != NULL) {
		if ((ret = print_fields(nprcols, prnt_list, 1, 0,
		    delimp, NULL, fp)) != CFGA_OK) {
			goto out;
		}
		if (ncols2 != 0) {
			if ((ret = print_fields(nprcols, prnt_list, 1,
			    1, delimp, NULL, fp)) != CFGA_OK) {
				goto out;
			}
		}
	}

	if (nsel != 0) {
		if (sort_list != NULL && nsel > 1) {
			qsort(sel_boards, nsel, sizeof (sel_boards[0]),
			    ldata_compare);
		}

		if (prnt_list != NULL) {
			for (i = 0; i < nsel; i++) {
				if ((ret = print_fields(nprcols,
				    prnt_list, 0, 0, delimp, sel_boards[i], fp))
				    != CFGA_OK)
					goto out;
				if (ncols2 != 0) {
					if ((ret = print_fields(
					    nprcols, prnt_list, 0, 1, delimp,
					    sel_boards[i], fp)) != CFGA_OK)
						goto out;
				}
			}
		}
	}
	/*
	 * Go thru the argument list and notify user about args
	 * which did not have a match
	 */
	report_no_response(arg_array, napids_to_list);
	ret = CFGA_OK;
	/*FALLTHRU*/
out:
	S_FREE(sel_boards);
	S_FREE(arg_array);
	S_FREE(out_array);

	S_FREE(sort_list);
	S_FREE(prnt_list);

	return (ret);
}


/*
 * Mark all user inputs which got a response
 */
static void
arg_got_resp(ap_arg_t *inp, ap_out_t *out_array, int nouts, int dyn_exp)
{
	int i;
	cfga_ap_types_t type;


	if (nouts == 0) {
		return;
	}

	type = find_arg_type(inp->arg);

	/*
	 * Go through list of output stats and check if argument
	 * produced that output
	 */
	for (i = 0; i < nouts; i++) {
		if (type == PHYSICAL_AP_ID) {
			if (config_ap_id_cmp(out_array[i].ldatap->ap_phys_id,
			    inp->arg) == 0) {
				break;
			}
		} else if (type == LOGICAL_AP_ID) {
			if (config_ap_id_cmp(out_array[i].ldatap->ap_log_id,
			    inp->arg) == 0) {
				break;
			}
		} else if (type == AP_TYPE) {
			/*
			 * An AP_TYPE argument cannot generate dynamic
			 * attachment point stats unless dynamic expansion was
			 * requested by user.
			 */
			if (!dyn_exp && get_dyn(out_array[i].ldatap->ap_log_id)
			    != NULL) {
				continue;
			}

			if (strncmp(out_array[i].ldatap->ap_log_id, inp->arg,
			    strlen(inp->arg)) == 0) {
				break;
			}
		} else {
			return;
		}
	}

	if (i < nouts) {
		inp->resp = 1;
	}
}

/* Mark all stat data which were requested by user */
static void
out_was_req(ap_out_t *outp, ap_arg_t *in_array, int nargs, int no_dyn)
{
	int i;
	cfga_ap_types_t type = UNKNOWN_AP;
	char physid[MAXPATHLEN], logid[MAXPATHLEN];


	/* If no user args, all output is acceptable */
	if (nargs == 0) {
		outp->req = 1;
		return;
	}


	(void) snprintf(physid, sizeof (physid), "%s",
	    outp->ldatap->ap_phys_id);
	(void) snprintf(logid, sizeof (logid), "%s", outp->ldatap->ap_log_id);

	/*
	 * Do comparison with or without dynamic component as requested by
	 * user.
	 */
	if (no_dyn) {
		/* Remove the dynamic component */
		remove_dyn(physid);
		remove_dyn(logid);
	}

	for (i = 0; i < nargs; i++) {
		type = find_arg_type(in_array[i].arg);
		if (type == PHYSICAL_AP_ID) {

			if (config_ap_id_cmp(in_array[i].arg, physid) == 0) {
				break;
			}
		} else if (type == LOGICAL_AP_ID) {

			if (config_ap_id_cmp(in_array[i].arg, logid) == 0) {
				break;
			}
		} else if (type == AP_TYPE) {
			/*
			 * Aptypes cannot generate dynamic attachment
			 * points unless dynamic expansion is specified.
			 * in which case this routine would be called a
			 * 2nd time with the no_dyn flag set and there
			 * would be no dynamic ap_ids.
			 */
			if (get_dyn(logid) != NULL) {
				continue;
			}

			if (strncmp(in_array[i].arg, logid,
			    strlen(in_array[i].arg)) == 0) {
				break;
			}
		} else {
			continue;
		}
	}

	if (i < nargs) {
		/* Ok, this output was requested */
		outp->req = 1;
	}

}

static void
do_post_filter(ap_out_t *outp, post_filter_t *post_filtp, int *nselp)
{
	int i;

	if (outp->req != 1) {
		return;
	}

	/*
	 * For fields without filtering (CFGA_MATCH_NOFILTER),
	 * compare always returns 0 (success)
	 */
	for (i = 0; i < N_FIELDS; i++) {
		/*
		 * Note: Order is important for partial match (via strncmp).
		 * The first argument for compare must be the filter.
		 */
		if (all_fields[i].compare(&post_filtp->ldata, outp->ldatap,
		    post_filtp->match_type_p[i])) {
			outp->req = 0;	/* Blocked by filter */
			return;
		}
	}

	/*
	 * Passed through filter
	 */
	(*nselp)++;
}

static void
report_no_response(ap_arg_t *arg_array, int nargs)
{
	int i;

	if (nargs == 0) {
		return;
	}


	/*
	 * nop if no user arguments
	 */
	for (i = 0; i < nargs; i++) {
		if (arg_array[i].resp == 0) {
			(void) fprintf(stderr,
			    gettext("%s: No matching library found\n"),
			    arg_array[i].arg);
		}
	}
}

/*
 * ldata_compare - compare two attachment point list data structures.
 */
static int
ldata_compare(
	const void *vb1,
	const void *vb2)
{
	int i;
	int res = -1;
	cfga_list_data_t *b1, *b2;


	b1 = *(cfga_list_data_t **)vb1;
	b2 = *(cfga_list_data_t **)vb2;

	for (i = 0; i < nsort_list; i++) {
		res = (*(sort_list[i].fld->compare))(b1, b2, CFGA_MATCH_ORDER);
		if (res != 0) {
			if (sort_list[i].reverse)
				res = -res;
			break;
		}
	}

	return (res);
}

/*
 * count_fields - Count the number of fields, using supplied delimiter.
 */
static int
count_fields(char *fspec, char delim)
{
	char *cp = NULL;
	int n;

	if (fspec == 0 || *fspec == '\0')
		return (0);
	n = 1;
	for (cp = fspec; *cp != '\0'; cp++)
		if (*cp == delim)
			n++;
	return (n);
}

/*
 * get_field
 * This function is not a re-implementation of strtok().
 * There can be null fields - strtok() eats spans of delimiters.
 */
static char *
get_field(char **fspp)
{
	char *cp = NULL, *fld;

	fld = *fspp;

	if (fld != NULL && *fld == '\0')
		fld = NULL;

	if (fld != NULL) {
		cp = strchr(*fspp, FDELIM);
		if (cp == NULL) {
			*fspp = NULL;
		} else {
			*cp = '\0';
			*fspp = cp + 1;
			if (*fld == '\0')
				fld = NULL;
		}
	}
	return (fld);
}

/*
 * process_fields -
 */
static int
process_fields(
	int ncol,
	struct print_col *list,
	int line2,
	char *fmt)
{
	struct print_col *pp = NULL;
	struct field_info *fldp = NULL;
	char *fmtx;
	char *fldn;
	int err;

	err = 0;
	fmtx = fmt;
	for (pp = list; pp < &list[ncol]; pp++) {
		fldn = get_field(&fmtx);
		fldp = &null_field;
		if (fldn != NULL) {
			struct field_info *tfldp;

			tfldp = find_field(fldn);
			if (tfldp != NULL) {
				fldp = tfldp;
			} else {
				(void) fprintf(stderr, gettext(unk_field),
				    cmdname, fldn);
				err = 1;
			}
		}
		if (line2) {
			pp->line2 = fldp;
			if (fldp->width > pp->width)
				pp->width = fldp->width;
		} else {
			pp->line1 = fldp;
			pp->width = fldp->width;
		}
	}
	return (err);
}

/*
 * process_sort_fields -
 */
static int
process_sort_fields(
	int nsort,
	struct sort_el *list,
	char *fmt)
{
	int i;
	int rev;
	struct field_info *fldp = NULL;
	char *fmtx;
	char *fldn;
	int err;

	err = 0;
	fmtx = fmt;
	for (i = 0; i < nsort; i++) {
		fldn = get_field(&fmtx);
		fldp = &null_field;
		rev = 0;
		if (fldn != NULL) {
			struct field_info *tfldp = NULL;

			if (*fldn == '-') {
				rev = 1;
				fldn++;
			}
			tfldp = find_field(fldn);
			if (tfldp != NULL) {
				fldp = tfldp;
			} else {
				(void) fprintf(stderr, gettext(unk_field),
				    cmdname, fldn);
				err = 1;
			}
		}
		list[i].reverse = rev;
		list[i].fld = fldp;
	}
	return (err);
}

/*
 * print_fields -
 */
static cfga_err_t
print_fields(
	int ncol,
	struct print_col *list,
	int heading,
	int line2,
	char *delim,
	cfga_list_data_t *bdp,
	FILE *fp)
{
	char *del = NULL;
	struct print_col *pp = NULL;
	struct field_info *fldp = NULL;
	static char *outline, *end;
	char *lp;

	if (outline == NULL) {
		int out_len, delim_len;

		delim_len = strlen(delim);
		out_len = 0;
		for (pp = list; pp < &list[ncol]; pp++) {
			out_len += pp->width;
			out_len += delim_len;
		}
		out_len -= delim_len;
		outline = config_calloc_check(out_len + 1, 1);
		if (outline == NULL) {
			return (CFGA_LIB_ERROR);
		}
		end = &outline[out_len + 1];
	}

	lp = outline;
	del = "";
	for (pp = list; pp < &list[ncol]; pp++) {
		fldp = line2 ? pp->line2 : pp->line1;
		(void) snprintf(lp, end - lp, "%s", del);
		lp += strlen(lp);
		if (heading) {
			(void) snprintf(lp, end - lp, "%-*s",
			    fldp->width, fldp->heading);
		} else {
			(*fldp->printfn)(bdp, fldp->width, lp);
		}
		lp += strlen(lp);
		del = delim;
	}

	/*
	 * Trim trailing spaces
	 */
	while (--lp >= outline && *lp == ' ')
		*lp = '\0';
	(void) fprintf(fp, "%s\n", outline);
	return (CFGA_OK);
}

/*
 * config_calloc_check - perform allocation, check result and
 * set error indicator
 */
static void *
config_calloc_check(
	size_t nelem,
	size_t elsize)
{
	void *p;
	static char alloc_fail[] =
"%s: memory allocation failed (%d*%d bytes)\n";


	p = calloc(nelem, elsize);
	if (p == NULL) {
		(void) fprintf(stderr, gettext(alloc_fail), cmdname,
		    nelem, elsize);
	}
	return (p);
}

/*
 * find_arg_type - determine if an argument is an ap_id or an ap_type.
 */
static cfga_ap_types_t
find_arg_type(const char *ap_id)
{
	struct stat sbuf;
	cfga_ap_types_t type;
	char *mkr = NULL, *cp;
	int size_ap = 0, size_mkr = 0, digit = 0, i = 0;
	char path[MAXPATHLEN];
	char apbuf[MAXPATHLEN];
	size_t len;


	/*
	 * sanity checks
	 */
	if (ap_id == NULL || *ap_id == '\0') {
		return (UNKNOWN_AP);
	}

	/*
	 * Mask the dynamic component if any
	 */
	if ((cp = GET_DYN(ap_id)) != NULL) {
		len = cp - ap_id;
	} else {
		len = strlen(ap_id);
	}

	if (len >= sizeof (apbuf)) {
		return (UNKNOWN_AP);
	}

	(void) strncpy(apbuf, ap_id, len);
	apbuf[len] = '\0';

	/*
	 * If it starts with a slash and is stat-able
	 * its a physical.
	 */
	if (*apbuf == '/' && stat(apbuf, &sbuf) == 0) {
		return (PHYSICAL_AP_ID);
	}

	/*
	 * Is this a symlink in CFGA_DEV_DIR ?
	 */
	(void) snprintf(path, sizeof (path), "%s/%s", CFGA_DEV_DIR, apbuf);

	if (lstat(path, &sbuf) == 0 && S_ISLNK(sbuf.st_mode) &&
	    stat(path, &sbuf) == 0) {
		return (LOGICAL_AP_ID);
	}

	/*
	 * Check for ":" which is always present in an ap_id but not maybe
	 * present or absent in an ap_type.
	 * We need to check that the characters right before the : are digits
	 * since an ap_id is of the form <name><instance>:<specific ap name>
	 */
	if ((mkr = strchr(apbuf, ':')) == NULL)  {
		type = AP_TYPE;
	} else {
		size_ap = strlen(apbuf);
		size_mkr = strlen(mkr);
		mkr = apbuf;

		digit = 0;
		for (i = size_ap - size_mkr - 1;  i > 0; i--) {
			if ((int)isdigit(mkr[i])) {
				digit++;
				break;
			}
		}
		if (digit == 0) {
			type = AP_TYPE;
		} else {
			type = LOGICAL_AP_ID;
		}
	}

	return (type);
}


static char *
get_dyn(const char *ap_id)
{
	if (ap_id == NULL) {
		return (NULL);
	}

	return (strstr(ap_id, CFGA_DYN_SEP));
}

/*
 * removes the dynamic component
 */
static void
remove_dyn(char *ap_id)
{
	char *cp;

	if (ap_id == NULL) {
		return;
	}

	cp = strstr(ap_id, CFGA_DYN_SEP);
	if (cp != NULL) {
		*cp = '\0';
	}
}


static char *
s_strdup(char *str)
{
	char *dup;

	/*
	 * sometimes NULL strings may be passed in (see DEF_COLS2). This
	 * is not an error.
	 */
	if (str == NULL) {
		return (NULL);
	}

	dup = strdup(str);
	if (dup == NULL) {
		(void) fprintf(stderr,
		    "%s \"%s\"\n", gettext("Cannot copy string"), str);
		return (NULL);
	}

	return (dup);
}
