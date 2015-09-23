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
 *  Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * svccfg(1) interpreter and command execution engine.
 */

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <libtecla.h>
#include <md5.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "manifest_find.h"
#include "manifest_hash.h"
#include "svccfg.h"

#define	MS_PER_US		1000

engine_state_t *est;

/*
 * Replacement lex(1) character retrieval routines.
 */
int
engine_cmd_getc(engine_state_t *E)
{
	if (E->sc_cmd_file != NULL)
		return (getc(E->sc_cmd_file));

	if (E->sc_cmd_flags & SC_CMD_EOF)
		return (EOF);

	if (E->sc_cmd_bufoff < E->sc_cmd_bufsz)
		return (*(E->sc_cmd_buf + E->sc_cmd_bufoff++));

	if (!(E->sc_cmd_flags & SC_CMD_IACTIVE)) {
		E->sc_cmd_flags |= SC_CMD_EOF;

		return (EOF);
	} else {
#ifdef NATIVE_BUILD
		return (EOF);
#else
		extern int parens;

		if (parens <= 0) {
			E->sc_cmd_flags |= SC_CMD_EOF;
			return (EOF);
		}

		for (;;) {
			E->sc_cmd_buf = gl_get_line(E->sc_gl, "> ", NULL, -1);
			if (E->sc_cmd_buf != NULL)
				break;

			switch (gl_return_status(E->sc_gl)) {
			case GLR_SIGNAL:
				gl_abandon_line(E->sc_gl);
				continue;

			case GLR_EOF:
				E->sc_cmd_flags |= SC_CMD_EOF;
				return (EOF);

			case GLR_ERROR:
				uu_die(gettext("Error reading terminal: %s.\n"),
				    gl_error_message(E->sc_gl, NULL, 0));
				/* NOTREACHED */

			default:
#ifndef NDEBUG
				(void) fprintf(stderr, "%s:%d: gl_get_line() "
				    "returned unexpected value %d.\n", __FILE__,
				    __LINE__, gl_return_status(E->sc_gl));
#endif
				abort();
			}
		}

		E->sc_cmd_bufsz = strlen(E->sc_cmd_buf);
		E->sc_cmd_bufoff = 1;

		return (E->sc_cmd_buf[0]);
#endif	/* NATIVE_BUILD */
	}
}

int
engine_cmd_ungetc(engine_state_t *E, char c)
{
	if (E->sc_cmd_file != NULL)
		return (ungetc(c, E->sc_cmd_file));

	if (E->sc_cmd_buf != NULL)
		*(E->sc_cmd_buf + --E->sc_cmd_bufoff) = c;

	return (c);
}

/*ARGSUSED*/
void
engine_cmd_nputs(engine_state_t *E, char *c, size_t n)
{
	/* our lexer shouldn't need this state */
	exit(11);
}

int
engine_exec(char *cmd)
{
	est->sc_cmd_buf = cmd;
	est->sc_cmd_bufsz = strlen(cmd) + 1;
	est->sc_cmd_bufoff = 0;

	(void) yyparse();

	return (0);
}

#ifndef NATIVE_BUILD
/* ARGSUSED */
static
CPL_CHECK_FN(check_xml)
{
	const char *ext;

	if (strlen(pathname) < 4)
		return (0);

	ext = pathname + strlen(pathname) - 4;

	return (strcmp(ext, ".xml") == 0 ? 1 : 0);
}

static const char * const whitespace = " \t";

static
CPL_MATCH_FN(complete_single_xml_file_arg)
{
	const char *arg1 = data;
	int arg1end_i, ret;
	CplFileConf *cfc;

	arg1end_i = arg1 + strcspn(arg1, whitespace) - line;
	if (arg1end_i < word_end)
		return (0);

	cfc = new_CplFileConf();
	if (cfc == NULL) {
		cpl_record_error(cpl, "Out of memory.");
		return (1);
	}

	cfc_set_check_fn(cfc, check_xml, NULL);

	ret = cpl_file_completions(cpl, cfc, line, word_end);

	(void) del_CplFileConf(cfc);
	return (ret);
}

static struct cmd_info {
	const char	*name;
	uint32_t	flags;
	CplMatchFn	*complete_args_f;
} cmds[] = {
	{ "validate", CS_GLOBAL, complete_single_xml_file_arg },
	{ "import", CS_GLOBAL, complete_single_xml_file_arg },
	{ "cleanup", CS_GLOBAL, NULL},
	{ "export", CS_GLOBAL, NULL },
	{ "archive", CS_GLOBAL, NULL },
	{ "apply", CS_GLOBAL, complete_single_xml_file_arg },
	{ "extract", CS_GLOBAL, NULL },
	{ "repository", CS_GLOBAL, NULL },
	{ "inventory", CS_GLOBAL, complete_single_xml_file_arg },
	{ "set", CS_GLOBAL, NULL },
	{ "end", CS_GLOBAL, NULL },
	{ "exit", CS_GLOBAL, NULL },
	{ "quit", CS_GLOBAL, NULL },
	{ "help", CS_GLOBAL, NULL },
	{ "delete", CS_GLOBAL, NULL },
	{ "select", CS_GLOBAL, complete_select },
	{ "unselect", CS_SVC | CS_INST | CS_SNAP, NULL },
	{ "list", CS_SCOPE | CS_SVC | CS_SNAP, NULL },
	{ "add", CS_SCOPE | CS_SVC, NULL },
	{ "listpg", CS_SVC | CS_INST | CS_SNAP, NULL },
	{ "addpg", CS_SVC | CS_INST, NULL },
	{ "delpg", CS_SVC | CS_INST, NULL },
	{ "delhash", CS_GLOBAL, complete_single_xml_file_arg },
	{ "listprop", CS_SVC | CS_INST | CS_SNAP, NULL },
	{ "setprop", CS_SVC | CS_INST, NULL },
	{ "delprop", CS_SVC | CS_INST, NULL },
	{ "editprop", CS_SVC | CS_INST, NULL },
	{ "describe", CS_SVC | CS_INST | CS_SNAP, NULL },
	{ "listsnap", CS_INST | CS_SNAP, NULL },
	{ "selectsnap", CS_INST | CS_SNAP, NULL },
	{ "revert", CS_INST | CS_SNAP, NULL },
	{ "refresh", CS_INST, NULL },
	{ NULL }
};

int
add_cmd_matches(WordCompletion *cpl, const char *line, int word_end,
    uint32_t scope)
{
	int word_start, err;
	size_t len;
	const char *bol;
	struct cmd_info *cip;

	word_start = strspn(line, whitespace);
	len = word_end - word_start;
	bol = line + word_end - len;

	for (cip = cmds; cip->name != NULL; ++cip) {
		if ((cip->flags & scope) == 0)
			continue;

		if (strncmp(cip->name, bol, len) == 0) {
			err = cpl_add_completion(cpl, line, word_start,
			    word_end, cip->name + len, "", " ");
			if (err != 0)
				return (err);
		}
	}

	return (0);
}

/*
 * Suggest completions.  We must first determine if the cursor is in command
 * position or in argument position.  If the former, complete_command() finds
 * matching commands.  If the latter, we tail-call the command-specific
 * argument-completion routine in the cmds table.
 */
/* ARGSUSED */
static
CPL_MATCH_FN(complete)
{
	const char *arg0, *arg1;
	size_t arg0len;
	struct cmd_info *cip;

	arg0 = line + strspn(line, whitespace);
	arg0len = strcspn(arg0, whitespace);
	if ((arg0 + arg0len) - line >= word_end ||
	    (arg0[arg0len] != ' ' && arg0[arg0len] != '\t'))
		return (complete_command(cpl, (void *)arg0, line, word_end));

	arg1 = arg0 + arg0len;
	arg1 += strspn(arg1, whitespace);

	for (cip = cmds; cip->name != NULL; ++cip) {
		if (strlen(cip->name) != arg0len)
			continue;

		if (strncmp(cip->name, arg0, arg0len) != 0)
			continue;

		if (cip->complete_args_f == NULL)
			break;

		return (cip->complete_args_f(cpl, (void *)arg1, line,
		    word_end));
	}

	return (0);
}
#endif	/* NATIVE_BUILD */

int
engine_interp()
{
#ifdef NATIVE_BUILD
	uu_die("native build does not support interactive mode.");
#else
	char *selfmri;
	size_t sfsz;
	int r;

	extern int parens;

	(void) sigset(SIGINT, SIG_IGN);

	est->sc_gl = new_GetLine(512, 8000);
	if (est->sc_gl == NULL)
		uu_die(gettext("Out of memory.\n"));

	/* The longest string is "[snapname]fmri[:instname]> ". */
	sfsz = 1 + max_scf_name_len + 1 + max_scf_fmri_len + 2 +
	    max_scf_name_len + 1 + 2 + 1;
	selfmri = safe_malloc(sfsz);

	r = gl_customize_completion(est->sc_gl, NULL, complete);
	assert(r == 0);

	for (;;) {
		lscf_get_selection_str(selfmri, sfsz - 2);
		(void) strcat(selfmri, "> ");
		est->sc_cmd_buf = gl_get_line(est->sc_gl, selfmri, NULL, -1);

		if (est->sc_cmd_buf == NULL) {
			switch (gl_return_status(est->sc_gl)) {
			case GLR_SIGNAL:
				gl_abandon_line(est->sc_gl);
				continue;

			case GLR_EOF:
				break;

			case GLR_ERROR:
				uu_die(gettext("Error reading terminal: %s.\n"),
				    gl_error_message(est->sc_gl, NULL, 0));
				/* NOTREACHED */

			default:
#ifndef NDEBUG
				(void) fprintf(stderr, "%s:%d: gl_get_line() "
				    "returned unexpected value %d.\n", __FILE__,
				    __LINE__, gl_return_status(est->sc_gl));
#endif
				abort();
			}

			break;
		}

		parens = 0;
		est->sc_cmd_bufsz = strlen(est->sc_cmd_buf);
		est->sc_cmd_bufoff = 0;
		est->sc_cmd_flags = SC_CMD_IACTIVE;

		(void) yyparse();
	}

	free(selfmri);
	est->sc_gl = del_GetLine(est->sc_gl);	/* returns NULL */

#endif	/* NATIVE_BUILD */
	return (0);
}

int
engine_source(const char *name, boolean_t dont_exit)
{
	engine_state_t *old = est;
	struct stat st;
	int ret;

	est = uu_zalloc(sizeof (engine_state_t));

	/* first, copy the stuff set up in engine_init */
	est->sc_repo_pid = old->sc_repo_pid;
	if (old->sc_repo_filename != NULL)
		est->sc_repo_filename = safe_strdup(old->sc_repo_filename);
	if (old->sc_repo_doordir != NULL)
		est->sc_repo_doordir = safe_strdup(old->sc_repo_doordir);
	if (old->sc_repo_doorname != NULL)
		est->sc_repo_doorname = safe_strdup(old->sc_repo_doorname);
	if (old->sc_repo_server != NULL)
		est->sc_repo_server = safe_strdup(old->sc_repo_server);

	/* set up the new guy */
	est->sc_cmd_lineno = 1;

	if (dont_exit)
		est->sc_cmd_flags |= SC_CMD_DONT_EXIT;

	if (strcmp(name, "-") == 0) {
		est->sc_cmd_file = stdin;
		est->sc_cmd_filename = "<stdin>";
	} else {
		errno = 0;
		est->sc_cmd_filename = name;
		est->sc_cmd_file = fopen(name, "r");
		if (est->sc_cmd_file == NULL) {
			if (errno == 0)
				semerr(gettext("No free stdio streams.\n"));
			else
				semerr(gettext("Could not open %s"), name);

			ret = -1;
			goto fail;
		}

		do {
			ret = fstat(fileno(est->sc_cmd_file), &st);
		} while (ret != 0 && errno == EINTR);
		if (ret != 0) {
			(void) fclose(est->sc_cmd_file);
			est->sc_cmd_file = NULL;	/* for semerr() */

			semerr(gettext("Could not stat %s"), name);

			ret = -1;
			goto fail;
		}

		if (!S_ISREG(st.st_mode)) {
			(void) fclose(est->sc_cmd_file);
			est->sc_cmd_file = NULL;	/* for semerr() */

			semerr(gettext("%s is not a regular file.\n"), name);

			ret = -1;
			goto fail;
		}
	}

	(void) yyparse();

	if (est->sc_cmd_file != stdin)
		(void) fclose(est->sc_cmd_file);

	ret = 0;

fail:
	if (est->sc_repo_pid != old->sc_repo_pid)
		lscf_cleanup();		/* clean up any new repository */

	if (est->sc_repo_filename != NULL)
		free((void *)est->sc_repo_filename);
	if (est->sc_repo_doordir != NULL)
		free((void *)est->sc_repo_doordir);
	if (est->sc_repo_doorname != NULL)
		free((void *)est->sc_repo_doorname);
	if (est->sc_repo_server != NULL)
		free((void *)est->sc_repo_server);
	free(est);

	est = old;

	return (ret);
}

/*
 * Initialize svccfg state.  We recognize four environment variables:
 *
 * SVCCFG_REPOSITORY	Create a private instance of svc.configd(1M) to answer
 *			requests for the specified repository file.
 * SVCCFG_DOOR_PATH	Directory for door creation.
 *
 * SVCCFG_DOOR		Rendezvous via an alternative repository door.
 *
 * SVCCFG_CONFIGD_PATH	Resolvable path to alternative svc.configd(1M) binary.
 */
void
engine_init()
{
	const char *cp;

	est = uu_zalloc(sizeof (engine_state_t));

	est->sc_cmd_lineno = 1;
	est->sc_repo_pid = -1;

	cp = getenv("SVCCFG_REPOSITORY");
	est->sc_repo_filename = cp ? safe_strdup(cp) : NULL;

	cp = getenv("SVCCFG_DOOR_PATH");
	est->sc_repo_doordir = cp ? cp : "/var/run";

	cp = getenv("SVCCFG_DOOR");
	if (cp != NULL) {
		if (est->sc_repo_filename != NULL) {
			uu_warn(gettext("SVCCFG_DOOR unused when "
			    "SVCCFG_REPOSITORY specified\n"));
		} else {
			est->sc_repo_doorname = safe_strdup(cp);
		}
	}

	cp = getenv("SVCCFG_CONFIGD_PATH");
	est->sc_repo_server = cp ? cp : "/lib/svc/bin/svc.configd";

	est->sc_miss_type = B_FALSE;
	est->sc_in_emi = 0;
	cp = getenv("SMF_FMRI");
	if ((cp != NULL) && (strcmp(cp, SCF_INSTANCE_EMI) == 0))
		est->sc_in_emi = 1;

	cp = smf_get_state(SCF_INSTANCE_FS_MINIMAL);
	if (cp && (strcmp(cp, SCF_STATE_STRING_ONLINE) == 0))
		est->sc_fs_minimal = B_TRUE;
	free((void *) cp);
}

static int
import_manifest_file(manifest_info_t *info, boolean_t validate, FILE *pout,
    uint_t flags)
{
	bundle_t *b;
	tmpl_errors_t *errs;
	const char *file;
	tmpl_validate_status_t vr;

	file = info->mi_path;

	/* Load the manifest */
	b = internal_bundle_new();

	if (lxml_get_bundle_file(b, file, SVCCFG_OP_IMPORT) != 0) {
		internal_bundle_free(b);
		return (-1);
	}

	/* Validate */
	if ((vr = tmpl_validate_bundle(b, &errs)) != TVS_SUCCESS) {
		char *prefix;

		if ((validate == 0) || (vr == TVS_WARN)) {
			prefix = gettext("Warning: ");
		} else {
			prefix = "";
		}
		tmpl_errors_print(stderr, errs, prefix);
		if (validate && (vr != TVS_WARN)) {
			tmpl_errors_destroy(errs);
			semerr(gettext("Import of %s failed.\n"),
			    info->mi_path);
			if (pout != NULL) {
				(void) fprintf(pout, gettext("WARNING: svccfg "
				    "import of %s failed.\n"), info->mi_path);
			}

			return (-1);
		}
	}
	tmpl_errors_destroy(errs);

	/* Import */
	if (lscf_bundle_import(b, file, flags) != 0) {
		internal_bundle_free(b);
		semerr(gettext("Import of %s failed.\n"), info->mi_path);
		if (pout != NULL) {
			(void) fprintf(pout, gettext("WARNING: svccfg import "
			    "of %s failed.\n"), info->mi_path);
		}
		return (-1);
	}

	internal_bundle_free(b);

	if (info->mi_prop) {
		char *errstr;

		if (mhash_store_entry(g_hndl, info->mi_prop, file,
		    info->mi_hash, APPLY_NONE, &errstr)) {
			if (errstr)
				semerr(gettext("Could not store hash for %s. "
				    "%s\n"), info->mi_path, errstr);
			else
				semerr(gettext("Unknown error from "
				    "mhash_store_entry() for %s\n"),
				    info->mi_path);
		}

	}

	return (0);
}

/*
 * Return values:
 *	1	No manifests need to be imported.
 *	0	Success
 *	-1	Error
 *	-2	Syntax error
 */
int
engine_import(uu_list_t *args)
{
	int argc, i, o;
	int dont_exit;
	int failed_manifests;
	int total_manifests;
	char *file;
	char **argv = NULL;
	string_list_t *slp;
	boolean_t validate = B_FALSE;
	uint_t flags = SCI_GENERALLAST;
	int dirarg = 0;
	int isdir;
	int rc = -1;
	struct stat sb;
	char **paths;
	manifest_info_t ***manifest_sets = NULL;
	manifest_info_t **manifests;
	char *progress_file = NULL;
	FILE *progress_out = NULL;
	int progress_count;
	int back_count;
	int count;
	int fm_flags;

	argc = uu_list_numnodes(args);
	if (argc < 1)
		return (-2);

	argv = calloc(argc + 1, sizeof (char *));
	if (argv == NULL)
		uu_die(gettext("Out of memory.\n"));

	for (slp = uu_list_first(args), i = 0;
	    slp != NULL;
	    slp = uu_list_next(args, slp), ++i)
		argv[i] = slp->str;

	argv[i] = NULL;

	opterr = 0;
	optind = 0;				/* Remember, no argv[0]. */
	for (;;) {
		o = getopt(argc, argv, "np:V");
		if (o == -1)
			break;

		switch (o) {
		case 'n':
			flags |= SCI_NOREFRESH;
			break;

		case 'p':
			progress_file = optarg;
			break;

		case 'V':
			validate = B_TRUE;
			break;

		case '?':
			free(argv);
			return (-2);

		default:
			bad_error("getopt", o);
		}
	}

	argc -= optind;
	if (argc < 1) {
		free(argv);
		return (-2);
	}

	/* Open device for progress messages */
	if (progress_file != NULL) {
		if (strcmp(progress_file, "-") == 0) {
			progress_out = stdout;
		} else {
			progress_out = fopen(progress_file, "w");
			if (progress_out == NULL) {
				semerr(gettext("Unable to open %s for "
				    "progress reporting.  %s\n"),
				    progress_file, strerror(errno));
				goto out;
			}
			setbuf(progress_out, NULL);
		}
	}

	paths = argv+optind;
	manifest_sets = safe_malloc(argc * sizeof (*manifest_sets));

	/* If we're in interactive mode, force strict validation. */
	if (est->sc_cmd_flags & SC_CMD_IACTIVE)
		validate = B_TRUE;

	lscf_prep_hndl();

	/* Determine which manifests must be imported. */

	total_manifests = 0;
	for (i = 0; i < argc; i++) {
		file = *(paths + i);
		fm_flags = CHECKHASH;

		/* Determine if argument is a directory or file. */
		if (stat(file, &sb) == -1) {
			semerr(gettext("Unable to stat file %s.  %s\n"), file,
			    strerror(errno));
			goto out;
		}
		if (sb.st_mode & S_IFDIR) {
			fm_flags |= CHECKEXT;
			dirarg = 1;
			isdir = 1;
		} else if (sb.st_mode & S_IFREG) {
			isdir = 0;
		} else {
			semerr(gettext("%s is not a directory or regular "
			    "file\n"), file);
			goto out;
		}

		/* Get list of manifests that we should import for this path. */
		if ((count = find_manifests(g_hndl, file, &manifests,
		    fm_flags)) < 0) {
			if (isdir) {
				semerr(gettext("Could not hash directory %s\n"),
				    file);
			} else {
				semerr(gettext("Could not hash file %s\n"),
				    file);
			}
			free_manifest_array(manifests);
			goto out;
		}
		total_manifests += count;
		manifest_sets[i] = manifests;
	}

	if (total_manifests == 0) {
		/* No manifests to process. */
		if (g_verbose) {
			warn(gettext("No changes were necessary\n"));
		}
		rc = 1;
		goto out;
	}

	/*
	 * If we're processing more than one file, we don't want to exit if
	 * we encounter an error.  We should go ahead and process all of
	 * the manifests.
	 */
	dont_exit = est->sc_cmd_flags & SC_CMD_DONT_EXIT;
	if (total_manifests > 1)
		est->sc_cmd_flags |= SC_CMD_DONT_EXIT;

	if (progress_out != NULL)
		(void) fprintf(progress_out,
		    "Loading smf(5) service descriptions: ");

	failed_manifests = 0;
	progress_count = 0;
	for (i = 0; i < argc; i++) {
		manifests = manifest_sets[i];
		if (manifests == NULL)
			continue;
		for (; *manifests != NULL; manifests++) {
			progress_count++;
			if (progress_out != NULL) {
				back_count = fprintf(progress_out, "%d/%d",
				    progress_count, total_manifests);
				while (back_count-- > 0) {
					(void) fputc('\b', progress_out);
				}
			}
			if (import_manifest_file(*manifests, validate,
			    progress_out, flags) != 0) {
				failed_manifests++;
			}
		}
	}
	if (progress_out != NULL)
		(void) fputc('\n', progress_out);

	if ((total_manifests > 1) && (dont_exit == 0))
		est->sc_cmd_flags &= ~SC_CMD_DONT_EXIT;

	if (dirarg && total_manifests > 0) {
		char *msg;

		msg = "Loaded %d smf(5) service descriptions\n";
		warn(gettext(msg), progress_count);

		if (failed_manifests) {
			msg = "%d smf(5) service descriptions failed to load\n";
			warn(gettext(msg), failed_manifests);
		}
	}

	if (failed_manifests > 0)
		goto out;

	if (g_verbose)
		warn(gettext("Successful import.\n"));
	rc = 0;

out:
	if ((progress_out != NULL) && (progress_out != stdout))
		(void) fclose(progress_out);
	free(argv);
	if (manifest_sets != NULL) {
		for (i = 0; i < argc; i++) {
			free_manifest_array(manifest_sets[i]);
		}
		free(manifest_sets);
	}
	return (rc);
}

/*
 * Walk each service and get its manifest file.
 *
 * If the file exists check instance support, and cleanup any
 * stale instances.
 *
 * If the file doesn't exist tear down the service and/or instances
 * that are no longer supported by files.
 */
int
engine_cleanup(int flags)
{
	boolean_t		activity = B_TRUE;
	int			dont_exit;
	int			r = -1;

	lscf_prep_hndl();

	if (flags == 1) {
		activity = B_FALSE;
	}

	dont_exit = est->sc_cmd_flags & SC_CMD_DONT_EXIT;
	est->sc_cmd_flags |= SC_CMD_DONT_EXIT;

	if (scf_walk_fmri(g_hndl, 0, NULL, SCF_WALK_SERVICE|SCF_WALK_NOINSTANCE,
	    lscf_service_cleanup, (void *)activity, NULL,
	    uu_warn) == SCF_SUCCESS)
		r = 0;

	if (dont_exit == 0)
		est->sc_cmd_flags &= ~SC_CMD_DONT_EXIT;

	(void) lscf_hash_cleanup();

	return (r);
}

static int
apply_profile(manifest_info_t *info, int apply_changes)
{
	bundle_t *b = internal_bundle_new();

	if (lxml_get_bundle_file(b, info->mi_path, SVCCFG_OP_APPLY) != 0) {
		internal_bundle_free(b);
		return (-1);
	}

	if (!apply_changes) {	/* we don't want to apply, just test */
		internal_bundle_free(b);
		return (0);
	}

	if (lscf_bundle_apply(b, info->mi_path) != 0) {
		internal_bundle_free(b);
		return (-1);
	}

	internal_bundle_free(b);

	if (info->mi_prop) {
		apply_action_t apply;
		char *errstr;

		apply = (est->sc_in_emi == 1) ? APPLY_LATE : APPLY_NONE;
		if (mhash_store_entry(g_hndl, info->mi_prop, info->mi_path,
		    info->mi_hash, apply, &errstr)) {
			semerr(errstr);
		}
	}

	return (0);
}

int
engine_apply(const char *file, int apply_changes)
{
	int rc = 0;
	int isdir;
	int dont_exit;
	int profile_count;
	int fm_flags;
	struct stat sb;
	manifest_info_t **profiles = NULL;
	manifest_info_t **entry;
	manifest_info_t *pfile;

	lscf_prep_hndl();

	/* Determine which profile(s) must be applied. */

	profile_count = 0;
	fm_flags = BUNDLE_PROF | CHECKHASH;

	/* Determine if argument is a directory or file. */
	if (stat(file, &sb) == -1) {
		semerr(gettext("Unable to stat file %s.  %s\n"), file,
		    strerror(errno));
		rc = -1;
		goto out;
	}

	if (sb.st_mode & S_IFDIR) {
		fm_flags |= CHECKEXT;
		isdir = 1;
	} else if (sb.st_mode & S_IFREG) {
		isdir = 0;
	} else {
		semerr(gettext("%s is not a directory or regular "
		    "file\n"), file);
		rc = -1;
		goto out;
	}

	/* Get list of profiles to be applied. */
	if ((profile_count = find_manifests(g_hndl, file, &profiles,
	    fm_flags)) < 0) {

		if (isdir) {
			semerr(gettext("Could not hash directory %s\n"), file);
		} else {
			semerr(gettext("Could not hash file %s\n"), file);
		}
		rc = -1;
		goto out;
	}

	if (profile_count == 0) {
		/* No profiles to process. */
		if (g_verbose) {
			warn(gettext("No changes were necessary\n"));
		}
		goto out;
	}

	/*
	 * We don't want to exit if we encounter an error.  We should go ahead
	 * and process all of the profiles.
	 */
	dont_exit = est->sc_cmd_flags & SC_CMD_DONT_EXIT;
	est->sc_cmd_flags |= SC_CMD_DONT_EXIT;

	for (entry = profiles; *entry != NULL; entry++) {
		pfile = *entry;

		if (apply_profile(pfile, apply_changes) == 0) {
			if (g_verbose) {
				warn(gettext("Successfully applied: %s\n"),
				    pfile->mi_path);
			}
		} else {
			warn(gettext("WARNING: Failed to apply %s\n"),
			    pfile->mi_path);
			rc = -1;
		}
	}

	if (dont_exit == 0)
		est->sc_cmd_flags &= ~SC_CMD_DONT_EXIT;

	/* exit(1) appropriately if any profile failed to be applied. */
	if ((rc == -1) &&
	    (est->sc_cmd_flags & (SC_CMD_IACTIVE | SC_CMD_DONT_EXIT)) == 0) {
		free_manifest_array(profiles);
		exit(1);
	}

out:
	free_manifest_array(profiles);
	return (rc);
}

int
engine_restore(const char *file)
{
	bundle_t *b;

	lscf_prep_hndl();

	b = internal_bundle_new();

	if (lxml_get_bundle_file(b, file, SVCCFG_OP_RESTORE) != 0) {
		internal_bundle_free(b);
		return (-1);
	}

	if (lscf_bundle_import(b, file, SCI_NOSNAP) != 0) {
		internal_bundle_free(b);
		return (-1);
	}

	internal_bundle_free(b);

	return (0);
}

int
engine_set(uu_list_t *args)
{
	uu_list_walk_t *walk;
	string_list_t *slp;

	if (uu_list_first(args) == NULL) {
		/* Display current options. */
		if (!g_verbose)
			(void) fputs("no", stdout);
		(void) puts("verbose");

		return (0);
	}

	walk = uu_list_walk_start(args, UU_DEFAULT);
	if (walk == NULL)
		uu_die(gettext("Couldn't read arguments"));

	/* Use getopt? */
	for (slp = uu_list_walk_next(walk);
	    slp != NULL;
	    slp = uu_list_walk_next(walk)) {
		if (slp->str[0] == '-') {
			char *op;

			for (op = &slp->str[1]; *op != '\0'; ++op) {
				switch (*op) {
				case 'v':
					g_verbose = 1;
					break;

				case 'V':
					g_verbose = 0;
					break;

				default:
					warn(gettext("Unknown option -%c.\n"),
					    *op);
				}
			}
		} else {
			warn(gettext("No non-flag arguments defined.\n"));
		}
	}

	return (0);
}

void
help(int com)
{
	int i;

	if (com == 0) {
		warn(gettext("General commands:	 help set repository end\n"
		    "Manifest commands:	 inventory validate import export "
		    "archive\n"
		    "Profile commands:	 apply extract\n"
		    "Entity commands:	 list select unselect add delete "
		    "describe\n"
		    "Snapshot commands:	 listsnap selectsnap revert\n"
		    "Instance commands:	 refresh\n"
		    "Property group commands: listpg addpg delpg\n"
		    "Property commands:	 listprop setprop delprop editprop\n"
		    "Property value commands: addpropvalue delpropvalue "
		    "setenv unsetenv\n"
		    "Notification parameters: "
		    "listnotify setnotify delnotify\n"));
		return;
	}

	for (i = 0; help_messages[i].message != NULL; ++i) {
		if (help_messages[i].token == com) {
			warn(gettext("Usage: %s\n"),
			    gettext(help_messages[i].message));
			return;
		}
	}

	warn(gettext("Unknown command.\n"));
}
