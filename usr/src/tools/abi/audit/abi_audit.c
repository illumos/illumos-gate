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

#include "abi_audit.h"
#include <time.h>

/* to be used by sequence_t data structure */
#define	PUBLIC		1
#define	PRIVATE		2
#define	UNEXPORTED	3

/* Global variables */
FILE		*Db = stdout;
FILE		*Msgout = stdout;
char		*program;
int		Debug = 0;		/* Debug initialized to zero */
int		Total_relcnt = 0;	/* Total_relcnt is initialized to 0 */
int		iflag;
rellist_t	*Rel;
tree_t		*Sym_List = NULL;

/* local variables */
static int	Num_abi_dirs = 0;	/* # of abi_dirs read in */
static int	Tflag;
static int	gflag;
static int	lflag;
static int	nflag;
static int	oflag;
static int	pflag;
static int	sflag;
static int	tflag;
static list_t	*lib_list = NULL;
static list_t	*removed_lib_list = NULL;
static list_t	*actual_libs_pool = NULL;

/* tmp abi_audit output files */

static char	*Reference_Db = "/opt/onbld/etc/abi/ABI_sparc.db"; /* default */
static list_t	*Abi_Dir;		/* abi_dirs at command line */

/* Internal functions */
static int		add_release(char *, int);
static int		analyze_args(int, char **);
static int		last_transition(liblist_t *);
static int		load_db(FILE *);
static int		load_liblog(void);
static int		proc_intf_check_dir(char *);
static int		process_abi_dirs(void);
static int		process_db_options(void);
static int		read_intf_check_file(char *, int);
static int		skip_line(char *);
static scenario_t	detect_sequence(sequence_t *, liblist_t *);
static scenario_t	sequence_match(liblist_t *, int);
static sequence_t	*generate_sequence(sequence_t *, bvlist_t *,
			liblist_t *);
static void		add_copyright_and_release(FILE *);
static void		cleanup(void);
static void		decode_filename(char *);
static void		detect_errors(symbol_t *, FILE *);
static void		libc_migration(liblist_t **);
static void		perform_dis_check_list(liblist_t *);
static void		perform_id_check(tree_t *, int);
static void		perform_int_check_list(liblist_t *);
static void		print_usage(char *);
static void		process_unexported(tree_t *, int);
static void		process_unexported_list(liblist_t *, int);
static void		report_err_msg(char *, symbol_t *, FILE *);
static void		report_errors(tree_t *);

int
main(int argc, char *argv[])
{
	int		i = 0;
	list_t		*loc;

	/* process arguments and set up tmp files */
	if ((analyze_args(argc, argv) == FAIL) ||
	    (process_db_options() == FAIL) ||
	    (process_abi_dirs() == FAIL)) {
		cleanup();
		return (1);
	}

	/*
	 * After loading ABI information from ABI_*.db and the abi_dir(s),
	 * identify all symbols which have disappeared in later releases
	 */
	while (i < Total_relcnt)
		process_unexported(Sym_List, ++ i);

	/* in analyze args, we've ensured that Total_relcnt >= 2 */
	if (Total_relcnt < 2) {
		(void) fprintf(stderr,
		    "%s: Need to compare between 2 or more releases\n",
		    program);
		cleanup();
		return (1);
	}

	if (!gflag) {
		/* perform discrepancy or integrity checking */
		perform_id_check(Sym_List, iflag);
		/* perform version checking */
		version_checker(Sym_List);
		/* print errors to stdout */
		report_errors(Sym_List);
		/* print out removed libs */
		if (oflag) {
			loc = removed_lib_list;
			while (loc) {
				fprintf(Msgout,
				    "WARNING: %s: library is not found\n",
				    loc->lt_name);
				loc = loc->lt_next;
			}
		}
	} else {
		/* print symbol info to file */
		add_copyright_and_release(Db);
		tree_traverse(Sym_List);
	}

	return (0);
}

/*
 * Print Usage information
 */

static void
print_usage(char *prog)
{
	(void) fprintf(stderr, "\nUsage: %s [-iostpT] [-f log_file]"
	    "[-g ABI_DB_filename] \n\t[-l | -n ABI_DB_filename] "
	    "abi_dir, ...\n\n", prog);
}

/*
 * Analyze the command line arguments
 */

static int
analyze_args(int argc, char *argv[])
{
	int		option;
	struct stat	stbuf;
	int		errflag = 0;
	int		count = 0;
	list_t		*new_Abi_Dir;
	list_t		*end_Abi_Dir;

	program = basename(argv[0]);

	while ((option = getopt(argc, argv, "f:hiostTg:lpn:")) != EOF) {
		switch (option) {
			case 'f': /* output file to append to */
				if ((Msgout = fopen(optarg, "ab")) == NULL) {
					(void) fprintf(stderr, "%s: fopen "
					    "failed to open <%s>: %s\n",
					    program, optarg, strerror(errno));
					return (FAIL);
				}
				break;
			case 'o': /* check for omissions */
				oflag ++;
				break;
			case 'i': /* perform integrity check */
				iflag ++;
				break;
			case 't': /* check for private->public transition */
				tflag ++;
				break;
			case 'T': /* check for private->unexported transition */
				Tflag ++;
				break;
			case 's': /* silent the WARNINGs */
				sflag ++;
				break;
			case 'g': /* to generate ABI database */
				if ((Db = fopen(optarg, "w")) == NULL) {
					(void) fprintf(stderr,
					"%s: fopen failed to open <%s>: %s\n",
					    program, optarg, strerror(errno));
					return (FAIL);
				}
				gflag ++;
				break;
			case 'l': /* provide old intf_check output */
				lflag ++;
				break;
			case 'p': /* report new public interfaces */
				pflag ++;
				break;
			case 'n': /* to load user's own ABI database */
				nflag ++;
				Reference_Db = optarg;
				break;
			case 'h':
				errflag ++;
				break;
			case '?':
				errflag ++;
				break;
			default:
				errflag ++;
				break;
		} /* end switch */
	} /* end while */

	if (nflag && lflag) {
		(void) fprintf(stderr,
		    "%s: the -n and -l options are mutually exclusive\n",
		    program);
		errflag ++;
	}

	/* check that at least 2 abi_dirs are listed with the -p option on */
	if (lflag && ((argc - optind) < 2)) {
		(void) fprintf(stderr,
		    "%s: -l requires at least two abi_dirs to be listed\n",
		    program);
		errflag ++;
	}

	/* -s option overrides -p option */
	if (sflag && pflag) {
		pflag = 0;
	}

	if (errflag || optind >= argc) {
		print_usage(program);
		return (FAIL);
	}

	/*
	 * Record number of abi_dirs specified on the command line.
	 */
	Num_abi_dirs = argc - optind;

	/* Collect all the abi_dirs listed on the command line */
	for (count = 0; (optind < argc); optind ++, count ++) {
		if ((new_Abi_Dir = calloc(1, sizeof (list_t))) == NULL) {
			(void) fprintf(stderr,
			    "%s: analyze_args: calloc: new_Abi_Dir: %s\n",
			    program, strerror(errno));
			return (FAIL);
		}
		new_Abi_Dir->lt_name = argv[optind];

		/* make sure Abi_Dir->lt_name is a directory */
		if ((stat(new_Abi_Dir->lt_name, &stbuf) == -1) ||
		    ((stbuf.st_mode & S_IFMT) != S_IFDIR)) {
			(void) fprintf(stderr, "%s: %s: %s: No such directory. "
			    "Please Try Again.\n",
			    program, new_Abi_Dir->lt_name, strerror(errno));
			return (FAIL);
		}

		/* Attach new directory to end of linked list */
		if (Abi_Dir == NULL) {
			Abi_Dir = new_Abi_Dir;
			end_Abi_Dir = new_Abi_Dir;
		} else {
			end_Abi_Dir->lt_next = new_Abi_Dir;
			end_Abi_Dir = new_Abi_Dir;
		}
	}
	return (SUCCEED);
}

/*
 * Filters through -l flag to determine Num_abi_dirs
 * and whether to load an Abi reference database.
 */

static int
process_db_options(void)
{
	FILE	*ref_db;

	if (lflag) {
		/* do not load ABI_*.db */
		Total_relcnt = Num_abi_dirs;
	} else {
		if (load_liblog() == FAIL)
			return (FAIL);
		if ((ref_db = fopen(Reference_Db, "rb")) == NULL) {
			(void) fprintf(stderr,
			    "%s: fopen failed to open <%s> : %s\n",
			    program, Reference_Db, strerror(errno));
			return (FAIL);
		}
		if (load_db(ref_db) == FAIL) {
			(void) fprintf(stderr, "%s: load_db %s failed\n",
			    program, Reference_Db);
			return (FAIL);
		}
		(void) fclose(ref_db);
	}
	return (SUCCEED);
}

/*
 * Add the release name info to the linked list of releases. If release
 * is already found in the Rel of rellist_t type, then return FAIL.
 */

static int
add_release(char *release, int count)
{
	int	i;

	/* check to make sure we have enough rellist_t allocated */
	if (add_rellist(count) == FAIL) {
		return (FAIL);
	}

	for (i = 0; i < count; i ++) {

		/* found an empty slot for the release name */
		if (get_rel_name(i) == NULL) {
			assign_rel_name(release, i);
			break;
		}

		/* this release is a dup entry in the Rel[] array */
		if (strcmp(release, get_rel_name(i)) == 0) {
			(void) fprintf(stderr,
			    "%s: Error: Loading duplicate abi_dir %s\n",
			    program, release);
			return (FAIL);
		}
	}
	return (i);
}

/*
 * Routine to load the Solaris FCS ABI (Reference_Db)
 */

static int
load_db(FILE *fp)
{
	char		line[MAXPATHLEN];
	char		*releases;
	int		length = 0;
	symbol_t	*sym;
	liblist_t	*lib;
	category_t	*cat;
	int		rel_num, i;
	int		Num_db_releases;
	char		db_sym_name[MAXPATHLEN];
	char		db_lib_name[MAXPATHLEN];
	char		db_type[32];
	char		db_size[32];
	char		db_lib_version[RELMAX];
	char		db_sym_version[RELMAX];
	char		*db_release;
	char		*db_public;
	char		*db_private;
	char		*db_unexported;
	char		*db_scoped;
	char		*db_evolving;
	char		*db_obsolete;
	char		*db_unclassified;

	Num_db_releases = 0;

	/* process releases in database file */
	line[0] = '\0';
	while (fgets(line, MAXPATHLEN, fp) != NULL) {
		if (strstr(line, "#Releases:") == 0)
			continue;
		else
			break;
	}
	(void) fseek(fp, ftell(fp) - strlen(line), SEEK_SET);
	while (fgetc(fp) != '\n') {
		length ++;
	}
	length ++;
	if ((releases = calloc(1, length)) == NULL) {
		(void) fprintf(stderr,
		    "%s: load_db: calloc: releases: %s\n",
		    program, strerror(errno));
		return (FAIL);
	}
	(void) rewind(fp);
	while (fgets(releases, length, fp) != NULL) {
		const char	key[] = "#Releases:";
		char		*tok, *del = ",";
		if ((tok = strstr(releases, key)) == 0)
			continue;

		tok += sizeof (key) - 1;
		if ((tok = strtok(tok, del)) != 0) {
			do {
				/* adding a release */
				Num_db_releases ++;
				if (add_release(trimmer(tok),
				    Num_db_releases) == FAIL) {
					return (FAIL);
				}
			} while (tok = strtok(NULL, del));
			break;
		}
	}

	free(releases);

	/*
	 * Now, the total # of release = # of releases in database file plus
	 * the # of abi_dirs read in at the command line
	 */
	Total_relcnt = Num_db_releases + Num_abi_dirs;

	/* An assertion: the ref database contains a valid "#Releases:" line */
	if (Total_relcnt < 2) {
		(void) fprintf(stderr,
		    "%s: Need to compare between 2 or more releases\n",
		    program);
		return (FAIL);
	}

	rel_num = Num_db_releases - 1;

	/* allocates necessary spaces for the following variables */
	if (((db_release = calloc(1, Total_relcnt + 1)) == NULL) ||
	    ((db_public = calloc(1, Total_relcnt + 1)) == NULL) ||
	    ((db_private = calloc(1, Total_relcnt + 1)) == NULL) ||
	    ((db_unexported = calloc(1, Total_relcnt + 1)) == NULL) ||
	    ((db_scoped = calloc(1, Total_relcnt + 1)) == NULL) ||
	    ((db_evolving = calloc(1, Total_relcnt + 1)) == NULL) ||
	    ((db_obsolete = calloc(1, Total_relcnt + 1)) == NULL) ||
	    ((db_unclassified = calloc(1, Total_relcnt + 1)) == NULL)) {
		(void) fprintf(stderr,
		    "%s: load_db: calloc: db_*: %s\n",
		    program, strerror(errno));
		return (FAIL);
	}

	while (!feof(fp)) {
		if (((sym = calloc(1, sizeof (symbol_t))) == NULL) ||
		    ((lib = calloc(1, sizeof (liblist_t))) == NULL) ||
		    ((cat = calloc(1, sizeof (category_t))) == NULL)) {
			(void) fprintf(stderr,
			    "%s: load_db: calloc: tree_node: %s\n",
			    program, strerror(errno));
			return (FAIL);
		}

		/* get symbol name, library name, data type and data size */
		db_sym_name[0] = '\0';
		db_lib_name[0] = '\0';
		db_size[0] = '\0';
		db_type[0] = '\0';
		if (fscanf(fp, "%s %s %s %s ",
		    db_sym_name, db_lib_name, db_type, db_size) != 4) {
			(void) fprintf(stderr, "%s: load_db: fscanf(1) : %s\n",
			    program, strerror(errno));
			return (FAIL);
		}

		/*
		 * Load versioning info for releases specified in the
		 * Reference_Db
		 */

		if (add_verlist(lib, Total_relcnt) == FAIL) {
			return (FAIL);
		}

		/* get library version and symbol version names */
		for (i = 0; i < Num_db_releases; i ++) {
			db_lib_version[0] = '\0';
			db_sym_version[0] = '\0';
			if (fscanf(fp, "%s %s ", db_lib_version,
			    db_sym_version) != 2) {
				(void) fprintf(stderr,
				    "%s: load_db: fscanf(2) : %s\n",
				    program, strerror(errno));
				return (FAIL);
			}
			if (strcmp(db_lib_version, "0") != 0)
				assign_lib_ver(lib, db_lib_version, i);
			else
				assign_lib_ver(lib, NULL, i);
			if (strcmp(db_sym_version, "0") != 0)
				assign_sym_ver(lib, db_sym_version, i);
			else
				assign_sym_ver(lib, NULL, i);
		}

		/* Get category info */
		(void) memset(db_release, 0, Total_relcnt + 1);
		(void) memset(db_public, 0, Total_relcnt + 1);
		(void) memset(db_private, 0, Total_relcnt + 1);
		(void) memset(db_unexported, 0, Total_relcnt + 1);
		(void) memset(db_scoped, 0, Total_relcnt + 1);
		(void) memset(db_evolving, 0, Total_relcnt + 1);
		(void) memset(db_obsolete, 0, Total_relcnt + 1);
		(void) memset(db_unclassified, 0, Total_relcnt + 1);
		if (fscanf(fp, "%s %s %s %s %s %s %s %s\n", db_release,
		    db_public, db_private, db_unexported, db_scoped,
		    db_evolving, db_obsolete, db_unclassified) != 8) {
			(void) fprintf(stderr, "%s: load_db: fscanf(3) : %s\n",
			    program, strerror(errno));
			return (FAIL);
		}

		/* Initialize info for release specified on the command line */
		/* At this point, Total_relcnt=Num_db_releases+Num_abi_dirs */
		for (i = Num_db_releases; i < Total_relcnt; i ++) {

			/* initialize versioning info */
			assign_lib_ver(lib, NULL, i);
			assign_sym_ver(lib, NULL, i);

			/* initialize categories */
			(void) strncat(db_release, "1", 1);
			(void) strncat(db_public, "0", 1);
			(void) strncat(db_private, "0", 1);
			(void) strncat(db_unexported, "0", 1);
			(void) strncat(db_scoped, "0", 1);
			(void) strncat(db_evolving, "0", 1);
			(void) strncat(db_obsolete, "0", 1);
			(void) strncat(db_unclassified, "0", 1);
		}

		/* symbol assignments */
		sym->st_sym_name = strdup(db_sym_name);
		if (!sym->st_sym_name) {
			(void) fprintf(stderr,
			    "%s: load_db: strdup: sym->st_sym_name: %s\n",
			    program, strerror(errno));
			return (FAIL);
		}
		sym->st_type = atoi(db_type);
		sym->st_size = atoi(db_size);

		/* library assignments */
		lib->lt_lib_name = strdup(db_lib_name);
		if (!lib->lt_lib_name) {
			(void) fprintf(stderr,
			    "%s: load_db: strdup: lib->lt_lib_name: %s\n",
			    program, strerror(errno));
			return (FAIL);
		}
		lib->lt_release = stobv(db_release, Total_relcnt);
		lib->lt_trans_bits = create_bv_list(Total_relcnt);

		/* category assignments */
		cat->ct_public = stobv(db_public, Total_relcnt);
		cat->ct_private = stobv(db_private, Total_relcnt);
		cat->ct_unexported =
		    stobv(db_unexported, Total_relcnt);
		cat->ct_scoped = stobv(db_scoped, Total_relcnt);
		cat->ct_evolving = stobv(db_evolving, Total_relcnt);
		cat->ct_obsolete = stobv(db_obsolete, Total_relcnt);
		cat->ct_unclassified =
		    stobv(db_unclassified, Total_relcnt);

		if (oflag) {
			/*
			 * if checks for omission, make sure this library
			 * still exists under current test directory.  If
			 * yes, checks for any symbol disappears illegally.
			 * If not, make sure the symbol isn't unexported
			 * in previous release.  In that case, add the library
			 * onto the removed library linked list.
			 */
			if (check_lib_info(actual_libs_pool,
			    lib->lt_lib_name) == TRUE) {
				lib->lt_check_me = TRUE;
			} else {
				lib->lt_check_me = FALSE;
				if (bv_all_zero(cat->ct_unexported) == TRUE) {
					removed_lib_list =
					    store_lib_info(removed_lib_list,
					    lib->lt_lib_name);
				}
			}
		} else {
			/* We need to check throughout the list of libs */
			lib->lt_check_me = FALSE;
		}
		lib->lt_next = NULL;

		/* build tree node and insert symbol info into Sym_List */
		if (add_symbol(sym, lib, cat, rel_num) == FAIL)
			return (FAIL);
	}

	free(db_release);
	free(db_public);
	free(db_private);
	free(db_unexported);
	free(db_scoped);
	free(db_evolving);
	free(db_obsolete);
	free(db_unclassified);

	return (SUCCEED);
}

/*
 * Process the intf_check output for each of the abi_dirs listed on the
 * command line
 */

static int
process_abi_dirs(void)
{
	list_t		*tmp_Abi_Dir;
	rellist_t	*Rel_ptr;
	int		num_nodes;
	int		i, j;

	num_nodes = find_num_nodes(Total_relcnt);

	/*
	 * create Rel linked list and assign the proper release bitmask
	 * to reference each release.
	 */
	if (!Rel) {
		Rel = calloc(1, sizeof (rellist_t));
	}

	Rel_ptr = Rel;
	for (i = 0; i < (num_nodes - 1); i ++) {
		for (j = 0; j < RELMAX; j ++) {
			Rel_ptr->rt_release[j].rt_rel_bitmask = 1;
			Rel_ptr->rt_release[j].rt_rel_bitmask =
			    Rel_ptr->rt_release[j].rt_rel_bitmask
			    << (RELMAX - 1 - j);
		}
		if (!Rel_ptr->rt_next) {
			Rel_ptr->rt_next = calloc(1, sizeof (rellist_t));
		}
		Rel_ptr = Rel_ptr->rt_next;
	}
	for (j = 0; j < (Total_relcnt % RELMAX); j ++) {
		Rel_ptr->rt_release[j].rt_rel_bitmask = 1;
		Rel_ptr->rt_release[j].rt_rel_bitmask =
		    Rel_ptr->rt_release[j].rt_rel_bitmask
		    << (RELMAX - 1 - j);
	}
	Rel_ptr = NULL;

	tmp_Abi_Dir = Abi_Dir;
	/* Only process the abi_dirs passed in from the command line */
	for (i = 0; i < Num_abi_dirs && tmp_Abi_Dir != NULL; i ++) {
		if (proc_intf_check_dir(tmp_Abi_Dir->lt_name) == FAIL) {
			return (FAIL);
		}
		tmp_Abi_Dir = tmp_Abi_Dir->lt_next;
	}
	return (SUCCEED);
}

/*
 * Perform Discrepancy or Integrity Check on the AVL tree based on flag setting
 */

static void
perform_id_check(tree_t *rootptr, int flag)
{
	if (rootptr) {
		perform_id_check(rootptr->tt_left, flag);
		if (flag)
			perform_int_check_list(rootptr->tt_sym->st_lib);
		else
			perform_dis_check_list(rootptr->tt_sym->st_lib);

		libc_migration(&(rootptr->tt_sym->st_lib));
		perform_id_check(rootptr->tt_right, flag);
	}
}

/*
 * Process intf_check Directory
 */

static int
proc_intf_check_dir(char *intf_check_dir)
{
	DIR		*dirp;
	struct dirent	*dp;
	char		path[MAXPATHLEN];
	char		data_file[MAXPATHLEN];
	char		release[MAXPATHLEN];
	int		total_path_length;
	int		rel_flag = 0;
	int		dir_len;
	const char	*audit = "audit/";
	int		errmsg = SUCCEED;
	int		rel_index;

	dir_len = strlen(intf_check_dir);

	/* 5 ("audit") + 1 ("/") + 1 ("\0") + optionally 1 ("/") */
	total_path_length = dir_len + 7;
	if (*(intf_check_dir + dir_len - 1) != '/') {
		total_path_length ++;
	}
	if (total_path_length >= MAXPATHLEN) {
		(void) fprintf(stderr, "%s: %s: path name too long.\n",
		    program, intf_check_dir);
		return (FAIL);
	}

	/* Ensure intf_check_dir ends with a "/" char. */
	if (strlcpy(path, intf_check_dir, MAXPATHLEN) >= MAXPATHLEN) {
		(void) fprintf(stderr, "%s: proc_intf_check_dir: strlcpy: %s\n",
		    program, strerror(errno));
		return (FAIL);
	}

	if (*(intf_check_dir + dir_len - 1) != '/') {
		(void) strncat(path, "/", 1);
	}

	/* look for release string file */
	if ((dirp = opendir(intf_check_dir)) == NULL) {
		(void) fprintf(stderr,
		    "%s: %s: %s: No such directory. Please try again.\n",
		    program, path, strerror(errno));
		return (FAIL);
	}


	while ((dp = readdir(dirp)) != NULL) {

		/* Ensure the file specifying the release ends with ".rel" */
		if (strcmp((dp->d_name+strlen(dp->d_name)-4), ".rel") == 0) {
			if (rel_flag != 0) {
				(void) fprintf(stderr, "%s: Error: More than 1 "
				    "release file found under %s: %s, %s.\n",
				    program, intf_check_dir,
				    dp->d_name, release);
				errmsg = FAIL;
				break;
			}

			if (strlcpy(release, dp->d_name, MAXPATHLEN)
			    >= MAXPATHLEN) {
				(void) fprintf(stderr,
				    "%s: proc_intf_check_dir: strlcpy: %s\n",
				    program, strerror(errno));
				errmsg = FAIL;
				break;
			}
			/* null terminate release string to parse off ".rel" */
			release[strlen(dp->d_name) - 4] = '\0';

			/* command line processing of releases */
			if (release[0] == '\0') {
				(void) fprintf(stderr,
				    "%s: Error: No release is specified with "
				    ".rel file\n", program);
				errmsg = FAIL;
				break;
			}
			rel_flag ++;
		}
	}

	(void) closedir(dirp);

	if (errmsg == FAIL) {
		return (FAIL);
	}

	/*
	 * if no release file is found, then use the basename of intf_check
	 * dir as the release name
	 */
	if (rel_flag != 1) {
		if (strlcpy(release, basename(intf_check_dir), MAXPATHLEN) >=
		    MAXPATHLEN) {
			(void) fprintf(stderr,
			    "%s: proc_intf_check_dir: strlcpy: %s\n",
			    program, strerror(errno));
			return (FAIL);
		}
	}

	if ((rel_index = add_release(release, Total_relcnt)) == FAIL) {
		return (FAIL);
	}
	/* check for existence of audit/ directory in intf_check_dir */
	(void) strlcat(path, audit, MAXPATHLEN);

	if ((dirp = opendir(path)) == NULL) {
		(void) fprintf(stderr,
		    "%s: %s: %s: No such directory. Please try again.\n",
		    program, path, strerror(errno));
		return (FAIL);
	}

	/* Ready to process intf_check files located in the audit dir */
	while ((dp = readdir(dirp)) != NULL) {
		if ((strcmp(dp->d_name, ".") != 0) &&
		    (strcmp(dp->d_name, "..") != 0)) {
			(void) strlcpy(data_file, path, MAXPATHLEN);
			if (strlcat(data_file, dp->d_name, MAXPATHLEN)
			    >= MAXPATHLEN) {
				(void) fprintf(stderr,
				    "%s: proc_intf_check_dir: "
				    "strlcat: %s: %s\n",
				    program, dp->d_name, strerror(errno));
				errmsg = FAIL;
				break;
			}

			if (read_intf_check_file(data_file, rel_index)
			    == FAIL) {
				errmsg = FAIL;
				break;
			}
		}
	}
	(void) closedir(dirp);
	return (errmsg);
}

/*
 * Read and Process intf_check files
 */

static int
read_intf_check_file(char *intf_check_file, int rel_num)
{
	FILE		*fp;
	char		line[MAXPATHLEN];
	char		*filename;
	char		*symbolname;
	char		*symbolversion;
	symbol_t	*sym;
	category_t	*cat;
	liblist_t	*lib;
	bvlist_t	*release;

	if ((fp = fopen(intf_check_file, "r")) == NULL) {
		(void) fprintf(stderr, "%s: fopen failed to open <%s>: %s\n",
		    program, intf_check_file, strerror(errno));
		return (FAIL);
	}
	filename = basename(intf_check_file);

	decode_filename(filename);

	while (!feof(fp)) {
		line[0] = '\0';

		/*
		 * "line" will match one of the following patterns:
		 *	<symbol version>: <symbol name>
		 *	<symbol version>: <symbol name> <data size>
		 */
		if (fgets(line, MAXPATHLEN, fp) == NULL)
			break;
		if (skip_line(line) == SUCCEED)
			continue;

		/*
		 * If there is insufficient memory, the structs are not
		 * freed since this will result in an immediate fatal error
		 * upon returning FAIL to proc_intf_check_dir().
		 */
		if (((sym = calloc(1, sizeof (symbol_t))) == NULL) ||
		    ((lib = calloc(1, sizeof (liblist_t))) == NULL) ||
		    ((cat = calloc(1, sizeof (category_t))) == NULL)) {
			(void) fprintf(stderr,
			    "%s: read_intf_check_file: calloc: %s\n",
			    program, strerror(errno));
			(void) fclose(fp);
			return (FAIL);
		}

		/* Get the version info. */
		symbolversion = strtok(line, (const char *)":");

		release = get_rel_bitmask(rel_num);
		if (build_cat_bits(release, symbolversion, cat) == FAIL) {
			(void) fprintf(stderr,
			    "%s: read_intf_check_file: build_cat_bits: %s\n",
			    program, strerror(errno));
			free_bv_list(release);
			return (FAIL);
		}

		if (lflag) {
			if (add_verlist(lib, Total_relcnt) == FAIL)
				return (FAIL);
		}

		if (build_lib_tag(release, filename, symbolversion,
		    lib, rel_num) == FAIL) {
			(void) fprintf(stderr,
			    "%s: read_intf_check_file: build_lib_tag: %s\n",
			    program, strerror(errno));
			free_bv_list(release);
			return (FAIL);
		}
		if (!oflag)
			lib_list = store_lib_info(lib_list, lib->lt_lib_name);

		/* Get the symbol name */
		symbolname = strtok(NULL, (const char *)":");
		symbolname = trimmer(symbolname);
		build_sym_tag(symbolname, sym);

		/* Adds symbol to Sym_List */
		if (add_symbol(sym, lib, cat, rel_num) == FAIL)
			return (FAIL);
		free_bv_list(release);
	}
	(void) fclose(fp);

	return (SUCCEED);
}

/*
 * Returns the release where a classification transition is detected
 * e.g., public->private
 */

static int
last_transition(liblist_t *lib)
{
	int		release = 0;
	int		count = 0;
	bvlist_t	*bitmask;

	bitmask = get_rel_bitmask(0);

	while (count < Total_relcnt) {
		if (bv_and(bitmask, lib->lt_trans_bits) == TRUE)
			release = count;
		bitmask = bv_bitmask_rshift(bitmask);
		count ++;
	}
	free_bv_list(bitmask);
	return (release);
}

/*
 * Walk through the unique linked list, and check if symbol is migrated into
 * libc.so.1.  lt_libc_migrate will initialized to FALSE first.
 */

static void
libc_migration(liblist_t **lib)
{
	liblist_t	*p = *lib;
	liblist_t	*q;

	while (p) {
		if (((p->lt_scenario == SCENARIO_04) ||
		    (p->lt_scenario == SCENARIO_08) ||
		    (p->lt_scenario == SCENARIO_13) ||
		    (p->lt_scenario == SCENARIO_14)) &&
		    (bv_all_zero(p->lt_cat->ct_scoped) == TRUE) &&
		    (strstr(p->lt_lib_name, "libc.so.1") == NULL)) {
			q = *lib;
			p->lt_libc_migrate = FALSE;
			while (q) {
				if ((strstr(q->lt_lib_name,
				    "libc.so.1") != NULL) &&
				    ((q->lt_scenario == SCENARIO_01) ||
				    (q->lt_scenario == SCENARIO_02) ||
				    (q->lt_scenario == SCENARIO_07) ||
				    (q->lt_scenario == SCENARIO_05))) {
					p->lt_libc_migrate = TRUE;
					break;
				}
				q = q->lt_next;
			}
		}
		p = p->lt_next;
	}
}

/*
 * Perform Discrepancy Checking on the linked list
 */

void
perform_dis_check_list(liblist_t *lib)
{
	liblist_t	*p = lib;
	bvlist_t	*release;
	bvlist_t	*public;
	bvlist_t	*private;
	bvlist_t	*unexported;
	int		index = Total_relcnt - 1;	/* index always > 0 */
	bvlist_t	*prev_rel_bitmask = get_rel_bitmask(index - 1);
	bvlist_t	*curr_rel_bitmask = get_rel_bitmask(index);

	release = create_bv_list(Total_relcnt);
	public = create_bv_list(Total_relcnt);
	private = create_bv_list(Total_relcnt);
	unexported = create_bv_list(Total_relcnt);

	while (p) {
		bv_assign(release, p->lt_release);
		bv_assign(public, p->lt_cat->ct_public);
		bv_assign(private, p->lt_cat->ct_private);
		bv_assign(unexported, p->lt_cat->ct_unexported);

		/*
		 * #1, a new public symbol
		 * is introduced
		 */
		if ((bv_compare(release, curr_rel_bitmask) == TRUE) &&
		    (bv_compare(public, release) == TRUE) &&
		    (bv_all_zero(private) == TRUE) &&
		    (bv_all_zero(unexported) == TRUE)) {
			p->lt_scenario = SCENARIO_01;
		}
		/*
		 * #2, a public symbol exists
		 * at all releases
		 */
		else if ((bv_and(public, curr_rel_bitmask) == TRUE) &&
		    (bv_and(public, prev_rel_bitmask) == TRUE) &&
		    (bv_and(private, curr_rel_bitmask) != TRUE) &&
		    (bv_and(private, prev_rel_bitmask) != TRUE) &&
		    (bv_and(unexported, curr_rel_bitmask) != TRUE) &&
		    (bv_and(unexported, prev_rel_bitmask) != TRUE)) {
			p->lt_scenario = SCENARIO_02;
		}
		/*
		 * #3, a old public symbol
		 * becomes private
		 */
		else if ((bv_and(private, curr_rel_bitmask) == TRUE) &&
		    (bv_and(private, prev_rel_bitmask) != TRUE) &&
		    (bv_and(public, curr_rel_bitmask) != TRUE) &&
		    (bv_and(public, prev_rel_bitmask) == TRUE)) {
			p->lt_scenario = SCENARIO_03;
		}
		/*
		 * #4, public symbol is unexported
		 */
		else if ((bv_and(unexported, curr_rel_bitmask) == TRUE) &&
		    (bv_and(public, curr_rel_bitmask) != TRUE) &&
		    (bv_and(public, prev_rel_bitmask) == TRUE)) {
			p->lt_scenario = SCENARIO_04;
		}
		/*
		 * #5, a new private symbol is introduced
		 */
		else if ((bv_compare(release, curr_rel_bitmask) == TRUE) &&
		    (bv_compare(private, release) == TRUE) &&
		    (bv_all_zero(public) == TRUE) &&
		    (bv_all_zero(unexported) == TRUE)) {
			p->lt_scenario = SCENARIO_05;
		}
		/*
		 * #6, a private symbol becomes public
		 */
		else if ((bv_and(public, curr_rel_bitmask) == TRUE) &&
		    (bv_and(public, prev_rel_bitmask) != TRUE) &&
		    (bv_and(private, curr_rel_bitmask) != TRUE) &&
		    (bv_and(private, prev_rel_bitmask) == TRUE)) {
				p->lt_scenario = SCENARIO_06;
		}
		/*
		 * #7, a private symbol exists at all releases
		 */
		else if ((bv_and(public, curr_rel_bitmask) != TRUE) &&
		    (bv_and(public, prev_rel_bitmask) != TRUE) &&
		    (bv_and(private, curr_rel_bitmask) == TRUE) &&
		    (bv_and(private, prev_rel_bitmask) == TRUE) &&
		    (bv_and(unexported, curr_rel_bitmask) != TRUE) &&
		    (bv_and(unexported, prev_rel_bitmask) != TRUE)) {
			p->lt_scenario = SCENARIO_07;
		}
		/*
		 * #8, a private symbol is unexported
		 */
		else if ((bv_and(unexported, curr_rel_bitmask) == TRUE) &&
		    (bv_and(private, curr_rel_bitmask) != TRUE) &&
		    (bv_and(private, prev_rel_bitmask) == TRUE)) {
			p->lt_scenario = SCENARIO_08;
		}
		/*
		 * #9, previously unexported symbol
		 * comes back as public
		 */
		else if ((bv_and(public, curr_rel_bitmask) == TRUE) &&
		    (bv_and(unexported, curr_rel_bitmask) != TRUE) &&
		    (bv_and(public, prev_rel_bitmask) != TRUE) &&
		    (bv_and(unexported, prev_rel_bitmask) == TRUE)) {
			p->lt_scenario = SCENARIO_09;
		}
		/*
		 * #10, previously unexported symbol
		 * comes back as private
		 */
		else if ((bv_and(private, curr_rel_bitmask) == TRUE) &&
		    (bv_and(unexported, curr_rel_bitmask) != TRUE) &&
		    (bv_and(private, prev_rel_bitmask) != TRUE) &&
		    (bv_and(unexported, prev_rel_bitmask) == TRUE)) {
			p->lt_scenario = SCENARIO_10;
		}
		/*
		 * #11, a previously unexported symbol
		 * stays as unexported
		 */
		else if ((bv_and(unexported, curr_rel_bitmask) == TRUE) &&
		    (bv_and(unexported, prev_rel_bitmask) == TRUE)) {
			p->lt_scenario = SCENARIO_11;
		}
		p = p->lt_next;
	}
	free_bv_list(release);
	free_bv_list(public);
	free_bv_list(private);
	free_bv_list(unexported);
	free_bv_list(curr_rel_bitmask);
	free_bv_list(prev_rel_bitmask);
}

/*
 * Detects transitions and generates a history of a symbol's classifications
 * during integrity checking
 * For example; public->private->unexported
 */

static sequence_t *
generate_sequence(sequence_t *pat, bvlist_t *bitmask, liblist_t *p)
{
	sequence_t	*lst;
	bvlist_t	*temp;
	class_t		classification;

	/* category assignments for liblist_t p */
	bvlist_t	*private;
	bvlist_t	*public;
	bvlist_t	*unexported;

	public = create_bv_list(Total_relcnt);
	private = create_bv_list(Total_relcnt);
	unexported = create_bv_list(Total_relcnt);
	bv_assign(public, p->lt_cat->ct_public);
	bv_assign(private, p->lt_cat->ct_private);
	bv_assign(unexported, p->lt_cat->ct_unexported);

	if (bv_and(bitmask, public) == TRUE) {
		classification = PUBLIC;
	} else if (bv_and(bitmask, private) == TRUE) {
		classification = PRIVATE;
	} else if (bv_and(bitmask, unexported) == TRUE) {
		classification = UNEXPORTED;
	} else {
		free_bv_list(public);
		free_bv_list(private);
		free_bv_list(unexported);
		return (NULL);
	}
	if (!pat) {
		if ((pat = calloc(1, sizeof (sequence_t))) == NULL) {
			(void) fprintf(stderr,
			    "%s: generate_sequence: calloc: %s\n",
			    program, strerror(errno));
			free_bv_list(public);
			free_bv_list(private);
			free_bv_list(unexported);
			return (NULL);
		}
		pat->s_class = classification;
		pat->s_pos = create_bv_list(Total_relcnt);
		bv_assign(pat->s_pos, bitmask);
		bv_assign(p->lt_trans_bits, bitmask);
		pat->s_next = NULL;
	} else {
		lst = pat;
		while (lst->s_next)
			lst = lst->s_next;
		temp = create_bv_list(Total_relcnt);
		bv_assign(temp, bitmask);
		temp = bv_bitmask_lshift(temp);

		/*
		 * If the new item has the same classification as the last item
		 * on the list, just update the position bitvector
		 */
		if ((bv_compare(temp, lst->s_pos) == TRUE) &&
		    (lst->s_class == classification)) {
			bv_assign(lst->s_pos, bitmask);
		} else {
			/* Otherwise, add the new item to the end */
			lst->s_next = calloc(1, sizeof (sequence_t));
			if (!lst->s_next) {
				(void) fprintf(stderr,
				    "%s: generate_sequence: calloc: %s\n",
				    program, strerror(errno));
				free_bv_list(temp);
				free_bv_list(lst->s_pos);
				return (NULL);
			}
			lst = lst->s_next;
			lst->s_class = classification;
			lst->s_pos = create_bv_list(Total_relcnt);
			bv_assign(lst->s_pos, bitmask);
			set_bv_or(p->lt_trans_bits, bitmask);
			lst->s_next = NULL;
		}
		free_bv_list(temp);
	}
	free_bv_list(public);
	free_bv_list(private);
	free_bv_list(unexported);
	return (pat);
}

/*
 * Walks through the history of a symbol's classifications, assigns scenario #
 * based on the algorithm of sequence detection for integrity checking.
 */

static scenario_t
detect_sequence(sequence_t *pat, liblist_t *lib)
{
	sequence_t	*last = pat;
	sequence_t	*first;
	scenario_t	scenario = SCENARIO_NONE;
	int		trans_cnt = 0;
	int		public_bit_in_trans_on = FALSE;

	/* category assignments for liblist_t *lib */
	bvlist_t	*public;
	bvlist_t	*private;
	bvlist_t	*unexported;

	private = create_bv_list(Total_relcnt);
	public = create_bv_list(Total_relcnt);
	unexported = create_bv_list(Total_relcnt);

	bv_assign(public, lib->lt_cat->ct_public);
	bv_assign(private, lib->lt_cat->ct_private);
	bv_assign(unexported, lib->lt_cat->ct_unexported);

	while (last) {
		if (last->s_class == PUBLIC)
			public_bit_in_trans_on = TRUE;
		if (last->s_next) {
			trans_cnt ++;
			last = last->s_next;
		} else break;
	}

	first = pat;
	if (pat) {
		if ((bv_all_zero(public) != TRUE) &&
		    (bv_all_zero(private) != TRUE) &&
		    (bv_all_zero(unexported) == TRUE)) {

			/* mixture of public/private transitions */
			if (trans_cnt == 1) {
				if (last->s_class == PUBLIC)
					scenario = SCENARIO_06;
				else
					scenario = SCENARIO_03;
			} else if (trans_cnt > 1)
				scenario = SCENARIO_12;

		} else if ((bv_all_zero(public) != TRUE) &&
		    (bv_all_zero(private) == TRUE) &&
		    (bv_all_zero(unexported) != TRUE)) {

			/* mixture of public/unexported transitions */
			if (trans_cnt == 1)
				scenario = SCENARIO_04;
			else
				scenario = SCENARIO_13;

		} else if ((bv_all_zero(public) == TRUE) &&
		    (bv_all_zero(private) != TRUE) &&
		    (bv_all_zero(unexported) != TRUE)) {

			/* mixture of private/unexported transitions */
			if (trans_cnt == 1)
				scenario = SCENARIO_08;
			else
				scenario = SCENARIO_14;

		} else if ((bv_all_zero(public) != TRUE) &&
		    (bv_all_zero(private) != TRUE) &&
		    (bv_all_zero(unexported) != TRUE)) {

			/* mixture of public/private/unexported transitions */
			if (trans_cnt == 2) {
				if (last->s_class == PUBLIC)
					scenario = SCENARIO_15;
				else if ((last->s_class == PRIVATE) ||
				    (first->s_class == PUBLIC))
					scenario = SCENARIO_16;
				else
					scenario = SCENARIO_17;
			} else if (trans_cnt > 2) {
				if ((last->s_class == PUBLIC) &&
				    (public_bit_in_trans_on == TRUE))
					scenario = SCENARIO_18;
				else
					scenario = SCENARIO_19;
			}
		}
	}
	free_bv_list(public);
	free_bv_list(private);
	free_bv_list(unexported);
	return (scenario);
}

/*
 * Calls generate_sequence() and detect_sequence(),
 * it returns a scenario #
 */

static scenario_t
sequence_match(liblist_t *lib, int idx)
{
	scenario_t	scenario = SCENARIO_NONE;
	sequence_t	*pat = NULL;
	bvlist_t	*bitmask = get_rel_bitmask(0);
	bvlist_t	*this_release = get_rel_bitmask(idx);

	while (bv_and(bitmask, lib->lt_release) != TRUE) {
		bitmask = bv_bitmask_rshift(bitmask);
	}

	while (bv_earlier_than(bitmask, this_release) == TRUE) {
		pat = generate_sequence(pat, bitmask, lib);
		bitmask = bv_bitmask_rshift(bitmask);
	}

	scenario = detect_sequence(pat, lib);
	sequence_list_destroy(pat);
	free_bv_list(bitmask);
	free_bv_list(this_release);
	return (scenario);
}

/*
 * Perform Integrity Check on the linked list
 */

static void
perform_int_check_list(liblist_t *lib)
{
	liblist_t	*p = lib;
	bvlist_t	*release;
	bvlist_t	*public;
	bvlist_t	*private;
	bvlist_t	*unexported;
	int		index = Total_relcnt - 1;
	bvlist_t	*prev_rel_bitmask = get_rel_bitmask(index - 1);
	bvlist_t	*curr_rel_bitmask = get_rel_bitmask(index);

	release = create_bv_list(Total_relcnt);
	public = create_bv_list(Total_relcnt);
	private = create_bv_list(Total_relcnt);
	unexported = create_bv_list(Total_relcnt);

	while (p) {
		bv_assign(release, p->lt_release);
		bv_assign(public, p->lt_cat->ct_public);
		bv_assign(private, p->lt_cat->ct_private);
		bv_assign(unexported, p->lt_cat->ct_unexported);

		/*
		 * #1, a new public symbol
		 * is introduced
		 */
		if ((bv_compare(release, curr_rel_bitmask) == TRUE) &&
		    (bv_compare(release, prev_rel_bitmask) != TRUE) &&
		    (bv_compare(public, release) == TRUE) &&
		    (bv_all_zero(public) != TRUE) &&
		    (bv_all_zero(private) == TRUE) &&
		    (bv_all_zero(unexported) == TRUE)) {
			p->lt_scenario = SCENARIO_01;
		}
		/*
		 * #2, a public symbol exists
		 * at all releases
		 */
		else if ((bv_all_zero(public) != TRUE) &&
		    (bv_compare(release, public) == TRUE) &&
		    (bv_all_zero(private) == TRUE) &&
		    (bv_all_zero(unexported) == TRUE)) {
			p->lt_scenario = SCENARIO_02;
		}
		/*
		 * #5, a new private symbol is introduced
		 */
		else if ((bv_compare(release, curr_rel_bitmask) == TRUE) &&
		    (bv_compare(release, prev_rel_bitmask) != TRUE) &&
		    (bv_compare(private, release) == TRUE) &&
		    (bv_all_zero(private) != TRUE) &&
		    (bv_all_zero(public) == TRUE) &&
		    (bv_all_zero(unexported) == TRUE)) {
			p->lt_scenario = SCENARIO_05;
		}
		/*
		 * #7, a private symbol exists at all releases
		 */
		else if ((bv_all_zero(private) != TRUE) &&
		    (bv_all_zero(public) == TRUE) &&
		    (bv_all_zero(unexported) == TRUE) &&
		    (bv_compare(release, private) == TRUE)) {
			p->lt_scenario = SCENARIO_07;
		}
		/*
		 * mixed sequences detected
		 */
		else {
			p->lt_scenario = sequence_match(p, index);
		}
		p = p->lt_next;
	}
	free_bv_list(release);
	free_bv_list(public);
	free_bv_list(private);
	free_bv_list(unexported);
	free_bv_list(prev_rel_bitmask);
	free_bv_list(curr_rel_bitmask);
}

/*
 * It will do a inorder tree traversal to determine if any symbol is
 * unexported from previous Solaris release.
 */

static void
process_unexported(tree_t *rootptr, int index)
{
	if (rootptr) {
		process_unexported(rootptr->tt_left, index);
		process_unexported_list(rootptr->tt_sym->st_lib, index);
		process_unexported(rootptr->tt_right, index);
	}
}

/*
 * Walk through the linked list, and check if the symbol disappears
 * on current build if it was public/private in previous build(s).
 */

static void
process_unexported_list(liblist_t *node_ptr, int i)
{
	liblist_t	*p = node_ptr;
	bvlist_t	*prev_rel_bitmask = get_rel_bitmask(i - 1);
	bvlist_t	*curr_rel_bitmask = get_rel_bitmask(i);
	bvlist_t	*public;
	bvlist_t	*private;
	bvlist_t	*unexported;

	public = create_bv_list(Total_relcnt);
	private = create_bv_list(Total_relcnt);
	unexported = create_bv_list(Total_relcnt);

	while (p) {
		bv_assign(public, p->lt_cat->ct_public);
		bv_assign(private, p->lt_cat->ct_private);
		bv_assign(unexported, p->lt_cat->ct_unexported);

		if (((bv_all_zero(public) != TRUE) ||
		    (bv_all_zero(private) != TRUE)) &&
		    (bv_and(public, curr_rel_bitmask) != TRUE) &&
		    (bv_and(private, curr_rel_bitmask) != TRUE) &&
		    (bv_and(unexported, curr_rel_bitmask) != TRUE) &&
		    ((bv_and(public, prev_rel_bitmask) == TRUE) ||
		    (bv_and(private, prev_rel_bitmask) == TRUE) ||
		    (bv_and(unexported, prev_rel_bitmask) == TRUE))) {
			set_bv_or(p->lt_release, curr_rel_bitmask);
			set_bv_or(p->lt_cat->ct_unexported, curr_rel_bitmask);
			if (!oflag) {
				if (check_lib_info(lib_list, p->lt_lib_name)) {
					p->lt_check_me |= TRUE;
				}
			}
		}
		p = p->lt_next;
	}
	free_bv_list(public);
	free_bv_list(private);
	free_bv_list(unexported);
	free_bv_list(prev_rel_bitmask);
	free_bv_list(curr_rel_bitmask);
}

/*
 * Skips line processing from the intf_check output file if it does not match
 * one of the following patterns:
 *      i.e. SUNW_m.n: _symbol          # for FUNCTION types
 *           SUNW_m.n: _symbol(4)      # for OBJECT types
 *           SUNW_m.n: _symbol (4)      # for OBJECT types
 * Examples of lines we would skip include:
 * 	- commented lines beginning with '#'
 * 	- lines containing the library name (i.e. the first few lines of
 * 	pvs -dos output)
 */

static int
skip_line(char *line)
{
	char	*lasttoken;
	char	*first_left_paren;
	char	*first_right_paren;
	int	num_spaces;

	/*
	 * skip lines ^#comments, and matching ".so." or ".so:" (i.e., lines
	 * containing the library name.
	 */
	if ((strstr(line, ".so.") != NULL) || (strstr(line, ".so:") != NULL) ||
	    (line[0] == '#')) {
		return (SUCCEED);
	}

	if (count_num_char(':', line) != 1) {
		return (SUCCEED);

	} else if ((num_spaces = count_num_char(' ', line)) == 2) {
		lasttoken = strrchr(line, (int)' ');

		/* check that the 3rd token is surrounded by '()' */
		first_left_paren = strchr(lasttoken, (int)'(');
		first_right_paren = strchr(lasttoken, (int)')');

		if (first_left_paren == NULL &&
		    first_right_paren == NULL &&
		    first_left_paren > first_right_paren) {
			return (SUCCEED);
		}
	} else if (num_spaces != 1) {
		return (SUCCEED);
	}

	return (FAIL);
}

/*
 * Counts number of times a char "c" occurs in the NULL terminated string "str"
 */

int
count_num_char(const char c, char *str)
{
	int	count = 0;

	while (*str) {
		if (*str == c)
			count ++;
		str ++;
	}
	return (count);
}

/*
 * Converts all occurrences of '=' in the filename to '/'
 * i.e. =usr=lib=libfoo.so.1 is translated to /usr/lib/libfoo.so.1
 * No error checking since decode_filename() will only be called
 * on files found from the intf_check's audit/ directory.
 */

static void
decode_filename(char *filename)
{
	char	*tmp_path = filename;

	while (tmp_path[0] != '\0') {
		if (tmp_path[0] == '=') {
			*tmp_path = '/';
		}
		tmp_path ++;
	}
}

/*
 * Traverses AVL Tree reporting all behaviors
 */

static void
report_errors(tree_t *rootptr)
{
	if (rootptr) {
		report_errors(rootptr->tt_left);
		detect_errors(rootptr->tt_sym, Msgout);
		report_errors(rootptr->tt_right);
	}
}

/*
 * Detects scenario numbers assigned to each symbol.  This will determine
 * whether an error message needs to be reported.
 */

static void
detect_errors(symbol_t *sym, FILE *fp)
{
	symbol_t	*p = sym;
	scenario_t	scenario;
	liblist_t	*lib = p->st_lib;

	if (!p)
		return;
	while (p->st_lib) {
		if (p->st_lib->lt_check_me == TRUE) {
			scenario = p->st_lib->lt_scenario;

			/* detect symbol transitions */
			if ((scenario == SCENARIO_06) && tflag) {
				if (!sflag)
					report_err_msg("WARNING", p, fp);
			} else if ((scenario == SCENARIO_03) ||
			    (scenario == SCENARIO_12) ||
			    (scenario == SCENARIO_16) ||
			    (scenario == SCENARIO_19)) {
				report_err_msg("ERROR", p, fp);
			} else if (((scenario == SCENARIO_04) ||
			    (scenario == SCENARIO_13) ||
			    (scenario == SCENARIO_17)) &&
			    (p->st_lib->lt_libc_migrate == FALSE)) {
				report_err_msg("ERROR", p, fp);
			} else if (((scenario == SCENARIO_08) ||
			    (scenario == SCENARIO_14) ||
			    (scenario == SCENARIO_15) ||
			    (scenario == SCENARIO_18)) &&
			    (p->st_lib->lt_libc_migrate == FALSE) && Tflag) {
				if (!sflag)
					report_err_msg("WARNING", p, fp);
			} else if (pflag && (scenario == SCENARIO_01)) {
				if (!sflag)
					report_err_msg("WARNING", p, fp);
			}
		}
		p->st_lib = p->st_lib->lt_next;
	}

	/* Reset p->st_lib for further use of tree pointer */
	p->st_lib = lib;
}

/*
 * Reports all errors detected by the scenario number in detect_errors().
 * "msg" can be either "ERROR" or "WARNING".
 * ERROR will be reported if a symbol transitions from:
 * 	public->unexported
 * 	public->private.
 * WARNING messages are only reported when a symbol transitions from:
 * 	private->unexported.
 */

static void
report_err_msg(char *msg, symbol_t *sym, FILE *fp)
{
	int		rel;
	bvlist_t	*bitmask;
	char		*rel_name;
	category_t	*cat = sym->st_lib->lt_cat;

	/* Do not report if the symbol was scoped local and never exported */
	if (find_exported_release(sym->st_lib, 0) == FAIL) {
		return;
	}

	(void) fprintf(fp, "%s: %s: %s: ",
	    msg, sym->st_lib->lt_lib_name, sym->st_sym_name);

	if (sym->st_lib->lt_scenario == SCENARIO_01) {
		(void) fprintf(fp,
		    "new public interface introduced\n");
		return;
	}
	/* Integrity checking requires reporting of all releases */
	if (iflag) {
		rel = 0;
		bitmask = get_rel_bitmask(0);
	/* Discrepancy checking only reports transitions in last 2 releases */
	} else {
		rel = Total_relcnt - 2;
		bitmask = get_rel_bitmask(Total_relcnt - 2);
	}

	while (rel < Total_relcnt) {
		rel_name = get_rel_name(rel);

		/*
		 * For discrepancy checking, reporting will pass through
		 * this loop twice: e.g. was public in 5.7, is now private
		 * For integrity checking, we will need to check if transition
		 * bit is on for each release, and only report in such cases
		 */
		if (!iflag ||
		    (bv_and(bitmask, sym->st_lib->lt_trans_bits) == TRUE)) {
			if ((iflag && rel == last_transition(sym->st_lib)) ||
			    (!iflag && rel == Total_relcnt - 1)) {
				(void) fprintf(fp, "is now ");
			} else {
				(void) fprintf(fp, "was ");
			}

			if (bv_and(bitmask, cat->ct_public) == TRUE) {
				(void) fprintf(fp, "public");
			} else if (bv_and(bitmask, cat->ct_private) == TRUE) {
				(void) fprintf(fp, "private");
			} else if ((bv_and(bitmask, cat->ct_scoped) == TRUE) &&
			    (bv_and(bitmask, cat->ct_unexported) == TRUE)) {
				(void) fprintf(fp, "scoped");
			} else if (bv_and(bitmask,
			    cat->ct_unexported) == TRUE) {
				(void) fprintf(fp, "unexported");
			} else if (bv_and(bitmask, cat->ct_obsolete) == TRUE) {
				(void) fprintf(fp, "obsolete");
			} else if (bv_and(bitmask, cat->ct_evolving) == TRUE) {
				(void) fprintf(fp, "evolving");
			} else {
				(void) fprintf(fp, "unclassified");
			}

			/* print "->" if there are more transitions */
			if (iflag) {
				if (rel != last_transition(sym->st_lib))
					(void) fprintf(fp, " in %s, ",
					    rel_name);
			} else {
				if (rel == Total_relcnt - 2)
					(void) fprintf(fp, " in %s, ",
					    rel_name);
			}
		}
		bitmask =  bv_bitmask_rshift(bitmask);
		rel ++;
	}

	free_bv_list(bitmask);
	(void) fprintf(fp, "\n");
}

/*
 * Adds Copyright and customer releases captured in ABI database file
 */

static void
add_copyright_and_release(FILE *fp)
{
	int		i;
	time_t		t;
	struct tm	*gmt;

	t = time(NULL);
	gmt = gmtime(&t);

	(void) fprintf(fp, "#\n"
	    "# Copyright %d Sun Microsystems, Inc."
	    "  All rights reserved.\n"
	    "# Use is subject to license terms.\n"
	    "#\n"
	    "#Releases:", 1900 + gmt->tm_year);

	for (i = 0; i < Total_relcnt - 1; i ++) {
		(void) fprintf(fp, "%s,", get_rel_name(i));
	}
	(void) fprintf(fp, "%s\n", get_rel_name(i));
}

/*
 * Generate ABI Database in ASCII text format:
 * <symbol_name> <lib_name> <FUNCTION | OBJECT> <data_size>
 * (<highest_lib_version> <base_sym_version>)* <release_bitvector>
 * <public_bitvector> <private_bitvector> <unexported_bitvector>
 * <evolving_bitvector> <obsolete_bitvector> <scoped_bitvector>
 * <unclassified_bitvector>
 * i.e., .div /usr/lib/libc.so.1 0 0 SUNW_1.18 SUNW_0.7 \
 * SUNW_1.20 SUNW_0.7 11 11 0 0 0 0 0 0
 */

void
generate_db(symbol_t *p, FILE *db)
{
	int	index;
	char	*lib_ver;
	char	*sym_ver;

	if ((find_exported_release(p->st_lib, 0) != FAIL) &&
	    ((bv_all_zero(p->st_lib->lt_cat->ct_public) != TRUE) ||
	    (bv_all_zero(p->st_lib->lt_cat->ct_private) != TRUE))) {
		(void) fprintf(db, "%s %s %d %d ", p->st_sym_name,
		    p->st_lib->lt_lib_name, p->st_type, p->st_size);

		for (index = 0; index < Total_relcnt; index ++) {
			lib_ver = get_lib_ver(p->st_lib, index);
			sym_ver = get_sym_ver(p->st_lib, index);
			if (lib_ver != NULL) {
				(void) fprintf(db, "%s ", lib_ver);
			} else {
				(void) fprintf(db, "0 ");
			}
			if (sym_ver != NULL) {
				(void) fprintf(db, "%s ", sym_ver);
			} else {
				(void) fprintf(db, "0 ");
			}
		}
		(void) fprintf(db, "%s ", bvtos(p->st_lib->lt_release));
		if (bv_all_zero(p->st_lib->lt_cat->ct_public) != TRUE) {
			(void) fprintf(db, "%s ",
			    bvtos(p->st_lib->lt_cat->ct_public));
		} else {
			(void) fprintf(db, "0 ");
		}
		if (bv_all_zero(p->st_lib->lt_cat->ct_private) != TRUE) {
			(void) fprintf(db, "%s ",
			    bvtos(p->st_lib->lt_cat->ct_private));
		} else {
			(void) fprintf(db, "0 ");
		}
		if (bv_all_zero(p->st_lib->lt_cat->ct_unexported) != TRUE) {
			(void) fprintf(db, "%s ",
			    bvtos(p->st_lib->lt_cat->ct_unexported));
		} else {
			(void) fprintf(db, "0 ");
		}
		if (bv_all_zero(p->st_lib->lt_cat->ct_scoped) != TRUE) {
			(void) fprintf(db, "%s ",
			    bvtos(p->st_lib->lt_cat->ct_scoped));
		} else {
			(void) fprintf(db, "0 ");
		}
		if (bv_all_zero(p->st_lib->lt_cat->ct_evolving) != TRUE) {
			(void) fprintf(db, "%s ",
			    bvtos(p->st_lib->lt_cat->ct_evolving));
		} else {
			(void) fprintf(db, "0 ");
		}
		if (bv_all_zero(p->st_lib->lt_cat->ct_obsolete) != TRUE) {
			(void) fprintf(db, "%s ",
			    bvtos(p->st_lib->lt_cat->ct_obsolete));
		} else {
			(void) fprintf(db, "0 ");
		}
		if (bv_all_zero(p->st_lib->lt_cat->ct_unclassified) != TRUE) {
			(void) fprintf(db, "%s\n",
			    bvtos(p->st_lib->lt_cat->ct_unclassified));
		} else {
			(void) fprintf(db, "0\n");
		}
	}
}

/*
 * Cleanup routine to close opened files.
 */

static void
cleanup(void)
{
	if (Msgout != stdout) {
		(void) fclose(Msgout);
	}
	if (Db != stdout)
		(void) fclose(Db);
}

/*
 * read the contents file which records all the libraries under the current
 * test directory produced by intf_check.pl, and store them onto a simple
 * linked list (actual_libs_pool).
 */
static int
load_liblog(void)
{
	FILE	*liblog_fp;
	char	*liblog_file = "/tmp/abi_audit_lib_log";
	char	line[MAXPATHLEN];

	if ((liblog_fp = fopen(liblog_file, "r")) == NULL) {
		(void) fprintf(stderr, "%s: fopen "
		    "failed to open <%s>: %s\n",
		    program, liblog_file, strerror(errno));
		return (FAIL);
	}

	while (!feof(liblog_fp)) {
		line[0] = '\0';
		if (fgets(line, MAXPATHLEN, liblog_fp) != NULL) {
			trimmer(line);
			actual_libs_pool =
			    store_lib_info(actual_libs_pool, line);
		}
	}
	(void) fclose(liblog_fp);
	return (SUCCEED);
}
