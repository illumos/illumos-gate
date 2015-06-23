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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 *
 * Copyright (c) 2011 Gary Mills
 *
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains the code to perform program startup.  This
 * includes reading the data file and the search for disks.
 */
#include "global.h"

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <memory.h>
#include <dirent.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "startup.h"
#include "param.h"
#include "label.h"
#include "misc.h"
#include "menu_command.h"
#include "partition.h"
#include "ctlr_scsi.h"

#include "auto_sense.h"

extern	struct	ctlr_type ctlr_types[];
extern	int	nctypes;
extern	struct	ctlr_ops	genericops;
extern	long	strtol();

extern	int	errno;

#ifdef __STDC__

/* Function prototypes for ANSI C Compilers */
static void	usage(void);
static int	sup_prxfile(void);
static void	sup_setpath(void);
static void	sup_setdtype(void);
static int	sup_change_spec(struct disk_type *, char *);
static void	sup_setpart(void);
static void	search_for_logical_dev(char *devname);
static void	add_device_to_disklist(char *devname, char *devpath);
static int	disk_is_known(struct dk_cinfo *dkinfo);
static void	datafile_error(char *errmsg, char *token);
static void	search_duplicate_dtypes(void);
static void	search_duplicate_pinfo(void);
static void	check_dtypes_for_inconsistency(struct disk_type *dp1,
		struct disk_type *dp2);
static void	check_pinfo_for_inconsistency(struct partition_info *pp1,
		struct partition_info *pp2);
static uint_t	str2blks(char *str);
static int	str2cyls(char *str);
static struct	chg_list *new_chg_list(struct disk_type *);
static char	*get_physical_name(char *);
static void	sort_disk_list(void);
static int	disk_name_compare(const void *, const void *);
static void	make_controller_list(void);
static void	check_for_duplicate_disknames(char *arglist[]);

#else	/* __STDC__ */

/* Function prototypes for non-ANSI C Compilers */
static void	usage();
static int	sup_prxfile();
static void	sup_setpath();
static void	sup_setdtype();
static int	sup_change_spec();
static void	sup_setpart();
static void	search_for_logical_dev();
static void	add_device_to_disklist();
static int	disk_is_known();
static void	datafile_error();
static void	search_duplicate_dtypes();
static void	search_duplicate_pinfo();
static void	check_dtypes_for_inconsistency();
static void	check_pinfo_for_inconsistency();
static uint_t	str2blks();
static int	str2cyls();
static struct	chg_list *new_chg_list();
static char	*get_physical_name();
static void	sort_disk_list();
static int	disk_name_compare();
static void	make_controller_list();
static void	check_for_duplicate_disknames();

#endif	/* __STDC__ */

#if defined(sparc)
static char *other_ctlrs[] = {
	"ata"
	};
#define	OTHER_CTLRS 1

#elif defined(i386)
static char *other_ctlrs[] = {
	"ISP-80"
	};
#define	OTHER_CTLRS 2

#else
#error No Platform defined.
#endif


/*
 * This global is used to store the current line # in the data file.
 * It must be global because the I/O routines are allowed to side
 * effect it to keep track of backslashed newlines.
 */
int	data_lineno;			/* current line # in data file */

/*
 * Search path as defined in the format.dat files
 */
static char	**search_path = NULL;


static int name_represents_wholedisk(char *name);

static void get_disk_name(int fd, char *disk_name);

/*
 * This routine digests the options on the command line.  It returns
 * the index into argv of the first string that is not an option.  If
 * there are none, it returns -1.
 */
int
do_options(int argc, char *argv[])
{
	char	*ptr;
	int	i;
	int	next;

	/*
	 * Default is no extended messages.  Can be enabled manually.
	 */
	option_msg = 0;
	diag_msg = 0;
	expert_mode = 0;
	need_newline = 0;
	dev_expert = 0;

	/*
	 * Loop through the argument list, incrementing each time by
	 * an amount determined by the options found.
	 */
	for (i = 1; i < argc; i = next) {
		/*
		 * Start out assuming an increment of 1.
		 */
		next = i + 1;
		/*
		 * As soon as we hit a non-option, we're done.
		 */
		if (*argv[i] != '-')
			return (i);
		/*
		 * Loop through all the characters in this option string.
		 */
		for (ptr = argv[i] + 1; *ptr != '\0'; ptr++) {
			/*
			 * Determine each option represented.  For options
			 * that use a second string, increase the increment
			 * of the main loop so they aren't re-interpreted.
			 */
			switch (*ptr) {
			case 's':
			case 'S':
				option_s = 1;
				break;
			case 'f':
			case 'F':
				option_f = argv[next++];
				if (next > argc)
					goto badopt;
				break;
			case 'l':
			case 'L':
				option_l = argv[next++];
				if (next > argc)
					goto badopt;
				break;
			case 'x':
			case 'X':
				option_x = argv[next++];
				if (next > argc)
					goto badopt;
				break;
			case 'd':
			case 'D':
				option_d = argv[next++];
				if (next > argc)
					goto badopt;
				break;
			case 't':
			case 'T':
				option_t = argv[next++];
				if (next > argc)
					goto badopt;
				break;
			case 'p':
			case 'P':
				option_p = argv[next++];
				if (next > argc)
					goto badopt;
				break;
			case 'm':
				option_msg = 1;
				break;
			case 'M':
				option_msg = 1;
				diag_msg = 1;
				break;
			case 'e':
				expert_mode = 1;
				break;
#ifdef DEBUG
			case 'z':
				dev_expert = 1;
				break;
#endif
			default:
badopt:
				usage();
				break;
			}
		}
	}
	/*
	 * All the command line strings were options.  Return that fact.
	 */
	return (-1);
}


static void
usage()
{
	err_print("Usage:  format [-s][-d disk_name]");
	err_print("[-t disk_type][-p partition_name]\n");
	err_print("\t[-f cmd_file][-l log_file]");
	err_print("[-x data_file] [-m] [-M] [-e] disk_list\n");
	fullabort();
}


/*
 * This routine reads in and digests the data file.  The data file contains
 * definitions for the search path, known disk types, and known partition
 * maps.
 *
 * Note: for each file being processed, file_name is a pointer to that
 * file's name.  We are careful to make sure that file_name points to
 * globally-accessible data, not data on the stack, because each
 * disk/partition/controller definition now keeps a pointer to the
 * filename in which it was defined.  In the case of duplicate,
 * conflicting definitions, we can thus tell the user exactly where
 * the problem is occurring.
 */
void
sup_init()
{
	int		nopened_files = 0;
	char		fname[MAXPATHLEN];
	char		*path;
	char		*p;
	struct stat	stbuf;


	/*
	 * Create a singly-linked list of controller types so that we may
	 * dynamically add unknown controllers to this for 3'rd
	 * party disk support.
	 */

	make_controller_list();

	/*
	 * If a data file was specified on the command line, use it first
	 * If the file cannot be opened, fail.  We want to guarantee
	 * that, if the user explicitly names a file, they can
	 * access it.
	 *
	 * option_x is already global, no need to dup it on the heap.
	 */
	if (option_x) {
		file_name = option_x;
		if (sup_prxfile()) {
			nopened_files++;
		} else {
			err_print("Unable to open data file '%s' - %s.\n",
			    file_name, strerror(errno));
			fullabort();
		}
	}

	/*
	 * Now look for an environment variable FORMAT_PATH.
	 * If found, we use it as a colon-separated list
	 * of directories.  If no such environment variable
	 * is defined, use a default path of "/etc".
	 */
	path = getenv("FORMAT_PATH");
	if (path == NULL) {
		path = "/etc";
	}
	/*
	 * Traverse the path one file at a time.  Pick off
	 * the file name, and append the name "format.dat"
	 * at the end of the pathname.
	 * Whatever string we construct, duplicate it on the
	 * heap, so that file_name is globally accessible.
	 */
	while (*path != 0) {
		p = fname;
		while (*path != 0 && *path != ':')
			*p++ = *path++;
		if (p == fname)
			continue;
		*p = 0;
		if (*path == ':')
			path++;
		/*
		 * If the path we have so far is a directory,
		 * look for a format.dat file in that directory,
		 * otherwise try using the path name specified.
		 * This permits arbitrary file names in the
		 * path specification, if this proves useful.
		 */
		if (stat(fname, &stbuf) == -1) {
			err_print("Unable to access '%s' - %s.\n",
			    fname, strerror(errno));
		} else {
			if (S_ISDIR(stbuf.st_mode)) {
				if (*(p-1) != '/')
					*p++ = '/';
				(void) strcpy(p, "format.dat");
			}
			file_name = alloc_string(fname);
			if (sup_prxfile()) {
				nopened_files++;
			}
		}
	}

	/*
	 * Check for duplicate disk or partitions definitions
	 * that are inconsistent - this would be very confusing.
	 */
	search_duplicate_dtypes();
	search_duplicate_pinfo();
}


/*
 * Open and process a format data file.  Unfortunately, we use
 * globals: file_name for the file name, and data_file
 * for the descriptor.  Return true if able to open the file.
 */
static int
sup_prxfile()
{
	int	status;
	TOKEN	token;
	TOKEN	cleaned;

	/*
	 * Open the data file.  Return 0 if unable to do so.
	 */
	data_file = fopen(file_name, "r");
	if (data_file == NULL) {
		return (0);
	}
	/*
	 * Step through the data file a meta-line at a time.  There are
	 * typically several backslashed newlines in each meta-line,
	 * so data_lineno will be getting side effected along the way.
	 */
	data_lineno = 0;
	for (;;) {
		data_lineno++;
		/*
		 * Get the keyword.
		 */
		status = sup_gettoken(token);
		/*
		 * If we hit the end of the data file, we're done.
		 */
		if (status == SUP_EOF)
			break;
		/*
		 * If the line is blank, skip it.
		 */
		if (status == SUP_EOL)
			continue;
		/*
		 * If the line starts with some key character, it's an error.
		 */
		if (status != SUP_STRING) {
			datafile_error("Expecting keyword, found '%s'", token);
			continue;
		}
		/*
		 * Clean up the token and see which keyword it is.  Call
		 * the appropriate routine to process the rest of the line.
		 */
		clean_token(cleaned, token);
		if (strcmp(cleaned, "search_path") == 0)
			sup_setpath();
		else if (strcmp(cleaned, "disk_type") == 0)
			sup_setdtype();
		else if (strcmp(cleaned, "partition") == 0)
			sup_setpart();
		else {
			datafile_error("Unknown keyword '%s'", cleaned);
		}
	}
	/*
	 * Close the data file.
	 */
	(void) fclose(data_file);

	return (1);
}

/*
 * This routine processes a 'search_path' line in the data file.  The
 * search path is a list of disk names that will be searched for by the
 * program.
 *
 * The static path_size and path_alloc are used to build up the
 * list of files comprising the search path.  The static definitions
 * enable supporting multiple search path definitions.
 */
static void
sup_setpath()
{
	TOKEN		token;
	TOKEN		cleaned;
	int		status;
	static int	path_size;
	static int	path_alloc;

	/*
	 * Pull in some grammar.
	 */
	status = sup_gettoken(token);
	if (status != SUP_EQL) {
		datafile_error("Expecting '=', found '%s'", token);
		return;
	}
	/*
	 * Loop through the entries.
	 */
	for (;;) {
		/*
		 * Pull in the disk name.
		 */
		status = sup_gettoken(token);
		/*
		 * If we hit end of line, we're done.
		 */
		if (status == SUP_EOL)
			break;
		/*
		 * If we hit some key character, it's an error.
		 */
		if (status != SUP_STRING) {
			datafile_error("Expecting value, found '%s'", token);
			break;
		}
		clean_token(cleaned, token);
		/*
		 * Build the string into an argvlist.  This array
		 * is dynamically sized, as necessary, and terminated
		 * with a null.  Each name is alloc'ed on the heap,
		 * so no dangling references.
		 */
		search_path = build_argvlist(search_path, &path_size,
		    &path_alloc, cleaned);
		/*
		 * Pull in some grammar.
		 */
		status = sup_gettoken(token);
		if (status == SUP_EOL)
			break;
		if (status != SUP_COMMA) {
			datafile_error("Expecting ', ', found '%s'", token);
			break;
		}
	}
}

/*
 * This routine processes a 'disk_type' line in the data file.  It defines
 * the physical attributes of a brand of disk when connected to a specific
 * controller type.
 */
static void
sup_setdtype()
{
	TOKEN	token, cleaned, ident;
	int	val, status, i;
	ulong_t	flags = 0;
	struct	disk_type *dtype, *type;
	struct	ctlr_type *ctype;
	char	*dtype_name, *ptr;
	struct	mctlr_list	*mlp;

	/*
	 * Pull in some grammar.
	 */
	status = sup_gettoken(token);
	if (status != SUP_EQL) {
		datafile_error("Expecting '=', found '%s'", token);
		return;
	}
	/*
	 * Pull in the name of the disk type.
	 */
	status = sup_gettoken(token);
	if (status != SUP_STRING) {
		datafile_error("Expecting value, found '%s'", token);
		return;
	}
	clean_token(cleaned, token);
	/*
	 * Allocate space for the disk type and copy in the name.
	 */
	dtype_name = (char *)zalloc(strlen(cleaned) + 1);
	(void) strcpy(dtype_name, cleaned);
	dtype = (struct disk_type *)zalloc(sizeof (struct disk_type));
	dtype->dtype_asciilabel = dtype_name;
	/*
	 * Save the filename/linenumber where this disk was defined
	 */
	dtype->dtype_filename = file_name;
	dtype->dtype_lineno = data_lineno;
	/*
	 * Loop for each attribute.
	 */
	for (;;) {
		/*
		 * Pull in some grammar.
		 */
		status = sup_gettoken(token);
		/*
		 * If we hit end of line, we're done.
		 */
		if (status == SUP_EOL)
			break;
		if (status != SUP_COLON) {
			datafile_error("Expecting ':', found '%s'", token);
			return;
		}
		/*
		 * Pull in the attribute.
		 */
		status = sup_gettoken(token);
		/*
		 * If we hit end of line, we're done.
		 */
		if (status == SUP_EOL)
			break;
		/*
		 * If we hit a key character, it's an error.
		 */
		if (status != SUP_STRING) {
			datafile_error("Expecting keyword, found '%s'", token);
			return;
		}
		clean_token(ident, token);
		/*
		 * Check to see if we've got a change specification
		 * If so, this routine will parse the entire
		 * specification, so just restart at top of loop
		 */
		if (sup_change_spec(dtype, ident)) {
			continue;
		}
		/*
		 * Pull in more grammar.
		 */
		status = sup_gettoken(token);
		if (status != SUP_EQL) {
			datafile_error("Expecting '=', found '%s'", token);
			return;
		}
		/*
		 * Pull in the value of the attribute.
		 */
		status = sup_gettoken(token);
		if (status != SUP_STRING) {
			datafile_error("Expecting value, found '%s'", token);
			return;
		}
		clean_token(cleaned, token);
		/*
		 * If the attribute defined the ctlr...
		 */
		if (strcmp(ident, "ctlr") == 0) {
			/*
			 * Match the value with a ctlr type.
			 */
			mlp = controlp;

			while (mlp != NULL) {
				if (strcmp(mlp->ctlr_type->ctype_name,
				    cleaned) == 0)
					break;
				mlp = mlp->next;
			}
			/*
			 * If we couldn't match it, it's an error.
			 */
			if (mlp == NULL) {
				for (i = 0; i < OTHER_CTLRS; i++) {
					if (strcmp(other_ctlrs[i], cleaned)
					    == 0) {
						datafile_error(NULL, NULL);
						return;
					}
				}
				if (i == OTHER_CTLRS) {
					datafile_error(
					    "Unknown controller '%s'",
					    cleaned);
					return;
				}
			}
			/*
			 * Found a match.  Add this disk type to the list
			 * for the ctlr type if we can complete the
			 * disk specification correctly.
			 */
			ctype = mlp->ctlr_type;
			flags |= SUP_CTLR;
			continue;
		}
		/*
		 * All other attributes require a numeric value.  Convert
		 * the value to a number.
		 */
		val = (int)strtol(cleaned, &ptr, 0);
		if (*ptr != '\0') {
			datafile_error("Expecting an integer, found '%s'",
			    cleaned);
			return;
		}
		/*
		 * Figure out which attribute it was and fill in the
		 * appropriate value.  Also note that the attribute
		 * has been defined.
		 */
		if (strcmp(ident, "ncyl") == 0) {
			dtype->dtype_ncyl = val;
			flags |= SUP_NCYL;
		} else if (strcmp(ident, "acyl") == 0) {
			dtype->dtype_acyl = val;
			flags |= SUP_ACYL;
		} else if (strcmp(ident, "pcyl") == 0) {
			dtype->dtype_pcyl = val;
			flags |= SUP_PCYL;
		} else if (strcmp(ident, "nhead") == 0) {
			dtype->dtype_nhead = val;
			flags |= SUP_NHEAD;
		} else if (strcmp(ident, "nsect") == 0) {
			dtype->dtype_nsect = val;
			flags |= SUP_NSECT;
		} else if (strcmp(ident, "rpm") == 0) {
			dtype->dtype_rpm = val;
			flags |= SUP_RPM;
		} else if (strcmp(ident, "bpt") == 0) {
			dtype->dtype_bpt = val;
			flags |= SUP_BPT;
		} else if (strcmp(ident, "bps") == 0) {
			dtype->dtype_bps = val;
			flags |= SUP_BPS;
		} else if (strcmp(ident, "drive_type") == 0) {
			dtype->dtype_dr_type = val;
			flags |= SUP_DRTYPE;
		} else if (strcmp(ident, "cache") == 0) {
			dtype->dtype_cache = val;
			flags |= SUP_CACHE;
		} else if (strcmp(ident, "prefetch") == 0) {
			dtype->dtype_threshold = val;
			flags |= SUP_PREFETCH;
		} else if (strcmp(ident, "read_retries") == 0) {
			dtype->dtype_read_retries = val;
			flags |= SUP_READ_RETRIES;
		} else if (strcmp(ident, "write_retries") == 0) {
			dtype->dtype_write_retries = val;
			flags |= SUP_WRITE_RETRIES;
		} else if (strcmp(ident, "min_prefetch") == 0) {
			dtype->dtype_prefetch_min = val;
			flags |= SUP_CACHE_MIN;
		} else if (strcmp(ident, "max_prefetch") == 0) {
			dtype->dtype_prefetch_max = val;
			flags |= SUP_CACHE_MAX;
		} else if (strcmp(ident, "trks_zone") == 0) {
			dtype->dtype_trks_zone = val;
			flags |= SUP_TRKS_ZONE;
		} else if (strcmp(ident, "atrks") == 0) {
			dtype->dtype_atrks = val;
			flags |= SUP_ATRKS;
		} else if (strcmp(ident, "asect") == 0) {
			dtype->dtype_asect = val;
			flags |= SUP_ASECT;
		} else if (strcmp(ident, "psect") == 0) {
			dtype->dtype_psect = val;
			flags |= SUP_PSECT;
		} else if (strcmp(ident, "phead") == 0) {
			dtype->dtype_phead = val;
			flags |= SUP_PHEAD;
		} else if (strcmp(ident, "fmt_time") == 0) {
			dtype->dtype_fmt_time = val;
			flags |= SUP_FMTTIME;
		} else if (strcmp(ident, "cyl_skew") == 0) {
			dtype->dtype_cyl_skew = val;
			flags |= SUP_CYLSKEW;
		} else if (strcmp(ident, "trk_skew") == 0) {
			dtype->dtype_trk_skew = val;
			flags |= SUP_TRKSKEW;
		} else {
			datafile_error("Unknown keyword '%s'", ident);
		}
	}
	/*
	 * Check to be sure all the necessary attributes have been defined.
	 * If any are missing, it's an error.  Also, log options for later
	 * use by specific driver.
	 */
	dtype->dtype_options = flags;
	if ((flags & SUP_MIN_DRIVE) != SUP_MIN_DRIVE) {
		datafile_error("Incomplete specification", "");
		return;
	}
	if ((!(ctype->ctype_flags & CF_SCSI)) && (!(flags & SUP_BPT)) &&
	    (!(ctype->ctype_flags & CF_NOFORMAT))) {
		datafile_error("Incomplete specification", "");
		return;
	}
	if ((ctype->ctype_flags & CF_SMD_DEFS) && (!(flags & SUP_BPS))) {
		datafile_error("Incomplete specification", "");
		return;
	}
	/*
	 * Add this disk type to the list for the ctlr type
	 */
	assert(flags & SUP_CTLR);
	type = ctype->ctype_dlist;
	if (type == NULL) {
		ctype->ctype_dlist = dtype;
	} else {
		while (type->dtype_next != NULL)
			type = type->dtype_next;
		type->dtype_next = dtype;
	}
}


/*
 * Parse a SCSI mode page change specification.
 *
 * Return:
 *		0:  not change specification, continue parsing
 *		1:  was change specification, it was ok,
 *		    or we already handled the error.
 */
static int
sup_change_spec(struct disk_type *disk, char *id)
{
	char		*p;
	char		*p2;
	int		pageno;
	int		byteno;
	int		mode;
	int		value;
	TOKEN		token;
	TOKEN		ident;
	struct chg_list	*cp;
	int		tilde;
	int		i;

	/*
	 * Syntax: p[<nn>|0x<xx>]
	 */
	if (*id != 'p') {
		return (0);
	}
	pageno = (int)strtol(id+1, &p2, 0);
	if (*p2 != 0) {
		return (0);
	}
	/*
	 * Once we get this far, we know we have the
	 * beginnings of a change specification.
	 * If there's a problem now, report the problem,
	 * and return 1, so that the caller can restart
	 * parsing at the next expression.
	 */
	if (!scsi_supported_page(pageno)) {
		datafile_error("Unsupported mode page '%s'", id);
		return (1);
	}
	/*
	 * Next token should be the byte offset
	 */
	if (sup_gettoken(token) != SUP_STRING) {
		datafile_error("Unexpected value '%s'", token);
		return (1);
	}
	clean_token(ident, token);

	/*
	 * Syntax: b[<nn>|0x<xx>]
	 */
	p = ident;
	if (*p++ != 'b') {
		datafile_error("Unknown keyword '%s'", ident);
		return (1);
	}
	byteno = (int)strtol(p, &p2, 10);
	if (*p2 != 0) {
		datafile_error("Unknown keyword '%s'", ident);
		return (1);
	}
	if (byteno == 0 || byteno == 1) {
		datafile_error("Unsupported byte offset '%s'", ident);
		return (1);
	}

	/*
	 * Get the operator for this expression
	 */
	mode = CHG_MODE_UNDEFINED;
	switch (sup_gettoken(token)) {
	case SUP_EQL:
		mode = CHG_MODE_ABS;
		break;
	case SUP_OR:
		if (sup_gettoken(token) == SUP_EQL)
			mode = CHG_MODE_SET;
		break;
	case SUP_AND:
		if (sup_gettoken(token) == SUP_EQL)
			mode = CHG_MODE_CLR;
		break;
	}
	if (mode == CHG_MODE_UNDEFINED) {
		datafile_error("Unexpected operator: '%s'", token);
		return (1);
	}

	/*
	 * Get right-hand of expression - accept optional tilde
	 */
	tilde = 0;
	if ((i = sup_gettoken(token)) == SUP_TILDE) {
		tilde = 1;
		i = sup_gettoken(token);
	}
	if (i != SUP_STRING) {
		datafile_error("Expecting value, found '%s'", token);
		return (1);
	}
	clean_token(ident, token);
	value = (int)strtol(ident, &p, 0);
	if (*p != 0) {
		datafile_error("Expecting value, found '%s'", token);
		return (1);
	}

	/*
	 * Apply the tilde operator, if found.
	 * Constrain to a byte value.
	 */
	if (tilde) {
		value = ~value;
	}
	value &= 0xff;

	/*
	 * We parsed a successful change specification expression.
	 * Add it to the list for this disk type.
	 */
	cp = new_chg_list(disk);
	cp->pageno = pageno;
	cp->byteno = byteno;
	cp->mode = mode;
	cp->value = value;
	return (1);
}


/*
 * This routine processes a 'partition' line in the data file.  It defines
 * a known partition map for a particular disk type on a particular
 * controller type.
 */
static void
sup_setpart()
{
	TOKEN	token, cleaned, disk, ctlr, ident;
	struct	disk_type *dtype = NULL;
	struct	ctlr_type *ctype = NULL;
	struct	partition_info *pinfo, *parts;
	char	*pinfo_name;
	int	i, index, status, flags = 0;
	uint_t	val1, val2;
	ushort_t	vtoc_tag;
	ushort_t	vtoc_flag;
	struct	mctlr_list	*mlp;

	/*
	 * Pull in some grammar.
	 */
	status = sup_gettoken(token);
	if (status != SUP_EQL) {
		datafile_error("Expecting '=', found '%s'", token);
		return;
	}
	/*
	 * Pull in the name of the map.
	 */
	status = sup_gettoken(token);
	if (status != SUP_STRING) {
		datafile_error("Expecting value, found '%s'", token);
		return;
	}
	clean_token(cleaned, token);
	/*
	 * Allocate space for the partition map and fill in the name.
	 */
	pinfo_name = (char *)zalloc(strlen(cleaned) + 1);
	(void) strcpy(pinfo_name, cleaned);
	pinfo = (struct partition_info *)zalloc(sizeof (struct partition_info));
	pinfo->pinfo_name = pinfo_name;
	/*
	 * Save the filename/linenumber where this partition was defined
	 */
	pinfo->pinfo_filename = file_name;
	pinfo->pinfo_lineno = data_lineno;

	/*
	 * Install default vtoc information into the new partition table
	 */
	set_vtoc_defaults(pinfo);

	/*
	 * Loop for each attribute in the line.
	 */
	for (;;) {
		/*
		 * Pull in some grammar.
		 */
		status = sup_gettoken(token);
		/*
		 * If we hit end of line, we're done.
		 */
		if (status == SUP_EOL)
			break;
		if (status != SUP_COLON) {
			datafile_error("Expecting ':', found '%s'", token);
			return;
		}
		/*
		 * Pull in the attribute.
		 */
		status = sup_gettoken(token);
		/*
		 * If we hit end of line, we're done.
		 */
		if (status == SUP_EOL)
			break;
		if (status != SUP_STRING) {
			datafile_error("Expecting keyword, found '%s'", token);
			return;
		}
		clean_token(ident, token);
		/*
		 * Pull in more grammar.
		 */
		status = sup_gettoken(token);
		if (status != SUP_EQL) {
			datafile_error("Expecting '=', found '%s'", token);
			return;
		}
		/*
		 * Pull in the value of the attribute.
		 */
		status = sup_gettoken(token);
		/*
		 * If we hit a key character, it's an error.
		 */
		if (status != SUP_STRING) {
			datafile_error("Expecting value, found '%s'", token);
			return;
		}
		clean_token(cleaned, token);
		/*
		 * If the attribute is the ctlr, save the ctlr name and
		 * mark it defined.
		 */
		if (strcmp(ident, "ctlr") == 0) {
			(void) strcpy(ctlr, cleaned);
			flags |= SUP_CTLR;
			continue;
		/*
		 * If the attribute is the disk, save the disk name and
		 * mark it defined.
		 */
		} else if (strcmp(ident, "disk") == 0) {
			(void) strcpy(disk, cleaned);
			flags |= SUP_DISK;
			continue;
		}
		/*
		 * If we now know both the controller name and the
		 * disk name, let's see if we can find the controller
		 * and disk type.  This will give us the geometry,
		 * which can permit us to accept partitions specs
		 * in cylinders or blocks.
		 */
		if (((flags & (SUP_DISK|SUP_CTLR)) == (SUP_DISK|SUP_CTLR)) &&
		    dtype == NULL && ctype == NULL) {
			/*
			 * Attempt to match the specified ctlr to a known type.
			 */
			mlp = controlp;

			while (mlp != NULL) {
				if (strcmp(mlp->ctlr_type->ctype_name,
				    ctlr) == 0)
					break;
				mlp = mlp->next;
			}
			/*
			 * If no match is found, it's an error.
			 */
			if (mlp == NULL) {
				for (i = 0; i < OTHER_CTLRS; i++) {
					if (strcmp(other_ctlrs[i], ctlr) == 0) {
						datafile_error(NULL, NULL);
						return;
					}
				}
				if (i == OTHER_CTLRS) {
					datafile_error(
					    "Unknown controller '%s'", ctlr);
					return;
				}
			}
			ctype = mlp->ctlr_type;
			/*
			 * Attempt to match the specified disk to a known type.
			 */
			for (dtype = ctype->ctype_dlist; dtype != NULL;
			    dtype = dtype->dtype_next) {
				if (strcmp(dtype->dtype_asciilabel, disk) == 0)
					break;
			}
			/*
			 * If no match is found, it's an error.
			 */
			if (dtype == NULL) {
				datafile_error("Unknown disk '%s'", disk);
				return;
			}
			/*
			 * Now that we know the disk type, set up the
			 * globals that let that magic macro "spc()"
			 * do it's thing.  Sorry that this is glued
			 * together so poorly...
			 */
			nhead = dtype->dtype_nhead;
			nsect = dtype->dtype_nsect;
			acyl = dtype->dtype_acyl;
			ncyl = dtype->dtype_ncyl;
		}
		/*
		 * By now, the disk and controller type must be defined
		 */
		if (dtype == NULL || ctype == NULL) {
			datafile_error("Incomplete specification", "");
			return;
		}
		/*
		 * The rest of the attributes are all single letters.
		 * Make sure the specified attribute is a single letter.
		 */
		if (strlen(ident) != 1) {
			datafile_error("Unknown keyword '%s'", ident);
			return;
		}
		/*
		 * Also make sure it is within the legal range of letters.
		 */
		if (ident[0] < PARTITION_BASE || ident[0] > PARTITION_BASE+9) {
			datafile_error("Unknown keyword '%s'", ident);
			return;
		}
		/*
		 * Here's the index of the partition we're dealing with
		 */
		index = ident[0] - PARTITION_BASE;
		/*
		 * For SunOS 5.0, we support the additional syntax:
		 *	[<tag>, ] [<flag>, ] <start>, <end>
		 * instead of:
		 *	<start>, <end>
		 *
		 * <tag> may be one of: boot, root, swap, etc.
		 * <flag> consists of two characters:
		 *	W (writable) or R (read-only)
		 *	M (mountable) or U (unmountable)
		 *
		 * Start with the defaults assigned above:
		 */
		vtoc_tag = pinfo->vtoc.v_part[index].p_tag;
		vtoc_flag = pinfo->vtoc.v_part[index].p_flag;

		/*
		 * First try to match token against possible tag values
		 */
		if (find_value(ptag_choices, cleaned, &i) == 1) {
			/*
			 * Found valid tag. Use it and advance parser
			 */
			vtoc_tag = (ushort_t)i;
			status = sup_gettoken(token);
			if (status != SUP_COMMA) {
				datafile_error(
				    "Expecting ', ', found '%s'", token);
				return;
			}
			status = sup_gettoken(token);
			if (status != SUP_STRING) {
				datafile_error("Expecting value, found '%s'",
				    token);
				return;
			}
			clean_token(cleaned, token);
		}

		/*
		 * Try to match token against possible flag values
		 */
		if (find_value(pflag_choices, cleaned, &i) == 1) {
			/*
			 * Found valid flag. Use it and advance parser
			 */
			vtoc_flag = (ushort_t)i;
			status = sup_gettoken(token);
			if (status != SUP_COMMA) {
				datafile_error("Expecting ', ', found '%s'",
				    token);
				return;
			}
			status = sup_gettoken(token);
			if (status != SUP_STRING) {
				datafile_error("Expecting value, found '%s'",
				    token);
				return;
			}
			clean_token(cleaned, token);
		}
		/*
		 * All other attributes have a pair of numeric values.
		 * Convert the first value to a number.  This value
		 * is the starting cylinder number of the partition.
		 */
		val1 = str2cyls(cleaned);
		if (val1 == (uint_t)(-1)) {
			datafile_error("Expecting an integer, found '%s'",
			    cleaned);
			return;
		}
		/*
		 * Pull in some grammar.
		 */
		status = sup_gettoken(token);
		if (status != SUP_COMMA) {
			datafile_error("Expecting ', ', found '%s'", token);
			return;
		}
		/*
		 * Pull in the second value.
		 */
		status = sup_gettoken(token);
		if (status != SUP_STRING) {
			datafile_error("Expecting value, found '%s'", token);
			return;
		}
		clean_token(cleaned, token);
		/*
		 * Convert the second value to a number.  This value
		 * is the number of blocks composing the partition.
		 * If the token is terminated with a 'c', the units
		 * are cylinders, not blocks.  Also accept a 'b', if
		 * they choose to be so specific.
		 */
		val2 = str2blks(cleaned);
		if (val2 == (uint_t)(-1)) {
			datafile_error("Expecting an integer, found '%s'",
			    cleaned);
			return;
		}
		/*
		 * Fill in the appropriate map entry with the values.
		 */
		pinfo->pinfo_map[index].dkl_cylno = val1;
		pinfo->pinfo_map[index].dkl_nblk = val2;
		pinfo->vtoc.v_part[index].p_tag = vtoc_tag;
		pinfo->vtoc.v_part[index].p_flag = vtoc_flag;

#if defined(_SUNOS_VTOC_16)
		pinfo->vtoc.v_part[index].p_start = val1 * (nhead * nsect);
		pinfo->vtoc.v_part[index].p_size = val2;

		if (val2 == 0) {
			pinfo->vtoc.v_part[index].p_tag = 0;
			pinfo->vtoc.v_part[index].p_flag = 0;
			pinfo->vtoc.v_part[index].p_start = 0;
			pinfo->pinfo_map[index].dkl_cylno = 0;
		}
#endif /* defined(_SUNOS_VTOC_16) */

	}
	/*
	 * Check to be sure that all necessary attributes were defined.
	 */
	if ((flags & SUP_MIN_PART) != SUP_MIN_PART) {
		datafile_error("Incomplete specification", "");
		return;
	}
	/*
	 * Add this partition map to the list of known maps for the
	 * specified disk/ctlr.
	 */
	parts = dtype->dtype_plist;
	if (parts == NULL)
		dtype->dtype_plist = pinfo;
	else {
		while (parts->pinfo_next != NULL)
			parts = parts->pinfo_next;
		parts->pinfo_next = pinfo;
	}
}

/*
 * Open the disk device - just a wrapper for open.
 */
int
open_disk(char *diskname, int flags)
{
	return (open(diskname, flags));
}

/*
 * This routine performs the disk search during startup.  It looks for
 * all the disks in the search path, and creates a list of those that
 * are found.
 */
void
do_search(char *arglist[])
{
	char			**sp;
	DIR			*dir;
	struct dirent		*dp;
	char			s[MAXPATHLEN];
	char			path[MAXPATHLEN];
	char			curdir[MAXPATHLEN];
	char			*directory = "/dev/rdsk";
	struct disk_info	*disk;
	int			i;

	/*
	 * Change directory to the device directory.  This
	 * gives us the most efficient access to that directory.
	 * Remember where we were, and return there when finished.
	 */
	if (getcwd(curdir, sizeof (curdir)) == NULL) {
		err_print("Cannot get current directory - %s\n",
		    strerror(errno));
		fullabort();
	}
	if (chdir(directory) == -1) {
		err_print("Cannot set directory to %s - %s\n",
		    directory, strerror(errno));
		fullabort();
	}

	/*
	 * If there were disks specified on the command line,
	 * use those disks, and nothing but those disks.
	 */
	if (arglist != NULL) {
		check_for_duplicate_disknames(arglist);
		for (; *arglist != NULL; arglist++) {
			search_for_logical_dev(*arglist);
		}
	} else {
		/*
		 * If there were no disks specified on the command line,
		 * search for all disks attached to the system.
		 */
		fmt_print("Searching for disks...");
		(void) fflush(stdout);
		need_newline = 1;

		/*
		 * Find all disks specified in search_path definitions
		 * in whatever format.dat files were processed.
		 */
		sp = search_path;
		if (sp != NULL) {
			while (*sp != NULL) {
				search_for_logical_dev(*sp++);
			}
		}

		/*
		 * Open the device directory
		 */
		if ((dir = opendir(".")) == NULL) {
			err_print("Cannot open %s - %s\n",
			    directory, strerror(errno));
			fullabort();
		}

		/*
		 * Now find all usable nodes in /dev/rdsk (or /dev, if 4.x)
		 * First find all nodes which do not conform to
		 * standard disk naming conventions.  This permits
		 * all user-defined names to override the default names.
		 */
		while ((dp = readdir(dir)) != NULL) {
			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0)
				continue;
			if (!conventional_name(dp->d_name)) {
				if (!fdisk_physical_name(dp->d_name)) {
					/*
					 * If non-conventional name represents
					 * a link to non-s2 slice , ignore it.
					 */
					if (!name_represents_wholedisk
					    (dp->d_name)) {
						(void) strcpy(path, directory);
						(void) strcat(path, "/");
						(void) strcat(path, dp->d_name);
						add_device_to_disklist(
						    dp->d_name, path);
					}
				}
			}
		}
		rewinddir(dir);


		/*
		 * Now find all nodes corresponding to the standard
		 * device naming conventions.
		 */
		while ((dp = readdir(dir)) != NULL) {
			if (strcmp(dp->d_name, ".") == 0 ||
			    strcmp(dp->d_name, "..") == 0)
				continue;
			if (whole_disk_name(dp->d_name)) {
				(void) strcpy(path, directory);
				(void) strcat(path, "/");
				(void) strcat(path, dp->d_name);
				canonicalize_name(s, dp->d_name);
				add_device_to_disklist(s, path);
			}
		}
		/*
		 * Close the directory
		 */
		if (closedir(dir) == -1) {
			err_print("Cannot close directory %s - %s\n",
			    directory, strerror(errno));
			fullabort();
		}

		need_newline = 0;
		fmt_print("done\n");
	}

	/*
	 * Return to whence we came
	 */
	if (chdir(curdir) == -1) {
		err_print("Cannot set directory to %s - %s\n",
		    curdir, strerror(errno));
		fullabort();
	}

	/*
	 * If we didn't find any disks, give up.
	 */
	if (disk_list == NULL) {
		if (geteuid() == 0) {
			err_print("No disks found!\n");
		} else {
			err_print("No permission (or no disks found)!\n");
		}
		(void) fflush(stdout);
		fullabort();
	}

	sort_disk_list();

	/*
	 * Tell user the results of the auto-configure process
	 */
	i = 0;
	for (disk = disk_list; disk != NULL; disk = disk->disk_next) {
		float			scaled;
		diskaddr_t		nblks;
		struct disk_type	*type;
		if (disk->disk_flags & DSK_AUTO_CONFIG) {
			if (i++ == 0) {
				fmt_print("\n");
			}
			fmt_print("%s: ", disk->disk_name);
			if (disk->disk_flags & DSK_LABEL_DIRTY) {
				fmt_print("configured ");
			} else {
				fmt_print("configured and labeled ");
			}
			type = disk->disk_type;
			nblks = type->dtype_ncyl * type->dtype_nhead *
			    type->dtype_nsect;
			if (disk->label_type == L_TYPE_SOLARIS)
				scaled = bn2mb(nblks);
			else
				scaled = bn2mb(type->capacity);
			fmt_print("with capacity of ");
			if (scaled > 1024.0) {
				fmt_print("%1.2fGB\n", scaled/1024.0);
			} else {
				fmt_print("%1.2fMB\n", scaled);
			}
		}
	}
}


/*
 * For a given "logical" disk name as specified in a format.dat
 * search path, try to find the device it actually refers to.
 * Since we are trying to maintain 4.x naming convention
 * compatibility in 5.0, this involves a little bit of work.
 * We also want to be able to function under 4.x, if needed.
 *
 * canonical:	standard name reference.  append a partition
 *	reference, and open that file in the device directory.
 *	examples:	SVR4:	c0t0d0
 *			4.x:	sd0
 *
 * absolute:	begins with a '/', and is assumed to be an
 *	absolute pathname to some node.
 *
 * relative:	non-canonical, doesn't begin with a '/'.
 *	assumed to be the name of a file in the appropriate
 *	device directory.
 */
static void
search_for_logical_dev(char *devname)
{
	char		path[MAXPATHLEN];
	char		*directory = "/dev/rdsk/";
	char		*partition = "s2";

	/*
	 * If the name is an absolute path name, accept it as is
	 */
	if (*devname == '/') {
		(void) strcpy(path, devname);
	} else if (canonical_name(devname)) {
		/*
		 * If canonical name, construct a standard path name.
		 */
		(void) strcpy(path, directory);
		(void) strcat(path, devname);
		(void) strcat(path, partition);
	} else if (canonical4x_name(devname)) {
		/*
		 * Check to see if it's a 4.x file name in the /dev
		 * directory on 5.0.  Here, we only accept the
		 * canonicalized form: sd0.
		 */
		(void) strcpy(path, "/dev/r");
		(void) strcat(path, devname);
		(void) strcat(path, "c");
	} else {
		/*
		 * If it's not a canonical name, then it may be a
		 * reference to an actual file name in the device
		 * directory itself.
		 */
		(void) strcpy(path, directory);
		(void) strcat(path, devname);
	}

	/* now add the device */
	add_device_to_disklist(devname, path);
}

/*
 * Get the disk name from the inquiry data
 */
static void
get_disk_name(int fd, char *disk_name)
{
	struct scsi_inquiry	inquiry;

	if (uscsi_inquiry(fd, (char *)&inquiry, sizeof (inquiry))) {
		if (option_msg)
			err_print("\nInquiry failed - %s\n", strerror(errno));
		(void) strcpy(disk_name, "Unknown-Unknown-0001");
		return;
	}

	(void) get_generic_disk_name(disk_name, &inquiry);
}

/*
 * Add a device to the disk list, if it appears to be a disk,
 * and we haven't already found it under some other name.
 */
static void
add_device_to_disklist(char *devname, char *devpath)
{
	struct disk_info	*search_disk;
	struct ctlr_info	*search_ctlr;
	struct disk_type	*search_dtype, *efi_disk;
	struct partition_info	*search_parts;
	struct disk_info	*dptr;
	struct ctlr_info	*cptr;
	struct disk_type	*type;
	struct partition_info	*parts;
	struct dk_label		search_label;
	struct dk_cinfo		dkinfo;
	struct stat		stbuf;
	struct ctlr_type	*ctlr, *tctlr;
	struct	mctlr_list	*mlp;
	struct	efi_info	efi_info;
	struct dk_minfo		mediainfo;
	int			search_file;
	int			status;
	int			i;
	int			access_flags = 0;
	char			disk_name[MAXNAMELEN];

	/*
	 * Attempt to open the disk.  If it fails, skip it.
	 */
	if ((search_file = open_disk(devpath, O_RDWR | O_NDELAY)) < 0) {
		return;
	}
	/*
	 * Must be a character device
	 */
	if (fstat(search_file, &stbuf) == -1 || !S_ISCHR(stbuf.st_mode)) {
		(void) close(search_file);
		return;
	}
	/*
	 * Attempt to read the configuration info on the disk.
	 * Again, if it fails, we assume the disk's not there.
	 * Note we must close the file for the disk before we
	 * continue.
	 */
	if (ioctl(search_file, DKIOCINFO, &dkinfo) < 0) {
		(void) close(search_file);
		return;
	}

	/* If it is a removable media, skip it. */

	if (!expert_mode) {
		int isremovable, ret;
		ret = ioctl(search_file, DKIOCREMOVABLE, &isremovable);
		if ((ret >= 0) && (isremovable != 0)) {
			(void) close(search_file);
			return;
		}
	}

	if (ioctl(search_file, DKIOCGMEDIAINFO, &mediainfo) == -1) {
		cur_blksz = DEV_BSIZE;
	} else {
		cur_blksz = mediainfo.dki_lbsize;
	}

	/*
	 * If the type of disk is one we don't know about,
	 * add it to the list.
	 */
	mlp = controlp;

	while (mlp != NULL) {
		if (mlp->ctlr_type->ctype_ctype == dkinfo.dki_ctype) {
			break;
		}
		mlp = mlp->next;
	}

	if (mlp == NULL) {
		if (dkinfo.dki_ctype == DKC_CDROM) {
			if (ioctl(search_file, DKIOCGMEDIAINFO,
			    &mediainfo) < 0) {
				mediainfo.dki_media_type = DK_UNKNOWN;
			}
		}
		/*
		 * Skip CDROM devices, they are read only.
		 * But not devices like Iomega Rev Drive which
		 * identifies itself as a CDROM, but has a removable
		 * disk.
		 */
		if ((dkinfo.dki_ctype == DKC_CDROM) &&
		    (mediainfo.dki_media_type != DK_REMOVABLE_DISK)) {
			(void) close(search_file);
			return;
		}
		/*
		 * create the new ctlr_type structure and fill it in.
		 */
		tctlr = zalloc(sizeof (struct ctlr_type));
		tctlr->ctype_ctype = dkinfo.dki_ctype;
		tctlr->ctype_name = zalloc(DK_DEVLEN);
		if (strlcpy(tctlr->ctype_name, dkinfo.dki_cname,
		    DK_DEVLEN) > DK_DEVLEN) {
			/*
			 * DKIOCINFO returned a controller name longer
			 * than DK_DEVLEN bytes, which means more of the
			 * dk_cinfo structure may be corrupt.  We don't
			 * allow the user to perform any operations on
			 * the device in this case
			 */
			err_print("\nError: Device %s: controller "
			    "name (%s)\nis invalid.  Device will not "
			    "be displayed.\n", devname, dkinfo.dki_cname);
			(void) close(search_file);
			destroy_data(tctlr->ctype_name);
			destroy_data((char *)tctlr);
			return;
		} else {
			tctlr->ctype_ops = zalloc(sizeof (struct ctlr_ops));

			/*
			 * copy the generic disk ops structure into local copy.
			 */
			*(tctlr->ctype_ops) = genericops;

			tctlr->ctype_flags = CF_WLIST;

			mlp = controlp;

			while (mlp->next != NULL) {
				mlp = mlp->next;
			}

			mlp->next = zalloc(sizeof (struct mctlr_list));
			mlp->next->ctlr_type = tctlr;
		}
	}

	/*
	 * Search through all disks known at this time, to
	 * determine if we're already identified this disk.
	 * If so, then there's no need to include it a
	 * second time.  This permits the user-defined names
	 * to supercede the standard conventional names.
	 */
	if (disk_is_known(&dkinfo)) {
		(void) close(search_file);
		return;
	}
#if defined(sparc)
	/*
	 * Because opening id with FNDELAY always succeeds,
	 * read the label early on to see whether the device
	 * really exists.  A result of DSK_RESERVED
	 * means the disk may be reserved.
	 * In the future, it will be good
	 * to move these into controller specific files and have a common
	 * generic check for reserved disks here, including intel disks.
	 */
	if (dkinfo.dki_ctype == DKC_SCSI_CCS) {
		char	*first_sector;

		first_sector = zalloc(cur_blksz);
		i = scsi_rdwr(DIR_READ, search_file, (diskaddr_t)0,
		    1, first_sector, F_SILENT, NULL);
		switch (i) {
		case DSK_RESERVED:
			access_flags |= DSK_RESERVED;
			break;
		case DSK_UNAVAILABLE:
			access_flags |= DSK_UNAVAILABLE;
			break;
		default:
			break;
		}
		free(first_sector);
	}
#endif /* defined(sparc) */

	/*
	 * The disk appears to be present.  Allocate space for the
	 * disk structure and add it to the list of found disks.
	 */
	search_disk = (struct disk_info *)zalloc(sizeof (struct disk_info));
	if (disk_list == NULL)
		disk_list = search_disk;
	else {
		for (dptr = disk_list; dptr->disk_next != NULL;
		    dptr = dptr->disk_next)
			;
		dptr->disk_next = search_disk;
	}
	/*
	 * Fill in some info from the ioctls.
	 */
	search_disk->disk_dkinfo = dkinfo;
	if (is_efi_type(search_file)) {
		search_disk->label_type = L_TYPE_EFI;
	} else {
		search_disk->label_type = L_TYPE_SOLARIS;
	}
	/*
	 * Remember the names of the disk
	 */
	search_disk->disk_name = alloc_string(devname);
	search_disk->disk_path = alloc_string(devpath);

	/*
	 * Remember the lba size of the disk
	 */
	search_disk->disk_lbasize = cur_blksz;

	(void) strcpy(x86_devname, devname);

	/*
	 * Determine if this device is linked to a physical name.
	 */
	search_disk->devfs_name = get_physical_name(devpath);

	/*
	 * Try to match the ctlr for this disk with a ctlr we
	 * have already found.  A match is assumed if the ctlrs
	 * are at the same address && ctypes agree
	 */
	for (search_ctlr = ctlr_list; search_ctlr != NULL;
	    search_ctlr = search_ctlr->ctlr_next)
		if (search_ctlr->ctlr_addr == dkinfo.dki_addr &&
		    search_ctlr->ctlr_space == dkinfo.dki_space &&
		    search_ctlr->ctlr_ctype->ctype_ctype ==
		    dkinfo.dki_ctype)
			break;
	/*
	 * If no match was found, we need to identify this ctlr.
	 */
	if (search_ctlr == NULL) {
		/*
		 * Match the type of the ctlr to a known type.
		 */
		mlp = controlp;

		while (mlp != NULL) {
			if (mlp->ctlr_type->ctype_ctype == dkinfo.dki_ctype)
				break;
			mlp = mlp->next;
		}
		/*
		 * If no match was found, it's an error.
		 * Close the disk and report the error.
		 */
		if (mlp == NULL) {
			err_print("\nError: found disk attached to ");
			err_print("unsupported controller type '%d'.\n",
			    dkinfo.dki_ctype);
			(void) close(search_file);
			return;
		}
		/*
		 * Allocate space for the ctlr structure and add it
		 * to the list of found ctlrs.
		 */
		search_ctlr = (struct ctlr_info *)
		    zalloc(sizeof (struct ctlr_info));
		search_ctlr->ctlr_ctype = mlp->ctlr_type;
		if (ctlr_list == NULL)
			ctlr_list = search_ctlr;
		else {
			for (cptr = ctlr_list; cptr->ctlr_next != NULL;
			    cptr = cptr->ctlr_next)
				;
			cptr->ctlr_next = search_ctlr;
		}
		/*
		 * Fill in info from the ioctl.
		 */
		for (i = 0; i < DK_DEVLEN; i++) {
			search_ctlr->ctlr_cname[i] = dkinfo.dki_cname[i];
			search_ctlr->ctlr_dname[i] = dkinfo.dki_dname[i];
		}
		/*
		 * Make sure these can be used as simple strings
		 */
		search_ctlr->ctlr_cname[i] = 0;
		search_ctlr->ctlr_dname[i] = 0;

		search_ctlr->ctlr_flags = dkinfo.dki_flags;
		search_ctlr->ctlr_num = dkinfo.dki_cnum;
		search_ctlr->ctlr_addr = dkinfo.dki_addr;
		search_ctlr->ctlr_space = dkinfo.dki_space;
		search_ctlr->ctlr_prio = dkinfo.dki_prio;
		search_ctlr->ctlr_vec = dkinfo.dki_vec;
	}
	/*
	 * By this point, we have a known ctlr.  Link the disk
	 * to the ctlr.
	 */
	search_disk->disk_ctlr = search_ctlr;
	if (access_flags & (DSK_RESERVED | DSK_UNAVAILABLE)) {
		if (access_flags & DSK_RESERVED)
			search_disk->disk_flags |= DSK_RESERVED;
		else
			search_disk->disk_flags |= DSK_UNAVAILABLE;
		(void) close(search_file);
		return;
	} else {
		search_disk->disk_flags &= ~(DSK_RESERVED | DSK_UNAVAILABLE);
	}

	/*
	 * Attempt to read the primary label.
	 * (Note that this is really through the DKIOCGVTOC
	 * ioctl, then converted from vtoc to label.)
	 */
	if (search_disk->label_type == L_TYPE_SOLARIS) {
		status = read_label(search_file, &search_label);
	} else {
		status = read_efi_label(search_file, &efi_info);
	}
	/*
	 * If reading the label failed, and this is a SCSI
	 * disk, we can attempt to auto-sense the disk
	 * Configuration.
	 */
	ctlr = search_ctlr->ctlr_ctype;
	if ((status == -1) && (ctlr->ctype_ctype == DKC_SCSI_CCS)) {
		if (option_msg && diag_msg) {
			err_print("%s: attempting auto configuration\n",
			    search_disk->disk_name);
		}

		switch (search_disk->label_type) {
		case (L_TYPE_SOLARIS):
			if (auto_sense(search_file, 0, &search_label) != NULL) {
			/*
			 * Auto config worked, so we now have
			 * a valid label for the disk.  Mark
			 * the disk as needing the label flushed.
			 */
				status = 0;
				search_disk->disk_flags |=
				    (DSK_LABEL_DIRTY | DSK_AUTO_CONFIG);
			}
			break;
		case (L_TYPE_EFI):
			efi_disk = auto_efi_sense(search_file, &efi_info);
			if (efi_disk != NULL) {
				/*
				 * Auto config worked, so we now have
				 * a valid label for the disk.
				 */
				status = 0;
				search_disk->disk_flags |=
				    (DSK_LABEL_DIRTY | DSK_AUTO_CONFIG);
			}
			break;
		default:
			/* Should never happen */
			break;
		}
	}

	/*
	 * If we didn't successfully read the label, or the label
	 * appears corrupt, just leave the disk as an unknown type.
	 */
	if (status == -1) {
		(void) close(search_file);
		return;
	}

	if (search_disk->label_type == L_TYPE_SOLARIS) {
		if (!checklabel(&search_label)) {
			(void) close(search_file);
			return;
		}
		if (trim_id(search_label.dkl_asciilabel)) {
			(void) close(search_file);
			return;
		}
	}
	/*
	 * The label looks ok.  Mark the disk as labeled.
	 */
	search_disk->disk_flags |= DSK_LABEL;

	if (search_disk->label_type == L_TYPE_EFI) {
		search_dtype = (struct disk_type *)
		    zalloc(sizeof (struct disk_type));
		type = search_ctlr->ctlr_ctype->ctype_dlist;
		if (type == NULL) {
			search_ctlr->ctlr_ctype->ctype_dlist =
			    search_dtype;
		} else {
			while (type->dtype_next != NULL) {
				type = type->dtype_next;
			}
			type->dtype_next = search_dtype;
		}
		search_dtype->dtype_next = NULL;

		(void) strlcpy(search_dtype->vendor, efi_info.vendor, 9);
		(void) strlcpy(search_dtype->product, efi_info.product, 17);
		(void) strlcpy(search_dtype->revision, efi_info.revision, 5);
		search_dtype->capacity = efi_info.capacity;
		search_disk->disk_type = search_dtype;

		search_parts = (struct partition_info *)
		    zalloc(sizeof (struct partition_info));
		search_dtype->dtype_plist = search_parts;

		search_parts->pinfo_name = alloc_string("original");
		search_parts->pinfo_next = NULL;
		search_parts->etoc = efi_info.e_parts;
		search_disk->disk_parts = search_parts;

		/*
		 * Copy the volume name, if present
		 */
		for (i = 0; i < search_parts->etoc->efi_nparts; i++) {
			if (search_parts->etoc->efi_parts[i].p_tag ==
			    V_RESERVED) {
				if (search_parts->etoc->efi_parts[i].p_name) {
					bcopy(search_parts->etoc->efi_parts[i]
					    .p_name, search_disk->v_volume,
					    LEN_DKL_VVOL);
				} else {
					bzero(search_disk->v_volume,
					    LEN_DKL_VVOL);
				}
				break;
			}
		}
		(void) close(search_file);
		return;
	}

	/*
	 * Attempt to match the disk type in the label with a
	 * known disk type.
	 */
	for (search_dtype = search_ctlr->ctlr_ctype->ctype_dlist;
	    search_dtype != NULL;
	    search_dtype = search_dtype->dtype_next)
		if (dtype_match(&search_label, search_dtype))
			break;
	/*
	 * If no match was found, we need to create a disk type
	 * for this disk.
	 */
	if (search_dtype == NULL) {
		/*
		 * Allocate space for the disk type and add it
		 * to the list of disk types for this ctlr type.
		 */
		search_dtype = (struct disk_type *)
		    zalloc(sizeof (struct disk_type));
		type = search_ctlr->ctlr_ctype->ctype_dlist;
		if (type == NULL)
			search_ctlr->ctlr_ctype->ctype_dlist =
			    search_dtype;
		else {
			while (type->dtype_next != NULL)
				type = type->dtype_next;
			type->dtype_next = search_dtype;
		}
		/*
		 * Fill in the drive info from the disk label.
		 */
		search_dtype->dtype_next = NULL;
		if (strncmp(search_label.dkl_asciilabel, "DEFAULT",
		    strlen("DEFAULT")) == 0) {
			(void) get_disk_name(search_file, disk_name);
			search_dtype->dtype_asciilabel = (char *)
			    zalloc(strlen(disk_name) + 1);
			(void) strcpy(search_dtype->dtype_asciilabel,
			    disk_name);
		} else {
			search_dtype->dtype_asciilabel = (char *)
			    zalloc(strlen(search_label.dkl_asciilabel) + 1);
			(void) strcpy(search_dtype->dtype_asciilabel,
			    search_label.dkl_asciilabel);
		}
		search_dtype->dtype_pcyl = search_label.dkl_pcyl;
		search_dtype->dtype_ncyl = search_label.dkl_ncyl;
		search_dtype->dtype_acyl = search_label.dkl_acyl;
		search_dtype->dtype_nhead = search_label.dkl_nhead;
		search_dtype->dtype_nsect = search_label.dkl_nsect;
		search_dtype->dtype_rpm = search_label.dkl_rpm;
		/*
		 * Mark the disk as needing specification of
		 * ctlr specific attributes.  This is necessary
		 * because the label doesn't contain these attributes,
		 * and they aren't known at this point.  They will
		 * be asked for if this disk is ever selected by
		 * the user.
		 * Note: for SCSI, we believe the label.
		 */
		if ((search_ctlr->ctlr_ctype->ctype_ctype != DKC_SCSI_CCS) &&
		    (search_ctlr->ctlr_ctype->ctype_ctype != DKC_DIRECT) &&
		    (search_ctlr->ctlr_ctype->ctype_ctype != DKC_VBD) &&
		    (search_ctlr->ctlr_ctype->ctype_ctype != DKC_PCMCIA_ATA) &&
		    (search_ctlr->ctlr_ctype->ctype_ctype != DKC_BLKDEV)) {
			search_dtype->dtype_flags |= DT_NEED_SPEFS;
		}
	}
	/*
	 * By this time we have a known disk type.  Link the disk
	 * to the disk type.
	 */
	search_disk->disk_type = search_dtype;

	/*
	 * Close the file for this disk
	 */
	(void) close(search_file);

	/*
	 * Attempt to match the partition map in the label with
	 * a known partition map for this disk type.
	 */
	for (search_parts = search_dtype->dtype_plist;
	    search_parts != NULL;
	    search_parts = search_parts->pinfo_next)
		if (parts_match(&search_label, search_parts)) {
			break;
		}
	/*
	 * If no match was made, we need to create a partition
	 * map for this disk.
	 */
	if (search_parts == NULL) {
		/*
		 * Allocate space for the partition map and add
		 * it to the list of maps for this disk type.
		 */
		search_parts = (struct partition_info *)
		    zalloc(sizeof (struct partition_info));
		parts = search_dtype->dtype_plist;
		if (parts == NULL)
			search_dtype->dtype_plist = search_parts;
		else {
			while (parts->pinfo_next != NULL)
				parts = parts->pinfo_next;
			parts->pinfo_next = search_parts;
		}
		search_parts->pinfo_next = NULL;
		/*
		 * Fill in the name of the map with a name derived
		 * from the name of this disk.  This is necessary
		 * because the label contains no name for the
		 * partition map.
		 */
		search_parts->pinfo_name = alloc_string("original");
		/*
		 * Fill in the partition info from the disk label.
		 */
		for (i = 0; i < NDKMAP; i++) {

#if defined(_SUNOS_VTOC_8)
			search_parts->pinfo_map[i] =
			    search_label.dkl_map[i];

#elif defined(_SUNOS_VTOC_16)
			search_parts->pinfo_map[i].dkl_cylno =
			    search_label.dkl_vtoc.v_part[i].p_start /
			    ((blkaddr32_t)(search_label.dkl_nhead *
			    search_label.dkl_nsect));
			search_parts->pinfo_map[i].dkl_nblk =
			    search_label.dkl_vtoc.v_part[i].p_size;

#else
#error No VTOC format defined.
#endif
		}
	}
	/*
	 * If the vtoc looks valid, copy the volume name and vtoc
	 * info from the label.  Otherwise, install a default vtoc.
	 * This permits vtoc info to automatically appear in the sun
	 * label, without requiring an upgrade procedure.
	 */
	if (search_label.dkl_vtoc.v_version == V_VERSION) {
		bcopy(search_label.dkl_vtoc.v_volume,
		    search_disk->v_volume, LEN_DKL_VVOL);
		search_parts->vtoc = search_label.dkl_vtoc;
	} else {
		bzero(search_disk->v_volume, LEN_DKL_VVOL);
		set_vtoc_defaults(search_parts);
	}
	/*
	 * By this time we have a known partitition map.  Link the
	 * disk to the partition map.
	 */
	search_disk->disk_parts = search_parts;
}


/*
 * Search the disk list for a disk with the identical configuration.
 * Return true if one is found.
 */
static int
disk_is_known(struct dk_cinfo *dkinfo)
{
	struct disk_info	*dp;

	dp = disk_list;
	while (dp != NULL) {
		if (dp->disk_dkinfo.dki_ctype == dkinfo->dki_ctype &&
		    dp->disk_dkinfo.dki_cnum == dkinfo->dki_cnum &&
		    dp->disk_dkinfo.dki_unit == dkinfo->dki_unit &&
		    strcmp(dp->disk_dkinfo.dki_dname, dkinfo->dki_dname) == 0) {
			return (1);
		}
		dp = dp->disk_next;
	}
	return (0);
}


/*
 * This routine checks to see if a given disk type matches the type
 * in the disk label.
 */
int
dtype_match(label, dtype)
	register struct dk_label *label;
	register struct disk_type *dtype;
{

	if (dtype->dtype_asciilabel == NULL) {
	    return (0);
	}

	/*
	 * If the any of the physical characteristics are different, or
	 * the name is different, it doesn't match.
	 */
	if ((strcmp(label->dkl_asciilabel, dtype->dtype_asciilabel) != 0) ||
	    (label->dkl_ncyl != dtype->dtype_ncyl) ||
	    (label->dkl_acyl != dtype->dtype_acyl) ||
	    (label->dkl_nhead != dtype->dtype_nhead) ||
	    (label->dkl_nsect != dtype->dtype_nsect)) {
		return (0);
	}
	/*
	 * If those are all identical, assume it's a match.
	 */
	return (1);
}

/*
 * This routine checks to see if a given partition map matches the map
 * in the disk label.
 */
int
parts_match(label, pinfo)
	register struct dk_label *label;
	register struct partition_info *pinfo;
{
	int i;

	/*
	 * If any of the partition entries is different, it doesn't match.
	 */
	for (i = 0; i < NDKMAP; i++)

#if defined(_SUNOS_VTOC_8)
		if ((label->dkl_map[i].dkl_cylno !=
		    pinfo->pinfo_map[i].dkl_cylno) ||
		    (label->dkl_map[i].dkl_nblk !=
		    pinfo->pinfo_map[i].dkl_nblk))

#elif defined(_SUNOS_VTOC_16)
		if ((pinfo->pinfo_map[i].dkl_cylno !=
		    label->dkl_vtoc.v_part[i].p_start /
		    (label->dkl_nhead * label->dkl_nsect)) ||
		    (pinfo->pinfo_map[i].dkl_nblk !=
		    label->dkl_vtoc.v_part[i].p_size))
#else
#error No VTOC format defined.
#endif
			return (0);
	/*
	 * Compare the vtoc information for a match
	 * Do not require the volume name to be equal, for a match!
	 */
	if (label->dkl_vtoc.v_version != pinfo->vtoc.v_version)
		return (0);
	if (label->dkl_vtoc.v_nparts != pinfo->vtoc.v_nparts)
		return (0);
	for (i = 0; i < NDKMAP; i++) {
		if (label->dkl_vtoc.v_part[i].p_tag !=
				pinfo->vtoc.v_part[i].p_tag)
			return (0);
		if (label->dkl_vtoc.v_part[i].p_flag !=
				pinfo->vtoc.v_part[i].p_flag)
			return (0);
	}
	/*
	 * If they are all identical, it's a match.
	 */
	return (1);
}

/*
 * This routine checks to see if the given disk name refers to the disk
 * in the given disk structure.
 */
int
diskname_match(char *name, struct disk_info *disk)
{
	struct dk_cinfo		dkinfo;
	char			s[MAXPATHLEN];
	int			fd;

	/*
	 * Match the name of the disk in the disk_info structure
	 */
	if (strcmp(name, disk->disk_name) == 0) {
		return (1);
	}

	/*
	 * Check to see if it's a 4.x file name in the /dev
	 * directory on 5.0.  Here, we only accept the
	 * canonicalized form: sd0.
	 */
	if (canonical4x_name(name) == 0) {
		return (0);
	}

	(void) strcpy(s, "/dev/r");
	(void) strcat(s, name);
	(void) strcat(s, "c");

	if ((fd = open_disk(s, O_RDWR | O_NDELAY)) < 0) {
		return (0);
	}

	if (ioctl(fd, DKIOCINFO, &dkinfo) < 0) {
		(void) close(fd);
		return (0);
	}
	(void) close(fd);

	if (disk->disk_dkinfo.dki_ctype == dkinfo.dki_ctype &&
	    disk->disk_dkinfo.dki_cnum == dkinfo.dki_cnum &&
	    disk->disk_dkinfo.dki_unit == dkinfo.dki_unit &&
	    strcmp(disk->disk_dkinfo.dki_dname, dkinfo.dki_dname) == 0) {
		return (1);
	}
	return (0);
}


static void
datafile_error(char *errmsg, char *token)
{
	int	token_type;
	TOKEN	token_buf;

	/*
	 * Allow us to get by controllers that the other platforms don't
	 * know about.
	 */
	if (errmsg != NULL) {
		err_print(errmsg, token);
		err_print(" - %s (%d)\n", file_name, data_lineno);
	}

	/*
	 * Re-sync the parsing at the beginning of the next line
	 * unless of course we're already there.
	 */
	if (last_token_type != SUP_EOF && last_token_type != SUP_EOL) {
		do {
			token_type = sup_gettoken(token_buf);
		} while (token_type != SUP_EOF && token_type != SUP_EOL);

		if (token_type == SUP_EOF) {
			sup_pushtoken(token_buf, token_type);
		}
	}
}


/*
 * Search through all defined disk types for duplicate entries
 * that are inconsistent with each other.  Disks with different
 * characteristics should be named differently.
 * Note that this function only checks for duplicate disks
 * for the same controller.  It's possible to have two disks with
 * the same name, but defined for different controllers.
 * That may or may not be a problem...
 */
static void
search_duplicate_dtypes()
{
	struct disk_type	*dp1;
	struct disk_type	*dp2;
	struct mctlr_list	*mlp;

	mlp = controlp;

	while (mlp != NULL) {
		dp1 = mlp->ctlr_type->ctype_dlist;
		while (dp1 != NULL) {
			dp2 = dp1->dtype_next;
			while (dp2 != NULL) {
				check_dtypes_for_inconsistency(dp1, dp2);
				dp2 = dp2->dtype_next;
			}
			dp1 = dp1->dtype_next;
		}
	mlp = mlp->next;
	}
}


/*
 * Search through all defined partition types for duplicate entries
 * that are inconsistent with each other.  Partitions with different
 * characteristics should be named differently.
 * Note that this function only checks for duplicate partitions
 * for the same disk.  It's possible to have two partitions with
 * the same name, but defined for different disks.
 * That may or may not be a problem...
 */
static void
search_duplicate_pinfo()
{
	struct disk_type	*dp;
	struct partition_info	*pp1;
	struct partition_info	*pp2;
	struct mctlr_list	*mlp;

	mlp = controlp;

	while (mlp != NULL) {
		dp = mlp->ctlr_type->ctype_dlist;
		while (dp != NULL) {
			pp1 = dp->dtype_plist;
			while (pp1 != NULL) {
				pp2 = pp1->pinfo_next;
				while (pp2 != NULL) {
					check_pinfo_for_inconsistency(pp1, pp2);
					pp2 = pp2->pinfo_next;
				}
				pp1 = pp1->pinfo_next;
			}
			dp = dp->dtype_next;
		}
	mlp = mlp->next;
	}
}


/*
 * Determine if two particular disk definitions are inconsistent.
 * Ie:  same name, but different characteristics.
 * If so, print an error message and abort.
 */
static void
check_dtypes_for_inconsistency(dp1, dp2)
	struct disk_type	*dp1;
	struct disk_type	*dp2;
{
	int		i;
	int		result;
	struct chg_list	*cp1;
	struct chg_list	*cp2;


	/*
	 * If the name's different, we're ok
	 */
	if (strcmp(dp1->dtype_asciilabel, dp2->dtype_asciilabel) != 0) {
		return;
	}

	/*
	 * Compare all the disks' characteristics
	 */
	result = 0;
	result |= (dp1->dtype_flags != dp2->dtype_flags);
	result |= (dp1->dtype_options != dp2->dtype_options);
	result |= (dp1->dtype_fmt_time != dp2->dtype_fmt_time);
	result |= (dp1->dtype_bpt != dp2->dtype_bpt);
	result |= (dp1->dtype_ncyl != dp2->dtype_ncyl);
	result |= (dp1->dtype_acyl != dp2->dtype_acyl);
	result |= (dp1->dtype_pcyl != dp2->dtype_pcyl);
	result |= (dp1->dtype_nhead != dp2->dtype_nhead);
	result |= (dp1->dtype_nsect != dp2->dtype_nsect);
	result |= (dp1->dtype_rpm != dp2->dtype_rpm);
	result |= (dp1->dtype_cyl_skew != dp2->dtype_cyl_skew);
	result |= (dp1->dtype_trk_skew != dp2->dtype_trk_skew);
	result |= (dp1->dtype_trks_zone != dp2->dtype_trks_zone);
	result |= (dp1->dtype_atrks != dp2->dtype_atrks);
	result |= (dp1->dtype_asect != dp2->dtype_asect);
	result |= (dp1->dtype_cache != dp2->dtype_cache);
	result |= (dp1->dtype_threshold != dp2->dtype_threshold);
	result |= (dp1->dtype_read_retries != dp2->dtype_read_retries);
	result |= (dp1->dtype_write_retries != dp2->dtype_write_retries);
	result |= (dp1->dtype_prefetch_min != dp2->dtype_prefetch_min);
	result |= (dp1->dtype_prefetch_max != dp2->dtype_prefetch_max);
	for (i = 0; i < NSPECIFICS; i++) {
		result |= (dp1->dtype_specifics[i] != dp2->dtype_specifics[i]);
	}

	cp1 = dp1->dtype_chglist;
	cp2 = dp2->dtype_chglist;
	while (cp1 != NULL && cp2 != NULL) {
		if (cp1 == NULL || cp2 == NULL) {
			result = 1;
			break;
		}
		result |= (cp1->pageno != cp2->pageno);
		result |= (cp1->byteno != cp2->byteno);
		result |= (cp1->mode != cp2->mode);
		result |= (cp1->value != cp2->value);
		cp1 = cp1->next;
		cp2 = cp2->next;
	}

	if (result) {
		err_print("Inconsistent definitions for disk type '%s'\n",
			dp1->dtype_asciilabel);
		if (dp1->dtype_filename != NULL &&
					dp2->dtype_filename != NULL) {
			err_print("%s (%d) - %s (%d)\n",
				dp1->dtype_filename, dp1->dtype_lineno,
				dp2->dtype_filename, dp2->dtype_lineno);
			}
		fullabort();
	}
}


/*
 * Determine if two particular partition definitions are inconsistent.
 * Ie:  same name, but different characteristics.
 * If so, print an error message and abort.
 */
static void
check_pinfo_for_inconsistency(pp1, pp2)
	struct partition_info	*pp1;
	struct partition_info	*pp2;
{
	int		i;
	int		result;
	struct dk_map32	*map1;
	struct dk_map32	*map2;

#if defined(_SUNOS_VTOC_8)
	struct dk_map2	*vp1;
	struct dk_map2	*vp2;

#elif defined(_SUNOS_VTOC_16)
	struct dkl_partition    *vp1;
	struct dkl_partition    *vp2;
#else
#error No VTOC layout defined.
#endif /* defined(_SUNOS_VTOC_8) */

	/*
	 * If the name's different, we're ok
	 */
	if (strcmp(pp1->pinfo_name, pp2->pinfo_name) != 0) {
		return;
	}

	/*
	 * Compare all the partitions' characteristics
	 */
	result = 0;
	map1 = pp1->pinfo_map;
	map2 = pp2->pinfo_map;
	for (i = 0; i < NDKMAP; i++, map1++, map2++) {
		result |= (map1->dkl_cylno != map2->dkl_cylno);
		result |= (map1->dkl_nblk != map2->dkl_nblk);
	}

	/*
	 * Compare the significant portions of the vtoc information
	 */
	vp1 = pp1->vtoc.v_part;
	vp2 = pp2->vtoc.v_part;
	for (i = 0; i < NDKMAP; i++, vp1++, vp2++) {
		result |= (vp1->p_tag != vp2->p_tag);
		result |= (vp1->p_flag != vp2->p_flag);
	}

	if (result) {
		err_print("Inconsistent definitions for partition type '%s'\n",
			pp1->pinfo_name);
		if (pp1->pinfo_filename != NULL &&
					pp2->pinfo_filename != NULL) {
			err_print("%s (%d) - %s (%d)\n",
				pp1->pinfo_filename, pp1->pinfo_lineno,
				pp2->pinfo_filename, pp2->pinfo_lineno);
			}
		fullabort();
	}
}

/*
 * Convert a string of digits into a block number.
 * The digits are assumed to be a block number unless the
 * the string is terminated by 'c', in which case it is
 * assumed to be in units of cylinders.  Accept a 'b'
 * to explictly specify blocks, for consistency.
 *
 * NB: uses the macro spc(), which requires that the
 * globals nhead/nsect/acyl be set up correctly.
 *
 * Returns -1 in the case of an error.
 */
static uint_t
str2blks(char *str)
{
	int	blks;
	char	*p;

	blks = (int)strtol(str, &p, 0);
	/*
	 * Check what terminated the conversion.
	 */
	if (*p != 0) {
		/*
		 * Units specifier of 'c': convert cylinders to blocks
		 */
		if (*p == 'c') {
			p++;
			blks = blks * spc();
		/*
		 * Ignore a 'b' specifier.
		 */
		} else if (*p == 'b') {
			p++;
		}
		/*
		 * Anthing left over is an error
		 */
		if (*p != 0) {
			blks = -1;
		}
	}

	return (blks);
}
/*
 * Convert a string of digits into a cylinder number.
 * Accept a an optional 'c' specifier, for consistency.
 *
 * Returns -1 in the case of an error.
 */
int
str2cyls(char *str)
{
	int	cyls;
	char	*p;

	cyls = (int)strtol(str, &p, 0);
	/*
	 * Check what terminated the conversion.
	 */
	if (*p != 0) {
		/*
		 * Units specifier of 'c': accept it.
		 */
		if (*p == 'c') {
			p++;
		}
		/*
		 * Anthing left over is an error
		 */
		if (*p != 0) {
			cyls = -1;
		}
	}

	return (cyls);
}


/*
 * Create a new chg_list structure, and append it onto the
 * end of the current chg_list under construction.  By
 * applying changes in the order in which listed in the
 * data file, the changes we make are deterministic.
 * Return a pointer to the new structure, so that the
 * caller can fill in the appropriate information.
 */
static struct chg_list *
new_chg_list(struct disk_type *disk)
{
	struct chg_list		*cp;
	struct chg_list		*nc;

	nc = zalloc(sizeof (struct chg_list));

	if (disk->dtype_chglist == NULL) {
		disk->dtype_chglist = nc;
	} else {
		for (cp = disk->dtype_chglist; cp->next; cp = cp->next)
			;
		cp->next = nc;
	}
	nc->next = NULL;
	return (nc);
}


/*
 * Follow symbolic links from the logical device name to
 * the /devfs physical device name.  To be complete, we
 * handle the case of multiple links.  This function
 * either returns NULL (no links, or some other error),
 * or the physical device name, alloc'ed on the heap.
 *
 * Note that the standard /devices prefix is stripped from
 * the final pathname, if present.  The trailing options
 * are also removed (":c, raw").
 */
static char *
get_physical_name(char *path)
{
	struct stat	stbuf;
	int		i;
	int		level;
	char		*p;
	char		s[MAXPATHLEN];
	char		buf[MAXPATHLEN];
	char		dir[MAXPATHLEN];
	char		savedir[MAXPATHLEN];
	char		*result = NULL;

	if (getcwd(savedir, sizeof (savedir)) == NULL) {
		err_print("getcwd() failed - %s\n", strerror(errno));
		return (NULL);
	}

	(void) strcpy(s, path);
	if ((p = strrchr(s, '/')) != NULL) {
		*p = 0;
	}
	if (s[0] == 0) {
		(void) strcpy(s, "/");
	}
	if (chdir(s) == -1) {
		err_print("cannot chdir() to %s - %s\n",
		    s, strerror(errno));
		goto exit;
	}

	level = 0;
	(void) strcpy(s, path);
	for (;;) {
		/*
		 * See if there's a real file out there.  If not,
		 * we have a dangling link and we ignore it.
		 */
		if (stat(s, &stbuf) == -1) {
			goto exit;
		}
		if (lstat(s, &stbuf) == -1) {
			err_print("%s: lstat() failed - %s\n",
			    s, strerror(errno));
			goto exit;
		}
		/*
		 * If the file is not a link, we're done one
		 * way or the other.  If there were links,
		 * return the full pathname of the resulting
		 * file.
		 */
		if (!S_ISLNK(stbuf.st_mode)) {
			if (level > 0) {
				/*
				 * Strip trailing options from the
				 * physical device name
				 */
				if ((p = strrchr(s, ':')) != NULL) {
					*p = 0;
				}
				/*
				 * Get the current directory, and
				 * glue the pieces together.
				 */
				if (getcwd(dir, sizeof (dir)) == NULL) {
					err_print("getcwd() failed - %s\n",
					    strerror(errno));
					goto exit;
				}
				(void) strcat(dir, "/");
				(void) strcat(dir, s);
				/*
				 * If we have the standard fixed
				 * /devices prefix, remove it.
				 */
				p = (strstr(dir, DEVFS_PREFIX) == dir) ?
				    dir+strlen(DEVFS_PREFIX) : dir;
				result = alloc_string(p);
			}
			goto exit;
		}
		i = readlink(s, buf, sizeof (buf));
		if (i == -1) {
			err_print("%s: readlink() failed - %s\n",
			    s, strerror(errno));
			goto exit;
		}
		level++;
		buf[i] = 0;

		/*
		 * Break up the pathname into the directory
		 * reference, if applicable and simple filename.
		 * chdir()'ing to the directory allows us to
		 * handle links with relative pathnames correctly.
		 */
		(void) strcpy(dir, buf);
		if ((p = strrchr(dir, '/')) != NULL) {
			*p = 0;
			if (chdir(dir) == -1) {
				err_print("cannot chdir() to %s - %s\n",
				    dir, strerror(errno));
				goto exit;
			}
			(void) strcpy(s, p+1);
		} else {
			(void) strcpy(s, buf);
		}
	}

exit:
	if (chdir(savedir) == -1) {
		err_print("cannot chdir() to %s - %s\n",
		    savedir, strerror(errno));
	}

	return (result);
}


static void
sort_disk_list()
{
	int			n;
	struct disk_info	**disks;
	struct disk_info	*d;
	struct disk_info	**dp;
	struct disk_info	**dp2;

	/*
	 * Count the number of disks in the list
	 */
	n = 0;
	for (d = disk_list; d != NULL; d = d->disk_next) {
		n++;
	}
	if (n == 0) {
		return;
	}

	/*
	 * Allocate a simple disk list array and fill it in
	 */
	disks = (struct disk_info **)
	    zalloc((n+1) * sizeof (struct disk_info *));

	dp = disks;
	for (d = disk_list; d != NULL; d = d->disk_next) {
		*dp++ = d;
	}
	*dp = NULL;

	/*
	 * Sort the disk list array
	 */
	qsort((void *) disks, n, sizeof (struct disk_info *),
	    disk_name_compare);

	/*
	 * Rebuild the linked list disk list structure
	 */
	dp = disks;
	disk_list = *dp;
	dp2 = dp + 1;
	do {
		(*dp++)->disk_next = *dp2++;
	} while (*dp != NULL);

	/*
	 * Clean up
	 */
	(void) destroy_data((void *)disks);
}


/*
 * Compare two disk names
 */
static int
disk_name_compare(
	const void	*arg1,
	const void	*arg2)
{
	char		*s1;
	char		*s2;
	int		n1;
	int		n2;
	char		*p1;
	char		*p2;

	s1 = (*((struct disk_info **)arg1))->disk_name;
	s2 = (*((struct disk_info **)arg2))->disk_name;

	for (;;) {
		if (*s1 == 0 || *s2 == 0)
			break;
		if (isdigit(*s1) && isdigit(*s2)) {
			n1 = strtol(s1, &p1, 10);
			n2 = strtol(s2, &p2, 10);
			if (n1 != n2) {
				return (n1 - n2);
			}
			s1 = p1;
			s2 = p2;
		} else if (*s1 != *s2) {
			break;
		} else {
			s1++;
			s2++;
		}
	}

	return (*s1 - *s2);
}

static void
make_controller_list()
{
	int	x;
	struct	mctlr_list	*ctlrp;

	ctlrp = controlp;

	for (x = nctypes; x != 0; x--) {
		ctlrp = zalloc(sizeof (struct mctlr_list));
		ctlrp->next = controlp;
		ctlrp->ctlr_type = &ctlr_types[x - 1];
		controlp = ctlrp;

	}
}

static void
check_for_duplicate_disknames(arglist)
char *arglist[];
{
	char			*directory = "/dev/rdsk/";
	char			**disklist;
	int			len;
	char			s[MAXPATHLEN], t[MAXPATHLEN];
	int			diskno = 0;
	int			i;


	len = strlen(directory);
	disklist = arglist;
	for (; *disklist != NULL; disklist++) {
		if (strncmp(directory, *disklist, len) == 0) {
			/* Disk is in conventional format */
			canonicalize_name(s, *disklist);
			/*
			 *  check if the disk is already present in
			 *  disk list.
			 */
			for (i = 0; i < diskno; i++) {
			    canonicalize_name(t, arglist[i]);
			    if (strncmp(s, t, strlen(t)) == 0)
				break;
			}
			if (i != diskno)
				continue;
		}
		(void) strcpy(arglist[diskno], *disklist);
		diskno++;
	}
	arglist[diskno] = NULL;
}

#define	DISK_PREFIX	"/dev/rdsk/"

/*
 * This Function checks if the non-conventional name is a a link to
 * one of the conventional whole disk name.
 */
static int
name_represents_wholedisk(char	*name)
{
	char	symname[MAXPATHLEN];
	char	localname[MAXPATHLEN];
	char	*nameptr;
	ssize_t symname_size;

	if (strlcpy(localname, name, MAXPATHLEN) >= MAXPATHLEN)
		return (1); /* buffer overflow, reject this name */

	while ((symname_size = readlink(
	    localname, symname, MAXPATHLEN - 1)) != -1) {
		symname[symname_size] = '\0';
		nameptr = symname;
		if (strncmp(symname, DISK_PREFIX,
		    (sizeof (DISK_PREFIX) - 1)) == 0)
			nameptr += (sizeof (DISK_PREFIX) - 1);

		if (conventional_name(nameptr)) {
			if (whole_disk_name(nameptr))
				return (0);
			else
				return (1);
		}
		(void) strcpy(localname, symname);
	}
	return (0);
}
