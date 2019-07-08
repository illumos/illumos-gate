/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <unistd.h>
#include "bart.h"

static int compare_manifests(FILE *rulesfile, char *control, char *test,
    boolean_t prog_fmt, uint_t flags);
static void extract_fname_ftype(char *line, char *fname, char *type);
static int report_add(char *fname, char *type);
static int report_delete(char *fname, char *type);
static int evaluate_differences(char *control_line, char *test_line,
    boolean_t prog_fmt, int flags);
static void report_error(char *fname, char *type, char *ctrl_val,
    char *test_val, boolean_t prog_fmt);
static int read_manifest_line(FILE *fd, char *buf, int buf_size, int start_pos,
    char **line, char *fname);
static void parse_line(char *line, char *fname, char *type, char *size,
    char *mode, char *acl, char *mtime, char *uid, char *gid, char *contents,
    char *devnode, char *dest);
static void init_default_flags(uint_t *flags);
static void get_token(char *line, int *curr_pos, int line_len, char *buf,
    int buf_size);

int
bart_compare(int argc, char **argv)
{
	char			*control_fname, *test_fname;
	int			c;
	FILE			*rules_fd = NULL;
	uint_t			glob_flags;
	boolean_t		prog_fmt = B_FALSE;

	init_default_flags(&glob_flags);

	while ((c = getopt(argc, argv, "pr:i:")) != EOF) {
		switch (c) {
		case 'p':
			prog_fmt = B_TRUE;
			break;

		case 'r':
			if (optarg == NULL)
				usage();

			if (strcmp(optarg, "-") == 0)
				rules_fd = stdin;
			else
				rules_fd = fopen(optarg, "r");
			if (rules_fd == NULL) {
				perror(optarg);
				usage();
			}
			break;

		case 'i':
			process_glob_ignores(optarg, &glob_flags);
			break;

		case '?':
		default:
			usage();
		}
	}

	/* Make sure we have the right number of args */
	if ((optind + 2) != argc)
		usage();
	argv += optind;
	control_fname = argv[0];
	test_fname = argv[1];
	/* At this point, the filenames are sane, so do the comparison */
	return (compare_manifests(rules_fd, control_fname, test_fname,
	    prog_fmt, glob_flags));
}

static int
compare_manifests(FILE *rulesfile, char *control, char *test,
    boolean_t prog_fmt, uint_t flags)
{
	FILE	*control_fd, *test_fd;
	char	*control_line, *test_line, control_buf[BUF_SIZE],
	    test_buf[BUF_SIZE], control_fname[PATH_MAX],
	    control_type[TYPE_SIZE], test_fname[PATH_MAX],
	    test_type[TYPE_SIZE];
	int	control_pos, test_pos, ret, fname_cmp, return_status;

	return_status = EXIT;

	return_status = read_rules(rulesfile, "", flags, 0);

	control_fd = fopen(control, "r");
	if (control_fd == NULL) {
		perror(control);
		return (FATAL_EXIT);
	}

	test_fd = fopen(test, "r");
	if (test_fd == NULL) {
		perror(test);
		return (FATAL_EXIT);
	}

	control_pos = read_manifest_line(control_fd, control_buf,
	    BUF_SIZE, 0, &control_line, control);
	test_pos = read_manifest_line(test_fd, test_buf, BUF_SIZE, 0,
	    &test_line, test);

	while ((control_pos != -1) && (test_pos != -1)) {
		ret = strcmp(control_line, test_line);
		if (ret == 0) {
			/* Lines compare OK, just read the next lines.... */
			control_pos = read_manifest_line(control_fd,
			    control_buf, BUF_SIZE, control_pos, &control_line,
			    control);
			test_pos = read_manifest_line(test_fd, test_buf,
			    BUF_SIZE, test_pos, &test_line, test);
			continue;
		}

		/*
		 * Something didn't compare properly.
		 */
		extract_fname_ftype(control_line, control_fname, control_type);
		extract_fname_ftype(test_line, test_fname, test_type);
		fname_cmp = strcmp(control_fname, test_fname);

		if (fname_cmp == 0) {
			/*
			 * Filenames were the same, see what was
			 * different and continue.
			 */
			if (evaluate_differences(control_line, test_line,
			    prog_fmt, flags) != 0)
				return_status = WARNING_EXIT;

			control_pos = read_manifest_line(control_fd,
			    control_buf, BUF_SIZE, control_pos, &control_line,
			    control);
			test_pos = read_manifest_line(test_fd, test_buf,
			    BUF_SIZE, test_pos, &test_line, test);
		} else if (fname_cmp > 0) {
			/* Filenames were different, a files was ADDED */
			if (report_add(test_fname, test_type)) {
				report_error(test_fname, ADD_KEYWORD, NULL,
				    NULL, prog_fmt);
				return_status = WARNING_EXIT;
			}
			test_pos = read_manifest_line(test_fd, test_buf,
			    BUF_SIZE, test_pos, &test_line, test);
		} else if (fname_cmp < 0) {
			/* Filenames were different, a files was DELETED */
			if (report_delete(control_fname, control_type)) {
				report_error(control_fname, DELETE_KEYWORD,
				    NULL, NULL, prog_fmt);
				return_status = WARNING_EXIT;
			}
			control_pos = read_manifest_line(control_fd,
			    control_buf, BUF_SIZE, control_pos, &control_line,
			    control);
		}
	}

	/*
	 * Entering this while loop means files were DELETED from the test
	 * manifest.
	 */
	while (control_pos != -1) {
		(void) sscanf(control_line, "%1023s", control_fname);
		if (report_delete(control_fname, control_type)) {
			report_error(control_fname, DELETE_KEYWORD, NULL,
			    NULL, prog_fmt);
			return_status = WARNING_EXIT;
		}
		control_pos = read_manifest_line(control_fd, control_buf,
		    BUF_SIZE, control_pos, &control_line, control);
	}

	/*
	 * Entering this while loop means files were ADDED to the test
	 * manifest.
	 */
	while (test_pos != -1) {
		(void) sscanf(test_line, "%1023s", test_fname);
		if (report_add(test_fname, test_type)) {
			report_error(test_fname, ADD_KEYWORD, NULL,
			    NULL, prog_fmt);
			return_status = WARNING_EXIT;
		}
		test_pos = read_manifest_line(test_fd, test_buf,
		    BUF_SIZE, test_pos, &test_line, test);
	}

	(void) fclose(control_fd);
	(void) fclose(test_fd);

	/* For programmatic mode, add a newline for cosmetic reasons */
	if (prog_fmt && (return_status != 0))
		(void) printf("\n");

	return (return_status);
}

static void
parse_line(char *line, char *fname, char *type, char *size, char *mode,
    char *acl, char *mtime, char *uid, char *gid, char *contents, char *devnode,
    char *dest)
{
	int		pos, line_len;

	line_len = strlen(line);
	pos = 0;

	get_token(line, &pos, line_len, fname, PATH_MAX);
	get_token(line, &pos, line_len, type, TYPE_SIZE);
	get_token(line, &pos, line_len, size, MISC_SIZE);
	get_token(line, &pos, line_len, mode, MISC_SIZE);
	get_token(line, &pos, line_len, acl, ACL_SIZE);
	get_token(line, &pos, line_len, mtime, MISC_SIZE);
	get_token(line, &pos, line_len, uid, MISC_SIZE);
	get_token(line, &pos, line_len, gid, MISC_SIZE);

	/* Reset these fields... */

	*contents = '\0';
	*devnode = '\0';
	*dest = '\0';

	/* Handle filetypes which have a last field..... */
	if (type[0] == 'F')
		get_token(line, &pos, line_len, contents, PATH_MAX);
	else if ((type[0] == 'B') || (type[0] == 'C'))
		get_token(line, &pos, line_len, devnode, PATH_MAX);
	else if (type[0] == 'L')
		get_token(line, &pos, line_len, dest, PATH_MAX);
}

static void
get_token(char *line, int *curr_pos, int line_len, char *buf, int buf_size)
{
	int	cnt = 0;

	while (isspace(line[*curr_pos]) && (*curr_pos < line_len))
		(*curr_pos)++;

	while (!isspace(line[*curr_pos]) &&
	    (*curr_pos < line_len) && (cnt < (buf_size-1))) {
		buf[cnt] = line[*curr_pos];
		(*curr_pos)++;
		cnt++;
	}
	buf[cnt] = '\0';
}

/*
 * Utility function: extract fname and type from this line
 */
static void
extract_fname_ftype(char *line, char *fname, char *type)
{
	int		line_len, pos;

	pos = 0;
	line_len = strlen(line);

	get_token(line, &pos, line_len, fname, PATH_MAX);
	get_token(line, &pos, line_len, type, TYPE_SIZE);
}

/*
 * Utility function: tells us whether or not this addition should be reported
 *
 * Returns 0 if the discrepancy is ignored, non-zero if the discrepancy is
 * reported.
 */
static int
report_add(char *fname, char *type)
{
	struct rule	*rule_ptr;

	rule_ptr = check_rules(fname, type[0]);
	if ((rule_ptr != NULL) && (rule_ptr->attr_list & ATTR_ADD))
		return (1);
	else
		return (0);
}

/*
 * Utility function: tells us whether or not this deletion should be reported
 *
 * Returns 0 if the discrepancy is ignored, non-zero if the discrepancy is
 * reported.
 */
static int
report_delete(char *fname, char *type)
{
	struct rule	*rule_ptr;

	rule_ptr = check_rules(fname, type[0]);

	if ((rule_ptr != NULL) && (rule_ptr->attr_list & ATTR_DELETE))
		return (1);
	else
		return (0);
}

/*
 * This function takes in the two entries, which have been flagged as
 * different, breaks them up and reports discrepancies.  Note, discrepancies
 * are affected by the 'CHECK' and 'IGNORE' stanzas which may apply to
 * these entries.
 *
 * Returns the number of discrepancies reported.
 */
static int
evaluate_differences(char *control_line, char *test_line,
    boolean_t prog_fmt, int flags)
{
	char		ctrl_fname[PATH_MAX], test_fname[PATH_MAX],
	    ctrl_type[TYPE_SIZE], test_type[TYPE_SIZE],
	    ctrl_size[MISC_SIZE], ctrl_mode[MISC_SIZE],
	    ctrl_acl[ACL_SIZE], ctrl_mtime[MISC_SIZE],
	    ctrl_uid[MISC_SIZE], ctrl_gid[MISC_SIZE],
	    ctrl_dest[PATH_MAX], ctrl_contents[PATH_MAX],
	    ctrl_devnode[PATH_MAX], test_size[MISC_SIZE],
	    test_mode[MISC_SIZE], test_acl[ACL_SIZE],
	    test_mtime[MISC_SIZE], test_uid[MISC_SIZE],
	    test_gid[MISC_SIZE], test_dest[PATH_MAX],
	    test_contents[PATH_MAX], test_devnode[PATH_MAX],
	    *tag;
	int		ret_val;
	struct rule	*rule_ptr;

	ret_val = 0;

	parse_line(control_line, ctrl_fname, ctrl_type, ctrl_size, ctrl_mode,
	    ctrl_acl, ctrl_mtime, ctrl_uid, ctrl_gid, ctrl_contents,
	    ctrl_devnode, ctrl_dest);

	/*
	 * Now we know the fname and type, let's get the rule that matches this
	 * manifest entry.  If there is a match, make sure to setup the
	 * correct reporting flags.
	 */
	rule_ptr = check_rules(ctrl_fname, ctrl_type[0]);
	if (rule_ptr != NULL)
		flags = rule_ptr->attr_list;

	parse_line(test_line, test_fname, test_type, test_size, test_mode,
	    test_acl, test_mtime, test_uid, test_gid, test_contents,
	    test_devnode, test_dest);

	/*
	 * Report the errors based upon which keywords have been set by
	 * the user.
	 */
	if ((flags & ATTR_TYPE) && (ctrl_type[0] != test_type[0])) {
		report_error(ctrl_fname, TYPE_KEYWORD, ctrl_type,
		    test_type, prog_fmt);
		ret_val++;
	}

	if ((flags & ATTR_SIZE) && (strcmp(ctrl_size, test_size) != 0)) {
		report_error(ctrl_fname, SIZE_KEYWORD, ctrl_size,
		    test_size, prog_fmt);
		ret_val++;
	}

	if ((flags & ATTR_MODE) && (strcmp(ctrl_mode, test_mode) != 0)) {
		report_error(ctrl_fname, MODE_KEYWORD, ctrl_mode,
		    test_mode, prog_fmt);
		ret_val++;
	}

	if ((flags & ATTR_ACL) && (strcmp(ctrl_acl, test_acl) != 0)) {
		report_error(ctrl_fname, ACL_KEYWORD, ctrl_acl,
		    test_acl, prog_fmt);
		ret_val++;
	}

	if ((flags & ATTR_MTIME) && (ctrl_type[0] == test_type[0])) {
		if (strcmp(ctrl_mtime, test_mtime) != 0) {
			switch (ctrl_type[0]) {
			case 'D':
				tag = "dirmtime";
				break;
			case 'L':
				tag = "lnmtime";
				break;
			default:
				tag = "mtime";
				break;
			}
			if (flags == 0) {
				report_error(ctrl_fname, tag, ctrl_mtime,
				    test_mtime, prog_fmt);
			ret_val++;
		}
	}

	if ((ctrl_type[0] == 'F') && (flags & ATTR_MTIME) &&
	    (strcmp(ctrl_mtime, test_mtime) != 0)) {
		report_error(ctrl_fname, MTIME_KEYWORD, ctrl_mtime, test_mtime,
		    prog_fmt);
		ret_val++;
	}

	if ((ctrl_type[0] == 'D') && (flags & ATTR_DIRMTIME) &&
	    (strcmp(ctrl_mtime, test_mtime) != 0)) {
		report_error(ctrl_fname, DIRMTIME_KEYWORD, ctrl_mtime,
		    test_mtime, prog_fmt);
		ret_val++;
	}

	if ((ctrl_type[0] == 'L') && (flags & ATTR_LNMTIME) &&
	    (strcmp(ctrl_mtime, test_mtime) != 0)) {
		report_error(ctrl_fname, LNMTIME_KEYWORD, ctrl_mtime,
		    test_mtime, prog_fmt);
		ret_val++;
	}
	} else if ((flags & ATTR_MTIME) &&
	    (strcmp(ctrl_mtime, test_mtime) != 0)) {
		report_error(ctrl_fname, MTIME_KEYWORD, ctrl_mtime,
		    test_mtime, prog_fmt);
		ret_val++;
	}

	if ((flags & ATTR_UID) && (strcmp(ctrl_uid, test_uid) != 0)) {
		report_error(ctrl_fname, UID_KEYWORD, ctrl_uid,
		    test_uid, prog_fmt);
		ret_val++;
	}

	if ((flags & ATTR_GID) && (strcmp(ctrl_gid, test_gid) != 0)) {
		report_error(ctrl_fname, GID_KEYWORD, ctrl_gid,
		    test_gid, prog_fmt);
		ret_val++;
	}

	if ((flags & ATTR_DEVNODE) &&
	    (strcmp(ctrl_devnode, test_devnode) != 0)) {
		report_error(ctrl_fname, DEVNODE_KEYWORD, ctrl_devnode,
		    test_devnode, prog_fmt);
		ret_val++;
	}

	if ((flags & ATTR_DEST) && (strcmp(ctrl_dest, test_dest) != 0)) {
		report_error(ctrl_fname, DEST_KEYWORD, ctrl_dest,
		    test_dest, prog_fmt);
		ret_val++;
	}

	if ((flags & ATTR_CONTENTS) &&
	    (strcmp(ctrl_contents, test_contents)) != 0) {
		report_error(ctrl_fname, CONTENTS_KEYWORD, ctrl_contents,
		    test_contents, prog_fmt);
		ret_val++;
	}

	return (ret_val);
}

/*
 * Function responsible for reporting errors.
 */
static void
report_error(char *fname, char *type, char *ctrl_val, char *test_val,
    boolean_t prog_fmt)
{
	static char	last_fname[PATH_MAX] = "";

	if (!prog_fmt) {
		/* Verbose mode */
		if (strcmp(fname, last_fname) != 0) {
			(void) printf("%s:\n", fname);
			(void) strlcpy(last_fname, fname, sizeof (last_fname));
		}

		if (strcmp(type, ADD_KEYWORD) == 0 ||
		    strcmp(type, DELETE_KEYWORD) == 0)
			(void) printf("  %s\n", type);
		else
			(void) printf("  %s  control:%s  test:%s\n", type,
			    ctrl_val, test_val);
	} else {
		/* Programmatic mode */
		if (strcmp(fname, last_fname) != 0) {
			/* Ensure a line is not printed for the initial case */
			if (strlen(last_fname) != 0)
				(void) printf("\n");
			(void) strlcpy(last_fname, fname, sizeof (last_fname));
			(void) printf("%s ", fname);
		}

		(void) printf("%s ", type);
		if (strcmp(type, ADD_KEYWORD) != 0 &&
		    strcmp(type, DELETE_KEYWORD) != 0) {
			(void) printf("%s ", ctrl_val);
			(void) printf("%s ", test_val);
		}
	}
}

/*
 * Function responsible for reading in a line from the manifest.
 * Takes in the file ptr and a buffer, parses the buffer  and sets the 'line'
 * ptr correctly.  In the case when the buffer is fully parsed, this function
 * reads more data from the file ptr and refills the buffer.
 */
static int
read_manifest_line(FILE *fd, char *buf, int buf_size, int start_pos,
    char **line, char *fname)
{
	int	end_pos, len, iscomment = 0, filepos;

	/*
	 * Initialization case: make sure the manifest version is OK
	 */
	if (start_pos == 0) {
		end_pos = 0;
		buf[0] = '\0';
		filepos = ftell(fd);
		(void) fread((void *) buf, (size_t)buf_size, (size_t)1, fd);

		*line = buf;

		if (filepos == 0) {
			if (strncmp(buf, MANIFEST_VER,
			    strlen(MANIFEST_VER)) != 0)
				(void) fprintf(stderr, MISSING_VER, fname);
			if ((*line[0] == '!') || (*line[0] == '#'))
				iscomment++;

			while (iscomment) {
				while ((buf[end_pos] != '\n') &&
				    (buf[end_pos] != '\0') &&
				    (end_pos < buf_size))
					end_pos++;

				if (end_pos >= buf_size)
					return (-1);

				end_pos++;
				*line = &(buf[end_pos]);
				iscomment = 0;
				if ((*line[0] == '!') || (*line[0] == '#'))
					iscomment++;
			}
		}

		while ((buf[end_pos] != '\n') && (buf[end_pos] != '\0') &&
		    (end_pos < buf_size))
			end_pos++;

		if (end_pos < buf_size) {
			if (buf[end_pos] == '\n') {
				buf[end_pos] = '\0';
				return (end_pos);
			}

			if (buf[end_pos] == '\0')
				return (-1);
		}

		(void) fprintf(stderr, MANIFEST_ERR);
		exit(FATAL_EXIT);
	}

	end_pos = (start_pos+1);
	*line = &(buf[end_pos]);

	/* Read the buffer until EOL or the buffer is empty */
	while ((buf[end_pos] != '\n') && (buf[end_pos] != '\0') &&
	    (end_pos < buf_size))
		end_pos++;

	if (end_pos < buf_size) {
		/* Found the end of the line, normal exit */
		if (buf[end_pos] == '\n') {
			buf[end_pos] = '\0';
			return (end_pos);
		}

		/* No more input to read */
		if (buf[end_pos] == '\0')
			return (-1);
	}

	/*
	 * The following code takes the remainder of the buffer and
	 * puts it at the beginning.  The space after the remainder, which
	 * is now at the beginning, is blanked.
	 * At this point, read in more data and continue to find the EOL....
	 */
	len = end_pos - (start_pos + 1);
	(void) memcpy(buf, &(buf[start_pos+1]), (size_t)len);
	(void) memset(&buf[len], '\0', (buf_size - len));
	(void) fread((void *) &buf[len], (size_t)(buf_size-len), (size_t)1, fd);
	*line = buf;
	end_pos = len;

	/* Read the buffer until EOL or the buffer is empty */
	while ((buf[end_pos] != '\n') && (buf[end_pos] != '\0') &&
	    (end_pos < buf_size))
		end_pos++;

	if (end_pos < buf_size) {
		/* Found the end of the line, normal exit */
		if (buf[end_pos] == '\n') {
			buf[end_pos] = '\0';
			return (end_pos);
		}

		/* No more input to read */
		if (buf[end_pos] == '\0')
			return (-1);
	}

	(void) fprintf(stderr, MANIFEST_ERR);
	exit(FATAL_EXIT);

	/* NOTREACHED */
}

static void
init_default_flags(uint_t *flags)
{
	/* Default behavior: everything is checked *except* dirmtime */
	*flags = ATTR_ALL & ~(ATTR_DIRMTIME);
}
