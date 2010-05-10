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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <signal.h>
#include <unistd.h>
#include <sys/acl.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include "bart.h"
#include <aclutils.h>

static int	sanitize_reloc_root(char *root, size_t bufsize);
static int	create_manifest_filelist(char **argv, char *reloc_root);
static int	create_manifest_rule(char *reloc_root, FILE *rule_fp);
static void	output_manifest(void);
static int	eval_file(const char *fname, const struct stat64 *statb);
static char	*sanitized_fname(const char *, boolean_t);
static char	*get_acl_string(const char *fname, const struct stat64 *statb,
    int *err_code);
static int	generate_hash(int fdin, char *hash_str);
static int	read_filelist(char *reloc_root, char **argv, char *buf,
    size_t bufsize);
static int	walker(const char *name, const struct stat64 *sp,
    int type, struct FTW *ftwx);

/*
 * The following globals are necessary due to the "walker" function
 * provided by nftw().  Since there is no way to pass them through to the
 * walker function, they must be global.
 */
static int		compute_chksum = 1, eval_err = 0;
static struct rule	*subtree_root;
static char		reloc_root[PATH_MAX];
static struct statvfs64	parent_vfs;

int
bart_create(int argc, char **argv)
{
	boolean_t	filelist_input;
	int		ret, c, output_pipe[2];
	FILE 		*rules_fd = NULL;
	pid_t		pid;

	filelist_input = B_FALSE;
	reloc_root[0] = '\0';

	while ((c = getopt(argc, argv, "Inr:R:")) != EOF) {
		switch (c) {
		case 'I':
			if (rules_fd != NULL) {
				(void) fprintf(stderr, "%s", INPUT_ERR);
				usage();
			}
			filelist_input = B_TRUE;
			break;

		case 'n':
			compute_chksum = 0;
			break;

		case 'r':
			if (strcmp(optarg, "-") == 0)
				rules_fd = stdin;
			else
				rules_fd = fopen(optarg, "r");
			if (rules_fd == NULL) {
				perror(optarg);
				usage();
			}
			break;

		case 'R':
			(void) strlcpy(reloc_root, optarg, sizeof (reloc_root));
			ret = sanitize_reloc_root(reloc_root,
			    sizeof (reloc_root));
			if (ret == 0)
				usage();
			break;

		case '?':
		default :
			usage();
		}
	}
	argv += optind;

	if (pipe(output_pipe) < 0) {
		perror("");
		exit(FATAL_EXIT);
	}

	pid = fork();
	if (pid < 0) {
		perror(NULL);
		exit(FATAL_EXIT);
	}

	/*
	 * Break the creation of a manifest into two parts: the parent process
	 * generated the data whereas the child process sorts the data.
	 *
	 * The processes communicate through the pipe.
	 */
	if (pid > 0) {
		/*
		 * Redirect the stdout of this process so it goes into
		 * output_pipe[0].  The output of this process will be read
		 * by the child, which will sort the output.
		 */
		if (dup2(output_pipe[0], STDOUT_FILENO) != STDOUT_FILENO) {
			perror(NULL);
			exit(FATAL_EXIT);
		}
		(void) close(output_pipe[0]);
		(void) close(output_pipe[1]);

		if (filelist_input == B_TRUE) {
			ret = create_manifest_filelist(argv, reloc_root);
		} else {
			ret = create_manifest_rule(reloc_root, rules_fd);
		}

		/* Close stdout so the sort in the child proc will complete */
		(void) fclose(stdout);
	} else {
		/*
		 * Redirect the stdin of this process so its read in from
		 * the pipe, which is the parent process in this case.
		 */
		if (dup2(output_pipe[1], STDIN_FILENO) != STDIN_FILENO) {
			perror(NULL);
			exit(FATAL_EXIT);
		}
		(void) close(output_pipe[0]);

		output_manifest();
	}

	/* Wait for the child proc (the sort) to complete */
	(void) wait(0);

	return (ret);
}

/*
 * Handle the -R option and sets 'root' to be the absolute path of the
 * relocatable root.  This is useful when the user specifies '-R ../../foo'.
 *
 * Return code is whether or not the location spec'd by the -R flag is a
 * directory or not.
 */
static int
sanitize_reloc_root(char *root, size_t bufsize)
{
	char		pwd[PATH_MAX];

	/*
	 * First, save the current directory and go to the location
	 * specified with the -R option.
	 */
	(void) getcwd(pwd, sizeof (pwd));
	if (chdir(root) < 0) {
		/* Failed to change directory, something is wrong.... */
		perror(root);
		return (0);
	}

	/*
	 * Save the absolute path of the relocatable root directory.
	 */
	(void) getcwd(root, bufsize);

	/*
	 * Now, go back to where we started, necessary for picking up a rules
	 * file.
	 */
	if (chdir(pwd) < 0) {
		/* Failed to change directory, something is wrong.... */
		perror(root);
		return (0);
	}

	/*
	 * Make sure the path returned does not have a trailing /. This
	 * can only happen when the entire pathname is "/".
	 */
	if (strcmp(root, "/") == 0)
		root[0] = '\0';

	/*
	 * Since the earlier chdir() succeeded, return success.
	 */
	return (1);
}

/*
 * This is the worker bee which creates the manifest based upon the command
 * line options supplied by the user.
 *
 * NOTE: create_manifest() eventually outputs data to a pipe, which is read in
 * by the child process.  The child process is running output_manifest(), which
 * is responsible for generating sorted output.
 */
static int
create_manifest_rule(char *reloc_root, FILE *rule_fp)
{
	struct rule	*root;
	int		ret_status = EXIT;
	uint_t		flags;

	if (compute_chksum)
		flags = ATTR_CONTENTS;
	else
		flags = 0;
	ret_status = read_rules(rule_fp, reloc_root, flags, 1);

	/* Loop through every single subtree */
	for (root = get_first_subtree(); root != NULL;
	    root = get_next_subtree(root)) {

		/*
		 * Check to see if this subtree should have contents
		 * checking turned on or off.
		 *
		 * NOTE: The 'compute_chksum' and 'parent_vfs'
		 * are a necessary hack: the variables are used in
		 * walker(), both directly and indirectly.  Since
		 * the parameters to walker() are defined by nftw(),
		 * the globals are really a backdoor mechanism.
		 */
		ret_status = statvfs64(root->subtree, &parent_vfs);
		if (ret_status < 0) {
			perror(root->subtree);
			continue;
		}

		/*
		 * Walk the subtree and invoke the callback function walker()
		 * Use FTW_ANYERR to get FTW_NS and FTW_DNR entries *and*
		 * to continue past those errors.
		 */
		subtree_root = root;
		(void) nftw64(root->subtree, &walker, 20, FTW_PHYS|FTW_ANYERR);

		/*
		 * Ugly but necessary:
		 *
		 * walker() must return 0, or the tree walk will stop,
		 * so warning flags must be set through a global.
		 */
		if (eval_err == WARNING_EXIT)
			ret_status = WARNING_EXIT;

	}
	return (ret_status);
}

static int
create_manifest_filelist(char **argv, char *reloc_root)
{
	int	ret_status = EXIT;
	char	input_fname[PATH_MAX];

	while (read_filelist(reloc_root, argv,
	    input_fname, sizeof (input_fname)) != -1) {

		struct stat64	stat_buf;
		int		ret;

		ret = lstat64(input_fname, &stat_buf);
		if (ret < 0) {
			ret_status = WARNING_EXIT;
			perror(input_fname);
		} else {
			ret = eval_file(input_fname, &stat_buf);

			if (ret == WARNING_EXIT)
				ret_status = WARNING_EXIT;
		}
	}

	return (ret_status);
}

/*
 * output_manifest() the child process.  It reads in the output from
 * create_manifest() and sorts it.
 */
static void
output_manifest(void)
{
	char	*env[] = {"LC_CTYPE=C", "LC_COLLATE=C", "LC_NUMERIC=C", NULL};
	time_t		time_val;
	struct tm	*tm;
	char		time_buf[1024];

	(void) printf("%s", MANIFEST_VER);
	time_val = time((time_t)0);
	tm = localtime(&time_val);
	(void) strftime(time_buf, sizeof (time_buf), "%A, %B %d, %Y (%T)", tm);
	(void) printf("! %s\n", time_buf);
	(void) printf("%s", FORMAT_STR);
	(void) fflush(stdout);
	/*
	 * Simply run sort and read from the the current stdin, which is really
	 * the output of create_manifest().
	 * Also, make sure the output is unique, since a given file may be
	 * included by several stanzas.
	 */
	if (execle("/usr/bin/sort", "sort", "-u", NULL, env) < 0) {
		perror("");
		exit(FATAL_EXIT);
	}

	/*NOTREACHED*/
}

/*
 * Callback function for nftw()
 */
static int
walker(const char *name, const struct stat64 *sp, int type, struct FTW *ftwx)
{
	int			ret;
	struct statvfs64	path_vfs;
	boolean_t		dir_flag = B_FALSE;
	struct rule		*rule;

	switch (type) {
	case FTW_F:	/* file 		*/
		rule = check_rules(name, 'F');
		if (rule != NULL) {
			if (rule->attr_list & ATTR_CONTENTS)
				compute_chksum = 1;
			else
				compute_chksum = 0;
		}
		break;
	case FTW_SL:	/* symbolic link, FTW_PHYS	*/
	case FTW_SLN:	/* symbolic link, ~FTW_PHYS	*/
		break;
	case FTW_DP:	/* end of directory, FTW_DEPTH	*/
	case FTW_D:	/* enter directory, ~FTW_DEPTH	*/
		dir_flag = B_TRUE;
		ret = statvfs64(name, &path_vfs);
		if (ret < 0)
			eval_err = WARNING_EXIT;
		break;
	case FTW_NS:	/* unstatable file	*/
		(void) fprintf(stderr, UNKNOWN_FILE, name);
		eval_err = WARNING_EXIT;
		return (0);
	case FTW_DNR:	/* unreadable directory	*/
		(void) fprintf(stderr, CANTLIST_DIR, name);
		eval_err = WARNING_EXIT;
		return (0);
	default:
		(void) fprintf(stderr, INTERNAL_ERR, name);
		eval_err = WARNING_EXIT;
		return (0);
	}

	/* This is the function which really processes the file */
	ret = eval_file(name, sp);

	/*
	 * Since the parameters to walker() are constrained by nftw(),
	 * need to use a global to reflect a WARNING.  Sigh.
	 */
	if (ret == WARNING_EXIT)
		eval_err = WARNING_EXIT;

	/*
	 * This is a case of a directory which crosses into a mounted
	 * filesystem of a different type, e.g., UFS -> NFS.
	 * BART should not walk the new filesystem (by specification), so
	 * set this consolidation-private flag so the rest of the subtree
	 * under this directory is not waled.
	 */
	if (dir_flag &&
	    (strcmp(parent_vfs.f_basetype, path_vfs.f_basetype) != 0))
		ftwx->quit = FTW_PRUNE;

	return (0);
}

/*
 * This file does the per-file evaluation and is run to generate every entry
 * in the manifest.
 *
 * All output is written to a pipe which is read by the child process,
 * which is running output_manifest().
 */
static int
eval_file(const char *fname, const struct stat64 *statb)
{
	int	fd, ret, err_code, i;
	char	last_field[PATH_MAX], ftype, *acl_str;
	char	*quoted_name;

	err_code = EXIT;

	switch (statb->st_mode & S_IFMT) {
	/* Regular file */
	case S_IFREG: ftype = 'F'; break;

	/* Directory */
	case S_IFDIR: ftype = 'D'; break;

	/* Block Device */
	case S_IFBLK: ftype = 'B'; break;

	/* Character Device */
	case S_IFCHR: ftype = 'C'; break;

	/* Named Pipe */
	case S_IFIFO: ftype = 'P'; break;

	/* Socket */
	case S_IFSOCK: ftype = 'S'; break;

	/* Door */
	case S_IFDOOR: ftype = 'O'; break;

	/* Symbolic link */
	case S_IFLNK: ftype = 'L'; break;

	default: ftype = '-'; break;
	}

	/* First, make sure this file should be cataloged */

	if ((subtree_root != NULL) &&
	    (exclude_fname(fname, ftype, subtree_root)))
		return (err_code);

	for (i = 0; i < PATH_MAX; i++)
		last_field[i] = '\0';

	/*
	 * Regular files, compute the MD5 checksum and put it into 'last_field'
	 * UNLESS instructed to ignore the checksums.
	 */
	if (ftype == 'F') {
		if (compute_chksum) {
			fd = open(fname, O_RDONLY|O_LARGEFILE);
			if (fd < 0) {
				err_code = WARNING_EXIT;
				perror(fname);

				/* default value since the computution failed */
				(void) strcpy(last_field, "-");
			} else {
				if (generate_hash(fd, last_field) != 0) {
					err_code = WARNING_EXIT;
					(void) fprintf(stderr, CONTENTS_WARN,
					    fname);
					(void) strcpy(last_field, "-");
				}
			}
			(void) close(fd);
		}
		/* Instructed to ignore checksums, just put in a '-' */
		else
			(void) strcpy(last_field, "-");
	}

	/*
	 * For symbolic links, put the destination of the symbolic link into
	 * 'last_field'
	 */
	if (ftype == 'L') {
		ret = readlink(fname, last_field, sizeof (last_field));
		if (ret < 0) {
			err_code = WARNING_EXIT;
			perror(fname);

			/* default value since the computation failed */
			(void) strcpy(last_field, "-");
		}
		else
			(void) strlcpy(last_field,
			    sanitized_fname(last_field, B_FALSE),
			    sizeof (last_field));

		/*
		 * Boundary condition: possible for a symlink to point to
		 * nothing [ ln -s '' link_name ].  For this case, set the
		 * destination to "\000".
		 */
		if (strlen(last_field) == 0)
			(void) strcpy(last_field, "\\000");
	}

	acl_str = get_acl_string(fname, statb, &err_code);

	/* Sanitize 'fname', so its in the proper format for the manifest */
	quoted_name = sanitized_fname(fname, B_TRUE);

	/* Start to build the entry.... */
	(void) printf("%s %c %d %o %s %x %d %d", quoted_name, ftype,
	    (int)statb->st_size, (int)statb->st_mode, acl_str,
	    (int)statb->st_mtime, (int)statb->st_uid, (int)statb->st_gid);

	/* Finish it off based upon whether or not it's a device node */
	if ((ftype == 'B') || (ftype == 'C'))
		(void) printf(" %x\n", (int)statb->st_rdev);
	else if (strlen(last_field) > 0)
		(void) printf(" %s\n", last_field);
	else
		(void) printf("\n");

	/* free the memory consumed */
	free(acl_str);
	free(quoted_name);

	return (err_code);
}

/*
 * When creating a manifest, make sure all '?', tabs, space, newline, '/'
 * and '[' are all properly quoted.  Convert them to a "\ooo" where the 'ooo'
 * represents their octal value. For filesystem objects, as opposed to symlink
 * targets, also canonicalize the pathname.
 */
static char *
sanitized_fname(const char *fname, boolean_t canon_path)
{
	const char *ip;
	unsigned char ch;
	char *op, *quoted_name;

	/* Initialize everything */
	quoted_name = safe_calloc((4 * PATH_MAX) + 1);
	ip = fname;
	op = quoted_name;

	if (canon_path) {
		/*
		 * In the case when a relocatable root was used, the relocatable
		 * root should *not* be part of the manifest.
		 */
		ip += strlen(reloc_root);

		/*
		 * In the case when the '-I' option was used, make sure
		 * the quoted_name starts with a '/'.
		 */
		if (*ip != '/')
			*op++ = '/';
	}

	/* Now walk through 'fname' and build the quoted string */
	while ((ch = *ip++) != 0) {
		switch (ch) {
		/* Quote the following characters */
		case ' ':
		case '*':
		case '\n':
		case '?':
		case '[':
		case '\\':
		case '\t':
			op += sprintf(op, "\\%.3o", (unsigned char)ch);
			break;

		/* Otherwise, simply append them */
		default:
			*op++ = ch;
			break;
		}
	}

	*op = 0;

	return (quoted_name);
}

/*
 * Function responsible for generating the ACL information for a given
 * file.  Note, the string is put into buffer malloc'd by this function.
 * It's the responsibility of the caller to free the buffer.  This function
 * should never return a NULL pointer.
 */
static char *
get_acl_string(const char *fname, const struct stat64 *statb, int *err_code)
{
	acl_t		*aclp;
	char		*acltext;
	int		error;

	if (S_ISLNK(statb->st_mode)) {
		return (safe_strdup("-"));
	}

	/*
	 *  Include trivial acl's
	 */
	error = acl_get(fname, 0, &aclp);

	if (error != 0) {
		*err_code = WARNING_EXIT;
		(void) fprintf(stderr, "%s: %s\n", fname, acl_strerror(error));
		return (safe_strdup("-"));
	} else {
		acltext = acl_totext(aclp, 0);
		acl_free(aclp);
		if (acltext == NULL)
			return (safe_strdup("-"));
		else
			return (acltext);
	}
}


/*
 *
 * description:	This routine reads stdin in BUF_SIZE chunks, uses the bits
 *		to update the md5 hash buffer, and outputs the chunks
 *		to stdout.  When stdin is exhausted, the hash is computed,
 *		converted to a hexadecimal string, and returned.
 *
 * returns:	The md5 hash of stdin, or NULL if unsuccessful for any reason.
 */
static int
generate_hash(int fdin, char *hash_str)
{
	unsigned char buf[BUF_SIZE];
	unsigned char hash[MD5_DIGEST_LENGTH];
	int i, amtread;
	MD5_CTX ctx;

	MD5Init(&ctx);

	for (;;) {
		amtread = read(fdin, buf, sizeof (buf));
		if (amtread == 0)
			break;
		if (amtread <  0)
			return (1);

		/* got some data.  Now update hash */
		MD5Update(&ctx, buf, amtread);
	}

	/* done passing through data, calculate hash */
	MD5Final(hash, &ctx);

	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		(void) sprintf(hash_str + (i*2), "%2.2x", hash[i]);

	return (0);
}

/*
 * Used by 'bart create' with the '-I' option.  Return each entry into a 'buf'
 * with the appropriate exit code: '0' for success and '-1' for failure.
 */
static int
read_filelist(char *reloc_root, char **argv, char *buf, size_t bufsize)
{
	static int		argv_index = -1;
	static boolean_t	read_stdinput = B_FALSE;
	char			temp_buf[PATH_MAX];
	char 			*cp;

	/*
	 * INITIALIZATION:
	 * Setup this code so it knows whether or not to read sdtin.
	 * Also, if reading from argv, setup the index, "argv_index"
	 */
	if (argv_index == -1) {
		argv_index = 0;

		/* In this case, no args after '-I', so read stdin */
		if (argv[0] == NULL)
			read_stdinput = B_TRUE;
	}

	buf[0] = '\0';

	if (read_stdinput) {
		if (fgets(temp_buf, PATH_MAX, stdin) == NULL)
			return (-1);
		cp = strtok(temp_buf, "\n");
	} else {
		cp = argv[argv_index++];
	}

	if (cp == NULL)
		return (-1);

	/*
	 * Unlike similar code elsewhere, avoid adding a leading
	 * slash for relative pathnames.
	 */
	(void) snprintf(buf, bufsize,
	    (reloc_root[0] == '\0' || cp[0] == '/') ? "%s%s" : "%s/%s",
	    reloc_root, cp);

	return (0);
}
