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

/*
 *	syseventadm - command to administer the sysevent.conf registry
 *		    - administers the general purpose event framework
 *
 *	The current implementation of the registry using files in
 *	/etc/sysevent/config, files are named as event specifications
 *	are added with the combination of the vendor, publisher, event
 *	class and subclass strings:
 *
 *	[<vendor>,][<publisher>,][<class>,]sysevent.conf
 *
 */
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <synch.h>
#include <syslog.h>
#include <thread.h>
#include <limits.h>
#include <locale.h>
#include <assert.h>
#include <libsysevent.h>
#include <zone.h>
#include <sys/sysevent_impl.h>
#include <sys/modctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/wait.h>

#include "syseventadm.h"
#include "syseventadm_msg.h"

#ifndef DEBUG
#undef	assert
#define	assert(EX) ((void)0)
#endif

static char	*whoami		= NULL;
static char	*root_dir	= "";

static char	*arg_vendor	= NULL;
static char	*arg_publisher	= NULL;
static char	*arg_class	= NULL;
static char	*arg_subclass	= NULL;
static char	*arg_username	= NULL;
static char	*arg_path	= NULL;
static int	arg_nargs	= 0;
static char	**arg_args	= NULL;

static	int	lock_fd;
static	char 	lock_file[PATH_MAX + 1];

extern char	*optarg;
extern int	optind;

static int
usage_gen()
{
	(void) fprintf(stderr, MSG_USAGE_INTRO);
	(void) fprintf(stderr, MSG_USAGE_OPTIONS);
	(void) fprintf(stderr, "\n"
	    "\tsyseventadm add ...\n"
	    "\tsyseventadm remove ...\n"
	    "\tsyseventadm list ...\n"
	    "\tsyseventadm restart\n"
	    "\tsyseventadm help\n");

	return (EXIT_USAGE);
}

static int
serve_syseventdotconf(int argc, char **argv, char *cmd)
{
	int	c;
	int	rval;

	while ((c = getopt(argc, argv, "R:v:p:c:s:u:")) != EOF) {
		switch (c) {
		case 'R':
			/*
			 * Alternate root path for install, etc.
			 */
			set_root_dir(optarg);
			break;
		case 'v':
			arg_vendor = optarg;
			break;
		case 'p':
			arg_publisher = optarg;
			break;
		case 'c':
			arg_class = optarg;
			break;
		case 's':
			arg_subclass = optarg;
			break;
		case 'u':
			arg_username = optarg;
			break;
		default:
			return (usage());
		}
	}

	if (optind < argc) {
		arg_path = argv[optind++];
		if (optind < argc) {
			arg_nargs = argc - optind;
			arg_args = argv + optind;
		}
	}

	enter_lock(root_dir);

	if (strcmp(cmd, "add") == 0) {
		rval = add_cmd();
	} else if (strcmp(cmd, "list") == 0) {
		rval = list_remove_cmd(CMD_LIST);
	} else if (strcmp(cmd, "remove") == 0) {
		rval = list_remove_cmd(CMD_REMOVE);
	} else if (strcmp(cmd, "restart") == 0) {
		rval = restart_cmd();
	} else {
		rval = usage();
	}

	exit_lock();

	return (rval);
}


int
main(int argc, char **argv)
{
	char	*cmd;
	int	rval;


	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((whoami = strrchr(argv[0], '/')) == NULL) {
		whoami = argv[0];
	} else {
		whoami++;
	}

	if (argc == 1) {
		return (usage_gen());
	}

	cmd = argv[optind++];

	/* Allow non-privileged users to get the help messages */
	if (strcmp(cmd, "help") == 0) {
		rval = usage_gen();
		return (rval);
	}

	if (getuid() != 0) {
		(void) fprintf(stderr, MSG_NOT_ROOT, whoami);
		exit(EXIT_PERM);
	}

	if (strcmp(cmd, "evc") != 0 && getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr, MSG_NOT_GLOBAL, whoami);
		exit(EXIT_PERM);
	}

	if (strcmp(cmd, "add") == 0 ||
	    strcmp(cmd, "remove") == 0 || strcmp(cmd, "list") == 0 ||
	    strcmp(cmd, "restart") == 0) {
		rval = serve_syseventdotconf(argc, argv, cmd);
	} else {
		rval = usage_gen();
	}
	return (rval);
}


static void
enter_lock(char *root_dir)
{
	struct flock	lock;

	if (snprintf(lock_file, sizeof (lock_file), "%s%s", root_dir,
	    LOCK_FILENAME) >= sizeof (lock_file)) {
		(void) fprintf(stderr, MSG_LOCK_PATH_ERR, whoami, lock_file);
		exit(EXIT_CMD_FAILED);
	}
	lock_fd = open(lock_file, O_CREAT|O_RDWR, 0644);
	if (lock_fd < 0) {
		(void) fprintf(stderr, MSG_LOCK_CREATE_ERR,
			whoami, lock_file, strerror(errno));
		exit(EXIT_CMD_FAILED);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

retry:
	if (fcntl(lock_fd, F_SETLKW, &lock) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			goto retry;
		(void) close(lock_fd);
		(void) fprintf(stderr, MSG_LOCK_SET_ERR,
			whoami, lock_file, strerror(errno));
		exit(EXIT_CMD_FAILED);
	}
}


static void
exit_lock()
{
	struct flock	lock;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLK, &lock) == -1) {
		(void) fprintf(stderr, MSG_LOCK_CLR_ERR,
			whoami, lock_file, strerror(errno));
	}

	if (close(lock_fd) == -1) {
		(void) fprintf(stderr, MSG_LOCK_CLOSE_ERR,
			whoami, lock_file, strerror(errno));
	}
}


static void
set_root_dir(char *dir)
{
	root_dir = sc_strdup(dir);
}


static char *usage_msg[] = {
	"\n"
	"\tsyseventadm add [-R <rootdir>] [-v vendor] [-p publisher]\n"
	"\t[-c class] [-s subclass] [-u username] path [args]\n"
	"\n"
	"\tsyseventadm remove [-R <rootdir>] [-v vendor] [-p publisher]\n"
	"\t[-c class] [-s subclass] [-u username] [path [args]]\n"
	"\n"
	"\tsyseventadm list [-R <rootdir>] [-v vendor] [-p publisher]\n"
	"\t[-c class] [-s subclass] [-u username] [path [args]]\n"
};

static int
usage()
{
	char	**msgs;
	int	i;

	msgs = usage_msg;
	for (i = 0; i < sizeof (usage_msg)/sizeof (char *); i++) {
		(void) fputs(*msgs++, stderr);
	}

	return (EXIT_USAGE);
}


static int
add_cmd(void)
{
	char	fname[MAXPATHLEN+1];
	int	need_comma = 0;
	int	noptions = 0;
	struct stat st;
	FILE	*fp;
	str_t	*line;
	int	i;

	/*
	 * At least one of vendor/publisher/class must be specified.
	 * Subclass is only defined within the context of class.
	 * For add, path must also be specified.
	 */
	if (arg_vendor)
		noptions++;
	if (arg_publisher)
		noptions++;
	if (arg_class)
		noptions++;

	if (noptions == 0 || (arg_subclass && arg_class == NULL)) {
		return (usage());
	}

	if (arg_path == NULL)
		return (usage());

	/*
	 * Generate the sysevent.conf file name
	 */
	(void) strcpy(fname, root_dir);
	(void) strcat(fname, SYSEVENT_CONFIG_DIR);
	(void) strcat(fname, "/");

	if (arg_vendor) {
		(void) strcat(fname, arg_vendor);
		need_comma = 1;
	}
	if (arg_publisher) {
		if (need_comma)
			(void) strcat(fname, ",");
		(void) strcat(fname, arg_publisher);
		need_comma = 1;
	}
	if (arg_class) {
		if (need_comma)
			(void) strcat(fname, ",");
		(void) strcat(fname, arg_class);
	}
	(void) strcat(fname, SYSEVENT_CONF_SUFFIX);

	/*
	 * Prepare the line to be written to the sysevent.conf file
	 */
	line = initstr(128);

	strcats(line, arg_class == NULL ? "-" : arg_class);
	strcatc(line, ' ');

	strcats(line, arg_subclass == NULL ? "-" : arg_subclass);
	strcatc(line, ' ');

	strcats(line, arg_vendor == NULL ? "-" : arg_vendor);
	strcatc(line, ' ');

	strcats(line, arg_publisher == NULL ? "-" : arg_publisher);
	strcatc(line, ' ');

	strcats(line, arg_username == NULL ? "-" : arg_username);
	strcatc(line, ' ');

	strcats(line, "- - ");
	strcats(line, arg_path);

	if (arg_nargs) {
		for (i = 0; i < arg_nargs; i++) {
			strcatc(line, ' ');
			strcats(line, arg_args[i]);
		}
	}

	if (stat(fname, &st) == -1) {
		if (creat(fname, 0644) == -1) {
			(void) fprintf(stderr, MSG_CANNOT_CREATE,
				whoami, fname, strerror(errno));
			freestr(line);
			return (EXIT_CMD_FAILED);
		}
	}

	fp = fopen(fname, "a");
	if (fp == NULL) {
		(void) fprintf(stderr, MSG_CANNOT_OPEN,
			whoami, fname, strerror(errno));
		freestr(line);
		return (EXIT_CMD_FAILED);
	}

	(void) fprintf(fp, "%s\n", line->s_str);
	freestr(line);

	if (fclose(fp) == -1) {
		(void) fprintf(stderr, MSG_CLOSE_ERROR,
			whoami, fname, strerror(errno));
		return (EXIT_CMD_FAILED);
	}

	if (chmod(fname, 0444) == -1) {
		(void) fprintf(stderr, MSG_CHMOD_ERROR,
			whoami, fname, strerror(errno));
		return (EXIT_CMD_FAILED);
	}
	return (EXIT_OK);
}


static int
list_remove_cmd(int cmd)
{
	struct dirent	*dp;
	DIR		*dir;
	char		path[MAXPATHLEN+1];
	char		fname[MAXPATHLEN+1];
	char		*suffix;
	char		**dirlist = NULL;
	int		list_size = 0;
	int		list_alloc = 0;
	char		**p;
	int		rval;
	int		result;

	/*
	 * For the remove cmd, at least one of vendor/publisher/class/username
	 * path must be specified.  Subclass is only defined within the
	 * context of a class.
	 */
	if (cmd == CMD_REMOVE) {
		int	noptions = 0;
		if (arg_vendor)
			noptions++;
		if (arg_publisher)
			noptions++;
		if (arg_class)
			noptions++;
		if (arg_username)
			noptions++;
		if (arg_path)
			noptions++;
		if (noptions == 0 || (arg_subclass && arg_class == NULL)) {
			return (usage());
		}
	}

	(void) strcpy(path, root_dir);
	(void) strcat(path, SYSEVENT_CONFIG_DIR);

	if ((dir = opendir(path)) == NULL) {
		(void) fprintf(stderr, MSG_CANNOT_OPEN_DIR,
			whoami, path, strerror(errno));
		return (EXIT_CMD_FAILED);
	}

	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;
		if ((strlen(dp->d_name) == 0) ||
		    (strcmp(dp->d_name, "lost+found") == 0))
			continue;
		suffix = strrchr(dp->d_name, ',');
		if (suffix && strcmp(suffix, SYSEVENT_CONF_SUFFIX) == 0) {
			(void) strcpy(fname, path);
			(void) strcat(fname, "/");
			(void) strcat(fname, dp->d_name);
			dirlist = build_strlist(dirlist,
				&list_size, &list_alloc, fname);
		}
	}

	if (closedir(dir) == -1) {
		(void) fprintf(stderr, MSG_CLOSE_DIR_ERROR,
			whoami, path, strerror(errno));
		return (EXIT_CMD_FAILED);
	}

	rval = EXIT_NO_MATCH;
	if (dirlist) {
		for (p = dirlist; *p != NULL; p++) {
			switch (cmd) {
			case CMD_LIST:
				result = list_file(*p);
				break;
			case CMD_REMOVE:
				result = remove_file(*p);
				break;
			}
			if (rval == EXIT_NO_MATCH &&
			    result != EXIT_NO_MATCH)
				rval = result;
		}
	}
	return (rval);
}


static int
list_file(char *fname)
{
	FILE		*fp;
	str_t		*line;
	serecord_t	*sep;
	int		rval = EXIT_NO_MATCH;

	fp = fopen(fname, "r");
	if (fp == NULL) {
		(void) fprintf(stderr, MSG_CANNOT_OPEN,
			whoami, fname, strerror(errno));
		return (EXIT_CMD_FAILED);
	}
	for (;;) {
		line = read_next_line(fp);
		if (line == NULL)
			break;
		sep = parse_line(line);
		if (sep != NULL) {
			if (matches_serecord(sep)) {
				print_serecord(stdout, sep);
				rval = EXIT_OK;
			}
			free_serecord(sep);
		}
		freestr(line);
	}
	(void) fclose(fp);

	return (rval);
}


static int
remove_file(char *fname)
{
	FILE		*fp;
	FILE		*tmp_fp;
	str_t		*line;
	char		*raw_line;
	serecord_t	*sep;
	char		tmp_name[MAXPATHLEN+1];
	int		is_empty = 1;

	fp = fopen(fname, "r");
	if (fp == NULL) {
		(void) fprintf(stderr, MSG_CANNOT_OPEN,
			whoami, fname, strerror(errno));
		return (EXIT_CMD_FAILED);
	}

	if (check_for_removes(fp) == 0) {
		(void) fclose(fp);
		return (EXIT_NO_MATCH);
	}

	rewind(fp);

	(void) strcpy(tmp_name, root_dir);
	(void) strcat(tmp_name, SYSEVENT_CONFIG_DIR);
	(void) strcat(tmp_name, "/tmp.XXXXXX");
	if (mktemp(tmp_name) == NULL) {
		(void) fprintf(stderr, "unable to make tmp file name\n");
		return (EXIT_CMD_FAILED);
	}

	if (creat(tmp_name, 0644) == -1) {
		(void) fprintf(stderr, MSG_CANNOT_CREATE,
			whoami, tmp_name, strerror(errno));
		return (EXIT_CMD_FAILED);
	}

	tmp_fp = fopen(tmp_name, "a");
	if (tmp_fp == NULL) {
		(void) fprintf(stderr, MSG_CANNOT_OPEN,
			whoami, tmp_name, strerror(errno));
		(void) unlink(tmp_name);
		(void) fclose(fp);
		return (EXIT_CMD_FAILED);
	}

	for (;;) {
		line = read_next_line(fp);
		if (line == NULL)
			break;
		raw_line = sc_strdup(line->s_str);
		sep = parse_line(line);
		if (sep == NULL) {
			(void) fputs(line->s_str, tmp_fp);
		} else {
			if (!matches_serecord(sep)) {
				is_empty = 0;
				(void) fprintf(tmp_fp, "%s\n", raw_line);
			}
			free_serecord(sep);
		}
		freestr(line);
		sc_strfree(raw_line);
	}
	(void) fclose(fp);
	if (fclose(tmp_fp) == -1) {
		(void) fprintf(stderr, MSG_CLOSE_ERROR,
			whoami, tmp_name, strerror(errno));
	}

	if (is_empty) {
		if (unlink(tmp_name) == -1) {
			(void) fprintf(stderr, MSG_CANNOT_UNLINK,
				whoami, tmp_name, strerror(errno));
			return (EXIT_CMD_FAILED);
		}
		if (unlink(fname) == -1) {
			(void) fprintf(stderr, MSG_CANNOT_UNLINK,
				whoami, fname, strerror(errno));
			return (EXIT_CMD_FAILED);
		}
	} else {
		if (unlink(fname) == -1) {
			(void) fprintf(stderr, MSG_CANNOT_UNLINK,
				whoami, fname, strerror(errno));
			return (EXIT_CMD_FAILED);
		}
		if (rename(tmp_name, fname) == -1) {
			(void) fprintf(stderr, MSG_CANNOT_RENAME,
				whoami, tmp_name, fname, strerror(errno));
			return (EXIT_CMD_FAILED);
		}
		if (chmod(fname, 0444) == -1) {
			(void) fprintf(stderr, MSG_CHMOD_ERROR,
				whoami, fname, strerror(errno));
			return (EXIT_CMD_FAILED);
		}
	}

	return (EXIT_OK);
}

static int
check_for_removes(FILE *fp)
{
	str_t		*line;
	serecord_t	*sep;

	for (;;) {
		line = read_next_line(fp);
		if (line == NULL)
			break;
		sep = parse_line(line);
		if (sep != NULL) {
			if (matches_serecord(sep)) {
				free_serecord(sep);
				freestr(line);
				return (1);
			}
			free_serecord(sep);
		}
		freestr(line);
	}

	return (0);
}


static int
matches_serecord(serecord_t *sep)
{
	char	*line;
	char	*lp;
	char	*token;
	int	i;

	if (arg_vendor &&
	    strcmp(arg_vendor, sep->se_vendor) != 0) {
		return (0);
	}

	if (arg_publisher &&
	    strcmp(arg_publisher, sep->se_publisher) != 0) {
		return (0);
	}

	if (arg_class &&
	    strcmp(arg_class, sep->se_class) != 0) {
		return (0);
	}

	if (arg_subclass &&
	    strcmp(arg_subclass, sep->se_subclass) != 0) {
		return (0);
	}

	if (arg_username &&
	    strcmp(arg_username, sep->se_user) != 0) {
		return (0);
	}

	if (arg_path &&
	    strcmp(arg_path, sep->se_path) != 0) {
		return (0);
	}

	if (arg_nargs > 0) {
		line = sc_strdup(sep->se_args);
		lp = line;
		for (i = 0; i < arg_nargs; i++) {
			token = next_field(&lp);
			if (strcmp(arg_args[i], token) != 0) {
				sc_strfree(line);
				return (0);
			}
		}
		sc_strfree(line);
	}

	return (1);
}

static void
print_serecord(FILE *fp, serecord_t *sep)
{
	str_t	*line;

	line = initstr(128);

	if (strcmp(sep->se_vendor, "-") != 0) {
		strcats(line, "vendor=");
		strcats(line, sep->se_vendor);
		strcats(line, " ");
	}
	if (strcmp(sep->se_publisher, "-") != 0) {
		strcats(line, "publisher=");
		strcats(line, sep->se_publisher);
		strcats(line, " ");
	}
	if (strcmp(sep->se_class, "-") != 0) {
		strcats(line, "class=");
		strcats(line, sep->se_class);
		strcats(line, " ");
		if (strcmp(sep->se_subclass, "-") != 0) {
			strcats(line, "subclass=");
			strcats(line, sep->se_subclass);
			strcats(line, " ");
		}
	}
	if (strcmp(sep->se_user, "-") != 0) {
		strcats(line, "username=");
		strcats(line, sep->se_user);
		strcats(line, " ");
	}
	strcats(line, sep->se_path);
	if (sep->se_args) {
		strcats(line, " ");
		strcats(line, sep->se_args);
	}
	strcats(line, "\n");

	(void) fputs(line->s_str, fp);
	freestr(line);
}




static int
restart_cmd(void)
{
	if (system("pkill -HUP syseventd") == -1) {
		(void) fprintf(stderr, MSG_RESTART_FAILED,
			whoami, strerror(errno));
		return (EXIT_CMD_FAILED);
	}
	return (EXIT_OK);
}


static str_t *
read_next_line(FILE *fp)
{
	char	*lp;
	str_t	*line;

	line = initstr(128);

	lp = fstrgets(line, fp);
	if (lp == NULL) {
		freestr(line);
		return (NULL);
	}

	*(lp + strlen(lp)-1) = 0;
	return (line);
}


static serecord_t *
parse_line(str_t *line)
{
	char	*lp;
	char	*vendor, *publisher;
	char	*class, *subclass;
	char	*user;
	char	*reserved1, *reserved2;
	char	*path, *args;
	serecord_t *sep;

	lp = line->s_str;
	if (*lp == 0 || *lp == '#') {
		return (NULL);
	}

	if ((class = next_field(&lp)) != NULL) {
		subclass = next_field(&lp);
		if (lp == NULL)
			return (NULL);
		vendor = next_field(&lp);
		if (lp == NULL)
			return (NULL);
		publisher = next_field(&lp);
		if (lp == NULL)
			return (NULL);
		user = next_field(&lp);
		if (lp == NULL)
			return (NULL);
		reserved1 = next_field(&lp);
		if (lp == NULL)
			return (NULL);
		reserved2 = next_field(&lp);
		if (lp == NULL)
			return (NULL);
		path = next_field(&lp);
		if (lp == NULL)
			return (NULL);
		args = skip_spaces(&lp);
	}

	sep = sc_malloc(sizeof (serecord_t));

	sep->se_vendor = sc_strdup(vendor);
	sep->se_publisher = sc_strdup(publisher);
	sep->se_class = sc_strdup(class);
	sep->se_subclass = sc_strdup(subclass);
	sep->se_user = sc_strdup(user);
	sep->se_reserved1 = sc_strdup(reserved1);
	sep->se_reserved2 = sc_strdup(reserved2);
	sep->se_path = sc_strdup(path);
	sep->se_args = (args == NULL) ? NULL : sc_strdup(args);

	return (sep);
}


static void
free_serecord(serecord_t *sep)
{
	sc_strfree(sep->se_vendor);
	sc_strfree(sep->se_publisher);
	sc_strfree(sep->se_class);
	sc_strfree(sep->se_subclass);
	sc_strfree(sep->se_user);
	sc_strfree(sep->se_reserved1);
	sc_strfree(sep->se_reserved2);
	sc_strfree(sep->se_path);
	sc_strfree(sep->se_args);
	sc_free(sep, sizeof (serecord_t));
}


/*
 * skip_spaces() - skip to next non-space character
 */
static char *
skip_spaces(char **cpp)
{
	char *cp = *cpp;

	while (*cp == ' ' || *cp == '\t')
		cp++;
	if (*cp == 0) {
		*cpp = 0;
		return (NULL);
	}
	return (cp);
}


/*
 * Get next white-space separated field.
 * next_field() will not check any characters on next line.
 * Each entry is composed of a single line.
 */
static char *
next_field(char **cpp)
{
	char *cp = *cpp;
	char *start;

	while (*cp == ' ' || *cp == '\t')
		cp++;
	if (*cp == 0) {
		*cpp = 0;
		return (NULL);
	}
	start = cp;
	while (*cp && *cp != ' ' && *cp != '\t')
		cp++;
	if (*cp != 0)
		*cp++ = 0;
	*cpp = cp;
	return (start);
}



/*
 * The following functions are simple wrappers/equivalents
 * for malloc, realloc, free, strdup and a special free
 * for strdup.
 */

static void *
sc_malloc(size_t n)
{
	void *p;

	p = malloc(n);
	if (p == NULL) {
		no_mem_err();
	}
	return (p);
}

/*ARGSUSED*/
static void *
sc_realloc(void *p, size_t current, size_t n)
{
	p = realloc(p, n);
	if (p == NULL) {
		no_mem_err();
	}
	return (p);
}


/*ARGSUSED*/
static void
sc_free(void *p, size_t n)
{
	free(p);
}


static char *
sc_strdup(char *cp)
{
	char *new;

	new = malloc((unsigned)(strlen(cp) + 1));
	if (new == NULL) {
		no_mem_err();
	}
	(void) strcpy(new, cp);
	return (new);
}


static void
sc_strfree(char *s)
{
	if (s)
		free(s);
}


/*
 * The following functions provide some simple dynamic string
 * capability.  This module has no hard-coded maximum string
 * lengths and should be able to parse and generate arbitrarily
 * long strings, macro expansion and command lines.
 *
 * Each string must be explicitly allocated and freed.
 */

/*
 * Allocate a dynamic string, with a hint to indicate how
 * much memory to dynamically add to the string as it grows
 * beyond its existing bounds, so as to avoid excessive
 * reallocs as a string grows.
 */
static str_t *
initstr(int hint)
{
	str_t	*str;

	str = sc_malloc(sizeof (str_t));
	str->s_str = NULL;
	str->s_len = 0;
	str->s_alloc = 0;
	str->s_hint = hint;
	return (str);
}


/*
 * Free a dynamically-allocated string
 */
static void
freestr(str_t *str)
{
	if (str->s_str) {
		sc_free(str->s_str, str->s_alloc);
	}
	sc_free(str, sizeof (str_t));
}


/*
 * Reset a dynamically-allocated string, allows reuse
 * rather than freeing the old and allocating a new one.
 */
static void
resetstr(str_t *str)
{
	str->s_len = 0;
}


/*
 * Concatenate a (simple) string onto a dynamically-allocated string
 */
static void
strcats(str_t *str, char *s)
{
	char	*new_str;
	int	len = str->s_len + strlen(s) + 1;

	if (str->s_alloc < len) {
		new_str = (str->s_str == NULL) ? sc_malloc(len+str->s_hint) :
			sc_realloc(str->s_str, str->s_alloc, len+str->s_hint);
		str->s_str = new_str;
		str->s_alloc = len + str->s_hint;
	}
	(void) strcpy(str->s_str + str->s_len, s);
	str->s_len = len - 1;
}


/*
 * Concatenate a character onto a dynamically-allocated string
 */
static void
strcatc(str_t *str, int c)
{
	char	*new_str;
	int	len = str->s_len + 2;

	if (str->s_alloc < len) {
		new_str = (str->s_str == NULL) ? sc_malloc(len+str->s_hint) :
			sc_realloc(str->s_str, str->s_alloc, len+str->s_hint);
		str->s_str = new_str;
		str->s_alloc = len + str->s_hint;
	}
	*(str->s_str + str->s_len) = (char)c;
	*(str->s_str + str->s_len + 1) = 0;
	str->s_len++;
}

/*
 * fgets() equivalent using a dynamically-allocated string
 */
static char *
fstrgets(str_t *line, FILE *fp)
{
	int	c;

	resetstr(line);
	while ((c = fgetc(fp)) != EOF) {
		strcatc(line, c);
		if (c == '\n')
			break;
	}
	if (line->s_len == 0)
		return (NULL);
	return (line->s_str);
}



#define	INITIAL_LISTSIZE	4
#define	INCR_LISTSIZE		4

static char **
build_strlist(
	char 	**argvlist,
	int	*size,
	int	*alloc,
	char	*str)
{
	int	n;

	if (*size + 1 > *alloc) {
		if (*alloc == 0) {
			*alloc = INITIAL_LISTSIZE;
			n = sizeof (char *) * (*alloc + 1);
			argvlist = (char **)malloc(n);
			if (argvlist == NULL)
				no_mem_err();
		} else {
			*alloc += INCR_LISTSIZE;
			n = sizeof (char *) * (*alloc + 1);
			argvlist = (char **)realloc(argvlist, n);
			if (argvlist == NULL)
				no_mem_err();
		}
	}

	argvlist[*size] = strdup(str);
	*size += 1;
	argvlist[*size] = NULL;

	return (argvlist);
}

static void
no_mem_err()
{
	(void) fprintf(stderr, MSG_NO_MEM, whoami);
	exit_lock();
	exit(EXIT_NO_MEM);
	/*NOTREACHED*/
}
