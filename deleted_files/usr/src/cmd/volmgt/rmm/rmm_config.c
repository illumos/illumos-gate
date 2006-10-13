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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<string.h>
#include	<errno.h>
#include	<libintl.h>
#include	<rmmount.h>
#include	<libgen.h>
#include	<sys/types.h>
#include	<rpc/types.h>
#include	<sys/param.h>
#include	<sys/stat.h>
#include	<regex.h>

#include	"rmm_int.h"


static void	conf_ident(int, char **, u_int);
static void	conf_action(int, char **, u_int);
static void	conf_fsck(int, char **, u_int);
static void	conf_mount(int, char **, u_int);
static void	conf_share(int, char **, u_int);


#define	IDENT_MEDARG	3
#define	FS_IDENT_PATH	"/usr/lib/fs"


static struct cmds {
	char	*name;
	void	(*func)(int, char **, u_int);
} cmd_list[] = {
	{ "ident", conf_ident },
	{ "action", conf_action },
	{ "fsck", conf_fsck },
	{ "mount", conf_mount },
	{ "share", conf_share },
	{ 0, 0}
};



/*
 * filesystem types recognized on the "mount" config line
 */
struct fs_names {
	char	*fn_name;
	u_int	fn_flag;
};
static struct fs_names fs_names[] = {
	{ "ufs",	MA_UFS },
	{ "hsfs",	MA_HSFS },
	{ "pcfs",	MA_PCFS },
	{ "dos",	MA_PCFS },
	{ "udfs",	MA_UDFS },
	{ 0, 0}
};


struct mount_args	**cmd_args[3] = {NULL, NULL, NULL};
static int		cmd_arg_index[3] = {0, 0, 0};


void
config_read()
{
	extern void	makeargv(int *, char **, char *);
	struct	cmds	*cmd;
	FILE		*cfp;
	char		buf[BUFSIZ];
	char		*wholeline = 0;
	char		*av[MAX_ARGC];
	int		ac;
	int		found;
	u_int		lineno = 0;
	size_t		len;
	size_t		linelen = 0;



	if ((cfp = fopen(rmm_config, "r")) == NULL) {
		(void) fprintf(stderr,
		    gettext("%s(%ld) error: open of \"%s\"; %s\n"),
		    prog_name, prog_pid, rmm_config, strerror(errno));
		exit(1);
	}

	while (fgets(buf, BUFSIZ, cfp) != NULL) {

		lineno++;

		/* skip comment lines (starting with #) and blanks */
		if ((buf[0] == '#') || (buf[0] == '\n')) {
			continue;
		}

		len = strlen(buf);

		if (buf[len-2] == '\\') {
			if (wholeline == NULL) {
				buf[len-2] = NULLC;
				wholeline = strdup(buf);
				linelen = len-2;
				continue;
			} else {
				buf[len-2] = NULLC;
				len -= 2;
				wholeline = (char *)realloc(wholeline,
				    linelen+len+1);
				(void) strcpy(&wholeline[linelen], buf);
				linelen += len;
				continue;
			}
		} else {
			if (wholeline == NULL) {
				/* just a one liner */
				wholeline = buf;
			} else {
				wholeline = (char *)realloc(wholeline,
				    linelen+len+1);
				(void) strcpy(&wholeline[linelen], buf);
				linelen += len;
			}
		}

		/* make a nice argc, argv thing for the commands */
		makeargv(&ac, av, wholeline);

		found = 0;
		for (cmd = cmd_list; cmd->name; cmd++) {
			if (strcmp(cmd->name, av[0]) == 0) {
				(*cmd->func)(ac, av, lineno);
				found++;
			}
		}
		if (!found) {
			(void) fprintf(stderr, gettext(
		"%s(%ld) warning: \"%s\" line %d: unknown directive \"%s\"\n"),
			    prog_name, prog_pid, rmm_config, lineno, av[0]);
		}
		if (wholeline != buf) {
			free(wholeline);
		}
		wholeline = NULL;
		linelen = 0;
	}
	(void) fclose(cfp);
}


/*
 * argv[0] = "action"
 * argv[1] = <optional_flag>
 * argv[next] = <media>
 * argv[next] = <dso>
 * [argv[next] = <action_arg[N]>]
 */
static void
conf_action(int argc, char **argv, u_int ln)
{
	int		nextarg;
	static int	ali;
	int		i;
	int		j;



	if (argc < 3) {
		(void) fprintf(stderr, gettext(
		    "%s(%ld) warning: \"%s\" line %d: insufficient args\n"),
		    prog_name, prog_pid, rmm_config, ln);
		return;
	}

	if (action_list == NULL) {
		action_list = (struct action_list **)calloc(MAX_ACTIONS,
		    sizeof (struct action_list *));
		ali = 0;
	}

	if (ali == MAX_ACTIONS) {
		(void) fprintf(stderr, gettext(
	"%s(%ld) warning: \"%s\" line %d: maximum actions (%d) exceeded\n"),
		    prog_name, prog_pid, rmm_config, ln, MAX_ACTIONS);
		return;
	}

	action_list[ali] = (struct action_list *)calloc(1,
	    sizeof (struct action_list));

	nextarg = 1;
	action_list[ali]->a_flag = 0;

	/*
	 * or in the bits for the flags.
	 */
	if (strcmp(argv[1], "-premount") == 0) {
		nextarg++;
		action_list[ali]->a_flag |= A_PREMOUNT;
	}

	action_list[ali]->a_media = strdup(argv[nextarg++]);
	/*
	 * Here, we just remember the name.  We won't actually
	 * load in the dso until we're sure that we need to
	 * call the function.
	 */
	action_list[ali]->a_dsoname = strdup(argv[nextarg++]);

	action_list[ali]->a_argc = argc - nextarg + 1;
	action_list[ali]->a_argv =
	    (char **)calloc(action_list[ali]->a_argc + 1, sizeof (char *));

	action_list[ali]->a_argv[0] = action_list[ali]->a_dsoname;
	for (i = nextarg, j = 1; i < argc; i++, j++) {
		action_list[ali]->a_argv[j] = strdup(argv[i]);
	}

	ali++;	/* next one... */
}


/*
 * argv[0] = "ident"
 * argv[1] = <fstype>
 * argv[2] = <dsoname>
 * argv[3] = <media>
 * [argv[n] = <media>]
 */
static void
conf_ident(int argc, char **argv, u_int ln)
{
	static int	ili;
	int		i;
	int		j;
	char		namebuf[MAXNAMELEN+1];


	if (argc < 3) {
		(void) fprintf(stderr, gettext(
		    "%s(%ld) warning: \"%s\" line %d: insufficient args\n"),
		    prog_name, prog_pid, rmm_config, ln);
		return;
	}

	if (ident_list == NULL) {
		ident_list = (struct ident_list **)calloc(MAX_IDENTS,
		    sizeof (struct ident_list *));
		ili = 0;
	}

	if (ili == MAX_IDENTS) {
		(void) fprintf(stderr, gettext(
	"%s(%ld) warning: \"%s\" line %d: %s maximum idents (%d) exceeded\n"),
		    prog_name, prog_pid, rmm_config, ln, MAX_IDENTS);
		return;
	}

	ident_list[ili] = (struct ident_list *)calloc(1,
	    sizeof (struct ident_list));
	ident_list[ili]->i_type = strdup(argv[1]);
	(void) sprintf(namebuf, "%s/%s/%s", FS_IDENT_PATH, argv[1], argv[2]);
	ident_list[ili]->i_dsoname = strdup(namebuf);
	ident_list[ili]->i_media = (char **)calloc(argc - IDENT_MEDARG+1,
	    sizeof (char *));

	for (i = IDENT_MEDARG, j = 0; i < argc; i++, j++) {
		ident_list[ili]->i_media[j] = strdup(argv[i]);
	}

	ili++;
}


/*
 * allocate mount args
 *   symname	- string containing media or file system regular expression
 *   key	- flag indicating file system type and/or command
 *   ln		- line number from config file, used for error messages
 */
static struct mount_args *
alloc_ma(char *symname, int key, int ln)
{
	char			*re_symname;
	struct mount_args	*ma,
				***argvp;
	int			*argcp;
	int			i;


	switch (key & MA_CMD_MASK) {
	case MA_FSCK:
		argvp = &cmd_args[CMD_FSCK];
		argcp = &cmd_arg_index[CMD_FSCK];
		break;
	case MA_MOUNT:
		argvp = &cmd_args[CMD_MOUNT];
		argcp = &cmd_arg_index[CMD_MOUNT];
		break;
	case MA_SHARE:
		argvp = &cmd_args[CMD_SHARE];
		argcp = &cmd_arg_index[CMD_SHARE];
		break;
	default:
		(void) fprintf(stderr, gettext(
			"%s(%ld) warning: \"%s\" line %d: unknown command\n"),
			prog_name, prog_pid, rmm_config, ln);
		return (NULL);
	}

	if (*argvp == NULL) {
		*argvp = (struct mount_args **)calloc(MAX_MOUNTS,
		    sizeof (struct mount_args *));
		*argcp = 0;
	}

	if (*argcp == MAX_MOUNTS) {
		(void) fprintf(stderr, gettext(
	"%s(%ld) warning: \"%s\" line %d: maximum mounts (%d) exceeded\n"),
		    prog_name, prog_pid, rmm_config, ln, MAX_MOUNTS);
		return (NULL);
	}
	/*
	 * See if we already have args for this symbolic name.
	 */
	re_symname = sh_to_regex(symname);
	for (ma = NULL, i = 0; i < *argcp; i++) {
		ma = (*argvp)[i];
		if (strcmp(re_symname, ma->ma_namere) == 0 &&
		    ma->ma_key == key) {
			break;
		}
	}

	/*
	 * if we don't already have a mount_args then allocate one
	 */
	if (i == *argcp) {

#ifdef	DEBUG_MA
		dprintf("alloc_ma: no existing mount args -- creating one\n");
#endif

		if ((ma = (struct mount_args *)calloc(1,
		    sizeof (struct mount_args))) == NULL) {
			(void) fprintf(stderr, gettext(
			"%s(%ld) error: can't allocate memory (error %d)\n"),
			    prog_name, prog_pid, errno);
			return (NULL);
		}

		/* convert to a useful regular expression */
		ma->ma_namere = re_symname;
		if (regcomp(&(ma->ma_re), ma->ma_namere, REG_NOSUB) != 0) {
			/* can't convert to compiled regex?? */
			free(ma);
			ma = NULL;
			(void) fprintf(stderr, gettext(
"%s(%ld) warning: \"%s\" line %d: unknown regular expression: \"%s\"\n"),
			    prog_name, prog_pid, rmm_config, ln,
			    ma->ma_namere);
		} else {
			ma->ma_key = key;
			(*argvp)[i] = ma;
			*argcp += 1;
#ifdef	DEBUG_MA
			dprintf(
			    "alloc_ma: added regexp \"%s\" to mount args\n",
			    ma->ma_namere);
#endif
		}
	}

	return (ma);
}


/*
 * argv[0] = "fsck"			the "fsck" keyword
 * argv[1] = <symdev>			name to match on
 * argv[...] = <fs_type>		0 or more filesystem types
 * argv[next] = "-o"			the "-o" keystring
 * argv[next...] = <option>		1 or more options
 */
static void
conf_fsck(int argc, char **argv, u_int ln)
{
	int			i;		/* arg index */
	int			j;		/* option/fs index */
	struct mount_args	*ma;		/* args struct ptr */
	int			opt_ind;	/* argv index */
	char			*optptr;	/* ptr to option */
	int			fs_found_cnt;	/* how many FSs found */
	int			key = MA_FSCK;	/* command key */


	/* first-level check */
	if (argc < 4) {
		(void) fprintf(stderr, gettext(
		    "%s(%ld) warning: \"%s\" line %d: insufficient args\n"),
		    prog_name, prog_pid, rmm_config, ln);
		return;
	}

	/* check for zero or more filesystem types */
	if (strcmp(argv[2], "-o") == 0) {

		/* no FS type(s) specified -- just like "all" */
		key |= MA_FS_ANY;

		opt_ind = 2;		/* options start here */

	} else {

		/* scan for which FS(s) specified */
		for (i = 2; i < argc; i++) {

			if (strcmp(argv[i], "-o") == 0) {
				break;		/* no more FSs specified */
			}

			fs_found_cnt = 0;
			for (j = 0; fs_names[j].fn_name != NULL; j++) {
				if (strcmp(argv[i],
				    fs_names[j].fn_name) == 0) {
					/* found a match */
					key |= fs_names[j].fn_flag;
					fs_found_cnt++;
				}
			}
			/* was this "fs" found in our list ?? */
			if (fs_found_cnt == 0) {
				(void) fprintf(stderr, gettext(
"%s(%ld) warning: \"%s\" line %d: filesystem type \"%s\" not recognized\n"),
				    prog_name, prog_pid, rmm_config, ln,
				    argv[i]);
			}
		}

		/* ensure at least one FS type is specified */
		if ((key & MA_FS_ANY) == 0) {
			(void) fprintf(stderr, gettext(
"%s(%ld) warning: \"%s\" line %d: no known filesystem type(s) specified\n"),
			    prog_name, prog_pid, rmm_config, ln);
			return;
		}

		opt_ind = i;			/* options start here */
	}

	/* ensure we have a mount_args structure for this name */
	if ((ma = alloc_ma(argv[1], key, ln)) == NULL) {
		return;
	}


	/*
	 * The option "list" is comma separated and without spaces.
	 * It should appear as a single "argument" in the argv vector.
	 */
	if ((opt_ind != argc-2) || (strcmp(argv[opt_ind], "-o") != 0)) {
		(void) fprintf(stderr,
				gettext("%s(%ld) warning: \"%s\" line %d: "
					"bad options specification\n"),
				prog_name, prog_pid, rmm_config, ln);
		return;
	}

	/* skip past the "-o" */
	opt_ind++;
	ma->ma_options = strdup(argv[opt_ind]);
}


/*
 * argv[0] = "mount"			the "mount" keyword
 * argv[1] = <symdev>			name to match on
 * argv[...] = <fs_type>		0 or more filesystem types
 * argv[next] = "-o"			the "-o" keystring
 * argv[next...] = <option>		1 or more options
 */
static void
conf_mount(int argc, char **argv, u_int ln)
{
	int			i;		/* arg index */
	int			j;		/* option/fs index */
	struct mount_args	*ma;		/* mount args struct ptr */
	int			opt_ind;	/* argv index */
	char			*optptr;	/* ptr to option */
	int			fs_found_cnt;	/* how many FSs found */
	int			key = MA_MOUNT;	/* command key */
	int			len;		/* length of option string */


	/* first-level check */
	if (argc < 4) {
		(void) fprintf(stderr, gettext(
		    "%s(%ld) warning: \"%s\" line %d: insufficient args\n"),
		    prog_name, prog_pid, rmm_config, ln);
		return;
	}

	/* check for zero or more filesystem types */
	if (strcmp(argv[2], "-o") == 0) {

		/* no FS type(s) specified -- just like "all" */
		key |= MA_FS_ANY;

		opt_ind = 2;		/* options start here */

	} else {

		/* scan for which FS(s) specified */
		for (i = 2; i < argc; i++) {

			if (strcmp(argv[i], "-o") == 0) {
				break;		/* no more FSs specified */
			}

			fs_found_cnt = 0;
			for (j = 0; fs_names[j].fn_name != NULL; j++) {
				if (strcmp(argv[i],
				    fs_names[j].fn_name) == 0) {
					/* found a match */
					key |= fs_names[j].fn_flag;
					fs_found_cnt++;
				}
			}
			/* was this "fs" found in our list ?? */
			if (fs_found_cnt == 0) {
				(void) fprintf(stderr, gettext(
"%s(%ld) warning: \"%s\" line %d: filesystem type \"%s\" not recognized\n"),
				    prog_name, prog_pid, rmm_config, ln,
				    argv[i]);
			}
		}

		/* ensure at least one FS type is specified */
		if ((key & MA_FS_ANY) == 0) {
			(void) fprintf(stderr, gettext(
"%s(%ld) warning: \"%s\" line %d: filesystem type(s) specified unknown\n"),
			    prog_name, prog_pid, rmm_config, ln);
			return;
		}

		opt_ind = i;			/* options start here */
	}

	/* ensure we have a mount_args structure for this name */
	if ((ma = alloc_ma(argv[1], key, ln)) == NULL) {
		return;
	}

	/*
	 * The option "list" should be a comma separated and without
	 * spaces, but, for backward compatibility, we will allow spaces
	 * as separators.
	 */
	if ((opt_ind > argc-2) || (strcmp(argv[opt_ind], "-o") != 0)) {
		(void) fprintf(stderr,
				gettext("%s(%ld) warning: \"%s\" line %d: "
					"bad options specification\n"),
				prog_name, prog_pid, rmm_config, ln);
		return;
	}

	/*
	 * Allocate memory in ma->ma_options for the option
	 * string on the "mount" options line in the config file.
	 */

	/*
	 * skip past the "-o"
	 */
	opt_ind++;

	for (len = 0, i = opt_ind; i < argc; i++) {
		/*
		 * Add an extra character for the comma between
		 * mount options, and one for the null string terminator
		 */
		len += strlen(argv[i]) + 1;
	}
	ma->ma_options = (char *)malloc(len);
	ma->ma_options[0] = NULLC;

	/*
	 * Do minimal parsing of the option list (would prefer to do
	 * none) to locate any "ro" or "rw" flags.  This information
	 * is necessary so that the apporiate mode can be propagated
	 * to the share command.  The flags are stripped from the
	 * option line and re-added later prior to the actual mount.
	 */
	for (i = opt_ind; i < argc; i++) {
		for (optptr = strtok(argv[i], ","); optptr;
		    optptr = strtok(0, ",")) {
			if ((strcmp(optptr, "ro") == 0) ||
			    (strcmp(optptr, "readonly") == 0))
				ma->ma_key |= MA_READONLY;
			else if (strcmp(optptr, "rw") != 0) {
				if (ma->ma_options[0] != NULLC)
					strcat(ma->ma_options, ",");
				strcat(ma->ma_options, optptr);
			}
		}
	}
}


/*
 * argv[0] = "share"			the "share" keyword
 * argv[1] = <symdev>			name to match on
 * argv[next...] = <option>		1 or more options
 */
static void
conf_share(int argc, char **argv, u_int ln)
{
	int			i;
	struct mount_args	*ma;
	char			buf[BUFSIZ];
	int			key = MA_SHARE | MA_FS_ANY;


	if (argc < 2) {
		(void) fprintf(stderr, gettext(
		    "%s(%ld) warning: \"%s\" line %d: insufficient args\n"),
		    prog_name, prog_pid, rmm_config, ln);
		return;
	}

	if ((ma = alloc_ma(argv[1], key, ln)) == NULL) {
		return;
	}

	/*
	 * start the buffer off right.
	 */
	buf[0] = NULLC;

	for (i = 2; i < argc; i++) {
		strcat(buf, argv[i]);
		strcat(buf, " ");
	}
	ma->ma_options = strdup(buf);
}


/*
 * return whether or not the supplied filesystem type is supported in
 *  the supplied mount arg struct
 */
bool_t
fs_supported(char *fs, struct mount_args *ma)
{
	int		i;
	bool_t		res = FALSE;


	for (i = 0; fs_names[i].fn_name != NULL; i++) {
		if (strcmp(fs_names[i].fn_name, fs) == 0) {
			if (ma->ma_key & fs_names[i].fn_flag) {
				res = TRUE;
			}
		}
	}
#ifdef	DEBUG
	dprintf("fs_supported(%s, %s) -> %s\n", fs, ma->ma_namere,
	    res ? "TRUE" : "FALSE");
#endif
	return (res);
}
