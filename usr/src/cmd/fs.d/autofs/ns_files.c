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
 *	ns_files.c
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <nsswitch.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs_prot.h>
#include <thread.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <synch.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <strings.h>
#include "automount.h"

static int read_execout(char *, char **, char *, char *, int);
static int call_read_execout(char *, char *, char *, int);
static FILE *file_open(char *, char *, char **, char ***);

/*
 * Initialize the stack
 */
void
init_files(char **stack, char ***stkptr)
{
	/*
	 * The call is bogus for automountd since the stack is
	 * is more appropriately initialized in the thread-private
	 * routines
	 */
	if (stack == NULL && stkptr == NULL)
		return;
	(void) stack_op(INIT, NULL, stack, stkptr);
}

int
getmapent_files(char *key, char *mapname, struct mapline *ml,
    char **stack, char ***stkptr, bool_t *iswildcard, bool_t isrestricted)
{
	int nserr;
	FILE *fp;
	char word[MAXPATHLEN+1], wordq[MAXPATHLEN+1];
	char linebuf[LINESZ], lineqbuf[LINESZ];
	char *lp, *lq;
	struct stat stbuf;
	char fname[MAXFILENAMELEN]; /* /etc prepended to mapname if reqd */
	int syntaxok = 1;

	if (iswildcard)
		*iswildcard = FALSE;
	if ((fp = file_open(mapname, fname, stack, stkptr)) == NULL) {
		nserr = __NSW_UNAVAIL;
		goto done;
	}

	if (stat(fname, &stbuf) < 0) {
		nserr = __NSW_UNAVAIL;
		goto done;
	}

	/*
	 * If the file has its execute bit on then
	 * assume it's an executable map.
	 * Execute it and pass the key as an argument.
	 * Expect to get a map entry on the stdout.
	 * Ignore the "x" bit on restricted maps.
	 */
	if (!isrestricted && (stbuf.st_mode & S_IXUSR)) {
		int rc;

		if (trace > 1) {
			trace_prt(1, "\tExecutable map: map=%s key=%s\n",
			    fname, key);
		}

		rc = call_read_execout(key, fname, ml->linebuf, LINESZ);

		if (rc != 0) {
			nserr = __NSW_UNAVAIL;
			goto done;
		}

		if (strlen(ml->linebuf) == 0) {
			nserr = __NSW_NOTFOUND;
			goto done;
		}

		unquote(ml->linebuf, ml->lineqbuf);
		nserr = __NSW_SUCCESS;
		goto done;
	}


	/*
	 * It's just a normal map file.
	 * Search for the entry with the required key.
	 */
	for (;;) {
		lp = get_line(fp, fname, linebuf, sizeof (linebuf));
		if (lp == NULL) {
			nserr = __NSW_NOTFOUND;
			goto done;
		}
		if (verbose && syntaxok && isspace(*(uchar_t *)lp)) {
			syntaxok = 0;
			syslog(LOG_ERR,
			    "leading space in map entry \"%s\" in %s",
			    lp, mapname);
		}
		lq = lineqbuf;
		unquote(lp, lq);
		if ((getword(word, wordq, &lp, &lq, ' ', sizeof (word))
		    == -1) || (word[0] == '\0'))
			continue;
		if (strcmp(word, key) == 0)
			break;
		if (word[0] == '*' && word[1] == '\0') {
			if (iswildcard)
				*iswildcard = TRUE;
			break;
		}
		if (word[0] == '+') {
			nserr = getmapent(key, word+1, ml, stack, stkptr,
			    iswildcard, isrestricted);
			if (nserr == __NSW_SUCCESS)
				goto done;
			continue;
		}

		/*
		 * sanity check each map entry key against
		 * the lookup key as the map is searched.
		 */
		if (verbose && syntaxok) { /* sanity check entry */
			if (*key == '/') {
				if (*word != '/') {
					syntaxok = 0;
					syslog(LOG_ERR, "bad key \"%s\" in "
					    "direct map %s\n", word, mapname);
				}
			} else {
				if (strchr(word, '/')) {
					syntaxok = 0;
					syslog(LOG_ERR, "bad key \"%s\" in "
					    "indirect map %s\n", word, mapname);
				}
			}
		}
	}

	(void) strcpy(ml->linebuf, lp);
	(void) strcpy(ml->lineqbuf, lq);
	nserr = __NSW_SUCCESS;
done:
	if (fp) {
		(void) stack_op(POP, (char *)NULL, stack, stkptr);
		(void) fclose(fp);
	}


	return (nserr);
}

int
getmapkeys_files(char *mapname, struct dir_entry **list, int *error,
    int *cache_time, char **stack, char ***stkptr)
{
	FILE *fp = NULL;
	char word[MAXPATHLEN+1], wordq[MAXPATHLEN+1];
	char linebuf[LINESZ], lineqbuf[LINESZ];
	char *lp, *lq;
	struct stat stbuf;
	char fname[MAXFILENAMELEN]; /* /etc prepended to mapname if reqd */
	int syntaxok = 1;
	int nserr;
	struct dir_entry *last = NULL;

	if (trace > 1)
		trace_prt(1, "getmapkeys_files %s\n", mapname);

	*cache_time = RDDIR_CACHE_TIME;
	if ((fp = file_open(mapname, fname, stack, stkptr)) == NULL) {
		*error = ENOENT;
		nserr = __NSW_UNAVAIL;
		goto done;
	}
	if (fseek(fp, 0L, SEEK_SET) == -1) {
		*error = ENOENT;
		nserr = __NSW_UNAVAIL;
		goto done;
	}

	if (stat(fname, &stbuf) < 0) {
		*error = ENOENT;
		nserr = __NSW_UNAVAIL;
		goto done;
	}

	/*
	 * If the file has its execute bit on then
	 * assume it's an executable map.
	 * I don't know how to list executable maps, return
	 * an empty map.
	 */
	if (stbuf.st_mode & S_IXUSR) {
		*error = 0;
		nserr = __NSW_SUCCESS;
		goto done;
	}
	/*
	 * It's just a normal map file.
	 * List entries one line at a time.
	 */
	for (;;) {
		lp = get_line(fp, fname, linebuf, sizeof (linebuf));
		if (lp == NULL) {
			nserr = __NSW_SUCCESS;
			goto done;
		}
		if (syntaxok && isspace(*(uchar_t *)lp)) {
			syntaxok = 0;
			syslog(LOG_ERR,
			    "leading space in map entry \"%s\" in %s",
			    lp, mapname);
		}
		lq = lineqbuf;
		unquote(lp, lq);
		if ((getword(word, wordq, &lp, &lq, ' ', MAXFILENAMELEN)
		    == -1) || (word[0] == '\0'))
			continue;
		/*
		 * Wildcard entries should be ignored and this should be
		 * the last entry read to corroborate the search through
		 * files, i.e., search for key until a wildcard is reached.
		 */
		if (word[0] == '*' && word[1] == '\0')
			break;
		if (word[0] == '+') {
			/*
			 * Name switch here
			 */
			getmapkeys(word+1, list, error, cache_time,
			    stack, stkptr, 0);
			/*
			 * the list may have been updated, therefore
			 * our 'last' may no longer be valid
			 */
			last = NULL;
			continue;
		}

		if (add_dir_entry(word, list, &last) != 0) {
			*error = ENOMEM;
			goto done;
		}
		assert(last != NULL);
	}

	nserr = __NSW_SUCCESS;
done:
	if (fp) {
		(void) stack_op(POP, (char *)NULL, stack, stkptr);
		(void) fclose(fp);
	}

	if (*list != NULL) {
		/*
		 * list of entries found
		 */
		*error = 0;
	}
	return (nserr);
}

int
loadmaster_files(char *mastermap, char *defopts, char **stack, char ***stkptr)
{
	FILE *fp;
	int done = 0;
	char *line, *dir, *map, *opts;
	char linebuf[LINESZ];
	char lineq[LINESZ];
	char fname[MAXFILENAMELEN]; /* /etc prepended to mapname if reqd */


	if ((fp = file_open(mastermap, fname, stack, stkptr)) == NULL)
		return (__NSW_UNAVAIL);

	while ((line = get_line(fp, fname, linebuf,
	    sizeof (linebuf))) != NULL) {
		unquote(line, lineq);
		if (macro_expand("", line, lineq, LINESZ)) {
			syslog(LOG_ERR, "map %s: line too long (max %d chars)",
			    mastermap, LINESZ - 1);
			continue;
		}
		dir = line;
		while (*dir && isspace(*dir))
			dir++;
		if (*dir == '\0')
			continue;
		map = dir;

		while (*map && !isspace(*map)) map++;
		if (*map)
			*map++ = '\0';

		if (*dir == '+') {
			opts = map;
			while (*opts && isspace(*opts))
				opts++;
			if (*opts != '-')
				opts = defopts;
			else
				opts++;
			/*
			 * Check for no embedded blanks.
			 */
			if (strcspn(opts, " 	") == strlen(opts)) {
				dir++;
				(void) loadmaster_map(dir, opts, stack, stkptr);
			} else {
pr_msg("Warning: invalid entry for %s in %s ignored.\n", dir, fname);
				continue;
			}

		} else {
			while (*map && isspace(*map))
				map++;
			if (*map == '\0')
				continue;
			opts = map;
			while (*opts && !isspace(*opts))
				opts++;
			if (*opts) {
				*opts++ = '\0';
				while (*opts && isspace(*opts))
					opts++;
			}
			if (*opts != '-')
				opts = defopts;
			else
				opts++;
			/*
			 * Check for no embedded blanks.
			 */
			if (strcspn(opts, " 	") == strlen(opts)) {
				dirinit(dir, map, opts, 0, stack, stkptr);
			} else {
pr_msg("Warning: invalid entry for %s in %s ignored.\n", dir, fname);
				continue;
			}
		}
		done++;
	}

	(void) stack_op(POP, (char *)NULL, stack, stkptr);
	(void) fclose(fp);

	return (done ? __NSW_SUCCESS : __NSW_NOTFOUND);
}

int
loaddirect_files(char *map, char *local_map, char *opts,
    char **stack, char ***stkptr)
{
	FILE *fp;
	int done = 0;
	char *line, *p1, *p2;
	char linebuf[LINESZ];
	char fname[MAXFILENAMELEN]; /* /etc prepended to mapname if reqd */

	if ((fp = file_open(map, fname, stack, stkptr)) == NULL)
		return (__NSW_UNAVAIL);

	while ((line = get_line(fp, fname, linebuf,
	    sizeof (linebuf))) != NULL) {
		p1 = line;
		while (*p1 && isspace(*p1))
			p1++;
		if (*p1 == '\0')
			continue;
		p2 = p1;
		while (*p2 && !isspace(*p2))
			p2++;
		*p2 = '\0';
		if (*p1 == '+') {
			p1++;
			(void) loaddirect_map(p1, local_map, opts, stack,
			    stkptr);
		} else {
			dirinit(p1, local_map, opts, 1, stack, stkptr);
		}
		done++;
	}

	(void) stack_op(POP, (char *)NULL, stack, stkptr);
	(void) fclose(fp);

	return (done ? __NSW_SUCCESS : __NSW_NOTFOUND);
}

/*
 * This procedure opens the file and pushes it onto the
 * the stack. Only if a file is opened successfully, is
 * it pushed onto the stack
 */
static FILE *
file_open(char *map, char *fname, char **stack, char ***stkptr)
{
	FILE *fp;

	if (*map != '/') {
		/* prepend an "/etc" */
		(void) strcpy(fname, "/etc/");
		(void) strcat(fname, map);
	} else {
		(void) strcpy(fname, map);
	}

	fp = fopen(fname, "r");

	if (fp != NULL) {
		if (!stack_op(PUSH, fname, stack, stkptr)) {
			(void) fclose(fp);
			return (NULL);
		}
	}
	return (fp);
}

/*
 * reimplemnted to be MT-HOT.
 */
int
stack_op(int op, char *name, char **stack, char ***stkptr)
{
	char **ptr = NULL;
	char **stk_top = &stack[STACKSIZ - 1];

	/*
	 * the stackptr points to the next empty slot
	 * for PUSH: put the element and increment stkptr
	 * for POP: decrement stkptr and free
	 */

	switch (op) {
	case INIT:
		for (ptr = stack; ptr != stk_top; ptr++)
			*ptr = (char *)NULL;
		*stkptr = stack;
		return (1);
	case ERASE:
		for (ptr = stack; ptr != stk_top; ptr++)
			if (*ptr) {
				if (trace > 1)
					trace_prt(1, "  ERASE %s\n", *ptr);
				free (*ptr);
				*ptr = (char *)NULL;
			}
		*stkptr = stack;
		return (1);
	case PUSH:
		if (*stkptr == stk_top)
			return (0);
		for (ptr = stack; ptr != *stkptr; ptr++)
			if (*ptr && (strcmp(*ptr, name) == 0)) {
				return (0);
			}
		if (trace > 1)
			trace_prt(1, "  PUSH %s\n", name);
		if ((**stkptr = strdup(name)) == NULL) {
			syslog(LOG_ERR, "stack_op: Memory alloc failed : %m");
			return (0);
		}
		(*stkptr)++;
		return (1);
	case POP:
		if (*stkptr != stack)
			(*stkptr)--;
		else
			syslog(LOG_ERR, "Attempt to pop empty stack\n");

		if (*stkptr && **stkptr) {
			if (trace > 1)
				trace_prt(1, "  POP %s\n", **stkptr);
			free (**stkptr);
			**stkptr = (char *)NULL;
		}
		return (1);
	default:
		return (0);
	}
}

#define	READ_EXECOUT_ARGS 3

/*
 * read_execout(char *key, char **lp, char *fname, char *line, int linesz)
 * A simpler, multithreaded implementation of popen(). Used due to
 * non multithreaded implementation of popen() (it calls vfork()) and a
 * significant bug in execl().
 * Returns 0 on OK or -1 on error.
 */
static int
read_execout(char *key, char **lp, char *fname, char *line, int linesz)
{
	int p[2];
	int status = 0;
	int child_pid;
	char *args[READ_EXECOUT_ARGS];
	FILE *fp0;

	if (pipe(p) < 0) {
		syslog(LOG_ERR, "read_execout: Cannot create pipe");
		return (-1);
	}

	/* setup args for execv */
	if (((args[0] = strdup(fname)) == NULL) ||
	    ((args[1] = strdup(key)) == NULL)) {
		if (args[0] != NULL)
			free(args[0]);
		syslog(LOG_ERR, "read_execout: Memory allocation failed");
		return (-1);
	}
	args[2] = NULL;

	if (trace > 3)
		trace_prt(1, "\tread_execout: forking .....\n");

	switch ((child_pid = fork1())) {
	case -1:
		syslog(LOG_ERR, "read_execout: Cannot fork");
		return (-1);
	case 0:
		/*
		 * Child
		 */
		close(p[0]);
		close(1);
		if (fcntl(p[1], F_DUPFD, 1) != 1) {
			syslog(LOG_ERR,
			"read_execout: dup of stdout failed");
			_exit(-1);
		}
		close(p[1]);
		execv(fname, &args[0]);
		_exit(-1);
	default:
		/*
		 * Parent
		 */
		close(p[1]);

		/*
		 * wait for child to complete. Note we read after the
		 * child exits to guarantee a full pipe.
		 */
		while (waitpid(child_pid, &status, 0) < 0) {
			/* if waitpid fails with EINTR, restart */
			if (errno != EINTR) {
				status = -1;
				break;
			}
		}
		if (status != -1) {
			if ((fp0 = fdopen(p[0], "r")) != NULL) {
				*lp = get_line(fp0, fname, line, linesz);
				fclose(fp0);
			} else {
				close(p[0]);
				status = -1;
			}
		} else {
			close(p[0]);
		}

		/* free args */
		free(args[0]);
		free(args[1]);

		if (trace > 3) {
			trace_prt(1, "\tread_execout: map=%s key=%s line=%s\n",
			    fname, key, line);
		}

		return (status);
	}
}

void
automountd_do_exec_map(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dfd, uint_t n_desc)
{
	command_t	*command;
	char	line[LINESZ];
	char	*lp;
	int	rc;

	command = (command_t *)argp;

	if (sizeof (*command) != arg_size) {
		rc = 0;
		syslog(LOG_ERR, "read_execout: invalid door arguments");
		door_return((char *)&rc, sizeof (rc), NULL, 0);
	}

	rc = read_execout(command->key, &lp, command->file, line, LINESZ);

	if (rc != 0) {
		/*
		 * read_execout returned an error, return 0 to the door_client
		 * to indicate failure
		 */
		rc = 0;
		door_return((char *)&rc, sizeof (rc), NULL, 0);
	} else {
		door_return((char *)line, LINESZ, NULL, 0);
	}
	trace_prt(1, "automountd_do_exec_map, door return failed %s, %s\n",
	    command->file, strerror(errno));
	door_return(NULL, 0, NULL, 0);
}

static int
call_read_execout(char *key, char *fname, char *line, int linesz)
{
	command_t command;
	door_arg_t darg;
	int ret;

	bzero(&command, sizeof (command));
	(void) strlcpy(command.file, fname, MAXPATHLEN);
	(void) strlcpy(command.key, key, MAXOPTSLEN);

	if (trace >= 1)
		trace_prt(1, "call_read_execout %s %s\n", fname, key);
	darg.data_ptr = (char *)&command;
	darg.data_size = sizeof (command);
	darg.desc_ptr = NULL;
	darg.desc_num = 0;
	darg.rbuf = line;
	darg.rsize = linesz;

	ret = door_call(did_exec_map, &darg);

	return (ret);
}
