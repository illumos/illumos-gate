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

#include "benv.h"
#include "message.h"
#include <ctype.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

/*
 * Usage:  % eeprom [-v] [-f prom_dev] [-]
 *	   % eeprom [-v] [-f prom_dev] field[=value] ...
 */

extern void get_kbenv(void);
extern void close_kbenv(void);
extern caddr_t get_propval(char *name, char *node);
extern void setprogname(char *prog);

char *boottree;
struct utsname uts_buf;

static int test;
int verbose;

/*
 * Concatenate a NULL terminated list of strings into
 * a single string.
 */
char *
strcats(char *s, ...)
{
	char *cp, *ret;
	size_t len;
	va_list ap;

	va_start(ap, s);
	for (ret = NULL, cp = s; cp; cp = va_arg(ap, char *)) {
		if (ret == NULL) {
			ret = strdup(s);
			len = strlen(ret) + 1;
		} else {
			len += strlen(cp);
			ret = realloc(ret, len);
			(void) strcat(ret, cp);
		}
	}
	va_end(ap);

	return (ret);
}

eplist_t *
new_list(void)
{
	eplist_t *list;

	list = (eplist_t *)malloc(sizeof (eplist_t));
	(void) memset(list, 0, sizeof (eplist_t));

	list->next = list;
	list->prev = list;
	list->item = NULL;

	return (list);
}

void
add_item(void *item, eplist_t *list)
{
	eplist_t *entry;

	entry = (eplist_t *)malloc(sizeof (eplist_t));
	(void) memset(entry, 0, sizeof (eplist_t));
	entry->item = item;

	entry->next = list;
	entry->prev = list->prev;
	list->prev->next = entry;
	list->prev = entry;
}

typedef struct benv_ent {
	char *cmd;
	char *name;
	char *val;
} benv_ent_t;

typedef struct benv_des {
	char *name;
	int fd;
	caddr_t adr;
	size_t len;
	eplist_t *elist;
} benv_des_t;

static benv_des_t *
new_bd(void)
{

	benv_des_t *bd;

	bd = (benv_des_t *)malloc(sizeof (benv_des_t));
	(void) memset(bd, 0, sizeof (benv_des_t));

	bd->elist = new_list();

	return (bd);
}

/*
 * Create a new entry.  Comment entries have NULL names.
 */
static benv_ent_t *
new_bent(char *comm, char *cmd, char *name, char *val)
{
	benv_ent_t *bent;

	bent = (benv_ent_t *)malloc(sizeof (benv_ent_t));
	(void) memset(bent, 0, sizeof (benv_ent_t));

	if (comm) {
		bent->cmd = strdup(comm);
		comm = NULL;
	} else {
		bent->cmd = strdup(cmd);
		bent->name = strdup(name);
		if (val)
			bent->val = strdup(val);
	}

	return (bent);
}

/*
 * Add a new entry to the benv entry list.  Entries can be
 * comments or commands.
 */
static void
add_bent(eplist_t *list, char *comm, char *cmd, char *name, char *val)
{
	benv_ent_t *bent;

	bent = new_bent(comm, cmd, name, val);
	add_item((void *)bent, list);
}

static benv_ent_t *
get_var(char *name, eplist_t *list)
{
	eplist_t *e;
	benv_ent_t *p;

	for (e = list->next; e != list; e = e->next) {
		p = (benv_ent_t *)e->item;
		if (p->name != NULL && strcmp(p->name, name) == 0)
			return (p);
	}

	return (NULL);
}

/*PRINTFLIKE1*/
static void
eeprom_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	(void) fprintf(stderr, "eeprom: ");
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
}

static int
exec_cmd(char *cmdline, char *output, int64_t osize)
{
	char buf[BUFSIZ];
	int ret;
	size_t len;
	FILE *ptr;
	sigset_t set;
	void (*disp)(int);

	if (output)
		output[0] = '\0';

	/*
	 * For security
	 * - only absolute paths are allowed
	 * - set IFS to space and tab
	 */
	if (*cmdline != '/') {
		eeprom_error(ABS_PATH_REQ, cmdline);
		return (-1);
	}
	(void) putenv("IFS= \t");

	/*
	 * We may have been exec'ed with SIGCHLD blocked
	 * unblock it here
	 */
	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGCHLD);
	if (sigprocmask(SIG_UNBLOCK, &set, NULL) != 0) {
		eeprom_error(FAILED_SIG, strerror(errno));
		return (-1);
	}

	/*
	 * Set SIGCHLD disposition to SIG_DFL for popen/pclose
	 */
	disp = sigset(SIGCHLD, SIG_DFL);
	if (disp == SIG_ERR) {
		eeprom_error(FAILED_SIG, strerror(errno));
		return (-1);
	}
	if (disp == SIG_HOLD) {
		eeprom_error(BLOCKED_SIG, cmdline);
		return (-1);
	}

	ptr = popen(cmdline, "r");
	if (ptr == NULL) {
		eeprom_error(POPEN_FAIL, cmdline, strerror(errno));
		return (-1);
	}

	/*
	 * If we simply do a pclose() following a popen(), pclose()
	 * will close the reader end of the pipe immediately even
	 * if the child process has not started/exited. pclose()
	 * does wait for cmd to terminate before returning though.
	 * When the executed command writes its output to the pipe
	 * there is no reader process and the command dies with
	 * SIGPIPE. To avoid this we read repeatedly until read
	 * terminates with EOF. This indicates that the command
	 * (writer) has closed the pipe and we can safely do a
	 * pclose().
	 *
	 * Since pclose() does wait for the command to exit,
	 * we can safely reap the exit status of the command
	 * from the value returned by pclose()
	 */
	while (fgets(buf, sizeof (buf), ptr) != NULL) {
		if (output && osize > 0) {
			(void) snprintf(output, osize, "%s", buf);
			len = strlen(buf);
			output += len;
			osize -= len;
		}
	}

	/*
	 * If there's a "\n" at the end, we want to chop it off
	 */
	if (output) {
		len = strlen(output) - 1;
		if (output[len] == '\n')
			output[len] = '\0';
	}

	ret = pclose(ptr);
	if (ret == -1) {
		eeprom_error(PCLOSE_FAIL, cmdline, strerror(errno));
		return (-1);
	}

	if (WIFEXITED(ret)) {
		return (WEXITSTATUS(ret));
	} else {
		eeprom_error(EXEC_FAIL, cmdline, ret);
		return (-1);
	}
}

#define	BOOTADM_STR	"bootadm: "

/*
 * bootadm starts all error messages with "bootadm: ".
 * Add a note so users don't get confused on how they ran bootadm.
 */
static void
output_error_msg(const char *msg)
{
	size_t len = sizeof (BOOTADM_STR) - 1;

	if (strncmp(msg, BOOTADM_STR, len) == 0) {
		eeprom_error("error returned from %s\n", msg);
	} else if (msg[0] != '\0') {
		eeprom_error("%s\n", msg);
	}
}

static char *
get_bootadm_value(char *name, const int quiet)
{
	char *ptr, *ret_str, *end_ptr, *orig_ptr;
	char output[BUFSIZ];
	int is_console, is_kernel = 0;
	size_t len;

	is_console = (strcmp(name, "console") == 0);

	if (strcmp(name, "boot-file") == 0) {
		is_kernel = 1;
		ptr = "/sbin/bootadm set-menu kernel 2>&1";
	} else if (is_console || (strcmp(name, "boot-args") == 0)) {
		ptr = "/sbin/bootadm set-menu args 2>&1";
	} else {
		eeprom_error("Unknown value in get_bootadm_value: %s\n", name);
		return (NULL);
	}

	if (exec_cmd(ptr, output, BUFSIZ) != 0) {
		if (quiet == 0) {
			output_error_msg(output);
		}
		return (NULL);
	}

	if (is_console) {
		if ((ptr = strstr(output, "console=")) == NULL) {
			return (NULL);
		}
		ptr += strlen("console=");

		/*
		 * -B may have comma-separated values.  It may also be
		 * followed by other flags.
		 */
		len = strcspn(ptr, " \t,");
		ret_str = calloc(len + 1, 1);
		if (ret_str == NULL) {
			eeprom_error(NO_MEM, len + 1);
			return (NULL);
		}
		(void) strncpy(ret_str, ptr, len);
		return (ret_str);
	} else if (is_kernel) {
		ret_str = strdup(output);
		if (ret_str == NULL)
			eeprom_error(NO_MEM, strlen(output) + 1);
		return (ret_str);
	} else {
		/* If there's no console setting, we can return */
		if ((orig_ptr = strstr(output, "console=")) == NULL) {
			return (strdup(output));
		}
		len = strcspn(orig_ptr, " \t,");
		ptr = orig_ptr;
		end_ptr = orig_ptr + len + 1;

		/* Eat up any white space */
		while ((*end_ptr == ' ') || (*end_ptr == '\t'))
			end_ptr++;

		/*
		 * If there's data following the console string, copy it.
		 * If not, cut off the new string.
		 */
		if (*end_ptr == '\0')
			*ptr = '\0';

		while (*end_ptr != '\0') {
			*ptr = *end_ptr;
			ptr++;
			end_ptr++;
		}
		*ptr = '\0';
		if ((strchr(output, '=') == NULL) &&
		    (strncmp(output, "-B ", 3) == 0)) {
			/*
			 * Since we removed the console setting, we no
			 * longer need the initial "-B "
			 */
			orig_ptr = output + 3;
		} else {
			orig_ptr = output;
		}

		ret_str = strdup(orig_ptr);
		if (ret_str == NULL)
			eeprom_error(NO_MEM, strlen(orig_ptr) + 1);
		return (ret_str);
	}
}

/*
 * If quiet is 1, print nothing if there is no value.  If quiet is 0, print
 * a message.  Return 1 if the value is printed, 0 otherwise.
 */
static int
print_bootadm_value(char *name, const int quiet)
{
	int rv = 0;
	char *value = get_bootadm_value(name, quiet);

	if ((value != NULL) && (value[0] != '\0')) {
		(void) printf("%s=%s\n", name, value);
		rv = 1;
	} else if (quiet == 0) {
		(void) printf("%s: data not available.\n", name);
	}

	if (value != NULL)
		free(value);
	return (rv);
}

static void
print_var(char *name, eplist_t *list)
{
	benv_ent_t *p;

	/*
	 * The console property is kept in both menu.lst and bootenv.rc.  The
	 * menu.lst value takes precedence.
	 */
	if (strcmp(name, "console") == 0) {
		if (print_bootadm_value(name, 1) == 0) {
			if ((p = get_var(name, list)) != NULL) {
				(void) printf("%s=%s\n", name, p->val ?
				    p->val : "");
			} else {
				(void) printf("%s: data not available.\n",
				    name);
			}
		}
	} else if ((strcmp(name, "boot-file") == 0) ||
	    (strcmp(name, "boot-args") == 0)) {
		(void) print_bootadm_value(name, 0);
	} else if ((p = get_var(name, list)) == NULL)
		(void) printf("%s: data not available.\n", name);
	else
		(void) printf("%s=%s\n", name, p->val ? p->val : "");
}

static void
print_vars(eplist_t *list)
{
	eplist_t *e;
	benv_ent_t *p;
	int console_printed = 0;

	/*
	 * The console property is kept both in menu.lst and bootenv.rc.
	 * The menu.lst value takes precedence, so try printing that one
	 * first.
	 */
	console_printed = print_bootadm_value("console", 1);

	for (e = list->next; e != list; e = e->next) {
		p = (benv_ent_t *)e->item;
		if (p->name != NULL) {
			if (((strcmp(p->name, "console") == 0) &&
			    (console_printed == 1)) ||
			    ((strcmp(p->name, "boot-file") == 0) ||
			    (strcmp(p->name, "boot-args") == 0))) {
				/* handle these separately */
				continue;
			}
			(void) printf("%s=%s\n", p->name, p->val ? p->val : "");
		}
	}
	(void) print_bootadm_value("boot-file", 1);
	(void) print_bootadm_value("boot-args", 1);
}

/*
 * Write a string to a file, quoted appropriately.  We use single
 * quotes to prevent any variable expansion.  Of course, we backslash-quote
 * any single quotes or backslashes.
 */
static void
put_quoted(FILE *fp, char *val)
{
	(void) putc('\'', fp);
	while (*val) {
		switch (*val) {
		case '\'':
		case '\\':
			(void) putc('\\', fp);
			/* FALLTHROUGH */
		default:
			(void) putc(*val, fp);
			break;
		}
		val++;
	}
	(void) putc('\'', fp);
}

static void
set_bootadm_var(char *name, char *value)
{
	char buf[BUFSIZ];
	char output[BUFSIZ] = "";
	char *console, *args;
	int is_console;

	if (verbose) {
		(void) printf("old:");
		(void) print_bootadm_value(name, 0);
	}

	/*
	 * For security, we single-quote whatever we run on the command line,
	 * and we don't allow single quotes in the string.
	 */
	if (strchr(value, '\'') != NULL) {
		eeprom_error("Single quotes are not allowed "
		    "in the %s property.\n", name);
		return;
	}

	is_console = (strcmp(name, "console") == 0);
	if (strcmp(name, "boot-file") == 0) {
		(void) snprintf(buf, BUFSIZ, "/sbin/bootadm set-menu "
		    "kernel='%s' 2>&1", value);
	} else if (is_console || (strcmp(name, "boot-args") == 0)) {
		if (is_console) {
			args = get_bootadm_value("boot-args", 1);
			console = value;
		} else {
			args = value;
			console = get_bootadm_value("console", 1);
		}
		if (((args == NULL) || (args[0] == '\0')) &&
		    ((console == NULL) || (console[0] == '\0'))) {
			(void) snprintf(buf, BUFSIZ, "/sbin/bootadm set-menu "
			    "args= 2>&1");
		} else if ((args == NULL) || (args[0] == '\0')) {
			(void) snprintf(buf, BUFSIZ, "/sbin/bootadm "
			    "set-menu args='-B console=%s' 2>&1",
			    console);
		} else if ((console == NULL) || (console[0] == '\0')) {
			(void) snprintf(buf, BUFSIZ, "/sbin/bootadm "
			    "set-menu args='%s' 2>&1", args);
		} else if (strncmp(args, "-B ", 3) != 0) {
			(void) snprintf(buf, BUFSIZ, "/sbin/bootadm "
			    "set-menu args='-B console=%s %s' 2>&1",
			    console, args);
		} else {
			(void) snprintf(buf, BUFSIZ, "/sbin/bootadm "
			    "set-menu args='-B console=%s,%s' 2>&1",
			    console, args + 3);
		}
	} else {
		eeprom_error("Unknown value in set_bootadm_value: %s\n", name);
		return;
	}

	if (exec_cmd(buf, output, BUFSIZ) != 0) {
		output_error_msg(output);
		return;
	}

	if (verbose) {
		(void) printf("new:");
		(void) print_bootadm_value(name, 0);
	}
}

/*
 * Returns 1 if bootenv.rc was modified, 0 otherwise.
 */
static int
set_var(char *name, char *val, eplist_t *list)
{
	benv_ent_t *p;
	int old_verbose;

	if ((strcmp(name, "boot-file") == 0) ||
	    (strcmp(name, "boot-args") == 0)) {
		set_bootadm_var(name, val);
		return (0);
	}

	/*
	 * The console property is kept in two places: menu.lst and bootenv.rc.
	 * Update them both.  We clear verbose to prevent duplicate messages.
	 */
	if (strcmp(name, "console") == 0) {
		old_verbose = verbose;
		verbose = 0;
		set_bootadm_var(name, val);
		verbose = old_verbose;
	}

	if (verbose) {
		(void) printf("old:");
		print_var(name, list);
	}

	if ((p = get_var(name, list)) != NULL) {
		free(p->val);
		p->val = strdup(val);
	} else
		add_bent(list, NULL, "setprop", name, val);

	if (verbose) {
		(void) printf("new:");
		print_var(name, list);
	}
	return (1);
}

/*
 * Returns 1 if bootenv.rc is modified or 0 if no modification was
 * necessary.  This allows us to implement non super-user look-up of
 * variables by name without the user being yelled at for trying to
 * modify the bootenv.rc file.
 */
static int
proc_var(char *name, eplist_t *list)
{
	register char *val;

	if ((val = strchr(name, '=')) == NULL) {
		print_var(name, list);
		return (0);
	} else {
		*val++ = '\0';
		return (set_var(name, val, list));
	}
}

static void
init_benv(benv_des_t *bd, char *file)
{
	get_kbenv();

	if (test)
		boottree = "/tmp";
	else if ((boottree = (char *)get_propval("boottree", "chosen")) == NULL)
		boottree = strcats("/boot", NULL);

	if (file != NULL)
		bd->name = file;
	else
		bd->name = strcats(boottree, "/solaris/bootenv.rc", NULL);
}

static void
map_benv(benv_des_t *bd)
{
	if ((bd->fd = open(bd->name, O_RDONLY)) == -1)
		if (errno == ENOENT)
			return;
		else
			exit(_error(PERROR, "cannot open %s", bd->name));

	if ((bd->len = (size_t)lseek(bd->fd, 0, SEEK_END)) == 0) {
		if (close(bd->fd) == -1)
			exit(_error(PERROR, "close error on %s", bd->name));
		return;
	}

	(void) lseek(bd->fd, 0, SEEK_SET);

	if ((bd->adr = mmap((caddr_t)0, bd->len, (PROT_READ | PROT_WRITE),
	    MAP_PRIVATE, bd->fd, 0)) == MAP_FAILED)
		exit(_error(PERROR, "cannot map %s", bd->name));
}

static void
unmap_benv(benv_des_t *bd)
{
	if (munmap(bd->adr, bd->len) == -1)
		exit(_error(PERROR, "unmap error on %s", bd->name));

	if (close(bd->fd) == -1)
		exit(_error(PERROR, "close error on %s", bd->name));
}

#define	NL	'\n'
#define	COMM	'#'

/*
 * Add a comment block to the benv list.
 */
static void
add_comm(benv_des_t *bd, char *base, char *last, char **next, int *line)
{
	int nl, lines;
	char *p;

	nl = 0;
	for (p = base, lines = 0; p < last; p++) {
		if (*p == NL) {
			nl++;
			lines++;
		} else if (nl) {
			if (*p != COMM)
				break;
			nl = 0;
		}
	}
	*(p - 1) = NULL;
	add_bent(bd->elist, base, NULL, NULL, NULL);
	*next = p;
	*line += lines;
}

/*
 * Parse out an operator (setprop) from the boot environment
 */
static char *
parse_cmd(benv_des_t *bd, char **next, int *line)
{
	char *strbegin;
	char *badeof = "unexpected EOF in %s line %d";
	char *syntax = "syntax error in %s line %d";
	char *c = *next;

	/*
	 * Skip spaces or tabs. New lines increase the line count.
	 */
	while (isspace(*c)) {
		if (*c++ == '\n')
			(*line)++;
	}

	/*
	 * Check for a the setprop command.  Currently that's all we
	 * seem to support.
	 *
	 * XXX need support for setbinprop?
	 */

	/*
	 * Check first for end of file.  Finding one now would be okay.
	 * We should also bail if we are at the start of a comment.
	 */
	if (*c == '\0' || *c == COMM) {
		*next = c;
		return (NULL);
	}

	strbegin = c;
	while (*c && !isspace(*c))
		c++;

	/*
	 * Check again for end of file.  Finding one now would NOT be okay.
	 */
	if (*c == '\0') {
		exit(_error(NO_PERROR, badeof, bd->name, *line));
	}

	*c++ = '\0';
	*next = c;

	/*
	 * Last check is to make sure the command is a setprop!
	 */
	if (strcmp(strbegin, "setprop") != 0) {
		exit(_error(NO_PERROR, syntax, bd->name, *line));
		/* NOTREACHED */
	}
	return (strbegin);
}

/*
 * Parse out the name (LHS) of a setprop from the boot environment
 */
static char *
parse_name(benv_des_t *bd, char **next, int *line)
{
	char *strbegin;
	char *badeof = "unexpected EOF in %s line %d";
	char *syntax = "syntax error in %s line %d";
	char *c = *next;

	/*
	 * Skip spaces or tabs. No tolerance for new lines now.
	 */
	while (isspace(*c)) {
		if (*c++ == '\n')
			exit(_error(NO_PERROR, syntax, bd->name, *line));
	}

	/*
	 * Grab a name for the property to set.
	 */

	/*
	 * Check first for end of file.  Finding one now would NOT be okay.
	 */
	if (*c == '\0') {
		exit(_error(NO_PERROR, badeof, bd->name, *line));
	}

	strbegin = c;
	while (*c && !isspace(*c))
		c++;

	/*
	 * At this point in parsing we have 'setprop name'.  What follows
	 * is a newline, other whitespace, or EOF.  Most of the time we
	 * want to replace a white space character with a NULL to terminate
	 * the name, and then continue on processing.  A newline here provides
	 * the most grief.  If we just replace it with a null we'll
	 * potentially get the setprop on the next line as the value of this
	 * setprop! So, if the last thing we see is a newline we'll have to
	 * dup the string.
	 */
	if (isspace(*c)) {
		if (*c == '\n') {
			*c = '\0';
			strbegin = strdup(strbegin);
			*c = '\n';
		} else {
			*c++ = '\0';
		}
	}

	*next = c;
	return (strbegin);
}

/*
 * Parse out the value (RHS) of a setprop line from the boot environment
 */
static char *
parse_value(benv_des_t *bd, char **next, int *line)
{
	char *strbegin;
	char *badeof = "unexpected EOF in %s line %d";
	char *result;
	char *c = *next;
	char quote;

	/*
	 * Skip spaces or tabs. A newline here would indicate a
	 * NULL property value.
	 */
	while (isspace(*c)) {
		if (*c++ == '\n') {
			(*line)++;
			*next = c;
			return (NULL);
		}
	}

	/*
	 * Grab the value of the property to set.
	 */

	/*
	 * Check first for end of file.  Finding one now would
	 * also indicate a NULL property.
	 */
	if (*c == '\0') {
		*next = c;
		return (NULL);
	}

	/*
	 * Value may be quoted, in which case we assume the end of the value
	 * comes with a closing quote.
	 *
	 * We also allow escaped quote characters inside the quoted value.
	 *
	 * For obvious reasons we do not attempt to parse variable references.
	 */
	if (*c == '"' || *c == '\'') {
		quote = *c;
		c++;
		strbegin = c;
		result = c;
		while (*c != quote) {
			if (*c == '\\') {
				c++;
			}
			if (*c == '\0') {
				break;
			}
			*result++ = *c++;
		}

		/*
		 *  Throw fatal exception if no end quote found.
		 */
		if (*c != quote) {
			exit(_error(NO_PERROR, badeof, bd->name, *line));
		}

		*result = '\0';		/* Terminate the result */
		c++;			/* and step past the close quote */
	} else {
		strbegin = c;
		while (*c && !isspace(*c))
			c++;
	}

	/*
	 * Check again for end of file.  Finding one now is okay.
	 */
	if (*c == '\0') {
		*next = c;
		return (strbegin);
	}

	*c++ = '\0';
	*next = c;
	return (strbegin);
}

/*
 * Add a command to the benv list.
 */
static void
add_cmd(benv_des_t *bd, char *last, char **next, int *line)
{
	char *cmd, *name, *val;

	while (*next <= last && **next != COMM) {
		if ((cmd = parse_cmd(bd, next, line)) == NULL)
			break;
		name = parse_name(bd, next, line);
		val = parse_value(bd, next, line);
		add_bent(bd->elist, NULL, cmd, name, val);
		(*line)++;
	};
}

/*
 * Parse the benv (bootenv.rc) file and break it into a benv
 * list.  List entries may be comment blocks or commands.
 */
static void
parse_benv(benv_des_t *bd)
{
	int line;
	char *pbase, *pend;
	char *tok, *tnext;

	line = 1;
	pbase = (char *)bd->adr;
	pend = pbase + bd->len;

	for (tok = tnext = pbase; tnext < pend && '\0' != *tnext; tok = tnext)
		if (*tok == COMM)
			add_comm(bd, tok, pend, &tnext, &line);
		else
			add_cmd(bd, pend, &tnext, &line);
}

static void
write_benv(benv_des_t *bd)
{
	FILE *fp;
	eplist_t *list, *e;
	benv_ent_t *bent;
	char *name;

	list = bd->elist;

	if (list->next == list)
		return;

	if ((fp = fopen(bd->name, "w")) == NULL)
		exit(_error(PERROR, "cannot open %s", bd->name));

	for (e = list->next; e != list; e = e->next) {
		bent = (benv_ent_t *)e->item;
		name = bent->name;
		if (name) {
			if (bent->val) {
				(void) fprintf(fp, "%s %s ",
				    bent->cmd, bent->name);
				put_quoted(fp, bent->val);
				(void) fprintf(fp, "\n");
			} else {
				(void) fprintf(fp, "%s %s\n",
				    bent->cmd, bent->name);
			}
		} else {
			(void) fprintf(fp, "%s\n", bent->cmd);
		}
	}

	(void) fclose(fp);
}

static char *
get_line(void)
{
	int c;
	char *nl;
	static char line[256];

	if (fgets(line, sizeof (line), stdin) != NULL) {
		/*
		 * Remove newline if present,
		 * otherwise discard rest of line.
		 */
		if (nl = strchr(line, '\n'))
			*nl = 0;
		else
			while ((c = getchar()) != '\n' && c != EOF)
				;
		return (line);
	} else
		return (NULL);
}

int
main(int argc, char **argv)
{
	int c;
	int updates = 0;
	char *usage = "Usage: %s [-v] [-f prom-device]"
	    " [variable[=value] ...]";
	eplist_t *elist;
	benv_des_t *bd;
	char *file = NULL;

	setprogname(argv[0]);

	while ((c = getopt(argc, argv, "f:Itv")) != -1)
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'f':
			file = optarg;
			break;
		case 't':
			test++;
			break;
		default:
			exit(_error(NO_PERROR, usage, argv[0]));
		}

	(void) uname(&uts_buf);
	bd = new_bd();
	init_benv(bd, file);

	map_benv(bd);
	if (bd->len) {
		parse_benv(bd);
		unmap_benv(bd);
	}

	elist = bd->elist;

	if (optind >= argc) {
		print_vars(elist);
		return (0);
	} else
		while (optind < argc) {
			/*
			 * If "-" specified, read variables from stdin;
			 * otherwise, process each argument as a variable
			 * print or set request.
			 */
			if (strcmp(argv[optind], "-") == 0) {
				char *line;

				while ((line = get_line()) != NULL)
					updates += proc_var(line, elist);
				clearerr(stdin);
			} else
				updates += proc_var(argv[optind], elist);

			optind++;
		}

	/*
	 * don't write benv if we are processing delayed writes since
	 * it is likely that the delayed writes changes bootenv.rc anyway...
	 */
	if (updates)
		write_benv(bd);
	close_kbenv();

	return (0);
}
