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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "benv.h"
#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <libzfsbootenv.h>

/*
 * Usage:  % eeprom [-v] [-f prom_dev] [-]
 *	   % eeprom [-v] [-f prom_dev] field[=value] ...
 */

extern void get_kbenv(void);
extern void close_kbenv(void);
extern caddr_t get_propval(char *name, char *node);
extern void setpname(char *prog);
extern char *getbootcmd(void);

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

static void
print_var(char *name, eplist_t *list)
{
	benv_ent_t *p;
	char *bootcmd;

	if (strcmp(name, "bootcmd") == 0) {
		bootcmd = getbootcmd();
		(void) printf("%s=%s\n", name, bootcmd ? bootcmd : "");
	} else if ((p = get_var(name, list)) == NULL) {
		(void) printf("%s: data not available.\n", name);
	} else {
		(void) printf("%s=%s\n", name, p->val ? p->val : "");
	}
}

static void
print_vars(eplist_t *list)
{
	eplist_t *e;
	benv_ent_t *p;

	for (e = list->next; e != list; e = e->next) {
		p = (benv_ent_t *)e->item;
		if (p->name != NULL) {
			(void) printf("%s=%s\n", p->name, p->val ? p->val : "");
		}
	}
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

/*
 * Returns 1 if bootenv.rc was modified, 0 otherwise.
 */
static int
set_var(char *name, char *val, eplist_t *list)
{
	benv_ent_t *p;

	if (strcmp(name, "bootcmd") == 0)
		return (0);

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
	*(p - 1) = '\0';
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

static int
add_pair(const char *name, const char *nvlist, const char *key,
    const char *type, const char *value)
{
	void *data, *nv;
	size_t size;
	int rv;
	char *end;

	rv = lzbe_nvlist_get(name, nvlist, &nv);
	if (rv != 0)
		return (rv);

	data = NULL;
	rv = EINVAL;
	if (strcmp(type, "DATA_TYPE_STRING") == 0) {
		data = (void *)(uintptr_t)value;
		size = strlen(data) + 1;
		rv = lzbe_add_pair(nv, key, type, data, size);
	} else if (strcmp(type, "DATA_TYPE_UINT64") == 0) {
		uint64_t v;

		v = strtoull(value, &end, 0);
		if (errno != 0 || *end != '\0')
			goto done;
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	} else if (strcmp(type, "DATA_TYPE_INT64") == 0) {
		int64_t v;

		v = strtoll(value, &end, 0);
		if (errno != 0 || *end != '\0')
			goto done;
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	} else if (strcmp(type, "DATA_TYPE_UINT32") == 0) {
		u_longlong_t lv;
		uint32_t v;

		lv = strtoull(value, &end, 0);
		if (errno != 0 || *end != '\0')
			goto done;
		if (lv > UINT32_MAX)
			goto done;
		v = lv;
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	} else if (strcmp(type, "DATA_TYPE_INT32") == 0) {
		longlong_t lv;
		int32_t v;

		lv = strtoll(value, &end, 0);
		if (errno != 0 || *end != '\0')
			goto done;
		if (lv < INT32_MIN || lv > INT32_MAX)
			goto done;
		v = lv;
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	} else if (strcmp(type, "DATA_TYPE_UINT16") == 0) {
		uint32_t lv;
		uint16_t v;

		lv = strtoul(value, &end, 0);
		if (errno != 0 || *end != '\0')
			goto done;
		if (lv > UINT16_MAX)
			goto done;
		v = lv;
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	} else if (strcmp(type, "DATA_TYPE_INT16") == 0) {
		int32_t lv;
		int16_t v;

		lv = strtol(value, &end, 0);
		if (errno != 0 || *end != '\0')
			goto done;
		if (lv < INT16_MIN || lv > INT16_MAX)
			goto done;
		v = lv;
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	} else if (strcmp(type, "DATA_TYPE_UINT8") == 0) {
		uint32_t lv;
		uint8_t v;

		lv = strtoul(value, &end, 0);
		if (errno != 0 || *end != '\0')
			goto done;
		if (lv > UINT8_MAX)
			goto done;
		v = lv;
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	} else if (strcmp(type, "DATA_TYPE_INT8") == 0) {
		int32_t lv;
		int8_t v;

		lv = strtol(value, &end, 0);
		if (errno != 0 || *end != '\0')
			goto done;
		if (lv < INT8_MIN || lv > INT8_MAX)
			goto done;
		v = lv;
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	} else if (strcmp(type, "DATA_TYPE_BYTE") == 0) {
		uint32_t lv;
		uint8_t v;

		lv = strtoul(value, &end, 0);
		if (errno != 0 || *end != '\0')
			goto done;
		if (lv > UINT8_MAX)
			goto done;
		v = lv;
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	} else if (strcmp(type, "DATA_TYPE_BOOLEAN_VALUE") == 0) {
		int32_t v;

		v = strtol(value, &end, 0);
		if (errno != 0 || *end != '\0') {
			if (strcasecmp(value, "YES") == 0)
				v = 1;
			else if (strcasecmp(value, "NO") == 0)
				v = 0;
			else if (strcasecmp(value, "true") == 0)
				v = 1;
			else if (strcasecmp(value, "false") == 0)
				v = 0;
			else goto done;
		}
		size = sizeof (v);
		rv = lzbe_add_pair(nv, key, type, &v, size);
	}

	if (rv == 0)
		rv = lzbe_nvlist_set(name, nvlist, nv);

done:
	lzbe_nvlist_free(nv);
	return (rv);
}

static int
delete_pair(const char *name, const char *nvlist, const char *key)
{
	void *nv;
	int rv;

	rv = lzbe_nvlist_get(name, nvlist, &nv);
	if (rv == 0)
		rv = lzbe_remove_pair(nv, key);

	if (rv == 0)
		rv = lzbe_nvlist_set(name, nvlist, nv);

	lzbe_nvlist_free(nv);
	return (rv);
}

static int
usage(char *name)
{
	char *usage = "Usage: %s [-v] [-f prom-device]"
	    " [variable[=value] ...]\n"
	    "%s [-z pool] [-d key] [-k key -t type -v value] [-p]\n"
	    "%s [-z pool] -n nvlist [-d key] [-k key -t type -v value] [-p]\n";

	return (_error(NO_PERROR, usage, name, name, name));
}

int
main(int argc, char **argv)
{
	int c;
	int updates = 0;
	eplist_t *elist;
	benv_des_t *bd;
	char *file = NULL;
	bool bootenv, bootenv_print, bootenv_delete;
	char *name, *key, *type, *nvlist, *value;
	lzbe_flags_t flag = lzbe_add;

	nvlist = NULL;
	name = "rpool";
	key = NULL;
	type = NULL;
	value = NULL;
	bootenv = false;
	bootenv_print = false;
	bootenv_delete = false;

	setpname(argv[0]);

	while ((c = getopt(argc, argv, "bd:f:k:n:prt:v:z:")) != -1)
		switch (c) {
		case 'b':
			bootenv = true;
			break;
		case 'd':
			if (bootenv) {
				bootenv_delete = true;
				key = optarg;
			} else {
				exit(usage(argv[0]));
			}
			break;
		case 'f':
			file = optarg;
			break;
		case 'k':
			if (bootenv)
				key = optarg;
			else
				exit(usage(argv[0]));
			break;
		case 'n':
			if (bootenv)
				nvlist = optarg;
			else
				exit(usage(argv[0]));
			break;
		case 'p':
			if (bootenv)
				bootenv_print = true;
			else
				exit(usage(argv[0]));
			break;
		case 'r':
			if (bootenv)
				flag = lzbe_replace;
			else
				exit(usage(argv[0]));
			break;
		case 't':
			if (bootenv)
				type = optarg;
			else
				test++;
			break;
		case 'v':
			if (bootenv)
				value = optarg;
			else
				verbose++;
			break;
		case 'z':
			if (bootenv)
				name = optarg;
			else
				exit(usage(argv[0]));
			break;
		default:
			exit(usage(argv[0]));
		}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (bootenv) {
		int rv = 0;

		if (argc == 1)
			value = argv[optind];

		if (bootenv_print)
			return (lzbe_bootenv_print(name, nvlist, stdout));

		if (key != NULL || value != NULL) {
			if (type == NULL)
				type = "DATA_TYPE_STRING";

			if (bootenv_delete)
				rv = delete_pair(name, nvlist, key);
			else if (key == NULL)
				rv = lzbe_set_boot_device(name, flag, value);
			else
				rv = add_pair(name, nvlist, key, type, value);

			if (rv == 0)
				printf("zfs bootenv is successfully written\n");
			else
				printf("error: %s\n", strerror(rv));
		}
		return (rv);
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
	} else {
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
