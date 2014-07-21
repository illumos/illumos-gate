/*
 * Copyright (c) 2002 John Rochester
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "man.h"
#include "stringlist.h"


/* Information collected about each man page in a section */
struct page_info {
	char	*filename;
	char	*name;
	char	*suffix;
	ino_t	inode;
};

/* An expanding string */
struct sbuf {
	char	*content;	/* the start of the buffer */
	char	*end;		/* just past the end of the content */
	char	*last;		/* the last allocated character */
};

/* Remove the last amount characters from the sbuf */
#define	sbuf_retract(sbuf, amount) ((sbuf)->end -= (amount))
/* Return the length of the sbuf content */
#define	sbuf_length(sbuf) ((sbuf)->end - (sbuf)->content)

typedef char *edited_copy(char *from, char *to, int length);

/*
 * While the whatis line is being formed, it is stored in whatis_proto.
 * When finished, it is reformatted into whatis_final and then appended
 * to whatis_lines.
 */
static struct sbuf	*whatis_proto;
static struct sbuf	*whatis_final;
static stringlist	*whatis_lines;	/* collected output lines */

static char tempfile[MAXPATHLEN];	/* path of temporary file, if any */

#define	MDOC_COMMANDS	"ArDvErEvFlLiNmPa"


/* Free a struct page_info and its content */
static void
free_page_info(struct page_info *info)
{

	free(info->filename);
	free(info->name);
	free(info->suffix);
	free(info);
}

/*
 * Allocate and fill in a new struct page_info given the
 * name of the man section directory and the dirent of the file.
 * If the file is not a man page, return NULL.
 */
static struct page_info *
new_page_info(char *dir, struct dirent *dirent)
{
	struct page_info *info;
	int		basename_length;
	char		*suffix;
	struct stat	st;

	if ((info = malloc(sizeof (struct page_info))) == NULL)
		err(1, "malloc");
	basename_length = strlen(dirent->d_name);
	suffix = &dirent->d_name[basename_length];
	if (asprintf(&info->filename, "%s/%s", dir, dirent->d_name) == -1)
		err(1, "asprintf");
	for (;;) {
		if (--suffix == dirent->d_name || !isalnum(*suffix)) {
			if (*suffix == '.')
				break;
			free(info->filename);
			free(info);
			return (NULL);
		}
	}
	*suffix++ = '\0';
	info->name = strdup(dirent->d_name);
	info->suffix = strdup(suffix);
	if (stat(info->filename, &st) < 0) {
		warn("%s", info->filename);
		free_page_info(info);
		return (NULL);
	}
	if (!S_ISREG(st.st_mode)) {
		free_page_info(info);
		return (NULL);
	}
	info->inode = st.st_ino;
	return (info);
}

/*
 * Reset sbuf length to 0.
 */
static void
sbuf_clear(struct sbuf *sbuf)
{

	sbuf->end = sbuf->content;
}

/*
 * Allocate a new sbuf.
 */
static struct sbuf *
new_sbuf(void)
{
	struct sbuf	*sbuf;

	if ((sbuf = malloc(sizeof (struct sbuf))) == NULL)
		err(1, "malloc");
	if ((sbuf->content = (char *)malloc(LINE_ALLOC)) == NULL)
		err(1, "malloc");
	sbuf->last = sbuf->content + LINE_ALLOC - 1;
	sbuf_clear(sbuf);

	return (sbuf);
}

/*
 * Ensure that there is enough room in the sbuf
 * for nchars more characters.
 */
static void
sbuf_need(struct sbuf *sbuf, int nchars)
{
	char *new_content;
	size_t size, cntsize;
	size_t grow = 128;

	while (grow < nchars) {
		grow += 128;	/* we grow in chunks of 128 bytes */
	}

	/* Grow if the buffer isn't big enough */
	if (sbuf->end + nchars > sbuf->last) {
		size = sbuf->last + 1 - sbuf->content;
		size += grow;
		cntsize = sbuf->end - sbuf->content;

		if ((new_content = realloc(sbuf->content, size)) == NULL) {
			perror("realloc");
			if (tempfile[0] != '\0')
				(void) unlink(tempfile);
			exit(1);
		}
		sbuf->content = new_content;
		sbuf->end = new_content + cntsize;
		sbuf->last = new_content + size - 1;
	}
}

/*
 * Append a string of a given length to the sbuf.
 */
static void
sbuf_append(struct sbuf *sbuf, const char *text, int length)
{
	if (length > 0) {
		sbuf_need(sbuf, length);
		(void) memcpy(sbuf->end, text, length);
		sbuf->end += length;
	}
}

/*
 * Append a null-terminated string to the sbuf.
 */
static void
sbuf_append_str(struct sbuf *sbuf, char *text)
{

	sbuf_append(sbuf, text, strlen(text));
}

/*
 * Append an edited null-terminated string to the sbuf.
 */
static void
sbuf_append_edited(struct sbuf *sbuf, char *text, edited_copy copy)
{
	int	length;

	if ((length = strlen(text)) > 0) {
		sbuf_need(sbuf, length);
		sbuf->end = copy(text, sbuf->end, length);
	}
}

/*
 * Strip any of a set of chars from the end of the sbuf.
 */
static void
sbuf_strip(struct sbuf *sbuf, const char *set)
{

	while (sbuf->end > sbuf->content && strchr(set, sbuf->end[-1]) != NULL)
		sbuf->end--;
}

/*
 * Return the null-terminated string built by the sbuf.
 */
static char *
sbuf_content(struct sbuf *sbuf)
{

	*sbuf->end = '\0';
	return (sbuf->content);
}

/*
 * Return true if no man page exists in the directory with
 * any of the names in the stringlist.
 */
static int
no_page_exists(char *dir, stringlist *names, char *suffix)
{
	char	path[MAXPATHLEN];
	char	*suffixes[] = { "", ".gz", ".bz2", NULL };
	size_t	i;
	int	j;

	for (i = 0; i < names->sl_cur; i++) {
		for (j = 0; suffixes[j] != NULL; j++) {
			(void) snprintf(path, MAXPATHLEN, "%s/%s.%s%s",
			    dir, names->sl_str[i], suffix, suffixes[j]);
			if (access(path, F_OK) == 0) {
				return (0);
			}
		}
	}
	return (1);
}

/* ARGSUSED sig */
static void
trap_signal(int sig)
{

	if (tempfile[0] != '\0')
		(void) unlink(tempfile);

	exit(1);
}

/*
 * Attempt to open an output file.
 * Return NULL if unsuccessful.
 */
static FILE *
open_output(char *name)
{
	FILE	*output;

	whatis_lines = sl_init();
	(void) snprintf(tempfile, MAXPATHLEN, "%s.tmp", name);
	name = tempfile;
	if ((output = fopen(name, "w")) == NULL) {
		warn("%s", name);
		return (NULL);
	}
	return (output);
}

static int
linesort(const void *a, const void *b)
{

	return (strcmp((*(const char * const *)a), (*(const char * const *)b)));
}

/*
 * Write the unique sorted lines to the output file.
 */
static void
finish_output(FILE *output, char *name)
{
	size_t	i;
	char	*prev = NULL;

	qsort(whatis_lines->sl_str, whatis_lines->sl_cur, sizeof (char *),
	    linesort);
	for (i = 0; i < whatis_lines->sl_cur; i++) {
		char *line = whatis_lines->sl_str[i];
		if (i > 0 && strcmp(line, prev) == 0)
			continue;
		prev = line;
		(void) fputs(line, output);
		(void) putc('\n', output);
	}
	(void) fclose(output);
	sl_free(whatis_lines, 1);
	(void) rename(tempfile, name);
	(void) unlink(tempfile);
}

static FILE *
open_whatis(char *mandir)
{
	char	filename[MAXPATHLEN];

	(void) snprintf(filename, MAXPATHLEN, "%s/%s", mandir, WHATIS);
	return (open_output(filename));
}

static void
finish_whatis(FILE *output, char *mandir)
{
	char	filename[MAXPATHLEN];

	(void) snprintf(filename, MAXPATHLEN, "%s/%s", mandir, WHATIS);
	finish_output(output, filename);
}

/*
 * Remove trailing spaces from a string, returning a pointer to just
 * beyond the new last character.
 */
static char *
trim_rhs(char *str)
{
	char	*rhs;

	rhs = &str[strlen(str)];
	while (--rhs > str && isspace(*rhs))
		;
	*++rhs = '\0';
	return (rhs);
}

/*
 * Return a pointer to the next non-space character in the string.
 */
static char *
skip_spaces(char *s)
{

	while (*s != '\0' && isspace(*s))
		s++;

	return (s);
}

/*
 * Return whether the line is of one of the forms:
 *	.Sh NAME
 *	.Sh "NAME"
 *	etc.
 * assuming that section_start is ".Sh".
 */
static int
name_section_line(char *line, const char *section_start)
{
	char		*rhs;

	if (strncmp(line, section_start, 3) != 0)
		return (0);
	line = skip_spaces(line + 3);
	rhs = trim_rhs(line);
	if (*line == '"') {
		line++;
		if (*--rhs == '"')
			*rhs = '\0';
	}
	if (strcmp(line, "NAME") == 0)
		return (1);

	return (0);
}

/*
 * Copy characters while removing the most common nroff/troff markup:
 *	\(em, \(mi, \s[+-N], \&
 *	\fF, \f(fo, \f[font]
 *	\*s, \*(st, \*[stringvar]
 */
static char *
de_nroff_copy(char *from, char *to, int fromlen)
{
	char	*from_end = &from[fromlen];

	while (from < from_end) {
		switch (*from) {
		case '\\':
			switch (*++from) {
			case '(':
				if (strncmp(&from[1], "em", 2) == 0 ||
				    strncmp(&from[1], "mi", 2) == 0) {
					from += 3;
					continue;
				}
				break;
			case 's':
				if (*++from == '-')
					from++;
				while (isdigit(*from))
					from++;
				continue;
			case 'f':
			case '*':
				if (*++from == '(') {
					from += 3;
				} else if (*from == '[') {
					while (*++from != ']' &&
					    from < from_end)
						;
					from++;
				} else {
					from++;
				}
				continue;
			case '&':
				from++;
				continue;
			}
			break;
		}
		*to++ = *from++;
	}
	return (to);
}

/*
 * Append a string with the nroff formatting removed.
 */
static void
add_nroff(char *text)
{

	sbuf_append_edited(whatis_proto, text, de_nroff_copy);
}

/*
 * Appends "name(suffix), " to whatis_final
 */
static void
add_whatis_name(char *name, char *suffix)
{

	if (*name != '\0') {
		sbuf_append_str(whatis_final, name);
		sbuf_append(whatis_final, "(", 1);
		sbuf_append_str(whatis_final, suffix);
		sbuf_append(whatis_final, "), ", 3);
	}
}

/*
 * Processes an old-style man(7) line. This ignores commands with only
 * a single number argument.
 */
static void
process_man_line(char *line)
{
	char	*p;

	if (*line == '.') {
		while (isalpha(*++line))
			;
		p = line = skip_spaces(line);
		while (*p != '\0') {
			if (!isdigit(*p))
				break;
			p++;
		}
		if (*p == '\0')
			return;
	} else
		line = skip_spaces(line);
	if (*line != '\0') {
		add_nroff(line);
		sbuf_append(whatis_proto, " ", 1);
	}
}

/*
 * Processes a new-style mdoc(7) line.
 */
static void
process_mdoc_line(char *line)
{
	int	xref;
	int	arg = 0;
	char	*line_end = &line[strlen(line)];
	int	orig_length = sbuf_length(whatis_proto);
	char	*next;

	if (*line == '\0')
		return;
	if (line[0] != '.' || !isupper(line[1]) || !islower(line[2])) {
		add_nroff(skip_spaces(line));
		sbuf_append(whatis_proto, " ", 1);
		return;
	}
	xref = strncmp(line, ".Xr", 3) == 0;
	line += 3;
	while ((line = skip_spaces(line)) < line_end) {
		if (*line == '"') {
			next = ++line;
			for (;;) {
				next = strchr(next, '"');
				if (next == NULL)
					break;
				(void) memmove(next, next + 1, strlen(next));
				line_end--;
				if (*next != '"')
					break;
				next++;
			}
		} else {
			next = strpbrk(line, " \t");
		}
		if (next != NULL)
			*next++ = '\0';
		else
			next = line_end;
		if (isupper(*line) && islower(line[1]) && line[2] == '\0') {
			if (strcmp(line, "Ns") == 0) {
				arg = 0;
				line = next;
				continue;
			}
			if (strstr(line, MDOC_COMMANDS) != NULL) {
				line = next;
				continue;
			}
		}
		if (arg > 0 && strchr(",.:;?!)]", *line) == 0) {
			if (xref) {
				sbuf_append(whatis_proto, "(", 1);
				add_nroff(line);
				sbuf_append(whatis_proto, ")", 1);
				xref = 0;
			} else {
				sbuf_append(whatis_proto, " ", 1);
			}
		}
		add_nroff(line);
		arg++;
		line = next;
	}
	if (sbuf_length(whatis_proto) > orig_length)
		sbuf_append(whatis_proto, " ", 1);
}

/*
 * Collect a list of comma-separated names from the text.
 */
static void
collect_names(stringlist *names, char *text)
{
	char	*arg;

	for (;;) {
		arg = text;
		text = strchr(text, ',');
		if (text != NULL)
			*text++ = '\0';
		(void) sl_add(names, arg);
		if (text == NULL)
			return;
		if (*text == ' ')
			text++;
	}
}

enum { STATE_UNKNOWN, STATE_MANSTYLE, STATE_MDOCNAME, STATE_MDOCDESC };

/*
 * Process a man page source into a single whatis line and add it
 * to whatis_lines.
 */
static void
process_page(struct page_info *page, char *section_dir)
{
	FILE		*fp;
	stringlist	*names;
	char		*descr;
	int		state = STATE_UNKNOWN;
	size_t		i;
	char		*line = NULL;
	size_t		linecap = 0;

	sbuf_clear(whatis_proto);
	if ((fp = fopen(page->filename, "r")) == NULL) {
		warn("%s", page->filename);
		return;
	}
	while (getline(&line, &linecap, fp) > 0) {
		/* Skip comments */
		if (strncmp(line, ".\\\"", 3) == 0)
			continue;
		switch (state) {
		/* Haven't reached the NAME section yet */
		case STATE_UNKNOWN:
			if (name_section_line(line, ".SH"))
				state = STATE_MANSTYLE;
			else if (name_section_line(line, ".Sh"))
				state = STATE_MDOCNAME;
			continue;
		/* Inside an old-style .SH NAME section */
		case STATE_MANSTYLE:
			if (strncmp(line, ".SH", 3) == 0 ||
			    strncmp(line, ".SS", 3) == 0)
				break;
			(void) trim_rhs(line);
			if (strcmp(line, ".") == 0)
				continue;
			if (strncmp(line, ".IX", 3) == 0) {
				line += 3;
				line = skip_spaces(line);
			}
			process_man_line(line);
			continue;
		/* Inside a new-style .Sh NAME section (the .Nm part) */
		case STATE_MDOCNAME:
			(void) trim_rhs(line);
			if (strncmp(line, ".Nm", 3) == 0) {
				process_mdoc_line(line);
				continue;
			} else {
				if (strcmp(line, ".") == 0)
					continue;
				sbuf_append(whatis_proto, "- ", 2);
				state = STATE_MDOCDESC;
			}
			/* FALLTHROUGH */
		/* Inside a new-style .Sh NAME section (after the .Nm-s) */
		case STATE_MDOCDESC:
			if (strncmp(line, ".Sh", 3) == 0)
				break;
			(void) trim_rhs(line);
			if (strcmp(line, ".") == 0)
				continue;
			process_mdoc_line(line);
			continue;
		}
		break;
	}
	(void) fclose(fp);
	sbuf_strip(whatis_proto, " \t.-");
	line = sbuf_content(whatis_proto);
	/*
	 * Line now contains the appropriate data, but without the
	 * proper indentation or the section appended to each name.
	 */
	descr = strstr(line, " - ");
	if (descr == NULL) {
		descr = strchr(line, ' ');
		if (descr == NULL)
			return;
		*descr++ = '\0';
	} else {
		*descr = '\0';
		descr += 3;
	}
	names = sl_init();
	collect_names(names, line);
	sbuf_clear(whatis_final);
	if (!sl_find(names, page->name) &&
	    no_page_exists(section_dir, names, page->suffix)) {
		/*
		 * Add the page name since that's the only
		 * thing that man(1) will find.
		 */
		add_whatis_name(page->name, page->suffix);
	}
	for (i = 0; i < names->sl_cur; i++)
		add_whatis_name(names->sl_str[i], page->suffix);
	sl_free(names, 0);
	/* Remove last ", " */
	sbuf_retract(whatis_final, 2);
	while (sbuf_length(whatis_final) < INDENT)
		sbuf_append(whatis_final, " ", 1);
	sbuf_append(whatis_final, " - ", 3);
	sbuf_append_str(whatis_final, skip_spaces(descr));
	(void) sl_add(whatis_lines, strdup(sbuf_content(whatis_final)));
}

/*
 * Sort pages first by inode number, then by name.
 */
static int
pagesort(const void *a, const void *b)
{
	const struct page_info *p1 = *(struct page_info * const *) a;
	const struct page_info *p2 = *(struct page_info * const *) b;

	if (p1->inode == p2->inode)
		return (strcmp(p1->name, p2->name));

	return (p1->inode - p2->inode);
}

/*
 * Process a single man section.
 */
static void
process_section(char *section_dir)
{
	struct dirent	**entries;
	int		nentries;
	struct page_info **pages;
	int		npages = 0;
	int		i;
	ino_t		prev_inode = 0;

	/* Scan the man section directory for pages */
	nentries = scandir(section_dir, &entries, NULL, alphasort);

	/* Collect information about man pages */
	pages = (struct page_info **)calloc(nentries,
	    sizeof (struct page_info *));
	for (i = 0; i < nentries; i++) {
		struct page_info *info = new_page_info(section_dir, entries[i]);
		if (info != NULL)
			pages[npages++] = info;
		free(entries[i]);
	}
	free(entries);
	qsort(pages, npages, sizeof (struct page_info *), pagesort);

	/* Process each unique page */
	for (i = 0; i < npages; i++) {
		struct page_info *page = pages[i];
		if (page->inode != prev_inode) {
			prev_inode = page->inode;
			process_page(page, section_dir);
		}
		free_page_info(page);
	}
	free(pages);
}

/*
 * Return whether the directory entry is a man page section.
 */
static int
select_sections(const struct dirent *entry)
{
	const char	*p = &entry->d_name[3];

	if (strncmp(entry->d_name, "man", 3) != 0)
		return (0);
	while (*p != '\0') {
		if (!isalnum(*p++))
			return (0);
	}
	return (1);
}

/*
 * Process a single top-level man directory by finding all the
 * sub-directories named man* and processing each one in turn.
 */
void
mwpath(char *path)
{
	FILE		*fp = NULL;
	struct dirent	**entries;
	int		nsections;
	int		i;

	(void) signal(SIGINT, trap_signal);
	(void) signal(SIGHUP, trap_signal);
	(void) signal(SIGQUIT, trap_signal);
	(void) signal(SIGTERM, trap_signal);

	whatis_proto = new_sbuf();
	whatis_final = new_sbuf();

	nsections = scandir(path, &entries, select_sections, alphasort);
	if ((fp = open_whatis(path)) == NULL)
		return;
	for (i = 0; i < nsections; i++) {
		char	section_dir[MAXPATHLEN];

		(void) snprintf(section_dir, MAXPATHLEN, "%s/%s",
		    path, entries[i]->d_name);
		process_section(section_dir);
		free(entries[i]);
	}
	free(entries);
	finish_whatis(fp, path);
}
