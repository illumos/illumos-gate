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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/param.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "rules.h"

char * lex(FILE *);

extern char *mstrdup(const char *);
extern void *mmalloc(size_t size);

void
read_rules(FILE *file, int (*rulefunc)())
{
	char *s;
	int base_active = 0;
	int list_ent_cnt = 0;
	int gign_ent_cnt = 0;
	int lign_ent_cnt = 0;
	struct item *add_item();
	struct item *fitem, *sitem;
	char version[20];

	last_gign = &gign_hd;
	gign_hd.i_next = (struct item *)0;
	gign_hd.i_str = (char *)0;
	list_hd.i_next = (struct item *)0;
	list_hd.i_str = (char *)0;
	while (s = lex(file)) {
		if (s == (char *)0)
			break;
		if (*s == '#')
			continue;
		if (*s == '*')
			continue;
		if (strcmp(s, BASE) == 0) {
#ifdef DEBUG
			printf("BASE base_active = %d\n", base_active);
#endif /* DEBUG */
			if (base_active) {
				/*
				 * Tack local IGNORE strings to end of globals
				 */
				if (lign_hd.i_next != (struct item *)0) {
					last_gign->i_next = &lign_hd;
				}
				/*
				 * Process directives for previous BASE command
				 * if there was one. Also free up LIST items
				 * and local IGNORE items.
				 */
				do_base_dir(basedir, &list_hd, &gign_hd,
				    rulefunc);
				/*
				 * Free up space from LIST item list
				 */
				fitem  = list_hd.i_next;
				if (fitem != (struct item *)0) {
					while (fitem != (struct item *)0) {
						free(fitem->i_str);
						sitem = fitem->i_next;
						free(fitem);
						fitem = sitem;
					}
				}
				/*
				 * Free up space from local IGNORE item list
				 */
				fitem  = lign_hd.i_next;
				if (fitem != (struct item *)0) {
					while (fitem != (struct item *)0) {
						free(fitem->i_str);
						sitem = fitem->i_next;
						free(fitem);
						fitem = sitem;
					}
				}
				last_gign->i_next = (struct item *)0;
			}
			base_active = 1;
			/*
			 * Reset LIST item list and local IGNORE item
			 * list to be empty.
			 */
			last_list = &list_hd;
			list_hd.i_next = (struct item *)0;
			list_hd.i_str = (char *)0;
			last_lign = &lign_hd;
			lign_hd.i_next = (struct item *)0;
			lign_hd.i_str = (char *)0;
			/*
			 * Get BASE directory specified
			 */
			s = lex(0);
			if (s == (char *)0) {
				fprintf(stderr, gettext("cachefspack: "));
				fprintf(stderr, gettext(
				    "illegal BASE command\n"));
				return;
			}

			if (*s == '$') {
				/*
				 * String starts with a '$', it must be an
				 * environment variable
				 */
				s = getenv(&s[1]);
				if (s == (char *)NULL) {
					fprintf(stderr,
					    gettext("cachefspack: "));
					fprintf(stderr,
					    gettext("Can't find "
					    "environment variable\n"));
					exit(1);
				}
			}
			basedir = mstrdup(s);
#ifdef DEBUG
			printf("basedir = %s\n", basedir);
#endif /* DEBUG */
			continue;
		}
		if (strcmp(s, IGNORE) == 0) {
#ifdef DEBUG
			printf("IGNORE - base_active = %d\n", base_active);
#endif /* DEBUG */
			if (base_active) {
				/*
				 * Local IGNORE rule
				 */
				while ((s = lex(0))
				    != 0) {
					last_lign = add_item(last_lign, s,
					    def_lign_flags);
				}
			} else {
				/*
				 * Global IGNORE rule
				 */
				while ((s = lex(0)) != 0) {
					last_gign = add_item(last_gign, s,
					    def_gign_flags);
				}
			}
			continue;
		}
		if (strcmp(s, LIST) == 0) {
#ifdef DEBUG
			printf("LIST\n");
#endif /* DEBUG */
			if (!base_active) {
				fprintf(stderr,
				    gettext(
				    "cachefspack: skipping LIST command - "));
				fprintf(stderr,
				    gettext(" no active base\n"));
				continue;
			}
			while ((s = lex(0)) != 0) {
				last_list = add_item(last_list, s,
				    def_list_flags);
			}
			continue;
		}
		if (strcmp(s, VERSION) == 0) {
			sprintf(version, "%d.%d", VERMAJOR, VERMINOR);
			s = lex(0);
			if (s == (char *)0) {
				fprintf(stderr, gettext("cachefspack: "));
				fprintf(stderr, gettext("missing version\n"));
				fprintf(stderr, gettext("cachefspack: "));
				fprintf(stderr, gettext(
				    "version = %d.%d\n"), VERMAJOR, VERMINOR);
				exit(1);
			}
			if (strcmp(version, s) != 0) {
				fprintf(stderr, gettext(
				    "cachefspack: "));
				fprintf(stderr, gettext(
				    "WARNING - version of packing rules "));
				fprintf(stderr, gettext(
				    "does not match cachefspack version\n"));
				fprintf(stderr, gettext(
				    "version = %d.%d\n"), VERMAJOR, VERMINOR);
			}
		}
	}
	/*
	 * Tack local IGNORE strings to end of globals
	 */
	if (lign_hd.i_next != (struct item *)0) {
		last_gign->i_next = &lign_hd;
	}
	do_base_dir(basedir, &list_hd, &gign_hd, rulefunc);
}

struct item *
add_item(struct item *last_item, char *str, int flags)
{
	struct item * add_cmd_items();

	if (*str == CMDCHAR) {
		last_item = add_cmd_items(last_item, &str[1], bang_list_flags);
	} else {
		last_item->i_next = (struct item *)mmalloc(
		    sizeof (struct item));
		last_item = last_item->i_next;
		last_item->i_str = mstrdup(str);
		last_item->i_flag = flags;
		last_item->i_next = (struct item *)0;
	}
	return (last_item);
}

struct item *
add_cmd_items(struct item *last_item, char *str, int flags)
{
	FILE *fd;
	char inbuf[MAX_RULE_SZ];
	char *olddir = NULL;
	char *s;
	void getcmd(char *, char *);

	if ((basedir != NULL) && (basedir[0] != '\0')) {
		olddir = getcwd(NULL, MAXPATHLEN + 1);
		if (olddir == NULL) {
			fprintf(stderr, gettext("cannot malloc buffer\n"));
			exit(1);
		}

		if (chdir(basedir) != 0) {
			fprintf(stderr, gettext("cannot chdir to %s: %s\n"),
			    basedir, strerror(errno));
			exit(1);
		}
	}

	getcmd(str, inbuf);
	fd = popen(inbuf, "r");
	if (fd == NULL) {
		fprintf(stderr, gettext("cachefspack: LIST can't execute - "));
		fprintf(stderr, "%s\n", inbuf);
		exit(1);
	}

	while (s = lex(fd)) {
		last_item = add_item(last_item, s, flags);
		while (s = lex(0)) {
			last_item = add_item(last_item, s, flags);
		}
	}
	if (pclose(fd) < 0) {
		fprintf(stderr, gettext("cachefspack: can't close pipe\n"));
	}

	if (olddir != NULL) {
		if (chdir(olddir) != 0) {
			fprintf(stderr, gettext("cannot return to %s: %s\n"),
			    olddir, strerror(errno));
			exit(1);
		}
		free(olddir);
	}

	return (last_item);
}

void
getcmd(char *str, char *buf)
{
	char *s;

	strcpy(buf, str);
	strcat(buf, " ");
	while (s = lex(0)) {
		strcat(buf, s);
		strcat(buf, " ");
	}
#ifdef DEBUG
	printf("getcmd: cmd = %s\n", buf);
#endif /* DEBUG */
}

/*
 * routine:
 *	lex
 *
 * purpose:
 *	my own version of strtok that handles quoting and escaping
 *
 * parameters:
 *	string to be lexed (or 0 for same string)
 *
 * returns:
 *	pointer to next token
 *
 * notes:
 *	this routine makes no changes to the string it is passed,
 *	copying tokens into a static buffer.
 */
char *
lex(FILE *fd)
{	char c, delim;
	char *p;
	const char *s;
	static const char *savep = 0;
	static char namebuf[MAX_RULE_SZ];
	static char inbuf[MAX_RULE_SZ];
	int len, space_left;
	char *err;

	/*
	 * if the file descriptor is non-zero read a new command. Otherwise
	 * get fields from current line.
	 */
	if (fd != 0) {
		len = 0;
		space_left = sizeof (inbuf);
		while ((err = fgets(&inbuf[len], space_left, fd)) != NULL) {
			len = strlen(inbuf);
			if (len == 1) {
				/*
				 * must be a blank line starting command.
				 * If a blank line occurs after the start of
				 * a command, blanks will be included in the
				 * command.
				 */
				len = 0;
				continue;
			}
			len -= 2;
			space_left -= len;
			s = (char *)((int)inbuf + len);
			/*
			 * Continuation character
			 */
			if (strcmp(s, "\\\n") == 0) {
				continue;
			}
			break;
		}
		if (err == NULL) {
			return (err);
		}
		s = inbuf;
	} else {
		if (savep == 0)
			return (0);
		s = savep;
	}
	savep = 0;

	/* skip over leading white space	*/
	while (isspace(*s))
		s++;
	if (*s == 0) {
		return (0);
	}

	/* see if this is a quoted string	*/
	c = *s;
	if (c == '\'' || c == '"') {
		delim = c;
		s++;
	} else
		delim = 0;

	/* copy the token into the buffer	*/
	for (p = namebuf; (c = *s) != 0; s++) {
		if ((p - namebuf) >= sizeof (namebuf)) {
			savep = 0;
			return (0);
		}
		/* literal escape		*/
		if (c == '\\') {
			s++;
			*p++ = *s;
			continue;
		}

		/* closing delimiter		*/
		if (c == delim) {
			s++;
			break;
		}

		/* delimiting white space	*/
		if (delim == 0 && isspace(c))
			break;

		/* ordinary characters		*/
		*p++ = *s;
	}


	/* remember where we left off		*/
	savep = *s ? s : 0;

	/* null terminate and return the buffer	*/
	*p = 0;
	return (namebuf);
}

char *
mk_base_dir(char *path, char *linkpath)
{
	static char pathb[MAXPATHLEN];
	char *dnam;
	char *get_dirname(char *);
	int len;

	/*
	 * absolute path name
	 */
	if (*linkpath == '/') {
		strcpy(pathb, linkpath);
	} else {
		/*
		 * relative path
		 */
		dnam = get_dirname(path);
		if (dnam == (char *)0) {
			return ((char *) 0);
		}
		strcpy(pathb, dnam);
		len = strlen(pathb);
		if (len == 0)
			return (pathb);
		if (pathb[len-1] != '/')
		    strcat(pathb, "/");
		if (strncmp(linkpath, "../", 3) == 0) {
			/*
			 * path is relative to directory containing sym link
			 * remove "../" from beginning of linkpath
			 */
			strcat(pathb, &linkpath[3]);
		} else {
			/*
			 * path is relative to directory containing sym link
			 */
			strcat(pathb, linkpath);
		}
	}
	return (pathb);
}
