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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "gnu_msgfmt.h"

static int	next_entry_is_fuzzy = 0;
static int	next_entry_is_c_format = 0;
static struct catalog	*cur_catalog = NULL;
static char	*cur_mo = NULL;

FILE	*fp;
iconv_t	cd = (iconv_t)-1;
struct catalog	*catalog_head = NULL;
int	cur_po_index = 0;

static size_t
search_alias(char **paddr, size_t size, const char *variant)
{
	char	*addr = *paddr;
	char 	*p, *sp, *q;
	size_t	var_len, can_len;

	var_len = strlen(variant);
	p = addr;
	q = addr + size;
	while (q > p) {
		if (*p == '#') {
			/*
			 * Line beginning with '#' is a comment
			 */
			p++;
			while ((q > p) && (*p++ != '\n'))
				;
			continue;
		}
		/* skip leading spaces */
		while ((q > p) &&
		    ((*p == ' ') || (*p == '\t')))
			p++;
		if (q <= p)
			break;
		sp = p;
		while ((q > p) && (*p != ' ') &&
		    (*p != '\t') && (*p != '\n'))
			p++;
		if (q <= p) {
			/* invalid entry */
			break;
		}
		if (*p == '\n') {
			/* invalid entry */
			p++;
			continue;
		}

		if (((p - sp) != var_len) ||
		    ((strncmp(sp, variant, var_len) != 0) &&
		    (strncasecmp(sp, variant, var_len) != 0))) {
			/*
			 * didn't match
			 */

			/* skip remaining chars in this line */
			p++;
			while ((q > p) && (*p++ != '\n'))
				;
			continue;
		}

		/* matching entry found */

		/* skip spaces */
		while ((q > p) &&
		    ((*p == ' ') || (*p == '\t')))
			p++;
		if (q <= p)
			break;
		sp = p;
		while ((q > p) && (*p != ' ') &&
		    (*p != '\t') && (*p != '\n'))
			p++;
		can_len = p - sp;
		if (can_len == 0) {
			while ((q > p) && (*p++ != '\n'))
				;
			continue;
		}
		*paddr = sp;
		return (can_len);
	}
	return (0);
}

/*
 * Checks if the specified charset is equivalent to UTF-8.
 * If it's equivalent to UTF-8, returns 1; Otherwise, returns 0.
 */
static int
check_utf8(const char *charset)
{
	int	fd;
	struct stat64	statbuf;
	caddr_t	addr;
	size_t	buflen, charset_len, utf8_len;
	char	*c_charset, *c_utf8, *p;

	if (strcmp(charset, DEST_CHARSET) == 0)
		return (1);

	fd = open(_ENCODING_ALIAS_PATH, O_RDONLY);
	if (fd == -1) {
		/* no alias file found */
		return (0);
	}
	if (fstat64(fd, &statbuf) == -1) {
		(void) close(fd);
		return (0);
	}
	buflen = (size_t)statbuf.st_size;
	addr = mmap(NULL, buflen, PROT_READ, MAP_SHARED, fd, 0);
	(void) close(fd);
	if (addr == MAP_FAILED) {
		warning("mmap() for %s failed.", _ENCODING_ALIAS_PATH);
		return (0);
	}
	p = (char *)addr;
	charset_len = search_alias(&p, buflen, charset);
	if (charset_len) {
		c_charset = alloca(charset_len + 1);
		(void) memcpy(c_charset, p, charset_len);
		c_charset[charset_len] = '\0';
	} else {
		c_charset = (char *)charset;
	}
	p = (char *)addr;
	utf8_len = search_alias(&p, buflen, DEST_CHARSET);
	if (utf8_len) {
		c_utf8 = alloca(utf8_len + 1);
		(void) memcpy(c_utf8, p, utf8_len);
		c_utf8[utf8_len] = '\0';
	} else {
		c_utf8 = DEST_CHARSET;
	}
	(void) munmap(addr, buflen);
	if (charset_len == 0 && utf8_len == 0) {
		/*
		 * Entry for neither charset nor utf8 found
		 */
		return (0);
	}

	if (strcmp(c_charset, c_utf8) == 0)
		return (1);
	else
		return (0);
}

static void
conv_init(const char *charset)
{
	if (charset == NULL) {
		/*
		 * No conversion
		 */
		cd = (iconv_t)-1;
		return;
	}
	if (check_utf8(charset)) {
		/*
		 * Charset is UTF-8.
		 * No conversion is required.
		 */
		cd = (iconv_t)-1;
		return;
	}
	cd = iconv_open(DEST_CHARSET, charset);
	if (cd == (iconv_t)-1) {
		/*
		 * No such a conversion
		 */
		warning(gettext(WARN_NOCONV),
			cur_line, cur_po, charset, DEST_CHARSET);
		return;
	}
}

void
clear_state(void)
{
	next_entry_is_fuzzy = 0;
	next_entry_is_c_format = 0;
}

void
handle_domain(char *domainname)
{
	if (outfile) {
		/*
		 * outfile has been specified by -o option
		 * ignore all domain directives
		 */
		if (verbose_flag) {
			diag(gettext(DIAG_IGNORE_DOMAIN),
				cur_line, cur_po, domainname);
		}
		free(domainname);
		return;
	}

	if (strict_flag) {
		/*
		 * add ".mo" to the domain
		 */
		char	*tmp;
		tmp = Xrealloc(domainname, strlen(domainname) + 3 + 1);
		(void) strcat(tmp, ".mo");
		domainname = tmp;
	}
	catalog_init(domainname);
	free(domainname);
}

void
catalog_init(const char *filename)
{
	struct catalog	*p;

	if (!catalog_head) {
		p = Xcalloc(1, sizeof (struct catalog));
		p->fname = Xstrdup(filename);
		p->msg_size = DEF_MSG_NUM;
		p->nmsg = 0;
		p->msg = Xcalloc(p->msg_size, sizeof (struct messages));
		p->thash_size = find_prime(DEF_MSG_NUM);
		p->thash = Xcalloc(p->thash_size, sizeof (unsigned int));
		catalog_head = p;
	} else {
		p = catalog_head;
		for (; ; ) {
			struct catalog	*tmp;
			if (strcmp(p->fname, filename) == 0) {
				/* already registered */
				break;
			}
			if (p->next) {
				p = p->next;
				continue;
			}
			/*
			 * this domain hasn't been registered
			 */
			tmp = Xcalloc(1, sizeof (struct catalog));
			tmp->fname = Xstrdup(filename);
			tmp->msg_size = DEF_MSG_NUM;
			tmp->nmsg = 0;
			tmp->msg = Xcalloc(tmp->msg_size,
			    sizeof (struct messages));
			tmp->thash_size = find_prime(DEF_MSG_NUM);
			tmp->thash = Xcalloc(tmp->thash_size,
			    sizeof (unsigned int));
			p->next = tmp;
			p = tmp;
			break;
		}
	}
	cur_catalog = p;
	cur_mo = p->fname;
}


void
handle_comment(char *comment)
{
	char	*p;

	p = comment;

	if (*p != ',') {
		/*
		 * This comment is just informative only.
		 */
		free(comment);
		return;
	}
	/*
	 * Checks "fuzzy", "c-format", and "no-c-format"
	 */
	p++;
	if (strstr(p, "fuzzy") != NULL) {
		next_entry_is_fuzzy = 1;
	}
	if (strstr(p, "no-c-format") != NULL) {
		next_entry_is_c_format = 0;
	} else if (strstr(p, "c-format") != NULL) {
		next_entry_is_c_format = 1;
	}

	free(comment);
}

void
handle_message(struct entry *id, struct entry *str)
{
	char	*charset, *nplurals, *tmp, *p;
	struct messages	*msg, *dupmsg;
	size_t	len;
	unsigned int	hash_val;
	unsigned int	nmsg, n, thash_idx;

	if (cur_mo == NULL) {
		/*
		 * output file hasn't been specified, nor
		 * no domain directive found
		 */
		char	*default_domain;

		default_domain = strict_flag ? DEFAULT_DOMAIN_MO :
		    DEFAULT_DOMAIN;
		catalog_init(default_domain);
	}

	/*
	 * cur_catalog should be valid, at this point
	 */

	hash_val = hashpjw(id->str);
	dupmsg = search_msg(cur_catalog, id->str, hash_val);

	if (dupmsg) {
		if ((dupmsg->str_len == str->len) &&
		    (memcmp(dupmsg->str, str->str, str->len) == 0)) {
			/* totally same entry */
			if (verbose_flag) {
				warning(gettext(WARN_DUP_ENTRIES),
				    dupmsg->num, po_names[dupmsg->po],
				    id->num, cur_po);
			}
			free(id->str);
			if (id->pos)
				free(id->pos);
			free(str->str);
			if (str->pos)
				free(str->pos);
			return;
		}
		/* duplicate msgid */
		if (verbose_flag) {
			diag(gettext(ERR_DUP_ENTRIES),
			    dupmsg->num, po_names[dupmsg->po],
			    id->num, cur_po);
			po_error++;
		}
		/* ignore this etnry */
		free(id->str);
		if (id->pos)
			free(id->pos);
		free(str->str);
		if (str->pos)
			free(str->pos);
		return;
	}

	if (next_entry_is_fuzzy) {
		/* fuzzy entry */
		cur_catalog->fnum++;
		if (!fuzzy_flag) {
			/* ignore this entry */
			free(id->str);
			if (id->pos)
				free(id->pos);
			free(str->str);
			if (str->pos)
				free(str->pos);
			return;
		}
	}

	if (str->len == str->no) {
		/* this entry is not translated */
		cur_catalog->unum++;
		free(id->str);
		if (id->pos)
			free(id->pos);
		free(str->str);
		if (str->pos)
			free(str->pos);
		return;
	}

	/* Checks if this is the header entry */
	if ((id->no == 1) && (id->len == 1)) {
		/*
		 * Header entry
		 */
		cur_catalog->header++;

		/*
		 * Need to extract the charset information
		 */
		charset = strstr(str->str, CHARSET_STR);
		if (charset == NULL) {
			/* no charset information */
			warning(gettext(WARN_NOCHARSET),
			    id->num, cur_po, str->num);
			conv_init(NULL);
		} else {
			charset += CHARSET_LEN;
			p = strpbrk(charset, " \t\n");
			if (p != NULL) {
				/* p points to a space, tab or new line char */
				len = p - charset;
			} else {
				/* not found */
				len = strlen(charset);
			}
			tmp = Xmalloc(len + 1);
			(void) memcpy(tmp, charset, len);
			*(tmp + len) = '\0';
			charset = tmp;
			conv_init(charset);
			free(charset);
		}
		nplurals = strstr(str->str, NPLURALS_STR);
		if (nplurals == NULL) {
			cur_catalog->nplurals = 0;
		} else {
			unsigned int	num;
			nplurals += NPLURALS_LEN;
			p = nplurals;
			num = 0;
			while (isdigit((unsigned char)*p)) {
				num = num * 10 + *p++ - '0';
			}
			cur_catalog->nplurals = num;
		}
	}

	if (verbose_flag)
		check_format(id, str, next_entry_is_c_format);

	if (id->pos)
		free(id->pos);
	if (str->pos)
		free(str->pos);

	msg = cur_catalog->msg;
	nmsg = cur_catalog->nmsg;

	msg[nmsg].po = cur_po_index;
	msg[nmsg].num = id->num;
	msg[nmsg].id = id->str;
	msg[nmsg].id_len = id->len;
	msg[nmsg].str = str->str;
	msg[nmsg].str_len = str->len;
	msg[nmsg].hash = hash_val;

	thash_idx = get_hash_index(cur_catalog->thash,
	    hash_val, cur_catalog->thash_size);
	cur_catalog->thash[thash_idx] = nmsg + 1;
	cur_catalog->nmsg++;

	if (cur_catalog->nmsg >= cur_catalog->msg_size) {
		/* no vacancy in message array */
		cur_catalog->msg_size += DEF_MSG_NUM;
		cur_catalog->msg = Xrealloc(cur_catalog->msg,
		    cur_catalog->msg_size * sizeof (struct messages));

		cur_catalog->thash_size =
			find_prime(cur_catalog->msg_size);
		free(cur_catalog->thash);
		cur_catalog->thash = Xcalloc(cur_catalog->thash_size,
		    sizeof (unsigned int));

		for (n = 0; n < cur_catalog->nmsg; n++) {
			thash_idx = get_hash_index(cur_catalog->thash,
			    cur_catalog->msg[n].hash,
			    cur_catalog->thash_size);
			cur_catalog->thash[thash_idx] = n + 1;
		}
	}
}

void
po_init(const char *file)
{
	char	*filename;

	if (!inputdir) {
		filename = Xstrdup(file);
	} else {
		size_t	dirlen, filelen, len;

		dirlen = strlen(inputdir);
		filelen = strlen(file);
		len = dirlen + 1 + filelen + 1;
		filename = Xmalloc(len);
		(void) memcpy(filename, inputdir, dirlen);
		*(filename + dirlen) = '/';
		(void) memcpy(filename + dirlen + 1, file, filelen);
		*(filename + dirlen + 1 + filelen) = '\0';
	}

	fp = fopen(filename, "r");
	if (fp == NULL) {
		error(gettext(ERR_OPEN_FAILED), filename);
		/* NOTREACHED */
	}

	po_names[cur_po_index] = filename;
	cur_line = 1;
	cd = (iconv_t)-1;
	if (!outfile)
		cur_mo = NULL;
}

void
po_fini(void)
{
	cur_po_index++;
	(void) fclose(fp);
	if (cd != (iconv_t)-1)
		(void) iconv_close(cd);
}
