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

#include <stdio.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <sys/vtoc.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <locale.h>
#include <langinfo.h>
#include <libintl.h>
#include <stdarg.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include "cfg_impl.h"
#include "cfg.h"
#include "cfg_lockd.h"

#if 0
#define	DEBUG_CFGLIST
#define	DEBUG_EXTRA
#define	DEBUG_LIB
#define	DEBUG_NOISY
#define	DEBUG_OUT
#endif

#define	MAX_CFG		16	/* Max. number of lines in /etc/dscfg_format */
#define	MAX_SET		12	/* number of chars in a set name */


/* parser tree for config section */
static struct parser chead[MAX_CFG] = { NULL };
static int chead_loaded = 0;
static char	config_file[CFG_MAX_BUF];
static char	dectohex[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
#define	CHARS_TO_ENCODE "=;\t "
#define	min(a, b) ((a) > (b) ? (b) : (a))

/* field to be sorted on in sorting routines */
static struct sortby_s {
	char section[CFG_MAX_KEY];
	char field[CFG_MAX_KEY];
	int offset;
	int comperror;
} sortby;

int	cfg_severity = 0;
char	*cfg_perror_str;
static int	cfg_read(cfp_t *);
static void	cfg_read_parser_config(cfp_t *);
static int	cfg_rdlock(CFGFILE *);
static int	cfg_wrlock(CFGFILE *);
static int	cfg_lockd;
void 		cfg_replace_lists(cfp_t *);
void		cfg_free_parser_tree();
void		cfg_invalidate_hsizes(int, const char *);
int		cfg_map_cfglists(cfp_t *);
int		cfg_hdrcmp(cfp_t *);
void		cfg_free_cfglist(cfp_t *);

extern cfg_io_t *cfg_block_io_provider(void);
extern cfg_io_t *cfg_raw_io_provider(void);
extern int cl_initialized;

#ifdef DEBUG_LIB
static void
dump_status(cfp_t *cfp, char *str)
{
	printf("called from %s\n", str);
	printf(gettext("Header info:\n"
	    "\tmagic: %x\tstate: %x\n"),
	    cfp->cf_head->h_magic, cfp->cf_head->h_state);
	printf(gettext("Parser section:\n"
	    "Start: %x\tsize: %d\toffset: %d\n"),
	    cfp->cf_mapped, cfp->cf_head->h_parsesize,
	    cfp->cf_head->h_parseoff);
	printf(gettext("Config section:\n"
	    "Start: %x\tsize:%d\tacsize: %d\n"),
	    cfp->cf_head->h_cparse, cfp->cf_head->h_csize,
	    cfp->cf_head->h_acsize);
	printf("\n\tccopy1: %x\tccopy2: %x\n",
	    cfp->cf_head->h_ccopy1, cfp->cf_head->h_ccopy2);
	printf(gettext("Sequence:\n"
	    "\tseq1: %d\t\tseq2: %d\n"),
	    cfp->cf_head->h_seq1, cfp->cf_head->h_seq2);
}
#endif /* DEBUG */

/*
 * cfg_get_item
 * return position from parser config given tag and field
 */
static int
cfg_get_item(struct parser *tbl, const char *tag, const char *field)
{
	int i;
	struct lookup *p;

	for (i = 0; i < MAX_CFG; i++) {
		/* only as many lists as defined */
		if (tbl[i].tag.l_word[0] == '\0') {
			i = MAX_CFG;
			break;
		}
		if (strcmp(tbl[i].tag.l_word, tag) == 0)
			break;
	}

	/* Handle table size */
	if (i < MAX_CFG) {
		p = tbl[i].fld;
		while (p) {
			if (strcmp(p->l_word, field) == 0)
				return (p->l_value);
			p = p->l_next;
		}
	}

	/* Handle failure */
	return (-1);
}

/*
 * cfg_get_num_flds
 * return number of fields for given parser tag
 */
static int
cfg_get_num_flds(struct parser *tbl, const char *tag, int *table_index)
{
	int i;
	int pos = 0;
	struct lookup *p;

	for (i = 0; i < MAX_CFG; i++) {
		/* only as many lists as defined */
		if (tbl[i].tag.l_word[0] == '\0') {
			i = MAX_CFG;
			break;
		}
		if (strcmp(tbl[i].tag.l_word, tag) == 0) {
			*table_index = i;
			break;
		}
	}

	/* Handle table size */
	if (i < MAX_CFG) {
		p = tbl[i].fld;
		while (p) {
			pos++;
			p = p->l_next;
		}
		return (pos);
	}

	return (0);
}

/*
 * count white space fields
 */
static int
cfg_cnt_flds(char *value)
{
	char *ptr;
	char buf[CFG_MAX_BUF];
	int flds = 0;

	if ((value == NULL) || (strlen(value) >= CFG_MAX_BUF))
		return (0);

	bzero(buf, CFG_MAX_BUF);
	strcpy(buf, value);
	ptr = strtok(buf, " ");
	while (ptr) {
		flds++;
		ptr = strtok(NULL, " ");
	}
	return (flds);
}

/*
 * cfg_get_parser_offset
 * returns the index for each
 * section of the parser..
 * ie. parser info for sndr is chead[3].tag.l_word
 * this will help us find sndr quicker, as the
 * the memory picture of the sets mimic this ordering
 */
static int
cfg_get_parser_offset(const char *section)
{
	int i;

	for (i = 0; i < MAX_CFG; i++) {
		/* only as many lists as defined */
		if (chead[i].tag.l_word[0] == '\0') {
			i = MAX_CFG;
			break;
		}
		if (strcmp(chead[i].tag.l_word, section) == 0)
			break;
	}

	/* Handle table size */
	if (i < MAX_CFG)
		return (i);

	/* Handle failure */
	cfg_perror_str = dgettext("cfg",
	    "cfg_get_parser_offset: section not found");
	cfg_severity = CFG_EFATAL;
	errno = ESRCH;
	return (-1);
}

/*
 * cfg_fld_mov
 * move fields from old buffer to new
 * moving only specified fields
 * concates newbuf
 * returns fields moved
 */
static int
cfg_fld_mov(char *newbuf, char *oldbuf, int start, int end)
{
	char buf[CFG_MAX_BUF];
	char *ptr;
	int flds = 0;

	bzero(buf, CFG_MAX_BUF);
	if (oldbuf == NULL)
		return (0);

	if ((start > end) || (strlen(oldbuf) >= CFG_MAX_BUF)) {
		return (0);
	}
	if (!start || !end)
		return (-1);
	strcpy(buf, oldbuf);
	ptr = strtok(buf, " ");
	while (ptr) {
		flds++;
		if (flds >= start && flds <= end) {
			strcat(newbuf, ptr);
			strcat(newbuf, " ");
		}
		ptr = strtok(NULL, " ");
	}

	return (flds);
}

/*
 * cfg_filter_node
 * return indication if this raw buf should be returned
 * checks cfg->cf_node for filtering
 * We already know that this buf meets most of our criteria
 * find the cnode field in the buf and see if it matches
 * returns
 * 	TRUE	Good entry
 * 	FALSE	Don't use it
 */
static int
cfg_filter_node(CFGFILE *cfg, struct parser *tbl, char *buf, char *tag)
{
	char tmpbuf[CFG_MAX_BUF];
	int i = 1;
	int fld;
	char *ptr;

	if (!cfg->cf_node)		/* no filter always good */
		return (TRUE);
	bzero(tmpbuf, CFG_MAX_BUF);
	fld = cfg_get_item(tbl, tag, "cnode");
	if (fld < 0)	/* no cnode field always good */
		return (TRUE);
	strncpy(tmpbuf, buf, CFG_MAX_BUF);
	if (tmpbuf[CFG_MAX_BUF - 1] != '\0')
		return (FALSE);
	ptr = strtok(tmpbuf, " ");
	while (ptr && (i < fld)) {
		ptr = strtok(NULL, " ");
		i++;
	}
	if (!ptr)
		return (FALSE);
#ifdef DEBUG_EXTRA
	(void) fprintf(stderr, "cfg_filter_node: node=%s:%d cnode=%s:%d\n",
	    cfg->cf_node, strlen(cfg->cf_node), ptr, strlen(ptr));
#endif
	if (strcmp(ptr, cfg->cf_node) == 0)
		return (TRUE);
	return (FALSE);
}
/*
 * cfg_insert_node
 * insert resource in bufs which contain cnode parser field
 */
static void
cfg_insert_node(CFGFILE *cfg, struct parser *tbl, char *buf, char *tag)
{
	char tmpbuf[CFG_MAX_BUF];
	int fld;
	int nflds;
	int table_index;

	bzero(tmpbuf, CFG_MAX_BUF);
	strcpy(tmpbuf, " ");
	fld = cfg_get_item(tbl, tag, "cnode");
	nflds = cfg_get_num_flds(tbl, tag, &table_index);
	if ((fld < 0) && !(cfg->cf_node))	/* no cnode field always good */
		return;

	cfg_fld_mov(tmpbuf, buf, 1, (fld - 1));
	if (cfg->cf_node)
		strcat(tmpbuf, cfg->cf_node);
	else
		strcat(tmpbuf, "-");
	strcat(tmpbuf, " ");
	cfg_fld_mov(tmpbuf, buf, (fld + 1), nflds);
	bcopy(tmpbuf, buf, strlen(tmpbuf) + 1);
}

/*
 * cfg_is_cnode
 * Parser current buffer to see if a non-empty " - " cnode exists
 */
/*ARGSUSED*/
static int
cfg_is_cnode(CFGFILE *cfg, struct parser *tbl, char *buf, char *tag)
{
	char tmpbuf[CFG_MAX_BUF];
	int fld = cfg_get_item(tbl, tag, "cnode");

	if (fld >= 0) {
		tmpbuf[0] = '\0';
		cfg_fld_mov(tmpbuf, buf, fld, fld);
		return (strcmp(tmpbuf, "- ") ? TRUE : FALSE);
	}
	return (FALSE);
}
/*
 * cfg_get_cstring
 * key determines section and value
 * special considerations:
 * AA.BB.CC...
 * AA = data service tag
 * BB = set number relative to first set (1..n)
 * CC = field of set or if absent, all
 */
int
cfg_get_cstring(CFGFILE *cfg, const char *key, void *value, int value_len)
{
	cfp_t *cfp;
	char buf[CFG_MAX_BUF];
	char tmpkey[CFG_MAX_KEY];
	char *section;
	char set[MAX_SET];
	char *setp;
	char *itemp;
	char *p;
	int pos = 1;
	int setnum;
	int relnum;
	int secnum;
	int numfound;
	int needed;
	int table_offset;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	if (!cfg_rdlock(cfg)) {
		cfg_perror_str = dgettext("cfg", CFG_NOTLOCKED);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	bzero(buf, sizeof (buf));
	bzero(set, sizeof (set));
	bzero(tmpkey, sizeof (tmpkey));
	strcpy(tmpkey, key);
	section = strtok(tmpkey, ".");
	setp = strtok(NULL, ".");
	itemp = strtok(NULL, ".");

#ifdef DEBUG_EXTRA
	if (!itemp)
		(void) fprintf(stderr, "cfg_get_cstring:section:%s setp=%s\n",
		    section, setp);
	else
		(void) fprintf(stderr,
		    "cfg_get_cstring:section:%s setp=%s fld=%s\n",
		    section, setp, itemp);
#endif

	table_offset = cfg_get_parser_offset(section);
	setnum = atoi(setp + 3);
	if ((setnum < 1) || (setnum > 0x7ffd)) {
		errno = EINVAL;
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_ENONFATAL;
		return (-1);
	}

	/*
	 * we have to figure out where this set is
	 * in relation to other sets
	 */
	relnum = 1;
	secnum = 0;
	numfound = 0;
	for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
		if (!cfp->cf_fd) continue;
		if (cfp->cf_head->h_state & CFG_HDR_INVALID) {
			if (!cfg_read(cfp)) {
				cfg_perror_str = dgettext("cfg", CFG_RDFAILED);
				cfg_severity = CFG_EFATAL;
				return (-1);
			}
		}
		while (numfound < setnum) {
			if ((*cfp->cf_pp->readcf)
			    (cfp, buf, table_offset, relnum - secnum) == NULL) {
				secnum = relnum - 1;
				break;
			}
			if (cfg_filter_node(cfg, &chead[0], buf, section))
				numfound++;

			if (numfound == setnum)
				break;

			relnum++;
		}
		if (numfound == setnum)
			break;
	}

	/* Fail to find anything? */
	if (cfp >= &cfg->cf[2]) {
		errno = ESRCH;
		cfg_perror_str = dgettext("cfg", strerror(errno));
		cfg_severity = CFG_ENONFATAL;
		return (-1);
	}

	if (buf) {
		if (!itemp) {
			strncpy(value, buf, value_len);
			return (0);
		}

		if (itemp) {
			needed = cfg_get_item(&chead[0], section, itemp);
			p = strtok(buf, " ");
			while (p) {
				if (needed == pos) {
					errno = 0;
					if (*p == '-') {
						strcpy(value, "");
						return (0);
					} else {
						if (strlen(p) > value_len) {
							errno = E2BIG;
							cfg_perror_str =
							    dgettext("cfg",
							    strerror(errno));
							cfg_severity =
							    CFG_ENONFATAL;
							return (-1);
						}
					}
					strncpy(value, p, value_len);

					return (pos);
				}
				p = strtok(NULL, " ");
				if (!p)
					break;
				pos++;
			}
		}
	}
	errno = ESRCH;
	cfg_perror_str = dgettext("cfg", strerror(errno));
	cfg_severity = CFG_ENONFATAL;
	return (-1);
}

/*
 * cfg_find_cstring()
 * search for a string in the specified section
 * in the specified field(s)
 * if nfld is 0, then the string is searched for in
 * every field of the entry
 * the set number of the first occurence of target is returned
 * ie. if /dev/vx/rdsk/vol10 is found in sndr.set9, 9 will be returned
 * that is, of course, if the correct field was searched on.
 * -1 on error
 *
 */
int
cfg_find_cstring(CFGFILE *cfg, const char *target,
    const char *section, int numflds, ...)
{

	char **list = NULL;
	va_list ap;
	char buf[CFG_MAX_BUF];
	char *field, *p;
	char **fldbuf = NULL;
	int i, j, rc;
	int pos = 1;
	int fieldnum;
	int nflds;
	int tbl_off;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	if (numflds == 0) {
		nflds = cfg_get_num_flds(&chead[0], section, &tbl_off);

	} else {
		nflds = numflds;
	}
	if ((fldbuf = calloc(nflds, CFG_MAX_KEY)) == NULL) {
		cfg_perror_str = dgettext("cfg", strerror(errno));
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	if (numflds == 0) { /* search the whole string */
		if ((rc = cfg_get_section(cfg, &list, section)) <= 0) {
			for (i = 0; i < nflds; i++)
				free(fldbuf[i]);
			free(fldbuf);
			return (rc);
		}
		for (i = 0; i < rc; i++) {
			bzero(buf, sizeof (buf));
			strcpy(buf, list[i]);
			p = strtok(buf, " ");
			while (p) {
				if (strcmp(p, target) == 0) { /* we found it! */
					for (j = 0; j < rc; j++)
						free(list[j]);
					free(list);
					for (j = 0; j < nflds; j++)
						free(fldbuf[j]);
					free(fldbuf);
					return (i + 1);
				}
			p = strtok(NULL, " ");
			}
		}
		for (i = 0; i < nflds; i++)
			free(fldbuf[j]);
		for (i = 0; i < rc; i++)
			free(list[i]);
		free(fldbuf);
		free(list);
		return (0);
	}

	if ((rc = cfg_get_section(cfg, &list, section)) <= 0) {
		for (i = 0; i < nflds; i++)
			free(fldbuf[i]);
		free(fldbuf);
		return (rc);
	}

	va_start(ap, numflds);
	for (i = 0; i < numflds; i++) {
		fldbuf[i] = strdup(va_arg(ap, char *));
	}

	fldbuf[i] = NULL;

	for (j = 0; j < numflds; j++) {
		fieldnum = cfg_get_item(&chead[0], section, fldbuf[j]);
		for (i = 0; i < rc; i++) {
			bzero(buf, sizeof (buf));
			strcpy(buf, list[i]);

			field = strtok(buf, " ");
			pos = 1;
			while (pos < fieldnum) {
				field = strtok(NULL, " ");
				pos++;
			}
			if (field == NULL) {
				for (j = 0; j < numflds; j++)
					free(fldbuf[j]);
				for (j = 0; j < rc; j++)
					free(list[j]);
				free(fldbuf);
				free(list);
				return (-1);
			}

			if (strcmp(field, target) == 0) {
				for (j = 0; j < numflds; j++)
					free(fldbuf[j]);
				for (j = 0; j < rc; j++)
					free(list[j]);
				free(fldbuf);
				free(list);

				return (i + 1);
			}

		}

	}
	for (i = 0; i < nflds; i++)
		free(fldbuf[i]);
	for (i = 0; i < rc; i++)
		free(list[i]);
	free(fldbuf);
	free(list);
	return (0);
}

/*
 * cfg_put_cstring
 * modify entry or add an entry to configuration section
 * Key syntax supported
 *	tag		Add entry (in entirely) to config
 * 	tag.setn	Add entry to setn If it exists overwrite old entry
 * 	tag.setn.field	Change field in setn
 * value
 *	string to change
 *	NULL	delete specified key
 *
 */

int
cfg_put_cstring(CFGFILE *cfg, const char *key,  void *value, int val_len)
{
	cfp_t *cfp;
	char buf[CFG_MAX_BUF];
	char newbuf[CFG_MAX_BUF];
	char *bufp;
	char tmpkey[CFG_MAX_KEY];
	char *section;
	char *setp;
	char *itemp;
	int nofield = 0;
	int noset = 0;
	int fldnum;
	int setnum = 0;
	int relnum;
	int secnum;
	int numfound;
	int addcnode = 1;
	int table_index;
	int table_offset;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	bzero(buf, sizeof (buf));
	strcpy(tmpkey, key);
	section = strtok(tmpkey, ".");
	setp = strtok(NULL, ".");
	itemp = strtok(NULL, ".");

	if (!cfg_wrlock(cfg)) {
		cfg_perror_str = dgettext("cfg", CFG_RDFAILED);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	if (!key) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_ENONFATAL;
		return (-1);
	}
	if (value && val_len == 0) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_ENONFATAL;
		return (-1);
	}
	if (!itemp)
		nofield++;
	if (!setp)
		noset++;
	else if (setp) {
		setnum = atoi(setp + 3);
		if (setnum < 1 || setnum > 0x7ffd) {
			errno = EINVAL;
			cfg_perror_str = dgettext("cfg", CFG_EINVAL);
			cfg_severity = CFG_ENONFATAL;
			return (-1);
		}
	}

	table_offset = cfg_get_parser_offset(section);

	/*
	 * we have to figure out where this set is
	 * in relation to other sets
	 */
	relnum = 1;
	secnum = 0;
	numfound = 0;

	if (setp && nofield) {
		char tmpbuf[CFG_MAX_BUF];
		int rc;
		int nflds;
		int got;

		/*
		 * Set specified but no field
		 */
		for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
			if (!cfp->cf_fd) continue;
			if (cfp->cf_head->h_state & CFG_HDR_INVALID) {
				if (!cfg_read(cfp)) {
					cfg_perror_str =
					    dgettext("cfg", CFG_RDFAILED);
					cfg_severity = CFG_EFATAL;
					return (-1);
				}
			}
			while (numfound < setnum) {
				if ((*cfp->cf_pp->readcf)
				    (cfp, tmpbuf, table_offset, relnum - secnum)
				    == NULL) {
					secnum = relnum - 1;
					break;
				}
				if (cfg_filter_node(cfg, &chead[0], tmpbuf,
				    section))
					numfound++;

				if (numfound == setnum)
					break;

				relnum++;
			}
			if (numfound == setnum)
				break;
		}

		/* Fail to find anything? */
		if (cfp >= &cfg->cf[2]) {
			errno = ESRCH;
			cfg_perror_str = dgettext("cfg", strerror(errno));
			cfg_severity = CFG_ENONFATAL;
			return (-1);
		}

		nflds = cfg_get_num_flds(&chead[0], section, &table_index);

		if (value == NULL) {
			/* Remove entry completely */

			rc = (*cfp->cf_pp->remcf)(cfp, table_index,
			    relnum - secnum);
			if (rc < 0)
				return (rc);
			return (0);
		}

		got = cfg_cnt_flds(value);
		bzero(buf, sizeof (buf));

		strncpy(buf, " ", 1);
		if (strlen(value) > sizeof (buf) - 2) {
			errno = E2BIG;
			cfg_perror_str = dgettext("cfg", strerror(errno));
			cfg_severity = CFG_ENONFATAL;
			return (-1);
		}
		strncat(buf, value, val_len);
		if (got < nflds) {
			for (/* CSTYLED */; got < nflds; got++)
				strncat(buf, " - ", 3);
		} else if (got > nflds) {
			return (-1);
		} else {
			/* got == nflds, so cnode was included */
			addcnode = 0;
		}

		bufp = buf;
		if (addcnode) {
			cfg_insert_node(cfg, &chead[0], buf, section);
		}

		(*cfp->cf_pp->replacecf)(cfp, bufp, table_index,
		    relnum - secnum);

		return (TRUE);
	}

	/*
	 * Both Set and field are specified
	 * needs to get current whole entry and old requested field
	 * copy good fields to buf, replace new field in buf
	 * move everything depending of new size
	 * replace entry so set# does not change
	 */
	if (setp && itemp) {
		int rc;
		int nflds;
		int cnodepos;

		for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
			if (!cfp->cf_fd) continue;
			if (cfp->cf_head->h_state & CFG_HDR_INVALID) {
				if (!cfg_read(cfp)) {
					cfg_perror_str =
					    dgettext("cfg", CFG_RDFAILED);
					cfg_severity = CFG_EFATAL;
					return (-1);
				}
			}
			while (numfound < setnum) {
				if ((*cfp->cf_pp->readcf)
				    (cfp, buf, table_offset, relnum - secnum)
				    == NULL) {
					secnum = relnum - 1;
					break;
				}
				if (cfg_filter_node(cfg, &chead[0], buf,
				    section))
					numfound++;

				if (numfound == setnum)
					break;

				relnum++;
			}
			if (numfound == setnum)
				break;
		}

		/* Fail to find anything? */
		if (cfp >= &cfg->cf[2]) {
			errno = ESRCH;
			cfg_perror_str = dgettext("cfg", strerror(errno));
			cfg_severity = CFG_ENONFATAL;
			return (-1);
		}

		nflds = cfg_get_num_flds(&chead[0], section, &table_index);
		fldnum = cfg_get_item(&chead[0], section, itemp);
		bzero(newbuf, sizeof (newbuf));
		strncpy(newbuf, " ", 1);

		/* move good flds in */
		rc = cfg_fld_mov(newbuf, buf, 1, fldnum - 1);
		if (rc < 0)
			return (rc);

		/* move new fld in */
		strncat(newbuf, value, strlen(value));
		strcat(newbuf, " ");

		/* move remaining flds in */
		rc = cfg_fld_mov(newbuf, buf, fldnum + 1, nflds);
		if (rc < 0)
			return (rc);

		cnodepos = cfg_get_item(&chead[0], section, "cnode");
		if ((cnodepos >= 0) && strcmp(itemp, "cnode") != 0) {
			/* add cnode if user didn't specify it */
			cfg_insert_node(cfg, &chead[0],
			    newbuf, section);
		}

		(*cfp->cf_pp->replacecf)(cfp, newbuf, table_index,
		    relnum - secnum);

		return (TRUE);
	}

	if (noset) {	/* blast entire thing in */
		int nflds;
		int got;
		int cnodepos;

		bufp = buf;
		if (!value) { /* we shouldn't be here */
			errno = EINVAL;
			return (-1);
		}
		strncat(buf, " ", 1);
		if (strlen(value) > sizeof (buf) - 2) {
			errno = E2BIG;
			return (-1);
		}

		strncat(buf, value, val_len);
		nflds = cfg_get_num_flds(&chead[0], section, &table_index);
		got = cfg_cnt_flds(value);

		cnodepos = cfg_get_item(&chead[0], section, "cnode");
		if (cnodepos < 0 || got >= cnodepos) {
			/* no cnode, or cnode was specified by caller */
			addcnode = 0;
		}

		if (got < nflds) {
			for (/* CSTYLED */; got < nflds; got++)
				strncat(buf, " - ", 3);
		} else if (got > nflds) {
			errno = EINVAL; /* specified too many fields */
			return (-1);
		} else {
			/* got == nflds, so cnode was included */
			addcnode = 0;
		}

		if (addcnode) {
			cfg_insert_node(cfg, &chead[0], buf, section);
		}

		/* Make sure we put this entry in the right database */
		if (cfg_is_cnode(cfg, &chead[0], buf, section) &&
		    cfg->cf[1].cf_fd)
			cfp = &cfg->cf[1];
		else
			cfp = &cfg->cf[0];

		if (cfp->cf_head->h_state & CFG_HDR_INVALID) {
			if (!cfg_read(cfp)) {
				cfg_perror_str = dgettext("cfg", CFG_RDFAILED);
				cfg_severity = CFG_EFATAL;
				return (-1);
			}
		}
		if (cfp->cf_head->h_csize + strlen(buf) > CFG_DEFAULT_SSIZE) {
			errno = ENOSPC;
			return (-1);
		}

		(*cfp->cf_pp->addcf)(cfp, bufp, table_index);

		return (TRUE);
	}

	errno = EINVAL;
	cfg_perror_str = strerror(errno);
	cfg_severity = CFG_ENONFATAL;
	return (-1);
}

/*
 * cfg_encode_char
 *
 *	Encode a single character into % + hex ascii value
 */
static void
cfg_encode_char(char *result, char ch)
{
	*result++ = '%';
	*result++ = dectohex[ (ch >> 4) & 0xf ];
	*result++ = dectohex[ ch & 0xf ];
}

/*
 * cfg_decode_char
 *
 *	Reverses cfg_encode_char
 */
static char
cfg_decode_char(char *code)
{
	char retval;
	if (*code != '%') {
		return ('\0');
	}
	++code;
	if (!isxdigit(*code))
		return ('\0');
	retval = (isdigit(*code)? *code - '0' : *code - 'a' + 10);
	retval <<= 4;
	++code;
	if (!isxdigit(*code))
		return ('\0');
	retval |= (isdigit(*code)? *code - '0' : *code - 'a' + 10);

	return (retval);
}

/*
 * cfg_encode_option
 *
 *	Transforms the key and value strings so that special characters
 *	can be used within the options field.
 *
 * Returns:
 *	Length of encoded string; -1 on failure
 */
static int
cfg_encode_string(char *str, char *output, int outlen)
{
	char *mem, *p, *q;
	int curlen;


	/* first, scan through the tag string converting %-signs */
	p = str;
	q = output;
	curlen = 0;
	while (*p && curlen < outlen) {
		if (*p == '%') {
			if (curlen + 3 >= outlen) {
				return (-1);
			}
			cfg_encode_char(q, *p);
			curlen += 3;
			q += 3;
		} else {
			*q++ = *p;
			++curlen;
		}
		++p;
	}
	if (curlen < outlen)
		*q = '\0';

	/* now encode special characters */
	p = mem = strdup(output);
	q = output;
	curlen = 0;
	while (*p && curlen < outlen) {
		if (strchr(CHARS_TO_ENCODE, *p) != 0) {
			if (curlen + 3 >= outlen) {
				free(mem);
				return (-1);
			}
			cfg_encode_char(q, *p);
			curlen += 3;
			q += 3;
		} else {
			*q++ = *p;
			++curlen;
		}
		++p;
	}
	free(mem);

	if (curlen < outlen)
		*q = '\0';
	/* LINTED possible ptrdiff_t overflow */
	return (q - output);
}

/*
 * cfg_decode_option
 *
 *	Given a string, decodes any %-encodes on it.
 */
static void
cfg_decode_string(char *str, char *output, int outlen)
{
	char *p, *q;
	int curlen;

	p = str;
	q = output;
	curlen = 0;
	while (*p && curlen < outlen) {
		if (*p == '%') {
			char ch = cfg_decode_char(p);
			if (!ch) {
				*q++ = *p++;
				++curlen;
			} else {
				*q++ = ch;
				p += 3;
				++curlen;
			}
		} else {
			*q++ = *p++;
			++curlen;
		}
	}
	if (curlen < outlen)
		*q = '\0';
}

/*
 * cfg_get_options
 * return first options set from basekey
 * Subsequent calls with basekey = NULL return next option if any
 * into tag and val
 * returns
 *	true 	success and more options data
 *	-1 	no options data
 */

int
cfg_get_options(CFGFILE *cfg, int section, const char *basekey, char *tag,
    int tag_len, char *val, int val_len)
{
	static char buf[CFG_MAX_BUF];
	char decode_buf[CFG_MAX_BUF];
	int rc;
	char *ttag, *tval;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	errno = ENOSYS;
	if (basekey == 0) {
		ttag = strtok(NULL, "=");
	} else {
		bzero(buf, CFG_MAX_BUF);
		if (section == CFG_SEC_CONF) {
			rc = cfg_get_cstring(cfg, basekey, buf, CFG_MAX_BUF);
		} else
			return (-1);
		if (rc < 0)
			return (rc);
		/* buf now contains raw options data */
		ttag = strtok(buf, "=");
	}
	tval = strtok(NULL, ";");
	if (!(tval) || !(ttag))
		return (-1);
	if ((strlen(tval) > val_len) || (strlen(ttag) > tag_len)) {
		errno = E2BIG;
		return (-1);
	}
	cfg_decode_string(tval, decode_buf, CFG_MAX_BUF);
	strncpy(val, decode_buf, val_len);
	cfg_decode_string(ttag, decode_buf, CFG_MAX_BUF);
	strncpy(tag, decode_buf, tag_len);
	errno = 0;
	return (TRUE);
}

/*
 * cfg_put_options
 *
 *	Replaces existing tag with new val.  If tag doesn't exist,
 *	then it adds a new tag with the specified val.
 *
 * Return:
 *	true	success
 *	-1	incorrect section, or read error from cfg DB
 */
int
cfg_put_options(CFGFILE *cfg, int section, const char *basekey, char *tag,
    char *val)
{
	char buf[CFG_MAX_BUF];
	char encode_buf[CFG_MAX_BUF];
	char *p;
	int enclen;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	errno = ENOSYS;
	bzero(buf, CFG_MAX_BUF);
	if (section != CFG_SEC_CONF) {
		cfg_severity = CFG_ENONFATAL;
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		return (-1);
	}
	if (!tag || !*tag || !val || !*val)
		return (-1);
	if (cfg_get_cstring(cfg, basekey, buf, CFG_MAX_BUF) < 0) {
		/* cfg severity & perror_str set up cfg_get_cstring() */
		return (-1);
	}
	*encode_buf = ';';
	enclen = cfg_encode_string(tag, &encode_buf[1], CFG_MAX_BUF - 1) + 1;
	if (enclen < 1 || (enclen + 1) >= CFG_MAX_BUF) {
		cfg_severity = CFG_ENONFATAL;
		cfg_perror_str = dgettext("cfg", "Buffer too small");
		return (-1);
	}
	encode_buf[enclen] = '=';
	encode_buf[enclen + 1] = '\0';

	/* check the start of the string */
	if (strncmp(buf, &encode_buf[1], enclen) == 0) {
		/* locate the end of this option */
		p = strchr(buf, ';');
		if (p && *(p + 1) != '\0') {
			/* add the new tag to the end */
			++p;
			strcat(p, &encode_buf[1]);
		} else {
			/* completely overwrite the existing tag */
			p = buf;
			strcpy(p, &encode_buf[1]);
		}
		if (cfg_encode_string(val, encode_buf, CFG_MAX_BUF) < 0) {
			cfg_severity = CFG_ENONFATAL;
			cfg_perror_str = dgettext("cfg", "Buffer too small");
			return (-1);
		}
		strcat(p, encode_buf);
		strcat(p, ";");
		if (cfg_put_cstring(cfg, basekey, p, strlen(p)) < 0) {
			/* severity & perror_str set by cfg_put_cstring */
			return (-1);
		}
		errno = 0;
		return (TRUE);
	}

	/* it's hiding somewhere inside... */
	p = strstr(buf, encode_buf);
	if (p) {
		/* delete the old value */
		char *q = strchr(p + 1, ';');
		if (q) {
			strcpy(p + 1, q + 1);
		} else {
			*p = '\0';
		}
		strcat(buf, &encode_buf[1]);
	} else if (*buf) {
		strcat(buf, &encode_buf[1]);
	} else {
		strcpy(buf, &encode_buf[1]);
	}
	enclen = cfg_encode_string(val, encode_buf, CFG_MAX_BUF);
	if (enclen < 0 || (strlen(buf) + enclen) >= CFG_MAX_BUF) {
		cfg_severity = CFG_ENONFATAL;
		cfg_perror_str = dgettext("cfg", "Buffer too small");
		return (-1);
	}
	strcat(buf, encode_buf);
	strcat(buf, ";");
	if (cfg_put_cstring(cfg, basekey, buf, CFG_MAX_BUF) < 0) {
		/* severity & perror_str set by cfg_put_cstring */
		return (-1);
	}
	errno = 0;
	return (TRUE);
}

/*
 * cfg_get_single_option
 *
 *	Scans the options string for the specified option and returns
 *	the decoded value
 *
 * Return:
 *	true	success
 *	-1	incorrect section, or read error from cfg DB
 */
int
cfg_get_single_option(CFGFILE *cfg, int section, const char *basekey, char *tag,
    char *val, int val_len)
{
	char buf[CFG_MAX_BUF];
	char encode_buf[CFG_MAX_BUF];
	char *p, *q;
	int enclen;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	errno = ENOSYS;
	bzero(buf, CFG_MAX_BUF);
	if (section != CFG_SEC_CONF) {
		cfg_severity = CFG_ENONFATAL;
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		return (-1);
	}
	if (cfg_get_cstring(cfg, basekey, buf, CFG_MAX_BUF) < 0) {
		/* severity & perror_str set by cfg_get_cstring */
		return (-1);
	}

	*encode_buf = ';';
	enclen = cfg_encode_string(tag, &encode_buf[1], CFG_MAX_BUF - 1) + 1;
	if (enclen < 1 || (enclen + 1) >= CFG_MAX_BUF) {
		cfg_severity = CFG_ENONFATAL;
		cfg_perror_str = dgettext("cfg", "Buffer too small");
		return (-1);
	}
	encode_buf[enclen] = '=';
	encode_buf[enclen + 1] = '\0';

	/* check the start of the string */
	if (strncmp(buf, &encode_buf[1], enclen) == 0) {
		p = strchr(buf, '=');
		if (!p) {
			cfg_severity = CFG_ENONFATAL;
			cfg_perror_str = dgettext("cfg", "Option not found");
			return (-1);
		}
		++p;
		q = strchr(p, ';');
		if (q) {
			*q = '\0';
		}
		cfg_decode_string(p, val, val_len);
		errno = 0;
		return (TRUE);
	}

	/* it's hiding somewhere inside... */
	p = strstr(buf, encode_buf);
	if (p) {
		p += enclen + 1;
		q = strchr(p, ';');
		if (q) {
			*q = '\0';
		}
		cfg_decode_string(p, val, val_len);
		errno = 0;
		return (TRUE);
	}

	/* key not found */
	return (-1);

}

/*
 * cfg_del_option
 *
 *	Removes a single key=val pair from the specified option field
 *
 * Return:
 *	true	success
 *	-1	unable to update config
 */
int
cfg_del_option(CFGFILE *cfg, int section, const char *basekey, char *tag)
{
	char buf[CFG_MAX_BUF];
	char encode_buf[CFG_MAX_BUF];
	char *p, *q;
	int enclen, rc;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	bzero(buf, CFG_MAX_BUF);
	if (section != CFG_SEC_CONF) {
		cfg_severity = CFG_ENONFATAL;
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		return (-1);
	}
	if (cfg_get_cstring(cfg, basekey, buf, CFG_MAX_BUF) < 0) {
		/* severity & perror_str are set by cfg_get_cstring */
		return (-1);
	}

	*encode_buf = ';';
	enclen = cfg_encode_string(tag, &encode_buf[1], CFG_MAX_BUF - 1) + 1;
	if (enclen < 1 || (enclen + 1) >= CFG_MAX_BUF) {
		cfg_severity = CFG_ENONFATAL;
		cfg_perror_str = dgettext("cfg", "Buffer too small");
		return (-1);
	}
	encode_buf[enclen] = '=';
	encode_buf[enclen + 1] = '\0';

	/* check the start of the string */
	if (strncmp(buf, &encode_buf[1], enclen) == 0) {
		p = strchr(buf, ';');
		if (p && (*(p + 1) != '\0')) {
			rc = cfg_put_cstring(cfg, basekey, p + 1,
			    strlen(p + 1));
		} else {
			rc = cfg_put_cstring(cfg, basekey, "-", 1);
		}
		/* severity & perror_str are set by cfg_put_cstring */
		return (rc);
	}

	/* sigh */
	p = strstr(buf, encode_buf);
	if (!p) {
		/* already removed */
		return (TRUE);
	}
	q = strchr(p + 1, ';');

	/*
	 * Now the string looks like:
	 *	| first few options | *p | option to remove | *q | rest | '\0'
	 */

	if (!q) {
		/* hum... */
		*p = '\0';
	} else {
		strcpy(p, q);
	}

	return (cfg_put_cstring(cfg, basekey, buf, strlen(buf)));
}

static void
cfg_set_memorymap(cfp_t *cfp)
{
	cfgheader_t *hd = cfp->cf_head;

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "callocing %d for initial reads\n", hd->h_csize);
#endif

	hd->h_ccopy1 = (char *)calloc(hd->h_csize, sizeof (char));
	hd->h_ccopy2 = (char *)calloc(hd->h_csize, sizeof (char));
	hd->h_sizes1 = (int *)calloc(CFG_DEFAULT_PSIZE, sizeof (int));
	hd->h_sizes2 = (int *)calloc(CFG_DEFAULT_PSIZE, sizeof (int));
}

/*
 * cfg_init_header
 * fill in default header info
 */
static void
cfg_init_header(cfp_t *cfp)
{
	time_t tloc;
	cfgheader_t *hd = cfp->cf_head;

	hd->h_magic = (int32_t)CFG_NEW_MAGIC;
	hd->h_stamp = time(&tloc);
	hd->h_lock = 0;
	/* parser config */
	hd->h_parsesize = 0;
	hd->h_parseoff = 0;
	hd->h_csize = 0;
	hd->h_psize = 0;
	hd->h_cfgs = NULL;
	hd->h_ncfgs = 0;
	hd->h_seq1 = hd->h_seq2 = 1;
	bzero(hd->h_cfgsizes, MAX_CFG * sizeof (int));
}
/*
 * cfg_read
 * read header and all sections of configuration file
 * gets new data for incore copy
 * removes invalid header state
 * works even if config and persistent sections are empty
 *
 */
static int
cfg_read(cfp_t *cfp)
{
	int rc;
	cfgheader_t *hd;
	int readsize = 0;
#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "cfg_read\n");
#endif

	if (!cfp->cf_head) {
		if ((hd = calloc(1, sizeof (*hd))) == NULL)
			return (FALSE);
#ifdef DEBUG_HDR
			(void) fprintf(stderr, "initial cfg header read\n");
#endif
		cfp->cf_head = hd;
	}

	if ((*cfp->cf_pp->seek)(cfp, 0, SEEK_SET) < 0) {
#ifdef DEBUG_LIB
		(void) fprintf(stderr, "cfg: seek header failed\n");
#endif
		return (FALSE);
	}

	rc = (*cfp->cf_pp->read)(cfp, (char *)cfp->cf_head, 4);
	if (rc < 4) {
#ifdef DEBUG_LIB
		(void) fprintf(stderr, "cfg: read magic number failed\n");
#endif
		return (FALSE);
	}

	if ((*cfp->cf_pp->seek)(cfp, 0, SEEK_SET) < 0) {
#ifdef DEBUG_LIB
		(void) fprintf(stderr, "cfg: seek header failed\n");
#endif
		return (FALSE);
	}

	rc = (*cfp->cf_pp->read)(cfp, (char *)cfp->cf_head, sizeof (*hd));
	if (rc < sizeof (*hd)) {
#ifdef DEBUG_LIB
		(void) fprintf(stderr, "cfg: read header failed\n");
#endif
		return (FALSE);
	}

	cfp->cf_head->h_cfgs = NULL;
	cfg_set_memorymap(cfp);
	if (cfp->cf_head->h_magic != CFG_NEW_MAGIC) {
#ifdef DEBUG_LIB
		(void) fprintf(stderr, "cfg_read: wrong MAGIC number %x\n",
		    cfp->cf_head->h_magic);
#endif
		return (FALSE);
	}

	cfp->cf_head->h_state &= ~(CFG_HDR_INVALID);

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "reading parser\n");
#endif
	rc = (*cfp->cf_pp->read)(cfp, (char *)cfp->cf_mapped,
	    CFG_DEFAULT_PARSE_SIZE);
	if (rc < sizeof (*hd)) {
#ifdef DEBUG
		(void) fprintf(stderr, "cfg: read parse config failed\n");
#endif
		return (FALSE);
	}

	readsize = cfp->cf_head->h_csize;

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "reading copy1 readsize = %d\n", readsize);
#endif
	rc = (*cfp->cf_pp->read)(cfp, (char *)cfp->cf_head->h_ccopy1,
	    readsize);
	if (rc < 0) {
		/* don't fail just return */
#ifdef DEBUG
		(void) fprintf(stderr, "cfg: read ccopy1 section failed\n");
#endif
		return (FALSE);
	}

	if ((*cfp->cf_pp->seek)
	    (cfp, CFG_DEFAULT_SSIZE - rc, SEEK_CUR) < 0) {
#ifdef DEBUG
		(void) fprintf(stderr, "cfg: seek (SEEK_CUR) failed\n");
#endif
		return (FALSE);
	}

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "reading copy2 readsize = %d\n", readsize);
#endif

	rc = (*cfp->cf_pp->read)(cfp, (char *)cfp->cf_head->h_ccopy2,
	    readsize);
	if (rc < 0) {
		/* don't fail just return */
#ifdef DEBUG
		(void) fprintf(stderr, "cfg: read ccopy2 section failed\n");
#endif
		return (FALSE);
	}

	/* read the sizes of the lists from disk  */
	if ((*cfp->cf_pp->seek)
	    (cfp, CFG_DEFAULT_SSIZE - rc, SEEK_CUR) < 0) {
#ifdef DEBUG
		(void) fprintf(stderr, "cfg: seek (SEEK_CUR) failed\n");
#endif
		return (FALSE);
	}

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "reading sizes\n");
#endif
	rc = (*cfp->cf_pp->read)(cfp, (int *)cfp->cf_head->h_sizes1,
	    CFG_DEFAULT_PSIZE);
	if (rc < 0) {
#ifdef DEBUG
		(void) fprintf(stderr, "cfg: read h_sizes1 failed\n");
#endif
		return (FALSE);
	}

	rc = (*cfp->cf_pp->read)(cfp, (int *)cfp->cf_head->h_sizes2,
	    CFG_DEFAULT_PSIZE);
	if (rc < 0) {
#ifdef DEBUG
		(void) fprintf(stderr, "cfg: read h_sizes2 failed\n");
#endif
		return (FALSE);
	}

	/*
	 * If initial or invalid sequence, use first section
	 */
	if ((cfp->cf_head->h_seq1 <= 0) && (cfp->cf_head->h_seq2 <= 0)) {
		cfp->cf_head->h_cparse = cfp->cf_head->h_ccopy1;
		cfp->cf_head->h_sizes = cfp->cf_head->h_sizes1;
	}

	if (cfp->cf_head->h_seq1 >= cfp->cf_head->h_seq2) {
		cfp->cf_head->h_cparse = cfp->cf_head->h_ccopy1;
		cfp->cf_head->h_sizes = cfp->cf_head->h_sizes1;
	} else {
		cfp->cf_head->h_cparse = cfp->cf_head->h_ccopy2;
		cfp->cf_head->h_sizes = cfp->cf_head->h_sizes2;
	}

#ifdef DEBUG_LIB
	dump_status(cfp, "cfg_read");
#endif

	return (TRUE);
}

/*
 * cfg_lock
 * Read-write locking of the configuration
 * reads into core all sections
 * builds parser trees for each section
 * Returns: TRUE if the lock was acquired, FALSE otherwise.
 */
int
cfg_lock(CFGFILE *cfg, CFGLOCK mode)
{
	cfp_t *cfp;
	int is_locked = 0;
	int rc;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (FALSE);
	}

	if (mode == CFG_UPGRADE) {
		mode = CFG_WRLOCK;
	}

	if (mode == CFG_WRLOCK && (cfg->cf[0].cf_flag & CFG_RDONLY)) {
		goto fail;
	}

	/*
	 * if you don't even give me the right lock request,
	 * why should I give you one?
	 */
	if (mode != CFG_RDLOCK && mode != CFG_WRLOCK)
		goto fail;

	if (cfg_lockd) {
		if (mode == CFG_WRLOCK)
			cfg_lockd_wrlock();
		else
			cfg_lockd_rdlock();
		is_locked = 1;
	} else {

#ifdef DEBUG_CFGLIST
		(void) fprintf(stderr, "cfg_lock\n");
#endif
		/* Lock is always based on local file pointer */
		cfg->cf[1].cf_lock = cfg->cf[0].cf_lock = cfg->cf[0].cf_fd;

		if (!((cfg->cf[0].cf_flag & CFG_RDONLY) &&
		    (mode == CFG_RDLOCK))) {

			struct flock lk = {0};
			lk.l_type = (mode == CFG_RDLOCK ? F_RDLCK : F_WRLCK);
			lk.l_whence = SEEK_SET;
			lk.l_start = (off_t)0;
			lk.l_len = (off_t)0;

			if (fcntl(cfg->cf[0].cf_lock, F_SETLKW, &lk) < 0)
				goto fail;
		}
	}

	/* Determine number of files open */
	for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
		if (!cfp->cf_fd) continue;
		if ((cfp->cf_head) &&
		    (cfp->cf_head->h_state & CFG_HDR_INVALID)) {
			if ((rc = cfg_hdrcmp(cfp)) == 0) {
#ifdef DEBUG_HDR
		(void) fprintf(stderr,
		    "cfg header match, skipping re-read\n");
#endif
				cfp->cf_head->h_state |= CFG_HDR_RDLOCK;
				if (mode == CFG_WRLOCK)
					cfp->cf_head->h_state |= CFG_HDR_WRLOCK;

				cfp->cf_head->h_state &= ~(CFG_HDR_INVALID);
				continue;
			}
#ifdef DEBUG_HDR
		(void) fprintf(stderr, "re-reading cfg, header mismatch\n");
#endif
			/*
			 * dump what we have, info is stale
			 */
			cfg_free_cfglist(cfp);
			cfg_free_parser_tree();

			if (cfp->cf_head->h_ccopy1) {
				free(cfp->cf_head->h_ccopy1);
				cfp->cf_head->h_ccopy1 = NULL;
			}
			if (cfp->cf_head->h_ccopy2) {
				free(cfp->cf_head->h_ccopy2);
				cfp->cf_head->h_ccopy2 = NULL;
			}
			if (cfp->cf_head->h_sizes1) {
				free(cfp->cf_head->h_sizes1);
				cfp->cf_head->h_sizes1 = NULL;
			}
			if (cfp->cf_head->h_sizes2) {
				free(cfp->cf_head->h_sizes2);
				cfp->cf_head->h_sizes2 = NULL;
			}

			if (cfp->cf_head)
				free(cfp->cf_head);
			cfp->cf_head = NULL;
		}

		if (cfp->cf_head == NULL) {
			if (!cfg_read(cfp)) {
				if (cfp->cf_head != NULL)
					cfg_init_header(cfp);
				else
					goto fail;
			} else {
#ifdef DEBUG_CFGLIST
				(void) fprintf(stderr,
				"reading parser config\n");
#endif
				/* build parser trees */
				cfg_read_parser_config(cfp);
			}

		}
		cfp->cf_head->h_state |= CFG_HDR_RDLOCK;
		if (mode == CFG_WRLOCK) {
			if (cfp->cf_head->h_seq1 >= cfp->cf_head->h_seq2) {
#ifdef DEBUG_LIB
				(void) fprintf(stderr,
				    "cfg_lock: WRLOCK copying 1 to 2\n");
#endif
				memcpy(cfp->cf_head->h_ccopy2,
				    cfp->cf_head->h_ccopy1,
				    cfp->cf_head->h_csize);
				memcpy(cfp->cf_head->h_sizes2,
				    cfp->cf_head->h_sizes1,
				    CFG_DEFAULT_PSIZE);

				cfp->cf_head->h_cparse = cfp->cf_head->h_ccopy2;
				cfp->cf_head->h_sizes = cfp->cf_head->h_sizes2;
			} else {
#ifdef DEBUG_LIB
				(void) fprintf(stderr,
				    "cfg_lock: WRLOCK copying 2 to 1\n");
#endif
				memcpy(cfp->cf_head->h_ccopy1,
				    cfp->cf_head->h_ccopy2,
				    cfp->cf_head->h_csize);
				memcpy(cfp->cf_head->h_sizes1,
				    cfp->cf_head->h_sizes2,
				    CFG_DEFAULT_PSIZE);

				cfp->cf_head->h_cparse = cfp->cf_head->h_ccopy1;
				cfp->cf_head->h_sizes = cfp->cf_head->h_sizes1;
			}

			cfp->cf_head->h_state |= CFG_HDR_WRLOCK;
		}

		if (cfg_map_cfglists(cfp) < 0) {
#ifdef DEBUG_LIB
			(void) fprintf(stderr, "cfg: map_cfglists failed\n");
#endif
			goto fail;
		}

#ifdef DEBUG_LIB
		dump_status(cfp, "cfg_lock");
#endif
	}

	return (TRUE);

fail:
	if (is_locked) {
		cfg_lockd_unlock();
	}
	cfg_perror_str = dgettext("cfg", CFG_EGENERIC);
	cfg_severity = CFG_ENONFATAL;
	return (FALSE);
}

/*
 * Unlock the database
 */
void
cfp_unlock(cfp_t *cfp)
{

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "cfg_unlock\n");
#endif
	if (cfg_lockd) {
		cfg_lockd_unlock();
	} else {
		struct flock lk = {0};
		lk.l_type = F_UNLCK;
		lk.l_whence = SEEK_SET;
		lk.l_start = (off_t)0;
		lk.l_len = (off_t)0;
		(void) fcntl(cfp->cf_lock, F_SETLKW, &lk);
	}

	if (cfp->cf_head != NULL) {
		cfp->cf_head->h_state &= ~(CFG_HDR_RDLOCK|CFG_HDR_WRLOCK);
		cfp->cf_head->h_state |= CFG_HDR_INVALID;
	}
}
void
cfg_unlock(CFGFILE *cfg)
{
	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return;
	}

	cfp_unlock(&cfg->cf[0]);
	cfp_unlock(&cfg->cf[1]);
}

/*
 * Test for a read lock, set errno if failed.
 */
static int
cfg_rdlock(CFGFILE *cfg)
{
	int rc;
	cfp_t *cfp;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (FALSE);
	}

	/* Determine number of files open */
	for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
		if (!cfp->cf_fd)
			continue;
		if (cfp->cf_head == NULL) {
#ifdef DEBUG_LIB
			(void) fprintf(stderr, "cfg_rdlock: cf_head == NULL\n");
#endif
			/*
			 * 6335583, if header == NULL,
			 * we can't call cfg_read to fill the header again
			 * since it will change the lock state to
			 * CFG_HDR_WRLOCK and dscfg will be the processer
			 * that hold the lock,
			 * just returning a FALSE if the case,
			 * then retrieve the lock state from flock structure.
			 */
			rc = FALSE;
			break;
		} else {
#ifdef DEBUG_LIB
			(void) fprintf(stderr, "cfg_rdlock: cf_head != NULL\n");
#endif
			if ((cfp->cf_head->h_state & CFG_HDR_RDLOCK)
			    == CFG_HDR_RDLOCK) {
				rc = TRUE;
			} else {
				rc = FALSE;
				break;
			}
		}
	}

	if (!rc)
		errno = EPERM;

	return (rc);
}

/*
 * Test for a write lock, set errno if failed.
 */
static int
cfg_wrlock(CFGFILE *cfg)
{
	int rc;
	cfp_t *cfp;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (FALSE);
	}

	/* Determine number of files open */
	for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
		if (!cfp->cf_fd)
			continue;
		if (cfp->cf_head == NULL) {
#ifdef DEBUG_LIB
			(void) fprintf(stderr, "cfg wrlock: cf_head == NULL\n");
#endif
			/*
			 * 6335583, see comments on cfg_rdlock
			 */
			rc = FALSE;
			break;
		} else {
#ifdef DEBUG_LIB
			(void) fprintf(stderr, "cfg wrlock: cf_head != NULL\n");
#endif
			if ((cfp->cf_head->h_state & CFG_HDR_WRLOCK)
			    == CFG_HDR_WRLOCK) {
				rc = TRUE;
			} else {
				rc = FALSE;
				break;
			}
		}
	}

	if (!rc)
		errno = EPERM;

	return (rc);
}

/*
 * cfg_get_lock
 * Find lock status of CFG database.
 * Returns: TRUE and sets lock and pid if the lock is held, FALSE otherwise.
 */
int
cfg_get_lock(CFGFILE *cfg, CFGLOCK *lock, pid_t *pid)
{
	struct flock lk;
	int rc;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (FALSE);
	}

	if (cfg_lockd) {
		switch (cfg_lockedby(pid)) {
		case LOCK_READ:
			*lock = CFG_RDLOCK;
			return (TRUE);
		case LOCK_WRITE:
			*lock = CFG_WRLOCK;
			return (TRUE);
		case LOCK_NOTLOCKED:
		default:
			return (FALSE);
		}
	} else {
		if (cfg_wrlock(cfg)) {
			*lock = CFG_WRLOCK;
			*pid = getpid();
			return (TRUE);
		}

		if (cfg_rdlock(cfg)) {
			*lock = CFG_RDLOCK;
			*pid = getpid();
			return (TRUE);
		}
	}
	/* Lock is always based on local file pointer */
	cfg->cf[1].cf_lock = cfg->cf[0].cf_lock = cfg->cf[0].cf_fd;

	bzero(&lk, sizeof (lk));
	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	lk.l_start = (off_t)0;
	lk.l_len = (off_t)0;

	if (fcntl(cfg->cf[0].cf_lock, F_GETLK, &lk) < 0)
		rc = FALSE;
	else {
		if (lk.l_type == F_UNLCK)
			rc = FALSE;
		else {
			rc = TRUE;
			*pid = lk.l_pid;
			*lock = lk.l_type == F_WRLCK ? CFG_WRLOCK : CFG_RDLOCK;
		}
	}

	return (rc);
}

/*
 * cfg_commit
 * Write modified version of header, configuration and persistent
 * data using 2 stage commit.
 * If no valid data is found in header, it is assumed to be an initial
 * write and we will create the default header (could be dangerous)
 * another tricky part, if we are doing an upgrade we may be dealing
 * with an old database. we need to take care seeking and writing
 * until such time that it is upgraded.
 *
 * Mutual exclusion is checked using cfg_lock
 */

int
cfg_commit(CFGFILE *cfg)
{
	cfp_t *cfp;
	int rc;
	time_t tloc;
	int section;
	int wrsize, *ip;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (FALSE);
	}

	if (!cfg_wrlock(cfg))
		return (FALSE);

	/* Determine number of files open */
	for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
		if (!cfp->cf_fd)
			continue;

		/*
		 * lets put everything back into one char *
		 */
		cfg_replace_lists(cfp);

		if ((*cfp->cf_pp->seek)(cfp, 0, SEEK_SET) < 0) {
#ifdef DEBUG_LIB
			(void) fprintf(stderr, "cfg: seek header failed\n");
#endif
			return (FALSE);
		}

		cfp->cf_head->h_size = cfp->cf_head->h_parsesize
		    + cfp->cf_head->h_csize + cfp->cf_head->h_psize;
		cfp->cf_head->h_stamp = time(&tloc);

		/* seeking into database */
		if ((*cfp->cf_pp->seek)(cfp, sizeof (cfgheader_t),
		    SEEK_CUR) < 0)
			return (FALSE);

		if (cfp->cf_head->h_ccopy1 == cfp->cf_head->h_cparse) {
			if (cfp->cf_head->h_seq1 < 0)
				cfp->cf_head->h_seq1 = 1;
			else
				cfp->cf_head->h_seq1 = cfp->cf_head->h_seq2 + 1;
			section = 1;
		} else {
			if (cfp->cf_head->h_seq2 < 0)
				cfp->cf_head->h_seq2 = 1;
			else
				cfp->cf_head->h_seq2 = cfp->cf_head->h_seq1 + 1;
			section = 2;
		}
#ifdef DEBUG_LIB
		dump_status(cfp, "cfg_commit");
#endif
		rc = (*cfp->cf_pp->write)(cfp, cfp->cf_mapped,
		    CFG_DEFAULT_PARSE_SIZE);
#ifdef DEBUG
		if (rc < 0) {
			(void) fprintf(stderr,
			    "parse commit: rc %d h_parsesize %d\n",
			    rc, cfp->cf_head->h_parsesize);
		}
#endif
		if (section == 1) {
			rc = (*cfp->cf_pp->write) (cfp, cfp->cf_head->h_ccopy1,
			    cfp->cf_head->h_csize);
#ifdef DEBUG
			if (rc < 0) {
				(void) fprintf(stderr,
				    "csection commit 1: rc %d h_csize %d\n",
				    rc, cfp->cf_head->h_csize);
			}
#endif
			if ((*cfp->cf_pp->seek)
			    (cfp, (2 * CFG_DEFAULT_SSIZE) - rc, SEEK_CUR) < 0)
				return (FALSE);

			/*
			 * limit the write to only what we need
			 */
			ip = cfp->cf_head->h_sizes1;
			for (wrsize = 0; *ip; ip += *ip + 1)
				wrsize += *ip + 1;

			rc = (*cfp->cf_pp->write)(cfp, cfp->cf_head->h_sizes1,
			    wrsize * sizeof (int));
#ifdef DEBUG
			if (rc < 0) {
				(void) fprintf(stderr,
				    "cfg: write list sizes1 failed rc\n");
			}
#endif
		} else {
			if ((*cfp->cf_pp->seek)(cfp, CFG_DEFAULT_SSIZE,
			    SEEK_CUR) < 0)
				return (FALSE);

			rc = (*cfp->cf_pp->write)(cfp, cfp->cf_head->h_ccopy2,
			    cfp->cf_head->h_csize);
#ifdef DEBUG
			if (rc < 0) {
				(void) fprintf(stderr,
				    "csection commit 2: rc %d h_csize %d\n",
				    rc, cfp->cf_head->h_csize);
			}
#endif
			if ((*cfp->cf_pp->seek)
			    (cfp, (CFG_DEFAULT_SSIZE + CFG_DEFAULT_PSIZE) - rc,
			    SEEK_CUR) < 0)
				return (FALSE);

			/*
			 * limit the write to only what we need
			 */
			ip = cfp->cf_head->h_sizes2;
			for (wrsize = 0; *ip; ip += *ip + 1)
				wrsize += *ip + 1;

			rc = (*cfp->cf_pp->write)(cfp, cfp->cf_head->h_sizes2,
			    wrsize * sizeof (int));
#ifdef DEBUG
			if (rc < 0) {
				(void) fprintf(stderr,
				    "cfg: write list sizes2 failed\n");
			}
#endif

		}


#ifdef DEBUG_CFGLIST
		(void) fprintf(stderr,
		    "writing h_csize %d\n", cfp->cf_head->h_csize);
#endif
		if ((*cfp->cf_pp->seek)(cfp, 0, SEEK_SET) < 0)
			return (FALSE);

		cfp->cf_head->h_size = cfp->cf_head->h_parsesize +
		    cfp->cf_head->h_csize + cfp->cf_head->h_psize;

		rc = (*cfp->cf_pp->write)(cfp, cfp->cf_head,
		    sizeof (cfgheader_t));
		if (rc < 0) {
			cfg_perror_str = dgettext("cfg",
			    "cfg_commit: header write failed");
			cfg_severity = CFG_EFATAL;
			return (FALSE);
		}
	}

	return (TRUE);
}

/*
 * cfg_rewind
 * rewind internal file pointer for specified section
 * empty now, rewind not necessary. But don't break
 * old code.
 */
/*ARGSUSED*/
void
cfg_rewind(CFGFILE *cfg, int section)
{
	switch (section) {
		case CFG_SEC_CONF:
			break;
		case CFG_SEC_ALL:
			break;
	};
}

/*
 * cfg_location
 * set or return the default location file to
 * determine the partition name of the configuration partition
 * location is stored in well known file location
 */
char *
cfg_location(char *location, int mode, char *altroot)
{
	int fd;
	int fmode;
	int rc;
	char wellknown[NSC_MAXPATH];
	char loc[NSC_MAXPATH];

	if (mode == CFG_LOC_GET_LOCAL) {
		return (CFG_LOCAL_LOCATION);
	} else if (mode == CFG_LOC_GET_CLUSTER) {
		fmode = O_RDONLY;
	} else {
		fmode = O_RDWR | O_CREAT;
	}

	if (altroot) {
		strcpy(wellknown, altroot);
		strcat(wellknown, CFG_CLUSTER_LOCATION);
	} else
		strcpy(wellknown, CFG_CLUSTER_LOCATION);

	fd = open(wellknown, fmode, 0644);
	if (fd < 0) {
		cfg_perror_str = dgettext("cfg", strerror(errno));
		cfg_severity = CFG_ENONFATAL;
		return (NULL);
	}

	if (mode == CFG_LOC_SET_CLUSTER) {
		if (location == NULL || (strlen(location) > NSC_MAXPATH)) {
			cfg_perror_str = dgettext("cfg",
			    "cfg_location: filename too big or missing");
			cfg_severity = CFG_EFATAL;
			return (NULL);
		}

		/*
		 * 5082142
		 * If we're in a cluster, make sure that the config location
		 * is a raw device.  Using non-raw did devices in a cluster
		 * can result in data corruption, since inconsistent data
		 * may reside in the block cache on one node, but has not
		 * been flushed to disk.
		 */
		if (cfg_iscluster() > 0) {
			struct stat dscfg_stat;
			if (stat(location, &dscfg_stat) != 0) {
				cfg_perror_str = dgettext("cfg",
				    "Unable to access dscfg location");
				cfg_severity = CFG_EFATAL;
				return (NULL);
			}
			if (!S_ISCHR(dscfg_stat.st_mode)) {
				cfg_perror_str = dgettext("cfg",
				    "dscfg location must be a raw device");
				cfg_severity = CFG_EFATAL;
				return (NULL);
			}
		}

		if (ftruncate(fd, 0) < 0)
			return (NULL);

		rc = write(fd, location, strlen(location));
		if (rc < 0) {
			cfg_perror_str = dgettext("cfg",
			    "cfg_location: write to well known failed");
			cfg_severity = CFG_EFATAL;
			return (NULL);
		}
		bzero(config_file, sizeof (config_file));
	}
	if (lseek(fd, 0, SEEK_SET) < 0)
		return (NULL);

	bzero(config_file, sizeof (config_file));
	rc = read(fd, config_file, sizeof (config_file));
	if (rc < 0) {
		cfg_perror_str = dgettext("cfg",
		    "cfg_location: read from well known failed");
		cfg_severity = CFG_EFATAL;
		return (NULL);
	}
	close(fd);
	if (altroot) {
		strcpy(loc, altroot);
		strcat(loc, config_file);
		bzero(config_file, sizeof (config_file));
		strcpy(config_file, loc);
	}

	/*
	 * scan string out of config_file, to strip whitespace
	 */
	sscanf(config_file, "%s", loc);
	strcpy(config_file, loc);

	return (config_file);
}

/*
 * cfg_update_parser_config
 * If tag and key exist return -1
 *
 * XXX Currently does not append new field to existing parser rule
 */

int
cfg_update_parser_config(CFGFILE *cfg, const char *key, int section)
{
	cfp_t *cfp;
	int size;
	char buf[CFG_MAX_BUF];
	struct parser *tbl;
	char tmpkey[CFG_MAX_KEY];
	char *ky, *fld;
	errno = 0;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	cfp = FP_SUN_CLUSTER(cfg);
	if (!cfg_wrlock(cfg))
		return (-1);

	bzero(buf, CFG_MAX_BUF);
	bzero(tmpkey, sizeof (tmpkey));
	strcpy(tmpkey, key);
	if (section == CFG_PARSE_CONF) {
		strcat(buf, "C:");
		tbl =  chead;
	} else {
		errno = EINVAL;
		return (-1);
	}
	ky = strtok(tmpkey, ".");
	fld = strtok(NULL, ".");
	while (fld) {
		size = cfg_get_item(tbl, ky, fld);

		/*
		 * Assure we are loading a clean table, with do duplicates
		 * based on our File Descriptor
		 */
		if (chead_loaded && (chead_loaded != cfp->cf_fd)) {
			if (size <= 0)
				return (-1);
		} else {
			if (size > 0)
				return (-1);
		}
		fld = strtok(NULL, ".");
	}
	size = strlen(key) + 2;
	strncat(buf, key, size);
#ifdef DEBUG_LIB
	(void) fprintf(stderr, "update parser config %s size %d\n", buf, size);
#endif
	if ((size + cfp->cf_head->h_parseoff) > CFG_DEFAULT_PARSE_SIZE) {
		cfg_perror_str = dgettext("cfg",
		    "cfg_update_parser_config: header overrun");
		cfg_severity = CFG_EFATAL;
#ifdef DEBUG_LIB
		(void) fprintf(stderr, "update parser config: "
		    "overrun siz %d poff %d parsesize %d\n",
		    size, cfp->cf_head->h_parseoff, cfp->cf_head->h_parsesize);
#endif
		errno = E2BIG;
		return (-1);
	}
	bcopy(buf, (cfp->cf_mapped + cfp->cf_head->h_parseoff), size);
	cfp->cf_head->h_parseoff += size;
	cfp->cf_head->h_state |= CFG_HDR_INVALID;
	if (cfp->cf_mapped[cfp->cf_head->h_parseoff - 1] != '\n') {
		cfp->cf_mapped[cfp->cf_head->h_parseoff] = '\n';
		cfp->cf_head->h_parseoff++;
	}
	cfp->cf_head->h_parsesize = cfp->cf_head->h_parseoff;
	cfg_read_parser_config(cfp);
	return (TRUE);
}
/*
 * cfg_read_parser_config
 * reads parser config from file
 * converts it to internal tree for parsing
 * chead for configuration parser entries
 *
 */
static
void
cfg_read_parser_config(cfp_t *cfp)
{
	struct lookup *p, *q;
	struct parser *thead;
	int off, foff;
	char *part;
	char *key;
	char *fld;
	int fldnum;
	char c;
	char buf[CFG_MAX_BUF];
	int i = 0;
	int n = 0;

	off = foff = 0;
	/*CONSTCOND*/
	while (TRUE) {
		off = 0;
		bzero(buf, CFG_MAX_BUF);
		/* LINTED it assigns value to c */
		while (c = cfp->cf_mapped[foff++]) {
			if (c == '\n')
				break;
			buf[off++] = c;
		}
		part = strtok(buf, ":");
		if (!part)
			break;
		if (*part == 'C') {
			thead = chead;
			n = i;
		}
		key = strtok(NULL, ".");
		if (!key)
			break;
		strcpy(thead[n].tag.l_word, key);
		thead[n].tag.l_value = 0;
		thead[n].fld = NULL;
		fldnum = 1;
		while ((fld = strtok(NULL, ".")) != NULL) {
			p = thead[n].fld;
			if (p == NULL) {
				q = thead[n].fld = calloc(1,
				    sizeof (struct lookup));
			} else {
				for (q = thead[n].fld; q; q = q->l_next)
					p = q;
				q = calloc(1, sizeof (struct lookup));
				p->l_next = q;
			}
			strcpy(q->l_word, fld);
			q->l_value = fldnum;
			q->l_next = NULL;
#ifdef DEBUG_EXTRA
			(void) fprintf(stderr,
			    "read parser: q: word %s value %d\n",
			    q->l_word, q->l_value);
#endif
			fldnum++;
		}
		if (*part == 'C')
			i++;
	}

	/* All done, indicate parser table is loaded */
	if (i && (chead_loaded == 0))
		chead_loaded = cfp->cf_fd;

	/*
	 * before I go and alloc, why am I here?
	 * do I need a bunch of cfglists, or do I just
	 * need to accommodate a just added parser entry
	 * if the latter, we already have a base, just set
	 * i to the index of the cfg which members need allocing
	 */
	if ((cfp->cf_head->h_cfgs == NULL) ||
	    (cfp->cf_head->h_cfgs[n-1].l_entry == NULL)) {
		cfp->cf_head->h_cfgs = (cfglist_t *)calloc(MAX_CFG,
		    sizeof (cfglist_t));
		i = 0;
	}
	else
		i = n;

	if (cfp->cf_head->h_cfgs) {

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "alloced %d cfg lists \n", n + 1);
#endif
		for (cfp->cf_head->h_ncfgs = n + 1;
		    i < min(cfp->cf_head->h_ncfgs, MAX_CFG); i++) {
			cfp->cf_head->h_cfgs[i].l_name = '\0';
			cfp->cf_head->h_cfgs[i].l_name =
			    strdup(chead[i].tag.l_word);
			cfp->cf_head->h_cfgs[i].l_index = i;
			cfp->cf_head->h_cfgs[i].l_entry =
			    calloc(DEFAULT_ENTRY_SIZE, sizeof (char));
			cfp->cf_head->h_cfgs[i].l_nentry = 0;
			cfp->cf_head->h_cfgs[i].l_esiz =
			    calloc(DEFAULT_NENTRIES, sizeof (int));
			cfp->cf_head->h_cfgs[i].l_size = 0;
			cfp->cf_head->h_cfgs[i].l_free = DEFAULT_ENTRY_SIZE;
			if ((cfp->cf_head->h_cfgs[i].l_entry == NULL) ||
			    (cfp->cf_head->h_cfgs[i].l_esiz == NULL)) {
				cfg_perror_str = dgettext("cfg", "unable to"
				    " allocate cfglist members");
				cfg_severity = CFG_EFATAL;
			}
		}
	} else {
		cfg_perror_str = dgettext("cfg", "unable to alloc cfglist");
		cfg_severity = CFG_EFATAL;
	}
}

/*
 * cfg_map_cfglists()
 * go through list of list sizes in header
 * and create separate lists
 */
int
cfg_map_cfglists(cfp_t *cfp)
{
	int i;
	int offset = 0;
	int *ip;
	int list_size = 0;
	int slot_inc;
	char *p;
	cfgheader_t *ch;

	ch = cfp->cf_head;
	p = ch->h_cparse;

	/* get the first list size */
	ip = ch->h_sizes;

	for (i = 0; i < min(ch->h_ncfgs, MAX_CFG); i++) {
		if (ch->h_cfgsizes[i] > 0) {
			if (ch->h_cfgsizes[i] > DEFAULT_ENTRY_SIZE) {

				ch->h_cfgs[i].l_entry = (char *)
				    realloc(ch->h_cfgs[i].l_entry,
				    ch->h_cfgsizes[i] * sizeof (char));
				/* set free to 0, we'll get more when we add */
				ch->h_cfgs[i].l_free = 0;

			} else
				ch->h_cfgs[i].l_free -= ch->h_cfgsizes[i];

			/* get lists and marry up to each cfgs structure */


			list_size = *ip;
			ip++;

			if (list_size > DEFAULT_NENTRIES) {
				/*
				 *  we're gonna need more slots
				 * we want to alloc on DEFAULT_NENTRIES
				 * boundry. ie. always a multiple of it
				 * later on, when we add to the list
				 * we can see if we need to add by mod'ding
				 * l_nentry and DEFAULT_NENTRIES and check for 0
				 */
				slot_inc = DEFAULT_NENTRIES -
				    (list_size % DEFAULT_NENTRIES);
				if (slot_inc == DEFAULT_NENTRIES)
					slot_inc = 0; /* addcfline reallocs */

				ch->h_cfgs[i].l_esiz = (int *)realloc(
				    ch->h_cfgs[i].l_esiz,
				    (list_size + slot_inc) * sizeof (int));
			}
			memcpy(ch->h_cfgs[i].l_esiz, ip,
			    list_size * sizeof (int));

			ch->h_cfgs[i].l_nentry = list_size;

			ip += list_size;

		} else

			continue;

		if (ch->h_cfgs[i].l_entry != NULL) {
			p = ch->h_cparse + offset;
#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "mapping list %d size %d offset %d, addr 0x%x\n",
	    i, ch->h_cfgsizes[i], offset, p);
#endif
			memcpy(ch->h_cfgs[i].l_entry,
			    p, ch->h_cfgsizes[i]);
			ch->h_cfgs[i].l_size = ch->h_cfgsizes[i];
			offset += ch->h_cfgsizes[i];
		} else {
#ifdef DEBUG_CFGLIST
			(void) fprintf(stderr, "NULL l_entry\n");
#endif
			return (-1);
		}
	}


	return (1);

}

void
cfg_replace_lists(cfp_t *cfp)
{
	int i;
	int offset = 0;
	int size_offset = 0;

	int section = 0;
	cfgheader_t *cf;
	cfglist_t	*cfl;

	cf = cfp->cf_head;

	if ((cfl = cfp->cf_head->h_cfgs) == NULL)
		return;

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "cfg_replace_lists\n");
#endif

	if (cf->h_cparse == cf->h_ccopy1)
		section = 1;

	/*
	 * check to see if we are using copy1 or 2,
	 * grow or shrink the size, fix h_cparse reference
	 * in case realloc gave us a funky new address.
	 * put stuff in it.
	 */
	cf->h_ccopy1 = (char *)
	    realloc(cf->h_ccopy1, cf->h_csize * sizeof (char));
	cf->h_ccopy2 = (char *)
	    realloc(cf->h_ccopy2, cf->h_csize * sizeof (char));
	if (section == 1) {
		/* we used copy1 */
		cf->h_cparse = cf->h_ccopy1;
	} else
		cf->h_cparse = cf->h_ccopy2;

	/*
	 * just because, we'll zero out h_csize and recalc
	 * after all, this is the number the next guy gets
	 */
	cf->h_csize = cf->h_sizes[0] = 0;
	for (i = 0; i < MAX_CFG; i++) {
		/* only as many lists as chead has */
		if (chead[i].tag.l_word[0] == '\0') {
			break;
		}
		if (cfl[i].l_entry && cfl[i].l_entry[0] != '\0') {
#ifdef DEBUG_CFGLIST
			(void) fprintf(stderr,
			    "copying list %d at %x size %d\n",
			    i, cf->h_cparse + offset,
			    cfl[i].l_size);
#endif
			memcpy((cf->h_cparse + offset),
			    cfl[i].l_entry, cfl[i].l_size);
			offset += cfl[i].l_size;
#ifdef DEBUG_CFGLIST
			(void) fprintf(stderr,
			    "cfl[%d].l_nentry %d cfl[%d].l_esiz[%d] %d"
			    " size offset %d\n",
			    i, cfl[i].l_nentry, i, cfl[i].l_nentry - 1,
			    cfl[i].l_esiz[cfl[i].l_nentry - 1], size_offset);
#endif
			/*
			 * first write the number of entries
			 * then copy over the array ie.
			 * a list with 5 elements would be copied
			 * as a 6 element array slot 0 being the
			 * number of elements
			 */
			cf->h_sizes[size_offset++] = cfl[i].l_nentry;
			memcpy((cf->h_sizes + size_offset), cfl[i].l_esiz,
			    cfl[i].l_nentry * sizeof (int));
			size_offset += cfl[i].l_nentry;
			cf->h_sizes[size_offset] = 0;
		}
		cf->h_csize += cfl[i].l_size;
	}
}

void
cfg_free_cfglist(cfp_t *cfp)
{
	int i;

	if (!cfp->cf_head || !cfp->cf_head->h_cfgs)
		return;

	for (i = 0; cfp->cf_head && i < MAX_CFG; i++) {
		if (cfp->cf_head->h_cfgs[i].l_entry) {
			free(cfp->cf_head->h_cfgs[i].l_entry);
			cfp->cf_head->h_cfgs[i].l_entry = NULL;
		}

		if (cfp->cf_head->h_cfgs[i].l_name) {
			free(cfp->cf_head->h_cfgs[i].l_name);
			cfp->cf_head->h_cfgs[i].l_entry = NULL;
		}

		if (cfp->cf_head->h_cfgs[i].l_esiz) {
			free(cfp->cf_head->h_cfgs[i].l_esiz);
			cfp->cf_head->h_cfgs[i].l_esiz = NULL;
		}
	}

	if (cfp->cf_head) {
		free(cfp->cf_head->h_cfgs);
		cfp->cf_head->h_cfgs = NULL;
	}
}

void
cfg_free_parser_tree()
{
	struct lookup *p = NULL;
	struct lookup *q = NULL;
	int i;

	for (i = 0; i < MAX_CFG; i++) {
		if (chead)
			p = chead[i].fld;
		while (p) {
			q = p->l_next;
			if (p) {
				free(p);
				p = NULL;
			}
			p = q;
		}
	}
	bzero(chead, MAX_CFG * sizeof (struct parser));
}

void
cfg_close(CFGFILE *cfg)
{
	cfp_t *cfp;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return;
	}

	/* Determine number of files open */
	for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
		if (!cfp->cf_fd) continue;

		(*cfp->cf_pp->close)(cfp);
#ifdef DEBUG_CFGLIST
		(void) fprintf(stderr, "freeing cfglists\n");
#endif
		cfg_free_cfglist(cfp);

#ifdef DEBUG_CFGLIST
		(void) fprintf(stderr, "freeing cfp->cf_mapped\n");
#endif
		free(cfp->cf_mapped);
		cfp->cf_mapped = NULL;

#ifdef DEBUG_CFGLIST
		(void) fprintf(stderr,
		    "freeing copy1, copy2, h_sizes and cf\n");
#endif
		if (cfp->cf_head) {
			if (cfp->cf_head->h_ccopy1) {
				free(cfp->cf_head->h_ccopy1);
				cfp->cf_head->h_ccopy1 = NULL;
			}
			if (cfp->cf_head->h_ccopy2) {
				free(cfp->cf_head->h_ccopy2);
				cfp->cf_head->h_ccopy2 = NULL;
			}
			if (cfp->cf_head->h_sizes1) {
				free(cfp->cf_head->h_sizes1);
				cfp->cf_head->h_sizes1 = NULL;
			}
			if (cfp->cf_head->h_sizes2) {
				free(cfp->cf_head->h_sizes2);
				cfp->cf_head->h_sizes2 = NULL;
			}

		}
		if (cfp->cf_head)
			free(cfp->cf_head);
	}

	free(cfg);
	cfg = NULL;
	cfg_free_parser_tree();

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "cfg_close\n");
#endif
}


char *
cfg_get_resource(CFGFILE *cfg)
{
	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (NULL);
	}

	return (cfg->cf_node);
}

/*
 * cfg_resource
 * set or clear the cluster node filter for get/put
 */

void
cfg_resource(CFGFILE *cfg, const char *node)
{
	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return;
	}

	if (cfg->cf_node) {
#ifdef DEBUG_CFGLIST
		(void) fprintf(stderr,
		    "cfg_resource: changing node from %s to %s\n",
		    cfg->cf_node, (node?node:"NULL"));
#endif
		free(cfg->cf_node);
		cfg->cf_node = NULL;
	}

	/*
	 * just in case someone passes in a non-NULL
	 * node, but has no valid value
	 */
	if ((node) && (node[0] != '\0')) {
		cfg->cf_node = strdup(node);
	}
}

/*
 * cfg_open
 * Open the current configuration file
 */
CFGFILE *
cfg_open(char *name)
{
	CFGFILE *cfg;
	cfp_t *cfp;
	int32_t magic;
	long needed;
	int rc;

#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "cfg_open\n");
#endif

	cfg_severity = 0;
	if ((cfg = (CFGFILE *)calloc(1, sizeof (*cfg))) == NULL) {
		cfg_perror_str = dgettext("cfg",
		    "cfg_open: malloc failed");
		cfg_severity = CFG_EFATAL;
		return (NULL);
	}

	cfp = &cfg->cf[0];
	if ((name) && strlen(name)) {
#ifdef DEBUG
		(void) fprintf(stderr, "cfg_open: Using non-standard name\n");
#endif
		cfp->cf_name = name;
		cfp->cf_pp = (strstr(cfp->cf_name, "/rdsk/") == NULL) ?
		    cfg_block_io_provider() : cfg_raw_io_provider();
	} else {
		cfp->cf_name = cfg_location(NULL, CFG_LOC_GET_LOCAL, NULL);
		cfp->cf_pp = cfg_block_io_provider();

		/* Handle cfg_open(""), which is an open from boot tools */
		if (name)
			cl_initialized = 1;
		if (cfg_iscluster() > 0) {
			cfp = &cfg->cf[1];
			cfp->cf_name =
			    cfg_location(NULL, CFG_LOC_GET_CLUSTER, NULL);
			if (cfp->cf_name) {
				cfp->cf_pp = cfg_raw_io_provider();
			}
		}
	}

	/*
	 * Open one or two configuration files
	 */
	for (cfp = &cfg->cf[0]; cfp->cf_name && (cfp <= &cfg->cf[1]); cfp++) {
		if ((*cfp->cf_pp->open)(cfp, cfp->cf_name) == NULL) {
			cfg_perror_str = dgettext("cfg",
			    "cfg_open: unable to open configuration location");
			cfg_severity = CFG_EFATAL;
			break;
		}

		/* block device smaller than repository? */
		rc = (*cfp->cf_pp->read)(cfp, &magic, sizeof (magic));
		if (rc < sizeof (magic)) {
			cfg_perror_str = dgettext("cfg",
			    "cfg_open: unable to read configuration header");
			cfg_severity = CFG_EFATAL;
			break;
		}

		if ((*cfp->cf_pp->seek)(cfp, 0, SEEK_SET) < 0) {
			cfg_perror_str = dgettext("cfg",
			    "cfg_open: unable to seek configuration header");
			cfg_severity = CFG_EFATAL;
			break;
		}

		/*
		 * we can't enforce size rules on an old database
		 * so check the magic number before we test for size
		 */
		if (magic == CFG_NEW_MAGIC) {
			needed = FBA_NUM(FBA_SIZE(1) - 1 +
			    (sizeof (struct cfgheader) + CFG_CONFIG_SIZE));
		} else {
			needed = 0;
		}

		if (cfp->cf_size < needed) {
			cfg_perror_str = dgettext("cfg",
			    "cfg_open: configuration file too small");
			cfg_severity = CFG_EFATAL;
			errno = ENOMEM;
			break;
		}

		cfp->cf_mapped = (char *)malloc(CFG_DEFAULT_PARSE_SIZE);
		if (cfp->cf_mapped == NULL) {
			cfg_perror_str = dgettext("cfg",
			    "cfg_open: malloc failed");
			cfg_severity = CFG_EFATAL;
			break;
		}

		bzero(cfp->cf_mapped, CFG_DEFAULT_PARSE_SIZE);
		cfp->cf_lock = -1;
	}

	/* Processing errors, take care of one or more cfp pointers */
	if (cfg_severity && (cfp <= &cfg->cf[1])) {
		cfp = &cfg->cf[0];
		if (cfp->cf_fd)
			(*cfp->cf_pp->close)(cfp);
		cfp = &cfg->cf[1];
		if (cfp->cf_fd)
			(*cfp->cf_pp->close)(cfp);
		free(cfg);
		return (NULL);
	}

	cfg_lockd = cfg_lockd_init();


#ifdef DEBUG_CFGLIST
	(void) fprintf(stderr, "cfg_open ok\n");
#endif
	return (cfg);
}

void
cfg_invalidate_hsizes(int fd, const char *loc)
{
	int offset;
	int rc = -1;
	int hdrsz;

	char buf[2 * CFG_DEFAULT_PSIZE];

	hdrsz = sizeof (cfgheader_t) + 512 -
	    (sizeof (cfgheader_t) % 512);

	offset = hdrsz + CFG_DEFAULT_PARSE_SIZE +
	    (CFG_DEFAULT_SSIZE * 2);

	if (cfg_shldskip_vtoc(fd, loc) > 0)
		offset += CFG_VTOC_SKIP;

	bzero(buf, sizeof (buf));

	if (lseek(fd, offset, SEEK_SET) > 0)
		rc = write(fd, buf, sizeof (buf));
	if (rc < 0)
		(void) fprintf(stderr, "cfg: invalidate hsizes failed\n");

}

char *
cfg_error(int *severity)
{
	if (severity != NULL)
		*severity = cfg_severity;
	return (cfg_perror_str ? cfg_perror_str : CFG_EGENERIC);
}
/*
 * cfg_cfg_isempty
 */
int
cfg_cfg_isempty(CFGFILE *cfg)
{
	cfp_t *cfp;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (FALSE);
	}

	cfp = FP_SUN_CLUSTER(cfg);
	if (cfp->cf_head->h_csize == 0)
		return (TRUE);
	else
		return (FALSE);
}

/*
 * cfg_get_num_entries
 * return the number of entries in a given section of database
 * sndr, ii, ndr_ii...
 */
int
cfg_get_num_entries(CFGFILE *cfg, char *section)
{
	int count = 0;
	int table_offset;
	cfp_t *cfp;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	if ((table_offset = cfg_get_parser_offset(section)) < 0) {
		errno = ESRCH;
		return (-1);
	}

	/* Determine number of files open */
	for (cfp = &cfg->cf[0]; cfp->cf_fd && (cfp <= &cfg->cf[1]); cfp++)
		count += cfp->cf_head->h_cfgs[table_offset].l_nentry;

	return (count);
}

/*
 * cfg_get_section
 * all etries in a config file section is placed in
 * buf, allocation is done inside
 * freeing buf is responisbility of the caller
 * number of entries in section is returned
 * -1 on failure, errno is set
 */
int
cfg_get_section(CFGFILE *cfg, char ***list, const char *section)
{
	int table_offset;
	int i, count;
	cfglist_t *cfl;
	char *p = NULL;
	char **buf;
	cfp_t *cfp;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (FALSE);
	}

	if ((table_offset = cfg_get_parser_offset(section)) < 0) {
		errno = ESRCH;
		return (-1);
	}

	/* Determine number of files open */
	count = 0;
	for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
		if (!cfp->cf_fd) continue;
		if (cfp->cf_head->h_state & CFG_HDR_INVALID) {
			if (!cfg_read(cfp)) {
				cfg_perror_str = dgettext("cfg", CFG_RDFAILED);
				cfg_severity = CFG_EFATAL;
				return (-1);
			}
		}

		cfl = &cfp->cf_head->h_cfgs[table_offset];
		if (cfl->l_nentry == 0) /* empty list */
			continue;

		if (count == 0)
			buf = (char **)malloc(cfl->l_nentry * sizeof (char *));
		else
			buf = (char **)realloc(buf, (cfl->l_nentry + count) *
			    sizeof (char *));
		if (buf == NULL) {
			errno = ENOMEM;
			return (-1);
		} else {
			bzero(&buf[count], cfl->l_nentry * sizeof (char *));
		}

		p = cfl->l_entry;
		for (i = 0; i < cfl->l_nentry; i++) {
			if ((buf[i + count] = strdup(p)) == NULL) {
				errno = ENOMEM;
				return (-1);
			}
			p += cfl->l_esiz[i];
		}
		count +=  cfl->l_nentry;
	}

	*list = buf;
	return (count);
}

/*
 * cluster upgrade helper functions. These support old database operations
 * while upgrading nodes on a cluster.
 */

/*
 * returns the list of configured tags
 * return -1 on error, else the number
 * of tags returned in taglist
 * caller frees
 */
int
cfg_get_tags(CFGFILE *cfg, char ***taglist)
{
	char **list;
	int i = 0;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	if (!cfg_rdlock(cfg)) {
		return (-1);
	}
	list = calloc(1, MAX_CFG * sizeof (char *));
	if (list == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	while ((i < MAX_CFG) && (chead[i].tag.l_word[0] != '\0')) {
		list[i] = strdup(chead[i].tag.l_word);
		if (list[i] == NULL) {
			for (/* CSTYLE */; i >= 0; i--) {
				if (list[i])
					free(list[i]);
			}
			free(list);
			errno = ENOMEM;
			return (-1);
		}
		i++;
	}
	*taglist = list;
	return (i);

}

/*
 * is this a database?
 * check the header for the magic number
 * 0 no match 1 match, -1 on error
 */
int
cfg_is_cfg(CFGFILE *cfg)
{
	int32_t magic;
	int rc;
	cfp_t *cfp = FP_SUN_CLUSTER(cfg);

	rc = (cfp->cf_pp->read)(cfp, &magic, sizeof (magic));
	if (rc < sizeof (magic)) {
		cfg_perror_str = dgettext("cfg", "Fail to read configuration");
		cfg_severity = CFG_EFATAL;
		return (-1);
	}

	if (magic == CFG_NEW_MAGIC)
		return (1);

	cfg_perror_str = dgettext("cfg",
	    "configuration not initialized, bad magic");
	cfg_severity = CFG_EFATAL;

	return (0);
}

int
compare(const void* a, const void *b)
{
	char *p;
	char *pbuf;
	char *q;
	char *qbuf;
	int needed;
	int cmp;
	int pos;

	pbuf = strdup(a);
	qbuf = strdup(b);

	if (!qbuf || !pbuf)
		return (0);

	pos = 1;
	needed = sortby.offset;

	p = strtok(pbuf, " ");
	while (p) {
		if (needed == pos) {
			break;
		}
		p = strtok(NULL, " ");
		if (!p)
			break;
		pos++;
	}

	pos = 1;
	q = strtok(qbuf, " ");
	while (q) {
		if (needed == pos) {
			break;
		}
		q = strtok(NULL, " ");
		if (!q)
			break;
		pos++;
	}
	if (!p || !q) {
		sortby.comperror++;
		free(pbuf);
		free(qbuf);
		return (0);
	}
	cmp = strcmp(p, q);
	free(pbuf);
	free(qbuf);
	return (cmp);


}
/*
 * cfg_get_srtdsec
 * returns the section, sorted by supplied field
 * caller frees mem
 */
int
cfg_get_srtdsec(CFGFILE *cfg, char ***list, const char *section,
    const char *field)
{
	cfglist_t *cfl;
	cfp_t *cfp;
	char **buf;
	char *tmplst;
	char *p, *q;
	int table_offset;
	int count, i;

	if (cfg == NULL) {
		cfg_perror_str = dgettext("cfg", CFG_EINVAL);
		cfg_severity = CFG_EFATAL;
		return (FALSE);
	}

	if ((table_offset = cfg_get_parser_offset(section)) < 0) {
		cfg_perror_str = dgettext("cfg", CFG_RDFAILED);
		errno = ESRCH;
		return (-1);
	}

	/*
	 * do essentially what get_section does,
	 * except stick entries in a static size
	 * buf to make things easier to qsort
	 */
	count = 0;
	for (cfp = &cfg->cf[0]; cfp <= &cfg->cf[1]; cfp++) {
		if (!cfp->cf_fd) continue;
		if (cfp->cf_head->h_state & CFG_HDR_INVALID) {
			if (!cfg_read(cfp)) {
				cfg_perror_str = dgettext("cfg", CFG_RDFAILED);
				cfg_severity = CFG_EFATAL;
				return (-1);
			}
		}

		cfl = &cfp->cf_head->h_cfgs[table_offset];
		if (cfl->l_nentry == 0) /* empty list */
			continue;

		if (count == 0)
			buf = (char **)malloc(cfl->l_nentry * sizeof (char *));
		else
			buf = (char **)realloc(buf, (cfl->l_nentry + count) *
			    sizeof (char *));
		if (buf == NULL) {
			errno = ENOMEM;
			cfg_perror_str = dgettext("cfg", "cfg_get_srtdsec: "
			    "malloc failed");
			cfg_severity = CFG_EFATAL;
			return (-1);
		} else {
			bzero(&buf[count], cfl->l_nentry * sizeof (char *));
		}

		/*
		 * allocate each line
		 */
		for (i = count; i < cfl->l_nentry + count; i++) {
			buf[i] = calloc(1, CFG_MAX_BUF);
			if (buf[i] == NULL) {
				free(buf);
				errno = ENOMEM;
				return (-1);
			}
		}

		if (count == 0)
			tmplst = (char *)malloc(cfl->l_nentry * CFG_MAX_BUF);
		else
			tmplst = (char *)realloc(tmplst,
			    (cfl->l_nentry + count) * CFG_MAX_BUF);
		if (tmplst == NULL) {
			cfg_perror_str = dgettext("cfg", "cfg_get_srtdsec: "
			    "malloc failed");
			cfg_severity = CFG_EFATAL;
			free(buf);
			return (-1);
		} else {
			bzero(&tmplst[count], cfl->l_nentry * CFG_MAX_BUF);
		}

		/*
		 * put the section in tmplst and sort
		 */
		p = &tmplst[count];
		q = cfl->l_entry;
		for (i = 0; i < cfl->l_nentry; i++) {
			bcopy(q, p, cfl->l_esiz[i]);
			p += CFG_MAX_BUF;
			q += cfl->l_esiz[i];
		}
		count += cfl->l_nentry;
	}

	bzero(sortby.section, CFG_MAX_KEY);
	bzero(sortby.field, CFG_MAX_KEY);

	strcpy(sortby.section, section);
	strcpy(sortby.field, field);
	sortby.comperror = 0;
	sortby.offset = cfg_get_item(&chead[0], section, field);

	qsort(tmplst, count, CFG_MAX_BUF, compare);

	if (sortby.comperror) {
		sortby.comperror = 0;
		cfg_perror_str = dgettext("cfg", "cfg_get_srtdsec: "
		    "comparison error");
		cfg_severity = CFG_ENONFATAL;
		cfg_free_section(&buf, cfl->l_nentry);
		free(tmplst);
		*list = NULL;
		return (-1);
	}

	p = tmplst;
	for (i = 0; i < count; i++) {
		bcopy(p, buf[i], CFG_MAX_BUF);
		p +=  CFG_MAX_BUF;
	}

	free(tmplst);
	*list = buf;
	return (count);
}

/*
 * free an array alloc'd by get_*section
 * or some other array of size size
 */

void
cfg_free_section(char ***section, int size)
{
	int i;
	char **secpp = *section;

	for (i = 0; i < size; i++) {
		if (secpp[i]) {
			free(secpp[i]);
			secpp[i] = NULL;
		}
	}
	if (secpp) {
		free(secpp);
		secpp = NULL;
	}
	section = NULL;
}


int
cfg_shldskip_vtoc(int fd, const char *loc)
{
	struct vtoc vtoc;
	struct stat sb;
	int slice;
	int rfd;
	char char_name[PATH_MAX];
	char *p;

	if (fstat(fd, &sb) == -1) {
		cfg_perror_str = dgettext("cfg", "unable to stat config");
		cfg_severity = CFG_EFATAL;
		return (-1);
	}
	if (S_ISREG(sb.st_mode))
		return (0);

	if (S_ISCHR(sb.st_mode)) {
		if ((slice = read_vtoc(fd, &vtoc)) < 0)
			return (-1);

		if (vtoc.v_part[slice].p_start < CFG_VTOC_SIZE)
			return (1);
		else
			return (0);
	}

	if (S_ISBLK(sb.st_mode)) {
		p = strstr(loc, "/dsk/");
		if (p == NULL)
			return (-1);
		strcpy(char_name, loc);
		char_name[strlen(loc) - strlen(p)] = 0;
		strcat(char_name, "/rdsk/");
		strcat(char_name, p + 5);

		if ((rfd = open(char_name, O_RDONLY)) < 0) {
			return (-1);
		}
		if ((slice = read_vtoc(rfd, &vtoc)) < 0) {
			close(rfd);
			return (-1);
		}
		close(rfd);
		if (vtoc.v_part[slice].p_start < CFG_VTOC_SIZE)
			return (1);
		else
			return (0);
	}

	return (-1);
}

/*
 * comapares incore header with one on disk
 * returns 0 if equal, 1 if not,  -1 error
 */
int
cfg_hdrcmp(cfp_t *cfp)
{
	cfgheader_t *dskhdr, *memhdr;
	int rc;

	if ((dskhdr = calloc(1, sizeof (*dskhdr))) == NULL) {
		cfg_perror_str = dgettext("cfg", "cfg_hdrcmp: No memory");
		cfg_severity = CFG_ENONFATAL;
	}

	if ((*cfp->cf_pp->seek)(cfp, 0, SEEK_SET) < 0) {
		cfg_perror_str = dgettext("cfg", "cfg_hdrcmp: seek failed");
		cfg_severity = CFG_ENONFATAL;
		free(dskhdr);
		return (-1);
	}

	rc = (*cfp->cf_pp->read)(cfp, (char *)dskhdr, sizeof (*dskhdr));
	if (rc < 0) {
		cfg_perror_str = dgettext("cfg", "cfg_hdrcmp: read failed");
		cfg_severity = CFG_ENONFATAL;
		free(dskhdr);
		return (-1);
	}

	memhdr = cfp->cf_head;

	if ((memhdr->h_seq1 == dskhdr->h_seq1) &&
	    (memhdr->h_seq2 == dskhdr->h_seq2))
		rc = 0;
	else
		rc = 1;


	free(dskhdr);
	return (rc);
}
