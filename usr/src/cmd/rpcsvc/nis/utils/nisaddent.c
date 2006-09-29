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

/*
 * nisaddent.c
 *
 * utility to add/merge /etc files and YP dbm files into nis+ tables
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <ndbm.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>
#include <rpcsvc/nis_dhext.h>
#include <pwd.h>
#include <auth_attr.h>
#include <exec_attr.h>
#include <prof_attr.h>
#include <user_attr.h>
#undef GROUP
#undef opaque
#include <bsm/libbsm.h>
#include <nss_dbdefs.h>

#define	NIS_ALL_ACC (NIS_READ_ACC|NIS_MODIFY_ACC|NIS_CREATE_ACC|NIS_DESTROY_ACC)
#define	NIS_WORLD_MASK(a)	(a)
#define	NIS_GROUP_MASK(a)	(a << 8)
#define	NIS_OWNER_MASK(a)	(a << 16)
#define	NIS_NOBODY_MASK(a)	(a << 24)

/* same as in nis_util.c (we really need a .h) */
#define	NIS_SRC_DEFAULT 0
#define	NIS_SRC_ENV 1
#define	NIS_SRC_ARG 2

#define	BIGBUF 8192


extern int 	optind;
extern char	*optarg;

extern nis_object nis_default_obj;
extern int nis_default_access_src;

extern char *__nis_quote_key(const char *, char *, int);
extern char *strpbrk_quotes(char *, char *);
extern char *strtok_quotes(char *, char *);
extern char *strchr_quotes(char *, char);

extern char *_strtok_escape(char *, char *, char **); /* from libnsl */

/*
 *  Temporary files used by merge_file.  The 'created' variables
 *  record whether or not we created the file.  An exit routine
 *  will unlink the files if they were created.
 */
char tmpdirbuf[MAXPATHLEN];
char tmppagbuf[MAXPATHLEN];
int created_dir;
int created_pag;

struct file_loc {
	off_t offset;
	size_t size;
};

struct line_buf {
	char *str;
	int len;
	int alloc;
};


struct ttypelist_t {
	char *ttype;		/* type tag */
	char *ypmap;		/* nis map to use */
	char *nistbl;		/* nis+ table to use */
	char *ta_type;		/* nis+ table type */
	char *clrsrch;		/* nis+ search critera to clear table */
	int niskeycol;		/* nis+ key column */
	int filekeycol;		/* file key column */
	char *filesep;		/* chars marking columns in files */
	char *(*dbmniskey)();	/* routine to turn dbm key into nis key */
	datum (*nisdbmkey)();	/* routine to turn nis entry into dbm key */
	datum (*filedbmkey)();	/* routine to turn file line into dbm key */
	int (*genent)();	/* routine to turn line into nis+ entries */
	void (*dump)();		/* routine to print nis+ table */
	nis_result *(*dump_match)();    /* routine to match entries */
	int (*filedbmline)();	/* routine to turn file line into dbm line */
	void (*filetodbm)();	/* routine to convert to dbm key/content */
	char *(*fetchdbm)();	/* routine to fetch a nis map line */
	void (*printfkeystr)();	/* routine to print keystr for -v */
} *tt;

char *nisdomain;
mechanism_t **mechs;		/* A list of mechs */

char ta_name[NIS_MAXNAMELEN];
char ta_type[BUFSIZ];
nis_object *ta_obj;

FILE *etcf = 0;
DBM *dbmf = 0;

#define	OP_ADD 0
#define	OP_REPLACE 1
#define	OP_MERGE 2
#define	OP_DUMP 3

#define	F_VERBOSE 0x1
#define	F_PASSWD  0x2
#define	F_QUICK   0x4

int exit_val = 0;

unsigned flags = 0;
int oldpubkeymode = 0;

unsigned nent_add = 0;
unsigned nent_del = 0;

ulong_t fpath = 0, allres = 0, master = 0;

int user_attr_keycol[USERATTR_DB_NKEYCOL] = {
	USERATTR_KEYCOL0, USERATTR_KEYCOL1
};

int exec_attr_keycol[EXECATTR_DB_NKEYCOL] = {
	EXECATTR_KEYCOL0, EXECATTR_KEYCOL1, EXECATTR_KEYCOL2
};

#define	PARSE_ERR_MSG_LEN 512
static char parse_err_msg [PARSE_ERR_MSG_LEN];

char null_string[] = "";

/* the followings are defined to fix cstyle complain of line too long */
#define	ENTRY_COL(c)		\
    zo_data.objdata_u.en_data.en_cols.en_cols_val[(c)]

#define	OBJ_COL_VAL(i, c)	\
    res->objects.objects_val[(i)].ENTRY_COL(c).ec_value.ec_value_val

/*
 * The following is a version of OBJ_COL_VALUE that returns a pointer
 * to an empty string, rather than a NULL pointer, if the entry does not
 * exist. Involves two derefs but this only a cmd line app so performance
 * should not be an issue. The null string is defined as a constant so a new
 * copy of it is not created for each macro invocation.
 */
char *nullStr = "";
#define	OBJ_COL_VAL_NO_NULL(i, c) \
    OBJ_COL_VAL(i, c) == NULL ? nullStr : OBJ_COL_VAL(i, c)

#define	KEYVAL(c)	\
    entry->ENTRY_COL(c).ec_value.ec_value_val

/* get either key value or, if it is null, an empty string */
#define	NKEYVAL(c) ((KEYVAL(c))?(KEYVAL(c)):"")

#define	OBJ_COL_NAME(c)		\
    ta_obj->zo_data.objdata_u.ta_data.ta_cols.ta_cols_val[(c)].tc_name

void
usage()
{
	fprintf(stderr, "usage:\tnisaddent [-D defaults] [-Parv]");
	fprintf(stderr, " [-t table] type [nisdomain]\n\n");

	fprintf(stderr, "\tnisaddent [-D defaults] [-Parmv] -f file");
	fprintf(stderr, " [-t table] type [nisdomain]\n\n");

	fprintf(stderr, "\tnisaddent [-D defaults] [-Parmv] -y ypdomain");

	fprintf(stderr, " [-Y map] [-t table] type\n\t\t[nisdomain]\n\n");
	fprintf(stderr,
	    "	nisaddent [-AM] -d [-t table] type [nisdomain]\n");
	exit(1);
}

void
line_buf_expand(line)
	struct line_buf *line;
{
	if (line->alloc == 0) {
		line->alloc = BUFSIZ;
		line->str = (char *)malloc(line->alloc);
	} else {
		line->alloc += BUFSIZ;
		line->str = (char *)realloc(line->str, line->alloc);
	}

	if (line->str == 0) {
		fprintf(stderr, "line_buf_expand:  out of memory\n");
		exit(1);
	}
}

void
line_buf_init(line)
	struct line_buf *line;
{
	memset((char *)line, 0, sizeof (*line));
	line_buf_expand(line);
}

void
print2buf(struct line_buf *line, char *toprint)
{
	int toprintlen = 0;

	/* has print buffer line been exhausted */
	if ((toprintlen = strlen(toprint)) + line->len > (line->alloc - 1)) {
		do {
			if (line->alloc == 0) {
				line->alloc = BUFSIZ;
				line->str = (char *)malloc(line->alloc);
			} else {
				line->alloc += BUFSIZ;
				line->str = (char *)realloc(line->str,
				    line->alloc);
			}
			if (line->str == 0) {
				fprintf(stderr, "print2buf:  out of memory\n");
				exit(1);
			}
		} while (toprintlen > line->alloc);
	}
	/* now add new 'toprint' data to buffer */
	strcat(line->str, toprint);
	line->len += toprintlen;
}

void
print2buf_init(struct line_buf *line)
{
	memset((char *)line, 0, sizeof (*line));
	line->str = NULL;
	line->alloc = 0;
	line->len = 0;
	line_buf_expand(line);
}

void
print2buf_destroy(struct line_buf *line)
{
	free(line->str);
	line->str = NULL;
	line->alloc = 0;
	line->len = 0;
}


int
col_equal(tc, ec1, ec2, mod)
	table_col *tc;
	entry_col *ec1;
	entry_col *ec2;
	int mod;
{
	/* ignore unset columns in modified entries */
	if (mod && (ec1->ec_value.ec_value_val == 0))
		return (1);

	if (ec1->ec_value.ec_value_len != ec2->ec_value.ec_value_len)
		return (0);

	if (ec1->ec_value.ec_value_val == 0 ||
	    ec2->ec_value.ec_value_val == 0) {
		if (ec1->ec_value.ec_value_val == 0 &&
		    ec2->ec_value.ec_value_val == 0)
			return (1);
		else
			return (0);
	}

	if (tc->tc_flags & TA_CASE)
		return (strncasecmp(ec1->ec_value.ec_value_val,
				    ec2->ec_value.ec_value_val,
				    ec1->ec_value.ec_value_len) == 0);
	else
		return (strncmp(ec1->ec_value.ec_value_val,
				ec2->ec_value.ec_value_val,
				ec1->ec_value.ec_value_len) == 0);
}

int
entry_equal(e1, e2, mod)
	nis_object *e1;
	nis_object *e2;
	int mod;
{
	int i;
	table_col *tc;
	entry_col *ec1, *ec2;

	for (i = e1->zo_data.objdata_u.en_data.en_cols.en_cols_len,
	    tc = ta_obj->zo_data.objdata_u.ta_data.ta_cols.ta_cols_val,
	    ec1 = e1->zo_data.objdata_u.en_data.en_cols.en_cols_val,
	    ec2 = e2->zo_data.objdata_u.en_data.en_cols.en_cols_val;
	    i > 0;
	    tc++, ec1++, ec2++, i--)
		if (!col_equal(tc, ec1, ec2, mod))
			return (0);

	return (1);
}

int
entry_inresult(e, r, mod)
	nis_object *e;
	nis_result *r;
	int mod;
{
	int i;

	for (i = r->objects.objects_len-1; i >= 0; i--) {
		if (entry_equal(e, &(r->objects.objects_val[i]), mod))
			return (1);
	}

	return (0);
}

int
addentry(table, entry, udata, mod)
	nis_name table;
	nis_object *entry;
	void *udata;
	int mod;
{
	nis_result *ares;

	if (udata && entry_inresult(entry, (nis_result*)udata, mod))
		return (0);

	if (flags & F_VERBOSE)
		(*(tt->printfkeystr))("adding/updating \"%s\"\n", entry);

	if (mod) {
		ares = nis_modify_entry(table, entry, 0);
		if (ares->status == NIS_NOTFOUND)
			ares = nis_add_entry(table, entry, 0);
	} else
		ares = nis_add_entry(table, entry, ADD_OVERWRITE);
	if (ares->status == NIS_SUCCESS)
		nent_add++;
	else {
		if (!(flags & F_VERBOSE))
			(*(tt->printfkeystr))("adding/updating "
			    "\"%s\"\n", entry);
		if (mod)
			nis_perror(ares->status, "can't modify entry");
		else
			nis_perror(ares->status, "can't add entry");
	}
	nis_freeresult(ares);

	return (0);
}

int
matchentry(table, entry, udata, mod)
	nis_name table;
	nis_object *entry;
	void *udata;
	int mod;
{
	datum key, val;

	if (udata && entry_inresult(entry, (nis_result*)udata, mod))
		return (1);

	return (0);
}


int
removeentry(table, entry)
	nis_name table;
	nis_object *entry;
{
	nis_result *rres;

	if (flags & F_VERBOSE)
		(*(tt->printfkeystr))("removing %s\n", entry);

	rres = nis_remove_entry(table, entry, 0);
	if (rres->status == NIS_SUCCESS)
		nent_del++;
	else {
		if (!(flags & F_VERBOSE))
			(*(tt->printfkeystr))("removing \"%s\"\n", entry);
		nis_perror(rres->status, "can't remove entry");
	}
	nis_freeresult(rres);

	return (0);
}


/*
 * return a string of tab characters that when concatenated with the
 * specified string leave the cursor at the beginning of the specified
 * column.  if the string is too long, then return a single space.  the
 * specified column must be less than 10.
 */

char *
tabtocol(str, col)
	char *str;
	int col;
{
	int c, l;
	char *p;

	for (c = l = 0, p = str; *p; p++) {
		if (*p == '\t' || ++l == 8) {
			c++;
			l = 0;
		}
	}

	if (c < col)
		return (&("\t\t\t\t\t\t\t\t\t\t"[10-col+c]));

	return (" ");
}

char *
dbmniskey_publickey(datum key)
{
	static char	buf[NIS_MAXNAMELEN];
	char		netname[MAXNETNAMELEN], *tmp;

	strcpy(netname, key.dptr);
	if (tmp = strchr(netname, ':'))
		*tmp = '\0';

	sprintf(buf, "%s=%.*s", OBJ_COL_NAME(tt->niskeycol),
		strlen(netname), netname);

	return (buf);
}

char *
dbmniskey_attr(datum key)
{
	int		i, numkeycol;
	int		*keycol;
	char		*p, *s;
	static char	buf[NIS_MAXNAMELEN];

	s = key.dptr;
	buf[0] = 0;

	if (strcmp(tt->ttype, NSS_DBNAM_EXECATTR) == 0) {
		numkeycol = EXECATTR_DB_NKEYCOL;
		keycol = exec_attr_keycol;
	} else if (strcmp(tt->ttype, NSS_DBNAM_USERATTR) == 0) {
		numkeycol = USERATTR_DB_NKEYCOL;
		keycol = user_attr_keycol;
	}

	for (i = 0; i < numkeycol; i++) {
		p = strpbrk(s, tt->filesep);
		if (p == NULL) {
			(void) snprintf(buf, NIS_MAXNAMELEN, "%s%s=%.*s", buf,
			    OBJ_COL_NAME(keycol[i]), key.dsize, s);
			break;
		}
		(void) snprintf(buf, NIS_MAXNAMELEN, "%s%s=%.*s%s", buf,
		    OBJ_COL_NAME(keycol[i]), (p - s), s, tt->filesep);
		s = ++p;
	}
	if (p = strrchr(buf, ':'))
		*p = 0;

	return (buf);
}

char *
dbmniskey(key)
	datum key;
{
	static char buf[NIS_MAXNAMELEN];

	sprintf(buf, "%s=%.*s", OBJ_COL_NAME(tt->niskeycol),
		key.dsize, key.dptr);

	return (buf);
}

datum
nisdbmkey(entry)
	nis_object *entry;
{
	static char buf[BUFSIZ+1];
	datum key;

	strcpy(buf, NKEYVAL(tt->niskeycol));

	key.dptr = buf;
	key.dsize = strlen(buf);

	return (key);
}

datum
nisdbmkey_attr(nis_object *entry)
{
	int		i;
	int		numkeycol;
	int		*keycol;
	char		*p, *s;
	datum		key;
	static char	buf[BUFSIZ+1];

	buf[0] = 0;

	if (strcmp(tt->ttype, NSS_DBNAM_EXECATTR) == 0) {
		numkeycol = EXECATTR_DB_NKEYCOL;
		keycol = exec_attr_keycol;
	} else if (strcmp(tt->ttype, NSS_DBNAM_USERATTR) == 0) {
		numkeycol = USERATTR_DB_NKEYCOL;
		keycol = user_attr_keycol;
	}

	for (i = 0; i < numkeycol; i++) {
		s = NKEYVAL(keycol[i]);
		if ((s == NULL) || (strcmp(s, "") == 0))
			continue;
		(void) snprintf(buf, BUFSIZ, "%s%s%s", buf, s, tt->filesep);
	}
	if (p = strrchr(buf, ':'))
		*p = 0;

	key.dptr = buf;
	key.dsize = strlen(buf);

	return (key);
}

datum
nisdbmkey_publickey(entry)
	nis_object *entry;
{
	static char buf[BUFSIZ+1];
	datum key;

	if (mechs) {
		char		mechalias[MECH_MAXALIASNAME], keylen[256];
		keylen_t	bitlen;
		algtype_t	algtype;

		if (!__nis_authtype2mechalias(NKEYVAL(1), mechalias,
						MECH_MAXALIASNAME))
			goto nomechs;

		if (__nis_translate_mechanism(mechalias, &bitlen,
						&algtype) < 0)
			goto nomechs;

		if (bitlen == 192)
			strcpy(keylen, "DES");
		else
			snprintf(keylen, 256, "%d", bitlen);
		snprintf(buf, BUFSIZ, "%s:%s:%d", NKEYVAL(2), keylen, algtype);
	} else {
nomechs:
		strcpy(buf, NKEYVAL(2));
	}
	key.dptr = buf;
	key.dsize = strlen(buf);

	return (key);
}

datum
filedbmkey_attr(char *line)
{
	int		i, j, skip;
	int		numkeycol;
	int		*keycol;
	char		*p = NULL;
	char		*q = NULL;
	char		*s = NULL;
	static char	buf[BUFSIZ+1];
	datum		key;

	s = line;
	buf[0] = 0;

	if (strcmp(tt->ttype, NSS_DBNAM_EXECATTR) == 0) {
		numkeycol = EXECATTR_DB_NKEYCOL;
		keycol = exec_attr_keycol;
	} else if (strcmp(tt->ttype, NSS_DBNAM_USERATTR) == 0) {
		numkeycol = USERATTR_DB_NKEYCOL;
		keycol = user_attr_keycol;
	}

	for (i = 0; i < numkeycol; i++) {
		for (j = keycol[i]; j >= 0; j--) {
			p = strpbrk(s, tt->filesep);
			if (j > 0) {
				if (p == NULL) {
					key.dptr = 0;
					key.dsize = 0;
					return (key);
				}
				skip = strspn(p, tt->filesep);
				if (skip > 1) {
					if ((j = j - skip) <= 0)
						j = 1;
				}
				s = p + skip;
			}
		}
		if (p) {
			sprintf(buf, "%s%.*s:", buf, (p - s), s);
		} else {
			if (buf[0] == 0)
				strcpy(buf, s);
			break;
		}
	}

	if (q = strrchr(buf, ':'))
		*q = 0;

	key.dptr = buf;
	key.dsize = strlen(buf);

	return (key);
}

datum
filedbmkey_publickey(line)
	char *line;
{
	static char buf[BUFSIZ+1];
	int i;
	char *p;
	datum key;


	if (mechs) {
		char		netname[MAXNETNAMELEN], keys[8704];
		char		keylen[256];
		char		*pubkey, *privkey, *algtype;
		int		bitlen = 0;

		sscanf(line, "%s %s", netname, keys);

		pubkey = keys;
		/*
		 * We don't use the private key, but we need to get to
		 * the algtype
		 */
		if (privkey = strchr(keys, ':')) {
			*privkey++ = '\0';
			/* Get rid of extra :'s */
			if (*privkey == ':')
				privkey++;
		}
		if (algtype = strchr(privkey, ':'))
			*algtype++ = '\0';
		else
			algtype = "0";

		bitlen = (strlen(pubkey) / 2) * 8;
		if (bitlen == 192)
			strcpy(keylen, "DES");
		else
			snprintf(keylen, 256, "%d", bitlen);

		snprintf(buf, BUFSIZ, "%s:%s:%s", netname, keylen, algtype);
	} else {
		for (i = tt->filekeycol; i >= 0; i--) {
			p = strpbrk(line, tt->filesep);
			if (i > 0) {
				if (p == 0) {
					key.dptr = 0;
					key.dsize = 0;
					return (key);
				}
				line = p + strspn(p, tt->filesep);
			}
		}

		if (p)
			sprintf(buf, "%.*s", p-line, line);
		else
			strcpy(buf, line);
	}

	key.dptr = buf;
	key.dsize = strlen(buf);

	return (key);
}

/*
 * Note that most of the filedbmkey() code is duplicated in
 * filedbmkey_netid() below.
 */
datum
filedbmkey(line)
	char *line;
{
	static char buf[BUFSIZ+1];
	int i;
	char *p;
	datum key;

	for (i = tt->filekeycol; i >= 0; i--) {
		p = strpbrk(line, tt->filesep);
		if (i > 0) {
			if (p == 0) {
				key.dptr = 0;
				key.dsize = 0;
				return (key);
			}
			line = p + strspn(p, tt->filesep);
		}
	}

	if (p)
		sprintf(buf, "%.*s", p-line, line);
	else
		strcpy(buf, line);

	key.dptr = buf;
	key.dsize = strlen(buf);

	return (key);
}

/*
 * filedbmkey_netid() duplicates filedbmkey() above, but also
 * removes trailing dots.
 */
datum
filedbmkey_netid(line)
	char *line;
{
	static char buf[BUFSIZ+1];
	int i;
	char *p;
	datum key;

	for (i = tt->filekeycol; i >= 0; i--) {
		p = strpbrk(line, tt->filesep);
		if (i > 0) {
			if (p == 0) {
				key.dptr = 0;
				key.dsize = 0;
				return (key);
			}
			line = p + strspn(p, tt->filesep);
		}
	}

	if (p)
		sprintf(buf, "%.*s", p-line, line);
	else
		strcpy(buf, line);

	key.dptr = buf;
	key.dsize = strlen(buf);

	/* Strip any trailing dot from key */
	if (key.dsize > 0 && buf[key.dsize-1] == '.') {
		buf[key.dsize-1] = '\0';
		key.dsize--;
	}

	return (key);
}

int
blankline(line)
	char *line;
{
	char *p;

	for (p = line; *p; p++)
		if (*p != ' ' && *p != '\t')
			return (0);
	return (1);
}

/*
 *  Read a line into a line_buf starting at offset 'n'.  We expand the
 *  line_buf when needed.  We read until '\n' or EOF.  If we don't read
 *  any characters before EOF we return 0.  Otherwise, we return a pointer
 *  to the string read.
 */

char *
fget_line_at(line, n, fp)
	struct line_buf *line;
	int n;
	FILE *fp;
{
	int c;

	line->len = n;
	while (1) {
		c = fgetc(fp);
		if (c == -1)
			break;
		if (line->len >= line->alloc)
			line_buf_expand(line);
		line->str[line->len++] = c;
		if (c == '\n')
			break;
	}

	/* null terminate */
	if (line->len >= line->alloc)
		line_buf_expand(line);
	line->str[line->len++] = 0;

	/* if we read no characters, return NULL to indicate EOF */
	if (line->str[0] == '\0')
		return (0);

	return (line->str);
}


int
filedbmline(line, etcf, lineno, loc)
	struct line_buf *line;
	FILE *etcf;
	int *lineno;
	struct file_loc *loc;
{
	int len = 0;

	loc->offset = ftell(etcf);
	while (1) {
		if (fget_line_at(line, len, etcf) == 0)
			return (0);

		if (lineno)
			(*lineno)++;

		len = strlen(line->str);
		if (line->str[len-1] == '\n') {
			line->str[len-1] = 0;
			len -= 1;
		}

		if (!blankline(line->str))
			break;

		len = 0;
		loc->offset = ftell(etcf);
	}

	loc->size = len;
	return (1);
}

int
filedbmline_comment(line, etcf, lineno, loc)
	struct line_buf *line;
	FILE *etcf;
	int *lineno;
	struct file_loc *loc;
{
	int len = 0;

	loc->offset = ftell(etcf);
	while (1) {
		if (fget_line_at(line, len, etcf) == 0)
			return (0);

		if (lineno)
			(*lineno)++;

		len = strlen(line->str);
		if (len >= 2 &&
		    line->str[0] != '#' &&
		    line->str[len-2] == '\\' && line->str[len-1] == '\n') {
			line->str[len-2] = 0;
			len -= 2;
			continue;    /* append next line at end */
		}

		if (line->str[len-1] == '\n') {
			line->str[len-1] = 0;
			len -= 1;
		}

		if (!blankline(line->str) && line->str[0] != '#')
			break;

		len = 0;
		loc->offset = ftell(etcf);
	}

	loc->size = len;
	return (1);
}

int
filedbmline_plus(line, etcf, lineno, loc)
	struct line_buf *line;
	FILE *etcf;
	int *lineno;
	struct file_loc *loc;
{
	int len = 0;

	loc->offset = ftell(etcf);
	while (1) {
		if (fget_line_at(line, len, etcf) == 0)
			return (0);

		if (lineno)
			(*lineno)++;

		len = strlen(line->str);
		if (line->str[len-1] == '\n') {
			line->str[len-1] = 0;
			len -= 1;
		}

		if (!blankline(line->str) &&
		    line->str[0] != '+' && line->str[0] != '-')
			break;

		len = 0;
		loc->offset = ftell(etcf);
	}

	loc->size = len;
	return (1);
}


char *
fetchdbm(key)
	datum key;
{
	static char line[BUFSIZ+1];
	datum val;

	val = dbm_fetch(dbmf, key);
	if (val.dptr) {
		sprintf(line, "%.*s", val.dsize, val.dptr);
		return (line);
	}
	return (0);
}

char *
fetchdbm_addkey(key)
	datum key;
{
	static char line[BUFSIZ+1];
	datum val;

	val = dbm_fetch(dbmf, key);
	if (val.dptr) {
		sprintf(line, "%.*s %.*s",
			key.dsize, key.dptr,
			val.dsize, val.dptr);
		return (line);
	} else if (key.dptr[key.dsize-1] == NULL) {
	    key.dsize -= 1;
	    val = dbm_fetch(dbmf, key);
	    if (val.dptr) {
		sprintf(line, "%.*s %.*s",
			key.dsize, key.dptr,
			val.dsize, val.dptr);
		return (line);
	    }
	}
	return (0);
}

char *
fetchfile(key)
	datum key;
{
	static struct line_buf line;
	char *p;
	datum content;
	datum lkey;
	struct file_loc loc;

	content = dbm_fetch(dbmf, key);
	if (content.dptr == 0)
		return (0);    /* not in file */
	memcpy((char *)&loc, (char *)content.dptr, sizeof (loc));

	if (fseek(etcf, loc.offset, SEEK_SET) == -1) {
		fprintf(stderr, "error seeking on file\n");
		exit(1);
	}

	if (line.alloc == 0)
		line_buf_init(&line);

	if (tt->filedbmline(&line, etcf, 0, &loc))
		return (line.str);
	return (0);
}
/*
 * Convert a line into key and content.  The key is included
 * in the content.
 */
void
filetodbm(line, key, content)
	char *line;
	datum *key;
	datum *content;
{
	int i;
	char *p;

	content->dptr = line;
	content->dsize = strlen(line);

	for (i = tt->filekeycol; i >= 0; i--) {
		p = strpbrk(line, tt->filesep);
		if (i > 0) {
			if (p == 0) {
				key->dptr = 0;
				key->dsize = 0;
				return;
			}
			line = p + strspn(p, tt->filesep);
		}
	}

	if (p) {
		key->dptr = line;
		key->dsize = p-line;
	} else {
		key->dptr = line;
		key->dsize = strlen(line);
	}
}

/*
 * Convert a line into key and content.  Unlike filetodbm, the key
 * is not included in the content.
 */
void
filetodbm_keyvalue(line, key, content)
	char *line;
	datum *key;
	datum *content;
{
	int i;
	char *p;

	for (i = tt->filekeycol; i >= 0; i--) {
		p = strpbrk(line, tt->filesep);
		if (i > 0) {
			if (p == 0) {
				key->dptr = 0;
				key->dsize = 0;
				return;
			}
			line = p + strspn(p, tt->filesep);
		}
	}

	if (p) {
		key->dptr = line;
		key->dsize = p-line;
		line = p + strspn(p, tt->filesep);
		content->dptr = line;
		content->dsize = strlen(line);
	} else {
		key->dptr = line;
		key->dsize = strlen(line);
		content->dptr = "";
		content->dsize = 0;
	}
}

/*
 * Convert a line into key and content.  The key is included
 * in the content.
 */
void
filetodbm_attr(char *line, datum *key, datum *content)
{
	int	i, j, skip, numkeycol;
	int	*keycol;
	char	*p;

	content->dptr = line;
	content->dsize = strlen(line);

	if (strcmp(tt->ttype, NSS_DBNAM_EXECATTR) == 0) {
		numkeycol = EXECATTR_DB_NKEYCOL;
		keycol = exec_attr_keycol;
	} else if (strcmp(tt->ttype, NSS_DBNAM_USERATTR) == 0) {
		numkeycol = USERATTR_DB_NKEYCOL;
		keycol = user_attr_keycol;
	}

	for (i = 0; i < numkeycol; i++) {
		for (j = keycol[i]; j >= 0; j--) {
			p = strpbrk(line, tt->filesep);
			if (j > 0) {
				if (p == NULL) {
					key->dptr = 0;
					key->dsize = 0;
					return;
				}
				skip = strspn(p, tt->filesep);
				if (skip > 1) {
					if ((j = j - skip) <= 0)
						j = 1;
				}
				line = p + skip;
			}
		}
	}

	if (p) {
		key->dptr = line;
		key->dsize = p - line;
	} else {
		key->dptr = line;
		key->dsize = strlen(line);
	}
}

void
printfkeystr_0(fstr, entry)
	char *fstr;
	nis_object *entry;
{
	char keystr[BUFSIZ];

	sprintf(keystr, "%s", NKEYVAL(0));
	printf(fstr, keystr);
}

void
printfkeystr_01(fstr, entry)
	char *fstr;
	nis_object *entry;
{
	char keystr[BUFSIZ];

	sprintf(keystr, "%s %s", NKEYVAL(0), NKEYVAL(1));
	printf(fstr, keystr);
}

void
printfkeystr_cname(fstr, entry)
	char *fstr;
	nis_object *entry;
{
	char keystr[BUFSIZ];

	if (strcasecmp(NKEYVAL(0), NKEYVAL(1)) == 0)
		sprintf(keystr, "%s", NKEYVAL(0));
	else
		sprintf(keystr, "%s (%s)", NKEYVAL(0), NKEYVAL(1));

	printf(fstr, keystr);
}


#define	GENENT_OK 0
#define	GENENT_PARSEERR 1
#define	GENENT_CBERR 2
#define	GENENT_ERR 3


/*
 * /etc/hosts
 * nis+ table: (hosts_tbl) cname, name, addr, comment
 * Builds IPv4 entries only, IPv6 entries in hosts are ignored.
 */

int
genent_hosts(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[4];
	char *cname;
	struct in6_addr in6;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 3)
	 */
	t = strchr(buf, '#');
	if (t != NULL) {
		*t++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		ecol[3].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;
	}

	/*
	 * addr(col 2)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no host");
		return (GENENT_PARSEERR);
	}

	/*
	 * Ignore IPv6 entries in hosts file, return OK.
	 */
	if (inet_pton(AF_INET6, t, &in6) == 1)
		return (GENENT_OK);

	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * cname (col 0)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no cname");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 4;

	if (!cback)
		cback = addentry;

	/*
	 * name (col 1)
	 */
	do {
		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		if ((*cback)(ta_name, &eobj, udata, 0))
			return (GENENT_CBERR);

		/*
		 * only put comment in canonical entry
		 */
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;

	} while (t = strtok(NULL, " \t"));

	return (GENENT_OK);
}


/*
 * /etc/inet/ipnodes (symlink to /etc/inet/hosts)
 * nis+ table: (ipnodes_tbl) cname, name, addr, comment
 * Builds both IPv4 and IPv6 entries for ipnodes map.
 */

int
genent_hosts6(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[4];
	char *cname;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 3)
	 */
	t = strchr(buf, '#');
	if (t != NULL) {
		*t++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		ecol[3].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;
	}

	/*
	 * addr(col 2)
	 */
	if ((t = strtok(buf, " \t")) == NULL) {
		strcpy(parse_err_msg, "no host");
		return (GENENT_PARSEERR);
	}
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * cname (col 0)
	 */
	if ((t = strtok(NULL, " \t")) == NULL) {
		strcpy(parse_err_msg, "no cname");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 4;

	if (cback == NULL)
		cback = addentry;

	/*
	 * name (col 1)
	 */
	do {
		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		if ((*cback)(ta_name, &eobj, udata, 0))
			return (GENENT_CBERR);

		/*
		 * only put comment in canonical entry
		 */
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;

	} while ((t = strtok(NULL, " \t")) != NULL);

	return (GENENT_OK);
}

/*
 * List all of the entries that have the same cname as the passed
 * entry.
 */
nis_result *
dump_match_cname(table, entry)
	nis_name table;
	nis_object *entry;
{
	nis_result *res = 0;
	char *c0, *c1, *c2;
	char srch[NIS_MAXNAMELEN];

	if ((c0 = KEYVAL(0)) && *c0 &&
	    (c1 = KEYVAL(1)) && (c2 = KEYVAL(2)) &&
	    (strcasecmp(c0, c1) == 0)) {
		sprintf(srch, "[cname=%s],%s", c0, table);
		res = nis_list(srch, allres|master, 0, 0);
	}

	return (res);
}

/*
 * List all of the entries that have the same cname and address as the passed
 * entry.
 */
nis_result *
dump_match_hosts(table, entry)
    nis_name table;
    nis_object *entry;
{
	nis_result *res = 0;
	char *c0, *c1, *c2;
	char srch[NIS_MAXNAMELEN];

	if ((c0 = KEYVAL(0)) && *c0 &&
			(c1 = KEYVAL(1)) && (c2 = KEYVAL(2)) &&
			(strcasecmp(c0, c1) == 0)) {
		sprintf(srch, "[cname=%s,addr=%s],%s", c0, c2, table);
		res = nis_list(srch, allres|master, 0, 0);
	}

	return (res);
}

void
dump_hosts(res)
	nis_result *res;
{
	int i, j;
	char buf[BUFSIZ+1], *c0, *c1, *c2, *c3, *c0a, *c1a;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && *c0 &&
		    (c1 = OBJ_COL_VAL(i, 1)) && (c2 = OBJ_COL_VAL(i, 2)) &&
		    (strcasecmp(c0, c1) == 0)) {
			strcpy(buf, c2);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c0);
			for (j = 0; j < res->objects.objects_len; j++)
				if (j != i &&
				    (c0a = OBJ_COL_VAL(j, 0)) && *c0a &&
				    (c1a = OBJ_COL_VAL(j, 1)) &&
				    strcasecmp(c0, c0a) == 0) {
					strcat(buf, " ");
					strcat(buf, c1a);
					*c0a = 0;
				}
			if ((c3 = OBJ_COL_VAL(i, 3)) && !blankline(c3)) {
				strcat(buf, tabtocol(buf, 5));
				strcat(buf, "#");
				strcat(buf, c3);
			}
			*c0 = 0;
			printf("%s\n", buf);
		}
	}
}


/*
 * /etc/passwd
 * /etc/shadow
 * nis+ table: (passwd_tbl) name, passwd, uid, gid, gcos, home, shell, shadow
 *
 */

int
genent_passwd(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *s, *t;
	nis_object eobj;
	entry_col ecol[8];
	char *name, pname[NIS_MAXNAMELEN];
	char aname[NIS_MAXNAMELEN];

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);
	t = buf;

	/* ignore empty entries */
	if (*t == '\0')
		return (GENENT_OK);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * name (col 0)
	 */
	if ((s = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "no password");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	name = t;
	t = s;

	/*
	 * passwd (col 1)
	 */
	if ((s = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "no uid");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
#ifndef FOURDOTX
	if ((dbmf && ! etcf) || (flags & F_PASSWD)) {
#endif
		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;
		ecol[1].ec_flags = EN_CRYPT|EN_MODIFIED;
#ifndef FOURDOTX
	}
#endif
	t = s;

	/*
	 * uid (col 2)
	 */
	if ((s = strchr(t, ':')) == 0 || s == t) {
		strcpy(parse_err_msg, "no gid");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;
	ecol[2].ec_flags = EN_MODIFIED;
	t = s;

	/*
	 * gid (col 3)
	 */
	if ((s = strchr(t, ':')) == 0 || s == t) {
		strcpy(parse_err_msg, "no gcos");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[3].ec_value.ec_value_val = t;
	ecol[3].ec_value.ec_value_len = strlen(t)+1;
	ecol[3].ec_flags = EN_MODIFIED;
	t = s;

	/*
	 * gcos (col 4)
	 */
	if ((s = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "no home");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[4].ec_value.ec_value_val = t;
	ecol[4].ec_value.ec_value_len = strlen(t)+1;
	ecol[4].ec_flags = EN_MODIFIED;
	t = s;

	/*
	 * home (col 5)
	 */
	if ((s = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "no shell");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[5].ec_value.ec_value_val = t;
	ecol[5].ec_value.ec_value_len = strlen(t)+1;
	ecol[5].ec_flags = EN_MODIFIED;
	t = s;

	/*
	 * shell (col 6)
	 */
	ecol[6].ec_value.ec_value_val = t;
	ecol[6].ec_value.ec_value_len = strlen(t)+1;
	ecol[6].ec_flags = EN_MODIFIED;

	/*
	 * NIS+ principal name
	 */
	sprintf(pname, "%s.%s", name, nisdomain);

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_owner = pname;
	/*
	 *  If access mode did not come from -D option,
	 *  then ignore it.
	 */
	if (nis_default_access_src != NIS_SRC_ARG)
		eobj.zo_access = NIS_OWNER_MASK(NIS_READ_ACC);
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 8;

	if (!cback)
		cback = addentry;

	/* specify entry by name alone (ignore uid) */
	sprintf(aname, "[name=%s],%s", name, ta_name);

	if ((*cback)(aname, &eobj, udata, 1))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_passwd(res)
	nis_result *res;
{
	int i;
	char *c0, *c1, *c2, *c3, *c4, *c5, *c6;

	for (i = 0; i < res->objects.objects_len; i++) {
		if (c0 = OBJ_COL_VAL(i, 0)) {
			c1 = OBJ_COL_VAL(i, 1);
			c1 = c1 ? c1 : null_string;
			c2 = OBJ_COL_VAL(i, 2);
			c2 = c2 ? c2 : null_string;
			c3 = OBJ_COL_VAL(i, 3);
			c3 = c3 ? c3 : null_string;
			c4 = OBJ_COL_VAL(i, 4);
			c4 = c4 ? c4 : null_string;
			c5 = OBJ_COL_VAL(i, 5);
			c5 = c5 ? c5 : null_string;
			c6 = OBJ_COL_VAL(i, 6);
			c6 = c6 ? c6 : null_string;
			printf("%s:%s:%s:%s:%s:%s:%s\n",
				c0,
#ifndef FOURDOTX
				"x",
#else
				c1,
#endif
				c2, c3, c4, c5, c6);
		}
	}
}

int
genent_shadow(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *s, *t;
	nis_object eobj;
	entry_col ecol[8];
	char *name, mname[NIS_MAXNAMELEN], pname[NIS_MAXNAMELEN];

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);
	t = buf;

	/* ignore empty entries */
	if (*t == '\0')
		return (GENENT_OK);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * name (col 0)
	 */
	if ((s = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "no password");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	name = t;
	t = s;

	/*
	 * passwd (col 1)
	 */
	if ((s = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "no shadow");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;
	ecol[1].ec_flags = EN_CRYPT|EN_MODIFIED;
	t = s;

	/*
	 * shadow (col 7)
	 */
	ecol[7].ec_value.ec_value_val = t;
	ecol[7].ec_value.ec_value_len = strlen(t)+1;
	ecol[7].ec_flags = EN_MODIFIED;

	/*
	 * NIS+ principal name
	 */
	sprintf(pname, "%s.%s", name, nisdomain);

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_owner = pname;
	/*
	 *  If access mode did not come from -D option,
	 *  then ignore it.
	 */
	if (nis_default_access_src != NIS_SRC_ARG)
		eobj.zo_access = NIS_OWNER_MASK(NIS_READ_ACC);
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 8;

	if (!cback)
		cback = addentry;

	/* specify entry by name alone (ignore uid) */
	sprintf(mname, "[name=%s],%s", name, ta_name);

	if ((*cback)(mname, &eobj, udata, 1))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_shadow(res)
	nis_result *res;
{
	int i;
	char *c0, *c1, *c7;

	for (i = 0; i < res->objects.objects_len; i++) {
		if (c0 = OBJ_COL_VAL(i, 0)) {
			c1 = OBJ_COL_VAL(i, 1);
			c1 = c1 ? c1 : null_string;
			if (c7 = OBJ_COL_VAL(i, 7))
				printf("%s:%s:%s\n", c0, c1, c7);
			else
				printf("%s:%s::::::\n", c0, c1);
		}
	}
}


/*
 * /etc/ethers
 * nis+ table: (ethers_tbl) addr, name, comment
 *
 */

int
genent_ethers(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[3];
	char *name;
	char *addr, aname[NIS_MAXNAMELEN];

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 2)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[2].ec_value.ec_value_val = t;
		ecol[2].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[2].ec_value.ec_value_val = 0;
		ecol[2].ec_value.ec_value_len = 0;
	}

	/*
	 * addr(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no name");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	addr = t;

	/*
	 * name(col 1)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no white space allowed in name");
		return (GENENT_PARSEERR);
	}
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;
	name = t;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 3;

	if (!cback)
		cback = addentry;

	/* specify entry by addr alone (ignore name) */
	sprintf(aname, "[addr=%s],%s", addr, ta_name);

	if ((*cback)(aname, &eobj, udata, 0))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_ethers(res)
	nis_result *res;
{
	int i;
	char buf[BUFSIZ+1], *c0, *c1, *c2;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) &&
		    (c1 = OBJ_COL_VAL(i, 1))) {
			strcpy(buf, c0);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c1);
			if ((c2 = OBJ_COL_VAL(i, 2)) &&
			    !blankline(c2)) {
				strcat(buf, tabtocol(buf, 5));
				strcat(buf, "#");
				strcat(buf, c2);
			}
			printf("%s\n", buf);
		}
	}
}


/*
 * /etc/group
 * nis+ table: (group_tbl) name, passwd, gid, members
 *
 */

int
genent_group(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BIGBUF+1];
	char *s, *t;
	nis_object eobj;
	entry_col ecol[4];
	char *name;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);
	t = buf;

	/* ignore empty entries */
	if (*t == '\0')
		return (GENENT_OK);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * name (col 0)
	 */
	if ((s = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "no passwd");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	name = t;
	t = s;

	/*
	 * passwd (col 1)
	 */
	if ((s = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "no gid");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;
	ecol[1].ec_flags = EN_CRYPT;
	t = s;

	/*
	 * gid (col 2)
	 */
	if ((s = strchr(t, ':')) == 0 || s == t) {
		strcpy(parse_err_msg, "no members");
		return (GENENT_PARSEERR);
	}
	*s++ = 0;
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;
	t = s;

	/*
	 * members (col 3)
	 */
	ecol[3].ec_value.ec_value_val = t;
	ecol[3].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 4;

	if (!cback)
		cback = addentry;

	if ((*cback)(ta_name, &eobj, udata, 0))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_group(res)
	nis_result *res;
{
	int i;
	char *c0, *c1, *c2, *c3;

	for (i = 0; i < res->objects.objects_len; i++) {
		if (c0 = OBJ_COL_VAL(i, 0)) {
			c1 = OBJ_COL_VAL(i, 1);
			c1 = c1 ? c1 : null_string;
			c2 = OBJ_COL_VAL(i, 2);
			c2 = c2 ? c2 : null_string;
			c3 = OBJ_COL_VAL(i, 3);
			c3 = c3 ? c3 : null_string;
			printf("%s:%s:%s:%s\n", c0, c1, c2, c3);
		}
	}
}


/*
 * /etc/netmasks
 * nis+ table: (netmasks_tbl) number, mask, comment
 *
 */

int
genent_netmasks(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[3];
	char *addr, aname[NIS_MAXNAMELEN];

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 2)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[2].ec_value.ec_value_val = t;
		ecol[2].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[2].ec_value.ec_value_val = 0;
		ecol[2].ec_value.ec_value_len = 0;
	}

	/*
	 * addr(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no mask");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	addr = t;

	/*
	 * mask (col 1)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no mask");
		return (GENENT_PARSEERR);
	}
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 3;

	if (!cback)
		cback = addentry;

	/* specify entry by addr alone (ignore mask) */
	sprintf(aname, "[addr=%s],%s", addr, ta_name);

	if ((*cback)(aname, &eobj, udata, 0))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_netmasks(res)
	nis_result *res;
{
	int i;
	char buf[BUFSIZ+1], *c0, *c1, *c2;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && (c1 = OBJ_COL_VAL(i, 1))) {
			strcpy(buf, c0);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c1);
			if ((c2 = OBJ_COL_VAL(i, 2)) &&
			    !blankline(c2)) {
				strcat(buf, tabtocol(buf, 5));
				strcat(buf, "#");
				strcat(buf, c2);
			}
			printf("%s\n", buf);
		}
	}
}


/*
 * /etc/networks
 * nis+ table: (networks_tbl) cname, name, addr, comment
 *
 */

int
genent_networks(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[4];
	char *cname;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 3)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		ecol[3].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;
	}

	/*
	 * cname(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no number");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * number (col 2)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no number");
		return (GENENT_PARSEERR);
	}
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 4;

	if (!cback)
		cback = addentry;

	/*
	 * name (col 1)
	 */
	t = cname;
	do {
		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		if ((*cback)(ta_name, &eobj, udata, 0))
			return (GENENT_CBERR);

		/*
		 * only put comment in canonical entry
		 */
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;

	} while (t = strtok(NULL, " \t"));

	return (GENENT_OK);
}

void
dump_networks(res)
	nis_result *res;
{
	int i, j, a;
	char buf[BUFSIZ+1], *c0, *c1, *c2, *c3, *c0a, *c1a;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && *c0 &&
		    (c1 = OBJ_COL_VAL(i, 1)) && (c2 = OBJ_COL_VAL(i, 2)) &&
		    (strcasecmp(c0, c1) == 0)) {
			strcpy(buf, c0);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c2);
			for (a = j = 0; j < res->objects.objects_len; j++)
				if (j != i &&
				    (c0a = OBJ_COL_VAL(j, 0)) && *c0a &&
				    (c1a = OBJ_COL_VAL(j, 1)) &&
				    strcasecmp(c0, c0a) == 0) {
					if (a++ > 0)
						strcat(buf, " ");
					else
						strcat(buf, tabtocol(buf, 4));
					strcat(buf, c1a);
					*c0a = 0;
				}
			if ((c3 = OBJ_COL_VAL(i, 3)) && !blankline(c3)) {
				strcat(buf, tabtocol(buf, 6));
				strcat(buf, "#");
				strcat(buf, c3);
			}
			*c0 = 0;
			printf("%s\n", buf);
		}
	}
}


/*
 * /etc/protocols
 * nis+ table: (protocols_tbl) cname, name, number, comment
 *
 */

int
genent_protocols(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[4];
	char *cname;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 3)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		ecol[3].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;
	}

	/*
	 * cname(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no number");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * number (col 2)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no number");
		return (GENENT_PARSEERR);
	}
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 4;

	if (!cback)
		cback = addentry;

	/*
	 * name (col 1)
	 */
	t = cname;
	do {
		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		if ((*cback)(ta_name, &eobj, udata, 0))
			return (GENENT_CBERR);

		/*
		 * only put comment in canonical entry
		 */
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;

	} while (t = strtok(NULL, " \t"));

	return (GENENT_OK);
}

void
dump_protocols(res)
	nis_result *res;
{
	int i, j, a;
	char buf[BUFSIZ+1], *c0, *c1, *c2, *c3, *c0a, *c1a;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && *c0 &&
		    (c1 = OBJ_COL_VAL(i, 1)) && (c2 = OBJ_COL_VAL(i, 2)) &&
		    (strcasecmp(c0, c1) == 0)) {
			strcpy(buf, c0);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c2);
			for (a = j = 0; j < res->objects.objects_len; j++)
				if (j != i &&
				    (c0a = OBJ_COL_VAL(j, 0)) && *c0a &&
				    (c1a = OBJ_COL_VAL(j, 1)) &&
				    strcasecmp(c0, c0a) == 0) {
					if (a++ > 0)
						strcat(buf, " ");
					else
						strcat(buf, tabtocol(buf, 4));
					strcat(buf, c1a);
					*c0a = 0;
				}
			if ((c3 = OBJ_COL_VAL(i, 3)) && !blankline(c3)) {
				strcat(buf, tabtocol(buf, 6));
				strcat(buf, "#");
				strcat(buf, c3);
			}
			*c0 = 0;
			printf("%s\n", buf);
		}
	}
}


/*
 * /etc/rpc
 * nis+ table: (rpc_tbl) cname, name, number, comment
 *
 */

int
genent_rpc(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[4];
	char *cname;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 3)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[3].ec_value.ec_value_val = t;
		ecol[3].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;
	}

	/*
	 * cname(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no number");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * number (col 2)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no number");
		return (GENENT_PARSEERR);
	}
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 4;

	if (!cback)
		cback = addentry;

	/*
	 * name (col 1)
	 */
	t = cname;
	do {
		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		if ((*cback)(ta_name, &eobj, udata, 0))
			return (GENENT_CBERR);

		/*
		 * only put comment in canonical entry
		 */
		ecol[3].ec_value.ec_value_val = 0;
		ecol[3].ec_value.ec_value_len = 0;

	} while (t = strtok(NULL, " \t"));

	return (GENENT_OK);
}

void
dump_rpc(res)
	nis_result *res;
{
	int i, j, a;
	char buf[BUFSIZ+1], *c0, *c1, *c2, *c3, *c0a, *c1a;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && *c0 &&
		    (c1 = OBJ_COL_VAL(i, 1)) && (c2 = OBJ_COL_VAL(i, 2)) &&
		    (strcasecmp(c0, c1) == 0)) {
			strcpy(buf, c0);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c2);
			for (a = j = 0; j < res->objects.objects_len; j++)
				if (j != i &&
				    (c0a = OBJ_COL_VAL(j, 0)) && *c0a &&
				    (c1a = OBJ_COL_VAL(j, 1)) &&
				    strcasecmp(c0, c0a) == 0) {
					if (a++ > 0)
						strcat(buf, " ");
					else
						strcat(buf, tabtocol(buf, 4));
					strcat(buf, c1a);
					*c0a = 0;
				}
			if ((c3 = OBJ_COL_VAL(i, 3)) &&
			    !blankline(c3)) {
				strcat(buf, tabtocol(buf, 6));
				strcat(buf, "#");
				strcat(buf, c3);
			}
			*c0 = 0;
			printf("%s\n", buf);
		}
	}
}


/*
 * /etc/services
 * nis+ table: (services_tbl) cname, name, proto, port, comment
 *
 */

int
genent_services(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t, *p;
	nis_object eobj;
	entry_col ecol[5];
	char *cname;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 4)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[4].ec_value.ec_value_val = t;
		ecol[4].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[4].ec_value.ec_value_val = 0;
		ecol[4].ec_value.ec_value_len = 0;
	}

	/*
	 * cname(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no port");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	cname = t;

	/*
	 * port (col 3)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no protocol");
		return (GENENT_PARSEERR);
	}
	if ((p = strchr(t, '/')) == 0) {
		strcpy(parse_err_msg, "bad port/proto");
		return (GENENT_PARSEERR);
	}
	*(p++) = 0;
	ecol[3].ec_value.ec_value_val = t;
	ecol[3].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * proto (col 2)
	 */
	ecol[2].ec_value.ec_value_val = p;
	ecol[2].ec_value.ec_value_len = strlen(p)+1;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 5;

	if (!cback)
		cback = addentry;

	/*
	 * name (col 1)
	 */
	t = cname;
	do {
		/*
		 * don't clobber comment in canonical entry
		 */
		if (t != cname && strcasecmp(t, cname) == 0)
			continue;

		ecol[1].ec_value.ec_value_val = t;
		ecol[1].ec_value.ec_value_len = strlen(t)+1;

		if ((*cback)(ta_name, &eobj, udata, 0))
			return (GENENT_CBERR);

		/*
		 * only put comment in canonical entry
		 */
		ecol[4].ec_value.ec_value_val = 0;
		ecol[4].ec_value.ec_value_len = 0;

	} while (t = strtok(NULL, " \t"));

	return (GENENT_OK);
}

/*
 * List all of the entries that match the cname, proto, and port
 * of the passed entry.
 */
nis_result *
dump_match_services(table, entry)
	nis_name table;
	nis_object *entry;
{
	nis_result *res = 0;
	char *c0, *c1, *c2, *c3;
	char srch[NIS_MAXNAMELEN];

	if ((c0 = KEYVAL(0)) && *c0 &&
	    (c1 = KEYVAL(1)) && (c2 = KEYVAL(2)) && (c3 = KEYVAL(3)) &&
	    (strcasecmp(c0, c1) == 0)) {
		sprintf(srch, "[cname=%s,proto=%s,port=%s],%s",
			c0, c2, c3, table);
		res = nis_list(srch, allres|master, 0, 0);
	}

	return (res);
}

void
dump_services(res)
	nis_result *res;
{
	int i, j, a;
	char buf[BUFSIZ+1], *c0, *c1, *c2, *c3, *c4, *c0a, *c1a, *c2a, *c3a;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && *c0 &&
		    (c1 = OBJ_COL_VAL(i, 1)) && (c2 = OBJ_COL_VAL(i, 2)) &&
		    (c3 = OBJ_COL_VAL(i, 3)) && (strcasecmp(c0, c1) == 0)) {
			strcpy(buf, c0);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c3);
			strcat(buf, "/");
			strcat(buf, c2);
			for (a = j = 0; j < res->objects.objects_len; j++)
				if (j != i &&
				    (c0a = OBJ_COL_VAL(j, 0)) && *c0a &&
				    (c1a = OBJ_COL_VAL(j, 1)) &&
				    (c2a = OBJ_COL_VAL(j, 2)) &&
				    (c3a = OBJ_COL_VAL(j, 3)) &&
				    strcasecmp(c0, c0a) == 0 &&
				    strcasecmp(c2, c2a) == 0 &&
				    strcasecmp(c3, c3a) == 0) {
					if (a++ > 0)
						strcat(buf, " ");
					else
						strcat(buf, tabtocol(buf, 4));
					strcat(buf, c1a);
					*c0a = 0;
				}
			if ((c4 = OBJ_COL_VAL(i, 4)) && !blankline(c4)) {
				strcat(buf, tabtocol(buf, 6));
				strcat(buf, "#");
				strcat(buf, c4);
			}
			*c0 = 0;
			printf("%s\n", buf);
		}
	}
}

char *
dbmniskey_services(key)
	datum key;
{
	static char buf[NIS_MAXNAMELEN];
	char *p;

	if ((p = strchr(key.dptr, '/')) == 0) {
		sprintf(buf, "%s=%.*s", OBJ_COL_NAME(2),
			key.dsize, key.dptr);
	} else {
		sprintf(buf, "%s=%.*s,%s=%.*s", OBJ_COL_NAME(2),
			key.dsize-(p-key.dptr)-1, p+1,
			OBJ_COL_NAME(3), p-key.dptr, key.dptr);
	}

	return (buf);
}

datum
nisdbmkey_services(entry)
	nis_object *entry;
{
	static char buf[BUFSIZ+1];
	datum key;

	sprintf(buf, "%s/%s", NKEYVAL(3), NKEYVAL(2));
	key.dptr = buf;
	key.dsize = strlen(buf);

	return (key);
}

void
printfkeystr_services(fstr, entry)
	char *fstr;
	nis_object *entry;
{
	char keystr[BUFSIZ];

	if (strcasecmp(NKEYVAL(0), NKEYVAL(1)) == 0)
		sprintf(keystr, "%s %s/%s", NKEYVAL(0), NKEYVAL(3),
			NKEYVAL(2));
	else
		sprintf(keystr, "%s %s/%s (%s)", NKEYVAL(0), NKEYVAL(3),
			NKEYVAL(2), NKEYVAL(1));

	printf(fstr, keystr);
}


/*
 * /etc/publickey
 * /etc/netid
 * nis+ table: (cred_tbl) cname, auth_type, auth_name, public_data,
 *			private_data
 *
 */

int
genent_publickey(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1], tmpbuf[BUFSIZ+1], cname[NIS_MAXNAMELEN];
	char *t, *p;
	nis_object eobj;
	entry_col ecol[5];
	int uid;
	struct passwd *pwd;
	char aname[NIS_MAXNAMELEN], auth_type[MECH_MAXATNAME+1];
	keylen_t keylen;
	algtype_t algtype;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * auth_name (col 2)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no cname");
		return (GENENT_PARSEERR);
	}
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * Special case:  /etc/publickey usually has an entry
	 * for principal "nobody".  We skip it because it does
	 * not apply to NIS+.
	 */
	if (strcmp(t, "nobody") == 0)
		return (GENENT_OK);

	/*
	 * cname (col 0)
	 */
	if (strncmp(t, "unix.", 5)) {
		strcpy(parse_err_msg, "bad cname");
		return (GENENT_PARSEERR);
	}
	strcpy(tmpbuf, &(t[5]));
	if ((p = strchr(tmpbuf, '@')) == 0) {
		strcpy(parse_err_msg, "bad cname");
		return (GENENT_PARSEERR);
	}
	*(p++) = 0;
	if (isdigit(*tmpbuf)) {
		nis_error st;
		extern struct passwd *getpwuid_nisplus_master();

		uid = atoi(tmpbuf);
		/*
		 * don't generate entries for uids without passwd entries
		 * first try it in the regular way, and if that fails, then
		 * a lookup to the NIS+ Master server to be sure.
		 */
		if (((pwd = getpwuid(uid)) == 0) &&
		    ((pwd = getpwuid_nisplus_master(nisdomain,
						uid, &st)) == 0)) {
			fprintf(stderr,
				"can't map uid %d to username, skipping\n",
				uid);
			return (GENENT_OK);
		}
		strcpy(cname, pwd->pw_name);
	} else
		strcpy(cname, tmpbuf);
	if (*p != '.')
		strcat(cname, ".");
	strcat(cname, p);
	if (cname[strlen(cname)-1] != '.')
		strcat(cname, ".");
	/*
	 * XXX complain if domain in netname not same as nisdomain?
	 */
	ecol[0].ec_value.ec_value_val = cname;
	ecol[0].ec_value.ec_value_len = strlen(cname)+1;

	/*
	 * public_data (col 3)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no private_data");
		return (GENENT_PARSEERR);
	}
	if ((p = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "bad public_data");
		return (GENENT_PARSEERR);
	}
	*(p++) = 0;
	ecol[3].ec_value.ec_value_val = t;
	ecol[3].ec_value.ec_value_len = strlen(t)+1;
	keylen = (strlen(t) / 2) * 8;

	/*
	 * private_data (col 4) and algtype extraction
	 */
	if (*p == ':')
		p++;
	t = p;
	if (!(t = strchr(t, ':'))) {
		if (!oldpubkeymode)
			printf(
	"WARNING: No algtype data found in publickey file, assuming 0\n");
		algtype = 0;
	} else {
		*t = '\0';
		t++;
		algtype = atoi(t);
	}
	ecol[4].ec_value.ec_value_val = p;
	ecol[4].ec_value.ec_value_len = strlen(p)+1;
	ecol[4].ec_flags = EN_CRYPT;

	/*
	 * auth_type (col 1)
	 */
	if (!(__nis_keyalg2authtype(keylen, algtype, auth_type,
						MECH_MAXATNAME)))
		return (GENENT_PARSEERR);

	ecol[1].ec_value.ec_value_val = auth_type;
	ecol[1].ec_value.ec_value_len = strlen(auth_type)+1;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_owner = cname;
	eobj.zo_access = NIS_OWNER_MASK(NIS_READ_ACC) |
			NIS_GROUP_MASK(NIS_ALL_ACC);
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 5;

	if (!cback)
		cback = addentry;

	/* specify entry by cname/auth_type alone (ignore auth_name) */
	sprintf(aname, "[cname=%s,auth_type=%s],%s", cname, auth_type,
		ta_name);

	if ((*cback)(aname, &eobj, udata, 0))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_publickey(res)
	nis_result *res;
{
	int i, mcount = 0, authlistcount = 0, filter = 0;
	char buf[BUFSIZ+1], *c0, *c1, *c2, *c3, *c4;
	char **authlist = NULL;

	/*
	 * If RPCSEC_GSS is configured on this system, a list of
	 * auth_types needs to be generated to filter entries (since
	 * dumptable has ignored tt->clrsrch).  Otherwise, the
	 * nis_list has prefiltered out the extra entries in
	 * dumptable.
	 */
	if (mechs) {
		while (mechs[mcount]) {
			char *authtype;

			authtype = (char *)malloc(MECH_MAXATNAME+1);
			if (__nis_mechalias2authtype(mechs[mcount]->alias,
							authtype,
							MECH_MAXATNAME)) {
				authlist = (char **)realloc(authlist,
					sizeof (char *) * (authlistcount + 2));
				authlist[authlistcount] = authtype;
				authlistcount++;
			} else
				free(authtype);
			mcount++;
		}
		if (authlistcount) {
			authlist[authlistcount] = NULL;
			filter++;
		}
	}

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && (c1 = OBJ_COL_VAL(i, 1)) &&
		    (c2 = OBJ_COL_VAL(i, 2)) && (c3 = OBJ_COL_VAL(i, 3)) &&
		    (c4 = OBJ_COL_VAL(i, 4))) {
			/*
			 * If we have a filter list, then we walk
			 * through it until we find a matching
			 * auth_type.  Otherwise we go on to the next
			 * result entry.
			 */
			if (filter) {
				int gotit = 0;

				authlistcount = 0;
				while (authlist[authlistcount]) {
					if (strcmp(authlist[authlistcount],
						    c1) == 0) {
						gotit++;
						break;
					}
					authlistcount++;
				}
				if (!gotit)
					continue;
			}

			strcpy(buf, c2);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c3);
			if (strchr(c3, ':') == 0)
				strcat(buf, ":");
			strcat(buf, c4);
			if (!oldpubkeymode) {
				if (strcmp(c1, AUTH_DES_AUTH_TYPE) == 0)
					strcat(buf, ":0");
				else {
					char algbuf[MECH_MAXATNAME], *a;

					strcpy(algbuf, c1);
					if (a = strchr(algbuf, '-')) {
						*a = ':';
						strcat(buf, a);
					} else
						strcat(buf, ":0");
				}
			}
			printf("%s\n", buf);
		}
	}
}

int
genent_netid(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1], tmpbuf[BUFSIZ+1], cname[NIS_MAXNAMELEN];
	char *t, *p;
	nis_object eobj;
	entry_col ecol[5];
	int uid;
	struct passwd *pwd;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * cname (col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no auth_name");
		return (GENENT_PARSEERR);
	}
	if (strncmp(t, "unix.", 5)) {
		strcpy(parse_err_msg, "bad cname");
		return (GENENT_PARSEERR);
	}
	strcpy(tmpbuf, &(t[5]));
	if ((t[5] == '@') || ((p = strchr(tmpbuf, '@')) == 0)) {
		strcpy(parse_err_msg, "bad cname");
		return (GENENT_PARSEERR);
	}
	*(p++) = 0;
	if (isdigit(*tmpbuf)) {
		nis_error st;
		extern struct passwd *getpwuid_nisplus_master();

		uid = atoi(tmpbuf);
		/*
		 * don't generate entries for uids without passwd entries
		 * first try it in the regular way, and if that fails, then
		 * a lookup to the NIS+ Master server to be sure.
		 */
		if (((pwd = getpwuid(uid)) == 0) &&
		    ((pwd = getpwuid_nisplus_master(nisdomain,
						    uid, &st)) == 0)) {
			fprintf(stderr,
				"can't map uid %d to username, skipping\n",
				uid);
			return (GENENT_OK);
		}
		strcpy(cname, pwd->pw_name);
	} else
		uid = 0;
	/*
	 * don't generate LOCAL entries for root
	 */
	if (uid == 0)
		return (GENENT_OK);
	if (*p != '.')
		strcat(cname, ".");
	strcat(cname, p);
	if (cname[strlen(cname)-1] != '.')
		strcat(cname, ".");
	/*
	 * XXX complain if domain in netname not same as nisdomain?
	 */
	ecol[0].ec_value.ec_value_val = cname;
	ecol[0].ec_value.ec_value_len = strlen(cname)+1;

	/*
	 * auth_name (col 2)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no public_data");
		return (GENENT_PARSEERR);
	}
	if ((p = strchr(t, ':')) == 0) {
		strcpy(parse_err_msg, "bad auth_name");
		return (GENENT_PARSEERR);
	}
	*(p++) = 0;
	ecol[2].ec_value.ec_value_val = t;
	ecol[2].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * public_data (col 3)
	 */
	ecol[3].ec_value.ec_value_val = p;
	ecol[3].ec_value.ec_value_len = strlen(p)+1;

	/*
	 * private_data (col 4)
	 */
	ecol[4].ec_value.ec_value_val = 0;
	ecol[4].ec_value.ec_value_len = 0;

	/*
	 * auth_type (col 1)
	 */
	ecol[1].ec_value.ec_value_val = "LOCAL";
	ecol[1].ec_value.ec_value_len = 6;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 5;

	if (!cback)
		cback = addentry;

	if ((*cback)(ta_name, &eobj, udata, 0))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_netid(res)
	nis_result *res;
{
	int i, j;
	char buf[BUFSIZ+1], *c0, *c1, *c2, *c3, *c4;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && (c1 = OBJ_COL_VAL(i, 1)) &&
		    (c2 = OBJ_COL_VAL(i, 2)) && (c3 = OBJ_COL_VAL(i, 3))) {
			nis_name objdom = nis_domain_of(c0);
			size_t   objdom_len = strlen(objdom);

			if (objdom_len > 0) {
				if (objdom[objdom_len - 1] == '.')
					objdom[objdom_len - 1] = '\0';
			}

			sprintf(buf, "unix.%s@%s", c2, objdom);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c2);
			strcat(buf, ":");
			strcat(buf, c3);
			printf("%s\n", buf);
		}
	}
}

char *
dbmniskey_netid(key)
	datum key;
{
	static char buf[NIS_MAXNAMELEN];
	int i;

	strcpy(buf, "auth_name=xxx");

	if (key.dsize < 7 || strncmp(key.dptr, "unix.", 5))
		return (buf);
	for (i = 5; i < key.dsize; i++)
		if (key.dptr[i] == '@')
			break;
	if (i == 5 || i == key.dsize)
		return (buf);
	strncpy(&(buf[10]), &(key.dptr[5]), i-5);
	buf[5+i] = 0;

	return (buf);
}

datum
nisdbmkey_netid(entry)
	nis_object *entry;
{
	static char buf[BUFSIZ+1];
	datum key;

	sprintf(buf, "unix.%s@%s", NKEYVAL(2), nis_domain_of(NKEYVAL(0)));
	buf[strlen(buf)-1] = 0;

	key.dptr = buf;
	key.dsize = strlen(buf);

	return (key);
}


/*
 * /etc/aliases
 * nis+ table: (mail_aliases) alias, expansion, comments, options
 *
 * The handling of dbm keys and values for aliases is a little funny
 * because the length field in a datum includes the terminating
 * null (e.g., "name" would have length 5).  The other types of dbm
 * files do not include the terminating null.
 */

int
genent_aliases(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[4];
	char *alias, aname[NIS_MAXNAMELEN], key[NIS_MAXNAMELEN];

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * alias(col 0)
	 */
	if ((t = strtok_quotes(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no expansion");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;
	alias = t;

	/*
	 * expansion (col 1)
	 */
	if ((t = strtok_quotes(NULL, "")) == 0) {
		strcpy(parse_err_msg, "no expansion");
		return (GENENT_PARSEERR);
	}
	/*
	 * skip white space
	 */
	t += strspn(t, " \t");
	if (*t == 0) {
		strcpy(parse_err_msg, "empty expansion");
		return (GENENT_PARSEERR);
	}
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * comments (col 2)
	 */
	ecol[2].ec_value.ec_value_val = 0;
	ecol[2].ec_value.ec_value_len = 0;

	/*
	 * options (col 3)
	 */
	ecol[3].ec_value.ec_value_val = 0;
	ecol[3].ec_value.ec_value_len = 0;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 4;

	if (!cback)
		cback = addentry;

	(void) __nis_quote_key(alias, key, sizeof (key));

	/* specify entry by alias alone (ignore expansion) */
	sprintf(aname, "[alias=%s],%s", key, ta_name);

	if ((*cback)(aname, &eobj, udata, 0))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_aliases(res)
	nis_result *res;
{
	int i;
	char *c0, *c1, *c2;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && (c1 = OBJ_COL_VAL(i, 1))) {
			if ((c2 = OBJ_COL_VAL(i, 2)) && !blankline(c2))
				printf("# %s\n", c2);
			printf("%s: %s\n", c0, c1);
		}
	}
}

datum
nisdbmkey_aliases(entry)
	nis_object *entry;
{
	static char buf[BUFSIZ+1];
	datum key;

	strcpy(buf, NKEYVAL(tt->niskeycol));

	key.dptr = buf;
	key.dsize = strlen(buf)+1;

	return (key);
}

datum
filedbmkey_aliases(line)
	char *line;
{
	static char buf[BUFSIZ+1];
	int i;
	char *p;
	datum key;

	for (i = tt->filekeycol; i >= 0; i--) {
		p = strpbrk_quotes(line, tt->filesep);
		if (i > 0) {
			if (p == 0) {
				key.dptr = 0;
				key.dsize = 0;
				return (key);
			}
			line = p + strspn(p, tt->filesep);
		}
	}

	if (p)
		sprintf(buf, "%.*s", p-line, line);
	else
		strcpy(buf, line);

	key.dptr = buf;
	key.dsize = strlen(buf)+1;

	return (key);
}

int
filedbmline_aliases(line, etcf, lineno, loc)
	struct line_buf *line;
	FILE *etcf;
	int *lineno;
	struct file_loc *loc;
{
	char *p;
	int c;
	int len = 0;

	loc->offset = ftell(etcf);
	while (1) {
		if (fget_line_at(line, len, etcf) == 0)
			return (0);

		if (lineno)
			(*lineno)++;

		len = strlen(line->str);
		if (line->str[len-1] == '\n') {
			line->str[len-1] = 0;
			len -= 1;
		}

		/*
		 *  A continuation line starts with a space or a tab.
		 *  Continuation lines count even for commented lines.
		 */
		if ((c = fgetc(etcf)) != EOF &&
		    ungetc(c, etcf) != EOF &&
		    (c == ' ' || c == '\t')) {
			continue;
		}

		if (!blankline(line->str) && line->str[0] != '#')
			break;

		len = 0;
		loc->offset = ftell(etcf);
	}

	if (p = strchr_quotes(line->str, ':'))
		*p = ' ';

	loc->size = len;
	return (1);
}

/*
 * Convert an alias line into key and content.  Just like filetodbm_keyvalue
 * but the key and data includes the terminating null.
 */
void
filetodbm_aliases(line, key, content)
	char *line;
	datum *key;
	datum *content;
{
	int i;
	char *p;

	for (i = tt->filekeycol; i >= 0; i--) {
		p = strpbrk_quotes(line, tt->filesep);
		if (i > 0) {
			if (p == 0) {
				key->dptr = 0;
				key->dsize = 0;
				return;
			}
			line = p + strspn(p, tt->filesep);
		}
	}

	if (p) {
		*p++ = '\0';    /* null-terminate key */
		key->dptr = line;
		key->dsize = p-line;    /* include terminating null */
		line = p + strspn(p, tt->filesep);
		content->dptr = line;
		content->dsize = strlen(line) + 1;
	} else {
		key->dptr = line;
		key->dsize = strlen(line) + 1;
		content->dptr = "";
		content->dsize = 0;
	}
}

/*
 * key-value
 * nis+ table: key, value
 *
 */

int
genent_keyvalue(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[2];

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * key(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no value");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * value (col 1)
	 */
	if ((t = strtok(NULL, "")) == 0)
		t = "";
	else
		t += strspn(t, " \t");    /* skip white space */
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 2;

	if (!cback)
		cback = addentry;

	if ((*cback)(ta_name, &eobj, udata, 0))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_keyvalue(res)
	nis_result *res;
{
	int i, j;
	char buf[BUFSIZ+1], *c0, *c1;

	for (i = 0; i < res->objects.objects_len; i++) {
		if (c0 = OBJ_COL_VAL(i, 0)) {
			strcpy(buf, c0);
			if (c1 = OBJ_COL_VAL(i, 1)) {
				strcat(buf, tabtocol(buf, 2));
				strcat(buf, c1);
			}
			printf("%s\n", buf);
		}
	}
}

/*
 * /etc/netgroup
 * nis+ table: (netgroup_tbl) name, group, host, user, domain, comment
 *
 */

int
genent_netgroup(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BIGBUF+1];    /* netgroup entries tend to be big */
	char *t, *p;
	nis_object eobj;
	entry_col ecol[6];

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 5)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[5].ec_value.ec_value_val = t;
		ecol[5].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[5].ec_value.ec_value_val = 0;
		ecol[5].ec_value.ec_value_len = 0;
	}

	/*
	 * name(col 0)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		return (GENENT_OK);    /* empty line */
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * membership list
	 */
	if ((p = strtok(NULL, "")) == 0)
		p = "";

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 6;

	if (!cback)
		cback = addentry;

	/*
	 * group (col 1)
	 * host (col 2)
	 * user (col 3)
	 * domain (col 4)
	 */
	while (*p) {
		while (*p == ' ' || *p == '\t')
			p++;

		if (*p == '\0')
			break;

		if (*p == '(') {
			/*
			 * group (col 1)
			 */
			ecol[1].ec_value.ec_value_val = 0;
			ecol[1].ec_value.ec_value_len = 0;

			/*
			 * host (col 2)
			 */
			p++;
			while (*p == ' ' || *p == '\t')
				p++;
			t = p;
			while (*p != ' ' && *p != '\t' && *p != ',')
				if (*p == '\0' || *p == ')') {
					strcpy(parse_err_msg, "bad host");
					return (GENENT_PARSEERR);
				}
				else
					p++;
			*p++ = 0;
			ecol[2].ec_value.ec_value_val = t;
			ecol[2].ec_value.ec_value_len = strlen(t)+1;


			/*
			 * user (col 3)
			 */
			while (*p == ' ' || *p == '\t')
				p++;
			t = p;
			while (*p != ' ' && *p != '\t' && *p != ',')
				if (*p == '\0' || *p == ')') {
					strcpy(parse_err_msg, "bad user");
					return (GENENT_PARSEERR);
				}
				else
					p++;
			*p++ = 0;
			ecol[3].ec_value.ec_value_val = t;
			ecol[3].ec_value.ec_value_len = strlen(t)+1;

			/*
			 * domain (col 4)
			 */
			while (*p == ' ' || *p == '\t')
				p++;
			t = p;
			while (*p != ' ' && *p != '\t' && *p != ')')
				if (*p == '\0' || *p == ',') {
					strcpy(parse_err_msg, "bad domain");
					return (GENENT_PARSEERR);
				}
				else
					p++;
			*p++ = 0;
			ecol[4].ec_value.ec_value_val = t;
			ecol[4].ec_value.ec_value_len = strlen(t)+1;

		} else {
			/*
			 * host (col 2)
			 */
			ecol[2].ec_value.ec_value_val = 0;
			ecol[2].ec_value.ec_value_len = 0;

			/*
			 * user (col 3)
			 */
			ecol[3].ec_value.ec_value_val = 0;
			ecol[3].ec_value.ec_value_len = 0;

			/*
			 * domain (col 4)
			 */
			ecol[4].ec_value.ec_value_val = 0;
			ecol[4].ec_value.ec_value_len = 0;

			/*
			 * group (col 1)
			 */
			t = p;
			while (*p != ' ' && *p != '\t' && *p != '\0')
				p++;
			if (*p)
				*p++ = 0;
			ecol[1].ec_value.ec_value_val = t;
			ecol[1].ec_value.ec_value_len = strlen(t)+1;
		}

		/*
		 * XXX should avoid adding duplicates of first entry in
		 * order to keep from clobbering comment
		 */

		if ((*cback)(ta_name, &eobj, udata, 0))
			return (GENENT_CBERR);

		/*
		 * only put comment in first entry
		 */
		ecol[5].ec_value.ec_value_val = 0;
		ecol[5].ec_value.ec_value_len = 0;

	};

	return (GENENT_OK);
}


/*
 *  There is no notion of a canonical entry for netgroup, so
 *  we can't tell be looking at an entry if it has already
 *  been handled.  So, we keep a table of all of the netgroups
 *  we have done so far.
 */

#define	HASH_SIZE 64

struct hashent {
	struct hashent *next;
	char *name;
};

struct hashent *netgroup_table[64];

int
hash(s)
	char *s;
{
	int retval = 0;

	while (*s)
		retval += *s++;
	return (retval % HASH_SIZE);
}

int
did_netgroup(s)
	char *s;
{
	int n;
	struct hashent *hp;

	n = hash(s);
	for (hp = netgroup_table[n]; hp; hp = hp->next) {
		if (strcmp(s, hp->name) == 0) {
			return (1);
		}
	}

	return (0);
}

void
mark_netgroup(s)
	char *s;
{
	int n;
	struct hashent *hp;

	hp = (struct hashent *)malloc(sizeof (*hp));
	if (hp == 0) {
		fprintf(stderr, "mark_netgroup:  out of memory\n");
		exit(1);
	}

	hp->name = strdup(s);
	if (hp->name == 0) {
		fprintf(stderr, "mark_netgroup:  out of memory\n");
		exit(1);
	}

	n = hash(s);
	hp->next = netgroup_table[n];
	netgroup_table[n] = hp;
}

/*
 * List all of the entries that match the name of the passed entry.
 */
nis_result *
dump_match_netgroup(table, entry)
	nis_name table;
	nis_object *entry;
{
	nis_result *res = 0;
	char *c0, *c1, *c2, *c3, *c4;
	char srch[NIS_MAXNAMELEN];

	c0 = KEYVAL(0);
	c1 = KEYVAL(1);
	c2 = KEYVAL(2);
	c3 = KEYVAL(3);
	c4 = KEYVAL(4);
	if (c0 && *c0 && (c1 || (c3 && c4)) && ! did_netgroup(c0)) {
		sprintf(srch, "[name=%s],%s", c0, table);
		res = nis_list(srch, allres|master, 0, 0);
		mark_netgroup(c0);
	}

	return (res);
}

void
dump_netgroup(res)
	nis_result *res;
{
	int i, j;
	char *c0, *c1, *c2, *c3, *c4, *c5;
	char *c0a, *c1a, *c2a, *c3a, *c4a;
	static struct line_buf	line;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && *c0 &&
		    ((c1 = OBJ_COL_VAL(i, 1)) ||
					((c2 = OBJ_COL_VAL_NO_NULL(i, 2)) &&
		    (c3 = OBJ_COL_VAL(i, 3)) && (c4 = OBJ_COL_VAL(i, 4))))) {
			print2buf_init(&line);
			print2buf(&line, c0);
			print2buf(&line, tabtocol(line.str, 2));
			if (c1)
				print2buf(&line, c1);
			else {
				print2buf(&line, "(");
				print2buf(&line, c2);
				print2buf(&line, ",");
				print2buf(&line, c3);
				print2buf(&line, ",");
				print2buf(&line, c4);
				print2buf(&line, ")");
			}
			c5 = OBJ_COL_VAL(i, 5);
			for (j = i+1; j < res->objects.objects_len; j++) {
				if ((c0a = OBJ_COL_VAL(j, 0)) && *c0a &&
				    ((c1a = OBJ_COL_VAL(j, 1)) ||
				    ((c2a = OBJ_COL_VAL_NO_NULL(j, 2)) &&
				    (c3a = OBJ_COL_VAL(j, 3)) &&
				    (c4a = OBJ_COL_VAL(j, 4)))) &&
				    strcmp(c0, c0a) == 0) {
					print2buf(&line, " ");
					if (c1a)
						print2buf(&line, c1a);
					else {
						print2buf(&line, "(");
						print2buf(&line, c2a);
						print2buf(&line, ",");
						print2buf(&line, c3a);
						print2buf(&line, ",");
						print2buf(&line, c4a);
						print2buf(&line, ")");
					}
					if (!c5)
						c5 = OBJ_COL_VAL(j, 5);
					*c0a = 0;
				}
			}
			if (c5 && !blankline(c5)) {
				print2buf(&line, tabtocol(line.str, 6));
				print2buf(&line, "#");
				print2buf(&line, c5);
			}
			*c0 = 0;
			printf("%s\n", line.str);
			print2buf_destroy(&line);
		}
	}
}

void
printfkeystr_netgroup(fstr, entry)
	char *fstr;
	nis_object *entry;
{
	char keystr[BUFSIZ];

	if (NKEYVAL(1))
		sprintf(keystr, "%s %s", NKEYVAL(0), NKEYVAL(1));
	else
		sprintf(keystr, "%s (%s,%s,%s)", NKEYVAL(0), NKEYVAL(2),
			NKEYVAL(3), NKEYVAL(4));

	printf(fstr, keystr);
}

/*
 * /etc/timezone
 * nis+ table: (timezone_tbl) name, tzone, comment
 *
 */

int
genent_timezone(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char buf[BUFSIZ+1];
	char *t;
	nis_object eobj;
	entry_col ecol[3];
	char *cname;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * clear column data
	 */
	memset((char *)ecol, 0, sizeof (ecol));

	/*
	 * comment (col 2)
	 */
	t = strchr(buf, '#');
	if (t) {
		*t++ = 0;
		ecol[2].ec_value.ec_value_val = t;
		ecol[2].ec_value.ec_value_len = strlen(t)+1;
	} else {
		ecol[2].ec_value.ec_value_val = 0;
		ecol[2].ec_value.ec_value_len = 0;
	}

	/*
	 * tzone (col 1)
	 */
	if ((t = strtok(buf, " \t")) == 0) {
		strcpy(parse_err_msg, "no name");
		return (GENENT_PARSEERR);
	}
	ecol[1].ec_value.ec_value_val = t;
	ecol[1].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * name(col 0)
	 */
	if ((t = strtok(NULL, " \t")) == 0) {
		strcpy(parse_err_msg, "no name");
		return (GENENT_PARSEERR);
	}
	ecol[0].ec_value.ec_value_val = t;
	ecol[0].ec_value.ec_value_len = strlen(t)+1;

	/*
	 * build entry
	 */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = NIS_ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = 3;

	if (!cback)
		cback = addentry;

	if ((*cback)(ta_name, &eobj, udata, 0))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_timezone(res)
	nis_result *res;
{
	int i, j;
	char buf[BUFSIZ+1], *c0, *c1, *c2;

	for (i = 0; i < res->objects.objects_len; i++) {
		if ((c0 = OBJ_COL_VAL(i, 0)) && (c1 = OBJ_COL_VAL(i, 1))) {
			strcpy(buf, c1);
			strcat(buf, tabtocol(buf, 2));
			strcat(buf, c0);
			if ((c2 = OBJ_COL_VAL(i, 2)) &&
			    !blankline(c2)) {
				strcat(buf, tabtocol(buf, 6));
				strcat(buf, "#");
				strcat(buf, c2);
			}
			printf("%s\n", buf);
		}
	}
}

/*
 * genent_attr:
 *   Generic function for generating entries for all of the *_attr databases.
 */
int
genent_attr(line, cback, udata, database, ncol, cnames, nkeycol, keycol)
	char *line;
	int (*cback)();
	void *udata;
	char *database;	/* name of the database */
	int ncol;	/* number of columns in the database */
	char **cnames;	/* array of column names */
	int nkeycol;	/* number of searchable columns that form the id */
	int keycol[];	/* array containing indices of searchable columns */
{
	int		i, j;
	char		buf[BUFSIZ+1];
	char		aname[NIS_MAXNAMELEN];
	char		*s;
	char		*sep = KV_TOKEN_DELIMIT;
	char		*lasts;
	entry_col	*ecol;
	nis_object	eobj;

	/*
	 * don't clobber our argument
	 */
	if (strlen(line) >= sizeof (buf)) {
		strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}
	strcpy(buf, line);

	/*
	 * setup and clear column data
	 */
	if ((ecol = (entry_col *)malloc(ncol * sizeof (entry_col))) == NULL)
		return (GENENT_ERR);
	memset((char *)ecol, 0, ncol * sizeof (ecol));

	/* Split up columns */
	i = 0;
	while (i < ncol) {
		s = _strtok_escape(i ? NULL : buf, sep, &lasts);
		if (s == NULL) {
			ecol[i].ec_value.ec_value_val = NULL;
			ecol[i].ec_value.ec_value_len = 0;
		} else {
			ecol[i].ec_value.ec_value_val = s;
			ecol[i].ec_value.ec_value_len = strlen(s)+1;
		}
		ecol[i].ec_flags = EN_MODIFIED;
		i++;
	}

	/* build entry */
	eobj = nis_default_obj;
	eobj.zo_data.zo_type = ENTRY_OBJ;
	eobj.EN_data.en_type = ta_type;
	eobj.EN_data.en_cols.en_cols_val = ecol;
	eobj.EN_data.en_cols.en_cols_len = ncol;

	if (!cback)
		cback = addentry;

	/* specify entry by unique identifier */
	memset(aname, 0, NIS_MAXNAMELEN * sizeof (char));
	strcat(aname, "[");
	for (i = 0; i < nkeycol; i++) {
		j = keycol[i];
		if (i)
			strcat(aname, ",");
		strcat(aname, cnames[j]);
		strcat(aname, "=\"");
		strcat(aname, ecol[j].ec_value.ec_value_val);
		strcat(aname, "\"");
	}
	strcat(aname, "],");
	strcat(aname, ta_name);

	if ((*cback)(aname, &eobj, udata, 0))
		return (GENENT_CBERR);

	return (GENENT_OK);
}

void
dump_attr(res, ncol)
	nis_result *res;
	int ncol;
{
	int i, j;
	char *c;

	for (i = 0; i < res->objects.objects_len; i++) {
		if (c = OBJ_COL_VAL(i, 0)) {
			printf("%s", c);
			for (j = 1; j < ncol; j++) {
				c = OBJ_COL_VAL(i, j);
				printf(":%s", c ? c : null_string);
			}
			printf("\n");
		}
	}
}

int
genent_auth_attr(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	int keycol[AUTHATTR_DB_NKEYCOL] = {AUTHATTR_KEYCOL0};
	char *cnames[AUTHATTR_DB_NCOL] = {
		AUTHATTR_COL0_KW,
		AUTHATTR_COL1_KW,
		AUTHATTR_COL2_KW,
		AUTHATTR_COL3_KW,
		AUTHATTR_COL4_KW,
		AUTHATTR_COL5_KW
	};

	return (genent_attr(line, cback, udata, NSS_DBNAM_AUTHATTR,
	    AUTHATTR_DB_NCOL, cnames, AUTHATTR_DB_NKEYCOL, keycol));
}

void
dump_auth_attr(res)
	nis_result *res;
{
	dump_attr(res, AUTHATTR_DB_NCOL);
}

int
genent_exec_attr(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char *cnames[EXECATTR_DB_NCOL] = {
		EXECATTR_COL0_KW,
		EXECATTR_COL1_KW,
		EXECATTR_COL2_KW,
		EXECATTR_COL3_KW,
		EXECATTR_COL4_KW,
		EXECATTR_COL5_KW,
		EXECATTR_COL6_KW
	};

	return (genent_attr(line, cback, udata, NSS_DBNAM_EXECATTR,
	    EXECATTR_DB_NCOL, cnames, EXECATTR_DB_NKEYCOL, exec_attr_keycol));
}

void
dump_exec_attr(res)
	nis_result *res;
{
	dump_attr(res, EXECATTR_DB_NCOL);
}

int
genent_prof_attr(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	int keycol[PROFATTR_DB_NKEYCOL] = {PROFATTR_KEYCOL0};
	char *cnames[PROFATTR_DB_NCOL] = {
		PROFATTR_COL0_KW,
		PROFATTR_COL1_KW,
		PROFATTR_COL2_KW,
		PROFATTR_COL3_KW,
		PROFATTR_COL4_KW
	};

	return (genent_attr(line, cback, udata, NSS_DBNAM_PROFATTR,
	    PROFATTR_DB_NCOL, cnames, PROFATTR_DB_NKEYCOL, keycol));
}

void
dump_prof_attr(res)
	nis_result *res;
{
	dump_attr(res, PROFATTR_DB_NCOL);
}

int
genent_user_attr(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	char *cnames[USERATTR_DB_NCOL] = {
		USERATTR_COL0_KW,
		USERATTR_COL1_KW,
		USERATTR_COL2_KW,
		USERATTR_COL3_KW,
		USERATTR_COL4_KW,
	};

	return (genent_attr(line, cback, udata, NSS_DBNAM_USERATTR,
	    USERATTR_DB_NCOL, cnames, USERATTR_DB_NKEYCOL, user_attr_keycol));
}

void
dump_user_attr(res)
	nis_result *res;
{
	dump_attr(res, USERATTR_DB_NCOL);
}

int
genent_audit_user(line, cback, udata)
	char *line;
	int (*cback)();
	void *udata;
{
	int keycol[AUDITUSER_DB_NKEYCOL] = {AUDITUSER_KEYCOL0};
	char *cnames[AUDITUSER_DB_NCOL] = {
		AUDITUSER_COL0_KW,
		AUDITUSER_COL1_KW,
		AUDITUSER_COL2_KW
	};

	return (genent_attr(line, cback, udata, NSS_DBNAM_AUDITUSER,
	    AUDITUSER_DB_NCOL, cnames, AUDITUSER_DB_NKEYCOL, keycol));
}

void
dump_audit_user(res)
	nis_result *res;
{
	dump_attr(res, AUDITUSER_DB_NCOL);
}

struct ttypelist_t ttypelist[] = {
	{ "key-value", 0, 0, 0,
	    0, 0, 0, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_keyvalue,
	    dump_keyvalue, 0,
	    filedbmline_comment, filetodbm_keyvalue, fetchdbm_addkey,
	    printfkeystr_0 },
	{ "aliases", "mail.aliases", "mail_aliases.org_dir", "mail_aliases",
	    0, 0, 0, " \t",
	    dbmniskey, nisdbmkey_aliases, filedbmkey_aliases, genent_aliases,
	    dump_aliases, 0,
	    filedbmline_aliases, filetodbm_aliases, fetchdbm_addkey,
	    printfkeystr_0 },
	{ "bootparams", "bootparams", "bootparams.org_dir", "bootparams_tbl",
	    0, 0, 0, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_keyvalue,
	    dump_keyvalue, 0,
	    filedbmline_comment, filetodbm_keyvalue, fetchdbm_addkey,
	    printfkeystr_0 },
	{ "ethers", "ethers.byaddr", "ethers.org_dir", "ethers_tbl",
	    0, 0, 0, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_ethers,
	    dump_ethers, 0,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_0 },
	{ "group", "group.byname", "group.org_dir", "group_tbl",
	    0, 0, 0, ":",
	    dbmniskey, nisdbmkey, filedbmkey, genent_group,
	    dump_group, 0,
	    filedbmline_plus, filetodbm, fetchdbm,
	    printfkeystr_0 },
	{ "hosts", "hosts.byaddr", "hosts.org_dir", "hosts_tbl",
	    0, 2, 0, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_hosts,
	    dump_hosts, dump_match_hosts,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_cname },
	{ "ipnodes", "ipnodes.byaddr", "ipnodes.org_dir", "ipnodes_tbl",
	    0, 2, 0, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_hosts6,
	    dump_hosts, dump_match_hosts,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_cname },
	{ "netgroup", "netgroup", "netgroup.org_dir", "netgroup_tbl",
	    0, 0, 0, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_netgroup,
	    dump_netgroup, dump_match_netgroup,
	    filedbmline_comment, filetodbm_keyvalue, fetchdbm_addkey,
	    printfkeystr_netgroup },
	{ "netid", "netid.byname", "cred.org_dir", "cred_tbl",
	    "auth_type=LOCAL", 0, 0, " \t",
	    dbmniskey_netid, nisdbmkey_netid, filedbmkey_netid, genent_netid,
	    dump_netid, 0,
	    filedbmline_comment, filetodbm, fetchdbm_addkey,
	    printfkeystr_01 },
	{ "netmasks", "netmasks.byaddr", "netmasks.org_dir", "netmasks_tbl",
	    0, 0, 0, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_netmasks,
	    dump_netmasks, 0,
	    filedbmline_comment, filetodbm_keyvalue, fetchdbm_addkey,
	    printfkeystr_0 },
	{ "networks", "networks.byname", "networks.org_dir", "networks_tbl",
	    0, 0, 0, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_networks,
	    dump_networks, dump_match_cname,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_cname },
	{ "passwd", "passwd.byname", "passwd.org_dir", "passwd_tbl",
	    0, 0, 0, ":",
	    dbmniskey, nisdbmkey, filedbmkey, genent_passwd,
	    dump_passwd, 0,
	    filedbmline_plus, filetodbm, fetchdbm,
	    printfkeystr_0 },
	{ "protocols", "protocols.byname", "protocols.org_dir", "protocols_tbl",
	    0, 0, 0, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_protocols,
	    dump_protocols, dump_match_cname,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_cname },
	{"publickey", "publickey.byname", "cred.org_dir", "cred_tbl",
	    "auth_type=DES", 2, 0, " \t",
	    dbmniskey_publickey, nisdbmkey_publickey, filedbmkey_publickey,
	    genent_publickey, dump_publickey, 0,
	    filedbmline_comment, filetodbm_keyvalue, fetchdbm_addkey,
	    printfkeystr_01 },
	{ "rpc", "rpc.bynumber", "rpc.org_dir", "rpc_tbl",
	    0, 2, 1, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_rpc,
	    dump_rpc, dump_match_cname,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_cname },
	{ "services", "services.byname", "services.org_dir", "services_tbl",
	    0, -1, 1, " \t",
	    dbmniskey_services, nisdbmkey_services, filedbmkey, genent_services,
	    dump_services, dump_match_services,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_services },
#ifndef FOURDOTX
	{ "shadow", 0, "passwd.org_dir", "passwd_tbl",
	    0, 0, 0, ":",
	    dbmniskey, nisdbmkey, filedbmkey, genent_shadow,
	    dump_shadow, 0,
	    filedbmline_plus, filetodbm, fetchdbm,
	    printfkeystr_0 },
#endif
	{ "timezone", "timezone.byname", "timezone.org_dir", "timezone_tbl",
	    0, 0, 1, " \t",
	    dbmniskey, nisdbmkey, filedbmkey, genent_timezone,
	    dump_timezone, 0,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_0 },
	{ "auth_attr", "auth_attr.byname", "auth_attr.org_dir", "auth_attr_tbl",
	    0, 0, 0, ":",
	    dbmniskey, nisdbmkey, filedbmkey, genent_auth_attr,
	    dump_auth_attr, 0,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_0 },
	{ "exec_attr", "exec_attr.byname", "exec_attr.org_dir", "exec_attr_tbl",
	    0, 0, 0, ":",
	    dbmniskey_attr, nisdbmkey_attr, filedbmkey_attr, genent_exec_attr,
	    dump_exec_attr, 0,
	    filedbmline_comment, filetodbm_attr, fetchdbm,
	    printfkeystr_0 },
	{ "prof_attr", "prof_attr.byname", "prof_attr.org_dir", "prof_attr_tbl",
	    0, 0, 0, ":",
	    dbmniskey, nisdbmkey, filedbmkey, genent_prof_attr,
	    dump_prof_attr, 0,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_0 },
	{ "user_attr", "user_attr.byname", "user_attr.org_dir", "user_attr_tbl",
	    0, 0, 0, ":",
	    dbmniskey_attr, nisdbmkey_attr, filedbmkey_attr, genent_user_attr,
	    dump_user_attr, 0,
	    filedbmline_comment, filetodbm_attr, fetchdbm,
	    printfkeystr_0 },
	{ "audit_user", "audit_user.byname", "audit_user.org_dir",
	    "audit_user_tbl",
	    0, 0, 0, ":",
	    dbmniskey, nisdbmkey, filedbmkey, genent_audit_user,
	    dump_audit_user, 0,
	    filedbmline_comment, filetodbm, fetchdbm,
	    printfkeystr_0 },
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

/*
 *  This routine dumps a table entry.  If the dump_match routine
 *  is defined, then we call it to get all of the entries related
 *  to this one.  For example, in the hosts table, we want all
 *  of the entries for a given address.  If the dump_match routine
 *  returns 0, then the entry will be handled in conjuction with
 *  another entry and should be ignored now.  If the dump_match
 *  routine is not defined, then we make a nis_result out of
 *  the entry and then dump it.
 */
int
dumpcback(table, entry, udata)
	nis_name table;
	nis_object *entry;
	void *udata;
{
	datum key, val;
	char *line;
	nis_result *res;
	nis_result matchres;

	if (tt->dump_match) {
		res = tt->dump_match(table, entry);
		if (res) {
			tt->dump(res);
			nis_freeresult(res);
		}
	} else {
		matchres.status = NIS_SUCCESS;
		matchres.objects.objects_len = 1;
		matchres.objects.objects_val = entry;
		tt->dump(&matchres);
	}
	return (0);
}


/*
 *  In "quick" mode, we ask the server for all of the entries for
 *  the table and then call the dump routine to merge entries and
 *  print them.  This only works for small tables or on machines
 *  with a LOT of swap space.  In "normal" mode, we go through
 *  the entries one by one, calling the dumpcback routine for
 *  each one.  The dumpcback routine will find all of the entries
 *  related to the current one, merge them, and then print the
 *  result.
 */
void
dumptable()
{
	int i, j;
	char buf[BUFSIZ+1], srch[NIS_MAXNAMELEN], *c0, *c1, *c2, *c3, *c4;
	nis_result *eres;

	if ((strcmp("publickey", tt->ttype) == 0) && mechs)
		sprintf(srch, "%s", ta_name);
	else {
		if (tt->clrsrch)
			sprintf(srch, "[%s],%s", tt->clrsrch, ta_name);
		else
			sprintf(srch, "%s", ta_name);
	}

	if (flags & F_QUICK) {
		eres = nis_list(srch, allres|master, 0, 0);
		tt->dump(eres);
	} else {
		eres = nis_list(srch, allres|master, dumpcback, 0);

		if (eres->status != NIS_CBRESULTS &&
		    eres->status != NIS_NOTFOUND) {
			nis_perror(eres->status, "can't list table");
			exit(1);
		}
		nis_freeresult(eres);
	}
}


int lineno = 0;

int
putfile()
{
	struct line_buf line;
	char *p;
	struct file_loc loc;

	line_buf_init(&line);
	while (tt->filedbmline(&line, etcf, &lineno, &loc)) {

		switch ((*(tt->genent))(line.str, 0, 0)) {
		case GENENT_OK:
			break;
		case GENENT_PARSEERR:
			fprintf(stderr, "parse error: %s (line %d)\n",
				parse_err_msg, lineno);
			exit_val = 2;
			break;
		default:
			return (1);
		}
	}

	return (0);
}


int
isypsym(key)
	datum *key;
{
	if (key->dptr && (key->dsize > 3) && !memcmp(key->dptr, "YP_", 3))
		return (1);

	return (0);
}

int
putdbm()
{
	datum key, val;
	char *line;

	for (key = dbm_firstkey(dbmf); key.dptr; key = dbm_nextkey(dbmf)) {

		if (isypsym(&key))
			continue;

		if (line = tt->fetchdbm(key)) {
			switch ((*(tt->genent))(line, 0, 0)) {
			case GENENT_OK:
				break;
			case GENENT_PARSEERR:
				fprintf(stderr, "parse error: %s (key %.*s)\n",
					parse_err_msg, key.dsize, key.dptr);
				exit_val = 2;
				break;
			default:
				return (1);
			}
		} else {
			fprintf(stderr, "bad dbm file");
			exit(1);
		}
	}

	return (0);
}

/*
 * __nis_form_keys: puts "," as key component separator, as required by
 *	nis_list etc.
 * E.g.: "name=File System Mangement,policy=tsol,id=/usr/sbin/mount" is the
 *	corrent search key for exec_attr.
 *
 */
void
__nis_form_keys(char *keyname)
{
	char *p, *s;

	s = keyname;
	while (s) {
		p = strpbrk(s, tt->filesep);
		if (p == NULL)
			break;
		*p = ',';
		s = ++p;
	}
}

int
addfile(merge)
	int merge;
{
	struct line_buf line;
	char **p;
	datum key;
	datum content;
	datum tmp;
	char *niskey, keyname[NIS_MAXNAMELEN], indexname[NIS_MAXNAMELEN];
	nis_result *eres;
	struct file_loc loc;

	line_buf_init(&line);
	while (tt->filedbmline(&line, etcf, &lineno, &loc)) {

		key = tt->filedbmkey(line.str);
		if (key.dptr == 0) {
			fprintf(stderr,
			    "parse error: zero key length (line %d)\n", lineno);
			continue;
		}

		/* if merging, add key/file_offset to dbm file */
		if (merge) {
			content.dsize = sizeof (loc);
			content.dptr = (char *)&loc;
			tmp = dbm_fetch(dbmf, key);
			if (tmp.dptr == NULL) {
				if (dbm_store(dbmf, key, content, 1) != 0) {
					fprintf(stderr,
						"problem storing  %.*s %.*s\n",
						key.dsize, key.dptr,
						content.dsize, content.dptr);
					dbm_close(dbmf);
					return (1);
				}
			}
		}
		(void) __nis_quote_key(tt->dbmniskey(key), keyname,
		    sizeof (keyname));

		/*
		 * Make sure "," is the separator for multi-component key. E.g.,
		 * "name=File System Mangement,policy=tsol,id=/usr/sbin/mount"
		 * is the correct search key for exec_attr.
		 *
		 * __nis_quote_key puts quotes around ",". Is case of multi-
		 * component key, "," is a separator and should not be in
		 * quotes (requirement of nis_list etc. Hence __nis_form_keys
		 * is called after __nis_quote_key.
		 */
		(void) __nis_form_keys(keyname);

		sprintf(indexname, "[%s],%s", keyname, ta_name);
		eres = nis_list(indexname, fpath|MASTER_ONLY, 0, 0);
		switch (eres->status) {
		case NIS_BADATTRIBUTE:
			fprintf(stderr, "parse error: bad key (line %d)\n",
				lineno);
			break;
		case NIS_SUCCESS:
			switch ((*(tt->genent))(line.str, 0, eres)) {
			case GENENT_OK:
				break;
			case GENENT_PARSEERR:
				fprintf(stderr, "parse error: %s (line %d)\n",
					parse_err_msg, lineno);
				exit_val = 2;
				break;
			default:
				nis_freeresult(eres);
				return (1);
			}
			break;
		case NIS_NOTFOUND:
			switch ((*(tt->genent))(line.str, 0, 0)) {
			case GENENT_OK:
				break;
			case GENENT_PARSEERR:
				fprintf(stderr, "parse error: %s (line %d)\n",
					parse_err_msg, lineno);
				exit_val = 2;
				break;
			default:
				nis_freeresult(eres);
				return (1);
			}
			break;
		default:
			nis_perror(eres->status, "can't list table");
			exit(1);
		}
		nis_freeresult(eres);
	}

	return (0);
}


int
adddbm()
{
	datum key, val;
	char *line;
	char *niskey, keyname[NIS_MAXNAMELEN], indexname[NIS_MAXNAMELEN];
	nis_result *eres;

	for (key = dbm_firstkey(dbmf); key.dptr; key = dbm_nextkey(dbmf)) {

		if (isypsym(&key))
			continue;

		if (line = tt->fetchdbm(key)) {
			(void) __nis_quote_key(tt->dbmniskey(key), keyname,
						sizeof (keyname));
			sprintf(indexname, "[%s],%s", keyname,
					ta_name);
			eres = nis_list(indexname, fpath|MASTER_ONLY, 0, 0);
			switch (eres->status) {
			case NIS_BADATTRIBUTE:
				fprintf(stderr, "bad key (%.*s)\n", key.dsize,
						key.dptr);
				break;
			case NIS_SUCCESS:
				switch ((*(tt->genent))(line, 0, eres)) {
				case GENENT_OK:
					break;
				case GENENT_PARSEERR:
					fprintf(stderr,
					    "parse error: %s (key %.*s)\n",
					    parse_err_msg, key.dsize, key.dptr);
					exit_val = 2;
					break;
				default:
					nis_freeresult(eres);
					return (1);
				}
				break;
			case NIS_NOTFOUND:
				switch ((*(tt->genent))(line, 0, 0)) {
				case GENENT_OK:
					break;
				case GENENT_PARSEERR:
					fprintf(stderr,
					    "parse error: %s (key %.*s)\n",
					    parse_err_msg, key.dsize, key.dptr);
					exit_val = 2;
					break;
				default:
					nis_freeresult(eres);
					return (1);
				}
				break;
			default:
				nis_perror(eres->status, "can't list table");
				exit(1);
			}
			nis_freeresult(eres);

		} else {
			fprintf(stderr, "bad dbm file");
			exit(1);
		}
	}

	return (0);
}


int
deletecback(table, entry, udata)
	nis_name table;
	nis_object *entry;
	void *udata;
{
	datum key;
	char *line;
	nis_result matchres;
	static nis_name last_table = NULL;
	static nis_object *last_entry = NULL;
	nis_name tmp_table = table;
	nis_object *tmp_entry;
	int ret;

	/*
	 * nis_list requires that the previous entry exists
	 * to return the next batch of entries. If we remove
	 * the last entry in a batch, we will not be able to
	 * get any more entries.
	 *
	 * To work around this, we will remember the last entry
	 * and only remove it after obtaining the next entry.
	 * deletecback must be called after nis_list completes
	 * to remove the last entry.
	 */

	if (entry != NULL) {
		key = tt->nisdbmkey(entry);

		if (line = ((char *(*)())udata)(key)) {
			matchres.objects.objects_len = 1;
			matchres.objects.objects_val = entry;

			switch ((*(tt->genent))(line, matchentry, &matchres)) {
			case GENENT_CBERR:
				return (0);
			case GENENT_OK:
				break;
			case GENENT_PARSEERR:
				fprintf(stderr,
				    "parse error (key %.*s)\n",
				    key.dsize, key.dptr);
				exit_val = 2;
				return (1);
			default:
				return (1);
			}
		}

		tmp_entry = nis_clone_object(entry, 0);
		if (tmp_entry == NULL) {
			fprintf(stderr,
				    "Could not clone %s\n", NKEYVAL(0));
			exit_val = 2;
			return (0);
		}
		tmp_table = strdup(table);
		if (tmp_table == NULL) {
			fprintf(stderr, "deletecback:  out of memory\n");
			exit_val = 2;
			return (0);
		}
	} else {
		tmp_entry = NULL;
	}

	if (last_entry == NULL || last_table == NULL) {
		last_table = tmp_table;
		last_entry = tmp_entry;
		return (0);
	}

	ret = removeentry(last_table, last_entry);

	nis_destroy_object(last_entry);
	free(last_table);

	last_table = tmp_table;
	last_entry = tmp_entry;

	return (ret);
}


/*
 *  The deletecback routine is too slow for large files, so we create
 *  a dbm file and then use mergedbm instead.  An exit routine will
 *  clean up the temporary files when we exit.
 */
int
mergefile()
{
	char line[BUFSIZ+1], *p;
	char lname[NIS_MAXNAMELEN];
	datum key;
	datum content;
	datum tmp;
	char *niskey, keyname[NIS_MAXNAMELEN];
	nis_result *eres;
	char *dbmfile;
	FILE *fp;

	/* create dbm file from text file */

	dbmfile = tmpnam((char *)0);

	strcpy(tmpdirbuf, dbmfile);
	strcat(tmpdirbuf, ".dir");
	strcpy(tmppagbuf, dbmfile);
	strcat(tmppagbuf, ".pag");

	fp = fopen(tmpdirbuf, "w");
	if (fp == 0) {
		fprintf(stderr, "can't open %s\n", tmpdirbuf);
		return (1);
	}
	fclose(fp);
	created_dir = 1;

	fp = fopen(tmppagbuf, "w");
	if (fp == 0) {
		fprintf(stderr, "can't open %s\n", tmppagbuf);
		return (1);
	}
	fclose(fp);
	created_pag = 1;

	if ((dbmf = dbm_open(dbmfile, O_RDWR, 0)) == 0) {
		fprintf(stderr, "can't open dbmfile %s\n", dbmfile);
		exit(1);
	}

	if (addfile(1))
		return (1);

	if (mechs && (strcmp(tt->ttype, "publickey") == 0))
		sprintf(lname, "[],%s", ta_name);
	else
		sprintf(lname, "[%s],%s",
			(tt->clrsrch)?tt->clrsrch:"", ta_name);
	eres = nis_list(lname, MASTER_ONLY, deletecback,
		(void*)(fetchfile));
	(void) deletecback(NULL, NULL, NULL);
	if (eres->status != NIS_CBRESULTS &&
	    eres->status != NIS_NOTFOUND) {
		nis_perror(eres->status, "can't list table");
		exit(1);
	}

	nis_freeresult(eres);

	/* dbm files will be removed in cleanup, called at exit */
	dbm_close(dbmf);

	return (0);
}

int
mergedbm()
{
	nis_result *eres;
	char lname[NIS_MAXNAMELEN];

	if ((strcmp(tt->ttype, "publickey") == 0) && mechs) {
		fprintf(stderr,
"Merging of extended Diffie-Hellman keys from NIS(YP) are not supported!\n");
		exit(1);
	}

	if (adddbm())
		return (1);

	sprintf(lname, "[%s],%s",
		(tt->clrsrch)?tt->clrsrch:"", ta_name);
	eres = nis_list(lname, MASTER_ONLY, deletecback, (void*)(tt->fetchdbm));
	(void) deletecback(NULL, NULL, NULL);
	if (eres->status != NIS_CBRESULTS &&
	    eres->status != NIS_NOTFOUND) {
		nis_perror(eres->status, "can't list table");
		exit(1);
	}

	nis_freeresult(eres);
	return (0);
}

void
cleanup()
{
	if (created_dir)
		unlink(tmpdirbuf);
	if (created_pag)
		unlink(tmppagbuf);
}


int
main(int argc, char *argv[])
{
	char *defstr = 0, *ttype, *tname = 0, *ypdomain = 0, *ypmap = 0,
		*etcfile = 0;
	int c;
	int op = OP_ADD;
	nis_result *tres, *rres;
	char rname[NIS_MAXNAMELEN];
	char dbmfile[MAXPATHLEN];

	/*
	 *  We register an exit routine to clean up any temporary
	 *  files.
	 */
	atexit(cleanup);

	mechs = __nis_get_mechanisms(FALSE);

	while ((c = getopt(argc, argv, "D:PAMvapqrmdt:f:y:Y:o")) != -1) {
		switch (c) {
		case 'D':
			defstr = optarg;
			break;
		case 'P':
			fpath = FOLLOW_PATH;
			break;
		case 'A':
			allres = ALL_RESULTS;
			break;
		case 'M':
			master = MASTER_ONLY;
			break;
		case 'p':
			flags |= F_PASSWD;
			break;
		case 'v':
			flags |= F_VERBOSE;
			break;
		case 'a':
			if (op)
				usage();
			op = OP_ADD;
			break;
		case 'r':
			if (op)
				usage();
			op = OP_REPLACE;
			break;
		case 'm':
			if (op)
				usage();
			op = OP_MERGE;
			break;
		case 'd':
			if (op)
				usage();
			op = OP_DUMP;
			break;
		case 'q':
			flags |= F_QUICK;
			break;
		case 't':
			tname = optarg;
			break;
		case 'f':
			if (ypmap || ypdomain)
				usage();
			etcfile = optarg;
			break;
		case 'y':
			if (etcfile)
				usage();
			ypdomain = optarg;
			break;
		case 'Y':
			if (etcfile)
				usage();
			ypmap = optarg;
			break;
		case 'o':
			oldpubkeymode++;
			break;
		default:
			usage();
		}
	}

	if (ypmap && !ypdomain)
		usage();

	if ((op == OP_MERGE) && !ypdomain && !etcfile)
		usage();

	if (argc - optind < 1)
		usage();

	ttype = argv[optind++];

	for (tt = ttypelist; tt->ttype; tt++)
		if (strcmp(tt->ttype, ttype) == 0)
			break;
	if (tt->ttype == 0) {
		fprintf(stderr, "type %s not supported; supported types are:\n",
				ttype);
		for (tt = ttypelist; tt->ttype; tt++)
			fprintf(stderr, "\t%s\n", tt->ttype);
		exit(1);
	}

	if (ypdomain && !ypmap && !(tt->ypmap)) {
		fprintf(stderr, "yp map not known; specify with -Y\n");
		exit(1);
	}

	if (!tname && !(tt->nistbl)) {
		fprintf(stderr, "nis table not known; specify with -t\n");
		exit(1);
	}

	if (argc - optind > 0) {
		nisdomain = argv[optind++];
		if (nisdomain[strlen(nisdomain)-1] != '.') {
			fprintf(stderr,
				"nisdomain must be fully qualified.\n");
			exit(1);
		}
	} else
		nisdomain = nis_local_directory();

	if (argc - optind > 0)
		usage();

	if (!tname)
		tname = tt->nistbl;

	if (tname[strlen(tname)-1] != '.')
		sprintf(ta_name, "%s.%s", tname, nisdomain);
	else
		strcpy(ta_name, tname);

	tres = nis_lookup(ta_name, MASTER_ONLY|FOLLOW_LINKS);
	if (tres->status != NIS_SUCCESS) {
		nis_perror(tres->status, ta_name);
		exit(1);
	}
	ta_obj = tres->objects.objects_val;

	if (ta_obj->zo_data.zo_type != NIS_TABLE_OBJ) {
		fprintf(stderr, "%s is not a table!\n", ta_name);
		exit(1);
	}

	/*
	 * Check type of table
	 */
	if (tt->ta_type) {
		if (strcmp(ta_obj->zo_data.objdata_u.ta_data.ta_type,
			    tt->ta_type)) {
			fprintf(stderr, "%s is not of type %s!\n",
				ta_name, tt->ta_type);
			exit(1);
		}
	} else {
		/*
		 * key-value requires two column table
		 */
		if (ta_obj->zo_data.objdata_u.ta_data.ta_cols.ta_cols_len
		    != 2) {
			fprintf(stderr, "%s is not a two column table!\n",
				ta_name);
			exit(1);
		}
	}
	strcpy(ta_type, ta_obj->zo_data.objdata_u.ta_data.ta_type);

	if (op == OP_DUMP) {
		master = MASTER_ONLY;
		dumptable();
		exit(exit_val);
	}

	if (!nis_defaults_init(defstr))
		exit(1);

	if (nis_default_obj.zo_ttl > ta_obj->zo_ttl)
		nis_default_obj.zo_ttl = ta_obj->zo_ttl;

	if (ypdomain) {
		sprintf(dbmfile, "/var/yp/%s/%s", ypdomain,
			(ypmap)?ypmap:tt->ypmap);
		if ((dbmf = dbm_open(dbmfile, O_RDONLY, 0)) == 0) {
			fprintf(stderr, "can't open dbmfile %s\n", dbmfile);
			exit(1);
		}
	} else if (etcfile) {
		if ((etcf = fopen(etcfile, "r")) == 0) {
			fprintf(stderr, "can't open file %s\n", etcfile);
			exit(1);
		}
	} else {
		etcfile = "stdin";
		etcf = stdin;
	}

	if (flags & F_VERBOSE)
		switch (op) {
		case OP_MERGE:
			printf("merging %s into table %s\n",
				(ypdomain)?dbmfile:etcfile, ta_name);
			break;
		case OP_REPLACE:
		case OP_ADD:
			printf("adding %s to table %s\n",
				(ypdomain)?dbmfile:etcfile, ta_name);
			break;
		}

	switch (op) {
	case OP_REPLACE:
		/*
		 * Handle special case of publickey and RPCSEC_GSS
		 * being configured on this system.
		 */
		if ((strcmp(tt->ttype, "publickey") == 0) && mechs) {
			int		mcount = 0;
			int		verbose = flags & F_VERBOSE;

			while (mechs[mcount]) {
				char authtype[MECH_MAXATNAME+1];

				if (__nis_mechalias2authtype(
						mechs[mcount]->alias,
						authtype,
						MECH_MAXATNAME)) {
					if (verbose)
						printf(
					"clearing table (auth_type=%s) %s\n",
					authtype, ta_name);

					sprintf(rname, "[auth_type=%s],%s",
						authtype, ta_name);
					rres = nis_remove_entry(rname, 0,
								REM_MULTIPLE);
					switch (rres->status) {
					case NIS_NOTFOUND:
					case NIS_SUCCESS:
						break;
					default:
						nis_perror(rres->status,
							"can't clear table");
						exit(1);
					}
					nis_freeresult(rres);
				}
				mcount++;
			}
		} else {
			if (flags & F_VERBOSE) {
				if (tt->clrsrch)
					printf("clearing table (%s) %s\n",
						tt->clrsrch, ta_name);
				else
					printf("clearing table %s\n", ta_name);
			}

			sprintf(rname, "[%s],%s",
				(tt->clrsrch)?tt->clrsrch:"", ta_name);
			rres = nis_remove_entry(rname, 0, REM_MULTIPLE);
			switch (rres->status) {
			case NIS_NOTFOUND:
			case NIS_SUCCESS:
				break;
			default:
				nis_perror(rres->status, "can't clear table");
				exit(1);
			}
			nis_freeresult(rres);
		}

		if (ypdomain)
			putdbm();
		else
			putfile();
		break;

	case OP_ADD:
		if (ypdomain)
			adddbm();
		else
			addfile(0);
		break;

	case OP_MERGE:
		if (ypdomain)
			mergedbm();
		else
			mergefile();
		break;
	}

	if (flags & F_VERBOSE) {
		printf("%d entries added/updated\n", nent_add);
		if (op == OP_MERGE)
			printf("%d entries removed\n", nent_del);
	}

	return (exit_val);
}
