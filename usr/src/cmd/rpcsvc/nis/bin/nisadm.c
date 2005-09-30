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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Ported from SCCS version :
 *	"@(#)nisadm.c 1.14 90/12/12 Copyr 1990 Sun Micro";
 *
 *	nisadm.c
 *
 * This utility is a shell interface to the NIS name service.
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <rpc/rpc.h>
#include <rpcsvc/nis.h>

extern char *optarg;
extern int  optind, opterr;
#define	ZVAL zattr_val.zattr_val_val
#define	ZLEN zattr_val.zattr_val_len
#define	nilstring(s)    ((s) ? (s) : "(nil)")

#define	LOWER(c) (isupper((c)) ? _tolower((c)) : (c))

struct obj_defaults {
	nis_name	oname[512];
	nis_attr	attrs[NIS_MAXATTR];
	table_col	tcols[NIS_MAXCOLUMNS];
	entry_col	ecols[NIS_MAXCOLUMNS];
	nis_server	srvrs[NIS_MAXATTR];
	nis_name	grps[NIS_MAXATTR];
	endpoint	endp[NIS_MAXATTR];
	char		buffer[8192]; /* String space */
};
oar_mask masks[6] = {
		{DEFAULT_RIGHTS, NIS_DIRECTORY_OBJ},
		{DEFAULT_RIGHTS, NIS_GROUP_OBJ},
		{DEFAULT_RIGHTS, NIS_LINK_OBJ},
		{DEFAULT_RIGHTS, NIS_ENTRY_OBJ},
		{DEFAULT_RIGHTS, NIS_TABLE_OBJ},
		{0L, NIS_BOGUS_OBJ}
};

typedef struct obj_defaults obj_defaults;
static obj_defaults *
__get_obj_defaults()
{
	static obj_defaults	*obd = NULL;

	if (obd)
		return (obd);

	obd = (obj_defaults *)malloc(sizeof (obj_defaults));
	if (obd == NULL)
		return (obd);
	memset((char *)obd, 0, sizeof (obj_defaults));

	return (obd);
}

static char *
ask(buf, buflen)
	char	**buf;
	int	*buflen;
{
	char	*a, *s;

	if (feof(stdin))
		return (NULL);

	a = *buf; 	/* Point a at the buffer */
	fflush(stdin);
	if (feof(stdin))
		exit(0);	/* Exit on EOF */
	if (fgets(a, *buflen, stdin) == NULL)
		return (NULL); /* return NULL on EOF */

	s = a + strlen(a); /* Point s at the end of it */
	*(s-1) = '\0'; /* Nul terminate the string */
	*buf = s;
	*buflen = *buflen - (strlen(a)+1);
	return (a);
}

static char *
getname(buf, len)
	char	**buf;
	int	*len;
{
	char		*a, *s;
	nis_name	ldir = nis_local_directory();

	if (feof(stdin))
		return (NULL);

	a = *buf; 	/* Point a at the buffer */
	fflush(stdin);
	if (fgets(a, *len, stdin) == NULL)
		return (NULL); /* return NULL on EOF */

	s = a + strlen(a); /* Point s at the end of it */
	*(s-1) = '\0'; /* Nul terminate the string */
	if (*(s-2) != '.') {
		if (strlen(a))  /* don't prepend a dot on a null name */
			strcat(a, ".");
		strcat(a, ldir);
	}
	s = a + strlen(a) + 1;
	*buf = s;
	*len = *len - (strlen(a)+1);
	return (a);
}

/*
 * Convert two hex digits to one unsigned char byte.
 */
static uchar_t
getbyte(uchar_t *bp)
{
	uchar_t	nyb, val;

	nyb = LOWER(*bp);
	if (nyb >= 'a')
		nyb = (nyb - 'a') + 10;
	else
		nyb = (nyb - '0');
	if (nyb > 15)
		fprintf(stderr, "Illegal character in binary data, '%c'\n",
				*bp);
	val = (nyb & 0xf) << 4;

	nyb = LOWER(*(bp+1));
	if (nyb >= 'a')
		nyb = (nyb - 'a') + 10;
	else
		nyb = (nyb - '0');
	if (nyb > 15)
		fprintf(stderr, "Illegal character in binary data, '%c'\n",
				*(bp+1));
	val |= (nyb & 0xf);
	return (val);
}

#define	xask(x) { fflush(stdin); \
		if (feof(stdin))\
			return (NULL); \
		fgets(x, 32, stdin); \
		x[strlen(x)-1] = '\0'; }

/*
 * nis_get_object()
 *
 * This object will query the user for an object of the type specified
 * in the 'type' variable. All of it's queries go to stdin.
 */
nis_object *
nis_get_object(char *name, char *group, char *owner,
    ulong_t rights, ulong_t ttl, zotypes type)
{
	/*
	 * These variables define a string buffer array that is used
	 * while fetching the object, later the data is cloned so we
	 * can toss it. Yes, it's a giant hunk to put on the stack.
	 */
#define	BUFLENGTH 4096
	char		buffer[BUFLENGTH];
	char 		*bp = &buffer[0]; /* For various uses */
	int		bl = BUFLENGTH;
	char		tmpval[32], *s; /* for fetching numbers and such */
	char		*t;	/* temporary */
	nis_object	*obj, tmp;
	int		np, i, j;
	ulong_t		flags;
	obj_defaults	*ob_data = __get_obj_defaults();
	link_obj	*li;
	directory_obj	*di;
	entry_obj	*en;
	group_obj	*gr;
	table_obj	*ta;

	memset((char *)&tmp, 0, sizeof (tmp));

	printf("Creating NIS object... \n");
	if (! name) {
		printf("Enter objects name : ");
		name = getname(&bp, &bl);
		if (!name)
			return (NULL);
	}
	s = (char *)nis_leaf_of(name);
	if (s)
		strcpy(bp, s);
	else
		strcpy(bp, "<none>");

	tmp.zo_name = bp;
	bl = bl - strlen(bp) - 1;
	bp = bp + strlen(bp) + 1;

	if (owner)
		tmp.zo_owner   = owner;
	else
		tmp.zo_owner   = nis_local_principal();

	if (group)
		tmp.zo_group   = group;
	else
		tmp.zo_group   = nis_local_group();

	if (rights)
		tmp.zo_access  = rights;
	else
		tmp.zo_access  = DEFAULT_RIGHTS;

	if (ttl)
		tmp.zo_ttl = ttl;
	else
		tmp.zo_ttl = 24 * 3600;

	/* name must be fully qualified */
	tmp.zo_domain  = nis_domain_of(name);
	if (tmp.zo_domain == NULL)
		tmp.zo_domain = ".";

	if (type == NIS_BOGUS_OBJ) {
		tmp.zo_data.zo_type = NIS_BOGUS_OBJ;
		while (tmp.zo_data.zo_type == NIS_BOGUS_OBJ) {
			printf("Enter the objects type : ");
			xask(tmpval);
			if (LOWER(tmpval[0]) == 'g')
				tmp.zo_data.zo_type = NIS_GROUP_OBJ;
			else if (LOWER(tmpval[0]) == 't')
				tmp.zo_data.zo_type = NIS_TABLE_OBJ;
			else if (LOWER(tmpval[0]) == 'd')
				tmp.zo_data.zo_type = NIS_DIRECTORY_OBJ;
			else if (LOWER(tmpval[0]) == 'e')
				tmp.zo_data.zo_type = NIS_ENTRY_OBJ;
			else if (LOWER(tmpval[0]) == 'l')
				tmp.zo_data.zo_type = NIS_LINK_OBJ;
			else if (LOWER(tmpval[0]) == 'p')
				tmp.zo_data.zo_type = NIS_PRIVATE_OBJ;
		}
	} else
		tmp.zo_data.zo_type = type;

	switch (tmp.zo_data.zo_type) {
		case NIS_GROUP_OBJ :
			gr = &(tmp.GR_data);
			printf("Enter flags value [IRN] ? ");
			xask(tmpval);
			gr->gr_flags = 0;
			for (s = &tmpval[0]; *s; s++) {
				if (LOWER(*s) == 'i')
					gr->gr_flags |= IMPMEM_GROUPS;
				else if (LOWER(*s) == 'r')
					gr->gr_flags |= RECURS_GROUPS;
				else if (LOWER(*s) == 'n')
					gr->gr_flags |= NEGMEM_GROUPS;
				else {
					printf("Must be some combo of :\n");
					printf("\tR = Recursive groups ok\n");
					printf("\tN = Negative groups ok\n");
					printf("\tI = Implicit groups ok\n");
					exit(1);
				}
			}
			do {
				printf("Number of members in this group ? ");
				xask(tmpval);
				np = atoi(tmpval);
				if ((np < 1) || (np > NIS_MAXATTR))
					printf("Illegal number of members.\n");
			} while ((np < 1) || (np > NIS_MAXATTR));
			gr->gr_members.gr_members_len = np;
			gr->gr_members.gr_members_val = &(ob_data->grps[0]);
			for (i = 0; i < np; i++) {
				printf("\tMember #%d name :\n", i);
				ob_data->grps[i] = getname(&bp, &bl);
			}
			break;
		case NIS_LINK_OBJ :

			li = &(tmp.LI_data);
			type = NIS_BOGUS_OBJ;
			while (type == NIS_BOGUS_OBJ) {
				printf(
			"Linked object, enter real type [Group/Table/Entry] :");
				xask(tmpval);
				if (LOWER(tmpval[0]) == 'g')
					type = NIS_GROUP_OBJ;
				else if (LOWER(tmpval[0]) == 't')
					type = NIS_TABLE_OBJ;
				else if (LOWER(tmpval[0]) == 'd')
					type = NIS_DIRECTORY_OBJ;
				else if (LOWER(tmpval[0]) == 'e')
					type = NIS_ENTRY_OBJ;
				else
					type = NIS_BOGUS_OBJ;
			}
			li->li_rtype = type;
			do {
				printf("Number of attributes in this name ? ");
				xask(tmpval);
				np = atoi(tmpval);
				if ((np < 0) || (np > NIS_MAXATTR))
					fprintf(stderr,
					"Illegal number of attributes.\n");
			} while ((np < 0) || (np > NIS_MAXATTR));
			for (i = 0; i < np; i++) {
				printf("Attribute #%d\n", i);
				printf("\tAttribute Name : ");
				ob_data->attrs[i].zattr_ndx = ask(&bp, &bl);
				printf("\tAttribute Value : ");
				ob_data->attrs[i].ZVAL = ask(&bp, &bl);
				ob_data->attrs[i].ZLEN =
					    strlen(ob_data->attrs[i].ZVAL) + 1;
			}
			printf("Enter Linked name : ");
			li->li_name = getname(&bp, &bl);
			li->li_attrs.li_attrs_len = np;
			li->li_attrs.li_attrs_val = &(ob_data->attrs[0]);
			break;
		case NIS_TABLE_OBJ :

			ta = &(tmp.TA_data);
			printf("Enter table type : ");
			ta->ta_type = ask(&bp, &bl);
			do {
				printf("Number of columns in this table ? ");
				xask(tmpval);
				np = atoi(tmpval);
				if ((np < 1) || (np > NIS_MAXCOLUMNS))
					printf("Illegal number of columns.\n");
			} while ((np < 1) || (np > NIS_MAXCOLUMNS));
			ta->ta_maxcol = np;
			printf("Enter separator character : ");
			xask(tmpval);
			ta->ta_sep = (tmpval[0] == '\0') ? ' ' : tmpval[0];
			printf("Enter Search path : ");
			ta->ta_path = ask(&bp, &bl);
			for (i = 0; i < np; i++) {
				int	tmplen;

				printf("Column #%d : \n", i+1);
				printf("\tEnter Name : ");
				ob_data->tcols[i].tc_name = ask(&bp, &bl);
				ob_data->tcols[i].tc_rights = DEFAULT_RIGHTS;
				printf("\tEnter Flags [S/C/B/X] : ");
				xask(tmpval);
				tmplen = strlen(tmpval);
				for (j = 0, flags = 0; j < tmplen; j++) {
					if (LOWER(tmpval[j]) == 'x')
						flags |= TA_XDR;
					else if (LOWER(tmpval[j]) == 'c')
						flags |= TA_CASE;
					else if (LOWER(tmpval[j]) == 'b')
						flags |= TA_BINARY;
					else if (LOWER(tmpval[j]) == 's')
						flags |= TA_SEARCHABLE;
				}
				if ((flags & TA_SEARCHABLE) &&
				    (strlen(ob_data->tcols[i].tc_name) == 0)) {
					fprintf(stderr,
			    "Can't have a searchable column with no name.\n");
					return (NULL);

				}
				ob_data->tcols[i].tc_flags = flags;
			}
			ta->ta_cols.ta_cols_len = np;
			ta->ta_cols.ta_cols_val = &(ob_data->tcols[0]);
			break;
		case NIS_DIRECTORY_OBJ :

			di = &(tmp.DI_data);
			printf("This new directory's name : ");
			di->do_name = getname(&bp, &bl);
			do {
				printf(
				"Number of servers for this directory? ");
				xask(tmpval);
				np = atoi(tmpval);
				if ((np < 1) || (np > NIS_MAXATTR))
					printf("Illegal number of servers.\n");
			} while ((np < 1) || (np > NIS_MAXATTR));

			for (i = 0; i < np; i++) {
				if (i == 0)
					printf("Enter Master server name    :");
				else
					printf("Enter replicate server name :");
				ob_data->srvrs[i].name = getname(&bp, &bl);
				printf("Enter Universal Address : ");
				ob_data->endp[i].uaddr  = ask(&bp, &bl);
				ob_data->endp[i].family = "INET";
				ob_data->endp[i].proto  = "TCP";
				ob_data->srvrs[i].key_type = NIS_PK_NONE;
				ob_data->srvrs[i].pkey.n_len = 0;
				ob_data->srvrs[i].pkey.n_bytes = NULL;
				ob_data->srvrs[i].ep.ep_val = &ob_data->endp[0];
				ob_data->srvrs[i].ep.ep_len = 1;
			}
			di->do_servers.do_servers_len = np;
			di->do_servers.do_servers_val = &ob_data->srvrs[0];
			do {
				printf("Enter ns type [Z/Y/D] :");
				xask(tmpval);
				if (LOWER(tmpval[0]) == 'z')
					di->do_type = NIS;
				else if (LOWER(tmpval[0]) == 'y')
					di->do_type = SUNYP;
				else if (LOWER(tmpval[0]) == 'd')
					di->do_type = DNS;
				else
					di->do_type = IVY;
			} while (di->do_type == IVY); /* XXX */
			printf("Enter time to live value : ");
			xask(tmpval);
			di->do_ttl = atoi(tmpval);
			if (! (di->do_ttl))
				fprintf(stderr,
				"Warning, ttl = 0 prohibits caching.\n");
			di->do_armask.do_armask_len = 6;
			di->do_armask.do_armask_val = &masks[0];
			break;
		case NIS_ENTRY_OBJ :
			en = &(tmp.EN_data);
			/* Presumed to be the same. */
			printf("Enter entry type : ");
			en->en_type = ask(&bp, &bl);
			if (!en->en_type)
				return (NULL);
			do {
				printf("Number of columns for this entry ? ");
				xask(tmpval);
				np = atoi(tmpval);
				if ((np < 1) || (np > NIS_MAXCOLUMNS))
					printf("Illegal number of columns.\n");
			} while ((np < 1) || (np > NIS_MAXCOLUMNS));

			for (i = 0; i < np; i++) {
				entry_col	*ec;
				uchar_t		*val;
				int		len;

				ec = &(ob_data->ecols[i]);
				printf("Column #%d :\n", i+1);
				printf("\tEnter Flags [M/C/B/X] : ");
				xask(tmpval);
				len = strlen(tmpval);
				for (j = 0, flags = 0; j < len; j++) {
					if (LOWER(tmpval[j]) == 'x')
						flags |= EN_XDR;
					else if (LOWER(tmpval[j]) == 'c')
						flags |= EN_CRYPT;
					else if (LOWER(tmpval[j]) == 'b')
						flags |= EN_BINARY;
					else if (LOWER(tmpval[j]) == 'm')
						flags |= EN_MODIFIED;
					else
						printf("** Unknown flag '%c'\n",
								tmpval[j]);
				}
				ec->ec_flags = flags;
				printf("\tValue : ");
				val = (uchar_t *)ask(&bp, &bl);
				len = strlen((char *)val)+1;
				if (flags & EN_BINARY) {
					for (j = 0; j < len; j += 2)
						*(val + (j>>1)) =
							getbyte(val+j);
					len = len >> 1; /* Half the bytes */
				}
				ec->ec_value.ec_value_val = (char *)val;
				ec->ec_value.ec_value_len = len;
			}
			en->en_cols.en_cols_len = np;
			en->en_cols.en_cols_val = &(ob_data->ecols[0]);
			break;
		case NIS_PRIVATE_OBJ:
			printf("Data length : ");
			xask(tmpval);
			i = atoi(tmpval);
			tmp.zo_data.objdata_u.po_data.po_data_len = i;
			tmp.zo_data.objdata_u.po_data.po_data_val = bp;
			for (j = 0; j < i; j++) {
				xask(tmpval);
				*(bp+j) = getbyte((uchar_t *)tmpval);
			}
			break;

	}
	obj = nis_clone_object(&tmp, NULL); /* Create a "clean" copy */

	return (obj);
}
void
usage(nm)
	char	*nm;
{
	fprintf(stderr,
"usage : %s -C|a|A|r|R|m|p|l|L [-t G|E|D|L|T] [-S] [-o file] name\n", nm);
}

char	*nis_errors[] = {
		"SUCCESS",
		"S_SUCCESS",
		"NOTFOUND",
		"S_NOTFOUND",
		"CACHEEXPIRED",
		"NAMEUNREACHABLE",
		"UNKNOWNOBJ",
		"TRYAGAIN",
		"SYSTEMERROR",
		"CHAINBROKEN",
		"PERMISSION",
		"NOTOWNER",
		"NOT_ME",
		"NOMEMORY",
		"NAMEEXISTS",
		"NOTMASTER",
		"INVALIDOBJ",
		"BADNAME",
		"NOCALLBACK",
		"CBRESULTS",
		"NOSUCHNAME",
		"NOTUNIQUE",
		"IBMODERROR",
		"NOSUCHTABLE",
		"TYPEMISMATCH",
		"LINKNAMEERROR",
		"PARTIAL",
		"TOOMANYATTRS",
		"RPCERROR",
		"BADATTRIBUTE",
		"NOTSEARCHABLE",
		"CBERROR",
		"FOREIGNNS",
		"BADOBJECT",
		"NOTSAMEOBJ",
		"MODFAIL",
		"BADREQUEST",
		"NOTEMPTY"
};

static char *
text_of(s)
	nis_error s;
{
	static char	*bg = "BOGUS_ERROR";

	if (s > NIS_NOTEMPTY)
		return (bg);
	else
		return (nis_errors[s]);
}


void
print_stats(r)
	nis_result	*r;
{
	fprintf(stderr, "%s:C=%d:A=%d:D=%d:S=%d:\n", text_of(r->status),
			r->cticks, r->aticks, r->dticks, r->zticks);
}

enum op_todo {NOP, ADD, ADD_NS, REMOVE, REMOVE_OBJ, REM_DIR, MODIFY,
		PRINT, LIST, CHECKPOINT, LOOKUP};
XDR	in_xdrs, out_xdrs;

void
put_obj(obj, f)
	nis_object	*obj;
	int		f;
{
	if (f)
		nis_print_object(obj);
	else
		xdr_nis_object(&out_xdrs, obj);
}

nis_object *
get_obj(name, type, f)
	nis_name	name;
	zotypes		type;
	int		f;
{
	nis_object	*obj;
	char		*s;
	int		stat;

	if (f) {
		obj = nis_get_object(name, NULL, NULL, 0, 0, type);
		stat = TRUE;
	} else {
		obj = (nis_object *)(calloc(1, sizeof (nis_object)));
		stat = xdr_nis_object(&in_xdrs, obj);
		if (! stat) {
			free(obj);
			obj = NULL;
		} else if (name) {
			/* We "rewrite" the name of the object. */
			free(obj->zo_name);
			obj->zo_name = strdup(nis_leaf_of(name));
			free(obj->zo_domain);
			obj->zo_domain = strdup(nis_domain_of(name));
		}
	}
	/* FIXUP for some old objects */
	if (obj) {
		s = obj->zo_name;
		if (s[strlen(s)-1] == '.')
			s[strlen(s)-1] = '\0';
	}

	return	(obj); /* will be NULL if undecodable */
}

/*
 * Attempt to actually create the directories for a particular
 * dir object.
 */
static void
make_directory(nis_object *obj)
{
	directory_obj	*da;
	nis_server	*srvs;
	int		i, ms;
	nis_error	status;

	da = &(obj->DI_data);
	ms = da->do_servers.do_servers_len;
	srvs = da->do_servers.do_servers_val;
	for (i = 0; i < ms; i++) {
		printf("Attempting to create directory \"%s\"\n", da->do_name);
		status = nis_mkdir(da->do_name, &(srvs[i]));
	}
}

/*
 * Attempt to actually remove the directories for a particular
 * dir object.
 */
static void
remove_dir(nis_object *obj)
{
	directory_obj	*da;
	nis_server	*srvs;
	int		i, ms;
	nis_error	status;

	da = &(obj->DI_data);
	ms = da->do_servers.do_servers_len;
	srvs = da->do_servers.do_servers_val;
	for (i = 0; i < ms; i++) {
		printf("Attempting to remove directory \"%s\"\n", da->do_name);
		status = nis_rmdir(da->do_name, &(srvs[i]));
	}
}


char		name_buf[1024];		/* Temp buffer for names */
/*
 * Construct a legal NIS name from the object components.
 * Uses static name buffer above.
 */
char *
make_name(name, domain)
	nis_name	name;
	nis_name	domain;
{

	strcpy(name_buf, name);
	if (domain[0] != '.')
		strcat(name_buf, ".");
	strcat(name_buf, domain);
	if (name_buf[strlen(name_buf)-1] != '.')
		strcat(name_buf, ".");
	return (name_buf);
}

/*
 * Main code for the nisadm command
 */

int
main(int argc, char *argv[])
{
	enum op_todo 	op = PRINT;		/* Operation to perform	*/
	zotypes		obj_type = 0;		/* Object "type" to use	*/
	ib_request	req;			/* Request to use	*/
	int		stats = FALSE;		/* Print statistics	*/
	ulong_t		flags = 0, 		/* Lookup flags		*/
			err = 0;		/* errors encountered	*/
	int		interact = FALSE,	/* Interactive input	*/
			prettyprint = FALSE;	/* Print in ASCII text	*/
	char		*s,			/* Some temporaries	*/
			*name,			/* NIS name to look up 	*/
			*rname;			/* name to look up 	*/
	int		i, j;			/* More temporaries	*/
	nis_object	*obj;			/* Working object	*/
	char		real_name[1024];	/* discovered name	*/
	nis_result	*res;			/* Operation result	*/
	int		c;

	if (strcmp(argv[0], "zadd") == 0)
		op = ADD;
	else if (strcmp(argv[0], "zrem") == 0)
		op = REMOVE;
	else if (strcmp(argv[0], "zmod") == 0)
		op = MODIFY;
	else if (strcmp(argv[0], "zlist") == 0)
		op = LIST;
	else if (strcmp(argv[0], "zdump") == 0) {
		op = LIST;
		prettyprint = TRUE;
	}


	while ((c = getopt(argc, argv, "CARLarmpit:SlF:")) != -1) {
		switch (c) {
		case 'a' :
			op = ADD;
			break;
		case 'A' :
			op = ADD_NS;
			break;
		case 'R' :
			op = REMOVE_OBJ;
			break;
		case 'r' :
			op = REMOVE;
			break;
		case 'm' :
			op = MODIFY;
			break;
		case 'L' :
			op = LIST;
			break;
		case 'l' :
			op = LOOKUP;
			break;
		case 'p' :
			prettyprint = TRUE;
			break;
		case 'i' :
			interact = TRUE;
			break;
		case 'S' :
			stats = TRUE;
			break;
		case 'C' :
			op = CHECKPOINT;
			break;
		case 'F' :
			for (s = optarg; *s; s++) {
				switch (*s) {
					case 'h' :
						flags |= HARD_LOOKUP;
						break;
					case 'f' :
						flags |= FOLLOW_LINKS;
						break;
					case 'p' :
						flags |= FOLLOW_PATH;
						break;
					case 'c' :
						flags |= NO_CACHE;
						break;
					case 'a' :
						flags |= ALL_RESULTS;
						break;
					case 'm' :
						flags |= MASTER_ONLY;
						break;
					default :
						fprintf(stderr, "bad flag\n");
						err++;
				}
			}
			break;
		case 't':
			switch (*optarg) {
				case 'G' :
					obj_type = NIS_GROUP_OBJ;
					break;
				case 'D' :
					obj_type = NIS_DIRECTORY_OBJ;
					break;
				case 'T' :
					obj_type = NIS_TABLE_OBJ;
					break;
				case 'E' :
					obj_type = NIS_ENTRY_OBJ;
					break;
				case 'L' :
					obj_type = NIS_LINK_OBJ;
					break;
				default :
					fprintf(stderr,
						"unknown object type\n");
					err++;
					break;
			}
			break;
		case '?' :
			usage(argv[0]);
			exit(1);
		default :
			err++;
			break;
		}
	}
	for (name = NULL; optind < argc; optind++) {
		if ((name) || (*argv[optind] == '-')) {
			fprintf(stderr, "Extra input beyond name.\n");
			err++;
		} else
			name = argv[optind];
	}

	if (err || name == NULL) {
		usage(argv[0]);
		exit(1);
	}

	if (name[strlen(name) - 1] != '.') {
		res = nis_lookup(name, EXPAND_NAME);
		if (res->status != NIS_SUCCESS) {
			fprintf(stderr, "unable to locate \"%s\"\n", name);
			exit(1);
		}
		sprintf(real_name, "%s.%s", res->objects.objects_val->zo_name,
				    res->objects.objects_val->zo_domain);
		name = real_name;
		nis_freeresult(res);
	}

	if (! interact)
		xdrstdio_create(&in_xdrs, stdin, XDR_DECODE);

	if (! prettyprint)
		xdrstdio_create(&out_xdrs, stdout, XDR_ENCODE);

	switch (op) {
		case ADD :
		case ADD_NS :
			while ((obj = get_obj(name, obj_type, interact))) {

				rname = make_name(obj->zo_name, obj->zo_domain);
				if ((__type_of(obj) == NIS_ENTRY_OBJ) &&
								(op == ADD))
					res = nis_add_entry(rname, obj, 0);
				else
					res = nis_add(rname, obj);
				if (stats)
					print_stats(res);
				if (res->status != NIS_SUCCESS) {
					if (!stats)
						print_stats(res);
					err = res->status;
					if (__type_of(obj) != NIS_ENTRY_OBJ)
						break;
				}
				if (__type_of(obj) == NIS_DIRECTORY_OBJ)
					make_directory(obj);

				nis_destroy_object(obj);
			}
			break;

		case REMOVE_OBJ :
			if (interact) {
				fprintf(stderr,
			"This option cannot use user typed in objects.\n");
				break;
			}
			while ((obj = get_obj(name, obj_type, 0))) {
				rname = make_name(obj->zo_name, obj->zo_domain);
				if (__type_of(obj) == NIS_ENTRY_OBJ)
					res = nis_remove_entry(rname, obj, 0);
				else
					res = nis_remove(rname, obj);
				if (stats)
					print_stats(res);
				if (res->status != NIS_SUCCESS) {
					if (!stats)
						print_stats(res);
					nis_print_object(obj);
					err = res->status;
				}
				nis_destroy_object(obj);
			}
			break;

		case REMOVE :
			if (name == NULL) {
				fprintf(stderr,
			"Name required for remove operation.\n");
				exit(1);
			}
			strcpy(name_buf, name);
			if (name_buf[strlen(name_buf)-1] != '.')
					strcat(name_buf, ".");

			if (obj_type == NIS_DIRECTORY_OBJ) {
				res = nis_lookup(name_buf, 0);
				if (NIS_RES_STATUS(res) != NIS_SUCCESS) {
					err = res->status;
					break;
				}
				obj = nis_clone_object(NIS_RES_OBJECT(res),
									NULL);
				nis_freeresult(res);
				res = nis_remove(name_buf, obj);
				if (NIS_RES_STATUS(res) == NIS_SUCCESS) {
					remove_dir(obj);
				}
				nis_destroy_object(obj);
				if ((stats) || (NIS_RES_STATUS(res)
								!= NIS_SUCCESS))
					print_stats(res);
				err = NIS_RES_STATUS(res);
				nis_freeresult(res);
				break;
			}
			nis_get_request(name_buf, NULL, NULL, &req);
			if (req.ibr_srch.ibr_srch_len)
				res = nis_remove_entry(name_buf, NULL, 0);
			else
				res = nis_remove(name_buf, NULL);
			nis_free_request(&req);
			if ((stats) || (NIS_RES_STATUS(res) != NIS_SUCCESS))
				print_stats(res);
			if (res->status != NIS_SUCCESS)
				err = res->status;
			break;

		case MODIFY :
			while ((obj = get_obj(name, obj_type, interact))) {
				rname = make_name(obj->zo_name, obj->zo_domain);
				if (__type_of(obj) == NIS_ENTRY_OBJ)
					res = nis_modify_entry(rname, obj, 0);
				else
					res = nis_modify(rname, obj);
				if (stats)
					print_stats(res);
				if (res->status != NIS_SUCCESS) {
					if (!stats)
						print_stats(res);
					err = res->status;
				}
				nis_destroy_object(obj);
			}
			break;

		case LOOKUP :
		case LIST :
			if (name == NULL) {
				fprintf(stderr,
			"Name required for List or Lookup operation.\n");
				exit(1);
			}
			strcpy(name_buf, name);
			if (name_buf[strlen(name_buf)-1] != '.')
					strcat(name_buf, ".");

			nis_get_request(name_buf, NULL, NULL, &req);
			if ((op == LIST) || (req.ibr_srch.ibr_srch_len != 0))
				res = nis_list(name_buf, flags, NULL, NULL);
			else
				res = nis_lookup(req.ibr_name, flags);
			nis_free_request(&req);
			if (res->status == NIS_SUCCESS) {
				if (stats)
					print_stats(res);
				for (i = 0; i < res->objects.objects_len; i++) {
					put_obj((res->objects.objects_val)+ i,
							prettyprint);
				}
			}
			if (stats)
				print_stats(res);

			if (res->status != NIS_SUCCESS) {
				if (!stats)
					print_stats(res);
				err = res->status;
				break;
			}
			break;

		case PRINT :
			while ((obj = get_obj(name, obj_type, interact))) {
				put_obj(obj, prettyprint);
				nis_destroy_object(obj);
			}
			break;

		case CHECKPOINT :
			if (! name) {
				fprintf(stderr,
				    "Name required for Checkpoint operation.");
				err++;
				break;
			}
			strcpy(name_buf, name);
			if (name_buf[strlen(name_buf)-1] != '.')
					strcat(name_buf, ".");

			res = nis_checkpoint(name_buf);
			if (stats)
				print_stats(res);
			if (res->status != NIS_SUCCESS) {
				if (!stats)
					print_stats(res);
				err = res->status;
			}
			break;

		default :
			fprintf(stderr, "Unknown operation requested.\n");
			err = -1;
			break;

	}

	if (! interact)
		xdr_destroy(&in_xdrs);
	else
		printf("\n");

	if (! prettyprint)
		xdr_destroy(&out_xdrs);

	return (err);
}
