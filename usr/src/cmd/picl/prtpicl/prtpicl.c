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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <alloca.h>
#include <libintl.h>
#include <locale.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/termios.h>
#include <picl.h>

/*
 * Constant definitions and macros
 */
#define	COL_DELIM		"|"
#define	ROOT_LEVEL		0
#define	LEVEL_INDENT		4
#define	PROP_INDENT		2
#define	NCOLS			80
#define	NODEINFO_LEFT_MARGIN(x)	(x * LEVEL_INDENT)
#define	PROPINFO_LEFT_MARGIN(x)	(x * LEVEL_INDENT + PROP_INDENT)

#define	PRIxPICLTBL		PRIx64
#define	PRIxPICLHDL		PRIx64

/*
 * Program variables
 */
static	char	*prog;
static	int	verbose_mode = 0;

/*
 * Error codes
 */
#define	EM_USAGE		0
#define	EM_INIT			1
#define	EM_GETROOT		2
#define	EM_GETPVAL		3
#define	EM_GETNXTBYCOL		4
#define	EM_GETNXTBYROW		5
#define	EM_GETPINFO		6
#define	EM_GETPVALBYNAME	7
#define	EM_GETPROPBYNAME	8
#define	EM_INT_INVSIZE		9
#define	EM_UINT_INVSIZE		10
#define	EM_FLOAT_INVSIZE	11
#define	EM_TS_INVALID		12
#define	EM_TABLE_INVSIZE	13
#define	EM_REF_INVSIZE		14
#define	EM_TYPE_UNKNOWN		15
#define	EM_TS_OVERFLOW		16
#define	EM_TS_INVSIZE		17

/*
 * Error mesage texts
 */
static	char	*err_msg[] = {
	/* program usage */
	"Usage: %s [-v] [-c <picl_class>]\n",			/*  0 */
	/* picl call failed messages */
	"picl_initialize failed: %s\n",				/*  1 */
	"picl_get_root failed: %s\n",				/*  2 */
	"picl_get_propval failed: %s\n",			/*  3 */
	"picl_get_next_by_col failed: %s\n",			/*  4 */
	"picl_get_next_by_row failed: %s\n",			/*  5 */
	"picl_get_propinfo failed: %s\n",			/*  6 */
	"picl_get_propval_by_name failed: %s\n",		/*  7 */
	"picl_get_prop_by_name failed: %s\n",			/*  8 */
	/* invalid data error messages */
	"picl_get_propval: invalid int size %d\n",		/*  9 */
	"picl_get_propval: invalid unsigned int size %d\n",	/* 10 */
	"picl_get_propval: invalid float size %d\n",		/* 11 */
	"picl_get_propval: invalid timestamp\n",		/* 12 */
	"picl_get_propval: invalid table handle size %d\n",	/* 13 */
	"picl_get_propval: invalid reference size %d\n",	/* 14 */
	"picl_get_propval: unknown type\n",			/* 15 */
	"picl_get_propval: timestamp value too large\n",	/* 16 */
	"picl_get_propval: invalid timestamp size\n"		/* 17 */
};

/*PRINTFLIKE1*/
static void
print_errmsg(char *message, ...)
{
	va_list ap;

	va_start(ap, message);
	(void) fprintf(stderr, "%s: ", prog);
	(void) vfprintf(stderr, message, ap);
	va_end(ap);
}

/*
 * Print prtpicl usage
 */
static void
usage(void)
{
	print_errmsg(gettext(err_msg[EM_USAGE]), prog);
	exit(1);
}

/*
 * print a bytearray value and format it to fit in 80 columns
 */
static void
print_bytearray(int lvl, uint8_t *vbuf, size_t nbytes)
{
	int		cnum;
	int		columns;
	char		*s;
	struct winsize	winsize;
	size_t		i;

	/*
	 * The COLUMNS_PER_BYTE is set to 4 to match the printf
	 * format used below, i.e. " %02x ", to print a byte
	 */
#define	COLUMNS_PER_BYTE	4

	/*
	 * Kind of a hack to determine the width of the output...
	 */
	columns = NCOLS;
	if ((s = getenv("COLUMNS")) != NULL && (cnum = atoi(s)) > 0)
		columns = cnum;
	else if (isatty(fileno(stdout)) &&
	    ioctl(fileno(stdout), TIOCGWINSZ, &winsize) == 0 &&
	    winsize.ws_col != 0)
		columns = winsize.ws_col;


	cnum = PROPINFO_LEFT_MARGIN(lvl);
	if ((nbytes * COLUMNS_PER_BYTE + cnum) > columns) {
		(void) printf("\n");
		cnum = 0;
	}
	for (i = 0; i < nbytes; ++i) {
		if (cnum > columns - COLUMNS_PER_BYTE) {
			(void) printf("\n");
			cnum = 0;
		}
		(void) printf(" %02x ", vbuf[i]);
		cnum += COLUMNS_PER_BYTE;
	}
}

/*
 * Print a property's value
 * If the property is read protected, return success.
 * If an invalid/stale handle error is encountered, return the error. For
 * other errors, print a message and return success.
 */
static int
print_propval(int lvl, picl_prophdl_t proph, const picl_propinfo_t *propinfo)
{
	int		err;
	void		*vbuf;
	char		*str;
	uint64_t	val64;
	time_t		tmp;

	/*
	 * If property is read protected, print a message and continue
	 */
	if (!(propinfo->accessmode & PICL_READ)) {
		(void) printf("<%s>", gettext("WRITE-ONLY"));
		return (PICL_SUCCESS);
	}

	vbuf = alloca(propinfo->size);
	if (propinfo->type == PICL_PTYPE_VOID)
		return (PICL_SUCCESS);

	err = picl_get_propval(proph, vbuf, propinfo->size);
	/*
	 * If the error is not a stale/invalid handle or noresponse, continue
	 * by ignoring the error/skipping the property.
	 */
	if ((err == PICL_INVALIDHANDLE) || (err == PICL_STALEHANDLE) ||
	    (err == PICL_NORESPONSE))
		return (err);
	else if (err != PICL_SUCCESS) {
		(void) printf("<%s: %s>", gettext("ERROR"), picl_strerror(err));
		return (PICL_SUCCESS);
	}

	switch (propinfo->type) {
	case PICL_PTYPE_CHARSTRING:
		if (propinfo->size > 0)
			(void) printf(" %s ", (char *)vbuf);
		break;
	case PICL_PTYPE_INT:
		switch (propinfo->size) {
		case sizeof (int8_t):
			/* avoid using PRId8 until lint recognizes hh */
			(void) printf(" %d ", *(int8_t *)vbuf);
			break;
		case sizeof (int16_t):
			(void) printf(" %" PRId16 " ", *(int16_t *)vbuf);
			break;
		case sizeof (int32_t):
			(void) printf(" %" PRId32 " ", *(int32_t *)vbuf);
			break;
		case sizeof (int64_t):
			(void) printf(" %" PRId64 " ", *(int64_t *)vbuf);
			break;
		default:
			print_errmsg(gettext(err_msg[EM_INT_INVSIZE]),
			    propinfo->size);
			return (PICL_FAILURE);
		}
		break;
	case PICL_PTYPE_UNSIGNED_INT:
		switch (propinfo->size) {
		case sizeof (uint8_t):
			/* avoid using PRIx8 until lint recognizes hh */
			(void) printf(" %#x ", *(uint8_t *)vbuf);
			break;
		case sizeof (uint16_t):
			(void) printf(" %#" PRIx16 " ", *(uint16_t *)vbuf);
			break;
		case sizeof (uint32_t):
			(void) printf(" %#" PRIx32 " ", *(uint32_t *)vbuf);
			break;
		case sizeof (uint64_t):
			(void) printf(" %#" PRIx64 " ", *(uint64_t *)vbuf);
			break;
		default:
			print_errmsg(gettext(err_msg[EM_UINT_INVSIZE]),
			    propinfo->size);
			return (PICL_FAILURE);
		}
		break;
	case PICL_PTYPE_FLOAT:
		switch (propinfo->size) {
		case sizeof (float):
			(void) printf(" %f ", *(float *)vbuf);
			break;
		case sizeof (double):
			(void) printf(" %f ", *(double *)vbuf);
			break;
		default:
			print_errmsg(gettext(err_msg[EM_FLOAT_INVSIZE]),
			    propinfo->size);
			return (PICL_FAILURE);
		}
		break;
	case PICL_PTYPE_TIMESTAMP:
		if (propinfo->size != sizeof (val64)) {
			print_errmsg(gettext(err_msg[EM_TS_INVSIZE]));
			return (PICL_FAILURE);
		}
		val64 = *(uint64_t *)vbuf;
		tmp = (time_t)val64;
		if ((uint64_t)tmp != val64) {
			print_errmsg(gettext(err_msg[EM_TS_OVERFLOW]));
			return (PICL_FAILURE);
		}
		str = ctime(&tmp);
		if (str == NULL) {
			print_errmsg(gettext(err_msg[EM_TS_INVALID]));
			return (PICL_FAILURE);
		}
		str[strlen(str) - 1] = '\0';
		(void) printf(" %s ", str);
		break;
	case PICL_PTYPE_TABLE:
		if (propinfo->size != sizeof (picl_prophdl_t)) {
			print_errmsg(gettext(err_msg[EM_TABLE_INVSIZE]),
			    propinfo->size);
			return (PICL_FAILURE);
		}
		(void) printf("(%" PRIxPICLTBL "TBL) ",
		    *(picl_prophdl_t *)vbuf);
		break;
	case PICL_PTYPE_REFERENCE:
		if (propinfo->size != sizeof (picl_nodehdl_t)) {
			print_errmsg(gettext(err_msg[EM_REF_INVSIZE]),
			    propinfo->size);
			return (PICL_FAILURE);
		}
		(void) printf(" (%" PRIxPICLHDL "H) ", *(picl_nodehdl_t *)vbuf);
		break;
	case PICL_PTYPE_BYTEARRAY:
		if (propinfo->size > 0)
			print_bytearray(lvl, vbuf, propinfo->size);
		break;
	default:
		print_errmsg(gettext(err_msg[EM_TYPE_UNKNOWN]));
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

/*
 * print table property value
 */
static int
print_table_prop(int lvl, picl_prophdl_t tblh)
{
	picl_prophdl_t	rowproph;
	picl_prophdl_t	colproph;
	int		err;
	picl_propinfo_t	propinfo;

	for (err = picl_get_next_by_col(tblh, &rowproph); err != PICL_ENDOFLIST;
	    err = picl_get_next_by_col(rowproph, &rowproph)) {
		if (err != PICL_SUCCESS) {
			print_errmsg(gettext(err_msg[EM_GETNXTBYCOL]),
			    picl_strerror(err));
			return (err);
		}

		(void) printf("%*s %s", PROPINFO_LEFT_MARGIN(lvl), " ",
		    COL_DELIM);

		for (colproph = rowproph; err != PICL_ENDOFLIST;
		    err = picl_get_next_by_row(colproph, &colproph)) {

			if (err != PICL_SUCCESS) {
				print_errmsg(gettext(err_msg[EM_GETNXTBYROW]),
				    picl_strerror(err));
				return (err);
			}

			err = picl_get_propinfo(colproph, &propinfo);
			if (err != PICL_SUCCESS) {
				print_errmsg(gettext(err_msg[EM_GETPINFO]),
				    picl_strerror(err));
				return (err);
			}

			err = print_propval(lvl, colproph, &propinfo);
			if (err != PICL_SUCCESS)
				return (err);
			(void) printf(COL_DELIM);
		}
		(void) printf("\n");
	}
	return (PICL_SUCCESS);
}

/*
 * Print the properties (name = value) of a node. If an error occurs
 * when printing the property value, stop. print_propval() suppresses
 * errors during getting property value except for stale/invalid handle
 * and no response errors.
 */
static int
print_proplist(int lvl, picl_nodehdl_t nodeh)
{
	int		err;
	picl_prophdl_t	proph;
	picl_propinfo_t	propinfo;
	picl_prophdl_t	tblh;

	for (err = picl_get_first_prop(nodeh, &proph); err == PICL_SUCCESS;
	    err = picl_get_next_prop(proph, &proph)) {

		err = picl_get_propinfo(proph, &propinfo);
		if (err != PICL_SUCCESS) {
			print_errmsg(gettext(err_msg[EM_GETPINFO]),
			    picl_strerror(err));
			return (err);
		}

		if (propinfo.type == PICL_PTYPE_VOID)
			(void) printf("%*s:%s\n", PROPINFO_LEFT_MARGIN(lvl),
			    " ", propinfo.name);
		else {
			(void) printf("%*s:%s\t", PROPINFO_LEFT_MARGIN(lvl),
			    " ", propinfo.name);
			err = print_propval(lvl, proph, &propinfo);
			(void) printf("\n");
			if (err != PICL_SUCCESS)
				return (err);
		}

		/*
		 * Expand the table property
		 */
		if (propinfo.type == PICL_PTYPE_TABLE) {
			err = picl_get_propval(proph, &tblh, propinfo.size);
			if (err != PICL_SUCCESS) {
				print_errmsg(gettext(err_msg[EM_GETPVAL]),
				    picl_strerror(err));
				return (err);
			}
			err = print_table_prop(lvl, tblh);
			if (err != PICL_SUCCESS)
				return (err);
		}
	}
	return (PICL_SUCCESS);
}

/*
 * Recursively print the PICL tree
 * When piclclass is specified, print only the nodes of that class.
 */
static int
print_tree_by_class(int lvl, picl_nodehdl_t nodeh, char *piclclass)
{
	picl_nodehdl_t	chdh;
	char		*nameval;
	char		classval[PICL_PROPNAMELEN_MAX];
	int		err;
	picl_prophdl_t	proph;
	picl_propinfo_t	pinfo;

	/*
	 * First get the class name of the node to compare with piclclass
	 */
	err = picl_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME, classval,
	    sizeof (classval));
	if (err != PICL_SUCCESS) {
		print_errmsg(gettext(err_msg[EM_GETPVALBYNAME]),
		    picl_strerror(err));
		return (err);
	}

#define	MATCHING_CLASSVAL(x, y)	((x == NULL) || (strcasecmp(x, y) == 0))

	if (MATCHING_CLASSVAL(piclclass, classval)) {
		err = picl_get_prop_by_name(nodeh, PICL_PROP_NAME, &proph);
		if (err != PICL_SUCCESS) {
			print_errmsg(gettext(err_msg[EM_GETPROPBYNAME]),
			    picl_strerror(err));
			return (err);
		}

		err = picl_get_propinfo(proph, &pinfo);
		if (err != PICL_SUCCESS) {
			print_errmsg(gettext(err_msg[EM_GETPINFO]),
			    picl_strerror(err));
			return (err);
		}

		nameval = alloca(pinfo.size);
		err = picl_get_propval(proph, nameval, pinfo.size);
		if (err != PICL_SUCCESS) {
			print_errmsg(gettext(err_msg[EM_GETPVAL]),
			    picl_strerror(err));
			return (err);
		}

		(void) printf("%*s %s (%s, %" PRIxPICLHDL ")\n",
		    NODEINFO_LEFT_MARGIN(lvl), " ", nameval, classval, nodeh);

		if (verbose_mode) {
			err = print_proplist(lvl, nodeh);
			if (err != PICL_SUCCESS)
				return (err);
		}
		++lvl;
	}

	for (err = picl_get_propval_by_name(nodeh, PICL_PROP_CHILD, &chdh,
	    sizeof (picl_nodehdl_t)); err != PICL_PROPNOTFOUND;
	    err = picl_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
	    sizeof (picl_nodehdl_t))) {

		if (err != PICL_SUCCESS) {
			print_errmsg(gettext(err_msg[EM_GETPVALBYNAME]),
			    picl_strerror(err));
			return (err);
		}

		err = print_tree_by_class(lvl, chdh, piclclass);
		if (err != PICL_SUCCESS)
			return (err);
	}
	return (PICL_SUCCESS);
}


/*
 * This program prints the PICL tree.
 * If an invalid handle or stale handle is encountered while printing
 * the tree, it starts over from the root node.
 */
int
main(int argc, char **argv)
{
	int		err;
	picl_nodehdl_t	rooth;
	int		c;
	int		done;
	char		piclclass[PICL_CLASSNAMELEN_MAX];
	int		cflg;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((prog = strrchr(argv[0], '/')) == NULL)
		prog = argv[0];
	else
		prog++;

	cflg = 0;
	while ((c = getopt(argc, argv, "vc:")) != EOF) {
		switch (c) {
		case 'v':
			verbose_mode = 1;
			break;
		case 'c':
			cflg = 1;
			(void) strlcpy(piclclass, optarg,
			    PICL_CLASSNAMELEN_MAX);
			break;
		case '?':
			/*FALLTHROUGH*/
		default:
			usage();
			/*NOTREACHED*/
		}
	}
	if (optind != argc)
		usage();

	err = picl_initialize();
	if (err != PICL_SUCCESS) {
		print_errmsg(gettext(err_msg[EM_INIT]), picl_strerror(err));
		exit(1);
	}


	do {
		done = 1;
		err = picl_get_root(&rooth);
		if (err != PICL_SUCCESS) {
			print_errmsg(gettext(err_msg[EM_GETROOT]),
			    picl_strerror(err));
			exit(1);
		}

		err = print_tree_by_class(ROOT_LEVEL, rooth,
		    (cflg ? piclclass : NULL));
		if ((err == PICL_STALEHANDLE) || (err == PICL_INVALIDHANDLE))
			done = 0;
	} while (!done);

	(void) picl_shutdown();

	return (0);
}
