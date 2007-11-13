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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	lint
#define	_REENTRANT	/* for localtime_r */
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>
#include <time.h>
#include <sys/param.h>
#include <sys/vfstab.h>
#include <dirent.h>
#ifdef __sparc
#include <sys/scsi/adapters/scsi_vhci.h>
#include <sys/sunmdi.h>
#endif /* __sparc */
#include "libdevinfo.h"
#include "device_info.h"
#include <regex.h>

#define	isnewline(ch)	((ch) == '\n' || (ch) == '\r' || (ch) == '\f')
#define	isnamechar(ch)  (isalpha(ch) || isdigit(ch) || (ch) == '_' ||\
	(ch) == '-')
#define	MAX_TOKEN_SIZE	1024
#define	BUFSIZE		1024
#define	STRVAL(s)	((s) ? (s) : "NULL")

#define	SCSI_VHCI_CONF		"/kernel/drv/scsi_vhci.conf"
#define	QLC_CONF		"/kernel/drv/qlc.conf"
#define	FP_CONF			"/kernel/drv/fp.conf"
#define	DRIVER_CLASSES		"/etc/driver_classes"
#define	FP_AT			"fp@"
#define	VHCI_CTL_NODE		"/devices/scsi_vhci:devctl"
#define	SLASH_DEVICES		"/devices"
#define	SLASH_DEVICES_SLASH	"/devices/"
#define	SLASH_FP_AT		"/fp@"
#define	SLASH_SCSI_VHCI		"/scsi_vhci"
#define	META_DEV		"/dev/md/dsk/"
#define	SLASH_DEV_SLASH		"/dev/"

/*
 * Macros to produce a quoted string containing the value of a
 * preprocessor macro. For example, if SIZE is defined to be 256,
 * VAL2STR(SIZE) is "256". This is used to construct format
 * strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)

typedef enum {
	CLIENT_TYPE_UNKNOWN,
	CLIENT_TYPE_PHCI,
	CLIENT_TYPE_VHCI
} client_type_t;

typedef enum {
	T_EQUALS,
	T_AMPERSAND,
	T_BIT_OR,
	T_STAR,
	T_POUND,
	T_COLON,
	T_SEMICOLON,
	T_COMMA,
	T_SLASH,
	T_WHITE_SPACE,
	T_NEWLINE,
	T_EOF,
	T_STRING,
	T_HEXVAL,
	T_DECVAL,
	T_NAME
} token_t;

typedef enum {
	begin, parent, drvname, drvclass, prop,
	parent_equals, name_equals, drvclass_equals,
	parent_equals_string, name_equals_string,
	drvclass_equals_string,
	prop_equals, prop_equals_string, prop_equals_integer,
	prop_equals_string_comma, prop_equals_integer_comma
} conf_state_t;

/* structure to hold entries with mpxio-disable property in driver.conf file */
struct conf_entry {
	char *name;
	char *parent;
	char *class;
	char *unit_address;
	int port;
	int mpxio_disable;
	struct conf_entry *next;
};

struct conf_file {
	char *filename;
	FILE *fp;
	int linenum;
};

static char *tok_err = "Unexpected token '%s'\n";


/* #define	DEBUG */

#ifdef DEBUG

int devfsmap_debug = 0;
/* /var/run is not mounted at install time. Therefore use /tmp */
char *devfsmap_logfile = "/tmp/devfsmap.log";
static FILE *logfp;
#define	logdmsg(args)	log_debug_msg args
static void vlog_debug_msg(char *, va_list);
static void log_debug_msg(char *, ...);
#ifdef __sparc
static void log_confent_list(char *, struct conf_entry *, int);
static void log_pathlist(char **);
#endif /* __sparc */

#else /* DEBUG */
#define	logdmsg(args)	/* nothing */
#endif /* DEBUG */


/*
 * Leave NEWLINE as the next character.
 */
static void
find_eol(FILE *fp)
{
	int ch;

	while ((ch = getc(fp)) != EOF) {
		if (isnewline(ch)) {
			(void) ungetc(ch, fp);
			break;
		}
	}
}

/* ignore parsing errors */
/*ARGSUSED*/
static void
file_err(struct conf_file *filep, char *fmt, ...)
{
#ifdef DEBUG
	va_list ap;

	va_start(ap, fmt);
	log_debug_msg("WARNING: %s line # %d: ",
	    filep->filename, filep->linenum);
	vlog_debug_msg(fmt, ap);
	va_end(ap);
#endif /* DEBUG */
}

/* return the next token from the given driver.conf file, or -1 on error */
static token_t
lex(struct conf_file *filep, char *val, size_t size)
{
	char	*cp;
	int	ch, oval, badquote;
	size_t	remain;
	token_t token;
	FILE	*fp = filep->fp;

	if (size < 2)
		return (-1);

	cp = val;
	while ((ch = getc(fp)) == ' ' || ch == '\t')
		;

	remain = size - 1;
	*cp++ = (char)ch;
	switch (ch) {
	case '=':
		token = T_EQUALS;
		break;
	case '&':
		token = T_AMPERSAND;
		break;
	case '|':
		token = T_BIT_OR;
		break;
	case '*':
		token = T_STAR;
		break;
	case '#':
		token = T_POUND;
		break;
	case ':':
		token = T_COLON;
		break;
	case ';':
		token = T_SEMICOLON;
		break;
	case ',':
		token = T_COMMA;
		break;
	case '/':
		token = T_SLASH;
		break;
	case ' ':
	case '\t':
	case '\f':
		while ((ch = getc(fp)) == ' ' ||
		    ch == '\t' || ch == '\f') {
			if (--remain == 0) {
				*cp = '\0';
				return (-1);
			}
			*cp++ = (char)ch;
		}
		(void) ungetc(ch, fp);
		token = T_WHITE_SPACE;
		break;
	case '\n':
	case '\r':
		token = T_NEWLINE;
		break;
	case '"':
		remain++;
		cp--;
		badquote = 0;
		while (!badquote && (ch  = getc(fp)) != '"') {
			switch (ch) {
			case '\n':
			case EOF:
				file_err(filep, "Missing \"\n");
				remain = size - 1;
				cp = val;
				*cp++ = '\n';
				badquote = 1;
				/* since we consumed the newline/EOF */
				(void) ungetc(ch, fp);
				break;

			case '\\':
				if (--remain == 0) {
					*cp = '\0';
					return (-1);
				}
				ch = (char)getc(fp);
				if (!isdigit(ch)) {
					/* escape the character */
					*cp++ = (char)ch;
					break;
				}
				oval = 0;
				while (ch >= '0' && ch <= '7') {
					ch -= '0';
					oval = (oval << 3) + ch;
					ch = (char)getc(fp);
				}
				(void) ungetc(ch, fp);
				/* check for character overflow? */
				if (oval > 127) {
					file_err(filep,
					    "Character "
					    "overflow detected.\n");
				}
				*cp++ = (char)oval;
				break;
			default:
				if (--remain == 0) {
					*cp = '\0';
					return (-1);
				}
				*cp++ = (char)ch;
				break;
			}
		}
		token = T_STRING;
		break;

	case EOF:
		token = T_EOF;
		break;

	default:
		/*
		 * detect a lone '-' (including at the end of a line), and
		 * identify it as a 'name'
		 */
		if (ch == '-') {
			if (--remain == 0) {
				*cp = '\0';
				return (-1);
			}
			*cp++ = (char)(ch = getc(fp));
			if (ch == ' ' || ch == '\t' || ch == '\n') {
				(void) ungetc(ch, fp);
				remain++;
				cp--;
				token = T_NAME;
				break;
			}
		} else if (ch == '~' || ch == '-') {
			if (--remain == 0) {
				*cp = '\0';
				return (-1);
			}
			*cp++ = (char)(ch = getc(fp));
		}


		if (isdigit(ch)) {
			if (ch == '0') {
				if ((ch = getc(fp)) == 'x') {
					if (--remain == 0) {
						*cp = '\0';
						return (-1);
					}
					*cp++ = (char)ch;
					ch = getc(fp);
					while (isxdigit(ch)) {
						if (--remain == 0) {
							*cp = '\0';
							return (-1);
						}
						*cp++ = (char)ch;
						ch = getc(fp);
					}
					(void) ungetc(ch, fp);
					token = T_HEXVAL;
				} else {
					goto digit;
				}
			} else {
				ch = getc(fp);
digit:
				while (isdigit(ch)) {
					if (--remain == 0) {
						*cp = '\0';
						return (-1);
					}
					*cp++ = (char)ch;
					ch = getc(fp);
				}
				(void) ungetc(ch, fp);
				token = T_DECVAL;
			}
		} else if (isalpha(ch) || ch == '\\') {
			if (ch != '\\') {
				ch = getc(fp);
			} else {
				/*
				 * if the character was a backslash,
				 * back up so we can overwrite it with
				 * the next (i.e. escaped) character.
				 */
				remain++;
				cp--;
			}
			while (isnamechar(ch) || ch == '\\') {
				if (ch == '\\')
					ch = getc(fp);
				if (--remain == 0) {
					*cp = '\0';
					return (-1);
				}
				*cp++ = (char)ch;
				ch = getc(fp);
			}
			(void) ungetc(ch, fp);
			token = T_NAME;
		} else {
			return (-1);
		}
		break;
	}

	*cp = '\0';

	return (token);
}

#ifdef __sparc

static void
free_confent(struct conf_entry *confent)
{
	if (confent->name)
		free(confent->name);
	if (confent->parent)
		free(confent->parent);
	if (confent->class)
		free(confent->class);
	if (confent->unit_address)
		free(confent->unit_address);
	free(confent);
}

static void
free_confent_list(struct conf_entry *confent_list)
{
	struct conf_entry *confent, *next;

	for (confent = confent_list; confent != NULL; confent = next) {
		next = confent->next;
		free_confent(confent);
	}
}

/*
 * Parse the next entry from the driver.conf file and return in the form of
 * a pointer to the conf_entry.
 */
static struct conf_entry *
parse_conf_entry(struct conf_file *filep, char *tokbuf, size_t linesize)
{
	char *prop_name, *string;
	token_t token;
	struct conf_entry *confent;
	conf_state_t state;
	int failed = 1;

	if ((confent = calloc(1, sizeof (*confent))) == NULL)
		return (NULL);

	confent->port = -1;
	confent->mpxio_disable = -1;

	state = begin;
	token = T_NAME;
	prop_name = NULL;
	string = NULL;
	do {
		switch (token) {
		case T_NAME:
			switch (state) {
			case prop_equals_string:
			case prop_equals_integer:
			case begin:
				state = prop;
				if ((prop_name = strdup(tokbuf)) == NULL)
					goto bad;
				break;
			default:
				file_err(filep, tok_err, tokbuf);
			}
			break;
		case T_EQUALS:
			switch (state) {
			case prop:
				state = prop_equals;
				break;
			default:
				file_err(filep, tok_err, tokbuf);
			}
			break;
		case T_STRING:
			switch (state) {
			case prop_equals:
				if ((string = strdup(tokbuf)) == NULL)
					goto bad;

				state = begin;
				if (strcmp(prop_name, "PARENT") == 0 ||
				    strcmp(prop_name, "parent") == 0) {
					if (confent->parent) {
						file_err(filep,
				"'parent' property already specified\n");
						goto bad;
					}
					confent->parent = string;
				} else if (strcmp(prop_name, "NAME") == 0 ||
				    strcmp(prop_name, "name") == 0) {
					if (confent->name) {
						file_err(filep,
				"'name' property already specified\n");
						goto bad;
					}
					confent->name = string;
				} else if (strcmp(prop_name, "CLASS") == 0 ||
				    strcmp(prop_name, "class") == 0) {
					if (confent->class) {
						file_err(filep,
				"'class' property already specified\n");
						goto bad;
					}
					confent->class = string;
				} else if (strcmp(prop_name, "unit-address")
				    == 0) {
					if (confent->unit_address) {
						file_err(filep,
				"'unit-address' property already specified\n");
						goto bad;
					}
					confent->unit_address = string;
				} else if (strcmp(prop_name, "mpxio-disable")
				    == 0) {
					if (confent->mpxio_disable != -1) {
						file_err(filep,
				"'mpxio-disable' property already specified\n");
						goto bad;
					}
					if (strcmp(string, "yes") == 0)
						confent->mpxio_disable = 1;
					else if (strcmp(string, "no") == 0)
						confent->mpxio_disable = 0;
					else {
						file_err(filep,
				"'mpxio-disable' property setting is invalid. "
				"The value must be either \"yes\" or \"no\"\n");
						goto bad;
					}
					free(string);
				} else {
					free(string);
					state = prop_equals_string;
				}
				string = NULL;
				free(prop_name);
				prop_name = NULL;
				break;

			case prop_equals_string_comma:
				state = prop_equals_string;
				break;
			default:
				file_err(filep, tok_err, tokbuf);
			}
			break;
		case T_HEXVAL:
		case T_DECVAL:
			switch (state) {
			case prop_equals:
				if (strcmp(prop_name, "port") == 0) {
					if (confent->port != -1) {
						file_err(filep,
					"'port' property already specified\n");
						goto bad;
					}
					confent->port =
					    (int)strtol(tokbuf, NULL, 0);
					state = begin;
				} else
					state = prop_equals_integer;
				free(prop_name);
				prop_name = NULL;
				break;

			case prop_equals_integer_comma:
				state = prop_equals_integer;
				break;
			default:
				file_err(filep, tok_err, tokbuf);
			}
			break;
		case T_COMMA:
			switch (state) {
			case prop_equals_string:
				state = prop_equals_string_comma;
				break;
			case prop_equals_integer:
				state = prop_equals_integer_comma;
				break;
			default:
				file_err(filep, tok_err, tokbuf);
			}
			break;
		case T_NEWLINE:
			filep->linenum++;
			break;
		case T_POUND:
			find_eol(filep->fp);
			break;
		case T_EOF:
			file_err(filep, "Unexpected EOF\n");
			goto bad;
		default:
			file_err(filep, tok_err, tokbuf);
			goto bad;
		}
	} while ((token = lex(filep, tokbuf, linesize)) != T_SEMICOLON);

	failed = 0;

bad:
	if (prop_name)
		free(prop_name);
	if (string)
		free(string);
	if (failed == 1) {
		free_confent(confent);
		return (NULL);
	}
	return (confent);
}

/*
 * Parse all entries with mpxio-disable property in the given driver.conf
 * file.
 *
 * fname		driver.conf file name
 * confent_list		on return *confent_list will contain the list of
 *			driver.conf file entries with mpxio-disable property.
 * mpxio_disable	on return *mpxio_disable is set to the setting of the
 * 			driver global mpxio-dissable property as follows.
 *			0  if driver mpxio-disable="no"
 *			1  if driver mpxio-disable="yes"
 *			-1 if driver mpxio-disable property isn't specified.
 */
static void
parse_conf_file(char *fname, struct conf_entry **confent_list,
    int *mpxio_disable)
{
	struct conf_entry *confent, *tail = NULL;
	token_t token;
	struct conf_file file;
	char tokval[MAX_TOKEN_SIZE];

	*confent_list = NULL;
	*mpxio_disable = -1;
	if ((file.fp = fopen(fname, "r")) == NULL)
		return;

	file.filename = fname;
	file.linenum = 1;

	while ((token = lex(&file, tokval, MAX_TOKEN_SIZE)) != T_EOF) {
		switch (token) {
		case T_POUND:
			/*
			 * Skip comments.
			 */
			find_eol(file.fp);
			break;
		case T_NAME:
			if ((confent = parse_conf_entry(&file, tokval,
			    MAX_TOKEN_SIZE)) == NULL)
				break;
			/*
			 * No name indicates global property.
			 * Make sure parent and class not NULL.
			 */
			if (confent->name == NULL) {
				if (confent->parent ||
				    confent->class) {
					file_err(&file,
					    "missing name attribute\n");
				} else if (confent->mpxio_disable != -1) {
					if (*mpxio_disable == -1)
						*mpxio_disable =
						    confent->mpxio_disable;
					else
						file_err(&file,
				"'mpxio-disable' property already specified\n");
				}
				free_confent(confent);
				break;
			}

			/*
			 * This is a node spec, either parent or class
			 * must be specified.
			 */
			if (confent->parent == NULL && confent->class == NULL) {
				file_err(&file,
				    "missing parent or class attribute\n");
				free_confent(confent);
				break;
			}

			/* only need entries with mpxio_disable property */
			if (confent->mpxio_disable == -1) {
				free_confent(confent);
				break;
			}

			if (tail)
				tail->next = confent;
			else
				*confent_list = confent;
			tail = confent;
			break;

		case T_NEWLINE:
			file.linenum++;
			break;
		default:
			break;
		}
	}

	(void) fclose(file.fp);
}

/*
 * Return the driver class of the given driver_name.
 * The memory for the driver class is allocated by this function and the
 * caller must free it.
 */
static char *
get_driver_class(char *rootdir, char *driver_name)
{
	FILE *fp;
	char buf[BUFSIZE];
	char driver[BUFSIZE];
	char class_name[BUFSIZE];

	logdmsg(("get_driver_class: rootdir = %s, driver name = %s\n",
	    rootdir, driver_name));

	(void) snprintf(buf, sizeof (buf), "%s%s", rootdir, DRIVER_CLASSES);

	if ((fp = fopen(buf, "r")) == NULL) {
		logdmsg(("get_driver_class: failed to open %s: %s\n",
		    buf, strerror(errno)));
		return (NULL);
	}

	while (fgets(buf, sizeof (buf), fp) != NULL) {
		/* LINTED - unbounded string specifier */
		if ((sscanf(buf, "%s %s", driver, class_name) == 2) &&
		    driver[0] != '#' && strcmp(driver, driver_name) == 0) {
			logdmsg(("get_driver_class: driver class = %s\n",
			    class_name));
			(void) fclose(fp);
			return (strdup(class_name));
		}
	}

	(void) fclose(fp);
	return (NULL);
}

static int
lookup_in_confent_list(struct conf_entry *confent_list,
    int match_class, char *parent, char *unit_addr, int port)
{
	struct conf_entry *confent;
	char *par;

	logdmsg(("lookup_in_confent_list: %s = \"%s\", unit_addr = \"%s\", "
	    "port = %d\n", (match_class) ? "class" : "parent", parent,
	    STRVAL(unit_addr), port));

	for (confent = confent_list; confent != NULL; confent = confent->next) {
		par = (match_class) ? confent->class : confent->parent;
		if (unit_addr) {
			if (confent->unit_address != NULL &&
			    strcmp(confent->unit_address, unit_addr) == 0 &&
			    par != NULL && strcmp(par, parent) == 0)
				return (confent->mpxio_disable);
		} else {
			if (confent->port == port &&
			    par != NULL && strcmp(par, parent) == 0)
				return (confent->mpxio_disable);
		}
	}
	return (-1);
}

/*
 * lookup mpxio-disabled property setting for the given path in the given
 * driver.conf file. Match the entries from most specific to least specific.
 *
 * conf_file	the path name of either fp.conf, qlc.conf or scsi_vhci.conf
 * path		/devices node path without the /devices prefix.
 *		If the conf_file is fp.conf, path must be a fp node path
 *		if the conf_file is qlc.conf, path must be a qlc node path.
 *		if the conf_file is scsi_vhci.conf, path must be NULL.
 *		ex:	/pci@8,600000/SUNW,qlc@4/fp@0,0
 *			/pci@8,600000/SUNW,qlc@4
 *
 * returns:
 *	0	if mpxio-disable="no"
 *	1	if mpxio-disable="yes"
 *	-1	if mpxio-disable property isn't specified.
 */
static int
lookup_in_conf_file(char *rootdir, char *conf_file, char *path)
{
	struct conf_entry *confent_list = NULL;
	int mpxio_disable;
	di_node_t par_node = DI_NODE_NIL;
	char *node_name = NULL, *node_addr = NULL;
	char *unit_addr = NULL;
	int port = -1;
	char *par_node_name = NULL, *par_node_addr = NULL;
	char *par_binding_name = NULL, *par_driver_name = NULL;
	char *par_driver_class = NULL, *par_node_name_addr;
	int rv = -1;
	char buf[MAXPATHLEN];

	logdmsg(("lookup_in_conf_file: rootdir = \"%s\", conf_file = \"%s\", "
	    "path = \"%s\"\n", rootdir, conf_file, STRVAL(path)));

	(void) snprintf(buf, MAXPATHLEN, "%s%s", rootdir, conf_file);
	parse_conf_file(buf, &confent_list, &mpxio_disable);
#ifdef DEBUG
	log_confent_list(buf, confent_list, mpxio_disable);
#endif

	/* if path is NULL, return driver global mpxio-disable setting */
	if (path == NULL) {
		rv = mpxio_disable;
		goto done;
	}

	if ((node_name = strrchr(path, '/')) == NULL)
		goto done;

	*node_name = '\0';
	node_name++;

	if ((node_addr = strchr(node_name, '@')) == NULL)
		goto done;

	*node_addr = '\0';
	node_addr++;

	if (strcmp(node_name, "fp") == 0) {
		/* get port number; encoded in the node addr as a hex number */
		port = (int)strtol(node_addr, NULL, 16);
	} else
		unit_addr = node_addr;

	/*
	 * Match from most specific to least specific;
	 * first, start the lookup based on full path.
	 */
	if ((rv = lookup_in_confent_list(confent_list, 0, path,
	    unit_addr, port)) != -1)
		goto done;

	/* lookup nodename@address */
	if ((par_node_name_addr = strrchr(path, '/')) != NULL) {
		par_node_name_addr++;
		if ((rv = lookup_in_confent_list(confent_list, 0,
		    par_node_name_addr, unit_addr, port)) != -1)
			goto done;
	}

	/* di_init() doesn't work when 0 is passed in flags */
	par_node = di_init(path, DINFOMINOR);
	if (par_node != DI_NODE_NIL) {
		par_node_name = di_node_name(par_node);
		par_node_addr = di_bus_addr(par_node);
		par_binding_name = di_binding_name(par_node);
		par_driver_name = di_driver_name(par_node);
	}

	logdmsg(("par_node_name = %s\n", STRVAL(par_node_name)));
	logdmsg(("par_node_addr = %s\n", STRVAL(par_node_addr)));
	logdmsg(("par_binding_name = %s\n", STRVAL(par_binding_name)));
	logdmsg(("par_driver_name = %s\n", STRVAL(par_driver_name)));

	/* lookup bindingname@address */
	if (par_binding_name != NULL && par_binding_name != par_node_name &&
	    par_node_addr != NULL) {
		(void) snprintf(buf, sizeof (buf), "%s@%s", par_binding_name,
		    par_node_addr);
		if ((rv = lookup_in_confent_list(confent_list, 0,
		    buf, unit_addr, port)) != -1)
			goto done;
	}

	/* lookup binding name */
	if (par_binding_name != NULL) {
		if ((rv = lookup_in_confent_list(confent_list, 0,
		    par_binding_name, unit_addr, port)) != -1)
			goto done;
	}

	if (par_driver_name != NULL) {
		/* lookup driver name */
		if ((rv = lookup_in_confent_list(confent_list, 0,
		    par_driver_name, unit_addr, port)) != -1)
			goto done;

		/* finally, lookup class name */
		par_driver_class = get_driver_class(rootdir, par_driver_name);
		if (par_driver_class != NULL) {
			if ((rv = lookup_in_confent_list(confent_list, 1,
			    par_driver_class, unit_addr, port)) != -1)
				goto done;
		}
	}

	/*
	 * no match so far;
	 * use the driver global mpxio-disable setting if exists.
	 */
	rv = mpxio_disable;

done:
	if (node_name != NULL)
		*(node_name - 1) = '/';
	if (node_addr != NULL)
		*(node_addr - 1) = '@';
	if (par_driver_class != NULL)
		free(par_driver_class);
	if (confent_list != NULL)
		free_confent_list(confent_list);
	if (par_node != DI_NODE_NIL)
		di_fini(par_node);

	return (rv);
}

/*
 * Given client_name return whether it is a phci or vhci based name.
 * client_name is /devices name of a client without the /devices prefix.
 *
 * client_name			Return value
 * .../fp@xxx/ssd@yyy		CLIENT_TYPE_PHCI
 * .../scsi_vhci/ssd@yyy	CLIENT_TYPE_VHCI
 * other			CLIENT_TYPE_UNKNOWN
 */
static client_type_t
client_name_type(char *client_name)
{
	client_type_t client_type;
	char *p1, *p2;

	logdmsg(("client_name_type: client_name = %s\n", client_name));

	if (strncmp(client_name, SLASH_SCSI_VHCI,
	    sizeof (SLASH_SCSI_VHCI) - 1) == 0)
		return (CLIENT_TYPE_VHCI);

	if (*client_name != '/')
		return (CLIENT_TYPE_UNKNOWN);

	if ((p1 = strrchr(client_name, '/')) == NULL)
		return (CLIENT_TYPE_UNKNOWN);

	*p1 = '\0';

	if ((p2 = strrchr(client_name, '/')) != NULL &&
	    strncmp(p2, SLASH_FP_AT, sizeof (SLASH_FP_AT) - 1) == 0)
		client_type = CLIENT_TYPE_PHCI;
	else
		client_type = CLIENT_TYPE_UNKNOWN;

	*p1 = '/';
	return (client_type);
}

/*
 * Compare controller name portion of dev1 and dev2.
 *
 * rootdir	root directory of the target environment
 * dev1		can be either a /dev link or /devices name in the target
 *		environemnt
 * dev2		/devices name of a device without the /devices prefix
 *
 * Returns:
 *	0	if controller names match
 *	1	if controller names don't match
 *	-1	an error occurred.
 */
static int
compare_controller(char *rootdir, char *dev1, char *dev2)
{
	int linksize;
	char *p1, *p;
	char physdev1[MAXPATHLEN];
	char buf[MAXPATHLEN];

	logdmsg(("compare_controller: rootdir = %s, dev1 = %s, dev2 = %s\n",
	    rootdir, dev1, dev2));

	if (strncmp(dev1, SLASH_DEV_SLASH, sizeof (SLASH_DEV_SLASH) - 1)
	    == 0) {
		(void) snprintf(buf, MAXPATHLEN, "%s%s", rootdir, dev1);
		if ((linksize = readlink(buf, physdev1, MAXPATHLEN)) > 0 &&
		    linksize < (MAXPATHLEN - 1)) {
			physdev1[linksize] = '\0';
			logdmsg(("compare_controller: physdev1 = %s\n",
			    physdev1));
		} else
			return (-1);
	} else
		(void) strlcpy(physdev1, dev1, MAXPATHLEN);

	if ((p1 = strstr(physdev1, SLASH_DEVICES)) == NULL)
		return (-1);

	p1 += sizeof (SLASH_DEVICES) - 1;
	/* strip the device portion */
	if ((p = strrchr(p1, '/')) == NULL)
		return (-1);
	*p = '\0';

	if ((p = strrchr(dev2, '/')) == NULL)
		return (-1);
	*p = '\0';

	logdmsg(("compare_controller: path1 = %s, path2 = %s\n",
	    p1, dev2));
	if (strcmp(p1, dev2) == 0) {
		*p = '/';
		return (0);
	} else {
		*p = '/';
		return (1);
	}
}

/*
 * Check if the specified device path is on the root controller.
 *
 * rootdir	root directory of the target environment
 * path		/devices name of a device without the /devices prefix
 *
 * Returns
 *	1	if the path is on the root controller
 *	0	if the path is not on the root controller
 *	-1	if an error occurs
 */
static int
is_root_controller(char *rootdir, char *path)
{
	FILE *fp;
	char *tmpfile;
	int rv = -1;
	struct vfstab vfsent;
	char buf[MAXPATHLEN];
	char ctd[MAXNAMELEN + 1];

	logdmsg(("is_root_controller: rootdir = %s, path = %s\n", rootdir,
	    path));

	(void) snprintf(buf, MAXPATHLEN, "%s%s", rootdir, VFSTAB);

	if ((fp = fopen(buf, "r")) == NULL) {
		logdmsg(("is_root_controller: failed to open %s: %s\n",
		    buf, strerror(errno)));
		return (-1);
	}

	if (getvfsfile(fp, &vfsent, "/") != 0) {
		logdmsg(("is_root_controller: getvfsfile: failed to read "
		    "vfstab entry for mount point \"/\": %s\n",
		    strerror(errno)));
		(void) fclose(fp);
		return (-1);
	}
	(void) fclose(fp);

	/* check if the root is an svm metadisk */
	if (strncmp(vfsent.vfs_special, META_DEV, sizeof (META_DEV) - 1) != 0) {
		if (compare_controller(rootdir, vfsent.vfs_special, path) == 0)
			return (1);
		else
			return (0);
	}

	/* Don't use /var/run as it is not mounted in miniroot */
	if ((tmpfile = tempnam("/tmp", "diirc")) == NULL) {
		logdmsg(("is_root_controller: tempnam: failed: %s\n",
		    strerror(errno)));
		return (-1);
	}

	/* get metadisk components using metastat command */
	(void) snprintf(buf, MAXPATHLEN,
	    "/usr/sbin/metastat -p %s 2>/dev/null | "
	    "/usr/bin/grep ' 1 1 ' | "
	    "/usr/bin/sed -e 's/^.* 1 1 //' | "
	    "/usr/bin/cut -f1 -d ' ' > %s",
	    vfsent.vfs_special + sizeof (META_DEV) - 1, tmpfile);

	logdmsg(("is_root_controller: command = %s\n", buf));
	fp = NULL;
	if (system(buf) == 0 && (fp = fopen(tmpfile, "r")) != NULL) {
		while (fscanf(fp, "%" VAL2STR(MAXNAMELEN) "s", ctd) == 1) {
			(void) snprintf(buf, MAXPATHLEN, "/dev/dsk/%s", ctd);
			if (compare_controller(rootdir, buf, path) == 0) {
				rv = 1;
				goto out;
			}
		}
		rv = 0;
	}

out:
	if (fp)
		(void) fclose(fp);
	(void) unlink(tmpfile);
	free(tmpfile);
	return (rv);
}

static int
file_exists(char *rootdir, char *path)
{
	struct stat stbuf;
	char fullpath[MAXPATHLEN];
	int x;

	(void) snprintf(fullpath, MAXPATHLEN, "%s%s", rootdir, path);

	x = stat(fullpath, &stbuf);
	logdmsg(("file_exists: %s: %s\n", fullpath, (x == 0) ? "yes" : "no"));
	if (x == 0)
		return (1);
	else
		return (0);
}

/*
 * Check if mpxio is enabled or disabled on the specified device path.
 * Looks through the .conf files to determine the mpxio setting.
 *
 * rootdir	root directory of the target environment
 * path		/devices name of a device without the /devices prefix and
 *		minor name component.
 *
 * Returns
 *	1	if mpxio is disabled
 *	0	if mpxio is enabled
 *	-1	if an error occurs
 */
static int
is_mpxio_disabled(char *rootdir, char *path)
{
	int mpxio_disable;
	char *p;
	int check_root_controller;

	logdmsg(("is_mpxio_disabled: rootdir = %s, path = %s\n",
	    rootdir, path));

	if (file_exists(rootdir, SCSI_VHCI_CONF) == 0) {
		/*
		 * scsi_vhci.conf doesn't exist:
		 *  if upgrading from a pre solaris 9 release. or
		 *  if this function is called during fresh or flash install
		 *  prior to installing scsi_vhci.conf file.
		 */
		if (file_exists(rootdir, "/kernel/drv"))
			/* upgrading from pre solaris 9 */
			return (1);
		else
			/* fresh or flash install */
			return (0);
	}

	mpxio_disable = lookup_in_conf_file(rootdir, SCSI_VHCI_CONF, NULL);

	/*
	 * scsi_vhci.conf contains mpxio-disable property only in s9 and
	 * s8+sfkpatch. This property is no longer present from s10 onwards.
	 */
	if (mpxio_disable == 1) {
		/* upgrading from s8 or s9 with mpxio globally disabled */
		return (1);
	} else if (mpxio_disable == 0) {
		/* upgrading from s8 or s9 with mpxio globally enabled */
		check_root_controller = 1;
	} else {
		/*
		 * We are looking at the s10 version of the file. This is
		 * the case if this function is called after installing the
		 * new scsi_vhci.conf file.
		 */
		check_root_controller = 0;
	}

	if ((mpxio_disable = lookup_in_conf_file(rootdir, FP_CONF, path))
	    != -1)
		return (mpxio_disable);

	if ((p = strrchr(path, '/')) == NULL)
		return (-1);

	*p = '\0';
	if ((mpxio_disable = lookup_in_conf_file(rootdir, QLC_CONF, path))
	    != -1) {
		*p = '/';
		return (mpxio_disable);
	}
	*p = '/';

	/*
	 * mpxio-disable setting is not found in the .conf files.
	 * The default is to enable mpxio, except if the path is on the root
	 * controller.
	 *
	 * In s8 and s9 mpxio is not supported on the root controller.
	 * NWS supplies a patch to enable root controller support in s8 and s9.
	 * If the system had the patch installed, the fp.conf file would have
	 * explicit "mpxio-disable=no" for the root controller. So we would
	 * have found the mpxio-disable setting when we looked up this property
	 * in the fp.conf file.
	 */
	if (check_root_controller) {
		mpxio_disable = is_root_controller(rootdir, path);
		logdmsg(("is_mpxio_disabled: is_root_controller returned %d\n",
		    mpxio_disable));
	} else
		mpxio_disable = 0;

	return (mpxio_disable);
}

static int
vhci_ctl(sv_iocdata_t *iocp, int cmd)
{
	int fd, rv;

	if ((fd = open(VHCI_CTL_NODE, O_RDWR)) < 0)
		return (-1);
	rv = ioctl(fd, cmd, iocp);
	(void) close(fd);
	return (rv);
}

/*
 * Convert a phci client name to vhci client name.
 *
 * phci_name	phci client /devices name without the /devices prefix and
 *		minor name component.
 *		ex: /pci@8,600000/SUNW,qlc@4/fp@0,0/ssd@w2100002037cd9f72,0
 *
 * Returns 	on success, vhci client name is returned. The memory for
 *		the vhci name is allocated by this function and the caller
 * 		must free it.
 *		on failure, NULL is returned.
 */
static char *
phci_to_vhci(char *phci_name)
{
	sv_iocdata_t ioc;
	char *slash, *addr, *retp;
	char vhci_name_buf[MAXPATHLEN];
	char phci_name_buf[MAXPATHLEN];
	char addr_buf[MAXNAMELEN];

	logdmsg(("phci_to_vhci: pchi_name =  %s\n", phci_name));
	(void) strlcpy(phci_name_buf, phci_name, MAXPATHLEN);

	if ((slash = strrchr(phci_name_buf, '/')) == NULL ||
	    (addr = strchr(slash, '@')) == NULL)
		return (NULL);

	*slash = '\0';
	addr++;
	(void) strlcpy(addr_buf, addr, MAXNAMELEN);

	bzero(&ioc, sizeof (sv_iocdata_t));
	ioc.client = vhci_name_buf;
	ioc.phci = phci_name_buf;
	ioc.addr = addr_buf;
	if (vhci_ctl(&ioc, SCSI_VHCI_GET_CLIENT_NAME) != 0) {
		logdmsg(("phci_to_vhci: vhci_ctl failed: %s\n",
		    strerror(errno)));
		return (NULL);
	}

	retp = strdup(vhci_name_buf);
	logdmsg(("phci_to_vhci: vhci name = %s\n", STRVAL(retp)));
	return (retp);
}

static int
add_to_phci_list(char **phci_list, sv_path_info_t *pi, int npaths, int state,
    char *node_name)
{
	int rv = 0;
	char name[MAXPATHLEN];

	while (npaths--) {
		if (state == pi->ret_state) {
			(void) snprintf(name, MAXPATHLEN, "%s/%s@%s",
			    pi->device.ret_phci, node_name, pi->ret_addr);
			if ((*phci_list = strdup(name)) == NULL)
				return (-1);
			phci_list++;
			rv++;
		}
		pi++;
	}

	return (rv);
}

static void
free_pathlist(char **pathlist)
{
	char **p;

	if (pathlist != NULL) {
		for (p = pathlist; *p != NULL; p++)
			free(*p);
		free(pathlist);
	}
}


/*
 * Convert a vhci client name to phci client names.
 *
 * vhci_name	vhci client /devices name without the /devices prefix and
 *		minor name component.
 * num_paths	On return, *num_paths is set to the number paths in the
 *		returned path list.
 *
 * Returns 	NULL terminated path list containing phci client paths is
 *		returned on success. The memory for the path list is
 *		allocated by this function and the caller must free it by
 *		calling free_pathlist().
 *		NULL is returned on failure.
 */
static char **
vhci_to_phci(char *vhci_name, int *num_paths)
{
	sv_iocdata_t ioc;
	uint_t npaths;
	int n;
	char **phci_list = NULL;
	char *node_name, *at;
	char vhci_name_buf[MAXPATHLEN];

	logdmsg(("vhci_to_phci: vchi_name =  %s\n", vhci_name));

	*num_paths = 0;
	(void) strlcpy(vhci_name_buf, vhci_name, MAXPATHLEN);

	/* first get the number paths */
	bzero(&ioc, sizeof (sv_iocdata_t));
	ioc.client = vhci_name_buf;
	ioc.ret_elem = &npaths;
	if (vhci_ctl(&ioc, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO) != 0 ||
	    npaths == 0) {
		logdmsg(("vhci_to_phci: vhci_ctl failed to get npaths: %s\n",
		    strerror(errno)));
		return (NULL);
	}

	/* now allocate memory for the path information and get all paths */
	bzero(&ioc, sizeof (sv_iocdata_t));
	ioc.client = vhci_name_buf;
	ioc.buf_elem = npaths;
	ioc.ret_elem = &npaths;
	if ((ioc.ret_buf = (sv_path_info_t *)calloc(npaths,
	    sizeof (sv_path_info_t))) == NULL)
		return (NULL);
	if (vhci_ctl(&ioc, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO) != 0 ||
	    npaths == 0) {
		logdmsg(("vhci_to_phci: vhci_ctl failed: %s\n",
		    strerror(errno)));
		goto out;
	}

	if (ioc.buf_elem < npaths)
		npaths = ioc.buf_elem;

	if ((node_name = strrchr(vhci_name_buf, '/')) == NULL ||
	    (at = strchr(node_name, '@')) == NULL)
		goto out;

	node_name++;
	*at = '\0';

	/* allocate one more (than npaths) for the terminating NULL pointer */
	if ((phci_list = calloc(npaths + 1, sizeof (char *))) == NULL)
		goto out;

	/*
	 * add only online paths as non-online paths may not be accessible
	 * in the target environment.
	 */
	if ((n = add_to_phci_list(phci_list, ioc.ret_buf, npaths,
	    MDI_PATHINFO_STATE_ONLINE, node_name)) <= 0)
		goto out;

	free(ioc.ret_buf);
	*num_paths = n;

#ifdef DEBUG
	logdmsg(("vhci_to_phci: phci list:\n"));
	log_pathlist(phci_list);
#endif
	return (phci_list);

out:
	free(ioc.ret_buf);
	if (phci_list)
		free_pathlist(phci_list);
	return (NULL);
}

/*
 * build list of paths accessible from the target environment
 */
static int
build_pathlist(char *rootdir, char *vhcipath, char **pathlist, int npaths)
{
	int mpxio_disabled;
	int i, j;
	char *vpath = NULL;

	for (i = 0; i < npaths; i++) {
		mpxio_disabled = is_mpxio_disabled(rootdir, pathlist[i]);
		logdmsg(("build_pathlist: mpxio_disabled = %d "
		    "on path %s\n", mpxio_disabled, pathlist[i]));
		if (mpxio_disabled == -1)
			return (-1);
		if (mpxio_disabled == 0) {
			/*
			 * mpxio is enabled on this phci path.
			 * So use vhci path instead of phci path.
			 */
			if (vpath == NULL) {
				if ((vpath = strdup(vhcipath)) == NULL)
					return (-1);
				free(pathlist[i]);
				/* keep vhci path at beginning of the list */
				for (j = i; j > 0; j--)
					pathlist[j] = pathlist[j - 1];
				pathlist[0] = vpath;
			} else {
				free(pathlist[i]);
				npaths--;
				for (j = i; j < npaths; j++)
					pathlist[j] = pathlist[j + 1];
				pathlist[npaths] = NULL;
				/* compensate for i++ in the for loop */
				i--;
			}
		}
	}

#ifdef DEBUG
	logdmsg(("build_pathlist: returning npaths = %d, pathlist:\n", npaths));
	log_pathlist(pathlist);
#endif
	return (npaths);
}

/*
 * Check if the specified device is refenced in the vfstab file.
 * Return 1 if referenced, 0 if not.
 *
 * rootdir	root directory of the target environment
 * nodepath	/devices path of a device in the target environment without
 *		the /devices prefix and minor component.
 */
static int
is_dev_in_vfstab(char *rootdir, char *nodepath)
{
	FILE *fp;
	int linksize;
	struct vfstab vfsent;
	char *abspath, *minor;
	char physpath[MAXPATHLEN];
	char buf[MAXPATHLEN];

	logdmsg(("is_dev_in_vfstab: rootdir = %s, nodepath = %s\n",
	    rootdir, nodepath));

	(void) snprintf(buf, sizeof (buf), "%s%s", rootdir, VFSTAB);

	if ((fp = fopen(buf, "r")) == NULL)
		return (0);

	/*
	 * read device specials from vfstab and compare names at physical
	 * node path level.
	 */
	while (getvfsent(fp, &vfsent) == 0) {
		if (strncmp(vfsent.vfs_special, SLASH_DEV_SLASH,
		    sizeof (SLASH_DEV_SLASH) - 1) == 0) {
			(void) snprintf(buf, MAXPATHLEN, "%s%s",
			    rootdir, vfsent.vfs_special);
			if ((linksize = readlink(buf, physpath,
			    MAXPATHLEN)) > 0 && linksize < (MAXPATHLEN - 1)) {
				physpath[linksize] = '\0';
				if ((abspath = strstr(physpath,
				    SLASH_DEVICES_SLASH)) == NULL)
					continue;
			} else
				continue;
		} else if (strncmp(vfsent.vfs_special, SLASH_DEVICES_SLASH,
		    sizeof (SLASH_DEVICES_SLASH) - 1) == 0) {
			(void) strlcpy(physpath, vfsent.vfs_special,
			    MAXPATHLEN);
			abspath = physpath;
		} else
			continue;

		/* point to / after /devices */
		abspath += sizeof (SLASH_DEVICES_SLASH) - 2;
		/* strip minor component */
		if ((minor = strrchr(abspath, ':')) != NULL)
			*minor = '\0';

		if (strcmp(nodepath, abspath) == 0) {
			(void) fclose(fp);
			logdmsg(("is_dev_in_vfstab: returning 1\n"));
			return (1);
		}
	}

	(void) fclose(fp);
	return (0);
}

#endif /* __sparc */

static int
devlink_callback(di_devlink_t devlink, void *argp)
{
	const char *link;

	if ((link = di_devlink_path(devlink)) != NULL)
		(void) strlcpy((char *)argp, link, MAXPATHLEN);

	return (DI_WALK_CONTINUE);
}

/*
 * Get the /dev name in the install environment corresponding to physpath.
 *
 * physpath	/devices path in the install environment without the /devices
 * 		prefix.
 * buf		caller supplied buffer where the /dev name is placed on return
 * bufsz	length of the buffer
 *
 * Returns	strlen of the /dev name on success, -1 on failure.
 */
static int
get_install_devlink(char *physpath, char *buf, size_t bufsz)
{
	di_devlink_handle_t devlink_hdl;
	char devname[MAXPATHLEN];

	logdmsg(("get_install_devlink: physpath = %s\n", physpath));

	if ((devlink_hdl = di_devlink_init(NULL, 0)) == NULL) {
		logdmsg(("get_install_devlink: di_devlink_init() failed: %s\n",
		    strerror(errno)));
		return (-1);
	}

	devname[0] = '\0';
	if (di_devlink_walk(devlink_hdl, NULL, physpath, DI_PRIMARY_LINK,
	    devname, devlink_callback) != 0 || devname[0] == '\0') {
		logdmsg(("get_install_devlink: di_devlink_walk failed: %s\n",
		    strerror(errno)));
		(void) di_devlink_fini(&devlink_hdl);
		return (-1);
	}

	(void) di_devlink_fini(&devlink_hdl);

	logdmsg(("get_install_devlink: devlink = %s\n", devname));
	return (strlcpy(buf, devname, bufsz));
}

/*
 * Get the /dev name in the target environment corresponding to physpath.
 *
 * rootdir	root directory of the target environment
 * physpath	/devices path in the target environment without the /devices
 * 		prefix.
 * buf		caller supplied buffer where the /dev name is placed on return
 * bufsz	length of the buffer
 *
 * Returns	strlen of the /dev name on success, -1 on failure.
 */
static int
get_target_devlink(char *rootdir, char *physpath, char *buf, size_t bufsz)
{
	char *p;
	int linksize;
	DIR *dirp;
	struct dirent *direntry;
	char dirpath[MAXPATHLEN];
	char devname[MAXPATHLEN];
	char physdev[MAXPATHLEN];

	logdmsg(("get_target_devlink: rootdir = %s, physpath = %s\n",
	    rootdir, physpath));

	if ((p = strrchr(physpath, '/')) == NULL)
		return (-1);

	if (strstr(p, ",raw") != NULL) {
		(void) snprintf(dirpath, MAXPATHLEN, "%s/dev/rdsk", rootdir);
	} else {
		(void) snprintf(dirpath, MAXPATHLEN, "%s/dev/dsk", rootdir);
	}

	if ((dirp = opendir(dirpath)) == NULL)
		return (-1);

	while ((direntry = readdir(dirp)) != NULL) {
		if (strcmp(direntry->d_name, ".") == 0 ||
		    strcmp(direntry->d_name, "..") == 0)
			continue;

		(void) snprintf(devname, MAXPATHLEN, "%s/%s",
		    dirpath, direntry->d_name);

		if ((linksize = readlink(devname, physdev, MAXPATHLEN)) > 0 &&
		    linksize < (MAXPATHLEN - 1)) {
			physdev[linksize] = '\0';
			if ((p = strstr(physdev, SLASH_DEVICES_SLASH)) !=
			    NULL && strcmp(p + sizeof (SLASH_DEVICES) - 1,
			    physpath) == 0) {
				(void) closedir(dirp);
				logdmsg(("get_target_devlink: devlink = %s\n",
				    devname + strlen(rootdir)));
				return (strlcpy(buf, devname + strlen(rootdir),
				    bufsz));
			}
		}
	}

	(void) closedir(dirp);
	return (-1);
}

/*
 * Convert device name to physpath.
 *
 * rootdir	root directory
 * devname	a /dev name or /devices name under rootdir
 * physpath	caller supplied buffer where the /devices path will be placed
 *		on return (without the /devices prefix).
 * physpathlen	length of the physpath buffer
 *
 * Returns 0 on success, -1 on failure.
 */
static int
devname2physpath(char *rootdir, char *devname, char *physpath, int physpathlen)
{
	int linksize;
	char *p;
	char devlink[MAXPATHLEN];
	char tmpphyspath[MAXPATHLEN];

	logdmsg(("devname2physpath: rootdir = %s, devname = %s\n",
	    rootdir, devname));

	if (strncmp(devname, SLASH_DEVICES_SLASH,
	    sizeof (SLASH_DEVICES_SLASH) - 1) != 0) {
		if (*rootdir == '\0')
			linksize = readlink(devname, tmpphyspath, MAXPATHLEN);
		else {
			(void) snprintf(devlink, MAXPATHLEN, "%s%s",
			    rootdir, devname);
			linksize = readlink(devlink, tmpphyspath, MAXPATHLEN);
		}
		if (linksize > 0 && linksize < (MAXPATHLEN - 1)) {
			tmpphyspath[linksize] = '\0';
			if ((p = strstr(tmpphyspath, SLASH_DEVICES_SLASH))
			    == NULL)
				return (-1);
		} else
			return (-1);
	} else
		p = devname;

	(void) strlcpy(physpath, p + sizeof (SLASH_DEVICES) - 1, physpathlen);
	logdmsg(("devname2physpath: physpath = %s\n", physpath));
	return (0);
}

/*
 * Map a device name (devname) from the target environment to the
 * install environment.
 *
 * rootdir	root directory of the target environment
 * devname	/dev or /devices name under the target environment
 * buf		caller supplied buffer where the mapped /dev name is placed
 *		on return
 * bufsz	length of the buffer
 *
 * Returns	strlen of the mapped /dev name on success, -1 on failure.
 */
int
devfs_target2install(const char *rootdir, const char *devname, char *buf,
    size_t bufsz)
{
	char physpath[MAXPATHLEN];

	logdmsg(("devfs_target2install: rootdir = %s, devname = %s\n",
	    STRVAL(rootdir), STRVAL(devname)));

	if (rootdir == NULL || devname == NULL || buf == NULL || bufsz == 0)
		return (-1);

	if (strcmp(rootdir, "/") == 0)
		rootdir = "";

	if (devname2physpath((char *)rootdir, (char *)devname, physpath,
	    MAXPATHLEN) != 0)
		return (-1);

#ifdef __sparc
	if (client_name_type(physpath) == CLIENT_TYPE_PHCI) {
		char *mapped_node_path, *minor;
		char minorbuf[MAXNAMELEN];

		/* strip minor component if present */
		if ((minor = strrchr(physpath, ':')) != NULL) {
			*minor = '\0';
			minor++;
			(void) strlcpy(minorbuf, minor, MAXNAMELEN);
		}
		if ((mapped_node_path = phci_to_vhci(physpath)) != NULL) {
			if (minor)
				(void) snprintf(physpath, MAXPATHLEN,
				    "%s:%s", mapped_node_path, minorbuf);
			else
				(void) strlcpy(physpath, mapped_node_path,
				    MAXPATHLEN);
			free(mapped_node_path);
			logdmsg(("devfs_target2install: mapped physpath: %s\n",
			    physpath));

		} else if (minor)
			*(minor - 1) = ':';
	}
#endif /* __sparc */

	return (get_install_devlink(physpath, buf, bufsz));
}

/*
 * Map a device name (devname) from the install environment to the target
 * environment.
 *
 * rootdir	root directory of the target environment
 * devname	/dev or /devices name under the install environment
 * buf		caller supplied buffer where the mapped /dev name is placed
 *		on return
 * bufsz	length of the buffer
 *
 * Returns	strlen of the mapped /dev name on success, -1 on failure.
 */
int
devfs_install2target(const char *rootdir, const char *devname, char *buf,
    size_t bufsz)
{
	char physpath[MAXPATHLEN];

	logdmsg(("devfs_install2target: rootdir = %s, devname = %s\n",
	    STRVAL(rootdir), STRVAL(devname)));

	if (rootdir == NULL || devname == NULL || buf == NULL || bufsz == 0)
		return (-1);

	if (strcmp(rootdir, "/") == 0)
		rootdir = "";

	if (devname2physpath("", (char *)devname, physpath, MAXPATHLEN) != 0)
		return (-1);

#ifdef __sparc
	if (client_name_type(physpath) == CLIENT_TYPE_VHCI) {
		char **pathlist;
		int npaths, i, j;
		char *minor;
		char minorbuf[MAXNAMELEN];

		/* strip minor component if present */
		if ((minor = strrchr(physpath, ':')) != NULL) {
			*minor = '\0';
			minor++;
			(void) strlcpy(minorbuf, minor, MAXNAMELEN);
		}

		if ((pathlist = vhci_to_phci(physpath, &npaths)) == NULL)
			return (-1);

		if ((npaths = build_pathlist((char *)rootdir, physpath,
		    pathlist, npaths)) <= 0) {
			free_pathlist(pathlist);
			return (-1);
		}

		/*
		 * in case of more than one path, try to use the path
		 * referenced in the vfstab file, otherwise use the first path.
		 */
		j = 0;
		if (npaths > 1) {
			for (i = 0; i < npaths; i++) {
				if (is_dev_in_vfstab((char *)rootdir,
				    pathlist[i])) {
					j = i;
					break;
				}
			}
		}

		if (minor)
			(void) snprintf(physpath, MAXPATHLEN,
			    "%s:%s", pathlist[j], minorbuf);
		else
			(void) strlcpy(physpath, pathlist[j], MAXPATHLEN);
		free_pathlist(pathlist);
	}
#endif /* __sparc */

	return (get_target_devlink((char *)rootdir, physpath, buf, bufsz));
}

/*
 * A parser for /etc/path_to_inst.
 * The user-supplied callback is called once for each entry in the file.
 * Returns 0 on success, ENOMEM/ENOENT/EINVAL on error.
 * Callback may return DI_WALK_TERMINATE to terminate the walk,
 * otherwise DI_WALK_CONTINUE.
 */
int
devfs_parse_binding_file(const char *binding_file,
	int (*callback)(void *, const char *, int,
	    const char *), void *cb_arg)
{
	token_t token;
	struct conf_file file;
	char tokval[MAX_TOKEN_SIZE];
	enum { STATE_RESET, STATE_DEVPATH, STATE_INSTVAL } state;
	char *devpath;
	char *bindname;
	int instval = 0;
	int rv;

	if ((devpath = calloc(1, MAXPATHLEN)) == NULL)
		return (ENOMEM);
	if ((bindname = calloc(1, MAX_TOKEN_SIZE)) == NULL) {
		free(devpath);
		return (ENOMEM);
	}

	if ((file.fp = fopen(binding_file, "r")) == NULL) {
		free(devpath);
		free(bindname);
		return (errno);
	}

	file.filename = (char *)binding_file;
	file.linenum = 1;

	state = STATE_RESET;
	while ((token = lex(&file, tokval, MAX_TOKEN_SIZE)) != T_EOF) {
		switch (token) {
		case T_POUND:
			/*
			 * Skip comments.
			 */
			find_eol(file.fp);
			break;
		case T_NAME:
		case T_STRING:
			switch (state) {
			case STATE_RESET:
				if (strlcpy(devpath, tokval,
				    MAXPATHLEN) >= MAXPATHLEN)
					goto err;
				state = STATE_DEVPATH;
				break;
			case STATE_INSTVAL:
				if (strlcpy(bindname, tokval,
				    MAX_TOKEN_SIZE) >= MAX_TOKEN_SIZE)
					goto err;
				rv = callback(cb_arg,
				    devpath, instval, bindname);
				if (rv == DI_WALK_TERMINATE)
					goto done;
				if (rv != DI_WALK_CONTINUE)
					goto err;
				state = STATE_RESET;
				break;
			default:
				file_err(&file, tok_err, tokval);
				state = STATE_RESET;
				break;
			}
			break;
		case T_DECVAL:
		case T_HEXVAL:
			switch (state) {
			case STATE_DEVPATH:
				instval = (int)strtol(tokval, NULL, 0);
				state = STATE_INSTVAL;
				break;
			default:
				file_err(&file, tok_err, tokval);
				state = STATE_RESET;
				break;
			}
			break;
		case T_NEWLINE:
			file.linenum++;
			state = STATE_RESET;
			break;
		default:
			file_err(&file, tok_err, tokval);
			state = STATE_RESET;
			break;
		}
	}

done:
	(void) fclose(file.fp);
	free(devpath);
	free(bindname);
	return (0);

err:
	(void) fclose(file.fp);
	free(devpath);
	free(bindname);
	return (EINVAL);
}

/*
 * Walk the minor nodes of all children below the specified device
 * by calling the provided callback with the path to each minor.
 */
static int
devfs_walk_children_minors(const char *device_path, struct stat *st,
    int (*callback)(void *, const char *), void *cb_arg, int *terminate)
{
	DIR *dir;
	struct dirent *dp;
	char *minor_path = NULL;
	int need_close = 0;
	int rv;

	if ((minor_path = calloc(1, MAXPATHLEN)) == NULL)
		return (ENOMEM);

	if ((dir = opendir(device_path)) == NULL) {
		rv = ENOENT;
		goto err;
	}
	need_close = 1;

	while ((dp = readdir(dir)) != NULL) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		(void) snprintf(minor_path, MAXPATHLEN,
		    "%s/%s", device_path, dp->d_name);
		if (stat(minor_path, st) == -1)
			continue;
		if (S_ISDIR(st->st_mode)) {
			rv = devfs_walk_children_minors(
			    (const char *)minor_path, st,
			    callback, cb_arg, terminate);
			if (rv != 0)
				goto err;
			if (*terminate)
				break;
		} else {
			rv = callback(cb_arg, minor_path);
			if (rv == DI_WALK_TERMINATE) {
				*terminate = 1;
				break;
			}
			if (rv != DI_WALK_CONTINUE) {
				rv = EINVAL;
				goto err;
			}
		}
	}

	rv = 0;
err:
	if (need_close)
		(void) closedir(dir);
	if (minor_path)
		free(minor_path);
	return (rv);
}

/*
 * Return the path to each minor node for a device by
 * calling the provided callback.
 */
static int
devfs_walk_device_minors(const char *device_path, struct stat *st,
    int (*callback)(void *, const char *), void *cb_arg, int *terminate)
{
	char *minor_path;
	char *devpath;
	char *expr;
	regex_t regex;
	int need_regfree = 0;
	int need_close = 0;
	DIR *dir;
	struct dirent *dp;
	int rv;
	char *p;

	minor_path = calloc(1, MAXPATHLEN);
	devpath = calloc(1, MAXPATHLEN);
	expr = calloc(1, MAXNAMELEN);
	if (devpath == NULL || expr == NULL || minor_path == NULL) {
		rv = ENOMEM;
		goto err;
	}

	rv = EINVAL;
	if (strlcpy(devpath, device_path, MAXPATHLEN) >= MAXPATHLEN)
		goto err;
	if ((p = strrchr(devpath, '/')) == NULL)
		goto err;
	*p++ = 0;
	if (strlen(p) == 0)
		goto err;
	if (snprintf(expr, MAXNAMELEN, "%s:.*", p) >= MAXNAMELEN)
		goto err;
	if (regcomp(&regex, expr, REG_EXTENDED) != 0)
		goto err;
	need_regfree = 1;

	if ((dir = opendir(devpath)) == NULL) {
		rv = ENOENT;
		goto err;
	}
	need_close = 1;

	while ((dp = readdir(dir)) != NULL) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		(void) snprintf(minor_path, MAXPATHLEN,
		    "%s/%s", devpath, dp->d_name);
		if (stat(minor_path, st) == -1)
			continue;
		if ((S_ISBLK(st->st_mode) || S_ISCHR(st->st_mode)) &&
		    regexec(&regex, dp->d_name, 0, NULL, 0) == 0) {
			rv = callback(cb_arg, minor_path);
			if (rv == DI_WALK_TERMINATE) {
				*terminate = 1;
				break;
			}
			if (rv != DI_WALK_CONTINUE) {
				rv = EINVAL;
				goto err;
			}
		}
	}

	rv = 0;
err:
	if (need_close)
		(void) closedir(dir);
	if (need_regfree)
		regfree(&regex);
	if (devpath)
		free(devpath);
	if (minor_path)
		free(minor_path);
	if (expr)
		free(expr);
	return (rv);
}

/*
 * Perform a walk of all minor nodes for the specified device,
 * and minor nodes below the device.
 */
int
devfs_walk_minor_nodes(const char *device_path,
	int (*callback)(void *, const char *), void *cb_arg)
{
	struct stat stbuf;
	int rv;
	int terminate = 0;

	rv = devfs_walk_device_minors(device_path,
	    &stbuf, callback, cb_arg, &terminate);
	if (rv == 0 && terminate == 0) {
		rv = devfs_walk_children_minors(device_path,
		    &stbuf, callback, cb_arg, &terminate);
	}
	return (rv);
}

#ifdef DEBUG

static void
vlog_debug_msg(char *fmt, va_list ap)
{
	time_t clock;
	struct tm t;

	if (!devfsmap_debug)
		return;

	if (logfp == NULL) {
		if (*devfsmap_logfile != '\0') {
			logfp = fopen(devfsmap_logfile, "a");
			if (logfp)
				(void) fprintf(logfp, "\nNew Log:\n");
		}

		if (logfp == NULL)
			logfp = stdout;
	}

	clock = time(NULL);
	(void) localtime_r(&clock, &t);
	(void) fprintf(logfp, "%02d:%02d:%02d ", t.tm_hour, t.tm_min,
	    t.tm_sec);
	(void) vfprintf(logfp, fmt, ap);
	(void) fflush(logfp);
}

static void
log_debug_msg(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog_debug_msg(fmt, ap);
	va_end(ap);
}

#ifdef __sparc

static char *
mpxio_disable_string(int mpxio_disable)
{
	if (mpxio_disable == 0)
		return ("no");
	else if (mpxio_disable == 1)
		return ("yes");
	else
		return ("not specified");
}

static void
log_confent_list(char *filename, struct conf_entry *confent_list,
    int global_mpxio_disable)
{
	struct conf_entry *confent;

	log_debug_msg("log_confent_list: filename = %s:\n", filename);
	if (global_mpxio_disable != -1)
		log_debug_msg("\tdriver global mpxio_disable = \"%s\"\n\n",
		    mpxio_disable_string(global_mpxio_disable));

	for (confent = confent_list; confent != NULL; confent = confent->next) {
		if (confent->name)
			log_debug_msg("\tname = %s\n", confent->name);
		if (confent->parent)
			log_debug_msg("\tparent = %s\n", confent->parent);
		if (confent->class)
			log_debug_msg("\tclass = %s\n", confent->class);
		if (confent->unit_address)
			log_debug_msg("\tunit_address = %s\n",
			    confent->unit_address);
		if (confent->port != -1)
			log_debug_msg("\tport = %d\n", confent->port);
		log_debug_msg("\tmpxio_disable = \"%s\"\n\n",
		    mpxio_disable_string(confent->mpxio_disable));
	}
}

static void
log_pathlist(char **pathlist)
{
	char **p;

	for (p = pathlist; *p != NULL; p++)
		log_debug_msg("\t%s\n", *p);
}

#endif /* __sparc */

#endif /* DEBUG */
