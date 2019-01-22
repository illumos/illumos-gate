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

#include "cfga_usb.h"


#define	MAXLINESIZE	512
#define	FE_BUFLEN 256

#define	isunary(ch)	((ch) == '~' || (ch) == '-')
#define	iswhite(ch)	((ch) == ' ' || (ch) == '\t')
#define	isnewline(ch)	((ch) == '\n' || (ch) == '\r' || (ch) == '\f')
#define	isalphanum(ch)	(isalpha(ch) || isdigit(ch))
#define	isnamechar(ch)	(isalphanum(ch) || (ch) == '_' || (ch) == '-')

#define	MAX(a, b)	((a) < (b) ? (b) : (a))
#define	GETC(a, cntr)	a[cntr++]
#define	UNGETC(cntr)	cntr--


typedef struct usb_configrec {
	char    *selection;
	int	idVendor, idProduct, cfgndx;
	char    *serialno;
	char    *pathname;
	char    *driver;
} usb_configrec_t;

typedef enum {
	USB_SELECTION, USB_VENDOR, USB_PRODUCT, USB_CFGNDX, USB_SRNO,
	USB_PATH, USB_DRIVER, USB_NONE
} config_field_t;

typedef struct usbcfg_var {
	const char *name;
	config_field_t field;
} usbcfg_var_t;

static usbcfg_var_t usbcfg_varlist[] = {
	{ "selection",	USB_SELECTION },
	{ "idVendor",	USB_VENDOR },
	{ "idProduct",	USB_PRODUCT },
	{ "cfgndx",	USB_CFGNDX },
	{ "srno",	USB_SRNO },
	{ "pathname",	USB_PATH },
	{ "driver",	USB_DRIVER },
	{ NULL,		USB_NONE }
};

typedef enum {
	EQUALS,
	AMPERSAND,
	BIT_OR,
	STAR,
	POUND,
	COLON,
	SEMICOLON,
	COMMA,
	SLASH,
	WHITE_SPACE,
	NEWLINE,
	E_O_F,
	STRING,
	HEXVAL,
	DECVAL,
	NAME
} token_t;


static char	usbconf_file[] = USBCONF_FILE;
static int	linenum = 1;
static int	cntr = 0;
static int	frec = 0;
static int	brec = 0;
static int	btoken = 0;
mutex_t		file_lock = DEFAULTMUTEX;


/*
 * prototypes
 */
static int	get_string(u_longlong_t *llptr, char *tchar);
static int	getvalue(char *token, u_longlong_t *valuep);


/*
 * The next item on the line is a string value. Allocate memory for
 * it and copy the string. Return 1, and set arg ptr to newly allocated
 * and initialized buffer, or NULL if an error occurs.
 */
static int
get_string(u_longlong_t *llptr, char *tchar)
{
	register char *cp;
	register char *start = NULL;
	register int len = 0;

	len = strlen(tchar);
	start = tchar;
	/* copy string */
	cp = calloc(len + 1, sizeof (char));
	if (cp == NULL) {
		*llptr = 0;

		return (0);
	}

	*llptr = (u_longlong_t)(uintptr_t)cp;
	for (; len > 0; len--) {
		/* convert some common escape sequences */
		if (*start == '\\') {
			switch (*(start + 1)) {
			case 't':
				/* tab */
				*cp++ = '\t';
				len--;
				start += 2;
				break;
			case 'n':
				/* new line */
				*cp++ = '\n';
				len--;
				start += 2;
				break;
			case 'b':
				/* back space */
				*cp++ = '\b';
				len--;
				start += 2;
				break;
			default:
				/* simply copy it */
				*cp++ = *start++;
				break;
			}
		} else {
			*cp++ = *start++;
		}
	}
	*cp = '\0';
	return (1);
}


/*
 * get a decimal octal or hex number. Handle '~' for one's complement.
 */
static int
getvalue(char *token, u_longlong_t *valuep)
{
	register int radix;
	register u_longlong_t retval = 0;
	register int onescompl = 0;
	register int negate = 0;
	register char c;

	if (*token == '~') {
		onescompl++; /* perform one's complement on result */
		token++;
	} else if (*token == '-') {
		negate++;
		token++;
	}
	if (*token == '0') {
		token++;
		c = *token;

		if (c == '\0') {
			*valuep = 0;    /* value is 0 */
			return (0);
		}

		if (c == 'x' || c == 'X') {
			radix = 16;
			token++;
		} else {
			radix = 8;
		}
	} else {
		radix = 10;
	}

	while ((c = *token++)) {
		switch (radix) {
		case 8:
			if (c >= '0' && c <= '7') {
				c -= '0';
			} else {
				return (-1);    /* invalid number */
			}
			retval = (retval << 3) + c;
			break;
		case 10:
			if (c >= '0' && c <= '9') {
				c -= '0';
			} else {
				return (-1);    /* invalid number */
			}
			retval = (retval * 10) + c;
			break;
		case 16:
			if (c >= 'a' && c <= 'f') {
				c = c - 'a' + 10;
			} else if (c >= 'A' && c <= 'F') {
				c = c - 'A' + 10;
			} else if (c >= '0' && c <= '9') {
				c -= '0';
			} else {
				return (-1);    /* invalid number */
			}
			retval = (retval << 4) + c;
			break;
		}
	}
	if (onescompl)
		retval = ~retval;
	if (negate)
		retval = -retval;
	*valuep = retval;

	return (0);
}

/*
 * returns the field from the token
 */
static config_field_t
usb_get_var_type(char *str)
{
	usbcfg_var_t    *cfgvar;

	cfgvar = &usbcfg_varlist[0];
	while (cfgvar->field != USB_NONE) {
		if (strcasecmp(cfgvar->name, str) == 0) {
			break;
		} else {
			cfgvar++;
		}
	}

	return (cfgvar->field);
}


/* ARGSUSED */
static token_t
lex(char *buf, char *val, char **errmsg)
{
	int	ch, oval, badquote;
	char	*cp;
	token_t token;

	cp = val;
	while ((ch = GETC(buf, cntr)) == ' ' || ch == '\t');

	/*
	 * Note the beginning of a token
	 */
	btoken = cntr - 1;

	*cp++ = (char)ch;
	switch (ch) {
	case '=':
		token = EQUALS;
		break;
	case '&':
		token = AMPERSAND;
		break;
	case '|':
		token = BIT_OR;
		break;
	case '*':
		token = STAR;
		break;
	case '#':
		token = POUND;
		break;
	case ':':
		token = COLON;
		break;
	case ';':
		token = SEMICOLON;
		break;
	case ',':
		token = COMMA;
		break;
	case '/':
		token = SLASH;
		break;
	case ' ':
	case '\t':
	case '\f':
		while ((ch  = GETC(buf, cntr)) == ' ' ||
		    ch == '\t' || ch == '\f')
			*cp++ = (char)ch;
		(void) UNGETC(cntr);
		token = WHITE_SPACE;
		break;
	case '\n':
	case '\r':
		token = NEWLINE;
		break;
	case '"':
		cp--;
		badquote = 0;
		while (!badquote && (ch  = GETC(buf, cntr)) != '"') {
			switch (ch) {
			case '\n':
			case -1:
				(void) snprintf(*errmsg, MAXPATHLEN,
				    "Missing \"");
				cp = val;
				*cp++ = '\n';
				badquote = 1;
				/* since we consumed the newline/EOF */
				(void) UNGETC(cntr);
				break;

			case '\\':
				ch = (char)GETC(buf, cntr);
				if (!isdigit(ch)) {
					/* escape the character */
					*cp++ = (char)ch;
					break;
				}
				oval = 0;
				while (ch >= '0' && ch <= '7') {
					ch -= '0';
					oval = (oval << 3) + ch;
					ch = (char)GETC(buf, cntr);
				}
				(void) UNGETC(cntr);
				/* check for character overflow? */
				if (oval > 127) {
					(void) snprintf(*errmsg, MAXPATHLEN,
					    "Character overflow detected.\n");
				}
				*cp++ = (char)oval;
				break;
			default:
				*cp++ = (char)ch;
				break;
			}
		}
		token = STRING;
		break;

	default:
		if (ch == -1) {
			token = EOF;
			break;
		}
		/*
		 * detect a lone '-' (including at the end of a line), and
		 * identify it as a 'name'
		 */
		if (ch == '-') {
			*cp++ = (char)(ch = GETC(buf, cntr));
			if (iswhite(ch) || (ch == '\n')) {
				(void) UNGETC(cntr);
				cp--;
				token = NAME;
				break;
			}
		} else if (isunary(ch)) {
			*cp++ = (char)(ch = GETC(buf, cntr));
		}

		if (isdigit(ch)) {
			if (ch == '0') {
				if ((ch = GETC(buf, cntr)) == 'x') {
					*cp++ = (char)ch;
					ch = GETC(buf, cntr);
					while (isxdigit(ch)) {
						*cp++ = (char)ch;
						ch = GETC(buf, cntr);
					}
					(void) UNGETC(cntr);
					token = HEXVAL;
				} else {
					goto digit;
				}
			} else {
				ch = GETC(buf, cntr);
digit:
				while (isdigit(ch)) {
					*cp++ = (char)ch;
					ch = GETC(buf, cntr);
				}
				(void) UNGETC(cntr);
				token = DECVAL;
			}
		} else if (isalpha(ch) || ch == '\\') {
			if (ch != '\\') {
				ch = GETC(buf, cntr);
			} else {
				/*
				 * if the character was a backslash,
				 * back up so we can overwrite it with
				 * the next (i.e. escaped) character.
				 */
				cp--;
			}

			while (isnamechar(ch) || ch == '\\') {
				if (ch == '\\')
					ch = GETC(buf, cntr);
				*cp++ = (char)ch;
				ch = GETC(buf, cntr);
			}
			(void) UNGETC(cntr);
			token = NAME;
		} else {

			return (-1);
		}
		break;
	}
	*cp = '\0';

	return (token);
}


/*
 * Leave NEWLINE as the next character.
 */
static void
find_eol(char *buf)
{
	register int ch;

	while ((ch = GETC(buf, cntr)) != -1) {
		if (isnewline(ch)) {
			(void) UNGETC(cntr);
			break;
		}
	}
}


/*
 * Fetch one record from the USBCONF_FILE
 */
static token_t
usb_get_conf_rec(char *buf, usb_configrec_t **rec, char **errmsg)
{
	token_t token;
	char tokval[MAXLINESIZE];
	usb_configrec_t *user_rec;
	config_field_t  cfgvar;
	u_longlong_t    llptr;
	u_longlong_t    value;
	boolean_t	sor = B_TRUE;

	enum {
		USB_NEWVAR, USB_CONFIG_VAR, USB_VAR_EQUAL, USB_VAR_VALUE,
		USB_ERROR
	} parse_state = USB_NEWVAR;

	DPRINTF("usb_get_conf_rec:\n");

	user_rec = (usb_configrec_t *)calloc(1, sizeof (usb_configrec_t));
	if (user_rec == (usb_configrec_t *)NULL) {
		return (0);
	}

	user_rec->idVendor = user_rec->idProduct = user_rec->cfgndx = -1;

	token = lex(buf, tokval, errmsg);
	while ((token != EOF) && (token != SEMICOLON)) {
		switch (token) {
		case STAR:
		case POUND:
			/* skip comments */
			find_eol(buf);
			break;
		case NEWLINE:
			linenum++;
			break;
		case NAME:
		case STRING:
			switch (parse_state) {
			case USB_NEWVAR:
				cfgvar = usb_get_var_type(tokval);
				if (cfgvar == USB_NONE) {
					parse_state = USB_ERROR;
					(void) snprintf(*errmsg, MAXPATHLEN,
					    "Syntax Error: Invalid field %s",
					    tokval);
				} else {
					/*
					 * Note the beginning of a record
					 */
					if (sor) {
						brec = btoken;
						if (frec == 0) frec = brec;
						sor = B_FALSE;
					}
					parse_state = USB_CONFIG_VAR;
				}
				break;
			case USB_VAR_VALUE:
				if ((cfgvar == USB_VENDOR) ||
				    (cfgvar == USB_PRODUCT) ||
				    (cfgvar == USB_CFGNDX)) {
					parse_state = USB_ERROR;
					(void) snprintf(*errmsg, MAXPATHLEN,
					    "Syntax Error: Invalid value %s "
					    "for field: %s\n", tokval,
					    usbcfg_varlist[cfgvar].name);
				} else if (get_string(&llptr, tokval)) {
					switch (cfgvar) {
					case USB_SELECTION:
						user_rec->selection =
						    (char *)(uintptr_t)llptr;
						parse_state = USB_NEWVAR;
						break;
					case USB_SRNO:
						user_rec->serialno =
						    (char *)(uintptr_t)llptr;
						parse_state = USB_NEWVAR;
						break;
					case USB_PATH:
						user_rec->pathname =
						    (char *)(uintptr_t)llptr;
						parse_state = USB_NEWVAR;
						break;
					case USB_DRIVER:
						user_rec->driver =
						    (char *)(uintptr_t)llptr;
						parse_state = USB_NEWVAR;
						break;
					default:
						parse_state = USB_ERROR;
						free((void *)(uintptr_t)llptr);
					}
				} else {
					parse_state = USB_ERROR;
					(void) snprintf(*errmsg, MAXPATHLEN,
					    "Syntax Error: Invalid value %s "
					    "for field: %s\n", tokval,
					    usbcfg_varlist[cfgvar].name);
				}
				break;
			case USB_ERROR:
				/* just skip */
				break;
			default:
				parse_state = USB_ERROR;
				(void) snprintf(*errmsg, MAXPATHLEN,
				    "Syntax Error: at %s", tokval);
				break;
			}
			break;
		case EQUALS:
			if (parse_state == USB_CONFIG_VAR) {
				if (cfgvar == USB_NONE) {
					parse_state = USB_ERROR;
					(void) snprintf(*errmsg, MAXPATHLEN,
					    "Syntax Error: unexpected '='");
				} else {
					parse_state = USB_VAR_VALUE;
				}
			} else if (parse_state != USB_ERROR) {
				(void) snprintf(*errmsg, MAXPATHLEN,
				    "Syntax Error: unexpected '='");
				parse_state = USB_ERROR;
			}
			break;
		case HEXVAL:
		case DECVAL:
			if ((parse_state == USB_VAR_VALUE) && (cfgvar !=
			    USB_NONE)) {
				(void) getvalue(tokval, &value);
				switch (cfgvar) {
				case USB_VENDOR:
					user_rec->idVendor = (int)value;
					parse_state = USB_NEWVAR;
					break;
				case USB_PRODUCT:
					user_rec->idProduct = (int)value;
					parse_state = USB_NEWVAR;
					break;
				case USB_CFGNDX:
					user_rec->cfgndx = (int)value;
					parse_state = USB_NEWVAR;
					break;
				default:
					(void) snprintf(*errmsg, MAXPATHLEN,
					    "Syntax Error: Invalid value for "
					    "%s", usbcfg_varlist[cfgvar].name);
				}
			} else if (parse_state != USB_ERROR) {
				parse_state = USB_ERROR;
				(void) snprintf(*errmsg, MAXPATHLEN,
				    "Syntax Error: unexpected hex/decimal: %s",
				    tokval);
			}
			break;
		default:
			(void) snprintf(*errmsg, MAXPATHLEN,
			    "Syntax Error: at: %s", tokval);
			parse_state = USB_ERROR;
			break;
		}
		token = lex(buf, tokval, errmsg);
	}
	*rec = user_rec;

	return (token);
}


/*
 * Here we compare the two records and determine if they are the same
 */
static boolean_t
usb_cmp_rec(usb_configrec_t *cfg_rec, usb_configrec_t *user_rec)
{
	char		*ustr, *cstr;
	boolean_t	srno = B_FALSE, path = B_FALSE;

	DPRINTF("usb_cmp_rec:\n");

	if ((cfg_rec->idVendor == user_rec->idVendor) &&
	    (cfg_rec->idProduct == user_rec->idProduct)) {
		if (user_rec->serialno) {
			if (cfg_rec->serialno) {
				srno = (strcmp(cfg_rec->serialno,
				    user_rec->serialno) == 0);
			} else {

				return (B_FALSE);
			}

		} else if (user_rec->pathname) {
			if (cfg_rec->pathname) {
				/*
				 * Comparing on this is tricky. At this point
				 * hubd knows: ../hubd@P/device@P while user
				 * will specify ..../hubd@P/keyboard@P
				 * First compare till .../hubd@P
				 * Second compare is just P in "device@P"
				 *
				 * XXX: note that we assume P as one character
				 * as there are no 2 digit hubs in the market.
				 */
				ustr = strrchr(user_rec->pathname, '/');
				cstr = strrchr(cfg_rec->pathname, '/');
				path = (strncmp(cfg_rec->pathname,
				    user_rec->pathname,
				    MAX(ustr - user_rec->pathname,
				    cstr - cfg_rec->pathname)) == 0);
				path = path && (*(user_rec->pathname +
				    strlen(user_rec->pathname) -1) ==
					*(cfg_rec->pathname +
					strlen(cfg_rec->pathname) - 1));
			} else {

				return (B_FALSE);
			}

		} else if (cfg_rec->serialno || cfg_rec->pathname) {

			return (B_FALSE);
		} else {

			return (B_TRUE);
		}

		return (srno || path);
	} else {

		return (B_FALSE);
	}
}


/*
 * free the record allocated in usb_get_conf_rec
 */
static void
usb_free_rec(usb_configrec_t *rec)
{
	if (rec == (usb_configrec_t *)NULL) {

		return;
	}

	free(rec->selection);
	free(rec->serialno);
	free(rec->pathname);
	free(rec->driver);
	free(rec);
}


int
add_entry(char *selection, int vid, int pid, int cfgndx, char *srno,
    char *path, char *driver, char **errmsg)
{
	int		file;
	int		rval = CFGA_USB_OK;
	char		*buf = (char *)NULL;
	char		str[MAXLINESIZE];
	token_t		token = NEWLINE;
	boolean_t	found = B_FALSE;
	struct stat	st;
	usb_configrec_t cfgrec, *user_rec = NULL;

	DPRINTF("add_entry: driver=%s, path=%s\n",
	    driver ? driver : "", path ? path : "");

	if (*errmsg == (char *)NULL) {
		if ((*errmsg = calloc(MAXPATHLEN, 1)) == (char *)NULL) {

			return (CFGA_USB_CONFIG_FILE);
		}
	}

	(void) mutex_lock(&file_lock);

	/* Initialize the cfgrec */
	cfgrec.selection = selection;
	cfgrec.idVendor = vid;
	cfgrec.idProduct = pid;
	cfgrec.cfgndx = cfgndx;
	cfgrec.serialno = srno;
	cfgrec.pathname = path;
	cfgrec.driver = driver;

	/* open config_map.conf file */
	file = open(usbconf_file, O_RDWR, 0666);
	if (file == -1) {
		(void) snprintf(*errmsg, MAXPATHLEN,
		    "failed to open config file\n");
		(void) mutex_unlock(&file_lock);

		return (CFGA_USB_CONFIG_FILE);
	}

	if (lockf(file, F_TLOCK, 0) == -1) {
		(void) snprintf(*errmsg, MAXPATHLEN,
		    "failed to lock config file\n");
		close(file);
		(void) mutex_unlock(&file_lock);

		return (CFGA_USB_LOCK_FILE);
	}

	/*
	 * These variables need to be reinitialized here as they may
	 * have been modified by a previous thread that called this
	 * function
	 */
	linenum = 1;
	cntr = 0;
	frec = 0;
	brec = 0;
	btoken = 0;

	if (fstat(file, &st) != 0) {
		DPRINTF("add_entry: failed to fstat config file\n");
		rval = CFGA_USB_CONFIG_FILE;
		goto exit;
	}

	if ((buf = (char *)malloc(st.st_size)) == NULL) {
		DPRINTF("add_entry: failed to fstat config file\n");
		rval = CFGA_USB_ALLOC_FAIL;
		goto exit;
	}

	if (st.st_size != read(file, buf, st.st_size)) {
		DPRINTF("add_entry: failed to read config file\n");
		rval = CFGA_USB_CONFIG_FILE;
		goto exit;
	}

	/* set up for reading the file */

	while ((token != EOF) && !found) {
		if (user_rec) {
			usb_free_rec(user_rec);
			user_rec = NULL;
		}
		token = usb_get_conf_rec(buf, &user_rec, errmsg);
		found = usb_cmp_rec(&cfgrec, user_rec);
		DPRINTF("add_entry: token=%x, found=%x\n", token, found);
	}

	bzero(str, MAXLINESIZE);

	if (found) {
		DPRINTF("FOUND\n");
		(void) snprintf(str, MAXLINESIZE, "selection=%s idVendor=0x%x "
		    "idProduct=0x%x ",
		    (cfgrec.selection) ? cfgrec.selection : user_rec->selection,
		    user_rec->idVendor, user_rec->idProduct);

		if ((user_rec->cfgndx != -1) || (cfgrec.cfgndx != -1)) {
			(void) snprintf(&str[strlen(str)], MAXLINESIZE,
			    "cfgndx=0x%x ", (cfgrec.cfgndx != -1) ?
			    cfgrec.cfgndx : user_rec->cfgndx);
		}

		if (user_rec->serialno) {
			(void) snprintf(&str[strlen(str)],  MAXLINESIZE,
			    "srno=\"%s\" ", user_rec->serialno);
		}

		if (user_rec->pathname) {
			(void) snprintf(&str[strlen(str)],  MAXLINESIZE,
			    "pathname=\"%s\" ", user_rec->pathname);
		}

		if (user_rec->driver) {
			(void) snprintf(&str[strlen(str)],  MAXLINESIZE,
			    "driver=\"%s\" ", user_rec->driver);
		} else if (cfgrec.driver != NULL) {
			if (strlen(cfgrec.driver)) {
				(void) snprintf(&str[strlen(str)],  MAXLINESIZE,
				    "driver=\"%s\" ", cfgrec.driver);
			}
		}

		(void) strlcat(str, ";", sizeof (str));

		/*
		 * Seek to the beginning of the record
		 */
		if (lseek(file, brec, SEEK_SET) == -1) {
			DPRINTF("add_entry: failed to lseek config file\n");
			rval = CFGA_USB_CONFIG_FILE;
			goto exit;
		}

		/*
		 * Write the modified record
		 */
		if (write(file, str, strlen(str)) == -1) {
			DPRINTF("add_entry: failed to write config file\n");
			rval = CFGA_USB_CONFIG_FILE;
			goto exit;
		}

		/*
		 * Write the rest of the file as it was
		 */
		if (write(file, buf+cntr, st.st_size - cntr) == -1) {
			DPRINTF("add_entry: failed to write config file\n");
			rval = CFGA_USB_CONFIG_FILE;
			goto exit;
		}

	} else {
		DPRINTF("!FOUND\n");
		(void) snprintf(str, MAXLINESIZE,
		    "selection=%s idVendor=0x%x idProduct=0x%x ",
		    (cfgrec.selection) ? cfgrec.selection : "enable",
		    cfgrec.idVendor, cfgrec.idProduct);

		if (cfgrec.cfgndx != -1) {
			(void) snprintf(&str[strlen(str)], MAXLINESIZE,
			    "cfgndx=0x%x ", cfgrec.cfgndx);
		}

		if (cfgrec.serialno) {
			(void) snprintf(&str[strlen(str)], MAXLINESIZE,
			    "srno=\"%s\" ", cfgrec.serialno);
		}

		if (cfgrec.pathname != NULL) {
			(void) snprintf(&str[strlen(str)], MAXLINESIZE,
			    "pathname=\"%s\" ", cfgrec.pathname);
		}

		if (cfgrec.driver != NULL) {
			if (strlen(cfgrec.driver)) {
				(void) snprintf(&str[strlen(str)], MAXLINESIZE,
				    "driver=\"%s\" ", cfgrec.driver);
			}
		}

		(void) strlcat(str, ";\n", sizeof (str));

		/*
		 * Incase this is the first entry, add it after the comments
		 */
		if (frec == 0) {
			frec = st.st_size;
		}

		/*
		 * Go to the beginning of the records
		 */
		if (lseek(file, frec, SEEK_SET) == -1) {
			DPRINTF("add_entry: failed to lseek config file\n");
			rval = CFGA_USB_CONFIG_FILE;
			goto exit;
		}

		/*
		 * Add the entry
		 */
		if (write(file, str, strlen(str)) == -1) {
			DPRINTF("add_entry: failed to write config file\n");
			rval = CFGA_USB_CONFIG_FILE;
			goto exit;
		}

		/*
		 * write the remaining file as it was
		 */
		if (write(file, buf+frec, st.st_size - frec) == -1) {
			DPRINTF("add_entry: failed to write config file\n");
			rval = CFGA_USB_CONFIG_FILE;
			goto exit;
		}
	}

	/* no error encountered */
	if (rval == CFGA_USB_OK) {
		free(errmsg);
	}

exit:
	if (buf != NULL) {
		free(buf);
	}

	if (lockf(file, F_ULOCK, 0) == -1) {
		DPRINTF("add_entry: failed to unlock config file\n");

		rval = CFGA_USB_LOCK_FILE;
	}

	close(file);

	(void) mutex_unlock(&file_lock);

	return (rval);
}
