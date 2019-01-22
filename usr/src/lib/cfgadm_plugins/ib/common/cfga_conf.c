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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "cfga_ib.h"
#include "cfga_conf.h"
#include <sys/stat.h>

/*
 * cfga_conf.c
 *
 *	This file supports adding/deleting/listing services from IBCONF_FILE.
 */

/*
 * function prototypes:
 */
static ib_service_type_t	ib_get_var_type(char *);
static ib_token_t		ib_lex(char *, char **);
static void			ib_find_eol();
static int			ib_get_string(char **, char *);
static int			ib_service_record_add(char *,
				    ib_service_type_t);
static ib_token_t		ib_get_services(char **);
static boolean_t		ib_cmp_service();
static void			ib_free_service_recs(void);
static int			ib_cleanup_file(int);
static int			ib_init_file(char **);
int				ib_add_service(char **);
int				ib_delete_service(char **);
int				ib_list_services(struct cfga_msg *, char **);
static cfga_ib_ret_t		ib_conf_control_ioctl(char *, uint_t);
static int			ib_service_record_valid(char *);

extern void			cfga_msg(struct cfga_msg *, const char *);


/* Global variables */

/*
 * supported "name=value" pairs from IBCONF_FILE
 */
static ibcfg_var_t ibcfg_varlist[] = {
	{ "name",		IB_NAME },
	{ "class",		IB_CLASS },
	{ "port-svc-list",	IB_PORT_SERVICE },
	{ "vppa-svc-list",	IB_VPPA_SERVICE },
	{ "hca-svc-list",	IB_HCASVC_SERVICE },
	{ NULL,			IB_NONE }
};

static char		ibconf_file[] = IBCONF_FILE;	/* file being read */
static int		ibcfg_linenum = 1;		/* track line#s */
static int		ibcfg_cntr = 0;			/* current char read */
static int		ibcfg_brec = 0;			/* beginning of rec */
static int		bvpparec = 0;			/* begin of vppa rec */
static int		bportrec = 0;			/* begin of port rec */
static int		bhcarec = 0;			/* begin of HCA rec */
static int		ibcfg_btoken = 0;		/* begin of new token */
static mutex_t		ibcfg_lock = DEFAULTMUTEX;	/* lock for the file */
static int		ibcfg_fd = -1;			/* file descriptor */
static int		ibcfg_tmpfd = 0;		/* tmp file "fd" */
static char		*file_buf = (char *)NULL;	/* read file into buf */
static char		*tmpnamef = (char *)NULL;	/* tmp file name */
static boolean_t	wrote_tmp = B_FALSE;		/* tmp file write in */
							/* progress indicator */
static struct stat	ibcfg_st;			/* file stat struct */

static int		ibcfg_nport_services;		/* # of PORT services */
static int		ibcfg_nvppa_services;		/* # of VPPA services */
static int		ibcfg_nhca_services;		/* # of HCA services */
static ib_svc_rec_t	*ibcfg_vppa_head;		/* VPPA service recs */
static ib_svc_rec_t	*ibcfg_port_head;		/* PORT service recs */
static ib_svc_rec_t	*ibcfg_hca_head;		/* HCA service recs */

extern char		*service_name;			/* service name */
extern ib_service_type_t service_type;			/* service type */


/*
 * Function:
 *	ib_get_var_type
 * Input:
 *	str	-	A parsed string from IBCONF_FILE
 * Output:
 *	NONE
 * Returns:
 *	Service type
 * Description:
 *	Returns the field from the token
 */
static ib_service_type_t
ib_get_var_type(char *str)
{
	register ibcfg_var_t    *cfgvar;

	cfgvar = &ibcfg_varlist[0];
	while (cfgvar->type != IB_NONE) {
		if (strcasecmp(cfgvar->name, str) == 0)
			break;
		else
			cfgvar++;
	}
	return (cfgvar->type);
}


/*
 * Function:
 *	ib_lex
 * Input:
 *	NONE
 * Output:
 *	val	-	value just read
 *	errmsg	-	pointer to error message string, if there are any errors
 * Returns:
 *	valid IB token
 * Description:
 *	Read tokens from the IBCONF_FILE and parse them
 */
/* ARGSUSED */
static ib_token_t
ib_lex(char *val, char **errmsg)
{
	int		ch, oval, badquote;
	char		*cp = val;
	ib_token_t	token;

	while ((ch = GETC(file_buf, ibcfg_cntr)) == ' ' || ch == '\t')
		;

	/* make a note of the beginning of token */
	ibcfg_btoken = ibcfg_cntr - 1;

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
		while ((ch  = GETC(file_buf, ibcfg_cntr)) == ' ' ||
		    ch == '\t' || ch == '\f')
			*cp++ = (char)ch;
		(void) UNGETC(ibcfg_cntr);
		token = WHITE_SPACE;
		break;
	case '\n':
	case '\r':
		token = NEWLINE;
		break;
	case '"':
		cp--;
		badquote = 0;
		while (!badquote && (ch  = GETC(file_buf, ibcfg_cntr)) != '"') {
			switch (ch) {
			case '\n':
			case -1:
				(void) snprintf(*errmsg, MAXPATHLEN,
				    "Missing \"");
				cp = val;
				*cp++ = '\n';
				badquote = 1;
				/* since we consumed the newline/EOF */
				(void) UNGETC(ibcfg_cntr);
				break;

			case '\\':
				ch = (char)GETC(file_buf, ibcfg_cntr);
				if (!isdigit(ch)) {
					/* escape the character */
					*cp++ = (char)ch;
					break;
				}
				oval = 0;
				while (ch >= '0' && ch <= '7') {
					ch -= '0';
					oval = (oval << 3) + ch;
					ch = (char)GETC(file_buf, ibcfg_cntr);
				}
				(void) UNGETC(ibcfg_cntr);
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
			*cp++ = (char)(ch = GETC(file_buf, ibcfg_cntr));
			if (iswhite(ch) || (ch == '\n')) {
				(void) UNGETC(ibcfg_cntr);
				cp--;
				token = NAME;
				break;
			}
		} else if (isunary(ch)) {
			*cp++ = (char)(ch = GETC(file_buf, ibcfg_cntr));
		}

		if (isdigit(ch)) {
			if (ch == '0') {
				if ((ch = GETC(file_buf, ibcfg_cntr)) == 'x') {
					*cp++ = (char)ch;
					ch = GETC(file_buf, ibcfg_cntr);
					while (isxdigit(ch)) {
						*cp++ = (char)ch;
						ch = GETC(file_buf, ibcfg_cntr);
					}
					(void) UNGETC(ibcfg_cntr);
					token = HEXVAL;
				} else {
					goto digit;
				}
			} else {
				ch = GETC(file_buf, ibcfg_cntr);
digit:
				while (isdigit(ch)) {
					*cp++ = (char)ch;
					ch = GETC(file_buf, ibcfg_cntr);
				}
				(void) UNGETC(ibcfg_cntr);
				token = DECVAL;
			}
		} else if (isalpha(ch) || ch == '\\') {
			if (ch != '\\') {
				ch = GETC(file_buf, ibcfg_cntr);
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
					ch = GETC(file_buf, ibcfg_cntr);
				*cp++ = (char)ch;
				ch = GETC(file_buf, ibcfg_cntr);
			}
			(void) UNGETC(ibcfg_cntr);
			token = NAME;
		} else
			return (-1);
		break;
	}
	*cp = '\0';
	return (token);
}


/*
 * Function:
 *	ib_find_eol
 * Input:
 *	NONE
 * Output:
 *	NONE
 * Returns:
 *	NONE
 * Description:
 *	Leave NEWLINE as the next character.
 */
static void
ib_find_eol()
{
	int ch;

	while ((ch = GETC(file_buf, ibcfg_cntr)) != -1) {
		if (isnewline(ch))  {
			(void) UNGETC(ibcfg_cntr);
			break;
		}
	}
}


/*
 * Function:
 *	ib_get_string
 * Input:
 *	tchar		- name of the string
 * Output:
 *	llptr		- Valid string
 * Returns:
 *	1 for success, NULL for errors.
 * Description:
 *	The next item on the line is a string value. Allocate memory for
 *	it and copy the string. Return 1, and set arg ptr to newly allocated
 *	and initialized buffer, or NULL if an error occurs.
 */
static int
ib_get_string(char **llptr, char *tchar)
{
	int	tlen = strlen(tchar);
	char	*cp;
	char	*start = (char *)0;

	start = tchar;
	/* copy string */
	if ((cp = (char *)calloc(tlen + 1, sizeof (char))) == (char *)NULL) {
		*llptr = NULL;
		return (0);
	}
	bzero(cp, tlen + 1);

	*llptr = cp;
	for (; tlen > 0; tlen--) {
		/* convert some common escape sequences */
		if (*start == '\\') {
			switch (*(start + 1)) {
			case 't':
				/* tab */
				*cp++ = '\t';
				tlen--;
				start += 2;
				break;
			case 'n':
				/* new line */
				*cp++ = '\n';
				tlen--;
				start += 2;
				break;
			case 'b':
				/* back space */
				*cp++ = '\b';
				tlen--;
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
 * Function:
 *	ib_service_record_add
 * Input:
 *	service		- name of the service
 *	type		- type of the service
 * Output:
 *	rec		- one valid service record
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Add one record to internal data structures
 */
static int
ib_service_record_add(char *service, ib_service_type_t type)
{
	ib_svc_rec_t	*tmp, *recp;

	DPRINTF("ib_service_record_add: (%x, %s) "
	    "(#port = %d #vppa = %d #hca = %d)\n", type, service,
	    ibcfg_nport_services, ibcfg_nvppa_services,
	    ibcfg_nhca_services);
	recp = (ib_svc_rec_t *)calloc(1, sizeof (ib_svc_rec_t));
	if (recp == NULL)
		return (CFGA_IB_ALLOC_FAIL);

	recp->type = type;
	recp->name = strdup((char *)service);
	if (type == IB_PORT_SERVICE) {
		if (ibcfg_port_head) {
			for (tmp = ibcfg_port_head; tmp->next != NULL; )
				tmp = tmp->next;
			tmp->next = recp;
		} else
			ibcfg_port_head = recp;
		ibcfg_nport_services++;
	} else if (type == IB_VPPA_SERVICE) {
		if (ibcfg_vppa_head) {
			for (tmp = ibcfg_vppa_head; tmp->next != NULL; )
				tmp = tmp->next;
			tmp->next = recp;
		} else
			ibcfg_vppa_head = recp;
		ibcfg_nvppa_services++;
	} else if (type == IB_HCASVC_SERVICE) {
		if (ibcfg_hca_head) {
			for (tmp = ibcfg_hca_head; tmp->next != NULL; )
				tmp = tmp->next;
			tmp->next = recp;
		} else
			ibcfg_hca_head = recp;
		ibcfg_nhca_services++;
	}

	return (CFGA_IB_OK);
}


/*
 * Function:
 *	ib_get_services
 * Input:
 *	errmsg		- Error message filled in case of a failure
 * Output:
 *	rec		- one valid service record
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Fetch one record from the IBCONF_FILE
 */
static ib_token_t
ib_get_services(char **errmsg)
{
	char			tokval[MAXLINESIZE];
	char			*llptr;
	boolean_t		sor = B_TRUE;
	ib_token_t		token;
	ib_service_type_t	cfgvar;
	ib_parse_state_t	parse_state = IB_NEWVAR;

	token = ib_lex(tokval, errmsg);
	while ((token != EOF) && (token != SEMICOLON)) {
		if (token == STAR || token == POUND) {
			/* skip comments */
			ib_find_eol();
		} else if (token == NEWLINE) {
			ibcfg_linenum++;
		} else if (token == NAME || token == STRING) {
			if (parse_state == IB_NEWVAR) {
				cfgvar = ib_get_var_type(tokval);
				if (cfgvar == IB_NONE) {
					parse_state = IB_ERROR;
					(void) snprintf(*errmsg, MAXPATHLEN,
					    "Syntax Error: Invalid type %s",
					    tokval);
				} else {
					/* Note the beginning of the entry */
					if (sor) {
						ibcfg_brec = ibcfg_btoken;
						sor = B_FALSE;
					}
					parse_state = IB_CONFIG_VAR;
					if (cfgvar == IB_PORT_SERVICE)
						bportrec = ibcfg_cntr + 1;
					else if (cfgvar == IB_VPPA_SERVICE)
						bvpparec = ibcfg_cntr + 1;
					else if (cfgvar == IB_HCASVC_SERVICE)
						bhcarec = ibcfg_cntr + 1;
				}

			} else if (parse_state == IB_VAR_VALUE) {
				llptr = NULL;
				if (ib_get_string(&llptr, tokval)) {
					if ((cfgvar == IB_PORT_SERVICE) ||
					    (cfgvar == IB_VPPA_SERVICE) ||
					    (cfgvar == IB_HCASVC_SERVICE)) {
						if (ib_service_record_valid(
						    llptr) &&
						    ib_service_record_add(
						    (char *)llptr, cfgvar) !=
						    CFGA_IB_OK) {
							return (E_O_F);
						} else {
							parse_state =
							    IB_CONFIG_VAR;
						}
					} else if ((cfgvar == IB_NAME) ||
					    (cfgvar == IB_CLASS)) {
						free((char *)llptr);
						parse_state = IB_NEWVAR;
					} else {
						free((char *)llptr);
						parse_state = IB_ERROR;
					}
				} else {
					parse_state = IB_ERROR;
					(void) snprintf(*errmsg, MAXPATHLEN,
					    "Syntax Error: Invalid value %s "
					    "for type: %s\n", tokval,
					    ibcfg_varlist[cfgvar].name);
				}
			} else if (parse_state == IB_ERROR) {
				/* just skip */
				DPRINTF("ib_get_services: ERROR\n");
			} else {
				parse_state = IB_ERROR;
				(void) snprintf(*errmsg, MAXPATHLEN,
				    "Syntax Error: at %s", tokval);
			}
		} else if (token == COMMA || token == EQUALS) {
			if (parse_state == IB_CONFIG_VAR) {
				if (cfgvar == IB_NONE) {
					parse_state = IB_ERROR;
					(void) snprintf(*errmsg, MAXPATHLEN,
					    "Syntax Error: unexpected '='");
				} else {
					parse_state = IB_VAR_VALUE;
				}
			} else if (parse_state != IB_ERROR) {
				(void) snprintf(*errmsg, MAXPATHLEN,
				    "Syntax Error: unexpected '='");
				parse_state = IB_ERROR;
			}
		} else {
			(void) snprintf(*errmsg, MAXPATHLEN,
			    "Syntax Error: at: %s", tokval);
			parse_state = IB_ERROR;
		}
		token = ib_lex(tokval, errmsg);
		if (ib_get_var_type(tokval) != IB_NONE)
			parse_state = IB_NEWVAR;
	}
	return (token);
}

/*
 * Function:
 *	ib_cmp_service
 * Input:
 *	NONE
 * Output:
 *	NONE
 * Returns:
 *	B_TRUE if this service is already seen. B_FALSE if not.
 * Description:
 *	Compare the service just read from the services already seen.
 *	Check if this service was already seen or not.
 */
static boolean_t
ib_cmp_service()
{
	ib_svc_rec_t	*recp;

	DPRINTF("ib_cmp_service: (%x, %s) "
	    "(#port = %d #vppa = %d #hca = %d)\n", service_type,
	    service_name, ibcfg_nport_services, ibcfg_nvppa_services,
	    ibcfg_nhca_services);

	for (recp = ibcfg_port_head; recp != NULL; recp = recp->next) {
		DPRINTF("ib_cmp_service:P usvc = %s, usvc_name = %s\n",
		    service_name, recp->name ? recp->name : "NONE");
		if (recp->name && strcmp(recp->name, service_name) == 0)
			return (B_TRUE);
	}
	for (recp = ibcfg_vppa_head; recp != NULL; recp = recp->next) {
		DPRINTF("ib_cmp_service:V utype = %x, usvc_name = %s\n",
		    recp->type, recp->name ? recp->name : "NONE");
		if (recp->name && strcmp(recp->name, service_name) == 0)
			return (B_TRUE);
	}
	for (recp = ibcfg_hca_head; recp != NULL; recp = recp->next) {
		DPRINTF("ib_cmp_service:V utype = %x, usvc_name = %s\n",
		    recp->type, recp->name ? recp->name : "NONE");
		if (recp->name && strcmp(recp->name, service_name) == 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}


/*
 * Function:
 *	ib_free_service_recs
 * Input:
 *	NONE
 * Output:
 *	NONE
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Free the service records allocated in ib_get_services
 */
static void
ib_free_service_recs(void)
{
	ib_svc_rec_t	*tmp, *recp;

	DPRINTF("ib_free_service_recs: "
	    "#port_services = %d, #vppa_services = %d, #hca_services = %d\n",
	    ibcfg_nport_services, ibcfg_nvppa_services, ibcfg_nhca_services);

	for (recp = ibcfg_port_head; recp != NULL; ) {
		if (recp && strlen(recp->name))
			S_FREE(recp->name);
		tmp = recp;
		recp = recp->next;
		S_FREE(tmp);
	}

	for (recp = ibcfg_vppa_head; recp != NULL; ) {
		if (recp && strlen(recp->name))
			S_FREE(recp->name);
		tmp = recp;
		recp = recp->next;
		S_FREE(tmp);
	}

	for (recp = ibcfg_hca_head; recp != NULL; ) {
		if (recp && strlen(recp->name))
			S_FREE(recp->name);
		tmp = recp;
		recp = recp->next;
		S_FREE(tmp);
	}
}


/*
 * Function:
 *	ib_cleanup_file
 * Input:
 *	rval		- error return value
 * Output:
 *	NONE
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Cleanup  IBCONF_FILE etc.
 */
static int
ib_cleanup_file(int rval)
{
	int	rv = rval;

	ib_free_service_recs();
	if (lockf(ibcfg_fd, F_ULOCK, 0) == -1) {
		DPRINTF("ib_cleanup_file: unlock file %s failed\n",
		    ibconf_file);
		rv = CFGA_IB_UNLOCK_FILE_ERR;
	}
	S_FREE(file_buf);
	close(ibcfg_fd);
	ibcfg_fd = -1;
	if (ibcfg_tmpfd && wrote_tmp == B_TRUE) {
		DPRINTF("ib_cleanup_file: tmpfile %s being renamed to %s\n",
		    tmpnamef, IBCONF_FILE);
		close(ibcfg_tmpfd);
		rename((const char *)tmpnamef, (const char *)IBCONF_FILE);
		unlink(tmpnamef);
	}
	(void) mutex_unlock(&ibcfg_lock);
	return (rv);
}


/*
 * Function:
 *	ib_init_file
 * Input:
 *	NONE
 * Output:
 *	errmsg		- Error message filled in case of a failure
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	Initialize IBCONF_FILE for reading
 */
static int
ib_init_file(char **errmsg)
{
	(void) mutex_lock(&ibcfg_lock);

	if (*errmsg == (char *)NULL) {
		if ((*errmsg = calloc(MAXPATHLEN, 1)) == (char *)NULL) {
			(void) mutex_unlock(&ibcfg_lock);
			DPRINTF("ib_init_file: calloc errmsg failed\n");
			return (CFGA_IB_CONFIG_FILE_ERR);
		}
	}

	/* Open the .conf file */
	if ((ibcfg_fd = open(ibconf_file, O_RDWR, 0666)) == -1) {
		(void) snprintf(*errmsg, MAXPATHLEN,
		    "failed to open %s file\n", ibconf_file);
		(void) mutex_unlock(&ibcfg_lock);
		return (CFGA_IB_CONFIG_FILE_ERR);
	}

	/* Lock the file so that another cfgadm instance doesn't modify it */
	if (lockf(ibcfg_fd, F_TLOCK, 0) == -1) {
		(void) snprintf(*errmsg, MAXPATHLEN,
		    "failed to lock %s file\n", ibconf_file);
		close(ibcfg_fd);
		ibcfg_fd = -1;
		(void) mutex_unlock(&ibcfg_lock);
		return (CFGA_IB_LOCK_FILE_ERR);
	}

	if (fstat(ibcfg_fd, &ibcfg_st) != 0) {
		DPRINTF("ib_init_file: failed to fstat %s file\n", ibconf_file);
		return (ib_cleanup_file(CFGA_IB_CONFIG_FILE_ERR));
	}

	/* Allocate a buffer for the file */
	if ((file_buf = (char *)malloc(ibcfg_st.st_size)) == NULL) {
		DPRINTF("ib_init_file: failed to fstat %s file\n",
		    ibconf_file);
		return (ib_cleanup_file(CFGA_IB_ALLOC_FAIL));
	}

	/* Check if size matches */
	if (ibcfg_st.st_size != read(ibcfg_fd, file_buf, ibcfg_st.st_size)) {
		DPRINTF("ib_init_file: failed to read %s file\n", ibconf_file);
		return (ib_cleanup_file(CFGA_IB_CONFIG_FILE_ERR));
	}

	/*
	 * These variables need to be reinitialized here as they may
	 * have been modified by a previous thread that called this
	 * function
	 */
	ibcfg_linenum = 1;
	ibcfg_cntr = 0;
	ibcfg_brec = 0;
	ibcfg_btoken = 0;

	ibcfg_nport_services = 0;
	ibcfg_nvppa_services = 0;
	ibcfg_nhca_services = 0;
	ibcfg_port_head = (ib_svc_rec_t *)NULL;
	ibcfg_vppa_head = (ib_svc_rec_t *)NULL;
	ibcfg_hca_head = (ib_svc_rec_t *)NULL;
	return (CFGA_IB_OK);
}


/*
 * Function:
 *	ib_add_service
 * Input:
 *	NONE
 * Output:
 *	errmsg		- Error message filled in case of a failure
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	open IBCONF_FILE and add "service_name".
 */
int
ib_add_service(char **errmsg)
{
	int		rval;
	char		*sbuf;
	boolean_t	found = B_FALSE;
	ib_token_t	token = NEWLINE;

	DPRINTF("ib_add_service: type = %x, service_name=%s\n", service_type,
	    service_name);
	if ((rval = ib_init_file(errmsg)) != CFGA_IB_OK) {
		DPRINTF("ib_add_service: initializing file failed\n");
		return (rval);
	}

	/* Start reading the file */
	while (token != EOF) {
		token = ib_get_services(errmsg);
		found = ib_cmp_service();
		if (found == B_TRUE) {
			DPRINTF("ib_add_service: token=%x, found=%x\n",
			    token, found);
			break;
		}
	}

	/* Service shouldn't already exist while adding */
	if (found) {
		(void) snprintf(*errmsg, MAXPATHLEN, "service entry %s exists ",
		    service_name);
		DPRINTF("ib_add_service: invalid add operation\n");
		return (ib_cleanup_file(CFGA_IB_SVC_EXISTS_ERR));
	}

	DPRINTF("!FOUND and adding\n");
	switch (service_type) {
		case IB_PORT_SERVICE :
			ibcfg_brec = bportrec;
			break;
		case IB_VPPA_SERVICE :
			ibcfg_brec = bvpparec;
			break;
		case IB_HCASVC_SERVICE :
			ibcfg_brec = bhcarec;
			break;
		default :
			DPRINTF("ib_add_service: invalid add operation\n");
			return (ib_cleanup_file(CFGA_IB_SVC_INVAL_ERR));
	}


	if ((sbuf = (char *)calloc(12, sizeof (char))) == NULL) {
		DPRINTF("ib_add_service: failed to calloc sbuf %s file\n",
		    ibconf_file);
		return (ib_cleanup_file(CFGA_IB_ALLOC_FAIL));
	}
	if (file_buf[ibcfg_brec] == '"' && file_buf[ibcfg_brec + 1] == '"') {
		(void) snprintf(sbuf, 9, "%s", service_name);
		ibcfg_brec += 1;
	} else
		(void) snprintf(sbuf, 9, "\"%s\", ", service_name);


	/* Seek to the beginning of the file */
	if (lseek(ibcfg_fd, ibcfg_brec, SEEK_SET) == -1) {
		DPRINTF("ib_add_service: lseek %s file failed\n", ibconf_file);
		return (ib_cleanup_file(CFGA_IB_CONFIG_FILE_ERR));
	}

	/* Add service to w/ IBNEX  */
	if (ib_conf_control_ioctl(service_name, IBNEX_CONF_ENTRY_ADD)) {
		DPRINTF("ib_add_service: ioctl add failed %d\n", errno);
		(void) snprintf(*errmsg, MAXPATHLEN, "failed to add "
		    "%s service incore ", service_name);
		return (ib_cleanup_file(CFGA_IB_SVC_EXISTS_ERR));
	}

	/* Write the modified file */
	if (write(ibcfg_fd, sbuf, strlen(sbuf)) == -1) {
		DPRINTF("ib_add_service: write %s file failed\n", ibconf_file);
		return (ib_cleanup_file(CFGA_IB_CONFIG_FILE_ERR));
	}

	/* Write the rest of the file as it was */
	if (write(ibcfg_fd, file_buf + ibcfg_brec,
	    ibcfg_st.st_size - ibcfg_brec) == -1) {
		DPRINTF("ib_add_service: write %s file failed 2\n",
		    ibconf_file);
		return (ib_cleanup_file(CFGA_IB_CONFIG_FILE_ERR));
	}

	return (ib_cleanup_file(rval));
}


/*
 * Function:
 *	ib_delete_service
 * Input:
 *	NONE
 * Output:
 *	errmsg		- Error message filled in case of a failure
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	open ib.conf file and delete "service_name"
 */
int
ib_delete_service(char **errmsg)
{
	int		rval;
	int		num_svcs;
	int		skip_len;
	int		sbuf_len;
	int		tot_len;
	char		tmp[12];
	char		*sbuf = (char *)NULL;
	boolean_t	found = B_FALSE;
	ib_token_t	token = NEWLINE;
	ib_svc_rec_t	*recp;

	DPRINTF("ib_delete_service: type = %x, service_name=%s\n",
	    service_type, service_name);
	if ((rval = ib_init_file(errmsg)) != CFGA_IB_OK) {
		DPRINTF("ib_delete_service: initializing file failed\n");
		return (rval);
	}

	/* Start reading the file */
	while (token != EOF) {
		token = ib_get_services(errmsg);
		found = ib_cmp_service();		/* search for a match */
		if (found == B_TRUE) {
			DPRINTF("ib_delete_service: token=%x, found=%x\n",
			    token, found);
			break;
		}
	}

	/* No service found, return */
	if (!found) {
		DPRINTF("ib_delete_service: invalid delete operation\n");
		(void) snprintf(*errmsg, MAXPATHLEN, "service entry %s "
		    "does not exist ", service_name);
		return (ib_cleanup_file(CFGA_IB_SVC_NO_EXIST_ERR));
	}

	DPRINTF("FOUND and deleting \n");

	switch (service_type) {
		case IB_PORT_SERVICE :
			ibcfg_brec = bportrec;
			num_svcs = ibcfg_nport_services;
			break;
		case IB_VPPA_SERVICE :
			ibcfg_brec = bvpparec;
			num_svcs = ibcfg_nvppa_services;
			break;
		case IB_HCASVC_SERVICE :
			ibcfg_brec = bhcarec;
			num_svcs = ibcfg_nhca_services;
			break;
		default :
			DPRINTF("ib_delete_service: invalid delete "
			    "operation\n");
			return (ib_cleanup_file(CFGA_IB_SVC_INVAL_ERR));
	}

	if ((sbuf = (char *)calloc(num_svcs * 8, sizeof (char))) == NULL) {
		DPRINTF("ib_delete_service: sbuf alloc failed %s\n",
		    ibconf_file);
		return (ib_cleanup_file(CFGA_IB_ALLOC_FAIL));
	}

	if (num_svcs == 1) {
		(void) snprintf(sbuf, 9, "\"\"");
		sbuf_len = 2;
		skip_len = 0;
	} else {
		if (service_type == IB_PORT_SERVICE) {
			for (recp = ibcfg_port_head; recp; recp = recp->next) {
				if (strcmp(recp->name, service_name) == 0)
					continue;
				(void) snprintf(tmp, 9, "\"%s\", ", recp->name);
				(void) strcat(sbuf, tmp);
			}

		} else if (service_type == IB_VPPA_SERVICE) {
			for (recp = ibcfg_vppa_head; recp; recp = recp->next) {
				if (strcmp(recp->name, service_name) == 0)
					continue;
				(void) snprintf(tmp, 9, "\"%s\", ", recp->name);
				(void) strcat(sbuf, tmp);
			}
		} else {
			for (recp = ibcfg_hca_head; recp; recp = recp->next) {
				if (strcmp(recp->name, service_name) == 0)
					continue;
				(void) snprintf(tmp, 9, "\"%s\", ", recp->name);
				(void) strcat(sbuf, tmp);
			}
		}
		skip_len = 4;
		sbuf_len = strlen(sbuf);
		sbuf[sbuf_len - 2] = '\0';
		sbuf_len -= 2;
	}

	tot_len = strlen(service_name) + skip_len;

	tmpnamef = tmpnam(ibconf_file);
	DPRINTF("ib_delete_service: tmpnamef = %s\n", tmpnamef);
	if ((ibcfg_tmpfd = creat(tmpnamef, 0666)) == -1) {
		(void) snprintf(*errmsg, MAXPATHLEN,
		    "failed to creat %s file\n", ibconf_file);
		DPRINTF("ib_delete_service: failed to creat tmpnamef\n");
		return (ib_cleanup_file(CFGA_IB_ALLOC_FAIL));
	}

	/* Delete service from IBNEX  */
	if (ib_conf_control_ioctl(service_name, IBNEX_CONF_ENTRY_DEL)) {
		DPRINTF("ib_delete_service: ioctl delete failed %d\n", errno);
		(void) snprintf(*errmsg, MAXPATHLEN, "failed to delete "
		    "in core %s entry ", service_name);
		close(ibcfg_tmpfd);
		unlink(tmpnamef);
		return (ib_cleanup_file(CFGA_IB_SVC_EXISTS_ERR));
	}

	/* write till ibcfg_brec */
	if (write(ibcfg_tmpfd, file_buf, ibcfg_brec) == -1) {
		DPRINTF("ib_delete_service: write %s file failed 1\n",
		    ibconf_file);
		close(ibcfg_tmpfd);
		unlink(tmpnamef);
		return (ib_cleanup_file(CFGA_IB_CONFIG_FILE_ERR));
	}

	/* write modified buffer */
	if (write(ibcfg_tmpfd, sbuf, sbuf_len) == -1) {
		DPRINTF("ib_delete_service: write %s file failed 2\n",
		    ibconf_file);
		close(ibcfg_tmpfd);
		unlink(tmpnamef);
		return (ib_cleanup_file(CFGA_IB_CONFIG_FILE_ERR));
	}

	/* Write the rest of the file as it was */
	if (write(ibcfg_tmpfd, file_buf + ibcfg_brec + sbuf_len + tot_len,
	    ibcfg_st.st_size - ibcfg_brec - sbuf_len - tot_len) == -1) {
		DPRINTF("ib_delete_service: write %s file failed 3\n",
		    ibconf_file);
		close(ibcfg_tmpfd);
		unlink(tmpnamef);
		return (ib_cleanup_file(CFGA_IB_CONFIG_FILE_ERR));
	}
	wrote_tmp = B_TRUE;

	/* No error encountered */
	return (ib_cleanup_file(rval));
}


/*
 * Function:
 *	ib_list_services
 * Input:
 *	msgp		- CFGADM message pointer
 * Output:
 *	errmsg		- Error message filled in case of a failure
 * Returns:
 *	CFGA_IB_OK on success or an appropriate error
 * Description:
 *	open IBCONF_FILE and list services.
 */
int
ib_list_services(struct cfga_msg *msgp, char **errmsg)
{
	int		rval = CFGA_IB_OK;
	char		pbuf[IBCONF_SERVICE_HDR_LEN];
	ib_token_t	token = NEWLINE;
	ib_svc_rec_t	*recp;

	DPRINTF("ib_list_services:\n");
	if ((rval = ib_init_file(errmsg)) != CFGA_IB_OK) {
		DPRINTF("ib_list_services: initializing file failed\n");
		return (rval);
	}

	/* start reading the file */
	while (token != EOF)
		token = ib_get_services(errmsg);

	DPRINTF("ib_list_services: #port_services = %d, #vppa_services = %d,"
	    " #hca_services = %d\n", ibcfg_nport_services,
	    ibcfg_nvppa_services, ibcfg_nhca_services);

	bzero(pbuf, IBCONF_SERVICE_HDR_LEN);
	if (ibcfg_nport_services) {
		(void) snprintf(pbuf, IBCONF_SERVICE_HDR_LEN,
		    IBCONF_PORT_SERVICE_HDR);
		cfga_msg(msgp, pbuf);
		for (recp = ibcfg_port_head; recp; recp = recp->next) {
			DPRINTF("ib_list_services: svc_name = %s\n",
			    recp->name ? recp->name : "NONE");
			(void) snprintf(pbuf, 14, "\t\t%s\n", recp->name);
			cfga_msg(msgp, pbuf);
		}
		(void) snprintf(pbuf, 2, "\n");
		cfga_msg(msgp, pbuf);
	}

	if (ibcfg_nvppa_services) {
		(void) snprintf(pbuf, IBCONF_SERVICE_HDR_LEN,
		    IBCONF_VPPA_SERVICE_HDR);
		cfga_msg(msgp, pbuf);
		for (recp = ibcfg_vppa_head; recp; recp = recp->next) {
			DPRINTF("ib_list_services: svc_name = %s\n",
			    strlen(recp->name) > 0 ? recp->name : "NONE");
			(void) snprintf(pbuf, 14, "\t\t%s\n", recp->name);
			cfga_msg(msgp, pbuf);
		}
	}

	if (ibcfg_nhca_services) {
		(void) snprintf(pbuf, IBCONF_SERVICE_HDR_LEN,
		    IBCONF_HCA_SERVICE_HDR);
		cfga_msg(msgp, pbuf);
		for (recp = ibcfg_hca_head; recp; recp = recp->next) {
			DPRINTF("ib_list_services: svc_name = %s\n",
			    strlen(recp->name) > 0 ? recp->name : "NONE");
			(void) snprintf(pbuf, 14, "\t\t%s\n", recp->name);
			cfga_msg(msgp, pbuf);
		}
	}
	return (ib_cleanup_file(CFGA_IB_OK));
}


/*
 * Function:
 *	ib_conf_control_ioctl
 * Input:
 *	svc		- Service being added/deleted
 *	cmd		- Command to DEVCTL_AP_CONTROL devctl
 * Output:
 *	NONE
 * Returns:
 *	CFGA_IB_OK if it succeeds or an appropriate error.
 * Description:
 *	Issues DEVCTL_AP_CONTROL devctl with cmd
 */
static cfga_ib_ret_t
ib_conf_control_ioctl(char *svc, uint_t cmd)
{
	int			apid_fd = -1;
	cfga_ib_ret_t		rv = CFGA_IB_OK;
	struct ibnex_ioctl_data	ioctl_data;

	DPRINTF("Service = %s len = %x, type = %x\n", svc,
	    strlen(svc), service_type);

	/* try to open the static IB ap_id */
	if ((apid_fd = open(IB_STATIC_APID, O_RDONLY)) == -1) {
		DPRINTF("ib_conf_control_ioctl: open failed: errno = %d\n",
		    errno);
		/* Provides a more useful error msg */
		rv = (errno == EBUSY) ? CFGA_IB_BUSY_ERR : CFGA_IB_OPEN_ERR;
		return (rv);
	}

	ioctl_data.cmd = cmd;
	ioctl_data.misc_arg = (uint_t)service_type;
	ioctl_data.buf = (caddr_t)svc;
	ioctl_data.bufsiz = strlen(svc);
	ioctl_data.ap_id = (caddr_t)IB_STATIC_APID;
	ioctl_data.ap_id_len = strlen(IB_STATIC_APID);

	if (ioctl(apid_fd, DEVCTL_AP_CONTROL, &ioctl_data) != 0) {
		DPRINTF("ib_conf_control_ioctl: size ioctl ERR, errno: %d\n",
		    errno);
		rv = (errno == EBUSY) ? CFGA_IB_BUSY_ERR : CFGA_IB_IOCTL_ERR;
	}
	(void) close(apid_fd);
	return (rv);
}

/*
 * This functions checks if the service name is valid. Valid
 * service names have  :
 *		0 < strlen(name) <= 4
 *		Service name is unique
 * Returns: 	0 - Name is not valid, 1 - Name is valid
 */
static int
ib_service_record_valid(char *sname)
{
	int rc = 1, len;
	char *tmp_service_name;

	tmp_service_name = service_name;
	service_name = strdup(sname);
	len = strlen(sname);
	if (len == 0 || len > 4) {
		S_FREE(service_name);
		service_name = tmp_service_name;
		return (0);
	}
	if (ib_cmp_service() == B_TRUE)
		rc = 0;
	S_FREE(service_name);
	service_name = tmp_service_name;
	return (rc);
}
