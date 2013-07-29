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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/salib.h>
#include <sys/promif.h>
#include <sys/wanboot_impl.h>
#include <netinet/in.h>
#include <parseURL.h>
#include <bootlog.h>
#include <sys/socket.h>
#include <netinet/inetutil.h>
#include <netinet/dhcp.h>
#include <dhcp_impl.h>
#include <lib/inet/mac.h>
#include <lib/inet/ipv4.h>
#include <lib/inet/dhcpv4.h>
#include <lib/sock/sock_test.h>
#include <sys/sunos_dhcp_class.h>
#include <aes.h>
#include <des3.h>
#include <hmac_sha1.h>
#include <netdb.h>
#include <wanboot_conf.h>
#include <bootinfo.h>

#include "wbcli.h"

#define	skipspace(p)	while (isspace(*(p))) ++p

#define	skiptext(p)	while (*(p) != '\0' && !isspace(*(p)) && \
			    *(p) != '=' && *(p) != ',') ++p

#define	PROMPT		"boot> "
#define	TEST_PROMPT	"boot-test> "

#define	CLI_SET		0
#define	CLI_FAIL	(-1)
#define	CLI_EXIT	(-2)
#define	CLI_CONT	(-3)

#define	CLF_CMD		0x00000001	/* builtin command */
#define	CLF_ARG		0x00000002	/* boot argument directive */

#define	CLF_IF		0x00000100	/* interface parameter */
#define	CLF_BM		0x00000200	/* bootmisc parameter */

#define	CLF_VALSET	0x00010000	/* value set, may be null */
#define	CLF_HIDDEN	0x00020000	/* don't show its value (key) */
#define	CLF_VALMOD	0x00040000	/* value modified by the user */

/*
 * Macros for use in managing the flags in the cli_list[].
 * The conventions we follow are:
 *
 *	CLF_VALSET is cleared	if a value is removed from varptr
 *	CLF_VALSET is set	if a value has been placed in varptr
 *				(that value need not be vetted)
 *	CLF_HIDDEN is set	if a value must not be exposed to the user
 *	CLF_HIDDEN is cleared	if a value can be exposed to the user
 *	CLF_VALMOD is cleared	if a value in varptr has not been modified
 *	CLF_VALMOD is set	if a value in varptr has been modified by
 *				the user
 */
#ifdef	DEBUG
#define	CLF_SETVAL(var)		{					\
					(((var)->flags) |= CLF_VALSET);	\
					printf("set %s\n", var->varname);\
				}

#define	CLF_ISSET(var)		(printf("%s\n",				\
				    (((var)->flags) & CLF_VALSET) != 0	\
				    ? "is set" : "not set"),		\
				    ((((var)->flags) & CLF_VALSET) != 0))

#define	CLF_CLRHIDDEN(var)	{					\
					(((var)->flags) &= ~CLF_HIDDEN); \
					printf("unhide %s\n", var->varname); \
				}

#define	CLF_ISHIDDEN(var)	(printf("%s\n",				\
				    (((var)->flags) & CLF_HIDDEN) != 0	\
				    ? "is hidden" : "not hidden"),	\
				    ((((var)->flags) & CLF_HIDDEN) != 0))

#define	CLF_MODVAL(var)		{					\
					(((var)->flags) |=		\
					(CLF_VALMOD | CLF_VALSET));	\
					printf("modified %s\n", var->varname);\
				}

#define	CLF_ISMOD(var)		(printf("%s\n",				\
				    (((var)->flags) & CLF_VALMOD) != 0 \
				    ? "is set" : "not set"),	\
				    ((((var)->flags) & CLF_VALMOD) != 0))
#else	/* DEBUG */

#define	CLF_SETVAL(var)		(((var)->flags) |= CLF_VALSET)
#define	CLF_ISSET(var)		((((var)->flags) & CLF_VALSET) != 0)
#define	CLF_CLRHIDDEN(var)	(((var)->flags) &= ~CLF_HIDDEN)
#define	CLF_ISHIDDEN(var)	((((var)->flags) & CLF_HIDDEN) != 0)
#define	CLF_MODVAL(var)		(((var)->flags) |= (CLF_VALMOD | CLF_VALSET))
#define	CLF_ISMOD(var)		((((var)->flags) & CLF_VALMOD) != 0)

#endif	/* DEBUG */

/*
 * The width of the widest varname below - currently "subnet_mask".
 */
#define	VAR_MAXWIDTH	strlen(BI_SUBNET_MASK)

struct cli_ent;
typedef	int claction_t(struct cli_ent *, char *, boolean_t);

typedef struct cli_ent {
	char   		*varname;
	claction_t	*action;
	int		flags;
	void		*varptr;
	uint_t		varlen;
	uint_t 		varmax;
} cli_ent_t;

static cli_ent_t	 *find_cli_ent(char *varstr);

static char		cmdbuf[2048];			/* interpreter buffer */
static char		hostip[INET_ADDRSTRLEN];
static char		subnet[INET_ADDRSTRLEN];
static char		router[INET_ADDRSTRLEN];
static char		hostname[MAXHOSTNAMELEN];
static char		httpproxy[INET_ADDRSTRLEN + 5];		/* a.b.c.d:p */
static char		bootserverURL[URL_MAX_STRLEN + 1];
static unsigned char	clientid[WB_MAX_CID_LEN];
static unsigned char	aeskey[AES_128_KEY_SIZE];
static unsigned char	des3key[DES3_KEY_SIZE];
static unsigned char	sha1key[WANBOOT_HMAC_KEY_SIZE];
static boolean_t	args_specified_prompt = B_FALSE;

extern bc_handle_t	bc_handle;
extern int		getchar(void);

static claction_t	clcid, clkey, clip, clstr, clurl, clhp;
static claction_t	clhelp, cllist, clprompt, cldhcp, cltest, clgo, clexit;

static cli_ent_t cli_list[] = {
	/*
	 * Commands/bootargs:
	 */
	{ "test",		cltest,		CLF_ARG,
	    NULL,		0,		0			},
	{ "dhcp",		cldhcp,		CLF_ARG,
	    NULL,		0,		0			},
	{ "prompt",		clprompt,	CLF_CMD | CLF_ARG,
	    NULL,		0,		0			},
	{ "list",		cllist,		CLF_CMD,
	    NULL,		0,		0			},
	{ "help",		clhelp,		CLF_CMD,
	    NULL,		0,		0			},
	{ "go",			clgo,		CLF_CMD,
	    NULL,		0,		0			},
	{ "exit",		clexit,		CLF_CMD,
	    NULL,		0,		0			},

	/*
	 * Interface:
	 */
	{ BI_HOST_IP,		clip,		CLF_IF,
	    hostip,		0,		sizeof (hostip)		},
	{ BI_SUBNET_MASK,	clip,		CLF_IF,
	    subnet,		0,		sizeof (subnet)		},
	{ BI_ROUTER_IP,		clip,		CLF_IF,
	    router,		0,		sizeof (router)		},
	{ BI_HOSTNAME,		clstr,		CLF_IF,
	    hostname,		0,		sizeof (hostname)	},
	{ BI_HTTP_PROXY,	clhp,		CLF_IF,
	    httpproxy,		0,		sizeof (httpproxy)	},
	{ BI_CLIENT_ID,		clcid,		CLF_IF,
	    clientid,		0,		sizeof (clientid)	},

	/*
	 * Bootmisc:
	 */
	{ BI_AES_KEY,		clkey,		CLF_BM | CLF_HIDDEN,
	    aeskey,		0,		sizeof (aeskey)		},
	{ BI_3DES_KEY,		clkey,		CLF_BM | CLF_HIDDEN,
	    des3key,		0,		sizeof (des3key)	},
	{ BI_SHA1_KEY,		clkey,		CLF_BM | CLF_HIDDEN,
	    sha1key,		0,		sizeof (sha1key)	},
	{ BI_BOOTSERVER,	clurl,		CLF_BM,
	    bootserverURL,	0,		sizeof (bootserverURL)	},
};

static int num_cli_ent = (sizeof (cli_list) / sizeof (cli_ent_t));

/*
 * Fetch a line from the user, handling backspace appropriately.
 */
static int
editline(char *buf, int count)
{
	int	i = 0;
	char	c;

	while (i < count - 1) {
		c = getchar();
		if (c == '\n') {
			break;
		} else if (c == '\b') {
			/* Clear for backspace. */
			if (i > 0)
				i--;
			continue;
		} else {
			buf[i++] = c;
		}
	}
	buf[i] = '\0';
	return (i);
}

/*
 * Assign a client-id to cliptr, or output cliptr's value as a client-id.
 * On assignment the value is specified in valstr, either in hexascii or
 * as a quoted string; on output its value is printed in hexascii.
 */
static int
clcid(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	uint_t		len, vmax;
	boolean_t	hexascii = B_TRUE;
	char		buffer[2 * WB_MAX_CID_LEN + 1];

	if (out) {
		len = cliptr->varlen * 2 + 1;
		(void) octet_to_hexascii(cliptr->varptr, cliptr->varlen,
		    buffer, &len);
		printf("%s", buffer);
		return (CLI_CONT);
	} else {
		len = strlen(valstr);
		vmax = cliptr->varmax - 1;	/* space for the prefix */

		/*
		 * Check whether the value is a quoted string; if so, strip
		 * the quotes and note that it's not in hexascii.
		 */
		if ((valstr[0] == '"' || valstr[0] == '\'') &&
		    valstr[len-1] == valstr[0]) {
			hexascii = B_FALSE;
			++valstr;
			len -= 2;
			valstr[len] = '\0';
		} else {
			/*
			 * If the value contains any non-hex digits assume
			 * that it's not in hexascii.
			 */
			char	*p;

			for (p = valstr; *p != '\0'; ++p) {
				if (!isxdigit(*p)) {
					hexascii = B_FALSE;
					break;
				}
			}
		}

		if (hexascii) {
			if (len > vmax * 2 ||
			    hexascii_to_octet(valstr, len,
			    (char *)(cliptr->varptr), &vmax) != 0) {
				return (CLI_FAIL);
			}
			cliptr->varlen = vmax;
		} else {
			if (len > vmax) {
				return (CLI_FAIL);
			}
			bcopy(valstr, cliptr->varptr, len);
			cliptr->varlen = len;
		}

		return (CLI_SET);
	}
}

/*
 * Assign a key to cliptr, or output cliptr's value as a key.
 * On assignment the value is specified in valstr in hexascii;
 * on output its value is printed in hexascii, provided the key
 * was entered at the interpreter (not obtained from OBP and
 * thus hidden).
 */
static int
clkey(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	uint_t	len, vmax;

	if (out) {
		char buffer[2 * WANBOOT_MAXKEYLEN + 1];

		if (!CLF_ISHIDDEN(cliptr)) {
			len = cliptr->varlen * 2 + 1;
			(void) octet_to_hexascii(cliptr->varptr,
			    cliptr->varlen, buffer, &len);
			printf("%s", buffer);
		} else {
			printf("*HIDDEN*");
		}
		return (CLI_CONT);
	} else {
		len = strlen(valstr);
		vmax = cliptr->varmax;
		if (len != vmax * 2 || hexascii_to_octet(valstr, len,
		    cliptr->varptr, &vmax) != 0) {
			return (CLI_FAIL);
		}
		cliptr->varlen = vmax;
		CLF_CLRHIDDEN(cliptr);
		return (CLI_SET);
	}
}

/*
 * Assign an IP address to cliptr, or output cliptr's value as an
 * IP address.  On assignment the value is specified in valstr in
 * dotted-decimal format; on output its value is printed in dotted-
 * decimal format.
 */
static int
clip(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	uint_t		len;

	if (out) {
		printf("%s", (char *)cliptr->varptr);
		return (CLI_CONT);
	}

	if (inet_addr(valstr) == (in_addr_t)-1 ||
	    (len = strlen(valstr)) >= cliptr->varmax) {
		return (CLI_FAIL);
	}

	(void) strcpy(cliptr->varptr, valstr);
	cliptr->varlen = len + 1;
	return (CLI_SET);
}

/*
 * Assign an arbitrary string to cliptr, or output cliptr's value as a string.
 */
static int
clstr(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	uint_t	len;

	if (out) {
		printf("%s", (char *)cliptr->varptr);
		return (CLI_CONT);
	} else {
		if ((len = strlen(valstr)) >= cliptr->varmax) {
			return (CLI_FAIL);
		} else {
			(void) strcpy(cliptr->varptr, valstr);
			cliptr->varlen = len + 1;
			return (CLI_SET);
		}
	}
}

/*
 * Assign a URL to cliptr (having verified the format), or output cliptr's
 * value as a URL.  The host must be specified in dotted-decimal, and the
 * scheme must not be https.
 */
static int
clurl(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	url_t		u;
	uint_t		len;

	if (out) {
		printf("%s", (char *)cliptr->varptr);
		return (CLI_CONT);
	}

	if (url_parse(valstr, &u) != URL_PARSE_SUCCESS ||
	    u.https || inet_addr(u.hport.hostname) == (in_addr_t)-1 ||
	    (len = strlen(valstr)) >= cliptr->varmax) {
		return (CLI_FAIL);
	}

	(void) strcpy(cliptr->varptr, valstr);
	cliptr->varlen = len + 1;
	return (CLI_SET);
}

/*
 * Assign a hostport to cliptr (having verified the format), or output cliptr's
 * value as a hostport.  The host must be specified in dotted-decimal.
 */
static int
clhp(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	url_hport_t	u;
	uint_t		len;

	if (out) {
		printf("%s", (char *)cliptr->varptr);
		return (CLI_CONT);
	}

	if (url_parse_hostport(valstr, &u, URL_DFLT_PROXY_PORT) !=
	    URL_PARSE_SUCCESS ||
	    inet_addr(u.hostname) == (in_addr_t)-1 ||
	    (len = strlen(valstr)) >= cliptr->varmax) {
		return (CLI_FAIL);
	}

	(void) strcpy(cliptr->varptr, valstr);
	cliptr->varlen = len + 1;
	return (CLI_SET);
}

/*
 * Exit the interpreter and return to the booter.
 */
/*ARGSUSED*/
static int
clgo(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	return (CLI_EXIT);
}

/*
 * Exit the interpreter and return to OBP.
 */
/*ARGSUSED*/
static int
clexit(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	prom_exit_to_mon();
	/*NOTREACHED*/
	return (CLI_EXIT);
}

/*
 * Provide simple help information.
 */
/*ARGSUSED*/
static int
clhelp(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	printf("var=val		- set variable\n");
	printf("var=		- unset variable\n");
	printf("var		- print variable\n");
	printf("list		- list variables and their values\n");
	printf("prompt		- prompt for unset variables\n");
	printf("go		- continue booting\n");
	printf("exit		- quit boot interpreter and return to OBP\n");

	return (CLI_CONT);
}

/*
 * List variables and their current values.
 */
/*ARGSUSED*/
static int
cllist(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	int	wanted = (int)(uintptr_t)valstr; /* use uintptr_t for gcc */
	int	i;

	wanted  &= ~(CLF_CMD | CLF_ARG);

	for (cliptr = cli_list; cliptr < &cli_list[num_cli_ent]; cliptr++) {
		if ((cliptr->flags & (CLF_CMD | CLF_ARG)) != 0 ||
		    (cliptr->flags & wanted) == 0) {
			continue;
		}
		printf("%s: ", cliptr->varname);
		/*
		 * Line the values up - space to the width of the widest
		 * varname + 1 for the ':'.
		 */
		for (i = VAR_MAXWIDTH + 1 - strlen(cliptr->varname);
		    i > 0; --i) {
			printf(" ");
		}

		if (CLF_ISSET(cliptr) || CLF_ISHIDDEN(cliptr)) {
			(void) cliptr->action(cliptr, NULL, B_TRUE);
			printf("\n");
		} else {
			printf("UNSET\n");
		}
	}

	return (CLI_CONT);
}

/*
 * Prompt for wanted values.
 */
/*ARGSUSED*/
static int
clprompt(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	char	*p;
	int	wanted = (int)(uintptr_t)valstr; /* use uintrptr_t for gcc */

	/*
	 * If processing boot arguments, simply note the fact that clprompt()
	 * should be invoked later when other parameters may be supplied.
	 */
	if ((wanted & CLF_ARG) != 0) {
		args_specified_prompt = B_TRUE;
		return (CLI_CONT);
	}
	wanted  &= ~(CLF_CMD | CLF_ARG);

	for (cliptr = cli_list; cliptr < &cli_list[num_cli_ent]; ++cliptr) {
		if ((cliptr->flags & wanted) == 0) {
			continue;
		}

		printf("%s", cliptr->varname);
		if (CLF_ISSET(cliptr)) {
			printf(" [");
			(void) cliptr->action(cliptr, NULL, B_TRUE);
			printf("]");
		}
		printf("? ");
		(void) editline(cmdbuf, sizeof (cmdbuf));
		printf("\n");

		p = cmdbuf;
		skipspace(p);
		if (*p == '\0') {	/* nothing there */
			continue;
		}

		/* Get valstr and nul terminate */
		valstr = p;
		++p;
		skiptext(p);
		*p = '\0';

		/* If empty value, do nothing */
		if (strlen(valstr) == 0) {
			continue;
		}

		switch (cliptr->action(cliptr, valstr, B_FALSE)) {
		case CLI_SET:
			CLF_MODVAL(cliptr);
			break;
		case CLI_FAIL:
			printf("Incorrect format, parameter unchanged!\n");
			break;
		case CLI_EXIT:
			return (CLI_EXIT);
		case CLI_CONT:
			break;
		}
	}

	return (CLI_CONT);
}

/*
 * If the PROM has done DHCP, bind the interface; otherwise do the full
 * DHCP packet exchange.
 */
/*ARGSUSED*/
static int
cldhcp(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	static boolean_t	first_time = B_TRUE;
	static int		ret = CLI_CONT;

	if (first_time) {
		/*
		 * Set DHCP's idea of the client_id from our cached value.
		 */
		cliptr = find_cli_ent(BI_CLIENT_ID);
		if (CLF_ISMOD(cliptr)) {
			dhcp_set_client_id(cliptr->varptr, cliptr->varlen);
		}

		bootlog("wanboot", BOOTLOG_INFO, "Starting DHCP configuration");

		(void) ipv4_setpromiscuous(B_TRUE);
		if (dhcp() == 0) {
			bootlog("wanboot", BOOTLOG_INFO,
			    "DHCP configuration succeeded");
		} else {
			bootlog("wanboot", BOOTLOG_CRIT,
			    "DHCP configuration failed");
			ret = CLI_FAIL;
		}
		(void) ipv4_setpromiscuous(B_FALSE);

		first_time = B_FALSE;
	}

	return (ret);
}

/*
 * Invoke the socket test interpreter (for testing purposes only).
 */
/*ARGSUSED*/
static int
cltest(cli_ent_t *cliptr, char *valstr, boolean_t out)
{
	(void) ipv4_setpromiscuous(B_FALSE);
	printf("\n");
	for (;;) {
		printf(TEST_PROMPT);
		if (editline(cmdbuf, sizeof (cmdbuf)) > 0) {
			printf("\n");
			(void) st_interpret(cmdbuf);
		} else {
			prom_exit_to_mon();
			/* NOTREACHED */
		}
	}

	/* NOTREACHED */
	return (CLI_CONT);
}

/*
 * Return the cliptr corresponding to the named variable.
 */
static cli_ent_t *
find_cli_ent(char *varstr)
{
	cli_ent_t	*cliptr;

	for (cliptr = cli_list; cliptr < &cli_list[num_cli_ent]; ++cliptr) {
		if (strcmp(varstr, cliptr->varname) == 0) {
			return (cliptr);
		}
	}

	return (NULL);
}

/*
 * Evaluate the commands provided by the user (either as "-o" boot arguments
 * or interactively at the boot interpreter).
 */
static int
cli_eval_buf(char *inbuf, int wanted)
{
	char		*p, *varstr, *end_varstr, *valstr, *end_valstr;
	boolean_t	assign;
	cli_ent_t	*cliptr;

	for (p = inbuf; *p != '\0'; ) {
		skipspace(p);

		/* If nothing more on line, go get the next one */
		if (*p == '\0') {
			break;
		} else if (*p == ',') {		/* orphan ',' ? */
			++p;
			continue;
		}

		/* Get ptrs to start & end of variable */
		varstr = p;
		++p;
		skiptext(p);
		end_varstr = p;
		skipspace(p);

		/* See if we're doing an assignment */
		valstr = NULL;
		if (*p != '=') {	/* nope, just printing */
			assign = B_FALSE;
		} else {
			assign = B_TRUE;
			++p;			/* past '=' */
			skipspace(p);

			/* Assigning something? (else clear variable) */
			if (*p != '\0' && *p != ',') {
				/* Get ptrs to start & end of valstr */
				valstr = p;
				++p;
				skiptext(p);
				end_valstr = p;
				skipspace(p);
			}
		}

		/* Skip ',' delimiter if present */
		if (*p == ',') {
			++p;
		}

		/* Nul-terminate varstr and valstr (if appropriate) */
		*end_varstr = '\0';
		if (valstr != NULL) {
			*end_valstr = '\0';
		}

		if ((cliptr = find_cli_ent(varstr)) == NULL) {
			printf("Unknown variable '%s'; ignored\n", varstr);
			continue;
		}

		/*
		 * It's an error to specify a parameter which can only be a
		 * boot argument (and not a command) when not processing the
		 * boot arguments.
		 */
		if ((cliptr->flags & (CLF_CMD | CLF_ARG)) == CLF_ARG &&
		    (wanted & CLF_ARG) == 0) {
			printf("'%s' may only be specified as a "
			    "boot argument; ignored\n", varstr);
			continue;
		}

		/*
		 * When doing an assignment, verify that it's not a command
		 * or argument name, and that it is permissible in the current
		 * context.  An 'empty' assignment (var=) is treated the same
		 * as a null assignment (var="").
		 *
		 * If processing the boot arguments, it is an error to not
		 * assign a value to a non-argument parameter.
		 */
		if (assign) {
			if ((cliptr->flags & (CLF_CMD | CLF_ARG)) != 0) {
				printf("'%s' is a command and cannot "
				    "be assigned\n", varstr);
				return (CLI_FAIL);
			}
			if ((cliptr->flags & wanted) == 0) {
				printf("'%s' cannot be assigned\n", varstr);
				return (CLI_FAIL);
			}

			if (valstr == NULL) {
				cliptr->varlen = 0;
				CLF_MODVAL(cliptr);
				continue;
			}
		} else if ((wanted & CLF_ARG) != 0 &&
		    (cliptr->flags & (CLF_CMD | CLF_ARG)) == 0) {
			printf("'%s' must be assigned when specified in "
			    " the boot arguments\n", varstr);
			return (CLI_FAIL);
		}

		/*
		 * Pass 'wanted' to command-handling functions, in particular
		 * clprompt() and cllist().
		 */
		if ((cliptr->flags & CLF_CMD) != 0) {
			/* use uintptr_t to suppress the gcc warning */
			valstr = (char *)(uintptr_t)wanted;
		}

		/*
		 * Call the parameter's action function.
		 */
		switch (cliptr->action(cliptr, valstr, !assign)) {
		case CLI_SET:
			CLF_MODVAL(cliptr);
			break;
		case CLI_FAIL:
			printf("Incorrect format: variable '%s' not set\n",
			    cliptr->varname);
			break;
		case CLI_EXIT:
			return (CLI_EXIT);
		case CLI_CONT:
			if (!assign) {
				printf("\n");
			}
			break;
		}
	}

	return (CLI_CONT);
}

static void
cli_interpret(int wanted)
{
	printf("\n");
	do {
		printf(PROMPT);
		(void) editline(cmdbuf, sizeof (cmdbuf));
		printf("\n");

	} while (cli_eval_buf(cmdbuf, wanted) != CLI_EXIT);
}

#if	defined(__sparcv9)
/*
 * This routine queries the PROM to see what encryption keys exist.
 */
static void
get_prom_encr_keys()
{
	cli_ent_t *cliptr;
	char encr_key[WANBOOT_MAXKEYLEN];
	int keylen;
	int status;
	int ret;

	/*
	 * At the top of the priority list, we have AES.
	 */
	ret = prom_get_security_key(WANBOOT_AES_128_KEY_NAME, encr_key,
	    WANBOOT_MAXKEYLEN, &keylen, &status);
	if ((ret == 0) && (status == 0) && (keylen == AES_128_KEY_SIZE)) {
		cliptr = find_cli_ent(BI_AES_KEY);
		bcopy(encr_key, cliptr->varptr, AES_128_KEY_SIZE);
		cliptr->varlen = AES_128_KEY_SIZE;
		CLF_MODVAL(cliptr);
	}

	/*
	 * Next, 3DES.
	 */
	ret = prom_get_security_key(WANBOOT_DES3_KEY_NAME, encr_key,
	    WANBOOT_MAXKEYLEN, &keylen, &status);
	if ((ret == 0) && (status == 0) && (keylen == DES3_KEY_SIZE)) {
		cliptr = find_cli_ent(BI_3DES_KEY);
		bcopy(encr_key, cliptr->varptr, DES3_KEY_SIZE);
		cliptr->varlen = DES3_KEY_SIZE;
		CLF_MODVAL(cliptr);
	}
}

/*
 * This routine queries the PROM to see what hashing keys exist.
 */
static void
get_prom_hash_keys()
{
	cli_ent_t *cliptr;
	char hash_key[WANBOOT_HMAC_KEY_SIZE];
	int keylen;
	int status;
	int ret;

	/*
	 * The only supported key thus far is SHA1.
	 */
	ret = prom_get_security_key(WANBOOT_HMAC_SHA1_KEY_NAME, hash_key,
	    WANBOOT_HMAC_KEY_SIZE, &keylen, &status);
	if ((ret == 0) && (status == 0) && (keylen == WANBOOT_HMAC_KEY_SIZE)) {
		cliptr = find_cli_ent(BI_SHA1_KEY);
		bcopy(hash_key, cliptr->varptr, WANBOOT_HMAC_KEY_SIZE);
		cliptr->varlen = WANBOOT_HMAC_KEY_SIZE;
		CLF_MODVAL(cliptr);
	}
}
#endif	/* defined(__sparcv9) */

/*
 * For the given parameter type(s), get values from bootinfo and cache in
 * the local variables used by the "boot>" interpreter.
 */
static void
bootinfo_defaults(int which)
{
	cli_ent_t	*cliptr;

	for (cliptr = cli_list; cliptr < &cli_list[num_cli_ent]; ++cliptr) {
		if ((cliptr->flags & which) != 0 && !CLF_ISSET(cliptr)) {
			size_t	len = cliptr->varmax;

			if (bootinfo_get(cliptr->varname, cliptr->varptr,
			    &len, NULL) == BI_E_SUCCESS) {
				cliptr->varlen = len;
				CLF_SETVAL(cliptr);
			}
		}
	}
}

/*
 * For the given parameter type(s), store values entered at the "boot>"
 * interpreter back into bootinfo.
 */
static void
update_bootinfo(int which)
{
	cli_ent_t	*cliptr;

	for (cliptr = cli_list; cliptr < &cli_list[num_cli_ent]; ++cliptr) {
		if ((cliptr->flags & which) != 0 && CLF_ISMOD(cliptr)) {
			(void) bootinfo_put(cliptr->varname,
			    cliptr->varptr, cliptr->varlen, 0);
		}
	}
}

/*
 * Return the net-config-strategy: "dhcp", "manual" or "rarp"
 */
static char *
net_config_strategy(void)
{
	static char	ncs[8];		/* "dhcp" or "manual" */
	size_t		len = sizeof (ncs);

	if (ncs[0] == '\0' &&
	    bootinfo_get(BI_NET_CONFIG_STRATEGY, ncs, &len, NULL) !=
	    BI_E_SUCCESS) {
		/*
		 * Support for old PROMs: create the net-config-strategy
		 * property under /chosen with an appropriate value.  If we
		 * have a bootp-response (not interested in its value, just
		 * its presence) then we did DHCP; otherwise configuration
		 * is manual.
		 */
		if (bootinfo_get(BI_BOOTP_RESPONSE, NULL, NULL,
		    NULL) == BI_E_BUF2SMALL) {
			(void) strcpy(ncs, "dhcp");
		} else {
			(void) strcpy(ncs, "manual");
		}
		(void) bootinfo_put(BI_NET_CONFIG_STRATEGY, ncs, strlen(ncs),
		    BI_R_CHOSEN);

		bootlog("wanboot", BOOTLOG_INFO,
		    "Default net-config-strategy: %s", ncs);
	}

	return (ncs);
}

/*
 * If there is no client-id property published in /chosen (by the PROM or the
 * boot interpreter) provide a default client-id based on the MAC address of
 * the client.
 * As specified in RFC2132 (section 9.14), this is prefixed with a byte
 * which specifies the ARP hardware type defined in RFC1700 (for Ethernet,
 * this should be 1).
 */
static void
generate_default_clientid(void)
{
	char	clid[WB_MAX_CID_LEN];
	size_t	len = sizeof (clid);

	if (bootinfo_get(BI_CLIENT_ID, clid, &len, NULL) != BI_E_SUCCESS) {
		len = mac_get_addr_len() + 1;	/* include hwtype */

		if (len > sizeof (clid)) {
			return;
		}

		clid[0] = mac_arp_type(mac_get_type());
		bcopy(mac_get_addr_buf(), &clid[1], len - 1);

		(void) bootinfo_put(BI_CLIENT_ID, clid, len, 0);
	}
}

/*
 * Determine the URL of the boot server from the 'file' parameter to OBP,
 * the SbootURI or BootFile DHCP options, or the 'bootserver' value entered
 * either as a "-o" argument or at the interpreter.
 */
static void
determine_bootserver_url(void)
{
	char	bs[URL_MAX_STRLEN + 1];
	size_t	len;
	url_t	url;

	if (bootinfo_get(BI_BOOTSERVER, bs, &len, NULL) != BI_E_SUCCESS) {
		/*
		 * If OBP has published a network-boot-file property in
		 * /chosen (or there is a DHCP BootFile or SbootURI vendor
		 * option) and it's a URL, construct the bootserver URL
		 * from it.
		 */
		len = URL_MAX_STRLEN;
		if (bootinfo_get(BI_NETWORK_BOOT_FILE, bs, &len, NULL) !=
		    BI_E_SUCCESS) {
			len = URL_MAX_STRLEN;
			if (bootinfo_get(BI_BOOTFILE, bs, &len, NULL) !=
			    BI_E_SUCCESS) {
				return;
			}
		}
		if (url_parse(bs, &url) == URL_PARSE_SUCCESS) {
			(void) bootinfo_put(BI_BOOTSERVER, bs, len, 0);
		}
	}
}

/*
 * Provide a classful subnet mask based on the client's IP address.
 */
static in_addr_t
generate_classful_subnet(in_addr_t client_ipaddr)
{
	struct in_addr	subnetmask;
	char		*netstr;

	if (IN_CLASSA(client_ipaddr)) {
		subnetmask.s_addr = IN_CLASSA_NET;
	} else if (IN_CLASSB(client_ipaddr)) {
		subnetmask.s_addr = IN_CLASSB_NET;
	} else if (IN_CLASSC(client_ipaddr)) {
		subnetmask.s_addr = IN_CLASSC_NET;
	} else {
		subnetmask.s_addr = IN_CLASSE_NET;
	}

	netstr = inet_ntoa(subnetmask);
	(void) bootinfo_put(BI_SUBNET_MASK, netstr, strlen(netstr) + 1, 0);

	return (subnetmask.s_addr);
}

/*
 * Informational output to the user (if interactive) or the bootlogger.
 */
static void
info(const char *msg, boolean_t interactive)
{
	if (interactive) {
		printf("%s\n", msg);
	} else {
		bootlog("wanboot", BOOTLOG_INFO, "%s", msg);
	}
}

/*
 * Determine whether we have sufficient information to proceed with booting,
 * either for configuring the interface and downloading the bootconf file,
 * or for downloading the miniroot.
 */
static int
config_incomplete(int why, boolean_t interactive)
{
	boolean_t		error = B_FALSE;
	char			buf[URL_MAX_STRLEN + 1];
	size_t			len;
	char			*urlstr;
	url_t			u;
	struct hostent		*hp;
	in_addr_t		client_ipaddr, ipaddr, bsnet, pxnet;
	static in_addr_t	subnetmask, clnet;
	static boolean_t	have_router = B_FALSE;
	static boolean_t	have_proxy = B_FALSE;
	boolean_t		have_root_server = B_FALSE;
	boolean_t		have_boot_logger = B_FALSE;
	in_addr_t		rsnet, blnet;

	/*
	 * Note that 'have_router', 'have_proxy', 'subnetmask', and 'clnet'
	 * are static, so that their values (gathered when checking the
	 * interface configuration) may be used again when checking the boot
	 * configuration.
	 */
	if (why == CLF_IF) {
		/*
		 * A valid host IP address is an absolute requirement.
		 */
		len = sizeof (buf);
		if (bootinfo_get(BI_HOST_IP, buf, &len, NULL) == BI_E_SUCCESS) {
			if ((client_ipaddr = inet_addr(buf)) == (in_addr_t)-1) {
				info("host-ip invalid!", interactive);
				error = B_TRUE;
			}
		} else {
			info("host-ip not set!", interactive);
			error = B_TRUE;
		}

		/*
		 * If a subnet mask was provided, use it; otherwise infer it.
		 */
		len = sizeof (buf);
		if (bootinfo_get(BI_SUBNET_MASK, buf, &len, NULL) ==
		    BI_E_SUCCESS) {
			if ((subnetmask = inet_addr(buf)) == (in_addr_t)-1) {
				info("subnet-mask invalid!", interactive);
				error = B_TRUE;
			}
		} else {
			info("Defaulting to classful subnetting", interactive);

			subnetmask = generate_classful_subnet(client_ipaddr);
		}
		clnet = client_ipaddr & subnetmask;

		/*
		 * A legal bootserver URL is also an absolute requirement.
		 */
		len = sizeof (buf);
		if (bootinfo_get(BI_BOOTSERVER, buf, &len, NULL) ==
		    BI_E_SUCCESS) {
			if (url_parse(buf, &u) != URL_PARSE_SUCCESS ||
			    u.https ||
			    (ipaddr = inet_addr(u.hport.hostname)) ==
			    (in_addr_t)-1) {
				info("bootserver not legal URL!", interactive);
				error = B_TRUE;
			} else {
				bsnet = ipaddr & subnetmask;
			}
		} else {
			info("bootserver not specified!", interactive);
			error = B_TRUE;
		}

		/*
		 * Is there a correctly-defined router?
		 */
		len = sizeof (buf);
		if (bootinfo_get(BI_ROUTER_IP, buf, &len, NULL) ==
		    BI_E_SUCCESS) {
			if ((ipaddr = inet_addr(buf)) == (in_addr_t)-1) {
				info("router-ip invalid!", interactive);
				error = B_TRUE;
			} else if (clnet != (ipaddr & subnetmask)) {
				info("router not on local subnet!",
				    interactive);
				error = B_TRUE;
			} else {
				have_router = B_TRUE;
			}
		}

		/*
		 * Is there a correctly-defined proxy?
		 */
		len = sizeof (buf);
		if (bootinfo_get(BI_HTTP_PROXY, buf, &len, NULL) ==
		    BI_E_SUCCESS) {
			url_hport_t	u;

			if (url_parse_hostport(buf, &u, URL_DFLT_PROXY_PORT) !=
			    URL_PARSE_SUCCESS ||
			    (ipaddr = inet_addr(u.hostname)) == (in_addr_t)-1) {
				info("http-proxy port invalid!", interactive);
				error = B_TRUE;
			} else {
				/*
				 * The proxy is only of use to us if it's on
				 * our local subnet, or if a router has been
				 * specified (which should hopefully allow us
				 * to access the proxy).
				 */
				pxnet = ipaddr & subnetmask;
				have_proxy = (have_router || pxnet == clnet);
			}
		}

		/*
		 * If there is no router and no proxy (either on the local
		 * subnet or reachable via a router), then the bootserver
		 * URL must be on the local net.
		 */
		if (!error && !have_router && !have_proxy && bsnet != clnet) {
			info("bootserver URL not on local subnet",
			    interactive);
			error = B_TRUE;
		}
	} else {
		/*
		 * There must be a correctly-defined root_server URL.
		 */
		if ((urlstr = bootconf_get(&bc_handle,
		    BC_ROOT_SERVER)) == NULL) {
			info("no root_server URL!", interactive);
			error = B_TRUE;
		} else if (url_parse(urlstr, &u) != URL_PARSE_SUCCESS) {
			info("root_server not legal URL!", interactive);
			error = B_TRUE;
		} else if ((hp = gethostbyname(u.hport.hostname)) == NULL) {
			info("cannot resolve root_server hostname!",
			    interactive);
			error = B_TRUE;
		} else {
			rsnet = *(in_addr_t *)hp->h_addr & subnetmask;
			have_root_server = B_TRUE;
		}

		/*
		 * Is there a correctly-defined (non-empty) boot_logger URL?
		 */
		if ((urlstr = bootconf_get(&bc_handle,
		    BC_BOOT_LOGGER)) != NULL) {
			if (url_parse(urlstr, &u) != URL_PARSE_SUCCESS) {
				info("boot_logger not legal URL!", interactive);
				error = B_TRUE;
			} else if ((hp = gethostbyname(u.hport.hostname)) ==
			    NULL) {
				info("cannot resolve boot_logger hostname!",
				    interactive);
				error = B_TRUE;
			} else {
				blnet = *(in_addr_t *)hp->h_addr & subnetmask;
				have_boot_logger = B_TRUE;
			}
		}

		/*
		 * If there is no router and no proxy (either on the local
		 * subnet or reachable via a router), then the root_server
		 * URL (and the boot_logger URL if specified) must be on the
		 * local net.
		 */
		if (!error && !have_router && !have_proxy) {
			if (have_root_server && rsnet != clnet) {
				info("root_server URL not on local subnet",
				    interactive);
				error = B_TRUE;
			}
			if (have_boot_logger && blnet != clnet) {
				info("boot_logger URL not on local subnet",
				    interactive);
				error = B_TRUE;
			}
		}
	}

	return (error);
}

/*
 * Actually setup our network interface with the values derived from the
 * PROM, DHCP or interactively from the user.
 */
static void
setup_interface()
{
	char		str[MAXHOSTNAMELEN];	/* will accomodate an IP too */
	size_t		len;
	struct in_addr	in_addr;

	len = sizeof (str);
	if (bootinfo_get(BI_HOST_IP, str, &len, NULL) == BI_E_SUCCESS &&
	    (in_addr.s_addr = inet_addr(str)) != (in_addr_t)-1) {
		in_addr.s_addr = htonl(in_addr.s_addr);
		ipv4_setipaddr(&in_addr);
	}

	len = sizeof (str);
	if (bootinfo_get(BI_SUBNET_MASK, str, &len, NULL) == BI_E_SUCCESS &&
	    (in_addr.s_addr = inet_addr(str)) != (in_addr_t)-1) {
		in_addr.s_addr = htonl(in_addr.s_addr);
		ipv4_setnetmask(&in_addr);
	}

	len = sizeof (str);
	if (bootinfo_get(BI_ROUTER_IP, str, &len, NULL) == BI_E_SUCCESS &&
	    (in_addr.s_addr = inet_addr(str)) != (in_addr_t)-1) {
		in_addr.s_addr = htonl(in_addr.s_addr);
		ipv4_setdefaultrouter(&in_addr);
		(void) ipv4_route(IPV4_ADD_ROUTE, RT_DEFAULT, NULL, &in_addr);
	}

	len = sizeof (str);
	if (bootinfo_get(BI_HOSTNAME, str, &len, NULL) == BI_E_SUCCESS) {
		(void) sethostname(str, len);
	}
}

boolean_t
wanboot_init_interface(char *boot_arguments)
{
	boolean_t	interactive;
	int		which;

#if	defined(__sparcv9)
	/*
	 * Get the keys from PROM before we allow the user
	 * to override them from the CLI.
	 */
	get_prom_encr_keys();
	get_prom_hash_keys();
#endif	/* defined(__sparcv9) */

	/*
	 * If there is already a bootp-response property under
	 * /chosen then the PROM must have done DHCP for us;
	 * invoke dhcp() to 'bind' the interface.
	 */
	if (bootinfo_get(BI_BOOTP_RESPONSE, NULL, NULL, NULL) ==
	    BI_E_BUF2SMALL) {
		(void) cldhcp(NULL, NULL, 0);
	}

	/*
	 * Obtain default interface values from bootinfo.
	 */
	bootinfo_defaults(CLF_IF);

	/*
	 * Process the boot arguments (following the "-o" option).
	 */
	if (boot_arguments != NULL) {
		(void) cli_eval_buf(boot_arguments,
		    (CLF_ARG | CLF_IF | CLF_BM));
	}

	/*
	 * Stash away any interface/bootmisc parameter values we got
	 * from either the PROM or the boot arguments.
	 */
	update_bootinfo(CLF_IF | CLF_BM);

	/*
	 * If we don't already have a value for bootserver, try to
	 * deduce one.  Refresh wbcli's idea of these values.
	 */
	determine_bootserver_url();
	bootinfo_defaults(CLF_BM);

	/*
	 * Check that the information we have collected thus far is sufficient.
	 */
	interactive = args_specified_prompt;

	if (interactive) {
		/*
		 * Drop into the boot interpreter to allow the input
		 * of keys, bootserver and bootmisc, and in the case
		 * that net-config-strategy == "manual" the interface
		 * parameters.
		 */
		which = CLF_BM | CLF_CMD;
		if (strcmp(net_config_strategy(), "manual") == 0)
			which |= CLF_IF;

		do {
			cli_interpret(which);
			update_bootinfo(CLF_IF | CLF_BM);
		} while (config_incomplete(CLF_IF, interactive));
	} else {
		/*
		 * The user is not to be given the opportunity to
		 * enter further values; fail.
		 */
		if (config_incomplete(CLF_IF, interactive)) {
			bootlog("wanboot", BOOTLOG_CRIT,
			    "interface incorrectly configured");
			return (B_FALSE);
		}
	}

	/*
	 * If a wanboot-enabled PROM hasn't processed client-id in
	 * network-boot-arguments, or no value for client-id has been
	 * specified to the boot interpreter, then provide a default
	 * client-id based on our MAC address.
	 */
	generate_default_clientid();

	/*
	 * If net-config-strategy == "manual" then we must setup
	 * the interface now; if "dhcp" then it will already have
	 * been setup.
	 */
	if (strcmp(net_config_strategy(), "manual") == 0)
		setup_interface();
	return (B_TRUE);
}

boolean_t
wanboot_verify_config(void)
{
	/*
	 * Check that the wanboot.conf file defines a valid root_server
	 * URL, and check that, if given, the boot_logger URL is valid.
	 */
	if (config_incomplete(0, B_FALSE)) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "incomplete boot configuration");
		return (B_FALSE);
	}
	return (B_TRUE);
}
