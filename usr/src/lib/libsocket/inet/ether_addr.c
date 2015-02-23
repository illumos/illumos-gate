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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * All routines necessary to deal the "ethers" database.  The sources
 * contain mappings between 48 bit ethernet addresses and corresponding
 * hosts names.  The addresses have an ascii representation of the form
 * "x:x:x:x:x:x" where x is a hex number between 0x00 and 0xff;  the
 * bytes are always in network order.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <thread.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <nss_dbdefs.h>

int str2ether(const char *, int, void *, char *, int);

static DEFINE_NSS_DB_ROOT(db_root);

void
_nss_initf_ethers(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_ETHERS;
	p->default_config = NSS_DEFCONF_ETHERS;
}

/*
 * Given a host's name, this routine finds the corresponding 48 bit
 * ethernet address based on the "ethers" policy in /etc/nsswitch.conf.
 * Returns zero if successful, non-zero otherwise.
 */
int
ether_hostton(
	const char *host,		/* function input */
	struct ether_addr *e		/* function output */
)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	/*
	 * let the backend do the allocation to store stuff for parsing.
	 */
	NSS_XbyY_INIT(&arg, e, NULL, 0, str2ether);
	arg.key.name = host;
	res = nss_search(&db_root, _nss_initf_ethers,
	    NSS_DBOP_ETHERS_HOSTTON, &arg);
	(void) NSS_XbyY_FINI(&arg);
	return (arg.status = res);
}

/*
 * Given a 48 bit ethernet address, it finds the corresponding hostname
 * ethernet address based on the "ethers" policy in /etc/nsswitch.conf.
 * Returns zero if successful, non-zero otherwise.
 */
int
ether_ntohost(
	char *host,			/* function output */
	const struct ether_addr *e	/* function input */
)
{
	nss_XbyY_args_t arg;
	nss_status_t	res;

	/*
	 * let the backend do the allocation to store stuff for parsing.
	 */
	NSS_XbyY_INIT(&arg, NULL, host, 0, str2ether);
	arg.key.ether = (void *)e;
	res = nss_search(&db_root, _nss_initf_ethers,
	    NSS_DBOP_ETHERS_NTOHOST, &arg);
	/* memcpy(host, ether_res.host, strlen(ether_res.host)); */
	(void) NSS_XbyY_FINI(&arg);
	return (arg.status = res);
}

/*
 * Parses a line from "ethers" database into its components.  The line has
 * the form 8:0:20:1:17:c8	krypton
 * where the first part is a 48 bit ethernet address and the second is
 * the corresponding hosts name.
 * Returns zero if successful, non-zero otherwise.
 */
int
ether_line(
	const char *s,		/* the string to be parsed */
	struct ether_addr *e,	/* ethernet address struct to be filled in */
	char *hostname		/* hosts name to be set */
)
{
	int i;
	uint_t t[6];

	i = sscanf(s, " %x:%x:%x:%x:%x:%x %s",
	    &t[0], &t[1], &t[2], &t[3], &t[4], &t[5], hostname);
	if (i != 7) {
		return (7 - i);
	}
	for (i = 0; i < 6; i++)
		e->ether_addr_octet[i] = (uchar_t)t[i];
	return (0);
}

/*
 * Parses a line from "ethers" database into its components.
 * Useful for the vile purposes of the backends that
 * expect a str2ether() format.
 *
 * This function, after parsing the instr line, will
 * place the resulting struct ether_addr in b->buf.result only if
 * b->buf.result is initialized (not NULL). I.e. it always happens
 * for "files" backend (that needs to parse input line and
 * then do a match for the ether key) and happens for "nis"
 * backend only if the call was ether_hostton.
 *
 * Also, it will place the resulting hostname into b->buf.buffer
 * only if b->buf.buffer is initialized. I.e. it always happens
 * for "files" backend (that needs to parse input line and
 * then do a match for the host key) and happens for "nis"
 * backend only if the call was ether_ntohost.
 *
 * Cannot use the sscanf() technique for parsing because instr
 * is a read-only, not necessarily null-terminated, buffer.
 *
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas.
 */
#define	DIGIT(x)	(isdigit(x) ? (x) - '0' : \
		islower(x) ? (x) + 10 - 'a' : (x) + 10 - 'A')
#define	lisalnum(x)	(isdigit(x) || \
		((x) >= 'a' && (x) <= 'z') || ((x) >= 'A' && (x) <= 'Z'))
/* ARGSUSED */
int
str2ether(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	uchar_t	*ether =  (uchar_t *)ent;
	char	*host = buffer;
	const char	*p, *limit, *start;
	ptrdiff_t i;

	p = instr;
	limit = p + lenstr;

	/* skip beginning whitespace, if any */
	while (p < limit && isspace(*p))
		p++;

	if (ether) {	/* parse ether */
		for (i = 0; i < 6; i++) {
			int	j = 0, n = 0;

			start = p;
			while (p < limit && lisalnum(start[j])) {
				/* don't worry about overflow here */
				n = 16 * n + DIGIT(start[j]);
				j++;
				p++;
			}
			if (*p != ':' && i < 5) {
				return (NSS_STR_PARSE_PARSE);
			} else {
				p++;
				*(ether + i) = (uchar_t)n;
			}
		}
	} else {	/* skip ether */
		while (p < limit && !isspace(*p))
			p++;
	}
	if (host) {	/* parse host */
		while (p < limit && isspace(*p))	/* skip whitespace */
			p++;
		start = p;
		while (p < limit && !isspace(*p))	/* skip hostname */
			p++;
		if ((i = (p - start)) < MAXHOSTNAMELEN) {
			(void) memcpy(host, start, i);
			host[i] = '\0';
		} else
			return (NSS_STR_PARSE_ERANGE); /* failure */
	}
	return (NSS_STR_PARSE_SUCCESS);
}

typedef struct {
	char			ea_string[18];
	struct ether_addr	ea_addr;
} eabuf_t;

static eabuf_t *
ea_buf(void)
{
	static thread_key_t key = THR_ONCE_KEY;
	static eabuf_t ea_main;
	eabuf_t *eabuf;

	if (thr_main())
		return (&ea_main);

	if (thr_keycreate_once(&key, free) != 0)
		return (NULL);
	eabuf = pthread_getspecific(key);
	if (eabuf == NULL) {
		eabuf = malloc(sizeof (eabuf_t));
		(void) thr_setspecific(key, eabuf);
	}
	return (eabuf);
}

/*
 * Converts a 48 bit ethernet number to its string representation using a user
 * defined buffer.
 */
char *
ether_ntoa_r(const struct ether_addr *e, char *buf)
{
	(void) sprintf(buf, "%x:%x:%x:%x:%x:%x",
	    e->ether_addr_octet[0], e->ether_addr_octet[1],
	    e->ether_addr_octet[2], e->ether_addr_octet[3],
	    e->ether_addr_octet[4], e->ether_addr_octet[5]);
	return (buf);
}

/*
 * Converts a 48 bit ethernet number to its string representation using a
 * per-thread buffer.
 */
char *
ether_ntoa(const struct ether_addr *e)
{
	eabuf_t *eabuf;

	if ((eabuf = ea_buf()) == NULL)
		return (NULL);
	return (ether_ntoa_r(e, eabuf->ea_string));
}

/*
 * Converts an ethernet address representation back into its 48 bits using a
 * user defined buffer.
 */
struct ether_addr *
ether_aton_r(const char *s, struct ether_addr *e)
{
	int i;
	uint_t t[6];
	i = sscanf(s, " %x:%x:%x:%x:%x:%x",
	    &t[0], &t[1], &t[2], &t[3], &t[4], &t[5]);
	if (i != 6)
		return (NULL);
	for (i = 0; i < 6; i++)
		e->ether_addr_octet[i] = (uchar_t)t[i];
	return (e);
}

/*
 * Converts an ethernet address representation back into its 48 bits using a
 * per-thread buffer.
 */
struct ether_addr *
ether_aton(const char *s)
{
	eabuf_t *eabuf;

	if ((eabuf = ea_buf()) == NULL)
		return (NULL);
	return (ether_aton_r(s, &eabuf->ea_addr));
}
