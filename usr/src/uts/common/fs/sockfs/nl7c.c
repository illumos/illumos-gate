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
 * NL7C (Network Layer 7 Cache) as part of SOCKFS provides an in-kernel
 * gateway cache for the request/response message based L7 protocol HTTP
 * (Hypertext Transfer Protocol, see HTTP/1.1 RFC2616) in a semantically
 * transparent manner.
 *
 * Neither the requesting user agent (client, e.g. web broweser) nor the
 * origin server (e.g. webserver) that provided the response cached by
 * NL7C are impacted in any way.
 *
 * Note, currently NL7C only processes HTTP messages via the embedded
 * URI of scheme http (not https nor any other), additional scheme are
 * intended to be supproted as is practical such that much of the NL7C
 * framework may appear more gerneral purpose then would be needed just
 * for an HTTP gateway cache.
 *
 * NL7C replaces NCA (Network Cache and Accelerator) and in the future
 * NCAS (NCA/SSL).
 *
 * Further, NL7C uses all NCA configuration files, see "/etc/nca/", the
 * NCA socket API, "AF_NCA", and "ndd /dev/nca" for backwards compatability.
 */

#include <sys/promif.h>
#include <sys/systm.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <inet/common.h>
#include <inet/led.h>
#include <inet/mi.h>
#include <netinet/in.h>
#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/nl7curi.h>

#include <inet/nca/ncadoorhdr.h>
#include <inet/nca/ncalogd.h>

/*
 * NL7C, NCA, NL7C logger enabled:
 */

boolean_t	nl7c_enabled = B_FALSE;

boolean_t	nl7c_logd_enabled = B_FALSE;
boolean_t	nl7c_logd_started = B_FALSE;
boolean_t	nl7c_logd_cycle = B_TRUE;

/*
 * Some externs:
 */

extern int	inet_pton(int, char *, void *);

extern void	nl7c_uri_init(void);
extern boolean_t nl7c_logd_init(int, caddr_t *);
extern void	nl7c_nca_init(void);

/*
 * nl7c_addr_t - a singly linked grounded list, pointed to by *nl7caddrs,
 * constructed at init time by parsing "/etc/nca/ncaport.conf".
 *
 * This list is searched at bind(3SOCKET) time when an application doesn't
 * explicitly set AF_NCA but instead uses AF_INET, if a match is found then
 * the underlying socket is marked so_nl7c_flags NL7C_ENABLED.
 */

typedef struct nl7c_addr_s {
	struct nl7c_addr_s *next;	/* next entry */
	sa_family_t	family;		/* addr type, only INET and INET6 */
	uint16_t	port;		/* port */
	union {
		ipaddr_t	v4;	/* IPv4 address */
		in6_addr_t	v6;	/* IPv6 address */
		void		*align;	/* foce alignment */
	}		addr;		/* address */

	queue_t		*listenerq;	/* listen()er's Q (NULL if none ) */
	boolean_t	temp;		/* temporary addr via add_addr() ? */
} nl7c_addr_t;

nl7c_addr_t	*nl7caddrs = NULL;

void
nl7c_listener_addr(void *arg, queue_t *q)
{
	nl7c_addr_t	*p = (nl7c_addr_t *)arg;

	if (p->listenerq == NULL)
		p->listenerq = q;
}

void *
nl7c_lookup_addr(void *addr, t_uscalar_t addrlen)
{
	struct sockaddr		*sap = addr;
	struct sockaddr_in	*v4p = addr;
	nl7c_addr_t		*p = nl7caddrs;

	if (sap->sa_family != AF_INET || addrlen != sizeof (*v4p)) {
		/* Only support IPv4 */
		return (B_FALSE);
	}
	while (p) {
		if (sap->sa_family == p->family &&
		    v4p->sin_port == p->port &&
		    (v4p->sin_addr.s_addr == p->addr.v4 ||
		    p->addr.v4 == INADDR_ANY)) {
			/* Match */
			return (p);
		}
		p = p->next;
	}
	return (NULL);
}

void *
nl7c_add_addr(void *addr, t_uscalar_t addrlen)
{
	struct sockaddr		*sap = addr;
	struct sockaddr_in	*v4p = addr;
	nl7c_addr_t		*new = NULL;
	nl7c_addr_t		*old;
	nl7c_addr_t		*p;
	boolean_t		alloced;

	if (sap->sa_family != AF_INET || addrlen != sizeof (*v4p)) {
		/* Only support IPv4 */
		return (NULL);
	}
again:
	old = nl7caddrs;
	p = nl7caddrs;
	while (p) {
		if (new == NULL && p->port == 0)
			new = p;
		if (sap->sa_family == p->family &&
		    v4p->sin_port == p->port &&
		    (v4p->sin_addr.s_addr == p->addr.v4 ||
		    p->addr.v4 == INADDR_ANY)) {
			/* Match */
			return (p);
		}
		p = p->next;
	}
	if (new == NULL) {
		new = kmem_zalloc(sizeof (*new), KM_SLEEP);
		if (new == NULL)
			return (NULL);
		alloced = B_TRUE;
	} else
		alloced = B_FALSE;

	new->family = sap->sa_family;
	new->port = v4p->sin_port;
	new->addr.v4 = v4p->sin_addr.s_addr;
	new->temp = B_TRUE;

	if (alloced) {
		new->next = old;
		if (atomic_cas_ptr(&nl7caddrs, old, new) != old) {
			kmem_free(new, sizeof (*new));
			goto again;
		}
	}

	return (new);
}

boolean_t
nl7c_close_addr(struct sonode *so)
{
	nl7c_addr_t	*p = nl7caddrs;
	queue_t		*q = strvp2wq(SOTOV(so));

	while (p) {
		if (p->listenerq == q) {
			if (p->temp)
				p->port = (uint16_t)-1;
			p->listenerq = NULL;
			return (B_TRUE);
		}
		p = p->next;
	}
	return (B_FALSE);
}

static void
nl7c_addr_add(nl7c_addr_t *p)
{
	p->next = nl7caddrs;
	nl7caddrs = p;
}

void
nl7c_mi_report_addr(mblk_t *mp)
{
	ipaddr_t	ip;
	uint16_t	port;
	nl7c_addr_t	*p = nl7caddrs;
	char		addr[32];

	(void) mi_mpprintf(mp, "Door  Up-Call-Queue IPaddr:TCPport Listenning");

	while (p) {
		if (p->listenerq != NULL) {
			/* Only report listen()ed on addr(s) */
			ip = ntohl(p->addr.v4);
			port = ntohs(p->port);

			if (ip == INADDR_ANY) {
				(void) strcpy(addr, "*");
			} else {
				int a1 = (ip >> 24) & 0xFF;
				int a2 = (ip >> 16) & 0xFF;
				int a3 = (ip >> 8) & 0xFF;
				int a4 = ip & 0xFF;

				(void) mi_sprintf(addr, "%d.%d.%d.%d",
					a1, a2, a3, a4);
			}
			(void) mi_sprintf(addr, "%s:%d", addr, port);
			(void) mi_mpprintf(mp, "%p  %p  %s  %d", (void *)NULL,
				(void *)p->listenerq, addr, 1);
		}
		p = p->next;
	}
}

/*
 * ASCII to unsigned.
 *
 * Note, it's assumed that *p is a valid zero byte terminated string.
 */

static unsigned
atou(const char *p)
{
	int c;
	int v = 0;

	/* Shift and add digit by digit */
	while ((c = *p++) != NULL && isdigit(c)) {
		v *= 10;
		v += c - '0';
	}
	return (v);
}

/*
 * strdup(), yet another strdup() in the kernel.
 */

static char *
strdup(char *s)
{
	int	len = strlen(s) + 1;
	char	*ret = kmem_alloc(len, KM_SLEEP);

	bcopy(s, ret, len);

	return (ret);
}

/*
 * Inet ASCII to binary.
 *
 * Note, it's assumed that *s is a valid zero byte terminated string, and
 * that *p is a zero initialized struct (this is important as the value of
 * INADDR_ANY and IN6ADDR_ANY is zero).
 */

static int
inet_atob(char *s, nl7c_addr_t *p)
{
	if (strcmp(s, "*") == 0) {
		/* INADDR_ANY */
		p->family = AF_INET;
		return (0);
	}
	if (strcmp(s, "::") == 0) {
		/* IN6ADDR_ANY */
		p->family = AF_INET6;
		return (0);
	}
	/* IPv4 address ? */
	if (inet_pton(AF_INET, s, &p->addr.v4) != 1) {
		/* Nop, IPv6 address ? */
		if (inet_pton(AF_INET6, s, &p->addr.v6) != 1) {
			/* Nop, return error */
			return (1);
		}
		p->family = AF_INET6;
	} else {
		p->family = AF_INET;
	}
	return (0);
}

/*
 * Open and read each line from "/etc/nca/ncaport.conf", the syntax of a
 * ncaport.conf file line is: ncaport=IPaddr/Port, all other lines will
 * be ignored, where:
 *
 * ncaport - the only token recognized.
 *
 *  IPaddr - an IPv4 numeric dot address (e.g. 192.168.84.71) or '*' for
 *           INADDR_ANY, or an IPv6 numeric address or "::" for IN6ADDR_ANY.
 *
 *       / - IPaddr/Port seperator.
 *
 *    Port - a TCP decimal port number.
 */

static void
ncaportconf_read(void)
{
	int	ret;
	struct vnode *vp;
	char	c;
	ssize_t resid;
	char	buf[1024];
	char	*ebp = &buf[sizeof (buf)];
	char	*bp = ebp;
	offset_t off = 0;
	enum parse_e {START, TOK, ADDR, PORT, EOL} parse = START;
	nl7c_addr_t *addrp = NULL;
	char	*ncaport = "ncaport";
	char	string[] = "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX";
	char	*stringp;
	char	*tok;
	char	*portconf = "/etc/nca/ncaport.conf";

	ret = vn_open(portconf, UIO_SYSSPACE, FREAD, 0, &vp, 0, 0);
	if (ret == ENOENT) {
		/* No portconf file, nothing to do */
		return;
	}
	if (ret != 0) {
		/* Error of some sort, tell'm about it */
		cmn_err(CE_WARN, "%s: open error %d", portconf, ret);
		return;
	}
	/*
	 * Read portconf one buf[] at a time, parse one char at a time.
	 */
	for (;;) {
		if (bp == ebp) {
			/* Nothing left in buf[], read another */
			ret = vn_rdwr(UIO_READ, vp, buf, sizeof (buf), off,
			    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), &resid);
			if (ret != 0) {
				/* Error of some sort, tell'm about it */
				cmn_err(CE_WARN, "%s: read error %d",
					portconf, ret);
				break;
			}
			if (resid == sizeof (buf)) {
				/* EOF, done */
				break;
			}
			/* Initilize per buf[] state */
			bp = buf;
			ebp = &buf[sizeof (buf) - resid];
			off += sizeof (buf) - resid;
		}
		c = *bp++;
		switch (parse) {
		case START:
			/* Initilize all per file line state */
			if (addrp == NULL) {
				addrp = kmem_zalloc(sizeof (*addrp),
				    KM_NOSLEEP);
			}
			tok = ncaport;
			stringp = string;
			parse = TOK;
			/*FALLTHROUGH*/
		case TOK:
			if (c == '#') {
				/* Comment through end of line */
				parse = EOL;
				break;
			}
			if (isalpha(c)) {
				if (c != *tok++) {
					/* Only know one token, skip */
					parse = EOL;
				}
			} else if (c == '=') {
				if (*tok != NULL) {
					/* Only know one token, skip */
					parse = EOL;
					break;
				}
				parse = ADDR;
			} else if (c == '\n') {
				/* Found EOL, empty line, next line */
				parse = START;
			} else {
				/* Unexpected char, skip */
				parse = EOL;
			}
			break;

		case ADDR:
			if (c == '/') {
				/* addr/port separator, end of addr */
				*stringp = NULL;
				if (inet_atob(string, addrp)) {
					/* Bad addr, skip */
					parse = EOL;
				} else {
					stringp = string;
					parse = PORT;
				}
			} else {
				/* Save char to string */
				if (stringp ==
				    &string[sizeof (string) - 1]) {
					/* Would overflow, skip */
					parse = EOL;
				} else {
					/* Copy IP addr char */
					*stringp++ = c;
				}
			}
			break;

		case PORT:
			if (isdigit(c)) {
				/* Save char to string */
				if (stringp ==
				    &string[sizeof (string) - 1]) {
					/* Would overflow, skip */
					parse = EOL;
				} else {
					/* Copy port digit char */
					*stringp++ = c;
				}
				break;
			} else if (c == '#' || isspace(c)) {
				/* End of port number, convert */
				*stringp = NULL;
				addrp->port = atou(string);

				/* End of parse, add entry */
				nl7c_addr_add(addrp);
				addrp = NULL;
				parse = EOL;
			} else {
				/* Unrecognized char, skip */
				parse = EOL;
				break;
			}
			/*FALLTHROUGH*/
		case EOL:
			if (c == '\n') {
				/* Found EOL, start on next line */
				parse = START;
			}
			break;
		}

	}
	if (addrp != NULL) {
		kmem_free(addrp, sizeof (*addrp));
	}
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED());
	VN_RELE(vp);
}

/*
 * Open and read each line from "/etc/nca/ncakmod.conf" and parse looking
 * for the NCA enabled, the syntax is: status=enabled, all other lines will
 * be ignored.
 */

static void
ncakmodconf_read(void)
{
	int	ret;
	struct vnode *vp;
	char	c;
	ssize_t resid;
	char	buf[1024];
	char	*ebp = &buf[sizeof (buf)];
	char	*bp = ebp;
	offset_t off = 0;
	enum parse_e {START, TOK, EOL} parse = START;
	char	*status = "status=enabled";
	char	*tok;
	char	*ncakmod = "/etc/nca/ncakmod.conf";

	ret = vn_open(ncakmod, UIO_SYSSPACE, FREAD, 0, &vp, 0, 0);
	if (ret == ENOENT) {
		/* No ncakmod file, nothing to do */
		return;
	}
	if (ret != 0) {
		/* Error of some sort, tell'm about it */
		cmn_err(CE_WARN, "%s: open error %d", status, ret);
		return;
	}
	/*
	 * Read ncakmod one buf[] at a time, parse one char at a time.
	 */
	for (;;) {
		if (bp == ebp) {
			/* Nothing left in buf[], read another */
			ret = vn_rdwr(UIO_READ, vp, buf, sizeof (buf), off,
			    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), &resid);
			if (ret != 0) {
				/* Error of some sort, tell'm about it */
				cmn_err(CE_WARN, "%s: read error %d",
					status, ret);
				break;
			}
			if (resid == sizeof (buf)) {
				/* EOF, done */
				break;
			}
			/* Initilize per buf[] state */
			bp = buf;
			ebp = &buf[sizeof (buf) - resid];
			off += sizeof (buf) - resid;
		}
		c = *bp++;
		switch (parse) {
		case START:
			/* Initilize all per file line state */
			tok = status;
			parse = TOK;
			/*FALLTHROUGH*/
		case TOK:
			if (c == '#') {
				/* Comment through end of line */
				parse = EOL;
				break;
			}
			if (isalpha(c) || c == '=') {
				if (c != *tok++) {
					/* Only know one token, skip */
					parse = EOL;
				}
			} else if (c == '\n') {
				/*
				 * Found EOL, if tok found done,
				 * else start on next-line.
				 */
				if (*tok == NULL) {
					nl7c_enabled = B_TRUE;
					goto done;
				}
				parse = START;
			} else {
				/* Unexpected char, skip */
				parse = EOL;
			}
			break;

		case EOL:
			if (c == '\n') {
				/* Found EOL, start on next line */
				parse = START;
			}
			break;
		}

	}
done:
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED());
	VN_RELE(vp);
}

/*
 * Open and read each line from "/etc/nca/ncalogd.conf" and parse for
 * the tokens and token text (i.e. key and value ncalogd.conf(4)):
 *
 *	status=enabled
 *
 *	logd_file_size=[0-9]+
 *
 *	logd_file_name=["]filename( filename)*["]
 */

static int	file_size = 1000000;
static caddr_t	fnv[NCA_FIOV_SZ];

static void
ncalogdconf_read(void)
{
	int	ret;
	struct vnode *vp;
	char	c;
	int	sz;
	ssize_t resid;
	char	buf[1024];
	char	*ebp = &buf[sizeof (buf)];
	char	*bp = ebp;
	offset_t off = 0;
	enum parse_e {START, TOK, TEXT, EOL} parse = START;
	char	*tokstatus = "status\0enabled";
	char	*toksize = "logd_file_size";
	char	*tokfile = "logd_path_name";
	char	*tokstatusp;
	char	*toksizep;
	char	*tokfilep;
	char	*tok;
	int	tokdelim = 0;
	char	*ncalogd = "/etc/nca/ncalogd.conf";
	char	*ncadeflog = "/var/nca/log";
	char	file[TYPICALMAXPATHLEN] = {0};
	char	*fp = file;
	caddr_t	*fnvp = fnv;

	ret = vn_open(ncalogd, UIO_SYSSPACE, FREAD, 0, &vp, 0, 0);
	if (ret == ENOENT) {
		/* No ncalogd file, nothing to do */
		return;
	}
	if (ret != 0) {
		/* Error of some sort, tell'm about it */
		cmn_err(CE_WARN, "ncalogdconf_read: %s: open error(%d).",
		    ncalogd, ret);
		return;
	}
	/*
	 * Read ncalogd.conf one buf[] at a time, parse one char at a time.
	 */
	for (;;) {
		if (bp == ebp) {
			/* Nothing left in buf[], read another */
			ret = vn_rdwr(UIO_READ, vp, buf, sizeof (buf), off,
			    UIO_SYSSPACE, 0, (rlim64_t)0, CRED(), &resid);
			if (ret != 0) {
				/* Error of some sort, tell'm about it */
				cmn_err(CE_WARN, "%s: read error %d",
					ncalogd, ret);
				break;
			}
			if (resid == sizeof (buf)) {
				/* EOF, done */
				break;
			}
			/* Initilize per buf[] state */
			bp = buf;
			ebp = &buf[sizeof (buf) - resid];
			off += sizeof (buf) - resid;
		}
		c = *bp++;
		switch (parse) {
		case START:
			/* Initilize all per file line state */
			tokstatusp = tokstatus;
			toksizep = toksize;
			tokfilep = tokfile;
			tok = NULL;
			parse = TOK;
			sz = 0;
			/*FALLTHROUGH*/
		case TOK:
			if (isalpha(c) || c == '_') {
				/*
				 * Found a valid tok char, if matches
				 * any of the tokens continue else NULL
				 * then string pointer.
				 */
				if (tokstatusp != NULL && c != *tokstatusp++)
					tokstatusp = NULL;
				if (toksizep != NULL && c != *toksizep++)
					toksizep = NULL;
				if (tokfilep != NULL && c != *tokfilep++)
					tokfilep = NULL;

				if (tokstatusp == NULL &&
				    toksizep == NULL &&
				    tokfilep == NULL) {
					/*
					 * All tok string pointers are NULL
					 * so skip rest of line.
					 */
					parse = EOL;
				}
			} else if (c == '=') {
				/*
				 * Found tok separator, if tok found get
				 * tok text, else skip rest of line.
				 */
				if (tokstatusp != NULL && *tokstatusp == NULL)
					tok = tokstatus;
				else if (toksizep != NULL && *toksizep == NULL)
					tok = toksize;
				else if (tokfilep != NULL && *tokfilep == NULL)
					tok = tokfile;
				if (tok != NULL)
					parse = TEXT;
				else
					parse = EOL;
			} else if (c == '\n') {
				/* Found EOL, start on next line */
				parse = START;
			} else {
				/* Comment or unknown char, skip rest of line */
				parse = EOL;
			}
			break;
		case TEXT:
			if (c == '\n') {
				/*
				 * Found EOL, finish up tok text processing
				 * (if any) and start on next line.
				 */
				if (tok == tokstatus) {
					if (*++tokstatusp == NULL)
						nl7c_logd_enabled = B_TRUE;
				} else if (tok == toksize) {
					file_size = sz;
				} else if (tok == tokfile) {
					if (tokdelim == 0) {
						/* Non delimited path name */
						*fnvp++ = strdup(file);
					} else if (fp != file) {
						/* No closing delimiter */
						/*EMPTY*/;
					}
				}
				parse = START;
			} else if (tok == tokstatus) {
				if (! isalpha(c) || *++tokstatusp == NULL ||
				    c != *tokstatusp) {
					/* Not enabled, skip line */
					parse = EOL;
				}
			} else if (tok == toksize) {
				if (isdigit(c)) {
					sz *= 10;
					sz += c - '0';
				} else {
					/* Not a decimal digit, skip line */
					parse = EOL;
				}
			} else {
				/* File name */
				if (c == '"' && tokdelim++ == 0) {
					/* Opening delimiter, skip */
					/*EMPTY*/;
				} else if (c == '"' || c == ' ') {
					/* List delim or filename seperator */
					*fnvp++ = strdup(file);
					fp = file;
				} else if (fp < &file[sizeof (file) - 1]) {
					/* Filename char */
					*fp++ = c;
				} else {
					/* Filename to long, skip line */
					parse = EOL;
				}
			}
			break;

		case EOL:
			if (c == '\n') {
				/* Found EOL, start on next line */
				parse = START;
			}
			break;
		}

	}
done:
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED());
	VN_RELE(vp);

	if (nl7c_logd_enabled) {
		if (fnvp == fnv) {
			/*
			 * No logfile was specified and found so
			 * so use defualt NCA log file path.
			 */
			*fnvp++ = strdup(ncadeflog);
		}
		if (fnvp < &fnv[NCA_FIOV_SZ]) {
			/* NULL terminate list */
			*fnvp = NULL;
		}
	}
}

void
nl7clogd_startup(void)
{
	static kmutex_t startup;

	/*
	 * Called on the first log() attempt, have to wait until then to
	 * initialize logd as at logdconf_read() the root fs is read-only.
	 */
	mutex_enter(&startup);
	if (nl7c_logd_started) {
		/* Lost the race, nothing todo */
		mutex_exit(&startup);
		return;
	}
	nl7c_logd_started = B_TRUE;
	if (! nl7c_logd_init(file_size, fnv)) {
		/* Failure, disable logging */
		nl7c_logd_enabled = B_FALSE;
		cmn_err(CE_WARN, "nl7clogd_startup: failed, disabling loggin");
		mutex_exit(&startup);
		return;
	}
	mutex_exit(&startup);
}


void
nl7c_startup()
{
	ncalogdconf_read();
	nl7c_uri_init();
	nl7c_nca_init();

	nl7c_enabled = B_TRUE;
}

void
nl7c_init()
{
	/* Open, read, and parse the NCA kmod configuration file */
	ncakmodconf_read();

	if (nl7c_enabled) {
		/*
		 * NL7C is enabled so open, read, and parse
		 * the NCA address/port configuration file
		 * and call startup() to finish config/init.
		 */
		ncaportconf_read();
		nl7c_startup();
	}
}

/*
 * The main processing function called by accept() on a newly created
 * socket prior to returning it to the caller of accept().
 *
 * Here data is read from the socket until a completed L7 request parse
 * is completed. Data will be read in the context of the user thread
 * which called accept(), when parse has been completed either B_TRUE
 * or B_FALSE will be returned.
 *
 * If NL7C successfully process the L7 protocol request, i.e. generates
 * a response, B_TRUE will be returned.
 *
 * Else, B_FALSE will be returned if NL7C can't process the request:
 *
 * 1) Couldn't locate a URI within the request.
 *
 * 2) URI scheme not reqcognized.
 *
 * 3) A request which can't be procesed.
 *
 * 4) A request which could be processed but NL7C dosen't currently have
 *    the response data. In which case NL7C will parse the returned response
 *    from the application for possible caching for subsequent request(s).
 */

volatile uint64_t nl7c_proc_cnt = 0;
volatile uint64_t nl7c_proc_error = 0;
volatile uint64_t nl7c_proc_ETIME = 0;
volatile uint64_t nl7c_proc_again = 0;
volatile uint64_t nl7c_proc_next = 0;
volatile uint64_t nl7c_proc_rcv = 0;
volatile uint64_t nl7c_proc_noLRI = 0;

boolean_t
nl7c_process(struct sonode *so, boolean_t nonblocking, int max_mblk)
{
	vnode_t	*vp = SOTOV(so);
	mblk_t	*mp = so->so_nl7c_rcv_mp;
	mblk_t	*tmp;
	clock_t	timout;
	uchar_t pri;
	int 	pflag;
	mblk_t	*rmp;
	rval_t	rval;
	int	error;
	boolean_t ret;
	boolean_t more;

	nl7c_proc_cnt++;

	error = so_lock_read_intr(so, nonblocking ? FNDELAY|FNONBLOCK : 0);
	if (error) {
		/* Couldn't read lock, pass on this socket */
		so->so_nl7c_flags = 0;
		ret = B_FALSE;
		nl7c_proc_noLRI++;
		goto out;
	}
	mutex_exit(&so->so_lock);

	if (mp != NULL) {
		/*
		 * Some data from a previous process() call,
		 * move to rmp so we skip the first kstrgetmsg().
		 */
		rmp = mp;
		mp = NULL;
	} else
		rmp = NULL;

	/* Initialize some kstrgetmsg() constants */
	pflag = MSG_ANY;
	pri = 0;
	if (nonblocking)
		timout = 0;
	else
		timout = -1;

	do {
		if (rmp == NULL) {
			rval.r_vals = 0;
			error = kstrgetmsg(vp, &rmp, NULL, &pri, &pflag,
					timout, &rval);

			if (error) {
				if (error == ETIME) {
					/* Timeout */
					error = 0;
					nl7c_proc_ETIME++;
				} else {
					/* Error of some sort */
					nl7c_proc_error++;
				}
				ret = B_FALSE;
				break;
			}

			if (rmp == NULL) {
				/* No more data */
				ret = B_FALSE;
				break;
			}
		}
		if (mp == NULL) {
			/* First msg, common case */
			mp = rmp;
			so->so_nl7c_rcv_mp = mp;
		} else {
			/*
			 * Add msg to tail.
			 *
			 * Note, mp == NULL first pass through the loop
			 * and tmp is set below.
			 */
			/*LINTED*/
			tmp->b_cont = rmp;
		}

		/* New tail */
		tmp = rmp;
		rmp = NULL;
		while (tmp->b_cont != NULL)
			tmp = tmp->b_cont;

	again:
		more = nl7c_parse(so, nonblocking, &ret, max_mblk);

		if (more == B_FALSE && ret == B_TRUE &&
		    (so->so_nl7c_flags & NL7C_SOPERSIST)) {
			/*
			 * Parse complete, socket is persistent so
			 * process the next request (if any).
			 */
			if (so->so_nl7c_rcv_mp) {
				/* More recv-side data, pipelined ? */
				nl7c_proc_again++;
				goto again;
			}
			nl7c_proc_next++;
			if (nonblocking)
				timout = 0;
			else
				timout = 15000; /* 15 seconds */
			mp = NULL;
			more = B_TRUE;
			ret = B_FALSE;
		}

	} while (more);

	if (error) {
		/*
		 * An error of some sort occured above, save the error
		 * value for passing the socket onto the accept()er.
		 *
		 * Update the saved rval_t with the error value and
		 * clear the NL7C so_state so the socket accept() can
		 * complete, return B_FALSE.
		 */
		so->so_nl7c_rcv_rval = (int64_t)error;
		so->so_nl7c_flags = 0;
		ret = B_FALSE;
	} else if (so->so_nl7c_rcv_mp) {
		/*
		 * Recieve side data leftover so save the last rval_t
		 * from above for subsequent read() processing and if
		 * POLLIN is indicated (i.e. a read-side poll() may be
		 * pending) do a pollwakeup().
		 */
		nl7c_proc_rcv++;
		so->so_nl7c_rcv_rval = rval.r_vals;
	}
	mutex_enter(&so->so_lock);
	so_unlock_read(so);
out:
	return (ret);
}
