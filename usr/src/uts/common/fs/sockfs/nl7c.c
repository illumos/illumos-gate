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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * NL7C (Network Layer 7 Cache) as part of SOCKFS provides an in-kernel
 * gateway cache for the request/response message based L7 protocol HTTP
 * (Hypertext Transfer Protocol, see HTTP/1.1 RFC2616) in a semantically
 * transparent manner.
 *
 * Neither the requesting user agent (client, e.g. web browser) nor the
 * origin server (e.g. webserver) that provided the response cached by
 * NL7C are impacted in any way.
 *
 * Note, currently NL7C only processes HTTP messages via the embedded
 * URI of scheme http (not https nor any other), additional scheme are
 * intended to be supported as is practical such that much of the NL7C
 * framework may appear more general purpose then would be needed just
 * for an HTTP gateway cache.
 *
 * NL7C replaces NCA (Network Cache and Accelerator) and in the future
 * NCAS (NCA/SSL).
 *
 * Further, NL7C uses all NCA configuration files, see "/etc/nca/", the
 * NCA socket API, "AF_NCA", and "ndd /dev/nca" for backwards compatibility.
 */

#include <sys/systm.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/led.h>
#include <inet/mi.h>
#include <netinet/in.h>
#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/nl7curi.h>
#include <fs/sockfs/socktpi.h>

#include <inet/nca/ncadoorhdr.h>
#include <inet/nca/ncalogd.h>
#include <inet/nca/ncandd.h>

#include <sys/promif.h>

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
extern void	nl7c_uri_init(void);
extern boolean_t nl7c_logd_init(int, caddr_t *);
extern void	nl7c_nca_init(void);

/*
 * nl7c_addr_t - a singly linked grounded list, pointed to by *nl7caddrs,
 * constructed at init time by parsing "/etc/nca/ncaport.conf".
 *
 * This list is searched at bind(3SOCKET) time when an application doesn't
 * explicitly set AF_NCA but instead uses AF_INET, if a match is found then
 * the underlying socket is marked sti_nl7c_flags NL7C_ENABLED.
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

	struct sonode	*listener;	/* listen()er's sonode */
	boolean_t	temp;		/* temporary addr via add_addr() ? */
} nl7c_addr_t;

nl7c_addr_t	*nl7caddrs = NULL;

/*
 * Called for an NL7C_ENABLED listen()er socket for the nl7c_addr_t
 * previously returned by nl7c_lookup_addr().
 */

void
nl7c_listener_addr(void *arg, struct sonode *so)
{
	nl7c_addr_t		*p = (nl7c_addr_t *)arg;

	if (p->listener == NULL)
		p->listener = so;
	SOTOTPI(so)->sti_nl7c_addr = arg;
}

struct sonode *
nl7c_addr2portso(void *arg)
{
	nl7c_addr_t		*p = (nl7c_addr_t *)arg;

	return (p->listener);
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
		alloced = B_TRUE;
	} else
		alloced = B_FALSE;

	new->family = sap->sa_family;
	new->port = v4p->sin_port;
	new->addr.v4 = v4p->sin_addr.s_addr;
	new->temp = B_TRUE;

	if (alloced) {
		old = nl7caddrs;
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

	while (p) {
		if (p->listener == so) {
			if (p->temp)
				p->port = (uint16_t)-1;
			p->listener = NULL;
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
	struct sonode	*so;
	char		addr[32];

	(void) mi_mpprintf(mp, "Door  Up-Call-Queue IPaddr:TCPport Listenning");
	while (p) {
		if (p->port != (uint16_t)-1) {
			/* Don't report freed slots */
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
			so = p->listener;
			(void) mi_mpprintf(mp, "%p  %s:%d  %d",
			    so ? (void *)strvp2wq(SOTOV(so)) : NULL,
			    addr, port, p->listener ? 1 : 0);
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
 * ncaport.conf file line is:
 *
 *	ncaport=IPaddr/Port[/Proxy]
 *
 * Where:
 *
 * ncaport - the only token recognized.
 *
 *  IPaddr - an IPv4 numeric dot address (e.g. 192.168.84.71) or '*' for
 *           INADDR_ANY, or an IPv6 numeric address or "::" for IN6ADDR_ANY.
 *
 *       / - IPaddr/Port separator.
 *
 *    Port - a TCP decimal port number.
 *
 * Note, all other lines will be ignored.
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
				addrp->port = ntohs(atou(string));

				/* End of parse, add entry */
				nl7c_addr_add(addrp);
				addrp = NULL;
				parse = EOL;
			} else {
				/* Unrecognized char, skip */
				parse = EOL;
				break;
			}
			if (c == '\n') {
				/* Found EOL, start on next line */
				parse = START;
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
	if (addrp != NULL) {
		kmem_free(addrp, sizeof (*addrp));
	}
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
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
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
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
					/* List delim or filename separator */
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
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
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
	/*
	 * Open, read, and parse the NCA logd configuration file,
	 * then initialize URI processing and NCA compat.
	 */
	ncalogdconf_read();
	nl7c_uri_init();
	nl7c_nca_init();
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
 * 3) A request which can't be processed.
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
volatile uint64_t nl7c_proc_nodata = 0;
volatile uint64_t nl7c_proc_parse = 0;

boolean_t
nl7c_process(struct sonode *so, boolean_t nonblocking)
{
	vnode_t	*vp = SOTOV(so);
	sotpi_info_t *sti = SOTOTPI(so);
	mblk_t	*rmp = sti->sti_nl7c_rcv_mp;
	clock_t	timout;
	rval_t	rval;
	uchar_t pri;
	int 	pflag;
	int	error;
	boolean_t more;
	boolean_t ret = B_FALSE;
	boolean_t first = B_TRUE;
	boolean_t pollin = (sti->sti_nl7c_flags & NL7C_POLLIN);

	nl7c_proc_cnt++;

	/* Caller has so_lock enter()ed */
	error = so_lock_read_intr(so, nonblocking ? FNDELAY|FNONBLOCK : 0);
	if (error) {
		/* Couldn't read lock, pass on this socket */
		sti->sti_nl7c_flags = 0;
		nl7c_proc_noLRI++;
		return (B_FALSE);
	}
	/* Exit so_lock for now, will be reenter()ed prior to return */
	mutex_exit(&so->so_lock);

	if (pollin)
		sti->sti_nl7c_flags &= ~NL7C_POLLIN;

	/* Initialize some kstrgetmsg() constants */
	pflag = MSG_ANY | MSG_DELAYERROR;
	pri = 0;
	if (nonblocking) {
		/* Non blocking so don't block */
		timout = 0;
	} else if (sti->sti_nl7c_flags & NL7C_SOPERSIST) {
		/* 2nd or more time(s) here so use keep-alive value */
		timout = nca_http_keep_alive_timeout;
	} else {
		/* 1st time here so use connection value */
		timout = nca_http_timeout;
	}

	rval.r_vals = 0;
	do {
		/*
		 * First time through, if no data left over from a previous
		 * kstrgetmsg() then try to get some, else just process it.
		 *
		 * Thereafter, rmp = NULL after the successful kstrgetmsg()
		 * so try to get some new data and append to list (i.e. until
		 * enough fragments are collected for a successful parse).
		 */
		if (rmp == NULL) {

			error = kstrgetmsg(vp, &rmp, NULL, &pri, &pflag,
			    timout, &rval);
			if (error) {
				if (error == ETIME) {
					/* Timeout */
					nl7c_proc_ETIME++;
				} else if (error != EWOULDBLOCK) {
					/* Error of some sort */
					nl7c_proc_error++;
					rval.r_v.r_v2 = error;
					sti->sti_nl7c_flags = 0;
					break;
				}
				error = 0;
			}
			if (rmp != NULL) {
				mblk_t	*mp = sti->sti_nl7c_rcv_mp;


				if (mp == NULL) {
					/* Just new data, common case */
					sti->sti_nl7c_rcv_mp = rmp;
				} else {
					/* Add new data to tail */
					while (mp->b_cont != NULL)
						mp = mp->b_cont;
					mp->b_cont = rmp;
				}
			}
			if (sti->sti_nl7c_rcv_mp == NULL) {
				/* No data */
				nl7c_proc_nodata++;
				if (timout > 0 || (first && pollin)) {
					/* Expected data so EOF */
					ret = B_TRUE;
				} else if (sti->sti_nl7c_flags &
				    NL7C_SOPERSIST) {
					/* Persistent so just checking */
					ret = B_FALSE;
				}
				break;
			}
			rmp = NULL;
		}
		first = B_FALSE;
	again:
		nl7c_proc_parse++;

		more = nl7c_parse(so, nonblocking, &ret);

		if (ret == B_TRUE && (sti->sti_nl7c_flags & NL7C_SOPERSIST)) {
			/*
			 * Parse complete, cache hit, response on its way,
			 * socket is persistent so try to process the next
			 * request.
			 */
			if (nonblocking) {
				ret = B_FALSE;
				break;
			}
			if (sti->sti_nl7c_rcv_mp) {
				/* More recv-side data, pipelined */
				nl7c_proc_again++;
				goto again;
			}
			nl7c_proc_next++;
			if (nonblocking)
				timout = 0;
			else
				timout = nca_http_keep_alive_timeout;

			more = B_TRUE;
		}

	} while (more);

	if (sti->sti_nl7c_rcv_mp) {
		nl7c_proc_rcv++;
	}
	sti->sti_nl7c_rcv_rval = rval.r_vals;
	/* Renter so_lock, caller called with it enter()ed */
	mutex_enter(&so->so_lock);
	so_unlock_read(so);

	return (ret);
}
