/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sbin/routed/parms.c,v 1.9 2000/08/11 08:24:38 sheldonh Exp $
 */

#include "defs.h"
#include "pathnames.h"
#include <sys/stat.h>
#include <arpa/inet.h>
#include <ctype.h>

#define	PARMS_MAXLINELEN	500
static struct parm *parms;
struct intnet *intnets;
struct r1net *r1nets;
struct tgate *tgates;

static void addroutefordefault(in_addr_t, in_addr_t, in_addr_t,
    uint32_t, uint16_t);

/* use configured parameters */
void
get_parms(struct interface *ifp)
{
	static boolean_t warned_auth_in, warned_auth_out;
	struct parm *parmp;
	int i, num_passwds = 0;

	if (ifp == NULL)
		return;

	/* get all relevant parameters */
	for (parmp = parms; parmp != NULL; parmp = parmp->parm_next) {
		if (parmp->parm_name[0] == '\0' ||
		    strcmp(ifp->int_name, parmp->parm_name) == 0 ||
		    (parmp->parm_name[0] == '\n' &&
		    on_net(ifp->int_addr,
		    parmp->parm_net, parmp->parm_mask))) {

			/*
			 * This group of parameters is relevant,
			 * so get its settings
			 */
			ifp->int_state |= parmp->parm_int_state;
			for (i = 0; i < MAX_AUTH_KEYS; i++) {
				if (parmp->parm_auth[i].type == RIP_AUTH_NONE ||
				    num_passwds >= MAX_AUTH_KEYS)
					break;
				ifp->int_auth[num_passwds++] =
				    parmp->parm_auth[i];
			}
			if (parmp->parm_rdisc_pref != 0)
				ifp->int_rdisc_pref = parmp->parm_rdisc_pref;
			if (parmp->parm_rdisc_int != 0)
				ifp->int_rdisc_int = parmp->parm_rdisc_int;
			if (parmp->parm_d_metric != 0)
				ifp->int_d_metric = parmp->parm_d_metric;
			if (parmp->parm_ripout_addr != 0)
				ifp->int_ripout_addr = parmp->parm_ripout_addr;
		}
	}

	/*
	 * Set general defaults.
	 *
	 * Default poor-man's router discovery to a metric that will
	 * be heard by old versions of `routed`.  They ignored received
	 * routes with metric 15.
	 */
	if ((ifp->int_state & IS_PM_RDISC) && ifp->int_d_metric == 0)
		ifp->int_d_metric = FAKE_METRIC;

	if (ifp->int_rdisc_int == 0)
		ifp->int_rdisc_int = DEF_MAXADVERTISEINTERVAL;

	if (!(ifp->int_if_flags & IFF_MULTICAST) &&
	    !(ifp->int_state & IS_REMOTE))
		ifp->int_state |= IS_BCAST_RDISC;

	if (ifp->int_if_flags & IFF_POINTOPOINT) {
		ifp->int_state |= IS_BCAST_RDISC;
		/*
		 * By default, point-to-point links should be passive
		 * about router-discovery for the sake of demand-dialing.
		 */
		if (!(ifp->int_state & GROUP_IS_SOL_OUT))
			ifp->int_state |= IS_NO_SOL_OUT;
		if (!(ifp->int_state & GROUP_IS_ADV_OUT))
			ifp->int_state |= IS_NO_ADV_OUT;
	}

	if (0 != (ifp->int_state & (IS_PASSIVE | IS_REMOTE)))
		ifp->int_state |= IS_NO_RDISC;
	if (ifp->int_state & IS_PASSIVE)
		ifp->int_state |= IS_NO_RIP;

	if (!IS_RIP_IN_OFF(ifp->int_state) &&
	    ifp->int_auth[0].type != RIP_AUTH_NONE &&
	    !(ifp->int_state & IS_NO_RIPV1_IN) && !warned_auth_in) {
		writelog(LOG_WARNING, "RIPv1 input via %s"
		    " will be accepted without authentication",
		    ifp->int_name);
		warned_auth_in = _B_TRUE;
	}
	if (!IS_RIP_OUT_OFF(ifp->int_state) &&
	    ifp->int_auth[0].type != RIP_AUTH_NONE &&
	    !(ifp->int_state & IS_NO_RIPV1_OUT)) {
		if (!warned_auth_out) {
			writelog(LOG_WARNING, "RIPv1 output via %s"
			    " will be sent without authentication",
			    ifp->int_name);
			warned_auth_out = _B_TRUE;
		}
	}

	/*
	 * If not overriden by the rip_neighbor option, set the
	 * default address to which RIP packets will be sent on
	 * this interface.
	 */
	if (ifp->int_ripout_addr == 0) {
		if (ifp->int_state & IS_REMOTE) {
			/*
			 * By definition we always send RIP packets to
			 * the address assigned to a remote interface.
			 */
			ifp->int_ripout_addr = ifp->int_addr;
		} else if ((ifp->int_state & IS_NO_RIPV1_OUT) &&
		    (ifp->int_if_flags & IFF_MULTICAST) &&
		    !(ifp->int_state & IS_NO_RIP_MCAST)) {
			/*
			 * If the interface is being used for RIPv2
			 * and it supports multicast, and if the user
			 * has not explicitely turned off multicast
			 * RIP output, send to the all RIP routers
			 * multicast address.
			 */
			ifp->int_ripout_addr = htonl(INADDR_RIP_GROUP);
		} else if (ifp->int_if_flags & IFF_POINTOPOINT) {
			/*
			 * For point-to-point interfaces which don't
			 * fall into the two categories above, just
			 * send to the destination address of the
			 * interface.
			 */
			ifp->int_ripout_addr = ifp->int_dstaddr;
		} else {
			/* Otherwise, use the broadcast address. */
			ifp->int_ripout_addr = ifp->int_brdaddr;
		}
	}
}


/*
 * Read a list of gateways from /etc/gateways and add them to our tables.
 *
 * This file contains a list of "remote" gateways.  That is usually
 * a gateway which we cannot immediately determine if it is present or
 * not as we can do for those provided by directly connected hardware.
 *
 * If a gateway is marked "passive" in the file, then we assume it
 * does not understand RIP and assume it is always present.  Those
 * not marked passive are treated as if they were directly connected
 * and assumed to be broken if they do not send us advertisements.
 * All remote interfaces are added to our list, and those not marked
 * passive are sent routing updates.
 *
 * A passive interface can also be local, hardware interface exempt
 * from RIP.
 */
void
gwkludge(void)
{
#define	STR2(x)	#x
#define	STR(x)	STR2(x)

#define	NETHOST_LEN	4
#define	DNAME_LEN	MAXHOSTNAMELEN
#define	GNAME_LEN	MAXHOSTNAMELEN
#define	QUAL_LEN	8

	FILE *fp;
	char *p, *lptr;
	const char *cp;
	char lbuf[PARMS_MAXLINELEN], net_host[NETHOST_LEN + 1];
	char dname[MAXHOSTNAMELEN + 1];
	char gname[MAXHOSTNAMELEN + 1], qual[QUAL_LEN +1];
	struct interface *ifp;
	uint32_t dst, netmask, gate;
	int n;
	uint32_t lnum;
	struct stat sb;
	uint32_t state, metric;
	boolean_t default_dst;


	fp = fopen(PATH_GATEWAYS, "r");
	if (fp == NULL)
		return;

	if (0 > fstat(fileno(fp), &sb)) {
		msglog("fstat() failed: %s for  "PATH_GATEWAYS,
		    rip_strerror(errno));
		(void) fclose(fp);
		return;
	}

	for (lnum = 1; ; lnum++) {
		if (NULL == fgets(lbuf, sizeof (lbuf), fp))
			break;

		/* Eliminate the /n character at the end of the lbuf */
		if (strlen(lbuf) > 0)
			lbuf[strlen(lbuf) - 1] = '\0';

		/* Move lptr to the first non-space character */
		for (lptr = lbuf; isspace(*lptr); lptr++)
			;

		if (*lptr == '#' || *lptr == '\0')
			continue;

		/* Move p to the end of the line */
		p = lptr + strlen(lptr) - 1;

		/* Skip all trailing spaces except escaped space */
		while (p > lptr && (isspace(*p) && *(p-1) != '\\'))
			p--;

		/* truncate the line to remove trailing spaces */
		*++p = '\0';

		/* notice newfangled parameter lines */
		if (strncasecmp("net", lptr, 3) != 0 &&
		    strncasecmp("host", lptr, 4) != 0) {
			cp = parse_parms(lptr, (sb.st_uid == 0 &&
			    !(sb.st_mode&(S_IRWXG|S_IRWXO))));
			if (cp != 0)
				msglog("%s in line %u of "PATH_GATEWAYS,
				    cp, lnum);
			continue;
		}

		/*
		 * Processes lines of the follwoing format:
		 * net|host <name>[/mask] gateway <Gname> metric <value>
		 * passive|active|extern
		 */
		qual[0] = '\0';
		n = sscanf(lptr, "%"STR(NETHOST_LEN)"s %"STR(DNAME_LEN)
		    "[^ \t] gateway %"STR(GNAME_LEN)"[^ / \t] metric %u %"
		    STR(QUAL_LEN)"s\n", net_host, dname, gname, &metric, qual);
		if (n != 4 && n != 5) {
			msglog("bad "PATH_GATEWAYS" entry \"%s\"; %d values",
			    lptr, n);
			continue;
		}
		if (metric >= HOPCNT_INFINITY) {
			msglog("bad metric in "PATH_GATEWAYS" entry \"%s\"",
			    lptr);
			continue;
		}
		default_dst = _B_FALSE;
		if (strcasecmp(net_host, "host") == 0) {
			if (!gethost(dname, &dst)) {
				msglog("bad host \"%s\" in "PATH_GATEWAYS
				    " entry \"%s\"", dname, lptr);
				continue;
			}
			netmask = HOST_MASK;
		} else if (strcasecmp(net_host, "net") == 0) {
			if (!getnet(dname, &dst, &netmask)) {
				msglog("bad net \"%s\" in "PATH_GATEWAYS
				    " entry \"%s\"", dname, lptr);
				continue;
			}
			default_dst = (dst == RIP_DEFAULT);
			dst = htonl(dst); /* make network # into IP address */
		} else {
			msglog("bad \"%s\" in "PATH_GATEWAYS
			    " entry \"%s\"", net_host, lptr);
			continue;
		}

		if (!gethost(gname, &gate)) {
			msglog("bad gateway \"%s\" in "PATH_GATEWAYS
			    " entry \"%s\"", gname, lptr);
			continue;
		}

		if (strcasecmp(qual, "passive") == 0) {
			/*
			 * Passive entries are not placed in our tables,
			 * only the kernel's, so we don't copy all of the
			 * external routing information within a net.
			 * Internal machines should use the default
			 * route to a suitable gateway (like us).
			 */
			state = IS_REMOTE | IS_PASSIVE;
			if (metric == 0)
				metric = 1;

		} else if (strcasecmp(qual, "external") == 0) {
			/*
			 * External entries are handled by other means
			 * such as EGP, and are placed only in the daemon
			 * tables to prevent overriding them with something
			 * else.
			 */
			(void) strlcpy(qual, "external", sizeof (qual));
			state = IS_REMOTE | IS_PASSIVE | IS_EXTERNAL;
			if (metric == 0)
				metric = 1;

		} else if (strcasecmp(qual, "active") == 0 ||
		    qual[0] == '\0') {

			if (default_dst) {
				msglog("bad net \"%s\" in "PATH_GATEWAYS
				    " entry \"%s\"-- cannot be default",
				    dname, lptr);
				continue;
			}

			if (metric != 0) {
				/*
				 * Entries that are neither "passive" nor
				 * "external" are "remote" and must behave
				 * like physical interfaces.  If they are not
				 * heard from regularly, they are deleted.
				 */
				state = IS_REMOTE;
			} else {
				/*
				 * "remote" entries with a metric of 0
				 * are aliases for our own interfaces
				 */
				state = IS_REMOTE | IS_PASSIVE | IS_ALIAS;
			}

		} else {
			msglog("bad "PATH_GATEWAYS" entry \"%s\";"
			    " unknown type %s", lptr, qual);
			continue;
		}

		if (0 != (state & (IS_PASSIVE | IS_REMOTE)))
			state |= IS_NO_RDISC;
		if (state & IS_PASSIVE)
			state |= IS_NO_RIP;


		if (default_dst) {
			addroutefordefault(dst, gate, netmask, metric,
			    ((state & IS_EXTERNAL)? RTS_EXTERNAL : 0));
			continue;
		}

		ifp = check_dup(NULL, gate, dst, netmask, 0, _B_FALSE);
		if (ifp != NULL) {
			msglog("duplicate "PATH_GATEWAYS" entry \"%s\"", lptr);
			continue;
		}

		ifp = rtmalloc(sizeof (*ifp), "gwkludge()");
		(void) memset(ifp, 0, sizeof (*ifp));

		ifp->int_state = state;
		if (netmask == HOST_MASK)
			ifp->int_if_flags = IFF_POINTOPOINT | IFF_UP;
		else
			ifp->int_if_flags = IFF_UP;
		ifp->int_act_time = NEVER;
		ifp->int_addr = gate;
		ifp->int_dstaddr = dst;
		ifp->int_mask = netmask;
		ifp->int_ripv1_mask = netmask;
		ifp->int_std_mask = std_mask(gate);
		ifp->int_net = ntohl(dst);
		ifp->int_std_net = ifp->int_net & ifp->int_std_mask;
		ifp->int_std_addr = htonl(ifp->int_std_net);
		ifp->int_metric = metric;
		if (!(state & IS_EXTERNAL) &&
		    ifp->int_mask != ifp->int_std_mask)
			ifp->int_state |= IS_SUBNET;
		(void) snprintf(ifp->int_name, sizeof (ifp->int_name),
		    "remote(%s)", gname);

		if_link(ifp, 0);
	}

	(void) fclose(fp);

	/*
	 * After all of the parameter lines have been read,
	 * apply them to any remote interfaces.
	 */
	for (ifp = ifnet; NULL != ifp; ifp = ifp->int_next) {
		get_parms(ifp);

		tot_interfaces++;
		if (!IS_RIP_OFF(ifp->int_state))
			rip_interfaces++;
		if (!IS_RIP_OUT_OFF(ifp->int_state))
			ripout_interfaces++;

		trace_if("Add", ifp);
	}

}

/* Parse password timestamp */
static char *
parse_ts(time_t *tp,
    char **valp,
    char *val0,
    char *delimp,
    char *buf,
    uint_t bufsize)
{
	struct tm tm;

	if (0 > parse_quote(valp, "| ,", delimp, buf, bufsize) ||
	    buf[bufsize-1] != '\0' || buf[bufsize-2] != '\0') {
		(void) snprintf(buf, bufsize, "bad timestamp %.25s", val0);
		return (buf);
	}
	(void) strlcat(buf, "\n", bufsize);
	(void) memset(&tm, 0, sizeof (tm));
	if (5 != sscanf(buf, "%u/%u/%u@%u:%u\n",
	    (unsigned *)&tm.tm_year, (unsigned *)&tm.tm_mon,
	    (unsigned *)&tm.tm_mday, (unsigned *)&tm.tm_hour,
	    (unsigned *)&tm.tm_min) ||
	    tm.tm_mon < 1 || tm.tm_mon > 12 ||
	    tm.tm_mday < 1 || tm.tm_mday > 31) {
		(void) snprintf(buf, bufsize, "bad timestamp %.25s", val0);
		return (buf);
	}
	tm.tm_mon--;
	/* assume small years are in the 3rd millenium */
	if (tm.tm_year <= 37)
		tm.tm_year += 100;

	if (tm.tm_year >= 1900)
		tm.tm_year -= 1900;

	if ((*tp = mktime(&tm)) == -1) {
		(void) snprintf(buf, bufsize, "bad timestamp %.25s", val0);
		return (buf);
	}

	return (NULL);
}


/*
 * Get a password, key ID, and expiration date in the format
 *	passwd|keyID|year/mon/day@hour:min|year/mon/day@hour:min
 * returns NULL or error message
 */
static const char *
get_passwd(char *tgt,
    char *val,
    struct parm *parmp,
    uint16_t type,
    boolean_t safe)			/* 1=from secure file */
{
	static char buf[80];
	char *val0, *p, delim;
	struct auth k, *ap, *ap2;
	int i;
	ulong_t l;


	if (!safe)
		return ("ignore unsafe password");

	for (ap = parmp->parm_auth, i = 0; ap->type != RIP_AUTH_NONE;
	    i++, ap++) {
		if (i >= MAX_AUTH_KEYS)
			return ("too many passwords");
	}

	(void) memset(&k, 0, sizeof (k));
	k.type = type;
	k.end = -1-DAY;

	val0 = val;
	if (0 > parse_quote(&val, "| ,", &delim,
	    (char *)k.key, sizeof (k.key)))
		return (tgt);

	if (delim != '|') {
		if (type == RIP_AUTH_MD5)
			return ("missing Keyid");
	} else {
		val0 = ++val;
		buf[sizeof (buf)-1] = '\0';
		if (0 > parse_quote(&val, "| ,", &delim, buf,
		    sizeof (buf)) ||
		    buf[sizeof (buf) - 1] != '\0' ||
		    (l = strtoul(buf, &p, 0)) > 255 ||
		    p == buf || *p != '\0') {
			(void) snprintf(buf, sizeof (buf),
			    "bad KeyID \"%.20s\"", val0);
			return (buf);
		}
		for (ap2 = parmp->parm_auth; ap2 < ap; ap2++) {
			if (ap2->keyid == l) {
				(void) snprintf(buf, sizeof (buf),
				    "duplicate KeyID \"%.20s\"",
				    val0);
				return (buf);
			}
		}
		k.keyid = (int)l;

		if (delim == '|') {
			val0 = ++val;
			if (NULL != (p = parse_ts(&k.start, &val, val0, &delim,
			    buf, sizeof (buf))))
				return (p);
			if (delim != '|')
				return ("missing second timestamp");
			val0 = ++val;
			if (NULL != (p = parse_ts(&k.end, &val, val0, &delim,
			    buf, sizeof (buf))))
				return (p);
			if ((ulong_t)k.start > (ulong_t)k.end) {
				(void) snprintf(buf, sizeof (buf),
				    "out of order timestamp %.30s", val0);
				return (buf);
			}
		}
	}
	if (delim != '\0')
		return (tgt);

	(void) memmove(ap, &k, sizeof (*ap));
	return (NULL);
}


static const char *
bad_str(const char *estr)
{
	static char buf[100+8];

	(void) snprintf(buf, sizeof (buf), "bad \"%.100s\"", estr);
	return (buf);
}


/*
 * Parse a set of parameters for an interface.
 * returns NULL or error message
 */
const char *
parse_parms(char *line,
    boolean_t safe)			/* 1=from secure file */
{
#define	PARS(str) (strcasecmp(tgt, str) == 0)
#define	PARSEQ(str) (strncasecmp(tgt, str"=", sizeof (str)) == 0)
/*
 * This macro checks for conflicting configurations options
 * For eg  one can set either the IS_NO_SOL_OUT flag bit or the IS_SOL_OUT flag
 * bit, but not both.
 */
#define	CKF(g, b) {if (0 != (parm.parm_int_state & ((g) & ~(b)))) break; \
	parm.parm_int_state |= (b); }
	struct parm parm;
	struct intnet *intnetp;
	struct r1net *r1netp;
	struct tgate *tg;
	uint32_t addr, mask;
	char delim, *val0 = 0, *tgt, *val, *p;
	const char *msg;
	char buf[PARMS_MAXLINELEN], buf2[PARMS_MAXLINELEN];
	int i;


	/* "subnet=x.y.z.u/mask[,metric]" must be alone on the line */
	if (strncasecmp(line, "subnet=", sizeof ("subnet=") - 1) == 0 &&
	    *(val = &line[sizeof ("subnet=") -1 ]) != '\0') {
		if (0 > parse_quote(&val, ",", &delim, buf, sizeof (buf)))
			return (bad_str(line));
		intnetp = rtmalloc(sizeof (*intnetp),
		    "parse_parms subnet");
		intnetp->intnet_metric = 1;
		if (delim == ',') {
			intnetp->intnet_metric = (int)strtol(val+1, &p, 0);
			if (*p != '\0' || intnetp->intnet_metric <= 0 ||
			    val+1 == p ||
			    intnetp->intnet_metric >= HOPCNT_INFINITY) {
				free(intnetp);
				return (bad_str(line));
			}
		}
		if (!getnet(buf, &intnetp->intnet_addr,
		    &intnetp->intnet_mask) ||
		    intnetp->intnet_mask == HOST_MASK ||
		    intnetp->intnet_addr == RIP_DEFAULT) {
			free(intnetp);
			return (bad_str(line));
		}
		intnetp->intnet_addr = htonl(intnetp->intnet_addr);
		intnetp->intnet_next = intnets;
		intnets = intnetp;
		return (NULL);
	}

	/*
	 * "ripv1_mask=x.y.z.u/mask1,mask2" must be alone on the line.
	 * This requires that x.y.z.u/mask1 be considered a subnet of
	 * x.y.z.u/mask2, as if x.y.z.u/mask2 were a class-full network.
	 */
	if (!strncasecmp(line, "ripv1_mask=", sizeof ("ripv1_mask=") - 1) &&
	    *(val = &line[sizeof ("ripv1_mask=")-1]) != '\0') {
		if (0 > parse_quote(&val, ",", &delim, buf, sizeof (buf)) ||
		    delim == '\0')
			return (bad_str(line));
		if ((i = (int)strtol(val+1, &p, 0)) <= 0 || i > 32 ||
		    *p != '\0')
			return (bad_str(line));
		r1netp = rtmalloc(sizeof (*r1netp), "parse_parms ripv1_mask");
		r1netp->r1net_mask = HOST_MASK << (32-i);
		if (!getnet(buf, &r1netp->r1net_net, &r1netp->r1net_match) ||
		    r1netp->r1net_net == RIP_DEFAULT ||
		    r1netp->r1net_mask > r1netp->r1net_match) {
			free(r1netp);
			return (bad_str(line));
		}
		r1netp->r1net_next = r1nets;
		r1nets = r1netp;
		return (NULL);
	}

	(void) memset(&parm, 0, sizeof (parm));
	/*
	 * Support of the following for Solaris backward compatibility
	 * norip <ifname>
	 * noripin <ifname>
	 * noripout <ifname>
	 */
	if (strncasecmp("norip", line, 5) == 0) {
		char cmd[64], ifname[64];
		int n;

		n = sscanf(line, "%63s %63s\n", cmd, ifname);
		if (n != 2) {
			/* Not enough parameters */
			return (bad_str(line));
		}

		/*
		 * Get the interface name and turn on the appropriate
		 * interface flags
		 */
		(void) strlcpy(parm.parm_name, ifname, sizeof (parm.parm_name));
		if (strcasecmp("norip", cmd) == 0) {
			parm.parm_int_state |= IS_NO_RIP;
		} else if (strcasecmp("noripin", cmd) == 0) {
			parm.parm_int_state |= IS_NO_RIP_IN;
		} else if (strcasecmp("noripout", cmd) == 0) {
			parm.parm_int_state |= IS_NO_RIP_OUT;
		} else {
			/* Bad command */
			return (bad_str(line));
		}
		/*
		 * Look for duplication, and if new,
		 * link to the rest of the parm entries.
		 */
		return (insert_parm(&parm));
	}

	for (;;) {
		tgt = line + strspn(line, " ,\n\r");
		if (*tgt == '\0' || *tgt == '#')
			break;
		line = tgt+strcspn(tgt, "= #,\n\r");
		delim = *line;
		if (delim == '=') {
			val0 = ++line;
			if (0 > parse_quote(&line, " #,", &delim,
			    buf, sizeof (buf)))
				return (bad_str(tgt));
		}
		if (delim != '\0') {
			for (;;) {
				*line = '\0';
				if (delim == '#')
					break;
				++line;
				if (!isspace(delim) ||
				    ((delim = *line), !isspace(delim)))
					break;
			}
		}

		if (PARSEQ("if")) {
			if (parm.parm_name[0] != '\0' ||
			    strlen(buf) > IF_NAME_LEN)
				return (bad_str(tgt));
			(void) strlcpy(parm.parm_name, buf,
			    sizeof (parm.parm_name));

		} else if (PARSEQ("addr")) {
			/*
			 * This is a bad idea, because the address based
			 * sets of parameters cannot be checked for
			 * consistency with the interface name parameters.
			 * The parm_net stuff is needed to allow several
			 * -F settings.
			 */
			if (!getnet(val0, &addr, &mask) ||
			    parm.parm_name[0] != '\0')
				return (bad_str(tgt));
			parm.parm_net = addr;
			parm.parm_mask = mask;
			parm.parm_name[0] = '\n';

		} else if (PARSEQ("passwd")) {
			/*
			 * since cleartext passwords are so weak allow
			 * them anywhere
			 */
			msg = get_passwd(tgt, val0, &parm, RIP_AUTH_PW, 1);
			if (msg) {
				*val0 = '\0';
				return (bad_str(msg));
			}

		} else if (PARSEQ("md5_passwd")) {
			msg = get_passwd(tgt, val0, &parm, RIP_AUTH_MD5, safe);
			if (msg) {
				*val0 = '\0';
				return (bad_str(msg));
			}

		} else if (PARS("no_ag")) {
			parm.parm_int_state |= (IS_NO_AG | IS_NO_SUPER_AG);

		} else if (PARS("no_host")) {
			parm.parm_int_state |= IS_NO_HOST;

		} else if (PARS("no_super_ag")) {
			parm.parm_int_state |= IS_NO_SUPER_AG;

		} else if (PARS("no_ripv1_in")) {
			parm.parm_int_state |= IS_NO_RIPV1_IN;

		} else if (PARS("no_ripv2_in")) {
			parm.parm_int_state |= IS_NO_RIPV2_IN;

		} else if (PARS("ripv2_out")) {
			if (parm.parm_int_state & IS_NO_RIPV2_OUT)
				return (bad_str(tgt));
			parm.parm_int_state |= IS_NO_RIPV1_OUT;

		} else if (PARS("ripv2")) {
			if ((parm.parm_int_state & IS_NO_RIPV2_OUT) ||
			    (parm.parm_int_state & IS_NO_RIPV2_IN))
				return (bad_str(tgt));
			parm.parm_int_state |= (IS_NO_RIPV1_IN
			    | IS_NO_RIPV1_OUT);

		} else if (PARS("no_rip")) {
			CKF(IS_PM_RDISC, IS_NO_RIP);

		} else if (PARS("no_rip_mcast")) {
			parm.parm_int_state |= IS_NO_RIP_MCAST;

		} else if (PARS("no_rdisc")) {
			CKF((GROUP_IS_SOL_OUT|GROUP_IS_ADV_OUT), IS_NO_RDISC);

		} else if (PARS("no_solicit")) {
			CKF(GROUP_IS_SOL_OUT, IS_NO_SOL_OUT);

		} else if (PARS("send_solicit")) {
			CKF(GROUP_IS_SOL_OUT, IS_SOL_OUT);

		} else if (PARS("no_rdisc_adv")) {
			CKF(GROUP_IS_ADV_OUT, IS_NO_ADV_OUT);

		} else if (PARS("rdisc_adv")) {
			CKF(GROUP_IS_ADV_OUT, IS_ADV_OUT);

		} else if (PARS("bcast_rdisc")) {
			parm.parm_int_state |= IS_BCAST_RDISC;

		} else if (PARS("passive")) {
			CKF((GROUP_IS_SOL_OUT|GROUP_IS_ADV_OUT), IS_NO_RDISC);
			parm.parm_int_state |= IS_NO_RIP | IS_PASSIVE;

		} else if (PARSEQ("rdisc_pref")) {
			if (parm.parm_rdisc_pref != 0 ||
			    (parm.parm_rdisc_pref = (int)strtol(buf, &p, 0),
			    *p != '\0') || (buf == p))
				return (bad_str(tgt));

		} else if (PARS("pm_rdisc")) {
			if (IS_RIP_OUT_OFF(parm.parm_int_state))
				return (bad_str(tgt));
			parm.parm_int_state |= IS_PM_RDISC;

		} else if (PARSEQ("rdisc_interval")) {
			if (parm.parm_rdisc_int != 0 ||
			    (parm.parm_rdisc_int = (int)strtoul(buf, &p, 0),
			    *p != '\0') || (buf == p) ||
			    parm.parm_rdisc_int < MIN_MAXADVERTISEINTERVAL ||
			    parm.parm_rdisc_int > MAX_MAXADVERTISEINTERVAL)
				return (bad_str(tgt));

		} else if (PARSEQ("fake_default")) {
			if (parm.parm_d_metric != 0 ||
			    IS_RIP_OUT_OFF(parm.parm_int_state) ||
			    (parm.parm_d_metric = (int)strtoul(buf, &p, 0),
			    *p != '\0') || (buf == p) ||
			    parm.parm_d_metric > HOPCNT_INFINITY-1)
				return (bad_str(tgt));

		} else if (PARSEQ("trust_gateway")) {
			/* look for trust_gateway=x.y.z|net/mask|...) */
			p = buf;
			if (0 > parse_quote(&p, "|", &delim, buf2,
			    sizeof (buf2)) || !gethost(buf2, &addr))
				return (bad_str(tgt));
			tg = rtmalloc(sizeof (*tg),
			    "parse_parms trust_gateway");
			(void) memset(tg, 0, sizeof (*tg));
			tg->tgate_addr = addr;
			i = 0;
			/* The default is to trust all routes. */
			while (delim == '|') {
				p++;
				if (i >= MAX_TGATE_NETS ||
				    0 > parse_quote(&p, "|", &delim, buf2,
				    sizeof (buf2)) ||
				    !getnet(buf2, &tg->tgate_nets[i].net,
				    &tg->tgate_nets[i].mask) ||
				    tg->tgate_nets[i].net == RIP_DEFAULT ||
				    tg->tgate_nets[i].mask == 0) {
					free(tg);
					return (bad_str(tgt));
				}
				i++;
			}
			tg->tgate_next = tgates;
			tgates = tg;
			parm.parm_int_state |= IS_DISTRUST;

		} else if (PARS("redirect_ok")) {
			parm.parm_int_state |= IS_REDIRECT_OK;

		} else if (PARSEQ("rip_neighbor")) {
			if (parm.parm_name[0] == '\0' ||
			    gethost(buf, &parm.parm_ripout_addr) != 1)
				return (bad_str(tgt));

		} else {
			return (bad_str(tgt));	/* error */
		}
	}

	return (insert_parm(&parm));
#undef PARS
#undef PARSEQ
#undef CKF
}


/*
 * Insert parameter specifications into the parms list.  Returns NULL if
 * successful, or an error message otherwise.
 */
const char *
insert_parm(struct parm *new)
{
	struct parm *parmp, **parmpp;
	int i, num_passwds;

	/* set implicit values */
	if (new->parm_int_state & (IS_NO_ADV_IN|IS_NO_SOL_OUT))
		new->parm_int_state |= IS_NO_ADV_IN|IS_NO_SOL_OUT;

	for (i = num_passwds = 0; i < MAX_AUTH_KEYS; i++) {
		if (new->parm_auth[i].type != RIP_AUTH_NONE)
			num_passwds++;
	}

	/* compare with existing sets of parameters */
	for (parmpp = &parms; (parmp = *parmpp) != 0;
	    parmpp = &parmp->parm_next) {
		if (strcmp(new->parm_name, parmp->parm_name) != 0)
			continue;
		if (!on_net(htonl(parmp->parm_net), new->parm_net,
		    new->parm_mask) &&
		    !on_net(htonl(new->parm_net), parmp->parm_net,
		    parmp->parm_mask))
			continue;

		for (i = 0; i < MAX_AUTH_KEYS; i++) {
			if (parmp->parm_auth[i].type != RIP_AUTH_NONE)
				num_passwds++;
		}
		if (num_passwds > MAX_AUTH_KEYS)
			return ("too many conflicting passwords");

		if ((0 != (new->parm_int_state & GROUP_IS_SOL_OUT) &&
		    0 != (parmp->parm_int_state & GROUP_IS_SOL_OUT) &&
		    0 != ((new->parm_int_state ^ parmp->parm_int_state) &&
		    GROUP_IS_SOL_OUT)) ||
		    (0 != (new->parm_int_state & GROUP_IS_ADV_OUT) &&
		    0 != (parmp->parm_int_state & GROUP_IS_ADV_OUT) &&
		    0 != ((new->parm_int_state ^ parmp->parm_int_state) &&
		    GROUP_IS_ADV_OUT)) ||
		    (new->parm_rdisc_pref != 0 &&
		    parmp->parm_rdisc_pref != 0 &&
		    new->parm_rdisc_pref != parmp->parm_rdisc_pref) ||
		    (new->parm_rdisc_int != 0 &&
		    parmp->parm_rdisc_int != 0 &&
		    new->parm_rdisc_int != parmp->parm_rdisc_int)) {
			return ("conflicting, duplicate router discovery"
			    " parameters");

		}

		if (new->parm_d_metric != 0 && parmp->parm_d_metric != 0 &&
		    new->parm_d_metric != parmp->parm_d_metric) {
			return ("conflicting, duplicate poor man's router"
			    " discovery or fake default metric");
		}
	}

	/*
	 * link new entry on the list so that when the entries are scanned,
	 * they affect the result in the order the operator specified.
	 */
	parmp = rtmalloc(sizeof (*parmp), "insert_parm");
	(void) memcpy(parmp, new, sizeof (*parmp));
	*parmpp = parmp;

	return (NULL);
}

int					/* 0=bad */
gethost(char *name, in_addr_t *addrp)
{
	struct hostent *hp;
	struct in_addr in;


	/*
	 * Try for a number first.  This avoids hitting the name
	 * server which might be sick because routing is.
	 */
	if ((in.s_addr = inet_addr(name)) != (in_addr_t)-1) {
		/*
		 * get a good number, but check that it makes some
		 * sense.
		 */
		if ((ntohl(in.s_addr) >> 24) == 0 ||
		    (ntohl(in.s_addr) >> 24) == 0xff)
			return (0);
		*addrp = in.s_addr;
		return (1);
	}

	hp = gethostbyname(name);
	if (hp != NULL) {
		(void) memcpy(addrp, hp->h_addr, sizeof (*addrp));
		return (1);
	}

	return (0);
}


static void
addroutefordefault(in_addr_t dst, in_addr_t gate, in_addr_t mask,
    uint32_t metric, uint16_t rts_flags)
{
	struct rt_spare new;
	struct interface *ifp;
	uint16_t rt_newstate = RS_STATIC;


	ifp = iflookup(gate);
	if (ifp == NULL) {
		msglog("unreachable gateway %s in "PATH_GATEWAYS,
		    naddr_ntoa(gate));
		return;
	}

	trace_misc("addroutefordefault: found interface %s", ifp->int_name);

	(void) memset(&new, 0, sizeof (new));
	new.rts_ifp = ifp;
	new.rts_router = gate;
	new.rts_gate = gate;
	new.rts_metric = metric;
	new.rts_time = now.tv_sec;
	new.rts_flags = rts_flags;
	new.rts_origin = RO_FILE;

	input_route(dst, mask, &new, NULL, rt_newstate);
}
