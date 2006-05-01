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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <sys/resource.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/stropts.h>
#include <netinet/dhcp.h>
#include <dhcp_impl.h>
#include <synch.h>
#include <netdb.h>
#include <locale.h>
#include <mtmalloc.h>
#include <tnf/probe.h>
#include <libinetutil.h>

struct client {
	thread_t	id;
	PKT_LIST	*pktlistp;
	cond_t		cv;
	cond_t		acv;
	mutex_t		mtx;
	int		proto;
	uchar_t		chaddr[20];
	char		chost[40];
	int		hlen;
	uint_t		xid;
	int		flags;
	time_t		ltime;
	int		state;
};

#define	CLIENT_BUSY		0x1
#define	CLIENT_FIRSTTIME	0x2

ushort_t	port_offset = 0;	/* offset to port for multiple server */
int		fast = 0;		/* higher load */
int		bound = 0;		/* only broadcast on given interface */
int		lrecv = 1;		/* only receive on given interface */
static struct in_addr relay;		/* spoof being a relay agent */
static struct sockaddr_in from, relfrom;
static int clients, s, srelay = -1;
static struct client *clientsp;

static PKT request;
static char ifname[IFNAMSIZ];
static int startindex;
static mutex_t go_mtx;
static cond_t go_cv;
static boolean_t time_to_go;
static int release_time = 0;
static int desynch = 1;
static double avg = 0;
static timespec_t avgslp;
static volatile ulong_t tops, otops;
static volatile ulong_t minops[6];
static volatile time_t mintim[6];
static volatile int minind;
long sample_time = 10L;
long nsamples = 2;

static volatile ulong_t ops_outstanding;
static time_t start, ostart;
int verbose = 0;
int dohost = 0;
int randcl = 0;
int randhlen = 0;
int randerr = 0;
int dos = 0;
int dofork = 0;
int printid = 0;

static time_t ltime;
static struct lifreq lifr;

static void corrupt(char *, int);

static void
dhcpmsgtype(uchar_t pkt, char *buf)
{
	char	*p;

	switch (pkt) {
	case DISCOVER:
		p = "DISCOVER";
		break;
	case OFFER:
		p = "OFFER";
		break;
	case REQUEST:
		p = "REQUEST";
		break;
	case DECLINE:
		p = "DECLINE";
		break;
	case ACK:
		p = "ACK";
		break;
	case NAK:
		p = "NAK";
		break;
	case RELEASE:
		p = "RELEASE";
		break;
	case INFORM:
		p = "INFORM";
		break;
	default:
		p = "UNKNOWN";
		break;
	}

	(void) strcpy(buf, p);
}

static int
closeif(int ms, char *cifname, struct sockaddr_in *myip, thread_t myself)
{
	struct ifreq ifr;
	int error = 0;

	(void) strcpy(ifr.ifr_name, cifname);
	if (ioctl(ms, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
		(void) fprintf(stderr,
		    "Client %04d - can't get interface flags on %s\n", myself,
		    cifname);
		error = 7;
	}
	ifr.ifr_flags &= ~IFF_UP;
	if (ioctl(ms, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
		(void) fprintf(stderr,
		    "Client %04d - can't set interface flags on %s\n", myself,
		    cifname);
		error = 7;
	}
	myip->sin_addr.s_addr = htonl(INADDR_ANY);
	ifr.ifr_addr = *(struct sockaddr *)myip;
	if (ioctl(ms, SIOCSIFADDR, (caddr_t)&ifr)) {
		(void) fprintf(stderr,
		    "Client %04d - Can't unset address on %s\n", myself,
		    cifname);
		error = 8;
	}
	(void) close(ms);
	return (error);
}

static void *
client(void *args)
{
	PKT crequest, *irequestp;
	PKT_LIST *bp = NULL, *wbp, *twbp;
	struct client *mep = (struct client *)args;
	time_t retry_time = 2, lease, sleep_time = 0;
	uchar_t *endp;
	boolean_t	done, config, timeout;
	int nstate, ms = -1;
	DHCP_OPT *optp, *unused_optp;
	timespec_t ts, tr;
	int error = 0;
	thread_t myself = thr_self();
	struct sockaddr_in to, myip, maskip;
	struct in_addr serverip;
	time_t start_time, expired = 0;
	char	cid[BUFSIZ];
	char	cifname[IFNAMSIZ];
	char		host[40];
	char		domain[40];
	char p[30], np[30];
	struct ifreq ifr;
	int moldy;
	int i;
	uint_t cidlen;
	char		*domainp;

forever:
	if (bp) {
		(void) free(bp->pkt);
		(void) free(bp);
		bp = NULL;
	}
	if (!time_to_go) {
		(void) mutex_lock(&mep->mtx);
		mep->flags &= ~CLIENT_BUSY;
		if (mep->flags & CLIENT_FIRSTTIME) {
			mep->flags &= ~CLIENT_FIRSTTIME;
		} else {
			tops++;
			ops_outstanding--;
		}
		if (avg)
			(void) cond_wait(&mep->acv, &mep->mtx);
		mep->flags |= CLIENT_BUSY;
		mep->ltime = time(NULL);
		ops_outstanding++;
		(void) mutex_unlock(&mep->mtx);
	}
	if (desynch)
		(void) sleep((desynch & myself) + 3);	/* desynch clients */
	if (verbose == 1)
		(void) fprintf(stdout, "Client %04d - started.\n", myself);
	start_time = time(NULL);
	(void) sprintf(cifname, "%s:%d", ifname, startindex + myself);

	/* reset client addr each time */
	if (relay.s_addr != INADDR_ANY) {
		to.sin_addr.s_addr = relay.s_addr;
	} else {
		to.sin_addr.s_addr = INADDR_BROADCAST;
	}
	to.sin_port = htons(IPPORT_BOOTPS + port_offset);
	to.sin_family = AF_INET;

	domain[0] = host[0] = NULL;
	if (randcl) {
		/* Further randomize. */
		if (randhlen > 0) {
			mep->hlen = randhlen;
		}

		for (i = 3; i < mep->hlen; i++) {
			mep->chaddr[i] = random() & 0xff;
		}
	}

	(void) memcpy(&crequest, &request, sizeof (request));
	(void) memcpy(crequest.chaddr, mep->chaddr, mep->hlen);
	crequest.hlen = mep->hlen;


	if (mep->proto) {
		mep->state = DISCOVER;
		optp = (DHCP_OPT *) & crequest.options[3];	/* skip TYPE */
		optp->code = CD_CLIENT_ID;
		optp->len = mep->hlen + 1;
		optp->value[0] = 0x01;
		(void) memcpy(&optp->value[1], mep->chaddr, mep->hlen);
		cidlen = sizeof (cid);
		(void) octet_to_hexascii(optp->value, mep->hlen + 1, cid,
		    &cidlen);
		unused_optp = (DHCP_OPT *) & optp->value[mep->hlen + 1];
	} else {
		mep->state = 0;
		cidlen = sizeof (cid);
		(void) octet_to_hexascii(mep->chaddr, mep->hlen, cid, &cidlen);
		unused_optp = (DHCP_OPT *)&crequest.options[3]; /* skip TYPE */
	}

	/* Use global descriptor at first */
	ms = s;

	myip.sin_addr.s_addr = htonl(INADDR_ANY);
	done = B_FALSE;
	config = B_FALSE;
	do {
		timeout = B_FALSE;

		TNF_PROBE_2(client,
			    "client",
			    "client%debug 'in func client'",
			    tnf_ulong, state, mep->state,
			    tnf_string, cid, (char *)cid);

		if (time_to_go) {
			if (mep->state == ACK) {
				mep->state = RELEASE;
				if (verbose == 1)
					(void) fprintf(stderr,
					    "Client %04d - RELEASEing %s\n",
					    myself, inet_ntoa(myip.sin_addr));
				else if (verbose == 2)
					fprintf(stderr, "[%d %s]",
						clientsp[i].id,
						inet_ntoa(myip.sin_addr));
				optp = (DHCP_OPT *) crequest.options;
				(void) memset((char *)unused_optp, 0,
				    (int)((char *)&crequest.options[
				    sizeof (crequest.options)] -
				    (char *)unused_optp));
				optp->value[0] = RELEASE;
			} else {
				done = B_TRUE;
				if (verbose == 1)
					(void) fprintf(stderr,
					    "Client %04d - terminated.\n",
					    myself);
				break;
			}
		} else if (release_time || avg) {
			if (mep->state == ACK) {

				/* lru testing: don't release lease */
				if (randcl & 0x2) {
					done = B_FALSE;
					mep->state = nstate = 0;
					sleep_time = 0;
					if (bp) {
						(void) free(bp->pkt);
						(void) free(bp);
						bp = NULL;
					}
					goto forever;
				}
				mep->state = RELEASE;
				if (verbose == 1)
					(void) fprintf(stderr,
					    "Client %04d - RELEASEing %s\n",
					    myself, inet_ntoa(myip.sin_addr));
				else if (verbose == 2)
					fprintf(stderr, "[%d %s]",
						clientsp[i].id,
						inet_ntoa(myip.sin_addr));
				optp = (DHCP_OPT *) crequest.options;
				(void) memset((char *)unused_optp, 0,
				    (int)((char *)&crequest.options[
				    sizeof (crequest.options)] -
				    (char *)unused_optp));
				optp->value[0] = RELEASE;
			}
		}
		if (mep->state == REQUEST && expired < time(NULL)) {
			/* drop back to INIT state. */
			if (verbose == 1)
				(void) fprintf(stderr,
				    "Client %04d - Dropping back to INIT.\n",
				    myself);
			done = B_FALSE;
			mep->state = nstate = 0;
			sleep_time = 0;
			if (bp) {
				(void) free(bp->pkt);
				(void) free(bp);
				bp = NULL;
			}
			goto forever;
		}
		if (mep->state == RELEASE && !time_to_go) {
			(void) mutex_lock(&mep->mtx);
			tops++;
			ops_outstanding--;
			mep->flags &= ~CLIENT_BUSY;
			if (avg)
				(void) cond_wait(&mep->acv, &mep->mtx);
			mep->ltime = time(NULL);
			ops_outstanding++;
			mep->flags |= CLIENT_BUSY;
			(void) mutex_unlock(&mep->mtx);
		}
		/* Send request... */
		crequest.secs = htons((ushort_t)(time(NULL) - start_time));
		crequest.xid = htonl((myself << 2) + mep->xid++);

		/* Randomly corrupt packets of a certain type. */
		if ((randerr & 0xF) == mep->state || (randerr & 0xF) == 0xF) {
			if (randerr & 0x10) {
				/* Randomly corrupt entire request. */
				corrupt((char *)&crequest, sizeof (crequest));
			} else {
				/* Randomly corrupt options. */
				corrupt((char *)&crequest.options[3],
				    sizeof (crequest.options) - 3);
			}
		}

		if (sendto(ms, (char *)&crequest, sizeof (PKT), 0,
		    (struct sockaddr *)&to, sizeof (struct sockaddr)) < 0) {
			perror("Sendto");
			error = 4;
			thr_exit(&error);
		}
		if (mep->state == RELEASE) {
			done = B_TRUE;
			if (!avg) {
				(void) strcpy(ifr.ifr_name, cifname);
				if (ioctl(ms, SIOCGIFFLAGS,
				    (caddr_t)&ifr) < 0) {
					(void) fprintf(stderr, "Client %04d - "
					    "can't get interface flags on %s\n",
					    myself, cifname);
					error = 7;
				}
				ifr.ifr_flags &= ~IFF_UP;
				if (ioctl(ms, SIOCSIFFLAGS,
				    (caddr_t)&ifr) < 0) {
					(void) fprintf(stderr, "Client %04d - "
					"can't set interface flags on %s\n",
					myself, cifname);
					error = 7;
				}
				myip.sin_addr.s_addr = htonl(INADDR_ANY);
				ifr.ifr_addr = *(struct sockaddr *)&myip;
				if (ioctl(ms, SIOCSIFADDR, (caddr_t)&ifr)) {
					(void) fprintf(stderr, "Client %04d - "
					    "Can't unset address on %s\n",
					    myself, cifname);
					error = 8;
				}
				(void) close(ms);
			}
			if (release_time || avg) {
				done = B_FALSE;
				mep->state = nstate = 0;
				sleep_time = 0;
				if (bp) {
					(void) free(bp->pkt);
					(void) free(bp);
					bp = NULL;
				}
				goto forever;
			}
			break;
		}
		/* await reply */
moldy:
		(void) mutex_lock(&mep->mtx);
		ts.tv_sec = time(NULL) + retry_time;
		ts.tv_nsec = 0;

		while (mep->pktlistp == NULL)
			if (cond_timedwait(&mep->cv, &mep->mtx, &ts) == ETIME) {
				timeout = B_TRUE;
				if (retry_time > 64)
					retry_time = 2;
				else if (fast)
					retry_time += 2;
				else
					retry_time *= 2;
				break;
			} else {
				if (time_to_go)
					break;
			}
		(void) mutex_unlock(&mep->mtx);

		if (time_to_go || timeout)
			continue;

		(void) mutex_lock(&mep->mtx);
		moldy = 0;
		if (bp) {
			(void) free(bp->pkt);
			(void) free(bp);
		}
		bp = NULL;
		wbp = mep->pktlistp;
		while (wbp != NULL) {
			irequestp = wbp->pkt;
			if (bp == NULL && irequestp->op == BOOTREPLY &&
			    memcmp(&crequest.xid, &irequestp->xid,
			    sizeof (crequest.xid)) == 0) {
				bp = wbp;
				wbp = wbp->next;
				continue;
			}
			(void) free(wbp->pkt);
			twbp = wbp;
			wbp = wbp->next;
			(void) free(twbp);
			if (verbose == 1)
				(void) fprintf(stderr,
				"Client %04d - Moldy xid\n", myself);
			moldy++;
		}

		mep->pktlistp = NULL;
		(void) mutex_unlock(&mep->mtx);

		if (bp == NULL) {
			if (moldy > 0)
				goto moldy;

			continue;
		}
		irequestp = bp->pkt;

		if (mep->proto) {
			/*
			 * Scan for CD_DHCP_TYPE, CD_SERVER_ID, and
			 * CD_LEASE_TIME if proto.
			 */
			nstate = 0;
			maskip.sin_addr.s_addr = serverip.s_addr = INADDR_ANY;
			maskip.sin_family = AF_INET;
			lease = (time_t)0;
			optp = (DHCP_OPT *) irequestp->options;
			endp = (uchar_t *)irequestp + bp->len;
			host[0] = NULL;
			while ((uchar_t *)optp < (uchar_t *)endp) {
				switch (optp->code) {
				case CD_HOSTNAME:
					(void) strncpy(host,
					    (const char *)optp->value,
					    optp->len);
					host[optp->len] = '\0';
					break;
				case CD_DNSDOMAIN:
					(void) strncpy(domain,
					    (const char *)optp->value,
					    optp->len);
					domain[optp->len] = '\0';
					break;
				case CD_DHCP_TYPE:
					nstate = optp->value[0];
					break;
				case CD_SUBNETMASK:
					(void) memcpy(&maskip.sin_addr,
					    optp->value,
					    sizeof (struct in_addr));
					break;
				case CD_SERVER_ID:
					(void) memcpy(&serverip, optp->value,
					    sizeof (struct in_addr));
					break;
				case CD_LEASE_TIME:
					(void) memcpy(&lease, optp->value,
					    sizeof (time_t));
					lease = htonl(lease);
					break;
				}
				optp = (DHCP_OPT *) & optp->value[optp->len];
			}
			if (mep->state == DISCOVER && nstate == OFFER) {
				mep->state = REQUEST;
				expired = time(NULL) + 60;
				/*
				 * Add in the requested IP address option and
				 * server ID.
				 */
				optp = (DHCP_OPT *) crequest.options;
				optp->value[0] = REQUEST;
				optp = unused_optp; /* step over CD_DHCP_TYPE */
				optp->code = CD_REQUESTED_IP_ADDR;
				optp->len = sizeof (struct in_addr);
				(void) memcpy(optp->value, &irequestp->yiaddr,
				    sizeof (struct in_addr));
				optp = (DHCP_OPT *) & optp->value[
				    sizeof (struct in_addr)];
				optp->code = CD_SERVER_ID;
				optp->len = sizeof (struct in_addr);
				(void) memcpy(optp->value, &serverip,
				    sizeof (struct in_addr));
				optp = (DHCP_OPT *) & optp->value[
				    sizeof (struct in_addr)];
				if (dohost == 0) {
					if (bp) {
						(void) free(bp->pkt);
						(void) free(bp);
						bp = NULL;
					}
					continue;
				}

				if (domain[0] == '\0' && host[0] != '\0' &&
				    (domainp = strchr(host, '.')) != NULL) {
					(void) snprintf(domain, sizeof (domain),
					    "%s", domainp);
				}

				if (dohost & 0x2) {
					cidlen = sizeof (cid);
					(void) octet_to_hexascii(mep->chaddr,
					    mep->hlen, host, &cidlen);

					if (domain[0])
						(void) snprintf(host,
						    sizeof (host), "%s.%s",
						    cid, domain);
					else
						(void) snprintf(host,
						    sizeof (host), "%s", cid);
				}

				optp->code = CD_HOSTNAME;
				optp->len = strlen(host);
				(void) memcpy(optp->value, host, strlen(host));
				optp->value[strlen(host)] = '\0';
				if (randcl && (random() & 0x1)) {
					/* create a random name */
					for (i = 0; i < optp->len &&
						optp->value[i] != '.'; i++)
						if (i & 1)
						    optp->value[i] = '0' +
							(mep->chaddr[i] & 0x7);
						else
						    optp->value[i] = 'a' +
							(mep->chaddr[i] & 0x7);
						strcpy((char *)mep->chost,
						    (const char *)optp->value);
				} else if (randcl && mep->chost[0]) {
					/* use the previous one */
					optp->len = strlen(mep->chost);
					(void) memcpy(optp->value, mep->chost,
					    strlen(mep->chost));
					optp->value[strlen(mep->chost)] = '\0';
				}
				if (bp) {
					(void) free(bp->pkt);
					(void) free(bp);
					bp = NULL;
				}
				continue;
			} else if ((mep->state == REQUEST ||
			    mep->state == ACK) && nstate == ACK) {
				/*
				 * we're bound. defend the lease. Add the
				 * address to our interface. Due to the
				 * service architecture of this program, we
				 * can't unset the broadcast bit..
				 */
				mep->state = ACK;
				nstate = 0;
				retry_time = 2;
				myip.sin_family = AF_INET;
				myip.sin_addr.s_addr = irequestp->yiaddr.s_addr;
				crequest.ciaddr.s_addr = myip.sin_addr.s_addr;
				optp = unused_optp;
				optp->code = CD_LEASE_TIME;
				optp->len = sizeof (time_t);
				(void) memcpy(optp->value, &lease,
				    sizeof (time_t));
				optp = (DHCP_OPT *)
					& optp->value[sizeof (time_t)];
				(void) memset((char *)optp, 0, (int)((char *)
				    &crequest.options[
				    sizeof (crequest.options)] -
				    (char *)optp));
				to.sin_addr.s_addr = serverip.s_addr;

				if (lease == -1) {
					done = B_TRUE;	/* permanent lease */
					sleep_time = 0;
				} else {
					sleep_time = lease / 2;
					lease = time(NULL) + lease;
				}

				if (release_time || avg) {
					sleep_time = release_time;
					done = B_FALSE;
				}
				if (verbose == 1)
					(void) fprintf(stdout,
					    "Client %04d(%s) - DHCP: %s == %s",
					    myself, cid,
					    inet_ntoa(myip.sin_addr),
					    (lease == -1) ? "Forever\n" :
					    ctime(&lease));
				else if (verbose == 2)
					fprintf(stderr, "(%d %s)", mep->id,
						cid);
				if (!config && !avg) {
					/* Add mask and address */
					if ((ms = socket(AF_INET, SOCK_DGRAM,
					    0)) < 0) {
						(void) fprintf(stderr,
						    "Client %04d - can't open "
						    "DGRAM socket.\n", myself);
						error = 7;
						break;
					}
					(void) strcpy(ifr.ifr_name, cifname);
					ifr.ifr_addr =
					    *(struct sockaddr *)&myip;
					/*
					 * XXXX: needed in on81
					 * for initial
					 * interface creation
					 */
					(void) (ioctl(ms, SIOCLIFADDIF,
					    (caddr_t)&ifr));
					(void) strcpy(ifr.ifr_name, cifname);
					ifr.ifr_addr =
					    *(struct sockaddr *)&maskip;
					if (ioctl(ms, SIOCSIFNETMASK,
					    (caddr_t)&ifr)) {
						(void) fprintf(stderr,
						    "Client %04d - Can't set "
						    "netmask: %s on %s\n",
						    myself,
						    inet_ntoa(maskip.sin_addr),
						    cifname);
						error = 7;
						(void) close(ms);
						break;
					}
					if (ioctl(ms, SIOCGIFFLAGS,
					    (caddr_t)&ifr) < 0) {
						(void) fprintf(stderr,
						    "Client %04d - can't get "
						    "interface flags on %s\n",
						    myself, cifname);
						error = 7;
						(void) close(ms);
						break;
					}
					ifr.ifr_flags |= IFF_UP;
					if (ioctl(ms, SIOCSIFFLAGS,
					    (caddr_t)&ifr) < 0) {
						(void) fprintf(stderr,
						    "Client %04d - can't set "
						    "interface flags on %s\n",
						    myself, cifname);
						error = 7;
						(void) close(ms);
						break;
					}
					ifr.ifr_addr =
					    *(struct sockaddr *)&myip;
					if (ioctl(ms, SIOCSIFADDR,
					    (caddr_t)&ifr)) {
						(void) fprintf(stderr,
						    "Client %04d - Can't set "
						    "address on %s\n",
						    myself, cifname);
						error = 8;
						(void) close(ms);
						break;
					}
					config = B_TRUE;
				}
				if (sleep_time != 0) {
					/* Go to sleep for 50% of lease time. */
					tr.tv_sec = time(NULL) + sleep_time;
					if (verbose == 1)
						(void) fprintf(stderr,
						    "Client %04d - sleeping "
						    "until %s", myself,
						    ctime(&tr.tv_sec));
					tr.tv_nsec = 0;
					(void) mutex_lock(&go_mtx);
					while (!time_to_go) {
						if (cond_timedwait(&go_cv,
						    &go_mtx, &tr) == ETIME)
							break;
					}
					(void) mutex_unlock(&go_mtx);
					if (verbose == 1)
						(void) fprintf(stderr,
						    "Client %04d - awake\n",
						    myself);
				}
			} else if (mep->state == ACK && nstate == NAK) {
				/* drop back to INIT state. */
				if (verbose == 1) {
					(void) fprintf(stdout, "Client %04d - "
					    "DHCP: we got NAKed.\n", myself);
					(void) fprintf(stderr, "Client %04d - "
					    "Dropping back to INIT.\n", myself);
				}
				if (!avg)
					(void) closeif(ms, cifname,
						&myip, myself);
				done = B_FALSE;
				mep->state = nstate = 0;
				sleep_time = 0;
				if (bp) {
					(void) free(bp->pkt);
					(void) free(bp);
					bp = NULL;
				}
				goto forever;
			} else {
				dhcpmsgtype(nstate, np);
				dhcpmsgtype(mep->state, p);
				(void) fprintf(stderr, "Client %04d - "
				    "unexpected mesg: %s, when I'm in state: "
				    "%s.\n", myself, np, p);
				error = 9;
				break;
			}
		} else {
			done = B_TRUE;	/* BOOTP is done */
			if (verbose == 1)
				(void) fprintf(stdout,
				    "Client %04d(%s) - BOOTP: %s\n", myself,
				    cid, inet_ntoa(irequestp->yiaddr));
			if (release_time || avg) {
				done = B_FALSE;
				mep->state = nstate = 0;
				sleep_time = 0;
				if (bp) {
					(void) free(bp->pkt);
					(void) free(bp);
					bp = NULL;
				}
				goto forever;
			}
		}
		if (bp) {
			(void) free(bp->pkt);
			(void) free(bp);
			bp = NULL;
		}
	} while (!done);

	if (!done) {
		(void) fprintf(stderr,
		    "Client %04d - %s: configuration failed.\n",
		    myself, (mep->proto) ? "DHCP" : "BOOTP");
	}
	wbp = mep->pktlistp;
	while (wbp != NULL) {
		twbp = wbp->next;
		if (wbp->pkt != NULL)
			(void) free(wbp->pkt);
		(void) free(wbp);
		wbp = twbp;
	}

	thr_exit(&error);
	return (NULL);		/* NOTREACHED */
}

/*
 * Never returns. Just loads client lists.
 */
static void *
service(void *args)
{
	struct client *clientp = (struct client *)args;
	PKT_LIST *bp, *wbp;
	PKT *irequestp;
	int error = 0;
	struct pollfd pfd[2];
	ulong_t *bufp;	/* ulong_t to force alignment */
	int len, i;

	pfd[0].fd = s;
	pfd[0].events = POLLIN | POLLPRI;
	if (relay.s_addr != INADDR_ANY) {
		pfd[1].fd = srelay;
		pfd[1].events = POLLIN | POLLPRI;
	} else {
		pfd[1].fd = -1;
		pfd[1].events = 0;
	}

	for (;;) {
		pfd[0].revents = 0;
		pfd[1].revents = 0;
		if (poll(pfd, (nfds_t)2, INFTIM) < 0) {
			(void) fprintf(stderr, "Service - can't poll...\n");
			error = 5;
			break;
		}
		(void) mutex_lock(&go_mtx);
		if (time_to_go) {
			(void) fprintf(stderr, "Service - exiting...\n");
			error = 0;
			break;
		}
		(void) mutex_unlock(&go_mtx);
		len = BUFSIZ * 2;
		bufp = malloc(len);
		if (pfd[0].revents)
			len = recv(s, (char *)bufp, len, 0);
		else {
			len = recv(srelay, (char *)bufp, len, 0);
		}

		if (len < 0) {
			(void) fprintf(stderr,
			    "Service - can't receive - %s\n", strerror(errno));
			error = 6;
			break;
		} else {
			irequestp = (PKT *) bufp;
			for (i = 0; i < clients; i++) {
				if (memcmp(clientp[i].chaddr, irequestp->chaddr,
				    clientp[i].hlen) == 0) {
					(void) mutex_lock(&clientp[i].mtx);
					bp = malloc(sizeof (PKT_LIST));
					bp->pkt = irequestp;
					bp->len = len;
					if (verbose == 1)
						(void) fprintf(stderr,
						    "Service - received packet "
						    "for thread %04d...\n",
						    clientp[i].id);
					if (clientp[i].pktlistp == NULL) {
						clientp[i].pktlistp = bp;
						bp->prev = NULL;
					} else {
						for (wbp = clientp[i].pktlistp;
						    wbp->next != NULL;
						    wbp = wbp->next)
							/* null */;
						wbp->next = bp;
						bp->prev = wbp;
					}
					bp->next = NULL;
					(void) cond_signal(&clientp[i].cv);
					(void) mutex_unlock(&clientp[i].mtx);
					break;
				}
			}
			if (i >= clients)
				free(bufp);
		}
	}
	thr_exit(&error);
	return (NULL);		/* NOTREACHED */
}

/* ARGSUSED */
static void *
sig_handle(void *arg)
{
	boolean_t leave = B_FALSE;
	int sig;
	sigset_t set;
	char buf[SIG2STR_MAX];
	int old, new, unstarted;
	int i;
	int oldi;
	uint_t cidlen;
	char cid[BUFSIZ];
	int discover, offer, req, decline, ack, nak;
	int release, inform, unknown;
	int kicked;
	ulong_t		minavg;
	time_t		minstime;

	(void) sigfillset(&set);

	if (avg == 0) {
		avgslp.tv_sec = sample_time;
		avgslp.tv_nsec = 0L;
	}
	while (!leave) {
		discover = offer = req = decline = ack = nak = 0;
		release = inform = unknown = 0;
		switch (sig = sigtimedwait(&set, NULL, &avgslp)) {
		case SIGHUP:
		case -1:
			old = time(NULL);
			new = unstarted = 0;
			kicked = 0;
			for (i = 0; i < clients; i++) {
				/* Start next client at avgslp offset */
				if (avg && kicked == 0 &&
				    (clientsp[i].flags &
				    (CLIENT_FIRSTTIME | CLIENT_BUSY)) == 0) {
					(void) mutex_lock(&clientsp[i].mtx);
					(void) cond_signal(&clientsp[i].acv);
					(void) mutex_unlock(&clientsp[i].mtx);
					kicked++;
				}
				switch (clientsp[i].state) {
				case DISCOVER:
					discover++;
					break;
				case OFFER:
					offer++;
					break;
				case REQUEST:
					req++;
					break;
				case DECLINE:
					decline++;
					break;
				case ACK:
					ack++;
					break;
				case NAK:
					nak++;
					break;
				case RELEASE:
					release++;
					break;
				case INFORM:
					inform++;
					break;
				default:
					unknown++;
					break;
				}
				if (clientsp[i].ltime == NULL ||
				    (clientsp[i].flags & CLIENT_BUSY) == 0)
					unstarted++;
				if (clientsp[i].ltime &&
				    clientsp[i].ltime < old) {
					old = clientsp[i].ltime;
					oldi = i;
				}
				if (clientsp[i].ltime &&
				    clientsp[i].ltime > new) {
					new = clientsp[i].ltime;
				}
			}

			if (time(NULL) < ltime + sample_time)
				continue;
			ltime = time(NULL);

			if (start == 0) {
				/* toss initial sample */
				ostart = start = time(NULL);
				otops = tops = 0;
				minind = 0;
			} else {
				minops[minind] = tops - otops;
				mintim[minind] = ostart;
				otops = tops;
				ostart = time(NULL);
				minind = minind + 1 > nsamples - 1 ? 0 :
				    minind + 1;
				minstime = 0;
				minavg = 0;
				for (i = 0; i < nsamples; i++) {
					if (mintim[i])
						minavg += minops[i];
					if (minstime == 0)
						minstime = mintim[i];
					else if (mintim[i] &&
					    mintim[i] < minstime)
						minstime = mintim[i];
				}

				cidlen = sizeof (cid);
				(void) octet_to_hexascii(clientsp[oldi].chaddr,
				clientsp[oldi].hlen, cid, &cidlen);
				fprintf(stderr, "%9.9d: Totops %d Curr %d "
				    "Persec %4.2f (%4.2f) Oldest %d (%d) "
				    "Gap %d Free %d\n", time(NULL), tops,
				    ops_outstanding,
				    (double)tops / (double)(time(NULL) - start),
				    (double)minavg / (double)(time(NULL)
				    - minstime),
				    time(NULL) - old, clientsp[oldi].id, cid,
				    new - old, unstarted);
				fprintf(stderr, "\tdiscov %d off %d req %d "
				    "decl %d ack %d nak %d rel %d inf %d "
				    "free/unknown %d\n", discover, offer, req,
				    decline, ack, nak, release, inform,
				    unknown);
			}
			break;
		case SIGINT:
			/* FALLTHRU */
		case SIGTERM:
			(void) sig2str(sig, buf);
			(void) fprintf(stderr,
			    "Signal: %s received...Exiting\n", buf);
			(void) mutex_lock(&go_mtx);
			time_to_go = B_TRUE;
			(void) cond_broadcast(&go_cv);
			(void) mutex_unlock(&go_mtx);
			for (i = 0; i < clients; i++) {
				(void) mutex_lock(&clientsp[i].mtx);
				(void) cond_signal(&clientsp[i].acv);
				(void) mutex_unlock(&clientsp[i].mtx);
			}
			leave = B_TRUE;
			break;
		default:
			(void) sig2str(sig, buf);
			(void) fprintf(stderr,
			    "Signal: %s received...Ignoring\n", buf);
			leave = B_FALSE;
			break;
		}
	}
	thr_exit((void *) NULL);
	return (NULL);		/* NOTREACHED */
}

int
main(int argc, char *argv[])
{
	boolean_t proto;
	int i, j, threrror = 0, *threrrorp;
	int sockoptbuf = 1;
	register char *endp, *octet;
	thread_t service_id, sig_id;
	sigset_t set;
	uint_t buf;
	int slen;
	socklen_t sslen = sizeof (slen);
	unsigned int ifceno;
	char cifname[IFNAMSIZ];
	struct rlimit rl;

	if (randcl)
		srandom(time(NULL));

	if (dofork) {
		if (fork() != 0)
			exit(0);
	}
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0) {
		(void) fprintf(stderr, "Cannot get open file limit: %s\n",
		    strerror(errno));
	}
	/* handle cases where limit is infinity */
	if (rl.rlim_cur == RLIM_INFINITY) {
		rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY) ?
			OPEN_MAX : rl.rlim_max;
	}
	/* set NOFILE to unlimited */
	rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
		(void) fprintf(stderr, "Cannot set open file limit: %s\n",
		    strerror(errno));
	}
	(void) enable_extended_FILE_stdio(-1, -1);

	if (argc < 5) {
		(void) fprintf(stderr, "%s <interface> <ether_addr> <protocol> "
		    "<clients> [time] [desynch] [avg] [relayaddr]\n", argv[0]);
		return (1);
	}
	(void) strcpy(ifname, argv[1]);
	(void) strcpy(cifname, argv[1]);
	if ((endp = strchr(ifname, ':')) != NULL) {
		*endp = '\0';
		startindex = strtol(endp + 1, 0L, 0L);
	}
	if (strcasecmp(argv[3], "dhcp") == 0)
		proto = B_TRUE;
	else
		proto = B_FALSE;

	clients = atoi(argv[4]);

	if (argc >= 6) {
		release_time = atoi(argv[5]);
	}
	if (argc >= 7)
		desynch = atoi(argv[6]);

	if (argc >= 8) {
		avg = atof(argv[7]);
		if (avg > 0.0) {
			avgslp.tv_sec = avg;
			avgslp.tv_nsec = (avg -
			    (double)((int)avg)) * 1000000000.0;
		} else if (avg < 0.0) {
			avgslp.tv_sec = abs((int)avg);
			avgslp.tv_nsec = (avg + abs((double)((int)avg))) *
			    1000000000.0;
		}
	}
	if (argc >= 9)
		relay.s_addr = inet_addr(argv[8]);

	if (argc >= 10)
		slen = strtol(argv[0], 0L, 0L);
	else
		slen = 1024 * 64;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("Socket");
		return (1);
	}
	(void) setsockopt(s, SOL_SOCKET, SO_SNDBUF, &slen, sslen);
	(void) setsockopt(s, SOL_SOCKET, SO_RCVBUF, &slen, sslen);

	if (relay.s_addr == INADDR_ANY)
		if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&sockoptbuf,
		    (int)sizeof (sockoptbuf)) < 0) {
			perror("Setsockopt");
			return (2);
		}
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
	    (char *)&sockoptbuf, (int)sizeof (sockoptbuf)) < 0) {
		perror("Setsockopt: REUSEADDR");
		return (2);
	}
	if (relay.s_addr != INADDR_ANY) {
		relfrom.sin_port = htons(IPPORT_BOOTPS + port_offset);
		relfrom.sin_family = AF_INET;
		relfrom.sin_addr.s_addr = INADDR_ANY;
		relfrom.sin_port = htons(IPPORT_BOOTPS + port_offset);

		(void) strncpy(lifr.lifr_name, cifname,
		    sizeof (lifr.lifr_name));
		if (lrecv) {
			if (ioctl(s, SIOCGLIFADDR, (char *)&lifr) < 0) {
			    (void) fprintf(stderr, "Warning: SIOCGLIFADDR: %s",
				strerror(errno));
			} else {
				relfrom.sin_addr.s_addr =
				    ((struct sockaddr_in *)
				    &lifr.lifr_addr)->sin_addr.s_addr;
			}
		}

		if ((srelay = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			perror("Socket");
			return (1);
		}
		(void) setsockopt(srelay, SOL_SOCKET, SO_SNDBUF, &slen, sslen);
		(void) setsockopt(srelay, SOL_SOCKET, SO_RCVBUF, &slen, sslen);

		if (setsockopt(srelay, SOL_SOCKET, SO_REUSEADDR,
		    (char *)&sockoptbuf, (int)sizeof (sockoptbuf)) < 0) {
			perror("Setsockopt: REUSEADDR");
			return (2);
		}
		if (bind(srelay, (struct sockaddr *)&relfrom,
		    sizeof (relfrom)) < 0) {
			perror("Bind");
			return (3);
		}
		ifceno = if_nametoindex(cifname);
		if (bound) {
			if (setsockopt(s, IPPROTO_IP, IP_BOUND_IF,
			    (char *)&ifceno, (int)sizeof (char *)) < 0) {
				perror("Setsockopt bind");
				return (3);
			}
		}
	}
	from.sin_family = AF_INET;
	if (relay.s_addr != INADDR_ANY) {
		from.sin_addr.s_addr =
		    ((struct sockaddr_in *)&lifr.lifr_addr)->sin_addr.s_addr;
	} else {
		from.sin_addr.s_addr = INADDR_ANY;
	}
	from.sin_port = htons(IPPORT_BOOTPC + port_offset);

	if (bind(s, (struct sockaddr *)&from, sizeof (from)) < 0) {
		perror("Bind");
		return (3);
	}
	ifceno = if_nametoindex(cifname);
	if (bound) {
		if (setsockopt(s, IPPROTO_IP, IP_BOUND_IF,
		    (char *)&ifceno, (int)sizeof (char *)) < 0) {
			perror("Setsockopt bind");
			return (3);
		}
	}
	request.op = 1;		/* BOOTP request */
	request.htype = 1;	/* Ethernet */
	request.hlen = 6;	/* Ethernet addr len */

	endp = octet = argv[2];
	for (i = 0; i < (int)request.hlen && octet != NULL; i++) {
		if ((endp = (char *)strchr(endp, ':')) != NULL)
			*endp++ = '\0';
		(void) sscanf(octet, "%x", &buf);
		request.chaddr[i] = (uchar_t)buf;
		octet = endp;
	}

	/* broadcast bit */
	if (relay.s_addr == INADDR_ANY)
		request.flags = htons(0x8000);

	/* magic cookie */
	request.cookie[0] = 99;
	request.cookie[1] = 130;
	request.cookie[2] = 83;
	request.cookie[3] = 99;

	if (proto) {
		/* Pretend to be a discover packet */
		request.options[0] = CD_DHCP_TYPE;
		request.options[1] = 1;
		request.options[2] = DISCOVER;
		request.options[3] = 0xff;

		(void) cond_init(&go_cv, USYNC_THREAD, NULL);
		(void) mutex_init(&go_mtx, USYNC_THREAD, NULL);
	}
	if (relay.s_addr != INADDR_ANY)
		request.giaddr.s_addr = from.sin_addr.s_addr;

	(void) sigfillset(&set);

	(void) sigdelset(&set, SIGABRT);	/* allow for user abort */

	(void) thr_sigsetmask(SIG_SETMASK, &set, NULL);

	/*
	 * Create the client threads
	 */
	clientsp = malloc(sizeof (struct client) * clients);
	(void) memset(clientsp, 0, sizeof (struct client) * clients);
	if (clientsp == NULL)
		return (1);

	for (i = 0; i < clients; i++) {
		(void) memcpy(clientsp[i].chaddr, request.chaddr, request.hlen);
		clientsp[i].hlen = request.hlen;
		if (i > 100)
			j = 3;
		else if (i > 50)
			j = 2;
		else
			j = 1;

		if (i) {
			clientsp[i].chaddr[j] = (unsigned char) i;
			clientsp[i].chaddr[3] += (unsigned char) j;
			clientsp[i].chaddr[4] = (unsigned char) (i * j);
		}
		if (printid)
			fprintf(stderr, "ID %x:%x:%x:%x:%x:%x\n",
				clientsp[i].chaddr[0],
				clientsp[i].chaddr[1],
				clientsp[i].chaddr[2],
				clientsp[i].chaddr[3],
				clientsp[i].chaddr[4],
				clientsp[i].chaddr[5]);

		(void) cond_init(&clientsp[i].cv, USYNC_THREAD, 0);
		(void) mutex_init(&clientsp[i].mtx, USYNC_THREAD, 0);
		clientsp[i].proto = proto;
		clientsp[i].flags = CLIENT_FIRSTTIME;
		if (thr_create(NULL, NULL, client, (void *) &clientsp[i],
		    THR_BOUND | THR_SUSPENDED, &clientsp[i].id) != 0) {
			(void) fprintf(stderr, "Error starting Client %04d\n",
			    clientsp[i].id);
		}
	}

	/*
	 * Create signal handling thread.
	 */
	if (thr_create(NULL, 0, sig_handle, NULL,
	THR_BOUND | THR_DAEMON | THR_DETACHED, &sig_id) != 0) {
		(void) fprintf(stderr, "Error starting signal handler.\n");
		return (1);
	} else
		(void) fprintf(stderr, "Started Signal handler: %04d...\n",
		    sig_id);

	/*
	 * Create/start the service thread.
	 */
	if (thr_create(NULL, NULL, service, (void *) clientsp, THR_BOUND,
	    &service_id) != 0) {
		(void) fprintf(stderr, "Error starting Service %d\n",
		    service_id);
		exit(1);
	} else
		(void) fprintf(stderr, "Started Service %04d...\n",
		    service_id);

	/*
	 * Continue the client threads.
	 */
	for (i = 0; i < clients; i++) {
		(void) thr_continue(clientsp[i].id);
	}

	/*
	 * join them
	 */
	threrrorp = &threrror;
	for (i = 0; i < clients; i++) {
		if (thr_join(clientsp[i].id, NULL, (void **) &threrrorp) == 0) {
			if (threrror != 0) {
				(void) fprintf(stdout,
				    "Client %04d - exited with %d\n",
				    clientsp[i].id, threrror);
			}
			(void) cond_destroy(&clientsp[i].cv);
			(void) mutex_destroy(&clientsp[i].mtx);
		}
	}

	(void) close(s);	/* force service out of poll */

	if (thr_join(service_id, NULL, (void **) &threrrorp) == 0) {
		if (threrror != 0) {
			(void) fprintf(stdout, "Service - exited with %d\n",
			    threrror);
		}
	}
	(void) free((char *)clientsp);
	(void) fprintf(stdout, "Exiting...\n");

	return (0);
}

/*
 * corrupt: simulate packet corruption for debugging server
 */
static void
corrupt(char *pktp, int size)
{
	int c;
	int i;
	int p;
	char *pp;
	char *pe = pktp + size;
	int li = rand() % (size - 1) + 1;

	for (pp = pktp; pp < pe; pp += li) {
		c = ((pe - pp) < li ? pe - pp : li);
		i = (rand() % c)>>1;
		while (--i > 0) {
			p = (rand() % c);
			pp[p] = (unsigned char)(rand() & 0xFF);
		}
	}
}
