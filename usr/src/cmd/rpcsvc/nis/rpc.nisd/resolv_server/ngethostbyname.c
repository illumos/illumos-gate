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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Taken from 4.1.3 ypserv resolver code. */

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <syslog.h>
#include "nres.h"
#include "prnt.h"

#ifndef NO_DATA
#define	NO_DATA NO_ADDRESS
#endif

static void nres_abort_xmit(struct nres *);
static struct nres *nres_setup(char *,
    void (*)(void *, struct hostent *, ulong_t, struct cache_ent *, int),
    struct cache_ent *);
static int nres_dosrch(struct nres *);
static int nres_register(struct nres *, int);
extern struct hostent *nres_getanswer(struct nres *);
extern int lookup_T_type(struct cache_ent *);
extern int lookup_AF_type(struct cache_ent *chl);

/*
 * these two routines return immediate errors in h_errno and null
 * if they fail or the return a struct nres
 */

struct nres    *
nres_gethostbyname(name, handler, info)
	char		*name;
	struct cache_ent *info;
	void		(*handler) ();
{
	struct nres	*temp;
	char		*cp;


	/*
	 * disallow names consisting only of digits/dots, unless they end in
	 * a dot.
	 */
	if (isdigit(name[0])) {
		cp = name;
		/* CONSTCOND */
		while (1) {
			if (!*cp) {
				if (*--cp == '.')
					break;
				h_errno = HOST_NOT_FOUND;
				return ((struct nres *)0);
			}
			if (!isdigit(*cp) && *cp != '.')
				break;
			cp++;
		}
	}

	temp = nres_setup(name, handler, info);

	if (temp != NULL) {
		temp->h_errno = TRY_AGAIN;
		if (nres_dosrch(temp) >= 0)
			return (temp);
		else {
			if (temp->udp_socket >= 0)
				(void) close(temp->udp_socket);
			if (temp->tcp_socket >= 0)
				(void) close(temp->tcp_socket);
			h_errno = temp->h_errno;
			free((char *)temp);
			return ((struct nres *)0);

		}
	} else {
		prnt(P_INFO, "nres-gethostbyname:setup failed.\n");
		return ((struct nres *)-1);
	}

}


/*
 * NOTE: nres_gethostbyaddr() should never be used to lookup IPv4 mapped
 *	 and tunnelled addresses.  The client side getXbyY routine should
 *	 have already check for this kind of lookup and translated to the
 *	 proper IPv4 lookup.
 */
/* ARGSUSED 4 : Len is not used. */
struct nres    *
nres_gethostbyaddr(addr, len, type, handler, info)
	char		*addr;
	int		len;
	int		type;
	struct cache_ent *info;
	void		(*handler) ();
{
	struct nres	*temp;
	unsigned char	*uaddr = (unsigned char *)addr;
	char		qbuf[MAXDNAME], *qp;
	int		n;

	switch (type) {
	case AF_INET:
		(void) sprintf(qbuf, "%d.%d.%d.%d",
			(uaddr[3] & 0xff), (uaddr[2] & 0xff),
			(uaddr[1] & 0xff), (uaddr[0] & 0xff));
		break;
	case AF_INET6:
		qp = qbuf;
		for (n = IN6ADDRSZ - 1; n >= 0; n--) {
			qp += sprintf(qp, "%x.%x.",
				uaddr[n] & 0xf, (uaddr[n] >> 4) & 0xf);
		}
		qbuf[(qp - qbuf - 1)] = '\0'; /* Remove trailing dot. */
		break;
	default:
		return ((struct nres *)0);
	}

	temp = nres_setup(qbuf, handler, info);
	if (temp != NULL) {
		temp->reverse = REVERSE_PTR;
		if (type == AF_INET)
			(void) memcpy(&(temp->theaddr.s_addr), addr, 4);
		else
			(void) memcpy(&(temp->theaddr6.s6_addr), addr, 16);
		temp->h_errno = TRY_AGAIN;
		if (nres_dosrch(temp) >= 0)
			return (temp);
		else {
			if (temp->udp_socket >= 0)
				(void) close(temp->udp_socket);
			if (temp->tcp_socket >= 0)
				(void) close(temp->tcp_socket);
			h_errno = temp->h_errno;
			free((char *)temp);
			return ((struct nres *)0);

		}
	} else {
		prnt(P_INFO, "nres-gethostbyaddr:setup failed.\n");
		return ((struct nres *)-1);
	}

}

/*
 * A timeout has occured -- try to retransmit, if it fails call abort_xmit to
 * decide to pursue the search or give up
 */

static void
nres_dotimeout(as)
	rpc_as		*as;
{

	struct nres    *temp;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	temp = (struct nres *)as->as_userptr;

	/*
	 * timeout
	 */
	prnt(P_INFO, "timeout.\n");
	temp->current_ns = temp->current_ns + 1;

	if (temp->using_tcp) {
		(void) close(temp->tcp_socket);
		temp->tcp_socket = -1;
		(void) rpc_as_unregister(as); /* if you close it */
	}

	if (nres_xmit(temp) < 0) {
		temp->h_errno	= TRY_AGAIN;
		(void) rpc_as_unregister(as);
		nres_abort_xmit(temp);
	} else {
		if (temp->using_tcp) {
			if (nres_register(temp, temp->tcp_socket) < 0) {
				temp->h_errno	= TRY_AGAIN;
				nres_abort_xmit(temp);
			}
		} else {
			if (nres_register(temp, temp->udp_socket) < 0) {
				temp->h_errno	= TRY_AGAIN;
				nres_abort_xmit(temp);
			}
		}
	}
}

/* this advances the search with dosrch or gives up */
/* if it gives up it calls the users 'done' function */
/* this is the timeout way to call the user */
static void
nres_abort_xmit(temp)
	struct nres    *temp;
{
	/* called on timeout */
	int		give_up;
	prnt(P_INFO, "nres_abort().\n");
	give_up = 0;
	if (temp->search_index == 1 ||
	    (temp->search_index == 0 && temp->tried_asis == 1)) {
		/* Timeout occurred on first attempt. */
		give_up = 1;
		prnt(P_INFO, "Name server(s) seem to be down.\n");
	} else if (nres_dosrch(temp) < 0)
		give_up = 1;
	if (give_up) {
		prnt(P_INFO,
		"more srching aborted: would ret try_again to caller.\n");
		temp->h_errno = TRY_AGAIN;
		if (temp->done)
			(temp->done)((void *)temp, NULL, 0,
					temp->userinfo, temp->h_errno);
		if (temp->udp_socket >= 0)
			(void) close(temp->udp_socket);
		if (temp->tcp_socket >= 0)
			(void) close(temp->tcp_socket);
		free((char *)temp);
	}
}

/*
 * try to pursue the search by calling nres_search and nres_xmit -- if both
 * work then register an asynch reply to come to nres_dorcv or a timeout to
 * nres_dotimeout
 */
/*
 * 0 means that the search is continuing -1 means that the search is not
 * continuing h_errno has the cause.
 */

static int
nres_dosrch(temp)
	struct nres    *temp;
{
	int		type;

	if (nres_search(temp) >= 0) {
		type = temp->qtype;
		prnt(P_INFO, "search \'%s\'.\n", temp->search_name);
		temp->question_len = res_mkquery(QUERY, temp->search_name,
					C_IN, type, (uchar_t *)NULL, 0, NULL,
					(uchar_t *)temp->question, MAXPACKET);
		if (temp->question_len < 0) {
			temp->h_errno = NO_RECOVERY;
			prnt(P_INFO, "res_mkquery --NO RECOVERY.\n");
			return (-1);
		}
		if (nres_xmit(temp) < 0) {
			prnt(P_INFO, "nres_xmit() fails.\n");
			temp->h_errno	= TRY_AGAIN;
			return (-1);
		} else {
			if (temp->using_tcp) {
				if (nres_register(temp, temp->tcp_socket) < 0) {
					temp->h_errno	= TRY_AGAIN;
					return (-1);
				}
			} else {
				if (nres_register(temp, temp->udp_socket) < 0) {
					temp->h_errno	= TRY_AGAIN;
					return (-1);
				}
			}
		}
		return (0);
	}
	return (-1);
}


/*
 * this processes an answer received asynchronously a nres_rcv is done to
 * pick up the packet, if it fails we just return, otherwise we unregister
 * the fd, check the reply. If the reply has an answer we call nres_getanswer
 * to get the answer, otherwise there is no answer an we call nres_dosrch to
 * press the search forward, if nres_dosrch works we return.  If the search
 * can not be continued or if we got the answer we call the users done
 * routine
 */

static void
nres_dorecv(as)
	struct rpc_as  *as;
{
	struct nres    *temp;
	struct nres    *again;
	struct hostent *theans;
	int status;
	struct in_addr **a;
	struct in6_addr **a6;
	void		(*done) ();

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	temp = (struct nres *)as->as_userptr;
	theans = NULL;
	errno = 0;
	status = nres_rcv(temp);
	if (status > 0) {
		prnt(P_INFO, "Recieved chars=%d.\n", temp->answer_len);
		if (verbose && verbose_out) p_query((uchar_t *)temp->answer);
	} else if (status < 0) {
		prnt(P_INFO, "nres_rcv() hard fails.\n");
		(void) rpc_as_unregister(as);	/* socket was closed for us */
		nres_dotimeout(as);	/* this may revive it */
		return;		/* keep running */
	} else {
		prnt(P_INFO, "nres_rcv() soft fails.\n");
		return;		/* keep running */
	}
	(void) rpc_as_unregister(as);

	/* reply part */
	temp->answer_len = nres_chkreply(temp);

	if (temp->answer_len < 0) {
		if (errno == ECONNREFUSED) {
			temp->h_errno = TRY_AGAIN;
			goto out;
		}
		if (temp->h_errno == NO_DATA)
			temp->got_nodata++;
		if ((temp->h_errno != HOST_NOT_FOUND &&
		    temp->h_errno != NO_DATA) ||
		    (_res.options & RES_DNSRCH) == 0)
			goto out;
	} else {
		prnt(P_INFO, "nres_getanswer().\n");
		theans = nres_getanswer(temp);
		goto out;
	}
	prnt(P_INFO, "continuing search... .\n");
	if (nres_dosrch(temp) < 0)
		goto out;
	return;		/* keep running  with new search */

out:
	prnt(P_INFO, "done with this case.\n");
	/* answer resolution */
	if ((theans == NULL) && temp->got_nodata) {
		temp->h_errno = NO_DATA;
		prnt(P_INFO, "no_data.\n");
	}


	done = temp->done;
	if (theans) {
		if (temp->reverse == REVERSE_PTR) {
			/* raise security */
			theans->h_addrtype = temp->af_type;
			if (theans->h_addrtype == AF_INET) {
				theans->h_length = 4;
				theans->h_addr_list[0] =
						(char *)&(temp->theaddr);
			} else {
				theans->h_length = 16;
				theans->h_addr_list[0] =
						(char *)&(temp->theaddr6);
			}
			theans->h_addr_list[1] = (char *)0;
			if (temp->udp_socket >= 0)
				(void) close(temp->udp_socket);
			if (temp->tcp_socket >= 0)
				(void) close(temp->tcp_socket);
			again = nres_setup(theans->h_name, temp->done,
							temp->userinfo);
			if (again != NULL) {
				if (again->af_type == AF_INET) {
					again->qtype = T_A;
					again->theaddr = temp->theaddr;
				} else {
					again->qtype = T_AAAA;
					again->theaddr6 = temp->theaddr6;
				}
				again->reverse = REVERSE_A;
				again->h_errno = TRY_AGAIN;
				if (nres_dosrch(again) < 0) {
					if (done)
						(*done) (again, NULL, 0,
					again->userinfo, again->h_errno);
					if (again->udp_socket >= 0)
						(void) close(again->udp_socket);
					if (again->tcp_socket >= 0)
						(void) close(again->tcp_socket);
					free((char *)again);
				}
			} else {
				/* memory error */
				temp->h_errno = TRY_AGAIN;
				if (done)
					(*done) (temp, NULL, 0, temp->userinfo,
								temp->h_errno);

			}
			free((char *)temp);
			return;
		} else if (temp->reverse == REVERSE_A) {
			int found_addr = FALSE;
			if (temp->af_type == AF_INET) {
				for (a = (struct in_addr **)theans->h_addr_list;
						*a; a++) {
					if (memcmp(*a, &(temp->theaddr),
						    theans->h_length) == 0) {
						if (done)
							(*done) (temp,
							theans, temp->ttl,
							temp->userinfo,
							temp->h_errno);
						done = NULL;
						found_addr = TRUE;
						break;
					}
				}
				if (!found_addr) {  /* weve been spoofed */
					char bb[100];
					(void) inet_ntop(AF_INET,
					    (void *)&temp->theaddr, bb, 100);
					prnt(P_ERR,
					"nres_gethostbyaddr: %s != %s.\n",
						temp->name, bb);
					theans = NULL;
					temp->h_errno = HOST_NOT_FOUND;
				}
			} else {
				/* AF_INET6 */
				for (a6 = (struct in6_addr **)
					    theans->h_addr_list; *a6; a6++) {
					if (memcmp(*a6, &(temp->theaddr6),
						    theans->h_length) == 0) {
						if (done)
							(*done) (temp,
							theans, temp->ttl,
							temp->userinfo,
							temp->h_errno);
						done = NULL;
						found_addr = TRUE;
						break;
					}
				}
				if (!found_addr) {  /* weve been spoofed */
					char bb[100];
					(void) inet_ntop(AF_INET6,
					    (void *)&temp->theaddr6, bb, 100);
					prnt(P_ERR,
					"nres_gethostbyaddr: %s != %s.\n",
						temp->name, bb);
					theans = NULL;
					temp->h_errno = HOST_NOT_FOUND;
				}
			}
		}
	}
	if (done)
		(*done) (temp, theans, temp->ttl,
				temp->userinfo, temp->h_errno);
	if (temp->udp_socket >= 0)
		(void) close(temp->udp_socket);
	if (temp->tcp_socket >= 0)
		(void) close(temp->tcp_socket);
	free((char *)temp);
	return;			/* done running */

}

static int
nres_register(a, b)
	int		b;
	struct nres	*a;
{
	a->nres_rpc_as.as_fd = b;
	a->nres_rpc_as.as_timeout_flag = TRUE;
	a->nres_rpc_as.as_timeout = nres_dotimeout;
	a->nres_rpc_as.as_recv = nres_dorecv;
	a->nres_rpc_as.as_userptr = (char *)a;
	return (rpc_as_register(&(a->nres_rpc_as)));
}

static struct nres *
nres_setup(name, done, userinfo)
	char		*name;
	struct cache_ent *userinfo;
	void		(*done) ();
{
	struct nres	*tmp;

	tmp = (struct nres *)calloc(1, sizeof (struct nres));
	if (tmp == NULL)
		return (tmp);
	(void) strncpy(tmp->name, name, MAXDNAME);
	tmp->tcp_socket = -1;
	tmp->udp_socket = -1;
	tmp->done = done;
	tmp->userinfo = userinfo;
	tmp->qtype = lookup_T_type(userinfo);
	tmp->af_type = lookup_AF_type(userinfo);
	return (tmp);
}
