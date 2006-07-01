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

#include <sys/types.h>
#include <sys/dlpi.h>
#include <libdlpi.h>
#include <ctype.h>
#include <sys/sysmacros.h>
#include <net/if_types.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if_dl.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <strings.h>
#include <stropts.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "local_types.h"
#include "target.h"
#include "queue.h"
#include "utility.h"

#define	LOCAL_LOOPBACK	"lo0"

/*
 * This entire file is all about getting these two variables. To create a
 * unique iSCSI IQN string we need information that is unique. What Sun has
 * decided is to use a MAC address along with a timestamp. No other machine
 * at this given time will have the same MAC address and as time moves along
 * well, time will change.
 */
uchar_t	*mac_addr;
size_t	mac_len;

#define	PATH_PART	"/dev/"

static struct lifreq *if_setup(int *n);
static void dump_addr_to_ascii(struct sockaddr *addr, char *buf,
    size_t len);
static int strputmsg(int fd, uint8_t *ctl_buf, size_t ctl_len, int flags);
static int strgetmsg(int fd, char *ctl_buf, size_t *ctl_lenp, char *data_buf,
    size_t *data_lenp);
static Boolean_t grab_address(char *ifname, uchar_t **addr, size_t *lp);

/*
 * []----
 * | if_find_mac -- Finds a valid MAC address to use for GUID & IQN creation
 * |
 * | To create both the GUID and the IQN string we need to make them unique
 * | and do so without requiring the user to have to register each target
 * | creation with Sun. Each machine that's using iSCSI will have a network
 * | interface from which we can obtain the MAC address. That guarantees
 * | uniqueness within the network, but doesn't guarantee uniqueness with
 * | the machine. So when creating the GUID/IQN we also use a timestamp.
 * []----
 */
Boolean_t
if_find_mac(target_queue_t *mgmt)
{
	struct lifreq	*lifrp, *first;
	int		n;
	char		*str		= NULL;

	first = if_setup(&n);
	for (lifrp = first; n > 0; n--, lifrp++) {
		if (grab_address(lifrp->lifr_name, &mac_addr,
		    &mac_len) == True) {
			str = _link_ntoa(mac_addr, str, mac_len, IFT_OTHER);
			if ((str != NULL) && (mgmt != NULL)) {
				queue_prt(mgmt, Q_GEN_DETAILS,
				    "MAIN  %s: %s \n", lifrp->lifr_name, str);
				free(str);
			}
			/* ---- grab the first valid MAC address ---- */
			break;
		}
	}
	if (first)
		free(first);
	return (mac_len == 0 ? False : True);
}

/*
 * []----
 * | if_target_address -- setup IP address for SendTargets
 * |
 * | This routine is called when the iSCSI target is returning SendTargets
 * | data during a discovery phase. The target name is returned along
 * | with all of the IP address that can access that target. There's one
 * | catch, the first address in the list will be the address used by
 * | the initiator if it doesn't support multiple connections per session.
 * | Therefore, whatever connection the initiator used is the first one
 * | that should be in our list. The ramificiations of not doing this are
 * | possible performance issues. Take for example a setup where both the
 * | initiator and target have 10GbE and 1GbE interfaces. The initiator wants
 * | to use the 10GbE interface because of it's speed. If the target returns
 * | a list of addresses with the 1GbE listed first, that's the one which
 * | the initiator would use. Not good.
 * []----
 */
void
if_target_address(char **text, int *text_length, struct sockaddr *sp)
{
	struct lifreq		*lp,
				*first;
	int			n,
				i,
				s;
	struct sockaddr_in	*sin4_cur,
				*sin4_pos;
	struct sockaddr_in6	*sin6_cur,
				*sin6_pos;
	char			ta[80],
				ip_buf[INET6_ADDRSTRLEN];
	int			fromlen;

	if (sp->sa_family == AF_INET) {
		fromlen = sizeof (struct sockaddr_in);

		if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
			return;

		/*LINTED*/
		sin4_cur = (struct sockaddr_in *)sp;

		/*
		 * Ugh. Would you believe that even though this array
		 * is defined as zero, we get back non-zero data from
		 * getsockname().
		 */
		bzero(&sin4_cur->sin_zero[0], sizeof (sin4_cur->sin_zero));

	} else if (sp->sa_family == AF_INET6) {
		fromlen = sizeof (struct sockaddr_in6);

		if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
			return;

		/*LINTED*/
		sin6_cur = (struct sockaddr_in6 *)sp;
	} else
		return;

	first = if_setup(&n);
	for (lp = first, i = 0; i < n; i++, lp++) {

		if (ioctl(s, SIOCGLIFADDR, lp) < 0)
			continue;

		if (sp->sa_family != lp->lifr_addr.ss_family)
			continue;

		/*
		 * Change the possible incoming addresses port number,
		 * which would be zero, to that of the current incoming
		 * port number. Otherwise the comparison will not match.
		 */
		if (sp->sa_family == AF_INET) {
			sin4_pos = (struct sockaddr_in *)&lp->lifr_addr;
			sin4_pos->sin_port = sin4_cur->sin_port;
		} else if (sp->sa_family == AF_INET6) {
			sin6_pos = (struct sockaddr_in6 *)&lp->lifr_addr;
			sin6_pos->sin6_port = sin6_cur->sin6_port;
		} else
			goto clean_up;
	}

	for (lp = first, i = 0; i < n; i++, lp++) {

		if (bcmp(sp, &lp->lifr_addr, fromlen) == 0) {
			dump_addr_to_ascii((struct sockaddr *)&lp->lifr_addr,
			    ip_buf, sizeof (ip_buf));

			if (sp->sa_family == AF_INET) {
				(void) snprintf(ta, sizeof (ta), "%s,1",
				    ip_buf);
			} else if (sp->sa_family == AF_INET6) {
				(void) snprintf(ta, sizeof (ta), "[%s],1",
				    ip_buf);
			} else
				goto clean_up;

			(void) add_text(text, text_length, "TargetAddress", ta);

			/*
			 * There is possiblity that both IPv4 & IPv6 enabled on
			 * certain interface, then we will see that interface
			 * twice identically in the list.
			 * Of course we need only one of them, not both.
			 */
			break;
		}
	}

	for (lp = first, i = 0; i < n; i++, lp++) {
		/*
		 * We allow for the loopback address to match the discovery
		 * address above since it's entirely possible to create
		 * a target on the same machine that you're running the
		 * initiator. Now, when we provide the list of other
		 * possible interfaces to use we don't want to include
		 * the loopback because that's obviously not a valid I/F
		 * for a remote node.
		 */
		if (strcmp(lp->lifr_name, LOCAL_LOOPBACK) == 0)
			continue;

		if (bcmp(sp, &lp->lifr_addr, fromlen) != 0) {
			dump_addr_to_ascii((struct sockaddr *)&lp->lifr_addr,
			    ip_buf, sizeof (ip_buf));

			if (sp->sa_family == AF_INET) {
				(void) snprintf(ta, sizeof (ta), "%s,1",
				    ip_buf);
			} else if (sp->sa_family == AF_INET6) {
				(void) snprintf(ta, sizeof (ta), "[%s],1",
				    ip_buf);
			} else
				goto clean_up;
			(void) add_text(text, text_length, "TargetAddress", ta);
		}
	}

clean_up:
	(void) close(s);
	if (first)
		free(first);
}

/*
 * []----
 * | dump_addr_to_ascii -- Use appropriate translation routine
 * []----
 */
static void
dump_addr_to_ascii(struct sockaddr *addr, char *buf, size_t len)
{
	struct sockaddr_in	*sin4;
	struct sockaddr_in6	*sin6;

	if (addr->sa_family == AF_INET) {
		/*LINTED*/
		sin4 = (struct sockaddr_in *)addr;
		(void) inet_ntop(AF_INET, &sin4->sin_addr, buf, len);
	} else if (addr->sa_family == AF_INET6) {
		/*LINTED*/
		sin6 = (struct sockaddr_in6 *)addr;
		(void) inet_ntop(AF_INET6, &sin6->sin6_addr, buf, len);
	}
}

/*
 * []----
 * | if_setup -- Load up the interface names
 * |
 * | If this routine returns NULL, argument 'n' is also guaranteed to
 * | be set to 0.
 * []----
 */
static struct lifreq *
if_setup(int *n)
{
	struct lifnum	lifn;
	struct lifconf	lifc;
	int		numifs;
	unsigned	bufsize;
	char		*buf;
	int		s;

	*n = 0;
	if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		/*
		 * If we failed to open an IPv6 socket
		 * try IPv4 socket instead
		 */
		if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
			return (NULL);
	}

	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	if (ioctl(s, SIOCGLIFNUM, (char *)&lifn) < 0)
		return (NULL);

	numifs = lifn.lifn_count;

	bufsize = numifs * sizeof (struct lifreq);
	if ((buf = malloc(bufsize)) == NULL) {
		/*
		 * This call is made so early on that if we're out of memory
		 * here, just say goodbye.
		 */
		return (NULL);
	}

	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;

	if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) < 0) {
		free(buf);
		return (NULL);
	}

	(void) close(s);
	*n = lifc.lifc_len / sizeof (struct lifreq);
	return (lifc.lifc_req);
}

static int
strputmsg(int fd, uint8_t *ctl_buf, size_t ctl_len, int flags)
{
	struct strbuf	ctl;

	bzero(&ctl, sizeof (ctl));
	ctl.buf = (char *)ctl_buf;
	ctl.len = ctl_len;

	return (putmsg(fd, &ctl, NULL, flags));
}

static int
strgetmsg(int fd, char *ctl_buf, size_t *ctl_lenp, char *data_buf,
    size_t *data_lenp)
{
	struct strbuf	ctl;
	struct strbuf	data;
	int		flags	= 0,
			res;

	bzero(&ctl, sizeof (ctl));
	ctl.buf = ctl_buf;
	ctl.len = 0;
	ctl.maxlen = (ctl_lenp != NULL) ? *ctl_lenp : 0;

	bzero(&data, sizeof (data));
	data.buf = data_buf;
	data.len = 0;
	data.maxlen = (data_lenp != NULL) ? *data_lenp : 0;

	res = getmsg(fd, &ctl, &data, &flags);
	if (ctl_lenp != NULL)
		*ctl_lenp = ctl.len;
	if (data_lenp != NULL)
		*data_lenp = data.len;

	return (res);
}

static Boolean_t
ppa_attach(int fd, int ppa)
{
	union DL_primitives	*buf	= NULL;
	dl_attach_req_t		dlar;
	size_t			size;
	Boolean_t		rval	= False;

	size = 0;
	size = MAX(sizeof (dl_ok_ack_t), size);
	size = MAX(sizeof (dl_error_ack_t), size);

	if ((buf = malloc(size)) == NULL)
		return (False);

	dlar.dl_primitive	= DL_ATTACH_REQ;
	dlar.dl_ppa		= ppa;

	if (strputmsg(fd, (uint8_t *)&dlar, DL_ATTACH_REQ_SIZE, 0) == -1)
		goto error;

	if (strgetmsg(fd, (char *)buf, &size, NULL, NULL) == -1)
		goto error;

	if (size < sizeof (t_uscalar_t))
		goto error;

	switch (buf->dl_primitive) {
	case DL_OK_ACK:
		if (size == DL_OK_ACK_SIZE)
			rval = True;
		break;
	}

error:
	if (buf != NULL)
		free(buf);

	return (rval);
}

static Boolean_t
grab_address(char *ifname, uchar_t **addr, size_t *lp)
{
	char			*dev_name	= NULL,
				*p;
	size_t			len;
	int			ppa,
				fd		= -1;
	union DL_primitives	*buf		= NULL;
	dl_phys_addr_req_t	dlpar;
	dl_phys_addr_ack_t	*dlpaap;
	Boolean_t		rval		= False;

	if (strcmp(ifname, LOCAL_LOOPBACK) == 0)
		return (False);

	bzero(&dlpar, sizeof (dlpar));
	len = strlen(PATH_PART) + strlen(ifname) + 1;
	if ((dev_name = (char *)malloc(len)) == NULL) {
		goto error;
	}
	(void) snprintf(dev_name, len, "%s%s", PATH_PART, ifname);

	if ((fd = open(dev_name, O_RDWR)) < 0) {
		for (p = dev_name; *p; p++) {
			if (isdigit(*p)) {
				ppa = atoi(p);
				*p = '\0';
				if (((fd = open(dev_name, O_RDWR)) < 0) ||
				    (ppa_attach(fd, ppa) == False)) {
					goto error;
				}
				break;
			}
		}
		if (fd == -1)
			goto error;
	}

	len = 0;
	len = MAX(sizeof (dl_phys_addr_ack_t) + MAXADDRLEN, len);
	len = MAX(sizeof (dl_error_ack_t), len);

	if ((buf = calloc(len, 1)) == NULL)
		goto error;
	dlpar.dl_primitive = DL_PHYS_ADDR_REQ;
	dlpar.dl_addr_type = DL_CURR_PHYS_ADDR;

	if (strputmsg(fd, (uint8_t *)&dlpar, DL_PHYS_ADDR_REQ_SIZE, 0) == -1) {
		goto error;
	}

	if (strgetmsg(fd, (char *)buf, &len, NULL, NULL) == -1) {
		goto error;
	}

	switch (buf->dl_primitive) {
	case DL_PHYS_ADDR_ACK:
		if (len < DL_PHYS_ADDR_ACK_SIZE) {
			goto error;
		}

		dlpaap = (dl_phys_addr_ack_t *)buf;
		if (dlpaap->dl_addr_offset != 0) {
			if (dlpaap->dl_addr_length == 0) {
				goto error;
			}
			*addr = malloc(dlpaap->dl_addr_length);
			if (*addr == NULL)
				goto error;
			bcopy((char *)buf + dlpaap->dl_addr_offset, *addr,
			    dlpaap->dl_addr_length);
			*lp = dlpaap->dl_addr_length;
			rval = True;
		}
		break;
	}

error:
	if (fd != -1)
		(void) close(fd);
	if (dev_name != NULL)
		free(dev_name);
	if (buf != NULL)
		free(buf);
	return (rval);
}
