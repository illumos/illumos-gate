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

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <tzfile.h>
#include "snoop.h"
#include "ntp.h"

/*
 * In verbose mode, how many octets of the control-mode data payload
 * are displayed per line of output.  The value 64 fits well on an
 * 80-column screen and, as a power of 2, is easily correlated to
 * hexadecimal output.
 */
#define	OCTETS_PER_LINE	64

extern char *dlc_header;

static	char	*show_leap(int);
static	char	*show_mode(int);
static	char	*show_ref(int, ulong_t);
static	char	*show_time(struct l_fixedpt);
static	double	s_fixed_to_double(struct s_fixedpt *);
static	char	*iso_date_time(time_t);
static	char	*show_operation(int);

int
interpret_ntp(int flags, struct ntpdata *ntp_pkt, int fraglen)
{
	unsigned int	i, j, macbytes;
	unsigned int	proto_version;
	unsigned int	datalen;
	unsigned int	linelen = OCTETS_PER_LINE;
	unsigned int	sofar = 0;

	char	*datap;
	char	hbuf[2 * MAC_OCTETS_MAX + 1];
	static	char *hexstr = "0123456789ABCDEF";

	union	ntp_pkt_buf {
		struct	ntpdata ntp_msg;
		union ntpc_buf {
			struct	ntp_control chdr;
			uchar_t	data2[NTPC_DATA_MAXLEN - 1];
		} ntpc_msg;
		union ntpp_buf {
			struct	ntp_private phdr;
			uchar_t	data2[1];
		} ntpp_msg;
	} fragbuf;

	struct	ntpdata		*ntp = &fragbuf.ntp_msg;
	struct	ntp_control	*ntpc = (struct ntp_control *)&fragbuf.ntpc_msg;
	struct	ntp_private	*ntpp = (struct ntp_private *)&fragbuf.ntpp_msg;

	/*
	 * Copying packet contents into a local buffer avoids
	 * problems of interpretation if the packet is truncated.
	 */
	(void) memcpy(&fragbuf, ntp_pkt, MIN(sizeof (fragbuf), fraglen));

	if (flags & F_SUM) {
		switch (ntp->li_vn_mode & NTPMODEMASK) {
		case MODE_SYM_ACT:
		case MODE_SYM_PAS:
		case MODE_CLIENT:
		case MODE_SERVER:
		case MODE_BROADCAST:
		    (void) sprintf(get_sum_line(),
			"NTP  %s [st=%hd] (%s)",
			show_mode(ntp->li_vn_mode & NTPMODEMASK),
			ntp->stratum,
			show_time(ntp->xmt));
		    break;
		case MODE_CONTROL:
		    (void) sprintf(get_sum_line(),
			"NTP  %s "
			"(Flags/op=0x%02x Seq=%hu Status=0x%04hx Assoc=%hu)",
			show_mode(ntpc->li_vn_mode & NTPMODEMASK),
			ntpc->r_m_e_op,
			ntohs(ntpc->sequence),
			ntohs(ntpc->status),
			ntohs(ntpc->associd));
		    break;
		default:
		    (void) sprintf(get_sum_line(),
			"NTP  %s",
			show_mode(ntpp->rm_vn_mode & NTPMODEMASK));
		    break;
		}
	}

	proto_version = (ntp->li_vn_mode & VERSIONMASK) >> 3;

	if (flags & F_DTAIL) {
		show_header("NTP:  ", "Network Time Protocol", fraglen);
		show_space();
		switch (ntp->li_vn_mode & NTPMODEMASK) {
		case MODE_SYM_ACT:
		case MODE_SYM_PAS:
		case MODE_CLIENT:
		case MODE_SERVER:
		case MODE_BROADCAST:
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->li_vn_mode -
			dlc_header, 1),
			"Leap    = 0x%x (%s)",
			(int)(ntp->li_vn_mode & LEAPMASK) >> 6,
			show_leap(ntp->li_vn_mode & LEAPMASK));
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->li_vn_mode -
			dlc_header, 1),
			"Version = %lu", proto_version);
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->li_vn_mode -
			dlc_header, 1),
			"Mode    = %hu (%s)",
			ntp->li_vn_mode & NTPMODEMASK,
			show_mode(ntp->li_vn_mode & NTPMODEMASK));
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->stratum -
			dlc_header, 1),
			"Stratum = %d (%s)",
			ntp->stratum,
			ntp->stratum == 0 ? "unspecified" :
			ntp->stratum == 1 ? "primary reference" :
			"secondary reference");
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->ppoll -
			dlc_header, 1),	"Poll    = %hu", ntp->ppoll);
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->precision -
			dlc_header, 1),
			"Precision = %d seconds",
			ntp->precision);
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntp->distance.int_part -
			dlc_header, 1),
			"Synchronizing distance   = 0x%04x.%04x  (%f)",
			ntohs(ntp->distance.int_part),
			ntohs(ntp->distance.fraction),
			s_fixed_to_double(&ntp->distance));
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntp->dispersion.int_part -
			dlc_header, 1),
			"Synchronizing dispersion = 0x%04x.%04x  (%f)",
			ntohs(ntp->dispersion.int_part),
			ntohs(ntp->dispersion.fraction),
			s_fixed_to_double(&ntp->dispersion));
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->refid -
			dlc_header, 1), "Reference clock = %s",
			show_ref(ntp->stratum, ntp->refid));

		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntp->reftime.int_part - dlc_header,
			1), "Reference time = 0x%08lx.%08lx (%s)",
			ntohl(ntp->reftime.int_part),
			ntohl(ntp->reftime.fraction),
			show_time(ntp->reftime));

		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntp->org.int_part - dlc_header, 1),
			"Originate time = 0x%08lx.%08lx (%s)",
			ntohl(ntp->org.int_part),
			ntohl(ntp->org.fraction),
			show_time(ntp->org));

		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntp->rec.int_part - dlc_header, 1),
			"Receive   time = 0x%08lx.%08lx (%s)",
			ntohl(ntp->rec.int_part),
			ntohl(ntp->rec.fraction),
			show_time(ntp->rec));

		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntp->xmt.int_part - dlc_header, 1),
			"Transmit  time = 0x%08lx.%08lx (%s)",
			ntohl(ntp->xmt.int_part),
			ntohl(ntp->xmt.fraction),
			show_time(ntp->xmt));

		    if (proto_version > 3 ||
			fraglen < (LEN_PKT_NOMAC + MAC_OCTETS_MIN)) {
				/*
				 * A newer protocol version we can't parse,
				 * or v3 packet with no valid authentication.
				 */
				break;
		    }
		    (void) sprintf(get_line((char *)ntp->keyid -
			dlc_header, 1),
			"Key ID  = %8lu", ntohl(ntp->keyid));

		    macbytes = fraglen - (LEN_PKT_NOMAC + sizeof (uint32_t));

		    for (i = 0, j = 0; i < macbytes; i++) {
			    hbuf[j++] = hexstr[ntp->mac[i] >> 4 & 0x0f];
			    hbuf[j++] = hexstr[ntp->mac[i] & 0x0f];
		    }
		    hbuf[j] = '\0';
		    (void) sprintf(get_line((char *)ntp->mac -
			dlc_header, 1),
			"Authentication code = %s", hbuf);
		    break;

		case MODE_CONTROL:
		    /* NTP Control Message, mode 6 */

		    (void) sprintf(get_line((char *)(uintptr_t)ntp->li_vn_mode -
			dlc_header, 1),
			"Leap    = 0x%x (%s)",
			(int)(ntp->li_vn_mode & LEAPMASK) >> 6,
			show_leap(ntp->li_vn_mode & LEAPMASK));
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->li_vn_mode -
			dlc_header, 1),
			"Version = %lu", proto_version);
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->li_vn_mode -
			dlc_header, 1),
			"Mode    = %hu (%s)",
			ntp->li_vn_mode & NTPMODEMASK,
			show_mode(ntp->li_vn_mode & NTPMODEMASK));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->r_m_e_op -
			dlc_header, 1),
			"Flags and operation code = 0x%02x",
			ntpc->r_m_e_op);
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->r_m_e_op -
			dlc_header, 1),
			"      %s",
			getflag(ntpc->r_m_e_op, CTL_RESPONSE, "response",
			"request"));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->r_m_e_op -
			dlc_header, 1),
			"      %s",
			getflag(ntpc->r_m_e_op, CTL_ERROR, "error",
			"success"));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->r_m_e_op -
			dlc_header, 1),
			"      %s",
			getflag(ntpc->r_m_e_op, CTL_MORE, "more",
			"no more"));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->r_m_e_op -
			dlc_header, 1),
			"      ...x xxxx = %hd (%s)",
			ntpc->r_m_e_op & CTL_OP_MASK,
			show_operation(ntpc->r_m_e_op & CTL_OP_MASK));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->sequence -
			dlc_header, 1),
			"Sequence = %hu",
			ntohs(ntpc->sequence));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->status -
			dlc_header, 1),
			"Status = 0x%04hx",
			ntohs(ntpc->status));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->associd -
			dlc_header, 1),
			"Assoc ID = %hu",
			ntohs(ntpc->associd));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->offset -
			dlc_header, 1),
			"Data offset = %hu",
			ntohs(ntpc->offset));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpc->count -
			dlc_header, 1),
			"Data bytes = %hu",
			ntohs(ntpc->count));
		    datalen = ntohs(ntpc->count);
		    if (datalen == 0) {
			    break;
		    } else if (datalen > NTPC_DATA_MAXLEN) {
			    datalen = NTPC_DATA_MAXLEN;
		    }
		    show_space();
		    datap = (char *)ntpc->data;
		    do {
			    (void) sprintf(get_line(datap -
				dlc_header, 1),
				"\"%s\"",
				show_string(datap, linelen, datalen));
			    sofar += linelen;
			    datap += linelen;
			    if ((sofar + linelen) > datalen) {
				    linelen = datalen - sofar;
			    }
		    } while (sofar < datalen);
		    show_trailer();
		    break;

		case MODE_PRIVATE:
		    /* NTP Private Message, mode 7 */

		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntpp->rm_vn_mode - dlc_header, 1),
			"Version = %hu", INFO_VERSION(ntpp->rm_vn_mode));
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntpp->rm_vn_mode - dlc_header, 1),
			"Mode    = %hu (%s)", INFO_MODE(ntpp->rm_vn_mode),
			show_mode(INFO_MODE(ntpp->rm_vn_mode)));
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntpp->rm_vn_mode - dlc_header, 1),
			"Flags = 0x%02hx", ntpp->rm_vn_mode);
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntpp->rm_vn_mode - dlc_header, 1),
			"      %s",
			getflag(ntpp->rm_vn_mode, RESP_BIT, "response",
			"request"));
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntpp->rm_vn_mode - dlc_header, 1),
			"      %s",
			getflag(ntpp->rm_vn_mode, MORE_BIT, "more", "no more"));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpp->auth_seq -
			dlc_header, 1),
			"Authentication and sequence = 0x%02x", ntpp->auth_seq);
		    (void) sprintf(get_line((char *)(uintptr_t)ntpp->auth_seq -
			dlc_header, 1),
			"      %s",
			getflag(ntpp->auth_seq, AUTH_BIT, "authenticated",
			"unauthenticated"));
		    (void) sprintf(get_line((char *)(uintptr_t)ntpp->auth_seq -
			dlc_header, 1),
			"      .xxx xxxx = %hu (sequence number)",
			INFO_SEQ(ntpp->auth_seq));
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntpp->implementation - dlc_header,
			1), "Implementation = %hu", ntpp->implementation);
		    (void) sprintf(get_line((char *)(uintptr_t)ntpp->request -
			dlc_header, 1), "Request = %hu", ntpp->request);
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntpp->err_nitems - dlc_header, 1),
			"Error = %hu", INFO_ERR(ntpp->err_nitems));
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntpp->err_nitems - dlc_header, 1),
			"Items = %hu", INFO_NITEMS(ntpp->err_nitems));
		    (void) sprintf(get_line(
			(char *)(uintptr_t)ntpp->mbz_itemsize - dlc_header, 1),
			"Item size = %hu", INFO_ITEMSIZE(ntpp->mbz_itemsize));
		    break;

		default:
		    /* Unknown mode */
		    (void) sprintf(get_line((char *)(uintptr_t)ntp->li_vn_mode -
			dlc_header, 1),	"Mode    = %hu (%s)",
			ntp->li_vn_mode & NTPMODEMASK,
			show_mode(ntp->li_vn_mode & NTPMODEMASK));
		    break;
		}
	}

	return (fraglen);
}

char *
show_leap(int leap)
{
	switch (leap) {
	case NO_WARNING: return ("OK");
	case PLUS_SEC:	return ("add a second (61 seconds)");
	case MINUS_SEC: return ("minus a second (59 seconds)");
	case ALARM:	return ("alarm condition (clock unsynchronized)");
	default:	return ("unknown");
	}
}

char *
show_mode(int mode)
{
	switch (mode) {
	case MODE_UNSPEC:	return ("unspecified");
	case MODE_SYM_ACT:	return ("symmetric active");
	case MODE_SYM_PAS:	return ("symmetric passive");
	case MODE_CLIENT:	return ("client");
	case MODE_SERVER:	return ("server");
	case MODE_BROADCAST:	return ("broadcast");
	case MODE_CONTROL:	return ("control");
	case MODE_PRIVATE:	return ("private");
	default:		return ("unknown");
	}
}

char *
show_ref(int mode, ulong_t refid)
{
	static char buff[MAXHOSTNAMELEN + 32];
	struct in_addr host;
	extern char *inet_ntoa();

	switch (mode) {
	case 0:
	case 1:
		(void) strncpy(buff, (char *)&refid, 4);
		buff[4] = '\0';
		break;

	default:
		host.s_addr = refid;
		(void) sprintf(buff, "%s (%s)",
		    inet_ntoa(host),
		    addrtoname(AF_INET, &host));
		break;
	}

	return (buff);
}

/*
 *  Here we have to worry about the high order bit being signed
 */
double
s_fixed_to_double(struct s_fixedpt *t)
{
	double a;

	if (ntohs(t->int_part) & 0x8000) {
		a = ntohs((int)(~t->fraction) & 0xFFFF);
		a = a / 65536.0;	/* shift dec point over by 16 bits */
		a +=  ntohs((int)(~t->int_part) & 0xFFFF);
		a = -a;
	} else {
		a = ntohs(t->fraction);
		a = a / 65536.0;	/* shift dec point over by 16 bits */
		a += ntohs(t->int_part);
	}
	return (a);
}

/*
 * Consistent with RFC-3339, ISO 8601.
 */
char *
iso_date_time(time_t input_time)
{
	struct tm	*time_parts;
	static char	tbuf[sizeof ("yyyy-mm-dd hh:mm:ss")];

	time_parts = localtime(&input_time);
	(void) strftime(tbuf, sizeof (tbuf), "%Y-%m-%d %H:%M:%S", time_parts);
	return (tbuf);
}

/*
 * The base of NTP timestamps is 1900-01-01 00:00:00.00000
 */
char *
show_time(struct l_fixedpt pkt_time)
{
	struct l_fixedpt net_time;
	unsigned long	fracsec;
	static char	buff[32];

	if (pkt_time.int_part == 0) {
		buff[0] = '\0';
		return (buff);
	}

	net_time.int_part = ntohl(pkt_time.int_part) - JAN_1970;
	net_time.fraction = ntohl(pkt_time.fraction);

	fracsec = net_time.fraction / 42949;	/* fract / (2**32/10**6) */

	(void) snprintf(buff, sizeof (buff), "%s.%05lu",
	    iso_date_time(net_time.int_part), fracsec);

	return (buff);
}

char *
show_operation(int op)
{
	switch (op) {
	case CTL_OP_UNSPEC:	return ("unspecified");
	case CTL_OP_READSTAT:	return ("read stats");
	case CTL_OP_READVAR:	return ("read var");
	case CTL_OP_WRITEVAR:	return ("write var");
	case CTL_OP_READCLOCK:	return ("read clock");
	case CTL_OP_WRITECLOCK: return ("write clock");
	case CTL_OP_SETTRAP:	return ("set trap");
	case CTL_OP_ASYNCMSG:	return ("async msg");
	case CTL_OP_UNSETTRAP:	return ("unset trap");
	default:		return ("unknown");
	}
}
