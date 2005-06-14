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
 * Copyright 1998, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <sys/log.h>
#include <sys/time.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <netinet/in.h>

#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/tcp_trace.h>
#include <inet/ip6.h>
#include <inet/ipclassifier.h>

void	    tcp_record_trace(tcp_t *tcp, mblk_t *mp, int flag);
static void make_digit(char *wbuf, uint_t cookie, uint_t base, uint_t scl);
static void event_format(char *clbp, hrtime_t gap, tcptrcrec_t *evts);
static void tcp_report_trace(tcp_t *tcp, tcptrch_t *traceinfo);


/*
 * Get TCP trace buffer address.
 */
#define	TCP_TRACEINFO_ADDR(tcp)	  ((tcptrch_t *)((tcp)->tcp_tracebuf))

/*
 * Get TCP module id.
 * NOTE: TCP module id is defined in tcp.c.
 */
#define	TCP_MODULE_ID(tcp)	((tcp)->tcp_rq->q_qinfo->qi_minfo->mi_idnum)

/*
 * MAKE_DIGIT(), and its friend, MAKE_DIGIT_20() format an unsigned integer
 * value (cookie) into a buffer, taking base into account.  Their behavior is
 * quite similar to sprintf(buf, "%u", cookie) or sprintf(buf, "%x", cookie).
 *
 * The string is assumed to contain '0's in the appropriate places, so we need
 * only call make_digit() when cookie has a nonzero value.
 */
#define	MAKE_DIGIT(buf, cookie, base, scale) {		\
	if (cookie) {					\
		make_digit(buf, cookie, base, scale);	\
	}						\
}

/*
 * Both IP header length which has no optional field (IP_SIMPLE_HDR_LENGTH)
 * and TCP header length which has no optional field (TCP_MIN_HEADER_LENGTH)
 * are 20(0x14) bytes so we set the default value (0x14) in the initial buffer
 * call make_digit() only when necessary.
 */
#define	MAKE_DIGIT_20(buf, cookie, base, scale) {	\
	if (cookie != TCP_MIN_HEADER_LENGTH) {		\
		make_digit(buf, cookie, base, scale);	\
	}						\
}


/*
 * Tracing a send/recive packet.
 */
void
tcp_record_trace(tcp_t *tcp, mblk_t *mp, int flag)
{
	ipha_t			*iph;
	int			 iph_length;
	tcpha_t			*tcph;
	int			 tcph_length;
	uint8_t			 tcph_flags;
	int			 trace_rec_pos;
	struct tcp_trace_header *traceinfo;
	struct tcp_trace_rec    *trace_evt_p;

	/*
	 * XXX This module currently has no support for IPv6.
	 * XXX It explicitly assumes IPv4 and will panic the system
	 * XXX while tracing v6 connections if it explicitly dereferences
	 * XXX the tcp_t's NULL pointer to the IPv4 tcp/ip header template.
	 * XXX
	 * XXX To avoid this until v6 support is added,
	 * XXX return immediately if tcp->tcp_ipversion == IPV6_VERSION
	 */
	if (tcp->tcp_ipversion == IPV6_VERSION)
		return;

	/*
	 * If this is a segment needing TCP-directed IPsec protection
	 * (e.g. a segment from a detached connection), make sure the
	 * IPsec info is bypassed for tracing.
	 */
	if (mp->b_datap->db_type == M_CTL)
		mp = mp->b_cont;

	traceinfo = TCP_TRACEINFO_ADDR(tcp);

	ASSERT((flag == TCP_TRACE_SEND_PKT) || (flag == TCP_TRACE_RECV_PKT));
	if (flag == TCP_TRACE_SEND_PKT) {
		traceinfo->tcptrh_send_total++;
	} else {
		/*  TCP_TRACE_RECV_PKT */
		traceinfo->tcptrh_recv_total++;
	}

	trace_rec_pos = traceinfo->tcptrh_currec;
	trace_evt_p = &traceinfo->tcptrh_evts[trace_rec_pos];

	iph = (ipha_t *)mp->b_rptr;
	iph_length = IPH_HDR_LENGTH(iph);
	tcph = (tcpha_t *)((char *)iph + iph_length);
	tcph_length = TCP_HDR_LENGTH((tcph_t *)tcph);
	tcph_flags = tcph->tha_flags;

	trace_evt_p->tcptr_tcp_seq = tcph->tha_seq;
	trace_evt_p->tcptr_tcp_ack = tcph->tha_ack;
	trace_evt_p->tcptr_iotime = gethrtime();
	trace_evt_p->tcptr_tcp_data = iph->ipha_length;
	trace_evt_p->tcptr_tcp_win = tcph->tha_win;
	trace_evt_p->tcptr_pkttype = (uint8_t)flag;
	trace_evt_p->tcptr_ip_hdr_len = (uint8_t)iph_length;
	trace_evt_p->tcptr_tcp_hdr_len = (uint8_t)tcph_length;
	trace_evt_p->tcptr_tcp_flags[0] = tcph_flags;

	/*
	 * When the RST packet is transmitted or received,
	 * information on as many as 10 packets which were
	 * transmited or received is saved on the DISK by
	 * calling tcp_report_trace().
	 */
	if (tcph_flags & TH_RST) {
		tcp_report_trace(tcp, traceinfo);
	}

	if (++trace_rec_pos == TCP_TRACE_NREC) {
		trace_rec_pos = 0;
	}
	traceinfo->tcptrh_currec = trace_rec_pos;
}


/*
 * TCP trace output data fromat.
 *
 * char logbuf[] = \
 *     01234567
 *    "TCP TAS\n
 *    8901234567890123456789012345678901234567890123456789012345678901234
 *         Local 000.000.000.000:00000 <--> Remote 000.000.000.000:00000\n\
 *    567890123456789012345678901234567890123456789012345678901234567
 *         Conn time 0000/00/00 00:00:00 GMT. Wscale snd 00. rcv 00.\n\
 *    8901234567890123456789012345678901234567890123456789012345678901234567
 *         iss 00000000, irs 00000000. Pcnt snd 0000000000. rcv 0000000000.\n\
 *    8901234567890123456789012345678901234567890123456789012345678901234
 *         Time         Snd/Rcv seq      ack      data win  ip tcp flags\n
 *    56789012345678901234567890123456789012345678901234567890123456789
 *         00:00:00.000.000  R  00000000 00000000 0000 0000 00 00  00\n"
 */
static const char log_format[] = \
"TCP RAS\n" \
"     Local 000.000.000.000:00000 <--> Remote 000.000.000.000:00000\n" \
"     Conn time 0000/00/00 00:00:00 GMT. Wscale snd 00. rcv 00.\n" \
"     iss 00000000, irs 00000000. Pcnt snd 0000000000. rcv 0000000000.\n" \
"     Time         Snd/Rcv seq      ack      data win  ip tcp flags\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n" \
"     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n";

/*
 * Offset (within the log_format string) of the beginning of tcp_t and
 * tcp_trace_header data.  For example,
 *
 * "     Local 000.000.000.000:00000 <--> Remote 000.000.000.000:00000\n"
 *	       ^	       ^
 *	       |	       |
 * &log_format[LOC_IPADDR]     |
 *			&log_format[LOC_PORTN]
 * and so on.
 *
 * N.B.:  these values are truly hardwired and the danger in changing them is
 *	  extreme, since they are used directly as offsets into which bytes of
 *	  formatted data are stuffed.
 */
#define	LOC_IPADDR	 19	/* Local host's IP Address	   */
#define	LOC_PORTN	 35	/* Local host's port		   */
#define	REM_IPADDR	 53	/* Remote hosts's IP Address	   */
#define	REM_PORTN	 69	/* Remote hosts's port		   */
#define	CON_DATE	 90	/* Connection established date	   */
#define	CON_TIME	101	/* Connection established time	   */
#define	WSCAL_SND	126	/* Send WSCALE ?		   */
#define	WSCAL_RCV	134	/* Received WSCALE ?		   */
#define	ISS		147	/* Initial send sequence number	   */
#define	IRS		161	/* Initial receive sequence number */
#define	PCNT_SND	180	/* Total send packet number	   */
#define	PCNT_RCV	196	/* Total receive packet number	   */
#define	TRC_DATA	275	/* Top of each packet's field	   */

/*
 * Offset (within a single trace line) of tcp_trace_rec data.  For example, in
 * this line,
 *
 * "     00:00:00.000.000  R  00000000 00000000 0000 0000 14 14  00\n";
 *  ----->					this length is TRC_DATA_TIME
 *  ----------------------->			this length is TRC_DATA_SR
 *
 * and so on.
 *
 * N.B.:  these values are truly hardwired and the danger in changing them is
 *	  extreme, since they are used directly as offsets into which bytes of
 *	  formatted data are stuffed.
 */
#define	TRCLINESIZE	64	/* Size of each packets field	*/
#define	TRC_DATA_TIME	 5	/* Packet send/receive time	*/
#define	TRC_DATA_SR	23	/* Send/Receive flag		*/
#define	TRC_DATA_SEQ	26	/* Sequence number		*/
#define	TRC_DATA_ACK	35	/* Acknowledge number		*/
#define	TRC_DATA_DATA	44	/* TCP data size		*/
#define	TRC_DATA_WIN	49	/* Window size			*/
#define	TRC_DATA_IP	54	/* IP header size		*/
#define	TRC_DATA_TCP	57	/* TCP header size		*/
#define	TRC_DATA_FLAG	61	/* TCP flags			*/

#define	B_HEX		16	/* trace as hexadecimal number	*/
#define	B_DEC		10	/* trace as decimal naumber	*/


/*
 * Make printable trace data and log it using strlog().
 */
static void
tcp_report_trace(tcp_t *tcp, tcptrch_t *traceinfo)
{
	short		sid = 0;
	short		mid = 0;
	hrtime_t	gap_time;	/* from gethrtime() to gethrestime() */
	hrtime_t	cur_hrtime;
	hrtime_t	conn_hrtime;
	timespec_t	conn_tstime;
	timespec_t	cur_ts;
	todinfo_t	conn_todtime;
	char		logbuf[sizeof (log_format) + 1];
	char		*cur_logbuf_ptr;
	int		cur_pos;
	int		rec_no;
	int		nrecords;	/* # of packet trace lines to print */
	int		rec_start;	/* where to start in evts[] array */

	cur_hrtime = gethrtime();
	gethrestime(&cur_ts);
	gap_time = ts2hrt(&cur_ts) - cur_hrtime;	/* Boot time */

	/*
	 * trace report header construct
	 */

	/* Initialize log format data */
	bcopy(log_format, logbuf, sizeof (log_format));

	/* Local IP address */
	MAKE_DIGIT(&logbuf[LOC_IPADDR],
	    ((uchar_t *)&tcp->tcp_ipha->ipha_src)[0], B_DEC, 3);
	MAKE_DIGIT(&logbuf[LOC_IPADDR + 4],
	    ((uchar_t *)&tcp->tcp_ipha->ipha_src)[1], B_DEC, 3);
	MAKE_DIGIT(&logbuf[LOC_IPADDR + 8],
	    ((uchar_t *)&tcp->tcp_ipha->ipha_src)[2], B_DEC, 3);
	MAKE_DIGIT(&logbuf[LOC_IPADDR +12],
	    ((uchar_t *)&tcp->tcp_ipha->ipha_src)[3], B_DEC, 3);

	/* Local Port number */
	MAKE_DIGIT(&logbuf[LOC_PORTN], tcp->tcp_lport, B_DEC, 5);

	/* Remote IP address */
	MAKE_DIGIT(&logbuf[REM_IPADDR],
	    ((uchar_t *)&tcp->tcp_ipha->ipha_dst)[0], B_DEC, 3);
	MAKE_DIGIT(&logbuf[REM_IPADDR + 4],
	    ((uchar_t *)&tcp->tcp_ipha->ipha_dst)[1], B_DEC, 3);
	MAKE_DIGIT(&logbuf[REM_IPADDR + 8],
	    ((uchar_t *)&tcp->tcp_ipha->ipha_dst)[2], B_DEC, 3);
	MAKE_DIGIT(&logbuf[REM_IPADDR +12],
	    ((uchar_t *)&tcp->tcp_ipha->ipha_dst)[3], B_DEC, 3);

	/* Remote Port number */
	MAKE_DIGIT(&logbuf[REM_PORTN], tcp->tcp_fport, B_DEC, 5);

	/* Connection date & time */
	conn_hrtime = gap_time + traceinfo->tcptrh_conn_time;
	hrt2ts(conn_hrtime, &conn_tstime);
	mutex_enter(&tod_lock);
	conn_todtime = utc_to_tod(conn_tstime.tv_sec);
	mutex_exit(&tod_lock);

	MAKE_DIGIT(&logbuf[CON_DATE], (conn_todtime.tod_year)+1900, B_DEC, 4);
	MAKE_DIGIT(&logbuf[CON_DATE + 5], conn_todtime.tod_month, B_DEC, 2);
	MAKE_DIGIT(&logbuf[CON_DATE + 8], conn_todtime.tod_day, B_DEC, 2);
	MAKE_DIGIT(&logbuf[CON_TIME], conn_todtime.tod_hour, B_DEC, 2);
	MAKE_DIGIT(&logbuf[CON_TIME + 3], conn_todtime.tod_min, B_DEC, 2);
	MAKE_DIGIT(&logbuf[CON_TIME + 6], conn_todtime.tod_sec, B_DEC, 2);

	/* Wscale snd & rcv */
	MAKE_DIGIT(&logbuf[WSCAL_SND], tcp->tcp_snd_ws, B_DEC, 2);
	MAKE_DIGIT(&logbuf[WSCAL_RCV], tcp->tcp_rcv_ws, B_DEC, 2);

	/* Initial send seq number */
	MAKE_DIGIT(&logbuf[ISS], tcp->tcp_iss, B_HEX, 8);

	/* Initial recv seq number */
	MAKE_DIGIT(&logbuf[IRS], tcp->tcp_irs, B_HEX, 8);

	/* total traced sent packets */
	MAKE_DIGIT(&logbuf[PCNT_SND], traceinfo->tcptrh_send_total, B_DEC, 10);

	/* total traced recv packets */
	MAKE_DIGIT(&logbuf[PCNT_RCV], traceinfo->tcptrh_recv_total, B_DEC, 10);

	cur_logbuf_ptr = &logbuf[TRC_DATA];

	/*
	 * The evts[] array contains information about up to TCP_TRACE_NREC
	 * packets.  We assume that the information is either recorded in
	 * slots 0 through traceinfo->tcptrh_currec (in which case, slots
	 * traceinfo->tcptrh_currec + 1 through TCP_TRACE_NREC - 1 must be
	 * unused) or wraparound has occurred and all TCP_TRACE_NREC slots
	 * are in use.
	 */
	cur_pos = traceinfo->tcptrh_currec + 1;
	if ((cur_pos < TCP_TRACE_NREC) &&
	    (traceinfo->tcptrh_evts[cur_pos].tcptr_pkttype ==
	    TCP_TRACE_NOENT)) {
		/* Log records 0 through traceinfo->tcptrh_currec */
		nrecords = cur_pos;
		rec_start = 0;
#ifdef	DEBUG
		/* test the assumption outlined above */
		for (rec_no = cur_pos; rec_no < TCP_TRACE_NREC; rec_no++) {
			ASSERT(traceinfo->tcptrh_evts[rec_no].tcptr_pkttype ==
			    TCP_TRACE_NOENT);
		}
#endif	/* DEBUG */
	} else {
		/*
		 * Log TCP_TRACE_NREC records starting at
		 * traceinfo->tcptrh_currec + 1, wrapping,
		 * and ending at traceinfo->tcptrh_currec
		 */
		nrecords = TCP_TRACE_NREC;
		rec_start = traceinfo->tcptrh_currec + 1;
	}

	for (rec_no = 0; rec_no < nrecords; rec_no++) {
		cur_pos = (rec_start + rec_no) % TCP_TRACE_NREC;
		ASSERT(traceinfo->tcptrh_evts[rec_no].tcptr_pkttype !=
		    TCP_TRACE_NOENT);
		event_format(cur_logbuf_ptr, gap_time,
		    &traceinfo->tcptrh_evts[cur_pos]);
		cur_logbuf_ptr += TRCLINESIZE;
	}

	/* overwrite last '\n' */
	*(cur_logbuf_ptr - 1) = '\0';

	/*
	 * We use strlog() to log trace data. mi_strlog()'s buffer
	 * size is only 200 bytes. We need more than 928 bytes buffer.
	 * strlog() has 1024 bytes buffer, so we use strlog().
	 */
	mid = TCP_MODULE_ID(tcp);
	(void) strlog(mid, sid, 0, SL_TRACE|SL_ERROR, logbuf);
}


/*
 * Formatting event data.
 */
static void
event_format(char *logbufp, hrtime_t gap, tcptrcrec_t *evts)
{
	hrtime_t   trc_hrtime;
	timespec_t trc_tstime;
	todinfo_t  trc_todtime;
	int32_t	   trc_msec, trc_usec;

	/*
	 * calculate trace time
	 */
	trc_hrtime = evts->tcptr_iotime + gap;
	hrt2ts(trc_hrtime, &trc_tstime);
	mutex_enter(&tod_lock);
	trc_todtime = utc_to_tod(trc_tstime.tv_sec);
	mutex_exit(&tod_lock);
	trc_msec = trc_tstime.tv_nsec / 1000000;
	trc_usec = (trc_tstime.tv_nsec / 1000) % 1000;

	/*
	 * Time
	 * NOTE: The separators of time field which are ":" and "." are
	 *	 statically set in buffer.
	 */
	MAKE_DIGIT(logbufp + TRC_DATA_TIME, trc_todtime.tod_hour, B_DEC, 2);
	MAKE_DIGIT(logbufp + TRC_DATA_TIME + 3, trc_todtime.tod_min, B_DEC, 2);
	MAKE_DIGIT(logbufp + TRC_DATA_TIME + 6, trc_todtime.tod_sec, B_DEC, 2);
	MAKE_DIGIT(logbufp + TRC_DATA_TIME + 9, trc_msec, B_DEC, 3);
	MAKE_DIGIT(logbufp + TRC_DATA_TIME + 13, trc_usec, B_DEC, 3);

	/*
	 * Event (Send or Recv flag)
	 * NOTE: The default value of event field is "R"
	 *	 which is statically set in buffer.
	 */
	if (evts->tcptr_pkttype == TCP_TRACE_SEND_PKT) {
		*(logbufp+TRC_DATA_SR) = 'S';
	}

	/*
	 * Sequence number, Acknowledge number, Packet data length,
	 * and Window size
	 */
	MAKE_DIGIT(logbufp + TRC_DATA_SEQ,
	    ABE32_TO_U32(&evts->tcptr_tcp_seq), B_HEX, 8);
	MAKE_DIGIT(logbufp + TRC_DATA_ACK,
	    ABE32_TO_U32(&evts->tcptr_tcp_ack), B_HEX, 8);
	MAKE_DIGIT(logbufp + TRC_DATA_DATA,
	    ABE16_TO_U16(&evts->tcptr_tcp_data) -
	    (uint16_t)evts->tcptr_ip_hdr_len -
	    (uint16_t)evts->tcptr_tcp_hdr_len, B_HEX, 4);
	MAKE_DIGIT(logbufp + TRC_DATA_WIN,
		ABE16_TO_U16(&evts->tcptr_tcp_win), B_HEX, 4);

	/*
	 * IP and TCP Header length
	 */
	MAKE_DIGIT_20(logbufp + TRC_DATA_IP, evts->tcptr_ip_hdr_len, B_HEX, 2);
	MAKE_DIGIT_20(logbufp + TRC_DATA_TCP, evts->tcptr_tcp_hdr_len, B_HEX,
	    2);

	/*
	 * Control flags
	 */
	MAKE_DIGIT(logbufp + TRC_DATA_FLAG, evts->tcptr_tcp_flags[0], B_HEX, 2);

	/*
	 * NOTE: Newline code "\n" per lines are statically set in buffer.
	 */
}


/*
 * make_digit() formats an unsigned integer value (cookie) into a buffer,
 * taking base into account.  Its behavior is quite similar to
 * sprintf(buf, "%u", cookie) or sprintf(buf, "%x", cookie).
 */
static void
make_digit(char *wbuf, uint_t cookie, uint_t base, uint_t scale)
{
	static char hex_val[] = "0123456789abcdef";

	wbuf += (scale - 1);

	do {
		*wbuf-- = hex_val[cookie % base];
		if (--scale == 0) {
			break;
		}
	} while (cookie /= base);
}
