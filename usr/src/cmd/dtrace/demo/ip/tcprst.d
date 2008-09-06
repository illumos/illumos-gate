#!/usr/sbin/dtrace -Cqs
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

#pragma D option dynvarsize=64m

#define TH_RST		0x04
#define MAX_RECORDS	10
#define M_CTL		0x0d

#define PRINT_MAIN_HEADER()						\
	(printf("\n%-25s %-6s %-25s %-6s %-10s %-10s %8s %8s\n",	\
	    "LADDR", "LPORT", "RADDR", "RPORT", "ISS", "IRS",		\
	    "SND_CNT", "RCV_CNT"))

#define PRINT_RECORD_HEADER()						\
	(printf("%-20s %-20s %-3s %15s %15s %8s %8s %5s\n",		\
	    "PROBENAME", "TIME", "S/R", "SEQ", "ACK", "DATALEN",	\
	    "WND", "FLAGS"))

#define PRINT_MAIN_HEADER_VALUES()					\
	(printf("%-25s %-6d %-25s %-6d %-10d %-10d %8d %8d\n",		\
	    laddr[self->conn_id], lport[self->conn_id],			\
	    faddr[self->conn_id], fport[self->conn_id],			\
	    iss[self->conn_id], irs[self->conn_id],			\
	    send_count[self->conn_id], recv_count[self->conn_id]))

#define PRINT_HEADER()							\
	PRINT_MAIN_HEADER(); PRINT_MAIN_HEADER_VALUES();		\
	    PRINT_RECORD_HEADER()

#define PRINT_RECORD(i)							\
	(printf("%-20s %-20Y %-3s %15d %15d %8d %8d %2x\n",		\
	    probe_name[self->conn_id, i],				\
	    conn_time[self->conn_id, i],				\
	    send_recv[self->conn_id, i],				\
	    seqno[self->conn_id, i],					\
	    ack[self->conn_id, i],					\
	    datalen[self->conn_id, i],					\
	    wnd[self->conn_id, i],					\
	    flags[self->conn_id, i]))

tcp-trace-*
{
	/* extract connection details */

	this->mp = (mblk_t *)arg0;
	this->mp = (this->mp->b_datap->db_type == M_CTL?
	    this->mp->b_cont : this->mp);
	self->tcpp = (tcp_t *)arg1;
	this->connp = (conn_t *)self->tcpp->tcp_connp;

	self->iph = (ipha_t *)this->mp->b_rptr;
	this->iph_length =
	    (int)(((ipha_t *)self->iph)->ipha_version_and_hdr_length
	    & 0xF) << 2;
	self->tcph = (tcpha_t *)((char *)self->iph + this->iph_length);
	this->tcph_length =
	    (((tcph_t *)self->tcph)->th_offset_and_rsrvd[0] >>2) &(0xF << 2);

	/* ports */
	self->i_lport = ntohs(this->connp->u_port.tcpu_ports.tcpu_lport);
	self->i_fport = ntohs(this->connp->u_port.tcpu_ports.tcpu_fport);

	/* IP addresses */
	this->i_fad = (in6_addr_t *)&this->connp->connua_v6addr.connua_faddr;
	this->i_lad = (in6_addr_t *)&this->connp->connua_v6addr.connua_laddr;

	/* the address would either be IPv6 or IPv4-mapped-IPv6  */
	self->i_faddr = inet_ntop(AF_INET6, (void *)this->i_fad);
	self->i_laddr = inet_ntop(AF_INET6, (void *)this->i_lad);

	/* create connection identifier, so we can track packets by conn */
	self->conn_id = (uint64_t)self->tcpp->tcp_connp;
}

tcp-trace-*
/first[self->conn_id] == 0/
{
	/* initialize counters - this is the first packet for this connection */
	pcount[self->conn_id] = -1;
	rollover[self->conn_id] = 0;
	end_ptr[self->conn_id] = 0;
	num[self->conn_id] = 0;

	first[self->conn_id] = 1;

	/* connection info */
	laddr[self->conn_id] = self->i_laddr;
	faddr[self->conn_id] = self->i_faddr;
	lport[self->conn_id] = self->i_lport;
	fport[self->conn_id] = self->i_fport;
	iss[self->conn_id] = self->tcpp->tcp_iss;
	irs[self->conn_id] = self->tcpp->tcp_irs;

}

tcp-trace-*
{
	/* counters, to keep track of how much info to dump */
	pcount[self->conn_id]++;
	rollover[self->conn_id] |= pcount[self->conn_id]/MAX_RECORDS;
	pcount[self->conn_id] = pcount[self->conn_id]%MAX_RECORDS;
	self->pcount = pcount[self->conn_id];
	end_ptr[self->conn_id] = self->pcount;
	num[self->conn_id] = (rollover[self->conn_id]?
	    MAX_RECORDS : pcount[self->conn_id] + 1);
	conn_time[self->conn_id, self->pcount] = walltimestamp;

	/* tcp state info */
	seqno[self->conn_id, self->pcount] = ntohl(self->tcph->tha_seq);
	ack[self->conn_id, self->pcount] = ntohl(self->tcph->tha_ack);
	datalen[self->conn_id, self->pcount] =  ntohs(self->iph->ipha_length);
	wnd[self->conn_id, self->pcount] =  ntohs(self->tcph->tha_win);
	probe_name[self->conn_id, self->pcount] = probename;

	/* flag 0x04 indicates a RST packet */
	flags[self->conn_id, self->pcount] = self->tcph->tha_flags;
	self->flags = self->tcph->tha_flags;
}

tcp-trace-send
{
	send_count[self->conn_id]++;
	send_recv[self->conn_id, self->pcount] = "S";
}

tcp-trace-recv
{
	recv_count[self->conn_id]++;
	send_recv[self->conn_id, self->pcount] = "R";
}

tcp-trace-*
/(self->flags & TH_RST)/
{
	PRINT_HEADER();

	self->i = (end_ptr[self->conn_id] + MAX_RECORDS - num[self->conn_id]
	    + 1)%MAX_RECORDS;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 10)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 9)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 8)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 7)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 6)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 5)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 4)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 3)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 2)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
}

tcp-trace-*
/(self->flags & TH_RST) && (num[self->conn_id] >= 1)/
{
	PRINT_RECORD(self->i);
	self->i = (self->i + 1)%MAX_RECORDS;

	num[self->conn_id]--;
	self->reset = self->conn_id;
}

tcp-trace-*
/self->reset/
{
	pcount[self->reset] = -1;
	rollover[self->reset] = 0;
	end_ptr[self->reset] = 0;
	num[self->reset] = 0;

	self->reset = 0;
}

conn-destroy
{
	/* clear old connection state */
	this->conn_id = (uint64_t)arg0;

	pcount[this->conn_id] = -1;
	rollover[this->conn_id] = 0;
	end_ptr[this->conn_id] = 0;
	num[this->conn_id] = 0;
	first[this->conn_id] = 0;

	laddr[this->conn_id] = 0;
	faddr[this->conn_id] = 0;
	lport[this->conn_id] = 0;
	fport[this->conn_id] = 0;
	iss[this->conn_id] = 0;
	irs[this->conn_id] = 0;
}
