/*	$NetBSD: bpfdesc.h,v 1.29 2009/03/14 14:46:10 dsl Exp $	*/

/*
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 *	@(#)bpfdesc.h	8.1 (Berkeley) 6/10/93
 *
 * @(#) Header: bpfdesc.h,v 1.14 96/06/16 22:28:07 leres Exp  (LBL)
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NET_BPFDESC_H_
#define	_NET_BPFDESC_H_

#include <net/if.h>			/* for IFNAMSIZ */
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/queue.h>

/*
 * Access to "layer 2" networking is provided through each such provider
 * delcaring a set of functions to use in the structure below. It has been
 * modeled around what's required to use the mac layer. All of the functions
 * below must be declared, even if only filled by a stub function.
 */
typedef struct bpf_provider_s {
	int		bpr_unit;
	int		(*bpr_open)(const char *, uintptr_t *, zoneid_t);
	void		(*bpr_close)(uintptr_t);
	const char 	*(*bpr_name)(uintptr_t);
	int		(*bpr_type)(uintptr_t);
	void		(*bpr_sdu_get)(uintptr_t, uint_t *);
	int		(*bpr_tx)(uintptr_t, mblk_t *);
	uintptr_t	(*bpr_promisc_add)(uintptr_t, int, void *, uintptr_t *,
			    int);
	void		(*bpr_promisc_remove)(uintptr_t);
	int		(*bpr_getlinkid)(const char *, datalink_id_t *,
			    zoneid_t);
	void		(*bpr_client_close)(uintptr_t);
	const char 	*(*bpr_client_name)(uintptr_t);
	int		(*bpr_client_open)(uintptr_t, uintptr_t *);
	int		(*bpr_getzone)(uintptr_t, zoneid_t *);
	int		(*bpr_getdlt)(uintptr_t, uint_t *);
} bpf_provider_t;

typedef struct bpf_provider_list {
	LIST_ENTRY(bpf_provider_list)	bpl_next;
	bpf_provider_t			*bpl_what;
} bpf_provider_list_t;

/*
 * The bpr_field from bpf_provider_t expects an integer that comes from
 * the list of defines below.
 */
#define	BPR_MAC		1
#define	BPR_IPNET	2

#define	MBPF_OPEN(_m, _n, _p, _z)	(_m)->bpr_open(_n, (uintptr_t *)_p, _z)
#define	MBPF_CLOSE(_m, _h)		(_m)->bpr_close(_h)
#define	MBPF_NAME(_m, _h)		(_m)->bpr_name(_h)
#define	MBPF_TYPE(_m, _h)		(_m)->bpr_type(_h)
#define	MBPF_SDU_GET(_m, _h, _p)	(_m)->bpr_sdu_get(_h, _p)
#define	MBPF_TX(_m, _h, _pkt)		(_m)->bpr_tx(_h, _pkt)
#define	MBPF_PROMISC_ADD(_m, _h, _o, _d, _p, _f) \
				(_m)->bpr_promisc_add(_h, _o, _d, _p, _f)
#define	MBPF_PROMISC_REMOVE(_m, _h)	(_m)->bpr_promisc_remove(_h)
#define	MBPF_GET_LINKID(_m, _n, _ip, _z) \
					(_m)->bpr_getlinkid(_n, _ip, _z)
#define	MBPF_CLIENT_CLOSE(_m, _h)	(_m)->bpr_client_close(_h)
#define	MBPF_CLIENT_NAME(_m, _h)	(_m)->bpr_client_name(_h)
#define	MBPF_CLIENT_OPEN(_m, _h, _p)	(_m)->bpr_client_open((uintptr_t)_h, \
					    (uintptr_t *)_p)
#define	MBPF_GET_ZONE(_m, _h, _zp)	(_m)->bpr_getzone(_h, _zp)
#define	MBPF_GET_DLT(_m, _h, _dp)	(_m)->bpr_getdlt(_h, _dp);
#define	MBPF_GET_HDRLEN(_m, _h, _dp)	(_m)->bpr_gethdrlen(_h, _dp);


/*
 * Descriptor associated with each open bpf file.
 */
struct bpf_d {
	LIST_ENTRY(bpf_d) bd_list;	/* List of bpf_d */
	LIST_ENTRY(bpf_d) bd_next;	/* List attaced to bif_if */
	/*
	 * Buffer slots: two mbuf clusters buffer the incoming packets.
	 *   The model has three slots.  Sbuf is always occupied.
	 *   sbuf (store) - Receive interrupt puts packets here.
	 *   hbuf (hold) - When sbuf is full, put cluster here and
	 *		   wakeup read (replace sbuf with fbuf).
	 *   fbuf (free) - When read is done, put cluster here.
	 * On receiving, if sbuf is full and fbuf is 0, packet is dropped.
	 */
	void *		bd_sbuf;	/* store slot */
	void *		bd_hbuf;	/* hold slot */
	void *		bd_fbuf;	/* free slot */
	int 		bd_slen;	/* current length of store buffer */
	int 		bd_hlen;	/* current length of hold buffer */

	int		bd_bufsize;	/* absolute length of buffers */

	uintptr_t 	bd_bif;		/* interface pointer */
	ulong_t		bd_rtout;	/* Read timeout in 'ticks' */
	struct bpf_insn *bd_filter; 	/* filter code */
	size_t		bd_filter_size;
	ulong_t		bd_rcount;	/* number of packets received */
	ulong_t		bd_dcount;	/* number of packets dropped */
	ulong_t		bd_ccount;	/* number of packets captured */

	uchar_t		bd_promisc;	/* true if listening promiscuously */
	uchar_t		bd_state;	/* idle, waiting, or timed out */
	uchar_t		bd_immediate;	/* true to return on packet arrival */
	int		bd_hdrcmplt;	/* false to fill in src lladdr */
	int		bd_seesent;	/* true if bpf should see sent pkts */
	int		bd_async;	/* non-zero if packet reception .. */
					/* .. should generate signal */
	int		bd_nonblock;	/* non-zero for non-blocking read */
	pid_t		bd_pgid;	/* process or group id for signal */
	int		bd_timedout;
	timeout_id_t	bd_callout;	/* for BPF timeouts with select */
	pid_t		bd_pid;		/* corresponding PID */
	void		*bd_sih;	/* soft interrupt handle */
	/*
	 * Solaris specific bits after this.
	 */
	kmutex_t	bd_lock;
	kcondvar_t	bd_wait;
	uintptr_t	bd_mh;		/* where mac_handle gets put */
	uintptr_t	bd_mcip;	/* Where mac_client_handle_t gets put */
	uintptr_t	bd_promisc_handle;
	minor_t		bd_dev;		/* device number for this handle */
	int		bd_fmode;	/* flags from bpfopen */
	zoneid_t	bd_zone;	/* zoneid of the opening process */
	int		bd_inuse;
	int		bd_waiting;
	char		bd_ifname[LIFNAMSIZ];
	int		bd_dlt;
	int		bd_hdrlen;
	bpf_provider_t	bd_mac;
	datalink_id_t	bd_linkid;
	/*
	 * bd_promisc_flags is used to store the promiscuous state of the
	 * the interface in BPF so that the correct mode of operation can
	 * be kept across changing DLT or network interface.
	 */
	int		bd_promisc_flags;
};


/* Values for bd_state */
#define	BPF_IDLE	0		/* no select in progress */
#define	BPF_WAITING	1		/* waiting for read timeout in select */
#define	BPF_TIMED_OUT	2		/* read timeout has expired in select */

/*
 * Description associated with the external representation of each
 * open bpf file.
 */
struct bpf_d_ext {
	int32_t		bde_bufsize;
	uint8_t		bde_promisc;
	uint8_t		bde_state;
	uint8_t		bde_immediate;
	int32_t		bde_hdrcmplt;
	int32_t		bde_seesent;
	pid_t		bde_pid;
	uint64_t	bde_rcount;		/* number of packets received */
	uint64_t	bde_dcount;		/* number of packets dropped */
	uint64_t	bde_ccount;		/* number of packets captured */
	char		bde_ifname[IFNAMSIZ];
};

#ifdef _KERNEL
typedef struct bpf_kstats_s {
	kstat_named_t	kp_read_wait;
	kstat_named_t	kp_write_ok;
	kstat_named_t	kp_write_error;
	kstat_named_t	kp_receive;
	kstat_named_t	kp_capture;
	kstat_named_t	kp_dropped;
} bpf_kstats_t;

int	 bpf_setf(struct bpf_d *, struct bpf_program *);
#endif

typedef void	(*bpf_attach_fn_t)(uintptr_t, int, zoneid_t, int);
typedef void	(*bpf_detach_fn_t)(uintptr_t);
typedef int	(*bpf_provider_reg_fn_t)(bpf_provider_t *);
typedef	LIST_HEAD(, bpf_provider_list) bpf_provider_head_t;

extern bpf_provider_t	*bpf_find_provider_by_id(int);
extern int		bpf_provider_tickle(char *, zoneid_t);
extern bpf_provider_head_t bpf_providers;

#endif /* !_NET_BPFDESC_H_ */
