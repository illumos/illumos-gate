/*	$NetBSD: bpf.h,v 1.50 2009/01/13 19:10:52 christos Exp $	*/

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
 *	@(#)bpf.h	8.2 (Berkeley) 1/9/95
 * @(#) Header: bpf.h,v 1.36 97/06/12 14:29:53 leres Exp  (LBL)
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NET_BPF_H_
#define	_NET_BPF_H_

#include <sys/time.h>
#include <sys/types32.h>
#include <sys/ioccom.h>

/* BSD style release date */
#define	BPF_RELEASE 199606

typedef	int bpf_int32;
typedef	uint_t bpf_uint_t32;
typedef	uint_t bpf_u_int32;

/*
 * Alignment macros.  BPF_WORDALIGN rounds up to the next
 * even multiple of BPF_ALIGNMENT.
 */
#define	BPF_ALIGNMENT sizeof (uint32_t)
#define	BPF_WORDALIGN(x) (((x)+(BPF_ALIGNMENT-1))&~(BPF_ALIGNMENT-1))

#define	BPF_MAXINSNS 512
#define	BPF_DFLTBUFSIZE (1024*1024)	/* default static upper limit */
#define	BPF_MAXBUFSIZE (1024*1024*16)	/* hard limit on sysctl'able value */
#define	BPF_MINBUFSIZE 32

/*
 *  Structure for BIOCSETF.
 */
struct bpf_program {
	uint_t bf_len;
	struct bpf_insn *bf_insns;
};
struct bpf_program32 {
	uint_t bf_len;
	caddr32_t bf_insns;
};

/*
 * Struct returned by BIOCGSTATS and net.bpf.stats sysctl.
 */
struct bpf_stat {
	uint64_t bs_recv;	/* number of packets received */
	uint64_t bs_drop;	/* number of packets dropped */
	uint64_t bs_capt;	/* number of packets captured */
	uint64_t bs_padding[13];
};

/*
 * Struct returned by BIOCGSTATSOLD.
 */
struct bpf_stat_old {
	uint_t bs_recv;		/* number of packets received */
	uint_t bs_drop;		/* number of packets dropped */
};

/*
 * Struct return by BIOCVERSION.  This represents the version number of
 * the filter language described by the instruction encodings below.
 * bpf understands a program iff kernel_major == filter_major &&
 * kernel_minor >= filter_minor, that is, if the value returned by the
 * running kernel has the same major number and a minor number equal
 * equal to or less than the filter being downloaded.  Otherwise, the
 * results are undefined, meaning an error may be returned or packets
 * may be accepted haphazardly.
 * It has nothing to do with the source code version.
 */
struct bpf_version {
	ushort_t bv_major;
	ushort_t bv_minor;
};
/* Current version number of filter architecture. */
#define	BPF_MAJOR_VERSION 1
#define	BPF_MINOR_VERSION 1

/*
 * BPF ioctls
 *
 * The first set is for compatibility with Sun's pcc style
 * header files.  If your using gcc, we assume that you
 * have run fixincludes so the latter set should work.
 */
#define	BIOCGBLEN	 _IOR('B', 102, uint_t)
#define	BIOCSBLEN	_IOWR('B', 102, uint_t)
#define	BIOCSETF	 _IOW('B', 103, struct bpf_program)
#define	BIOCFLUSH	  _IO('B', 104)
#define	BIOCPROMISC	  _IO('B', 105)
#define	BIOCGDLT	 _IOR('B', 106, uint_t)
#define	BIOCGETIF	 _IOR('B', 107, struct ifreq)
#define	BIOCGETLIF	 _IOR('B', 107, struct lifreq)
#define	BIOCSETIF	 _IOW('B', 108, struct ifreq)
#define	BIOCSETLIF	 _IOW('B', 108, struct lifreq)
#define	BIOCGSTATS	 _IOR('B', 111, struct bpf_stat)
#define	BIOCGSTATSOLD	 _IOR('B', 111, struct bpf_stat_old)
#define	BIOCIMMEDIATE	 _IOW('B', 112, uint_t)
#define	BIOCVERSION	 _IOR('B', 113, struct bpf_version)
#define	BIOCSTCPF	 _IOW('B', 114, struct bpf_program)
#define	BIOCSUDPF	 _IOW('B', 115, struct bpf_program)
#define	BIOCGHDRCMPLT	 _IOR('B', 116, uint_t)
#define	BIOCSHDRCMPLT	 _IOW('B', 117, uint_t)
#define	BIOCSDLT	 _IOW('B', 118, uint_t)
#define	BIOCGDLTLIST	_IOWR('B', 119, struct bpf_dltlist)
#define	BIOCGSEESENT	 _IOR('B', 120, uint_t)
#define	BIOCSSEESENT	 _IOW('B', 121, uint_t)
#define	BIOCSRTIMEOUT	 _IOW('B', 122, struct timeval)
#define	BIOCGRTIMEOUT	 _IOR('B', 123, struct timeval)
/*
 */
#define	BIOCSETF32	 _IOW('B', 103, struct bpf_program32)
#define	BIOCGDLTLIST32	_IOWR('B', 119, struct bpf_dltlist32)
#define	BIOCSRTIMEOUT32	 _IOW('B', 122, struct timeval32)
#define	BIOCGRTIMEOUT32	 _IOR('B', 123, struct timeval32)

/*
 * Structure prepended to each packet. This is "wire" format, so we
 * cannot change it unfortunately to 64 bit times on 32 bit systems [yet].
 */
struct bpf_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};

struct bpf_hdr {
	struct bpf_timeval bh_tstamp;	/* time stamp */
	uint32_t	bh_caplen;	/* length of captured portion */
	uint32_t	bh_datalen;	/* original length of packet */
	uint16_t	bh_hdrlen;	/* length of bpf header (this struct */
					/*  plus alignment padding) */
};
/*
 * Because the structure above is not a multiple of 4 bytes, some compilers
 * will insist on inserting padding; hence, sizeof(struct bpf_hdr) won't work.
 * Only the kernel needs to know about it; applications use bh_hdrlen.
 * XXX To save a few bytes on 32-bit machines, we avoid end-of-struct
 * XXX padding by using the size of the header data elements.  This is
 * XXX fail-safe: on new machines, we just use the 'safe' sizeof.
 */
#ifdef _KERNEL
#if defined(__arm32__) || defined(__i386__) || defined(__m68k__) || \
    defined(__mips__) || defined(__ns32k__) || defined(__vax__) || \
    defined(__sh__) || (defined(__sparc__) && !defined(__sparc64__))
#define	SIZEOF_BPF_HDR 18
#else
#define	SIZEOF_BPF_HDR sizeof (struct bpf_hdr)
#endif
#endif

/* Pull in data-link level type codes. */
#include <net/dlt.h>

/*
 * The instruction encodings.
 */
/* instruction classes */
#define	BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC	0x07

/* ld/ldx fields */
#define	BPF_SIZE(code)	((code) & 0x18)
#define		BPF_W		0x00
#define		BPF_H		0x08
#define		BPF_B		0x10
#define	BPF_MODE(code)	((code) & 0xe0)
#define		BPF_IMM 	0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define	BPF_OP(code)	((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET	0x40
#define	BPF_SRC(code)	((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

/* ret - BPF_K and BPF_X also apply */
#define	BPF_RVAL(code)	((code) & 0x18)
#define		BPF_A		0x10

/* misc */
#define	BPF_MISCOP(code) ((code) & 0xf8)
#define		BPF_TAX		0x00
#define		BPF_TXA		0x80

/*
 * The instruction data structure.
 */
struct bpf_insn {
	uint16_t  code;
	uint8_t   jt;
	uint8_t   jf;
	uint32_t  k;
};

/*
 * Macros for insn array initializers.
 */
#define	BPF_STMT(code, k) { (uint16_t)(code), 0, 0, k }
#define	BPF_JUMP(code, k, jt, jf) { (uint16_t)(code), jt, jf, k }

/*
 * Structure to retrieve available DLTs for the interface.
 */
struct bpf_dltlist {
	uint_t	bfl_len;	/* number of bfd_list array */
	uint_t	*bfl_list;	/* array of DLTs */
};
struct bpf_dltlist32 {
	uint_t	bfl_len;
	caddr32_t bfl_list;
};

#ifdef _KERNEL
#include <sys/mac.h>
#include <sys/dls_impl.h>

typedef void (*bpf_itap_fn_t)(void *, mblk_t *, boolean_t, uint_t);

extern void	bpfattach(uintptr_t, int, zoneid_t, int);
extern void	bpfdetach(uintptr_t);
extern uint_t	bpf_filter(struct bpf_insn *, uchar_t *, uint_t, uint_t);
extern void	bpf_itap(void *, mblk_t *, boolean_t, uint_t);
extern void	bpf_mtap(void *, mac_resource_handle_t, mblk_t *, boolean_t);
extern int	bpf_validate(struct bpf_insn *, int);

#endif /* _KERNEL */

/*
 * Number of scratch memory words (for BPF_LD|BPF_MEM and BPF_ST).
 */
#define	BPF_MEMWORDS 16

#endif /* !_NET_BPF_H_ */
