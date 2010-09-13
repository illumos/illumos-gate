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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_CPU_SGN_H
#define	_CPU_SGN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ASM
#include <sys/types.h>
#include <sys/cpuvar.h>
#endif /* _ASM */

/*
 * BBSRAM virtual address - 64 bits max.
 */
typedef uint64_t vaddr_t;

/*
 * Special type for BBSRAM offsets (rather than pointers).
 * This must be a 32 bit value
 */
typedef uint32_t bboff_t;

/*
 *  As long as each component of the revision is less than
 *  256, this trick will work.  So we check for that and generate a
 *  syntax error if the SID is out of range.
 */
#define	SIGB_MBOX_SIZE  64
/* reserved space - rounds size of sigblock_t to 512 */
#define	SIGB_RESV	16

#define	BASE_ADDR_T_OFFSET	0xFE0	/* BBSRAM base_addr_t offset */

#define	CVC_OUT_SIZ		1024	/* cvc output buffer size */
#define	CVC_IN_SIZ		256	/* cvc input buffer size */

/* make sure the assembler doesn't see the C code */
#ifndef _ASM

/*
 * The reserved hardware interrupt 7F is used as a pointer structure
 * to the two processors' signature blocks in bbsram. Each trap entry
 * is 32 bytes, so this structure is always present at bbsram offset
 * 0xFE0.
 * Over time, we may discover other items that need pointers, that don't
 * logically fit in the sigblocks themselves. This structure declares
 * the global use of these 8 words.
 * The spare_x words are reserved in case a design change calls for
 * using 64-bit virtual addresses instead of offsets. This is
 * considered unlikely.
 *
 * The offsets and this structure are normally created by POST when it
 * initially creates the sigblocks. Subsequent programs  may move the
 * sigblocks in bbsram as they see fit, as long as this structure is changed
 * to reflect the new location.
 */

typedef struct {
	bboff_t sigblk_offset_0;	/* BBSRAM sig block 0 offset */
	uint32_t spare_0;		/* spare word just in case */
	bboff_t sigblk_offset_1;	/* BBSRAM sig block 1 offset */
	uint32_t spare_1;		/* another just in case */
	uint32_t pad[4];		/* trap is 8 32-bit words long */
} base_addr_t;


/*
 * The following are used in the flag field of the mailbox structure.
 * They are used to synchronize access with the mailbox between the
 * SSP and Host, and indicate direction of the given message.
 */
#define	SIGB_MBOX_EMPTY	0
#define	SIGB_MBOX_BUSY	1
#define	HOST_TO_CBS	2
#define	CBS_TO_HOST	3

/* for sigblk polling */
#define	SIGB_INTR_OFF	0x00
#define	SIGB_INTR_SEND	0xFF

typedef	short	mboxflag_t;

/*
 *  BE CAREFUL with modifications. To optimize transfers on the
 *  bootbus between the kernel and mailbox, try to make sure the data
 *  field falls on a 16 byte boundary.
 */
typedef struct {
/*  0 */	short		intr;
/*  2 */	mboxflag_t	flag;
/*  4 */	int32_t		len;
/*  8 */	uint32_t	cmd;
/*  c */	char		data[SIGB_MBOX_SIZE];
} sigbmbox_t;	/* sizeof = 76 (0x4c) = 19X */

typedef struct {
	uchar_t	cvc_output_buf[CVC_OUT_SIZ];
	uchar_t	cvc_input_buf[CVC_IN_SIZ];
	uchar_t cvc_obp_input_flag;	/* !=0 -> OBP wants CVC input */
} sigb_cvc_t;

/*
 * Every CPU signature, state, or substate transition is captured
 * in the ring buffer. OS or OBP will be the writer of the ring buffer
 * and control board executive (via JTAG) will be the sole reader. Because of
 * space limitation in the BBSRAM, the ring buffer can only be 64 entries big.
 * A ring buffer is necessary because of the speed difference between the
 * reader and writer, and to prevent race condition.
 *
 * The ring buffer structure contains two pointers, one for reading and
 * one for writing, and the buffer itself. The last 6 bits in each of the
 * pointer identify an entry in the buffer. The read pointer represents
 * the next entry the reader should read. The write pointer represents the
 * next entry the writer is going to write. For the reader, the ring buffer
 * contains un-read entries if the read and write pointers are different.
 *
 * In most situations, the reader should be able to keep up with the
 * writer. However, in the case where the writer is transitioning
 * rapidly, the reader may not be able to keep up and causes an overflow.
 * When an overflow happens, instead of suspending the writer, the
 * writer continues to write.
 *
 * The first transition that causes an overflow has 2 consequences
 * because of this continuous write action:
 * 1. The ring buffer is flushed, all previous transitions history are lost.
 *
 * Flushing the ring buffer is acceptable since the reader is not
 * able to keep up with rapid transitions, it is better off to start
 * from the current transition than trying to catch up.
 *
 * 2. The new transition is recorded in the ring buffer. However, bcecause of
 *    the way the write pointer is updated, both the read and write pointers
 *    will be identical which makes the reader thinks there is no transition to
 *    read.
 *
 * Even though the reader does not see the most current signature/state in the
 * ring buffer, it can be found in the signature block data structure.
 * The reader can do a read in the signature block to obtain the current
 * signature/block if the read/write pointers indicate the buffer is empty.
 * The problem will go away once the writer starts writing again.
 *
 * Initial condition:
 * rd_ptr = 0
 * wr_ptr = 0
 *
 * To write a signature into the ring buffer, the steps are:
 * 1. write signature into ringbuf[wr_ptr]
 * 2. increment wr_ptr by 1 modulo SIGB_RB_SIZ using RB_IDX_MASK
 *
 * Note: the writer always writes to the ring buffer and the signature
 * field in the signature block data structure.
 *
 * To read a signature from the ring buffer, the steps are:
 * 1. compare rd_ptr and wr_ptr
 * 2. if they are not equal then
 *    	read signature ringbuf[rd_ptr]
 *    	increment rd_ptr by 1 modulo SIGB_RB_SIZ using RB_IDX_MASK
 *	save a copy of the signature locally
 *	return the signature
 * 3. else
 * 	read signature from the signature block data structure
 * 	if signature is not the same as the last signature then
 *		return the signature
 *
 */

#define	SIGB_RB_SIZ	64		/* ring buffer size */
#define	RB_IDX_MASK	0x3f		/* mask to determine read/write index */

typedef struct {
/*  0 */	uchar_t		rd_ptr;		/* entry to read */
/*  1 */	uchar_t		wr_ptr;		/* next entry to write */
/*  4 */	sig_state_t	ringbuf[SIGB_RB_SIZ];
} sigb_ringbuf_t;	/* sizeof = 260 (0x104) = 65X */

typedef struct cpu_sgnblk {
/*  0 */	uint32_t	sigb_magic;	/* SIGBLOCK_MAGIC */
/*  4 */	uint32_t	sigb_version;	/* changes with each SID */
/*  8 */	uint32_t	sigb_flags;	/* struct sigblock status */
/*  c */	uint32_t	sigb_heartbeat; /* prog's heartbeat */

/* 10 */	uint32_t	sigb_leds;	/* Software LED */
/* 14 */	sig_state_t	sigb_signature; /* Current signature & state */

	/*
	 * sigb_ringbuf captures the last SIGB_RB_SIZ signature/state
	 * transitions.
	 */
/* 18 */	sigb_ringbuf_t	sigb_ringbuf;

	/*
	 * sigb_host_mbox is intended for msgs targeted for the Host and
	 * follows the protocol:
	 *   SSP -> [cmd] -> Host -> [resp] -> SSP.
	 */
/* 11c */	sigbmbox_t	sigb_host_mbox;

/* 168 */	char	sigb_idn[sizeof (sigbmbox_t)];

/* 1b4 */	bboff_t	sigb_obp_mbox;	/* OBP/DHLP mailbox. */

/* 1b8 */	bboff_t	sigb_postconfig; /* config info from POST */

/* 1bc */	uint32_t	sigb_post;	/* POST opaque */

/* 1c0 */	bboff_t	sigb_slavep;	/* Slave startup block offset */

/* 1c4 */	bboff_t	sigb_resetinfo_off;	/* Resetinfo offset */

/* 1c8 */	bboff_t	sigb_cvc_off;	/* CVC offset */

/* 1cc */	bboff_t	sigb_eeprom_off;	/* EEPROM offset */

/* 1d0 */	vaddr_t	sigb_wdog_reset_vec; /* Watchdog Reset Vector */

/* 1d8 */	vaddr_t	sigb_xir_reset_vec;	/* XIR Reset vector */

/* 1e0 */	vaddr_t	sigb_sir_reset_vec;	/* SIR Reset Vector */

/* 1e8 */	vaddr_t	sigb_red_state_reset_vec;   /* RED State Reset Vector */

/* 1f0 */	uchar_t	sigb_resv_array[SIGB_RESV]; /* reserved space */
} cpu_sgnblk_t;	/* sizeof = 512 (0x200) = 128X */

#endif /* _ASM */

/*
 * Mailbox commands.
 *
 * The commands are listed here so that they are in a central place
 * for all users of the signature block mailbox.  Want to be careful
 * that some subsystems don't accidently use the same value for a
 * command.  For this reason we introduce a cookie for each subsystem.
 */

#define	SIGB_HANDLER_BUSY	(-2)
#define	SIGB_BAD_MBOX_CMD	(-1)
#define	SSP_CMD			('S' << 8)	/* generic SSP */
#define	SSP_CMD_SUCCESS		(SSP_CMD | 0x1)
#define	SSP_GOTO_OBP		(SSP_CMD | 0x2)
#define	SSP_GOTO_PANIC		(SSP_CMD | 0x3)
#define	SSP_ENVIRON		(SSP_CMD | 0x4) /* environmental intr */

#ifdef _KERNEL

#ifdef _STARFIRE

extern void juggle_sgnblk_poll(struct cpu *);
extern int sgnblk_poll_register(void (*)(processorid_t, cpu_sgnblk_t *));
extern int sgnblk_poll_unregister(void (*)(processorid_t, cpu_sgnblk_t *));
extern int sgnblk_poll_reference(void (*)(cpu_sgnblk_t *, void *), void *);
extern void sgnblk_poll_unreference(void (*)(cpu_sgnblk_t *, void *));

extern cpu_sgnblk_t *cpu_sgnblkp[NCPU];

/*
 *  Starfire specific signatures
 */
#define	POST_SIG	SIG_BLD('P', 'O')
#define	DHLP_SIG	SIG_BLD('D', 'H')

/*
 *  Starfire specific Sigblock states.
 */
#define	SIGBST_NONE	0	/* no state */
#define	SIGBST_RUN	1	/* running */
#define	SIGBST_EXIT	2	/* finished */
#define	SIGBST_PRERUN	3	/* pre-exec */
#define	SIGBST_ARBSTOP	4	/* transient arbstop state */
#define	SIGBST_RESET	5	/* reset */
#define	SIGBST_POWEROFF	6	/* no power */
#define	SIGBST_DETACHED	7	/* spinning in OBP after DR DETACH */
#define	SIGBST_CALLBACK	8	/* kernel calling back into OBP */
#define	SIGBST_WATCHDOG	9	/* OBP running after watchdog */
#define	SIGBST_WATCHDOG_SYNC	10 /* OBP "sync" after watchdog reset */
#define	SIGBST_OFFLINE	11	/* cpu offline */
#define	SIGBST_BOOTING	12	/* booting */
#define	SIGBST_UNKNOWN	13	/* unknown */
#define	SIGBST_XIR	14	/* OBP running after XIR */
#define	SIGBST_XIR_SYNC	15	/* OBP trying "sync" in XIR */
#define	SIGBST_SIR	16	/* OBP running after SIR */
#define	SIGBST_SIR_SYNC	17	/* OBP trying "sync" in SIR */
#define	SIGBST_REDMODE	18	/* OBP running after REDMODE */
#define	SIGBST_REDMODE_SYNC	19	/* OBP trying "sync" in REDMODE */
#define	SIGBST_QUIESCED		20	/* system quiesced */
#define	SIGBST_QUIESCE_INPROGRESS 21	/* system quiesce in-progress */
#define	SIGBST_RESUME_INPROGRESS 22	/* system resume in-progress */

/*
 *  Starfire specific Sigblock sub-states
 */
#define	EXIT_NULL		0
#define	EXIT_HALT		1
#define	EXIT_ENVIRON		2
#define	EXIT_REBOOT		3
#define	EXIT_PANIC1		4
#define	EXIT_PANIC2		5
#define	EXIT_HUNG		6
#define	EXIT_WATCH		7
#define	EXIT_PANIC_REBOOT	8
#define	EXIT_WATCHDOG_REBOOT	9
#define	EXIT_SOFT_INIT_RESET	10   /* SIR */
#define	EXIT_EXTERN_INIT_RESET	11   /* XIR */
#define	EXIT_REDMODE_REBOOT	12   /* REDMODE */
#define	EXIT_OBP_RESET		13   /* OBP RESET */

#else

#define	REGISTER_BBUS_INTR()
#define	CPU_SGN_MAPIN(cpuid)
#define	CPU_SGN_MAPOUT(cpuid)
#define	CPU_SGN_EXISTS(cpuid)	(0)
#define	SGN_CPU_IS_OS(cpuid)	(0)
#define	SGN_CPU_IS_OBP(cpuid)	(0)
#define	SGN_CPU_STATE_IS_DETACHED(cpuid)	(0)

#endif	/* _STARFIRE */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _CPU_SGN_H */
