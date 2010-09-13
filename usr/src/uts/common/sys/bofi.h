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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BOFI_H
#define	_SYS_BOFI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * header file for bus_ops fault injector
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/feature_tests.h>

/*
 * ioctl command values
 */
#define	BOFI_ADD_DEF 0
#define	BOFI_DEL_DEF 1
#define	BOFI_START 2
#define	BOFI_STOP 3
#define	BOFI_CHK_STATE 8
#define	BOFI_CHK_STATE_W 9
#define	BOFI_BROADCAST 10
#define	BOFI_CLEAR_ACC_CHK 11
#define	BOFI_CLEAR_ERRORS 12
#define	BOFI_CLEAR_ERRDEFS 13
#define	BOFI_GET_HANDLES 16
#define	BOFI_GET_HANDLE_INFO 17

#define	NAMESIZE 256
#define	ERRMSGSIZE 256

struct  acc_log_elem {
    hrtime_t	access_time;	/* timestamp */
    uint_t	access_type;	/* the type of access */
    uint_t	_pad;		/* pad struct to multiple of 8 bytes for x86 */
    offset_t 	offset;		/* the offset into handle */
    uint64_t	value;		/* the value being read or written */
    uint32_t 	size;		/* the size (in bytes) of the transaction */
    uint32_t  	repcount;	/* repcount parameter of a ddi_repX routine */
};

/* Access logging flags */
#define	BOFI_LOG_REPIO	0x1	/* log ddi_repX as multiple accesses */
#define	BOFI_LOG_WRAP	0x2	/* do continuous logging of accesses */
#define	BOFI_LOG_FULL	0x4	/* lets callers know if the log has wrapped */
#define	BOFI_LOG_TIMESTAMP	0x8 /* timestamp each log entry */

struct  acc_log {
    uint32_t	logsize;	/* length of the logbase array */
    uint32_t	entries;	/* number of valid log elements */
    uint_t	flags;		/* access logging flags */
    uint_t	wrapcnt;	/* wrap cnt */
    hrtime_t	start_time;	/* activation time */
    hrtime_t	stop_time;	/* deactivation time (or time when full) */
    caddr_t	logbase;	/* pointer to acc_log_elem struct */
};
#if defined(_SYSCALL32)

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

struct  acc_log32 {
    uint32_t	logsize;	/* length of the logbase array */
    uint32_t	entries;	/* number of valid log elements */
    uint_t	flags;		/* access logging flags */
    uint_t	wrapcnt;	/* wrap cnt */
    hrtime_t	start_time;	/* activation time */
    hrtime_t	stop_time;	/* deactivation time (or time when full) */
    caddr32_t	logbase;	/* pointer to acc_log_elem struct */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif /* _SYSCALL32 */

struct bofi_errdef {
    uint_t 	namesize;
    char 	name[NAMESIZE];		/* as returned by ddi_get_name() */
				/* pointer to char */
    int 	instance;	/* as returned by ddi_get_instance() */
    int		rnumber;	/* as used by ddi_regs_map_setup() */
    offset_t 	offset;		/* as used by ddi_regs_map_setup() */
    offset_t 	len;		/* as used by ddi_regs_map_setup() */
    uint_t	access_type;
    uint_t	access_count;
    uint_t	fail_count;
    uint_t	acc_chk;
    uint_t	optype;
    uint64_t	operand;
    struct acc_log log;
    uint64_t 	errdef_handle;	/* pointer to void */
};
#if defined(_SYSCALL32)

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

struct bofi_errdef32 {
    uint_t 	namesize;
    char 	name[NAMESIZE];		/* as returned by ddi_get_name() */
				/* pointer to char */
    int 	instance;	/* as returned by ddi_get_instance() */
    int		rnumber;	/* as used by ddi_regs_map_setup() */
    offset_t 	offset;		/* as used by ddi_regs_map_setup() */
    offset_t 	len;		/* as used by ddi_regs_map_setup() */
    uint_t	access_type;
    uint_t	access_count;
    uint_t	fail_count;
    uint_t	acc_chk;
    uint_t	optype;
    uint64_t	operand;
    struct acc_log32 log;
    uint64_t 	errdef_handle;	/* pointer to void */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif /* _SYSCALL32 */

struct bofi_errctl {
    uint_t 	namesize;
    char 	name[NAMESIZE];		/* as returned by ddi_get_name() */
    int 	instance;	/* as returned by ddi_get_instance() */
};

struct bofi_get_handles {
    uint_t 	namesize;
    char 	name[NAMESIZE];		/* as returned by ddi_get_name() */
    int 	instance;	/* as returned by ddi_get_instance() */
    int 	count;
    caddr_t 	buffer;
};
#if defined(_SYSCALL32)
struct bofi_get_handles32 {
    uint_t 	namesize;
    char 	name[NAMESIZE];		/* as returned by ddi_get_name() */
    int 	instance;	/* as returned by ddi_get_instance() */
    int 	count;
    caddr32_t 	buffer;
};
#endif /* _SYSCALL32 */

struct handle_info {
    int 	instance;
    uint_t 	access_type;
    int 	rnumber;
    int		_pad;		/* pad to 8 bytes for x86 */
    offset_t 	len;
    offset_t 	offset;
    uint64_t 	addr_cookie;
};

struct bofi_get_hdl_info {
    uint_t 	namesize;
    char 	name[NAMESIZE];		/* as returned by ddi_get_name() */
    int 	count;		/* number of handle_info structures */
    caddr_t 	hdli;		/* pointer to struct handle_info */
};
#if defined(_SYSCALL32)
struct bofi_get_hdl_info32 {
    uint_t 	namesize;
    char 	name[NAMESIZE];		/* as returned by ddi_get_name() */
    int 	count;		/* number of handle_info structures */
    caddr32_t 	hdli;		/* pointer to struct handle_info */
};
#endif /* _SYSCALL32 */

/*
 * values for optype
 */
#define	BOFI_EQUAL 0
#define	BOFI_AND 1
#define	BOFI_OR 2
#define	BOFI_XOR 3
#define	BOFI_NO_TRANSFER 4
#define	BOFI_DELAY_INTR 5
#define	BOFI_LOSE_INTR 6
#define	BOFI_EXTRA_INTR 7
#define	BOFI_NOP 16
/*
 * values for access_type
 */
#define	BOFI_PIO_R 1
#define	BOFI_PIO_W 2
#define	BOFI_PIO_RW (BOFI_PIO_R|BOFI_PIO_W)
#define	BOFI_DMA_R 4
#define	BOFI_DMA_W 8
#define	BOFI_DMA_RW (BOFI_DMA_R|BOFI_DMA_W)
#define	BOFI_INTR 64
#define	BOFI_LOG 128

struct bofi_errstate {
    hrtime_t	fail_time;	/* time that count went to zero */
    hrtime_t	msg_time;	/* time that ddi_report_error was called */
    uint_t	access_count;
    uint_t	fail_count;
    uint_t	acc_chk;
    uint_t 	errmsg_count;
    char 	buffer[ERRMSGSIZE];
    ddi_fault_impact_t severity;
    struct acc_log log;
    uint64_t 	errdef_handle;
};
#if defined(_SYSCALL32)

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

struct bofi_errstate32 {
    hrtime_t	fail_time;	/* time that count went to zero */
    hrtime_t	msg_time;	/* time that ddi_report_error was called */
    uint_t	access_count;
    uint_t	fail_count;
    uint_t	acc_chk;
    uint_t 	errmsg_count;
    char 	buffer[ERRMSGSIZE];
    ddi_fault_impact_t severity;
    struct acc_log32 log;
    uint64_t 	errdef_handle;
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif /* _SYSCALL32 */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_BOFI_H */
