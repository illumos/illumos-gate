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

#ifndef	_SYS_NSCTL_H
#define	_SYS_NSCTL_H

#ifdef	__cplusplus
extern "C" {
#endif

#if (defined(lint) || defined(OSDEBUG)) && defined(_KERNEL)
#define	__NSC_GEN__
#include <sys/ksynch.h>
#include <sys/nsctl/nsc_dev.h>
#include <sys/nsctl/nsc_gen.h>
#include <sys/nsctl/nsc_mem.h>
#include <sys/nsctl/nsc_rmspin.h>
#endif


/*
 * nsctl multi-terabyte volume support
 *
 * To build a multi-terabyte stack, '#define NSC_MULTI_TERABYTE'.
 */

#ifdef NSC_MULTI_TERABYTE
typedef uint64_t	nsc_off_t;	/* positions, offsets */
typedef uint64_t	nsc_size_t;	/* lengths, sizes */
#ifdef _LP64
#define	NSC_SZFMT	"lu"
#define	NSC_XSZFMT	"lx"
#else
#define	NSC_SZFMT	"llu"
#define	NSC_XSZFMT	"llx"
#endif

#else	/* max 1TB volume size */
typedef int		nsc_off_t;
typedef int		nsc_size_t;
#define	NSC_SZFMT	"u"
#define	NSC_XSZFMT	"x"
#endif


#ifdef _KERNEL

#ifdef sun
#include <sys/nsc_ddi.h>
#endif

/*
 * Generic parameter definition.
 */

typedef struct nsc_def_s {
	char	*name;			/* Parameter name */
	uintptr_t value;		/* Parameter value */
	int	offset;			/* Structure offset */
} nsc_def_t;

extern int nsc_inval(), nsc_ioerr();
extern int nsc_fatal(), nsc_null(), nsc_true();
extern void nsc_decode_param(nsc_def_t *, nsc_def_t *, long *);
#endif	/* _KERNEL */


/* ID and Type flags */

#define	NSC_ID		0x40000000	/* Module ID */
#define	NSC_NULL	0x00000100	/* No I/O possible */
#define	NSC_DEVICE	0x00000200	/* Device interface */
#define	NSC_FILE	0x00000400	/* File vnode interface */
#define	NSC_CACHE	0x00000800	/* Cache interface */
#define	NSC_ANON	0x00001000	/* Supports anonymous buffers */
#define	NSC_VCHR	0x00002000	/* VCHR vnode device */
#define	NSC_NCALL	0x00004000	/* ncall-io interface */

#define	NSC_IDS		0x7ff00000	/* ID mask */
#define	NSC_TYPES	0x7fffff00	/* Type mask */

#define	NSC_MKID(x)	(NSC_ID | ((x) << 20))

#define	NSC_RAW_ID  	NSC_MKID(39)	/* Raw device */
#define	NSC_FILE_ID	NSC_MKID(40)	/* File vnode device */
#define	NSC_FREEZE_ID	NSC_MKID(41)	/* Frozen raw device */
#define	NSC_VCHR_ID	NSC_MKID(42)	/* VCHR vnode device */
#define	NSC_NCALL_ID	NSC_MKID(43)	/* ncall-io */
#define	NSC_SDBC_ID	NSC_MKID(80)	/* Block based cache */
#define	NSC_RDCLR_ID	NSC_MKID(94)	/* RDC (low, raw) */
#define	NSC_RDCL_ID	NSC_MKID(95)	/* RDC (low, cache) */
#define	NSC_IIR_ID	NSC_MKID(96)	/* Instant Image (raw) */
#define	NSC_II_ID	NSC_MKID(98)	/* Instant Image */
#define	NSC_RDCHR_ID	NSC_MKID(99)	/* RDC (high, raw) */
#define	NSC_RDCH_ID	NSC_MKID(100)	/* RDC (high, cache) */

typedef enum nsc_power_ops_e {
	Power_Lost,	/* Power Failing initial warning */
			/* with timeleft (rideout) minutes */

	Power_OK,	/* Power OK or restored before death */

	Power_Down 	/* that's all folks machine will */
			/* be shutdown, save any state */
} nsc_power_ops_t;

#ifdef _KERNEL

/* Module Flags */

#define	NSC_REFCNT	0x00000001	/* Counts references */
#define	NSC_FILTER	0x00000002	/* Uses lower level driver */


#ifndef _NSC_DEV_H
typedef struct nsc_io_s { int x; } nsc_io_t;
typedef struct nsc_path_s { int x; } nsc_path_t;
#endif

extern nsc_io_t *nsc_register_io(char *, int, nsc_def_t *);
extern int nsc_unregister_io(nsc_io_t *, int);
extern nsc_path_t *nsc_register_path(char *, int, nsc_io_t *);
extern int nsc_unregister_path(nsc_path_t *, int);
extern int nsc_cache_sizes(int *, int *);
extern int nsc_node_hints(unsigned int *);
extern int nsc_node_hints_set(unsigned int);
extern blind_t nsc_register_power(char *, nsc_def_t *);
extern int nsc_unregister_power(blind_t);

/*
 *  Strategy function interface
 */
#ifndef DS_DDICT
typedef int (*strategy_fn_t)(struct buf *);
#endif
extern strategy_fn_t    nsc_get_strategy(major_t);

extern void *nsc_get_devops(major_t);

#endif /* _KERNEL */


/* Block sizes */

#define	FBA_SHFT	9
#define	FBA_MASK	0x1ff
#define	FBA_SIZE(x)	((x) << FBA_SHFT)		/* fba to bytes */
#define	FBA_OFF(x)	((x) & FBA_MASK)		/* byte offset */
#define	FBA_LEN(x)	FBA_NUM((x) + FBA_MASK)		/* len to fba */
#define	FBA_NUM(x)	((nsc_size_t)((uint64_t)(x) >> FBA_SHFT))
							/* bytes to fba */


/* Return values */

#define	NSC_DONE	(0)
#define	NSC_PENDING  	(-1)
#define	NSC_HIT		(-2)


#if defined(_KERNEL) || defined(_KMEMUSER)

/*
 * External file descriptor.
 */

#ifndef _NSC_DEV_H
typedef struct nsc_fd_s { int x; } nsc_fd_t;
#endif

#endif /* _KERNEL || _KMEMUSER */


#ifdef _KERNEL

#define	NSC_TRY		(1<<24)		/* Conditional operation */
#define	NSC_PCATCH	(1<<25)		/* Catch signals */
#define	NSC_DEFER	(1<<26)		/* Defer if busy */
#define	NSC_MULTI	(1<<27)		/* Multiple reserves */
#define	NSC_NOWAIT	(1<<28)		/* Don't wait if busy */

extern nsc_fd_t *nsc_open(char *, int, nsc_def_t *, blind_t, int *);
extern int nsc_close(nsc_fd_t *);
extern char *nsc_pathname(nsc_fd_t *);
extern int nsc_fdpathcmp(nsc_fd_t *, uint64_t, char *);
extern int nsc_shared(nsc_fd_t *);
extern int nsc_setval(nsc_fd_t *, char *, int);
extern int nsc_getval(nsc_fd_t *, char *, int *);
extern int nsc_set_trksize(nsc_fd_t *, nsc_size_t);
extern int nsc_discard_pinned(nsc_fd_t *, nsc_off_t, nsc_size_t);
extern kmutex_t *nsc_lock_addr(nsc_fd_t *);
extern int nsc_attach(nsc_fd_t *, int);
extern int nsc_reserve(nsc_fd_t *, int);
extern void nsc_reserve_lk(nsc_fd_t *);
extern void nsc_release(nsc_fd_t *);
extern int nsc_release_lk(nsc_fd_t *);
extern int nsc_detach(nsc_fd_t *, int);
extern int nsc_avail(nsc_fd_t *);
extern int nsc_held(nsc_fd_t *);
extern int nsc_waiting(nsc_fd_t *);
extern int nsc_partsize(nsc_fd_t *, nsc_size_t *);
extern int nsc_maxfbas(nsc_fd_t *, int, nsc_size_t *);
extern int nsc_get_pinned(nsc_fd_t *);
extern int nsc_max_devices(void);
extern int nsc_control(nsc_fd_t *, int, void *, int);

#endif /* _KERNEL */


#if defined(_KERNEL) || defined(_KMEMUSER)

/*
 * I/O device structure.
 */

#ifndef _NSC_DEV_H
typedef struct nsc_iodev_s { int x; } nsc_iodev_t;
#endif

#ifdef _KERNEL
extern void nsc_set_owner(nsc_fd_t *, nsc_iodev_t *);
extern void nsc_pinned_data(nsc_iodev_t *, nsc_off_t, nsc_size_t);
extern void nsc_unpinned_data(nsc_iodev_t *, nsc_off_t, nsc_size_t);
#endif


/*
 * Data structures used by I/O interface.
 */

typedef struct nsc_vec_s {		/* Scatter gather element */
	unsigned char	*sv_addr;	/* Virtual address of data */
	unsigned long	sv_vme;		/* VME address of data */
	int		sv_len;		/* Data length in bytes */
} nsc_vec_t;


typedef struct nsc_buf_s {		/* Buffer structure */
	nsc_fd_t *sb_fd;		/* File descriptor */
	nsc_off_t sb_pos;		/* Block offset of data */
	nsc_size_t sb_len;		/* Length of data in blocks */
	volatile int sb_flag;		/* Buffer flags */
	int sb_error;			/* Error code */
	uintptr_t sb_user;		/* User definable */
	nsc_vec_t *sb_vec;		/* Scatter gather list */
} nsc_buf_t;

#endif /* _KERNEL || _KMEMUSER */


/* Allocate flags */

#define	NSC_RDBUF	0x0001
#define	NSC_WRBUF	0x0002
#define	NSC_PINNABLE	0x0004
#define	NSC_NOBLOCK	0x0008

#define	NSC_READ	(NSC_RDBUF)
#define	NSC_WRITE	(NSC_WRBUF)
#define	NSC_RDWR	(NSC_RDBUF | NSC_WRBUF)
#define	NSC_RDWRBUF	(NSC_RDBUF | NSC_WRBUF)


/* Other flags */

#define	NSC_CACHEBLK	0x0008	/* nsc_maxfbas: size of cache block in fbas */
#define	NSC_HALLOCATED	0x0010	/* handle allocated (IO provider internals) */
#define	NSC_HACTIVE	0x0020	/* handle active (IO provider internals) */
#define	NSC_BCOPY	0x0040	/* bcopy, don't DMA when moving data */
#define	NSC_PAGEIO	0x0080	/* client will use handle for pageio */
#define	NSC_ABUF	0x0100	/* anonymous buffer handle */
#define	NSC_MIXED	0x0200	/* data from 2 devs is mixed in this buffer */
#define	NSC_NODATA	0x0400	/* allocate without data buffer (sb_vec) */


#define	NSC_FLAGS	0xffff

#ifdef _KERNEL

#define	NSC_ANON_CD	((blind_t)(-1)) /* used for IO provider alloc buf */

extern int nsc_alloc_buf(nsc_fd_t *, nsc_off_t, nsc_size_t, int, nsc_buf_t **);
extern int nsc_alloc_abuf(nsc_off_t, nsc_size_t, int, nsc_buf_t **);
extern int nsc_read(nsc_buf_t *, nsc_off_t, nsc_size_t, int);
extern int nsc_write(nsc_buf_t *, nsc_off_t, nsc_size_t, int);
extern int nsc_zero(nsc_buf_t *, nsc_off_t, nsc_size_t, int);
extern int nsc_copy(nsc_buf_t *, nsc_buf_t *, nsc_off_t, nsc_off_t, nsc_size_t);
extern int nsc_copy_direct(nsc_buf_t *, nsc_buf_t *, nsc_off_t,
    nsc_off_t, nsc_size_t);
extern int nsc_uncommit(nsc_buf_t *, nsc_off_t, nsc_size_t, int);
extern int nsc_free_buf(nsc_buf_t *);
extern nsc_buf_t *nsc_alloc_handle(nsc_fd_t *,
	void (*)(), void (*)(), void (*)());
extern int nsc_free_handle(nsc_buf_t *);
extern int nsc_uread(nsc_fd_t *, void *, void *);
extern int nsc_uwrite(nsc_fd_t *, void *, void *);

#endif /* _KERNEL */


/*
 * Performance hints.
 */

#define	NSC_WRTHRU		0x00010000
#define	NSC_FORCED_WRTHRU  	0x00020000
#define	NSC_NOCACHE		0x00040000
#define	NSC_QUEUE		0x00080000
#define	NSC_RDAHEAD		0x00100000
#define	NSC_NO_FORCED_WRTHRU	0x00200000
#define	NSC_METADATA		0x00400000
#define	NSC_SEQ_IO		0x00800000

#define	NSC_HINTS		0x00ff0000


#ifdef _KERNEL
/*
 * node hint actions
 */

#define	NSC_GET_NODE_HINT	0
#define	NSC_SET_NODE_HINT	1
#define	NSC_CLEAR_NODE_HINT	2

/*
 * Reflective memory spinlocks.
 */


#ifndef _NSC_RMSPIN_H
typedef struct nsc_rmlock_s { int x; } nsc_rmlock_t;
#endif


extern nsc_rmlock_t *nsc_rm_lock_alloc(char *, int, void *);
extern void nsc_rm_lock_dealloc(nsc_rmlock_t *);
extern int nsc_rm_lock(nsc_rmlock_t *);
extern void nsc_rm_unlock(nsc_rmlock_t *);

#endif /* _KERNEL */


/*
 * Memory allocation routines.
 */

#define	NSC_MEM_LOCAL	0x1
#define	NSC_MEM_GLOBAL	0x4

#define	NSC_MEM_RESIZE  0x100
#define	NSC_MEM_NVDIRTY 0x400


#ifdef _KERNEL

#ifndef _NSC_MEM_H
typedef struct nsc_mem_s { int x; } nsc_mem_t;
#endif


extern nsc_mem_t *nsc_register_mem(char *, int, int);
extern void nsc_unregister_mem(nsc_mem_t *);
extern void *nsc_kmem_alloc(size_t, int, nsc_mem_t *);
extern void *nsc_kmem_zalloc(size_t, int, nsc_mem_t *);
extern void nsc_kmem_free(void *, size_t);
extern void nsc_mem_sizes(nsc_mem_t *, size_t *, size_t *, size_t *);
extern size_t nsc_mem_avail(nsc_mem_t *);

/* nvmem suppport */
typedef void (*nsc_mem_err_cb) (void *, void *, size_t, int);
extern int nsc_commit_mem(void *, void *, size_t, nsc_mem_err_cb);

extern void nsc_cm_errhdlr(void *, void *, size_t, int);

#endif /* _KERNEL */


/*
 * Max pathname
 * Note: Currently defined both here and in nsc_dev.h
 */
#if !defined(NSC_MAXPATH)
#define	NSC_MAXPATH	64
#endif

#ifdef _KERNEL

/*
 * Inter-module function (callback) services
 */

#ifndef _NSC_GEN_H
typedef struct nsc_svc_s { int x; } nsc_svc_t;
#endif

extern nsc_svc_t *nsc_register_svc(char *, void (*)(intptr_t));
extern int nsc_unregister_svc(nsc_svc_t *);
extern int nsc_call_svc(nsc_svc_t *, intptr_t);


/*
 * String manipulation functions.
 */

#ifndef sun
#define	sprintf nsc_sprintf
#endif /* sun */

extern char *nsc_strdup(char *);
extern void nsc_strfree(char *);
extern int nsc_strmatch(char *, char *);
extern void nsc_sprintf(char *, char *, ...);
extern uint64_t nsc_strhash(char *);


/*
 * Macro definitions.
 */

#define	NSC_HIER	1

#ifndef NULL
#define	NULL		0
#endif


/*
 * External definitions.
 */

#undef HZ
extern clock_t HZ;
extern int nsc_max_nodeid, nsc_min_nodeid;

extern int nsc_node_id(void);
extern char *nsc_node_name(void);
extern int nsc_node_up(int);
extern time_t nsc_time(void);
extern clock_t nsc_lbolt(void);
extern int nsc_delay_sig(clock_t);
extern clock_t nsc_usec(void);
extern void nsc_yield(void);

extern void nsc_membar_stld(void);
extern uint8_t nsc_ldstub(uint8_t *);
extern caddr_t nsc_caller(void);
extern caddr_t nsc_callee(void);

extern int nsc_create_process(void (*)(void *), void *, boolean_t);

extern int nsc_power_init(void);
extern void nsc_power_deinit(void);
extern int nsc_nodeid_data(void);

#define	NSC_ALERT_INFO		0	/* Information alert */
#define	NSC_ALERT_WARNING	1	/* Warning alert */
#define	NSC_ALERT_ERROR		2	/* Error alert */
#define	NSC_ALERT_DOWN		3	/* System or Module down */

extern void nsc_do_sysevent(char *, char *, int, int, char *, dev_info_t *);


/*
 * Missing DDI/DKI definition.
 */

#if defined(_SYS_CONF_H)
#ifndef D_MP
#define	D_MP 0
#endif
#endif

extern void *nsc_threadp(void);

#endif /* _KERNEL */


/*
 * Common defines
 */

#ifndef TRUE
#define	TRUE	1
#endif

#ifndef FALSE
#define	FALSE	0
#endif

#ifndef  NBBY
#define	NBBY	8	/* number of bits per byte */
#endif

/*
 * kstat definition
 */
#define	KSTAT_DATA_CHAR_LEN (sizeof (((kstat_named_t *)0)->value.c))

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_NSCTL_H */
