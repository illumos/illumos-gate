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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_N2CP_H
#define	_SYS_N2CP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/mdesc.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/ncs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DRIVER			"n2cp"
#define	N2CP_MANUFACTURER_ID	"SUNWn2cp"

#if defined(_KERNEL)

#define	FALSE		0
#define	TRUE		1

#define	BITS2BYTES(b)	((b) >> 3)
#define	BYTES2BITS(b)	((b) << 3)

#define	N_MBLKL(mp)	((uint64_t)(mp)->b_wptr - (uint64_t)(mp)->b_rptr)

/*
 * N2CP Structures.
 */
typedef struct n2cp n2cp_t;
typedef struct n2cp_minor n2cp_minor_t;
typedef struct n2cp_listnode n2cp_listnode_t;
typedef struct n2cp_request n2cp_request_t;
typedef struct n2cp_stat n2cp_stat_t;
typedef	struct n2cp_block_ctx n2cp_block_ctx_t;
typedef	struct n2cp_hash_ctx n2cp_hash_ctx_t;
typedef	struct n2cp_hmac_ctx n2cp_hmac_ctx_t;

/*
 * Linked-list linkage.
 */
struct n2cp_listnode {
	n2cp_listnode_t *nl_next;
	n2cp_listnode_t *nl_prev;
};

#define	N2CP_MODE_STRING	"n2cp-mode"

typedef enum {
	N_ASYNC,
	N_SYNC
} n2cp_mode_t;


#define	N2CP_MAX_NCWQS		32
#define	N2CP_MAX_CPUS_PER_CWQ	8
#define	N2CP_MAX_HELPERTHREADS	(N2CP_MAX_NCWQS * N2CP_MAX_CPUS_PER_CWQ)
#define	N2CP_MAX_BUF_CNT	1024

/* numbers of completion theads */
#define	NUM_COMPLETE_THREADS	1

/*
 * Device flags (n2cp_t.n_flags)
 */
#define	N2CP_FAILED		0x0000001
#define	N2CP_ATTACHED		0x0000002
#define	N2CP_REGISTERED		0x0000004
#define	N2CP_CPU_REGISTERED	0x0000008

/*
 * HW limitaions for Data and Key. For an input greater than 64KB, Driver will
 * break up the input into 64KB blocks, and send the jobs to the hardware.
 */
#define	CW_MAX_DATA_LEN		(1 << 16)	/* 64K */
#define	CW_MAX_KEY_LEN		(1 << 8)	/* 256 */

#define	CW_TYPE_INITIAL		1
#define	CW_TYPE_EXTENSION	2
#define	CW_TYPE_FINAL		3
#define	CW_TYPE_COMPLETE	4

/*
 * Defines for fields in Initial Control Word.
 */
#define	CW_OP_SSL		16
#define	CW_OP_COPY		32
#define	CW_OP_ENCRYPT		64
#define	CW_OP_MAC_AUTH		65
#define	CW_OP_INLINE_BIT	(1 << 7)

#define	CW_AUTH_MD5		1
#define	CW_AUTH_SHA1		2
#define	CW_AUTH_SHA256		3
#define	CW_AUTH_CRC32		4
#define	CW_AUTH_HMAC_MD5	5
#define	CW_AUTH_HMAC_SHA1	6
#define	CW_AUTH_HMAC_SHA256	7
#define	CW_AUTH_TCPCKSUM	8
#define	CW_AUTH_SSL_HMAC_MD5	9
#define	CW_AUTH_SSL_HMAC_SHA1	10
#define	CW_AUTH_SSL_HMAC_SHA256 11

#define	CW_ENC_ALGO_RC4WSTRM	0
#define	CW_ENC_ALGO_RC4WOSTRM	1
#define	CW_ENC_ALGO_DES		2
#define	CW_ENC_ALGO_3DES	3
#define	CW_ENC_ALGO_AES128	4
#define	CW_ENC_ALGO_AES192	5
#define	CW_ENC_ALGO_AES256	6

#define	CW_ENC_CHAIN_ECB	0
#define	CW_ENC_CHAIN_CBC	1
#define	CW_ENC_CHAIN_CFB	2
#define	CW_ENC_CHAIN_AESCTR	3

#define	CW_ENC_TYPE(a, c)	((((a) & 7) << 2) | ((c) & 3))

#define	CWQ_NENTRIES		(1 << 5)	/* 32 */
#define	CWQ_WRAPMASK		(CWQ_NENTRIES - 1)

/* CWS_ALIGNMENT is used as an alignment parameter to contig_mem_alloc */
#define	CWQ_ALIGNMENT		64
#define	CWQ_SLOTS_USED(q)	(((q)->cq_tail - (q)->cq_head) & CWQ_WRAPMASK)
#define	CWQ_SLOTS_AVAIL(q)	(CWQ_NENTRIES - CWQ_SLOTS_USED(q) - 1)
#define	CWQ_QINDEX_TO_QOFFSET(i)	((i) * sizeof (cwq_cw_t))
#define	CWQ_QOFFSET_TO_QINDEX(o)	((o) / sizeof (cwq_cw_t))
#define	CWQ_QINDEX_INCR(i)		(((i) + 1) & CWQ_WRAPMASK)
#define	CWQ_QINDEX_IS_VALID(i)		(((i) >= 0) && ((i) < CWQ_NENTRIES))

#define	N2CP_QTIMEOUT_SECONDS		60

/* needs up to 9 pages for 64KB buffers */
#define	N2CP_MAX_CHAIN			9

#define	N2CP_JOB_DONE	0xDEADBEEF

typedef struct {
	uint64_t		cq_handle;
	uint64_t		cq_devino;
	int			cq_inum;
	kmutex_t		cq_lock;
	int			cq_id;
	int			cq_init;
	int			cq_busy_wait;
	kcondvar_t		cq_busy_cv;

	n2cp_t			*cq_n2cp;
	n2cp_listnode_t		cq_joblist;	/* runq */

	ddi_taskq_t		*cq_cworker;
	kmutex_t		cq_complete_lock;
	kcondvar_t		cq_complete_cv;
	kcondvar_t		cq_wait_complete_cv;

	/* head of completed job linked list */
	n2cp_request_t		 *cq_rdylist;

	n2cp_request_t		**cq_jobs;
	size_t			cq_jobs_size;
	void			*cq_mem;
	int			cq_memsize;
	cwq_cw_t		*cq_first;
	cwq_cw_t		*cq_last;
	cwq_cw_t		*cq_head;
	cwq_cw_t		*cq_tail;

	struct {
		uint64_t	qks_njobs;
		uint64_t	qks_ncws;
		uint64_t	qks_qfull;
		uint64_t	qks_qbusy;
		uint64_t	qks_qfail;
		uint64_t	qks_nintr;
		uint64_t	qks_nintr_err;
		uint64_t	qks_nintr_jobs;
		uint64_t	qks_nsync_jobs;
		uint64_t	qks_nsync_err;
	} cq_ks;
	kmutex_t		cq_sync_lock;
	n2cp_request_t		*cq_sync_req;
	kcondvar_t		cq_sync_cv;
} cwq_t;

#define	CWQ_STATE_ERROR		(-1)
#define	CWQ_STATE_OFFLINE	0
#define	CWQ_STATE_ONLINE	1
#define	CWQ_STATE_DETACHING	2

typedef struct {
	int		mm_cwqid;
	int		mm_cpulistsz;
	int		*mm_cpulist;
	int		mm_ncpus;
	int		mm_nextcpuidx;
	/*
	 * Only protects mm_nextcpuidx
	 */
	kmutex_t	mm_lock;
	int		mm_state;	/* CWQ_STATE_... */
	cwq_t		mm_queue;
} cwq_entry_t;

typedef struct {
	int		mc_cpuid;
	int		mc_cwqid;
	int		mc_state;	/* CWQ_STATE_... */
} cpu_entry_t;

typedef struct {
	/*
	 * CWQ stuff
	 */
	int		m_cwqlistsz;
	cwq_entry_t	*m_cwqlist;
	int		m_ncwqs;
	int		m_ncwqs_online;
	int		m_nextcwqidx;
	/*
	 * Only protects m_nextcwqidx and m_ncwqs_online
	 */
	kmutex_t	m_lock;

	/*
	 * CPU stuff
	 */
	int		m_cpulistsz;
	cpu_entry_t	*m_cpulist;
	int		m_ncpus;
} n2cp_cwq2cpu_map_t;

#define	SECOND				1000000 /* micro seconds */
#define	N2CP_JOB_STALL_LIMIT		2

typedef uint64_t	n2cp_counter_t;

/* Information for performing periodic timeout (stall) checks */
typedef struct n2cp_timeout {
	clock_t		ticks;	/* Number of clock ticks before next check */
	timeout_id_t	id;	/* ID of timeout thread (used in detach) */
	n2cp_counter_t	count;	/* Number of timeout checks made (statistic) */
} n2cp_timeout_t;

/*
 * Job timeout information:
 *
 * A timeout condition will be detected if all "submitted" jobs have not been
 * "reclaimed" (completed) and we have not made any "progress" within the
 * cumulative timeout "limit".  The cumulative timeout "limit" is incremented
 * with a job specific timeout value (usually one second) each time a new job
 * is submitted.
 */
typedef struct n2cp_job_info {
	kmutex_t	lock;		/* Lock for all other elements */
	n2cp_counter_t	submitted;	/* Number of jobs submitted */
	n2cp_counter_t	reclaimed;	/* Number of jobs completed */
	n2cp_counter_t	progress;	/* Progress recorded during TO check */
	n2cp_timeout_t	timeout;	/* Timeout processing information */
	struct {
		clock_t count;		/* Ticks since last completion */
		clock_t addend;		/* Added to count during TO check */
		clock_t limit;		/* Cumulative timeout value */
	} stalled;
} n2cp_job_info_t;

#define	MAX_FIXED_IV_WORDS	8
typedef struct fixed_iv {
	int		ivsize;
	uint32_t	iv[MAX_FIXED_IV_WORDS];
} fixed_iv_t;

#define	MD5_DIGESTSZ	(4 * sizeof (uint32_t))
#define	SHA1_DIGESTSZ	(5 * sizeof (uint32_t))
#define	SHA256_DIGESTSZ	(8 * sizeof (uint32_t))
#define	MAX_DIGESTSZ	(MAX_FIXED_IV_WORDS * sizeof (uint32_t))

#define	MAX_DATA_LEN		0x10000

#define	DES_KEY_LEN	8
#define	DES3_KEY_LEN	24
#define	DESBLOCK	8
#define	AES_MIN_KEY_LEN	16
#define	AES_MAX_KEY_LEN	32
#define	AESBLOCK	16
#define	MAXBLOCK	AESBLOCK
#define	MAXVALUE	AES_MAX_KEY_LEN

#define	RC4_MIN_KEY_LEN		1
#define	RC4_MAX_KEY_LEN		256

/*
 * We only support up to 64 counter bit
 */
#define	MAX_CTR_BITS	64


#define	HMAC_MIN_KEY_LEN	1
#define	HMAC_MAX_KEY_LEN	CW_MAX_KEY_LEN


/*
 * Some pkcs#11 defines as there are no pkcs#11 header files included.
 */
#define	CKA_VALUE		0x00000011
#define	CKA_KEY_TYPE		0x00000100

/*
 * Request flags (n2cp_request_t.nr_flags).
 */
#define	N2CP_SCATTER		0x01
#define	N2CP_GATHER		0x02
#define	N2CP_SYNC		0x04
#define	N2CP_FREEREQ		0x08

/* define	the mechanisms strings not defined in <sys/crypto/common.h> */
#define	SUN_CKM_SSL3_MD5_MAC		"CKM_SSL3_MD5_MAC"
#define	SUN_CKM_SSL3_SHA1_MAC		"CKM_SSL3_SHA1_MAC"

#ifdef	SSL3_SHA256_MAC_SUPPORT
#define	SUN_CKM_SSL3_SHA256_MAC		"CKM_SSL3_SHA256_MAC"
#endif

/*
 * XXX: Vendor defined version of CKM_AES_CTR. This lets us test AES_CTR
 * from PKCS#11. Note: this is temporally added until CKM_AES_CTR is officially
 * added to PKCS#11 spec.
 */
#define	N2CP_CKM_AES_CTR		"0x80001086"

/*
 * Scatter/gather checks.
 */
#define	N2CP_SG_CONTIG		0x01	/* contiguous buffer */
#define	N2CP_SG_WALIGN		0x02	/* word aligned */
#define	N2CP_SG_PALIGN		0x04	/* page aligned */
#define	N2CP_SG_PCONTIG		0x08	/* physically contiguous buffer */
#define	N2CP_SG_ALIGN16		0x10	/* page aligned */


/*
 * Kstats.
 */
#define	DS_DES			0
#define	DS_DES3			1
#define	DS_AES			2
#define	DS_MD5			3
#define	DS_SHA1			4
#define	DS_SHA256		5
#define	DS_MD5_HMAC		6
#define	DS_SHA1_HMAC		7
#define	DS_SHA256_HMAC		8
#define	DS_SSL_MD5_MAC		9
#define	DS_SSL_SHA1_MAC		10
#define	DS_SSL_SHA256_MAC	11
#define	DS_RC4			12
#define	DS_MAX			13

struct n2cp_stat {
	kstat_named_t		ns_status;
	kstat_named_t		ns_algs[DS_MAX];
	struct {
		kstat_named_t	ns_cwqid;
		kstat_named_t	ns_cwqhandle;
		kstat_named_t	ns_cwqstate;
		kstat_named_t	ns_submit;
		kstat_named_t	ns_cwcount;
		kstat_named_t	ns_qfull;
		kstat_named_t	ns_qbusy;
		kstat_named_t	ns_qupdate_failure;
		kstat_named_t	ns_nintr;
		kstat_named_t	ns_nintr_err;
		kstat_named_t	ns_nintr_jobs;
		kstat_named_t	ns_nsync_jobs;
		kstat_named_t	ns_nsync_err;
	} ns_cwq[N2CP_MAX_NCWQS];
};


typedef enum n2cp_mech_type {
	DES_CBC_MECH_INFO_TYPE,			/* CKM_DES_CBC */
	DES_ECB_MECH_INFO_TYPE,			/* CKM_DES_ECB */
	DES_CFB_MECH_INFO_TYPE,			/* CKM_DES_CFB */
	DES3_CBC_MECH_INFO_TYPE,		/* CKM_DES3_CBC */
	DES3_ECB_MECH_INFO_TYPE,		/* CKM_DES3_ECB */
	DES3_CFB_MECH_INFO_TYPE,		/* CKM_DES3_CFB */
	AES_CBC_MECH_INFO_TYPE,			/* CKM_AES_CBC */
	AES_ECB_MECH_INFO_TYPE,			/* CKM_AES_ECB */
	AES_CTR_MECH_INFO_TYPE,			/* CKM_AES_CTR */
	RC4_WSTRM_MECH_INFO_TYPE,		/* CKM_RC4 */
	RC4_WOSTRM_MECH_INFO_TYPE,		/* CKM_RC4 w/o stream */
	MD5_MECH_INFO_TYPE,			/* CKM_MD5 */
	SHA1_MECH_INFO_TYPE,			/* CKM_SHA_1 */
	SHA256_MECH_INFO_TYPE,			/* CKM_SHA256 */
	MD5_HMAC_MECH_INFO_TYPE,		/* CKM_MD5_HMAC */
	SHA1_HMAC_MECH_INFO_TYPE,		/* CKM_SHA_1_HMAC */
	SHA256_HMAC_MECH_INFO_TYPE,		/* CKM_SHA256_HMAC */
	MD5_HMAC_GENERAL_MECH_INFO_TYPE,	/* CKM_MD5_HMAC_GENERAL */
	SHA1_HMAC_GENERAL_MECH_INFO_TYPE,	/* CKM_SHA_1_HMAC_GENERAL */
	SHA256_HMAC_GENERAL_MECH_INFO_TYPE,	/* CKM_SHA256_HMAC_GENERAL */
	SSL3_MD5_MAC_MECH_INFO_TYPE,		/* CKM_SSL3_MD5_MAC */
	SSL3_SHA1_MAC_MECH_INFO_TYPE,		/* CKM_SSL3_SHA1_MAC */
	SSL3_SHA256_MAC_MECH_INFO_TYPE,		/* CKM_SSL3_SHA256_MAC */
	/* Vendor Defined Mechanism */
	N2CP_AES_CTR_MECH_INFO_TYPE		/* CKM_AES_CTR */
} n2cp_mech_type_t;

/*
 * Operation Flags: These flags are used internally within driver to specify
 * the kind of operation for a job.
 */
#define	N2CP_CMD_MASK		0x0000ffff
#define	N2CP_OP_ENCRYPT		0x00010000
#define	N2CP_OP_DECRYPT		0x00020000
#define	N2CP_OP_SIGN		0x00040000
#define	N2CP_OP_VERIFY		0x00080000
#define	N2CP_OP_DIGEST		0x00100000
#define	N2CP_OP_SINGLE		0x00200000
#define	N2CP_OP_MULTI		0x00400000

/*
 * Mechanism Specific Contexts
 */

typedef struct {
	uchar_t		key[RC4_MAX_KEY_LEN];
	uchar_t		i, j;
} rc4_key_t;

/*
 * Offset within the ctx.
 */
#define	BLOCK_KEY_OFFSET	offsetof(n2cp_block_ctx_t, keystruct)
#define	BLOCK_IV_OFFSET		offsetof(n2cp_block_ctx_t, iv)
#define	HASH_IV_OFFSET		offsetof(n2cp_hash_ctx_t, iv)
#define	HMAC_KEY_OFFSET		offsetof(n2cp_hmac_ctx_t, keyval)
#define	HMAC_IV_OFFSET		offsetof(n2cp_hmac_ctx_t, iv)

struct n2cp_block_ctx {
	int		keylen;
	union {
		uchar_t		val[MAXVALUE];
		rc4_key_t	rc4val;
		arcfour_state_t	kcf_rc4val;
	} keystruct;
	uint64_t	key_paddr;	/* paddr of value */
	int		ivlen;
	uchar_t		iv[MAXBLOCK];
	uint64_t	iv_paddr;	/* paddr of iv */
	int		nextivlen;
	uchar_t		nextiv[MAXBLOCK];
	int		ctrbits;	/* used for AES_CTR */
	int		residlen;
	char		resid[MAXBLOCK];
	int		lastblocklen;
	char		lastblock[MAXBLOCK];
};

#define	keyvalue	keystruct.val
#define	rc4keyvalue	keystruct.rc4val


struct n2cp_hash_ctx {
	uint32_t	hashsz;
	uint32_t	iv[MAX_FIXED_IV_WORDS];
};

struct n2cp_hmac_ctx {
	uint32_t	hashsz;
	uint32_t	signlen;
	uint32_t	iv[MAX_FIXED_IV_WORDS];
	int		keylen;
	uchar_t		keyval[CW_MAX_KEY_LEN];
};


/*
 * Work structure.
 * Contains everything we need to submit the job, and everything we
 * need to notify caller and release resources.
 */
typedef union {
		n2cp_block_ctx_t	blockctx;
		n2cp_hash_ctx_t		hashctx;
		n2cp_hmac_ctx_t		hmacctx;
} nr_ctx_t;

#define	N2CP_OP_PATTERN		"BROKE HW"
#define	N2CP_OP_PATTERN_SZ	8

/* n2cp_request.nr_job_state */
#define	N2CP_JOBSTATE_FREED		0	/* in freed list */
#define	N2CP_JOBSTATE_WAITQ		1	/* in waitq */
#define	N2CP_JOBSTATE_PENDING		2	/* in runq */
#define	N2CP_JOBSTATE_SOLO		3	/* not linked */

typedef struct n2cp_buf_struct {
	n2cp_listnode_t		link;
	uchar_t			*buf;
	uint64_t		buf_paddr;
} n2cp_buf_struct_t;


struct n2cp_request {
	n2cp_listnode_t		nr_linkage;	/* must be at the top */
	n2cp_listnode_t		nr_activectx;	/* must be at the top */
	uint32_t		nr_cmd;	/* N2CP_OP | MECH_INFO_TYPE */
	uint16_t		nr_pkt_length;
	crypto_req_handle_t	nr_kcfreq;
	n2cp_t			*nr_n2cp;
	clock_t			nr_timeout;
	int			nr_errno;
	/*
	 * Consumer's I/O buffers.
	 */
	crypto_data_t		*nr_in;
	crypto_data_t		*nr_out;
	crypto_data_t		nr_tmpin;

	/*
	 * CWB
	 */
	int			nr_cwq_id;	/* Associated CWQ ID */
	int			nr_id;		/* job id */
	int			nr_job_state;
	cwq_cw_t		nr_cws[N2CP_MAX_CHAIN];
	cwq_cw_t		*nr_cwb;
	int			nr_cwcnt;

	nr_ctx_t		*nr_context;
	int			nr_context_sz;
	int			nr_blocksz;
	uint64_t		nr_context_paddr;

	n2cp_request_t		*nr_rdylink;

	/*
	 * Callback.
	 */
	void			(*nr_callback)(n2cp_request_t *);
	/*
	 * Other stuff.
	 */
	/* pre-allocated buffers */
	uchar_t			*nr_in_buf;
	uint64_t		nr_in_buf_paddr;
	n2cp_buf_struct_t	*nr_in_buf_struct;
	uchar_t			*nr_out_buf;
	uint64_t		nr_out_buf_paddr;
	n2cp_buf_struct_t	*nr_out_buf_struct;

	uint32_t		nr_flags;
	int			nr_resultlen;
	/*
	 * Statistics.
	 */
	int			nr_job_stat;
};

struct n2cp {
	int				n_hvapi_major_version;
	int				n_hvapi_minor_version;
	dev_info_t			*n_dip;

	unsigned			n_flags;	/* dev state flags */

	kstat_t				*n_ksp;
	uint64_t			n_stats[DS_MAX];

	ddi_intr_handle_t		*n_htable;
	int				n_intr_cid[N2CP_MAX_NCWQS];
	int				n_intr_cnt;
	size_t				n_intr_size;
	uint_t				n_intr_pri;

	size_t				n_reqctx_sz;
	crypto_kcf_provider_handle_t	n_prov;

	kmutex_t			n_freereqslock;
	n2cp_listnode_t			n_freereqs; /* available requests */
	n2cp_listnode_t			n_ctx_list; /* list of all requests */

	/* pool of 64KB contig buffer used for scatter-gather */
	n2cp_listnode_t			n_buf_pool;
	uint32_t			n_buf_cnt;
	kmutex_t			n_buf_pool_lock;

	md_t				*n_mdp;
	n2cp_cwq2cpu_map_t		n_cwqmap;

	kmutex_t			n_timeout_lock;
	n2cp_timeout_t			n_timeout;
	n2cp_job_info_t			n_job[N2CP_MAX_NCWQS];
	n2cp_mode_t			n_mode;
	int				n_spins_per_usec;
};

/* CK_AES_CTR_PARAMS provides the parameters to the CKM_AES_CTR mechanism */
typedef struct CK_AES_CTR_PARAMS {
	ulong_t		ulCounterBits;
	uint8_t		iv[AESBLOCK];
} CK_AES_CTR_PARAMS;

typedef struct CK_AES_CTR_PARAMS32 {
	uint32_t	ulCounterBits;
	uint8_t		iv[AESBLOCK];
} CK_AES_CTR_PARAMS32;


/*
 * Priority of task threads used for handling interrupts.
 */
#define	N2CP_INTRTASK_PRI	80

#endif	/* _KERNEL */

/*
 * Miscellaneous defines.
 */
#define	ROUNDUP(a, n)		(((a) + ((n) - 1)) & ~((n) - 1))
#define	ROUNDDOWN(a, n)		((a) & ~((n) - 1))
#define	PAD32(x)		ROUNDUP(x, sizeof (uint32_t))
#define	PADAES(x)		ROUNDUP(x, AESBLOCK)
#define	BYTES_TO_UINT64(n)	\
	(((n) + (sizeof (uint64_t) - 1)) / sizeof (uint64_t))
#define	BYTES_TO_UINT32(n)	\
	(((n) + (sizeof (uint32_t) - 1)) / sizeof (uint32_t))

#if defined(_KERNEL)

#define	N2CP_REQ_SETUP(reqp, in, out) \
	reqp->nr_tmpin = *in; \
	reqp->nr_in = &reqp->nr_tmpin; \
	if (in == out) { \
		reqp->nr_out = in; \
	} else { \
		reqp->nr_out = out; \
	} \
	reqp->nr_out->cd_length = 0;

#if defined(DEBUG)

#define	DWARN		0x00000001
#define	DMA_ARGS	0x00000002
#define	DMA_LDST	0x00000004
#define	DNCS_QTAIL	0x00000008
#define	DATTACH		0x00000010
#define	DMD		0x00000020
#define	DHV		0x00000040
#define	DINTR		0x00000080
#define	DMOD		0x00000100  /* _init/_fini/_info/attach/detach */
#define	DCHATTY		0x00000400
#define	DALL		0xFFFFFFFF

void	n2cp_dprintf(n2cp_t *, int, const char *, ...);
void	n2cp_dumphex(void *, int);
int	n2cp_dflagset(int);

#define	DBG0	n2cp_dprintf
#define	DBG1	n2cp_dprintf
#define	DBG2	n2cp_dprintf
#define	DBG3	n2cp_dprintf
#define	DBG4	n2cp_dprintf

#else	/* !defined(DEBUG) */

#define	DBG0(vca, lvl, fmt)
#define	DBG1(vca, lvl, fmt, arg1)
#define	DBG2(vca, lvl, fmt, arg1, arg2)
#define	DBG3(vca, lvl, fmt, arg1, arg2, arg3)
#define	DBG4(vca, lvl, fmt, arg1, arg2, arg3, arg4)


#endif	/* !defined(DEBUG) */

/*
 * n2cp.c
 */
int	n2cp_start(n2cp_t *, n2cp_request_t *);
void	*n2_contig_alloc(int);
void	n2_contig_free(void *, int);


/*
 * n2cp_debug.c
 */
void	n2cp_error(n2cp_t *, const char *, ...);
void	n2cp_diperror(dev_info_t *, const char *, ...);
void	n2cp_dipverror(dev_info_t *, const char *, va_list);
void	n2cp_dump_cwb(cwq_cw_t *cw);
void	n2cp_dumphex(void *, int);
void	n2cp_offline_cwq(n2cp_t *n2cp, int cwq_id);

/*
 * n2cp_kstat.c
 */
void	n2cp_ksinit(n2cp_t *);
void	n2cp_ksdeinit(n2cp_t *);

/*
 * n2cp_kcf.c
 */
int	n2cp_init(n2cp_t *);
int	n2cp_uninit(n2cp_t *);
int	n2cp_get_inbuf(n2cp_t *, n2cp_request_t *);
int	n2cp_get_outbuf(n2cp_t *, n2cp_request_t *);
void	n2cp_free_buf(n2cp_t *, n2cp_request_t *);
n2cp_request_t *n2cp_getreq(n2cp_t *, int);
void	n2cp_freereq(n2cp_request_t *);
void	n2cp_destroyreq(n2cp_request_t *);
caddr_t	n2cp_bufdaddr(crypto_data_t *);
int	n2cp_gather(crypto_data_t *, char *, int);
int	n2cp_gather_zero_pad(crypto_data_t *, caddr_t, size_t, int);
int	n2cp_scatter(const char *, crypto_data_t *, int);
int	n2cp_sgcheck(crypto_data_t *, int);
int	n2cp_construct_chain(cwq_cw_t *, crypto_data_t *, int, int *chaincnt);
int	n2cp_attr_lookup_uint8_array(crypto_object_attribute_t *, uint_t,
			uint64_t, void **, unsigned int *);
crypto_object_attribute_t *
	n2cp_find_attribute(crypto_object_attribute_t *, uint_t, uint64_t);
char	*n2cp_get_dataaddr(crypto_data_t *, off_t);
void	n2cp_setresid(crypto_data_t *, int);
void	n2cp_getbufbytes(crypto_data_t *, int, int, char *);
uint16_t n2cp_padhalf(int);
uint16_t n2cp_padfull(int);

void n2cp_initq(n2cp_listnode_t *);
void n2cp_enqueue(n2cp_listnode_t *, n2cp_listnode_t *);
n2cp_listnode_t *n2cp_dequeue(n2cp_listnode_t *);
void    n2cp_rmqueue(n2cp_listnode_t *);
int	n2cp_is_emptyqueue(n2cp_listnode_t *);
void    n2cp_mvqueue(n2cp_listnode_t *, n2cp_listnode_t *);
void n2cp_enqueue_ctx(n2cp_t *, n2cp_listnode_t *);
void n2cp_dequeue_ctx(n2cp_t *, n2cp_listnode_t *);


/*
 * n2cp_hash.c
 */
int	n2cp_hashatomic(n2cp_t *, crypto_mechanism_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
int	n2cp_hashinit(crypto_ctx_t *, crypto_mechanism_t *);
int	n2cp_hash(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);

/*
 * n2cp_block.c
 */
int	n2cp_blockinit(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, int);
int	n2cp_block(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
int	n2cp_blockupdate(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t *);
int	n2cp_blockfinal(crypto_ctx_t *, crypto_data_t *, crypto_req_handle_t *);
int	n2cp_blockatomic(n2cp_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t, int);
void	n2cp_clean_blockctx(n2cp_request_t *);
int	n2cp_aes_ctr_allocmech(crypto_mechanism_t *, crypto_mechanism_t *,
    int *, int);
int	n2cp_aes_ctr_freemech(crypto_mechanism_t *);


/*
 * n2cp_hmac.c
 */
int	n2cp_hmacinit(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *);
int	n2cp_hmac_sign(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
int	n2cp_hmac_verify(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
int	n2cp_hmac_signatomic(n2cp_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
int	n2cp_hmac_verifyatomic(n2cp_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
void	n2cp_clean_hmacctx(n2cp_request_t *);
int	n2cp_ssl3_sha1_mac_signatomic(n2cp_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
int	n2cp_ssl3_sha1_mac_verifyatomic(n2cp_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_data_t *, crypto_data_t *, crypto_req_handle_t);

/*
 * n2cp_md.c
 */
int	n2cp_init_cwq2cpu_map(n2cp_t *);
void	n2cp_deinit_cwq2cpu_map(n2cp_t *);
int	n2cp_map_cwq_to_cpu(n2cp_t *, int, int);
int	n2cp_map_cpu_to_cwq(n2cp_t *, int);
int	n2cp_map_nextcwq(n2cp_t *);
cwq_entry_t	*n2cp_map_findcwq(n2cp_t *, int);
void	n2cp_online_cwq(n2cp_t *, int cwq_id);
void	n2cp_offline_cwq(n2cp_t *, int cwq_id);
void	n2cp_online_cpu(n2cp_t *, int cpu_id);
void	n2cp_offline_cpu(n2cp_t *, int cpu_id);

/*
 * n2cp_asm.s
 */
void n2cp_delay(void);

#ifdef N2_ERRATUM_175

typedef struct noncache_info {
	int		n_workaround_enabled;
	/*
	 * Stats to track how many (4M) slabs get allocated.
	 * Intended for debugging problems or performance analysis.
	 */
	uint64_t	n_alloc;	/* # contig slabs alloc'd */
	uint64_t	n_free;		/* # contig slabs free'd */
	uint64_t	n_alloc_fail;	/* contig_mem_alloc failures */
	uint64_t	n_hat_fail;	/* hat_getattr failures */
	uint64_t	n_sync_fail;	/* mem_sync failures */
	/*
	 * The following are function pointers to switch between
	 * standard contig_mem_alloc/free and bcopy, and our special
	 * noncache_contig_mem_alloc/free and noncache_bcopy.
	 * Set up at driver attach time.
	 */
	void		*(*n_contig_alloc)(size_t);
	void		(*n_contig_free)(void *, size_t);
	void		(*n_bcopy)(const void *, void *, size_t);
} noncache_info_t;

extern noncache_info_t	n2cp_nc;

#define	BCOPY	n2cp_nc.n_bcopy

#else /* N2_ERRATUM_175 */

#define	BCOPY	bcopy

#endif /* N2_ERRATUM_175 */

#define	n2cp_setfailed(n2cp)		((n2cp)->n_flags |= N2CP_FAILED)
#define	n2cp_isfailed(n2cp)		((n2cp)->n_flags & N2CP_FAILED)
#define	n2cp_setregistered(n2cp)	((n2cp)->n_flags |= N2CP_REGISTERED)
#define	n2cp_clrregistered(n2cp)	((n2cp)->n_flags &= ~N2CP_REGISTERED)
#define	n2cp_isregistered(n2cp)		((n2cp)->n_flags & N2CP_REGISTERED)
#define	n2cp_setcpuregistered(n2cp)	((n2cp)->n_flags |= N2CP_CPU_REGISTERED)
#define	n2cp_clrcpuregistered(n2cp) ((n2cp)->n_flags &= ~N2CP_CPU_REGISTERED)
#define	n2cp_iscpuregistered(n2cp)	((n2cp)->n_flags & N2CP_CPU_REGISTERED)

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_N2CP_H */
