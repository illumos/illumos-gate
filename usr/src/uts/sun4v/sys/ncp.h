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

#ifndef	_SYS_NCP_H
#define	_SYS_NCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/mdesc.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/ncs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DRIVER			"ncp"
#define	NCP_MANUFACTURER_ID	"SUNWncp"

#if defined(_KERNEL)

#define	FALSE		0
#define	TRUE		1

#define	N_MBLKL(mp)	((uint64_t)(mp)->b_wptr - (uint64_t)(mp)->b_rptr)

#define	NCP_N1_MAX_NMAUS		8
#define	NCP_N1_MAX_CPUS_PER_MAU		4
#define	NCP_N2_MAX_NMAUS		8
#define	NCP_N2_MAX_CPUS_PER_MAU		8
#define	NCP_MAX_MAX_NMAUS		NCP_N2_MAX_NMAUS

#define	NCP_CPUID2MAUID(n, c)		((c) / (n)->n_max_cpus_per_mau)

#define	NCP_MAX_HELPERTHREADS(n)	((n)->n_max_nmaus * \
						(n)->n_max_cpus_per_mau)

#define	NCP_BINDNAME_N1		"SUNW,sun4v-ncp"
#define	NCP_BINDNAME_N2		"SUNW,n2-mau"

typedef enum {
	NCP_CPU_UNKNOWN,
	NCP_CPU_N1,
	NCP_CPU_N2
} ncp_binding_t;

/*
 * These are constants.  Do not change them.
 */
#define	MAXPACKET	0xffff	/* Max size of a packet or fragment */
#define	DSAPARTLEN	20	/* Size of fixed DSA parts (r, s, q, x, v) */
#define	DSASIGLEN	40	/* Size of a DSA signature */

/*
 * Mechanism info structure passed to KCF during registration.
 */
#define	DSA_MIN_KEY_LEN		64	/* DSA min key length in bytes */
#define	DSA_MAX_KEY_LEN		128	/* DSA max key length in bytes */

#define	RSA_MIN_KEY_LEN		32	/* RSA min key length in bytes */
#define	RSA_MAX_KEY_LEN		256	/* RSA max key length in bytes */

/*
 * RSA implementation.
 */
#define	NCP_RSA_ENC	0
#define	NCP_RSA_DEC	1
#define	NCP_RSA_SIGN	2
#define	NCP_RSA_VRFY	3
#define	NCP_RSA_SIGNR	4
#define	NCP_RSA_VRFYR	5

/*
 * DSA implementation.
 */
#define	NCP_DSA_SIGN	0
#define	NCP_DSA_VRFY	1

/*
 * NCP Structures.
 */
typedef struct ncp ncp_t;
typedef struct ncp_minor ncp_minor_t;
typedef struct ncp_listnode ncp_listnode_t;
typedef struct ncp_request ncp_request_t;
typedef struct ncp_stat ncp_stat_t;

/*
 * Linked-list linkage.
 */
struct ncp_listnode {
	ncp_listnode_t	*nl_next;
	ncp_listnode_t	*nl_prev;
};

typedef enum ncp_mech_type {
	DSA_MECH_INFO_TYPE,		/* SUN_CKM_DSA */
	RSA_X_509_MECH_INFO_TYPE,	/* SUN_CKM_RSA_X_509 */
	RSA_PKCS_MECH_INFO_TYPE		/* SUN_CKM_RSA_PKCS */
} ncp_mech_type_t;


#define	SUN_CKM_DSA			"CKM_DSA"


/*
 * Work structure.
 * Contains everything we need to submit the job, and everything we
 * need to notify caller and release resources.
 */
struct ncp_request {
	ncp_listnode_t		nr_linkage;
	uint16_t		nr_pkt_length;
	crypto_req_handle_t	nr_kcf_req;
	ncp_t			*nr_ncp;
	clock_t			nr_timeout;

	/*
	 * Consumer's I/O buffers.
	 */
	crypto_data_t		*nr_in;
	crypto_data_t		*nr_out;

	crypto_mech_type_t	nr_ctx_cm_type;	/* Mechanism type */
	int			nr_mode;	/* Mode of operation */
	int 			nr_atomic;	/* Boolean */

	uint8_t			nr_mod_orig[RSA_MAX_KEY_LEN];
	uint8_t			nr_exp[RSA_MAX_KEY_LEN];
	uint8_t			nr_mod[RSA_MAX_KEY_LEN];
	uint8_t			nr_p[RSA_MAX_KEY_LEN];
	uint8_t			nr_q[RSA_MAX_KEY_LEN];
	uint8_t			nr_dp[RSA_MAX_KEY_LEN]; /* g for DSA */
	uint8_t			nr_dq[RSA_MAX_KEY_LEN]; /* x or y for DSA */
	uint8_t			nr_pinv[RSA_MAX_KEY_LEN];

	uint8_t			nr_inbuf[RSA_MAX_KEY_LEN];
	uint8_t			nr_outbuf[RSA_MAX_KEY_LEN];

	unsigned		nr_inlen;
	unsigned		nr_modlen;
	unsigned		nr_explen;
	unsigned		nr_plen;
	unsigned		nr_qlen;
	unsigned		nr_dplen; /* glen for DSA */
	unsigned		nr_dqlen; /* xlen or ylen for DSA */
	unsigned		nr_pinvlen;

	/*
	 * Callback.
	 */
	void			(*nr_callback)(ncp_request_t *, int);
	/*
	 * Other stuff.
	 */
	uint32_t		nr_flags;
	/*
	 * Statistics.
	 */
	int			nr_job_stat;
	int			nr_byte_stat;

	/* Destroy this request if true */
	int			nr_destroy;
};

/*
 * Request flags (ncp_request_t.dr_flags).
 */
#define	DR_INPLACE		0x002
#define	DR_SCATTER		0x004
#define	DR_GATHER		0x008
#define	DR_NOCACHE		0x020
#define	DR_ENCRYPT		0x040
#define	DR_DECRYPT		0x080
#define	DR_TRIPLE		0x100	/* triple DES vs. single DES */
#define	DR_ATOMIC		0x200	/* for atomic operation */

/*
 * Scatter/gather checks.
 */
typedef enum ncp_sg_param {
	NCP_SG_CONTIG = 1,
	NCP_SG_WALIGN,
	NCP_SG_PALIGN
} ncp_sg_param_t;

/*
 * Kstats.
 */
#define	DS_RSAPUBLIC		0
#define	DS_RSAPRIVATE		1
#define	DS_DSASIGN		2
#define	DS_DSAVERIFY		3
#define	DS_MAX			4


/*
 * Used to guarantee alignment.
 */
#define	ROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))
#define	ROUNDDOWN(a, n)	(((a) & ~((n) - 1)))
#define	HIDBLWORD(x)	(((x) & 0xffffffff00000000ULL) >> 32)
#define	LODBLWORD(x)	((x) & 0xffffffffULL)

/*
 * Other utility macros.
 */
#define	QEMPTY(q)	((q)->dl_next == (q))
#define	BITS2BYTES(b)	((b) >> 3)

/*
 * Some pkcs#11 defines as there are no pkcs#11 header files included.
 */
#define	CKA_VALUE		0x00000011
#define	CKA_KEY_TYPE		0x00000100
#define	CKA_MODULUS		0x00000120
#define	CKA_PUBLIC_EXPONENT	0x00000122
#define	CKA_PRIVATE_EXPONENT	0x00000123
#define	CKA_PRIME_1		0x00000124
#define	CKA_PRIME_2		0x00000125
#define	CKA_EXPONENT_1		0x00000126
#define	CKA_EXPONENT_2		0x00000127
#define	CKA_COEFFICIENT		0x00000128
#define	CKA_PRIME		0x00000130
#define	CKA_SUBPRIME		0x00000131
#define	CKA_BASE		0x00000132


struct ncp_stat {
	kstat_named_t		ns_status;
	kstat_named_t		ns_algs[DS_MAX];
	struct {
		kstat_named_t	ns_mauid;
		kstat_named_t	ns_mauhandle;
		kstat_named_t	ns_maustate;
		kstat_named_t	ns_submit;
		kstat_named_t	ns_qfull;
		kstat_named_t	ns_qbusy;
		kstat_named_t	ns_qupdate_failure;
		kstat_named_t	ns_nintr;
		kstat_named_t	ns_nintr_err;
		kstat_named_t	ns_nintr_jobs;
	}			ns_mau[NCP_MAX_MAX_NMAUS];
};

/*
 * Device flags (ncp_t.n_flags)
 */
#define	NCP_FAILED		0x0000001
#define	NCP_ATTACHED		0x0000002
#define	NCP_REGISTERED		0x0000004
#define	NCP_CPU_REGISTERED	0x0000008

/*
 * IMPORTANT:
 *	NCP_MAQUEUE_NENTRIES *must* be a power-of-2.
 *	requirement: sizeof (ncs_hvdesc_t) == 64
 */
#define	NCP_MAQUEUE_NENTRIES	(1 << 9)	/* 512 */
#define	NCP_MAQUEUE_WRAPMASK	(NCP_MAQUEUE_NENTRIES - 1)
#define	NCP_MAQUEUE_SIZE	(NCP_MAQUEUE_NENTRIES * sizeof (ncs_hvdesc_t))
#define	NCP_MAQUEUE_ALIGN	(NCP_MAQUEUE_SIZE - 1)
#define	NCP_MAQUEUE_SLOTS_USED(q)	\
		(((q)->nmq_tail - (q)->nmq_head) & NCP_MAQUEUE_WRAPMASK)
#define	NCP_MAQUEUE_SLOTS_AVAIL(q)	\
		(NCP_MAQUEUE_NENTRIES - NCP_MAQUEUE_SLOTS_USED(q) - 1)

#define	NCP_QINDEX_TO_QOFFSET(i)	((i) * sizeof (ncs_hvdesc_t))
#define	NCP_QOFFSET_TO_QINDEX(o)	((o) / sizeof (ncs_hvdesc_t))
#define	NCP_QINDEX_INCR(i)		(((i) + 1) & NCP_MAQUEUE_WRAPMASK)
#define	NCP_QINDEX_IS_VALID(i)		(((i) >= 0) && \
						((i) < NCP_MAQUEUE_NENTRIES))
#define	NCP_QTIMEOUT_SECONDS		60

typedef struct ncp_ma {
	kmutex_t	nma_lock;
	uint8_t		*nma_mem;	/* MA memory */
	int		nma_ref;	/* # of descriptor references */
} ncp_ma_t;

typedef struct ncp_desc ncp_desc_t;
struct ncp_desc {
	ncs_hvdesc_t	nd_hv;
	ncp_desc_t	*nd_link;	/* to string related descriptors */
	ncp_ma_t	*nd_ma;		/* referenced MA buffer */
};

typedef struct ncp_descjob {
	int			dj_id;
	kcondvar_t		dj_cv;
	boolean_t		dj_pending;	/* awaiting MAU */
	ncp_desc_t		*dj_jobp;
	struct ncp_descjob	*dj_prev;
	struct ncp_descjob	*dj_next;
	int			dj_error;
} ncp_descjob_t;

/*
 * nmq_head, nmq_tail = indexes into nmq_desc[].
 */
typedef struct {
	uint64_t	nmq_handle;
	uint64_t	nmq_devino;
	int		nmq_inum;
	int		nmq_mauid;
	int		nmq_init;
	int		nmq_busy_wait;
	kcondvar_t	nmq_busy_cv;
	kmutex_t	nmq_lock;
	int		nmq_head;
	int		nmq_tail;
	uint_t		nmq_wrapmask;
	ncp_descjob_t	**nmq_jobs;
	size_t		nmq_jobs_size;
	ncs_hvdesc_t	*nmq_desc;	/* descriptor array */
	char		*nmq_mem;
	size_t		nmq_memsize;
	ncp_descjob_t	*nmq_joblist;
	int		nmq_joblistcnt;
	struct {
		uint64_t	qks_njobs;
		uint64_t	qks_qfull;
		uint64_t	qks_qbusy;
		uint64_t	qks_qfail;
		uint64_t	qks_nintr;
		uint64_t	qks_nintr_err;
		uint64_t	qks_nintr_jobs;
	} nmq_ks;
} ncp_mau_queue_t;

#define	MAU_STATE_ERROR		(-1)
#define	MAU_STATE_OFFLINE	0
#define	MAU_STATE_ONLINE	1

typedef struct {
	int		mm_mauid;
	int		mm_cpulistsz;
	int		*mm_cpulist;
	int		mm_ncpus;
	int		mm_nextcpuidx;
	/*
	 * Only protects mm_nextcpuidx
	 */
	kmutex_t	mm_lock;
	int		mm_state;	/* MAU_STATE_... */
	ncp_mau_queue_t	mm_queue;
} mau_entry_t;

typedef struct {
	int		mc_cpuid;
	int		mc_mauid;
	int		mc_state;	/* MAU_STATE_... */
} cpu_entry_t;

typedef struct {
	/*
	 * MAU stuff
	 */
	int		m_maulistsz;
	mau_entry_t	*m_maulist;
	int		m_nmaus;
	int		m_nmaus_online;
	int		m_nextmauidx;
	/*
	 * Only protects m_nextmauidx field.
	 */
	kmutex_t	m_lock;

	/*
	 * CPU stuff
	 */
	int		m_cpulistsz;
	cpu_entry_t	*m_cpulist;
	int		m_ncpus;
} ncp_mau2cpu_map_t;


#define	SECOND			1000000	/* micro seconds */
#define	NCP_JOB_STALL_LIMIT	2
typedef u_longlong_t ncp_counter_t;

/* Information for performing periodic timeout (stall) checks */
typedef struct ncp_timeout {
	clock_t		ticks;	/* Number of clock ticks before next check */
	timeout_id_t	id;	/* ID of timeout thread (used in detach) */
	ncp_counter_t	count;	/* Number of timeout checks made (statistic) */
} ncp_timeout_t;

/*
 * Job timeout information:
 *
 * A timeout condition will be detected if all "submitted" jobs have not been
 * "reclaimed" (completed) and we have not made any "progress" within the
 * cumulative timeout "limit".  The cumulative timeout "limit" is incremented
 * with a job specific timeout value (usually one second) each time a new job
 * is submitted.
 */
typedef struct ncp_job_info {
	kmutex_t	lock;		/* Lock for all other elements */
	ncp_counter_t	submitted;	/* Number of jobs submitted */
	ncp_counter_t	reclaimed;	/* Number of jobs completed */
	ncp_counter_t	progress;	/* Progress recorded during TO check */
	ncp_timeout_t	timeout;	/* Timeout processing information */
	struct {
		clock_t count;		/* Ticks since last completion */
		clock_t addend;		/* Added to count during TO check */
		clock_t limit;		/* Cumulative timeout value */
	} stalled;
} ncp_job_info_t;

struct ncp {
	uint_t				n_hvapi_major_version;
	uint_t				n_hvapi_minor_version;
	ncp_binding_t			n_binding;
	char				*n_binding_name;
	kmem_cache_t			*n_ds_cache;
	kmem_cache_t			*n_mactl_cache;
	kmem_cache_t			*n_mabuf_cache;
	dev_info_t			*n_dip;

	ddi_taskq_t			*n_taskq;

	uint_t				n_flags;	/* dev state flags */

	int				n_max_nmaus;
	int				n_max_cpus_per_mau;

	kstat_t				*n_ksp;
	u_longlong_t			n_stats[DS_MAX];

	ddi_intr_handle_t		*n_htable;
	int				n_intr_mid[NCP_MAX_MAX_NMAUS];
	int				n_intr_cnt;
	size_t				n_intr_size;
	uint_t				n_intr_pri;

	ulong_t				n_pagesize;
	crypto_kcf_provider_handle_t	n_prov;

	kmutex_t			n_freereqslock;
	ncp_listnode_t			n_freereqs;   /* available requests */

	kmutex_t			n_ctx_list_lock;
	ncp_listnode_t			n_ctx_list;

	md_t				*n_mdp;
	ncp_mau2cpu_map_t		n_maumap;
	kmutex_t			n_timeout_lock;
	ncp_timeout_t			n_timeout;
	ncp_job_info_t			n_job[NCP_MAX_MAX_NMAUS];
};

#endif	/* _KERNEL */

/*
 * Miscellaneous defines.
 */
#define	ROUNDUP(a, n)		(((a) + ((n) - 1)) & ~((n) - 1))
#define	BYTES_TO_UINT64(n)	\
	(((n) + (sizeof (uint64_t) - 1)) / sizeof (uint64_t))
#define	BYTES_TO_UINT32(n)	\
	(((n) + (sizeof (uint32_t) - 1)) / sizeof (uint32_t))

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
#define	DENTRY		0x00000200  /* crypto routine entry/exit points */
#define	DALL		0xFFFFFFFF

#define	DBG0	ncp_dprintf
#define	DBG1	ncp_dprintf
#define	DBG2	ncp_dprintf
#define	DBG3	ncp_dprintf
#define	DBG4	ncp_dprintf
#define	DBGCALL(flag, func)	{ if (ncp_dflagset(flag)) (void) func; }

void	ncp_dprintf(ncp_t *, int, const char *, ...);
void	ncp_dumphex(void *, int);
int	ncp_dflagset(int);

#else	/* !defined(DEBUG) */

#define	DBG0(vca, lvl, fmt)
#define	DBG1(vca, lvl, fmt, arg1)
#define	DBG2(vca, lvl, fmt, arg1, arg2)
#define	DBG3(vca, lvl, fmt, arg1, arg2, arg3)
#define	DBG4(vca, lvl, fmt, arg1, arg2, arg3, arg4)
#define	DBGCALL(flag, func)

#endif	/* !defined(DEBUG) */

/*
 * ncp_debug.c
 */
void    ncp_error(ncp_t *, const char *, ...);
void    ncp_diperror(dev_info_t *, const char *, ...);
void    ncp_dipverror(dev_info_t *, const char *, va_list);

/*
 * ncp_rsa.c
 */
int	ncp_rsastart(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
			crypto_req_handle_t, int);
int	ncp_rsainit(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *, int);
void	ncp_rsactxfree(void *);
int	ncp_rsaatomic(crypto_provider_handle_t, crypto_session_id_t,
			crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
			crypto_data_t *, int, crypto_req_handle_t, int);
int	ncp_rsa_private_process(ncp_t *ncp, ncp_request_t *reqp);
int	ncp_rsa_public_process(ncp_t *ncp, ncp_request_t *reqp);
int	ncp_dsa_sign_process(ncp_t *ncp, ncp_request_t *reqp);
int	ncp_dsa_verify_process(ncp_t *ncp, ncp_request_t *reqp);

/*
 * ncp_dsa.c
 */
int	ncp_dsa_sign(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
			crypto_req_handle_t);
int	ncp_dsa_verify(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
			crypto_req_handle_t);
int	ncp_dsainit(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
			int, int);
void	ncp_dsactxfree(void *);
int	ncp_dsaatomic(crypto_provider_handle_t, crypto_session_id_t,
			crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
			crypto_data_t *, int, crypto_req_handle_t, int);

/*
 * ncp_md.
 */
int	ncp_init_mau2cpu_map(ncp_t *);
void	ncp_deinit_mau2cpu_map(ncp_t *);
int	ncp_map_cpu_to_mau(ncp_t *, int);
int	ncp_map_mau_to_cpu(ncp_t *, int);
int	ncp_map_nextmau(ncp_t *);
mau_entry_t	*ncp_map_findmau(ncp_t *, int);
void	ncp_online_mau(ncp_t *, int mau_id);
void	ncp_offline_mau(ncp_t *, int mau_id);
void	ncp_online_cpu(ncp_t *, int cpu_id);
void	ncp_offline_cpu(ncp_t *, int cpu_id);


/*
 * ncp_kstat.c
 */
void	ncp_ksinit(ncp_t *);
void	ncp_ksdeinit(ncp_t *);

/*
 * ncp_kcf.c
 */
int	ncp_init(ncp_t *);
int	ncp_uninit(ncp_t *);
void	ncp_rmqueue(ncp_listnode_t *);
ncp_request_t *ncp_getreq(ncp_t *, int);
void	ncp_freereq(ncp_request_t *);
int	ncp_start(ncp_t *, ncp_request_t *);
void	ncp_done(ncp_request_t *, int);
void	ncp_destroyreq(ncp_request_t *);
int	ncp_length(crypto_data_t *);
int	ncp_gather(crypto_data_t *, char *, int, int);
int	ncp_scatter(const char *, crypto_data_t *, int, int);
int	ncp_sgcheck(ncp_t *, crypto_data_t *, ncp_sg_param_t);
crypto_object_attribute_t *ncp_get_key_attr(crypto_key_t *);
int	ncp_attr_lookup_uint8_array(crypto_object_attribute_t *, uint_t,
			uint64_t, void **, unsigned int *);
crypto_object_attribute_t *
	ncp_find_attribute(crypto_object_attribute_t *, uint_t, uint64_t);
caddr_t	ncp_bufdaddr(crypto_data_t *);
int	ncp_bitlen(unsigned char *, int);
uint16_t ncp_padhalf(int);
uint16_t ncp_padfull(int);
void	ncp_reverse(void *, void *, int, int);
int	ncp_numcmp(caddr_t, int, caddr_t, int);

int	ncp_free_context(crypto_ctx_t *);

#define	ncp_setfailed(ncp)	((ncp)->n_flags |= NCP_FAILED)
#define	ncp_isfailed(ncp)	((ncp)->n_flags & NCP_FAILED)
#define	ncp_setregistered(ncp)	((ncp)->n_flags |= NCP_REGISTERED)
#define	ncp_clrregistered(ncp)	((ncp)->n_flags &= ~NCP_REGISTERED)
#define	ncp_isregistered(ncp)	((ncp)->n_flags & NCP_REGISTERED)

#define	ncp_setcpuregistered(ncp)	((ncp)->n_flags |= NCP_CPU_REGISTERED)
#define	ncp_clrcpuregistered(ncp)	((ncp)->n_flags &= ~NCP_CPU_REGISTERED)
#define	ncp_iscpuregistered(ncp)	((ncp)->n_flags & NCP_CPU_REGISTERED)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NCP_H */
