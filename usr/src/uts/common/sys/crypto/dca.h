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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_CRYPTO_DCA_H
#define	_SYS_CRYPTO_DCA_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/varargs.h>

#include <sys/crypto/spi.h>

/*
 * Deimos - cryptographic acceleration based upon Broadcom 582x.
 *
 * Note: Everything in this file is private to the Deimos device
 *	 driver!  Do not include this in any other file.
 */

#define	DRIVER			"dca"
#define	DCA_MANUFACTURER_ID	"SUNWdca"

#ifdef _KERNEL

/*
 * Tunables.
 */
#define	MCR1LOWATER	16	/* these numbers favor overall throughput */
#define	MCR1HIWATER	24
#define	MCR1MAXREQS	8
#define	MCR2LOWATER	16
#define	MCR2HIWATER	24
#define	MCR2MAXREQS	4
#define	MAXMCR		2	/* there are 2 mcrs */
#define	MAXREQSPERMCR	16	/* there are 4 subunits serviced by MCR2 */
#define	MAXFRAGS	6	/* Limit on the number of fragments */
#define	MAXWORK		6	/* How many work structures to preallocate */

/*
 * These are constants.  Do not change them.
 */
#if defined(i386) || defined(__i386) || defined(__amd64)
#define	MAXPACKET	0xefff	/* rootnex INT_MAX_BUF hack. */
#else
#define	MAXPACKET	0xffff	/* Max size of a packet or fragment */
#endif
#define	DESBLOCK	8	/* Size of a DES or 3DES block */
#define	DSAPARTLEN	20	/* Size of fixed DSA parts (r, s, q, x, v) */
#define	DSASIGLEN	40	/* Size of a DSA signature */
#define	SHA1LEN		20	/* Size of a SHA1 hash */
#define	SECOND		1000000	/* One second in usec */
#define	MSEC		1000	/* One millisecond in usec */
#define	DES_KEYSIZE	8
#define	DES_IV_LEN	8
#define	DES3_KEYSIZE	(3 * DES_KEYSIZE)

/*
 * Mechanism info structure passed to KCF during registration.
 */

#define	MD5_HMAC_BLOCK_SIZE	64	/* MD5-HMAC block size */
#define	MD5_HMAC_MIN_KEY_LEN	1	/* MD5-HMAC min key length in bytes */
#define	MD5_HMAC_MAX_KEY_LEN	64	/* MD5-HMAC max key length in bytes */

#define	SHA1_HMAC_BLOCK_SIZE	64	/* SHA1-HMAC block size */
#define	SHA1_HMAC_MIN_KEY_LEN	1	/* SHA1-HMAC min key length in bytes */
#define	SHA1_HMAC_MAX_KEY_LEN	64	/* SHA1-HMAC max key length in bytes */

#define	DES_KEY_LEN		8	/* DES key length in bytes */
#define	DES3_MIN_KEY_LEN	16	/* 3DES min key length in bytes */
#define	DES3_MAX_KEY_LEN	24	/* 3DES max key length in bytes */

#define	DSA_MIN_KEY_LEN		64	/* DSA min key length in bytes */
#define	DSA_MAX_KEY_LEN		128	/* DSA max key length in bytes */

#define	RSA_MIN_KEY_LEN		32	/* RSA min key length in bytes */
#define	RSA_MAX_KEY_LEN		256	/* RSA max key length in bytes */

/*
 * RSA implementation.
 */

#define	DCA_RSA_ENC	0
#define	DCA_RSA_DEC	1
#define	DCA_RSA_SIGN	2
#define	DCA_RSA_VRFY	3
#define	DCA_RSA_SIGNR	4
#define	DCA_RSA_VRFYR	5

/*
 * DSA implementation.
 */

#define	DCA_DSA_SIGN	0
#define	DCA_DSA_VRFY	1

/*
 * FMA eclass index definitions. Note that this enum must be consistent
 * with the dca_fma_eclass_sca1000 and dca_fma_eclass_sca500 string arrays.
 */
typedef enum dca_fma_eclass {
	DCA_FM_ECLASS_HW_DEVICE = 0,
	DCA_FM_ECLASS_HW_TIMEOUT,
	DCA_FM_ECLASS_NONE
} dca_fma_eclass_t;

/*
 * Forward typedefs.
 */
typedef struct dca dca_t;
typedef struct dca_chain dca_chain_t;
typedef struct dca_listnode dca_listnode_t;
typedef struct dca_worklist dca_worklist_t;
typedef struct dca_work dca_work_t;
typedef struct dca_request dca_request_t;
typedef struct dca_stat dca_stat_t;
typedef struct dca_cookie dca_cookie_t;
typedef struct dca_device dca_device_t;

/*
 * This structure is used to identify a specific board.
 */
struct dca_device {
	ushort_t		dd_vendor_id;
	ushort_t		dd_device_id;
	char			*dd_model;
};

/*
 * Structure representing a node in a DMA chain.  (Broadcom calls
 * these "Data Buffer Chain Entries".)
 *
 * note, this structure must be a multiple of sizeof (intptr_t)
 */
struct dca_chain {
	/* the descriptor */
	caddr_t			dc_desc_kaddr;
	/* and the buffer to which it points */
	size_t			dc_buffer_length;
	ddi_dma_handle_t	dc_buffer_dmah;
	caddr_t			dc_buffer_kaddr;
	/* physical addresses */
	uint32_t		dc_desc_paddr;
	uint32_t		dc_buffer_paddr;
	uint32_t		dc_next_paddr;
};

/*
 * Linked-list linkage.
 */
struct dca_listnode {
	dca_listnode_t		*dl_next;
	dca_listnode_t		*dl_prev;
	dca_listnode_t		*dl_next2;
	dca_listnode_t		*dl_prev2;
};

typedef enum dca_mech_type {
	DES_CBC_MECH_INFO_TYPE,		/* SUN_CKM_DES_CBC */
	DES3_CBC_MECH_INFO_TYPE,	/* SUN_CKM_DES3_CBC */
	DSA_MECH_INFO_TYPE,		/* SUN_CKM_DSA */
	RSA_X_509_MECH_INFO_TYPE,	/* SUN_CKM_RSA_X_509 */
	RSA_PKCS_MECH_INFO_TYPE		/* SUN_CKM_RSA_PKCS */
} dca_mech_type_t;

#define	SUN_CKM_DSA			"CKM_DSA"

struct dca_rng {
	uint32_t		dr_chunklen;
};

union dca_parameters {
	struct dca_rng		dp_rng;
};

typedef struct dca_ctx {
	/*
	 * The following are context fields for Deimos 2.0.
	 */
	crypto_mech_type_t	ctx_cm_type;	/* Mechanism type */
	int			mode;		/* Mode of operation */
	int 			atomic;		/* Boolean */

	/* Fields for RSA and DSA */
	uchar_t			*mod;		/* RSA modulus */
	unsigned		modlen;		/* RSA modulus length */
	unsigned		pqfix;		/* RSA flag */

	/* Fields for DES and 3DES */
	uint32_t		iv[2];
	uint32_t		key[6];
	int			residlen;
	uchar_t			resid[DESBLOCK];
	int			activeresidlen;
	uchar_t			activeresid[DESBLOCK];
	crypto_data_t		in_dup;		/* input data duplicate */
} dca_ctx_t;

/*
 * Work structure.  One of these per actual job submitted to an MCR.
 * Contains everything we need to submit the job, and everything we
 * need to notify caller and release resources when the completion
 * interrupt comes.
 */
struct dca_request {
	dca_listnode_t		dr_linkage;
	uint16_t		dr_pkt_length;
	crypto_req_handle_t	dr_kcf_req;
	dca_t			*dr_dca;
	dca_worklist_t		*dr_wlp;
	/*
	 * Consumer's I/O buffers.
	 */
	crypto_data_t		*dr_in;
	crypto_data_t		*dr_out;
	dca_ctx_t		dr_ctx;
	/*
	 * Chains and DMA structures.
	 */
	size_t			dr_dma_size;
	uint32_t		dr_ctx_paddr;
	caddr_t			dr_ctx_kaddr;
	ddi_acc_handle_t	dr_ctx_acch;
	ddi_dma_handle_t	dr_ctx_dmah;
	/*
	 * Scratch input buffer.
	 */
	ddi_acc_handle_t	dr_ibuf_acch;
	ddi_dma_handle_t	dr_ibuf_dmah;
	caddr_t			dr_ibuf_kaddr;
	uint32_t		dr_ibuf_paddr;

	/*
	 * Scratch output buffer.
	 */
	ddi_acc_handle_t	dr_obuf_acch;
	ddi_dma_handle_t	dr_obuf_dmah;
	caddr_t			dr_obuf_kaddr;
	uint32_t		dr_obuf_paddr;

	/*
	 * Values to program MCR with.
	 */
	uint32_t		dr_in_paddr;
	uint32_t		dr_out_paddr;
	uint32_t		dr_in_next;
	uint32_t		dr_out_next;
	uint16_t		dr_in_len;
	uint16_t		dr_out_len;
	/*
	 * Callback.
	 */
	void			(*dr_callback)(dca_request_t *, int);
	/*
	 * Other stuff.
	 */
	uint32_t		dr_flags;
	/*
	 * Algorithm specific parameters.
	 */
	void			*dr_context;
	union dca_parameters	dr_param;
	/*
	 * Statistics.
	 */
	int			dr_job_stat;
	int			dr_byte_stat;

	/* Pre-mapped input and output data buffer chain support */
	dca_chain_t		dr_ibuf_head;
	dca_chain_t		dr_obuf_head;

	/*
	 * User buffers are mapped to DMA handles dynamically. The physically
	 * contigous blocks ( >= a page) are built into a data buffer chain.
	 */
	dca_chain_t		dr_chain_in_head;
	ddi_dma_handle_t	dr_chain_in_dmah;

	dca_chain_t		dr_chain_out_head;
	ddi_dma_handle_t	dr_chain_out_dmah;

	/* Offset in the context page for storing dynamic buffer chains */
	int			dr_offset;

	/* Destroy this request if true */
	int			destroy;
};

/*
 * Request flags (dca_request_t.dr_flags).
 */
#define	DR_INPLACE		0x002
#define	DR_SCATTER		0x004
#define	DR_GATHER		0x008
#define	DR_NOCACHE		0x020
#define	DR_ENCRYPT		0x040
#define	DR_DECRYPT		0x080
#define	DR_TRIPLE		0x100	/* triple DES vs. single DES */
#define	DR_ATOMIC		0x200	/* for atomic operation */

struct dca_work {
	dca_listnode_t		dw_linkage;
	dca_worklist_t		*dw_wlp;

	/* DMA access to the MCR and context */
	ddi_acc_handle_t	dw_mcr_acch;
	ddi_dma_handle_t	dw_mcr_dmah;
	caddr_t			dw_mcr_kaddr;
	uint32_t		dw_mcr_paddr;

	dca_request_t		*dw_reqs[MAXREQSPERMCR];
	clock_t			dw_lbolt;
};

/*
 * MCRs.
 */
#define	MCR1			0x1
#define	MCR2			0x2

struct dca_worklist {
	dca_t			*dwl_dca;
	crypto_kcf_provider_handle_t	dwl_prov;
	char			dwl_name[16];
	int			dwl_mcr;
	kmutex_t		dwl_lock;
	kmutex_t		dwl_freelock;
	kmutex_t		dwl_freereqslock;
	kcondvar_t		dwl_cv;
	dca_listnode_t		dwl_freereqs;	/* available requests */
	dca_listnode_t		dwl_waitq;	/* requests arrive here */
	dca_listnode_t		dwl_freework;	/* available work structures */
	dca_listnode_t		dwl_runq;	/* work structs sent to chip */
	timeout_id_t		dwl_schedtid;
	clock_t			dwl_lastsubmit;
	int			dwl_count;
	int			dwl_busy;
	int			dwl_lowater;
	int			dwl_hiwater;
	int			dwl_reqspermcr;
	int			dwl_drain;	/* for DR (suspend) */
	/* Kstats */
	u_longlong_t		dwl_submit;
	u_longlong_t		dwl_flowctl;
};

/*
 * Operations for MCR1 (bulk stuff).
 */
#define	CMD_IPSEC		0x0	/* IPsec packet processing */
#define	CMD_SSLMAC		0x1	/* SSL HMAC processing */
#define	CMD_TLSMAC		0x2	/* TLS HMAC processing */
#define	CMD_3DES		0x3	/* SSL/TLS/raw 3DES processing */
#define	CMD_RC4			0x4	/* ARCFOUR procesing */
#define	CMD_PUREHASH		0x5	/* Pure MD5/SHA1 hash processing */

/*
 * Operations for MCR2 (key stuff).
 */
#define	CMD_DHPUBLIC		0x1	/* DH public key generation */
#define	CMD_DHSHARED		0x2	/* DH shared secret generation */
#define	CMD_RSAPUBLIC		0x3	/* RSA public key operation */
#define	CMD_RSAPRIVATE		0x4	/* RSA private key operation (CRT) */
#define	CMD_DSASIGN		0x5	/* DSA signing operation */
#define	CMD_DSAVERIFY		0x6	/* DSA verification operation */
#define	CMD_RNGDIRECT		0x41	/* Direct access to the RNG */
#define	CMD_RNGSHA1		0x42	/* RNG output processed by SHA1 */
#define	CMD_MODADD		0x43	/* Modular add */
#define	CMD_MODSUB		0x44	/* Moduler subtract */
#define	CMD_MODMUL		0x45	/* Modular multiply */
#define	CMD_MODREM		0x46	/* Modular remainder */
#define	CMD_MODEXP		0x47	/* Modular exponentiation */
#define	CMD_MODINV		0x48	/* Modular inverse */

/*
 * Kstats.
 */
#define	DS_3DESJOBS		0
#define	DS_3DESBYTES		1
#define	DS_RSAPUBLIC		2
#define	DS_RSAPRIVATE		3
#define	DS_DSASIGN		4
#define	DS_DSAVERIFY		5
#define	DS_RNGJOBS		6
#define	DS_RNGBYTES		7
#define	DS_RNGSHA1JOBS		8
#define	DS_RNGSHA1BYTES		9
#define	DS_MAX			10

#if 0
/*
 * note that when reenabling any of these stats, DS_MAX will need to
 * be adjusted.
 */
#define	DS_RC4JOBS		11
#define	DS_RC4BYTES		12
#define	DS_DHPUBLIC		13
#define	DS_DHSECRET		14
#endif

struct dca_stat {
	kstat_named_t		ds_status;
	kstat_named_t		ds_algs[DS_MAX];
	struct {
		kstat_named_t	ds_submit;
		kstat_named_t	ds_flowctl;
		kstat_named_t	ds_lowater;
		kstat_named_t	ds_hiwater;
		kstat_named_t	ds_maxreqs;
	}			ds_mcr[MAXMCR];
};

/*
 * Blocking structure for ioctls.
 */
struct dca_cookie {
	kmutex_t		dc_mx;
	kcondvar_t		dc_cv;
	int			dc_outstanding;
	int			dc_status;
};

/*
 * Per instance structure.
 */
struct dca {
	dev_info_t		*dca_dip;
	kmutex_t		dca_intrlock;
	caddr_t			dca_regs;
	ddi_acc_handle_t	dca_regs_handle;
	ddi_iblock_cookie_t	dca_icookie;
	timeout_id_t		dca_jobtid;
	ulong_t			dca_pagesize;
	unsigned		dca_flags;	/* dev state flags */

	/*
	 * Work requests.
	 */
	dca_worklist_t		dca_worklist[MAXMCR];

	/*
	 * hardware model
	 */
	char			*dca_model;
	ushort_t		dca_devid;

	/*
	 * Kstats.  There is no standard for what standards
	 * Cryptographic Providers should supply, so we're
	 * making them up for now.
	 */
	kstat_t			*dca_ksp;
	kstat_t			*dca_intrstats;
	u_longlong_t		dca_stats[DS_MAX];

	/* For the local random number pool used internally by the dca driver */
	char 			*dca_buf1;
	char 			*dca_buf2;
	char 			*dca_buf_ptr;
	int 			dca_index;
	uint32_t 		dca_random_filling;
	kmutex_t 		dca_random_lock;

	/* FMA capabilities */
	int			fm_capabilities;	/* FMA capabilities */

	kmutex_t		dca_ctx_list_lock;
	dca_listnode_t		dca_ctx_list;
};

/*
 * Device flags (dca_t.dca_flags)
 */
#define	DCA_FAILED		0x1
#define	DCA_POWERMGMT		0x4
#define	DCA_RNGSHA1		0x8

#define	KIOIP(dca)		KSTAT_INTR_PTR((dca)->dca_intrstats)

/*
 * Scatter/gather checks.
 */
typedef enum dca_sg_param {
	DCA_SG_CONTIG = 1,
	DCA_SG_WALIGN,
	DCA_SG_PALIGN
} dca_sg_param_t;

#define	FALSE		0
#define	TRUE		1

/*
 * PCI configuration registers.
 */
#define	PCI_VENID		0x00	/* vendor id, 16 bits */
#define	PCI_DEVID		0x02	/* device id, 16 bits */
#define	PCI_COMM		0x04	/* command, 16 bits */
#define	PCI_STATUS		0x06	/* status, 16 bits */
#define	PCI_REVID		0x08	/* revision id, 8 bits */
#define	PCI_PROGCLASS		0x09	/* programming class, 8 bits */
#define	PCI_SUBCLASS		0x0A	/* subclass, 8 bits */
#define	PCI_CACHELINESZ		0x0C	/* cache line size, 8 bits */
#define	PCI_LATTMR		0x0D	/* latency timer, 8 bits */
#define	PCI_BIST		0x0F	/* builtin-self-test, 8 bits */
#define	PCI_SUBVENID		0x2C	/* subsystem vendor id, 16 bits */
#define	PCI_SUBSYSID		0x2E	/* subsystem id, 16 bits */
#define	PCI_MINGNT		0x3E	/* min grant for burst, 8 bits */
#define	PCI_MAXLAT		0x3F	/* maximum grant for burst, 8 bits */
#define	PCI_TRDYTO		0x40	/* TRDY timeout, 8 bits */
#define	PCI_RETRIES		0x41	/* retries bus will perform, 8 bits */

/*
 * PCI configuration register bit values.
 */
#define	PCICOMM_FBBE		0x0200	/* fast back-to-back enable */
#define	PCICOMM_SEE		0x0100	/* system error enable */
#define	PCICOMM_PEE		0x0040	/* parity error enable */
#define	PCICOMM_MWIE		0x0010	/* memory write & invalidate enable */
#define	PCICOMM_BME		0x0004	/* bus master enable */
#define	PCICOMM_MAE		0x0002	/* memory access enable */

#define	PCISTAT_PERR		0x8000	/* parity error detected */
#define	PCISTAT_SERR		0x4000	/* system error detected */
#define	PCISTAT_MABRT		0x2000	/* master abort detected */
#define	PCISTAT_TABRT		0x1000	/* target abort detected */
#define	PCISTAT_TABRTS		0x0800	/* target abort signaled */
#define	PCISTAT_PARITY		0x0100	/* data parity error detected */

#define	PCIREVID_DOMESTIC	0x01	/* domestic version */
#define	PCIREVID_EXPORT		0xE1	/* export version */

/* Note: 5820 errata: BIST feature does not work */
#define	PCIBIST_CAP		0x80	/* BIST capable */
#define	PCIBIST_START		0x40	/* start BIST test */
#define	PCIBIST_ERRMASK		0x0F	/* mask of BIST error codes */

/*
 * Command and Status Registers.
 */
#define	CSR_MCR1		0x00	/* pointer to MCR1 (bulk) */
#define	CSR_DMACTL		0x04	/* DMA control */
#define	CSR_DMASTAT		0x08	/* DMA status */
#define	CSR_DMAEA		0x0C	/* DMA error address */
#define	CSR_MCR2		0x10	/* pointer to MCR2 (exponentiator) */

/*
 * Command and status register bits.
 */
#define	DMACTL_RESET		0x80000000U	/* reset the chip */
#define	DMACTL_MCR2IE		0x40000000U	/* MCR2 interrupt enable */
#define	DMACTL_MCR1IE		0x20000000U	/* MCR1 interrupt enable */
#define	DMACTL_OFM		0x10000000U	/* output fragment mode */
#define	DMACTL_BE32		0x08000000U	/* 32-bit big endian mode */
#define	DMACTL_BE64		0x04000000U	/* 64-bit big endian mode */
#define	DMACTL_EIE		0x02000000U	/* error interrupt enable */
#define	DMACTL_RNGMASK		0x01800000U	/* RNG mode mask */
#define	DMACTL_RNG1		0x00000000U	/* 1 RNG bit per cycle */
#define	DMACTL_RNG4		0x00800000U	/* 1 RNG bit per 4 cycles */
#define	DMACTL_RNG8		0x01000000U	/* 1 RNG bit per 8 cycles */
#define	DMACTL_RNG16		0x01800000U	/* 1 RNG bit per 16 cycles */
#define	DMACTL_MODNORM		0x00400000U	/* s/w modulus normalization */
#define	DMACTL_RD256		0x00020000U	/* 256 byte read DMA size */
#define	DMACTL_FRAGMASK		0x0000FFFFU	/* output fragment size */

#define	DMASTAT_MAIP		0x80000000U	/* master access in progress */
#define	DMASTAT_MCR1FULL	0x40000000U	/* MCR1 is full */
#define	DMASTAT_MCR1INT		0x20000000U	/* MCR1 interrupted */
#define	DMASTAT_ERRINT		0x10000000U	/* error interrupted */
#define	DMASTAT_MCR2FULL	0x08000000U	/* MCR2 is full */
#define	DMASTAT_MCR2INT		0x04000000U	/* MCR2 interrupted */
#define	DMASTAT_INTERRUPTS	0x34000000U	/* all interrupts */

/*
 * Offsets of things relative to an MCR.
 */
#define	MCR_COUNT	0	/* 16 bits */
#define	MCR_FLAGS	2	/* 16 bits */
#define	MCR_CTXADDR	4	/* 32 bits */

/*
 * Basis for size (should be optimized by constant folding):
 *	4 bytes for flags and #packets.
 *	for each packet:
 *		2 descriptors (DESC_SIZE)
 *		4 bytes for context address
 *		4 bytes for packet length and reserved
 */
#define	MCR_SIZE	(4 + MAXREQSPERMCR * ((2 * DESC_SIZE) + 8))

/*
 * MCR flags.
 */
#define	MCRFLAG_FINISHED	0x0001		/* MCR processing complete */
#define	MCRFLAG_ERROR		0x0002		/* set if an error occured */
#define	MCRFLAG_ERRORMASK	0xff00		/* error code bits */

/*
 * Fields within a descriptor (data buffer chain).
 */
#define	DESC_BUFADDR	0	/* 32 bits */
#define	DESC_NEXT	4	/* 32 bits */
#define	DESC_LENGTH	8	/* 16 bits */
#define	DESC_RSVD	10	/* 16 bits */
#define	DESC_SIZE	16	/* ROUNDUP(12, 16) - descriptor size (bytes) */

/*
 * Offsets of fields within context structures, see Broadcom spec.
 */
#define	CTX_LENGTH		0	/* 16 bits */
#define	CTX_CMD			2	/* 16 bits */
#define	CTX_MAXLENGTH		768	/* max size of ctx, fits anything */

#define	CTX_3DESDIRECTION	4	/* 16 bits */
#define	CTX_3DESKEY1HI		8	/* 32 bits */
#define	CTX_3DESKEY1LO		12	/* 32 bits */
#define	CTX_3DESKEY2HI		16	/* 32 bits */
#define	CTX_3DESKEY2LO		20	/* 32 bits */
#define	CTX_3DESKEY3HI		24	/* 32 bits */
#define	CTX_3DESKEY3LO		28	/* 32 bits */
#define	CTX_3DESIVHI		32	/* 32 bits */
#define	CTX_3DESIVLO		36	/* 32 bits */

#define	CTX_IPSECFLAGS		4	/* 16 bits */
#define	CTX_IPSECOFFSET		6	/* 16 bits */
#define	CTX_IPSECKEY1HI		8	/* 32 bits */
#define	CTX_IPSECKEY1LO		12	/* 32 bits */
#define	CTX_IPSECKEY2HI		16	/* 32 bits */
#define	CTX_IPSECKEY2LO		20	/* 32 bits */
#define	CTX_IPSECKEY3HI		24	/* 32 bits */
#define	CTX_IPSECKEY3LO		28	/* 32 bits */
#define	CTX_IPSECIVHI		32	/* 32 bits */
#define	CTX_IPSECIVLO		36	/* 32 bits */
#define	CTX_IPSECHMACINNER1	40	/* 32 bits */
#define	CTX_IPSECHMACINNER2	44	/* 32 bits */
#define	CTX_IPSECHMACINNER3	48	/* 32 bits */
#define	CTX_IPSECHMACINNER4	52	/* 32 bits */
#define	CTX_IPSECHMACINNER5	56	/* 32 bits */
#define	CTX_IPSECHMACOUTER1	60	/* 32 bits */
#define	CTX_IPSECHMACOUTER2	64	/* 32 bits */
#define	CTX_IPSECHMACOUTER3	68	/* 32 bits */
#define	CTX_IPSECHMACOUTER4	72	/* 32 bits */
#define	CTX_IPSECHMACOUTER5	76	/* 32 bits */

#define	CTX_RSAEXPLEN		4	/* 16 bits */
#define	CTX_RSAMODLEN		6	/* 16 bits */
#define	CTX_RSABIGNUMS		8	/* variable length */
#define	CTX_RSAQLEN		4	/* 16 bits */
#define	CTX_RSAPLEN		6	/* 16 bits */

#define	CTX_DSAMSGTYPE		4	/* 16 bits */
#define	CTX_DSARSVD		6	/* 16 bits */
#define	CTX_DSARNG		8	/* 16 bits */
#define	CTX_DSAPLEN		10	/* 16 bits */
#define	CTX_DSABIGNUMS		12	/* variable length */

/*
 * Values for specific operations.
 */
#define	CTX_RNG_LENGTH		64	/* context length for RNG (64 min) */
#define	CTX_3DES_LENGTH		64	/* context length for 3DES (64 min) */
#define	CTX_3DES_DECRYPT	0x4000	/* perform decryption */
#define	CTX_3DES_ENCRYPT	0x0000	/* perform encryption */
#define	CTX_IPSEC_LENGTH	80	/* context length for IPsec */
#define	CTX_IPSEC_ENCRYPT	0x8000	/* perform encryption */
#define	CTX_IPSEC_DECRYPT	0xc000	/* perform decryption */
#define	CTX_IPSEC_HMAC_MD5	0x1000	/* HMAC-MD5 authentication */
#define	CTX_IPSEC_HMAC_SHA1	0x2000	/* HMAC-MD5 authentication */
#define	CTX_DSAMSGTYPE_SHA1	0	/* Message is SHA1 */
#define	CTX_DSAMSGTYPE_TEXT	1	/* Generate SHA1 hash first */
#define	CTX_DSARNG_GEN		1	/* Generate random k */
#define	CTX_DSARNG_SUPPLY	0	/* Random k is supplied */

/*
 * Macros to access fields within the MCR.  Note that this includes the
 * context fields as well, since the context is just offset from the
 * base of the MCR.
 */

#define	PUTMCR32(work, reg, val)	\
	ddi_put32(work->dw_mcr_acch,	\
	(uint32_t *)(work->dw_mcr_kaddr + reg), val)

#define	PUTMCR16(work, reg, val)	\
	ddi_put16(work->dw_mcr_acch,	\
	(uint16_t *)(work->dw_mcr_kaddr + reg), val)

#define	GETMCR32(work, reg)	\
	ddi_get32(work->dw_mcr_acch, (uint32_t *)(work->dw_mcr_kaddr + reg))

#define	GETMCR16(work, reg)	\
	ddi_get16(work->dw_mcr_acch, (uint16_t *)(work->dw_mcr_kaddr + reg))

#define	PUTDESC32(req, dc_desc_kaddr, reg, val)	\
	ddi_put32(req->dr_ctx_acch,	\
	(uint32_t *)(dc_desc_kaddr + reg), val)

#define	PUTDESC16(req, dc_desc_kaddr, reg, val)	\
	ddi_put16(req->dr_ctx_acch,	\
	(uint16_t *)(dc_desc_kaddr + reg), val)

/* XXX: define the GET forms for descriptors only if needed */

#define	PUTCTX32(req, reg, val)	\
	ddi_put32(req->dr_ctx_acch,	\
	(uint32_t *)(req->dr_ctx_kaddr + reg), val)

#define	PUTCTX16(req, reg, val)	\
	ddi_put16(req->dr_ctx_acch,	\
	(uint16_t *)(req->dr_ctx_kaddr + reg), val)

#define	CTXBCOPY(req, src, dst, count)	\
	ddi_rep_put8(req->dr_ctx_acch, (uchar_t *)src, (uchar_t *)dst, count, \
	DDI_DEV_AUTOINCR)

/*
 * Register access.
 */
#define	GETCSR(dca, reg)	\
	ddi_get32(dca->dca_regs_handle, (uint_t *)(dca->dca_regs + reg))

#define	PUTCSR(dca, reg, val)	\
	ddi_put32(dca->dca_regs_handle, (uint_t *)(dca->dca_regs + reg), val)

#define	SETBIT(dca, reg, val)	\
	PUTCSR(dca, reg, GETCSR(dca, reg) | val)

#define	CLRBIT(dca, reg, val)	\
	PUTCSR(dca, reg, GETCSR(dca, reg) & ~val)

/*
 * Used to guarantee alignment.
 */
#define	ROUNDUP(a, n)	(((a) + ((n) - 1)) & ~((n) - 1))
#define	ROUNDDOWN(a, n)	(((a) & ~((n) - 1)))
#define	HIDBLWORD(x)	(((x) & 0xffffffff00000000ULL) >> 32)
#define	LODBLWORD(x)	((x) & 0xffffffffULL)

/*
 * Driver hardening related.
 */
#define	CHECK_REGS(dca)	ddi_check_acc_handle(dca->dca_regs_handle)

/*
 * Other utility macros.
 */
#define	QEMPTY(q)	((q)->dl_next == (q))
#define	BITS2BYTES(b)	((b) >> 3)
#define	WORKLIST(dca, mcr)	(&((dca)->dca_worklist[mcr - 1]))

/*
 * Debug stuff.
 */
#ifdef	DEBUG
#define	DWARN		0x0001
#define	DPCI		0x0002
#define	DINTR		0x0004
#define	DSTART		0x0008
#define	DRECLAIM	0x0010
#define	DCHATTY		0x0020
#define	DMOD		0x0040	/* _init/_fini/_info/attach/detach */
#define	DENTRY		0x0080	/* crypto routine entry/exit points */

void	dca_dprintf(dca_t *, int, const char *, ...);
#define	DBG	dca_dprintf
#else
#define	DBG(dca, lvl, ...)
#endif

/*
 * Some pkcs#11 defines as there are no pkcs#11 header files included.
 */
#define	CKO_PUBLIC_KEY		0x00000002UL
#define	CKO_PRIVATE_KEY		0x00000003UL

#define	CKA_CLASS		0x00000000UL
#define	CKA_VALUE		0x00000011UL
#define	CKA_KEY_TYPE		0x00000100UL
#define	CKA_MODULUS		0x00000120UL
#define	CKA_PUBLIC_EXPONENT	0x00000122UL
#define	CKA_PRIVATE_EXPONENT	0x00000123UL
#define	CKA_PRIME_1		0x00000124UL
#define	CKA_PRIME_2		0x00000125UL
#define	CKA_EXPONENT_1		0x00000126UL
#define	CKA_EXPONENT_2		0x00000127UL
#define	CKA_COEFFICIENT		0x00000128UL
#define	CKA_PRIME		0x00000130UL
#define	CKA_SUBPRIME		0x00000131UL
#define	CKA_BASE		0x00000132UL
/*
 * Driver globals.
 */
extern int	dca_mindma;
extern int	dca_hardening;

/*
 * Prototypes.
 */

/*
 * dca_debug.c
 */
void	dca_error(dca_t *, const char *, ...);
void	dca_diperror(dev_info_t *, const char *, ...);
void	dca_dipverror(dev_info_t *, const char *, va_list);
/*
 * dca_3des.c
 */
int	dca_3desctxinit(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    int, int);
int	dca_3des(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t, int);
int	dca_3desupdate(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t, int);
int	dca_3desfinal(crypto_ctx_t *, crypto_data_t *, int);
int	dca_3desatomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    int, crypto_req_handle_t, int);
void	dca_3desctxfree(void *);

/*
 * dca_rsa.c
 */
int	dca_rsastart(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t, int);
int	dca_rsainit(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *, int);
void	dca_rsactxfree(void *);
int	dca_rsaatomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    int, crypto_req_handle_t, int);

/*
 * dca_dsa.c
 */
int	dca_dsa_sign(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
int	dca_dsa_verify(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
int	dca_dsainit(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *, int,
    int);
void	dca_dsactxfree(void *);
int	dca_dsaatomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    int, crypto_req_handle_t, int);

/*
 * dca_rng.c
 */
int	dca_rng(dca_t *, uchar_t *, size_t len, crypto_req_handle_t);
int	dca_random_buffer(dca_t *dca, caddr_t buf, int len);
int	dca_random_init();
void	dca_random_fini();

/*
 * dca_kstat.c
 */
void	dca_ksinit(dca_t *);
/*
 * dca.c
 */
void	dca_rmqueue(dca_listnode_t *);
dca_request_t *dca_getreq(dca_t *, int, int);
void	dca_freereq(dca_request_t *);
int	dca_bindchains(dca_request_t *, size_t, size_t);
int	dca_unbindchains(dca_request_t *);
int	dca_start(dca_t *, dca_request_t *, int, int);
void	dca_done(dca_request_t *, int);
void	dca_destroyreq(dca_request_t *);
int	dca_length(crypto_data_t *);
int	dca_gather(crypto_data_t *, char *, int, int);
int	dca_resid_gather(crypto_data_t *, char *, int *, char *, int);
int	dca_scatter(const char *, crypto_data_t *, int, int);
int	dca_bcmp_reverse(const void *s1, const void *s2, size_t n);
int	dca_dupcrypto(crypto_data_t *, crypto_data_t *);
int	dca_verifyio(crypto_data_t *, crypto_data_t *);
int	dca_getbufbytes(crypto_data_t *, size_t, int, uchar_t *);
int	dca_sgcheck(dca_t *, crypto_data_t *, dca_sg_param_t);
crypto_object_attribute_t *
	dca_get_key_attr(crypto_key_t *);
int	dca_attr_lookup_uint32(crypto_object_attribute_t *, uint_t, uint64_t,
	    uint32_t *);
int	dca_attr_lookup_uint8_array(crypto_object_attribute_t *, uint_t,
	    uint64_t, void **, unsigned int *);
crypto_object_attribute_t *
	dca_find_attribute(crypto_object_attribute_t *, uint_t, uint64_t);
caddr_t	dca_bufdaddr(crypto_data_t *);
void	dca_rcoalesce(dca_request_t *, int);
void	dca_runcoalesce(dca_request_t *);
int	dca_bitlen(unsigned char *, int);
uint16_t dca_padhalf(int);
uint16_t dca_padfull(int);
void	dca_reverse(void *, void *, int, int);
int	dca_numcmp(caddr_t, int, caddr_t, int);
int dca_check_dma_handle(dca_t *dca, ddi_dma_handle_t handle,
	dca_fma_eclass_t eclass_index);
int dca_free_context(crypto_ctx_t *ctx);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CRYPTO_DCA_H */
