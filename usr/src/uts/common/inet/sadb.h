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

#ifndef	_INET_SADB_H
#define	_INET_SADB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <inet/ipsec_info.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>

#define	IPSA_MAX_ADDRLEN 4	/* Max address len. (in 32-bits) for an SA. */

/*
 * Return codes of IPsec processing functions.
 */
typedef enum {
	IPSEC_STATUS_SUCCESS = 1,
	IPSEC_STATUS_FAILED = 2,
	IPSEC_STATUS_PENDING = 3
} ipsec_status_t;

/*
 * IP security association.  Synchronization assumes 32-bit loads, so
 * the 64-bit quantities can't even be be read w/o locking it down!
 */

/* keying info */
typedef struct ipsa_key_s {
	void *sak_key;		/* Algorithm key. */
	uint_t sak_keylen;	/* Algorithm key length (in bytes). */
	uint_t sak_keybits;	/* Algorithm key length (in bits) */
	uint_t sak_algid;	/* Algorithm ID number. */
} ipsa_key_t;

/* the security association */
typedef struct ipsa_s {
	struct ipsa_s *ipsa_next;	/* Next in hash bucket */
	struct ipsa_s **ipsa_ptpn;	/* Pointer to previous next pointer. */
	kmutex_t *ipsa_linklock;	/* Pointer to hash-chain lock. */
	void (*ipsa_freefunc)(struct ipsa_s *); /* freeassoc function */
	/*
	 * NOTE: I may need more pointers, depending on future SA
	 * requirements.
	 */
	ipsa_key_t ipsa_authkeydata;
#define	ipsa_authkey ipsa_authkeydata.sak_key
#define	ipsa_authkeylen ipsa_authkeydata.sak_keylen
#define	ipsa_authkeybits ipsa_authkeydata.sak_keybits
#define	ipsa_auth_alg ipsa_authkeydata.sak_algid
	ipsa_key_t ipsa_encrkeydata;
#define	ipsa_encrkey ipsa_encrkeydata.sak_key
#define	ipsa_encrkeylen ipsa_encrkeydata.sak_keylen
#define	ipsa_encrkeybits ipsa_encrkeydata.sak_keybits
#define	ipsa_encr_alg ipsa_encrkeydata.sak_algid

	struct ipsid_s *ipsa_src_cid;	/* Source certificate identity */
	struct ipsid_s *ipsa_dst_cid;	/* Destination certificate identity */
	struct ipsid_s *ipsa_proxy_cid;	/* (src) Proxy agent's cert. id. */
	uint64_t *ipsa_integ;	/* Integrity bitmap */
	uint64_t *ipsa_sens;	/* Sensitivity bitmap */
	mblk_t	*ipsa_lpkt;	/* Packet received while larval (CAS me) */

	/*
	 * PF_KEYv2 supports a replay window size of 255.  Hence there is a
	 * need a bit vector to support a replay window of 255.  256 is a nice
	 * round number, so I support that.
	 *
	 * Use an array of uint64_t for best performance on 64-bit
	 * processors.  (And hope that 32-bit compilers can handle things
	 * okay.)  The " >> 6 " is to get the appropriate number of 64-bit
	 * ints.
	 */
#define	SADB_MAX_REPLAY 256	/* Must be 0 mod 64. */
	uint64_t ipsa_replay_arr[SADB_MAX_REPLAY >> 6];

	uint64_t ipsa_unique_id;	/* Non-zero for unique SAs */
	uint64_t ipsa_unique_mask;	/* mask value for unique_id */

	/*
	 * Reference count semantics:
	 *
	 *	An SA has a reference count of 1 if something's pointing
	 *	to it.  This includes being in a hash table.  So if an
	 *	SA is in a hash table, it has a reference count of at least 1.
	 *
	 *	When a ptr. to an IPSA is assigned, you MUST REFHOLD after
	 *	said assignment.  When a ptr. to an IPSA is released
	 *	you MUST REFRELE.  When the refcount hits 0, REFRELE
	 *	will free the IPSA.
	 */
	kmutex_t ipsa_lock;	/* Locks non-linkage/refcnt fields. */
	/* Q:  Since I may be doing refcnts differently, will I need cv? */
	uint_t ipsa_refcnt;	/* Reference count. */

	/*
	 * The following four time fields are the ones monitored by ah_ager()
	 * and esp_ager() respectively.  They are all absolute wall-clock
	 * times.  The times of creation (i.e. add time) and first use are
	 * pretty straightforward.  The soft and hard expire times are
	 * derived from the times of first use and creation, plus the minimum
	 * expiration times in the fields that follow this.
	 *
	 * For example, if I had a hard add time of 30 seconds, and a hard
	 * use time of 15, the ipsa_hardexpiretime would be time of add, plus
	 * 30 seconds.  If I USE the SA such that time of first use plus 15
	 * seconds would be earlier than the add time plus 30 seconds, then
	 * ipsa_hardexpiretime would become this earlier time.
	 */
	time_t ipsa_addtime;	/* Time I was added. */
	time_t ipsa_usetime;	/* Time of my first use. */
	time_t ipsa_softexpiretime;	/* Time of my first soft expire. */
	time_t ipsa_hardexpiretime;	/* Time of my first hard expire. */

	/*
	 * The following fields are directly reflected in PF_KEYv2 LIFETIME
	 * extensions.  The time_ts are in number-of-seconds, and the bytes
	 * are in... bytes.
	 */
	time_t ipsa_softaddlt;	/* Seconds of soft lifetime after add. */
	time_t ipsa_softuselt;	/* Seconds of soft lifetime after first use. */
	time_t ipsa_hardaddlt;	/* Seconds of hard lifetime after add. */
	time_t ipsa_harduselt;	/* Seconds of hard lifetime after first use. */
	uint64_t ipsa_softbyteslt;	/* Bytes of soft lifetime. */
	uint64_t ipsa_hardbyteslt;	/* Bytes of hard lifetime. */
	uint64_t ipsa_bytes;	/* Bytes encrypted/authed by this SA. */

	/*
	 * "Allocations" are a concept mentioned in PF_KEYv2.  We do not
	 * support them, except to record them per the PF_KEYv2 spec.
	 */
	uint_t ipsa_softalloc;	/* Allocations allowed (soft). */
	uint_t ipsa_hardalloc;	/* Allocations allowed (hard). */
	uint_t ipsa_alloc;	/* Allocations made. */

	uint_t ipsa_integlen;	/* Length of the integrity bitmap (bytes). */
	uint_t ipsa_senslen;	/* Length of the sensitivity bitmap (bytes). */

	uint_t ipsa_type;	/* Type of security association. (AH/etc.) */
	uint_t ipsa_dpd;	/* Domain for sensitivity bit vectors. */
	uint_t ipsa_senslevel;	/* Sensitivity level. */
	uint_t ipsa_integlevel;	/* Integrity level. */
	uint_t ipsa_state;	/* State of my association. */
	uint_t ipsa_replay_wsize; /* Size of replay window */
	uint32_t ipsa_flags;	/* Flags for security association. */
	uint32_t ipsa_spi;	/* Security parameters index. */
	uint32_t ipsa_replay;	/* Highest seen replay value for this SA. */
	uint32_t ipsa_kmp;	/* key management proto */
	uint32_t ipsa_kmc;	/* key management cookie */

	boolean_t ipsa_haspeer;	/* Has peer in another table. */

	/*
	 * Address storage.
	 * The source address can be INADDR_ANY, IN6ADDR_ANY, etc.
	 *
	 * Address families (per sys/socket.h) guide us.  We could have just
	 * used sockaddr_storage
	 */
	sa_family_t ipsa_addrfam;
	sa_family_t ipsa_proxyfam;	/* Proxy AF can be != src/dst AF. */

	uint32_t ipsa_srcaddr[IPSA_MAX_ADDRLEN];
	uint32_t ipsa_dstaddr[IPSA_MAX_ADDRLEN];
	uint32_t ipsa_proxysrc[IPSA_MAX_ADDRLEN];
	uint32_t ipsa_proxydst[IPSA_MAX_ADDRLEN];

	/* these can only be v4 */
	uint32_t ipsa_natt_addr_loc[IPSA_MAX_ADDRLEN];
	uint32_t ipsa_natt_addr_rem[IPSA_MAX_ADDRLEN];

	uint16_t ipsa_inbound_cksum; /* cksum correction for inbound packets */
	uint16_t ipsa_remote_port; /* the other port that isn't 4500 */

	timeout_id_t ipsa_natt_ka_timer;
	queue_t *ipsa_natt_q;
	/*
	 * icmp type and code. *_end are to specify ranges. if only
	 * a single value, * and *_end are the same value.
	 */
	uint8_t ipsa_icmp_type;
	uint8_t ipsa_icmp_type_end;
	uint8_t ipsa_icmp_code;
	uint8_t ipsa_icmp_code_end;

	/*
	 * For the kernel crypto framework.
	 */
	crypto_key_t ipsa_kcfauthkey;		/* authentication key */
	crypto_key_t ipsa_kcfencrkey;		/* encryption key */
	crypto_ctx_template_t ipsa_authtmpl;	/* auth context template */
	crypto_ctx_template_t ipsa_encrtmpl;	/* encr context template */
	crypto_mechanism_t ipsa_amech;		/* auth mech type and ICV len */
	crypto_mechanism_t ipsa_emech;		/* encr mech type */
	size_t ipsa_mac_len;			/* auth MAC length */
	size_t ipsa_iv_len;			/* encr IV length */

	/*
	 * Input and output processing functions called from IP.
	 */
	ipsec_status_t (*ipsa_output_func)(mblk_t *);
	ipsec_status_t (*ipsa_input_func)(mblk_t *, void *);

	/* MLS boxen will probably need more fields in here. */

} ipsa_t;

/*
 * ipsa_t address handling macros.  We want these to be inlined, and deal
 * with 32-bit words to avoid bcmp/bcopy calls.
 *
 * Assume we only have AF_INET and AF_INET6 addresses for now.  Also assume
 * that we have 32-bit alignment on everything.
 */
#define	IPSA_IS_ADDR_UNSPEC(addr, fam) ((((uint32_t *)(addr))[0] == 0) && \
	(((fam) == AF_INET) || (((uint32_t *)(addr))[3] == 0 && \
	((uint32_t *)(addr))[2] == 0 && ((uint32_t *)(addr))[1] == 0)))
#define	IPSA_ARE_ADDR_EQUAL(addr1, addr2, fam) \
	((((uint32_t *)(addr1))[0] == ((uint32_t *)(addr2))[0]) && \
	(((fam) == AF_INET) || \
	(((uint32_t *)(addr1))[3] == ((uint32_t *)(addr2))[3] && \
	((uint32_t *)(addr1))[2] == ((uint32_t *)(addr2))[2] && \
	((uint32_t *)(addr1))[1] == ((uint32_t *)(addr2))[1])))
#define	IPSA_COPY_ADDR(dstaddr, srcaddr, fam) { \
	((uint32_t *)(dstaddr))[0] = ((uint32_t *)(srcaddr))[0]; \
	if ((fam) == AF_INET6) {\
		((uint32_t *)(dstaddr))[1] = ((uint32_t *)(srcaddr))[1]; \
		((uint32_t *)(dstaddr))[2] = ((uint32_t *)(srcaddr))[2]; \
		((uint32_t *)(dstaddr))[3] = ((uint32_t *)(srcaddr))[3]; } }

/*
 * ipsa_t reference hold/release macros.
 *
 * If you have a pointer, you REFHOLD.  If you are releasing a pointer, you
 * REFRELE.  An ipsa_t that is newly inserted into the table should have
 * a reference count of 1 (for the table's pointer), plus 1 more for every
 * pointer that is referencing the ipsa_t.
 */

#define	IPSA_REFHOLD(ipsa) {			\
	atomic_add_32(&(ipsa)->ipsa_refcnt, 1);	\
	ASSERT((ipsa)->ipsa_refcnt != 0);	\
}

/*
 * Decrement the reference count on the SA.
 * In architectures e.g sun4u, where atomic_add_32_nv is just
 * a cas, we need to maintain the right memory barrier semantics
 * as that of mutex_exit i.e all the loads and stores should complete
 * before the cas is executed. membar_exit() does that here.
 */

#define	IPSA_REFRELE(ipsa) {					\
	ASSERT((ipsa)->ipsa_refcnt != 0);			\
	membar_exit();						\
	if (atomic_add_32_nv(&(ipsa)->ipsa_refcnt, -1) == 0)	\
		((ipsa)->ipsa_freefunc)(ipsa);			\
}

/*
 * Security association hash macros and definitions.  For now, assume the
 * IPsec model, and hash outbounds on destination address, and inbounds on
 * SPI.
 *
 * Also assume a 256 bucket hash.
 */
#define	OUTBOUND_BUCKETS 256
/* Outbound hash treats v4addr like a 32-bit quantity */
#define	OUTBOUND_HASH_V4(v4addr) (((uint32_t)(v4addr) ^ \
	(((uint32_t)v4addr) >> 8) ^ (((uint32_t)v4addr) >> 16) ^ \
	(((uint32_t)v4addr) >> 24)) & 0xff)
/* Its v6 counterpart treats v6addr like something I can take the address of. */
#define	OUTBOUND_HASH_V6(v6addr) OUTBOUND_HASH_V4((*(uint32_t *)&(v6addr)) ^ \
	(*((uint32_t *)&(v6addr)) + 1) ^ (*((uint32_t *)&(v6addr)) + 2) ^ \
	(*((uint32_t *)&(v6addr)) + 3))

/* No v4/v6 distinction needed for inbound. */
#define	INBOUND_BUCKETS 256
#define	INBOUND_HASH(spi) OUTBOUND_HASH_V4(spi)

#define	IPSA_F_PFS	SADB_SAFLAGS_PFS	/* PFS in use for this SA? */
#define	IPSA_F_NOREPFLD	SADB_SAFLAGS_NOREPLAY	/* No replay field, for */
						/* backward compat. */
#define	IPSA_F_USED	SADB_X_SAFLAGS_USED	/* SA has been used. */
#define	IPSA_F_UNIQUE	SADB_X_SAFLAGS_UNIQUE	/* SA is unique */
#define	IPSA_F_AALG1	SADB_X_SAFLAGS_AALG1	/* Auth alg flag 1 */
#define	IPSA_F_AALG2	SADB_X_SAFLAGS_AALG2	/* Auth alg flag 2 */
#define	IPSA_F_EALG1	SADB_X_SAFLAGS_EALG1	/* Encrypt alg flag 1 */
#define	IPSA_F_EALG2	SADB_X_SAFLAGS_EALG2	/* Encrypt alg flag 2 */

#define	IPSA_F_HW	0x200000		/* hwaccel capable SA */
#define	IPSA_F_NATT_LOC	SADB_X_SAFLAGS_NATT_LOC
#define	IPSA_F_NATT_REM	SADB_X_SAFLAGS_NATT_REM
#define	IPSA_F_NATT	(SADB_X_SAFLAGS_NATT_LOC | SADB_X_SAFLAGS_NATT_REM)
#define	IPSA_F_CINVALID	0x40000		/* SA shouldn't be cached */

/* SA states are important for handling UPDATE PF_KEY messages. */
#define	IPSA_STATE_LARVAL	SADB_SASTATE_LARVAL
#define	IPSA_STATE_MATURE	SADB_SASTATE_MATURE
#define	IPSA_STATE_DYING	SADB_SASTATE_DYING
#define	IPSA_STATE_DEAD		SADB_SASTATE_DEAD

/*
 * NOTE:  If the document authors do things right in defining algorithms, we'll
 *	  probably have flags for what all is here w.r.t. replay, ESP w/HMAC,
 *	  etc.
 */

#define	IPSA_T_ACQUIRE	SEC_TYPE_NONE	/* If this typed returned, sa needed */
#define	IPSA_T_AH	SEC_TYPE_AH	/* IPsec AH association */
#define	IPSA_T_ESP	SEC_TYPE_ESP	/* IPsec ESP association */

#define	IPSA_AALG_NONE	SADB_AALG_NONE		/* No auth. algorithm */
#define	IPSA_AALG_MD5H	SADB_AALG_MD5HMAC	/* MD5-HMAC algorithm */
#define	IPSA_AALG_SHA1H	SADB_AALG_SHA1HMAC	/* SHA1-HMAC algorithm */

#define	IPSA_EALG_NONE		SADB_EALG_NONE	/* No encryption algorithm */
#define	IPSA_EALG_DES_CBC	SADB_EALG_DESCBC
#define	IPSA_EALG_3DES		SADB_EALG_3DESCBC

/*
 * Protect each ipsa_t bucket (and linkage) with a lock.
 */

typedef struct isaf_s {
	ipsa_t *isaf_ipsa;
	kmutex_t isaf_lock;
	uint64_t isaf_gen;
} isaf_t;

/*
 * ACQUIRE record.  If AH/ESP/whatever cannot find an association for outbound
 * traffic, it sends up an SADB_ACQUIRE message and create an ACQUIRE record.
 */

#define	IPSACQ_MAXPACKETS 4	/* Number of packets that can be queued up */
				/* waiting for an ACQUIRE to finish. */

typedef struct ipsacq_s {
	struct ipsacq_s *ipsacq_next;
	struct ipsacq_s **ipsacq_ptpn;
	kmutex_t *ipsacq_linklock;
	struct ipsec_policy_s  *ipsacq_policy;
	struct ipsec_action_s  *ipsacq_act;

	sa_family_t ipsacq_addrfam;	/* Address family. */
	int ipsacq_numpackets;		/* How many packets queued up so far. */
	uint32_t ipsacq_seq;		/* PF_KEY sequence number. */
	uint64_t ipsacq_unique_id;	/* Unique ID for SAs that need it. */

	kmutex_t ipsacq_lock;	/* Protects non-linkage fields. */
	time_t ipsacq_expire;	/* Wall-clock time when this record expires. */
	mblk_t *ipsacq_mp;	/* List of datagrams waiting for an SA. */

	/* These two point inside the last mblk inserted. */
	uint32_t *ipsacq_srcaddr;
	uint32_t *ipsacq_dstaddr;

	/* uint32_t ipsacq_proxysrc[IPSA_MAX_ADDRLEN]; */	/* For later */
	/* uint32_t ipsacq_proxydst[IPSA_MAX_ADDRLEN]; */	/* For later */

	/* These may change per-acquire. */
	uint16_t ipsacq_srcport;
	uint16_t ipsacq_dstport;
	uint8_t ipsacq_proto;
	/* icmp type and code of triggering packet (if applicable) */
	uint8_t	ipsacq_icmp_type;
	uint8_t ipsacq_icmp_code;
} ipsacq_t;

/*
 * Kernel-generated sequence numbers will be no less than 0x80000000 to
 * forestall any cretinous problems with manual keying accidentally updating
 * an ACQUIRE entry.
 */
#define	IACQF_LOWEST_SEQ 0x80000000

#define	SADB_AGE_INTERVAL_DEFAULT 1000

/*
 * ACQUIRE fanout.  Protect each linkage with a lock.
 */

typedef struct iacqf_s {
	ipsacq_t *iacqf_ipsacq;
	kmutex_t iacqf_lock;
} iacqf_t;

/*
 * A (network protocol, ipsec protocol) specific SADB.
 * (i.e., one each for {ah, esp} and {v4, v6}.
 *
 * Keep outbound assocs about the same as ire_cache entries for now.
 * One danger point, multiple SAs for a single dest will clog a bucket.
 * For the future, consider two-level hashing (2nd hash on IPC?), then probe.
 */

typedef struct sadb_s
{
	isaf_t	*sdb_of;
	isaf_t	*sdb_if;
	iacqf_t	*sdb_acq;
} sadb_t;

/*
 * A pair of SADB's (one for v4, one for v6), and related state (including
 * acquire callbacks).
 */

typedef struct sadbp_s
{
	uint32_t	s_satype;
	queue_t		*s_ip_q;
	uint32_t	*s_acquire_timeout;
	void 		(*s_acqfn)(ipsacq_t *, mblk_t *);
	sadb_t		s_v4;
	sadb_t		s_v6;
} sadbp_t;

/*
 * Global IPsec security association databases (and all that go with them).
 */
extern sadbp_t ah_sadb, esp_sadb;

/* Pointer to an all-zeroes IPv6 address. */
#define	ALL_ZEROES_PTR	((uint32_t *)&ipv6_all_zeros)

/*
 * Form unique id from ipsec_out_t
 */

#define	SA_FORM_UNIQUE_ID(io)				\
	SA_UNIQUE_ID((io)->ipsec_out_src_port, (io)->ipsec_out_dst_port, \
		(io)->ipsec_out_proto)

/*
 * This macro is used to generate unique ids (along with the addresses) for
 * outbound datagrams that require unique SAs.
 *
 * N.B. casts and unsigned shift amounts discourage unwarranted
 * sign extension of dstport and proto.
 */
#define	SA_UNIQUE_ID(srcport, dstport, proto) 		\
	((srcport) | ((uint64_t)(dstport) << 16U) | ((uint64_t)(proto) << 32U))

/*
 * SA_UNIQUE_MASK generates a mask value to use when comparing the unique value
 * from a packet to an SA.
 */

#define	SA_UNIQUE_MASK(srcport, dstport, proto) 		\
	SA_UNIQUE_ID((srcport != 0)? 0xffff : 0,		\
		    (dstport != 0)? 0xffff : 0,			\
		    (proto != 0)? 0xff : 0)

/*
 * Decompose unique id back into its original fields.
 */
#define	SA_PROTO(ipsa) ((ipsa)->ipsa_unique_id>>32)&0xff
#define	SA_SRCPORT(ipsa) ((ipsa)->ipsa_unique_id & 0xffff)
#define	SA_DSTPORT(ipsa) (((ipsa)->ipsa_unique_id >> 16) & 0xffff)

/*
 * All functions that return an ipsa_t will return it with IPSA_REFHOLD()
 * already called.
 */

/* SA retrieval (inbound and outbound) */
ipsa_t *ipsec_getassocbyspi(isaf_t *, uint32_t, uint32_t *, uint32_t *,
    sa_family_t);
ipsa_t *ipsec_getassocbyconn(isaf_t *, ipsec_out_t *, uint32_t *, uint32_t *,
    sa_family_t, uint8_t);

/* SA insertion. */
int sadb_insertassoc(ipsa_t *, isaf_t *);

/* SA table construction and destruction. */
void sadbp_init(sadbp_t *, int);
void sadbp_flush(sadbp_t *);
void sadbp_destroy(sadbp_t *);

/* SA insertion and deletion. */
int sadb_insertassoc(ipsa_t *, isaf_t *);
void sadb_unlinkassoc(ipsa_t *);

/* Support routines to interface a keysock consumer to PF_KEY. */
mblk_t *sadb_keysock_out(minor_t);
int sadb_hardsoftchk(sadb_lifetime_t *, sadb_lifetime_t *);
void sadb_pfkey_echo(queue_t *, mblk_t *, sadb_msg_t *, struct keysock_in_s *,
    ipsa_t *);
void sadb_pfkey_error(queue_t *, mblk_t *, int, int, uint_t);
void sadb_keysock_hello(queue_t **, queue_t *, mblk_t *, void (*)(void *),
    timeout_id_t *, int);
int sadb_addrcheck(queue_t *, queue_t *, mblk_t *, sadb_ext_t *, uint_t);
void sadb_srcaddrfix(keysock_in_t *);
int sadb_addrset(ire_t *);
int sadb_delget_sa(mblk_t *, keysock_in_t *, sadbp_t *, int *, queue_t *,
    boolean_t);
#define	sadb_get_sa(m, k, s, i, q)	sadb_delget_sa(m, k, s, i, q, B_FALSE)
#define	sadb_del_sa(m, k, s, i, q)	sadb_delget_sa(m, k, s, i, q, B_TRUE)

int sadb_purge_sa(mblk_t *, keysock_in_t *, sadb_t *, int *,
    queue_t *, queue_t *);
int sadb_common_add(queue_t *, queue_t *, mblk_t *, sadb_msg_t *,
    keysock_in_t *, isaf_t *, isaf_t *, ipsa_t *, boolean_t, boolean_t);
void sadb_set_usetime(ipsa_t *);
boolean_t sadb_age_bytes(queue_t *, ipsa_t *, uint64_t, boolean_t);
int sadb_update_sa(mblk_t *, keysock_in_t *, sadb_t *,
    int *, queue_t *, int (*)(mblk_t *, keysock_in_t *, int *));
void sadb_acquire(mblk_t *, ipsec_out_t *, boolean_t, boolean_t);

void sadb_destroy_acquire(ipsacq_t *);
void sadb_destroy_acqlist(iacqf_t *, uint_t, boolean_t);
uint8_t *sadb_setup_acquire(uint8_t *, uint8_t *, ipsacq_t *);
ipsa_t *sadb_getspi(keysock_in_t *, uint32_t, int *);
void sadb_in_acquire(sadb_msg_t *, sadbp_t *, queue_t *);
boolean_t sadb_replay_check(ipsa_t *, uint32_t);
boolean_t sadb_replay_peek(ipsa_t *, uint32_t);
mblk_t *sadb_sa2msg(ipsa_t *, sadb_msg_t *);
int sadb_dump(queue_t *, mblk_t *, minor_t, sadb_t *);
void sadb_replay_delete(ipsa_t *);
void sadb_ager(sadb_t *, queue_t *, queue_t *, int);

timeout_id_t sadb_retimeout(hrtime_t, queue_t *, void (*)(void *),
    uint_t *, uint_t, short);
void sadb_sa_refrele(void *target);
void sadb_set_lpkt(ipsa_t *, mblk_t *);
mblk_t *sadb_clear_lpkt(ipsa_t *);

/*
 * Hw accel-related calls (downloading sadb to driver)
 */
void sadb_ill_download(ill_t *, uint_t);
mblk_t *sadb_fmt_sa_req(uint_t, uint_t, ipsa_t *, boolean_t);
/*
 * Sub-set of the IPsec hardware acceleration capabilities functions
 * implemented by ip_if.c
 */
extern	boolean_t ipsec_capab_match(ill_t *, uint_t, boolean_t, ipsa_t *);
extern	void	ill_ipsec_capab_send_all(uint_t, mblk_t *, ipsa_t *);


/*
 * One IPsec -> IP linking routine, and two IPsec rate-limiting routines.
 */
extern boolean_t sadb_t_bind_req(queue_t *, int);
/*PRINTFLIKE5*/
extern void ipsec_rl_strlog(short, short, char, ushort_t, char *, ...)
    __KPRINTFLIKE(5);
extern void ipsec_assocfailure(short, short, char, ushort_t, char *, uint32_t,
    void *, int);

/*
 * Algorithm types.
 */

#define	IPSEC_NALGTYPES 	2

typedef enum ipsec_algtype {
	IPSEC_ALG_AUTH = 0,
	IPSEC_ALG_ENCR = 1
} ipsec_algtype_t;

/*
 * Definitions as per IPsec/ISAKMP DOI.
 */

#define	IPSEC_MAX_ALGS		256
#define	PROTO_IPSEC_AH		2
#define	PROTO_IPSEC_ESP		3

/*
 * Common algorithm info.
 */
typedef struct ipsec_alginfo
{
	uint8_t		alg_id;
	uint8_t		alg_flags;
	uint16_t	*alg_key_sizes;
	uint16_t	*alg_block_sizes;
	uint16_t	alg_nkey_sizes;
	uint16_t	alg_nblock_sizes;
	uint16_t	alg_minbits;
	uint16_t	alg_maxbits;
	uint16_t	alg_datalen;
	/*
	 * increment: number of bits from keysize to keysize
	 * default: # of increments from min to default key len
	 */
	uint16_t	alg_increment;
	uint16_t	alg_default;
	uint16_t	alg_default_bits;
	/*
	 * Min, max, and default key sizes effectively supported
	 * by the encryption framework.
	 */
	uint16_t	alg_ef_minbits;
	uint16_t	alg_ef_maxbits;
	uint16_t	alg_ef_default;
	uint16_t	alg_ef_default_bits;

	crypto_mech_type_t alg_mech_type;	/* KCF mechanism type */
	crypto_mech_name_t alg_mech_name;	/* KCF mechanism name */
} ipsec_alginfo_t;

#define	alg_datalen alg_block_sizes[0]

#define	ALG_FLAG_VALID	0x01
#define	ALG_VALID(_alg)	((_alg)->alg_flags & ALG_FLAG_VALID)

/*
 * Software crypto execution mode.
 */
typedef enum {
	IPSEC_ALGS_EXEC_SYNC = 0,
	IPSEC_ALGS_EXEC_ASYNC = 1
} ipsec_algs_exec_mode_t;

extern uint8_t ipsec_nalgs[IPSEC_NALGTYPES];
extern ipsec_alginfo_t *ipsec_alglists[IPSEC_NALGTYPES][IPSEC_MAX_ALGS];
extern uint8_t ipsec_sortlist[IPSEC_NALGTYPES][IPSEC_MAX_ALGS];
extern ipsec_algs_exec_mode_t ipsec_algs_exec_mode[IPSEC_NALGTYPES];

extern kmutex_t alg_lock;

extern void ipsec_alg_reg(ipsec_algtype_t, ipsec_alginfo_t *);
extern void ipsec_alg_unreg(ipsec_algtype_t, uint8_t);
extern void ipsec_alg_fix_min_max(ipsec_alginfo_t *, ipsec_algtype_t);
extern void ipsec_alg_free(ipsec_alginfo_t *);
extern void ipsec_register_prov_update(void);
extern void sadb_alg_update(ipsec_algtype_t, uint8_t, boolean_t);

/*
 * Context templates management.
 */

#define	IPSEC_CTX_TMPL_ALLOC ((crypto_ctx_template_t)-1)
#define	IPSEC_CTX_TMPL(_sa, _which, _type, _tmpl) {			\
	if ((_tmpl = (_sa)->_which) == IPSEC_CTX_TMPL_ALLOC) {		\
		mutex_enter(&assoc->ipsa_lock);				\
		if ((_sa)->_which == IPSEC_CTX_TMPL_ALLOC) {		\
			mutex_enter(&alg_lock);				\
			(void) ipsec_create_ctx_tmpl(_sa, _type);	\
			mutex_exit(&alg_lock);				\
		}							\
		mutex_exit(&assoc->ipsa_lock);				\
		if ((_tmpl = (_sa)->_which) == IPSEC_CTX_TMPL_ALLOC)	\
			_tmpl = NULL;					\
	}								\
}

extern int ipsec_create_ctx_tmpl(ipsa_t *, ipsec_algtype_t);
extern void ipsec_destroy_ctx_tmpl(ipsa_t *, ipsec_algtype_t);

/* key checking */
extern int ipsec_check_key(crypto_mech_type_t, sadb_key_t *, boolean_t, int *);

/* natt cleanup */
extern void sadb_clear_timeouts(queue_t *);

typedef struct {
	kstat_named_t esp_stat_in_requests;
	kstat_named_t esp_stat_in_discards;
	kstat_named_t esp_stat_lookup_failure;
	kstat_named_t ah_stat_in_requests;
	kstat_named_t ah_stat_in_discards;
	kstat_named_t ah_stat_lookup_failure;
} ipsec_kstats_t;

extern ipsec_kstats_t *ipsec_kstats;
extern void ipsec_kstat_init(void);
extern void ipsec_kstat_destroy(void);

#define	IP_ESP_BUMP_STAT(x) (ipsec_kstats->esp_stat_ ## x).value.ui64++
#define	IP_AH_BUMP_STAT(x) (ipsec_kstats->ah_stat_ ## x).value.ui64++

#ifdef	__cplusplus
}
#endif

#endif /* _INET_SADB_H */
