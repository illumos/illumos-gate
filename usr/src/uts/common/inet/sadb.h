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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

#ifndef	_INET_SADB_H
#define	_INET_SADB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <inet/ipsec_info.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/note.h>

#define	IPSA_MAX_ADDRLEN 4	/* Max address len. (in 32-bits) for an SA. */

#define	MAXSALTSIZE 8

/*
 * For combined mode ciphers, store the crypto_mechanism_t in the
 * per-packet ipsec_in_t/ipsec_out_t structures. This is because the PARAMS
 * and nonce values change for each packet. For non-combined mode
 * ciphers, these values are constant for the life of the SA.
 */
typedef struct ipsa_cm_mech_s {
	crypto_mechanism_t combined_mech;
	union {
		CK_AES_CCM_PARAMS paramu_ccm;
		CK_AES_GCM_PARAMS paramu_gcm;
	} paramu;
	uint8_t nonce[MAXSALTSIZE + sizeof (uint64_t)];
#define	param_ulMACSize paramu.paramu_ccm.ulMACSize
#define	param_ulNonceSize paramu.paramu_ccm.ipsa_ulNonceSize
#define	param_ulAuthDataSize paramu.paramu_ccm.ipsa_ulAuthDataSize
#define	param_ulDataSize paramu.paramu_ccm.ipsa_ulDataSize
#define	param_nonce paramu.paramu_ccm.nonce
#define	param_authData paramu.paramu_ccm.authData
#define	param_pIv paramu.paramu_gcm.ipsa_pIv
#define	param_ulIvLen paramu.paramu_gcm.ulIvLen
#define	param_ulIvBits paramu.paramu_gcm.ulIvBits
#define	param_pAAD paramu.paramu_gcm.pAAD
#define	param_ulAADLen paramu.paramu_gcm.ulAADLen
#define	param_ulTagBits paramu.paramu_gcm.ulTagBits
} ipsa_cm_mech_t;

/*
 * The Initialization Vector (also known as IV or Nonce) used to
 * initialize the Block Cipher, is made up of a Counter and a Salt.
 * The Counter is fixed at 64 bits and is incremented for each packet.
 * The Salt value can be any whole byte value upto 64 bits. This is
 * algorithm mode specific and can be configured with ipsecalgs(1m).
 *
 * We only support whole byte salt lengths, this is because the salt is
 * stored in an array of uint8_t's. This is enforced by ipsecalgs(1m)
 * which configures the salt length as a number of bytes. Checks are
 * made to ensure the salt length defined in ipsecalgs(1m) fits in
 * the ipsec_nonce_t.
 *
 * The Salt value remains constant for the life of the SA, the Salt is
 * know to both peers, but NOT transmitted on the network. The Counter
 * portion of the nonce is transmitted over the network with each packet
 * and is confusingly described as the Initialization Vector by RFCs
 * 4309/4106.
 *
 * The maximum Initialization Vector length is 128 bits, if the actual
 * size is less, its padded internally by the algorithm.
 *
 * The nonce structure is defined like this in the SA (ipsa_t)to ensure
 * the Initilization Vector (counter) is 64 bit aligned, because it will
 * be incremented as an uint64_t. The nonce as used by the algorithms is
 * a straight uint8_t array.
 *
 *                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                     | | | | |x|x|x|x|               |
 *                     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * salt_offset         <------>
 * ipsa_saltlen                <------->
 * ipsa_nonce_buf------^
 * ipsa_salt-------------~~~~~~^
 * ipsa_nonce------------~~~~~~^
 * ipsa_iv-----------------------------^
 */
typedef struct ipsec_nonce_s {
	uint8_t		salt[MAXSALTSIZE];
	uint64_t	iv;
} ipsec_nonce_t;

/*
 * IP security association.  Synchronization assumes 32-bit loads, so
 * the 64-bit quantities can't even be be read w/o locking it down!
 */

/* keying info */
typedef struct ipsa_key_s {
	uint8_t *sak_key;		/* Algorithm key. */
	uint_t sak_keylen;	/* Algorithm key length (in bytes). */
	uint_t sak_keybits;	/* Algorithm key length (in bits) */
	uint_t sak_algid;	/* Algorithm ID number. */
} ipsa_key_t;

typedef struct ipsa_s {
	struct ipsa_s *ipsa_next;	/* Next in hash bucket */
	struct ipsa_s **ipsa_ptpn;	/* Pointer to previous next pointer. */
	kmutex_t *ipsa_linklock;	/* Pointer to hash-chain lock. */
	void (*ipsa_freefunc)(struct ipsa_s *); /* freeassoc function */
	void (*ipsa_noncefunc)(struct ipsa_s *, uchar_t *,
	    uint_t, uchar_t *, ipsa_cm_mech_t *, crypto_data_t *);
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
	mblk_t	*ipsa_lpkt;	/* Packet received while larval (CAS me) */
	mblk_t	*ipsa_bpkt_head;	/* Packets received while idle */
	mblk_t	*ipsa_bpkt_tail;
#define	SADB_MAX_IDLEPKTS	100
	uint8_t	ipsa_mblkcnt;	/* Number of packets received while idle */

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
	time_t ipsa_lastuse;	/* Time of my last use. */
	time_t ipsa_idletime;	/* Seconds of idle time */
	time_t ipsa_last_nat_t_ka;	/* Time of my last NAT-T keepalive. */
	time_t ipsa_softexpiretime;	/* Time of my first soft expire. */
	time_t ipsa_hardexpiretime;	/* Time of my first hard expire. */
	time_t ipsa_idleexpiretime;	/* Time of my next idle expire time */

	struct ipsec_nonce_s *ipsa_nonce_buf;
	uint8_t	*ipsa_nonce;
	uint_t ipsa_nonce_len;
	uint8_t	*ipsa_salt;
	uint_t ipsa_saltbits;
	uint_t ipsa_saltlen;
	uint64_t *ipsa_iv;

	uint64_t ipsa_iv_hardexpire;
	uint64_t ipsa_iv_softexpire;
	/*
	 * The following fields are directly reflected in PF_KEYv2 LIFETIME
	 * extensions.  The time_ts are in number-of-seconds, and the bytes
	 * are in... bytes.
	 */
	time_t ipsa_softaddlt;	/* Seconds of soft lifetime after add. */
	time_t ipsa_softuselt;	/* Seconds of soft lifetime after first use. */
	time_t ipsa_hardaddlt;	/* Seconds of hard lifetime after add. */
	time_t ipsa_harduselt;	/* Seconds of hard lifetime after first use. */
	time_t ipsa_idleaddlt;	/* Seconds of idle time after add */
	time_t ipsa_idleuselt;	/* Seconds of idle time after first use */
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

	uint_t ipsa_type;	/* Type of security association. (AH/etc.) */
	uint_t ipsa_state;	/* State of my association. */
	uint_t ipsa_replay_wsize; /* Size of replay window */
	uint32_t ipsa_flags;	/* Flags for security association. */
	uint32_t ipsa_spi;	/* Security parameters index. */
	uint32_t ipsa_replay;	/* Highest seen replay value for this SA. */
	uint32_t ipsa_kmp;	/* key management proto */
	uint64_t ipsa_kmc;	/* key management cookie (now 64-bit) */

	boolean_t ipsa_haspeer;		/* Has peer in another table. */

	/*
	 * Address storage.
	 * The source address can be INADDR_ANY, IN6ADDR_ANY, etc.
	 *
	 * Address families (per sys/socket.h) guide us.  We could have just
	 * used sockaddr_storage
	 */
	sa_family_t ipsa_addrfam;
	sa_family_t ipsa_innerfam;	/* Inner AF can be != src/dst AF. */

	uint32_t ipsa_srcaddr[IPSA_MAX_ADDRLEN];
	uint32_t ipsa_dstaddr[IPSA_MAX_ADDRLEN];
	uint32_t ipsa_innersrc[IPSA_MAX_ADDRLEN];
	uint32_t ipsa_innerdst[IPSA_MAX_ADDRLEN];

	uint8_t ipsa_innersrcpfx;
	uint8_t ipsa_innerdstpfx;

	uint16_t ipsa_inbound_cksum; /* cksum correction for inbound packets */
	uint16_t ipsa_local_nat_port;	/* Local NAT-T port.  (0 --> 4500) */
	uint16_t ipsa_remote_nat_port; /* The other port that isn't 4500 */

	/* these can only be v4 */
	uint32_t ipsa_natt_addr_loc;
	uint32_t ipsa_natt_addr_rem;

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
	size_t ipsa_mac_len;			/* auth MAC/ICV length */
	size_t ipsa_iv_len;			/* encr IV length */
	size_t ipsa_datalen;			/* block length in bytes. */

	/*
	 * Input and output processing functions called from IP.
	 * The mblk_t is the data; the IPsec information is in the attributes
	 * Returns NULL if the mblk is consumed which it is if there was
	 * a failure or if pending. If failure then
	 * the ipIfInDiscards/OutDiscards counters are increased.
	 */
	mblk_t *(*ipsa_output_func)(mblk_t *, ip_xmit_attr_t *);
	mblk_t *(*ipsa_input_func)(mblk_t *, void *, ip_recv_attr_t *);

	/*
	 * Soft reference to paired SA
	 */
	uint32_t	ipsa_otherspi;
	netstack_t	*ipsa_netstack;	/* Does not have a netstack_hold */

	ts_label_t *ipsa_tsl;			/* MLS: label attributes */
	ts_label_t *ipsa_otsl;			/* MLS: outer label */
	uint8_t	ipsa_mac_exempt;		/* MLS: mac exempt flag */
	uchar_t	ipsa_opt_storage[IP_MAX_OPT_LENGTH];
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
	atomic_inc_32(&(ipsa)->ipsa_refcnt);	\
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
	if (atomic_dec_32_nv(&(ipsa)->ipsa_refcnt) == 0)	\
		((ipsa)->ipsa_freefunc)(ipsa);			\
}

/*
 * Security association hash macros and definitions.  For now, assume the
 * IPsec model, and hash outbounds on destination address, and inbounds on
 * SPI.
 */

#define	IPSEC_DEFAULT_HASH_SIZE 256

#define	INBOUND_HASH(sadb, spi) ((spi) % ((sadb)->sdb_hashsize))
#define	OUTBOUND_HASH_V4(sadb, v4addr) ((v4addr) % ((sadb)->sdb_hashsize))
#define	OUTBOUND_HASH_V6(sadb, v6addr) OUTBOUND_HASH_V4((sadb), \
	(*(uint32_t *)&(v6addr)) ^ (*(((uint32_t *)&(v6addr)) + 1)) ^ \
	(*(((uint32_t *)&(v6addr)) + 2)) ^ (*(((uint32_t *)&(v6addr)) + 3)))

/*
 * Syntactic sugar to find the appropriate hash bucket directly.
 */

#define	INBOUND_BUCKET(sadb, spi) &(((sadb)->sdb_if)[INBOUND_HASH(sadb, spi)])
#define	OUTBOUND_BUCKET_V4(sadb, v4addr) \
	&(((sadb)->sdb_of)[OUTBOUND_HASH_V4(sadb, v4addr)])
#define	OUTBOUND_BUCKET_V6(sadb, v6addr) \
	&(((sadb)->sdb_of)[OUTBOUND_HASH_V6(sadb, v6addr)])

#define	IPSA_F_PFS	SADB_SAFLAGS_PFS	/* PFS in use for this SA? */
#define	IPSA_F_NOREPFLD	SADB_SAFLAGS_NOREPLAY	/* No replay field, for */
						/* backward compat. */
#define	IPSA_F_USED	SADB_X_SAFLAGS_USED	/* SA has been used. */
#define	IPSA_F_UNIQUE	SADB_X_SAFLAGS_UNIQUE	/* SA is unique */
#define	IPSA_F_AALG1	SADB_X_SAFLAGS_AALG1	/* Auth alg flag 1 */
#define	IPSA_F_AALG2	SADB_X_SAFLAGS_AALG2	/* Auth alg flag 2 */
#define	IPSA_F_EALG1	SADB_X_SAFLAGS_EALG1	/* Encrypt alg flag 1 */
#define	IPSA_F_EALG2	SADB_X_SAFLAGS_EALG2	/* Encrypt alg flag 2 */

#define	IPSA_F_ASYNC	0x200000		/* Call KCF asynchronously? */
#define	IPSA_F_NATT_LOC	SADB_X_SAFLAGS_NATT_LOC
#define	IPSA_F_NATT_REM	SADB_X_SAFLAGS_NATT_REM
#define	IPSA_F_BEHIND_NAT SADB_X_SAFLAGS_NATTED
#define	IPSA_F_NATT	(SADB_X_SAFLAGS_NATT_LOC | SADB_X_SAFLAGS_NATT_REM | \
	SADB_X_SAFLAGS_NATTED)
#define	IPSA_F_CINVALID	0x40000		/* SA shouldn't be cached */
#define	IPSA_F_PAIRED	SADB_X_SAFLAGS_PAIRED	/* SA is one of a pair */
#define	IPSA_F_OUTBOUND	SADB_X_SAFLAGS_OUTBOUND	/* SA direction bit */
#define	IPSA_F_INBOUND	SADB_X_SAFLAGS_INBOUND	/* SA direction bit */
#define	IPSA_F_TUNNEL	SADB_X_SAFLAGS_TUNNEL
/*
 * These flags are only defined here to prevent a flag value collision.
 */
#define	IPSA_F_COMBINED	SADB_X_SAFLAGS_EALG1	/* Defined in pfkeyv2.h */
#define	IPSA_F_COUNTERMODE SADB_X_SAFLAGS_EALG2	/* Defined in pfkeyv2.h */

/*
 * Sets of flags that are allowed to by set or modified by PF_KEY apps.
 */
#define	AH_UPDATE_SETTABLE_FLAGS \
	(SADB_X_SAFLAGS_PAIRED | SADB_SAFLAGS_NOREPLAY | \
	SADB_X_SAFLAGS_OUTBOUND | SADB_X_SAFLAGS_INBOUND | \
	SADB_X_SAFLAGS_KM1 | SADB_X_SAFLAGS_KM2 | \
	SADB_X_SAFLAGS_KM3 | SADB_X_SAFLAGS_KM4)

/* AH can't set NAT flags (or even use NAT).  Add NAT flags to the ESP set. */
#define	ESP_UPDATE_SETTABLE_FLAGS (AH_UPDATE_SETTABLE_FLAGS | IPSA_F_NATT)

#define	AH_ADD_SETTABLE_FLAGS \
	(AH_UPDATE_SETTABLE_FLAGS | SADB_X_SAFLAGS_AALG1 | \
	SADB_X_SAFLAGS_AALG2 | SADB_X_SAFLAGS_TUNNEL | \
	SADB_SAFLAGS_NOREPLAY)

/* AH can't set NAT flags (or even use NAT).  Add NAT flags to the ESP set. */
#define	ESP_ADD_SETTABLE_FLAGS (AH_ADD_SETTABLE_FLAGS | IPSA_F_NATT | \
	SADB_X_SAFLAGS_EALG1 | SADB_X_SAFLAGS_EALG2)



/* SA states are important for handling UPDATE PF_KEY messages. */
#define	IPSA_STATE_LARVAL		SADB_SASTATE_LARVAL
#define	IPSA_STATE_MATURE		SADB_SASTATE_MATURE
#define	IPSA_STATE_DYING		SADB_SASTATE_DYING
#define	IPSA_STATE_DEAD			SADB_SASTATE_DEAD
#define	IPSA_STATE_IDLE			SADB_X_SASTATE_IDLE
#define	IPSA_STATE_ACTIVE_ELSEWHERE	SADB_X_SASTATE_ACTIVE_ELSEWHERE

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
	sa_family_t ipsacq_inneraddrfam; /* Inner-packet address family. */
	int ipsacq_numpackets;		/* How many packets queued up so far. */
	uint32_t ipsacq_seq;		/* PF_KEY sequence number. */
	uint64_t ipsacq_unique_id;	/* Unique ID for SAs that need it. */

	kmutex_t ipsacq_lock;	/* Protects non-linkage fields. */
	time_t ipsacq_expire;	/* Wall-clock time when this record expires. */
	mblk_t *ipsacq_mp;	/* List of datagrams waiting for an SA. */

	/* These two point inside the last mblk inserted. */
	uint32_t *ipsacq_srcaddr;
	uint32_t *ipsacq_dstaddr;

	/* Cache these instead of point so we can mask off accordingly */
	uint32_t ipsacq_innersrc[IPSA_MAX_ADDRLEN];
	uint32_t ipsacq_innerdst[IPSA_MAX_ADDRLEN];

	/* These may change per-acquire. */
	uint16_t ipsacq_srcport;
	uint16_t ipsacq_dstport;
	uint8_t ipsacq_proto;
	uint8_t ipsacq_inner_proto;
	uint8_t ipsacq_innersrcpfx;
	uint8_t ipsacq_innerdstpfx;

	/* icmp type and code of triggering packet (if applicable) */
	uint8_t	ipsacq_icmp_type;
	uint8_t ipsacq_icmp_code;

	/* label associated with triggering packet */
	ts_label_t	*ipsacq_tsl;
} ipsacq_t;

/*
 * Kernel-generated sequence numbers will be no less than 0x80000000 to
 * forestall any cretinous problems with manual keying accidentally updating
 * an ACQUIRE entry.
 */
#define	IACQF_LOWEST_SEQ 0x80000000

#define	SADB_AGE_INTERVAL_DEFAULT 8000

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
 * Keep outbound assocs in a simple hash table for now.
 * One danger point, multiple SAs for a single dest will clog a bucket.
 * For the future, consider two-level hashing (2nd hash on IPC?), then probe.
 */

typedef struct sadb_s
{
	isaf_t	*sdb_of;
	isaf_t	*sdb_if;
	iacqf_t	*sdb_acq;
	int	sdb_hashsize;
} sadb_t;

/*
 * A pair of SADB's (one for v4, one for v6), and related state.
 */

typedef struct sadbp_s
{
	uint32_t	s_satype;
	uint32_t	*s_acquire_timeout;
	sadb_t		s_v4;
	sadb_t		s_v6;
	uint32_t	s_addflags;
	uint32_t	s_updateflags;
} sadbp_t;

/*
 * A pair of SA's for a single connection, the structure contains a
 * pointer to a SA and the SA its paired with (opposite direction) as well
 * as the SA's respective hash buckets.
 */
typedef struct ipsap_s
{
	boolean_t	in_inbound_table;
	isaf_t		*ipsap_bucket;
	ipsa_t		*ipsap_sa_ptr;
	isaf_t		*ipsap_pbucket;
	ipsa_t		*ipsap_psa_ptr;
} ipsap_t;

typedef struct templist_s
{
	ipsa_t		*ipsa;
	struct templist_s	*next;
} templist_t;

/* Pointer to an all-zeroes IPv6 address. */
#define	ALL_ZEROES_PTR	((uint32_t *)&ipv6_all_zeros)

/*
 * Form unique id from ip_xmit_attr_t.
 */
#define	SA_FORM_UNIQUE_ID(ixa)					\
	SA_UNIQUE_ID((ixa)->ixa_ipsec_src_port, (ixa)->ixa_ipsec_dst_port, \
	    (((ixa)->ixa_flags & IXAF_IPSEC_TUNNEL) ?			\
	    ((ixa)->ixa_ipsec_inaf == AF_INET6 ? \
	    IPPROTO_IPV6 : IPPROTO_ENCAP) :				\
	    (ixa)->ixa_ipsec_proto),					\
	    (((ixa)->ixa_flags & IXAF_IPSEC_TUNNEL) ? \
	    (ixa)->ixa_ipsec_proto : 0))

/*
 * This macro is used to generate unique ids (along with the addresses, both
 * inner and outer) for outbound datagrams that require unique SAs.
 *
 * N.B. casts and unsigned shift amounts discourage unwarranted
 * sign extension of dstport, proto, and iproto.
 *
 * Unique ID is 64-bits allocated as follows (pardon my big-endian bias):
 *
 *   6               4      43      33              11
 *   3               7      09      21              65              0
 *   +---------------*-------+-------+--------------+---------------+
 *   |  MUST-BE-ZERO |<iprot>|<proto>| <src port>   |  <dest port>  |
 *   +---------------*-------+-------+--------------+---------------+
 *
 * If there are inner addresses (tunnel mode) the ports come from the
 * inner addresses.  If there are no inner addresses, the ports come from
 * the outer addresses (transport mode).  Tunnel mode MUST have <proto>
 * set to either IPPROTO_ENCAP or IPPPROTO_IPV6.
 */
#define	SA_UNIQUE_ID(srcport, dstport, proto, iproto) 	\
	((srcport) | ((uint64_t)(dstport) << 16U) | \
	((uint64_t)(proto) << 32U) | ((uint64_t)(iproto) << 40U))

/*
 * SA_UNIQUE_MASK generates a mask value to use when comparing the unique value
 * from a packet to an SA.
 */

#define	SA_UNIQUE_MASK(srcport, dstport, proto, iproto) 	\
	SA_UNIQUE_ID((srcport != 0) ? 0xffff : 0,		\
		    (dstport != 0) ? 0xffff : 0,		\
		    (proto != 0) ? 0xff : 0,			\
		    (iproto != 0) ? 0xff : 0)

/*
 * Decompose unique id back into its original fields.
 */
#define	SA_IPROTO(ipsa) ((ipsa)->ipsa_unique_id>>40)&0xff
#define	SA_PROTO(ipsa) ((ipsa)->ipsa_unique_id>>32)&0xff
#define	SA_SRCPORT(ipsa) ((ipsa)->ipsa_unique_id & 0xffff)
#define	SA_DSTPORT(ipsa) (((ipsa)->ipsa_unique_id >> 16) & 0xffff)

typedef struct ipsa_query_s ipsa_query_t;

typedef boolean_t (*ipsa_match_fn_t)(ipsa_query_t *, ipsa_t *);

#define	IPSA_NMATCH	10

/*
 * SADB query structure.
 *
 * Provide a generalized mechanism for matching entries in the SADB;
 * one of these structures is initialized using sadb_form_query(),
 * and then can be used as a parameter to sadb_match_query() which returns
 * B_TRUE if the SA matches the query.
 *
 * Under the covers, sadb_form_query populates the matchers[] array with
 * functions which are called one at a time until one fails to match.
 */
struct ipsa_query_s {
	uint32_t req, match;
	sadb_address_t *srcext, *dstext;
	sadb_ident_t *srcid, *dstid;
	sadb_x_kmc_t *kmcext;
	sadb_sa_t *assoc;
	uint32_t spi;
	struct sockaddr_in *src;
	struct sockaddr_in6 *src6;
	struct sockaddr_in *dst;
	struct sockaddr_in6 *dst6;
	sa_family_t af;
	uint32_t *srcaddr, *dstaddr;
	uint32_t ifindex;
	uint32_t kmp;
	uint64_t kmc;
	char *didstr, *sidstr;
	uint16_t didtype, sidtype;
	sadbp_t *spp;
	sadb_t *sp;
	isaf_t	*inbound, *outbound;
	uint32_t outhash;
	uint32_t inhash;
	ipsa_match_fn_t matchers[IPSA_NMATCH];
};

#define	IPSA_Q_SA		0x00000001
#define	IPSA_Q_DST		0x00000002
#define	IPSA_Q_SRC		0x00000004
#define	IPSA_Q_DSTID		0x00000008
#define	IPSA_Q_SRCID		0x00000010
#define	IPSA_Q_KMC		0x00000020
#define	IPSA_Q_INBOUND		0x00000040 /* fill in inbound isaf_t */
#define	IPSA_Q_OUTBOUND		0x00000080 /* fill in outbound isaf_t */

int sadb_form_query(keysock_in_t *, uint32_t, uint32_t, ipsa_query_t *, int *);
boolean_t sadb_match_query(ipsa_query_t *q, ipsa_t *sa);


/*
 * All functions that return an ipsa_t will return it with IPSA_REFHOLD()
 * already called.
 */

/* SA retrieval (inbound and outbound) */
ipsa_t *ipsec_getassocbyspi(isaf_t *, uint32_t, uint32_t *, uint32_t *,
    sa_family_t);
ipsa_t *ipsec_getassocbyconn(isaf_t *, ip_xmit_attr_t *, uint32_t *, uint32_t *,
    sa_family_t, uint8_t, ts_label_t *);

/* SA insertion. */
int sadb_insertassoc(ipsa_t *, isaf_t *);

/* SA table construction and destruction. */
void sadbp_init(const char *name, sadbp_t *, int, int, netstack_t *);
void sadbp_flush(sadbp_t *, netstack_t *);
void sadbp_destroy(sadbp_t *, netstack_t *);

/* SA insertion and deletion. */
int sadb_insertassoc(ipsa_t *, isaf_t *);
void sadb_unlinkassoc(ipsa_t *);

/* Support routines to interface a keysock consumer to PF_KEY. */
mblk_t *sadb_keysock_out(minor_t);
int sadb_hardsoftchk(sadb_lifetime_t *, sadb_lifetime_t *, sadb_lifetime_t *);
int sadb_labelchk(struct keysock_in_s *);
void sadb_pfkey_echo(queue_t *, mblk_t *, sadb_msg_t *, struct keysock_in_s *,
    ipsa_t *);
void sadb_pfkey_error(queue_t *, mblk_t *, int, int, uint_t);
void sadb_keysock_hello(queue_t **, queue_t *, mblk_t *, void (*)(void *),
    void *, timeout_id_t *, int);
int sadb_addrcheck(queue_t *, mblk_t *, sadb_ext_t *, uint_t, netstack_t *);
boolean_t sadb_addrfix(keysock_in_t *, queue_t *, mblk_t *, netstack_t *);
int sadb_addrset(ire_t *);
int sadb_delget_sa(mblk_t *, keysock_in_t *, sadbp_t *, int *, queue_t *,
    uint8_t);

int sadb_purge_sa(mblk_t *, keysock_in_t *, sadb_t *, int *, queue_t *);
int sadb_common_add(queue_t *, mblk_t *, sadb_msg_t *,
    keysock_in_t *, isaf_t *, isaf_t *, ipsa_t *, boolean_t, boolean_t, int *,
    netstack_t *, sadbp_t *);
void sadb_set_usetime(ipsa_t *);
boolean_t sadb_age_bytes(queue_t *, ipsa_t *, uint64_t, boolean_t);
int sadb_update_sa(mblk_t *, keysock_in_t *, mblk_t **, sadbp_t *,
    int *, queue_t *, int (*)(mblk_t *, keysock_in_t *, int *, netstack_t *),
    netstack_t *, uint8_t);
void sadb_acquire(mblk_t *, ip_xmit_attr_t *, boolean_t, boolean_t);
void gcm_params_init(ipsa_t *, uchar_t *, uint_t, uchar_t *, ipsa_cm_mech_t *,
    crypto_data_t *);
void ccm_params_init(ipsa_t *, uchar_t *, uint_t, uchar_t *, ipsa_cm_mech_t *,
    crypto_data_t *);
void cbc_params_init(ipsa_t *, uchar_t *, uint_t, uchar_t *, ipsa_cm_mech_t *,
    crypto_data_t *);

void sadb_destroy_acquire(ipsacq_t *, netstack_t *);
struct ipsec_stack;
ipsa_t *sadb_getspi(keysock_in_t *, uint32_t, int *, netstack_t *, uint_t);
void sadb_in_acquire(sadb_msg_t *, sadbp_t *, queue_t *, netstack_t *);
boolean_t sadb_replay_check(ipsa_t *, uint32_t);
boolean_t sadb_replay_peek(ipsa_t *, uint32_t);
int sadb_dump(queue_t *, mblk_t *, keysock_in_t *, sadb_t *);
void sadb_replay_delete(ipsa_t *);
void sadb_ager(sadb_t *, queue_t *, int, netstack_t *);

timeout_id_t sadb_retimeout(hrtime_t, queue_t *, void (*)(void *), void *,
    uint_t *, uint_t, short);
void sadb_sa_refrele(void *target);
mblk_t *sadb_set_lpkt(ipsa_t *, mblk_t *, ip_recv_attr_t *);
mblk_t *sadb_clear_lpkt(ipsa_t *);
void sadb_buf_pkt(ipsa_t *, mblk_t *, ip_recv_attr_t *);
void sadb_clear_buf_pkt(void *ipkt);

/* Note that buf_pkt is the product of ip_recv_attr_to_mblk() */
#define	HANDLE_BUF_PKT(taskq, stack, dropper, buf_pkt)			\
{									\
	if (buf_pkt != NULL) {						\
		if (taskq_dispatch(taskq, sadb_clear_buf_pkt,		\
		    (void *) buf_pkt, TQ_NOSLEEP) == 0) {		\
		    /* Dispatch was unsuccessful drop the packets. */	\
			mblk_t		*tmp;				\
			while (buf_pkt != NULL) {			\
				tmp = buf_pkt->b_next;			\
				buf_pkt->b_next = NULL;			\
				buf_pkt = ip_recv_attr_free_mblk(buf_pkt); \
				ip_drop_packet(buf_pkt, B_TRUE, NULL,	\
				    DROPPER(stack,			\
				    ipds_sadb_inidle_timeout),		\
				    &dropper);				\
				buf_pkt = tmp;				\
			}						\
		}							\
	}								\
}									\

/*
 * Two IPsec rate-limiting routines.
 */
/*PRINTFLIKE6*/
extern void ipsec_rl_strlog(netstack_t *, short, short, char,
    ushort_t, char *, ...)
    __KPRINTFLIKE(6);
extern void ipsec_assocfailure(short, short, char, ushort_t, char *, uint32_t,
    void *, int, netstack_t *);

/*
 * Algorithm types.
 */

#define	IPSEC_NALGTYPES 	2

typedef enum ipsec_algtype {
	IPSEC_ALG_AUTH = 0,
	IPSEC_ALG_ENCR = 1,
	IPSEC_ALG_ALL = 2
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
	uint16_t	*alg_params;
	uint16_t	alg_nkey_sizes;
	uint16_t	alg_ivlen;
	uint16_t	alg_icvlen;
	uint8_t		alg_saltlen;
	uint16_t	alg_nblock_sizes;
	uint16_t	alg_nparams;
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
#define	ALG_VALID(_alg)	((_alg)->alg_flags & ALG_FLAG_VALID)

/*
 * Software crypto execution mode.
 */
typedef enum {
	IPSEC_ALGS_EXEC_SYNC = 0,
	IPSEC_ALGS_EXEC_ASYNC = 1
} ipsec_algs_exec_mode_t;

extern void ipsec_alg_reg(ipsec_algtype_t, ipsec_alginfo_t *, netstack_t *);
extern void ipsec_alg_unreg(ipsec_algtype_t, uint8_t, netstack_t *);
extern void ipsec_alg_fix_min_max(ipsec_alginfo_t *, ipsec_algtype_t,
    netstack_t *ns);
extern void alg_flag_check(ipsec_alginfo_t *);
extern void ipsec_alg_free(ipsec_alginfo_t *);
extern void ipsec_register_prov_update(void);
extern void sadb_alg_update(ipsec_algtype_t, uint8_t, boolean_t, netstack_t *);

extern int sadb_sens_len_from_label(ts_label_t *);
extern void sadb_sens_from_label(sadb_sens_t *, int, ts_label_t *, int);

/*
 * Context templates management.
 */

#define	IPSEC_CTX_TMPL_ALLOC ((crypto_ctx_template_t)-1)
#define	IPSEC_CTX_TMPL(_sa, _which, _type, _tmpl) {			\
	if ((_tmpl = (_sa)->_which) == IPSEC_CTX_TMPL_ALLOC) {		\
		mutex_enter(&assoc->ipsa_lock);				\
		if ((_sa)->_which == IPSEC_CTX_TMPL_ALLOC) {		\
			ipsec_stack_t *ipss;				\
									\
			ipss = assoc->ipsa_netstack->netstack_ipsec;	\
			rw_enter(&ipss->ipsec_alg_lock, RW_READER);	\
			(void) ipsec_create_ctx_tmpl(_sa, _type);	\
			rw_exit(&ipss->ipsec_alg_lock);			\
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

typedef struct ipsec_kstats_s {
	kstat_named_t esp_stat_in_requests;
	kstat_named_t esp_stat_in_discards;
	kstat_named_t esp_stat_lookup_failure;
	kstat_named_t ah_stat_in_requests;
	kstat_named_t ah_stat_in_discards;
	kstat_named_t ah_stat_lookup_failure;
	kstat_named_t sadb_acquire_maxpackets;
	kstat_named_t sadb_acquire_qhiwater;
} ipsec_kstats_t;

/*
 * (ipss)->ipsec_kstats is equal to (ipss)->ipsec_ksp->ks_data if
 * kstat_create_netstack for (ipss)->ipsec_ksp succeeds, but when it
 * fails, it will be NULL. Note this is done for all stack instances,
 * so it *could* fail. hence a non-NULL checking is done for
 * IP_ESP_BUMP_STAT, IP_AH_BUMP_STAT and IP_ACQUIRE_STAT
 */
#define	IP_ESP_BUMP_STAT(ipss, x)					\
do {									\
	if ((ipss)->ipsec_kstats != NULL)				\
		((ipss)->ipsec_kstats->esp_stat_ ## x).value.ui64++;	\
_NOTE(CONSTCOND)							\
} while (0)

#define	IP_AH_BUMP_STAT(ipss, x)					\
do {									\
	if ((ipss)->ipsec_kstats != NULL)				\
		((ipss)->ipsec_kstats->ah_stat_ ## x).value.ui64++;	\
_NOTE(CONSTCOND)							\
} while (0)

#define	IP_ACQUIRE_STAT(ipss, val, new)					\
do {									\
	if ((ipss)->ipsec_kstats != NULL &&				\
	    ((uint64_t)(new)) >						\
	    ((ipss)->ipsec_kstats->sadb_acquire_ ## val).value.ui64)	\
		((ipss)->ipsec_kstats->sadb_acquire_ ## val).value.ui64 = \
			((uint64_t)(new));				\
_NOTE(CONSTCOND)							\
} while (0)


#ifdef	__cplusplus
}
#endif

#endif /* _INET_SADB_H */
