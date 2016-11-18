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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SOCKFS_SOCKTPI_H
#define	_SOCKFS_SOCKTPI_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Internal representation used for addresses.
 */
struct soaddr {
	struct sockaddr	*soa_sa;	/* Actual address */
	t_uscalar_t	soa_len;	/* Length in bytes for kmem_free */
	t_uscalar_t	soa_maxlen;	/* Allocated length */
};
/* Maximum size address for transports that have ADDR_size == 1 */
#define	SOA_DEFSIZE	128

struct sonode;

/*
 * TPI Sockets
 * ======================
 *
 * A TPI socket can be created by the TPI socket module, or as a
 * result of fallback. In either case, the TPI related information is
 * stored in a sotpi_info_t. Sockets that are TPI based from the
 * beginning will use a sotpi_sonode_t, but fallback case the
 * sotpi_info_t will be allocated when needed. However, the so_priv
 * field in the sonode will always point to the sotpi_info_t, and the
 * structure should only be accessed via so_priv. Use SOTOTPI().
 *
 * A TPI socket always corresponds to a VCHR stream representing the
 * transport provider (e.g. /dev/tcp). This information is retrieved
 * from the kernel socket configuration table and accessible via
 * so_sockparams->sp_sdev_info.  sockfs uses this to perform
 * VOP_ACCESS checks before allowing an open of the transport
 * provider.
 *
 * AF_UNIX Sockets
 * -------------------------
 *
 * When an AF_UNIX socket is bound to a pathname the sockfs creates a
 * VSOCK vnode in the underlying file system. However, the vnodeops
 * etc in this VNODE remain those of the underlying file system.
 * Sockfs uses the v_stream pointer in the underlying file system
 * VSOCK node to find the sonode bound to the pathname. The bound
 * pathname vnode is accessed through sti_ux_vp.
 *
 * Out of Band Data Handling
 * -------------------------
 *
 * The counts (sti_oobcnt and sti_oobsigcnt) track the number of
 * urgent indicates that are (logically) queued on the stream head
 * read queue. The urgent data is queued on the stream head
 * as follows.
 *
 * In the normal case the SIGURG is not generated until
 * the T_EXDATA_IND arrives at the stream head. However, transports
 * that have an early indication that urgent data is pending
 * (e.g. TCP receiving a "new" urgent pointer value) can send up
 * an M_PCPROTO/SIGURG message to generate the signal early.
 *
 * The mark is indicated by either:
 *  - a T_EXDATA_IND (with no M_DATA b_cont) with MSGMARK set.
 *    When this message is consumed by sorecvmsg the socket layer
 *    sets SS_RCVATMARK until data has been consumed past the mark.
 *  - a message with MSGMARKNEXT set (indicating that the
 *    first byte of the next message constitutes the mark). When
 *    the last byte of the MSGMARKNEXT message is consumed in
 *    the stream head the stream head sets STRATMARK. This flag
 *    is cleared when at least one byte is read. (Note that
 *    the MSGMARKNEXT messages can be of zero length when there
 *    is no previous data to which the marknext can be attached.)
 *
 * While the T_EXDATA_IND method is the common case which is used
 * with all TPI transports, the MSGMARKNEXT method is needed to
 * indicate the mark when e.g. the TCP urgent byte has not been
 * received yet but the TCP urgent pointer has made TCP generate
 * the M_PCSIG/SIGURG.
 *
 * The signal (the M_PCSIG carrying the SIGURG) and the mark
 * indication can not be delivered as a single message, since
 * the signal should be delivered as high priority and any mark
 * indication must flow with the data. This implies that immediately
 * when the SIGURG has been delivered if the stream head queue is
 * empty it is impossible to determine if this will be the position
 * of the mark. This race condition is resolved by using MSGNOTMARKNEXT
 * messages and the STRNOTATMARK flag in the stream head. The
 * SIOCATMARK code calls the stream head to wait for either a
 * non-empty queue or one of the STR*ATMARK flags being set.
 * This implies that any transport that is sending M_PCSIG(SIGURG)
 * should send the appropriate MSGNOTMARKNEXT message (which can be
 * zero length) after sending an M_PCSIG to prevent SIOCATMARK
 * from sleeping unnecessarily.
 */

#define	SOTPI_INFO_MAGIC	0x12345678

/*
 * Information used by TPI/STREAMS sockets
 */
typedef struct sotpi_info {
	/*
	 * These fields are initialized once.
	 */
	uint32_t	sti_magic;	/* always set to SOTPI_INFO_MAGIC */
	dev_t		sti_dev;	/* device the sonode represents */

	struct sockparams *sti_orig_sp;	/* in case of fallback; the orig sp */

	kmutex_t	sti_plumb_lock;	/* serializes plumbs, and the related */
					/* so_pushcnt */
	short		sti_pushcnt;	/* Number of modules above "sockmod" */

	kcondvar_t	sti_ack_cv;	/* wait for TPI acks */

	uint8_t
		sti_laddr_valid : 1,	/* sti_laddr valid for user */
		sti_faddr_valid : 1,	/* sti_faddr valid for user */
		sti_faddr_noxlate : 1,	/* No xlation of faddr for AF_UNIX */

		sti_direct : 1,		/* transport is directly below */

		sti_pad_to_bit7 : 4;

	mblk_t	*sti_ack_mp;		/* TPI ack received from below */
	mblk_t	*sti_unbind_mp;		/* Preallocated T_UNBIND_REQ message */

	time_t  sti_atime;		/* time of last access */
	time_t  sti_mtime;		/* time of last modification */
	time_t  sti_ctime;		/* time of last attributes change */

	ushort_t sti_delayed_error;	/* From T_uderror_ind */
	mblk_t	*sti_eaddr_mp;		/* for so_delayed_error */
					/* put here for delayed processing  */

	mblk_t	*sti_conn_ind_head;	/* b_next list of T_CONN_IND */
	mblk_t	*sti_conn_ind_tail;

	uint_t	sti_oobsigcnt;		/* Number of SIGURG generated */
	uint_t	sti_oobcnt;		/* Number of T_EXDATA_IND queued */

	/* From T_info_ack */
	t_uscalar_t	sti_tsdu_size;
	t_uscalar_t	sti_etsdu_size;
	t_scalar_t	sti_addr_size;
	t_uscalar_t	sti_opt_size;
	t_uscalar_t	sti_tidu_size;
	t_scalar_t	sti_serv_type;

	/* From T_capability_ack */
	t_uscalar_t	sti_acceptor_id;

	/* Internal provider information */
	struct tpi_provinfo	*sti_provinfo;

	/*
	 * The local and remote addresses have multiple purposes
	 * but one of the key reasons for their existence and careful
	 * tracking in sockfs is to support getsockname and getpeername
	 * when the transport does not handle the TI_GET*NAME ioctls
	 * and caching when it does (signalled by valid bits in so_state).
	 * When all transports support the new TPI (with T_ADDR_REQ)
	 * we can revisit this code.
	 *
	 * The other usage of sti_faddr is to keep the "connected to"
	 * address for datagram sockets.
	 *
	 * Finally, for AF_UNIX both local and remote addresses are used
	 * to record the sockaddr_un since we use a separate namespace
	 * in the loopback transport.
	 */
	struct soaddr sti_laddr;	/* Local address */
	struct soaddr sti_faddr;	/* Peer address */
#define	sti_laddr_sa		sti_laddr.soa_sa
#define	sti_faddr_sa		sti_faddr.soa_sa
#define	sti_laddr_len		sti_laddr.soa_len
#define	sti_faddr_len		sti_faddr.soa_len
#define	sti_laddr_maxlen	sti_laddr.soa_maxlen
#define	sti_faddr_maxlen	sti_faddr.soa_maxlen

	/*
	 * For AF_UNIX sockets:
	 *
	 * sti_ux_laddr/faddr records the internal addresses used with the
	 * transport. sti_ux_vp and v_stream->sd_vnode form the
	 * cross-linkage between the underlying fs vnode corresponding
	 * to the bound sockaddr_un and the socket node.
	 *
	 * sti_ux_taddr holds the result of translations done in
	 * so_ux_addr_xlate(), which may or may not be the same as
	 * sti_ux_faddr (which is our connected peer address).
	 */
	struct so_ux_addr sti_ux_laddr; /* laddr bound with the transport */
	struct so_ux_addr sti_ux_faddr; /* connected peer address */
	struct so_ux_addr sti_ux_taddr; /* temporary address for sendmsg */
	struct vnode	*sti_ux_bound_vp; /* bound AF_UNIX file system vnode */
	struct sonode	*sti_next_so;	/* next sonode on socklist	*/
	struct sonode	*sti_prev_so;	/* previous sonode on socklist	*/
	mblk_t	*sti_discon_ind_mp;	/* T_DISCON_IND received from below */

	/*
	 * For NL7C sockets:
	 *
	 * sti_nl7c_flags	the NL7C state of URL processing.
	 *
	 * sti_nl7c_rcv_mp	mblk_t chain of already received data to be
	 *			passed up to the app after NL7C gives up on
	 *			a socket.
	 *
	 * sti_nl7c_rcv_rval	returned rval for last mblk_t from above.
	 *
	 * sti_nl7c_uri		the URI currently being processed.
	 *
	 * sti_nl7c_rtime	URI request gethrestime_sec().
	 *
	 * sti_nl7c_addr	pointer returned by nl7c_addr_lookup().
	 */
	uint64_t	sti_nl7c_flags;
	mblk_t		*sti_nl7c_rcv_mp;
	int64_t		sti_nl7c_rcv_rval;
	void		*sti_nl7c_uri;
	time_t		sti_nl7c_rtime;
	void		*sti_nl7c_addr;
} sotpi_info_t;

struct T_capability_ack;

extern sonodeops_t sotpi_sonodeops;

extern int	socktpi_init(void);
extern int	sotpi_convert_sonode(struct sonode *, struct sockparams *,
		    boolean_t *, queue_t **, struct cred *);
extern void	sotpi_revert_sonode(struct sonode *, struct cred *);
extern void	sotpi_update_state(struct sonode *, struct T_capability_ack *,
		    struct sockaddr *, socklen_t, struct sockaddr *, socklen_t,
		    short);

extern sotpi_info_t 	*sotpi_sototpi(struct sonode *);
#ifdef DEBUG
#define	SOTOTPI(so)	(sotpi_sototpi(so))
#else
#define	SOTOTPI(so)	((sotpi_info_t *)(so)->so_priv)
#endif

/* for consumers outside sockfs */
#define	_SOTOTPI(so)	((sotpi_info_t *)(so)->so_priv)

#ifdef	__cplusplus
}
#endif

#endif /* _SOCKFS_SOCKTPI_H */
