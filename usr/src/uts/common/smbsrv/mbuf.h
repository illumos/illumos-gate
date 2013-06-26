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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1982, 1986, 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 */

#ifndef _SMBSRV_MBUF_H
#define	_SMBSRV_MBUF_H

/*
 * This mbuf simulation should be replaced with (native) mblk_t support.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <smbsrv/string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MSIZE		256
#define	MCLBYTES	8192

/*
 * Mbufs are of a single size, MSIZE (machine/machparam.h), which
 * includes overhead.  An mbuf may add a single "mbuf cluster" of size
 * MCLBYTES (also in machine/machparam.h), which has no additional overhead
 * and is used instead of the internal data area; this is done when
 * at least MINCLSIZE of data must be stored.
 */

#define	MLEN		(MSIZE - sizeof (struct m_hdr))	/* normal data len */
#define	MHLEN		(MLEN - sizeof (struct pkthdr))	/* data len w/pkthdr */

#define	MINCLSIZE	(MHLEN + MLEN)	/* smallest amount to put in cluster */

/*
 * Macros for type conversion
 * mtod(m,t) -	convert mbuf pointer to data pointer of correct type
 */
#define	mtod(m, t)	((t)((m)->m_data))


/* header at beginning of each mbuf: */
struct m_hdr {
	struct	mbuf *mh_next;		/* next buffer in chain */
	struct	mbuf *mh_nextpkt;	/* next chain in queue/record */
	int	mh_len;			/* amount of data in this mbuf */
	caddr_t	mh_data;		/* location of data */
	short	mh_type;		/* type of data in this mbuf */
	short	mh_flags;		/* flags; see below */
};

/* record/packet header in first mbuf of chain; valid if M_PKTHDR set */
struct	pkthdr {
	int	len;		/* total packet length */
};


/* description of external storage mapped into mbuf, valid if M_EXT set */
struct m_ext {
	caddr_t	ext_buf;		/* start of buffer */
	int	(*ext_ref)();		/* refcount adjust function */
	uint_t	ext_size;		/* size of buffer, for ext_free */
};

typedef struct mbuf {
	struct	m_hdr m_hdr;
	union {
		struct {
			struct	pkthdr MH_pkthdr;	/* M_PKTHDR set */
			union {
				struct	m_ext MH_ext;	/* M_EXT set */
				char	MH_databuf[MHLEN];
			} MH_dat;
		} MH;
		char	M_databuf[MLEN];		/* !M_PKTHDR, !M_EXT */
	} M_dat;
} mbuf_t;

#define	m_next		m_hdr.mh_next
#define	m_len		m_hdr.mh_len
#define	m_data		m_hdr.mh_data
#define	m_type		m_hdr.mh_type
#define	m_flags		m_hdr.mh_flags
#define	m_nextpkt	m_hdr.mh_nextpkt
#define	m_act		m_nextpkt
#define	m_pkthdr	M_dat.MH.MH_pkthdr
#define	m_ext		M_dat.MH.MH_dat.MH_ext
#define	m_pktdat	M_dat.MH.MH_dat.MH_databuf
#define	m_dat		M_dat.M_databuf

/* mbuf flags */
#define	M_EXT		0x0001	/* has associated external storage */
#define	M_PKTHDR	0x0002	/* start of record */
#define	M_EOR		0x0004	/* end of record */

/* mbuf pkthdr flags, also in m_flags */
#define	M_BCAST		0x0100	/* send/received as link-level broadcast */
#define	M_MCAST		0x0200	/* send/received as link-level multicast */

/* flags copied when copying m_pkthdr */
#define	M_COPYFLAGS	(M_PKTHDR|M_EOR|M_BCAST|M_MCAST)

/* XXX probably only need MT_DATA */

/* mbuf types */
#define	MT_FREE		0	/* should be on free list */
#define	MT_DATA		1	/* dynamic (data) allocation */
#define	MT_HEADER	2	/* packet header */
#define	MT_SOCKET	3	/* socket structure */
#define	MT_PCB		4	/* protocol control block */
#define	MT_RTABLE	5	/* routing tables */
#define	MT_HTABLE	6	/* IMP host tables */
#define	MT_ATABLE	7	/* address resolution tables */
#define	MT_SONAME	8	/* socket name */
#define	MT_SOOPTS	10	/* socket options */
#define	MT_FTABLE	11	/* fragment reassembly header */
#define	MT_RIGHTS	12	/* access rights */
#define	MT_IFADDR	13	/* interface address */
#define	MT_CONTROL	14	/* extra-data protocol message */
#define	MT_OOBDATA	15	/* expedited data  */

/*
 * flags to malloc: PBSHORTCUT
 */
#define	M_WAITOK	0x0000
#define	M_NOWAIT	0x0001

/* flags to m_get/MGET */
#define	M_DONTWAIT	M_NOWAIT
#define	M_WAIT		M_WAITOK


/*
 * mbuf allocation/deallocation macros:
 *
 *	MGET(struct mbuf *m, int how, int type)
 * allocates an mbuf and initializes it to contain internal data.
 *
 *	MGETHDR(struct mbuf *m, int how, int type)
 * allocates an mbuf and initializes it to contain a packet header
 * and internal data.
 */

#define	MGET(m, how, type) { \
	m = smb_mbuf_alloc(); \
	(m)->m_next = (struct mbuf *)NULL; \
	(m)->m_nextpkt = (struct mbuf *)NULL; \
	(m)->m_data = (m)->m_dat; \
	(m)->m_flags = 0; \
	(m)->m_type = (short)(type); \
}

#define	MGETHDR(m, how, type) { \
	m = smb_mbuf_alloc(); \
	(m)->m_type = (MT_HEADER); \
	(m)->m_next = (struct mbuf *)NULL; \
	(m)->m_nextpkt = (struct mbuf *)NULL; \
	(m)->m_data = (m)->m_pktdat; \
	(m)->m_flags = M_PKTHDR; \
}

#define	MCLGET(m, how) \
	{ \
		(m)->m_ext.ext_buf = smb_mbufcl_alloc();	\
		(m)->m_data = (m)->m_ext.ext_buf;		\
		(m)->m_flags |= M_EXT;				\
		(m)->m_ext.ext_size = MCLBYTES;			\
		(m)->m_ext.ext_ref = smb_mbufcl_ref;		\
	}

/*
 * MFREE(struct mbuf *m, struct mbuf *nn)
 * Free a single mbuf and associated external storage.
 * Place the successor, if any, in nn.
 */
#define	MFREE(m, nn) \
	{ \
		if ((m)->m_flags & M_EXT) {		    \
			(*((m)->m_ext.ext_ref))((m)->m_ext.ext_buf,	\
			    (m)->m_ext.ext_size, -1);			\
			(m)->m_ext.ext_buf = 0;				\
		}							\
		(nn) = (m)->m_next;					\
		(m)->m_next = 0;					\
		smb_mbuf_free(m);					\
	}



/*
 * As above, for mbufs allocated with m_gethdr/MGETHDR
 * or initialized by M_COPY_PKTHDR.
 */
#define	MH_ALIGN(m, len) \
	{ (m)->m_data += (MHLEN - (len)) &~ (sizeof (int32_t) - 1); }

#define	SMB_MBC_MAGIC		0x4D42435F
#define	SMB_MBC_VALID(p)	ASSERT((p)->mbc_magic == SMB_MBC_MAGIC)

typedef struct mbuf_chain {
	uint32_t		mbc_magic;
	volatile uint32_t	flags;		/* Various flags */
	struct mbuf_chain	*shadow_of;	/* I'm shadowing someone */
	mbuf_t			*chain;		/* Start of chain */
	int32_t			max_bytes;	/* max # of bytes for chain */
	int32_t			chain_offset;	/* Current offset into chain */
} mbuf_chain_t;

mbuf_t *smb_mbuf_alloc(void);
void smb_mbuf_free(mbuf_t *);

void *smb_mbufcl_alloc(void);
void smb_mbufcl_free(void *);
int smb_mbufcl_ref(void *, uint_t, int);

mbuf_t *m_free(mbuf_t *);
void m_freem(mbuf_t *);
void smb_mbc_init(void);
void smb_mbc_fini(void);
mbuf_chain_t *smb_mbc_alloc(uint32_t);
void smb_mbc_free(mbuf_chain_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_MBUF_H */
