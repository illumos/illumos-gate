/*	$NetBSD: bpf.c,v 1.143 2009/03/11 05:55:22 mrg Exp $	*/

/*
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 *	@(#)bpf.c	8.4 (Berkeley) 1/9/95
 * static char rcsid[] =
 * "Header: bpf.c,v 1.67 96/09/26 22:00:52 leres Exp ";
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The BPF implements the following access controls for zones attempting
 * to read and write data. Writing of data requires that the net_rawaccess
 * privilege is held whilst reading data requires either net_rawaccess or
 * net_observerability.
 *
 *                              | Shared |  Exclusive |   Global
 * -----------------------------+--------+------------+------------+
 * DLT_IPNET in local zone      |  Read  |    Read    |    Read    |
 * -----------------------------+--------+------------+------------+
 * Raw access to local zone NIC |  None  | Read/Write | Read/Write |
 * -----------------------------+--------+------------+------------+
 * Raw access to all NICs       |  None  |    None    | Read/Write |
 * -----------------------------+--------+------------+------------+
 *
 * The BPF driver is written as a cloning driver: each call to bpfopen()
 * allocates a new minor number. This provides BPF with a 1:1 relationship
 * between open's and close's. There is some amount of "descriptor state"
 * that is kept per open. Pointers to this data are stored in a hash table
 * (bpf_hash) that is index'd by the minor device number for each open file.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/filio.h>
#include <sys/policy.h>
#include <sys/cmn_err.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/sysmacros.h>
#include <sys/zone.h>

#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/poll.h>
#include <sys/dlpi.h>
#include <sys/neti.h>

#include <net/if.h>

#include <net/bpf.h>
#include <net/bpfdesc.h>
#include <net/dlt.h>

#include <netinet/in.h>
#include <sys/mac.h>
#include <sys/mac_client.h>
#include <sys/mac_impl.h>
#include <sys/time_std_impl.h>
#include <sys/hook.h>
#include <sys/hook_event.h>


#define	mtod(_v, _t)	(_t)((_v)->b_rptr)
#define	M_LEN(_m)	((_m)->b_wptr - (_m)->b_rptr)

/*
 * 4096 is too small for FDDI frames. 8192 is too small for gigabit Ethernet
 * jumbos (circa 9k), ATM, or Intel gig/10gig ethernet jumbos (16k).
 */
#define	BPF_BUFSIZE (32 * 1024)

typedef void *(*cp_fn_t)(void *, const void *, size_t);

/*
 * The default read buffer size, and limit for BIOCSBLEN.
 */
int bpf_bufsize = BPF_BUFSIZE;
int bpf_maxbufsize = (16 * 1024 * 1024);
int bpf_debug = 0;
mod_hash_t *bpf_hash = NULL;

/*
 * Use a mutex to avoid a race condition between gathering the stats/peers
 * and opening/closing the device.
 */
static kcondvar_t bpf_dlt_waiter;
static kmutex_t bpf_mtx;
static bpf_kstats_t ks_stats;
static bpf_kstats_t bpf_kstats = {
	{ "readWait",		KSTAT_DATA_UINT64 },
	{ "writeOk",		KSTAT_DATA_UINT64 },
	{ "writeError",		KSTAT_DATA_UINT64 },
	{ "receive",		KSTAT_DATA_UINT64 },
	{ "captured",		KSTAT_DATA_UINT64 },
	{ "dropped",		KSTAT_DATA_UINT64 },
};
static kstat_t *bpf_ksp;

/*
 *  bpf_iflist is the list of interfaces; each corresponds to an ifnet
 *  bpf_dtab holds the descriptors, indexed by minor device #
 */
TAILQ_HEAD(, bpf_if) bpf_iflist;
LIST_HEAD(, bpf_d) bpf_list;

static int	bpf_allocbufs(struct bpf_d *);
static void	bpf_clear_timeout(struct bpf_d *);
static void	bpf_debug_nic_action(char *, struct bpf_if *);
static void	bpf_deliver(struct bpf_d *, cp_fn_t,
		    void *, uint_t, uint_t, boolean_t);
static struct bpf_if *
		bpf_findif(struct bpf_d *, char *, int);
static void	bpf_freed(struct bpf_d *);
static int	bpf_ifname(struct bpf_d *d, char *, int);
static void	*bpf_mcpy(void *, const void *, size_t);
static void	bpf_attachd(struct bpf_d *, struct bpf_if *);
static void	bpf_detachd(struct bpf_d *);
static int	bpf_setif(struct bpf_d *, char *, int);
static void	bpf_timed_out(void *);
static inline void
		bpf_wakeup(struct bpf_d *);
static void	catchpacket(struct bpf_d *, uchar_t *, uint_t, uint_t,
		    cp_fn_t, struct timeval *);
static void	reset_d(struct bpf_d *);
static int	bpf_getdltlist(struct bpf_d *, struct bpf_dltlist *);
static int	bpf_setdlt(struct bpf_d *, void *);
static void	bpf_dev_add(struct bpf_d *);
static struct bpf_d *bpf_dev_find(minor_t);
static struct bpf_d *bpf_dev_get(minor_t);
static void	bpf_dev_remove(struct bpf_d *);

static int
bpf_movein(struct uio *uio, int linktype, int mtu, mblk_t **mp)
{
	mblk_t *m;
	int error;
	int len;
	int hlen;
	int align;

	/*
	 * Build a sockaddr based on the data link layer type.
	 * We do this at this level because the ethernet header
	 * is copied directly into the data field of the sockaddr.
	 * In the case of SLIP, there is no header and the packet
	 * is forwarded as is.
	 * Also, we are careful to leave room at the front of the mbuf
	 * for the link level header.
	 */
	switch (linktype) {

	case DLT_EN10MB:
		hlen = sizeof (struct ether_header);
		break;

	case DLT_FDDI:
		hlen = 16;
		break;

	case DLT_NULL:
		hlen = 0;
		break;

	case DLT_IPOIB:
		hlen = 44;
		break;

	default:
		return (EIO);
	}

	align = 4 - (hlen & 3);

	len = uio->uio_resid;
	/*
	 * If there aren't enough bytes for a link level header or the
	 * packet length exceeds the interface mtu, return an error.
	 */
	if (len < hlen || len - hlen > mtu)
		return (EMSGSIZE);

	m = allocb(len + align, BPRI_MED);
	if (m == NULL) {
		error = ENOBUFS;
		goto bad;
	}

	/* Insure the data is properly aligned */
	if (align > 0)
		m->b_rptr += align;
	m->b_wptr = m->b_rptr + len;

	error = uiomove(mtod(m, void *), len, UIO_WRITE, uio);
	if (error)
		goto bad;
	*mp = m;
	return (0);

bad:
	if (m != NULL)
		freemsg(m);
	return (error);
}


/*
 * Attach file to the bpf interface, i.e. make d listen on bp.
 */
static void
bpf_attachd(struct bpf_d *d, struct bpf_if *bp)
{
	uintptr_t mh = bp->bif_ifp;

	ASSERT(bp != NULL);
	ASSERT(d->bd_bif == NULL);
	/*
	 * Point d at bp, and add d to the interface's list of listeners.
	 * Finally, point the driver's bpf cookie at the interface so
	 * it will divert packets to bpf.
	 *
	 * Note: Although this results in what looks like a lock order
	 * reversal (bd_lock is held), the deadlock threat is not present
	 * because the descriptor is not attached to any interface and
	 * therefore there cannot be a packet waiting on bd_lock in
	 * catchpacket.
	 */
	mutex_enter(&bp->bif_lock);
	d->bd_bif = bp;
	LIST_INSERT_HEAD(&bp->bif_dlist, d, bd_next);
	mutex_exit(&bp->bif_lock);

	if (MBPF_CLIENT_OPEN(&bp->bif_mac, mh, &d->bd_mcip) == 0)
		(void) MBPF_PROMISC_ADD(&bp->bif_mac, d->bd_mcip, 0, d,
		    &d->bd_promisc_handle, d->bd_promisc_flags);
}

/*
 * Detach a file from its interface.
 */
static void
bpf_detachd(struct bpf_d *d)
{
	struct bpf_if *bp;
	uintptr_t mph;
	uintptr_t mch;

	mch = d->bd_mcip;
	d->bd_mcip = 0;
	bp = d->bd_bif;
	ASSERT(bp != NULL);

	/*
	 * Check if this descriptor had requested promiscuous mode.
	 * If so, turn it off. There's no need to take any action
	 * here, that is done when MBPF_PROMISC_REMOVE is used;
	 * bd_promisc is just a local flag to stop promiscuous mode
	 * from being set more than once.
	 */
	if (d->bd_promisc)
		d->bd_promisc = 0;

	/*
	 * Take device out of "promiscuous" mode.  Since we were able to
	 * enter "promiscuous" mode, we should be able to turn it off.
	 * Note, this field stores a pointer used to support both
	 * promiscuous and non-promiscuous callbacks for packets.
	 */
	mph = d->bd_promisc_handle;
	d->bd_promisc_handle = 0;

	/*
	 * The lock has to be dropped here because mac_promisc_remove may
	 * need to wait for mac_promisc_dispatch, which has called into
	 * bpf and catchpacket is waiting for bd_lock...
	 * i.e mac_promisc_remove() needs to be called with none of the
	 * locks held that are part of the bpf_mtap() call path.
	 */
	mutex_exit(&d->bd_lock);
	if (mph != 0)
		MBPF_PROMISC_REMOVE(&bp->bif_mac, mph);

	if (mch != 0)
		MBPF_CLIENT_CLOSE(&bp->bif_mac, mch);

	/*
	 * bd_lock needs to stay not held by this function until after
	 * it has finished with bif_lock, otherwise there's a lock order
	 * reversal with bpf_deliver and the system can deadlock.
	 *
	 * Remove d from the interface's descriptor list.
	 */
	mutex_enter(&bp->bif_lock);
	LIST_REMOVE(d, bd_next);
	mutex_exit(&bp->bif_lock);

	/*
	 * Because this function is called with bd_lock held, so it must
	 * exit with it held.
	 */
	mutex_enter(&d->bd_lock);
	/*
	 * bd_bif cannot be cleared until after the promisc callback has been
	 * removed.
	 */
	d->bd_bif = 0;
}


/*
 * bpfilterattach() is called at load time.
 */
int
bpfilterattach(void)
{

	bpf_hash = mod_hash_create_idhash("bpf_dev_tab", 31,
	    mod_hash_null_keydtor);
	if (bpf_hash == NULL)
		return (ENOMEM);

	(void) memcpy(&ks_stats, &bpf_kstats, sizeof (bpf_kstats));

	bpf_ksp = kstat_create("bpf", 0, "global", "misc",
	    KSTAT_TYPE_NAMED, sizeof (bpf_kstats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (bpf_ksp != NULL) {
		bpf_ksp->ks_data = &ks_stats;
		kstat_install(bpf_ksp);
	} else {
		mod_hash_destroy_idhash(bpf_hash);
		bpf_hash = NULL;
		return (EEXIST);
	}

	cv_init(&bpf_dlt_waiter, NULL, CV_DRIVER, NULL);
	mutex_init(&bpf_mtx, NULL, MUTEX_DRIVER, NULL);

	LIST_INIT(&bpf_list);
	TAILQ_INIT(&bpf_iflist);

	return (0);
}


/*
 * bpfilterdetach() is called at unload time.
 */
int
bpfilterdetach(void)
{
	struct bpf_if *bp;

	if (bpf_ksp != NULL) {
		kstat_delete(bpf_ksp);
		bpf_ksp = NULL;
	}

	/*
	 * When no attach/detach callbacks can arrive from mac,
	 * this is now safe without a lock.
	 */
	while ((bp = TAILQ_FIRST(&bpf_iflist)) != NULL)
		bpfdetach(bp->bif_ifp);

	mutex_enter(&bpf_mtx);
	if (!LIST_EMPTY(&bpf_list)) {
		mutex_exit(&bpf_mtx);
		return (EBUSY);
	}
	mutex_exit(&bpf_mtx);

	mod_hash_destroy_idhash(bpf_hash);
	bpf_hash = NULL;

	cv_destroy(&bpf_dlt_waiter);
	mutex_destroy(&bpf_mtx);

	return (0);
}

/*
 * Open ethernet device. Clones.
 */
/* ARGSUSED */
int
bpfopen(dev_t *devp, int flag, int mode, cred_t *cred)
{
	struct bpf_d *d;
	uint_t dmin;

	/*
	 * The security policy described at the top of this file is
	 * enforced here.
	 */
	if ((flag & FWRITE) != 0) {
		if (secpolicy_net_rawaccess(cred) != 0)
			return (EACCES);
	}

	if ((flag & FREAD) != 0) {
		if ((secpolicy_net_observability(cred) != 0) &&
		    (secpolicy_net_rawaccess(cred) != 0))
			return (EACCES);
	}

	if ((flag & (FWRITE|FREAD)) == 0)
		return (ENXIO);

	/*
	 * If BPF is being opened from a non-global zone, trigger a call
	 * back into the driver to see if it needs to initialise local
	 * state in a zone.
	 */
	if (crgetzoneid(cred) != GLOBAL_ZONEID)
		bpf_open_zone(crgetzoneid(cred));

	/*
	 * A structure is allocated per open file in BPF to store settings
	 * such as buffer capture size, provide private buffers, etc.
	 */
	d = (struct bpf_d *)kmem_zalloc(sizeof (*d), KM_SLEEP);
	d->bd_bufsize = bpf_bufsize;
	d->bd_fmode = flag;
	d->bd_zone = crgetzoneid(cred);
	d->bd_seesent = 1;
	d->bd_promisc_flags = MAC_PROMISC_FLAGS_NO_PHYS|
	    MAC_PROMISC_FLAGS_NO_COPY;
	mutex_init(&d->bd_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&d->bd_wait, NULL, CV_DRIVER, NULL);

	mutex_enter(&bpf_mtx);
	/*
	 * Find an unused minor number. Obviously this is an O(n) algorithm
	 * and doesn't scale particularly well, so if there are large numbers
	 * of open file descriptors happening in real use, this design may
	 * need to be revisited.
	 */
	for (dmin = 0; dmin < L_MAXMIN; dmin++)
		if (bpf_dev_find(dmin) == NULL)
			break;
	if (dmin == L_MAXMIN) {
		mutex_exit(&bpf_mtx);
		kmem_free(d, sizeof (*d));
		return (ENXIO);
	}
	d->bd_dev = dmin;
	LIST_INSERT_HEAD(&bpf_list, d, bd_list);
	bpf_dev_add(d);
	mutex_exit(&bpf_mtx);

	*devp = makedevice(getmajor(*devp), dmin);

	return (0);
}

/*
 * Close the descriptor by detaching it from its interface,
 * deallocating its buffers, and marking it free.
 *
 * Because we only allow a device to be opened once, there is always a
 * 1 to 1 relationship between opens and closes supporting this function.
 */
/* ARGSUSED */
int
bpfclose(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	struct bpf_d *d = bpf_dev_get(getminor(dev));

	mutex_enter(&d->bd_lock);
	if (d->bd_state == BPF_WAITING)
		bpf_clear_timeout(d);
	d->bd_state = BPF_IDLE;
	if (d->bd_bif)
		bpf_detachd(d);
	mutex_exit(&d->bd_lock);

	mutex_enter(&bpf_mtx);
	LIST_REMOVE(d, bd_list);
	bpf_dev_remove(d);
	mutex_exit(&bpf_mtx);

	mutex_enter(&d->bd_lock);
	mutex_destroy(&d->bd_lock);
	cv_destroy(&d->bd_wait);

	bpf_freed(d);
	kmem_free(d, sizeof (*d));

	return (0);
}

/*
 * Rotate the packet buffers in descriptor d.  Move the store buffer
 * into the hold slot, and the free buffer into the store slot.
 * Zero the length of the new store buffer.
 */
#define	ROTATE_BUFFERS(d) \
	(d)->bd_hbuf = (d)->bd_sbuf; \
	(d)->bd_hlen = (d)->bd_slen; \
	(d)->bd_sbuf = (d)->bd_fbuf; \
	(d)->bd_slen = 0; \
	(d)->bd_fbuf = 0;
/*
 *  bpfread - read next chunk of packets from buffers
 */
/* ARGSUSED */
int
bpfread(dev_t dev, struct uio *uio, cred_t *cred)
{
	struct bpf_d *d = bpf_dev_get(getminor(dev));
	int timed_out;
	ulong_t delay;
	int error;

	if ((d->bd_fmode & FREAD) == 0)
		return (EBADF);

	/*
	 * Restrict application to use a buffer the same size as
	 * the kernel buffers.
	 */
	if (uio->uio_resid != d->bd_bufsize)
		return (EINVAL);

	mutex_enter(&d->bd_lock);
	if (d->bd_state == BPF_WAITING)
		bpf_clear_timeout(d);
	timed_out = (d->bd_state == BPF_TIMED_OUT);
	d->bd_state = BPF_IDLE;
	/*
	 * If the hold buffer is empty, then do a timed sleep, which
	 * ends when the timeout expires or when enough packets
	 * have arrived to fill the store buffer.
	 */
	while (d->bd_hbuf == 0) {
		if (d->bd_nonblock) {
			if (d->bd_slen == 0) {
				mutex_exit(&d->bd_lock);
				return (EWOULDBLOCK);
			}
			ROTATE_BUFFERS(d);
			break;
		}

		if ((d->bd_immediate || timed_out) && d->bd_slen != 0) {
			/*
			 * A packet(s) either arrived since the previous
			 * read or arrived while we were asleep.
			 * Rotate the buffers and return what's here.
			 */
			ROTATE_BUFFERS(d);
			break;
		}
		ks_stats.kp_read_wait.value.ui64++;
		delay = ddi_get_lbolt() + d->bd_rtout;
		error = cv_timedwait_sig(&d->bd_wait, &d->bd_lock, delay);
		if (error == 0) {
			mutex_exit(&d->bd_lock);
			return (EINTR);
		}
		if (error == -1) {
			/*
			 * On a timeout, return what's in the buffer,
			 * which may be nothing.  If there is something
			 * in the store buffer, we can rotate the buffers.
			 */
			if (d->bd_hbuf)
				/*
				 * We filled up the buffer in between
				 * getting the timeout and arriving
				 * here, so we don't need to rotate.
				 */
				break;

			if (d->bd_slen == 0) {
				mutex_exit(&d->bd_lock);
				return (0);
			}
			ROTATE_BUFFERS(d);
		}
	}
	/*
	 * At this point, we know we have something in the hold slot.
	 */
	mutex_exit(&d->bd_lock);

	/*
	 * Move data from hold buffer into user space.
	 * We know the entire buffer is transferred since
	 * we checked above that the read buffer is bpf_bufsize bytes.
	 */
	error = uiomove(d->bd_hbuf, d->bd_hlen, UIO_READ, uio);

	mutex_enter(&d->bd_lock);
	d->bd_fbuf = d->bd_hbuf;
	d->bd_hbuf = 0;
	d->bd_hlen = 0;
done:
	mutex_exit(&d->bd_lock);
	return (error);
}


/*
 * If there are processes sleeping on this descriptor, wake them up.
 * NOTE: the lock for bd_wait is bd_lock and is held by bpf_deliver,
 * so there is no code here grabbing it.
 */
static inline void
bpf_wakeup(struct bpf_d *d)
{
	cv_signal(&d->bd_wait);
}

static void
bpf_timed_out(void *arg)
{
	struct bpf_d *d = arg;

	mutex_enter(&d->bd_lock);
	if (d->bd_state == BPF_WAITING) {
		d->bd_state = BPF_TIMED_OUT;
		if (d->bd_slen != 0)
			cv_signal(&d->bd_wait);
	}
	mutex_exit(&d->bd_lock);
}


/* ARGSUSED */
int
bpfwrite(dev_t dev, struct uio *uio, cred_t *cred)
{
	struct bpf_d *d = bpf_dev_get(getminor(dev));
	struct bpf_if *bp;
	uintptr_t mch;
	uintptr_t ifp;
	uint_t mtu;
	mblk_t *m;
	int error;
	int dlt;

	if ((d->bd_fmode & FWRITE) == 0)
		return (EBADF);

	mutex_enter(&d->bd_lock);
	if (d->bd_bif == 0 || d->bd_mcip == 0 || d->bd_bif->bif_ifp == 0) {
		mutex_exit(&d->bd_lock);
		return (EINTR);
	}

	if (uio->uio_resid == 0) {
		mutex_exit(&d->bd_lock);
		return (0);
	}

	while (d->bd_inuse < 0) {
		d->bd_waiting++;
		if (cv_wait_sig(&d->bd_wait, &d->bd_lock) <= 0) {
			d->bd_waiting--;
			mutex_exit(&d->bd_lock);
			return (EINTR);
		}
		d->bd_waiting--;
	}

	mutex_exit(&d->bd_lock);

	bp = d->bd_bif;
	dlt = bp->bif_dlt;
	mch = d->bd_mcip;
	ifp = bp->bif_ifp;
	MBPF_SDU_GET(&bp->bif_mac, ifp, &mtu);
	d->bd_inuse++;

	m = NULL;
	if (dlt == DLT_IPNET) {
		error = EIO;
		goto done;
	}

	error = bpf_movein(uio, dlt, mtu, &m);
	if (error)
		goto done;

	DTRACE_PROBE5(bpf__tx, struct bpf_d *, d, struct bpf_if *, bp,
	    int, dlt, uint_t, mtu, mblk_t *, m);

	if (M_LEN(m) > mtu) {
		error = EMSGSIZE;
		goto done;
	}

	error = MBPF_TX(&bp->bif_mac, mch, m);
	/*
	 * The "tx" action here is required to consume the mblk_t.
	 */
	m = NULL;

done:
	if (error == 0)
		ks_stats.kp_write_ok.value.ui64++;
	else
		ks_stats.kp_write_error.value.ui64++;
	if (m != NULL)
		freemsg(m);

	mutex_enter(&d->bd_lock);
	d->bd_inuse--;
	if ((d->bd_inuse == 0) && (d->bd_waiting != 0))
		cv_signal(&d->bd_wait);
	mutex_exit(&d->bd_lock);

	/*
	 * The driver frees the mbuf.
	 */
	return (error);
}


/*
 * Reset a descriptor by flushing its packet buffer and clearing the
 * receive and drop counts.  Should be called at splnet.
 */
static void
reset_d(struct bpf_d *d)
{
	if (d->bd_hbuf) {
		/* Free the hold buffer. */
		d->bd_fbuf = d->bd_hbuf;
		d->bd_hbuf = 0;
	}
	d->bd_slen = 0;
	d->bd_hlen = 0;
	d->bd_rcount = 0;
	d->bd_dcount = 0;
	d->bd_ccount = 0;
}

/*
 *  FIONREAD		Check for read packet available.
 *  BIOCGBLEN		Get buffer len [for read()].
 *  BIOCSETF		Set ethernet read filter.
 *  BIOCFLUSH		Flush read packet buffer.
 *  BIOCPROMISC		Put interface into promiscuous mode.
 *  BIOCGDLT		Get link layer type.
 *  BIOCGETIF		Get interface name.
 *  BIOCSETIF		Set interface.
 *  BIOCSRTIMEOUT	Set read timeout.
 *  BIOCGRTIMEOUT	Get read timeout.
 *  BIOCGSTATS		Get packet stats.
 *  BIOCIMMEDIATE	Set immediate mode.
 *  BIOCVERSION		Get filter language version.
 *  BIOCGHDRCMPLT	Get "header already complete" flag.
 *  BIOCSHDRCMPLT	Set "header already complete" flag.
 */
/* ARGSUSED */
int
bpfioctl(dev_t dev, int cmd, intptr_t addr, int mode, cred_t *cred, int *rval)
{
	struct bpf_d *d = bpf_dev_get(getminor(dev));
	struct bpf_program prog;
	struct lifreq lifreq;
	struct ifreq ifreq;
	int error = 0;
	uint_t size;

	/*
	 * Refresh the PID associated with this bpf file.
	 */
	mutex_enter(&d->bd_lock);
	if (d->bd_state == BPF_WAITING)
		bpf_clear_timeout(d);
	d->bd_state = BPF_IDLE;
	mutex_exit(&d->bd_lock);

	switch (cmd) {

	default:
		error = EINVAL;
		break;

	/*
	 * Check for read packet available.
	 */
	case FIONREAD:
		{
			int n;

			mutex_enter(&d->bd_lock);
			n = d->bd_slen;
			if (d->bd_hbuf)
				n += d->bd_hlen;
			mutex_exit(&d->bd_lock);

			*(int *)addr = n;
			break;
		}

	/*
	 * Get buffer len [for read()].
	 */
	case BIOCGBLEN:
		error = copyout(&d->bd_bufsize, (void *)addr,
		    sizeof (d->bd_bufsize));
		break;

	/*
	 * Set buffer length.
	 */
	case BIOCSBLEN:
		if (copyin((void *)addr, &size, sizeof (size)) != 0) {
			error = EFAULT;
			break;
		}

		mutex_enter(&d->bd_lock);
		if (d->bd_bif != 0) {
			error = EINVAL;
		} else {
			if (size > bpf_maxbufsize)
				size = bpf_maxbufsize;
			else if (size < BPF_MINBUFSIZE)
				size = BPF_MINBUFSIZE;

			d->bd_bufsize = size;
		}
		mutex_exit(&d->bd_lock);

		if (error == 0)
			error = copyout(&size, (void *)addr, sizeof (size));
		break;

	/*
	 * Set link layer read filter.
	 */
	case BIOCSETF:
		if (ddi_copyin((void *)addr, &prog, sizeof (prog), mode)) {
			error = EFAULT;
			break;
		}
		error = bpf_setf(d, &prog);
		break;

	/*
	 * Flush read packet buffer.
	 */
	case BIOCFLUSH:
		mutex_enter(&d->bd_lock);
		reset_d(d);
		mutex_exit(&d->bd_lock);
		break;

	/*
	 * Put interface into promiscuous mode.
	 * This is a one-way ioctl, it is not used to turn promiscuous
	 * mode off.
	 */
	case BIOCPROMISC:
		if (d->bd_bif == 0) {
			/*
			 * No interface attached yet.
			 */
			error = EINVAL;
			break;
		}
		mutex_enter(&d->bd_lock);
		if (d->bd_promisc == 0) {

			if (d->bd_promisc_handle) {
				uintptr_t mph;

				mph = d->bd_promisc_handle;
				d->bd_promisc_handle = 0;

				mutex_exit(&d->bd_lock);
				MBPF_PROMISC_REMOVE(&d->bd_bif->bif_mac, mph);
				mutex_enter(&d->bd_lock);
			}

			d->bd_promisc_flags = MAC_PROMISC_FLAGS_NO_COPY;
			error = MBPF_PROMISC_ADD(&d->bd_bif->bif_mac,
			    d->bd_mcip, MAC_CLIENT_PROMISC_ALL, d,
			    &d->bd_promisc_handle, d->bd_promisc_flags);
			if (error == 0)
				d->bd_promisc = 1;
		}
		mutex_exit(&d->bd_lock);
		break;

	/*
	 * Get device parameters.
	 */
	case BIOCGDLT:
		if (d->bd_bif == 0)
			error = EINVAL;
		else
			error = copyout(&d->bd_bif->bif_dlt, (void *)addr,
			    sizeof (d->bd_bif->bif_dlt));
		break;

	/*
	 * Get a list of supported device parameters.
	 */
	case BIOCGDLTLIST:
		if (d->bd_bif == 0) {
			error = EINVAL;
		} else {
			struct bpf_dltlist list;

			if (copyin((void *)addr, &list, sizeof (list)) != 0) {
				error = EFAULT;
				break;
			}
			error = bpf_getdltlist(d, &list);
			if ((error == 0) &&
			    copyout(&list, (void *)addr, sizeof (list)) != 0)
				error = EFAULT;
		}
		break;

	/*
	 * Set device parameters.
	 */
	case BIOCSDLT:
		error = bpf_setdlt(d, (void *)addr);
		break;

	/*
	 * Get interface name.
	 */
	case BIOCGETIF:
		if (copyin((void *)addr, &ifreq, sizeof (ifreq)) != 0) {
			error = EFAULT;
			break;
		}
		error = bpf_ifname(d, ifreq.ifr_name, sizeof (ifreq.ifr_name));
		if ((error == 0) &&
		    copyout(&ifreq, (void *)addr, sizeof (ifreq)) != 0) {
			error = EFAULT;
			break;
		}
		break;

	/*
	 * Set interface.
	 */
	case BIOCSETIF:
		if (copyin((void *)addr, &ifreq, sizeof (ifreq)) != 0) {
			error = EFAULT;
			break;
		}
		error = bpf_setif(d, ifreq.ifr_name, sizeof (ifreq.ifr_name));
		break;

	/*
	 * Get interface name.
	 */
	case BIOCGETLIF:
		if (copyin((void *)addr, &lifreq, sizeof (lifreq)) != 0) {
			error = EFAULT;
			break;
		}
		error = bpf_ifname(d, lifreq.lifr_name,
		    sizeof (lifreq.lifr_name));
		if ((error == 0) &&
		    copyout(&lifreq, (void *)addr, sizeof (lifreq)) != 0) {
			error = EFAULT;
			break;
		}
		break;

	/*
	 * Set interface.
	 */
	case BIOCSETLIF:
		if (copyin((void *)addr, &lifreq, sizeof (lifreq)) != 0) {
			error = EFAULT;
			break;
		}
		error = bpf_setif(d, lifreq.lifr_name,
		    sizeof (lifreq.lifr_name));
		break;

#ifdef _SYSCALL32_IMPL
	/*
	 * Set read timeout.
	 */
	case BIOCSRTIMEOUT32:
		{
			struct timeval32 tv;

			if (copyin((void *)addr, &tv, sizeof (tv)) != 0) {
				error = EFAULT;
				break;
			}

			/* Convert the timeout in microseconds to ticks */
			d->bd_rtout = drv_usectohz(tv.tv_sec * 1000000 +
			    tv.tv_usec);
			if ((d->bd_rtout == 0) && (tv.tv_usec != 0))
				d->bd_rtout = 1;
			break;
		}

	/*
	 * Get read timeout.
	 */
	case BIOCGRTIMEOUT32:
		{
			struct timeval32 tv;
			clock_t ticks;

			ticks = drv_hztousec(d->bd_rtout);
			tv.tv_sec = ticks / 1000000;
			tv.tv_usec = ticks - (tv.tv_sec * 1000000);
			error = copyout(&tv, (void *)addr, sizeof (tv));
			break;
		}

	/*
	 * Get a list of supported device parameters.
	 */
	case BIOCGDLTLIST32:
		if (d->bd_bif == 0) {
			error = EINVAL;
		} else {
			struct bpf_dltlist32 lst32;
			struct bpf_dltlist list;

			if (copyin((void *)addr, &lst32, sizeof (lst32)) != 0) {
				error = EFAULT;
				break;
			}

			list.bfl_len = lst32.bfl_len;
			list.bfl_list = (void *)(uint64_t)lst32.bfl_list;
			error = bpf_getdltlist(d, &list);
			if (error == 0) {
				lst32.bfl_len = list.bfl_len;

				if (copyout(&lst32, (void *)addr,
				    sizeof (lst32)) != 0)
					error = EFAULT;
			}
		}
		break;

	/*
	 * Set link layer read filter.
	 */
	case BIOCSETF32: {
		struct bpf_program32 prog32;

		if (ddi_copyin((void *)addr, &prog32, sizeof (prog), mode)) {
			error = EFAULT;
			break;
		}
		prog.bf_len = prog32.bf_len;
		prog.bf_insns = (void *)(uint64_t)prog32.bf_insns;
		error = bpf_setf(d, &prog);
		break;
	}
#endif

	/*
	 * Set read timeout.
	 */
	case BIOCSRTIMEOUT:
		{
			struct timeval tv;

			if (copyin((void *)addr, &tv, sizeof (tv)) != 0) {
				error = EFAULT;
				break;
			}

			/* Convert the timeout in microseconds to ticks */
			d->bd_rtout = drv_usectohz(tv.tv_sec * 1000000 +
			    tv.tv_usec);
			if ((d->bd_rtout == 0) && (tv.tv_usec != 0))
				d->bd_rtout = 1;
			break;
		}

	/*
	 * Get read timeout.
	 */
	case BIOCGRTIMEOUT:
		{
			struct timeval tv;
			clock_t ticks;

			ticks = drv_hztousec(d->bd_rtout);
			tv.tv_sec = ticks / 1000000;
			tv.tv_usec = ticks - (tv.tv_sec * 1000000);
			if (copyout(&tv, (void *)addr, sizeof (tv)) != 0)
				error = EFAULT;
			break;
		}

	/*
	 * Get packet stats.
	 */
	case BIOCGSTATS:
		{
			struct bpf_stat bs;

			bs.bs_recv = d->bd_rcount;
			bs.bs_drop = d->bd_dcount;
			bs.bs_capt = d->bd_ccount;
			if (copyout(&bs, (void *)addr, sizeof (bs)) != 0)
				error = EFAULT;
			break;
		}

	/*
	 * Set immediate mode.
	 */
	case BIOCIMMEDIATE:
		if (copyin((void *)addr, &d->bd_immediate,
		    sizeof (d->bd_immediate)) != 0)
			error = EFAULT;
		break;

	case BIOCVERSION:
		{
			struct bpf_version bv;

			bv.bv_major = BPF_MAJOR_VERSION;
			bv.bv_minor = BPF_MINOR_VERSION;
			if (copyout(&bv, (void *)addr, sizeof (bv)) != 0)
				error = EFAULT;
			break;
		}

	case BIOCGHDRCMPLT:	/* get "header already complete" flag */
		if (copyout(&d->bd_hdrcmplt, (void *)addr,
		    sizeof (d->bd_hdrcmplt)) != 0)
			error = EFAULT;
		break;

	case BIOCSHDRCMPLT:	/* set "header already complete" flag */
		if (copyin((void *)addr, &d->bd_hdrcmplt,
		    sizeof (d->bd_hdrcmplt)) != 0)
			error = EFAULT;
		break;

	/*
	 * Get "see sent packets" flag
	 */
	case BIOCGSEESENT:
		if (copyout(&d->bd_seesent, (void *)addr,
		    sizeof (d->bd_seesent)) != 0)
			error = EFAULT;
		break;

	/*
	 * Set "see sent" packets flag
	 */
	case BIOCSSEESENT:
		if (copyin((void *)addr, &d->bd_seesent,
		    sizeof (d->bd_seesent)) != 0)
			error = EFAULT;
		break;

	case FIONBIO:		/* Non-blocking I/O */
		if (copyin((void *)addr, &d->bd_nonblock,
		    sizeof (d->bd_nonblock)) != 0)
			error = EFAULT;
		break;
	}
	return (error);
}

/*
 * Set d's packet filter program to fp.  If this file already has a filter,
 * free it and replace it. If the new filter is "empty" (has a 0 size), then
 * the result is to just remove and free the existing filter.
 * Returns EINVAL for bogus requests.
 */
int
bpf_setf(struct bpf_d *d, struct bpf_program *fp)
{
	struct bpf_insn *fcode, *old;
	uint_t flen, size;
	size_t oldsize;

	if (fp->bf_insns == 0) {
		if (fp->bf_len != 0)
			return (EINVAL);
		mutex_enter(&d->bd_lock);
		old = d->bd_filter;
		oldsize = d->bd_filter_size;
		d->bd_filter = 0;
		d->bd_filter_size = 0;
		reset_d(d);
		mutex_exit(&d->bd_lock);
		if (old != 0)
			kmem_free(old, oldsize);
		return (0);
	}
	flen = fp->bf_len;
	if (flen > BPF_MAXINSNS)
		return (EINVAL);

	size = flen * sizeof (*fp->bf_insns);
	fcode = kmem_alloc(size, KM_SLEEP);
	if (copyin(fp->bf_insns, fcode, size) != 0)
		return (EFAULT);

	if (bpf_validate(fcode, (int)flen)) {
		mutex_enter(&d->bd_lock);
		old = d->bd_filter;
		oldsize = d->bd_filter_size;
		d->bd_filter = fcode;
		d->bd_filter_size = size;
		reset_d(d);
		mutex_exit(&d->bd_lock);
		if (old != 0)
			kmem_free(old, oldsize);

		return (0);
	}
	kmem_free(fcode, size);
	return (EINVAL);
}

/*
 * Detach a file from its current interface (if attached at all) and attach
 * to the interface indicated by the name stored in ifr.
 * Return an errno or 0.
 */
static int
bpf_setif(struct bpf_d *d, char *ifname, int namesize)
{
	struct bpf_if *bp;
	int unit_seen;
	char *cp;
	int i;

	/*
	 * Make sure the provided name has a unit number, and default
	 * it to '0' if not specified.
	 * XXX This is ugly ... do this differently?
	 */
	unit_seen = 0;
	cp = ifname;
	cp[namesize - 1] = '\0';	/* sanity */
	while (*cp++)
		if (*cp >= '0' && *cp <= '9')
			unit_seen = 1;
	if (!unit_seen) {
		/* Make sure to leave room for the '\0'. */
		for (i = 0; i < (namesize - 1); ++i) {
			if ((ifname[i] >= 'a' && ifname[i] <= 'z') ||
			    (ifname[i] >= 'A' && ifname[i] <= 'Z'))
				continue;
			ifname[i] = '0';
		}
	}

	/*
	 * Make sure that only one call to this function happens at a time
	 * and that we're not interleaving a read/write
	 */
	mutex_enter(&d->bd_lock);
	while (d->bd_inuse != 0) {
		d->bd_waiting++;
		if (cv_wait_sig(&d->bd_wait, &d->bd_lock) <= 0) {
			d->bd_waiting--;
			mutex_exit(&d->bd_lock);
			return (EINTR);
		}
		d->bd_waiting--;
	}
	d->bd_inuse = -1;
	mutex_exit(&d->bd_lock);

	/*
	 * Look through attached interfaces for the named one.
	 *
	 * The search is done twice - once
	 */
	mutex_enter(&bpf_mtx);

	bp = bpf_findif(d, ifname, -1);

	if (bp != NULL) {
		int error = 0;

		if (d->bd_sbuf == 0)
			error = bpf_allocbufs(d);

		/*
		 * We found the requested interface.
		 * If we're already attached to requested interface,
		 * just flush the buffer.
		 */
		mutex_enter(&d->bd_lock);
		if (error == 0 && bp != d->bd_bif) {
			if (d->bd_bif)
				/*
				 * Detach if attached to something else.
				 */
				bpf_detachd(d);

			bpf_attachd(d, bp);
		}
		reset_d(d);
		d->bd_inuse = 0;
		if (d->bd_waiting != 0)
			cv_signal(&d->bd_wait);
		mutex_exit(&d->bd_lock);
		mutex_exit(&bpf_mtx);
		return (error);
	}

	mutex_enter(&d->bd_lock);
	d->bd_inuse = 0;
	if (d->bd_waiting != 0)
		cv_signal(&d->bd_wait);
	mutex_exit(&d->bd_lock);
	mutex_exit(&bpf_mtx);

	/*
	 * Try tickle the mac layer into attaching the device...
	 */
	return (bpf_provider_tickle(ifname, d->bd_zone));
}

/*
 * Copy the interface name to the ifreq.
 */
static int
bpf_ifname(struct bpf_d *d, char *buffer, int bufsize)
{
	struct bpf_if *bp;

	mutex_enter(&d->bd_lock);
	bp = d->bd_bif;
	if (bp == NULL) {
		mutex_exit(&d->bd_lock);
		return (EINVAL);
	}

	(void) strlcpy(buffer, bp->bif_ifname, bufsize);
	mutex_exit(&d->bd_lock);

	return (0);
}

/*
 * Support for poll() system call
 *
 * Return true iff the specific operation will not block indefinitely - with
 * the assumption that it is safe to positively acknowledge a request for the
 * ability to write to the BPF device.
 * Otherwise, return false but make a note that a selnotify() must be done.
 */
int
bpfchpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	struct bpf_d *d = bpf_dev_get(getminor(dev));

	if (events & (POLLIN | POLLRDNORM)) {
		/*
		 * An imitation of the FIONREAD ioctl code.
		 */
		mutex_enter(&d->bd_lock);
		if (d->bd_hlen != 0 ||
		    ((d->bd_immediate || d->bd_state == BPF_TIMED_OUT) &&
		    d->bd_slen != 0)) {
			*reventsp |= events & (POLLIN | POLLRDNORM);
		} else {
			*reventsp = 0;
			if (!anyyet)
				*phpp = &d->bd_poll;
			/* Start the read timeout if necessary */
			if (d->bd_rtout > 0 && d->bd_state == BPF_IDLE) {
				bpf_clear_timeout(d);
				/*
				 * Only allow the timeout to be set once.
				 */
				if (d->bd_callout == 0)
					d->bd_callout = timeout(bpf_timed_out,
					    d, d->bd_rtout);
				d->bd_state = BPF_WAITING;
			}
		}
		mutex_exit(&d->bd_lock);
	}

	return (0);
}

/*
 * Copy data from an mblk_t chain into a buffer. This works for ipnet
 * because the dl_ipnetinfo_t is placed in an mblk_t that leads the
 * packet itself.
 */
static void *
bpf_mcpy(void *dst_arg, const void *src_arg, size_t len)
{
	const mblk_t *m;
	uint_t count;
	uchar_t *dst;

	m = src_arg;
	dst = dst_arg;
	while (len > 0) {
		if (m == NULL)
			panic("bpf_mcpy");
		count = (uint_t)min(M_LEN(m), len);
		(void) memcpy(dst, mtod(m, const void *), count);
		m = m->b_cont;
		dst += count;
		len -= count;
	}
	return (dst_arg);
}

/*
 * Dispatch a packet to all the listeners on interface bp.
 *
 * marg    pointer to the packet, either a data buffer or an mbuf chain
 * buflen  buffer length, if marg is a data buffer
 * cpfn    a function that can copy marg into the listener's buffer
 * pktlen  length of the packet
 * issent  boolean indicating whether the packet was sent or receive
 */
static inline void
bpf_deliver(struct bpf_d *d, cp_fn_t cpfn, void *marg, uint_t pktlen,
    uint_t buflen, boolean_t issent)
{
	struct timeval tv;
	uint_t slen;

	if (!d->bd_seesent && issent)
		return;

	/*
	 * Accuracy of the packet counters in BPF is vital so it
	 * is important to protect even the outer ones.
	 */
	mutex_enter(&d->bd_lock);
	slen = bpf_filter(d->bd_filter, marg, pktlen, buflen);
	DTRACE_PROBE5(bpf__packet, struct bpf_if *, d->bd_bif,
	    struct bpf_d *, d, void *, marg, uint_t, pktlen, uint_t, slen);
	d->bd_rcount++;
	ks_stats.kp_receive.value.ui64++;
	if (slen != 0) {
		uniqtime(&tv);
		catchpacket(d, marg, pktlen, slen, cpfn, &tv);
	}
	mutex_exit(&d->bd_lock);
}

/*
 * Incoming linkage from device drivers.
 */
/* ARGSUSED */
void
bpf_mtap(void *arg, mac_resource_handle_t mrh, mblk_t *m, boolean_t issent)
{
	cp_fn_t cpfn;
	struct bpf_d *d = arg;
	uint_t pktlen, buflen;
	void *marg;

	pktlen = msgdsize(m);

	if (pktlen == M_LEN(m)) {
		cpfn = (cp_fn_t)memcpy;
		marg = mtod(m, void *);
		buflen = pktlen;
	} else {
		cpfn = bpf_mcpy;
		marg = m;
		buflen = 0;
	}

	bpf_deliver(d, cpfn, marg, pktlen, buflen, issent);
}

/*
 * Incoming linkage from ipnet.
 * In ipnet, there is only one event, NH_OBSERVE, that delivers packets
 * from all network interfaces. Thus the tap function needs to apply a
 * filter using the interface index/id to immitate snoop'ing on just the
 * specified interface.
 */
/* ARGSUSED */
void
bpf_itap(void *arg, mblk_t *m, boolean_t issent, uint_t length)
{
	hook_pkt_observe_t *hdr;
	struct bpf_d *d = arg;

	hdr = (hook_pkt_observe_t *)m->b_rptr;
	if (ntohl(hdr->hpo_ifindex) != d->bd_bif->bif_linkid)
		return;
	bpf_deliver(d, bpf_mcpy, m, length, 0, issent);

}

/*
 * Move the packet data from interface memory (pkt) into the
 * store buffer.  Return 1 if it's time to wakeup a listener (buffer full),
 * otherwise 0.  "copy" is the routine called to do the actual data
 * transfer.  memcpy is passed in to copy contiguous chunks, while
 * bpf_mcpy is passed in to copy mbuf chains.  In the latter case,
 * pkt is really an mbuf.
 */
static void
catchpacket(struct bpf_d *d, uchar_t *pkt, uint_t pktlen, uint_t snaplen,
    cp_fn_t cpfn, struct timeval *tv)
{
	struct bpf_hdr *hp;
	int totlen, curlen;
	int hdrlen = d->bd_bif->bif_hdrlen;
	int do_wakeup = 0;

	++d->bd_ccount;
	ks_stats.kp_capture.value.ui64++;
	/*
	 * Figure out how many bytes to move.  If the packet is
	 * greater or equal to the snapshot length, transfer that
	 * much.  Otherwise, transfer the whole packet (unless
	 * we hit the buffer size limit).
	 */
	totlen = hdrlen + min(snaplen, pktlen);
	if (totlen > d->bd_bufsize)
		totlen = d->bd_bufsize;

	/*
	 * Round up the end of the previous packet to the next longword.
	 */
	curlen = BPF_WORDALIGN(d->bd_slen);
	if (curlen + totlen > d->bd_bufsize) {
		/*
		 * This packet will overflow the storage buffer.
		 * Rotate the buffers if we can, then wakeup any
		 * pending reads.
		 */
		if (d->bd_fbuf == 0) {
			/*
			 * We haven't completed the previous read yet,
			 * so drop the packet.
			 */
			++d->bd_dcount;
			ks_stats.kp_dropped.value.ui64++;
			return;
		}
		ROTATE_BUFFERS(d);
		do_wakeup = 1;
		curlen = 0;
	} else if (d->bd_immediate || d->bd_state == BPF_TIMED_OUT) {
		/*
		 * Immediate mode is set, or the read timeout has
		 * already expired during a select call.  A packet
		 * arrived, so the reader should be woken up.
		 */
		do_wakeup = 1;
	}

	/*
	 * Append the bpf header to the existing buffer before we add
	 * on the actual packet data.
	 */
	hp = (struct bpf_hdr *)((char *)d->bd_sbuf + curlen);
	hp->bh_tstamp.tv_sec = tv->tv_sec;
	hp->bh_tstamp.tv_usec = tv->tv_usec;
	hp->bh_datalen = pktlen;
	hp->bh_hdrlen = (uint16_t)hdrlen;
	/*
	 * Copy the packet data into the store buffer and update its length.
	 */
	(*cpfn)((uchar_t *)hp + hdrlen, pkt,
	    (hp->bh_caplen = totlen - hdrlen));
	d->bd_slen = curlen + totlen;

	/*
	 * Call bpf_wakeup after bd_slen has been updated.
	 */
	if (do_wakeup)
		bpf_wakeup(d);
}

/*
 * Initialize all nonzero fields of a descriptor.
 */
static int
bpf_allocbufs(struct bpf_d *d)
{

	d->bd_fbuf = kmem_zalloc(d->bd_bufsize, KM_NOSLEEP);
	if (!d->bd_fbuf)
		return (ENOBUFS);
	d->bd_sbuf = kmem_zalloc(d->bd_bufsize, KM_NOSLEEP);
	if (!d->bd_sbuf) {
		kmem_free(d->bd_fbuf, d->bd_bufsize);
		return (ENOBUFS);
	}
	d->bd_slen = 0;
	d->bd_hlen = 0;
	return (0);
}

/*
 * Free buffers currently in use by a descriptor.
 * Called on close.
 */
static void
bpf_freed(struct bpf_d *d)
{
	/*
	 * At this point the descriptor has been detached from its
	 * interface and it yet hasn't been marked free.
	 */
	if (d->bd_sbuf != 0) {
		kmem_free(d->bd_sbuf, d->bd_bufsize);
		if (d->bd_hbuf != 0)
			kmem_free(d->bd_hbuf, d->bd_bufsize);
		if (d->bd_fbuf != 0)
			kmem_free(d->bd_fbuf, d->bd_bufsize);
	}
	if (d->bd_filter)
		kmem_free(d->bd_filter, d->bd_filter_size);
}

/*
 * Attach additional dlt for a interface to bpf.
 * dlt is the link layer type.
 *
 * The zoneid is passed in explicitly to prevent the need to
 * do a lookup in dls using the linkid. Such a lookup would need
 * to use the same hash table that gets used for walking when
 * dls_set_bpfattach() is called.
 */
void
bpfattach(uintptr_t ifp, int dlt, zoneid_t zoneid, int provider)
{
	bpf_provider_t *bpr;
	struct bpf_if *bp;
	uintptr_t client;
	int hdrlen;

	bpr = bpf_find_provider_by_id(provider);
	if (bpr == NULL) {
		if (bpf_debug)
			cmn_err(CE_WARN, "bpfattach: unknown provider %d",
			    provider);
		return;
	}

	bp = kmem_zalloc(sizeof (*bp), KM_NOSLEEP);
	if (bp == NULL) {
		if (bpf_debug)
			cmn_err(CE_WARN, "bpfattach: no memory for bpf_if");
		return;
	}
	bp->bif_mac = *bpr;

	/*
	 * To get the user-visible name, it is necessary to get the mac
	 * client name of an interface and for this, we need to do the
	 * mac_client_open. Leaving it open is undesirable because it
	 * creates an open reference that is hard to see from outside
	 * of bpf, potentially leading to data structures not being
	 * cleaned up when they should.
	 */
	if (MBPF_CLIENT_OPEN(&bp->bif_mac, ifp, &client) != 0) {
		if (bpf_debug)
			cmn_err(CE_WARN,
			    "bpfattach: mac_client_open fail for %s",
			    MBPF_NAME(&bp->bif_mac, ifp));
		kmem_free(bp, sizeof (*bp));
		return;
	}
	(void) strlcpy(bp->bif_ifname, MBPF_CLIENT_NAME(&bp->bif_mac, client),
	    sizeof (bp->bif_ifname));
	MBPF_CLIENT_CLOSE(&bp->bif_mac, client);

	bp->bif_ifp = ifp;
	bp->bif_dlt = bpf_dl_to_dlt(dlt);
	bp->bif_zoneid = zoneid;
	LIST_INIT(&bp->bif_dlist);

	/*
	 * Compute the length of the bpf header.  This is not necessarily
	 * equal to SIZEOF_BPF_HDR because we want to insert spacing such
	 * that the network layer header begins on a longword boundary (for
	 * performance reasons and to alleviate alignment restrictions).
	 */
	hdrlen = bpf_dl_hdrsize(dlt);
	bp->bif_hdrlen = BPF_WORDALIGN(hdrlen + SIZEOF_BPF_HDR) - hdrlen;

	if (MBPF_GET_LINKID(&bp->bif_mac, MBPF_NAME(&bp->bif_mac, ifp),
	    &bp->bif_linkid, zoneid) != 0) {
		if (bpf_debug) {
			cmn_err(CE_WARN,
			    "bpfattach: linkid resolution fail for %s/%s",
			    MBPF_NAME(&bp->bif_mac, ifp), bp->bif_ifname);
		}
		kmem_free(bp, sizeof (*bp));
		return;
	}
	mutex_init(&bp->bif_lock, NULL, MUTEX_DRIVER, NULL);

	bpf_debug_nic_action("attached to", bp);

	mutex_enter(&bpf_mtx);
	TAILQ_INSERT_TAIL(&bpf_iflist, bp, bif_next);
	mutex_exit(&bpf_mtx);
}

/*
 * Remove an interface from bpf.
 */
void
bpfdetach(uintptr_t ifp)
{
	struct bpf_if *bp;
	struct bpf_d *d;
	int removed = 0;

	mutex_enter(&bpf_mtx);
	/*
	 * Loop through all of the known descriptors to find any that are
	 * using the interface that wants to be detached.
	 */
	LIST_FOREACH(d, &bpf_list, bd_list) {
		mutex_enter(&d->bd_lock);
		bp = d->bd_bif;
		if (bp != NULL && bp->bif_ifp == ifp) {
			/*
			 * Detach the descriptor from an interface now.
			 * It will be free'ed later by close routine.
			 */
			bpf_detachd(d);
		}
		mutex_exit(&d->bd_lock);
	}

again:
	TAILQ_FOREACH(bp, &bpf_iflist, bif_next) {
		if (bp->bif_ifp == ifp) {
			TAILQ_REMOVE(&bpf_iflist, bp, bif_next);
			bpf_debug_nic_action("detached from", bp);
			while (bp->bif_inuse != 0)
				cv_wait(&bpf_dlt_waiter, &bpf_mtx);
			kmem_free(bp, sizeof (*bp));
			removed++;
			goto again;
		}
	}
	mutex_exit(&bpf_mtx);

	ASSERT(removed > 0);
}

/*
 * Get a list of available data link type of the interface.
 */
static int
bpf_getdltlist(struct bpf_d *d, struct bpf_dltlist *listp)
{
	char ifname[LIFNAMSIZ+1];
	struct bpf_if *bp;
	uintptr_t ifp;
	int n, error;

	mutex_enter(&bpf_mtx);
	ifp = d->bd_bif->bif_ifp;
	(void) strlcpy(ifname, MBPF_NAME(&d->bd_bif->bif_mac, ifp),
	    sizeof (ifname));
	n = 0;
	error = 0;
	TAILQ_FOREACH(bp, &bpf_iflist, bif_next) {
		if (strcmp(bp->bif_ifname, ifname) != 0)
			continue;
		if (d->bd_zone != GLOBAL_ZONEID &&
		    d->bd_zone != bp->bif_zoneid)
			continue;
		if (listp->bfl_list != NULL) {
			if (n >= listp->bfl_len)
				return (ENOMEM);
			/*
			 * Bumping of bif_inuse ensures the structure does not
			 * disappear while the copyout runs and allows the for
			 * loop to be continued.
			 */
			bp->bif_inuse++;
			mutex_exit(&bpf_mtx);
			if (copyout(&bp->bif_dlt,
			    listp->bfl_list + n, sizeof (uint_t)) != 0)
				error = EFAULT;
			mutex_enter(&bpf_mtx);
			bp->bif_inuse--;
		}
		n++;
	}
	cv_signal(&bpf_dlt_waiter);
	mutex_exit(&bpf_mtx);
	listp->bfl_len = n;
	return (error);
}

/*
 * Set the data link type of a BPF instance.
 */
static int
bpf_setdlt(struct bpf_d *d, void *addr)
{
	char ifname[LIFNAMSIZ+1];
	struct bpf_if *bp;
	int error;
	int dlt;

	if (copyin(addr, &dlt, sizeof (dlt)) != 0)
		return (EFAULT);
	/*
	 * The established order is get bpf_mtx before bd_lock, even
	 * though bpf_mtx is not needed until the loop...
	 */
	mutex_enter(&bpf_mtx);
	mutex_enter(&d->bd_lock);

	if (d->bd_bif == 0) {			/* Interface not set */
		mutex_exit(&d->bd_lock);
		mutex_exit(&bpf_mtx);
		return (EINVAL);
	}
	if (d->bd_bif->bif_dlt == dlt) {	/* NULL-op */
		mutex_exit(&d->bd_lock);
		mutex_exit(&bpf_mtx);
		return (0);
	}

	/*
	 * See the matrix at the top of the file for the permissions table
	 * enforced by this driver.
	 */
	if ((d->bd_zone != GLOBAL_ZONEID) && (dlt != DLT_IPNET) &&
	    (d->bd_bif->bif_zoneid != d->bd_zone)) {
		mutex_exit(&d->bd_lock);
		mutex_exit(&bpf_mtx);
		return (EINVAL);
	}

	(void) strlcpy(ifname,
	    MBPF_NAME(&d->bd_bif->bif_mac, d->bd_bif->bif_ifp),
	    sizeof (ifname));

	bp = bpf_findif(d, ifname, dlt);

	mutex_exit(&bpf_mtx);
	/*
	 * Now only bd_lock is held.
	 *
	 * If there was no matching interface that supports the requested
	 * DLT, return an error and leave the current binding alone.
	 */
	if (bp == NULL) {
		mutex_exit(&d->bd_lock);
		return (EINVAL);
	}

	error = 0;
	bpf_detachd(d);
	bpf_attachd(d, bp);
	reset_d(d);

	mutex_exit(&d->bd_lock);
	return (error);
}

/*
 * bpf_clear_timeout is called with the bd_lock mutex held, providing it
 * with the necessary protection to retrieve and modify bd_callout but it
 * does not hold the lock for its entire duration... see below...
 */
static void
bpf_clear_timeout(struct bpf_d *d)
{
	timeout_id_t tid = d->bd_callout;
	d->bd_callout = 0;
	d->bd_inuse++;

	/*
	 * If the timeout has fired and is waiting on bd_lock, we could
	 * deadlock here because untimeout if bd_lock is held and would
	 * wait for bpf_timed_out to finish and it never would.
	 */
	if (tid != 0) {
		mutex_exit(&d->bd_lock);
		(void) untimeout(tid);
		mutex_enter(&d->bd_lock);
	}

	d->bd_inuse--;
}

/*
 * As a cloning device driver, BPF needs to keep track of which device
 * numbers are in use and which ones are not. A hash table, indexed by
 * the minor device number, is used to store the pointers to the
 * individual descriptors that are allocated in bpfopen().
 * The functions below present the interface for that hash table to
 * the rest of the driver.
 */
static struct bpf_d *
bpf_dev_find(minor_t minor)
{
	struct bpf_d *d = NULL;

	(void) mod_hash_find(bpf_hash, (mod_hash_key_t)(uintptr_t)minor,
	    (mod_hash_val_t *)&d);

	return (d);
}

static void
bpf_dev_add(struct bpf_d *d)
{
	(void) mod_hash_insert(bpf_hash, (mod_hash_key_t)(uintptr_t)d->bd_dev,
	    (mod_hash_val_t)d);
}

static void
bpf_dev_remove(struct bpf_d *d)
{
	struct bpf_d *stor;

	(void) mod_hash_remove(bpf_hash, (mod_hash_key_t)(uintptr_t)d->bd_dev,
	    (mod_hash_val_t *)&stor);
	ASSERT(stor == d);
}

/*
 * bpf_def_get should only ever be called for a minor number that exists,
 * thus there should always be a pointer in the hash table that corresponds
 * to it.
 */
static struct bpf_d *
bpf_dev_get(minor_t minor)
{
	struct bpf_d *d = NULL;

	(void) mod_hash_find(bpf_hash, (mod_hash_key_t)(uintptr_t)minor,
	    (mod_hash_val_t *)&d);
	ASSERT(d != NULL);

	return (d);
}

static void
bpf_debug_nic_action(char *txt, struct bpf_if *bp)
{
	if (bpf_debug) {
		cmn_err(CE_CONT, "%s %s %s/%d/%d/%d\n", bp->bif_ifname, txt,
		    MBPF_NAME(&bp->bif_mac, bp->bif_ifp), bp->bif_linkid,
		    bp->bif_zoneid, bp->bif_dlt);
	}
}

/*
 * Finding a BPF network interface is a two pass job.
 * In the first pass, the best possible match is made on zone, DLT and
 * interface name.
 * In the second pass, we allow global zone snoopers to attach to interfaces
 * that are reserved for other zones.
 * This ensures that the global zone will always see its own interfaces first
 * before attaching to those that belong to a shared IP instance zone.
 */
static struct bpf_if *
bpf_findif(struct bpf_d *d, char *ifname, int dlt)
{
	struct bpf_if *bp;

	TAILQ_FOREACH(bp, &bpf_iflist, bif_next) {
		if ((bp->bif_ifp == 0) ||
		    (strcmp(ifname, bp->bif_ifname) != 0))
			continue;

		if (bp->bif_zoneid != d->bd_zone)
			continue;

		if ((dlt != -1) && (dlt != bp->bif_dlt))
			continue;

		return (bp);
	}

	if (d->bd_zone == GLOBAL_ZONEID) {
		TAILQ_FOREACH(bp, &bpf_iflist, bif_next) {
			if ((bp->bif_ifp == 0) ||
			    (strcmp(ifname, bp->bif_ifname) != 0))
				continue;

			if ((dlt != -1) && (dlt != bp->bif_dlt))
				continue;
			return (bp);
		}
	}

	return (NULL);
}
