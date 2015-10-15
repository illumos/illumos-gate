/*
 * Copyright (c) 2010 Minoura Makoto.
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Part of the file derived from `Virtio PCI Card Specification v0.8.6 DRAFT'
 * Appendix A.
 */

/*
 * An interface for efficient virtio implementation.
 *
 * This header is BSD licensed so anyone can use the definitions
 * to implement compatible drivers/servers.
 *
 * Copyright 2007, 2009, IBM Corporation
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
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' ANDANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef __VIRTIOVAR_H__
#define	__VIRTIOVAR_H__

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/cmn_err.h>
#include <sys/list.h>

#ifdef DEBUG
#define	dev_debug(dip, fmt, arg...) \
	dev_err(dip, fmt, ##arg)
#else
#define	dev_debug(dip, fmt, arg...)
#endif

struct vq_entry {
	list_node_t		qe_list;
	struct virtqueue	*qe_queue;
	uint16_t		qe_index; /* index in vq_desc array */
	/* followings are used only when it is the `head' entry */
	struct vq_entry		*qe_next;
	struct vring_desc	*qe_desc;
	ddi_dma_cookie_t	qe_indirect_dma_cookie;
	ddi_dma_handle_t	qe_indirect_dma_handle;
	ddi_acc_handle_t	qe_indirect_dma_acch;
	struct vring_desc	*qe_indirect_descs;
	unsigned int 		qe_indirect_next;
};

struct virtqueue {
	struct virtio_softc	*vq_owner;
	unsigned int		vq_num; /* queue size (# of entries) */
	unsigned int		vq_indirect_num;
	int			vq_index; /* queue number (0, 1, ...) */

	/* vring pointers (KVA) */
	struct vring_desc	*vq_descs;
	struct vring_avail	*vq_avail;
	struct vring_used	*vq_used;

	/* virtqueue allocation info */
	void			*vq_vaddr;
	int			vq_availoffset;
	int			vq_usedoffset;
	ddi_dma_cookie_t	vq_dma_cookie;
	ddi_dma_handle_t	vq_dma_handle;
	ddi_acc_handle_t	vq_dma_acch;

	int			vq_maxsegsize;

	/* free entry management */
	struct vq_entry		*vq_entries;
	list_t			vq_freelist;
	kmutex_t		vq_freelist_lock;
	int			vq_used_entries;

	/* enqueue/dequeue status */
	uint16_t		vq_avail_idx;
	kmutex_t		vq_avail_lock;
	uint16_t		vq_used_idx;
	kmutex_t		vq_used_lock;
};

struct virtio_softc {
	dev_info_t		*sc_dev;

	uint_t			sc_intr_prio;

	ddi_acc_handle_t	sc_ioh;
	caddr_t			sc_io_addr;
	int			sc_config_offset;

	uint32_t		sc_features;

	int			sc_nvqs; /* set by the user */

	ddi_intr_handle_t	*sc_intr_htable;
	int			sc_intr_num;
	boolean_t		sc_intr_config;
	int			sc_intr_cap;
	int			sc_int_type;
};

struct virtio_int_handler {
	ddi_intr_handler_t *vh_func;
	void *vh_priv;
};

/* public interface */
uint32_t virtio_negotiate_features(struct virtio_softc *, uint32_t);
size_t virtio_show_features(uint32_t features, char *buffer, size_t len);
boolean_t virtio_has_feature(struct virtio_softc *sc, uint32_t feature);
void virtio_set_status(struct virtio_softc *sc, unsigned int);
#define	virtio_device_reset(sc)	virtio_set_status((sc), 0)

uint8_t virtio_read_device_config_1(struct virtio_softc *sc,
		unsigned int index);
uint16_t virtio_read_device_config_2(struct virtio_softc *sc,
		unsigned int index);
uint32_t virtio_read_device_config_4(struct virtio_softc *sc,
		unsigned int index);
uint64_t virtio_read_device_config_8(struct virtio_softc *sc,
		unsigned int index);
void virtio_write_device_config_1(struct virtio_softc *sc,
		unsigned int index, uint8_t value);
void virtio_write_device_config_2(struct virtio_softc *sc,
		unsigned int index, uint16_t value);
void virtio_write_device_config_4(struct virtio_softc *sc,
		unsigned int index, uint32_t value);
void virtio_write_device_config_8(struct virtio_softc *sc,
		unsigned int index, uint64_t value);

struct virtqueue *virtio_alloc_vq(struct virtio_softc *sc,
		unsigned int index, unsigned int size,
		unsigned int indirect_num, const char *name);
void virtio_free_vq(struct virtqueue *);
void virtio_reset(struct virtio_softc *);
struct vq_entry *vq_alloc_entry(struct virtqueue *vq);
void vq_free_entry(struct virtqueue *vq, struct vq_entry *qe);
uint_t vq_num_used(struct virtqueue *vq);
unsigned int virtio_ve_indirect_available(struct vq_entry *qe);

void virtio_stop_vq_intr(struct virtqueue *);
void virtio_start_vq_intr(struct virtqueue *);

void virtio_ve_add_cookie(struct vq_entry *qe, ddi_dma_handle_t dma_handle,
    ddi_dma_cookie_t dma_cookie, unsigned int ncookies, boolean_t write);
void virtio_ve_add_indirect_buf(struct vq_entry *qe, uint64_t paddr,
    uint32_t len, boolean_t write);
void virtio_ve_set(struct vq_entry *qe, uint64_t paddr, uint32_t len,
		boolean_t write);

void virtio_push_chain(struct vq_entry *qe, boolean_t sync);
struct vq_entry *virtio_pull_chain(struct virtqueue *vq, uint32_t *len);
void virtio_free_chain(struct vq_entry *ve);
void virtio_sync_vq(struct virtqueue *vq);

int virtio_register_ints(struct virtio_softc *sc,
		struct virtio_int_handler *config_handler,
		struct virtio_int_handler vq_handlers[]);
void virtio_release_ints(struct virtio_softc *sc);
int virtio_enable_ints(struct virtio_softc *sc);

#endif /* __VIRTIOVAR_H__ */
