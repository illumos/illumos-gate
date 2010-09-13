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
 *
 * Copyright (c) 2002-2006 Neterion, Inc.
 */

#ifndef XGE_HAL_MM_H
#define XGE_HAL_MM_H

#include "xge-os-pal.h"
#include "xge-debug.h"
#include "xgehal-types.h"
#include "xgehal-driver.h"

__EXTERN_BEGIN_DECLS

typedef void* xge_hal_mempool_h;

/*
 * struct xge_hal_mempool_dma_t - Represents DMA objects passed to the
 caller.
 */
typedef struct xge_hal_mempool_dma_t {
	dma_addr_t			addr;
	pci_dma_h			handle;
	pci_dma_acc_h			acc_handle;
} xge_hal_mempool_dma_t;

/*
 * xge_hal_mempool_item_f  - Mempool item alloc/free callback
 * @mempoolh: Memory pool handle.
 * @item: Item that gets allocated or freed.
 * @index: Item's index in the memory pool.
 * @is_last: True, if this item is the last one in the pool; false - otherwise.
 * userdat: Per-pool user context.
 *
 * Memory pool allocation/deallocation callback.
 */
typedef xge_hal_status_e (*xge_hal_mempool_item_f) (xge_hal_mempool_h mempoolh,
				void *memblock, int memblock_index,
				xge_hal_mempool_dma_t *dma_object, void	*item,
				int index, int is_last, void *userdata);

/*
 * struct xge_hal_mempool_t - Memory pool.
 */
typedef struct xge_hal_mempool_t {
	xge_hal_mempool_item_f		item_func_alloc;
	xge_hal_mempool_item_f		item_func_free;
	void				*userdata;
	void				**memblocks_arr;
	void				**memblocks_priv_arr;
	xge_hal_mempool_dma_t		*memblocks_dma_arr;
	pci_dev_h			pdev;
	int				memblock_size;
	int				memblocks_max;
	int				memblocks_allocated;
	int				item_size;
	int				items_max;
	int				items_initial;
	int				items_current;
	int				items_per_memblock;
	void				**items_arr;
	void				**shadow_items_arr;
	int				items_priv_size;
} xge_hal_mempool_t;

/*
 * __hal_mempool_item - Returns pointer to the item in the mempool
 * items array.
 */
static inline void*
__hal_mempool_item(xge_hal_mempool_t *mempool, int index)
{
	return mempool->items_arr[index];
}

/*
 * __hal_mempool_item_priv - will return pointer on per item private space
 */
static inline void*
__hal_mempool_item_priv(xge_hal_mempool_t *mempool, int memblock_idx,
			void *item, int *memblock_item_idx)
{
	ptrdiff_t offset;
	void *memblock = mempool->memblocks_arr[memblock_idx];

	xge_assert(memblock);

	offset = (int)((char * )item - (char *)memblock);
	xge_assert(offset >= 0 && offset < mempool->memblock_size);

	(*memblock_item_idx) = (int) offset / mempool->item_size;
	xge_assert((*memblock_item_idx) < mempool->items_per_memblock);

	return (char*)mempool->memblocks_priv_arr[memblock_idx] +
			    (*memblock_item_idx) * mempool->items_priv_size;
}

/*
 * __hal_mempool_items_arr - will return pointer to the items array in the
 *  mempool.
 */
static inline void*
__hal_mempool_items_arr(xge_hal_mempool_t *mempool)
{
	return mempool->items_arr;
}

/*
 * __hal_mempool_memblock - will return pointer to the memblock in the
 *  mempool memblocks array.
 */
static inline void*
__hal_mempool_memblock(xge_hal_mempool_t *mempool, int memblock_idx)
{
	xge_assert(mempool->memblocks_arr[memblock_idx]);
	return mempool->memblocks_arr[memblock_idx];
}

/*
 * __hal_mempool_memblock_dma - will return pointer to the dma block
 *  corresponds to the memblock(identified by memblock_idx) in the mempool.
 */
static inline xge_hal_mempool_dma_t*
__hal_mempool_memblock_dma(xge_hal_mempool_t *mempool, int memblock_idx)
{
	return mempool->memblocks_dma_arr + memblock_idx;
}

xge_hal_status_e __hal_mempool_grow(xge_hal_mempool_t *mempool,
			int num_allocate, int *num_allocated);

xge_hal_mempool_t* __hal_mempool_create(pci_dev_h pdev, int memblock_size,
			int item_size, int private_size, int items_initial,
			int items_max, xge_hal_mempool_item_f item_func_alloc,
			xge_hal_mempool_item_f item_func_free, void *userdata);

void __hal_mempool_destroy(xge_hal_mempool_t *mempool);


__EXTERN_END_DECLS

#endif /* XGE_HAL_MM_H */
