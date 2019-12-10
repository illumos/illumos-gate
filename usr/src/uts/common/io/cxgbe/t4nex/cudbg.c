#include "cudbg.h"

void
init_cudbg_hdr(struct cudbg_init_hdr *hdr)
{
	hdr->major_ver = CUDBG_MAJOR_VERSION;
	hdr->minor_ver = CUDBG_MINOR_VERSION;
	hdr->build_ver = CUDBG_BUILD_VERSION;
	hdr->init_struct_size = sizeof(struct cudbg_init);
}

/**
 *  cudbg_alloc_handle - Allocates and initializes a handle that represents
 *  cudbg state.  Needs to called first before calling any other function.
 *
 *  returns a pointer to memory that has a cudbg_init structure at the begining
 *  and enough space after that for internal book keeping.
 */

void *
cudbg_alloc_handle(void)
{
	struct cudbg_private *handle;

#ifdef _KERNEL
	handle = kmem_zalloc(sizeof(*handle), KM_NOSLEEP);
#else
	handle = malloc(sizeof(*handle));
#endif

	if (handle == NULL)
		return NULL;

	init_cudbg_hdr(&handle->dbg_init.header);

	return (handle);
}

/**
 *  cudbg_free_handle - Release cudbg resources.
 *  ## Parameters ##
 *  @handle : A pointer returned by cudbg_alloc_handle.
 */
void
cudbg_free_handle(void *handle)
{
#ifdef _KERNEL
	kmem_free(handle, sizeof(struct cudbg_private));
#else
	free(handle);
#endif
}

/********************************* Helper functions *************************/
void
set_dbg_bitmap(u8 *bitmap, enum CUDBG_DBG_ENTITY_TYPE type)
{
	int index = type / 8;
	int bit = type % 8;

	bitmap[index] |= (1 << bit);
}

void
reset_dbg_bitmap(u8 *bitmap, enum CUDBG_DBG_ENTITY_TYPE type)
{
	int index = type / 8;
	int bit = type % 8;

	bitmap[index] &= ~(1 << bit);
}

/********************************* End of Helper functions
 * *************************/

struct cudbg_init *
cudbg_get_init(void *handle)
{
	return (handle);
}
