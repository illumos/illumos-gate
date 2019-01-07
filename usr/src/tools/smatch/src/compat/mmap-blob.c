#include <sys/mman.h>
#include <sys/types.h>

/*
 * Allow old BSD naming too, it would be a pity to have to make a
 * separate file just for this.
 */
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/*
 * Our blob allocator enforces the strict CHUNK size
 * requirement, as a portability check.
 */
void *blob_alloc(unsigned long size)
{
	void *ptr;

	if (size & ~CHUNK)
		die("internal error: bad allocation size (%lu bytes)", size);
	ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ptr == MAP_FAILED)
		ptr = NULL;
	return ptr;
}

void blob_free(void *addr, unsigned long size)
{
	if (!size || (size & ~CHUNK) || ((unsigned long) addr & 512))
		die("internal error: bad blob free (%lu bytes at %p)", size, addr);
#ifndef DEBUG
	munmap(addr, size);
#else
	mprotect(addr, size, PROT_NONE);
#endif
}
