#include <sys/mman.h>

#include <stdlib.h>
#include <unistd.h>
#include <err.h>

int
main(int argc, char **argv)
{
	int stack = 0;
	void *heap = NULL;
	void *mapping = NULL;

	if ((heap = malloc(10)) == NULL)
		err(1, "couldn't allocate");

	if ((mapping = mmap((caddr_t)0, 10, (PROT_READ | PROT_WRITE),
	    MAP_ANON|MAP_PRIVATE, -1, 0)) == (void*)-1)
		err(1, "couldn't map");

	printf("  stack: 0x%p\n", &stack);
	printf("   heap: 0x%p\n", heap);
	printf("mapping: 0x%p\n", mapping);
	printf("   text: 0x%p\n", &main);
	return (0);
}
