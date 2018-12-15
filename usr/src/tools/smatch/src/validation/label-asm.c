#define barrier() __asm__ __volatile__("": : :"memory")

static void f(void)
{
	barrier();
l:
	barrier();
}
/*
 * check-name: Label followed by __asm__
 * check-description: Sparse used to parse the __asm__ as modifying the label.
 */
