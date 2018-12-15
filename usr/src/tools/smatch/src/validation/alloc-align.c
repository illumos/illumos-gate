typedef unsigned long int size_t;

/*
 * The alloc_align attribute is used to tell the compiler that the return
 * value points to memory, where the returned pointer minimum alignment is given
 * by one of the functions parameters. GCC uses this information to improve
 * pointer alignment analysis.
 *
 * The function parameter denoting the allocated alignment is specified by one
 * integer argument, whose number is the argument of the attribute. Argument
 * numbering starts at one.
 *
 * For instance,
 *
 *    void* my_memalign(size_t, size_t) __attribute__((alloc_align(1)))
 *
 * declares that my_memalign returns memory with minimum alignment given by
 * parameter 1.
 */

#define __alloc_align(x)  __attribute__((__alloc_align__(x)))

/*
 * The aligned_alloc function allocates space for an object whose alignment is
 * specified by alignment, whose size is specified by size, and whose value is
 * indeterminate. The value of alignment shall be a valid alignment supported
 * by the implementation and the value of size shall be an integral multiple
 * of alignment.
 *
 * The aligned_alloc function returns either a null pointer or a pointer to the
 * allocated space.
 */
void *aligned_alloc(size_t alignment, size_t size) __alloc_align(1);


/*
 * check-name: attribute __alloc_align__
 */
