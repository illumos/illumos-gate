#ifndef COMPAT_H
#define COMPAT_H

/*
 * Various systems get these things wrong. So
 * we create a small compat library for them.
 *
 *  - zeroed anonymous mmap
 *	Missing in MinGW
 *  - "string to long double" (C99 strtold())
 *	Missing in Solaris and MinGW
 */
struct stream;
struct stat;

/*
 * Our "blob" allocator works on chunks that are multiples
 * of this size (the underlying allocator may be a mmap that
 * cannot handle smaller chunks, for example, so trying to
 * allocate blobs that aren't aligned is not going to work).
 */
#define CHUNK 32768

void *blob_alloc(unsigned long size);
void blob_free(void *addr, unsigned long size);
long double string_to_ld(const char *nptr, char **endptr);

#endif
