void memcpy(void *dst, const void *src, unsigned int size);
void memcpy(void *dst, const void *src, unsigned int size)
{
	__builtin_memcpy(dst, src, size);
}

unsigned int strlen(const char *src);
unsigned int strlen(const char *src)
{
	return __builtin_strlen(src);
}

/*
 * check-name: builtin-prototype
 */
