#ifndef FOO
struct st { int len; };
#define FOO
#else
struct st;
static int test(struct st *s);
static int test(struct st *s)
{
	return s->len;
}
#endif
/*
 * check-name: There is no scope boundary between global and file scope
 * check-description: Used to mess scopes with -include
 * check-command: sparse -include $file $file
 */
