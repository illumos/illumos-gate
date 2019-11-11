#ifndef __has_attribute
__has_attribute()??? Quesako?
#define __has_attribute(x) 0
#else
"has __has_attribute(), yeah!"
#endif

123 __has_attribute(nothinx) def

#if __has_attribute(nothinx)
#error "not a attribute!"
#endif

#if 1					\
 && __has_attribute(packed)		\
 && __has_attribute(aligned)		\
 && __has_attribute(const)		\
 && __has_attribute(pure)		\
 && __has_attribute(noreturn)		\
 && __has_attribute(designated_init)	\
 && __has_attribute(transparent_union)	\

"ok gcc"
#endif

#if 1					\
 && __has_attribute(fastcall)		\

"ok gcc ignore"
#endif

#if 1					\
 && __has_attribute(nocast)		\
 && __has_attribute(noderef)		\
 && __has_attribute(safe)		\
 && __has_attribute(force)		\
 && __has_attribute(bitwise)		\
 && __has_attribute(address_space)	\
 && __has_attribute(context)		\

"ok sparse specific"
#endif

/*
 * check-name: has-attribute
 * check-command: sparse -E $file
 *
 * check-output-start

"has __has_attribute(), yeah!"
123 0 def
"ok gcc"
"ok gcc ignore"
"ok sparse specific"
 * check-output-end
 */
