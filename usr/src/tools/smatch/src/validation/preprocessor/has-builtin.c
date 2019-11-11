#ifndef __has_builtin
__has_builtin()??? Quesako?
#define __has_builtin(x) 0
#else
"has __has_builtin(), yeah!"
#endif

#if __has_builtin(nothing)
#error "not a builtin!"
#endif

#if __has_builtin(__builtin_offsetof)		\
 || __has_builtin(__builtin_types_compatible_p)
#error "builtin ops are not builtin functions!"
#endif

#if __has_builtin(__builtin_va_list)		\
 || __has_builtin(__builtin_ms_va_list)
#error "builtin types are not builtin functions!"
#endif

#if __has_builtin(__builtin_abs)
abs
#endif

#if __has_builtin(__builtin_constant_p)
constant_p
#endif

123 __has_builtin(abc) def

/*
 * check-name: has-builtin
 * check-command: sparse -E $file
 *
 * check-output-start

"has __has_builtin(), yeah!"
abs
constant_p
123 0 def
 * check-output-end
 */
