#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

dnl Copyright (c) 1994 James Clark
dnl See the file COPYING for copying permission.
dnl M4 macros for template instantiation.
define(`__undefine', defn(`undefine'))dnl
define(`__define', defn(`define'))dnl
define(`__changequote', defn(`changequote'))dnl
define(`__include', defn(`include'))dnl
define(`__ifdef', defn(`ifdef'))dnl
define(`__divert', defn(`divert'))dnl
define(`__dnl', defn(`dnl'))dnl
define(`__incr', defn(`incr'))dnl
define(`__index', 0)dnl
define(`__concat', $1$2)dnl
define(`__instantiate',`#ifdef __DECCXX
#pragma define_template $1
#else
#ifdef __xlC__
#pragma define($1)
#else
#ifdef SP_ANSI_CLASS_INST
template class $1;
#else
typedef $1 __concat(Dummy_,__index);
#endif
#endif
#endif
__define(`__index',__incr(__index))__dnl')dnl
define(`__func_index', 0)dnl
define(`__instantiate_func3',
`#ifdef __GNUG__
template void $1($2, $3, $4);
#else
static
void  __concat(func_,__func_index) ($2 arg1, $3 arg2, $4 arg3) {
(void)$1(arg1, arg2, arg3);
}
#endif
__define(`__func_index',__incr(__func_index))__dnl')dnl
dnl we want __p to be expanded even inside comments
changecom()__dnl
__undefine(`changecom')__dnl
__undefine(`changequote')__dnl
__undefine(`decr')__dnl
__undefine(`define')__dnl
__undefine(`defn')__dnl
__undefine(`divert')__dnl
__undefine(`divnum')__dnl
__undefine(`dnl')__dnl
__undefine(`dumpdef')__dnl
__undefine(`errprint')__dnl
__undefine(`eval')__dnl
__undefine(`ifdef')__dnl
__undefine(`ifelse')__dnl
__undefine(`include')__dnl
__undefine(`incr')__dnl
__undefine(`index')__dnl
__undefine(`len')__dnl
__undefine(`m4exit')__dnl
__undefine(`m4wrap')__dnl
__undefine(`maketemp')__dnl
__undefine(`popdef')__dnl
__undefine(`pushdef')__dnl
__undefine(`shift')__dnl
__undefine(`sinclude')__dnl
__undefine(`substr')__dnl
__undefine(`syscmd')__dnl
__undefine(`sysval')__dnl
__undefine(`traceoff')__dnl
__undefine(`traceon')__dnl
__undefine(`translit')__dnl
__undefine(`undefine')__dnl
__undefine(`undivert')__dnl
__undefine(`unix')__dnl
__dnl __changequote(,)__dnl disable quoting

#ifdef SP_NAMESPACE
}
#endif
