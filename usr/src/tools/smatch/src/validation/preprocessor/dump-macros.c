#define ABC abc
#undef ABC

#define	DEF def
#undef DEF
#define DEF xyz

#define NYDEF ydef
/*
 * check-name: dump-macros
 * check-command: sparse -E -dD -DIJK=ijk -UNDEF -UNYDEF $file
 *
 * check-output-ignore
check-output-pattern-1-times: #define __CHECKER__ 1
check-output-contains: #define IJK ijk
check-output-contains: #define DEF xyz
check-output-contains: #define NYDEF ydef
 */
