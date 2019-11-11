#define ABC abc
#undef ABC

#define	DEF def
#undef DEF
#define DEF xyz

#define NYDEF ydef

#define STRING(x) #x
#define CONCAT(x,y) x ## y

#define unlocks(...) annotate(unlock_func(__VA_ARGS__))
#define apply(x,...) x(__VA_ARGS__)

int main(int argc, char *argv[])
{
	return 0;
}
/*
 * check-name: dump-macros
 * check-command: sparse -E -dD -DIJK=ijk -UNDEF -UNYDEF $file
 *
 * check-output-ignore
check-output-pattern(1): #define __CHECKER__ 1
check-output-contains: #define IJK ijk
check-output-contains: #define DEF xyz
check-output-contains: #define NYDEF ydef
check-output-contains: #define STRING(x) #x
check-output-contains: #define CONCAT(x,y) x ## y
check-output-contains: #define unlocks(...) annotate(unlock_func(__VA_ARGS__))
check-output-contains: #define apply(x,...) x(__VA_ARGS__)
check-output-contains: int main(int argc, char \\*argv\\[\\])
 */
