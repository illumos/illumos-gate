#define __restrict_arr __restrict

struct aiocb64;
struct sigevent;

extern int lio_listio64 (int __mode,
			 struct aiocb64 *__const __list[__restrict_arr],
			 int __nent, struct sigevent *__restrict __sig);

#undef __restrict_arr
#define __restrict_arr __restrict__

struct gaicb;

extern int getaddrinfo_a (int __mode, struct gaicb *__list[__restrict_arr],
			  int __ent, struct sigevent *__restrict __sig);

#undef __restrict_arr
#define __restrict_arr restrict

typedef struct re_pattern_buffer regex_t;
typedef int regoff_t;
typedef struct
{
  regoff_t rm_so;  /* Byte offset from string's start to substring's start.  */
  regoff_t rm_eo;  /* Byte offset from string's start to substring's end.  */
} regmatch_t;
typedef unsigned long int size_t;

extern int regexec (const regex_t *__restrict __preg,
		    const char *__restrict __string, size_t __nmatch,
		    regmatch_t __pmatch[__restrict_arr],
		    int __eflags);

/*
 * check-name: restrict array attribute
 */
