#include <sys/sunddi.h>
#include <sys/ddi.h>
#if SOLARIS2 >= 6
# include <net/if_types.h>
#endif
#undef	IPOPT_EOL
#undef	IPOPT_NOP
#undef	IPOPT_LSRR
#undef	IPOPT_RR
#undef	IPOPT_SSRR

#include <inet/common.h>
#include <inet/mi.h>
#include <inet/led.h>
#include <inet/nd.h>
#if SOLARIS2 >= 8
# include <netinet/ip6.h>
#endif
#include <inet/ip.h>

#define	MUTEX_ENTER(x)		mutex_enter(x)
#define	MUTEX_EXIT(x)		mutex_exit(x)
#define	READ_ENTER(x)		rw_enter(x, RW_READER)
#define	WRITE_ENTER(x)		rw_enter(x, RW_WRITER)
#define	RW_DOWNGRADE(x)		rw_downgrade(x)
#define	RW_EXIT(x)		rw_exit(x)
#define	KMALLOC(v,t,z,w)	(v) = (t)kmem_zalloc(z, w)
#define	KMFREE(v, z)		kmem_free(v, z)

extern	caddr_t			pfil_nd;
