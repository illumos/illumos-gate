#ifdef DEBUG
# define	PFILDEBUG
#endif

#include "os.h"

#ifndef	MTYPE
# define	MTYPE(m)	((m)->b_datap->db_type)
#endif

#ifndef	MLEN
# define	MLEN(m)		((m)->b_wptr - (m)->b_rptr)
#endif

#ifndef	MIN
# define	MIN(a,b)	(((a)<(b))?(a):(b))
#endif

#ifndef ALIGN32
# define	ALIGN32(x)      (x)
#endif

#ifdef  PFILDEBUG
# define	PRINT(l,x)	do {if ((l) <= pfildebug) cmn_err x; } while (0)
# define	QTONM(x)	(((x) && (x)->q_ptr) ? \
				 ((qif_t *)(x)->q_ptr)->qf_name : "??")
#else
# define	PRINT(l,x)	;
#endif

#ifndef	LIFNAMSIZ
# define	LIFNAMSIZ	32
#endif
