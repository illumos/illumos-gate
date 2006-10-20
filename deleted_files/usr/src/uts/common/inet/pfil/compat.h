/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
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

#ifndef	ASSERT
# define	ASSERT(x)
#endif

/*
 * The list of SAPs below all come from Sun's <atm/iftypes.h> file.  It's not
 * yet clear whether pfil should deal with any of these or not.
 */
#ifndef	IFMP_SAP
# define	IFMP_SAP	0x0065
#endif

#ifndef	LANER_SAP
# define	LANER_SAP	0x9999
#endif

#ifndef	SNMP_SAP
# define	SNMP_SAP	0x999a
#endif

#ifndef	ILMI_SAP
# define	ILMI_SAP	0x999b
#endif

#ifndef	SIG_SAP
# define	SIG_SAP		0x999c
#endif

#ifndef	Q93B_MGMT_SAP
# define	Q93B_MGMT_SAP	0x999d
#endif

#ifndef	UTIL_SAP
# define	UTIL_SAP	0x999e
#endif

#ifndef	ERROR_SAP
# define	ERROR_SAP	0x999f
#endif
