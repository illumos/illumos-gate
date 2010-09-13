/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBDLPI_H
#define	_LIBDLPI_H

#include <sys/types.h>
#include <sys/dlpi.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Maximum Physical (hardware) address length, in bytes.
 * Must be as large as MAXMACADDRLEN (see <sys/mac.h>).
 */
#define	DLPI_PHYSADDR_MAX	64

/*
 * Maximum link name length, including terminating NUL, in bytes.
 * Must be no larger than MAXLINKNAMELEN (see <sys/param.h>).
 */
#define	DLPI_LINKNAME_MAX	32

/*
 * Constant used to indicate bind to any SAP value
 */
#define	DLPI_ANY_SAP	(uint_t)-1

/*
 * Flag values for dlpi_open(); those not documented in dlpi_open(3DLPI)
 * are Consolidation Private and subject to change or removal.
 */
#define	DLPI_EXCL	0x0001	/* Exclusive open */
#define	DLPI_PASSIVE	0x0002	/* Open DLPI link in passive mode */
#define	DLPI_RAW	0x0004	/* Open DLPI link in raw mode */
#define	DLPI_SERIAL	0x0008	/* Synchronous serial line interface */
#define	DLPI_NOATTACH	0x0010	/* Do not attach PPA */
#define	DLPI_NATIVE	0x0020	/* Open DLPI link in native mode */
#define	DLPI_DEVONLY	0x0040	/* Open DLPI link under /dev only */
#define	DLPI_DEVIPNET	0x0080	/* Open IP DLPI link under /dev/ipnet */
#define	DLPI_IPNETINFO	0x0100	/* Request ipnetinfo headers */
/*
 * Timeout to be used in DLPI-related operations, in seconds.
 */
#define	DLPI_DEF_TIMEOUT  5

/*
 * Since this library returns error codes defined in either <sys/dlpi.h> or
 * <libdlpi.h>, libdlpi specific error codes will start at value 10000 to
 * avoid overlap. DLPI_SUCCESS cannot be 0 because 0 is already DL_BADSAP in
 * <sys/dlpi.h>.
 */
enum {
	DLPI_SUCCESS = 10000,	/* DLPI operation succeeded */
	DLPI_EINVAL,		/* invalid argument */
	DLPI_ELINKNAMEINVAL,	/* invalid DLPI linkname */
	DLPI_ENOLINK,		/* DLPI link does not exist */
	DLPI_EBADLINK,		/* bad DLPI link */
	DLPI_EINHANDLE,		/* invalid DLPI handle */
	DLPI_ETIMEDOUT,		/* DLPI operation timed out */
	DLPI_EVERNOTSUP,	/* unsupported DLPI Version */
	DLPI_EMODENOTSUP,	/* unsupported DLPI connection mode */
	DLPI_EUNAVAILSAP,	/* unavailable DLPI SAP */
	DLPI_FAILURE,		/* DLPI operation failed */
	DLPI_ENOTSTYLE2,	/* DLPI style-2 node reports style-1 */
	DLPI_EBADMSG,		/* bad DLPI message */
	DLPI_ERAWNOTSUP,	/* DLPI raw mode not supported */
	DLPI_ENOTEINVAL,	/* invalid DLPI notification type */
	DLPI_ENOTENOTSUP,	/* DLPI notification not supported by link */
	DLPI_ENOTEIDINVAL,	/* invalid DLPI notification id */
	DLPI_EIPNETINFONOTSUP,	/* DLPI_IPNETINFO not supported */
	DLPI_ERRMAX		/* Highest + 1 libdlpi error code */
};

/*
 * DLPI information; see dlpi_info(3DLPI).
 */
typedef struct {
	uint_t			di_opts;
	uint_t			di_max_sdu;
	uint_t			di_min_sdu;
	uint_t			di_state;
	uint_t			di_mactype;
	char			di_linkname[DLPI_LINKNAME_MAX];
	uchar_t			di_physaddr[DLPI_PHYSADDR_MAX];
	uchar_t			di_physaddrlen;
	uchar_t			di_bcastaddr[DLPI_PHYSADDR_MAX];
	uchar_t			di_bcastaddrlen;
	uint_t			di_sap;
	int			di_timeout;
	dl_qos_cl_sel1_t	di_qos_sel;
	dl_qos_cl_range1_t 	di_qos_range;
} dlpi_info_t;

/*
 * DLPI send information; see dlpi_send(3DLPI).
 */
typedef struct {
	uint_t 		dsi_sap;
	dl_priority_t	dsi_prio;
} dlpi_sendinfo_t;

/*
 * Destination DLPI address type; see dlpi_recv(3DLPI).
 */
typedef enum {
	DLPI_ADDRTYPE_UNICAST,
	DLPI_ADDRTYPE_GROUP
} dlpi_addrtype_t;

/*
 * DLPI receive information; see dlpi_recv(3DLPI).
 */
typedef struct {
	uchar_t 	dri_destaddr[DLPI_PHYSADDR_MAX];
	uchar_t 	dri_destaddrlen;
	dlpi_addrtype_t	dri_destaddrtype;
	size_t  	dri_totmsglen;
} dlpi_recvinfo_t;

/*
 * DLPI notification, (DL_NOTIFY_IND) payload information;
 * see dlpi_enabnotify(3DLPI).
 */
typedef struct {
	uint_t  dni_note;
	union {
		uint_t  dniu_speed;
		uint_t  dniu_size;
		struct {
			uchar_t physaddr[DLPI_PHYSADDR_MAX];
			uchar_t physaddrlen;
		} dniu_addr;
	} dni_data;
} dlpi_notifyinfo_t;

#define	dni_speed		dni_data.dniu_speed
#define	dni_size		dni_data.dniu_size
#define	dni_physaddr		dni_data.dniu_addr.physaddr
#define	dni_physaddrlen 	dni_data.dniu_addr.physaddrlen

typedef struct __dlpi_handle *dlpi_handle_t;

/*
 * dlpi_notifyid_t refers to a registered notification. Its value should
 * not be interpreted by the interface consumer.
 */
typedef struct __dlpi_notifyid *dlpi_notifyid_t;

/*
 * Callback function invoked with arguments; see dlpi_enabnotify(3DLPI).
 */
typedef void dlpi_notifyfunc_t(dlpi_handle_t, dlpi_notifyinfo_t *, void *);

extern const char	*dlpi_mactype(uint_t);
extern const char 	*dlpi_strerror(int);
extern const char 	*dlpi_linkname(dlpi_handle_t);

typedef boolean_t dlpi_walkfunc_t(const char *, void *);

extern void dlpi_walk(dlpi_walkfunc_t *, void *, uint_t);
extern int dlpi_open(const char *, dlpi_handle_t *, uint_t);
extern void dlpi_close(dlpi_handle_t);
extern int dlpi_info(dlpi_handle_t, dlpi_info_t *, uint_t);
extern int dlpi_bind(dlpi_handle_t, uint_t, uint_t *);
extern int dlpi_unbind(dlpi_handle_t);
extern int dlpi_enabmulti(dlpi_handle_t, const void *, size_t);
extern int dlpi_disabmulti(dlpi_handle_t, const void *, size_t);
extern int dlpi_promiscon(dlpi_handle_t, uint_t);
extern int dlpi_promiscoff(dlpi_handle_t, uint_t);
extern int dlpi_get_physaddr(dlpi_handle_t, uint_t, void *, size_t *);
extern int dlpi_set_physaddr(dlpi_handle_t, uint_t, const void *, size_t);
extern int dlpi_recv(dlpi_handle_t, void *, size_t *, void *, size_t *,
    int, dlpi_recvinfo_t *);
extern int dlpi_send(dlpi_handle_t, const void *, size_t, const void *, size_t,
    const dlpi_sendinfo_t *);
extern int dlpi_enabnotify(dlpi_handle_t, uint_t, dlpi_notifyfunc_t *,
    void *arg, dlpi_notifyid_t *);
extern int dlpi_disabnotify(dlpi_handle_t, dlpi_notifyid_t, void **);
extern int dlpi_fd(dlpi_handle_t);
extern int dlpi_set_timeout(dlpi_handle_t, int);
extern uint_t dlpi_arptype(uint_t);
extern uint_t dlpi_iftype(uint_t);

/*
 * These are Consolidation Private interfaces and are subject to change.
 */
extern int dlpi_parselink(const char *, char *, uint_t *);
extern int dlpi_makelink(char *, const char *, uint_t);
extern uint_t dlpi_style(dlpi_handle_t);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBDLPI_H */
