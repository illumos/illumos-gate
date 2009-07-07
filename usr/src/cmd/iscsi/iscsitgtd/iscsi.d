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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma D depends_on library net.d
#pragma D depends_on module genunix
#pragma D depends_on library scsi.d

typedef struct uiscsiproto uiscsiproto_t;

typedef struct uiscsiproto64 {
	struct sockaddr_storage *uip_taddr;
	struct sockaddr_storage *uip_iaddr;

	uint64_t uip_target;
	uint64_t uip_initiator;
	uint64_t uip_lun;

	uint32_t uip_itt;
	uint32_t uip_ttt;

	uint32_t uip_cmdsn;
	uint32_t uip_statsn;
	uint32_t uip_datasn;

	uint32_t uip_datalen;
	uint32_t uip_flags;
} uiscsiproto64_t;

typedef struct uiscsiproto32 {
	struct sockaddr_storage *uip_taddr;
	struct sockaddr_storage *uip_iaddr;

	uint32_t uip_target;
	uint32_t uip_initiator;
	uint64_t uip_lun;

	uint32_t uip_itt;
	uint32_t uip_ttt;

	uint32_t uip_cmdsn;
	uint32_t uip_statsn;
	uint32_t uip_datasn;

	uint32_t uip_datalen;
	uint32_t uip_flags;
} uiscsiproto32_t;

#pragma D binding "1.5" translator
translator conninfo_t < uiscsiproto_t *P > {
	ci_local = (2 == *(sa_family_t *)
	    copyin((uintptr_t)((curthread->t_procp->p_model == 0x00100000) ?
	    *(uint32_t *)copyin((uintptr_t)
		&(((uiscsiproto32_t *)P)->uip_taddr), sizeof (uint32_t)) :
	    *(uint64_t *)copyin((uintptr_t)
		&(((uiscsiproto64_t *)P)->uip_taddr), sizeof (uint64_t))),
	    sizeof (sa_family_t))) ?

	    inet_ntoa((ipaddr_t *)copyin((uintptr_t)
	    &((struct sockaddr_in *) 
		((curthread->t_procp->p_model == 0x00100000) ?
	    	*(uint32_t *)copyin((uintptr_t)
		&(((uiscsiproto32_t *)P)->uip_taddr), sizeof (uint32_t)) :
	    	*(uint64_t *)copyin((uintptr_t)
	       	&(((uiscsiproto64_t *)P)->uip_taddr), sizeof (uint64_t))))
	    ->sin_addr, sizeof (ipaddr_t))) :

	    inet_ntoa6((in6_addr_t *)copyin((uintptr_t)
	    &((struct sockaddr_in6 *) 
		((curthread->t_procp->p_model == 0x00100000) ?
	    	*(uint32_t *)copyin((uintptr_t)
		&(((uiscsiproto32_t *)P)->uip_taddr), sizeof (uint32_t)) :
	    	*(uint64_t *)copyin((uintptr_t)
	       	&(((uiscsiproto64_t *)P)->uip_taddr), sizeof (uint64_t))))
	    ->sin6_addr, sizeof (in6_addr_t)));

	ci_remote = (2 == *(sa_family_t *)
	    copyin((uintptr_t)((curthread->t_procp->p_model == 0x00100000) ?
	    *(uint32_t *)copyin((uintptr_t)
		&(((uiscsiproto32_t *)P)->uip_iaddr), sizeof (uint32_t)) :
	    *(uint64_t *)copyin((uintptr_t)
		&(((uiscsiproto64_t *)P)->uip_iaddr), sizeof (uint64_t))),
	    sizeof (sa_family_t))) ?

	    inet_ntoa((ipaddr_t *)copyin((uintptr_t)
	    &((struct sockaddr_in *) 
		((curthread->t_procp->p_model == 0x00100000) ?
	    	*(uint32_t *)copyin((uintptr_t)
		&(((uiscsiproto32_t *)P)->uip_iaddr), sizeof (uint32_t)) :
	    	*(uint64_t *)copyin((uintptr_t)
	       	&(((uiscsiproto64_t *)P)->uip_iaddr), sizeof (uint64_t))))
	    ->sin_addr, sizeof (ipaddr_t))) :

	    inet_ntoa6((in6_addr_t *)copyin((uintptr_t)
	    &((struct sockaddr_in6 *) 
		((curthread->t_procp->p_model == 0x00100000) ?
	    	*(uint32_t *)copyin((uintptr_t)
		&(((uiscsiproto32_t *)P)->uip_iaddr), sizeof (uint32_t)) :
	    	*(uint64_t *)copyin((uintptr_t)
	       	&(((uiscsiproto64_t *)P)->uip_iaddr), sizeof (uint64_t))))
	    ->sin6_addr, sizeof (in6_addr_t)));

	ci_protocol = (*(sa_family_t *)copyin((uintptr_t)
	    ((curthread->t_procp->p_model == 0x00100000) ?

	    *(uint32_t *)copyin((uintptr_t)
		&(((uiscsiproto32_t *)P)->uip_taddr), sizeof (uint32_t)) :

	    *(uint64_t *)copyin((uintptr_t)
		&(((uiscsiproto64_t *)P)->uip_taddr), sizeof (uint64_t))),

	    sizeof (sa_family_t)) == 2) ? "ipv4" : "ipv6";
};

#pragma D binding "1.5" translator
translator iscsiinfo_t < uiscsiproto_t *P > {
	ii_initiator = (curthread->t_procp->p_model == 0x00100000) ?
	    copyinstr((uintptr_t)*(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_initiator, sizeof (uint32_t))) :
	    copyinstr((uintptr_t)*(uint64_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_initiator, sizeof (uint64_t)));

	ii_target = (curthread->t_procp->p_model == 0x00100000) ?
	    copyinstr((uintptr_t)*(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_target, sizeof (uint32_t))) :
	    copyinstr((uintptr_t)*(uint64_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_target, sizeof (uint64_t)));

	ii_lun = (curthread->t_procp->p_model == 0x00100000) ?
	    *(uint64_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_lun, sizeof (uint64_t)) :
	    *(uint64_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_lun, sizeof (uint64_t));

	ii_itt = (curthread->t_procp->p_model == 0x00100000) ?
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_itt, sizeof (uint32_t)) :
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_itt, sizeof (uint32_t));

	ii_ttt = (curthread->t_procp->p_model == 0x00100000) ?
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_ttt, sizeof (uint32_t)) :
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_ttt, sizeof (uint32_t));

	ii_cmdsn = (curthread->t_procp->p_model == 0x00100000) ?
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_cmdsn, sizeof (uint32_t)) :
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_cmdsn, sizeof (uint32_t));

	ii_statsn = (curthread->t_procp->p_model == 0x00100000) ?
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_statsn, sizeof (uint32_t)) :
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_statsn, sizeof (uint32_t));

	ii_datasn = (curthread->t_procp->p_model == 0x00100000) ?
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_datasn, sizeof (uint32_t)) :
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_datasn, sizeof (uint32_t));

	ii_datalen = (curthread->t_procp->p_model == 0x00100000) ?
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_datalen, sizeof (uint32_t)) :
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_datalen, sizeof (uint32_t));

	ii_flags = (curthread->t_procp->p_model == 0x00100000) ?
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto32_t *)P)->uip_flags, sizeof (uint32_t)) :
	    *(uint32_t *)copyin((uintptr_t)
		&((uiscsiproto64_t *)P)->uip_flags, sizeof (uint32_t));
};

typedef struct iscsicmd {
	uint64_t ic_len;	/* CDB length */
	uint8_t *ic_cdb;	/* CDB data */
} iscsicmd_t;

typedef struct uiscsicmd {
	uint64_t uic_len;
	uint8_t *uic_cdb;
} uiscsicmd_t;

#pragma D binding "1.5" translator
translator iscsicmd_t < uiscsicmd_t *P > {
	ic_len = *(uint64_t *)copyin((uintptr_t)&P->uic_len, sizeof (uint64_t));
	ic_cdb = (uint8_t *)copyin((curthread->t_procp->p_model == 0x00100000) ?
	    (uintptr_t)*(uint32_t *)copyin((uintptr_t)&P->uic_cdb,
	    sizeof (uint32_t)) :
	    (uintptr_t)*(uint64_t *)copyin((uintptr_t)&P->uic_cdb,
	    sizeof (uint64_t)),
	    *(uint64_t *)copyin((uintptr_t)&P->uic_len, sizeof (uint64_t)));
};

inline int ISCSI_FLAG_FINAL = 0x80;
#pragma D binding "1.5" ISCSI_FLAG_FINAL
inline int ISCSI_FLAG_CMD_WRITE = 0x20;
#pragma D binding "1.5" ISCSI_FLAG_CMD_WRITE
inline int ISCSI_FLAG_CMD_READ = 0x40;
#pragma D binding "1.5" ISCSI_FLAG_CMD_READ
inline int ISCSI_FLAG_CMD_BIDI_UNDERFLOW = 0x08;
#pragma D binding "1.5" ISCSI_FLAG_CMD_BIDI_UNDERFLOW
inline int ISCSI_FLAG_CMD_BIDI_OVERFLOW = 0x10;
#pragma D binding "1.5" ISCSI_FLAG_CMD_BIDI_OVERFLOW
inline int ISCSI_FLAG_CMD_UNDERFLOW = 0x02;
#pragma D binding "1.5" ISCSI_FLAG_CMD_UNDERFLOW
inline int ISCSI_FLAG_CMD_OVERFLOW = 0x04;
#pragma D binding "1.5" ISCSI_FLAG_CMD_OVERFLOW
inline int ISCSI_FLAG_DATA_STATUS = 0x01;
#pragma D binding "1.5" ISCSI_FLAG_DATA_STATUS
inline int ISCSI_FLAG_DATA_UNDERFLOW = 0x02;
#pragma D binding "1.5" ISCSI_FLAG_DATA_UNDERFLOW
inline int ISCSI_FLAG_DATA_OVERFLOW = 0x04;
#pragma D binding "1.5" ISCSI_FLAG_DATA_OVERFLOW
inline int ISCSI_FLAG_DATA_ACK = 0x40;
#pragma D binding "1.5" ISCSI_FLAG_DATA_ACK
inline int ISCSI_FLAG_TEXT_CONTINUE = 0x40;
#pragma D binding "1.5" ISCSI_FLAG_TEXT_CONTINUE
inline int ISCSI_FLAG_LOGIN_CONTINUE = 0x40;
#pragma D binding "1.5" ISCSI_FLAG_LOGIN_CONTINUE
inline int ISCSI_FLAG_LOGIN_TRANSIT = 0x80;
#pragma D binding "1.5" ISCSI_FLAG_LOGIN_TRANSIT
