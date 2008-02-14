
#ifndef _NETSMB_SMB_NETSHAREENUM_H_
#define	_NETSMB_SMB_NETSHAREENUM_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* This is from Apple.  See ../smb/netshareenum.c */

struct share_info {
	uint16_t	type;
	char		*netname;
	char		*remark;
};
typedef struct share_info share_info_t;

int  smb_netshareenum(struct smb_ctx *, int *, int *, struct share_info **);

#endif /* _NETSMB_SMB_NETSHAREENUM_H_ */
