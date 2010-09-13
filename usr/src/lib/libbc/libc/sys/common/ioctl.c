/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Do not include sys/conf.h- it isn't in the compatibility include dirs.
 */
#ifdef	THIS_IS_AVAIL
#include <sys/conf.h>
#endif
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/stropts.h>
#include <sys/des.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/termios.h>
#include <sys/termio.h>
#include <sys/ttold.h>
#include <sys/ttycom.h>
#include <sys/msio.h>
#include <sys/errno.h>
#include <nettli/tihdr.h>
#include <nettli/timod.h>
#include <nettli/tiuser.h>
#include <sun/dkio.h>
#include <scsi/impl/uscsi.h>
#include "cdioctl.h"
#include "s5dkio.h"
#include "s5fdio.h"

/*
 * parameter for windows ioctls 
 */
struct winclip {
        int     wc_blockbytes;          /* size of wc_block */
        int     wc_clipid;              /* Current clip id of clipping */
        short   wc_screenrect[4];       /* Screen relatived (used when paint) */
        char    *wc_block;              /* Block where RectList is copied. */
};

/*
 * Ioctl control packet
 */
struct s5termios {
	tcflag_t	c_iflag;	/* input modes */
	tcflag_t	c_oflag;	/* output modes */
	tcflag_t	c_cflag;	/* control modes */
	tcflag_t	c_lflag;	/* line discipline modes */
	cc_t		c_cc[19];	/* control chars */
};

#define N_ENOMSG	35	
#define N_I_FIND	('S'<<8)|013
#define N_I_PUSH	('S'<<8)|02
#define WINGETEXPOSEDRL	_IOWR('g',31,struct winclip)
#define WINGETDAMAGEDRL _IOWR('g',32,struct winclip)

struct n_sgttyb {
	char    sg_ispeed;              /* input speed */
	char    sg_ospeed;              /* output speed */
	char    sg_erase;               /* erase character */
	char    sg_kill;                /* kill character */
	int     sg_flags;               /* mode flags */
};

static int handle_dkio_partitions(int, int, int);
static int tcget(int, int, int);
static int tcset(int, int, int);
static int _bc_ioctl(int, int, int);

int
ioctl(int des, int request, int arg)
{
	int ret;

	if ((ret = _bc_ioctl(des, request, arg)) == -1)
		maperror();
	return (ret);
}

int
bc_ioctl(int des, int request, int arg)
{
	int ret;

	if ((ret = _bc_ioctl(des, request, arg)) == -1)
		maperror();
	return (ret);
}

static int
_bc_ioctl(int des, int request, int arg)
{
	int ret;
	int nreq = (request >> 8) & 0xFF;
	struct n_sgttyb nsg;
	struct s5_dk_cinfo newArgs;
	struct dk_info *infoArgs;
	struct dk_conf *confArgs;
	extern int errno;

	/* not all mappings for 'm' have been performed */
	switch (nreq) {
		case ((int) 't'):
			if (_ioctl(des, N_I_FIND, "ttcompat") == 0)
				if (_ioctl(des, N_I_PUSH, "ttcompat") == -1)
					perror("ioctl/I_PUSH");
			switch(request) {
				case TIOCSETD:
					     /* added for sunview */
					     return(0);
				case TIOCREMOTE: request = ('t'<<8)|30;
					     break;
				case TIOCNOTTY:
					     bc_setsid();
					     return(0);
				case TIOCGPGRP: request = ('t'<<8)|20;
					     break;
				case TIOCSPGRP:
				    {
					pid_t pgid;
					sigset_t set, oset;

					request = ('t'<<8)|21;
					ret = _ioctl(des, request, arg);

					/*
					 * SunOS4.x allows this to succeed
					 * even if the process group does
					 * not exist yet.  We emulate the 4.x
					 * bug by creating the process group
					 * and reissuing the ioctl().
					 * See bugid 1175044.
					 */
					if (ret != 0 && errno == EPERM &&
					    (pgid = *((pid_t *)arg)) != 0 &&
					    pgid == getpid() &&
					    setpgid(0, pgid) == 0) {
						sigemptyset(&set);
						sigaddset(&set, SIGTSTP);
						sigaddset(&set, SIGTTIN);
						sigaddset(&set, SIGTTOU);
						sigprocmask(SIG_BLOCK,
							&set, &oset);
						ret = _ioctl(des,
							request, arg);
						sigprocmask(SIG_SETMASK,
							&oset, NULL);
					}
					return(ret);
				    }
				case TIOCSTI: request = ('t'<<8)|23;
					     break;
				case TIOCSIGNAL: request = ('t'<<8)|31;
					     break;
				case TIOCCONS: request = ('t'<<8)|36;
					     break;
				case TIOCSWINSZ: request = ('T'<<8)|103;
					     break;
				case TIOCGWINSZ: request = ('T'<<8)|104;
					     break;
				case TIOCSETP:
				case TIOCSETN:
			  	    {
					struct sgttyb *sg = (struct sgttyb *)arg;
					nsg.sg_ispeed = sg->sg_ispeed;
					nsg.sg_ospeed = sg->sg_ospeed;
					nsg.sg_erase = sg->sg_erase;
					nsg.sg_kill = sg->sg_kill;
					nsg.sg_flags = (int)sg->sg_flags;
					arg = (int)&nsg;
				        request = request & 0x0FFFF;
					break;
				    }
				
				case TIOCGETP:			
				    {
					struct sgttyb *sg = (struct sgttyb *)arg;

					ret = _ioctl(des, request&0xFFFF, &nsg);
					if (ret != -1) {
						sg->sg_ispeed = nsg.sg_ispeed;
						sg->sg_ospeed = nsg.sg_ospeed;
						sg->sg_erase = nsg.sg_erase;
						sg->sg_kill = nsg.sg_kill;
						sg->sg_flags = (short)nsg.sg_flags & 0x0FFFF;
					}
					return(ret);
				    }
				case TIOCPKT:
				case TIOCUCNTL:
				case TIOCTCNTL:
				case TIOCSSOFTCAR:
				case TIOCGSOFTCAR:
				case TIOCISPACE:
				case TIOCISIZE:
				case TIOCSSIZE:
				case TIOCGSIZE:
				    	     break;
				default:     request = request & 0x0FFFF;
				 	     break;
			}
			break;
		case ((int) 'T'):
			switch(request) {
				case TCGETS:
					request = ('T'<<8)|13;
					return(tcget(des, request, arg));
					break;
				case TCSETS:
					request = ('T'<<8)|14;
					return(tcset(des, request, arg));
					break;
				case TCSETSW:
					request = ('T'<<8)|15;
					return(tcset(des, request, arg));
					break;
				case TCSETSF:
					request = ('T'<<8)|16;
					return(tcset(des, request, arg));
					break;
				case TCGETA:
				case TCSETA:
				case TCSETAW:
				case TCSETAF:
				default:
					request = request & 0x0FFFF;
					break;
			}
			break;
		case ((int) 'S'):
			switch (request) {
 				case I_PLINK: request = ('S'<<8)|026;
					      break;
 				case I_PUNLINK: request = ('S'<<8)|027;
					      break;
 				case I_STR: {
					struct strioctl *iarg =
					    (struct strioctl *)arg;
					int cmd = iarg->ic_cmd;

					switch (cmd) {
					case TI_GETINFO: {
						/*
						 * The T_info_ack structure
						 * has one additional word
						 * added to it in 5.x.
						 * To prevent the module from
						 * overwritting user memory we
						 * use an internal buffer for
						 * the transfer and copy out
						 * the results to the caller.
						 */
						struct {
							struct T_info_ack info;
							long		pad[16];
						} args;
						char *dp = iarg->ic_dp;

						memcpy(&args.info, iarg->ic_dp,
						    sizeof(struct T_info_ack));
						iarg->ic_dp =
						    (char *) &args.info;
						iarg->ic_cmd = (TIMOD | 140);
						ret = _ioctl(des,
						    request & 0xffff, arg);
						iarg->ic_cmd = cmd;
						iarg->ic_dp = dp;
						iarg->ic_len =
						    sizeof(struct T_info_ack);
						memcpy(iarg->ic_dp, &args.info,
						    iarg->ic_len);
						return (ret);
						break;
					}
					case TI_OPTMGMT:
						iarg->ic_cmd = (TIMOD | 141);
						break;
					case TI_BIND:
						iarg->ic_cmd = (TIMOD | 142);
						break;
					case TI_UNBIND:
						iarg->ic_cmd = (TIMOD | 143);
						break;
					}
					ret = _ioctl(des,
					    request & 0xffff, arg);
					iarg->ic_cmd = cmd;
					return ret;
				}
				default:      request = request & 0x0FFFF;
				  	      break;
			}
			break;
		case ((int) 'm'):
			switch (request) {
				case MSIOGETPARMS: request = ('m'<<8)|1;
					      break;
				case MSIOSETPARMS: request = ('m'<<8)|2;
					      break;
				default:      request = request & 0x0FFFF;
				  	      break;
			}	
			break;
		case ((int) 'd'):
			switch (request) {
				case DKIOCGGEOM:
					request = S5DKIOCGGEOM;
					break;
				case DKIOCSGEOM:
					request = S5DKIOCSGEOM;
					break;
				case DKIOCSAPART:
					request = S5DKIOCSAPART;
					break;
				case DKIOCGAPART:
					request = S5DKIOCGAPART;
					break;
				case DKIOCSTYPE:
					request = S5HDKIOCSTYPE;
					break;
				case DKIOCGTYPE:
					request = S5HDKIOCGTYPE;
					break;
				case DKIOCSBAD:
					request = S5HDKIOCSBAD;
					break;
				case DKIOCGBAD:
					request = S5HDKIOCGBAD;
					break;
				case DKIOCSCMD:
					request = S5HDKIOCSCMD;
					break;
				case DKIOCGDIAG:
					request = S5HDKIOCGDIAG;
					break;
				case FDKIOGCHAR:
					request = S5FDIOGCHAR;
					break;
				case FDKIOSCHAR:
					request = S5FDIOSCHAR;
					break;
				case FDKEJECT:
					request = S5FDEJECT;
					break;
				case FDKGETCHANGE:
					request = S5FDGETCHANGE;
					break;
				case FDKGETDRIVECHAR:
					request = S5FDGETDRIVECHAR;
					break;
				case FDKSETDRIVECHAR:
					request = S5FDSETDRIVECHAR;
					break;
				case FDKGETSEARCH:
					request = S5FDGETSEARCH;
					break;
				case FDKSETSEARCH:
					request = S5FDSETSEARCH;
					break;
				case FDKIOCSCMD:
					request = S5FDIOCMD;
					break;
				case F_RAW:
					request = S5FDRAW;
					break;
				case DKIOCINFO:
					ret = _ioctl(des, S5DKIOCINFO, &newArgs);
					if (ret != -1) {
						infoArgs = (struct dk_info *)arg;
						infoArgs->dki_ctlr =
							newArgs.dki_addr;
						infoArgs->dki_unit =
							newArgs.dki_unit;
						infoArgs->dki_ctype =
							newArgs.dki_ctype;
						infoArgs->dki_flags =
							newArgs.dki_flags;
					}
					return ret;
					break;
				case DKIOCGCONF:
					ret = _ioctl(des, S5DKIOCINFO, &newArgs);
					if (ret != -1) {
						confArgs = (struct dk_conf *)arg;
						strncpy(confArgs->dkc_cname,
							newArgs.dki_cname,
							DK_DEVLEN);
						strncpy(confArgs->dkc_dname,
							newArgs.dki_dname,
							DK_DEVLEN);
						confArgs->dkc_ctype =
							(u_short)newArgs.dki_ctype;
						confArgs->dkc_flags =
							(u_short)newArgs.dki_flags;
						confArgs->dkc_cnum =
							newArgs.dki_cnum;
						confArgs->dkc_addr =
							newArgs.dki_addr;
						confArgs->dkc_space =
							(u_int)newArgs.dki_space;
						confArgs->dkc_prio =
							newArgs.dki_prio;
						confArgs->dkc_vec =
							newArgs.dki_vec;
						confArgs->dkc_unit =
							newArgs.dki_unit;
						confArgs->dkc_slave =
							newArgs.dki_slave;
					}
					return ret;
					break;
				case DKIOCWCHK:
					/*
					 * This is unsupported in SVR4. It
					 * turns on verify-after-write for
					 * the floppy. I don't think the
					 * system call should fail, however.
					 */
					return 0;
					break;
				case DKIOCGPART:
				case DKIOCSPART:
					return (handle_dkio_partitions(des,
					       request, arg));
				case DKIOCGLOG:
					/* unsupported */
					errno = EINVAL;
					return -1;
					break;
				case DESIOCBLOCK:
				case DESIOCQUICK:
					break; /* no change for these two */
				default:
					request = request & 0x0FFFF; /* try */
					break;
			}
			break;
		case ((int) 'c'):
			switch (request) {
				case CDROMPAUSE:
					request = S5CDROMPAUSE;
					break;
				case CDROMRESUME:
					request = S5CDROMRESUME;
					break;
				case CDROMPLAYMSF:
					request = S5CDROMPLAYMSF;
					break;
				case CDROMPLAYTRKIND:
					request = S5CDROMPLAYTRKIND;
					break;
				case CDROMREADTOCHDR:
					request = S5CDROMREADTOCHDR;
					break;
				case CDROMREADTOCENTRY:
					request = S5CDROMREADTOCENTRY;
					break;
				case CDROMSTOP:
					request = S5CDROMSTOP;
					break;
				case CDROMSTART:
					request = S5CDROMSTART;
					break;
				case CDROMEJECT:
					request = S5CDROMEJECT;
					break;
				case CDROMVOLCTRL:
					request = S5CDROMVOLCTRL;
					break;
				case CDROMSUBCHNL:
					request = S5CDROMSUBCHNL;
					break;
				case CDROMREADMODE1:
					request = S5CDROMREADMODE1;
					break;
				case CDROMREADMODE2:
					request = S5CDROMREADMODE2;
					break;
			}
			break;
		case ((int) 'u'):
			switch (request) {
				case USCSICMD:
				    {
					struct s5_uscsi_cmd s5_cmd;
					struct uscsi_cmd *cmd =
						(struct uscsi_cmd *) arg;
					request = S5USCSICMD;
					s5_cmd.uscsi_cdb = cmd->uscsi_cdb;
					s5_cmd.uscsi_cdblen =
						cmd->uscsi_cdblen;
					s5_cmd.uscsi_bufaddr =
						cmd->uscsi_bufaddr;
					s5_cmd.uscsi_buflen = 
						cmd->uscsi_buflen;
					s5_cmd.uscsi_flags =
						cmd->uscsi_flags;
					ret = _ioctl(des, request, &s5_cmd);
					cmd->uscsi_status = s5_cmd.uscsi_status;
					return(ret);
				    }
			}
			break;
		case ((int) 'k'):
		case ((int) 'v'):
		case ((int) 'F'):
		case ((int) 'G'):
		case ((int) 'X'):
		case ((int) 'L'):
			request = request & 0x0FFFF;
			break;
		case ((int) 'f'):
			if ((request == FIOCLEX) || (request == FIONCLEX))
				return(fcntl(des, F_SETFD,
				    ((request == FIOCLEX) ? 1 : 0)));
			break;
		case ((int) 'g'):
			/* Treat the following 2 ioctls specially for
			 * sunview. */
			if (request == WINGETEXPOSEDRL || 
				request == WINGETDAMAGEDRL) {
				ret = _ioctl(des, request, arg);
				if (errno == N_ENOMSG)
					errno = EFBIG;
				return(ret);	
			}
			break;
	}
	return (_ioctl(des, request, arg));
}


static int
handle_dkio_partitions(int des, int request, int arg)
{
	struct s5_dk_cinfo	cinfo;
	struct dk_allmap	map;
	struct dk_map		*part;
	int			ret;
	extern int		errno;

	part = (struct dk_map *) arg;
	
	ret = _ioctl(des, S5DKIOCINFO, &cinfo);

	if ((cinfo.dki_partition < 0) || (cinfo.dki_partition >= NDKMAP)) {
		errno = EINVAL;
		return (-1);
	}
	
	if (ret != -1) {
		ret = _ioctl(des, S5DKIOCGAPART, &map);
		if (ret != -1) {
			if (request == DKIOCGPART) {
				part->dkl_cylno =
				    map.dka_map[cinfo.dki_partition].dkl_cylno;
				part->dkl_nblk = 
				    map.dka_map[cinfo.dki_partition].dkl_nblk;
			} else {
				map.dka_map[cinfo.dki_partition].dkl_cylno = 
					part->dkl_cylno;
				map.dka_map[cinfo.dki_partition].dkl_nblk =
					part->dkl_nblk;
				ret = _ioctl(des, S5DKIOCSAPART, &map);
			}
		}
	}
	return (ret);
}

static int
tcset(des, request, arg)
	register int	des;
	register int	request;
	int		arg;
{
	struct s5termios	s5termios;
	struct termios		*termios;

	termios = (struct termios *)arg;

	if (termios != NULL) {
		s5termios.c_iflag = termios->c_iflag;
		s5termios.c_oflag = termios->c_oflag;
		s5termios.c_cflag = termios->c_cflag;
		s5termios.c_lflag = termios->c_lflag;
		memcpy(s5termios.c_cc, termios->c_cc, NCCS);
		return (_ioctl(des, request, &s5termios));
	} else
		return (_ioctl(des, request, NULL));

}

static int
tcget(des, request, arg)
	register int	des;
	register int	request;
	int		arg;
{
	struct s5termios	s5termios;
	struct termios		*termios;
	int			ret;

	termios = (struct termios *)arg;

	ret = _ioctl(des, request, &s5termios);

	if (termios != NULL) {
		termios->c_iflag = s5termios.c_iflag;
		termios->c_oflag = s5termios.c_oflag;
		termios->c_cflag = s5termios.c_cflag;
		termios->c_lflag = s5termios.c_lflag;
		memcpy(termios->c_cc, s5termios.c_cc, NCCS);
	}

	return (ret);
}
