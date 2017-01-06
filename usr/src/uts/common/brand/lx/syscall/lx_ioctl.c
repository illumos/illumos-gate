/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/vnode.h>
#include <sys/fcntl.h>
#include <sys/termio.h>
#include <sys/termios.h>
#include <sys/ptyvar.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/sockio.h>
#include <sys/stropts.h>
#include <sys/ptms.h>
#include <sys/cred.h>
#include <sys/cred_impl.h>
#include <sys/sysmacros.h>
#include <sys/lx_misc.h>
#include <sys/lx_ptm.h>
#include <sys/sunddi.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/session.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/if_arp.h>
#include <sys/ioccom.h>
#include <sys/dtrace.h>
#include <sys/ethernet.h>
#include <sys/dlpi.h>
#include <sys/lx_autofs.h>
#include <sys/netstack.h>
#include <inet/ip.h>
#include <inet/ip_if.h>
#include <sys/dkio.h>
#include <sys/sdt.h>

/*
 * Linux ioctl types
 */
#define	LX_IOC_TYPE_HD		0x03
#define	LX_IOC_TYPE_BLK		0x12
#define	LX_IOC_TYPE_FD		0x54
#define	LX_IOC_TYPE_DTRACE	0x68
#define	LX_IOC_TYPE_SOCK	0x89
#define	LX_IOC_TYPE_AUTOFS	0x93

/*
 * Supported ioctls
 */
#define	LX_HDIO_GETGEO		0x0301
#define	LX_BLKGETSIZE		0x1260
#define	LX_BLKSSZGET		0x1268
#define	LX_BLKGETSIZE64		0x80081272
#define	LX_TCGETS		0x5401
#define	LX_TCSETS		0x5402
#define	LX_TCSETSW		0x5403
#define	LX_TCSETSF		0x5404
#define	LX_TCGETA		0x5405
#define	LX_TCSETA		0x5406
#define	LX_TCSETAW		0x5407
#define	LX_TCSETAF		0x5408
#define	LX_TCSBRK		0x5409
#define	LX_TCXONC		0x540a
#define	LX_TCFLSH		0x540b
#define	LX_TIOCEXCL		0x540c
#define	LX_TIOCNXCL		0x540d
#define	LX_TIOCSCTTY		0x540e
#define	LX_TIOCGPGRP		0x540f
#define	LX_TIOCSPGRP		0x5410
#define	LX_TIOCOUTQ		0x5411
#define	LX_TIOCSTI		0x5412
#define	LX_TIOCGWINSZ		0x5413
#define	LX_TIOCSWINSZ		0x5414
#define	LX_TIOCMGET		0x5415
#define	LX_TIOCMBIS		0x5416
#define	LX_TIOCMBIC		0x5417
#define	LX_TIOCMSET		0x5418
#define	LX_TIOCGSOFTCAR		0x5419
#define	LX_TIOCSSOFTCAR		0x541a
#define	LX_FIONREAD		0x541b
#define	LX_TIOCPKT		0x5420
#define	LX_FIONBIO		0x5421
#define	LX_TIOCNOTTY		0x5422
#define	LX_TIOCSETD		0x5423
#define	LX_TIOCGETD		0x5424
#define	LX_TCSBRKP		0x5425
#define	LX_TIOCGSID		0x5429
#define	LX_TIOCGPTN		0x80045430
#define	LX_TIOCSPTLCK		0x40045431
#define	LX_FIONCLEX		0x5450
#define	LX_FIOCLEX		0x5451
#define	LX_FIOASYNC		0x5452
#define	LX_FIOSETOWN		0x8901
#define	LX_SIOCSPGRP		0x8902
#define	LX_FIOGETOWN		0x8903
#define	LX_SIOCGPGRP		0x8904
#define	LX_SIOCATMARK		0x8905
#define	LX_SIOCGSTAMP		0x8906
#define	LX_SIOCADDRT		0x890b
#define	LX_SIOCDELRT		0x890c
#define	LX_SIOCRTMSG		0x890d
#define	LX_SIOCGIFNAME		0x8910
#define	LX_SIOCSIFLINK		0x8911
#define	LX_SIOCGIFCONF		0x8912
#define	LX_SIOCGIFFLAGS		0x8913
#define	LX_SIOCSIFFLAGS		0x8914
#define	LX_SIOCGIFADDR		0x8915
#define	LX_SIOCSIFADDR		0x8916
#define	LX_SIOCGIFDSTADDR	0x8917
#define	LX_SIOCSIFDSTADDR	0x8918
#define	LX_SIOCGIFBRDADDR	0x8919
#define	LX_SIOCSIFBRDADDR	0x891a
#define	LX_SIOCGIFNETMASK	0x891b
#define	LX_SIOCSIFNETMASK	0x891c
#define	LX_SIOCGIFMETRIC	0x891d
#define	LX_SIOCSIFMETRIC	0x891e
#define	LX_SIOCGIFMEM		0x891f
#define	LX_SIOCSIFMEM		0x8920
#define	LX_SIOCGIFMTU		0x8921
#define	LX_SIOCSIFMTU		0x8922
#define	LX_SIOCSIFNAME		0x8923
#define	LX_SIOCSIFHWADDR	0x8924
#define	LX_SIOCGIFENCAP		0x8925
#define	LX_SIOCSIFENCAP		0x8926
#define	LX_SIOCGIFHWADDR	0x8927
#define	LX_SIOCGIFSLAVE		0x8929
#define	LX_SIOCSIFSLAVE		0x8930
#define	LX_SIOCADDMULTI		0x8931
#define	LX_SIOCDELMULTI		0x8932
#define	LX_SIOCGIFINDEX		0x8933
#define	LX_SIOCSIFPFLAGS	0x8934
#define	LX_SIOCGIFPFLAGS	0x8935
#define	LX_SIOCDIFADDR		0x8936
#define	LX_SIOCSIFHWBROADCAST	0x8937
#define	LX_SIOCGIFCOUNT		0x8938
#define	LX_SIOCGIFBR		0x8940
#define	LX_SIOCSIFBR		0x8941
#define	LX_SIOCGIFTXQLEN	0x8942
#define	LX_SIOCSIFTXQLEN	0x8943
#define	LX_SIOCETHTOOL		0x8946
#define	LX_SIOCGMIIPHY		0x8947
#define	LX_SIOCGMIIREG		0x8948
#define	LX_SIOCSMIIREG		0x8949
#define	LX_SIOCWANDEV		0x894a
#define	LX_SIOCOUTQNSD		0x894b
#define	LX_SIOCDARP		0x8953
#define	LX_SIOCGARP		0x8954
#define	LX_SIOCSARP		0x8955
#define	LX_SIOCDRARP		0x8960
#define	LX_SIOCGRARP		0x8961
#define	LX_SIOCSRARP		0x8962
#define	LX_SIOCGIFMAP		0x8970
#define	LX_SIOCSIFMAP		0x8971
#define	LX_SIOCADDDLCI		0x8980
#define	LX_SIOCDELDLCI		0x8981
#define	LX_SIOCGIFVLAN		0x8982
#define	LX_SIOCSIFVLAN		0x8983
#define	LX_SIOCBONDENSLAVE	0x8990
#define	LX_SIOCBONDRELEASE	0x8991
#define	LX_SIOCBONDSETHWADDR	0x8992
#define	LX_SIOCBONDSLAVEINFOQUERY 0x8993
#define	LX_SIOCBONDINFOQUERY	0x8994
#define	LX_SIOCBONDCHANGEACTIVE	0x8995
#define	LX_SIOCBRADDBR		0x89a0
#define	LX_SIOCBRDELBR		0x89a1
#define	LX_SIOCBRADDIF		0x89a2
#define	LX_SIOCBRDELIF		0x89a3
#define	LX_SIOCSHWTSTAMP	0x89b0
#define	LX_SIOCGHWTSTAMP	0x89b1
#define	LX_SIOCDEVPRIVATE	0x89f0
#define	LX_SIOCPROTOPRIVATE	0x89e0

#define	FLUSER(fp)	fp->f_flag | get_udatamodel()
#define	FLFAKE(fp)	fp->f_flag | FKIOCTL

/*
 * LX_NCC must be different from LX_NCCS since while the termio and termios
 * structures may look similar they are fundamentally different sizes and
 * have different members.
 */
#define	LX_NCC	8
#define	LX_NCCS	19

struct lx_termio {
	unsigned short c_iflag;		/* input mode flags */
	unsigned short c_oflag;		/* output mode flags */
	unsigned short c_cflag;		/* control mode flags */
	unsigned short c_lflag;		/* local mode flags */
	unsigned char c_line;		/* line discipline */
	unsigned char c_cc[LX_NCC];	/* control characters */
};

struct lx_termios {
	uint32_t c_iflag;		/* input mode flags */
	uint32_t c_oflag;		/* output mode flags */
	uint32_t c_cflag;		/* control mode flags */
	uint32_t c_lflag;		/* local mode flags */
	unsigned char c_line;		/* line discipline */
	unsigned char c_cc[LX_NCCS];	/* control characters */
};

/*
 * c_cc characters which are valid for lx_termio and lx_termios
 */
#define	LX_VINTR	0
#define	LX_VQUIT	1
#define	LX_VERASE	2
#define	LX_VKILL	3
#define	LX_VEOF		4
#define	LX_VTIME	5
#define	LX_VMIN		6
#define	LX_VSWTC	7

/*
 * c_cc characters which are valid for lx_termios
 */
#define	LX_VSTART	8
#define	LX_VSTOP	9
#define	LX_VSUSP	10
#define	LX_VEOL		11
#define	LX_VREPRINT	12
#define	LX_VDISCARD	13
#define	LX_VWERASE	14
#define	LX_VLNEXT	15
#define	LX_VEOL2	16

/*
 * Defaults needed for SunOS to Linux format conversion.
 * See INIT_C_CC in linux-stable/include/asm-generic/termios.h
 */
#define	LX_DEF_VTIME	0
#define	LX_DEF_VMIN	1
#define	LX_DEF_VEOF	'\004'
#define	LX_DEF_VEOL	0

/* VSD key for lx_cc information */
static uint_t lx_ioctl_vsd = 0;


/* Terminal helpers */

static void
l2s_termios(struct lx_termios *l_tios, struct termios *s_tios)
{
	ASSERT((l_tios != NULL) && (s_tios != NULL));

	bzero(s_tios, sizeof (*s_tios));

	s_tios->c_iflag = l_tios->c_iflag;
	s_tios->c_oflag = l_tios->c_oflag;
	s_tios->c_cflag = l_tios->c_cflag;
	s_tios->c_lflag = l_tios->c_lflag;

	if (s_tios->c_lflag & ICANON) {
		s_tios->c_cc[VEOF] = l_tios->c_cc[LX_VEOF];
		s_tios->c_cc[VEOL] = l_tios->c_cc[LX_VEOL];
	} else {
		s_tios->c_cc[VMIN] = l_tios->c_cc[LX_VMIN];
		s_tios->c_cc[VTIME] = l_tios->c_cc[LX_VTIME];
	}

	s_tios->c_cc[VEOL2] = l_tios->c_cc[LX_VEOL2];
	s_tios->c_cc[VERASE] = l_tios->c_cc[LX_VERASE];
	s_tios->c_cc[VKILL] = l_tios->c_cc[LX_VKILL];
	s_tios->c_cc[VREPRINT] = l_tios->c_cc[LX_VREPRINT];
	s_tios->c_cc[VLNEXT] = l_tios->c_cc[LX_VLNEXT];
	s_tios->c_cc[VWERASE] = l_tios->c_cc[LX_VWERASE];
	s_tios->c_cc[VINTR] = l_tios->c_cc[LX_VINTR];
	s_tios->c_cc[VQUIT] = l_tios->c_cc[LX_VQUIT];
	s_tios->c_cc[VSWTCH] = l_tios->c_cc[LX_VSWTC];
	s_tios->c_cc[VSTART] = l_tios->c_cc[LX_VSTART];
	s_tios->c_cc[VSTOP] = l_tios->c_cc[LX_VSTOP];
	s_tios->c_cc[VSUSP] = l_tios->c_cc[LX_VSUSP];
	s_tios->c_cc[VDISCARD] = l_tios->c_cc[LX_VDISCARD];
}

static void
l2s_termio(struct lx_termio *l_tio, struct termio *s_tio)
{
	ASSERT((l_tio != NULL) && (s_tio != NULL));

	bzero(s_tio, sizeof (*s_tio));

	s_tio->c_iflag = l_tio->c_iflag;
	s_tio->c_oflag = l_tio->c_oflag;
	s_tio->c_cflag = l_tio->c_cflag;
	s_tio->c_lflag = l_tio->c_lflag;

	if (s_tio->c_lflag & ICANON) {
		s_tio->c_cc[VEOF] = l_tio->c_cc[LX_VEOF];
	} else {
		s_tio->c_cc[VMIN] = l_tio->c_cc[LX_VMIN];
		s_tio->c_cc[VTIME] = l_tio->c_cc[LX_VTIME];
	}

	s_tio->c_cc[VINTR] = l_tio->c_cc[LX_VINTR];
	s_tio->c_cc[VQUIT] = l_tio->c_cc[LX_VQUIT];
	s_tio->c_cc[VERASE] = l_tio->c_cc[LX_VERASE];
	s_tio->c_cc[VKILL] = l_tio->c_cc[LX_VKILL];
	s_tio->c_cc[VSWTCH] = l_tio->c_cc[LX_VSWTC];
}

static void
termios2lx_cc(struct lx_termios *l_tios, struct lx_cc *lio)
{
	ASSERT((l_tios != NULL) && (lio != NULL));

	bzero(lio, sizeof (*lio));

	lio->veof = l_tios->c_cc[LX_VEOF];
	lio->veol = l_tios->c_cc[LX_VEOL];
	lio->vmin = l_tios->c_cc[LX_VMIN];
	lio->vtime = l_tios->c_cc[LX_VTIME];
}

static void
termio2lx_cc(struct lx_termio *l_tio, struct lx_cc *lio)
{
	ASSERT((l_tio != NULL) && (lio != NULL));

	bzero(lio, sizeof (*lio));

	lio->veof = l_tio->c_cc[LX_VEOF];
	lio->veol = 0;
	lio->vmin = l_tio->c_cc[LX_VMIN];
	lio->vtime = l_tio->c_cc[LX_VTIME];
}

static void
s2l_termios(struct termios *s_tios, struct lx_termios *l_tios)
{
	ASSERT((s_tios != NULL) && (l_tios != NULL));

	bzero(l_tios, sizeof (*l_tios));

	l_tios->c_iflag = s_tios->c_iflag;
	l_tios->c_oflag = s_tios->c_oflag;
	l_tios->c_cflag = s_tios->c_cflag;
	l_tios->c_lflag = s_tios->c_lflag;

	/*
	 * Since use of the VMIN/VTIME and VEOF/VEOL control characters is
	 * mutually exclusive (determined by ICANON), SunOS aliases them in the
	 * c_cc field in termio/termios.  Linux does not perform this aliasing,
	 * so it expects that the default values are present regardless of
	 * ICANON status.
	 *
	 * These defaults can be overridden later by any values stored via the
	 * lx_cc mechanism.
	 */
	if (s_tios->c_lflag & ICANON) {
		l_tios->c_cc[LX_VEOF] = s_tios->c_cc[VEOF];
		l_tios->c_cc[LX_VEOL] = s_tios->c_cc[VEOL];
		l_tios->c_cc[LX_VTIME] = LX_DEF_VTIME;
		l_tios->c_cc[LX_VMIN] = LX_DEF_VMIN;

	} else {
		l_tios->c_cc[LX_VMIN] = s_tios->c_cc[VMIN];
		l_tios->c_cc[LX_VTIME] = s_tios->c_cc[VTIME];
		l_tios->c_cc[LX_VEOF] = LX_DEF_VEOF;
		l_tios->c_cc[LX_VEOL] = LX_DEF_VEOL;
	}

	l_tios->c_cc[LX_VEOL2] = s_tios->c_cc[VEOL2];
	l_tios->c_cc[LX_VERASE] = s_tios->c_cc[VERASE];
	l_tios->c_cc[LX_VKILL] = s_tios->c_cc[VKILL];
	l_tios->c_cc[LX_VREPRINT] = s_tios->c_cc[VREPRINT];
	l_tios->c_cc[LX_VLNEXT] = s_tios->c_cc[VLNEXT];
	l_tios->c_cc[LX_VWERASE] = s_tios->c_cc[VWERASE];
	l_tios->c_cc[LX_VINTR] = s_tios->c_cc[VINTR];
	l_tios->c_cc[LX_VQUIT] = s_tios->c_cc[VQUIT];
	l_tios->c_cc[LX_VSWTC] = s_tios->c_cc[VSWTCH];
	l_tios->c_cc[LX_VSTART] = s_tios->c_cc[VSTART];
	l_tios->c_cc[LX_VSTOP] = s_tios->c_cc[VSTOP];
	l_tios->c_cc[LX_VSUSP] = s_tios->c_cc[VSUSP];
	l_tios->c_cc[LX_VDISCARD] = s_tios->c_cc[VDISCARD];
}

static void
s2l_termio(struct termio *s_tio, struct lx_termio *l_tio)
{
	ASSERT((s_tio != NULL) && (l_tio != NULL));

	bzero(l_tio, sizeof (*l_tio));

	l_tio->c_iflag = s_tio->c_iflag;
	l_tio->c_oflag = s_tio->c_oflag;
	l_tio->c_cflag = s_tio->c_cflag;
	l_tio->c_lflag = s_tio->c_lflag;

	if (s_tio->c_lflag & ICANON) {
		l_tio->c_cc[LX_VEOF] = s_tio->c_cc[VEOF];
		l_tio->c_cc[LX_VTIME] = LX_DEF_VTIME;
		l_tio->c_cc[LX_VMIN] = LX_DEF_VMIN;
	} else {
		l_tio->c_cc[LX_VMIN] = s_tio->c_cc[VMIN];
		l_tio->c_cc[LX_VTIME] = s_tio->c_cc[VTIME];
		l_tio->c_cc[LX_VEOF] = LX_DEF_VEOF;
	}

	l_tio->c_cc[LX_VINTR] = s_tio->c_cc[VINTR];
	l_tio->c_cc[LX_VQUIT] = s_tio->c_cc[VQUIT];
	l_tio->c_cc[LX_VERASE] = s_tio->c_cc[VERASE];
	l_tio->c_cc[LX_VKILL] = s_tio->c_cc[VKILL];
	l_tio->c_cc[LX_VSWTC] = s_tio->c_cc[VSWTCH];
}

static void
set_lx_cc(vnode_t *vp, struct lx_cc *lio)
{
	struct lx_cc *cur;
	/*
	 * Linux expects that the termio/termios control characters are
	 * preserved more strictly than illumos supports.  In order to preserve
	 * the illusion that the characters are maintained, they are stored as
	 * vnode-specific data.
	 */
	mutex_enter(&vp->v_vsd_lock);
	cur = (struct lx_cc *)vsd_get(vp, lx_ioctl_vsd);
	if (cur == NULL) {
		cur = kmem_alloc(sizeof (struct lx_cc), KM_SLEEP);
		bcopy(lio, cur, sizeof (struct lx_cc));
		(void) vsd_set(vp, lx_ioctl_vsd, cur);
	} else {
		bcopy(lio, cur, sizeof (struct lx_cc));
	}
	mutex_exit(&vp->v_vsd_lock);
}

static int
get_lx_cc(vnode_t *vp, struct lx_cc *lio)
{
	struct lx_cc *cur;
	int rv = 1;
	mutex_enter(&vp->v_vsd_lock);
	cur = (struct lx_cc *)vsd_get(vp, lx_ioctl_vsd);
	if (cur != NULL) {
		bcopy(cur, lio, sizeof (*lio));
		rv = 0;
	}
	mutex_exit(&vp->v_vsd_lock);
	return (rv);
}

/* Socket helpers */

typedef struct lx_ifreq32 {
	char	ifr_name[IFNAMSIZ];
	union {
		struct	sockaddr ifru_addr;
	} ifr_ifrn;
} lx_ifreq32_t;

typedef struct lx_ifreq64 {
	char	ifr_name[IFNAMSIZ];
	union {
		struct	sockaddr ifru_addr;
		/* pad this out to the Linux size */
		uint64_t	ifmap[3];
	} ifr_ifrn;
} lx_ifreq64_t;

typedef struct lx_ifconf32 {
	int32_t	if_len;
	caddr32_t if_buf;
} lx_ifconf32_t;

typedef struct lx_ifconf64 {
	int32_t	if_len;
	caddr_t if_buf;
} lx_ifconf64_t;


/* Generic translators */

/* ARGSUSED */
static int
ict_pass(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	int error = 0;
	int rv;

	error = VOP_IOCTL(fp->f_vnode, cmd, arg, FLUSER(fp), fp->f_cred, &rv,
	    NULL);
	return ((error != 0) ? set_errno(error) : 0);
}

/* ARGSUSED */
static int
ict_fionbio(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	vnode_t *vp;
	int32_t iflag, flags;
	int error;

	if (copyin((caddr_t)arg, &iflag, sizeof (iflag)))
		return (set_errno(EFAULT));

	mutex_enter(&fp->f_tlock);
	vp = fp->f_vnode;
	flags = fp->f_flag;
	/* Linux sets NONBLOCK instead of FIONBIO */
	if (iflag)
		flags |= FNONBLOCK;
	else
		flags &= ~FNONBLOCK;
	/* push the flag down */
	error = VOP_SETFL(vp, fp->f_flag, flags, fp->f_cred, NULL);
	fp->f_flag = flags;
	mutex_exit(&fp->f_tlock);
	return ((error != 0) ? set_errno(error) : 0);
}

/* ARGSUSED */
static int
ict_fionread(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	vnode_t *vp;
	struct vattr vattr;
	int error = 0;
	int rv;
	/*
	 * offset is int32_t because that is what FIONREAD is defined in terms
	 * of.  We cap at INT_MAX as in other cases for this ioctl.
	 */
	int32_t offset;

	vp = fp->f_vnode;

	if (vp->v_type == VREG || vp->v_type == VDIR) {
		vattr.va_mask = AT_SIZE;
		error = VOP_GETATTR(vp, &vattr, 0, fp->f_cred, NULL);
		if (error != 0)
			return (set_errno(error));
		offset = MIN(vattr.va_size - fp->f_offset, INT_MAX);
		if (copyout(&offset, (caddr_t)arg, sizeof (offset)))
			return (set_errno(EFAULT));
	} else {
		error = VOP_IOCTL(vp, FIONREAD, arg, FLUSER(fp), fp->f_cred,
		    &rv, NULL);
		if (error)
			return (set_errno(error));
	}
	return (0);
}

/*
 * hard disk-related translators
 *
 * Note that the normal disk ioctls only work for VCHR devices. See spec_ioctl
 * which will return ENOTTY for a VBLK device. However, fdisk, etc. expect to
 * work with block devices.
 *
 * We expect a zvol to be the primary block device we're interacting with and
 * we use the zone's lxzd_vdisks list to handle zvols specifically.
 */

typedef struct lx_hd_geom {
	unsigned char heads;
	unsigned char sectors;
	unsigned short cylinders;
	unsigned long start;
} lx_hd_geom_t;

static lx_virt_disk_t *
lx_lookup_zvol(lx_zone_data_t *lxzd, dev_t dev)
{
	lx_virt_disk_t *vd;

	vd = list_head(lxzd->lxzd_vdisks);
	while (vd != NULL) {
		if (vd->lxvd_type == LXVD_ZVOL && vd->lxvd_real_dev == dev)
			return (vd);
		vd = list_next(lxzd->lxzd_vdisks, vd);
	}

	return (NULL);
}

/*
 * See zvol_ioctl() which always fails for DKIOCGGEOM. The geometry for a
 * zvol (or really any modern disk) is made up, so we do that here as well.
 */
/* ARGSUSED */
static int
ict_hdgetgeo(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	lx_hd_geom_t lx_geom;
	lx_zone_data_t *lxzd;

	if (fp->f_vnode->v_type != VCHR && fp->f_vnode->v_type != VBLK)
		return (set_errno(EINVAL));

	lxzd = ztolxzd(curproc->p_zone);
	ASSERT(lxzd != NULL);
	ASSERT(lxzd->lxzd_vdisks != NULL);

	if (getmajor(fp->f_vnode->v_rdev) == getmajor(lxzd->lxzd_zfs_dev)) {
		lx_virt_disk_t *vd;

		vd = lx_lookup_zvol(lxzd, fp->f_vnode->v_rdev);
		if (vd == NULL) {
			/* should only happen if new zvol */
			bzero(&lx_geom, sizeof (lx_geom));
		} else {
			diskaddr_t tot;

			tot = vd->lxvd_volsize / vd->lxvd_blksize;

			/*
			 * Since the 'sectors' value is only one byte we make
			 * up heads/cylinder values to get things to fit.
			 * We roundup the number of heads to ensure we don't
			 * overflow the sectors due to truncation.
			 */
			lx_geom.heads = lx_geom.cylinders = (tot / 0xff) + 1;
			lx_geom.sectors = tot / lx_geom.heads;
			lx_geom.start = 0;
		}
	} else {
		int res, rv;
		struct dk_geom geom;

		res = VOP_IOCTL(fp->f_vnode, DKIOCGGEOM, (intptr_t)&geom,
		    fp->f_flag | FKIOCTL, fp->f_cred, &rv, NULL);
		if (res > 0)
			return (set_errno(res));

		lx_geom.heads = geom.dkg_nhead;
		lx_geom.sectors = geom.dkg_nsect;
		lx_geom.cylinders = geom.dkg_ncyl;
		lx_geom.start = 0;
	}

	if (copyout(&lx_geom, (caddr_t)arg, sizeof (lx_geom)))
		return (set_errno(EFAULT));
	return (0);
}

/*
 * Per the Linux sd(4) man page, get the number of sectors. The linux/fs.h
 * header says its 512 byte blocks.
 */
/* ARGSUSED */
static int
ict_blkgetsize(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	diskaddr_t tot;
	lx_zone_data_t *lxzd;

	if (fp->f_vnode->v_type != VCHR && fp->f_vnode->v_type != VBLK)
		return (set_errno(EINVAL));

	lxzd = ztolxzd(curproc->p_zone);
	ASSERT(lxzd != NULL);
	ASSERT(lxzd->lxzd_vdisks != NULL);

	if (getmajor(fp->f_vnode->v_rdev) == getmajor(lxzd->lxzd_zfs_dev)) {
		lx_virt_disk_t *vd;

		vd = lx_lookup_zvol(lxzd, fp->f_vnode->v_rdev);
		if (vd == NULL) {
			/* should only happen if new zvol */
			tot = 0;
		} else {
			tot = vd->lxvd_volsize / 512;
		}
	} else {
		int res, rv;
		struct dk_minfo minfo;

		res = VOP_IOCTL(fp->f_vnode, DKIOCGMEDIAINFO, (intptr_t)&minfo,
		    fp->f_flag | FKIOCTL, fp->f_cred, &rv, NULL);
		if (res > 0)
			return (set_errno(res));

		tot = minfo.dki_capacity;
		if (minfo.dki_lbsize > 512) {
			uint_t bsize = minfo.dki_lbsize / 512;

			tot *= bsize;
		}
	}

	if (copyout(&tot, (caddr_t)arg, sizeof (long)))
		return (set_errno(EFAULT));
	return (0);
}

/*
 * Get the sector size (i.e. the logical block size).
 */
/* ARGSUSED */
static int
ict_blkgetssize(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	uint_t bsize;
	lx_zone_data_t *lxzd;

	if (fp->f_vnode->v_type != VCHR && fp->f_vnode->v_type != VBLK)
		return (set_errno(EINVAL));

	lxzd = ztolxzd(curproc->p_zone);
	ASSERT(lxzd != NULL);
	ASSERT(lxzd->lxzd_vdisks != NULL);

	if (getmajor(fp->f_vnode->v_rdev) == getmajor(lxzd->lxzd_zfs_dev)) {
		lx_virt_disk_t *vd;

		vd = lx_lookup_zvol(lxzd, fp->f_vnode->v_rdev);
		if (vd == NULL) {
			/* should only happen if new zvol */
			bsize = 0;
		} else {
			bsize = (uint_t)vd->lxvd_blksize;
		}
	} else {
		int res, rv;
		struct dk_minfo minfo;

		res = VOP_IOCTL(fp->f_vnode, DKIOCGMEDIAINFO, (intptr_t)&minfo,
		    fp->f_flag | FKIOCTL, fp->f_cred, &rv, NULL);
		if (res > 0)
			return (set_errno(res));

		bsize = (uint_t)minfo.dki_lbsize;
	}

	if (copyout(&bsize, (caddr_t)arg, sizeof (bsize)))
		return (set_errno(EFAULT));
	return (0);
}

/*
 * Get the size. The linux/fs.h header says its in bytes.
 */
/* ARGSUSED */
static int
ict_blkgetsize64(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	uint64_t tot;
	lx_zone_data_t *lxzd;

	if (fp->f_vnode->v_type != VCHR && fp->f_vnode->v_type != VBLK)
		return (set_errno(EINVAL));

	lxzd = ztolxzd(curproc->p_zone);
	ASSERT(lxzd != NULL);
	ASSERT(lxzd->lxzd_vdisks != NULL);

	if (getmajor(fp->f_vnode->v_rdev) == getmajor(lxzd->lxzd_zfs_dev)) {
		lx_virt_disk_t *vd;

		vd = lx_lookup_zvol(lxzd, fp->f_vnode->v_rdev);
		if (vd == NULL) {
			/* should only happen if new zvol */
			tot = 0;
		} else {
			tot = vd->lxvd_volsize;
		}
	} else {
		int res, rv;
		struct dk_minfo minfo;

		res = VOP_IOCTL(fp->f_vnode, DKIOCGMEDIAINFO, (intptr_t)&minfo,
		    fp->f_flag | FKIOCTL, fp->f_cred, &rv, NULL);
		if (res > 0)
			return (set_errno(res));

		tot = minfo.dki_capacity * minfo.dki_lbsize;
	}

	if (copyout(&tot, (caddr_t)arg, sizeof (uint64_t)))
		return (set_errno(EFAULT));
	return (0);
}

/* ARGSUSED */
/* Terminal-related translators */

/* ARGSUSED */
static int
ict_tcsets(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct lx_termios	l_tios;
	struct termios		s_tios;
	struct lx_cc		lio;
	int			error, rv;

	ASSERT(cmd == TCSETS || cmd == TCSETSW || cmd == TCSETSF);

	if (copyin((struct lx_termios *)arg, &l_tios, sizeof (l_tios)) != 0)
		return (set_errno(EFAULT));
	termios2lx_cc(&l_tios, &lio);
	l2s_termios(&l_tios, &s_tios);

	error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&s_tios,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);
	if (error)
		return (set_errno(error));
	/* preserve lx_cc */
	set_lx_cc(fp->f_vnode, &lio);

	return (0);
}

/* ARGSUSED */
static int
ict_tcseta(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct lx_termio	l_tio;
	struct termio		s_tio;
	struct lx_cc		lio;
	int			error, rv;

	ASSERT(cmd == TCSETA || cmd == TCSETAW || cmd == TCSETAF);

	if (copyin((struct lx_termio *)arg, &l_tio, sizeof (l_tio)) != 0)
		return (set_errno(EFAULT));
	l2s_termio(&l_tio, &s_tio);
	termio2lx_cc(&l_tio, &lio);

	error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&s_tio,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);
	if (error)
		return (set_errno(error));
	/* preserve lx_cc */
	set_lx_cc(fp->f_vnode, &lio);

	return (0);
}

/* ARGSUSED */
static int
ict_tcgets_ptm(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct lx_termios	l_tios;
	struct termios		s_tios, *s_tiosd;
	uint_t			s_tiosl;

	/* get termios defaults */
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_NOTPROM, "ttymodes", (uchar_t **)&s_tiosd,
	    &s_tiosl) != DDI_SUCCESS)
		return (EIO);
	ASSERT(s_tiosl == sizeof (*s_tiosd));
	bcopy(s_tiosd, &s_tios, sizeof (s_tios));
	ddi_prop_free(s_tiosd);

	/* Now munge the data to how Linux wants it. */
	s2l_termios(&s_tios, &l_tios);
	if (copyout(&l_tios, (struct lx_termios *)arg, sizeof (l_tios)) != 0)
		return (set_errno(EFAULT));

	return (0);
}

/* ARGSUSED */
static int
ict_tcgets_native(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct lx_termios	l_tios;
	struct termios		s_tios;
	struct lx_cc		lio;
	int			error, rv;

	error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&s_tios,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);
	if (error)
		return (set_errno(error));

	/* Now munge the data to how Linux wants it. */
	s2l_termios(&s_tios, &l_tios);

	/* return preserved lx_cc */
	if (get_lx_cc(fp->f_vnode, &lio) == 0) {
		l_tios.c_cc[LX_VEOF] = lio.veof;
		l_tios.c_cc[LX_VEOL] = lio.veol;
		l_tios.c_cc[LX_VMIN] = lio.vmin;
		l_tios.c_cc[LX_VTIME] = lio.vtime;
	}

	if (copyout(&l_tios, (struct lx_termios *)arg, sizeof (l_tios)) != 0)
		return (set_errno(EFAULT));

	return (0);
}

/* ARGSUSED */
static int
ict_tcgets(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	if (getmajor(fp->f_vnode->v_rdev) == ddi_name_to_major(LX_PTM_DRV))
		return (ict_tcgets_ptm(fp, cmd, arg, lxcmd));
	else
		return (ict_tcgets_native(fp, cmd, arg, lxcmd));
}

/* ARGSUSED */
static int
ict_tcgeta(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct lx_termio	l_tio;
	struct termio		s_tio;
	struct lx_cc		lio;
	int			error, rv;

	error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&s_tio,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);
	if (error)
		return (set_errno(error));

	s2l_termio(&s_tio, &l_tio);
	/* return preserved lx_cc */
	if (get_lx_cc(fp->f_vnode, &lio) == 0) {
		l_tio.c_cc[LX_VEOF] = lio.veof;
		l_tio.c_cc[LX_VMIN] = lio.vmin;
		l_tio.c_cc[LX_VTIME] = lio.vtime;
	}

	if (copyout(&l_tio, (struct lx_termios *)arg, sizeof (l_tio)) != 0)
		return (set_errno(EFAULT));

	return (0);
}

/* ARGSUSED */
static int
ict_tiocspgrp(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	pid_t lpid, spid, tid;
	int error, rv;

	/* Converting to the illumos pid is necessary */
	if (copyin((pid_t *)arg, &lpid, sizeof (lpid)) < 0)
		return (set_errno(EFAULT));
	if (lx_lpid_to_spair(lpid, &spid, &tid) < 0)
		return (set_errno(EPERM));

	error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&spid,
	    fp->f_flag |FKIOCTL, fp->f_cred, &rv, NULL);
	return ((error != 0) ? set_errno(error) : 0);
}

/* ARGSUSED */
static int
ict_tcsbrkp(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	int rv, error;
	/* use null duration to emulate TCSBRKP */
	int dur = 0;
	error = VOP_IOCTL(fp->f_vnode, TCSBRK, (intptr_t)&dur,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);
	return ((error != 0) ? set_errno(error) : 0);
}

/* ARGSUSED */
static int
ict_tiocgpgrp(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	pid_t	spgrp;
	int	error, rv;

	error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&spgrp, FLFAKE(fp),
	    fp->f_cred, &rv, NULL);
	if (error == 0) {
		if (spgrp == curproc->p_zone->zone_proc_initpid) {
			spgrp = 1;
		}
		if (copyout(&spgrp, (caddr_t)arg, sizeof (spgrp))) {
			return (set_errno(EFAULT));
		}
	}
	return ((error != 0) ? set_errno(error) : 0);
}

/* ARGSUSED */
static int
ict_sptlock(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct strioctl istr;
	int error, rv;

	istr.ic_cmd = UNLKPT;
	istr.ic_len = 0;
	istr.ic_timout = 0;
	istr.ic_dp = NULL;
	error = VOP_IOCTL(fp->f_vnode, I_STR, (intptr_t)&istr,
	    fp->f_flag |FKIOCTL, fp->f_cred, &rv, NULL);
	/*
	 * The success/fail return values are different between Linux
	 * and illumos.   Linux expects 0 or -1.  Illumos can return
	 * positive number on success.
	 */
	return ((error != 0) ? set_errno(error) : 0);
}

/* ARGSUSED */
static int
ict_gptn(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct strioctl istr;
	cred_t *cr;
	pt_own_t pto;
	int error, rv;
	int ptyno;
	lx_zone_data_t *lxzd = ztolxzd(curproc->p_zone);

	/* This operation is only valid for the lx_ptm device. */
	if (getmajor(fp->f_vnode->v_rdev) != ddi_name_to_major(LX_PTM_DRV))
		return (set_errno(ENOTTY));

	cr = CRED();
	pto.pto_ruid = cr->cr_uid;
	/*
	 * Both Linux and our native code (see grantpt() in native libc)
	 * prefer assigning the "tty" gid to the new pty. On Linux this is
	 * done by udev. Since we're in the kernel we cannot lookup the gid, so
	 * we rely on the lx_support program to initialize the value in the
	 * zone data at boot time.
	 */
	if (lxzd->lxzd_ttygrp == 0) {
		pto.pto_rgid = cr->cr_gid;
	} else {
		pto.pto_rgid = lxzd->lxzd_ttygrp;
	}

	istr.ic_cmd = OWNERPT;
	istr.ic_len = sizeof (pto);
	istr.ic_timout = 0;
	istr.ic_dp = (char *)&pto;
	error = VOP_IOCTL(fp->f_vnode, I_STR, (intptr_t)&istr,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);

	if (error)
		return (set_errno((error == ENOTTY) ? error: EACCES));

	ptyno = getminor(fp->f_vnode->v_rdev) - 1;
	if (copyout(&ptyno, (caddr_t)arg, sizeof (ptyno)))
		return (set_errno(EFAULT));

	return (0);
}

/* ARGSUSED */
static int
ict_tiocgwinsz(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	int error, rv;

	error = VOP_IOCTL(fp->f_vnode, cmd, arg, FLUSER(fp), fp->f_cred, &rv,
	    NULL);

	/*
	 * A few Linux libc's (e.g. musl) have chosen to implement isatty()
	 * using the TIOCGWINSZ ioctl. Some apps also do the same thing
	 * directly. On Linux that ioctl will return a size of 0x0 for dumb
	 * terminals but on illumos see the handling for TIOCGWINSZ in ptem's
	 * ptioc(). We fail if the winsize is all zeros. To emulate the Linux
	 * behavior use the native ioctl check that we do for isatty and return
	 * a size of 0x0 if that succeeds.
	 */
	if (error == EINVAL) {
		int err;
		struct termio s_tio;

		err = VOP_IOCTL(fp->f_vnode, TCGETA, (intptr_t)&s_tio,
		    FLFAKE(fp), fp->f_cred, &rv, NULL);

		if (err == 0) {
			struct winsize w;

			bzero(&w, sizeof (w));
			if (copyout(&w, (struct winsize *)arg, sizeof (w)) != 0)
				return (set_errno(EFAULT));
			return (0);
		}
	}

	if (error != 0)
		return (set_errno(error));

	return (0);
}

/* ARGSUSED */
static int
ict_tiocsctty(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	pid_t	ttysid, mysid;
	int	error, rv;
	proc_t *p = curproc;

	/* getsid */
	mutex_enter(&p->p_splock);
	mysid = p->p_sessp->s_sid;
	mutex_exit(&p->p_splock);

	/*
	 * Report success if we already control the tty.
	 * If no one controls it, TIOCSCTTY will change that later.
	 */
	error = VOP_IOCTL(fp->f_vnode, TIOCGSID, (intptr_t)&ttysid,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);
	if (error == 0 && ttysid == mysid)
		return (0);

	/*
	 * Need to make sure we're a session leader, otherwise the
	 * TIOCSCTTY ioctl will fail.
	 */
	mutex_enter(&pidlock);
	if (p->p_sessp->s_sidp != p->p_pidp && !pgmembers(p->p_pid)) {
		mutex_exit(&pidlock);
		sess_create();
	} else {
		mutex_exit(&pidlock);
	}

	error = VOP_IOCTL(fp->f_vnode, cmd, 0, FLUSER(fp),
	    fp->f_cred, &rv, NULL);
	return ((error != 0) ? set_errno(error) : 0);
}

/* Socket-related translators */

/* ARGSUSED */
static int
ict_siocatmark(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	vnode_t *vp = fp->f_vnode;
	int error, rv;
	/*
	 * Linux expects a SIOCATMARK of a UDP socket to return ENOTTY, while
	 * Illumos allows it. Linux prior to 2.6.39 returned EINVAL for this.
	 */
	if (vp->v_type != VSOCK || VTOSO(vp)->so_type != SOCK_STREAM)
		return (set_errno(ENOTTY));

	error = VOP_IOCTL(fp->f_vnode, cmd, arg, FLUSER(fp), fp->f_cred, &rv,
	    NULL);
	if (error)
		return (set_errno(error));

	return (0);
}

static int
ict_if_ioctl(vnode_t *vn, int cmd, intptr_t arg, int flags, cred_t *cred)
{
	int error, rv;
	lx_zone_data_t *lxzd = ztolxzd(curproc->p_zone);
	ksocket_t ks;

	ASSERT(lxzd != NULL);

	/*
	 * For ioctls of this type, we are strict about address family
	 * whereas Linux is lenient.  This strictness can be avoided by using
	 * an internal AF_INET ksocket, which we use if the family is anything
	 * but AF_PACKET.
	 */
	if (vn->v_type == VSOCK && VTOSO(vn)->so_family == AF_PACKET)
		return (VOP_IOCTL(vn, cmd, arg, flags, cred, &rv, NULL));

	mutex_enter(&lxzd->lxzd_lock);
	ks = lxzd->lxzd_ioctl_sock;
	if (ks == NULL) {
		/*
		 * Linux is not at all picky about address family when it comes
		 * to supporting interface-related ioctls. To mimic this
		 * behavior, we'll attempt those ioctls against a ksocket
		 * configured for that purpose.
		 */
		(void) ksocket_socket(&lxzd->lxzd_ioctl_sock, AF_INET,
		    SOCK_DGRAM, 0, 0, curproc->p_zone->zone_kcred);
		ks = lxzd->lxzd_ioctl_sock;
	}
	mutex_exit(&lxzd->lxzd_lock);

	if (ks != NULL) {
		error = ksocket_ioctl(ks, cmd, arg, &rv, cred);
	} else {
		error = VOP_IOCTL(vn, cmd, arg, flags, cred, &rv, NULL);
	}

	return (error);
}

static int
ict_sioghwaddr(file_t *fp, struct lifreq *lreq)
{
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)&lreq->lifr_addr;
	struct sockaddr hwaddr;
	int error, size;

	error = ict_if_ioctl(fp->f_vnode, SIOCGLIFHWADDR, (intptr_t)lreq,
	    FLFAKE(fp), fp->f_cred);

	if (error == EADDRNOTAVAIL &&
	    strncmp(lreq->lifr_name, "lo", 2) == 0) {
		/* Emulate success on suspected loopbacks */
		sdl->sdl_type = DL_LOOP;
		sdl->sdl_alen = ETHERADDRL;
		bzero(LLADDR(sdl), sdl->sdl_alen);
		error = 0;
	}

	if (error == 0) {
		bzero(&hwaddr, sizeof (hwaddr));
		lx_stol_hwaddr(sdl, &hwaddr, &size);
		bcopy(&hwaddr, &lreq->lifr_addr,
		    size + sizeof (sdl->sdl_family));
	}

	return (error);
}

/* ARGSUSED */
static int
ict_siocgifname(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct ifreq	req;
	int		len;
	char		name[LIFNAMSIZ];
	netstack_t *ns;
	ip_stack_t *ipst;
	phyint_t *phyi;

	if (fp->f_vnode->v_type != VSOCK) {
		return (set_errno(EINVAL));
	}

	len = (curproc->p_model == DATAMODEL_LP64) ? sizeof (lx_ifreq64_t) :
	    sizeof (lx_ifreq32_t);
	if (copyin((struct ifreq *)arg, &req, len) != 0) {
		return (set_errno(EFAULT));
	}

	/*
	 * Since Linux calls this ioctl on all sorts of sockets, perform the
	 * interface name lookup manually.
	 */
	if ((ns = netstack_get_current()) == NULL) {
		return (set_errno(EINVAL));
	}
	ipst = ns->netstack_ip;

	rw_enter(&ipst->ips_ill_g_lock, RW_READER);
	phyi = avl_find(&ipst->ips_phyint_g_list->phyint_list_avl_by_index,
	    (void *) &req.ifr_index, NULL);
	if (phyi != NULL) {
		(void) strncpy(name, phyi->phyint_name, LIFNAMSIZ);
		lx_ifname_convert(name, LX_IF_FROMNATIVE);
	} else {
		name[0] = '\0';
	}

	rw_exit(&ipst->ips_ill_g_lock);
	netstack_rele(ns);

	if (strlen(name) != 0) {
		/* Truncate for ifreq and copyout */
		(void) strncpy(req.ifr_name, name, IFNAMSIZ);
		if (copyout(&req, (struct ifreq *)arg, len) != 0) {
			return (set_errno(EFAULT));
		}
		return (0);
	}

	return (set_errno(EINVAL));
}

/* ARGSUSED */
static int
ict_siolifreq(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct ifreq	req;
	struct lifreq	lreq;
	int		error, len;

	/* Convert from Linux ifreq to illumos lifreq */
	if (curproc->p_model == DATAMODEL_LP64)
		len = sizeof (lx_ifreq64_t);
	else
		len = sizeof (lx_ifreq32_t);
	if (copyin((struct ifreq *)arg, &req, len) != 0)
		return (set_errno(EFAULT));
	bzero(&lreq, sizeof (lreq));
	(void) strncpy(lreq.lifr_name, req.ifr_name, IFNAMSIZ);
	bcopy(&req.ifr_ifru, &lreq.lifr_lifru, len - IFNAMSIZ);
	lx_ifname_convert(lreq.lifr_name, LX_IF_TONATIVE);

	switch (cmd) {
	case SIOCGIFADDR:
	case SIOCSIFADDR:
	case SIOCGIFDSTADDR:
	case SIOCSIFDSTADDR:
	case SIOCGIFBRDADDR:
	case SIOCSIFBRDADDR:
	case SIOCGIFNETMASK:
	case SIOCSIFNETMASK:
	case SIOCGIFMETRIC:
	case SIOCSIFMETRIC:
	case SIOCGIFMTU:
	case SIOCSIFMTU:
		/*
		 * Convert cmd from SIO*IF* to SIO*LIF*.
		 * This is needed since Linux allows ifreq operations on ipv6
		 * sockets where illumos does not.
		 */
		cmd = ((cmd & IOC_INOUT) |
		    _IOW('i', ((cmd & 0xff) + 100), struct lifreq));
		error = ict_if_ioctl(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred);
		break;
	case SIOCGIFINDEX:
		cmd = SIOCGLIFINDEX;
		error = ict_if_ioctl(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred);
		break;
	case SIOCGIFFLAGS:
		cmd = SIOCGLIFFLAGS;
		error = ict_if_ioctl(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred);
		if (error == 0)
			lx_ifflags_convert(&lreq.lifr_flags, LX_IF_FROMNATIVE);
		break;
	case SIOCSIFFLAGS:
		cmd = SIOCSLIFFLAGS;
		lx_ifflags_convert(&lreq.lifr_flags, LX_IF_TONATIVE);
		error = ict_if_ioctl(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred);
		break;
	case SIOCGIFHWADDR:
		error = ict_sioghwaddr(fp, &lreq);
		break;
	case LX_SIOCGIFTXQLEN:
		/*
		 * Illumos lacks the notion of txqlen.  Confirm the provided
		 * interface is valid with SIOCGLIFINDEX and return a fake
		 * txqlen of 1.  Loopback devices will report txqlen of 0.
		 */
		if (strncmp(lreq.lifr_name, "lo", 2) == 0) {
			lreq.lifr_index = 0;
			error = 0;
			break;
		}
		cmd = SIOCGLIFINDEX;
		error = ict_if_ioctl(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred);
		if (error == 0) {
			/* lifr_index aliases to the qlen field */
			lreq.lifr_index = 1;
		}
		break;
	case LX_SIOCSIFHWADDR:
		/*
		 * We're not going to support SIOCSIFHWADDR, but we need to be
		 * able to check the result of the copyin first to see if the
		 * command should have returned EFAULT.
		 */
	default:
		error = EINVAL;
	}

	if (error != 0)
		return (set_errno(error));

	/* Convert back to a Linux ifreq */
	lx_ifname_convert(lreq.lifr_name, LX_IF_FROMNATIVE);
	bzero(&req, sizeof (req));
	(void) strncpy(req.ifr_name, lreq.lifr_name, IFNAMSIZ);
	bcopy(&lreq.lifr_lifru, &req.ifr_ifru, len - IFNAMSIZ);

	if (copyout(&req, (struct lifreq *)arg, len) != 0)
		return (set_errno(EFAULT));

	return (0);
}

/* ARGSUSED */
static int
ict_siocgifconf32(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	lx_ifconf32_t	conf;
	lx_ifreq32_t	*oreq;
	struct ifconf	sconf;
	int		ifcount, error, i, buf_len;

	if (copyin((lx_ifconf32_t *)arg, &conf, sizeof (conf)) != 0)
		return (set_errno(EFAULT));

	/* They want to know how many interfaces there are. */
	if (conf.if_len <= 0 || conf.if_buf == NULL) {
		error = ict_if_ioctl(fp->f_vnode, SIOCGIFNUM,
		    (intptr_t)&ifcount, FLFAKE(fp), fp->f_cred);
		if (error != 0)
			return (set_errno(error));

		conf.if_len = ifcount * sizeof (lx_ifreq32_t);

		if (copyout(&conf, (lx_ifconf32_t *)arg, sizeof (conf)) != 0)
			return (set_errno(EFAULT));
		return (0);
	} else {
		ifcount = conf.if_len / sizeof (lx_ifreq32_t);
	}

	/* Get interface configuration list. */
	sconf.ifc_len = ifcount * sizeof (struct ifreq);
	sconf.ifc_req = (struct ifreq *)kmem_alloc(sconf.ifc_len, KM_SLEEP);

	error = ict_if_ioctl(fp->f_vnode, cmd, (intptr_t)&sconf, FLFAKE(fp),
	    fp->f_cred);
	if (error != 0) {
		kmem_free(sconf.ifc_req, ifcount * sizeof (struct ifreq));
		return (set_errno(error));
	}

	/* Convert data to Linux format & rename interfaces */
	buf_len = ifcount * sizeof (lx_ifreq32_t);
	oreq = (lx_ifreq32_t *)kmem_alloc(buf_len, KM_SLEEP);
	for (i = 0; i < sconf.ifc_len / sizeof (struct ifreq); i++) {
		bcopy(&sconf.ifc_req[i], oreq + i, sizeof (lx_ifreq32_t));
		lx_ifname_convert(oreq[i].ifr_name, LX_IF_FROMNATIVE);
	}
	conf.if_len = i * sizeof (*oreq);
	kmem_free(sconf.ifc_req, ifcount * sizeof (struct ifreq));

	error = 0;
	if (copyout(oreq, (caddr_t)(uintptr_t)conf.if_buf, conf.if_len) != 0 ||
	    copyout(&conf, (lx_ifconf32_t *)arg, sizeof (conf)) != 0)
		error = set_errno(EFAULT);

	kmem_free(oreq, buf_len);
	return (error);
}

/* ARGSUSED */
static int
ict_siocgifconf64(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	lx_ifconf64_t	conf;
	lx_ifreq64_t	*oreq;
	struct ifconf	sconf;
	int		ifcount, error, i, buf_len;

	if (copyin((lx_ifconf64_t *)arg, &conf, sizeof (conf)) != 0)
		return (set_errno(EFAULT));

	/* They want to know how many interfaces there are. */
	if (conf.if_len <= 0 || conf.if_buf == NULL) {
		error = ict_if_ioctl(fp->f_vnode, SIOCGIFNUM,
		    (intptr_t)&ifcount, FLFAKE(fp), fp->f_cred);
		if (error != 0)
			return (set_errno(error));

		conf.if_len = ifcount * sizeof (lx_ifreq64_t);

		if (copyout(&conf, (lx_ifconf64_t *)arg, sizeof (conf)) != 0)
			return (set_errno(EFAULT));
		return (0);
	} else {
		ifcount = conf.if_len / sizeof (lx_ifreq64_t);
	}

	/* Get interface configuration list. */
	sconf.ifc_len = ifcount * sizeof (struct ifreq);
	sconf.ifc_req = (struct ifreq *)kmem_alloc(sconf.ifc_len, KM_SLEEP);

	error = ict_if_ioctl(fp->f_vnode, cmd, (intptr_t)&sconf, FLFAKE(fp),
	    fp->f_cred);
	if (error != 0) {
		kmem_free(sconf.ifc_req, ifcount * sizeof (struct ifreq));
		return (set_errno(error));
	}

	/* Convert data to Linux format & rename interfaces */
	buf_len = ifcount * sizeof (lx_ifreq64_t);
	oreq = (lx_ifreq64_t *)kmem_alloc(buf_len, KM_SLEEP);
	for (i = 0; i < sconf.ifc_len / sizeof (struct ifreq); i++) {
		bcopy(&sconf.ifc_req[i], oreq + i, sizeof (lx_ifreq64_t));
		lx_ifname_convert(oreq[i].ifr_name, LX_IF_FROMNATIVE);
	}
	conf.if_len = i * sizeof (*oreq);
	kmem_free(sconf.ifc_req, ifcount * sizeof (struct ifreq));

	error = 0;
	if (copyout(oreq, (caddr_t)(uintptr_t)conf.if_buf, conf.if_len) != 0 ||
	    copyout(&conf, (lx_ifconf64_t *)arg, sizeof (conf)) != 0)
		error = set_errno(EFAULT);

	kmem_free(oreq, buf_len);
	return (error);
}

/* ARGSUSED */
static int
ict_siocgifconf(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	if (curproc->p_model == DATAMODEL_LP64)
		return (ict_siocgifconf64(fp, cmd, arg, lxcmd));
	else
		return (ict_siocgifconf32(fp, cmd, arg, lxcmd));
}

/*
 * Unfortunately some of the autofs ioctls want to return a positive integer
 * result which does not indicate an error. To minimize disruption in the
 * rest of the code, we'll treat a positive return as an errno and a negative
 * return as the non-error return (which we then negate).
 */
/* ARGSUSED */
static int
ict_autofs(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	int res = 0;
	int rv;

	res = VOP_IOCTL(fp->f_vnode, cmd, arg, FLUSER(fp), fp->f_cred, &rv,
	    NULL);
	if (res > 0)
		return (set_errno(res));
	if (res == 0)
		return (0);
	return (-res);
}

/* Structure used to define an ioctl translator. */
typedef struct lx_ioc_cmd_translator {
	int	lict_lxcmd;
	int	lict_cmd;
	int	(*lict_func)(file_t *fp, int cmd, intptr_t arg, int lxcmd);
} lx_ioc_cmd_translator_t;

#define	LX_IOC_CMD_TRANSLATOR_PASS(ioc_cmd_sym)				\
	{ (int)LX_##ioc_cmd_sym, (int)ioc_cmd_sym, ict_pass },

#define	LX_IOC_CMD_TRANSLATOR_FILTER(ioc_cmd_sym, ioct_handler)		\
	{ (int)LX_##ioc_cmd_sym, (int)ioc_cmd_sym, ioct_handler },

#define	LX_IOC_CMD_TRANSLATOR_CUSTOM(ioc_cmd_sym, ioct_handler)		\
	{ (int)ioc_cmd_sym, (int)ioc_cmd_sym, ioct_handler },

#define	LX_IOC_CMD_TRANSLATOR_PTHRU(ioc_cmd_sym)			\
	{ (int)ioc_cmd_sym, (int)ioc_cmd_sym, ict_pass },

#define	LX_IOC_CMD_TRANSLATOR_END					\
	{0, 0, NULL}

static lx_ioc_cmd_translator_t lx_ioc_xlate_fd[] = {
	LX_IOC_CMD_TRANSLATOR_FILTER(FIONBIO,	ict_fionbio)
	LX_IOC_CMD_TRANSLATOR_FILTER(FIONREAD,	ict_fionread)
	LX_IOC_CMD_TRANSLATOR_PASS(FIOASYNC)

	/* streams related */
	LX_IOC_CMD_TRANSLATOR_PASS(TCXONC)
	LX_IOC_CMD_TRANSLATOR_PASS(TCFLSH)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCEXCL)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCNXCL)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCSTI)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCSWINSZ)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCMBIS)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCMBIC)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCMSET)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCSETD)
	LX_IOC_CMD_TRANSLATOR_PASS(TCSBRK)

	/* terminal related */
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCGETD)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCGSID)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCNOTTY)
	LX_IOC_CMD_TRANSLATOR_PASS(TIOCPKT)

	LX_IOC_CMD_TRANSLATOR_FILTER(TCSETS,		ict_tcsets)
	LX_IOC_CMD_TRANSLATOR_FILTER(TCSETSW,		ict_tcsets)
	LX_IOC_CMD_TRANSLATOR_FILTER(TCSETSF,		ict_tcsets)
	LX_IOC_CMD_TRANSLATOR_FILTER(TCSETA,		ict_tcseta)
	LX_IOC_CMD_TRANSLATOR_FILTER(TCSETAW,		ict_tcseta)
	LX_IOC_CMD_TRANSLATOR_FILTER(TCSETAF,		ict_tcseta)
	LX_IOC_CMD_TRANSLATOR_FILTER(TCGETS,		ict_tcgets)
	LX_IOC_CMD_TRANSLATOR_FILTER(TCGETA,		ict_tcgeta)
	LX_IOC_CMD_TRANSLATOR_FILTER(TIOCGWINSZ,	ict_tiocgwinsz)
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_TCSBRKP,	ict_tcsbrkp)
	LX_IOC_CMD_TRANSLATOR_FILTER(TIOCSPGRP,		ict_tiocspgrp)
	LX_IOC_CMD_TRANSLATOR_FILTER(TIOCGPGRP,		ict_tiocgpgrp)
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCSPTLCK,	ict_sptlock)
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCGPTN,	ict_gptn)
	LX_IOC_CMD_TRANSLATOR_FILTER(TIOCSCTTY,		ict_tiocsctty)

	LX_IOC_CMD_TRANSLATOR_END
};

static lx_ioc_cmd_translator_t lx_ioc_xlate_socket[] = {
	LX_IOC_CMD_TRANSLATOR_PASS(FIOGETOWN)

	LX_IOC_CMD_TRANSLATOR_PASS(SIOCSPGRP)
	LX_IOC_CMD_TRANSLATOR_PASS(SIOCGPGRP)
	LX_IOC_CMD_TRANSLATOR_PASS(SIOCGSTAMP)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCATMARK,	ict_siocatmark)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFFLAGS,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCSIFFLAGS,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFADDR,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCSIFADDR,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFDSTADDR,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCSIFDSTADDR,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFBRDADDR,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCSIFBRDADDR,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFNETMASK,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCSIFNETMASK,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFMETRIC,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCSIFMETRIC,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFMTU,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCSIFMTU,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFHWADDR,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_SIOCSIFHWADDR,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFINDEX,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_SIOCGIFTXQLEN,	ict_siolifreq)
	LX_IOC_CMD_TRANSLATOR_FILTER(SIOCGIFCONF,	ict_siocgifconf)
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_SIOCGIFNAME,	ict_siocgifname)

	LX_IOC_CMD_TRANSLATOR_END
};

static lx_ioc_cmd_translator_t lx_ioc_xlate_dtrace[] = {
	LX_IOC_CMD_TRANSLATOR_PTHRU(DTRACEHIOC_ADD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(DTRACEHIOC_REMOVE)
	LX_IOC_CMD_TRANSLATOR_PTHRU(DTRACEHIOC_ADDDOF)

	LX_IOC_CMD_TRANSLATOR_END
};

static lx_ioc_cmd_translator_t lx_ioc_xlate_autofs[] = {
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_IOC_READY)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_IOC_FAIL)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_IOC_CATATONIC)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_IOC_PROTOVER)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_IOC_SETTIMEOUT)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_IOC_EXPIRE)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_IOC_EXPIRE_MULTI)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_IOC_PROTOSUBVER)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_IOC_ASKUMOUNT)

	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_VERSION_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_PROTOVER_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_PROTOSUBVER_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_OPENMOUNT_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_CLOSEMOUNT_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_READY_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_FAIL_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_SETPIPEFD_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_CATATONIC_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_TIMEOUT_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_REQUESTER_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_EXPIRE_CMD)
	LX_IOC_CMD_TRANSLATOR_PTHRU(LX_AUTOFS_DEV_IOC_ASKUMOUNT_CMD)
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_AUTOFS_DEV_IOC_ISMOUNTPOINT_CMD,
	    ict_autofs)

	LX_IOC_CMD_TRANSLATOR_END
};

static lx_ioc_cmd_translator_t lx_ioc_xlate_hd[] = {
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_HDIO_GETGEO, ict_hdgetgeo)

	LX_IOC_CMD_TRANSLATOR_END
};

static lx_ioc_cmd_translator_t lx_ioc_xlate_blk[] = {
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_BLKGETSIZE, ict_blkgetsize)
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_BLKSSZGET, ict_blkgetssize)
	LX_IOC_CMD_TRANSLATOR_CUSTOM(LX_BLKGETSIZE64, ict_blkgetsize64)

	LX_IOC_CMD_TRANSLATOR_END
};

static void
lx_ioctl_vsd_free(void *data)
{
	kmem_free(data, sizeof (struct lx_cc));
}

void
lx_ioctl_init()
{
	vsd_create(&lx_ioctl_vsd, lx_ioctl_vsd_free);
}

void
lx_ioctl_fini()
{
	vsd_destroy(&lx_ioctl_vsd);
}

long
lx_ioctl(int fdes, int cmd, intptr_t arg)
{
	file_t *fp;
	int res = 0, error = ENOTTY;
	lx_ioc_cmd_translator_t *ict = NULL;

	if (cmd == LX_FIOCLEX || cmd == LX_FIONCLEX) {
		res = f_setfd_error(fdes, (cmd == LX_FIOCLEX) ? FD_CLOEXEC : 0);
		return ((res != 0) ? set_errno(res) : 0);
	}

	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));

	switch ((cmd & 0xff00) >> 8) {
	case LX_IOC_TYPE_FD:
		ict = lx_ioc_xlate_fd;
		break;

	case LX_IOC_TYPE_DTRACE:
		ict = lx_ioc_xlate_dtrace;
		break;

	case LX_IOC_TYPE_SOCK:
		ict = lx_ioc_xlate_socket;
		error = EOPNOTSUPP;
		break;

	case LX_IOC_TYPE_AUTOFS:
		ict = lx_ioc_xlate_autofs;
		break;

	case LX_IOC_TYPE_BLK:
		ict = lx_ioc_xlate_blk;
		break;

	case LX_IOC_TYPE_HD:
		ict = lx_ioc_xlate_hd;
		break;

	default:
		releasef(fdes);
		return (set_errno(ENOTTY));
	}

	/*
	 * Today, none of the ioctls supported by the emulation possess
	 * overlapping cmd values.  Because of that, no type interrogation of
	 * the fd is done before executing specific ioctl emulation.  It's
	 * assumed that the vnode-specific logic called by the emulation
	 * function will reject ioctl commands not supported by the fd.
	 */
	VERIFY(ict != NULL);
	while (ict->lict_func != NULL) {
		if (ict->lict_lxcmd == cmd)
			break;
		ict++;
	}
	if (ict->lict_func == NULL) {
		releasef(fdes);
		return (set_errno(error));
	}

	res = ict->lict_func(fp, ict->lict_cmd, arg, ict->lict_lxcmd);
	releasef(fdes);
	return (res);
}
