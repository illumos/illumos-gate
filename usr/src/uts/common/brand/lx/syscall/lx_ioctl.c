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
 * Copyright 2015 Joyent, Inc.  All rights reserved.
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

/*
 * Supported ioctls
 */
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
#define	LX_SIOCSIFHWADDR	0x8924
#define	LX_SIOCGIFHWADDR	0x8927
#define	LX_SIOCGIFINDEX		0x8933

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

/* VSD key for lx_cc information */
static uint_t lx_ioctl_vsd = 0;

extern int lx_lpid_to_spair(pid_t l_pid, pid_t *s_pid, id_t *s_tid);

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

	if (s_tios->c_lflag & ICANON) {
		l_tios->c_cc[LX_VEOF] = s_tios->c_cc[VEOF];
		l_tios->c_cc[LX_VEOL] = s_tios->c_cc[VEOL];
	} else {
		l_tios->c_cc[LX_VMIN] = s_tios->c_cc[VMIN];
		l_tios->c_cc[LX_VTIME] = s_tios->c_cc[VTIME];
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
	} else {
		l_tio->c_cc[LX_VMIN] = s_tio->c_cc[VMIN];
		l_tio->c_cc[LX_VTIME] = s_tio->c_cc[VTIME];
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
	};
} lx_ifreq32_t;

typedef struct lx_ifreq64 {
	char	ifr_name[IFNAMSIZ];
	union {
		struct	sockaddr ifru_addr;
		/* pad this out to the Linux size */
		uint64_t	ifmap[3];
	};
} lx_ifreq64_t;

typedef struct lx_ifconf32 {
	int32_t	if_len;
	caddr32_t if_buf;
} lx_ifconf32_t;

typedef struct lx_ifconf64 {
	int32_t	if_len;
	caddr_t if_buf;
} lx_ifconf64_t;

/* Linux ARP protocol hardware identifiers */
#define	LX_ARPHRD_ETHER		1	/* Ethernet */
#define	LX_ARPHRD_LOOPBACK	772	/* Loopback */
#define	LX_ARPHRD_VOID		0xffff	/* Unknown */


/* Generic translators */

static int
ict_pass(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	int error = 0;
	int rv;

	error = VOP_IOCTL(fp->f_vnode, cmd, arg, FLUSER(fp), fp->f_cred, &rv,
	    NULL);
	return ((error != 0) ? set_errno(error) : 0);
}

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

/* Terminal-related translators */

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

static int
ict_tcgets(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	if (getmajor(fp->f_vnode->v_rdev) == ddi_name_to_major(LX_PTM_DRV))
		return (ict_tcgets_ptm(fp, cmd, arg, lxcmd));
	else
		return (ict_tcgets_native(fp, cmd, arg, lxcmd));
}

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

static int
ict_tiocgpgrp(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	pid_t	ttysid;
	int	error, rv;

	error = VOP_IOCTL(fp->f_vnode, TIOCGSID, (intptr_t)&ttysid,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);
	if (error != 0)
		return (set_errno(error));

	mutex_enter(&curproc->p_splock);
	if (ttysid != curproc->p_sessp->s_sid) {
		mutex_exit(&curproc->p_splock);
		return (set_errno(ENOTTY));
	}
	mutex_exit(&curproc->p_splock);

	error = VOP_IOCTL(fp->f_vnode, cmd, arg, FLUSER(fp),
	    fp->f_cred, &rv, NULL);
	return ((error != 0) ? set_errno(error) : 0);
}

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

static int
ict_gptn(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct strioctl istr;
	cred_t *cr;
	pt_own_t pto;
	int error, rv;
	int ptyno;

	/* This operation is only valid for the lx_ptm device. */
	if (getmajor(fp->f_vnode->v_rdev) != ddi_name_to_major(LX_PTM_DRV))
		return (set_errno(ENOTTY));

	cr = CRED();
	pto.pto_ruid = cr->cr_uid;
	pto.pto_rgid = cr->cr_gid;

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

static int
ict_tiocgwinsz(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	int error, rv;
	struct winsize winsize;

	error = VOP_IOCTL(fp->f_vnode, cmd, arg, FLUSER(fp), fp->f_cred, &rv,
	    NULL);

	if (error == EINVAL) {
		bzero(&winsize, sizeof (winsize));
		if (copyout(&winsize, (caddr_t)arg, sizeof (winsize)))
			return (set_errno(EFAULT));
	} else if (error != 0) {
		return (set_errno(error));
	}

	return (0);
}

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

static void
ict_convert_ifflags(uint64_t *flags, boolean_t tonative)
{
	uint64_t buf;
	buf = *flags & (IFF_UP | IFF_BROADCAST | IFF_DEBUG |
	    IFF_LOOPBACK | IFF_POINTOPOINT | IFF_NOTRAILERS |
	    IFF_RUNNING | IFF_NOARP | IFF_PROMISC | IFF_ALLMULTI);

	/* Linux has different shift for multicast flag */
	if (tonative == B_TRUE) {
		if (*flags & 0x1000)
			buf |= IFF_MULTICAST;
	} else {
		if (*flags & IFF_MULTICAST)
			buf |= 0x1000;
	}
	*flags = buf;
}

static int
ict_siolifreq(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	struct ifreq	req;
	struct lifreq	lreq;
	int		error, rv, len;

	/* Convert from Linux ifreq to illumos lifreq */
	if (curproc->p_model == DATAMODEL_LP64)
		len = sizeof (lx_ifreq64_t);
	else
		len = sizeof (lx_ifreq32_t);
	if (copyin((struct ifreq *)arg, &req, len) != 0)
		return (set_errno(EFAULT));
	bzero(&lreq, sizeof (lreq));
	strncpy(lreq.lifr_name, req.ifr_name, IFNAMSIZ);
	bcopy(&req.ifr_ifru, &lreq.lifr_lifru, len - IFNAMSIZ);
	lx_ifname_convert(lreq.lifr_name, LX_IFNAME_TONATIVE);

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
		error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred, &rv, NULL);
		break;
	case SIOCGIFINDEX:
		cmd = SIOCGLIFINDEX;
		error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred, &rv, NULL);
		break;
	case SIOCGIFFLAGS:
		cmd = SIOCGLIFFLAGS;
		error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred, &rv, NULL);
		if (error == 0)
			ict_convert_ifflags(&lreq.lifr_flags, B_FALSE);
		break;
	case SIOCSIFFLAGS:
		cmd = SIOCSLIFFLAGS;
		ict_convert_ifflags(&lreq.lifr_flags, B_TRUE);
		error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred, &rv, NULL);
		break;
	case SIOCGIFHWADDR:
		cmd = SIOCGLIFHWADDR;
		error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&lreq,
		    FLFAKE(fp), fp->f_cred, &rv, NULL);
		/*
		 * SIOCGIFHWADDR on Linux sets sa_family to ARPHRD_ETHER (1) on
		 * ethernet and ARPHRD_LOOPBACK (772) on loopback.
		 */
		if (error == EADDRNOTAVAIL &&
		    strncmp(lreq.lifr_name, "lo", 2) == 0) {
			/* Emulate success on suspected loopbacks */
			lreq.lifr_addr.ss_family = 772;
			error = 0;
		} else if (error == 0) {
			/* convert illumos sockaddr to Linux */
			struct sockaddr_dl *src =
			    (struct sockaddr_dl *)&lreq.lifr_addr;
			caddr_t dst = (caddr_t)&lreq.lifr_addr +
			    sizeof (lreq.lifr_addr.ss_family);
			bcopy(LLADDR(src), dst, src->sdl_alen);
			/* Default to Ethernet type for all successes */
			lreq.lifr_addr.ss_family = 1;
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
	lx_ifname_convert(lreq.lifr_name, LX_IFNAME_FROMNATIVE);
	bzero(&req, sizeof (req));
	strncpy(req.ifr_name, lreq.lifr_name, IFNAMSIZ);
	bcopy(&lreq.lifr_lifru, &req.ifr_ifru, len - IFNAMSIZ);

	if (copyout(&req, (struct lifreq *)arg, len) != 0)
		return (set_errno(EFAULT));

	return (0);
}

static int
ict_siocgifconf32(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	lx_ifconf32_t	conf;
	lx_ifreq32_t	*oreq;
	struct ifconf	sconf;
	int		ifcount, error, rv, i, buf_len;

	if (copyin((lx_ifconf32_t *)arg, &conf, sizeof (conf)) != 0)
		return (set_errno(EFAULT));

	/* They want to know how many interfaces there are. */
	if (conf.if_len <= 0 || conf.if_buf == NULL) {
		error = VOP_IOCTL(fp->f_vnode, SIOCGIFNUM, (intptr_t)&ifcount,
		    FLFAKE(fp), fp->f_cred, &rv, NULL);
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

	error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&sconf,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);
	if (error != 0) {
		kmem_free(sconf.ifc_req, ifcount * sizeof (struct ifreq));
		return (set_errno(error));
	}

	/* Convert data to Linux format & rename interfaces */
	buf_len = ifcount * sizeof (lx_ifreq32_t);
	oreq = (lx_ifreq32_t *)kmem_alloc(buf_len, KM_SLEEP);
	for (i = 0; i < sconf.ifc_len / sizeof (struct ifreq); i++) {
		bcopy(&sconf.ifc_req[i], oreq + i, sizeof (lx_ifreq32_t));
		lx_ifname_convert(oreq[i].ifr_name, LX_IFNAME_FROMNATIVE);
	}
	conf.if_len = i * sizeof (*oreq);
	kmem_free(sconf.ifc_req, ifcount * sizeof (struct ifreq));

	rv = 0;
	if (copyout(oreq, (caddr_t)(uintptr_t)conf.if_buf, conf.if_len) != 0 ||
	    copyout(&conf, (lx_ifconf32_t *)arg, sizeof (conf)) != 0)
		rv = set_errno(EFAULT);

	kmem_free(oreq, buf_len);
	return (rv);
}

static int
ict_siocgifconf64(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	lx_ifconf64_t	conf;
	lx_ifreq64_t	*oreq;
	struct ifconf	sconf;
	int		ifcount, error, rv, i, buf_len;

	if (copyin((lx_ifconf64_t *)arg, &conf, sizeof (conf)) != 0)
		return (set_errno(EFAULT));

	/* They want to know how many interfaces there are. */
	if (conf.if_len <= 0 || conf.if_buf == NULL) {
		error = VOP_IOCTL(fp->f_vnode, SIOCGIFNUM, (intptr_t)&ifcount,
		    FLFAKE(fp), fp->f_cred, &rv, NULL);
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

	error = VOP_IOCTL(fp->f_vnode, cmd, (intptr_t)&sconf,
	    FLFAKE(fp), fp->f_cred, &rv, NULL);
	if (error != 0) {
		kmem_free(sconf.ifc_req, ifcount * sizeof (struct ifreq));
		return (set_errno(error));
	}

	/* Convert data to Linux format & rename interfaces */
	buf_len = ifcount * sizeof (lx_ifreq64_t);
	oreq = (lx_ifreq64_t *)kmem_alloc(buf_len, KM_SLEEP);
	for (i = 0; i < sconf.ifc_len / sizeof (struct ifreq); i++) {
		bcopy(&sconf.ifc_req[i], oreq + i, sizeof (lx_ifreq64_t));
		lx_ifname_convert(oreq[i].ifr_name, LX_IFNAME_FROMNATIVE);
	}
	conf.if_len = i * sizeof (*oreq);
	kmem_free(sconf.ifc_req, ifcount * sizeof (struct ifreq));

	rv = 0;
	if (copyout(oreq, (caddr_t)(uintptr_t)conf.if_buf, conf.if_len) != 0 ||
	    copyout(&conf, (lx_ifconf64_t *)arg, sizeof (conf)) != 0)
		rv = set_errno(EFAULT);

	kmem_free(oreq, buf_len);
	return (rv);
}

static int
ict_siocgifconf(file_t *fp, int cmd, intptr_t arg, int lxcmd)
{
	if (curproc->p_model == DATAMODEL_LP64)
		return (ict_siocgifconf64(fp, cmd, arg, lxcmd));
	else
		return (ict_siocgifconf32(fp, cmd, arg, lxcmd));
}

/* Structure used to define an ioctl translator. */
typedef struct ioc_cmd_translator {
	int	ict_lxcmd;
	int	ict_cmd;
	int	(*ict_func)(file_t *fp, int cmd, intptr_t arg, int lxcmd);
} ioc_cmd_translator_t;

#define	IOC_CMD_TRANSLATOR_PASS(ioc_cmd_sym)				\
	{ (int)LX_##ioc_cmd_sym, (int)ioc_cmd_sym, ict_pass },

#define	IOC_CMD_TRANSLATOR_FILTER(ioc_cmd_sym, ioct_handler)		\
	{ (int)LX_##ioc_cmd_sym, (int)ioc_cmd_sym, ioct_handler },

#define	IOC_CMD_TRANSLATOR_CUSTOM(ioc_cmd_sym, ioct_handler)		\
	{ (int)ioc_cmd_sym, (int)ioc_cmd_sym, ioct_handler },

#define	IOC_CMD_TRANSLATOR_END						\
	{0, 0, NULL}

static ioc_cmd_translator_t ioc_translators[] = {
	IOC_CMD_TRANSLATOR_FILTER(FIONBIO,	ict_fionbio)
	IOC_CMD_TRANSLATOR_FILTER(FIONREAD,	ict_fionread)
	IOC_CMD_TRANSLATOR_PASS(FIOGETOWN)
	IOC_CMD_TRANSLATOR_PASS(FIOASYNC)

	/* streams related */
	IOC_CMD_TRANSLATOR_PASS(TCXONC)
	IOC_CMD_TRANSLATOR_PASS(TCFLSH)
	IOC_CMD_TRANSLATOR_PASS(TIOCEXCL)
	IOC_CMD_TRANSLATOR_PASS(TIOCNXCL)
	IOC_CMD_TRANSLATOR_PASS(TIOCSTI)
	IOC_CMD_TRANSLATOR_PASS(TIOCSWINSZ)
	IOC_CMD_TRANSLATOR_PASS(TIOCMBIS)
	IOC_CMD_TRANSLATOR_PASS(TIOCMBIC)
	IOC_CMD_TRANSLATOR_PASS(TIOCMSET)
	IOC_CMD_TRANSLATOR_PASS(TIOCSETD)
	IOC_CMD_TRANSLATOR_PASS(TCSBRK)

	/* terminal related */
	IOC_CMD_TRANSLATOR_PASS(TIOCGETD)
	IOC_CMD_TRANSLATOR_PASS(TIOCGSID)
	IOC_CMD_TRANSLATOR_PASS(TIOCNOTTY)
	IOC_CMD_TRANSLATOR_PASS(TIOCPKT)

	IOC_CMD_TRANSLATOR_FILTER(TCSETS,		ict_tcsets)
	IOC_CMD_TRANSLATOR_FILTER(TCSETSW,		ict_tcsets)
	IOC_CMD_TRANSLATOR_FILTER(TCSETSF,		ict_tcsets)
	IOC_CMD_TRANSLATOR_FILTER(TCSETA,		ict_tcseta)
	IOC_CMD_TRANSLATOR_FILTER(TCSETAW,		ict_tcseta)
	IOC_CMD_TRANSLATOR_FILTER(TCSETAF,		ict_tcseta)
	IOC_CMD_TRANSLATOR_FILTER(TCGETS,		ict_tcgets)
	IOC_CMD_TRANSLATOR_FILTER(TCGETA,		ict_tcgeta)
	IOC_CMD_TRANSLATOR_FILTER(TIOCGWINSZ,		ict_tiocgwinsz)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TCSBRKP,		ict_tcsbrkp)
	IOC_CMD_TRANSLATOR_FILTER(TIOCSPGRP,		ict_tiocspgrp)
	IOC_CMD_TRANSLATOR_FILTER(TIOCGPGRP,		ict_tiocgpgrp)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCSPTLCK,	ict_sptlock)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_TIOCGPTN,		ict_gptn)
	IOC_CMD_TRANSLATOR_FILTER(TIOCSCTTY,		ict_tiocsctty)

	/* socket related */
	IOC_CMD_TRANSLATOR_PASS(SIOCSPGRP)
	IOC_CMD_TRANSLATOR_PASS(SIOCGPGRP)
	IOC_CMD_TRANSLATOR_PASS(SIOCGSTAMP)
	IOC_CMD_TRANSLATOR_FILTER(SIOCATMARK,		ict_siocatmark)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFFLAGS,		ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFFLAGS,		ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFADDR,		ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFADDR,		ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFDSTADDR,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFDSTADDR,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFBRDADDR,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFBRDADDR,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFNETMASK,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFNETMASK,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFMETRIC,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFMETRIC,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFMTU,		ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCSIFMTU,		ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFHWADDR,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_CUSTOM(LX_SIOCSIFHWADDR,	ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFINDEX,		ict_siolifreq)
	IOC_CMD_TRANSLATOR_FILTER(SIOCGIFCONF,		ict_siocgifconf)

	IOC_CMD_TRANSLATOR_END
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

int
lx_ioctl(int fdes, int cmd, intptr_t arg)
{
	file_t *fp;
	int res = 0;
	ioc_cmd_translator_t *ict;

	if (cmd == LX_FIOCLEX || cmd == LX_FIONCLEX) {
		res = f_setfd_error(fdes, (cmd == LX_FIOCLEX) ? FD_CLOEXEC : 0);
		return ((res != 0) ? set_errno(res) : 0);
	}

	if ((fp = getf(fdes)) == NULL)
		return (set_errno(EBADF));

	/*
	 * Today, none of the ioctls supported by the emulation possess
	 * overlapping cmd values.  Because of that, no type interrogation of
	 * the fd is done before executing specific ioctl emulation.  It's
	 * assumed that the vnode-specific logic called by the emulation
	 * function will reject ioctl commands not supported by the fd.
	 */
	ict = ioc_translators;
	while (ict->ict_func != NULL) {
		if (ict->ict_lxcmd == cmd)
			break;
		ict++;
	}

	if (ict->ict_func != NULL) {
		res = ict->ict_func(fp, ict->ict_cmd, arg, ict->ict_lxcmd);
	} else {
		res = set_errno(EINVAL);
	}

	releasef(fdes);
	return (res);
}
