/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "big5_cns11643.h"	/* Big-5 to CNS 11643 mapping table */
#include "gb18030_big5.h"	/* GBK to Big-5 mapping table */

#ifdef DEBUG
#include <sys/fcntl.h>
#include <sys/stat.h>
#endif

#define	MSB	0x80	/* most significant bit */
#define	MBYTE	0x8e	/* multi-byte (4 byte character) */
#define	PMASK	0xa0	/* plane number mask */
#define ONEBYTE	0xff	/* right most byte */
#define MSB_OFF 0x7f    /* mask off MSB */

#define SI      0x0f    /* shift in */
#define SO      0x0e    /* shift out */
#define SS2	0x4e	/* SS2 shift out */
#define SS3	0x4f	/* ss3 shift out, used so far */
#define ESC     0x1b    /* escape */

#define gbk4_2nd_byte(v)  ( (v) >= 0x30 && (v) <= 0x39 )
#define gbk4_3rd_byte(v)  ( (v) >= 0x81 && (v) <= 0xfe )
#define gbk4_4th_byte(v)  gbk4_2nd_byte(v)

/* We use plane 0 for GB2312 */

static const char plane_char[] = "AGHIJKLMNOPQRSTUV";

#define GET_PLANEC(i)   (plane_char[i])

#define NON_ID_CHAR_BYTE1 0x21	/* non-identified character */
#define NON_ID_CHAR_BYTE2 0x75	/* non-identified character */

typedef struct _icv_state {
	unsigned char	keepc[2];	/* maximum # byte of Big-5 code */
	short	gstate;		/* state machine id (Big-5) */
	short	istate;		/* state machine id (ISO) */
	short	plane;		/* plane no. */
	short	last_plane;	/* last charactor's plane no. */
	int	_errno;			/* internal errno */
} _iconv_st;

enum _CSTATE	{ G0, G1, G2, G3 };
enum _ISTATE    { IN, OUT };


void get_plane_no_by_big5(_iconv_st * , int * , unsigned long *);
int isGB2312Char(_iconv_st * st);
int isBIG5Char(_iconv_st * st);
int binsearch_gbk_big5(unsigned int gbkcode);
int binsearch(unsigned long x, table_t v[], int n);
int gb_to_iso(_iconv_st * st, char* buf, int buflen);
int isGBK2(_iconv_st * st);
int big5_to_iso(_iconv_st * st, int unidx, unsigned long cnscode, char * buf,
    size_t buflen);


int isGBK2(_iconv_st * st) {
	unsigned char c0, c1;

	c0 = st->keepc[0] & ONEBYTE;
	c1 = st->keepc[1] & ONEBYTE;
	if	(c0 >= 0x80 && c0 <= 0xfe && \
			c1 >= 0x40 && c1 <= 0xfe && \
			c1 != 0x7f)
		return 1;
	st->_errno = EILSEQ;
	return 0;
}

/*
 * Open; called from iconv_open()
 */
void * _icv_open() {
	_iconv_st *st;

	if ((st = (_iconv_st *)malloc(sizeof(_iconv_st))) == NULL) {
		errno = ENOMEM;
		return ((void *) -1);
	}

	st->gstate = G0;
	st->istate = IN;
	st->plane = st->last_plane = -1;/* give it an invalid initnumber */
	st->_errno = 0;
	return ((void *) st);
}


/*
 * Close; called from iconv_close()
 */
void _icv_close(_iconv_st *st) {
	if (st == NULL)
		errno = EBADF;
	else
		free(st);
}


/*
 *Actual conversion; called from iconv()
 */
/*=======================================================
 *
 *   State Machine for interpreting GBK code
 *
 *=======================================================
 *
 *                                  3rd C
 *                              G2--------> G3
 *                              ^            |
 *                        2nd C |      4th C |
 *                     1st C    |            |
 *    +--------> G0 ----------> G1           |
 *    |    ascii |        2nd C |            |
 *    ^          v              v            V
 *    +----<-----+-----<--------+-----<------+
 *
 *=======================================================*/
/*
 *	GBK2 encoding range:
 *		High byte: 0x81 - 0xFE
 *		Low byte:  0x40 - 0x7E, 0x80 - 0xFE
 *
 *	GBK4 encoding range:
 *		The 1st byte: 0x81 - 0xFE
 *		The 2nd byte: 0x30 - 0x39
 *		The 3rd byte: 0x81 - 0xFE
 *		The 4th byte: 0x30 - 0x39
 *
 *	We divide the GBK charset into three parts:
 *	GB2312:
 *		High byte: 0xb0 - 0xfe
 *		Low byte: 0xa1 - 0xfe
 *		Exclusive: 0xd7fa - 0xd8fe
 *	Big5:
 *		Plane #1:  0xA140 - 0xC8FE
 *		Plane #2:  0xC940 - 0xFEFE
 *	Other:
 *		Unknow Chinese charactors
 */
size_t _icv_iconv(      _iconv_st *st,
					char **inbuf,
					size_t *inbytesleft,
					char **outbuf,
					size_t *outbytesleft) {
	int	     n, unidx;
	unsigned long   cnscode;
	if (st == NULL) {
		errno = EBADF;
		return ((size_t) -1);
	}

	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		if (st->gstate == G1) {
			if (outbytesleft && *outbytesleft >= 1 &&
						outbuf && *outbuf) {
				**outbuf = SI;
				(*outbuf) ++;
				(*outbytesleft) --;
			} else {
				errno = E2BIG;
				return ((size_t)-1);
			}
		}
		st->gstate = G0;
		st->istate = IN;
		st->plane = 0;
		st->last_plane = 0;
		st->_errno = 0;
		return ((size_t) 0);
	}

	errno = st->_errno = 0; /* reset internal & external errno */

	/*
	 *      Automatic machine starts.
	 */
	while (*inbytesleft > 0 && *outbytesleft > 0) {
		switch (st->gstate) {
			case G0:	/* beginning with ASCII*/
				if (**inbuf & MSB) {
					st->keepc[0] = (**inbuf);
					st->gstate = G1;
				} else {	/* ASCII */
					if (st->istate == OUT) {
						st->gstate = G0;
						st->istate = IN;
						if (*outbytesleft >= 2) {
							**outbuf = SI;
							(*outbuf)++;
							(*outbytesleft)--;
						} else {
							errno = st->_errno = E2BIG;
							return(size_t)(-1);
						}
						st->last_plane = st->plane;
					}
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft)--;
				}
				break;
			case G1:		/* Chinese characters: 2nd byte */
				st->keepc[1] = (**inbuf);
				if ( gbk4_2nd_byte((unsigned char)**inbuf) ) {
					st->gstate = G2;
				} else if (!isGBK2(st)) {
					errno = st->_errno;
					return (size_t)-1;
				} else if (isGB2312Char(st)) {
					st->plane = 0;  /* 0 is for GB2312 */
					if (st->last_plane == -1 || \
							st->plane != st->last_plane) {
						if (*outbytesleft < 5) {
							errno = st->_errno = E2BIG;
							return (size_t)-1;
						}
						**outbuf = ESC;
						*(*outbuf + 1) = '$';
						*(*outbuf+2) = ')';
						*(*outbuf+3) = 'A';
						*(*outbuf+4) = SO;
						(*outbuf) += 5;
						(*outbytesleft) -= 5;
						st->last_plane = st->plane;
					} else if (st->istate == IN) {
						**outbuf = SO;
						(*outbuf) += 1;
						(*outbytesleft) -= 1;
					}
					n = gb_to_iso(st, *outbuf, *outbytesleft);
					if (n > 0) {
						(*outbuf) += n;
						(*outbytesleft) -= n;
					} else {
						errno = st->_errno;
						return (size_t)-1;
					}
					st->istate = OUT;
					st->gstate = G0;
				} else if (isBIG5Char(st)) {
					get_plane_no_by_big5(st, &unidx, &cnscode);
					if (unidx < 0) {	/* legal Big-5; illegal CNS */
						goto nonindentify;
					}

					if (st->last_plane != st->plane) {
						switch (st->plane) {
							case 1:
								if (*outbytesleft < 5) {
									st->_errno = errno = E2BIG;
									return (size_t)-1;
								}
								**outbuf = ESC;
								*(*outbuf + 1) = '$';
								*(*outbuf + 2) = ')';
								*(*outbuf + 3) = 'G';
								*(*outbuf + 4) = SO;
								(*outbuf) += 5;
								(*outbytesleft) -= 5;
								break;
							case 2:
								if (*outbytesleft < 6) {
									errno = st->_errno = E2BIG;
									return (size_t)-1;
								}
								**outbuf = ESC;
								*(*outbuf + 1) = '$';
								*(*outbuf + 2) = '*';
								*(*outbuf + 3) = 'H';
								*(*outbuf + 4) = ESC;
								*(*outbuf + 5) = SS2;
								(*outbuf) += 6;
								(*outbytesleft) -= 6;
								break;
							case 3:
							case 4:
							case 5:
							case 6:
							case 7:
							case 8:
							case 9:
								if (*outbytesleft < 6) {
									errno = st->_errno = E2BIG;
									return (size_t)-1;
								}
								**outbuf = ESC;
								*(*outbuf + 1) = '$';
								*(*outbuf + 2) = '+';
								*(*outbuf + 3) = GET_PLANEC(st->plane);
								*(*outbuf + 4) = ESC;
								*(*outbuf + 5) = SS3;
								(*outbuf) += 6;
								(*outbytesleft) -= 6;
								break;
							default:
								errno = st->_errno = EILSEQ;
								return (size_t)-1;
						}
						st->last_plane = st->plane;
					} else if (st->istate == IN) {
						switch (st->plane) {
							case 1:
								**outbuf = SO;
								(*outbuf) ++;
								(*outbytesleft)--;
								break;
							case 2:
								if (*outbytesleft >= 2) {
									**outbuf = ESC;
									*(*outbuf + 1) = SS2;
									(*outbuf) += 2;
									(*outbytesleft) -= 2;
								} else {
									errno = st->_errno = E2BIG;
									return (size_t)-1;
								}
								break;
							case 3:
							case 4:
							case 5:
							case 6:
							case 7:
							case 8:
							case 9:
								if (*outbytesleft >= 2) {
									**outbuf = ESC;
									*(*outbuf + 1) = SS3;
									(*outbuf) += 2;
									(*outbytesleft) -= 2;
								} else {
									errno = st->_errno = E2BIG;
									return (size_t)-1;
								}
								break;
							default:
								break;
						}	/* end of switch */
					}
					n = big5_to_iso(st, unidx, cnscode,
							*outbuf, *outbytesleft);
					if (n > 0) {
						(*outbuf) += n;
						(*outbytesleft) -= n;
					} else {
						errno = st->_errno;
						return(size_t)(-1);
					}
					st->istate = OUT;
					st->gstate = G0;
				} else {	/* Neither GB2312 nor Big5 */
nonindentify:				st->plane = 0;
					if (st->plane != st->last_plane) {
						if (*outbytesleft >= 7) {
							**outbuf = ESC;
							*(*outbuf + 1) = '$';
							*(*outbuf + 2) = ')';
							*(*outbuf + 3) = 'A';
							*(*outbuf + 4) = SO;
							(*outbuf) += 5;
							(*outbytesleft) -= 5;
						} else {
							st->_errno = errno = E2BIG;
							return (size_t)-1;
						}
						st->last_plane = st->plane;
					} else if (st->istate == IN) {
						if (*outbytesleft >= 3) {
							**outbuf = SO;
							(*outbuf)++;
							(*outbytesleft)--;
						} else {
							st->_errno = errno = E2BIG;
							return (size_t)-1;
						}
					}

					if ( *outbytesleft < 2) {
						errno = st->_errno = E2BIG;
						return (size_t)-1;
					}
					**outbuf = NON_ID_CHAR_BYTE1;
					*(*outbuf + 1) = NON_ID_CHAR_BYTE2;
					(*outbuf) += 2;
					(*outbytesleft) -= 2;
					st->istate = OUT;
					st->gstate = G0;
					st->_errno = 0;
				}
				break;
			case G2:
				if ( gbk4_3rd_byte((unsigned char)**inbuf) ) {
					st->gstate = G3;
				} else {
					errno = st->_errno = EILSEQ;
					return (size_t)-1;
				}
				break;
			case G3:
				if ( gbk4_4th_byte((unsigned char)**inbuf) ) {
					st->plane = 0;
					if ( st->plane != st->last_plane ) {
						if (*outbytesleft >= 7) {
							**outbuf = ESC;
							*(*outbuf + 1) = '$';
							*(*outbuf + 2) = ')';
							*(*outbuf + 3) = 'A';
							*(*outbuf + 4) = SO;
							(*outbuf) += 5;
							(*outbytesleft) -= 5;
						} else {
							st->_errno = errno = E2BIG;
							return (size_t)-1;
						}
						st->last_plane = st->plane;
					} else if (st->istate == IN) {
						if (*outbytesleft >= 3) {
							**outbuf = SO;
							(*outbuf)++;
							(*outbytesleft)--;
						} else {
							st->_errno = errno = E2BIG;
							return (size_t)-1;
						}
					}

					if ( *outbytesleft < 2) {
						errno = st->_errno = E2BIG;
						return (size_t) -1;
					}

					**outbuf = NON_ID_CHAR_BYTE1;
					*(*outbuf + 1) = NON_ID_CHAR_BYTE2;
					(*outbuf) += 2;
					(*outbytesleft) -= 2;
					st->istate = OUT;
					st->gstate = G0;
					st->_errno = 0;
				} else {
					errno = st->_errno = EILSEQ;
					return (size_t)-1;
				}
				break;
			default:			/* should never come here */
				st->_errno = errno = EILSEQ;
				st->istate = IN;
				st->gstate = G0;	/* reset state */
				break;
		}

		(*inbuf)++;
		(*inbytesleft)--;

		if (st->_errno) {
			break;
		}
		if (errno)
			return (size_t)(-1);
	}

	if (*inbytesleft == 0 && st->gstate != G0 ) {
		errno = EINVAL;
		return (size_t)-1;
	}

	if (*inbytesleft > 0 && *outbytesleft == 0) {
		st->_errno = errno = E2BIG;
		return (size_t)(-1);
	}
	return (size_t)(*inbytesleft);
}


int isGB2312Char(_iconv_st * st) {
	unsigned char buf1 = (unsigned char) (st->keepc[0] & ONEBYTE);
	unsigned char buf2 = (unsigned char) (st->keepc[1] & ONEBYTE);

	if (buf2 >= 0xA1 && buf2 <= 0xFE) {
		if ((buf1 >= 0xA1 && buf1 <= 0xA9) || \
			(buf1 >= 0xB0 && buf1 <= 0xF7))
		    return 1;
	}
	return 0;
}

int isBIG5Char(_iconv_st * st) {
	unsigned int gbkcode = \
		(unsigned int) (((st->keepc[0] & ONEBYTE) << 8) | \
						(st->keepc[1] & ONEBYTE));
	unsigned int big5code;
	int idx;

	if (gbkcode < gbk_big5_tab[0].key || \
			gbkcode > gbk_big5_tab[BIG5MAX-1].key) {
		return 0;
	}
	idx = binsearch_gbk_big5(gbkcode);
	if (idx < 0)
		return 0;
	else {
		big5code = gbk_big5_tab[idx].value;
		st->keepc[0] = (unsigned char)((big5code >> 8) & ONEBYTE);
		st->keepc[1] = (unsigned char)(big5code & ONEBYTE);
		return 1;
	}
}

/*
 * Test whether inbuf is a valid character for 2nd byte Big-5 code
 * Return: = 0 - valid Big-5 2nd byte
 *	 = 1 - invalid Big-5 2nd byte
 */
int big5_2nd_byte(inbuf)
char inbuf;
{
	unsigned char    buf = (unsigned char) (inbuf & ONEBYTE);

	if ((buf >= 0x40) && (buf <= 0x7E))
		return (0);
	if ((buf >= 0xA1) && (buf <= 0xFE))
		return (0);
	return(1);
}


/*
 * Get plane number by Big-5 code; i.e. plane #1 returns 1, #2 returns 2, etc.
 * Returns -1 on error conditions
 *
 * Since binary search of the Big-5 to CNS table is necessary, might as well
 * return index and CNS code matching to the unicode.
 */
void get_plane_no_by_big5(_iconv_st * st,
						int * unidx,
						unsigned long * cnscode) {
	int	     ret;
	unsigned long   big5code;

	big5code = (unsigned long) ((st->keepc[0] & ONEBYTE) << 8) + \
								(st->keepc[1] & ONEBYTE);
	*unidx = binsearch(big5code, big5_cns_tab, MAX_BIG5_NUM);
	if ((*unidx) >= 0)
		*cnscode = big5_cns_tab[*unidx].value;
	else {
		return; /* match from Big-5 to CNS not found */
	}
	ret = (int) (*cnscode >> 16);
	switch (ret) {
		case 0x21:      /* 0x8EA1 - G */
		case 0x22:      /* 0x8EA2 - H */
		case 0x23:      /* 0x8EA3 - I */
		case 0x24:      /* 0x8EA4 - J */
		case 0x25:      /* 0x8EA5 - K */
		case 0x26:      /* 0x8EA6 - L */
		case 0x27:      /* 0x8EA7 - M */
		case 0x28:      /* 0x8EA8 - N */
		case 0x29:      /* 0x8EA9 - O */
		case 0x2a:      /* 0x8EAA - P */
		case 0x2b:      /* 0x8EAB - Q */
		case 0x2c:      /* 0x8EAC - R */
		case 0x2d:      /* 0x8EAD - S */
		case 0x2f:      /* 0x8EAF - U */
		case 0x30:      /* 0x8EB0 - V */
			st->plane = ret - 0x20; /* so that we can use GET_PLANEC() */
			break;
		case 0x2e:      /* 0x8EAE - T */
			st->plane = 3;	  /* CNS 11643-1992 */
			break;
		default:
			st->_errno = EILSEQ;
			return;
	}
	st->_errno = 0;
}


/*
 * Big-5 code --> ISO 2022-7
 * Return: > 0 - converted with enough space in output buffer
 *	 = 0 - no space in outbuf
 */
int big5_to_iso(_iconv_st * st, int unidx,
				unsigned long cnscode,
				char * buf, size_t buflen) {
	unsigned long   val;	    /* CNS 11643 value */

	if (buflen < 2) {
		st->_errno = E2BIG;
		return 0;
	}

	if (unidx < 0) {	/* no match from UTF8 to CNS 11643 */
		st->_errno = EILSEQ;
		return 0;
	} else {
		val = cnscode & 0xffff;
		*buf = (unsigned char)((val & 0xff00) >> 8);
		*(buf+1) = (unsigned char)(val & 0xff);
	}

	return(2);
}


/* binsearch: find x in v[0] <= v[1] <= ... <= v[n-1] */
int binsearch(unsigned long x, table_t v[], int n) {
	int low, high, mid;

	low = 0;
	high = n - 1;
	while (low <= high) {
		mid = (low + high) / 2;
		if (x < v[mid].key)
			high = mid - 1;
		else if (x > v[mid].key)
			low = mid + 1;
		else    /* found match */
			return mid;
	}
	return (-1);    /* no match */
}

/* binsearch_gbk_big5: find x in v[0] <= v[1] <= ... <= v[n-1] */
int binsearch_gbk_big5(unsigned int c) {
	int low, high, mid;
	long gbkcode = (long)(c & 0xFFFF);

	low = 0;
	high = BIG5MAX - 1;
	while (low <= high) {
		mid = (low + high) / 2;
		if (gbkcode < gbk_big5_tab[mid].key)
			high = mid - 1;
		else if (gbkcode > gbk_big5_tab[mid].key)
			low = mid + 1;
		else    /* found match */
			return mid;
	}
	return (-1);    /* no match */
}

/*
 * return: > 0 - converted with enough space
 *	 = 0 - no space in outbuf
 */
int gb_to_iso(_iconv_st * st, char* buf, int buflen) {
	if ( buflen < 2 ) {
		st->_errno = E2BIG;
		return 0;
	}
	*buf = st->keepc[0] & MSB_OFF;
	*(buf+1) = st->keepc[1] & MSB_OFF;
	return 2;
}

#ifdef DEBUG
int main(int argc, char ** argv) {
	_iconv_st * st;
	char *inbuf, *outbuf, *in_tmp, *out_tmp;
	size_t inlen, outlen;
	int fd, i;
	struct stat s;

	if (argc < 2) {
		exit(-1);
	}
	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		perror("open");
		exit(-2);
	}
	if (fstat(fd, &s) == -1) {
		perror("stat");
		exit(-2);
	}
	inlen = s.st_size;
	in_tmp = inbuf = (char *)malloc(inlen);
	out_tmp = outbuf = (char*)malloc((outlen = inlen * 3));
	if (!inbuf || !outbuf) {
		perror("malloc");
		exit(-1);
	}
	if (read(fd, inbuf, inlen) != inlen) {
		perror("read");
		exit(-4);
	}
	st = _icv_open();
	if (st == (_iconv_st *) -1) {
		perror("_icv_open");
		exit(-3);
	}
	if (_icv_iconv(st, &inbuf, &inlen, &outbuf, &outlen))
		perror("ERROR");
	fprintf(stderr, "%d bytes left\n", outlen);
	if (write(1, out_tmp, s.st_size * 5 - outlen) == -1) {
		perror("write");
		exit(-5);
	}
	free(in_tmp);
	free(out_tmp);
	close(fd);
	_icv_close(st);
}
#endif
