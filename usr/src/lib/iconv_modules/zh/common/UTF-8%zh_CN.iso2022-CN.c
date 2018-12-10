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
 * Copyright(c) 1998 Sun Microsystems, Inc.
 * All right reserved.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <public_struc.h>
#include <unicode_gb2312.h>
#include <unicode_cns11643_CN.h>
#ifdef DEBUG
#include <fcntl.h>
#include <sys/stat.h>
#endif
#include "common_defs.h"

#define	SI	0x0f
#define	SO	0x0e
#define SS2 0x4e
#define SS3 0x4f
#define	ESC	0x1b
#define	MSB	0x80
#define MSB_OFF 0x7f

#define	NON_ID_CHAR1	0x21
#define NON_ID_CHAR2	0x75

typedef struct _icv_state {
	short	_ustate;
	short	_istate;
	short	_gstate;
	char	_keepc[6];
	int		_errno;
} _iconv_st;

enum	_USTATE	{ U0, U1, U2, U3, U4, U5, U6, U7 };
enum	_ISTATE	{ IN, OUT };
enum	_GSTATE	{ G0, G1, G2 };

int binary_search(unsigned long key, table_t *table, int tab_len);

/*
 *	Open; called from iconv_open()
 */
void * _icv_open() {
	_iconv_st * st;
	if ((st = (_iconv_st *)malloc(sizeof(_iconv_st))) == NULL) {
		errno = ENOMEM;
		return (void *)-1;
	}

	st->_ustate = U0;
	st->_istate = IN;
	st->_gstate = -1;
	st->_errno = 0;

	return (void *)st;
}

/*
 *	Close; called from iconv_close()
 */

void _icv_close(_iconv_st *st) {
	if (st == NULL)
		errno = EBADF;
	else
		free(st);
}

/*
 *	Actual conversion; called from iconv()
 */

size_t _icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
					char **outbuf, size_t *outbytesleft) {
	char c1 = '\0', c2 = '\0';
	int n = 0;
	unsigned long key;
	unsigned long gbk;
	int index;
	short new_state;

#ifdef DEBUG
	fprintf(stderr, "in length is %d\toutlength is %d\n",
			*inbytesleft, *outbytesleft);
#endif
	if (st == NULL) {
		errno = EBADF;
		return ((size_t)-1);
	}

	if (inbuf == NULL || *inbuf == NULL) {	/* Reset request. */
		st->_ustate = U0;
		st->_istate = IN;
		st->_gstate = G0;
		st->_errno = 0;
		return ((size_t)0);
	}

	errno = 0;
	while (*inbytesleft > 0 && *outbytesleft > 0) {

	        uchar_t  first_byte;

		switch (st->_ustate) {
			case U0:
				if ((**inbuf & MSB) == 0) {	/* ASCII */
					if (st->_istate == OUT) {
						if (*outbytesleft < 2) {
#ifdef DEBUG
							fprintf(stderr, "11111 outbytesleft is %d\n", *outbytesleft);
#endif
							errno = E2BIG;
							return (size_t) -1;
						}
						st->_istate = IN;
						**outbuf = SI;
						(*outbuf)++;
						(*outbytesleft)--;
					}
					if (*outbytesleft < 1) {
#ifdef DEBUG
						fprintf(stderr, "22222 outbytesleft is %d\n", *outbytesleft);
#endif
						errno = E2BIG;
						return (size_t) -1;
					}
					**outbuf = **inbuf;
					(*outbuf)++;
					(*outbytesleft)--;
				} else {	/* Chinese charactor */
					if ((**inbuf & 0xe0) == 0xc0) {	/* 2-byte unicode 0xc2..0xdf */

					   /* invalid sequence if the first char is either 0xc0 or 0xc1 */
					   if ( number_of_bytes_in_utf8_char[((uchar_t)**inbuf)] == ICV_TYPE_ILLEGAL_CHAR )
					        st->_errno = errno = EILSEQ;
					   else {
						st->_ustate = U1;
						st->_keepc[0] = **inbuf;
					   }
					} else if ((**inbuf & 0xf0) == 0xe0) {	/* 3-bytes unicode */
						st->_ustate = U2;
						st->_keepc[0] = **inbuf;
					} else {

					   /* four bytes of UTF-8 sequences */
					   if ( number_of_bytes_in_utf8_char[((uchar_t)**inbuf)] == ICV_TYPE_ILLEGAL_CHAR )
						st->_errno = errno = EILSEQ;
					   else
					     {
						st->_ustate = U5;
						st->_keepc[0] = **inbuf;
					     }
#ifdef DEBUG
						fprintf(stderr, "state = %d, keepc is %x\n", st->_ustate, st->_keepc[0]);
#endif
					}
				}
				break;

			case U1:	/* 2-byte unicode */
				if ((**inbuf & 0xc0) == 0x80) {	/* 2nd byte is 1xxxxxxx */
					st->_ustate = U4;
					st->_keepc[1] = **inbuf;
					c1 = (st->_keepc[0] & 0x1c)>>2;
					c2 = ((st->_keepc[0] & 0x03) << 6) | \
							(st->_keepc[1] & 0x3f);
					continue;
				} else {
					st->_errno = errno = EILSEQ;
#ifdef DEBUG
					fprintf(stderr, "state = %d, keepc is %x\n", st->_ustate, st->_keepc[0]);
#endif
				}
				break;

			case U2:	/* 3-byte unicode - 2nd byte */
		                first_byte = st->_keepc[0];

		                /* if the first byte is 0xed, it is illegal sequence if the second
				 * one is between 0xa0 and 0xbf because surrogate section is ill-formed
				 */
		                if (((uchar_t)**inbuf) < valid_min_2nd_byte[first_byte] ||
				    ((uchar_t)**inbuf) > valid_max_2nd_byte[first_byte] )
		                        st->_errno = errno = EILSEQ;
		                else {
					st->_ustate = U3;
					st->_keepc[1] = **inbuf;
				}
				break;

			case U3:	/* 3-byte unicode - 3th byte */
				if ((**inbuf & 0xc0) == 0x80) {
					st->_ustate = U4;
					st->_keepc[2] = **inbuf;
					c1 = ((st->_keepc[0] & 0x0f) << 4) | \
							((st->_keepc[1] & 0x3c) >> 2);
					c2 = ((st->_keepc[1] & 0x03) << 6) | \
							(st->_keepc[2] & 0x3f);
					continue;
				} else {
					st->_errno = errno = EILSEQ;
#ifdef DEBUG
					fprintf(stderr, "state = %d, keepc is %x\n", st->_ustate, st->_keepc[0]);
#endif
				}
				break;

			case U4:	/* Generate iso2022 sequence */
				key = ((c1 & 0xff) << 8) | (c2 & 0xff);

		                /* 0xFFFE and 0xFFFF should not be allowed */
		                if ( key == 0xFFFE || key == 0xFFFF ) {
				        st->_errno = errno = EILSEQ;
				        break;
				}

				if ((index = binary_search(key, unicode_gb_tab, UNICODEMAX)) != -1) {	/* GB code set */
					gbk = unicode_gb_tab[index].value;
					if (st->_gstate != G0) {
						if (*outbytesleft < 7) {
#ifdef DEBUG
							fprintf(stderr, "33333 outbytesleft is %d\n", *outbytesleft);
#endif
							errno = E2BIG;
							return ((size_t)-1);
						}
						st->_istate = OUT;
						st->_gstate = G0;
						**outbuf = ESC;
						*(*outbuf + 1) = '$';
						*(*outbuf + 2) = ')';
						*(*outbuf + 3) = 'A';
						*(*outbuf + 4) = SO;
						*(*outbuf + 5) = (gbk & 0xff00) >> 8;
						*(*outbuf + 6) = gbk & 0xff;
						n = 7;
					} else if (st->_istate == IN) {
						if (*outbytesleft < 3) {
#ifdef DEBUG
							fprintf(stderr, "44444outbytesleft is %d\n", *outbytesleft);
#endif
							errno = E2BIG;
							return ((size_t) -1);
						}
						st->_istate = OUT;
						**(outbuf) = SO;
						*(*outbuf + 1) = (gbk & 0xff00) >> 8;
						*(*outbuf + 2) = gbk & 0xff;
						n = 3;
					} else {
					        if ( *outbytesleft < 2 ) {
						   errno = E2BIG;
						   return ((size_t)-1);
					        }

						**outbuf = (gbk & 0xff00) >> 8;
						*(*outbuf + 1) = gbk & 0xff;
						n = 2;
					}
				} else if ((index = binary_search(key, utf_cns_tab, MAX_UTF_NUM)) != -1) {
					gbk = utf_cns_tab[index].value;
					new_state = ((gbk >> 16 ) & 0xff) - 0x20;
					if (new_state == G2 || new_state == G1) {
						if (st->_gstate != new_state) {
							if (*outbytesleft < 7) {
#ifdef DEBUG
								fprintf(stderr, "55555 outbytesleft is %d\n", *outbytesleft);
#endif
								errno = E2BIG;
								return (size_t) -1;
							}
							**outbuf = ESC;
							*(*outbuf + 1) = '$';
							*(*outbuf + 2) = ')';
							*(*outbuf + 3) = 'G' + new_state - 1;
							st->_istate = OUT;
							st->_gstate = new_state;
							*(*outbuf + 4) = SO;
							*(*outbuf + 5) = (gbk & 0xff00) >> 8;
							*(*outbuf + 6) = gbk & 0xff;
							n = 7;
						} else if (st->_istate == IN) {
							if (*outbytesleft < 3) {
#ifdef DEBUG
								fprintf(stderr, "66666 outbytesleft is %d\n", *outbytesleft);
#endif
								errno = E2BIG;
								return (size_t) -1;
							}
							st->_istate = OUT;
							**outbuf = SO;
							*(*outbuf + 1) = (gbk & 0xff00) >> 8;
							*(*outbuf + 2) = gbk & 0xff;
							n = 3;
						} else {
							if (*outbytesleft < 2) {
#ifdef DEBUG
								fprintf(stderr, "77777 outbytesleft is %d\n", *outbytesleft);
#endif
								errno = E2BIG;
								return (size_t) -1;
							}
							**outbuf = (gbk & 0xff00) >> 8;
							*(*outbuf + 1) = gbk & 0xff;
							n = 2;
						}
					} else if (new_state > G2) {
						if (st->_gstate != G0) {
							if (*outbytesleft < 7) {
#ifdef DEBUG
								fprintf(stderr, " 888888 outbytesleft is %d\n", *outbytesleft);
#endif
								errno = E2BIG;
								return (size_t) -1;
							}
							st->_gstate = G0;
							st->_istate = OUT;
							**outbuf = ESC;
							*(*outbuf + 1) = '$';
							*(*outbuf + 2) = ')';
							*(*outbuf + 3) = 'A';
							*(*outbuf + 4) = SO;
							*(*outbuf + 5) = NON_ID_CHAR1;
							*(*outbuf + 6) = NON_ID_CHAR2;
							n = 7;
						} else if (st->_istate == IN) {
							if (*outbytesleft < 3) {
#ifdef DEBUG
								fprintf(stderr, "99999 outbytesleft is %d\n", *outbytesleft);
#endif
								errno = E2BIG;
								return (size_t) -1;
							}
							st->_gstate = G0;
							st->_istate = OUT;
							**outbuf = SO;
							*(*outbuf + 1) = NON_ID_CHAR1;
							*(*outbuf + 2) = NON_ID_CHAR2;
							n = 3;
						} else {
							if (*outbytesleft < 2) {
#ifdef DEBUG
								fprintf(stderr, "aaaaaaoutbytesleft is %d\n", *outbytesleft);
#endif
								errno = E2BIG;
								return (size_t) -1;
							}
							**outbuf = NON_ID_CHAR1;
							*(*outbuf + 1) = NON_ID_CHAR2;
							n = 2;
						}
					}
				} else {	/* Non-GB & Non-Big5 */
					if (st->_gstate != G0) {
						if (*outbytesleft < 7) {
							errno = E2BIG;
							return (size_t) -1;
						}
						st->_gstate = G0;
						st->_istate = OUT;
						**outbuf = ESC;
						*(*outbuf + 1) = '$';
						*(*outbuf + 2) = ')';
						*(*outbuf + 3) = 'A';
						*(*outbuf + 4) = SO;
						*(*outbuf + 5) = NON_ID_CHAR1;
						*(*outbuf + 6) = NON_ID_CHAR2;
						n = 7;
					} else if (st->_istate == IN) {
						if(*outbytesleft < 3) {
							errno = E2BIG;
							return (size_t) -1;
						}
						st->_istate = OUT;
						st->_gstate = G0;
						**outbuf = SO;
						*(*outbuf + 1) = NON_ID_CHAR1;
						*(*outbuf + 2) = NON_ID_CHAR2;
						n = 3;
					} else {
					        /* add sanity check to avoid segment error */
						if (*outbytesleft < 2) {
							errno = E2BIG;
							return (size_t) -1;
						}
						**outbuf = NON_ID_CHAR1;
						*(*outbuf + 1) = NON_ID_CHAR2;
						n = 2;
					}
				}
/*
					n = gen_undef(st, *outbuf, *outbytesleft);
					fprintf(stderr, "gen_undef return %d\n", n );
				}
 */
				if (n > 0) {
					(*outbuf) += n;
					(*outbytesleft) -= n;
				} else {
#ifdef DEBUG
					fprintf(stderr, "bbbbb outbytesleft is %d\n", *outbytesleft);
#endif
					errno = E2BIG;
					return ((size_t)-1);
				}
				st->_ustate = U0;
				break;

		        case U5:
		                first_byte = st->_keepc[0];

		                /* if the first byte is 0xf0, it is illegal sequence if
				 * the second one is between 0x80 and 0x8f
				 * for Four-Byte UTF: U+10000..U+10FFFF
				 */
		                if (((uchar_t)**inbuf) < valid_min_2nd_byte[first_byte] ||
				    ((uchar_t)**inbuf) > valid_max_2nd_byte[first_byte] )
		                    st->_errno = errno = EILSEQ;
		                else {
				   st->_ustate = U6;
				   st->_keepc[1] = **inbuf;
				}
		                break;
		        case U6:
		                if ((**inbuf & 0xc0) == 0x80) /* 0x80..0xbf */
		                  {
				     st->_ustate = U7;
				     st->_keepc[2] = **inbuf;
				  }
		                else
		                     st->_errno = errno = EILSEQ;
		                break;
		        case U7:
		                if ((**inbuf & 0xc0) == 0x80) /* 0x80..0xbf */
		                  {  /* skip it to simplify */
				     st->_ustate = U0;
				  }
		                else
		                     st->_errno = errno = EILSEQ;
		                break;
			default:
				st->_errno = errno = EILSEQ;
#ifdef DEBUG
				fprintf(stderr, "WHY HERE\n");
#endif
				st->_ustate = U0;	/* reset state */
				break;
		}	/* end of switc */
		if (st->_errno)
			break;
		(*inbuf)++;
		(*inbytesleft)--;
	}

        if (errno)
		return ((size_t)-1);

        if (*inbytesleft == 0 && st->_ustate != U0)
         {
	    errno = EINVAL;
	    return ((size_t) -1);
         }

	if (*inbytesleft > 0 && *outbytesleft == 0) {
#ifdef DEBUG
		fprintf(stderr, "cccccc outbytesleft is %d\n", *outbytesleft);
#endif
		errno = E2BIG;
		return ((size_t)-1);
	}
	return ((size_t)(*inbytesleft));
}

/*
 *	gen_undef(); Called when a char non-gb and non-big5 found.
 */
int gen_undef(_iconv_st * st, char * outbuf, int bytes) {
	if (st->_gstate != G0) {
		if (bytes < 7) {
#ifdef DEBUG
			fprintf(stderr, "in gen outbytesleft is %d\n", bytes);
#endif
			errno = st->_errno = E2BIG;
			return -1;
		}
		st->_gstate = G0;
		st->_istate = OUT;
		*outbuf = ESC;
		*(outbuf + 1) = '$';
		*(outbuf + 2) = ')';
		*(outbuf + 3) = 'A';
		*(outbuf + 4) = SO;
		*(outbuf + 5) = NON_ID_CHAR1;
		*(outbuf + 6) = NON_ID_CHAR2;
		return 7;
	}
	if (st->_istate == IN) {
		if (bytes < 3) {
#ifdef DEBUG
			fprintf(stderr, "in gen outbytesleft is %d\n", bytes);
#endif
			errno = st->_errno = E2BIG;
			return -1;
		}
		st->_istate = OUT;
		*outbuf = SO;
		*(outbuf + 1) = NON_ID_CHAR1;
		*(outbuf + 2) = NON_ID_CHAR2;
		return 3;
	}
	if (bytes < 2) {
#ifdef DEBUG
		fprintf(stderr, "in gen outbytesleft is %d\n", bytes);
#endif
		errno = st->_errno = E2BIG;
		return -1;
	}
	*outbuf = NON_ID_CHAR1;
	*(outbuf + 1) = NON_ID_CHAR2;
	return 2;
}

/*
 *	binary_search();
 */
int binary_search(unsigned long key, table_t *table, int tab_len) {
	int i, low, high;

	for (low = 0, high = tab_len-1; low < high; ) {
		if (table[low].key == key)
			return low;
		if (table[high].key == key)
			return high;
		i = (low + high) >> 1;
		if (table[i].key == key)
			return i;
		if (table[i].key < key)
			low = i + 1;
		else
			high = i - 1;
	}
	return -1;
}

#ifdef DEBUG
main(int argc, char ** argv) {
	_iconv_st	* st;
	int fd;
	char * in_str;
	char * out_str;
	char * tmp_in;
	char * tmp_out;
	unsigned int in_len;
	unsigned int out_len;

	struct stat s;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s input\n", argv[0]);
		exit(-1);
	}

	if (stat(argv[1], &s) == -1) {
		perror("stat");
		exit(-1);
	}

	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		perror("open");
		exit(-1);
	}

	tmp_in = in_str = (char *) malloc(1024);
	tmp_out = out_str = (char *) malloc(1024);
	if (!in_str || !out_str) {
		perror("malloc");
		exit(-3);
		free(in_str);
		free(out_str);
	}
	in_len = s.st_size;
	out_len = s.st_size << 2;
	st = _icv_open();
	if (st == (_iconv_st *) -1) {
		perror("_icv_open");
		free(in_str);
		free(out_str);
		exit(-3);
	}

	while (1) {
	in_len = 1024;
	out_len = 1024;
	in_str = tmp_in;
	out_str = tmp_out;

	if (!read(fd, in_str, in_len))
		exit(0);

	if (_icv_iconv(st, &in_str, &in_len, &out_str, &out_len) == -1) {
		perror("icv_iconv");
		fprintf(stderr, "\ninbytesleft = %d\n", in_len);
		exit(-2);
	}
	fprintf(stderr, "Result is in len %d, out len %d\n", in_len,
	out_len);
	if (write(1, tmp_out, 4096 - out_len) == -1) {
		perror("write");
	}
	}	/* end of while */

	free(tmp_in);
	free(tmp_out);
	close(fd);
	_icv_close(st);
}
#endif
