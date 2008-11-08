/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000,2001,2002  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* Based on "src/misc.c" in etherboot-5.0.5.  */

#include "grub.h"
#include "timer.h"

#include "nic.h"

/**************************************************************************
RANDOM - compute a random number between 0 and 2147483647L or 2147483562?
**************************************************************************/
int32_t random(void)
{
	static int32_t seed = 0;
	int32_t q;
	if (!seed) /* Initialize linear congruential generator */
		seed = currticks() + *(int32_t *)&arptable[ARP_CLIENT].node
		       + ((int16_t *)arptable[ARP_CLIENT].node)[2];
	/* simplified version of the LCG given in Bruce Schneier's
	   "Applied Cryptography" */
	q = seed/53668;
	if ((seed = 40014*(seed-53668*q) - 12211*q) < 0) seed += 2147483563L;
	return seed;
}

/**************************************************************************
POLL INTERRUPTIONS
**************************************************************************/
void poll_interruptions(void)
{
	if (checkkey() != -1 && ASCII_CHAR(getkey()) == K_INTR) {
		user_abort++;
	}
}

/**************************************************************************
SLEEP
**************************************************************************/
void sleep(int secs)
{
	unsigned long tmo;

	for (tmo = currticks()+secs*TICKS_PER_SEC; currticks() < tmo; ) {
		poll_interruptions();
	}
}

/**************************************************************************
INTERRUPTIBLE SLEEP
**************************************************************************/
void interruptible_sleep(int secs)
{
	printf("<sleep>\n");
	return sleep(secs);
}

/**************************************************************************
TWIDDLE
**************************************************************************/
void twiddle(void)
{
#ifdef BAR_PROGRESS
	static int count=0;
	static const char tiddles[]="-\\|/";
	static unsigned long lastticks = 0;
	unsigned long ticks;
#endif
#ifdef FREEBSD_PXEEMU
	extern char pxeemu_nbp_active;
	if(pxeemu_nbp_active != 0)
		return;
#endif
#ifdef	BAR_PROGRESS
	/* Limit the maximum rate at which characters are printed */
	ticks = currticks();
	if ((lastticks + (TICKS_PER_SEC/18)) > ticks)
		return;
	lastticks = ticks;

	putchar(tiddles[(count++)&3]);
	putchar('\b');
#else
	//putchar('.');
#endif	/* BAR_PROGRESS */
}


/* Because Etherboot uses its own formats for the printf family,
   define separate definitions from GRUB.  */
/**************************************************************************
PRINTF and friends

	Formats:
		%[#]x	- 4 bytes long (8 hex digits, lower case)
		%[#]X	- 4 bytes long (8 hex digits, upper case)
		%[#]hx	- 2 bytes int (4 hex digits, lower case)
		%[#]hX	- 2 bytes int (4 hex digits, upper case)
		%[#]hhx	- 1 byte int (2 hex digits, lower case)
		%[#]hhX	- 1 byte int (2 hex digits, upper case)
			- optional # prefixes 0x or 0X
		%d	- decimal int
		%c	- char
		%s	- string
		%@	- Internet address in ddd.ddd.ddd.ddd notation
		%!	- Ethernet address in xx:xx:xx:xx:xx:xx notation
	Note: width specification not supported
**************************************************************************/
static int
etherboot_vsprintf (char *buf, const char *fmt, const int *dp)
{
  char *p, *s;
  
  s = buf;
  for ( ; *fmt != '\0'; ++fmt)
    {
      if (*fmt != '%')
	{
	  buf ? *s++ = *fmt : grub_putchar (*fmt);
	  continue;
	}
      
      if (*++fmt == 's')
	{
	  for (p = (char *) *dp++; *p != '\0'; p++)
	    buf ? *s++ = *p : grub_putchar (*p);
	}
      else
	{
	  /* Length of item is bounded */
	  char tmp[20], *q = tmp;
	  int alt = 0;
	  int shift = 28;
	  
	  if (*fmt == '#')
	    {
	      alt = 1;
	      fmt++;
	    }
	  
	  if (*fmt == 'h')
	    {
	      shift = 12;
	      fmt++;
	    }
	  
	  if (*fmt == 'h')
	    {
	      shift = 4;
	      fmt++;
	    }
	  
	  /*
	   * Before each format q points to tmp buffer
	   * After each format q points past end of item
	   */
	  if ((*fmt | 0x20) == 'x')
	    {
	      /* With x86 gcc, sizeof(long) == sizeof(int) */
	      const long *lp = (const long *) dp;
	      long h = *lp++;
	      int ncase = (*fmt & 0x20);
	      
	      dp = (const int *) lp;
	      if (alt)
		{
		  *q++ = '0';
		  *q++ = 'X' | ncase;
		}
	      for (; shift >= 0; shift -= 4)
		*q++ = "0123456789ABCDEF"[(h >> shift) & 0xF] | ncase;
	    }
	  else if (*fmt == 'd')
	    {
	      int i = *dp++;
	      char *r;
	      
	      if (i < 0)
		{
		  *q++ = '-';
		  i = -i;
		}
	      
	      p = q;		/* save beginning of digits */
	      do
		{
		  *q++ = '0' + (i % 10);
		  i /= 10;
		}
	      while (i);
	      
	      /* reverse digits, stop in middle */
	      r = q;		/* don't alter q */
	      while (--r > p)
		{
		  i = *r;
		  *r = *p;
		  *p++ = i;
		}
	    }
	  else if (*fmt == '@')
	    {
	      unsigned char *r;
	      union
	      {
		long		l;
		unsigned char	c[4];
	      }
	      u;
	      const long *lp = (const long *) dp;
	      
	      u.l = *lp++;
	      dp = (const int *) lp;
	      
	      for (r = &u.c[0]; r < &u.c[4]; ++r)
		q += etherboot_sprintf (q, "%d.", *r);
	      
	      --q;
	    }
	  else if (*fmt == '!')
	    {
	      char *r;
	      p = (char *) *dp++;
	      
	      for (r = p + ETH_ALEN; p < r; ++p)
		q += etherboot_sprintf (q, "%hhX:", *p);
	      
	      --q;
	    }
	  else if (*fmt == 'c')
	    *q++ = *dp++;
	  else
	    *q++ = *fmt;
	  
	  /* now output the saved string */
	  for (p = tmp; p < q; ++p)
	    buf ? *s++ = *p : grub_putchar (*p);
	}
    }
  
  if (buf)
    *s = '\0';
  
  return (s - buf);
}

int
etherboot_sprintf (char *buf, const char *fmt, ...)
{
  return etherboot_vsprintf (buf, fmt, ((const int *) &fmt) + 1);
}

void
etherboot_printf (const char *fmt, ...)
{
  (void) etherboot_vsprintf (0, fmt, ((const int *) &fmt) + 1);
}

int
inet_aton (char *p, in_addr *addr)
{
  unsigned long ip = 0;
  int val;
  int i;
  
  for (i = 0; i < 4; i++)
    {
      val = getdec (&p);
      
      if (val < 0 || val > 255)
	return 0;
      
      if (i != 3 && *p++ != '.')
	return 0;
      
      ip = (ip << 8) | val;
    }

  addr->s_addr = htonl (ip);

  return 1;
}

int
getdec (char **ptr)
{
  char *p = *ptr;
  int ret = 0;
  
  if (*p < '0' || *p > '9')
    return -1;
  
  while (*p >= '0' && *p <= '9')
    {
      ret = ret * 10 + (*p - '0');
      p++;
    }
  
  *ptr = p;
  
  return ret;
}


