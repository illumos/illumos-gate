/* serial.c - serial device interface */
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

#ifdef SUPPORT_SERIAL

#include <shared.h>
#include <serial.h>
#include <term.h>
#include <terminfo.h>

#define	COMP_BS_SERIAL	0x01
#define	COMP_BS_BIOS	0x02

/* An input buffer.  */
static char input_buf[8];
static int npending = 0;

static int serial_x;
static int serial_y;

static int keep_track = 1;
static int composite_bitset = COMP_BS_SERIAL | COMP_BS_BIOS;


/* Hardware-dependent definitions.  */

#ifndef GRUB_UTIL
/* The structure for speed vs. divisor.  */
struct divisor
{
  int speed;
  unsigned short div;
};

/* Store the port number of a serial unit.  */
static unsigned short serial_hw_port = 0;

/* The table which lists common configurations.  */
static struct divisor divisor_tab[] =
  {
    { 2400,   0x0030 },
    { 4800,   0x0018 },
    { 9600,   0x000C },
    { 19200,  0x0006 },
    { 38400,  0x0003 },
    { 57600,  0x0002 },
    { 115200, 0x0001 }
  };

/* Read a byte from a port.  */
static inline unsigned char
inb (unsigned short port)
{
  unsigned char value;

  asm volatile ("inb	%w1, %0" : "=a" (value) : "Nd" (port));
  asm volatile ("outb	%%al, $0x80" : : );
  
  return value;
}

/* Write a byte to a port.  */
static inline void
outb (unsigned short port, unsigned char value)
{
  asm volatile ("outb	%b0, %w1" : : "a" (value), "Nd" (port));
  asm volatile ("outb	%%al, $0x80" : : );
}

/* Fetch a key.  */
int
serial_hw_fetch (void)
{
  if (inb (serial_hw_port + UART_LSR) & UART_DATA_READY)
    return inb (serial_hw_port + UART_RX);

  return -1;
}

/* Put a chararacter.  */
void
serial_hw_put (int c)
{
  int timeout = 100000;

  /* Wait until the transmitter holding register is empty.  */
  while ((inb (serial_hw_port + UART_LSR) & UART_EMPTY_TRANSMITTER) == 0)
    {
      if (--timeout == 0)
	/* There is something wrong. But what can I do?  */
	return;
    }

  outb (serial_hw_port + UART_TX, c);
}

void
serial_hw_delay (void)
{
  outb (0x80, 0);
}

/* Return the port number for the UNITth serial device.  */
unsigned short
serial_hw_get_port (int unit)
{
  /* The BIOS data area.  */
  const unsigned short *addr = (const unsigned short *) 0x0400;
  
  return addr[unit];
}

/* Initialize a serial device. PORT is the port number for a serial device.
   SPEED is a DTE-DTE speed which must be one of these: 2400, 4800, 9600,
   19200, 38400, 57600 and 115200. WORD_LEN is the word length to be used
   for the device. Likewise, PARITY is the type of the parity and
   STOP_BIT_LEN is the length of the stop bit. The possible values for
   WORD_LEN, PARITY and STOP_BIT_LEN are defined in the header file as
   macros.  */
int
serial_hw_init (unsigned short port, unsigned int speed,
		int word_len, int parity, int stop_bit_len)
{
  int i;
  unsigned short div = 0;
  unsigned char status = 0;

  if (port == 0)
    return 0;

  /* Make sure the port actually exists. */
  outb (port + UART_SR, UART_SR_TEST);
  outb (port + UART_FCR, 0);
  status = inb (port + UART_SR);
  if (status != UART_SR_TEST)
    return 0;
  
  /* Turn off the interrupt.  */
  outb (port + UART_IER, 0);

  /* Set DLAB.  */
  outb (port + UART_LCR, UART_DLAB);
  
  /* Set the baud rate.  */
  for (i = 0; i < sizeof (divisor_tab) / sizeof (divisor_tab[0]); i++)
    if (divisor_tab[i].speed == speed)
      {
	div = divisor_tab[i].div;
	break;
      }
  
  if (div == 0)
    return 0;
  
  outb (port + UART_DLL, div & 0xFF);
  outb (port + UART_DLH, div >> 8);
  
  /* Set the line status.  */
  status = parity | word_len | stop_bit_len;
  outb (port + UART_LCR, status);

  /* Enable the FIFO.  */
  outb (port + UART_FCR, UART_ENABLE_FIFO);

  /* Turn on DTR, RTS, and OUT2.  */
  outb (port + UART_MCR, UART_ENABLE_MODEM);

  /* Store the port number.  */
  serial_hw_port = port;
  
  /* Drain the input buffer.  */
  while (serial_checkkey () != -1)
    (void) serial_getkey ();

  /* Get rid of TERM_NEED_INIT from the serial terminal.  */
  for (i = 0; term_table[i].name; i++)
    if (grub_strcmp (term_table[i].name, "serial") == 0 ||
	grub_strcmp (term_table[i].name, "composite") == 0)
      {
	term_table[i].flags &= ~TERM_NEED_INIT;
      }
  
  return 1;
}
#endif /* ! GRUB_UTIL */


/* Generic definitions.  */

static void
serial_translate_key_sequence (void)
{
  const struct
  {
    char key;
    char ascii;
  }
  three_code_table[] =
    {
      {'A', 16},
      {'B', 14},
      {'C', 6},
      {'D', 2},
      {'F', 5},
      {'H', 1},
      {'4', 4}
    };

  const struct
  {
    short key;
    char ascii;
  }
  four_code_table[] =
    {
      {('1' | ('~' << 8)), 1},
      {('3' | ('~' << 8)), 4},
      {('5' | ('~' << 8)), 7},
      {('6' | ('~' << 8)), 3},
    };
  
  /* The buffer must start with ``ESC [''.  */
  if (*((unsigned short *) input_buf) != ('\e' | ('[' << 8)))
    return;
  
  if (npending >= 3)
    {
      int i;

      for (i = 0;
	   i < sizeof (three_code_table) / sizeof (three_code_table[0]);
	   i++)
	if (three_code_table[i].key == input_buf[2])
	  {
	    input_buf[0] = three_code_table[i].ascii;
	    npending -= 2;
	    grub_memmove (input_buf + 1, input_buf + 3, npending - 1);
	    return;
	  }
    }

  if (npending >= 4)
    {
      int i;
      short key = *((short *) (input_buf + 2));

      for (i = 0;
	   i < sizeof (four_code_table) / sizeof (four_code_table[0]);
	   i++)
	if (four_code_table[i].key == key)
	  {
	    input_buf[0] = four_code_table[i].ascii;
	    npending -= 3;
	    grub_memmove (input_buf + 1, input_buf + 4, npending - 1);
	    return;
	  }
    }
}
    
static
int fill_input_buf (int nowait)
{
  int i;

  for (i = 0; i < 10000 && npending < sizeof (input_buf); i++)
    {
      int c;

      c = serial_hw_fetch ();
      if (c >= 0)
	{
	  input_buf[npending++] = c;

	  /* Reset the counter to zero, to wait for the same interval.  */
	  i = 0;
	}
      
      if (nowait)
	break;
    }

  /* Translate some key sequences.  */
  serial_translate_key_sequence ();
	  
  return npending;
}

/* The serial version of getkey.  */
int
serial_getkey (void)
{
  int c;
  
  while (! fill_input_buf (0))
    ;

  c = input_buf[0];
  npending--;
  grub_memmove (input_buf, input_buf + 1, npending);
  
  return c;
}

/* The serial version of checkkey.  */
int
serial_checkkey (void)
{
  if (fill_input_buf (1))
    return input_buf[0];

  return -1;
}

/* The serial version of grub_putchar.  */
void
serial_putchar (int c)
{
  /* Keep track of the cursor.  */
  if (keep_track)
    {
      /* The serial terminal doesn't have VGA fonts.  */
      switch (c)
	{
	case DISP_UL:
	  c = ACS_ULCORNER;
	  break;
	case DISP_UR:
	  c = ACS_URCORNER;
	  break;
	case DISP_LL:
	  c = ACS_LLCORNER;
	  break;
	case DISP_LR:
	  c = ACS_LRCORNER;
	  break;
	case DISP_HORIZ:
	  c = ACS_HLINE;
	  break;
	case DISP_VERT:
	  c = ACS_VLINE;
	  break;
	case DISP_LEFT:
	  c = ACS_LARROW;
	  break;
	case DISP_RIGHT:
	  c = ACS_RARROW;
	  break;
	case DISP_UP:
	  c = ACS_UARROW;
	  break;
	case DISP_DOWN:
	  c = ACS_DARROW;
	  break;
	default:
	  break;
	}
      
      switch (c)
	{
	case '\r':
	  serial_x = 0;
	  break;
	  
	case '\n':
	  serial_y++;
	  break;
	  
	case '\b':
	case 127:
	  if (serial_x > 0)
	    serial_x--;
	  break;
	  
	case '\a':
	  break;
	  
	default:
	  if (serial_x >= 79)
	    {
	      serial_putchar ('\r');
	      serial_putchar ('\n');
	    }
	  serial_x++;
	  break;
	}
    }
  
  serial_hw_put (c);
}

int
serial_getxy (void)
{
  return (serial_x << 8) | serial_y;
}

void
serial_gotoxy (int x, int y)
{
  int saved_cbs = composite_bitset;

  keep_track = 0;
  composite_bitset &= ~COMP_BS_BIOS;
  ti_cursor_address (x, y);
  composite_bitset = saved_cbs;
  keep_track = 1;
  
  serial_x = x;
  serial_y = y;
}

void
serial_cls (void)
{
  int saved_cbs = composite_bitset;

  keep_track = 0;
  composite_bitset &= ~COMP_BS_BIOS;
  ti_clear_screen ();
  composite_bitset = saved_cbs;
  keep_track = 1;
  
  serial_x = serial_y = 0;
}

void
serial_setcolorstate (color_state state)
{
  int saved_cbs = composite_bitset;

  keep_track = 0;
  composite_bitset &= ~COMP_BS_BIOS;
  if (state == COLOR_STATE_HIGHLIGHT)
    ti_enter_standout_mode ();
  else
    ti_exit_standout_mode ();
  composite_bitset = saved_cbs;
  keep_track = 1;
}

void
composite_putchar (int c)
{
  if (composite_bitset & COMP_BS_SERIAL)
    serial_putchar (c);
  if (composite_bitset & COMP_BS_BIOS)
    console_putchar (c);
}

int
composite_getkey (void)
{
  for (;;) {
    if (serial_checkkey () != -1)
      return (serial_getkey ());
    if (console_checkkey () != -1)
      return (console_getkey ());
  }
}

int
composite_checkkey (void)
{
  int ch;

  if ((ch = serial_checkkey ()) != -1)
    return (ch);
  return (console_checkkey ());
}

void
composite_gotoxy (int x, int y)
{
  serial_gotoxy (x, y);
  console_gotoxy (x, y);
}

void
composite_cls (void)
{
  serial_cls();
  console_cls();
}

void
composite_setcolorstate (color_state state)
{
  serial_setcolorstate (state);
  console_setcolorstate (state);
}

#endif /* SUPPORT_SERIAL */
