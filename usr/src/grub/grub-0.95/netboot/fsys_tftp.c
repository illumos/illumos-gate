/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000,2001,2002,2004  Free Software Foundation, Inc.
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

/* Based on "src/main.c" in etherboot-4.5.8.  */
/**************************************************************************
ETHERBOOT -  BOOTP/TFTP Bootstrap Program

Author: Martin Renters
  Date: Dec/93

**************************************************************************/

/* #define TFTP_DEBUG	1 */

#include <filesys.h>
#include <shared.h>

#include "grub.h"
#include "tftp.h"
#include "nic.h"

static int tftp_file_read_undi(const char *name,
    int (*fnc)(unsigned char *, unsigned int, unsigned int, int));
static int tftp_read_undi(char *addr, int size);
static int tftp_dir_undi(char *dirname);
static void tftp_close_undi(void);
static int buf_fill_undi(int abort);

extern int use_bios_pxe;

static int retry;
static unsigned short iport = 2000;
static unsigned short oport = 0;
static unsigned short block, prevblock;
static int bcounter;
static struct tftp_t tp, saved_tp;
static int packetsize;
static int buf_eof, buf_read;
static int saved_filepos;
static unsigned short len, saved_len;
static char *buf, *saved_name;

/**
 * tftp_read
 *
 * Read file with _name_, data handled by _fnc_. In fact, grub never
 * use it, we just use it to read dhcp config file.
 */
static int await_tftp(int ival, void *ptr __unused, 
		      unsigned short ptype __unused, struct iphdr *ip, 
		      struct udphdr *udp)
{
	static int tftp_count = 0;

	if (!udp) {
		return 0;
	}
	if (arptable[ARP_CLIENT].ipaddr.s_addr != ip->dest.s_addr)
		return 0;
	if (ntohs(udp->dest) != ival)
		return 0;
	tftp_count++;	/* show progress */
	if ((tftp_count % 1000) == 0)
		printf(".");
	return 1;
}

int tftp_file_read(const char *name, int (*fnc)(unsigned char *, unsigned int, unsigned int, int))
{
	struct tftpreq_t tp;
	struct tftp_t  *tr;
	int		rc;

	if (use_bios_pxe)
		return (tftp_file_read_undi(name, fnc));

	retry = 0;
	block = 0;
	prevblock = 0;
	bcounter = 0;
	

	rx_qdrain();

	tp.opcode = htons(TFTP_RRQ);
	/* Warning: the following assumes the layout of bootp_t.
	   But that's fixed by the IP, UDP and BOOTP specs. */
	len = sizeof(tp.ip) + sizeof(tp.udp) + sizeof(tp.opcode) +
		sprintf((char *)tp.u.rrq, "%s%coctet%cblksize%c%d",
		name, 0, 0, 0, TFTP_MAX_PACKET) + 1;
	if (!udp_transmit(arptable[ARP_SERVER].ipaddr.s_addr, ++iport,
			  TFTP_PORT, len, &tp))
		return (0);
	for (;;)
	{
		long timeout;
#ifdef	CONGESTED
		timeout = rfc2131_sleep_interval(block?TFTP_REXMT: TIMEOUT, retry);
#else
		timeout = rfc2131_sleep_interval(TIMEOUT, retry);
#endif
		if (!await_reply(await_tftp, iport, NULL, timeout))
		{
			if (!block && retry++ < MAX_TFTP_RETRIES)
			{	/* maybe initial request was lost */
				if (!udp_transmit(arptable[ARP_SERVER].ipaddr.s_addr,
						  ++iport, TFTP_PORT, len, &tp))
					return (0);
				continue;
			}
#ifdef	CONGESTED
			if (block && ((retry += TFTP_REXMT) < TFTP_TIMEOUT))
			{	/* we resend our last ack */
#ifdef	MDEBUG
				printf("<REXMT>\n");
#endif
				udp_transmit(arptable[ARP_SERVER].ipaddr.s_addr,
					     iport, oport,
					     TFTP_MIN_PACKET, &tp);
				continue;
			}
#endif
			break;	/* timeout */
		}
		tr = (struct tftp_t *)&nic.packet[ETH_HLEN];
		if (tr->opcode == ntohs(TFTP_ERROR))
		{
			printf("TFTP error %d (%s)\n",
			       ntohs(tr->u.err.errcode),
			       tr->u.err.errmsg);
			break;
		}

		if (tr->opcode == ntohs(TFTP_OACK)) {
			char *p = tr->u.oack.data, *e;

			if (prevblock)		/* shouldn't happen */
				continue;	/* ignore it */
			len = ntohs(tr->udp.len) - sizeof(struct udphdr) - 2;
			if (len > TFTP_MAX_PACKET)
				goto noak;
			e = p + len;
			while (*p != '\0' && p < e) {
/* 				if (!strcasecmp("blksize", p)) { */
				if (!grub_strcmp("blksize", p)) {
					p += 8;
/* 					if ((packetsize = strtoul(p, &p, 10)) < */
					if ((packetsize = getdec(&p)) < TFTP_DEFAULTSIZE_PACKET)
						goto noak;
					while (p < e && *p) p++;
					if (p < e)
						p++;
				}
				else {
				noak:
					tp.opcode = htons(TFTP_ERROR);
					tp.u.err.errcode = 8;
/*
 *	Warning: the following assumes the layout of bootp_t.
 *	But that's fixed by the IP, UDP and BOOTP specs.
 */
					len = sizeof(tp.ip) + sizeof(tp.udp) + sizeof(tp.opcode) + sizeof(tp.u.err.errcode) +
/*
 *	Normally bad form to omit the format string, but in this case
 *	the string we are copying from is fixed. sprintf is just being
 *	used as a strcpy and strlen.
 */
						sprintf((char *)tp.u.err.errmsg,
						"RFC1782 error") + 1;
					udp_transmit(arptable[ARP_SERVER].ipaddr.s_addr,
						     iport, ntohs(tr->udp.src),
						     len, &tp);
					return (0);
				}
			}
			if (p > e)
				goto noak;
			block = tp.u.ack.block = 0; /* this ensures, that */
						/* the packet does not get */
						/* processed as data! */
		}
		else if (tr->opcode == htons(TFTP_DATA)) {
			len = ntohs(tr->udp.len) - sizeof(struct udphdr) - 4;
			if (len > packetsize)	/* shouldn't happen */
				continue;	/* ignore it */
			block = ntohs(tp.u.ack.block = tr->u.data.block); }
		else {/* neither TFTP_OACK nor TFTP_DATA */
			break;
		}

		if ((block || bcounter) && (block != (unsigned short)(prevblock+1))) {
			/* Block order should be continuous */
			tp.u.ack.block = htons(block = prevblock);
		}
		tp.opcode = htons(TFTP_ACK);
		oport = ntohs(tr->udp.src);
		udp_transmit(arptable[ARP_SERVER].ipaddr.s_addr, iport,
			     oport, TFTP_MIN_PACKET, &tp);	/* ack */
		if ((unsigned short)(block-prevblock) != 1) {
			/* Retransmission or OACK, don't process via callback
			 * and don't change the value of prevblock.  */
			continue;
		}
		prevblock = block;
		retry = 0;	/* It's the right place to zero the timer? */
		if ((rc = fnc(tr->u.data.download,
			      ++bcounter, len, len < packetsize)) <= 0)
			return(rc);
		if (len < packetsize) {	/* End of data --- fnc should not have returned */
			printf("tftp download complete, but\n");
			return (1);
		}
	}
	return (0);
}

/* Fill the buffer by receiving the data via the TFTP protocol.  */
static int
buf_fill (int abort)
{
#ifdef TFTP_DEBUG
  grub_printf ("buf_fill (%d)\n", abort);
#endif
  
  if (use_bios_pxe)
	return (buf_fill_undi(abort));

  while (! buf_eof && (buf_read + packetsize <= FSYS_BUFLEN))
    {
      struct tftp_t *tr;
      long timeout;

#ifdef CONGESTED
      timeout = rfc2131_sleep_interval (block ? TFTP_REXMT : TIMEOUT, retry);
#else
      timeout = rfc2131_sleep_interval (TIMEOUT, retry);
#endif
  
      if (! await_reply (await_tftp, iport, NULL, timeout))
	{
	  if (user_abort)
	    return 0;

	  if (! block && retry++ < MAX_TFTP_RETRIES)
	    {
	      /* Maybe initial request was lost.  */
#ifdef TFTP_DEBUG
	      grub_printf ("Maybe initial request was lost.\n");
#endif
	      if (! udp_transmit (arptable[ARP_SERVER].ipaddr.s_addr,
				  ++iport, TFTP_PORT, len, &tp))
		return 0;
	      
	      continue;
	    }
	  
#ifdef CONGESTED
	  if (block && ((retry += TFTP_REXMT) < TFTP_TIMEOUT))
	    {
	      /* We resend our last ack.  */
# ifdef TFTP_DEBUG
	      grub_printf ("<REXMT>\n");
# endif
	      udp_transmit (arptable[ARP_SERVER].ipaddr.s_addr,
			    iport, oport,
			    TFTP_MIN_PACKET, &tp);
	      continue;
	    }
#endif
	  /* Timeout.  */
	  return 0;
	}

      tr = (struct tftp_t *) &nic.packet[ETH_HLEN];
      if (tr->opcode == ntohs (TFTP_ERROR))
	{
	  grub_printf ("TFTP error %d (%s)\n",
		       ntohs (tr->u.err.errcode),
		       tr->u.err.errmsg);
	  return 0;
	}
      
      if (tr->opcode == ntohs (TFTP_OACK))
	{
	  char *p = tr->u.oack.data, *e;

#ifdef TFTP_DEBUG
	  grub_printf ("OACK ");
#endif
	  /* Shouldn't happen.  */
	  if (prevblock)
	    {
	      /* Ignore it.  */
	      grub_printf ("%s:%d: warning: PREVBLOCK != 0 (0x%x)\n",
			   __FILE__, __LINE__, prevblock);
	      continue;
	    }
	  
	  len = ntohs (tr->udp.len) - sizeof (struct udphdr) - 2;
	  if (len > TFTP_MAX_PACKET)
	    goto noak;
	  
	  e = p + len;
	  while (*p != '\000' && p < e)
	    {
	      if (! grub_strcmp ("blksize", p))
		{
		  p += 8;
		  if ((packetsize = getdec (&p)) < TFTP_DEFAULTSIZE_PACKET)
		    goto noak;
#ifdef TFTP_DEBUG
		  grub_printf ("blksize = %d\n", packetsize);
#endif
		}
	      else if (! grub_strcmp ("tsize", p))
		{
		  p += 6;
		  if ((filemax = getdec (&p)) < 0)
		    {
		      filemax = -1;
		      goto noak;
		    }
#ifdef TFTP_DEBUG
		  grub_printf ("tsize = %d\n", filemax);
#endif
		}
	      else
		{
		noak:
#ifdef TFTP_DEBUG
		  grub_printf ("NOAK\n");
#endif
		  tp.opcode = htons (TFTP_ERROR);
		  tp.u.err.errcode = 8;
		  len = (grub_sprintf ((char *) tp.u.err.errmsg,
				       "RFC1782 error")
			 + sizeof (tp.ip) + sizeof (tp.udp)
			 + sizeof (tp.opcode) + sizeof (tp.u.err.errcode)
			 + 1);
		  udp_transmit (arptable[ARP_SERVER].ipaddr.s_addr,
				iport, ntohs (tr->udp.src),
				len, &tp);
		  return 0;
		}
	      
	      while (p < e && *p)
		p++;
	      
	      if (p < e)
		p++;
	    }
	  
	  if (p > e)
	    goto noak;
	  
	  /* This ensures that the packet does not get processed as
	     data!  */
	  block = tp.u.ack.block = 0;
	}
      else if (tr->opcode == ntohs (TFTP_DATA))
	{
#ifdef TFTP_DEBUG
	  grub_printf ("DATA ");
#endif
	  len = ntohs (tr->udp.len) - sizeof (struct udphdr) - 4;
	  
	  /* Shouldn't happen.  */
	  if (len > packetsize)
	    {
	      /* Ignore it.  */
	      grub_printf ("%s:%d: warning: LEN > PACKETSIZE (0x%x > 0x%x)\n",
			   __FILE__, __LINE__, len, packetsize);
	      continue;
	    }
	  
	  block = ntohs (tp.u.ack.block = tr->u.data.block);
	}
      else
	/* Neither TFTP_OACK nor TFTP_DATA.  */
	break;

      if ((block || bcounter) && (block != prevblock + (unsigned short) 1))
	/* Block order should be continuous */
	tp.u.ack.block = htons (block = prevblock);
      
      /* Should be continuous.  */
      tp.opcode = abort ? htons (TFTP_ERROR) : htons (TFTP_ACK);
      oport = ntohs (tr->udp.src);

#ifdef TFTP_DEBUG
      grub_printf ("ACK\n");
#endif
      /* Ack.  */
      udp_transmit (arptable[ARP_SERVER].ipaddr.s_addr, iport,
		    oport, TFTP_MIN_PACKET, &tp);
      
      if (abort)
	{
	  buf_eof = 1;
	  break;
	}

      /* Retransmission or OACK.  */
      if ((unsigned short) (block - prevblock) != 1)
	/* Don't process.  */
	continue;
      
      prevblock = block;
      /* Is it the right place to zero the timer?  */
      retry = 0;

      /* In GRUB, this variable doesn't play any important role at all,
	 but use it for consistency with Etherboot.  */
      bcounter++;
      
      /* Copy the downloaded data to the buffer.  */
      grub_memmove (buf + buf_read, tr->u.data.download, len);
      buf_read += len;

      /* End of data.  */
      if (len < packetsize)		
	buf_eof = 1;
    }
  
  return 1;
}

/* Send the RRQ whose length is LEN.  */
static int
send_rrq (void)
{
  /* Initialize some variables.  */
  retry = 0;
  block = 0;
  prevblock = 0;
  packetsize = TFTP_DEFAULTSIZE_PACKET;
  bcounter = 0;

  buf = (char *) FSYS_BUF;
  buf_eof = 0;
  buf_read = 0;
  saved_filepos = 0;

  rx_qdrain();
  
#ifdef TFTP_DEBUG
  grub_printf ("send_rrq ()\n");
  {
    int i;
    char *p;

    for (i = 0, p = (char *) &tp; i < len; i++)
      if (p[i] >= ' ' && p[i] <= '~')
	grub_putchar (p[i]);
      else
	grub_printf ("\\%x", (unsigned) p[i]);

    grub_putchar ('\n');
  }
#endif
  /* Send the packet.  */
  return udp_transmit (arptable[ARP_SERVER].ipaddr.s_addr, ++iport,
		       TFTP_PORT, len, &tp);
}

/* Mount the network drive. If the drive is ready, return one, otherwise
   return zero.  */
int
tftp_mount (void)
{
  /* Check if the current drive is the network drive.  */
  if (current_drive != NETWORK_DRIVE)
    return 0;

  /* If the drive is not initialized yet, abort.  */
  if (! network_ready)
    return 0;

  return 1;
}

/* Read up to SIZE bytes, returned in ADDR.  */
int
tftp_read (char *addr, int size)
{
  /* How many bytes is read?  */
  int ret = 0;

#ifdef TFTP_DEBUG
  grub_printf ("tftp_read (0x%x, %d)\n", (int) addr, size);
#endif
  
  if (use_bios_pxe)
	return (tftp_read_undi(addr, size));

  if (filepos < saved_filepos)
    {
      /* Uggh.. FILEPOS has been moved backwards. So reopen the file.  */
      buf_read = 0;
      buf_fill (1);
      grub_memmove ((char *) &tp, (char *) &saved_tp, saved_len);
      len = saved_len;
#ifdef TFTP_DEBUG
      {
	int i;
	grub_printf ("opcode = 0x%x, rrq = ", (unsigned long) tp.opcode);
	for (i = 0; i < TFTP_DEFAULTSIZE_PACKET; i++)
	  {
	    if (tp.u.rrq[i] >= ' ' && tp.u.rrq[i] <= '~')
	      grub_putchar (tp.u.rrq[i]);
	    else
	      grub_putchar ('*');
	  }
	grub_putchar ('\n');
      }
#endif
      
      if (! send_rrq ())
	{
	  errnum = ERR_WRITE;
	  return 0;
	}
    }
  
  while (size > 0)
    {
      int amt = buf_read + saved_filepos - filepos;

      /* If the length that can be copied from the buffer is over the
	 requested size, cut it down.  */
      if (amt > size)
	amt = size;

      if (amt > 0)
	{
	  /* Copy the buffer to the supplied memory space.  */
	  grub_memmove (addr, buf + filepos - saved_filepos, amt);
	  size -= amt;
	  addr += amt;
	  filepos += amt;
	  ret += amt;

	  /* If the size of the empty space becomes small, move the unused
	     data forwards.  */
	  if (filepos - saved_filepos > FSYS_BUFLEN / 2)
	    {
	      grub_memmove (buf, buf + FSYS_BUFLEN / 2, FSYS_BUFLEN / 2);
	      buf_read -= FSYS_BUFLEN / 2;
	      saved_filepos += FSYS_BUFLEN / 2;
	    }
	}
      else
	{
	  /* Skip the whole buffer.  */
	  saved_filepos += buf_read;
	  buf_read = 0;
	}

      /* Read the data.  */
      if (size > 0 && ! buf_fill (0))
	{
	  errnum = ERR_READ;
	  return 0;
	}

      /* Sanity check.  */
      if (size > 0 && buf_read == 0)
	{
	  errnum = ERR_READ;
	  return 0;
	}
    }

  return ret;
}

/* Check if the file DIRNAME really exists. Get the size and save it in
   FILEMAX.  */
int
tftp_dir (char *dirname)
{
  int ch;

#ifdef TFTP_DEBUG
  grub_printf ("tftp_dir (%s)\n", dirname);
#endif
  
  if (use_bios_pxe)
	return (tftp_dir_undi(dirname));

  /* In TFTP, there is no way to know what files exist.  */
  if (print_possibilities)
    return 1;

  /* Don't know the size yet.  */
  filemax = -1;
  
 reopen:
  /* Construct the TFTP request packet.  */
  tp.opcode = htons (TFTP_RRQ);
  /* Terminate the filename.  */
  ch = nul_terminate (dirname);
  /* Make the request string (octet, blksize and tsize).  */
  len = (grub_sprintf ((char *) tp.u.rrq,
		       "%s%coctet%cblksize%c%d%ctsize%c0",
		       dirname, 0, 0, 0, TFTP_MAX_PACKET, 0, 0)
	 + sizeof (tp.ip) + sizeof (tp.udp) + sizeof (tp.opcode) + 1);
  /* Restore the original DIRNAME.  */
  dirname[grub_strlen (dirname)] = ch;
  /* Save the TFTP packet so that we can reopen the file later.  */
  grub_memmove ((char *) &saved_tp, (char *) &tp, len);
  saved_len = len;
  if (! send_rrq ())
    {
      errnum = ERR_WRITE;
      return 0;
    }
  
  /* Read the data.  */
  if (! buf_fill (0))
    {
      errnum = ERR_FILE_NOT_FOUND;
      return 0;
    }

  if (filemax == -1)
    {
      /* The server doesn't support the "tsize" option, so we must read
	 the file twice...  */

      /* Zero the size of the file.  */
      filemax = 0;
      do
	{
	  /* Add the length of the downloaded data.  */
	  filemax += buf_read;
	  /* Reset the offset. Just discard the contents of the buffer.  */
	  buf_read = 0;
	  /* Read the data.  */
	  if (! buf_fill (0))
	    {
	      errnum = ERR_READ;
	      return 0;
	    }
	}
      while (! buf_eof);

      /* Maybe a few amounts of data remains.  */
      filemax += buf_read;
      
      /* Retry the open instruction.  */
      goto reopen;
    }

  return 1;
}

/* Close the file.  */
void
tftp_close (void)
{
#ifdef TFTP_DEBUG
  grub_printf ("tftp_close ()\n");
#endif
  
  if (use_bios_pxe) {
	tftp_close_undi();
	return;
  }

  buf_read = 0;
  buf_fill (1);
}

/* tftp implementation using BIOS established PXE stack */

static int tftp_file_read_undi(const char *name,
    int (*fnc)(unsigned char *, unsigned int, unsigned int, int))
{
	int rc;
	uint16_t len;
	
	buf = (char *)&nic.packet;
	/* open tftp session */
	if (eb_pxenv_tftp_open(name, arptable[ARP_SERVER].ipaddr,
	    arptable[ARP_GATEWAY].ipaddr, &packetsize) == 0)
		return (0);

	/* read blocks and invoke fnc for each block */
	for (;;) {
		rc = eb_pxenv_tftp_read(buf, &len);
		if (rc == 0)
			break;
		rc = fnc(buf, ++block, len, len < packetsize);
		if (rc <= 0 || len < packetsize)
			break;
	}

	(void) eb_pxenv_tftp_close();
	return (rc > 0 ? 1 : 0);
}

/* Fill the buffer by reading the data via the TFTP protocol.  */
static int
buf_fill_undi(int abort)
{
	int rc;
	uint8_t *tmpbuf;

	while (! buf_eof && (buf_read + packetsize <= FSYS_BUFLEN)) {
		poll_interruptions();
		if (user_abort)
			return 0;
		if (abort) {
			buf_eof = 1;
			break;
		}

		if (eb_pxenv_tftp_read(buf + buf_read, &len) == 0)
			return (0);

		buf_read += len;

		/* End of data.  */
		if (len < packetsize)		
			buf_eof = 1;
	}
	return 1;
}

static void
tftp_reopen_undi(void)
{
	tftp_close();
	(void) eb_pxenv_tftp_open(saved_name, arptable[ARP_SERVER].ipaddr,
	    arptable[ARP_GATEWAY].ipaddr, &packetsize);

	buf_eof = 0;
	buf_read = 0;
	saved_filepos = 0;
}

/* Read up to SIZE bytes, returned in ADDR.  */
static int
tftp_read_undi(char *addr, int size)
{
	int ret = 0;

	if (filepos < saved_filepos) {
		/* Uggh.. FILEPOS has been moved backwards. reopen the file. */
		tftp_reopen_undi();
	}

	while (size > 0) {
		int amt = buf_read + saved_filepos - filepos;

		/* If the length that can be copied from the buffer is over
		   the requested size, cut it down. */
		if (amt > size)
			amt = size;

		if (amt > 0) {
			/* Copy the buffer to the supplied memory space.  */
			grub_memmove (addr, buf + filepos - saved_filepos, amt);
			size -= amt;
			addr += amt;
			filepos += amt;
			ret += amt;

			/* If the size of the empty space becomes small,
			 * move the unused data forwards.
			 */
			if (filepos - saved_filepos > FSYS_BUFLEN / 2) {
				grub_memmove (buf, buf + FSYS_BUFLEN / 2,
				    FSYS_BUFLEN / 2);
				buf_read -= FSYS_BUFLEN / 2;
				saved_filepos += FSYS_BUFLEN / 2;
			}
		} else {
			/* Skip the whole buffer.  */
			saved_filepos += buf_read;
			buf_read = 0;
		}

		/* Read the data.  */
		if (size > 0 && ! buf_fill (0)) {
			errnum = ERR_READ;
			return 0;
		}

		/* Sanity check.  */
		if (size > 0 && buf_read == 0) {
			errnum = ERR_READ;
			return 0;
		}
	}

	return ret;
}

static int
tftp_dir_undi(char *dirname)
{
	int rc, ch;
	uint16_t len;

	/* In TFTP, there is no way to know what files exist.  */
	if (print_possibilities)
		return 1;

	/* name may be space terminated */
	ch = nul_terminate(dirname);
	saved_name = (char *)&saved_tp;
	sprintf(saved_name, "%s", dirname);

  	/* Restore the original dirname */
	dirname[grub_strlen (dirname)] = ch;

	/* get the file size; must call before tftp_open */
	rc = eb_pxenv_tftp_get_fsize(saved_name, arptable[ARP_SERVER].ipaddr,
	    arptable[ARP_GATEWAY].ipaddr, &filemax);

	/* open tftp session */
	if (eb_pxenv_tftp_open(saved_name, arptable[ARP_SERVER].ipaddr,
	    arptable[ARP_GATEWAY].ipaddr, &packetsize) == 0)
		return (0);

	buf = (char *) FSYS_BUF;
	buf_eof = 0;
	buf_read = 0;
	saved_filepos = 0;

	if (rc == 0) {
		/* Read the entire file to get filemax */
		filemax = 0;
		do {
			/* Add the length of the downloaded data.  */
			filemax += buf_read;
			buf_read = 0;
			if (! buf_fill (0)) {
				errnum = ERR_READ;
				return 0;
			}
		} while (! buf_eof);

		/* Maybe a few amounts of data remains.  */
		filemax += buf_read;

		tftp_reopen_undi(); /* reopen file to read from beginning */
	}

	return (1);
}

static void
tftp_close_undi(void)
{
	buf_read = 0;
	buf_fill (1);
	(void) eb_pxenv_tftp_close();
}
