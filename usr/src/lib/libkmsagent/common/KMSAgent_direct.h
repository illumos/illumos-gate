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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/**
 * \file direct.h
 *
 * This file is included in KMSAgentStorage.cpp to provide file handling
 * hooks. It also contains our EEPROM file handling functions.
 *
 * HISTORY:
 * 8/6/07   BJB  Added code for 9840D encryption sectors
 * 4/7/08   BJB  Changed to remove 'file is junk' message - EVT
 *                 didn't like it.
 * 4/24/08  BJB  Added function call back to T10000/9840D code
 *                 to lookup eeprom address -
 *                 so it isn't a hardcoded value.
 * 05/09/08 BJB  Added being more conservative about EEPROM so as to change
 *                 frequency of 32CA problems
 * 
 */


#ifndef KMSAGENT_DIRECT_H
#define KMSAGENT_DIRECT_H

#include <stdio.h>
#include <string.h>

#ifdef WIN32
#include <direct.h>
#endif

#define my_unlink(a) unlink(a)
#define my_rmdir(a)  rmdir(a)

#ifndef METAWARE

#define myFILE FILE

#else // METAWARE

#include "SYSCommon.h"
#include "debug.h"
#include <snprintf.h>

extern "C" void ecpt_trace_msg(ECPT_TRACE_ENTRY*,const char*,...);

extern char st[256];


#ifndef I_KNOW_REAL_NAMES
#undef fopen
#undef fclose
#undef fputs
#undef fgets
#undef fwrite
#undef fread
#undef unlink
#undef rmdir

#define fopen  my_eeprom_fopen
#define fclose my_eeprom_fclose
#define fputs  my_eeprom_fputs
#define fwrite my_eeprom_fwrite
#define fread  my_eeprom_fread
#define fgets  my_eeprom_fgets
#define unlink my_eeprom_unlink
#define rmdir  my_eeprom_rmdir

#define my_eeprom_rmdir(a)  (1)

#endif


#include "KMSClientProfile.h"
extern char KMSAgent_Version[KMS_MAX_VERSION_LENGTH];

unsigned char volatile* eeprom_addr_lookup_FILESYSTEM_START_ADDR(void);
unsigned int  EEPROM_Sector_size(void);

#define FILESYSTEM_SECTOR     (eeprom_addr_lookup_FILESYSTEM_START_ADDR())
// was ((unsigned char volatile*)0xf20000)   on 9840
// was ((unsigned char volatile*)0x41dc0000) on T10000

#define FILESYSTEM_SECTOR_SIZE (EEPROM_Sector_size())
// was hardcoded 0x20000

#define EEPROM_ERASED_BYTE      0xFF

/* size of a file allowed (not counting the name) */
#define EEPROM_FILE_SECT_SIZE   0x1800

/* size of a file name allowed (+ the null) */
#define EEPROM_FNAME_SIZE       0x80

// 1000h = 4096d
#define EEPROM_BLOCK_SIZE       (EEPROM_FILE_SECT_SIZE - EEPROM_FNAME_SIZE - 4)

/*  number of 'files' available */
#define FTABLE_SIZE             0x5


#define UCHAR8 unsigned char
#define UINT32 unsigned long


extern "C" unsigned long
EEPROM_Sector_Erase( unsigned char volatile *sector_address );

extern "C" unsigned long
Flash_Write( UCHAR8 *destinationP,
             UCHAR8 *sourceP,
             UINT32  byteCount);
   
extern "C" unsigned long
Flash_Read( UCHAR8 *dstP,
            UCHAR8 *srcP,
            UINT32  byteCount);

/* a eeprom file */
struct eepromBlockStruct
{
   unsigned long fsize;
   char          fname[EEPROM_FNAME_SIZE];
   unsigned char fdata[EEPROM_BLOCK_SIZE];
};


struct fileSystem
{
   struct eepromBlockStruct ftable[FTABLE_SIZE];
   /* what level of toolkit wrote this - for
      future compatibility */
   char writingversion[KMS_MAX_VERSION_LENGTH+1];
};


#define MODE_WRITE 0x01
#define MODE_READ  0x02

#define MYFILE_CLOSED      0x0
#define MYFILE_OPEN_READ   0x1
#define MYFILE_OPEN_WRITE  0x2


/* an open file */
typedef struct fileStruct
{
   unsigned char *readptr;
   unsigned long readsize;
   unsigned char *writeptr;
   struct eepromBlockStruct *memptr;
   unsigned long mode;
   unsigned long file_number;
} myFILE;


extern "C" myFILE *my_eeprom_fopen  (const char *filename, const char *mode);
extern "C" int     my_eeprom_fclose (myFILE *stream);
extern "C" int     my_eeprom_fputs  (const char *s, myFILE *stream);
extern "C" int     my_eeprom_fwrite (const char *s, int size, int nobj, myFILE *f);
extern "C" int     my_eeprom_fread  (char *s, int size, int nobj, myFILE *f);
extern "C" char   *my_eeprom_fgets  (char *s, int n, myFILE *stream);
extern "C" int     my_eeprom_unlink (const char *filename);
extern "C" int     my_eeprom_fsys_erase(void);

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#ifdef DEFINE_STORAGE
/* ram copy of the file system */
struct fileSystem ramFileSystem;
int file_read = FALSE;

/* file state - open/closed/etc */
unsigned long fstate[FTABLE_SIZE] = {MYFILE_CLOSED,
                                     MYFILE_CLOSED,
                                     MYFILE_CLOSED,
                                     MYFILE_CLOSED,
                                     MYFILE_CLOSED};
#else
/* ram copy of the file system */
extern struct fileSystem ramFileSystem;
extern int file_read;

/* file state - open/closed/etc */
extern unsigned long fstate[FTABLE_SIZE];

#endif



#ifdef DEFINE_STORAGE


extern "C" unsigned long


/* UNIT TEST */
int TESTV = 0;

/* UNIT TEST */
#define MY_FLASH_READ(a,b,c) \
  Flash_Read(a,b,c); \
  if (TESTV++ < 5) { \
     ramFileSystem.ftable[0].fname[0] = EEPROM_ERASED_BYTE; \
     ramFileSystem.ftable[1].fsize = EEPROM_BLOCK_SIZE+1;   \
  } 
 


/**
 * my_eeprom_fopen()
 * my filesystem fileopen
 */
extern "C" myFILE *my_eeprom_fopen(const char *filename, const char *mode)
{
   int i;
   myFILE *file;
   int open_for_write = TRUE;
   static int Firsttime = TRUE;
   int retries = 100;

   ECPT_TRACE_ENTRY   *trace = NULL;  
   ECPT_TRACE( trace, my_eeprom_fopen ) ;
   ecpt_trace_msg( trace, "file %s", (char*)filename);
  
   FATAL_ASSERT(filename);
   FATAL_ASSERT(mode);

   if ( (strcmp(mode,"wb") == 0) ||
        (strcmp(mode,"w") == 0))
   {
      // write
      open_for_write = TRUE;
   }
   else if ( (strcmp(mode,"r") == 0) ||
             (strcmp(mode,"rb") == 0) )
   {
      // read binary
      open_for_write = FALSE;
   }
   else
   {
      FATAL_APPLICATION_STATE("my_eeprom_fopen : Illegal mode");
   }
   
   /* read the file table from eeprom? */
   if (!file_read)
   {
     RETRY:
      
      MY_FLASH_READ((unsigned char *)&ramFileSystem,
                    (unsigned char *)FILESYSTEM_SECTOR,
                    sizeof(ramFileSystem));

      /* Audit the filesystem - if it looks junked, reclaim bad files */

      for (i=0; i < FTABLE_SIZE; i++)
      {
         if ( (ramFileSystem.ftable[i].fname[0] == EEPROM_ERASED_BYTE) ||
              (ramFileSystem.ftable[i].fsize >     EEPROM_BLOCK_SIZE)  )
         {
            /* if this looks bad, don't accept this outcome until
               100 retries */
            if (retries-- > 0)
            {
               ecpt_trace_msg( trace, "file was junk - retrying %s", (char*)filename);
               log_error_printf(
                  "KMSAgent_direct::fopen file %d is junk - (name %x, "
                  "size %x, data %x) RETRYING \n",
                  i,
                  ramFileSystem.ftable[i].fname[0],
                  ramFileSystem.ftable[i].fsize ,
                  ramFileSystem.ftable[i].fdata[0]);
               
               goto RETRY;
            }
            else
            {
               ecpt_trace_msg( trace, "file was junk - formatting %s", (char*)filename);
               log_error_printf(
                  "KMSAgent_direct::fopen file %d is junk - (name %x, "
                  "size %x, data %x) formatting it\n",
                  i,
                  ramFileSystem.ftable[i].fname[0],
                  ramFileSystem.ftable[i].fsize ,
                  ramFileSystem.ftable[i].fdata[0]);
               
               /* set data to reasonable starting values */
               ramFileSystem.ftable[i].fname[0] = 0;
               ramFileSystem.ftable[i].fsize    = 0;
               ramFileSystem.ftable[i].fdata[0] = 0;
            }
               
         }
         
      } /* for */
         
      file_read = TRUE;
         
   } /* !file read */
   
   /* read the file table */
   for (i=0; i < FTABLE_SIZE; i++)
   {
      /* compare filename to ram copy filename */
      if (strcmp(filename, (const char *)ramFileSystem.ftable[i].fname) == 0)
      {

         if (fstate[i] != MYFILE_CLOSED)
         {
            log_printf("KMSAgent_direct::fopen FN=%s file matches, "
                       "FILE %d WAS ALREADY OPEN for %s with mode %s"
                       "file size is %d \n",
                       filename,
                       i,
                       (fstate[i] == MYFILE_OPEN_WRITE ? "WRITE": "READ"),
                       mode,
                       ramFileSystem.ftable[i].fsize);
         }
         
         /* create a new ramfile handle */
         file = malloc(sizeof(myFILE));

         /* since file is being rewritten, it is now size 0 */
         if (open_for_write)
            ramFileSystem.ftable[i].fsize = 0;

         /* remember the file is open */
         fstate[i]= open_for_write ? MYFILE_OPEN_WRITE : MYFILE_OPEN_READ;
         
 
         /* if filename matches, set file pointers to it */
         file->writeptr = file->readptr = ramFileSystem.ftable[i].fdata;
         file->memptr   = &ramFileSystem.ftable[i];
         file->readsize = 0;
         file->mode = open_for_write ? MODE_WRITE : MODE_READ;
         file->file_number = i;


         log_printf("KMSAgent_direct::fopen FN=%s file matches, "
                    "opening existing file number %d with mode %s"
                    "file size is %d \n",
                    filename,
                    i,
                    mode,
                    ramFileSystem.ftable[i].fsize);

         break;
      }
      
   }
   
   /* if no existing entry was found, assign a new entry to this filename */
   if (i == FTABLE_SIZE)
   {
      /* couldn't find an old file and opened for read so return NULL */
      if (open_for_write == FALSE)
      {


         log_printf("KMSAgent_direct::fopen FN=%s no file match, "
                    "file opened for read so return NULL %d\n",
                    filename,
                    i);

         
         return NULL;
      }
      
      /* find a free file pointer */
      for (i=0; i < FTABLE_SIZE ; i++)
      {
         /* empty data will be 0xffffffff since it was copied
            straight from EEPROM */
         if (ramFileSystem.ftable[i].fname[0] == '\0')
         {
            log_printf("KMSAgent_direct::fopen FN=%s no file match, "
                       "opening new file %d\n",
                       filename,
                       i);

            /* give it a filename - marks this as in use */
            strcpy ((char *)ramFileSystem.ftable[i].fname, filename);
            
            /* set filesize to zero */
            ramFileSystem.ftable[i].fsize = 0;

            /* remember the file is open */
            fstate[i]= open_for_write ? MYFILE_OPEN_WRITE : MYFILE_OPEN_READ;

            
            /* create a new ramfile handle */
            file = malloc(sizeof(myFILE));
            
            /* if filename matches, set file pointers to it */
            file->writeptr = file->readptr = ramFileSystem.ftable[i].fdata;
            file->memptr =  &ramFileSystem.ftable[i];
            file->readsize = 0;
            file->mode = open_for_write ? MODE_WRITE : MODE_READ;
            file->file_number = i;
            
            break;
         }
         
      }
      
      if (i == FTABLE_SIZE)
      {
         log_error_printf("KMSAgent_direct::fopen FN=%s no free files \n",
                          filename);
         /* no free entries - bail */
         return NULL;
      }
      
   }

   /* return pointer to the myFILE struct created */
   return file;
   
}

/**
 * my_eeprom_fclose()
 * my filesystem fileclose
 */
extern "C" int  my_eeprom_fclose(myFILE *f)
{
   ECPT_TRACE_ENTRY   *trace = NULL;  
   ECPT_TRACE( trace, my_eeprom_fclose ) ;
   ecpt_trace_msg( trace, "entered");
   
   FATAL_ASSERT(f);

#ifdef DEBUG
   log_printf("KMSAgent_direct::fclose FN=%s, "
              "FILE %d "
              "file size is %d \n",
              ramFileSystem.ftable[f->file_number].fname,
              f->file_number,
              ramFileSystem.ftable[f->file_number].fsize);
#endif

   if (fstate[f->file_number] == MYFILE_CLOSED)
   {
      log_error_printf("KMSAgent_direct::fclose FN=%s, "
                       "FILE %d WAS ALREADY CLOSED "
                       "file size is %d \n",
                       ramFileSystem.ftable[f->file_number].fname,
                       f->file_number,
                       ramFileSystem.ftable[f->file_number].fsize);
   }

   /* remember the file is closed */
   fstate[f->file_number]= MYFILE_CLOSED;
   
   /* don't rewrite eeprom unless file was opened for writing */
   if (f->mode == MODE_WRITE)
   {
      /* Erase the sector we are rewriting */
      EEPROM_Sector_Erase( (unsigned char*)FILESYSTEM_SECTOR ) ;

      /* remember the version of toolkit that wrote this filesystem
         (for any future compatibility problems). */
      strncpy(ramFileSystem.writingversion,
              KMSAgent_Version,
              sizeof(KMSAgent_Version));

      /* flush the memory indicated by myFILE * out to EEPROM */
      /* see boot_eeprom.c for details on Flash_Write */
      Flash_Write ((unsigned char*)FILESYSTEM_SECTOR,
                   (unsigned char*)&ramFileSystem,
                   FILESYSTEM_SECTOR_SIZE);
   }
   
   /* delete the placeholder file */
   free(f);

   return 0;
}

/**
 * my_eeprom_fputs()
 * my filesystem put string
 */
extern "C" int  my_eeprom_fputs(const char *s, myFILE *f)
{
   /* put the string to the memory indicated by myFILE */
   int i;
   ECPT_TRACE_ENTRY   *trace = NULL;  
   ECPT_TRACE( trace, my_eeprom_fputs ) ;

   ecpt_trace_msg (trace, "\nmy_eeprom_fputs : Entered");
   
#ifdef DEBUG
   log_printf(
      "\nKMSAgent_direct::my_eeprom_fputs "
      "f->writeptr =%x "
      "f->readptr=%x "
      "f->readsize=%x "
      "f->memptr=%x"
      "f->memptr->fsize=%x\n",
      f->writeptr,
      f->readptr,
      f->readsize,
      f->memptr,
      f->memptr->fsize);
   
#endif

   FATAL_ASSERT(s);
   FATAL_ASSERT(f);
   
   for (i=0;;i++)
   {
      /* end of input string? quit */
      if (*s == '\0')
         break;

      /* end of max file memory, quit */
      if ((unsigned char*)s >=
          (unsigned char*)(f->memptr + sizeof(struct eepromBlockStruct)))
         break;
      
      /* copy */
      *(f->writeptr) = *s++;
      f->writeptr++;
      
      /* increment the filesize */
      f->memptr->fsize += 1;
      
   }

#ifdef DEBUG
   log_printf(
           "\nKMSAgent_direct::fputs wrote %d chars, "
           "filesize is %d\n",
           i,
           f->memptr->fsize );
#endif
   
   /* return how many chars were written */
   return i;
}


/**
 * my_eeprom_fwrite()
 * my filesystem put string
 */
extern "C" int  my_eeprom_fwrite(const char *s,
                                 int size,
                                 int nobj,
                                 myFILE *f)
{
   /* put the string to the memory indicated by myFILE */
   int i,j;
   
   ECPT_TRACE_ENTRY   *trace = NULL;  
   ECPT_TRACE( trace, my_eeprom_fwrite ) ;
   ecpt_trace_msg ( trace, "Entered");

   log_printf(
           "\nKMSAgent_direct::my_eeprom_fputs "
           "f->writeptr =%x "
           "f->readptr=%x "
           "f->readsize=%x "
           "f->memptr=%x"
           "f->memptr->fsize=%x\n",
           f->writeptr,
           f->readptr,
           f->readsize,
           f->memptr,
           f->memptr->fsize);

   FATAL_ASSERT(s);
   FATAL_ASSERT(f);
   FATAL_ASSERT((size*nobj) > 0);
   
   for (i=0; i<nobj; i++)
   {
      for (j=0; j<size; j++)
      {
         /* end of max file memory, quit */
         if ((unsigned char*)s >=
             (unsigned char*)(f->memptr + sizeof(struct eepromBlockStruct)))
            goto DONE;
      
         /* copy */
         *(f->writeptr) = *s++;
         f->writeptr++;
      
         /* increment the filesize */
         f->memptr->fsize += 1;
      }
      
   }

  DONE:
   
   
#ifdef DEBUG
   log_printf(
           "\nKMSAgent_direct::fwrite wrote %d chars, "
           "filesize is %d\n",
           i,
           f->memptr->fsize );
#endif
   
   /* return how many objects were written */
   return i;
}



/**
 * my_eeprom_fgets()
 * my filesystem getstring
 */
extern "C" char *my_eeprom_fgets(char *s, int n, myFILE *f)
{
   /* put the string to the memory indicated by myFILE */
   int i;
   char *tmp = s;

   ECPT_TRACE_ENTRY   *trace = NULL;  
   ECPT_TRACE( trace, my_eeprom_fgets ) ;
   ecpt_trace_msg (trace, "entered");
   
   FATAL_ASSERT(s);
   FATAL_ASSERT(n > 0);
   FATAL_ASSERT(f);
   
#ifdef DEBUG
   log_printf(
           "\nKMSAgent_direct::my_eeprom_fgets from file %s "
           "fileptr %x "
           "readptr = %x "
           "readsize = %d "
           "filesize = %d \n",
           f->memptr->fname,
           f,
           f->readptr,
           f->readsize,
           f->memptr->fsize);
#endif    

   /* get up to n-1 (and a \0) chars */
   for (i=0; i < n; i++)
   {
      /* end of read line? quit */
      if (*f->readptr == '\n')
      {
         /* increment the number of bytes read */
         f->readptr++;
         f->readsize++;
         break;
      }
      
      /* trying to read beyond what was written? quit */
      if (f->readsize >
          f->memptr->fsize)
      {
#ifdef DEBUG
         log_printf(
                  "\nKMSAgent_direct::fgets eof after %d chars, "
                  "readsize is %d "
                  "filesize is %d\n",
                  i,
                  f->readsize,
                  f->memptr->fsize);
#endif    
         return NULL;
      }

      /* trying to read beyond max file memory, quit */
      if ((unsigned char*)f->readptr >=
          (unsigned char*)(f->memptr + sizeof(struct eepromBlockStruct)))
      {
#ifdef DEBUG
         log_printf(
                 "\nKMSAgent_direct::fgets end of max file after %d chars "
                 "readsize is %d "
                 "filesize is %d\n",
                 i,
                 f->readsize,
                 f->memptr->fsize);
#endif    
         /* EOF or error is signalled by NULL return */
         return NULL;
      }
      
      /* copy a char */
      *tmp++ = *f->readptr;

      /* increment the number of bytes read */
      f->readptr++;
      f->readsize++;
      
   } /* for */

   /* terminate the returned string with a 0, but not a \n */
   *tmp='\0';
   
#ifdef DEBUG
   /* terminate returned string after a non-absurd number of chars
    */   
   log_printf(
           "\nKMSAgent_direct::fgets string [%s] "
           "end of line after %d chars "
           "readsize is %d "
           "filesize is %d\n",
           s,
           i,
           f->readsize,
           f->memptr->fsize);
#endif    

   /* on success, return the original pointer */
   return s;
}




/**
 * my_eeprom_fread()
 * my filesystem read a file
 */
extern "C" int my_eeprom_fread(char *s, int size, int nobj, myFILE *f)
{
   /* put the string to the memory indicated by myFILE */
   int i,j;
   
   ECPT_TRACE_ENTRY   *trace = NULL;  
   ECPT_TRACE( trace, my_eeprom_fread ) ;
   ecpt_trace_msg (trace, "entered");

   FATAL_ASSERT(s);
   FATAL_ASSERT(f);
   FATAL_ASSERT((size*nobj) > 0);
   
   for (i=0; i<nobj; i++)
   {
      for (j=0; j<size; j++)
      {
         /* end of written file memory, quit */
         if ( (unsigned char*) s >=
              (unsigned char*) (f->memptr + f->memptr->fsize) )
            goto DONE;
      
         /* copy */
         *s++ = *(f->readptr);
         f->readptr++;
      }
      
   }

  DONE:
   
#ifdef DEBUG
   log_printf(
           "\nKMSAgent_direct::fread read %d chars, "
           "filesize is %d\n",
           i,
           f->memptr->fsize );
#endif
   
   /* return how many objects were written */
   return i;

}






/**
 * my_eeprom_unlink() - delete the file named
 */
extern "C" int my_eeprom_unlink(const char *filename)
{
   int i;
   
   ECPT_TRACE_ENTRY   *trace = NULL;  
   ECPT_TRACE( trace, my_eeprom_fgets ) ;
   ecpt_trace_msg (trace, "Entered fn=%s", (char*)filename);
   
   /* assume the file is closed */
   FATAL_ASSERT(filename);
   
   /* read the file table */
   for (i=0; i < FTABLE_SIZE; i++)
   {

      if (fstate[i] != MYFILE_CLOSED)
      {
         log_error_printf("KMSAgent_direct::unlink FN=%s file matches, "
                          "FILE %d WAS STILL OPEN for %s" 
                          "file size is %d \n",
                          filename,
                          i,
                          (fstate[i] == MYFILE_OPEN_WRITE ? "WRITE": "READ"),
                          ramFileSystem.ftable[i].fsize);
      }
      
      /* compare input filename to ram copy filename */
      if (strcmp(filename, (const char*)ramFileSystem.ftable[i].fname) == 0)
      {
         /* if filename matches, zero it out to delete the file */
         ramFileSystem.ftable[i].fname[0] = '\0';
         ramFileSystem.ftable[i].fsize    = 0;
         ramFileSystem.ftable[i].fdata[0] = 1;

         /* remember the file is closed */
         fstate[i]= MYFILE_CLOSED;
 
         EEPROM_Sector_Erase( FILESYSTEM_SECTOR ) ;

         /* remember the version of toolkit that wrote this filesystem
            (for any future compatibility problems). */
         strncpy(ramFileSystem.writingversion,
                 KMSAgent_Version,
                 sizeof(KMSAgent_Version));
         
         /* flush the memory indicated by myFILE * out to EEPROM */
         Flash_Write ((unsigned char*)FILESYSTEM_SECTOR,
                      (unsigned char*)&ramFileSystem,
                      FILESYSTEM_SECTOR_SIZE);
         
         break;
      }
  
   }
   
#ifdef DEBUG
   log_printf ("my_eeprom_unlink : returning");
#endif 

   if (i == FTABLE_SIZE)
      return -1;

   /* success */
   return 0;
}


/**
 * my_eeprom_fsys_erase() - delete all files
 */
extern "C" int my_eeprom_fsys_erase(void)
{
   int i;

   ECPT_TRACE_ENTRY   *trace = NULL;  
   ECPT_TRACE( trace, my_eeprom_fread ) ;
   ecpt_trace_msg (trace, "my_eeprom_fsys_erase : entering ");
   
   /* read the file table */
   for (i=0; i < FTABLE_SIZE; i++)
   {
      if (fstate[i] != MYFILE_CLOSED)
      {
         log_error_printf("KMSAgent_direct::fsys_erase FN=%s file "
                          "FILE %d WAS STILL OPEN for %s "
                          "file size is %d \n",
                          ramFileSystem.ftable[i].fname,
                          i,
                          (fstate[i] == MYFILE_OPEN_WRITE ? "WRITE": "READ"),
                          ramFileSystem.ftable[i].fsize);
      }

      /* zero filename out to delete the file */
      ramFileSystem.ftable[i].fname[0] = '\0';
      ramFileSystem.ftable[i].fsize    = 0;
      ramFileSystem.ftable[i].fdata[0] = 2;
      
      /* remember the file is closed */
      fstate[i]= MYFILE_CLOSED;

      EEPROM_Sector_Erase( FILESYSTEM_SECTOR ) ;

      /* remember the version of toolkit that wrote this filesystem
         (for any future compatibility problems). */
      strncpy(ramFileSystem.writingversion,
              KMSAgent_Version,
              sizeof(KMSAgent_Version));

      /* flush the memory indicated by myFILE * out to EEPROM */
      Flash_Write ((unsigned char*)FILESYSTEM_SECTOR,
                   (unsigned char*)&ramFileSystem,
                   FILESYSTEM_SECTOR_SIZE);
         
  
   }
   
#ifdef DEBUG
   log_printf ("\nmy_eeprom_fsys_erase : returning");
#endif
   
   if (i == FTABLE_SIZE)
      return -1;

   /* success */
   return 0;
}




#endif  // DEFINE_STORAGE
#endif  // METAWARE
#endif

