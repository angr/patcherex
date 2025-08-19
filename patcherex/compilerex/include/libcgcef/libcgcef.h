/*
 * libcgcef.h - public header file for libcgcef.
 * Copyright (C) 1995 - 2008 Michael Riepe
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 * 
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* @(#) $Id: libcgcef.h,v 1.29 2009/07/07 17:57:43 michael Exp $ */

#ifndef _LIBCGCEF_H
#define _LIBCGCEF_H

#include <stddef.h>	/* for size_t */
#include <sys/types.h>

#if __LIBCGCEF_INTERNAL__
#include <sys_cgcef.h>
#else /* __LIBCGCEF_INTERNAL__ */
#include <libcgcef/sys_cgcef.h>
#endif /* __LIBCGCEF_INTERNAL__ */

#if defined __GNUC__ && !defined __cplusplus
#define DEPRECATED	__attribute__((deprecated))
#else
#define DEPRECATED	/* nothing */
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef __P
# if (__STDC__ + 0) || defined(__cplusplus) || defined(_WIN32)
#  define __P(args) args
# else /* __STDC__ || defined(__cplusplus) */
#  define __P(args) ()
# endif /* __STDC__ || defined(__cplusplus) */
#endif /* __P */

/*
 * Commands
 */
typedef enum {
    CGCEF_C_NULL = 0,	/* must be first, 0 */
    CGCEF_C_READ,
    CGCEF_C_WRITE,
    CGCEF_C_CLR,
    CGCEF_C_SET,
    CGCEF_C_FDDONE,
    CGCEF_C_FDREAD,
    CGCEF_C_RDWR,
    CGCEF_C_NUM		/* must be last */
} CGCEf_Cmd;

/*
 * Flags
 */
#define CGCEF_F_DIRTY	0x1
#define CGCEF_F_LAYOUT	0x4
/*
 * Allow sections to overlap when CGCEF_F_LAYOUT is in effect.
 * Note that this flag ist NOT portable, and that it may render
 * the output file unusable.  Use with extreme caution!
 */
#define CGCEF_F_LAYOUT_OVERLAP	0x10000000

/*
 * File types
 */
typedef enum {
    CGCEF_K_NONE = 0,	/* must be first, 0 */
    CGCEF_K_AR,
    CGCEF_K_COFF,
    CGCEF_K_CGCEF,
    CGCEF_K_NUM		/* must be last */
} CGCEf_Kind;

/*
 * Data types
 */
typedef enum {
    CGCEF_T_BYTE = 0,	/* must be first, 0 */
    CGCEF_T_ADDR,
    CGCEF_T_DYN,
    CGCEF_T_EHDR,
    CGCEF_T_HALF,
    CGCEF_T_OFF,
    CGCEF_T_PHDR,
    CGCEF_T_RELA,
    CGCEF_T_REL,
    CGCEF_T_SHDR,
    CGCEF_T_SWORD,
    CGCEF_T_SYM,
    CGCEF_T_WORD,
    /*
     * New stuff for 64-bit.
     *
     * Most implementations add CGCEF_T_SXWORD after CGCEF_T_SWORD
     * which breaks binary compatibility with earlier versions.
     * If this causes problems for you, contact me.
     */
    CGCEF_T_SXWORD,
    CGCEF_T_XWORD,
    /*
     * Symbol versioning.  Sun broke binary compatibility (again!),
     * but I won't.
     */
    CGCEF_T_VDEF,
    CGCEF_T_VNEED,
    CGCEF_T_NUM		/* must be last */
} CGCEf_Type;

/*
 * CGCEf descriptor
 */
typedef struct CGCEf	CGCEf;

/*
 * Section descriptor
 */
typedef struct CGCEf_Scn	CGCEf_Scn;

/*
 * Archive member header
 */
typedef struct {
    char*		ar_name;
    time_t		ar_date;
    long		ar_uid;
    long 		ar_gid;
    unsigned long	ar_mode;
    off_t		ar_size;
    char*		ar_rawname;
} CGCEf_Arhdr;

/*
 * Archive symbol table
 */
typedef struct {
    char*		as_name;
    size_t		as_off;
    unsigned long	as_hash;
} CGCEf_Arsym;

/*
 * Data descriptor
 */
typedef struct {
    void*		d_buf;
    CGCEf_Type		d_type;
    size_t		d_size;
    off_t		d_off;
    size_t		d_align;
    unsigned		d_version;
} CGCEf_Data;

/*
 * Function declarations
 */
extern CGCEf *cgcef_begin __P((int __fd, CGCEf_Cmd __cmd, CGCEf *__ref));
extern CGCEf *cgcef_memory __P((char *__image, size_t __size));
extern int cgcef_cntl __P((CGCEf *__cgcef, CGCEf_Cmd __cmd));
extern int cgcef_end __P((CGCEf *__cgcef));
extern const char *cgcef_errmsg __P((int __err));
extern int cgcef_errno __P((void));
extern void cgcef_fill __P((int __fill));
extern unsigned cgcef_flagdata __P((CGCEf_Data *__data, CGCEf_Cmd __cmd,
	unsigned __flags));
extern unsigned cgcef_flagehdr __P((CGCEf *__cgcef, CGCEf_Cmd __cmd,
	unsigned __flags));
extern unsigned cgcef_flagcgcef __P((CGCEf *__cgcef, CGCEf_Cmd __cmd,
	unsigned __flags));
extern unsigned cgcef_flagphdr __P((CGCEf *__cgcef, CGCEf_Cmd __cmd,
	unsigned __flags));
extern unsigned cgcef_flagscn __P((CGCEf_Scn *__scn, CGCEf_Cmd __cmd,
	unsigned __flags));
extern unsigned cgcef_flagshdr __P((CGCEf_Scn *__scn, CGCEf_Cmd __cmd,
	unsigned __flags));
extern size_t cgcef32_fsize __P((CGCEf_Type __type, size_t __count,
	unsigned __ver));
extern CGCEf_Arhdr *cgcef_getarhdr __P((CGCEf *__cgcef));
extern CGCEf_Arsym *cgcef_getarsym __P((CGCEf *__cgcef, size_t *__ptr));
extern off_t cgcef_getbase __P((CGCEf *__cgcef));
extern CGCEf_Data *cgcef_getdata __P((CGCEf_Scn *__scn, CGCEf_Data *__data));
extern CGCEf32_Ehdr *cgcef32_getehdr __P((CGCEf *__cgcef));
extern char *cgcef_getident __P((CGCEf *__cgcef, size_t *__ptr));
extern CGCEf32_Phdr *cgcef32_getphdr __P((CGCEf *__cgcef));
extern CGCEf_Scn *cgcef_getscn __P((CGCEf *__cgcef, size_t __index));
extern CGCEf32_Shdr *cgcef32_getshdr __P((CGCEf_Scn *__scn));
extern unsigned long cgcef_hash __P((const unsigned char *__name));
extern CGCEf_Kind cgcef_kind __P((CGCEf *__cgcef));
extern size_t cgcef_ndxscn __P((CGCEf_Scn *__scn));
extern CGCEf_Data *cgcef_newdata __P((CGCEf_Scn *__scn));
extern CGCEf32_Ehdr *cgcef32_newehdr __P((CGCEf *__cgcef));
extern CGCEf32_Phdr *cgcef32_newphdr __P((CGCEf *__cgcef, size_t __count));
extern CGCEf_Scn *cgcef_newscn __P((CGCEf *__cgcef));
extern CGCEf_Cmd cgcef_next __P((CGCEf *__cgcef));
extern CGCEf_Scn *cgcef_nextscn __P((CGCEf *__cgcef, CGCEf_Scn *__scn));
extern size_t cgcef_rand __P((CGCEf *__cgcef, size_t __offset));
extern CGCEf_Data *cgcef_rawdata __P((CGCEf_Scn *__scn, CGCEf_Data *__data));
extern char *cgcef_rawfile __P((CGCEf *__cgcef, size_t *__ptr));
extern char *cgcef_strptr __P((CGCEf *__cgcef, size_t __section, size_t __offset));
extern off_t cgcef_update __P((CGCEf *__cgcef, CGCEf_Cmd __cmd));
extern unsigned cgcef_version __P((unsigned __ver));
extern CGCEf_Data *cgcef32_xlatetof __P((CGCEf_Data *__dst, const CGCEf_Data *__src,
	unsigned __encode));
extern CGCEf_Data *cgcef32_xlatetom __P((CGCEf_Data *__dst, const CGCEf_Data *__src,
	unsigned __encode));

/*
 * Additional functions found on Solaris
 */
extern long cgcef32_checksum __P((CGCEf *__cgcef));

#if __LIBCGCEF64
/*
 * 64-bit CGCEF functions
 * Not available on all platforms
 */
extern CGCEf64_Ehdr *cgcef64_getehdr __P((CGCEf *__cgcef));
extern CGCEf64_Ehdr *cgcef64_newehdr __P((CGCEf *__cgcef));
extern CGCEf64_Phdr *cgcef64_getphdr __P((CGCEf *__cgcef));
extern CGCEf64_Phdr *cgcef64_newphdr __P((CGCEf *__cgcef, size_t __count));
extern CGCEf64_Shdr *cgcef64_getshdr __P((CGCEf_Scn *__scn));
extern size_t cgcef64_fsize __P((CGCEf_Type __type, size_t __count,
	unsigned __ver));
extern CGCEf_Data *cgcef64_xlatetof __P((CGCEf_Data *__dst, const CGCEf_Data *__src,
	unsigned __encode));
extern CGCEf_Data *cgcef64_xlatetom __P((CGCEf_Data *__dst, const CGCEf_Data *__src,
	unsigned __encode));

/*
 * Additional functions found on Solaris
 */
extern long cgcef64_checksum __P((CGCEf *__cgcef));

#endif /* __LIBCGCEF64 */

/*
 * CGCEF format extensions
 *
 * These functions return 0 on failure, 1 on success.  Since other
 * implementations of libcgcef may behave differently (there was quite
 * some confusion about the correct values), they are now officially
 * deprecated and should be replaced with the three new functions below.
 */
DEPRECATED extern int cgcef_getphnum __P((CGCEf *__cgcef, size_t *__resultp));
DEPRECATED extern int cgcef_getshnum __P((CGCEf *__cgcef, size_t *__resultp));
DEPRECATED extern int cgcef_getshstrndx __P((CGCEf *__cgcef, size_t *__resultp));
/*
 * Replacement functions (return -1 on failure, 0 on success).
 */
extern int cgcef_getphdrnum __P((CGCEf *__cgcef, size_t *__resultp));
extern int cgcef_getshdrnum __P((CGCEf *__cgcef, size_t *__resultp));
extern int cgcef_getshdrstrndx __P((CGCEf *__cgcef, size_t *__resultp));

/*
 * Convenience functions
 *
 * cgcefx_update_shstrndx is cgcef_getshstrndx's counterpart.
 * It should be used to set the e_shstrndx member.
 * There is no update function for e_shnum or e_phnum
 * because libcgcef handles them internally.
 */
extern int cgcefx_update_shstrndx __P((CGCEf *__cgcef, size_t __index));

/*
 * Experimental extensions:
 *
 * cgcefx_movscn() moves section `__scn' directly after section `__after'.
 * cgcefx_remscn() removes section `__scn'.  Both functions update
 * the section indices; cgcefx_remscn() also adjusts the CGCEF header's
 * e_shnum member.  The application is responsible for updating other
 * data (in particular, e_shstrndx and the section headers' sh_link and
 * sh_info members).
 *
 * cgcefx_movscn() returns the new index of the moved section.
 * cgcefx_remscn() returns the original index of the removed section.
 * A return value of zero indicates an error.
 */
extern size_t cgcefx_movscn __P((CGCEf *__cgcef, CGCEf_Scn *__scn, CGCEf_Scn *__after));
extern size_t cgcefx_remscn __P((CGCEf *__cgcef, CGCEf_Scn *__scn));

/*
 * cgcef_delscn() is obsolete.  Please use cgcefx_remscn() instead.
 */
extern size_t cgcef_delscn __P((CGCEf *__cgcef, CGCEf_Scn *__scn));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _LIBCGCEF_H */
