/*
 * gcgcef.h - public header file for libcgcef.
 * Copyright (C) 2000 - 2006 Michael Riepe
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

/* @(#) $Id: gcgcef.h,v 1.16 2008/05/23 08:15:34 michael Exp $ */

#ifndef _GCGCEF_H
#define _GCGCEF_H

#if __LIBCGCEF_INTERNAL__
#include <libcgcef.h>
#else /* __LIBCGCEF_INTERNAL__ */
#include <libcgcef/libcgcef.h>
#endif /* __LIBCGCEF_INTERNAL__ */

#if __LIBCGCEF_NEED_LINK_H
#include <link.h>
#elif __LIBCGCEF_NEED_SYS_LINK_H
#include <sys/link.h>
#endif /* __LIBCGCEF_NEED_LINK_H */

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

#if !__LIBCGCEF64

#error "GCGCEf is not supported on this system."

#else /* __LIBCGCEF64 */

typedef CGCEf64_Addr	GCGCEf_Addr;
typedef CGCEf64_Half	GCGCEf_Half;
typedef CGCEf64_Off	GCGCEf_Off;
typedef CGCEf64_Sword	GCGCEf_Sword;
typedef CGCEf64_Word	GCGCEf_Word;
typedef CGCEf64_Sxword	GCGCEf_Sxword;
typedef CGCEf64_Xword	GCGCEf_Xword;

typedef CGCEf64_Ehdr	GCGCEf_Ehdr;
typedef CGCEf64_Phdr	GCGCEf_Phdr;
typedef CGCEf64_Shdr	GCGCEf_Shdr;
typedef CGCEf64_Dyn	GCGCEf_Dyn;
typedef CGCEf64_Rel	GCGCEf_Rel;
typedef CGCEf64_Rela	GCGCEf_Rela;
typedef CGCEf64_Sym	GCGCEf_Sym;

/*
 * Symbol versioning
 */
#if __LIBCGCEF_SYMBOL_VERSIONS
typedef CGCEf64_Verdef	GCGCEf_Verdef;
typedef CGCEf64_Verneed	GCGCEf_Verneed;
typedef CGCEf64_Verdaux	GCGCEf_Verdaux;
typedef CGCEf64_Vernaux	GCGCEf_Vernaux;
#endif /* __LIBCGCEF_SYMBOL_VERSIONS */

/*
 * These types aren't implemented (yet)
 *
typedef CGCEf64_Move    GCGCEf_Move;
typedef CGCEf64_Syminfo GCGCEf_Syminfo;
 */

/*
 * Generic macros
 */
#define GCGCEF_ST_BIND	CGCEF64_ST_BIND
#define GCGCEF_ST_TYPE	CGCEF64_ST_TYPE
#define GCGCEF_ST_INFO	CGCEF64_ST_INFO

#define GCGCEF_R_TYPE	CGCEF64_R_TYPE
#define GCGCEF_R_SYM	CGCEF64_R_SYM
#define GCGCEF_R_INFO	CGCEF64_R_INFO

/*
 * Function declarations
 */
extern int             gcgcef_getclass __P((CGCEf *__cgcef));

extern size_t             gcgcef_fsize __P((CGCEf *__cgcef, CGCEf_Type __type, size_t __count, unsigned __ver));

extern CGCEf_Data       *gcgcef_xlatetof __P((CGCEf *__cgcef, CGCEf_Data *__dst, const CGCEf_Data *__src, unsigned __encode));
extern CGCEf_Data       *gcgcef_xlatetom __P((CGCEf *__cgcef, CGCEf_Data *__dst, const CGCEf_Data *__src, unsigned __encode));

extern GCGCEf_Ehdr       *gcgcef_getehdr __P((CGCEf *__cgcef, GCGCEf_Ehdr *__dst));
extern int          gcgcef_update_ehdr __P((CGCEf *__cgcef, GCGCEf_Ehdr *__src));
extern unsigned long    gcgcef_newehdr __P((CGCEf *__cgcef, int __cgcefclass));

extern GCGCEf_Phdr       *gcgcef_getphdr __P((CGCEf *__cgcef, int ndx, GCGCEf_Phdr *__dst));
extern int          gcgcef_update_phdr __P((CGCEf *__cgcef, int ndx, GCGCEf_Phdr *__src));
extern unsigned long    gcgcef_newphdr __P((CGCEf *__cgcef, size_t __phnum));

extern GCGCEf_Shdr       *gcgcef_getshdr __P((CGCEf_Scn *__scn, GCGCEf_Shdr *__dst));
extern int          gcgcef_update_shdr __P((CGCEf_Scn *__scn, GCGCEf_Shdr *__src));

extern GCGCEf_Dyn         *gcgcef_getdyn __P((CGCEf_Data *__src, int __ndx, GCGCEf_Dyn *__dst));
extern int           gcgcef_update_dyn __P((CGCEf_Data *__dst, int __ndx, GCGCEf_Dyn *__src));

extern GCGCEf_Rel         *gcgcef_getrel __P((CGCEf_Data *__src, int __ndx, GCGCEf_Rel *__dst));
extern int           gcgcef_update_rel __P((CGCEf_Data *__dst, int __ndx, GCGCEf_Rel *__src));

extern GCGCEf_Rela       *gcgcef_getrela __P((CGCEf_Data *__src, int __ndx, GCGCEf_Rela *__dst));
extern int          gcgcef_update_rela __P((CGCEf_Data *__dst, int __ndx, GCGCEf_Rela *__src));

extern GCGCEf_Sym         *gcgcef_getsym __P((CGCEf_Data *__src, int __ndx, GCGCEf_Sym *__dst));
extern int           gcgcef_update_sym __P((CGCEf_Data *__dst, int __ndx, GCGCEf_Sym *__src));

extern long            gcgcef_checksum __P((CGCEf *__cgcef));

/*
 * These functions aren't implemented (yet)
 *
extern GCGCEf_Move       *gcgcef_getmove __P((CGCEf_Data *__src, int __ndx, GCGCEf_Move *__src));
extern int          gcgcef_update_move __P((CGCEf_Data *__dst, int __ndx, GCGCEf_Move *__src));
 *
extern GCGCEf_Syminfo* gcgcef_getsyminfo __P((CGCEf_Data *__src, int __ndx, GCGCEf_Syminfo *__dst));
extern int       gcgcef_update_syminfo __P((CGCEf_Data *__dst, int __ndx, GCGCEf_Syminfo *__src));
 */

/*
 * Extensions (not available in other versions of libcgcef)
 */
extern size_t             gcgcef_msize __P((CGCEf *__cgcef, CGCEf_Type __type, size_t __count, unsigned __ver));

#endif /* __LIBCGCEF64 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _GCGCEF_H */
