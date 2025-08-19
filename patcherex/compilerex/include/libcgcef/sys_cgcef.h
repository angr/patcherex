/* lib/sys_cgcef.h.  Generated from sys_cgcef.h.in by configure.  */
/*
sys_cgcef.h.in - configure template for private "switch" file.
Copyright (C) 1998 - 2001 Michael Riepe

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public
License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
*/

/* @(#) $Id: sys_cgcef.h.in,v 1.13 2008/05/23 08:57:07 michael Exp $ */

/*
 * DO NOT USE THIS IN APPLICATIONS - #include <libcgcef.h> INSTEAD!
 */

/* Define to `<cgcef.h>' or `<sys/cgcef.h>' if one of them is present */
/* #undef __LIBCGCEF_HEADER_CGCEF_H */

/* Define if CGCEf32_Dyn is declared in <link.h> */
/* #undef __LIBCGCEF_NEED_LINK_H */

/* Define if CGCEf32_Dyn is declared in <sys/link.h> */
/* #undef __LIBCGCEF_NEED_SYS_LINK_H */

/* Define if you want 64-bit support (and your system supports it) */
#define __LIBCGCEF64 1

/* Define if you want 64-bit support, and are running IRIX */
/* #undef __LIBCGCEF64_IRIX */

/* Define if you want 64-bit support, and are running Linux */
/* #undef __LIBCGCEF64_LINUX */

/* Define if you want symbol versioning (and your system supports it) */
#define __LIBCGCEF_SYMBOL_VERSIONS 1

/* Define to a 64-bit signed integer type if one exists */
#define __libcgcef_i64_t long long

/* Define to a 64-bit unsigned integer type if one exists */
#define __libcgcef_u64_t unsigned long long

/* Define to a 32-bit signed integer type if one exists */
#define __libcgcef_i32_t int

/* Define to a 32-bit unsigned integer type if one exists */
#define __libcgcef_u32_t unsigned int

/* Define to a 16-bit signed integer type if one exists */
#define __libcgcef_i16_t short

/* Define to a 16-bit unsigned integer type if one exists */
#define __libcgcef_u16_t unsigned short

/*
 * Ok, now get the correct instance of cgcef.h...
 */
#ifdef __LIBCGCEF_HEADER_CGCEF_H
# include __LIBCGCEF_HEADER_CGCEF_H
#else /* __LIBCGCEF_HEADER_CGCEF_H */
# if __LIBCGCEF_INTERNAL__
#  include <cgcef_repl.h>
# else /* __LIBCGCEF_INTERNAL__ */
#  include <libcgcef/cgcef_repl.h>
# endif /* __LIBCGCEF_INTERNAL__ */
#endif /* __LIBCGCEF_HEADER_CGCEF_H */

/*
 * On some systems, <cgcef.h> is severely broken.  Try to fix it.
 */
#ifdef __LIBCGCEF_HEADER_CGCEF_H

# ifndef CGCEF32_FSZ_ADDR
#  define CGCEF32_FSZ_ADDR	4
#  define CGCEF32_FSZ_HALF	2
#  define CGCEF32_FSZ_OFF		4
#  define CGCEF32_FSZ_SWORD	4
#  define CGCEF32_FSZ_WORD	4
# endif /* CGCEF32_FSZ_ADDR */

# ifndef STN_UNDEF
#  define STN_UNDEF	0
# endif /* STN_UNDEF */

# if __LIBCGCEF64

#  ifndef CGCEF64_FSZ_ADDR
#   define CGCEF64_FSZ_ADDR	8
#   define CGCEF64_FSZ_HALF	2
#   define CGCEF64_FSZ_OFF	8
#   define CGCEF64_FSZ_SWORD	4
#   define CGCEF64_FSZ_WORD	4
#   define CGCEF64_FSZ_SXWORD	8
#   define CGCEF64_FSZ_XWORD	8
#  endif /* CGCEF64_FSZ_ADDR */

#  ifndef CGCEF64_ST_BIND
#   define CGCEF64_ST_BIND(i)	((i)>>4)
#   define CGCEF64_ST_TYPE(i)	((i)&0xf)
#   define CGCEF64_ST_INFO(b,t)	(((b)<<4)+((t)&0xf))
#  endif /* CGCEF64_ST_BIND */

#  ifndef CGCEF64_R_SYM
#   define CGCEF64_R_SYM(i)	((CGCEf64_Xword)(i)>>32)
#   define CGCEF64_R_TYPE(i)	((i)&0xffffffffL)
#   define CGCEF64_R_INFO(s,t)	(((CGCEf64_Xword)(s)<<32)+((t)&0xffffffffL))
#  endif /* CGCEF64_R_SYM */

#  if __LIBCGCEF64_LINUX
typedef __libcgcef_u64_t	CGCEf64_Addr;
typedef __libcgcef_u16_t	CGCEf64_Half;
typedef __libcgcef_u64_t	CGCEf64_Off;
typedef __libcgcef_i32_t	CGCEf64_Sword;
typedef __libcgcef_u32_t	CGCEf64_Word;
typedef __libcgcef_i64_t	CGCEf64_Sxword;
typedef __libcgcef_u64_t	CGCEf64_Xword;
#  endif /* __LIBCGCEF64_LINUX */

# endif /* __LIBCGCEF64 */
#endif /* __LIBCGCEF_HEADER_CGCEF_H */
