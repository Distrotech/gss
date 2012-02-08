/* internal.h --- Internal header file for GSS.
 * Copyright (C) 2003-2012 Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <errno.h>

/* Get i18n. */
#include <gettext.h>
#define _(String) dgettext (PACKAGE PO_SUFFIX, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

/* Get specification. */
#include <gss.h>

typedef struct gss_name_struct
{
  size_t length;
  char *value;
  gss_OID type;
} gss_name_desc;

typedef struct gss_cred_id_struct
{
  gss_OID mech;
#ifdef USE_KERBEROS5
  struct _gss_krb5_cred_struct *krb5;
#endif
} gss_cred_id_desc;

typedef struct gss_ctx_id_struct
{
  gss_OID mech;
#ifdef USE_KERBEROS5
  struct _gss_krb5_ctx_struct *krb5;
#endif
} gss_ctx_id_desc;

/* asn1.c */
extern OM_uint32
_gss_encapsulate_token_prefix (const char *prefix, size_t prefixlen,
			       const char *in, size_t inlen,
			       const char *oid, OM_uint32 oidlen,
			       void **out, size_t * outlen);

#endif /* _INTERNAL_H */
