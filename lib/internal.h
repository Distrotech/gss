/* internal.h	Internal header file for GPL GSS-API.
 * Copyright (C) 2003  Simon Josefsson
 *
 * This file is part of GPL GSS-API.
 *
 * GPL GSS-API is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * GPL GSS-API is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GPL GSS-API; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef STDC_HEADERS
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#endif

#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif

#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif

#include "gettext.h"
#include "gss.h"
#include "gssapi.h"

#ifdef USE_KERBEROS5
#include <shishi.h>

/*
 * From RFC 1964:
 *
 * To support ongoing experimentation, testing, and evolution of the
 * specification, the Kerberos V5 GSS-API mechanism as defined in this
 * and any successor memos will be identified with the following
 * Object Identifier, as defined in RFC-1510, until the specification
 * is advanced to the level of Proposed Standard RFC:
 *
 * {iso(1), org(3), dod(5), internet(1), security(5), kerberosv5(2)}
 *
 * Upon advancement to the level of Proposed Standard RFC, the
 * Kerberos V5 GSS-API mechanism will be identified by an Object
 * Identifier having the value:
 *
 * {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
 * gssapi(2) krb5(2)}
 *
 */

#define GSS_KRB5_OID "1.2.840.113554.1.2.2"
#endif

#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

struct gss_ctx_id_t
{
#ifdef USE_KERBEROS5
  Shishi *sh;
  Shishi_ap *ap;
  Shishi_tkt *tkt;
#endif
};

struct gss_cred_id_t
{
#ifdef USE_KERBEROS5
  Shishi_tkt *tkt;
#endif
};

struct gss_name_t
{
  int length;
  char *value;
  gss_OID type;
};

int
_gss_wrap_token (char *oid,
		 char *in, size_t inlen,
		 char **out, size_t *outlen);

OM_uint32
krb5_gss_init_sec_context (OM_uint32 * minor_status,
			   const gss_cred_id_t initiator_cred_handle,
			   gss_ctx_id_t * context_handle,
			   const gss_name_t target_name,
			   const gss_OID mech_type,
			   OM_uint32 req_flags,
			   OM_uint32 time_req,
			   const gss_channel_bindings_t input_chan_bindings,
			   const gss_buffer_t input_token,
			   gss_OID * actual_mech_type,
			   gss_buffer_t output_token,
			   OM_uint32 * ret_flags, OM_uint32 * time_rec);

#endif /* _INTERNAL_H */
