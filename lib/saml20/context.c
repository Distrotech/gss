/* saml20/context.c --- Implementation of SAML20 GSS Context functions.
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

#include <gss.h>

#include "internal.h"
#include "protos.h"

/* Initiates the establishment of a SAML20 security context between
   the application and a remote peer.  Assumes that context_handle and
   output_token are valid and cleared. */
OM_uint32
gss_saml20_init_sec_context (OM_uint32 * minor_status,
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
			     OM_uint32 * ret_flags,
			     OM_uint32 * time_rec)
{
  OM_uint32 maj;
  gss_buffer_desc token;

  if (minor_status)
    *minor_status = 0;

  if (initiator_cred_handle)
    return GSS_S_NO_CRED;

  if (input_token)
    {
      printf ("got url %.*s\n", (int) input_token->length,
	      (char*) input_token->value);

      output_token->value = strdup ("=");
      output_token->length = 1;

      return GSS_S_COMPLETE;
    }

  token.value = (char *) "openidp.feide.no";
  token.length = strlen ("openidp.feide.no");

  maj = gss_encapsulate_token (&token, GSS_SAML20, output_token);
  if (GSS_ERROR (maj))
    return maj;

  return GSS_S_CONTINUE_NEEDED;
}
