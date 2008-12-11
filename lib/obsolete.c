/* obsolete.c --- Obsolete GSS-API v1 compatibility mappings.
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008  Simon Josefsson
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

#include "internal.h"

OM_uint32
gss_sign (OM_uint32 * minor_status,
	  gss_ctx_id_t context_handle,
	  int qop_req,
	  gss_buffer_t message_buffer, gss_buffer_t message_token)
{
  return gss_get_mic (minor_status, context_handle,
		      (gss_qop_t)qop_req, message_buffer, message_token);
}


OM_uint32
gss_verify (OM_uint32 * minor_status,
	    gss_ctx_id_t context_handle,
	    gss_buffer_t message_buffer,
	    gss_buffer_t token_buffer, int *qop_state)
{
  return gss_verify_mic (minor_status, context_handle, message_buffer,
			 token_buffer, (gss_qop_t *) qop_state);
}

OM_uint32
gss_seal (OM_uint32 * minor_status,
	  gss_ctx_id_t context_handle,
	  int conf_req_flag,
	  int qop_req,
	  gss_buffer_t input_message_buffer,
	  int *conf_state, gss_buffer_t output_message_buffer)
{
  return gss_wrap (minor_status, context_handle, conf_req_flag,
		   (gss_qop_t) qop_req,
		   input_message_buffer, conf_state, output_message_buffer);
}


OM_uint32
gss_unseal (OM_uint32 * minor_status,
	    gss_ctx_id_t context_handle,
	    gss_buffer_t input_message_buffer,
	    gss_buffer_t output_message_buffer,
	    int *conf_state, int *qop_state)
{
  return gss_unwrap (minor_status, context_handle, input_message_buffer,
		     output_message_buffer, conf_state,
		     (gss_qop_t *) qop_state);
}
