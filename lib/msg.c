/* msg.c --- Implementation of GSS-API Per-Message functions.
 * Copyright (C) 2003, 2004  Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include "internal.h"

/* _gss_find_mech */
#include "meta.h"

/**
 * gss_get_mic:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @context_handle: (gss_ctx_id_t, read) Identifies the context on
 *   which the message will be sent.
 * @qop_req: (gss_qop_t, read, optional) Specifies requested quality
 *   of protection.  Callers are encouraged, on portability grounds,
 *   to accept the default quality of protection offered by the chosen
 *   mechanism, which may be requested by specifying GSS_C_QOP_DEFAULT
 *   for this parameter.  If an unsupported protection strength is
 *   requested, gss_get_mic will return a major_status of
 *   GSS_S_BAD_QOP.
 * @message_buffer: (buffer, opaque, read) Message to be protected.
 * @message_token: (buffer, opaque, modify) Buffer to receive token.  The
 *   application must free storage associated with this buffer after
 *   use with a call to gss_release_buffer().
 *
 * Generates a cryptographic MIC for the supplied message, and places
 * the MIC in a token for transfer to the peer application. The
 * qop_req parameter allows a choice between several cryptographic
 * algorithms, if supported by the chosen mechanism.
 *
 * Since some application-level protocols may wish to use tokens
 * emitted by gss_wrap() to provide "secure framing", implementations
 * must support derivation of MICs from zero-length messages.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_CONTEXT_EXPIRED`: The context has already expired.
 *
 * `GSS_S_NO_CONTEXT`: The context_handle parameter did not identify a
 * valid context.
 *
 * `GSS_S_BAD_QOP`: The specified QOP is not supported by the
 * mechanism.
 **/
OM_uint32
gss_get_mic (OM_uint32 * minor_status,
	     const gss_ctx_id_t context_handle,
	     gss_qop_t qop_req,
	     const gss_buffer_t message_buffer, gss_buffer_t message_token)
{
  _gss_mech_api_t mech;

  if (!context_handle)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CONTEXT;
    }

  mech = _gss_find_mech (context_handle->mech);

  return mech->get_mic (minor_status, context_handle, qop_req,
			message_buffer, message_token);
}

/**
 * gss_verify_mic:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @context_handle: (gss_ctx_id_t, read) Identifies the context on
 *   which the message arrived.
 * @message_buffer: (buffer, opaque, read) Message to be verified.
 * @token_buffer: (buffer, opaque, read) Token associated with
 *   message.
 * @qop_state: (gss_qop_t, modify, optional) Quality of protection
 *   gained from MIC Specify NULL if not required.
 *
 * Verifies that a cryptographic MIC, contained in the token
 * parameter, fits the supplied message.  The qop_state parameter
 * allows a message recipient to determine the strength of protection
 * that was applied to the message.
 *
 * Since some application-level protocols may wish to use tokens
 * emitted by gss_wrap() to provide "secure framing", implementations
 * must support the calculation and verification of MICs over
 * zero-length messages.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_DEFECTIVE_TOKEN`: The token failed consistency checks.
 *
 * `GSS_S_BAD_SIG`: The MIC was incorrect.
 *
 * `GSS_S_DUPLICATE_TOKEN`: The token was valid, and contained a
 * correct MIC for the message, but it had already been processed.
 *
 * `GSS_S_OLD_TOKEN`: The token was valid, and contained a correct MIC
 * for the message, but it is too old to check for duplication.
 *
 * `GSS_S_UNSEQ_TOKEN`: The token was valid, and contained a correct
 * MIC for the message, but has been verified out of sequence; a later
 * token has already been received.
 *
 * `GSS_S_GAP_TOKEN`: The token was valid, and contained a correct MIC
 * for the message, but has been verified out of sequence; an earlier
 * expected token has not yet been received.
 *
 * `GSS_S_CONTEXT_EXPIRED`: The context has already expired.
 *
 * `GSS_S_NO_CONTEXT`: The context_handle parameter did not identify a
 * valid context.
 **/
OM_uint32
gss_verify_mic (OM_uint32 * minor_status,
		const gss_ctx_id_t context_handle,
		const gss_buffer_t message_buffer,
		const gss_buffer_t token_buffer, gss_qop_t * qop_state)
{
  _gss_mech_api_t mech;

  if (!context_handle)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CONTEXT;
    }

  mech = _gss_find_mech (context_handle->mech);

  return mech->verify_mic (minor_status, context_handle,
			   message_buffer, token_buffer, qop_state);
}

/**
 * gss_wrap:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @context_handle: (gss_ctx_id_t, read) Identifies the context on
 *   which the message will be sent.
 * @conf_req_flag: (boolean, read) Non-zero - Both confidentiality and
 *   integrity services are requested. Zero - Only integrity service is
 *   requested.
 * @qop_req: (gss_qop_t, read, optional) Specifies required quality of
 *   protection.  A mechanism-specific default may be requested by
 *   setting qop_req to GSS_C_QOP_DEFAULT.  If an unsupported
 *   protection strength is requested, gss_wrap will return a
 *   major_status of GSS_S_BAD_QOP.
 * @input_message_buffer: (buffer, opaque, read) Message to be
 *   protected.
 * @conf_state: (boolean, modify, optional) Non-zero -
 *   Confidentiality, data origin authentication and integrity
 *   services have been applied. Zero - Integrity and data origin
 *   services only has been applied.  Specify NULL if not required.
 * @output_message_buffer: (buffer, opaque, modify) Buffer to receive
 *   protected message.  Storage associated with this message must be
 *   freed by the application after use with a call to
 *   gss_release_buffer().
 *
 * Attaches a cryptographic MIC and optionally encrypts the specified
 * input_message.  The output_message contains both the MIC and the
 * message.  The qop_req parameter allows a choice between several
 * cryptographic algorithms, if supported by the chosen mechanism.
 *
 * Since some application-level protocols may wish to use tokens
 * emitted by gss_wrap() to provide "secure framing", implementations
 * must support the wrapping of zero-length messages.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_CONTEXT_EXPIRED`: The context has already expired.
 *
 * `GSS_S_NO_CONTEXT`: The context_handle parameter did not identify a
 *  valid context.
 *
 * `GSS_S_BAD_QOP`: The specified QOP is not supported by the
 * mechanism.
 **/
OM_uint32
gss_wrap (OM_uint32 * minor_status,
	  const gss_ctx_id_t context_handle,
	  int conf_req_flag,
	  gss_qop_t qop_req,
	  const gss_buffer_t input_message_buffer,
	  int *conf_state, gss_buffer_t output_message_buffer)
{
  _gss_mech_api_t mech;

  if (!context_handle)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CONTEXT;
    }

  mech = _gss_find_mech (context_handle->mech);

  return mech->wrap (minor_status, context_handle, conf_req_flag, qop_req,
		     input_message_buffer, conf_state, output_message_buffer);
}

/**
 * gss_unwrap:
 * @minor_status: (Integer, modify) Mechanism specific status code.
 * @context_handle: (gss_ctx_id_t, read) Identifies the context on
 *   which the message arrived.
 * @input_message_buffer: (buffer, opaque, read) Protected message.
 * @output_message_buffer: (buffer, opaque, modify) Buffer to receive
 *   unwrapped message.  Storage associated with this buffer must be
 *   freed by the application after use use with a call to
 *   gss_release_buffer().
 * @conf_state: (boolean, modify, optional) Non-zero - Confidentiality
 *   and integrity protection were used. Zero - Integrity service only
 *   was used.  Specify NULL if not required.
 * @qop_state: (gss_qop_t, modify, optional) Quality of protection
 *   provided.  Specify NULL if not required.
 *
 * Converts a message previously protected by gss_wrap back to a
 * usable form, verifying the embedded MIC.  The conf_state parameter
 * indicates whether the message was encrypted; the qop_state
 * parameter indicates the strength of protection that was used to
 * provide the confidentiality and integrity services.
 *
 * Since some application-level protocols may wish to use tokens
 * emitted by gss_wrap() to provide "secure framing", implementations
 * must support the wrapping and unwrapping of zero-length messages.
 *
 * Return value:
 *
 * `GSS_S_COMPLETE`: Successful completion.
 *
 * `GSS_S_DEFECTIVE_TOKEN`: The token failed consistency checks.
 *
 * `GSS_S_BAD_SIG`: The MIC was incorrect.
 *
 * `GSS_S_DUPLICATE_TOKEN`: The token was valid, and contained a
 *  correct MIC for the message, but it had already been processed.
 *
 * `GSS_S_OLD_TOKEN`: The token was valid, and contained a correct MIC
 * for the message, but it is too old to check for duplication.
 *
 * `GSS_S_UNSEQ_TOKEN`: The token was valid, and contained a correct
 * MIC for the message, but has been verified out of sequence; a later
 * token has already been received.
 *
 * `GSS_S_GAP_TOKEN`: The token was valid, and contained a correct MIC
 * for the message, but has been verified out of sequence; an earlier
 * expected token has not yet been received.
 *
 * `GSS_S_CONTEXT_EXPIRED`: The context has already expired.
 *
 * `GSS_S_NO_CONTEXT`: The context_handle parameter did not identify a
 * valid context.
 **/
OM_uint32
gss_unwrap (OM_uint32 * minor_status,
	    const gss_ctx_id_t context_handle,
	    const gss_buffer_t input_message_buffer,
	    gss_buffer_t output_message_buffer,
	    int *conf_state, gss_qop_t * qop_state)
{
  _gss_mech_api_t mech;

  if (!context_handle)
    {
      if (minor_status)
	*minor_status = 0;
      return GSS_S_NO_CONTEXT;
    }

  mech = _gss_find_mech (context_handle->mech);

  return mech->unwrap (minor_status, context_handle, input_message_buffer,
		       output_message_buffer, conf_state, qop_state);
}
