/* name.c	Implementation of GSS-API Name Manipulation functions.
 * Copyright (C) 2003  Simon Josefsson
 *
 * This file is part of GPL GSS-API.
 *
 * GPL GSS-API is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include "internal.h"

OM_uint32
gss_get_mic (OM_uint32 * minor_status,
	     const gss_ctx_id_t context_handle,
	     gss_qop_t qop_req,
	     const gss_buffer_t message_buffer, gss_buffer_t message_token)
{
  return GSS_S_FAILURE;
}

OM_uint32
gss_verify_mic (OM_uint32 * minor_status,
		const gss_ctx_id_t context_handle,
		const gss_buffer_t message_buffer,
		const gss_buffer_t token_buffer, gss_qop_t * qop_state)
{
  return GSS_S_FAILURE;
}

/**
 * gss_wrap:
 * @minor_status: Mechanism specific status code.
 * @context_handle: Identifies the context on which the message will be sent
 * @conf_req_flag: Whether confidentiality is requested.
 * @qop_req: Specifies required quality of protection.  A
 *   mechanism-specific default may be requested by setting qop_req to
 *   GSS_C_QOP_DEFAULT.  If an unsupported protection strength is
 *   requested, gss_wrap will return a major_status of GSS_S_BAD_QOP.
 * @input_message_buffer: Message to be protected.
 * @conf_state: Optional output variable indicating if confidentiality
 *   services have been applied.
 * @output_message_buffer: Buffer to receive protected message.
 *   Storage associated with this message must be freed by the
 *   application after use with a call to gss_release_buffer().
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
 * Return value: Returns
 *
 * GSS_S_COMPLETE    Successful completion
 *
 * GSS_S_CONTEXT_EXPIRED The context has already expired
 *
 * GSS_S_NO_CONTEXT The context_handle parameter did not identify a
 * valid context
 *
 * GSS_S_BAD_QOP     The specified QOP is not supported by the mechanism.
 *
 **/
OM_uint32
gss_wrap (OM_uint32 * minor_status,
	  const gss_ctx_id_t context_handle,
	  int conf_req_flag,
	  gss_qop_t qop_req,
	  const gss_buffer_t input_message_buffer,
	  int *conf_state, gss_buffer_t output_message_buffer)
{
  puts("wrap:");

  {
    int i;
    for (i = 0; i < input_message_buffer->length; i++)
      {
	printf("%02x ", ((char*)input_message_buffer->value)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
  }
  return GSS_S_FAILURE;
}

/**
 * gss_unwrap:
 * @minor_status: Mechanism specific status code.
 * @context_handle: Identifies the context on which the message arrived
 * @input_message_buffer: input protected message
 * @output_message_buffer: Buffer to receive unwrapped message.
 *   Storage associated with this buffer must be freed by the
 *   application after use use with a call to gss_release_buffer().
 * @conf_state: optional output variable indicating if confidentiality
 *   protection was used.
 * @qop_state: optional output variable indicating quality of protection.
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
 * Return value: Returns:
 *
 * GSS_S_COMPLETE    Successful completion
 *
 * GSS_S_DEFECTIVE_TOKEN The token failed consistency checks
 *
 * GSS_S_BAD_SIG     The MIC was incorrect
 *
 * GSS_S_DUPLICATE_TOKEN The token was valid, and contained a correct
 *   MIC for the message, but it had already been processed
 *
 * GSS_S_OLD_TOKEN The token was valid, and contained a correct MIC
 *   for the message, but it is too old to check for duplication.
 *
 * GSS_S_UNSEQ_TOKEN The token was valid, and contained a correct MIC
 *   for the message, but has been verified out of sequence; a later
 *   token has already been received.
 *
 * GSS_S_GAP_TOKEN The token was valid, and contained a correct MIC
 *   for the message, but has been verified out of sequence; an earlier
 *   expected token has not yet been received.
 *
 * GSS_S_CONTEXT_EXPIRED The context has already expired
 *
 * GSS_S_NO_CONTEXT The context_handle parameter did not identify a
 *   valid context
 *
 **/
OM_uint32
gss_unwrap (OM_uint32 * minor_status,
	    const gss_ctx_id_t context_handle,
	    const gss_buffer_t input_message_buffer,
	    gss_buffer_t output_message_buffer,
	    int *conf_state, gss_qop_t * qop_state)
{

  {
    int i;
    for (i = 0; i < input_message_buffer->length; i++)
      {
	printf("%02x ", ((char*)input_message_buffer->value)[i] & 0xFF);
	if ((i+1)%16 == 0)
	  printf("\n");
      }
  }

  if (input_message_buffer->length > 8)
    {
      output_message_buffer->length = 4;
      output_message_buffer->value = malloc(4);
      memcpy(output_message_buffer->value,
	     input_message_buffer->value + input_message_buffer->length - 8,
	     4);

      puts("ok:");
      {
	int i;
	for (i = 0; i < output_message_buffer->length; i++)
	  {
	    printf("%02x ", ((char*)output_message_buffer->value)[i] & 0xFF);
	    if ((i+1)%16 == 0)
	      printf("\n");
	  }
      }

      return GSS_S_COMPLETE;
    }

  return GSS_S_FAILURE;
}
