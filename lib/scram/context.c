/* scram/context.c --- Implementation of SCRAM GSS Context functions.
 * Copyright (C) 2012 Simon Josefsson
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

/* SCRAM implementation */
#include "tokens.h"
#include "printer.h"

/* gnulib */
#include "gc.h"

#define CNONCE_ENTROPY_BYTES 23

typedef struct _gss_scram_ctx_struct
{
  struct scram_client_first cf;
} _gss_scram_ctx_desc, *_gss_scram_ctx_t;

static void
bin2hex (const char *binstr, size_t binlen, char *hexstr)
{
  static const char trans[] = "0123456789abcdef";

  while (binlen--)
    {
      *hexstr++ = trans[(*binstr >> 4) & 0xf];
      *hexstr++ = trans[*binstr++ & 0xf];
    }

  *hexstr = '\0';
}

/* Generate SCRAM client-first message.  Returns GSS_S_CONTINUE_NEEDED
   on success, or an error code. */
static OM_uint32
client_first (OM_uint32 * minor_status,
	      _gss_scram_ctx_t sctx,
	      gss_buffer_t output_token)
{
  OM_uint32 maj;
  gss_buffer_desc token;
  int rc;
  char buf[CNONCE_ENTROPY_BYTES];

  rc = gc_nonce (buf, sizeof (buf));
  if (rc != GC_OK)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  sctx->cf.client_nonce = malloc (2 * sizeof (buf) + 1);
  if (sctx->cf.client_nonce == NULL)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }

  bin2hex (buf, sizeof (buf), sctx->cf.client_nonce);

  sctx->cf.cbflag = 'n';
  sctx->cf.username = strdup ("jas");  /* XXX */
  sctx->cf.authzid = strdup ("authzid"); /* XXX */

  rc = scram_print_client_first (&sctx->cf, (char **) &token.value);
  if (rc != 0)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  token.length = strlen (token.value);

  maj = gss_encapsulate_token (&token, GSS_SCRAMSHA1, output_token);
  if (GSS_ERROR (maj))
    return maj;

  return GSS_S_CONTINUE_NEEDED;
}

/* SCRAM client */
OM_uint32
gss_scram_init_sec_context (OM_uint32 * minor_status,
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
  gss_ctx_id_t ctx = *context_handle;
  _gss_scram_ctx_t sctx = ctx->scram;
  OM_uint32 maj;

  if (minor_status)
    *minor_status = 0;

  if (initiator_cred_handle)
    return GSS_S_NO_CRED;

  if (sctx == NULL)
    {
      sctx = ctx->scram = calloc (sizeof (*sctx), 1);
      if (!sctx)
	{
	  if (minor_status)
	    *minor_status = ENOMEM;
	  return GSS_S_FAILURE;
	}

      maj = client_first (minor_status, sctx, output_token);

      if (maj != GSS_S_CONTINUE_NEEDED)
	{
	  scram_free_client_first (&sctx->cf);
	  free (sctx);
	  return maj;
	}

      return maj;
    }

  return GSS_S_FAILURE;
}

/* SCRAM server. */
OM_uint32
gss_scram_accept_sec_context (OM_uint32 * minor_status,
			      gss_ctx_id_t * context_handle,
			      const gss_cred_id_t acceptor_cred_handle,
			      const gss_buffer_t input_token_buffer,
			      const gss_channel_bindings_t input_chan_bindings,
			      gss_name_t * src_name,
			      gss_OID * mech_type,
			      gss_buffer_t output_token,
			      OM_uint32 * ret_flags,
			      OM_uint32 * time_rec,
			      gss_cred_id_t * delegated_cred_handle)
{
  OM_uint32 maj;
  gss_buffer_desc token;

  maj = gss_decapsulate_token (input_token_buffer, GSS_SCRAMSHA1, &token);
  if (GSS_ERROR (maj))
    return maj;

  printf ("foo: %.*s\n", (int) token.length, (char *) token.value);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
