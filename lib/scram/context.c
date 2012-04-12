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

#include "internal.h"
#include "protos.h"

/* SCRAM implementation */
#include "tokens.h"
#include "printer.h"
#include "parser.h"

/* gnulib */
#include "base64.h"
#include "gc.h"
#include "memxor.h"

/* Example protocol handshake:
   C: n=jas,r=8a28ac6b003dd443
   S: r=8a28ac6b003dd443a908a5589a34ce51,s=466dd77d0bb64f57aecd277f,i=4096
   C: c=,r=8a28ac6b003dd443c32635ebcfe8b3ed,p=proof
   S: v=ver
 */

#define CNONCE_ENTROPY_BYTES 8
#define SNONCE_ENTROPY_BYTES 8
#define DEFAULT_SALT_BYTES 12

typedef struct _gss_scram_ctx_struct
{
  struct scram_client_first cf;
  struct scram_client_final cl;
  struct scram_server_first sf;
  struct scram_server_final sl;
  char *salt;
  char *cnonce;
  char *snonce;
  char *authmessage;
  char *cfmb;
  char *serversignature;
} _gss_scram_ctx_desc, *_gss_scram_ctx_t;

/* SCRAM client */

/* Generate SCRAM client-first message.  Returns GSS_S_CONTINUE_NEEDED
   on success, or an error code.  Example output:
   n=jas,r=8a28ac6b003dd443
 */
static OM_uint32
client_first (OM_uint32 * minor_status,
	      _gss_scram_ctx_t sctx,
	      gss_buffer_t output_token)
{
  OM_uint32 maj;
  gss_buffer_desc token;
  int rc;

  /* Derive sctx->cnonce. */
  {
    char buf[CNONCE_ENTROPY_BYTES];

    rc = gc_nonce (buf, sizeof (buf));
    if (rc != GC_OK)
      {
	if (minor_status)
	  *minor_status = rc;
	return GSS_S_FAILURE;
      }

    base64_encode_alloc (buf, sizeof (buf), &sctx->cnonce);
    if (sctx->cnonce == NULL)
      {
	if (minor_status)
	  *minor_status = ENOMEM;
	return GSS_S_FAILURE;
      }
  }

  sctx->cf.username = strdup ("jas");  /* XXX */
  sctx->cf.client_nonce = sctx->cnonce;

  rc = scram_print_client_first (&sctx->cf, &sctx->cfmb);
  if (rc != 0)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  token.value = sctx->cfmb;
  token.length = strlen (token.value);

  printf ("C: C: %.*s\n", (int) token.length, (char *) token.value);

  maj = gss_encapsulate_token (&token, GSS_SCRAMSHA1, output_token);
  if (GSS_ERROR (maj))
    return maj;

  return GSS_S_CONTINUE_NEEDED;
}

static OM_uint32
client_final_proof (OM_uint32 * minor_status,
		    _gss_scram_ctx_t sctx,
		    const gss_buffer_t input_token)
{
  char saltedpassword[20];
  char clientkey[20];
  char storedkey[20];
  char clientsignature[20];
  char clientproof[20];
  int rc;

  /* Get SaltedPassword. */
  {
    const char *pass = "pencil"; /* XXX */
    Gc_rc err;
    char *salt;
    size_t saltlen;
    bool ok;

    /* XXX saslprep */

    ok = base64_decode_alloc (sctx->sf.salt, strlen (sctx->sf.salt),
			      &salt, &saltlen);
    if (!ok || salt == NULL)
      return -1;

    /* SaltedPassword := Hi(password, salt) */
    err = gc_pbkdf2_sha1 (pass, strlen (pass),
			  salt, saltlen,
			  sctx->sf.iter, saltedpassword, 20);
    free (salt);
    if (err != GC_OK)
      return -1;
  }


  /* Get client-final-message-without-proof. */
  {
    char *cfmwp;
    int n;

    sctx->cl.proof = strdup ("p");
    rc = scram_print_client_final (&sctx->cl, &cfmwp);
    if (rc != 0)
      return -1;
    free (sctx->cl.proof);

    /* Compute AuthMessage */
    n = asprintf (&sctx->authmessage, "%s,%.*s,%.*s",
		  sctx->cfmb,
		  (int) input_token->length, (char *) input_token->value,
		  (int) (strlen (cfmwp) - 4), cfmwp);
    free (cfmwp);
    if (n <= 0 || !sctx->authmessage)
      return -1;
  }

  /* ClientKey := HMAC(SaltedPassword, "Client Key") */
#define CLIENT_KEY "Client Key"
  rc = gc_hmac_sha1 (saltedpassword, 20,
		     CLIENT_KEY, strlen (CLIENT_KEY), clientkey);
  if (rc != 0)
    return rc;

  /* StoredKey := H(ClientKey) */
  rc = gc_sha1 (clientkey, 20, storedkey);
  if (rc != 0)
    return rc;

  /* ClientSignature := HMAC(StoredKey, AuthMessage) */
  rc = gc_hmac_sha1 (storedkey, 20,
		     sctx->authmessage,
		     strlen (sctx->authmessage),
		     clientsignature);
  if (rc != 0)
    return rc;

  /* ClientProof := ClientKey XOR ClientSignature */
  memcpy (clientproof, clientkey, 20);
  memxor (clientproof, clientsignature, 20);

  base64_encode_alloc (clientproof, 20, &sctx->cl.proof);
  if (sctx->cl.proof == NULL)
    return -1;

  /* Generate ServerSignature, for comparison in next step. */
  {
    char serverkey[20];
    char serversignature[20];

    /* ServerKey := HMAC(SaltedPassword, "Server Key") */
#define SERVER_KEY "Server Key"
    rc = gc_hmac_sha1 (saltedpassword, 20,
		       SERVER_KEY, strlen (SERVER_KEY),
		       serverkey);
    if (rc != 0)
      return rc;

    /* ServerSignature := HMAC(ServerKey, AuthMessage) */
    rc = gc_hmac_sha1 (serverkey, 20,
		       sctx->authmessage,
		       strlen (sctx->authmessage),
		       serversignature);
    if (rc != 0)
      return rc;

    base64_encode_alloc (serversignature, 20, &sctx->serversignature);
    if (sctx->cl.proof == NULL)
      return -1;
  }

  return GSS_S_COMPLETE;
}

/* Generate SCRAM client-final message.  Returns GSS_S_COMPLETE
   on success, or an error code.  Example output:
   c=,r=8a28ac6b003dd443c32635ebcfe8b3ed,p=b64proof
*/
static OM_uint32
client_final (OM_uint32 * minor_status,
	      _gss_scram_ctx_t sctx,
	      const gss_channel_bindings_t input_chan_bindings,
	      const gss_buffer_t input_token,
	      gss_buffer_t output_token)
{
  int rc;

  printf ("C: S: %.*s\n", (int) input_token->length,
	  (char *) input_token->value);

  rc = scram_parse_server_first (input_token->value, input_token->length,
				 &sctx->sf);
  if (rc < 0)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  if (strlen (sctx->sf.nonce) < strlen (sctx->cf.client_nonce) ||
      memcmp (sctx->cf.client_nonce, sctx->sf.nonce,
	      strlen (sctx->cf.client_nonce)) != 0)
    {
      if (minor_status)
	*minor_status = 0;
      // return GSS_S_FAILURE;
    }

  sctx->cl.nonce = strdup (sctx->sf.nonce);
  if (!sctx->cl.nonce)
    {
      if (minor_status)
	*minor_status = ENOMEM;
      return GSS_S_FAILURE;
    }

  if (input_chan_bindings == GSS_C_NO_CHANNEL_BINDINGS
      || input_chan_bindings->application_data.length == 0)
    {
      sctx->cl.cbind = NULL;
    }
  else
    {
      size_t outlen;

      outlen = base64_encode_alloc
	(input_chan_bindings->application_data.value,
	 input_chan_bindings->application_data.length, &sctx->cl.cbind);
      if (sctx->cl.cbind == NULL && outlen == 0)
	{
	  if (minor_status)
	    *minor_status = ENOMEM;
	  return GSS_S_FAILURE;
	}
    }

  rc = client_final_proof (minor_status, sctx, input_token);
  if (rc != GSS_S_COMPLETE)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  rc = scram_print_client_final (&sctx->cl, (char **) &output_token->value);
  if (rc != 0)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  output_token->length = strlen (output_token->value);

  printf ("C: C: %.*s\n", (int) output_token->length,
	  (char *) output_token->value);

  return GSS_S_COMPLETE;
}

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

      return client_first (minor_status, sctx, output_token);
    }

  return client_final (minor_status, sctx, input_chan_bindings,
		       input_token, output_token);
}

/* SCRAM server. */

/* Generate SCRAM server-first message.  Returns GSS_S_CONTINUE_NEEDED
   on success, or an error code.  Example output:
   r=8a28ac6b003dd4437665b51e22b092ee,s=1c148340b862bf2ca31bb50f,i=4096
*/
static OM_uint32
server_first (OM_uint32 * minor_status,
	      _gss_scram_ctx_t sctx,
	      const gss_buffer_t input_token_buffer,
	      gss_buffer_t output_token)
{
  gss_buffer_desc token;
  OM_uint32 maj;
  int rc;

  maj = gss_decapsulate_token (input_token_buffer, GSS_SCRAMSHA1, &token);
  if (GSS_ERROR (maj))
    return maj;

  printf ("S: C: %.*s\n", (int) token.length,
	  (char *) token.value);

  rc = scram_parse_client_first (token.value, token.length, &sctx->cf);
  if (rc < 0)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  /* Derive sctx->snonce. */
  {
    char buf[SNONCE_ENTROPY_BYTES];

    rc = gc_nonce (buf, sizeof (buf));
    if (rc != GC_OK)
      {
	if (minor_status)
	  *minor_status = rc;
	return GSS_S_FAILURE;
      }

    base64_encode_alloc (buf, sizeof (buf), &sctx->snonce);
    if (sctx->snonce == NULL)
      {
	if (minor_status)
	  *minor_status = ENOMEM;
	return GSS_S_FAILURE;
      }
  }

  /* Derive sf.salt. */
  {
    char buf[DEFAULT_SALT_BYTES];

    rc = gc_nonce (buf, sizeof (buf));
    if (rc != GC_OK)
      {
	if (minor_status)
	  *minor_status = rc;
	return GSS_S_FAILURE;
      }

    base64_encode_alloc (buf, sizeof (buf), &sctx->salt);
    if (sctx->salt == NULL)
      {
	if (minor_status)
	  *minor_status = ENOMEM;
	return GSS_S_FAILURE;
      }
  }

  /* Create combined nonce. */
  {
    size_t cnlen = strlen (sctx->cf.client_nonce);

    sctx->sf.nonce = malloc (cnlen + strlen (sctx->snonce) + 1);
    if (!sctx->sf.nonce)
      {
	if (minor_status)
	  *minor_status = ENOMEM;
	return GSS_S_FAILURE;
      }

    memcpy (sctx->sf.nonce, sctx->cf.client_nonce, cnlen);
    strcpy (sctx->sf.nonce + cnlen, sctx->snonce);
  }

  sctx->sf.iter = 4096; /* XXX */
  sctx->sf.salt = sctx->salt; /* XXX */

  rc = scram_print_server_first (&sctx->sf, (char **) &output_token->value);
  if (rc != 0)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  output_token->length = strlen (output_token->value);

  printf ("S: S: %.*s\n", (int) output_token->length,
	  (char *) output_token->value);

  return GSS_S_CONTINUE_NEEDED;
}

/* Generate SCRAM server-final message.  Returns GSS_S_COMPLETE
   on success, or an error code.  Example output:
   v=b64ver
*/
static OM_uint32
server_final (OM_uint32 * minor_status,
	      _gss_scram_ctx_t sctx,
	      const gss_buffer_t input_token,
	      gss_buffer_t output_token)
{
  int rc;

  printf ("S: C: %.*s\n", (int) input_token->length,
	  (char *) input_token->value);

  rc = scram_parse_client_final (input_token->value, input_token->length,
				 &sctx->cl);
  if (rc < 0)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  rc = strcmp (sctx->cl.nonce, sctx->sf.nonce);
  if (rc != 0)
    {
      if (minor_status)
	*minor_status = rc;
      // return GSS_S_FAILURE;
    }

  /* XXX Base64 decode the c= field and check that it matches
     client-first.  Also check channel binding data. */

  /* XXX proof */

  sctx->sl.verifier = strdup ("ver"); /* XXX */

  rc = scram_print_server_final (&sctx->sl, (char **) &output_token->value);
  if (rc != 0)
    {
      if (minor_status)
	*minor_status = rc;
      return GSS_S_FAILURE;
    }

  output_token->length = strlen (output_token->value);

  printf ("S: S: %.*s\n", (int) output_token->length,
	  (char *) output_token->value);

  return GSS_S_COMPLETE;
}

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
  gss_ctx_id_t ctx;
  _gss_scram_ctx_t sctx;

  if (*context_handle == GSS_C_NO_CONTEXT)
    {
      ctx = calloc (sizeof (*ctx), 1);
      if (!ctx)
	{
	  if (minor_status)
	    *minor_status = ENOMEM;
	  return GSS_S_FAILURE;
	}

      sctx = calloc (sizeof (*sctx), 1);
      if (!sctx)
	{
	  free (ctx);
	  if (minor_status)
	    *minor_status = ENOMEM;
	  return GSS_S_FAILURE;
	}

      ctx->mech = GSS_SCRAMSHA1;
      ctx->scram = sctx;

      *context_handle = ctx;

      maj = server_first (minor_status, sctx,
			  input_token_buffer, output_token);
      if (maj != GSS_S_CONTINUE_NEEDED)
	return maj;

      if (minor_status)
	*minor_status = 0;
      return GSS_S_CONTINUE_NEEDED;
    }
  else
    {
      ctx = *context_handle;
      sctx = ctx->scram;
    }

  return server_final (minor_status, sctx, input_token_buffer, output_token);
}

/* Delete a SCRAM security context.  Assumes context_handle is valid.
   Should only delete krb5 specific part of context. */
OM_uint32
gss_scram_delete_sec_context (OM_uint32 * minor_status,
			      gss_ctx_id_t * context_handle,
			      gss_buffer_t output_token)
{
  _gss_scram_ctx_t sctx = (*context_handle)->scram;

  scram_free_client_first (&sctx->cf);
  scram_free_server_first (&sctx->sf);
  scram_free_client_final (&sctx->cl);
  scram_free_server_final (&sctx->sl);
  free (sctx->salt);
  free (sctx->cnonce);
  free (sctx->snonce);
  free (sctx);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
