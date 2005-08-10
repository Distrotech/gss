/* krb5/context.c --- Implementation of Kerberos 5 GSS Context functions.
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
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

/* Get specification. */
#include "k5internal.h"

/* Get checksum (un)packers. */
#include "checksum.h"

#define TOK_LEN 2
#define TOK_AP_REQ "\x01\x00"
#define TOK_AP_REP "\x02\x00"

/* Request part of gss_krb5_init_sec_context.  Assumes that
   context_handle is valid, and has krb5 specific structure, and that
   output_token is valid and cleared. */
static OM_uint32
init_request (OM_uint32 * minor_status,
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
	      OM_uint32 * ret_flags, OM_uint32 * time_rec)
{
  gss_ctx_id_t ctx = *context_handle;
  _gss_krb5_ctx_t k5 = ctx->krb5;
  char *cksum, *der;
  size_t cksumlen;
  int rc;
  OM_uint32 maj_stat;
  gss_buffer_desc tmp;
  Shishi_tkts_hint hint;

  /* Get service ticket. */
  maj_stat = gss_krb5_canonicalize_name (minor_status, target_name,
					 GSS_C_NO_OID, &k5->peerptr);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  memset (&hint, 0, sizeof (hint));
  hint.server = k5->peerptr->value;
  hint.endtime = time_req;

  k5->tkt = shishi_tkts_get (shishi_tkts_default (k5->sh), &hint);
  if (!k5->tkt)
    {
      if (minor_status)
	*minor_status = GSS_KRB5_S_KG_CCACHE_NOMATCH;
      return GSS_S_NO_CRED;
    }

  /* Create Authenticator checksum field. */
  maj_stat = _gss_krb5_checksum_pack (initiator_cred_handle,
				      input_chan_bindings, req_flags,
				      &cksum, &cksumlen);
  if (GSS_ERROR (maj_stat))
    return maj_stat;

  /* Create AP-REQ in output_token. */
  rc = shishi_ap_tktoptionsraw (k5->sh, &k5->ap, k5->tkt,
				SHISHI_APOPTIONS_MUTUAL_REQUIRED,
				0x8003, cksum, cksumlen);
  free (cksum);
  if (rc != SHISHI_OK)
    return GSS_S_FAILURE;

  rc = shishi_authenticator_seqnumber_get (k5->sh,
					   shishi_ap_authenticator (k5->ap),
					   &k5->initseqnr);
  if (rc != SHISHI_OK)
    return GSS_S_FAILURE;

  rc = shishi_ap_req_der (k5->ap, &der, &tmp.length);
  if (rc != SHISHI_OK)
    return GSS_S_FAILURE;

  tmp.value = der;

  rc = gss_encapsulate_token_prefix (&tmp, TOK_AP_REQ, TOK_LEN,
				     GSS_KRB5, output_token);
  free (der);
  if (!rc)
    return GSS_S_FAILURE;

  if (req_flags & GSS_C_MUTUAL_FLAG)
    return GSS_S_CONTINUE_NEEDED;

  return GSS_S_COMPLETE;
}

/* Reply part of gss_krb5_init_sec_context.  Assumes that
   context_handle is valid, and has krb5 specific structure, and that
   output_token is valid and cleared. */
static OM_uint32
init_reply (OM_uint32 * minor_status,
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
	    OM_uint32 * ret_flags, OM_uint32 * time_rec)
{
  gss_ctx_id_t ctx = *context_handle;
  _gss_krb5_ctx_t k5 = ctx->krb5;
  char *data;
  size_t datalen;
  int rc;

  if (!gss_decapsulate_token (input_token, GSS_KRB5, &data, &datalen))
    return GSS_S_DEFECTIVE_TOKEN;

  if (datalen < TOK_LEN)
    return GSS_S_DEFECTIVE_TOKEN;

  if (memcmp (data, TOK_AP_REP, TOK_LEN) != 0)
    return GSS_S_DEFECTIVE_TOKEN;

  rc = shishi_ap_rep_der_set (k5->ap, data + TOK_LEN, datalen - TOK_LEN);
  if (rc != SHISHI_OK)
    return GSS_S_DEFECTIVE_TOKEN;

  rc = shishi_ap_rep_verify (k5->ap);
  if (rc != SHISHI_OK)
    return GSS_S_DEFECTIVE_TOKEN;

  rc = shishi_encapreppart_seqnumber_get (k5->sh,
					  shishi_ap_encapreppart (k5->ap),
					  &k5->acceptseqnr);
  if (rc != SHISHI_OK)
    {
      /* A strict 1964 implementation would return
         GSS_S_DEFECTIVE_TOKEN here.  gssapi-cfx permit absent
         sequence number, though. */
      k5->acceptseqnr = 0;
    }

  return GSS_S_COMPLETE;
}

/* Initiates the establishment of a krb5 security context between the
   application and a remote peer.  Assumes that context_handle and
   output_token are valid and cleared. */
OM_uint32
gss_krb5_init_sec_context (OM_uint32 * minor_status,
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
			   OM_uint32 * ret_flags, OM_uint32 * time_rec)
{
  gss_ctx_id_t ctx = *context_handle;
  _gss_krb5_ctx_t k5 = ctx->krb5;
  OM_uint32 maj_stat;
  int rc;

  if (minor_status)
    *minor_status = 0;

  if (initiator_cred_handle)
    {
      /* We only support the default initiator.  See k5internal.h for
         adding a Shishi_tkt to the credential structure.  I'm not sure
         what the use would be -- user-to-user authentication perhaps?
         Later: if you have tickets for foo@BAR and bar@FOO, it may be
         useful to call gss_acquire_cred first to chose which one to
         initiate the context with.  Not many applications need this. */
      return GSS_S_NO_CRED;
    }

  if (k5 == NULL)
    {
      k5 = ctx->krb5 = xcalloc (sizeof (*k5), 1);

      rc = shishi_init (&k5->sh);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
    }

  if (!k5->reqdone)
    {
      maj_stat = init_request (minor_status,
			       initiator_cred_handle,
			       context_handle,
			       target_name,
			       mech_type,
			       req_flags,
			       time_req,
			       input_chan_bindings,
			       input_token,
			       actual_mech_type,
			       output_token, ret_flags, time_rec);
      if (GSS_ERROR (maj_stat))
	return maj_stat;

      k5->flags = req_flags & (	/* GSS_C_DELEG_FLAG | */
				GSS_C_MUTUAL_FLAG |
				GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG |
				GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG);
      /* PROT_READY is not mentioned in 1964/gssapi-cfx but we support
         it anyway. */
      k5->flags |= GSS_C_PROT_READY_FLAG;

      if (ret_flags)
	*ret_flags = k5->flags;

      k5->key = shishi_ap_key (k5->ap);
      k5->reqdone = 1;
    }
  else if (k5->reqdone && k5->flags & GSS_C_MUTUAL_FLAG && !k5->repdone)
    {
      maj_stat = init_reply (minor_status,
			     initiator_cred_handle,
			     context_handle,
			     target_name,
			     mech_type,
			     req_flags,
			     time_req,
			     input_chan_bindings,
			     input_token,
			     actual_mech_type,
			     output_token, ret_flags, time_rec);
      if (GSS_ERROR (maj_stat))
	return maj_stat;

      if (ret_flags)
	*ret_flags = k5->flags;

      k5->repdone = 1;
    }
  else
    maj_stat = GSS_S_FAILURE;

  if (time_rec)
    *time_rec = gss_krb5_tktlifetime (k5->tkt);

  return maj_stat;
}

/* Allows a remotely initiated security context between the
   application and a remote peer to be established, using krb5.
   Assumes context_handle is valid. */
OM_uint32
gss_krb5_accept_sec_context (OM_uint32 * minor_status,
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
  gss_buffer_desc data;
  char *in;
  size_t inlen;
  gss_ctx_id_t cx;
  _gss_krb5_ctx_t cxk5;
  _gss_krb5_cred_t crk5;
  OM_uint32 maj_stat;
  int rc;

  if (minor_status)
    *minor_status = 0;

  if (ret_flags)
    *ret_flags = 0;

  if (!acceptor_cred_handle)
    /* XXX support GSS_C_NO_CREDENTIAL: acquire_cred() default server */
    return GSS_S_NO_CRED;

  if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS)
    /* XXX support channel bindings */
    return GSS_S_BAD_BINDINGS;

  if (*context_handle)
    return GSS_S_FAILURE;

  crk5 = acceptor_cred_handle->krb5;

  cx = xcalloc (sizeof (*cx), 1);
  cxk5 = xcalloc (sizeof (*cxk5), 1);
  cx->mech = GSS_KRB5;
  cx->krb5 = cxk5;
  /* XXX cx->peer?? */
  *context_handle = cx;

  cxk5->sh = crk5->sh;
  cxk5->key = crk5->key;
  cxk5->acceptor = 1;

  rc = shishi_ap (cxk5->sh, &cxk5->ap);
  if (rc != SHISHI_OK)
    return GSS_S_FAILURE;

  rc = gss_decapsulate_token (input_token_buffer, GSS_KRB5, &in, &inlen);
  if (!rc)
    return GSS_S_BAD_MIC;

  if (inlen < TOK_LEN)
    return GSS_S_BAD_MIC;

  if (memcmp (in, TOK_AP_REQ, TOK_LEN) != 0)
    return GSS_S_BAD_MIC;

  rc = shishi_ap_req_der_set (cxk5->ap, in + TOK_LEN, inlen - TOK_LEN);
  if (rc != SHISHI_OK)
    return GSS_S_FAILURE;

  rc = shishi_ap_req_process (cxk5->ap, crk5->key);
  if (rc != SHISHI_OK)
    {
      if (minor_status)
	*minor_status = GSS_KRB5_S_G_VALIDATE_FAILED;
      return GSS_S_FAILURE;
    }

  rc = shishi_authenticator_seqnumber_get (cxk5->sh,
					   shishi_ap_authenticator (cxk5->ap),
					   &cxk5->initseqnr);
  if (rc != SHISHI_OK)
    return GSS_S_FAILURE;

  if (shishi_ap_authenticator_cksumtype (cxk5->ap) != 0x8003)
    {
      if (minor_status)
	*minor_status = GSS_KRB5_S_G_VALIDATE_FAILED;
      return GSS_S_FAILURE;
    }

  /* XXX Parse authenticator.checksum data. */

  cxk5->tkt = shishi_ap_tkt (cxk5->ap);
  cxk5->key = shishi_ap_key (cxk5->ap);

  if (shishi_apreq_mutual_required_p (crk5->sh, shishi_ap_req (cxk5->ap)))
    {
      Shishi_asn1 aprep;

      rc = shishi_ap_rep_asn1 (cxk5->ap, &aprep);
      if (rc != SHISHI_OK)
	{
	  printf ("Error creating AP-REP: %s\n", shishi_strerror (rc));
	  return GSS_S_FAILURE;
	}

      rc = shishi_encapreppart_seqnumber_get (cxk5->sh,
					      shishi_ap_encapreppart (cxk5->
								      ap),
					      &cxk5->acceptseqnr);
      if (rc != SHISHI_OK)
	{
	  /* A strict 1964 implementation would return
	     GSS_S_DEFECTIVE_TOKEN here.  gssapi-cfx permit absent
	     sequence number, though. */
	  cxk5->acceptseqnr = 0;
	}

      rc = shishi_asn1_to_der (crk5->sh, aprep,
			       (char **) &data.value, &data.length);
      if (rc != SHISHI_OK)
	{
	  printf ("Error der encoding aprep: %s\n", shishi_strerror (rc));
	  return GSS_S_FAILURE;
	}

      rc = gss_encapsulate_token_prefix (&data, TOK_AP_REP, TOK_LEN,
					 GSS_KRB5, output_token);
      if (!rc)
	return GSS_S_FAILURE;

      if (ret_flags)
	*ret_flags = GSS_C_MUTUAL_FLAG;
    }
  else
    {
      output_token->value = NULL;
      output_token->length = 0;
    }

  if (src_name)
    {
      gss_name_t p;

      p = xmalloc (sizeof (*p));

      rc = shishi_encticketpart_client (cxk5->sh,
					shishi_tkt_encticketpart (cxk5->tkt),
					&p->value, &p->length);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      p->type = GSS_KRB5_NT_PRINCIPAL_NAME;

      *src_name = p;
    }

  /* PROT_READY is not mentioned in 1964/gssapi-cfx but we support
     it anyway. */
  if (ret_flags)
    *ret_flags |= GSS_C_PROT_READY_FLAG;

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/* Delete a krb5 security context.  Assumes context_handle is valid.
   Should only delete krb5 specific part of context. */
OM_uint32
gss_krb5_delete_sec_context (OM_uint32 * minor_status,
			     gss_ctx_id_t * context_handle,
			     gss_buffer_t output_token)
{
  _gss_krb5_ctx_t k5 = (*context_handle)->krb5;

  if (k5->peerptr != GSS_C_NO_NAME)
    gss_release_name (NULL, &k5->peerptr);

  if (k5->ap)
    shishi_ap_done (k5->ap);

  if (!k5->acceptor)
    shishi_done (k5->sh);
  free (k5);

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}

/* Determines the number of seconds for which the specified krb5
   context will remain valid.  Assumes context_handle is valid. */
OM_uint32
gss_krb5_context_time (OM_uint32 * minor_status,
		       const gss_ctx_id_t context_handle,
		       OM_uint32 * time_rec)
{
  _gss_krb5_ctx_t k5 = context_handle->krb5;

  if (time_rec)
    {
      *time_rec = gss_krb5_tktlifetime (k5->tkt);

      if (*time_rec == 0)
	{
	  if (minor_status)
	    *minor_status = 0;
	  return GSS_S_CONTEXT_EXPIRED;
	}
    }

  if (minor_status)
    *minor_status = 0;
  return GSS_S_COMPLETE;
}
