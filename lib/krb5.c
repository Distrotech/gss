/* krb5.c	Implementation of Kerberos 5 GSS functions.
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

#ifdef USE_KERBEROS5

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
			   OM_uint32 * ret_flags, OM_uint32 * time_rec)
{
  Shishi *h;
  Shishi_ap *ap;
  Shishi_tkt *tkt;
  char *data;
  size_t len;
  int rc;

  /* Note: mech_type not tested */

  if (*context_handle == GSS_C_NO_CONTEXT)
    {
      *context_handle = malloc(sizeof(*context_handle));

      if (!*context_handle)
	return GSS_S_FAILURE;

      rc = shishi_init(&h);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
      (*context_handle)->sh = h;

      if (initiator_cred_handle)
	{
	  tkt = initiator_cred_handle->tkt;
	  printf("urk\n");
	  exit(0);
	}
      else
	{
	  Shishi_tkts_hint hint;

	  memset(&hint, 0, sizeof(hint));
	  hint.server = target_name->value;

	  tkt = shishi_tkts_get (shishi_tkts_default (h), &hint);
	  if (!tkt)
	    return GSS_S_FAILURE;

	  /* XXX */
	  shishi_tkts_to_file (shishi_tkts_default (h),
			       shishi_tkts_default_file (h));
	}
      (*context_handle)->tkt = tkt;

      rc = shishi_ap_tktoptions (h, &ap, tkt, 0);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;
      (*context_handle)->ap = ap;

      rc = shishi_ap_req_der_new (ap, &data, &len);
      if (rc != SHISHI_OK)
	return GSS_S_FAILURE;

      rc = _gss_wrap_token(GSS_KRB5_OID, data, len,
			   (void**)&(output_token->value),
			   &output_token->length);
      if (!rc)
	return GSS_S_FAILURE;

      {
	int i;
	for (i = 0; i < output_token->length; i++)
	  {
	    printf("%02x ", ((char*)output_token->value)[i] & 0xFF);
	    if ((i+1)%16 == 0)
	      printf("\n");
	  }
      }

      puts(target_name->value);
    }

  return GSS_S_COMPLETE;
}

#endif /* USE_KERBEROS5 */
