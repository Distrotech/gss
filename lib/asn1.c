/* asn1.c	Wrapper around pseudo-ASN.1 token format.
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

/*
 * The following two functions borrowed from libtasn.1, under LGPL.
 * Copyright (C) 2002 Fabio Fiorina.
 */
static void
_gss_asn1_length_der (size_t len, unsigned char *ans, size_t * ans_len)
{
  size_t k;
  unsigned char temp[sizeof (len)];

  if (len < 128)
    {
      if (ans != NULL)
	ans[0] = (unsigned char) len;
      *ans_len = 1;
    }
  else
    {
      k = 0;

      while (len)
	{
	  temp[k++] = len & 0xFF;
	  len = len >> 8;
	}

      *ans_len = k + 1;

      if (ans != NULL)
	{
	  ans[0] = ((unsigned char) k & 0x7F) + 128;
	  while (k--)
	    ans[*ans_len - 1 - k] = temp[k];
	}
    }
}

static unsigned long
_gss_asn1_get_length_der (const unsigned char *der, int *len)
{
  unsigned long ans;
  int k, punt;

  if (!(der[0] & 128))
    {
      /* short form */
      *len = 1;
      return der[0];
    }
  else
    {
      /* Long form */
      k = der[0] & 0x7F;
      punt = 1;
      ans = 0;
      while (punt <= k && punt < *len)
	ans = ans * 256 + der[punt++];

      *len = punt;
      return ans;
    }
}

static int
_gss_encapsulate_token (char *oid, size_t oidlen,
			char *in, size_t inlen, char **out, size_t * outlen)
{
  size_t oidlenlen;
  size_t asn1len, asn1lenlen;
  char *p;

  _gss_asn1_length_der (oidlen, NULL, &oidlenlen);
  asn1len = 1 + oidlenlen + oidlen + inlen;
  _gss_asn1_length_der (asn1len, NULL, &asn1lenlen);

  *outlen = 1 + asn1lenlen + asn1len;
  p = xmalloc (*outlen);
  *out = p;

  *p++ = '\x60';
  _gss_asn1_length_der (asn1len, p, &asn1lenlen);
  p += asn1lenlen;
  *p++ = '\x06';
  _gss_asn1_length_der (oidlen, p, &oidlenlen);
  p += oidlenlen;
  memcpy (p, oid, oidlen);
  p += oidlen;
  memcpy (p, in, inlen);

  return 1;
}

int
gss_encapsulate_token (gss_buffer_t input_message,
		       gss_OID token_oid, gss_buffer_t output_message)
{
  return _gss_encapsulate_token (token_oid->elements,
				 token_oid->length,
				 input_message->value,
				 input_message->length,
				 &output_message->value,
				 &output_message->length);
}

int
gss_encapsulate_token_prefix (gss_buffer_t input_message,
			      char *prefix, size_t prefixlen,
			      gss_OID token_oid, gss_buffer_t output_message)
{
  char *in;
  size_t inlen;
  int rc;

  inlen = prefixlen + input_message->length;
  in = xmalloc (inlen);
  memcpy (in, prefix, prefixlen);
  memcpy (in + prefixlen, input_message->value, input_message->length);

  rc = _gss_encapsulate_token (token_oid->elements,
			       token_oid->length,
			       in,
			       inlen,
			       &output_message->value,
			       &output_message->length);

  free (in);

  return rc;
}

static int
_gss_decapsulate_token (char *in, size_t inlen,
			char **oid, size_t * oidlen,
			char **out, size_t * outlen)
{
  int i;
  size_t asn1lenlen;

  if (inlen-- == 0)
    return 0;
  if (*in++ != '\x60')
    return 0;

  i = inlen;
  asn1lenlen = _gss_asn1_get_length_der (in, &i);
  if (inlen < i)
    return 0;

  inlen -= i;
  in += i;

  if (inlen != asn1lenlen)
    return 0;

  if (inlen-- == 0)
    return 0;
  if (*in++ != '\x06')
    return 0;

  i = inlen;
  asn1lenlen = _gss_asn1_get_length_der (in, &i);
  if (inlen < i)
    return 0;

  inlen -= i;
  in += i;

  if (inlen < asn1lenlen)
    return 0;

  *oidlen = asn1lenlen;
  *oid = xmalloc (*oidlen);
  memcpy (*oid, in, *oidlen);

  inlen -= asn1lenlen;
  in += asn1lenlen;

  *outlen = inlen;
  *out = xmalloc (*outlen);
  memcpy (*out, in, *outlen);

  return 1;
}

int
gss_decapsulate_token (gss_buffer_t input_message,
		       gss_OID token_oid, gss_buffer_t output_message)
{
  char *oid, *out;
  size_t oidlen, outlen;
  int rc;

  rc = _gss_decapsulate_token (input_message->value,
			       input_message->length,
			       &oid, &oidlen, &out, &outlen);
  if (!rc)
    return 0;

  token_oid->length = oidlen;
  token_oid->elements = (void *) oid;

  output_message->length = outlen;
  output_message->value = (void *) out;

  return 1;
}

int
gss_decapsulate_token_check (gss_buffer_t input_message,
			     char *prefix, size_t prefixlen,
			     gss_OID token_oid,
			     gss_buffer_t output_message)
{
  gss_OID_desc tmp;
  gss_buffer_desc data;
  int rc;

  rc = gss_decapsulate_token (input_message, &tmp, &data);
  if (!rc)
    return 0;

  if (!gss_oid_equal (&tmp, token_oid) ||
      data.length < prefixlen ||
      memcmp (data.value, prefix, prefixlen) != 0)
    {
      gss_release_oid (NULL, &tmp);
      gss_release_buffer (NULL, &data);
      return 0;
    }

  memmove (data.value, data.value + prefixlen, data.length - prefixlen);

  output_message->length = data.length - prefixlen;
  output_message->value = data.value;

  return 1;
}
