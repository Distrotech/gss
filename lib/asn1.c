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

static size_t
_gss_asn1_get_length_der (const char *der, int *len)
{
  size_t ans;
  int k, punt;

  if (!(der[0] & 128))
    {
      /* short form */
      *len = 1;
      return (unsigned char) der[0];
    }
  else
    {
      /* Long form */
      k = (unsigned char) der[0] & 0x7F;
      punt = 1;
      ans = 0;
      while (punt <= k && punt < *len)
	ans = ans * 256 + (unsigned char) der[punt++];

      *len = punt;
      return ans;
    }
}

static int
_gss_encapsulate_token (const char *oid, size_t oidlen,
			const char *in, size_t inlen,
			void **out, size_t * outlen)
{
  size_t oidlenlen;
  size_t asn1len, asn1lenlen;
  unsigned char *p;

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
gss_encapsulate_token (const gss_buffer_t input_message,
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
gss_encapsulate_token_prefix (const gss_buffer_t input_message,
			      const char *prefix, size_t prefixlen,
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
_gss_decapsulate_token (const char *in, size_t inlen,
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
  *oid = in;

  inlen -= asn1lenlen;
  in += asn1lenlen;

  *outlen = inlen;
  *out = in;

  return 1;
}

int
gss_decapsulate_token (const gss_buffer_t input_message,
		       const gss_OID token_oid,
		       char **dataptr, size_t *datalen)
{
  char *oid;
  size_t oidlen;
  int rc;

  rc = _gss_decapsulate_token (input_message->value,
			       input_message->length,
			       &oid, &oidlen, dataptr, datalen);
  if (!rc)
    return 0;

  if (oidlen != token_oid->length ||
      memcmp (oid, token_oid->elements, oidlen) != 0)
    return 0;

  return 1;
}
