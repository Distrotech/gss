/* asn1.c	Wrapper around pseudo-ASN.1 token format.
 * Copyright (C) 2003  Simon Josefsson
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

/* See RFC 2743 section 3.1. */

/*
 * The following function borrowed from libtasn.1, under LGPL.
 * Copyright (C) 2002  Fabio Fiorina
 */
static void
_gss_asn1_length_der(size_t len, unsigned char *ans, size_t *ans_len)
{
  size_t k;
  unsigned char temp[sizeof(len)];

  if(len<128)
    {
      if(ans!=NULL) ans[0]=(unsigned char)len;
      *ans_len=1;
    }
  else
    {
      k=0;

      while(len)
	{
	  temp[k++]=len&0xFF;
	  len=len>>8;
	}

      *ans_len=k+1;

      if(ans!=NULL)
	{
	  ans[0]=((unsigned char)k&0x7F)+128;
	  while(k--)
	    ans[*ans_len-1-k]=temp[k];
	}
    }
}

int
_gss_wrap_token (char *oid, size_t oidlen,
		 char *in, size_t inlen,
		 char **out, size_t *outlen)
{
  size_t asn1len, asn1lenlen;
  int rc;

  asn1len = oidlen + inlen;
  _gss_asn1_length_der(asn1len, NULL, &asn1lenlen);

  *outlen = 1 + asn1lenlen + asn1len;
  *out = malloc(*outlen);
  if (!*out)
    return 0;

  **out = '\x60';
  _gss_asn1_length_der(asn1len, *out + 1, &asn1lenlen);
  memcpy(*out + 1 + asn1lenlen, oid, oidlen);
  memcpy(*out + 1 + asn1lenlen + oidlen, in, inlen);

  return 1;
}
