/*******************************************************************************
*   (c) 2016 Ledger
*   (c) 2018 Taras Shchybovyk
*	(c) 2019 TechCoderX
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"

unsigned char const BASE58ALPHABET[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

// Base58 encoding
bool b58enc(uint8_t *bin, uint32_t binsz, char *b58, uint32_t *b58sz) {
	int carry;
	uint32_t i, j, high, zcount = 0;
	uint32_t size;
	
	while (zcount < binsz && !bin[zcount])
		++zcount;
	
	size = (binsz - zcount) * 138 / 100 + 1;
	uint8_t buf[size];
	os_memset(buf, 0, size);
	
	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
			if (!j) {
				// Otherwise j wraps to maxint which is > high
				break;
			}
		}
	}
	
	for (j = 0; j < size && !buf[j]; ++j);
	
	if (*b58sz <= zcount + size - j)
	{
		*b58sz = zcount + size - j + 1;
		return false;
	}
	
	if (zcount)
		os_memset(b58, '1', zcount);
	for (i = zcount; j < size; ++i, ++j)
		b58[i] = BASE58ALPHABET[buf[j]];
	b58[i] = '\0';
	*b58sz = i + 1;
	
	return true;
}

// Concatenate strings with integers
void reverse(char s[]) {
	int i, j;
	char c;

	for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

void itoa(int n, char s[]) {
	int i, sign;

	if ((sign = n) < 0)  /* record sign */
		n = -n;          /* make n positive */
	i = 0;
	do {       /* generate digits in reverse order */
		s[i++] = n % 10 + '0';   /* get next digit */
	} while ((n /= 10) > 0);     /* delete it */
	if (sign < 0)
		s[i++] = '-';
	s[i] = '\0';
	reverse(s);
}

// Hexlify/Unhexlify helpers
int a2v(char c) {
    if ((c >= '0') && (c <= '9')) {
        return c - '0';
    }
    if ((c >= 'a') && (c <= 'f')) {
        return c - 'a' + 10;
    }
    else return 0;
}

char v2a(int c) {
    const char hex[] = "0123456789abcdef";
    return hex[c];
}

unsigned int dualCharHexToInt(char h[]) {
    unsigned int r = 0;
    r = r + (a2v(h[0]) * 16);
    r = r + a2v(h[1]);
    return r;
}

void hexStrToAsciiStr(char *dest,char h[]) {
	char getchar[3];
	char resultchar[(strlen(h) / 2) + 1];
	unsigned int pos = 0;
	unsigned int charpos = 0;
	while(pos < strlen(h)) {
		strncpy(&getchar,h + pos,2);
		unsigned int charint = dualCharHexToInt(getchar);
		resultchar[charpos] = (char)charint;
		charpos++;
		pos = pos + 2;
	}
	resultchar[charpos] = '\0';
	os_memmove(dest,resultchar,sizeof(resultchar));
}

// Deserialize vote weight
int parsevoteweight(char sw[]) {
    char firstb[3] = {sw[2],sw[3]};
    char secondb[3] = {sw[0],sw[1]};
    
    unsigned int firstint = dualCharHexToInt(firstb);
    unsigned int secondint = dualCharHexToInt(secondb);

    int weight = 0;

    if (firstint >= 216 && firstint <= 255) {
        // Downvotes
        weight += ((firstint-255) * 256);
        weight += (secondint-256);
    } else if (firstint >= 0 && firstint <= 39) {
        // Upvotes
        weight += (firstint * 256);
        weight += secondint;
    }
    return weight;
}

// Remove non alphanumeric characters from string
void stringRemoveNonAlphaNum(char *str) {
	unsigned int i = 0;
    unsigned int j = 0;
    char c;

    while ((c = str[i++]) != '\0') {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            str[j++] = c;
        }
    }
    str[j] = '\0';
}

// Check if signature is canonical
unsigned char check_canonical(uint8_t *rs) {
    return !(rs[0] & 0x80) 
        && !(rs[0] == 0 
        && !(rs[1] & 0x80)) 
        && !(rs[32] & 0x80) 
        && !(rs[32] == 0 && !(rs[33] & 0x80));
}

int ecdsa_der_to_sig(const uint8_t *der, uint8_t *sig) {
    int length;
    int offset = 2;
    int delta = 0;
    if (der[offset + 2] == 0) {
        length = der[offset + 1] - 1;
        offset += 3;
    } else {
        length = der[offset + 1];
        offset += 2;
    } if ((length < 0) || (length > 32)) {
        return 0;
    }
    while ((length + delta) < 32) {
        sig[delta++] = 0;
    }
    os_memmove(sig + delta, der + offset, length);

    delta = 0;
    offset += length;
    if (der[offset + 2] == 0) {
        length = der[offset + 1] - 1;
        offset += 3;
    } else {
        length = der[offset + 1];
        offset += 2;
    }
    if ((length < 0) || (length > 32)) {
        return 0;
    }
    while ((length + delta) < 32) {
        sig[32 + delta++] = 0;
    }
    os_memmove(sig + 32 + delta, der + offset, length);

    return 1;
}

void rng_rfc6979(unsigned char *rnd,
                 unsigned char *h1,
                 unsigned char *x, unsigned int x_len,
                 const unsigned char *q, unsigned int q_len,
                 unsigned char *V, unsigned char *K)
{
    unsigned int h_len, offset, found, i;
    cx_hmac_sha256_t hmac;

    h_len = 32;
    //a. h1 as input

    //loop for a candidate
    found = 0;
    while (!found)
    {
        if (x)
        {
            //b.  Set:          V = 0x01 0x01 0x01 ... 0x01
            os_memset(V, 0x01, h_len);
            //c. Set: K = 0x00 0x00 0x00 ... 0x00
            os_memset(K, 0x00, h_len);
            //d.  Set: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
            V[h_len] = 0;
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, 0, V, h_len + 1, K, 32);
            cx_hmac(&hmac, 0, x, x_len, K, 32);
            cx_hmac(&hmac, CX_LAST, h1, h_len, K, 32);
            //e.  Set: V = HMAC_K(V)
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac((cx_hmac_t *)&hmac, CX_LAST, V, h_len, V, 32);
            //f.  Set:  K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
            V[h_len] = 1;
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, 0, V, h_len + 1, K, 32);
            cx_hmac(&hmac, 0, x, x_len, K, 32);
            cx_hmac(&hmac, CX_LAST, h1, h_len, K, 32);
            //g. Set: V = HMAC_K(V) --
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, CX_LAST, V, h_len, V, 32);
            // initial setup only once
            x = NULL;
        }
        else
        {
            // h.3  K = HMAC_K(V || 0x00)
            V[h_len] = 0;
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, CX_LAST, V, h_len + 1, K, 32);
            // h.3 V = HMAC_K(V)
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, CX_LAST, V, h_len, V, 32);
        }

        //generate candidate
        /* Shortcut: As only secp256k1/sha256 is supported, the step h.2 :
         *   While tlen < qlen, do the following:
         *     V = HMAC_K(V)
         *     T = T || V
         * is replace by 
         *     V = HMAC_K(V)
         */
        x_len = q_len;
        offset = 0;
        while (x_len)
        {
            if (x_len < h_len)
            {
                h_len = x_len;
            }
            cx_hmac_sha256_init(&hmac, K, 32);
            cx_hmac(&hmac, CX_LAST, V, h_len, V, 32);
            os_memmove(rnd + offset, V, h_len);
            x_len -= h_len;
        }

        // h.3 Check T is < n
        for (i = 0; i < q_len; i++)
        {
            if (V[i] < q[i])
            {
                found = 1;
                break;
            }
        }
    }
}