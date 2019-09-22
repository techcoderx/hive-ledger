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
	unsigned long i = 0;
    unsigned long j = 0;
    char c;

    while ((c = str[i++]) != '\0') {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
            str[j++] = c;
        }
    }
    str[j] = '\0';
}