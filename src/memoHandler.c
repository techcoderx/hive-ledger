/*******************************************************************************
*
*  (c) 2016 Ledger
*  (c) 2019 TechCoderX
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
#include "memoHandler.h"
#include "steemUtils.h"
#include "os.h"
#include "os_io_seproxyhal.h"
#include "cx.h"
#include "ux.h"

typedef struct memoContext_t {
    unsigned int reqType;
    unsigned int keyIndex;
    char pubKeyB[STEEM_PUB_KEY_LENGTH + 1];
    char messageToProcess[STEEM_MEMO_MAX_LENGTH + 1]; // Extra one character for terminator char
} memoContext_t;

memoContext_t memoctx;

static unsigned int current_text_pos;

// Confirmation UI

// Generate a random uint64_t number for encryption
void get_nonce() {
    uint8_t buf[20];
    cx_rng(buf,20); // not sure
    // PRINTF("Generated nonce: %s\n" + buf);
}

void get_shared_secret() {

}

static unsigned char parse_publickeyb() {
    // Parse public key of account B
    unsigned int i;
    WIDE char *text = (char*) G_io_apdu_buffer + 5;
    if (text[current_text_pos] == '\0') {
        return 0;
    }
    i = 0;
    while ((text[current_text_pos] != 0) && (text[current_text_pos] != '\n') &&
           (i < STEEM_PUB_KEY_LENGTH)) {
        memoctx.pubKeyB[i++] = text[current_text_pos];
        current_text_pos++;
    }
    if (text[current_text_pos] == '\n') {
        current_text_pos++;
    }
    memoctx.pubKeyB[i] = '\0';
    return 1;
}


static unsigned char parse_message_to_encrypt() {
    WIDE char *text2 = (char*) G_io_apdu_buffer + 58;
    unsigned int j = 0;
    while((text2[j] != '\n') && (text2[j] != 0) && (j < STEEM_MEMO_MAX_LENGTH)) {
        memoctx.messageToProcess[j] = text2[j];
        j++;
    }
    memoctx.messageToProcess[j] = '\0';
    PRINTF("Message parsed: %s\n",memoctx.messageToProcess);
    return 1;
}

// Handle APDU command 3
// Encrypt memo
void handleEncryptMemo (uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    // P1: Key index to be used for encryption
    // P2: Message part no. (up to 0x08, then 0x09 as terminator then process, or 0x0A to cancel and reset memoctx)
    PRINTF("Handle memo encryption\n");
    
    // Store request params in context
    memoctx.reqType = 1;
    os_memmove(&memoctx.keyIndex,&p1,sizeof(p1));

    // TODO: Stream APDU command to allow memo up to 2047 characters
    // Currently maximum size is 203 characters
    current_text_pos = 0;
    parse_publickeyb();

    parse_message_to_encrypt();
    
    PRINTF("Parsed public key: %s\n",memoctx.pubKeyB);
    PRINTF("Message parsed: %s\n",memoctx.messageToProcess);

    get_nonce();

    io_exchange_with_code(0x9000,0);
    

    // *flags |= IO_ASYNCH_REPLY;
}