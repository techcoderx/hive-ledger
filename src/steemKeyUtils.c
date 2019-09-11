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
#include <string.h>
#include <inttypes.h>
#include "steemUtils.h"
#include "steemKeyUtils.h"
#include "os_io_seproxyhal.h"
#include "os.h"
#include "cx.h"
#include "ux.h"

#define P1_CONFIRM 0x01
#define P1_NON_CONFIRM 0x00
#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE 0x01

typedef struct requestContext_t {
    uint8_t p1;
    uint8_t p2;
    uint16_t dataLength;
    unsigned int index;
    char * numstr[];
} requestContext_t;

requestContext_t reqctx;

typedef struct publicKeyContext_t{
    cx_ecfp_public_key_t publicKey;
    char address[60];
    uint8_t chainCode[32];
    bool getChaincode;
} publicKeyContext_t;

publicKeyContext_t pubKeyCtx;

// Generate Steem public key from seed and compare
uint32_t compressed_public_key_to_wif(uint8_t *publicKey, uint32_t keyLength, char *out, uint32_t outLength) {
    if (keyLength < 33) {
        THROW(INVALID_PARAMETER);
    }
    if (outLength < 40) {
        THROW(EXCEPTION_OVERFLOW);
    }

    uint8_t temp[37];
    os_memset(temp, 0, sizeof(temp));
    os_memmove(temp, publicKey, 33);
    
    uint8_t check[20];
    cx_ripemd160_t riprip;
    cx_ripemd160_init(&riprip);
    cx_hash(&riprip.header, CX_LAST, temp, 33, check, sizeof(check));
    os_memmove(temp + 33, check, 4);
    
    os_memset(out, 0, outLength);

    // First 3 letters of a Steem public key is STM
    out[0] = 'S';
    out[1] = 'T';
    out[2] = 'M';
    uint32_t addressLen = outLength - 3;
    b58enc(temp, sizeof(temp), out + 3, &addressLen);
    if (addressLen + 3 >= outLength) {
        THROW(EXCEPTION_OVERFLOW);
    }
    PRINTF("Steem public key: %s\n", out);
    // PRINTF("Address: %s\n", addressLen + 3);
    return addressLen + 3;
}

uint32_t public_key_to_wif(uint8_t *publicKey, uint32_t keyLength, char *out, uint32_t outLength) {
    if (publicKey == NULL || keyLength < 33) {
        THROW(INVALID_PARAMETER);
    }
    if (outLength < 40) {
        THROW(EXCEPTION_OVERFLOW);
    }

    uint8_t temp[33];
    // is even?
    temp[0] = (publicKey[64] & 0x1) ? 0x03 : 0x02;
    os_memmove(temp + 1, publicKey + 1, 32);
    return compressed_public_key_to_wif(temp, sizeof(temp), out, outLength);
}

static const SteemPubKeyApproved() {
    UNUSED(reqctx.dataLength);

    // Initialize private key contexts
    cx_ecfp_private_key_t privateKey;
    uint8_t privateKeyData[32];

    // Steem BIP32 path: 44'/135'/0'/0/0
    uint32_t bip32Path[5] = {0x8000002C, 0x80000087, 0x80000000, 0, reqctx.index};

    pubKeyCtx.getChaincode = (reqctx.p2 == P2_CHAINCODE);
    os_perso_derive_node_bip32(CX_CURVE_256K1,bip32Path,5,privateKeyData,(pubKeyCtx.getChaincode ? pubKeyCtx.chainCode : NULL));
    cx_ecfp_init_private_key(CX_CURVE_256K1,privateKeyData,32,&privateKey);
    cx_ecfp_generate_pair(CX_CURVE_256K1, &pubKeyCtx.publicKey,&privateKey, 1);
    os_memset(&privateKey,0,sizeof(privateKey));
    os_memset(privateKeyData,0,sizeof(privateKeyData));
    public_key_to_wif(pubKeyCtx.publicKey.W,sizeof(pubKeyCtx.publicKey.W),pubKeyCtx.address,sizeof(pubKeyCtx.address));

    G_io_apdu_buffer[0] = 0x90;
    G_io_apdu_buffer[1] = 0x00;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX,2);
    PRINTF("Request approved successfully\n");
    ui_idle();
    return 0;
}

// Approval UI for public key generation
static const bagl_element_t ui_getPublicKey_approve[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x00,BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00,BAGL_GLYPH_ICON_CHECK),
    UI_TEXT_BOLD(0x01,0,12,128,"Generate Steem"),
    UI_TEXT_BOLD(0x01,0,26,128,"Public Key"),
};

// Approval button click
unsigned int ui_getPublicKey_approve_button(unsigned int button_mask,unsigned int button_mask_counter) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            G_io_apdu_buffer[0] = 0x69;
            G_io_apdu_buffer[1] = 0x85;
            io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX,2);
            ui_idle(); // Cancel
            break;
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            SteemPubKeyApproved(); // TODO: Generate Steem public key and compare
            break;
    }
    return 0;
}

// Handle APDU command ID 1
// Approval to generate Steem public key
void handleGetSteemPubKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    // Sanity checks
    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM)) THROW(0x6B00);
    if ((p2 != P2_CHAINCODE) && (p2 != P2_NO_CHAINCODE)) THROW(0x6B00);

    os_memmove(&reqctx.p1,&p1,sizeof(p1));
    os_memmove(&reqctx.p2,&p2,sizeof(p2));
    os_memmove(&reqctx.dataLength,&dataLength,sizeof(dataLength));
    
    // Get deriavation address index requested (from 0 to 99)
    if (G_io_apdu_buffer[5] == 0xA5 && G_io_apdu_buffer[6] == 0xA5) {
        // Address #0 by default if not specified
        reqctx.index = 0;
    } else if (G_io_apdu_buffer[6] == 0xA5) {
        // Single digit number requested
        reqctx.index = G_io_apdu_buffer[5] - 48;
    } else {
        // Double digit number requested
        unsigned int tempindex = 0;
        tempindex += ((G_io_apdu_buffer[5] - 48) * 10);
        tempindex += (G_io_apdu_buffer[6] - 48);
        reqctx.index = tempindex;
        os_memset(&tempindex,0,sizeof(tempindex));
    }

    PRINTF("Requested deriavation index is %u\n",reqctx.index);

    // Show confirmation
    UX_DISPLAY(ui_getPublicKey_approve,NULL);
    *flags |= IO_ASYNCH_REPLY;
}