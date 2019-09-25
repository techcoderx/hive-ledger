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

#include "signHandler.h"
#include "steemUtils.h"
#include "os_io_seproxyhal.h"
#include "os.h"
#include "cx.h"
#include "ux.h"

// Due to hardware limitations, the maximum transaction size that it can process is 1 KB.
// 64 bytes have been allocated for Chain ID for signing.
typedef struct transactionContext_t {
    unsigned int txType;
    char serializedBuffer[1024];
    char txName[25];
    uint8_t hash[32];
} transactionContext_t;

transactionContext_t txctx;

extern unsigned short ux_step;
extern unsigned short ux_step_count;

union TxContent {
    vote_t votetx;
};

union TxContent txcontent;

uint8_t const SECP256K1_N[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                               0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                               0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

cx_sha256_t sha256;

// Forward declarations
void processOps(unsigned int txtype,char serializedDetail[]);

// ECC signing
void signTransaction(void) {
    char unhexedBuf[326];
    hexStrToAsciiStr(unhexedBuf,txctx.serializedBuffer);
    cx_sha256_init(&sha256);
    cx_hash(&sha256.header,CX_LAST,&txctx.hash,0,&txctx.hash,sizeof(txctx.hash));

    PRINTF("SHA256\n");
    PRINTF("Hash: %s\n",&txctx.hash);

    uint8_t privateKeyData[64];
    cx_ecfp_256_private_key_t privateKey;
    uint32_t tx = 0;
    uint8_t V[33];
    uint8_t K[32];
    int tries = 0;

    PRINTF("Private key begin\n");

    PRINTF("%u\n",G_io_apdu_buffer[2]);

    uint32_t bip32Path[5] = {0x8000002C, 0x80000087, 0x80000000, 0, G_io_apdu_buffer[2]};

    PRINTF("Serialized string received: %s\n",txctx.serializedBuffer);
    PRINTF("Unhexed string received: %s\n",unhexedBuf);

    os_perso_derive_node_bip32(CX_CURVE_256K1,bip32Path,5,privateKeyData,NULL);
    cx_ecfp_init_private_key(CX_CURVE_256K1,privateKeyData,32,&privateKey);
    os_memset(privateKeyData,0,sizeof(privateKeyData));

    for (;;) {
        if (tries == 0) {
            rng_rfc6979(unhexedBuf, txctx.hash, privateKey.d, privateKey.d_len, SECP256K1_N, 32, V, K);
        } else {
            rng_rfc6979(unhexedBuf, txctx.hash, NULL, 0, SECP256K1_N, 32, V, K);
        }
        uint32_t infos;
        tx = cx_ecdsa_sign(&privateKey, CX_NO_CANONICAL | CX_RND_PROVIDED | CX_LAST, CX_SHA256,
                           txctx.hash, 32, //?
                           unhexedBuf, 100,//?
                           &infos);
        if ((infos & CX_ECCINFO_PARITY_ODD) != 0) {
            G_io_apdu_buffer[100] |= 0x01; //?
        }
        G_io_apdu_buffer[0] = 27 + 4 + (0x00 & 0x01);//?
        ecdsa_der_to_sig(G_io_apdu_buffer + 100, G_io_apdu_buffer + 1); //?
        if (check_canonical(G_io_apdu_buffer + 1)) {
            tx = 1 + 64;
            break;
        } else {
            tries++;
        }
    }

    io_exchange_with_code(0x9000,tx);
    ui_idle();
}

// Confirmation UI
// Vote
static const bagl_element_t sign_request_confirmation_vote[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x00,BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00,BAGL_GLYPH_ICON_CHECK),
    UI_TEXT(0x01,0,12,128,"Operation"),
    UI_TEXT_BOLD(0x01,0,26,128,&txctx.txName),
    UI_TEXT(0x02,0,12,128,"Voter"),
    UI_TEXT_BOLD(0x02,0,26,128,txcontent.votetx.voter),
    UI_TEXT(0x03,0,12,128,"Author"),
    UI_TEXT_BOLD(0x03,0,26,128,txcontent.votetx.author),
    UI_TEXT(0x04,0,12,128,"Permlink"),
    UI_TEXT_BOLD_SCROLL(0x04,23,26,82,txcontent.votetx.permlink),
    UI_TEXT(0x05,0,12,128,"Weight"),
    UI_TEXT_BOLD(0x05,0,26,128,txcontent.votetx.weight)
};

unsigned int sign_request_confirmation_vote_button(unsigned int button_mask,unsigned int button_mask_counter) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT:
            signTransaction();
            break;
        case BUTTON_EVT_RELEASED | BUTTON_LEFT:
            io_exchange_with_code(0x9000,0);
            ui_idle();
            break;
    }
    return 0;
}

unsigned int signreq_vote_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        unsigned int display = (ux_step == element->component.userid - 1);
        if (display) {
            switch (element->component.userid) {
            case 1:
            case 2:
            case 3:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            case 4:
                UX_CALLBACK_SET_INTERVAL(MAX(
                    3000, 1000 + bagl_label_roundtrip_duration_ms(element, 7)));
                break;
            case 5:
                UX_CALLBACK_SET_INTERVAL(2000);
                break;
            }
        }
        return display;
    }
    return 1;
}

void parseTx(char *serialized) {
    unsigned int currentParsingPos = 86; // Starting from 84th character
    char hexStr[3];
    strncpy(&hexStr,serialized + currentParsingPos,2);
    txctx.txType = dualCharHexToInt(hexStr);
    strcpy(&txctx.txName,SteemOperations[txctx.txType]);
    PRINTF("Transaction Type: %u\n",txctx.txType);
    PRINTF("Transaction name: %s\n",txctx.txName);
    PRINTF("Transaction name with amphersand: %s\n",&txctx.txName);

    processOps(txctx.txType,serialized + currentParsingPos + 2);
}

// TODO: Fetch APDU data in parts
void cacheSerialBuffer() {
    char ChainID[322] = "0000000000000000000000000000000000000000000000000000000000000000";
    strcat(&ChainID,G_io_apdu_buffer+5);
    os_memmove(&txctx.serializedBuffer,&ChainID,strlen(ChainID));
    stringRemoveNonAlphaNum(&txctx.serializedBuffer);
    PRINTF("Cached buffer: %s\n",txctx.serializedBuffer);
}

// APDU command ID 2
// Sign Steem transactions
void handleSign(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    // P1 is the key index of private key to sign
    // P2 is the APDU stream section number (starts from 0, incremented, ff to process command)
    // PRINTF("%s\n",G_io_apdu_buffer+5);
    cacheSerialBuffer();
    PRINTF("%s\n",txctx.serializedBuffer);
    parseTx(&txctx.serializedBuffer);
    // io_exchange_with_code(0x9000,0);
    *flags |= IO_ASYNCH_REPLY;
}

// Deserialize operations for confirmation
void processOps(unsigned int txtype,char serializedDetail[]) {
    unsigned int pos = 0;
    char charnumstr[3];
    unsigned int charnum = 0;
    PRINTF("%s\n",serializedDetail);
    switch (txtype) {
        case 0: // Vote
            strncpy(&charnumstr,serializedDetail,2);
            charnum = dualCharHexToInt(charnumstr);
            PRINTF("Voter chars: %u\n",charnum);

            // Voter
            char ser[511];
            strncpy(&ser,serializedDetail+2,charnum * 2);
            hexStrToAsciiStr(txcontent.votetx.voter,ser);
            PRINTF("Voter: %s\n",txcontent.votetx.voter);
            PRINTF("Transaction name2: %s\n",txctx.txName);
            os_memset(&ser,0,sizeof(ser));

            pos = pos + (charnum * 2) + 2;

            // Author
            strncpy(&charnumstr,serializedDetail+pos,2);
            charnum = dualCharHexToInt(charnumstr);
            PRINTF("Author chars: %u\n",charnum);
            strncpy(&ser,serializedDetail+pos+2,charnum * 2);
            hexStrToAsciiStr(txcontent.votetx.author,ser);
            PRINTF("Author: %s\n",txcontent.votetx.author);
            os_memset(&ser,0,sizeof(ser));

            pos = pos + (charnum * 2) + 2;

            // Permlink
            strncpy(&charnumstr,serializedDetail+pos,2);
            charnum = dualCharHexToInt(charnumstr);
            PRINTF("Permlink chars: %u\n",charnum);
            strncpy(&ser,serializedDetail+pos+2,charnum * 2);
            hexStrToAsciiStr(txcontent.votetx.permlink,ser);
            PRINTF("Permlink: %s\n",txcontent.votetx.permlink);
            os_memset(&ser,0,sizeof(ser));

            pos = pos + (charnum * 2) + 2;

            // Weight
            strncpy(&ser,serializedDetail+pos,4);
            itoa(parsevoteweight(ser),txcontent.votetx.weight);
            PRINTF("Weight: %s\n",txcontent.votetx.weight);
            os_memset(&ser,0,sizeof(ser));

            // Prepare confirmation screen
            ux_step = 0;
            ux_step_count = 5;
            UX_DISPLAY(sign_request_confirmation_vote,signreq_vote_prepro);
            break;
        default:
            // Invalid operation type
            THROW(0x6B00);
            break;
    }
}