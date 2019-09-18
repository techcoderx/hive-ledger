from ledgerblue.comm import getDongle

keyIndex = raw_input("Specify Key Index: ")
# pubKeyB = raw_input("Enter public key for Steem Account B: ")
pubKeyB = "STM7mWDc7dnoRixozpqnmwzn8KL1xg1nhoJM8nr4qgvEuidyYF1os"

if pubKeyB.startswith("STM") == False:
    print("Error: Steem public keys must start with STM.")
    exit(1)
elif len(pubKeyB) != 53:
    print("Error: Invalid Steem public key.")
    exit(1)

messageToEncrypt = raw_input("Enter message to encrypt (up to 203 characters): ")
apdu = bytes("8003".decode('hex') + chr(eval(keyIndex)) + "0000".decode('hex') + pubKeyB + messageToEncrypt)
# print(apdu)
dongle = getDongle(True)
result = dongle.exchange(apdu)
