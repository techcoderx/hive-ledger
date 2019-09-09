from ledgerblue.comm import getDongle

username = raw_input("Enter Steem username: ")
apdu = bytes("8001000000".decode('hex') + username)
dongle = getDongle(True)
result = dongle.exchange(apdu)
print(result)