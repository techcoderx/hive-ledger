# from beem.steem import Steem
# from beembase.transactions import getBlockParams
from ledgerblue.comm import getDongle

# Get block references
# stm_online = Steem()
# ref_block_num, ref_block_prefix = getBlockParams(stm_online)

# Assuming at this point the transaction has been built and serialized

# {
#     ref_block_num: 43224,
#     ref_block_prefix: 15680641,
#     expiration: '2019-09-21T10:07:36',
#     operations: [
#         ['vote', {
#             voter: 'techcoderx',
#             author: 'onelovedtube',
#             permlink: 'introducing-oneloveipfs-referral-system',
#             weight: 10000
#         }]
#     ],
#     extensions: []
# }

serializedtx = "d8a88144ef0068f6855d01000a74656368636f646572780c6f6e656c6f7665647475626527696e74726f647563696e672d6f6e656c6f7665697066732d726566657272616c2d73797374656d102700"

# Assuming the serialized tx is always below 255 characters for now
dongle = getDongle(True)
apdu = bytes("80020000".decode('hex') + chr(len(serializedtx)) + serializedtx)
result = dongle.exchange(apdu)