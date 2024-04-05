from pwn import *

c = remote("46.30.202.223", 2429)
#c = remote("127.0.0.1", 2429)

MAGIC_NUMBER = (1100).to_bytes(2, "little")
PROTOCOL_CMD_HEALTHCHECK = (99).to_bytes(1, "little")
SIZE_HEADER = 5
CHECK = b"\x2a"
END = b"\r\n"
HEALTH = b"HEALTH_OK"

# Send Health Check command
pkt = CHECK + END
header = MAGIC_NUMBER + PROTOCOL_CMD_HEALTHCHECK + (len(pkt) - 2).to_bytes(2, "little") + END
c.send(header)
c.send(pkt)

# Receive Health OK packet length
flag_len_bytes = c.recv(4)
flag_len = int.from_bytes(flag_len_bytes, byteorder="little")

# Receive the flag itself
flag = c.recv(flag_len).decode()
print(flag)

# DGHACK{SeemsLike.YoureOnTheRightTrack!}
