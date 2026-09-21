# Log of past security issues that have been fixed

- In server.rs start_auth, an implementation bug caused random bytes to be placed in a copy of the challenge instead of the actual challenge, so the actual challenge was always all zeroes
- In listen.rs receive_file_connection, the received file name was not validated so it could be a path such as ../../../.. or ~/.local/bin/bash which could be malicious (now it only takes the last component of the path and rejects . and ..)
- The claimed sender name receiving-side in p2p connections was previously not checked, so an attacker could pretend to be sending a file as someone else (now it verifies using the server's public key entry for that name)

# Unfixed issues

- In almost all dynamic allocations where the allocation size is received from the network, there is no upper bound, so a malicious payload could cause out of memory errors
- Local LAN connections are trusted by default since it might not be possible to access the server to verify peer identities, so its possible to impersonate someone on the same network
