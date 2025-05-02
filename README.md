# secp256k1_keyhunt
For test and learn

## ✅ Step-by-step Integration Guide
1. Install libsecp256k1
On Ubuntu/Debian:
```cpp
sudo apt install autoconf libtool pkg-config git build-essential
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-ecmult --enable-module-recovery --enable-experimental
make
sudo make install
```
This installs the static library and headers.

## ✅ Compilation Instructions
```css
g++ secp256k1_keyhunt.cpp -o keyhunt -lsecp256k1 -pthread

or

g++ secp256k1_keyhunt.cpp -lgmp -lgmpxx -lsecp256k1 -pthread -o keyhunt

```

- If you installed `libsecp256k1` to `/usr/local`, add:
```css
g++ secp256k1_keyhunt.cpp -o keyhunt -I/usr/local/include -L/usr/local/lib -lsecp256k1 -pthread
```

- `tail -f found_keys.txt` in another terminal to monitor for hits.

## ✅ Input Files Required
- `minuses.txt` — list of offsets (integers)
- - For generate randomly `minuses` use python code:
```css
python3 gen.py
```
- `uncompress.txt` — set of public key x-coordinates (integers)

## ✅ Output File
- Matches are saved to `found_keys.txt` in format:
```css
<private_key>,<pubkey_x>
```