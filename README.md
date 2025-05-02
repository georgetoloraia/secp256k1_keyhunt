# secp256k1_keyhunt
For test and learn

## ✅ Compilation Instructions
```bash
g++ secp256k1_keyhunt.cpp -o keyhunt -lsecp256k1 -pthread
```

- If you installed `libsecp256k1` to `/usr/local`, add:
```bash
g++ secp256k1_keyhunt.cpp -o keyhunt -I/usr/local/include -L/usr/local/lib -lsecp256k1 -pthread
```

## ✅ Input Files Required
- `minuses.txt` — list of offsets (integers)
- - For generate randomly `minuses` use python code:
```bash
python3 gen.py
```
- `uncompress.txt` — set of public key x-coordinates (integers)

## ✅ Output File
- Matches are saved to `found_keys.txt` in format:
```bash
<private_key>,<pubkey_x>
```