from coincurve import PublicKey
from random import randint

def fast_generate_public_key(priv_key_int):
    priv_bytes = priv_key_int.to_bytes(32, 'big')
    pub = PublicKey.from_valid_secret(priv_bytes)
    pub_point = pub.point()
    # print(type(pub_point[0]))
    return pub_point[0]

def main():
    with open("minuses.txt", "a") as all:
        for i in range(2000000):
            l = randint(1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
            pub = fast_generate_public_key(l)
            add = l - pub
            all.write(f"{add}\n")

if __name__ == "__main__":
    main()