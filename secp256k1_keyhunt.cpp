// secp256k1_keyhunt.cpp using GMP with r - pr[i] logic and full 256-bit key support

#include <iostream>
#include <fstream>
#include <unordered_set>
#include <vector>
#include <random>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <gmpxx.h>

extern "C" {
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
}

std::unordered_set<std::string> target_x_coords;
std::vector<mpz_class> pr_values;
std::atomic<int> processed_count(0);
std::mutex print_mutex;
std::mutex file_mutex;

secp256k1_context* ctx;

void mpz_to_32bytes(const mpz_class& k, uint8_t out[32]) {
    std::string hex = k.get_str(16);
    while (hex.length() < 64) hex = "0" + hex;
    for (int i = 0; i < 32; ++i) {
        std::string byte_str = hex.substr(i * 2, 2);
        out[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
    }
}

bool scalar_mult(uint8_t privkey[32], uint8_t pubkey[65]) {
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, privkey)) {
        return false;
    }
    size_t output_length = 65;
    return secp256k1_ec_pubkey_serialize(
        ctx, pubkey, &output_length, &pub, SECP256K1_EC_UNCOMPRESSED
    );
}

void log_found(const mpz_class& priv_key, const std::string& pub_x_hex) {
    std::lock_guard<std::mutex> lock(file_mutex);
    std::ofstream out("found_keys.txt", std::ios::app);
    out << priv_key.get_str(10) << "," << pub_x_hex << "\n";
    out.close();
}

void process_forever() {
    gmp_randclass rng(gmp_randinit_default);
    rng.seed(static_cast<unsigned long>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));

    const mpz_class max_key("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0);

    while (true) {
        mpz_class r = rng.get_z_range(max_key);

        for (const auto& delta : pr_values) {
            mpz_class priv_key = r - delta;
            if (priv_key <= 0 || priv_key >= max_key) continue;

            for (int offset = 0; offset < 4; ++offset) {
                // mpz_class candidate = priv_key + offset;
                mpz_class candidate = (priv_key + offset) % max_key;
                if (candidate >= max_key) break;

                uint8_t priv_bytes[32], pub_bytes[65];
                mpz_to_32bytes(candidate, priv_bytes);

                if (scalar_mult(priv_bytes, pub_bytes)) {
                    std::string pub_x_hex;
                    char buf[3];
                    for (int j = 1; j <= 32; ++j) {
                        snprintf(buf, sizeof(buf), "%02x", pub_bytes[j]);
                        pub_x_hex += buf;
                    }
                    if (target_x_coords.count(pub_x_hex)) {
                        std::lock_guard<std::mutex> lock(print_mutex);
                        std::cout << "\n[FOUND] Key: " << candidate.get_str(10) << " X: " << pub_x_hex << "\n";
                        log_found(candidate, pub_x_hex);
                    }
                }

                int done = ++processed_count;
                if (done % 100 == 0) {
                    std::lock_guard<std::mutex> lock(print_mutex);
                    std::cout << "Processed " << done << "\r" << std::flush;
                }
            }
        }
    }
}

int main() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    std::ifstream pub_file("uncompress.txt");
    std::string line;
    while (std::getline(pub_file, line)) {
        if (!line.empty()) target_x_coords.insert(line);
    }

    std::ifstream pr_file("minuses.txt");
    while (std::getline(pr_file, line)) {
        if (!line.empty()) pr_values.emplace_back(line);
    }

    int num_threads = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;

    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back(process_forever);
    }

    for (auto &th : threads) th.join();

    secp256k1_context_destroy(ctx);
    return 0;
}
