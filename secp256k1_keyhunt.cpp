// secp256k1_keyhunt.cpp with signed support for pr_values and infinite loop

#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <unordered_set>
#include <random>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <cstring>

extern "C" {
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>
}

std::vector<int64_t> pr_values;
std::unordered_set<std::string> target_x_coords;
std::atomic<int> processed_count(0);
std::mutex print_mutex;
std::mutex file_mutex;

secp256k1_context* ctx;

// Convert uint64_t to 32-byte buffer
void int_to_32bytes(uint64_t k, uint8_t out[32]) {
    memset(out, 0, 32);
    for (int i = 0; i < 8; ++i)
        out[31 - i] = (k >> (8 * i)) & 0xFF;
}

// Perform scalar multiplication using libsecp256k1
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

void log_found(uint64_t priv_key, const std::string& pub_x_hex) {
    std::lock_guard<std::mutex> lock(file_mutex);
    std::ofstream out("found_keys.txt", std::ios::app);
    out << priv_key << "," << pub_x_hex << "\n";
    out.close();
}

void process_forever() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, UINT64_MAX);

    while (true) {
        for (int64_t i : pr_values) {
            uint64_t r = dis(gen);
            int64_t priv_signed = static_cast<int64_t>(r) - i;
            if (priv_signed <= 0) continue;
            uint64_t priv = static_cast<uint64_t>(priv_signed);

            for (int offset = 0; offset < 4; ++offset) {
                uint64_t k = priv + offset;
                uint8_t priv_bytes[32], pub_bytes[65];
                int_to_32bytes(k, priv_bytes);
                if (scalar_mult(priv_bytes, pub_bytes)) {
                    std::string pub_x_hex;
                    char buf[3];
                    for (int j = 1; j <= 32; ++j) {
                        snprintf(buf, sizeof(buf), "%02x", pub_bytes[j]);
                        pub_x_hex += buf;
                    }
                    if (target_x_coords.count(pub_x_hex)) {
                        std::lock_guard<std::mutex> lock(print_mutex);
                        std::cout << "\n[FOUND] Key: " << k << " X: " << pub_x_hex << "\n";
                        log_found(k, pub_x_hex);
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

    std::ifstream pr_file("minuses.txt");
    int64_t val;
    while (pr_file >> val) pr_values.push_back(val);

    std::ifstream pub_file("uncompress.txt");
    std::string line;
    while (std::getline(pub_file, line)) {
        if (!line.empty()) target_x_coords.insert(line);
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
