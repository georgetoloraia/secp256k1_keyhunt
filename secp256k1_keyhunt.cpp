// secp256k1_keyhunt.cpp with real libsecp256k1 integration

#include <iostream>
#include <fstream>
#include <vector>
#include <set>
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

std::vector<uint64_t> pr_values;
std::set<uint64_t> target_x_coords;
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

void log_found(uint64_t priv_key, uint64_t pub_x) {
    std::lock_guard<std::mutex> lock(file_mutex);
    std::ofstream out("found_keys.txt", std::ios::app);
    out << priv_key << "," << pub_x << "\n";
    out.close();
}

void process_range(int thread_id, int start_idx, int end_idx) {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, UINT64_MAX);

    for (int i = start_idx; i < end_idx; ++i) {
        uint64_t r = dis(gen);
        uint64_t priv = r - pr_values[i];

        for (int offset = 0; offset < 4; ++offset) {
            uint64_t k = priv + offset;
            uint8_t priv_bytes[32], pub_bytes[65];
            int_to_32bytes(k, priv_bytes);
            if (scalar_mult(priv_bytes, pub_bytes)) {
                uint64_t pub_x = 0;
                for (int i = 1; i <= 8; ++i) {
                    pub_x = (pub_x << 8) | pub_bytes[i];
                }
                if (target_x_coords.count(pub_x)) {
                    std::lock_guard<std::mutex> lock(print_mutex);
                    std::cout << "\n[FOUND] Key: " << k << " X: " << pub_x << "\n";
                    log_found(k, pub_x);
                }
            }
        }

        int done = ++processed_count;
        if (done % 10 == 0) {
            std::lock_guard<std::mutex> lock(print_mutex);
            std::cout << "Processed " << done << "/" << pr_values.size() << "\r" << std::flush;
        }
    }
}

int main() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    std::ifstream pr_file("minuses.txt");
    uint64_t val;
    while (pr_file >> val) pr_values.push_back(val);

    std::ifstream pub_file("uncompress.txt");
    while (pub_file >> val) target_x_coords.insert(val);

    int num_threads = std::thread::hardware_concurrency();
    int chunk_size = pr_values.size() / num_threads;

    std::vector<std::thread> threads;
    auto start = std::chrono::steady_clock::now();

    for (int t = 0; t < num_threads; ++t) {
        int start_idx = t * chunk_size;
        int end_idx = (t == num_threads - 1) ? pr_values.size() : start_idx + chunk_size;
        threads.emplace_back(process_range, t, start_idx, end_idx);
    }

    for (auto &th : threads) th.join();

    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "\nCompleted in " << elapsed.count() << " seconds.\n";

    secp256k1_context_destroy(ctx);
    return 0;
}
