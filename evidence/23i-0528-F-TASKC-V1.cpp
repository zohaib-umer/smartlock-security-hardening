// Zohaib Umer | 23i-0528 | CS3002 Assignment 2 | Part C self-check
#include "securelink2.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace sl2;

template<class F> bool raises(F&& fn) {
    try { fn(); return false; } catch (const std::exception&) { return true; }
}
void require(bool condition, const std::string& reason) {
    if (!condition) throw std::runtime_error("FAILED: " + reason);
    std::cout << "[PASS] " << reason << '\n';
}

int main() {
    try {
        auto suites = strong_suites();
        require(std::find(suites.begin(),suites.end(),"NULL") == suites.end() &&
                choose_suite({"NULL"}).empty() &&
                choose_suite({"NULL","AES128-GCM","AES256-GCM"}) == "AES256-GCM" &&
                choose_suite({"AES128-GCM"}) == "AES128-GCM", "strong suite selection / no NULL");

        std::vector<uint8_t> secret(32);
        for (size_t i = 0; i < secret.size(); i++) secret[i] = static_cast<uint8_t>(i + 1);
        auto c2s = derive_key(secret,"AES256-GCM","c2s");
        auto s2c = derive_key(secret,"AES256-GCM","s2c");
        require(c2s.size() == 32 && s2c.size() == 32 && c2s != s2c &&
                c2s != secret && c2s == derive_key(secret,"AES256-GCM","c2s"),
                "HKDF key derivation and direction separation");
        auto key128 = derive_key(secret,"AES128-GCM","c2s");
        require(key128.size() == 16 && raises([&]{ (void) derive_key(secret,"NULL","c2s"); }),
                "AES128 support and unsupported suite rejection");
        require(make_nonce(0).size() == 12 && make_nonce(0) != make_nonce(1) &&
                make_nonce(1) != make_nonce(UINT64_MAX),"unique 12-byte nonces for different sequences");

        auto rec0 = seal(c2s, 0, "STATUS");
        auto rec1 = seal(c2s, 1, "UNLOCK");
        require(open_record(c2s,rec0,0) == "STATUS" &&
                open_record(c2s,rec1,1) == "UNLOCK", "AES256-GCM seal/open round trip");
        require(open_record(key128,seal(key128,3,"LOCK"),3) == "LOCK",
                "AES128-GCM seal/open round trip");
        require(raises([&] { (void)open_record(c2s,rec0,1); }) &&
                raises([&] { (void)open_record(c2s,rec1,0); }),
                "replay and out-of-order sequences rejected");
        auto bad = rec1;
        bad[8] ^= 0x01;
        require(raises([&] { (void)open_record(c2s,bad,1); }),
                "tampered ciphertext rejected");
        auto bad_tag = rec1;
        bad_tag.back() ^= 0x01;
        require(raises([&] { (void)open_record(c2s,bad_tag,1); }),
                "tampered authentication tag rejected");
        auto bad_seq = rec1;
        bad_seq[7] ^= 0x01;
        require(raises([&] { (void)open_record(c2s,bad_seq,1); }),
                "altered sequence header rejected");
        require(raises([&] { (void)open_record(c2s,{},0); }),
                "truncated records rejected");
        std::cout << "ALL PART C CORE TESTS PASSED\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr << e.what() << '\n'; return 1;
    }
}
