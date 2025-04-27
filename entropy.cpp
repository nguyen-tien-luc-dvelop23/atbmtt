#include <iostream>
#include <vector>
#include <iomanip>
#include <string>
#include <cmath>
#include <fstream>
using namespace std;

// Ð?nh nghia ki?u khóa t?ng quát (64 bit d? h? tr? t?t c? tru?ng h?p)
typedef unsigned long long Key;
const int BLOCK_SIZE = 2;

// C?u trúc Config ? ph?m vi toàn c?c
struct Config {
    string name;
    int key_size;
    int num_rounds;
    bool use_f2;
    Key key;
};

// Hàm xoay trái và xoay ph?i v?i c?t b?t bit
Key rol(Key x, int n, int key_size) {
    n = n % key_size;
    x &= (1ULL << key_size) - 1; // C?t b?t bit ngoài key_size
    return ((x << n) | (x >> (key_size - n))) & ((1ULL << key_size) - 1);
}

Key ror(Key x, int n, int key_size) {
    n = n % key_size;
    x &= (1ULL << key_size) - 1; // C?t b?t bit ngoài key_size
    return ((x >> n) | (x << (key_size - n))) & ((1ULL << key_size) - 1);
}

// Hàm F1: Ch? XOR (cho Q1-Q3)
int feistel_function_f1(int R, int K) {
    return R ^ K;
}

// Hàm F2: XOR, xoay trái 2 bit, S-box chu?n (cho Q4)
int feistel_function_f2(int R, int K) {
    int result = R ^ K;
    result = rol(result, 2, 16);
    // S-box chu?n (l?y t? DES S1)
    static const unsigned char sbox[64] = {
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    };
    // Áp d?ng S-box cho 6 bit (gi? s? 16 bit chia thành 4 kh?i 4-bit)
    result = (sbox[(result >> 12) & 0x3F] << 12) | (sbox[(result >> 8) & 0x3F] << 8) |
             (sbox[(result >> 4) & 0x3F] << 4) | sbox[result & 0x3F];
    return result;
}

// Sinh khóa con
vector<Key> generate_round_keys(Key main_key, int num_rounds, int key_size, bool use_f2) {
    vector<Key> keys;
    main_key &= (1ULL << key_size) - 1; // C?t b?t bit ngoài key_size
    if (use_f2) {
        for (int i = 0; i < num_rounds; ++i) {
            keys.push_back(ror(main_key, i, key_size) ^ rol(main_key, i % 8, key_size));
        }
    } else {
        for (int i = 0; i < num_rounds; ++i) {
            keys.push_back((main_key >> i) ^ (main_key << (i % 3)));
        }
    }
    return keys;
}

// Mã hóa m?t kh?i 16 bit
unsigned short feistel_encrypt_block(unsigned short plaintext, const vector<Key>& round_keys, bool use_f2) {
    unsigned char L = plaintext >> 8;
    unsigned char R = plaintext & 0xFF;
    for (int i = 0; i < round_keys.size(); ++i) {
        int f_result = use_f2 ? feistel_function_f2(R, round_keys[i]) : feistel_function_f1(R, round_keys[i]);
        unsigned char new_R = L ^ f_result;
        L = R;
        R = new_R;
    }
    return (L << 8) | R;
}

// Chuy?n byte thành kh?i 16 bit
vector<unsigned short> bytes_to_blocks(const vector<unsigned char>& data) {
    vector<unsigned short> blocks;
    for (size_t i = 0; i < data.size(); i += 2) {
        unsigned short block = (data[i] << 8) | (i + 1 < data.size() ? data[i + 1] : 0);
        blocks.push_back(block);
    }
    return blocks;
}

// Chuy?n kh?i 16 bit thành byte
vector<unsigned char> blocks_to_bytes(const vector<unsigned short>& blocks) {
    vector<unsigned char> data;
    for (size_t i = 0; i < blocks.size(); ++i) {
        data.push_back(blocks[i] >> 8);
        data.push_back(blocks[i] & 0xFF);
    }
    return data;
}

// Mã hóa toàn b? tin nh?n
vector<unsigned char> encrypt_message(const string& message, Key key, int num_rounds, int key_size, bool use_f2, const string& config_name) {
    vector<unsigned char> input(message.begin(), message.end());
    if (input.size() % 2 != 0) {
        input.push_back(0x00);
    }
    vector<unsigned short> blocks = bytes_to_blocks(input);
    vector<unsigned short> encrypted_blocks;
    vector<Key> round_keys = generate_round_keys(key, num_rounds, key_size, use_f2);
    cout << "Config: " << config_name << ", Round keys: ";
    for (size_t i = 0; i < round_keys.size(); ++i) {
        cout << hex << round_keys[i] << " ";
    }
    cout << dec << "\n";
    for (size_t i = 0; i < blocks.size(); ++i) {
        encrypted_blocks.push_back(feistel_encrypt_block(blocks[i], round_keys, use_f2));
    }
    vector<unsigned char> encrypted = blocks_to_bytes(encrypted_blocks);
    cout << "Ciphertext (hex): ";
    for (size_t i = 0; i < encrypted.size(); ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(encrypted[i]) << " ";
    }
    cout << dec << "\n";
    return encrypted;
}

// Tính entropy
double calculate_entropy(const vector<unsigned char>& data) {
    vector<int> freq(256, 0);
    for (size_t i = 0; i < data.size(); ++i) {
        freq[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / data.size();
            entropy -= p * log(p) / log(2.0);
        }
    }
    return entropy;
}

// Main function
int main() {
    cout << "===== Feistel Cipher Entropy Calculation =====\n";
    
    // B?n rõ c? d?nh
    string plaintext = "nguyentienluc";
    cout << "Plaintext: " << plaintext << ", length: " << plaintext.size() << " bytes\n";

    Key base_key = 0x170D98AA; // Khóa 32 bit
    Key key_16 = 0x98AA; // 16 bit th?p
    Key key_64 = (base_key << 32) | base_key; // L?p l?i cho 64 bit

    // Kh?i t?o danh sách c?u hình
    vector<Config> configs;
    Config cfg;

    cfg.name = "k=16"; cfg.key_size = 16; cfg.num_rounds = 4; cfg.use_f2 = true; cfg.key = key_16;
    configs.push_back(cfg);
    cfg.name = "k=32"; cfg.key_size = 32; cfg.num_rounds = 4; cfg.use_f2 = true; cfg.key = base_key;
    configs.push_back(cfg);
    cfg.name = "k=64"; cfg.key_size = 64; cfg.num_rounds = 4; cfg.use_f2 = true; cfg.key = key_64;
    configs.push_back(cfg);
    cfg.name = "rounds=2"; cfg.key_size = 16; cfg.num_rounds = 2; cfg.use_f2 = true; cfg.key = key_16;
    configs.push_back(cfg);
    cfg.name = "rounds=4"; cfg.key_size = 16; cfg.num_rounds = 4; cfg.use_f2 = true; cfg.key = key_16;
    configs.push_back(cfg);
    cfg.name = "rounds=8"; cfg.key_size = 16; cfg.num_rounds = 8; cfg.use_f2 = true; cfg.key = key_16;
    configs.push_back(cfg);
    cfg.name = "rounds=16"; cfg.key_size = 16; cfg.num_rounds = 16; cfg.use_f2 = true; cfg.key = key_16;
    configs.push_back(cfg);
    cfg.name = "Hàm F1"; cfg.key_size = 32; cfg.num_rounds = 4; cfg.use_f2 = false; cfg.key = base_key;
    configs.push_back(cfg);
    cfg.name = "Hàm F2"; cfg.key_size = 32; cfg.num_rounds = 4; cfg.use_f2 = true; cfg.key = base_key;
    configs.push_back(cfg);

    // Luu k?t qu? entropy
    vector<double> entropies(configs.size(), 0.0);

    // Ch?y th? nghi?m
    for (size_t i = 0; i < configs.size(); ++i) {
        cout << "\nRunning config: " << configs[i].name << "\n";
        vector<unsigned char> encrypted = encrypt_message(plaintext, configs[i].key, configs[i].num_rounds, configs[i].key_size, configs[i].use_f2, configs[i].name);
        entropies[i] = calculate_entropy(encrypted);
        cout << "Entropy: " << fixed << setprecision(2) << entropies[i] << " bits\n";
    }

    // In b?ng k?t qu?
    cout << "\nGHI NH?N K?T QU? TH? NGHI?M MÃ KH?I FEISTEL\n";
    cout << "| k=16 | k=32 | k=64 | rounds=2 | rounds=4 | rounds=8 | rounds=16 | Hàm F1 | Hàm F2 |\n";
    cout << "|------|------|------|----------|----------|----------|-----------|--------|--------|\n";
    cout << "|";
    for (size_t i = 0; i < entropies.size(); ++i) {
        cout << " " << fixed << setprecision(2) << entropies[i] << " |";
    }
    cout << "\n";

    // Luu vào file CSV
    ofstream csv_file("experiment_NguyenTienLuc.csv");
    csv_file << "k=16,k=32,k=64,rounds=2,rounds=4,rounds=8,rounds=16,Hàm F1,Hàm F2\n";
    for (size_t i = 0; i < entropies.size(); ++i) {
        csv_file << fixed << setprecision(2) << entropies[i];
        if (i < entropies.size() - 1) csv_file << ",";
    }
    csv_file << "\n";
    csv_file.close();
    cout << "\nK?t qu? dã du?c luu vào experiment_NguyenTienLuc.csv\n";

    return 0;
}
