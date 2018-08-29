#include <iostream>
#include <sparsepp/spp.h>
#include <cryptocpp/hex.h>
#include "hash/sph_sha2.h"
#include "hash/sph_keccak.h"
#include "hash/sph_haval.h"
#include "hash/sph_tiger.h"
#include "hash/sph_whirlpool.h"
#include "hash/sph_ripemd.h"
#include "gmp/gmp.h"
#include "utils.h"
#include "base58.h"

#if !(defined(IS_BIG_ENDIAN) || defined(IS_LITTLE_ENDIAN))
    #if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || \
    (defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN) || \
    defined(__BIG_ENDIAN__) || defined(__ARMEB__) || \
    defined(__THUMBEB__) || defined(__AARCH64EB__) || \
    defined(_MIBSEB) || defined(__MIBSEB) || defined(__MIBSEB__)
        #define IS_BIG_ENDIAN
    #elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || \
    (defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN) || \
    defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || \
    defined(__THUMBEL__) || defined(__AARCH64EL__) || \
    defined(_MIPSEL) || defined(__MIPSEL) || defined(__MIPSEL__)
        #define IS_LITTLE_ENDIAN
    #else
        #error "Cannot determine platform endianness"
    #endif
#endif

#if defined(IS_BIG_ENDIAN)
    #error "System must be little endian!"
#endif

#define HEADER_SIZE 122

spp::sparse_hash_map<std::string, BlockData*> block_hash_map;
spp::sparse_hash_map<std::string, uint64_t> accnt_hash_map;

uint64_t max_out = uint64_t(1800000000) * uint64_t(10000000000);

inline void error_exit(const char* error_txt, uint64_t fail_height)
{
    std::cout << error_txt << "\nBlock height: " << fail_height << std::endl;
    exit(EXIT_FAILURE);
}

inline void mpz_set_uint512(mpz_t r, uint512& u)
{
    mpz_import(r, 64 / sizeof(unsigned long), -1, sizeof(unsigned long), -1, 0, u.data);
}

inline std::string hash160toaddress(const std::string& hash160)
{
    std::string ext_hash160 = std::string(1, 0x1C) + hash160;
    Blob256 sha_hash(SHA_256::HashX2((const byte*)ext_hash160.c_str(), ext_hash160.size()));
    return ext_hash160 + std::string(sha_hash.Bytes(), 4);
}

inline std::string hash160tobase58(const std::string& hash160)
{
    char base58_addr[40];
    size_t addr_len = 40;
    std::string full_addr(hash160toaddress(hash160));
    Base58::Encode(base58_addr, addr_len, full_addr.c_str(), full_addr.size());
    return std::string(base58_addr, addr_len);
}

inline void parse_txns(char* txn_bytes, std::vector<CTransaction>& txn_sink)
{
    size_t txn_count = ReadVarInt(txn_bytes);

    for (size_t t=0; t < txn_count; ++t)
    {
        CTransaction txn;
        txn.nVersion = ReadInt32(txn_bytes);

        size_t inp_cnt = ReadVarInt(txn_bytes);
        for (size_t i=0; i < inp_cnt; ++i)
        {
            CTxIn input;
            input.pubKey = ReadHexStr(txn_bytes, 20);
            input.nValue = ReadUInt64(txn_bytes);
            input.scriptSig = ReadString(txn_bytes);
            txn.vin.push_back(input);
        }

        size_t out_cnt = ReadVarInt(txn_bytes);
        for (size_t o=0; o < out_cnt; ++o)
        {
            CTxOut output;
            output.nValue = ReadUInt64(txn_bytes);
            output.pubKey = ReadHexStr(txn_bytes, 20);
            txn.vout.push_back(output);
        }

        txn.msg = ReadString(txn_bytes);
        txn.nLockHeight = ReadUInt64(txn_bytes);

        txn_sink.push_back(txn);
    }
}

inline uint256 hash_header(const void* hdr_bytes, size_t hdr_size)
{
    sph_sha256_context       ctx_sha256;
    sph_sha512_context       ctx_sha512;
    sph_keccak512_context    ctx_keccak;
    sph_whirlpool_context    ctx_whirlpool;
    sph_haval256_5_context   ctx_haval;
    sph_tiger_context        ctx_tiger;
    sph_ripemd160_context    ctx_ripemd;

    uint512 hash[7];
    uint256 finalhash;

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, hdr_bytes, hdr_size);
    sph_sha256_close(&ctx_sha256, &hash[0]);

    sph_sha512_init(&ctx_sha512);
    sph_sha512(&ctx_sha512, hdr_bytes, hdr_size);
    sph_sha512_close(&ctx_sha512, &hash[1]);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, hdr_bytes, hdr_size);
    sph_keccak512_close(&ctx_keccak, &hash[2]);

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, hdr_bytes, hdr_size);
    sph_whirlpool_close(&ctx_whirlpool, &hash[3]);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5(&ctx_haval, hdr_bytes, hdr_size);
    sph_haval256_5_close(&ctx_haval, &hash[4]);

    sph_tiger_init(&ctx_tiger);
    sph_tiger(&ctx_tiger, hdr_bytes, hdr_size);
    sph_tiger_close(&ctx_tiger, &hash[5]);

    sph_ripemd160_init(&ctx_ripemd);
    sph_ripemd160(&ctx_ripemd, hdr_bytes, hdr_size);
    sph_ripemd160_close(&ctx_ripemd, &hash[6]);

    mpz_t bns[7];

    for (int i=0; i < 7; i++)
    {
        /*bool all_zeros = true;

        for (int b=0; b < 64; ++b) {
            if (hash[i].data[b] != 0) {
                all_zeros = false;
                break;
            }
        }

        if (all_zeros) hash[i].data[63] = 1;*/

        mpz_init(bns[i]);
        mpz_set_uint512(bns[i], hash[i]);
    }

    mpz_t product;
    mpz_init(product);
    mpz_set_ui(product, 1);

    for (int i=0; i < 7; i++) {
        mpz_mul(product, product, bns[i]);
    }

    int bytes = mpz_sizeinbase(product, 256);
    char *data = (char*)malloc(bytes);
    mpz_export(data, NULL, -1, 1, 0, 0, product);

    for (int i=0; i < 7; i++) {
        mpz_clear(bns[i]);
    }
    mpz_clear(product);

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, data,bytes);
    sph_sha256_close(&ctx_sha256, &finalhash);

    free(data);
    return finalhash;
}

std::string read_block_files(std::string block_folder)
{
    uint32_t magic_bytes = 0xd9b4bef9;
    uint32_t bfile_num = 0;
    uint32_t block_size = 0;
    uint64_t block_count = 0;
    std::string block_hash;

    while (true)
    {
        std::stringstream ss;
        ss << bfile_num++;
        std::string int_str(5-ss.str().size(), '0');
        int_str.append(ss.str());

        std::string file_name = block_folder+"/blk"+int_str+".dat";
        FILE* pFile = fopen(file_name.c_str(), "rb");
        fseek(pFile, 0, SEEK_SET);

        if (pFile != NULL) {

            std::cout << "Reading " << file_name << std::endl;

            while (true)
            {
                bool magic_found = false;
                uint32_t magic_bbuff = 0;

                //scan file for magic bytes
                while (fread(&magic_bbuff, 1, 4, pFile) == 4)
                {
                    if (magic_bbuff == magic_bytes) {
                        magic_found = true;
                        ++block_count;
                        break;
                    } else {
                        fseek(pFile, -3, SEEK_CUR);
                    }
                }

                //no more magic, probably at end of file
                if (!magic_found) { break; }

                //get block size and read data into buffer
                fread(&block_size, 1, 4, pFile);
                BlockData* block_data = new BlockData();
                block_data->bytes = new char[block_size];
                char* block_buff = block_data->bytes;
                fread(block_buff, 1, block_size, pFile);

                BBUInt16 verNumber(&(block_buff[0]));
                BBUInt64 timeStamp(&(block_buff[98]));
                BBUInt64 blkHeight(&(block_buff[106]));
                BBUInt64 randNonce(&(block_buff[114]));

                CBlockHeader& block_hdr = block_data->header;
                block_hdr.hashPrevBlock.Set(&(block_buff[2]));
                block_hdr.hashMerkleRoot.Set(&(block_buff[34]));
                block_hdr.hashAccountRoot.Set(&(block_buff[66]));
                block_hdr.nTime = timeStamp.value;
                block_hdr.nHeight = blkHeight.value;
                block_hdr.nNonce = randNonce.value;
                block_hdr.nVersion = verNumber.value;

                uint256 hash_bytes(hash_header(block_hdr.hashPrevBlock.data, HEADER_SIZE));
                block_hash.assign(hash_bytes.data, 32);
                block_hash_map[block_hash] = block_data;
            }

        } else {
            if (bfile_num == 1) {
                std::cout << "Error: no block files found in " << block_folder << std::endl;
                exit(EXIT_FAILURE);
            }
            break;
        }
    }

    std::cout << "Blocks processed: " + IntToStr(block_count) << std::endl;

    return block_hash;
}

std::vector<BlockData*> build_chain_links(const std::string& last_hash)
{
    std::cout << "Building chain links ..." << std::endl;
    std::vector<BlockData*> chain_links;
    BlockData* last_block = block_hash_map[last_hash];
    std::string zero_str32(32, 0);
    uint64_t block_count = 0;

    while (true)
    {
        ++block_count;
        std::string prev_hash(last_block->header.hashPrevBlock.data, 32);
        chain_links.push_back(last_block);
        if (prev_hash == zero_str32) break;
        last_block = block_hash_map[prev_hash];
    }

    std::cout << "Blocks linked: " << block_count << std::endl;
    std::reverse(chain_links.begin(), chain_links.end());
    return chain_links;
}

bool validate_blockchain(std::vector<BlockData*>& block_chain)
{
    std::cout << "Analyzing blockchain ..." << std::endl;
    std::string zero_str20(20, 0);
    uint64_t block_count = 0;
    uint64_t last_reward = 2431000000000;
    CryptoPP::Integer coins_hacked(0L);
    CryptoPP::Integer rewards_hacked(0L);

    accnt_hash_map[zero_str20] =
        uint64_t(1844674407) * uint64_t(10000000000);

    for (size_t i=1; i < block_chain.size(); ++i)
    {
        ++block_count;
        BlockData& block_data = *(block_chain[i]);
        CBlock block(block_data.header);
        std::string prev_hash(block.hashPrevBlock.data, 32);

        if (block.nHeight != i) {
            std::stringstream ss;
            ss << "Error: invalid block height (" << i << ")";
            error_exit(ss.str().c_str(), block.nHeight);
        }

        parse_txns(&(block_data.bytes[HEADER_SIZE]), block.vtx);

        CTransaction& cb_txn = block.vtx[0];
        if (cb_txn.vin.size() != 1) {
            error_exit("Error: cb_txn.vin.size() != 1", block.nHeight);
        } else if (cb_txn.vout.size() != 1) {
            error_exit("Error: cb_txn.vout.size() != 1", block.nHeight);
        }

        CTxIn& cb_in = cb_txn.vin[0];
        CTxOut& cb_out = cb_txn.vout[0];

        if (cb_in.pubKey != zero_str20) {
            error_exit("Error: invalid cb pubkey", block.nHeight);
        } else if (cb_in.nValue > uint64_t(2500000000000)) {
            std::cout << "Reward error at height: " << block.nHeight << std::endl;
            uint64_t reward_hacked = cb_in.nValue - last_reward;
            rewards_hacked += CryptoPP::Integer((byte*)&reward_hacked, 8,
                CryptoPP::Integer::UNSIGNED, CryptoPP::ByteOrder::LITTLE_ENDIAN_ORDER);
        } else {
            last_reward = cb_in.nValue;
        }

        for (CTransaction& txn : block.vtx)
        {
            if (txn.vin.size()==1 && txn.vout.size()==1 && txn.vin[0].pubKey ==
            txn.vout[0].pubKey && txn.vout[0].nValue < txn.vin[0].nValue) {

                if (accnt_hash_map.contains(txn.vout[0].pubKey)) {
                    txn.nLimitValue = txn.vout[0].nValue;
                    txn.fSetLimit = true;
                    txn.vout[0].nValue = 0;
                    txn.vin[0].nValue -= txn.nLimitValue;
                    if (txn.vin[0].nValue > accnt_hash_map[txn.vout[0].pubKey]) {
                        error_exit("Error: unpayable limit fee", block.nHeight);
                    } else {
                        accnt_hash_map[txn.vout[0].pubKey] -= txn.vin[0].nValue;
                    }
                    if (accnt_hash_map.contains(cb_out.pubKey)) {
                        accnt_hash_map[cb_out.pubKey] += txn.vin[0].nValue;
                    } else {
                        accnt_hash_map[cb_out.pubKey] = txn.vin[0].nValue;
                    }
                } else {
                    error_exit("Error: invalid limit update", block.nHeight);
                }

            } else {

                uint64_t in_total = 0;
                uint64_t out_total = 0;

                for (const CTxIn& input : txn.vin)
                {
                    in_total += input.nValue;

                    if (accnt_hash_map.contains(input.pubKey)) {
                        uint64_t balance = accnt_hash_map[input.pubKey];
                        if (balance < input.nValue) {
                            error_exit("Error: insufficient balance found", block.nHeight);
                        }
                        accnt_hash_map[input.pubKey] = balance - input.nValue;
                    } else {
                        error_exit("Error: empty input address", block.nHeight);
                    }
                }

                for (const CTxOut& output : txn.vout)
                {
                    out_total += output.nValue;

                    if (output.nValue > in_total && output.nValue <= max_out) {
                            coins_hacked += CryptoPP::Integer((byte*)&output.nValue, 8,
                                CryptoPP::Integer::UNSIGNED, CryptoPP::ByteOrder::LITTLE_ENDIAN_ORDER);
                    }
                    if (accnt_hash_map.contains(output.pubKey)) {
                        accnt_hash_map[output.pubKey] += output.nValue;
                    } else {
                        accnt_hash_map[output.pubKey] = output.nValue;
                    }
                }

                if (in_total > out_total) {
                    accnt_hash_map[cb_out.pubKey] += in_total - out_total;
                }
            }
        }
    }

    std::cout << "coins hacked (64bit value): " << coins_hacked << std::endl;
    std::cout << "rewards hacked (64bit value): " << rewards_hacked << std::endl;
    return true;
}

int main(int argc, char *argv[])
{
    std::cout << "Starting ..." << std::endl;
    std::string data_dir;

    if (argc == 2) {
        data_dir.assign(argv[1]);
        TrimStrEnd(data_dir, "/\\");
    } else {
        std::cout << "Block folder not specified!" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string last_hash = read_block_files(data_dir+"/blocks");
    std::vector<BlockData*> block_chain(build_chain_links(last_hash));
    validate_blockchain(block_chain);

    return EXIT_SUCCESS;
}
