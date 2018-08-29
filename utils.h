#pragma once
#include <cstdlib>
#include <string>
#include <sstream>
#include <cmath>
#include <cstdio>
#include "cryptocpp/sha.h"

struct BBInt8 {
    union {
        int8_t value;
        char byte;
    };

    BBInt8(char input)
    {
        byte = input;
    }
};

struct BBUInt8 {
    union {
        uint8_t value;
        char byte;
    };

    BBUInt8(char input)
    {
        byte = input;
    }
};

struct BBInt16 {
    union {
        int16_t value;
        char byte[2];
    };

    BBInt16(char* input)
    {
        byte[0] = input[0];
        byte[1] = input[1];
    }
};

struct BBUInt16 {
    union {
        uint16_t value;
        char byte[2];
    };

    BBUInt16(char* input)
    {
        byte[0] = input[0];
        byte[1] = input[1];
    }
};

struct BBInt32 {
    union {
        int32_t value;
        char byte[4];
    };

    BBInt32(char* input)
    {
        byte[0] = input[0];
        byte[1] = input[1];
        byte[2] = input[2];
        byte[3] = input[3];
    }
};

struct BBUInt32 {
    union {
        uint32_t value;
        char byte[4];
    };

    BBUInt32(char* input)
    {
        byte[0] = input[0];
        byte[1] = input[1];
        byte[2] = input[2];
        byte[3] = input[3];
    }
};

struct BBInt64 {
    union {
        int64_t value;
        char byte[8];
    };

    BBInt64(char* input)
    {
        byte[0] = input[0];
        byte[1] = input[1];
        byte[2] = input[2];
        byte[3] = input[3];
        byte[4] = input[4];
        byte[5] = input[5];
        byte[6] = input[6];
        byte[7] = input[7];
    }
};

struct BBUInt64 {
    union {
        uint64_t value;
        char byte[8];
    };

    BBUInt64(char* input)
    {
        byte[0] = input[0];
        byte[1] = input[1];
        byte[2] = input[2];
        byte[3] = input[3];
        byte[4] = input[4];
        byte[5] = input[5];
        byte[6] = input[6];
        byte[7] = input[7];
    }
};

struct uint512
{
    char data[64];

    uint512()
    {
        memset(data, 0, 64);
    }

    uint512(const char* src)
    {
        memcpy(data, src, 64);
    }

    void Set(const char* src)
    {
        memcpy(data, src, 64);
    }
};

struct uint256
{
    char data[32];

    uint256()
    {
        memset(data, 0, 32);
    }

    uint256(const char* src)
    {
        memcpy(data, src, 32);
    }

    void Set(const char* src)
    {
        memcpy(data, src, 32);
    }
};

struct uint160
{
    char data[20];

    uint160()
    {
        memset(data, 0, 20);
    }

    uint160(const char* src)
    {
        memcpy(data, src, 20);
    }

    void Set(const char* src)
    {
        memcpy(data, src, 20);
    }

    inline int Compare(const uint160& other)
    {
        return memcmp(data, other.data, 20);
    }
};

inline size_t ReadVarInt(char*& bytes)
{
    uint8_t first_byte = ((uint8_t*)bytes)[0];

    if (first_byte < 0xfd) {
        ++bytes;
        return first_byte;
    } else if (first_byte == 0xfd) {
        BBUInt16 result(&(bytes[1]));
        bytes += 3;
        return result.value;
    } else if (first_byte == 0xfe) {
        BBUInt32 result(&(bytes[1]));
        bytes += 5;
        return result.value;
    } else {
        BBUInt64 result(&(bytes[1]));
        bytes += 9;
        return result.value;
    }
}

inline std::string ReadString(char*& bytes)
{
    size_t str_len = ReadVarInt(bytes);
    std::string result(bytes, str_len);
    bytes = &(bytes[str_len-1]); ++bytes;
    return result;
}

inline std::string ReadHexStr(char*& bytes, int count)
{
    std::string result(bytes, count);
    bytes = &(bytes[count-1]); ++bytes;
    return result;
}

inline uint16_t ReadUInt16(char*& bytes)
{
    BBUInt16 result(&(bytes[0]));
    bytes += 2;
    return result.value;
}

inline uint32_t ReadUInt32(char*& bytes)
{
    BBUInt32 result(&(bytes[0]));
    bytes += 4;
    return result.value;
}

inline uint64_t ReadUInt64(char*& bytes)
{
    BBUInt64 result(&(bytes[0]));
    bytes += 8;
    return result.value;
}

inline int16_t ReadInt16(char*& bytes)
{
    BBInt16 result(&(bytes[0]));
    bytes += 2;
    return result.value;
}

inline int32_t ReadInt32(char*& bytes)
{
    BBInt32 result(&(bytes[0]));
    bytes += 4;
    return result.value;
}

inline int64_t ReadInt64(char*& bytes)
{
    BBInt64 result(&(bytes[0]));
    bytes += 8;
    return result.value;
}

inline void TrimStrEnd(std::string& str, const std::string chrs="")
{
    if (chrs.empty()) {
        str.erase(std::find_if(str.rbegin(), str.rend(), [](int ch) {
            return !std::isspace(ch);
        }).base(), str.end());
    } else {
        size_t lastPos = str.size() - 1;
        for (const char& chr : chrs)
        {
            if (str[lastPos] == chr) {
                str.resize(lastPos);
                return;
            }
        }
    }
}

inline std::string IntToStr(int number)
{
	std::ostringstream s;
	s << number;
	return s.str();
}

inline std::string FltToStr(float number)
{
	std::ostringstream s;
	s << std::fixed << number;
	return s.str();
}

inline std::string DblToStr(double number)
{
	std::ostringstream s;
	s << number;
	return s.str();
}

inline std::string LngToStr(long number)
{
	std::ostringstream s;
	s << std::fixed << number;
	return s.str();
}

inline std::wstring StrToWstr(std::string str)
{
	return std::wstring(str.begin(), str.end());
}

inline std::wstring IntToWstr(int number)
{
	return StrToWstr(IntToStr(number));
}

template<unsigned int BITS>
class BaseBlob {
protected:

    enum { WIDTH=BITS/8 };
    byte _data[WIDTH];

public:

    BaseBlob() { SetNull(); }

    BaseBlob(const char* bytes) { Copy(bytes); }

    BaseBlob(const byte* bytes) { Copy(bytes); }

    void Copy(const byte* bytes)
    {
        memcpy(_data, bytes, WIDTH);
    }

    void Copy(const char* bytes)
    {
        memcpy(_data, bytes, WIDTH);
    }

    void SetNull()
    {
        memset(_data, 0, WIDTH);
    }

    byte Byte(uint32_t index) const
    {
        return _data[index];
    }

    const char* Bytes() const
    {
        return (const char*)&(_data[0]);
    }

    const byte* RawBytes() const
    {
        return &(_data[0]);
    }

    std::string RawString() const
    {
        return std::string((char*)&(_data[0]), WIDTH);
    }

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++) {
            if (_data[i] != 0) return false;
        }

        return true;
    }

    inline int Compare(const BaseBlob& other) const { return memcmp(_data, other._data, WIDTH); }
    void operator=(const BaseBlob& other) { memcpy(_data, other._data, WIDTH); }
    bool operator==(const BaseBlob& other) { return Compare(other) == 0; }
    bool operator!=(const BaseBlob& other) { return Compare(other) != 0; }
    bool operator<(const BaseBlob& other) { return Compare(other) < 0; }
    bool operator>(const BaseBlob& other) { return Compare(other) > 0; }

    BaseBlob operator^(const BaseBlob& other)
    {
        BaseBlob<BITS> result;

        std::transform(std::begin(_data), std::end(_data),
            std::begin(other._data), std::begin(result._data),
            std::bit_xor<byte>());

        return result;
    }

    BaseBlob operator|(const BaseBlob& other)
    {
        BaseBlob<BITS> result;

        std::transform(std::begin(_data), std::end(_data),
            std::begin(other._data), std::begin(result._data),
            std::bit_or<byte>());

        return result;
    }

    BaseBlob operator&(const BaseBlob& other)
    {
        BaseBlob<BITS> result;

        std::transform(std::begin(_data), std::end(_data),
            std::begin(other._data), std::begin(result._data),
            std::bit_and<byte>());

        return result;
    }
};

class SHA_256;

class Blob512 : public BaseBlob<512> {
public:
    Blob512() {}
    Blob512(const char* bytes) : BaseBlob<512>(bytes) {}
    Blob512(const byte* bytes) : BaseBlob<512>(bytes) {}
    Blob512(const BaseBlob<512>& b) : BaseBlob<512>(b) {}
};

class Blob256 : public BaseBlob<256> {
friend SHA_256;
public:
    Blob256() {}
    Blob256(const char* bytes) : BaseBlob<256>(bytes) {}
    Blob256(const byte* bytes) : BaseBlob<256>(bytes) {}
    Blob256(const BaseBlob<256>& b) : BaseBlob<256>(b) {}
};

class SHA_256 {
public:

    static inline Blob256 Hash(const byte* data, uint32_t size)
    {
        Blob256 result;
        CryptoPP::SHA256 hash;
        hash.CalculateDigest(result._data, data, size);
        return result;
    }

    static inline Blob256 Hash(const std::string& data)
    {
        Blob256 result;
        CryptoPP::SHA256 hash;
        hash.CalculateDigest(result._data, (byte*)data.c_str(), data.size());
        return result;
    }

    static inline Blob256 Hash(const Blob256& blob)
    {
        Blob256 result;
        CryptoPP::SHA256 hash;
        hash.Update(blob.RawBytes(), 32);
        hash.Final(result._data);
        return result;
    }

    static inline Blob256 HashX2(const byte* data, uint32_t size)
    {
        Blob256 hash = Hash(data, size);
        return Hash(hash);
    }

    static inline Blob256 HashX2(const Blob256& blob)
    {
        Blob256 hash = Hash(blob);
        return Hash(hash);
    }
};

class CTxIn
{
public:
    uint64_t nValue;
    std::string pubKey;
    std::string scriptSig;
};

class CTxOut
{
public:
    uint64_t nValue;
    std::string pubKey;
};

class CTransaction
{
public:
    int nVersion;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    std::string msg;
    uint64_t nLockHeight;
    uint64_t nLimitValue;
    bool fSetLimit;
};

#pragma pack(push,1)
class CBlockHeader
{
public:
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashAccountRoot;
    uint64_t nTime;
    uint64_t nHeight;
    uint64_t nNonce;
    uint16_t nVersion;
};

class CBlock : public CBlockHeader
{
public:
    std::vector<CTransaction> vtx;
    CBlock(CBlockHeader& header) : CBlockHeader(header) {}
};
#pragma pack(pop)

class BlockData
{
public:
    char* bytes;
    CBlockHeader header;
    BlockData() : bytes(nullptr) {}
};
