#include <boost/uuid/detail/md5.hpp>
#include <boost/uuid/detail/sha1.hpp>
#include <boost/crc.hpp>
#include <boost/algorithm/hex.hpp>


class IHasher
{
public:
    virtual std::string Hash(const char* buffer, unsigned int buffer_length) = 0;
    virtual ~IHasher() {};
};

class CRC32Hasher : public IHasher {
public:
    std::string Hash(const char *buffer, unsigned int buffer_length) override {
        boost::crc_32_type result;
        result.process_bytes(buffer, buffer_length);
        return std::to_string(result.checksum());
    }
};

using boost::uuids::detail::md5;
class MD5Hasher : public IHasher {
public:
    std::string Hash(const char *buffer, unsigned int buffer_length) override {
        md5 hash;
        md5::digest_type digest;
        hash.process_bytes(buffer, buffer_length);
        hash.get_digest(digest);

        const auto intDigest = reinterpret_cast<const int *>(digest);
        std::string result;
        boost::algorithm::hex(intDigest, intDigest + (sizeof(md5::digest_type) / sizeof(int)),
                              std::back_inserter(result));
        return result;
    }
};

using boost::uuids::detail::sha1;

class SHA1Hasher : public IHasher {
public:
    std::string Hash(const char *buffer, unsigned int buffer_length) override {
        sha1 hash;
        sha1::digest_type digest;
        hash.process_bytes(buffer, buffer_length);
        hash.get_digest(digest);

        const auto intDigest = reinterpret_cast<const int *>(digest);
        std::string result;
        boost::algorithm::hex(intDigest, intDigest + (sizeof(sha1::digest_type) / sizeof(int)),
                              std::back_inserter(result));
        return result;
    }
};

/*using boost::uuids::detail::md5;
std::string Hash_md5(const char *buffer, unsigned int buffer_length) {
    md5 hash;
    md5::digest_type digest;
    hash.process_bytes(buffer, buffer_length);
    hash.get_digest(digest);

    const auto intDigest = reinterpret_cast<const int *>(digest);
    std::string result;
    boost::algorithm::hex(intDigest, intDigest + (sizeof(md5::digest_type) / sizeof(int)), std::back_inserter(result));
    return result;
}

using boost::uuids::detail::sha1;
std::string Hash_SHA1(const char *buffer, unsigned int buffer_length) {
    sha1 hash;
    sha1::digest_type digest;
    hash.process_bytes(buffer, buffer_length);
    hash.get_digest(digest);

    const auto intDigest = reinterpret_cast<const int *>(digest);
    std::string result;
    boost::algorithm::hex(intDigest, intDigest + (sizeof(sha1::digest_type) / sizeof(int)), std::back_inserter(result));
    return result;
}

std::string Hash_Crc32(const char *buffer, unsigned int buffer_length) {
    boost::crc_32_type result;
    result.process_bytes(buffer, buffer_length);
    return std::to_string(result.checksum());
}*/

/*std::string toString(const md5::digest_type &digest)
{
    const auto intDigest = reinterpret_cast<const int*>(&digest);
    std::string result;
    boost::algorithm::hex(intDigest, intDigest + (sizeof(md5::digest_type)/sizeof(int)), std::back_inserter(result));
    return result;
}

int main ()
{
    std::string s;

    while(std::getline(std::cin, s)) {
        md5 hash;
        md5::digest_type digest;

        hash.process_bytes(s.data(), s.file_sz());
        hash.get_digest(digest);

        std::cout << "md5(" << s << ") = " << toString(digest) << '\n';
    }

    return 0;
}*/
