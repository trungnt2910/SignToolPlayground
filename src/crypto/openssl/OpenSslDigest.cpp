#include "crypto/openssl/OpenSslDigest.h"

#include <fstream>
#include <iomanip>
#include <sstream>

#include "crypto/CckyProbeAllocate.h"
#include "crypto/Strings.h"
#include "crypto/openssl/OpenSslException.h"
#include "crypto/openssl/OpenSslHelper.h"

namespace ccky
{
namespace crypto
{

OpenSslDigestStream::OpenSslDigestStream(const EVP_MD* md) : m_md(md)
{
    OpenSslCheck::check(m_md != nullptr, "Invalid OpenSSL digest algorithm");
    m_ctx.reset(EVP_MD_CTX_new());
    OpenSslCheck::check(m_ctx != nullptr && EVP_DigestInit_ex(m_ctx.get(), m_md, nullptr) == 1,
        "Failed to initialize OpenSSL digest context");
}

void OpenSslDigestStream::update(const std::vector<uint8_t>& data)
{
    if (!data.empty() && EVP_DigestUpdate(m_ctx.get(), data.data(), data.size()) != 1)
    {
        throw OpenSslException("Failed to update OpenSSL digest");
    }
}

std::vector<uint8_t> OpenSslDigestStream::calculateHash()
{
    EVPMDCtxPtr dupCtx(EVP_MD_CTX_new());
    OpenSslCheck::check(dupCtx != nullptr && EVP_MD_CTX_copy_ex(dupCtx.get(), m_ctx.get()) == 1,
        "Failed to duplicate OpenSSL digest context");
    unsigned char mdVal[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    OpenSslCheck::check(
        EVP_DigestFinal_ex(dupCtx.get(), mdVal, &mdLen) == 1, "Failed to finalize OpenSSL digest");
    return std::vector<uint8_t>(mdVal, mdVal + mdLen);
}

std::string OpenSslDigestStream::calculateHashString() { return Strings::hex(calculateHash()); }

OpenSslDigest::OpenSslDigest(int nid) : m_nid(nid)
{
    OpenSslCheck::check(
        getMd() != nullptr, "Unsupported NID for OpenSslDigest: " + std::to_string(nid));
}

const EVP_MD* OpenSslDigest::getMd() const { return EVP_get_digestbynid(m_nid); }

std::vector<uint8_t> OpenSslDigest::calculateHash(const std::vector<uint8_t>& data) const
{
    auto stream = createStream();
    stream->update(data);
    return stream->calculateHash();
}

std::vector<uint8_t> OpenSslDigest::calculateHash(const std::filesystem::path& path) const
{
    if (!std::filesystem::exists(path))
    {
        throw OpenSslException("File does not exist: " + path.string());
    }
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
    {
        throw OpenSslException("Failed to open file: " + path.string());
    }
    auto stream = createStream();
    std::vector<uint8_t> buf(65536);
    while (f.read(reinterpret_cast<char*>(buf.data()), buf.size()))
    {
        stream->update(buf);
    }
    if (f.gcount() > 0)
    {
        buf.resize(f.gcount());
        stream->update(buf);
    }
    return stream->calculateHash();
}

std::string OpenSslDigest::calculateHashString(const std::vector<uint8_t>& data) const
{
    return Strings::hex(calculateHash(data));
}

std::string OpenSslDigest::calculateHashString(const std::filesystem::path& path) const
{
    return Strings::hex(calculateHash(path));
}

DigestStreamPtr OpenSslDigest::createStream() const
{
    return std::make_unique<OpenSslDigestStream>(getMd());
}

std::string OpenSslDigest::getName() const
{
    const char* sn = OBJ_nid2sn(m_nid);
    if (!sn || m_nid == NID_undef)
    {
        return "";
    }
    return Strings::toLower(sn);
}

std::string OpenSslDigest::getOid() const
{
    ASN1ObjectPtr obj(OBJ_nid2obj(m_nid));
    if (obj == nullptr)
    {
        return "";
    }
    std::string oid;
    int len = CckyProbeAllocate<OBJ_obj2txt, CckyProbeReturnPositive{}>(
        CckyProbeString(oid), CckyProbeSize{}, obj.get(), /* no_name = */ 1);
    if (len <= 0)
    {
        return "";
    }
    return oid;
}

} // namespace crypto
} // namespace ccky
