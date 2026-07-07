#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/Certificate.h"
#include "crypto/CertificateStore.h"
#include "crypto/CryptoFactory.h"

class Given_Certificate : public CckyTest
{
};

TEST_F(Given_Certificate, When_LoadFromPfx_ReturnsExpectedProperties)
{
    std::string pfxPath = getTestDataPath("tests/data/ccky.pfx");
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::PfxFile, pfxPath);
    ccky::crypto::StoreOptions options;

    store->load(pfxPath, options);
    auto certs = store->getCertificates();

    ASSERT_EQ(certs.size(), 1);
    auto cert = certs[0];
    EXPECT_FALSE(cert->getEncoded().empty());
    EXPECT_EQ(cert->getSerialNumber(), "69 1F 6F 91 05 F0 D6 AE 40 5F 81 FA 4F 5B C7 67");
    EXPECT_EQ(cert->getSignatureAlgorithm(), "1.2.840.113549.1.1.11");
    EXPECT_EQ(cert->getSha1(), "70cc11b9d1bfdfa1d5f629a8a78173b33b17bee0");
    EXPECT_EQ(cert->getSha1Thumbprint(), "70CC11B9 D1BFDFA1 D5F629A8 A78173B3 3B17BEE0");
    EXPECT_EQ(cert->getMd5Thumbprint(), "A6107B8E FC84AF6A 986CCBEF EEBD532B");
    EXPECT_EQ(cert->getCommonName(), "ccky");
    EXPECT_EQ(cert->getSubjectDisplay(), "[0,0] 2.5.4.3 (CN) ccky");
    EXPECT_EQ(cert->getSubjectDN(), "CN=ccky");
    EXPECT_EQ(cert->getIssuerName(), "ccky");
    EXPECT_EQ(cert->getIssuerDisplay(), "[0,0] 2.5.4.3 (CN) ccky");
    EXPECT_EQ(cert->getIssuerDN(), "CN=ccky");
    EXPECT_EQ(cert->getNotBefore(), "Fri May 15 19:59:47 2026");
    EXPECT_EQ(cert->getNotAfter(), "Sat May 15 20:19:47 2027");
    EXPECT_EQ(cert->getKeyLength(), 2048);
    EXPECT_EQ(cert->getKeyMd5Thumbprint(), "394C27C3 AAD73C71 49833A75 27725686");
    EXPECT_EQ(cert->getKeySha256Thumbprint(),
        "8C4FBA4328174E84E5F7E5F49BB05F556775D4CB554F11239BFD7D3ADF54EEEF");
    EXPECT_TRUE(cert->hasPrivateKey());
    EXPECT_NE(cert->getPrivateKey(), nullptr);
    EXPECT_TRUE(cert->isPrivateKeyExportable());
    EXPECT_FALSE(cert->isCA());
    EXPECT_EQ(cert->getPathLenConstraint(), -1);
    EXPECT_EQ(cert->getNetscapeCertType(), 0);
    EXPECT_EQ(cert->getPolicyLink(), "");
}

TEST_F(Given_Certificate, When_LoadFromCer_ReturnsExpectedProperties)
{
    std::string cerPath = getTestDataPath("tests/data/ccky.cer");
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::CerFile, cerPath);
    ccky::crypto::StoreOptions options;

    store->load(cerPath, options);
    auto certs = store->getCertificates();

    ASSERT_EQ(certs.size(), 1);
    auto cert = certs[0];
    EXPECT_FALSE(cert->getEncoded().empty());
    EXPECT_EQ(cert->getSignatureAlgorithm(), "1.3.14.3.2.29");
    EXPECT_EQ(cert->getSha1(), "57088779e3a8616866b68d18997d5070f39064e0");
    EXPECT_EQ(cert->getSha1Thumbprint(), "57088779 E3A86168 66B68D18 997D5070 F39064E0");
    EXPECT_EQ(cert->getMd5Thumbprint(), "0B6B401D 42BF2284 A822C628 09C6912C");
    EXPECT_EQ(cert->getCommonName(), "ccky");
    EXPECT_EQ(cert->getSubjectDisplay(), "[0,0] 2.5.4.3 (CN) ccky");
    EXPECT_EQ(cert->getSubjectDN(), "CN=ccky");
    EXPECT_EQ(cert->getIssuerName(), "ccky");
    EXPECT_EQ(cert->getIssuerDisplay(), "[0,0] 2.5.4.3 (CN) ccky");
    EXPECT_EQ(cert->getIssuerDN(), "CN=ccky");
    EXPECT_EQ(cert->getKeyLength(), 2048);
    EXPECT_FALSE(cert->hasPrivateKey());
    EXPECT_EQ(cert->getPrivateKey(), nullptr);
    EXPECT_FALSE(cert->isPrivateKeyExportable());
    EXPECT_FALSE(cert->isCA());
    EXPECT_EQ(cert->getPathLenConstraint(), 0);
    EXPECT_EQ(cert->getNetscapeCertType(), 0);
    EXPECT_EQ(cert->getPolicyLink(), "");
}

TEST_F(Given_Certificate, When_LoadFromP7b_ReturnsExpectedProperties)
{
    std::string p7bPath = getTestDataPath("tests/data/ccky.p7b");
    auto store =
        ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::P7bFile, p7bPath);
    ccky::crypto::StoreOptions options;

    store->load(p7bPath, options);
    auto certs = store->getCertificates();

    ASSERT_EQ(certs.size(), 1);
    auto cert = certs[0];
    EXPECT_FALSE(cert->getEncoded().empty());
    EXPECT_EQ(cert->getSignatureAlgorithm(), "1.3.14.3.2.29");
    EXPECT_EQ(cert->getSha1(), "57088779e3a8616866b68d18997d5070f39064e0");
    EXPECT_EQ(cert->getSha1Thumbprint(), "57088779 E3A86168 66B68D18 997D5070 F39064E0");
    EXPECT_EQ(cert->getMd5Thumbprint(), "0B6B401D 42BF2284 A822C628 09C6912C");
    EXPECT_EQ(cert->getCommonName(), "ccky");
    EXPECT_EQ(cert->getSubjectDisplay(), "[0,0] 2.5.4.3 (CN) ccky");
    EXPECT_EQ(cert->getSubjectDN(), "CN=ccky");
    EXPECT_EQ(cert->getIssuerName(), "ccky");
    EXPECT_EQ(cert->getIssuerDisplay(), "[0,0] 2.5.4.3 (CN) ccky");
    EXPECT_EQ(cert->getIssuerDN(), "CN=ccky");
    EXPECT_EQ(cert->getKeyLength(), 2048);
    EXPECT_FALSE(cert->hasPrivateKey());
    EXPECT_EQ(cert->getPrivateKey(), nullptr);
    EXPECT_FALSE(cert->isPrivateKeyExportable());
    EXPECT_FALSE(cert->isCA());
    EXPECT_EQ(cert->getPathLenConstraint(), 0);
    EXPECT_EQ(cert->getNetscapeCertType(), 0);
    EXPECT_EQ(cert->getPolicyLink(), "");
}

TEST_F(Given_Certificate, When_LoadFromPe_ReturnsExpectedProperties)
{
    std::string pePath = getTestDataPath("tests/data/lxmonika.sys");
    auto store = ccky::crypto::CryptoFactory::createStore(ccky::crypto::StoreType::PeFile, pePath);
    ccky::crypto::StoreOptions options;

    store->load(pePath, options);
    auto certs = store->getCertificates();

    ASSERT_EQ(certs.size(), 1);
    auto cert = certs[0];
    EXPECT_FALSE(cert->getEncoded().empty());
    EXPECT_EQ(cert->getSignatureAlgorithm(), "1.2.840.113549.1.1.11");
    EXPECT_EQ(cert->getSha1(), "dd5937c1d1b767fd044ba1565dadb4f46c766686");
    EXPECT_EQ(cert->getSha1Thumbprint(), "DD5937C1 D1B767FD 044BA156 5DADB4F4 6C766686");
    EXPECT_EQ(cert->getMd5Thumbprint(), "55A02223 C5D1BA1E 54EEB5DD DC05E1E4");
    EXPECT_EQ(cert->getCommonName(), "Project Reality");
    EXPECT_EQ(cert->getSubjectDisplay(), "[0,0] 2.5.4.3 (CN) Project Reality");
    EXPECT_EQ(cert->getSubjectDN(), "CN=Project Reality");
    EXPECT_EQ(cert->getIssuerName(), "Project Reality");
    EXPECT_EQ(cert->getIssuerDisplay(), "[0,0] 2.5.4.3 (CN) Project Reality");
    EXPECT_EQ(cert->getIssuerDN(), "CN=Project Reality");
    EXPECT_EQ(cert->getKeyLength(), 2048);
    EXPECT_FALSE(cert->hasPrivateKey());
    EXPECT_EQ(cert->getPrivateKey(), nullptr);
    EXPECT_FALSE(cert->isPrivateKeyExportable());
    EXPECT_FALSE(cert->isCA());
    EXPECT_EQ(cert->getPathLenConstraint(), -1);
    EXPECT_EQ(cert->getNetscapeCertType(), 0);
    EXPECT_EQ(cert->getPolicyLink(), "");
}
