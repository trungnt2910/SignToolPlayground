#include "crypto/Pvk2PfxConverter.h"

#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <windows.h>

#include <wincrypt.h>

#include "crypto/CckyException.h"
#include "crypto/CryptoFactory.h"
#include "crypto/ICertStore.h"
#include "crypto/PvkKey.h"
#include "crypto/windows/WinCert.h"
#include "crypto/windows/WinHelper.h"
#include "crypto/windows/WindowsException.h"

using namespace ccky::crypto;

namespace ccky
{
namespace crypto
{

void Pvk2PfxConverter::convert(const Pvk2PfxOptions& opts)
{
    if (opts.pvkFile.empty() || opts.spcFile.empty())
    {
        throw FileNotFoundException("PVK or SPC file not specified");
    }

    if (!std::filesystem::exists(opts.pvkFile))
    {
        throw FileNotFoundException("PVK file not found: " + opts.pvkFile);
    }

    if (!std::filesystem::exists(opts.spcFile))
    {
        throw FileNotFoundException("SPC file not found: " + opts.spcFile);
    }

    std::string outPfxPath = opts.pfxFile;
    if (outPfxPath.empty())
    {
        std::filesystem::path spcPath(opts.spcFile);
        outPfxPath = spcPath.replace_extension(".pfx").string();
    }

    if (!opts.force && std::filesystem::exists(outPfxPath))
    {
        throw OutputFileExistsException("Output PFX file exists: " + outPfxPath);
    }

    PvkKey pvkKey;
    pvkKey.load(opts.pvkFile);
    pvkKey.decrypt(opts.pvkPassword);

    const std::vector<uint8_t>& keyData = pvkKey.getKeyData();
    uint32_t keyType = pvkKey.getKeyType();

    // 2. Load the CER/SPC file
    auto store = CryptoFactory::createStore(StoreType::CerFile, opts.spcFile);
    if (!store)
    {
        throw FileNotFoundException("Failed to open SPC file: " + opts.spcFile);
    }
    store->load(opts.spcFile);
    auto certs = store->getCertificates();
    if (certs.empty())
    {
        throw std::runtime_error("No certificates found in: " + opts.spcFile);
    }

    // 3. Create a temporary container and import the decrypted PRIVATEKEYBLOB
    HCRYPTPROV rawProv = 0;
    std::wstring containerName = L"CckyTempPvkContainer_" + std::to_wstring(GetCurrentProcessId());

    // Try to delete if it already exists from a previous crashed run
    CryptAcquireContextW(
        &rawProv, containerName.c_str(), MS_DEF_PROV_W, PROV_RSA_FULL, CRYPT_DELETEKEYSET);

    if (!CryptAcquireContextW(
            &rawProv, containerName.c_str(), MS_DEF_PROV_W, PROV_RSA_FULL, CRYPT_NEWKEYSET))
    {
        throw WindowsException("Failed to create temporary crypt container");
    }

    // RAII for crypt provider, with custom deleter to also delete the keyset
    struct TempProvDeleter
    {
        using pointer = HCRYPTPROV;
        std::wstring name;
        void operator()(HCRYPTPROV p) const
        {
            if (p)
            {
                CryptReleaseContext(p, 0);
                HCRYPTPROV tmp = 0;
                CryptAcquireContextW(
                    &tmp, name.c_str(), MS_DEF_PROV_W, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
            }
        }
    };
    std::unique_ptr<HCRYPTPROV, TempProvDeleter> hProv(rawProv, TempProvDeleter{containerName});

    HCRYPTKEY rawKey = 0;
    if (!CryptImportKey(hProv.get(), keyData.data(), static_cast<DWORD>(keyData.size()), 0,
            CRYPT_EXPORTABLE, &rawKey))
    {
        throw WindowsException("Failed to import PVK private key");
    }
    CryptKeyPtr hKey(rawKey);

    // 4. Create in-memory certificate store
    HCERTSTORE rawMemStore =
        CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
    if (!rawMemStore)
    {
        throw WindowsException("Failed to create memory store");
    }
    CertStorePtr hMemStore(rawMemStore);

    // Add all certificates and associate the private key with the first one
    bool first = true;
    for (auto& cert : certs)
    {
        auto winCert = dynamic_cast<WinCert*>(cert.get());
        if (winCert)
        {
            PCCERT_CONTEXT pCert = winCert->getInternal();
            CertAddCertificateContextToStore(
                static_cast<HCERTSTORE>(hMemStore.get()), pCert, CERT_STORE_ADD_ALWAYS, nullptr);

            if (first)
            {
                CRYPT_KEY_PROV_INFO provInfo = {0};
                provInfo.pwszContainerName = const_cast<LPWSTR>(containerName.c_str());
                provInfo.pwszProvName = const_cast<LPWSTR>(MS_DEF_PROV_W);
                provInfo.dwProvType = PROV_RSA_FULL;
                provInfo.dwKeySpec = keyType; // From PVK header
                provInfo.dwFlags = 0;
                provInfo.cProvParam = 0;
                provInfo.rgProvParam = nullptr;
                provInfo.dwKeySpec = keyType;

                CertSetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &provInfo);
                first = false;
            }
        }
    }

    // 5. Export to PFX
    CRYPT_DATA_BLOB pfxBlob = {0};
    std::wstring pfxPassW = WinHelper::utf8ToWide(opts.pfxPassword);
    if (!PFXExportCertStoreEx(static_cast<HCERTSTORE>(hMemStore.get()), &pfxBlob, pfxPassW.c_str(),
            nullptr, EXPORT_PRIVATE_KEYS))
    {
        throw WindowsException("Failed to export PFX size");
    }

    std::vector<BYTE> pfxData(pfxBlob.cbData);
    pfxBlob.pbData = pfxData.data();
    if (!PFXExportCertStoreEx(static_cast<HCERTSTORE>(hMemStore.get()), &pfxBlob, pfxPassW.c_str(),
            nullptr, EXPORT_PRIVATE_KEYS))
    {
        throw WindowsException("Failed to export PFX");
    }

    // 6. Write output
    std::ofstream pfxFileStream(outPfxPath, std::ios::binary);
    if (!pfxFileStream)
    {
        throw std::runtime_error("Failed to open output PFX file: " + outPfxPath);
    }
    pfxFileStream.write(reinterpret_cast<const char*>(pfxData.data()), pfxData.size());
}

} // namespace crypto
} // namespace ccky
