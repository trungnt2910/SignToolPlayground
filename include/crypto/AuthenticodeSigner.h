#ifndef CCKY_AUTHENTICODE_SIGNER_H
#define CCKY_AUTHENTICODE_SIGNER_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "crypto/ICertStore.h"

namespace ccky
{
namespace crypto
{

struct SignOptions
{
    std::string certPath;             // /f
    std::string password;             // /p
    std::string fileDigestAlg;        // /fd (SHA1, SHA256)
    std::string timestampUrl;         // /t or /tr
    std::string timestampDigestAlg;   // /td
    std::string description;          // /d
    std::string descriptionUrl;       // /du
    bool append = false;              // /as
    bool autoSelect = false;          // /a
    std::string additionalCert;       // /ac
    std::string certTemplate;         // /c
    std::string csp;                  // /csp
    std::string keyContainer;         // /kc
    std::string issuerName;           // /i
    std::string subjectName;          // /n
    std::string rootSubject;          // /r
    std::string systemStore;          // /s
    bool machineStore = false;        // /sm
    std::string sha1Hash;             // /sha1
    std::string ekuUsage;             // /u
    bool windowsComponentEku = false; // /uw
    bool noPageHashes = false;        // /nph
    bool pageHashes = false;          // /ph
};

struct VerifyOptions
{
    bool allMethods = false;         // /a
    bool defaultAuthPolicy = false;  // /pa
    bool printPageHashes = false;    // /ph
    bool warnNoTimestamp = false;    // /tw
    bool printDescription = false;   // /d
    std::string catalogFile;         // /c
    bool kernelDriverPolicy = false; // /kp
    bool multipleSemantics = false;  // /ms
    std::string osVersion;           // /o
    bool verifyPkcs7 = false;        // /p7
    std::string policyGUID;          // /pg
    std::string rootSubject;         // /r
    int signatureIndex = -1;         // /ds
};

struct TimestampOptions
{
    std::string timestampUrl;       // /t or /tr
    std::string timestampDigestAlg; // /td
    int index = 0;                  // /tp
    bool timestampPkcs7 = false;    // /p7
};

struct CatdbOptions
{
    bool updateDefault = false; // /d
    std::string guid;           // /g
    bool remove = false;        // /r
    bool uniqueName = false;    // /u
    std::vector<std::string> files;
};

class AuthenticodeSigner
{
  public:
    static void sign(CertificatePtr cert, const SignOptions& options, const std::string& filePath);
    static void verify(const VerifyOptions& options, const std::string& filePath);
    static void timestamp(const TimestampOptions& options, const std::string& filePath);
    static void catdb(const CatdbOptions& options);
};

} // namespace crypto
} // namespace ccky

#endif // CCKY_AUTHENTICODE_SIGNER_H
