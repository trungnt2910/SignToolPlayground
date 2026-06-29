#include "commands/CertMgrCommand.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "cli/CliParser.h"
#include "crypto/AuthenticodeSigner.h"
#include "crypto/CckyException.h"
#include "crypto/CryptoFactory.h"

namespace ccky
{
namespace commands
{

bool CertMgrCommand::isSubcommand(const std::string& arg) const
{
    std::string lower = arg;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower == "/add" || lower == "-add" || lower == "/del" || lower == "-del" ||
           lower == "/put" || lower == "-put";
}

std::vector<cli::FlagDef> CertMgrCommand::getFlagDefs(const std::string& subcommand) const
{
    return {{"add", cli::FlagType::Boolean,
                "Add certificates/CRLs/CTLs to a storeFile or a system store", "", ""},
        {"del", cli::FlagType::Boolean,
            "Delete certificates/CRLs/CTLs from a storeFile or \na system store", "", ""},
        {"put", cli::FlagType::Boolean,
            "Put an encoded certificate/CRL/CTL from a storeFile or\na system store to a file.  "
            "The file will be saved in X.509\nformat. -7 can be used to save the file in PKCS #7 "
            "format",
            "", ""},
        {"s", cli::FlagType::Boolean, "Indicate the store is a system store ", "", ""},
        {"r", cli::FlagType::Value,
            "The system store location \n    <currentUser|localMachine> Default to 'currentUser' ",
            "<location>", ""},
        {"c", cli::FlagType::Boolean, "Certificates in the store", "", ""},
        {"crl", cli::FlagType::Boolean, "Certificates revocation lists(CRLs) in the store", "", ""},
        {"ctl", cli::FlagType::Boolean, "Certificates trust lists(CTLs) in the store", "", ""},
        {"v", cli::FlagType::Boolean, "Verbose display of the certificates/CRLs/CTLs ", "", ""},
        {"all", cli::FlagType::Boolean, "All certificates/CRLs/CTLs in the store", "", ""},
        {"n", cli::FlagType::Value, "Common name of the certificate ", "<name>", ""},
        {"sha1", cli::FlagType::Value, "The sha1 hash of the certificate/CRLs/CTLs ",
            "<thumbPrint>", ""},
        {"7", cli::FlagType::Boolean, "Save the destination store in PKCS #7 format", "", ""},
        {"e", cli::FlagType::Value,
            "Certificate/CRL/CTL encoding type.  \nDefault to X509_ASN_ENCODING", "<encode>", ""},
        {"f", cli::FlagType::Value, "CertStore open flags.  Meaningful only if -y is set", "<flag>",
            ""},
        {"y", cli::FlagType::Value, "CertStore provider name", "<provider>", ""},
        {"?", cli::FlagType::Boolean, "Displays help.", "", "", 0, "*", true}};
}

std::shared_ptr<crypto::ICertStore> CertMgrCommand::getStore(
    const std::string& location, bool isSystemStore)
{
    crypto::StoreType type =
        isSystemStore ? crypto::StoreType::WinSystem : crypto::StoreType::CerFile;
    return crypto::CryptoFactory::createStore(type, location);
}

CertMgrCommand::CertMgrCommand(std::istream& in, std::ostream& out, std::ostream& err)
    : cli::Command(in, out, err)
{
}

void CertMgrCommand::registerUsage(cli::CommandRegistry* registry)
{
    if (registry)
    {
        cli::UsageBehavior behavior;
        behavior.useDashPrefix = true;
        behavior.basePadWidth = 20;
        behavior.noCategoryBlankLines = true;
        behavior.alignValueAtCol = 7;
        behavior.noInitialBlankLine = true;

        registry->registerCommandUsage("certmgr", "",
            "Usage: CertMgr [options][-s [-r <location>][SourceStoreName]\n"
            "                        [-s [-r <location>][DestinationStoreName]\n"
            "Options: \n",
            "", {}, getFlagDefs(""), behavior);
    }
}

void CertMgrCommand::printHelp()
{
    if (m_registry)
    {
        m_err << m_registry->getUsage("certmgr", "");
    }
}

void CertMgrCommand::displayError(const std::exception& e)
{
    const auto* cckyErr = dynamic_cast<const crypto::CckyException*>(&e);
    if (cckyErr && cckyErr->shouldPrintHelp())
    {
        m_err << "Error: " << e.what() << "\n";
    }
    else
    {
        m_err << "Error: " << e.what() << "\nCertMgr Failed\n";
    }
}

void CertMgrCommand::displayError(const std::string& msg)
{
    m_err << "Error: " << msg << "\nCertMgr Failed\n";
}

int CertMgrCommand::executeImpl(const cli::ParsedArgs& args)
{
    crypto::StoreOptions opts;
    opts.registryLocation = args.getFlagValue("r", "currentUser");
    opts.providerName = args.getFlagValue("y");
    opts.encodingType = args.getFlagValue("e", "X509_ASN_ENCODING");

    std::string sha1Flag = args.getFlagValue("sha1");
    if (!sha1Flag.empty())
    {
        if (sha1Flag.length() != 40 ||
            !std::all_of(sha1Flag.begin(), sha1Flag.end(),
                [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); }))
        {
            throw crypto::CckyException("Invalid value for -sha1 option", true);
        }
        std::transform(sha1Flag.begin(), sha1Flag.end(), sha1Flag.begin(), ::tolower);
    }

    if (args.subcommand == "/add" || args.subcommand == "-add")
    {
        if (args.positional.empty())
        {
            throw crypto::CckyException("Missing SourceStoreName", true);
        }
        if (args.positional.size() < 2)
        {
            throw crypto::CckyException("Has to specify DestinationStoreName", true);
        }
        std::string sourceLocation = args.positional[0];
        std::string destLocation = args.positional[1];

        bool isSourceSystemStore =
            (!args.positionalFlags.empty() && args.positionalFlags[0].count("s") > 0) ||
            (args.hasFlag("s") && args.positionalFlags.size() <= 1);
        bool isDestSystemStore =
            (args.positionalFlags.size() > 1 && args.positionalFlags[1].count("s") > 0);

        if (!isSourceSystemStore && !std::filesystem::exists(sourceLocation))
        {
            throw crypto::CckyException("Failed to open the source store", false);
        }

        auto sourceStore = getStore(sourceLocation, isSourceSystemStore);
        sourceStore->load(sourceLocation, opts);

        auto destStore = getStore(destLocation, isDestSystemStore);
        destStore->load(destLocation, opts);

        bool addAll = args.hasFlag("all");
        bool addC = args.hasFlag("c");
        bool addCrl = args.hasFlag("crl");
        bool addCtl = args.hasFlag("ctl");

        if (!addAll && !addC && !addCrl && !addCtl)
        {
            addAll = true; // Default to all if nothing specified
        }

        if (addAll || addC)
        {
            for (const auto& c : sourceStore->getCertificates())
            {
                destStore->addCertificate(c);
            }
        }
        if (addAll || addCrl)
        {
            for (const auto& c : sourceStore->getCrls())
            {
                destStore->addCrl(c);
            }
        }
        if (addAll || addCtl)
        {
            for (const auto& c : sourceStore->getCtls())
            {
                destStore->addCtl(c);
            }
        }

        destStore->save(destLocation, opts);
        m_out << "CertMgr Succeeded\n";
        return 0;
    }
    else if (args.subcommand == "/del" || args.subcommand == "-del")
    {
        if (args.positional.empty())
        {
            throw crypto::CckyException("Missing SourceStoreName", true);
        }
        std::string location = args.positional[0];
        bool isSystemStore =
            (!args.positionalFlags.empty() && args.positionalFlags[0].count("s") > 0) ||
            args.hasFlag("s");

        if (!isSystemStore && !std::filesystem::exists(location))
        {
            throw crypto::CckyException("Failed to open the source store", false);
        }

        auto store = getStore(location, isSystemStore);
        store->load(location, opts);

        std::string cn = args.getFlagValue("n");
        std::string sha1 = sha1Flag;

        bool delAll = args.hasFlag("all");
        bool delC = args.hasFlag("c");
        bool delCrl = args.hasFlag("crl");
        bool delCtl = args.hasFlag("ctl");

        if (!delAll && !delC && !delCrl && !delCtl)
        {
            delAll = true;
        }

        if (delAll || delC)
        {
            if (!sha1.empty())
            {
                auto certs = store->getCertificates();
                bool found = std::any_of(certs.begin(), certs.end(),
                    [&](const auto& c)
                    {
                        bool match = true;
                        if (!cn.empty() && c->getCommonName() != cn)
                        {
                            match = false;
                        }
                        if (c->getSha1() != sha1)
                        {
                            match = false;
                        }
                        return match;
                    });
                if (!found)
                {
                    throw crypto::CckyException(
                        "Can not find a certificate matching the hash value", false);
                }
            }
            store->deleteCertificate(cn, sha1);
        }
        if (delAll || delCrl)
        {
            store->deleteCrl(sha1);
        }
        if (delAll || delCtl)
        {
            store->deleteCtl(sha1);
        }

        store->save(location, opts);
        m_out << "CertMgr Succeeded\n";
        return 0;
    }
    else if (args.subcommand == "/put" || args.subcommand == "-put")
    {
        if (args.positional.empty())
        {
            throw crypto::CckyException("Missing SourceStoreName", true);
        }
        if (args.positional.size() < 2)
        {
            throw crypto::CckyException("Has to specify DestinationStoreName", true);
        }
        std::string sourceLocation = args.positional[0];
        std::string destLocation = args.positional[1];

        bool isSourceSystemStore =
            (!args.positionalFlags.empty() && args.positionalFlags[0].count("s") > 0) ||
            (args.hasFlag("s") && args.positionalFlags.size() <= 1);

        if (!isSourceSystemStore && !std::filesystem::exists(sourceLocation))
        {
            throw crypto::CckyException("Failed to open the source store", false);
        }

        auto sourceStore = getStore(sourceLocation, isSourceSystemStore);
        sourceStore->load(sourceLocation, opts);

        auto destStore = crypto::CryptoFactory::createStore(crypto::StoreType::CerFile);
        std::string cn = args.getFlagValue("n");
        std::string sha1 = sha1Flag;

        for (const auto& c : sourceStore->getCertificates())
        {
            if (!cn.empty() && c->getCommonName() != cn)
            {
                continue;
            }
            if (!sha1.empty() && c->getSha1() != sha1)
            {
                continue;
            }
            destStore->addCertificate(c);
        }

        // TODO: ICertStore does not currently expose saveAsPkcs7 in its virtual interface,
        // and the Windows backend lacks PKCS#7 serialization. Both branches fallback to standard
        // save.
        if (args.hasFlag("7"))
        {
            destStore->save(destLocation, opts);
        }
        else
        {
            destStore->save(destLocation, opts);
        }
        m_out << "CertMgr Succeeded\n";
        return 0;
    }
    else
    {
        // Display mode
        if (args.positional.empty())
        {
            throw crypto::CckyException("Missing SourceStoreName", true);
        }
        std::string location = args.positional[0];
        bool isSystemStore =
            (!args.positionalFlags.empty() && args.positionalFlags[0].count("s") > 0) ||
            args.hasFlag("s");

        if (!isSystemStore && !std::filesystem::exists(location))
        {
            throw crypto::CckyException("Failed to open the source store", false);
        }

        auto store = getStore(location, isSystemStore);
        store->load(location, opts);

        bool verbose = args.hasFlag("v");
        auto certs = store->getCertificates();
        for (size_t i = 0; i < certs.size(); ++i)
        {
            const auto& c = certs[i];
            m_out << "==============Certificate # " << (i + 1) << " ==========\n";
            m_out << "Subject::\n  " << c->getSubjectDisplay() << "\n";
            m_out << "Issuer::\n  " << c->getIssuerDisplay() << "\n";
            m_out << "SerialNumber::\n   " << c->getSerialNumber() << "\n";
            m_out << "SHA1 Thumbprint:: \n      " << c->getSha1Thumbprint() << " \n";
            m_out << "MD5 Thumbprint:: \n      " << c->getMd5Thumbprint() << " \n";
            m_out << "Key MD5 Thumbprint:: \n      " << c->getKeyMd5Thumbprint() << " \n";
            std::string provType = c->getProviderType();
            std::string provName = c->getProviderName();
            std::string contName = c->getContainerName();
            bool printedProv = false;
            if (!provType.empty())
            {
                m_out << "Provider Type:: " << provType;
                printedProv = true;
            }
            if (!provName.empty())
            {
                if (printedProv)
                {
                    m_out << " ";
                }
                m_out << "Provider Name:: " << provName;
                printedProv = true;
            }
            if (!contName.empty())
            {
                if (printedProv)
                {
                    m_out << " ";
                }
                m_out << "Container: " << contName;
                printedProv = true;
            }
            if (printedProv)
            {
                m_out << "\n";
            }
            m_out << "NotBefore:: \n  " << c->getNotBefore() << "\n";
            m_out << "NotAfter:: \n  " << c->getNotAfter() << "\n";
        }

        auto ctls = store->getCtls();
        if (ctls.empty())
        {
            m_out << "==============No CTLs ==========\n";
        }
        else
        {
            for (size_t i = 0; i < ctls.size(); ++i)
            {
                m_out << "==============CTL # " << (i + 1) << " ==========\n";
                m_out << "SHA1 Thumbprint:: \n      " << ctls[i]->getSha1() << " \n";
            }
        }

        auto crls = store->getCrls();
        if (crls.empty())
        {
            m_out << "==============No CRLs ==========\n";
        }
        else
        {
            for (size_t i = 0; i < crls.size(); ++i)
            {
                m_out << "==============CRL # " << (i + 1) << " ==========\n";
                m_out << "SHA1 Thumbprint:: \n      " << crls[i]->getSha1() << " \n";
            }
        }

        m_out << "==============================================\n";
        m_out << "CertMgr Succeeded\n";
        return 0;
    }
}

} // namespace commands
} // namespace ccky
