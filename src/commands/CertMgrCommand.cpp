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
#include "crypto/Strings.h"

namespace ccky
{
namespace commands
{

using ccky::crypto::Strings;

bool CertMgrCommand::isSubcommand(const std::string& arg) const
{
    return Strings::equalsCaseInsensitive(arg, "/add") ||
           Strings::equalsCaseInsensitive(arg, "-add") ||
           Strings::equalsCaseInsensitive(arg, "/del") ||
           Strings::equalsCaseInsensitive(arg, "-del") ||
           Strings::equalsCaseInsensitive(arg, "/put") ||
           Strings::equalsCaseInsensitive(arg, "-put");
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

crypto::CertificateStorePtr CertMgrCommand::getStore(
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

void CertMgrCommand::displayError(const std::string& msg, bool shouldPrintHelp)
{
    m_err << "Error: " << msg << "\n";
    if (shouldPrintHelp)
    {
        printHelp();
    }
    else
    {
        m_err << "CertMgr Failed\n";
    }
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
            displayError("Invalid value for -sha1 option", /* shouldPrintHelp = */ true);
            return 1;
        }
        sha1Flag = Strings::toLower(sha1Flag);
    }

    bool isAdd = (Strings::equalsCaseInsensitive(args.subcommand, "/add") ||
                  Strings::equalsCaseInsensitive(args.subcommand, "-add"));
    bool isDel = (Strings::equalsCaseInsensitive(args.subcommand, "/del") ||
                  Strings::equalsCaseInsensitive(args.subcommand, "-del"));
    bool isPut = (Strings::equalsCaseInsensitive(args.subcommand, "/put") ||
                  Strings::equalsCaseInsensitive(args.subcommand, "-put"));

    if (args.positional.empty())
    {
        displayError("Missing SourceStoreName", /* shouldPrintHelp = */ true);
        return 1;
    }
    if ((isAdd || isPut) && args.positional.size() < 2)
    {
        displayError("Has to specify DestinationStoreName", /* shouldPrintHelp = */ true);
        return 1;
    }

    std::string sourceLocation = args.positional[0];
    bool isSourceSystemStore =
        (!args.positionalFlags.empty() && args.positionalFlags[0].count("s") > 0) ||
        (args.hasFlag("s") && args.positionalFlags.size() <= 1);

    if (!isSourceSystemStore && !std::filesystem::exists(sourceLocation))
    {
        displayError("Failed to open the source store");
        return 1;
    }

    crypto::CertificateStorePtr sourceStore;
    try
    {
        sourceStore = getStore(sourceLocation, isSourceSystemStore);
        sourceStore->load(sourceLocation, opts);
    }
    catch (const std::exception&)
    {
        displayError("Failed to open the source store");
        return 1;
    }

    bool hasAll = args.hasFlag("all");
    bool hasC = args.hasFlag("c");
    bool hasCrl = args.hasFlag("crl");
    bool hasCtl = args.hasFlag("ctl");

    if (isAdd || isDel)
    {
        if (!hasAll && !hasC && !hasCrl && !hasCtl)
        {
            if (sourceStore->getStoreType() != crypto::StoreType::CerFile)
            {
                displayError("You must specify -all, -c, -CTL, -CRL for add or delete");
                return 1;
            }
            hasAll = true; // Default to all if nothing specified on CerFile
        }
    }

    if (isAdd)
    {
        std::string destLocation = args.positional[1];
        bool isDestSystemStore =
            (args.positionalFlags.size() > 1 && args.positionalFlags[1].count("s") > 0);

        auto destStore = getStore(destLocation, isDestSystemStore);
        destStore->load(destLocation, opts);

        if (hasAll || hasC)
        {
            for (const auto& c : sourceStore->getCertificates())
            {
                destStore->addCertificate(c);
            }
        }
        if (hasAll || hasCrl)
        {
            for (const auto& c : sourceStore->getCrls())
            {
                destStore->addCrl(c);
            }
        }
        if (hasAll || hasCtl)
        {
            for (const auto& c : sourceStore->getCtls())
            {
                destStore->addCtl(c);
            }
        }

        destStore->save(destLocation, opts);
    }
    else if (isDel)
    {
        std::string cn = args.getFlagValue("n");
        std::string sha1 = sha1Flag;

        if (hasAll || hasC)
        {
            if (!sha1.empty())
            {
                auto certs = sourceStore->getCertificates();
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
                    displayError("Can not find a certificate matching the hash value");
                    return 1;
                }
            }
            sourceStore->deleteCertificate(cn, sha1);
        }
        if (hasAll || hasCrl)
        {
            sourceStore->deleteCrl(sha1);
        }
        if (hasAll || hasCtl)
        {
            sourceStore->deleteCtl(sha1);
        }

        sourceStore->save(sourceLocation, opts);
    }
    else if (isPut)
    {
        if (args.hasFlag("7"))
        {
            opts.format = crypto::StoreFormat::Pkcs7;
        }
        std::string destLocation = args.positional[1];

        if (!hasC && !hasCrl && !hasCtl &&
            sourceStore->getStoreType() != crypto::StoreType::CerFile)
        {
            displayError(
                "Has to specify either -c, or -crl, or -ctl", /* shouldPrintHelp = */ true);
            return 1;
        }

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

        destStore->save(destLocation, opts);
    }
    else
    {
        // Display mode
        bool verbose = args.hasFlag("v");
        auto certs = sourceStore->getCertificates();
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

        auto ctls = sourceStore->getCtls();
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

        auto crls = sourceStore->getCrls();
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
    }

    m_out << "CertMgr Succeeded\n";
    return 0;
}

} // namespace commands
} // namespace ccky
