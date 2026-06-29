#include "commands/MakeCertCommand.h"

#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "cli/CommandRegistry.h"
#include "crypto/CckyException.h"
#include "crypto/CertGenerator.h"
#include "crypto/Console.h"
#include "crypto/PrivateKey.h"

namespace ccky
{
namespace commands
{

std::string MakeCertCommand::getDescription() const
{
    return "MakeCert (Makecert.exe) is a command-line CryptoAPI tool that creates an\n"
           "X.509 certificate that is signed by a system test root key or by another\n"
           "specified key.";
}

std::vector<cli::FlagDef> MakeCertCommand::getFlagDefs(const std::string& /*subcommand*/) const
{
    std::vector<cli::FlagDef> flags = {// Basic Options
        {"sk", cli::FlagType::Value, "Subject's key container name; To be created if not present",
            "<keyName>", "Basic Options"},
        {"pe", cli::FlagType::Boolean, "Mark generated private key as exportable", "",
            "Basic Options"},
        {"ss", cli::FlagType::Value,
            "Subject's certificate store name that stores the output \ncertificate", "<store>",
            "Basic Options"},
        {"sr", cli::FlagType::Value,
            "Subject's certificate store location.\n   <CurrentUser|LocalMachine>.  Default to "
            "'CurrentUser'",
            "<location>", "Basic Options"},
        {"#", cli::FlagType::Value, "Serial Number from 1 to 2^31-1.  Default to be unique",
            "<number>", "Basic Options"},
        {"$", cli::FlagType::Value,
            "The signing authority of the certificate\n   <individual|commercial>", "<authority>",
            "Basic Options"},
        {"n", cli::FlagType::Value, "Certificate subject X500 name (eg: CN=Fred Dews)",
            "<X509name>", "Basic Options"},

        // Extended Options
        {"tbs", cli::FlagType::Value, "Certificate or CRL file to be signed", "<file>",
            "Extended Options"},
        {"sc", cli::FlagType::Value, "Subject's certificate file", "<file>", "Extended Options"},
        {"sv", cli::FlagType::Value, "Subject's PVK file; To be created if not present",
            "<pvkFile>", "Extended Options"},
        {"ic", cli::FlagType::Value, "Issuer's certificate file", "<file>", "Extended Options"},
        {"ik", cli::FlagType::Value, "Issuer's key container name", "<keyName>",
            "Extended Options"},
        {"iv", cli::FlagType::Value, "Issuer's PVK file", "<pvkFile>", "Extended Options"},
        {"is", cli::FlagType::Value, "Issuer's certificate store name.", "<store>",
            "Extended Options"},
        {"ir", cli::FlagType::Value,
            "Issuer's certificate store location\n   <CurrentUser|LocalMachine>.  Default to "
            "'CurrentUser'",
            "<location>", "Extended Options"},
        {"in", cli::FlagType::Value, "Issuer's certificate common name.(eg: Fred Dews)", "<name>",
            "Extended Options"},
        {"a", cli::FlagType::Value,
            "The signature's digest algorithm.\n   <md5|sha1|sha256|sha384|sha512>.  Default to "
            "'sha1'",
            "<algorithm>", "Extended Options"},
        {"ip", cli::FlagType::Value, "Issuer's CryptoAPI provider's name", "<provider>",
            "Extended Options"},
        {"iy", cli::FlagType::Value, "Issuer's CryptoAPI provider's type", "<type>",
            "Extended Options"},
        {"sp", cli::FlagType::Value, "Subject's CryptoAPI provider's name", "<provider>",
            "Extended Options"},
        {"sy", cli::FlagType::Value, "Subject's CryptoAPI provider's type", "<type>",
            "Extended Options"},
        {"iky", cli::FlagType::Value, "Issuer key type\n   <signature|exchange|<integer>>.",
            "<keytype>", "Extended Options"},
        {"sky", cli::FlagType::Value, "Subject key type\n   <signature|exchange|<integer>>.",
            "<keytype>", "Extended Options"},
        {"l", cli::FlagType::Value, "Link to the policy information (such as a URL)", "<link>",
            "Extended Options"},
        {"cy", cli::FlagType::Value, "Certificate types\n   <end|authority>", "<certType>",
            "Extended Options"},
        {"b", cli::FlagType::Value, "Start of the validity period; default to now. ",
            "<mm/dd/yyyy>", "Extended Options"},
        {"m", cli::FlagType::Value, "The number of months for the cert validity period", "<number>",
            "Extended Options"},
        {"e", cli::FlagType::Value, "End of validity period; defaults to 2039", "<mm/dd/yyyy>",
            "Extended Options"},
        {"h", cli::FlagType::Value, "Max height of the tree below this cert", "<number>",
            "Extended Options"},
        {"len", cli::FlagType::Value,
            "Generated Key Length (Bits)\n   Default to '2048' for 'RSA' and '512' for 'DSS'",
            "<number>", "Extended Options"},
        {"r", cli::FlagType::Boolean, "Create a self signed certificate", "", "Extended Options"},
        {"nscp", cli::FlagType::Boolean, "Include Netscape client auth extension", "",
            "Extended Options"},
        {"crl", cli::FlagType::Boolean, "Generate a CRL instead of a certificate", "",
            "Extended Options"},
        {"eku", cli::FlagType::Value, "Comma separated enhanced key usage OIDs", "<oid[<,oid>]>",
            "Extended Options"},
        {"?", cli::FlagType::Boolean, "Return a list of basic options", "",
            std::vector<std::string>{"Basic Options", "Extended Options"}, 0, "Basic Options"},
        {"!", cli::FlagType::Boolean, "Return a list of extended options", "",
            std::vector<std::string>{"Basic Options", "Extended Options"}, 0, "Extended Options"}};
    return flags;
}

void MakeCertCommand::registerUsage(cli::CommandRegistry* registry)
{
    cli::UsageBehavior behavior;
    behavior.useDashPrefix = true;
    behavior.basePadWidth = 21;
    behavior.alignValueAtCol = 6;
    behavior.autoAlignDescriptions = true;
    registry->registerCommandUsage("makecert", "",
        "Usage: MakeCert [ basic|extended options] [outputCertificateFile]", getDescription(), {},
        getFlagDefs(""), behavior);
}

void MakeCertCommand::printHelp()
{
    // MakeCert has custom help depending on -? or -!
    // We will implement this in executeImpl when those flags are parsed.
}

int MakeCertCommand::executeImpl(const cli::ParsedArgs& args)
{
    // Default help if no arguments
    if (args.flags.empty() && args.positional.empty())
    {
        m_err << "Error: Please either specify the outputCertificateFile or -ss option\n";
        if (m_registry)
        {
            m_err << m_registry->getUsage(getName(), "", "Basic Options");
        }
        return 1;
    }

    if (args.positional.size() > 1)
    {
        m_err << "Error: Too many parameters\n";
        if (m_registry)
        {
            m_err << m_registry->getUsage(getName(), "", "Basic Options");
        }
        return 1;
    }

    // Extract common parameters
    std::string subjectName = args.getFlagValue("n", MAKECERT_DEFAULT_SUBJECT_NAME);
    std::string outputCertFile = args.positional.empty() ? "" : args.positional.front();

    if (outputCertFile.empty() && !args.hasFlag("ss"))
    {
        m_err << "Error: Please either specify the outputCertificateFile or -ss option\n";
        if (m_registry)
        {
            m_err << m_registry->getUsage(getName(), "", "Basic Options");
        }
        return 1;
    }

    auto printExtendedHelpAndReturn = [this]()
    {
        if (m_registry)
        {
            m_err << m_registry->getUsage(getName(), "", "Extended Options");
        }
        return 1;
    };

    auto printInvalidParameter = [this](const std::string& flagName)
    { m_err << "Error: Invalid input parameter for -" << flagName << " option. \n"; };

    auto invalidParameter = [&](const std::string& flagName)
    {
        printInvalidParameter(flagName);
        return printExtendedHelpAndReturn();
    };

    bool selfSigned = args.hasFlag("r");
    std::string pvkFile = args.getFlagValue("sv");
    std::string keyContainer = args.getFlagValue("sk");

    if (args.hasFlag("iv") && !args.hasFlag("ic"))
    {
        m_err << "Error: Has to specify -ic option. \n";
        return printExtendedHelpAndReturn();
    }

    if (args.hasFlag("ic"))
    {
        if (!args.hasFlag("is") && !args.hasFlag("ik") && !args.hasFlag("iv"))
        {
            m_err << "Error: Either -is or -ik has to be specified. \n";
            return printExtendedHelpAndReturn();
        }
    }

    if (selfSigned &&
        (args.hasFlag("ic") || args.hasFlag("iv") || args.hasFlag("ik") || args.hasFlag("is")))
    {
        m_err << "Error: Can not specify issuer's private key information for self signed "
                 "certificate.  Please use -sp and -sy instead. \n";
        return printExtendedHelpAndReturn();
    }

    // Parse validity dates
    auto tryGetDate = [&](const std::string& flagName, std::string& outVal) -> bool
    {
        if (args.hasFlag(flagName))
        {
            std::string dateStr = args.getFlagValue(flagName);
            int m, d, y;
            if (std::sscanf(dateStr.c_str(), "%d/%d/%d", &m, &d, &y) == 3 && m >= 1 && m <= 12 &&
                d >= 1 && d <= 31 && y >= 1900 && y <= 9999)
            {
                outVal = dateStr;
                return true;
            }
            printInvalidParameter(flagName);
            return false;
        }
        return true;
    };

    std::string startStr = "";
    if (!tryGetDate("b", startStr))
    {
        return printExtendedHelpAndReturn();
    }

    std::string endStr = "";
    if (!tryGetDate("e", endStr))
    {
        return printExtendedHelpAndReturn();
    }

    auto tryGetInt = [&](const std::string& flagName, auto& outVal) -> bool
    {
        if (args.hasFlag(flagName))
        {
            try
            {
                outVal = std::stoi(args.getFlagValue(flagName));
            }
            catch (...)
            {
                printInvalidParameter(flagName);
                return false;
            }
        }
        return true;
    };

    int months = 0;
    if (!tryGetInt("m", months))
    {
        return printExtendedHelpAndReturn();
    }

    std::string algo = args.getFlagValue("a", "sha1");
    int keyLen = 0;
    if (args.hasFlag("len"))
    {
        if (!tryGetInt("len", keyLen))
        {
            return printExtendedHelpAndReturn();
        }
    }

    int keySpec = 2; // Default to AT_SIGNATURE
    if (args.hasFlag("sky"))
    {
        std::string skyVal = args.getFlagValue("sky");
        if (skyVal == "exchange")
        {
            keySpec = 1;
        }
        else if (skyVal == "signature")
        {
            keySpec = 2;
        }
        else
        {
            try
            {
                keySpec = std::stoi(skyVal);
            }
            catch (...)
            {
                return invalidParameter("sky");
            }
        }
    }

    std::string issuerCertFile = args.getFlagValue("ic");
    std::string issuerPvkFile = args.getFlagValue("iv");
    std::string issuerKeyContainer = args.getFlagValue("ik");
    int issuerKeySpec = 2; // Default to AT_SIGNATURE
    if (args.hasFlag("iky"))
    {
        std::string ikyVal = args.getFlagValue("iky");
        if (ikyVal == "exchange")
        {
            issuerKeySpec = 1;
        }
        else if (ikyVal == "signature")
        {
            issuerKeySpec = 2;
        }
        else
        {
            try
            {
                issuerKeySpec = std::stoi(ikyVal);
            }
            catch (...)
            {
                return invalidParameter("iky");
            }
        }
    }

    std::string issuerName = args.getFlagValue("in");
    std::string issuerStoreName = args.getFlagValue("is", "my");
    std::string issuerStoreLocation = args.getFlagValue("ir", "CurrentUser");
    if (args.hasFlag("ir"))
    {
        std::string loc = issuerStoreLocation;
        std::transform(loc.begin(), loc.end(), loc.begin(), ::tolower);
        if (loc != "currentuser" && loc != "localmachine")
        {
            return invalidParameter("ir");
        }
    }

    std::string ssStoreName = args.getFlagValue("ss");
    std::string srStoreLocation = args.getFlagValue("sr", "CurrentUser");
    if (args.hasFlag("sr"))
    {
        std::string loc = srStoreLocation;
        std::transform(loc.begin(), loc.end(), loc.begin(), ::tolower);
        if (loc != "currentuser" && loc != "localmachine")
        {
            return invalidParameter("sr");
        }
    }

    std::string spProviderName = args.getFlagValue("sp");
    int syProviderType = 0;
    if (args.hasFlag("sy"))
    {
        try
        {
            syProviderType = std::stoi(args.getFlagValue("sy"));
        }
        catch (...)
        {
            return invalidParameter("sy");
        }
    }
    else if (args.hasFlag("sp"))
    {
        syProviderType = 1; // Default to PROV_RSA_FULL
    }

    bool exportable = args.hasFlag("pe");

    std::string cyCertType = args.getFlagValue("cy", "end");
    {
        std::string cy = cyCertType;
        std::transform(cy.begin(), cy.end(), cy.begin(), ::tolower);
        if (cy != "end" && cy != "authority")
        {
            return invalidParameter("cy");
        }
        cyCertType = cy;
    }

    int pathLen = 0;
    bool hasPathLen = args.hasFlag("h");
    if (hasPathLen)
    {
        try
        {
            pathLen = std::stoi(args.getFlagValue("h"));
            if (pathLen < 0)
            {
                throw std::exception();
            }
        }
        catch (...)
        {
            return invalidParameter("h");
        }
    }

    std::vector<std::string> ekuOids;
    if (args.hasFlag("eku"))
    {
        std::string ekuVal = args.getFlagValue("eku");
        std::stringstream ss(ekuVal);
        std::string item;
        while (std::getline(ss, item, ','))
        {
            if (item == "codeSigning")
            {
                ekuOids.push_back("1.3.6.1.5.5.7.3.3");
            }
            else if (item == "serverAuth")
            {
                ekuOids.push_back("1.3.6.1.5.5.7.3.1");
            }
            else if (item == "clientAuth")
            {
                ekuOids.push_back("1.3.6.1.5.5.7.3.2");
            }
            else
            {
                ekuOids.push_back(item);
            }
        }
    }

    std::string subjectCertFile = args.getFlagValue("sc");
    std::string policyLink = args.getFlagValue("l");
    bool netscape = args.hasFlag("nscp");

    std::string authority = args.getFlagValue("$");
    if (args.hasFlag("$"))
    {
        std::transform(authority.begin(), authority.end(), authority.begin(), ::tolower);
        if (authority != "individual" && authority != "commercial")
        {
            m_err << "Error: Invalid signing authority\n";
            if (m_registry)
            {
                m_err << m_registry->getUsage(getName(), "", "Basic Options");
            }
            return 1;
        }
    }

    crypto::MakeCertOptions opts;
    opts.subjectName = subjectName;
    opts.outputCertFile = outputCertFile;
    opts.selfSigned = selfSigned;
    opts.pvkFile = pvkFile;
    opts.keyContainer = keyContainer;
    opts.startStr = startStr;
    opts.endStr = endStr;
    opts.months = months;
    opts.algo = algo;
    opts.keyLen = keyLen;
    opts.keySpec = keySpec;
    opts.ssStoreName = ssStoreName;
    opts.srStoreLocation = srStoreLocation;
    opts.spProviderName = spProviderName;
    opts.syProviderType = syProviderType;
    opts.exportable = exportable;
    opts.cyCertType = cyCertType;
    opts.pathLen = pathLen;
    opts.hasPathLen = hasPathLen;
    opts.hasStoreOptions =
        args.hasFlag("ss") || args.hasFlag("sr") || args.hasFlag("is") || args.hasFlag("ir");
    opts.hasSerialNum = args.hasFlag("#");
    if (opts.hasSerialNum)
    {
        long serialVal = 0;
        if (!tryGetInt("#", serialVal))
        {
            return printExtendedHelpAndReturn();
        }
        opts.serialNum = serialVal;
    }
    opts.hasIssuerCert = args.hasFlag("ic") || args.hasFlag("in");
    opts.issuerCertFile = issuerCertFile;
    opts.issuerPvkFile = issuerPvkFile;
    opts.issuerKeyContainer = issuerKeyContainer;
    opts.issuerKeySpec = issuerKeySpec;
    opts.issuerName = issuerName;
    opts.issuerStoreName = issuerStoreName;
    opts.issuerStoreLocation = issuerStoreLocation;
    opts.ekuOids = ekuOids;
    opts.subjectCertFile = subjectCertFile;
    opts.policyLink = policyLink;
    opts.netscape = netscape;
    opts.authority = authority;

    opts.createPasswordCallback = [&]()
    {
        m_err << std::left << std::setw(18) << "Key:" << "Subject Key\n";
        m_err << std::left << std::setw(18) << "Password:" << std::flush;
        std::string p1 = crypto::Console::askPassword(m_in, m_err);

        m_err << std::left << std::setw(18) << "Confirm Password:" << std::flush;
        std::string p2 = crypto::Console::askPassword(m_in, m_err);

        if (p1 != p2)
        {
            throw crypto::CckyException("ERROR: Passwords do not match.", false);
        }
        return p1;
    };

    opts.openPasswordCallback = [&]()
    {
        m_err << std::left << std::setw(10) << "Key:" << "Subject Key\n";
        m_err << std::left << std::setw(10) << "Password:" << std::flush;
        return crypto::Console::askPassword(m_in, m_err);
    };

    opts.openIssuerPasswordCallback = [this]()
    {
        m_err << std::left << std::setw(18) << "Key:" << "Issuer Signature\n";
        m_err << std::left << std::setw(18) << "Password:" << std::flush;
        return crypto::Console::askPassword(m_in, m_err);
    };

    crypto::PrivateKeyPtr subjectKey;
    try
    {
        try
        {
            subjectKey = crypto::CertGenerator::loadSubjectKey(opts);
        }
        catch (const crypto::CckyException&)
        {
            // Swallow initial error for PVK to allow fallback to key generation.
            if (!opts.subjectCertFile.empty())
            {
                throw;
            }
        }

        if (!subjectKey)
        {
            if (!opts.pvkFile.empty() && std::filesystem::exists(opts.pvkFile))
            {
                m_err << "Error: File already exists for the subject ('" << opts.pvkFile << "')\n";
            }
            subjectKey = crypto::CertGenerator::generateSubjectKey(opts);
        }

        crypto::CertGenerator::generateCertificate(opts, subjectKey);
        m_out << "Succeeded\n";
        return 0;
    }
    catch (const crypto::CckyException&)
    {
        m_out << "Failed\n";
        throw;
    }
    catch (const std::exception&)
    {
        m_out << "Failed\n";
        return 1;
    }
    catch (...)
    {
        m_out << "Failed\n";
        return 1;
    }
}

void MakeCertCommand::displayError(const std::exception& e)
{
    m_err << "Error: " << e.what() << "\n";
}

void MakeCertCommand::displayError(const std::string& msg)
{
    // Output error message
    m_err << "Error: " << msg << "\n";
}

} // namespace commands
} // namespace ccky
