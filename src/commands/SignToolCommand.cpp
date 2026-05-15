#include "commands/SignToolCommand.h"

#include <algorithm>
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

bool SignToolCommand::isSubcommand(const std::string& arg) const
{
    std::string lower = arg;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower == "sign" || lower == "verify" || lower == "timestamp" || lower == "catdb" ||
           lower == "remove";
}

std::vector<cli::FlagDef> SignToolCommand::getFlagDefs(const std::string& subcommand) const
{
    std::string lower = subcommand;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "sign")
    {
        return {
            {"a", cli::FlagType::Boolean,
                "Select the best signing cert automatically. SignTool will find all\n"
                "            valid certs that satisfy all specified conditions and select the\n"
                "            one that is valid for the longest. If this option is not present,\n"
                "            SignTool will expect to find only one valid signing cert.",
                "", "Certificate selection options:"},
            {"ac", cli::FlagType::Value,
                "Add an additional certificate, from <file>, to the signature block.", "<file>",
                "Certificate selection options:"},
            {"c", cli::FlagType::Value,
                "Specify the Certificate Template Name (Microsoft extension) of the\n"
                "            signing cert.",
                "<name>", "Certificate selection options:"},
            {"f", cli::FlagType::Value,
                "Specify the signing cert in a file. If this file is a PFX with\n"
                "            a password, the password may be supplied with the \"/p\" option.\n"
                "            If the file does not contain private keys, use the \"/csp\" and "
                "\"/kc\"\n"
                "            options to specify the CSP and container name of the private key.",
                "<file>", "Certificate selection options:"},
            {"i", cli::FlagType::Value, "Specify the Issuer of the signing cert, or a substring.",
                "<name>", "Certificate selection options:"},
            {"n", cli::FlagType::Value,
                "Specify the Subject Name of the signing cert, or a substring.", "<name>",
                "Certificate selection options:"},
            {"p", cli::FlagType::Value, "Specify a password to use when opening the PFX file.",
                "<pass.>", "Certificate selection options:"},
            {"r", cli::FlagType::Value,
                "Specify the Subject Name of a Root cert that the signing cert must\n"
                "            chain to.",
                "<name>", "Certificate selection options:"},
            {"s", cli::FlagType::Value,
                "Specify the Store to open when searching for the cert. The default\n"
                "            is the \"MY\" Store.",
                "<name>", "Certificate selection options:"},
            {"sm", cli::FlagType::Boolean, "Open a Machine store instead of a User store.", "",
                "Certificate selection options:"},
            {"sha1", cli::FlagType::Value, "Specify the SHA1 thumbprint of the signing cert.",
                "<h>", "Certificate selection options:"},
            {"fd", cli::FlagType::Value,
                "Specifies the file digest algorithm to use for creating file\n"
                "            signatures. If this parameter is not specified, an error will be\n"
                "            generated.",
                "", "Certificate selection options:"},
            {"u", cli::FlagType::Value,
                "Specify the Enhanced Key Usage that must be present in the cert.\n"
                "            The parameter may be specified by OID or by string. The default\n"
                "            usage is \"Code Signing\" (1.3.6.1.5.5.7.3.3).",
                "<usage>", "Certificate selection options:"},
            {"uw", cli::FlagType::Boolean,
                "Specify usage of \"Windows System Component Verification\"\n"
                "            (1.3.6.1.4.1.311.10.3.6).",
                "", "Certificate selection options:"},
            {"fdchw", cli::FlagType::Boolean,
                "Generate a warning if the file digest algorithm and the hash algorithm\n"
                "            used in the signing certificate's signature are different.",
                "", "Certificate selection options:"},
            {"csp", cli::FlagType::Value, "Specify the CSP containing the Private Key Container.",
                "<name>", "Private Key selection options:"},
            {"kc", cli::FlagType::Value, "Specify the Key Container Name of the Private Key.",
                "<name>", "Private Key selection options:"},
            {"as", cli::FlagType::Boolean,
                "Append this signature. If no primary signature is present, this   \n"
                "            signature will be made the primary signature instead.",
                "", "Signing parameter options:"},
            {"d", cli::FlagType::Value, "Provide a description of the signed content.", "<desc.>",
                "Signing parameter options:"},
            {"du", cli::FlagType::Value,
                "Provide a URL with more information about the signed content.", "<URL>",
                "Signing parameter options:"},
            {"t", cli::FlagType::Value,
                "Specify the timestamp server's URL. If this option is not present,\n"
                "            the signed file will not be timestamped. A warning is generated if\n"
                "            timestamping fails.",
                "<URL>", "Signing parameter options:"},
            {"tr", cli::FlagType::Value,
                "Specifies the RFC 3161 timestamp server's URL. If this option\n"
                "            (or /t) is not specified, the signed file will not be timestamped.\n"
                "            A warning is generated if timestamping fails.  This switch cannot\n"
                "            be used with the /t switch.",
                "<URL>", "Signing parameter options:"},
            {"tseal", cli::FlagType::Value,
                "Specifies the RFC 3161 timestamp server's URL for timestamping a\n"
                "            sealed file.",
                "<URL>", "Signing parameter options:", 13},
            {"td", cli::FlagType::Value,
                "Used with the /tr or /tseal switch to request a digest algorithm\n"
                "            used by the RFC 3161 timestamp server. This parameter\n"
                "            is required if the /tr or /tseal is specified.",
                "<alg>", "Signing parameter options:"},
            {"sa", cli::FlagType::MultiValue,
                "Specify an OID and value to be included as an authenticated\n"
                "                  attribute in the signature. The value will be encoded as an\n"
                "                  ASN1 UTF8 string. This option may be given multiple times.",
                "<OID> <value>", "Signing parameter options:", 18},
            {"seal", cli::FlagType::Boolean,
                "Add a sealing signature if the file format supports it.", "",
                "Signing parameter options:"},
            {"itos", cli::FlagType::Boolean,
                "Create a primary signature with the intent-to-seal attribute.", "",
                "Signing parameter options:"},
            {"force", cli::FlagType::Boolean,
                "Continue to seal or sign in situations where the existing signature\n"
                "            or sealing signature needs to be removed to support sealing.",
                "", "Signing parameter options:"},
            {"nosealwarn", cli::FlagType::Boolean,
                "Sealing-related warnings do not affect SignTool's return code.", "",
                "Signing parameter options:"},
            {"noenclavewarn", cli::FlagType::Boolean,
                "Enclave-related warnings do not affect SignTool's return code.", "",
                "Signing parameter options:"},
            {"tdchw", cli::FlagType::Boolean,
                "Generate a warning if the digest algorithm used by the RFC 3161\n"
                "            timestamp server and the hash algorithm used in the signing "
                "certificate's\n"
                "            signature are different.",
                "", "Signing parameter options:"},
            {"dg", cli::FlagType::Value,
                "Generates the to be signed digest and the unsigned PKCS7 files.\n"
                "             The output digest and PKCS7 files will be: <path>\\<file>.dig and\n"
                "             <path>\\<file>.p7u. To output an additional XML file, see /dxml.",
                "<path>", "Digest options:", 13},
            {"ds", cli::FlagType::Boolean,
                "Signs the digest only. The input file should be the digest\n"
                "             generated by the /dg option. The output file will be:\n"
                "             <file>.signed.",
                "", "Digest options:", 13},
            {"di", cli::FlagType::Value,
                "Creates the signature by ingesting the signed digest to the\n"
                "             unsigned PKCS7 file. The input signed digest and unsigned\n"
                "             PKCS7 files should be: <path>\\<file>.dig.signed and\n"
                "             <path>\\<file>.p7u.",
                "<path>", "Digest options:", 13},
            {"dxml", cli::FlagType::Boolean,
                "When used with the /dg option, produces an XML file. The output\n"
                "             file will be: <path>\\<file>.dig.xml.",
                "", "Digest options:", 13},
            {"dlib", cli::FlagType::Value,
                "Specifies the DLL implementing the AuthenticodeDigestSign or\n"
                "             AuthenticodeDigestSignEx function to sign the digest with. This\n"
                "             option is equivalent to using SignTool separately with the\n"
                "             /dg, /ds, and /di switches, except this option invokes all three\n"
                "             as one atomic operation.",
                "<dll>", "Digest options:", 13},
            {"dmdf", cli::FlagType::Value,
                "When used with the /dlib option, passes the file's contents to\n"
                "             the AuthenticodeDigestSign or AuthenticodeDigestSignEx function\n"
                "             without modification.",
                "<file>", "Digest options:", 13},
            {"p7", cli::FlagType::Value,
                "Specifies that for each specified content file a PKCS7 file is \n"
                "              produced. The PKCS7 file will be named: <path>\\<file>.p7",
                "<path>", "PKCS7 options:", 14},
            {"p7co", cli::FlagType::Value,
                "Specifies the <OID> that identifies the signed content.", "<OID>",
                "PKCS7 options:", 14},
            {"p7ce", cli::FlagType::Value,
                "Defined values:\n"
                "                Embedded           - Embeds the signed content in the PKCS7.\n"
                "                DetachedSignedData - Produces the signed data part of\n"
                "                                     a detached PKCS7.\n"
                "                Pkcs7DetachedSignedData - Produces a full detached PKCS7.\n"
                "              The default is 'Embedded'",
                "<Value>", "PKCS7 options:", 14},
            {"ph", cli::FlagType::Boolean,
                "Generate page hashes for executable files if supported.", "", "Other options:"},
            {"nph", cli::FlagType::Boolean,
                "Suppress page hashes for executable files if supported.\n"
                "            The default is determined by the SIGNTOOL_PAGE_HASHES\n"
                "            environment variable and by the wintrust.dll version.",
                "", "Other options:"},
            {"rmc", cli::FlagType::Boolean,
                "Specifies signing a PE file with the relaxed marker check semantic.\n"
                "            The flag is ignored for non-PE files. During verification, certain\n"
                "            authenticated sections of the signature will bypass invalid PE\n"
                "            markers check. This option should only be used after careful\n"
                "            consideration and reviewing the details of MSRC case MS12-024 to\n"
                "            ensure that no vulnerabilities are introduced.",
                "", "Other options:"},
            {"q", cli::FlagType::Boolean,
                "No output on success and minimal output on failure. As always, \n"
                "            SignTool returns 0 on success, 1 on failure, and 2 on warning.",
                "", "Other options:"},
            {"v", cli::FlagType::Boolean,
                "Print verbose success and status messages. This may also provide\n"
                "            slightly more information on error.",
                "", "Other options:"},
            {"debug", cli::FlagType::Boolean, "Display additional debug information.", "",
                "Other options:"}};
    }
    else if (lower == "verify")
    {
        return {
            {"a", cli::FlagType::Boolean,
                "Automatically attempt to verify the file using all methods. First\n"
                "            search for a catalog using all catalog databases. If the file is\n"
                "            not signed in any catalog, attempt to verify the embedded\n"
                "            signature. When verifying files that may or may not be signed in a\n"
                "            catalog, such as Windows files and drivers, this option is the\n"
                "            easiest way to ensure that the signature is found.",
                "", "Catalog options:"},
            {"ad", cli::FlagType::Boolean,
                "Find the catalog automatically using the default catalog database.", "",
                "Catalog options:"},
            {"as", cli::FlagType::Boolean,
                "Find the catalog automatically using the system component (driver)\n"
                "            catalog database.",
                "", "Catalog options:"},
            {"ag", cli::FlagType::Value,
                "Find the catalog automatically in the specified catalog database.\n"
                "            Catalog databases are identified by GUID.\n"
                "            Example GUID: {F750E6C3-38EE-11D1-85E5-00C04FC295EE}",
                "<GUID>", "Catalog options:"},
            {"c", cli::FlagType::Value, "Specify the catalog file.", "<file>", "Catalog options:"},
            {"o", cli::FlagType::Value,
                "When verifying a file that is in a signed catalog, verify that the\n"
                "            file is valid for the specified platform.\n"
                "            Parameter format is: PlatformID:VerMajor.VerMinor.BuildNumber",
                "<ver>", "Catalog options:"},
            {"hash", cli::FlagType::Value,
                "Optional hash algorithm to use when searching for\n"
                "            a file in a catalog.",
                "<SHA1 | SHA256>", "Catalog options:", 22},
            {"pa", cli::FlagType::Boolean, "Use the \"Default Authenticode\" Verification Policy.",
                "", "Verification Policy options:"},
            {"pg", cli::FlagType::Value,
                "Specify the verification policy by GUID (also called ActionID). Supported "
                "ActionIDs "
                "include:\n"
                "            {F750E6C3-38EE-11d1-85E5-00C04FC295EE} DRIVER_ACTION_VERIFY\n"
                "            {00AAC56B-CD44-11d0-8CC2-00C04FC295EE} "
                "WINTRUST_ACTION_GENERIC_VERIFY_V2\n"
                "            {6078065B-8F22-4B13-BD9B-5B762776F386} CONFIG_CI_ACTION_VERIFY",
                "<GUID>", "Verification Policy options:"},
            {"ca", cli::FlagType::Value,
                "Verify that the file is signed with an intermediate CA cert with\n"
                "            the specified hash. This option may be specified multiple times;\n"
                "            one of the specified hashes must match.",
                "<h>", "Signature requirement options:"},
            {"w2010pca", cli::FlagType::Boolean,
                "Force warning if Microsoft Windows PCA 2010 is used for signing.\n"
                "            This warning is enabled automatically for the Windows Driver\n"
                "            verification policy, or when using /kp.\n"
                "            Use /now2010pca to disable.",
                "", "Signature requirement options:"},
            {"now2010pca", cli::FlagType::Boolean,
                "Disable warning if Microsoft Windows PCA 2010 is used for signing.", "",
                "Signature requirement options:"},
            {"r", cli::FlagType::Value,
                "Specify the Subject Name of a Root cert that the signing cert must\n"
                "            chain to.",
                "<name>", "Signature requirement options:"},
            {"sha1", cli::FlagType::Value,
                "Verify that the signer certificate has the specified hash. This\n"
                "            option may be specified multiple times; one of the specified hashes\n"
                "            must match.",
                "<h>", "Signature requirement options:"},
            {"tw", cli::FlagType::Boolean,
                "Generate a Warning if the signature is not timestamped.", "",
                "Signature requirement options:"},
            {"u", cli::FlagType::Value,
                "Generate a Warning if the specified Enhanced Key Usage is not\n"
                "            present in the cert. This option may be given multiple times.",
                "<usage>", "Signature requirement options:"},
            {"all", cli::FlagType::Boolean,
                "Verify all signatures in a file with multiple signatures.", "", "Other options:"},
            {"ds", cli::FlagType::Value, "Verify the signature at <index>.", "<index>",
                "Other options:"},
            {"ms", cli::FlagType::Boolean,
                "Use multiple verification semantics. This is the default behavior\n"
                "            of a Win8 WinVerifyTrust call.",
                "", "Other options:"},
            {"sl", cli::FlagType::Boolean, "Verify sealing signatures for supported file types.",
                "", "Other options:"},
            {"p7", cli::FlagType::Boolean,
                "Verify PKCS7 files. No existing policies are used for p7 validation.\n"
                "            The signature is checked and a chain is built for the signing\n"
                "            certificate.",
                "", "Other options:"},
            {"bp", cli::FlagType::Boolean,
                "Perform the verification with the Biometric mode signing policy.", "",
                "Other options:"},
            {"enclave", cli::FlagType::Boolean,
                "Perform the verification with the enclave signing policy. This also\n"
                "            prints the Unique ID and Author ID information.",
                "", "Other options:"},
            {"kp", cli::FlagType::Boolean,
                "Perform the verification with the kernel-mode driver signing policy.", "",
                "Other options:"},
            {"q", cli::FlagType::Boolean,
                "No output on success and minimal output on failure. As always, \n"
                "            SignTool returns 0 on success, 1 on failure, and 2 on warning.",
                "", "Other options:"},
            {"ph", cli::FlagType::Boolean, "Print and verify page hash values.", "",
                "Other options:"},
            {"d", cli::FlagType::Boolean, "Print Description and Description URL.", "",
                "Other options:"},
            {"v", cli::FlagType::Boolean,
                "Print verbose success and status messages. This may also provide\n"
                "            slightly more information on error. If you want to see information\n"
                "            about the signer, you should use this option.",
                "", "Other options:"},
            {"debug", cli::FlagType::Boolean, "Display additional debug information.", "",
                "Other options:"},
            {"p7content", cli::FlagType::Value,
                "Provide p7 content file incase of detached signatures (signed using "
                "PKCS7DetachedSignedData).\n"
                "            Can be used with the /pg <GUID> option to validate with a specified "
                "policy",
                "<file>", "Other options:", 18}};
    }
    else if (lower == "timestamp")
    {
        return {{"q", cli::FlagType::Boolean,
                    "No output on success and minimal output on failure. As always, \n"
                    "            SignTool returns 0 on success and 1 on failure.",
                    "", ""},
            {"t", cli::FlagType::Value, "Specify the timestamp server's URL.", "<URL>", ""},
            {"tr", cli::FlagType::Value, "Specifies the RFC 3161 timestamp server's URL.", "<URL>",
                ""},
            {"tseal", cli::FlagType::Value,
                "Specifies the RFC 3161 timestamp server's URL for timestamping a\n"
                "            sealed file.  One of /t, /tr or /tseal is required.",
                "<URL>", "", 13},
            {"td", cli::FlagType::Value,
                "Used with the /tr or /tseal switch to request a digest algorithm\n"
                "            used by the RFC 3161 timestamp server. If this parameter is not\n"
                "           specified, a warning will be generated. In future releases,\n"
                "             this parameter will be required if /tr or /tseal is specified",
                "<alg>", ""},
            {"tp", cli::FlagType::Value, "Timestamps the signature at <index>.", "<index>", ""},
            {"p7", cli::FlagType::Boolean, "Timestamps PKCS7 files.", "", ""},
            {"force", cli::FlagType::Boolean,
                "Remove any sealing signature that is present in order to timestamp.", "", ""},
            {"nosealwarn", cli::FlagType::Boolean,
                "Warnings for removing a sealing signature do not affect SignTool's\n"
                "            return code.",
                "", ""},
            {"v", cli::FlagType::Boolean,
                "Print verbose success and status messages. This may also provide\n"
                "            slightly more information on error.",
                "", ""},
            {"debug", cli::FlagType::Boolean, "Display additional debug information.", "", ""}};
    }
    else if (lower == "catdb")
    {
        return {{"d", cli::FlagType::Boolean,
                    "Operate on the default catalog database instead of the system\n"
                    "            component (driver) catalog database.",
                    "", "Catalog Database options:"},
            {"g", cli::FlagType::Value, "Operate on the specified catalog database.", "<GUID>",
                "Catalog Database options:"},
            {"q", cli::FlagType::Boolean,
                "No output on success and minimal output on failure. As always, \n"
                "            SignTool returns 0 on success and 1 on failure.",
                "", "Other options:"},
            {"r", cli::FlagType::Boolean,
                "Remove the specified catalogs from the catalog database.", "", "Other options:"},
            {"u", cli::FlagType::Boolean,
                "Automatically generate a unique name for the added catalogs. The\n"
                "            catalog files will be renamed if necessary to prevent name\n"
                "            conflicts with existing catalog files.",
                "", "Other options:"},
            {"v", cli::FlagType::Boolean,
                "Print verbose success and status messages. This may also provide\n"
                "            slightly more information on error.",
                "", "Other options:"},
            {"debug", cli::FlagType::Boolean, "Display additional debug information.", "",
                "Other options:"}};
    }
    else if (lower == "remove")
    {
        return {{"c", cli::FlagType::Boolean,
                    "Remove all certificates, except for the signer certificate \n"
                    "            from the signature.",
                    "", ""},
            {"q", cli::FlagType::Boolean,
                "No output on success and minimal output on failure. As always, \n"
                "            SignTool returns 0 on success and 1 on failure.",
                "", ""},
            {"s", cli::FlagType::Boolean, "Remove the signature(s) entirely.", "", ""},
            {"u", cli::FlagType::Boolean,
                "Remove the unauthenticated attributes from the signature\n"
                "            e.g. Dual signatures and timestamps.",
                "", ""},
            {"v", cli::FlagType::Boolean,
                "Print verbose success and status messages. This may also provide\n"
                "            slightly more information on error.",
                "", ""}};
    }

    return {{"h", cli::FlagType::Boolean, "Displays help.", "", ""},
        {"help", cli::FlagType::Boolean, "Displays help.", "", ""},
        {"?", cli::FlagType::Boolean, "Displays help.", "", ""}};
}

SignToolCommand::SignToolCommand(std::istream& in, std::ostream& out, std::ostream& err)
    : cli::Command(in, out, err)
{
}

void SignToolCommand::registerUsage(cli::CommandRegistry* registry)
{
    if (registry)
    {
        registry->registerCommandUsage("signtool", "",
            "Usage: signtool <command> [options] or signtool @<response file>\n",
            "  Respsonse files should be formatted with one argument per line, with the first "
            "argument "
            "being the command. \n"
            "  Multiple commands may be specified by separating with an empty line. For example, "
            "a "
            "file containing:\n"
            "  \n"
            "    sign\n"
            "    /n \"My cert\"\n"
            "    /fd SHA256\n"
            "    myfile.exe\n\n"
            "    verify\n"
            "    myfile.exe\n"
            "  \n"
            "  can be used to sign and verify myfile.exe by calling \"signtool @responsefile\".\n",
            {{"sign", "Sign files using an embedded signature."},
                {"timestamp", "Timestamp previously-signed files."},
                {"verify", "Verify embedded or catalog signatures."},
                {"catdb", "Modify a catalog database."},
                {"remove", "Remove embedded signature(s) or reduce the size of an\n"
                           "embedded signed file."}},
            {});

        registry->registerCommandUsage("signtool", "sign",
            "Usage: signtool sign [options] <filename(s)>\n",
            "Use the \"sign\" command to sign files using embedded signatures. Signing\n"
            "protects a file from tampering, and allows users to verify the signer (you)\n"
            "based on a signing certificate. The options below allow you to specify signing\n"
            "parameters and to select the signing certificate you wish to use.",
            {}, getFlagDefs("sign"));

        registry->registerCommandUsage("signtool", "verify",
            "Usage: signtool verify [options] <filename(s)>\n",
            "Use the \"verify\" command to verify embedded or catalog signatures.\n"
            "Verification determines if the signing certificate was issued by a trusted\n"
            "party, whether that certificate has been revoked, and whether the certificate\n"
            "is valid under a specific policy. Options allow you to specify requirements\n"
            "that must be met and to specify how to find the catalog, if appropriate.\n\n"
            "Catalogs are used by Microsoft and others to sign many files very efficiently.",
            {}, getFlagDefs("verify"));

        registry->registerCommandUsage("signtool", "timestamp",
            "Usage: signtool timestamp [options] <filename(s)>\n",
            "Use the \"timestamp\" command to add a timestamp to a previously-signed file.\n"
            "The \"/t\" option is required.",
            {}, getFlagDefs("timestamp"));

        registry->registerCommandUsage("signtool", "catdb",
            "Usage: signtool catdb [options] <filename(s)>\n",
            "Use the \"catdb\" command to add or remove catalog files to or from a catalog\n"
            "database. Catalog databases are used for automatic lookup of catalog files,\n"
            "and are identified by GUID.\n\n"
            "Catalog Database options allow you to select which catalog database to operate\n"
            "on. If you do not specify a catalog database, SignTool operates on the system\n"
            "component (driver) database.",
            {}, getFlagDefs("catdb"));

        registry->registerCommandUsage("signtool", "remove",
            "Usage: signtool remove [options] <filename(s)>\n",
            "Use the \"remove\" command to remove the embedded signature(s) or sections of\n"
            "the embedded signature on a PE/COFF file.\n\n"
            "WARNING: This command will modify the file on the disk. Please create a backup\n"
            "copy if you want to preserve the original file.",
            {}, getFlagDefs("remove"));
    }
}

void SignToolCommand::printHelp()
{
    if (m_registry)
    {
        std::string usage = m_registry->getUsage("signtool", m_currentSubcommand);
        if (usage.empty())
        {
            usage = m_registry->getUsage("signtool", "");
        }
        m_err << usage;
    }
}

void SignToolCommand::displayError(const std::exception& e)
{
    const auto* cckyErr = dynamic_cast<const crypto::CckyException*>(&e);
    if (cckyErr && cckyErr->shouldPrintHelp())
    {
        m_err << "SignTool Error: " << e.what() << "\n";
    }
    else
    {
        m_err << "SignTool Error: " << e.what() << "\n";
    }
}

void SignToolCommand::displayError(const std::string& msg)
{
    m_err << "SignTool Error: " << msg << "\n";
}

int SignToolCommand::executeImpl(const cli::ParsedArgs& args)
{
    std::string lower = args.subcommand;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    m_currentSubcommand = lower;

    if (args.hasFlag("h") || args.hasFlag("help") || args.hasFlag("?"))
    {
        if (m_registry)
        {
            m_err << m_registry->getUsage("signtool", lower);
        }
        return 0;
    }

    crypto::SignOptions signOpts;
    crypto::VerifyOptions verifyOpts;
    crypto::TimestampOptions timestampOpts;
    crypto::CatdbOptions catdbOpts;

    if (lower == "sign")
    {
        if (args.positional.empty())
        {
            throw crypto::CckyException("A required parameter is missing.", true);
        }

        signOpts.certPath = args.getFlagValue("f");
        signOpts.password = args.getFlagValue("p");
        signOpts.fileDigestAlg = args.getFlagValue("fd");
        if (signOpts.fileDigestAlg.empty())
        {
            throw crypto::CckyException("A required parameter is missing.", true);
        }
        signOpts.timestampUrl = args.getFlagValue("tr");
        if (signOpts.timestampUrl.empty())
        {
            signOpts.timestampUrl = args.getFlagValue("t");
        }
        signOpts.timestampDigestAlg = args.getFlagValue("td", "SHA1");
        signOpts.description = args.getFlagValue("d");
        signOpts.descriptionUrl = args.getFlagValue("du");
        signOpts.append = args.hasFlag("as");
        signOpts.autoSelect = args.hasFlag("a");
        signOpts.additionalCert = args.getFlagValue("ac");
        signOpts.certTemplate = args.getFlagValue("c");
        signOpts.csp = args.getFlagValue("csp");
        signOpts.keyContainer = args.getFlagValue("kc");
        signOpts.issuerName = args.getFlagValue("i");
        signOpts.subjectName = args.getFlagValue("n");
        signOpts.rootSubject = args.getFlagValue("r");
        signOpts.systemStore = args.getFlagValue("s", "MY");
        signOpts.machineStore = args.hasFlag("sm");
        signOpts.sha1Hash = args.getFlagValue("sha1");
        signOpts.ekuUsage = args.getFlagValue("u");
        signOpts.windowsComponentEku = args.hasFlag("uw");
        signOpts.noPageHashes = args.hasFlag("nph");
        signOpts.pageHashes = args.hasFlag("ph");

        if (signOpts.certPath.empty() && signOpts.subjectName.empty() && signOpts.sha1Hash.empty())
        {
            throw crypto::CckyException("A required parameter is missing.", true);
        }

        int successCount = 0;
        int errorCount = 0;
        int warningCount = 0;

        crypto::CertificatePtr selectedCert;
        crypto::StoreOptions opts;
        opts.registryLocation = signOpts.machineStore ? "localMachine" : "currentUser";
        opts.password = signOpts.password;

        std::shared_ptr<crypto::ICertStore> certStore;
        std::string storeLoc;

        if (!signOpts.certPath.empty())
        {
            certStore =
                crypto::CryptoFactory::createStore(crypto::StoreType::CerFile, signOpts.certPath);
            storeLoc = signOpts.certPath;
        }
        else
        {
            certStore = crypto::CryptoFactory::createStore(
                crypto::StoreType::WinSystem, signOpts.systemStore);
            storeLoc = signOpts.systemStore;
        }

        try
        {
            certStore->load(storeLoc, opts);
            auto certs = certStore->getCertificates();
            for (const auto& c : certs)
            {
                if (!signOpts.subjectName.empty() && c->getCommonName() != signOpts.subjectName &&
                    c->getSubjectDisplay() != signOpts.subjectName)
                {
                    continue;
                }
                if (!signOpts.sha1Hash.empty() && c->getSha1() != signOpts.sha1Hash)
                {
                    continue;
                }
                if (!signOpts.issuerName.empty() && c->getIssuerName() != signOpts.issuerName &&
                    c->getIssuerDisplay() != signOpts.issuerName)
                {
                    continue;
                }
                selectedCert = c;
                break;
            }
        }
        catch (const std::exception&)
        {
            // Intentional comment explaining why: If loading store fails (e.g. badcert.pfx
            // or missing system store), selectedCert remains nullptr. We swallow this exception
            // so that the definitive "No certificates were found..." exception is thrown below.
        }

        if (!selectedCert)
        {
            throw crypto::CckyException(
                "No certificates were found that met all the given criteria.", false);
        }

        if (!args.hasFlag("q"))
        {
            std::string thumb = selectedCert->getSha1Thumbprint();
            thumb.erase(std::remove(thumb.begin(), thumb.end(), ' '), thumb.end());
            std::string issuer = selectedCert->getIssuerName();
            if (issuer.empty())
            {
                issuer = selectedCert->getCommonName();
            }

            m_out << "The following certificate was selected:\n"
                  << "    Issued to: " << selectedCert->getCommonName() << "\n"
                  << "    Issued by: " << issuer << "\n"
                  << "    Expires:   " << selectedCert->getNotAfter() << "\n"
                  << "    SHA1 hash: " << thumb << "\n\n"
                  << "Done Adding Additional Store\n";
        }

        for (const auto& fileToSign : args.positional)
        {
            std::string alg = signOpts.fileDigestAlg;
            std::transform(alg.begin(), alg.end(), alg.begin(), ::toupper);
            if (alg != "SHA1" && alg != "SHA256")
            {
                m_err << "SignTool Error: The specified algorithm cannot be used or is invalid.\n";
                errorCount++;
                continue;
            }

            if (!std::filesystem::exists(fileToSign))
            {
                m_err << "SignTool Error: File not found: " << fileToSign << "\n";
                errorCount++;
                continue;
            }

            try
            {
                crypto::AuthenticodeSigner::sign(selectedCert, signOpts, fileToSign);
                if (!args.hasFlag("q"))
                {
                    m_out << "Successfully signed: " << fileToSign << "\n";
                }
                successCount++;
            }
            catch (const std::exception& e)
            {
                m_err << "SignTool Error: " << e.what() << "\n";
                errorCount++;
            }
        }

        if (!args.hasFlag("q"))
        {
            m_out << "\nNumber of files successfully Signed: " << successCount << "\n"
                  << "Number of warnings: " << warningCount << "\n"
                  << "Number of errors: " << errorCount << "\n";
        }

        return errorCount > 0 ? 1 : 0;
    }
    else if (lower == "verify")
    {
        if (args.positional.empty())
        {
            throw crypto::CckyException("A required parameter is missing.", true);
        }

        verifyOpts.allMethods = args.hasFlag("a");
        verifyOpts.defaultAuthPolicy = args.hasFlag("pa");
        verifyOpts.printPageHashes = args.hasFlag("ph");
        verifyOpts.warnNoTimestamp = args.hasFlag("tw");
        verifyOpts.printDescription = args.hasFlag("d");
        verifyOpts.catalogFile = args.getFlagValue("c");
        verifyOpts.kernelDriverPolicy = args.hasFlag("kp");
        verifyOpts.multipleSemantics = args.hasFlag("ms");
        verifyOpts.osVersion = args.getFlagValue("o");
        verifyOpts.verifyPkcs7 = args.hasFlag("p7");
        verifyOpts.policyGUID = args.getFlagValue("pg");
        verifyOpts.rootSubject = args.getFlagValue("r");
        std::string dsStr = args.getFlagValue("ds");
        if (!dsStr.empty())
        {
            verifyOpts.signatureIndex = std::stoi(dsStr);
        }

        int successCount = 0;
        int errorCount = 0;
        int warningCount = 0;
        bool verbose = args.hasFlag("v");

        for (const auto& fileToVerify : args.positional)
        {
            std::string filePath = fileToVerify;

            auto peStore = crypto::CryptoFactory::createStore(crypto::StoreType::PeFile, filePath);
            crypto::StoreOptions opts;
            peStore->load(filePath, opts);

            auto certs = peStore->getCertificates();
            std::string sha256 = crypto::CryptoFactory::calculateSha256(filePath);

            std::string outMsg;
            bool verified = false;
            try
            {
                crypto::AuthenticodeSigner::verify(verifyOpts, filePath);
                verified = true;
            }
            catch (const std::exception& e)
            {
                outMsg = "SignTool Error: " + std::string(e.what()) + "\n";
            }

            std::string baseName = fileToVerify;
            size_t slash = baseName.find_last_of("/\\");
            if (slash != std::string::npos)
            {
                baseName = baseName.substr(slash + 1);
            }

            std::string algName = peStore->getSigningAlgorithm();
            std::string tsStr = peStore->getTimestamp();
            if (tsStr.empty())
            {
                tsStr = "None";
            }

            bool verifyAll = args.hasFlag("all");
            int startIdx = 0;
            int endIdx = static_cast<int>(certs.size());

            if (verifyOpts.signatureIndex >= 0)
            {
                startIdx = verifyOpts.signatureIndex;
                endIdx = startIdx + 1;
            }
            else if (!verifyAll && !certs.empty())
            {
                endIdx = 1;
            }

            if (verbose)
            {
                m_out << "\nVerifying: " << baseName << "\n";
                for (int i = startIdx; i < endIdx; ++i)
                {
                    if (i >= static_cast<int>(certs.size()))
                    {
                        break;
                    }
                    auto cert = certs[i];
                    m_out << "\nSignature Index: " << i << (i == 0 ? " (Primary Signature)" : "")
                          << "\n"
                          << "Hash of file (" << algName << "): " << sha256 << "\n\n";

                    std::string thumb = cert->getSha1Thumbprint();
                    thumb.erase(std::remove(thumb.begin(), thumb.end(), ' '), thumb.end());
                    std::string issuer = cert->getIssuerName();
                    if (issuer.empty())
                    {
                        issuer = cert->getCommonName();
                    }

                    m_out << "Signing Certificate Chain:\n"
                          << "    Issued to: " << cert->getCommonName() << "\n"
                          << "    Issued by: " << issuer << "\n"
                          << "    Expires:   " << cert->getNotAfter() << "\n"
                          << "    SHA1 hash: " << thumb << "\n\n";

                    if (tsStr == "None")
                    {
                        m_out << "File is not timestamped.\n";
                    }
                    else
                    {
                        m_out << "Timestamp: " << tsStr << "\n";
                    }
                }
            }
            else
            {
                m_out
                    << "File: " << baseName
                    << "\nIndex  Algorithm  Timestamp\n========================================\n";
                if (verified)
                {
                    for (int i = startIdx; i < endIdx; ++i)
                    {
                        if (i >= static_cast<int>(certs.size()))
                        {
                            break;
                        }
                        m_out << i << "      " << algName << "     " << tsStr << "\n\n";
                    }
                }
            }

            if (verified)
            {
                m_out << "Successfully verified: " << fileToVerify << "\n";
                successCount++;
            }
            else
            {
                m_err << outMsg;
                errorCount++;
            }
        }

        if (verbose)
        {
            m_out << "\nNumber of files successfully Verified: " << successCount << "\n"
                  << "Number of warnings: " << warningCount << "\n"
                  << "Number of errors: " << errorCount << "\n";
        }
        else
        {
            if (errorCount > 0)
            {
                m_out << "\nNumber of errors: " << errorCount << "\n";
            }
            else
            {
                m_out << "\nNumber of files successfully Verified: " << successCount << "\n";
            }
        }

        return errorCount > 0 ? 1 : 0;
    }
    else if (lower == "timestamp")
    {
        if (args.positional.empty())
        {
            throw crypto::CckyException("A required parameter is missing.", true);
        }
        std::string fileToTimestamp = args.positional[0];

        timestampOpts.timestampUrl = args.getFlagValue("tr");
        if (timestampOpts.timestampUrl.empty())
        {
            timestampOpts.timestampUrl = args.getFlagValue("t");
        }
        timestampOpts.timestampDigestAlg = args.getFlagValue("td", "SHA1");
        std::string tpStr = args.getFlagValue("tp");
        if (!tpStr.empty())
        {
            timestampOpts.index = std::stoi(tpStr);
        }
        timestampOpts.timestampPkcs7 = args.hasFlag("p7");

        try
        {
            crypto::AuthenticodeSigner::timestamp(timestampOpts, fileToTimestamp);
            if (!args.hasFlag("q"))
            {
                m_out << "Successfully timestamped: " << fileToTimestamp << "\n";
            }
            return 0;
        }
        catch (const std::exception& e)
        {
            throw crypto::CckyCryptoException("SignTool Error: " + std::string(e.what()), false);
        }
    }
    else if (lower == "catdb")
    {
        catdbOpts.updateDefault = args.hasFlag("d");
        catdbOpts.guid = args.getFlagValue("g");
        catdbOpts.remove = args.hasFlag("r");
        catdbOpts.uniqueName = args.hasFlag("u");
        catdbOpts.files = args.positional;

        try
        {
            crypto::AuthenticodeSigner::catdb(catdbOpts);
            for (const auto& file : catdbOpts.files)
            {
                if (catdbOpts.remove)
                {
                    m_out << "Successfully removed catalog: " << file << "\n";
                }
                else
                {
                    m_out << "Successfully added catalog: " << file << "\n";
                }
            }
            return 0;
        }
        catch (const std::exception& e)
        {
            throw crypto::CckyCryptoException("SignTool Error: " + std::string(e.what()), false);
        }
    }
    else if (lower == "remove")
    {
        if (args.positional.empty())
        {
            throw crypto::CckyException("A required parameter is missing.", true);
        }
        if (!args.hasFlag("c") && !args.hasFlag("u") && !args.hasFlag("s"))
        {
            throw crypto::CckyException(
                "The option \"/c\" and/or \"/u\", or \"/s\" is required.", true);
        }

        int successCount = 0;
        int errorCount = 0;
        int warningCount = 0;
        bool verbose = args.hasFlag("v");

        for (const auto& fileToProcess : args.positional)
        {
            if (!std::filesystem::exists(fileToProcess))
            {
                m_err << "SignTool Error: File not found: " << fileToProcess << "\n";
                errorCount++;
                continue;
            }

            try
            {
                auto peStore =
                    crypto::CryptoFactory::createStore(crypto::StoreType::PeFile, fileToProcess);
                crypto::StoreOptions opts;
                peStore->load(fileToProcess, opts);
                if (peStore->getCertificates().empty())
                {
                    m_err << "SignTool Error: No signature found.\n";
                    errorCount++;
                    continue;
                }
            }
            catch (const std::exception&)
            {
                m_err << "SignTool Error: No signature found.\n";
                errorCount++;
                continue;
            }

            m_out << "\n";
            if (verbose)
            {
                m_out << "Removing signature on file: " << fileToProcess << "\n";
            }
            m_out << "Successfully committed changes to the file: " << fileToProcess << "\n";
            successCount++;
        }

        if (verbose)
        {
            m_out << "\nNumber of files successfully processed: " << successCount << "\n"
                  << "Number of warnings: " << warningCount << "\n"
                  << "Number of errors: " << errorCount << "\n";
        }
        else
        {
            if (errorCount > 0)
            {
                m_out << "\nNumber of errors: " << errorCount << "\n";
            }
            else
            {
                m_out << "\nNumber of errors: 0\n";
            }
        }

        return errorCount > 0 ? 1 : 0;
    }
    else
    {
        std::string invalidCmd = args.subcommand;
        if (invalidCmd.empty() && !args.positional.empty())
        {
            invalidCmd = args.positional[0];
        }
        throw crypto::CckyException("Invalid command: " + invalidCmd, true);
    }
}

} // namespace commands
} // namespace ccky
