#pragma once

#include <fstream>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "cli/CommandRegistry.h"
#include "commands/CertMgrCommand.h"
#include "commands/SignToolCommand.h"
#include "crypto/TimeFormatter.h"

class CckyTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ccky::crypto::TimeFormatter::setFormatUTC(true);
        registry.registerCommand(std::make_shared<ccky::commands::CertMgrCommand>());
        registry.registerCommand(std::make_shared<ccky::commands::SignToolCommand>());
    }

    std::string getTestDataPath(const std::string& relPath) { return relPath; }

    std::string getTestTextContent(const std::string& relPath)
    {
        std::string path = getTestDataPath(relPath);
        std::ifstream f(path);
        if (!f.is_open())
        {
            ADD_FAILURE() << "Failed to open test data file: " << relPath;
            return "";
        }
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        return content;
    }

    ccky::cli::CommandRegistry registry;
};
