# Refactor

Slop patterns that we need to refactor and purge.

## C Arrays

C arrays must be purged in favor of `std::array`.
Hard-coded sizes must be purged in favor of `std::array::size()`.

### DON'T

```cpp
const char* argv[] = {
    "ccky",
    "makecert",
    "/?",
};
auto args = ccky::cli::CliParser::parse(3, const_cast<char**>(argv), registry);
```

### DO

```cpp
std::array argv = {
    "ccky",
    "makecert",
    "/?",
};
auto args = ccky::cli::CliParser::parse(argv.size(), const_cast<char**>(argv.data()), registry);
```

## Backend Exceptions

Rather than throwing generic exceptions in backend classes (i.e. classes in the `crypto` module)
with messages and displaying these messages in the `commands` module, throw typed exceptions instead
with the required context. Use the context to format and display the preferred message.

### DON'T

Backend:
```cpp
if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wSubjectCertFile.c_str(),
        CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr,
        nullptr, nullptr, nullptr, reinterpret_cast<const void**>(&pTempCert)))
{
    throw CckyException(
        "Can't access the certificate of the subject ('" + options.subjectCertFile + "')",
        false);
}
```

Frontend:
```cpp
try
{
    // ...
}
catch (const crypto::CckyException &)
{
    m_out << "Failed\n";
    // Re-throw and expect Command.cpp to display the error message.
    throw;
}
```

### DO

Backend:
```cpp
if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wSubjectCertFile.c_str(),
        CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr,
        nullptr, nullptr, nullptr, reinterpret_cast<const void**>(&pTempCert)))
{
    throw CertGeneratorSubjectAccessException(/* file = */options.subjectCertFile);
}
```

Frontend:
```cpp
try
{
    // ...
}
catch (const crypto::CertGeneratorSubjectAccessException& exception)
{
    std::string error = "Can't access the certificate of the subject";
    if (!exception.file.empty())
    {
        error += " ('" + exception.file + "')";
    }
    displayError(error);
    m_out << "Failed\n";
    return 1;
}
catch (/* More Exceptions */)
{
    // Similar handling.
}
```
