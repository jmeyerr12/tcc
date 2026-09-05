#ifndef PARSER_HPP
#define PARSER_HPP

#include <cstddef>
#include <string>
#include <vector>

#include "types.hpp"

std::string trim(const std::string& text);
std::string lowerCopy(std::string text);
bool startsWithText(const std::string& text, const std::string& prefix);
bool isCommentOrBlank(const std::string& line);
bool isRuleLine(const std::string& line);
std::string getRuleProtocol(const std::string& rule);
bool getOptionsBounds(const std::string& rule, std::size_t& openPos, std::size_t& closePos);
std::vector<Token> tokenizeOptions(const std::string& options);
bool parseIntegerOption(const Token& token, const std::string& name, long long& value);
bool parseContentLength(const Token& token, long long& length);

#endif
