#include <string>
#include <vector>
#include <string.h>

std::string string_trim(const std::string& str)
{
    std::string::size_type start, end, i;
    start = end = std::string::npos;

    for (i = 0; i < str.length(); i++) {
        if (!isspace(str[i])) {
            start = i;
            break;
        }
    }
    if (start == end) {
        return "";
    }
    for (i = str.length(); i > 0; i--) {
        if (!isspace(str[i-1])) {
            end = i;
            break;
        }
    }
    return str.substr(start, end - start);
}

std::string string_upper(const std::string& str)
{
    std::string res(str.length(), 0);
    for (std::string::size_type i = 0; i < str.length(); i++) {
        res[i] = toupper(str[i]);
    }
    return res;
}

std::string string_lower(const std::string& str)
{
    std::string res(str.length(), 0);
    for (std::string::size_type i = 0; i < str.length(); i++) {
        res[i] = tolower(str[i]);
    }
    return res;
}

std::vector<std::string> string_split(const std::string& str, const std::string& delims = " ")
{
    std::vector<std::string> res;
    std::string::size_type current, previous;
    current = previous = 0;
    
    while ( (current = str.find_first_of(delims, previous)) != std::string::npos ) {
        res.emplace_back(str.substr(previous, current - previous));
        previous = current + 1;
    }
    res.emplace_back(str.substr(previous));
    return res;
}

bool string_starts_with(const std::string& str, const std::string& sub) {
    return (sub.length() <= str.length() && sub == str.substr(0, sub.length()));
}

std::string getline_trim(std::istream &is)
{
    std::string line;
    std::getline(is, line);
    return string_trim(line);
}

