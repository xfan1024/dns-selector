#ifndef USING_BOOST_REGEX
#define USING_BOOST_REGEX 0
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#if !USING_BOOST_REGEX
#include <regex>
namespace regns = std;
#else
#include <boost/regex.hpp>
namespace regns = boost;
#endif
#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind.hpp>
#include <stdint.h>
#include "utils.hpp"

using namespace std;
namespace asio = boost::asio;

static regns::regex pattern_start_resolver(R"(^\[([^\[\]]+)\]$)");
static regns::regex pattern_v4_endpoint(R"(^([^:]+):(\d+)$)");
static regns::regex pattern_v6_endpoint(R"(^\[([^\[\]]+)\]:(\d+)$)");

struct DnsResolverHelper {
    string name;
    vector<asio::ip::udp::endpoint> dnsaddr;
    bool as_answer;
};

typedef vector<DnsResolverHelper> DnsResolverGroup;

struct DomainNode
{
    map<string, DomainNode>     childs;
    int                         self_resolv_index;
    int                         child_resolv_index;
};

class DnsRule {
    using ip_address = asio::ip::address;
    using udp_ep     = asio::ip::udp::endpoint;
public:
    void parse_dns_rule(istream & stream)
    {
        string line;
        regns::smatch match;
        enum parse_state state = s_wait_resolver_name;

        lineno = 0;
        while (1)
        {
            line = getline_trim(stream);
            if (stream.fail()) {
                break;
            }
            lineno++;
            if (line.empty() || line[0] == '#' || line[0] == ';') {
                continue; // comment line
            }
            bool is_resolver_name = regns::regex_match(line, match, pattern_start_resolver);

            if (is_resolver_name) {
                state = s_wait_resolver_name;
            }

            switch (state)
            {
                case s_wait_resolver_name: 
                {
                    if (!is_resolver_name) {
                        cerr << rule_error_prefix() << "expect resolver name" << endl;
                        exit(1);
                    }
                    resolver_groups.emplace_back();
                    DnsResolverHelper& resolver = resolver_groups.back();
                    resolver.name = match[1].str();
                    state = s_wait_resolver_addr;
                    break;
                }
                case s_wait_resolver_addr:
                {
                    DnsResolverHelper& resolver = resolver_groups.back();
                    auto eqpos = line.find('=');
                    if (eqpos != string::npos) {
                        string type = string_lower(line.substr(0, eqpos));
                        if (type == "server") {
                            resolver.as_answer = false;
                        } else if (type == "answer") {
                            resolver.as_answer = true;
                        } else {
                            cerr << rule_error_prefix() << "unknown resolver type: " << type << endl;
                            exit(1);
                        }
                        vector<string> address = string_split(line.substr(eqpos+1), ",");
                        if (resolver.as_answer && address.size() != 1) {
                            cerr << rule_error_prefix() << "multiple anwser" << endl;
                            exit(1);
                        }
                        resolver.dnsaddr.clear();
                        for (const string& s : address) {
                            boost::system::error_code ec;
                            udp_ep ep;
                            if (regns::regex_match(line, match, pattern_v4_endpoint) || regns::regex_match(line, match, pattern_v6_endpoint)) {
                                ip_address ip = ip_address::from_string(match[1].str(), ec);
                                int port_integer = stoi(match[2].str());
                                if (ec || port_integer < 0 || port_integer > 0xffff) {
                                    cerr << rule_error_prefix() << "bad address" << endl;
                                    exit(1);
                                }
                                ep = udp_ep(ip, (unsigned short)port_integer);
                            } else {
                                ip_address ip = ip_address::from_string(s, ec);
                                if (ec) {
                                    cerr << rule_error_prefix() << "bad address" << endl;
                                    exit(1);
                                }
                                ep = udp_ep(ip, 53);
                            }
                            resolver.dnsaddr.emplace_back(ep);
                            if (ec) {
                                cerr << rule_error_prefix() << "bad address: " << s << endl;
                                exit(1);
                            }
                        }
                        state = s_wait_domain_pattern;
                    } else {
                        cerr << rule_error_prefix() << "expect resolver type and address" << endl;
                        exit(1);
                    }
                    break;
                }
                case s_wait_domain_pattern:
                {
                    string& domain = line;
                    bool match_self;
                    bool match_child;

                    if (domain == "*") {
                        match_self = false;
                        match_child = true;
                        domain = "";
                    } else if (string_starts_with(domain, "*.")) {
                        match_self = false;
                        match_child = true;
                        domain = domain.substr(2);
                    } else if (string_starts_with(domain, "$")) {
                        match_self = true;
                        match_child = false;
                        domain = domain.substr(1);
                    } else {
                        match_child = true;
                        match_self = true;
                    }
                    DomainNode &node = search_domain_node_or_create(domain);
                    int top = (int)(resolver_groups.size() - 1);
                    if (match_self) {
                        node.self_resolv_index = top;
                    }
                    if (match_child) {
                        node.child_resolv_index = top;
                    }
                }
            }
        }
        if (domain_root.child_resolv_index < 0) {
            cerr << "no default rule found" << endl;
            exit(1);
        }
    }

    DnsResolverHelper& best_match(const string& domain)
    {
        typedef vector<string> vecstr;
        vecstr layers = string_split(domain, ".");
        reverse(layers.begin(), layers.end());
        DnsResolverHelper * match;
        if (domain_root.child_resolv_index < 0) {
            match = &resolver_always_fail;
        } else {
            match = &resolver_groups[domain_root.child_resolv_index];
        }
        DomainNode *p = &domain_root;
        for (vecstr::size_type i = 0; i < layers.size(); i++) {
            const string& layer = layers[i];
            auto iter = p->childs.find(layer);
            if (iter == p->childs.end()) {
                break;
            } else {
                p = &iter->second;
                if (i == layers.size() - 1 && p->self_resolv_index >= 0) {
                    match = &resolver_groups[p->self_resolv_index];
                } else if (i < layers.size() - 1 && p->child_resolv_index >= 0) {
                    match = &resolver_groups[p->child_resolv_index];
                }
            }
        }
        if (match == &resolver_always_fail) {
            cerr << "warning: no match, please add default rule: " << domain << endl;
        }
        return *match;
    }
private:
    int lineno;
    enum parse_state{
        s_wait_resolver_name,
        s_wait_resolver_addr,
        s_wait_domain_pattern,
    };

    string rule_error_prefix()
    {
        string res = "line ";
        res += to_string(lineno);
        res += " rule format error: ";
        return res;
    }
    DomainNode& search_domain_node_or_create(const string& domain)
    {
        typedef vector<string> vecstr;
        vecstr layers;
        if (!domain.empty()) {
            layers = string_split(domain, ".");
            reverse(layers.begin(), layers.end());
        }

        DomainNode * p = &domain_root;
        for (vecstr::size_type i = 0; i < layers.size(); i++) {
            const string& layer = layers[i];
            auto iter = p->childs.find(layer);
            if (iter == p->childs.end()) {
                auto& newnode = p->childs.emplace(piecewise_construct, forward_as_tuple(layer), forward_as_tuple()).first->second;
                newnode.self_resolv_index = newnode.child_resolv_index = -1;
                p = &newnode;
            } else {
                p = &iter->second;
            }
        }
        return *p;
    }
    DnsResolverHelper   resolver_always_fail;
    DnsResolverGroup    resolver_groups;
    DomainNode          domain_root;
};

class DnsServer
{
    using udp_socket = asio::ip::udp::socket;
    using io_service = asio::io_service;
    using ip_address = asio::ip::address;
    using udp_ep = asio::ip::udp::endpoint;

public:
    DnsServer(io_service& service, DnsRule& rule) : usocket(service), rule(rule)
    {}

    void listen_configure(const string& addr, uint16_t port)
    {
        ip_address ipaddr = ip_address::from_string(addr);
        udp_ep ep(ipaddr, port);
        if (ipaddr.is_v4()) {
            usocket.open(asio::ip::udp::v4());
        } else {
            usocket.open(asio::ip::udp::v6());
        }
        usocket.bind(ep);
    }
    void start_receive_dns_request()
    {
        namespace ph = asio::placeholders;
        const size_t bufsize = 768;
        shared_ptr<uint8_t> buffer(new uint8_t[bufsize]);
        shared_ptr<udp_ep> ep(new udp_ep); 
        
        auto recvbuf = asio::buffer(buffer.get(), bufsize);
        usocket.async_receive_from(recvbuf, *ep, boost::bind(&DnsServer::handle_dns_request, this, ph::error, ep, buffer, ph::bytes_transferred));
    }

    static bool parse_dns_request(const uint8_t * payload, size_t length, string& host)
    {
        stringstream ss;
        const size_t header_size = 12;
        
        if (length < 12) {
            return false;
        }

        uint16_t questions = (payload[4] << 8) | payload[5];
        if (questions == 0) {
            return false;
        }
        size_t curindex = header_size;
        while (curindex < length - 3) {
            size_t len = payload[curindex++];
            if (len < 64 && curindex + len <= length - 3) {
                ss << string((char*)&payload[curindex], len);
                cerr << "debug: " << string((char*)&payload[curindex], len) << endl;
                curindex += len;
                if (payload[curindex]) {
                    ss << '.';
                } else {
                    host = ss.str();
                    return true;
                }
            } else {
                return false;
            }
        }
        return false;
    }

    static string make_dns_response_v4(const uint8_t id[2], const string& host, const ip_address& addr)
    {
        stringstream ss;
        static const uint8_t part1[] = {0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01};
        static const uint8_t part2[] = {0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x4b, 0x00, 0x04};
        ss << string((char*)id, 2) << string((char*)part1, sizeof(part1));
        vector<string> arr = string_split(host, ".");
        for (const string& s : arr)
        {
            ss << (char)s.length() << s;
        }
        ss << (char)0 <<  string((char*)part2, sizeof(part2));
        asio::ip::address_v4 addrv4 = addr.to_v4();
        auto addrb4bytes = addrv4.to_bytes();
        for (auto byte : addrb4bytes) {
            ss << (char)byte;
        }
        string s = ss.str();
        for (char c : s) {
            printf("%02x ", (uint8_t)c);
        }
        cout << endl;
        return s;
    }

    void handle_dns_request(const boost::system::error_code& ec,
                            shared_ptr<udp_ep> ep, 
                            shared_ptr<uint8_t> buffer, 
                            size_t nbytes)
    {
        if (ec) {
            cerr << ec.message() << endl;
            return;
        }
        cout << "request: " << endl;
        for (size_t i = 0; i < nbytes; i++) {
            printf("%02x ", buffer.get()[i]);
        }
        cout << endl;
        start_receive_dns_request();
        string host;
        if (parse_dns_request(buffer.get(), nbytes, host)) {
            cout << "Query " << host << endl;
            DnsResolverHelper& resolver = rule.best_match(host);
            if (resolver.as_answer) {
                ip_address addr = resolver.dnsaddr.front().address();
                string reply = make_dns_response_v4(buffer.get(), host, addr);
                cout << "send reply" << endl;
                usocket.send_to(asio::buffer(reply), *ep);
            } else {
                cout << "us dns: " << endl;
            }
 
            for (auto& ep : resolver.dnsaddr) {
                cout << "    " << ep.address().to_string() << endl;
            }
        }
    }

    void handle_upstream_response()
    {

    }

private:
    int lineno;
    udp_socket usocket;
    DnsRule& rule;
};



int main()
{
    ifstream config("./dns-selector.rule");
    DnsRule rule;
    rule.parse_dns_rule(config);

    asio::io_service io_service;
    DnsServer server{io_service, rule};
    server.listen_configure("0.0.0.0", 53);
    server.start_receive_dns_request();
    io_service.run();
    return 0;
}

