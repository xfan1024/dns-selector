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

regns::regex pattern_start_resolver(R"(^\[([^\[\]]+)\]$)");

using ipaddress = boost::asio::ip::address;

struct DnsResolverHelper {
    string name;
    vector<ipaddress> dnsaddr;
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
public:
    void parse_dns_rule(istream & stream)
    {
        string line;
        regns::smatch match;
        enum parse_state state = s_wait_resolver_name;

        int lineno = 0;
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
                        cerr << parse_dns_rule_error_prefix(lineno) << "expect resolver name" << endl;
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
                            cerr << parse_dns_rule_error_prefix(lineno) << "unknown resolver type: " << type << endl;
                            exit(1);
                        }
                        vector<string> address = string_split(line.substr(eqpos+1), ",");
                        if (resolver.as_answer && address.size() != 1) {
                            cerr << parse_dns_rule_error_prefix(lineno) << "multiple anwser" << endl;
                            exit(1);
                        }
                        resolver.dnsaddr.clear();
                        for (const string& s : address) {
                            boost::system::error_code ec;
                            resolver.dnsaddr.emplace_back(ipaddress::from_string(s, ec));
                            if (ec) {
                                cerr << parse_dns_rule_error_prefix(lineno) << "bad address: " << s << endl;
                                exit(1);
                            }
                        }
                        state = s_wait_domain_pattern;
                    } else {
                        cerr << parse_dns_rule_error_prefix(lineno) << "expect resolver type and address" << endl;
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
    enum parse_state{
        s_wait_resolver_name,
        s_wait_resolver_addr,
        s_wait_domain_pattern,
    };
    static string parse_dns_rule_error_prefix(int line)
    {
        string res = "line ";
        res += to_string(line);
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
    using udp_socket = boost::asio::ip::udp::socket;
    using io_service = boost::asio::io_service;
    using ip_address = boost::asio::ip::address;
    using udp_ep = boost::asio::ip::udp::endpoint;

public:
    DnsServer(io_service& service, DnsRule& rule) : usocket(service), rule(rule)
    {}

    void listen_configure(const string& addr, uint16_t port)
    {
        ip_address ipaddr = ip_address::from_string(addr);
        udp_ep ep(ipaddr, port);
        if (ipaddr.is_v4()) {
            usocket.open(boost::asio::ip::udp::v4());
        } else {
            usocket.open(boost::asio::ip::udp::v6());
        }
        usocket.bind(ep);
    }
    void start_receive_dns_request()
    {
        namespace ph = boost::asio::placeholders;
        const size_t bufsize = 768;
        shared_ptr<uint8_t> buffer(new uint8_t[bufsize]);
        shared_ptr<udp_ep> ep(new udp_ep); 
        
        auto recvbuf = boost::asio::buffer(buffer.get(), bufsize);
        usocket.async_receive_from(recvbuf, *ep, boost::bind(&DnsServer::handle_dns_request, this, ph::error, ep, buffer, ph::bytes_transferred));
    }

    static bool parse_dns_request(uint8_t * payload, size_t length, string& host)
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

    void handle_dns_request(const boost::system::error_code& ec,
                            shared_ptr<udp_ep> ep, 
                            shared_ptr<uint8_t> buffer, 
                            size_t nbytes)
    {
        if (ec) {
            cerr << ec.message() << endl;
            return;
        }
        start_receive_dns_request();
        string host;
        if (parse_dns_request(buffer.get(), nbytes, host)) {
            cout << "Query " << host << endl;
            DnsResolverHelper& resolver = rule.best_match(host);
            if (resolver.as_answer) {
                cout << "as answer: " << endl;
            } else {
                cout << "us dns: " << endl;
            }
 
            for (auto& addr : resolver.dnsaddr) {
                cout << "    " << addr.to_string() << endl;
            }
        }
    }

    void handle_upstream_response()
    {

    }

private:
    udp_socket usocket;
    DnsRule& rule;
};



int main()
{
    ifstream config("./dns-selector.rule");
    DnsRule rule;
    rule.parse_dns_rule(config);

    boost::asio::io_service io_service;
    DnsServer server{io_service, rule};
    server.listen_configure("0.0.0.0", 6666);
    server.start_receive_dns_request();
    io_service.run();
    return 0;
}