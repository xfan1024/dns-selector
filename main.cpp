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
#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind.hpp>
#include <stdint.h>
#include "utils.hpp"

using namespace std;

namespace posix_time = boost::posix_time;

namespace asio      = boost::asio;
using io_service    = asio::io_service;
using ip_address    = asio::ip::address;
using ip_address_v4 = asio::ip::address_v4;
using ip_address_v6 = asio::ip::address_v6;
using udp_ep        = asio::ip::udp::endpoint;
using udp_socket    = asio::ip::udp::socket;

using boost_error   = boost::system::error_code;

namespace po        = boost::program_options;

static regns::regex pattern_start_resolver(R"(^\[([^\[\]]+)\]$)");

static bool endpoint_from_string(string s, udp_ep& ep)
{
    static regns::regex pattern_v4_endpoint(R"(^([^:]+):(\d+)$)");
    static regns::regex pattern_v6_endpoint(R"(^\[([^\[\]]+)\]:(\d+)$)");

    regns::smatch match;
    boost_error ec;

    if (regns::regex_match(s, match, pattern_v4_endpoint) || regns::regex_match(s, match, pattern_v6_endpoint)) {
        ip_address ip = ip_address::from_string(match[1].str(), ec);
        int port_integer = stoi(match[2].str());
        if (ec || port_integer < 0 || port_integer > 0xffff) {
            return false;
        }
        ep = udp_ep(ip, (unsigned short)port_integer);
    } else {
        ip_address ip = ip_address::from_string(s, ec);
        if (ec) {
            return false;
        }
        ep = udp_ep(ip, 53);
    }
    return true;
}

static string endpoint_to_string(const udp_ep& ep)
{
    stringstream ss;
    if (ep.address().is_v4()) {
        ss << ep.address().to_string();
    } else {
        ss << "[" << ep.address().to_string() << "]";
    }
    ss << ":" << ep.port();
    return ss.str();
}


struct DnsResolverHelper {
    string name;
    vector<udp_ep> dnsaddr;
    bool as_answer;
    friend ostream& operator<<(ostream& os, const DnsResolverHelper& resolver)
    {
        if (resolver.as_answer) {
            os << "answer: ";
        } else {
            os << "dns server: ";
        }
        if (resolver.dnsaddr.empty()) {
            os << " <empty>";
        } else {
            bool first = true;
            for (auto& ep : resolver.dnsaddr) {
                if (first) {
                    first = false;
                } else {
                    os << ", ";
                }
                if (resolver.as_answer || ep.port() == 53) {
                    os << ep.address().to_string();
                } else {
                    os << endpoint_to_string(ep);
                }
            }
        }
        return os;
    }
};

using DnsResolverGroup = vector<DnsResolverHelper>;

struct DnsConfig
{
    udp_ep  bindaddr;
    string  rulefile;
    int     max_conn;

    DnsConfig(int argc, char* argv[])
    {
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help,h", "print help message")
            ("listen,l", po::value<string>()->default_value("127.0.0.1:1053"), "listen address")
            ("rule,r", po::value<string>()->default_value("/etc/dns-selector.rule"), "rule file")
            ("max_conn,m", po::value<int>()->default_value(8), "number of dns request handle at same time")
        ;
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        if (vm.count("help")) {
            cout << desc << endl;
            exit(1);
        }
        string listenstr = vm["listen"].as<string>();
        if (!endpoint_from_string(listenstr, bindaddr)) {
            cerr << "error: bad listen address " << listenstr << endl;
            exit(1);
        }
        rulefile = vm["rule"].as<string>();
        max_conn = vm["max_conn"].as<int>();
        cout << "listen on: " << endpoint_to_string(bindaddr) << endl;
        cout << " max_conn: " << max_conn << endl;
        cout << " rulefile: " << rulefile << endl;
    }
};

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
                        resolver.dnsaddr.clear();
                        for (const string& s : address) {
                            udp_ep ep;
                            if (s.empty()) {
                                continue;
                            }
                            if (!endpoint_from_string(s, ep)) {
                                cerr << rule_error_prefix() << "bad address: " << s << endl;
                                exit(1);
                            }
                            resolver.dnsaddr.emplace_back(ep);
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

    DnsResolverHelper& default_resolver()
    {
        return resolver_groups[domain_root.child_resolv_index];
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
public:
    DnsServer(DnsConfig& config) 
        : usocket(asio_service), config(config)
    {
        ifstream rule_config(config.rulefile);
        if (!rule_config) {
            cerr << "error: can not open rule file: " << config.rulefile << endl;
            exit(1);
        }
        rule.parse_dns_rule(rule_config);
    }

    void start()
    {
        if (usocket.is_open()) {
            usocket.close();
        }
        if (config.bindaddr.address().is_v4()) {
            usocket.open(asio::ip::udp::v4());
        } else {
            usocket.open(asio::ip::udp::v6());
        }
        usocket.bind(config.bindaddr);
        for (int i = 0; i < config.max_conn; i++) {
            start_receive_dns_request();
        }
        asio_service.run();
    }


private:
    void start_receive_dns_request()
    {
        namespace ph = asio::placeholders;
        const size_t bufsize = 768;
        shared_ptr<uint8_t> buffer(new uint8_t[bufsize]);
        shared_ptr<udp_ep> ep(new udp_ep); 
        
        auto recvbuf = asio::buffer(buffer.get(), bufsize);
        usocket.async_receive_from(recvbuf, *ep, boost::bind(&DnsServer::handle_dns_request, this, ph::error, ep, buffer, ph::bytes_transferred));
    }

    void handle_upstream_response(const boost_error& ec,
                            shared_ptr<udp_ep> ep,
                            shared_ptr<asio::deadline_timer> deadline_timer_ptr,
                            shared_ptr< vector<udp_socket> > dns_clients,
                            udp_socket& dns_client,
                            shared_ptr<uint8_t> buffer, 
                            size_t nbytes)
    {
        if (ec) {
            if (ec == asio::error::operation_aborted) {
                return;
            }
            cerr << __FUNCTION__ << ": " << ec.message() << endl;
            return;
        }
        deadline_timer_ptr->cancel();
        usocket.send_to(asio::buffer(buffer.get(), nbytes), *ep);
        start_receive_dns_request();
        for (auto& client : *dns_clients) {
            client.close();
        }
    }

    void handle_dns_request(const boost_error& ec,
                            shared_ptr<udp_ep> ep, 
                            shared_ptr<uint8_t> buffer, 
                            size_t nbytes)
    {
        if (ec) {
            cerr << __FUNCTION__ << ": " << ec.message() << endl;
            return;
        }
        string host;
        QType type;
        
        DnsResolverHelper * resolver_ptr = nullptr;
        if (parse_dns_request(buffer.get(), nbytes, type, host)) {
            cout << "query " << host;
            DnsResolverHelper& r = rule.best_match(host);
            resolver_ptr = &r;
        } else {
            cout << "could parse request, so using default resolver";
            DnsResolverHelper& r = rule.default_resolver();
            resolver_ptr = &r;
        }


        DnsResolverHelper& resolver = *resolver_ptr;
        cout << ": " << resolver << endl;
        if (resolver.as_answer) {
            string reply = make_dns_response(buffer.get(), type, host, resolver.dnsaddr);
            usocket.send_to(asio::buffer(reply), *ep);
            start_receive_dns_request();
        } else {
            if (resolver.dnsaddr.empty()) {
                cout << "dns server list is empty, ignore this request" << endl;
                start_receive_dns_request();
                return;
            }

            const size_t bufsize = 768;
            
            shared_ptr< vector<udp_socket> > dns_clients(new vector<udp_socket>);
            shared_ptr<asio::deadline_timer> deadline_timer_ptr(new asio::deadline_timer(asio_service, posix_time::seconds(3)));
            
            auto timeout_callback = [this, dns_clients, deadline_timer_ptr, &resolver](const boost_error& ec) {
                if (ec) {
                    return;
                }
                cerr << "error: request upstream timeout: " << resolver << endl;
                for (auto& client : *dns_clients) {
                    client.close();
                }
                start_receive_dns_request();
                return;
            };

            deadline_timer_ptr->async_wait(timeout_callback);

            namespace ph = asio::placeholders;
            for (auto& server : resolver.dnsaddr) {
                dns_clients->emplace_back(asio_service);
                udp_socket& dns_client = dns_clients->back();

                if (server.address().is_v4()) {
                    dns_client.open(asio::ip::udp::v4());
                } else {
                    dns_client.open(asio::ip::udp::v6());
                }
                dns_client.connect(server);
                shared_ptr<uint8_t> buffer_for_upstream(new uint8_t[bufsize]);
                auto recvbuf = asio::buffer(buffer_for_upstream.get(), bufsize);
                auto callback = boost::bind(&DnsServer::handle_upstream_response, this, ph::error, ep, deadline_timer_ptr, dns_clients, ref(dns_client), buffer_for_upstream, ph::bytes_transferred);
                dns_client.send(asio::buffer(buffer.get(), nbytes));
                dns_client.async_receive(recvbuf, callback);
            }
        }
    }


    enum QType { QType_A, QType_AAAA, QType_ANY, QType_UNKNOWN };

    static QType qtype_decode(const uint8_t data[2]) {
        if (data[0] == 0x00 && data[1] == 0x01) {
            return QType_A;
        } else if (data[0] == 0x00 && data[1] == 0x1c) {
            return QType_AAAA;
        } else if (data[0] == 0x00 && data[1] == 0xff) {
            return QType_ANY;
        } else {
            return QType_UNKNOWN;
        }
    }

    static void qtype_encode(QType type, uint8_t data[2]) {
        data[0] = 0x00;
        switch (type)
        {
        case QType_A:
            data[1] = 0x01;
            break;
        case QType_AAAA:
            data[1] = 0x1c;
            break;
        case QType_ANY:
            data[1] = 0xff;
            break;
        default:
            cerr << "error: no support qtype: " << (int)type << endl;
            exit(1);
        }
    }

    static bool parse_dns_request(const uint8_t * payload, size_t length, QType &type, string& host)
    {
        stringstream ss;
        const size_t header_size = 12;
        
        if (length < 12) {
            return false;
        }

        uint16_t questions = (payload[4] << 8) | payload[5];
        if (questions != 1) {
            return false;
        }
        size_t curindex = header_size;
        while (curindex < length - 5) {
            size_t len = payload[curindex++];
            if (len < 64 && curindex + len <= length - 5) {
                ss << string((char*)&payload[curindex], len);
                curindex += len;
                if (payload[curindex]) {
                    ss << '.';
                } else {
                    curindex++;
                    QType t = qtype_decode(&payload[curindex]);
                    if (t == QType_UNKNOWN) {
                        return false;
                    }
                    type = t;
                    host = ss.str();
                    return true;
                }
            } else {
                return false;
            }
        }
        return false;
    }

    static void make_dns_response_append_record(ostream& os, QType type, const uint8_t * data, uint16_t len)
    {
        uint8_t tmpdata[] = {
                                0xc0, 0x0c,             // Name
                                0x00, 0x00,             // type
                                0x00, 0x01,             // class: IN
                                0x00, 0x00, 0x02, 0x58, // ttl: 600
                            };
        qtype_encode(type, tmpdata+2);
        os.write((char*)tmpdata, sizeof(tmpdata));
        tmpdata[0] = len >> 8;
        tmpdata[1] = len & 0xff;
        os.write((char*)tmpdata, 2);
        os.write((char*)data, len);
    }

    static string make_dns_response(const uint8_t id[2], QType type, const string& host, const vector<udp_ep> vaddr)
    {
        stringstream ss;
        uint8_t part_header[] = { 
            0x81, 0x80,     // flags
            0x00, 0x01,     // Questions
            0x00, 0x01,     // RRs 
            0x00, 0x00,     // Authority RRs
            0x00, 0x00,     // Additional RRs
        };

        ip_address_v4 addr_v4;
        ip_address_v6 addr_v6;
        bool reply_v4, reply_v6, v4, v6;
        v4 = v6 = reply_v4 = reply_v6 = false;

        if (type == QType_A) {
            v4 = true;
        } else if(type == QType_AAAA) {
            v6 = true;
        } else {
            v4 = v6 = true;
        }

        uint8_t rrs = 0;
        for (auto& ep : vaddr)
        {
            if (v4 && !reply_v4 && ep.address().is_v4()) {
                rrs++;
                reply_v4 = true;
                addr_v4 = ep.address().to_v4();
            }
            if (v6 && !reply_v6 && ep.address().is_v6()) {
                rrs++;
                reply_v6 = true;
                addr_v6 = ep.address().to_v6();
            }
        }
        part_header[5] = rrs;
        ss.write((char*)id, 2);
        ss.write((char*)part_header, sizeof(part_header));
        vector<string> arr = string_split(host, ".");
        for (const string& s : arr)
        {
            ss << (char)s.length() << s;
        }
        ss << (char)0;
        {
            uint8_t data[4] = {0x00, 0x00, 0x00, 0x01};
            qtype_encode(type, data);
            ss.write((char*)data, 4);
        }
        
        if (reply_v4) {
            auto data = addr_v4.to_bytes();
            make_dns_response_append_record(ss, QType_A, data.data(), data.size());
        }
        if (reply_v6) {
            auto data = addr_v6.to_bytes();
            make_dns_response_append_record(ss, QType_AAAA, data.data(), data.size());
        }

        string s = ss.str();
        return s;
    }

    int lineno;
    
    io_service asio_service;
    udp_socket usocket;
    DnsRule rule;
    DnsConfig& config;
};



int main(int argc, char *argv[])
{
    DnsConfig config(argc, argv);
    DnsServer server(config);
    server.start();
    return 0;
}

