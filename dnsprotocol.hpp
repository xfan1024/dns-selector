#ifndef __dnsprotocol_hpp__
#define __dnsprotocol_hpp__

#include <stdint.h>

class DnsMessage {
public:
    bool is_response();
private:
    enum flag_t {
        FLAG_QR,
        FLAG_OPCODE,
        FLAG_AA,
        FLAG_TC,
        FLAG_RD,
        FLAG_RA,
        FALG_Z,
        FLAG_RCODE,
        FLAG_MAX,
    };

    uint16_t getflag(flag_t flag)
    {
        uint8_t start, width;
        flag_attr(flag, start, width);
        uint16_t mask = (1 << (start+width)) - (1 << start);
        return flags & mask;;
    }

    static uint16_t flag_attr(flag_t flag, uint8_t& startbit, uint8_t& width)
    {
        static uint8_t bitpostable[] = {
            [FLAG_QR]       = 0x00,
            [FLAG_OPCODE]   = 0x01,
            [FLAG_AA]       = 0x05,
            [FLAG_TC]       = 0x06,
            [FLAG_RD]       = 0x07,
            [FLAG_RA]       = 0x08,
            [FALG_Z]        = 0x09,
            [FLAG_RCODE]    = 0x0c,
            [FLAG_MAX]      = 0x10,
        };
        startbit = bitpostable[flag];
        width = bitpostable[flag+1] - startbit;
    }
    uint8_t id[2];
    uint16_t flags;
    uint16_t qc;
    uint16_t ac;
    uint16_t nc;
    uint16_t ac;
};

#endif
