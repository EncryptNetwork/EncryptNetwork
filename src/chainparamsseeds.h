#ifndef BITCOIN_CHAINPARAMSSEEDS_H
#define BITCOIN_CHAINPARAMSSEEDS_H
/**
 * List of fixed seed nodes for the encrypt network
 * AUTOGENERATED by share/seeds/generate-seeds.py
 *
 * Each line contains a 16-byte IPv6 address and a port.
 * IPv4 as well as onion addresses are wrapped inside a IPv6 address accordingly.
 */
static SeedSpec6 pnSeed6_main[] = {
    {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x25, 0x3b, 0xd1, 0x43}, 2020},
    {{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43, 0x96, 0xeb, 0xb6, 0xfe, 0xe7, 0x80, 0x0a, 0x6f, 0x48, 0x3f}, 2020}};


static SeedSpec6 pnSeed6_test[] = {
    {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x25, 0x3b, 0xd1, 0x43}, 53574},
    {{0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43, 0x96, 0xeb, 0xb6, 0xfe, 0xe7, 0x80, 0x0a, 0x6f, 0x48, 0x3f}, 53574}};
#endif // BITCOIN_CHAINPARAMSSEEDS_H
