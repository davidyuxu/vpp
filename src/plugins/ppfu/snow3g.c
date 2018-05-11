#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/dpo/dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <ppfu/snow3g.h>


/* move to context
u32 ctx->LFSR_S0 = 0x00;
u32 ctx->LFSR_S1 = 0x00;
u32 ctx->LFSR_S2 = 0x00;
u32 ctx->LFSR_S3 = 0x00;
u32 ctx->LFSR_S4 = 0x00;
u32 ctx->LFSR_S5 = 0x00;
u32 ctx->LFSR_S6 = 0x00;
u32 ctx->LFSR_S7 = 0x00;
u32 ctx->LFSR_S8 = 0x00;
u32 ctx->LFSR_S9 = 0x00;
u32 ctx->LFSR_S10 = 0x00;
u32 ctx->LFSR_S11 = 0x00;
u32 ctx->LFSR_S12 = 0x00;
u32 ctx->LFSR_S13 = 0x00;
u32 ctx->LFSR_S14 = 0x00;
u32 ctx->LFSR_S15 = 0x00;



u32 ctx->FSM_R1 = 0x00;
u32 ctx->FSM_R2 = 0x00;
u32 ctx->FSM_R3 = 0x00;
*/
  /* Rijndael S-box SR */

u8 SR[256] = {
	0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
	0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
	0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
	0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
	0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
	0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
	0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
	0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
	0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
	0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
	0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
	0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
	0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
	0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
	0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
	0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

  /* S-box SQ */

u8 SQ[256] = {
    0x25,0x24,0x73,0x67,0xD7,0xAE,0x5C,0x30,0xA4,0xEE,0x6E,0xCB,0x7D,0xB5,0x82,0xDB,
    0xE4,0x8E,0x48,0x49,0x4F,0x5D,0x6A,0x78,0x70,0x88,0xE8,0x5F,0x5E,0x84,0x65,0xE2,
    0xD8,0xE9,0xCC,0xED,0x40,0x2F,0x11,0x28,0x57,0xD2,0xAC,0xE3,0x4A,0x15,0x1B,0xB9,
    0xB2,0x80,0x85,0xA6,0x2E,0x02,0x47,0x29,0x07,0x4B,0x0E,0xC1,0x51,0xAA,0x89,0xD4,
    0xCA,0x01,0x46,0xB3,0xEF,0xDD,0x44,0x7B,0xC2,0x7F,0xBE,0xC3,0x9F,0x20,0x4C,0x64,
    0x83,0xA2,0x68,0x42,0x13,0xB4,0x41,0xCD,0xBA,0xC6,0xBB,0x6D,0x4D,0x71,0x21,0xF4,
    0x8D,0xB0,0xE5,0x93,0xFE,0x8F,0xE6,0xCF,0x43,0x45,0x31,0x22,0x37,0x36,0x96,0xFA,
    0xBC,0x0F,0x08,0x52,0x1D,0x55,0x1A,0xC5,0x4E,0x23,0x69,0x7A,0x92,0xFF,0x5B,0x5A,
    0xEB,0x9A,0x1C,0xA9,0xD1,0x7E,0x0D,0xFC,0x50,0x8A,0xB6,0x62,0xF5,0x0A,0xF8,0xDC,
    0x03,0x3C,0x0C,0x39,0xF1,0xB8,0xF3,0x3D,0xF2,0xD5,0x97,0x66,0x81,0x32,0xA0,0x00,
    0x06,0xCE,0xF6,0xEA,0xB7,0x17,0xF7,0x8C,0x79,0xD6,0xA7,0xBF,0x8B,0x3F,0x1F,0x53,
    0x63,0x75,0x35,0x2C,0x60,0xFD,0x27,0xD3,0x94,0xA5,0x7C,0xA1,0x05,0x58,0x2D,0xBD,
    0xD9,0xC7,0xAF,0x6B,0x54,0x0B,0xE0,0x38,0x04,0xC8,0x9D,0xE7,0x14,0xB1,0x87,0x9C,
    0xDF,0x6F,0xF9,0xDA,0x2A,0xC4,0x59,0x16,0x74,0x91,0xAB,0x26,0x61,0x76,0x34,0x2B,
    0xAD,0x99,0xFB,0x72,0xEC,0x33,0x12,0xDE,0x98,0x3B,0xC0,0x9B,0x3E,0x18,0x10,0x3A,
    0x56,0xE1,0x77,0xC9,0x1E,0x9E,0x95,0xA3,0x90,0x19,0xA8,0x6C,0x09,0xD0,0xF0,0x86
};

u32 MULa[256] = {
    0x00000000,0xE19FCF13,0x6B973726,0x8A08F835,0xD6876E4C,0x3718A15F,0xBD10596A,0x5C8F9679,
    0x05A7DC98,0xE438138B,0x6E30EBBE,0x8FAF24AD,0xD320B2D4,0x32BF7DC7,0xB8B785F2,0x59284AE1,
    0x0AE71199,0xEB78DE8A,0x617026BF,0x80EFE9AC,0xDC607FD5,0x3DFFB0C6,0xB7F748F3,0x566887E0,
    0x0F40CD01,0xEEDF0212,0x64D7FA27,0x85483534,0xD9C7A34D,0x38586C5E,0xB250946B,0x53CF5B78,
    0x1467229B,0xF5F8ED88,0x7FF015BD,0x9E6FDAAE,0xC2E04CD7,0x237F83C4,0xA9777BF1,0x48E8B4E2,
    0x11C0FE03,0xF05F3110,0x7A57C925,0x9BC80636,0xC747904F,0x26D85F5C,0xACD0A769,0x4D4F687A,
    0x1E803302,0xFF1FFC11,0x75170424,0x9488CB37,0xC8075D4E,0x2998925D,0xA3906A68,0x420FA57B,
    0x1B27EF9A,0xFAB82089,0x70B0D8BC,0x912F17AF,0xCDA081D6,0x2C3F4EC5,0xA637B6F0,0x47A879E3,
    0x28CE449F,0xC9518B8C,0x435973B9,0xA2C6BCAA,0xFE492AD3,0x1FD6E5C0,0x95DE1DF5,0x7441D2E6,
    0x2D699807,0xCCF65714,0x46FEAF21,0xA7616032,0xFBEEF64B,0x1A713958,0x9079C16D,0x71E60E7E,
    0x22295506,0xC3B69A15,0x49BE6220,0xA821AD33,0xF4AE3B4A,0x1531F459,0x9F390C6C,0x7EA6C37F,
    0x278E899E,0xC611468D,0x4C19BEB8,0xAD8671AB,0xF109E7D2,0x109628C1,0x9A9ED0F4,0x7B011FE7,
    0x3CA96604,0xDD36A917,0x573E5122,0xB6A19E31,0xEA2E0848,0x0BB1C75B,0x81B93F6E,0x6026F07D,
    0x390EBA9C,0xD891758F,0x52998DBA,0xB30642A9,0xEF89D4D0,0x0E161BC3,0x841EE3F6,0x65812CE5,
    0x364E779D,0xD7D1B88E,0x5DD940BB,0xBC468FA8,0xE0C919D1,0x0156D6C2,0x8B5E2EF7,0x6AC1E1E4,
    0x33E9AB05,0xD2766416,0x587E9C23,0xB9E15330,0xE56EC549,0x04F10A5A,0x8EF9F26F,0x6F663D7C,
    0x50358897,0xB1AA4784,0x3BA2BFB1,0xDA3D70A2,0x86B2E6DB,0x672D29C8,0xED25D1FD,0x0CBA1EEE,
    0x5592540F,0xB40D9B1C,0x3E056329,0xDF9AAC3A,0x83153A43,0x628AF550,0xE8820D65,0x091DC276,
    0x5AD2990E,0xBB4D561D,0x3145AE28,0xD0DA613B,0x8C55F742,0x6DCA3851,0xE7C2C064,0x065D0F77,
    0x5F754596,0xBEEA8A85,0x34E272B0,0xD57DBDA3,0x89F22BDA,0x686DE4C9,0xE2651CFC,0x03FAD3EF,
    0x4452AA0C,0xA5CD651F,0x2FC59D2A,0xCE5A5239,0x92D5C440,0x734A0B53,0xF942F366,0x18DD3C75,
    0x41F57694,0xA06AB987,0x2A6241B2,0xCBFD8EA1,0x977218D8,0x76EDD7CB,0xFCE52FFE,0x1D7AE0ED,
    0x4EB5BB95,0xAF2A7486,0x25228CB3,0xC4BD43A0,0x9832D5D9,0x79AD1ACA,0xF3A5E2FF,0x123A2DEC,
    0x4B12670D,0xAA8DA81E,0x2085502B,0xC11A9F38,0x9D950941,0x7C0AC652,0xF6023E67,0x179DF174,
    0x78FBCC08,0x9964031B,0x136CFB2E,0xF2F3343D,0xAE7CA244,0x4FE36D57,0xC5EB9562,0x24745A71,
    0x7D5C1090,0x9CC3DF83,0x16CB27B6,0xF754E8A5,0xABDB7EDC,0x4A44B1CF,0xC04C49FA,0x21D386E9,
    0x721CDD91,0x93831282,0x198BEAB7,0xF81425A4,0xA49BB3DD,0x45047CCE,0xCF0C84FB,0x2E934BE8,
    0x77BB0109,0x9624CE1A,0x1C2C362F,0xFDB3F93C,0xA13C6F45,0x40A3A056,0xCAAB5863,0x2B349770,
    0x6C9CEE93,0x8D032180,0x070BD9B5,0xE69416A6,0xBA1B80DF,0x5B844FCC,0xD18CB7F9,0x301378EA,
    0x693B320B,0x88A4FD18,0x02AC052D,0xE333CA3E,0xBFBC5C47,0x5E239354,0xD42B6B61,0x35B4A472,
    0x667BFF0A,0x87E43019,0x0DECC82C,0xEC73073F,0xB0FC9146,0x51635E55,0xDB6BA660,0x3AF46973,
    0x63DC2392,0x8243EC81,0x084B14B4,0xE9D4DBA7,0xB55B4DDE,0x54C482CD,0xDECC7AF8,0x3F53B5EB
};

u32 DIVa[256] = {
    0x00000000,0x180F40CD,0x301E8033,0x2811C0FE,0x603CA966,0x7833E9AB,0x50222955,0x482D6998,
    0xC078FBCC,0xD877BB01,0xF0667BFF,0xE8693B32,0xA04452AA,0xB84B1267,0x905AD299,0x88559254,
    0x29F05F31,0x31FF1FFC,0x19EEDF02,0x01E19FCF,0x49CCF657,0x51C3B69A,0x79D27664,0x61DD36A9,
    0xE988A4FD,0xF187E430,0xD99624CE,0xC1996403,0x89B40D9B,0x91BB4D56,0xB9AA8DA8,0xA1A5CD65,
    0x5249BE62,0x4A46FEAF,0x62573E51,0x7A587E9C,0x32751704,0x2A7A57C9,0x026B9737,0x1A64D7FA,
    0x923145AE,0x8A3E0563,0xA22FC59D,0xBA208550,0xF20DECC8,0xEA02AC05,0xC2136CFB,0xDA1C2C36,
    0x7BB9E153,0x63B6A19E,0x4BA76160,0x53A821AD,0x1B854835,0x038A08F8,0x2B9BC806,0x339488CB,
    0xBBC11A9F,0xA3CE5A52,0x8BDF9AAC,0x93D0DA61,0xDBFDB3F9,0xC3F2F334,0xEBE333CA,0xF3EC7307,
    0xA492D5C4,0xBC9D9509,0x948C55F7,0x8C83153A,0xC4AE7CA2,0xDCA13C6F,0xF4B0FC91,0xECBFBC5C,
    0x64EA2E08,0x7CE56EC5,0x54F4AE3B,0x4CFBEEF6,0x04D6876E,0x1CD9C7A3,0x34C8075D,0x2CC74790,
    0x8D628AF5,0x956DCA38,0xBD7C0AC6,0xA5734A0B,0xED5E2393,0xF551635E,0xDD40A3A0,0xC54FE36D,
    0x4D1A7139,0x551531F4,0x7D04F10A,0x650BB1C7,0x2D26D85F,0x35299892,0x1D38586C,0x053718A1,
    0xF6DB6BA6,0xEED42B6B,0xC6C5EB95,0xDECAAB58,0x96E7C2C0,0x8EE8820D,0xA6F942F3,0xBEF6023E,
    0x36A3906A,0x2EACD0A7,0x06BD1059,0x1EB25094,0x569F390C,0x4E9079C1,0x6681B93F,0x7E8EF9F2,
    0xDF2B3497,0xC724745A,0xEF35B4A4,0xF73AF469,0xBF179DF1,0xA718DD3C,0x8F091DC2,0x97065D0F,
    0x1F53CF5B,0x075C8F96,0x2F4D4F68,0x37420FA5,0x7F6F663D,0x676026F0,0x4F71E60E,0x577EA6C3,
    0xE18D0321,0xF98243EC,0xD1938312,0xC99CC3DF,0x81B1AA47,0x99BEEA8A,0xB1AF2A74,0xA9A06AB9,
    0x21F5F8ED,0x39FAB820,0x11EB78DE,0x09E43813,0x41C9518B,0x59C61146,0x71D7D1B8,0x69D89175,
    0xC87D5C10,0xD0721CDD,0xF863DC23,0xE06C9CEE,0xA841F576,0xB04EB5BB,0x985F7545,0x80503588,
    0x0805A7DC,0x100AE711,0x381B27EF,0x20146722,0x68390EBA,0x70364E77,0x58278E89,0x4028CE44,
    0xB3C4BD43,0xABCBFD8E,0x83DA3D70,0x9BD57DBD,0xD3F81425,0xCBF754E8,0xE3E69416,0xFBE9D4DB,
    0x73BC468F,0x6BB30642,0x43A2C6BC,0x5BAD8671,0x1380EFE9,0x0B8FAF24,0x239E6FDA,0x3B912F17,
    0x9A34E272,0x823BA2BF,0xAA2A6241,0xB225228C,0xFA084B14,0xE2070BD9,0xCA16CB27,0xD2198BEA,
    0x5A4C19BE,0x42435973,0x6A52998D,0x725DD940,0x3A70B0D8,0x227FF015,0x0A6E30EB,0x12617026,
    0x451FD6E5,0x5D109628,0x750156D6,0x6D0E161B,0x25237F83,0x3D2C3F4E,0x153DFFB0,0x0D32BF7D,
    0x85672D29,0x9D686DE4,0xB579AD1A,0xAD76EDD7,0xE55B844F,0xFD54C482,0xD545047C,0xCD4A44B1,
    0x6CEF89D4,0x74E0C919,0x5CF109E7,0x44FE492A,0x0CD320B2,0x14DC607F,0x3CCDA081,0x24C2E04C,
    0xAC977218,0xB49832D5,0x9C89F22B,0x8486B2E6,0xCCABDB7E,0xD4A49BB3,0xFCB55B4D,0xE4BA1B80,
    0x17566887,0x0F59284A,0x2748E8B4,0x3F47A879,0x776AC1E1,0x6F65812C,0x477441D2,0x5F7B011F,
    0xD72E934B,0xCF21D386,0xE7301378,0xFF3F53B5,0xB7123A2D,0xAF1D7AE0,0x870CBA1E,0x9F03FAD3,
    0x3EA637B6,0x26A9777B,0x0EB8B785,0x16B7F748,0x5E9A9ED0,0x4695DE1D,0x6E841EE3,0x768B5E2E,
    0xFEDECC7A,0xE6D18CB7,0xCEC04C49,0xD6CF0C84,0x9EE2651C,0x86ED25D1,0xAEFCE52F,0xB6F3A5E2
};

/* MULx.
* Input V: an 8-bit input.
* Input c: an 8-bit input.
* Output : an 8-bit output.
* See section 3.1.1 for details.
*/

#define MULx(v,c) (( (v) & 0x80 )?( ((v) << 1) ^ (c)):( (v) << 1))
#if 0
u8 MULx(u8 V, u8 c)
{
	if ( V & 0x80 )
	  return ( (V << 1) ^ c);
	else
	  return ( V << 1);
}
#endif

/* MULxPOW.
* Input V: an 8-bit input.
* Input i: a positive integer.
* Input c: an 8-bit input.
* Output : an 8-bit output.
* See section 3.1.2 for details.
*/

u8 MULxPOW(u8 V, u8 i, u8 c)
{
	if ( i == 0)
	  return V;
	else
	  return MULx( MULxPOW( V, i-1, c ), c);
}

  /* The function MUL alpha.
   * Input c: 8-bit input.
   * Output : 32-bit output.
   * See section 3.4.2 for details.
   */

u32 MULalpha(u8 c)
{
	return ( ( ((u32)MULxPOW(c, 23, 0xa9)) << 24 ) |
	    ( ((u32)MULxPOW(c, 245, 0xa9)) << 16 ) |
	    ( ((u32)MULxPOW(c, 48, 0xa9)) << 8 ) |
	    ( ((u32)MULxPOW(c, 239, 0xa9)) ) ) ;
}

  /* The function DIV alpha.
   * Input c: 8-bit input.
   * Output : 32-bit output.
   * See section 3.4.3 for details.
   */

u32 DIValpha(u8 c)
{
    return ( ( ((u32)MULxPOW(c, 16, 0xa9)) << 24 ) |
        ( ((u32)MULxPOW(c, 39, 0xa9)) << 16 ) |
        ( ((u32)MULxPOW(c, 6, 0xa9)) << 8 ) |
        ( ((u32)MULxPOW(c, 64, 0xa9)) ) ) ;
}

  /* The 32x32-bit S-Box S1
   * Input: a 32-bit input.
   * Output: a 32-bit output of S1 box.
   * See section 3.3.1.
   */

u32 S1(u32 w)
{
    u8 r0=0, r1=0, r2=0, r3=0;
    u8 srw0 = SR[ (u8)((w >> 24) & 0xff) ];
    u8 srw1 = SR[ (u8)((w >> 16) & 0xff) ];
    u8 srw2 = SR[ (u8)((w >> 8) & 0xff) ];
    u8 srw3 = SR[ (u8)((w) & 0xff) ];
    r0 = ( ( MULx( srw0 , 0x1b) ) ^
        ( srw1 ) ^
        ( srw2 ) ^
        ( (MULx( srw3, 0x1b)) ^ srw3 )
        );
    r1 = ( ( ( MULx( srw0 , 0x1b) ) ^ srw0 ) ^
        ( MULx(srw1, 0x1b) ) ^
        ( srw2 ) ^
        ( srw3 )
        );
    r2 = ( ( srw0 ) ^
        ( ( MULx( srw1 , 0x1b) ) ^ srw1 ) ^
        ( MULx(srw2, 0x1b) ) ^
        ( srw3 )
        );
    r3 = ( ( srw0 ) ^
        ( srw1 ) ^
        ( ( MULx( srw2 , 0x1b) ) ^ srw2 ) ^
        ( MULx( srw3, 0x1b) )
        );

    return ( ( ((u32)r0) << 24 ) | ( ((u32)r1) << 16 ) | ( ((u32)r2) << 8 ) |
        ( ((u32)r3) ) );
}

  /* The 32x32-bit S-Box S2
   * Input: a 32-bit input.
   * Output: a 32-bit output of S2 box.
   * See section 3.3.2.
   */

u32 S2(u32 w)
{
    u8 r0=0, r1=0, r2=0, r3=0;
    u8 sqw0 = SQ[ (u8)((w >> 24) & 0xff) ];
    u8 sqw1 = SQ[ (u8)((w >> 16) & 0xff) ];
    u8 sqw2 = SQ[ (u8)((w >> 8) & 0xff) ];
    u8 sqw3 = SQ[ (u8)((w) & 0xff) ];
    r0 = ( ( MULx( sqw0 , 0x69) ) ^
        ( sqw1 ) ^
        ( sqw2 ) ^
        ( (MULx( sqw3, 0x69)) ^ sqw3 )
        );
    r1 = ( ( ( MULx( sqw0 , 0x69) ) ^ sqw0 ) ^
        ( MULx(sqw1, 0x69) ) ^
        ( sqw2 ) ^
        ( sqw3 )
        );
    r2 = ( ( sqw0 ) ^
        ( ( MULx( sqw1 , 0x69) ) ^ sqw1 ) ^
        ( MULx(sqw2, 0x69) ) ^
        ( sqw3 )
        );
    r3 = ( ( sqw0 ) ^
        ( sqw1 ) ^
        ( ( MULx( sqw2 , 0x69) ) ^ sqw2 ) ^
        ( MULx( sqw3, 0x69) )
        );
    return ( ( ((u32)r0) << 24 ) | ( ((u32)r1) << 16 ) | ( ((u32)r2) << 8 ) |
        ( ((u32)r3) ) );
}

/* Clocking LFSR in initialization mode.
* LFSR Registers S0 to S15 are updated as the LFSR receives a single clock.
* Input F: a 32-bit word comes from output of FSM.
* See section 3.4.4.
*/

void ClockLFSRInitializationMode(snow3g_ctx_t* ctx,u32 F)
{
    u32 v = ( ( (ctx->LFSR_S0 << 8) & 0xffffff00 ) ^
        //( MULalpha( (u8)((ctx->LFSR_S0>>24) & 0xff) ) ) ^
        ( MULa[ (u8)((ctx->LFSR_S0>>24) & 0xff) ] ) ^
        ( ctx->LFSR_S2 ) ^
        ( (ctx->LFSR_S11 >> 8) & 0x00ffffff ) ^
        ( DIVa[ (u8)( ( ctx->LFSR_S11) & 0xff ) ]) ^
        ( F )
        );
    ctx->LFSR_S0 = ctx->LFSR_S1;
    ctx->LFSR_S1 = ctx->LFSR_S2;
    ctx->LFSR_S2 = ctx->LFSR_S3;
    ctx->LFSR_S3 = ctx->LFSR_S4;
    ctx->LFSR_S4 = ctx->LFSR_S5;
    ctx->LFSR_S5 = ctx->LFSR_S6;
    ctx->LFSR_S6 = ctx->LFSR_S7;
    ctx->LFSR_S7 = ctx->LFSR_S8;
    ctx->LFSR_S8 = ctx->LFSR_S9;
    ctx->LFSR_S9 = ctx->LFSR_S10;
    ctx->LFSR_S10 = ctx->LFSR_S11;
    ctx->LFSR_S11 = ctx->LFSR_S12;
    ctx->LFSR_S12 = ctx->LFSR_S13;
    ctx->LFSR_S13 = ctx->LFSR_S14;
    ctx->LFSR_S14 = ctx->LFSR_S15;
    ctx->LFSR_S15 = v;
}

  /* Clocking LFSR in keystream mode.
   * LFSR Registers S0 to S15 are updated as the LFSR receives a single clock.
   * See section 3.4.5.
   */

void ClockLFSRKeyStreamMode(snow3g_ctx_t* ctx)
{
    u32 v = ( ( (ctx->LFSR_S0 << 8) & 0xffffff00 ) ^
        ( MULa[ (u8)((ctx->LFSR_S0>>24) & 0xff) ] ) ^
        ( ctx->LFSR_S2 ) ^
        ( (ctx->LFSR_S11 >> 8) & 0x00ffffff ) ^
        ( DIVa[ (u8)( ( ctx->LFSR_S11) & 0xff ) ] )
        );
    ctx->LFSR_S0 = ctx->LFSR_S1;
    ctx->LFSR_S1 = ctx->LFSR_S2;
    ctx->LFSR_S2 = ctx->LFSR_S3;
    ctx->LFSR_S3 = ctx->LFSR_S4;
    ctx->LFSR_S4 = ctx->LFSR_S5;
    ctx->LFSR_S5 = ctx->LFSR_S6;
    ctx->LFSR_S6 = ctx->LFSR_S7;
    ctx->LFSR_S7 = ctx->LFSR_S8;
    ctx->LFSR_S8 = ctx->LFSR_S9;
    ctx->LFSR_S9 = ctx->LFSR_S10;
    ctx->LFSR_S10 = ctx->LFSR_S11;
    ctx->LFSR_S11 = ctx->LFSR_S12;
    ctx->LFSR_S12 = ctx->LFSR_S13;
    ctx->LFSR_S13 = ctx->LFSR_S14;
    ctx->LFSR_S14 = ctx->LFSR_S15;
    ctx->LFSR_S15 = v;
}

/* Clocking FSM.
* Produces a 32-bit word F.
* Updates FSM registers R1, R2, R3.
* See Section 3.4.6.
*/

u32 ClockFSM(snow3g_ctx_t* ctx)
{
    u32 F = ( ( ctx->LFSR_S15 + ctx->FSM_R1 ) & 0xffffffff ) ^ ctx->FSM_R2 ;
    u32 r = ( ctx->FSM_R2 + ( ctx->FSM_R3 ^ ctx->LFSR_S5 ) ) & 0xffffffff ;
    ctx->FSM_R3 = S2(ctx->FSM_R2);
    ctx->FSM_R2 = S1(ctx->FSM_R1);
    ctx->FSM_R1 = r;
    return F;
}

/* Initialization.
* Input k[4]: Four 32-bit words making up 128-bit key.
* Input IV[4]: Four 32-bit words making 128-bit initialization variable.
* Output: All the LFSRs and FSM are initialized for key generation.
* See Section 4.1.
*/

void Initialize(snow3g_ctx_t* ctx, u32 k[4], u32 IV[4])
{
    u8 i=0;
    u32 F = 0x0;
    ctx->LFSR_S15 = k[3] ^ IV[0];
    ctx->LFSR_S14 = k[2];
    ctx->LFSR_S13 = k[1];
    ctx->LFSR_S12 = k[0] ^ IV[1];
    ctx->LFSR_S11 = k[3] ^ 0xffffffff;
    ctx->LFSR_S10 = k[2] ^ 0xffffffff ^ IV[2];
    ctx->LFSR_S9 = k[1] ^ 0xffffffff ^ IV[3];
    ctx->LFSR_S8 = k[0] ^ 0xffffffff;
    ctx->LFSR_S7 = k[3];
    ctx->LFSR_S6 = k[2];
    ctx->LFSR_S5 = k[1];
    ctx->LFSR_S4 = k[0];
    ctx->LFSR_S3 = k[3] ^ 0xffffffff;
    ctx->LFSR_S2 = k[2] ^ 0xffffffff;
    ctx->LFSR_S1 = k[1] ^ 0xffffffff;
    ctx->LFSR_S0 = k[0] ^ 0xffffffff;
    ctx->FSM_R1 = 0x0;
    ctx->FSM_R2 = 0x0;
    ctx->FSM_R3 = 0x0;
    for(i=0;i<32;i++)
    {
      F = ClockFSM(ctx);
      ClockLFSRInitializationMode(ctx,F);
    }
}

/* Generation of Keystream.
* input n: number of 32-bit words of keystream.
* input z: space for the generated keystream, assumes
* memory is allocated already.
* output: generated keystream which is filled in z
* See section 4.2.
*/

void GenerateKeystream(snow3g_ctx_t* ctx, u32 n, u32 *ks)
{
    u32 t = 0;
    u32 F = 0x0;
    ClockFSM(ctx); /* Clock FSM once. Discard the output. */
    ClockLFSRKeyStreamMode(ctx); /* Clock LFSR in keystream mode once. */
    for ( t=0; t<n; t++)
    {
      F = ClockFSM(ctx); /* STEP 1 */

      ks[t] = F ^ ctx->LFSR_S0; /* STEP 2 */
      /* Note that ks[t] corresponds to z_{t+1} in section 4.2
      */
      ClockLFSRKeyStreamMode(ctx); /* STEP 3 */
    }
}

  /*-----------------------------------------------------------------------
   * end of SNOW_3G.c
   *-----------------------------------------------------------------------*/

  /*---------------------------------------------------------
   * f8.c
   *---------------------------------------------------------*/

  /*
#include "f8.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
*/

/* f8.
* Input key: 128 bit Confidentiality Key.
* Input count:32-bit Count, Frame dependent input.
* Input bearer: 5-bit Bearer identity (in the LSB side).
* Input dir:1 bit, direction of transmission.
* Input data: length number of bits, input bit stream.
* Input length: 32 bit Length, i.e., the number of bits to be encrypted or
* decrypted.
* Output data: Output bit stream. Assumes data is suitably memory
* allocated.
* Encrypts/decrypts blocks of data between 1 and 2^32 bits in length as
* defined in Section 3.
*/

void f8(snow3g_ctx_t* ctx, u8 *key, u32 count, u32 bearer, u32 dir, u8 *data, u8 *output, u32 length)
{
    u32 K[4],IV[4];
    int n = ( length + 31 ) / 32;
    int i=0;
    int lastbits = (8-(length%8)) % 8;
    u32 *KS;

    /*Initialisation*/
    /* Load the confidentiality key for SNOW 3G initialization as in section
       3.4. */
    for (i=0; i<4; i++)
      K[3-i] = (key[4*i] << 24) ^ (key[4*i+1] << 16) 
        ^ (key[4*i+2] << 8) ^ (key[4*i+3]);

    /* Prepare the initialization vector (IV) for SNOW 3G initialization as in
       section 3.4. */
    IV[3] = count;
    IV[2] = (bearer << 27) | ((dir & 0x1) << 26);
    IV[1] = IV[3];
    IV[0] = IV[2];

    /* Run SNOW 3G algorithm to generate sequence of key stream bits KS*/
    Initialize(ctx,K,IV);
    KS = (u32 *)malloc(4*n);
    GenerateKeystream(ctx,n,(u32*)KS);

    /* Exclusive-OR the input data with keystream to generate the output bit
       stream */


    for (i=0; i<n; i++)
    {
      output[4*i+0] = data[4*i+0] ^ ((u8) (KS[i] >> 24) & 0xff);
      output[4*i+1] =	data[4*i+1] ^ ((u8) (KS[i] >> 16) & 0xff);
      output[4*i+2] = data[4*i+2] ^ ((u8) (KS[i] >> 8) & 0xff);
      output[4*i+3] = data[4*i+3] ^ ((u8) (KS[i] ) & 0xff);
    }
    /*
       for (i=0; i<n; i++)
       {
       data[4*i+0] ^= (u8) (KS[i] >> 24) & 0xff;
       data[4*i+1] ^= (u8) (KS[i] >> 16) & 0xff;
       data[4*i+2] ^= (u8) (KS[i] >> 8) & 0xff;
       data[4*i+3] ^= (u8) (KS[i] ) & 0xff;
       }
       */
    free(KS);

    /* zero last bits of data in case its length is not byte-aligned 
       this is an addition to the C reference code, which did not handle it */
    if (lastbits)
      data[length/8] &= 256 - (1<<lastbits);
}
/* End of f8.c */

/*---------------------------------------------------------
*					f9.c
*---------------------------------------------------------*/

/* MUL64x.
* Input V: a 64-bit input.
* Input c: a 64-bit input.
* Output : a 64-bit output.
* A 64-bit memory is allocated which is to be freed by the calling 
* function.
* See section 4.3.2 for details.
*/
u64 MUL64x(u64 V, u64 c)
{
	if ( V & 0x8000000000000000 )
	  return (V << 1) ^ c;
	else
	  return V << 1;
}

/* MUL64xPOW.
* Input V: a 64-bit input.
* Input i: a positive integer.
* Input c: a 64-bit input.
* Output : a 64-bit output.
* A 64-bit memory is allocated which is to be freed by the calling function.
* See section 4.3.3 for details.
*/
u64 MUL64xPOW(u64 V, u8 i, u64 c)
{
    if ( i == 0)
      return V; 
    else
      return MUL64x( MUL64xPOW(V,i-1,c) , c);
}

/* MUL64.
* Input V: a 64-bit input.
* Input P: a 64-bit input.
* Input c: a 64-bit input.
* Output : a 64-bit output.
* A 64-bit memory is allocated which is to be freed by the calling 
* function.
* See section 4.3.4 for details.
*/
u64 MUL64(u64 V, u64 P, u64 c)
{
    u64 result = 0;
    int i = 0;

    for ( i=0; i<64; i++)
    {
      if( ( P>>i ) & 0x1 )
        result ^= MUL64xPOW(V,i,c);
    }
    return result;
}

/* mask8bit.
* Input n: an integer in 1-7.
* Output : an 8 bit mask.
* Prepares an 8 bit mask with required number of 1 bits on the MSB side.
*/
u8 mask8bit(int n)
{
    return 0xFF ^ ((1<<(8-n)) - 1);
}

/* f9.
* Input key: 128 bit Integrity Key.
* Input count:32-bit Count, Frame dependent input.
* Input fresh: 32-bit Random number.
* Input dir:1 bit, direction of transmission (in the LSB).
* Input data: length number of bits, input bit stream.
* Input length: 64 bit Length, i.e., the number of bits to be MAC'd.
* Output  : 32 bit block used as MAC 
* Generates 32-bit MAC using UIA2 algorithm as defined in Section 4.
*/
u8* f9(snow3g_ctx_t* ctx, u8* key, u32 count, u32 fresh, u32 dir, u8 *data, u64 length,
  u8* MAC_I)
{
    u32 K[4],IV[4], z[5];
    u32 i=0, D;
    /* static u8 MAC_I[4] = {0,0,0,0}; /1* static memory for the result *1/ */
    u64 EVAL;
    u64 V;
    u64 P;
    u64 Q;
    u64 c;

    u64 M_D_2;
    int rem_bits = 0;

    /* Load the Integrity Key for SNOW3G initialization as in section 4.4. */
    for (i=0; i<4; i++)
      K[3-i] = (key[4*i] << 24) ^ (key[4*i+1] << 16) ^
        (key[4*i+2] << 8) ^ (key[4*i+3]);

    /* Prepare the Initialization Vector (IV) for SNOW3G initialization as 
       in section 4.4. */
    IV[3] = count;
    IV[2] = fresh;
    IV[1] = count ^ ( dir << 31 ) ;
    IV[0] = fresh ^ (dir << 15);

    z[0] = z[1] = z[2] = z[3] = z[4] = 0;

    /* Run SNOW 3G to produce 5 keystream words z_1, z_2, z_3, z_4 and z_5. */
    Initialize(ctx,K, IV);
    GenerateKeystream(ctx,5, z);

    P = (u64)z[0] << 32 | (u64)z[1];
    Q = (u64)z[2] << 32 | (u64)z[3];

    /* Calculation */
    if ((length % 64) == 0)
      D = (length>>6) + 1;
    else
      D = (length>>6) + 2;
    EVAL = 0;
    c = 0x1b;

    /* for 0 <= i <= D-3 */
    for (i=0; i<D-2; i++)
    {
      V = EVAL ^ ( (u64)data[8*i  ]<<56 | (u64)data[8*i+1]<<48 | 
          (u64)data[8*i+2]<<40 | (u64)data[8*i+3]<<32 | 
          (u64)data[8*i+4]<<24 | (u64)data[8*i+5]<<16 | 
          (u64)data[8*i+6]<< 8 | (u64)data[8*i+7] )   ;
      EVAL = MUL64(V,P,c);
    }

    /* for D-2 */
    rem_bits = length % 64;
    if (rem_bits == 0)
      rem_bits = 64;

    M_D_2 = 0;
    i = 0;
    while (rem_bits > 7)
    {
      M_D_2 |= (u64)data[8*(D-2)+i] << (8*(7-i));
      rem_bits -= 8;
      i++;
    }
    if (rem_bits > 0)
      M_D_2 |= (u64)(data[8*(D-2)+i] & mask8bit(rem_bits)) << (8*(7-i));

    V = EVAL ^ M_D_2;
    EVAL = MUL64(V,P,c);

    /* for D-1 */
    EVAL ^= length;

    /* Multiply by Q */
    EVAL = MUL64(EVAL,Q,c);

    /* XOR with z_5: this is a modification to the reference C code, 
       which forgot to XOR z[5] */
    for (i=0; i<4; i++)
      /*
         MAC_I[i] = (mac32 >> (8*(3-i))) & 0xff;
         */
      MAC_I[i] = ((EVAL >> (56-(i*8))) ^ (z[4] >> (24-(i*8)))) & 0xff;

    return MAC_I;
}



void snow3g_encrypt(snow3g_ctx_t* ctx, u8* key, u32 count,u32 bearer,u32 dir,u8 *data, u8 *output,u32 length)
{
	f8(ctx,key,count,bearer,dir,data,output,length<<3);

}

void snow3g_decrypt(snow3g_ctx_t* ctx,u8* key, u32 count,u32 bearer,u32 dir,u8 *data, u8 *output,u32 length)
{
	f8(ctx,key,count,bearer,dir,data,output,length<<3);

}
//@length exclude 4-bytes MAC 
void snow3g_protect(snow3g_ctx_t* ctx, u8* key, u32 count,u32 bearer,u32 dir,u8 *data, u64 length, u8* MAC_I)
{
	f9(ctx,key,count,bearer<<27,dir,data,(length)<<3,MAC_I);

}

void snow3g_validate(snow3g_ctx_t* ctx, u8* key, u32 count,u32 bearer,u32 dir,u8 *data, u64 length, u8* MAC_I)
{ 
	f9(ctx,key,count,bearer<<27,dir,data,(length)<<3,MAC_I);

}




