#
#  Struct and enumerations for Bios Video INT10h for DOS based Systems
#

enum byte (
  FG_COLOR_BLACK,
  FG_COLOR_BLUE,
  FG_COLOR_GREEN,
  FG_COLOR_CYAN,
  FG_COLOR_RED,
  FG_COLOR_MAGENTA,
  FG_COLOR_BROWN,
  FG_COLOR_LIGHT_GREY
) VideoForegroudColor;

enum byte (
  BG_COLOR_DARK_GREY,
  BG_COLOR_LIGHT_BLUE,
  BG_COLOR_LIGHT_GREEN,
  BG_COLOR_LIGHT_CYAN,
  BG_COLOR_LIGHT_RED,
  BG_COLOR_LIGHT_MAGENTA,
  BG_COLOR_YELLOW,
  BG_COLOR_WHITE
) VideoBackgroundColor;

enum byte (
  VIDEO_MEMORY_SIZE_64K,
  VIDEO_MEMORY_SIZE_128K,
  VIDEO_MEMORY_SIZE_192K,
  VIDEO_MEMORY_SIZE_256K
) VideoMemorySize;

struct TVideoPos {
  byte row,      /* DH */
       column;   /* DL */
} *PVideoPos;

struct TScanLine {
  byte start_scan_line, /* CH */
       end_scan_line;   /* CL */
} *PScanLine;

struct TScanCursor {
   byte  cursor_start_and_options;
   byte  bottom_scan_line_containing_cursor;
} *PScanCursor;

struct TCharInfo {
  byte attribute;
  byte char_value;
} *PCharInfo;

struct TVideoPaletteList {
  byte palette[16];
  byte border_color;
} *PVidioPaletteList;

struct TVideoStateBuffer {
  DWORD	address_static_functionality_table;
  byte video_mode;
  WORD number_of_columns;
  WORD length_of_regen_buffers;
  WORD starting_address_regen_buffer;
  WORD cursor_position[8];
  WORD cursor_type;
  BYTE active_display_page;
  WORD crtc_port_address;
  byte setting_port_3x8;
  byte setting_port_3x9;
  byte number_of_rows; /* zero based so rows - 1 */
  WORD bytes_characters;
  byte display_combination;
  byte dss_alternate_display;
  WORD number_of_colors_current_mode;
  byte number_of_pages_current_mode;
  byte number_of_scan_lines_active;
  byte primary_character_block;
  byte secondary_character_block;
  byte miscellaneous_flags;
  /*
  0	all modes on all displays on
  1	gray summing on
  2	monochrome display attached
  3	default palette loading disabled
  4	cursor emulation enabled
  5	0 = intensity; 1 = blinking
  6	flat-panel display is active
  7	unused (0)
  */
  byte non_vga_mode_support;
  /*
  7-5	reserved
  4	132-column mode supported
  3	=1 MFI attributes enabled (see AH=12h/BL=37h)
   =0 VGA attributes
  2	16-bit VGA graphics present
  1	adapter interface driver required
  0	BIOS supports information return for adapter interface
  */
  byte reserved_block1;
  VideoMemorySize video_memory_available;
  byte save_pointer_state_flags;
  /*
  0	512 character set active
  1	dynamic save area present
  2	alpha font override active
  3	graphics font override active
  4	palette override active
  5	DCC override active
  6-7	unused (0)
  */
  byte display_information_status;
  /*
  7	640x480 flat-panel can be used simultaneously with CRT controller
  6-3	reserved
  2	color display
  1	flat-panel display active
  0	flat-panel display attached
  */
  byte reserved_block2[12];
} *PVideoStateBuffer;


enum (
  CGA_VIDEO_MODE_40x25_8x8_320x200_16GRAY,
  CGA_VIDEO_MODE_40x25_8x8_320x200_16,

) BiosVideoMode;

/*
00h = T  40x25	 8x8   320x200	16gray	  8   B800 CGA,PCjr,Tandy
    = T  40x25	 8x14  320x350	16gray	  8   B800 EGA
    = T  40x25	 8x16  320x400	 16	  8   B800 MCGA
    = T  40x25	 9x16  360x400	 16	  8   B800 VGA
01h = T  40x25	 8x8   320x200	 16	  8   B800 CGA,PCjr,Tandy
    = T  40x25	 8x14  320x350	 16	  8   B800 EGA
    = T  40x25	 8x16  320x400	 16	  8   B800 MCGA
    = T  40x25	 9x16  360x400	 16	  8   B800 VGA
02h = T  80x25	 8x8   640x200	16gray	  4   B800 CGA,PCjr,Tandy
    = T  80x25	 8x14  640x350	16gray	  8   B800 EGA
    = T  80x25	 8x16  640x400	 16	  8   B800 MCGA
    = T  80x25	 9x16  720x400	 16	  8   B800 VGA
03h = T  80x25	 8x8   640x200	 16	  4   B800 CGA,PCjr,Tandy
    = T  80x25	 8x14  640x350	 16/64	  8   B800 EGA
    = T  80x25	 8x16  640x400	 16	  8   B800 MCGA
    = T  80x25	 9x16  720x400	 16	  8   B800 VGA
    = T  80x43	 8x8   640x350	 16	  4   B800 EGA,VGA [17]
    = T  80x50	 8x8   640x400	 16	  4   B800 VGA [17]
04h = G  40x25	 8x8   320x200	  4	  .   B800 CGA,PCjr,EGA,MCGA,VGA
05h = G  40x25	 8x8   320x200	 4gray	  .   B800 CGA,PCjr,EGA
    = G  40x25	 8x8   320x200	  4	  .   B800 MCGA,VGA
06h = G  80x25	 8x8   640x200	  2	  .   B800 CGA,PCjr,EGA,MCGA,VGA
    = G  80x25	  .	  .	mono	  .   B000 HERCULES.COM on HGC [14]
07h = T  80x25	 9x14  720x350	mono	 var  B000 MDA,Hercules,EGA
    = T  80x25	 9x16  720x400	mono	  .   B000 VGA
08h = T 132x25	 8x8  1056x200	 16	  .   B800 ATI EGA/VGA Wonder [2]
    = T 132x25	 8x8  1056x200	mono	  .   B000 ATI EGA/VGA Wonder [2]
    = G  20x25	 8x8   160x200	 16	  .	.  PCjr, Tandy 1000
    = G  80x25	 8x16  640x400	color	  .	.  Tandy 2000
    = G  90x43	 8x8   720x348	mono	  .   B000 Hercules + MSHERC.COM
    = G  90x45	 8x8   720x360	mono	  .   B000 Hercules + HERKULES [11]
    = G  90x29	 8x12  720x348	mono	  .	.  Hercules + HERCBIOS [15]
09h = G  40x25	 8x8   320x200	 16	  .	.  PCjr, Tandy 1000
    = G  80x25	 8x16  640x400	mono	  .	.  Tandy 2000
    = G  90x43	 8x8   720x348	mono	  .	.  Hercules + HERCBIOS [15]
0Ah = G  80x25	 8x8   640x200	  4	  .	.  PCjr, Tandy 1000
0Bh =	 reserved				   (EGA BIOS internal use)
    = G  80x25	 8x8   640x200	 16	  .	.  Tandy 1000 SL/TL [13]
0Ch =	 reserved				   (EGA BIOS internal use)
0Dh = G  40x25	 8x8   320x200	 16	  8   A000 EGA,VGA
0Eh = G  80x25	 8x8   640x200	 16	  4   A000 EGA,VGA
0Fh = G  80x25	 8x14  640x350	mono	  2   A000 EGA,VGA
10h = G  80x25	 8x14  640x350	  4	  2   A000 64k EGA
    = G    .	  .    640x350	 16	  .   A000 256k EGA,VGA
11h = G  80x30	 8x16  640x480	mono	  .   A000 VGA,MCGA,ATI EGA,ATI VIP
12h = G  80x30	 8x16  640x480	 16/256K  .   A000 VGA,ATI VIP
    = G  80x30	 8x16  640x480	 16/64	  .   A000 ATI EGA Wonder
    = G    .	  .    640x480	 16	  .	.  UltraVision+256K EGA
13h = G  40x25	 8x8   320x200	256/256K  .   A000 VGA,MCGA,ATI VIP
14h = T 132x25	 Nx16	  .	 16	  .   B800 XGA, IBM Enhanced VGA [3]
    = T 132x25	 8x16 1056x400	 16/256K  .	.  Cirrus CL-GD5420/5422/5426
    = G  80x25	 8x8   640x200	  .	  .	.  Lava Chrome II EGA
    = G    .	  .    640x400	 16	  .	.  Tecmar VGA/AD
15h = G  80x25	 8x14  640x350	  .	  .	.  Lava Chrome II EGA
16h = G  80x25	 8x14  640x350	  .	  .	.  Lava Chrome II EGA
    = G    .	  .    800x600	 16	  .	.  Tecmar VGA/AD
17h = T 132x25	  .	  .	  .	  .	.  Tecmar VGA/AD
    = T  80x43	 8x8   640x348	 16	  4   B800 Tseng ET4000 BIOS [10]
    = G  80x34	 8x14  640x480	  .	  .	.  Lava Chrome II EGA
18h = T  80x30	 9x16  720x480	 16	  1   A000 Realtek RTVGA [12]
    = T 132x25	  .	  .	mono	  .   B000 Cirrus 5320 chipset
    = T 132x44	 8x8  1056x352	mono	  .   B000 Tseng Labs EVA
    = T 132x44	 9x8  1188x352	 4gray	  2   B000 Tseng ET3000 chipset
    = T 132x44	 8x8  1056x352	 16/256	  2   B000 Tseng ET4000 chipset
    = G  80x34	 8x14  640x480	  .	  .	.  Lava Chrome II EGA
    = G	      1024x768	 16	  .	.  Tecmar VGA/AD
19h = T  80x43	 9x11  720x473	 16	  1   A000 Realtek RTVGA [12]
    = T 132x25	 8x14 1056x350	mono	  .   B000 Tseng Labs EVA
    = T 132x25	 9x14 1188x350	 4gray	  4   B000 Tseng ET3000 chipset
    = T 132x25	 8x14 1056x350	 16/256	  4   B000 Tseng ET4000 chipset
    = T 132x34	  .	  .	mono	  .   B000 Cirrus 5320 chipset
1Ah = T  80x60	 9x8   720x480	 16	  1   A000 Realtek RTVGA [12]
    = T 132x28	 8x13 1056x364	mono	  .   B000 Tseng Labs EVA
    = T 132x28	 9x13 1188x364	 4gray	  4   B000 Tseng ET3000 chipset
    = T 132x28	 8x13 1056x364	 16/256	  4   B000 Tseng ET4000 chipset
    = T 132x44	  .	  .	mono	  .   B000 Cirrus 5320 chipset
    = G    .	  .    640x350	256	  .	.  Tecmar VGA/AD
1Bh = T 132x25	 9x14 1188x350	 16	  1   A000 Realtek RTVGA [12]
    = G    .	  .    640x400	256	  .	.  Tecmar VGA/AD
1Ch = T 132x25	  .	  .	  .	  .	.  Cirrus 5320 chipset
    = T 132x30	 9x16 1188x480	 16	  1   A000 Realtek RTVGA [12]
    = G    .	  .    640x480	256	  .	.  Tecmar VGA/AD
1Dh = T 132x43	  .	  .	  .	  .	.  Cirrus 5320 chipset
    = T 132x43	 9x11 1188x473	 16	  1   A000 Realtek RTVGA [12]
    = G    .	  .    800x600	256	  .	.  Tecmar VGA/AD
1Eh = T 132x44	  .	  .	  .	  .	.  Cirrus 5320 chipset
    = T 132x60	 9x8  1188x480	 16	  1   A000 Realtek RTVGA [12]
1Fh = G 100x75	 8x8   800x600	 16	  1   A000 Realtek RTVGA
20h = T 132x25	  .	  .	 16	  .	.  Avance Logic AL2101
    = G  40x16	  .    240x128	mono	  .   B000 HP 95LX/100LX/200LX
    = G  80x30	 8x16  640x480	 16	  .	.  C&T 64310/65530 BIOS
    = G 120x45	 8x16  960x720	 16	  1   A000 Realtek RTVGA
21h = T  80x25	  .	  .	mono	  .   B000 HP 200LX
    = T 132x30	  .	  .	 16	  .	.  Avance Logic AL2101
    = T 132x44	 9x9  1188x396	 16/256K  .   B800 WD90C
    = T 132x44	 9x9  1188x396	 16	  .   B800 Diamond Speedstar 24X
    = T 132x60	  .	  .	 16	  2   B800 Tseng ET4000 chipset [10]
    = G  80x43	 8x8   720x348	mono	  .   B000 DESQview 2.x+Hercules [4]
    = G 128x48	 8x16 1024x768	 16	  1   A000 Realtek RTVGA [12]
22h = T 132x43	  .	  .	  .	  .	.  Allstar Peacock (VGA)
    = T 132x43	  .	  .	 16	  .	.  Avance Logic AL2101
    = T 132x44	 8x8  1056x352	  .	  .   B800 Tseng Labs EVA
    = T 132x44	 9x8  1188x352	 16/256K  2   B800 Tseng ET3000 chipset
    = T 132x44	 8x8  1056x352	 16/256K  2   B800 Tseng ET4000 chipset
    = T 132x44	 8x8  1056x352	  .	  .	.  Ahead Systems EGA2001
    = T 132x44	 8x8  1056x352	 16	  2   B800 Ahead B
    = T 132x44	 8x9  1056x398	 16	  .	.  STB Lightspeed ET4000/W32P
    = T 132x44	  .	  .	 16	  .	.  Orchid Prodesigner VGA
    = G  80x43	 8x8   720x348	mono	  .   B800 DESQview 2.x+Hercules [4]
    = G  96x64	 8x16  768x1024	 16	  1   A000 Realtek RTVGA
    = G 100x37	 8x16  800x600	 16	  .	.  C&T 64310/65530 BIOS
23h = T 132x25	 6x14  792x350	  .	  .   B800 Tseng Labs EVA
    = T 132x25	 9x14 1188x350	 16/256K  4   B800 Tseng ET3000 chipset
    = T 132x25	 8x14 1056x350	 16/256	  4   B800 Tseng ET4000 chipset
    = T 132x25	 8x14 1056x350	  .	  .	.  Ahead Systems EGA2001
    = T 132x25	 8x14 1056x350	 16	  4   B800 Ahead B
    = T 132x25	 8x8  1056x200	 16	  .   B800 ATI EGA Wonder,ATI VIP
    = T 132x25	  .	  .	  .	  .	.  Cirrus 5320 chipset
    = T 132x28	  .	  .	  .	  .	.  Allstar Peacock (VGA)
    = T 132x28	  .	  .	 16	  .	.  Orchid Prodesigner VGA
    = T 132x60	  .	  .	 16	  .	.  Avance Logic AL2101
    = G 128x48	 8x16 1024x768	  4	  1   A000 Realtek RTVGA
24h = T  80x30	  .	  .	 16	  .	.  Avance Logic AL2101
    = T 132x25	  .	  .	  .	  .	.  Allstar Peacock (VGA)
    = T 132x25	  .	  .	 16	  .	.  Orchid Prodesigner VGA
    = T 132x28	 6x13  792x364	  .	  .   B800 Tseng Labs EVA
    = T 132x28	 9x13 1188x364	 16/256K  4   B800 Tseng ET3000 chipset
    = T 132x28	 8x12 1056x336	 16	  1   B800 Ahead B
    = T 132x28	 8x13 1056x364	 16/256K  4   B800 Tseng ET4000 chipset
    = T 132x28	 8x14 1056x392	 16	  .	.  STB Lightspeed ET4000/W32P
    = T 132x28	  .	  .	  .	  .	.  Cirrus 5320 chipset
    = G  64x32	 8x16  512x512	256	  1   A000 Realtek RTVGA
    = G 128x48	 8x16 1024x768	 16	  .	.  C&T 64310/65530 BIOS
25h = T  80x43	  .	  .	 16	  .	.  Avance Logic AL2101
    = G  80x60	 8x8   640x480	  .	  .   A000 Tseng Labs EVA
    = G  80x60	 8x8   640x480	 16/256K  1   A000 Tseng ET3000/4000 chipset
    = G    .	  .    640x480	 16	  .	.  VEGA VGA
    = G  80x60	 8x8   640x480	 16	  .   A000 Orchid Prodesigner VGA
    = G  80x60	 8x8   640x480	 16	  1   A000 Ahead B (same as 26h)
    = G    .	  .    640x480	 16	  .	.  NEC GB-1
    = G    .	  .    640x480	 16	  .	.  Cirrus 5320 chipset
    = G    .	  .    640x400	256	  .	.  Realtek RTVGA
26h = T  80x60	 8x8   640x480	  .	  .	.  Tseng Labs EVA
    = T  80x60	 8x8   640x480	 16/256K  3   B800 Tseng ET3000/4000 chipset
    = T  80x60	  .	  .	  .	  .	.  Allstar Peacock (VGA)
    = T  80x60	  .	  .	 16	  .	.  Orchid ProDesigner VGA
    = T  80x60	  .	  .	 16	  .	.  Avance Logic AL2101
    = G  80x60	 8x8   640x480	  .	  .	.  Ahead Systems EGA2001
    = G  80x60	 8x8   640x480	 16	  1   A000 Ahead B (same as 25h)
    = G    .	  .    640x480	256	  .	.  Realtek RTVGA
27h = T 132x25	 8x8  1056x200	mono	  .   B000 ATI EGA Wonder,ATI VIP
    = G    .	  .    720x512	 16	  .	.  VEGA VGA
    = G    .	  .    720x512	 16	  .	.  Genoa
    = G 100x75	 8x8   800x600	256	  1   A000 Realtek RTVGA [12]
    = G    .	  .    960x720	 16	  .	.  Avance Logic AL2101
28h = T ???x???  .	  .	  .	  .	.  VEGA VGA
    = G    .	  .    512x512	256	  .	.  Avance Logic AL2101
    = G    .	  .   1024x768	256	  .	.  Realtek RTVGA (1meg)
    = G 160x64	 8x16 1280x1024	 16	  .	.  Chips&Technologies 64310 [1]
29h = G    .	  .    640x400	256	  .	.  Avance Logic AL2101
    = G    .	  .    800x600	 16	  .	.  VEGA VGA
    = G 100x37	 8x16  800x600	 16	  .   A000 Orchid
    = G    .	  .    800x600	 16	  .   A000 STB,Genoa,Sigma
    = G    .	  .    800x600	 16	  .	.  Allstar Peacock (VGA)
    = G 100x37	 8x16  800x600	 16/256K  1   A000 Tseng ET3000/4000 chipset
    = G    .	  .    800x600	???	  .	.  EIZO MDB10
    = G    .	  .    800x600	 16	  .	.  Cirrus 5320 chipset
    = G   NA	  .    800x600	 16	  .	.  Compaq QVision 1024/1280
    = G    .	  .   1024x1024 256	  .	.  Realtek RTVGA BIOS v3.C10
2Ah = T 100x40	  .	  .	  .	  .	.  Allstar Peacock (VGA)
    = T 100x40	 8x16  800x640	 16	  .	.  Orchid Prodesigner VGA
    = T 100x40	 8x15  800x600	 16/256K  4   B800 Tseng ET3000/4000 chipset
    = T 100x40	 8x15  800x600	 16	  .	.  STB Lightspeed ET4000/W32P
    = G    .	  .    640x480	256	  .	.  Avance Logic AL2101
    = G    .	  .   1280x1024	 16	  .	.  Realtek RTVGA
2Bh = G    .	  .    800x600	 16	  .	.  Avance Logic AL2101
2Ch = G    .	  .    800x600	256	  .	.  Avance Logic AL2101
2Dh = G    .	  .    640x350	256	  .	.  VEGA VGA
    = G    .	  .    640x350	256/256K  .   A000 Orchid, Genoa, STB
    = G  80x25	 8x14  640x350	256/256K  1   A000 Tseng ET3000/4000 chipset
    = G    .	  .    640x350	256	  .	.  Cirrus 5320 chipset
    = G  80x25	 8x14  640x350	256	  .	.  STB Lightspeed ET4000/W32P
    = G    .	  .    768x1024	 16	  .	.  Avance Logic AL2101
2Eh = G    .	  .    640x480	256	  .	.  VEGA VGA
    = G  80x30	 8x16  640x480 256/256K	  .   A000 Orchid
    = G    .	  .    640x480 256/256K	  .   A000 STB,Genoa,Sigma
    = G  80x30	 8x16  640x480 256/256K	  1   A000 Tseng ET3000/4000 chipset
    = G    .	  .    640x480 256/256K	  .	.  Compaq QVision 1024/1280
    = G    .	  .    768x1024 256	  .	.  Avance Logic AL2101
2Fh = T 160x50	 8x8  1280x400	 16	  4   B800 Ahead B (Wizard/3270)
    = G    .	  .    720x512	256	  .	.  VEGA VGA
    = G    .	  .    720x512	256	  .	.  Genoa
    = G  80x25	 8x16  640x400 256/256K	  1   A000 Tseng ET4000 chipset
    = G    .	  .   1024x768	  4	  .	.  Avance Logic AL2101
30h = G  80x30	 8x16  640x480	256	  .	.  C&T 64310/65530 BIOS
    = G    .	  .	  .	  .	  .   B800 AT&T 6300
    = G    .	  .    720x350	  2	  .	.  3270 PC
    = G    .	  .    800x600	256	  .	.  VEGA VGA
    = G 100x37	 8x16  800x600 256/256K	  .   A000 Orchid
    = G    .	  .    800x600 256/256K	  .   A000 STB,Genoa,Sigma
    = G    .	  .    800x600	256	  .	.  Cardinal
    = G 100x37	 8x16  800x600 256/256K	  1   A000 Tseng ET3000/4000 chipset
    = G    .	  .   1024x768	 16	  .	.  Avance Logic AL2101
31h = G    .	  .   1024x768	256	  .	.  Avance Logic AL2101
32h = T  80x34	 8x10	  .	 16	  4   B800 Ahead B (Wizard/3270)
    = G    .	  .    640x480	256	  .	.  Compaq QVision 1024/1280
    = G 100x37	 8x16  800x600	256	  .	.  C&T 64310/65530 BIOS
33h = T 132x44	 8x8	  .	 16	  .   B800 ATI EGA Wonder,ATI VIP
    = T  80x34	 8x8	  .	 16	  4   B800 Ahead B (Wizard/3270)
34h = T  80x66	 8x8	  .	 16	  4   B800 Ahead B (Wizard/3270)
    = G    .	  .    800x600	256	  .	.  Compaq QVision 1024/1280
    = G 128x48	 8x16 1024x768	256	  .	.  Chips&Technologies 64310
36h = G    .	  .    960x720	 16	  .	.  VEGA VGA, STB
    = G    .	  .    960x720	 16	  .   A000 Tseng ET3000 only
    = G    .	  .   1280x1024	 16	  .	.  Avance Logic AL2101
37h = T 132x44	 8x8	  .	mono	  .   B800 ATI EGA Wonder,ATI VIP
    = G    .	  .   1024x768	 16	  .	.  VEGA VGA
    = G 128x48	 8x16 1024x768	 16	  .   A000 Orchid
    = G    .	  .   1024x768	 16	  .   A000 STB,Genoa,Sigma
    = G    .	  .   1024x768	 16	  .	.  Definicon
    = G 128x48	 8x16 1024x768	 16	  1   A000 Tseng ET3000/4000 chipset
    = G    .	  .   1024x768	 16	  .	.  Compaq QVision 1024/1280
    = G    .	  .   1280x1024 256	  .	.  Avance Logic AL2101
38h = G    .	  .   1024x768	256	  .	.  STB VGA/EM-16 Plus (1MB)
    = G 128x48	 8x16 1024x768	256/256K  1   A000 Tseng ET4000 chipset
    = G    .	  .   1024x768	256	  .	.  Orchid ProDesigner II
    = G    .	  .   1024x768	256	  .	.  Compaq QVision 1024/1280
    = G 160x64	 8x16 1280x1024	256	  .	.  Chips&Technologies 64310 [1]
39h = G    .	  .   1280x1024	 16	  .	.  Compaq QVision 1280
3Ah = G    .	  .   1280x1024	256	  .	.  Compaq QVision 1280
3Bh = G    .	  .    512x480	256	  .	.  Compaq QVision 1024/1280
3Ch = G    .	  .    640x400	 64K	  .	.  Compaq QVision 1024/1280
3Dh = G    .	  .   1280x1024	 16	  .	.  Definicon
    = G 128x64	 8x16 1280x1024	 16	  1   A000 Tseng ET4000 v3.00 [1,7]
3Eh = G    .	  .   1280x961	 16	  .	.  Definicon
    = G    .	  .    640x480	 64K	  .	.  Compaq QVision 1024/1280
3Fh = G    .	  .   1280x1024 256	  .	.  Hercules ??? (ET4000W32)
    = G    .	  .    800x600	 64K	  .	.  Compaq QVision 1024/1280
40h = T  80x43	  .	  .	  .	  .	.  VEGA VGA, Tecmar VGA/AD
    = T  80x43	  .	  .	  .	  .	.  Video7 V-RAM VGA
    = T  80x43	  .	  .	  .	  .	.  Tatung VGA
    = T 100x30	  .	  .	 16	  .	.  MORSE VGA
    = T 100x30	  .	  .	  .	  .	.  Cirrus 510/520 chipset
    = T  80x25	  .    720x350	mono	  .	.  Genoa SuperEGA BIOS 3.0+
    = G    .	  .    320x200	 64K	  .	.  Avance Logic AL2101
    = G  80x25	 8x16  640x400	  2	  1   B800 AT&T 6300, AT&T VDC600
    = G  80x25	 8x16  640x400	  2	  1   B800 Olivetti Quaderno
    = G  80x25	 8x16  640x400	  2	  1   B800 Compaq Portable
    = G  80x30	 8x16  640x480	32K	  .	.  Chips&Technologies 64310
    = G    .	  .   1024x768	 64K	  .	.  Compaq QVision 1280
41h = T 132x25	  .	  .	  .	  .	.  VEGA VGA
    = T 132x25	  .	  .	  .	  .	.  Tatung VGA
    = T 132x25	  .	  .	  .	  .	.  Video7 V-RAM VGA
    = T 100x50	  .	  .	 16	  .	.  MORSE VGA
    = T 100x50	  .	  .	  .	  .	.  Cirrus 510/520 chipset
    = T  80x34	 9x14  720x476	 16/256K  .   B800 WD90C
    = T  80x34	 9x14	  .	 16	  .   B800 Diamond Speedstar 24X
    = G    .	  .    512x512	 64K	  .	.  Avance Logic AL2101
    = G    .	  .    640x200	 16	  1	.  AT&T 6300
    = G  80x30	 8x16  640x480	 64K	  .	.  Chips&Technologies 64310
    = G  80x25	  .    720x348	mono	  .   B000 Genoa SuperEGA BIOS 3.0+
42h = T 132x43	  .	  .	  .	  .	.  VEGA VGA
    = T 132x43	  .	  .	  .	  .	.  Tatung VGA
    = T 132x43	  .	  .	  .	  .	.  Video7 V-RAM VGA
    = T  80x34	 9x10	  .	  4	  4   B800 Ahead B (Wizard/3270)
    = T 100x60	  .	  .	 16	  .	.  MORSE VGA
    = T 100x60	  .	  .	  .	  .	.  Cirrus 510/520 chipset
    = G  80x25	 8x16  640x400	 16	  .	.  AT&T 6300, AT&T VDC600
    = G    .	  .    640x400	 64K	  .	.  Avance Logic AL2101
    = G  80x25	  .    720x348	mono	  .   B800 Genoa SuperEGA BIOS 3.0+
    = G 100x37	 8x16  800x600	 32K	  .	.  Chips&Technologies 64310
43h = T  80x60	  .	  .	  .	  .	.  VEGA VGA
    = T  80x60	  .	  .	  .	  .	.  Tatung VGA
    = T  80x60	  .	  .	  .	  .	.  Video7 V-RAM VGA
    = T  80x45	 9x8	  .	  4	  4   B800 Ahead B (Wizard/3270)
    = T 100x75	  .	  .	 16	  .	.  MORSE VGA
    = T  80x29	  .    720x348	mono	  .	.  Genoa SuperEGA BIOS 3.0+
    = G    .	  . 640x200 of 640x400 viewport	   AT&T 6300 (unsupported)
    = G    .	  .    640x480	 64K	  .	.  Avance Logic AL2101
    = G 100x37	 8x16  800x600	 64K	  .	.  Chips&Technologies 64310
44h =	disable VDC and DEB output		.  AT&T 6300
    = T 100x60	  .	  .	  .	  .	.  VEGA VGA
    = T 100x60	  .	  .	  .	  .	.  Tatung VGA
    = T 100x60	  .	  .	  .	  .	.  Video7 V-RAM VGA
    = T  80x32	  .    720x352	mono	  .	.  Genoa SuperEGA BIOS 3.0+
    = G    .	  .    800x600	 64K	  .	.  Avance Logic AL2101
45h = T 132x28	  .	  .	  .	  .	.  Tatung VGA
    = T 132x28	  .	  .	  .	  .	.  Video7 V-RAM VGA
    = T  80x44	  .    720x352	mono	  .	.  Genoa SuperEGA BIOS 3.0+
46h = T 132x25	 8x14	  .	mono	  .	.  Genoa 6400
    = T 132x25	 9x14	  .	mono	  .	.  Genoa SuperEGA BIOS 3.0+
    = G 100x40	 8x15  800x600	  2	  .	.  AT&T VDC600
47h = T 132x29	 8x12	  .	mono	  .	.  Genoa 6400
    = T 132x29	 9x12	  .	mono	  .	.  Genoa SuperEGA BIOS 3.0+
    = T 132x28	 9x16 1188x448	 16/256K  .   B800 WD90C
    = T 132x28	 9x16	  .	 16	  .   B800 Diamond Speedstar 24X
    = G 100x37	 8x16  800x600	 16	  .	.  AT&T VDC600
48h = T 132x32	 8x12	  .	mono	  .	.  Genoa 6400
    = T 132x32	 9x11	  .	mono	  .	.  Genoa SuperEGA BIOS 3.0+
    = G  80x50	 8x8   640x400	  2	  .   B800 AT&T 6300, AT&T VDC600
    = G  80x50	 8x8   640x400	  2	  .   B800 Olivetti Quaderno
49h = T 132x44	 8x8	  .	mono	  .	.  Genoa 6400
    = T 132x44	 9x8	  .	mono	  .	.  Genoa SuperEGA BIOS 3.0+
    = G  80x30	 8x16  640x480	  .	  .	.  Lava Chrome II EGA
    = G  80x30	 8x16  640x480	  .	  .   A000 Diamond Stealth64 Video 2xx1
4Bh = G 100x37	 8x16  800x600	  .	  .   A000 Diamond Stealth64 Video 2xx1
4Dh = T 120x25	  .	  .	  .	  .	.  VEGA VGA
    = G    .	  .    512x480	 16M	  .	.  Compaq QVision 1024/1280
    = G 128x48	 8x16 1024x768	  .	  .   A000 Diamond Stealth64 Video 2xx1
4Eh = T 120x43	  .	  .	  .	  .	.  VEGA VGA
    = T  80x60	 8x8	  .	 16/256K  .   B800 Oak OTI-067/OTI-077 [8]
    = G    .	  .    640x400	 16M	  .	.  Compaq QVision 1024/1280
    = G 144x54	 8x16 1152x864	  .	  .   A000 Diamond Stealth64 Video 2xx1
4Fh = T 132x25	  .	  .	  .	  .	.  VEGA VGA
    = T 132x60	  .	  .	  .	  .	.  some Oak Tech VGA [8]
    = G    .	  .    640x480	 16M	  .	.  Compaq QVision 1280
50h = T  80x30	 8x16	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = T  80x34	  .	  .	  .	  .	.  Lava Chrome II EGA
    = T  80x43	  .	  .	mono	  .	.  VEGA VGA
    = T 132x25	 9x14	  .	mono	  .	.  Ahead Systems EGA2001
    = T 132x25	 9x14	  .	  4	  4   B800 Ahead B
    = T 132x25	 8x14	  .	 16	  8   B800 OAK Technologies VGA-16
    = T 132x25	 8x14	  .	 16/256K  .   B800 Oak OTI-037/067/077 [8]
    = T 132x25	 8x14 1056x350	 16	  8   B800 UM587 chipset
    = T 132x30	  .	  .	 16	  .	.  MORSE VGA
    = T 132x30	  .	  .	  .	  .	.  Cirrus 510/520 chipset
    = G  80x30	 8x16  640x480	 16	  .	.  Paradise EGA-480
    = G  80x30	 8x16  640x480	 16	  .	.  NEL Electronics BIOS
    = G  80x30	 8x16  640x480	 16M	  .	.  Chips&Technologies 64310
    = G    .	  .    640x480	mono???	  .	.  Taxan 565 EGA
    = G  40x25	 8x8   320x200	  .	  .	.  Genoa SuperEGA BIOS 3.0+
51h = T  80x30	 8x16	  .	  .	  .	.  Paradise EGA-480
    = T  80x30	 9x16	  .	  .	  .	.  NEL Electronics BIOS
    = T  80x30	  .	  .	  .	  .	.  Lava Chrome II EGA
    = T  80x43	 8x11	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = T 132x25	  .	  .	mono	  .	.  VEGA VGA
    = T 132x28	 9x12	  .	  4	  4   B800 Ahead B
    = T 132x43	 8x8	  .	 16	  5   B800 OAK Technologies VGA-16
    = T 132x43	 8x8	  .	 16/256K  .   B800 Oak OTI-037/067/077
    = T 132x43	 8x8  1056x344	 16	  5   B800 UM587 chipset
    = T 132x50	  .	  .	 16	  .	.  MORSE VGA
    = T 132x50	  .	  .	  .	  .	.  Cirrus 510/520 chipset
    = G  80x34	 8x14  640x480	 16	  .	.  ATI EGA Wonder
    = G  80x25	 8x8   640x200	  .	  .	.  Genoa SuperEGA BIOS 3.0+
52h = T  80x60	  .	  .	  .	  .	.  Lava Chrome II EGA
    = T  80x60	 8x8	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = T 132x43	  .	  .	mono	  .	.  VEGA VGA
    = T 132x44	 9x8	  .	mono	  .	.  Ahead Systems EGA2001
    = T 132x44	 9x8	  .	  4	  2   B800 Ahead B
    = T 132x60	  .	  .	 16	  .	.  MORSE VGA
    = T 132x60	  .	  .	  .	  .	.  Cirrus 510/520 chipset
    = G  80x25	 8x19  640x480	 16	  1   A000 AX VGA (Kanji&superimpose)
    = G  94x29	 8x14  752x410	 16	  .	.  ATI EGA Wonder
    = G 100x75	 8x8   800x600	 16	  1   A000 OAK Technologies VGA-16
    = G 100x75	 8x8   800x600	 16	  .   A000 Oak OTI-037 chipset [8]
    = G 100x37	 8x16  800x600	 16	  .   A000 Oak OTI-067/077 chips [8]
    = G 100x75	 8x8   800x600	 16	  .   A000 UM587 chipset
    = G 128x30	 8x16 1024x480	 16	  .	.  NEL Electronics BIOS
53h = T  80x25	 8x16	  .	  .	  .	.  NEL Electronics BIOS
    = T  80x60	  .	  .	 16	  .	.  MORSE VGA
    = T  80x60	  .	  .	  .	  .	.  Cirrus 510/520 chipset
    = T 132x25	 8x14	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = T 132x43	  .	  .	  .	  .	.  Lava Chrome II EGA
    = G  80x25	 8x19  640x480	 16	  1   A000 AX VGA (Kanji, no superimp.)
    = G    .	  .    640x480	256	  .	.  Oak VGA
    = G  80x30	 8x16  640x480	256	  .   A000 Oak OTI-067/OTI-077 [8]
    = G 100x40	 8x14  800x560	 16	  .	.  ATI EGA Wonder,ATI VIP
    = G    .	  .	  .	  .	  .	.  AX PC
54h = T 132x25	  .	  .	  .	  .	.  Lava Chrome II EGA
    = T 132x30	 8x16	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = T 132x43	 8x8	  .	  .	  .	.  Paradise EGA-480
    = T 132x43	 8x8	  .	  .	  .	.  NEL Electronics BIOS
    = T 132x43	 7x9	  .	 16/256K  .   B800 Paradise VGA
    = T 132x43	 8x9	  .	 16/256K  .   B800 Paradise VGA on multisync
    = T 132x43	  .	  .	  .	  .	.  Taxan 565 EGA
    = T 132x43	  .	  .	  .	  .	.  AST VGA Plus
    = T 132x43	  .	  .	  .	  .	.  Hewlett-Packard D1180A
    = T 132x43	 7x9	  .	 16	  .	.  AT&T VDC600
    = T 132x43	 9x9  1188x387	 16/256K  .   B800 WD90C
    = T 132x43	 9x9  1188x387	 16/256K  .   B800 Diamond Speedstar 24X
    = T 132x43	 9x9  1188x387	 16/256K  .   B800 Diamond Stealth 24
    = T 132x43	 8x8	  .	  .	  .   B800 Diamond Stealth64 Video 2xx1
    = T 132x43	 8x8  1056x350	 16/256K  .	.  Cirrus CL-GD5420/5422/5426
    = T 132x50	 8x8	  .	 16	  .   A000 NCR 77C22 [9]
    = G 100x42	 8x14  800x600	 16	  .   A000 ATI EGA Wonder, VGA Wonder
    = G 100x42	 8x14  800x600	 16	  .   A000 ATI Ultra 8514A, ATI XL
    = G    .	  .    800x600	256	  .   A000 Oak VGA
    = G 100x37	 8x16  800x600	256	  .   A000 Oak OTI-067/077 chips [8]
55h = T  80x66	 8x8	  .	 16/256K  .   A000 ATI VIP
    = T 132x25	 8x14	  .	  .	  .	.  Paradise EGA-480
    = T 132x25	 8x14	  .	  .	  .	.  NEL Electronics BIOS
    = T 132x25	 7x16	  .	 16/256K  .   B800 Paradise VGA
    = T 132x25	 8x16	  .	 16/256K  .   B800 Paradise VGA on multisync
    = T 132x25	  .	  .	  .	  .	.  Taxan 565 EGA
    = T 132x25	  .	  .	  .	  .	.  AST VGA Plus
    = T 132x25	  .	  .	  .	  .	.  Hewlett-Packard D1180A
    = T 132x25	 7x16	  .	 16	  .	.  AT&T VDC600
    = T 132x25	 8x16	  .	 16	  .   A000 NCR 77C22 [9]
    = T 132x25	 9x16 1188x400	 16/256K  .   B800 WD90C
    = T 132x25	 9x16 1188x400	 16/256K  .   B800 Diamond Speedstar 24X
    = T 132x25	 9x16 1188x400	 16/256K  .   B800 Diamond Stealth 24
    = T 132x25	 8x16	  .	  .	  .   B800 Diamond Stealth64 Video 2xx1
    = T 132x25	 8x14 1056x350	 16/256K  .	.  Cirrus CL-GD5420/5422/5426
    = T 132x43	 8x11	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = G  94x29	 8x14  752x410	  .	  .	.  Lava Chrome II EGA
    = G 128x48	 8x16 1024x768	 16/256K  .   A000 ATI VGA Wonder v4+  [5]
    = G    .	  .   1024x768	 16/256K  .	.  ATI VGA Wonder Plus
    = G    .	  .   1024x768	 16/256K  .	.  ATI Ultra 8514A,ATI XL
    = G 128x48	 8x16 1024x768	  4	  .   A000 Oak OTI-067/077 chips [8]
56h = T 132x43	 8x8	  .	  3???	  2   B000 NSI Smart EGA+
    = T 132x43	 7x9	  .	  4	  .   B000 Paradise VGA
    = T 132x43	 8x9	  .	  4	  .   B000 Paradise VGA on multisync
    = T 132x43	  .	  .	mono	  .	.  Taxan 565 EGA
    = T 132x43	 7x9	  .	  2	  .	.  AT&T VDC600
    = T 132x43	 9x8	  .	  .	  .	.  NEL Electronics BIOS
    = T 132x50	 8x8	  .	  4	  .   A000 NCR 77C22 [9]
    = T 132x60	 8x8	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = G    .	  .   1024x768	 16	  .   A000 Oak VGA
    = G 128x48	 8x16 1024x768	 16	  .   A000 Oak OTI-067/077 chips [8]
57h = T 132x25	 8x14	  .	  3???	  4   B000 NSI Smart EGA+
    = T 132x25	 7x16	  .	  4	  .   B000 Paradise VGA
    = T 132x25	 8x16	  .	  4	  .   B000 Paradise VGA on multisync
    = T 132x25	 9x14	  .	  .	  .	.  NEL Electronics BIOS
    = T 132x25	  .	  .	mono	  .	.  Taxan 565 EGA
    = T 132x25	 7x16	  .	  2	  .	.  AT&T VDC600
    = T 132x25	 9x14	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = T 132x25	 8x16	  .	  4	  .   A000 NCR 77C22 [9]
    = G  96x48	 8x16  768x1024	 16	  .   A000 Oak OTI-067/077 chips [8]
58h = T  80x33	 8x14	  .	 16	  .   B800 ATI EGA Wonder,ATI VIP
    = T  80x32	 9x16	  .	 16	  .	.  Genoa 6400
    = T  80x43	 8x8	  .	  .	  .	.  NEL Electronics BIOS
    = T 132x30	 9x16	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = G 100x75	 8x8   800x600	 16/256K  .   A000 Paradise VGA
    = G 100x75	 8x8   800x600	 16	  .	.  AT&T VDC600
    = G 100x75	 8x8   800x600	 16	  .   A000 NCR 77C22 [9]
    = G 100x75	 8x8   800x600	 16	  .   A000 Diamond Speedstar 24X
    = G 100x75	 8x8   800x600	 16/256K  .   A000 Paradise VGA, WD90C
    = G    .	  .    800x600	 16	  .	.  AST VGA Plus, Compaq VGA
    = G    .	  .    800x600	 16	  .	.  Dell VGA
    = G    .	  .    800x600	 16	  .	.  Hewlett-Packard D1180A
    = G    .	  .    800x600	???	  .	.  ELT VGA PLUS 16
    = G 100x37	 8x16  800x600	 16/256K  .   A000 Cirrus CL-GD5420/5422/5426
    = G 160x64	 8x16 1280x1024	 16	  .   A000 Oak OTI-077 chipset [8]
59h = T  80x43	 9x8	  .	  .	  .	.  NEL Electronics BIOS
    = T  80x66	 8x8	  .	 16/256K  .   A000 ATI VIP
    = T 132x43	 9x11	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = G 100x75	 8x8   800x600	  2	  .   A000 Paradise VGA
    = G 100x75	 8x8   800x600	  2	  .	.  AT&T VDC600
    = G    .	  .    800x600	  2	  .	.  AST VGA Plus, Compaq VGA
    = G    .	  .    800x600	  2	  .	.  Dell VGA
    = G    .	  .    800x600	  2	  .	.  Hewlett-Packard D1180A
    = G 100x75	 8x8   800x600	  2	  .   A000 NCR 77C22 [9]
    = G 128x48	 8x16 1024x768	256	  .   A000 Oak OTI-077 chipset [8]
5Ah = T  80x60	 8x8	  .	  .	  .	.  NEL Electronics BIOS
    = T 132x60	 9x8	  .	 16/256K  .   B800 Trident TVGA 8800/8900
    = G 128x48	 8x16 1024x768	  2	  .   A000 NCR 77C22 [9]
5Bh = T  80x30	 8x16	  .	  .	  .   B800 ATI VGA Wonder (undoc)
    = G    .	  .    640x350	256	  .	.  Genoa 6400
    = G  80x25	 8x16  640x400	 32K	  .   A000 Oak OTI-067/077 chips [8]
    = G    .	  .    800x600	 16	  .	.  Maxxon, SEFCO TVGA, Imtec
    = G 100x75	 8x8   800x600	 16/256K  .   A000 Trident TVGA 8800, 8900
    = G    .	  .    800x600	???	  .	.  Vobis MVGA
    = G 100x37	 8x16  800x600	  .	  .	.  NEL Electronics BIOS
    = G 128x48	 8x16 1024x768	 16	  .   A000 NCR 77C22 [1,9]
5Ch = T 100x37	 8x16	  .	  .	  .	.  NEL Electronics BIOS
    = G    .	  .    640x400	256	  .	.  Logix, ATI Prism Elite
    = G    .	  .    640x400	256	  .	.  Maxxon, SEFCO TVGA, Imtec
    = G  80x25	 8x16  640x400	256/256K  .   A000 Zymos Poach, Hi Res 512
    = G  80x25	 8x16  640x400	256/256K  .   A000 Trident TVGA 8800/8900
    = G  80x30	 8x16  640x480	256	  .	.  Genoa 6400
    = G  80x30	 8x16  640x480	 32K	  .   A000 Oak OTI-077 chipset [8]
    = G 100x75	 8x8   800x600	256	  .   A000 NCR 77C22 [9]
    = G 100x75	 8x8   800x600	256/256K  .   A000 WD90C
    = G 100x75	 8x8   800x600	256/256K  .   A000 Diamond Speedstar 24X
    = G 100x37	 8x16  800x600	256/256K  .   A000 Cirrus CL-GD5420/5422/5426
5Dh = T 100x75	 8x8	  .	  .	  .	.  NEL Electronics BIOS
    = G  80x25	 8x14  640x350	 64K	  .	.  STB Lightspeed ET4000/W32P
    = G    .	  .    640x480	256	  .	.  Logix, ATI Prism Elite
    = G    .	  .    640x480	256	  .	.  Maxxon, SEFCO TVGA, Imtec
    = G  80x30	 8x16  640x480	256/256K  .   A000 Zymos Poach, Hi Res 512
    = G  80x30	 8x16  640x480	256/256K  .   A000 Trident TVGA 8800 (512K)
    = G 128x48	 8x16 1024x768	 16	  .   A000 NCR 77C22 [9]
    = G 128x48	 8x16 1024x768	 16/256K  .   A000 WD90C
    = G 128x48	 8x16 1024x768	 16	  .   A000 Diamond Speedstar 24X
    = G 128x48	 8x16 1024x768	 16/256K  .   A000 Cirrus CL-GD5420/5422/5426
5Eh = G    .	  .    640x400	256	  .	.  Paradise VGA,VEGA VGA
    = G    .	  .    640x400	256	  .	.  AST VGA Plus, NCR 77C22
    = G    .	  .    640x400	256	  .	.  Compaq VGA, Dell VGA
    = G  80x25	 8x16  640x400	256	  .	.  AT&T VDC600
    = G  80x25	 8x16  640x400	256	  .   A000 NCR 77C22 [9]
    = G  80x25	 8x16  640x400	256/256K  .   A000 WD90C
    = G  80x25	 8x16  640x400	256/256K  .   A000 Diamond Speedstar 24X
    = G    .	  .    800x600	 16	  .	.  Logix, ATI Prism Elite
    = G 100x37	 8x16  800x600	 16	  .	.  NEL Electronics BIOS
    = G 100x75	 8x8   800x600	256	  .	.  Genoa 6400
    = G 100x75	 8x8   800x600	256/256K  .   A000 Zymos Poach, Trident 8900
    = G 100x75	 8x8   800x600	256/256K  .   A000 Hi Res 512
5Fh = G  80x25	 8x16  640x400	 64K	  .	.  STB Lightspeed ET4000/W32P
    = G    .	  .    640x480	256	  .	.  Paradise VGA
    = G    .	  .    640x480	256	  .	.  AST VGA Plus, NCR 77C22
    = G    .	  .    640x480	256	  .	.  Compaq VGA, Dell VGA
    = G    .	  .    640x480	256	  .	.  Hewlett-Packard D1180A
    = G  80x30	 8x16  640x480	256	  .	.  AT&T VDC600 (512K)
    = G  80x30	 8x16  640x480	256	  .   A000 NCR 77C22 [9]
    = G  80x30	 8x16  640x480	256/256K  .   A000 WD90C
    = G  80x30	 8x16  640x480	256/256K  .   A000 Diamond Speedstar 24X
    = G  80x30	 8x16  640x480	256/256K  .   A000 Cirrus CL-GD5420/5422/5426
    = G    .	  .   1024x768	 16	  .	.  Logix, ATI Prism Elite
    = G    .	  .   1024x768	 16	  .	.  Maxxon, Imtec
    = G 128x48	 8x16 1024x768	 16	  .	.  Genoa 6400
    = G 128x48	 8x16 1024x768	 16/256K  .   A000 Zymos Poach, Hi Res 512
    = G 128x48	 8x16 1024x768	 16/256K  .   A000 Trident TVGA 88/8900 512K
60h = T 132x25	 8x14	  .	 16/64	  8   B800 Quadram Ultra VGA
    = T 132x25	 8x14	  .	 16	  .	.  Genoa 6400
    = T 132x25	 8x14	  .	 16	  .	.  Genoa SuperEGA BIOS 3.0+
    = T 132x25	  .	  .	  .	  .	.  Cirrus 5320 chipset
    = T 132x25	 8x16 1056x400	 16	  .   B800 Chips&Technologies chipset
    = G  80x???  .    ???x400	  .	  .	.  Corona/Cordata BIOS 4.10+
    = G  80x25	 8x16  640x400	256	  1   A000 Ahead A, Ahead B
    = G    .	  .    752x410	  .	  .	.  VEGA VGA
    = G    .	  .    752x410	 16	  .	.  Tatung VGA
    = G    .	  .    752x410	 16	  .	.  Video7 V-RAM VGA
    = G 128x48	 8x16 1024x768	  4/256K  .   A000 Trident TVGA 8900
    = G 128x48	 8x16 1024x768	256/256K  .   A000 WD90C
    = G 128x48	 8x16 1024x768	256/256K  .   A000 Diamond Speedstar 24X
    = G 128x48	 8x16 1024x768	256/256K  .   A000 Cirrus CL-GD5420/5422/5426
    = G 144x54	 8x16 1152x864	  .	  .   A000 Diamond Stealth64 Video 2xx1
61h = T 132x29	 8x12	  .	 16/64	  8   B800 Quadram Ultra VGA
    = T 132x29	 8x8	  .	 16	  .	.  Genoa 6400
    = T 132x29	 8x8	  .	 16	  .	.  Genoa SuperEGA BIOS 3.0+
    = T 132x50	  .	  .	  .	  .	.  Cirrus 5320 chipset
    = T 132x50	 8x8  1056x400	 16	  .   B800 Chips&Technologies chipset
    = T 132x50	 8x16 1056x800	 16	  .   B800 Chips&Technologies 64310
    = G    .	  .    ???x400	  .	  .	.  Corona/Cordata BIOS 4.10+
    = G  80x25	 8x16  640x400	256	  .   A000 ATI VGA Wonder,VGA Wonder+
    = G  80x25	 8x16  640x400	256	  .   A000 ATI Ultra 8514A,ATI XL
    = G  80x25	 8x16  640x400	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = G  80x30	 8x16  640x480	256	  1   A000 Ahead A, Ahead B (512K)
    = G    .	  .    720x540	  .	  .	.  VEGA VGA
    = G    .	  .    720x540	 16	  .	.  Tatung VGA
    = G    .	  .    720x540	 16	  .	.  Video7 V-RAM VGA
    = G  96x64	 8x16  768x1024	 16/256K  .   A000 Trident TVGA 88/8900 512K
    = G 128x48	 8x16 1024x768	256	  .   A000 NCR 77C22 [1,9]
    = G 144x54	 8x16 1152x864	  .	  .   A000 Diamond Stealth64 Video 2xx1
62h = T 132x32	 8x11	  .	 16/64	  6   B800 Quadram Ultra VGA
    = T 132x32	 8x12	  .	 16	  .	.  Genoa 6400
    = T 132x32	 8x11	  .	 16	  .	.  Genoa SuperEGA BIOS 3.0+
    = T 132x43	 8x8  1056x344	 16	  .   B800 C&T 82C450 BIOS
    = G    .	  .    640x450	 16	  .	.  Cirrus 510/520 chipset
    = G  80x30	 8x16  640x480	256	  .   A000 ATI VGA Wonder,VGA Wonder+
    = G  80x30	 8x16  640x480	256	  .   A000 ATI Ultra 8514A,ATI XL
    = G  80x30	 8x16  640x480	32K	  .   A000 WD90C
    = G  80x30	 8x16  640x480	32K	  .   A000 Diamond Speedstar 24X
    = G    .	  .    800x600	  .	  .	.  VEGA VGA
    = G    .	  .    800x600	 16	  .	.  Tatung VGA
    = G    .	  .    800x600	 16	  .	.  Video7 V-RAM VGA
    = G 100x75	 8x8   800x600	256	  1   A000 Ahead A, Ahead B (512K)
    = G 128x48	 8x16 1024x768	256/256K  .   A000 Trident TVGA 8900, Zymos
    = G 128x48	 8x16 1024x768	256	  .   A000 NCR 77C22 [9]
63h = T 132x44	 8x8	  .	 16/64	  5   B800 Quadram Ultra VGA
    = T 132x44	 8x8	  .	 16	  .	.  Genoa 6400
    = T 132x44	 8x8	  .	 16	  .	.  Genoa SuperEGA BIOS 3.0+
    = G    .	  .    720x540	 16	  .	.  MORSE VGA
    = G    .	  .    720x540	 16	  .	.  Cirrus 510/520 chipset
    = G 100x42	 8x14  800x600	256	  .   A000 ATI VGA Wonder,VGA Wonder+
    = G 100x42	 8x14  800x600	256	  .   A000 ATI Ultra 8514A,ATI XL
    = G    .	  .    800x600	32K	  .   A000 WD90C
    = G    .	  .    800x600	32K	  .   A000 Diamond Speedstar 24X
    = G 128x48	 7x16 1024x768	256	  1   A000 Ahead B (1MB)
    = G    .	  .   1024x768	  2	  .	.  Video7 V-RAM VGA
64h = T 132x60	 8x8	  .	 16	  .	.  Genoa 6400
    = T  80x43	 8x8   528x344	 16	  .   B800 C&T 82C450 BIOS
    = G    .	  .    640x480	64K	  .   A000 Cirrus CL-GD 5422/5426
    = G    .	  .    800x600	 16	  .	.  MORSE VGA
    = G    .	  .    800x600	 16	  .	.  Cirrus 510/520 chipset
    = G    .	  .    800x600	???	  .	.  SAMPO-Mira VGA
    = G    .	  .   1024x768	  4	  .	.  Video7 V-RAM VGA
    = G 128x48	 8x16 1024x768	256	  .   A000 ATI VGA Wonder Plus,ATI XL
    = G 160x64	 8x16 1280x1024	 16/256K  .   A000 WD90C [1]
    = G 160x64	 8x16 1280x1024	 16/256K  .   A000 Diamond Speedstar 24X [1]
65h = T  80x50	 8x8   528x400	 16	  .   B800 C&T 82C450 BIOS
    = G    .	  .    800x600	64K	  .   A000 Cirrus CL-GD 5422/5426
    = G    .	  .   1024x768	 16	  .	.  Video7 V-RAM VGA
    = G 128x48	 8x16 1024x768	 16	  .   A000 ATI VGA Wonder
66h = T  80x50	 8x8   640x400	 16/256K  .   B800 WD90C
    = T  80x50	 8x8	  .	 16	  .   B800 Diamond Speedstar 24X
    = G    .	  .    640x400	256	  .	.  Tatung VGA
    = G    .	  .    640x400	256	  .	.  Video7 V-RAM VGA
    = G    .	  .    640x480	32K	  .   A000 Cirrus CL-GD 5422/5426
67h = T  80x43	 8x8   640x344	 16/256K  .   B800 WD90C
    = T  80x43	 8x8	  .	 16	  .   B800 Diamond Speedstar 24X
    = G    .	  .    640x480	256	  .	.  Video7 V-RAM VGA
    = G    .	  .    800x600	32K	  .   A000 Cirrus CL-GD 5422/5426
    = G 128x48	 8x16 1024x768	  4	  .   A000 ATI VGA Wonder
    = G 160x64	 8x16 1280x1024	 16	  .   A000 NCR 77C22 [1,9]
68h = G  80x25	 8x16  640x400	  .	  .   A000 Diamond Stealth64 Video 2xx1
69h = T 132x50	 8x8  1056x400	 16/256K  .   B800 WD90C
    = T 132x50	 8x8	  .	 16	  .   B800 Diamond Speedstar 24X
    = G  80x30	 8x16  640x480	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = G    .	  .    720x540	256	  .   A000 Video7 V-RAM VGA
6Ah = G    .	  .    800x600	 16	  .   A000 VESA standard interface
    = G 100x75	 8x8   800x600	 16	  .   A000 Genoa 6400
    = G 100x75	 8x8   800x600	 16	  .   A000 Diamond Speedstar 24X
    = G    .	  .    800x600	 16	  .   A000 Ahead A
    = G 100x75	 8x8   800x600	 16	  1   A000 Ahead B (VESA) [see 71h]
    = G    .	  .    800x600	 16	  .	.  Zymos Poach, Hi Res 512
    = G    .	  .    800x600	 16	  .	.  Epson LT-386SX in CRT Mode
    = G    .	  .    800x600	 16	  .	.  Compuadd 316SL in CRT Mode
    = G 100x37	 8x16  800x600	 16/256K  .   A000 Cirrus CL-GD5420/5422/5426
    = G 100x37	 8x16  800x600	 16	  .   A000 Diamond Stealth64 Video 2xx1
    = G 100x42	 8x14  800x600	  .	  .   A000 ATI VGA Wonder (undoc)
    = G    .	  .    800x600	 16	  .   A000 Chips&Technologies chipset
    = G 160x64	 8x16 1280x1024 256	  .   A000 NCR 77C22 [1,9]
6Bh = T 100x37	 8x16	  .	 16	  .	.  Genoa 6400
    = T 100x37	 8x16	  .	  .	  .	.  NEL Electronics BIOS
    = G 100x37	 8x16  800x600	  .	  .   A000 Diamond Stealth64 Video 2xx1
6Ch = G  80x30	 8x16  640x480	 16M	  .   A000 Trident 8900CL/BIOS C04
    = G 100x75	 8x8   800x600	256	  .	.  Genoa 6400
    = G 128x48	 8x16 1024x768	  2	  .   A000 Diamond Stealth64 Video 2xx1
    = G 160x60	 8x16 1280x960	 16/256K  .   A000 WD90C [1]
    = G 160x60	 8x16 1280x960	 16/256K  .   A000 Diamond Speedstar 24X [1]
    = G 160x64	 8x16 1280x1024	 16/256K  .   A000 Cirrus CL-GD 5422/5426 [1]
6Dh = G  80x25	 8x14  640x350	 64K	  .   A000 STB Lightspeed ET4000/W32P
    = G 128x48	 8x16 1024x768	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = G 160x64	 8x16 1280x1024 256/256K  .   A000 Cirrus CL-GD 5422/5426 [1]
6Eh = G  40x25	 8x8   320x200	 64K	  .   A000 Cirrus CL-GD 5422/5426
    = G 160x64	 8x16 1280x1024	  2	  .   A000 Diamond Stealth64 Video 2xx1
6Fh = G  40x25	 8x8   320x200	 16M	  .   A000 Cirrus CL-GD 5422/5426
    = G 160x64	 8x16 1280x1024	  .	  .   A000 Diamond Stealth64 Video 2xx1
70h =	extended mode set (see AX=0070h)	.  Everex Micro Enhancer EGA
    = T  40x25	 8x8	  .	 16	  8   B800 Quadram (CGA double scan)
    = T  40x25	 8x8   (CGA dblscan)	  .	.  Genoa SuperEGA BIOS 3.0+
    = G    .	  .    360x480	256	  .	.  Cirrus 510/520/5320 chips
    = G  90x28	 8x14  720x392	 16	  1   A000 Ahead B
    = G  80x30	 8x16  640x480	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = G 100x38	 8x16  800x600	 16	  .   A000 C&T chipset, Cardinal
    = G    .	  .   1024x480	256	  .   A000 Trident 8900C BIOS C3.0
71h = T  80x25	 8x8	  .	 16	  8   B800 Quadram (CGA double scan)
    = T  80x25	 8x8   (CGA dblscan)	  .	.  Genoa SuperEGA BIOS 3.0+
    = G    .	  .    528x400	256	  .	.  Cirrus 510/520 chipset
    = G  80x30	 8x16  640x480	 16M	  .   A000 Cirrus CL-GD 5422/5426
    = G  80x30	 8x16  640x480	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = G 100x35	 8x16  800x600	 16/64	  .   A000 NSI Smart EGA+
    = G 100x75	 8x8   800x600	 16	  1   A000 Ahead B (same as 6Ah)
    = G    .	  .    960x720	 16	  .	.  C&T chipset, Cardinal
    = G    .	  .   1024x480	256	  .   A000 Trident 8900C BIOS C3.0
72h = T  80x60	 8x8	  .	 16	  .   B800 Quadram Ultra VGA
    = T  80x60	 8x8	  .	 16	  .   B800 Genoa 6400
    = T  80x60	 8x8	  .	 16	  .   B800 Genoa SuperEGA BIOS 3.0+
    = G    .	  .    528x480	256	  .	.  Cirrus 510/520 chipset
    = G  80x25	 8x19  640x480	 16	  1   A000 DOS/V w/ any VGA
    = G  80x30	 8x16  640x480	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = G    .	  .    640x480	32K	  .   A000 ATI
    = G    .	  .    640x480	16M	  .   A000 WD90C
    = G    .	  .    640x480	16M	  .   A000 Diamond Speedstar 24X
    = G    .	  .   1024x768	 16	  .	.  C&T chipset, Cardinal
    = G 128x48	 8x16 1024x768i	 16	  .   A000 C&T 82C450 BIOS
    = G 128x48	 8x16 1024x768	 16	  .   A000 C&T 65530 BIOS (multisync)
73h = G  80x60	 8x8   640x480	 16	  .   A000 Quadram Ultra VGA
    = G  80x60	 8x8   640x480	 16	  .	.  Genoa 6400
    = G  80x60	 8x8   640x480	 16	  .	.  Genoa SuperEGA BIOS 3.0+
    = G 100x37	 8x16  800x600	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = T  80x25	 8x19  640x475	 16	  1   none DOS/V, emulated in VGA graph
74h = T  80x66	 8x8	  .	 16	  .   B800 Quadram Ultra VGA
    = T  80x66	 8x8	  .	 16	  .   B800 Genoa 6400
    = T  80x66	 8x8	  .	 16	  .   B800 Genoa SuperEGA BIOS 3.0+
    = G    .	  .    640x400	  2	  .   B800 Toshiba 3100 AT&T mode
    = G  80x30	 8x16  640x480	 32K	  .   A000 Trident 8900C/BIOS C03
    = G 100x37	 8x16  800x600	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = G 128x48	 8x16 1024x768	 16	  1   A000 Ahead A, Ahead B (512K)
    = G    .	  .   1024x768	 64K	  .   A000 Cirrus CL-GD 5422/5426 [1]
75h = G  80x30	 8x16  640x480	 64K	  .   A000 Trident 8900C/BIOS C03
    = G  80x66	  .    640x528	 16???	  .   A000 Quadram Ultra VGA
    = G  80x66	  .    640x528	 16	  .	.  Genoa SuperEGA BIOS 3.0+
    = G 100x37	 8x16  800x600	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = G 128x48	 8x16 1024x768	  4	  1   A000 Ahead B
    = G 128x48	 8x16 1024x768	 16	  .   A000 Chips&Technologies 64310
76h = T  94x29	 8x14	  .	 16	  .   B800 Quadram Ultra VGA
    = T  94x29	 8x14	  .	  .	  .	.  Genoa SuperEGA BIOS 3.0+
    = G 100x75	 8x8   800x600	 32K	  .   A000 Trident 8900C/BIOS C03
    = G 128x48	 8x16 1024x768	  2	  1   A000 Ahead B
    = G 128x48	 8x16 1024x768	  .	  .   A000 Diamond Stealth64 Video 2xx1
    = G 160x64	 8x16 1280x1024	 16	  .   A000 Chips&Technologies 64310 [1]
77h = G  94x29	  .    752x410	 16???	  .   A000 Quadram Ultra VGA
    = G  94x29	  .    752x410	 16	  .	.  Genoa SuperEGA BIOS 3.0+
    = G 100x75	 8x8   800x600	 64K	  .   A000 Trident 8900C/BIOS C03
    = G 128x48	 8x16 1024x768	  .	  .   A000 Diamond Stealth64 Video 2xx1
78h = T 100x37	 8x16	  .	 16	  .	.  Genoa 6400
    = T 100x75	 8x8	  .	 16	  .   B800 Quadram Ultra VGA
    = T 100x75	 8x8	  .	  .	  .	.  Genoa SuperEGA BIOS 3.0+
    = G    .	  .    640x400	256	  .	.  STB VGA/EM-16 Plus
    = G  80x25	 8x16  640x400	256	  .	.  Cardinal, C&T chipset
    = G    .	  .    640x400	256	  .	.  Cirrus 5320 chipset
    = G  80x25	 8x16  640x400	256	  .   A000 Chips&Technologies 64310
79h = G  80x30	 8x16  640x480	256	  .	.  Cardinal, C&T chipset
    = G  80x30	 8x16  640x480	256	  .   A000 Chips&Technologies 64310
    = G 100x75	  .    800x600	 16???	  .   A000 Quadram Ultra VGA
    = G 100x75	 8x8   800x600	 16	  .	.  Genoa SuperEGA BIOS 3.0+
    = G 100x75	 8x8   800x600	 16	  .	.  Genoa 6400
7Ah = T 114x60	 8x8	  .	 16	  .   B800 Quadram Ultra VGA
    = T 114x60	 8x8	  .	  .	  .	.  Genoa SuperEGA BIOS 3.0+
    = G    .	  .    720x540	256	  .	.  C&T chipset, Cardinal
7Bh = G    .	  .    800x600	256	  .	.  C&T chipset, Cardinal
    = G 114x60	  .    912x480	 16???	  .   A000 Quadram Ultra VGA
    = G    .	  .    912x480	 16	  .	.  Genoa SuperEGA BIOS 3.0+
7Ch = G    .	  .    512x512	 16	  .	.  Genoa
    = G 100x37	 8x16  800x600	256	  .	.  C&T 82C453/F65530 chipsets
    = G 100x37	 8x16  800x600	256	  .   A000 Chips&Technologies 64310
    = G 200x75	 8x16 1600x1200	  . [16]  .   A000 Diamond Stealth64 Video 2xx1
7Dh = G  64x32	 8x16  512x512	256	  .	.  Genoa
7Eh =	special mode set (see AX=007Eh)		.  Paradise VGA, AT&T VDC600
    = G  80x25	 8x16  640x400	256	  .	.  Genoa 6400
    = G    .	  .   1024x768	256	  .	.  C&T 82C453 chipset
    = G 128x48	 8x16 1024x768	256	  .   A000 Chips&Technologies 64310
    = G  90x43	  .	  .	mono	  .   B000 HERCULES.COM on HGC [14]
7Fh =	special function set (see AX=007Fh/BH=00h) Paradise VGA, AT&T VDC600
    = G 128x48	 8x16 1024x768	  4	  .	.  Genoa 6400
    = G  90x29	  .	  .	mono	  .   B000 HERCULES.COM on HGC [14]
82h = T  80x25	  .	  .	B&W	  .	.  AT&T VDC overlay mode [6]
83h = T  80x25	  .	  .	  .	  .	.  AT&T VDC overlay mode [6]
86h = G    .	  .    640x200	B&W	  .	.  AT&T VDC overlay mode [6]
88h = G  90x43	 8x8   720x348	mono	  .   B000 Hercules + MSHERC.COM
C0h = G    .	  .    640x400	2/prog palette	.  AT&T VDC overlay mode [6]
    = G    .	  .    640x400	2/prog palette	.  Olivetti Quaderno overlay
C4h =	disable output	  .	  .	  .	.  AT&T VDC overlay mode [6]
C8h = G  80x50	 8x8   640x400	  2	  .   B800 Olivetti Quaderno overlay
D0h = G    .	  .    640x400	  2	  .   B800 DEC VAXmate AT&T mode
*/