/*
 *  Structures used by DOS INT 21h calls
 */
#include <common_types.h>

/*
 *  A closed FCB (File Control Block) is allocated in the PSP - Program Segment Prefix
 *  Once opened it will "extend" to an DOSOPENFCB, overwriting the space directly after
 *  A FCB only support the old style 8.3 filename format.
 */
typedef struct DOSCLOSEDFCB {
  byte		drive_number;		/* Drive number (0 = default, 1 = A, etc, FF = extended) */
  char		filename[8];		/* Blank-padded file name */
  char		extension[3];		/* Blank-padded file extension */
  word		current_block;		/* Current block number */
  word		logical_rec_size;	/* Logical record size */
} DOSCLOSEDFCB;
typedef DOSCLOSEDFCB *	PDOSCLOSEDFCB;
/*
 *  An open FCB
 *  An Open FCB can be converted to a extended FCB by setting first byte (drive number) to 0xFF.
 */

typedef struct DOSOPENFCB {
  byte		drive_number;		/* Drive number (0 = default, 1 = A, etc, FF = extended) */
  char		filename[8];		/* Blank-padded file name */
  char		extension[3];		/* Blank-padded file extension */
  word		current_block;		/* Current block number */
  word		logical_rec_size;	/* Logical record size */
  dword		file_size;			/* File size */
  word		date_last_write;	/* Date of last write (see #01666 at AX=5700h) */
  word		time_last_write;	/* Time of last write (see #01665 at AX=5700h) */
  byte		reserved[8];		/* Reserved block */
  byte		record_curr_block;	/* Record within current block */
  dword		rnd_access_recno;	/* Random access record number */
} DOSOPENFCB;
typedef DOSOPENFCB * PDOSOPENFCB;

/*
 * An extended FCB - Additional file attributes
 */
typedef struct EXTFCB {
  byte		ext_signature;		/* FFh signature for extended FCB */
  byte		reserved[5];		/* Reserved */
  byte		file_attr_ext;		/* File attribute if extended FCB */
  DOSOPENFCB	fcb;			/* Standard FCB (all offsets are shifted by seven bytes) */
} DOSEXTFCB;
typedef DOSEXTFCB * PDOSEXTFCB;

/* The default DTA is 128 bytes */
typedef char	 DOSDTA[128];
typedef DOSDTA * PDOSDTA;

/*
 *   PSP - Program Segment Prefix
 *   This structure is generated and filled by DOS when opening a program
 *   for execution.
 *
 *   The FCB 1 and 2 space are filled with the first 2 parameters as filenames
 *   If FCB 1 is opened it will overwrite FCB 2.
 *   If an extended FCB is wanted it can be moved to the extended fcb space
  */
typedef struct DOSPSP {
  byte		terminate_instruction[2];	/* CP/M Call 0 program termination */
  SEGMENT	segment_after;				/* Segment beyond program */
  byte		unused1;					/* Unused (DOS) */
  byte		call_far_000C0;				/* CPM/M far call to 000C0h (5 bytes total) */
  word		size_first_seg;				/* Size of first segment for .COM files */
  word		remain_far_call;			/* Rest of the far call for CPM/M */
  dword		int22_termination;			/* Stored INT 22 termination address */
  dword		int23__control_break;		/* Stored INT 23 control-Break handler address */
  dword		int24_critical_handler;		/* Stored INT 24 critical error handler */
  SEGMENT	parent_psp_segment;			/* Segment of parent PSP */
  byte		job_file_table[20];			/* Job File Table, one byte per file handle */
  word		envionment_segment;			/* Segment of environment for process */
  dword		last_ss_sp_int21;			/* SS:SP on entry to last INT 21 call */
  word		entries_jft;				/* Number of entries in JFT (default 20) */
  dword		pointer_jft;				/* Pointer to JFT (default PSP:0018h) */
  dword		previous_psp;				/* Pointer to previous PSP (Used by SHARE) */
  byte		interim_console_flag;		/* DBCS interim console flag (see AX=6301h) */
  byte		truename_flag;				/* (APPEND) TrueName flag (see INT 2F/AX=B711h) */
  byte		flag_byte;					/* Next byte initialized if CEh */
  byte		novell_task_number;			/* Filled if previous byte is CEh */
  byte		version_number[2];			/* Version to return on INT 21/AH=30h */
  word		selector_next_psp;			/* Win3: selector of next PSP (PDB) in linked list */
  word		pdb_partition;				/* Win3: PDB_Partition */
  word		pdb_next_pdb;				/* Win3: PDB_NextPDB */
  byte		old_win_ap;					/* Win3: bit 0 set if non-Windows application */
  byte		unused2[3];					/* Unused by DOS versions <= 6.00 */
  word		pdb_entry_stack;			/* Win3: PDB_EntryStack */
  byte		unused3[2];					/* Unused by DOS versions <= 6.00 */
  byte		service_request;			/* INT 21/RETF instructions */
  word		unused4;					/* Unused by DOS versions <= 6.00 */
  byte		extended_fcb_space[7];		/* Space for extended FCB */
  DOSCLOSEDFCB	fcb1[16];				/* Space for FCB 1 */
  DOSCLOSEDFCB	fcb2[16];				/* Space for FCB 2 */
  byte		opened_fcb[4];				/* Space for opened FCB */
  DOSDTA	command_line;				/* Command line and default DTA */
} DOSPSP;
typedef DOSPSP* PDOSPSP;

/*
 *  PDB - Parameter Drive Block
 */
typedef struct DOSPBD {
  byte		seq_device_id;				/* Sequential device ID */
  byte		logical_drive_no;			/* Logical drive number (0=A:) */
  word		bytes_pr_sector;			/* Bytes per sector */
  byte		high_sector_no;				/* Highest sector number within a cluster */
  byte		shift_count_cluster_sector;	/* Shift count to convert clusters into sectors */
  word		starting_sector_fat;		/* Starting sector number of first FAT */
  byte		number_copies_fat;			/* Number of copies of FAT */
  word		no_dir_entries;				/* Number of directory entries */
  word		no_first_sector;			/* Number of first data sector */
  word		high_cluster_no;			/* Highest cluster number (number of data clusters + 1) */
  byte		sectors_per_fat;			/* Sectors per FAT */
  word		start_sector_dir;			/* Starting sector of directory */
  word		address_alloc_table;		/* Address of allocation table */
} DOSPDB;
typedef DOSPDB* PDOSPDB;

/*
 * Country information
 */

typedef struct COUNTRYINFO {
	word	date_format;
	char	currency_symbol[5];
	char	thousand_sep[2];
	char	decimal_sep[2];
	char	time_separator[2];
	byte	currency_format; /* bitfield */
	byte	digits_after_decimal;
	byte	time_format;
	void*	case_map_routine;
	char	data_list_separator[2];
	char	reserved[10];
 } COUNTRYINFO;
 typedef COUNTRYINFO *	PCOUNTRYINFO;

/*
 *  These are Microsoft defined values
 *  for country information
 */
#define COUNTRY_UNITED_STATES	1
#define COUNTRY_CANADA_FRENCH	2
#define COUNTRY_LATIN_AMERICA	3
#define COUNTRY_CANADA_ENGLISH	4
#define COUNTRY_RUSSIA			7
#define COUNTRY_EGYPT			20
#define COUNTRY_SOUTH_AFRICA	27
#define COUNTRY_GREECE			30
#define COUNTRY_NETHERLANDS		31
#define COUNTRY_BELGIUM			32
#define COUNTRY_FRANCE			33
#define COUNTRY_SPAIN			34
#define COUNTRY_BULGARIA		35
#define COUNTRY_HUNGARY			36
#define COUNTRY_YUGOSLAVIA		38
#define COUNTRY_ITALY			39
#define COUNTRY_ROMANIA			40
#define COUNTRY_SWITCHERLAND	41
#define COUNTRY_CZECHOSLOVAKIA	42
#define COUNTRY_TJEKIA			42
#define COUNTRY_SLOVAKIA		42
#define COUNTRY_AUSTRIA			43
#define COUNTRY_UNITED_KINGDOM	44
#define COUNTRY_DENMARK			45
#define COUNTRY_SWEDEN			46
#define COUNTRY_NORWAY			47
#define COUNTRY_POLAND			48
#define COUNTRY_GERMANY			49
#define COUNTRY_PERU			51
#define COUNTRY_MEXICO			52
#define COUNTRY_CUBA			53
#define COUNTRY_ARGENTINA		54
#define COUNTRY_BRAZIL			55
#define COUNTRY_CHILE			56
#define COUNTRY_COLUMBIA		57
#define COUNTRY_VENEZUELA		58
#define COUNTRY_MALAYSIA		60
#define COUNTRY_AUSTRALIA		61
#define COUNTRY_INT_ENGLISH		61
#define COUNTRY_INDONESIA		62
#define COUNTRY_EAST_TIMOR		62
#define COUNTRY_PHILIPPINES		63
#define COUNTRY_NEW_ZEALAND		64
#define COUNTRY_SINGAPORE		65
#define COUNTRY_THAILAND		66
#define COUNTRY_JAPAN			81
#define COUNTRY_SOUTH_KOREA		82

/*
 054h (84)	Vietnam
 056h (86)	China (MS-DOS 5.0+)
 058h (88)	Taiwan (MS-DOS 5.0+)
 05Ah (90)	Turkey (MS-DOS 5.0+)
 05Bh (91)	India
 05Ch (92)	Pakistan
 05Dh (93)	Afghanistan
 05Eh (94)	Sri Lanka
 062h (98)	Iran
 063h (99)	Asia (English)
 066h (102)	??? (Hebrew MS-DOS 5.0)
 070h (112)	Belarus
 0C8h (200)	Thailand (PC DOS 6.1+)
		(reported as 01h due to a bug in PC DOS COUNTRY.SYS)
 0D4h (212)	Morocco
 0D5h (213)	Algeria
 0D8h (216)	Tunisia
 0DAh (218)	Libya
 0DCh (220)	Gambia
 0DDh (221)	Senegal
 0DEh (222)	Maruitania
 0DFh (223)	Mali
 0E0h (224)	African Guinea
 0E1h (225)	Ivory Coast
 0E2h (226)	Burkina Faso
 0E3h (227)	Niger
 0E4h (228)	Togo
 0E5h (229)	Benin
 0E6h (230)	Mauritius
 0E7h (231)	Liberia
 0E8h (232)	Sierra Leone
 0E9h (233)	Ghana
 0EAh (234)	Nigeria
 0EBh (235)	Chad
 0ECh (236)	Centra African Republic
 0EDh (237)	Cameroon
 0EEh (238)	Cape Verde Islands
 0EFh (239)	Sao Tome and Principe
 0F0h (240)	Equatorial Guinea
 0F1h (241)	Gabon
 0F2h (242)	Congo
 0F3h (243)	Zaire
 0F4h (244)	Angola
 0F5h (245)	Guinea-Bissau
 0F6h (246)	Diego Garcia
 0F7h (247)	Ascension Isle
 0F8h (248)	Seychelles
 0F9h (249)	Sudan
 0FAh (250)	Rwhanda
 0FBh (251)	Ethiopia
 0FCh (252)	Somalia
 0FDh (253)	Djibouti
 0FEh (254)	Kenya
 0FFh (255)	Tanzania
 100h (256)	Uganda
 101h (257)	Burundi
 103h (259)	Mozambique
 104h (260)	Zambia
 105h (261)	Madagascar
 106h (262)	Reunion Island
 107h (263)	Zimbabwe
 108h (264)	Namibia
 109h (265)	Malawi
 10Ah (266)	Lesotho
 10Bh (267)	Botswana
 10Ch (268)	Swaziland
 10Dh (269)	Comoros
 10Eh (270)	Mayotte
 122h (290)	St. Helena
 129h (297)	Aruba
 12Ah (298)	Faroe Islands
 12Bh (299)	Greenland
 15Eh (350)	Gibraltar
 15Fh (351)	Portugal
 160h (352)	Luxembourg
 161h (353)	Ireland
 162h (354)	Iceland
 163h (355)	Albania
 164h (356)	Malta
 165h (357)	Cyprus
 166h (358)	Finland
 167h (359)	Bulgaria
 172h (370)	Lithuania (reported as 372 due to a bug in MS-DOS COUNTRY.SYS)
 173h (371)	Latvia (reported as 372 due to a bug in MS-DOS COUNTRY.SYS)
 174h (372)	Estonia
 175h (373)	Moldova
 177h (375)	??? (MS-DOS 7.10 / Windows98)
 17Ch (380)	Ukraine
 17Dh (381)	Serbia / Montenegro
 180h (384)	Croatia
 181h (385)	Croatia (PC DOS 7+)
 182h (386)	Slovenia
 183h (387)	Bosnia-Herzegovina (Latin)
 184h (388)	Bosnia-Herzegovina (Cyrillic) (PC DOS 7+)
		(reported as 381 due to a bug in PC DOS COUNTRY.SYS)
 185h (389)	FYR Macedonia
 1A5h (421)	Czech Republic / Tjekia (PC DOS 7+)
 1A6h (422)	Slovakia
		(reported as 421 due to a bug in COUNTRY.SYS)
 1F4h (500)	Falkland Islands
 1F5h (501)	Belize
 1F6h (502)	Guatemala
 1F7h (503)	El Salvador
 1F8h (504)	Honduras
 1F9h (505)	Nicraragua
 1FAh (506)	Costa Rica
 1FBh (507)	Panama
 1FCh (508)	St. Pierre and Miquelon
 1FDh (509)	Haiti
 24Eh (590)	Guadeloupe
 24Fh (591)	Bolivia
 250h (592)	Guyana
 251h (593)	Ecuador
 252h (594)	rench Guiana
 253h (595)	Paraguay
 254h (596)	Martinique / French Antilles
 255h (597)	Suriname
 256h (598)	Uruguay
 257h (599)	Netherland Antilles
 29Ah (666)	Russia??? (PTS-DOS 6.51 KEYB)
 29Bh (667)	Poland??? (PTS-DOS 6.51 KEYB)
 29Ch (668)	Poland??? (Slavic???) (PTS-DOS 6.51 KEYB)
 29Eh (670)	Saipan / N. Mariana Island
 29Fh (671)	Guam
 2A0h (672)	Norfolk Island (Australia) / Christmas Island/Cocos Islands / Antartica
 2A1h (673)	Brunei Darussalam
 2A2h (674)	Nauru
 2A3h (675)	Papua New Guinea
 2A4h (676)	Tonga Islands
 2A5h (677)	Solomon Islands
 2A6h (678)	Vanuatu
 2A7h (679)	Fiji
 2A8h (680)	Palau
 2A9h (681)	Wallis & Futuna
 2AAh (682)	Cook Islands
 2ABh (683)	Niue
 2ACh (684)	American Samoa
 2ADh (685)	Western Samoa
 2AEh (686)	Kiribati
 2AFh (687)	New Caledonia
 2B0h (688)	Tuvalu
 2B1h (689)	French Polynesia
 2B2h (690)	Tokealu
 2B3h (691)	Micronesia
 2B4h (692)	Marshall Islands
 2C7h (711)	??? (currency = EA$, code pages 437,737,850,852,855,857)
 311h (785)	Arabic (Middle East/Saudi Arabia/etc.)
 324h (804)	Ukraine
 329h (809)	Antigua and Barbuda / Anguilla / Bahamas / Barbados / Bermuda
		British Virgin Islands / Cayman Islands / Dominica
		Dominican Republic / Grenada / Jamaica / Montserra
		St. Kitts and Nevis / St. Lucia / St. Vincent and Grenadines
		Trinidad and Tobago / Turks and Caicos
 352h (850)	North Korea
 354h (852)	Hong Kong
 355h (853)	Macao
 357h (855)	Cambodia
 358h (856)	Laos
 370h (880)	Bangladesh
 376h (886)	Taiwan (MS-DOS 6.22+)
 3C0h (960)	Maldives
 3C1h (961)	Lebanon
 3C2h (962)	Jordan
 3C3h (963)	Syria / Syrian Arab Republic
 3C4h (964)	Iraq
 3C5h (965)	Kuwait
 3C6h (966)	Saudi Arabia
 3C7h (967)	Yemen
 3C8h (968)	Oman
 3C9h (969)	Yemen??? (Arabic MS-DOS 5.0)
 3CBh (971)	United Arab Emirates
 3CCh (972)	Israel (Hebrew) (DR DOS 5.0,MS-DOS 5.0+)
 3CDh (973)	Bahrain
 3CEh (974)	Qatar
 3CFh (975)	Bhutan
 3D0h (976)	Mongolia
 3D1h (977)	Nepal
 3E3h (995)	Myanmar (Burma)
*/

typedef struct DOSPARAMLIST {
  word	AX;
  word	BX;
  word	CX;
  word	DX;
  word	SI;
  word	DI;
  word	DS;
  word	ES;
  word	reserved;
  word	computer_id;
  word	process_id; /* PSP segment on specified computer */
} DOSPARAMLIST;
typedef DOSPARAMLIST*	PDOSPARAMLIST;

#define MEM_ALLOC_STRAT_LOW_FIRST_FIT	0
#define MEM_ALLOC_STRAT_LOW_BEST_FIT	1
#define MEM_ALLOC_STRAT_LOW_LAST_FIT	2
#define MEM_ALLOC_STRAT_HIGH_FIRST_FIT	0x40
#define MEM_ALLOC_STRAT_HIGH_BEST_FIT	0x41
#define MEM_ALLOC_STRAT_HIGH_LAST_FIT   0x42
#define MEM_ALLOC_STRAT_BOTH_FIRST_FIT	0x80
#define MEM_ALLOC_STRAT_BOTH_BEST_FIT	0x81
#define MEM_ALLOC_STRAT_BOTH_LAST_FIT	0x82

typedef struct DOSEAV {
  byte	reserved[4];
  byte	size_of_str;
  char	string[1]; /* In reality the full string */
} DOSEAV;

typedef struct DOSEAVLIST {
  word		num_entries;
  DOSEAV	list;
} DOSEAVLIST;
typedef DOSEAVLIST*	PDOSEAVLIST;

typedef struct DOSEAP {
  byte	attr_type;
  word	eap_flags;
  byte	size_of_str;
  char	string[1]; /* In reality the full string */
} DOSEAP;

#define EAP_TYPE_BOOLEAN	1
#define EAP_TYPE_NUMBER		2
#define EAP_TYPE_STRING		3
#define EAP_TYPE_DATE		4
#define EAP_TYPE_TIME		5

typedef struct DOSEAPLIST {
  word		num_entries;
  DOSEAP	list;
} DOSEAPLIST;
typedef DOSEAPLIST*	PDOSEAPLIST;

/*
 * Bios Parameter Block
 */
typedef struct DOSBPB {
  word	bytes_per_sector;
  byte	sectors_per_cluster;
  word	reserved_sectors;
  byte	number_of_fats;
  word	entries_in_root_dir;
  word	total_sectors;
  byte	media_id_byte;
  word	sectors_per_fat;
  dword	total_sectors_large;
  byte	reserved[6];
  word	num_of_cylinders;
  byte	device_type;
  word	device_attr;
} DOSBPB;
typedef DOSBPB*	PDOSBPB;

typedef struct DOSDPB {
  byte	drive_number;
  byte	unit_number;
  word	bytes_sector;
  byte	high_sector_no;
  byte	shift_count;
  word	reserved_sectors;
  byte	number_of_fats;
  word	number_root_dir_entries;
  word	first_data_sector;
  word	high_cluster_no;
  word	sectors_pr_fat;
  word	sector_no_first_dir;
  dword	device_driver_header; /* TODO: Should be pointer to that struct */
  byte	media_id_byte;
  byte	disk_accessed;
  struct DOSDPB	*next;
  word	cluster_search_free_space;
  word	number_free_clusters;
} DOSDPB;
typedef DOSDPB*	PDOSDPB;

/*
 *   This is an internal structure which you can get a pointer to with INT 21h/52h
 *   You get a pointer to the middle of a struct. Since compiler do not support
 *   negative offset this struct lies directly before.
 */
typedef struct {
   word		cx_from_int21_5e01;
   word		lru_count_fcb_caching;
   word		lru_count_fcb_opens;
   void*	oem_handler; /*	FFFFh:FFFFh if not installed or not available */
   word		offset_dos_cs_code;
   word		sharing_retry_count;
   word		sharing_relay_delay;
   byte*	current_disk_buffer;
   word		pointer_unread_con_input;
   word		segment_memory_control;
} DOSSYSVARNEGATIVE;

typedef struct {
  PDOSDPB	first_drive_parameter_block;
  void*		first_system_file_table;
  void*		active_clock_device;
  void*		active_con_device;
/*
 10h	WORD	maximum bytes per sector of any block device
 12h	DWORD	pointer to disk buffer info record (see #01652,#01653)
		Note: although the initialization code in IO.SYS uses this
		  pointer, MSDOS.SYS does not, instead using the hardcoded
		  address of the info record
 16h	DWORD	pointer to array of current directory structures
		(see #01643,#01644)
 1Ah	DWORD	pointer to system FCB tables (see #01640,#01641,#01642)
 1Eh	WORD	number of protected FCBs (the y in the CONFIG.SYS FCBS=x,y)
		(always 00h for DOS 5.0)
 20h	BYTE	number of block devices installed
 21h	BYTE	number of available drive letters; also size of current
		  directory structure array.
		For DOS 4.0-6.0: largest of 5, installed block devices,
		  and CONFIG.SYS LASTDRIVE=
		For DOS 7.x (Windows9X), set to 32 if no LASTDRIVE= or
		  LASTDRIVEHIGH=, else set to larger of installed block
		  devices and LASTDRIVE(HIGH)=
 22h 18 BYTEs	actual NUL device driver header (not a pointer!)
		NUL is always the first device on DOS's linked list of device
		  drivers. (see #01646)
 34h	BYTE	number of JOIN'ed drives
 35h	WORD	pointer within IBMDOS code segment to list of special program
		  names (see #01662)
		(always 0000h for DOS 5.0)
37h	DWORD	pointer to SETVER program list or 0000h:0000h
3Bh	WORD	(DOS=HIGH) offset in DOS CS of function to fix A20 control
		  when executing special .COM format
  3Dh	WORD	PSP of most-recently EXECed program if DOS in HMA, 0000h if low
		used for maintaining count of INT 21 calls which disable A20
		  on return
 3Fh	WORD	the x in BUFFERS x,y (rounded up to multiple of 30 if in EMS)
 41h	WORD	number of lookahead buffers (the y in BUFFERS x,y)
 43h	BYTE	boot drive (1=A:)
 44h	BYTE	flag: 01h to use DWORD moves (80386+), 00h otherwise
 45h	WORD	extended memory size in KB
*/
} *PDOSSYSVAR;

/*
 *  Parameter block for DosSetExecState
 */
typedef struct DOSEXECSTATE {
  word		reserved;
  word		type_flag;
  char*		file_name;
  word		psp_new_program;
  void*		start_pointer;
  dword		program_size;
} DOSEXECSTATE;
typedef DOSEXECSTATE *	PDOSEXECSTATE;

#define EXEC_STATE_EXE_TYPE   0x01
#define EXEC_STATE_OVERLAY	  0x02

typedef char	DOSASCIIZPATH[64];
typedef DOSASCIIZPATH*	PDOSASCIIZPATH;

#define FILE_MODE_ARCHIVE	0x20
#define FILE_MODE_DIR		0x10
#define FILE_MODE_VOL_LABEL	0x08
#define	FILE_MODE_SYSTEM	0x04
#define FILE_MODE_HIDDEN	0x02
#define FILE_MODE_READ_ONLY	0x01

/*
 *  This is in interrupt vector function
 */
typedef void (*InterruptVector)(void);

/*
 *  Structures to gather multi register return from functions.
 *  For any odd bytes return I have put the byte at the end for now.
 */
typedef struct {
  word	bytes_per_sector;
  word	number_of_clusters;
  byte	*media_id;
} R_DRIVEALLOC;

typedef struct {
  DOSPDB	*pdb;
  byte		status;
} R_GETPDB;

typedef struct {
  word	no_bytes;		/* No of bytes read or written */
  byte	status;			/* Status of operation */
} R_FILESTATUS;

typedef struct {
  word year;
  byte month;
  byte day;
  byte status;
} R_SYSTEMDATE;

typedef struct {
  byte hour;
  byte minute;
  byte seconds;
  byte sec_100; /* 1/100 second */
} R_SYSTEMTIME;

typedef struct {
  byte major;  /* AL */
  byte minor;  /* AH */
  byte high_serial; /* BL */
  byte version_flag; /* BH */
  word low_serial; /* CX */
} R_VERSIONINFO;

typedef struct {
  byte	dos_less_5;
  byte	major;
  byte	minor;
  byte	revision;
  byte	version_flag;
} R_TRUEVERSION;


typedef struct {
  word	sectors_pr_cluster;
  word	free_clusters;
  word	bytes_pr_sector;
  word	total_clusters;
} R_DISKSPACE;

typedef struct {
  byte status;
  byte switch_ch;
} R_SWITCHCHAR;

typedef struct {
	word error_code;
	word country_code;
} R_COUNTRYINFO;

typedef struct {
  word	extended_error;
  byte	error_class;
  byte	recommended_action;
  byte	error_locus;
  byte*	ptr;
} R_EXTENDEDERROR;

/*
Values for DOS extended error code:
---DOS 2.0+ ---
 00h (0)   no error
 01h (1)   function number invalid
 02h (2)   file not found
 03h (3)   path not found
 04h (4)   too many open files (no handles available)
 05h (5)   access denied
 06h (6)   invalid handle
 07h (7)   memory control block destroyed
 08h (8)   insufficient memory
 09h (9)   memory block address invalid
 0Ah (10)  environment invalid (usually >32K in length)
 0Bh (11)  format invalid
 0Ch (12)  access code invalid
 0Dh (13)  data invalid
 0Eh (14)  reserved
 0Eh (14)  (PTS-DOS 6.51+, S/DOS 1.0+) fixup overflow
 0Fh (15)  invalid drive
 10h (16)  attempted to remove current directory
 11h (17)  not same device
 12h (18)  no more files
---DOS 3.0+ (INT 24 errors)---
 13h (19)  disk write-protected
 14h (20)  unknown unit
 15h (21)  drive not ready
 16h (22)  unknown command
 17h (23)  data error (CRC)
 18h (24)  bad request structure length
 19h (25)  seek error
 1Ah (26)  unknown media type (non-DOS disk)
 1Bh (27)  sector not found
 1Ch (28)  printer out of paper
 1Dh (29)  write fault
 1Eh (30)  read fault
 1Fh (31)  general failure
 20h (32)  sharing violation
 21h (33)  lock violation
 22h (34)  disk change invalid (ES:DI -> media ID structure)(see #01681)
 23h (35)  FCB unavailable
 23h (35)  (PTS-DOS 6.51+, S/DOS 1.0+) bad FAT
 24h (36)  sharing buffer overflow
 25h (37)  (DOS 4.0+) code page mismatch
 26h (38)  (DOS 4.0+) cannot complete file operation (EOF / out of input)
 27h (39)  (DOS 4.0+) insufficient disk space
 28h-31h   reserved
---OEM network errors (INT 24)---
 32h (50)  network request not supported
 33h (51)  remote computer not listening
 34h (52)  duplicate name on network
 35h (53)  network name not found
 36h (54)  network busy
 37h (55)  network device no longer exists
 38h (56)  network BIOS command limit exceeded
 39h (57)  network adapter hardware error
 3Ah (58)  incorrect response from network
 3Bh (59)  unexpected network error
 3Ch (60)  incompatible remote adapter
 3Dh (61)  print queue full
 3Eh (62)  queue not full
 3Fh (63)  not enough space to print file
 40h (64)  network name was deleted
 41h (65)  network: Access denied
	  (DOS 3.0+ [maybe 3.3+???]) codepage switching not possible
	    (see also INT 21/AX=6602h,INT 2F/AX=AD42h)
 42h (66)  network device type incorrect
 43h (67)  network name not found
 44h (68)  network name limit exceeded
 45h (69)  network BIOS session limit exceeded
 46h (70)  temporarily paused
 47h (71)  network request not accepted
 48h (72)  network print/disk redirection paused
 49h (73)  network software not installed
	    (LANtastic) invalid network version
 4Ah (74)  unexpected adapter close
	    (LANtastic) account expired
 4Bh (75)  (LANtastic) password expired
 4Ch (76)  (LANtastic) login attempt invalid at this time
 4Dh (77)  (LANtastic v3+) disk limit exceeded on network node
 4Eh (78)  (LANtastic v3+) not logged in to network node
 4Fh (79)  reserved
---end of errors reportable via INT 24---
 50h (80)  file exists
 51h (81)  (undoc) duplicated FCB
 52h (82)  cannot make directory
 53h (83)  fail on INT 24h
---network-related errors (non-INT 24)---
 54h (84)  (DOS 3.3+) too many redirections / out of structures
 55h (85)  (DOS 3.3+) duplicate redirection / already assigned
 56h (86)  (DOS 3.3+) invalid password
 57h (87)  (DOS 3.3+) invalid parameter
 58h (88)  (DOS 3.3+) network write fault
 59h (89)  (DOS 4.0+) function not supported on network / no process slots
	      available
 5Ah (90)  (DOS 4.0+) required system component not installed / not frozen
 5Bh (91)  (DOS 4.0+,NetWare4) timer server table overflowed
 5Ch (92)  (DOS 4.0+,NetWare4) duplicate in timer service table
 5Dh (93)  (DOS 4.0+,NetWare4) no items to work on
 5Fh (95)  (DOS 4.0+,NetWare4) interrupted / invalid system call
 64h (100) (MSCDEX) unknown error
 64h (100) (DOS 4.0+,NetWare4) open semaphore limit exceeded
 65h (101) (MSCDEX) not ready
 65h (101) (DOS 4.0+,NetWare4) exclusive semaphore is already owned
 66h (102) (MSCDEX) EMS memory no longer valid
 66h (102) (DOS 4.0+,NetWare4) semaphore was set when close attempted
 67h (103) (MSCDEX) not High Sierra or ISO-9660 format
 67h (103) (DOS 4.0+,NetWare4) too many exclusive semaphore requests
 68h (104) (MSCDEX) door open
 68h (104) (DOS 4.0+,NetWare4) operation invalid from interrupt handler
 69h (105) (DOS 4.0+,NetWare4) semaphore owner died
 6Ah (106) (DOS 4.0+,NetWare4) semaphore limit exceeded
 6Bh (107) (DOS 4.0+,NetWare4) insert drive B: disk into A: / disk changed
 6Ch (108) (DOS 4.0+,NetWare4) drive locked by another process
 6Dh (109) (DOS 4.0+,NetWare4) broken pipe
 6Eh (110) (DOS 5.0+,NetWare4) pipe open/create failed
 6Fh (111) (DOS 5.0+,NetWare4) pipe buffer overflowed
 70h (112) (DOS 5.0+,NetWare4) disk full
 71h (113) (DOS 5.0+,NetWare4) no more search handles
 72h (114) (DOS 5.0+,NetWare4) invalid target handle for dup2
 73h (115) (DOS 5.0+,NetWare4) bad user virtual address / protection violation
 74h (116) (DOS 5.0+) VIOKBD request
 74h (116) (NetWare4) error on console I/O
 75h (117) (DOS 5.0+,NetWare4) unknown category code for IOCTL
 76h (118) (DOS 5.0+,NetWare4) invalid value for verify flag
 77h (119) (DOS 5.0+,NetWare4) level four driver not found by DOS IOCTL
 78h (120) (DOS 5.0+,NetWare4) invalid / unimplemented function number
 79h (121) (DOS 5.0+,NetWare4) semaphore timeout
 7Ah (122) (DOS 5.0+,NetWare4) buffer too small to hold return data
 7Bh (123) (DOS 5.0+,NetWare4) invalid character or bad file-system name
 7Ch (124) (DOS 5.0+,NetWare4) unimplemented information level
 7Dh (125) (DOS 5.0+,NetWare4) no volume label found
 7Eh (126) (DOS 5.0+,NetWare4) module handle not found
 7Fh (127) (DOS 5.0+,NetWare4) procedure address not found
 80h (128) (DOS 5.0+,NetWare4) CWait found no children
 81h (129) (DOS 5.0+,NetWare4) CWait children still running
 82h (130) (DOS 5.0+,NetWare4) invalid operation for direct disk-access handle
 83h (131) (DOS 5.0+,NetWare4) attempted seek to negative offset
 84h (132) (DOS 5.0+,NetWare4) attempted to seek on device or pipe
---JOIN/SUBST errors---
 85h (133) (DOS 5.0+,NetWare4) drive already has JOINed drives
 86h (134) (DOS 5.0+,NetWare4) drive is already JOINed
 87h (135) (DOS 5.0+,NetWare4) drive is already SUBSTed
 88h (136) (DOS 5.0+,NetWare4) can not delete drive which is not JOINed
 89h (137) (DOS 5.0+,NetWare4) can not delete drive which is not SUBSTed
 8Ah (138) (DOS 5.0+,NetWare4) can not JOIN to a JOINed drive
 8Bh (139) (DOS 5.0+,NetWare4) can not SUBST to a SUBSTed drive
 8Ch (140) (DOS 5.0+,NetWare4) can not JOIN to a SUBSTed drive
 8Dh (141) (DOS 5.0+,NetWare4) can not SUBST to a JOINed drive
 8Eh (142) (DOS 5.0+,NetWare4) drive is busy
 8Fh (143) (DOS 5.0+,NetWare4) can not JOIN/SUBST to same drive
 90h (144) (DOS 5.0+,NetWare4) directory must not be root directory
 91h (145) (DOS 5.0+,NetWare4) can only JOIN to empty directory
 92h (146) (DOS 5.0+,NetWare4) path is already in use for SUBST
 93h (147) (DOS 5.0+,NetWare4) path is already in use for JOIN
 94h (148) (DOS 5.0+,NetWare4) path is in use by another process
 95h (149) (DOS 5.0+,NetWare4) directory previously SUBSTituted
 96h (150) (DOS 5.0+,NetWare4) system trace error
 97h (151) (DOS 5.0+,NetWare4) invalid event count for DosMuxSemWait
 98h (152) (DOS 5.0+,NetWare4) too many waiting on mutex
 99h (153) (DOS 5.0+,NetWare4) invalid list format
 9Ah (154) (DOS 5.0+,NetWare4) volume label too large
 9Bh (155) (DOS 5.0+,NetWare4) unable to create another TCB
 9Ch (156) (DOS 5.0+,NetWare4) signal refused
 9Dh (157) (DOS 5.0+,NetWare4) segment discarded
 9Eh (158) (DOS 5.0+,NetWare4) segment not locked
 9Fh (159) (DOS 5.0+,NetWare4) invalid thread-ID address
-----
 A0h (160) (DOS 5.0+) bad arguments
 A0h (160) (NetWare4) bad environment pointer
 A1h (161) (DOS 5.0+,NetWare4) invalid pathname passed to EXEC
 A2h (162) (DOS 5.0+,NetWare4) signal already pending
 A3h (163) (DOS 5.0+) uncertain media
 A3h (163) (NetWare4) ERROR_124 mapping
 A4h (164) (DOS 5.0+) maximum number of threads reached
 A4h (164) (NetWare4) no more process slots
 A5h (165) (NetWare4) ERROR_124 mapping
 B0h (176) (MS-DOS 7.0) volume is not locked
 B1h (177) (MS-DOS 7.0) volume is locked in drive
 B2h (178) (MS-DOS 7.0) volume is not removable
 B4h (180) (MS-DOS 7.0) lock count has been exceeded
 B4h (180) (NetWare4) invalid segment number
 B5h (181) (MS-DOS 7.0) a valid eject request failed
 B5h (181) (DOS 5.0-6.0,NetWare4) invalid call gate
 B6h (182) (DOS 5.0+,NetWare4) invalid ordinal
 B7h (183) (DOS 5.0+,NetWare4) shared segment already exists
 B8h (184) (DOS 5.0+,NetWare4) no child process to wait for
 B9h (185) (DOS 5.0+,NetWare4) NoWait specified and child still running
 BAh (186) (DOS 5.0+,NetWare4) invalid flag number
 BBh (187) (DOS 5.0+,NetWare4) semaphore does not exist
 BCh (188) (DOS 5.0+,NetWare4) invalid starting code segment
 BDh (189) (DOS 5.0+,NetWare4) invalid stack segment
 BEh (190) (DOS 5.0+,NetWare4) invalid module type (DLL can not be used as
	      application)
 BFh (191) (DOS 5.0+,NetWare4) invalid EXE signature
 C0h (192) (DOS 5.0+,NetWare4) EXE marked invalid
 C1h (193) (DOS 5.0+,NetWare4) bad EXE format (e.g. DOS-mode program)
 C2h (194) (DOS 5.0+,NetWare4) iterated data exceeds 64K
 C3h (195) (DOS 5.0+,NetWare4) invalid minimum allocation size
 C4h (196) (DOS 5.0+,NetWare4) dynamic link from invalid Ring
 C5h (197) (DOS 5.0+,NetWare4) IOPL not enabled
 C6h (198) (DOS 5.0+,NetWare4) invalid segment descriptor privilege level
 C7h (199) (DOS 5.0+,NetWare4) automatic data segment exceeds 64K
 C8h (200) (DOS 5.0+,NetWare4) Ring2 segment must be moveable
 C9h (201) (DOS 5.0+,NetWare4) relocation chain exceeds segment limit
 CAh (202) (DOS 5.0+,NetWare4) infinite loop in relocation chain
 */
/*
Values for DOS Error Class:
 01h (1)  out of resource (storage space or I/O channels)
 02h (2)  temporary situation (file or record lock)
 03h (3)  authorization / permission problem (denied access)
 04h (4)  internal system error (system software bug)
 05h (5)  hardware failure
 06h (6)  system failure (configuration file missing or incorrect)
 07h (7)  application program error
 08h (8)  not found
 09h (9)  bad format
 0Ah (10) locked
 0Bh (11) media error
 0Ch (12) already exists / collision with existing item
 0Dh (13) unknown / other
 0Eh (14) (undoc) cannot
 0Fh (15) (undoc) time
 */

/*
Values for DOS recommended Action:
 01h	retry
 02h	delayed retry (after pause)
 03h	prompt user to reenter input
 04h	abort after cleanup
 05h	immediate abort ("panic")
 06h	ignore
 07h	retry after user intervention
 */

typedef struct {
  word	status;
  byte*	list;
} R_DATASWAPAREAS;

typedef struct {
  word	status;
  byte*	list;
  word swap_size;
  word always_swap;
} R_ADRSWAP;

typedef struct {
  word error_code;
  word time;
  word date;
  word milli;
} R_CREATEINFO;

typedef struct {
  word	error_code;
  word	size;
} R_STATUSLEN;

typedef struct {
  word error_code;
  word time;
  word date;
} R_FILEINFO;

typedef struct {
  byte	error_code;
  byte	termination_type;
} R_ERRORRETURN;

typedef struct {
  word error_code;
  word memory_size;
} R_RESIZEMEM;

typedef struct {
  word	error_code;
  void*	data;
} R_IOCTL;

typedef struct {
  word	error_code;
  void*	data;
  word	di_return;
  word	si_return;
} R_IOCTLCHAR;

typedef struct {
  word error_code;
  word attribute;
} R_HANDLEREMOTE;

typedef struct {
  word error_code;
  word information;
} R_DEVICEINFO;

typedef struct {
  word error_code;
  word attributes;
} R_GETATTR;

