enum byte (
  DISK_SECTOR_SIZE_128,
  DISK_SECTOR_SIZE_256,
  DISK_SECTOR_SIZE_512,
  DISK_SECTOR_SIZE_1024
) DiskSectorSize;

struct TDiskFieldBuffer {
  byte track_number;
  byte head_number;
  byte sector_number;
  DiskSectorSize sector_size;
} TDiskFieldBuffer, *PDiskFieldBuffer;

struct TDiskMediaType {
  byte reserved[11];
} TDiskMediaType, *PDiskMediaType;

struct TEsdiCommandCompleteStatusBlock {
  byte magic_number;
  byte size_block_in_words;
  byte command_error_code;
  byte command_status_code;
  byte device_error_code;
  byte device_error_flags;
  WORD number_of_unprocessed_sectors;
  DWORD last_relative_sector_address;
  WORD number_sector_corrected_ecc;
} TEsdiCommandCompleteStatusBlock, *PEsdiCommandCompleteStatusBlock;

struct TEsdiDeviceStatusBlock {
 byte magic_number;
 byte number_of_words_in_block;
 byte error_flags;
 byte unused;
 byte command_error_code;
 byte command_status_code;
 WORD esdi_standard_status;
 WORD esdi_vendor_codes[5];
} TEsdiDeviceStatusBlock, *PEsdiDeviceStatusBlock;

struct TEsdiDriveConfigurationStatusBlock {
  byte magic_number;
  byte number_of_words_in_block;
  byte flags;
  byte number_of_sparse_sectors_per_cylinder;
  DWORD total_number_of_usable_sectors;
  WORD total_number_of_cylinders;
  byte tracks_per_cylinder;
  byte sectors_per_track;
} TEsdiDriveConfigurationStatusBlock, *PEsdiDriveConfigurationStatusBlock;

struct TEsdiControllerConfigurationStatusBlock {
  byte magic_number;
  byte number_of_words_in_block;
  WORD unused1;
  DWORD controller_microcode_revision_level;
  WORD unused2[2];
} TEsdiControllerConfigurationStatusBlock, *PEsdiControllerConfigurationStatusBlock;

struct TEsdiPosInformationStatusBlock {
  byte magic_number;
  byte number_of_words_in_block;
  WORD magic_value;
  byte pos_register_3;
  byte pos_register_2;
  byte pos_register_5;
  byte pos_register_4;
  byte pos_register_7;
  byte pos_register_6;
} TEsdiPosInformationStatusBlock, *PEsdiPosInformationStatusBlock;
