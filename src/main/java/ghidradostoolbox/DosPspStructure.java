package ghidradostoolbox;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class DosPspStructure implements StructConverter {
	public final static String NAME = "PSP";

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(new ArrayDataType(BYTE,2,1),2, "terminate_instruction", "CP/M Call 0 program termination");
		struct.add(WORD, "segment_after", "Segment beyond program");
		struct.add(BYTE, "unused1", "Unused (DOS)");
		struct.add(BYTE, "call_far_000C0", "CP/M far call to 000C0h");
		struct.add(WORD, "size_first_seg", "Size of first segment for .COM files");
		struct.add(WORD, "remain_far_call", "Rest of the far call for CP/M");
		struct.add(DWORD, "int22_termination", "Stored INT 22 termination address");
		struct.add(DWORD, "int23_control_break", "Stored INT 23 control-Break handler address");
		struct.add(DWORD, "int24_critical_handler", "Stored INT 24 critical error handler");
		struct.add(WORD, "parent_psp_segment", "Segment of parent PSP");
		struct.add(new ArrayDataType(BYTE, 20, 1), "job_file_table", "Job File Table, one byte per file handle");
		struct.add(WORD, "envionment_segment", "Segment of environment for process");
		struct.add(DWORD, "last_ss_sp_int21", "SS:SP on entry to last INT 21 call");
		struct.add(WORD, "entries_jft", "Number of entries in JFT (default 20)");
		struct.add(DWORD, "pointer_jft", "Pointer to JFT (default PSP:0018h)");
		struct.add(DWORD, "previous_psp", "Pointer to previous PSP (Used by SHARE)");
		struct.add(BYTE, "interim_console_flag", "DBCS interim console flag (see AX=6301h)");
		struct.add(BYTE, "truename_flag", "(APPEND) TrueName flag (see INT 2F/AX=B711h)");
		struct.add(BYTE, "flag_byte", "Next byte initialized if CEh");
		struct.add(BYTE, "novell_task_number", "Filled if previous byte is CEh");
		struct.add(WORD, "version_number", "Version to return on INT 21/AH=30h");
		struct.add(WORD, "selector_next_psp", "Win3: selector of next PSP (PDB) in linked list");
		struct.add(WORD, "pdb_partition", "Win3: PDB_Partition");
		struct.add(WORD, "pdb_next_pdb", "Win3: PDB_NextPDB");
		struct.add(BYTE, "old_win_ap", "Win3: bit 0 set if non-Windows application");
		struct.add(new ArrayDataType(BYTE,3,1), "unused2", "Unused by DOS versions <= 6.00");
		struct.add(WORD, "pdb_entry_stack", "Win3: PDB_EntryStack");
		struct.add(WORD, "unused3", "Unused by DOS versions <= 6.00");
		struct.add(new ArrayDataType(BYTE,3,1), "service_request", "INT 21/RETF instructions");
		struct.add(WORD, "unused4", "Unused by DOS versions <= 6.00");
		struct.add(new ArrayDataType(BYTE,7,1), "space_extended_fcb", "Space for extended FCB 1");
		struct.add(new ArrayDataType(BYTE,16,1), "fcb1", "Space FCB 1");
		struct.add(new ArrayDataType(BYTE,16,1), "fcb2", "Space FCB 2");
		struct.add(new ArrayDataType(BYTE,4,1), "unsued5", "Unused");
		struct.add(new ArrayDataType(BYTE,128,1), "command_line", "Command line and default DTA");

		struct.setCategoryPath(new CategoryPath("/DOS"));

        return struct;
	}
}
