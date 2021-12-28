package ghidradostoolbox;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class DosPspStructure implements StructConverter {
	public final static String NAME = "PSP";

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		DataTypeComponent c = struct.add(new ArrayDataType(BYTE,2,1));
		c.setFieldName("terminate_instruction");
		c.setComment("CP/M Call 0 program termination");

		c = struct.add(WORD);
        c.setFieldName("segment_after");
        c.setComment("Segment beyond program");

		c = struct.add(BYTE);
        c.setFieldName("unsued1");
        c.setComment("Unused (DOS)");

		c = struct.add(BYTE);
        c.setFieldName("call_far_000C0");
        c.setComment("CPM/M far call to 000C0h");

		c = struct.add(WORD);
        c.setFieldName("size_first_seg");
        c.setComment("Size of first segment for .COM files");

		c = struct.add(WORD);
        c.setFieldName("remain_far_call");
        c.setComment("Rest of the far call for CPM/M");

		c = struct.add(DWORD);
        c.setFieldName("int22_termination");
        c.setComment("Stored INT 22 termination address");

		c = struct.add(DWORD);
        c.setFieldName("int23_control_break");
        c.setComment("Stored INT 23 control-Break handler address");

		c = struct.add(DWORD);
        c.setFieldName("int24_critical_handler");
        c.setComment("Stored INT 24 critical error handler");

		c = struct.add(WORD);
        c.setFieldName("parent_psp_segment");
        c.setComment("Segment of parent PSP");

		c = struct.add(new ArrayDataType(BYTE, 20, 1));
        c.setFieldName("job_file_table");
        c.setComment("Job File Table, one byte per file handle");

		c = struct.add(WORD);
        c.setFieldName("envionment_segment");
        c.setComment("Segment of environment for process");

		c = struct.add(DWORD);
        c.setFieldName("last_ss_sp_int21");
        c.setComment("SS:SP on entry to last INT 21 call");

		c = struct.add(WORD);
        c.setFieldName("entries_jft");
        c.setComment("Number of entries in JFT (default 20)");

		c = struct.add(DWORD);
        c.setFieldName("pointer_jft");
        c.setComment("Pointer to JFT (default PSP:0018h)");

		c = struct.add(DWORD);
        c.setFieldName("previous_psp");
        c.setComment("Pointer to previous PSP (Used by SHARE)");

		c = struct.add(BYTE);
        c.setFieldName("interim_console_flag");
        c.setComment("DBCS interim console flag (see AX=6301h)");

		c = struct.add(BYTE);
        c.setFieldName("truename_flag");
        c.setComment("(APPEND) TrueName flag (see INT 2F/AX=B711h)");

		c = struct.add(BYTE);
        c.setFieldName("flag_byte");
        c.setComment("Next byte initialized if CEh");

		c = struct.add(BYTE);
        c.setFieldName("novell_task_number");
        c.setComment("Filled if previous byte is CEh");

		c = struct.add(WORD);
        c.setFieldName("version_number");
        c.setComment("Version to return on INT 21/AH=30h");

		c = struct.add(WORD);
        c.setFieldName("selector_next_psp");
        c.setComment("Win3: selector of next PSP (PDB) in linked list");

		c = struct.add(WORD);
        c.setFieldName("pdb_partition");
        c.setComment("Win3: PDB_Partition");

		c = struct.add(WORD);
        c.setFieldName("pdb_next_pdb");
        c.setComment("Win3: PDB_NextPDB");

		c = struct.add(BYTE);
        c.setFieldName("old_win_ap");
        c.setComment("Win3: bit 0 set if non-Windows application");

		c = struct.add(new ArrayDataType(BYTE,3,1));
        c.setFieldName("unused2");
        c.setComment("Unused by DOS versions <= 6.00");

		c = struct.add(WORD);
        c.setFieldName("pdb_entry_stack");
        c.setComment("Win3: PDB_EntryStack");

		c = struct.add(WORD);
        c.setFieldName("unused3");
        c.setComment("Unused by DOS versions <= 6.00");

		c = struct.add(new ArrayDataType(BYTE,3,1));
        c.setFieldName("service_request");
        c.setComment("INT 21/RETF instructions");

		c = struct.add(WORD);
        c.setFieldName("unused4");
        c.setComment("Unused by DOS versions <= 6.00");

		c = struct.add(new ArrayDataType(BYTE,7,1));
        c.setFieldName("space_extended_fcb");
        c.setComment("Space for extended FCB 1");

		c = struct.add(new ArrayDataType(BYTE,16,1));
        c.setFieldName("fcb1");
        c.setComment("Space FCB 1");

		c = struct.add(new ArrayDataType(BYTE,16,1));
        c.setFieldName("fcb2");
        c.setComment("Space FCB 2");

		c = struct.add(new ArrayDataType(BYTE,4,1));
        c.setFieldName("unsued5");
        c.setComment("Unsued");

		c = struct.add(new ArrayDataType(BYTE,128,1));
        c.setFieldName("command_line");
        c.setComment("Command line and default DTA");

        struct.setCategoryPath(new CategoryPath("/DOS"));

        return struct;
	}
}
