package ghidradostoolbox;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * This class represents the <code>Interrupt Vector Table</code> which
 * is present at address 0:0 in an DOS environment
 * .
 * <br>
 * <pre>
 * typedef struct IVT_TABLE {
 *     DWORD  pointers[256];               // Pointer to interrupt functions
 * } IVT_TABLE;
 * </pre>
 *
 */
public class DosIvtStructure implements StructConverter {
	public final static String NAME = "IVT_TABLE";

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		// TODO: Figure the correct code pointer (4 bytes segment:offset)
		//       Not sure POINTER will do the trick
	    struct.add(new ArrayDataType(DWORD,256,4));

        struct.getComponent(0).setFieldName("table");
        struct.getComponent(0).setComment("Interrupt vector table");
		struct.setCategoryPath(new CategoryPath("/DOS"));

        return struct;
	}
}
