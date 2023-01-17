package ghidradostoolbox;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class DosBiosAreaStructure implements StructConverter {
	public final static String NAME = "BIOSAREA";

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(WORD, "first", "Fill out with information");

		struct.setCategoryPath(new CategoryPath("/DOS"));

        return struct;
	}

}
