/* ###
 * IP: GHIDRA
 * Modified by: Morten Rønne for testing purpose
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidradostoolbox;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.mz.*;
/*
import ghidra.app.util.bin.format.mz.MzRelocation;
import ghidra.app.util.bin.format.mz.OldDOSHeader;
*/
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
/*
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
*/
/*
import ghidra.program.model.data.*;
*/
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.*;
/*
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
*/
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.*;
/*
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
*/
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/*
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.mz.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.symbol.*;

*/

/**
 * This class is an replacement of the default MZ type loader, in order to test
 * and/or fix problems with that loader.
 */
public class DosLoader extends AbstractLibrarySupportLoader {
	public final static String MZ_NAME = "Old-style DOS Executable (MZ)(Experimental)";

	private final static String ENTRY_NAME = "entry";
	private final static int INITIAL_SEGMENT_VAL = 0x1000;
	private final static int INITIAL_PSP_SEGMENT = 0x0FEC; /* 320 bytes right before the program (PSP + Header) */
	// The DOS header is 64 bytes so need at least that much
	private static final long MIN_BYTE_LENGTH = 64;

	/** Dos loader option to control whether interrupt vector table is created at 0:0  */
	public static final String CREATE_IVT_TABLE_OPTION_NAME = "Create Interrupt Vector table";
	static final boolean CREATE_IVT_TABLE_OPTION_DEFAULT = false;

	/** Dos loader option to control whether bios memory area is created at 0040:0  */
	public static final String CREATE_BIOS_AREA_OPTION_NAME = "Create Bios area at 0040:0";
	static final boolean CREATE_BIOS_AREA_OPTION_DEFAULT = false;

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		/* These only applies to first loaded program, not when we add to the program */
		if(!isLoadIntoProgram) {
			list.add(new Option(CREATE_IVT_TABLE_OPTION_NAME, CREATE_IVT_TABLE_OPTION_DEFAULT,
				Boolean.class, null));
			list.add(new Option(CREATE_BIOS_AREA_OPTION_NAME, CREATE_BIOS_AREA_OPTION_DEFAULT,
				Boolean.class, null));
		}
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		if (options != null) {
			for (Option option : options) {
				String name = option.getName();
				if (name.equals(CREATE_IVT_TABLE_OPTION_NAME) ||
					name.equals(CREATE_BIOS_AREA_OPTION_NAME)) {
					if (!Boolean.class.isAssignableFrom(option.getValueClass())) {
						return "Invalid type for option: " + name + " - " + option.getValueClass();
					}
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	public int getTierPriority() {
		return 59; // we are less priority than PE!  But higher than standard MZ loader. Important for AutoImporter
	}

	public DosLoader() {
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}
		MzExecutable mz = new MzExecutable(provider);
		OldDOSHeader header = mz.getHeader();
		if (header.isDosSignature() && !header.hasNewExeHeader() && !header.hasPeHeader()) {
			List<QueryResult> results =
				QueryOpinionService.query(getName(), "" + header.e_magic(), null);
			for (QueryResult result : results) {
				loadSpecs.add(new LoadSpec(this, 0, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, 0, true));
			}
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AddressFactory af = program.getAddressFactory();
		if (!(af.getDefaultAddressSpace() instanceof SegmentedAddressSpace)) {
			throw new IOException("Selected Language must have a segmented address space.");
		}

		SegmentedAddressSpace space = (SegmentedAddressSpace) af.getDefaultAddressSpace();
		MzExecutable mz = new MzExecutable(provider);
		
		try {
			Set<RelocationFixup> relocationFixups = getRelocationFixups(space, mz, log, monitor);

			markupHeaders(program, fileBytes, mz, log, monitor);
			processMemoryBlocks(program, fileBytes, space, mz, relocationFixups, log, monitor);
			processRelocations(program, space, mz, relocationFixups, log, monitor);
			processEntryPoint(program, space, mz, log, monitor);
			processRegisters(program, mz, log, monitor);
			processHeaderStructures(program, space, mz, log, monitor, fileBytes, options);
		}
		catch (CancelledException e) {
			return;
		}
		catch (IOException e) {
			throw e;
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	/**
	 * Stores a relocation's fixup information
	 * 
	 * @param address The {@link SegmentedAddress} of the relocation
	 * @param fileOffset The file offset of the relocation
	 * @param segment The fixed-up segment after the relocation is applied
	 */
	private record RelocationFixup(SegmentedAddress address, int fileOffset, int segment) {}
	
	private void markupHeaders(Program program, FileBytes fileBytes, MzExecutable mz,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up headers...");
		OldDOSHeader header = mz.getHeader();
		int blockSize = paragraphsToBytes(header.e_cparhdr());
		try {
			Address headerSpaceAddr = AddressSpace.OTHER_SPACE.getAddress(0);
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				"HEADER", headerSpaceAddr, fileBytes, 0, blockSize, "", "", false,
				false, false, log);
			Address addr = headerBlock.getStart();

			// Header
			DataUtilities.createData(program, addr, mz.getHeader().toDataType(), -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			// Relocation Table
			List<MzRelocation> relocations = mz.getRelocations();
			if (!relocations.isEmpty()) {
				DataType relocationType = relocations.get(0).toDataType();
				int len = relocationType.getLength();
				addr = addr.add(header.e_lfarlc());
				for (int i = 0; i < relocations.size(); i++) {
					monitor.checkCanceled();
					DataUtilities.createData(program, addr.add(i * len), relocationType, -1, false,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
			}

		}
		catch (Exception e) {
			log.appendMsg("Failed to markup headers");
		}
	}

	private void processMemoryBlocks(Program program, FileBytes fileBytes,
			SegmentedAddressSpace space, MzExecutable mz, Set<RelocationFixup> relocationFixups,
			MessageLog log, TaskMonitor monitor) throws Exception {
		monitor.setMessage("Processing memory blocks...");

		OldDOSHeader header = mz.getHeader();
		BinaryReader reader = mz.getBinaryReader();

		// Use relocations to discover what segments are in use.
		// We also know about our desired load module segment, so add that too.	
		Set<SegmentedAddress> knownSegments = new TreeSet<>();
		relocationFixups.forEach(rf -> knownSegments.add(space.getAddress(rf.segment, 0)));
		knownSegments.add(space.getAddress(INITIAL_SEGMENT_VAL, 0));

		// Allocate an initialized memory block for each segment we know about
		int endOffset = pagesToBytes(header.e_cp() - 1) + header.e_cblp();
		MemoryBlock lastBlock = null;
		List<SegmentedAddress> orderedSegments = new ArrayList<>(knownSegments);
		for (int i = 0; i < orderedSegments.size(); i++) {
			SegmentedAddress segmentAddr = orderedSegments.get(i);

			int segmentFileOffset = addressToFileOffset(
				(segmentAddr.getSegment() - INITIAL_SEGMENT_VAL) & 0xffff, 0, header);
			if (segmentFileOffset < 0) {
				log.appendMsg("Invalid segment start file location: " + segmentFileOffset);
				continue;
			}

			int numBytes = 0;
			if (i + 1 < orderedSegments.size()) {
				SegmentedAddress end = orderedSegments.get(i + 1);
				int nextSegmentFileOffset = addressToFileOffset(
					(end.getSegment() - INITIAL_SEGMENT_VAL) & 0xffff, 0, header);
				numBytes = nextSegmentFileOffset - segmentFileOffset;
			}
			else {
				// last segment length
				numBytes = endOffset - segmentFileOffset;
			}
			if (numBytes <= 0) {
				log.appendMsg("No file data available for defined segment at: " + segmentAddr);
				continue;
			}
			int numUninitBytes = 0;
			if (segmentFileOffset + numBytes > endOffset) {
				int calcNumBytes = numBytes;
				numBytes = endOffset - segmentFileOffset;
				numUninitBytes = calcNumBytes - numBytes;
			}
			if (numBytes > 0) {
				MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false,
					"CODE_" + i, segmentAddr, fileBytes, segmentFileOffset, numBytes, "", "mz",
					true, true, true, log);
				if (block != null) {
					lastBlock = block;
				}
			}
			if (numUninitBytes > 0) {
				MemoryBlock block =
					MemoryBlockUtils.createUninitializedBlock(program, false, "CODE_" + i + "u",
						segmentAddr.add(numBytes), numUninitBytes, "", "mz", true, true, false,
						log);
				if (block != null) {
					lastBlock = block;
				}
			}
		}
		if (endOffset < reader.length()) {
			int extraByteCount = (int) reader.length() - endOffset;
			log.appendMsg(
				String.format("File contains 0x%x extra bytes starting at file offset 0x%x",
					extraByteCount, endOffset));
		}

		// Allocate an uninitialized memory block for extra minimum required data space
		if (lastBlock != null) {
			int extraAllocSize = paragraphsToBytes(header.e_minalloc());
			if (extraAllocSize > 0) {
				MemoryBlockUtils.createUninitializedBlock(program, false, "DATA",
					lastBlock.getEnd().add(1), extraAllocSize, "", "mz", true, true, false, log);

			}
		}
	}

	private void processRelocations(Program program, SegmentedAddressSpace space, MzExecutable mz,
			Set<RelocationFixup> relocationFixups, MessageLog log, TaskMonitor monitor)
			throws Exception {
		monitor.setMessage("Processing relocations...");
		Memory memory = program.getMemory();

		for (RelocationFixup relocationFixup : relocationFixups) {
			SegmentedAddress relocationAddress = relocationFixup.address();
			Status status = Status.FAILURE;
			try {
				memory.setShort(relocationAddress, (short) relocationFixup.segment());
				status = Status.APPLIED;
			}
			catch (MemoryAccessException e) {
				log.appendMsg(String.format("Failed to apply relocation: %s (%s)",
					relocationAddress, e.getMessage()));
			}

			// Add to relocation table
			program.getRelocationTable()
					.add(relocationAddress, status, 0, new long[] { relocationAddress.getSegment(),
						relocationAddress.getSegmentOffset() }, 2, null);
		}
	}

	private void processEntryPoint(Program program, SegmentedAddressSpace space, MzExecutable mz,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Processing entry point...");

		OldDOSHeader header = mz.getHeader();

		int ipValue = Short.toUnsignedInt(header.e_ip());

		Address addr = space.getAddress(INITIAL_SEGMENT_VAL, ipValue);
		SymbolTable symbolTable = program.getSymbolTable();

		try {
			symbolTable.createLabel(addr, ENTRY_NAME, SourceType.IMPORTED);
			symbolTable.addExternalEntryPoint(addr);
		}
		catch (InvalidInputException e) {
			log.appendMsg("Failed to process entry point");
		}
	}

	private void processRegisters(Program program, MzExecutable mz, MessageLog log,
			TaskMonitor monitor) {
		monitor.setMessage("Processing registers...");

		Symbol entry = SymbolUtilities.getLabelOrFunctionSymbol(program, ENTRY_NAME,
			err -> log.appendMsg(err));
		if (entry == null) {
			return;
		}

		DataConverter converter = LittleEndianDataConverter.INSTANCE;
		// For any DOS program DS points to the PSP structure created by DOS
		// As the program is analyzed, DS at each location should be identified
		// and this value should be overwritten
		long dsValue = INITIAL_PSP_SEGMENT;

		OldDOSHeader header = mz.getHeader();
		ProgramContext context = program.getProgramContext();
		Register ss = context.getRegister("ss");
		Register sp = context.getRegister("sp");
		Register ds = context.getRegister("ds");
		Register cs = context.getRegister("cs");

		try {
			context.setValue(sp, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(Short.toUnsignedLong(header.e_sp())));
			context.setValue(ss, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(
					Integer.toUnsignedLong((header.e_ss() + INITIAL_SEGMENT_VAL) & 0xffff)));

			for (MemoryBlock block : program.getMemory().getBlocks()) {
				// CS should point to segment for each loaded segment
				// In case of a data segment that is pointless but do no harm
				// Any jump/call into the segment should be a far one				
				SegmentedAddress start = (SegmentedAddress) block.getStart();
				if (!(start.getAddressSpace() instanceof SegmentedAddressSpace)) {
					continue;
				}

				int csValue = start.getSegment();
				Address end = block.getEnd();				
				context.setValue(cs, start, end, BigInteger.valueOf(csValue));
				context.setValue(ds, start, end, BigInteger.valueOf(dsValue));
			}
		}
		catch (ContextChangeException e) {
			// ignore since segment registers should never cause this error
		}
	}
	
	private void processHeaderStructures(Program program, SegmentedAddressSpace space, MzExecutable mz,
			MessageLog log, TaskMonitor monitor, FileBytes fileBytes, List<Option> options) {
		monitor.setMessage("Setting data and header information...");
		try {
			DataType dt = new DosPspStructure().toDataType();
			SegmentedAddress start =	space.getAddress(INITIAL_PSP_SEGMENT, 0);
			MemoryBlockUtils.createInitializedBlock(program, false, "PSP",
				start, 256, "Program Segment Prefix", "dos", true, true, false, log);
			// Set the proper data type for the PSP
			DataUtilities.createData(program, start, dt, -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			// TODO: What about environment variables, should be after PSP

			/* Load the header after PSP but before program */
			start = space.getAddress(INITIAL_PSP_SEGMENT + 16, 0);
			MemoryBlockUtils.createInitializedBlock(program, false, "Headers", start, fileBytes, 0,
				64, "DOS header", "mz", true, false, false, log);

			// Mark header data as just that, so it also get shown
			OldDOSHeader header = mz.getHeader();
			dt = header.toDataType();
			DataUtilities.createData(program, start, dt, -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			// Create IVT table (if requested)
			if (shouldCreateIVTTable(options)) {
				dt = new DosIvtStructure().toDataType();
				start =	space.getAddress(0, 0);
				MemoryBlockUtils.createUninitializedBlock(program, false, "IVT",
					start, 1024, "Interrupt vector table", "pc", true, true, false, log);
				// Set the proper data type for the IVT table
				DataUtilities.createData(program, start, dt, -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}

			// Create Bios memory area (if requested)
			if (shouldCreateBiosArea(options)) {
				dt = new DosBiosAreaStructure().toDataType();
				start =	space.getAddress(0x40, 0);
				MemoryBlockUtils.createUninitializedBlock(program, false, "BMA",
					start, 16, "Bios memory area", "pc", true, true, false, log);
				DataUtilities.createData(program, start, dt, -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}
		}
		catch(Exception e) {
			log.appendMsg("Error setting base header information " + e);
		}
	}

	private boolean shouldCreateIVTTable(List<Option> options) {
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(CREATE_IVT_TABLE_OPTION_NAME)) {
					return (Boolean) option.getValue();
				}
			}
		}
		return CREATE_IVT_TABLE_OPTION_DEFAULT;
	}

	private boolean shouldCreateBiosArea(List<Option> options) {
		if (options != null) {
			for (Option option : options) {
				String optName = option.getName();
				if (optName.equals(CREATE_BIOS_AREA_OPTION_NAME)) {
					return (Boolean) option.getValue();
				}
			}
		}
		return CREATE_BIOS_AREA_OPTION_DEFAULT;
	}

	@Override
	public String getName() {
		return MZ_NAME;
	}

	/**
	 * Gets a {@link Set} of {@link RelocationFixup relocation fixups}, adjusted to where the image
	 * is loaded into memory
	 * 
	 * @param space The address space
	 * @param mz The {@link MzExecutable}
	 * @param monitor A monitor
	 * @return A {@link Set} of {@link RelocationFixup relocation fixups}, adjusted to where the 
	 *   image is loaded into memory
	 * @throws CancelledException If the action was cancelled
	 */
	private Set<RelocationFixup> getRelocationFixups(SegmentedAddressSpace space,
			MzExecutable mz, MessageLog log, TaskMonitor monitor) throws CancelledException {
		Set<RelocationFixup> fixups = new HashSet<>();

		OldDOSHeader header = mz.getHeader();
		BinaryReader reader = mz.getBinaryReader();

		for (MzRelocation relocation : mz.getRelocations()) {
			monitor.checkCanceled();

			int seg = relocation.getSegment();
			int off = relocation.getOffset();

			int relativeSegment = (seg - Short.toUnsignedInt(header.e_cs())) & 0xffff;
			int relocationFileOffset = addressToFileOffset(relativeSegment, off, header);
			SegmentedAddress relocationAddress =
				space.getAddress((relativeSegment + INITIAL_SEGMENT_VAL) & 0xffff, off);

			try {
				int value = Short.toUnsignedInt(reader.readShort(relocationFileOffset));
				int relocatedSegment = (value + INITIAL_SEGMENT_VAL) & 0xffff;
				fixups.add(
					new RelocationFixup(relocationAddress, relocationFileOffset, relocatedSegment));
			}
			catch (AddressOutOfBoundsException | IOException e) {
				log.appendMsg(String.format("Failed to process relocation: %s (%s)",
					relocationAddress, e.getMessage()));
			}
		}

		return fixups;
	}

	/**
	 * Converts a segmented address to a file offset
	 * 
	 * @param segment The segment
	 * @param offset The offset
	 * @param header The header
	 * @return The segmented addresses converted to a file offset
	 */
	private int addressToFileOffset(int segment, int offset, OldDOSHeader header) {
		return (segment << 4) + offset + paragraphsToBytes(header.e_cparhdr());
	}

	/**
	 * Converts paragraphs to bytes.  There are 16 bytes in a paragraph.
	 * 
	 * @param paragraphs The number of paragraphs
	 * @return The number of bytes in the given number of paragraphs
	 */
	private int paragraphsToBytes(int paragraphs) {
		return paragraphs << 4;
	}

	/**
	 * Converts pages to bytes.  There are 512 bytes in a paragraph.
	 * 
	 * @param pages The number of pages
	 * @return The number of bytes in the given number of pages
	 */
	private int pagesToBytes(int pages) {
		return pages << 9;
	}
}