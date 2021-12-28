/* ###
 * IP: GHIDRA
 * Modified by: Gravelbones for testing purpose
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

import generic.continues.ContinuesFactory;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.mz.OldStyleExecutable;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.MessageLogContinuesFactory;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Conv;
import ghidra.util.DataConverter;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

import ghidra.util.task.TaskMonitor;

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

	private DataConverter converter = LittleEndianDataConverter.INSTANCE;

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
		OldStyleExecutable ose = new OldStyleExecutable(RethrowContinuesFactory.INSTANCE, provider);
		DOSHeader dos = ose.getDOSHeader();
		if (dos.isDosSignature() && !dos.hasNewExeHeader() && !dos.hasPeHeader()) {
			List<QueryResult> results =
				QueryOpinionService.query(getName(), "" + dos.e_magic(), null);
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
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program prog,
			TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(prog, provider, monitor);
		AddressFactory af = prog.getAddressFactory();
		if (!(af.getDefaultAddressSpace() instanceof SegmentedAddressSpace)) {
			throw new IOException("Selected Language must have a segmented address space.");
		}

		SegmentedAddressSpace space = (SegmentedAddressSpace) af.getDefaultAddressSpace();
		SymbolTable symbolTable = prog.getSymbolTable();
		ProgramContext context = prog.getProgramContext();
		Memory memory = prog.getMemory();

		ContinuesFactory factory = MessageLogContinuesFactory.create(log);
		OldStyleExecutable ose = new OldStyleExecutable(factory, provider);
		DOSHeader dos = ose.getDOSHeader();
		FactoryBundledWithBinaryReader reader = ose.getBinaryReader();

		if (monitor.isCancelled()) {
			return;
		}

		monitor.setMessage("Processing segments...");
		processSegments(prog, fileBytes, space, reader, dos, log, monitor);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing relocations...");
		doRelocations(prog, reader, dos);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Processing symbols...");
		createSymbols(space, symbolTable, dos);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Setting registers...");
		Symbol entrySymbol = SymbolUtilities.getLabelOrFunctionSymbol(prog, ENTRY_NAME,
			err -> log.appendMsg("MZ", err));
		setRegisters(context, entrySymbol, memory.getBlocks(), dos);

		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("Setting data and header information...");
		try {
			DataType dt = new DosPspStructure().toDataType();
			SegmentedAddress start =	space.getAddress(INITIAL_PSP_SEGMENT, 0);
			MemoryBlockUtils.createInitializedBlock(prog, false, "PSP",
				start, 256, "Program Segment Prefix", "dos", true, true, false, log);
			// Set the proper data type for the PSP
			DataUtilities.createData(prog, start, dt, -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			// TODO: What about environment variables, should be after PSP

			/* Load the header after PSP but before program */
			start = space.getAddress(INITIAL_PSP_SEGMENT + 16, 0);
			MemoryBlockUtils.createInitializedBlock(prog, false, "Headers", start, fileBytes, 0,
					64, "DOS header", "mz", true, false, false, log);

			// Mark header data as just that, so it also get shown
			dt = dos.toDataType();
			DataUtilities.createData(prog, start, dt, -1, false,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

			// Create IVT table (if requested)
			if (shouldCreateIVTTable(options)) {
				dt = new DosIvtStructure().toDataType();
				start =	space.getAddress(0, 0);
				MemoryBlockUtils.createUninitializedBlock(prog, false, "IVT",
					start, 1024, "Interrupt vector table", "pc", true, true, false, log);
				// Set the proper data type for the IVT table
				DataUtilities.createData(prog, start, dt, -1, false,
					DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}

			// Create Bios memory area (if requested)
			if (shouldCreateBiosArea(options)) {
				dt = new DosBiosAreaStructure().toDataType();
				start =	space.getAddress(0x40, 0);
				MemoryBlockUtils.createUninitializedBlock(prog, false, "BMA",
					start, 16, "Bios memory area", "pc", true, true, false, log);
				DataUtilities.createData(prog, start, dt, -1, false,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			}
		}
		catch(Exception e) {
			log.appendMsg("Error setting base header information " + e);
		}
	}

	private void setRegisters(ProgramContext context, Symbol entry, MemoryBlock[] blocks,
			DOSHeader dos) {
		if (entry == null) {
			return;
		}
		// For any DOS program DS points to the PSP structure created by DOS
		// As the program is analyzed, DS at each location should be identified
		// and this value should be overwritten
		long dsValue = INITIAL_PSP_SEGMENT;

		Register ss = context.getRegister("ss");
		Register sp = context.getRegister("sp");
		Register ds = context.getRegister("ds");
		Register cs = context.getRegister("cs");

		try {
			context.setValue(sp, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(Conv.shortToLong(dos.e_sp())));
			context.setValue(ss, entry.getAddress(), entry.getAddress(),
				BigInteger.valueOf(Conv.shortToLong(dos.e_ss())+INITIAL_SEGMENT_VAL));
/*
			BigInteger csValue = BigInteger.valueOf(
					Conv.intToLong(((SegmentedAddress) entry.getAddress()).getSegment()));
*/
			// CS should point to segment for each loaded segment
			// In case of a data segment that is pointless but do no harm
			// Any jump/call into the segment should be a far one anyway
			for (MemoryBlock block : blocks) {
				SegmentedAddress start = (SegmentedAddress) block.getStart();
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

	private void processSegments(Program program, FileBytes fileBytes, SegmentedAddressSpace space,
			FactoryBundledWithBinaryReader reader, DOSHeader dos, MessageLog log,
			TaskMonitor monitor) {
		try {
			int relocationTableOffset = Conv.shortToInt(dos.e_lfarlc());
			int csStart = INITIAL_SEGMENT_VAL;
			int dataStart = dos.e_cparhdr() << 4;

			SegmentedAddress codeAddress =
					space.getAddress(Conv.shortToInt(dos.e_cs()) + csStart, 0);

			HashMap<Address, Address> segMap = new HashMap<Address, Address>();
			segMap.put(codeAddress, codeAddress);
			codeAddress = space.getAddress(csStart, 0);
			segMap.put(codeAddress, codeAddress);			// This is there data starts loading
			int numRelocationEntries = dos.e_crlc();
			reader.setPointerIndex(relocationTableOffset);
			for (int i = 0; i < numRelocationEntries; i++) {
				int off = Conv.shortToInt(reader.readNextShort());
				int seg = Conv.shortToInt(reader.readNextShort());

				// compute the new segment referenced at the location
				SegmentedAddress segStartAddr = space.getAddress(seg + csStart, 0);
				segMap.put(segStartAddr, segStartAddr);

				int location = (seg << 4) + off;
				int locOffset = location + dataStart;

				int value = Conv.shortToInt(reader.readShort(locOffset));
				int fixupAddrSeg = (value + csStart) & Conv.SHORT_MASK;
				SegmentedAddress fixupAddr = space.getAddress(fixupAddrSeg, 0);
				segMap.put(fixupAddr, fixupAddr);
			}

			int exeBlockCount = dos.e_cp();
			int exeEndOffset = exeBlockCount * 512;
			int bytesUsedInLastBlock = dos.e_cblp();
			if (bytesUsedInLastBlock != 0) {
				exeEndOffset -= (512 - bytesUsedInLastBlock);
			}

			ArrayList<Address> segStartList = new ArrayList<Address>(segMap.values());
			int csStartEffective = csStart << 4;
			Collections.sort(segStartList);
			for (int i = 0; i < segStartList.size(); i++) {
				SegmentedAddress start = (SegmentedAddress) segStartList.get(i);

				int readLoc = ((start.getSegment() << 4) - csStartEffective) + dataStart;
				if (readLoc < 0) {
					Msg.error(this, "Invalid read location " + readLoc);
					continue;
				}

				int numBytes = 0;
				if ((i + 1) < segStartList.size()) {
					SegmentedAddress end = (SegmentedAddress) segStartList.get(i + 1);
					int nextLoc = ((end.getSegment() << 4) - csStartEffective) + dataStart;
					numBytes = nextLoc - readLoc;
				}
				else {
					// last segment length
					numBytes = exeEndOffset - readLoc;
				}
				if (numBytes <= 0) {
					log.appendMsg("No EXE file data available for defined segment at: " + start);
					continue;
				}
				int numUninitBytes = 0;
				if ((readLoc + numBytes) > exeEndOffset) {
					int calcNumBytes = numBytes;
					numBytes = exeEndOffset - readLoc;
					numUninitBytes = calcNumBytes - numBytes;
				}
				if (numBytes > 0) {
					MemoryBlockUtils.createInitializedBlock(program, false, "Seg_" + i, start,
						fileBytes, readLoc, numBytes, "", "mz", true, true, true, log);
				}
				if (numUninitBytes > 0) {
					MemoryBlockUtils.createUninitializedBlock(program, false, "Seg_" + i + "u",
						start.add(numBytes), numUninitBytes, "", "mz", true, true, false, log);
				}
			}

			if (exeEndOffset < reader.length()) {
				int extraByteCount = (int) reader.length() - exeEndOffset;
				log.appendMsg("File contains 0x" + Integer.toHexString(extraByteCount) +
					" extra bytes starting at file offset 0x" + Integer.toHexString(exeEndOffset));
			}

//			// create the stack segment
//			SegmentedAddress stackStart = space.getAddress((dos.e_ss() + csStart), 0);
//			mbu.createUninitializedBlock(false, "Stack", stackStart, dos.e_sp(), "", "", true, true, false);

		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (AddressOverflowException e) {
			throw new RuntimeException(e);
		}
	}

	private void doRelocations(Program prog, FactoryBundledWithBinaryReader reader, DOSHeader dos) {
		try {
			Memory mem = prog.getMemory();
			SegmentedAddressSpace space =
				(SegmentedAddressSpace) prog.getAddressFactory().getDefaultAddressSpace();

			int relocationTableOffset = Conv.shortToInt(dos.e_lfarlc());
			int csStart = INITIAL_SEGMENT_VAL;
			int dataStart = dos.e_cparhdr() << 4;

			int numRelocationEntries = dos.e_crlc();
			reader.setPointerIndex(relocationTableOffset);
			for (int i = 0; i < numRelocationEntries; i++) {
				int off = Conv.shortToInt(reader.readNextShort());
				int seg = Conv.shortToInt(reader.readNextShort());

				//SegmentedAddress segStartAddr = space.getAddress(seg + csStart, 0);

				int location = (seg << 4) + off;
				int locOffset = location + dataStart;

				// compute the new segment referenced at the location
				SegmentedAddress fixupAddr = space.getAddress(seg + csStart, off);
				int value = Conv.shortToInt(reader.readShort(locOffset));
				int fixupAddrSeg = (value + csStart) & Conv.SHORT_MASK;
				mem.setShort(fixupAddr, (short) fixupAddrSeg);

				// Add to relocation table
				prog.getRelocationTable()
						.add(fixupAddr, 0, new long[] { off, seg }, converter.getBytes(value),
							null);
			}
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
		catch (MemoryAccessException e) {
			throw new RuntimeException(e);
		}
	}

	private void createSymbols(SegmentedAddressSpace space, SymbolTable symbolTable,
			DOSHeader dos) {
		int ipValue = Conv.shortToInt(dos.e_ip());
		int codeSegment = Conv.shortToInt(dos.e_cs()) + INITIAL_SEGMENT_VAL;

		if (codeSegment > Conv.SHORT_MASK) {
			System.out.println("Invalid entry point location: " + Integer.toHexString(codeSegment) +
				":" + Integer.toHexString(ipValue));
			return;
		}

		Address addr = space.getAddress(codeSegment, ipValue);

		try {
			symbolTable.createLabel(addr, ENTRY_NAME, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			// Just skip if we can't create
		}

		symbolTable.addExternalEntryPoint(addr);
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
}