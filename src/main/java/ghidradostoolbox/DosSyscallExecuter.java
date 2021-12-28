package ghidradostoolbox;
/* ###
 * IP: Morten R�nne
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
 *
 */

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xml.sax.SAXException;

import java.util.Map.Entry;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd;
import ghidra.app.cmd.memory.AddUninitializedMemoryBlockCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.lang.BasicCompilerSpec;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadSleigh;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/*
 *  This class implements all the action of mapping to system calls.
 *  This is to have both an analyzer and a script to do the work.
 */
public class DosSyscallExecuter {
	// What program type can we analyze
	public static final String LANGUAGE = "x86:LE:16:Real Mode";

	// Name of file with interrupt functions
	public static final String INTR_FILE = "x86_msdos6_interrupt_functions";

	// Datatype archive containing signature of system calls
	public static final String DATATYPE_ARCHIVE_NAME = "dos_vs6_16";

	// This should be the max number of known interrupt functions (unique function names in input file)
	private static final int SYSCALL_SPACE_LENGTH = 0x400;

	// Name of address space for interrupt functions
    private static final String SPACE_NAME = "int";

	// Any function with this in the name will not return
	private static final String NON_RETURN_SYSCALLS = "Terminate";

	// List of the main interrupts (0-255)
	private SysCallIndex sysIndex[] = null;

	// The type of overriding reference to apply
	private RefType overrideType = RefType.CALL_OVERRIDE_UNCONDITIONAL;

	// Bookmark name
	private String bookmarkName = "Dos interrupt";

	// List of all function names
	private List<FunctionInformation> functions;

	// The message log
	private MessageLog log;

	// Monitor
	private TaskMonitor monitor;

	// Bookmark manager
	private BookmarkManager bookmarkManager;

	// Reference manager
	private ReferenceManager referenceManager;

	// Function manager
	private FunctionManager functionManager;

	// Map of functions to process
	private Map<Function, Set<Instruction>> funcsToCalls;

	// Store the reference to the program
	private Program program;

	//  Address space where syscall functions live
	private AddressSpace syscallSpace;

	// Parser to map names to DataTypes
	private DataTypeParser parser;

	// Datatype Manager service
	DataTypeManagerService service;

	public DosSyscallExecuter(Program prog, MessageLog l, TaskMonitor m) {
		program = prog;
		log = l;
		monitor = m;
	}

	public boolean execute(FunctionIterator funcs, String filename, String archive)
			throws CancelledException {
		DataTypeManager source;

		syscallSpace = program.getAddressFactory().getAddressSpace(SPACE_NAME);
		if (syscallSpace == null) {
			//don't muck with address spaces if you don't have exclusive access to the program.
			if (!program.hasExclusiveAccess()) {
				log.appendMsg("Must have exclusive access to " + program.getName() +
						" to run this script");
				return false;
			}
			Address startAddr = program.getAddressFactory().getAddressSpace(
					BasicCompilerSpec.OTHER_SPACE_NAME).getAddress(0x0L);
			// The block should be filled with 0xCB = RETF instructions
			AddUninitializedMemoryBlockCmd cmd = new AddUninitializedMemoryBlockCmd(
					SPACE_NAME, "Dos Interrupt Function area", this.getClass().getName(), startAddr,
					SYSCALL_SPACE_LENGTH, true, false, true, false, true);
			if (!cmd.applyTo(program)) {
				log.appendMsg("Failed to create memory" + SPACE_NAME);
				return false;
			}
			syscallSpace = program.getAddressFactory().getAddressSpace(SPACE_NAME);
		}
		if(sysIndex == null) {
			functions = new ArrayList<FunctionInformation>();
			// Get the map from system call numbers to system call names
			// File name = program.getOptions(OPTION_FUNCTION_NAME).getFile(OPTION_FUNCTION_NAME, null);
			sysIndex = SysCallIndex.ReadFromFile(program, filename, functions);
		}

		// Get managers
		bookmarkManager = program.getBookmarkManager();
		referenceManager = program.getReferenceManager();
		functionManager = program.getFunctionManager();

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		service = mgr.getDataTypeManagerService();
		try {
			source = service.openDataTypeArchive(archive);
		}
		catch (IOException e) {
			log.appendException(e);
			return false;
		}
		catch (DuplicateIdException e) {
			log.appendException(e);
			return false;
		}

		// Data type must exist in source or builtin to be resolved
		parser = new DataTypeParser(source, program.getDataTypeManager(), null, AllowedDataTypes.STRINGS_AND_FIXED_LENGTH);

		getSyscallsInFunctions(funcs);

		if (funcsToCalls.isEmpty()) {
			// This gets triggered from analysis of any added code, when
			// there is no syscalls in the code, which likely is ok.
			//log.appendMsg("No system calls found (within defined functions)");
			return false;
		}

		// Get the system call number at each callsite of a system call.
		// note that this is not guaranteed to succeed at a given system call call site -
		// it might be hard (or impossible) to determine a specific constant
		Map<Address, Integer> addressesToSyscalls =	resolveConstants();

		if (addressesToSyscalls.isEmpty()) {
			log.appendMsg("Couldn't resolve any syscall constants");
			return false;
		}

		// At each system call site where a constant could be determined, create
		// the system call (if not already created), then add the appropriate overriding reference
		// for each function created return value and input parameters are set to custom storage
		// matching registers
		for (Entry<Address, Integer> entry : addressesToSyscalls.entrySet()) {
			Address callSite = entry.getKey();
			Integer offset = entry.getValue();
			Address callTarget = syscallSpace.getAddress(offset);
			String name;

			FunctionInformation func = functions.get(offset);
			Function callee = functionManager.getFunctionAt(callTarget);
			name = func.getName();
			if (callee == null) {
				CreateFunctionCmd cmd = new CreateFunctionCmd(name, callTarget, null,
						SourceType.USER_DEFINED);
				if (!cmd.applyTo(program, monitor)) {
					continue;
				}
				callee = program.getListing().getFunctionAt(callTarget);
				try {
					callee.setCallingConvention("unknown");
					callee.setCustomVariableStorage(true);
					List<ParameterImpl> p = createParams(func.getParameters());
					callee.updateFunction(null, null, p,
						FunctionUpdateType.CUSTOM_STORAGE, false,
						SourceType.USER_DEFINED);
					setReturn(callee, func.getReturn());
				}
				catch (InvalidDataTypeException e) {
					log.appendMsg("Invalid DataType for " + name);
				}
				catch (InvalidInputException e) {
					log.appendMsg("Failed to parse input for " + name);
				}
				catch (DuplicateNameException e) {
					log.appendMsg("Duplicate name in parameter list for " + name);
				}

				//check if the function name is one of the non-returning syscalls
				if (name.contains(NON_RETURN_SYSCALLS)) {
					callee.setNoReturn(true);
				}
			} else {
				if (!callee.getName().equals(name)) {
					log.appendMsg("Function name doesn't match. Rerunning with different file will cause problems.");
					throw new CancelledException();
				}
			}
			Reference ref = referenceManager.addMemoryReference(callSite,
					callTarget, overrideType, SourceType.USER_DEFINED, Reference.MNEMONIC);
			//overriding references must be primary to be active
			referenceManager.setPrimary(ref, true);
		}
		return true;
	}

	/**
	 * Scans through all of the functions defined in the function iterator and returns
	 * a map which takes a function to the set of address in its body which contain
	 * system calls
	 * @param funcs Iterator with functions to scan through
	 * @param tMonitor monitor
	 * @return map function -> addresses in function containing syscalls
	 * @throws CancelledException if the user cancels
	 */
	private void getSyscallsInFunctions(FunctionIterator funcs) throws CancelledException {
		funcsToCalls = new HashMap<>();
		for (Function func : funcs) {
			monitor.checkCanceled();
			for (Instruction inst : program.getListing().getInstructions(func.getBody(), true)) {
				try {
					if (inst.getBytes()[0] == -51) {
						Set<Instruction> callSites = funcsToCalls.get(func);
						if (callSites == null) {
							callSites = new HashSet<>();
							funcsToCalls.put(func, callSites);
						}
						callSites.add(inst);
					}
				}
				catch (MemoryAccessException e) {
					log.appendMsg("MemoryAccessException at " + inst.getAddress().toString());
				}
			}
		}
	}

	/**
	 * Uses the symbolic propogator to attempt to determine the constant value in
	 * the syscall register at each system call instruction
	 *
	 * @return map from addresses of system calls to system call numbers
	 * @throws CancelledException if the user cancels
	 */
	private Map<Address, Integer> resolveConstants() throws CancelledException {
		Map<Address, Integer> addressesToSyscalls = new HashMap<>();
		Value val;
		Address callSite;
		String text;
		int func_val, interrupt, function, subfunction;
		SysCallIndex list, list2;

		for (Function func : funcsToCalls.keySet()) {
			Address start = func.getEntryPoint();
			ContextEvaluator eval = new ConstantPropagationContextEvaluator(true);
			SymbolicPropogator symEval = new SymbolicPropogator(program);
			symEval.flowConstants(start, func.getBody(), eval, true, monitor);
			for (Instruction inst : funcsToCalls.get(func)) {
				try {
				    interrupt = (inst.getBytes()[1] & 0xFF);
				}
				catch (MemoryAccessException e) {
					log.appendMsg("MemoryAccessException at " + inst.getAddress().toString());
					continue;
				}

				callSite = inst.getAddress();
				try {
				    list = sysIndex[interrupt];
				}
				catch(ArrayIndexOutOfBoundsException e) {
					list = null;
				}
				if (list == null) {
					text = String.format("Couldn't resolve interrupt %02xh", interrupt);
				    createBookmark(callSite, text);
					continue;
				}
				if (list.index == null) {
					func_val = list.no;
				} else {
					val = symEval.getRegisterValue(callSite, list.syscallReg);
				    if (val == null) {
				    	text = String.format("Couldn't resolve value of %s, int %02xh", list.syscallReg, interrupt);
				    	log.appendMsg(text);
					    createBookmark(callSite, text);
					    continue;
				    }
				    function = (int) val.getValue();
					try {
				        list2 = list.index[function];
					}
					catch(ArrayIndexOutOfBoundsException e) {
						text = String.format("Couldn't resolve interrupt %02xh, function %02xh",
								interrupt, function);
						log.appendMsg(text);
						createBookmark(callSite, text);
						continue;
					}
				    if (list2.index == null) {
				    	func_val = list2.no;
				    } else {
				    	func_val = list2.no;
				    	val = symEval.getRegisterValue(callSite, list2.syscallReg);
					    if (val == null) {
							text = String.format("Couldn't resolve value of %s, int %02xh, function %02xh",
									list2.syscallReg, interrupt, function);
							log.appendMsg(text);
						    createBookmark(callSite, text);
					    } else {
					    	subfunction = (int) val.getValue();
					    	try {
					    		if (list2.index[subfunction] != null)
					    			func_val = list2.index[subfunction].no;
					    	}
					    	catch(ArrayIndexOutOfBoundsException e) {
					    		text = String.format("Couldn't resolve interrupt %02xh, function %02xh, sub %02xh",
									interrupt, function, subfunction);
					    		log.appendMsg(text);
					    		createBookmark(callSite, text);
					    	}
					    }
					    if( func_val == 0 ) continue;
					}
				}
				addressesToSyscalls.put(callSite, func_val);
			}
		}
		return addressesToSyscalls;
	}

	/**
	 * Create bookmark with the given note at address
	 * @param address Address where note is placed
	 * @param note The note
	 * @return Bookmark instance created
	 */
	private Bookmark createBookmark(Address address, String note) {

		// enforce one bookmark per address, as this is what the UI does
		Bookmark[] existingBookmarks = getBookmarks(address);
		if (existingBookmarks != null && existingBookmarks.length > 0) {
			existingBookmarks[0].set(bookmarkName, note);
			return existingBookmarks[0];
		}
		return bookmarkManager.setBookmark(address, BookmarkType.NOTE, bookmarkName, note);
	}

	/**
	 * Returns all of the NOTE bookmarks defined at the specified address
	 * @param address the address to retrieve the bookmark
	 * @return the bookmarks at the specified address
	 */
	private Bookmark[] getBookmarks(Address address) {
		return bookmarkManager.getBookmarks(address, BookmarkType.NOTE);
	}

	/**
	 * Parse the parameter string into a list of parameters for a function
	 * @param param String with all parameters
	 * @return List of parameters for the function
	 */
	private List<ParameterImpl> createParams(String param)
			throws CancelledException, InvalidDataTypeException, InvalidInputException {
		String[] param_list, vlist;
		int i, r;
		List<ParameterImpl> plist;

		plist = new ArrayList<ParameterImpl>();
		if (param.equals("void")) return plist;
		param_list = param.split(",");
		for( i = 0; i < param_list.length; i++) {
			vlist = param_list[i].split(":");
			DataType dt = parser.parse(vlist[1]);
			Register[] regs = new Register[vlist.length - 2];
			for (r = 0; r < vlist.length-2; r++) {
				regs[r] = program.getLanguage().getRegister(vlist[r+2]);
			}
			plist.add(new ParameterImpl(vlist[0], dt, new VariableStorage(program, regs), program));
		}
		return plist;
	}

	/**
	 * Set return value for function based on the return value string description
	 * E.g.	R_SWAPDATAAREAS:AX:DS:SI
	 * @param func Function to set return value on
	 * @param return_value The return value string description
	 */
    private void setReturn(Function func, String return_value)
    		throws CancelledException, InvalidInputException, InvalidDataTypeException {
    	int i;
    	String[] list;

    	if (return_value.equals("void")) {
    		DataType dt = parser.parse("void");
    		func.setReturnType(dt, SourceType.USER_DEFINED);
    		return;
    	}
		list = return_value.split(":");
   		DataType dt = parser.parse(list[0]);
   		Register[] regs = new Register[list.length - 1];
   		for (i = 0; i < list.length-1; i++) {
   			regs[i] = program.getLanguage().getRegister(list[i+1]);
   		}
   		func.setReturn(dt, new VariableStorage(program, regs), SourceType.USER_DEFINED);
     }
}
