package ghidradostoolbox;

/* ###
 * IP: GHIDRA
 * Modified By: Morten Rønne
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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.listing.*;


/**
 * This Analyzer finds x86 INT instructions (opcode CD) and then maps these instruction to function prototypes.
 * This was the way DOS programs and to some extend Win3 did system calls and interface with BIOS function like
 * memory, disk, and screen functions.
 * Most commonly the AH register will contain the main function within the interrupt and in some cases AL will contain
 * a subfunction. In some cases other registers will contain the subfunction.
 * The analyzer will read a file with mapping of interrupt, function and subfunction to a function name.
 * The standard file will map to MS-DOS 6 functions.
 * To map other versions create a new file with new names for functions which are different.
 *
 * The functions lives in its own memory space where a function takes up 1 byte. This will normally be found at the
 * end of the listing.
 */
public class DosSyscallAnalyzer extends AbstractAnalyzer {
	// Name of the option for interrupt function filename
	//private static final String OPTION_FUNCTION_NAME = "Function list file";

	public DosSyscallAnalyzer() {
		super("DosSyscallAnalyzer", "Maps INT instructions to DOS/BIOS calls", AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return program.getLanguage().getLanguageID().getIdAsString().contains(DosSyscallExecuter.LANGUAGE);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getLanguageID().getIdAsString().contains(DosSyscallExecuter.LANGUAGE);
	}

/*
	@Override
	public void registerOptions(Options options, Program program) {
		// The file name with function names

		options.registerOption(OPTION_FUNCTION_NAME, OptionType.FILE_TYPE, INTR_FILE,  null,
			"Select which file with function name to use");

	}

	@Override
	public void optionsChanged(Options options, Program program) {

	}
*/

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		DosSyscallExecuter e = new DosSyscallExecuter(program, log, monitor);
		return e.execute(program.getFunctionManager().getFunctions(set, true),
			DosSyscallExecuter.INTR_FILE,
			DosSyscallExecuter.DATATYPE_ARCHIVE_NAME);
	}
}
