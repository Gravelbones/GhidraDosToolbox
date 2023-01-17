/* ###
 * IP: Morten Rønne
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
 * Uses overriding references and the symbolic propogator to resolve system calls
 */
//Resolve DOS interrupt calls
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.Msg;
import ghidradostoolbox.DosSyscallExecuter;

/**
 * This script will resolve DOS interrupt calls for old style x86 binaries.
 * The script will handle all interrupt numbers listed in the input file
 */

public class ResolveDosSyscalls extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (!(currentProgram.getLanguage().getLanguageID().getIdAsString().contains(
				DosSyscallExecuter.LANGUAGE))) {
			popup("This script is intended for old style x86 programs");
			return;
		}

		MessageLog msgLog = new MessageLog();
		DosSyscallExecuter e = new DosSyscallExecuter(currentProgram, msgLog, monitor);
		e.execute(currentProgram.getFunctionManager().getFunctionsNoStubs(true),
				DosSyscallExecuter.INTR_FILE,
				DosSyscallExecuter.DATATYPE_ARCHIVE_NAME);
		Msg.info(this, msgLog.toString());
	}
}

