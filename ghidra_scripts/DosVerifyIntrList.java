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
//Verify DOS interrupt list file
//@category Utility
import ghidra.app.script.GhidraScript;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.Application;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidradostoolbox.DosSyscallExecuter;

public class DosVerifyIntrList extends GhidraScript {

	@Override
	protected void run() throws Exception {
    	String[] parts, values, param_list;
    	Integer lineno = 0;
    	Integer no = -1, int_no = -1, func_no =-1, subfunc_no = -1;
    	int i, n;
    	Language l = currentProgram.getLanguage();
    	Register r;
    	DataType dt;
    	DataTypeParser parser;
    	DataTypeManagerService service;
    	DataTypeManager source;

    	ResourceFile rFile = Application.findDataFileInAnyModule(DosSyscallExecuter.INTR_FILE);
    	if (rFile == null) {
    		return;
    	}
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(currentProgram);
		service = mgr.getDataTypeManagerService();
		try {
			source = service.openDataTypeArchive(DosSyscallExecuter.DATATYPE_ARCHIVE_NAME);
		}
		catch (IOException e) {
			Msg.info(this, "Failed to open data archive", e);
			return;
		}
		catch (DuplicateIdException e) {
			Msg.info(this,  "Failed to open data archive", e);
			return;
		}
    	parser = new DataTypeParser(source, currentProgram.getDataTypeManager(),
    			null, AllowedDataTypes.STRINGS_AND_FIXED_LENGTH);

    	try (FileReader fReader = new FileReader(rFile.getFile(false));
    			BufferedReader bReader = new BufferedReader(fReader)) {
    		String line = null;
    		while ((line = bReader.readLine()) != null) {
    			lineno++;
    			if (!line.startsWith("#") && !line.equals("")) {
    				parts = line.trim().split(" ");
    				if (parts.length != 6) {
    					Msg.showInfo(this, null, "Error", "Expected 6 parameters. Line " + lineno);
    					continue;
    				}

    				// Test the interrupt number for range (part of the instruction)
					no = convertHex(parts[0]);
					if(no < 0 || no > 255) {
						Msg.showInfo(this, null, "Error", "Interrupt <"+parts[0]+"> not in range 0 - 0xff. Line: "+lineno);
					}
					if(no > int_no && int_no != -1) {
						Msg.showInfo(this, null, "Error", "Interrupt number must be same or lower than previous line: "+lineno);
					}
					if(no != int_no) {
						func_no = -1;
						int_no = no;
					}

					// If function isn't -- test for range and function register
					if (!parts[1].equals("--")) {
						values = ParseRegisterValue(parts[1], "AH");
						no = convertHex(values[1]);
						if(no < 0 || no > 255) {
							Msg.showInfo(this, null, "Error", "Function <"+values[1]+"> not in range 0 - 0xff. Line: "+lineno);
						}
						r = l.getRegister(values[0]);
						if(r == null) {
							Msg.showInfo(this, null, "Error", "Function register <"+values[0]+"> not found. Line: "+lineno);
						}
						if(no > func_no && func_no != -1) {
							Msg.showInfo(this, null, "Error", "Function number must be same or lower than previous line: "+lineno);
						}
						if(no != func_no) {
							subfunc_no = -1;
							func_no = no;
						}
					}

					// If subfunction isn't -- or ?? test for range and function register
					if (!(parts[2].equals("--") || parts[2].equals("??"))) {
						values = ParseRegisterValue(parts[2], "AL");
						no = convertHex(values[1]);
						if(no < 0 || no > 255) {
							Msg.showInfo(this, null, "Error", "Subfunction <"+values[1]+"> not in range 0 - 0xff. Line: "+lineno);
						}
						r = l.getRegister(values[0]);
						if(r == null) {
							Msg.showInfo(this, null, "Error", "Subfunction register <"+values[0]+"> not found. Line: "+lineno);
						}
						if(no > subfunc_no && subfunc_no != -1) {
							Msg.showInfo(this, null, "Error", "Subfuncion number must be same or lower than previous line: "+lineno);
						}
						if(no != subfunc_no) {
							subfunc_no = no;
						}
					}

					// Function name must start with letter and contain letters, digits or _ after that
					if (!parts[3].matches("\\A[A-Za-z][A-Za-z0-9_]*\\z")) {
						Msg.showInfo(this, null, "Error", "Function name <"+parts[3]+"> isn't valid. Line "+lineno);
					}

					// Check the return value
					if (!parts[4].equals("void")) {
						values = parts[4].split(":");
						if (values.length < 2) {
	    					Msg.showInfo(this, null, "Error", "Return <"+parts[4]+"> must be at least 2 elements. Line " + lineno);
	    					continue;
						}
						try {
							dt = parser.parse(values[0]);
						}
						catch(InvalidDataTypeException e) {
							dt = null;
						}
				   		if (dt == null) {
				   			Msg.showInfo(this, null, "Error", "Return type <"+values[0]+"> couldn't be parsed. Line "+lineno);
				   		}
				   		for (i = 0; i < values.length-1; i++) {
				   			r = l.getRegister(values[i+1]);
							if(r == null) {
								Msg.showInfo(this, null, "Error", "Return register <"+values[i+1]+"> not found. Line: "+lineno);
							}
				   		}
					}

					if (!parts[5].equals("void")) {
						param_list = parts[5].split(",");
						for( i = 0; i < param_list.length; i++) {
							values = param_list[i].split(":");
							if (values.length < 3) {
		    					Msg.showInfo(this, null, "Error", "Parameter <"+param_list[i]+"> must be at least 3 elements. Line " + lineno);
		    					continue;
							}
							if (!values[0].matches("\\A[A-Za-z][A-Za-z0-9_]*\\z")) {
								Msg.showInfo(this, null, "Error", "Parameter name <"+values[0]+"> isn't valid. Line "+lineno);
							}
							try {
								dt = parser.parse(values[1]);
							}
							catch(InvalidDataTypeException e) {
								dt = null;
							}
					   		if (dt == null) {
					   			Msg.showInfo(this, null, "Error", "Parameter type <"+values[1]+"> couldn't be parsed. Line "+lineno);
					   		}
							for (n = 0; n < values.length-2; n++) {
								r = l.getRegister(values[n+2]);
								if(r == null) {
									Msg.showInfo(this, null, "Error", "Parameter register <"+values[n+2]+"> not found. Line: "+lineno);
								}
							}
						}
					}
    			}
    		}
    	}
    	catch (IOException e) {
    		return;
    	}
	}

    private static String[] ParseRegisterValue(String input, String defaultRegister) {
    	String[] parts = input.split("[/:]");
    	if(parts.length == 2) {
    		return new String[] {parts[0], parts[1]};
    	}
    	return new String[] {defaultRegister, parts[0]};
    }

    private Integer convertHex(String t) {
    	try {
    		return Integer.parseInt(t, 16);
    	}
    	catch (NumberFormatException e) {
    		return -1;
    	}
    }

}
