package ghidradostoolbox;

/* ###
 * Created By: Morten Rønne
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
/***
 * Class for holding either a function reference and/or a list for further subdivision
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

public class SysCallIndex {
	// The Function no of this system call
    public int no;
    // This function has more functions
    public SysCallIndex index[];
    // The function number is in this register
    public Register syscallReg;

    // Read a list of interrupts and return an array of the top most interrupt
    public static SysCallIndex[] ReadFromFile(Program program, String filename, List<FunctionInformation> functions) {
    	Integer interrupt = -1;
    	Integer function = -1;
    	Integer subfunction = -1;
    	int no;
    	SysCallIndex self[], list, list2;
    	// List of all function names
    	String[] parts, values;

    	ResourceFile rFile = Application.findDataFileInAnyModule(filename);
    	if (rFile == null) {
    		return null;
    	}
    	self = null;
		// Assign value 0 to an unknown function.
		functions.add(new FunctionInformation("unknown function", "void", "void"));

    	try (FileReader fReader = new FileReader(rFile.getFile(false));
    			BufferedReader bReader = new BufferedReader(fReader)) {
    		String line = null;
    		while ((line = bReader.readLine()) != null) {
    			// lines starting with # are comments
    			if (!line.startsWith("#") && !line.equals("")) {
    				parts = line.trim().split(" ");

					interrupt = Integer.parseInt(parts[0], 16);
    				if (self == null) {
    					self = new SysCallIndex[interrupt+1];
    				}
    				no = getNo(functions, parts[3], parts[4], parts[5]);
    				if (self[interrupt] == null) {
    					self[interrupt] = new SysCallIndex();
    				}

    				if (!parts[1].equals("--")) {
    					list = self[interrupt];
    					values = ParseRegisterValue(parts[1], "AH");
    					function = Integer.parseInt(values[1], 16);
    					if (list.index == null) {
    						list.index = new SysCallIndex[function+1];
        					list.syscallReg = program.getLanguage().getRegister(values[0]);
    					}
    					if (list.index[function] == null) {
    						list.index[function] = new SysCallIndex();
    					}
    					if (!parts[2].equals("--") && !parts[2].equals("??")) {
    						list2 = list.index[function];
    						values = ParseRegisterValue(parts[2], "AL");
    						subfunction = Integer.parseInt(values[1], 16);
    						if (list2.index == null) {
    							list2.index = new SysCallIndex[subfunction+1];
    							list2.syscallReg = program.getLanguage().getRegister(values[0]);
    						}
    						list2.index[subfunction] = new SysCallIndex(no);
    					} else {
    						list.index[function].no = no;
    					}
    				} else {
    					self[interrupt].no = no;
    					self[interrupt].syscallReg = null;
    				}
    			}
    		}
    	}
    	catch (IOException e) {
    		return null;
    	}
    	return self;
    }

    private static String[] ParseRegisterValue(String input, String defaultRegister) {
    	String[] parts = input.split("[/:]");
    	if(parts.length == 2) {
    		return new String[] {parts[0], parts[1]};
    	}
    	return new String[] {defaultRegister, parts[0]};
    }

    public SysCallIndex() {
    	no = 0;
    	index = null;
    	syscallReg = null;
    }

    public SysCallIndex(Integer number) {
    	no = number;
    	syscallReg = null;
    	index = null;
    }

    public SysCallIndex(Integer number, Register reg) {
    	no = number;
    	syscallReg = reg;
    	index = null;
    }

    private static int getNo(List<FunctionInformation> functions, String name, String r, String p) {
		FunctionInformation f = new FunctionInformation(name, r, p);
		int no = functions.indexOf(f);
		if (no == -1) {
			no = functions.size();
			functions.add(f);
		}
		return no;
    }
}
