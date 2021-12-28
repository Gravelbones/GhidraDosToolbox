package ghidradostoolbox;

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
 */


/***
*  Class for holding information about a function, return value and parameters
*/

public class FunctionInformation {
	// The name of this system call
    public String name;
    // Return value of the function call
    // DataType:Registers E.g. R_SWAPDATAAREAS:AX:DS:SI
    public String return_value;
    // Parameters to this function definition
    // List of Name:DataType:Registers E.g. param:PDOSPARAMLIST:DS:DX
    public String parameters;

    FunctionInformation(String n, String rt, String p) {
    	name = n;
    	return_value = rt;
    	parameters = p;
    }

    public String getName() {
    	return name;
    }

    public String getReturn() {
    	return return_value;
    }

    public String getParameters() {
    	return parameters;
    }

    @Override
    public boolean equals(Object o) {
    	if (o instanceof String) {
    		return name.equals(o);
    	}
        if (!(o instanceof FunctionInformation)) {
            return false;
        }
        return name.equals(((FunctionInformation) o).getName());
    }
}
