# Ghidra Dos Toolbox

This package contains various scripts to help analyze old DOS programs.

For now this is a script (ResolveDosSyscalls) and an analyzer (DosSyscallAnalyzer)
which will map software interrupts (INT) to a function name.

The mapping is contained in a file, and the standard file is
x86_msdos6_interrupt_functions.

There is also a Ghidra Data Type (dos_vs6_16) for known DOS structures.
This will be included into the program on use.

The function list will most likely never be complete and programs may chain/replace
interrupts with functions of their own.

*Special notes about DOS programs*

Many of the functions uses the CPU Carry Flag (CF) to return error or not.
The decompiler may choke on that, because it has no idea how to handle that.

In case of error AX will often contain an error code, regardless of return register.
Most functions therefore have AX as a return value, for those situations.

## Installation

This will install as a standard Ghidra extension.
So download the zip file with the package matching your Ghidra version.
In Ghidra choose File -> Install extensions, select the Plus at the top to add a new
one and point to the downloaded file.

## Experimental loader

I have created an experimental loader, which I think better match the way a DOS program
works. You can always choose to use Ghidra's loader instead, but remember that once
loaded you have to start over, to load with another loader.

The loader offers options to create fixed memory area Interrupt Vector Table and Bios Area.
Those will simply be empty areas if created.

This is mostly meant for my own experiments with Ghidra functionality.
This should be handled/added at a later stage, when it is "detected" that the program
actually uses those areas.

### Changes to loader

- Create PSP segment before program (not populated)
- Show the image header as with new PE format.
- Change the way assumption about CS is done (local to each segment)
- Don't try to fix segment, just because there is specific byte (RETF) in the first 16 bytes.
- Fixed position of the ss segment. Commented code to create the stack block, did it correct.

# KNOWN BUGS/CAVEAT
Rerunning/reanalyzing with a different/updated interrupt file will give problems as
the functions already identified will be kept and reused even though its place move.

There may be problems with pointers. I have not yet fully tested that those are
handled properly.

Unused entries in the interrupt list is not checked for errors in return value
or parameters.

# Wanna help?

If you want to help I will happily accept any contribution in making the interrupt list more complete.

You don't have to make pull requests, just post your updates. Remember any new structs.

Also if you have access to old compiler libraries, tools or other resource used in creating DOS programs,
chances are that it would interesting.

# Don'ts

- Don't ask for specific interrupt/functions/subfunctions to be added.
- Don't report missing interrupt/functions/subfunctions as bugs. It is a feature for you to expand on.
- Don't comment on bad java code (in your opinion). No one is forcing you to use this and most likely I know already.

# The interrupt function file

The interrupt file has the following format separated with space:
- Interrupt no (in hex)
- [Register/]Function no (in hex) or --
- [Register/]Subfunction no (in hex) or -- or ??
- Name of function
- Return value of the function or void (no spaces)
- Parameters to the function or void (no spaces)

The default register for the function code is AH, and subfunction is AL
but adding Register/ in front will change it to that register.

The list must be sorted in decreasing order of interrupt, function and
subfunction. This is to make allocation of arrays simple, as the program
can just allocate the first number (highest number seen).

The value of ?? means that any (other) value will be mapped to this
function. Normally used in subfunctions where a number of values map
to the same function.

The program will only accept 4095 functions in a list.
Should the file grow beyond that, the SYSCALL_SPACE_LENGTH must be increased.

Any function with Terminate in the name will be marked as non returning function.

Return value is defined as `<Returntype>[:<Register>]+`

As Ghidra only recognize one return value, in case of multiple register return, a struct
must be created to contain the values. The order of fields should simply match the
order of register in the list.

The parameter list consist of `<Name>:<Datatype>[:<Register>]+ or void`

**Examples**

`21 5D 0B DosGetSwapableDataAreas R_DATASWAPAREAS:AX:DS:SI void`

This is interrupt 21 (DOS functions), function 5D (passed in AH), subfunction 0B (passed in AL)
which map to the function DosGetSwapableDataAreas which return a status code and a list

`10 12 BL/35 VideoAltFuncSelDisplaySwitchInterface byte:AL new_state:byte:AL,save_area:byte[128]*:ES:DX`

This in interrupt 10 (Video functions), function 12 (AH), subfunction 35 (BL)
which map to VideoAltFuncSelDisplaySwitchInterface which return a status byte and takes new state to set,
and a 128 byte area pointer passed in ES:DX register pair.

And a simple one

`20 -- -- DosTerminate void void`

Every instance of INT 20 will be directed at DosTerminate, regardless of registers.

## Supporting other DOS/Bios versions

To support/handle other DOS versions simply create a file which maps
to other functions.

Then copy the script and/or the analyzer and change the name passed
to the class doing the work.

# TODO:
- Script for validating the entire interrupt file.
- Call fixup at INT locations, to remove swi() disassembly.
- Fixed memory regions like screen ram, ROMS and so on.
- I/O ports. DOS has much more I/O than standard programs to day, even non device drivers.
- Find common library function from various compilers without access to the compiler.
- Find common library functions from game companies.
- Make "assumption" about segment values (CS, DS, ES, SS)
- Pointer handling together with the assumptions above.
- DOS4/GW handling and extended memory EMM/EMS
- Figure out how to make the interrupt file list "selectable".
- Change the namespace?
- Make the loader handle load of program in program (emulate DosExecute... for example or for overlays).
