#!/usr/bin/env python3
######################################################################
#
# Be sure to use python3...
#
# This is just an example to get you started if you are having
# difficulty starting the assignment. It is by no means the most
# efficient way to implement this disassembler, however, it is one
# that can easily be followed and extended to complete the requirements
#
# You may want to import other modules, but certainly not required
# This implements linear sweep..this can be modified to implement
# recursive descent as well
#
######################################################################
import sys


#
# Key is the opcode
# value is a list of useful information
GLOBAL_OPCODE_MAP = {
    # Opcode: ['Instruction', 'ModRM?', 'Encoding Type']
    0x01 : ['add ', True, 'mr'], 
    0x03 : ['add ', True, 'rm'],
    0x05 : ['add eax, ', False, 'i'],
    0x09 : ['or ', True, 'mr'],
    0x0B : ['or ', True, 'rm'],
    0x0d : ['or eax ', False, 'i'],
    0x0f : [ { 0x84: ['jz ', True, 'cd'], # i 32 bit dist
               0x85: ['jz ', True, 'cd'], # i 32 bit dist
               0xAE: [{ 0x7: ['clflush '] }, True, 'm'] }, True, 'hybrid'], # 11 mod is illegal
    0x21 : ['and ', True, 'mr'],
    0x23 : ['and ', True, 'rm'],
    0x25 : ['and eax ', False, 'i'],
    0x29 : ['sub ', True, 'mr'],
    0x2B : ['sub ', True, 'rm'],
    0x2d : ['sub eax ', False, 'i'],
    0x31 : ['xor ', True, 'mr'],
    0x33 : ['xor ', True, 'rm'],
    0x35 : ['xor eax', False, 'i'],
    0x39 : ['cmp ', True, 'mr'],
    0x3B : ['cmp ', True, 'rm'],
    0x3D : ['cmp eax, ', False, 'i'],
    0x40 : ['inc eax ', False, 'o'],
    0x41 : ['inc ecx ', False, 'o'],
    0x42 : ['inc edx ', False, 'o'],
    0x43 : ['inc ebx ', False, 'o'],
    0x44 : ['inc esp ', False, 'o'],
    0x45 : ['inc ebp ', False, 'o'],
    0x46 : ['inc esi ', False, 'o'],
    0x47 : ['inc edi ', False, 'o'],
    0x48 : ['dec eax ', False, 'o'],
    0x49 : ['dec ecx ', False, 'o'],
    0x4a : ['dec edx ', False, 'o'],
    0x4b : ['dec ebx ', False, 'o'],
    0x4c : ['dec esp ', False, 'o'],
    0x4d : ['dec ebp ', False, 'o'],
    0x4e : ['dec esi ', False, 'o'],
    0x4f : ['dec edi ', False, 'o'],
    0x50 : ['push eax ', False, 'o'],
    0x51 : ['push ecx ', False, 'o'],
    0x52 : ['push edx ', False, 'o'],
    0x53 : ['push ebx ', False, 'o'],
    0x54 : ['push esp ', False, 'o'],
    0x55 : ['push ebp ', False, 'o'],
    0x56 : ['push esi ', False, 'o'],
    0x57 : ['push edi ', False, 'o'],
    0x58 : ['pop eax ', False, 'o'],
    0x59 : ['pop ecx ', False, 'o'],
    0x5a : ['pop edx ', False, 'o'],
    0x5b : ['pop ebx ', False, 'o'],
    0x5c : ['pop esp ', False, 'o'],
    0x5d : ['pop ebp ', False, 'o'],
    0x5e : ['pop esi ', False, 'o'],
    0x5f : ['pop edi ', False, 'o'],
    0x68 : ['push ', False, 'i'],
    0x74 : ['jz ', False, 'cb'], # i 8 bit dist
    0x75 : ['jnz ', False, 'cd'], # i 32 bit dist
    0x81 : [ { 0x0: ['add '],
               0x0: ['or '], 
               0x4: ['and '],
               0x5: ['sub '],
               0x6: ['xor '],
               0x7: ['cmp ']  }, True, 'mi'],
    0x85 : ['test ', True, 'mr'],
    0x89 : ['mov ', True, 'mr'],
    0x8b : ['mov ', True, 'rm'],
    0x8d : ['lea ', True, 'rm'], # 11 mod is illegal
    0x8f : [ { 0x0: ['pop '] }, True, 'm'],
    0x90 : ['nop ', False, 'zo'],
    0xa1 : ['mov eax ', True, 'fd'], # treat as oi 32
    0xa5 : ['movsd ', False, 'zo'], 
    0xa3 : [['mov ', 'eax '], True, 'td'], # treat as oi 32
    0xa9 : ['test eax, ', False, 'i'],
    0xb8 : ['mov eax ', False, 'oi'],
    0xb9 : ['mov ecx ', False, 'oi'],
    0xba : ['mov edx ', False, 'oi'],
    0xbb : ['mov ebx ', False, 'oi'],
    0xbc : ['mov esp ', False, 'oi'],
    0xbd : ['mov ebp ', False, 'oi'],
    0xbe : ['mov esi ', False, 'oi'],
    0xbf : ['mov edi ', False, 'oi'],
    0xc2 : ['retn ', False, 'i'],  # i 16
    0xc3 : ['retn ', False, 'zo'],
    0xc7 : [ { 0x0: ['mov '] }, True, 'mi'],
    0xca : ['retf ', False, 'i'], # i 16
    0xcb : ['retf ', False, 'zo'],
    0xE8 : ['call ', False, 'cd'], # i 32 bit dist
    0xE9 : ['jmp ', False, 'cd'], # i 32 bit dist
    0xEB : ['jmp ', False, 'cb'], # i 8 bit dist
    0xf2 : [ { 0xa7: ['not '] }, False, 'zo'],
    0xf7 : [ { 0x0: ['test ', True, 'mi'], 
               0x2: ['not ', True, 'm'], 
               0x7: ['idiv', True, 'm'] }, True, 'hybrid'], 
    0xff : [ { 0x1: ['inc '],
               0x1: ['dec '],
               0x2: ['call '],
               0x4: ['jmp '],
               0x6: ['push '] }, True, 'm']
}

GLOBAL_REGISTER_NAMES = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi' ]

def isValidOpcode(opcode):
    if opcode in GLOBAL_OPCODE_MAP.keys():
        return True
    return False

def parseMODRM(modrm):
    #mod = (modrm & 0xC0) >> 6
    #reg = (modrm & 0x38) >> 3
    #rm  = (modrm & 0x07)

    mod = (modrm & 0b11000000) >> 6
    reg = (modrm & 0b00111000) >> 3
    rm  = (modrm & 0b00000111)
    return (mod,reg,rm)

def printDisasm( l ):

    # Good idea to add a "global label" structure...
    # can check to see if "addr" is in it for a branch reference

    for addr in sorted(l):
        print( '%s: %s' % (addr, l[addr]) )

def disassemble(b):

    ## TM
    # I would suggest maintaining an "output" dictionary
    # Your key should be the counter/address [you can use this
    # to print out labels easily]
    # and the value should be your disassembly output (or some
    # other data structure that can represent this..up to you )
    outputList = {}

    counter = 0

    while counter < len(b):

        implemented = False
        opcode = b[counter]	# current byte to work on
        instruction_bytes = "%02x" % b[counter]
        instruction = ''
        orig_index = counter
        
        counter += 1

        # Hint this is here for a reason, but is this the only spot
        # such a check is required in?
        if counter > len(b):
           break

        
        if isValidOpcode( opcode ):
            print ('Found valid opcode')
            if 1:
                li = GLOBAL_OPCODE_MAP[opcode]
                print ('Index -> %d' % counter )

                if li[1] == True:
                    print ('REQUIRES MODRM BYTE')
                    modrm = b[counter]
                    instruction_bytes += ' '
                    instruction_bytes += "%02x" % b[counter]

                    counter += 1 # we've consumed it now
                    mod,reg,rm = parseMODRM( modrm )

                    if mod == 3:
                        # Verify if opcode needs additional processing to determine correct instruction
                        if type(li[0]) is dict:
                            modifier = li[0][reg]
                            if modifier:
                                implemented = True
                                instruction += modifier
                        else:
                            implemented = True
                            instruction += li[0]

                        if not implemented:
                            break
                        
                        print ('r/m32 operand is direct register')
                        
                        if li[2] == 'mr':
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES[reg]
                        elif li[2] == 'rm':
                            instruction += GLOBAL_REGISTER_NAMES[reg]
                            instruction += ', '
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                        elif li[2] == 'mi':
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                            # Save immidiate values in results
                            instruction += ', 0x'
                            immidiate = ''
                            for x in range(0, 4):
                                instruction_bytes += "%02x" % b[counter]
                                immidiate = "%02x" % b[counter] + immidiate 
                            instruction += immidiate 
                            counter += 4 # Advance counter by immidiate size
                        elif li[2] == 'm':
                            instruction += GLOBAL_REGISTER_NAMES[rm]
                    elif mod == 2:
                        #Uncomment next line when you've implemented this 
                        #implemented = True
                        print ('r/m32 operand is [ reg + disp32 ] -> please implement')
                        # will need to parse the displacement32
                    elif mod == 1:
                        #Uncomment next line when you've implemented this 
                        # implemented = True
                        print ('r/m32 operand is [ reg + disp8 ] -> please implement')
                        # will need to parse the displacement8
                    else:
                        if rm == 5:
                            #Uncomment next line when you've implemented this
                            #implemented = True
                            print ('r/m32 operand is [disp32] -> please implement')
                        elif rm == 4:
                            #Uncomment next line when you've implemented this
                            #implemented = True
                            print ('Indicates SIB byte required -> please implement')
                        else:
                            #Uncomment next line when you've implemented this
                            #implemented = True
                            print ('r/m32 operand is [reg] -> please implement')

                    if implemented == True:
                        print ('Adding to list ' + instruction)
                        outputList[ "%08X" % orig_index ] = instruction_bytes + ' ' + instruction
                    else:
                        outputList[ "%08X" % orig_index ] = '%02x db %02x' % (int(opcode) & 0xff), (int(opcode) & 0xff)
                else:
                    print ('Does not require MODRM - modify to complete the instruction and consume the appropriate bytes')
            #except:
            else:
                outputList[ "%08X" % orig_index ] = 'db %02x' % (int(opcode) & 0xff)
                i = orig_index
        else:
            # TOD0: Fix regex
            outputList[ "%08X" % orig_index ] = '%02x db %02x' % [(int(opcode) & 0xff), (int(opcode) & 0xff)]


    printDisasm (outputList)


def getfile(filename):	
    with open(filename, 'rb') as f:
        a = f.read()
    return a		

def main():
    import sys 
    import argparse 

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", help='Given a binary file it prints the disassembled assembly code.', required=True)
    args = parser.parse_args()

    if args.i:
        binary = getfile(args.i)
        disassemble(binary)
    else:
        print("Please provide a binary file to disassembled and use flag -i.")


if __name__ == '__main__':
    main()

