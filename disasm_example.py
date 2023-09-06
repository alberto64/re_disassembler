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
    0x05 : ['add eax, ', False, 'id'],
    0x50 : ['push eax ', False, 'O'],
    0x51 : ['push ecx ', False, 'O'],
    0x52 : ['push edx ', False, 'O'],
    0x53 : ['push ebx ', False, 'O'],
    0x54 : ['push esp ', False, 'O'],
    0x55 : ['push ebp ', False, 'O'],
    0x56 : ['push esi ', False, 'O'],
    0x57 : ['push edi ', False, 'O'],
    0x58 : ['pop eax ', False, 'O'],
    0x59 : ['pop ecx ', False, 'O'],
    0x5a : ['pop edx ', False, 'O'],
    0x5b : ['pop ebx ', False, 'O'],
    0x5c : ['pop esp ', False, 'O'],
    0x5d : ['pop ebp ', False, 'O'],
    0x5e : ['pop esi ', False, 'O'],
    0x5f : ['pop edi ', False, 'O'],
    0x68 : ['push ', False, 'I'],
    0x81 : [ { 0x0: ['add '], 
               0x4: ['and '] }, True, 'mi'],
    0x89 : ['mov ', True, 'mr'],
    0x8b : ['mov ', True, 'rm'],
    0x8f : [ { 0x0: ['pop '] }, True, 'm'],
    0xb8 : ['mov eax ', False, 'OI'],
    0xb9 : ['mov ecx ', False, 'OI'],
    0xba : ['mov edx ', False, 'OI'],
    0xbb : ['mov ebx ', False, 'OI'],
    0xbc : ['mov esp ', False, 'OI'],
    0xbd : ['mov ebp ', False, 'OI'],
    0xbe : ['mov esi ', False, 'OI'],
    0xbf : ['mov edi ', False, 'OI'],
    0xff : [ { 0x6: ['push '] }, True, 'm']
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

