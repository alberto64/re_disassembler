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


 
# Key is the opcode
# value is a list of useful information
GLOBAL_OPCODE_MAP = {
    # Opcode: ['Instruction', 'ModRM?', 'Encoding Type']
    0x01 : ['add ', True, 'mr'], 
    0x03 : ['add ', True, 'rm'],
    0x05 : ['add eax, ', False, 'id'],
    0x09 : ['or ', True, 'mr'],
    0x0B : ['or ', True, 'rm'],
    0x0d : ['or eax ', False, 'id'],
    0x0f : [ { 0x84: ['jz ', False, 'cd'], # i dword 32 byte offset
               0x85: ['jnz ', False, 'cd'], # i dword 32 byte offset
               0xAE: [{ 0x7: ['clflush ', True, 'm'] }, True, 'mult'] }, False, 'mult'], # 11 mod is illegal
    0x21 : ['and ', True, 'mr'],
    0x23 : ['and ', True, 'rm'],
    0x25 : ['and eax ', False, 'id'],
    0x29 : ['sub ', True, 'mr'],
    0x2B : ['sub ', True, 'rm'],
    0x2d : ['sub eax ', False, 'id'],
    0x31 : ['xor ', True, 'mr'],
    0x33 : ['xor ', True, 'rm'],
    0x35 : ['xor eax', False, 'id'],
    0x39 : ['cmp ', True, 'mr'],
    0x3B : ['cmp ', True, 'rm'],
    0x3D : ['cmp eax, ', False, 'id'],
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
    0x68 : ['push ', False, 'id'],
    0x6A : ['push ', False, 'ib'], 
    0x74 : ['jz ', False, 'cb'], # ib 8 bit dist
    0x75 : ['jnz ', False, 'cb'], # id 8 bit dist
    0x81 : [ { 0x0: ['add ', True, 'mid'],
               0x1: ['or ', True, 'mid'], 
               0x4: ['and ', True, 'mid'],
               0x5: ['sub ', True, 'mid'],
               0x6: ['xor ', True, 'mid'],
               0x7: ['cmp ', True, 'mid']  }, True, 'mult'],
    0x85 : ['test ', True, 'mr'],
    0x89 : ['mov ', True, 'mr'],
    0x8b : ['mov ', True, 'rm'],
    0x8d : ['lea ', True, 'rm'], # 11 mod is illegal
    0x8f : [ { 0x0: ['pop ', True, 'm'] }, True, 'mult'],
    0x90 : ['nop ', False, 'zo'],
    0xa1 : ['mov eax ', False, 'fd'], # treat as oi 32
    0xa5 : ['movsd ', False, 'zo'], 
    0xa3 : [['mov ', 'eax '], False, 'td'], # treat as oi 32
    0xa9 : ['test eax, ', False, 'id'],
    0xb8 : ['mov eax ', False, 'oid'],
    0xb9 : ['mov ecx ', False, 'oid'],
    0xba : ['mov edx ', False, 'oid'],
    0xbb : ['mov ebx ', False, 'oid'],
    0xbc : ['mov esp ', False, 'oid'],
    0xbd : ['mov ebp ', False, 'oid'],
    0xbe : ['mov esi ', False, 'oid'],
    0xbf : ['mov edi ', False, 'oid'], 
    0xc2 : ['retn ', False, 'i16'],  # i 16
    0xc3 : ['retn ', False, 'zo'],
    0xc7 : [ { 0x0: ['mov ', True, 'mid'] }, True, 'mult'],
    0xca : ['retf ', False, 'i16'], # i 16
    0xcb : ['retf ', False, 'zo'],
    0xe8 : ['call ', False, 'cd'], # id 32 byte dist
    0xe9 : ['jmp ', False, 'cd'], # rel 32 byte offset
    0xeb : ['jmp ', False, 'cb'], # rel 8 byte offset
    0xf2 : [ { 0xa7: ['repne cmpsd ', False, 'zo'] }, False, 'mult'],
    0xf7 : [ { 0x0: ['test ', True, 'mid'], 
               0x2: ['not ', True, 'm'], 
               0x7: ['idiv', True, 'm'] }, True, 'mult'], 
    0xff : [ { 0x0: ['inc ', True, 'm'],
               0x1: ['dec ', True, 'm'],
               0x2: ['call ', True, 'm'],
               0x4: ['jmp ', True, 'm'], # Branch special case
               0x6: ['push ', True, 'm'] }, True, 'mult']
}

GLOBAL_REGISTER_NAMES = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi' ]

class InstructionDefinitonError(Exception):
    
    def __init__(self, value):
        self.value = value
 
    def __str__(self):
        return(repr(self.value))

def isValidOpcode(opcode):
    if opcode in GLOBAL_OPCODE_MAP.keys():
        return True
    return False

def parseSIB(sib):
    #scale = (modrm & 0xC0) >> 6
    #index = (modrm & 0x38) >> 3
    #base = (modrm & 0x07)
    return parseMODRM(sib)

def parseMODRM(modrm):
    #mod = (modrm & 0xC0) >> 6
    #reg = (modrm & 0x38) >> 3
    #rm  = (modrm & 0x07)

    mod = (modrm & 0b11000000) >> 6
    reg = (modrm & 0b00111000) >> 3
    rm  = (modrm & 0b00000111)
    return (mod,reg,rm)

def parse8disp(counter, b):
    if counter >= len(b):
        raise InstructionDefinitonError("Ran out of bytes to continue opcode instruction")
    instruction_bytes = "%02x" % b[counter]
    # TODO Process 8-BIT signed value
    immidiate = "%02x" % b[counter] 
    return instruction_bytes, immidiate, counter + 1

def parse32disp(counter, b):
    return parseXimm(32, counter, b)

def parse8imm(counter, b):
    return parseXimm(8, counter, b)

def parse16imm(counter, b):
    return parseXimm(16, counter, b)

def parse32imm(counter, b):
    return parseXimm(32, counter, b)

def parseXimm(X, counter, b):
    immidiate_bytes = ''
    immidiate = ''
    byte_count = X // 8
    for x in range(0, byte_count):
        if counter >= len(b):
            raise InstructionDefinitonError("Ran out of bytes to continue opcode instruction")
        immidiate_bytes += "%02x" % b[counter]
        immidiate = "%02x" % b[counter] + immidiate 
        counter += 1 # Advance counter by immidiate size
    return immidiate_bytes, immidiate, counter

def processMODRM(opcode, li, counter, b):

    # Parse MODRM Byte to get individual bits
    if counter >= len(b):
        raise InstructionDefinitonError("Ran out of bytes to continue opcode instruction")
    modrm = b[counter]
    instruction_bytes = "%02x" % b[counter]
    counter += 1 # we've consumed it now
    mod, reg, rm = parseMODRM( modrm )

    # Verify if opcode needs additional processing to determine correct instruction
    if li[2] == 'mult':
        if reg in li[0].keys():
            li = li[0][reg]
        else:
            raise InstructionDefinitonError("Illegal Opcode operand value.")                    
    instruction = li[0]

    # Addressing mode is 11
    if mod == 3:
        print ('r/m32 operand is direct register')

        # Check special cases
        if opcode == 0x8d:
            raise InstructionDefinitonError("Illegal lea instruction addressing mode")
        if opcode == 0x0f:
            raise InstructionDefinitonError("Illegal clflush instruction addressing mode")      

        if li[2] == 'mr': # Mem/Reg Reg
            instruction += GLOBAL_REGISTER_NAMES[rm]
            instruction += ', '
            instruction += GLOBAL_REGISTER_NAMES[reg]

        elif li[2] == 'rm': # Reg Mem/Reg
            instruction += GLOBAL_REGISTER_NAMES[reg]
            instruction += ', '
            instruction += GLOBAL_REGISTER_NAMES[rm]

        elif li[2] == 'mib': # Mem/Reg imm8
            instruction += GLOBAL_REGISTER_NAMES[rm]
            # Save immidiate values in results
            imidiateBytes, immidiate, counter = parse8imm(counter, b)
            instruction_bytes += imidiateBytes
            instruction += ', 0x' + immidiate 

        elif li[2] == 'mid': # Mem/Reg imm32
            instruction += GLOBAL_REGISTER_NAMES[rm]
            # Save immidiate values in results
            imidiateBytes, immidiate, counter = parse32imm(counter, b)
            instruction_bytes += imidiateBytes
            instruction += ', 0x' + immidiate 

        elif li[2] == 'm': # Mem/Reg
            instruction += GLOBAL_REGISTER_NAMES[rm]
    
    # Address is a SIB
    elif rm == 4:
        print ('Indicates SIB byte required')
        # Parse SIB Byte to get individual bits
        if counter >= len(b):
            raise InstructionDefinitonError("Ran out of bytes to continue opcode instruction")
        sib = b[counter]
        instruction_bytes += "%02x" % b[counter]
        counter += 1 # we've consumed it now
        ss, idx, base = parseSIB( sib )  
    
        # Addressing mode is 10
        if mod == 2:
            print ('sib operand is [ reg*ss + base + disp32 ]')
            dispBytes, disp, counter = parse32disp(counter, b)
            instruction_bytes += dispBytes

            if li[2] == 'mr': # Mem/Reg Reg
                # Save immidiate values in results
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '
                instruction += GLOBAL_REGISTER_NAMES[reg]

            elif li[2] == 'rm': # Reg Mem/Reg
                instruction += GLOBAL_REGISTER_NAMES[reg]
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '

            elif li[2] == 'mib': # Mem/Reg imm8
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '
                
                # Save immidiate values in results
                imidiateBytes, immidiate, counter = parse8imm(counter, b)
                instruction_bytes += imidiateBytes
                instruction += ', 0x' + immidiate 

            elif li[2] == 'mid': # Mem/Reg imm32
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '

                # Save immidiate values in results
                imidiateBytes, immidiate, counter = parse32imm(counter, b)
                instruction_bytes += imidiateBytes
                instruction += ', 0x' + immidiate 

            elif li[2] == 'm': # Mem/Reg
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '

        # Addressing mode is 01
        elif mod == 1:
            print ('sib operand is [ reg*ss + base + disp8 ]')
            dispBytes, disp, counter = parse8disp(counter, b)
            instruction_bytes += dispBytes

            if li[2] == 'mr': # Mem/Reg Reg
                # Save immidiate values in results
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '
                instruction += GLOBAL_REGISTER_NAMES[reg]

            elif li[2] == 'rm': # Reg Mem/Reg
                instruction += GLOBAL_REGISTER_NAMES[reg]
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '

            elif li[2] == 'mib': # Mem/Reg imm8
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '
                
                # Save immidiate values in results
                imidiateBytes, immidiate, counter = parse8imm(counter, b)
                instruction_bytes += imidiateBytes
                instruction += ', 0x' + immidiate 

            elif li[2] == 'mid': # Mem/Reg imm32
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '

                # Save immidiate values in results
                imidiateBytes, immidiate, counter = parse32imm(counter, b)
                instruction_bytes += imidiateBytes
                instruction += ', 0x' + immidiate 

            elif li[2] == 'm': # Mem/Reg
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' + 0x' + disp + ' ], '

        # Addressing mode is 00
        else:
            # No base register
            if base == 5:
                print ('sib operand is [ reg*ss + disp32 ]')  
                dispBytes, disp, counter = parse32disp(counter, b)
                instruction_bytes += dispBytes

                if li[2] == 'mr': # Mem/Reg Reg
                    # Save immidiate values in results
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + 0x' + disp + ' ], '
                    instruction += GLOBAL_REGISTER_NAMES[reg]

                elif li[2] == 'rm': # Reg Mem/Reg
                    instruction += GLOBAL_REGISTER_NAMES[reg]
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + 0x' + disp + ' ], '

                elif li[2] == 'mib': # Mem/Reg imm8
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + 0x' + disp + ' ], '
                    
                    # Save immidiate values in results
                    imidiateBytes, immidiate, counter = parse8imm(counter, b)
                    instruction_bytes += imidiateBytes
                    instruction += ', 0x' + immidiate 

                elif li[2] == 'mid': # Mem/Reg imm32
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + 0x' + disp + ' ], '

                    # Save immidiate values in results
                    imidiateBytes, immidiate, counter = parse32imm(counter, b)
                    instruction_bytes += imidiateBytes
                    instruction += ', 0x' + immidiate 

                elif li[2] == 'm': # Mem/Reg
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + 0x' + disp + ' ], '
                
            # No displacement register
            else:
                print ('sib operand is [ reg*ss + base ]')
                if li[2] == 'mr': # Mem/Reg Reg
                    # Save immidiate values in results
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' ], '
                    instruction += GLOBAL_REGISTER_NAMES[reg]

                elif li[2] == 'rm': # Reg Mem/Reg
                    instruction += GLOBAL_REGISTER_NAMES[reg]
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' ], '

                elif li[2] == 'mib': # Mem/Reg imm8
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' ], '
                    
                    # Save immidiate values in results
                    imidiateBytes, immidiate, counter = parse8imm(counter, b)
                    instruction_bytes += imidiateBytes
                    instruction += ', 0x' + immidiate 

                elif li[2] == 'mid': # Mem/Reg imm32
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' ], '

                    # Save immidiate values in results
                    imidiateBytes, immidiate, counter = parse32imm(counter, b)
                    instruction_bytes += imidiateBytes
                    instruction += ', 0x' + immidiate 

                elif li[2] == 'm': # Mem/Reg
                    instruction += '[ ' + GLOBAL_REGISTER_NAMES[idx] + '*' + str(2**ss) + ' + ' + GLOBAL_REGISTER_NAMES[base] + ' ], '
 


    # Addressing mode is 10
    elif mod == 2:
        print ('r/m32 operand is [ reg + disp32 ]')
        # will need to parse the displacement32 
        dispBytes, disp, counter = parse32disp(counter, b)
        instruction_bytes += dispBytes

        if li[2] == 'mr': # Mem/Reg Reg
            # Save immidiate values in results
            instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + disp + ' ], '
            instruction += GLOBAL_REGISTER_NAMES[reg]

        elif li[2] == 'rm': # Reg Mem/Reg
            instruction += GLOBAL_REGISTER_NAMES[reg]
            instruction += ', [ ' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + disp + ' ]'

        elif li[2] == 'mib': # Mem/Reg imm8
            instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + disp + ' ]'
            
            # Save immidiate values in results
            imidiateBytes, immidiate, counter = parse8imm(counter, b)
            instruction_bytes += imidiateBytes
            instruction += ', 0x' + immidiate 

        elif li[2] == 'mid': # Mem/Reg imm32
            instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + disp + ' ]'

            # Save immidiate values in results
            imidiateBytes, immidiate, counter = parse32imm(counter, b)
            instruction_bytes += imidiateBytes
            instruction += ', 0x' + immidiate 

        elif li[2] == 'm': # Mem/Reg
            instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + '0x' + disp + ' ]'
    
    # Addressing mode is 01
    elif mod == 1:
        print ('r/m32 operand is [ reg + disp8 ]')
        dispBytes, disp, counter = parse8disp(counter, b)
        instruction_bytes += dispBytes

        if li[2] == 'mr': # Mem/Reg Reg
            instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + disp + ' ], '
            instruction += GLOBAL_REGISTER_NAMES[reg]

        elif li[2] == 'rm': # Reg Mem/Reg
            instruction += GLOBAL_REGISTER_NAMES[reg]
            instruction += ', [ ' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + disp + ' ]'

        elif li[2] == 'mib': # Mem/Reg imm8
            instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + disp + ' ]'
            
            # Save immidiate values in results
            imidiateBytes, immidiate, counter = parse8imm(counter, b)
            instruction_bytes += imidiateBytes
            instruction += ', 0x' + immidiate 

        elif li[2] == 'mid': # Mem/Reg imm32
            instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + disp + ' ]'

            # Save immidiate values in results
            imidiateBytes, immidiate, counter = parse32imm(counter, b)
            instruction_bytes += imidiateBytes
            instruction += ', 0x' + immidiate 

        elif li[2] == 'm': # Mem/Reg
            instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' + 0x' + disp + ' ]'  
    
    # Addressing mode is 00
    else:
        # Address is a displacement32
        if rm == 5:
            print ('r/m32 operand is [disp32]')
            dispBytes, disp, counter = parse32disp(counter, b)
            instruction_bytes += dispBytes
            if li[2] == 'mr': # Mem/Reg Reg
                instruction += '[ 0x' + disp + ' ]'
                instruction += ', '
                instruction += GLOBAL_REGISTER_NAMES[reg]

            elif li[2] == 'rm': # Reg Mem/Reg
                instruction += GLOBAL_REGISTER_NAMES[reg]
                instruction += ', '
                instruction += '[ 0x' + disp + ' ]'

            elif li[2] == 'mib': # Mem/Reg imm8
                instruction += '[ 0x' + disp + ' ]'
                
                # Save immidiate values in results
                imidiateBytes, immidiate, counter = parse8imm(counter, b)
                instruction_bytes += imidiateBytes
                instruction += ', 0x' + immidiate 
                
            elif li[2] == 'mid': # Mem/Reg imm32
                instruction += '[ 0x' + disp + ' ]'

                # Save immidiate values in results
                imidiateBytes, immidiate, counter = parse32imm(counter, b)
                instruction_bytes += imidiateBytes
                instruction += ', 0x' + immidiate 

            elif li[2] == 'm': # Mem/Reg
                instruction += '[ 0x' + disp + ' ]'
        # Address is memory
        else:
            print ('r/m32 operand is [reg] -> please implement')
            if li[2] == 'mr': # Mem/Reg Reg
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' ], '
                instruction += GLOBAL_REGISTER_NAMES[reg]

            elif li[2] == 'rm': # Reg Mem/Reg
                instruction += GLOBAL_REGISTER_NAMES[reg]
                instruction += ', [ ' + GLOBAL_REGISTER_NAMES[rm] + ' ]'

            elif li[2] == 'mib': # Mem/Reg imm8
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' ]'
                
                # Save immidiate values in results
                imidiateBytes, immidiate, counter = parse8imm(counter, b)
                instruction_bytes += imidiateBytes
                instruction += ', 0x' + immidiate 
                
            elif li[2] == 'mid': # Mem/Reg imm32
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' ]'

                # Save immidiate values in results
                imidiateBytes, immidiate, counter = parse32imm(counter, b)
                instruction_bytes += imidiateBytes
                instruction += ', 0x' + immidiate 

            elif li[2] == 'm': # Mem/Reg
                instruction += '[ ' + GLOBAL_REGISTER_NAMES[rm] + ' ]'
    return counter, instruction_bytes, instruction

def printDisasm(outputList, labelList):
    labeladdrs = labelList.keys()
    print("Complete dissasembled binary:\n")
    for addr in sorted(outputList):
        if addr in labeladdrs:
            print(labelList[addr])
        print( '%s: %s' % (addr, outputList[addr]) )

def disassemble(b):

    # Output list with decoded assembly
    outputList = {}

    # List that will contain generated labels.
    labelList = {}

    # Global byte counter
    counter = 0

    # Iterate byte by byte
    while counter < len(b):

        opcode = b[counter]	# current byte to work on
        instruction_bytes = "%02x" % b[counter]
        instruction = ''
        orig_index = counter
        counter += 1

        # Check if byte exists as an opcode
        if isValidOpcode( opcode ):
            print ('Found valid opcode')
            li = GLOBAL_OPCODE_MAP[opcode]
            print ("Index -> %08X" % orig_index)

            try:
                # Requires MODRM processing
                if li[1] == True:
                    print ('REQUIRES MODRM BYTE')
                    counter, modrm_bytes, modrm = processMODRM(opcode, li, counter, b)
                    instruction_bytes += modrm_bytes
                    instruction += modrm
                    print ('Adding to list: ' + instruction)
                    outputList[ "%08X" % orig_index ] = "{:<16} {:<16}".format(instruction_bytes, instruction)
                
                # Doesn't require MODRM processing to get correct instruction 
                else:
                    print ('Does not require MODRM')
                    
                    # Verify if opcode needs additional processing to determine correct instruction
                    if li[2] == 'mult':
                        if counter >= len(b):
                            raise InstructionDefinitonError("Ran out of bytes to continue opcode instruction")
                        operand = b[counter]
                        instruction_bytes += "%02x" % b[counter]
                        counter += 1 # we've consumed it now
                        if operand in li[0].keys():
                            li = li[0][operand]
                        else:
                            raise InstructionDefinitonError("Illegal Opcode operand byte")

                    # No extra byte cases
                    if li[2] == 'zo' or li[2] == 'o':
                        instruction += li[0]
                    
                    # Special case that requires a MODRM operation to finish
                    elif li[2] == 'mult':
                        print ('REQUIRES MODRM BYTE for completion')
                        counter, modrm_bytes, modrm = processMODRM(opcode, li, counter, b)
                        instruction_bytes += modrm_bytes
                        instruction += modrm                    
                    # 1 byte cases
                    elif li[2] == 'ib': # imm8
                        instruction += li[0]
                        
                        # Save immidiate values in results
                        imidiateBytes, immidiate, counter = parse8imm(counter, b)
                        instruction_bytes += imidiateBytes
                        instruction += '0x' + immidiate 

                    elif li[2] == 'cb': # Branch instruction
                        instruction += li[0]

                        # Calculate offset
                        # TODO take into account negative values
                        dispBytes, disp, counter = parse8disp(counter, b)
                        instruction_bytes += dispBytes
                        offset = int(int(disp, 16)) + counter
                        label = 'offset_%08xh' % (int(offset) & 0xff)
                        instruction += label
                        labelList[ "%08X" % (int(offset) & 0xff) ] = label + ':'
                    
                    # 2 byte cases
                    elif li[2] == 'i16':  # imm16
                        instruction += li[0]

                        # Save immidiate values in results
                        imidiateBytes, immidiate, counter = parse16imm(counter, b)
                        instruction_bytes += imidiateBytes
                        instruction += '0x' + immidiate 

                    # 4 byte cases
                    elif li[2] == 'id' or li[2] == 'oid': # imm32
                        instruction += li[0]

                        # Save immidiate values in results
                        imidiateBytes, immidiate, counter = parse32imm(counter, b)
                        instruction_bytes += imidiateBytes
                        instruction += '0x' + immidiate 

                    elif li[2] == 'fd': # r32, imm32
                        instruction += li[0]

                        # Save immidiate values in results
                        imidiateBytes, immidiate, counter = parse32imm(counter, b)
                        instruction_bytes += imidiateBytes
                        instruction += ', 0x' + immidiate 

                    elif li[2] == 'td': # imm32, r32
                        instruction += li[0][0]

                        # Save immidiate values in results
                        imidiateBytes, immidiate, counter = parse16imm(counter, b)
                        instruction_bytes += imidiateBytes
                        instruction += '0x' + immidiate 
                        
                        instruction += ', ' + li[0][1]

                    # Branch instructions
                    elif li[2] == 'cd': 
                        instruction += li[0]

                        # Calculate offset
                        imidiateBytes, immidiate, counter = parse32imm(counter, b)
                        instruction_bytes += imidiateBytes
                        offset = int(int(immidiate, 16)) + counter
                        label = 'offset_%08xh' % (int(offset) & 0xff)
                        instruction += label
                        labelList[ "%08X" % (int(offset) & 0xff) ] = label  + ':'

                    print ('Adding to list: ' + instruction)
                    outputList[ "%08X" % orig_index ] = "{:<16} {:<16}".format(instruction_bytes, instruction)
            
            # Was unable to fully process an instruction
            except InstructionDefinitonError as err:
                print(err.value)
                instruction_bytes = '%02x' % (int(opcode) & 0xff)
                instruction = 'db 0x%02x' % (int(opcode) & 0xff)
                outputList[ "%08X" % orig_index ] = "{:<16} {:<16}".format(instruction_bytes, instruction)
                counter = orig_index + 1
                continue

        # Invalid opcode
        else:
            print ('Invalid opcode')
            print ("Index -> %08X" % orig_index)
            instruction_bytes = '%02x' % (int(opcode) & 0xff)
            instruction = 'db 0x%02x' % (int(opcode) & 0xff)
            outputList[ "%08X" % orig_index ] = "{:<16} {:<16}".format(instruction_bytes, instruction)

    printDisasm (outputList, labelList)


def getfile(filename):	
    with open(filename, 'rb') as f:
        a = f.read()
    return a		

def main():
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

