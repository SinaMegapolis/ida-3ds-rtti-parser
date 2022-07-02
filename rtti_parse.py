from core.vtable import TypeInfoVtable
from core.common import search, demangle
from core.rtti import BasicClass, SiClass, VmiClass
import time
import logging
from core.common import get_ida_bit_depended_stream

import idc
import idautils
import ida_bytes
import idaapi
import ida_xref
import ida_strlist
import ida_hexrays
import ida_kernwin


idaapi.require('core.binary_stream')
idaapi.require('core.vtable')
idaapi.require('core.consts')
idaapi.require('core.common')
idaapi.require('core.rtti')


logger = logging.getLogger(__name__)


class TiClassKind:
    CLASS_TYPE = '__class_type_info'
    # CLASS_TYPE = '_ZTVN10__cxxabiv117__class_type_infoE'
    # SI_CLASS_TYPE = '_ZTVN10__cxxabiv120__si_class_type_infoE'
    SI_CLASS_TYPE = '__si_class_type_infoE'
    # VMI_CLASS_TYPE = '_ZTVN10__cxxabiv121__vmi_class_type_infoE'
    VMI_CLASS_TYPE = '__vmi_class_type_infoE'


"""
These are symbols, that used to find typeinfos and vtables
"""
symbol_table = {
    TiClassKind.CLASS_TYPE: BasicClass,
    TiClassKind.SI_CLASS_TYPE: SiClass,
    TiClassKind.VMI_CLASS_TYPE: VmiClass
}

typeinfo_counter = 0
vtable_counter = 0
func_counter = 0

def gather_all_rtti():
    rttiaddr = []
    idaapi.cvar.inf.demnames |= idaapi.DEMNAM_GCC3
    for stringIndex in range(ida_strlist.get_strlist_qty()):
        strinfo = ida_strlist.string_info_t()
        if not ida_strlist.get_strlist_item(strinfo, stringIndex):
            logger.error(f'Failed to get string at index: {stringIndex}')
            continue
        name = idc.get_strlit_contents(strinfo.ea)
        mangled_name = '_ZTS' + name.decode('ascii')
        demangled_name = demangle(mangled_name)

        if not demangled_name or not ('N' in mangled_name): #Not a valid demangled name, thus not a RTTI name
            #logger.error(f'failed to demangle name. mangled is: {mangled_name}')
            continue
        #logger.warning(f'demangled name is: {demangled_name}')
        #logger.warning(f'strinfo.ea is: {hex(strinfo.ea)}')

        typeinfoaddr = ida_xref.get_first_dref_to(strinfo.ea) - 4
        #logger.warning(f'typeinfoaddr is: {hex(typeinfoaddr)}')
        typeinfo_vtable_addr = ida_xref.get_first_dref_to(typeinfoaddr)
        #logger.warning(f'typeinfo_vtable_addr is {hex(typeinfo_vtable_addr)}')
        rttiaddr.append(ida_bytes.get_dword(typeinfo_vtable_addr))
    return rttiaddr

def process_class_info(symbol_name):
    global typeinfo_counter, vtable_counter, func_counter

    for typeinfo_ea in gather_all_rtti():
        if typeinfo_ea == idc.BADADDR:
            logger.error(f'cant process class info since the address given is BADADDR')
            continue

        #Check against a bug where the parser would try to parse base classes as if they were inheriting classes
        #The first check is to avoid ExeFS not being parsed
        if symbol_name != '__class_type_info' and not (symbol_name in idc.get_name(ida_bytes.get_dword(typeinfo_ea))): 
            logger.warning(f'Address no processo: {hex(typeinfo_ea)}')
            continue

        logger.warning(f'currently processing address: {hex(typeinfo_ea)}')

        classtype = symbol_table[symbol_name](typeinfo_ea)

        # skip this one, because name hasn't been read.
        if not classtype.read_name():
            logger.error(
                f'Failed to read name of typeinfo. mangled is: {classtype.type_name} at {hex(typeinfo_ea)}'
            )
            continue
        # will get rid of global variables later
        typeinfo_counter += 1

        classtype.read_typeinfo()
        classtype.create_class_struct()

        logger.warning(
            f'Found typeinfo for {classtype.dn_name} at {hex(typeinfo_ea)}')

        # read vtable
        if not classtype.read_vtable():
            logger.error(
                f'Failed to find vtable for {classtype.dn_name}, possibly because this class doesnt have one'
            )
            continue

        vtable_counter += 1
        func_counter += len(classtype.vtable.entries)

        # create struct for vtable
        if classtype.create_vtable_struct():
            # retype functions
            classtype.retype_vtable_functions()
        else:
            logger.error(
                f'vtable struct for {classtype.dn_name} not created !')


def process():
    start_time = time.time()
    logger.setLevel(logging.INFO)
    if not ida_hexrays.init_hexrays_plugin():
        ida_kernwin.warning(f'The RTTI parser cant work properly without the HexRays decompiler, to fix any errors caused by this go to core/common.py and remove any usage of HexRays API')
    for symbol_name in symbol_table:
        addr_ea = search(symbol_name)
        # get start of the string
        addr_ea = ida_bytes.get_item_head(addr_ea)
        
        logger.warning(f'Found {symbol_name} at {hex(addr_ea)}')

        # get only first xref
        typeinfo_ea = next(idautils.XrefsTo(addr_ea, 0), None)
        if not typeinfo_ea:
            logger.error(
                f'No Code refs found for {symbol_name}'
            )
            continue

        logger.warning(f'typeinfo address is: {hex(typeinfo_ea.frm-4)}')
        typeinfo_vtable_addr = next(reversed(list(idautils.XrefsTo(typeinfo_ea.frm-4, 0)))).frm - 4
        logger.warning(f'typeinfo_vtable_addr proper is {hex(typeinfo_vtable_addr)}')
        typeinfo_vtable = TypeInfoVtable(
            symbol_name, demangle(symbol_name), typeinfo_vtable_addr)

        typeinfo_vtable.read()
        # using typeinfo offset to search for other typeinfos
        process_class_info(symbol_name)

    logger.warning(f'Completed in {round(time.time() - start_time, 2)}s')
    logger.warning(f'Total new classes: {typeinfo_counter}\n\
Total vtables: {vtable_counter}\n\
Total reanmed funcitons {func_counter}')


def main():
    process()


if __name__ == '__main__':
    # breakpoint()
    main()
