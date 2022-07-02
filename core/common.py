import logging
import re

from collections import namedtuple

import ida_bytes
import ida_typeinf
import idc
import ida_segment
import ida_name
import idaapi
import ida_hexrays
import ida_funcs
import ida_ida

from core.binary_stream import Ida64BinaryStream, Ida32BinaryStream, IdaBinaryStreamBase
from core.consts import BIT64_MODE, BAD_RET

logger = logging.getLogger(__name__)


class FunctionSignature:
    """
    :param return type:     Return type of function
    :param call_convention: Calling convention used in function
    :param func_name:       Mangled function name
    :param func_args:       Array of type of function arguments

    :ivar ret:              Return type of function
    :ivar conv:             Calling convention used in function
    :ivar func_name:        Mangled function name
    :ivar args:             Array of type of function arguments
    """

    def __init__(self, return_type, call_convention, func_name, func_args):
        self.ret = return_type
        self.conv = call_convention
        self.func_name = func_name
        self.args = func_args
        

    def make_sig(self):
        if len(self.args) == 1:
            return f'{self.ret} {self.conv} {self.func_name}({", ".join(self.args)});'
        else:
            if len(self.args) > 1:
                return f'{self.ret} {self.conv} {self.func_name}({", ".join(self.args)};'


#func_sig_pattern = re.compile(r'(\w+) (__\w+)(?:\()(\w.*)(?:\))')
func_sig_pattern = re.compile(r'(\(.*\))')


def string2hex(string, encoding='ascii'):
    """
    String to hex string with space seperation for each byte. Ex: '54 64 0A'
    """
    return bytearray(string, encoding=encoding).hex(' ')


def prepare_data_for_search(data):
    if isinstance(data, str):
        hexstr = string2hex(data)
    elif isinstance(data, bytearray) or isinstance(data, bytes):
        hexstr = data.hex(' ')
    else:
        raise Exception(f'Unsupported type of data {type(data)}')

    return hexstr


def search_75(start_ea, data, search_flags):
    hexstr = prepare_data_for_search(data)
    
    return idc.find_binary(start_ea, search_flags, hexstr)
    
    

def search(data, start_ea=None, end_ea=None, search_flags=None) -> int:
    """
    Search data throughout idb. 

    Currently only str and bytes/bytearray types are supported!

    :param data:            data to be converted to ida_bytes.compiled_binpat_vec_t obj
    :param start_ea:        Address to start searching from
    :param end_ea:          End address
    :param search_flags:    Search flags to be passed to ida_bytes.bin_search. Default is idc.SEARCH_DOWN
    :rval:                  Address where pattern has been found as int. Be carefull, check for idc.BADADDR
    """

    if start_ea is None:
        start_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    if end_ea is None:
        end_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    if search_flags is None:
        search_flags = idc.SEARCH_DOWN

    if idaapi.IDA_SDK_VERSION <= 750:
        return search_75(start_ea, data, search_flags)
    
    pattern_obj = ida_bytes.compiled_binpat_vec_t()

    hexstr = prepare_data_for_search(data)
    logger.debug(f'Searching {data} as hexstr {hexstr}')

    ida_bytes.parse_binpat_str(pattern_obj, 0, hexstr, 16)

    return ida_bytes.bin_search(start_ea, end_ea, pattern_obj, search_flags)


def check_compiler_support():
    """
    Check if compiler is supported.

    Currently only GNU C++ is supported
    """
    return ida_typeinf.is_gcc32() or ida_typeinf.is_gcc64()


def is_in_text_segment(ea):
    #text_segment = ida_segment.get_segm_by_name('.text')
    #if not text_segment:
    #    raise Exception(
    #        'No text segment found thus cannot determine if address is in range of executable segment.')
    segment = ida_segment.getseg(ea)
    return ida_segment.get_segm_class(segment) == "CODE"


def get_ida_bit_depended_stream(start_ea) -> IdaBinaryStreamBase:
    if BIT64_MODE:
        return Ida64BinaryStream(start_ea)
    else:
        return Ida32BinaryStream(start_ea)


def demangle(mangled_name):
    return ida_name.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_LONG_DEMNAMES))


def get_function_name(ea):
    return idaapi.get_func_name(ea)


def is_vtable_entry(pointer):
    return is_in_text_segment(pointer)


def simplify_demangled_name(name):
    """
    Removes everything before :: and everything inside <>.
    Ex:
    Base::SomeClass::ClassTemplate<int,double,char> --> ClassTemplate
    """
    return re.sub('`|<(?<=<).*(?=>)>|.*::', '', name)


def get_function_signature(func_ea) -> FunctionSignature:
    failureinfo = ida_hexrays.hexrays_failure_t()
    #logger.warning(f'attempting to decompile address: {hex(func_ea)}')
    cfunc = ida_hexrays.decompile(func_ea, failureinfo, ida_hexrays.DECOMP_WARNINGS|ida_hexrays.DECOMP_NO_WAIT)
    if not cfunc:
        logger.warning(f'error during decompilation: {failureinfo.desc()}')
        return
    #the function prototype given by cfunc_t.print_dcl() has a weird encoding, possibly a Hexrays issue
    #to fix the formatting and make it suitable for type changing all of the extra characters is removed by the parser
    signature = cfunc.print_dcl().replace('\x02', '').replace('\x01','').replace('\x17','').replace('\t','')
    logger.warning(f'func: {signature}')

    #signature = idc.get_func_name(func_ea)
    if not signature:
        logger.error(
            f'idc.get_type failed at {func_ea:X}'
        )
        return None
        
    parsed_sig = re.search(func_sig_pattern, signature)
    if not parsed_sig:
        logger.error(f'Failed to run re.match for sig: {signature}')
        return None

    return FunctionSignature(
        'void',            # return type (chosen at random since most virtual functions will have no return anyway. and the rest can be fixed manually)
        '__fastcall',            # calling convention
        idc.get_name(func_ea),
        parsed_sig.group(1).split(', ')  # arguments
    )

def make_class_symbol_name(func_ea, typenames):
    """
    Mangles name for class
    :param func_ea:     Function address
    :param typenames:   List of names which will be mangled
    """
    ret = '_ZN'
    
    sig = get_function_signature(func_ea)
    
    for typename in typenames:
        ret += str(len(typename))
        ret += typename

    ret += 'E'
     
    if sig and len(sig.args) == 0:
        ret += 'v'
        
    return ret
        

def make_class_method(func_ea, typename):
    sig = get_function_signature(func_ea)
    if not sig:
        logger.error(
            f'Failed to get function signature. skipping {hex(func_ea)}'
        )
        return None

    # change calling convention
    sig.conv = '__thiscall'
    # set class object as first argument
    sig.args[0] = typename + '*'
    # it's better to rename function.
    # There are cases, when function name contains _ZN.
    # Do I need to skip them ?
    sig.name = f'sub_{hex(func_ea)[2:]}'

    logger.warning(f'attempting to set type at {hex(func_ea)} as {sig.make_sig()}')
    ret = idc.SetType(func_ea, sig.make_sig())
    if ret:
        logger.warning(
            f'New function signature for {hex(func_ea)} is {sig.make_sig()}')
    else:
        logger.error(
            f'Failed to set function type for {sig.name} at {hex(func_ea)}'
        )


def create_find_struct(name):
    sid = idc.get_struc_id(name)
    # if not, then create it
    if sid != BAD_RET:
        return sid

    # ok, it doesn't exists, so we'll create it
    sid = idc.add_struc(-1, name, None)

    return sid if sid != BAD_RET else None
