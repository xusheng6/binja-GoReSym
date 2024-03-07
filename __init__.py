from binaryninja import *
import json


def add_functions(bv, functions):
    if functions is None:
        return

    for func in functions:
        try:
            start = int(func['Start'])
            name = func['FullName']
            if bv.get_function_at(start) is None:
                bv.create_user_function(start)

            sym = Symbol(SymbolType.FunctionSymbol, start, name, name, name)
            bv.define_user_symbol(sym)
        except:
            pass


def apply_goresym_info(bv: BinaryView):
    file = interaction.get_open_filename_input('Select GoReSym output file')
    if file is None:
        return

    try:
        data = json.loads(open(file, 'rb').read())
    except:
        log_warn('fail to load file %s as json' % file)
        return

    bv.begin_undo_actions()
    if 'UserFunction' in data:
        add_functions(bv, data['UserFunctions'])
    if 'StdFunctions' in data:
        add_functions(bv, data['StdFunctions'])
    bv.commit_undo_actions()

    log_info("GoReSym info successfully applied")


PluginCommand.register("Add GoReSym Info", "Add GoReSym Info", apply_goresym_info)
