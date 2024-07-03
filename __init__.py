from binaryninja import *
import json

def add_component(bv, func_name, pkg_name):
    functions = bv.get_functions_by_name(func_name)
    if functions:
        func = functions[0]
    else:
        return
    
    component = bv.get_component_by_path(pkg_name)
    if not component:
        component = bv.create_component(pkg_name)

    component.add_function(func)



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
            pkg_name = func['PackageName'].replace('/', '_')
            add_component(bv ,name, pkg_name)
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
    if 'UserFunctions' in data:
        add_functions(bv, data['UserFunctions'])
    if 'StdFunctions' in data:
        add_functions(bv, data['StdFunctions'])
    bv.commit_undo_actions()

    log_info("GoReSym info successfully applied")


PluginCommand.register("Add GoReSym Info", "Add GoReSym Info", apply_goresym_info)
