from analyzer_ast import *
import json


class AstParser:

    def __init__(self):
        self.type_string = ""

    def parse(self, slice_file):
        slice = json.load(slice_file)
        if "ast_type" in slice:
            self.type_string = "ast_type"
        else:
            self.type_string = "_type"
        return self.recursive(slice, [])

    def recursive(self, slice, slice_items):
        if type(slice) == type(dict()):
            if slice[self.type_string] == "Assign":
                arg1 = self.recursive(slice["targets"][0], [])
                arg2 = self.recursive(slice["value"], [])
                slice_items.append(Assign(arg1[0], arg2[0]))
            elif slice[self.type_string] == "Name":
                slice_items.append(VarExpr(slice["id"]))
            elif slice[self.type_string] == "Num":
                slice_items.append(NumExpr(slice["n"]))
            elif slice[self.type_string] == "Call":
                # args, func
                # missing attribute!!!
                args = []
                for arg in slice["args"]:
                    args.extend(self.recursive(arg, []))
                print("args {}".format(args))
                slice_items.append(FuncCall(args, Func(slice["func"]["id"])))
            elif slice[self.type_string] == "Expr":
                self.recursive(slice["value"], slice_items)
            else:
                for key, value in slice.items():

                    if type(value) == type(list()):
                        print("list key:{}, value:{}\n".format(key, value))
                        for value_list in value:

                            self.recursive(value_list, slice_items)

                    elif type(value) == type(str()) or type(value) == type(int()):
                        print("string key:{}, value:{}\n".format(key, value))


        return slice_items

    #def create_node(self, ):