from analysis.ProcessHelper import readSymbolTable


def test_readSymbolTable():

    symtable = readSymbolTable(
        "/home/vancir/Downloads/coral-qq1b.200205.002/system/system/lib64/libandroidfw.so"
    )

    for symbolName, symbolInformation in symtable.items():
        # print(
        #     symbolInformation.symbolName,
        #     symbolInformation.position,
        #     symbolInformation.addr,
        #     symbolInformation.length,
        #     symbolInformation.hashCode(),
        # )
        pass