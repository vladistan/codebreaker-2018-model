#include <stdio.h>
#include <stdlib.h>
#include "crack.h"

const char *CIDs[10] = {
        "bb52677e489ba0bdf9c55e092e1b9fb98c3d3966fa7126ccc7b3a9527f8d0f54",
        "06aeee4fcd565a4b527a20274a352a78e83b81a3a0f35509df144a6c1450270d",
        "56ea3b3d00df1ee0592dd4870317020ebe02a232f0ae37fff31733e1f918e571",
        "ea1e03022cc3a0378ef9056b5346befdf735f56d56509dcb3d1ea03191803815",
        "51b9326cad4f65e656ea6251937e9715643332adc5b811093faedf8d01fc10b8",
        "472d7834f4dd0ab70b631f58a923af3c8db18913491e03a6679bbe4ff8e658eb",
        "b784c8325a15d7b7d62d4ded79b86b08fd0cbc8ed0099fee200b55ef8791eae6",

        "047b5f5a6dd57f44ddc76f57bffeea7a06cd8d8dea2fdc6fc8ea5f47e4b4c117",
        "3431b241b4f09c76c4ae404919f09cad650fe5f83e4a51ed695464941680f680",
        "44d60efee6f4a5922742b51cc6b4345f083acb55b3b14d51256b19b778ffcfdb"
};

int main(int argc, char**argv) {
    if ( argc < 3 ) {
        printf("Usage: %s O3 S2\n", argv[0]);
        return 3;
    }
    int o3 = atoi(argv[1]);
    int slice2 = atoi(argv[2]);

    int o4s = crk_slice_start(slice2);
    int o4e = crk_slice_end(slice2);

    puts("Probing:");

    return cid_crack(CIDs, 10, o3, o3, o4s, o4e, 0, 999999);
}
