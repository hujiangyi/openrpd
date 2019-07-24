#!/bin/bash
cat ./001-configure-patch-part1.patch
echo $'+libev_configure_command = ["/bin/sh", abspath('\'libev/configure\'$'), "--host '$1$'", '\'$'> configure-output.txt'\'']'
echo $'+ares_configure_command = ["/bin/sh", abspath('\''c-ares/configure'\'$'), "--host '$1\"', '\'$'CONFIG_COMMANDS= CONFIG_FILES= > configure-output.txt'\'']'
