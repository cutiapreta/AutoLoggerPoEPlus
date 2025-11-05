// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/AutoLoggerPoEPlus.sol";

contract DeployAutoLoggerMainnet is Script {
    function run() external {
        vm.startBroadcast(); 

        AutoLoggerPoEPlus deployed = new AutoLoggerPoEPlus();
        console.log("AutoLoggerPoEPlus deployed at:", address(deployed));

        vm.stopBroadcast();
    }
}

