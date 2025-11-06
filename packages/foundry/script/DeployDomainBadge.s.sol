// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {DomainBadge} from "../contracts/DomainBadge.sol";

/// @notice Deploys DomainBadge with env ISSUER and OWNER (defaults to the broadcaster EOA).
contract DeployDomainBadge is Script {
    function run() external {
        address issuer = vm.envOr("ISSUER", address(0));
        address owner = vm.envOr("OWNER", address(0));

        vm.startBroadcast();
        address broadcaster = msg.sender;
        if (issuer == address(0)) issuer = broadcaster;
        if (owner == address(0)) owner = broadcaster;

        DomainBadge badge = new DomainBadge(issuer, owner);
        console2.log("DomainBadge deployed:", address(badge));
        console2.log("issuer:", issuer);
        console2.log("owner:", owner);
        vm.stopBroadcast();
    }
}
