// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.0;

contract SponsorWhitelistControl {

    struct SponsorInfo {
        /// This is the address of the sponsor for gas cost of the contract.
        address sponsor_for_gas;
        /// This is the upper bound of sponsor gas cost per tx.
        uint256 sponsor_gas_bound;
        /// This is the amount of tokens sponsor for gas cost to the contract.
        uint256 sponsor_balance_for_gas;
    }

    mapping(address => SponsorInfo) sponsor_infos;

    /*** Query Functions ***/
    /**
     * @dev get gas sponsor address of specific contract
     * @param contractAddr The address of the sponsored contract
     */
    function getSponsorForGas(address contractAddr) public view returns (address) {}

    /**
     * @dev get current Sponsored Balance for gas
     * @param contractAddr The address of the sponsored contract
     */
    function getSponsoredBalanceForGas(address contractAddr) public view returns (uint256) {}

    /**
     * @dev get current Sponsored Gas fee upper bound
     * @param contractAddr The address of the sponsored contract
     */
    function getSponsoredGasFeeUpperBound(address contractAddr) public view returns (uint256) {}

    /**
     * @dev check if a user is in a contract's whitelist
     * @param contractAddr The address of the sponsored contract
     * @param user The address of contract user
     */
    function isWhitelisted(address contractAddr, address user) public view returns (bool) {}

    /**
     * @dev check if all users are in a contract's whitelist
     * @param contractAddr The address of the sponsored contract
     */
    function isAllWhitelisted(address contractAddr) public view returns (bool) {}

    // ------------------------------------------------------------------------
    // Someone will sponsor the gas cost for contract `contractAddr` with an
    // `upper_bound` for a single transaction.
    // ------------------------------------------------------------------------
    function setSponsorForGas(address contractAddr, uint upperBound) public payable {}

    // ------------------------------------------------------------------------
    // Add commission privilege for address `user` to some contract.
    // ------------------------------------------------------------------------
    function addPrivilege(address[] memory) public {}

    // ------------------------------------------------------------------------
    // Remove commission privilege for address `user` from some contract.
    // ------------------------------------------------------------------------
    function removePrivilege(address[] memory) public {}
}