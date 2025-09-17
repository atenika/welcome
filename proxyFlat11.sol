// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.19;


/*
**Regulamin Smart Kontraktu 

**§ 1. Postanowienia Ogólne**
1. Niniejszy regulamin określa zasady uczestnictwa oraz odpowiedzialności użytkowników biorących udział w ankiecie realizowanej przy użyciu smart kontraktu protokołu Atenika.
2. Smart kontrakt jest dostarczany na zasadach freeware, tj. bezpłatnie, bez jakichkolwiek gwarancji, wyraźnych lub dorozumianych, w tym gwarancji zdatności do określonego celu.

**§ 2. Zakaz Wysyłania Tokenów Spoza Protokołu Atenika **
1. Użytkownikom kategorycznie zabrania się wysyłania do smart kontraktu jakichkolwiek tokenów pochodzących spoza protokołu Atenika.
2. W przypadku stwierdzenia próby przesłania takich tokenów, administrator smart kontraktu ma prawo do natychmiastowego wykluczenia użytkownika z udziału w ankiecie oraz podjęcia dalszych działań ochronnych.

**§ 3. Odpowiedzialność za Nieuprawnione Działania**
1. Użytkownik ponosi pełną odpowiedzialność za wszelkie działania mające na celu shakowanie, manipulację lub inne zakłócenie wyników głosowania.
2. Zabrania się posługiwania fałszywą tożsamością, która nie jest jednoznacznie oznaczona w publicznie dostępnych danych profilu użytkownika jako „TESTER” lub innym wyraźnym oznaczeniem testowym.
3. W przypadku wykrycia fałszerstwa i manipulacji wyniku głosowania przez pewnego użytkownika lub grupę użytkowników, pozostali użytkownicy mają prawo dochodzić odszkodowania i pokrycia kosztów organizacji referendum w formie tradycyjnym.

**§ 4. Kara Umowna**
1. Minimalna wysokość kary umownej w sytuacji opisanej w § 3 ust. 3 wynosi 100 000 PLN (słownie: sto tysięcy złotych).
2. Kara ta nie wyłącza prawa do dochodzenia dodatkowego odszkodowania na zasadach ogólnych, jeśli poniesione szkody przewyższają wysokość zastrzeżonej kary umownej.

**§ 5. Wyłączenie Odpowiedzialności**
1. Deployer i twórcy smart kontraktu nie ponoszą odpowiedzialności za jakiekolwiek bezpośrednie, pośrednie, przypadkowe, specjalne lub wtórne szkody wynikające z korzystania ze smart kontraktu, w szczególności za szkody wynikłe z utraty danych lub zysków.
2. Smart kontrakt jest udostępniany w formie freeware bez gwarancji co do poprawności działania, braku błędów, bezpieczeństwa lub zgodności z oczekiwaniami użytkownika.

**§ 6. Zrzeczenie się roszczeń
Użytkownik tego Smart Contract'u zrzeka się roszczeń wobec twórców i deployera tego Smart Contracts 
wynikających z jego użytkowania.

W maksymalnym dopuszczalnym przez prawo zakresie Użytkownik zrzeka się wobec twórców i deployera tego Smart Contracts 
oraz Smart Contracts z nim powiązanych wszelkich roszczeń wynikających lub związanych z korzystaniem z Smart Contractu tego 
i z nim współdziałających Smart Contracts w ramach Protokołu dostarczającego tożsamość zgodnie z ERC 7822 lub innych( w tym Atenika lub innych dostawców tożsamości w formie zdecentralizowanej). 
Użytkownik zrzeka się w tym roszczeń o odszkodowanie z tytułu szkód pośrednich, utraconych korzyści, utraty danych czy szkód wynikłych z opóźnień, 
przerw w działaniu lub błędów Serwisu. Postanowienie to nie ogranicza odpowiedzialności, której nie można wyłączyć 
na mocy bezwzględnie obowiązujących przepisów prawa.

**§ 7. Postanowienia Końcowe**
1. Uczestnictwo w ankiecie/prawyborach/wyborach/głosowaniu poprzez smart kontrakt jest jednoznaczne z akceptacją niniejszego regulaminu.
2. Regulamin obowiązuje od momentu jego publikacji w smart kontrakcie.

______________________________________________________
proxyABI dotyczy samego proxy:

[
	{
		"inputs": [],
		"name": "implementation",
		"outputs": [
			{
				"internalType": "address",
				"name": "impl",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "isThatProxy",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "whatVersionIsthat",
		"outputs": [
			{
				"internalType": "uint32",
				"name": "",
				"type": "uint32"
			}
		],
		"stateMutability": "pure",
		"type": "function"
	}
]

______________________________________________________
funkcje istotne w proxyABI dotyczy samego proxy i implementacji - logiki:


*/
// src/Proxy.sol

// OpenZeppelin Contracts (last updated v5.0.0) (proxy/Proxy.sol)

/**
 * @dev This abstract contract provides a fallback function that delegates all calls to another contract using the EVM
 * instruction `delegatecall`. We refer to the second contract as the _implementation_ behind the proxy, and it has to
 * be specified by overriding the virtual {_implementation} function.
 *
 * Additionally, delegation to the implementation can be triggered manually through the {_fallback} function, or to a
 * different contract through the {_delegate} function.
 *
 * The success and return data of the delegated call will be returned back to the caller of the proxy.
 */
abstract contract Proxy {
    /**
     * @dev Delegates the current call to `implementation`.
     *
     * This function does not return to its internal call site, it will return directly to the external caller.
     */
    function _delegate(address implementation) internal virtual {
        assembly {
            // Copy msg.data. We take full control of memory in this inline assembly
            // block because it will not return to Solidity code. We overwrite the
            // Solidity scratch pad at memory position 0.
            calldatacopy(0, 0, calldatasize())

            // Call the implementation.
            // out and outsize are 0 because we don't know the size yet.
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

            // Copy the returned data.
            returndatacopy(0, 0, returndatasize())

            switch result
            // delegatecall returns 0 on error.
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    /**
     * @dev This is a virtual function that should be overridden so it returns the address to which the fallback
     * function and {_fallback} should delegate.
     */
    function _implementation() internal view virtual returns (address);

    /**
     * @dev Delegates the current call to the address returned by `_implementation()`.
     *
     * This function does not return to its internal call site, it will return directly to the external caller.
     */
    function _fallback() internal virtual {
        _delegate(_implementation());
    }

    /**
     * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if no other
     * function in the contract matches the call data.
     */
    fallback() external payable virtual {
        _fallback();
    }
}

// src/beacon/IBeacon.sol

// OpenZeppelin Contracts (last updated v5.0.0) (proxy/beacon/IBeacon.sol)

/**
 * @dev This is the interface that {BeaconProxy} expects of its beacon.
 */
interface IBeacon {
    /**
     * @dev Must return an address that can be used as a delegate call target.
     *
     * {UpgradeableBeacon} will check that this address is a contract.
     */
    function implementation() external view returns (address);
}

// src/utils/Address.sol

// OpenZeppelin Contracts (last updated v5.0.0) (utils/Address.sol)

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev The ETH balance of the account is not enough to perform the operation.
     */
    error AddressInsufficientBalance(address account);

    /**
     * @dev There's no code at `target` (it is not a contract).
     */
    error AddressEmptyCode(address target);

    /**
     * @dev A call to an address target failed. The target may have reverted.
     */
    error FailedInnerCall();

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.8.19/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        if (address(this).balance < amount) {
            revert AddressInsufficientBalance(address(this));
        }

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert FailedInnerCall();
        }
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason or custom error, it is bubbled
     * up by this function (like regular Solidity function calls). However, if
     * the call reverted with no returned reason, this function reverts with a
     * {FailedInnerCall} error.
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        if (address(this).balance < value) {
            revert AddressInsufficientBalance(address(this));
        }
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and reverts if the target
     * was not a contract or bubbling up the revert reason (falling back to {FailedInnerCall}) in case of an
     * unsuccessful call.
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata
    ) internal view returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            // only check if target is a contract if the call was successful and the return data is empty
            // otherwise we already know that it was a contract
            if (returndata.length == 0 && target.code.length == 0) {
                revert AddressEmptyCode(target);
            }
            return returndata;
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and reverts if it wasn't, either by bubbling the
     * revert reason or with a default {FailedInnerCall} error.
     */
    function verifyCallResult(bool success, bytes memory returndata) internal pure returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            return returndata;
        }
    }

    /**
     * @dev Reverts with returndata if present. Otherwise reverts with {FailedInnerCall}.
     */
    function _revert(bytes memory returndata) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            /// @solidity memory-safe-assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert FailedInnerCall();
        }
    }
}

// src/utils/StorageSlot.sol

// OpenZeppelin Contracts (last updated v5.0.0) (utils/StorageSlot.sol)
// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.

/**
 * @dev Library for reading and writing primitive types to specific storage slots.
 *
 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.
 * This library helps with reading and writing to such slots without the need for inline assembly.
 *
 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.
 *
 * Example usage to set ERC1967 implementation slot:
 * ```solidity
 * contract ERC1967 {
 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 *
 *     function _getImplementation() internal view returns (address) {
 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
 *     }
 *
 *     function _setImplementation(address newImplementation) internal {
 *         require(newImplementation.code.length > 0);
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 */
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    struct StringSlot {
        string value;
    }

    struct BytesSlot {
        bytes value;
    }

    /**
     * @dev Returns an `AddressSlot` with member `value` located at `slot`.
     */
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BooleanSlot` with member `value` located at `slot`.
     */
    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Bytes32Slot` with member `value` located at `slot`.
     */
    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Uint256Slot` with member `value` located at `slot`.
     */
    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` with member `value` located at `slot`.
     */
    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.
     */
    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := store.slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` with member `value` located at `slot`.
     */
    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.
     */
    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := store.slot
        }
    }
}

// src/ERC1967/ERC1967Utils.sol

// OpenZeppelin Contracts (last updated v5.0.0) (proxy/ERC1967/ERC1967Utils.sol)

/**
 * @dev This abstract contract provides getters and event emitting update functions for
 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967] slots.
 */
library ERC1967Utils {
    // We re-declare ERC-1967 events here because they can't be used directly from IERC1967.
    // This will be fixed in Solidity 0.8.21. At that point we should remove these events.
    /**
     * @dev Emitted when the implementation is upgraded.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Emitted when the admin account has changed.
     */
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
     * @dev Emitted when the beacon is changed.
     */
    event BeaconUpgraded(address indexed beacon);

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev The `implementation` of the proxy is invalid.
     */
    error ERC1967InvalidImplementation(address implementation);

    /**
     * @dev The `admin` of the proxy is invalid.
     */
    error ERC1967InvalidAdmin(address admin);

    /**
     * @dev The `beacon` of the proxy is invalid.
     */
    error ERC1967InvalidBeacon(address beacon);

    /**
     * @dev An upgrade function sees `msg.value > 0` that may be lost.
     */
    error ERC1967NonPayable();

    /**
     * @dev Returns the current implementation address.
     */
    function getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        if (newImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(newImplementation);
        }
        StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /**
     * @dev Performs implementation upgrade with additional setup call if data is nonempty.
     * This function is payable only if the setup call is performed, otherwise `msg.value` is rejected
     * to avoid stuck value in the contract.
     *
     * Emits an {IERC1967-Upgraded} event.
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);

        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        } else {
            _checkNonPayable();
        }
    }

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Returns the current admin.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by EIP1967) using
     * the https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`
     */
    function getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(ADMIN_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 admin slot.
     */
    function _setAdmin(address newAdmin) private {
        if (newAdmin == address(0)) {
            revert ERC1967InvalidAdmin(address(0));
        }
        StorageSlot.getAddressSlot(ADMIN_SLOT).value = newAdmin;
    }

    /**
     * @dev Changes the admin of the proxy.
     *
     * Emits an {IERC1967-AdminChanged} event.
     */
    function changeAdmin(address newAdmin) internal {
        emit AdminChanged(getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is the keccak-256 hash of "eip1967.proxy.beacon" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Returns the current beacon.
     */
    function getBeacon() internal view returns (address) {
        return StorageSlot.getAddressSlot(BEACON_SLOT).value;
    }

    /**
     * @dev Stores a new beacon in the EIP1967 beacon slot.
     */
    function _setBeacon(address newBeacon) private {
        if (newBeacon.code.length == 0) {
            revert ERC1967InvalidBeacon(newBeacon);
        }

        StorageSlot.getAddressSlot(BEACON_SLOT).value = newBeacon;

        address beaconImplementation = IBeacon(newBeacon).implementation();
        if (beaconImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(beaconImplementation);
        }
    }

    /**
     * @dev Change the beacon and trigger a setup call if data is nonempty.
     * This function is payable only if the setup call is performed, otherwise `msg.value` is rejected
     * to avoid stuck value in the contract.
     *
     * Emits an {IERC1967-BeaconUpgraded} event.
     *
     * CAUTION: Invoking this function has no effect on an instance of {BeaconProxy} since v5, since
     * it uses an immutable beacon without looking at the value of the ERC-1967 beacon slot for
     * efficiency.
     */
    function upgradeBeaconToAndCall(address newBeacon, bytes memory data) internal {
        _setBeacon(newBeacon);
        emit BeaconUpgraded(newBeacon);

        if (data.length > 0) {
            Address.functionDelegateCall(IBeacon(newBeacon).implementation(), data);
        } else {
            _checkNonPayable();
        }
    }

    /**
     * @dev Reverts if `msg.value` is not zero. It can be used to avoid `msg.value` stuck in the contract
     * if an upgrade doesn't perform an initialization call.
     */
    function _checkNonPayable() private {
        if (msg.value > 0) {
            revert ERC1967NonPayable();
        }
    }
}

// src/ERC1967/ERC1967Proxy.sol

// OpenZeppelin Contracts (last updated v5.0.0) (proxy/ERC1967/ERC1967Proxy.sol)

/**
 * @dev This contract implements an upgradeable proxy. It is upgradeable because calls are delegated to an
 * implementation address that can be changed. This address is stored in storage in the location specified by
 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967], so that it doesn't conflict with the storage layout of the
 * implementation behind the proxy.
 */
contract ERC1967Proxy is Proxy {
    /**
     * @dev Initializes the upgradeable proxy with an initial implementation specified by `implementation`.
     *
     * If `_data` is nonempty, it's used as data in a delegate call to `implementation`. This will typically be an
     * encoded function call, and allows initializing the storage of the proxy like a Solidity constructor.
     *
     * Requirements:
     *
     * - If `data` is empty, `msg.value` must be zero.
     */
    constructor(address implementation, bytes memory _data) payable {
        ERC1967Utils.upgradeToAndCall(implementation, _data);
    }

    /**
     * @dev Returns the current implementation address.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by EIP1967) using
     * the https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
     */
    function _implementation() internal view virtual override returns (address) {
        return ERC1967Utils.getImplementation();
    }
}




pragma solidity ^0.8.19;



abstract contract ProxyToDeploy is ERC1967Proxy{
    // slot z adresem logicznego kontraktu, zgodnie z EIP-1967
    // bytes32 constant IMPLEMENTATION_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

bytes32 internal constant _ADMIN_SLOT = bytes32(uint256(keccak256("SLOTADMINA"))+1);
bytes32 internal constant ADMIN_DAO_SLOT = bytes32(uint256(keccak256("ADMIN_DAO_SLOT"))+1);


bytes32 internal constant _DAO_ACTIVE_SLOT = keccak256("proxy.dao.active.slot");
bytes32 internal constant _ADMIN_ACTIVE_SLOT = keccak256("proxy.admin.active.slot");


// Użycie StorageSlot do manipulacji danymi w slotach pamięci
function _getAdmin() public view returns (address admin) {
    return StorageSlot.getAddressSlot(_ADMIN_SLOT).value;
}

function _getDAOAdmin() public view returns (address daoAddress) {
    return StorageSlot.getAddressSlot(ADMIN_DAO_SLOT).value;
}


function _setAdmin(address newAdmin) internal {
    require(newAdmin != address(0), "New admin cannot be the zero address");
    StorageSlot.getAddressSlot(_ADMIN_SLOT).value = newAdmin;
}

function _setDAOAdmin(address newDaoAdmin) internal {
    require(newDaoAdmin != address(0), "New dao admin cannot be the zero address");
    StorageSlot.getAddressSlot(ADMIN_DAO_SLOT).value = newDaoAdmin;
}


function transferAdmin(address newAdmin) public {
    require(tx.origin==_getAdmin(),'You are not the admin');
    require(newAdmin != address(0), "New admin cannot be the zero address");
    StorageSlot.getAddressSlot(_ADMIN_SLOT).value = newAdmin;
}


    // Adres administratora; tylko administrator może aktualizować kontrakt


    constructor(address newImplementation, bytes memory _data)
    ERC1967Proxy( newImplementation, _data) {
        _setAdmin(tx.origin);  // Przypisanie roli admina do pierwotnego twórcy kontraktu
        setDAOActive(false);
        setAdminActive(true);
    }

 /*  ta funkcja jest w kontrakcie Proxy
    fallback() external payable {
        _delegate(ERC1967Proxy._implementation());
    }
 */
    function implementation() public view  returns (address impl) {
    impl=ERC1967Proxy._implementation();
    }

    // Funkcja do aktualizacji implementacji kontraktu
    function upgradeImplementation(address newImplementation) external returns(bool){
        require(tx.origin == _getAdmin(), "Unauthorized");  // Kontrola dostępu oparta o tx.origin
        require(getAdminActive() == true, "admin deactivated");        
        ERC1967Utils.upgradeToAndCall(newImplementation, "");

        return true;
    }
        // Funkcja do aktualizacji implementacji kontraktu
    function upgradeImplementationByTCDAO(address newImplementation) external returns(bool){
        require(getDAOActive(), "Unauthorized dao is not activated");  
        require(tx.origin == _getDAOAdmin(), "Unauthorized your wallet is not TCDAO");  // Kontrola dostępu oparta o tx.origin
        ERC1967Utils.upgradeToAndCall(newImplementation, "");

        return true;
    }


    function setTCdao(address setterTCdao) external returns(address){
        require(tx.origin == _getAdmin(), "Unauthorized not admin");
        require(getDAOActive() == false, "Unauthorized not admin"); 
        require(_getDAOAdmin() == address(0x0), "dao already setted");               
        _setDAOAdmin(setterTCdao);
        return _getDAOAdmin();
    }

    function activateTCdaoNow() external returns(address){
        require(_getDAOAdmin() != address(0x0), "dao is not setted");     
        require(tx.origin == _getDAOAdmin(), "Unauthorized"); 
        setDAOActive(true);
        // if dao cant even activate itself we can't cosider it as working , operational dao
        return _getDAOAdmin();
    }
    
    function deactivateAdminNow() external returns(address){
        require(tx.origin == _getDAOAdmin(), "Unauthorized not dao"); 
        require(getDAOActive() == true, "dao nto activated");    
        setAdminActive(false);

        return _getDAOAdmin();
    }

    function whatVersionIsthat() external pure returns(uint32){
        uint32 version = 1;

        return version;

    }


        // Setter dla boolDAOActive
    function setDAOActive(bool newValue) internal {
        StorageSlot.getBooleanSlot(_DAO_ACTIVE_SLOT).value = newValue;
    }

    // Getter dla boolDAOActive
    function getDAOActive() public view returns (bool) {
        return StorageSlot.getBooleanSlot(_DAO_ACTIVE_SLOT).value;
    }

    // Setter dla boolAdminActive
    function setAdminActive(bool newValue) internal {
        StorageSlot.getBooleanSlot(_ADMIN_ACTIVE_SLOT).value = newValue;
    }

    // Getter dla boolAdminActive
    function getAdminActive() public view returns (bool) {
        return StorageSlot.getBooleanSlot(_ADMIN_ACTIVE_SLOT).value;
    }



}


pragma solidity ^0.8.19;


contract AtenikaRdzenProtokoluProxy is ProxyToDeploy{
    // Funkcja, która zwraca stały string
    function isThatProxy() public view returns (string memory, address,string memory, address) {
        return ("Atenika: proxied Rdzen Polski, ENG:This is proxy for Polish Core of Atenika Rptokol",address(this)," logika jest na adresie: ",implementation());
    }

        constructor(address newImplementation, bytes memory _data)
    ProxyToDeploy(newImplementation,_data)
    {

    setDAOActive(false);
    setAdminActive(true);
    require(_getAdmin() != address(0x0), "Admin address cannot be 0x0");
    require(newImplementation != address(0x0), "Implementation address cannot be 0x0");
}

    receive() external payable {
        _delegate(ERC1967Proxy._implementation());
    }

}


contract GlosowanieNr1AtenikaProtokolo is ProxyToDeploy{
    // Funkcja, która zwraca stały string
    function isThatProxy() public view returns (string memory, address,string memory, address) {
        return ("Atenika: proxied Pytanie / Glosowanie w Polsce, ENG:This is proxy for Polish Question",address(this)," logika jest na adresie: ",implementation());
    }

        constructor(address newImplementation, bytes memory _data)
    ProxyToDeploy(newImplementation,_data)
    {

    setDAOActive(false);
    setAdminActive(true);
    require(_getAdmin() != address(0x0), "Admin address cannot be 0x0");
    require(newImplementation != address(0x0), "Implementation address cannot be 0x0");
}

    receive() external payable {
        _delegate(ERC1967Proxy._implementation());
    }

}


contract GlosowanieNr2AtenikaProtokolo is ProxyToDeploy{
    // Funkcja, która zwraca stały string
    function isThatProxy() public view returns (string memory, address,string memory, address) {
        return ("Atenika: proxied Pytanie 2 / Glosowanie nr 2 w Polsce, ENG:This is proxy for Polish Question number 2",address(this)," logika jest na adresie: ",implementation());
    }

        constructor(address newImplementation, bytes memory _data)
    ProxyToDeploy(newImplementation,_data)
    {

    setDAOActive(false);
    setAdminActive(true);
    require(_getAdmin() != address(0x0), "Admin address cannot be 0x0");
    require(newImplementation != address(0x0), "Implementation address cannot be 0x0");
}

    receive() external payable {
        _delegate(ERC1967Proxy._implementation());
    }

}

contract FabrykaProfiliDlaAteniki is ProxyToDeploy{
    // Funkcja, która zwraca stały string
    function isThatProxy() public view returns (string memory, address,string memory, address) {
        return ("Atenika: proxy dla Fabryki Profili w Polsce, ENG:This is proxy for Polish Factory of profiles in Atenika Protocol",address(this)," logika jest na adresie: ",implementation());
    }

        constructor(address newImplementation, bytes memory _data)
    ProxyToDeploy(newImplementation,_data)
    {

    setDAOActive(false);
    setAdminActive(true);
    require(_getAdmin() != address(0x0), "Admin address cannot be 0x0");
    require(newImplementation != address(0x0), "Implementation address cannot be 0x0");
}

    receive() external payable {
        _delegate(ERC1967Proxy._implementation());
    }

}