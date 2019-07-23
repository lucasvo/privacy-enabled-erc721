// Copyright (C) 2019 lucasvo

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

pragma solidity >=0.4.24;

import { ERC721Enumerable } from "./openzeppelin-solidity/token/ERC721/ERC721Enumerable.sol";
import { ERC721Metadata } from "./openzeppelin-solidity/token/ERC721/ERC721Metadata.sol";
import "./ECDSA.sol";
import "./merkle.sol";

contract AnchorLike {
    function getAnchorById(uint) public returns (uint, bytes32, uint32);
}

contract IdentityLike {
    function keyHasPurpose(bytes32, uint256) public returns (bool);
    function getKey(bytes32) public returns (bytes32, uint256[] memory, uint32);
}

contract NFT is ERC721Metadata, MerkleVerifier {

    using ECDSA for bytes32;

    // --- Data ---
    IdentityLike public         identity;
    AnchorLike public           anchors;
    bytes32 public              ratings;
    string public               uri_prefix;

    string public uri;

    // --- Compact Properties ---
    // compact prop for "signatures_tree.signatures"
    bytes constant internal SIGNATURE_TREE_SIGNATURES = hex"0300000000000001";
    // compact prop for "signature" for a signature tree signature
    bytes constant internal SIGNATURE_TREE_SIGNATURES_SIGNATURE = hex"00000004";

    // Value of the Signature purpose for an identity. sha256('CENTRIFUGE@SIGNING')
    // solium-disable-next-line
    uint256 constant internal SIGNING_PURPOSE = 0x774a43710604e3ce8db630136980a6ba5a65b5e6686ee51009ed5f3fded6ea7e;


    constructor (string memory name, string memory symbol, address anchors_, address identity_) ERC721Metadata(name, symbol) public {
        anchors = AnchorLike(anchors_);
        identity = IdentityLike(identity_);
    }

    event Minted(address usr, uint tkn);

    // --- Utils ---
    function concat(bytes32 b1, bytes32 b2) pure internal returns (bytes memory)
    {
        bytes memory result = new bytes(64);
        assembly {
            mstore(add(result, 32), b1)
            mstore(add(result, 64), b2)
        }
        return result;
    }

    function uint2str(uint i) internal pure returns (string memory) {
        if (i == 0) return "0";
        uint j = i;
        uint length;
        while (j != 0){
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint k = length - 1;
        while (i != 0){
            bstr[k--] = byte(uint8(48 + i % 10));
            i /= 10;
        }
        return string(bstr);
    }

    // --- NFT ---
    function _checkAnchor(uint anchor, bytes32 droot, bytes32 sigs) internal returns (bool) {
        bytes32 root;
        (, root, ) = anchors.getAnchorById(anchor);
        if (droot < sigs) {
            return root == sha256(concat(droot, sigs));
        } else {
            return root == sha256(concat(sigs, droot));
        }
    }

  /**
   * @dev Checks that provided document is signed by the given identity
   * and validates and checks if the public key used is a valid SIGNING_KEY.
   * Does not check if the signature root is part of the document root.
   * @param anchored_block uint32 block number for when the document root was anchored
   * @param data_root bytes32 hash of all invoice fields which is signed
   * @param signature bytes The signature used to contract the property for precise proofs
   */
    function _requireSignedByIdentity(uint32 anchored_block, bytes32 data_root, bytes memory signature) internal returns (bool) {

        // Extract the public key from the signature
    bytes32 pbKey_ = bytes32(
      uint256(
        data_root.toEthSignedMessageHash().recover(signature)
      )
    );

    // check that public key has signature purpose on provided identity
    require(
    identity.keyHasPurpose(pbKey_, SIGNING_PURPOSE),
    "Signature key is not valid."
    );

    // If key is revoked, anchor must be older the the key revocation
    (, , uint32 revokedAt_) = identity.getKey(pbKey_);
    if (revokedAt_ > 0) {
      require(
        anchored_block < revokedAt_,
        "Document signed with a revoked key"
      );
    }
    }

  /**
   * @dev Mints a token to a specified address
   * @param usr address deposit address of token
   * @param tkn uint tokenID
   */
    function _mint(address usr, uint tkn) internal {
        super._mint(usr, tkn);
        emit Minted(usr, tkn);
    }
}

