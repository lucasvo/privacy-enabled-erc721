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

import { ERC721Metadata } from "./openzeppelin-solidity/token/ERC721/ERC721Metadata.sol";
import "./ECDSA.sol";
import "./merkle.sol";

contract AnchorLike {
    function getAnchorById(uint) public view returns (uint, bytes32, uint32);
}

contract KeyManagerLike {
    function keyHasPurpose(bytes32, uint256) public view returns (bool);
    function getKey(bytes32) public view returns (bytes32, uint256[] memory, uint32);
}

contract IdentityFactoryLike {
    mapping(address => bool) internal _identities;
    function createdIdentity(address) public view returns (bool);
}

contract NFT is ERC721Metadata, MerkleVerifier {

    using ECDSA for bytes32;

    // --- Data ---
    KeyManagerLike public       key_manager;
    AnchorLike public           anchors;
    IdentityFactoryLike public  identity_factory;

    // Base for constructing dynamic metadata token URIS
    // the token uri also contains the registry address. uri + contract address + tokenId
    string public uri;

    // --- Compact Properties ---
    // compact prop for "signatures_tree.signatures"
    bytes constant internal SIGNATURE_TREE_SIGNATURES = hex"0300000000000001";
    // compact prop for "signature" for a signature tree signature
    bytes constant internal SIGNATURE_TREE_SIGNATURES_SIGNATURE = hex"00000004";
    // compact prop for "next_version"
    bytes constant internal NEXT_VERSION = hex"0100000000000004";
    // compact prop from "nfts"
    bytes constant internal NFTS = hex"0100000000000014";
    // Value of the Signature purpose for an identity. sha256('CENTRIFUGE@SIGNING')
    // solium-disable-next-line
    uint256 constant internal SIGNING_PURPOSE = 0x774a43710604e3ce8db630136980a6ba5a65b5e6686ee51009ed5f3fded6ea7e;

    constructor (string memory name, string memory symbol, address anchors_, address identity_, address identity_factory_) ERC721Metadata(name, symbol) public {
        anchors = AnchorLike(anchors_);
        key_manager = KeyManagerLike(identity_);
        identity_factory = IdentityFactoryLike(identity_factory_);
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
    /**
    * @dev Parses bytes and extracts a bytes8 value from
    * the given starting point
    * @param payload bytes From where to extract the index
    * @param startFrom uint256 where to start from
    * @return bytes8 the index found, it defaults to 0x00000000000000
    */
     function extractIndex(
       bytes memory payload,
       uint256 startFrom
     )
     internal
     pure
     returns (
       bytes8 index
     )
     {
       // solium-disable-next-line security/no-inline-assembly
       assembly {
         index := mload(add(add(payload, 0x20), startFrom))
       }
     }

     /**
      * @dev Parses bytes and extracts a uint256 value
      * @param payload bytes From where to extract the index
      * @return result the converted address
      */
     function bytesToUint(
       bytes memory payload
     )
     internal
     pure
     returns (
       uint256 result
     )
     {
       // solium-disable-next-line security/no-inline-assembly
       assembly {
         result := mload(add(payload, 0x20))
       }
     }

     /**
      * @dev Parses a uint and returns the hex string
      * @param payload uint
      * @return string the corresponding hex string
      */
     function uintToHexStr(
       uint payload
     )
     internal
     pure
     returns (
       string memory
     )
     {
       if (payload == 0)
         return "0";
       // calculate string length
       uint i = payload;
       uint length;

       while (i != 0) {
         length++;
         i = i >> 4;
       }
       // parse byte by byte and construct the string
       i = payload;
       uint mask = 15;
       bytes memory result = new bytes(length);
       uint k = length - 1;

       while (i != 0) {
         uint curr = (i & mask);
         result[k--] = curr > 9 ? byte(55 + uint8(curr)) : byte(48 + uint8(curr));
         i = i >> 4;
       }

       return string(result);
     }

    // --- NFT ---
    function _checkAnchor(uint anchor, bytes32 data_root, bytes32 sigs) internal view returns (bool) {
        bytes32 doc_root;
        (, doc_root, ) = anchors.getAnchorById(anchor);
        if (data_root < sigs) {
            return doc_root == sha256(concat(data_root, sigs));
        } else {
            return doc_root == sha256(concat(sigs, data_root));
        }
    }

  /**
   * @dev Returns an URI for a given token ID
   * the Uri is constructed dynamic based. _tokenUriBase + contract address + tokenId
   * Throws if the token ID does not exist. May return an empty string.
   * @param token_id uint256 ID of the token to query
   */
	  function tokenURI(
		  uint256 token_id
	  )
	  external
	  view
	  returns (
		  string memory
	  )
	  {
		  return string(
			  abi.encodePacked(
				  uri,
				  "0x",
				  uintToHexStr(uint256(address(this))),
				  "/0x",
				  uintToHexStr(token_id)
			  )
		  );
	  }

  /**
   * @dev Checks if the provided next id is part of the
   * document root and the document is the latest version anchored
   * @param data_root bytes32 hash of all invoice fields which is signed
   * @param next_anchor_id uint256 the next id to be anchored
   * @param salt bytes32 salt for leaf construction
   * @param proof bytes32[][] proofs for leaf construction
   */
  function _requireIsLatestDocumentVersion(
    bytes32 data_root,
    uint256 next_anchor_id,
    bytes32 salt,
    bytes32[][] memory proof
  )
  internal
  view
  {
    (, bytes32 next_merkle_root_, ) = anchors.getAnchorById(next_anchor_id);

    require(
      next_merkle_root_ == 0x0,
      "Document has a newer version on chain"
    );

    bytes32[] memory leaf = new bytes32[](1);
    leaf[0] = sha256(
        abi.encodePacked(
          NEXT_VERSION,
          next_anchor_id,
          salt
        )
      );

    require(
      verify(
        proof,
        data_root,
        leaf
      ),
      "Next version proof is not valid"
    );
  }

  /**
   * @dev Checks that provided document is signed by the given identity
   * and validates and checks if the public key used is a valid SIGNING_KEY.
   * Does not check if the signature root is part of the document root.
   * @param anchored_block uint32 block number for when the document root was anchored
   * @param data_root bytes32 hash of all invoice fields which is signed
   * @param signature bytes The signature used to contract the property for precise proofs
   */
    function _requireSignedByIdentity(uint32 anchored_block, bytes32 data_root, bytes memory signature) internal view returns (bool) {

      // Extract the public key and identity address from the signature
      address identity_ = data_root.toEthSignedMessageHash().recover(signature);
      bytes32 pbKey_ = bytes32(
      uint256(identity_)
      );

      // check that the identity being used has been created by the Centrifuge Identity Factory contract
      bool valid = identity_factory.createdIdentity(identity_);
      require(valid, "Identity is not registered.");

      // check that public key has signature purpose on provided identity
      require(
        key_manager.keyHasPurpose(pbKey_, SIGNING_PURPOSE),
        "Signature key is not valid."
      );

      // If key is revoked, anchor must be older the the key revocation
      (, , uint32 revokedAt_) = key_manager.getKey(pbKey_);
      if (revokedAt_ > 0) {
        require(
          anchored_block < revokedAt_,
          "Document signed with a revoked key."
        );
      }
    }

  /**
   * @dev Checks that the document has no other token
   * minted in this registry for the provided document
   * @param data_root bytes32 hash of all invoice fields which is signed
   * @param tokenId uint256 The ID for the token to be minted
   * @param salt bytes32 salt for leaf construction
   * @param proof bytes32[][] proofs for leaf construction
   */
	  function _requireTokenUniqueness(
	    bytes32 data_root,
	    uint256 tokenId,
	    bytes32 salt,
	    bytes32[][] memory proof
 	  )
	  internal
		view
	  {
		  // Reconstruct the property
		  // the property format: nfts[registryAddress]
	    bytes memory property_ = abi.encodePacked(
	    NFTS,
	    address(this),
	    hex"000000000000000000000000"
	    );

      bytes32[] memory leaf = new bytes32[](1);
		  leaf[0] = sha256(abi.encodePacked(property_, tokenId, salt));
	    require(
	      verify(
	      proof,
	      data_root,
        leaf
	    ),
	    "Token uniqueness proof is not valid"
	    );
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

