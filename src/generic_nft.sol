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

pragma solidity >=0.4.23;
pragma experimental ABIEncoderV2;

import "ds-test/test.sol";
import "./nft.sol";


contract GenericNFT is NFT {

    struct TokenData {
        uint document_version;
        uint val1;
        uint val2;
        uint val3;
        address minted_address;
    }
    mapping (uint => TokenData) public data;

    constructor (address anchors_) NFT("Generic NFT", "GNFT", anchors_) public {
    }

    // --- Utils ---
    function bytesToUint(bytes memory b) public returns (uint256){
      uint256 number;
      for (uint i = 0; i < b.length; i++){
              number = number + uint8(b[i]) * (2 ** (8 * (b.length - (i + 1))));
            }
      return number;
    }

    // --- Mint Method ---
    function mint(address usr, uint tkn, uint anchor, bytes32 data_root, bytes32 signatures_root, bytes[] memory properties, bytes[] memory values, bytes32[] memory salts, bytes32[][] memory proofs) public {

      data[tkn] = TokenData(
        anchor,
        bytesToUint(values[0]),
        bytesToUint(values[1]),
        bytesToUint(values[2]),
        usr
      );

      bytes32[] memory leaves = new bytes32[](3);
      leaves[0] = sha256(abi.encodePacked(properties[0], values[0], salts[0]));
      leaves[1] = sha256(abi.encodePacked(properties[1], values[1], salts[1]));
      leaves[2] = sha256(abi.encodePacked(properties[2], values[2], salts[2]));

      require(verify(proofs, data_root, leaves), "Validation of proofs failed.");
      require(_checkAnchor(anchor, data_root, signatures_root), "Validation against document anchor failed.");
      _mint(usr, tkn);
    }
}
