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


contract MerkleVerifier {
    uint constant hashLength = 512;
    function find(bytes32[] memory values, bytes32 value) public pure returns (bool) {
        for (uint i=0; i < values.length; i++) {
            if (values[i] == value) {
                return true;
            }
        }
        return false;
    }
     
    function verify(bytes32[] memory proof, bytes32[] memory matches, uint len, bytes32 leaf) public returns (bytes32[] memory, uint) {
        bytes32 res = leaf;
        
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 elem = proof[i];

            if (res < elem) {
                res = sha256(abi.encodePacked(res, elem));
            } else {
                res = sha256(abi.encodePacked(elem, res));
            }
            if (find(matches, res)){
                return (matches, len);
            }
            matches[len] = res;
            len++;
        }
        revert("invalid-matches");
    }
}
