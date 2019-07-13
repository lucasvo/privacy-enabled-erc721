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

import "ds-test/test.sol";
import "../merkle.sol";


contract MerkleTest is DSTest  {
    MerkleVerifier merkle;

    function setUp() public {
        merkle = new MerkleVerifier(); 
    }

    function hash(bytes32 a, bytes32 b) public view returns (bytes32) {
            if (a < b) {
                return sha256(abi.encodePacked(a, b));
            } else {
                return sha256(abi.encodePacked(b, a));
            }
    }

    function testVerifier() public {
        bytes32 leaf1 = sha256("1");
        bytes32 leaf2 = sha256("2");
        bytes32 leaf3 = sha256("3");
        bytes32 leaf4 = sha256("4");

        bytes32 parent1 = hash(leaf1, leaf2); 
        bytes32 parent2 = hash(leaf3, leaf4);
        bytes32 root = hash(parent1, parent2);

        bytes32[] memory matches = new bytes32[](10);
        matches[0] = root; 
        
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = leaf2;
        proof[1] = parent2;
        uint len = 1;

        (matches, len) = merkle.verify(proof, matches, len, leaf1); 
        assertEq(len, 4);

        proof[0] = leaf4;
        (matches, len) = merkle.verify(proof, matches, len, leaf3);
        assertEq(len, 5);

        proof[0] = leaf1;
        (matches, len) = merkle.verify(proof, matches, len, leaf2);
        assertEq(len, 5);
    }

    function testFind() public {
        bytes32[] memory matches = new bytes32[](512);
        matches[0] = "0";
        assertTrue(merkle.find(matches, "0"));
    }
}
