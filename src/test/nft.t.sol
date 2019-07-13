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
import "../nft.sol";

contract User {
    function doMint(address registry, address usr) public {
    }
}

contract AnchorMock {
    bytes32 documentRoot;
    uint32  blockNumber;

    function file(bytes32 documentRoot_, uint32 blockNumber_) public {
        documentRoot = documentRoot_;
        blockNumber = blockNumber;
    }

    function getAnchorById(uint id) public returns (uint, bytes32, uint32) {
        return (id, documentRoot, blockNumber);
    }
}

contract TestNFT is NFT {
    constructor (string memory name, string memory symbol, address anchors_) NFT(name, symbol, anchors_) public {
    }
    function checkAnchor(uint anchor, bytes32 droot, bytes32 sigs) public returns (bool) {
        return _checkAnchor(anchor, droot, sigs); 
    }
    function mint(address usr, uint tkn, uint anchor, bytes32 droot, bytes32 sigs, bytes32[3] memory values, bytes32[][] memory proofs, uint len) public {
        checkAnchor(anchor, droot, sigs);

        bytes32[] memory matches = new bytes32[](len);
        matches[0] = droot;
        uint len2 = len;
        uint len = 1;

        (matches, len) = verify(proofs[0], matches, len, values[0]);
        (matches, len) = verify(proofs[1], matches, len, values[1]);
        (matches, len) = verify(proofs[2], matches, len, values[2]);
        _mint(usr, tkn);
    }
} 

contract NFTTest is DSTest  {
    TestNFT     nft;
    address     self;
    User        usr1;
    User        usr2;
    AnchorMock  anchors;

    function setUp() public {
        self = address(this);
        usr1 = new User();
        usr2 = new User();
        anchors = new AnchorMock();
        nft = new TestNFT("test", "TEST", address(anchors));
    }
    
    function hash(bytes32 a, bytes32 b) public view returns (bytes32) {
            if (a < b) {
                return sha256(abi.encodePacked(a, b));
            } else {
                return sha256(abi.encodePacked(b, a));
            }
    }

    function testAnchor() public logs_gas {
        bytes32 sigs = 0x5d9215ea8ea2c12bcc724d9690de0801a1b9658014c29c2a26d3b89eaa65cd07;
        bytes32 data_root = 0x7fdb7b2d4ddb3ca67c1a79725fc9b3e4e2b8d4c15bedc8cac1873fa58a75b837;
        bytes32 root = 0x0ea4cc3dcbc2b85a3032d00edb8314119b9b199ca05d8a7c35e0427a8ae64991;

        // Setting AnchorMock to return a given root
        anchors.file(root, 0); 
          
        assertTrue(nft.checkAnchor(0, data_root, sigs));
    }

    function testMint() public logs_gas {
        bytes32 leaf1 = sha256("1");
        bytes32 leaf2 = sha256("2");
        bytes32 leaf3 = sha256("3");
        bytes32 leaf4 = sha256("4");

        bytes32 parent1 = hash(leaf1, leaf2); 
        bytes32 parent2 = hash(leaf3, leaf4);
        bytes32 data_root = hash(parent1, parent2);
        bytes32 sigs = sha256("sigs");
        bytes32 root = hash(data_root, sigs);

        anchors.file(root, 0); 

        bytes32[3] memory values = [leaf1, leaf2, leaf3];
        bytes32[][] memory proofs = new bytes32[][](3);
        proofs[0] = new bytes32[](2);
        proofs[0][0] = leaf2;
        proofs[0][1] = parent2;
        proofs[1] = new bytes32[](0);
        proofs[2] = new bytes32[](1);
        proofs[2][0] = leaf4;

        nft.mint(address(usr1), 1, 1, data_root, sigs, values, proofs, 5);
        assertEq(nft.ownerOf(1), address(usr1));
    }

}
