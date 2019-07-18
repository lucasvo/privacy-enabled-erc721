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
import "../generic_nft.sol";

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

contract NFTTest is DSTest {
    GenericNFT nft;
    address         self;
    User            usr1;
    AnchorMock      anchors;

    function setUp() public {
        self = address(this);
        usr1 = new User();
        anchors = new AnchorMock();
        nft = new GenericNFT(address(anchors));
    }

    function testMint() public logs_gas {

        // Set a bunch of values
        bytes32 sigs = 0xab3a51423550a6ac6a5ae3b07438fe4a16a7ebe3119352200a348af581b83d5c;
        bytes32 data_root = 0x9a5962acaca36b0607e4c46733219a2aa6abc29c41ed6988f19dc86865743cf5;
        bytes32 root = 0x11ac8d72d72354e3e64271878b698f9e770619ace3e7c5d6aa02968f729b453f;

        bytes[] memory properties = new bytes[](3);
        properties[0] = hex"010000000000001cdb691b0c78e9e1432d354d52e26b3cd5054cd1261c4272bf8fce2bcf285908f300000005";
        properties[1] = hex"010000000000001cc559f889f1afe5f0e8d3ad327b66c9b2facadb9918e2ba45963fe76e590f9e4200000005";
        properties[2] = hex"010000000000001cc26ac898297e7f1c950218e45d1933059ab9c2b284aac57b36e1f6cd46829ead00000005";

        bytes[] memory values = new bytes[](3);
        values[0] = hex"0000000000000000000000000000000000000000000000000000000000000064";
        values[1] = hex"00000000000000000000000000000000000000000000000000000000000003e8";
        values[2] = hex"00000000000000000000000000000000000000000000000000000000000007d0";

        bytes32[] memory salts = new bytes32[](3);
        salts[0] = 0xc0798a18953192518377f216f97e7a8b42249451664a39f9e52e7ee32045a0eb;
        salts[1] = 0xf6fda2e48246f91c98e317377f3514298d221f7e93d62a315b9a956f33c7e594;
        salts[2] = 0x038fea1f64d9925ce096e37db05f8bd6add09493574f29e0b40d6a48ea616379;

        bytes32[][] memory proofs = new bytes32[][](3);
        proofs[0] = new bytes32[](6);
        proofs[0][0] = 0xb77b0c26c232d21b5392643c29a07aad367411049b9ee50ae1a4377d5c25a079;
        proofs[0][1] = 0x298a3288a3590a18ad0000eab86b87182432424ca2cafd0ad983b179accd743f;
        proofs[0][2] = 0x43ee93a2023b43b061690614785dfe8cc978b686cd1a459af4028e1e53f02771;
        proofs[0][3] = 0x956a7fe14077ba295dc9f3aa58e7dd60e869cdc4b7172297f037a93e84faf55d;
        proofs[0][4] = 0x9c733d7a69131bbda95f765467e0533bbad0f9380bf759e2883d3a7e00075962;
        proofs[0][5] = 0x904a689147f7d2a86a39d8f4b542aa72f95ef86c872904640c47e0519b378e6a;

        proofs[1] = new bytes32[](6);
        proofs[1][0] = 0x8a4238935f4fe2caee2e7bc346dc78ada155943d81c58cfaf812b8b5fbfdda4f;
        proofs[1][1] = 0xa628dd21fbd2fa4f82e8d08767b6033399f1d3c0e1b67bec7f9ec2631e715163;
        proofs[1][2] = 0x8608290cd1b85fadba1823059adce717400e0c3839a9101fe23791c75878dde6;
        proofs[1][3] = 0x956a7fe14077ba295dc9f3aa58e7dd60e869cdc4b7172297f037a93e84faf55d;
        proofs[1][4] = 0x9c733d7a69131bbda95f765467e0533bbad0f9380bf759e2883d3a7e00075962;
        proofs[1][5] = 0x904a689147f7d2a86a39d8f4b542aa72f95ef86c872904640c47e0519b378e6a;

        proofs[2] = new bytes32[](6);
        proofs[2][0] = 0xca3cd23eeb4c48ab225a9fa8c58587fe404a0c52235fc853e22ee57f105b448e;
        proofs[2][1] = 0x002b9220cb013e7201c2d230076eebe8d02be4bacd93fba5236bb1324796ab06;
        proofs[2][2] = 0xff3c438da7ba4d738d68c1069fed293a7be9f5ea1c90829d912f2c8184df42cb;
        proofs[2][3] = 0x39265faac300ea00ff3084498ab26d5e07532a876e7e985509f0db35ffa85b17;
        proofs[2][4] = 0x9c733d7a69131bbda95f765467e0533bbad0f9380bf759e2883d3a7e00075962;
        proofs[2][5] = 0x904a689147f7d2a86a39d8f4b542aa72f95ef86c872904640c47e0519b378e6a;

        // Setting AnchorMock to return a given root
        anchors.file(root, 0);

         // Test that the mint method works
        nft.mint(address(usr1), 1, 0, data_root, sigs, properties, values, salts, proofs);
        assertEq(nft.ownerOf(1), address(usr1));
    }
}
