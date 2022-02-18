//SPDX-License-Identifier: Unlicense
// ERC1155

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract NFT is ERC721Enumerable, ERC721URIStorage, Ownable, ReentrancyGuard, EIP712, AccessControl {
    
    using SafeERC20 for IERC20;
    using SafeMath for uint256;
    using Strings for uint256;
    using ECDSA for bytes32;

    uint platformFees;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    bool public paused = true;

    mapping (address => bool) public acceptedTokens;

    // string private _baseURIextended;

    /// @notice Represents an un-minted NFT, which has not yet been recorded into the blockchain. A signed voucher can be redeemed for a real NFT using the redeem function.
    struct NFTVoucher {
        /// @notice The id of the token to be redeemed. Must be unique - if another token with this ID already exists, the redeem function will revert.
        uint256 tokenId;

        /// @notice The minimum price (in wei) that the NFT creator is willing to accept for the initial sale of this NFT.
        uint256 minPrice;

        /// @notice The metadata URI to associate with this token.
        string uri;

        /// @notice The original creator of this token.
        address creator;

        /// @notice index of accepted token
        address token;
    }

    constructor(string memory name, string memory symbol, string memory dapp, string memory version) ERC721(name, symbol) EIP712(dapp, version) ReentrancyGuard() {
        _setupRole(MINTER_ROLE, msg.sender);
    }

    /// @notice Redeems an NFTVoucher for an actual NFT, creating it in the process.
    /// @param voucher An NFTVoucher that describes the NFT to be redeemed.
    /// @param signature An EIP712 signature of the voucher, produced by the NFT creator.
    function redeem(NFTVoucher calldata voucher, bytes memory signature) public payable returns (uint256) {
        require(!paused, "NFT: contract is paused");
        // make sure signature is valid and get the address of the signer
        address signer = _verify(voucher, signature);

        // make sure that the signer is authorized to mint NFTs
        require(hasRole(MINTER_ROLE, signer), "Signature invalid or unauthorized");

        // make sure that the redeemer is paying enough to cover the buyer's cost
        require(acceptedTokens[voucher.token], "Token not accepted");
        
        uint platformFeeAmount = platformFees * voucher.minPrice / 10000;
        
        if (voucher.token == address(0)) {
            require(msg.value >= voucher.minPrice, "Insufficient funds to redeem");
            uint creatorFee = msg.value - platformFeeAmount;
            payable(voucher.creator).transfer(creatorFee);
            payable(signer).transfer(platformFeeAmount);
        } else {
            uint creatorFee = voucher.minPrice - platformFeeAmount;
            IERC20(voucher.token).safeTransferFrom(msg.sender, voucher.creator, creatorFee);
            IERC20(voucher.token).safeTransferFrom(msg.sender, signer, platformFeeAmount);
        }

        // first assign the token to the signer, to establish provenance on-chain
        _mint(voucher.creator, voucher.tokenId);
        _setTokenURI(voucher.tokenId, voucher.uri);
        
        // transfer the token to the redeemer
        _transfer(voucher.creator, msg.sender, voucher.tokenId);

        return voucher.tokenId;
    }

    // function mint(uint256 _amount, bool _state)internal{
    //     require(!paused, "NFT: contract is paused");
    //     require(totalSupply().add(_amount) <= maxSupply, "NFT: minting would exceed total supply");
    //     require(balanceOf(msg.sender).add(_amount) <= maxPurchase, "NFT: You can't mint so much tokens");
    //     if(_state){
    //         require(preSalePrice.mul(_amount) <= msg.value, "NFT: Ether value sent for presale mint is not correct");
    //     }
    //     else{
    //         require(publicSalePrice.mul(_amount) <= msg.value, "NFT: Ether value sent for public mint is not correct");
    //     }
    //     uint mintIndex = totalSupply().add(1);
    //     for (uint256 ind = 0; ind < _amount; ind++) {
    //         _safeMint(msg.sender, mintIndex.add(ind));
    //     }
    // }

    function setTokens(address[] calldata _tokens, bool value) external onlyOwner {
        for (uint256 i = 0; i < _tokens.length; i++) {
            acceptedTokens[_tokens[i]] = value;
        }
    }

    function setPlatformFees(uint _platformFees) external onlyOwner {
        platformFees = _platformFees;
    }

    // function setExcluded(address _excluded, bool _status) external onlyOwner {
    //     excludedList[_excluded] = _status;
    // }

    // function transferFrom(address from, address to, uint256 tokenId) public override {
    //     require(_isApprovedOrOwner(_msgSender(), tokenId),  'ERC721: transfer caller is not owner nor approved');
    //     if(excludedList[from] == false) {
    //         _payTxFee(from);
    //     }
    //     _transfer(from, to, tokenId);
    // }

    // function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public override {
    //     require(_isApprovedOrOwner(_msgSender(), tokenId), 'ERC721: transfer caller is not owner nor approved');
    //     if(excludedList[from] == false) {
    //         _payTxFee(from);
    //     }
    //     _safeTransfer(from, to, tokenId, _data);
    // }

    // function _payTxFee(address from) internal {
    //     // token.transferFrom(from, artist, txFeeAmount);
    // }

    // function updateNFTRoyalty(uint _id, uint _amount) internal {
    //     nftHedge[_id] += _amount;
    // }

    // function burn(uint _id) external {
    //     require(_isApprovedOrOwner(_msgSender(), _id), 'ERC721: burn caller is not owner nor approved');
    //     _burn(_id);
    //     uint amount = nftHedge[_id];
    //     delete nftHedge[_id];
    //     payable(ownerOf(_id)).transfer(amount);
    // }

    // function setBaseURI(string memory baseURI) external onlyOwner {
    //     _baseURIextended = baseURI;
    // }

    // function _baseURI() internal view virtual override returns (string memory) {
    //     return _baseURIextended;
    // }


    // function addWhiteListedAddresses(address[] memory _address) external onlyOwner {
    //     for (uint256 i = 0; i < _address.length; i++) {
    //         require(!isWhiteListed[_address[i]], "NFT: address is already white listed");
    //         isWhiteListed[_address[i]] = true;
    //     }
    // }

    function togglePauseState() external onlyOwner {
        paused = !paused;
    }

    // function togglePreSale()external onlyOwner {
    //     preSaleActive = !preSaleActive;
    // }

    // function setPreSalePrice(uint256 _preSalePrice)external onlyOwner {
    //     preSalePrice = _preSalePrice;
    // }

    // function togglePublicSale()external onlyOwner {
    //     publicSaleActive = !publicSaleActive;
    // }

    // function setPublicSalePrice(uint256 _publicSalePrice)external onlyOwner {
    //     publicSalePrice = _publicSalePrice;
    // }

    // function airDrop(address[] memory _address)external onlyOwner{
    //     uint256 mintIndex = totalSupply().add(1);
    //     require(mintIndex.add(_address.length) <= maxSupply, "NFT: minting would exceed total supply");
    //     for(uint256 i = 0; i < _address.length; i++){
    //         require(balanceOf(_address[i]).add(1) <= maxPurchase, "NFT: max purchase reached");
    //         _safeMint(_address[i], mintIndex.add(i));
    //     }
    // }

    // function reveal() external onlyOwner {
    //     revealed = true;
    // }

    function withdraw() external onlyOwner {
        uint balance = address(this).balance;
        payable(msg.sender).transfer(balance);
    }
    /*     
    * Set provenance once it's calculated
    */
    // function setProvenanceHash(string memory provenanceHash) external onlyOwner {
    //     NETWORK_PROVENANCE = provenanceHash;
    // }

    function _beforeTokenTransfer(address from, address to, uint tokenId) internal virtual override(ERC721, ERC721Enumerable) {
		super._beforeTokenTransfer(from, to, tokenId);
	}

	function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);
    }

    function _hash(NFTVoucher calldata voucher) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(
            keccak256("NFTVoucher(uint256 tokenId,uint256 minPrice,string uri)"),
            voucher.tokenId,
            voucher.minPrice,
            keccak256(bytes(voucher.uri))
        )));
    }

    /// @notice Verifies the signature for a given NFTVoucher, returning the address of the signer.
    /// @dev Will revert if the signature is invalid. Does not verify that the signer is authorized to mint NFTs.
    /// @param voucher An NFTVoucher describing an unminted NFT.
    /// @param signature An EIP712 signature of the given voucher.
    function _verify(NFTVoucher calldata voucher, bytes memory signature) internal view returns (address) {
        bytes32 digest = _hash(voucher);
        return digest.toEthSignedMessageHash().recover(signature);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override (AccessControl, ERC721, ERC721Enumerable) returns (bool) {
        return ERC721.supportsInterface(interfaceId) || AccessControl.supportsInterface(interfaceId);
    }

    function tokenURI(uint256 tokenId) public view virtual override(ERC721, ERC721URIStorage) returns (string memory) {
        return super.tokenURI(tokenId);
    }
    
    // function setNotRevealedURI(string memory _notRevealedURI) external onlyOwner {
    //     notRevealedUri = _notRevealedURI;
    // }

}