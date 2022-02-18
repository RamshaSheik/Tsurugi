const { expect } = require("chai");
const { ethers } = require("hardhat");
const provider = new ethers.providers.JsonRpcProvider("http://127.0.0.1:8545"); 

describe("NFT", function () {

  before(async() =>{
    const NFT = await ethers.getContractFactory("NFT");
    nft = await NFT.deploy("Harshit", "HAR", 500 , 150, "300000000000000000", "400000000000000000");
    await nft.deployed();

    accounts = await ethers.getSigners();
    
  })

  it("Should check for contract's ownership!", async function () {
    expect(await nft.owner()).to.equal(accounts[0].address);
  });

  it("Should set base URI", async function(){

    await nft.setBaseURI("https://ipfs.io/ipfs/");
    expect(await nft.baseURI()).to.equal("https://ipfs.io/ipfs/");

  });

  it("Should set provenance hash", async function(){
    await nft.setProvenanceHash("PROVENANCE");
    expect(await nft.NETWORK_PROVENANCE()).to.equal("PROVENANCE");
  });

  it("Should add whitelisted addresses", async function(){
    await nft.addWhiteListedAddresses([accounts[1].address, accounts[2].address, accounts[3].address, accounts[4].address]);
    expect(await nft.isWhiteListed(accounts[1].address)).to.equal(true);
    expect(await nft.isWhiteListed(accounts[2].address)).to.equal(true);
    expect(await nft.isWhiteListed(accounts[3].address)).to.equal(true);
    expect(await nft.isWhiteListed(accounts[4].address)).to.equal(true);
  });

  it("Should change paused state", async function(){
    await nft.togglePauseState();
    expect(await nft.paused()).to.equal(false);
  });

  it("Should set presale", async function(){
    await nft.togglePreSale();
    expect(await nft.preSaleActive()).to.equal(true);
  });

  it("Should set publicsale", async function(){
    await nft.togglePublicSale();
    expect(await nft.publicSaleActive()).to.equal(true);
  });

  it("Should set not revealed URI", async function(){
    await nft.setNotRevealedURI("NULL");
    expect(await nft.notRevealedUri()).to.equal("NULL");
  });

  it("Should do a presale mint", async function(){

    await expect(nft.connect(accounts[5])
    .preSaleMint(10, {value: ethers.utils.parseEther("1.0")}))
    .to.be.revertedWith("NFT:Sender is not whitelisted");

    // await expect(nft.connect(accounts[1])
    // .preSaleMint(10, {value: ethers.utils.parseEther("1.0")}))
    // .to.be.revertedWith("NFT: contract is paused");

    // await nft.togglePauseState();
    // expect(await nft.paused()).to.equal(false);

    await nft.connect(accounts[1])
    .preSaleMint(10, {value: ethers.utils.parseEther("3.0")});

    etherBal = await provider.getBalance(nft.address);
    expect(await nft.balanceOf(accounts[1].address)).to.equal(10);
    expect(etherBal).to.equal(ethers.utils.parseEther("3.0"));

    await nft.togglePreSale();

    await expect(nft.connect(accounts[2])
      .preSaleMint(10, {value: ethers.utils.parseEther("1.0")}))
      .to.be.revertedWith("NFT:Pre-sale is not active");

    await nft.togglePreSale();

    await nft.connect(accounts[1])
    .preSaleMint(140, {value: ethers.utils.parseEther("42.0")});

    //max purchase check
    await expect(nft.connect(accounts[1])
      .preSaleMint(10, {value: ethers.utils.parseEther("3.0")}))
      .to.be.revertedWith("NFT: You can't mint so much tokens");

    expect(await nft.balanceOf(accounts[1].address)).to.equal(150);   
  });

  it("Should do a public mint", async function(){

    await expect(nft.connect(accounts[5])
    .publicSaleMint(100, {value: ethers.utils.parseEther("10.0")}))
    .to.be.revertedWith("NFT: Ether value sent for public mint is not correct");

    await nft.connect(accounts[5])
    .publicSaleMint(100, {value: ethers.utils.parseEther("40.0")});

    expect(await nft.balanceOf(accounts[5].address)).to.equal(100);

    etherBal2 = await provider.getBalance(nft.address);
    expect(etherBal2).to.equal(ethers.utils.parseEther("85.0"));
  });

  it("Should check for NFT total supply and Max user Purchase", async function(){
    await nft.connect(accounts[6])
    .publicSaleMint(140, {value: ethers.utils.parseEther("60.0")});
    await expect(nft.connect(accounts[6])
    .publicSaleMint(20, {value: ethers.utils.parseEther("60.0")})).to.be.revertedWith("NFT: You can't mint so much tokens");
    await expect(nft.connect(accounts[7])
    .publicSaleMint(140, {value: ethers.utils.parseEther("60.0")})).to.be.revertedWith("NFT: minting would exceed total supply");
    expect(await nft.totalSupply()).to.equal(390);

  });

  it("Should do airdrop", async function(){

    await expect(nft.airDrop([accounts[1].address, accounts[6].address
      , accounts[7].address, accounts[8].address, accounts[9].address]))
      .to.be.revertedWith("NFT: max purchase reached");
    // expect(await nft.balanceOf(accounts[6].address)).to.equal(1);
    await nft.airDrop([accounts[6].address
      , accounts[7].address, accounts[8].address, accounts[9].address]);
    expect(await nft.balanceOf(accounts[6].address)).to.equal(141);
    expect(await nft.balanceOf(accounts[7].address)).to.equal(1);
    expect(await nft.balanceOf(accounts[8].address)).to.equal(1);
    expect(await nft.balanceOf(accounts[9].address)).to.equal(1);

    await nft.connect(accounts[8])
    .publicSaleMint(106, {value: ethers.utils.parseEther("60.0")});

    await expect(nft.airDrop([accounts[6].address
      , accounts[7].address, accounts[8].address, accounts[9].address]))
      .to.be.revertedWith("NFT: minting would exceed total supply");

  });

  it("Should return tokenURI", async function(){

    expect(await nft.tokenURI(1)).to.equal("NULL");
    await nft.reveal();
    expect(await nft.tokenURI(1)).to.equal("https://ipfs.io/ipfs/1.json");
  });

  it("Shoud withdraw ETH to Owner's account", async function(){

    bal1 = await provider.getBalance(accounts[0].address);
    await expect(nft.connect(accounts[1])
    .withdraw())
    .to.be.revertedWith("Ownable: caller is not the owner");
    // console.log(await provider.getBalance(nft.address));

    await nft.withdraw();

    contractBal = await provider.getBalance(nft.address);
    expect(contractBal).to.equal(ethers.utils.parseEther("0.0"));

    bal2 = await provider.getBalance(accounts[0].address);
    console.log(bal2.sub(bal1));
    expect(String(bal2.sub(bal1))).to.be.closeTo(ethers.utils.parseEther("205.0"), ethers.utils.parseEther("0.1"));

  });
});
