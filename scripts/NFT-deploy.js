const fs = require('fs');
const { web3, ethers } = require('hardhat');
const CONFIG = require("../credentials.json");
// const nftABI = (JSON.parse(fs.readFileSync('./artifacts/contracts/NFT.sol/NFT.json', 'utf8'))).abi;

contract("NFT deployment", () => {
    let nft;
    let tx;

    const provider = new ethers.providers.JsonRpcProvider(CONFIG["RINKEBY"]["URL"]);
    const signer = new ethers.Wallet(CONFIG["RINKEBY"]["PKEY"]);
    const account = signer.connect(provider);

    before(async () => {
      const NFT = await ethers.getContractFactory("NFT");
      nft = await NFT.deploy("Harshit", "HAR", "1000000000", 150, "300000000000000000", "400000000000000000");
      await nft.deployed();

      // nftaddr = new ethers.Contract(nft.address, nftABI, account);

      console.log("NFT deployed at address: ",nft.address);
      // console.log(nftaddr.address);

    })

    // after(async () => {
    //     console.log('\u0007');
    //     console.log('\u0007');
    //     console.log('\u0007');
    //     console.log('\u0007');
    // })

    // it ("should set correct params for NFT mint", async () => {
		// tx = await nft.setBaseURI("https://ipfs.io/ipfs/");
		// await tx.wait()
		// tx = await nft.setProvenanceHash("PROVENANCE");
		// await tx.wait()
		// // tx = await nft.addWhiteListedAddresses([accounts[1].address, accounts[2].address, accounts[3].address, accounts[4].address]);
    // // await tx.wait()
		// tx = await nft.setPreSale();
    // await tx.wait()
    // tx = await nft.setPublicSale();
    // await tx.wait()
    // tx = await nft.setNotRevealedURI("NULL");
    // await tx.wait()
    // })
})