import { ethers } from "ethers";

export const mainnet = new ethers.providers.JsonRpcProvider(
  "https://eth-mainnet.g.alchemy.com/v2/JIFe1wEUANNSU8m_zEdclSaq6hPT_3ch"
);
export const optimism = new ethers.providers.JsonRpcProvider(
  "https://opt-mainnet.g.alchemy.com/v2/JIFe1wEUANNSU8m_zEdclSaq6hPT_3ch"
);

export const safeL1 = new ethers.Contract(
  "0x6dC501a9911370285B3ECc2830dd481fFCDDa348",
  ["function getOwners() public view returns (address[] memory)"],
  mainnet
);
export const safeL2 = new ethers.Contract(
  "0x8eB9B5F9b631a52F9c9a47F574ec9eF5d3641421",
  ["function getOwners() public view returns (address[] memory)"],
  optimism
);
export const pluginL2 = new ethers.Contract(
  "0x77bcaf6bd465d971a6058042f7b205684f715a05",
  [
    "function executeTransaction(address manager,address safe,(address,uint256,bytes) calldata action,uint8 operation,bytes[] calldata zkProof,bytes calldata l1OwnerSignatures) external",
    "function pluginNonce() public view returns (uint256)",
  ],
  optimism
);
