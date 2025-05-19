import { MetaMaskSDK } from "@metamask/sdk"

async function getInfuraAPIKey() {
  const response = await fetch("http://localhost:5000/get-infura-key")
  const data = await response.json()
  return data.infuraAPIKey
}

async function connectToMetaMask() {
  const infuraAPIKey = await getInfuraAPIKey()

  const MMSDK = new MetaMaskSDK({
    dappMetadata: {
      name: "Example Node.js Dapp",
    },
    infuraAPIKey: infuraAPIKey,  // 🔹 Now it's fetched securely
  })

  const accounts = await MMSDK.connect()
  const provider = MMSDK.getProvider()
  provider.request({ method: "eth_accounts", params: [] })
}

connectToMetaMask()
