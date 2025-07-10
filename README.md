# Sandbox: Cross-Chain Bridge Event Listener

This repository contains a Python-based simulation of a cross-chain bridge event listener. This component is crucial for blockchain interoperability, acting as a relayer that monitors events on a source chain and triggers corresponding actions on a destination chain.

## Concept

A cross-chain bridge allows users to transfer assets or data from one blockchain (the "source chain") to another (the "destination chain"). A common mechanism for this is "lock-and-mint":

1.  **Lock**: A user locks their assets (e.g., ETH, ERC20 tokens) in a smart contract on the source chain.
2.  **Event Emission**: The smart contract emits an event (e.g., `TokensLocked`) containing details of the transaction, such as the recipient's address on the destination chain and the amount.
3.  **Listening**: Off-chain services, often called relayers or validators, constantly monitor the source chain for these specific events.
4.  **Verification & Minting**: Upon detecting a `TokensLocked` event, a relayer verifies it and submits a transaction to a corresponding smart contract on the destination chain. This transaction instructs the destination contract to "mint" an equivalent amount of a wrapped or synthetic token and send it to the specified recipient.

This script simulates the critical off-chain listener (Step 3 and 4), providing a robust framework for handling this process in a reliable and organized manner.

## Code Architecture

The script is designed with a modular, object-oriented approach to separate concerns and enhance maintainability. The core components are:

-   **`Config`**: A simple class that loads and holds all configuration parameters from environment variables (e.g., RPC URLs, contract addresses, private keys). This centralizes configuration management.

-   **`BlockchainConnector`**: A reusable utility class responsible for managing the connection to a single blockchain node using `web3.py`. It encapsulates the `Web3` instance and provides helper methods to check connectivity and instantiate contract objects.

-   **`EventScanner`**: This class is dedicated to scanning the source chain. It takes a `BlockchainConnector` and contract details. Its primary method, `scan_for_events`, queries a specified range of blocks for a particular event (e.g., `TokensLocked`) and returns any logs it finds.

-   **`TransactionProcessor`**: This component's role is to act upon the events detected by the `EventScanner`. It connects to the destination chain and has a method (`process_lock_event`) that takes event data, constructs a new transaction (e.g., a call to `mintWrappedTokens`), signs it with the validator's private key, and simulates sending it to the destination chain.

-   **`BridgeListener`**: The main orchestrator class. It initializes and coordinates all other components. It maintains the application's state (like the last block number it scanned) to prevent reprocessing events. Its `run()` method contains the main polling loop, which periodically triggers the `EventScanner` and passes any found events to the `TransactionProcessor`.

-   **State Management**: The listener persists its state (the last scanned block) in a JSON file (`listener_state.json`). This allows the script to be stopped and restarted without losing its place or reprocessing old events.

## How it Works

The operational flow of the script is as follows:

1.  **Initialization**: On startup, the `BridgeListener` loads its configuration from a `.env` file and reads its last known state from `listener_state.json`.
2.  **Connection**: It creates two `BlockchainConnector` instances, one for the source chain and one for the destination chain, verifying that a connection can be established to both.
3.  **Main Loop**: The listener enters an infinite loop that performs the following actions every `POLL_INTERVAL_SECONDS`:
    a. **Determine Block Range**: It gets the latest block number from the source chain. It calculates the `from_block` (last scanned block + 1) and `to_block` (latest block - block confirmations) to scan. Waiting for a few confirmations (`BLOCK_CONFIRMATIONS`) mitigates the risk of acting on events from orphaned blocks (chain re-organizations).
    b. **Scan for Events**: It calls the `EventScanner` to query the source chain's bridge contract for `TokensLocked` events within the determined block range.
    c. **Process Events**: If any events are found, it iterates through them.
    d. **Create Transaction**: For each event, it passes the data (recipient, amount, nonce) to the `TransactionProcessor`. The processor then builds, signs, and *simulates* sending a `mintWrappedTokens` transaction to the destination chain.
    e. **Update State**: After a successful scan (whether events were found or not), the listener updates its internal state with the `to_block` value and saves it to `listener_state.json`.
4.  **Graceful Shutdown**: If the script is interrupted (e.g., with Ctrl+C), it catches the signal, saves its final state, and exits cleanly.

## Usage Example

### 1. Prerequisites

-   Python 3.8+
-   Access to two Ethereum-compatible RPC nodes (e.g., from Infura, Alchemy, or a local node). For testing, you can use the same RPC URL for both source and destination.

### 2. Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd sandbox
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Create a configuration file:**
    Create a file named `.env` in the root of the project and populate it with the necessary details. **Replace the placeholder values.**

    ```ini
    # .env file

    # RPC endpoint for the source chain (e.g., Ethereum, Polygon)
    SOURCE_CHAIN_RPC_URL="https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"

    # RPC endpoint for the destination chain (e.g., Arbitrum, Optimism)
    DESTINATION_CHAIN_RPC_URL="https://arb-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_API_KEY"

    # Address of the bridge contract on the source chain that emits the lock event
    SOURCE_BRIDGE_CONTRACT_ADDRESS="0x0000000000000000000000000000000000000000"

    # Address of the bridge contract on the destination chain that handles minting
    DESTINATION_BRIDGE_CONTRACT_ADDRESS="0x0000000000000000000000000000000000000000"

    # Private key for the validator/relayer account that will pay gas on the destination chain
    # WARNING: Use a key from a test wallet with no real funds.
    VALIDATOR_PRIVATE_KEY="0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ```

### 3. Run the Listener

Execute the script from your terminal:

```bash
python script.py
```

### Expected Output

You will see log messages indicating the script's activity. It will show successful connections, the blocks it's scanning, and whether any events were found and processed.

```
2023-10-27 10:30:00,123 - __main__ - INFO - Initializing Bridge Listener...
2023-10-27 10:30:01,456 - __main__ - INFO - Successfully connected to blockchain node at https://.... Chain ID: 1
2023-10-27 10:30:02,789 - __main__ - INFO - Successfully connected to blockchain node at https://.... Chain ID: 42161
2023-10-27 10:30:02,790 - __main__ - INFO - TransactionProcessor initialized for address: 0xYourValidatorAddress...
2023-10-27 10:30:02,791 - __main__ - INFO - Bridge Listener started. Press Ctrl+C to stop.
2023-10-27 10:30:02,792 - __main__ - INFO - Scanning for 'TokensLocked' events from block 18450000 to 18450006.
2023-10-27 10:30:04,500 - __main__ - INFO - Found 1 new 'TokensLocked' event(s).
2023-10-27 10:30:04,501 - __main__ - INFO - Processing lock event for recipient 0xRecipientAddress..., amount 1000000000000000000, nonce 123.
2023-10-27 10:30:05,100 - __main__ - INFO - SIMULATED: Sent transaction to mint tokens. Tx Hash: 0x....
2023-10-27 10:30:05,101 - __main__ - INFO - No new events found in this scan range.
2023-10-27 10:30:05,102 - __main__ - DEBUG - Sleeping for 15 seconds...
```
