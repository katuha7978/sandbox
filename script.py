import os
import time
import json
import logging
from typing import Dict, Any, Optional, List

import requests
from web3 import Web3
from web3.contract import Contract
from web3.exceptions import BlockNotFound
from dotenv import load_dotenv

# --- Configuration Loading ---
load_dotenv()

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bridge_listener.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# --- Constants and Configuration ---
# In a real application, ABIs would be loaded from JSON files.
# For this simulation, we define them directly as strings.
SOURCE_CHAIN_BRIDGE_ABI = json.dumps([
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "sender", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "recipient", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "amount", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "nonce", "type": "uint256"}
        ],
        "name": "TokensLocked",
        "type": "event"
    }
])

DESTINATION_CHAIN_BRIDGE_ABI = json.dumps([
    {
        "inputs": [
            {"internalType": "address", "name": "recipient", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
            {"internalType": "uint256", "name": "sourceNonce", "type": "uint256"}
        ],
        "name": "mintWrappedTokens",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
])

class Config:
    """A dedicated class to hold all configuration parameters."""
    SOURCE_CHAIN_RPC_URL = os.getenv("SOURCE_CHAIN_RPC_URL")
    DESTINATION_CHAIN_RPC_URL = os.getenv("DESTINATION_CHAIN_RPC_URL")
    
    SOURCE_BRIDGE_CONTRACT_ADDRESS = os.getenv("SOURCE_BRIDGE_CONTRACT_ADDRESS")
    DESTINATION_BRIDGE_CONTRACT_ADDRESS = os.getenv("DESTINATION_BRIDGE_CONTRACT_ADDRESS")
    
    # The private key of the relayer/validator responsible for signing transactions on the destination chain.
    # WARNING: In a real-world scenario, never hardcode private keys. Use a secure vault or hardware security module.
    VALIDATOR_PRIVATE_KEY = os.getenv("VALIDATOR_PRIVATE_KEY")
    
    POLL_INTERVAL_SECONDS: int = 15
    BLOCK_CONFIRMATIONS: int = 6 # Number of blocks to wait before processing an event to handle re-orgs
    STATE_FILE_PATH: str = "listener_state.json"

class BlockchainConnector:
    """Manages the connection to a single blockchain node via Web3.py."""
    
    def __init__(self, rpc_url: str):
        """
        Initializes the connection to the blockchain node.
        
        Args:
            rpc_url (str): The HTTP RPC endpoint of the blockchain node.
        """
        self.rpc_url = rpc_url
        self.web3 = None
        self.connect()

    def connect(self) -> None:
        """Establishes the Web3 connection and verifies its status."""
        try:
            self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))
            if not self.web3.is_connected():
                raise ConnectionError(f"Failed to connect to the node at {self.rpc_url}")
            logger.info(f"Successfully connected to blockchain node at {self.rpc_url}. Chain ID: {self.web3.eth.chain_id}")
        except Exception as e:
            logger.error(f"Error connecting to {self.rpc_url}: {e}")
            self.web3 = None

    def is_connected(self) -> bool:
        """Checks if the Web3 instance is properly connected."""
        return self.web3 is not None and self.web3.is_connected()

    def get_contract(self, address: str, abi: str) -> Optional[Contract]:
        """
        Returns a Web3 contract instance.
        
        Args:
            address (str): The contract's on-chain address.
            abi (str): The contract's ABI in JSON string format.
            
        Returns:
            Optional[Contract]: A Web3 Contract object, or None if connection failed.
        """
        if not self.is_connected():
            logger.error("Cannot get contract, not connected to the blockchain.")
            return None
        
        checksum_address = self.web3.to_checksum_address(address)
        return self.web3.eth.contract(address=checksum_address, abi=abi)

class EventScanner:
    """Scans a source chain for specific smart contract events."""
    
    def __init__(self, connector: BlockchainConnector, contract_address: str, contract_abi: str, event_name: str):
        """
        Initializes the EventScanner.
        
        Args:
            connector (BlockchainConnector): The connector for the source blockchain.
            contract_address (str): The address of the contract to scan.
            contract_abi (str): The ABI of the contract.
            event_name (str): The name of the event to listen for.
        """
        self.connector = connector
        self.contract = self.connector.get_contract(contract_address, contract_abi)
        if not self.contract:
            raise ValueError("Failed to instantiate contract for EventScanner.")
        self.event_name = event_name
        self.event_filter = self.contract.events[event_name].create_filter

    def scan_for_events(self, from_block: int, to_block: int) -> List[Dict[str, Any]]:
        """
        Scans a range of blocks for new events and returns them.
        
        Args:
            from_block (int): The starting block number for the scan.
            to_block (int): The ending block number for the scan.
            
        Returns:
            List[Dict[str, Any]]: A list of decoded event logs.
        """
        if from_block > to_block:
            logger.debug(f"from_block ({from_block}) > to_block ({to_block}), no blocks to scan.")
            return []

        try:
            logger.info(f"Scanning for '{self.event_name}' events from block {from_block} to {to_block}.")
            event_filter = self.event_filter(fromBlock=from_block, toBlock=to_block)
            events = event_filter.get_all_entries()
            if events:
                logger.info(f"Found {len(events)} new '{self.event_name}' event(s).")
            return events
        except BlockNotFound:
            logger.warning(f"Block range [{from_block}-{to_block}] not found. The node might not have synced this far yet.")
            return []
        except Exception as e:
            logger.error(f"An unexpected error occurred while scanning for events: {e}")
            return []

class TransactionProcessor:
    """Processes events by creating and sending transactions to a destination chain."""
    
    def __init__(self, connector: BlockchainConnector, contract_address: str, contract_abi: str, private_key: str):
        """
        Initializes the TransactionProcessor.
        
        Args:
            connector (BlockchainConnector): The connector for the destination blockchain.
            contract_address (str): The address of the bridge contract on the destination chain.
            contract_abi (str): The ABI of the destination contract.
            private_key (str): The private key of the relayer account.
        """
        self.connector = connector
        self.web3 = self.connector.web3
        self.contract = self.connector.get_contract(contract_address, contract_abi)
        if not self.contract or not self.web3:
            raise ValueError("Failed to instantiate contract for TransactionProcessor.")
        self.account = self.web3.eth.account.from_key(private_key)
        logger.info(f"TransactionProcessor initialized for address: {self.account.address}")

    def process_lock_event(self, event: Dict[str, Any]) -> Optional[str]:
        """
        Processes a 'TokensLocked' event by simulating a 'mintWrappedTokens' transaction.
        
        Args:
            event (Dict[str, Any]): The event log data from the source chain.
            
        Returns:
            Optional[str]: The simulated transaction hash, or None on failure.
        """
        try:
            args = event['args']
            recipient = args['recipient']
            amount = args['amount']
            source_nonce = args['nonce']
            
            logger.info(f"Processing lock event for recipient {recipient}, amount {amount}, nonce {source_nonce}.")

            # --- Build Transaction --- #
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            tx_data = self.contract.functions.mintWrappedTokens(
                recipient,
                amount,
                source_nonce
            ).build_transaction({
                'chainId': self.web3.eth.chain_id,
                'from': self.account.address,
                'nonce': nonce,
                'gas': 200000, # A sensible default, in a real system this would be estimated
                'gasPrice': self.web3.eth.gas_price
            })

            # --- Sign Transaction --- #
            signed_tx = self.web3.eth.account.sign_transaction(tx_data, private_key=self.account.key)
            
            # --- Simulate Sending Transaction --- #
            # In a real application, you would uncomment the line below:
            # tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            # For this simulation, we will just log the action and return a fake hash.
            simulated_tx_hash = signed_tx.hash.hex()
            logger.info(f"SIMULATED: Sent transaction to mint tokens. Tx Hash: {simulated_tx_hash}")
            
            return simulated_tx_hash

        except Exception as e:
            logger.error(f"Failed to process event and create transaction: {e}")
            return None

class BridgeListener:
    """The main orchestrator that listens for events and triggers processing."""

    def __init__(self, config: Config):
        """
        Initializes the entire bridge listener system.
        
        Args:
            config (Config): An object containing all necessary configuration.
        """
        self.config = config
        self.state = self._load_state()
        
        logger.info("Initializing Bridge Listener...")
        self.source_connector = BlockchainConnector(config.SOURCE_CHAIN_RPC_URL)
        self.destination_connector = BlockchainConnector(config.DESTINATION_CHAIN_RPC_URL)

        if not self.source_connector.is_connected() or not self.destination_connector.is_connected():
            raise ConnectionError("Failed to establish connection with one or more blockchain nodes.")

        self.event_scanner = EventScanner(
            self.source_connector,
            config.SOURCE_BRIDGE_CONTRACT_ADDRESS,
            SOURCE_CHAIN_BRIDGE_ABI,
            "TokensLocked"
        )
        
        self.tx_processor = TransactionProcessor(
            self.destination_connector,
            config.DESTINATION_BRIDGE_CONTRACT_ADDRESS,
            DESTINATION_CHAIN_BRIDGE_ABI,
            config.VALIDATOR_PRIVATE_KEY
        )

    def _load_state(self) -> Dict[str, Any]:
        """Loads the last processed block number from a state file."""
        try:
            with open(self.config.STATE_FILE_PATH, 'r') as f:
                state = json.load(f)
                logger.info(f"Loaded state from {self.config.STATE_FILE_PATH}: {state}")
                return state
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning(f"State file not found or invalid. Starting with a default state.")
            return {"last_scanned_block": "latest"}

    def _save_state(self) -> None:
        """Saves the last processed block number to the state file."""
        try:
            with open(self.config.STATE_FILE_PATH, 'w') as f:
                json.dump(self.state, f, indent=4)
                logger.debug(f"Saved state to {self.config.STATE_FILE_PATH}: {self.state}")
        except IOError as e:
            logger.error(f"Could not save state to file: {e}")

    def run(self) -> None:
        """
        Starts the main event listening loop.
        This loop periodically scans for new events and processes them.
        """
        logger.info("Bridge Listener started. Press Ctrl+C to stop.")
        try:
            while True:
                self.poll_for_events()
                logger.debug(f"Sleeping for {self.config.POLL_INTERVAL_SECONDS} seconds...")
                time.sleep(self.config.POLL_INTERVAL_SECONDS)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received. Saving state and exiting.")
            self._save_state()
        except Exception as e:
            logger.critical(f"An unrecoverable error occurred in the main loop: {e}", exc_info=True)
            self._save_state()

    def poll_for_events(self) -> None:
        """The core logic for a single polling iteration."""
        if not self.source_connector.is_connected():
            logger.error("Source chain connection lost. Attempting to reconnect...")
            self.source_connector.connect()
            return # Skip this poll cycle
        
        try:
            # Determine the block range to scan
            latest_block = self.source_connector.web3.eth.block_number
            
            if self.state['last_scanned_block'] == 'latest':
                # On first run, start from the current block to avoid processing the whole chain history
                from_block = latest_block
            else:
                from_block = self.state['last_scanned_block'] + 1
            
            # We scan up to N blocks behind the tip to handle potential re-orgs
            to_block = latest_block - self.config.BLOCK_CONFIRMATIONS

            if from_block > to_block:
                logger.info(f"Chain has not advanced enough for scanning. Current head: {latest_block}, next scan starts at: {from_block}")
                return

            # Scan for events
            events = self.event_scanner.scan_for_events(from_block, to_block)

            if events:
                for event in events:
                    # Process each event
                    self.tx_processor.process_lock_event(event)
            else:
                logger.info("No new events found in this scan range.")

            # Update state with the last block we scanned successfully
            self.state['last_scanned_block'] = to_block
            self._save_state()

        except Exception as e:
            logger.error(f"Error during polling cycle: {e}", exc_info=True)


if __name__ == "__main__":
    # Basic validation of environment variables
    required_vars = [
        "SOURCE_CHAIN_RPC_URL", "DESTINATION_CHAIN_RPC_URL",
        "SOURCE_BRIDGE_CONTRACT_ADDRESS", "DESTINATION_BRIDGE_CONTRACT_ADDRESS",
        "VALIDATOR_PRIVATE_KEY"
    ]
    if any(not os.getenv(var) for var in required_vars):
        logger.critical("One or more required environment variables are not set. Please check your .env file.")
        exit(1)

    try:
        config = Config()
        listener = BridgeListener(config)
        listener.run()
    except (ValueError, ConnectionError) as e:
        logger.critical(f"Failed to initialize the Bridge Listener: {e}")
    except Exception as e:
        logger.critical(f"A fatal error occurred during startup: {e}", exc_info=True)
