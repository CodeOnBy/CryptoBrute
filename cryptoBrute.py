# btc_recover.py

# WARNING: This script handles cryptographic keys. Running it on a computer
# connected to the internet with a real seed phrase is a security risk.

import sys
import re
import requests
import time
from datetime import datetime
from itertools import product
from bip_utils import (
    Bip39SeedGenerator,
    Bip39MnemonicGenerator,
    Bip39WordsNum,
    Bip44, Bip44Coins, Bip44Changes,
    Bip49, Bip49Coins,
    Bip84, Bip84Coins
)
from bip_utils.utils.mnemonic.mnemonic_ex import MnemonicChecksumError

# --- Global Configuration & Settings ---
OUTPUT_FILE = "found.txt"
PASSPHRASE = ""
RETRY_COUNT = 3
BACKOFF_TIME = 30
WORDLIST = []
_loaded_wordlist_filename = None # Tracks which wordlist is currently in memory

settings = {
    "address_count": 5,
    "sleep_time": 1,
    "wordlist_filename": "english.txt",
    "api_url": "https://mempool.space/api/address/{}"
}

# --- Helper & Core Logic Functions ---

def get_wordlist():
    """
    Loads or reloads the wordlist from the file specified in settings.
    Returns the wordlist as a list, or None on failure.
    """
    global WORDLIST, _loaded_wordlist_filename
    
    # Reload if the filename in settings is different from what's loaded
    if settings['wordlist_filename'] != _loaded_wordlist_filename:
        try:
            print(f"\nLoading wordlist from '{settings['wordlist_filename']}'...")
            with open(settings['wordlist_filename'], "r", encoding="utf-8") as f:
                WORDLIST = [line.strip() for line in f.readlines()]
            
            if len(WORDLIST) != 2048:
                print(f"🛑 ERROR: Wordlist must contain exactly 2048 words. Found {len(WORDLIST)}.")
                _loaded_wordlist_filename = None # Mark as failed
                WORDLIST = []
                return None
            
            _loaded_wordlist_filename = settings['wordlist_filename']
            print("Wordlist loaded successfully.")

        except FileNotFoundError:
            print(f"🛑 ERROR: Wordlist file '{settings['wordlist_filename']}' not found.")
            _loaded_wordlist_filename = None # Mark as failed
            WORDLIST = []
            return None
            
    return WORDLIST

def check_address_balance(address, path, priv_key_wif, mnemonic):
    """Checks address balance using the API URL from settings."""
    retries = RETRY_COUNT
    while retries > 0:
        try:
            # Use the API URL from the settings dictionary
            url = settings['api_url'].format(address)
            response = requests.get(url, timeout=15)
            
            if response.status_code == 200:
                print("!", end="", flush=True)
                data = response.json()
                balance_sats = data['chain_stats']['funded_txo_sum'] - data['chain_stats']['spent_txo_sum']
                if balance_sats > 0:
                    balance_btc = balance_sats / 100_000_000
                    print(f"\n\n{'!'*20} SUCCESS! WALLET WITH BALANCE FOUND! {'!'*20}")
                    with open(OUTPUT_FILE, "a") as f:
                        f.write(f"{'='*60}\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Mnemonic: {mnemonic}\nPath: {path}\nAddress: {address}\n")
                        f.write(f"Private Key (WIF): {priv_key_wif}\nBalance: {balance_btc:.8f} BTC ({balance_sats} sats)\n{'='*60}\n")
                    print(f"\nDetails saved to {OUTPUT_FILE}")
                    return True
                return False
            elif response.status_code in [429, 503]:
                print(f"\n[!] API Warning: Status {response.status_code}. Retrying...")
                retries -= 1
                if retries > 0: time.sleep(BACKOFF_TIME)
            else: return False
        except requests.exceptions.RequestException:
            print(f"\n[!] Network Error. Retrying...")
            retries -= 1
            if retries > 0: time.sleep(BACKOFF_TIME)
    return False

def derive_and_check(master_key, description, mnemonic):
    # Unchanged
    print(f"\n--- Checking {description} ---")
    account_key = master_key.Purpose().Coin().Account(0)
    for change_idx in [0, 1]:
        change_key = account_key.Change(Bip44Changes.CHAIN_EXT if change_idx == 0 else Bip44Changes.CHAIN_INT)
        print(f"Checking {'receiving' if change_idx == 0 else 'change'} addresses (up to index {settings['address_count'] - 1}): ", end="")
        for i in range(settings['address_count']):
            address_key = change_key.AddressIndex(i)
            path, address, priv_key_wif = str(address_key), address_key.PublicKey().ToAddress(), address_key.PrivateKey().ToWif()
            if check_address_balance(address, path, priv_key_wif, mnemonic): return True
            time.sleep(settings['sleep_time'])
        print()
    return False

def scan_wallet(mnemonic):
    # Unchanged
    try:
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate(PASSPHRASE)
        bip44_master = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        if derive_and_check(bip44_master, "Legacy (BIP44)", mnemonic): return True
        bip49_master = Bip49.FromSeed(seed_bytes, Bip49Coins.BITCOIN)
        if derive_and_check(bip49_master, "Nested SegWit (BIP49)", mnemonic): return True
        bip84_master = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
        if derive_and_check(bip84_master, "Native SegWit (BIP84)", mnemonic): return True
        print("\nScan complete. No balance found for this seed phrase.")
    except MnemonicChecksumError:
        print("\n" + "="*50 + "\n🛑 ERROR: INVALID SEED PHRASE\n" + "="*50)

# --- Menu Option Functions ---

def run_single_wallet_check():
    # Unchanged
    print("\n--- Import & Check Seed Phrase ---")
    mnemonic_input = input("Please enter your 12-word seed phrase: ").strip().lower()
    mnemonic = " ".join(re.split(r'\s+', mnemonic_input))
    if len(mnemonic.split()) != 12:
        print("Error: Please enter exactly 12 words."); return
    scan_wallet(mnemonic)

def run_full_brute_force_hunter():
    # Unchanged, but now only called by the partial brute-force function
    print("\n--- Full Random Mnemonic Hunter ---")
    print("🚨 WARNING: Success is statistically impossible.")
    wallets_checked = 0
    generator = Bip39MnemonicGenerator()
    while True:
        mnemonic = generator.FromWordsNumber(Bip39WordsNum.WORDS_NUM_12).ToStr()
        print(f"\n{'='*60}\n#{wallets_checked + 1} | Scanning: '{mnemonic}'")
        if scan_wallet(mnemonic):
            print("Target found! Shutting down hunter."); sys.exit()
        wallets_checked += 1

def run_partial_brute_force():
    # Updated to use get_wordlist()
    print("\n--- Brute-Force Partial Seed Phrase ---")
    print("Enter your seed phrase template using '?' for unknown words.")
    template_input = input("> ").strip().lower()

    if template_input == '?':
        run_full_brute_force_hunter(); return

    template_list = re.split(r'\s+', template_input)
    if len(template_list) != 12:
        print("Error: Template must contain exactly 12 words/placeholders."); return

    current_wordlist = get_wordlist()
    if not current_wordlist:
        print("Cannot proceed without a valid wordlist."); return

    brute_force_indices = [i for i, word in enumerate(template_list) if word == '?']
    num_unknowns = len(brute_force_indices)

    if num_unknowns == 0:
        scan_wallet(" ".join(template_list)); return
        
    total_combinations = len(current_wordlist) ** num_unknowns
    print(f"\nFound {num_unknowns} unknown word(s). This will generate {total_combinations:,} mnemonics.")
    
    if total_combinations > 1000000:
        if input("This could take a very long time. Continue? (yes/no): ").lower() != 'yes':
            print("Aborting."); return

    combinations_generator = product(current_wordlist, repeat=num_unknowns)
    checked_count = 0
    for combo in combinations_generator:
        temp_mnemonic_list = list(template_list)
        for i, word in enumerate(combo):
            temp_mnemonic_list[brute_force_indices[i]] = word
        
        mnemonic_to_check = " ".join(temp_mnemonic_list)
        checked_count += 1
        print(f"\rChecked: {checked_count:,} / {total_combinations:,}", end="")
        try:
            Bip39SeedGenerator(mnemonic_to_check)
            print(f"\n[+] Valid Checksum Found for: {mnemonic_to_check}")
            if scan_wallet(mnemonic_to_check):
                print("\nSUCCESS! A wallet with a balance was found from your template!"); sys.exit()
        except MnemonicChecksumError: continue
    
    print(f"\n\nPartial brute-force complete. Checked all {total_combinations:,} combinations.")

def run_settings_menu():
    """Handles the settings menu, now with more options."""
    while True:
        print("\n" + "="*40 + "\n            Settings Menu\n" + "="*40)
        print(f"1) Address Count (Gap Limit): {settings['address_count']}")
        print(f"2) API Sleep Time (seconds):  {settings['sleep_time']}")
        print(f"3) Wordlist File:             {settings['wordlist_filename']}")
        print(f"4) API URL:                   {settings['api_url']}")
        print("5) Back to Main Menu")
        print("="*40)
        choice = input("Enter your choice (1-5): ").strip()
        if choice == '1':
            try:
                new_count = int(input(f"Enter new address count > ").strip())
                if new_count > 0: settings['address_count'] = new_count
                else: print("Error: Please enter a positive number.")
            except ValueError: print("Error: Invalid input.")
        elif choice == '2':
            try:
                new_sleep = float(input(f"Enter new sleep time > ").strip())
                if new_sleep >= 0: settings['sleep_time'] = new_sleep
                else: print("Error: Please enter a non-negative number.")
            except ValueError: print("Error: Invalid input.")
        elif choice == '3':
            new_filename = input(f"Enter new wordlist filename > ").strip()
            if new_filename: settings['wordlist_filename'] = new_filename
        elif choice == '4':
            print("Enter new API URL. Use '{}' as the placeholder for the address.")
            new_url = input(f"> ").strip()
            if '{}' not in new_url:
                print("Warning: API URL does not contain '{}'. It may not work correctly.")
            if new_url: settings['api_url'] = new_url
        elif choice == '5':
            break
        else:
            print("Invalid choice.")

# --- Main Menu ---

def main():
    """Main function to display the streamlined menu."""
    while True:
        print("\n" + "="*30 + "\n   Bitcoin Wallet Recovery\n" + "="*30)
        print("1) Import & Check Seed Phrase")
        print("2) Brute-Force Partial Phrase")
        print("3) Settings")
        print("4) Exit")
        print("="*30)
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == '1':
            run_single_wallet_check(); input("\nPress Enter to return...")
        elif choice == '2':
            run_partial_brute_force(); input("\nPress Enter to return...")
        elif choice == '3':
            run_settings_menu()
        elif choice == '4':
            print("Exiting. Thank you!"); break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()