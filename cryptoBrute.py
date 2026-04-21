# btc_recover.py (Version 20 - CLI & Interactive Modes)

# WARNING: This script handles cryptographic keys. Running it on a computer
# connected to the internet with a real seed phrase is a security risk.

import sys
import re
import requests
import time
import argparse
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
_loaded_wordlist_filename = None

settings = {
    "address_count": 5,
    "sleep_time": 1.2,
    "wordlist_filename": "english.txt",
    "api_url": "https://mempool.space/api/address/{}",
    "mnemonic_length": 12
}

# --- (Helper & Core Logic functions are mostly unchanged) ---
def get_wordlist():
    global WORDLIST, _loaded_wordlist_filename
    if settings['wordlist_filename'] != _loaded_wordlist_filename:
        try:
            print(f"\nLoading wordlist from '{settings['wordlist_filename']}'...")
            with open(settings['wordlist_filename'], "r", encoding="utf-8") as f:
                WORDLIST = [line.strip() for line in f.readlines()]
            if len(WORDLIST) != 2048:
                print(f"🛑 ERROR: Wordlist must contain 2048 words. Found {len(WORDLIST)}."); WORDLIST = []; return None
            _loaded_wordlist_filename = settings['wordlist_filename']
            print("Wordlist loaded successfully.")
        except FileNotFoundError:
            print(f"🛑 ERROR: Wordlist file '{settings['wordlist_filename']}' not found."); WORDLIST = []; return None
    return WORDLIST

def check_address_balance(address, path, priv_key_wif, mnemonic):
    retries = RETRY_COUNT
    while retries > 0:
        try:
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
                print(f"\n[!] API Warning: Status {response.status_code}. Retrying..."); retries -= 1
                if retries > 0: time.sleep(BACKOFF_TIME)
            else: return False
        except requests.exceptions.RequestException:
            print(f"\n[!] Network Error. Retrying..."); retries -= 1
            if retries > 0: time.sleep(BACKOFF_TIME)
    return False

def derive_and_check(master_key, description, mnemonic):
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

# --- Non-Interactive (CLI) Functions ---

def run_single_wallet_check_cli(mnemonic):
    words = mnemonic.split()
    if len(words) not in [12, 18, 24]:
        print(f"Error: Seed phrase must have 12, 18, or 24 words. Provided: {len(words)}.")
        return
    scan_wallet(mnemonic)

def run_full_brute_force_hunter_cli():
    length = settings['mnemonic_length']
    print(f"\n--- Full Random {length}-Word Mnemonic Hunter ---")
    print("🚨 WARNING: Success is statistically impossible. Press CTRL+C to stop.")
    length_map = {12: Bip39WordsNum.WORDS_NUM_12, 18: Bip39WordsNum.WORDS_NUM_18, 24: Bip39WordsNum.WORDS_NUM_24}
    words_num_enum = length_map[length]
    wallets_checked = 0
    generator = Bip39MnemonicGenerator()
    while True:
        mnemonic = generator.FromWordsNumber(words_num_enum).ToStr()
        print(f"\n{'='*60}\n#{wallets_checked + 1} | Scanning {length}-word: '{mnemonic}'")
        if scan_wallet(mnemonic):
            print("Target found! Shutting down hunter."); sys.exit()
        wallets_checked += 1

def run_partial_brute_force_cli(template):
    if template == '?':
        run_full_brute_force_hunter_cli(); return

    template_list = template.split()
    if len(template_list) not in [12, 18, 24]:
        print(f"Error: Template must be 12, 18, or 24 words/placeholders long. Provided: {len(template_list)}."); return

    current_wordlist = get_wordlist()
    if not current_wordlist:
        print("Cannot proceed without a valid wordlist."); return

    brute_force_indices = [i for i, word in enumerate(template_list) if word == '?']
    num_unknowns = len(brute_force_indices)

    if num_unknowns == 0:
        scan_wallet(" ".join(template_list)); return
        
    total_combinations = len(current_wordlist) ** num_unknowns
    print(f"\nFound {num_unknowns} unknown word(s), generating {total_combinations:,} mnemonics.")
    
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
                print("\nSUCCESS! A wallet with a balance was found!"); sys.exit()
        except MnemonicChecksumError: continue
    print(f"\n\nPartial brute-force complete. Checked all {total_combinations:,} combinations.")

# --- Interactive Menu Functions ---

def run_settings_menu_interactive():
    while True:
        print("\n" + "="*40 + "\n            Settings Menu\n" + "="*40)
        print(f"1) Address Count (Gap Limit): {settings['address_count']}")
        print(f"2) API Sleep Time (seconds):  {settings['sleep_time']}")
        print(f"3) Wordlist File:             {settings['wordlist_filename']}")
        print(f"4) API URL:                   {settings['api_url']}")
        print(f"5) Mnemonic Length (for hunter): {settings['mnemonic_length']} words")
        print("6) Back to Main Menu")
        print("="*40)
        choice = input("Enter your choice (1-6): ").strip()
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
                print("Warning: API URL does not contain '{}'.")
            if new_url: settings['api_url'] = new_url
        elif choice == '5':
            try:
                new_length = int(input("Enter new mnemonic length (12, 18, or 24) > ").strip())
                if new_length in [12, 18, 24]: settings['mnemonic_length'] = new_length
                else: print("Error: Please enter 12, 18, or 24.")
            except ValueError: print("Error: Invalid input.")
        elif choice == '6': break
        else: print("Invalid choice.")

def main_menu():
    while True:
        print("\n" + "="*30 + "\n   Crypto Brute Menu\n" + "="*30)
        print("1) Import & Check Seed Phrase")
        print("2) Brute-Force Partial Seed Phrase")
        print("3) Settings")
        print("4) Exit")
        print("="*30)
        choice = input("Enter your choice (1-4): ").strip()
        if choice == '1':
            run_single_wallet_check_cli(" ".join(input("Please enter your seed phrase: ").strip().lower().split()))
            input("\nPress Enter to return...")
        elif choice == '2':
            run_partial_brute_force_cli(" ".join(input("Enter your seed phrase template with '?': ").strip().lower().split()))
            input("\nPress Enter to return...")
        elif choice == '3':
            run_settings_menu_interactive()
        elif choice == '4':
            print("Exiting. Thank you!"); break
        else:
            print("Invalid choice.")

# --- Main Entry Point: CLI or Interactive ---

def main():
    if len(sys.argv) > 1:
        # --- CLI Mode ---
        parser = argparse.ArgumentParser(description="Crypto Wallet Recovery and Brute-Force Tool.")
        subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

        # Generic settings arguments for all commands
        def add_common_args(p):
            p.add_argument('-c', '--address-count', type=int, help=f"Number of addresses to check per wallet (default: {settings['address_count']})")
            p.add_argument('-s', '--sleep-time', type=float, help=f"Seconds to sleep between API calls (default: {settings['sleep_time']})")
            p.add_argument('-w', '--wordlist', type=str, help=f"Path to the BIP39 wordlist file (default: {settings['wordlist_filename']})")
            p.add_argument('-a', '--api-url', type=str, help=f"API URL for balance checks (default: {settings['api_url']})")

        # 'check' command
        parser_check = subparsers.add_parser('check', help='Check a single, complete seed phrase.')
        parser_check.add_argument('seed_phrase', nargs='+', help='The 12, 18, or 24-word seed phrase.')
        add_common_args(parser_check)

        # 'brute' command
        parser_brute = subparsers.add_parser('brute', help="Brute-force a partial seed phrase using '?' as a placeholder.")
        parser_brute.add_argument('template', nargs='+', help="The seed phrase template. Use '?' for the full random hunter.")
        add_common_args(parser_brute)
        
        args = parser.parse_args()

        # Override default settings with any provided CLI arguments
        if args.address_count is not None: settings['address_count'] = args.address_count
        if args.sleep_time is not None: settings['sleep_time'] = args.sleep_time
        if args.wordlist is not None: settings['wordlist_filename'] = args.wordlist
        if args.api_url is not None: settings['api_url'] = args.api_url

        # Execute command
        if args.command == 'check':
            mnemonic = " ".join(args.seed_phrase)
            run_single_wallet_check_cli(mnemonic)
        elif args.command == 'brute':
            template = " ".join(args.template)
            run_partial_brute_force_cli(template)
    else:
        # --- Interactive Mode ---
        main_menu()

if __name__ == "__main__":
    main()