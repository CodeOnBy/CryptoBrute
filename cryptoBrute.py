# CryptoBrute
# codeonbyte.com

# --- Dependency Check ---
# This block checks for required libraries at the very beginning.
try:
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
except ImportError as e:
    missing_library = e.name
    pip_package_map = {
        "requests": "requests",
        "bip_utils": "bip-utils" # Note the hyphen for pip
    }
    package_name = pip_package_map.get(missing_library, missing_library)
    print("="*60)
    print(f"🛑 Error: A required library is missing: '{missing_library}'")
    print(f"   Please install it by running the following command:")
    print(f"   pip install {package_name}")
    print("="*60)
    sys.exit(1)
# --- End of Dependency Check ---


# WARNING: This script handles cryptographic keys. Running it on a computer
# connected to the internet with a real seed phrase is a security risk.

# --- Global Configuration & Settings ---
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
    "mnemonic_length": 12,
    "output_file": "found.txt",
    "silent_mode": False
}

# --- (The rest of the script is identical to Version 21) ---

def get_wordlist():
    global WORDLIST, _loaded_wordlist_filename
    if settings['wordlist_filename'] != _loaded_wordlist_filename:
        try:
            if not settings['silent_mode']:
                print(f"\nLoading wordlist from '{settings['wordlist_filename']}'...")
            with open(settings['wordlist_filename'], "r", encoding="utf-8") as f:
                WORDLIST = [line.strip() for line in f.readlines()]
            if len(WORDLIST) != 2048:
                print(f"🛑 ERROR: Wordlist must contain 2048 words. Found {len(WORDLIST)}."); WORDLIST = []; return None
            _loaded_wordlist_filename = settings['wordlist_filename']
            if not settings['silent_mode']:
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
                if not settings['silent_mode']: print("!", end="", flush=True)
                data = response.json()
                balance_sats = data['chain_stats']['funded_txo_sum'] - data['chain_stats']['spent_txo_sum']
                if balance_sats > 0:
                    balance_btc = balance_sats / 100_000_000
                    print(f"\n\n{'!'*20} SUCCESS! WALLET WITH BALANCE FOUND! {'!'*20}")
                    with open(settings['output_file'], "a") as f:
                        f.write(f"{'='*60}\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Mnemonic: {mnemonic}\nPath: {path}\nAddress: {address}\n")
                        f.write(f"Private Key (WIF): {priv_key_wif}\nBalance: {balance_btc:.8f} BTC ({balance_sats} sats)\n{'='*60}\n")
                    print(f"\nDetails saved to {settings['output_file']}")
                    return True
                return False
            elif response.status_code in [429, 503]:
                if not settings['silent_mode']: print(f"\n[!] API Warning: Status {response.status_code}. Retrying...")
                retries -= 1
                if retries > 0: time.sleep(BACKOFF_TIME)
            else: return False
        except requests.exceptions.RequestException:
            if not settings['silent_mode']: print(f"\n[!] Network Error. Retrying...")
            retries -= 1
            if retries > 0: time.sleep(BACKOFF_TIME)
    return False

def derive_and_check(master_key, description, mnemonic):
    if not settings['silent_mode']: print(f"\n--- Checking {description} ---")
    account_key = master_key.Purpose().Coin().Account(0)
    for change_idx in [0, 1]:
        change_key = account_key.Change(Bip44Changes.CHAIN_EXT if change_idx == 0 else Bip44Changes.CHAIN_INT)
        if not settings['silent_mode']:
            print(f"Checking {'receiving' if change_idx == 0 else 'change'} addresses (up to index {settings['address_count'] - 1}): ", end="")
        for i in range(settings['address_count']):
            address_key = change_key.AddressIndex(i)
            path, address, priv_key_wif = str(address_key), address_key.PublicKey().ToAddress(), address_key.PrivateKey().ToWif()
            if check_address_balance(address, path, priv_key_wif, mnemonic): return True
            time.sleep(settings['sleep_time'])
        if not settings['silent_mode']: print()
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
        if not settings['silent_mode']:
            print("\nScan complete. No balance found for this seed phrase.")
    except MnemonicChecksumError:
        print("\n" + "="*50 + "\n🛑 ERROR: INVALID SEED PHRASE\n" + "="*50)

def run_single_wallet_check_cli(mnemonic):
    words = mnemonic.split()
    if len(words) not in [12, 18, 24]:
        print(f"Error: Seed phrase must have 12, 18, or 24 words. Provided: {len(words)}.")
        return
    scan_wallet(mnemonic)

def run_full_brute_force_hunter_cli():
    length = settings['mnemonic_length']
    if not settings['silent_mode']:
        print(f"\n--- Full Random {length}-Word Mnemonic Hunter ---")
        print("🚨 WARNING: Success is statistically impossible. Press CTRL+C to stop.")
    length_map = {12: Bip39WordsNum.WORDS_NUM_12, 18: Bip39WordsNum.WORDS_NUM_18, 24: Bip39WordsNum.WORDS_NUM_24}
    words_num_enum = length_map[length]
    wallets_checked = 0
    generator = Bip39MnemonicGenerator()
    while True:
        mnemonic = generator.FromWordsNumber(words_num_enum).ToStr()
        if not settings['silent_mode']:
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
    if not settings['silent_mode']:
        print(f"\nFound {num_unknowns} unknown word(s), generating {total_combinations:,} mnemonics.")
    
    combinations_generator = product(current_wordlist, repeat=num_unknowns)
    checked_count = 0
    for combo in combinations_generator:
        temp_mnemonic_list = list(template_list)
        for i, word in enumerate(combo):
            temp_mnemonic_list[brute_force_indices[i]] = word
        mnemonic_to_check = " ".join(temp_mnemonic_list)
        checked_count += 1
        if not settings['silent_mode']:
            print(f"\rChecked: {checked_count:,} / {total_combinations:,}", end="")
        try:
            Bip39SeedGenerator(mnemonic_to_check)
            if not settings['silent_mode']:
                print(f"\n[+] Valid Checksum Found for: {mnemonic_to_check}")
            if scan_wallet(mnemonic_to_check):
                print("\nSUCCESS! A wallet with a balance was found!"); sys.exit()
        except MnemonicChecksumError: continue
    if not settings['silent_mode']:
        print(f"\n\nPartial brute-force complete. Checked all {total_combinations:,} combinations.")

def run_settings_menu_interactive():
    while True:
        silent_status = "On" if settings['silent_mode'] else "Off"
        print("\n" + "="*45 + "\n                  Settings Menu\n" + "="*45)
        print(f"1) Address Count (Gap Limit)      : {settings['address_count']}")
        print(f"2) API Sleep Time (seconds)         : {settings['sleep_time']}")
        print(f"3) Wordlist File                    : {settings['wordlist_filename']}")
        print(f"4) API URL                          : {settings['api_url']}")
        print(f"5) Mnemonic Length (for hunter)     : {settings['mnemonic_length']} words")
        print(f"6) Output File                      : {settings['output_file']}")
        print(f"7) Silent Mode                      : {silent_status}")
        print("8) Back to Main Menu")
        print("="*45)
        choice = input("Enter your choice (1-8): ").strip()

        if choice == '1':
            try:
                new_count = int(input(f"Enter new address count > ").strip())
                if new_count > 0: settings['address_count'] = new_count
            except ValueError: print("Error: Invalid input.")
        elif choice == '2':
            try:
                new_sleep = float(input(f"Enter new sleep time > ").strip())
                if new_sleep >= 0: settings['sleep_time'] = new_sleep
            except ValueError: print("Error: Invalid input.")
        elif choice == '3':
            settings['wordlist_filename'] = input(f"Enter new wordlist filename > ").strip() or settings['wordlist_filename']
        elif choice == '4':
            print("Enter new API URL. Use '{}' as the placeholder for the address.")
            new_url = input(f"> ").strip()
            if new_url: settings['api_url'] = new_url
        elif choice == '5':
            try:
                new_length = int(input("Enter new mnemonic length (12, 18, or 24) > ").strip())
                if new_length in [12, 18, 24]: settings['mnemonic_length'] = new_length
                else: print("Error: Please enter 12, 18, or 24.")
            except ValueError: print("Error: Invalid input.")
        elif choice == '6':
            settings['output_file'] = input(f"Enter new output filename > ").strip() or settings['output_file']
        elif choice == '7':
            settings['silent_mode'] = not settings['silent_mode']
            print(f"Silent mode is now {'On' if settings['silent_mode'] else 'Off'}.")
        elif choice == '8': break
        else: print("Invalid choice.")

def main_menu():
    while True:
        print("\n" + "="*30 + "\n   CryptoBrute Tool Menu\n" + "="*30)
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
            run_partial_brute_force_cli(" ".join(input("Enter template with '?': ").strip().lower().split()))
            input("\nPress Enter to return...")
        elif choice == '3':
            run_settings_menu_interactive()
        elif choice == '4':
            print("Exiting. Thank you!"); break
        else:
            print("Invalid choice.")

def main():
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="CryptoBrute Recovery and Brute-Force Tool.")
        subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

        def add_common_args(p):
            p.add_argument('-c', '--address-count', type=int, help=f"Addresses to check (default: {settings['address_count']})")
            p.add_argument('-s', '--sleep-time', type=float, help=f"Sleep between API calls (default: {settings['sleep_time']})")
            p.add_argument('-w', '--wordlist', type=str, help=f"BIP39 wordlist file (default: {settings['wordlist_filename']})")
            p.add_argument('-a', '--api-url', type=str, help=f"API URL for balance checks (default: {settings['api_url']})")
            p.add_argument('-o', '--output-file', type=str, help=f"File to save found wallets (default: {settings['output_file']})")
            p.add_argument('--silent', action='store_true', help="Suppress progress output, only show results.")

        parser_check = subparsers.add_parser('check', help='Check a single, complete seed phrase.')
        parser_check.add_argument('seed_phrase', nargs='+', help='The 12, 18, or 24-word seed phrase.')
        add_common_args(parser_check)

        parser_brute = subparsers.add_parser('brute', help="Brute-force a partial seed phrase using '?'.")
        parser_brute.add_argument('template', nargs='+', help="The seed phrase template. Use '?' for the full random hunter.")
        parser_brute.add_argument('-l', '--length', type=int, choices=[12, 18, 24], help=f"Mnemonic length for full hunter mode ('?') (default: {settings['mnemonic_length']})")
        add_common_args(parser_brute)
        
        args = parser.parse_args()

        if args.address_count is not None: settings['address_count'] = args.address_count
        if args.sleep_time is not None: settings['sleep_time'] = args.sleep_time
        if args.wordlist is not None: settings['wordlist_filename'] = args.wordlist
        if args.api_url is not None: settings['api_url'] = args.api_url
        if args.output_file is not None: settings['output_file'] = args.output_file
        if args.silent: settings['silent_mode'] = True
        if hasattr(args, 'length') and args.length is not None: settings['mnemonic_length'] = args.length

        if args.command == 'check':
            run_single_wallet_check_cli(" ".join(args.seed_phrase))
        elif args.command == 'brute':
            run_partial_brute_force_cli(" ".join(args.template))
    else:
        main_menu()

if __name__ == "__main__":
    main()