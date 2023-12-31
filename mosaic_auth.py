import os
import discord
from discord.ext import commands
from discord.utils import get
from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.symbol.Network import Address
from symbolchain.symbol.MessageEncoder import MessageEncoder
from binascii import unhexlify
import requests
import random
import string
import time
import aiosqlite
import asyncio
import sys

address_to_discord_id = {}
challenge_lifetime = 300


class InvalidMappingFormatError(Exception):
    pass

class MosaicRoleMapper:
    def __init__(self, mapping_file):
        self.mosaic_roles = {}
        self.load_mapping(mapping_file)

    def load_mapping(self, mapping_file):
        with open(mapping_file, 'r') as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if line:
                    if ':' not in line:
                        raise InvalidMappingFormatError(
                            f"Invalid format in line {line_num}: {line}. Expected format: mosaic_id:role"
                        )
                    mosaic_id, role = line.split(":")
                    self.mosaic_roles[mosaic_id.strip()] = role.strip()


class SymbolSDKSetup:
    def __init__(self, network, node_url, private_key):
        self.facade = SymbolFacade(network)
        self.node_url = node_url
        self.private_key = PrivateKey(unhexlify(private_key))
        self.keypair = SymbolFacade.KeyPair(self.private_key)
        self.pubkey = self.keypair.public_key
        self.bot_address = self.facade.network.public_key_to_address(
            self.pubkey)
        self.message_encoder = MessageEncoder(self.keypair)


class DatabaseManager:
    def __init__(self, db_file):
        self.db_file = db_file

    async def create_database(self):
        async with aiosqlite.connect(self.db_file) as db:
            await db.execute(
                "CREATE TABLE IF NOT EXISTS verified_users (discord_id INTEGER PRIMARY KEY, public_key TEXT, symbol_address TEXT)")
            await db.execute(
                "CREATE TABLE IF NOT EXISTS symbol_addresses (discord_id INTEGER PRIMARY KEY, symbol_address TEXT)")
            await db.execute(
                "CREATE TABLE IF NOT EXISTS processed_transactions (transaction_hash TEXT PRIMARY KEY)")
            await db.commit()

    async def is_transaction_processed(self, transaction_hash):
        async with aiosqlite.connect("verification.db") as db:
            cursor = await db.execute(
                "SELECT * FROM processed_transactions WHERE transaction_hash = ?",
                (transaction_hash,))
            result = await cursor.fetchone()
        return result is not None

    async def is_account_verified(self, public_key):
        async with aiosqlite.connect("verification.db") as db:
            cursor = await db.execute(
                "SELECT * FROM verified_users WHERE public_key = ?",
                (public_key,))
            result = await cursor.fetchone()
        return result is not None

    async def is_address_registered(self, address):
        async with aiosqlite.connect("verification.db") as db:
            cursor = await db.execute(
                "SELECT * FROM symbol_addresses WHERE symbol_address = ?",
                (address,))
            result = await cursor.fetchone()
        return result is not None

    async def store_verified_user(self, discord_id, public_key, symbol_address):
        async with aiosqlite.connect("verification.db") as db:
            await db.execute(
                "INSERT INTO verified_users (discord_id, public_key, symbol_address) VALUES (?, ?, ?)",
                (discord_id, public_key, symbol_address))
            await db.commit()

    async def store_symbol_address(self, discord_id, symbol_address):
        async with aiosqlite.connect("verification.db") as db:
            await db.execute(
                "INSERT INTO symbol_addresses (discord_id, symbol_address) VALUES (?, ?)",
                (discord_id, symbol_address))
            await db.commit()
        address_to_discord_id[symbol_address] = discord_id
        print("Stored Symbol address for Discord ID:", discord_id, "Address:",
              symbol_address, flush=True)

    async def get_discord_id_by_address(self, symbol_address):
        discord_id = address_to_discord_id.get(symbol_address)
        if discord_id is not None:
            return discord_id

        async with aiosqlite.connect("verification.db") as db:
            cursor = await db.execute(
                "SELECT discord_id FROM symbol_addresses WHERE symbol_address = ?",
                (str(symbol_address),))
            result = await cursor.fetchone()

        return result[0] if result else None

    async def get_address_by_discord_id(self, discord_id):
        async with aiosqlite.connect("verification.db") as db:
            cursor = await db.execute(
                "SELECT symbol_address FROM symbol_addresses WHERE discord_id = ?",
                (discord_id,))
            result = await cursor.fetchone()

        return result[0] if result else None

    async def store_processed_transaction(self, transaction_hash):
        async with aiosqlite.connect("verification.db") as db:
            await db.execute(
                "INSERT OR IGNORE INTO processed_transactions (transaction_hash) VALUES (?)",
                (transaction_hash,))
            await db.commit()


class DiscordBot(commands.Bot):
    def __init__(self, command_prefix, intents, db_manager, mosaic_role_mapper,
                 symbol_sdk_setup):
        super().__init__(command_prefix=command_prefix, intents=intents)
        self.db_manager = db_manager
        self.mosaic_role_mapper = mosaic_role_mapper
        self.symbol_sdk_setup = symbol_sdk_setup

    async def on_ready(self):
        print(f'{self.user.name} has connected to Discord!')
        await self.db_manager.create_database()
        self.loop.create_task(
            self.monitor_transactions())  # Start monitoring transactions

    async def on_command_error(self, ctx, error):
        await ctx.send(f"An error occurred: {str(error)}")

    async def monitor_transactions(self):
        while True:
            await asyncio.sleep(5)  # Check every 5 seconds
            params = {
                "recipientAddress": self.symbol_sdk_setup.bot_address,
                "order": "desc"  # Sort by the most recent transactions
            }
            response = requests.get(
                f"{self.symbol_sdk_setup.node_url}/transactions/confirmed",
                params=params)

            if response.status_code == 200:
                transactions_data = response.json()
                transactions = transactions_data["data"]
                for transaction in transactions:
                    transaction_data = transaction["transaction"]
                    txhash = transaction["meta"]["hash"]
                    if not await self.db_manager.is_transaction_processed(
                            txhash):
                        await self.handle_incoming_transaction(transaction)
                        await self.db_manager.store_processed_transaction(
                            txhash)

    async def verify_mosaic(self, sendpubkey, mosaic_id):
        url = f"{self.symbol_sdk_setup.node_url}/accounts/{sendpubkey}"
        response = requests.get(url)

        if response.status_code == 200:
            account_info = response.json()
            mosaics = account_info['account']['mosaics']
            for mosaic in mosaics:
                if mosaic['id'] == mosaic_id:
                    return True
        return False

    async def handle_incoming_transaction(self, transaction):
        print("Handling incoming transaction...")
        sender_hex_public_key = transaction['transaction']['signerPublicKey']
        sendpubkey = PublicKey(unhexlify(sender_hex_public_key))

        # Get the sender's address
        sender_address = self.symbol_sdk_setup.facade.network.public_key_to_address(
            sendpubkey)
        print(f"Sender address: {sender_address}")

        if not await self.db_manager.is_address_registered(str(sender_address)):
            print(
                f"Received transaction for unregistered address {sender_address}. Skipping...")
            return

        discord_id = await self.db_manager.get_discord_id_by_address(
            sender_address)
        print(f"Symbol address: {sender_address} | Discord ID: {discord_id}")

        if discord_id is None:
            print(
                f"Unable to find user for Discord ID {discord_id}. Skipping...")
            return

        user = await bot.fetch_user(discord_id)

        if user is None:
            print(
                f"Unable to find user object for Discord ID {discord_id}. Skipping...")
            return

        print(f"User found: {user}")

        if 'message' in transaction['transaction']:
            if is_hex(transaction['transaction']['message']):
                tx_message = unhexlify(transaction['transaction']['message'])
            else:
                print("Message is not in hexadecimal format.")
                next

            if tx_message[0] == 0x01:  # Message is encrypted using deprecated

                print(f"Transaction message: {tx_message}")

                # Verify the message (challenge)
                try:
                    print("Verifying message...")
                    print(f"Sender address: {sender_address}")

                    encrypted_payload = bytes([1]) + unhexlify(
                        tx_message[1:].decode('utf8'))
                    sendpubkey = PublicKey(
                        unhexlify(
                            transaction['transaction']['signerPublicKey']))
                    (verified,
                     plain_message) = symbol_sdk_setup.message_encoder.try_decode(
                        sendpubkey, encrypted_payload)
                    plain_message = plain_message.decode('utf-8')
                    print(f"Verification result: {verified}")
                    print(f"Plaintext string: {plain_message}")

                    if verified:
                        # Verify message contains challenge
                        challenge_data = challenges.get(discord_id)
                        if challenge_data is not None:
                            challenge, timestamp = challenge_data
                            if plain_message == challenge and (
                                    time.time() - timestamp) < challenge_lifetime:
                                await self.grant_mosaic_holder_role(user,
                                                                    sendpubkey)
                            else:
                                await user.send(
                                    f"Challenge failed or expired. Access denied.")
                        else:
                            await user.send(
                                f"No active challenge found. Access denied.")

                except Exception as e:
                    print(f"Exception occurred during verification: {e}")
            else:
                try:
                    print("Verifying message...")
                    print(f"Sender address: {sender_address}")

                    encrypted_payload = unhexlify(tx_message.decode('utf8'))
                    sendpubkey = PublicKey(
                        unhexlify(
                            transaction['transaction']['signerPublicKey']))
                    (verified,
                     plain_message) = symbol_sdk_setup.message_encoder.try_decode(
                        sendpubkey, encrypted_payload)
                    plain_message = plain_message.decode('utf-8')
                    print(f"Verification result: {verified}")
                    print(f"Plaintext string: {plain_message}")

                    if verified:
                        # Verify message contains challenge
                        challenge_data = challenges.get(discord_id)
                        if challenge_data is not None:
                            challenge, timestamp = challenge_data
                            if plain_message == challenge and (
                                    time.time() - timestamp) < challenge_lifetime:
                                await self.grant_mosaic_holder_role(user,
                                                                    sendpubkey)
                            else:
                                await user.send(
                                    f"Challenge failed or expired. Access denied.")
                        else:
                            await user.send(
                                f"No active challenge found. Access denied.")

                except Exception as e:
                    print(f"Exception occurred during verification: {e}")

        else:
            print(
                f"Transaction {transaction['meta']['hash']} does not contain a message.")

    async def grant_mosaic_holder_role(self, user, sendpubkey):
        sender_address = symbol_sdk_setup.facade.network.public_key_to_address(
            sendpubkey)

        for mosaic_id, role_name in self.mosaic_role_mapper.mosaic_roles.items():
            if await self.verify_mosaic(sendpubkey, mosaic_id):
                for guild in bot.guilds:
                    print(f"Checking channel {guild.name}")
                    discord_id = await self.db_manager.get_discord_id_by_address(
                        sender_address)
                    member = await guild.fetch_member(user.id)

                    if member is not None:
                        member = get(guild.members, id=discord_id)
                        if guild.roles is None:
                            print(
                                f"Bot does not have 'View Server Members' permissions in guild {guild.name}")
                        else:
                            role = discord.utils.get(guild.roles,
                                                     name=role_name)
                            has_role = any(
                                r.name == role_name for r in member.roles)
                            if has_role:
                                print(f"{member} already has the {role} role.")
                            else:
                                print(f"{member} {role}")
                                await member.add_roles(role)
                                await user.send(
                                    f"Ownership of mosaic {mosaic_id} confirmed. Authentication successful! You have been granted the {role_name} role.")

def main():
    network = 'testnet'  # Can update to mainnet
    node_url = "http://mikun-testnet.tk:3000"  # Update if needed
    private_key = os.getenv('ACCOUNT_PRIVATE_KEY')

    if private_key is None:
        print("Error: The environment variable ACCOUNT_PRIVATE_KEY is not set.")
        sys.exit(1)

    # Instantiate components
    mapping_file = sys.argv[1]
    mosaic_role_mapper = MosaicRoleMapper(mapping_file)
    bot_token = os.environ['DISCORD_BOT_TOKEN']
    symbol_sdk_setup = SymbolSDKSetup(network, node_url, private_key)

    db_file = "verification.db"
    db_manager = DatabaseManager(db_file)

    challenges = {}  # Define the challenges dictionary

    intents = discord.Intents.all()
    intents.typing = False
    intents.presences = False
    intents.members = True

    bot_prefix = '!'
    bot = DiscordBot(command_prefix=bot_prefix, intents=intents,
                     db_manager=db_manager, mosaic_role_mapper=mosaic_role_mapper,
                     symbol_sdk_setup=symbol_sdk_setup)


    # For generating random challenge
    def generate_random_string(length=12):
        return ''.join(
            random.choices(string.ascii_letters + string.digits, k=length))


    def is_hex(s):
        try:
            int(s, 16)
            return True
        except ValueError:
            return False


    @bot.command(name='request_challenge')
    async def request_challenge(ctx):
        user_id = ctx.author.id
        user_address = await bot.db_manager.get_address_by_discord_id(user_id)
        if user_address is None:
            await ctx.send(
                "You must register before you can request a challenge. Use the `!register` command to register.")
            return
        if user_id in challenges:
            challenge, timestamp = challenges[user_id]
            if time.time() - timestamp < challenge_lifetime:
                await ctx.send(
                    f"You already have an active challenge: {challenge}. It will expire in {int(challenge_lifetime - (time.time() - timestamp))} seconds.")
                return

        challenge = f"{user_id:016x}" + generate_random_string()
        challenges[user_id] = (challenge, time.time())
        await ctx.send(
            f"Your challenge is: {challenge}\nPlease send an encrypted message to the bot's address {bot.symbol_sdk_setup.bot_address} with this challenge as the message payload.")


    @bot.event
    async def on_command_error(ctx, error):
        await ctx.send(f"An error occurred: {str(error)}")


    @bot.event
    async def on_ready():
        print(f'{bot.user.name} has connected to Discord!')
        await bot.db_manager.create_database()
        bot.loop.create_task(
            bot.monitor_transactions())  # Start monitoring transactions


    @bot.command(name="register")
    async def register(ctx, *args):
        print(f"Register command triggered with arguments: {args}")
        if not args:
            await ctx.send(
                "You must provide your Symbol address. Use the `!register <your_address>` command to register.")
            return

        user_id = ctx.message.author.id
        symbol_address = args[0].upper().strip()
        addr = Address(symbol_address)
        formatted_address = str(addr)
        try:
            await bot.db_manager.store_symbol_address(user_id, formatted_address)
            await ctx.send(
                f"Successfully registered Symbol address: {formatted_address}")
        except aiosqlite.IntegrityError:
            await ctx.send(f"Address {formatted_address} is already registered.")


    bot.run(bot_token)

if __name__ == "__main__":
    main()
