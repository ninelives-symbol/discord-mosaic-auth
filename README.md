# discord-mosaic-auth

## Dependencies
symbol-sdk-python<br>
discord<br>
binascii<br>
aiosqlite<br>
base64<br>

## Introduction
Python script that allows holders of specific Symbol mosaics to be assigned a role on a Discord server. The owner of the channel can specify a list of mosaics mapped to server roles in the format <code>[mosaic hex ID]:[server role]</code><br>
For example:<br>

<code>53CD7D13A450B11C:role1<br>
77C1A763F6A8E8B9:role2<br>
33C742BC6E6B4F03:role3<br>
0000000000000000:role4<br>
</code><br>

These values are read from a text file when starting the bot. The user can then request a challenge from the bot from within the discord channel and this will be sent as a DM. The user then sends an encrypted message containing the challenge string back to the bot. The bot decrypts the message using the user's public key and if successful checks the decrypted challenge string matches the one issued. Once the challenge is validated the bot checks all mosaics owned by the account and if there is a match it will assign the relevant role to the user on the Discord server.

## Setting up the Discord server
The administrator must add the bot to their Discord server with the admin role and set up the relevant roles on the server, corresponding to the roles in the mosaic:role mapping file. A new channel should be set up to facilitate authorisation. This channel should be set up so that only admin users have read access and that the bot will only function within this channel. <code>@everyone</code> should be able to post to the channel in order to validate their mosaics and be assigned a role on the server. 

## Running the bot
The bot requires its own Symbol account which should not contain any funds. The private key of the account is set as the environment variable <code>ACCOUNT_PRIVATE_KEY</code> e.g. <code>export ACCOUNT_PRIVATE_KEY=[private key string]</code>. A Discord bot token is also required and again is set as an environment variable <code>DISCORD_BOT_TOKEN</code> on the server that is running the bot.

After setting the relevant environment the owner of the Discord server simply runs the bot script with the text input file containing the mosaic to role mappings on the command line e.g. <code>python mosaic_auth.py [mosaic mapping file]</code>.

## Interacting with the bot
Users enter the verification channel and register their Symbol address containing the relevant mosaic(s) using the <code>!register</code> command. E.g. <code>!register <your address></code>. The bot will then map the Discord user to a Symbol address and store this in a sqlite database.

Once the user's address has been registered they can request an authorisation challenge string from the bot using the <code>!request_challenge</code> command. The bot will then print a random 12 character string which is required to prove that the Discord user is the owner of the address that they have registered along with the Symbol address that the message has to be sent to. The user then sends an encrypted message containing the challenge back to the bot address. Once the message has been received the bot will decrypt the message and check that the challenge string matches that assigned by the bot and stored in the database. If the message matches then the users Symbol address is checked and the relevant role(s) are assigned to the Discord user based on the mosaics they own. The bot will send a DM to the user reporting that the role(s) have been successfully assigned.


