require('dotenv').config();
const { Client, GatewayIntentBits, Partials, REST, Routes, SlashCommandBuilder } = require('discord.js');
const crypto = require('crypto');
global.window = this // JSEncrypt fails without this
const JSEncrypt = require('jsencrypt')
const { createHash } = require("node:crypto")
const { BigInteger } = require('jsbn')

// Check for required environment variables
if (!process.env.BOT_TOKEN) {
    console.error('Missing BOT_TOKEN in environment variables');
    process.exit(1);
}

if (!process.env.PRIVATE_KEY) {
    console.error('Missing PRIVATE_KEY in environment variables');
    process.exit(1);
}

if (!process.env.APPLICATION_ID) {
    console.error('Missing APPLICATION_ID in environment variables');
    process.exit(1);
}

// Create a new client instance with only necessary intents
// Removing DirectMessages intent for added security
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent
    ],
    partials: [
        Partials.Message
    ]
});

// Set up rate limiting
const userCooldowns = new Map();
const COOLDOWN_SECONDS = 60; // 1 minute cooldown between requests
const MAX_REQUESTS_PER_HOUR = 10; // Maximum requests per user per hour
const userHourlyRequests = new Map();
const hourlyResetInterval = 60 * 60 * 1000; // 1 hour in milliseconds

// Reset hourly request counts every hour
setInterval(() => {
    console.log(`Resetting hourly request limits for ${userHourlyRequests.size} users`);
    userHourlyRequests.clear();
}, hourlyResetInterval);

// Handle ONLY guild messages - explicit check for guild existence
client.on('messageCreate', (message) => {
    // First, explicitly verify this is a guild message
    if (!message.guild) {
        // This is a DM - log and ignore completely
        console.log(`Ignored non-guild message from ${message.author.tag}`);
        return;
    }

    // This code will ONLY run for messages in servers, never in DMs
    // We're not doing anything with regular messages currently,
    // but if you add functionality later, it will be protected
});

// Make sure our slash command handler explicitly checks for guild context first
client.on('interactionCreate', async (interaction) => {
    // Critical security check - ONLY process guild interactions
    if (!interaction.guild) {
        console.log(`Blocked non-guild interaction from ${interaction.user.tag}`);
        return; // Exit immediately
    }

    // Log all guild interactions for audit purposes
    console.log(`Received interaction: ${interaction.commandName || 'unknown'} from ${interaction.user.tag} in ${interaction.guild.name}#${interaction.channel?.name || 'unknown'}`);

    // At this point, we know we're in a guild, so continue with command processing
    if (!interaction.isCommand()) return;
    if (interaction.commandName !== 'ginvite') return;

    // Process the inviteme command
    await handleInviteCommand(interaction);
});

// Function to check if a user is rate limited
function isRateLimited(userId) {
    const now = Date.now();

    // Check cooldown
    if (userCooldowns.has(userId)) {
        const cooldownEnd = userCooldowns.get(userId);
        if (now < cooldownEnd) {
            return {
                limited: true,
                remainingSeconds: Math.ceil((cooldownEnd - now) / 1000),
                reason: 'cooldown'
            };
        }
    }

    // Check hourly limit
    if (!userHourlyRequests.has(userId)) {
        userHourlyRequests.set(userId, 0);
    }

    const hourlyCount = userHourlyRequests.get(userId);
    if (hourlyCount >= MAX_REQUESTS_PER_HOUR) {
        return {
            limited: true,
            remainingRequests: 0,
            reason: 'hourly'
        };
    }

    // User is not rate limited
    return { limited: false };
}

// Register the slash command
const commands = [
    new SlashCommandBuilder()
        .setName('ginvite')
        .setDescription('Request an invite link')
        .addStringOption(option =>
			option
				.setName('name')
				.setDescription('The in-game name of the character to invite')
                .setRequired(true)
        )
        .toJSON()
];

// Deploy commands when the bot starts
const deployCommands = async () => {
    try {
        console.log('Started refreshing application (/) commands.');

        const rest = new REST({ version: '10' }).setToken(process.env.BOT_TOKEN);

        // First, register guild-specific commands (instant update)
        for (const guild of client.guilds.cache.values()) {
            console.log(`Registering commands for guild: ${guild.name} (${guild.id})`);

            await rest.put(
                Routes.applicationGuildCommands(process.env.APPLICATION_ID, guild.id),
                { body: commands },
            );

            console.log(`Commands registered for guild: ${guild.name}`);
        }

        // Also register globally (for future servers)
        // await rest.put(
        //     Routes.applicationCommands(process.env.APPLICATION_ID),
        //     { body: commands },
        // );

        console.log('Successfully registered global and guild-specific application (/) commands.');
    } catch (error) {
        console.error('Error registering commands:', error);
    }
};



function signMessage(message) {
    try {
        // sha256 hash function, lowest 16 bits
        let digest = function(msg) {
            let hash = createHash('sha256').update(msg).digest('hex')
            return hash.substring(32)
        }

        // Get the private key
        let jse = new JSEncrypt()
        let privateKey = process.env.PRIVATE_KEY;
        jse.setKey(privateKey)
        
        // Sign the message
        console.log("message", message)
        console.log("digest", digest(message))
        let raw = new BigInteger(digest(message), 16)
        console.log("digestraw", raw.toString())
        let sig = jse.getKey().doPrivate(raw)
        console.log("sig", sig.toString())
        console.log("sighex", sig.toString(16))
        return sig.toString(16)
    } catch (error) {
        console.error('Signing error:', error);
        return 'Signing failed: ' + error.message;
    }
}

function createInvitation(character, discord, guild) {
    let expiration = Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
    let message = `{{["c"]="${character}",["d"]="${discord}",["g"]="${guild}",["e"]=${expiration}}}`
    let sig = signMessage(message)
    let invitation = Buffer.from(`${sig}\n${message}`).toString('base64')
    return invitation
}

// Function to encrypt discord username and timestamp using the PKCS#8 PEM private key
function encryptMessage(discordUsername, timestamp) {
    try {
        const privateKey = process.env.PRIVATE_KEY;

        // Create the message to encrypt
        const message = `${discordUsername} ${timestamp}`;

        // Generate a random initialization vector
        const iv = crypto.randomBytes(16);

        // For PKCS#8 format (-----BEGIN PRIVATE KEY-----), 
        // we'll use it to sign the message first
        const signer = crypto.createSign('SHA256');
        signer.update(message);
        const signature = signer.sign(privateKey, 'hex');

        // Create the full payload to encrypt
        const payload = JSON.stringify({
            discordUsername,
            timestamp,
            signature
        });

        // We'll use a derived key from the message for encryption
        const hmac = crypto.createHmac('sha256', privateKey);
        hmac.update(message);
        const derivedKey = hmac.digest().slice(0, 32); // 32 bytes for AES-256

        // Encrypt the payload with AES-256-CBC
        const cipher = crypto.createCipheriv('aes-256-cbc', derivedKey, iv);
        let encrypted = cipher.update(payload, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // Combine the IV and encrypted data
        const result = {
            iv: iv.toString('hex'),
            data: encrypted
        };

        return JSON.stringify(result);
    } catch (error) {
        console.error('Encryption error:', error);
        return 'Encryption failed: ' + error.message;
    }
}

// When the client is ready, run this code (only once)
client.once('ready', async () => {
    console.log(`✅ Bot is online as ${client.user.tag}!`);
    console.log(`⚙️ Bot is in ${client.guilds.cache.size} servers`);

    // List all servers the bot is in and check permissions
    client.guilds.cache.forEach(guild => {
        console.log(`📁 Server: ${guild.name} (ID: ${guild.id})`);

        // Check bot permissions in this guild
        const botMember = guild.members.cache.get(client.user.id);
        if (botMember) {
            const permissions = botMember.permissions.toArray();
            console.log(`   Bot permissions: ${permissions.join(', ')}`);

            // Check for critical permissions
            const requiredPermissions = [
                'UseApplicationCommands',
                'SendMessages',
                'ViewChannel',
                'ReadMessageHistory'
            ];

            const missingPermissions = requiredPermissions.filter(perm => !permissions.includes(perm));
            if (missingPermissions.length > 0) {
                console.log(`   ⚠️ WARNING: Missing required permissions: ${missingPermissions.join(', ')}`);
            } else {
                console.log(`   ✅ Bot has all required permissions`);
            }
        }

        // Find channels with "guild" and "invite" in the name
        const inviteChannels = guild.channels.cache.filter(channel =>
            channel.type === 0 && // 0 is text channel
            channel.name.toLowerCase().includes('guild') &&
            channel.name.toLowerCase().includes('invite')
        );

        if (inviteChannels.size > 0) {
            console.log(`   Found ${inviteChannels.size} possible invite channels:`);
            inviteChannels.forEach(channel => {
                console.log(`   - #${channel.name} (ID: ${channel.id})`);
            });
        } else {
            console.log(`   ⚠️ No channels containing 'guild' and 'invite' found. Create one for the bot to work.`);
        }
    });

    // Register all slash commands
    try {
        await deployCommands();
        console.log('👍 Commands registered successfully!');
        console.log('\n📋 If you don\'t see the /inviteme command, try these fixes:');
        console.log('   1. Double-check that your bot has the "applications.commands" scope checked in OAuth2');
        console.log('   2. Reinvite the bot to your server with proper permissions');
        console.log('   3. Wait a few minutes for Discord to fully register the commands');
        console.log('   4. Try restarting the bot\n');
        console.log('💡 Console commands: "exit", "quit", or "stop" to shutdown the bot, "help" for more info');
    } catch (error) {
        console.error('❌ Error during startup:', error);
    }
});

// Handle the invite command
async function handleInviteCommand(interaction) {
    console.log(interaction)
    try {
        // Check for rate limiting
        const userId = interaction.user.id;
        const rateLimitInfo = isRateLimited(userId);

        if (rateLimitInfo.limited) {
            if (rateLimitInfo.reason === 'cooldown') {
                await interaction.reply({
                    content: `You're sending commands too quickly. Please wait ${rateLimitInfo.remainingSeconds} seconds before trying again.`,
                    ephemeral: true
                });
            } else if (rateLimitInfo.reason === 'hourly') {
                await interaction.reply({
                    content: `You've reached the maximum number of requests (${MAX_REQUESTS_PER_HOUR}) for this hour. Please try again later.`,
                    ephemeral: true
                });
            }
            return;
        }

        // More flexible channel name check - accept both with and without hyphen
        const channelNameLower = interaction.channel?.name?.toLowerCase() || '';
        if (!channelNameLower.includes('guild') || !channelNameLower.includes('invite')) {
            console.log(`Channel check failed: ${channelNameLower}`);
            await interaction.reply({
                content: 'This command can only be used in a guild invites channel.',
                ephemeral: true
            });
            return;
        }

        // Get the discord username (handling new Discord username system)
        const discordUsername = interaction.user.discriminator !== '0'
            ? `${interaction.user.username}#${interaction.user.discriminator}`
            : interaction.user.username;

        // Get the current timestamp
        const timestamp = new Date().toISOString();

        console.log(`Processing invite request for ${discordUsername}`);

        // Encrypt the username and timestamp
        //const encryptedMessage = encryptMessage(discordUsername, timestamp);

        const characterName = interaction.options.getString('name') ?? 'invalidName';

        const invitation = createInvitation(characterName, discordUsername, "Frontier Alpha")
        // Send a DM to the user
        await interaction.user.send({
            content: `Here is your encrypted invite string: \`\`\`/gi invitation ${invitation}\`\`\``
        });

        // Reply to the command
        await interaction.reply({
            content: 'I\'ve sent you a DM with your encrypted invite token!',
            ephemeral: true
        });

        // Apply rate limiting after successful request
        userCooldowns.set(userId, Date.now() + (COOLDOWN_SECONDS * 1000));
        userHourlyRequests.set(userId, (userHourlyRequests.get(userId) || 0) + 1);

        console.log(`Successfully sent invite token to ${discordUsername} at ${timestamp}`);
    } catch (error) {
        console.error('Error processing invite command:', error);

        // Try to respond to the user if possible
        try {
            if (interaction.replied || interaction.deferred) {
                await interaction.followUp({
                    content: 'There was an error processing your request. Please try again later.',
                    ephemeral: true
                });
            } else {
                await interaction.reply({
                    content: 'There was an error processing your request. Please try again later.',
                    ephemeral: true
                });
            }
        } catch (followUpError) {
            console.error('Error sending error message:', followUpError);
        }
    }
};

// Login to Discord with your client's token
client.login(process.env.BOT_TOKEN);

// Handle process termination and console commands
process.on('SIGINT', () => {
    console.log('Bot is shutting down... (CTRL+C detected)');
    client.destroy();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('Bot is shutting down... (SIGTERM received)');
    client.destroy();
    process.exit(0);
});

// Console command handler for terminating the bot
process.stdin.on('data', (data) => {
    const input = data.toString().trim().toLowerCase();

    if (input === 'exit' || input === 'quit' || input === 'stop') {
        console.log('Bot is shutting down... (Console command received)');
        client.destroy();
        process.exit(0);
    }

    if (input === 'help') {
        console.log('\nAvailable console commands:');
        console.log('  exit, quit, stop - Shutdown the bot gracefully');
        console.log('  help - Display this help message\n');
    }
});